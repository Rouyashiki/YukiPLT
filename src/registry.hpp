// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKIPLT_REGISTRY_HPP_
#define YUKIPLT_REGISTRY_HPP_

#include <cstddef>
#include <cstdint>

#include "common.hpp"
#include "yukiplt.hpp"

namespace yukiplt {
// Internal access shared by the C++ implementation and the thin C boundary.
class detail_api {
 public:
  static HookHandle make(uint64_t id) noexcept { return HookHandle(id); }
  static uint64_t id(const HookHandle& h) noexcept { return h.id_; }
  static void set(HookHandle& h, uint64_t id) noexcept { h.id_ = id; }
  static constexpr uint64_t invalid() noexcept { return HookHandle::kInvalid; }
};
}  // namespace yukiplt

namespace yukiplt::detail {

template <typename T>
class NoDestructor;

// Every in-use state reserves its slots. Release advances the generation
// to reject stale handles; failed recovery retains ownership.
enum class GroupState : uint8_t {
  kPrepared,       ///< Slots reserved, not yet committed.
  kInstalled,      ///< All slots committed; the caller owns them.
  kRestoring,      ///< An unhook is in progress.
  kIndeterminate,  ///< A commit or restore left recovery partial.
};

/// Image identity recorded with a group, used to detect a stale handle after
/// the image is unloaded (and, for custom images, replaced).
struct ImageIdentity {
  uintptr_t load_bias = 0;
  uintptr_t phdr_addr = 0;
  size_t phdr_count = 0;
  uint64_t instance_token = 0;  ///< 0 = system-linker image.
  bool invalidated = false;     ///< Set by forget_image() for custom images.
};

/// One slot owned by a group.
struct SlotRecord {
  uintptr_t address = 0;
  uintptr_t original = 0;     ///< Value before we installed (what unhook restores).
  uintptr_t replacement = 0;  ///< Value we installed.
  /// Whether our replacement was ever actually written to this slot (the CAS
  /// committed, even if later rolled back or left by a failed rollback).  False
  /// means the slot still holds whatever it held before us — we never owned its
  /// contents — so a restore has nothing to undo for it.
  bool ever_written = false;
};

/// A page a group left raised to writable but could not restore.
struct PageResidueRecord {
  uintptr_t page = 0;
  int original_prot = 0;
  int sys_errno = 0;
};

// Per-copy Registry; every operation requires op_mutex. Callers receive copies.
// Ids combine generation/index with a random per-copy salt; unavailable
// randomness blocks claims. The salt detects misuse, not a security boundary.
class Registry {
 public:
  static constexpr uint64_t kInvalidId = ~uint64_t(0);

  static Registry& instance();

  // Claim all slots or return kInvalidId without ownership. Requires salt_ready().
  // Copy system_path before publishing ownership; null means the exact empty
  // path, not a wildcard. Custom images do not use it.
  uint64_t claim(const ImageIdentity& image, const SlotRecord* slots, size_t count);

  /// kPrepared -> kInstalled.  No-op on a bad id or wrong state.
  void mark_installed(uint64_t id);

  /// Move a kPrepared group to kIndeterminate (a commit left residue) and
  /// record the slots' actual installed/observed values and any page residue.
  void mark_indeterminate(uint64_t id, const SlotRecord* slots, size_t count,
                          const PageResidueRecord* pages, size_t page_count);

  /// Free a kPrepared group whose commit did not install anything.
  void drop(uint64_t id);

  // Move Installed/Indeterminate to Restoring and copy recovery state. Reject
  // stale ids, invalidated images and other states before concurrent recovery.
  Error begin_restore(uint64_t id, ImageIdentity& image, SlotRecord* slots, size_t slot_cap,
                      size_t* slot_count, PageResidueRecord* pages, size_t page_cap,
                      size_t* page_count);

  /// Finish an unhook started by begin_restore.
  ///   - released: free the record (full success);
  ///   - else: write back the possibly-updated slots/residue and set the state
  ///     (kInstalled to retry later, or kIndeterminate).
  void finish_restore(uint64_t id, bool released, GroupState not_released_state,
                      const SlotRecord* slots, size_t slot_count, const PageResidueRecord* pages,
                      size_t page_count);

  /// Free a group's record without touching memory (abandon).  Returns
  /// kInvalidArgument for a bad/stale id.
  Error release(uint64_t id);

  /// Copy a group's recorded image and slots for query().  Returns
  /// kInvalidArgument for a bad/stale id.
  Error snapshot(uint64_t id, ImageIdentity& image, SlotRecord* slots, size_t cap,
                 size_t* count) const;

  /// Mark every live group for a custom image (matching load_bias, phdr and
  /// token) as invalidated.  Returns the number marked.
  size_t forget_custom_image(const ImageIdentity& image);

  /// Diagnostics.
  bool is_installed(uint64_t id) const;
  /// True if the group is Installed, or Indeterminate with a slot whose
  /// contents are still our replacement (ever_written) — i.e. dropping the
  /// handle would strand a live replacement.
  bool owns_live_replacement(uint64_t id) const;
  uintptr_t first_slot_of(uint64_t id) const;
  size_t live_count() const;
  void record_diagnostic(uint64_t id, const RecoveryDiagnostic& diagnostic) noexcept;
  Error recovery_snapshot(uint64_t id, RecoveryDiagnostic& diagnostic, ResidualPage* pages,
                          size_t capacity) const noexcept;

 private:
  template <typename T>
  friend class NoDestructor;
  Registry() = default;

  struct Record {
    uint32_t generation = 0;
    bool in_use = false;
    GroupState state = GroupState::kPrepared;
    ImageIdentity image;
    SmallVec<SlotRecord, 2> slots;
    SmallVec<PageResidueRecord, 2> residue;
    RecoveryDiagnostic diagnostic;
  };

  static bool is_live(GroupState /*s*/) noexcept { return true; }  // all stored states are live
  static uint64_t make_id(uint32_t gen, uint32_t index) noexcept {
    return (static_cast<uint64_t>(gen) << 32) | index;
  }
  Record* resolve(uint64_t id) noexcept;
  const Record* resolve(uint64_t id) const noexcept;
  bool slot_is_live(uintptr_t addr) const noexcept;

  // Open-addressed live-slot index. Grow before claim; backward-shift deletion
  // releases slots without allocating.
  struct IndexEntry {
    uintptr_t address = 0;  ///< 0 = empty (a GOT slot is never at address 0).
    uint32_t record = 0;    ///< Index into records_.
  };
  size_t index_find(uintptr_t addr) const noexcept;  ///< Position, or capacity if absent.
  void index_insert(uintptr_t addr, uint32_t record) noexcept;  ///< Capacity reserved.
  void index_erase(uintptr_t addr, uint32_t record) noexcept;
  void index_erase_record(const Record& r, uint32_t record) noexcept;
  /// Make room for `extra` more entries at load factor <= 1/2.  May throw.
  void index_reserve(size_t extra);

  SmallVec<Record, 8> records_;
  SmallVec<uint32_t, 8> free_list_;
  SmallVec<IndexEntry, 16> index_;  ///< Size is 0 or a power of two.
  size_t index_used_ = 0;
};

}  // namespace yukiplt::detail

#endif  // YUKIPLT_REGISTRY_HPP_
