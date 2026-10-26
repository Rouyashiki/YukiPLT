// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKIPLT_REGISTRY_HPP_
#define YUKIPLT_REGISTRY_HPP_

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

#include "yukiplt.hpp"

namespace yukiplt::detail {

template <typename T>
class NoDestructor;

/// Hook lifecycle state.
///
///   kPrepared  -> kInstalled -> kRestoring -> kReleased
///       \             \             \-------> kFailed
///        \-------------\------------------->  kFailed
///
/// A slot is "live" (blocks a new claim on the same address) while an entry for
/// it is kPrepared, kInstalled or kRestoring.  kReleased and kFailed are
/// terminal and do not block a new claim.
enum class HookState : uint8_t {
  kPrepared,   ///< Slot located and reserved, not yet modified.
  kInstalled,  ///< CAS succeeded, replacement is active.
  kRestoring,  ///< Unhook in progress for this entry.
  kReleased,   ///< Successfully restored or ownership relinquished.
  kFailed,     ///< Operation failed, state is known.
};

/// Immutable description of one hook, recorded at claim time.
struct HookEntry {
  uintptr_t slot_addr = 0;
  uintptr_t original_value = 0;  ///< Value in the slot before hook.
  uintptr_t replacement = 0;

  /// Image identity — used to detect stale handles after dlclose/dlopen.
  uintptr_t image_load_bias = 0;
  uintptr_t image_phdr_addr = 0;
  size_t image_phdr_count = 0;
};

// Per-copy Registry; every operation requires op_mutex. Callers receive copies.
// Ids combine generation/index with a random per-copy salt; unavailable
// randomness blocks claims. The salt detects misuse, not a security boundary.
class Registry {
 public:
  static constexpr size_t kInvalidId = ~size_t(0);

  /// Get the singleton instance.
  static Registry& instance();

  /// Atomically reserve an entry for info.slot_addr in the kPrepared state.
  ///
  /// Fails (returns kInvalidId) if some entry for the same slot address is
  /// already live (kPrepared / kInstalled / kRestoring).  This closes the
  /// check-then-insert race: the liveness test and the insert happen under one
  /// lock, so two threads cannot both reserve the same slot.
  size_t claim(const HookEntry& info);

  /// Move an entry kPrepared -> kInstalled.  Returns false if the id is invalid
  /// or the entry was not kPrepared.
  bool mark_installed(size_t id);

  /// Move an entry to the terminal kFailed state unconditionally (used to
  /// release a reservation whose patch did not commit).  No-op on invalid id.
  void mark_failed(size_t id);

  /// Atomically begin an unhook: require the entry to be kInstalled, move it to
  /// kRestoring, and copy its fields into out.  Returns the matching error
  /// otherwise (kInvalidArgument for a bad id, kNotInstalled otherwise) so that
  /// two concurrent unhooks of the same handle cannot both proceed.
  Error begin_restore(size_t id, HookEntry& out);

  /// Finish an unhook started by begin_restore: kReleased on success, else back
  /// to kFailed.  No-op on invalid id.
  void finish_restore(size_t id, bool success);

  /// Returns true if the entry exists and is currently kInstalled.
  bool is_installed(size_t id) const;

  /// Returns the slot address recorded for an entry, or 0 for an invalid id.
  /// Used only for diagnostics (the destructor warning).
  uintptr_t slot_of(size_t id) const;

 private:
  template <typename T>
  friend class NoDestructor;

  Registry() = default;

  struct Record {
    HookEntry entry;
    HookState state = HookState::kPrepared;
  };

  static bool is_live(HookState s) noexcept {
    return s == HookState::kPrepared || s == HookState::kInstalled || s == HookState::kRestoring;
  }

  mutable std::mutex mutex_;
  std::vector<Record> records_;
};

}  // namespace yukiplt::detail

#endif  // YUKIPLT_REGISTRY_HPP_
