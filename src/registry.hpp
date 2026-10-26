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

/// Hook lifecycle state.
enum class HookState : uint8_t {
  kPrepared,   ///< Slot located, not yet modified.
  kInstalled,  ///< CAS succeeded, replacement is active.
  kRestoring,  ///< Attempting to restore original value.
  kReleased,   ///< Successfully restored or ownership relinquished.
  kFailed,     ///< Operation failed, state is known.
};

/// Internal record for one hook operation.
struct HookEntry {
  uintptr_t slot_addr = 0;
  uintptr_t original_value = 0;  ///< Value in the slot before hook.
  uintptr_t replacement = 0;
  HookState state = HookState::kPrepared;

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
  /// Get the singleton instance.
  static Registry& instance();

  /// Check whether a slot address is currently hooked by this library.
  bool is_slot_hooked(uintptr_t slot_addr) const;

  /// Register a new hook entry.  Returns an entry ID (index).
  size_t add(HookEntry entry);

  /// Get a mutable pointer to an entry by ID.  Returns nullptr if invalid.
  HookEntry* get(size_t id);

  /// Mark an entry as released.
  void mark_released(size_t id);

 private:
  Registry() = default;

  mutable std::mutex mutex_;
  std::vector<HookEntry> entries_;
};

}  // namespace yukiplt::detail

#endif  // YUKIPLT_REGISTRY_HPP_
