// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "registry.hpp"

#include <algorithm>

namespace yukiplt::detail {

Registry& Registry::instance() {
  static Registry reg;
  return reg;
}

bool Registry::is_slot_hooked(uintptr_t slot_addr) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return std::any_of(entries_.begin(), entries_.end(), [slot_addr](const HookEntry& e) {
    return e.slot_addr == slot_addr && e.state == HookState::kInstalled;
  });
}

size_t Registry::add(HookEntry entry) {
  std::lock_guard<std::mutex> lock(mutex_);
  size_t id = entries_.size();
  entries_.push_back(entry);
  return id;
}

HookEntry* Registry::get(size_t id) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (id >= entries_.size()) return nullptr;
  return &entries_[id];
}

void Registry::mark_released(size_t id) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (id < entries_.size()) {
    entries_[id].state = HookState::kReleased;
  }
}

}  // namespace yukiplt::detail
