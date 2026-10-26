// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "registry.hpp"

#include "common.hpp"

namespace yukiplt::detail {

Registry& Registry::instance() {
  // Never destroyed: see NoDestructor for why exit-time teardown is unsafe.
  static NoDestructor<Registry> reg;
  return reg.get();
}

size_t Registry::claim(const HookEntry& info) {
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto& rec : records_) {
    if (rec.entry.slot_addr == info.slot_addr && is_live(rec.state)) {
      return kInvalidId;  // Slot already reserved by a live entry.
    }
  }
  size_t id = records_.size();
  records_.push_back({info, HookState::kPrepared});
  return id;
}

bool Registry::mark_installed(size_t id) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (id >= records_.size()) return false;
  if (records_[id].state != HookState::kPrepared) return false;
  records_[id].state = HookState::kInstalled;
  return true;
}

void Registry::mark_failed(size_t id) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (id >= records_.size()) return;
  records_[id].state = HookState::kFailed;
}

Error Registry::begin_restore(size_t id, HookEntry& out) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (id >= records_.size()) return Error::Make(ErrorCode::kInvalidArgument);
  if (records_[id].state != HookState::kInstalled) return Error::Make(ErrorCode::kNotInstalled);
  records_[id].state = HookState::kRestoring;
  out = records_[id].entry;
  return Error::Ok();
}

void Registry::finish_restore(size_t id, bool success) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (id >= records_.size()) return;
  records_[id].state = success ? HookState::kReleased : HookState::kFailed;
}

bool Registry::is_installed(size_t id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (id >= records_.size()) return false;
  return records_[id].state == HookState::kInstalled;
}

uintptr_t Registry::slot_of(size_t id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (id >= records_.size()) return 0;
  return records_[id].entry.slot_addr;
}

}  // namespace yukiplt::detail
