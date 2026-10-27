// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "registry.hpp"

#include "common.hpp"

namespace yukiplt::detail {

Registry& Registry::instance() {
  // Never destroyed: a HookHandle (or a thread) may call in after static
  // destructors have begun.
  static NoDestructor<Registry> reg;
  return reg.get();
}

Registry::Record* Registry::resolve(uint64_t id) noexcept {
  if (id == kInvalidId) return nullptr;
  uint32_t index = static_cast<uint32_t>(id & 0xffffffffu);
  uint32_t gen = static_cast<uint32_t>(id >> 32);
  if (index >= records_.size()) return nullptr;
  Record& r = records_[index];
  if (!r.in_use || r.generation != gen) return nullptr;
  return &r;
}

const Registry::Record* Registry::resolve(uint64_t id) const noexcept {
  return const_cast<Registry*>(this)->resolve(id);
}

bool Registry::slot_is_live(uintptr_t addr) const noexcept {
  for (const Record& r : records_) {
    if (!r.in_use) continue;
    // An invalidated group (its image was forgotten) no longer owns its slots:
    // the caller has relinquished them, so a new instance may be hooked at the
    // same address.  The old group's handle still unhooks to kImageInvalidated.
    if (r.image.invalidated) continue;
    for (const SlotRecord& s : r.slots) {
      if (s.address == addr) return true;
    }
  }
  return false;
}

uint64_t Registry::claim(const ImageIdentity& image, const SlotRecord* slots, size_t count) {
  if (slots == nullptr || count == 0) return kInvalidId;

  // No slot may already be owned by a live group (one slot, one owner).  The
  // liveness test and the insert happen under one lock, closing the
  // check-then-insert race against a concurrent claim of the same slot.
  for (size_t i = 0; i < count; ++i) {
    if (slot_is_live(slots[i].address)) return kInvalidId;
  }

  uint32_t index;
  if (!free_list_.empty()) {
    index = free_list_[free_list_.size() - 1];
    free_list_.pop_back();
  } else {
    index = static_cast<uint32_t>(records_.size());
    records_.push_back(Record{});
    // Keep the free list able to hold every record without a later allocation,
    // so freeing a record (finish_restore/release) never throws.
    free_list_.reserve(records_.size());
  }

  Record& r = records_[index];
  r.in_use = true;
  r.state = GroupState::kPrepared;
  r.image = image;
  // Reserve now, before any memory is modified, so that recording the group's
  // slots and page residue after the commit cannot throw bad_alloc and leave
  // the record half-updated (AGENTS 4.4 / kOutOfMemory contract).  Every
  // residual page is a slot page, so `count` entries bound the residue too.
  r.slots.clear();
  r.slots.reserve(count);
  r.residue.clear();
  r.residue.reserve(count);
  for (size_t i = 0; i < count; ++i) r.slots.push_back(slots[i]);
  return make_id(r.generation, index);
}

void Registry::mark_installed(uint64_t id) {
  Record* r = resolve(id);
  if (r == nullptr || r->state != GroupState::kPrepared) return;
  r->state = GroupState::kInstalled;
}

void Registry::mark_indeterminate(uint64_t id, const SlotRecord* slots, size_t count,
                                  const PageResidueRecord* pages, size_t page_count) {
  Record* r = resolve(id);
  if (r == nullptr) return;
  r->state = GroupState::kIndeterminate;
  if (slots != nullptr) {
    r->slots.clear();
    for (size_t i = 0; i < count; ++i) r->slots.push_back(slots[i]);
  }
  r->residue.clear();
  for (size_t i = 0; i < page_count; ++i) r->residue.push_back(pages[i]);
}

void Registry::drop(uint64_t id) { release(id); }

Error Registry::begin_restore(uint64_t id, ImageIdentity& image, SlotRecord* slots, size_t slot_cap,
                              size_t* slot_count, PageResidueRecord* pages, size_t page_cap,
                              size_t* page_count) {
  Record* r = resolve(id);
  if (r == nullptr) return Error::Make(ErrorCode::kInvalidArgument);
  if (r->image.invalidated) return Error::Make(ErrorCode::kImageInvalidated);
  if (r->state != GroupState::kInstalled && r->state != GroupState::kIndeterminate)
    return Error::Make(ErrorCode::kNotInstalled);

  r->state = GroupState::kRestoring;
  image = r->image;
  size_t n = r->slots.size() < slot_cap ? r->slots.size() : slot_cap;
  for (size_t i = 0; i < n; ++i) slots[i] = r->slots[i];
  if (slot_count != nullptr) *slot_count = r->slots.size();
  size_t pn = r->residue.size() < page_cap ? r->residue.size() : page_cap;
  for (size_t i = 0; i < pn; ++i) pages[i] = r->residue[i];
  if (page_count != nullptr) *page_count = r->residue.size();
  return Error::Ok();
}

void Registry::finish_restore(uint64_t id, bool released, GroupState not_released_state,
                              const SlotRecord* slots, size_t slot_count,
                              const PageResidueRecord* pages, size_t page_count) {
  Record* r = resolve(id);
  if (r == nullptr) return;
  if (released) {
    r->in_use = false;
    ++r->generation;
    r->slots.clear();
    r->residue.clear();
    free_list_.push_back(static_cast<uint32_t>(id & 0xffffffffu));
    return;
  }
  r->state = not_released_state;
  if (slots != nullptr) {
    r->slots.clear();
    for (size_t i = 0; i < slot_count; ++i) r->slots.push_back(slots[i]);
  }
  if (pages != nullptr) {
    r->residue.clear();
    for (size_t i = 0; i < page_count; ++i) r->residue.push_back(pages[i]);
  }
}

Error Registry::release(uint64_t id) {
  Record* r = resolve(id);
  if (r == nullptr) return Error::Make(ErrorCode::kInvalidArgument);
  r->in_use = false;
  ++r->generation;
  r->slots.clear();
  r->residue.clear();
  free_list_.push_back(static_cast<uint32_t>(id & 0xffffffffu));
  return Error::Ok();
}

Error Registry::snapshot(uint64_t id, ImageIdentity& image, SlotRecord* slots, size_t cap,
                         size_t* count) const {
  const Record* r = resolve(id);
  if (r == nullptr) return Error::Make(ErrorCode::kInvalidArgument);
  image = r->image;
  size_t n = r->slots.size() < cap ? r->slots.size() : cap;
  for (size_t i = 0; i < n; ++i) slots[i] = r->slots[i];
  if (count != nullptr) *count = r->slots.size();
  return Error::Ok();
}

size_t Registry::forget_custom_image(const ImageIdentity& image) {
  size_t n = 0;
  for (Record& r : records_) {
    if (!r.in_use) continue;
    if (r.image.instance_token == 0) continue;  // system images are not forgettable
    if (r.image.load_bias == image.load_bias && r.image.phdr_addr == image.phdr_addr &&
        r.image.instance_token == image.instance_token) {
      r.image.invalidated = true;
      ++n;
    }
  }
  return n;
}

bool Registry::is_installed(uint64_t id) const {
  const Record* r = resolve(id);
  return r != nullptr && r->state == GroupState::kInstalled;
}

bool Registry::owns_live_replacement(uint64_t id) const {
  const Record* r = resolve(id);
  if (r == nullptr) return false;
  if (r->state == GroupState::kInstalled) return true;
  if (r->state == GroupState::kIndeterminate) {
    for (const SlotRecord& s : r->slots) {
      if (s.ever_written) return true;
    }
  }
  return false;
}

uintptr_t Registry::first_slot_of(uint64_t id) const {
  const Record* r = resolve(id);
  return (r != nullptr && !r->slots.empty()) ? r->slots[0].address : 0;
}

size_t Registry::live_count() const {
  size_t n = 0;
  for (const Record& r : records_) {
    if (r.in_use) ++n;
  }
  return n;
}

}  // namespace yukiplt::detail
