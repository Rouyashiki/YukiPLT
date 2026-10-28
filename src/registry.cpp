// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "registry.hpp"

#include "common.hpp"
#include "memory.hpp"

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
  // An invalidated group (its image was forgotten) no longer owns its slots: the
  // caller has relinquished them, so a new instance may be hooked at the same
  // address.  forget_custom_image() removes such a group's slots from the index,
  // so presence in the index is exactly "owned by a live, non-invalidated group".
  return index_find(addr) != index_.size();
}

namespace {
// Fibonacci hashing of a GOT slot address; retain the distinguishing bit of
// adjacent 4-byte slots on a 32-bit process.
inline size_t slot_hash(uintptr_t addr, size_t mask) noexcept {
  return static_cast<size_t>((static_cast<uint64_t>(addr >> (sizeof(uintptr_t) == 8 ? 3 : 2)) *
                              0x9E3779B97F4A7C15ull) >>
                             17) &
         mask;
}
}  // namespace

size_t Registry::index_find(uintptr_t addr) const noexcept {
  const size_t cap = index_.size();
  if (cap == 0 || addr == 0) return cap;
  const size_t mask = cap - 1;
  for (size_t i = slot_hash(addr, mask);; i = (i + 1) & mask) {
    if (index_[i].address == addr) return i;
    if (index_[i].address == 0) return cap;
  }
}

void Registry::index_insert(uintptr_t addr, uint32_t record) noexcept {
  // Capacity was reserved by index_reserve(); the load factor stays <= 1/2, so
  // an empty position always exists.
  const size_t mask = index_.size() - 1;
  size_t i = slot_hash(addr, mask);
  while (index_[i].address != 0) i = (i + 1) & mask;
  index_[i].address = addr;
  index_[i].record = record;
  ++index_used_;
}

void Registry::index_erase(uintptr_t addr, uint32_t record) noexcept {
  size_t i = index_find(addr);
  if (i == index_.size() || index_[i].record != record) return;
  // Backward-shift deletion keeps every probe chain unbroken without tombstones.
  const size_t mask = index_.size() - 1;
  size_t hole = i;
  for (size_t j = (hole + 1) & mask; index_[j].address != 0; j = (j + 1) & mask) {
    const size_t home = slot_hash(index_[j].address, mask);
    // Move j into the hole if its home position does not lie cyclically in (hole, j].
    const bool in_range = hole <= j ? (home > hole && home <= j) : (home > hole || home <= j);
    if (!in_range) {
      index_[hole] = index_[j];
      hole = j;
    }
  }
  index_[hole] = IndexEntry{};
  --index_used_;
}

void Registry::index_erase_record(const Record& r, uint32_t record) noexcept {
  for (const SlotRecord& s : r.slots) index_erase(s.address, record);
}

void Registry::index_reserve(size_t extra) {
  const size_t needed = index_used_ + extra;
  size_t cap = index_.size();
  if (cap != 0 && needed * 2 <= cap) return;
  if (cap == 0) cap = 16;
  while (needed * 2 > cap) cap *= 2;
  SmallVec<IndexEntry, 16> table;
  table.reserve(cap);
  for (size_t i = 0; i < cap; ++i) table.push_back(IndexEntry{});  // reserved: no throw
  // Rehash the live entries into the new table (nothing can throw from here).
  const size_t mask = cap - 1;
  for (const IndexEntry& e : index_) {
    if (e.address == 0) continue;
    size_t i = slot_hash(e.address, mask);
    while (table[i].address != 0) i = (i + 1) & mask;
    table[i] = e;
  }
  index_ = std::move(table);
}

uint64_t Registry::claim(const ImageIdentity& image, const SlotRecord* slots, size_t count) {
  if (slots == nullptr || count == 0) return kInvalidId;

  // No slot may already be owned by a live group (one slot, one owner).  The
  // liveness test and the insert happen under one lock, closing the
  // check-then-insert race against a concurrent claim of the same slot.
  for (size_t i = 0; i < count; ++i) {
    if (slot_is_live(slots[i].address)) return kInvalidId;
  }

  // Grow the index before anything else, so inserting below cannot fail.
  index_reserve(count);

  if (free_list_.empty()) {
    // Keep the free list able to hold every record without a later allocation,
    // so freeing a record (finish_restore/release) never throws. Reserve before
    // adding the record, so either allocation can fail without losing it.
    free_list_.reserve(records_.size() + 1);
    const auto index = static_cast<uint32_t>(records_.size());
    records_.push_back(Record{});
    free_list_.push_back(index);
  }

  const uint32_t index = free_list_[free_list_.size() - 1];
  Record& r = records_[index];
  // Reserve now, before any memory is modified, so that recording the group's
  // slots and page residue after the commit cannot throw bad_alloc and leave
  // the record half-updated (kOutOfMemory contract). Every
  // residual page is a slot page, so `count` entries bound the residue too.
  r.slots.reserve(count);
  r.residue.reserve(count);
  // Do not consume the free entry or publish ownership until all allocation
  // has succeeded. An exception leaves this record available for a retry.
  r.slots.clear();
  r.residue.clear();
  for (size_t i = 0; i < count; ++i) r.slots.push_back(slots[i]);
  r.image = image;
  r.diagnostic = {};
  r.state = GroupState::kPrepared;
  r.in_use = true;
  free_list_.pop_back();
  for (size_t i = 0; i < count; ++i) index_insert(slots[i].address, index);
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
    // The written-back slots are the group's own slots with updated values; the
    // addresses (and so the index) do not change.  `count` never exceeds the
    // reserved capacity, so these push_backs cannot allocate.
    r->slots.clear();
    for (size_t i = 0; i < count; ++i) r->slots.push_back(slots[i]);
  }
  r->residue.clear();
  for (size_t i = 0; i < page_count; ++i) r->residue.push_back(pages[i]);
}

void Registry::drop(uint64_t id) { (void)release(id); }

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
    const auto index = static_cast<uint32_t>(id & 0xffffffffu);
    if (!r->image.invalidated) index_erase_record(*r, index);
    r->in_use = false;
    ++r->generation;
    r->slots.clear();
    r->residue.clear();
    free_list_.push_back(index);
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
  const auto index = static_cast<uint32_t>(id & 0xffffffffu);
  if (!r->image.invalidated) index_erase_record(*r, index);
  r->in_use = false;
  ++r->generation;
  r->slots.clear();
  r->residue.clear();
  free_list_.push_back(index);
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

void Registry::record_diagnostic(uint64_t id, const RecoveryDiagnostic& diagnostic) noexcept {
  if (Record* r = resolve(id)) r->diagnostic = diagnostic;
}

Error Registry::recovery_snapshot(uint64_t id, RecoveryDiagnostic& diagnostic, ResidualPage* pages,
                                  size_t capacity) const noexcept {
  const Record* r = resolve(id);
  if (r == nullptr) return Error::Make(ErrorCode::kInvalidArgument);
  diagnostic = r->diagnostic;
  diagnostic.image_invalidated = r->image.invalidated;
  diagnostic.residual_page_count = r->residue.size();
  for (size_t i = 0; i < capacity && i < r->residue.size(); ++i) {
    const auto& p = r->residue[i];
    pages[i] = {p.page, static_cast<uint32_t>(p.original_prot),
                static_cast<uint32_t>(p.original_prot | kProtWrite), p.sys_errno};
  }
  return Error::Ok();
}

size_t Registry::forget_custom_image(const ImageIdentity& image) {
  size_t n = 0;
  for (size_t index = 0; index < records_.size(); ++index) {
    Record& r = records_[index];
    if (!r.in_use || r.image.invalidated) continue;
    if (r.image.instance_token == 0) continue;  // system images are not forgettable
    if (r.image.load_bias == image.load_bias && r.image.phdr_addr == image.phdr_addr &&
        r.image.phdr_count == image.phdr_count && r.image.instance_token == image.instance_token) {
      // An invalidated group no longer owns its slots; drop them from the index
      // so a new instance at the same address can be claimed.
      index_erase_record(r, static_cast<uint32_t>(index));
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
