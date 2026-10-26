// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "yukiplt.hpp"

#include <cstdio>
#include <cstring>
#include <mutex>
#include <new>

#include "common.hpp"
#include "elf.hpp"
#include "memory.hpp"
#include "registry.hpp"

#if defined(__linux__) || defined(__ANDROID__)
#include <link.h>
#include <sys/auxv.h>
#endif

namespace yukiplt {

using detail::CommitMode;
using detail::CommitResult;
using detail::GroupState;
using detail::ImageIdentity;
using detail::InspectedImage;
using detail::PageResidueRecord;
using detail::Registry;
using detail::SlotOp;
using detail::SlotOutcome;
using detail::SlotRecord;
using detail::Txn;

/// Grants the API functions access to HookHandle's private id.  (Named as a
/// friend in the header.)
class detail_api {
 public:
  static HookHandle make(uint64_t id) noexcept { return HookHandle(id); }
  static uint64_t id(const HookHandle& h) noexcept { return h.id_; }
  static void set(HookHandle& h, uint64_t id) noexcept { h.id_ = id; }
  static constexpr uint64_t invalid() noexcept { return HookHandle::kInvalid; }
};

namespace {

constexpr size_t kMaxBatch = 64;  // Upper bound on slots in one transaction.

SlotStatus to_status(SlotOutcome o) noexcept {
  switch (o) {
    case SlotOutcome::kCommitted:
      return SlotStatus::kInstalled;
    case SlotOutcome::kConflict:
      return SlotStatus::kConflict;
    case SlotOutcome::kRolledBack:
      return SlotStatus::kRolledBack;
    case SlotOutcome::kRollbackFailed:
      return SlotStatus::kRollbackFailed;
    case SlotOutcome::kUntouched:
    default:
      return SlotStatus::kUntouched;
  }
}

ImageIdentity identity_of(const ImageView& v) noexcept {
  ImageIdentity id;
  id.load_bias = v.load_bias;
  id.phdr_addr = reinterpret_cast<uintptr_t>(v.phdr_table);
  id.phdr_count = v.phdr_count;
  id.instance_token = v.instance_token;
  return id;
}

/// Run `fn(live)` on the loaded system image matching `want`, with the dynamic
/// linker's lock held (so the image cannot be unloaded during the call) and the
/// op lock acquired inside it.
///
/// Lock order is linker -> op, never the reverse: the op lock is only ever
/// taken inside this callback for an image operation, or standalone for a
/// registry-only operation that never calls dl_*.  dl_iterate_phdr is C, so an
/// exception must not escape `fn`; callers make `fn` catch its own allocation
/// failures.  Returns true if the image was found (and `fn` ran).
template <typename Fn>
bool run_on_system_image(const ImageIdentity& want, Fn&& fn) {
#if defined(__linux__) || defined(__ANDROID__)
  struct Ctx {
    const ImageIdentity* want;
    Fn* fn;
    bool matched;
  } ctx{&want, &fn, false};

  dl_iterate_phdr(
      [](struct dl_phdr_info* info, size_t /*size*/, void* p) -> int {
        auto* c = static_cast<Ctx*>(p);
        if (static_cast<uintptr_t>(info->dlpi_addr) != c->want->load_bias ||
            reinterpret_cast<uintptr_t>(info->dlpi_phdr) != c->want->phdr_addr ||
            info->dlpi_phnum != c->want->phdr_count) {
          return 0;
        }
        ImageView live;
        live.load_bias = static_cast<uintptr_t>(info->dlpi_addr);
        live.phdr_table = info->dlpi_phdr;
        live.phdr_count = info->dlpi_phnum;
        live.instance_token = 0;
        std::lock_guard<std::mutex> lock(detail::op_mutex());  // linker -> op
        (*c->fn)(live);
        c->matched = true;
        return 1;
      },
      &ctx);
  return ctx.matched;
#else
  (void)want;
  (void)fn;
  return false;
#endif
}

/// A resolved request: the slot and the values to install.
struct PlannedSlot {
  uintptr_t address;
  uintptr_t original;
  uintptr_t replacement;
  void** out_original;
  size_t report_index;  ///< Index into the caller's reports array.
};

/// Resolve every request against `img` to a unique slot, enforcing one-slot
/// uniqueness and no duplicate targets within the batch.
Error plan_requests(const InspectedImage& img, const HookRequest* reqs, size_t count,
                    detail::SmallVec<PlannedSlot, 4>& out) {
  for (size_t i = 0; i < count; ++i) {
    if (reqs[i].symbol == nullptr || reqs[i].replacement == nullptr)
      return Error::Make(ErrorCode::kNullPointer);

    auto slot = detail::resolve_unique_slot(img, reqs[i].symbol);
    if (!slot) return slot.error();

    uintptr_t addr = slot.value().address;
    for (const PlannedSlot& p : out) {
      if (p.address == addr) return Error::Make(ErrorCode::kInvalidArgument);  // duplicate target
    }
    PlannedSlot ps;
    ps.address = addr;
    ps.original = 0;
    ps.replacement = reinterpret_cast<uintptr_t>(reqs[i].replacement);
    ps.out_original = reqs[i].out_original;
    ps.report_index = i;
    out.push_back(ps);
  }
  return Error::Ok();
}

void write_reports(SlotReport* reports, size_t cap, const detail::SmallVec<PlannedSlot, 4>& planned,
                   const SlotOp* ops, size_t count) {
  if (reports == nullptr) return;
  for (size_t i = 0; i < count; ++i) {
    size_t ri = planned[i].report_index;
    if (ri >= cap) continue;
    reports[ri].address = ops[i].slot;
    reports[ri].value_before = planned[i].original;
    reports[ri].value_observed = ops[i].observed;
    reports[ri].status = to_status(ops[i].outcome);
  }
}

/// Core install path for one image, run under the op lock.  `img` must be a
/// freshly inspected, currently-valid image.
HookResult install(const ImageView& view, const InspectedImage& img, const HookRequest* reqs,
                   size_t count, SlotReport* reports, size_t report_cap) {
  detail::SmallVec<PlannedSlot, 4> planned;
  Error plan = plan_requests(img, reqs, count, planned);
  if (plan) return {plan, detail_api::make(detail_api::invalid())};

  const size_t ps = detail::page_size();
  if (ps == 0)
    return {Error::Make(ErrorCode::kUnsupportedFormat), detail_api::make(detail_api::invalid())};

  // Reserve ownership of every slot before any write (one slot, one owner).
  SlotRecord recs[kMaxBatch];
  uintptr_t slot_addrs[kMaxBatch];
  for (size_t i = 0; i < planned.size(); ++i) {
    recs[i].address = planned[i].address;
    recs[i].replacement = planned[i].replacement;
    slot_addrs[i] = planned[i].address;
  }
  Registry& reg = Registry::instance();
  uint64_t id = reg.claim(identity_of(view), recs, planned.size());
  if (id == Registry::kInvalidId)
    return {Error::Make(ErrorCode::kAlreadyHooked), detail_api::make(detail_api::invalid())};

  Txn txn(detail::system_ops(), ps);
  Error prep = txn.prepare(slot_addrs, planned.size());
  if (prep) {
    reg.drop(id);
    return {prep, detail_api::make(detail_api::invalid())};
  }

  // Read current slot values (now confirmed mapped and readable), fill the
  // ops, and publish each out_original before the commit makes a replacement
  // reachable.  out_original is never cleared once set.
  SlotOp ops[kMaxBatch];
  for (size_t i = 0; i < planned.size(); ++i) {
    uintptr_t cur = 0;
    txn.load(planned[i].address, cur);
    planned[i].original = cur;
    if (cur == planned[i].replacement) {  // replacement == current value: ambiguous ownership
      reg.drop(id);
      return {Error::Make(ErrorCode::kInvalidArgument), detail_api::make(detail_api::invalid())};
    }
    ops[i].slot = planned[i].address;
    ops[i].expected = cur;
    ops[i].desired = planned[i].replacement;
  }
  for (size_t i = 0; i < planned.size(); ++i) {
    if (planned[i].out_original != nullptr)
      *planned[i].out_original = reinterpret_cast<void*>(planned[i].original);
    // Update the registry's recorded original now that it is known.
    recs[i].original = planned[i].original;
  }

  CommitResult r = txn.commit(ops, planned.size(), CommitMode::kAllOrNothing);
  write_reports(reports, report_cap, planned, ops, planned.size());

  if (r.raise_errno != 0) {
    reg.drop(id);
    return {Error::Sys(ErrorCode::kPermissionDenied, r.raise_errno),
            detail_api::make(detail_api::invalid())};
  }

  if (r.all_committed && r.pages_restored) {
    // Record the final originals and mark installed.
    reg.finish_restore(id, /*released=*/false, GroupState::kPrepared, recs, planned.size(), nullptr,
                       0);
    reg.mark_installed(id);
    return {Error::Ok(), detail_api::make(id)};
  }

  if (r.rollback_failed || !r.pages_restored) {
    // Partial recovery: keep the group, record actual values and page residue.
    for (size_t i = 0; i < planned.size(); ++i) {
      recs[i].original = planned[i].original;
      // The slot currently holds observed; replacement stays what we tried.
    }
    PageResidueRecord pr[kMaxBatch];
    detail::PageResidue res[kMaxBatch];
    size_t pn = txn.residue(res, kMaxBatch);
    if (pn > kMaxBatch) pn = kMaxBatch;
    for (size_t i = 0; i < pn; ++i) {
      pr[i].page = res[i].page;
      pr[i].original_prot = res[i].original_prot;
    }
    reg.mark_indeterminate(id, recs, planned.size(), pr, pn);
    return {Error::Make(ErrorCode::kIndeterminate), detail_api::make(id)};
  }

  // A clean conflict: everything rolled back, pages restored, nothing installed.
  reg.drop(id);
  return {Error::Make(ErrorCode::kSlotOwnershipConflict), detail_api::make(detail_api::invalid())};
}

}  // namespace
// HookHandle

HookHandle::~HookHandle() { warn_if_installed(); }

HookHandle& HookHandle::operator=(HookHandle&& o) noexcept {
  if (this != &o) {
    warn_if_installed();
    id_ = o.id_;
    o.id_ = kInvalid;
  }
  return *this;
}

void HookHandle::warn_if_installed() const noexcept {
  if (id_ == kInvalid) return;
  std::lock_guard<std::mutex> lock(detail::op_mutex());
  auto& reg = Registry::instance();
  if (reg.is_installed(id_)) {
    std::fprintf(stderr,
                 "[YukiPLT] WARNING: HookHandle dropped while hook is still "
                 "installed (slot 0x%zx)\n",
                 static_cast<size_t>(reg.first_slot_of(id_)));
  }
}
// image_from_soname

Result<ImageView> image_from_soname(const char* soname) {
#if defined(__linux__) || defined(__ANDROID__)
  struct CallbackData {
    const char* target;
    uintptr_t main_phdr;
    ImageView result;
    size_t matches;
  };

  CallbackData data;
  data.target = (soname != nullptr && soname[0] != '\0') ? soname : nullptr;
  data.main_phdr = static_cast<uintptr_t>(getauxval(AT_PHDR));
  data.result = {};
  data.matches = 0;

  if (data.target == nullptr && data.main_phdr == 0) return Error::Make(ErrorCode::kImageNotFound);

  dl_iterate_phdr(
      [](struct dl_phdr_info* info, size_t /*size*/, void* ctx) -> int {
        auto* d = static_cast<CallbackData*>(ctx);
        const char* name = info->dlpi_name;

        bool match = false;
        if (d->target == nullptr) {
          match = reinterpret_cast<uintptr_t>(info->dlpi_phdr) == d->main_phdr;
        } else if (name != nullptr) {
          if (std::strchr(d->target, '/') != nullptr) {
            match = std::strcmp(name, d->target) == 0;
          } else {
            size_t name_len = std::strlen(name);
            size_t target_len = std::strlen(d->target);
            match = std::strcmp(name, d->target) == 0 ||
                    (name_len > target_len && name[name_len - target_len - 1] == '/' &&
                     std::strcmp(name + name_len - target_len, d->target) == 0);
          }
        }

        if (match) {
          d->result.load_bias = static_cast<uintptr_t>(info->dlpi_addr);
          d->result.phdr_table = info->dlpi_phdr;
          d->result.phdr_count = info->dlpi_phnum;
          d->result.instance_token = 0;
          ++d->matches;
        }
        return 0;
      },
      &data);

  if (data.matches == 0) return Error::Make(ErrorCode::kImageNotFound);
  if (data.matches > 1) return Error::Make(ErrorCode::kAmbiguousImage);
  return data.result;
#else
  (void)soname;
  return Error::Make(ErrorCode::kUnsupportedFormat);
#endif
}
// hook / hook_batch

HookResult hook(const ImageView& image, const char* symbol_name, void* replacement,
                void** out_original, SlotReport* report) {
  HookRequest req;
  req.symbol = symbol_name;
  req.replacement = replacement;
  req.out_original = out_original;
  return hook_batch(image, &req, 1, report);
}

HookResult hook_batch(const ImageView& image, const HookRequest* reqs, size_t count,
                      SlotReport* reports) {
  auto fail = [](ErrorCode c) {
    return HookResult{Error::Make(c), detail_api::make(detail_api::invalid())};
  };
  if (reqs == nullptr || count == 0) return fail(ErrorCode::kNullPointer);
  if (count > kMaxBatch) return fail(ErrorCode::kInvalidArgument);

  if (image.instance_token == 0) {
    // Keep inspection and installation inside the linker callback, taking op
    // after linker so unloading cannot invalidate the image during access.
    HookResult result = fail(ErrorCode::kImageNotFound);
    bool matched = run_on_system_image(identity_of(image), [&](const ImageView& live) {
      try {
        auto insp = detail::inspect(live.load_bias, live.phdr_table, live.phdr_count);
        if (!insp) {
          result = {insp.error(), detail_api::make(detail_api::invalid())};
          return;
        }
        result = install(image, insp.value(), reqs, count, reports, count);
      } catch (const std::bad_alloc&) {
        result = fail(ErrorCode::kOutOfMemory);
      }
    });
    if (!matched) return fail(ErrorCode::kImageNotFound);
    return result;
  }

  // Custom image: the caller guarantees it stays mapped (contract).
  try {
    std::lock_guard<std::mutex> lock(detail::op_mutex());
    auto insp = detail::inspect(image.load_bias, image.phdr_table, image.phdr_count);
    if (!insp) return {insp.error(), detail_api::make(detail_api::invalid())};
    return install(image, insp.value(), reqs, count, reports, count);
  } catch (const std::bad_alloc&) {
    return fail(ErrorCode::kOutOfMemory);
  }
}
// unhook

namespace {

/// The restore transaction, run with the op lock held and (for a system image)
/// inside the linker callback.  `image_live` is true when the image is known to
/// be mapped right now: for a system image, because we are inside
/// dl_iterate_phdr; for a custom image, by the caller's contract.
Error do_restore(uint64_t id, HookHandle& handle, bool image_live, SlotReport* reports,
                 size_t cap) {
  Registry& reg = Registry::instance();

  ImageIdentity image;
  SlotRecord recs[kMaxBatch];
  size_t slot_count = 0;
  PageResidueRecord pages[kMaxBatch];
  size_t page_count = 0;
  Error begin =
      reg.begin_restore(id, image, recs, kMaxBatch, &slot_count, pages, kMaxBatch, &page_count);
  if (begin) {
    if (begin.code == ErrorCode::kImageInvalidated) {
      reg.release(id);  // custom image forgotten: consume the handle
      detail_api::set(handle, detail_api::invalid());
    }
    return begin;
  }
  if (slot_count > kMaxBatch) slot_count = kMaxBatch;

  // A system image that we could not find under the linker lock is gone.
  if (!image_live) {
    reg.finish_restore(id, true, GroupState::kInstalled, nullptr, 0, nullptr, 0);
    detail_api::set(handle, detail_api::invalid());
    return Error::Make(ErrorCode::kImageInvalidated);
  }

  const size_t ps = detail::page_size();
  if (ps == 0) {
    reg.finish_restore(id, false, GroupState::kInstalled, recs, slot_count, pages, page_count);
    return Error::Make(ErrorCode::kUnsupportedFormat);
  }

  // Build the page set: slot pages plus any residual raised pages.
  uintptr_t slot_addrs[kMaxBatch];
  uintptr_t extra_pages[kMaxBatch];
  for (size_t i = 0; i < slot_count; ++i) slot_addrs[i] = recs[i].address;
  for (size_t i = 0; i < page_count; ++i) extra_pages[i] = pages[i].page;

  Txn txn(detail::system_ops(), ps);
  Error prep = txn.prepare(slot_count > 0 ? slot_addrs : nullptr, slot_count,
                           page_count > 0 ? extra_pages : nullptr, page_count);
  if (prep) {
    // Could not even map the slots.  If the whole image page is gone, treat it
    // as invalidated; otherwise keep the handle for a retry.
    if (prep.code == ErrorCode::kOutOfBounds || prep.code == ErrorCode::kVmaUnavailable) {
      reg.finish_restore(id, true, GroupState::kInstalled, nullptr, 0, nullptr, 0);
      detail_api::set(handle, detail_api::invalid());
      return Error::Make(ErrorCode::kImageInvalidated);
    }
    reg.finish_restore(id, false, GroupState::kInstalled, recs, slot_count, pages, page_count);
    return prep;
  }

  // Never-written slots need no recovery. CAS replacement to original; accept
  // already-original values and preserve conflicting third-party values.
  SlotOp ops[kMaxBatch];
  size_t op_count = 0;
  bool any_foreign = false;
  for (size_t i = 0; i < slot_count; ++i) {
    uintptr_t cur = 0;
    txn.load(recs[i].address, cur);
    if (cur == recs[i].replacement) {
      ops[op_count].slot = recs[i].address;
      ops[op_count].expected = recs[i].replacement;
      ops[op_count].desired = recs[i].original;
      ++op_count;
    } else if (cur != recs[i].original) {
      any_foreign = true;
    }
  }

  // Put back any residual raised page even if no slot needs a CAS.
  bool restore_ok = true;
  int restore_errno = 0;
  for (size_t i = 0; i < page_count; ++i) {
    int e = txn.protect_page(pages[i].page, pages[i].original_prot);
    if (e != 0) {
      restore_ok = false;
      if (restore_errno == 0) restore_errno = e;
    }
  }

  CommitResult r{};
  if (op_count > 0) {
    r = txn.commit(ops, op_count, CommitMode::kAllOrNothing);
  }

  // Unhook CAS: Committed restores original; RolledBack reinstalls replacement;
  // Conflict/RollbackFailed preserves the third-party value.
  size_t oi = 0;
  bool all_restored = true;
  bool rollback_failed = r.rollback_failed;
  for (size_t i = 0; i < slot_count; ++i) {
    SlotStatus st;
    uintptr_t observed = recs[i].original;
    if (i < cap && reports != nullptr) {
      reports[i].address = recs[i].address;
      reports[i].value_before = recs[i].replacement;
    }
    // Was this slot part of the CAS set?
    bool was_op = oi < op_count && ops[oi].slot == recs[i].address;
    if (was_op) {
      SlotOutcome o = ops[oi].outcome;
      observed = ops[oi].observed;
      st = (o == SlotOutcome::kCommitted || o == SlotOutcome::kRolledBack) ? SlotStatus::kRestored
                                                                           : to_status(o);
      if (o != SlotOutcome::kCommitted && o != SlotOutcome::kRolledBack) all_restored = false;
      ++oi;
    } else {
      // Not CAS'd: either already original (restored) or foreign (conflict).
      uintptr_t cur = 0;
      txn.load(recs[i].address, cur);
      if (cur == recs[i].original) {
        st = SlotStatus::kRestored;
      } else {
        st = SlotStatus::kConflict;
        observed = cur;
        all_restored = false;
      }
    }
    if (i < cap && reports != nullptr) {
      reports[i].value_observed = observed;
      reports[i].status = st;
    }
  }

  if (r.raise_errno != 0) {
    reg.finish_restore(id, false, GroupState::kInstalled, recs, slot_count, pages, page_count);
    return Error::Sys(ErrorCode::kPermissionDenied, r.raise_errno);
  }

  // Recompute remaining residue after this attempt.
  PageResidueRecord new_pages[kMaxBatch];
  detail::PageResidue res[kMaxBatch];
  size_t pn = txn.residue(res, kMaxBatch);
  if (pn > kMaxBatch) pn = kMaxBatch;
  for (size_t i = 0; i < pn; ++i) {
    new_pages[i].page = res[i].page;
    new_pages[i].original_prot = res[i].original_prot;
  }
  bool pages_clean = r.pages_restored && restore_ok && pn == 0;

  if (all_restored && pages_clean && !rollback_failed) {
    reg.finish_restore(id, true, GroupState::kInstalled, nullptr, 0, nullptr, 0);
    detail_api::set(handle, detail_api::invalid());
    return Error::Ok();
  }

  if (rollback_failed || !pages_clean) {
    reg.finish_restore(id, false, GroupState::kIndeterminate, recs, slot_count, new_pages, pn);
    if (!restore_ok && restore_errno != 0)
      return Error::Sys(ErrorCode::kIndeterminate, restore_errno);
    return Error::Make(ErrorCode::kIndeterminate);
  }

  // Slots left as a third party's value: keep ownership for a later retry.
  (void)any_foreign;
  reg.finish_restore(id, false, GroupState::kInstalled, recs, slot_count, new_pages, pn);
  return Error::Make(ErrorCode::kSlotModifiedExternally);
}

/// Read a group's image token under the op lock, without changing its state.
/// Returns kInvalidArgument for a bad id.  Used to route unhook to the system
/// (linker-lock) or custom path before touching registry state.
Error peek_image(uint64_t id, ImageIdentity& out) {
  ImageIdentity image;
  SlotRecord recs[1];
  size_t n = 0;
  Error e = Registry::instance().snapshot(id, image, recs, 1, &n);
  if (e) return e;
  out = image;
  return Error::Ok();
}

}  // namespace

Error unhook(HookHandle& handle, SlotReport* reports, size_t cap) {
  if (!handle.valid()) return Error::Make(ErrorCode::kInvalidArgument);
  uint64_t id = detail_api::id(handle);
  try {
    // Learn the image token first (brief op-lock) so we can pick the lock order.
    ImageIdentity image;
    {
      std::lock_guard<std::mutex> lock(detail::op_mutex());
      Error peek = peek_image(id, image);
      if (peek) return peek;
    }

    if (image.instance_token == 0 && !image.invalidated) {
      // System image: restore inside the linker callback (linker -> op order).
      Error result = Error::Make(ErrorCode::kImageInvalidated);
      bool matched = run_on_system_image(image, [&](const ImageView&) {
        try {
          result = do_restore(id, handle, /*image_live=*/true, reports, cap);
        } catch (const std::bad_alloc&) {
          result = Error::Make(ErrorCode::kOutOfMemory);
        }
      });
      if (!matched) {
        // The image is gone: consume the handle without touching memory.
        std::lock_guard<std::mutex> lock(detail::op_mutex());
        return do_restore(id, handle, /*image_live=*/false, reports, cap);
      }
      return result;
    }

    // Custom image (or already-forgotten): the caller guarantees mapping.
    std::lock_guard<std::mutex> lock(detail::op_mutex());
    return do_restore(id, handle, /*image_live=*/true, reports, cap);
  } catch (const std::bad_alloc&) {
    return Error::Make(ErrorCode::kOutOfMemory);
  }
}
// abandon / query / forget_image

Error abandon(HookHandle& handle) {
  if (!handle.valid()) return Error::Make(ErrorCode::kInvalidArgument);
  std::lock_guard<std::mutex> lock(detail::op_mutex());
  Error e = Registry::instance().release(detail_api::id(handle));
  if (!e) detail_api::set(handle, detail_api::invalid());
  return e;
}

Error query(const HookHandle& handle, SlotReport* out, size_t cap, size_t* count) {
  if (!handle.valid()) return Error::Make(ErrorCode::kInvalidArgument);
  try {
    std::lock_guard<std::mutex> lock(detail::op_mutex());
    Registry& reg = Registry::instance();

    ImageIdentity image;
    SlotRecord recs[kMaxBatch];
    size_t n = 0;
    Error snap = reg.snapshot(detail_api::id(handle), image, recs, kMaxBatch, &n);
    if (snap) return snap;
    if (n > kMaxBatch) n = kMaxBatch;
    if (count != nullptr) *count = n;

    const size_t ps = detail::page_size();
    for (size_t i = 0; i < n && i < cap && out != nullptr; ++i) {
      out[i].address = recs[i].address;
      out[i].value_before = recs[i].original;
      out[i].value_observed = recs[i].replacement;
      out[i].status = SlotStatus::kUntouched;
      // Best-effort live read of the slot via a one-page transaction.
      if (ps != 0 && !image.invalidated) {
        Txn txn(detail::system_ops(), ps);
        uintptr_t one = recs[i].address;
        if (!txn.prepare(&one, 1)) {
          uintptr_t cur = 0;
          if (txn.load(recs[i].address, cur)) out[i].value_observed = cur;
        }
      }
    }
    return Error::Ok();
  } catch (const std::bad_alloc&) {
    return Error::Make(ErrorCode::kOutOfMemory);
  }
}

Error forget_image(const ImageView& custom_image) {
  if (custom_image.instance_token == 0) return Error::Make(ErrorCode::kInvalidArgument);
  std::lock_guard<std::mutex> lock(detail::op_mutex());
  Registry::instance().forget_custom_image(identity_of(custom_image));
  return Error::Ok();
}

}  // namespace yukiplt
