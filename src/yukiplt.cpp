// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "yukiplt.hpp"

#include <cstdio>
#include <cstring>
#include <mutex>
#include <new>
#include <stdexcept>

#include "common.hpp"
#include "elf.hpp"
#include "imports.hpp"
#include "memory.hpp"
#include "registry.hpp"
#include "system_images.hpp"

#if defined(__linux__) || defined(__ANDROID__)
#include <link.h>
#include <sys/auxv.h>

#include <exception>
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
/// op lock acquired inside it.  If `want_path` is non-null, the live entry's
/// name (dlpi_name, or "" when absent, as find_images() reports it) must also
/// equal it; an entry with the same bias/phdr/phnum but another name is a
/// different image and does not match.
///
/// Lock order is linker -> op, never the reverse: the op lock is only ever
/// taken inside this callback for an image operation, or standalone for a
/// registry-only operation that never calls dl_*.  dl_iterate_phdr is C, so no
/// exception may unwind through it: one thrown by the lock or by `fn` is
/// captured and rethrown after the iteration returns.  Returns true if the
/// image was found (and `fn` ran).
template <typename Fn>
bool run_on_system_image(const ImageIdentity& want, Fn&& fn, const char* want_path = nullptr) {
#if defined(__linux__) || defined(__ANDROID__)
  struct Ctx {
    const ImageIdentity* want;
    const char* want_path;
    Fn* fn;
    bool matched;
    std::exception_ptr error;
  } ctx{&want, want_path, &fn, false, nullptr};

  dl_iterate_phdr(
      [](struct dl_phdr_info* info, size_t /*size*/, void* p) -> int {
        auto* c = static_cast<Ctx*>(p);
        if (static_cast<uintptr_t>(info->dlpi_addr) != c->want->load_bias ||
            reinterpret_cast<uintptr_t>(info->dlpi_phdr) != c->want->phdr_addr ||
            info->dlpi_phnum != c->want->phdr_count) {
          return 0;
        }
        if (c->want_path != nullptr &&
            std::strcmp(info->dlpi_name == nullptr ? "" : info->dlpi_name, c->want_path) != 0) {
          return 1;  // Same address, different image: the wanted one is gone.
        }
        ImageView live;
        live.load_bias = static_cast<uintptr_t>(info->dlpi_addr);
        live.phdr_table = info->dlpi_phdr;
        live.phdr_count = info->dlpi_phnum;
        live.instance_token = 0;
        c->matched = true;
        try {
          std::lock_guard<std::mutex> lock(detail::op_mutex());  // linker -> op
          (*c->fn)(live);
        } catch (...) {
          c->error = std::current_exception();
        }
        return 1;
      },
      &ctx);
  if (ctx.error) std::rethrow_exception(ctx.error);
  return ctx.matched;
#else
  (void)want;
  (void)fn;
  (void)want_path;
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
  /// A function GLOB_DAT slot must not be installed over an unresolved (zero)
  /// value: that would turn a null weak function pointer non-null.  JUMP_SLOT
  /// and legacy paths leave this false.
  bool reject_zero_original = false;
};

/// Every non-null original-pointer output must be pointer-aligned (the release
/// store is an atomic access) and distinct within one transaction, so one
/// target's original can never overwrite another's.  Checked before any lock
/// or write.
template <typename Request>
Error validate_outputs(const Request* reqs, size_t count) noexcept {
  for (size_t i = 0; i < count; ++i) {
    void** out = reqs[i].out_original;
    if (out == nullptr) continue;
    if (reinterpret_cast<uintptr_t>(out) % alignof(void*) != 0)
      return Error::Make(ErrorCode::kInvalidArgument);
    for (size_t j = 0; j < i; ++j) {
      if (reqs[j].out_original == out) return Error::Make(ErrorCode::kInvalidArgument);
    }
  }
  return Error::Ok();
}

/// Resolve every request against `img` to a unique slot, enforcing one-slot
/// uniqueness and no duplicate targets within the batch.
Error plan_requests(const InspectedImage& img, const HookRequest* reqs, size_t count,
                    detail::SmallVec<PlannedSlot, 4>& out) {
  // One complete validated scan for the batch; do not parse version metadata
  // on the legacy name-only path.
  auto snapshot = detail::snapshot_imports(img);
  if (!snapshot) return snapshot.error();
  for (size_t i = 0; i < count; ++i) {
    if (reqs[i].symbol == nullptr || reqs[i].replacement == nullptr)
      return Error::Make(ErrorCode::kNullPointer);

    const ImportInfo* selected = nullptr;
    for (const auto& entry : snapshot.value().imports) {
      if (entry.symbol != reqs[i].symbol) continue;
      if (selected) return Error::Make(ErrorCode::kAmbiguousSymbol);
      selected = &entry;
    }
    if (!selected) return Error::Make(ErrorCode::kSymbolNotFound);
    uintptr_t addr = selected->slot_address;
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

Error plan_selected_requests(const InspectedImage& img, const SelectedHookRequest* reqs,
                             size_t count, detail::SmallVec<PlannedSlot, 4>& out) {
  auto snapshot = detail::snapshot_versioned_imports(img);
  if (!snapshot) return snapshot.error();
  for (size_t i = 0; i < count; ++i) {
    if (reqs[i].replacement == nullptr) return Error::Make(ErrorCode::kNullPointer);
    auto selected = detail::select_import(snapshot.value(), reqs[i].target);
    if (!selected) return selected.error();
    const auto address = snapshot.value().imports[selected.value()].import.slot_address;
    for (const auto& previous : out) {
      if (previous.address == address) return Error::Make(ErrorCode::kInvalidArgument);
    }
    out.push_back(
        {address, 0, reinterpret_cast<uintptr_t>(reqs[i].replacement), reqs[i].out_original, i});
  }
  return Error::Ok();
}

/// Publish each planned original before the commit makes a replacement
/// reachable.  Runs from Txn::commit only after every page raise succeeded.
struct Publication {
  const detail::SmallVec<PlannedSlot, 4>* planned;
};

void publish_originals(void* context) noexcept {
  const auto& planned = *static_cast<Publication*>(context)->planned;
  for (const PlannedSlot& slot : planned) {
    if (slot.out_original == nullptr) continue;
    // Release store: the replacement reads *out_original with an acquire load
    // (documented), and the commit's release CAS publishes this write.  Using
    // an atomic store (not a plain store) keeps it race-free under the C++
    // model when a replacement on another thread is already reading it.
    __atomic_store_n(slot.out_original, reinterpret_cast<void*>(slot.original), __ATOMIC_RELEASE);
  }
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
/// freshly inspected, currently-valid image.  `plan_fn` resolves the caller's
/// requests into `planned` (one planner per request shape: legacy name,
/// versioned selector, or function selector).
template <typename PlanFn>
HookResult install_planned(const ImageView& view, SlotReport* reports, size_t report_cap,
                           PlanFn&& plan_fn) {
  detail::SmallVec<PlannedSlot, 4> planned;
  Error plan = plan_fn(planned);
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

  struct ClaimGuard {
    Registry& registry;
    uint64_t id;
    bool retained = false;
    ~ClaimGuard() {
      if (!retained) registry.drop(id);
    }
  } claim{reg, id};

  Txn txn(detail::active_ops(), ps);
  Error prep = txn.prepare(slot_addrs, planned.size());
  if (prep) {
    return {prep, detail_api::make(detail_api::invalid())};
  }

  // Read current slot values (now confirmed mapped and readable) and fill the
  // ops.  The originals are published from inside the commit, after every page
  // raise succeeded and before the first CAS makes a replacement reachable.
  // out_original is never cleared once set.
  SlotOp ops[kMaxBatch];
  for (size_t i = 0; i < planned.size(); ++i) {
    uintptr_t cur = 0;
    txn.load(planned[i].address, cur);
    planned[i].original = cur;
    // Reject unresolved GLOB_DAT before any write. Zero JUMP_SLOT remains valid.
    if (planned[i].reject_zero_original && cur == 0) {
      return {Error::Make(ErrorCode::kUnsupportedRelocation),
              detail_api::make(detail_api::invalid())};
    }
    if (cur == planned[i].replacement) {  // replacement == current value: ambiguous ownership
      return {Error::Make(ErrorCode::kInvalidArgument), detail_api::make(detail_api::invalid())};
    }
    ops[i].slot = planned[i].address;
    ops[i].expected = cur;
    ops[i].desired = planned[i].replacement;
    // Update the registry's recorded original now that it is known.
    recs[i].original = planned[i].original;
  }

  Publication publication{&planned};
  CommitResult r =
      txn.commit(ops, planned.size(), CommitMode::kAllOrNothing, publish_originals, &publication);
  write_reports(reports, report_cap, planned, ops, planned.size());

  // Pages this commit raised but could not restore.  While any such page
  // exists, the process has a page that is more permissive than we found it, so
  // we must keep a record of it and hand back a handle to recover it — never
  // "drop and claim nothing was modified".
  PageResidueRecord pr[kMaxBatch];
  detail::PageResidue res[kMaxBatch];
  size_t pn = 0;
  {
    size_t raised = txn.residue(res, kMaxBatch);
    for (size_t i = 0; i < raised && pn < kMaxBatch; ++i) {
      pr[pn].page = res[i].page;
      pr[pn].original_prot = res[i].original_prot;
      pr[pn].sys_errno = res[i].sys_errno;
      ++pn;
    }
  }
  for (size_t i = 0; i < planned.size(); ++i) {
    recs[i].original = planned[i].original;
    // The slot's contents are ours only if the CAS committed (kCommitted) or
    // committed and then failed to roll back (kRollbackFailed).  A conflict or a
    // clean rollback means the slot never held our replacement.
    SlotOutcome o = ops[i].outcome;
    recs[i].ever_written = (o == SlotOutcome::kCommitted || o == SlotOutcome::kRollbackFailed);
  }

  const bool clean_success = r.all_committed && r.pages_restored && pn == 0;
  if (clean_success) {
    reg.finish_restore(id, /*released=*/false, GroupState::kPrepared, recs, planned.size(), nullptr,
                       0);
    reg.mark_installed(id);
    reg.record_diagnostic(id, {OperationStage::kComplete, Error::Ok()});
    claim.retained = true;
    return {Error::Ok(), detail_api::make(id)};
  }

  // Not a clean success.  If a page is stuck or a rollback failed, recovery
  // state must be kept: Indeterminate with a valid handle.
  if (pn > 0 || r.rollback_failed) {
    reg.mark_indeterminate(id, recs, planned.size(), pr, pn);
    claim.retained = true;
    const Error error = Error::Sys(ErrorCode::kIndeterminate,
                                   r.restore_errno != 0 ? r.restore_errno : r.raise_errno);
    reg.record_diagnostic(id, {pn != 0 ? OperationStage::kRestorePages : OperationStage::kRollback,
                               error, r.raise_errno, r.restore_errno, r.rollback_failed});
    return {error, detail_api::make(id)};
  }

  // Every raised page was restored and no rollback failed, so nothing is left
  // modified: free the group and report the first cause.
  if (r.raise_errno != 0)
    return {Error::Sys(ErrorCode::kPermissionDenied, r.raise_errno),
            detail_api::make(detail_api::invalid())};
  return {Error::Make(ErrorCode::kSlotOwnershipConflict), detail_api::make(detail_api::invalid())};
}

/// Plan a function-import batch: one scan of the image's selected sources shared
/// by all requests, then unique selection per request with duplicate-target and
/// output checks.
Error plan_function_requests(const InspectedImage& img, const FunctionHookRequest* reqs,
                             size_t count, detail::SmallVec<PlannedSlot, 4>& out) {
  uint32_t sources = 0;
  for (size_t i = 0; i < count; ++i) {
    if (reqs[i].replacement == nullptr) return Error::Make(ErrorCode::kNullPointer);
    Error invalid = detail::validate_function_selector(reqs[i].target);
    if (invalid) return invalid;
    sources |= reqs[i].target.sources;
  }
  auto scan = detail::scan_function_imports(img, sources);
  if (!scan) return scan.error();
  for (size_t i = 0; i < count; ++i) {
    auto selected = detail::select_function_reloc(scan.value(), reqs[i].target);
    if (!selected) return selected.error();
    const auto& record = scan.value().records[selected.value()].entry;
    const uintptr_t address = record.base.import.slot_address;
    for (const auto& previous : out) {
      if (previous.address == address) return Error::Make(ErrorCode::kInvalidArgument);
    }
    PlannedSlot ps;
    ps.address = address;
    ps.original = 0;
    ps.replacement = reinterpret_cast<uintptr_t>(reqs[i].replacement);
    ps.out_original = reqs[i].out_original;
    ps.report_index = i;
    // Only a GLOB_DAT slot must refuse a zero current value; a JUMP_SLOT slot is
    // installed regardless (its lazy stub value is non-zero and legitimate).
    ps.reject_zero_original = record.relocation_type == detail::kRAarch64GlobDat;
    out.push_back(ps);
  }
  return Error::Ok();
}

/// Legacy name batch.
HookResult install(const ImageView& view, const InspectedImage& img, const HookRequest* reqs,
                   size_t count, SlotReport* reports, size_t report_cap) {
  return install_planned(view, reports, report_cap, [&](detail::SmallVec<PlannedSlot, 4>& planned) {
    return plan_requests(img, reqs, count, planned);
  });
}

/// Versioned selector batch.
HookResult install(const ImageView& view, const InspectedImage& img,
                   const SelectedHookRequest* selected, size_t count, SlotReport* reports,
                   size_t report_cap) {
  return install_planned(view, reports, report_cap, [&](detail::SmallVec<PlannedSlot, 4>& planned) {
    return plan_selected_requests(img, selected, count, planned);
  });
}

/// Function selector batch (JUMP_SLOT + function GLOB_DAT).
HookResult install(const ImageView& view, const InspectedImage& img,
                   const FunctionHookRequest* reqs, size_t count, SlotReport* reports,
                   size_t report_cap) {
  return install_planned(view, reports, report_cap, [&](detail::SmallVec<PlannedSlot, 4>& planned) {
    return plan_function_requests(img, reqs, count, planned);
  });
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
  // Warn whenever a dropped handle still owns a live replacement — Installed, or
  // Indeterminate with a slot whose contents are ours — not just Installed.
  if (reg.owns_live_replacement(id_)) {
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
  if (reqs == nullptr) return fail(ErrorCode::kNullPointer);
  if (count == 0 || count > kMaxBatch) return fail(ErrorCode::kInvalidArgument);
  // Reject unusable outputs before taking any lock or touching the image.
  Error outputs = validate_outputs(reqs, count);
  if (outputs) return {outputs, detail_api::make(detail_api::invalid())};

  auto apply = [&](const ImageView& live) -> HookResult {
    try {
      auto insp = detail::inspect(live.load_bias, live.phdr_table, live.phdr_count);
      if (!insp) return {insp.error(), detail_api::make(detail_api::invalid())};
      return install(image, insp.value(), reqs, count, reports, count);
    } catch (const std::bad_alloc&) {
      return fail(ErrorCode::kOutOfMemory);
    } catch (const std::length_error&) {
      return fail(ErrorCode::kIntegerOverflow);
    } catch (...) {
      return fail(ErrorCode::kUnsupportedFormat);
    }
  };
  try {
    if (image.instance_token == 0) {
      // Keep inspection and installation inside the linker callback, taking op
      // after linker so unloading cannot invalidate the image during access.
      HookResult result = fail(ErrorCode::kImageInvalidated);
      run_on_system_image(identity_of(image), [&](const ImageView& live) { result = apply(live); });
      return result;
    }

    // Custom image: the caller guarantees it stays mapped (contract).
    std::lock_guard<std::mutex> lock(detail::op_mutex());
    return apply(image);
  } catch (const std::bad_alloc&) {
    return fail(ErrorCode::kOutOfMemory);
  } catch (...) {
    return fail(ErrorCode::kUnsupportedFormat);
  }
}
// Precisely selected imports

HookResult hook_import(const ImageView& image, const ImportSelector& selector, void* replacement,
                       void** out_original, SlotReport* report) {
  SelectedHookRequest request{selector, replacement, out_original};
  return hook_imports(image, &request, 1, report);
}

HookResult hook_imports(const ImageView& image, const SelectedHookRequest* reqs, size_t count,
                        SlotReport* reports) {
  auto fail = [](Error error) { return HookResult{error, HookHandle{}}; };
  if (reqs == nullptr) return fail(Error::Make(ErrorCode::kNullPointer));
  if (count == 0 || count > kMaxBatch) return fail(Error::Make(ErrorCode::kInvalidArgument));
  for (size_t i = 0; i < count; ++i) {
    auto error = detail::validate_selector(reqs[i].target);
    if (error) return fail(error);
    if (reqs[i].replacement == nullptr) return fail(Error::Make(ErrorCode::kNullPointer));
  }
  // Reject unusable outputs before taking any lock or touching the image.
  Error outputs = validate_outputs(reqs, count);
  if (outputs) return fail(outputs);
  auto apply = [&](const ImageView& live) -> HookResult {
    try {
      auto inspected = detail::inspect(live.load_bias, live.phdr_table, live.phdr_count);
      if (!inspected) return fail(inspected.error());
      return install(live, inspected.value(), reqs, count, reports, count);
    } catch (const std::bad_alloc&) {
      return fail(Error::Make(ErrorCode::kOutOfMemory));
    } catch (const std::length_error&) {
      return fail(Error::Make(ErrorCode::kIntegerOverflow));
    } catch (...) {
      // Never unwind through the loader's C callback frame.
      return fail(Error::Make(ErrorCode::kUnsupportedFormat));
    }
  };
  try {
    if (image.instance_token == 0) {
      auto result = fail(Error::Make(ErrorCode::kImageInvalidated));
      run_on_system_image(identity_of(image), [&](const ImageView& live) { result = apply(live); });
      return result;
    }
    std::lock_guard<std::mutex> lock(detail::op_mutex());
    return apply(image);
  } catch (const std::bad_alloc&) {
    return fail(Error::Make(ErrorCode::kOutOfMemory));
  } catch (...) {
    return fail(Error::Make(ErrorCode::kUnsupportedFormat));
  }
}
// Function GLOB_DAT / APS2 imports (opt-in)
//
// inspect_function_imports() and find_function_import() are read-only and use
// the inspect_metadata() helper, so they live further down with the other
// snapshot entry points.  The installing entry points are here, next to
// hook_imports(), since they share its install() / run_on_system_image() path.

HookResult hook_function_import(const ImageView& image, const FunctionImportSelector& selector,
                                void* replacement, void** out_original, SlotReport* report) {
  FunctionHookRequest request{selector, replacement, out_original};
  return hook_function_imports(image, &request, 1, report);
}

HookResult hook_function_imports(const ImageView& image, const FunctionHookRequest* reqs,
                                 size_t count, SlotReport* reports) {
  return detail::hook_function_imports_at(image, nullptr, reqs, count, reports);
}

}  // namespace yukiplt

namespace yukiplt::detail {

HookResult hook_function_imports_at(const ImageView& image, const char* expected_path,
                                    const FunctionHookRequest* reqs, size_t count,
                                    SlotReport* reports) {
  auto fail = [](Error error) { return HookResult{error, HookHandle{}}; };
  if (reqs == nullptr) return fail(Error::Make(ErrorCode::kNullPointer));
  if (count == 0 || count > kMaxBatch) return fail(Error::Make(ErrorCode::kInvalidArgument));
  for (size_t i = 0; i < count; ++i) {
    auto error = detail::validate_function_selector(reqs[i].target);
    if (error) return fail(error);
    if (reqs[i].replacement == nullptr) return fail(Error::Make(ErrorCode::kNullPointer));
  }
  // Reject unusable outputs before taking any lock or touching the image.
  Error outputs = validate_outputs(reqs, count);
  if (outputs) return fail(outputs);
  auto apply = [&](const ImageView& live) -> HookResult {
    try {
      auto inspected = detail::inspect(live.load_bias, live.phdr_table, live.phdr_count);
      if (!inspected) return fail(inspected.error());
      return install(live, inspected.value(), reqs, count, reports, count);
    } catch (const std::bad_alloc&) {
      return fail(Error::Make(ErrorCode::kOutOfMemory));
    } catch (const std::length_error&) {
      return fail(Error::Make(ErrorCode::kIntegerOverflow));
    } catch (...) {
      // Never unwind through the loader's C callback frame.
      return fail(Error::Make(ErrorCode::kUnsupportedFormat));
    }
  };
  try {
    if (image.instance_token == 0) {
      // Not found, or found at the same address under another name: the image
      // the caller enumerated is no longer the one loaded there.
      auto result = fail(Error::Make(ErrorCode::kImageInvalidated));
      run_on_system_image(
          identity_of(image), [&](const ImageView& live) { result = apply(live); }, expected_path);
      return result;
    }
    std::lock_guard<std::mutex> lock(detail::op_mutex());
    return apply(image);
  } catch (const std::bad_alloc&) {
    return fail(Error::Make(ErrorCode::kOutOfMemory));
  } catch (...) {
    return fail(Error::Make(ErrorCode::kUnsupportedFormat));
  }
}

}  // namespace yukiplt::detail

namespace yukiplt {
// unhook

namespace {

/// The restore transaction, run with the op lock held and (for a system image)
/// inside the linker callback.  `image_live` is true when the image is known to
/// be mapped right now: for a system image, because we are inside
/// dl_iterate_phdr; for a custom image, by the caller's contract.
Error do_restore(uint64_t id, HookHandle& handle, bool image_live, SlotReport* reports,
                 size_t cap) {
  Registry& reg = Registry::instance();
  const auto previous_state =
      reg.is_installed(id) ? GroupState::kInstalled : GroupState::kIndeterminate;

  ImageIdentity image;
  SlotRecord recs[kMaxBatch];
  size_t slot_count = 0;
  PageResidueRecord pages[kMaxBatch];
  size_t page_count = 0;
  Error begin =
      reg.begin_restore(id, image, recs, kMaxBatch, &slot_count, pages, kMaxBatch, &page_count);
  if (begin) {
    if (begin.code == ErrorCode::kImageInvalidated) {
      const Error released = reg.release(id);
      if (released) return released;
      detail_api::set(handle, detail_api::invalid());
    }
    return begin;
  }
  if (slot_count > kMaxBatch) slot_count = kMaxBatch;
  if (page_count > kMaxBatch) page_count = kMaxBatch;

  // A system image that we could not find under the linker lock is gone.
  if (!image_live) {
    reg.finish_restore(id, true, GroupState::kInstalled, nullptr, 0, nullptr, 0);
    detail_api::set(handle, detail_api::invalid());
    return Error::Make(ErrorCode::kImageInvalidated);
  }

  const size_t ps = detail::page_size();
  if (ps == 0) {
    reg.finish_restore(id, false, previous_state, recs, slot_count, pages, page_count);
    reg.record_diagnostic(id,
                          {OperationStage::kPrepare, Error::Make(ErrorCode::kUnsupportedFormat)});
    return Error::Make(ErrorCode::kUnsupportedFormat);
  }

  // Build the page set: slot pages plus any residual raised pages.
  uintptr_t slot_addrs[kMaxBatch];
  uintptr_t extra_pages[kMaxBatch];
  for (size_t i = 0; i < slot_count; ++i) slot_addrs[i] = recs[i].address;
  for (size_t i = 0; i < page_count; ++i) extra_pages[i] = pages[i].page;

  Txn txn(detail::active_ops(), ps);
  Error prep;
  try {
    prep = txn.prepare(slot_count > 0 ? slot_addrs : nullptr, slot_count,
                       page_count > 0 ? extra_pages : nullptr, page_count);
  } catch (const std::bad_alloc&) {
    // prepare has not changed any slot or page. Restore the exact prior state
    // before the public boundary translates the allocation exception.
    reg.finish_restore(id, false, previous_state, nullptr, 0, nullptr, 0);
    reg.record_diagnostic(id, {OperationStage::kPrepare, Error::Make(ErrorCode::kOutOfMemory)});
    throw;
  } catch (...) {
    reg.finish_restore(id, false, previous_state, nullptr, 0, nullptr, 0);
    reg.record_diagnostic(id,
                          {OperationStage::kPrepare, Error::Make(ErrorCode::kUnsupportedFormat)});
    throw;
  }
  if (prep) {
    // A failed/incomplete maps read does not prove unload. Preserve recovery
    // state; custom-image invalidation requires forget_image().
    reg.finish_restore(id, false, previous_state, recs, slot_count, pages, page_count);
    reg.record_diagnostic(id, {OperationStage::kPrepare, prep});
    return prep;
  }

  // Never-written slots need no recovery. CAS replacement to original; accept
  // already-original values and preserve conflicting third-party values.
  SlotOp ops[kMaxBatch];
  size_t op_count = 0;
  bool any_foreign = false;
  for (size_t i = 0; i < slot_count; ++i) {
    if (!recs[i].ever_written) continue;
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

  CommitResult r{};
  if (op_count > 0) {
    r = txn.commit(ops, op_count, CommitMode::kAllOrNothing);
  }

  // Restore residual pages after CAS using live maps: accept original protection,
  // restore raised protection, and retain conflicts with third-party protection.
  PageResidueRecord leftover[kMaxBatch];
  size_t leftover_count = 0;
  int restore_errno = r.restore_errno;
  for (size_t i = 0; i < page_count; ++i) {
    detail::VmaInfo live{};
    if (!txn.page_vma(pages[i].page, live)) {
      pages[i].sys_errno = 0;
      leftover[leftover_count++] = pages[i];
      continue;
    }
    const int live_prot = detail::prot_of(live);
    if (live_prot == pages[i].original_prot) continue;
    const bool conflict = live_prot != (pages[i].original_prot | detail::kProtWrite);
    const int error = conflict ? 0 : txn.protect_page(pages[i].page, pages[i].original_prot);
    if (conflict || error != 0) {
      pages[i].sys_errno = error;
      if (restore_errno == 0) restore_errno = error;
      leftover[leftover_count++] = pages[i];
    }
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
    if (!recs[i].ever_written) {
      // We never owned this slot's contents, so there is nothing to restore and
      // it cannot be a conflict that keeps the group alive.
      st = SlotStatus::kRestored;
    } else if (was_op) {
      SlotOutcome o = ops[oi].outcome;
      observed = ops[oi].observed;
      if (o == SlotOutcome::kCommitted) {
        st = SlotStatus::kRestored;
      } else if (o == SlotOutcome::kRolledBack) {
        st = SlotStatus::kRolledBack;  // our replacement is back in the slot
        all_restored = false;
      } else {
        st = to_status(o);
        all_restored = false;
      }
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

  // Merge any still-unrestored carried-in page with the pages this attempt
  // raised but could not restore, so a page is never dropped from the record.
  PageResidueRecord new_pages[kMaxBatch];
  size_t pn = 0;
  detail::PageResidue res[kMaxBatch];
  size_t raised = txn.residue(res, kMaxBatch);
  for (size_t i = 0; i < raised && pn < kMaxBatch; ++i) {
    new_pages[pn].page = res[i].page;
    new_pages[pn].original_prot = res[i].original_prot;
    new_pages[pn].sys_errno = res[i].sys_errno;
    ++pn;
  }
  for (size_t i = 0; i < leftover_count && pn < kMaxBatch; ++i) {
    bool dup = false;
    for (size_t j = 0; j < pn; ++j) {
      if (new_pages[j].page == leftover[i].page) {
        dup = true;
        break;
      }
    }
    if (!dup) new_pages[pn++] = leftover[i];
  }
  const bool pages_clean = r.pages_restored && pn == 0;

  if (all_restored && pages_clean && !rollback_failed) {
    reg.finish_restore(id, true, GroupState::kInstalled, nullptr, 0, nullptr, 0);
    detail_api::set(handle, detail_api::invalid());
    return Error::Ok();
  }

  // A page left writable (pn > 0) or a failed rollback is partial recovery:
  // kIndeterminate, consistent with install().  This takes precedence over a
  // raise errno, since a stuck page is the more serious residual state.
  if (rollback_failed || !pages_clean) {
    reg.finish_restore(id, false, GroupState::kIndeterminate, recs, slot_count, new_pages, pn);
    const Error error =
        Error::Sys(ErrorCode::kIndeterminate, restore_errno != 0 ? restore_errno : r.raise_errno);
    reg.record_diagnostic(
        id, {!pages_clean ? OperationStage::kRestorePages : OperationStage::kRollback, error,
             r.raise_errno, restore_errno, rollback_failed});
    return error;
  }

  if (r.raise_errno != 0) {
    // A page could not be raised, but every page we did raise was restored, so
    // nothing is left writable.  No slot was written; keep the handle to retry.
    reg.finish_restore(id, false, GroupState::kInstalled, recs, slot_count, new_pages, 0);
    reg.record_diagnostic(
        id, {OperationStage::kRaise, Error::Sys(ErrorCode::kPermissionDenied, r.raise_errno),
             r.raise_errno});
    return Error::Sys(ErrorCode::kPermissionDenied, r.raise_errno);
  }

  // Slots left as a third party's value: keep ownership for a later retry.
  (void)any_foreign;
  reg.finish_restore(id, false, GroupState::kInstalled, recs, slot_count, new_pages, pn);
  reg.record_diagnostic(id,
                        {OperationStage::kCommit, Error::Make(ErrorCode::kSlotModifiedExternally)});
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
        result = do_restore(id, handle, /*image_live=*/true, reports, cap);
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
  } catch (...) {
    return Error::Make(ErrorCode::kUnsupportedFormat);
  }
}
// Import snapshots / abandon / query / forget_image

namespace {
template <typename Snapshot, typename Collect>
Result<Snapshot> inspect_metadata(const ImageView& image, Collect collect_metadata) {
  if (image.phdr_table == nullptr) return Error::Make(ErrorCode::kNullPointer);
  if (image.phdr_count == 0) return Error::Make(ErrorCode::kInvalidArgument);
  // Catch allocation failures inside the callable as well: it runs inside a
  // C loader callback for system images. Publish only a complete owning result.
  auto collect = [&](const ImageView& live) -> Result<Snapshot> {
    try {
      auto inspected = detail::inspect(live.load_bias, live.phdr_table, live.phdr_count);
      if (!inspected) return inspected.error();
      return collect_metadata(inspected.value());
    } catch (const std::bad_alloc&) {
      return Error::Make(ErrorCode::kOutOfMemory);
    } catch (const std::length_error&) {
      return Error::Make(ErrorCode::kIntegerOverflow);
    }
  };
  try {
    if (image.instance_token == 0) {
      Result<Snapshot> result = Error::Make(ErrorCode::kImageInvalidated);
      run_on_system_image(identity_of(image),
                          [&](const ImageView& live) { result = collect(live); });
      return result;
    }
    std::lock_guard<std::mutex> lock(detail::op_mutex());
    return collect(image);
  } catch (const std::bad_alloc&) {
    return Error::Make(ErrorCode::kOutOfMemory);
  } catch (...) {
    return Error::Make(ErrorCode::kUnsupportedFormat);
  }
}
}  // namespace

Result<ImportSnapshot> inspect_imports(const ImageView& image) {
  return inspect_metadata<ImportSnapshot>(image, detail::snapshot_imports);
}

Result<VersionedImportSnapshot> inspect_versioned_imports(const ImageView& image) {
  return inspect_metadata<VersionedImportSnapshot>(image, detail::snapshot_versioned_imports);
}

Result<VersionedImport> find_import(const ImageView& image, const ImportSelector& selector) {
  auto invalid = detail::validate_selector(selector);
  if (invalid) return invalid;
  return inspect_metadata<VersionedImport>(
      image, [&](const InspectedImage& inspected) -> Result<VersionedImport> {
        auto snapshot = detail::snapshot_versioned_imports(inspected);
        if (!snapshot) return snapshot.error();
        auto selected = detail::select_import(snapshot.value(), selector);
        if (!selected) return selected.error();
        return std::move(snapshot.value().imports[selected.value()]);
      });
}

Result<FunctionImportSnapshot> inspect_function_imports(const ImageView& image, uint32_t sources) {
  // Validate the source mask before any image access: a zero or out-of-range
  // mask is a programming error, not an image problem.
  if (sources == 0 || (sources & ~(kSourceJmprel | kSourceRela | kSourceAndroidRela)) != 0)
    return Error::Make(ErrorCode::kInvalidArgument);
  return inspect_metadata<FunctionImportSnapshot>(
      image, [&](const InspectedImage& inspected) -> Result<FunctionImportSnapshot> {
        return detail::snapshot_function_imports(inspected, sources);
      });
}

Result<FunctionImport> find_function_import(const ImageView& image,
                                            const FunctionImportSelector& selector) {
  auto invalid = detail::validate_function_selector(selector);
  if (invalid) return invalid;
  return inspect_metadata<FunctionImport>(
      image, [&](const InspectedImage& inspected) -> Result<FunctionImport> {
        auto scan = detail::scan_function_imports(inspected, selector.sources);
        if (!scan) return scan.error();
        auto selected = detail::select_function_reloc(scan.value(), selector);
        if (!selected) return selected.error();
        return std::move(scan.value().records[selected.value()].entry);
      });
}

Error abandon(HookHandle& handle) {
  if (!handle.valid()) return Error::Make(ErrorCode::kInvalidArgument);
  try {
    std::lock_guard<std::mutex> lock(detail::op_mutex());
    Error e = Registry::instance().release(detail_api::id(handle));
    if (!e) detail_api::set(handle, detail_api::invalid());
    return e;
  } catch (...) {
    return Error::Make(ErrorCode::kUnsupportedFormat);
  }
}

namespace {
/// Read live values under the operation lock and, for system images, linker lock.
/// Try one maps read for the group; fall back to individual slots on failure.
void fill_query(const SlotRecord* recs, size_t n, bool live_image, SlotReport* out, size_t cap) {
  const size_t ps = detail::page_size();
  const size_t filled = n < cap ? n : cap;
  if (out == nullptr) return;
  for (size_t i = 0; i < filled; ++i) {
    out[i].address = recs[i].address;
    out[i].value_before = recs[i].original;
    out[i].value_observed = 0;
    // kUntouched here means "the live value could not be read"; kInstalled
    // means value_observed holds a genuine live read.  We never invent an
    // observed value from the recorded replacement.
    out[i].status = SlotStatus::kUntouched;
  }
  if (ps == 0 || !live_image || filled == 0) return;

  uintptr_t addrs[kMaxBatch];
  for (size_t i = 0; i < filled; ++i) addrs[i] = recs[i].address;
  Txn all(detail::active_ops(), ps);
  if (!all.prepare(addrs, filled)) {
    for (size_t i = 0; i < filled; ++i) {
      uintptr_t cur = 0;
      if (all.load(recs[i].address, cur)) {
        out[i].value_observed = cur;
        out[i].status = SlotStatus::kInstalled;
      }
    }
    return;
  }
  for (size_t i = 0; i < filled; ++i) {
    Txn txn(detail::active_ops(), ps);
    uintptr_t one = recs[i].address;
    if (!txn.prepare(&one, 1)) {
      uintptr_t cur = 0;
      if (txn.load(recs[i].address, cur)) {
        out[i].value_observed = cur;
        out[i].status = SlotStatus::kInstalled;
      }
    }
  }
}
}  // namespace

Error query(const HookHandle& handle, SlotReport* out, size_t cap, size_t* count) {
  if (!handle.valid()) return Error::Make(ErrorCode::kInvalidArgument);
  const uint64_t id = detail_api::id(handle);
  try {
    // Snapshot the recorded slots, then read live values.  A system image's
    // slots are read only inside the linker callback, so a concurrent dlclose
    // cannot unmap them mid-read; an image no longer loaded reports only the
    // recorded values.
    ImageIdentity image;
    SlotRecord recs[kMaxBatch];
    size_t n = 0;
    {
      std::lock_guard<std::mutex> lock(detail::op_mutex());
      Error snap = Registry::instance().snapshot(id, image, recs, kMaxBatch, &n);
      if (snap) return snap;
    }
    if (n > kMaxBatch) n = kMaxBatch;

    if (out == nullptr || cap == 0) {
      // Count-only: no live read, so no image access or transaction pages.
    } else if (image.instance_token == 0 && !image.invalidated) {
      Error result = Error::Ok();
      bool matched = run_on_system_image(image, [&](const ImageView&) {
        // Re-snapshot under the op lock: the group may have changed or been
        // released between the two lock acquisitions.
        result = Registry::instance().snapshot(id, image, recs, kMaxBatch, &n);
        if (result) return;
        if (n > kMaxBatch) n = kMaxBatch;
        fill_query(recs, n, /*live_image=*/true, out, cap);
      });
      if (!matched) fill_query(recs, n, /*live_image=*/false, out, cap);
      if (result) return result;
    } else {
      std::lock_guard<std::mutex> lock(detail::op_mutex());
      Error snap = Registry::instance().snapshot(id, image, recs, kMaxBatch, &n);
      if (snap) return snap;
      if (n > kMaxBatch) n = kMaxBatch;
      fill_query(recs, n, !image.invalidated, out, cap);
    }
    if (count != nullptr) *count = n;
    return Error::Ok();
  } catch (const std::bad_alloc&) {
    return Error::Make(ErrorCode::kOutOfMemory);
  } catch (...) {
    return Error::Make(ErrorCode::kUnsupportedFormat);
  }
}

Error forget_image(const ImageView& custom_image) {
  if (custom_image.instance_token == 0) return Error::Make(ErrorCode::kInvalidArgument);
  try {
    std::lock_guard<std::mutex> lock(detail::op_mutex());
    Registry::instance().forget_custom_image(identity_of(custom_image));
    return Error::Ok();
  } catch (...) {
    return Error::Make(ErrorCode::kUnsupportedFormat);
  }
}

Error query_recovery(const HookHandle& handle, RecoveryDiagnostic* diagnostic, ResidualPage* pages,
                     size_t capacity) {
  if (diagnostic == nullptr || (pages == nullptr && capacity != 0))
    return Error::Make(ErrorCode::kNullPointer);
  if (!handle.valid()) return Error::Make(ErrorCode::kInvalidArgument);
  try {
    std::lock_guard<std::mutex> lock(detail::op_mutex());
    return Registry::instance().recovery_snapshot(detail_api::id(handle), *diagnostic, pages,
                                                  capacity);
  } catch (...) {
    return Error::Make(ErrorCode::kUnsupportedFormat);
  }
}

}  // namespace yukiplt
