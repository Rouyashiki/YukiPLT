// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "yukiplt.hpp"

#include <cstdio>
#include <cstring>

#include "elf.hpp"
#include "memory.hpp"
#include "registry.hpp"

#if defined(__linux__) || defined(__ANDROID__)
#include <link.h>
#include <sys/auxv.h>
#endif

namespace yukiplt {

using detail::HookEntry;
using detail::InspectedImage;
using detail::Registry;
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
  if (id_ != kInvalid) {
    auto& registry = Registry::instance();
    if (registry.is_installed(id_)) {
      std::fprintf(stderr,
                   "[YukiPLT] WARNING: HookHandle dropped while hook "
                   "is still installed (slot 0x%zx)\n",
                   static_cast<size_t>(registry.slot_of(id_)));
    }
  }
}
// image_from_soname

Result<ImageView> image_from_soname(const char* soname) {
#if defined(__linux__) || defined(__ANDROID__)
  struct CallbackData {
    const char* target;
    uintptr_t main_phdr;  // AT_PHDR; used when target names the main executable
    ImageView result;
    size_t matches;
  };

  CallbackData data;
  data.target = (soname != nullptr && soname[0] != '\0') ? soname : nullptr;
  data.main_phdr = static_cast<uintptr_t>(getauxval(AT_PHDR));
  data.result = {};
  data.matches = 0;

  if (data.target == nullptr && data.main_phdr == 0) return Error::Make(ErrorCode::kImageNotFound);

  // Visit every image: a name may match more than one (e.g. the same library
  // loaded in two linker namespaces), and we refuse to pick one silently.
  dl_iterate_phdr(
      [](struct dl_phdr_info* info, size_t /*size*/, void* ctx) -> int {
        auto* d = static_cast<CallbackData*>(ctx);
        const char* name = info->dlpi_name;

        bool match = false;
        if (d->target == nullptr) {
          // The main executable.  Its dlpi_name is "" on glibc but a full path
          // on bionic, so identify it by its program header address instead.
          match = reinterpret_cast<uintptr_t>(info->dlpi_phdr) == d->main_phdr;
        } else if (name != nullptr) {
          if (std::strchr(d->target, '/') != nullptr) {
            // A path: exact match only.
            match = std::strcmp(name, d->target) == 0;
          } else {
            // A bare name: match it exactly or as the final path component.
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
// hook

Result<HookHandle> hook(const ImageView& image, const char* symbol_name, void* replacement,
                        void** out_original) {
  if (symbol_name == nullptr) return Error::Make(ErrorCode::kNullPointer);
  if (replacement == nullptr) return Error::Make(ErrorCode::kNullPointer);
  if (out_original == nullptr) return Error::Make(ErrorCode::kNullPointer);

  // Inspect the image.
  auto insp = detail::inspect(image.load_bias, image.phdr_table, image.phdr_count);
  if (!insp) return insp.error();
  const InspectedImage& img = insp.value();

  // Resolve the unique GOT slot for the symbol.  A name matching more
  // than one distinct slot is ambiguous ( does not choose); a name matching
  // none is kSymbolNotFound.  Nothing is modified until this succeeds.
  auto slot_result = detail::resolve_unique_slot(img, symbol_name);
  if (!slot_result) return slot_result.error();
  const auto& slot = slot_result.value();

  // Read the current slot value.  The slot is 8-byte aligned (checked
  // by resolve_unique_slot) and lives in a mapped PT_LOAD segment.  Read it
  // atomically: a concurrent hook may be CASing the same slot right now, and a
  // torn read could yield a value that is neither the old nor the new pointer.
  uintptr_t current_value =
      __atomic_load_n(reinterpret_cast<const uintptr_t*>(slot.address), __ATOMIC_ACQUIRE);

  // Atomically reserve the slot in the registry.  claim() rejects the
  // reservation if any live entry already owns this slot address, closing the
  // check-then-insert race against a concurrent hook() of the same slot.
  HookEntry entry;
  entry.slot_addr = slot.address;
  entry.original_value = current_value;
  entry.replacement = reinterpret_cast<uintptr_t>(replacement);
  entry.image_load_bias = image.load_bias;
  entry.image_phdr_addr = reinterpret_cast<uintptr_t>(image.phdr_table);
  entry.image_phdr_count = image.phdr_count;

  auto& registry = Registry::instance();
  size_t id = registry.claim(entry);
  if (id == Registry::kInvalidId) return Error::Make(ErrorCode::kAlreadyHooked);

  // Write out_original BEFORE the CAS makes the replacement reachable.
  // The replacement may call through out_original immediately once the slot
  // points at it; the release CAS in patch_slot publishes this write.
  *out_original = reinterpret_cast<void*>(current_value);

  // Patch the GOT slot.
  auto patch_result = detail::patch_slot(slot.address, current_value,
                                         reinterpret_cast<uintptr_t>(replacement), img);

  if (!patch_result) {
    registry.mark_failed(id);
    *out_original = nullptr;
    return patch_result.error();
  }

  registry.mark_installed(id);
  return HookHandle(id);
}
// unhook

Error unhook(HookHandle&& handle) {
  if (!handle.valid()) return Error::Make(ErrorCode::kInvalidArgument);

  auto& registry = Registry::instance();

  // Atomically require kInstalled, move to kRestoring, and take a copy of the
  // entry.  Two concurrent unhooks of the same handle cannot both pass this:
  // the first moves the state out of kInstalled, so the second gets
  // kNotInstalled and does not touch the slot.
  HookEntry entry;
  Error begin = registry.begin_restore(handle.id_, entry);
  if (begin) return begin;

  // Re-inspect the image using the stored phdr info.
  auto insp = detail::inspect(entry.image_load_bias,
                              reinterpret_cast<const Elf64_Phdr*>(entry.image_phdr_addr),
                              entry.image_phdr_count);

  if (!insp) {
    // Cannot re-inspect — the image may have been unloaded.
    registry.finish_restore(handle.id_, /*success=*/false);
    return Error::Make(ErrorCode::kImageInvalidated);
  }

  // CAS: restore the original value only if the slot still holds our
  // replacement.  We never force a write over a third party's value.
  auto patch_result =
      detail::patch_slot(entry.slot_addr, entry.replacement, entry.original_value, insp.value());

  if (!patch_result) {
    registry.finish_restore(handle.id_, /*success=*/false);
    if (patch_result.error().code == ErrorCode::kSlotOwnershipConflict)
      return Error::Make(ErrorCode::kSlotModifiedExternally);
    return patch_result.error();
  }

  // Success: the handle is consumed and must not be reused.
  registry.finish_restore(handle.id_, /*success=*/true);
  handle.id_ = HookHandle::kInvalid;
  return Error::Ok();
}

}  // namespace yukiplt
