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
#endif

namespace yukiplt {

using detail::HookEntry;
using detail::HookState;
using detail::InspectedImage;
using detail::Registry;
// HookHandle

HookHandle::~HookHandle() {
  if (id_ != kInvalid) {
    auto* entry = Registry::instance().get(id_);
    if (entry && entry->state == HookState::kInstalled) {
      std::fprintf(stderr,
                   "[YukiPLT] WARNING: HookHandle destroyed while hook "
                   "is still installed (slot 0x%zx)\n",
                   static_cast<size_t>(entry->slot_addr));
    }
  }
}
// image_from_soname

Result<ImageView> image_from_soname(const char* soname) {
#if defined(__linux__) || defined(__ANDROID__)
  struct CallbackData {
    const char* target;
    ImageView result;
    bool found;
  };

  CallbackData data;
  data.target = soname;
  data.result = {};
  data.found = false;

  dl_iterate_phdr(
      [](struct dl_phdr_info* info, size_t /*size*/, void* ctx) -> int {
        auto* d = static_cast<CallbackData*>(ctx);
        const char* name = info->dlpi_name;

        bool match = false;
        if (d->target == nullptr || d->target[0] == '\0') {
          match = (name == nullptr || name[0] == '\0');
        } else {
          if (name != nullptr) {
            match = (std::strcmp(name, d->target) == 0);
            if (!match) {
              size_t name_len = std::strlen(name);
              size_t target_len = std::strlen(d->target);
              if (name_len > target_len && name[name_len - target_len - 1] == '/' &&
                  std::strcmp(name + name_len - target_len, d->target) == 0) {
                match = true;
              }
            }
          }
        }

        if (match) {
          d->result.load_bias = static_cast<uintptr_t>(info->dlpi_addr);
          d->result.phdr_table = info->dlpi_phdr;
          d->result.phdr_count = info->dlpi_phnum;
          d->found = true;
          return 1;
        }
        return 0;
      },
      &data);

  if (!data.found) return Error::Make(ErrorCode::kImageInvalidated);

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

  // Resolve GOT slots for the symbol.
  auto slots = detail::resolve_slots(img, symbol_name);
  if (!slots) return slots.error();

  if (slots.value().empty()) return Error::Make(ErrorCode::kSymbolNotFound);

  // : only hook the first matching slot.
  const auto& slot = slots.value()[0];

  // Check the registry for duplicates.
  auto& registry = Registry::instance();
  if (registry.is_slot_hooked(slot.address)) return Error::Make(ErrorCode::kAlreadyHooked);

  // Read the current slot value.
  uintptr_t current_value;
  std::memcpy(&current_value, reinterpret_cast<const void*>(slot.address), sizeof(uintptr_t));

  // Register the hook entry (Prepared state).
  HookEntry entry;
  entry.slot_addr = slot.address;
  entry.original_value = current_value;
  entry.replacement = reinterpret_cast<uintptr_t>(replacement);
  entry.state = HookState::kPrepared;
  entry.image_load_bias = image.load_bias;
  entry.image_phdr_addr = reinterpret_cast<uintptr_t>(image.phdr_table);
  entry.image_phdr_count = image.phdr_count;

  size_t id = registry.add(entry);

  // Write out_original BEFORE the CAS.
  // The replacement function may call through out_original immediately
  // after the CAS makes it reachable.  The release semantics of the CAS
  // in patch_slot ensure this write is visible.
  *out_original = reinterpret_cast<void*>(current_value);

  // Patch the GOT slot.
  auto patch_result = detail::patch_slot(slot.address, current_value,
                                         reinterpret_cast<uintptr_t>(replacement), img);

  auto* reg_entry = registry.get(id);
  if (!patch_result) {
    if (reg_entry) reg_entry->state = HookState::kFailed;
    *out_original = nullptr;
    return patch_result.error();
  }

  if (reg_entry) reg_entry->state = HookState::kInstalled;
  return HookHandle(id);
}
// unhook

Error unhook(HookHandle&& handle) {
  if (!handle.valid()) return Error::Make(ErrorCode::kInvalidArgument);

  auto& registry = Registry::instance();
  auto* entry = registry.get(handle.id_);

  if (entry == nullptr) return Error::Make(ErrorCode::kInvalidArgument);

  if (entry->state != HookState::kInstalled) return Error::Make(ErrorCode::kNotInstalled);

  // Transition to Restoring.
  entry->state = HookState::kRestoring;

  // Re-inspect the image using stored phdr info.
  auto insp = detail::inspect(entry->image_load_bias,
                              reinterpret_cast<const Elf64_Phdr*>(entry->image_phdr_addr),
                              entry->image_phdr_count);

  if (!insp) {
    // Cannot re-inspect — the image may have been unloaded.
    entry->state = HookState::kFailed;
    return Error::Make(ErrorCode::kImageInvalidated);
  }

  // CAS: restore original value.
  auto patch_result =
      detail::patch_slot(entry->slot_addr, entry->replacement, entry->original_value, insp.value());

  if (!patch_result) {
    // The slot was modified by someone else.
    entry->state = HookState::kFailed;
    if (patch_result.error().code == ErrorCode::kSlotOwnershipConflict)
      return Error::Make(ErrorCode::kSlotModifiedExternally);
    return patch_result.error();
  }

  // Success.
  entry->state = HookState::kReleased;
  handle.id_ = HookHandle::kInvalid;  // Consume the handle.
  return Error::Ok();
}

}  // namespace yukiplt
