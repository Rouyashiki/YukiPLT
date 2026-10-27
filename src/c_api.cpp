// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <algorithm>
#include <new>
#include <stdexcept>

#include "registry.hpp"
#include "yukiplt.h"

namespace {
using namespace yukiplt;
constexpr size_t kLimit = 64;
static_assert(static_cast<uint32_t>(ErrorCode::kVmaUnavailable) == YUKIPLT_C_VMA_UNAVAILABLE);
static_assert(static_cast<uint32_t>(SlotStatus::kRollbackFailed) == YUKIPLT_C_ROLLBACK_FAILED);
yukiplt_c_error converted(Error error) noexcept {
  return {static_cast<uint32_t>(error.code), error.sys_errno};
}
ImageView view(const yukiplt_c_image& image) noexcept {
  return {image.load_bias, static_cast<const Elf64_Phdr*>(image.program_headers),
          image.program_header_count, image.instance_token};
}
ImportSelector selector(const yukiplt_c_selector& source) noexcept {
  return {
      source.symbol,     static_cast<VersionMatch>(source.version_match), source.version,
      source.dependency, static_cast<HiddenMatch>(source.hidden),         source.relocation_index};
}
bool valid_enums(const yukiplt_c_selector& source) noexcept {
  // Check before narrowing to the C++ uint8 enums; 256 must not become kAny.
  return source.version_match <= YUKIPLT_C_VERSION_EXACT && source.hidden <= YUKIPLT_C_HIDDEN;
}
void copy_reports(yukiplt_c_slot_report* out, const SlotReport* reports, size_t count) noexcept {
  if (!out) return;
  for (size_t i = 0; i < count; ++i)
    out[i] = {reports[i].address, reports[i].value_before, reports[i].value_observed,
              static_cast<uint32_t>(reports[i].status)};
}
uint64_t token(const HookHandle& handle) noexcept {
  return handle.valid() ? detail_api::id(handle) + 1 : 0;
}
struct BorrowedHandle {
  HookHandle value;
  explicit BorrowedHandle(uint64_t token) : value(detail_api::make(token - 1)) {}
  ~BorrowedHandle() { detail_api::set(value, detail_api::invalid()); }
};
template <typename Function>
yukiplt_c_error guarded(Function function) noexcept {
  try {
    return converted(function());
  } catch (const std::bad_alloc&) {
    return converted(Error::Make(ErrorCode::kOutOfMemory));
  } catch (const std::length_error&) {
    return converted(Error::Make(ErrorCode::kIntegerOverflow));
  } catch (...) {
    return converted(Error::Make(ErrorCode::kUnsupportedFormat));
  }
}
}  // namespace

extern "C" {
uint32_t yukiplt_c_abi_version(void) noexcept { return YUKIPLT_C_ABI_VERSION; }
yukiplt_c_error yukiplt_c_image_from_soname(const char* name, yukiplt_c_image* out) noexcept {
  return guarded([&] {
    if (!out) return Error::Make(ErrorCode::kNullPointer);
    auto result = image_from_soname(name);
    if (!result) return result.error();
    const auto& image = result.value();
    *out = {image.load_bias, image.phdr_table, image.phdr_count, image.instance_token};
    return Error::Ok();
  });
}
yukiplt_c_error yukiplt_c_hook(const yukiplt_c_image* image, const yukiplt_c_selector* target,
                               void* replacement, void** original, yukiplt_c_handle* handle,
                               yukiplt_c_slot_report* report) noexcept {
  if (!target) return converted(Error::Make(ErrorCode::kNullPointer));
  const yukiplt_c_request request{*target, replacement, original};
  return yukiplt_c_hook_batch(image, &request, 1, handle, report);
}
yukiplt_c_error yukiplt_c_hook_batch(const yukiplt_c_image* image,
                                     const yukiplt_c_request* requests, size_t count,
                                     yukiplt_c_handle* handle,
                                     yukiplt_c_slot_report* output) noexcept {
  return guarded([&] {
    if (!image || !requests || !handle) return Error::Make(ErrorCode::kNullPointer);
    if (handle->token != 0 || count == 0 || count > kLimit)
      return Error::Make(ErrorCode::kInvalidArgument);
    SelectedHookRequest converted_requests[kLimit];
    SlotReport reports[kLimit];
    for (size_t i = 0; i < count; ++i) {
      if (!valid_enums(requests[i].target)) return Error::Make(ErrorCode::kInvalidArgument);
      converted_requests[i] = {selector(requests[i].target), requests[i].replacement,
                               requests[i].out_original};
    }
    auto result = hook_imports(view(*image), converted_requests, count, reports);
    handle->token = token(result.handle);
    detail_api::set(result.handle, detail_api::invalid());  // transfer, do not abandon
    copy_reports(output, reports, count);
    return result.error;
  });
}
yukiplt_c_error yukiplt_c_unhook(yukiplt_c_handle* handle, yukiplt_c_slot_report* output,
                                 size_t capacity) noexcept {
  return guarded([&] {
    if (!handle) return Error::Make(ErrorCode::kNullPointer);
    if (!handle->token) return Error::Make(ErrorCode::kInvalidArgument);
    BorrowedHandle borrowed(handle->token);
    SlotReport reports[kLimit];
    size_t count = 0;
    // Count-only query does not touch GOT or allocate transaction pages.
    Error queried = query(borrowed.value, nullptr, 0, &count);
    if (queried) return queried;
    const size_t n = std::min({count, capacity, kLimit});
    Error result = unhook(borrowed.value, reports, n);
    handle->token = token(borrowed.value);
    copy_reports(output, reports, n);
    return result;
  });
}
yukiplt_c_error yukiplt_c_abandon(yukiplt_c_handle* handle) noexcept {
  return guarded([&] {
    if (!handle) return Error::Make(ErrorCode::kNullPointer);
    if (!handle->token) return Error::Make(ErrorCode::kInvalidArgument);
    BorrowedHandle borrowed(handle->token);
    Error result = abandon(borrowed.value);
    handle->token = token(borrowed.value);
    return result;
  });
}
yukiplt_c_error yukiplt_c_query(const yukiplt_c_handle* handle, yukiplt_c_slot_report* output,
                                size_t capacity, size_t* total) noexcept {
  return guarded([&] {
    if (!handle) return Error::Make(ErrorCode::kNullPointer);
    if (!handle->token) return Error::Make(ErrorCode::kInvalidArgument);
    BorrowedHandle borrowed(handle->token);
    SlotReport reports[kLimit];
    size_t count = 0;
    const size_t cap = std::min(capacity, kLimit);
    Error result = query(borrowed.value, output ? reports : nullptr, cap, &count);
    if (total) *total = count;
    copy_reports(output, reports, std::min(cap, count));
    return result;
  });
}
yukiplt_c_error yukiplt_c_forget_image(const yukiplt_c_image* image) noexcept {
  return guarded([&] {
    if (!image) return Error::Make(ErrorCode::kNullPointer);
    return forget_image(view(*image));
  });
}
}  // extern C
