// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "memory.hpp"

#include <cerrno>

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/auxv.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace yukiplt::detail {
// Page size

size_t page_size() noexcept {
  // Cache the result.  This is safe for concurrent reads after first init
  // because size_t stores are atomic on all supported architectures and
  // the value is always the same.
  static size_t cached = 0;
  if (cached != 0) return cached;

#if defined(__linux__) || defined(__ANDROID__)
  // Prefer getauxval — available since glibc 2.16 and bionic API 18.
  unsigned long ps = getauxval(AT_PAGESZ);
  if (ps == 0) {
    // Fallback.
    ps = static_cast<unsigned long>(sysconf(_SC_PAGESIZE));
  }
  cached = static_cast<size_t>(ps);
#else
  // Non-Linux host build: use 4096 for compilation only.
  // Patch operations are not functional on non-Linux hosts.
  cached = 4096;
#endif

  return cached;
}
// Patch

Expected<void, Error> patch_slot(uintptr_t slot_addr, uintptr_t expected_old, uintptr_t desired_new,
                                 const InspectedImage& image) {
  // Validate alignment.
  if (slot_addr % 8 != 0) return Error::Make(ErrorCode::kInvalidArgument);

  // Validate the slot is within a load segment.
  if (!image.addr_in_load(slot_addr, sizeof(uintptr_t)))
    return Error::Make(ErrorCode::kOutOfBounds);

#if defined(__linux__) || defined(__ANDROID__)
  const size_t ps = page_size();
  const uintptr_t page_mask = ~(static_cast<uintptr_t>(ps) - 1);
  const uintptr_t page_base = slot_addr & page_mask;

  // Deduce the expected protection from segment info.
  int orig_prot = image.protection_for(slot_addr);
  bool needs_mprotect = (orig_prot & PROT_WRITE) == 0;

  // Temporarily make the page writable if needed.
  if (needs_mprotect) {
    if (mprotect(reinterpret_cast<void*>(page_base), ps, PROT_READ | PROT_WRITE) != 0) {
      return Error::Sys(ErrorCode::kPermissionDenied, errno);
    }
  }

  // Perform CAS with release semantics.
  // The caller must have already written any state that the replacement
  // function depends on (especially the original function pointer) before
  // calling patch_slot.  The release fence here ensures that those writes
  // are visible to any thread that sees the new slot value.
  uintptr_t old_val = expected_old;
  bool cas_ok =
      __atomic_compare_exchange_n(reinterpret_cast<uintptr_t*>(slot_addr), &old_val, desired_new,
                                  /*weak=*/false, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE);

  // Restore original protection.
  if (needs_mprotect) {
    // Best effort — if this fails, the page remains writable.
    // The CAS result is still valid either way.
    mprotect(reinterpret_cast<void*>(page_base), ps, orig_prot);
  }

  if (!cas_ok) {
    return Error::Make(ErrorCode::kSlotOwnershipConflict);
  }

  return Expected<void, Error>();  // Success
#else
  // Non-Linux: patch_slot is not functional.
  (void)expected_old;
  (void)desired_new;
  (void)image;
  return Error::Make(ErrorCode::kUnsupportedFormat);
#endif
}

}  // namespace yukiplt::detail
