// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKIPLT_H_
#define YUKIPLT_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#define YUKIPLT_C_NOEXCEPT noexcept
#else
#define YUKIPLT_C_NOEXCEPT
#endif

#define YUKIPLT_C_ABI_VERSION 1u
#define YUKIPLT_C_ANY_RELOCATION SIZE_MAX

enum {
  YUKIPLT_C_SUCCESS = 0,
  YUKIPLT_C_INVALID_ARGUMENT = 1,
  YUKIPLT_C_NULL_POINTER = 2,
  YUKIPLT_C_INVALID_IMAGE = 3,
  YUKIPLT_C_CORRUPTED_ELF = 4,
  YUKIPLT_C_UNSUPPORTED_FORMAT = 5,
  YUKIPLT_C_UNSUPPORTED_RELOCATION = 6,
  YUKIPLT_C_SYMBOL_NOT_FOUND = 7,
  YUKIPLT_C_NO_HASH_TABLE = 8,
  YUKIPLT_C_AMBIGUOUS_SYMBOL = 9,
  YUKIPLT_C_SLOT_OWNERSHIP_CONFLICT = 10,
  YUKIPLT_C_ALREADY_HOOKED = 11,
  YUKIPLT_C_NOT_INSTALLED = 12,
  YUKIPLT_C_SLOT_MODIFIED_EXTERNALLY = 13,
  YUKIPLT_C_INDETERMINATE = 14,
  YUKIPLT_C_PERMISSION_DENIED = 15,
  YUKIPLT_C_IMAGE_INVALIDATED = 16,
  YUKIPLT_C_OUT_OF_MEMORY = 17,
  YUKIPLT_C_INTEGER_OVERFLOW = 18,
  YUKIPLT_C_OUT_OF_BOUNDS = 19,
  YUKIPLT_C_IMAGE_NOT_FOUND = 20,
  YUKIPLT_C_AMBIGUOUS_IMAGE = 21,
  YUKIPLT_C_VMA_UNAVAILABLE = 22
};
enum { YUKIPLT_C_VERSION_ANY = 0, YUKIPLT_C_VERSION_UNVERSIONED = 1, YUKIPLT_C_VERSION_EXACT = 2 };
enum { YUKIPLT_C_HIDDEN_ANY = 0, YUKIPLT_C_NON_HIDDEN = 1, YUKIPLT_C_HIDDEN = 2 };
enum {
  YUKIPLT_C_UNTOUCHED = 0,
  YUKIPLT_C_INSTALLED = 1,
  YUKIPLT_C_RESTORED = 2,
  YUKIPLT_C_CONFLICT = 3,
  YUKIPLT_C_ROLLED_BACK = 4,
  YUKIPLT_C_ROLLBACK_FAILED = 5
};

typedef struct yukiplt_c_error {
  uint32_t code;
  int32_t sys_errno;
} yukiplt_c_error;
// 0 is invalid. A live token has one owner. Do not copy it into another owner,
// overwrite it, or discard it before explicit unhook/abandon. No destructor.
typedef struct yukiplt_c_handle {
  uint64_t token;
} yukiplt_c_handle;
typedef struct yukiplt_c_image {
  uintptr_t load_bias;
  const void* program_headers;  // ELF64 Program Headers, kept readable by caller.
  size_t program_header_count;
  uint64_t instance_token;  // 0: system linker; otherwise unique custom load.
} yukiplt_c_image;
typedef struct yukiplt_c_selector {
  const char* symbol;
  uint32_t version_match;
  const char* version;     // Nonempty only for VERSION_EXACT; otherwise NULL.
  const char* dependency;  // NULL: no filter; otherwise nonempty VERNEED name.
  uint32_t hidden;
  size_t relocation_index;  // YUKIPLT_C_ANY_RELOCATION for no index filter.
} yukiplt_c_selector;
#define YUKIPLT_C_SELECTOR(name) \
  {(name), YUKIPLT_C_VERSION_ANY, NULL, NULL, YUKIPLT_C_HIDDEN_ANY, YUKIPLT_C_ANY_RELOCATION}
typedef struct yukiplt_c_request {
  yukiplt_c_selector target;
  void* replacement;
  void** out_original;
} yukiplt_c_request;
typedef struct yukiplt_c_slot_report {
  uintptr_t address;
  uintptr_t value_before;
  uintptr_t value_observed;
  uint32_t status;
} yukiplt_c_slot_report;

// ABI v1 targets ARM64 Android API23+. No STL, allocation ownership or C++
// exceptions cross this boundary. Error values match the C++ core. No operation
// silently succeeds after partial commit: INDETERMINATE retains a valid token.
uint32_t yukiplt_c_abi_version(void) YUKIPLT_C_NOEXCEPT;
yukiplt_c_error yukiplt_c_image_from_soname(const char* name,
                                            yukiplt_c_image* out) YUKIPLT_C_NOEXCEPT;

// Strings are borrowed during the call. Selector filters are ANDed and must
// select one JUMP_SLOT. No GLOB_DAT/APS2. Caller holds images/replacements/output
// storage alive. The output handle must be zero; failure never overwrites an
// existing handle. Non-null original outputs must be distinct and aligned, else
// INVALID_ARGUMENT before any lock or write. A system image no longer loaded
// returns IMAGE_INVALIDATED. Originals are release-published after every page
// raise succeeded and before the first CAS, and never cleared afterward; a
// rolled-back conflict may leave a candidate original there without any hook
// installed. Replacement must acquire-load them. They may be another hook's
// replacement. A clean failure leaves no net GOT change, restored protections
// and no ownership; that excludes original outputs.
yukiplt_c_error yukiplt_c_hook(const yukiplt_c_image*, const yukiplt_c_selector*, void* replacement,
                               void** out_original, yukiplt_c_handle* out_handle,
                               yukiplt_c_slot_report* report) YUKIPLT_C_NOEXCEPT;
yukiplt_c_error yukiplt_c_hook_batch(const yukiplt_c_image*, const yukiplt_c_request*, size_t count,
                                     yukiplt_c_handle* out_handle,
                                     yukiplt_c_slot_report* reports) YUKIPLT_C_NOEXCEPT;
// One image, 1..64 requests, reports either NULL or at least count elements.
// Transaction recovery is guaranteed, not an atomic cross-slot switch.

// Success and IMAGE_INVALIDATED consume the handle. IMAGE_INVALIDATED means a
// system image no longer loaded or a custom image passed to forget_image.
// Transient/conflict/OOM/OUT_OF_BOUNDS/VMA_UNAVAILABLE/INDETERMINATE failures
// preserve it for retry. Success does not establish replacement quiescence;
// caller must coordinate code/context reclamation.
yukiplt_c_error yukiplt_c_unhook(yukiplt_c_handle*, yukiplt_c_slot_report* reports,
                                 size_t capacity) YUKIPLT_C_NOEXCEPT;
// Only relinquishes ownership; never changes slots or permissions.
yukiplt_c_error yukiplt_c_abandon(yukiplt_c_handle*) YUKIPLT_C_NOEXCEPT;
// count receives total slots; at most capacity reports are filled. Reports may
// be NULL (count-only). A copied token here is a borrowed view, not a new owner.
yukiplt_c_error yukiplt_c_query(const yukiplt_c_handle*, yukiplt_c_slot_report* reports,
                                size_t capacity, size_t* count) YUKIPLT_C_NOEXCEPT;
// Custom images only; matches load bias, Program Header address/count and
// token. Coordinate with the owner before unmapping; handles then unhook as
// IMAGE_INVALIDATED. System reload at the same address remains ABA.
yukiplt_c_error yukiplt_c_forget_image(const yukiplt_c_image*) YUKIPLT_C_NOEXCEPT;

#ifdef __cplusplus
}
#endif
#undef YUKIPLT_C_NOEXCEPT

#endif  // YUKIPLT_H_
