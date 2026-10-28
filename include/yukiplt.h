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
  // INDETERMINATE may carry the first restore errno, otherwise the raise errno.
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

// --- Function GLOB_DAT / APS2 (opt-in, added in ABI v1; see yukiplt.h) ---
//
// These extend selection/installation to R_AARCH64_GLOB_DAT function slots in
// DT_RELA and DT_ANDROID_RELA, alongside JUMP_SLOT.  They are strictly opt-in:
// the caller names the relocation sources and types.  v1's existing structs and
// functions are unchanged; a caller probes availability with
// yukiplt_c_has_feature(YUKIPLT_C_FEATURE_FUNCTION_IMPORTS).
enum {
  YUKIPLT_C_SOURCE_JMPREL = 1u << 0,       // DT_JMPREL (PLT).
  YUKIPLT_C_SOURCE_RELA = 1u << 1,         // DT_RELA (.rela.dyn).
  YUKIPLT_C_SOURCE_ANDROID_RELA = 1u << 2  // DT_ANDROID_RELA (APS2 packed).
};
enum {
  YUKIPLT_C_TYPE_JUMP_SLOT = 1u << 0,  // R_AARCH64_JUMP_SLOT.
  YUKIPLT_C_TYPE_GLOB_DAT = 1u << 1    // R_AARCH64_GLOB_DAT (function, addend 0, UND FUNC).
};
// Scopes a relocation_index filter to one table (matches the source bits' order).
enum {
  YUKIPLT_C_RELOC_SOURCE_JMPREL = 0,
  YUKIPLT_C_RELOC_SOURCE_RELA = 1,
  YUKIPLT_C_RELOC_SOURCE_ANDROID_RELA = 2
};
enum {
  YUKIPLT_C_FEATURE_FUNCTION_IMPORTS = 1,
  YUKIPLT_C_FEATURE_RECOVERY_DIAGNOSTICS = 2,
  YUKIPLT_C_FEATURE_ERROR_NAMES = 3,
  YUKIPLT_C_FEATURE_EXPECTED_CURRENT = 4,
  YUKIPLT_C_FEATURE_ADDRESS_DISCOVERY = 5
};

enum {
  YUKIPLT_C_STAGE_NONE = 0,
  YUKIPLT_C_STAGE_PREPARE = 1,
  YUKIPLT_C_STAGE_EXPECTED_CURRENT = 2,
  YUKIPLT_C_STAGE_RAISE = 3,
  YUKIPLT_C_STAGE_COMMIT = 4,
  YUKIPLT_C_STAGE_ROLLBACK = 5,
  YUKIPLT_C_STAGE_RESTORE_PAGES = 6,
  YUKIPLT_C_STAGE_COMPLETE = 7
};
typedef struct yukiplt_c_recovery_diagnostic {
  uint32_t stage;
  yukiplt_c_error error;
  int32_t raise_errno;
  int32_t restore_errno;
  uint32_t rollback_failed;
  uint32_t image_invalidated;
  size_t residual_page_count;
} yukiplt_c_recovery_diagnostic;
typedef struct yukiplt_c_residual_page {
  uintptr_t address;
  uint32_t original_protection;
  uint32_t raised_protection;
  int32_t sys_errno;
} yukiplt_c_residual_page;

// Registry-only recorded state, not current permissions. diagnostic is required;
// pages may be NULL with zero capacity for count-only. Copies at most capacity
// pages, and reports the full count. Outputs remain unchanged on error.
yukiplt_c_error yukiplt_c_query_recovery(const yukiplt_c_handle*,
                                         yukiplt_c_recovery_diagnostic* diagnostic,
                                         yukiplt_c_residual_page* pages,
                                         size_t capacity) YUKIPLT_C_NOEXCEPT;

// struct_size must be set to sizeof(yukiplt_c_function_selector) (use the macro);
// a mismatch is rejected with INVALID_ARGUMENT.  It is a layout check, not an
// extension mechanism: yukiplt_c_function_request embeds this struct by value,
// so its size is part of the v1 ABI and fields cannot be appended in place.  A
// later extension adds new structs and entry points instead.  sources and types
// are bitmasks that must both be nonzero — naming them is the opt-in.
typedef struct yukiplt_c_function_selector {
  uint32_t struct_size;
  uint32_t sources;
  uint32_t types;
  uint32_t index_source;  // YUKIPLT_C_RELOC_SOURCE_*; scopes base.relocation_index.
  yukiplt_c_selector base;
} yukiplt_c_function_selector;
#define YUKIPLT_C_FUNCTION_SELECTOR(name)                                             \
  {(uint32_t)sizeof(yukiplt_c_function_selector),                                     \
   YUKIPLT_C_SOURCE_JMPREL | YUKIPLT_C_SOURCE_RELA | YUKIPLT_C_SOURCE_ANDROID_RELA,   \
   YUKIPLT_C_TYPE_JUMP_SLOT | YUKIPLT_C_TYPE_GLOB_DAT, YUKIPLT_C_RELOC_SOURCE_JMPREL, \
   YUKIPLT_C_SELECTOR(name)}
typedef struct yukiplt_c_function_request {
  yukiplt_c_function_selector target;
  void* replacement;
  void** out_original;
} yukiplt_c_function_request;

// ABI v1 targets ARM64 Android API23+. No STL, allocation ownership or C++
// exceptions cross this boundary. Error values match the C++ core. No operation
// silently succeeds after partial commit: INDETERMINATE retains a valid token.
uint32_t yukiplt_c_abi_version(void) YUKIPLT_C_NOEXCEPT;
// Stable literal; never allocates. Unknown numeric values return "Unknown".
const char* yukiplt_c_error_name(uint32_t code) YUKIPLT_C_NOEXCEPT;
yukiplt_c_error yukiplt_c_image_from_soname(const char* name,
                                            yukiplt_c_image* out) YUKIPLT_C_NOEXCEPT;

// Strings are borrowed during the call. Selector filters are ANDed and must
// select one JUMP_SLOT. No GLOB_DAT/APS2. Caller holds images/replacements/output
// storage alive. Original outputs must be caller-owned writable storage, never
// GOT slots; aliases of planned or already owned slots are rejected before
// publication. The output handle must be zero; failure never overwrites an
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

// Returns nonzero if the running library implements the given feature id (one of
// YUKIPLT_C_FEATURE_*).  The ABI version stays 1; this lets a caller built
// against a newer header detect whether the opt-in function-import entry points
// below are present before calling them.
int yukiplt_c_has_feature(uint32_t feature_id) YUKIPLT_C_NOEXCEPT;

// Opt-in function-import hooks (JUMP_SLOT + function GLOB_DAT across the named
// sources).  Same image/selector/transaction/ownership/original-output contract
// as yukiplt_c_hook/yukiplt_c_hook_batch.  Each selector's struct_size must equal
// sizeof(yukiplt_c_function_selector), and its sources/types masks must both be
// nonzero.  Acceptance is a whitelist: a slot is hookable only as JUMP_SLOT, or
// as GLOB_DAT whose import symbol is an undefined STT_FUNC with addend zero and a
// nonzero current slot value; any other matched relocation fails the whole call
// with UNSUPPORTED_RELOCATION and modifies nothing.  Unhook/abandon/query with
// the shared yukiplt_c_unhook/abandon/query functions.
yukiplt_c_error yukiplt_c_hook_function(const yukiplt_c_image*, const yukiplt_c_function_selector*,
                                        void* replacement, void** out_original,
                                        yukiplt_c_handle* out_handle,
                                        yukiplt_c_slot_report* report) YUKIPLT_C_NOEXCEPT;
yukiplt_c_error yukiplt_c_hook_functions(const yukiplt_c_image*, const yukiplt_c_function_request*,
                                         size_t count, yukiplt_c_handle* out_handle,
                                         yukiplt_c_slot_report* reports) YUKIPLT_C_NOEXCEPT;

typedef struct yukiplt_c_function_request_ex {
  uint32_t struct_size;  // Must equal sizeof(this exact layout).
  yukiplt_c_function_request base;
  uint32_t require_current;  // 0 or 1 only.
  uintptr_t expected_current;
} yukiplt_c_function_request_ex;
// Value equality is a precondition, not provider authentication. Checked after
// complete VMA validation and before permissions/publication; CAS still applies.
// diagnostic is optional and immediate, including clean precondition failure.
// Output buffers must not alias requests or each other.
yukiplt_c_error yukiplt_c_hook_functions_ex(
    const yukiplt_c_image*, const yukiplt_c_function_request_ex*, size_t count,
    yukiplt_c_handle* out_handle, yukiplt_c_slot_report* reports,
    yukiplt_c_recovery_diagnostic* diagnostic) YUKIPLT_C_NOEXCEPT;
// Actual LOAD intervals only; complete enumeration rejects ambiguity. Android
// ARM64 ignores only the query's TBI top byte, without validating tags/PAC or
// pointer validity. The returned image is not held alive.
yukiplt_c_error yukiplt_c_image_containing(const void* address,
                                           yukiplt_c_image* out_image) YUKIPLT_C_NOEXCEPT;

#ifdef __cplusplus
}
#endif
#undef YUKIPLT_C_NOEXCEPT

#endif  // YUKIPLT_H_
