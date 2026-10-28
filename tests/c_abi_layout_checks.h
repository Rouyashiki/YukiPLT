// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

// Compile the same ABI checks in C and C++, including native 32-bit targets.
#ifndef YUKIPLT_TEST_C_ABI_LAYOUT_CHECKS_H_
#define YUKIPLT_TEST_C_ABI_LAYOUT_CHECKS_H_
#include "yukiplt.h"
#ifdef __cplusplus
#define YK_STATIC_ASSERT(value) static_assert(value)
#else
#define YK_STATIC_ASSERT(value) _Static_assert(value, #value)
#endif
YK_STATIC_ASSERT(YUKIPLT_C_ABI_VERSION == 1);
YK_STATIC_ASSERT(YUKIPLT_C_SOURCE_RELA == 2 && YUKIPLT_C_SOURCE_ANDROID_RELA == 4);
YK_STATIC_ASSERT(YUKIPLT_C_SOURCE_REL == 8 && YUKIPLT_C_SOURCE_ANDROID_REL == 16);
YK_STATIC_ASSERT(YUKIPLT_C_RELOC_SOURCE_RELA == 1 && YUKIPLT_C_RELOC_SOURCE_ANDROID_RELA == 2);
YK_STATIC_ASSERT(YUKIPLT_C_RELOC_SOURCE_REL == 3 && YUKIPLT_C_RELOC_SOURCE_ANDROID_REL == 4);
YK_STATIC_ASSERT(YUKIPLT_C_FEATURE_REL_IMPORTS == 6);
YK_STATIC_ASSERT(sizeof(yukiplt_c_error) == 8 && sizeof(yukiplt_c_handle) == 8);
YK_STATIC_ASSERT(offsetof(yukiplt_c_function_selector, base) == 16);
#if YUKIPLT_ELF_BITS == 64
YK_STATIC_ASSERT(sizeof(yukiplt_c_image) == 32);
YK_STATIC_ASSERT(offsetof(yukiplt_c_image, instance_token) == 24);
YK_STATIC_ASSERT(sizeof(yukiplt_c_selector) == 48);
YK_STATIC_ASSERT(sizeof(yukiplt_c_request) == 64);
YK_STATIC_ASSERT(sizeof(yukiplt_c_function_selector) == 64);
YK_STATIC_ASSERT(sizeof(yukiplt_c_function_request) == 80);
YK_STATIC_ASSERT(sizeof(yukiplt_c_slot_report) == 32);
#else
YK_STATIC_ASSERT(sizeof(yukiplt_c_selector) == 24);
YK_STATIC_ASSERT(sizeof(yukiplt_c_request) == 32);
YK_STATIC_ASSERT(sizeof(yukiplt_c_function_selector) == 40);
YK_STATIC_ASSERT(sizeof(yukiplt_c_function_request) == 48);
YK_STATIC_ASSERT(sizeof(yukiplt_c_slot_report) == 16);
#if YUKIPLT_ELF_MACHINE == 40
YK_STATIC_ASSERT(sizeof(yukiplt_c_image) == 24);
YK_STATIC_ASSERT(offsetof(yukiplt_c_image, instance_token) == 16);
#else
YK_STATIC_ASSERT(sizeof(yukiplt_c_image) == 20);
YK_STATIC_ASSERT(offsetof(yukiplt_c_image, instance_token) == 12);
#endif
#endif
#undef YK_STATIC_ASSERT
#endif
