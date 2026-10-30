// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <dlfcn.h>
#include <stdio.h>

#include "yukiplt.h"

typedef int (*function)(int);
static void* originals[2];
static void* retained_library;
static int replacement0(int x) {
  return ((function)yukiplt_c_load_original(&originals[0]))(x) + 100;
}
static int replacement1(int x) {
  return ((function)yukiplt_c_load_original(&originals[1]))(x) + 100;
}

static int exercise(int functions) {
  void* library = dlopen("./libhook_target.so", RTLD_NOW | RTLD_LOCAL);
  if (!library) {
    puts(dlerror());
    return 1;
  }
  void* address = dlsym(library, "call_import");
  function call = (function)address;
  yukiplt_c_image image;
  if (!call || call(1) != 11 || yukiplt_c_image_containing(address, &image).code) return 2;
  yukiplt_c_plan plan = {0};
  yukiplt_c_session session = {0};
  yukiplt_c_error error;
  size_t failed = 0;
  if (!functions) {
    yukiplt_c_hook_target target = {
        sizeof(target),
        image,
        {YUKIPLT_C_SELECTOR("sample_add"), (void*)replacement0, &originals[0]}};
    error = yukiplt_c_build_plan(&target, 1, &plan, &failed);
  } else {
    yukiplt_c_function_target target = {0};
    target.struct_size = sizeof(target);
    target.image = image;
    target.request.struct_size = sizeof(target.request);
    yukiplt_c_function_selector selector = YUKIPLT_C_FUNCTION_SELECTOR("sample_add");
    selector.sources = YUKIPLT_C_SOURCE_JMPREL;
    selector.types = YUKIPLT_C_TYPE_JUMP_SLOT;
    target.request.base.target = selector;
    target.request.base.replacement = (void*)replacement1;
    target.request.base.out_original = &originals[1];
    target.request.require_current = 1;
    target.request.expected_current = (uintptr_t)yukiplt_c_load_original(&originals[0]);
    error = yukiplt_c_build_function_plan(&target, 1, &plan, &failed);
  }
  if (error.code || failed != SIZE_MAX) return 3;
  if (yukiplt_c_prepare_session(&plan, &session).code || yukiplt_c_plan_destroy(&plan).code)
    return 4;
  yukiplt_c_summary summary;
  if (yukiplt_c_session_install(&session, &summary).code || summary.succeeded != 1) return 5;
  if (call(1) != 111 || yukiplt_c_session_destroy(&session).code != YUKIPLT_C_INVALID_ARGUMENT)
    return 6;
  if (yukiplt_c_session_unhook(&session, &summary).code || summary.retained || call(1) != 11)
    return 7;
  if (yukiplt_c_session_destroy(&session).code) return 8;
  // Keep provider/target loaded until both original snapshots are no longer used.
  if (!functions) {
    retained_library = library;
    return 0;
  }
  return dlclose(library) == 0 ? 0 : 9;
}

static int invalidation(void) {
  void* library = dlopen("./libhook_target.so", RTLD_NOW | RTLD_LOCAL);
  if (!library) return 10;
  yukiplt_c_image image;
  if (yukiplt_c_image_containing(dlsym(library, "call_import"), &image).code) return 11;
  yukiplt_c_hook_target target = {
      sizeof(target), image, {YUKIPLT_C_SELECTOR("sample_add"), (void*)replacement0, NULL}};
  yukiplt_c_plan plan = {0};
  yukiplt_c_session session = {0};
  if (yukiplt_c_build_plan(&target, 1, &plan, NULL).code ||
      yukiplt_c_prepare_session(&plan, &session).code || yukiplt_c_plan_destroy(&plan).code)
    return 12;
  if (dlclose(library)) return 13;
  yukiplt_c_summary summary;
  if (yukiplt_c_session_install(&session, &summary).code != YUKIPLT_C_IMAGE_INVALIDATED) return 14;
  yukiplt_c_recovery_diagnostic diagnostic;
  size_t pages = 0;
  if (yukiplt_c_session_recovery(&session, 0, &diagnostic, NULL, 0, &pages).code ||
      diagnostic.error.code != YUKIPLT_C_IMAGE_INVALIDATED || !diagnostic.image_invalidated)
    return 15;
  return yukiplt_c_session_destroy(&session).code ? 16 : 0;
}

int main(void) {
  int result = invalidation();
  if (!result) result = exercise(0);
  if (!result) result = exercise(1);
  if (!result && retained_library && dlclose(retained_library)) result = 17;
  printf("session_consumer: %d\n", result);
  return result;
}
