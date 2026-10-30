// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../c_abi_layout_checks.h"
#if defined(__ANDROID__)
#include <unistd.h>
#endif

#include "yukiplt.h"
static int metadata_anchor;
static int owned_metadata(void) {
  yukiplt_c_image_list images = {0};
  yukiplt_c_import_snapshot imports = {0};
  yukiplt_c_image_record record;
  size_t count = 0, bytes = 0, skipped = 0;
  uint32_t kind = 0;
  char* text = NULL;
  int result = 1;
  if (yukiplt_c_find_image_containing(&metadata_anchor, &images).code) goto done;
  if (yukiplt_c_image_list_copy(&images, NULL, 0, NULL, 0, &count, &bytes).code || count != 1)
    goto done;
  text = (char*)malloc(bytes);
  if (!text) goto done;
  if (yukiplt_c_image_list_copy(&images, &record, 1, text, bytes, &count, &bytes).code) goto done;
  yukiplt_c_named_image named = {sizeof(named), record.image, text + record.path.offset};
  if (yukiplt_c_inspect_imports_named(&named, YUKIPLT_C_SNAPSHOT_VERSIONED, 0, &imports).code)
    goto done;
  if (yukiplt_c_image_list_destroy(&images).code) goto done;
  if (yukiplt_c_import_snapshot_copy(&imports, NULL, 0, NULL, 0, &count, &bytes, &kind, &skipped)
          .code)
    goto done;
  if (kind != YUKIPLT_C_SNAPSHOT_VERSIONED) goto done;
  result = 0;
done:
  free(text);
  if (yukiplt_c_import_snapshot_destroy(&imports).code) result = 1;
  if (yukiplt_c_image_list_destroy(&images).code) result = 1;
  return result;
}
int main(void) {
  void* original = NULL;
  if (yukiplt_c_abi_version() != 1 || !yukiplt_c_has_feature(YUKIPLT_C_FEATURE_ORIGINAL_LOAD) ||
      yukiplt_c_load_original(&original) != NULL)
    return 1;
#if defined(__ANDROID__)
  printf("identity: bits=%zu page=%ld uid=%ld gid=%ld\n", sizeof(void*) * 8, sysconf(_SC_PAGESIZE),
         (long)getuid(), (long)getgid());
  const char* files[] = {"/proc/self/attr/current", "/proc/self/status"};
  for (size_t i = 0; i < 2; ++i) {
    FILE* stream = fopen(files[i], "r");
    if (!stream) return 2;
    char line[512];
    while (fgets(line, sizeof(line), stream)) {
      if (i == 0 || strncmp(line, "CapEff:", 7) == 0 || strncmp(line, "CapPrm:", 7) == 0)
        printf("%s", line);
    }
    fclose(stream);
  }
#endif
  if (owned_metadata()) return 3;
  puts("c_consumer: passed");
  return 0;
}
