// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <stdio.h>
#include <string.h>

#include "../c_abi_layout_checks.h"
#if defined(__ANDROID__)
#include <unistd.h>
#endif

#include "yukiplt.h"
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
  puts("c_consumer: passed");
  return 0;
}
