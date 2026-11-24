// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

extern int sample_add(int);
int call_import(int x) { return sample_add(x) + 3; }

#if defined(__riscv) && __riscv_xlen == 64
typedef int (*function)(int);
function sample_data_pointer = sample_add;
function sample_got_pointer(void) { return sample_add; }
#endif
