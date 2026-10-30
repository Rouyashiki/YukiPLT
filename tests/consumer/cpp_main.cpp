// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "../cpp_abi_layout_checks.hpp"
#include "yukiplt.hpp"
int main() {
  yukiplt::OriginalSlot<int (*)(int)> original;
  return original.load() == nullptr ? 0 : 1;
}
