// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "../cpp_abi_layout_checks.hpp"
#include "identity.h"
#include "yukiplt.hpp"
int main() {
  if (test_identity()) return 40;
  yukiplt::OriginalSlot<int (*)(int)> original;
  return original.load() == nullptr ? 0 : 1;
}
