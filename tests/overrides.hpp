// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#pragma once
#include "memory.hpp"
#include "system_images.hpp"

namespace yukiplt::detail {
void set_active_ops(const PlatformOps* ops) noexcept;
void set_active_image_enumerator(ImageEnumerator enumerator) noexcept;
}  // namespace yukiplt::detail
