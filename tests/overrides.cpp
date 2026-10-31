// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "overrides.hpp"

#include <atomic>

namespace yukiplt::detail {
std::atomic<const PlatformOps*> g_active_ops{nullptr};
const PlatformOps& wrapped_active_ops() noexcept asm("__wrap__ZN7yukiplt6detail10active_opsEv");
const PlatformOps& wrapped_active_ops() noexcept {
  const PlatformOps* p = g_active_ops.load(std::memory_order_acquire);
  return p != nullptr ? *p : system_ops();
}
void set_active_ops(const PlatformOps* ops) noexcept {
  g_active_ops.store(ops, std::memory_order_release);
}
std::atomic<ImageEnumerator> g_image_enumerator{nullptr};
ImageEnumerator wrapped_image_enumerator() noexcept
    asm("__wrap__ZN7yukiplt6detail23active_image_enumeratorEv");
ImageEnumerator wrapped_image_enumerator() noexcept {
  ImageEnumerator override_fn = g_image_enumerator.load(std::memory_order_acquire);
  return override_fn != nullptr ? override_fn : &find_images;
}
void set_active_image_enumerator(ImageEnumerator enumerator) noexcept {
  g_image_enumerator.store(enumerator, std::memory_order_release);
}
std::atomic<SystemIterator> g_system_iterator{nullptr};
void set_system_iterator(SystemIterator iterator) noexcept {
  g_system_iterator.store(iterator, std::memory_order_release);
}
}  // namespace yukiplt::detail

extern "C" int __real_dl_iterate_phdr(int (*callback)(dl_phdr_info*, size_t, void*), void* data);
extern "C" int __wrap_dl_iterate_phdr(int (*callback)(dl_phdr_info*, size_t, void*), void* data) {
  auto iterator = yukiplt::detail::g_system_iterator.load(std::memory_order_acquire);
  return iterator ? iterator(callback, data) : __real_dl_iterate_phdr(callback, data);
}
