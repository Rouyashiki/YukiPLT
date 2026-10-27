// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <gtest/gtest.h>

#include <cstdlib>
#include <new>

#include "elf_builder.hpp"
#include "overrides.hpp"
#include "memory.hpp"
#include "registry.hpp"
#include "versioned_elf.hpp"
#include "yukiplt.h"
#include "yukiplt.hpp"

namespace {
thread_local int fail_after = -1;
}

void* operator new(std::size_t size) {
  if (fail_after >= 0 && fail_after-- == 0) throw std::bad_alloc();
  if (void* result = std::malloc(size == 0 ? 1 : size)) return result;
  throw std::bad_alloc();
}
void operator delete(void* pointer) noexcept { std::free(pointer); }
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete[](void* pointer) noexcept { ::operator delete(pointer); }
void operator delete(void* pointer, std::size_t) noexcept { ::operator delete(pointer); }
void operator delete[](void* pointer, std::size_t) noexcept { ::operator delete(pointer); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
  try {
    return ::operator new(size);
  } catch (...) {
    return nullptr;
  }
}
void* operator new[](std::size_t size, const std::nothrow_t& tag) noexcept {
  return ::operator new(size, tag);
}
void operator delete(void* pointer, const std::nothrow_t&) noexcept { ::operator delete(pointer); }
void operator delete[](void* pointer, const std::nothrow_t&) noexcept {
  ::operator delete(pointer);
}

namespace {
using namespace yukiplt;

size_t live_groups() {
  std::lock_guard<std::mutex> lock(detail::op_mutex());
  return detail::Registry::instance().live_count();
}

struct AllocationFixture {
  static constexpr size_t count = 9;
  std::string names[count];
  void* originals[count]{};
  HookRequest legacy[count];
  SelectedHookRequest selected[count];
  test::ElfBuilder::BuiltImage image;
  char maps[128]{};
  size_t writes = 0;
  detail::PlatformOps ops{
      [](void*, uintptr_t, size_t, int) { return 0; },
      [](void* ctx, detail::MapsCoverage& coverage) {
        auto& self = *static_cast<AllocationFixture*>(ctx);
        coverage.feed_line(self.maps, std::strlen(self.maps));
        return coverage.finish();
      },
      [](void*, uintptr_t address) {
        return __atomic_load_n(reinterpret_cast<uintptr_t*>(address), __ATOMIC_ACQUIRE);
      },
      [](void* ctx, uintptr_t address, uintptr_t* expected, uintptr_t desired) {
        ++static_cast<AllocationFixture*>(ctx)->writes;
        return __atomic_compare_exchange_n(reinterpret_cast<uintptr_t*>(address), expected, desired,
                                           false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
      },
      this};

  AllocationFixture() {
    test::ElfBuilder builder;
    for (size_t i = 0; i < count; ++i) {
      names[i] = "allocation_failure_import_" + std::to_string(i);
      builder.add_symbol(names[i].c_str(), static_cast<uint32_t>(i + 1))
          .add_jump_slot(static_cast<uint32_t>(i + 1));
      auto* replacement = reinterpret_cast<void*>(uintptr_t{0x12345678});
      legacy[i] = {names[i].c_str(), replacement, &originals[i]};
      selected[i] = {{names[i].c_str()}, replacement, &originals[i]};
    }
    image = builder.build();
    const auto ps = detail::page_size();
    const auto start = image.load_bias() & ~(ps - 1);
    const auto end = (image.load_bias() + image.buffer.size() + ps - 1) & ~(ps - 1);
    std::snprintf(maps, sizeof(maps), "%zx-%zx rw-p 00000000 00:00 0", start, end);
    detail::set_active_ops(&ops);
  }
  ~AllocationFixture() { detail::set_active_ops(nullptr); }
  ImageView view() const { return {image.load_bias(), image.phdr_table(), image.phdr_count, 41}; }
  HookResult install(bool explicit_selector) {
    return explicit_selector ? hook_imports(view(), selected, count)
                             : hook_batch(view(), legacy, count);
  }
};
}  // namespace

TEST(ImportAllocation, FailedInstallNeverStrandsOwnershipOrPublishesOriginals) {
  for (bool selected : {true, false}) {
    AllocationFixture fixture;
    const auto before = fixture.image.buffer;
    const size_t baseline = live_groups();
    int failures = 0;
    bool completed = false;
    for (int allocation = 0; allocation < 256; ++allocation) {
      fail_after = allocation;
      auto result = fixture.install(selected);
      fail_after = -1;
      if (result.ok()) {
        ASSERT_FALSE(yukiplt::unhook(result.handle));
        completed = true;
        break;
      }
      ASSERT_EQ(result.error.code, yukiplt::ErrorCode::kOutOfMemory);
      EXPECT_FALSE(result.handle.valid());
      EXPECT_EQ(fixture.image.buffer, before);
      EXPECT_EQ(fixture.writes, 0u);
      for (void* original : fixture.originals) EXPECT_EQ(original, nullptr);
      ASSERT_EQ(live_groups(), baseline) << "allocation " << allocation;
      ++failures;
    }
    EXPECT_TRUE(completed);
    EXPECT_GE(failures, 3);
    EXPECT_EQ(live_groups(), baseline);
    auto retry = fixture.install(selected);
    ASSERT_TRUE(retry.ok());
    EXPECT_FALSE(yukiplt::unhook(retry.handle));
  }
}
