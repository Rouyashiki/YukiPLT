// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include "elf_builder.hpp"
#include "overrides.hpp"
#include "memory.hpp"
#include "registry.hpp"
#include "system_images.hpp"
#include "yukiplt.h"
#include "yukiplt.hpp"

namespace contracts_checks {
using namespace yukiplt;

namespace {

struct ContractFixture : testing::Test {
  test::ElfBuilder::BuiltImage image;
  uintptr_t first_page = 0;
  uintptr_t end_page = 0;

  bool writable = false;

  bool hide_image = false;
  int fail_raise = 0;
  int fail_restore = 0;
  size_t protect_calls = 0;
  size_t maps_calls = 0;
  size_t cas_calls = 0;

  size_t race_before_cas = 0;
  uintptr_t race_value = 0;
  void* outputs[2]{};

  void* output_at_first_cas = nullptr;
  detail::PlatformOps ops{
      [](void* p, uintptr_t, size_t, int prot) {
        auto& self = *static_cast<ContractFixture*>(p);
        ++self.protect_calls;
        const bool raise = (prot & detail::kProtWrite) != 0;
        if (raise && self.fail_raise != 0) return self.fail_raise;
        if (!raise && self.fail_restore != 0) return self.fail_restore;
        self.writable = raise;
        return 0;
      },
      [](void* p, detail::MapsCoverage& coverage) {
        auto& self = *static_cast<ContractFixture*>(p);
        ++self.maps_calls;
        char line[128];
        if (!self.hide_image) {
          std::snprintf(line, sizeof(line), "%zx-%zx %s 00000000 00:00 0",
                        static_cast<size_t>(self.first_page), static_cast<size_t>(self.end_page),
                        self.writable ? "rw-p" : "r--p");
          coverage.feed_line(line, std::strlen(line));
        }
        return coverage.finish();
      },
      [](void*, uintptr_t address) {
        return __atomic_load_n(reinterpret_cast<uintptr_t*>(address), __ATOMIC_ACQUIRE);
      },
      [](void* p, uintptr_t address, uintptr_t* expected, uintptr_t desired) {
        auto& self = *static_cast<ContractFixture*>(p);
        if (self.cas_calls == 0)
          self.output_at_first_cas = __atomic_load_n(&self.outputs[0], __ATOMIC_ACQUIRE);
        if (++self.cas_calls == self.race_before_cas)
          __atomic_store_n(reinterpret_cast<uintptr_t*>(self.image.got_slot_addr(1)),
                           self.race_value, __ATOMIC_RELEASE);
        return __atomic_compare_exchange_n(reinterpret_cast<uintptr_t*>(address), expected, desired,
                                           false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
      },
      this};

  void SetUp() override {
    test::ElfBuilder builder;
    builder.add_symbol("alpha", 1).add_symbol("beta", 2).add_jump_slot(1).add_jump_slot(2);
    image = builder.build();
    const size_t ps = detail::page_size();
    ASSERT_NE(ps, 0u);
    first_page = image.load_bias() & ~(ps - 1);
    end_page = (image.load_bias() + image.buffer.size() + ps - 1) & ~(ps - 1);
    set_slot(0, 0x1000);
    set_slot(1, 0x2000);
    detail::set_active_ops(&ops);
  }
  void TearDown() override { detail::set_active_ops(nullptr); }

  ImageView view(uint64_t token = 0x51) const {
    return {image.load_bias(), image.phdr_table(), image.phdr_count, token};
  }
  uintptr_t slot(size_t i) const {
    return __atomic_load_n(reinterpret_cast<uintptr_t*>(image.got_slot_addr(i)), __ATOMIC_ACQUIRE);
  }
  void set_slot(size_t i, uintptr_t value) {
    __atomic_store_n(reinterpret_cast<uintptr_t*>(image.got_slot_addr(i)), value, __ATOMIC_RELEASE);
  }
  void reset_counts() { protect_calls = maps_calls = cas_calls = 0; }
};

void* const kReplA = reinterpret_cast<void*>(uintptr_t{0xA000});
void* const kReplB = reinterpret_cast<void*>(uintptr_t{0xB000});

}  // namespace

TEST_F(ContractFixture, SuccessPublishesBeforeTheReplacementIsReachable) {
  output_at_first_cas = reinterpret_cast<void*>(uintptr_t{1});
  auto result = hook_import(view(), {"alpha"}, kReplA, &outputs[0]);
  ASSERT_TRUE(result.ok());

  EXPECT_EQ(output_at_first_cas, reinterpret_cast<void*>(uintptr_t{0x1000}));
  EXPECT_EQ(slot(0), reinterpret_cast<uintptr_t>(kReplA));
  EXPECT_TRUE(unhook(result.handle).ok());
  EXPECT_EQ(slot(0), 0x1000u);
}

TEST_F(ContractFixture, CustomImageMissingFromMapsKeepsHandleUntilForgotten) {
  auto result = hook_import(view(0x61), {"alpha"}, kReplA, &outputs[0]);
  ASSERT_TRUE(result.ok());
  hide_image = true;
  EXPECT_EQ(unhook(result.handle).code, ErrorCode::kOutOfBounds);
  ASSERT_TRUE(result.handle.valid());
  EXPECT_EQ(slot(0), reinterpret_cast<uintptr_t>(kReplA));

  hide_image = false;
  EXPECT_EQ(hook_import(view(0x61), {"alpha"}, kReplB, nullptr).error.code,
            ErrorCode::kAlreadyHooked);

  EXPECT_TRUE(forget_image(view(0x62)).ok());
  hide_image = true;
  EXPECT_EQ(unhook(result.handle).code, ErrorCode::kOutOfBounds);
  ASSERT_TRUE(result.handle.valid());

  EXPECT_TRUE(forget_image(view(0x61)).ok());
  EXPECT_EQ(unhook(result.handle).code, ErrorCode::kImageInvalidated);
  EXPECT_FALSE(result.handle.valid());
  EXPECT_EQ(slot(0), reinterpret_cast<uintptr_t>(kReplA));
}

TEST_F(ContractFixture, ResidueAlreadyRestoredByThirdPartyNeedsNoProtectCall) {
  fail_restore = EPERM;
  auto result = hook_import(view(0x81), {"alpha"}, kReplA, &outputs[0]);
  ASSERT_EQ(result.error.code, ErrorCode::kIndeterminate);
  ASSERT_TRUE(result.handle.valid());
  ASSERT_TRUE(writable);

  writable = false;
  set_slot(0, 0x1000);
  fail_restore = 0;
  reset_counts();
  EXPECT_TRUE(unhook(result.handle).ok());
  EXPECT_EQ(protect_calls, 0u);
  EXPECT_FALSE(result.handle.valid());
}

}  // namespace contracts_checks

namespace concurrency_checks {
using namespace yukiplt;
using namespace yukiplt::detail;

namespace {

ImageIdentity img(uintptr_t bias) {
  ImageIdentity id;
  id.load_bias = bias;
  id.phdr_addr = bias + 0x40;
  id.phdr_count = 4;
  return id;
}

SlotRecord slot(uintptr_t a) {
  SlotRecord s;
  s.address = a;
  return s;
}

}  // namespace

TEST(Concurrency, ContendedClaimOneOwner) {
  Registry& reg = Registry::instance();
  size_t baseline;
  {
    std::lock_guard<std::mutex> lock(op_mutex());
    baseline = reg.live_count();
  }

  constexpr int kThreads = 8;
  constexpr int kRounds = 500;
  constexpr uintptr_t kSlot = 0x7f00;
  std::atomic<int> concurrent_owners{0};
  std::atomic<int> max_owners{0};
  std::atomic<int> bad{0};
  std::vector<std::thread> ts;

  for (int i = 0; i < kThreads; ++i) {
    ts.emplace_back([&] {
      for (int r = 0; r < kRounds; ++r) {
        uint64_t id;
        {
          std::lock_guard<std::mutex> lock(op_mutex());
          SlotRecord s[] = {slot(kSlot)};
          id = reg.claim(img(0x1000), s, 1);
        }
        if (id == Registry::kInvalidId) continue;

        int now = concurrent_owners.fetch_add(1) + 1;
        int prev_max = max_owners.load();
        while (now > prev_max && !max_owners.compare_exchange_weak(prev_max, now)) {
        }

        concurrent_owners.fetch_sub(1);

        std::lock_guard<std::mutex> lock(op_mutex());
        if (!reg.release(id).ok()) bad.fetch_add(1);
      }
    });
  }
  for (auto& t : ts) t.join();

  EXPECT_EQ(bad.load(), 0);
  EXPECT_LE(max_owners.load(), 1) << "two threads owned the same slot at once";
  std::lock_guard<std::mutex> lock(op_mutex());
  EXPECT_EQ(reg.live_count(), baseline);
}

}  // namespace concurrency_checks

namespace registry_checks {
using namespace yukiplt;
using namespace yukiplt::detail;

namespace {

ImageIdentity sys_image(uintptr_t bias = 0x1000) {
  ImageIdentity id;
  id.load_bias = bias;
  id.phdr_addr = bias + 0x40;
  id.phdr_count = 8;
  id.instance_token = 0;
  return id;
}

SlotRecord slot(uintptr_t addr, uintptr_t orig = 0, uintptr_t repl = 0) {
  SlotRecord s;
  s.address = addr;
  s.original = orig;
  s.replacement = repl;
  return s;
}

}  // namespace

TEST(Registry, GenerationRejectsStaleHandle) {
  Registry& reg = Registry::instance();
  SlotRecord s[] = {slot(0x3000)};
  uint64_t a = reg.claim(sys_image(), s, 1);
  ASSERT_NE(a, Registry::kInvalidId);
  reg.mark_installed(a);
  EXPECT_TRUE(reg.is_installed(a));
  reg.drop(a);

  uint64_t b = reg.claim(sys_image(), s, 1);
  ASSERT_NE(b, Registry::kInvalidId);
  EXPECT_NE(a, b);
  EXPECT_FALSE(reg.is_installed(a));
  ImageIdentity img;
  SlotRecord out[1];
  size_t n = 0;
  EXPECT_EQ(reg.snapshot(a, img, out, 1, &n).code, ErrorCode::kInvalidArgument);
  reg.drop(b);
}

}  // namespace registry_checks

namespace rules_checks {
using namespace yukiplt;
using test::ElfBuilder;

namespace {

struct FakeImage {
  ElfBuilder::BuiltImage built;
  std::string path;
  uint64_t token = 0;

  ImageView view() const {
    return {built.load_bias(), built.phdr_table(), built.phdr_count, token};
  }
  uintptr_t slot() const { return built.got_slot_addr(0); }
};

struct RulesFixture : testing::Test {
  std::vector<FakeImage> images;

  uintptr_t first_page = 0;
  uintptr_t end_page = 0;
  bool writable = false;
  size_t enumeration_calls = 0;

  static RulesFixture* current;

  detail::PlatformOps ops{
      [](void* p, uintptr_t, size_t, int prot) {
        static_cast<RulesFixture*>(p)->writable = (prot & detail::kProtWrite) != 0;
        return 0;
      },
      [](void* p, detail::MapsCoverage& coverage) {
        auto& self = *static_cast<RulesFixture*>(p);
        const size_t ps = detail::page_size();

        std::vector<std::pair<uintptr_t, uintptr_t>> ranges;
        for (const auto& image : self.images) {
          uintptr_t begin = image.built.load_bias() & ~(ps - 1);
          uintptr_t end =
              (image.built.load_bias() + image.built.buffer.size() + ps - 1) & ~(ps - 1);
          ranges.emplace_back(begin, end);
        }
        std::sort(ranges.begin(), ranges.end());

        for (size_t i = 0; i < ranges.size(); ++i) {
          uintptr_t begin = ranges[i].first;
          uintptr_t end = ranges[i].second;
          while (i + 1 < ranges.size() && ranges[i + 1].first <= end) {
            end = std::max(end, ranges[i + 1].second);
            ++i;
          }
          char line[128];
          std::snprintf(line, sizeof(line), "%zx-%zx %s 00000000 00:00 0",
                        static_cast<size_t>(begin), static_cast<size_t>(end),
                        self.writable ? "rw-p" : "r--p");
          coverage.feed_line(line, std::strlen(line));
        }
        return coverage.finish();
      },
      [](void*, uintptr_t address) {
        return __atomic_load_n(reinterpret_cast<uintptr_t*>(address), __ATOMIC_ACQUIRE);
      },
      [](void*, uintptr_t address, uintptr_t* expected, uintptr_t desired) {
        return __atomic_compare_exchange_n(reinterpret_cast<uintptr_t*>(address), expected, desired,
                                           false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
      },
      this};

  void SetUp() override {
    current = this;
    detail::set_active_ops(&ops);
    detail::set_active_image_enumerator(&RulesFixture::enumerate);
  }
  void TearDown() override {
    detail::set_active_image_enumerator(nullptr);
    detail::set_active_ops(nullptr);
    current = nullptr;
  }

  static uint64_t next_token() {
    static uint64_t counter = 0x1000;
    return ++counter;
  }

  FakeImage& add_image(const char* path, uintptr_t slot_value) {
    ElfBuilder b;
    b.add_symbol("target", 1).add_jump_slot(1);
    FakeImage image;
    image.built = b.build();
    image.path = path;
    image.token = next_token();
    __atomic_store_n(reinterpret_cast<uintptr_t*>(image.built.got_slot_addr(0)), slot_value,
                     __ATOMIC_RELEASE);
    images.push_back(std::move(image));
    return images.back();
  }

  static Result<std::vector<NamedImage>> enumerate(const ImageSelector& selector) {
    ++current->enumeration_calls;
    if (selector.name && current->failed_filter == selector.name)
      return Error::Make(ErrorCode::kOutOfMemory);
    if (current->enumeration_error != ErrorCode::kSuccess)
      return Error::Make(current->enumeration_error);
    std::vector<NamedImage> out;
    for (const auto& image : current->images) {
      bool match = selector.match == ImageMatch::kMainExecutable ||
                   (selector.match == ImageMatch::kBasename && selector.name != nullptr &&
                    image.path == selector.name);
      if (match) out.push_back({image.view(), image.path});
    }
    if (out.empty()) return Error::Make(ErrorCode::kImageNotFound);
    return out;
  }

  uintptr_t read(uintptr_t addr) const {
    return __atomic_load_n(reinterpret_cast<uintptr_t*>(addr), __ATOMIC_ACQUIRE);
  }
  void write(uintptr_t addr, uintptr_t value) {
    __atomic_store_n(reinterpret_cast<uintptr_t*>(addr), value, __ATOMIC_RELEASE);
  }

  ErrorCode enumeration_error = ErrorCode::kSuccess;
  std::string failed_filter;
};

RulesFixture* RulesFixture::current = nullptr;

ImageSelector match_basename(const char* name) { return {ImageMatch::kBasename, name, 0}; }

void* const kRepl = reinterpret_cast<void*>(uintptr_t{0xA000});

FunctionImportSelector target_selector() {
  FunctionImportSelector s;
  s.base.symbol = "target";
  s.sources = kSourceJmprel;
  s.types = kTypeJumpSlot;
  return s;
}

}  // namespace

TEST_F(RulesFixture, NotifyUnloadingFailureKeepsHandleAndDoesNotForget) {
  auto& image = add_image("libkeep.so", 0x1000);
  RuleSet rules;
  void* originals[1]{};
  ASSERT_TRUE(rules.add_rule(match_basename("libkeep.so"), target_selector(), kRepl, originals, 1));
  ASSERT_EQ(rules.notify_loaded(image.view(), "libkeep.so").succeeded, 1u);

  write(image.slot(), 0xC000);
  auto failed = rules.notify_unloading(image.view());
  EXPECT_EQ(failed.failed, 1u);
  EXPECT_EQ(failed.retained, 1u);
  EXPECT_EQ(rules.bindings()[0].state, RuleState::kRestoreFailed);

  EXPECT_EQ(
      hook_import(image.view(), {"target"}, reinterpret_cast<void*>(uintptr_t{0xB000}), nullptr)
          .error.code,
      ErrorCode::kAlreadyHooked);

  ASSERT_TRUE(forget_image(image.view()).ok());
  auto after_forget = rules.notify_unloading(image.view());
  EXPECT_EQ(after_forget.failed, 0u);
  EXPECT_EQ(rules.bindings()[0].state, RuleState::kInvalidated);
  EXPECT_EQ(read(image.slot()), 0xC000u);
  write(image.slot(), 0x1000);
}

}  // namespace rules_checks
