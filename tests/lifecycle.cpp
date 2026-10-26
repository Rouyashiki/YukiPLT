// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <gtest/gtest.h>

#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

#include "memory.hpp"
#include "registry.hpp"

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
