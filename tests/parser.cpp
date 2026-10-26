// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <gtest/gtest.h>

#include "elf_builder.hpp"
#include "elf.hpp"

namespace elf_inspector_checks {
using namespace yukiplt;
using namespace yukiplt::detail;
using namespace yukiplt::test;

TEST(ElfInspector, MissingDtNull) {
  ElfBuilder b;
  b.add_symbol("f", 1);
  b.add_jump_slot(1);
  b.set_gnu_hash(true);
  b.omit_dt_null();

  auto img = b.build();
  auto result = inspect(img.load_bias(), img.phdr_table(), img.phdr_count);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error().code, ErrorCode::kCorruptedElf);
}

}  // namespace elf_inspector_checks

namespace hash_checks {
using namespace yukiplt;
using namespace yukiplt::detail;
using namespace yukiplt::test;

TEST(Resolver, UniqueSlotAmbiguousTwoDistinctSlots) {
  ElfBuilder b;
  b.add_symbol("dup", 1);
  b.add_jump_slot(1);
  b.add_jump_slot(1);
  b.set_gnu_hash(true);

  auto img = b.build();
  auto insp = inspect(img.load_bias(), img.phdr_table(), img.phdr_count);
  ASSERT_TRUE(insp.has_value());

  EXPECT_NE(img.got_slot_addr(0), img.got_slot_addr(1));

  auto r = resolve_unique_slot(insp.value(), "dup");
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, ErrorCode::kAmbiguousSymbol);
}

TEST(Resolver, UniqueSlotDuplicateRecordsRejected) {
  ElfBuilder b;
  b.add_symbol("aliased", 1);
  b.add_jump_slot(1);
  b.alias_jump_slot(1, 0);
  b.set_gnu_hash(true);

  auto img = b.build();
  auto insp = inspect(img.load_bias(), img.phdr_table(), img.phdr_count);
  ASSERT_TRUE(insp.has_value());

  auto raw = resolve_slots(insp.value(), "aliased");
  ASSERT_TRUE(raw.has_value());
  ASSERT_EQ(raw.value().size(), 2u);
  EXPECT_EQ(raw.value()[0].address, raw.value()[1].address);

  auto r = resolve_unique_slot(insp.value(), "aliased");
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, ErrorCode::kCorruptedElf);
}

}  // namespace hash_checks
