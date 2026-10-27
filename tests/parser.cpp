// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <gtest/gtest.h>

#include <cstring>
#include <limits>

#include "elf_builder.hpp"
#include "elf.hpp"
#include "imports.hpp"

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

namespace imports_checks {
using namespace yukiplt;
using namespace yukiplt::detail;
using namespace yukiplt::test;

namespace {

ImageView view_of(const ElfBuilder::BuiltImage& image) {
  return {image.load_bias(), image.phdr_table(), image.phdr_count, 1};
}

template <typename T>
void write_at(uintptr_t address, const T& value) {
  std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
}

ElfBuilder builder() {
  ElfBuilder b;
  b.add_symbol("first_import_with_a_long_owned_name", 1).add_symbol("second", 2);
  b.add_jump_slot(2).add_jump_slot(1);
  return b;
}

}  // namespace

TEST(Imports, RejectsInvalidAndUnterminatedNames) {
  for (bool unterminated : {false, true}) {
    auto image = builder().build();
    auto inspected = inspect(image.load_bias(), image.phdr_table(), image.phdr_count);
    ASSERT_TRUE(inspected);
    if (unterminated) {
      std::memset(reinterpret_cast<void*>(inspected.value().strtab), 'x', inspected.value().strsz);
    } else {
      write_at<uint32_t>(inspected.value().symtab + 2 * sizeof(Elf64_Sym),
                         static_cast<uint32_t>(inspected.value().strsz));
    }
    auto result = inspect_imports(view_of(image));
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, ErrorCode::kCorruptedElf);
  }
}

TEST(Imports, RejectsMisalignedOutOfRangeAndOverflowingSlots) {
  for (int mode : {0, 1, 2}) {
    auto image = builder().build();
    auto inspected = inspect(image.load_bias(), image.phdr_table(), image.phdr_count);
    ASSERT_TRUE(inspected);
    const uintptr_t offset = mode == 0   ? image.got_offset + 1
                             : mode == 1 ? image.buffer.size() + 8
                                         : std::numeric_limits<uintptr_t>::max();
    write_at<Elf64_Rela>(inspected.value().jmprel,
                         {offset, ELF64_R_INFO(2, R_AARCH64_JUMP_SLOT), 0});
    auto result = inspect_imports(view_of(image));
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code,
              mode == 2 ? ErrorCode::kIntegerOverflow : ErrorCode::kCorruptedElf);
  }
}

}  // namespace imports_checks

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
  ASSERT_FALSE(raw.has_value());
  EXPECT_EQ(raw.error().code, ErrorCode::kCorruptedElf);

  auto r = resolve_unique_slot(insp.value(), "aliased");
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, ErrorCode::kCorruptedElf);
}

}  // namespace hash_checks
