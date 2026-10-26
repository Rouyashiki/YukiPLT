// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

/// \brief Test helper: construct ELF images in memory.
///
/// ElfBuilder allocates an aligned buffer and writes ELF structures into it.
/// The resulting buffer has p_vaddr = 0 for its PT_LOAD segment, so
/// load_bias == buffer base address.  This allows the inspector to work
/// on Host (any architecture) using constructed byte buffers.

#ifndef YUKIPLT_TEST_ELF_BUILDER_HPP_
#define YUKIPLT_TEST_ELF_BUILDER_HPP_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "yukiplt.hpp"

namespace yukiplt::test {

/// Build a minimal ELF image in memory for testing the inspector.
///
/// Usage:
///   ElfBuilder b;
///   b.add_symbol("foo", 1);
///   b.add_jump_slot("foo", 1, 0);  // sym index 1, addend 0
///   b.set_gnu_hash(true);
///   auto img = b.build();
///   // img.phdr_table(), img.phdr_count(), img.load_bias() are ready.
///
/// The builder lays out structures in a flat buffer:
///   [phdr_table | dynamic_section | strtab | symtab | gnu_hash | sysv_hash | jmprel | got]
///
/// Everything lives in one PT_LOAD segment with p_vaddr = 0,
/// so load_bias = buffer base address.
class ElfBuilder {
 public:
  /// A symbol to place in the symbol table.
  struct SymEntry {
    std::string name;
    uint32_t sym_index;  ///< Desired index in symtab (0 is reserved for STN_UNDEF).
  };

  /// A JUMP_SLOT relocation entry.
  struct JmpSlotEntry {
    uint32_t sym_index;
    int64_t addend;
    // The GOT slot address will be assigned by build().
  };

  // --- Configuration ---

  ElfBuilder& add_symbol(const char* name, uint32_t index) {
    symbols_.push_back({name, index});
    return *this;
  }

  ElfBuilder& add_jump_slot(uint32_t sym_index, int64_t addend = 0) {
    jmpslots_.push_back({sym_index, addend});
    return *this;
  }

  /// Add a relocation with a custom type (for testing unsupported types).
  ElfBuilder& add_custom_rela(uint32_t sym_index, uint32_t rela_type, int64_t addend = 0) {
    custom_relas_.push_back({sym_index, rela_type, addend});
    return *this;
  }

  ElfBuilder& set_gnu_hash(bool enable) {
    use_gnu_hash_ = enable;
    return *this;
  }
  ElfBuilder& set_sysv_hash(bool enable) {
    use_sysv_hash_ = enable;
    return *this;
  }

  /// Override DT_PLTREL (default: DT_RELA).
  ElfBuilder& set_pltrel(uint64_t val) {
    pltrel_override_ = val;
    return *this;
  }

  /// Override DT_SYMENT (default: sizeof(Elf64_Sym)).
  ElfBuilder& set_syment(uint64_t val) {
    syment_override_ = val;
    return *this;
  }

  /// Mark the entire PT_LOAD as RELRO.
  ElfBuilder& set_relro(bool enable) {
    use_relro_ = enable;
    return *this;
  }

  /// Truncate the dynamic section to this many entries (for testing).
  /// 0 means no truncation.
  ElfBuilder& truncate_dynamic(size_t max_entries) {
    truncate_dyn_ = max_entries;
    return *this;
  }

  /// Inject an overflow-inducing vaddr for PT_LOAD (for testing).
  ElfBuilder& set_load_vaddr(uint64_t vaddr) {
    load_vaddr_override_ = vaddr;
    has_load_vaddr_override_ = true;
    return *this;
  }

  /// Remove all hash tables (for testing kNoHashTable).
  ElfBuilder& set_no_hash() {
    use_gnu_hash_ = false;
    use_sysv_hash_ = false;
    return *this;
  }

  /// Omit DT_SYMTAB from the dynamic section (for testing).
  ElfBuilder& omit_symtab(bool v = true) {
    omit_symtab_ = v;
    return *this;
  }

  /// Omit DT_STRTAB from the dynamic section (for testing).
  ElfBuilder& omit_strtab(bool v = true) {
    omit_strtab_ = v;
    return *this;
  }

  /// Omit DT_STRSZ from the dynamic section (for testing).
  ElfBuilder& omit_strsz(bool v = true) {
    omit_strsz_ = v;
    return *this;
  }

  // --- Build ---

  struct BuiltImage {
    std::vector<uint8_t> buffer;
    size_t phdr_offset = 0;
    size_t phdr_count = 0;

    uintptr_t load_bias() const { return reinterpret_cast<uintptr_t>(buffer.data()); }

    const Elf64_Phdr* phdr_table() const {
      return reinterpret_cast<const Elf64_Phdr*>(buffer.data() + phdr_offset);
    }

    /// Address of the GOT slot for the i-th JUMP_SLOT relocation.
    uintptr_t got_slot_addr(size_t i) const;

    size_t got_offset = 0;  // Offset of GOT in buffer
  };

  /// Build the image.  The returned BuiltImage owns the buffer.
  BuiltImage build() const;

 private:
  struct CustomRela {
    uint32_t sym_index;
    uint32_t rela_type;
    int64_t addend;
  };

  std::vector<SymEntry> symbols_;
  std::vector<JmpSlotEntry> jmpslots_;
  std::vector<CustomRela> custom_relas_;
  bool use_gnu_hash_ = true;
  bool use_sysv_hash_ = false;
  bool use_relro_ = false;
  size_t truncate_dyn_ = 0;
  uint64_t pltrel_override_ = DT_RELA;
  uint64_t syment_override_ = sizeof(Elf64_Sym);
  uint64_t load_vaddr_override_ = 0;
  bool has_load_vaddr_override_ = false;
  bool omit_symtab_ = false;
  bool omit_strtab_ = false;
  bool omit_strsz_ = false;
};

}  // namespace yukiplt::test

#endif  // YUKIPLT_TEST_ELF_BUILDER_HPP_
