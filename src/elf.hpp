// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKIPLT_ELF_HPP_
#define YUKIPLT_ELF_HPP_

#include <cstddef>
#include <cstdint>
#include <optional>

#include "common.hpp"
#include "yukiplt.hpp"

namespace yukiplt::detail {

/// A validated PT_LOAD segment with runtime addresses.
struct LoadSegment {
  uintptr_t vaddr_begin;  ///< Runtime start address (vaddr + load_bias).
  uintptr_t vaddr_end;    ///< Runtime end address (exclusive).
  uint32_t flags;         ///< Segment flags (PF_R | PF_W | PF_X).
};

/// Result of inspecting an ELF image.  All addresses are runtime addresses.
/// All ranges have been validated: no overflow, within PT_LOAD bounds.
struct InspectedImage {
  uintptr_t load_bias = 0;

  /// PT_LOAD segments, sorted by vaddr_begin.
  SmallVec<LoadSegment> load_segments;

  /// PT_GNU_RELRO range (zero if absent).
  uintptr_t relro_begin = 0;
  uintptr_t relro_end = 0;

  /// Symbol table (DT_SYMTAB runtime address).
  uintptr_t symtab = 0;

  /// String table (DT_STRTAB runtime address and DT_STRSZ).
  uintptr_t strtab = 0;
  size_t strsz = 0;

  /// Hash tables (zero if absent; at least one must be non-zero).
  uintptr_t gnu_hash = 0;
  uintptr_t sysv_hash = 0;

  /// PLT relocation table (DT_JMPREL runtime address and entry count).
  uintptr_t jmprel = 0;
  size_t jmprel_count = 0;

  /// Validated dynamic array for optional metadata readers.
  uintptr_t dynamic = 0;
  size_t dynamic_size = 0;

  /// Whether d_ptr values in the dynamic section were already adjusted
  /// to runtime addresses by the dynamic linker (glibc behavior).
  /// When false (bionic), runtime address = d_ptr + load_bias.
  bool dptr_adjusted = false;

  // --- Query methods ---

  /// Returns true if [addr, addr + size) falls entirely within a PT_LOAD segment.
  [[nodiscard]] bool addr_in_load(uintptr_t addr, size_t size) const noexcept;

  /// Returns true if [addr, addr + size) falls entirely within a PT_LOAD
  /// segment whose p_flags include PF_W.  A relocation target (GOT slot) must
  /// satisfy this: a slot inside a non-writable segment means a malformed or
  /// hostile r_offset, and patching it would write into read-only data.
  [[nodiscard]] bool addr_in_writable_load(uintptr_t addr, size_t size) const noexcept;

  /// Returns true if addr falls within the RELRO range.
  [[nodiscard]] bool addr_in_relro(uintptr_t addr) const noexcept;

  /// Deduce the POSIX protection flags (PROT_*) for an address from
  /// PT_LOAD flags and RELRO.  Returns 0 if the address is not in any segment.
  [[nodiscard]] int protection_for(uintptr_t addr) const noexcept;
};

// Inspect bounded native ELF metadata. The caller keeps the mapping and
// program-header table valid throughout the call.
Expected<InspectedImage, Error> inspect(uintptr_t load_bias, const Elf64_Phdr* phdr_table,
                                        size_t phdr_count);

/// Compute the GNU hash of a symbol name (dl_new_hash).
uint32_t gnu_hash_value(const char* name) noexcept;

/// Compute the SysV ELF hash of a symbol name.
uint32_t elf_hash_value(const char* name) noexcept;

/// Look up a symbol by name using the GNU hash table.
///
/// Returns the symbol index in the symbol table, or std::nullopt if not found.
/// Returns an Error if the hash table structure is corrupted.
Expected<std::optional<uint32_t>, Error> gnu_hash_lookup(const InspectedImage& image,
                                                         const char* name);

/// Look up a symbol by name using the SysV hash table.
Expected<std::optional<uint32_t>, Error> sysv_hash_lookup(const InspectedImage& image,
                                                          const char* name);

/// Unified symbol lookup: tries GNU hash first, falls back to SysV hash.
///
/// Returns kNoHashTable if neither hash table is present.
/// Returns kSymbolNotFound if the symbol is not in any hash table.
Expected<uint32_t, Error> lookup_symbol(const InspectedImage& image, const char* name);

/// Resolved GOT slot information.
struct ResolvedSlot {
  uintptr_t address;   ///< Runtime address of the GOT slot.
  uint32_t sym_index;  ///< Symbol index that this slot references.
};

// Validate all JMPREL entries and return matching records in table order.
// Duplicate slots are corrupt; no matches yields SymbolNotFound. Allocation
// exceptions are translated by the public boundary.
Expected<SmallVec<ResolvedSlot>, Error> resolve_slots(const InspectedImage& image,
                                                      const char* symbol_name);

// Resolve one slot: no match is SymbolNotFound, duplicate records are
// CorruptedElf, and multiple distinct slots are AmbiguousSymbol.
Expected<ResolvedSlot, Error> resolve_unique_slot(const InspectedImage& image,
                                                  const char* symbol_name);

}  // namespace yukiplt::detail

#endif  // YUKIPLT_ELF_HPP_
