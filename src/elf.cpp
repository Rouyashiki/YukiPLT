// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "elf.hpp"

#include <cstring>

#include "common.hpp"

namespace yukiplt::detail {
// Helpers

/// Convert ELF p_flags to POSIX PROT_* flags.
static int pf_to_prot(uint32_t pf) {
  int prot = 0;
  if (pf & PF_R) prot |= 0x1;  // PROT_READ
  if (pf & PF_W) prot |= 0x2;  // PROT_WRITE
  if (pf & PF_X) prot |= 0x4;  // PROT_EXEC
  return prot;
}
// InspectedImage query methods

bool InspectedImage::addr_in_load(uintptr_t addr, size_t size) const noexcept {
  if (size == 0) return false;
  uintptr_t end;
  if (!safe_add(addr, static_cast<uintptr_t>(size), end)) return false;
  for (const auto& seg : load_segments) {
    if (addr >= seg.vaddr_begin && end <= seg.vaddr_end) return true;
  }
  return false;
}

bool InspectedImage::addr_in_relro(uintptr_t addr) const noexcept {
  return relro_begin != relro_end && addr >= relro_begin && addr < relro_end;
}

int InspectedImage::protection_for(uintptr_t addr) const noexcept {
  int prot = 0;
  for (const auto& seg : load_segments) {
    if (addr >= seg.vaddr_begin && addr < seg.vaddr_end) {
      prot = pf_to_prot(seg.flags);
      break;
    }
  }
  // If the address is within RELRO, the loader has removed write permission.
  if (addr_in_relro(addr)) {
    prot &= ~0x2;  // Clear PROT_WRITE
  }
  return prot;
}
// Dynamic section parsing

/// Collected raw values from the dynamic section (before address resolution).
struct DynamicInfo {
  uint64_t dt_symtab = 0;
  uint64_t dt_strtab = 0;
  uint64_t dt_strsz = 0;
  uint64_t dt_syment = 0;
  uint64_t dt_gnu_hash = 0;
  uint64_t dt_hash = 0;  // SysV hash
  uint64_t dt_jmprel = 0;
  uint64_t dt_pltrelsz = 0;
  uint64_t dt_pltrel = 0;
  uint64_t dt_relaent = 0;

  bool has_symtab = false;
  bool has_strtab = false;
  bool has_strsz = false;
  bool has_syment = false;
  bool has_gnu_hash = false;
  bool has_hash = false;
  bool has_jmprel = false;
  bool has_pltrelsz = false;
  bool has_pltrel = false;
  bool has_relaent = false;
};

/// Parse the dynamic section, extracting the tags we care about.
/// The dynamic section is at [dyn_addr, dyn_addr + dyn_size) in memory.
static Expected<DynamicInfo, Error> parse_dynamic(uintptr_t dyn_addr, size_t dyn_size) {
  if (dyn_size < sizeof(Elf64_Dyn)) return Error::Make(ErrorCode::kCorruptedElf);

  const size_t max_entries = dyn_size / sizeof(Elf64_Dyn);
  const auto* dyn = reinterpret_cast<const Elf64_Dyn*>(dyn_addr);

  DynamicInfo info;
  bool found_null = false;

  for (size_t i = 0; i < max_entries; ++i) {
    const auto& d = dyn[i];
    if (d.d_tag == DT_NULL) {
      found_null = true;
      break;
    }

    switch (d.d_tag) {
      case DT_SYMTAB:
        info.dt_symtab = d.d_un.d_ptr;
        info.has_symtab = true;
        break;
      case DT_STRTAB:
        info.dt_strtab = d.d_un.d_ptr;
        info.has_strtab = true;
        break;
      case DT_STRSZ:
        info.dt_strsz = d.d_un.d_val;
        info.has_strsz = true;
        break;
      case DT_SYMENT:
        info.dt_syment = d.d_un.d_val;
        info.has_syment = true;
        break;
      case DT_GNU_HASH:
        info.dt_gnu_hash = d.d_un.d_ptr;
        info.has_gnu_hash = true;
        break;
      case DT_HASH:
        info.dt_hash = d.d_un.d_ptr;
        info.has_hash = true;
        break;
      case DT_JMPREL:
        info.dt_jmprel = d.d_un.d_ptr;
        info.has_jmprel = true;
        break;
      case DT_PLTRELSZ:
        info.dt_pltrelsz = d.d_un.d_val;
        info.has_pltrelsz = true;
        break;
      case DT_PLTREL:
        info.dt_pltrel = d.d_un.d_val;
        info.has_pltrel = true;
        break;
      case DT_RELAENT:
        info.dt_relaent = d.d_un.d_val;
        info.has_relaent = true;
        break;
      default:
        break;
    }
  }

  // We don't require DT_NULL if the table exactly fills the segment,
  // but warn about it through diagnostics in the future.
  (void)found_null;

  return info;
}
// Main inspection

Expected<InspectedImage, Error> inspect(uintptr_t load_bias, const Elf64_Phdr* phdr_table,
                                        size_t phdr_count) {
  if (phdr_table == nullptr) return Error::Make(ErrorCode::kNullPointer);
  if (phdr_count == 0) return Error::Make(ErrorCode::kInvalidArgument);

  InspectedImage image;
  image.load_bias = load_bias;

  // Collect PT_LOAD, PT_DYNAMIC, PT_GNU_RELRO.
  const Elf64_Phdr* dyn_phdr = nullptr;
  const Elf64_Phdr* relro_phdr = nullptr;

  for (size_t i = 0; i < phdr_count; ++i) {
    const auto& ph = phdr_table[i];

    switch (ph.p_type) {
      case PT_LOAD: {
        // Validate vaddr + memsz doesn't overflow.
        uint64_t vaddr_end64;
        if (!safe_add64(ph.p_vaddr, ph.p_memsz, vaddr_end64))
          return Error::Make(ErrorCode::kIntegerOverflow);

        // Validate vaddr + load_bias doesn't overflow.
        uintptr_t runtime_begin;
        if (!safe_add(load_bias, static_cast<uintptr_t>(ph.p_vaddr), runtime_begin))
          return Error::Make(ErrorCode::kIntegerOverflow);

        uintptr_t runtime_end;
        if (!safe_add(runtime_begin, static_cast<uintptr_t>(ph.p_memsz), runtime_end))
          return Error::Make(ErrorCode::kIntegerOverflow);

        // Reject zero-size segments.
        if (runtime_begin == runtime_end) continue;

        image.load_segments.push_back({runtime_begin, runtime_end, ph.p_flags});
        break;
      }
      case PT_DYNAMIC:
        if (dyn_phdr != nullptr)
          return Error::Make(ErrorCode::kCorruptedElf);  // Duplicate PT_DYNAMIC
        dyn_phdr = &ph;
        break;
      case PT_GNU_RELRO:
        if (relro_phdr != nullptr) return Error::Make(ErrorCode::kCorruptedElf);  // Duplicate
        relro_phdr = &ph;
        break;
      default:
        break;
    }
  }

  if (dyn_phdr == nullptr) return Error::Make(ErrorCode::kInvalidImage);  // No PT_DYNAMIC

  // Validate and compute PT_DYNAMIC runtime range.
  uintptr_t dyn_begin;
  if (!safe_add(load_bias, static_cast<uintptr_t>(dyn_phdr->p_vaddr), dyn_begin))
    return Error::Make(ErrorCode::kIntegerOverflow);

  uintptr_t dyn_end;
  if (!safe_add(dyn_begin, static_cast<uintptr_t>(dyn_phdr->p_memsz), dyn_end))
    return Error::Make(ErrorCode::kIntegerOverflow);

  size_t dyn_size = static_cast<size_t>(dyn_end - dyn_begin);

  // PT_DYNAMIC must be within a PT_LOAD segment.
  if (!image.addr_in_load(dyn_begin, dyn_size)) return Error::Make(ErrorCode::kCorruptedElf);

  // Compute RELRO range.
  if (relro_phdr != nullptr) {
    if (!safe_add(load_bias, static_cast<uintptr_t>(relro_phdr->p_vaddr), image.relro_begin))
      return Error::Make(ErrorCode::kIntegerOverflow);
    if (!safe_add(image.relro_begin, static_cast<uintptr_t>(relro_phdr->p_memsz), image.relro_end))
      return Error::Make(ErrorCode::kIntegerOverflow);
  }

  // Parse dynamic section.
  auto dyn_result = parse_dynamic(dyn_begin, dyn_size);
  if (!dyn_result) return dyn_result.error();
  const DynamicInfo& dinfo = dyn_result.value();

  // We need at minimum a symbol table and string table.
  if (!dinfo.has_symtab) return Error::Make(ErrorCode::kCorruptedElf);
  if (!dinfo.has_strtab) return Error::Make(ErrorCode::kCorruptedElf);
  if (!dinfo.has_strsz) return Error::Make(ErrorCode::kCorruptedElf);

  // Validate DT_SYMENT == sizeof(Elf64_Sym).
  if (dinfo.has_syment && dinfo.dt_syment != sizeof(Elf64_Sym))
    return Error::Make(ErrorCode::kUnsupportedFormat);

  // bionic keeps relative d_ptr; glibc may adjust it. Treat DT_SYMTAB as
  // adjusted when its raw address already lies within a runtime LOAD.
  {
    uintptr_t raw_symtab = static_cast<uintptr_t>(dinfo.dt_symtab);
    image.dptr_adjusted = image.addr_in_load(raw_symtab, sizeof(Elf64_Sym));
  }

  // Helper: resolve a d_ptr to a runtime address.
  auto resolve_ptr = [&](uint64_t d_ptr, uintptr_t& out) -> bool {
    if (image.dptr_adjusted) {
      out = static_cast<uintptr_t>(d_ptr);
      return true;
    }
    return safe_add(load_bias, static_cast<uintptr_t>(d_ptr), out);
  };

  // Resolve and validate address-type tags.

  // SYMTAB
  if (!resolve_ptr(dinfo.dt_symtab, image.symtab)) return Error::Make(ErrorCode::kIntegerOverflow);
  if (!image.addr_in_load(image.symtab, sizeof(Elf64_Sym)))
    return Error::Make(ErrorCode::kCorruptedElf);

  // STRTAB + STRSZ
  if (!resolve_ptr(dinfo.dt_strtab, image.strtab)) return Error::Make(ErrorCode::kIntegerOverflow);
  image.strsz = static_cast<size_t>(dinfo.dt_strsz);
  if (image.strsz == 0) return Error::Make(ErrorCode::kCorruptedElf);
  if (!image.addr_in_load(image.strtab, image.strsz)) return Error::Make(ErrorCode::kCorruptedElf);

  // GNU Hash (optional)
  if (dinfo.has_gnu_hash) {
    if (!resolve_ptr(dinfo.dt_gnu_hash, image.gnu_hash))
      return Error::Make(ErrorCode::kIntegerOverflow);
    // We validate the hash table structure later in elf.cpp; here just
    // check the base address is within a load segment (at least 16 bytes
    // for the header).
    if (!image.addr_in_load(image.gnu_hash, 16)) return Error::Make(ErrorCode::kCorruptedElf);
  }

  // SysV Hash (optional)
  if (dinfo.has_hash) {
    if (!resolve_ptr(dinfo.dt_hash, image.sysv_hash))
      return Error::Make(ErrorCode::kIntegerOverflow);
    // SysV hash header is two uint32_t: nbucket, nchain.
    if (!image.addr_in_load(image.sysv_hash, 8)) return Error::Make(ErrorCode::kCorruptedElf);
  }

  // At least one hash table is required for symbol lookup.
  if (image.gnu_hash == 0 && image.sysv_hash == 0) return Error::Make(ErrorCode::kNoHashTable);

  // JMPREL + PLTRELSZ (optional — an image may have no PLT relocations)
  if (dinfo.has_jmprel && dinfo.has_pltrelsz) {
    // Validate DT_PLTREL == DT_RELA (AArch64 requires RELA).
    if (dinfo.has_pltrel && dinfo.dt_pltrel != DT_RELA)
      return Error::Make(ErrorCode::kUnsupportedFormat);

    // Validate DT_RELAENT if present.
    if (dinfo.has_relaent && dinfo.dt_relaent != sizeof(Elf64_Rela))
      return Error::Make(ErrorCode::kUnsupportedFormat);

    // Validate PLTRELSZ is a multiple of sizeof(Elf64_Rela).
    if (dinfo.dt_pltrelsz == 0 || dinfo.dt_pltrelsz % sizeof(Elf64_Rela) != 0)
      return Error::Make(ErrorCode::kCorruptedElf);

    if (!resolve_ptr(dinfo.dt_jmprel, image.jmprel))
      return Error::Make(ErrorCode::kIntegerOverflow);

    image.jmprel_count = static_cast<size_t>(dinfo.dt_pltrelsz / sizeof(Elf64_Rela));

    // Validate the entire JMPREL table is within a PT_LOAD segment.
    if (!image.addr_in_load(image.jmprel, static_cast<size_t>(dinfo.dt_pltrelsz)))
      return Error::Make(ErrorCode::kCorruptedElf);
  }

  return image;
}

// Hash functions

uint32_t gnu_hash_value(const char* name) noexcept {
  uint32_t h = 5381;
  for (const auto* p = reinterpret_cast<const unsigned char*>(name); *p; ++p) h = (h << 5) + h + *p;
  return h;
}

uint32_t elf_hash_value(const char* name) noexcept {
  uint32_t h = 0;
  for (const auto* p = reinterpret_cast<const unsigned char*>(name); *p; ++p) {
    h = (h << 4) + *p;
    uint32_t g = h & 0xf0000000;
    if (g) h ^= g >> 24;
    h &= ~g;
  }
  return h;
}
// Helper: read a value from an address, checking bounds.

/// Read a T from a runtime address, verifying it falls within a load segment.
template <typename T>
static Expected<T, Error> read_checked(const InspectedImage& image, uintptr_t addr) {
  if (!image.addr_in_load(addr, sizeof(T))) return Error::Make(ErrorCode::kOutOfBounds);
  T val;
  std::memcpy(&val, reinterpret_cast<const void*>(addr), sizeof(T));
  return val;
}
// GNU Hash lookup

// GNU hash: four uint32_t header words, native-width bloom words, then
// uint32_t buckets and chains indexed from symoffset.

Expected<std::optional<uint32_t>, Error> gnu_hash_lookup(const InspectedImage& image,
                                                         const char* name) {
  if (image.gnu_hash == 0) return std::optional<uint32_t>(std::nullopt);

  uintptr_t base = image.gnu_hash;

  // Read header.
  auto r_nbuckets = read_checked<uint32_t>(image, base);
  auto r_symoffset = read_checked<uint32_t>(image, base + 4);
  auto r_bloom_size = read_checked<uint32_t>(image, base + 8);
  auto r_bloom_shift = read_checked<uint32_t>(image, base + 12);

  if (!r_nbuckets || !r_symoffset || !r_bloom_size || !r_bloom_shift)
    return Error::Make(ErrorCode::kCorruptedElf);

  uint32_t nbuckets = r_nbuckets.value();
  uint32_t symoffset = r_symoffset.value();
  uint32_t bloom_size = r_bloom_size.value();
  uint32_t bloom_shift = r_bloom_shift.value();

  if (nbuckets == 0 || bloom_size == 0) return Error::Make(ErrorCode::kCorruptedElf);

  // Compute layout addresses.
  uintptr_t bloom_addr = base + 16;
  uintptr_t buckets_addr = bloom_addr + static_cast<uintptr_t>(bloom_size) * 8;
  uintptr_t chains_addr = buckets_addr + static_cast<uintptr_t>(nbuckets) * 4;

  // Overflow checks.
  if (bloom_addr < base || buckets_addr < bloom_addr || chains_addr < buckets_addr)
    return Error::Make(ErrorCode::kIntegerOverflow);

  // Validate bloom array bounds.
  if (!image.addr_in_load(bloom_addr, static_cast<size_t>(bloom_size) * 8))
    return Error::Make(ErrorCode::kCorruptedElf);

  // Validate bucket array bounds.
  if (!image.addr_in_load(buckets_addr, static_cast<size_t>(nbuckets) * 4))
    return Error::Make(ErrorCode::kCorruptedElf);

  uint32_t h = gnu_hash_value(name);

  // Bloom filter check.
  {
    uint32_t word_idx = (h / 64) % bloom_size;
    auto r_bloom = read_checked<uint64_t>(image, bloom_addr + static_cast<uintptr_t>(word_idx) * 8);
    if (!r_bloom) return r_bloom.error();
    uint64_t bloom_word = r_bloom.value();

    uint64_t mask = (uint64_t(1) << (h % 64)) | (uint64_t(1) << ((h >> bloom_shift) % 64));
    if ((bloom_word & mask) != mask)
      return std::optional<uint32_t>(std::nullopt);  // Definitely not present.
  }

  // Bucket lookup.
  uint32_t bucket_idx = h % nbuckets;
  auto r_sym_idx =
      read_checked<uint32_t>(image, buckets_addr + static_cast<uintptr_t>(bucket_idx) * 4);
  if (!r_sym_idx) return r_sym_idx.error();
  uint32_t sym_idx = r_sym_idx.value();

  if (sym_idx == 0) return std::optional<uint32_t>(std::nullopt);  // Empty bucket.

  if (sym_idx < symoffset) return Error::Make(ErrorCode::kCorruptedElf);

  // Chain walk.
  uint32_t h1 = h & ~uint32_t(1);  // Clear lowest bit for comparison.

  for (;;) {
    uint32_t chain_idx = sym_idx - symoffset;
    auto r_chain =
        read_checked<uint32_t>(image, chains_addr + static_cast<uintptr_t>(chain_idx) * 4);
    if (!r_chain) return r_chain.error();
    uint32_t chain_val = r_chain.value();

    if ((chain_val & ~uint32_t(1)) == h1) {
      // Hash matches — compare the actual symbol name.
      uintptr_t sym_addr = image.symtab + static_cast<uintptr_t>(sym_idx) * sizeof(Elf64_Sym);
      auto r_sym = read_checked<Elf64_Sym>(image, sym_addr);
      if (!r_sym) return r_sym.error();
      const Elf64_Sym& sym = r_sym.value();

      // Validate name offset.
      if (sym.st_name >= image.strsz) return Error::Make(ErrorCode::kCorruptedElf);

      const char* sym_name = reinterpret_cast<const char*>(image.strtab + sym.st_name);

      // Verify the string is NUL-terminated within strsz.
      size_t max_len = image.strsz - sym.st_name;
      if (strnlen(sym_name, max_len) == max_len) return Error::Make(ErrorCode::kCorruptedElf);

      if (std::strcmp(sym_name, name) == 0) return std::optional<uint32_t>(sym_idx);
    }

    // End of chain?
    if (chain_val & 1) break;

    ++sym_idx;
  }

  return std::optional<uint32_t>(std::nullopt);
}
// SysV Hash lookup

// SysV hash: nbucket, nchain, followed by uint32_t bucket and chain arrays.

Expected<std::optional<uint32_t>, Error> sysv_hash_lookup(const InspectedImage& image,
                                                          const char* name) {
  if (image.sysv_hash == 0) return std::optional<uint32_t>(std::nullopt);

  uintptr_t base = image.sysv_hash;

  auto r_nbucket = read_checked<uint32_t>(image, base);
  auto r_nchain = read_checked<uint32_t>(image, base + 4);
  if (!r_nbucket || !r_nchain) return Error::Make(ErrorCode::kCorruptedElf);

  uint32_t nbucket = r_nbucket.value();
  uint32_t nchain = r_nchain.value();

  if (nbucket == 0) return Error::Make(ErrorCode::kCorruptedElf);

  uintptr_t bucket_addr = base + 8;
  uintptr_t chain_addr = bucket_addr + static_cast<uintptr_t>(nbucket) * 4;

  // Overflow checks.
  if (bucket_addr < base || chain_addr < bucket_addr)
    return Error::Make(ErrorCode::kIntegerOverflow);

  // Validate arrays.
  if (!image.addr_in_load(bucket_addr, static_cast<size_t>(nbucket) * 4))
    return Error::Make(ErrorCode::kCorruptedElf);
  if (!image.addr_in_load(chain_addr, static_cast<size_t>(nchain) * 4))
    return Error::Make(ErrorCode::kCorruptedElf);

  uint32_t h = elf_hash_value(name);
  uint32_t bucket_idx = h % nbucket;

  auto r_sym_idx =
      read_checked<uint32_t>(image, bucket_addr + static_cast<uintptr_t>(bucket_idx) * 4);
  if (!r_sym_idx) return r_sym_idx.error();
  uint32_t sym_idx = r_sym_idx.value();

  // Walk the chain.
  while (sym_idx != 0) {
    if (sym_idx >= nchain) return Error::Make(ErrorCode::kCorruptedElf);

    // Read symbol.
    uintptr_t sym_addr = image.symtab + static_cast<uintptr_t>(sym_idx) * sizeof(Elf64_Sym);
    auto r_sym = read_checked<Elf64_Sym>(image, sym_addr);
    if (!r_sym) return r_sym.error();
    const Elf64_Sym& sym = r_sym.value();

    // Validate and compare name.
    if (sym.st_name >= image.strsz) return Error::Make(ErrorCode::kCorruptedElf);

    const char* sym_name = reinterpret_cast<const char*>(image.strtab + sym.st_name);
    size_t max_len = image.strsz - sym.st_name;
    if (strnlen(sym_name, max_len) == max_len) return Error::Make(ErrorCode::kCorruptedElf);

    if (std::strcmp(sym_name, name) == 0) return std::optional<uint32_t>(sym_idx);

    // Next in chain.
    auto r_next = read_checked<uint32_t>(image, chain_addr + static_cast<uintptr_t>(sym_idx) * 4);
    if (!r_next) return r_next.error();
    sym_idx = r_next.value();
  }

  return std::optional<uint32_t>(std::nullopt);
}
// Unified lookup

Expected<uint32_t, Error> lookup_symbol(const InspectedImage& image, const char* name) {
  if (name == nullptr) return Error::Make(ErrorCode::kNullPointer);

  // Try GNU hash first.
  if (image.gnu_hash != 0) {
    auto result = gnu_hash_lookup(image, name);
    if (!result) return result.error();
    if (result.value().has_value()) return result.value().value();
  }

  // Fall back to SysV hash.
  if (image.sysv_hash != 0) {
    auto result = sysv_hash_lookup(image, name);
    if (!result) return result.error();
    if (result.value().has_value()) return result.value().value();
  }

  // If neither hash table exists, report it.
  if (image.gnu_hash == 0 && image.sysv_hash == 0) return Error::Make(ErrorCode::kNoHashTable);

  return Error::Make(ErrorCode::kSymbolNotFound);
}
// Relocation resolver

/// Compare a symbol name by reading it from the symbol table.
/// Returns true if the symbol at sym_index has the given name.
static Expected<bool, Error> sym_name_matches(const InspectedImage& image, uint32_t sym_index,
                                              const char* name) {
  uintptr_t sym_addr = image.symtab + static_cast<uintptr_t>(sym_index) * sizeof(Elf64_Sym);
  auto r_sym = read_checked<Elf64_Sym>(image, sym_addr);
  if (!r_sym) return r_sym.error();
  const Elf64_Sym& sym = r_sym.value();

  if (sym.st_name >= image.strsz) return Error::Make(ErrorCode::kCorruptedElf);

  const char* sym_name = reinterpret_cast<const char*>(image.strtab + sym.st_name);
  size_t max_len = image.strsz - sym.st_name;
  if (strnlen(sym_name, max_len) == max_len) return Error::Make(ErrorCode::kCorruptedElf);

  return std::strcmp(sym_name, name) == 0;
}

Expected<SmallVec<ResolvedSlot>, Error> resolve_slots(const InspectedImage& image,
                                                      const char* symbol_name) {
  if (symbol_name == nullptr) return Error::Make(ErrorCode::kNullPointer);

  if (image.jmprel == 0 || image.jmprel_count == 0) return Error::Make(ErrorCode::kSymbolNotFound);

  // Scan the JMPREL table and match by symbol name.
  //
  // We do NOT use hash table lookup here because GNU Hash does not index
  // undefined symbols — and PLT relocations reference undefined (imported)
  // symbols.  Instead, we iterate all JMPREL entries, read each entry's
  // symbol index, look up its name from the symbol table, and compare.
  SmallVec<ResolvedSlot> slots;

  for (size_t i = 0; i < image.jmprel_count; ++i) {
    uintptr_t rela_addr = image.jmprel + i * sizeof(Elf64_Rela);
    auto r_rela = read_checked<Elf64_Rela>(image, rela_addr);
    if (!r_rela) return r_rela.error();
    const Elf64_Rela& rela = r_rela.value();

    uint32_t rtype = static_cast<uint32_t>(ELF64_R_TYPE(rela.r_info));
    uint32_t rsym = static_cast<uint32_t>(ELF64_R_SYM(rela.r_info));

    // Only process R_AARCH64_JUMP_SLOT.
    if (rtype != R_AARCH64_JUMP_SLOT) continue;

    // Skip STN_UNDEF (symbol index 0).
    if (rsym == 0) continue;

    // Compare symbol name.
    auto name_match = sym_name_matches(image, rsym, symbol_name);
    if (!name_match) return name_match.error();
    if (!name_match.value()) continue;

    // Compute GOT slot runtime address.
    // r_offset is always the link-time virtual address of the GOT slot.
    // Unlike d_ptr in the dynamic section, r_offset is NOT adjusted by
    // the dynamic linker on glibc.  Runtime address = r_offset + load_bias.
    uintptr_t slot_addr;
    if (!safe_add(image.load_bias, static_cast<uintptr_t>(rela.r_offset), slot_addr))
      return Error::Make(ErrorCode::kIntegerOverflow);

    // Validate 8-byte alignment.
    if (slot_addr % 8 != 0) return Error::Make(ErrorCode::kCorruptedElf);

    // Validate the slot address is within a PT_LOAD segment.
    if (!image.addr_in_load(slot_addr, 8)) return Error::Make(ErrorCode::kCorruptedElf);

    slots.push_back({slot_addr, rsym});
  }

  if (slots.empty()) return Error::Make(ErrorCode::kSymbolNotFound);

  return slots;
}

}  // namespace yukiplt::detail
