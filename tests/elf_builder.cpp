// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "elf_builder.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>

namespace yukiplt::test {
// GNU Hash helpers

/// Compute GNU hash of a symbol name (dl_new_hash).
static uint32_t gnu_hash(const char* name) {
  uint32_t h = 5381;
  for (const unsigned char* p = reinterpret_cast<const unsigned char*>(name); *p; ++p)
    h = (h << 5) + h + *p;
  return h;
}

/// Compute SysV ELF hash.
[[maybe_unused]]
static uint32_t elf_hash(const char* name) {
  uint32_t h = 0;
  for (const unsigned char* p = reinterpret_cast<const unsigned char*>(name); *p; ++p) {
    h = (h << 4) + *p;
    uint32_t g = h & 0xf0000000;
    if (g) h ^= g >> 24;
    h &= ~g;
  }
  return h;
}
// Layout helper

/// Simple bump allocator for laying out structures in a flat buffer.
struct LayoutBuilder {
  std::vector<uint8_t> buf;
  size_t pos = 0;

  size_t align(size_t alignment) {
    size_t aligned = (pos + alignment - 1) & ~(alignment - 1);
    if (aligned > buf.size()) buf.resize(aligned, 0);
    pos = aligned;
    return pos;
  }

  size_t alloc(size_t size, size_t alignment = 1) {
    align(alignment);
    size_t offset = pos;
    pos += size;
    if (pos > buf.size()) buf.resize(pos, 0);
    return offset;
  }

  template <typename T>
  void write_at(size_t offset, const T& val) {
    assert(offset + sizeof(T) <= buf.size());
    std::memcpy(buf.data() + offset, &val, sizeof(T));
  }

  template <typename T>
  size_t append(const T& val, size_t alignment = alignof(T)) {
    size_t off = alloc(sizeof(T), alignment);
    write_at(off, val);
    return off;
  }
};
// ElfBuilder::BuiltImage

uintptr_t ElfBuilder::BuiltImage::got_slot_addr(size_t i) const {
  return reinterpret_cast<uintptr_t>(buffer.data() + got_offset + i * 8);
}

uintptr_t ElfBuilder::BuiltImage::rela_slot_addr(size_t i) const {
  return reinterpret_cast<uintptr_t>(buffer.data() + rela_got_offset + i * 8);
}

uintptr_t ElfBuilder::BuiltImage::android_slot_addr(size_t i) const {
  return reinterpret_cast<uintptr_t>(buffer.data() + android_got_offset + i * 8);
}
// ElfBuilder::build

ElfBuilder::BuiltImage ElfBuilder::build() const {
  LayoutBuilder lb;

  // Reserve generous space upfront to avoid excessive reallocs.
  lb.buf.resize(4096, 0);
  // 1. Determine the number of phdrs.
  size_t num_phdrs = 1;            // PT_LOAD
  num_phdrs += 1;                  // PT_DYNAMIC
  if (use_relro_) num_phdrs += 1;  // PT_GNU_RELRO
  // 2. Program headers (at the start of the buffer).
  size_t phdr_offset = lb.alloc(num_phdrs * sizeof(Elf64_Phdr), 8);
  // 3. String table (\0 + symbol names).
  size_t strtab_offset = lb.align(1);

  // First byte is always \0 (STN_UNDEF name).
  lb.alloc(1);

  // Map symbol index → name offset in strtab.
  // Find max sym index.
  uint32_t max_sym_index = 0;
  for (const auto& s : symbols_)
    if (s.sym_index > max_sym_index) max_sym_index = s.sym_index;

  std::vector<uint32_t> name_offsets(max_sym_index + 1, 0);
  for (const auto& s : symbols_) {
    name_offsets[s.sym_index] = static_cast<uint32_t>(lb.pos - strtab_offset);
    size_t name_off = lb.alloc(s.name.size() + 1);
    std::memcpy(lb.buf.data() + name_off, s.name.c_str(), s.name.size() + 1);
  }

  size_t strtab_size = lb.pos - strtab_offset;
  // 4. Symbol table (index 0 = STN_UNDEF, then up to max_sym_index).
  size_t symtab_offset = lb.align(8);
  size_t sym_count = max_sym_index + 1;
  lb.alloc(sym_count * sizeof(Elf64_Sym), 8);

  // Fill in symbols.
  for (size_t i = 0; i < sym_count; ++i) {
    Elf64_Sym sym{};
    sym.st_name = name_offsets[i];
    auto info_it = symbol_info_.find(static_cast<uint32_t>(i));
    sym.st_info =
        info_it != symbol_info_.end() ? info_it->second : ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    auto undef_it = symbol_undef_.find(static_cast<uint32_t>(i));
    const bool undefined = (i == 0) || (undef_it != symbol_undef_.end() && undef_it->second);
    sym.st_shndx = undefined ? SHN_UNDEF : 1;
    sym.st_value = 0;
    sym.st_size = 0;
    lb.write_at(symtab_offset + i * sizeof(Elf64_Sym), sym);
  }
  // 5. GNU Hash table (optional).
  size_t gnu_hash_offset = 0;
  if (use_gnu_hash_) {
    gnu_hash_offset = lb.align(8);

    // Simple layout: 1 bucket, symoffset = 1 (skip STN_UNDEF),
    // 1 bloom word, bloom_shift = 6.
    //
    // GNU Hash header: { nbuckets, symoffset, bloom_size, bloom_shift }
    // Followed by: bloom[bloom_size], buckets[nbuckets], chains[]
    //
    // The chain has one entry per symbol from symoffset to max_sym_index.

    uint32_t nbuckets = 1;
    uint32_t symoffset = 1;  // First hashed symbol index
    uint32_t bloom_size = 1;
    uint32_t bloom_shift = 6;

    // Header
    lb.append<uint32_t>(nbuckets, 4);
    lb.append<uint32_t>(symoffset, 4);
    lb.append<uint32_t>(bloom_size, 4);
    lb.append<uint32_t>(bloom_shift, 4);

    // Bloom filter (one 64-bit word, set all bits for simplicity —
    // this makes every symbol pass the bloom check).
    size_t bloom_offset = lb.append<uint64_t>(~uint64_t(0), 8);
    (void)bloom_offset;

    // Buckets: for each hashed symbol, bucket[hash % nbuckets] = sym_index.
    // With 1 bucket, everything chains from bucket 0.
    // bucket[0] = symoffset (first symbol).
    size_t bucket_offset = lb.alloc(nbuckets * sizeof(uint32_t), 4);
    if (sym_count > 1) {
      uint32_t first_sym = symoffset;
      lb.write_at(bucket_offset, first_sym);
    } else {
      // No symbols to hash.
      uint32_t zero = 0;
      lb.write_at(bucket_offset, zero);
    }

    // Chains: one uint32_t per symbol [symoffset .. max_sym_index].
    // chain[i - symoffset] = (gnu_hash(name) & ~1) | is_last
    size_t chain_count = (sym_count > symoffset) ? (sym_count - symoffset) : 0;
    size_t chain_offset = lb.alloc(chain_count * sizeof(uint32_t), 4);

    for (size_t ci = 0; ci < chain_count; ++ci) {
      uint32_t sym_idx = static_cast<uint32_t>(symoffset + ci);
      uint32_t h = 0;
      // Find the symbol name for this index.
      for (const auto& s : symbols_) {
        if (s.sym_index == sym_idx) {
          h = gnu_hash(s.name.c_str());
          break;
        }
      }
      uint32_t chain_val = (h & ~uint32_t(1));
      if (ci == chain_count - 1) chain_val |= 1;  // Last entry in chain
      lb.write_at(chain_offset + ci * sizeof(uint32_t), chain_val);
    }
  }
  // 6. SysV Hash table (optional).
  size_t sysv_hash_offset = 0;
  if (use_sysv_hash_) {
    sysv_hash_offset = lb.align(4);

    uint32_t nbucket = 1;
    uint32_t nchain = static_cast<uint32_t>(sym_count);

    lb.append<uint32_t>(nbucket, 4);
    lb.append<uint32_t>(nchain, 4);

    // buckets[nbucket]
    size_t buckets_off = lb.alloc(nbucket * sizeof(uint32_t), 4);
    // chains[nchain]
    size_t chains_off = lb.alloc(nchain * sizeof(uint32_t), 4);

    // Build single-bucket chain.
    // bucket[0] = first symbol with hash % 1 == 0 (all of them).
    // We chain all symbols through the chain array.
    // chain[i] = next symbol in the chain, or STN_UNDEF (0) for end.

    // Find which symbols exist and sort by index.
    std::vector<uint32_t> sym_indices;
    for (const auto& s : symbols_) sym_indices.push_back(s.sym_index);
    std::sort(sym_indices.begin(), sym_indices.end());

    if (!sym_indices.empty()) {
      uint32_t first = sym_indices[0];
      lb.write_at(buckets_off, first);

      // Chain: each symbol points to the next, last points to 0.
      for (size_t i = 0; i < sym_indices.size(); ++i) {
        uint32_t idx = sym_indices[i];
        uint32_t next = (i + 1 < sym_indices.size()) ? sym_indices[i + 1] : 0;
        lb.write_at(chains_off + idx * sizeof(uint32_t), next);
      }
    } else {
      uint32_t zero = 0;
      lb.write_at(buckets_off, zero);
    }
  }
  // 7. JMPREL table (PLT relocations) + GOT slots.
  size_t owned_slots = jmpslots_.size() + custom_relas_.size();
  size_t total_relas = owned_slots + aliased_slots_.size();
  size_t jmprel_offset = 0;
  size_t got_offset = 0;

  if (total_relas > 0) {
    // GOT slots: 8 bytes each, aligned to 8.  Aliased records reuse an
    // existing slot, so only owned records get their own slot.
    got_offset = lb.align(8);
    lb.alloc(owned_slots * 8, 8);

    // JMPREL table.
    jmprel_offset = lb.align(8);

    size_t slot_idx = 0;

    for (const auto& js : jmpslots_) {
      Elf64_Rela rela{};
      // r_offset is the vaddr of the GOT slot.
      // Since p_vaddr = 0 and load_bias = buffer base,
      // we use the offset within the buffer.
      rela.r_offset = got_offset + slot_idx * 8;
      rela.r_info = ELF64_R_INFO(js.sym_index, R_AARCH64_JUMP_SLOT);
      rela.r_addend = js.addend;
      lb.append(rela, 8);
      ++slot_idx;
    }

    for (const auto& cr : custom_relas_) {
      Elf64_Rela rela{};
      rela.r_offset = got_offset + slot_idx * 8;
      rela.r_info = ELF64_R_INFO(cr.sym_index, cr.rela_type);
      rela.r_addend = cr.addend;
      lb.append(rela, 8);
      ++slot_idx;
    }

    for (const auto& as : aliased_slots_) {
      Elf64_Rela rela{};
      // Reuse the GOT slot of the target jump slot: a duplicate record.
      rela.r_offset = got_offset + as.target_jmpslot_index * 8;
      rela.r_info = ELF64_R_INFO(as.sym_index, R_AARCH64_JUMP_SLOT);
      rela.r_addend = 0;
      lb.append(rela, 8);
    }
  }

  size_t jmprel_size = total_relas * sizeof(Elf64_Rela);
  // 7b. Separate DT_RELA table (.rela.dyn) + its own GOT slots.
  size_t rela_table_offset = 0;
  size_t rela_got_offset = 0;
  size_t rela_count = rela_entries_.size() + rela_aliases_.size();
  size_t rela_table_size = 0;
  if (rela_count > 0) {
    rela_got_offset = lb.align(8);
    lb.alloc(rela_count * 8, 8);
    rela_table_offset = lb.align(8);
    size_t slot_idx = 0;
    for (const auto& entry : rela_entries_) {
      Elf64_Rela rela{};
      rela.r_offset = rela_got_offset + slot_idx * 8;
      rela.r_info = ELF64_R_INFO(entry.sym_index, entry.rela_type);
      rela.r_addend = entry.addend;
      lb.append(rela, 8);
      ++slot_idx;
    }
    for (const auto& alias : rela_aliases_) {
      Elf64_Rela rela{};
      rela.r_offset = rela_got_offset + alias.target_rela_index * 8;
      rela.r_info = ELF64_R_INFO(alias.sym_index, alias.rela_type);
      rela.r_addend = 0;
      lb.append(rela, 8);
    }
    rela_table_size = rela_count * sizeof(Elf64_Rela);
  }
  // 7c. DT_ANDROID_RELA table (raw bytes) + its own GOT slots.
  size_t android_table_offset = 0;
  size_t android_got_offset = 0;
  if (has_android_rela_) {
    if (android_rela_slots_ > 0) {
      android_got_offset = lb.align(8);
      lb.alloc(android_rela_slots_ * 8, 8);
    }
    android_table_offset = lb.align(8);
    size_t bytes_off = lb.alloc(android_rela_bytes_.size(), 8);
    if (!android_rela_bytes_.empty())
      std::memcpy(lb.buf.data() + bytes_off, android_rela_bytes_.data(),
                  android_rela_bytes_.size());
  }
  // 8. Dynamic section.
  size_t dyn_offset = lb.align(8);

  auto add_dyn = [&](int64_t tag, uint64_t val) {
    Elf64_Dyn d{};
    d.d_tag = tag;
    d.d_un.d_val = val;
    lb.append(d, 8);
  };

  size_t dyn_count = 0;
  auto maybe_add_dyn = [&](int64_t tag, uint64_t val, bool condition = true) {
    if (!condition) return;
    if (truncate_dyn_ > 0 && dyn_count >= truncate_dyn_) return;
    add_dyn(tag, val);
    ++dyn_count;
  };

  // d_ptr values are offsets within the buffer (p_vaddr = 0, bionic-style).
  maybe_add_dyn(DT_SYMTAB, symtab_offset, !omit_symtab_);
  maybe_add_dyn(DT_STRTAB, strtab_offset, !omit_strtab_);
  maybe_add_dyn(DT_STRSZ, strtab_size, !omit_strsz_);
  maybe_add_dyn(DT_SYMENT, syment_override_);
  if (use_gnu_hash_) maybe_add_dyn(DT_GNU_HASH, gnu_hash_offset);
  if (use_sysv_hash_) maybe_add_dyn(DT_HASH, sysv_hash_offset);
  if (total_relas > 0) {
    maybe_add_dyn(DT_JMPREL, jmprel_offset);
    maybe_add_dyn(DT_PLTRELSZ, jmprel_size);
    maybe_add_dyn(DT_PLTREL, pltrel_override_);
    maybe_add_dyn(DT_RELAENT, has_relaent_override_ ? relaent_override_ : sizeof(Elf64_Rela));
  }
  if (rela_count > 0) {
    maybe_add_dyn(/*DT_RELA=*/7, rela_table_offset);
    maybe_add_dyn(/*DT_RELASZ=*/8, rela_table_size);
    if (total_relas == 0)
      maybe_add_dyn(DT_RELAENT, has_relaent_override_ ? relaent_override_ : sizeof(Elf64_Rela));
  }
  if (has_android_rela_) {
    maybe_add_dyn(/*DT_ANDROID_RELA=*/0x60000011, android_table_offset);
    maybe_add_dyn(/*DT_ANDROID_RELASZ=*/0x60000012, android_rela_bytes_.size());
  }
  if (emit_rel_tag_) maybe_add_dyn(/*DT_REL=*/17, 0);

  // DT_NULL terminator.
  if (!omit_dt_null_ && (truncate_dyn_ == 0 || dyn_count < truncate_dyn_)) add_dyn(DT_NULL, 0);

  size_t dyn_size = lb.pos - dyn_offset;
  // 9. Fill in program headers.
  size_t total_size = lb.pos;
  size_t phi = 0;

  // PT_LOAD: covers entire buffer.
  {
    Elf64_Phdr ph{};
    ph.p_type = PT_LOAD;
    ph.p_flags = load_flags_;
    ph.p_offset = 0;
    ph.p_vaddr = has_load_vaddr_override_ ? load_vaddr_override_ : 0;
    ph.p_paddr = ph.p_vaddr;
    ph.p_filesz = total_size;
    ph.p_memsz = total_size;
    ph.p_align = 0x1000;
    lb.write_at(phdr_offset + phi * sizeof(Elf64_Phdr), ph);
    ++phi;
  }

  // PT_DYNAMIC
  {
    Elf64_Phdr ph{};
    ph.p_type = PT_DYNAMIC;
    ph.p_flags = PF_R | PF_W;
    ph.p_offset = dyn_offset;
    ph.p_vaddr = has_load_vaddr_override_ ? (load_vaddr_override_ + dyn_offset) : dyn_offset;
    ph.p_paddr = ph.p_vaddr;
    ph.p_filesz = dyn_size;
    ph.p_memsz = dyn_size;
    ph.p_align = 8;
    lb.write_at(phdr_offset + phi * sizeof(Elf64_Phdr), ph);
    ++phi;
  }

  // PT_GNU_RELRO (optional)
  if (use_relro_) {
    Elf64_Phdr ph{};
    ph.p_type = PT_GNU_RELRO;
    ph.p_flags = PF_R;
    ph.p_offset = 0;
    ph.p_vaddr = has_load_vaddr_override_ ? load_vaddr_override_ : 0;
    ph.p_paddr = ph.p_vaddr;
    ph.p_filesz = total_size;
    ph.p_memsz = total_size;
    ph.p_align = 1;
    lb.write_at(phdr_offset + phi * sizeof(Elf64_Phdr), ph);
    ++phi;
  }

  BuiltImage result;
  result.buffer = std::move(lb.buf);
  result.phdr_offset = phdr_offset;
  result.phdr_count = num_phdrs;
  result.got_offset = got_offset;
  result.rela_got_offset = rela_got_offset;
  result.android_got_offset = android_got_offset;

  return result;
}

}  // namespace yukiplt::test
