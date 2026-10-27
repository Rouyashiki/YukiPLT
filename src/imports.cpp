// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "imports.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

#include "common.hpp"
#include "elf.hpp"

namespace yukiplt::detail {
namespace {

bool readable(const InspectedImage& image, uintptr_t address, size_t size) {
  uintptr_t end;
  if (size == 0 || !safe_add(address, size, end)) return false;
  for (const auto& segment : image.load_segments) {
    if ((segment.flags & PF_R) && address >= segment.vaddr_begin && end <= segment.vaddr_end)
      return true;
  }
  return false;
}

template <typename T>
Result<T> read(const InspectedImage& image, uintptr_t base, size_t index = 0) {
  if (index > std::numeric_limits<uintptr_t>::max() / sizeof(T))
    return Error::Make(ErrorCode::kIntegerOverflow);
  uintptr_t address;
  if (!safe_add(base, index * sizeof(T), address)) return Error::Make(ErrorCode::kIntegerOverflow);
  if (!readable(image, address, sizeof(T))) return Error::Make(ErrorCode::kOutOfBounds);
  T value;
  std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(T));
  return value;
}

bool array_readable(const InspectedImage& image, uintptr_t base, size_t count, size_t size) {
  return count <= std::numeric_limits<size_t>::max() / size && readable(image, base, count * size);
}

// Bound dynsym before interpreting an r_info index. A nonempty GNU hash's
// final bucket chain bounds the table. An empty GNU hash is different: GNU ld
// may emit symoffset=1 even when unhashed imports follow, so only the readable
// LOAD containing dynsym supplies a bound in that case (not an exact count).
Result<size_t> symbol_count(const InspectedImage& image) {
  if (image.sysv_hash != 0) {
    auto buckets = read<uint32_t>(image, image.sysv_hash);
    auto chains = read<uint32_t>(image, image.sysv_hash, 1);
    if (!buckets) return buckets.error();
    if (!chains) return chains.error();
    const uint64_t words = uint64_t{2} + buckets.value() + chains.value();
    if (buckets.value() == 0 || chains.value() == 0 || words > std::numeric_limits<size_t>::max() ||
        !array_readable(image, image.sysv_hash, static_cast<size_t>(words), sizeof(uint32_t)) ||
        !array_readable(image, image.symtab, chains.value(), sizeof(Elf64_Sym)))
      return Error::Make(ErrorCode::kCorruptedElf);
    return static_cast<size_t>(chains.value());
  }
  if (image.gnu_hash == 0) return Error::Make(ErrorCode::kNoHashTable);
  auto buckets = read<uint32_t>(image, image.gnu_hash);
  auto first = read<uint32_t>(image, image.gnu_hash, 1);
  auto bloom = read<uint32_t>(image, image.gnu_hash, 2);
  if (!buckets) return buckets.error();
  if (!first) return first.error();
  if (!bloom) return bloom.error();
  if (buckets.value() == 0 || first.value() == 0 || bloom.value() == 0 ||
      (bloom.value() & (bloom.value() - 1)) != 0)
    return Error::Make(ErrorCode::kCorruptedElf);

  const uint64_t prefix = uint64_t{16} + uint64_t{bloom.value()} * 8;
  const uint64_t header_size = prefix + uint64_t{buckets.value()} * 4;
  if (header_size > std::numeric_limits<size_t>::max() ||
      !readable(image, image.gnu_hash, static_cast<size_t>(header_size)))
    return Error::Make(ErrorCode::kCorruptedElf);
  // readable() above proves both additions cannot overflow.
  const uintptr_t bucket_base = image.gnu_hash + static_cast<uintptr_t>(prefix);
  const uintptr_t chain_base = image.gnu_hash + static_cast<uintptr_t>(header_size);
  uint32_t last_bucket = 0;
  for (size_t i = 0; i < buckets.value(); ++i) {
    auto bucket = read<uint32_t>(image, bucket_base, i);
    if (!bucket) return bucket.error();
    if (bucket.value() != 0 && bucket.value() < first.value())
      return Error::Make(ErrorCode::kCorruptedElf);
    last_bucket = std::max(last_bucket, bucket.value());
  }
  if (last_bucket == 0) {
    for (const auto& segment : image.load_segments) {
      if ((segment.flags & PF_R) && image.symtab >= segment.vaddr_begin &&
          image.symtab < segment.vaddr_end) {
        const size_t bound = (segment.vaddr_end - image.symtab) / sizeof(Elf64_Sym);
        if (bound == 0) return Error::Make(ErrorCode::kCorruptedElf);
        return bound;
      }
    }
    return Error::Make(ErrorCode::kOutOfBounds);
  }
  size_t count = first.value();
  if (last_bucket != 0) {
    // Each iteration must have a mapped chain word AND symbol, so a missing
    // terminator cannot turn into an unbounded walk or read past PT_LOAD.
    size_t index = last_bucket;
    for (;;) {
      auto symbol = read<Elf64_Sym>(image, image.symtab, index);
      auto chain = read<uint32_t>(image, chain_base, index - first.value());
      if (!symbol) return symbol.error();
      if (!chain) return chain.error();
      if (index == std::numeric_limits<uint32_t>::max())
        return Error::Make(ErrorCode::kIntegerOverflow);
      count = ++index;
      if (chain.value() & 1) break;
    }
  }
  if (!array_readable(image, image.symtab, count, sizeof(Elf64_Sym)))
    return Error::Make(ErrorCode::kCorruptedElf);
  return count;
}

}  // namespace

Result<ImportSnapshot> snapshot_imports(const InspectedImage& image) {
  ImportSnapshot snapshot;
  if (image.jmprel_count == 0) return snapshot;
  auto count = symbol_count(image);
  if (!count) return count.error();
  if (!readable(image, image.strtab, image.strsz)) return Error::Make(ErrorCode::kOutOfBounds);

  std::vector<uintptr_t> addresses;
  for (size_t i = 0; i < image.jmprel_count; ++i) {
    auto record = read<Elf64_Rela>(image, image.jmprel, i);
    if (!record) return record.error();
    const auto& rela = record.value();
    const auto symbol_index = static_cast<uint32_t>(ELF64_R_SYM(rela.r_info));
    if (ELF64_R_TYPE(rela.r_info) != R_AARCH64_JUMP_SLOT || symbol_index == 0) {
      ++snapshot.skipped_relocations;
      continue;
    }
    if (symbol_index >= count.value()) return Error::Make(ErrorCode::kCorruptedElf);
    auto symbol = read<Elf64_Sym>(image, image.symtab, symbol_index);
    if (!symbol) return symbol.error();
    const auto name_offset = symbol.value().st_name;
    if (name_offset >= image.strsz) return Error::Make(ErrorCode::kCorruptedElf);
    const char* name = reinterpret_cast<const char*>(image.strtab + name_offset);
    const auto* end = static_cast<const char*>(std::memchr(name, 0, image.strsz - name_offset));
    if (end == nullptr) return Error::Make(ErrorCode::kCorruptedElf);

    uintptr_t address;
    if (!safe_add(image.load_bias, static_cast<uintptr_t>(rela.r_offset), address))
      return Error::Make(ErrorCode::kIntegerOverflow);
    if (address % sizeof(uint64_t) != 0 || !image.addr_in_writable_load(address, sizeof(uint64_t)))
      return Error::Make(ErrorCode::kCorruptedElf);

    snapshot.imports.push_back(
        {std::string(name, static_cast<size_t>(end - name)), symbol_index, i, address});
    addresses.push_back(address);
  }
  // Preserve table order in the snapshot; sort a separate address list so
  // thousands of imports do not require quadratic duplicate detection.
  std::sort(addresses.begin(), addresses.end());
  if (std::adjacent_find(addresses.begin(), addresses.end()) != addresses.end())
    return Error::Make(ErrorCode::kCorruptedElf);
  return snapshot;
}

namespace {

constexpr uint16_t kVersionMask = 0x7fff;
constexpr uint16_t kHiddenBit = 0x8000;

template <typename T>
Result<T> read_version(const InspectedImage& image, uintptr_t address, size_t index = 0) {
  if (index > std::numeric_limits<uintptr_t>::max() / sizeof(T) ||
      !safe_add(address, index * sizeof(T), address))
    return Error::Make(ErrorCode::kIntegerOverflow);
  if (!readable(image, address, sizeof(T))) return Error::Make(ErrorCode::kOutOfBounds);
  T value;
  std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(T));
  return value;
}

Result<std::string> string_at(const InspectedImage& image, uint32_t offset) {
  if (offset >= image.strsz || !readable(image, image.strtab, image.strsz))
    return Error::Make(ErrorCode::kCorruptedElf);
  const char* begin = reinterpret_cast<const char*>(image.strtab + offset);
  const auto* end = static_cast<const char*>(std::memchr(begin, 0, image.strsz - offset));
  if (end == nullptr || end == begin) return Error::Make(ErrorCode::kCorruptedElf);
  return std::string(begin, static_cast<size_t>(end - begin));
}

Result<uintptr_t> advance(uintptr_t base, uint32_t offset, size_t minimum) {
  if (offset < minimum) return Error::Make(ErrorCode::kCorruptedElf);
  uintptr_t address;
  if (!safe_add(base, offset, address)) return Error::Make(ErrorCode::kIntegerOverflow);
  return address;
}

struct Tags {
  uint64_t values[5]{};  // VERSYM, VERNEED, VERNEEDNUM, VERDEF, VERDEFNUM
  bool present[5]{};
};

Result<Tags> version_tags(const InspectedImage& image) {
  Tags tags;
  constexpr int64_t wanted[] = {DT_VERSYM, DT_VERNEED, DT_VERNEEDNUM, DT_VERDEF, DT_VERDEFNUM};
  for (size_t i = 0; i < image.dynamic_size / sizeof(Elf64_Dyn); ++i) {
    auto entry = read_version<Elf64_Dyn>(image, image.dynamic, i);
    if (!entry) return entry.error();
    if (entry.value().d_tag == DT_NULL) return tags;
    for (size_t j = 0; j < 5; ++j) {
      if (entry.value().d_tag != wanted[j]) continue;
      if (tags.present[j]) return Error::Make(ErrorCode::kCorruptedElf);
      tags.present[j] = true;
      tags.values[j] = entry.value().d_un.d_val;
    }
  }
  return Error::Make(ErrorCode::kCorruptedElf);
}

struct NamedVersion {
  uint16_t index;
  VersionSource source;
  std::string name;
  std::string dependency;
};

struct RecordRange {
  uintptr_t begin;
  uintptr_t end;
};

template <typename T>
Result<T> read_record(const InspectedImage& image, uintptr_t address,
                      std::vector<RecordRange>& ranges) {
  auto value = read_version<T>(image, address);
  if (value) ranges.push_back({address, address + sizeof(T)});
  return value;
}

// Validate every linked entry, even versions that no selected import uses.
// Forward, non-overlapping relative offsets and exact terminal links bound
// traversal by both the declared counts and the readable mapping.
Error read_needs(const InspectedImage& image, uintptr_t address, uint64_t count,
                 std::vector<NamedVersion>& out, std::vector<RecordRange>& ranges) {
  for (uint64_t i = 0; i < count; ++i) {
    auto record = read_record<Elf64_Verneed>(image, address, ranges);
    if (!record) return record.error();
    const auto& need = record.value();
    if (need.vn_version != 1 || need.vn_cnt == 0 || (i + 1 == count) != (need.vn_next == 0))
      return Error::Make(ErrorCode::kCorruptedElf);
    auto file = string_at(image, need.vn_file);
    if (!file) return file.error();
    auto aux = advance(address, need.vn_aux, sizeof(Elf64_Verneed));
    if (!aux) return aux.error();
    uintptr_t next_record = 0;
    if (need.vn_next != 0) {
      auto next = advance(address, need.vn_next, sizeof(Elf64_Verneed));
      if (!next) return next.error();
      next_record = next.value();
    }
    for (size_t j = 0; j < need.vn_cnt; ++j) {
      auto item = read_record<Elf64_Vernaux>(image, aux.value(), ranges);
      if (!item) return item.error();
      const auto& value = item.value();
      const uint16_t index = value.vna_other & kVersionMask;
      if (index < 2 || (j + 1 == need.vn_cnt) != (value.vna_next == 0))
        return Error::Make(ErrorCode::kCorruptedElf);
      auto name = string_at(image, value.vna_name);
      if (!name) return name.error();
      if (elf_hash_value(name.value().c_str()) != value.vna_hash)
        return Error::Make(ErrorCode::kCorruptedElf);
      out.push_back({index, VersionSource::kNeeded, std::move(name.value()), file.value()});
      if (value.vna_next != 0) {
        aux = advance(aux.value(), value.vna_next, sizeof(Elf64_Vernaux));
        if (!aux) return aux.error();
      }
    }
    address = next_record;
  }
  return Error::Ok();
}

Error read_definitions(const InspectedImage& image, uintptr_t address, uint64_t count,
                       std::vector<NamedVersion>& out, std::vector<RecordRange>& ranges) {
  for (uint64_t i = 0; i < count; ++i) {
    auto record = read_record<Elf64_Verdef>(image, address, ranges);
    if (!record) return record.error();
    const auto& definition = record.value();
    const uint16_t index = definition.vd_ndx & kVersionMask;
    if (definition.vd_version != 1 || definition.vd_cnt == 0 || index == 0 ||
        (index == 1) != ((definition.vd_flags & 1) != 0) ||
        (i + 1 == count) != (definition.vd_next == 0))
      return Error::Make(ErrorCode::kCorruptedElf);
    auto aux = advance(address, definition.vd_aux, sizeof(Elf64_Verdef));
    if (!aux) return aux.error();
    uintptr_t next_record = 0;
    if (definition.vd_next != 0) {
      auto next = advance(address, definition.vd_next, sizeof(Elf64_Verdef));
      if (!next) return next.error();
      next_record = next.value();
    }
    for (size_t j = 0; j < definition.vd_cnt; ++j) {
      auto item = read_record<Elf64_Verdaux>(image, aux.value(), ranges);
      if (!item) return item.error();
      if ((j + 1 == definition.vd_cnt) != (item.value().vda_next == 0))
        return Error::Make(ErrorCode::kCorruptedElf);
      auto name = string_at(image, item.value().vda_name);
      if (!name) return name.error();
      if (j == 0) {
        if (elf_hash_value(name.value().c_str()) != definition.vd_hash)
          return Error::Make(ErrorCode::kCorruptedElf);
        out.push_back({index, VersionSource::kDefined, std::move(name.value()), {}});
      }
      if (item.value().vda_next != 0) {
        aux = advance(aux.value(), item.value().vda_next, sizeof(Elf64_Verdaux));
        if (!aux) return aux.error();
      }
    }
    address = next_record;
  }
  return Error::Ok();
}

}  // namespace

Result<VersionedImportSnapshot> snapshot_versioned_imports(const InspectedImage& image) {
  auto raw = snapshot_imports(image);
  if (!raw) return raw.error();
  auto tags = version_tags(image);
  if (!tags) return tags.error();
  const auto& t = tags.value();
  if (t.present[1] != t.present[2] || t.present[3] != t.present[4] ||
      (!t.present[0] && (t.present[1] || t.present[3])))
    return Error::Make(ErrorCode::kCorruptedElf);
  std::vector<NamedVersion> versions;
  std::vector<RecordRange> ranges;
  for (size_t pair : {size_t{1}, size_t{3}}) {
    if (!t.present[pair]) continue;
    if (t.values[pair + 1] == 0) return Error::Make(ErrorCode::kCorruptedElf);
    uintptr_t address;
    // Unlike SYMTAB and VERSYM, glibc leaves VERNEED/VERDEF load-relative.
    if (!safe_add(image.load_bias, t.values[pair], address))
      return Error::Make(ErrorCode::kIntegerOverflow);
    auto error = pair == 1 ? read_needs(image, address, t.values[pair + 1], versions, ranges)
                           : read_definitions(image, address, t.values[pair + 1], versions, ranges);
    if (error) return error;
  }
  // Main-record and auxiliary chains have independent relative offsets. Aux
  // entries may follow later main records; reject only actual byte overlap.
  std::sort(ranges.begin(), ranges.end(),
            [](const RecordRange& a, const RecordRange& b) { return a.begin < b.begin; });
  for (size_t i = 1; i < ranges.size(); ++i) {
    if (ranges[i].begin < ranges[i - 1].end) return Error::Make(ErrorCode::kCorruptedElf);
  }
  std::sort(versions.begin(), versions.end(),
            [](const NamedVersion& a, const NamedVersion& b) { return a.index < b.index; });
  for (size_t i = 1; i < versions.size(); ++i) {
    if (versions[i - 1].index == versions[i].index) return Error::Make(ErrorCode::kCorruptedElf);
  }
  uintptr_t versym = t.values[0];
  if (t.present[0] && !image.dptr_adjusted && !safe_add(image.load_bias, versym, versym))
    return Error::Make(ErrorCode::kIntegerOverflow);
  VersionedImportSnapshot result;
  result.skipped_relocations = raw.value().skipped_relocations;
  for (auto& entry : raw.value().imports) {
    SymbolVersion version;
    version.table_present = t.present[0];
    if (t.present[0]) {
      auto value = read_version<Elf64_Half>(image, versym, entry.symbol_index);
      if (!value) return value.error();
      version.index = value.value() & kVersionMask;
      version.hidden = (value.value() & kHiddenBit) != 0;
      if (version.index < 2 && version.hidden) return Error::Make(ErrorCode::kCorruptedElf);
      if (version.index >= 2) {
        auto found =
            std::lower_bound(versions.begin(), versions.end(), version.index,
                             [](const NamedVersion& v, uint16_t index) { return v.index < index; });
        if (found == versions.end() || found->index != version.index)
          return Error::Make(ErrorCode::kCorruptedElf);
        auto symbol = read_version<Elf64_Sym>(image, image.symtab, entry.symbol_index);
        if (!symbol) return symbol.error();
        if ((symbol.value().st_shndx == SHN_UNDEF) != (found->source == VersionSource::kNeeded))
          return Error::Make(ErrorCode::kCorruptedElf);
        version.name = found->name;
        version.dependency = found->dependency;
        version.source = found->source;
      }
    }
    result.imports.push_back({std::move(entry), std::move(version)});
  }
  return result;
}

Error validate_selector(const ImportSelector& selector) noexcept {
  if (selector.symbol == nullptr) return Error::Make(ErrorCode::kNullPointer);
  if (*selector.symbol == '\0' ||
      (selector.version_match != VersionMatch::kAny &&
       selector.version_match != VersionMatch::kUnversioned &&
       selector.version_match != VersionMatch::kExact) ||
      (selector.hidden != HiddenMatch::kAny && selector.hidden != HiddenMatch::kNonHidden &&
       selector.hidden != HiddenMatch::kHidden) ||
      (selector.version_match == VersionMatch::kExact
           ? selector.version == nullptr || *selector.version == '\0'
           : selector.version != nullptr) ||
      (selector.dependency != nullptr && *selector.dependency == '\0'))
    return Error::Make(ErrorCode::kInvalidArgument);
  return Error::Ok();
}

Result<size_t> select_import(const VersionedImportSnapshot& snapshot,
                             const ImportSelector& selector) {
  auto invalid = validate_selector(selector);
  if (invalid) return invalid;
  size_t selected = ~size_t{0};
  for (size_t i = 0; i < snapshot.imports.size(); ++i) {
    const auto& entry = snapshot.imports[i];
    if (entry.import.symbol != selector.symbol ||
        (selector.relocation_index != ~size_t{0} &&
         entry.import.relocation_index != selector.relocation_index) ||
        (selector.version_match == VersionMatch::kUnversioned && entry.version.index >= 2) ||
        (selector.version_match == VersionMatch::kExact &&
         entry.version.name != selector.version) ||
        (selector.dependency != nullptr && entry.version.dependency != selector.dependency) ||
        (selector.hidden == HiddenMatch::kHidden && !entry.version.hidden) ||
        (selector.hidden == HiddenMatch::kNonHidden && entry.version.hidden))
      continue;
    if (selected != ~size_t{0}) return Error::Make(ErrorCode::kAmbiguousSymbol);
    selected = i;
  }
  if (selected == ~size_t{0}) return Error::Make(ErrorCode::kSymbolNotFound);
  return selected;
}

}  // namespace yukiplt::detail
