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

Result<size_t> dynamic_symbol_count(const InspectedImage& image) { return symbol_count(image); }

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

// Attach version metadata to a caller-supplied set of imports (from DT_JMPREL,
// DT_RELA or DT_ANDROID_RELA).  Shared by snapshot_versioned_imports() and the
// function-import path so version parsing lives in one place.
Result<VersionedImportSnapshot> resolve_versions(const InspectedImage& image,
                                                 std::vector<ImportInfo> imports,
                                                 size_t skipped_relocations) {
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
  result.skipped_relocations = skipped_relocations;
  for (auto& entry : imports) {
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

Result<VersionedImportSnapshot> snapshot_versioned_imports(const InspectedImage& image) {
  auto raw = snapshot_imports(image);
  if (!raw) return raw.error();
  return resolve_versions(image, std::move(raw.value().imports), raw.value().skipped_relocations);
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

namespace {

// True if [addr, addr + size) lies entirely within one readable (PF_R) LOAD.

// Resolve r_offset to a runtime slot address.
bool resolve_slot(const InspectedImage& image, uint64_t r_offset, uintptr_t& out) noexcept {
  return safe_add(image.load_bias, static_cast<uintptr_t>(r_offset), out);
}

}  // namespace

Error decode_rela(const InspectedImage& image, RelocVisitor visit, void* context) {
  if (image.rela == 0 || image.rela_size == 0) return Error::Ok();
  if (image.rela_ent != 0 && image.rela_ent != sizeof(Elf64_Rela))
    return Error::Make(ErrorCode::kUnsupportedFormat);
  if (image.rela_size % sizeof(Elf64_Rela) != 0) return Error::Make(ErrorCode::kCorruptedElf);
  if (!readable(image, image.rela, image.rela_size)) return Error::Make(ErrorCode::kOutOfBounds);

  size_t count = image.rela_size / sizeof(Elf64_Rela);

  // Allow overlap only when JMPREL is wholly inside the native table and shares
  // its end; decode the prefix once. Reject all other overlaps.
  if (image.jmprel != 0 && image.jmprel_count != 0) {
    uintptr_t rela_begin = image.rela;
    uintptr_t rela_end = image.rela + image.rela_size;  // readable() proved no overflow.
    uintptr_t plt_begin = image.jmprel;
    uintptr_t plt_bytes = image.jmprel_count * sizeof(Elf64_Rela);
    uintptr_t plt_end;
    if (!safe_add(plt_begin, plt_bytes, plt_end)) return Error::Make(ErrorCode::kIntegerOverflow);
    const bool disjoint = plt_end <= rela_begin || plt_begin >= rela_end;
    if (!disjoint) {
      const bool contained_with_shared_end = plt_begin >= rela_begin && plt_end == rela_end &&
                                             (plt_begin - rela_begin) % sizeof(Elf64_Rela) == 0;
      if (!contained_with_shared_end) return Error::Make(ErrorCode::kCorruptedElf);
      count = (plt_begin - rela_begin) / sizeof(Elf64_Rela);
    }
  }

  for (size_t i = 0; i < count; ++i) {
    Elf64_Rela rela;
    std::memcpy(&rela, reinterpret_cast<const void*>(image.rela + i * sizeof(Elf64_Rela)),
                sizeof(rela));
    DecodedReloc decoded;
    if (!resolve_slot(image, rela.r_offset, decoded.slot_address))
      return Error::Make(ErrorCode::kIntegerOverflow);
    decoded.symbol_index = reloc_sym_of(rela.r_info);
    decoded.type = reloc_type_of(rela.r_info);
    decoded.addend = static_cast<int64_t>(rela.r_addend);
    decoded.source = RelocSource::kRela;
    decoded.index = i;
    if (Error e = visit(context, decoded)) return e;
  }
  return Error::Ok();
}

namespace {

/// A bounds-checked cursor over the packed byte stream.  Every read verifies it
/// stays within [base, base + size); SLEB128 reads also cap the encoding length.
class ByteCursor {
 public:
  ByteCursor(uintptr_t base, size_t size) noexcept : at_(base), end_(base + size), ok_(true) {
    // The caller proved [base, base+size) is readable, so base+size cannot wrap.
  }

  bool ok() const noexcept { return ok_; }
  size_t remaining() const noexcept { return ok_ ? static_cast<size_t>(end_ - at_) : 0; }

  // Read one byte; sets failure and returns 0 at end of stream.
  uint8_t byte() noexcept {
    if (!ok_ || at_ >= end_) {
      ok_ = false;
      return 0;
    }
    uint8_t value;
    std::memcpy(&value, reinterpret_cast<const void*>(at_), 1);
    ++at_;
    return value;
  }

  // SLEB128 must fit int64_t: byte ten may only terminate with 0x00 or 0x7f.
  // Reject truncation, continuation and invalid sign extension.
  int64_t sleb128() noexcept {
    uint64_t result = 0;
    int shift = 0;
    constexpr int kMaxBytes = 10;
    for (int i = 0; i < kMaxBytes; ++i) {
      const uint8_t byte_value = byte();
      if (!ok_) return 0;
      if (i == kMaxBytes - 1) {
        if (byte_value != 0x00 && byte_value != 0x7f) break;
        if (byte_value == 0x7f) result |= uint64_t{1} << 63;
        return static_cast<int64_t>(result);
      }
      result |= static_cast<uint64_t>(byte_value & 0x7f) << shift;
      shift += 7;
      if ((byte_value & 0x80) == 0) {
        // Sign-extend from the final bit (shift <= 63 here).
        if (byte_value & 0x40) result |= ~uint64_t{0} << shift;
        return static_cast<int64_t>(result);
      }
    }
    ok_ = false;
    return 0;
  }

 private:
  uintptr_t at_;
  uintptr_t end_;
  bool ok_;
};

constexpr uint64_t kKnownGroupFlags =
    kRelocGroupedByInfo | kRelocGroupedByOffsetDelta | kRelocGroupedByAddend | kRelocGroupHasAddend;

}  // namespace

Error decode_android_rela(const InspectedImage& image, RelocVisitor visit, void* context) {
  if (image.android_rela == 0 || image.android_rela_size == 0) return Error::Ok();
  if (image.android_rela_size > kMaxPackedBytes) return Error::Make(ErrorCode::kOutOfBounds);
  if (!readable(image, image.android_rela, image.android_rela_size))
    return Error::Make(ErrorCode::kOutOfBounds);

  ByteCursor cursor(image.android_rela, image.android_rela_size);

  // Magic "APS2".
  for (unsigned char expected : kAps2Magic) {
    if (cursor.byte() != expected || !cursor.ok()) return Error::Make(ErrorCode::kCorruptedElf);
  }

  const int64_t total_signed = cursor.sleb128();
  const int64_t group_base_offset = cursor.sleb128();
  if (!cursor.ok() || total_signed < 0 || group_base_offset < 0)
    return Error::Make(ErrorCode::kCorruptedElf);
  const uint64_t total = static_cast<uint64_t>(total_signed);
  if (total > kMaxPackedRelocations) return Error::Make(ErrorCode::kOutOfBounds);

  // r_offset and the addend are accumulated with checked signed arithmetic: a
  // stream whose running value overflows int64_t is rejected, never wrapped.
  // Every emitted r_offset must also be non-negative.
  int64_t offset = group_base_offset;
  int64_t addend = 0;
  uint64_t emitted = 0;

  while (emitted < total) {
    const int64_t group_size_signed = cursor.sleb128();
    const int64_t group_flags_signed = cursor.sleb128();
    if (!cursor.ok() || group_size_signed <= 0) return Error::Make(ErrorCode::kCorruptedElf);
    const uint64_t group_size = static_cast<uint64_t>(group_size_signed);
    if (group_size > total - emitted) return Error::Make(ErrorCode::kCorruptedElf);
    if (group_flags_signed < 0 ||
        (static_cast<uint64_t>(group_flags_signed) & ~kKnownGroupFlags) != 0)
      return Error::Make(ErrorCode::kCorruptedElf);
    const uint64_t flags = static_cast<uint64_t>(group_flags_signed);

    const bool grouped_by_delta = (flags & kRelocGroupedByOffsetDelta) != 0;
    const bool grouped_by_info = (flags & kRelocGroupedByInfo) != 0;
    const bool group_has_addend = (flags & kRelocGroupHasAddend) != 0;
    const bool grouped_by_addend = (flags & kRelocGroupedByAddend) != 0;
    // "grouped by addend" without "has addend" is contradictory.
    if (grouped_by_addend && !group_has_addend) return Error::Make(ErrorCode::kCorruptedElf);

    int64_t group_offset_delta = 0;
    uint64_t group_info = 0;
    if (grouped_by_delta) {
      group_offset_delta = cursor.sleb128();
      if (!cursor.ok()) return Error::Make(ErrorCode::kCorruptedElf);
    }
    if (grouped_by_info) {
      group_info = static_cast<uint64_t>(cursor.sleb128());
      if (!cursor.ok()) return Error::Make(ErrorCode::kCorruptedElf);
    }
    if (grouped_by_addend) {
      const int64_t group_addend_delta = cursor.sleb128();
      if (!cursor.ok()) return Error::Make(ErrorCode::kCorruptedElf);
      if (__builtin_add_overflow(addend, group_addend_delta, &addend))
        return Error::Make(ErrorCode::kIntegerOverflow);
    }

    for (uint64_t i = 0; i < group_size; ++i) {
      int64_t delta = group_offset_delta;
      if (!grouped_by_delta) {
        delta = cursor.sleb128();
        if (!cursor.ok()) return Error::Make(ErrorCode::kCorruptedElf);
      }
      if (__builtin_add_overflow(offset, delta, &offset))
        return Error::Make(ErrorCode::kIntegerOverflow);
      if (offset < 0) return Error::Make(ErrorCode::kCorruptedElf);
      uint64_t info = group_info;
      if (!grouped_by_info) {
        info = static_cast<uint64_t>(cursor.sleb128());
        if (!cursor.ok()) return Error::Make(ErrorCode::kCorruptedElf);
      }
      if (group_has_addend && !grouped_by_addend) {
        const int64_t addend_delta = cursor.sleb128();
        if (!cursor.ok()) return Error::Make(ErrorCode::kCorruptedElf);
        if (__builtin_add_overflow(addend, addend_delta, &addend))
          return Error::Make(ErrorCode::kIntegerOverflow);
      }
      if (!group_has_addend) addend = 0;

      DecodedReloc decoded;
      if (!resolve_slot(image, static_cast<uint64_t>(offset), decoded.slot_address))
        return Error::Make(ErrorCode::kIntegerOverflow);
      decoded.symbol_index = reloc_sym_of(info);
      decoded.type = reloc_type_of(info);
      decoded.addend = addend;
      decoded.source = RelocSource::kAndroidRela;
      decoded.index = static_cast<size_t>(emitted);
      if (Error e = visit(context, decoded)) return e;
      ++emitted;
    }
  }

  // The declared count is consumed.  Any remaining bytes must be all-zero
  // padding (LLD aligns the section); a non-zero trailing byte is malformed.
  while (cursor.remaining() != 0) {
    if (cursor.byte() != 0) return Error::Make(ErrorCode::kCorruptedElf);
  }
  if (!cursor.ok()) return Error::Make(ErrorCode::kCorruptedElf);
  return Error::Ok();
}

namespace {

RelocationSource to_public_source(RelocSource source) noexcept {
  switch (source) {
    case RelocSource::kJmprel:
      return RelocationSource::kJmprel;
    case RelocSource::kRela:
      return RelocationSource::kRela;
    case RelocSource::kAndroidRela:
    default:
      return RelocationSource::kAndroidRela;
  }
}

// True if [addr, addr + size) lies entirely within one readable (PF_R) LOAD.
// Every table this path reads must pass this, exactly as on the legacy path.

// Per-scan state shared by every source.  The dynsym bound and the string
// table are validated on the first record that needs a symbol, so an image
// with nothing to import never has its hash table or strings read.
struct ScanState {
  const InspectedImage& image;
  RawFunctionSnapshot& result;
  size_t symbol_bound = 0;
  bool symbols_ready = false;
};

Error ensure_symbols(ScanState& state) {
  if (state.symbols_ready) return Error::Ok();
  auto bound = dynamic_symbol_count(state.image);
  if (!bound) return bound.error();
  if (!readable(state.image, state.image.strtab, state.image.strsz))
    return Error::Make(ErrorCode::kOutOfBounds);
  state.symbol_bound = bound.value();
  state.symbols_ready = true;
  return Error::Ok();
}

// Read a record's symbol name (bounded by STRSZ), ELF symbol type and whether it
// is undefined.  An empty name is recorded as-is, as the legacy snapshot does;
// no selector can match it, because a selector's symbol must be non-empty.
Error read_symbol(const ScanState& state, uint32_t symbol_index, std::string& name,
                  uint8_t& symbol_type, bool& undefined) {
  const InspectedImage& image = state.image;
  if (symbol_index == 0 || symbol_index >= state.symbol_bound)
    return Error::Make(ErrorCode::kCorruptedElf);
  uintptr_t sym_addr;
  if (!safe_add(image.symtab, static_cast<uintptr_t>(symbol_index) * sizeof(Elf64_Sym), sym_addr))
    return Error::Make(ErrorCode::kIntegerOverflow);
  if (!readable(image, sym_addr, sizeof(Elf64_Sym))) return Error::Make(ErrorCode::kOutOfBounds);
  Elf64_Sym sym;
  std::memcpy(&sym, reinterpret_cast<const void*>(sym_addr), sizeof(sym));
  if (sym.st_name >= image.strsz) return Error::Make(ErrorCode::kCorruptedElf);
  const char* begin = reinterpret_cast<const char*>(image.strtab + sym.st_name);
  const auto* end = static_cast<const char*>(std::memchr(begin, 0, image.strsz - sym.st_name));
  if (end == nullptr) return Error::Make(ErrorCode::kCorruptedElf);
  name.assign(begin, static_cast<size_t>(end - begin));
  symbol_type = static_cast<uint8_t>(ELF64_ST_TYPE(sym.st_info));
  undefined = sym.st_shndx == kShnUndef;
  return Error::Ok();
}

// Keep one record from any source.  Only JUMP_SLOT and GLOB_DAT with a non-zero
// symbol index are materialized, whichever table holds them (labelled with their
// real source and type); every other record is only counted, so a large table
// of RELATIVE or other relocations costs no memory.
Error keep(ScanState& state, const DecodedReloc& reloc) {
  if ((reloc.type != kRAarch64JumpSlot && reloc.type != kRAarch64GlobDat) ||
      reloc.symbol_index == 0) {
    ++state.result.skipped_relocations;
    return Error::Ok();
  }
  if (reloc.slot_address % sizeof(uint64_t) != 0 ||
      !state.image.addr_in_writable_load(reloc.slot_address, sizeof(uint64_t)))
    return Error::Make(ErrorCode::kCorruptedElf);
  if (Error e = ensure_symbols(state)) return e;
  FunctionReloc record;
  if (Error e = read_symbol(state, reloc.symbol_index, record.entry.base.import.symbol,
                            record.entry.symbol_type, record.symbol_undefined))
    return e;
  record.entry.base.import.symbol_index = reloc.symbol_index;
  record.entry.base.import.relocation_index = reloc.index;
  record.entry.base.import.slot_address = reloc.slot_address;
  record.entry.source = to_public_source(reloc.source);
  record.entry.relocation_type = reloc.type;
  record.addend = reloc.addend;
  state.result.records.push_back(std::move(record));
  return Error::Ok();
}

Error visit_record(void* context, const DecodedReloc& reloc) {
  return keep(*static_cast<ScanState*>(context), reloc);
}

}  // namespace

Result<RawFunctionSnapshot> scan_function_imports(const InspectedImage& image, uint32_t sources) {
  if (sources == 0 || (sources & ~(kSourceJmprel | kSourceRela | kSourceAndroidRela)) != 0)
    return Error::Make(ErrorCode::kInvalidArgument);
  // Scanning DT_RELA or DT_ANDROID_RELA refuses an image whose relocation tags
  // are unusable (a repeated tag, a pointer without its size, an overflowing
  // address, or a REL form).  A DT_JMPREL-only scan does not read those tables
  // and, like the legacy path, ignores them.
  if (image.reloc_tags_unusable && (sources & (kSourceRela | kSourceAndroidRela)) != 0)
    return Error::Make(ErrorCode::kUnsupportedFormat);

  RawFunctionSnapshot result;
  ScanState state{image, result};

  if ((sources & kSourceJmprel) != 0 && image.jmprel_count != 0) {
    // inspect() bounded the table within a LOAD; reading it also needs PF_R.
    if (!readable(image, image.jmprel, image.jmprel_count * sizeof(Elf64_Rela)))
      return Error::Make(ErrorCode::kOutOfBounds);
    for (size_t i = 0; i < image.jmprel_count; ++i) {
      Elf64_Rela rela;
      std::memcpy(&rela, reinterpret_cast<const void*>(image.jmprel + i * sizeof(Elf64_Rela)),
                  sizeof(rela));
      DecodedReloc reloc;
      if (!safe_add(image.load_bias, static_cast<uintptr_t>(rela.r_offset), reloc.slot_address))
        return Error::Make(ErrorCode::kIntegerOverflow);
      reloc.symbol_index = reloc_sym_of(rela.r_info);
      reloc.type = reloc_type_of(rela.r_info);
      reloc.addend = static_cast<int64_t>(rela.r_addend);
      reloc.source = RelocSource::kJmprel;
      reloc.index = i;
      if (Error e = keep(state, reloc)) return e;
    }
  }
  if (sources & kSourceRela) {
    if (Error e = decode_rela(image, visit_record, &state)) return e;
  }
  if (sources & kSourceAndroidRela) {
    if (Error e = decode_android_rela(image, visit_record, &state)) return e;
  }

  // Duplicate slot addresses across all scanned sources are malformed.
  std::vector<uintptr_t> addresses;
  addresses.reserve(result.records.size());
  for (const auto& record : result.records)
    addresses.push_back(record.entry.base.import.slot_address);
  std::sort(addresses.begin(), addresses.end());
  if (std::adjacent_find(addresses.begin(), addresses.end()) != addresses.end())
    return Error::Make(ErrorCode::kCorruptedElf);

  // Attach version metadata over the whole set, preserving order.
  std::vector<ImportInfo> infos;
  infos.reserve(result.records.size());
  for (const auto& record : result.records) infos.push_back(record.entry.base.import);
  auto versioned = resolve_versions(image, std::move(infos), result.skipped_relocations);
  if (!versioned) return versioned.error();
  for (size_t i = 0; i < result.records.size(); ++i)
    result.records[i].entry.base.version = std::move(versioned.value().imports[i].version);
  return result;
}

Result<FunctionImportSnapshot> snapshot_function_imports(const InspectedImage& image,
                                                         uint32_t sources) {
  auto scan = scan_function_imports(image, sources);
  if (!scan) return scan.error();
  FunctionImportSnapshot result;
  result.skipped_relocations = scan.value().skipped_relocations;
  result.imports.reserve(scan.value().records.size());
  for (auto& record : scan.value().records) result.imports.push_back(std::move(record.entry));
  return result;
}

Error validate_function_selector(const FunctionImportSelector& selector) noexcept {
  if (Error e = validate_selector(selector.base)) return e;
  if (selector.sources == 0 ||
      (selector.sources & ~(kSourceJmprel | kSourceRela | kSourceAndroidRela)) != 0)
    return Error::Make(ErrorCode::kInvalidArgument);
  if (selector.types == 0 || (selector.types & ~(kTypeJumpSlot | kTypeGlobDat)) != 0)
    return Error::Make(ErrorCode::kInvalidArgument);
  return Error::Ok();
}

namespace {

uint32_t source_bit(RelocationSource source) noexcept {
  switch (source) {
    case RelocationSource::kJmprel:
      return kSourceJmprel;
    case RelocationSource::kRela:
      return kSourceRela;
    case RelocationSource::kAndroidRela:
    default:
      return kSourceAndroidRela;
  }
}

uint32_t type_bit(uint32_t relocation_type) noexcept {
  if (relocation_type == kRAarch64JumpSlot) return kTypeJumpSlot;
  if (relocation_type == kRAarch64GlobDat) return kTypeGlobDat;
  return 0;
}

// A record is acceptable to hook only as JUMP_SLOT, or as GLOB_DAT with addend
// zero, symbol type STT_FUNC and an undefined (imported) symbol.
bool is_acceptable(const FunctionReloc& record) noexcept {
  if (record.entry.relocation_type == kRAarch64JumpSlot) return true;
  if (record.entry.relocation_type != kRAarch64GlobDat) return false;
  return record.addend == 0 && record.entry.symbol_type == kSttFunc && record.symbol_undefined;
}

// Does the base (name/version/hidden/index) selector match this record?
bool base_matches(const FunctionReloc& record, const FunctionImportSelector& selector) {
  const auto& entry = record.entry;
  const auto& sel = selector.base;
  if (entry.base.import.symbol != sel.symbol) return false;
  if (sel.relocation_index != ~size_t{0}) {
    if (entry.source != selector.index_source) return false;
    if (entry.base.import.relocation_index != sel.relocation_index) return false;
  }
  if (sel.version_match == VersionMatch::kUnversioned && entry.base.version.index >= 2)
    return false;
  if (sel.version_match == VersionMatch::kExact && entry.base.version.name != sel.version)
    return false;
  if (sel.dependency != nullptr && entry.base.version.dependency != sel.dependency) return false;
  if (sel.hidden == HiddenMatch::kHidden && !entry.base.version.hidden) return false;
  if (sel.hidden == HiddenMatch::kNonHidden && entry.base.version.hidden) return false;
  return true;
}

}  // namespace

Result<size_t> select_function_reloc(const RawFunctionSnapshot& scan,
                                     const FunctionImportSelector& selector) {
  if (Error e = validate_function_selector(selector)) return e;
  size_t selected = ~size_t{0};
  for (size_t i = 0; i < scan.records.size(); ++i) {
    const FunctionReloc& record = scan.records[i];
    // Only records in the opted-in sources and types are candidates.
    if ((source_bit(record.entry.source) & selector.sources) == 0) continue;
    if ((type_bit(record.entry.relocation_type) & selector.types) == 0) continue;
    if (!base_matches(record, selector)) continue;
    // A matched record that is not hookable fails the whole call: never skip it
    // and silently hook a different slot of the same name.
    if (!is_acceptable(record)) return Error::Make(ErrorCode::kUnsupportedRelocation);
    if (selected != ~size_t{0}) return Error::Make(ErrorCode::kAmbiguousSymbol);
    selected = i;
  }
  if (selected == ~size_t{0}) return Error::Make(ErrorCode::kSymbolNotFound);
  return selected;
}

}  // namespace yukiplt::detail
