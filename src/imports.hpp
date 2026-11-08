// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKIPLT_IMPORTS_HPP_
#define YUKIPLT_IMPORTS_HPP_

#include <vector>

#include "common.hpp"
#include "elf.hpp"
#include "yukiplt.hpp"

namespace yukiplt::detail {

// Fixed request metadata, separate from decoded-record materialization.
struct SelectedRequests {
  const char* names[64]{};
  size_t heads[128]{};
  size_t next[64]{};
  size_t selected[64]{};
  ErrorCode errors[64]{};

  static size_t hash(std::string_view name) noexcept {
    size_t value = 2166136261u;
    for (unsigned char c : name) value = (value ^ c) * 16777619u;
    return value & 127;
  }
  template <typename Name>
  void prepare(size_t count, Name name) noexcept {
    for (size_t i = 0; i < count; ++i) {
      names[i] = name(i);
      selected[i] = ~size_t{0};
      size_t bucket = hash(names[i]);
      while (heads[bucket] && std::strcmp(names[heads[bucket] - 1], names[i]) != 0)
        bucket = (bucket + 1) & 127;
      next[i] = heads[bucket];
      heads[bucket] = i + 1;
    }
  }
  template <typename Match>
  void visit(std::string_view name, Match match) {
    size_t bucket = hash(name);
    while (heads[bucket]) {
      if (name == names[heads[bucket] - 1]) {
        for (size_t link = heads[bucket]; link; link = next[link - 1]) match(link - 1);
        return;
      }
      bucket = (bucket + 1) & 127;
    }
  }
  void choose(size_t request, size_t record, bool acceptable = true) noexcept {
    if (!acceptable || errors[request] == ErrorCode::kUnsupportedRelocation) {
      errors[request] = ErrorCode::kUnsupportedRelocation;
      return;
    }
    if (selected[request] != ~size_t{0}) errors[request] = ErrorCode::kAmbiguousSymbol;
    selected[request] = record;
  }
  Result<size_t> result(size_t request) const {
    if (errors[request] != ErrorCode::kSuccess) return Error::Make(errors[request]);
    if (selected[request] == ~size_t{0}) return Error::Make(ErrorCode::kSymbolNotFound);
    return selected[request];
  }
};

// Pure parsing over an inspected image whose metadata remains readable.
// May allocate; the public API catches failures before leaving the loader callback.
struct ImportView {
  std::string_view symbol;
  uint32_t symbol_index;
  size_t relocation_index;
  uintptr_t slot_address;
};
struct SymbolVersionView {
  std::string_view name;
  std::string_view dependency;
  uint16_t index = 1;
  bool table_present = false;
  bool hidden = false;
  VersionSource source = VersionSource::kNone;
};
struct VersionedImportView {
  ImportView import;
  SymbolVersionView version;
};
struct VersionedScanView {
  std::vector<VersionedImportView> imports;
  size_t skipped_relocations = 0;
};
struct FunctionImportView {
  VersionedImportView base;
  RelocationSource source = RelocationSource::kJmprel;
  uint32_t relocation_type = 0;
  uint8_t symbol_type = 0;
};
struct FunctionRelocView {
  FunctionImportView entry;
  int64_t addend = 0;
  bool symbol_undefined = false;
};
struct FunctionScanView {
  std::vector<FunctionRelocView> records;
  size_t skipped_relocations = 0;
};
VersionedImport own_import(const VersionedImportView&);
FunctionImport own_import(const FunctionImportView&);
Result<VersionedScanView> scan_versioned_views(const InspectedImage&, CauseContext* = nullptr);
Result<FunctionScanView> scan_function_views(const InspectedImage&, uint32_t,
                                             ScanBudget* = nullptr);
bool import_matches(const VersionedImportView&, const ImportSelector&) noexcept;
Result<size_t> select_import(const VersionedScanView&, const ImportSelector&);
bool function_reloc_acceptable(const FunctionRelocView&) noexcept;
bool function_reloc_matches(const FunctionRelocView&, const FunctionImportSelector&) noexcept;
Result<size_t> select_function_reloc(const FunctionScanView&, const FunctionImportSelector&);

// Selection and owning copies finish before the inspection window closes.
Result<std::vector<Result<VersionedImport>>> inspect_selected_imports(const ImageView&,
                                                                      const ImportSelector*,
                                                                      size_t);
Result<std::vector<Result<FunctionImport>>> inspect_selected_functions(
    const ImageView&, uint32_t, const FunctionImportSelector*, size_t);
// Views expire when the caller's image stability window ends. The visitor
// cannot stop validation of later records or the final duplicate-slot check.
Error walk_imports(const InspectedImage&, void (*visit)(void*, const ImportView&), void*,
                   size_t& skipped);
Result<ImportSnapshot> snapshot_imports(const InspectedImage& image);

// Upper bound on the dynamic symbol table index, derived from a hash table or,
// for an empty GNU hash, the readable LOAD holding dynsym.  Shared with the
// function-import path.
Result<size_t> dynamic_symbol_count(const InspectedImage& image);

Result<VersionedImportSnapshot> snapshot_versioned_imports(const InspectedImage& image,
                                                           CauseContext* cause = nullptr);
// Attach version metadata to a caller-provided import set (shared by the
// JUMP_SLOT and function-import paths).
Result<VersionedImportSnapshot> resolve_versions(const InspectedImage& image,
                                                 std::vector<ImportInfo> imports,
                                                 size_t skipped_relocations,
                                                 ScanBudget* budget = nullptr);
Error validate_selector(const ImportSelector& selector) noexcept;
bool import_matches(const VersionedImport&, const ImportSelector&) noexcept;
Result<size_t> select_import(const VersionedImportSnapshot& snapshot,
                             const ImportSelector& selector);

/// Internal per-record form carrying the acceptance inputs the public
/// FunctionImport does not expose (addend and whether the symbol is undefined).
struct FunctionReloc {
  FunctionImport entry;
  int64_t addend = 0;
  bool symbol_undefined = false;
};

/// All scanned function relocations with full acceptance metadata, in scan
/// order (JMPREL, then RELA, then APS2).  skipped_relocations counts records in
/// a scanned source that are neither JUMP_SLOT nor GLOB_DAT, or have symbol
/// index 0.  Duplicate slot addresses across any scanned source fail.
struct RawFunctionSnapshot {
  std::vector<FunctionReloc> records;
  size_t skipped_relocations = 0;
};

// Owning acceptance metadata acquired through the normal lifetime-protected
// inspection path. No GOT read and no retained image pointer is dereferenced.
Result<RawFunctionSnapshot> inspect_function_relocs(const ImageView&, uint32_t sources,
                                                    ScanBudget* budget = nullptr,
                                                    const char* expected_path = nullptr);
bool function_reloc_acceptable(const FunctionReloc&) noexcept;
bool function_reloc_matches(const FunctionReloc&, const FunctionImportSelector&) noexcept;

// `sources` is a non-zero subset of RelocationSourceBit.  Validates RELA/APS2
// metadata lazily (inspect() never fails on it).
Result<RawFunctionSnapshot> scan_function_imports(const InspectedImage& image, uint32_t sources,
                                                  ScanBudget* budget = nullptr);

// Build the public, owning snapshot from a scan.
Result<FunctionImportSnapshot> snapshot_function_imports(const InspectedImage& image,
                                                         uint32_t sources);

// Validate a function selector (base selector rules plus non-zero masks).
Error validate_function_selector(const FunctionImportSelector& selector) noexcept;

// Select one eligible record from the requested sources/types. Any matched
// non-function, defined symbol or nonzero addend rejects the whole selection.
Result<size_t> select_function_reloc(const RawFunctionSnapshot& scan,
                                     const FunctionImportSelector& selector);

// Adapters debit their temporary metadata before entering the same scanner.
Result<std::vector<FunctionCandidate>> expand_candidates_budgeted(const NamedImage*, size_t,
                                                                  const CandidateSelection&,
                                                                  ScanBudget&,
                                                                  OperationDiagnostic*);
}  // namespace yukiplt::detail

#endif  // YUKIPLT_IMPORTS_HPP_
