// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKIPLT_HPP_
#define YUKIPLT_HPP_

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <new>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include "yukiplt.h"

/// \brief Portable ELF type definitions for YukiPLT.
///
/// On Linux/Android, <elf.h> provides these.  On other hosts (Windows, macOS)
/// portable definitions are provided for other hosts.
/// All values come from the ELF specification and AArch64 ELF ABI.

#if defined(__linux__) || defined(__ANDROID__)
#include <elf.h>
#else

#include <cstdint>

// --- Basic ELF types (64-bit) ---
using Elf64_Addr = uint64_t;
using Elf64_Off = uint64_t;
using Elf64_Half = uint16_t;
using Elf64_Word = uint32_t;
using Elf64_Sword = int32_t;
using Elf64_Xword = uint64_t;
using Elf64_Sxword = int64_t;

// --- ELF Header ---
#define EI_NIDENT 16

struct Elf64_Ehdr {
  unsigned char e_ident[EI_NIDENT];
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;
  Elf64_Off e_phoff;
  Elf64_Off e_shoff;
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
};

// --- Program Header ---
struct Elf64_Phdr {
  Elf64_Word p_type;
  Elf64_Word p_flags;
  Elf64_Off p_offset;
  Elf64_Addr p_vaddr;
  Elf64_Addr p_paddr;
  Elf64_Xword p_filesz;
  Elf64_Xword p_memsz;
  Elf64_Xword p_align;
};

// --- Dynamic Section ---
struct Elf64_Dyn {
  Elf64_Sxword d_tag;
  union {
    Elf64_Xword d_val;
    Elf64_Addr d_ptr;
  } d_un;
};

// --- Symbol Table ---
struct Elf64_Sym {
  Elf64_Word st_name;
  unsigned char st_info;
  unsigned char st_other;
  Elf64_Half st_shndx;
  Elf64_Addr st_value;
  Elf64_Xword st_size;
};

// --- Relocation (with addend) ---
struct Elf64_Rela {
  Elf64_Addr r_offset;
  Elf64_Xword r_info;
  Elf64_Sxword r_addend;
};

// --- e_ident indices ---
#define EI_MAG0 0
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4
#define EI_DATA 5
#define EI_VERSION 6

// --- e_ident values ---
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define EV_CURRENT 1

// --- e_type ---
#define ET_DYN 3

// --- e_machine ---
#define EM_AARCH64 183

// --- p_type ---
#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_GNU_RELRO 0x6474e552

// --- p_flags ---
#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

// --- d_tag ---
#define DT_NULL 0
#define DT_NEEDED 1
#define DT_PLTRELSZ 2
#define DT_PLTGOT 3
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_RELA 7
#define DT_RELASZ 8
#define DT_RELAENT 9
#define DT_STRSZ 10
#define DT_SYMENT 11
#define DT_PLTREL 20
#define DT_JMPREL 23

// GNU extensions
#define DT_GNU_HASH 0x6ffffef5
#define DT_VERSYM 0x6ffffff0
#define DT_VERDEF 0x6ffffffc
#define DT_VERDEFNUM 0x6ffffffd
#define DT_VERNEED 0x6ffffffe
#define DT_VERNEEDNUM 0x6fffffff

struct Elf64_Verneed {
  Elf64_Half vn_version;
  Elf64_Half vn_cnt;
  Elf64_Word vn_file;
  Elf64_Word vn_aux;
  Elf64_Word vn_next;
};
struct Elf64_Vernaux {
  Elf64_Word vna_hash;
  Elf64_Half vna_flags;
  Elf64_Half vna_other;
  Elf64_Word vna_name;
  Elf64_Word vna_next;
};
struct Elf64_Verdef {
  Elf64_Half vd_version;
  Elf64_Half vd_flags;
  Elf64_Half vd_ndx;
  Elf64_Half vd_cnt;
  Elf64_Word vd_hash;
  Elf64_Word vd_aux;
  Elf64_Word vd_next;
};
struct Elf64_Verdaux {
  Elf64_Word vda_name;
  Elf64_Word vda_next;
};

// --- Relocation info macros ---
#define ELF64_R_SYM(info) ((info) >> 32)
#define ELF64_R_TYPE(info) ((info) & 0xffffffffULL)
#define ELF64_R_INFO(sym, type) (((Elf64_Xword)(sym) << 32) | ((type) & 0xffffffffULL))

// --- AArch64 relocation types ---
#define R_AARCH64_GLOB_DAT 1025
#define R_AARCH64_JUMP_SLOT 1026
#define R_AARCH64_RELATIVE 1027
#define R_AARCH64_IRELATIVE 1032

// --- Symbol binding / type macros ---
#define ELF64_ST_BIND(info) ((info) >> 4)
#define ELF64_ST_TYPE(info) ((info) & 0xf)
#define ELF64_ST_INFO(bind, type) (((bind) << 4) | ((type) & 0xf))

#define STB_GLOBAL 1
#define STB_WEAK 2
#define STT_FUNC 2
#define STT_OBJECT 1

#define SHN_UNDEF 0

#endif  // __linux__ || __ANDROID__

/// \brief YukiPLT error types.

namespace yukiplt {

// Fixed C/C++ error values; new codes append without reuse. Use diagnosed
// causes and errno to distinguish failures. Retry and recovery also depend on
// handle validity; query_recovery describes Indeterminate residue.
enum class ErrorCode : uint32_t {
  kSuccess = 0,

  // --- Argument errors ---
  kInvalidArgument,
  kNullPointer,

  // --- Image / ELF errors ---
  kInvalidImage,
  kCorruptedElf,
  kUnsupportedFormat,
  kUnsupportedRelocation,

  // --- Symbol errors ---
  kSymbolNotFound,
  kNoHashTable,
  kAmbiguousSymbol,

  // --- Hook errors ---
  kSlotOwnershipConflict,
  kAlreadyHooked,
  kNotInstalled,
  kSlotModifiedExternally,
  kIndeterminate,  ///< Recovery was partial; per-slot/per-page state is reported.

  // --- System errors ---
  kPermissionDenied,
  kImageInvalidated,
  kOutOfMemory,  ///< An allocation failed; the operation did nothing.

  // --- Internal validation ---
  kIntegerOverflow,
  kOutOfBounds,

  // --- Image lookup ---
  kImageNotFound,   ///< No loaded image matches the requested name.
  kAmbiguousImage,  ///< More than one loaded image matches the requested name.

  // --- Memory map ---
  kVmaUnavailable,  ///< /proc/self/maps could not be read (errno set) or parsed.
};

/// Describes an error with a code and optional system errno.
struct [[nodiscard]] Error {
  ErrorCode code = ErrorCode::kSuccess;

  /// System errno for permission/maps failures, including kIndeterminate:
  /// first restoration errno takes precedence over a page-raise errno.
  /// Zero when no system-call error occurred (e.g. CAS/protection conflict).
  int sys_errno = 0;

  /// Returns true when no error.
  [[nodiscard]] bool ok() const noexcept { return code == ErrorCode::kSuccess; }

  /// Returns true when an error is present.
  [[nodiscard]] explicit operator bool() const noexcept { return !ok(); }

  static Error Ok() noexcept { return {}; }
  static Error Make(ErrorCode c) noexcept { return {c, 0}; }
  static Error Sys(ErrorCode c, int e) noexcept { return {c, e}; }
};

/// Stable, allocation-free name; unknown values return "Unknown".
[[nodiscard]] inline const char* error_name(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::kSuccess:
      return "Success";
    case ErrorCode::kInvalidArgument:
      return "InvalidArgument";
    case ErrorCode::kNullPointer:
      return "NullPointer";
    case ErrorCode::kInvalidImage:
      return "InvalidImage";
    case ErrorCode::kCorruptedElf:
      return "CorruptedElf";
    case ErrorCode::kUnsupportedFormat:
      return "UnsupportedFormat";
    case ErrorCode::kUnsupportedRelocation:
      return "UnsupportedRelocation";
    case ErrorCode::kSymbolNotFound:
      return "SymbolNotFound";
    case ErrorCode::kNoHashTable:
      return "NoHashTable";
    case ErrorCode::kAmbiguousSymbol:
      return "AmbiguousSymbol";
    case ErrorCode::kSlotOwnershipConflict:
      return "SlotOwnershipConflict";
    case ErrorCode::kAlreadyHooked:
      return "AlreadyHooked";
    case ErrorCode::kNotInstalled:
      return "NotInstalled";
    case ErrorCode::kSlotModifiedExternally:
      return "SlotModifiedExternally";
    case ErrorCode::kIndeterminate:
      return "Indeterminate";
    case ErrorCode::kPermissionDenied:
      return "PermissionDenied";
    case ErrorCode::kImageInvalidated:
      return "ImageInvalidated";
    case ErrorCode::kOutOfMemory:
      return "OutOfMemory";
    case ErrorCode::kIntegerOverflow:
      return "IntegerOverflow";
    case ErrorCode::kOutOfBounds:
      return "OutOfBounds";
    case ErrorCode::kImageNotFound:
      return "ImageNotFound";
    case ErrorCode::kAmbiguousImage:
      return "AmbiguousImage";
    case ErrorCode::kVmaUnavailable:
      return "VmaUnavailable";
  }
  return "Unknown";
}

}  // namespace yukiplt

/// \brief Minimal Expected<T, E> for error propagation (C++17).

namespace yukiplt::detail {

/// A discriminated union holding either a value of type T or an error of type E.
///
/// For the special case Expected<void, E>, only the error branch stores data.
template <typename T, typename E>
class [[nodiscard]] Expected {
  static_assert(!std::is_same_v<T, E>, "T and E must be different types");
  static_assert(std::is_nothrow_move_constructible_v<T> && std::is_nothrow_move_constructible_v<E>,
                "Expected requires non-throwing move construction");

 public:
  Expected(const T& val) : has_value_(true) {  // NOLINT: implicit
    new (&storage_.value) T(val);
  }
  Expected(T&& val) : has_value_(true) {  // NOLINT: implicit
    new (&storage_.value) T(std::move(val));
  }
  Expected(const E& err) : has_value_(false) {  // NOLINT: implicit
    new (&storage_.error) E(err);
  }
  Expected(E&& err) : has_value_(false) {  // NOLINT: implicit
    new (&storage_.error) E(std::move(err));
  }

  Expected(const Expected& o) : has_value_(o.has_value_) {
    if (has_value_)
      new (&storage_.value) T(o.storage_.value);
    else
      new (&storage_.error) E(o.storage_.error);
  }
  Expected(Expected&& o) noexcept : has_value_(o.has_value_) {
    if (has_value_)
      new (&storage_.value) T(std::move(o.storage_.value));
    else
      new (&storage_.error) E(std::move(o.storage_.error));
  }

  Expected& operator=(const Expected& o) {
    if (this != &o) {
      // Copy first: an owning value (e.g. ImportSnapshot) can throw while
      // copying. Destroying the old union member first would leave this
      // object claiming a value whose construction never completed.
      static_assert(
          std::is_nothrow_move_constructible_v<T> && std::is_nothrow_move_constructible_v<E>,
          "Expected copy assignment needs a non-throwing commit");
      Expected copy(o);
      *this = std::move(copy);
    }
    return *this;
  }
  Expected& operator=(Expected&& o) noexcept {
    if (this != &o) {
      destroy();
      has_value_ = o.has_value_;
      if (has_value_)
        new (&storage_.value) T(std::move(o.storage_.value));
      else
        new (&storage_.error) E(std::move(o.storage_.error));
    }
    return *this;
  }

  ~Expected() { destroy(); }

  [[nodiscard]] bool has_value() const noexcept { return has_value_; }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value_; }

  [[nodiscard]] T& value() & {
    assert(has_value_);
    return storage_.value;
  }
  [[nodiscard]] const T& value() const& {
    assert(has_value_);
    return storage_.value;
  }
  [[nodiscard]] T&& value() && {
    assert(has_value_);
    return std::move(storage_.value);
  }

  [[nodiscard]] E& error() & {
    assert(!has_value_);
    return storage_.error;
  }
  [[nodiscard]] const E& error() const& {
    assert(!has_value_);
    return storage_.error;
  }

  /// Transform the value with f, propagating errors.
  template <typename F>
  auto map(F&& f) const& -> Expected<decltype(f(std::declval<const T&>())), E> {
    using U = decltype(f(std::declval<const T&>()));
    if (has_value_) {
      if constexpr (std::is_void_v<U>) {
        f(storage_.value);
        return Expected<void, E>();
      } else {
        return Expected<U, E>(f(storage_.value));
      }
    }
    return Expected<U, E>(storage_.error);
  }

  /// Chain with a function returning Expected<U, E>, propagating errors.
  template <typename F>
  auto and_then(F&& f) const& -> decltype(f(std::declval<const T&>())) {
    if (has_value_) return f(storage_.value);
    using Ret = decltype(f(std::declval<const T&>()));
    return Ret(storage_.error);
  }

 private:
  void destroy() {
    if (has_value_)
      storage_.value.~T();
    else
      storage_.error.~E();
  }

  union Storage {
    T value;
    E error;
    Storage() {}   // NOLINT: leave uninitialized
    ~Storage() {}  // NOLINT: destroyed by Expected
  } storage_;
  bool has_value_;
};

/// Specialization for Expected<void, E>.
template <typename E>
class [[nodiscard]] Expected<void, E> {
  static_assert(std::is_nothrow_move_constructible_v<E>,
                "Expected requires non-throwing move construction");

 public:
  Expected() : has_value_(true) {}                                  // NOLINT
  Expected(const E& err) : has_value_(false), error_(err) {}        // NOLINT: implicit
  Expected(E&& err) : has_value_(false), error_(std::move(err)) {}  // NOLINT: implicit

  Expected(const Expected&) = default;
  Expected(Expected&&) noexcept = default;
  Expected& operator=(const Expected& other) {
    if (this != &other) {
      Expected copy(other);
      *this = std::move(copy);
    }
    return *this;
  }
  Expected& operator=(Expected&& other) noexcept {
    if (this != &other) {
      // Commit with the constrained constructor, not E::operator=.
      error_.~E();
      new (&error_) E(std::move(other.error_));
      has_value_ = other.has_value_;
    }
    return *this;
  }

  [[nodiscard]] bool has_value() const noexcept { return has_value_; }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value_; }

  void value() const { assert(has_value_); }

  [[nodiscard]] E& error() & {
    assert(!has_value_);
    return error_;
  }
  [[nodiscard]] const E& error() const& {
    assert(!has_value_);
    return error_;
  }

 private:
  bool has_value_;
  E error_{};
};

}  // namespace yukiplt::detail

/// \brief YukiPLT public API — PLT/GOT hooking for ARM64 ELF.
///
/// ## Quick start
///
///     void* original = nullptr;
///     auto r = yukiplt::hook(image, "target_func", (void*)replacement, &original);
///     if (r.ok()) {
///         // Hook is active.  Calls through the image's PLT now go to
///         // replacement.  Read `original` with an acquire load (see below)
///         // and cast it to the function type to call the original.
///     } else if (r.handle.valid()) {
///         // kIndeterminate: not cleanly installed; recover with
///         // unhook()/abandon().
///     }
///     // Later:
///     const auto undo = yukiplt::unhook(r.handle);
///     if (!undo.ok()) { /* retain r.handle and retry before releasing context */ }
///
/// ## Semantics
///
/// - Android runtime support starts at API 23 (Android 6.0), ARM64 only.
///   Android API 21 and 22 are not supported.
///
/// - PLT hooks only intercept calls that go through the target image's GOT.
///   Direct calls within the defining library, dlsym-obtained pointers,
///   and GLOB_DAT-obtained function pointers are NOT intercepted.
///
/// - "Original function address" means the value found in the GOT slot at
///   hook time.  It may be another hook's replacement, not the real function.
///   A replacement that calls through it must read `*out_original` with an
///   acquire load (e.g. __atomic_load_n(&p, __ATOMIC_ACQUIRE)): the install
///   publishes the pointer with release, but the PLT branch that reaches the
///   replacement is not itself an acquire.
///
/// - If a symbol name matches more than one distinct GOT slot (e.g. the same
///   name imported under several symbol versions),  do not choose: the
///   call returns kAmbiguousSymbol and modifies nothing.  Multiple relocation
///   records naming one slot mean a malformed image (kCorruptedElf).
///
/// - One slot, one owner.  A second hook of a slot this library already owns
///   returns kAlreadyHooked.  There is no hook stacking, no reference counting.
///
/// ## Batches and atomicity
///
/// - hook() installs one slot; hook_batch() installs several as one unit over
///   a single image, rolling back on any conflict so the batch leaves either
///   every slot installed or none.  A batch never spans two images.
///
/// - No cross-slot atomicity is promised: another thread may briefly see some
///   slots switched and others not.  The guarantee is on commit and failure
///   recovery, not a simultaneous switch.
///
/// ## Lifecycle
///
/// - The caller must keep the target image mapped until every handle for it is
///   released or abandoned.  For a system-linker image, every call validates
///   the image under the dynamic linker's lock (dl_iterate_phdr) and never
///   dereferences a stale pointer; a view whose image is no longer loaded
///   returns kImageInvalidated (kImageNotFound is only for name lookup that
///   finds nothing).  For a custom (e.g. YukiLinker) image, set instance_token
///   to a value unique to that load and call forget_image() before unmapping.
///   A missing page in /proc/self/maps never invalidates a custom image by
///   itself: the maps file is not an atomic snapshot.
///
/// - Same-address reload is an ABA hazard: after dlclose + dlopen at the same
///   address, CAS cannot by itself prove the slot is still the same instance.
///   The caller's lifecycle contract above is what closes that gap; this
///   library does not claim to eliminate the unload race.
///
/// - Unhook can fail and must be called explicitly; HookHandle's destructor
///   does NOT unhook.  Destroying or move-overwriting a handle that still owns
///   an installed hook logs a warning and leaves the hook in place.
///
/// - After a successful unhook a thread may still be executing the
///   replacement.  Do not unload the replacement's code until the caller has
///   established quiescence.
///
/// ## Original-pointer outputs
///
/// - Every non-null out_original must be aligned for void* and distinct within
///   one call; otherwise the call returns kInvalidArgument before taking any
///   lock or writing anything.
///
/// - The library publishes each prior slot value to its out_original after all
///   validation and page-protection raises have succeeded and before the first
///   slot CAS, so a replacement can never run before its original is readable.
///   A failure after that point (a CAS conflict that rolled back) may therefore
///   leave a candidate original in *out_original.  That value does not mean the
///   hook is installed and is never cleared.
///
/// Failure never returns "success".  A clean failure modifies nothing: no net
/// GOT change, every page protection restored and no Registry ownership left.
/// This guarantee covers neither out_original (see above) nor the transient
/// protection change made during the attempt.  See kIndeterminate for the one
/// state where recovery is partial.

namespace yukiplt {

/// Result is the public-facing result type for YukiPLT operations.
template <typename T>
using Result = detail::Expected<T, Error>;

// Borrowed native ELF view. Use the loader's exact load bias and a nonempty,
// aligned, readable PHDR table; keep custom mappings and metadata stable until
// handles are released. A readable ELF header must agree on e_phnum; an in-image
// table must match e_phoff in a readable zero-offset LOAD. External copies are
// allowed; without a readable ELF header the supplied view is trusted.
// Token 0 selects linker-validated system images; a unique nonzero token selects
// caller-managed custom loads. Mislabeling bypasses or fails system validation.
// The view carries neither a path nor a load generation.
struct ImageView {
  uintptr_t load_bias;           ///< Runtime load bias (dlpi_addr).
  const Elf64_Phdr* phdr_table;  ///< Program header table address.
  size_t phdr_count;             ///< Number of program headers.
  uint64_t instance_token = 0;   ///< 0 = system-linker image; else custom load id.
};

/// One named R_AARCH64_JUMP_SLOT record, copied from DT_JMPREL.
/// Addresses and indices are diagnostic metadata, not an installation token.
struct ImportInfo {
  std::string symbol;
  uint32_t symbol_index = 0;
  size_t relocation_index = 0;
  uintptr_t slot_address = 0;
};

/// Owning, read-only metadata snapshot. Strings survive image unloading;
/// addresses do not. The snapshot neither pins the image nor owns any slots.
struct ImportSnapshot {
  std::vector<ImportInfo> imports;  ///< In DT_JMPREL order, including duplicate names.
  size_t skipped_relocations = 0;   ///< Non-JUMP_SLOT or symbol-index-zero records.
};

// Copy owning JUMP_SLOT metadata without GOT access, permission changes or
// ownership. No GLOB_DAT/APS2 scan; use inspect_versioned_imports for versions.
// The three PLT tags must be unique and complete. Empty tables succeed; duplicate
// non-NONE destinations or malformed metadata reject the entire snapshot.
// Unsupported records are counted. This path is bounded by JMPREL size, without
// the function-scan budget. System copying stays under the linker lock; callers
// keep custom metadata stable. Allocation/size failures return errors, never exceptions.
Result<ImportSnapshot> inspect_imports(const ImageView& image);

enum class VersionSource : uint8_t { kNone, kNeeded, kDefined };

/// Version metadata declared by this image, not proof of the bound provider.
struct SymbolVersion {
  std::string name;
  std::string dependency;  ///< VERNEED's file; empty for definitions/no version.
  uint16_t index = 1;      ///< Low 15 bits of VERSYM; 0/1 have no version name.
  bool table_present = false;
  bool hidden = false;  ///< VERSYM's high bit, not ELF symbol visibility.
  VersionSource source = VersionSource::kNone;
};

struct VersionedImport {
  ImportInfo import;
  SymbolVersion version;
};

struct VersionedImportSnapshot {
  std::vector<VersionedImport> imports;
  size_t skipped_relocations = 0;
};

/// Like inspect_imports(), also validates/copies VERSYM, VERNEED and VERDEF.
/// Missing version metadata is represented explicitly, not guessed from names.
Result<VersionedImportSnapshot> inspect_versioned_imports(const ImageView& image);

enum class VersionMatch : uint8_t { kAny, kUnversioned, kExact };
enum class HiddenMatch : uint8_t { kAny, kNonHidden, kHidden };

/// All supplied filters must match ONE slot. No fallback to another version.
/// Strings are borrowed only during the API call. An empty version/dependency
/// filter is invalid; nullptr means no dependency filter. kUnversioned matches
/// absent VERSYM or indices 0/1. kAny never resolves ambiguity automatically.
struct ImportSelector {
  const char* symbol = nullptr;
  VersionMatch version_match = VersionMatch::kAny;
  const char* version = nullptr;  ///< Required only for kExact; otherwise null.
  const char* dependency = nullptr;
  HiddenMatch hidden = HiddenMatch::kAny;
  size_t relocation_index = ~size_t{0};  ///< ~0: any DT_JMPREL index.
};

/// Read-only unique selection. Result addresses remain diagnostic snapshots.
Result<VersionedImport> find_import(const ImageView& image, const ImportSelector& selector);

struct SelectedHookRequest {
  ImportSelector target;
  void* replacement = nullptr;
  void** out_original = nullptr;
};

/// What happened to one slot in a hook/unhook/query.
enum class SlotStatus : uint8_t {
  kUntouched,       ///< No write was attempted on this slot.
  kInstalled,       ///< Replacement installed (value_before holds the prior value).
  kRestored,        ///< Original value put back.
  kConflict,        ///< Slot did not hold the expected value; left as found.
  kRolledBack,      ///< Installed, then reverted after another slot conflicted.
  kRollbackFailed,  ///< Installed, but the revert failed; slot left as observed.
};

/// Per-slot report, optionally filled by hook/hook_batch/unhook/query.
struct SlotReport {
  uintptr_t address = 0;         ///< GOT slot runtime address.
  uintptr_t value_before = 0;    ///< Value in the slot before this operation.
  uintptr_t value_observed = 0;  ///< Value seen if the CAS conflicted.
  SlotStatus status = SlotStatus::kUntouched;
};

/// One slot to install in a batch.
struct HookRequest {
  const char* symbol;   ///< Symbol name to hook (must resolve to one slot).
  void* replacement;    ///< Replacement function pointer.
  void** out_original;  ///< Receives the prior slot value; written just before
                        ///< commit and never cleared once set (may be null).
};

/// Opaque handle representing a hook group (one slot or a batch).
///
/// Move-only.  Must be explicitly unhook()'d or abandon()'d before destruction.
/// Destroying or move-overwriting a handle that still owns an installed hook
/// logs a warning but does NOT unhook.
class HookHandle {
 public:
  HookHandle() noexcept : id_(kInvalid) {}
  ~HookHandle();

  HookHandle(const HookHandle&) = delete;
  HookHandle& operator=(const HookHandle&) = delete;

  HookHandle(HookHandle&& o) noexcept : id_(o.id_) { o.id_ = kInvalid; }
  HookHandle& operator=(HookHandle&& o) noexcept;

  /// Returns true if this handle refers to a live hook entry.
  [[nodiscard]] bool valid() const noexcept { return id_ != kInvalid; }

 private:
  friend class detail_api;

  explicit HookHandle(uint64_t id) noexcept : id_(id) {}
  void warn_if_installed() const noexcept;

  static constexpr uint64_t kInvalid = ~uint64_t(0);
  uint64_t id_;
};

/// Result of a hook/hook_batch: an error and, on success, an owning handle.
///
/// `error.ok()` is the single source of truth for success.  A valid handle is
/// returned on success (the hook is active) and, exceptionally, on
/// kIndeterminate — where the hook is NOT fully active but the handle must be
/// kept so the caller can recover (unhook) or relinquish (abandon) the
/// partially-applied state.  On every other error the handle is invalid.
struct [[nodiscard]] HookResult {
  Error error;
  HookHandle handle;

  /// True only on a clean install (error.ok()).  kIndeterminate is not ok(),
  /// even though it carries a valid handle.
  [[nodiscard]] bool ok() const noexcept { return error.ok(); }
};

// Linux/Android loader lookup: null/empty selects the main executable via
// AT_PHDR; a slash selects exact dlpi_name; a bare name also matches basename.
// Return a token-0 view or ImageNotFound/AmbiguousImage; never choose arbitrarily.
Result<ImageView> image_from_soname(const char* soname);

// Install one uniquely selected JUMP_SLOT with a non-null replacement.
// out_original is optional, pointer-aligned, and published before replacement
// becomes reachable. Success owns the slot; Indeterminate retains recovery
// state. Other failures leave no installed hook or ownership. Check the result
// and optional SlotReport; published originals are never cleared.
HookResult hook(const ImageView& image, const char* symbol_name, void* replacement,
                void** out_original, SlotReport* report = nullptr);

// Install 1..64 requests in one image. Targets and non-null aligned original
// outputs must be distinct; all targets must be unowned. Preflight rejects the
// whole batch. CAS conflicts roll back; failed rollback/protection restoration
// returns Indeterminate with a recovery handle. reports has count entries.
HookResult hook_batch(const ImageView& image, const HookRequest* reqs, size_t count,
                      SlotReport* reports = nullptr);

/// Exact selection with the same transaction/ownership/recovery and
/// original-pointer output contract as hook()/hook_batch(). Re-inspects
/// metadata under the lifetime lock; never accepts a raw snapshot address. A
/// batch is limited to 64 distinct slots in one image.
HookResult hook_import(const ImageView& image, const ImportSelector& selector, void* replacement,
                       void** out_original, SlotReport* report = nullptr);
HookResult hook_imports(const ImageView& image, const SelectedHookRequest* reqs, size_t count,
                        SlotReport* reports = nullptr);
// Explicit function sources/types extend the JUMP_SLOT APIs with GLOB_DAT.
// Every match must be an undefined STT_FUNC with zero effective addend; only
// GLOB_DAT also requires a nonzero current value. Any ineligible match rejects
// the whole operation. RELA uses r_addend; Android REL binding uses no addend.
// Scanned function records validate versions; legacy name-only APIs do not.
// Import STT_FUNC cannot exclude an IFUNC provider. Cached pointers remain valid
// caller responsibilities; out_original is the pre-install slot value.

/// Which relocation tables to scan (a bitmask over these bits).
enum RelocationSourceBit : uint32_t {
  kSourceJmprel = 1u << 0,       ///< DT_JMPREL (PLT relocations).
  kSourceRela = 1u << 1,         ///< DT_RELA (.rela.dyn).
  kSourceAndroidRela = 1u << 2,  ///< DT_ANDROID_RELA (APS2 packed).
};

/// Which relocation types to accept (a bitmask over these bits).
enum RelocationTypeBit : uint32_t {
  kTypeJumpSlot = 1u << 0,  ///< R_AARCH64_JUMP_SLOT.
  kTypeGlobDat = 1u << 1,   ///< R_AARCH64_GLOB_DAT (function, addend 0, UND FUNC).
};

/// The table a decoded function import came from.
enum class RelocationSource : uint8_t { kJmprel, kRela, kAndroidRela };

/// One function import, with its relocation source and type.  `base` carries the
/// name, symbol index, version metadata and slot address; `base.import`'s
/// relocation_index is the index within `source`'s own table.
struct FunctionImport {
  VersionedImport base;
  RelocationSource source = RelocationSource::kJmprel;
  uint32_t relocation_type = 0;  ///< R_AARCH64_* value as found.
  uint8_t symbol_type = 0;       ///< ELF symbol type (STT_*).
};

struct FunctionImportSnapshot {
  std::vector<FunctionImport> imports;
  /// Records in a scanned source that are neither JUMP_SLOT nor GLOB_DAT, or
  /// have symbol index 0.  A JUMP_SLOT or GLOB_DAT is listed in `imports`
  /// whichever scanned table holds it (labelled with its real source and type),
  /// so a GLOB_DAT inside DT_JMPREL is listed, not skipped.  This differs from
  /// inspect_imports(), which counts such a record as skipped.
  size_t skipped_relocations = 0;
};

/// Selector for a function import.  `sources` and `types` are bitmasks that must
/// both be non-zero — naming them is the explicit opt-in.  `index_source` scopes
/// `base.relocation_index` (when not ~0) to one table.
struct FunctionImportSelector {
  ImportSelector base;
  uint32_t sources = 0;
  uint32_t types = 0;
  RelocationSource index_source = RelocationSource::kJmprel;
};

struct FunctionHookRequest {
  FunctionImportSelector target;
  void* replacement = nullptr;
  void** out_original = nullptr;
};

// Copy owning function-import metadata from a nonzero valid source mask.
// No GOT access, permissions or ownership; optional tables are validated only
// when selected. All scanned non-NONE records participate in duplicate-slot
// checks, including skipped types. Share a 2^22-record and 64 MiB logical
// materialization budget, including indexes, copied text and temporaries;
// excess returns OutOfBounds before allocation. This is not an RSS limit.
Result<FunctionImportSnapshot> inspect_function_imports(const ImageView& image, uint32_t sources);

/// Read-only unique selection over the scanned sources/types.
Result<FunctionImport> find_function_import(const ImageView& image,
                                            const FunctionImportSelector& selector);

/// Install one / several function hooks on one image, same transaction,
/// ownership, recovery and original-pointer contract as hook_import()/
/// hook_imports().  A batch mixing JUMP_SLOT and GLOB_DAT slots on one image
/// runs as a single transaction and is limited to 64 distinct slots.
HookResult hook_function_import(const ImageView& image, const FunctionImportSelector& selector,
                                void* replacement, void** out_original,
                                SlotReport* report = nullptr);
HookResult hook_function_imports(const ImageView& image, const FunctionHookRequest* reqs,
                                 size_t count, SlotReport* reports = nullptr);

// Restore owned replacement values by CAS; already-original values are done.
// Never-written slots are Untouched with live values. Preserve third-party values
// as conflicts. Roll back this attempt if any restore CAS loses a race.
// Success and ImageInvalidated consume the handle; other failures retain it.
// Maps failure or incomplete coverage does not prove invalidation. Indeterminate
// retains failed rollback/page residue. Retry uses live maps: accept original
// protection, restore raised protection, and retain third-party protection conflicts.
// System identity includes the installation path; mismatch consumes the old handle
// without accessing the new image. Custom invalidation requires forget_image.
// reports is an optional array of cap SlotReports. Success does not prove quiescence.
Error unhook(HookHandle& handle, SlotReport* reports = nullptr, size_t cap = 0);

// Release bookkeeping and consume the handle without changing memory.
// The caller assumes responsibility for remaining replacements and page residue.
Error abandon(HookHandle& handle);

// Copy at most cap reports and return the total slot count. address/value_before
// are recorded; readable live slots report Installed and the observed value.
// Unreadable or invalidated slots report Untouched/zero, never a fabricated value.
// System reads require the recorded identity/path under the linker lock. Null out
// or zero cap requests only the count. No writes or handle consumption.
Error query(const HookHandle& handle, SlotReport* out, size_t cap, size_t* count);

// Forget a custom image by bias, PHDR identity and nonzero load token without
// modifying memory. Its handles are consumed as ImageInvalidated on unhook.
// System images are rejected. Call before unmapping the custom instance.
Error forget_image(const ImageView& custom_image);

class HookHandle;

enum class OperationStage : uint32_t {
  kNone = 0,
  kPrepare = 1,
  kExpectedCurrent = 2,
  kRaise = 3,
  kCommit = 4,
  kRollback = 5,
  kRestorePages = 6,
  kComplete = 7,
};

/// Recorded recovery state, not a live inspection of memory or permissions.
struct RecoveryDiagnostic {
  OperationStage stage = OperationStage::kNone;
  Error error;
  int raise_errno = 0;
  int restore_errno = 0;
  bool rollback_failed = false;
  bool image_invalidated = false;
  size_t residual_page_count = 0;
};

struct ResidualPage {
  uintptr_t address = 0;
  uint32_t original_protection = 0;  ///< Linux PROT_* bits, as last recorded.
  uint32_t raised_protection = 0;
  int sys_errno = 0;  ///< Last failed restoration; 0 may mean a protection conflict.
};

/// Copies the last operation and residual pages under the Registry lock only.
/// Never reads an image, GOT or maps. diagnostic is required; pages may be null
/// for count-only (capacity must then be zero). At most capacity pages are
/// copied; diagnostic.residual_page_count always gives the total. Outputs are
/// unchanged on failure. A consumed handle has no queryable history.
[[nodiscard]] Error query_recovery(const HookHandle& handle, RecoveryDiagnostic* diagnostic,
                                   ResidualPage* pages = nullptr, size_t capacity = 0);

enum class ImageMatch : uint8_t { kMainExecutable, kExactPath, kBasename, kLoadBias };
struct ImageSelector {
  ImageMatch match = ImageMatch::kMainExecutable;
  const char* name = nullptr;
  uintptr_t load_bias = 0;
};
struct NamedImage {
  ImageView image;
  std::string path;
};

/// Explicit matching of publicly enumerable system images, never implicit
/// match-all. Empty matches return kImageNotFound. Paths are owned; ImageViews
/// are not pinned. No promise of visibility into every linker namespace.
Result<std::vector<NamedImage>> find_images(const ImageSelector& selector);

struct HookTarget {
  ImageView image;
  ImportSelector import;
  void* replacement = nullptr;
  void** out_original = nullptr;
};
struct PlannedTarget {
  ImageView image;
  VersionedImport selected;
  void* replacement = nullptr;
  void** out_original = nullptr;
};

class HookSession;
class HookPlan {
 public:
  const std::vector<PlannedTarget>& targets() const noexcept { return targets_; }

 private:
  friend Result<HookPlan> build_hook_plan(const HookTarget*, size_t, size_t*);
  std::vector<PlannedTarget> targets_;
};

/// Resolve every target without writing GOT, outputs, permissions or Registry.
/// Failure reports the first target index (~0 for an error not tied to one).
/// Strings are copied. Same-slot targets and shared non-null outputs fail.
/// At most 64 targets per identical ImageView; no cross-image atomicity.
/// Caller keeps images, headers, replacements and output storage alive through
/// installation/recovery; planning does not pin images or freeze GOT values.
Result<HookPlan> build_hook_plan(const HookTarget* targets, size_t count,
                                 size_t* failed_target = nullptr);

enum class SessionState : uint8_t {
  kPrepared,
  kInstalled,
  kInstallFailed,
  kIndeterminate,
  kRestoreFailed,
  kReleased,
  kInvalidated,
  kAbandoned,
};
struct SessionTargetResult {
  PlannedTarget target;
  /// Prior slot value reported by the last install attempt, not a lifetime
  /// guarantee.  After a failed attempt it may be a candidate original even
  /// though nothing is installed; check the group's state.
  void* original = nullptr;
  SlotReport install_report;
  SlotReport restore_report;
};
struct SessionImageResult {
  ImageView image;
  std::vector<size_t> target_indices;
  HookHandle handle;
  SessionState state = SessionState::kPrepared;
  Error install_error;
  Error restore_error;
};
struct [[nodiscard]] SessionSummary {
  size_t attempted = 0;
  size_t succeeded = 0;
  size_t failed = 0;
  size_t retained = 0;  ///< Groups still holding ownership/recovery handles.
  bool ok() const noexcept { return failed == 0; }
};

/// Caller serializes all operations AND result access on one session. Storage
/// is allocated before any install. Destruction/move-overwrite does not unhook;
/// live handles retain the core's warning behavior. Explicit unhook or abandon
/// is required. Original outputs are caller-owned and distinct for each target.
class HookSession {
 public:
  HookSession() = default;
  HookSession(const HookSession&) = delete;
  HookSession& operator=(const HookSession&) = delete;
  HookSession(HookSession&&) noexcept = default;
  HookSession& operator=(HookSession&&) noexcept = default;

  const std::vector<SessionTargetResult>& targets() const noexcept { return targets_; }
  const std::vector<SessionImageResult>& images() const noexcept { return images_; }

  /// One transaction per image in first-appearance order. Continue after group
  /// errors; no rollback across images. Retry only Prepared/InstallFailed.
  /// A remaining Indeterminate/RestoreFailed group counts as failed and is
  /// never overwritten: explicitly unhook/abandon it first.
  SessionSummary install();
  /// Reverse image order, attempt every valid handle despite earlier errors.
  /// Failed handles remain retryable; invalidated images consume their handle.
  SessionSummary unhook();
  /// Drop all remaining ownership without touching slots or page protections.
  SessionSummary abandon();

 private:
  friend Result<HookSession> prepare_session(const HookPlan&);
  std::vector<SessionTargetResult> targets_;
  std::vector<SessionImageResult> images_;
};

/// Copy a validated plan and preallocate every report/group before any write.
/// Failure never leaves a partial session or any installed hook.
Result<HookSession> prepare_session(const HookPlan& plan);

// Explicit rule refresh; no background tracking. Each (rule, image instance)
// owns one single-slot group. Serialize all operations and result reads per
// RuleSet; different RuleSets share the core Registry/op lock. No user callback
// runs under internal locks. bindings() references expire at the next mutation.

/// State of one (rule, image instance) binding.
enum class RuleState : uint8_t {
  kPending,        ///< Matched but not yet installed (e.g. a prior conflict/OOM).
  kInstalled,      ///< Installed and owned.
  kInstallFailed,  ///< A clean install failure (conflict, capacity, OOM); retryable.
  kIndeterminate,  ///< Partial install; handle retained, must unhook/abandon.
  kReleased,       ///< Cleanly unhooked (by remove_rule/release_image/unhook).
  kInvalidated,    ///< Image no longer loaded; handle consumed by the core.
  kRestoreFailed,  ///< Unhook failed; handle retained, retryable.
  kAbandoned,      ///< Ownership relinquished without touching memory.
};

/// One (rule, image instance) binding and its last result.  A read-only view;
/// valid until the next mutation of the owning RuleSet.
struct RuleBinding {
  uint64_t rule_id = 0;
  ImageView image{};          ///< Instance identity (bias/phdr/phnum/token).
  std::string path;           ///< Diagnostic, from the image enumerator.
  size_t original_index = 0;  ///< Slot in the rule's out_originals array.
  RuleState state = RuleState::kPending;
  Error error;
  SlotReport install_report;
  SlotReport restore_report;
};

/// Summary of a RuleSet operation, same shape as SessionSummary.
struct [[nodiscard]] RuleSummary {
  size_t attempted = 0;
  size_t succeeded = 0;
  size_t failed = 0;
  size_t retained = 0;  ///< Live handles among this operation's targets, including skipped ones.
  [[nodiscard]] bool ok() const noexcept { return failed == 0; }
};

enum class RuleOperationStage : uint32_t {
  kValidate,
  kEnumerate,
  kBindingPrepare,
  kCapacity,
  kInstall,
  kRestore,
  kAbandon
};
struct RuleOperationEvent {
  uint64_t rule_id = 0;
  ImageView image{};
  std::string path;
  RuleOperationStage stage = RuleOperationStage::kValidate;
  Error error;
  bool attempted = false;
  RuleState state = RuleState::kPending;
  size_t binding_index = ~size_t{0};
  RecoveryDiagnostic recovery;
};
/// Caller-owned results. Preparation errors precede every side effect; events
/// own their text and are not references into the RuleSet. An ImageView remains
/// an identity, not a lifetime guarantee. kImageNotFound enumeration is normal.
struct RuleOperationReport {
  Error preparation_error;
  std::vector<RuleOperationEvent> events;
};
struct RuleStatistics {
  uint64_t rule_id = 0;
  bool removed = false;
  bool original_storage_enabled = false;
  size_t original_capacity = 0;
  size_t original_used = 0;
  size_t original_remaining = 0;
  size_t bindings = 0;
  size_t active_handles = 0;
};
struct RuleSetStatistics {
  size_t registered_rules = 0;
  size_t active_rules = 0;
  size_t bindings = 0;
  size_t active_handles = 0;
};

/// Move-only, like HookSession.  Destruction/move-overwrite does NOT unhook;
/// live handles retain the core's warning behavior.  The caller must explicitly
/// unhook() or abandon() before destruction.
class RuleSet {
 public:
  RuleSet() = default;
  ~RuleSet();
  RuleSet(const RuleSet&) = delete;
  RuleSet& operator=(const RuleSet&) = delete;
  RuleSet(RuleSet&&) noexcept = default;
  RuleSet& operator=(RuleSet&&) noexcept = default;

  // Copy the selector and return a nonzero rule id. Caller-owned original slots
  // must be aligned, stable and disjoint; published slots are never cleared or reused.
  // Capacity zero disables original output. Exhaustion fails before writes and is
  // terminal for that binding; remove and re-register with larger storage to recover.
  // A null/empty symbol returns NullPointer/InvalidArgument.
  Result<uint64_t> add_rule(const ImageSelector& filter, const FunctionImportSelector& selector,
                            void* replacement, void** out_originals, size_t capacity);

  /// Convenience overload for a plain JUMP_SLOT name/version selector.
  Result<uint64_t> add_rule(const ImageSelector& filter, const ImportSelector& selector,
                            void* replacement, void** out_originals, size_t capacity);

  // Prepare all enumeration caches/reports before any install; preparation failure
  // returns failed=1, attempted=retained=0. Use the report overload for its error.
  // Then install one slot per (rule, instance), allowing partial success. Clean
  // failures retry with the same original slot; released/invalidated bindings take
  // a fresh slot. Indeterminate, restore-failed, abandoned and exhausted bindings
  // are not reinstalled. Retained system bindings revalidate path/identity/value
  // under linker -> op locks; mismatch preserves ownership and reports failure.
  // Reuse one maps read per verified image, discard it before later installations.
  // Only core-confirmed invalidation ends ownership; callers prevent reload ABA.
  // retained counts unique targets enumerated this call, including skipped live
  // bindings. statistics().active_handles counts the entire outstanding population.
  RuleSummary refresh();

  /// Undo this RuleSet's hooks on one image instance before the caller unloads
  /// it.  Failure keeps the handle and ownership and is reported.  This does not
  /// disable the rules: a later refresh()/notify_loaded() that still finds the
  /// instance applies them again (see refresh()); remove_rule() stops a rule.
  RuleSummary release_image(const ImageView& image);

  // Custom-loader notifications run synchronously after relocation/final
  // protections and before unmapping, respectively. Keep the instance stable,
  // serialize RuleSet access, and hold no loader lock or dl_iterate_phdr callback.
  // path supplies diagnostics and matching. Token-0 system images are rejected.
  RuleSummary notify_loaded(const ImageView& image, const char* path);
  RuleSummary notify_unloading(const ImageView& image);

  /// Remove a rule: undo all its bindings (reverse order), keep failures, and
  /// stop it participating in future refreshes.
  RuleSummary remove_rule(uint64_t rule_id);

  /// Undo all of this RuleSet's hooks (reverse order), keeping failures.  The
  /// rules stay registered; a later refresh() applies them again.
  RuleSummary unhook();

  /// Relinquish all registrations without touching memory.  Abandoned bindings
  /// are never re-applied by refresh()/notify_loaded().
  RuleSummary abandon();

  /// Detailed overloads reserve all report storage before any hook/unhook.
  /// A preparation failure returns failed=1, attempted=0 and preserves hooks.
  RuleSummary refresh(RuleOperationReport& report);
  RuleSummary notify_loaded(const ImageView& image, const char* path, RuleOperationReport& report);
  RuleSummary notify_unloading(const ImageView& image, RuleOperationReport& report);
  RuleSummary release_image(const ImageView& image, RuleOperationReport& report);
  RuleSummary remove_rule(uint64_t rule_id, RuleOperationReport& report);
  RuleSummary unhook(RuleOperationReport& report);
  RuleSummary abandon(RuleOperationReport& report);
  [[nodiscard]] RuleSetStatistics statistics() const noexcept;
  [[nodiscard]] Result<RuleStatistics> statistics(uint64_t rule_id) const noexcept;

  /// Per-(rule, image instance) results.  Valid until the next mutation.
  [[nodiscard]] const std::vector<RuleBinding>& bindings() const noexcept { return bindings_; }

 private:
  struct Rule {
    uint64_t id = 0;
    ImageSelector filter{};
    std::string filter_name;                  ///< Owns filter.name.
    FunctionImportSelector selector{};        ///< Points into the owned strings below.
    std::string symbol, version, dependency;  ///< Owned selector strings.
    void* replacement = nullptr;
    void** out_originals = nullptr;
    size_t capacity = 0;
    size_t next_slot = 0;  ///< Next free out_originals index (grow-only).
    bool removed = false;
  };

  // Internal helpers (rules.cpp).
  Rule* find_rule(uint64_t id) noexcept;
  Rule* rule_by_id(uint64_t id) noexcept;
  const Rule* rule_by_id(uint64_t id) const noexcept;
  size_t find_binding(uint64_t rule_id, const ImageView& image) const noexcept;
  static void rebind_selector(Rule& rule) noexcept;
  size_t retained_for(uint64_t rule_id = 0, const ImageView* image = nullptr,
                      bool active_only = false) const noexcept;
  // Apply one rule to one already-matched image instance, updating bindings.
  void apply_rule_to_image(Rule& rule, const ImageView& image, const char* path,
                           const char* expected_path, RuleSummary& summary,
                           RuleOperationEvent* event = nullptr);
  Error prepare_undo_report(RuleOperationReport& report, uint64_t rule_id, const ImageView* image,
                            RuleOperationStage stage) const;
  void finish_undo_report(RuleOperationReport& report) const;

  std::vector<Rule> rules_;
  std::vector<RuleBinding> bindings_;
  std::vector<HookHandle> handles_;  ///< Parallel to bindings_ (HookHandle is move-only).
  /// (rule id, image instance) -> index of that pair's current binding in
  /// bindings_, so refresh() looks it up in O(1).  A binding superseded
  /// by a re-application stays in bindings_ but leaves the index.
  struct BindingKey {
    uint64_t rule_id;
    uintptr_t load_bias;
    const void* phdr_table;
    size_t phdr_count;
    uint64_t instance_token;
    bool operator==(const BindingKey& o) const noexcept {
      return rule_id == o.rule_id && load_bias == o.load_bias && phdr_table == o.phdr_table &&
             phdr_count == o.phdr_count && instance_token == o.instance_token;
    }
  };
  struct BindingKeyHash {
    size_t operator()(const BindingKey& k) const noexcept;
  };
  static BindingKey key_of(uint64_t rule_id, const ImageView& image) noexcept {
    return {rule_id, image.load_bias, image.phdr_table, image.phdr_count, image.instance_token};
  }
  std::unordered_map<BindingKey, size_t, BindingKeyHash> binding_index_;
  uint64_t next_rule_id_ = 1;
};

/// Stable original-address storage. Keep it and all replacement code/context
/// alive until recovery AND caller-established quiescence. No implicit unhook,
/// reset or reuse. The declared Fn does not prove the ELF target's actual ABI.
template <typename Fn>
class OriginalSlot {
  static_assert(std::is_pointer_v<Fn> && std::is_function_v<std::remove_pointer_t<Fn>>,
                "OriginalSlot requires a function pointer type");

 public:
  OriginalSlot() = default;
  OriginalSlot(const OriginalSlot&) = delete;
  OriginalSlot& operator=(const OriginalSlot&) = delete;
  OriginalSlot(OriginalSlot&&) = delete;
  OriginalSlot& operator=(OriginalSlot&&) = delete;
  [[nodiscard]] Fn load() const noexcept {
    return reinterpret_cast<Fn>(__atomic_load_n(&value_, __ATOMIC_ACQUIRE));
  }
  [[nodiscard]] void** output_address() noexcept { return &value_; }
  [[nodiscard]] FunctionHookRequest request(const FunctionImportSelector& selector,
                                            Fn replacement) noexcept {
    return {selector, reinterpret_cast<void*>(replacement), &value_};
  }

 private:
  alignas(void*) void* value_ = nullptr;
};
}  // namespace yukiplt

#endif  // YUKIPLT_HPP_
