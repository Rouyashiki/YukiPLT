// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKIPLT_HPP_
#define YUKIPLT_HPP_

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <new>
#include <type_traits>
#include <utility>

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

  // --- System errors ---
  kPermissionDenied,
  kImageInvalidated,

  // --- Internal validation ---
  kIntegerOverflow,
  kOutOfBounds,

  // --- Image lookup ---
  kImageNotFound,   ///< No loaded image matches the requested name.
  kAmbiguousImage,  ///< More than one loaded image matches the requested name.
};

/// Describes an error with a code and optional system errno.
struct Error {
  ErrorCode code = ErrorCode::kSuccess;

  /// System errno, meaningful only when code == kPermissionDenied.
  int sys_errno = 0;

  /// Returns true when no error.
  [[nodiscard]] bool ok() const noexcept { return code == ErrorCode::kSuccess; }

  /// Returns true when an error is present.
  [[nodiscard]] explicit operator bool() const noexcept { return !ok(); }

  static Error Ok() noexcept { return {}; }
  static Error Make(ErrorCode c) noexcept { return {c, 0}; }
  static Error Sys(ErrorCode c, int e) noexcept { return {c, e}; }
};

}  // namespace yukiplt

/// \brief Minimal Expected<T, E> for error propagation (C++17).

namespace yukiplt::detail {

/// A discriminated union holding either a value of type T or an error of type E.
///
/// For the special case Expected<void, E>, only the error branch stores data.
template <typename T, typename E>
class Expected {
  static_assert(!std::is_same_v<T, E>, "T and E must be different types");

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
      destroy();
      has_value_ = o.has_value_;
      if (has_value_)
        new (&storage_.value) T(o.storage_.value);
      else
        new (&storage_.error) E(o.storage_.error);
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
    if (has_value_) return Expected<U, E>(f(storage_.value));
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
class Expected<void, E> {
 public:
  Expected() : has_value_(true) {}                                  // NOLINT
  Expected(const E& err) : has_value_(false), error_(err) {}        // NOLINT: implicit
  Expected(E&& err) : has_value_(false), error_(std::move(err)) {}  // NOLINT: implicit

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
///     auto handle = yukiplt::hook(image, "target_func", (void*)replacement, &original);
///     if (handle) {
///         // Hook is active.  Calls through the image's PLT now go to replacement.
///         // Cast original to the function type to call the original.
///     }
///     // Later:
///     yukiplt::unhook(std::move(handle.value()));
///
/// ## Semantics
///
/// - PLT hooks only intercept calls that go through the target image's GOT.
///   Direct calls within the defining library, dlsym-obtained pointers,
///   and GLOB_DAT-obtained function pointers are NOT intercepted.
///
/// - "Original function address" means the value found in the GOT slot at
///   hook time.  It may be another hook's replacement, not the real function.
///
/// - If the symbol name matches more than one distinct GOT slot (e.g. the same
///   name imported under several symbol versions),  does not choose: hook()
///   returns kAmbiguousSymbol and modifies nothing.  Multiple relocation
///   records naming one slot mean a malformed image (kCorruptedElf).
///
/// - Duplicate hook on the same slot returns kAlreadyHooked.
///
/// - Failure never returns "success".  If hook() fails, the slot is unmodified.
///
/// - HookHandle destructor does NOT implicitly unhook.  If a handle is
///   destroyed while Installed, a warning is logged but the hook stays.

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
};

/// Opaque handle representing an active hook.
///
/// Move-only.  Must be explicitly unhook()'d before destruction.
/// Destroying an Installed handle logs a warning but does NOT unhook.
class HookHandle {
 public:
  HookHandle() noexcept : id_(kInvalid) {}
  ~HookHandle();

  HookHandle(const HookHandle&) = delete;
  HookHandle& operator=(const HookHandle&) = delete;

  HookHandle(HookHandle&& o) noexcept : id_(o.id_) { o.id_ = kInvalid; }

  /// Move-assigning over a handle that still owns an installed hook drops that
  /// ownership; like the destructor, this logs a warning and does NOT unhook.
  HookHandle& operator=(HookHandle&& o) noexcept;

  /// Returns true if this handle refers to a valid hook entry.
  [[nodiscard]] bool valid() const noexcept { return id_ != kInvalid; }

 private:
  friend Result<HookHandle> hook(const ImageView&, const char*, void*, void**);
  friend Error unhook(HookHandle&&);

  explicit HookHandle(size_t id) noexcept : id_(id) {}

  /// Log a warning if this handle still owns an installed hook.
  void warn_if_installed() const noexcept;

  static constexpr size_t kInvalid = ~size_t(0);
  size_t id_;
};

// Linux/Android loader lookup: null/empty selects the main executable via
// AT_PHDR; a slash selects exact dlpi_name; a bare name also matches basename.
// Return a token-0 view or ImageNotFound/AmbiguousImage; never choose arbitrarily.
Result<ImageView> image_from_soname(const char* soname);

/// Install a PLT hook.
///
/// \param image        Target image (whose GOT to modify).
/// \param symbol_name  Name of the symbol to hook.
/// \param replacement  Pointer to the replacement function.
/// \param out_original On success, set to the value that was in the GOT slot
///                     before hooking (the "original" function pointer).
///                     May be another hook's replacement, not the real function.
///
/// \return A HookHandle on success, or an Error.
///
/// Returns kSymbolNotFound if no JUMP_SLOT matches, kAmbiguousSymbol if more
/// than one distinct slot matches ( does not choose), or kAlreadyHooked if
/// the slot is already hooked by this library.  On any error, nothing is
/// modified.
Result<HookHandle> hook(const ImageView& image, const char* symbol_name, void* replacement,
                        void** out_original);

/// Remove a previously installed hook.
///
/// Uses CAS to restore the original value.  Fails with kSlotModifiedExternally
/// if the slot no longer holds our replacement (someone else changed it).
///
/// On success, the handle is consumed and the slot is restored.
/// On failure, the handle remains valid and the hook is still conceptually
/// "ours" (but the slot may have been overwritten by a third party).
Error unhook(HookHandle&& handle);

}  // namespace yukiplt

#endif  // YUKIPLT_HPP_
