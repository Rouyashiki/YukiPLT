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
struct Error {
  ErrorCode code = ErrorCode::kSuccess;

  /// System errno, meaningful only for kPermissionDenied and kVmaUnavailable.
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
///     auto r = yukiplt::hook(image, "target_func", (void*)replacement, &original);
///     if (r.ok()) {
///         // Hook is active.  Calls through the image's PLT now go to
///         // replacement.  Read `original` with an acquire load (see below)
///         // and cast it to the function type to call the original.
///     } else if (r.handle.valid()) {
///         // kIndeterminate: not active, but recover with unhook()/abandon().
///     }
///     // Later:
///     yukiplt::unhook(r.handle);
///
/// ## Semantics
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
///   released or abandoned.  For a system-linker image, hook/unhook validate
///   the image under the dynamic linker's lock (dl_iterate_phdr) and never
///   dereference a stale pointer; if the image is gone, the call returns
///   kImageInvalidated.  For a custom (e.g. YukiLinker) image, set
///   instance_token to a value unique to that load and call forget_image()
///   before unmapping.
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
/// Failure never returns "success".  On any failure before commit, nothing is
/// modified.  See kIndeterminate for the one state where recovery is partial.

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
struct HookResult {
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

}  // namespace yukiplt

#endif  // YUKIPLT_HPP_
