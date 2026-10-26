// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "memory.hpp"

#include <cerrno>

#if defined(__linux__) || defined(__ANDROID__)
#include <fcntl.h>
#include <unistd.h>
#endif

#include <atomic>
#include <mutex>

#include "common.hpp"

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/auxv.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace yukiplt::detail {

namespace {

/// Parse a lowercase hex run starting at s[i] (bounded by len) into `out`.
/// Advances i.  Returns false if no hex digit is present or the value would
/// overflow uintptr_t.
bool parse_hex(const char* s, size_t len, size_t& i, uintptr_t& out) noexcept {
  if (i >= len) return false;
  uintptr_t value = 0;
  size_t digits = 0;
  for (; i < len; ++i) {
    char c = s[i];
    unsigned d;
    if (c >= '0' && c <= '9') {
      d = static_cast<unsigned>(c - '0');
    } else if (c >= 'a' && c <= 'f') {
      d = static_cast<unsigned>(c - 'a' + 10);
    } else {
      break;
    }
    // value = value * 16 + d, with overflow check.
    if (value > (~uintptr_t(0) >> 4)) return false;
    value <<= 4;
    value |= d;
    ++digits;
  }
  if (digits == 0) return false;
  out = value;
  return true;
}

}  // namespace

bool parse_maps_line(const char* line, size_t len, VmaInfo& out) noexcept {
  // Expected prefix: "<begin>-<end> <perms> ..." e.g.
  //   7f8a1c00000-7f8a1c01000 r--p 00000000 00:00 0  [stack]
  size_t i = 0;
  VmaInfo info;

  if (!parse_hex(line, len, i, info.begin)) return false;
  if (i >= len || line[i] != '-') return false;
  ++i;  // skip '-'
  if (!parse_hex(line, len, i, info.end)) return false;
  if (i >= len || line[i] != ' ') return false;
  ++i;  // skip ' '

  // Permission field is exactly four characters: r/w/x/- then p/s.
  if (i + 4 > len) return false;
  char r = line[i + 0];
  char w = line[i + 1];
  char x = line[i + 2];
  char p = line[i + 3];
  if (r != 'r' && r != '-') return false;
  if (w != 'w' && w != '-') return false;
  if (x != 'x' && x != '-') return false;
  if (p != 'p' && p != 's') return false;

  if (info.end <= info.begin) return false;

  info.readable = (r == 'r');
  info.writable = (w == 'w');
  info.executable = (x == 'x');
  info.shared = (p == 's');
  out = info;
  return true;
}

#if defined(__linux__) || defined(__ANDROID__)

Expected<VmaInfo, Error> probe_vma(uintptr_t addr, size_t size) {
  if (size == 0) return Error::Make(ErrorCode::kInvalidArgument);
  uintptr_t range_end;
  if (!safe_add(addr, static_cast<uintptr_t>(size), range_end))
    return Error::Make(ErrorCode::kIntegerOverflow);

  int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return Error::Sys(ErrorCode::kPermissionDenied, errno);

  // A process can have thousands of mappings; read in chunks and scan each
  // completed line.  We keep a rolling buffer so a line split across reads is
  // reassembled.
  constexpr size_t kChunk = 8192;
  char buf[kChunk + 1];
  char line[1024];
  size_t line_len = 0;
  bool found = false;
  VmaInfo result;
  int saved_errno = 0;

  for (;;) {
    ssize_t n = read(fd, buf, kChunk);
    if (n < 0) {
      if (errno == EINTR) continue;
      saved_errno = errno;
      break;
    }
    if (n == 0) break;

    for (ssize_t k = 0; k < n; ++k) {
      char c = buf[k];
      if (c == '\n') {
        VmaInfo info;
        if (parse_maps_line(line, line_len, info) && addr >= info.begin && range_end <= info.end) {
          result = info;
          found = true;
        }
        line_len = 0;
        if (found) break;
      } else if (line_len < sizeof(line)) {
        line[line_len++] = c;
      }
      // Lines longer than our buffer are permission-field-complete well before
      // 1024 bytes; extra bytes (the pathname) are simply dropped.
    }
    if (found) break;
  }

  close(fd);

  if (saved_errno != 0) return Error::Sys(ErrorCode::kPermissionDenied, saved_errno);
  if (!found) return Error::Make(ErrorCode::kOutOfBounds);
  return result;
}

#else  // non-Linux host

Expected<VmaInfo, Error> probe_vma(uintptr_t addr, size_t size) {
  (void)addr;
  (void)size;
  return Error::Make(ErrorCode::kUnsupportedFormat);
}

#endif

// Page size

size_t page_size() noexcept {
  // Relaxed atomics suffice: every thread computes the same value, so a racing
  // first call merely repeats the query.  A plain static here would be a data
  // race (undefined behaviour) between concurrent first callers.
  static std::atomic<size_t> cached{0};
  size_t ps = cached.load(std::memory_order_relaxed);
  if (ps != 0) return ps;

#if defined(__linux__) || defined(__ANDROID__)
  // Prefer getauxval — available since glibc 2.16 and bionic API 18.
  unsigned long aux = getauxval(AT_PAGESZ);
  if (aux != 0) {
    ps = static_cast<size_t>(aux);
  } else {
    long sc = sysconf(_SC_PAGESIZE);
    ps = sc > 0 ? static_cast<size_t>(sc) : 0;
  }
#else
  // Non-Linux host build: use 4096 for compilation only.
  // Patch operations are not functional on non-Linux hosts.
  ps = 4096;
#endif

  // A page size that is not a non-zero power of two would corrupt every page
  // mask computed from it.  Report 0; callers treat it as a hard failure.
  if (ps == 0 || (ps & (ps - 1)) != 0) return 0;

  cached.store(ps, std::memory_order_relaxed);
  return ps;
}

#if defined(__linux__) || defined(__ANDROID__)

namespace {

/// Serializes page-protection changes made by this library.
///
/// Page protection is process-level shared state.  If two operations each flip
/// the same page to writable and then restore it, the later restore can revoke
/// write under the earlier operation's feet and fault its CAS.  Holding this
/// mutex across the mprotect/CAS/restore window makes the whole sequence atomic
/// with respect to other YukiPLT operations.  It cannot stop a third party's
/// concurrent mprotect; that race is documented, not solved (AGENTS 5.3).
std::mutex& patch_mutex() {
  static NoDestructor<std::mutex> m;
  return m.get();
}

/// Translate VmaInfo permission bits to a POSIX PROT_* mask.
int prot_from_vma(const VmaInfo& vma) noexcept {
  int prot = 0;
  if (vma.readable) prot |= PROT_READ;
  if (vma.writable) prot |= PROT_WRITE;
  if (vma.executable) prot |= PROT_EXEC;
  return prot == 0 ? PROT_NONE : prot;
}

}  // namespace

Expected<void, Error> patch_slot(uintptr_t slot_addr, uintptr_t expected_old, uintptr_t desired_new,
                                 const InspectedImage& image) {
  // Validate alignment.
  if (slot_addr % 8 != 0) return Error::Make(ErrorCode::kInvalidArgument);

  // The slot's ELF identity must check out: it lies inside a writable (PF_W)
  // PT_LOAD segment of the image we were asked to patch.  (Page *permission*
  // comes from the live VMA below, never from this segment's PT_LOAD/RELRO
  // flags.)
  if (!image.addr_in_writable_load(slot_addr, sizeof(uintptr_t)))
    return Error::Make(ErrorCode::kOutOfBounds);

  const size_t ps = page_size();
  if (ps == 0) return Error::Make(ErrorCode::kUnsupportedFormat);
  const uintptr_t page_mask = ~(static_cast<uintptr_t>(ps) - 1);
  const uintptr_t page_base = slot_addr & page_mask;

  // Everything that touches page protection is serialized against other
  // YukiPLT operations on any page.
  std::lock_guard<std::mutex> lock(patch_mutex());

  // Query the slot's real current protection from /proc/self/maps.  The whole
  // 8-byte slot must be covered by one mapping.
  auto probe = probe_vma(slot_addr, sizeof(uintptr_t));
  if (!probe) return probe.error();
  const VmaInfo& vma = probe.value();

  // Mapping policy: only private, non-executable, readable mappings with
  // reliable permission information are accepted.
  if (vma.shared) return Error::Make(ErrorCode::kPermissionDenied);      // r/w-s rejected.
  if (vma.executable) return Error::Make(ErrorCode::kPermissionDenied);  // any x rejected.
  if (!vma.readable) return Error::Make(ErrorCode::kPermissionDenied);   // must be readable.

  const int orig_prot = prot_from_vma(vma);
  const bool needs_mprotect = !vma.writable;

  // Temporarily add write to the slot's page if the live mapping lacks it.
  if (needs_mprotect) {
    if (mprotect(reinterpret_cast<void*>(page_base), ps, orig_prot | PROT_WRITE) != 0) {
      return Error::Sys(ErrorCode::kPermissionDenied, errno);
    }
  }

  // CAS with release semantics.  The caller must have published any state the
  // replacement depends on (notably the original function pointer) before this
  // point; the release makes those writes visible to a thread that observes the
  // new slot value.
  uintptr_t old_val = expected_old;
  bool cas_ok =
      __atomic_compare_exchange_n(reinterpret_cast<uintptr_t*>(slot_addr), &old_val, desired_new,
                                  /*weak=*/false, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE);

  // Restore the page to its real original protection — the value read from the
  // live VMA, not an inference from PT_LOAD/RELRO.
  bool restore_failed = false;
  int restore_errno = 0;
  if (needs_mprotect) {
    if (mprotect(reinterpret_cast<void*>(page_base), ps, orig_prot) != 0) {
      restore_failed = true;
      restore_errno = errno;
    }
  }

  if (!cas_ok) return Error::Make(ErrorCode::kSlotOwnershipConflict);

  // The slot write committed, but we could not put the page's protection back.
  // Report it rather than claim a clean success: the page is now more permissive
  // than we found it.
  if (restore_failed) return Error::Sys(ErrorCode::kPermissionDenied, restore_errno);

  return Expected<void, Error>();  // Success
}

#else  // non-Linux host

Expected<void, Error> patch_slot(uintptr_t slot_addr, uintptr_t expected_old, uintptr_t desired_new,
                                 const InspectedImage& image) {
  if (slot_addr % 8 != 0) return Error::Make(ErrorCode::kInvalidArgument);
  if (!image.addr_in_writable_load(slot_addr, sizeof(uintptr_t)))
    return Error::Make(ErrorCode::kOutOfBounds);
  // Patch operations are not functional on non-Linux hosts.
  (void)expected_old;
  (void)desired_new;
  return Error::Make(ErrorCode::kUnsupportedFormat);
}

#endif

}  // namespace yukiplt::detail
