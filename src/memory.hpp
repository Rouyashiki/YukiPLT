// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKIPLT_MEMORY_HPP_
#define YUKIPLT_MEMORY_HPP_

#include <cstddef>
#include <cstdint>

#include "elf.hpp"
#include "yukiplt.hpp"

namespace yukiplt::detail {

/// One virtual memory area, as reported by /proc/self/maps.
struct VmaInfo {
  uintptr_t begin = 0;
  uintptr_t end = 0;        ///< Exclusive.
  bool readable = false;    ///< 'r'
  bool writable = false;    ///< 'w'
  bool executable = false;  ///< 'x'
  bool shared = false;      ///< 's' (true) vs private 'p' (false).
};

/// Parse a single /proc/self/maps line, reading only the address range and
/// permission field.  `line` need not be NUL-terminated; `len` bounds it.
///
/// Returns false if the line does not begin with a well-formed
/// "begin-end rwxp" prefix.  This parser performs no I/O.
bool parse_maps_line(const char* line, size_t len, VmaInfo& out) noexcept;

/// Find the VMA that fully covers [addr, addr + size) by reading
/// /proc/self/maps.
///
/// Returns:
///   - the covering VmaInfo on success,
///   - kOutOfBounds if no mapping covers the whole range,
///   - kIntegerOverflow if addr + size overflows,
///   - kPermissionDenied (with errno) if /proc/self/maps cannot be read,
///   - kUnsupportedFormat on non-Linux hosts.
///
/// The returned protection is a snapshot at read time; /proc/self/maps offers
/// no atomic guarantee against a concurrent mprotect/mmap/munmap by other code.
Expected<VmaInfo, Error> probe_vma(uintptr_t addr, size_t size);

/// Get the runtime page size (cached after first call).
size_t page_size() noexcept;

/// Atomically replace a GOT slot value using CAS with page permission handling.
///
/// On success, the slot at slot_addr now contains desired_new.
///
/// Steps: validate the slot's ELF identity against `image`; query the slot
/// page's real protection and private/shared state from the live VMA; refuse a
/// shared, executable, or unreadable mapping (kPermissionDenied); temporarily
/// add write if the mapping lacks it; CAS; then restore the page to exactly the
/// protection the VMA reported.
///
/// Errors:
///   - kInvalidArgument      slot not 8-byte aligned.
///   - kOutOfBounds          slot not inside a PT_LOAD segment of `image`,
///                           or no single VMA covers it.
///   - kSlotOwnershipConflict  the slot did not hold expected_old (CAS failed).
///   - kPermissionDenied     mapping refused by policy, or mprotect failed
///                           (with errno); also returned if the write committed
///                           but the page protection could not be restored.
///
/// \param slot_addr     Runtime address of the GOT slot (must be 8-byte aligned).
/// \param expected_old  Expected current value of the slot.
/// \param desired_new   Value to write.
/// \param image         Inspected image, used only to validate ELF identity.
Expected<void, Error> patch_slot(uintptr_t slot_addr, uintptr_t expected_old, uintptr_t desired_new,
                                 const InspectedImage& image);

}  // namespace yukiplt::detail

#endif  // YUKIPLT_MEMORY_HPP_
