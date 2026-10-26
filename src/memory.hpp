// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKIPLT_MEMORY_HPP_
#define YUKIPLT_MEMORY_HPP_

#include <cstddef>
#include <cstdint>

#include "elf.hpp"
#include "yukiplt.hpp"

namespace yukiplt::detail {

/// Get the runtime page size (cached after first call).
size_t page_size() noexcept;

/// Atomically replace a GOT slot value using CAS with page permission handling.
///
/// On success, the slot at slot_addr now contains desired_new.
/// On CAS failure (the slot held a value other than expected_old),
/// returns kSlotOwnershipConflict.
///
/// The function temporarily makes the page writable if needed (deduced from
/// the image's segment info), and restores the original protection afterward.
///
/// \param slot_addr     Runtime address of the GOT slot (must be 8-byte aligned).
/// \param expected_old  Expected current value of the slot.
/// \param desired_new   Value to write.
/// \param image         Inspected image, used to deduce page protection.
Expected<void, Error> patch_slot(uintptr_t slot_addr, uintptr_t expected_old, uintptr_t desired_new,
                                 const InspectedImage& image);

}  // namespace yukiplt::detail

#endif  // YUKIPLT_MEMORY_HPP_
