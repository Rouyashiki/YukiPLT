// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKIPLT_IMPORTS_HPP_
#define YUKIPLT_IMPORTS_HPP_

#include "elf.hpp"
#include "yukiplt.hpp"

namespace yukiplt::detail {

// Pure parsing over an inspected image whose metadata remains readable.
// May allocate; the public API catches failures before leaving the loader callback.
Result<ImportSnapshot> snapshot_imports(const InspectedImage& image);

Result<VersionedImportSnapshot> snapshot_versioned_imports(const InspectedImage& image);
Error validate_selector(const ImportSelector& selector) noexcept;
Result<size_t> select_import(const VersionedImportSnapshot& snapshot,
                             const ImportSelector& selector);
}  // namespace yukiplt::detail

#endif  // YUKIPLT_IMPORTS_HPP_
