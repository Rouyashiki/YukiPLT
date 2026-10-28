// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKIPLT_SYSTEM_IMAGES_HPP_
#define YUKIPLT_SYSTEM_IMAGES_HPP_

#include "yukiplt.hpp"

namespace yukiplt::detail {

/// Enumerate images matching `selector`.  Same contract as find_images().
using ImageEnumerator = Result<std::vector<NamedImage>> (*)(const ImageSelector&);

/// Validate an image filter with find_images()' rules (kInvalidArgument on a
/// bad match kind, or a missing/ill-formed name for path/basename matching).
Error validate_image_selector(const ImageSelector& selector) noexcept;

/// The system-image enumerator used by RuleSet.
ImageEnumerator active_image_enumerator() noexcept;

// For system images, match expected_path when supplied and record the live
// path for later recovery/query. Custom images ignore it. Otherwise use the
// hook_function_imports contract.
HookResult hook_function_imports_at(const ImageView& image, const char* expected_path,
                                    const FunctionHookRequest* reqs, size_t count,
                                    SlotReport* reports);

}  // namespace yukiplt::detail

#endif  // YUKIPLT_SYSTEM_IMAGES_HPP_
