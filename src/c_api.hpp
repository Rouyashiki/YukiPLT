// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKIPLT_C_API_HPP_
#define YUKIPLT_C_API_HPP_

#include <memory>

#include "common.hpp"
#include "yukiplt.h"
#include "yukiplt.hpp"

namespace yukiplt::detail::c_objects {
enum class Kind { kImages, kImports };
struct Object {
  explicit Object(Kind value) noexcept : kind(value) {}
  virtual ~Object() = default;
  const Kind kind;
};
// Per-copy table. The mutex protects only lookup/publication/removal. Leases
// keep object storage alive without holding the table lock across core calls.
// Callers still serialize access to each object, including destruction.
Result<uint64_t> publish(std::shared_ptr<Object> object);
std::shared_ptr<Object> acquire(uint64_t token, Kind kind);
Error destroy(uint64_t& token, Kind kind);
inline yukiplt_c_error converted(Error e) noexcept {
  return {static_cast<uint32_t>(e.code), e.sys_errno};
}
inline Error invalid() noexcept { return Error::Make(ErrorCode::kInvalidArgument); }
template <typename F>
yukiplt_c_error boundary(F&& call) noexcept {
  try {
    return converted(call());
  } catch (...) {
    return converted(current_exception_error());
  }
}
inline ImageView image(const yukiplt_c_image& v) noexcept {
  return {v.load_bias, static_cast<const NativeElfPhdr*>(v.program_headers), v.program_header_count,
          v.instance_token};
}
inline yukiplt_c_image image(const ImageView& v) noexcept {
  return {v.load_bias, v.phdr_table, v.phdr_count, v.instance_token};
}
inline ImportSelector selector(const yukiplt_c_selector& v) noexcept {
  return {v.symbol,     static_cast<VersionMatch>(v.version_match), v.version,
          v.dependency, static_cast<HiddenMatch>(v.hidden),         v.relocation_index};
}
inline bool valid(const yukiplt_c_selector& v) noexcept {
  return v.version_match <= YUKIPLT_C_VERSION_EXACT && v.hidden <= YUKIPLT_C_HIDDEN;
}
inline bool valid(const yukiplt_c_function_selector& v) noexcept {
  return v.struct_size == sizeof(v) && v.index_source <= YUKIPLT_C_RELOC_SOURCE_ANDROID_REL &&
         valid(v.base);
}
inline FunctionImportSelector selector(const yukiplt_c_function_selector& v) noexcept {
  return {selector(v.base), v.sources, v.types, static_cast<RelocationSource>(v.index_source)};
}
}  // namespace yukiplt::detail::c_objects

#endif  // YUKIPLT_C_API_HPP_
