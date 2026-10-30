// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <cstring>
#include <limits>
#include <string_view>
#include <variant>

#include "c_api.hpp"
#include "common.hpp"

namespace {
using namespace yukiplt;
using namespace yukiplt::detail::c_objects;
using namespace yukiplt::detail::c_copy;
static_assert(YUKIPLT_C_FEATURE_OWNED_IMAGES == 10);
static_assert(YUKIPLT_C_FEATURE_IMPORT_SNAPSHOTS == 11);
static_assert(YUKIPLT_C_SNAPSHOT_IMPORTS == 0 && YUKIPLT_C_SNAPSHOT_VERSIONED == 1 &&
              YUKIPLT_C_SNAPSHOT_FUNCTIONS == 2);
static_assert(YUKIPLT_C_IMAGE_MAIN == 0 &&
              static_cast<uint32_t>(ImageMatch::kMainExecutable) == YUKIPLT_C_IMAGE_MAIN);
static_assert(YUKIPLT_C_IMAGE_PATH == 1 &&
              static_cast<uint32_t>(ImageMatch::kExactPath) == YUKIPLT_C_IMAGE_PATH);
static_assert(YUKIPLT_C_IMAGE_BASENAME == 2 &&
              static_cast<uint32_t>(ImageMatch::kBasename) == YUKIPLT_C_IMAGE_BASENAME);
static_assert(YUKIPLT_C_IMAGE_BIAS == 3 &&
              static_cast<uint32_t>(ImageMatch::kLoadBias) == YUKIPLT_C_IMAGE_BIAS);
static_assert(YUKIPLT_C_VERSION_SOURCE_NONE == 0 &&
              static_cast<uint32_t>(VersionSource::kNone) == YUKIPLT_C_VERSION_SOURCE_NONE);
static_assert(YUKIPLT_C_VERSION_SOURCE_NEEDED == 1 &&
              static_cast<uint32_t>(VersionSource::kNeeded) == YUKIPLT_C_VERSION_SOURCE_NEEDED);
static_assert(YUKIPLT_C_VERSION_SOURCE_DEFINED == 2 &&
              static_cast<uint32_t>(VersionSource::kDefined) == YUKIPLT_C_VERSION_SOURCE_DEFINED);
struct Images final : Object {
  Images() : Object(Kind::kImages) {}
  std::vector<NamedImage> values;
};
struct Imports final : Object {
  Imports() : Object(Kind::kImports) {}
  std::variant<ImportSnapshot, VersionedImportSnapshot, FunctionImportSnapshot> value;
};
template <typename T, typename H>
Error publish_to(std::shared_ptr<T> value, H* out) {
  auto token = publish(std::move(value));
  if (!token) return token.error();
  out->token = token.value();
  return Error::Ok();
}
template <typename T>
Error save(Result<T>&& result, yukiplt_c_import_snapshot* out) {
  if (!result) return result.error();
  auto snapshot = std::make_shared<Imports>();
  snapshot->value = std::move(result.value());
  return publish_to(std::move(snapshot), out);
}
Error inspect_snapshot(const ImageView& view, const NamedImage* named, uint32_t kind,
                       uint32_t sources, yukiplt_c_import_snapshot* out) {
  if (!out) return Error::Make(ErrorCode::kNullPointer);
  if (out->token) return invalid();
  if (kind > YUKIPLT_C_SNAPSHOT_FUNCTIONS || (kind != YUKIPLT_C_SNAPSHOT_FUNCTIONS && sources))
    return invalid();
  if (kind == YUKIPLT_C_SNAPSHOT_IMPORTS)
    return save(named ? inspect_imports_named(*named) : inspect_imports(view), out);
  if (kind == YUKIPLT_C_SNAPSHOT_VERSIONED)
    return save(named ? inspect_versioned_imports_named(*named) : inspect_versioned_imports(view),
                out);
  return save(named ? inspect_function_imports_named(*named, sources)
                    : inspect_function_imports(view, sources),
              out);
}
}  // namespace

extern "C" {
yukiplt_c_error yukiplt_c_find_images(const yukiplt_c_image_selector* selected,
                                      yukiplt_c_image_list* out) noexcept {
  return boundary([&]() -> Error {
    if (!selected || !out) return Error::Make(ErrorCode::kNullPointer);
    if (out->token || selected->struct_size != sizeof(*selected) ||
        selected->match > YUKIPLT_C_IMAGE_BIAS)
      return invalid();
    auto result = find_images(
        {static_cast<ImageMatch>(selected->match), selected->name, selected->load_bias});
    if (!result) return result.error();
    auto value = std::make_shared<Images>();
    value->values = std::move(result.value());
    return publish_to(std::move(value), out);
  });
}
yukiplt_c_error yukiplt_c_find_image_containing(const void* address,
                                                yukiplt_c_image_list* out) noexcept {
  return boundary([&]() -> Error {
    if (!out) return Error::Make(ErrorCode::kNullPointer);
    if (out->token) return invalid();
    auto result = find_image_containing(address);
    if (!result) return result.error();
    auto value = std::make_shared<Images>();
    value->values.push_back(std::move(result.value()));
    return publish_to(std::move(value), out);
  });
}
yukiplt_c_error yukiplt_c_image_list_destroy(yukiplt_c_image_list* value) noexcept {
  return boundary([&] {
    return value ? destroy(value->token, Kind::kImages) : Error::Make(ErrorCode::kNullPointer);
  });
}
yukiplt_c_error yukiplt_c_image_list_copy(const yukiplt_c_image_list* handle,
                                          yukiplt_c_image_record* rows, size_t capacity, char* text,
                                          size_t text_capacity, size_t* required_count,
                                          size_t* required_text) noexcept {
  return boundary([&]() -> Error {
    if (!handle) return Error::Make(ErrorCode::kNullPointer);
    auto owned = acquire(handle->token, Kind::kImages);
    if (!owned) return invalid();
    auto& values = static_cast<Images&>(*owned).values;
    size_t bytes = 0;
    for (const auto& value : values)
      if (!append_size(bytes, value.path)) return Error::Make(ErrorCode::kIntegerOverflow);
    bool sizes_only = false;
    if (auto e = buffers(values.size(), bytes, rows, capacity, text, text_capacity, required_count,
                         required_text, sizes_only))
      return e;
    if (sizes_only) return Error::Ok();
    size_t offset = 0;
    for (size_t i = 0; i < values.size(); ++i)
      rows[i] = {image(values[i].image), copy_text(values[i].path, text, offset)};
    return Error::Ok();
  });
}
yukiplt_c_error yukiplt_c_inspect_imports(const yukiplt_c_image* view, uint32_t kind,
                                          uint32_t sources,
                                          yukiplt_c_import_snapshot* out) noexcept {
  return boundary([&] {
    return view ? inspect_snapshot(image(*view), nullptr, kind, sources, out)
                : Error::Make(ErrorCode::kNullPointer);
  });
}
yukiplt_c_error yukiplt_c_inspect_imports_named(const yukiplt_c_named_image* view, uint32_t kind,
                                                uint32_t sources,
                                                yukiplt_c_import_snapshot* out) noexcept {
  return boundary([&]() -> Error {
    if (!view || !out || !view->path) return Error::Make(ErrorCode::kNullPointer);
    if (out->token || view->struct_size != sizeof(*view) || view->image.instance_token != 0)
      return invalid();
    NamedImage named{image(view->image), view->path};
    return inspect_snapshot(named.image, &named, kind, sources, out);
  });
}
yukiplt_c_error yukiplt_c_select_import(const yukiplt_c_image* view,
                                        const yukiplt_c_selector* selected,
                                        yukiplt_c_import_snapshot* out) noexcept {
  return boundary([&]() -> Error {
    if (!view || !selected || !out) return Error::Make(ErrorCode::kNullPointer);
    if (out->token || !valid(*selected)) return invalid();
    auto result = find_import(image(*view), selector(*selected));
    if (!result) return result.error();
    VersionedImportSnapshot snapshot;
    snapshot.imports.push_back(std::move(result.value()));
    return save(Result<VersionedImportSnapshot>{std::move(snapshot)}, out);
  });
}
yukiplt_c_error yukiplt_c_select_function_import(const yukiplt_c_image* view,
                                                 const yukiplt_c_function_selector* selected,
                                                 yukiplt_c_import_snapshot* out) noexcept {
  return boundary([&]() -> Error {
    if (!view || !selected || !out) return Error::Make(ErrorCode::kNullPointer);
    if (out->token || !valid(*selected)) return invalid();
    auto result = find_function_import(image(*view), selector(*selected));
    if (!result) return result.error();
    FunctionImportSnapshot snapshot;
    snapshot.imports.push_back(std::move(result.value()));
    return save(Result<FunctionImportSnapshot>{std::move(snapshot)}, out);
  });
}
yukiplt_c_error yukiplt_c_import_snapshot_destroy(yukiplt_c_import_snapshot* value) noexcept {
  return boundary([&] {
    return value ? destroy(value->token, Kind::kImports) : Error::Make(ErrorCode::kNullPointer);
  });
}
yukiplt_c_error yukiplt_c_import_snapshot_copy(const yukiplt_c_import_snapshot* handle,
                                               yukiplt_c_import_record* rows, size_t capacity,
                                               char* text, size_t text_capacity,
                                               size_t* required_count, size_t* required_text,
                                               uint32_t* kind, size_t* skipped) noexcept {
  return boundary([&]() -> Error {
    if (!handle || !kind || !skipped) return Error::Make(ErrorCode::kNullPointer);
    auto owned = acquire(handle->token, Kind::kImports);
    if (!owned) return invalid();
    auto& value = static_cast<Imports&>(*owned).value;
    return std::visit(
        [&](const auto& snapshot) -> Error {
          size_t bytes = 0;
          const auto& empty = empty_text();
          for (const auto& item : snapshot.imports) {
            auto v = record(item);
            if (!append_size(bytes, v.import.symbol) ||
                !append_size(bytes, v.version ? v.version->name : empty) ||
                !append_size(bytes, v.version ? v.version->dependency : empty))
              return Error::Make(ErrorCode::kIntegerOverflow);
          }
          bool sizes_only = false;
          if (auto e = buffers(snapshot.imports.size(), bytes, rows, capacity, text, text_capacity,
                               required_count, required_text, sizes_only))
            return e;
          if (!sizes_only) {
            size_t offset = 0, index = 0;
            for (const auto& item : snapshot.imports) {
              auto v = record(item);
              auto r = copy_import(v, text, offset);
              rows[index++] = r;
            }
          }
          *kind = static_cast<uint32_t>(value.index());
          *skipped = snapshot.skipped_relocations;
          return Error::Ok();
        },
        value);
  });
}
}  // extern "C"
