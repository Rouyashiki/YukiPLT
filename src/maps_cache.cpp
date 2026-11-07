// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include "maps_cache.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <charconv>

#include "registry.hpp"
#if defined(__linux__) || defined(__ANDROID__)
#include <fcntl.h>
#include <unistd.h>
#endif

namespace yukiplt::detail {
std::shared_ptr<MapsCacheState> MapsCacheAccess::get(const MapsCache& cache) noexcept {
  return cache.state_;
}
Error MapsCacheState::remember_page(uintptr_t page, const VmaInfo& vma) {
  if (pages.find(page) != pages.end()) return Error::Ok();
  const size_t mapping_bytes = mappings.size() * sizeof(VmaInfo);
  const size_t page_bytes = sizeof(decltype(pages)::value_type);
  if (mapping_bytes > kMaterializedBytes ||
      pages.size() >= (kMaterializedBytes - mapping_bytes) / page_bytes)
    return Error::Make(ErrorCode::kOutOfBounds);
  pages.emplace(page, CachedPage{vma, false, false});
  return Error::Ok();
}
Error MapsCacheState::lookup(uintptr_t page, VmaInfo& out, bool baseline,
                             bool allow_unknown) const noexcept {
  if (invalid || page_size == 0) return Error::Make(ErrorCode::kInvalidArgument);
  if (!baseline) {
    auto found = pages.find(page);
    if (found != pages.end()) {
      if (found->second.invalid || (found->second.unknown && !allow_unknown))
        return Error::Make(ErrorCode::kInvalidArgument);
      out = found->second.vma;
      return Error::Ok();
    }
  }
  auto it = std::upper_bound(mappings.begin(), mappings.end(), page,
                             [](uintptr_t p, const VmaInfo& v) { return p < v.begin; });
  if (it == mappings.begin()) return Error::Make(ErrorCode::kOutOfBounds);
  --it;
  uintptr_t end;
  if (!safe_add(page, page_size, end)) return Error::Make(ErrorCode::kIntegerOverflow);
  if (end > it->end) return Error::Make(ErrorCode::kOutOfBounds);
  out = *it;
  return Error::Ok();
}
}  // namespace yukiplt::detail

namespace yukiplt {
namespace {
constexpr size_t kMapsBytes = size_t{64} * 1024 * 1024;
constexpr size_t kMapsRecords = 1u << 20;
bool parse_number(const char*& cursor, const char* end, int base, char separator) noexcept {
  uint64_t value = 0;
  auto result = std::from_chars(cursor, end, value, base);
  if (result.ec != std::errc{}) return false;
  cursor = result.ptr;
  if (cursor == end) return separator == '\0';
  if (*cursor != (separator == '\0' ? ' ' : separator)) return false;
  ++cursor;
  if (separator == ' ') {
    while (cursor != end && *cursor == ' ') ++cursor;
  }
  return true;
}
bool valid_maps_suffix(const char* cursor, const char* end) noexcept {
  if (cursor == end || *cursor != ' ') return false;
  ++cursor;
  return parse_number(cursor, end, 16, ' ') && parse_number(cursor, end, 16, ':') &&
         parse_number(cursor, end, 16, ' ') && parse_number(cursor, end, 10, '\0');
}
class SnapshotParser {
 public:
  explicit SnapshotParser(detail::MapsCacheState& result) : result_(result) {}

  Error feed(const char* text, size_t length) {
    if (!text) return Error::Make(ErrorCode::kNullPointer);
    if (length > kMapsBytes - bytes_) return Error::Make(ErrorCode::kOutOfBounds);
    bytes_ += length;
    while (length != 0) {
      size_t size = 0;
#if defined(__arm__)
      // Short-line memchr calls are costly on ARM32 Bionic.
      while (size < length && text[size] != '\n') {
        if (text[size] == '\0') return Error::Make(ErrorCode::kVmaUnavailable);
        ++size;
      }
#else
      const auto* newline = static_cast<const char*>(std::memchr(text, '\n', length));
      size = newline ? static_cast<size_t>(newline - text) : length;
      if (std::memchr(text, '\0', size)) return Error::Make(ErrorCode::kVmaUnavailable);
#endif
      if (size == length) {
        pending_.append(text, size);
        return Error::Ok();
      }
      if (pending_.empty()) {
        if (Error error = line(text, size)) return error;
      } else {
        pending_.append(text, size);
        if (Error error = line(pending_.data(), pending_.size())) return error;
        pending_.clear();
      }
      text += size + 1;
      length -= size + 1;
    }
    return Error::Ok();
  }

  Error finish() {
    if (!bytes_) return Error::Make(ErrorCode::kVmaUnavailable);
    return pending_.empty() ? Error::Ok() : line(pending_.data(), pending_.size());
  }

 private:
  Error line(const char* text, size_t length) {
    if (!result_.page_size) {
      result_.page_size = detail::page_size();
      if (!result_.page_size) return Error::Make(ErrorCode::kUnsupportedFormat);
    }
    detail::VmaInfo vma;
    size_t permission = 0;
    while (permission < length && text[permission] != ' ') ++permission;
    if (permission + 5 >= length || !valid_maps_suffix(text + permission + 5, text + length))
      return Error::Make(ErrorCode::kVmaUnavailable);
    if (!detail::parse_maps_line(text, length, vma) || vma.begin < previous_ ||
        ((vma.begin | vma.end) & (result_.page_size - 1)) != 0)
      return Error::Make(ErrorCode::kVmaUnavailable);
    if (result_.mappings.size() >= kMapsRecords ||
        result_.mappings.size() >= kMapsBytes / sizeof(detail::VmaInfo))
      return Error::Make(ErrorCode::kOutOfBounds);
    result_.mappings.push_back(vma);
    previous_ = vma.end;
    return Error::Ok();
  }

  detail::MapsCacheState& result_;
  std::string pending_;
  size_t bytes_ = 0;
  uintptr_t previous_ = 0;
};
}  // namespace
static Error replace_snapshot(std::shared_ptr<detail::MapsCacheState>& state_,
                              std::shared_ptr<detail::MapsCacheState> next) {
  if (Error e = detail::process_entry()) return e;
  try {
    if (Error e = detail::Registry::instance().prepare_cache_update(state_.get(), *next)) return e;
    if (state_) {
      // Existing handles retain this stable state object. Swap only after validation.
      for (const auto& entry : state_->pages) {
        detail::VmaInfo vma;
        if (!next->lookup(entry.first, vma)) {
          if (Error e = next->remember_page(entry.first, vma)) return e;
        }
      }
      state_->mappings.swap(next->mappings);
      state_->pages.swap(next->pages);
      state_->page_size = next->page_size;
      state_->invalid = false;
    } else {
      state_ = std::move(next);
    }
    return Error::Ok();
  } catch (...) {
    return detail::current_exception_error();
  }
}
Error MapsCache::import_text(const char* text, size_t length) {
  yukiplt::detail::OperationGuard admission;
  if (admission.error()) return admission.error();

  if (Error e = detail::process_entry()) return e;
  try {
    std::lock_guard<std::mutex> lock(detail::op_mutex());
    auto next = std::make_shared<detail::MapsCacheState>();
    SnapshotParser parser(*next);
    if (Error error = parser.feed(text, length)) return error;
    if (Error error = parser.finish()) return error;
    return replace_snapshot(state_, std::move(next));
  } catch (...) {
    return detail::current_exception_error();
  }
}
Error MapsCache::capture() {
  yukiplt::detail::OperationGuard admission;
  if (admission.error()) return admission.error();

  if (Error e = detail::process_entry()) return e;
#if defined(__linux__) || defined(__ANDROID__)
  try {
    std::lock_guard<std::mutex> lock(detail::op_mutex());
    // The host's stability window includes capture and publication.
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return Error::Sys(ErrorCode::kVmaUnavailable, errno);
    struct Close {
      int fd;
      ~Close() { close(fd); }
    } close_fd{fd};
    auto next = std::make_shared<detail::MapsCacheState>();
    SnapshotParser parser(*next);
    char buffer[8192];
    for (;;) {
      ssize_t count = read(fd, buffer, sizeof(buffer));
      if (count < 0) {
        if (errno == EINTR) continue;
        return Error::Sys(ErrorCode::kVmaUnavailable, errno);
      }
      if (count == 0) break;
      if (Error error = parser.feed(buffer, static_cast<size_t>(count))) return error;
    }
    if (Error error = parser.finish()) return error;
    return replace_snapshot(state_, std::move(next));
  } catch (...) {
    return detail::current_exception_error();
  }
#else
  return Error::Make(ErrorCode::kUnsupportedFormat);
#endif
}
Error MapsCache::invalidate() {
  yukiplt::detail::OperationGuard admission;
  if (admission.error()) return admission.error();

  if (Error e = detail::process_entry()) return e;
  try {
    std::lock_guard<std::mutex> lock(detail::op_mutex());
    if (state_) state_->invalid = true;
    return Error::Ok();
  } catch (...) {
    return detail::current_exception_error();
  }
}
bool MapsCache::has_bindings() const noexcept {
  yukiplt::detail::OperationGuard admission;
  if (admission.error()) return true;

  if (detail::process_entry()) return true;
  try {
    std::lock_guard<std::mutex> lock(detail::op_mutex());
    return state_ && detail::Registry::instance().cache_bound(state_.get());
  } catch (...) {
    return true;
  }
}
}  // namespace yukiplt
