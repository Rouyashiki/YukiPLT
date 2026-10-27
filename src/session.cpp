// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#include <cstring>
#include <new>
#include <stdexcept>

#include "imports.hpp"
#include "yukiplt.hpp"

#if defined(__linux__) || defined(__ANDROID__)
#include <link.h>
#include <sys/auxv.h>
#endif

namespace yukiplt {
namespace {
constexpr size_t kGroupLimit = 64;

bool same_image(const ImageView& a, const ImageView& b) noexcept {
  return a.load_bias == b.load_bias && a.phdr_table == b.phdr_table &&
         a.phdr_count == b.phdr_count && a.instance_token == b.instance_token;
}

ImportSelector exact_selector(const VersionedImport& chosen) noexcept {
  ImportSelector result;
  result.symbol = chosen.import.symbol.c_str();
  result.version_match =
      chosen.version.index >= 2 ? VersionMatch::kExact : VersionMatch::kUnversioned;
  result.version = chosen.version.index >= 2 ? chosen.version.name.c_str() : nullptr;
  result.dependency =
      chosen.version.dependency.empty() ? nullptr : chosen.version.dependency.c_str();
  result.hidden = chosen.version.hidden ? HiddenMatch::kHidden : HiddenMatch::kNonHidden;
  result.relocation_index = chosen.import.relocation_index;
  return result;
}
}  // namespace

Result<std::vector<NamedImage>> find_images(const ImageSelector& selector) {
  if (selector.match == ImageMatch::kExactPath || selector.match == ImageMatch::kBasename) {
    if (selector.name == nullptr || *selector.name == '\0' ||
        ((std::strchr(selector.name, '/') != nullptr) !=
         (selector.match == ImageMatch::kExactPath)))
      return Error::Make(ErrorCode::kInvalidArgument);
  } else if (selector.match != ImageMatch::kMainExecutable &&
             selector.match != ImageMatch::kLoadBias) {
    return Error::Make(ErrorCode::kInvalidArgument);
  }
#if defined(__linux__) || defined(__ANDROID__)
  struct Context {
    const ImageSelector& selector;
    std::vector<NamedImage> images;
    uintptr_t main_phdr;
    Error error;
  };
  try {
    Context ctx{selector, {}, getauxval(AT_PHDR), {}};
    dl_iterate_phdr(
        [](dl_phdr_info* info, size_t, void* opaque) -> int {
          auto& c = *static_cast<Context*>(opaque);
          const char* path = info->dlpi_name == nullptr ? "" : info->dlpi_name;
          bool match = false;
          switch (c.selector.match) {
            case ImageMatch::kMainExecutable:
              match = reinterpret_cast<uintptr_t>(info->dlpi_phdr) == c.main_phdr;
              break;
            case ImageMatch::kLoadBias:
              match = info->dlpi_addr == c.selector.load_bias;
              break;
            case ImageMatch::kExactPath:
              match = std::strcmp(path, c.selector.name) == 0;
              break;
            case ImageMatch::kBasename: {
              const char* slash = std::strrchr(path, '/');
              match = std::strcmp(slash ? slash + 1 : path, c.selector.name) == 0;
              break;
            }
          }
          if (!match) return 0;
          try {
            c.images.push_back(
                {{static_cast<uintptr_t>(info->dlpi_addr), info->dlpi_phdr, info->dlpi_phnum, 0},
                 path});
          } catch (const std::bad_alloc&) {
            c.error = Error::Make(ErrorCode::kOutOfMemory);
            return 1;
          } catch (const std::length_error&) {
            c.error = Error::Make(ErrorCode::kIntegerOverflow);
            return 1;
          }
          return 0;
        },
        &ctx);
    if (ctx.error) return ctx.error;
    if (ctx.images.empty()) return Error::Make(ErrorCode::kImageNotFound);
    return std::move(ctx.images);
  } catch (const std::bad_alloc&) {
    return Error::Make(ErrorCode::kOutOfMemory);
  }
#else
  return Error::Make(ErrorCode::kUnsupportedFormat);
#endif
}

Result<HookPlan> build_hook_plan(const HookTarget* targets, size_t count, size_t* failed_target) {
  if (failed_target) *failed_target = ~size_t{0};
  if (targets == nullptr || count == 0) return Error::Make(ErrorCode::kInvalidArgument);
  try {
    HookPlan plan;
    plan.targets_.reserve(count);
    for (size_t i = 0; i < count; ++i) {
      if (failed_target) *failed_target = i;
      const auto& target = targets[i];
      auto invalid = detail::validate_selector(target.import);
      if (invalid) return invalid;
      if (!target.replacement ||
          reinterpret_cast<uintptr_t>(target.out_original) % alignof(void*) != 0)
        return Error::Make(ErrorCode::kInvalidArgument);
      size_t group_size = 1;
      for (size_t j = 0; j < i; ++j) {
        if (target.out_original && target.out_original == targets[j].out_original)
          return Error::Make(ErrorCode::kInvalidArgument);
        if (same_image(target.image, targets[j].image)) ++group_size;
      }
      if (group_size > kGroupLimit) return Error::Make(ErrorCode::kInvalidArgument);
      auto found = find_import(target.image, target.import);
      if (!found) return found.error();
      for (const auto& previous : plan.targets_) {
        if (previous.selected.import.slot_address == found.value().import.slot_address)
          return Error::Make(ErrorCode::kInvalidArgument);
      }
      plan.targets_.push_back(
          {target.image, std::move(found.value()), target.replacement, target.out_original});
    }
    if (failed_target) *failed_target = ~size_t{0};
    return plan;
  } catch (const std::bad_alloc&) {
    return Error::Make(ErrorCode::kOutOfMemory);
  } catch (const std::length_error&) {
    return Error::Make(ErrorCode::kIntegerOverflow);
  }
}

Result<HookSession> prepare_session(const HookPlan& plan) {
  if (plan.targets().empty()) return Error::Make(ErrorCode::kInvalidArgument);
  try {
    HookSession session;
    session.targets_.reserve(plan.targets().size());
    for (const auto& target : plan.targets()) {
      size_t group = 0;
      for (; group < session.images_.size(); ++group) {
        if (same_image(session.images_[group].image, target.image)) break;
      }
      if (group == session.images_.size()) {
        SessionImageResult result;
        result.image = target.image;
        session.images_.push_back(std::move(result));
      }
      session.images_[group].target_indices.push_back(session.targets_.size());
      session.targets_.push_back({target, nullptr, {}, {}});
    }
    return session;
  } catch (const std::bad_alloc&) {
    return Error::Make(ErrorCode::kOutOfMemory);
  } catch (const std::length_error&) {
    return Error::Make(ErrorCode::kIntegerOverflow);
  }
}

SessionSummary HookSession::install() {
  SessionSummary summary;
  for (auto& group : images_) {
    if (group.state == SessionState::kIndeterminate ||
        group.state == SessionState::kRestoreFailed) {
      ++summary.failed;
    } else if (group.state == SessionState::kPrepared ||
               group.state == SessionState::kInstallFailed) {
      ++summary.attempted;
      SelectedHookRequest requests[kGroupLimit];
      SlotReport reports[kGroupLimit];
      size_t n = 0;
      for (size_t index : group.target_indices) {
        auto& target = targets_[index].target;
        requests[n++] = {exact_selector(target.selected), target.replacement, target.out_original};
      }
      auto result = hook_imports(group.image, requests, n, reports);
      group.install_error = result.error;
      group.handle = std::move(result.handle);
      group.state = result.ok()            ? SessionState::kInstalled
                    : group.handle.valid() ? SessionState::kIndeterminate
                                           : SessionState::kInstallFailed;
      if (result.ok())
        ++summary.succeeded;
      else
        ++summary.failed;
      for (size_t i = 0; i < n; ++i) {
        auto& target = targets_[group.target_indices[i]];
        target.install_report = reports[i];
        if (reports[i].address != 0)
          target.original = reinterpret_cast<void*>(reports[i].value_before);
      }
    }
    if (group.handle.valid()) ++summary.retained;
  }
  return summary;
}

SessionSummary HookSession::unhook() {
  SessionSummary summary;
  for (auto it = images_.rbegin(); it != images_.rend(); ++it) {
    auto& group = *it;
    if (!group.handle.valid()) continue;
    ++summary.attempted;
    SlotReport reports[kGroupLimit];
    group.restore_error = yukiplt::unhook(group.handle, reports, group.target_indices.size());
    if (!group.restore_error) {
      group.state = SessionState::kReleased;
      ++summary.succeeded;
    } else {
      group.state = group.restore_error.code == ErrorCode::kImageInvalidated
                        ? SessionState::kInvalidated
                        : SessionState::kRestoreFailed;
      ++summary.failed;
    }
    for (size_t i = 0; i < group.target_indices.size(); ++i)
      targets_[group.target_indices[i]].restore_report = reports[i];
    if (group.handle.valid()) ++summary.retained;
  }
  return summary;
}

SessionSummary HookSession::abandon() {
  SessionSummary summary;
  for (auto& group : images_) {
    if (!group.handle.valid()) continue;
    ++summary.attempted;
    group.restore_error = yukiplt::abandon(group.handle);
    if (!group.restore_error) {
      group.state = SessionState::kAbandoned;
      ++summary.succeeded;
    } else
      ++summary.failed;
    if (group.handle.valid()) ++summary.retained;
  }
  return summary;
}

}  // namespace yukiplt
