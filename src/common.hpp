// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rouyashiki <https://rouyashiki.org>

#ifndef YUKIPLT_COMMON_HPP_
#define YUKIPLT_COMMON_HPP_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <type_traits>
#include <utility>

#include "yukiplt.hpp"

namespace yukiplt::detail {

/// Unsigned addition with overflow detection.
/// Returns false on overflow; result is undefined on overflow.
inline bool safe_add(uintptr_t a, uintptr_t b, uintptr_t& result) noexcept {
  result = a + b;
  return result >= a;
}

inline bool safe_add64(uint64_t a, uint64_t b, uint64_t& result) noexcept {
  result = a + b;
  return result >= a;
}

// Inline process state without exit-time destruction; late handles and threads
// must not access a destroyed Registry or operation mutex.
template <typename T>
class NoDestructor {
 public:
  template <typename... Args>
  explicit NoDestructor(Args&&... args) {
    new (storage_) T(std::forward<Args>(args)...);
  }

  NoDestructor(const NoDestructor&) = delete;
  NoDestructor& operator=(const NoDestructor&) = delete;

  [[nodiscard]] T& get() noexcept { return *std::launder(reinterpret_cast<T*>(storage_)); }

 private:
  alignas(T) unsigned char storage_[sizeof(T)];
};

/// Fixed-capacity inline storage with heap overflow.
///
/// Stores up to N elements on the stack.  When the count exceeds N, all
/// elements are moved to a heap allocation that doubles in capacity.
template <typename T, size_t N = 8>
class SmallVec {
  static_assert(std::is_trivially_destructible_v<T> || std::is_nothrow_destructible_v<T>,
                "T must be trivially or nothrow destructible");

 public:
  SmallVec() noexcept = default;

  ~SmallVec() {
    clear();
    if (heap_) ::operator delete(heap_);
  }

  SmallVec(const SmallVec& o) {
    reserve(o.size_);
    for (size_t i = 0; i < o.size_; ++i) new (ptr() + i) T(o[i]);
    size_ = o.size_;
  }

  SmallVec(SmallVec&& o) noexcept {
    if (o.on_heap()) {
      heap_ = o.heap_;
      capacity_ = o.capacity_;
      size_ = o.size_;
      o.heap_ = nullptr;
      o.capacity_ = 0;
      o.size_ = 0;
    } else {
      for (size_t i = 0; i < o.size_; ++i) new (inline_ptr() + i) T(std::move(o.inline_ptr()[i]));
      size_ = o.size_;
      o.clear();
    }
  }

  SmallVec& operator=(const SmallVec& o) {
    if (this != &o) {
      clear();
      reserve(o.size_);
      for (size_t i = 0; i < o.size_; ++i) new (ptr() + i) T(o[i]);
      size_ = o.size_;
    }
    return *this;
  }

  SmallVec& operator=(SmallVec&& o) noexcept {
    if (this != &o) {
      clear();
      if (heap_) {
        ::operator delete(heap_);
        heap_ = nullptr;
      }
      if (o.on_heap()) {
        heap_ = o.heap_;
        capacity_ = o.capacity_;
        size_ = o.size_;
        o.heap_ = nullptr;
        o.capacity_ = 0;
        o.size_ = 0;
      } else {
        capacity_ = 0;
        for (size_t i = 0; i < o.size_; ++i) new (inline_ptr() + i) T(std::move(o.inline_ptr()[i]));
        size_ = o.size_;
        o.clear();
      }
    }
    return *this;
  }

  void push_back(const T& val) {
    ensure_capacity(size_ + 1);
    new (ptr() + size_) T(val);
    ++size_;
  }

  void push_back(T&& val) {
    ensure_capacity(size_ + 1);
    new (ptr() + size_) T(std::move(val));
    ++size_;
  }

  template <typename... Args>
  T& emplace_back(Args&&... args) {
    ensure_capacity(size_ + 1);
    T* p = new (ptr() + size_) T(std::forward<Args>(args)...);
    ++size_;
    return *p;
  }

  void clear() noexcept {
    if constexpr (!std::is_trivially_destructible_v<T>) {
      for (size_t i = 0; i < size_; ++i) ptr()[i].~T();
    }
    size_ = 0;
  }

  /// Remove the last element.  Undefined if empty.
  void pop_back() noexcept {
    --size_;
    if constexpr (!std::is_trivially_destructible_v<T>) ptr()[size_].~T();
  }

  void reserve(size_t new_cap) {
    if (new_cap <= capacity()) return;
    grow(new_cap);
  }

  [[nodiscard]] T& operator[](size_t i) noexcept { return ptr()[i]; }
  [[nodiscard]] const T& operator[](size_t i) const noexcept { return ptr()[i]; }

  [[nodiscard]] T* begin() noexcept { return ptr(); }
  [[nodiscard]] T* end() noexcept { return ptr() + size_; }
  [[nodiscard]] const T* begin() const noexcept { return ptr(); }
  [[nodiscard]] const T* end() const noexcept { return ptr() + size_; }
  [[nodiscard]] const T* data() const noexcept { return ptr(); }

  [[nodiscard]] size_t size() const noexcept { return size_; }
  [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
  [[nodiscard]] size_t capacity() const noexcept { return on_heap() ? capacity_ : N; }

 private:
  [[nodiscard]] bool on_heap() const noexcept { return heap_ != nullptr; }

  [[nodiscard]] T* inline_ptr() noexcept { return reinterpret_cast<T*>(&inline_storage_); }
  [[nodiscard]] const T* inline_ptr() const noexcept {
    return reinterpret_cast<const T*>(&inline_storage_);
  }

  [[nodiscard]] T* ptr() noexcept { return on_heap() ? heap_ : inline_ptr(); }
  [[nodiscard]] const T* ptr() const noexcept { return on_heap() ? heap_ : inline_ptr(); }

  void ensure_capacity(size_t needed) {
    if (needed <= capacity()) return;
    size_t new_cap = capacity() * 2;
    if (new_cap < needed) new_cap = needed;
    grow(new_cap);
  }

  void grow(size_t new_cap) {
    T* new_buf = static_cast<T*>(::operator new(new_cap * sizeof(T)));
    T* old = ptr();
    for (size_t i = 0; i < size_; ++i) {
      new (new_buf + i) T(std::move(old[i]));
      old[i].~T();
    }
    if (heap_) ::operator delete(heap_);
    heap_ = new_buf;
    capacity_ = new_cap;
  }

  // Inline storage: aligned for T, room for N elements.
  typename std::aligned_storage<sizeof(T) * N, alignof(T)>::type inline_storage_{};
  T* heap_ = nullptr;
  size_t capacity_ = 0;
  size_t size_ = 0;
};

/// Non-owning, bounds-checked view over a contiguous byte range.
///
/// All read operations return Expected — out-of-bounds access never causes UB.
/// The viewed memory must remain valid for the lifetime of the Span.
class Span {
 public:
  Span() noexcept : data_(nullptr), size_(0) {}
  Span(const uint8_t* data, size_t size) noexcept : data_(data), size_(size) {}

  [[nodiscard]] const uint8_t* data() const noexcept { return data_; }
  [[nodiscard]] size_t size() const noexcept { return size_; }
  [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

  /// Returns a sub-span, or an error if the range exceeds bounds.
  [[nodiscard]] Expected<Span, Error> subspan(size_t offset, size_t count) const noexcept {
    if (offset > size_) return Error::Make(ErrorCode::kOutOfBounds);
    if (count > size_ - offset) return Error::Make(ErrorCode::kOutOfBounds);
    return Span(data_ + offset, count);
  }

  /// Read a single value of type U at the given byte offset.
  /// U must be trivially copyable.  Uses memcpy to avoid alignment UB.
  template <typename U>
  [[nodiscard]] Expected<U, Error> read_at(size_t byte_offset) const noexcept {
    static_assert(std::is_trivially_copyable_v<U>, "U must be trivially copyable");
    if (byte_offset > size_ || sizeof(U) > size_ - byte_offset)
      return Error::Make(ErrorCode::kOutOfBounds);
    U val;
    std::memcpy(&val, data_ + byte_offset, sizeof(U));
    return val;
  }

  /// Check whether [byte_offset, byte_offset + byte_count) fits within the span.
  [[nodiscard]] bool contains(size_t byte_offset, size_t byte_count) const noexcept {
    return byte_offset <= size_ && byte_count <= size_ - byte_offset;
  }

  /// Read a raw byte, or error if out of bounds.
  [[nodiscard]] Expected<uint8_t, Error> at(size_t index) const noexcept {
    if (index >= size_) return Error::Make(ErrorCode::kOutOfBounds);
    return data_[index];
  }

 private:
  const uint8_t* data_;
  size_t size_;
};

}  // namespace yukiplt::detail

#endif  // YUKIPLT_COMMON_HPP_
