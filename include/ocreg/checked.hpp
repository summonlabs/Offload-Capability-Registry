// Offload Capability Registry - checked arithmetic primitives.
// Copyright 2026 Summon Software Labs.
//
// Every externally derived size, count, timestamp, counter or limit passes
// through these helpers. Overflow is a hard, reported failure; it is never
// allowed to wrap into a plausible-looking value.
#ifndef OCREG_CHECKED_HPP
#define OCREG_CHECKED_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <type_traits>

namespace ocreg {

template <class T>
[[nodiscard]] constexpr bool checked_add(T a, T b, T& out) noexcept {
  static_assert(std::is_integral_v<T>, "checked arithmetic requires an integral type");
  if constexpr (std::is_unsigned_v<T>) {
    if (a > static_cast<T>(std::numeric_limits<T>::max() - b)) return false;
    out = static_cast<T>(a + b);
    return true;
  } else {
    if (b > 0 && a > static_cast<T>(std::numeric_limits<T>::max() - b)) return false;
    if (b < 0 && a < static_cast<T>(std::numeric_limits<T>::min() - b)) return false;
    out = static_cast<T>(a + b);
    return true;
  }
}

template <class T>
[[nodiscard]] constexpr bool checked_sub(T a, T b, T& out) noexcept {
  static_assert(std::is_integral_v<T>, "checked arithmetic requires an integral type");
  if constexpr (std::is_unsigned_v<T>) {
    if (a < b) return false;
    out = static_cast<T>(a - b);
    return true;
  } else {
    if (b < 0 && a > static_cast<T>(std::numeric_limits<T>::max() + b)) return false;
    if (b > 0 && a < static_cast<T>(std::numeric_limits<T>::min() + b)) return false;
    out = static_cast<T>(a - b);
    return true;
  }
}

template <class T>
[[nodiscard]] constexpr bool checked_mul(T a, T b, T& out) noexcept {
  static_assert(std::is_integral_v<T>, "checked arithmetic requires an integral type");
  if (a == 0 || b == 0) {
    out = T{0};
    return true;
  }
  if constexpr (std::is_unsigned_v<T>) {
    if (a > static_cast<T>(std::numeric_limits<T>::max() / b)) return false;
    out = static_cast<T>(a * b);
    return true;
  } else {
    constexpr T kMax = std::numeric_limits<T>::max();
    constexpr T kMin = std::numeric_limits<T>::min();
    if (a > 0) {
      if (b > 0) {
        if (a > kMax / b) return false;
      } else {
        if (b < kMin / a) return false;
      }
    } else {
      if (b > 0) {
        if (a < kMin / b) return false;
      } else {
        if (a != 0 && b < kMax / a) return false;
      }
    }
    out = static_cast<T>(a * b);
    return true;
  }
}

// Division that refuses to divide by zero and refuses the single signed case
// whose mathematical result is not representable.
template <class T>
[[nodiscard]] constexpr bool checked_div(T a, T b, T& out) noexcept {
  static_assert(std::is_integral_v<T>, "checked arithmetic requires an integral type");
  if (b == 0) return false;
  if constexpr (std::is_signed_v<T>) {
    if (a == std::numeric_limits<T>::min() && b == T{-1}) return false;
  }
  out = static_cast<T>(a / b);
  return true;
}

// Narrowing conversion that fails rather than truncating.
template <class To, class From>
[[nodiscard]] constexpr bool checked_narrow(From value, To& out) noexcept {
  static_assert(std::is_integral_v<To> && std::is_integral_v<From>, "integral types required");
  if constexpr (std::is_signed_v<From> && std::is_unsigned_v<To>) {
    if (value < 0) return false;
  }
  using Common = std::common_type_t<To, From>;
  const auto widened = static_cast<Common>(value);
  if (widened < static_cast<Common>(std::numeric_limits<To>::min())) return false;
  if (widened > static_cast<Common>(std::numeric_limits<To>::max())) return false;
  out = static_cast<To>(value);
  return true;
}

// Smallest representable unsigned width for a bound check used by decoders.
[[nodiscard]] constexpr bool fits_u32(std::uint64_t value) noexcept {
  return value <= static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max());
}

[[nodiscard]] constexpr bool fits_size(std::uint64_t value) noexcept {
  return value <= static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max());
}

// Saturating-free bounded counter used by accounting paths.
class BoundedCounter {
 public:
  constexpr BoundedCounter() noexcept = default;
  constexpr explicit BoundedCounter(std::uint64_t limit) noexcept : limit_(limit) {}

  // Returns false when the increment would exceed the configured limit; the
  // counter is left unchanged in that case so accounting never drifts.
  constexpr bool try_add(std::uint64_t amount = 1) noexcept {
    std::uint64_t next = 0;
    if (!checked_add(value_, amount, next)) return false;
    if (next > limit_) return false;
    value_ = next;
    return true;
  }

  constexpr void reset() noexcept { value_ = 0; }

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
  [[nodiscard]] constexpr std::uint64_t limit() const noexcept { return limit_; }

 private:
  std::uint64_t value_ = 0;
  std::uint64_t limit_ = std::numeric_limits<std::uint64_t>::max();
};

}  // namespace ocreg

#endif  // OCREG_CHECKED_HPP
