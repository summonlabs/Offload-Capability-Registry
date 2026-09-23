// Offload Capability Registry - exact physical units and scales.
// Copyright 2026 Summon Software Labs.
#include "ocreg/units.hpp"

#include <limits>
#include <string>
#include <vector>

#include "ocreg/checked.hpp"

#if defined(_MSC_VER) && defined(_M_X64)
#include <intrin.h>
#endif

namespace ocreg {
namespace {

struct U128 {
  std::uint64_t hi = 0;
  std::uint64_t lo = 0;
};

[[nodiscard]] U128 mul_u64(std::uint64_t a, std::uint64_t b) noexcept {
  U128 result;
#if defined(_MSC_VER) && defined(_M_X64)
  result.lo = _umul128(a, b, &result.hi);
#elif defined(__SIZEOF_INT128__)
  const unsigned __int128 product = static_cast<unsigned __int128>(a) * b;
  result.lo = static_cast<std::uint64_t>(product);
  result.hi = static_cast<std::uint64_t>(product >> 64);
#else
  const std::uint64_t a_lo = a & 0xFFFFFFFFull;
  const std::uint64_t a_hi = a >> 32;
  const std::uint64_t b_lo = b & 0xFFFFFFFFull;
  const std::uint64_t b_hi = b >> 32;
  const std::uint64_t p0 = a_lo * b_lo;
  const std::uint64_t p1 = a_lo * b_hi;
  const std::uint64_t p2 = a_hi * b_lo;
  const std::uint64_t p3 = a_hi * b_hi;
  const std::uint64_t carry = ((p0 >> 32) + (p1 & 0xFFFFFFFFull) + (p2 & 0xFFFFFFFFull)) >> 32;
  result.lo = p0 + (p1 << 32) + (p2 << 32);
  result.hi = p3 + (p1 >> 32) + (p2 >> 32) + carry;
#endif
  return result;
}

// Exact 128-by-64 division. Returns false when the quotient does not fit in 64
// bits or the division is not exact.
[[nodiscard]] bool div_u128_exact(U128 value, std::uint64_t divisor, std::uint64_t& quotient) noexcept {
  if (divisor == 0) return false;
#if defined(_MSC_VER) && defined(_M_X64)
  if (value.hi >= divisor) return false;
  std::uint64_t remainder = 0;
  const std::uint64_t result = _udiv128(value.hi, value.lo, divisor, &remainder);
  if (remainder != 0) return false;
  quotient = result;
  return true;
#else
  // Portable restoring long division. Correct for any input; used only when a
  // 128-bit primitive is unavailable. A quotient that does not fit in 64 bits
  // is refused rather than truncated.
  if (value.hi >= divisor) return false;
  std::uint64_t remainder = 0;
  std::uint64_t result = 0;
  for (int bit = 127; bit >= 0; --bit) {
    const std::uint64_t next_bit =
        bit >= 64 ? ((value.hi >> (bit - 64)) & 1ull) : ((value.lo >> bit) & 1ull);
    const bool carry = (remainder >> 63) != 0;
    remainder = (remainder << 1) | next_bit;
    if (carry || remainder >= divisor) {
      remainder -= divisor;
      if (bit >= 64) return false;
      result |= (1ull << bit);
    }
  }
  if (remainder != 0) return false;
  quotient = result;
  return true;
#endif
}

struct UnitCodeInfo {
  UnitCode code;
  std::string_view name;
  Dimension dimension;
  std::uint64_t base_factor;
  bool decimal_scale;
  bool binary_scale;
};

constexpr UnitCodeInfo kUnitCodes[] = {
    {UnitCode::None, "none", Dimension::Dimensionless, 1, false, false},
    {UnitCode::Count, "count", Dimension::Count, 1, false, false},
    {UnitCode::Bit, "bit", Dimension::Data, 1, true, true},
    {UnitCode::Byte, "byte", Dimension::Data, 8, true, true},
    {UnitCode::BitPerSecond, "bit_per_second", Dimension::DataRate, 1, true, true},
    {UnitCode::BytePerSecond, "byte_per_second", Dimension::DataRate, 8, true, true},
    {UnitCode::PacketPerSecond, "packet_per_second", Dimension::Rate, 1, true, true},
    {UnitCode::OperationPerSecond, "operation_per_second", Dimension::Rate, 1, true, false},
    {UnitCode::NanoSecond, "nanosecond", Dimension::Time, 1, true, false},
    {UnitCode::MicroSecond, "microsecond", Dimension::Time, 1000ull, true, false},
    {UnitCode::MilliSecond, "millisecond", Dimension::Time, 1000000ull, true, false},
    {UnitCode::Second, "second", Dimension::Time, 1000000000ull, true, false},
    {UnitCode::Hertz, "hertz", Dimension::Frequency, 1, true, false},
    {UnitCode::PartsPerMillion, "parts_per_million", Dimension::Ratio, 1, false, false},
    {UnitCode::Percent, "percent", Dimension::Ratio, 10000ull, false, false},
};

[[nodiscard]] const UnitCodeInfo* find_code(UnitCode code) noexcept {
  for (const auto& info : kUnitCodes) {
    if (info.code == code) return &info;
  }
  return nullptr;
}

[[nodiscard]] std::optional<std::uint64_t> scale_multiplier(UnitScale scale,
                                                            std::uint8_t exponent) noexcept {
  std::uint64_t result = 1;
  const std::uint64_t base = scale == UnitScale::Decimal ? 10ull : 1024ull;
  for (std::uint8_t i = 0; i < exponent; ++i) {
    std::uint64_t next = 0;
    if (!checked_mul<std::uint64_t>(result, base, next)) return std::nullopt;
    result = next;
  }
  return result;
}

}  // namespace

bool unit_is_well_formed(const Unit& unit) noexcept {
  const UnitCodeInfo* info = find_code(unit.code);
  if (info == nullptr) return false;
  if (unit.exponent > kMaxUnitExponent) return false;
  if (unit.scale == UnitScale::Unity) return unit.exponent == 0;
  if (unit.scale == UnitScale::Decimal) return info->decimal_scale;
  if (unit.scale == UnitScale::Binary) return info->binary_scale;
  return false;
}

Dimension dimension_of(UnitCode code) noexcept {
  const UnitCodeInfo* info = find_code(code);
  return info == nullptr ? Dimension::Dimensionless : info->dimension;
}

bool unit_scale_permitted(UnitCode code, UnitScale scale) noexcept {
  const UnitCodeInfo* info = find_code(code);
  if (info == nullptr) return false;
  switch (scale) {
    case UnitScale::Unity: return true;
    case UnitScale::Decimal: return info->decimal_scale;
    case UnitScale::Binary: return info->binary_scale;
  }
  return false;
}

std::optional<std::uint64_t> factor_to_base(const Unit& unit) noexcept {
  if (!unit_is_well_formed(unit)) return std::nullopt;
  const UnitCodeInfo* info = find_code(unit.code);
  if (info == nullptr) return std::nullopt;
  const auto multiplier = scale_multiplier(unit.scale, unit.exponent);
  if (!multiplier.has_value()) return std::nullopt;
  std::uint64_t result = 0;
  if (!checked_mul<std::uint64_t>(info->base_factor, *multiplier, result)) return std::nullopt;
  return result;
}

std::optional<std::int64_t> convert_exact(std::int64_t value, const Unit& from,
                                          const Unit& to) noexcept {
  if (!unit_is_well_formed(from) || !unit_is_well_formed(to)) return std::nullopt;
  if (dimension_of(from.code) != dimension_of(to.code)) return std::nullopt;
  const auto from_factor = factor_to_base(from);
  const auto to_factor = factor_to_base(to);
  if (!from_factor.has_value() || !to_factor.has_value()) return std::nullopt;

  const bool negative = value < 0;
  const std::uint64_t magnitude =
      negative ? static_cast<std::uint64_t>(-(value + 1)) + 1ull : static_cast<std::uint64_t>(value);

  const U128 product = mul_u64(magnitude, *from_factor);
  std::uint64_t quotient = 0;
  if (!div_u128_exact(product, *to_factor, quotient)) return std::nullopt;
  if (quotient > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
    if (!(negative && quotient == static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1ull)) {
      return std::nullopt;
    }
    return std::numeric_limits<std::int64_t>::min();
  }
  const auto signed_quotient = static_cast<std::int64_t>(quotient);
  return negative ? -signed_quotient : signed_quotient;
}

std::optional<std::strong_ordering> compare_exact(std::int64_t lhs, const Unit& lhs_unit,
                                                  std::int64_t rhs, const Unit& rhs_unit) noexcept {
  if (lhs_unit == rhs_unit) return lhs <=> rhs;
  const auto lhs_in_rhs = convert_exact(lhs, lhs_unit, rhs_unit);
  if (lhs_in_rhs.has_value()) return *lhs_in_rhs <=> rhs;
  const auto rhs_in_lhs = convert_exact(rhs, rhs_unit, lhs_unit);
  if (rhs_in_lhs.has_value()) return lhs <=> *rhs_in_lhs;
  return std::nullopt;
}

std::string_view to_string(UnitCode code) noexcept {
  const UnitCodeInfo* info = find_code(code);
  return info == nullptr ? std::string_view("none") : info->name;
}

std::string_view to_string(UnitScale scale) noexcept {
  switch (scale) {
    case UnitScale::Unity: return "unity";
    case UnitScale::Decimal: return "dec";
    case UnitScale::Binary: return "bin";
  }
  return "unity";
}

std::string_view to_string(Dimension dimension) noexcept {
  switch (dimension) {
    case Dimension::Dimensionless: return "dimensionless";
    case Dimension::Count: return "count";
    case Dimension::Data: return "data";
    case Dimension::DataRate: return "data_rate";
    case Dimension::Rate: return "rate";
    case Dimension::Time: return "time";
    case Dimension::Frequency: return "frequency";
    case Dimension::Ratio: return "ratio";
  }
  return "dimensionless";
}

std::string unit_to_string(const Unit& unit) {
  std::string out(to_string(unit.code));
  if (unit.scale != UnitScale::Unity) {
    out.push_back('.');
    out += std::string(to_string(unit.scale));
    out += std::to_string(static_cast<unsigned>(unit.exponent));
  }
  return out;
}

bool parse_unit_code(std::string_view text, UnitCode& out) noexcept {
  for (const auto& info : kUnitCodes) {
    if (info.name == text) {
      out = info.code;
      return true;
    }
  }
  return false;
}

bool parse_unit(std::string_view text, Unit& out) noexcept {
  if (text.empty() || text.size() > 48) return false;
  const std::size_t dot = text.find('.');
  const std::string_view code_text = dot == std::string_view::npos ? text : text.substr(0, dot);
  UnitCode code{};
  if (!parse_unit_code(code_text, code)) return false;

  UnitScale scale = UnitScale::Unity;
  std::uint8_t exponent = 0;
  if (dot != std::string_view::npos) {
    const std::string_view rest = text.substr(dot + 1);
    if (rest.size() < 4) return false;
    const std::string_view scale_text = rest.substr(0, 3);
    if (scale_text == "dec") {
      scale = UnitScale::Decimal;
    } else if (scale_text == "bin") {
      scale = UnitScale::Binary;
    } else {
      return false;
    }
    const std::string_view exponent_text = rest.substr(3);
    if (exponent_text.empty() || exponent_text.size() > 2) return false;
    unsigned parsed = 0;
    for (const char c : exponent_text) {
      if (c < '0' || c > '9') return false;
      parsed = parsed * 10u + static_cast<unsigned>(c - '0');
    }
    if (parsed > kMaxUnitExponent) return false;
    exponent = static_cast<std::uint8_t>(parsed);
  }

  Unit candidate{code, scale, exponent};
  if (!unit_is_well_formed(candidate)) return false;
  out = candidate;
  return true;
}

}  // namespace ocreg
