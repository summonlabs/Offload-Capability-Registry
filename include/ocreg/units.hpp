// Offload Capability Registry - exact physical units and scales.
// Copyright 2026 Summon Software Labs.
//
// Units are never guessed and never implicitly converted. A conversion is
// performed only when the two units share a dimension and the integer scale
// factor divides exactly; every other case is reported as an explicit unknown
// rather than a rounded value.
#ifndef OCREG_UNITS_HPP
#define OCREG_UNITS_HPP

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ocreg {

// Stable numeric unit codes. Never renumbered.
enum class UnitCode : std::uint16_t {
  None = 0,
  Count = 1,
  Bit = 2,
  Byte = 3,
  BitPerSecond = 4,
  BytePerSecond = 5,
  PacketPerSecond = 6,
  NanoSecond = 7,
  MicroSecond = 8,
  MilliSecond = 9,
  Second = 10,
  Hertz = 11,
  PartsPerMillion = 12,
  Percent = 13,
  OperationPerSecond = 14,
};

enum class UnitScale : std::uint8_t {
  Unity = 0,
  Decimal = 1,
  Binary = 2,
};

enum class Dimension : std::uint8_t {
  Dimensionless = 0,
  Count = 1,
  Data = 2,
  DataRate = 3,
  Rate = 4,
  Time = 5,
  Frequency = 6,
  Ratio = 7,
};

inline constexpr std::uint8_t kMaxUnitExponent = 6;

// A unit is a code plus a scale. A "kibibyte" is {Byte, Binary, 1};
// a "gigabit per second" is {BitPerSecond, Decimal, 3}.
struct Unit {
  UnitCode code = UnitCode::None;
  UnitScale scale = UnitScale::Unity;
  std::uint8_t exponent = 0;

  friend constexpr bool operator==(const Unit&, const Unit&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const Unit& a, const Unit& b) noexcept {
    if (a.code != b.code) return a.code < b.code ? std::strong_ordering::less
                                                 : std::strong_ordering::greater;
    if (a.scale != b.scale) return a.scale < b.scale ? std::strong_ordering::less
                                                     : std::strong_ordering::greater;
    return a.exponent <=> b.exponent;
  }
};

[[nodiscard]] constexpr Unit unity(UnitCode code) noexcept { return Unit{code, UnitScale::Unity, 0}; }

[[nodiscard]] bool unit_is_well_formed(const Unit& unit) noexcept;
[[nodiscard]] Dimension dimension_of(UnitCode code) noexcept;
[[nodiscard]] bool unit_scale_permitted(UnitCode code, UnitScale scale) noexcept;

// Exact integer factor from the unit to the dimension's base unit.
// Returns std::nullopt when the unit is malformed or the factor overflows.
[[nodiscard]] std::optional<std::uint64_t> factor_to_base(const Unit& unit) noexcept;

// Exact conversion. Returns std::nullopt when dimensions differ, units are
// malformed, or the conversion is not an exact integer mapping.
[[nodiscard]] std::optional<std::int64_t> convert_exact(std::int64_t value, const Unit& from,
                                                        const Unit& to) noexcept;

// Compares two quantities exactly. std::nullopt means "not comparable exactly",
// which callers must surface as an explicit unknown, never as a guess.
[[nodiscard]] std::optional<std::strong_ordering> compare_exact(std::int64_t lhs,
                                                                const Unit& lhs_unit,
                                                                std::int64_t rhs,
                                                                const Unit& rhs_unit) noexcept;

[[nodiscard]] std::string_view to_string(UnitCode code) noexcept;
[[nodiscard]] std::string_view to_string(UnitScale scale) noexcept;
[[nodiscard]] std::string_view to_string(Dimension dimension) noexcept;

// Canonical single-token spelling: "byte", "bit.dec3", "nanosecond",
// "byte_per_second.bin1". Round-trips through parse_unit.
[[nodiscard]] std::string unit_to_string(const Unit& unit);
[[nodiscard]] bool parse_unit(std::string_view text, Unit& out) noexcept;

[[nodiscard]] bool parse_unit_code(std::string_view text, UnitCode& out) noexcept;

}  // namespace ocreg

#endif  // OCREG_UNITS_HPP
