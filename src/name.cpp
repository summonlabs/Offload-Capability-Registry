// Offload Capability Registry - canonical bounded name tokens.
// Copyright 2026 Summon Software Labs.
#include "ocreg/name.hpp"

namespace ocreg {
namespace {

[[nodiscard]] constexpr bool is_lower_alnum(char c) noexcept {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

[[nodiscard]] constexpr bool is_continuation(char c) noexcept {
  return is_lower_alnum(c) || c == '.' || c == '_' || c == '-';
}

}  // namespace

std::optional<Name> Name::parse(std::string_view text) noexcept {
  if (text.empty() || text.size() > kMaxNameLength) return std::nullopt;
  if (!is_lower_alnum(text.front())) return std::nullopt;
  for (const char c : text) {
    if (!is_continuation(c)) return std::nullopt;
  }
  // A trailing separator would make two spellings of one identity possible.
  if (text.back() == '.' || text.back() == '_' || text.back() == '-') return std::nullopt;
  // No doubled separators: keeps the token unambiguous in listings.
  for (std::size_t i = 1; i < text.size(); ++i) {
    const char prev = text[i - 1];
    const char cur = text[i];
    if ((prev == '.' || prev == '_' || prev == '-') &&
        (cur == '.' || cur == '_' || cur == '-')) {
      return std::nullopt;
    }
  }

  Name result;
  for (std::size_t i = 0; i < text.size(); ++i) {
    result.chars_[i] = text[i];
  }
  result.size_ = static_cast<std::uint8_t>(text.size());
  return result;
}

}  // namespace ocreg
