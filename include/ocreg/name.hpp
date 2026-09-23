// Offload Capability Registry - canonical bounded name tokens.
// Copyright 2026 Summon Software Labs.
#ifndef OCREG_NAME_HPP
#define OCREG_NAME_HPP

#include <array>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ocreg {

// Maximum length of any registry name token, in bytes.
inline constexpr std::size_t kMaxNameLength = 48;

// A validated, fixed-capacity ASCII token.
//
// Grammar: [a-z0-9] ( [a-z0-9] | '.' | '_' | '-' )*
// Upper case is rejected rather than folded so that two spellings can never
// silently denote the same identity.
class Name {
 public:
  constexpr Name() noexcept = default;

  // Returns std::nullopt when the text violates the grammar or length bound.
  [[nodiscard]] static std::optional<Name> parse(std::string_view text) noexcept;

  [[nodiscard]] constexpr std::string_view view() const noexcept {
    return std::string_view(chars_.data(), size_);
  }
  [[nodiscard]] constexpr bool empty() const noexcept { return size_ == 0; }
  [[nodiscard]] std::string str() const { return std::string(view()); }

  friend constexpr bool operator==(const Name& a, const Name& b) noexcept {
    if (a.size_ != b.size_) return false;
    for (std::size_t i = 0; i < a.size_; ++i) {
      if (a.chars_[i] != b.chars_[i]) return false;
    }
    return true;
  }
  friend constexpr std::strong_ordering operator<=>(const Name& a, const Name& b) noexcept {
    const std::size_t n = a.size_ < b.size_ ? a.size_ : b.size_;
    for (std::size_t i = 0; i < n; ++i) {
      if (a.chars_[i] != b.chars_[i]) {
        return a.chars_[i] < b.chars_[i] ? std::strong_ordering::less
                                         : std::strong_ordering::greater;
      }
    }
    return a.size_ <=> b.size_;
  }

 private:
  std::array<char, kMaxNameLength> chars_{};
  std::uint8_t size_ = 0;
};

// Distinct name-typed identities. Each tag yields an incompatible type.
template <class Tag>
class NameId {
 public:
  constexpr NameId() noexcept = default;
  constexpr explicit NameId(Name name) noexcept : name_(name) {}

  [[nodiscard]] static std::optional<NameId> parse(std::string_view text) noexcept {
    const auto parsed = Name::parse(text);
    if (!parsed.has_value()) return std::nullopt;
    return NameId(*parsed);
  }

  [[nodiscard]] constexpr const Name& name() const noexcept { return name_; }
  [[nodiscard]] constexpr std::string_view view() const noexcept { return name_.view(); }
  [[nodiscard]] constexpr bool empty() const noexcept { return name_.empty(); }

  friend constexpr bool operator==(const NameId&, const NameId&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const NameId& a, const NameId& b) noexcept {
    return a.name_ <=> b.name_;
  }

 private:
  Name name_{};
};

struct ProviderIdTag;
using ProviderId = NameId<ProviderIdTag>;

struct DeviceModelIdTag;
using DeviceModelId = NameId<DeviceModelIdTag>;

struct DeviceSerialIdTag;
using DeviceSerialId = NameId<DeviceSerialIdTag>;

struct SourceIdTag;
using SourceId = NameId<SourceIdTag>;

struct PolicyIdTag;
using PolicyId = NameId<PolicyIdTag>;

}  // namespace ocreg

#endif  // OCREG_NAME_HPP
