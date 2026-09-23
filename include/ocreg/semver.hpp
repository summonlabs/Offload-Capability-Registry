// Offload Capability Registry - exact semantic versions.
// Copyright 2026 Summon Software Labs.
//
// Semantic Versioning 2.0.0 is modelled in full: major/minor/patch, an optional
// dot-separated pre-release identifier, and optional build metadata.
// Precedence follows the specification exactly (build metadata is ignored for
// precedence) while identity compares every field, so two versions that differ
// only in build metadata are distinct identities with equal precedence.
#ifndef OCREG_SEMVER_HPP
#define OCREG_SEMVER_HPP

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ocreg {

inline constexpr std::size_t kMaxSemVerQualifierLength = 32;
inline constexpr std::uint32_t kMaxSemVerComponent = 1000000u;

class SemVer {
 public:
  constexpr SemVer() noexcept = default;
  constexpr SemVer(std::uint32_t major, std::uint32_t minor, std::uint32_t patch) noexcept
      : major_(major), minor_(minor), patch_(patch) {}

  // Strict SemVer 2.0.0 parse. Rejects leading zeros, empty identifiers,
  // over-long qualifiers, characters outside [0-9A-Za-z-.] and empty input.
  [[nodiscard]] static std::optional<SemVer> parse(std::string_view text) noexcept;

  [[nodiscard]] constexpr std::uint32_t major() const noexcept { return major_; }
  [[nodiscard]] constexpr std::uint32_t minor() const noexcept { return minor_; }
  [[nodiscard]] constexpr std::uint32_t patch() const noexcept { return patch_; }
  [[nodiscard]] std::string_view prerelease() const noexcept {
    return std::string_view(prerelease_.data(), prerelease_size_);
  }
  [[nodiscard]] std::string_view build() const noexcept {
    return std::string_view(build_.data(), build_size_);
  }
  [[nodiscard]] bool has_prerelease() const noexcept { return prerelease_size_ != 0; }

  [[nodiscard]] std::string str() const;

  // Full identity comparison: every field participates.
  friend bool operator==(const SemVer& a, const SemVer& b) noexcept;
  friend std::strong_ordering operator<=>(const SemVer& a, const SemVer& b) noexcept;

  // Specification precedence: build metadata does not participate.
  [[nodiscard]] std::strong_ordering precedence_compare(const SemVer& other) const noexcept;

 private:
  std::uint32_t major_ = 0;
  std::uint32_t minor_ = 0;
  std::uint32_t patch_ = 0;
  std::string prerelease_{};
  std::string build_{};
  std::uint8_t prerelease_size_ = 0;
  std::uint8_t build_size_ = 0;
};

// Half-open interval [minimum, maximum). An absent maximum means unbounded.
struct VersionRequirement {
  SemVer minimum{};
  std::optional<SemVer> maximum_exclusive{};

  [[nodiscard]] bool satisfied_by(const SemVer& candidate) const noexcept;
  [[nodiscard]] std::string str() const;
  friend bool operator==(const VersionRequirement&, const VersionRequirement&) noexcept = default;
};

}  // namespace ocreg

#endif  // OCREG_SEMVER_HPP
