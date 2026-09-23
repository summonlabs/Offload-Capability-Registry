// Offload Capability Registry - exact semantic versions.
// Copyright 2026 Summon Software Labs.
#include "ocreg/semver.hpp"

#include <cstddef>
#include <string>

namespace ocreg {
namespace {

[[nodiscard]] bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }

[[nodiscard]] bool is_alnum_dash(char c) noexcept {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-';
}

[[nodiscard]] bool is_numeric_identifier(std::string_view text) noexcept {
  if (text.empty()) return false;
  for (const char c : text) {
    if (!is_digit(c)) return false;
  }
  return true;
}

// Parses a dot-separated identifier list. Numeric identifiers may not carry
// leading zeros; every identifier must be non-empty and within the character
// set permitted by the specification.
[[nodiscard]] bool parse_identifiers(std::string_view text, bool enforce_numeric_rule) noexcept {
  if (text.empty() || text.size() > kMaxSemVerQualifierLength) return false;
  std::size_t start = 0;
  while (start <= text.size()) {
    std::size_t end = text.find('.', start);
    if (end == std::string_view::npos) end = text.size();
    const std::string_view identifier = text.substr(start, end - start);
    if (identifier.empty()) return false;
    for (const char c : identifier) {
      if (!is_alnum_dash(c)) return false;
    }
    if (enforce_numeric_rule && is_numeric_identifier(identifier) && identifier.size() > 1 &&
        identifier.front() == '0') {
      return false;
    }
    if (end == text.size()) break;
    start = end + 1;
  }
  return true;
}

[[nodiscard]] bool parse_component(std::string_view text, std::uint32_t& out) noexcept {
  if (text.empty() || text.size() > 10) return false;
  for (const char c : text) {
    if (!is_digit(c)) return false;
  }
  if (text.size() > 1 && text.front() == '0') return false;
  std::uint64_t value = 0;
  for (const char c : text) {
    value = value * 10u + static_cast<std::uint64_t>(c - '0');
    if (value > 0xFFFFFFFFull) return false;
  }
  out = static_cast<std::uint32_t>(value);
  return true;
}

// Splits the version core from optional pre-release and build metadata.
[[nodiscard]] bool split(std::string_view text, std::string_view& core, std::string_view& prerelease,
                         std::string_view& build) noexcept {
  prerelease = {};
  build = {};
  const std::size_t plus = text.find('+');
  if (plus != std::string_view::npos) {
    build = text.substr(plus + 1);
    text = text.substr(0, plus);
    if (build.empty()) return false;
    if (build.find('+') != std::string_view::npos) return false;
  }
  const std::size_t dash = text.find('-');
  if (dash != std::string_view::npos) {
    prerelease = text.substr(dash + 1);
    core = text.substr(0, dash);
    if (prerelease.empty()) return false;
  } else {
    core = text;
  }
  return true;
}

[[nodiscard]] std::strong_ordering compare_identifiers(std::string_view lhs,
                                                       std::string_view rhs) noexcept {
  std::size_t lhs_start = 0;
  std::size_t rhs_start = 0;
  while (true) {
    std::size_t lhs_end = lhs.find('.', lhs_start);
    if (lhs_end == std::string_view::npos) lhs_end = lhs.size();
    std::size_t rhs_end = rhs.find('.', rhs_start);
    if (rhs_end == std::string_view::npos) rhs_end = rhs.size();

    const bool lhs_done = lhs_start >= lhs.size();
    const bool rhs_done = rhs_start >= rhs.size();
    if (lhs_done && rhs_done) return std::strong_ordering::equal;
    if (lhs_done) return std::strong_ordering::less;
    if (rhs_done) return std::strong_ordering::greater;

    const std::string_view lhs_id = lhs.substr(lhs_start, lhs_end - lhs_start);
    const std::string_view rhs_id = rhs.substr(rhs_start, rhs_end - rhs_start);
    const bool lhs_numeric = is_numeric_identifier(lhs_id);
    const bool rhs_numeric = is_numeric_identifier(rhs_id);

    if (lhs_numeric && rhs_numeric) {
      if (lhs_id.size() != rhs_id.size()) {
        return lhs_id.size() < rhs_id.size() ? std::strong_ordering::less
                                             : std::strong_ordering::greater;
      }
      const int cmp = lhs_id.compare(rhs_id);
      if (cmp != 0) return cmp < 0 ? std::strong_ordering::less : std::strong_ordering::greater;
    } else if (lhs_numeric != rhs_numeric) {
      return lhs_numeric ? std::strong_ordering::less : std::strong_ordering::greater;
    } else {
      const int cmp = lhs_id.compare(rhs_id);
      if (cmp != 0) return cmp < 0 ? std::strong_ordering::less : std::strong_ordering::greater;
    }

    if (lhs_end == lhs.size() && rhs_end == rhs.size()) return std::strong_ordering::equal;
    lhs_start = lhs_end + 1;
    rhs_start = rhs_end + 1;
  }
}

}  // namespace

std::optional<SemVer> SemVer::parse(std::string_view text) noexcept {
  if (text.empty() || text.size() > 128) return std::nullopt;
  std::string_view core;
  std::string_view prerelease;
  std::string_view build;
  if (!split(text, core, prerelease, build)) return std::nullopt;

  std::uint32_t major = 0;
  std::uint32_t minor = 0;
  std::uint32_t patch = 0;
  std::size_t start = 0;
  std::uint32_t* slots[3] = {&major, &minor, &patch};
  for (int index = 0; index < 3; ++index) {
    const std::size_t dot = core.find('.', start);
    std::string_view component;
    if (index == 2) {
      if (dot != std::string_view::npos) return std::nullopt;
      component = core.substr(start);
    } else {
      if (dot == std::string_view::npos) return std::nullopt;
      component = core.substr(start, dot - start);
      start = dot + 1;
    }
    if (!parse_component(component, *slots[index])) return std::nullopt;
  }

  if (!prerelease.empty() && !parse_identifiers(prerelease, true)) return std::nullopt;
  if (!build.empty() && !parse_identifiers(build, false)) return std::nullopt;

  SemVer result(major, minor, patch);
  result.prerelease_ = std::string(prerelease);
  result.prerelease_size_ = static_cast<std::uint8_t>(result.prerelease_.size());
  result.build_ = std::string(build);
  result.build_size_ = static_cast<std::uint8_t>(result.build_.size());
  return result;
}

std::string SemVer::str() const {
  std::string out;
  out.reserve(64);
  out += std::to_string(major_);
  out.push_back('.');
  out += std::to_string(minor_);
  out.push_back('.');
  out += std::to_string(patch_);
  if (prerelease_size_ != 0) {
    out.push_back('-');
    out.append(prerelease());
  }
  if (build_size_ != 0) {
    out.push_back('+');
    out.append(build());
  }
  return out;
}

bool operator==(const SemVer& a, const SemVer& b) noexcept {
  return a.major_ == b.major_ && a.minor_ == b.minor_ && a.patch_ == b.patch_ &&
         a.prerelease_size_ == b.prerelease_size_ && a.build_size_ == b.build_size_ &&
         a.prerelease() == b.prerelease() && a.build() == b.build();
}

std::strong_ordering operator<=>(const SemVer& a, const SemVer& b) noexcept {
  if (a.major_ != b.major_) return a.major_ <=> b.major_;
  if (a.minor_ != b.minor_) return a.minor_ <=> b.minor_;
  if (a.patch_ != b.patch_) return a.patch_ <=> b.patch_;
  const int pre = a.prerelease().compare(b.prerelease());
  if (pre != 0) return pre < 0 ? std::strong_ordering::less : std::strong_ordering::greater;
  const int build = a.build().compare(b.build());
  if (build != 0) return build < 0 ? std::strong_ordering::less : std::strong_ordering::greater;
  return std::strong_ordering::equal;
}

std::strong_ordering SemVer::precedence_compare(const SemVer& other) const noexcept {
  if (major_ != other.major_) return major_ <=> other.major_;
  if (minor_ != other.minor_) return minor_ <=> other.minor_;
  if (patch_ != other.patch_) return patch_ <=> other.patch_;
  const bool lhs_pre = prerelease_size_ != 0;
  const bool rhs_pre = other.prerelease_size_ != 0;
  if (!lhs_pre && !rhs_pre) return std::strong_ordering::equal;
  if (!lhs_pre) return std::strong_ordering::greater;
  if (!rhs_pre) return std::strong_ordering::less;
  return compare_identifiers(prerelease(), other.prerelease());
}

bool VersionRequirement::satisfied_by(const SemVer& candidate) const noexcept {
  if (candidate.precedence_compare(minimum) == std::strong_ordering::less) return false;
  if (maximum_exclusive.has_value() &&
      candidate.precedence_compare(*maximum_exclusive) != std::strong_ordering::less) {
    return false;
  }
  return true;
}

std::string VersionRequirement::str() const {
  std::string out = ">=";
  out += minimum.str();
  if (maximum_exclusive.has_value()) {
    out += ",<";
    out += maximum_exclusive->str();
  }
  return out;
}

}  // namespace ocreg
