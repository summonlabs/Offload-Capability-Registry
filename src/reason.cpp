// Offload Capability Registry - stable reason code table.
// Copyright 2026 Summon Software Labs.
#include "ocreg/reason.hpp"

#include <array>
#include <cstddef>
#include <string>

#include "ocreg/hash.hpp"

namespace ocreg {
namespace {

// Turns an enum identifier into its canonical UPPER_SNAKE spelling. This keeps
// the enumeration and the wire spelling from never drifting apart.
[[nodiscard]] std::string canonical_spelling(std::string_view identifier) {
  std::string out;
  out.reserve(identifier.size() + 8);
  for (std::size_t i = 0; i < identifier.size(); ++i) {
    const char c = identifier[i];
    const bool upper = c >= 'A' && c <= 'Z';
    if (upper && i != 0) {
      const char prev = identifier[i - 1];
      const bool prev_lower = (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9');
      if (prev_lower) out.push_back('_');
    }
    out.push_back(upper ? static_cast<char>(c - 'A' + 'a') : c);
  }
  for (char& c : out) {
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
  }
  return out;
}

constexpr ReasonCode kCodes[] = {
#define OCREG_REASON_CODE_ENTRY(code, numeric, category, failure) ReasonCode::code,
    OCREG_REASON_TABLE(OCREG_REASON_CODE_ENTRY)
#undef OCREG_REASON_CODE_ENTRY
};

constexpr ReasonCategory kCategories[] = {
#define OCREG_REASON_CATEGORY_ENTRY(code, numeric, category, failure) ReasonCategory::category,
    OCREG_REASON_TABLE(OCREG_REASON_CATEGORY_ENTRY)
#undef OCREG_REASON_CATEGORY_ENTRY
};

constexpr bool kFailures[] = {
#define OCREG_REASON_FAILURE_ENTRY(code, numeric, category, failure) (failure) != 0,
    OCREG_REASON_TABLE(OCREG_REASON_FAILURE_ENTRY)
#undef OCREG_REASON_FAILURE_ENTRY
};

constexpr const char* kIdentifiers[] = {
#define OCREG_REASON_IDENTIFIER_ENTRY(code, numeric, category, failure) #code,
    OCREG_REASON_TABLE(OCREG_REASON_IDENTIFIER_ENTRY)
#undef OCREG_REASON_IDENTIFIER_ENTRY
};

constexpr std::size_t kEntryCount = sizeof(kCodes) / sizeof(kCodes[0]);
static_assert(sizeof(kCategories) / sizeof(kCategories[0]) == kEntryCount,
              "reason category table must match the reason code table");
static_assert(sizeof(kFailures) / sizeof(kFailures[0]) == kEntryCount,
              "reason failure table must match the reason code table");
static_assert(sizeof(kIdentifiers) / sizeof(kIdentifiers[0]) == kEntryCount,
              "reason identifier table must match the reason code table");

struct TableEntry {
  ReasonCode code;
  ReasonCategory category;
  bool failure;
  std::string text;
};

using Table = std::array<TableEntry, kEntryCount>;

[[nodiscard]] const Table& table() {
  static const Table instance = [] {
    Table built{};
    for (std::size_t index = 0; index < kEntryCount; ++index) {
      built[index].code = kCodes[index];
      built[index].category = kCategories[index];
      built[index].failure = kFailures[index];
      built[index].text = canonical_spelling(kIdentifiers[index]);
    }
    return built;
  }();
  return instance;
}

}  // namespace

std::string_view to_string(ReasonCode code) noexcept {
  for (const auto& entry : table()) {
    if (entry.code == code) return entry.text;
  }
  return "UNKNOWN_REASON_CODE";
}

bool is_failure(ReasonCode code) noexcept {
  for (const auto& entry : table()) {
    if (entry.code == code) return entry.failure;
  }
  // An unrecognised code is treated as a failure: an unknown outcome must
  // never be mistaken for success.
  return true;
}

ReasonCategory category_of(ReasonCode code) noexcept {
  for (const auto& entry : table()) {
    if (entry.code == code) return entry.category;
  }
  return ReasonCategory::Rejection;
}

std::string_view to_string(ReasonCategory category) noexcept {
  switch (category) {
    case ReasonCategory::Acceptance: return "ACCEPTANCE";
    case ReasonCategory::Idempotent: return "IDEMPOTENT";
    case ReasonCategory::Rejection: return "REJECTION";
    case ReasonCategory::Unknown: return "UNKNOWN";
    case ReasonCategory::Incompatible: return "INCOMPATIBLE";
    case ReasonCategory::Conflict: return "CONFLICT";
    case ReasonCategory::Persistence: return "PERSISTENCE";
    case ReasonCategory::Recovery: return "RECOVERY";
    case ReasonCategory::Accounting: return "ACCOUNTING";
    case ReasonCategory::Transport: return "TRANSPORT";
    case ReasonCategory::Cancellation: return "CANCELLATION";
  }
  return "REJECTION";
}

bool parse_reason_code(std::string_view text, ReasonCode& out) noexcept {
  for (const auto& entry : table()) {
    if (entry.text == text) {
      out = entry.code;
      return true;
    }
  }
  return false;
}

std::size_t reason_code_count() noexcept { return table().size(); }

std::uint32_t reason_table_fingerprint() noexcept {
  Sha256 hash;
  for (const auto& entry : table()) {
    hash.update_u16(static_cast<std::uint16_t>(entry.code));
    hash.update_bytes(entry.text);
    hash.update_byte(static_cast<std::uint8_t>(entry.category));
    hash.update_byte(entry.failure ? 1 : 0);
  }
  const auto digest = hash.finish();
  const auto& bytes = digest.bytes();
  return (static_cast<std::uint32_t>(bytes[0]) << 24) |
         (static_cast<std::uint32_t>(bytes[1]) << 16) |
         (static_cast<std::uint32_t>(bytes[2]) << 8) | static_cast<std::uint32_t>(bytes[3]);
}

}  // namespace ocreg
