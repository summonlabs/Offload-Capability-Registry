// Offload Capability Registry - strict canonical JSON.
// Copyright 2026 Summon Software Labs.
#include "ocreg/json.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace ocreg {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

[[nodiscard]] bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }

// Strict UTF-8 validation. Over-long encodings, surrogate code points and
// values above U+10FFFF are all rejected.
[[nodiscard]] bool valid_utf8(std::string_view text) noexcept {
  std::size_t i = 0;
  while (i < text.size()) {
    const auto byte = static_cast<unsigned char>(text[i]);
    std::size_t extra = 0;
    std::uint32_t code_point = 0;
    if (byte < 0x80u) {
      ++i;
      continue;
    } else if ((byte & 0xE0u) == 0xC0u) {
      extra = 1;
      code_point = byte & 0x1Fu;
      if (code_point < 0x02u) return false;
    } else if ((byte & 0xF0u) == 0xE0u) {
      extra = 2;
      code_point = byte & 0x0Fu;
    } else if ((byte & 0xF8u) == 0xF0u) {
      extra = 3;
      code_point = byte & 0x07u;
    } else {
      return false;
    }
    if (i + extra >= text.size()) return false;
    for (std::size_t k = 1; k <= extra; ++k) {
      const auto continuation = static_cast<unsigned char>(text[i + k]);
      if ((continuation & 0xC0u) != 0x80u) return false;
      code_point = (code_point << 6) | (continuation & 0x3Fu);
    }
    if (extra == 2 && code_point < 0x0800u) return false;
    if (extra == 3 && code_point < 0x10000u) return false;
    if (code_point > 0x10FFFFu) return false;
    if (code_point >= 0xD800u && code_point <= 0xDFFFu) return false;
    i += extra + 1;
  }
  return true;
}

void append_utf8(std::string& out, std::uint32_t code_point) {
  if (code_point < 0x80u) {
    out.push_back(static_cast<char>(code_point));
  } else if (code_point < 0x800u) {
    out.push_back(static_cast<char>(0xC0u | (code_point >> 6)));
    out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
  } else if (code_point < 0x10000u) {
    out.push_back(static_cast<char>(0xE0u | (code_point >> 12)));
    out.push_back(static_cast<char>(0x80u | ((code_point >> 6) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
  } else {
    out.push_back(static_cast<char>(0xF0u | (code_point >> 18)));
    out.push_back(static_cast<char>(0x80u | ((code_point >> 12) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | ((code_point >> 6) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
  }
}

[[nodiscard]] int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

class Parser {
 public:
  Parser(std::string_view text, const JsonLimits& limits) : text_(text), limits_(limits) {}

  [[nodiscard]] bool parse_document(JsonValue& out) {
    if (text_.size() > limits_.max_bytes) {
      reason_ = ReasonCode::RejectedOversizedInput;
      return false;
    }
    // The document must be pure ASCII plus valid UTF-8 in strings; validating
    // the whole buffer once keeps the string path simple and still rejects
    // malformed byte sequences.
    if (!valid_utf8(text_)) {
      reason_ = ReasonCode::RejectedInvalidUtf8;
      return false;
    }
    skip_whitespace();
    if (!parse_value(out, 0)) return false;
    skip_whitespace();
    if (position_ != text_.size()) {
      reason_ = ReasonCode::RejectedTrailingGarbage;
      return false;
    }
    return true;
  }

  [[nodiscard]] ReasonCode reason() const noexcept { return reason_; }

 private:
  void skip_whitespace() noexcept {
    while (position_ < text_.size()) {
      const char c = text_[position_];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        ++position_;
      } else {
        break;
      }
    }
  }

  [[nodiscard]] bool consume(char expected) noexcept {
    if (position_ < text_.size() && text_[position_] == expected) {
      ++position_;
      return true;
    }
    reason_ = position_ >= text_.size() ? ReasonCode::RejectedTruncatedInput
                                        : ReasonCode::RejectedMalformedDocument;
    return false;
  }

  [[nodiscard]] bool literal(std::string_view word) noexcept {
    if (text_.size() - position_ < word.size() ||
        text_.compare(position_, word.size(), word) != 0) {
      reason_ = ReasonCode::RejectedMalformedDocument;
      return false;
    }
    position_ += word.size();
    return true;
  }

  [[nodiscard]] bool account_item() noexcept {
    if (items_ >= limits_.max_items) {
      reason_ = ReasonCode::RejectedOversizedInput;
      return false;
    }
    ++items_;
    return true;
  }

  [[nodiscard]] bool parse_value(JsonValue& out, std::size_t depth) {
    if (depth > limits_.max_depth) {
      reason_ = ReasonCode::RejectedNestingTooDeep;
      return false;
    }
    if (position_ >= text_.size()) {
      reason_ = ReasonCode::RejectedTruncatedInput;
      return false;
    }
    if (!account_item()) return false;
    switch (text_[position_]) {
      case '{': return parse_object(out, depth);
      case '[': return parse_array(out, depth);
      case '"': {
        std::string value;
        if (!parse_string(value)) return false;
        out = JsonValue::string(std::move(value));
        return true;
      }
      case 't':
        if (!literal("true")) return false;
        out = JsonValue::boolean(true);
        return true;
      case 'f':
        if (!literal("false")) return false;
        out = JsonValue::boolean(false);
        return true;
      case 'n':
        if (!literal("null")) return false;
        out = JsonValue::null();
        return true;
      default: return parse_integer(out);
    }
  }

  [[nodiscard]] bool parse_integer(JsonValue& out) {
    const std::size_t start = position_;
    bool negative = false;
    if (position_ < text_.size() && text_[position_] == '-') {
      negative = true;
      ++position_;
    }
    const std::size_t digits_start = position_;
    while (position_ < text_.size() && is_digit(text_[position_])) ++position_;
    const std::size_t digits = position_ - digits_start;
    if (digits == 0) {
      reason_ = ReasonCode::RejectedMalformedDocument;
      return false;
    }
    if (digits > 1 && text_[digits_start] == '0') {
      // Leading zeros are not canonically representable.
      reason_ = ReasonCode::RejectedMalformedDocument;
      return false;
    }
    if (position_ < text_.size() &&
        (text_[position_] == '.' || text_[position_] == 'e' || text_[position_] == 'E')) {
      // Floating point is not part of the canonical format: a value that
      // cannot be represented exactly is refused rather than rounded.
      reason_ = ReasonCode::RejectedMalformedDocument;
      return false;
    }
    if (digits > 19) {
      reason_ = ReasonCode::RejectedOversizedInput;
      return false;
    }
    std::uint64_t magnitude = 0;
    for (std::size_t i = digits_start; i < position_; ++i) {
      magnitude = magnitude * 10u + static_cast<std::uint64_t>(text_[i] - '0');
    }
    constexpr std::uint64_t kMaxPositive = 9223372036854775807ull;
    if (negative) {
      if (magnitude > kMaxPositive + 1ull) {
        reason_ = ReasonCode::RejectedOversizedInput;
        return false;
      }
      const std::int64_t value =
          magnitude == kMaxPositive + 1ull
              ? std::numeric_limits<std::int64_t>::min()
              : -static_cast<std::int64_t>(magnitude);
      out = JsonValue::integer(value);
      return true;
    }
    if (magnitude > kMaxPositive) {
      reason_ = ReasonCode::RejectedOversizedInput;
      return false;
    }
    out = JsonValue::integer(static_cast<std::int64_t>(magnitude));
    (void)start;
    return true;
  }

  [[nodiscard]] bool parse_hex4(std::uint32_t& out) {
    if (text_.size() - position_ < 4) {
      reason_ = ReasonCode::RejectedTruncatedInput;
      return false;
    }
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
      const int digit = hex_value(text_[position_ + static_cast<std::size_t>(i)]);
      if (digit < 0) {
        reason_ = ReasonCode::RejectedMalformedDocument;
        return false;
      }
      value = (value << 4) | static_cast<std::uint32_t>(digit);
    }
    position_ += 4;
    out = value;
    return true;
  }

  [[nodiscard]] bool parse_string(std::string& out) {
    if (!consume('"')) return false;
    out.clear();
    while (true) {
      if (position_ >= text_.size()) {
        reason_ = ReasonCode::RejectedTruncatedInput;
        return false;
      }
      const char c = text_[position_];
      if (c == '"') {
        ++position_;
        return true;
      }
      if (static_cast<unsigned char>(c) < 0x20u) {
        reason_ = ReasonCode::RejectedMalformedDocument;
        return false;
      }
      if (c != '\\') {
        out.push_back(c);
        ++position_;
      } else {
        ++position_;
        if (position_ >= text_.size()) {
          reason_ = ReasonCode::RejectedTruncatedInput;
          return false;
        }
        const char escape = text_[position_++];
        switch (escape) {
          case '"': out.push_back('"'); break;
          case '\\': out.push_back('\\'); break;
          case '/': out.push_back('/'); break;
          case 'b': out.push_back('\b'); break;
          case 'f': out.push_back('\f'); break;
          case 'n': out.push_back('\n'); break;
          case 'r': out.push_back('\r'); break;
          case 't': out.push_back('\t'); break;
          case 'u': {
            std::uint32_t code_point = 0;
            if (!parse_hex4(code_point)) return false;
            if (code_point >= 0xD800u && code_point <= 0xDBFFu) {
              if (text_.size() - position_ < 2 || text_[position_] != '\\' ||
                  text_[position_ + 1] != 'u') {
                reason_ = ReasonCode::RejectedInvalidUtf8;
                return false;
              }
              position_ += 2;
              std::uint32_t low = 0;
              if (!parse_hex4(low)) return false;
              if (low < 0xDC00u || low > 0xDFFFu) {
                reason_ = ReasonCode::RejectedInvalidUtf8;
                return false;
              }
              code_point = 0x10000u + ((code_point - 0xD800u) << 10) + (low - 0xDC00u);
            } else if (code_point >= 0xDC00u && code_point <= 0xDFFFu) {
              reason_ = ReasonCode::RejectedInvalidUtf8;
              return false;
            }
            append_utf8(out, code_point);
            break;
          }
          default:
            reason_ = ReasonCode::RejectedMalformedDocument;
            return false;
        }
        if (out.size() > limits_.max_string_bytes) {
          reason_ = ReasonCode::RejectedOversizedInput;
          return false;
        }
      }
    }
  }

  [[nodiscard]] bool parse_object(JsonValue& out, std::size_t depth) {
    if (!consume('{')) return false;
    JsonValue result = JsonValue::object();
    skip_whitespace();
    if (position_ < text_.size() && text_[position_] == '}') {
      ++position_;
      out = std::move(result);
      return true;
    }
    while (true) {
      skip_whitespace();
      std::string key;
      if (!parse_string(key)) return false;
      if (key.size() > limits_.max_key_bytes) {
        reason_ = ReasonCode::RejectedOversizedInput;
        return false;
      }
      skip_whitespace();
      if (!consume(':')) return false;
      skip_whitespace();
      JsonValue value;
      if (!parse_value(value, depth + 1)) return false;
      if (result.find(key) != nullptr) {
        reason_ = ReasonCode::RejectedDuplicateKey;
        return false;
      }
      result.set(std::move(key), std::move(value));
      skip_whitespace();
      if (position_ < text_.size() && text_[position_] == ',') {
        ++position_;
        continue;
      }
      if (position_ < text_.size() && text_[position_] == '}') {
        ++position_;
        out = std::move(result);
        return true;
      }
      reason_ = position_ >= text_.size() ? ReasonCode::RejectedTruncatedInput
                                          : ReasonCode::RejectedMalformedDocument;
      return false;
    }
  }

  [[nodiscard]] bool parse_array(JsonValue& out, std::size_t depth) {
    if (!consume('[')) return false;
    JsonValue result = JsonValue::array();
    skip_whitespace();
    if (position_ < text_.size() && text_[position_] == ']') {
      ++position_;
      out = std::move(result);
      return true;
    }
    while (true) {
      skip_whitespace();
      JsonValue value;
      if (!parse_value(value, depth + 1)) return false;
      result.push(std::move(value));
      skip_whitespace();
      if (position_ < text_.size() && text_[position_] == ',') {
        ++position_;
        continue;
      }
      if (position_ < text_.size() && text_[position_] == ']') {
        ++position_;
        out = std::move(result);
        return true;
      }
      reason_ = position_ >= text_.size() ? ReasonCode::RejectedTruncatedInput
                                          : ReasonCode::RejectedMalformedDocument;
      return false;
    }
  }

  std::string_view text_{};
  const JsonLimits& limits_;
  std::size_t position_ = 0;
  std::size_t items_ = 0;
  ReasonCode reason_ = ReasonCode::Ok;
};

}  // namespace

std::string json_escape(std::string_view text) {
  std::string out;
  out.reserve(text.size() + 2);
  out.push_back('"');
  for (const char c : text) {
    const auto byte = static_cast<unsigned char>(c);
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      default:
        if (byte < 0x20u) {
          out += "\\u00";
          out.push_back(kHexDigits[(byte >> 4) & 0xFu]);
          out.push_back(kHexDigits[byte & 0xFu]);
        } else {
          out.push_back(c);
        }
        break;
    }
  }
  out.push_back('"');
  return out;
}

JsonValue JsonValue::null() { return JsonValue(); }

JsonValue JsonValue::boolean(bool value) {
  JsonValue result;
  result.type_ = Type::Bool;
  result.boolean_ = value;
  return result;
}

JsonValue JsonValue::integer(std::int64_t value) {
  JsonValue result;
  result.type_ = Type::Integer;
  result.integer_ = value;
  return result;
}

JsonValue JsonValue::string(std::string value) {
  JsonValue result;
  result.type_ = Type::String;
  result.string_ = std::move(value);
  return result;
}

JsonValue JsonValue::array() {
  JsonValue result;
  result.type_ = Type::Array;
  return result;
}

JsonValue JsonValue::object() {
  JsonValue result;
  result.type_ = Type::Object;
  return result;
}

const JsonValue* JsonValue::find(std::string_view key) const noexcept {
  if (type_ != Type::Object) return nullptr;
  const auto it = std::lower_bound(
      object_.begin(), object_.end(), key,
      [](const Member& member, std::string_view probe) { return member.first < probe; });
  if (it == object_.end() || it->first != key) return nullptr;
  return &it->second;
}

void JsonValue::set(std::string key, JsonValue value) {
  const auto it = std::lower_bound(
      object_.begin(), object_.end(), key,
      [](const Member& member, const std::string& probe) { return member.first < probe; });
  if (it != object_.end() && it->first == key) {
    it->second = std::move(value);
    return;
  }
  object_.insert(it, Member(std::move(key), std::move(value)));
}

void JsonValue::push(JsonValue value) { array_.push_back(std::move(value)); }

std::string JsonValue::dump(bool pretty) const {
  std::string out;
  dump_to(out, pretty, 0);
  return out;
}

void JsonValue::dump_to(std::string& out, bool pretty, std::size_t depth) const {
  const std::string indent = pretty ? std::string((depth + 1) * 2, ' ') : std::string();
  const std::string closing_indent = pretty ? std::string(depth * 2, ' ') : std::string();
  switch (type_) {
    case Type::Null: out += "null"; break;
    case Type::Bool: out += boolean_ ? "true" : "false"; break;
    case Type::Integer: out += std::to_string(integer_); break;
    case Type::String: out += json_escape(string_); break;
    case Type::Array: {
      if (array_.empty()) {
        out += "[]";
        break;
      }
      out.push_back('[');
      for (std::size_t i = 0; i < array_.size(); ++i) {
        if (i != 0) out.push_back(',');
        if (pretty) {
          out.push_back('\n');
          out += indent;
        }
        array_[i].dump_to(out, pretty, depth + 1);
      }
      if (pretty) {
        out.push_back('\n');
        out += closing_indent;
      }
      out.push_back(']');
      break;
    }
    case Type::Object: {
      if (object_.empty()) {
        out += "{}";
        break;
      }
      out.push_back('{');
      for (std::size_t i = 0; i < object_.size(); ++i) {
        if (i != 0) out.push_back(',');
        if (pretty) {
          out.push_back('\n');
          out += indent;
        }
        out += json_escape(object_[i].first);
        out.push_back(':');
        if (pretty) out.push_back(' ');
        object_[i].second.dump_to(out, pretty, depth + 1);
      }
      if (pretty) {
        out.push_back('\n');
        out += closing_indent;
      }
      out.push_back('}');
      break;
    }
  }
}

Outcome<JsonValue> JsonValue::parse(std::string_view text, const JsonLimits& limits) {
  Parser parser(text, limits);
  JsonValue value;
  if (!parser.parse_document(value)) {
    return Outcome<JsonValue>(Status::failure(parser.reason(), "canonical JSON rejected"));
  }
  return Outcome<JsonValue>(std::move(value));
}

}  // namespace ocreg
