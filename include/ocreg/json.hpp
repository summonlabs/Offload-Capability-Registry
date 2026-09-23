// Offload Capability Registry - strict canonical JSON.
// Copyright 2026 Summon Software Labs.
//
// A deliberately small JSON subset with hard bounds. The parser rejects
// trailing content, duplicate keys, over-deep nesting, over-long strings,
// oversized documents, control characters and every numeric form that cannot
// be represented exactly as a signed 64-bit integer. The writer emits
// canonical output: object keys sorted, no insignificant whitespace, no
// floating point.
#ifndef OCREG_JSON_HPP
#define OCREG_JSON_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "ocreg/outcome.hpp"

namespace ocreg {

struct JsonLimits {
  std::size_t max_bytes = 8u * 1024u * 1024u;
  std::size_t max_depth = 32;
  std::size_t max_items = 262144;
  std::size_t max_string_bytes = 1u * 1024u * 1024u;
  std::size_t max_key_bytes = 128;
};

class JsonValue {
 public:
  enum class Type : std::uint8_t { Null = 0, Bool = 1, Integer = 2, String = 3, Array = 4, Object = 5 };

  using Array = std::vector<JsonValue>;
  using Member = std::pair<std::string, JsonValue>;
  using Object = std::vector<Member>;

  JsonValue() = default;
  static JsonValue null();
  static JsonValue boolean(bool value);
  static JsonValue integer(std::int64_t value);
  static JsonValue string(std::string value);
  static JsonValue array();
  static JsonValue object();

  [[nodiscard]] Type type() const noexcept { return type_; }
  [[nodiscard]] bool is_null() const noexcept { return type_ == Type::Null; }
  [[nodiscard]] bool is_bool() const noexcept { return type_ == Type::Bool; }
  [[nodiscard]] bool is_integer() const noexcept { return type_ == Type::Integer; }
  [[nodiscard]] bool is_string() const noexcept { return type_ == Type::String; }
  [[nodiscard]] bool is_array() const noexcept { return type_ == Type::Array; }
  [[nodiscard]] bool is_object() const noexcept { return type_ == Type::Object; }

  [[nodiscard]] bool as_bool() const noexcept { return boolean_; }
  [[nodiscard]] std::int64_t as_integer() const noexcept { return integer_; }
  [[nodiscard]] const std::string& as_string() const noexcept { return string_; }
  [[nodiscard]] const Array& as_array() const noexcept { return array_; }
  [[nodiscard]] const Object& as_object() const noexcept { return object_; }

  // Object access. Keys are held in canonical (lexicographic) order.
  [[nodiscard]] const JsonValue* find(std::string_view key) const noexcept;
  // Inserts or replaces, keeping canonical key order.
  void set(std::string key, JsonValue value);
  void push(JsonValue value);

  [[nodiscard]] std::string dump(bool pretty = false) const;
  void dump_to(std::string& out, bool pretty, std::size_t depth) const;

  // Strict parse. On failure 'reason' carries a stable code and no value is
  // produced.
  [[nodiscard]] static Outcome<JsonValue> parse(std::string_view text,
                                                const JsonLimits& limits = JsonLimits{});

  friend bool operator==(const JsonValue&, const JsonValue&) noexcept = default;

 private:
  Type type_ = Type::Null;
  bool boolean_ = false;
  std::int64_t integer_ = 0;
  std::string string_{};
  Array array_{};
  Object object_{};
};

// Escapes a string as a canonical JSON string literal including the quotes.
[[nodiscard]] std::string json_escape(std::string_view text);

}  // namespace ocreg

#endif  // OCREG_JSON_HPP
