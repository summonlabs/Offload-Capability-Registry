// Offload Capability Registry - canonical binary codec primitives.
// Copyright 2026 Summon Software Labs.
//
// One canonical encoding is shared by persistence, the wire protocol and the
// deterministic digest surface. Encoding is fixed-width and big-endian so that
// equivalent values always produce identical bytes. Decoding is fully
// bounds-checked: a truncated, oversized or impossible input sets the reader
// into a failed state that callers must observe.
#ifndef OCREG_CODEC_HPP
#define OCREG_CODEC_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "ocreg/catalog.hpp"
#include "ocreg/checked.hpp"
#include "ocreg/hash.hpp"
#include "ocreg/name.hpp"
#include "ocreg/reason.hpp"
#include "ocreg/semver.hpp"
#include "ocreg/strong.hpp"
#include "ocreg/units.hpp"

namespace ocreg {

inline constexpr std::size_t kMaxDecodeBytes = 64u * 1024u * 1024u;

class Writer {
 public:
  Writer() = default;

  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void i64(std::int64_t value);

  // Length-prefixed (u32) byte sequence.
  void bytes(std::span<const std::uint8_t> value);
  void str(std::string_view value);
  void name(const Name& value);
  template <class Tag>
  void name_id(NameId<Tag> value) {
    name(value.name());
  }
  template <class Tag, class Rep>
  void strong(Strong<Tag, Rep> value) {
    u64(static_cast<std::uint64_t>(value.value()));
  }
  void digest(const Digest256& value);
  void reason(ReasonCode value);
  void boolean(bool value);

  // Presence-tagged optional, encoded as a single flag byte plus the value.
  template <class T, class Fn>
  void optional(const std::optional<T>& value, Fn&& encode_value) {
    if (value.has_value()) {
      u8(1);
      encode_value(*value);
    } else {
      u8(0);
    }
  }

  [[nodiscard]] const std::vector<std::uint8_t>& buffer() const noexcept { return buffer_; }
  [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }
  [[nodiscard]] std::span<const std::uint8_t> span() const noexcept {
    return std::span<const std::uint8_t>(buffer_.data(), buffer_.size());
  }
  [[nodiscard]] std::string_view view() const noexcept {
    return std::string_view(reinterpret_cast<const char*>(buffer_.data()), buffer_.size());
  }
  void reserve(std::size_t bytes) { buffer_.reserve(bytes); }
  void clear() noexcept { buffer_.clear(); }

 private:
  std::vector<std::uint8_t> buffer_{};
};

class Reader {
 public:
  Reader() = default;
  explicit Reader(std::span<const std::uint8_t> data) noexcept : data_(data) {}
  explicit Reader(std::string_view data) noexcept
      : data_(reinterpret_cast<const std::uint8_t*>(data.data()), data.size()) {}

  [[nodiscard]] bool ok() const noexcept { return ok_; }
  void fail(ReasonCode reason) noexcept {
    if (ok_) {
      ok_ = false;
      reason_ = reason;
    }
  }
  [[nodiscard]] ReasonCode failure() const noexcept { return reason_; }
  [[nodiscard]] std::size_t position() const noexcept { return position_; }
  [[nodiscard]] std::size_t remaining() const noexcept {
    return position_ <= data_.size() ? data_.size() - position_ : 0;
  }
  [[nodiscard]] bool at_end() const noexcept { return position_ == data_.size(); }

  [[nodiscard]] std::uint8_t u8() noexcept;
  [[nodiscard]] std::uint16_t u16() noexcept;
  [[nodiscard]] std::uint32_t u32() noexcept;
  [[nodiscard]] std::uint64_t u64() noexcept;
  [[nodiscard]] std::int64_t i64() noexcept;
  [[nodiscard]] bool boolean() noexcept;

  // Returns a view into the underlying buffer; empty on failure. A declared
  // length larger than the remaining input is a hard failure.
  [[nodiscard]] std::string_view bytes() noexcept;
  [[nodiscard]] bool name(Name& out) noexcept;
  template <class Tag>
  [[nodiscard]] bool name_id(NameId<Tag>& out) noexcept {
    Name parsed;
    if (!name(parsed)) return false;
    out = NameId<Tag>(parsed);
    return true;
  }
  template <class Tag, class Rep>
  [[nodiscard]] bool strong(Strong<Tag, Rep>& out) noexcept {
    const std::uint64_t raw = u64();
    if (!ok_) return false;
    Rep narrowed{};
    if (!checked_narrow<Rep, std::uint64_t>(raw, narrowed)) {
      fail(ReasonCode::RejectedMalformedDocument);
      return false;
    }
    out = Strong<Tag, Rep>(narrowed);
    return true;
  }
  [[nodiscard]] bool digest(Digest256& out) noexcept;
  [[nodiscard]] bool reason(ReasonCode& out) noexcept;

  template <class T, class Fn>
  [[nodiscard]] bool optional(std::optional<T>& out, Fn&& decode_value) noexcept {
    const std::uint8_t flag = u8();
    if (!ok_) return false;
    if (flag == 0) {
      out.reset();
      return true;
    }
    if (flag != 1) {
      fail(ReasonCode::RejectedMalformedDocument);
      return false;
    }
    T value{};
    if (!decode_value(value)) return false;
    out = std::move(value);
    return true;
  }

 private:
  [[nodiscard]] bool require(std::size_t count) noexcept;

  std::span<const std::uint8_t> data_{};
  std::size_t position_ = 0;
  bool ok_ = true;
  ReasonCode reason_ = ReasonCode::Ok;
};

// ---------------------------------------------------------------------------
// Canonical encoders/decoders. Every function appends exactly one canonical
// representation; decoders reject impossible values through the reader.
// ---------------------------------------------------------------------------
// Every Strong<...> scalar uses the same canonical fixed-width encoding.
template <class Tag, class Rep>
inline void encode(Writer& w, Strong<Tag, Rep> value) {
  w.strong(value);
}

template <class Tag, class Rep>
inline bool decode(Reader& r, Strong<Tag, Rep>& value) {
  return r.strong(value);
}

void encode(Writer& w, const SemVer& value);
bool decode(Reader& r, SemVer& value);

void encode(Writer& w, const Unit& value);
bool decode(Reader& r, Unit& value);

void encode(Writer& w, const FeatureSet& value);
bool decode(Reader& r, FeatureSet& value);

void encode(Writer& w, const LimitValue& value);
bool decode(Reader& r, LimitValue& value);

void encode(Writer& w, const LimitSet& value);
bool decode(Reader& r, LimitSet& value);

[[nodiscard]] bool capability_kind_from_code(std::uint16_t raw, CapabilityKind& out) noexcept;
[[nodiscard]] bool feature_from_code(std::uint32_t raw, FeatureCode& out) noexcept;
[[nodiscard]] bool limit_from_code(std::uint32_t raw, LimitCode& out) noexcept;

inline void encode(Writer& w, CapabilityKind value) { w.u16(static_cast<std::uint16_t>(value)); }
inline void encode(Writer& w, FeatureCode value) { w.u32(static_cast<std::uint32_t>(value)); }
inline void encode(Writer& w, LimitCode value) { w.u32(static_cast<std::uint32_t>(value)); }

inline bool decode(Reader& r, CapabilityKind& value) {
  const std::uint16_t raw = r.u16();
  if (!r.ok()) return false;
  CapabilityKind parsed{};
  if (!capability_kind_from_code(raw, parsed)) {
    r.fail(ReasonCode::RejectedUnknownCapabilityKind);
    return false;
  }
  value = parsed;
  return true;
}

inline bool decode(Reader& r, FeatureCode& value) {
  const std::uint32_t raw = r.u32();
  if (!r.ok()) return false;
  FeatureCode parsed{};
  if (!feature_from_code(raw, parsed)) {
    r.fail(ReasonCode::RejectedUnknownFeatureCode);
    return false;
  }
  value = parsed;
  return true;
}

inline bool decode(Reader& r, LimitCode& value) {
  const std::uint32_t raw = r.u32();
  if (!r.ok()) return false;
  LimitCode parsed{};
  if (!limit_from_code(raw, parsed)) {
    r.fail(ReasonCode::RejectedUnknownLimitCode);
    return false;
  }
  value = parsed;
  return true;
}

// Canonical order helpers shared by every container.
[[nodiscard]] bool canonical_order_ok(const FeatureSet& set) noexcept;
[[nodiscard]] bool canonical_order_ok(const LimitSet& set) noexcept;

}  // namespace ocreg

#endif  // OCREG_CODEC_HPP
