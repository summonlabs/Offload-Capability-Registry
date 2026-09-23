// Offload Capability Registry - canonical binary codec.
// Copyright 2026 Summon Software Labs.
//
// One encoding, used by persistence, the wire protocol and digest computation.
// Decoding is defensive: every enum is range-checked, every length is bounded,
// every collection is size-limited before allocation and every container is
// required to be in canonical order.
#include "ocreg/codec.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "ocreg/decision.hpp"
#include "ocreg/evidence.hpp"
#include "ocreg/export.hpp"
#include "ocreg/persist.hpp"
#include "ocreg/protocol.hpp"
#include "ocreg/registry.hpp"
#include "ocreg/version.hpp"

namespace ocreg {
namespace {

constexpr std::size_t kMaxCollectionEntries = 1048576;

template <class E, class Converter>
[[nodiscard]] bool read_enum(Reader& r, E& out, Converter&& convert, ReasonCode failure) noexcept {
  const std::uint16_t raw = r.u16();
  if (!r.ok()) return false;
  E parsed{};
  if (!convert(raw, parsed)) {
    r.fail(failure);
    return false;
  }
  out = parsed;
  return true;
}

[[nodiscard]] bool source_kind_from(std::uint16_t raw, SourceKind& out) noexcept {
  switch (raw) {
    case 1: out = SourceKind::Synthetic; return true;
    case 2: out = SourceKind::AdjacentRuntime; return true;
    case 3: out = SourceKind::DeviceSelfReport; return true;
    case 4: out = SourceKind::OperatorDeclaration; return true;
    case 5: out = SourceKind::ImportedBundle; return true;
    default: return false;
  }
}

[[nodiscard]] bool authority_from(std::uint16_t raw, AuthorityRank& out) noexcept {
  if (raw > static_cast<std::uint16_t>(AuthorityRank::Operator)) return false;
  out = static_cast<AuthorityRank>(raw);
  return true;
}

[[nodiscard]] bool trust_from(std::uint16_t raw, SourceTrustState& out) noexcept {
  switch (raw) {
    case 1: out = SourceTrustState::Trusted; return true;
    case 2: out = SourceTrustState::Untrusted; return true;
    case 3: out = SourceTrustState::Revoked; return true;
    default: return false;
  }
}

[[nodiscard]] bool lifecycle_from(std::uint16_t raw, EvidenceLifecycle& out) noexcept {
  switch (raw) {
    case 1: out = EvidenceLifecycle::Admitted; return true;
    case 2: out = EvidenceLifecycle::Rejected; return true;
    case 3: out = EvidenceLifecycle::Retired; return true;
    default: return false;
  }
}

[[nodiscard]] bool evidence_state_from(std::uint16_t raw, EvidenceState& out) noexcept {
  switch (raw) {
    case 1: out = EvidenceState::Active; return true;
    case 2: out = EvidenceState::Superseded; return true;
    case 3: out = EvidenceState::Retired; return true;
    case 4: out = EvidenceState::Rejected; return true;
    case 5: out = EvidenceState::Fenced; return true;
    case 6: out = EvidenceState::Stale; return true;
    case 7: out = EvidenceState::Outranked; return true;
    case 8: out = EvidenceState::Evicted; return true;
    default: return false;
  }
}

[[nodiscard]] bool decision_kind_from(std::uint16_t raw, DecisionKind& out) noexcept {
  switch (raw) {
    case 1: out = DecisionKind::Compatible; return true;
    case 2: out = DecisionKind::Incompatible; return true;
    case 3: out = DecisionKind::Unknown; return true;
    case 4: out = DecisionKind::Conflicted; return true;
    default: return false;
  }
}

[[nodiscard]] bool boot_policy_from(std::uint16_t raw, BootPolicy& out) noexcept {
  switch (raw) {
    case 1: out = BootPolicy::ConservativeFence; return true;
    case 2: out = BootPolicy::CarryForwardWithinFreshness; return true;
    default: return false;
  }
}

[[nodiscard]] bool clock_mode_from(std::uint16_t raw, ClockMode& out) noexcept {
  switch (raw) {
    case 1: out = ClockMode::Manual; return true;
    case 2: out = ClockMode::SystemMonotonic; return true;
    default: return false;
  }
}

[[nodiscard]] bool recovery_class_from(std::uint16_t raw, RecoveryClass& out) noexcept {
  if (raw < 1 || raw > 6) return false;
  out = static_cast<RecoveryClass>(raw);
  return true;
}

[[nodiscard]] bool reason_from(std::uint16_t raw, ReasonCode& out) noexcept {
  switch (raw) {
#define OCREG_REASON_MATCH(code, numeric, category, failure) \
  case numeric: out = ReasonCode::code; return true;
    OCREG_REASON_TABLE(OCREG_REASON_MATCH)
#undef OCREG_REASON_MATCH
    default: return false;
  }
}

// Canonical container helpers -------------------------------------------------

void encode_name(Writer& w, const Name& value) { w.name(value); }

[[nodiscard]] bool decode_name(Reader& r, Name& out) noexcept { return r.name(out); }

void encode_device_identity(Writer& w, const DeviceIdentity& value) {
  w.name_id(value.provider);
  w.name_id(value.model);
  w.u32(value.unit_index);
  w.optional(value.serial, [&w](const DeviceSerialId& serial) { w.name_id(serial); });
}

[[nodiscard]] bool decode_device_identity(Reader& r, DeviceIdentity& value) noexcept {
  if (!r.name_id(value.provider)) return false;
  if (!r.name_id(value.model)) return false;
  value.unit_index = r.u32();
  if (!r.ok()) return false;
  if (value.unit_index > kMaxDeviceUnitIndex) {
    r.fail(ReasonCode::RejectedMalformedDocument);
    return false;
  }
  return r.optional(value.serial, [&r](DeviceSerialId& serial) { return r.name_id(serial); });
}

void encode_device_ref(Writer& w, const DeviceIncarnationRef& value) {
  encode_device_identity(w, value.device);
  w.strong(value.incarnation);
}

[[nodiscard]] bool decode_device_ref(Reader& r, DeviceIncarnationRef& value) noexcept {
  if (!decode_device_identity(r, value.device)) return false;
  if (!r.strong(value.incarnation)) return false;
  if (value.incarnation.is_unset()) {
    r.fail(ReasonCode::RejectedZeroIncarnation);
    return false;
  }
  return true;
}

void encode_source_incarnation(Writer& w, const SourceIncarnation& value) {
  w.name_id(value.source);
  w.strong(value.counter);
}

[[nodiscard]] bool decode_source_incarnation(Reader& r, SourceIncarnation& value) noexcept {
  if (!r.name_id(value.source)) return false;
  return r.strong(value.counter);
}

void encode_evidence_key(Writer& w, const EvidenceKey& value) {
  encode_device_ref(w, value.device);
  encode(w, value.kind);
  w.name_id(value.source);
}

[[nodiscard]] bool decode_evidence_key(Reader& r, EvidenceKey& value) noexcept {
  if (!decode_device_ref(r, value.device)) return false;
  if (!decode(r, value.kind)) return false;
  return r.name_id(value.source);
}

void encode_evidence_id(Writer& w, const EvidenceId& value) { w.digest(value.digest()); }
[[nodiscard]] bool decode_evidence_id(Reader& r, EvidenceId& value) noexcept {
  Digest256 digest;
  if (!r.digest(digest)) return false;
  value = EvidenceId(digest);
  return true;
}

void encode_decision_id(Writer& w, const DecisionId& value) { w.digest(value.digest()); }
[[nodiscard]] bool decode_decision_id(Reader& r, DecisionId& value) noexcept {
  Digest256 digest;
  if (!r.digest(digest)) return false;
  value = DecisionId(digest);
  return true;
}

void encode_conflict_id(Writer& w, const ConflictId& value) { w.digest(value.digest()); }
[[nodiscard]] bool decode_conflict_id(Reader& r, ConflictId& value) noexcept {
  Digest256 digest;
  if (!r.digest(digest)) return false;
  value = ConflictId(digest);
  return true;
}

void encode_source_policy(Writer& w, const SourcePolicy& value) {
  w.name_id(value.id);
  w.u16(static_cast<std::uint16_t>(value.kind));
  w.u16(static_cast<std::uint16_t>(value.authority));
  w.u16(static_cast<std::uint16_t>(value.trust));
  w.strong(value.max_age);
  w.boolean(value.durable_across_boot);
}

[[nodiscard]] bool decode_source_policy(Reader& r, SourcePolicy& value) noexcept {
  if (!r.name_id(value.id)) return false;
  if (!read_enum(r, value.kind, source_kind_from, ReasonCode::RejectedMalformedDocument)) return false;
  if (!read_enum(r, value.authority, authority_from, ReasonCode::RejectedMalformedDocument)) return false;
  if (!read_enum(r, value.trust, trust_from, ReasonCode::RejectedMalformedDocument)) return false;
  if (!r.strong(value.max_age)) return false;
  value.durable_across_boot = r.boolean();
  return r.ok();
}

void encode_limits(Writer& w, const RegistryLimits& value) {
  w.u64(value.max_devices);
  w.u64(value.max_incarnations_per_device);
  w.u64(value.max_streams);
  w.u64(value.max_records);
  w.u64(value.max_records_per_stream);
  w.u64(value.max_tombstones);
  w.u64(value.max_conflict_groups);
  w.u64(value.max_resolutions);
  w.u64(value.max_eviction_ledger);
  w.u64(value.max_sources);
  w.u64(value.max_decisions);
  w.u64(value.max_features_per_record);
  w.u64(value.max_limits_per_record);
  w.u64(value.max_limits_per_requirement);
  w.u64(value.max_required_features);
}

[[nodiscard]] bool decode_limits(Reader& r, RegistryLimits& value) noexcept {
  const auto read_bound = [&r](std::size_t& field) {
    const std::uint64_t raw = r.u64();
    if (!r.ok()) return;
    std::size_t narrowed = 0;
    if (!checked_narrow<std::size_t, std::uint64_t>(raw, narrowed)) {
      r.fail(ReasonCode::RejectedOversizedInput);
      return;
    }
    field = narrowed;
  };
  read_bound(value.max_devices);
  read_bound(value.max_incarnations_per_device);
  read_bound(value.max_streams);
  read_bound(value.max_records);
  read_bound(value.max_records_per_stream);
  read_bound(value.max_tombstones);
  read_bound(value.max_conflict_groups);
  read_bound(value.max_resolutions);
  read_bound(value.max_eviction_ledger);
  read_bound(value.max_sources);
  read_bound(value.max_decisions);
  read_bound(value.max_features_per_record);
  read_bound(value.max_limits_per_record);
  read_bound(value.max_limits_per_requirement);
  read_bound(value.max_required_features);
  return r.ok();
}

void encode_registry_policy(Writer& w, const RegistryPolicy& value) {
  w.u32(static_cast<std::uint32_t>(value.sources.size()));
  for (const auto& source : value.sources) encode_source_policy(w, source);
  w.boolean(value.require_configured_source);
  w.boolean(value.refuse_untrusted_sources);
  w.u16(static_cast<std::uint16_t>(value.boot_policy));
  w.u16(static_cast<std::uint16_t>(value.clock_mode));
  w.strong(value.retention_horizon);
  w.strong(value.max_future_skew);
  w.strong(value.default_max_age);
  encode_limits(w, value.limits);
  w.strong(value.rule_generation);
  w.str(value.policy_name);
}

[[nodiscard]] bool decode_registry_policy(Reader& r, RegistryPolicy& value) noexcept {
  const std::uint32_t count = r.u32();
  if (!r.ok()) return false;
  if (count > kMaxCollectionEntries) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.sources.clear();
  value.sources.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!decode_source_policy(r, value.sources[i])) return false;
  }
  value.require_configured_source = r.boolean();
  value.refuse_untrusted_sources = r.boolean();
  if (!read_enum(r, value.boot_policy, boot_policy_from, ReasonCode::RejectedMalformedDocument)) return false;
  if (!read_enum(r, value.clock_mode, clock_mode_from, ReasonCode::RejectedMalformedDocument)) return false;
  if (!r.strong(value.retention_horizon)) return false;
  if (!r.strong(value.max_future_skew)) return false;
  if (!r.strong(value.default_max_age)) return false;
  if (!decode_limits(r, value.limits)) return false;
  if (!r.strong(value.rule_generation)) return false;
  const std::string_view policy_name = r.bytes();
  if (!r.ok()) return false;
  if (policy_name.size() > 128) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.policy_name.assign(policy_name);
  return true;
}

void encode_counters(Writer& w, const RegistryCounters& value) {
  w.u64(value.admissions_accepted);
  w.u64(value.admissions_idempotent);
  w.u64(value.admissions_rejected);
  w.u64(value.retirements_accepted);
  w.u64(value.retirements_rejected);
  w.u64(value.decisions_emitted);
  w.u64(value.decisions_evicted);
  w.u64(value.conflicts_resolved);
  w.u64(value.evictions_total);
  w.u64(value.eviction_ledger_dropped);
  w.u64(value.conflicts_dropped);
  w.u64(value.resolutions_dropped);
  w.u64(value.tombstones_dropped);
}

[[nodiscard]] bool decode_counters(Reader& r, RegistryCounters& value) noexcept {
  value.admissions_accepted = r.u64();
  value.admissions_idempotent = r.u64();
  value.admissions_rejected = r.u64();
  value.retirements_accepted = r.u64();
  value.retirements_rejected = r.u64();
  value.decisions_emitted = r.u64();
  value.decisions_evicted = r.u64();
  value.conflicts_resolved = r.u64();
  value.evictions_total = r.u64();
  value.eviction_ledger_dropped = r.u64();
  value.conflicts_dropped = r.u64();
  value.resolutions_dropped = r.u64();
  value.tombstones_dropped = r.u64();
  return r.ok();
}

void encode_incarnation_entry(Writer& w, const DeviceIncarnationEntry& value) {
  encode_device_identity(w, value.device);
  w.strong(value.current);
  w.u32(static_cast<std::uint32_t>(value.history.size()));
  for (const auto incarnation : value.history) w.strong(incarnation);
}

[[nodiscard]] bool decode_incarnation_entry(Reader& r, DeviceIncarnationEntry& value) noexcept {
  if (!decode_device_identity(r, value.device)) return false;
  if (!r.strong(value.current)) return false;
  const std::uint32_t count = r.u32();
  if (!r.ok()) return false;
  if (count > kMaxCollectionEntries) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.history.clear();
  value.history.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!r.strong(value.history[i])) return false;
  }
  return true;
}

void encode_stats(Writer& w, const RegistryStats& value) {
  w.u64(value.devices);
  w.u64(value.incarnations);
  w.u64(value.streams);
  w.u64(value.records_total);
  w.u64(value.records_active);
  w.u64(value.records_superseded);
  w.u64(value.records_retired);
  w.u64(value.records_rejected);
  w.u64(value.records_fenced);
  w.u64(value.records_stale);
  w.u64(value.records_outranked);
  w.u64(value.records_evicted);
  w.u64(value.conflicts_open);
  w.u64(value.conflicts_resolved);
  w.u64(value.tombstones);
  w.u64(value.resolutions);
  w.u64(value.eviction_ledger_dropped);
  w.u64(value.conflicts_dropped);
  w.u64(value.resolutions_dropped);
  w.u64(value.tombstones_dropped);
  w.u64(value.decisions_emitted);
  w.u64(value.decisions_evicted);
  w.u64(value.admissions_accepted);
  w.u64(value.admissions_idempotent);
  w.u64(value.admissions_rejected);
  w.u64(value.retirements_accepted);
  w.u64(value.retirements_rejected);
  w.strong(value.registry_epoch);
  w.strong(value.rule_generation);
  w.strong(value.policy_revision);
  w.strong(value.boot_epoch);
  w.strong(value.logical_tick);
}

[[nodiscard]] bool decode_stats(Reader& r, RegistryStats& value) noexcept {
  value.devices = r.u64();
  value.incarnations = r.u64();
  value.streams = r.u64();
  value.records_total = r.u64();
  value.records_active = r.u64();
  value.records_superseded = r.u64();
  value.records_retired = r.u64();
  value.records_rejected = r.u64();
  value.records_fenced = r.u64();
  value.records_stale = r.u64();
  value.records_outranked = r.u64();
  value.records_evicted = r.u64();
  value.conflicts_open = r.u64();
  value.conflicts_resolved = r.u64();
  value.tombstones = r.u64();
  value.resolutions = r.u64();
  value.eviction_ledger_dropped = r.u64();
  value.conflicts_dropped = r.u64();
  value.resolutions_dropped = r.u64();
  value.tombstones_dropped = r.u64();
  value.decisions_emitted = r.u64();
  value.decisions_evicted = r.u64();
  value.admissions_accepted = r.u64();
  value.admissions_idempotent = r.u64();
  value.admissions_rejected = r.u64();
  value.retirements_accepted = r.u64();
  value.retirements_rejected = r.u64();
  if (!r.strong(value.registry_epoch)) return false;
  if (!r.strong(value.rule_generation)) return false;
  if (!r.strong(value.policy_revision)) return false;
  if (!r.strong(value.boot_epoch)) return false;
  if (!r.strong(value.logical_tick)) return false;
  return true;
}

}  // namespace

// Public canonical codecs for the identity types. The internal helpers above
// stay private so the public surface has exactly one spelling per type.

void encode(Writer& w, const DeviceIdentity& value) { encode_device_identity(w, value); }
bool decode(Reader& r, DeviceIdentity& value) { return decode_device_identity(r, value); }
void encode(Writer& w, const DeviceIncarnationRef& value) { encode_device_ref(w, value); }
bool decode(Reader& r, DeviceIncarnationRef& value) { return decode_device_ref(r, value); }
void encode(Writer& w, const SourceIncarnation& value) { encode_source_incarnation(w, value); }
bool decode(Reader& r, SourceIncarnation& value) { return decode_source_incarnation(r, value); }
void encode(Writer& w, const EvidenceKey& value) { encode_evidence_key(w, value); }
bool decode(Reader& r, EvidenceKey& value) { return decode_evidence_key(r, value); }
void encode(Writer& w, const EvidenceId& value) { encode_evidence_id(w, value); }
bool decode(Reader& r, EvidenceId& value) { return decode_evidence_id(r, value); }
void encode(Writer& w, const ConflictId& value) { encode_conflict_id(w, value); }
bool decode(Reader& r, ConflictId& value) { return decode_conflict_id(r, value); }
void encode(Writer& w, const DecisionId& value) { encode_decision_id(w, value); }
bool decode(Reader& r, DecisionId& value) { return decode_decision_id(r, value); }
void encode(Writer& w, const ResolutionId& value) { w.digest(value.digest()); }
bool decode(Reader& r, ResolutionId& value) {
  Digest256 digest;
  if (!r.digest(digest)) return false;
  value = ResolutionId(digest);
  return true;
}
void encode(Writer& w, const SourcePolicy& value) { encode_source_policy(w, value); }
bool decode(Reader& r, SourcePolicy& value) { return decode_source_policy(r, value); }

// --- Writer -----------------------------------------------------------------

void Writer::u8(std::uint8_t value) { buffer_.push_back(value); }

void Writer::u16(std::uint16_t value) {
  buffer_.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
  buffer_.push_back(static_cast<std::uint8_t>(value & 0xFFu));
}

void Writer::u32(std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    buffer_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

void Writer::u64(std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    buffer_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

void Writer::i64(std::int64_t value) { u64(static_cast<std::uint64_t>(value)); }

void Writer::bytes(std::span<const std::uint8_t> value) {
  u32(static_cast<std::uint32_t>(value.size()));
  buffer_.insert(buffer_.end(), value.begin(), value.end());
}

void Writer::str(std::string_view value) {
  u32(static_cast<std::uint32_t>(value.size()));
  buffer_.insert(buffer_.end(), value.begin(), value.end());
}

void Writer::name(const Name& value) {
  u8(static_cast<std::uint8_t>(value.view().size()));
  const auto view = value.view();
  buffer_.insert(buffer_.end(), view.begin(), view.end());
}

void Writer::digest(const Digest256& value) {
  buffer_.insert(buffer_.end(), value.bytes().begin(), value.bytes().end());
}

void Writer::reason(ReasonCode value) { u16(static_cast<std::uint16_t>(value)); }

void Writer::boolean(bool value) { u8(value ? 1 : 0); }

// --- Reader -----------------------------------------------------------------

bool Reader::require(std::size_t count) noexcept {
  if (!ok_) return false;
  if (count > remaining()) {
    fail(ReasonCode::RejectedTruncatedInput);
    return false;
  }
  return true;
}

std::uint8_t Reader::u8() noexcept {
  if (!require(1)) return 0;
  return data_[position_++];
}

std::uint16_t Reader::u16() noexcept {
  if (!require(2)) return 0;
  const std::uint16_t value = static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(data_[position_]) << 8) |
      static_cast<std::uint16_t>(data_[position_ + 1]));
  position_ += 2;
  return value;
}

std::uint32_t Reader::u32() noexcept {
  if (!require(4)) return 0;
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value = (value << 8) | static_cast<std::uint32_t>(data_[position_ + static_cast<std::size_t>(i)]);
  }
  position_ += 4;
  return value;
}

std::uint64_t Reader::u64() noexcept {
  if (!require(8)) return 0;
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value = (value << 8) | static_cast<std::uint64_t>(data_[position_ + static_cast<std::size_t>(i)]);
  }
  position_ += 8;
  return value;
}

std::int64_t Reader::i64() noexcept { return static_cast<std::int64_t>(u64()); }

bool Reader::boolean() noexcept {
  const std::uint8_t raw = u8();
  if (!ok_) return false;
  if (raw > 1) {
    fail(ReasonCode::RejectedMalformedDocument);
    return false;
  }
  return raw == 1;
}

std::string_view Reader::bytes() noexcept {
  const std::uint32_t length = u32();
  if (!ok_) return {};
  if (!require(length)) return {};
  const std::string_view view(reinterpret_cast<const char*>(data_.data() + position_), length);
  position_ += length;
  return view;
}

bool Reader::name(Name& out) noexcept {
  const std::uint8_t length = u8();
  if (!ok_) return false;
  if (length == 0 || length > kMaxNameLength) {
    fail(ReasonCode::RejectedMalformedName);
    return false;
  }
  if (!require(length)) return false;
  const std::string_view view(reinterpret_cast<const char*>(data_.data() + position_), length);
  position_ += length;
  const auto parsed = Name::parse(view);
  if (!parsed.has_value()) {
    fail(ReasonCode::RejectedMalformedName);
    return false;
  }
  out = *parsed;
  return true;
}

bool Reader::digest(Digest256& out) noexcept {
  if (!require(kDigestBytes)) return false;
  std::array<std::uint8_t, kDigestBytes> bytes{};
  for (std::size_t i = 0; i < kDigestBytes; ++i) bytes[i] = data_[position_ + i];
  position_ += kDigestBytes;
  out = Digest256(bytes);
  return true;
}

bool Reader::reason(ReasonCode& out) noexcept {
  const std::uint16_t raw = u16();
  if (!ok_) return false;
  if (!reason_from(raw, out)) {
    fail(ReasonCode::RejectedMalformedDocument);
    return false;
  }
  return true;
}

// --- Value codecs -----------------------------------------------------------

void encode(Writer& w, const SemVer& value) {
  w.u32(value.major());
  w.u32(value.minor());
  w.u32(value.patch());
  w.str(value.prerelease());
  w.str(value.build());
}

bool decode(Reader& r, SemVer& value) {
  const std::uint32_t major = r.u32();
  const std::uint32_t minor = r.u32();
  const std::uint32_t patch = r.u32();
  if (!r.ok()) return false;
  const std::string_view prerelease = r.bytes();
  const std::string_view build = r.bytes();
  if (!r.ok()) return false;
  if (prerelease.size() > kMaxSemVerQualifierLength || build.size() > kMaxSemVerQualifierLength) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  SemVer parsed(major, minor, patch);
  // Re-parse through the canonical text form so the decoded value can never
  // differ from what a textual round trip would produce.
  std::string text = parsed.str();
  if (!prerelease.empty()) {
    text.push_back('-');
    text.append(prerelease);
  }
  if (!build.empty()) {
    text.push_back('+');
    text.append(build);
  }
  const auto canonical = SemVer::parse(text);
  if (!canonical.has_value()) {
    r.fail(ReasonCode::RejectedMalformedVersion);
    return false;
  }
  value = *canonical;
  return true;
}

void encode(Writer& w, const Unit& value) {
  w.u16(static_cast<std::uint16_t>(value.code));
  w.u8(static_cast<std::uint8_t>(value.scale));
  w.u8(value.exponent);
}

bool decode(Reader& r, Unit& value) {
  const std::uint16_t code = r.u16();
  const std::uint8_t scale = r.u8();
  const std::uint8_t exponent = r.u8();
  if (!r.ok()) return false;
  Unit parsed{};
  parsed.code = static_cast<UnitCode>(code);
  if (scale > static_cast<std::uint8_t>(UnitScale::Binary)) {
    r.fail(ReasonCode::RejectedLimitUnitScaleInvalid);
    return false;
  }
  parsed.scale = static_cast<UnitScale>(scale);
  parsed.exponent = exponent;
  if (!unit_is_well_formed(parsed)) {
    r.fail(ReasonCode::RejectedLimitUnitInvalid);
    return false;
  }
  value = parsed;
  return true;
}

void encode(Writer& w, const FeatureSet& value) {
  w.u32(static_cast<std::uint32_t>(value.codes().size()));
  for (const auto code : value.codes()) encode(w, code);
}

bool decode(Reader& r, FeatureSet& value) {
  const std::uint32_t count = r.u32();
  if (!r.ok()) return false;
  if (count > kMaxFeaturesPerRecord) {
    r.fail(ReasonCode::RejectedFeatureBudgetExceeded);
    return false;
  }
  std::vector<FeatureCode> codes;
  codes.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    FeatureCode code{};
    if (!decode(r, code)) return false;
    if (!codes.empty() && !(codes.back() < code)) {
      r.fail(ReasonCode::RejectedDuplicateKey);
      return false;
    }
    codes.push_back(code);
  }
  value = FeatureSet::from_validated(std::move(codes));
  return true;
}

void encode(Writer& w, const LimitValue& value) {
  encode(w, value.code);
  encode(w, value.unit);
  w.i64(value.value);
}

bool decode(Reader& r, LimitValue& value) {
  LimitValue parsed{};
  if (!decode(r, parsed.code)) return false;
  if (!decode(r, parsed.unit)) return false;
  parsed.value = r.i64();
  if (!r.ok()) return false;
  if (parsed.value < 0) {
    r.fail(ReasonCode::RejectedNegativeLimit);
    return false;
  }
  if (limit_info(parsed.code) == nullptr) {
    r.fail(ReasonCode::RejectedUnknownLimitCode);
    return false;
  }
  if (parsed.unit.code != limit_info(parsed.code)->unit) {
    r.fail(ReasonCode::RejectedLimitUnitInvalid);
    return false;
  }
  if (!unit_valid_for_limit(parsed.code, parsed.unit)) {
    r.fail(ReasonCode::RejectedLimitScaleNotPermitted);
    return false;
  }
  value = parsed;
  return true;
}

void encode(Writer& w, const LimitSet& value) {
  w.u32(static_cast<std::uint32_t>(value.values().size()));
  for (const auto& entry : value.values()) encode(w, entry);
}

bool decode(Reader& r, LimitSet& value) {
  const std::uint32_t count = r.u32();
  if (!r.ok()) return false;
  if (count > kMaxLimitsPerRecord) {
    r.fail(ReasonCode::RejectedLimitBudgetExceeded);
    return false;
  }
  std::vector<LimitValue> values;
  values.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    LimitValue entry{};
    if (!decode(r, entry)) return false;
    if (!values.empty() && !(values.back().code < entry.code)) {
      r.fail(ReasonCode::RejectedDuplicateKey);
      return false;
    }
    values.push_back(entry);
  }
  value = LimitSet::from_validated(std::move(values));
  return true;
}

bool canonical_order_ok(const FeatureSet& set) noexcept {
  const auto& codes = set.codes();
  for (std::size_t i = 1; i < codes.size(); ++i) {
    if (!(static_cast<std::uint32_t>(codes[i - 1]) < static_cast<std::uint32_t>(codes[i]))) {
      return false;
    }
  }
  return true;
}

bool canonical_order_ok(const LimitSet& set) noexcept {
  const auto& values = set.values();
  for (std::size_t i = 1; i < values.size(); ++i) {
    if (!(values[i - 1].code < values[i].code)) return false;
  }
  return true;
}

// --- Evidence ---------------------------------------------------------------

void encode(Writer& w, const CapabilityEvidence& value) {
  encode_evidence_key(w, value.key);
  encode_source_incarnation(w, value.source_incarnation);
  encode(w, value.capability_version);
  encode(w, value.features);
  encode(w, value.limits);
  w.optional(value.firmware_version, [&w](const SemVer& version) { encode(w, version); });
  w.strong(value.firmware_generation);
  w.optional(value.runtime_version, [&w](const SemVer& version) { encode(w, version); });
  w.strong(value.runtime_generation);
  w.strong(value.observed_at);
  w.optional(value.valid_until, [&w](const Tick& tick) { w.strong(tick); });
  w.strong(value.generation);
  w.u16(static_cast<std::uint16_t>(value.authority));
  w.strong(value.epoch_at_ingest);
  w.strong(value.boot_at_ingest);
  w.strong(value.policy_revision);
}

bool decode(Reader& r, CapabilityEvidence& value) {
  CapabilityEvidence parsed{};
  if (!decode_evidence_key(r, parsed.key)) return false;
  if (!decode_source_incarnation(r, parsed.source_incarnation)) return false;
  if (!decode(r, parsed.capability_version)) return false;
  if (!decode(r, parsed.features)) return false;
  if (!decode(r, parsed.limits)) return false;
  if (!r.optional(parsed.firmware_version, [&r](SemVer& version) { return decode(r, version); })) {
    return false;
  }
  if (!r.strong(parsed.firmware_generation)) return false;
  if (!r.optional(parsed.runtime_version, [&r](SemVer& version) { return decode(r, version); })) {
    return false;
  }
  if (!r.strong(parsed.runtime_generation)) return false;
  if (!r.strong(parsed.observed_at)) return false;
  if (!r.optional(parsed.valid_until, [&r](Tick& tick) { return r.strong(tick); })) return false;
  if (!r.strong(parsed.generation)) return false;
  if (!read_enum(r, parsed.authority, authority_from, ReasonCode::RejectedMalformedDocument)) return false;
  if (!r.strong(parsed.epoch_at_ingest)) return false;
  if (!r.strong(parsed.boot_at_ingest)) return false;
  if (!r.strong(parsed.policy_revision)) return false;
  if (parsed.generation.is_unset()) {
    r.fail(ReasonCode::RejectedGenerationRegression);
    return false;
  }
  if (parsed.valid_until.has_value() && *parsed.valid_until < parsed.observed_at) {
    r.fail(ReasonCode::RejectedValidityWindowInverted);
    return false;
  }
  // Feature and limit membership against the declared capability kind.
  for (const auto code : parsed.features.codes()) {
    if (!feature_allowed_for(code, parsed.key.kind)) {
      r.fail(ReasonCode::RejectedFeatureNotInKind);
      return false;
    }
  }
  for (const auto& entry : parsed.limits.values()) {
    if (!limit_allowed_for(entry.code, parsed.key.kind)) {
      r.fail(ReasonCode::RejectedLimitNotInKind);
      return false;
    }
  }
  parsed.refresh_id();
  value = std::move(parsed);
  return true;
}

void encode(Writer& w, const StoredEvidence& value) {
  encode(w, value.evidence);
  w.u16(static_cast<std::uint16_t>(value.lifecycle));
  w.reason(value.admission_reason);
  w.strong(value.admitted_at);
  w.optional(value.retired_at, [&w](const Tick& tick) { w.strong(tick); });
  w.reason(value.retirement_reason);
}

bool decode(Reader& r, StoredEvidence& value) {
  StoredEvidence parsed{};
  if (!decode(r, parsed.evidence)) return false;
  if (!read_enum(r, parsed.lifecycle, lifecycle_from, ReasonCode::RejectedMalformedDocument)) return false;
  if (!r.reason(parsed.admission_reason)) return false;
  if (!r.strong(parsed.admitted_at)) return false;
  if (!r.optional(parsed.retired_at, [&r](Tick& tick) { return r.strong(tick); })) return false;
  if (!r.reason(parsed.retirement_reason)) return false;
  if (parsed.lifecycle == EvidenceLifecycle::Retired && !parsed.retired_at.has_value()) {
    r.fail(ReasonCode::RejectedMalformedDocument);
    return false;
  }
  value = std::move(parsed);
  return true;
}

void encode(Writer& w, const RetirementRecord& value) {
  encode_evidence_key(w, value.key);
  w.strong(value.generation);
  w.strong(value.retired_at);
  w.reason(value.reason);
  w.strong(value.epoch);
  w.strong(value.policy_revision);
  w.u16(static_cast<std::uint16_t>(value.authority));
}

bool decode(Reader& r, RetirementRecord& value) {
  RetirementRecord parsed{};
  if (!decode_evidence_key(r, parsed.key)) return false;
  if (!r.strong(parsed.generation)) return false;
  if (!r.strong(parsed.retired_at)) return false;
  if (!r.reason(parsed.reason)) return false;
  if (!r.strong(parsed.epoch)) return false;
  if (!r.strong(parsed.policy_revision)) return false;
  if (!read_enum(r, parsed.authority, authority_from, ReasonCode::RejectedMalformedDocument)) return false;
  if (parsed.generation.is_unset()) {
    r.fail(ReasonCode::RejectedGenerationRegression);
    return false;
  }
  value = parsed;
  return true;
}

void encode(Writer& w, const ConflictGroup& value) {
  encode_conflict_id(w, value.id);
  encode_device_ref(w, value.device);
  encode(w, value.kind);
  w.u16(static_cast<std::uint16_t>(value.authority));
  w.u32(static_cast<std::uint32_t>(value.members.size()));
  for (const auto& member : value.members) encode_evidence_id(w, member);
  w.u32(static_cast<std::uint32_t>(value.generations.size()));
  for (const auto generation : value.generations) w.strong(generation);
  w.strong(value.observed_first);
  w.strong(value.observed_last);
}

bool decode(Reader& r, ConflictGroup& value) {
  ConflictGroup parsed{};
  if (!decode_conflict_id(r, parsed.id)) return false;
  if (!decode_device_ref(r, parsed.device)) return false;
  if (!decode(r, parsed.kind)) return false;
  if (!read_enum(r, parsed.authority, authority_from, ReasonCode::RejectedMalformedDocument)) return false;
  const std::uint32_t member_count = r.u32();
  if (!r.ok()) return false;
  if (member_count > kMaxCollectionEntries) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  parsed.members.clear();
  parsed.members.resize(member_count);
  for (std::uint32_t i = 0; i < member_count; ++i) {
    if (!decode_evidence_id(r, parsed.members[i])) return false;
  }
  const std::uint32_t generation_count = r.u32();
  if (!r.ok()) return false;
  if (generation_count > kMaxCollectionEntries || generation_count != member_count) {
    r.fail(ReasonCode::RejectedMalformedDocument);
    return false;
  }
  parsed.generations.clear();
  parsed.generations.resize(generation_count);
  for (std::uint32_t i = 0; i < generation_count; ++i) {
    if (!r.strong(parsed.generations[i])) return false;
  }
  if (!r.strong(parsed.observed_first)) return false;
  if (!r.strong(parsed.observed_last)) return false;
  value = std::move(parsed);
  return true;
}

void encode(Writer& w, const ConflictResolution& value) {
  w.digest(value.id.digest());
  encode_conflict_id(w, value.conflict);
  encode_evidence_id(w, value.chosen);
  w.u32(static_cast<std::uint32_t>(value.rejected_members.size()));
  for (const auto& member : value.rejected_members) encode_evidence_id(w, member);
  w.name_id(value.resolver);
  w.strong(value.resolved_at);
  w.strong(value.epoch);
}

bool decode(Reader& r, ConflictResolution& value) {
  ConflictResolution parsed{};
  Digest256 id_digest;
  if (!r.digest(id_digest)) return false;
  parsed.id = ResolutionId(id_digest);
  if (!decode_conflict_id(r, parsed.conflict)) return false;
  if (!decode_evidence_id(r, parsed.chosen)) return false;
  const std::uint32_t count = r.u32();
  if (!r.ok()) return false;
  if (count > kMaxCollectionEntries) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  parsed.rejected_members.clear();
  parsed.rejected_members.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!decode_evidence_id(r, parsed.rejected_members[i])) return false;
  }
  if (!r.name_id(parsed.resolver)) return false;
  if (!r.strong(parsed.resolved_at)) return false;
  if (!r.strong(parsed.epoch)) return false;
  value = std::move(parsed);
  return true;
}

void encode(Writer& w, const EvictionEntry& value) {
  encode_evidence_id(w, value.id);
  encode_evidence_key(w, value.key);
  w.strong(value.generation);
  w.u16(static_cast<std::uint16_t>(value.state_at_eviction));
  w.reason(value.reason);
  w.strong(value.evicted_at);
}

bool decode(Reader& r, EvictionEntry& value) {
  EvictionEntry parsed{};
  if (!decode_evidence_id(r, parsed.id)) return false;
  if (!decode_evidence_key(r, parsed.key)) return false;
  if (!r.strong(parsed.generation)) return false;
  if (!read_enum(r, parsed.state_at_eviction, evidence_state_from,
                 ReasonCode::RejectedMalformedDocument)) {
    return false;
  }
  if (!r.reason(parsed.reason)) return false;
  if (!r.strong(parsed.evicted_at)) return false;
  value = parsed;
  return true;
}

void canonicalize_reasons(std::vector<ReasonCode>& reasons) {
  std::sort(reasons.begin(), reasons.end(), [](ReasonCode a, ReasonCode b) {
    return static_cast<std::uint16_t>(a) < static_cast<std::uint16_t>(b);
  });
  reasons.erase(std::unique(reasons.begin(), reasons.end()), reasons.end());
}

std::vector<ReasonCode> canonical_reasons(std::vector<ReasonCode> reasons) {
  canonicalize_reasons(reasons);
  return reasons;
}

// --- Requirements and decisions ---------------------------------------------

void encode(Writer& w, const LimitRequirement& value) {
  encode(w, value.code);
  encode(w, value.unit);
  w.i64(value.minimum);
}

bool decode(Reader& r, LimitRequirement& value) {
  LimitRequirement parsed{};
  if (!decode(r, parsed.code)) return false;
  if (!decode(r, parsed.unit)) return false;
  parsed.minimum = r.i64();
  if (!r.ok()) return false;
  if (parsed.minimum < 0) {
    r.fail(ReasonCode::RejectedNegativeLimit);
    return false;
  }
  if (limit_info(parsed.code) == nullptr) {
    r.fail(ReasonCode::RejectedUnknownLimitCode);
    return false;
  }
  if (parsed.unit.code != limit_info(parsed.code)->unit) {
    r.fail(ReasonCode::RejectedLimitUnitInvalid);
    return false;
  }
  if (!unit_valid_for_limit(parsed.code, parsed.unit)) {
    r.fail(ReasonCode::RejectedLimitScaleNotPermitted);
    return false;
  }
  value = parsed;
  return true;
}

void encode(Writer& w, const CapabilityRequirement& value) {
  encode_device_ref(w, value.device);
  encode(w, value.capability);
  encode(w, value.version.minimum);
  w.optional(value.version.maximum_exclusive, [&w](const SemVer& version) { encode(w, version); });
  encode(w, value.required_features);
  w.u32(static_cast<std::uint32_t>(value.required_limits.size()));
  for (const auto& limit : value.required_limits) encode(w, limit);
  w.optional(value.minimum_firmware_version, [&w](const SemVer& version) { encode(w, version); });
  w.optional(value.minimum_firmware_generation,
             [&w](const FirmwareGeneration& generation) { w.strong(generation); });
  w.optional(value.minimum_runtime_version, [&w](const SemVer& version) { encode(w, version); });
  w.optional(value.minimum_runtime_generation,
             [&w](const RuntimeGeneration& generation) { w.strong(generation); });
  w.strong(value.max_evidence_age);
}

bool decode(Reader& r, CapabilityRequirement& value) {
  CapabilityRequirement parsed{};
  if (!decode_device_ref(r, parsed.device)) return false;
  if (!decode(r, parsed.capability)) return false;
  if (!decode(r, parsed.version.minimum)) return false;
  if (!r.optional(parsed.version.maximum_exclusive,
                  [&r](SemVer& version) { return decode(r, version); })) {
    return false;
  }
  if (!decode(r, parsed.required_features)) return false;
  const std::uint32_t limit_count = r.u32();
  if (!r.ok()) return false;
  if (limit_count > kMaxLimitsPerRecord) {
    r.fail(ReasonCode::RejectedLimitBudgetExceeded);
    return false;
  }
  parsed.required_limits.clear();
  parsed.required_limits.resize(limit_count);
  for (std::uint32_t i = 0; i < limit_count; ++i) {
    if (!decode(r, parsed.required_limits[i])) return false;
    if (i > 0 && !(parsed.required_limits[i - 1].code < parsed.required_limits[i].code)) {
      r.fail(ReasonCode::RejectedDuplicateKey);
      return false;
    }
  }
  if (!r.optional(parsed.minimum_firmware_version,
                  [&r](SemVer& version) { return decode(r, version); })) {
    return false;
  }
  if (!r.optional(parsed.minimum_firmware_generation,
                  [&r](FirmwareGeneration& generation) { return r.strong(generation); })) {
    return false;
  }
  if (!r.optional(parsed.minimum_runtime_version,
                  [&r](SemVer& version) { return decode(r, version); })) {
    return false;
  }
  if (!r.optional(parsed.minimum_runtime_generation,
                  [&r](RuntimeGeneration& generation) { return r.strong(generation); })) {
    return false;
  }
  if (!r.strong(parsed.max_evidence_age)) return false;
  for (const auto code : parsed.required_features.codes()) {
    if (!feature_allowed_for(code, parsed.capability)) {
      r.fail(ReasonCode::RejectedFeatureNotInKind);
      return false;
    }
  }
  for (const auto& limit : parsed.required_limits) {
    if (!limit_allowed_for(limit.code, parsed.capability)) {
      r.fail(ReasonCode::RejectedLimitNotInKind);
      return false;
    }
  }
  value = std::move(parsed);
  return true;
}

void encode(Writer& w, const Status& value) {
  w.reason(value.code);
  w.str(value.detail);
}

bool decode(Reader& r, Status& value) {
  if (!r.reason(value.code)) return false;
  const std::string_view detail = r.bytes();
  if (!r.ok()) return false;
  if (detail.size() > 4096) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.detail.assign(detail);
  return true;
}

// --- Registry state ---------------------------------------------------------

void encode(Writer& w, const RegistryState& value) {
  w.u32(kStoreFormatVersion);
  encode_registry_policy(w, value.policy);
  w.strong(value.epoch);
  w.strong(value.rule_generation);
  w.strong(value.policy_revision);
  w.strong(value.boot_epoch);
  w.strong(value.store_generation);
  w.strong(value.logical_tick);
  w.u64(value.next_incarnation);

  w.u32(static_cast<std::uint32_t>(value.incarnations.size()));
  for (const auto& entry : value.incarnations) encode_incarnation_entry(w, entry);

  w.u32(static_cast<std::uint32_t>(value.records.size()));
  for (const auto& record : value.records) encode(w, record);

  w.u32(static_cast<std::uint32_t>(value.tombstones.size()));
  for (const auto& tombstone : value.tombstones) encode(w, tombstone);

  w.u32(static_cast<std::uint32_t>(value.conflicts.size()));
  for (const auto& conflict : value.conflicts) encode(w, conflict);

  w.u32(static_cast<std::uint32_t>(value.resolutions.size()));
  for (const auto& resolution : value.resolutions) encode(w, resolution);

  w.u32(static_cast<std::uint32_t>(value.evictions.size()));
  for (const auto& eviction : value.evictions) encode(w, eviction);

  encode_counters(w, value.counters);
}

bool decode(Reader& r, RegistryState& value) {
  RegistryState parsed{};
  const std::uint32_t format = r.u32();
  if (!r.ok()) return false;
  if (format != kStoreFormatVersion) {
    r.fail(ReasonCode::StoreVersionIncompatible);
    return false;
  }
  if (!decode_registry_policy(r, parsed.policy)) return false;
  if (!r.strong(parsed.epoch)) return false;
  if (!r.strong(parsed.rule_generation)) return false;
  if (!r.strong(parsed.policy_revision)) return false;
  if (!r.strong(parsed.boot_epoch)) return false;
  if (!r.strong(parsed.store_generation)) return false;
  if (!r.strong(parsed.logical_tick)) return false;
  parsed.next_incarnation = r.u64();
  if (!r.ok()) return false;
  if (parsed.next_incarnation == 0) {
    r.fail(ReasonCode::RejectedZeroIncarnation);
    return false;
  }

  const auto read_collection = [&r](auto& target, auto&& read_one) {
    const std::uint32_t count = r.u32();
    if (!r.ok()) return false;
    if (count > kMaxCollectionEntries) {
      r.fail(ReasonCode::RejectedOversizedInput);
      return false;
    }
    target.clear();
    target.resize(count);
    for (std::uint32_t i = 0; i < count; ++i) {
      if (!read_one(target[i])) return false;
    }
    return true;
  };

  if (!read_collection(parsed.incarnations,
                       [&r](DeviceIncarnationEntry& entry) { return decode_incarnation_entry(r, entry); })) {
    return false;
  }
  if (!read_collection(parsed.records,
                       [&r](StoredEvidence& record) { return decode(r, record); })) {
    return false;
  }
  if (!read_collection(parsed.tombstones,
                       [&r](RetirementRecord& record) { return decode(r, record); })) {
    return false;
  }
  if (!read_collection(parsed.conflicts,
                       [&r](ConflictGroup& group) { return decode(r, group); })) {
    return false;
  }
  if (!read_collection(parsed.resolutions,
                       [&r](ConflictResolution& resolution) { return decode(r, resolution); })) {
    return false;
  }
  if (!read_collection(parsed.evictions,
                       [&r](EvictionEntry& entry) { return decode(r, entry); })) {
    return false;
  }
  if (!decode_counters(r, parsed.counters)) return false;

  // Cross-field consistency: a state whose declared bounds cannot hold its own
  // contents is not a valid state.
  if (parsed.records.size() > parsed.policy.limits.max_records) {
    r.fail(ReasonCode::StoreSemanticMismatch);
    return false;
  }
  if (parsed.tombstones.size() > parsed.policy.limits.max_tombstones) {
    r.fail(ReasonCode::StoreSemanticMismatch);
    return false;
  }
  for (std::size_t i = 1; i < parsed.policy.sources.size(); ++i) {
    if (!(parsed.policy.sources[i - 1].id < parsed.policy.sources[i].id)) {
      r.fail(ReasonCode::StoreSemanticMismatch);
      return false;
    }
  }
  value = std::move(parsed);
  return true;
}

// --- Digests ----------------------------------------------------------------

void encode(Writer& w, const RuleGeneration& value) { w.strong(value); }

bool decode(Reader& r, RuleGeneration& value) { return r.strong(value); }

Digest256 state_digest(const RegistryState& state) {
  Writer writer;
  encode(writer, state);
  return Digest256::of(writer.span());
}

// --- Requests ---------------------------------------------------------------

void encode(Writer& w, const AdmissionRequest& value) {
  encode_device_ref(w, value.device);
  encode(w, value.kind);
  encode_source_incarnation(w, value.source);
  encode(w, value.capability_version);
  encode(w, value.features);
  encode(w, value.limits);
  w.optional(value.firmware_version, [&w](const SemVer& version) { encode(w, version); });
  w.strong(value.firmware_generation);
  w.optional(value.runtime_version, [&w](const SemVer& version) { encode(w, version); });
  w.strong(value.runtime_generation);
  w.strong(value.observed_at);
  w.optional(value.valid_until, [&w](const Tick& tick) { w.strong(tick); });
  w.strong(value.generation);
}

bool decode(Reader& r, AdmissionRequest& value) {
  AdmissionRequest parsed{};
  if (!decode_device_ref(r, parsed.device)) return false;
  if (!decode(r, parsed.kind)) return false;
  if (!decode_source_incarnation(r, parsed.source)) return false;
  if (!decode(r, parsed.capability_version)) return false;
  if (!decode(r, parsed.features)) return false;
  if (!decode(r, parsed.limits)) return false;
  if (!r.optional(parsed.firmware_version, [&r](SemVer& version) { return decode(r, version); })) {
    return false;
  }
  if (!r.strong(parsed.firmware_generation)) return false;
  if (!r.optional(parsed.runtime_version, [&r](SemVer& version) { return decode(r, version); })) {
    return false;
  }
  if (!r.strong(parsed.runtime_generation)) return false;
  if (!r.strong(parsed.observed_at)) return false;
  if (!r.optional(parsed.valid_until, [&r](Tick& tick) { return r.strong(tick); })) return false;
  if (!r.strong(parsed.generation)) return false;
  if (parsed.generation.is_unset()) {
    r.fail(ReasonCode::RejectedGenerationRegression);
    return false;
  }
  if (parsed.valid_until.has_value() && *parsed.valid_until < parsed.observed_at) {
    r.fail(ReasonCode::RejectedValidityWindowInverted);
    return false;
  }
  value = std::move(parsed);
  return true;
}

void encode(Writer& w, const RetirementRequest& value) {
  encode_device_ref(w, value.device);
  encode(w, value.kind);
  w.name_id(value.source);
  w.strong(value.generation);
  w.strong(value.retired_at);
  w.reason(value.reason);
}

bool decode(Reader& r, RetirementRequest& value) {
  RetirementRequest parsed{};
  if (!decode_device_ref(r, parsed.device)) return false;
  if (!decode(r, parsed.kind)) return false;
  if (!r.name_id(parsed.source)) return false;
  if (!r.strong(parsed.generation)) return false;
  if (!r.strong(parsed.retired_at)) return false;
  if (!r.reason(parsed.reason)) return false;
  if (parsed.generation.is_unset()) {
    r.fail(ReasonCode::RejectedGenerationRegression);
    return false;
  }
  value = parsed;
  return true;
}

}  // namespace ocreg