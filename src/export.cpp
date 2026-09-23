// Offload Capability Registry - canonical machine-readable export/import.
// Copyright 2026 Summon Software Labs.
//
// The canonical document is the registry's external fact surface. It is
// complete (nothing correct is omitted), deterministic (identical states render
// byte-identical documents) and self-checking (it carries the digest of the
// binary state it was produced from, and import refuses a mismatch).
#include "ocreg/export.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "ocreg/codec.hpp"
#include "ocreg/evidence.hpp"
#include "ocreg/json.hpp"
#include "ocreg/persist.hpp"
#include "ocreg/version.hpp"

namespace ocreg {
namespace {

constexpr std::string_view kFormatName = "ocreg.canonical-state";

[[nodiscard]] JsonValue json_of(const Name& value) { return JsonValue::string(value.str()); }

template <class Tag>
[[nodiscard]] JsonValue json_of(NameId<Tag> value) {
  return JsonValue::string(std::string(value.view()));
}

[[nodiscard]] JsonValue json_of(const SemVer& value) { return JsonValue::string(value.str()); }

[[nodiscard]] JsonValue json_of(const Unit& value) {
  return JsonValue::string(unit_to_string(value));
}

[[nodiscard]] JsonValue json_of(const FeatureSet& value) {
  JsonValue array = JsonValue::array();
  for (const auto code : value.codes()) {
    array.push(JsonValue::string(std::string(to_string(code))));
  }
  return array;
}

[[nodiscard]] JsonValue json_of(const LimitSet& value) {
  JsonValue array = JsonValue::array();
  for (const auto& entry : value.values()) {
    JsonValue item = JsonValue::object();
    item.set("code", JsonValue::string(std::string(to_string(entry.code))));
    item.set("unit", json_of(entry.unit));
    item.set("value", JsonValue::integer(entry.value));
    array.push(std::move(item));
  }
  return array;
}

[[nodiscard]] JsonValue json_of(const DeviceIdentity& value) {
  JsonValue object = JsonValue::object();
  object.set("provider", json_of(value.provider));
  object.set("model", json_of(value.model));
  object.set("unit_index", JsonValue::integer(value.unit_index));
  if (value.serial.has_value()) object.set("serial", json_of(*value.serial));
  return object;
}

[[nodiscard]] JsonValue json_of(const DeviceIncarnationRef& value) {
  JsonValue object = JsonValue::object();
  object.set("device", json_of(value.device));
  object.set("incarnation", JsonValue::integer(static_cast<std::int64_t>(value.incarnation.value())));
  return object;
}

[[nodiscard]] JsonValue json_of(const SourceIncarnation& value) {
  JsonValue object = JsonValue::object();
  object.set("source", json_of(value.source));
  object.set("counter", JsonValue::integer(static_cast<std::int64_t>(value.counter.value())));
  return object;
}

[[nodiscard]] JsonValue json_of(const SourcePolicy& value) {
  JsonValue object = JsonValue::object();
  object.set("id", json_of(value.id));
  object.set("kind", JsonValue::string(std::string(to_string(value.kind))));
  object.set("authority", JsonValue::string(std::string(to_string(value.authority))));
  object.set("trust", JsonValue::string(std::string(to_string(value.trust))));
  object.set("max_age", JsonValue::integer(static_cast<std::int64_t>(value.max_age.value())));
  object.set("durable_across_boot", JsonValue::boolean(value.durable_across_boot));
  return object;
}

[[nodiscard]] JsonValue json_of(const RegistryLimits& value) {
  JsonValue object = JsonValue::object();
  object.set("max_conflict_groups", JsonValue::integer(static_cast<std::int64_t>(value.max_conflict_groups)));
  object.set("max_decisions", JsonValue::integer(static_cast<std::int64_t>(value.max_decisions)));
  object.set("max_devices", JsonValue::integer(static_cast<std::int64_t>(value.max_devices)));
  object.set("max_eviction_ledger", JsonValue::integer(static_cast<std::int64_t>(value.max_eviction_ledger)));
  object.set("max_features_per_record", JsonValue::integer(static_cast<std::int64_t>(value.max_features_per_record)));
  object.set("max_incarnations_per_device", JsonValue::integer(static_cast<std::int64_t>(value.max_incarnations_per_device)));
  object.set("max_limits_per_record", JsonValue::integer(static_cast<std::int64_t>(value.max_limits_per_record)));
  object.set("max_limits_per_requirement", JsonValue::integer(static_cast<std::int64_t>(value.max_limits_per_requirement)));
  object.set("max_records", JsonValue::integer(static_cast<std::int64_t>(value.max_records)));
  object.set("max_records_per_stream", JsonValue::integer(static_cast<std::int64_t>(value.max_records_per_stream)));
  object.set("max_required_features", JsonValue::integer(static_cast<std::int64_t>(value.max_required_features)));
  object.set("max_resolutions", JsonValue::integer(static_cast<std::int64_t>(value.max_resolutions)));
  object.set("max_sources", JsonValue::integer(static_cast<std::int64_t>(value.max_sources)));
  object.set("max_streams", JsonValue::integer(static_cast<std::int64_t>(value.max_streams)));
  object.set("max_tombstones", JsonValue::integer(static_cast<std::int64_t>(value.max_tombstones)));
  return object;
}

[[nodiscard]] JsonValue json_of(const RegistryPolicy& value) {
  JsonValue object = JsonValue::object();
  JsonValue sources = JsonValue::array();
  for (const auto& source : value.sources) sources.push(json_of(source));
  object.set("sources", std::move(sources));
  object.set("require_configured_source", JsonValue::boolean(value.require_configured_source));
  object.set("refuse_untrusted_sources", JsonValue::boolean(value.refuse_untrusted_sources));
  object.set("boot_policy", JsonValue::string(std::string(to_string(value.boot_policy))));
  object.set("clock_mode", JsonValue::string(std::string(to_string(value.clock_mode))));
  object.set("retention_horizon", JsonValue::integer(static_cast<std::int64_t>(value.retention_horizon.value())));
  object.set("max_future_skew", JsonValue::integer(static_cast<std::int64_t>(value.max_future_skew.value())));
  object.set("default_max_age", JsonValue::integer(static_cast<std::int64_t>(value.default_max_age.value())));
  object.set("limits", json_of(value.limits));
  object.set("rule_generation", JsonValue::integer(static_cast<std::int64_t>(value.rule_generation.value())));
  object.set("policy_name", JsonValue::string(value.policy_name));
  return object;
}

[[nodiscard]] JsonValue json_of(const StoredEvidence& value) {
  const CapabilityEvidence& e = value.evidence;
  JsonValue object = JsonValue::object();
  object.set("id", JsonValue::string(e.id().hex()));
  object.set("device", json_of(e.key.device));
  object.set("capability_kind", JsonValue::string(std::string(to_string(e.key.kind))));
  object.set("source", json_of(e.source_incarnation));
  object.set("capability_version", json_of(e.capability_version));
  object.set("features", json_of(e.features));
  object.set("limits", json_of(e.limits));
  if (e.firmware_version.has_value()) object.set("firmware_version", json_of(*e.firmware_version));
  object.set("firmware_generation", JsonValue::integer(static_cast<std::int64_t>(e.firmware_generation.value())));
  if (e.runtime_version.has_value()) object.set("runtime_version", json_of(*e.runtime_version));
  object.set("runtime_generation", JsonValue::integer(static_cast<std::int64_t>(e.runtime_generation.value())));
  object.set("observed_at", JsonValue::integer(static_cast<std::int64_t>(e.observed_at.value())));
  if (e.valid_until.has_value()) {
    object.set("valid_until", JsonValue::integer(static_cast<std::int64_t>(e.valid_until->value())));
  }
  object.set("generation", JsonValue::integer(static_cast<std::int64_t>(e.generation.value())));
  object.set("authority", JsonValue::string(std::string(to_string(e.authority))));
  object.set("epoch_at_ingest", JsonValue::integer(static_cast<std::int64_t>(e.epoch_at_ingest.value())));
  object.set("boot_at_ingest", JsonValue::integer(static_cast<std::int64_t>(e.boot_at_ingest.value())));
  object.set("evidence_policy_revision", JsonValue::integer(static_cast<std::int64_t>(e.policy_revision.value())));
  object.set("lifecycle", JsonValue::string(std::string(to_string(value.lifecycle))));
  object.set("admission_reason", JsonValue::string(std::string(to_string(value.admission_reason))));
  object.set("admitted_at", JsonValue::integer(static_cast<std::int64_t>(value.admitted_at.value())));
  if (value.retired_at.has_value()) {
    object.set("retired_at", JsonValue::integer(static_cast<std::int64_t>(value.retired_at->value())));
  }
  object.set("retirement_reason", JsonValue::string(std::string(to_string(value.retirement_reason))));
  return object;
}

[[nodiscard]] JsonValue json_of(const RetirementRecord& value) {
  JsonValue object = JsonValue::object();
  object.set("device", json_of(value.key.device));
  object.set("capability_kind", JsonValue::string(std::string(to_string(value.key.kind))));
  object.set("source", json_of(value.key.source));
  object.set("generation", JsonValue::integer(static_cast<std::int64_t>(value.generation.value())));
  object.set("retired_at", JsonValue::integer(static_cast<std::int64_t>(value.retired_at.value())));
  object.set("reason", JsonValue::string(std::string(to_string(value.reason))));
  object.set("epoch", JsonValue::integer(static_cast<std::int64_t>(value.epoch.value())));
  object.set("policy_revision", JsonValue::integer(static_cast<std::int64_t>(value.policy_revision.value())));
  object.set("authority", JsonValue::string(std::string(to_string(value.authority))));
  return object;
}

[[nodiscard]] JsonValue json_of(const ConflictGroup& value) {
  JsonValue object = JsonValue::object();
  object.set("id", JsonValue::string(value.id.hex()));
  object.set("device", json_of(value.device));
  object.set("capability_kind", JsonValue::string(std::string(to_string(value.kind))));
  object.set("authority", JsonValue::string(std::string(to_string(value.authority))));
  JsonValue members = JsonValue::array();
  for (const auto& member : value.members) members.push(JsonValue::string(member.hex()));
  object.set("members", std::move(members));
  JsonValue generations = JsonValue::array();
  for (const auto generation : value.generations) {
    generations.push(JsonValue::integer(static_cast<std::int64_t>(generation.value())));
  }
  object.set("generations", std::move(generations));
  object.set("observed_first", JsonValue::integer(static_cast<std::int64_t>(value.observed_first.value())));
  object.set("observed_last", JsonValue::integer(static_cast<std::int64_t>(value.observed_last.value())));
  return object;
}

[[nodiscard]] JsonValue json_of(const ConflictResolution& value) {
  JsonValue object = JsonValue::object();
  object.set("id", JsonValue::string(value.id.hex()));
  object.set("conflict", JsonValue::string(value.conflict.hex()));
  object.set("chosen", JsonValue::string(value.chosen.hex()));
  JsonValue rejected = JsonValue::array();
  for (const auto& member : value.rejected_members) rejected.push(JsonValue::string(member.hex()));
  object.set("rejected_members", std::move(rejected));
  object.set("resolver", json_of(value.resolver));
  object.set("resolved_at", JsonValue::integer(static_cast<std::int64_t>(value.resolved_at.value())));
  object.set("epoch", JsonValue::integer(static_cast<std::int64_t>(value.epoch.value())));
  return object;
}

[[nodiscard]] JsonValue json_of(const EvictionEntry& value) {
  JsonValue object = JsonValue::object();
  object.set("id", JsonValue::string(value.id.hex()));
  object.set("device", json_of(value.key.device));
  object.set("capability_kind", JsonValue::string(std::string(to_string(value.key.kind))));
  object.set("source", json_of(value.key.source));
  object.set("generation", JsonValue::integer(static_cast<std::int64_t>(value.generation.value())));
  object.set("state_at_eviction", JsonValue::string(std::string(to_string(value.state_at_eviction))));
  object.set("reason", JsonValue::string(std::string(to_string(value.reason))));
  object.set("evicted_at", JsonValue::integer(static_cast<std::int64_t>(value.evicted_at.value())));
  return object;
}

[[nodiscard]] JsonValue json_of(const DeviceIncarnationEntry& value) {
  JsonValue object = JsonValue::object();
  object.set("device", json_of(value.device));
  object.set("current", JsonValue::integer(static_cast<std::int64_t>(value.current.value())));
  JsonValue history = JsonValue::array();
  for (const auto incarnation : value.history) {
    history.push(JsonValue::integer(static_cast<std::int64_t>(incarnation.value())));
  }
  object.set("history", std::move(history));
  return object;
}

[[nodiscard]] JsonValue json_of(const RegistryCounters& value) {
  JsonValue object = JsonValue::object();
  object.set("admissions_accepted", JsonValue::integer(static_cast<std::int64_t>(value.admissions_accepted)));
  object.set("admissions_idempotent", JsonValue::integer(static_cast<std::int64_t>(value.admissions_idempotent)));
  object.set("admissions_rejected", JsonValue::integer(static_cast<std::int64_t>(value.admissions_rejected)));
  object.set("retirements_accepted", JsonValue::integer(static_cast<std::int64_t>(value.retirements_accepted)));
  object.set("retirements_rejected", JsonValue::integer(static_cast<std::int64_t>(value.retirements_rejected)));
  object.set("decisions_emitted", JsonValue::integer(static_cast<std::int64_t>(value.decisions_emitted)));
  object.set("decisions_evicted", JsonValue::integer(static_cast<std::int64_t>(value.decisions_evicted)));
  object.set("conflicts_resolved", JsonValue::integer(static_cast<std::int64_t>(value.conflicts_resolved)));
  object.set("evictions_total", JsonValue::integer(static_cast<std::int64_t>(value.evictions_total)));
  object.set("eviction_ledger_dropped", JsonValue::integer(static_cast<std::int64_t>(value.eviction_ledger_dropped)));
  object.set("conflicts_dropped", JsonValue::integer(static_cast<std::int64_t>(value.conflicts_dropped)));
  object.set("resolutions_dropped", JsonValue::integer(static_cast<std::int64_t>(value.resolutions_dropped)));
  object.set("tombstones_dropped", JsonValue::integer(static_cast<std::int64_t>(value.tombstones_dropped)));
  return object;
}

// --- Parsing helpers --------------------------------------------------------

[[nodiscard]] bool value_missing(const JsonValue& object, std::string_view key) noexcept {
  return object.find(key) == nullptr;
}

[[nodiscard]] bool read_string(const JsonValue& object, std::string_view key, std::string& out,
                               ReasonCode& reason, bool required = true) {
  const JsonValue* value = object.find(key);
  if (value == nullptr) {
    reason = required ? ReasonCode::RejectedMissingField : ReasonCode::Ok;
    return !required;
  }
  if (!value->is_string()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out = value->as_string();
  return true;
}

[[nodiscard]] bool read_integer(const JsonValue& object, std::string_view key, std::int64_t& out,
                                ReasonCode& reason, bool required = true) {
  const JsonValue* value = object.find(key);
  if (value == nullptr) {
    reason = required ? ReasonCode::RejectedMissingField : ReasonCode::Ok;
    return !required;
  }
  if (!value->is_integer()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out = value->as_integer();
  return true;
}

[[nodiscard]] bool read_bool(const JsonValue& object, std::string_view key, bool& out,
                             ReasonCode& reason) {
  const JsonValue* value = object.find(key);
  if (value == nullptr) {
    reason = ReasonCode::RejectedMissingField;
    return false;
  }
  if (!value->is_bool()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out = value->as_bool();
  return true;
}

[[nodiscard]] bool read_u64(const JsonValue& object, std::string_view key, std::uint64_t& out,
                            ReasonCode& reason, bool required = true) {
  std::int64_t raw = 0;
  if (!read_integer(object, key, raw, reason, required)) return false;
  if (value_missing(object, key)) return true;
  if (raw < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out = static_cast<std::uint64_t>(raw);
  return true;
}

[[nodiscard]] bool read_name(const JsonValue& object, std::string_view key, Name& out,
                             ReasonCode& reason) {
  std::string text;
  if (!read_string(object, key, text, reason)) return false;
  const auto parsed = Name::parse(text);
  if (!parsed.has_value()) {
    reason = ReasonCode::RejectedMalformedName;
    return false;
  }
  out = *parsed;
  return true;
}

template <class Tag>
[[nodiscard]] bool read_name_id(const JsonValue& object, std::string_view key, NameId<Tag>& out,
                                ReasonCode& reason) {
  Name parsed;
  if (!read_name(object, key, parsed, reason)) return false;
  out = NameId<Tag>(parsed);
  return true;
}

[[nodiscard]] bool read_digest(const JsonValue& object, std::string_view key, Digest256& out,
                               ReasonCode& reason) {
  std::string text;
  if (!read_string(object, key, text, reason)) return false;
  if (!Digest256::parse(text, out)) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  return true;
}

[[nodiscard]] bool read_semver(const JsonValue& object, std::string_view key, SemVer& out,
                               ReasonCode& reason) {
  std::string text;
  if (!read_string(object, key, text, reason)) return false;
  const auto parsed = SemVer::parse(text);
  if (!parsed.has_value()) {
    reason = ReasonCode::RejectedMalformedVersion;
    return false;
  }
  out = *parsed;
  return true;
}

[[nodiscard]] bool read_unit(const JsonValue& object, std::string_view key, Unit& out,
                             ReasonCode& reason) {
  std::string text;
  if (!read_string(object, key, text, reason)) return false;
  if (!parse_unit(text, out)) {
    reason = ReasonCode::RejectedLimitUnitInvalid;
    return false;
  }
  return true;
}

template <class Enum, class Parse>
[[nodiscard]] bool read_enum(const JsonValue& object, std::string_view key, Enum& out,
                             ReasonCode& reason, Parse&& parse) {
  std::string text;
  if (!read_string(object, key, text, reason)) return false;
  if (!parse(text, out)) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  return true;
}

[[nodiscard]] bool read_device(const JsonValue& value, DeviceIdentity& out, ReasonCode& reason) {
  if (!value.is_object()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  if (!read_name_id(value, "provider", out.provider, reason)) return false;
  if (!read_name_id(value, "model", out.model, reason)) return false;
  std::int64_t unit_index = 0;
  if (!read_integer(value, "unit_index", unit_index, reason)) return false;
  if (unit_index < 0 || unit_index > static_cast<std::int64_t>(kMaxDeviceUnitIndex)) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out.unit_index = static_cast<std::uint32_t>(unit_index);
  const JsonValue* serial = value.find("serial");
  if (serial != nullptr) {
    if (!serial->is_string()) {
      reason = ReasonCode::RejectedMalformedDocument;
      return false;
    }
    const auto parsed = DeviceSerialId::parse(serial->as_string());
    if (!parsed.has_value()) {
      reason = ReasonCode::RejectedMalformedName;
      return false;
    }
    out.serial = *parsed;
  }
  return true;
}

[[nodiscard]] bool read_device_ref(const JsonValue& value, DeviceIncarnationRef& out,
                                   ReasonCode& reason) {
  if (!value.is_object()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  const JsonValue* device = value.find("device");
  if (device == nullptr) {
    reason = ReasonCode::RejectedMissingField;
    return false;
  }
  if (!read_device(*device, out.device, reason)) return false;
  std::int64_t incarnation = 0;
  if (!read_integer(value, "incarnation", incarnation, reason)) return false;
  if (incarnation <= 0) {
    reason = ReasonCode::RejectedZeroIncarnation;
    return false;
  }
  out.incarnation = IncarnationId(static_cast<std::uint64_t>(incarnation));
  return true;
}

[[nodiscard]] bool read_source_incarnation(const JsonValue& value, SourceIncarnation& out,
                                           ReasonCode& reason) {
  if (!value.is_object()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  if (!read_name_id(value, "source", out.source, reason)) return false;
  std::int64_t counter = 0;
  if (!read_integer(value, "counter", counter, reason)) return false;
  if (counter < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out.counter = SourceIncarnationCounter(static_cast<std::uint64_t>(counter));
  return true;
}

[[nodiscard]] bool read_features(const JsonValue& value, CapabilityKind kind, FeatureSet& out,
                                 ReasonCode& reason) {
  if (!value.is_array()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  std::vector<FeatureCode> codes;
  if (value.as_array().size() > kMaxFeaturesPerRecord) {
    reason = ReasonCode::RejectedFeatureBudgetExceeded;
    return false;
  }
  for (const auto& item : value.as_array()) {
    if (!item.is_string()) {
      reason = ReasonCode::RejectedMalformedFeature;
      return false;
    }
    FeatureCode code{};
    if (!parse_feature_code(item.as_string(), code)) {
      reason = ReasonCode::RejectedUnknownFeatureCode;
      return false;
    }
    codes.push_back(code);
  }
  if (!FeatureSet::make(codes, kind, out, reason)) return false;
  return true;
}

[[nodiscard]] bool read_limits(const JsonValue& value, CapabilityKind kind, LimitSet& out,
                               ReasonCode& reason) {
  if (!value.is_array()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  std::vector<LimitValue> values;
  if (value.as_array().size() > kMaxLimitsPerRecord) {
    reason = ReasonCode::RejectedLimitBudgetExceeded;
    return false;
  }
  for (const auto& item : value.as_array()) {
    if (!item.is_object()) {
      reason = ReasonCode::RejectedMalformedLimit;
      return false;
    }
    LimitValue entry;
    std::string code_text;
    if (!read_string(item, "code", code_text, reason)) return false;
    if (!parse_limit_code(code_text, entry.code)) {
      reason = ReasonCode::RejectedUnknownLimitCode;
      return false;
    }
    if (!read_unit(item, "unit", entry.unit, reason)) return false;
    std::int64_t raw = 0;
    if (!read_integer(item, "value", raw, reason)) return false;
    if (raw < 0) {
      reason = ReasonCode::RejectedNegativeLimit;
      return false;
    }
    entry.value = raw;
    values.push_back(entry);
  }
  if (!LimitSet::make(values, kind, out, reason)) return false;
  return true;
}

[[nodiscard]] bool read_stored_evidence(const JsonValue& value, StoredEvidence& out,
                                        ReasonCode& reason) {
  if (!value.is_object()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  CapabilityEvidence& evidence = out.evidence;
  const JsonValue* device = value.find("device");
  if (device == nullptr) {
    reason = ReasonCode::RejectedMissingField;
    return false;
  }
  if (!read_device_ref(*device, evidence.key.device, reason)) return false;
  if (!read_enum(value, "capability_kind", evidence.key.kind, reason, parse_capability_kind)) {
    return false;
  }
  const JsonValue* source = value.find("source");
  if (source == nullptr) {
    reason = ReasonCode::RejectedMissingField;
    return false;
  }
  if (!read_source_incarnation(*source, evidence.source_incarnation, reason)) return false;
  evidence.key.source = evidence.source_incarnation.source;
  if (!read_semver(value, "capability_version", evidence.capability_version, reason)) return false;
  const JsonValue* features = value.find("features");
  if (features == nullptr) {
    reason = ReasonCode::RejectedMissingField;
    return false;
  }
  if (!read_features(*features, evidence.key.kind, evidence.features, reason)) return false;
  const JsonValue* limits = value.find("limits");
  if (limits == nullptr) {
    reason = ReasonCode::RejectedMissingField;
    return false;
  }
  if (!read_limits(*limits, evidence.key.kind, evidence.limits, reason)) return false;

  const JsonValue* firmware_version = value.find("firmware_version");
  if (firmware_version != nullptr) {
    SemVer parsed;
    if (!read_semver(value, "firmware_version", parsed, reason)) return false;
    evidence.firmware_version = parsed;
  }
  std::int64_t firmware_generation = 0;
  if (!read_integer(value, "firmware_generation", firmware_generation, reason)) return false;
  if (firmware_generation < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  evidence.firmware_generation = FirmwareGeneration(static_cast<std::uint64_t>(firmware_generation));

  const JsonValue* runtime_version = value.find("runtime_version");
  if (runtime_version != nullptr) {
    SemVer parsed;
    if (!read_semver(value, "runtime_version", parsed, reason)) return false;
    evidence.runtime_version = parsed;
  }
  std::int64_t runtime_generation = 0;
  if (!read_integer(value, "runtime_generation", runtime_generation, reason)) return false;
  if (runtime_generation < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  evidence.runtime_generation = RuntimeGeneration(static_cast<std::uint64_t>(runtime_generation));

  std::int64_t observed_at = 0;
  if (!read_integer(value, "observed_at", observed_at, reason)) return false;
  if (observed_at < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  evidence.observed_at = Tick(static_cast<std::uint64_t>(observed_at));

  std::int64_t valid_until = 0;
  if (read_integer(value, "valid_until", valid_until, reason, false)) {
    if (!value_missing(value, "valid_until")) {
      if (valid_until < 0) {
        reason = ReasonCode::RejectedMalformedDocument;
        return false;
      }
      evidence.valid_until = Tick(static_cast<std::uint64_t>(valid_until));
    }
  } else {
    return false;
  }

  std::int64_t generation = 0;
  if (!read_integer(value, "generation", generation, reason)) return false;
  if (generation <= 0) {
    reason = ReasonCode::RejectedGenerationRegression;
    return false;
  }
  evidence.generation = RecordGeneration(static_cast<std::uint64_t>(generation));

  if (!read_enum(value, "authority", evidence.authority, reason, parse_authority_rank)) return false;

  std::int64_t epoch_at_ingest = 0;
  if (!read_integer(value, "epoch_at_ingest", epoch_at_ingest, reason)) return false;
  if (epoch_at_ingest < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  evidence.epoch_at_ingest = RegistryEpoch(static_cast<std::uint64_t>(epoch_at_ingest));

  std::int64_t boot_at_ingest = 0;
  if (!read_integer(value, "boot_at_ingest", boot_at_ingest, reason)) return false;
  if (boot_at_ingest < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  evidence.boot_at_ingest = BootEpoch(static_cast<std::uint64_t>(boot_at_ingest));

  std::int64_t evidence_policy_revision = 0;
  if (!read_integer(value, "evidence_policy_revision", evidence_policy_revision, reason)) return false;
  if (evidence_policy_revision < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  evidence.policy_revision = PolicyRevision(static_cast<std::uint64_t>(evidence_policy_revision));

  if (!read_enum(value, "lifecycle", out.lifecycle, reason, parse_evidence_lifecycle)) return false;
  std::string admission_reason;
  if (!read_string(value, "admission_reason", admission_reason, reason)) return false;
  if (!parse_reason_code(admission_reason, out.admission_reason)) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  std::int64_t admitted_at = 0;
  if (!read_integer(value, "admitted_at", admitted_at, reason)) return false;
  if (admitted_at < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out.admitted_at = Tick(static_cast<std::uint64_t>(admitted_at));

  std::int64_t retired_at = 0;
  if (read_integer(value, "retired_at", retired_at, reason, false)) {
    if (!value_missing(value, "retired_at")) {
      if (retired_at < 0) {
        reason = ReasonCode::RejectedMalformedDocument;
        return false;
      }
      out.retired_at = Tick(static_cast<std::uint64_t>(retired_at));
    }
  } else {
    return false;
  }
  std::string retirement_reason;
  if (!read_string(value, "retirement_reason", retirement_reason, reason)) return false;
  if (!parse_reason_code(retirement_reason, out.retirement_reason)) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  if (out.lifecycle == EvidenceLifecycle::Retired && !out.retired_at.has_value()) {
    reason = ReasonCode::RejectedMissingField;
    return false;
  }

  // The declared identifier must match the content, otherwise a mutated
  // document could present one identity with another's content.
  Digest256 declared;
  if (!read_digest(value, "id", declared, reason)) return false;
  detail::refresh_evidence_id(evidence);
  if (!(declared == evidence.compute_digest())) {
    reason = ReasonCode::StorePayloadCorrupt;
    return false;
  }
  return true;
}

[[nodiscard]] bool read_tombstone(const JsonValue& value, RetirementRecord& out,
                                  ReasonCode& reason) {
  if (!value.is_object()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  const JsonValue* device = value.find("device");
  if (device == nullptr) {
    reason = ReasonCode::RejectedMissingField;
    return false;
  }
  if (!read_device_ref(*device, out.key.device, reason)) return false;
  if (!read_enum(value, "capability_kind", out.key.kind, reason, parse_capability_kind)) return false;
  if (!read_name_id(value, "source", out.key.source, reason)) return false;
  std::int64_t generation = 0;
  if (!read_integer(value, "generation", generation, reason)) return false;
  if (generation <= 0) {
    reason = ReasonCode::RejectedGenerationRegression;
    return false;
  }
  out.generation = RecordGeneration(static_cast<std::uint64_t>(generation));
  std::int64_t retired_at = 0;
  if (!read_integer(value, "retired_at", retired_at, reason)) return false;
  if (retired_at < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out.retired_at = Tick(static_cast<std::uint64_t>(retired_at));
  std::string reason_text;
  if (!read_string(value, "reason", reason_text, reason)) return false;
  if (!parse_reason_code(reason_text, out.reason)) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  std::int64_t epoch = 0;
  if (!read_integer(value, "epoch", epoch, reason)) return false;
  if (epoch < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out.epoch = RegistryEpoch(static_cast<std::uint64_t>(epoch));
  std::int64_t policy_revision = 0;
  if (!read_integer(value, "policy_revision", policy_revision, reason)) return false;
  if (policy_revision < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out.policy_revision = PolicyRevision(static_cast<std::uint64_t>(policy_revision));
  return read_enum(value, "authority", out.authority, reason, parse_authority_rank);
}

[[nodiscard]] bool read_conflict(const JsonValue& value, ConflictGroup& out, ReasonCode& reason) {
  if (!value.is_object()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  Digest256 id;
  if (!read_digest(value, "id", id, reason)) return false;
  out.id = ConflictId(id);
  const JsonValue* device = value.find("device");
  if (device == nullptr) {
    reason = ReasonCode::RejectedMissingField;
    return false;
  }
  if (!read_device_ref(*device, out.device, reason)) return false;
  if (!read_enum(value, "capability_kind", out.kind, reason, parse_capability_kind)) return false;
  if (!read_enum(value, "authority", out.authority, reason, parse_authority_rank)) return false;
  const JsonValue* members = value.find("members");
  if (members == nullptr || !members->is_array()) {
    reason = ReasonCode::RejectedMissingField;
    return false;
  }
  for (const auto& item : members->as_array()) {
    if (!item.is_string()) {
      reason = ReasonCode::RejectedMalformedDocument;
      return false;
    }
    Digest256 member;
    if (!Digest256::parse(item.as_string(), member)) {
      reason = ReasonCode::RejectedMalformedDocument;
      return false;
    }
    out.members.push_back(EvidenceId(member));
  }
  const JsonValue* generations = value.find("generations");
  if (generations == nullptr || !generations->is_array() ||
      generations->as_array().size() != out.members.size()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  for (const auto& item : generations->as_array()) {
    if (!item.is_integer() || item.as_integer() <= 0) {
      reason = ReasonCode::RejectedMalformedDocument;
      return false;
    }
    out.generations.push_back(RecordGeneration(static_cast<std::uint64_t>(item.as_integer())));
  }
  if (!std::is_sorted(out.members.begin(), out.members.end())) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  std::int64_t observed_first = 0;
  if (!read_integer(value, "observed_first", observed_first, reason)) return false;
  std::int64_t observed_last = 0;
  if (!read_integer(value, "observed_last", observed_last, reason)) return false;
  if (observed_first < 0 || observed_last < observed_first) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out.observed_first = Tick(static_cast<std::uint64_t>(observed_first));
  out.observed_last = Tick(static_cast<std::uint64_t>(observed_last));
  return true;
}

[[nodiscard]] bool read_resolution(const JsonValue& value, ConflictResolution& out,
                                   ReasonCode& reason) {
  if (!value.is_object()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  Digest256 id;
  if (!read_digest(value, "id", id, reason)) return false;
  out.id = ResolutionId(id);
  Digest256 conflict;
  if (!read_digest(value, "conflict", conflict, reason)) return false;
  out.conflict = ConflictId(conflict);
  Digest256 chosen;
  if (!read_digest(value, "chosen", chosen, reason)) return false;
  out.chosen = EvidenceId(chosen);
  const JsonValue* rejected = value.find("rejected_members");
  if (rejected == nullptr || !rejected->is_array()) {
    reason = ReasonCode::RejectedMissingField;
    return false;
  }
  for (const auto& item : rejected->as_array()) {
    if (!item.is_string()) {
      reason = ReasonCode::RejectedMalformedDocument;
      return false;
    }
    Digest256 member;
    if (!Digest256::parse(item.as_string(), member)) {
      reason = ReasonCode::RejectedMalformedDocument;
      return false;
    }
    out.rejected_members.push_back(EvidenceId(member));
  }
  if (!read_name_id(value, "resolver", out.resolver, reason)) return false;
  std::int64_t resolved_at = 0;
  if (!read_integer(value, "resolved_at", resolved_at, reason)) return false;
  if (resolved_at < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out.resolved_at = Tick(static_cast<std::uint64_t>(resolved_at));
  std::int64_t epoch = 0;
  if (!read_integer(value, "epoch", epoch, reason)) return false;
  if (epoch < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out.epoch = RegistryEpoch(static_cast<std::uint64_t>(epoch));
  return true;
}

[[nodiscard]] bool read_eviction(const JsonValue& value, EvictionEntry& out, ReasonCode& reason) {
  if (!value.is_object()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  Digest256 id;
  if (!read_digest(value, "id", id, reason)) return false;
  out.id = EvidenceId(id);
  const JsonValue* device = value.find("device");
  if (device == nullptr) {
    reason = ReasonCode::RejectedMissingField;
    return false;
  }
  if (!read_device_ref(*device, out.key.device, reason)) return false;
  if (!read_enum(value, "capability_kind", out.key.kind, reason, parse_capability_kind)) return false;
  if (!read_name_id(value, "source", out.key.source, reason)) return false;
  std::int64_t generation = 0;
  if (!read_integer(value, "generation", generation, reason)) return false;
  if (generation <= 0) {
    reason = ReasonCode::RejectedGenerationRegression;
    return false;
  }
  out.generation = RecordGeneration(static_cast<std::uint64_t>(generation));
  if (!read_enum(value, "state_at_eviction", out.state_at_eviction, reason, parse_evidence_state)) {
    return false;
  }
  std::string reason_text;
  if (!read_string(value, "reason", reason_text, reason)) return false;
  if (!parse_reason_code(reason_text, out.reason)) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  std::int64_t evicted_at = 0;
  if (!read_integer(value, "evicted_at", evicted_at, reason)) return false;
  if (evicted_at < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out.evicted_at = Tick(static_cast<std::uint64_t>(evicted_at));
  return true;
}

[[nodiscard]] bool read_incarnation_entry(const JsonValue& value, DeviceIncarnationEntry& out,
                                          ReasonCode& reason) {
  if (!value.is_object()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  const JsonValue* device = value.find("device");
  if (device == nullptr) {
    reason = ReasonCode::RejectedMissingField;
    return false;
  }
  if (!read_device(*device, out.device, reason)) return false;
  std::int64_t current = 0;
  if (!read_integer(value, "current", current, reason)) return false;
  if (current <= 0) {
    reason = ReasonCode::RejectedZeroIncarnation;
    return false;
  }
  out.current = IncarnationId(static_cast<std::uint64_t>(current));
  const JsonValue* history = value.find("history");
  if (history == nullptr || !history->is_array() || history->as_array().empty()) {
    reason = ReasonCode::RejectedMissingField;
    return false;
  }
  for (const auto& item : history->as_array()) {
    if (!item.is_integer() || item.as_integer() <= 0) {
      reason = ReasonCode::RejectedZeroIncarnation;
      return false;
    }
    out.history.push_back(IncarnationId(static_cast<std::uint64_t>(item.as_integer())));
  }
  if (!std::is_sorted(out.history.begin(), out.history.end())) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  if (!std::binary_search(out.history.begin(), out.history.end(), out.current)) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  return true;
}

[[nodiscard]] bool read_source_policy(const JsonValue& value, SourcePolicy& out,
                                      ReasonCode& reason) {
  if (!value.is_object()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  if (!read_name_id(value, "id", out.id, reason)) return false;
  if (!read_enum(value, "kind", out.kind, reason, parse_source_kind)) return false;
  if (!read_enum(value, "authority", out.authority, reason, parse_authority_rank)) return false;
  if (!read_enum(value, "trust", out.trust, reason, parse_source_trust_state)) return false;
  std::int64_t max_age = 0;
  if (!read_integer(value, "max_age", max_age, reason)) return false;
  if (max_age < 0) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  out.max_age = Tick(static_cast<std::uint64_t>(max_age));
  return read_bool(value, "durable_across_boot", out.durable_across_boot, reason);
}

[[nodiscard]] bool read_counters(const JsonValue& value, RegistryCounters& out,
                                 ReasonCode& reason) {
  if (!value.is_object()) {
    reason = ReasonCode::RejectedMalformedDocument;
    return false;
  }
  struct Field {
    const char* key;
    std::uint64_t* target;
  };
  const Field fields[] = {
      {"admissions_accepted", &out.admissions_accepted},
      {"admissions_idempotent", &out.admissions_idempotent},
      {"admissions_rejected", &out.admissions_rejected},
      {"retirements_accepted", &out.retirements_accepted},
      {"retirements_rejected", &out.retirements_rejected},
      {"decisions_emitted", &out.decisions_emitted},
      {"decisions_evicted", &out.decisions_evicted},
      {"conflicts_resolved", &out.conflicts_resolved},
      {"evictions_total", &out.evictions_total},
      {"eviction_ledger_dropped", &out.eviction_ledger_dropped},
      {"conflicts_dropped", &out.conflicts_dropped},
      {"resolutions_dropped", &out.resolutions_dropped},
      {"tombstones_dropped", &out.tombstones_dropped},
  };
  for (const auto& field : fields) {
    if (!read_u64(value, field.key, *field.target, reason)) return false;
  }
  return true;
}

}  // namespace

Outcome<ExportResult> export_registry(const Registry& registry, const ExportOptions& options,
                                      Tick now) {
  Outcome<RegistryState> snapshot = registry.snapshot_state();
  if (!snapshot.ok()) {
    return Outcome<ExportResult>(snapshot.status());
  }
  const RegistryState& state = snapshot.value();

  JsonValue document = JsonValue::object();
  document.set("format", JsonValue::string(std::string(kFormatName)));
  document.set("format_version", JsonValue::integer(static_cast<std::int64_t>(kExportFormatVersion)));
  document.set("api_generation", JsonValue::integer(static_cast<std::int64_t>(kApiGeneration)));
  document.set("catalog_fingerprint", JsonValue::integer(static_cast<std::int64_t>(catalog_fingerprint())));
  document.set("reason_table_fingerprint", JsonValue::integer(static_cast<std::int64_t>(reason_table_fingerprint())));
  document.set("registry_epoch", JsonValue::integer(static_cast<std::int64_t>(state.epoch.value())));
  document.set("rule_generation", JsonValue::integer(static_cast<std::int64_t>(state.rule_generation.value())));
  document.set("policy_revision", JsonValue::integer(static_cast<std::int64_t>(state.policy_revision.value())));
  document.set("boot_epoch", JsonValue::integer(static_cast<std::int64_t>(state.boot_epoch.value())));
  document.set("store_generation", JsonValue::integer(static_cast<std::int64_t>(state.store_generation.value())));
  document.set("logical_tick", JsonValue::integer(static_cast<std::int64_t>(state.logical_tick.value())));
  document.set("exported_at", JsonValue::integer(static_cast<std::int64_t>(now.value())));
  document.set("next_incarnation", JsonValue::integer(static_cast<std::int64_t>(state.next_incarnation)));

  ExportResult result;
  bool truncated = false;

  if (options.include_policy) {
    document.set("policy", json_of(state.policy));
  }

  JsonValue devices = JsonValue::array();
  for (const auto& entry : state.incarnations) devices.push(json_of(entry));
  document.set("devices", std::move(devices));

  JsonValue evidence = JsonValue::array();
  for (const auto& record : state.records) {
    if (!options.include_rejected && record.lifecycle == EvidenceLifecycle::Rejected) continue;
    if (record.lifecycle != EvidenceLifecycle::Rejected) {
      // Superseded and outranked records are history; drop them only when the
      // caller explicitly asked for the current view.
      if (!options.include_history && record.lifecycle != EvidenceLifecycle::Admitted) continue;
    }
    if (result.records_written >= options.max_records) {
      truncated = true;
      break;
    }
    evidence.push(json_of(record));
    ++result.records_written;
  }
  document.set("evidence", std::move(evidence));

  JsonValue tombstones = JsonValue::array();
  for (const auto& record : state.tombstones) tombstones.push(json_of(record));
  result.tombstones_written = state.tombstones.size();
  document.set("tombstones", std::move(tombstones));

  JsonValue conflicts = JsonValue::array();
  for (const auto& group : state.conflicts) conflicts.push(json_of(group));
  result.conflicts_written = state.conflicts.size();
  document.set("conflicts", std::move(conflicts));

  JsonValue resolutions = JsonValue::array();
  for (const auto& resolution : state.resolutions) resolutions.push(json_of(resolution));
  document.set("resolutions", std::move(resolutions));

  JsonValue evictions = JsonValue::array();
  if (options.include_evictions) {
    for (const auto& entry : state.evictions) evictions.push(json_of(entry));
    result.evictions_written = state.evictions.size();
  }
  document.set("evictions", std::move(evictions));

  document.set("counters", json_of(state.counters));

  result.truncated = truncated;
  if (truncated) result.notes.push_back(ReasonCode::ExportTruncated);
  result.digest = state_digest(state);
  document.set("state_digest", JsonValue::string(result.digest.hex()));
  document.set("truncated", JsonValue::boolean(truncated));
  JsonValue notes = JsonValue::array();
  for (const auto reason : result.notes) {
    notes.push(JsonValue::string(std::string(to_string(reason))));
  }
  document.set("notes", std::move(notes));

  result.document = document.dump(options.pretty);
  if (result.document.size() > options.max_bytes) {
    return Outcome<ExportResult>(Status::failure(ReasonCode::RejectedOversizedInput,
                                                 "canonical export exceeds the byte bound"));
  }
  result.notes.push_back(ReasonCode::ExportComplete);
  canonicalize_reasons(result.notes);
  return Outcome<ExportResult>(std::move(result));
}

Outcome<ImportResult> import_document(std::string_view document) {
  const auto parsed = JsonValue::parse(document, JsonLimits{});
  if (!parsed.ok()) {
    return Outcome<ImportResult>(parsed.status());
  }
  const JsonValue& root = parsed.value();
  ReasonCode reason = ReasonCode::Ok;
  if (!root.is_object()) {
    return Outcome<ImportResult>(
        Status::failure(ReasonCode::RejectedMalformedDocument, "document root must be an object"));
  }

  std::string format;
  if (!read_string(root, "format", format, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "missing format"));
  }
  if (format != kFormatName) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::StoreSemanticMismatch,
                                                 "document format is not ocreg.canonical-state"));
  }
  std::int64_t format_version = 0;
  if (!read_integer(root, "format_version", format_version, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "missing format_version"));
  }
  if (format_version != static_cast<std::int64_t>(kExportFormatVersion)) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::StoreVersionIncompatible,
                                                 "document format version is not supported"));
  }
  std::int64_t api_generation = 0;
  if (!read_integer(root, "api_generation", api_generation, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "missing api_generation"));
  }
  if (api_generation != static_cast<std::int64_t>(kApiGeneration)) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::StoreVersionIncompatible,
                                                 "document API generation is not supported"));
  }
  std::int64_t catalog = 0;
  if (!read_integer(root, "catalog_fingerprint", catalog, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "missing catalog_fingerprint"));
  }
  if (static_cast<std::uint32_t>(catalog) != catalog_fingerprint()) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::StoreSemanticMismatch,
                                                 "capability catalog generation differs"));
  }
  std::int64_t reason_fingerprint = 0;
  if (!read_integer(root, "reason_table_fingerprint", reason_fingerprint, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "missing reason_table_fingerprint"));
  }
  if (static_cast<std::uint32_t>(reason_fingerprint) != reason_table_fingerprint()) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::StoreSemanticMismatch,
                                                 "reason table generation differs"));
  }

  bool truncated = false;
  if (!read_bool(root, "truncated", truncated, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "missing truncated flag"));
  }
  if (truncated) {
    return Outcome<ImportResult>(Status::failure(
        ReasonCode::ExportTruncated, "a truncated export is not a complete state"));
  }

  RegistryState state;
  std::int64_t registry_epoch = 0;
  if (!read_integer(root, "registry_epoch", registry_epoch, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "missing registry_epoch"));
  }
  std::int64_t rule_generation = 0;
  if (!read_integer(root, "rule_generation", rule_generation, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "missing rule_generation"));
  }
  std::int64_t policy_revision = 0;
  if (!read_integer(root, "policy_revision", policy_revision, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "missing policy_revision"));
  }
  std::int64_t boot_epoch = 0;
  if (!read_integer(root, "boot_epoch", boot_epoch, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "missing boot_epoch"));
  }
  std::int64_t store_generation = 0;
  if (!read_integer(root, "store_generation", store_generation, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "missing store_generation"));
  }
  std::int64_t logical_tick = 0;
  if (!read_integer(root, "logical_tick", logical_tick, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "missing logical_tick"));
  }
  std::int64_t next_incarnation = 0;
  if (!read_integer(root, "next_incarnation", next_incarnation, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "missing next_incarnation"));
  }
  if (registry_epoch < 0 || rule_generation <= 0 || policy_revision < 0 || boot_epoch < 0 ||
      store_generation < 0 || logical_tick < 0 || next_incarnation <= 0) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::RejectedEpochOutOfRange,
                                                 "document contains an impossible generation"));
  }
  state.epoch = RegistryEpoch(static_cast<std::uint64_t>(registry_epoch));
  state.rule_generation = RuleGeneration(static_cast<std::uint64_t>(rule_generation));
  state.policy_revision = PolicyRevision(static_cast<std::uint64_t>(policy_revision));
  state.boot_epoch = BootEpoch(static_cast<std::uint64_t>(boot_epoch));
  state.store_generation = StoreGeneration(static_cast<std::uint64_t>(store_generation));
  state.logical_tick = Tick(static_cast<std::uint64_t>(logical_tick));
  state.next_incarnation = static_cast<std::uint64_t>(next_incarnation);

  const JsonValue* policy = root.find("policy");
  if (policy == nullptr || !policy->is_object()) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::RejectedMissingField,
                                                 "missing policy object"));
  }
  RegistryPolicy& target_policy = state.policy;
  const JsonValue* sources = policy->find("sources");
  if (sources == nullptr || !sources->is_array()) {
    return Outcome<ImportResult>(
        Status::failure(ReasonCode::RejectedMissingField, "missing policy sources"));
  }
  for (const auto& item : sources->as_array()) {
    SourcePolicy source;
    if (!read_source_policy(item, source, reason)) {
      return Outcome<ImportResult>(Status::failure(reason, "source policy rejected"));
    }
    target_policy.sources.push_back(source);
  }
  std::sort(target_policy.sources.begin(), target_policy.sources.end());
  if (!std::is_sorted(target_policy.sources.begin(), target_policy.sources.end()) ||
      std::adjacent_find(target_policy.sources.begin(), target_policy.sources.end(),
                         [](const SourcePolicy& a, const SourcePolicy& b) { return a.id == b.id; }) !=
          target_policy.sources.end()) {
    return Outcome<ImportResult>(
        Status::failure(ReasonCode::RejectedDuplicateKey, "policy sources are not unique"));
  }
  if (!read_bool(*policy, "require_configured_source", target_policy.require_configured_source, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "policy field rejected"));
  }
  if (!read_bool(*policy, "refuse_untrusted_sources", target_policy.refuse_untrusted_sources, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "policy field rejected"));
  }
  if (!read_enum(*policy, "boot_policy", target_policy.boot_policy, reason, parse_boot_policy)) {
    return Outcome<ImportResult>(Status::failure(reason, "policy field rejected"));
  }
  if (!read_enum(*policy, "clock_mode", target_policy.clock_mode, reason, parse_clock_mode)) {
    return Outcome<ImportResult>(Status::failure(reason, "policy field rejected"));
  }
  std::int64_t retention_horizon = 0;
  std::int64_t max_future_skew = 0;
  std::int64_t default_max_age = 0;
  if (!read_integer(*policy, "retention_horizon", retention_horizon, reason) ||
      !read_integer(*policy, "max_future_skew", max_future_skew, reason) ||
      !read_integer(*policy, "default_max_age", default_max_age, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "policy field rejected"));
  }
  if (retention_horizon < 0 || max_future_skew < 0 || default_max_age < 0) {
    return Outcome<ImportResult>(
        Status::failure(ReasonCode::RejectedMalformedDocument, "negative policy duration"));
  }
  target_policy.retention_horizon = Tick(static_cast<std::uint64_t>(retention_horizon));
  target_policy.max_future_skew = Tick(static_cast<std::uint64_t>(max_future_skew));
  target_policy.default_max_age = Tick(static_cast<std::uint64_t>(default_max_age));
  if (!read_string(*policy, "policy_name", target_policy.policy_name, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "policy field rejected"));
  }

  const JsonValue* limits = policy->find("limits");
  if (limits == nullptr || !limits->is_object()) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::RejectedMissingField, "missing limits"));
  }
  RegistryLimits& target_limits = target_policy.limits;
  struct LimitField {
    const char* key;
    std::size_t* target;
  };
  const LimitField limit_fields[] = {
      {"max_devices", &target_limits.max_devices},
      {"max_incarnations_per_device", &target_limits.max_incarnations_per_device},
      {"max_streams", &target_limits.max_streams},
      {"max_records", &target_limits.max_records},
      {"max_records_per_stream", &target_limits.max_records_per_stream},
      {"max_tombstones", &target_limits.max_tombstones},
      {"max_conflict_groups", &target_limits.max_conflict_groups},
      {"max_resolutions", &target_limits.max_resolutions},
      {"max_eviction_ledger", &target_limits.max_eviction_ledger},
      {"max_sources", &target_limits.max_sources},
      {"max_decisions", &target_limits.max_decisions},
      {"max_features_per_record", &target_limits.max_features_per_record},
      {"max_limits_per_record", &target_limits.max_limits_per_record},
      {"max_limits_per_requirement", &target_limits.max_limits_per_requirement},
      {"max_required_features", &target_limits.max_required_features},
  };
  for (const auto& field : limit_fields) {
    std::int64_t raw = 0;
    if (!read_integer(*limits, field.key, raw, reason)) {
      return Outcome<ImportResult>(Status::failure(reason, "limits field rejected"));
    }
    if (raw < 0) {
      return Outcome<ImportResult>(
          Status::failure(ReasonCode::RejectedOversizedInput, "negative limit bound"));
    }
    *field.target = static_cast<std::size_t>(raw);
  }
  std::int64_t policy_rule_generation = 0;
  if (!read_integer(*policy, "rule_generation", policy_rule_generation, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "policy field rejected"));
  }
  if (policy_rule_generation <= 0) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::RejectedRuleGenerationOutOfRange,
                                                 "policy rule generation must be non-zero"));
  }
  target_policy.rule_generation = RuleGeneration(static_cast<std::uint64_t>(policy_rule_generation));

  ImportResult result;
  const JsonValue* evidence = root.find("evidence");
  if (evidence == nullptr || !evidence->is_array()) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::RejectedMissingField, "missing evidence"));
  }
  if (evidence->as_array().size() > target_limits.max_records) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::RejectedRecordBudgetExhausted,
                                                 "document exceeds the record bound"));
  }
  for (const auto& item : evidence->as_array()) {
    StoredEvidence record;
    if (!read_stored_evidence(item, record, reason)) {
      return Outcome<ImportResult>(Status::failure(reason, "evidence record rejected"));
    }
    state.records.push_back(std::move(record));
    ++result.records_read;
  }

  const JsonValue* tombstones = root.find("tombstones");
  if (tombstones == nullptr || !tombstones->is_array()) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::RejectedMissingField, "missing tombstones"));
  }
  for (const auto& item : tombstones->as_array()) {
    RetirementRecord record;
    if (!read_tombstone(item, record, reason)) {
      return Outcome<ImportResult>(Status::failure(reason, "tombstone rejected"));
    }
    state.tombstones.push_back(std::move(record));
    ++result.tombstones_read;
  }

  const JsonValue* conflicts = root.find("conflicts");
  if (conflicts == nullptr || !conflicts->is_array()) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::RejectedMissingField, "missing conflicts"));
  }
  for (const auto& item : conflicts->as_array()) {
    ConflictGroup group;
    if (!read_conflict(item, group, reason)) {
      return Outcome<ImportResult>(Status::failure(reason, "conflict group rejected"));
    }
    state.conflicts.push_back(std::move(group));
    ++result.conflicts_read;
  }

  const JsonValue* resolutions = root.find("resolutions");
  if (resolutions == nullptr || !resolutions->is_array()) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::RejectedMissingField, "missing resolutions"));
  }
  for (const auto& item : resolutions->as_array()) {
    ConflictResolution resolution;
    if (!read_resolution(item, resolution, reason)) {
      return Outcome<ImportResult>(Status::failure(reason, "conflict resolution rejected"));
    }
    state.resolutions.push_back(std::move(resolution));
  }

  const JsonValue* evictions = root.find("evictions");
  if (evictions == nullptr || !evictions->is_array()) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::RejectedMissingField, "missing evictions"));
  }
  for (const auto& item : evictions->as_array()) {
    EvictionEntry entry;
    if (!read_eviction(item, entry, reason)) {
      return Outcome<ImportResult>(Status::failure(reason, "eviction entry rejected"));
    }
    state.evictions.push_back(std::move(entry));
    ++result.evictions_read;
  }

  const JsonValue* devices = root.find("devices");
  if (devices == nullptr || !devices->is_array()) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::RejectedMissingField, "missing devices"));
  }
  for (const auto& item : devices->as_array()) {
    DeviceIncarnationEntry entry;
    if (!read_incarnation_entry(item, entry, reason)) {
      return Outcome<ImportResult>(Status::failure(reason, "device entry rejected"));
    }
    state.incarnations.push_back(std::move(entry));
  }
  std::sort(state.incarnations.begin(), state.incarnations.end());

  const JsonValue* counters = root.find("counters");
  if (counters == nullptr) {
    return Outcome<ImportResult>(Status::failure(ReasonCode::RejectedMissingField, "missing counters"));
  }
  if (!read_counters(*counters, state.counters, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "counters rejected"));
  }

  // Every record must belong to a registered device incarnation, otherwise the
  // document describes evidence that cannot be attributed.
  for (const auto& record : state.records) {
    bool found = false;
    for (const auto& entry : state.incarnations) {
      if (entry.device == record.evidence.key.device.device) {
        found = std::find(entry.history.begin(), entry.history.end(),
                          record.evidence.key.device.incarnation) != entry.history.end();
        break;
      }
    }
    if (!found) {
      return Outcome<ImportResult>(Status::failure(
          ReasonCode::RejectedDeviceIncarnationFenced,
          "evidence references a device incarnation the document does not register"));
    }
  }

  Digest256 declared;
  if (!read_digest(root, "state_digest", declared, reason)) {
    return Outcome<ImportResult>(Status::failure(reason, "missing state_digest"));
  }
  if (!(declared == state_digest(state))) {
    return Outcome<ImportResult>(Status::failure(
        ReasonCode::StorePayloadCorrupt,
        "declared state digest does not match the reconstructed state"));
  }

  result.state = std::move(state);
  result.reason = ReasonCode::Ok;
  return Outcome<ImportResult>(std::move(result));
}

Digest256 export_digest(const RegistryState& state) { return state_digest(state); }

Outcome<RegistryPolicy> parse_policy_document(std::string_view document) {
  const auto parsed = JsonValue::parse(document, JsonLimits{});
  if (!parsed.ok()) return Outcome<RegistryPolicy>(parsed.status());
  const JsonValue* policy = &parsed.value();
  if (!policy->is_object()) {
    return Outcome<RegistryPolicy>(Status::failure(ReasonCode::RejectedMalformedDocument,
                                                   "policy document root must be an object"));
  }
  const JsonValue* nested = policy->find("policy");
  if (nested != nullptr) {
    if (!nested->is_object()) {
      return Outcome<RegistryPolicy>(Status::failure(ReasonCode::RejectedMalformedDocument,
                                                     "policy member must be an object"));
    }
    policy = nested;
  }
  ReasonCode reason = ReasonCode::Ok;
  RegistryPolicy result;
  const JsonValue* sources = policy->find("sources");
  if (sources == nullptr || !sources->is_array()) {
    return Outcome<RegistryPolicy>(
        Status::failure(ReasonCode::RejectedMissingField, "policy sources are required"));
  }
  if (sources->as_array().size() > 1024u) {
    return Outcome<RegistryPolicy>(
        Status::failure(ReasonCode::RejectedOversizedInput, "too many policy sources"));
  }
  for (const auto& item : sources->as_array()) {
    SourcePolicy source;
    if (!read_source_policy(item, source, reason)) {
      return Outcome<RegistryPolicy>(Status::failure(reason, "source policy rejected"));
    }
    result.sources.push_back(source);
  }
  std::sort(result.sources.begin(), result.sources.end());
  if (std::adjacent_find(result.sources.begin(), result.sources.end(),
                         [](const SourcePolicy& a, const SourcePolicy& b) {
                           return a.id == b.id;
                         }) != result.sources.end()) {
    return Outcome<RegistryPolicy>(
        Status::failure(ReasonCode::RejectedDuplicateKey, "policy sources are not unique"));
  }
  if (!read_bool(*policy, "require_configured_source", result.require_configured_source, reason)) {
    return Outcome<RegistryPolicy>(Status::failure(reason, "policy field rejected"));
  }
  if (!read_bool(*policy, "refuse_untrusted_sources", result.refuse_untrusted_sources, reason)) {
    return Outcome<RegistryPolicy>(Status::failure(reason, "policy field rejected"));
  }
  if (!read_enum(*policy, "boot_policy", result.boot_policy, reason, parse_boot_policy)) {
    return Outcome<RegistryPolicy>(Status::failure(reason, "policy field rejected"));
  }
  if (!read_enum(*policy, "clock_mode", result.clock_mode, reason, parse_clock_mode)) {
    return Outcome<RegistryPolicy>(Status::failure(reason, "policy field rejected"));
  }
  std::int64_t retention_horizon = 0;
  std::int64_t max_future_skew = 0;
  std::int64_t default_max_age = 0;
  if (!read_integer(*policy, "retention_horizon", retention_horizon, reason) ||
      !read_integer(*policy, "max_future_skew", max_future_skew, reason) ||
      !read_integer(*policy, "default_max_age", default_max_age, reason)) {
    return Outcome<RegistryPolicy>(Status::failure(reason, "policy field rejected"));
  }
  if (retention_horizon < 0 || max_future_skew < 0 || default_max_age < 0) {
    return Outcome<RegistryPolicy>(
        Status::failure(ReasonCode::RejectedMalformedDocument, "negative policy duration"));
  }
  result.retention_horizon = Tick(static_cast<std::uint64_t>(retention_horizon));
  result.max_future_skew = Tick(static_cast<std::uint64_t>(max_future_skew));
  result.default_max_age = Tick(static_cast<std::uint64_t>(default_max_age));
  if (!read_string(*policy, "policy_name", result.policy_name, reason)) {
    return Outcome<RegistryPolicy>(Status::failure(reason, "policy field rejected"));
  }
  std::int64_t rule_generation = 0;
  if (!read_integer(*policy, "rule_generation", rule_generation, reason)) {
    return Outcome<RegistryPolicy>(Status::failure(reason, "policy field rejected"));
  }
  if (rule_generation <= 0) {
    return Outcome<RegistryPolicy>(Status::failure(ReasonCode::RejectedRuleGenerationOutOfRange,
                                                   "rule generation must be non-zero"));
  }
  result.rule_generation = RuleGeneration(static_cast<std::uint64_t>(rule_generation));
  const JsonValue* limits = policy->find("limits");
  if (limits != nullptr) {
    if (!limits->is_object()) {
      return Outcome<RegistryPolicy>(
          Status::failure(ReasonCode::RejectedMalformedDocument, "limits must be an object"));
    }
    struct LimitField {
      const char* key;
      std::size_t* target;
    };
    const LimitField fields[] = {
        {"max_devices", &result.limits.max_devices},
        {"max_incarnations_per_device", &result.limits.max_incarnations_per_device},
        {"max_streams", &result.limits.max_streams},
        {"max_records", &result.limits.max_records},
        {"max_records_per_stream", &result.limits.max_records_per_stream},
        {"max_tombstones", &result.limits.max_tombstones},
        {"max_conflict_groups", &result.limits.max_conflict_groups},
        {"max_resolutions", &result.limits.max_resolutions},
        {"max_eviction_ledger", &result.limits.max_eviction_ledger},
        {"max_sources", &result.limits.max_sources},
        {"max_decisions", &result.limits.max_decisions},
        {"max_features_per_record", &result.limits.max_features_per_record},
        {"max_limits_per_record", &result.limits.max_limits_per_record},
        {"max_limits_per_requirement", &result.limits.max_limits_per_requirement},
        {"max_required_features", &result.limits.max_required_features},
    };
    for (const auto& field : fields) {
      std::int64_t raw = 0;
      if (!read_integer(*limits, field.key, raw, reason, false)) {
        return Outcome<RegistryPolicy>(Status::failure(reason, "limits field rejected"));
      }
      if (value_missing(*limits, field.key)) continue;
      if (raw < 0) {
        return Outcome<RegistryPolicy>(
            Status::failure(ReasonCode::RejectedOversizedInput, "negative limit bound"));
      }
      *field.target = static_cast<std::size_t>(raw);
    }
  }
  return Outcome<RegistryPolicy>(std::move(result));
}

Outcome<CapabilityRequirement> parse_requirement_document(std::string_view document) {
  const auto parsed = JsonValue::parse(document, JsonLimits{});
  if (!parsed.ok()) return Outcome<CapabilityRequirement>(parsed.status());
  if (!parsed.value().is_object()) {
    return Outcome<CapabilityRequirement>(Status::failure(ReasonCode::RejectedMalformedDocument,
                                                          "requirement root must be an object"));
  }
  const JsonValue* nested = parsed.value().find("requirement");
  const JsonValue& node = nested != nullptr ? *nested : parsed.value();
  if (!node.is_object()) {
    return Outcome<CapabilityRequirement>(Status::failure(ReasonCode::RejectedMalformedDocument,
                                                          "requirement must be an object"));
  }
  ReasonCode reason = ReasonCode::Ok;
  CapabilityRequirement requirement;
  const JsonValue* device = node.find("device");
  if (device == nullptr) {
    return Outcome<CapabilityRequirement>(
        Status::failure(ReasonCode::RejectedMissingField, "requirement device is required"));
  }
  if (!read_device_ref(*device, requirement.device, reason)) {
    return Outcome<CapabilityRequirement>(Status::failure(reason, "requirement device rejected"));
  }
  if (!read_enum(node, "capability_kind", requirement.capability, reason, parse_capability_kind)) {
    return Outcome<CapabilityRequirement>(Status::failure(reason, "capability kind rejected"));
  }
  const JsonValue* version = node.find("version");
  if (version == nullptr || !version->is_object()) {
    return Outcome<CapabilityRequirement>(
        Status::failure(ReasonCode::RejectedMissingField, "requirement version is required"));
  }
  if (!read_semver(*version, "minimum", requirement.version.minimum, reason)) {
    return Outcome<CapabilityRequirement>(Status::failure(reason, "minimum version rejected"));
  }
  if (!value_missing(*version, "maximum_exclusive")) {
    SemVer maximum;
    if (!read_semver(*version, "maximum_exclusive", maximum, reason)) {
      return Outcome<CapabilityRequirement>(Status::failure(reason, "maximum version rejected"));
    }
    requirement.version.maximum_exclusive = maximum;
  }

  const JsonValue* features = node.find("required_features");
  if (features != nullptr) {
    if (!read_features(*features, requirement.capability, requirement.required_features, reason)) {
      return Outcome<CapabilityRequirement>(Status::failure(reason, "required features rejected"));
    }
  }

  const JsonValue* limits = node.find("required_limits");
  if (limits != nullptr) {
    if (!limits->is_array()) {
      return Outcome<CapabilityRequirement>(
          Status::failure(ReasonCode::RejectedMalformedDocument, "required_limits must be an array"));
    }
    if (limits->as_array().size() > requirement.required_limits.capacity() + 64u) {
      return Outcome<CapabilityRequirement>(
          Status::failure(ReasonCode::RejectedLimitBudgetExceeded, "too many required limits"));
    }
    for (const auto& item : limits->as_array()) {
      if (!item.is_object()) {
        return Outcome<CapabilityRequirement>(
            Status::failure(ReasonCode::RejectedMalformedLimit, "limit entry must be an object"));
      }
      LimitRequirement entry;
      std::string code_text;
      if (!read_string(item, "code", code_text, reason)) {
        return Outcome<CapabilityRequirement>(Status::failure(reason, "limit code rejected"));
      }
      if (!parse_limit_code(code_text, entry.code)) {
        return Outcome<CapabilityRequirement>(
            Status::failure(ReasonCode::RejectedUnknownLimitCode, code_text));
      }
      if (!read_unit(item, "unit", entry.unit, reason)) {
        return Outcome<CapabilityRequirement>(Status::failure(reason, "limit unit rejected"));
      }
      std::int64_t raw = 0;
      if (!read_integer(item, "value", raw, reason)) {
        return Outcome<CapabilityRequirement>(Status::failure(reason, "limit value rejected"));
      }
      if (raw < 0) {
        return Outcome<CapabilityRequirement>(
            Status::failure(ReasonCode::RejectedNegativeLimit, "limit value must be non-negative"));
      }
      entry.minimum = raw;
      const LimitInfo* info = limit_info(entry.code);
      if (info == nullptr) {
        return Outcome<CapabilityRequirement>(
            Status::failure(ReasonCode::RejectedUnknownLimitCode, code_text));
      }
      if (entry.unit.code != info->unit) {
        return Outcome<CapabilityRequirement>(
            Status::failure(ReasonCode::RejectedLimitUnitInvalid, code_text));
      }
      if (!unit_valid_for_limit(entry.code, entry.unit)) {
        return Outcome<CapabilityRequirement>(
            Status::failure(ReasonCode::RejectedLimitScaleNotPermitted, code_text));
      }
      if (!limit_allowed_for(entry.code, requirement.capability)) {
        return Outcome<CapabilityRequirement>(
            Status::failure(ReasonCode::RejectedLimitNotInKind, code_text));
      }
      requirement.required_limits.push_back(entry);
    }
    std::sort(requirement.required_limits.begin(), requirement.required_limits.end());
    for (std::size_t i = 1; i < requirement.required_limits.size(); ++i) {
      if (!(requirement.required_limits[i - 1].code < requirement.required_limits[i].code)) {
        return Outcome<CapabilityRequirement>(
            Status::failure(ReasonCode::RejectedDuplicateKey, "duplicate required limit"));
      }
    }
  }

  if (!value_missing(node, "minimum_firmware_version")) {
    SemVer version_value;
    if (!read_semver(node, "minimum_firmware_version", version_value, reason)) {
      return Outcome<CapabilityRequirement>(Status::failure(reason, "firmware version rejected"));
    }
    requirement.minimum_firmware_version = version_value;
  }
  if (!value_missing(node, "minimum_firmware_generation")) {
    std::int64_t raw = 0;
    if (!read_integer(node, "minimum_firmware_generation", raw, reason) || raw < 0) {
      return Outcome<CapabilityRequirement>(
          Status::failure(ReasonCode::RejectedMalformedDocument, "firmware generation rejected"));
    }
    requirement.minimum_firmware_generation =
        FirmwareGeneration(static_cast<std::uint64_t>(raw));
  }
  if (!value_missing(node, "minimum_runtime_version")) {
    SemVer version_value;
    if (!read_semver(node, "minimum_runtime_version", version_value, reason)) {
      return Outcome<CapabilityRequirement>(Status::failure(reason, "runtime version rejected"));
    }
    requirement.minimum_runtime_version = version_value;
  }
  if (!value_missing(node, "minimum_runtime_generation")) {
    std::int64_t raw = 0;
    if (!read_integer(node, "minimum_runtime_generation", raw, reason) || raw < 0) {
      return Outcome<CapabilityRequirement>(
          Status::failure(ReasonCode::RejectedMalformedDocument, "runtime generation rejected"));
    }
    requirement.minimum_runtime_generation = RuntimeGeneration(static_cast<std::uint64_t>(raw));
  }
  if (!value_missing(node, "max_evidence_age")) {
    std::int64_t raw = 0;
    if (!read_integer(node, "max_evidence_age", raw, reason) || raw < 0) {
      return Outcome<CapabilityRequirement>(
          Status::failure(ReasonCode::RejectedMalformedDocument, "max_evidence_age rejected"));
    }
    requirement.max_evidence_age = Tick(static_cast<std::uint64_t>(raw));
  }
  return Outcome<CapabilityRequirement>(std::move(requirement));
}

std::string render_requirement_document(const CapabilityRequirement& requirement, bool pretty) {
  JsonValue root = JsonValue::object();
  root.set("format", JsonValue::string("ocreg.requirement"));
  root.set("format_version", JsonValue::integer(static_cast<std::int64_t>(kExportFormatVersion)));
  JsonValue node = JsonValue::object();
  node.set("device", json_of(requirement.device));
  node.set("capability_kind", JsonValue::string(std::string(to_string(requirement.capability))));
  JsonValue version = JsonValue::object();
  version.set("minimum", json_of(requirement.version.minimum));
  if (requirement.version.maximum_exclusive.has_value()) {
    version.set("maximum_exclusive", json_of(*requirement.version.maximum_exclusive));
  }
  node.set("version", std::move(version));
  node.set("required_features", json_of(requirement.required_features));
  JsonValue limits = JsonValue::array();
  for (const auto& limit : requirement.required_limits) {
    JsonValue item = JsonValue::object();
    item.set("code", JsonValue::string(std::string(to_string(limit.code))));
    item.set("unit", json_of(limit.unit));
    item.set("value", JsonValue::integer(limit.minimum));
    limits.push(std::move(item));
  }
  node.set("required_limits", std::move(limits));
  if (requirement.minimum_firmware_version.has_value()) {
    node.set("minimum_firmware_version", json_of(*requirement.minimum_firmware_version));
  }
  if (requirement.minimum_firmware_generation.has_value()) {
    node.set("minimum_firmware_generation",
             JsonValue::integer(static_cast<std::int64_t>(requirement.minimum_firmware_generation->value())));
  }
  if (requirement.minimum_runtime_version.has_value()) {
    node.set("minimum_runtime_version", json_of(*requirement.minimum_runtime_version));
  }
  if (requirement.minimum_runtime_generation.has_value()) {
    node.set("minimum_runtime_generation",
             JsonValue::integer(static_cast<std::int64_t>(requirement.minimum_runtime_generation->value())));
  }
  node.set("max_evidence_age", JsonValue::integer(static_cast<std::int64_t>(requirement.max_evidence_age.value())));
  root.set("requirement", std::move(node));
  return root.dump(pretty);
}

std::string render_policy_document(const RegistryPolicy& policy, bool pretty) {
  JsonValue root = JsonValue::object();
  root.set("format", JsonValue::string("ocreg.policy"));
  root.set("format_version", JsonValue::integer(static_cast<std::int64_t>(kExportFormatVersion)));
  root.set("policy", json_of(policy));
  return root.dump(pretty);
}

}  // namespace ocreg
