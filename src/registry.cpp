// Offload Capability Registry - registry engine.
// Copyright 2026 Summon Software Labs.
//
// Locking discipline
// ------------------
//   * Every public entry point takes exactly one lock: shared for read-only
//     operations, exclusive for mutations. No helper called while the lock is
//     held ever takes a lock again, so there is no read-to-write reacquisition
//     and no nested acquisition anywhere in this translation unit.
//   * No callback, no user code, no allocation-time hook and no I/O runs while
//     a lock is held.
//   * Worker threads and the persistence layer never call back into the
//     registry.
//   * Where a caller holds two locks the order is always (registry, store).
//     The registry never acquires a store lock.
#include "ocreg/registry.hpp"

#include <algorithm>
#include <cstddef>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

#include "compat_internal.hpp"
#include "ocreg/checked.hpp"
#include "ocreg/codec.hpp"
#include "ocreg/persist.hpp"
#include "ocreg/version.hpp"

namespace ocreg {
namespace {

using KindMap = std::map<CapabilityKind, struct GroupState>;

// One source's view of one capability of one device incarnation.
struct Stream {
  std::vector<StoredEvidence> records{};  // ordered by (generation, id)
  RecordGeneration max_generation{};
};

struct GroupState {
  std::map<SourceId, Stream> streams{};
  std::map<SourceId, RetirementRecord> tombstones{};
};

struct World {
  std::map<DeviceIncarnationRef, KindMap> groups{};
};

[[nodiscard]] bool generation_less(const StoredEvidence& a, const StoredEvidence& b) noexcept {
  if (a.evidence.generation != b.evidence.generation) {
    return a.evidence.generation < b.evidence.generation;
  }
  return a.evidence.id() < b.evidence.id();
}

struct RecordById {
  [[nodiscard]] bool operator()(const StoredEvidence& record, const EvidenceId& id) const {
    return record.evidence.id() < id;
  }
  [[nodiscard]] bool operator()(const EvidenceId& id, const StoredEvidence& record) const {
    return id < record.evidence.id();
  }
};

// Freshness bound that applies to a record. A caller-supplied override always
// wins: it is the most specific statement of intent.
[[nodiscard]] Tick effective_max_age(const RegistryPolicy& policy, const SourcePolicy* source,
                                     Tick override_age) noexcept {
  if (override_age.value() != 0) return override_age;
  if (source == nullptr) return policy.default_max_age;
  if (source->max_age.value() != 0) return source->max_age;
  if (source->kind == SourceKind::OperatorDeclaration) return Tick{};
  return policy.default_max_age;
}

[[nodiscard]] Tick observed_age(Tick now, Tick observed_at) noexcept {
  if (now <= observed_at) return Tick{};
  std::uint64_t delta = 0;
  if (!checked_sub<std::uint64_t>(now.value(), observed_at.value(), delta)) return Tick{};
  return Tick{delta};
}

[[nodiscard]] bool feature_set_valid(const FeatureSet& set, CapabilityKind kind,
                                     ReasonCode& reason) noexcept {
  if (set.size() > kMaxFeaturesPerRecord) {
    reason = ReasonCode::RejectedFeatureBudgetExceeded;
    return false;
  }
  if (!canonical_order_ok(set)) {
    reason = ReasonCode::RejectedDuplicateKey;
    return false;
  }
  for (const auto code : set.codes()) {
    if (feature_info(code) == nullptr) {
      reason = ReasonCode::RejectedUnknownFeatureCode;
      return false;
    }
    if (!feature_allowed_for(code, kind)) {
      reason = ReasonCode::RejectedFeatureNotInKind;
      return false;
    }
  }
  reason = ReasonCode::Ok;
  return true;
}

[[nodiscard]] bool limit_set_valid(const LimitSet& set, CapabilityKind kind,
                                   ReasonCode& reason) noexcept {
  if (set.size() > kMaxLimitsPerRecord) {
    reason = ReasonCode::RejectedLimitBudgetExceeded;
    return false;
  }
  if (!canonical_order_ok(set)) {
    reason = ReasonCode::RejectedDuplicateKey;
    return false;
  }
  for (const auto& entry : set.values()) {
    const LimitInfo* info = limit_info(entry.code);
    if (info == nullptr) {
      reason = ReasonCode::RejectedUnknownLimitCode;
      return false;
    }
    if (!limit_allowed_for(entry.code, kind)) {
      reason = ReasonCode::RejectedLimitNotInKind;
      return false;
    }
    if (entry.value < 0) {
      reason = ReasonCode::RejectedNegativeLimit;
      return false;
    }
    if (entry.unit.code != info->unit) {
      reason = ReasonCode::RejectedLimitUnitInvalid;
      return false;
    }
    if (!unit_is_well_formed(entry.unit)) {
      reason = ReasonCode::RejectedLimitUnitScaleInvalid;
      return false;
    }
    if (!unit_valid_for_limit(entry.code, entry.unit)) {
      reason = ReasonCode::RejectedLimitScaleNotPermitted;
      return false;
    }
  }
  reason = ReasonCode::Ok;
  return true;
}

[[nodiscard]] bool records_differ(const CapabilityEvidence& lhs,
                                  const CapabilityEvidence& rhs) noexcept {
  return lhs.capability_version != rhs.capability_version || lhs.features != rhs.features ||
         lhs.limits != rhs.limits || lhs.firmware_version != rhs.firmware_version ||
         lhs.firmware_generation != rhs.firmware_generation ||
         lhs.runtime_version != rhs.runtime_version ||
         lhs.runtime_generation != rhs.runtime_generation;
}

[[nodiscard]] ConflictId compute_conflict_id(const DeviceIncarnationRef& device, CapabilityKind kind,
                                             const std::vector<EvidenceId>& members) {
  Writer writer;
  writer.u16(kApiGeneration);
  encode(writer, device);
  writer.u16(static_cast<std::uint16_t>(kind));
  writer.u32(static_cast<std::uint32_t>(members.size()));
  for (const auto& member : members) writer.digest(member.digest());
  return ConflictId(Digest256::of(writer.span()));
}

}  // namespace

// --- Enum spellings ---------------------------------------------------------

std::string_view to_string(BootPolicy policy) noexcept {
  switch (policy) {
    case BootPolicy::ConservativeFence: return "conservative_fence";
    case BootPolicy::CarryForwardWithinFreshness: return "carry_forward_within_freshness";
  }
  return "conservative_fence";
}

std::string_view to_string(ClockMode mode) noexcept {
  switch (mode) {
    case ClockMode::Manual: return "manual";
    case ClockMode::SystemMonotonic: return "system_monotonic";
  }
  return "manual";
}

bool parse_boot_policy(std::string_view text, BootPolicy& out) noexcept {
  if (text == "conservative_fence") {
    out = BootPolicy::ConservativeFence;
    return true;
  }
  if (text == "carry_forward_within_freshness") {
    out = BootPolicy::CarryForwardWithinFreshness;
    return true;
  }
  return false;
}

bool parse_clock_mode(std::string_view text, ClockMode& out) noexcept {
  if (text == "manual") {
    out = ClockMode::Manual;
    return true;
  }
  if (text == "system_monotonic") {
    out = ClockMode::SystemMonotonic;
    return true;
  }
  return false;
}

std::string_view to_string(RecoveryClass value) noexcept {
  switch (value) {
    case RecoveryClass::CleanOpen: return "clean_open";
    case RecoveryClass::TornTailTruncated: return "torn_tail_truncated";
    case RecoveryClass::TrailingCorruptDropped: return "trailing_corrupt_dropped";
    case RecoveryClass::RebuiltFromSnapshot: return "rebuilt_from_snapshot";
    case RecoveryClass::JournalReplayed: return "journal_replayed";
    case RecoveryClass::Refused: return "refused";
  }
  return "refused";
}

bool parse_recovery_class(std::string_view text, RecoveryClass& out) noexcept {
  const RecoveryClass candidates[] = {RecoveryClass::CleanOpen,
                                      RecoveryClass::TornTailTruncated,
                                      RecoveryClass::TrailingCorruptDropped,
                                      RecoveryClass::RebuiltFromSnapshot,
                                      RecoveryClass::JournalReplayed,
                                      RecoveryClass::Refused};
  for (const auto candidate : candidates) {
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

std::string_view to_string(DecisionKind kind) noexcept {
  switch (kind) {
    case DecisionKind::Compatible: return "compatible";
    case DecisionKind::Incompatible: return "incompatible";
    case DecisionKind::Unknown: return "unknown";
    case DecisionKind::Conflicted: return "conflicted";
  }
  return "unknown";
}

bool parse_decision_kind(std::string_view text, DecisionKind& out) noexcept {
  const DecisionKind candidates[] = {DecisionKind::Compatible, DecisionKind::Incompatible,
                                     DecisionKind::Unknown, DecisionKind::Conflicted};
  for (const auto candidate : candidates) {
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

RegistryPolicy make_lab_policy() {
  RegistryPolicy policy;
  policy.policy_name = "ocreg-lab-v1";
  policy.require_configured_source = true;
  policy.refuse_untrusted_sources = true;
  policy.boot_policy = BootPolicy::ConservativeFence;
  policy.clock_mode = ClockMode::Manual;
  policy.retention_horizon = Tick{};
  policy.max_future_skew = Tick{0};
  policy.default_max_age = Tick{1'000'000'000ull};  // 1e9 ticks == one second
  policy.rule_generation = RuleGeneration{1};

  const auto add = [&policy](const char* id, SourceKind kind, AuthorityRank authority, Tick max_age,
                             bool durable) {
    const auto parsed = SourceId::parse(id);
    if (!parsed.has_value()) return;
    SourcePolicy source;
    source.id = *parsed;
    source.kind = kind;
    source.authority = authority;
    source.trust = SourceTrustState::Trusted;
    source.max_age = max_age;
    source.durable_across_boot = durable;
    policy.sources.push_back(source);
  };

  // Synthetic fixtures and simulated devices: short-lived, lowest authority.
  add("fixture-sim", SourceKind::Synthetic, AuthorityRank::Synthetic, Tick{1'000'000'000ull}, false);
  // Machinery-declared facts relayed from an adjacent runtime.
  add("topology-relay", SourceKind::AdjacentRuntime, AuthorityRank::AdjacentRuntime,
      Tick{2'000'000'000ull}, false);
  // Device or driver self-report relayed through a validated adapter.
  add("driver-selfreport", SourceKind::DeviceSelfReport, AuthorityRank::DeviceSelfReport,
      Tick{1'000'000'000ull}, false);
  // Imported previously-exported bundles.
  add("bundle-import", SourceKind::ImportedBundle, AuthorityRank::Imported,
      Tick{60'000'000'000ull}, false);
  // Human operator declarations: durable, never stale.
  add("operator-declared", SourceKind::OperatorDeclaration, AuthorityRank::Operator, Tick{}, true);
  std::sort(policy.sources.begin(), policy.sources.end());
  return policy;
}

const SourcePolicy* RegistryPolicy::find_source(const SourceId& id) const noexcept {
  for (const auto& source : sources) {
    if (source.id == id) return &source;
  }
  return nullptr;
}

Digest256 requirement_digest(const CapabilityRequirement& requirement) {
  Writer writer;
  writer.u16(kApiGeneration);
  encode(writer, requirement);
  return Digest256::of(writer.span());
}

Digest256 CompatibilityDecision::compute_digest() const {
  Writer writer;
  writer.u16(kApiGeneration);
  encode(writer, requirement);
  writer.u16(static_cast<std::uint16_t>(kind));
  writer.strong(rule_generation);
  writer.strong(registry_epoch);
  writer.strong(policy_revision);
  writer.strong(evaluated_at);
  writer.u32(static_cast<std::uint32_t>(reasons.size()));
  for (const auto reason : reasons) writer.reason(reason);
  writer.u32(static_cast<std::uint32_t>(evidence.size()));
  for (const auto& evidence_id : evidence) writer.digest(evidence_id.digest());
  writer.optional(selected, [&writer](const EvidenceId& value) { writer.digest(value.digest()); });
  writer.optional(conflict, [&writer](const ConflictId& value) { writer.digest(value.digest()); });
  writer.u16(static_cast<std::uint16_t>(selected_authority));
  return Digest256::of(writer.span());
}

// --- Implementation ---------------------------------------------------------

struct Registry::Impl {
  mutable std::shared_mutex mutex{};
  RegistryPolicy policy{};
  RegistryEpoch epoch{1};
  RuleGeneration rule_generation_value{1};
  PolicyRevision policy_revision_value{1};
  BootEpoch boot_epoch_value{1};
  StoreGeneration store_generation_value{0};
  Tick logical_tick_value{0};
  std::uint64_t next_incarnation = 1;
  // Devices are indexed by identity so that looking one up is logarithmic
  // rather than a scan per evidence record.
  std::map<DeviceIdentity, DeviceIncarnationEntry> incarnation_table{};
  World world{};
  std::size_t total_records = 0;
  std::vector<ConflictGroup> conflict_table{};
  std::vector<ConflictResolution> resolution_table{};
  // A deque for the same reason: the ledger drops its oldest entry when full.
  std::deque<EvictionEntry> eviction_table{};
  RegistryCounters counters{};
  std::map<DecisionId, CompatibilityDecision> decisions{};
  // A deque, not a vector: eviction from the retained-decision store removes
  // the oldest entry, which must not cost a shift of the whole queue.
  std::deque<DecisionId> decision_order{};

  // --- Containers (caller holds the lock) ----------------------------------

  [[nodiscard]] const DeviceIncarnationEntry* find_device(const DeviceIdentity& device) const {
    const auto it = incarnation_table.find(device);
    return it == incarnation_table.end() ? nullptr : &it->second;
  }

  [[nodiscard]] DeviceIncarnationEntry* find_device_mutable(const DeviceIdentity& device) {
    const auto it = incarnation_table.find(device);
    return it == incarnation_table.end() ? nullptr : &it->second;
  }

  [[nodiscard]] KindMap* find_kind_map(const DeviceIncarnationRef& device) {
    const auto it = world.groups.find(device);
    return it == world.groups.end() ? nullptr : &it->second;
  }

  [[nodiscard]] GroupState* find_group(const EvidenceKey& key) {
    KindMap* kinds = find_kind_map(key.device);
    if (kinds == nullptr) return nullptr;
    const auto it = kinds->find(key.kind);
    return it == kinds->end() ? nullptr : &it->second;
  }

  [[nodiscard]] GroupState& ensure_group(const EvidenceKey& key) {
    return world.groups[key.device][key.kind];
  }

  [[nodiscard]] Stream* find_stream(const EvidenceKey& key) {
    GroupState* group = find_group(key);
    if (group == nullptr) return nullptr;
    const auto it = group->streams.find(key.source);
    return it == group->streams.end() ? nullptr : &it->second;
  }

  [[nodiscard]] const RetirementRecord* find_tombstone(const EvidenceKey& key) const {
    const auto device_it = world.groups.find(key.device);
    if (device_it == world.groups.end()) return nullptr;
    const auto kind_it = device_it->second.find(key.kind);
    if (kind_it == device_it->second.end()) return nullptr;
    const auto tombstone_it = kind_it->second.tombstones.find(key.source);
    if (tombstone_it == kind_it->second.tombstones.end()) return nullptr;
    return &tombstone_it->second;
  }

  [[nodiscard]] const ConflictGroup* find_conflict(const DeviceIncarnationRef& device,
                                                   CapabilityKind kind) const {
    for (const auto& group : conflict_table) {
      if (group.device == device && group.kind == kind) return &group;
    }
    return nullptr;
  }

  [[nodiscard]] ConflictGroup* find_conflict_mutable(const DeviceIncarnationRef& device,
                                                     CapabilityKind kind) {
    for (auto& group : conflict_table) {
      if (group.device == device && group.kind == kind) return &group;
    }
    return nullptr;
  }

  [[nodiscard]] const ConflictResolution* find_resolution(const ConflictId& id) const {
    for (const auto& resolution : resolution_table) {
      if (resolution.conflict == id) return &resolution;
    }
    return nullptr;
  }

  // --- State derivation -----------------------------------------------------

  struct DerivedFact {
    const StoredEvidence* record = nullptr;
    EvidenceState state = EvidenceState::Rejected;
    ReasonCode reason = ReasonCode::Ok;
    Tick age{};
  };

  struct Derivation {
    std::vector<DerivedFact> facts{};              // ordered by evidence id
    std::vector<const StoredEvidence*> live{};     // Active at the highest authority
    std::vector<EvidenceId> live_ids{};            // ordered by evidence id
    AuthorityRank live_authority = AuthorityRank::None;
    bool disagrees = false;
    std::optional<ConflictId> conflict{};
  };

  [[nodiscard]] EvidenceState classify(const StoredEvidence& record, const Stream& stream,
                                       const SourcePolicy* source,
                                       const DeviceIncarnationRef& device, Tick now,
                                       Tick max_age_override, ReasonCode& reason) const {
    if (record.lifecycle == EvidenceLifecycle::Rejected) {
      reason = record.admission_reason;
      return EvidenceState::Rejected;
    }
    if (record.lifecycle == EvidenceLifecycle::Retired) {
      reason = record.retirement_reason;
      return EvidenceState::Retired;
    }
    if (stream.max_generation.value() != 0 && record.evidence.generation < stream.max_generation) {
      reason = ReasonCode::RejectedSupersededGeneration;
      return EvidenceState::Superseded;
    }
    const DeviceIncarnationEntry* entry = find_device(device.device);
    if (entry == nullptr || entry->current != device.incarnation) {
      reason = ReasonCode::UnknownIncarnationNotCurrent;
      return EvidenceState::Fenced;
    }
    if (source == nullptr) {
      reason = ReasonCode::UnknownSourceNotConfigured;
      return EvidenceState::Fenced;
    }
    if (source->trust == SourceTrustState::Revoked) {
      reason = ReasonCode::IncompatibleSourceRevoked;
      return EvidenceState::Fenced;
    }
    if (source->trust == SourceTrustState::Untrusted && policy.refuse_untrusted_sources) {
      reason = ReasonCode::RejectedSourceUntrusted;
      return EvidenceState::Fenced;
    }
    if (record.evidence.boot_at_ingest > boot_epoch_value) {
      // An observation stamped with a boot epoch that has not happened is an
      // integrity fault, not a freshness question.
      reason = ReasonCode::StoreBootReplay;
      return EvidenceState::Fenced;
    }
    if (record.evidence.boot_at_ingest < boot_epoch_value && !source->durable_across_boot &&
        policy.boot_policy == BootPolicy::ConservativeFence) {
      reason = ReasonCode::UnknownFencedEvidence;
      return EvidenceState::Fenced;
    }
    const Tick bound = effective_max_age(policy, source, max_age_override);
    if (bound.value() != 0 && observed_age(now, record.evidence.observed_at) > bound) {
      reason = ReasonCode::UnknownStaleEvidence;
      return EvidenceState::Stale;
    }
    if (record.evidence.valid_until.has_value() && now > *record.evidence.valid_until) {
      reason = ReasonCode::UnknownStaleEvidence;
      return EvidenceState::Stale;
    }
    reason = ReasonCode::AcceptedNew;
    return EvidenceState::Active;
  }

  [[nodiscard]] Derivation derive(const DeviceIncarnationRef& device, CapabilityKind kind, Tick now,
                                  Tick max_age_override) const {
    Derivation result;
    const auto device_it = world.groups.find(device);
    if (device_it == world.groups.end()) return result;
    const auto kind_it = device_it->second.find(kind);
    if (kind_it == device_it->second.end()) return result;

    for (const auto& [source_id, stream] : kind_it->second.streams) {
      const SourcePolicy* source = policy.find_source(source_id);
      for (const auto& record : stream.records) {
        DerivedFact fact;
        fact.record = &record;
        fact.age = observed_age(now, record.evidence.observed_at);
        fact.state = classify(record, stream, source, device, now, max_age_override, fact.reason);
        result.facts.push_back(fact);
      }
    }

    AuthorityRank highest = AuthorityRank::None;
    for (const auto& fact : result.facts) {
      if (fact.state == EvidenceState::Active && fact.record->evidence.authority > highest) {
        highest = fact.record->evidence.authority;
      }
    }
    for (auto& fact : result.facts) {
      if (fact.state == EvidenceState::Active && fact.record->evidence.authority < highest) {
        fact.state = EvidenceState::Outranked;
        fact.reason = ReasonCode::ConflictOutranked;
      }
    }
    result.live_authority = highest;
    for (const auto& fact : result.facts) {
      if (fact.state == EvidenceState::Active) result.live.push_back(fact.record);
    }
    std::sort(result.live.begin(), result.live.end(),
              [](const StoredEvidence* a, const StoredEvidence* b) {
                return a->evidence.id() < b->evidence.id();
              });
    for (const auto* record : result.live) result.live_ids.push_back(record->evidence.id());

    for (std::size_t i = 1; i < result.live.size(); ++i) {
      if (records_differ(result.live[0]->evidence, result.live[i]->evidence)) {
        result.disagrees = true;
        break;
      }
    }
    if (result.disagrees) {
      result.conflict = compute_conflict_id(device, kind, result.live_ids);
    }

    std::sort(result.facts.begin(), result.facts.end(),
              [](const DerivedFact& a, const DerivedFact& b) {
                return a.record->evidence.id() < b.record->evidence.id();
              });
    return result;
  }

  void refresh_conflict(const DeviceIncarnationRef& device, CapabilityKind kind, Tick now) {
    const Derivation derivation = derive(device, kind, now, Tick{});
    ConflictGroup* existing = find_conflict_mutable(device, kind);
    if (!derivation.disagrees) {
      if (existing != nullptr) {
        const std::size_t index = static_cast<std::size_t>(existing - conflict_table.data());
        conflict_table.erase(conflict_table.begin() + static_cast<std::ptrdiff_t>(index));
      }
      return;
    }
    ConflictGroup group;
    group.id = *derivation.conflict;
    group.device = device;
    group.kind = kind;
    group.authority = derivation.live_authority;
    for (const auto* record : derivation.live) {
      group.members.push_back(record->evidence.id());
      group.generations.push_back(record->evidence.generation);
    }
    std::sort(group.members.begin(), group.members.end());
    group.observed_first = derivation.live.front()->evidence.observed_at;
    group.observed_last = group.observed_first;
    for (const auto* record : derivation.live) {
      if (record->evidence.observed_at < group.observed_first) {
        group.observed_first = record->evidence.observed_at;
      }
      if (record->evidence.observed_at > group.observed_last) {
        group.observed_last = record->evidence.observed_at;
      }
    }
    if (existing != nullptr) {
      const ConflictId previous = existing->id;
      *existing = group;
      if (!(previous == group.id)) {
        std::sort(conflict_table.begin(), conflict_table.end(),
                  [](const ConflictGroup& a, const ConflictGroup& b) { return a.id < b.id; });
      }
      return;
    }
    if (conflict_table.size() >= policy.limits.max_conflict_groups) {
      ++counters.conflicts_dropped;
      return;
    }
    conflict_table.push_back(group);
    std::sort(conflict_table.begin(), conflict_table.end(),
              [](const ConflictGroup& a, const ConflictGroup& b) { return a.id < b.id; });
  }

  void refresh_all_conflicts(Tick now) {
    const std::vector<DeviceIncarnationRef> keys = group_keys();
    conflict_table.clear();
    for (const auto& device : keys) {
      const auto device_it = world.groups.find(device);
      if (device_it == world.groups.end()) continue;
      for (const auto& [kind, unused] : device_it->second) {
        (void)unused;
        refresh_conflict(device, kind, now);
      }
    }
  }

  [[nodiscard]] std::vector<DeviceIncarnationRef> group_keys() const {
    std::vector<DeviceIncarnationRef> keys;
    for (const auto& [device, kinds] : world.groups) {
      if (!kinds.empty()) keys.push_back(device);
    }
    return keys;
  }

  // --- Eviction -------------------------------------------------------------

  [[nodiscard]] int eviction_priority(const EvidenceKey& key, const Stream& stream,
                                      const StoredEvidence& record, Tick now) const {
    if (record.lifecycle == EvidenceLifecycle::Rejected) return 0;
    if (record.lifecycle == EvidenceLifecycle::Retired) return 4;
    if (stream.max_generation.value() != 0 && record.evidence.generation < stream.max_generation) {
      return 1;
    }
    const DeviceIncarnationEntry* entry = find_device(key.device.device);
    const SourcePolicy* source = policy.find_source(key.source);
    if (entry == nullptr || entry->current != key.device.incarnation) return 2;
    if (source == nullptr || source->trust == SourceTrustState::Revoked) return 2;
    if (source->trust == SourceTrustState::Untrusted && policy.refuse_untrusted_sources) return 2;
    if (record.evidence.boot_at_ingest > boot_epoch_value) return 2;
    if (record.evidence.boot_at_ingest < boot_epoch_value && !source->durable_across_boot &&
        policy.boot_policy == BootPolicy::ConservativeFence) {
      return 2;
    }
    const Tick bound = effective_max_age(policy, source, Tick{});
    if (bound.value() != 0 && observed_age(now, record.evidence.observed_at) > bound) return 3;
    if (record.evidence.valid_until.has_value() && now > *record.evidence.valid_until) return 3;
    return 5;
  }

  struct EvictionCandidate {
    EvidenceKey key{};
    EvidenceId id{};
    int priority = 0;
    Tick observed_at{};
  };

  [[nodiscard]] bool pick_eviction_candidate(const EvidenceKey* restrict_key,
                                             const EvidenceId* forbidden, Tick now,
                                             EvictionCandidate& out) const {
    bool found = false;
    for (const auto& [device, kinds] : world.groups) {
      for (const auto& [kind, group] : kinds) {
        for (const auto& [source_id, stream] : group.streams) {
          const EvidenceKey key{device, kind, source_id};
          if (restrict_key != nullptr && !(key == *restrict_key)) continue;
          for (const auto& record : stream.records) {
            if (forbidden != nullptr && record.evidence.id() == *forbidden) continue;
            const int priority = eviction_priority(key, stream, record, now);
            bool evictable = priority <= 4;
            if (priority == 5) {
              const Derivation derivation = derive(device, kind, now, Tick{});
              for (const auto& fact : derivation.facts) {
                if (fact.record->evidence.id() == record.evidence.id()) {
                  evictable = fact.state == EvidenceState::Outranked;
                  break;
                }
              }
            }
            if (!evictable) continue;
            const bool better =
                !found || priority < out.priority ||
                (priority == out.priority && record.evidence.observed_at < out.observed_at) ||
                (priority == out.priority && record.evidence.observed_at == out.observed_at &&
                 record.evidence.id() < out.id);
            if (better) {
              out.key = key;
              out.id = record.evidence.id();
              out.priority = priority;
              out.observed_at = record.evidence.observed_at;
              found = true;
            }
          }
        }
      }
    }
    return found;
  }

  // Removes exactly the selected record. Records inside a stream are ordered by
  // (generation, id), so the record is located by identity rather than by a
  // position guessed from a different ordering.
  [[nodiscard]] bool apply_eviction(const EvictionCandidate& candidate, Tick now,
                                    std::vector<EvidenceId>& out) {
    GroupState* group = find_group(candidate.key);
    if (group == nullptr) return false;
    const auto stream_it = group->streams.find(candidate.key.source);
    if (stream_it == group->streams.end()) return false;
    auto& records = stream_it->second.records;
    const auto position = std::find_if(records.begin(), records.end(),
                                       [&candidate](const StoredEvidence& record) {
                                         return record.evidence.id() == candidate.id;
                                       });
    if (position == records.end()) return false;

    EvictionEntry entry;
    entry.id = position->evidence.id();
    entry.key = candidate.key;
    entry.generation = position->evidence.generation;
    entry.state_at_eviction = position->lifecycle == EvidenceLifecycle::Retired
                                  ? EvidenceState::Retired
                                  : (position->lifecycle == EvidenceLifecycle::Rejected
                                         ? EvidenceState::Rejected
                                         : (position->evidence.generation <
                                                    stream_it->second.max_generation
                                                ? EvidenceState::Superseded
                                                : EvidenceState::Outranked));
    entry.reason = entry.state_at_eviction == EvidenceState::Retired
                       ? ReasonCode::EvictedRetired
                       : (entry.state_at_eviction == EvidenceState::Superseded
                              ? ReasonCode::EvictedSuperseded
                              : ReasonCode::EvictedBudgetPressure);
    entry.evicted_at = now;

    ++counters.evictions_total;
    if (eviction_table.size() >= policy.limits.max_eviction_ledger) {
      eviction_table.erase(eviction_table.begin());
      ++counters.eviction_ledger_dropped;
    }
    eviction_table.push_back(entry);
    out.push_back(entry.id);

    records.erase(position);
    if (total_records > 0) --total_records;
    RecordGeneration highest{};
    for (const auto& record : records) {
      if (record.evidence.generation > highest) highest = record.evidence.generation;
    }
    stream_it->second.max_generation = highest;
    return true;
  }

  // Applies the global and per-stream bounds on behalf of one incoming record.
  // Every iteration removes exactly one record, and a step that removes nothing
  // ends the loop, so the bound is enforced in finite time by construction.
  [[nodiscard]] bool enforce_budget(const EvidenceKey& keep_key, const EvidenceId& keep_id,
                                    Tick now, std::vector<EvidenceId>& evicted) {
    while (total_records > policy.limits.max_records) {
      EvictionCandidate candidate;
      if (!pick_eviction_candidate(nullptr, &keep_id, now, candidate)) return false;
      if (!apply_eviction(candidate, now, evicted)) return false;
    }
    while (true) {
      Stream* stream = find_stream(keep_key);
      if (stream == nullptr) return true;
      if (stream->records.size() <= policy.limits.max_records_per_stream) return true;
      EvictionCandidate candidate;
      if (!pick_eviction_candidate(&keep_key, &keep_id, now, candidate)) return false;
      if (!apply_eviction(candidate, now, evicted)) return false;
    }
  }

  // --- Explanation store ----------------------------------------------------

  void push_decision(const CompatibilityDecision& decision) {
    const auto existing = decisions.find(decision.id);
    if (existing != decisions.end()) {
      existing->second = decision;
      return;
    }
    while (decisions.size() >= policy.limits.max_decisions && !decision_order.empty()) {
      const DecisionId oldest = decision_order.front();
      decision_order.erase(decision_order.begin());
      if (decisions.erase(oldest) > 0) ++counters.decisions_evicted;
    }
    decisions.emplace(decision.id, decision);
    decision_order.push_back(decision.id);
  }

  void push_resolution(const ConflictResolution& resolution) {
    for (auto& existing : resolution_table) {
      if (existing.id == resolution.id) {
        existing = resolution;
        return;
      }
    }
    if (resolution_table.size() >= policy.limits.max_resolutions) {
      resolution_table.erase(resolution_table.begin());
      ++counters.resolutions_dropped;
    }
    resolution_table.push_back(resolution);
    std::sort(resolution_table.begin(), resolution_table.end(),
              [](const ConflictResolution& a, const ConflictResolution& b) { return a.id < b.id; });
  }

  void push_tombstone(const RetirementRecord& tombstone) {
    GroupState& group = ensure_group(tombstone.key);
    auto& slot = group.tombstones[tombstone.key.source];
    if (slot.generation >= tombstone.generation && !slot.key.source.empty()) return;
    slot = tombstone;
    std::size_t count = 0;
    for (const auto& [device, kinds] : world.groups) {
      (void)device;
      for (const auto& [kind, state] : kinds) {
        (void)kind;
        count += state.tombstones.size();
      }
    }
    if (count > policy.limits.max_tombstones) {
      // Drop the oldest tombstone in the whole registry and account for it.
      bool removed = false;
      Tick oldest{};
      DeviceIncarnationRef oldest_device{};
      CapabilityKind oldest_kind = CapabilityKind::PacketClassification;
      SourceId oldest_source{};
      for (const auto& [device, kinds] : world.groups) {
        for (const auto& [kind, state] : kinds) {
          for (const auto& [source_id, record] : state.tombstones) {
            if (!removed || record.retired_at < oldest) {
              oldest = record.retired_at;
              oldest_device = device;
              oldest_kind = kind;
              oldest_source = source_id;
              removed = true;
            }
          }
        }
      }
      if (removed && !(oldest_device == tombstone.key.device && oldest_kind == tombstone.key.kind &&
                       oldest_source == tombstone.key.source)) {
        world.groups[oldest_device][oldest_kind].tombstones.erase(oldest_source);
        ++counters.tombstones_dropped;
      }
    }
  }

  // --- Enumeration ----------------------------------------------------------

  [[nodiscard]] std::vector<StoredEvidence> flatten_records() const {
    std::vector<StoredEvidence> out;
    out.reserve(total_records);
    for (const auto& [device, kinds] : world.groups) {
      (void)device;
      for (const auto& [kind, group] : kinds) {
        (void)kind;
        for (const auto& [source_id, stream] : group.streams) {
          (void)source_id;
          for (const auto& record : stream.records) out.push_back(record);
        }
      }
    }
    return out;
  }

  [[nodiscard]] std::vector<RetirementRecord> flatten_tombstones() const {
    std::vector<RetirementRecord> out;
    for (const auto& [device, kinds] : world.groups) {
      (void)device;
      for (const auto& [kind, group] : kinds) {
        (void)kind;
        for (const auto& [source_id, record] : group.tombstones) {
          (void)source_id;
          out.push_back(record);
        }
      }
    }
    std::sort(out.begin(), out.end(), [](const RetirementRecord& a, const RetirementRecord& b) {
      if (a.key != b.key) return a.key < b.key;
      return a.generation < b.generation;
    });
    return out;
  }

  void adopt(RegistryState state) {
    policy = std::move(state.policy);
    std::sort(policy.sources.begin(), policy.sources.end());
    epoch = state.epoch;
    rule_generation_value = state.rule_generation;
    policy_revision_value = state.policy_revision;
    boot_epoch_value = state.boot_epoch;
    store_generation_value = state.store_generation;
    logical_tick_value = state.logical_tick;
    next_incarnation = state.next_incarnation == 0 ? 1 : state.next_incarnation;
    incarnation_table.clear();
    for (auto& entry : state.incarnations) {
      const DeviceIdentity device = entry.device;
      incarnation_table[device] = std::move(entry);
    }
    world = World{};
    total_records = 0;
    for (auto& record : state.records) {
      const EvidenceKey& key = record.evidence.key;
      Stream& stream = world.groups[key.device][key.kind].streams[key.source];
      if (record.evidence.generation > stream.max_generation) {
        stream.max_generation = record.evidence.generation;
      }
      stream.records.push_back(std::move(record));
      ++total_records;
    }
    for (auto& [device, kinds] : world.groups) {
      (void)device;
      for (auto& [kind, group] : kinds) {
        (void)kind;
        for (auto& [source_id, stream] : group.streams) {
          (void)source_id;
          std::sort(stream.records.begin(), stream.records.end(), generation_less);
        }
      }
    }
    for (const auto& tombstone : state.tombstones) {
      world.groups[tombstone.key.device][tombstone.key.kind].tombstones[tombstone.key.source] =
          tombstone;
    }
    conflict_table = std::move(state.conflicts);
    std::sort(conflict_table.begin(), conflict_table.end(),
              [](const ConflictGroup& a, const ConflictGroup& b) { return a.id < b.id; });
    resolution_table = std::move(state.resolutions);
    std::sort(resolution_table.begin(), resolution_table.end(),
              [](const ConflictResolution& a, const ConflictResolution& b) { return a.id < b.id; });
    eviction_table.assign(state.evictions.begin(), state.evictions.end());
    counters = state.counters;
    decisions.clear();
    decision_order.clear();
  }

  [[nodiscard]] RegistryState to_state() const {
    RegistryState state;
    state.policy = policy;
    state.epoch = epoch;
    state.rule_generation = rule_generation_value;
    state.policy_revision = policy_revision_value;
    state.boot_epoch = boot_epoch_value;
    state.store_generation = store_generation_value;
    state.logical_tick = logical_tick_value;
    state.next_incarnation = next_incarnation;
    state.incarnations.reserve(incarnation_table.size());
    for (const auto& [device, entry] : incarnation_table) {
      (void)device;
      state.incarnations.push_back(entry);
    }
    state.records = flatten_records();
    state.tombstones = flatten_tombstones();
    state.conflicts = conflict_table;
    state.resolutions = resolution_table;
    state.evictions.assign(eviction_table.begin(), eviction_table.end());
    state.counters = counters;
    return state;
  }

  void bump_policy_revision() {
    policy_revision_value = PolicyRevision(policy_revision_value.value() + 1);
    epoch = RegistryEpoch(epoch.value() + 1);
  }

  [[nodiscard]] std::size_t count_streams() const noexcept {
    std::size_t count = 0;
    for (const auto& [device, kinds] : world.groups) {
      (void)device;
      for (const auto& [kind, group] : kinds) {
        (void)kind;
        count += group.streams.size();
      }
    }
    return count;
  }
};

// --- Construction -----------------------------------------------------------

Registry::Registry(RegistryPolicy policy) : impl_(std::make_unique<Impl>()) {
  impl_->policy = std::move(policy);
  std::sort(impl_->policy.sources.begin(), impl_->policy.sources.end());
  impl_->rule_generation_value = impl_->policy.rule_generation;
}

Registry::Registry(RegistryPolicy policy, RegistryState restored)
    : impl_(std::make_unique<Impl>()) {
  RegistryPolicy merged = std::move(policy);
  std::sort(merged.sources.begin(), merged.sources.end());
  impl_->adopt(std::move(restored));
  impl_->policy = std::move(merged);
  impl_->rule_generation_value = impl_->policy.rule_generation;
}

Registry::~Registry() = default;

// --- Mutations --------------------------------------------------------------

Outcome<AdmissionOutcome> Registry::admit(const AdmissionRequest& request, Tick now) {
  std::unique_lock lock(impl_->mutex);
  Impl& impl = *impl_;

  const auto reject = [&impl](ReasonCode reason, const char* detail) {
    ++impl.counters.admissions_rejected;
    return Outcome<AdmissionOutcome>(Status::failure(reason, detail));
  };

  if (request.generation.is_unset()) {
    return reject(ReasonCode::RejectedGenerationRegression, "stream generation must be non-zero");
  }
  if (request.valid_until.has_value() && *request.valid_until < request.observed_at) {
    return reject(ReasonCode::RejectedValidityWindowInverted, "valid_until precedes observed_at");
  }
  if (request.observed_at > now &&
      (request.observed_at.value() - now.value()) > impl.policy.max_future_skew.value()) {
    return reject(ReasonCode::RejectedFutureObservation, "observation is ahead of the logical clock");
  }
  if (impl.policy.retention_horizon.value() != 0 && now.value() != 0 &&
      observed_age(now, request.observed_at) > impl.policy.retention_horizon) {
    return reject(ReasonCode::RejectedBeyondRetentionHorizon,
                  "observation is outside the retention horizon");
  }

  const SourcePolicy* source = impl.policy.find_source(request.source.source);
  if (source == nullptr) {
    if (impl.policy.require_configured_source) {
      return reject(ReasonCode::RejectedUnknownSource, "source has no policy entry");
    }
  } else {
    if (source->trust == SourceTrustState::Revoked) {
      return reject(ReasonCode::RejectedSourceRevoked, "source is revoked");
    }
    if (source->trust == SourceTrustState::Untrusted && impl.policy.refuse_untrusted_sources) {
      return reject(ReasonCode::RejectedSourceUntrusted, "source is untrusted");
    }
  }

  ReasonCode validation = ReasonCode::Ok;
  if (request.features.size() > impl.policy.limits.max_features_per_record ||
      request.limits.size() > impl.policy.limits.max_limits_per_record) {
    return reject(ReasonCode::RejectedFeatureBudgetExceeded,
                  "record exceeds the configured width bound");
  }
  if (!feature_set_valid(request.features, request.kind, validation)) {
    return reject(validation, "feature set rejected");
  }
  if (!limit_set_valid(request.limits, request.kind, validation)) {
    return reject(validation, "limit set rejected");
  }

  DeviceIncarnationEntry* device_entry = impl.find_device_mutable(request.device.device);
  if (device_entry == nullptr) {
    if (impl.incarnation_table.size() >= impl.policy.limits.max_devices) {
      return reject(ReasonCode::RejectedDeviceBudgetExhausted, "device bound reached");
    }
    DeviceIncarnationEntry entry;
    entry.device = request.device.device;
    entry.current = request.device.incarnation;
    entry.history.push_back(request.device.incarnation);
    impl.incarnation_table[request.device.device] = std::move(entry);
    if (impl.next_incarnation <= request.device.incarnation.value()) {
      impl.next_incarnation = request.device.incarnation.value() + 1;
    }
  } else {
    const bool known = std::find(device_entry->history.begin(), device_entry->history.end(),
                                 request.device.incarnation) != device_entry->history.end();
    if (!known) {
      if (device_entry->history.size() >= impl.policy.limits.max_incarnations_per_device) {
        return reject(ReasonCode::RejectedDeviceBudgetExhausted, "incarnation bound reached");
      }
      device_entry->history.push_back(request.device.incarnation);
      std::sort(device_entry->history.begin(), device_entry->history.end());
    }
    if (impl.next_incarnation <= request.device.incarnation.value()) {
      impl.next_incarnation = request.device.incarnation.value() + 1;
    }
  }

  const EvidenceKey key{request.device, request.kind, request.source.source};
  if (impl.find_stream(key) == nullptr && impl.count_streams() >= impl.policy.limits.max_streams) {
    return reject(ReasonCode::RejectedStreamBudgetExhausted, "stream bound reached");
  }

  const RetirementRecord* tombstone = impl.find_tombstone(key);
  if (tombstone != nullptr && tombstone->generation >= request.generation) {
    return reject(ReasonCode::RejectedRetiredStream,
                  "stream is retired at this generation or later");
  }

  CapabilityEvidence evidence;
  evidence.key = key;
  evidence.source_incarnation = request.source;
  evidence.capability_version = request.capability_version;
  evidence.features = request.features;
  evidence.limits = request.limits;
  evidence.firmware_version = request.firmware_version;
  evidence.firmware_generation = request.firmware_generation;
  evidence.runtime_version = request.runtime_version;
  evidence.runtime_generation = request.runtime_generation;
  evidence.observed_at = request.observed_at;
  evidence.valid_until = request.valid_until;
  evidence.generation = request.generation;
  evidence.authority = source == nullptr ? AuthorityRank::None : source->authority;
  evidence.epoch_at_ingest = impl.epoch;
  evidence.boot_at_ingest = impl.boot_epoch_value;
  evidence.policy_revision = impl.policy_revision_value;

  // The identifier is computed once here and only read afterwards.
  detail::refresh_evidence_id(evidence);
  const EvidenceId incoming = evidence.id();
  Stream& stream = impl.ensure_group(key).streams[key.source];

  const auto duplicate = std::find_if(stream.records.begin(), stream.records.end(),
                                     [&incoming](const StoredEvidence& candidate) {
                                       return candidate.evidence.id() == incoming;
                                     });
  if (duplicate != stream.records.end()) {
    ++impl.counters.admissions_idempotent;
    AdmissionOutcome outcome;
    outcome.id = incoming;
    outcome.reason = ReasonCode::AlreadyPresent;
    outcome.idempotent = true;
    outcome.stream_generation = stream.max_generation;
    const Impl::Derivation derivation = impl.derive(key.device, key.kind, now, Tick{});
    for (const auto& fact : derivation.facts) {
      if (fact.record->evidence.id() == incoming) outcome.state = fact.state;
    }
    return Outcome<AdmissionOutcome>(outcome);
  }

  const bool generation_regression =
      stream.max_generation.value() != 0 && request.generation < stream.max_generation;
  const bool generation_collision =
      stream.max_generation.value() != 0 && request.generation == stream.max_generation;
  if (generation_regression || generation_collision) {
    const ReasonCode reason = generation_regression ? ReasonCode::RejectedSupersededGeneration
                                                    : ReasonCode::RejectedGenerationCollision;
    ++impl.counters.admissions_rejected;
    StoredEvidence rejected;
    rejected.evidence = evidence;
    rejected.lifecycle = EvidenceLifecycle::Rejected;
    rejected.admission_reason = reason;
    rejected.admitted_at = now;
    // Rejected evidence is retained when the bounds allow, so that a later
    // query can explain the refusal. When they do not, it is accounted for
    // through the rejection counter and the caller still sees the reason.
    Stream* rejected_stream = impl.find_stream(key);
    if (rejected_stream != nullptr &&
        rejected_stream->records.size() < impl.policy.limits.max_records_per_stream &&
        impl.total_records < impl.policy.limits.max_records) {
      const auto position = std::lower_bound(rejected_stream->records.begin(),
                                             rejected_stream->records.end(), rejected,
                                             generation_less);
      rejected_stream->records.insert(position, std::move(rejected));
      ++impl.total_records;
      impl.refresh_conflict(key.device, key.kind, now);
    }
    AdmissionOutcome outcome;
    outcome.id = incoming;
    outcome.state = EvidenceState::Rejected;
    outcome.reason = reason;
    outcome.stream_generation = stream.max_generation;
    return Outcome<AdmissionOutcome>(outcome);
  }

  StoredEvidence stored;
  stored.evidence = std::move(evidence);
  stored.lifecycle = EvidenceLifecycle::Admitted;
  stored.admission_reason = stream.max_generation.value() == 0 ? ReasonCode::AcceptedNew
                                                               : ReasonCode::AcceptedSuperseding;
  stored.admitted_at = now;

  const RecordGeneration previous_max = stream.max_generation;
  const auto insert_at =
      std::lower_bound(stream.records.begin(), stream.records.end(), stored, generation_less);
  stream.records.insert(insert_at, std::move(stored));
  stream.max_generation = request.generation;
  ++impl.total_records;

  AdmissionOutcome outcome;
  outcome.id = incoming;
  outcome.reason = previous_max.value() == 0 ? ReasonCode::AcceptedNew
                                             : ReasonCode::AcceptedSuperseding;
  outcome.stream_generation = stream.max_generation;
  if (previous_max.value() != 0) {
    for (const auto& record : stream.records) {
      if (record.evidence.generation < stream.max_generation) {
        outcome.superseded.push_back(record.evidence.id());
      }
    }
    std::sort(outcome.superseded.begin(), outcome.superseded.end());
  }

  if (!impl.enforce_budget(key, incoming, now, outcome.evicted)) {
    GroupState* group = impl.find_group(key);
    if (group != nullptr) {
      auto& records = group->streams[key.source].records;
      const auto position = std::find_if(records.begin(), records.end(),
                                         [&incoming](const StoredEvidence& candidate) {
                                           return candidate.evidence.id() == incoming;
                                         });
      if (position != records.end()) {
        records.erase(position);
        if (impl.total_records > 0) --impl.total_records;
      }
      RecordGeneration highest{};
      for (const auto& record : records) {
        if (record.evidence.generation > highest) highest = record.evidence.generation;
      }
      group->streams[key.source].max_generation = highest;
      if (group->streams[key.source].records.empty()) group->streams.erase(key.source);
      if (group->streams.empty() && group->tombstones.empty()) {
        auto kinds = impl.find_kind_map(key.device);
        if (kinds != nullptr) {
          kinds->erase(key.kind);
          if (kinds->empty()) impl.world.groups.erase(key.device);
        }
      }
    }
    ++impl.counters.admissions_rejected;
    return Outcome<AdmissionOutcome>(
        Status::failure(ReasonCode::RejectedRecordBudgetExhausted,
                        "no evictable record exists to satisfy the record budget"));
  }

  ++impl.counters.admissions_accepted;
  impl.refresh_conflict(key.device, key.kind, now);
  const Impl::Derivation derivation = impl.derive(key.device, key.kind, now, Tick{});
  for (const auto& fact : derivation.facts) {
    if (fact.record->evidence.id() == incoming) outcome.state = fact.state;
  }
  if (derivation.disagrees) outcome.conflict = derivation.conflict;
  return Outcome<AdmissionOutcome>(outcome);
}

Outcome<RetirementOutcome> Registry::retire(const RetirementRequest& request, Tick now) {
  std::unique_lock lock(impl_->mutex);
  Impl& impl = *impl_;

  const auto reject = [&impl](ReasonCode reason, const char* detail) {
    ++impl.counters.retirements_rejected;
    return Outcome<RetirementOutcome>(Status::failure(reason, detail));
  };

  if (request.generation.is_unset()) {
    return reject(ReasonCode::RejectedGenerationRegression, "retirement generation must be non-zero");
  }
  if (impl.policy.find_source(request.source) == nullptr &&
      impl.policy.require_configured_source) {
    return reject(ReasonCode::RejectedUnknownSource, "source has no policy entry");
  }
  const DeviceIncarnationEntry* device_entry = impl.find_device(request.device.device);
  if (device_entry == nullptr) {
    return reject(ReasonCode::RejectedDeviceIncarnationFenced, "device is not registered");
  }

  const EvidenceKey key{request.device, request.kind, request.source};
  const RetirementRecord* tombstone = impl.find_tombstone(key);
  if (tombstone != nullptr && tombstone->generation == request.generation) {
    ++impl.counters.retirements_accepted;
    RetirementOutcome outcome;
    outcome.key = key;
    outcome.generation = request.generation;
    outcome.reason = ReasonCode::AlreadyPresent;
    outcome.idempotent = true;
    return Outcome<RetirementOutcome>(outcome);
  }
  if (tombstone != nullptr && tombstone->generation > request.generation) {
    return reject(ReasonCode::RejectedSupersededGeneration,
                  "a later retirement already fences this stream");
  }

  const Stream* stream = impl.find_stream(key);
  if (stream != nullptr && stream->max_generation.value() != 0 &&
      request.generation <= stream->max_generation) {
    return reject(ReasonCode::RejectedSupersededGeneration,
                  "retirement generation must exceed the newest admitted generation");
  }
  if (stream == nullptr) {
    return reject(ReasonCode::UnknownNoEvidence, "stream holds no records");
  }

  RetirementRecord record;
  record.key = key;
  record.generation = request.generation;
  record.retired_at = now;
  record.reason = request.reason == ReasonCode::Ok ? ReasonCode::UnknownCapabilityRetired
                                                   : request.reason;
  record.epoch = impl.epoch;
  record.policy_revision = impl.policy_revision_value;
  const SourcePolicy* source = impl.policy.find_source(request.source);
  record.authority = source == nullptr ? AuthorityRank::None : source->authority;

  RetirementOutcome outcome;
  outcome.key = key;
  outcome.generation = request.generation;
  outcome.reason = record.reason;

  GroupState* group = impl.find_group(key);
  if (group != nullptr) {
    auto& records = group->streams[key.source].records;
    for (auto& stored : records) {
      if (stored.evidence.generation <= request.generation &&
          stored.lifecycle == EvidenceLifecycle::Admitted) {
        stored.lifecycle = EvidenceLifecycle::Retired;
        stored.retired_at = now;
        stored.retirement_reason = record.reason;
        outcome.retired.push_back(stored.evidence.id());
      }
    }
    std::sort(outcome.retired.begin(), outcome.retired.end());
  }
  impl.push_tombstone(record);
  ++impl.counters.retirements_accepted;
  impl.refresh_conflict(key.device, key.kind, now);
  return Outcome<RetirementOutcome>(outcome);
}

Outcome<IncarnationId> Registry::begin_device_incarnation(const DeviceIdentity& device, Tick now) {
  std::unique_lock lock(impl_->mutex);
  Impl& impl = *impl_;

  DeviceIncarnationEntry* entry = impl.find_device_mutable(device);
  if (entry == nullptr) {
    if (impl.incarnation_table.size() >= impl.policy.limits.max_devices) {
      return Outcome<IncarnationId>(Status::failure(ReasonCode::RejectedDeviceBudgetExhausted,
                                                    "device bound reached"));
    }
    if (impl.next_incarnation == 0) impl.next_incarnation = 1;
    DeviceIncarnationEntry created;
    created.device = device;
    created.current = IncarnationId(impl.next_incarnation++);
    created.history.push_back(created.current);
    const IncarnationId result = created.current;
    impl.incarnation_table[device] = std::move(created);
    impl.bump_policy_revision();
    return Outcome<IncarnationId>(result);
  }
  if (entry->history.size() >= impl.policy.limits.max_incarnations_per_device) {
    return Outcome<IncarnationId>(Status::failure(ReasonCode::RejectedDeviceBudgetExhausted,
                                                  "incarnation bound reached"));
  }
  if (impl.next_incarnation == 0) impl.next_incarnation = 1;
  entry->current = IncarnationId(impl.next_incarnation++);
  entry->history.push_back(entry->current);
  std::sort(entry->history.begin(), entry->history.end());
  impl.bump_policy_revision();
  // Every group of this device changes authority status, so conflicts are
  // recomputed rather than patched.
  impl.refresh_all_conflicts(now);
  return Outcome<IncarnationId>(entry->current);
}

Outcome<IncarnationId> Registry::set_device_incarnation(const DeviceIdentity& device,
                                                        IncarnationId incarnation, Tick now) {
  std::unique_lock lock(impl_->mutex);
  Impl& impl = *impl_;
  if (incarnation.is_unset()) {
    return Outcome<IncarnationId>(
        Status::failure(ReasonCode::RejectedZeroIncarnation, "incarnation must be non-zero"));
  }
  DeviceIncarnationEntry* entry = impl.find_device_mutable(device);
  if (entry == nullptr) {
    if (impl.incarnation_table.size() >= impl.policy.limits.max_devices) {
      return Outcome<IncarnationId>(Status::failure(ReasonCode::RejectedDeviceBudgetExhausted,
                                                    "device bound reached"));
    }
    DeviceIncarnationEntry created;
    created.device = device;
    created.current = incarnation;
    created.history.push_back(incarnation);
    impl.incarnation_table[device] = std::move(created);
    if (impl.next_incarnation <= incarnation.value()) impl.next_incarnation = incarnation.value() + 1;
    impl.bump_policy_revision();
    impl.refresh_all_conflicts(now);
    return Outcome<IncarnationId>(incarnation);
  }
  const bool known = std::find(entry->history.begin(), entry->history.end(), incarnation) !=
                     entry->history.end();
  if (!known) {
    if (entry->history.size() >= impl.policy.limits.max_incarnations_per_device) {
      return Outcome<IncarnationId>(Status::failure(ReasonCode::RejectedDeviceBudgetExhausted,
                                                    "incarnation bound reached"));
    }
    entry->history.push_back(incarnation);
    std::sort(entry->history.begin(), entry->history.end());
  }
  if (impl.next_incarnation <= incarnation.value()) impl.next_incarnation = incarnation.value() + 1;
  if (entry->current == incarnation) {
    return Outcome<IncarnationId>(incarnation);
  }
  entry->current = incarnation;
  impl.bump_policy_revision();
  impl.refresh_all_conflicts(now);
  return Outcome<IncarnationId>(incarnation);
}

Outcome<IncarnationId> Registry::current_incarnation(const DeviceIdentity& device) const {
  std::shared_lock lock(impl_->mutex);
  const DeviceIncarnationEntry* entry = impl_->find_device(device);
  if (entry == nullptr) {
    return Outcome<IncarnationId>(
        Status::failure(ReasonCode::UnknownDeviceNotRegistered, "device is not registered"));
  }
  return Outcome<IncarnationId>(entry->current);
}

Outcome<bool> Registry::revoke_source(const SourceId& source, Tick now) {
  std::unique_lock lock(impl_->mutex);
  Impl& impl = *impl_;
  SourcePolicy* target = nullptr;
  for (auto& entry : impl.policy.sources) {
    if (entry.id == source) target = &entry;
  }
  if (target == nullptr) {
    return Outcome<bool>(Status::failure(ReasonCode::UnknownSourceNotConfigured,
                                         "source has no policy entry"));
  }
  if (target->trust == SourceTrustState::Revoked) {
    return Outcome<bool>::success(true, ReasonCode::AlreadyPresent);
  }
  target->trust = SourceTrustState::Revoked;
  impl.bump_policy_revision();
  impl.refresh_all_conflicts(now);
  return Outcome<bool>::success(true, ReasonCode::AcceptedNew);
}

Outcome<bool> Registry::restore_source(const SourceId& source, Tick now) {
  std::unique_lock lock(impl_->mutex);
  Impl& impl = *impl_;
  SourcePolicy* target = nullptr;
  for (auto& entry : impl.policy.sources) {
    if (entry.id == source) target = &entry;
  }
  if (target == nullptr) {
    return Outcome<bool>(Status::failure(ReasonCode::UnknownSourceNotConfigured,
                                         "source has no policy entry"));
  }
  if (target->trust == SourceTrustState::Trusted) {
    return Outcome<bool>::success(true, ReasonCode::AlreadyPresent);
  }
  target->trust = SourceTrustState::Trusted;
  impl.bump_policy_revision();
  impl.refresh_all_conflicts(now);
  return Outcome<bool>::success(true, ReasonCode::AcceptedNew);
}

Outcome<bool> Registry::set_source_authority(const SourceId& source, AuthorityRank authority,
                                             Tick now) {
  std::unique_lock lock(impl_->mutex);
  Impl& impl = *impl_;
  SourcePolicy* target = nullptr;
  for (auto& entry : impl.policy.sources) {
    if (entry.id == source) target = &entry;
  }
  if (target == nullptr) {
    return Outcome<bool>(Status::failure(ReasonCode::UnknownSourceNotConfigured,
                                         "source has no policy entry"));
  }
  if (target->authority == authority) {
    return Outcome<bool>::success(true, ReasonCode::AlreadyPresent);
  }
  target->authority = authority;
  // Already admitted records keep the authority they were admitted under; new
  // evidence carries the new authority. Re-ranking is therefore a live
  // derivation, not a rewrite of history.
  impl.bump_policy_revision();
  impl.refresh_all_conflicts(now);
  return Outcome<bool>::success(true, ReasonCode::AcceptedNew);
}

Outcome<SourcePolicy> Registry::upsert_source_policy(SourcePolicy policy, Tick now) {
  std::unique_lock lock(impl_->mutex);
  Impl& impl = *impl_;
  if (policy.id.empty()) {
    return Outcome<SourcePolicy>(
        Status::failure(ReasonCode::RejectedMalformedName, "source id is empty"));
  }
  if (policy.kind == SourceKind::OperatorDeclaration && policy.authority < AuthorityRank::Operator) {
    policy.authority = AuthorityRank::Operator;
  }
  for (auto& entry : impl.policy.sources) {
    if (entry.id == policy.id) {
      entry = policy;
      impl.bump_policy_revision();
      impl.refresh_all_conflicts(now);
      return Outcome<SourcePolicy>(entry);
    }
  }
  if (impl.policy.sources.size() >= impl.policy.limits.max_sources) {
    return Outcome<SourcePolicy>(
        Status::failure(ReasonCode::RejectedAuthorityInsufficient, "source bound reached"));
  }
  impl.policy.sources.push_back(policy);
  std::sort(impl.policy.sources.begin(), impl.policy.sources.end());
  impl.bump_policy_revision();
  impl.refresh_all_conflicts(now);
  return Outcome<SourcePolicy>(policy);
}

Outcome<ConflictResolution> Registry::resolve_conflict(const ConflictId& conflict,
                                                       const EvidenceId& chosen,
                                                       const SourceId& resolver, Tick now) {
  std::unique_lock lock(impl_->mutex);
  Impl& impl = *impl_;

  const ConflictGroup* group = nullptr;
  for (const auto& candidate : impl.conflict_table) {
    if (candidate.id == conflict) group = &candidate;
  }
  if (group == nullptr) {
    return Outcome<ConflictResolution>(
        Status::failure(ReasonCode::ConflictUnresolved, "conflict group is not known"));
  }
  if (std::find(group->members.begin(), group->members.end(), chosen) == group->members.end()) {
    return Outcome<ConflictResolution>(
        Status::failure(ReasonCode::ConflictUnresolved, "chosen record is not a member"));
  }
  const SourcePolicy* resolver_policy = impl.policy.find_source(resolver);
  if (impl.policy.require_configured_source && resolver_policy == nullptr) {
    return Outcome<ConflictResolution>(
        Status::failure(ReasonCode::RejectedUnknownSource, "resolver has no policy entry"));
  }
  if (resolver_policy != nullptr && resolver_policy->trust != SourceTrustState::Trusted) {
    return Outcome<ConflictResolution>(
        Status::failure(ReasonCode::RejectedSourceUntrusted, "resolver is not trusted"));
  }

  ConflictResolution resolution;
  resolution.conflict = conflict;
  resolution.chosen = chosen;
  for (const auto& member : group->members) {
    if (!(member == chosen)) resolution.rejected_members.push_back(member);
  }
  resolution.resolver = resolver;
  resolution.resolved_at = now;
  resolution.epoch = impl.epoch;

  Writer writer;
  writer.u16(kApiGeneration);
  writer.digest(conflict.digest());
  writer.digest(chosen.digest());
  writer.u32(static_cast<std::uint32_t>(resolution.rejected_members.size()));
  for (const auto& member : resolution.rejected_members) writer.digest(member.digest());
  writer.name_id(resolver);
  writer.strong(now);
  resolution.id = ResolutionId(Digest256::of(writer.span()));

  impl.push_resolution(resolution);
  ++impl.counters.conflicts_resolved;
  return Outcome<ConflictResolution>(resolution);
}

Outcome<bool> Registry::set_rule_generation(RuleGeneration generation, Tick now) {
  (void)now;
  std::unique_lock lock(impl_->mutex);
  if (generation.is_unset()) {
    return Outcome<bool>(
        Status::failure(ReasonCode::RejectedRuleGenerationOutOfRange, "generation must be non-zero"));
  }
  if (generation < impl_->rule_generation_value) {
    return Outcome<bool>(Status::failure(ReasonCode::RejectedRuleGenerationOutOfRange,
                                         "rule generation must not move backwards"));
  }
  if (generation == impl_->rule_generation_value) {
    return Outcome<bool>::success(true, ReasonCode::AlreadyPresent);
  }
  impl_->rule_generation_value = generation;
  impl_->policy.rule_generation = generation;
  impl_->bump_policy_revision();
  return Outcome<bool>::success(true, ReasonCode::AcceptedNew);
}

Outcome<bool> Registry::advance_epoch(ReasonCode reason, Tick now) {
  (void)reason;
  (void)now;
  std::unique_lock lock(impl_->mutex);
  impl_->bump_policy_revision();
  return Outcome<bool>::success(true, ReasonCode::AcceptedNew);
}

Outcome<bool> Registry::set_logical_tick(Tick now) {
  std::unique_lock lock(impl_->mutex);
  if (now < impl_->logical_tick_value) {
    return Outcome<bool>(Status::failure(ReasonCode::RejectedStaleObservation,
                                         "logical clock must be monotonic"));
  }
  impl_->logical_tick_value = now;
  return Outcome<bool>::success(true, ReasonCode::Ok);
}

void Registry::set_limits(RegistryLimits limits) {
  std::unique_lock lock(impl_->mutex);
  impl_->policy.limits = limits;
  impl_->bump_policy_revision();
}

// --- Queries ----------------------------------------------------------------

Outcome<QueryResult> Registry::query(const CapabilityQuery& request, Tick now) const {
  std::shared_lock lock(impl_->mutex);
  const Impl& impl = *impl_;

  const DeviceIncarnationEntry* entry = impl.find_device(request.device.device);
  if (entry == nullptr) {
    return Outcome<QueryResult>(Status::failure(ReasonCode::UnknownDeviceNotRegistered,
                                                "device incarnation is not registered"));
  }

  QueryResult result;
  result.device = request.device;
  result.kind_requested = request.kind;
  result.evaluated_at = now;
  result.rule_generation = impl.rule_generation_value;
  result.registry_epoch = impl.epoch;
  result.policy_revision = impl.policy_revision_value;

  const Impl::Derivation derivation =
      impl.derive(request.device, request.kind, now, request.max_evidence_age);

  std::vector<ReasonCode> reasons;
  bool saw_superseded = false;
  bool saw_fenced = false;
  bool saw_stale = false;
  bool saw_retired = false;
  bool saw_outranked = false;
  bool saw_rejected = false;
  bool saw_evicted = false;
  for (const auto& eviction : impl.eviction_table) {
    if (eviction.key.device == request.device && eviction.key.kind == request.kind) {
      saw_evicted = true;
    }
  }

  for (const auto& fact : derivation.facts) {
    const bool historical =
        fact.state == EvidenceState::Superseded || fact.state == EvidenceState::Rejected;
    if (!request.include_history && historical) {
      if (fact.state == EvidenceState::Superseded) {
        saw_superseded = true;
      } else {
        saw_rejected = true;
      }
      continue;
    }
    EvidenceStateFact out;
    out.id = fact.record->evidence.id();
    out.lifecycle = fact.record->lifecycle;
    out.state = fact.state;
    out.reason = fact.reason;
    out.observed_at = fact.record->evidence.observed_at;
    out.age = fact.age;
    out.authority = fact.record->evidence.authority;
    out.generation = fact.record->evidence.generation;
    out.source_incarnation = fact.record->evidence.source_incarnation;
    out.capability_version = fact.record->evidence.capability_version;
    out.features = fact.record->evidence.features;
    out.limits = fact.record->evidence.limits;
    out.firmware_version = fact.record->evidence.firmware_version;
    out.runtime_version = fact.record->evidence.runtime_version;
    result.facts.push_back(std::move(out));

    switch (fact.state) {
      case EvidenceState::Superseded: saw_superseded = true; break;
      case EvidenceState::Fenced: saw_fenced = true; break;
      case EvidenceState::Stale: saw_stale = true; break;
      case EvidenceState::Retired: saw_retired = true; break;
      case EvidenceState::Outranked: saw_outranked = true; break;
      case EvidenceState::Rejected: saw_rejected = true; break;
      default: break;
    }
  }

  if (entry->current != request.device.incarnation) {
    reasons.push_back(ReasonCode::UnknownIncarnationNotCurrent);
  }

  if (derivation.disagrees) {
    result.kind = DecisionKind::Conflicted;
    result.conflict = derivation.conflict;
    reasons.push_back(ReasonCode::ConflictEqualAuthority);
  } else if (!derivation.live.empty()) {
    result.kind = DecisionKind::Compatible;
    result.selected = derivation.live.front()->evidence.id();
    reasons.push_back(ReasonCode::AcceptedNew);
  } else {
    result.kind = DecisionKind::Unknown;
    if (saw_retired) reasons.push_back(ReasonCode::UnknownCapabilityRetired);
    if (saw_superseded || saw_stale) reasons.push_back(ReasonCode::UnknownStaleEvidence);
    if (saw_fenced) reasons.push_back(ReasonCode::UnknownFencedEvidence);
    if (saw_outranked) reasons.push_back(ReasonCode::UnknownConflictingEvidence);
    if (saw_rejected && reasons.empty()) {
      reasons.push_back(ReasonCode::RejectedSupersededGeneration);
    }
    if (reasons.empty() && saw_evicted) reasons.push_back(ReasonCode::UnknownEvidenceEvicted);
    if (reasons.empty()) reasons.push_back(ReasonCode::UnknownNoEvidence);
  }

  result.reasons = canonical_reasons(std::move(reasons));
  return Outcome<QueryResult>(std::move(result));
}

CompatibilityDecision Registry::evaluate(const CapabilityRequirement& requirement, Tick now) {
  std::unique_lock lock(impl_->mutex);
  Impl& impl = *impl_;

  CompatibilityDecision decision;
  decision.device = requirement.device;
  decision.capability = requirement.capability;
  decision.requirement = requirement;
  decision.rule_generation = impl.rule_generation_value;
  decision.registry_epoch = impl.epoch;
  decision.policy_revision = impl.policy_revision_value;
  decision.evaluated_at = now;
  decision.kind = DecisionKind::Unknown;

  const auto finish = [&decision, &impl]() {
    decision.reasons = canonical_reasons(decision.reasons);
    std::sort(decision.evidence.begin(), decision.evidence.end());
    decision.id = decision.compute_id();
    impl.push_decision(decision);
    ++impl.counters.decisions_emitted;
  };

  const DeviceIncarnationEntry* entry = impl.find_device(requirement.device.device);
  if (entry == nullptr) {
    decision.reasons.push_back(ReasonCode::UnknownDeviceNotRegistered);
    finish();
    return decision;
  }

  const Impl::Derivation derivation =
      impl.derive(requirement.device, requirement.capability, now, requirement.max_evidence_age);
  decision.evidence_facts.reserve(derivation.facts.size());
  for (const auto& fact : derivation.facts) {
    EvidenceStateFact out;
    out.id = fact.record->evidence.id();
    out.lifecycle = fact.record->lifecycle;
    out.state = fact.state;
    out.reason = fact.reason;
    out.observed_at = fact.record->evidence.observed_at;
    out.age = fact.age;
    out.authority = fact.record->evidence.authority;
    out.generation = fact.record->evidence.generation;
    out.source_incarnation = fact.record->evidence.source_incarnation;
    out.capability_version = fact.record->evidence.capability_version;
    out.features = fact.record->evidence.features;
    out.limits = fact.record->evidence.limits;
    out.firmware_version = fact.record->evidence.firmware_version;
    out.runtime_version = fact.record->evidence.runtime_version;
    decision.evidence.push_back(out.id);
    decision.evidence_facts.push_back(std::move(out));
  }

  if (entry->current != requirement.device.incarnation) {
    decision.reasons.push_back(ReasonCode::UnknownIncarnationNotCurrent);
  }

  const StoredEvidence* selected = nullptr;
  if (derivation.disagrees) {
    decision.conflict = derivation.conflict;
    const ConflictResolution* resolution =
        derivation.conflict.has_value() ? impl.find_resolution(*derivation.conflict) : nullptr;
    if (resolution != nullptr) {
      for (const auto* record : derivation.live) {
        if (record->evidence.id() == resolution->chosen) selected = record;
      }
      if (selected == nullptr) {
        decision.kind = DecisionKind::Conflicted;
        decision.reasons.push_back(ReasonCode::ConflictResolvedByResolution);
        decision.reasons.push_back(ReasonCode::ConflictEqualAuthority);
        finish();
        return decision;
      }
      decision.reasons.push_back(ReasonCode::ConflictResolvedByResolution);
    } else {
      decision.kind = DecisionKind::Conflicted;
      decision.reasons.push_back(ReasonCode::ConflictEqualAuthority);
      finish();
      return decision;
    }
  } else if (!derivation.live.empty()) {
    selected = derivation.live.front();
  }

  if (selected == nullptr) {
    bool saw_retired = false;
    bool saw_superseded = false;
    bool saw_fenced = false;
    bool saw_stale = false;
    for (const auto& fact : derivation.facts) {
      switch (fact.state) {
        case EvidenceState::Retired: saw_retired = true; break;
        case EvidenceState::Superseded: saw_superseded = true; break;
        case EvidenceState::Outranked: saw_superseded = true; break;
        case EvidenceState::Fenced: saw_fenced = true; break;
        case EvidenceState::Stale: saw_stale = true; break;
        case EvidenceState::Rejected: saw_superseded = true; break;
        case EvidenceState::Active: break;
        case EvidenceState::Evicted: break;
      }
    }
    bool saw_evicted = false;
    for (const auto& eviction : impl.eviction_table) {
      if (eviction.key.device == requirement.device &&
          eviction.key.kind == requirement.capability) {
        saw_evicted = true;
      }
    }
    decision.kind = DecisionKind::Unknown;
    if (saw_retired) decision.reasons.push_back(ReasonCode::UnknownCapabilityRetired);
    if (saw_superseded) decision.reasons.push_back(ReasonCode::UnknownStaleEvidence);
    if (saw_stale) decision.reasons.push_back(ReasonCode::UnknownStaleEvidence);
    if (saw_fenced) decision.reasons.push_back(ReasonCode::UnknownFencedEvidence);
    if (decision.reasons.empty() && saw_evicted) {
      decision.reasons.push_back(ReasonCode::UnknownEvidenceEvicted);
    }
    if (decision.reasons.empty()) decision.reasons.push_back(ReasonCode::UnknownNoEvidence);
    finish();
    return decision;
  }

  decision.selected = selected->evidence.id();
  decision.selected_authority = selected->evidence.authority;
  const detail::ComparisonResult comparison =
      detail::compare_requirement(requirement, selected->evidence);
  decision.kind = comparison.kind;
  for (const auto reason : comparison.reasons) decision.reasons.push_back(reason);
  finish();
  return decision;
}

Outcome<Explanation> Registry::explain(const DecisionId& id) const {
  std::shared_lock lock(impl_->mutex);
  const Impl& impl = *impl_;

  const auto it = impl.decisions.find(id);
  if (it == impl.decisions.end()) {
    return Outcome<Explanation>(Status::failure(
        ReasonCode::UnknownNoEvidence,
        "decision is not retained in the bounded explanation store"));
  }
  Explanation explanation;
  explanation.decision = it->second;
  explanation.decision_available = true;
  explanation.reason = ReasonCode::Ok;

  std::vector<SourceId> sources;
  for (const auto& fact : explanation.decision.evidence_facts) {
    sources.push_back(fact.source_incarnation.source);
  }
  std::sort(sources.begin(), sources.end());
  sources.erase(std::unique(sources.begin(), sources.end()), sources.end());
  for (const auto& source : sources) {
    const SourcePolicy* source_policy = impl.policy.find_source(source);
    if (source_policy != nullptr) explanation.involved_sources.push_back(*source_policy);
  }

  if (explanation.decision.conflict.has_value()) {
    for (const auto& group : impl.conflict_table) {
      if (group.id == *explanation.decision.conflict) explanation.conflict = group;
    }
    const ConflictResolution* resolution = impl.find_resolution(*explanation.decision.conflict);
    if (resolution != nullptr) explanation.resolution = *resolution;
  }
  return Outcome<Explanation>(std::move(explanation));
}

Outcome<ConflictGroup> Registry::conflict_for(const DeviceIncarnationRef& device,
                                              CapabilityKind kind, Tick now) const {
  std::shared_lock lock(impl_->mutex);
  const Impl& impl = *impl_;
  const Impl::Derivation derivation = impl.derive(device, kind, now, Tick{});
  if (!derivation.disagrees || !derivation.conflict.has_value()) {
    return Outcome<ConflictGroup>(Status::failure(ReasonCode::ConflictUnresolved,
                                                  "no equal-authority disagreement is present"));
  }
  for (const auto& group : impl.conflict_table) {
    if (group.id == *derivation.conflict) return Outcome<ConflictGroup>(group);
  }
  ConflictGroup group;
  group.id = *derivation.conflict;
  group.device = device;
  group.kind = kind;
  group.authority = derivation.live_authority;
  for (const auto* record : derivation.live) {
    group.members.push_back(record->evidence.id());
    group.generations.push_back(record->evidence.generation);
  }
  std::sort(group.members.begin(), group.members.end());
  group.observed_first = derivation.live.front()->evidence.observed_at;
  group.observed_last = group.observed_first;
  for (const auto* record : derivation.live) {
    if (record->evidence.observed_at < group.observed_first) {
      group.observed_first = record->evidence.observed_at;
    }
    if (record->evidence.observed_at > group.observed_last) {
      group.observed_last = record->evidence.observed_at;
    }
  }
  return Outcome<ConflictGroup>(std::move(group));
}

std::vector<EvictionEntry> Registry::eviction_ledger() const {
  std::shared_lock lock(impl_->mutex);
  return std::vector<EvictionEntry>(impl_->eviction_table.begin(), impl_->eviction_table.end());
}

std::vector<StoredEvidence> Registry::records() const {
  std::shared_lock lock(impl_->mutex);
  return impl_->flatten_records();
}

std::vector<RetirementRecord> Registry::tombstones() const {
  std::shared_lock lock(impl_->mutex);
  return impl_->flatten_tombstones();
}

std::vector<DeviceIncarnationEntry> Registry::incarnations() const {
  std::shared_lock lock(impl_->mutex);
  std::vector<DeviceIncarnationEntry> entries;
  entries.reserve(impl_->incarnation_table.size());
  for (const auto& [device, entry] : impl_->incarnation_table) {
    (void)device;
    entries.push_back(entry);
  }
  return entries;
}

std::vector<ConflictResolution> Registry::resolutions() const {
  std::shared_lock lock(impl_->mutex);
  return impl_->resolution_table;
}

std::vector<ConflictGroup> Registry::conflict_groups() const {
  std::shared_lock lock(impl_->mutex);
  return impl_->conflict_table;
}

RegistryStats Registry::stats(Tick now) const {
  std::shared_lock lock(impl_->mutex);
  const Impl& impl = *impl_;

  RegistryStats result;
  result.devices = impl.incarnation_table.size();
  for (const auto& [device, entry] : impl.incarnation_table) {
    (void)device;
    result.incarnations += entry.history.size();
  }
  result.streams = impl.count_streams();
  result.records_total = impl.total_records;
  result.conflicts_open = impl.conflict_table.size();
  result.conflicts_resolved = impl.counters.conflicts_resolved;
  result.tombstones = impl.flatten_tombstones().size();
  result.resolutions = impl.resolution_table.size();
  result.eviction_ledger_dropped = impl.counters.eviction_ledger_dropped;
  result.conflicts_dropped = impl.counters.conflicts_dropped;
  result.resolutions_dropped = impl.counters.resolutions_dropped;
  result.tombstones_dropped = impl.counters.tombstones_dropped;
  result.decisions_emitted = impl.counters.decisions_emitted;
  result.decisions_evicted = impl.counters.decisions_evicted;
  result.admissions_accepted = impl.counters.admissions_accepted;
  result.admissions_idempotent = impl.counters.admissions_idempotent;
  result.admissions_rejected = impl.counters.admissions_rejected;
  result.retirements_accepted = impl.counters.retirements_accepted;
  result.retirements_rejected = impl.counters.retirements_rejected;
  result.records_evicted = impl.counters.evictions_total;
  result.registry_epoch = impl.epoch;
  result.rule_generation = impl.rule_generation_value;
  result.policy_revision = impl.policy_revision_value;
  result.boot_epoch = impl.boot_epoch_value;
  result.logical_tick = impl.logical_tick_value;

  for (const auto& [device, kinds] : impl.world.groups) {
    for (const auto& [kind, group] : kinds) {
      (void)group;
      const Impl::Derivation derivation = impl.derive(device, kind, now, Tick{});
      for (const auto& fact : derivation.facts) {
        switch (fact.state) {
          case EvidenceState::Active: ++result.records_active; break;
          case EvidenceState::Superseded: ++result.records_superseded; break;
          case EvidenceState::Retired: ++result.records_retired; break;
          case EvidenceState::Rejected: ++result.records_rejected; break;
          case EvidenceState::Fenced: ++result.records_fenced; break;
          case EvidenceState::Stale: ++result.records_stale; break;
          case EvidenceState::Outranked: ++result.records_outranked; break;
          case EvidenceState::Evicted: ++result.records_evicted; break;
        }
      }
    }
  }
  return result;
}

RegistryPolicy Registry::policy() const {
  std::shared_lock lock(impl_->mutex);
  return impl_->policy;
}

RegistryEpoch Registry::epoch() const {
  std::shared_lock lock(impl_->mutex);
  return impl_->epoch;
}

RuleGeneration Registry::rule_generation() const {
  std::shared_lock lock(impl_->mutex);
  return impl_->rule_generation_value;
}

PolicyRevision Registry::policy_revision() const {
  std::shared_lock lock(impl_->mutex);
  return impl_->policy_revision_value;
}

BootEpoch Registry::boot_epoch() const {
  std::shared_lock lock(impl_->mutex);
  return impl_->boot_epoch_value;
}

Tick Registry::logical_tick() const {
  std::shared_lock lock(impl_->mutex);
  return impl_->logical_tick_value;
}

// --- Persistence support ----------------------------------------------------

Outcome<RegistryState> Registry::snapshot_state() const {
  std::shared_lock lock(impl_->mutex);
  return Outcome<RegistryState>(impl_->to_state());
}

Outcome<RecoverySummary> Registry::adopt_state(RegistryState state, Tick now) {
  std::unique_lock lock(impl_->mutex);
  Impl& impl = *impl_;

  RecoverySummary summary;
  summary.previous_boot_epoch = state.boot_epoch;
  summary.snapshot_generation = state.store_generation.value();

  Tick highest_observed{};
  for (const auto& record : state.records) {
    if (record.evidence.observed_at > highest_observed) {
      highest_observed = record.evidence.observed_at;
    }
  }

  // A state that carries no policy of its own (for example the state of a
  // brand-new store) must not erase the policy the registry was constructed
  // with. A state that does carry sources restores them.
  const bool state_carries_policy = !state.policy.sources.empty();
  const RegistryPolicy configured = impl.policy;
  impl.adopt(std::move(state));
  if (!state_carries_policy) impl.policy = configured;
  impl.rule_generation_value = impl.policy.rule_generation;
  impl.boot_epoch_value = BootEpoch(summary.previous_boot_epoch.value() + 1);
  impl.bump_policy_revision();

  Tick resume = impl.logical_tick_value;
  if (now > resume) resume = now;
  if (highest_observed > resume) resume = highest_observed;
  impl.logical_tick_value = resume;

  summary.records_adopted = impl.total_records;
  summary.tombstones_adopted = impl.flatten_tombstones().size();
  summary.resolutions_adopted = impl.resolution_table.size();
  summary.evictions_adopted = impl.eviction_table.size();
  summary.boot_epoch = impl.boot_epoch_value;

  impl.refresh_all_conflicts(resume);
  summary.conflicts_adopted = impl.conflict_table.size();

  for (const auto& [device, kinds] : impl.world.groups) {
    for (const auto& [kind, group] : kinds) {
      (void)group;
      const Impl::Derivation derivation = impl.derive(device, kind, resume, Tick{});
      for (const auto& fact : derivation.facts) {
        if (fact.state == EvidenceState::Fenced) {
          ++summary.records_fenced;
        } else if (fact.state == EvidenceState::Active ||
                   fact.state == EvidenceState::Outranked) {
          ++summary.records_carried_forward;
        }
      }
    }
  }

  if (summary.records_fenced > 0) {
    summary.classification = RecoveryClass::RebuiltFromSnapshot;
    summary.reason = ReasonCode::RecoveryRebuiltFromSnapshot;
  } else {
    summary.classification = RecoveryClass::CleanOpen;
    summary.reason = ReasonCode::RecoveryCleanOpen;
  }
  summary.notes.push_back(summary.reason);
  canonicalize_reasons(summary.notes);
  return Outcome<RecoverySummary>(std::move(summary));
}

Digest256 Registry::state_digest() const {
  std::shared_lock lock(impl_->mutex);
  return ocreg::state_digest(impl_->to_state());
}

}  // namespace ocreg
