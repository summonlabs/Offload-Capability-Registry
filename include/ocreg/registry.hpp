// Offload Capability Registry - public registry runtime.
// Copyright 2026 Summon Software Labs.
#ifndef OCREG_REGISTRY_HPP
#define OCREG_REGISTRY_HPP

#include <cstdint>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

#include "ocreg/catalog.hpp"
#include "ocreg/decision.hpp"
#include "ocreg/evidence.hpp"
#include "ocreg/name.hpp"
#include "ocreg/outcome.hpp"
#include "ocreg/reason.hpp"
#include "ocreg/semver.hpp"
#include "ocreg/strong.hpp"

namespace ocreg {

class Writer;
class Reader;

// How loaded evidence is treated after a process restart.
enum class BootPolicy : std::uint8_t {
  // Default. Every record loaded from persistence is fenced until its source
  // re-attests under the new boot epoch. Nothing is resurrected.
  ConservativeFence = 1,
  // Records survive only while they remain inside their source freshness
  // window; everything else is fenced exactly as for ConservativeFence.
  CarryForwardWithinFreshness = 2,
};

// Source of logical time. Manual keeps every run reproducible.
enum class ClockMode : std::uint8_t {
  Manual = 1,
  SystemMonotonic = 2,
};

[[nodiscard]] std::string_view to_string(BootPolicy policy) noexcept;
[[nodiscard]] std::string_view to_string(ClockMode mode) noexcept;
[[nodiscard]] bool parse_boot_policy(std::string_view text, BootPolicy& out) noexcept;
[[nodiscard]] bool parse_clock_mode(std::string_view text, ClockMode& out) noexcept;

// Hard upper bounds. Every one of them is enforced before allocation.
struct RegistryLimits {
  std::size_t max_devices = 4096;
  std::size_t max_incarnations_per_device = 64;
  std::size_t max_streams = 65536;
  std::size_t max_records = 262144;
  std::size_t max_records_per_stream = 64;
  std::size_t max_tombstones = 65536;
  std::size_t max_conflict_groups = 16384;
  std::size_t max_resolutions = 16384;
  std::size_t max_eviction_ledger = 65536;
  std::size_t max_sources = 1024;
  std::size_t max_decisions = 8192;
  std::size_t max_features_per_record = kMaxFeaturesPerRecord;
  std::size_t max_limits_per_record = kMaxLimitsPerRecord;
  std::size_t max_limits_per_requirement = kMaxLimitsPerRecord;
  std::size_t max_required_features = kMaxFeaturesPerRecord;
};

struct SourcePolicy {
  SourceId id{};
  SourceKind kind = SourceKind::Synthetic;
  AuthorityRank authority = AuthorityRank::Synthetic;
  SourceTrustState trust = SourceTrustState::Trusted;
  // Evidence older than this is stale. Zero means "never stale", which is only
  // appropriate for operator declarations.
  Tick max_age{};
  // True when records from this source may survive a restart without a fresh
  // attestation under the new boot epoch.
  bool durable_across_boot = false;

  friend bool operator==(const SourcePolicy&, const SourcePolicy&) noexcept = default;
  friend std::strong_ordering operator<=>(const SourcePolicy& a, const SourcePolicy& b) noexcept {
    return a.id <=> b.id;
  }
};

void encode(Writer& w, const SourcePolicy& value);
bool decode(Reader& r, SourcePolicy& value);

struct RegistryPolicy {
  std::vector<SourcePolicy> sources{};
  // When true an assertion from a source with no policy entry is refused.
  bool require_configured_source = true;
  // When true a source whose trust state is Untrusted is refused.
  bool refuse_untrusted_sources = true;
  BootPolicy boot_policy = BootPolicy::ConservativeFence;
  ClockMode clock_mode = ClockMode::Manual;
  // Observations older than 'now - retention_horizon' are refused outright.
  Tick retention_horizon{};
  // Observations further than this ahead of 'now' are refused.
  Tick max_future_skew{};
  // Fallback freshness bound for a configured source whose max_age is zero
  // and whose kind is not OperatorDeclaration.
  Tick default_max_age{};
  RegistryLimits limits{};
  RuleGeneration rule_generation{1};
  std::string policy_name{};

  [[nodiscard]] const SourcePolicy* find_source(const SourceId& id) const noexcept;
};

struct AdmissionRequest {
  DeviceIncarnationRef device{};
  CapabilityKind kind = CapabilityKind::PacketClassification;
  SourceIncarnation source{};
  SemVer capability_version{};
  FeatureSet features{};
  LimitSet limits{};
  std::optional<SemVer> firmware_version{};
  FirmwareGeneration firmware_generation{};
  std::optional<SemVer> runtime_version{};
  RuntimeGeneration runtime_generation{};
  Tick observed_at{};
  std::optional<Tick> valid_until{};
  RecordGeneration generation{};
};

void encode(Writer& w, const AdmissionRequest& value);
bool decode(Reader& r, AdmissionRequest& value);

struct AdmissionOutcome {
  EvidenceId id{};
  EvidenceState state = EvidenceState::Rejected;
  ReasonCode reason = ReasonCode::Ok;
  bool idempotent = false;
  // Records that this admission demoted to Superseded.
  std::vector<EvidenceId> superseded{};
  // Records evicted by a bound while applying this admission.
  std::vector<EvidenceId> evicted{};
  std::optional<ConflictId> conflict{};
  RecordGeneration stream_generation{};
  std::uint64_t conflicts_opened = 0;
};

struct RetirementRequest {
  DeviceIncarnationRef device{};
  CapabilityKind kind = CapabilityKind::PacketClassification;
  SourceId source{};
  RecordGeneration generation{};
  Tick retired_at{};
  ReasonCode reason = ReasonCode::Ok;
};

void encode(Writer& w, const RetirementRequest& value);
bool decode(Reader& r, RetirementRequest& value);

struct RetirementOutcome {
  EvidenceKey key{};
  RecordGeneration generation{};
  ReasonCode reason = ReasonCode::Ok;
  bool idempotent = false;
  std::vector<EvidenceId> retired{};
  std::vector<EvidenceId> evicted{};
};

struct CapabilityQuery {
  DeviceIncarnationRef device{};
  CapabilityKind kind = CapabilityKind::PacketClassification;
  // Zero means "use the source policy freshness bound".
  Tick max_evidence_age{};
  bool include_history = false;
};

struct QueryResult {
  DecisionKind kind = DecisionKind::Unknown;
  DeviceIncarnationRef device{};
  CapabilityKind kind_requested = CapabilityKind::PacketClassification;
  std::vector<ReasonCode> reasons{};
  std::vector<EvidenceStateFact> facts{};
  std::optional<EvidenceId> selected{};
  std::optional<ConflictId> conflict{};
  RuleGeneration rule_generation{};
  RegistryEpoch registry_epoch{};
  PolicyRevision policy_revision{};
  Tick evaluated_at{};
};

struct Explanation {
  CompatibilityDecision decision{};
  std::vector<SourcePolicy> involved_sources{};
  std::optional<ConflictGroup> conflict{};
  std::optional<ConflictResolution> resolution{};
  bool decision_available = false;
  ReasonCode reason = ReasonCode::Ok;
};

// Full durable state of a registry. Produced and consumed by the persistence
// layer and by the canonical export surface.
struct DeviceIncarnationEntry {
  DeviceIdentity device{};
  IncarnationId current{};
  std::vector<IncarnationId> history{};

  friend bool operator==(const DeviceIncarnationEntry&, const DeviceIncarnationEntry&) noexcept = default;
  friend std::strong_ordering operator<=>(const DeviceIncarnationEntry& a,
                                          const DeviceIncarnationEntry& b) noexcept {
    return a.device <=> b.device;
  }
};

struct RegistryCounters {
  std::uint64_t admissions_accepted = 0;
  std::uint64_t admissions_idempotent = 0;
  std::uint64_t admissions_rejected = 0;
  std::uint64_t retirements_accepted = 0;
  std::uint64_t retirements_rejected = 0;
  std::uint64_t decisions_emitted = 0;
  std::uint64_t decisions_evicted = 0;
  std::uint64_t conflicts_resolved = 0;
  std::uint64_t evictions_total = 0;
  std::uint64_t eviction_ledger_dropped = 0;
  std::uint64_t conflicts_dropped = 0;
  std::uint64_t resolutions_dropped = 0;
  std::uint64_t tombstones_dropped = 0;
};

// A conservative starting policy for the shipped tools and for tests. It
// declares explicitly synthetic, fixture and operator sources and claims
// nothing about real hardware. Every source must be declared before evidence
// from it is accepted.
[[nodiscard]] RegistryPolicy make_lab_policy();

struct RegistryState {
  RegistryPolicy policy{};
  RegistryEpoch epoch{};
  RuleGeneration rule_generation{};
  PolicyRevision policy_revision{};
  BootEpoch boot_epoch{};
  StoreGeneration store_generation{};
  Tick logical_tick{};
  std::uint64_t next_incarnation = 1;
  std::vector<DeviceIncarnationEntry> incarnations{};
  std::vector<StoredEvidence> records{};
  std::vector<RetirementRecord> tombstones{};
  std::vector<ConflictGroup> conflicts{};
  std::vector<ConflictResolution> resolutions{};
  std::vector<EvictionEntry> evictions{};
  RegistryCounters counters{};
};

// Classification of a recovery attempt. Every recovery is reported, including
// the ones that discarded bytes.
enum class RecoveryClass : std::uint8_t {
  CleanOpen = 1,
  TornTailTruncated = 2,
  TrailingCorruptDropped = 3,
  RebuiltFromSnapshot = 4,
  JournalReplayed = 5,
  Refused = 6,
};

[[nodiscard]] std::string_view to_string(RecoveryClass value) noexcept;
[[nodiscard]] bool parse_recovery_class(std::string_view text, RecoveryClass& out) noexcept;

struct RecoverySummary {
  RecoveryClass classification = RecoveryClass::CleanOpen;
  ReasonCode reason = ReasonCode::RecoveryCleanOpen;
  std::uint64_t records_adopted = 0;
  std::uint64_t records_fenced = 0;
  std::uint64_t records_carried_forward = 0;
  std::uint64_t tombstones_adopted = 0;
  std::uint64_t conflicts_adopted = 0;
  std::uint64_t resolutions_adopted = 0;
  std::uint64_t evictions_adopted = 0;
  std::uint64_t journal_records_replayed = 0;
  std::uint64_t journal_records_dropped = 0;
  std::uint64_t bytes_discarded = 0;
  std::uint64_t snapshot_generation = 0;
  BootEpoch previous_boot_epoch{};
  BootEpoch boot_epoch{};
  std::vector<ReasonCode> notes{};
};

// The registry. Thread-safe: mutations take an exclusive lock, queries and
// evaluations take a shared lock.
//
// No callback is ever invoked while a lock is held, and no method re-enters the
// registry from inside a lock.
class Registry {
 public:
  explicit Registry(RegistryPolicy policy);
  Registry(RegistryPolicy policy, RegistryState restored);
  ~Registry();

  Registry(const Registry&) = delete;
  Registry& operator=(const Registry&) = delete;
  Registry(Registry&&) = delete;
  Registry& operator=(Registry&&) = delete;

  // --- Mutations -----------------------------------------------------------

  Outcome<AdmissionOutcome> admit(const AdmissionRequest& request, Tick now);
  Outcome<RetirementOutcome> retire(const RetirementRequest& request, Tick now);

  Outcome<IncarnationId> begin_device_incarnation(const DeviceIdentity& device, Tick now);
  // Installs an explicit current incarnation, for example when re-ingesting a
  // document. Evidence attached to any other incarnation is fenced.
  Outcome<IncarnationId> set_device_incarnation(const DeviceIdentity& device,
                                                IncarnationId incarnation, Tick now);
  Outcome<IncarnationId> current_incarnation(const DeviceIdentity& device) const;

  Outcome<bool> revoke_source(const SourceId& source, Tick now);
  Outcome<bool> restore_source(const SourceId& source, Tick now);
  Outcome<bool> set_source_authority(const SourceId& source, AuthorityRank authority, Tick now);
  Outcome<SourcePolicy> upsert_source_policy(SourcePolicy policy, Tick now);

  Outcome<ConflictResolution> resolve_conflict(const ConflictId& conflict, const EvidenceId& chosen,
                                               const SourceId& resolver, Tick now);

  Outcome<bool> set_rule_generation(RuleGeneration generation, Tick now);
  Outcome<bool> advance_epoch(ReasonCode reason, Tick now);
  Outcome<bool> set_logical_tick(Tick now);
  void set_limits(RegistryLimits limits);

  // --- Queries -------------------------------------------------------------

  Outcome<QueryResult> query(const CapabilityQuery& query, Tick now) const;
  // Evaluating records the decision in the bounded explanation store, so the
  // registry takes the exclusive lock here.
  CompatibilityDecision evaluate(const CapabilityRequirement& requirement, Tick now);
  Outcome<Explanation> explain(const DecisionId& id) const;

  Outcome<ConflictGroup> conflict_for(const DeviceIncarnationRef& device, CapabilityKind kind,
                                      Tick now) const;

  std::vector<EvictionEntry> eviction_ledger() const;
  std::vector<StoredEvidence> records() const;
  std::vector<RetirementRecord> tombstones() const;
  std::vector<DeviceIncarnationEntry> incarnations() const;
  std::vector<ConflictResolution> resolutions() const;
  std::vector<ConflictGroup> conflict_groups() const;

  RegistryStats stats(Tick now) const;
  RegistryPolicy policy() const;

  RegistryEpoch epoch() const;
  RuleGeneration rule_generation() const;
  PolicyRevision policy_revision() const;
  BootEpoch boot_epoch() const;
  Tick logical_tick() const;

  // --- Persistence support -------------------------------------------------

  Outcome<RegistryState> snapshot_state() const;
  // Installs a state produced by snapshot_state() in another process. The
  // receiver applies its own boot epoch and fences everything not explicitly
  // durable, so a restart never resurrects authority.
  Outcome<RecoverySummary> adopt_state(RegistryState state, Tick now);

  // Digest of the canonical export of all current state.
  [[nodiscard]] Digest256 state_digest() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ocreg

#endif  // OCREG_REGISTRY_HPP
