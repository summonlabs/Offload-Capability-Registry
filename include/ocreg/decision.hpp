// Offload Capability Registry - requirements, decisions and explanations.
// Copyright 2026 Summon Software Labs.
//
// A decision is either a fact derived from admitted evidence, or an explicit
// unknown. An absence of evidence is never reported as incompatibility and an
// unknown limit is never treated as zero.
#ifndef OCREG_DECISION_HPP
#define OCREG_DECISION_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ocreg/catalog.hpp"
#include "ocreg/evidence.hpp"
#include "ocreg/reason.hpp"
#include "ocreg/semver.hpp"
#include "ocreg/strong.hpp"
#include "ocreg/units.hpp"

namespace ocreg {

class Writer;
class Reader;

// Four, and only four, answers are possible.
enum class DecisionKind : std::uint8_t {
  // Every requirement is met by admitted, current, authoritative evidence.
  Compatible = 1,
  // Admitted evidence positively shows a requirement is not met.
  Incompatible = 2,
  // The registry has no basis to answer; the reason codes say why.
  Unknown = 3,
  // Equal-authority evidence disagrees and no resolution exists.
  Conflicted = 4,
};

[[nodiscard]] std::string_view to_string(DecisionKind kind) noexcept;
[[nodiscard]] bool parse_decision_kind(std::string_view text, DecisionKind& out) noexcept;

// A single numeric requirement. The registry compares it with a device limit
// using exact units; a unit mismatch is an unknown, never a guess.
struct LimitRequirement {
  LimitCode code = LimitCode::ClassifierEntries;
  Unit unit{};
  std::int64_t minimum = 0;

  friend bool operator==(const LimitRequirement&, const LimitRequirement&) noexcept = default;
  friend std::strong_ordering operator<=>(const LimitRequirement& a,
                                          const LimitRequirement& b) noexcept {
    return a.code <=> b.code;
  }
};

void encode(Writer& w, const LimitRequirement& value);
bool decode(Reader& r, LimitRequirement& value);

// What a caller needs from a device incarnation.
struct CapabilityRequirement {
  DeviceIncarnationRef device{};
  CapabilityKind capability = CapabilityKind::PacketClassification;
  VersionRequirement version{};
  FeatureSet required_features{};
  std::vector<LimitRequirement> required_limits{};
  std::optional<SemVer> minimum_firmware_version{};
  std::optional<FirmwareGeneration> minimum_firmware_generation{};
  std::optional<SemVer> minimum_runtime_version{};
  std::optional<RuntimeGeneration> minimum_runtime_generation{};
  // Zero means "use the source policy freshness bound".
  Tick max_evidence_age{};
};

void encode(Writer& w, const CapabilityRequirement& value);
bool decode(Reader& r, CapabilityRequirement& value);

// A derived fact about one evidence record at one logical tick.
struct EvidenceStateFact {
  EvidenceId id{};
  EvidenceLifecycle lifecycle = EvidenceLifecycle::Admitted;
  EvidenceState state = EvidenceState::Active;
  ReasonCode reason = ReasonCode::Ok;
  Tick observed_at{};
  Tick age{};
  AuthorityRank authority = AuthorityRank::None;
  RecordGeneration generation{};
  SourceIncarnation source_incarnation{};
  SemVer capability_version{};
  FeatureSet features{};
  LimitSet limits{};
  std::optional<SemVer> firmware_version{};
  std::optional<SemVer> runtime_version{};
};

// The registry's answer, with everything needed to justify it.
struct CompatibilityDecision {
  DecisionId id{};
  DecisionKind kind = DecisionKind::Unknown;
  DeviceIncarnationRef device{};
  CapabilityKind capability = CapabilityKind::PacketClassification;
  CapabilityRequirement requirement{};
  std::vector<ReasonCode> reasons{};
  std::vector<EvidenceId> evidence{};
  std::vector<EvidenceStateFact> evidence_facts{};
  std::optional<EvidenceId> selected{};
  std::optional<ConflictId> conflict{};
  AuthorityRank selected_authority = AuthorityRank::None;
  RuleGeneration rule_generation{};
  RegistryEpoch registry_epoch{};
  PolicyRevision policy_revision{};
  Tick evaluated_at{};

  // Canonical digest over the inputs and the outcome. Identical inputs produce
  // an identical digest.
  [[nodiscard]] Digest256 compute_digest() const;
  [[nodiscard]] DecisionId compute_id() const { return DecisionId(compute_digest()); }
};

// Digest of a requirement alone, used by tests to prove input equivalence.
[[nodiscard]] Digest256 requirement_digest(const CapabilityRequirement& requirement);

// A device-level capability report. Unknown fields stay absent rather than
// being flattened to zero.
struct DeviceCapabilityReport {
  DeviceIncarnationRef device{};
  IncarnationId current_incarnation{};
  bool incarnation_is_current = false;
  std::vector<EvidenceStateFact> facts{};
  std::optional<ConflictGroup> conflict{};
  ReasonCode reason = ReasonCode::UnknownNoEvidence;
};

struct RegistryStats {
  std::uint64_t devices = 0;
  std::uint64_t incarnations = 0;
  std::uint64_t streams = 0;
  std::uint64_t records_total = 0;
  std::uint64_t records_active = 0;
  std::uint64_t records_superseded = 0;
  std::uint64_t records_retired = 0;
  std::uint64_t records_rejected = 0;
  std::uint64_t records_fenced = 0;
  std::uint64_t records_stale = 0;
  std::uint64_t records_outranked = 0;
  std::uint64_t records_evicted = 0;
  std::uint64_t conflicts_open = 0;
  std::uint64_t conflicts_resolved = 0;
  std::uint64_t tombstones = 0;
  std::uint64_t resolutions = 0;
  std::uint64_t eviction_ledger_dropped = 0;
  std::uint64_t conflicts_dropped = 0;
  std::uint64_t resolutions_dropped = 0;
  std::uint64_t tombstones_dropped = 0;
  std::uint64_t decisions_emitted = 0;
  std::uint64_t decisions_evicted = 0;
  std::uint64_t admissions_accepted = 0;
  std::uint64_t admissions_idempotent = 0;
  std::uint64_t admissions_rejected = 0;
  std::uint64_t retirements_accepted = 0;
  std::uint64_t retirements_rejected = 0;
  RegistryEpoch registry_epoch{};
  RuleGeneration rule_generation{};
  PolicyRevision policy_revision{};
  BootEpoch boot_epoch{};
  Tick logical_tick{};
};

}  // namespace ocreg

#endif  // OCREG_DECISION_HPP
