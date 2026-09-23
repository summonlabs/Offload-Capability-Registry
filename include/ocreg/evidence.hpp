// Offload Capability Registry - evidence, provenance and lifecycle model.
// Copyright 2026 Summon Software Labs.
//
// A capability record is an evidence-bound assertion made by an identified
// observation source about an identified device incarnation. It is never a
// hardware probe and never an inference: it is exactly what a source stated,
// with the authority, freshness and generation needed to judge it later.
#ifndef OCREG_EVIDENCE_HPP
#define OCREG_EVIDENCE_HPP

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ocreg/catalog.hpp"
#include "ocreg/hash.hpp"
#include "ocreg/name.hpp"
#include "ocreg/reason.hpp"
#include "ocreg/semver.hpp"
#include "ocreg/strong.hpp"

namespace ocreg {

class Writer;
class Reader;

inline constexpr std::size_t kMaxSerialLength = 48;
inline constexpr std::uint32_t kMaxDeviceUnitIndex = 4095;

// Where an assertion came from. The kind is descriptive; the authority that
// the registry actually grants is a policy decision recorded per source.
enum class SourceKind : std::uint8_t {
  // Synthetic fixture or simulated device. Never real hardware.
  Synthetic = 1,
  // Machinery-declared facts imported from an adjacent runtime.
  AdjacentRuntime = 2,
  // Device or driver self-report relayed through an adapter.
  DeviceSelfReport = 3,
  // Human operator declaration.
  OperatorDeclaration = 4,
  // Previously exported canonical bundle re-imported.
  ImportedBundle = 5,
};

// Authority of a source relative to other sources. Higher outranks lower.
enum class AuthorityRank : std::uint8_t {
  None = 0,
  Synthetic = 1,
  Imported = 2,
  AdjacentRuntime = 3,
  DeviceSelfReport = 4,
  Operator = 5,
};

enum class SourceTrustState : std::uint8_t {
  Trusted = 1,
  Untrusted = 2,
  Revoked = 3,
};

[[nodiscard]] std::string_view to_string(SourceKind kind) noexcept;
[[nodiscard]] std::string_view to_string(AuthorityRank rank) noexcept;
[[nodiscard]] std::string_view to_string(SourceTrustState state) noexcept;
[[nodiscard]] bool parse_source_kind(std::string_view text, SourceKind& out) noexcept;
[[nodiscard]] bool parse_authority_rank(std::string_view text, AuthorityRank& out) noexcept;
[[nodiscard]] bool parse_source_trust_state(std::string_view text, SourceTrustState& out) noexcept;

// A physical or virtual device identity. 'unit_index' disambiguates repeated
// units of the same model so that two identical cards never collide.
struct DeviceIdentity {
  ProviderId provider{};
  DeviceModelId model{};
  std::uint32_t unit_index = 0;
  std::optional<DeviceSerialId> serial{};

  friend bool operator==(const DeviceIdentity&, const DeviceIdentity&) noexcept = default;
  friend std::strong_ordering operator<=>(const DeviceIdentity& a,
                                          const DeviceIdentity& b) noexcept;
};

// A specific incarnation of a device. Incarnations are assigned by the
// registry; evidence attached to a superseded incarnation is fenced.
struct DeviceIncarnationRef {
  DeviceIdentity device{};
  IncarnationId incarnation{};

  friend bool operator==(const DeviceIncarnationRef&, const DeviceIncarnationRef&) noexcept = default;
  friend std::strong_ordering operator<=>(const DeviceIncarnationRef& a,
                                          const DeviceIncarnationRef& b) noexcept;
};

// The identity of an observation source process incarnation. A source that
// restarts increments its incarnation counter; evidence carries the counter it
// was produced under.
struct SourceIncarnation {
  SourceId source{};
  SourceIncarnationCounter counter{};

  friend bool operator==(const SourceIncarnation&, const SourceIncarnation&) noexcept = default;
  friend std::strong_ordering operator<=>(const SourceIncarnation& a,
                                          const SourceIncarnation& b) noexcept;
};

// The stream a record belongs to. Generations are monotonic within a stream.
struct EvidenceKey {
  DeviceIncarnationRef device{};
  CapabilityKind kind = CapabilityKind::PacketClassification;
  SourceId source{};

  friend bool operator==(const EvidenceKey&, const EvidenceKey&) noexcept = default;
  friend std::strong_ordering operator<=>(const EvidenceKey& a, const EvidenceKey& b) noexcept;
};

// Content-derived identity of an evidence record. Two byte-identical
// assertions have the same id, which is what makes duplicate delivery
// idempotent rather than duplicated.
class EvidenceId {
 public:
  EvidenceId() = default;
  explicit EvidenceId(Digest256 digest) noexcept : digest_(digest) {}

  [[nodiscard]] const Digest256& digest() const noexcept { return digest_; }
  [[nodiscard]] std::string hex() const { return digest_.hex(); }

  friend bool operator==(const EvidenceId&, const EvidenceId&) noexcept = default;
  friend std::strong_ordering operator<=>(const EvidenceId& a, const EvidenceId& b) noexcept {
    return a.digest_ <=> b.digest_;
  }

 private:
  Digest256 digest_{};
};

// Content-derived identity of an emitted decision.
class DecisionId {
 public:
  DecisionId() = default;
  explicit DecisionId(Digest256 digest) noexcept : digest_(digest) {}

  [[nodiscard]] const Digest256& digest() const noexcept { return digest_; }
  [[nodiscard]] std::string hex() const { return digest_.hex(); }

  friend bool operator==(const DecisionId&, const DecisionId&) noexcept = default;
  friend std::strong_ordering operator<=>(const DecisionId& a, const DecisionId& b) noexcept {
    return a.digest_ <=> b.digest_;
  }

 private:
  Digest256 digest_{};
};

// Content-derived identity of a conflict group.
class ConflictId {
 public:
  ConflictId() = default;
  explicit ConflictId(Digest256 digest) noexcept : digest_(digest) {}

  [[nodiscard]] const Digest256& digest() const noexcept { return digest_; }
  [[nodiscard]] std::string hex() const { return digest_.hex(); }

  friend bool operator==(const ConflictId&, const ConflictId&) noexcept = default;
  friend std::strong_ordering operator<=>(const ConflictId& a, const ConflictId& b) noexcept {
    return a.digest_ <=> b.digest_;
  }

 private:
  Digest256 digest_{};
};

// The exact semantic content asserted by a source about one capability of one
// device incarnation.
struct CapabilityEvidence {
  EvidenceKey key{};
  SourceIncarnation source_incarnation{};
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
  AuthorityRank authority = AuthorityRank::None;
  RegistryEpoch epoch_at_ingest{};
  BootEpoch boot_at_ingest{};
  PolicyRevision policy_revision{};

  // Canonical digest over every semantic field above.
  [[nodiscard]] Digest256 compute_digest() const;

  // The content-derived identifier.
  //
  // The digest is expensive and the identifier is read constantly (in sort
  // comparators, in explanations, in every decision). It is therefore computed
  // once, when the value is created or decoded, by refresh_id(), and merely
  // read afterwards. id() never writes, so concurrent readers of the same
  // record cannot race on it.
  [[nodiscard]] EvidenceId id() const noexcept { return EvidenceId(id_cache_); }

  // Recomputes and stores the identifier. Call this at every point where a
  // value comes into existence (construction, decoding, import).
  void refresh_id() const noexcept { id_cache_ = compute_digest(); }

 private:
  mutable Digest256 id_cache_{};
};

void encode(Writer& w, const DeviceIdentity& value);
bool decode(Reader& r, DeviceIdentity& value);
void encode(Writer& w, const DeviceIncarnationRef& value);
bool decode(Reader& r, DeviceIncarnationRef& value);
void encode(Writer& w, const SourceIncarnation& value);
bool decode(Reader& r, SourceIncarnation& value);
void encode(Writer& w, const EvidenceKey& value);
bool decode(Reader& r, EvidenceKey& value);
void encode(Writer& w, const EvidenceId& value);
bool decode(Reader& r, EvidenceId& value);
void encode(Writer& w, const ConflictId& value);
bool decode(Reader& r, ConflictId& value);
void encode(Writer& w, const DecisionId& value);
bool decode(Reader& r, DecisionId& value);
void encode(Writer& w, const CapabilityEvidence& value);
bool decode(Reader& r, CapabilityEvidence& value);

// Registry-side lifecycle. 'Admitted' means the registry accepted the
// assertion as evidence; it does not mean the device was asked to do anything.
enum class EvidenceLifecycle : std::uint8_t {
  Admitted = 1,
  Rejected = 2,
  Retired = 3,
};

// Effective state, derived at evaluation time from generations, policy and the
// current logical tick. Only 'Active' can satisfy a requirement.
enum class EvidenceState : std::uint8_t {
  Active = 1,
  Superseded = 2,
  Retired = 3,
  Rejected = 4,
  Fenced = 5,
  Stale = 6,
  Outranked = 7,
  Evicted = 8,
};

[[nodiscard]] std::string_view to_string(EvidenceState state) noexcept;
[[nodiscard]] std::string_view to_string(EvidenceLifecycle lifecycle) noexcept;
[[nodiscard]] bool parse_evidence_state(std::string_view text, EvidenceState& out) noexcept;
[[nodiscard]] bool parse_evidence_lifecycle(std::string_view text, EvidenceLifecycle& out) noexcept;

// A record as held by the registry: the assertion plus the registry's own
// bookkeeping. Rejected records are retained so refusals stay explainable.
struct StoredEvidence {
  CapabilityEvidence evidence{};
  EvidenceLifecycle lifecycle = EvidenceLifecycle::Admitted;
  ReasonCode admission_reason = ReasonCode::Ok;
  Tick admitted_at{};
  std::optional<Tick> retired_at{};
  ReasonCode retirement_reason = ReasonCode::Ok;

  [[nodiscard]] EvidenceId id() const { return evidence.id(); }
};

void encode(Writer& w, const StoredEvidence& value);
bool decode(Reader& r, StoredEvidence& value);

// A retirement tombstone. It fences every record in the stream whose
// generation is not greater than 'generation', so an out-of-order replay of an
// older record can never revive a retired capability.
struct RetirementRecord {
  EvidenceKey key{};
  RecordGeneration generation{};
  Tick retired_at{};
  ReasonCode reason = ReasonCode::Ok;
  RegistryEpoch epoch{};
  PolicyRevision policy_revision{};
  AuthorityRank authority = AuthorityRank::None;
};

void encode(Writer& w, const RetirementRecord& value);
bool decode(Reader& r, RetirementRecord& value);

// A group of records that disagree at equal authority. Held, never merged.
struct ConflictGroup {
  ConflictId id{};
  DeviceIncarnationRef device{};
  CapabilityKind kind = CapabilityKind::PacketClassification;
  AuthorityRank authority = AuthorityRank::None;
  std::vector<EvidenceId> members{};
  std::vector<RecordGeneration> generations{};
  Tick observed_first{};
  Tick observed_last{};
};

void encode(Writer& w, const ConflictGroup& value);
bool decode(Reader& r, ConflictGroup& value);

// Explicit operator resolution of a conflict group. Content-derived like the
// other identifiers, so re-resolution of the same disagreement by the same
// operator at the same tick is idempotent.
class ResolutionId {
 public:
  ResolutionId() = default;
  explicit ResolutionId(Digest256 digest) noexcept : digest_(digest) {}

  [[nodiscard]] const Digest256& digest() const noexcept { return digest_; }
  [[nodiscard]] std::string hex() const { return digest_.hex(); }

  friend bool operator==(const ResolutionId&, const ResolutionId&) noexcept = default;
  friend std::strong_ordering operator<=>(const ResolutionId& a, const ResolutionId& b) noexcept {
    return a.digest_ <=> b.digest_;
  }

 private:
  Digest256 digest_{};
};

struct ConflictResolution {
  ResolutionId id{};
  ConflictId conflict{};
  EvidenceId chosen{};
  std::vector<EvidenceId> rejected_members{};
  SourceId resolver{};
  Tick resolved_at{};
  RegistryEpoch epoch{};
};

void encode(Writer& w, const ConflictResolution& value);
bool decode(Reader& r, ConflictResolution& value);

// One entry of the eviction ledger. Every record removed by a bound is
// accounted for here; nothing disappears silently.
struct EvictionEntry {
  EvidenceId id{};
  EvidenceKey key{};
  RecordGeneration generation{};
  EvidenceState state_at_eviction = EvidenceState::Superseded;
  ReasonCode reason = ReasonCode::EvictedSuperseded;
  Tick evicted_at{};
};

void encode(Writer& w, const EvictionEntry& value);
bool decode(Reader& r, EvictionEntry& value);

// Canonical ordering helpers used everywhere a list of reason codes escapes
// the registry, so explanations are byte-stable.
namespace detail {
// Populates the identifier cache of a freshly created or decoded record. The
// cache is never written by readers, so it is safe under a shared lock.
void refresh_evidence_id(const CapabilityEvidence& evidence) noexcept;
}  // namespace detail

void canonicalize_reasons(std::vector<ReasonCode>& reasons);
[[nodiscard]] std::vector<ReasonCode> canonical_reasons(std::vector<ReasonCode> reasons);

}  // namespace ocreg

#endif  // OCREG_EVIDENCE_HPP
