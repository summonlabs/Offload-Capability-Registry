// Offload Capability Registry - evidence model support code.
// Copyright 2026 Summon Software Labs.
#include "ocreg/evidence.hpp"

#include <algorithm>
#include <cstddef>

#include "ocreg/codec.hpp"

namespace ocreg {

std::string_view to_string(SourceKind kind) noexcept {
  switch (kind) {
    case SourceKind::Synthetic: return "synthetic";
    case SourceKind::AdjacentRuntime: return "adjacent_runtime";
    case SourceKind::DeviceSelfReport: return "device_self_report";
    case SourceKind::OperatorDeclaration: return "operator_declaration";
    case SourceKind::ImportedBundle: return "imported_bundle";
  }
  return "unknown";
}

std::string_view to_string(AuthorityRank rank) noexcept {
  switch (rank) {
    case AuthorityRank::None: return "none";
    case AuthorityRank::Synthetic: return "synthetic";
    case AuthorityRank::Imported: return "imported";
    case AuthorityRank::AdjacentRuntime: return "adjacent_runtime";
    case AuthorityRank::DeviceSelfReport: return "device_self_report";
    case AuthorityRank::Operator: return "operator";
  }
  return "none";
}

std::string_view to_string(SourceTrustState state) noexcept {
  switch (state) {
    case SourceTrustState::Trusted: return "trusted";
    case SourceTrustState::Untrusted: return "untrusted";
    case SourceTrustState::Revoked: return "revoked";
  }
  return "untrusted";
}

bool parse_source_kind(std::string_view text, SourceKind& out) noexcept {
  const SourceKind candidates[] = {SourceKind::Synthetic, SourceKind::AdjacentRuntime,
                                   SourceKind::DeviceSelfReport, SourceKind::OperatorDeclaration,
                                   SourceKind::ImportedBundle};
  for (const auto candidate : candidates) {
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

bool parse_authority_rank(std::string_view text, AuthorityRank& out) noexcept {
  const AuthorityRank candidates[] = {AuthorityRank::None,       AuthorityRank::Synthetic,
                                      AuthorityRank::Imported,   AuthorityRank::AdjacentRuntime,
                                      AuthorityRank::DeviceSelfReport, AuthorityRank::Operator};
  for (const auto candidate : candidates) {
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

bool parse_source_trust_state(std::string_view text, SourceTrustState& out) noexcept {
  const SourceTrustState candidates[] = {SourceTrustState::Trusted, SourceTrustState::Untrusted,
                                         SourceTrustState::Revoked};
  for (const auto candidate : candidates) {
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

std::string_view to_string(EvidenceState state) noexcept {
  switch (state) {
    case EvidenceState::Active: return "active";
    case EvidenceState::Superseded: return "superseded";
    case EvidenceState::Retired: return "retired";
    case EvidenceState::Rejected: return "rejected";
    case EvidenceState::Fenced: return "fenced";
    case EvidenceState::Stale: return "stale";
    case EvidenceState::Outranked: return "outranked";
    case EvidenceState::Evicted: return "evicted";
  }
  return "rejected";
}

std::string_view to_string(EvidenceLifecycle lifecycle) noexcept {
  switch (lifecycle) {
    case EvidenceLifecycle::Admitted: return "admitted";
    case EvidenceLifecycle::Rejected: return "rejected";
    case EvidenceLifecycle::Retired: return "retired";
  }
  return "rejected";
}

bool parse_evidence_state(std::string_view text, EvidenceState& out) noexcept {
  const EvidenceState candidates[] = {
      EvidenceState::Active,     EvidenceState::Superseded, EvidenceState::Retired,
      EvidenceState::Rejected,   EvidenceState::Fenced,     EvidenceState::Stale,
      EvidenceState::Outranked,  EvidenceState::Evicted};
  for (const auto candidate : candidates) {
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

bool parse_evidence_lifecycle(std::string_view text, EvidenceLifecycle& out) noexcept {
  const EvidenceLifecycle candidates[] = {EvidenceLifecycle::Admitted, EvidenceLifecycle::Rejected,
                                          EvidenceLifecycle::Retired};
  for (const auto candidate : candidates) {
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

std::strong_ordering operator<=>(const DeviceIdentity& a, const DeviceIdentity& b) noexcept {
  if (a.provider != b.provider) return a.provider <=> b.provider;
  if (a.model != b.model) return a.model <=> b.model;
  if (a.unit_index != b.unit_index) return a.unit_index <=> b.unit_index;
  const bool a_has = a.serial.has_value();
  const bool b_has = b.serial.has_value();
  if (a_has != b_has) return a_has ? std::strong_ordering::greater : std::strong_ordering::less;
  if (!a_has) return std::strong_ordering::equal;
  return *a.serial <=> *b.serial;
}

std::strong_ordering operator<=>(const DeviceIncarnationRef& a,
                                 const DeviceIncarnationRef& b) noexcept {
  if (a.device != b.device) return a.device <=> b.device;
  return a.incarnation <=> b.incarnation;
}

std::strong_ordering operator<=>(const SourceIncarnation& a, const SourceIncarnation& b) noexcept {
  if (a.source != b.source) return a.source <=> b.source;
  return a.counter <=> b.counter;
}

std::strong_ordering operator<=>(const EvidenceKey& a, const EvidenceKey& b) noexcept {
  if (a.device != b.device) return a.device <=> b.device;
  if (a.kind != b.kind) {
    return static_cast<std::uint16_t>(a.kind) < static_cast<std::uint16_t>(b.kind)
               ? std::strong_ordering::less
               : std::strong_ordering::greater;
  }
  return a.source <=> b.source;
}

Digest256 CapabilityEvidence::compute_digest() const {
  Writer writer;
  encode(writer, *this);
  return Digest256::of(writer.span());
}

namespace detail {

void refresh_evidence_id(const CapabilityEvidence& evidence) noexcept { evidence.refresh_id(); }

}  // namespace detail

}  // namespace ocreg
