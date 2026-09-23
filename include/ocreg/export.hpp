// Offload Capability Registry - canonical machine-readable export/import.
// Copyright 2026 Summon Software Labs.
#ifndef OCREG_EXPORT_HPP
#define OCREG_EXPORT_HPP

#include <cstddef>
#include <string>
#include <vector>

#include "ocreg/outcome.hpp"
#include "ocreg/reason.hpp"
#include "ocreg/registry.hpp"

namespace ocreg {

struct ExportOptions {
  bool include_history = true;
  bool include_rejected = true;
  bool include_evictions = true;
  bool include_policy = true;
  bool pretty = false;
  std::size_t max_records = 262144;
  std::size_t max_bytes = 64u * 1024u * 1024u;
};

struct ExportResult {
  std::string document{};
  Digest256 digest{};
  std::uint64_t records_written = 0;
  std::uint64_t tombstones_written = 0;
  std::uint64_t conflicts_written = 0;
  std::uint64_t evictions_written = 0;
  bool truncated = false;
  std::vector<ReasonCode> notes{};
};

// Serialises the complete current state of 'registry' as a canonical document.
// Truncation, when a bound is reached, is reported in the result and in the
// document itself; it is never silent.
Outcome<ExportResult> export_registry(const Registry& registry, const ExportOptions& options,
                                      Tick now);

struct ImportResult {
  RegistryState state{};
  ReasonCode reason = ReasonCode::Ok;
  std::uint64_t records_read = 0;
  std::uint64_t tombstones_read = 0;
  std::uint64_t conflicts_read = 0;
  std::uint64_t evictions_read = 0;
};

// Parses a document produced by export_registry. Any malformed, truncated,
// oversized or semantically impossible input is refused with a stable code.
Outcome<ImportResult> import_document(std::string_view document);

// Canonical document digests, for equivalence testing.
[[nodiscard]] Digest256 export_digest(const RegistryState& state);

// A policy document is canonical JSON with a top-level "policy" object (or the
// root object itself when it already looks like a policy). Loading is strict:
// an unknown or impossible policy is refused with a stable reason code.
[[nodiscard]] Outcome<RegistryPolicy> parse_policy_document(std::string_view document);
[[nodiscard]] std::string render_policy_document(const RegistryPolicy& policy, bool pretty);

// A requirement document shares the vocabulary of the canonical export so the
// two surfaces cannot drift apart. The root object may be the requirement
// itself or carry it under "requirement".
[[nodiscard]] Outcome<CapabilityRequirement> parse_requirement_document(std::string_view document);
[[nodiscard]] std::string render_requirement_document(const CapabilityRequirement& requirement,
                                                      bool pretty);

}  // namespace ocreg

#endif  // OCREG_EXPORT_HPP
