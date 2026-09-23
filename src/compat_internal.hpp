// Offload Capability Registry - internal compatibility comparison surface.
// Copyright 2026 Summon Software Labs.
#ifndef OCREG_SRC_COMPAT_INTERNAL_HPP
#define OCREG_SRC_COMPAT_INTERNAL_HPP

#include <vector>

#include "ocreg/decision.hpp"
#include "ocreg/evidence.hpp"
#include "ocreg/reason.hpp"

namespace ocreg::detail {

struct ComparisonResult {
  DecisionKind kind = DecisionKind::Unknown;
  std::vector<ReasonCode> reasons{};
};

// Compares one admitted, current, authoritative evidence record against a
// requirement. Every failure and every unknown is reported; the overall kind
// is Incompatible when any requirement is positively unmet, Unknown when the
// registry has no basis to decide a part of it, and Compatible only when every
// part is met by evidence.
ComparisonResult compare_requirement(const CapabilityRequirement& requirement,
                                     const CapabilityEvidence& evidence);

}  // namespace ocreg::detail

#endif  // OCREG_SRC_COMPAT_INTERNAL_HPP
