// Offload Capability Registry - compatibility comparison.
// Copyright 2026 Summon Software Labs.
#include "compat_internal.hpp"

#include <optional>

#include "ocreg/checked.hpp"

namespace ocreg::detail {
namespace {

// Compares a reported limit with a required minimum using exact units only.
// A missing limit, an unknown unit relationship and an inexact conversion are
// all reported as unknowns, never as zero and never as success.
void compare_limit(const LimitRequirement& required, const CapabilityEvidence& evidence,
                   std::vector<ReasonCode>& reasons) {
  const LimitValue* reported = evidence.limits.find(required.code);
  if (reported == nullptr) {
    reasons.push_back(ReasonCode::UnknownLimitNotReported);
    return;
  }
  if (dimension_of(reported->unit.code) != dimension_of(required.unit.code)) {
    reasons.push_back(ReasonCode::UnknownUnitMismatch);
    return;
  }
  // Comparison is exact in both directions: the registry converts whichever
  // side maps cleanly onto the other and refuses when neither does.
  const auto ordering =
      compare_exact(reported->value, reported->unit, required.minimum, required.unit);
  if (!ordering.has_value()) {
    reasons.push_back(ReasonCode::UnknownInexactUnitConversion);
    return;
  }
  if (*ordering == std::strong_ordering::less) {
    reasons.push_back(ReasonCode::IncompatibleLimitBelowRequirement);
  }
}

}  // namespace

ComparisonResult compare_requirement(const CapabilityRequirement& requirement,
                                     const CapabilityEvidence& evidence) {
  ComparisonResult result;
  result.kind = DecisionKind::Compatible;

  if (!requirement.version.satisfied_by(evidence.capability_version)) {
    result.reasons.push_back(ReasonCode::IncompatibleVersionTooLow);
  }

  for (const auto code : requirement.required_features.codes()) {
    if (!evidence.features.contains(code)) {
      result.reasons.push_back(ReasonCode::IncompatibleFeatureAbsent);
    }
  }

  for (const auto& limit : requirement.required_limits) {
    compare_limit(limit, evidence, result.reasons);
  }

  if (requirement.minimum_firmware_version.has_value()) {
    if (!evidence.firmware_version.has_value()) {
      result.reasons.push_back(ReasonCode::UnknownFirmwareGenerationAbsent);
    } else if (evidence.firmware_version->precedence_compare(*requirement.minimum_firmware_version) ==
               std::strong_ordering::less) {
      result.reasons.push_back(ReasonCode::IncompatibleFirmwareGenerationTooLow);
    }
  }

  if (requirement.minimum_firmware_generation.has_value()) {
    if (evidence.firmware_generation.is_unset()) {
      result.reasons.push_back(ReasonCode::UnknownFirmwareGenerationAbsent);
    } else if (evidence.firmware_generation < *requirement.minimum_firmware_generation) {
      result.reasons.push_back(ReasonCode::IncompatibleFirmwareGenerationTooLow);
    }
  }

  if (requirement.minimum_runtime_version.has_value()) {
    if (!evidence.runtime_version.has_value()) {
      result.reasons.push_back(ReasonCode::UnknownRuntimeGenerationAbsent);
    } else if (evidence.runtime_version->precedence_compare(*requirement.minimum_runtime_version) ==
               std::strong_ordering::less) {
      result.reasons.push_back(ReasonCode::IncompatibleRuntimeGenerationTooLow);
    }
  }

  if (requirement.minimum_runtime_generation.has_value()) {
    if (evidence.runtime_generation.is_unset()) {
      result.reasons.push_back(ReasonCode::UnknownRuntimeGenerationAbsent);
    } else if (evidence.runtime_generation < *requirement.minimum_runtime_generation) {
      result.reasons.push_back(ReasonCode::IncompatibleRuntimeGenerationTooLow);
    }
  }

  canonicalize_reasons(result.reasons);
  for (const auto reason : result.reasons) {
    if (category_of(reason) == ReasonCategory::Incompatible) {
      result.kind = DecisionKind::Incompatible;
      return result;
    }
  }
  for (const auto reason : result.reasons) {
    if (category_of(reason) == ReasonCategory::Unknown) {
      result.kind = DecisionKind::Unknown;
      return result;
    }
  }
  result.kind = DecisionKind::Compatible;
  return result;
}

}  // namespace ocreg::detail
