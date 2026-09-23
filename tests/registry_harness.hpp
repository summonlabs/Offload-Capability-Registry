// Offload Capability Registry - shared registry test fixtures.
// Copyright 2026 Summon Software Labs.
//
// Every device and source used by the tests is SYNTHETIC. Nothing in this
// header describes real hardware, and no test claims hardware validation.
#ifndef OCREG_TESTS_REGISTRY_HARNESS_HPP
#define OCREG_TESTS_REGISTRY_HARNESS_HPP

#include <string>
#include <vector>

#include "ocreg/export.hpp"
#include "ocreg/persist.hpp"
#include "ocreg/registry.hpp"

namespace ocreg::test {

inline constexpr Tick kSecond = Tick{1'000'000'000ull};

[[nodiscard]] inline SourceId source_id(std::string_view text) {
  const auto parsed = SourceId::parse(text);
  return parsed.has_value() ? *parsed : SourceId{};
}

[[nodiscard]] inline DeviceIdentity synthetic_device(std::string_view model, std::uint32_t unit) {
  DeviceIdentity device;
  const auto provider = ProviderId::parse("fixture-sim");
  const auto parsed_model = DeviceModelId::parse(model);
  if (provider.has_value()) device.provider = *provider;
  if (parsed_model.has_value()) device.model = *parsed_model;
  device.unit_index = unit;
  return device;
}

[[nodiscard]] inline DeviceIncarnationRef reference(std::string_view model, std::uint32_t unit,
                                                    std::uint64_t incarnation) {
  DeviceIncarnationRef result;
  result.device = synthetic_device(model, unit);
  result.incarnation = IncarnationId(incarnation);
  return result;
}

[[nodiscard]] inline SourceIncarnation source_incarnation(const char* id, std::uint64_t counter) {
  return SourceIncarnation{source_id(id), SourceIncarnationCounter(counter)};
}

[[nodiscard]] inline AdmissionRequest make_request(const DeviceIncarnationRef& device,
                                                   std::string_view source,
                                                   std::string_view version,
                                                   std::uint64_t generation, Tick observed_at) {
  AdmissionRequest request;
  request.device = device;
  request.kind = CapabilityKind::ChecksumOffload;
  request.source = source_incarnation(std::string(source).c_str(), 1);
  const auto parsed = SemVer::parse(version);
  if (parsed.has_value()) request.capability_version = *parsed;
  request.features = FeatureSet::from_validated(
      {FeatureCode::ChecksumIpv4HeaderTx, FeatureCode::ChecksumL4Tx});
  request.limits = LimitSet::from_validated(
      {LimitValue{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 9000}});
  request.firmware_version = *SemVer::parse("3.0.0");
  request.firmware_generation = FirmwareGeneration(7);
  request.runtime_version = *SemVer::parse("2.4.0");
  request.runtime_generation = RuntimeGeneration(11);
  request.observed_at = observed_at;
  request.generation = RecordGeneration(generation);
  return request;
}

[[nodiscard]] inline CapabilityRequirement make_requirement(const DeviceIncarnationRef& device,
                                                            std::string_view minimum_version) {
  CapabilityRequirement requirement;
  requirement.device = device;
  requirement.capability = CapabilityKind::ChecksumOffload;
  const auto parsed = SemVer::parse(minimum_version);
  if (parsed.has_value()) requirement.version.minimum = *parsed;
  requirement.required_features = FeatureSet::from_validated({FeatureCode::ChecksumL4Tx});
  requirement.required_limits.push_back(
      LimitRequirement{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 1500});
  return requirement;
}

}  // namespace ocreg::test

#endif  // OCREG_TESTS_REGISTRY_HARNESS_HPP
