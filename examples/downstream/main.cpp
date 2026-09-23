// Offload Capability Registry - independent downstream consumer.
// Copyright 2026 Summon Software Labs.
//
// This program uses only installed headers and the installed library. It walks
// the public surface end to end: declare a policy, admit evidence, ask a
// question, read the explanation, persist, recover and export.
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>

#include <ocreg/export.hpp>
#include <ocreg/persist.hpp>
#include <ocreg/registry.hpp>
#include <ocreg/version.hpp>

namespace {

int failures = 0;

void expect(bool condition, const char* what) {
  if (!condition) {
    std::fprintf(stderr, "consumer failure: %s\n", what);
    ++failures;
  }
}

ocreg::DeviceIncarnationRef device() {
  ocreg::DeviceIncarnationRef reference;
  reference.device.provider = *ocreg::ProviderId::parse("fixture-sim");
  reference.device.model = *ocreg::DeviceModelId::parse("sim-nic-42");
  reference.device.unit_index = 0;
  reference.incarnation = ocreg::IncarnationId(1);
  return reference;
}

}  // namespace

int main() {
  constexpr ocreg::Tick now{1'000'000'000ull};

  ocreg::RegistryPolicy policy = ocreg::make_lab_policy();
  ocreg::Registry registry(policy);

  ocreg::AdmissionRequest request;
  request.device = device();
  request.kind = ocreg::CapabilityKind::ChecksumOffload;
  request.source = ocreg::SourceIncarnation{*ocreg::SourceId::parse("fixture-sim"),
                                            ocreg::SourceIncarnationCounter(1)};
  request.capability_version = *ocreg::SemVer::parse("1.4.0");
  request.features = ocreg::FeatureSet::from_validated(
      {ocreg::FeatureCode::ChecksumIpv4HeaderTx, ocreg::FeatureCode::ChecksumL4Tx});
  request.limits = ocreg::LimitSet::from_validated(
      {ocreg::LimitValue{ocreg::LimitCode::MaximumTransmissionUnit,
                         ocreg::unity(ocreg::UnitCode::Byte), 9000}});
  request.firmware_version = *ocreg::SemVer::parse("3.1.0");
  request.firmware_generation = ocreg::FirmwareGeneration(11);
  request.observed_at = now;
  request.generation = ocreg::RecordGeneration(1);

  const auto admitted = registry.admit(request, now);
  expect(admitted.ok(), "admission must succeed");
  expect(admitted.ok() && admitted.value().state == ocreg::EvidenceState::Active,
         "admitted evidence must be current");

  ocreg::CapabilityRequirement requirement;
  requirement.device = device();
  requirement.capability = ocreg::CapabilityKind::ChecksumOffload;
  requirement.version.minimum = *ocreg::SemVer::parse("1.2.0");
  requirement.required_features =
      ocreg::FeatureSet::from_validated({ocreg::FeatureCode::ChecksumL4Tx});
  requirement.required_limits.push_back(
      ocreg::LimitRequirement{ocreg::LimitCode::MaximumTransmissionUnit,
                              ocreg::unity(ocreg::UnitCode::Byte), 1500});

  const ocreg::CompatibilityDecision decision = registry.evaluate(requirement, now);
  expect(decision.kind == ocreg::DecisionKind::Compatible, "requirement must be satisfied");
  expect(!decision.id.hex().empty(), "a decision carries a stable identifier");

  const auto explanation = registry.explain(decision.id);
  expect(explanation.ok(), "the decision must be explainable");
  expect(explanation.ok() && explanation.value().decision_available,
         "the explanation must be present");

  // A requirement the evidence positively fails is incompatible; one the
  // registry cannot answer is an explicit unknown.
  ocreg::CapabilityRequirement impossible = requirement;
  impossible.version.minimum = *ocreg::SemVer::parse("9.0.0");
  expect(registry.evaluate(impossible, now).kind == ocreg::DecisionKind::Incompatible,
         "an unmet version must be incompatible");

  ocreg::CapabilityRequirement silent = requirement;
  silent.capability = ocreg::CapabilityKind::Timestamping;
  silent.required_features = ocreg::FeatureSet{};
  silent.required_limits.clear();
  expect(registry.evaluate(silent, now).kind == ocreg::DecisionKind::Unknown,
         "absent evidence must be unknown rather than false");

  // Canonical export round-trips the state.
  ocreg::ExportOptions export_options;
  const auto exported = ocreg::export_registry(registry, export_options, now);
  expect(exported.ok(), "export must succeed");
  const auto imported =
      exported.ok() ? ocreg::import_document(exported.value().document)
                    : ocreg::Outcome<ocreg::ImportResult>(ocreg::Status::failure(
                          ocreg::ReasonCode::StorePayloadCorrupt, "export failed"));
  expect(imported.ok(), "import must succeed");
  expect(imported.ok() && ocreg::state_digest(imported.value().state) == registry.state_digest(),
         "export and import must preserve the state");

  // Durable persistence and a clean reopen.
  const std::filesystem::path base =
      std::filesystem::current_path() / "ocreg-consumer-store";
  std::error_code error;
  std::filesystem::remove(base, error);
  error.clear();
  std::filesystem::remove(base.string() + ".ocregjournal", error);
  error.clear();

  ocreg::StoreOptions store_options;
  store_options.base_path = base.string();
  auto bound = ocreg::Store::bind(store_options);
  expect(bound.ok(), "the store must bind");
  if (bound.ok()) {
    ocreg::RegistryState state = registry.snapshot_state().value();
    state.store_generation = ocreg::StoreGeneration(1);
    std::vector<ocreg::ReasonCode> notes;
    const auto committed = bound.value()->commit(state, now, notes);
    expect(committed.ok() && committed.value().synchronised, "the commit must be durable");
    bound.value().reset();

    const auto reopened = ocreg::Store::open(store_options);
    expect(reopened.ok(), "the store must reopen");
    expect(reopened.ok() && ocreg::state_digest(reopened.value().state) == ocreg::state_digest(state),
           "the reopened state must match the committed state");

    std::filesystem::remove(base, error);
    error.clear();
    std::filesystem::remove(base.string() + ".ocregjournal", error);
  }

  if (failures == 0) {
    std::printf("ocreg downstream consumer: OK (library version %.*s, state digest %s)\n",
                static_cast<int>(ocreg::version_string().size()), ocreg::version_string().data(),
                registry.state_digest().hex().c_str());
  }
  return failures == 0 ? 0 : 1;
}
