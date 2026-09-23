// Offload Capability Registry - registry benchmarks.
// Copyright 2026 Summon Software Labs.
#include <cstdint>
#include <string>
#include <vector>

#include <filesystem>
#include <system_error>

#include "bench_support.hpp"
#include "ocreg/export.hpp"
#include "ocreg/persist.hpp"
#include "ocreg/registry.hpp"

namespace {

using namespace ocreg;

[[nodiscard]] DeviceIncarnationRef device_for(std::uint32_t unit) {
  DeviceIncarnationRef device;
  device.device.provider = *ProviderId::parse("fixture-sim");
  device.device.model = *DeviceModelId::parse("sim-nic-bench");
  device.device.unit_index = unit;
  device.incarnation = IncarnationId(1);
  return device;
}

[[nodiscard]] SourceIncarnation source_for(const char* id) {
  return SourceIncarnation{*SourceId::parse(id), SourceIncarnationCounter(1)};
}

}  // namespace

int main() {
  constexpr std::uint32_t kDevices = 64;
  constexpr std::uint64_t kGenerations = 32;
  constexpr Tick kNow{1'000'000'000ull};

  RegistryPolicy policy = make_lab_policy();
  policy.default_max_age = Tick{0};
  policy.limits.max_devices = 4096;
  policy.limits.max_records = 262144;
  policy.limits.max_records_per_stream = 64;

  std::printf("%-46s %10s %-14s %12s %16s\n", "benchmark", "completed", "unit", "elapsed",
              "per unit");
  std::printf("-------------------------------------------------------------------------------------"
              "-------------------\n");

  // --- Admission ------------------------------------------------------------
  {
    Registry registry(policy);
    const std::uint64_t expected = static_cast<std::uint64_t>(kDevices) * kGenerations;
    std::uint64_t completed = 0;
    bench::Timer timer;
    for (std::uint32_t unit = 0; unit < kDevices; ++unit) {
      for (std::uint64_t generation = 1; generation <= kGenerations; ++generation) {
        AdmissionRequest request;
        request.device = device_for(unit);
        request.kind = CapabilityKind::ChecksumOffload;
        request.source = source_for("fixture-sim");
        request.capability_version = *SemVer::parse("1." + std::to_string(generation % 12) + ".0");
        request.features = FeatureSet::from_validated(
            {FeatureCode::ChecksumIpv4HeaderTx, FeatureCode::ChecksumL4Tx});
        request.limits = LimitSet::from_validated(
            {LimitValue{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 9000}});
        request.firmware_version = *SemVer::parse("3.0.0");
        request.firmware_generation = FirmwareGeneration(7);
        request.observed_at = kNow;
        request.generation = RecordGeneration(generation);
        const auto outcome = registry.admit(request, kNow);
        if (outcome.ok() && outcome.value().state != EvidenceState::Rejected) ++completed;
      }
    }
    const double elapsed = timer.seconds();
    bench::require(completed == expected, "every admission must complete");
    bench::require(registry.stats(kNow).records_active == kDevices,
                   "exactly one current record per device");
    bench::report("registry.admit", completed, elapsed, "op");
  }

  // --- Evaluation -----------------------------------------------------------
  {
    Registry registry(policy);
    for (std::uint32_t unit = 0; unit < kDevices; ++unit) {
      for (std::uint64_t generation = 1; generation <= kGenerations; ++generation) {
        AdmissionRequest request;
        request.device = device_for(unit);
        request.kind = CapabilityKind::ChecksumOffload;
        request.source = source_for("fixture-sim");
        request.capability_version = *SemVer::parse("1." + std::to_string(generation % 12) + ".0");
        request.features = FeatureSet::from_validated({FeatureCode::ChecksumL4Tx});
        request.limits = LimitSet::from_validated(
            {LimitValue{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 9000}});
        request.observed_at = kNow;
        request.generation = RecordGeneration(generation);
        (void)registry.admit(request, kNow);
      }
    }
    constexpr std::uint64_t kEvaluations = 20000;
    std::uint64_t completed = 0;
    bench::Timer timer;
    for (std::uint64_t index = 0; index < kEvaluations; ++index) {
      CapabilityRequirement requirement;
      requirement.device = device_for(static_cast<std::uint32_t>(index % kDevices));
      requirement.capability = CapabilityKind::ChecksumOffload;
      requirement.version.minimum = *SemVer::parse("1.0.0");
      requirement.required_features = FeatureSet::from_validated({FeatureCode::ChecksumL4Tx});
      requirement.required_limits.push_back(
          LimitRequirement{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 1500});
      const auto decision = registry.evaluate(requirement, kNow);
      if (decision.kind == DecisionKind::Compatible) ++completed;
    }
    const double elapsed = timer.seconds();
    bench::require(completed == kEvaluations, "every evaluation must complete");
    bench::report("registry.evaluate", kEvaluations, elapsed, "op");
  }

  // --- Query ----------------------------------------------------------------
  {
    Registry registry(policy);
    for (std::uint32_t unit = 0; unit < kDevices; ++unit) {
      for (std::uint64_t generation = 1; generation <= kGenerations; ++generation) {
        AdmissionRequest request;
        request.device = device_for(unit);
        request.kind = CapabilityKind::ChecksumOffload;
        request.source = source_for("fixture-sim");
        request.capability_version = *SemVer::parse("1." + std::to_string(generation % 12) + ".0");
        request.features = FeatureSet::from_validated({FeatureCode::ChecksumL4Tx});
        request.observed_at = kNow;
        request.generation = RecordGeneration(generation);
        (void)registry.admit(request, kNow);
      }
    }
    constexpr std::uint64_t kQueries = 20000;
    std::uint64_t completed = 0;
    bench::Timer timer;
    for (std::uint64_t index = 0; index < kQueries; ++index) {
      CapabilityQuery query;
      query.device = device_for(static_cast<std::uint32_t>(index % kDevices));
      query.kind = CapabilityKind::ChecksumOffload;
      query.include_history = true;
      const auto result = registry.query(query, kNow);
      if (result.ok() && result.value().kind == DecisionKind::Compatible) ++completed;
    }
    const double elapsed = timer.seconds();
    bench::require(completed == kQueries, "every query must complete");
    bench::report("registry.query", kQueries, elapsed, "op");
  }

  // --- Canonical export and import -----------------------------------------
  {
    Registry registry(policy);
    for (std::uint32_t unit = 0; unit < kDevices; ++unit) {
      for (std::uint64_t generation = 1; generation <= kGenerations; ++generation) {
        AdmissionRequest request;
        request.device = device_for(unit);
        request.kind = CapabilityKind::ChecksumOffload;
        request.source = source_for("fixture-sim");
        request.capability_version = *SemVer::parse("1." + std::to_string(generation % 12) + ".0");
        request.features = FeatureSet::from_validated({FeatureCode::ChecksumL4Tx});
        request.observed_at = kNow;
        request.generation = RecordGeneration(generation);
        (void)registry.admit(request, kNow);
      }
    }
    ExportOptions options;
    options.max_bytes = 64u * 1024u * 1024u;
    constexpr std::uint64_t kRounds = 8;
    std::uint64_t completed = 0;
    bench::Timer timer;
    for (std::uint64_t round = 0; round < kRounds; ++round) {
      const auto exported = export_registry(registry, options, kNow);
      bench::require(exported.ok(), "export must complete");
      const auto imported = import_document(exported.value().document);
      bench::require(imported.ok(), "import must complete");
      bench::require(state_digest(imported.value().state) == registry.state_digest(),
                     "round trip must preserve the state digest");
      ++completed;
    }
    const double elapsed = timer.seconds();
    bench::report("registry.export+import round trip", completed, elapsed, "round");
  }

  // --- Persistence ----------------------------------------------------------
  {
    Registry registry(policy);
    for (std::uint32_t unit = 0; unit < kDevices; ++unit) {
      AdmissionRequest request;
      request.device = device_for(unit);
      request.kind = CapabilityKind::ChecksumOffload;
      request.source = source_for("fixture-sim");
      request.capability_version = *SemVer::parse("1.0.0");
      request.features = FeatureSet::from_validated({FeatureCode::ChecksumL4Tx});
      request.observed_at = kNow;
      request.generation = RecordGeneration(1);
      (void)registry.admit(request, kNow);
    }
    RegistryState state = registry.snapshot_state().value();
    const std::string base = "ocreg-bench-store";
    StoreOptions store_options;
    store_options.base_path = base;
    auto bound = Store::bind(store_options);
    bench::require(bound.ok(), "store must bind");

    constexpr std::uint64_t kCommits = 64;
    std::uint64_t completed = 0;
    bench::Timer timer;
    for (std::uint64_t round = 0; round < kCommits; ++round) {
      state.store_generation = StoreGeneration(round + 1);
      std::vector<ReasonCode> notes;
      const auto committed = bound.value()->commit(state, kNow, notes);
      bench::require(committed.ok(), "commit must complete durably");
      bench::require(committed.value().synchronised, "commit must be synchronised");
      ++completed;
    }
    const double elapsed = timer.seconds();
    bound.value().reset();

    const auto reopened = Store::open(store_options);
    bench::require(reopened.ok(), "store must reopen");
    bench::require(state_digest(reopened.value().state) == state_digest(state),
                   "reopened state must match the last commit");
    bench::report("store.commit (durable, synchronised)", completed, elapsed, "commit");

    std::error_code error;
    std::filesystem::remove(base, error);
    std::filesystem::remove(base + ".ocregjournal", error);
  }

  std::printf("all registry benchmarks completed\n");
  return 0;
}