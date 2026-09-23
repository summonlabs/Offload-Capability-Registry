// Offload Capability Registry - persistence and recovery benchmarks.
// Copyright 2026 Summon Software Labs.
#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include "bench_support.hpp"
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

[[nodiscard]] RegistryState build_state(std::uint32_t devices, std::uint64_t generations,
                                        StoreGeneration generation, Tick now) {
  RegistryPolicy policy = make_lab_policy();
  policy.default_max_age = Tick{0};
  policy.limits.max_devices = 4096;
  Registry registry(policy);
  for (std::uint32_t unit = 0; unit < devices; ++unit) {
    for (std::uint64_t index = 1; index <= generations; ++index) {
      AdmissionRequest request;
      request.device = device_for(unit);
      request.kind = CapabilityKind::ChecksumOffload;
      request.source = SourceIncarnation{*SourceId::parse("fixture-sim"), SourceIncarnationCounter(1)};
      request.capability_version = *SemVer::parse("1." + std::to_string(index % 12) + ".0");
      request.features = FeatureSet::from_validated({FeatureCode::ChecksumL4Tx});
      request.limits = LimitSet::from_validated(
          {LimitValue{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 9000}});
      request.observed_at = now;
      request.generation = RecordGeneration(index);
      (void)registry.admit(request, now);
    }
  }
  RegistryState state = registry.snapshot_state().value();
  state.store_generation = generation;
  return state;
}

void clean(const std::string& base) {
  std::error_code error;
  std::filesystem::remove(base, error);
  error.clear();
  std::filesystem::remove(base + ".ocregjournal", error);
  error.clear();
  std::filesystem::remove(base + ".ocregtmp", error);
}

}  // namespace

int main() {
  constexpr Tick kNow{1'000'000'000ull};
  std::printf("%-46s %10s %-14s %12s %16s\n", "benchmark", "completed", "unit", "elapsed",
              "per unit");
  std::printf("-------------------------------------------------------------------------------------"
              "-------------------\n");

  // --- Snapshot write and clean reopen -------------------------------------
  {
    const std::string base = "ocreg-bench-snapshot";
    clean(base);
    const RegistryState state = build_state(64, 16, StoreGeneration(1), kNow);
    StoreOptions options;
    options.base_path = base;
    auto bound = Store::bind(options);
    bench::require(bound.ok(), "store must bind");

    constexpr std::uint64_t kRounds = 16;
    std::uint64_t completed = 0;
    bench::Timer timer;
    for (std::uint64_t round = 0; round < kRounds; ++round) {
      RegistryState copy = state;
      copy.store_generation = StoreGeneration(round + 1);
      const auto written = bound.value()->write_snapshot(copy, kNow);
      bench::require(written.ok(), "snapshot must complete");
      bench::require(written.value().synchronised, "snapshot must be synchronised");
      ++completed;
    }
    const double elapsed = timer.seconds();
    bench::require(completed == kRounds, "every snapshot write must complete");
    bench::report("store.write_snapshot (durable)", completed, elapsed, "snapshot");
    bound.value().reset();

    const auto reopened = Store::open(options);
    bench::require(reopened.ok(), "store must reopen cleanly");
    bench::require(reopened.value().classification == RecoveryClass::CleanOpen,
                   "a clean reopen must be classified clean");
    bench::require(reopened.value().state.records.size() == state.records.size(),
                   "every record must survive the round trip");
    clean(base);
  }

  // --- Recovery from a journal with a torn tail -----------------------------
  {
    const std::string base = "ocreg-bench-recovery";
    clean(base);
    StoreOptions options;
    options.base_path = base;
    auto bound = Store::bind(options);
    bench::require(bound.ok(), "store must bind");
    const RegistryState state = build_state(32, 8, StoreGeneration(3), kNow);
    std::vector<ReasonCode> notes;
    bench::require(bound.value()->commit(state, kNow, notes).ok(), "commit must complete");
    bound.value().reset();

    // Damage the tail so recovery has real work to classify.
    {
      std::FILE* file = std::fopen((base + ".ocregjournal").c_str(), "ab");
      bench::require(file != nullptr, "journal must open for damage");
      const unsigned char junk[5] = {0x4F, 0x43, 0x4A, 0x52, 0x00};
      (void)std::fwrite(junk, 1, sizeof(junk), file);
      (void)std::fclose(file);
    }

    constexpr std::uint64_t kRounds = 16;
    std::uint64_t completed = 0;
    bench::Timer timer;
    for (std::uint64_t round = 0; round < kRounds; ++round) {
      // Re-damage the tail each round because a successful open truncates it.
      if (round != 0) {
        std::FILE* file = std::fopen((base + ".ocregjournal").c_str(), "ab");
        bench::require(file != nullptr, "journal must open for damage");
        const unsigned char junk[5] = {0x4F, 0x43, 0x4A, 0x52, 0x00};
        (void)std::fwrite(junk, 1, sizeof(junk), file);
        (void)std::fclose(file);
      }
      const auto report = Store::open(options);
      bench::require(report.ok(), "recovery must complete");
      bench::require(report.value().classification == RecoveryClass::TornTailTruncated,
                     "the torn tail must be classified");
      bench::require(report.value().bytes_discarded == 5, "the refused tail must be accounted");
      bench::require(state_digest(report.value().state) == state_digest(state),
                     "recovery must return the committed state");
      ++completed;
    }
    const double elapsed = timer.seconds();
    bench::require(completed == kRounds, "every recovery must complete");
    bench::report("store.open (torn tail recovery)", completed, elapsed, "open");
    clean(base);
  }

  std::printf("all persistence benchmarks completed\n");
  return 0;
}