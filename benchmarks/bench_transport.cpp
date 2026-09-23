// Offload Capability Registry - transport benchmarks.
// Copyright 2026 Summon Software Labs.
//
// The measured unit is a completed request/response exchange over a real
// loopback socket. Nothing is measured at enqueue time.
#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "bench_support.hpp"
#include "ocreg/client.hpp"
#include "ocreg/registry.hpp"
#include "ocreg/service.hpp"

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

}  // namespace

int main() {
  constexpr Tick kNow{1'000'000'000ull};
  std::printf("%-46s %10s %-14s %12s %16s\n", "benchmark", "completed", "unit", "elapsed",
              "per unit");
  std::printf("-------------------------------------------------------------------------------------"
              "-------------------\n");

  RegistryPolicy policy = make_lab_policy();
  policy.default_max_age = Tick{0};
  Registry registry(policy);
  ServerOptions options;
  options.max_workers = 4;
  options.max_connections = 16;
  Service service(registry, options);
  const auto started = service.start();
  bench::require(started.ok(), "service must start");

  // --- Single client, sequential round trips --------------------------------
  {
    ClientOptions client_options;
    client_options.port = started.value();
    auto client = Client::connect(client_options);
    bench::require(client.ok(), "client must connect");

    constexpr std::uint64_t kRequests = 5000;
    std::uint64_t completed = 0;
    bench::Timer timer;
    for (std::uint64_t index = 0; index < kRequests; ++index) {
      const auto reply = client.value()->ping(kNow);
      if (reply.ok() && reply.value().value) ++completed;
    }
    const double elapsed = timer.seconds();
    bench::require(completed == kRequests, "every round trip must complete");
    bench::report("transport.ping (1 client, sequential)", completed, elapsed, "round trip");
  }

  // --- Admission over the wire ---------------------------------------------
  {
    ClientOptions client_options;
    client_options.port = started.value();
    auto client = Client::connect(client_options);
    bench::require(client.ok(), "client must connect");

    constexpr std::uint64_t kDevices = 64;
    constexpr std::uint64_t kGenerations = 8;
    const std::uint64_t expected = kDevices * kGenerations;
    std::uint64_t completed = 0;
    bench::Timer timer;
    for (std::uint32_t unit = 0; unit < kDevices; ++unit) {
      for (std::uint64_t generation = 1; generation <= kGenerations; ++generation) {
        AdmissionRequest request;
        request.device = device_for(unit);
        request.kind = CapabilityKind::ChecksumOffload;
        request.source = SourceIncarnation{*SourceId::parse("fixture-sim"),
                                           SourceIncarnationCounter(1)};
        request.capability_version = *SemVer::parse("1." + std::to_string(generation) + ".0");
        request.features = FeatureSet::from_validated({FeatureCode::ChecksumL4Tx});
        request.limits = LimitSet::from_validated(
            {LimitValue{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 9000}});
        request.observed_at = kNow;
        request.generation = RecordGeneration(generation);
        const auto outcome = client.value()->admit(request, kNow);
        if (outcome.ok()) ++completed;
      }
    }
    const double elapsed = timer.seconds();
    bench::require(completed == expected, "every admission round trip must complete");
    bench::report("transport.admit (1 client, sequential)", completed, elapsed, "round trip");
  }

  // --- Concurrent clients ---------------------------------------------------
  {
    constexpr int kClients = 8;
    constexpr std::uint64_t kRequestsPerClient = 500;
    std::atomic<std::uint64_t> completed{0};
    std::vector<std::thread> clients;
    clients.reserve(kClients);
    bench::Timer timer;
    for (int index = 0; index < kClients; ++index) {
      clients.emplace_back([&, index] {
        ClientOptions client_options;
        client_options.port = started.value();
        auto client = Client::connect(client_options);
        if (!client.ok()) return;
        std::uint64_t local = 0;
        for (std::uint64_t request = 0; request < kRequestsPerClient; ++request) {
          const auto reply = client.value()->ping(kNow);
          if (reply.ok() && reply.value().value) ++local;
        }
        completed.fetch_add(local);
        (void)index;
      });
    }
    for (auto& client : clients) client.join();
    const double elapsed = timer.seconds();
    const std::uint64_t expected = static_cast<std::uint64_t>(kClients) * kRequestsPerClient;
    bench::require(completed.load() == expected, "every concurrent round trip must complete");
    bench::report("transport.ping (8 clients concurrent)", completed.load(), elapsed, "round trip");
  }

  service.stop();
  bench::require(!service.running(), "service must be stopped");
  bench::require(service.requests_served() >= 5000 + 512 + 4000, "served count must be coherent");
  std::printf("all transport benchmarks completed\n");
  return 0;
}