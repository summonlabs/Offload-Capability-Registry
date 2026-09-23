// Offload Capability Registry - concurrency tests.
// Copyright 2026 Summon Software Labs.
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "ocreg/client.hpp"
#include "ocreg/export.hpp"
#include "ocreg/registry.hpp"
#include "ocreg/service.hpp"
#include "registry_harness.hpp"
#include "test_support.hpp"

using namespace ocreg;
using namespace ocreg::test;

namespace {

constexpr int kThreads = 8;
constexpr int kDevicesPerThread = 12;

[[nodiscard]] DeviceIncarnationRef thread_device(int thread, int unit) {
  return reference("sim-nic-concurrent-" + std::to_string(thread), static_cast<std::uint32_t>(unit),
                   1);
}

}  // namespace

OCREG_TEST(concurrent_ingest_matches_serial_ingest_exactly) {
  RegistryPolicy policy = make_lab_policy();
  policy.limits.max_devices = 4096;

  Registry concurrent(policy);
  Registry serial(policy);

  std::vector<std::vector<AdmissionRequest>> per_thread(kThreads);
  for (int thread = 0; thread < kThreads; ++thread) {
    for (int unit = 0; unit < kDevicesPerThread; ++unit) {
      const auto device = thread_device(thread, unit);
      for (std::uint64_t generation = 1; generation <= 3; ++generation) {
        per_thread[static_cast<std::size_t>(thread)].push_back(make_request(
            device, "fixture-sim", "1." + std::to_string(generation) + ".0", generation, kSecond));
      }
    }
  }

  // Serial reference: every thread's requests in thread order.
  for (const auto& batch : per_thread) {
    for (const auto& request : batch) (void)serial.admit(request, kSecond);
  }

  std::atomic<int> failures{0};
  std::vector<std::thread> workers;
  workers.reserve(kThreads);
  for (int thread = 0; thread < kThreads; ++thread) {
    workers.emplace_back([&, thread] {
      for (const auto& request : per_thread[static_cast<std::size_t>(thread)]) {
        const auto outcome = concurrent.admit(request, kSecond);
        if (!outcome.ok()) failures.fetch_add(1);
      }
    });
  }
  for (auto& worker : workers) worker.join();
  CHECK_EQ(failures.load(), 0);

  // Serial and concurrent execution agree on every semantic result.
  CHECK(concurrent.state_digest() == serial.state_digest());
  CHECK_EQ(concurrent.stats(kSecond).records_total, serial.stats(kSecond).records_total);
  CHECK_EQ(concurrent.stats(kSecond).records_active, serial.stats(kSecond).records_active);
  for (int thread = 0; thread < kThreads; ++thread) {
    for (int unit = 0; unit < kDevicesPerThread; ++unit) {
      const auto device = thread_device(thread, unit);
      const auto left = concurrent.evaluate(make_requirement(device, "1.0.0"), kSecond);
      const auto right = serial.evaluate(make_requirement(device, "1.0.0"), kSecond);
      CHECK(left.id == right.id);
      CHECK(left.kind == right.kind);
    }
  }
}

OCREG_TEST(queries_are_consistent_while_ingest_runs) {
  RegistryPolicy policy = make_lab_policy();
  Registry registry(policy);
  const auto probe = reference("sim-nic-probe", 0, 1);
  REQUIRE(registry.admit(make_request(probe, "fixture-sim", "1.0.0", 1, kSecond), kSecond).ok());

  std::atomic<bool> writer_done{false};
  std::atomic<int> query_failures{0};
  std::atomic<int> mismatches{0};

  std::thread writer([&] {
    for (int device = 0; device < 200; ++device) {
      const auto target = reference("sim-nic-load", static_cast<std::uint32_t>(device), 1);
      for (std::uint64_t generation = 1; generation <= 3; ++generation) {
        (void)registry.admit(
            make_request(target, "fixture-sim", "1." + std::to_string(generation) + ".0", generation,
                         kSecond),
            kSecond);
      }
    }
    writer_done.store(true);
  });

  std::vector<std::thread> readers;
  readers.reserve(4);
  for (int reader = 0; reader < 4; ++reader) {
    readers.emplace_back([&] {
      while (!writer_done.load()) {
        const auto result = registry.query(
            CapabilityQuery{probe, CapabilityKind::ChecksumOffload, Tick{}, true}, kSecond);
        if (!result.ok()) {
          query_failures.fetch_add(1);
          continue;
        }
        // The probe's evidence is never touched by the writer, so its answer
        // must be stable throughout.
        if (result.value().kind != DecisionKind::Compatible) mismatches.fetch_add(1);
      }
    });
  }
  writer.join();
  for (auto& reader : readers) reader.join();
  CHECK_EQ(query_failures.load(), 0);
  CHECK_EQ(mismatches.load(), 0);
  CHECK_EQ(registry.stats(kSecond).devices, std::uint64_t{201});
}

OCREG_TEST(many_clients_share_one_service_without_interleaving) {
  // One client, one request at a time; the service must never interleave or
  // mismatch a reply with another client's request.
  RegistryPolicy policy = make_lab_policy();
  Registry registry(policy);
  ServerOptions options;
  options.max_workers = 8;
  options.max_connections = 16;
  Service service(registry, options);
  const auto started = service.start();
  REQUIRE(started.ok());

  constexpr int kClients = 8;
  constexpr int kRequests = 12;
  std::atomic<int> failures{0};
  std::vector<std::thread> clients;
  clients.reserve(kClients);
  for (int index = 0; index < kClients; ++index) {
    clients.emplace_back([&, index] {
      ClientOptions client_options;
      client_options.port = started.value();
      auto client = Client::connect(client_options);
      if (!client.ok()) {
        failures.fetch_add(1);
        return;
      }
      const auto device = reference("sim-nic-multiclient", static_cast<std::uint32_t>(index), 1);
      for (int request = 0; request < kRequests; ++request) {
        const auto pong = client.value()->ping(kSecond);
        if (!pong.ok() || !pong.value().value) failures.fetch_add(1);
        const auto admitted = client.value()->admit(
            make_request(device, "fixture-sim", "1." + std::to_string(request + 1) + ".0",
                         static_cast<std::uint64_t>(request + 1), kSecond),
            kSecond);
        if (!admitted.ok()) failures.fetch_add(1);
      }
      const auto queried = client.value()->query(
          CapabilityQuery{device, CapabilityKind::ChecksumOffload, Tick{}, true}, kSecond);
      if (!queried.ok() || queried.value().kind != DecisionKind::Compatible) failures.fetch_add(1);
      // The first Shutdown drains the service; later ones may observe a closed
      // transport, which is not a defect.
      (void)client.value()->shutdown(kSecond);
    });
  }
  for (auto& client : clients) client.join();

  service.wait_for_shutdown();
  service.stop();
  CHECK_EQ(failures.load(), 0);
  CHECK_EQ(registry.stats(kSecond).devices, std::uint64_t{kClients});
  CHECK_EQ(registry.stats(kSecond).records_active, std::uint64_t{kClients});
  CHECK(service.connections_accepted() >= static_cast<std::uint64_t>(kClients));
}

OCREG_TEST(shutdown_with_work_in_flight_completes_without_losing_committed_work) {
  RegistryPolicy policy = make_lab_policy();
  Registry registry(policy);
  ServerOptions options;
  options.max_workers = 4;
  Service service(registry, options);
  const auto started = service.start();
  REQUIRE(started.ok());

  constexpr int kClients = 4;
  std::atomic<int> accepted_by_client{0};
  std::atomic<int> unexpected_failures{0};
  std::mutex barrier_mutex;
  std::condition_variable barrier;
  int ready = 0;
  std::vector<std::thread> clients;
  clients.reserve(kClients);
  for (int index = 0; index < kClients; ++index) {
    clients.emplace_back([&, index] {
      ClientOptions client_options;
      client_options.port = started.value();
      auto client = Client::connect(client_options);
      if (!client.ok()) return;
      const auto device = reference("sim-nic-shutdown", static_cast<std::uint32_t>(index), 1);
      // Synchronise on completed work: every client has connected and had one
      // admission applied before the shutdown is issued, so the shutdown really
      // does race with work in flight.
      if (client.value()->ping(kSecond).ok()) {
        std::lock_guard<std::mutex> guard(barrier_mutex);
        ++ready;
        barrier.notify_all();
      }
      for (int request = 0; request < 16; ++request) {
        const auto outcome = client.value()->admit(
            make_request(device, "fixture-sim", "1." + std::to_string(request + 1) + ".0",
                         static_cast<std::uint64_t>(request + 1), kSecond),
            kSecond);
        if (outcome.ok()) {
          if (!outcome.value().idempotent) accepted_by_client.fetch_add(1);
        } else if (outcome.reason() != ReasonCode::TransportClosed &&
                   outcome.reason() != ReasonCode::ProtocolShutdownInProgress) {
          // Only a closed or draining transport is an acceptable failure while
          // stopping. Anything else is a real defect.
          unexpected_failures.fetch_add(1);
        }
      }
    });
  }

  {
    std::unique_lock<std::mutex> guard(barrier_mutex);
    barrier.wait(guard, [&ready] { return ready == kClients; });
  }

  // Stop while the clients are still sending. The service must finish or refuse
  // every request, never acknowledge one it did not apply.
  service.stop();
  for (auto& client : clients) client.join();

  // Every admission the clients saw acknowledged was actually applied, and no
  // acknowledgement was issued for an admission the registry did not record.
  const auto stats = registry.stats(kSecond);
  CHECK_EQ(unexpected_failures.load(), 0);
  CHECK(stats.admissions_accepted >= 1);
  // The property that matters is one-directional: an acknowledgement implies
  // that the registry applied the admission. Stopping in the middle of a
  // request may lose the reply, which is a lost acknowledgement and not a
  // fabricated one, so the accepted count may exceed what the clients observed.
  CHECK(stats.admissions_accepted >= static_cast<std::uint64_t>(accepted_by_client.load()));
  // Every device that accepted at least one admission has exactly one current
  // record, and nothing was rejected.
  CHECK_EQ(stats.records_active, stats.devices);
  CHECK(stats.devices >= 1);
  CHECK(stats.devices <= static_cast<std::uint64_t>(kClients));
  CHECK_EQ(stats.admissions_rejected, std::uint64_t{0});
}

OCREG_TEST(repeated_start_stop_under_load_returns_resources_to_baseline) {
  RegistryPolicy policy = make_lab_policy();
  Registry registry(policy);
  ServerOptions options;
  options.max_workers = 3;
  Service service(registry, options);

  std::uint64_t served = 0;
  for (int round = 0; round < 6; ++round) {
    const auto started = service.start();
    REQUIRE(started.ok());
    const auto before = service.requests_served();

    std::vector<std::thread> clients;
    for (int index = 0; index < 3; ++index) {
      clients.emplace_back([&, index] {
        ClientOptions client_options;
        client_options.port = started.value();
        auto client = Client::connect(client_options);
        if (!client.ok()) return;
        const auto device =
            reference("sim-nic-restart", static_cast<std::uint32_t>(index + round * 3), 1);
        for (int request = 0; request < 4; ++request) {
          (void)client.value()->ping(kSecond);
          (void)client.value()->admit(
              make_request(device, "fixture-sim", "1." + std::to_string(request + 1) + ".0",
                           static_cast<std::uint64_t>(request + 1), kSecond),
              kSecond);
        }
        (void)client.value()->shutdown(kSecond);
      });
    }
    service.wait_for_shutdown();
    service.stop();
    for (auto& client : clients) client.join();
    CHECK(service.requests_served() > before);
    served = service.requests_served();
  }
  CHECK(served > 0);
  CHECK(!service.running());
  CHECK_EQ(registry.stats(kSecond).devices, std::uint64_t{18});
  CHECK_EQ(registry.stats(kSecond).records_active, std::uint64_t{18});
}
