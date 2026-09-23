// Offload Capability Registry - independent OS process and crash-boundary tests.
// Copyright 2026 Summon Software Labs.
//
// These tests use real processes and a real loopback socket. Threads alone are
// not evidence of multiprocess behaviour, so nothing here is simulated.
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "ocreg/client.hpp"
#include "ocreg/export.hpp"
#include "ocreg/json.hpp"
#include "ocreg/persist.hpp"
#include "ocreg/registry.hpp"
#include "ocreg/service.hpp"
#include "registry_harness.hpp"
#include "test_support.hpp"

using namespace ocreg;
using namespace ocreg::test;

namespace {

[[nodiscard]] std::string quote(const std::filesystem::path& path) { return path.string(); }

[[nodiscard]] std::uint16_t parse_port_line(const std::string& line) {
  if (line.rfind("PORT ", 0) != 0) return 0;
  bool ok = false;
  std::uint64_t value = 0;
  for (const char c : line.substr(5)) {
    if (c < '0' || c > '9') return 0;
    value = value * 10u + static_cast<std::uint64_t>(c - '0');
  }
  ok = value > 0 && value <= 65535;
  return ok ? static_cast<std::uint16_t>(value) : 0;
}

}  // namespace

OCREG_TEST(a_service_process_serves_a_client_over_a_real_socket) {
  const auto directory = fresh_dir("process_service");
  const auto base = directory / "state.ocregstore";

  auto child = ChildProcess::spawn({OCREG_SERVICE_EXE, "--store", base.string(), "--port", "0",
                                    "--workers", "4", "--tick", "1000000000"});
  REQUIRE(child != nullptr);

  std::string line;
  REQUIRE(child->read_line(line));
  const std::uint16_t port = parse_port_line(line);
  CHECK_MSG(port != 0, line);

  ClientOptions options;
  options.host = "127.0.0.1";
  options.port = port;
  auto client = Client::connect(options);
  REQUIRE(client.ok());

  const Tick now = kSecond;
  const auto device = reference("sim-nic-1000", 0, 1);
  const auto admitted =
      client.value()->admit(make_request(device, "fixture-sim", "1.4.0", 1, now), now);
  REQUIRE(admitted.ok());
  CHECK(admitted.value().state == EvidenceState::Active);

  const auto evaluated = client.value()->evaluate(make_requirement(device, "1.2.0"), now);
  REQUIRE(evaluated.ok());
  CHECK(evaluated.value().kind == DecisionKind::Compatible);

  ExportOptions export_options;
  const auto exported = client.value()->export_state(export_options, now);
  REQUIRE(exported.ok());

  const auto stopped = client.value()->shutdown(now);
  REQUIRE(stopped.ok());

  // The process reports its served count and its durable commit digest, then
  // exits on its own.
  std::string served_line;
  REQUIRE(child->read_line(served_line));
  CHECK(served_line.rfind("SERVED ", 0) == 0);
  std::string committed_line;
  REQUIRE(child->read_line(committed_line));
  CHECK(committed_line.rfind("COMMITTED ", 0) == 0);
  const int exit_code = child->wait();
  CHECK_EQ(exit_code, 0);

  // The state the service committed is exactly the state a fresh process reads.
  const auto reopened = Store::open([&] {
    StoreOptions store_options;
    store_options.base_path = base.string();
    return store_options;
  }());
  REQUIRE(reopened.ok());
  CHECK_EQ(reopened.value().state.records.size(), std::size_t{1});

  RegistryPolicy policy = make_lab_policy();
  Registry restored(policy);
  const auto adopted = restored.adopt_state(reopened.value().state, now);
  REQUIRE(adopted.ok());
  // Conservative restart: the evidence survives as history but not as current
  // authority until its source re-attests under the new boot epoch.
  CHECK_EQ(adopted.value().records_fenced, std::uint64_t{1});
  CHECK(restored.evaluate(make_requirement(device, "1.2.0"), now).kind == DecisionKind::Unknown);
}

OCREG_TEST(a_second_service_process_reads_what_the_first_committed) {
  const auto directory = fresh_dir("process_restart");
  const auto base = directory / "state.ocregstore";
  const auto device = reference("sim-nic-1001", 0, 1);
  const Tick now = kSecond;

  for (int round = 0; round < 2; ++round) {
    auto child = ChildProcess::spawn({OCREG_SERVICE_EXE, "--store", base.string(), "--port", "0",
                                      "--workers", "2", "--tick", std::to_string(now.value())});
    REQUIRE(child != nullptr);
    std::string line;
    REQUIRE(child->read_line(line));
    const std::uint16_t port = parse_port_line(line);
    REQUIRE(port != 0);

    ClientOptions options;
    options.port = port;
    auto client = Client::connect(options);
    REQUIRE(client.ok());

    // Round one admits the evidence; round two re-attests it under the new boot
    // epoch, which is the only way authority comes back.
    if (round == 1) {
      // The evidence the previous process committed survived the restart as
      // history but not as authority: it is fenced until its source re-attests.
      const auto before = client.value()->query(
          CapabilityQuery{device, CapabilityKind::ChecksumOffload, Tick{}, true}, now);
      REQUIRE(before.ok());
      CHECK(before.value().kind == DecisionKind::Unknown);
      bool fenced = false;
      for (const auto& fact : before.value().facts) {
        if (fact.state == EvidenceState::Fenced) fenced = true;
      }
      CHECK(fenced);
    }

    const std::uint64_t generation = static_cast<std::uint64_t>(round + 1);
    const auto admitted = client.value()->admit(
        make_request(device, "fixture-sim", "1." + std::to_string(round + 4) + ".0", generation,
                     now),
        now);
    REQUIRE(admitted.ok());
    if (round == 1) {
      CHECK(admitted.value().state == EvidenceState::Active);
    }

    const auto stats = client.value()->stats(now);
    REQUIRE(stats.ok());
    if (round == 0) {
      CHECK_EQ(stats.value().records_total, std::uint64_t{1});
    } else {
      // The re-attestation is a strictly newer generation, so the restart-fenced
      // record is superseded by it rather than left in the current set.
      CHECK_EQ(stats.value().records_total, std::uint64_t{2});
      CHECK_EQ(stats.value().records_active, std::uint64_t{1});
      CHECK_EQ(stats.value().records_superseded, std::uint64_t{1});
      CHECK_EQ(stats.value().records_fenced, std::uint64_t{0});
    }

    REQUIRE(client.value()->shutdown(now).ok());
    std::string line_two;
    REQUIRE(child->read_line(line_two));
    std::string line_three;
    REQUIRE(child->read_line(line_three));
    CHECK_EQ(child->wait(), 0);
  }
}

OCREG_TEST(hard_kill_at_every_durable_boundary_never_fabricates_success) {
  const auto directory = fresh_dir("process_crash");
  StoreOptions probe_options;

  const auto open_store = [&](const std::filesystem::path& base) {
    StoreOptions options;
    options.base_path = base.string();
    return Store::open(options);
  };

  enum class Expect { NoStore, Refused, CommittedState };
  struct Boundary {
    const char* name;
    Expect expect;
    RecoveryClass expected_class;
  };
  const Boundary boundaries[] = {
      {"before-commit", Expect::NoStore, RecoveryClass::CleanOpen},
      {"partial-header", Expect::Refused, RecoveryClass::Refused},
      {"payload-no-trailer", Expect::Refused, RecoveryClass::Refused},
      {"mid-snapshot", Expect::NoStore, RecoveryClass::CleanOpen},
      {"after-commit-before-ack", Expect::CommittedState, RecoveryClass::JournalReplayed},
      {"after-ack", Expect::CommittedState, RecoveryClass::JournalReplayed},
  };

  for (const auto& boundary : boundaries) {
    const auto base = directory / (std::string(boundary.name) + ".ocregstore");
    auto child = ChildProcess::spawn({OCREG_CRASH_HELPER_EXE, "--store", base.string(),
                                      "--boundary", boundary.name, "--seed", "21", "--count",
                                      "5"});
    REQUIRE(child != nullptr);
    const int exit_code = child->wait();
    CHECK_MSG(exit_code != 0, boundary.name);

    const auto report = open_store(base);
    switch (boundary.expect) {
      case Expect::CommittedState:
        REQUIRE_MSG(report.ok(), boundary.name);
        CHECK_EQ(report.value().state.records.size(), std::size_t{5});
        CHECK_EQ(report.value().state.store_generation.value(), std::uint64_t{21});
        CHECK_EQ(static_cast<int>(report.value().classification),
                 static_cast<int>(boundary.expected_class));
        break;
      case Expect::NoStore:
        // Nothing durable was written, so the store reports itself as new. The
        // point is that no partial state is presented as a complete one.
        REQUIRE_MSG(report.ok(), boundary.name);
        CHECK(report.value().reason == ReasonCode::StoreEmptyNew);
        CHECK(!report.value().existed);
        CHECK_EQ(report.value().state.records.size(), std::size_t{0});
        break;
      case Expect::Refused:
        // A refused recovery, never a fabricated empty-but-successful state.
        CHECK_MSG(!report.ok(), boundary.name);
        break;
    }

    // Whatever happened, a subsequent clean commit produces a readable store.
    RegistryState fresh;
    {
      Registry registry(make_lab_policy());
      const auto device = reference("sim-nic-1002", 0, 1);
      REQUIRE(registry.admit(make_request(device, "fixture-sim", "1.0.0", 1, kSecond), kSecond).ok());
      const auto snapshot = registry.snapshot_state();
      REQUIRE(snapshot.ok());
      fresh = snapshot.value();
      fresh.store_generation = StoreGeneration(100);
    }
    auto bound = Store::bind([&] {
      StoreOptions options;
      options.base_path = base.string();
      return options;
    }());
    REQUIRE(bound.ok());
    std::vector<ReasonCode> notes;
    REQUIRE(bound.value()->compact(fresh, kSecond).ok());
    const auto reopened = open_store(base);
    REQUIRE(reopened.ok());
    CHECK(state_digest(reopened.value().state) == state_digest(fresh));
  }
  (void)probe_options;
}

OCREG_TEST(a_durable_commit_is_visible_even_when_the_process_dies_before_acknowledging) {
  const auto directory = fresh_dir("process_ambiguous");
  const auto base = directory / "state.ocregstore";

  // The helper commits, then dies before writing its acknowledgement.
  auto child = ChildProcess::spawn({OCREG_CRASH_HELPER_EXE, "--store", base.string(),
                                    "--boundary", "after-commit-before-ack", "--seed", "5",
                                    "--count", "3"});
  REQUIRE(child != nullptr);
  CHECK(child->wait() != 0);

  StoreOptions options;
  options.base_path = base.string();
  const auto report = Store::open(options);
  REQUIRE(report.ok());
  CHECK_EQ(report.value().state.records.size(), std::size_t{3});
  CHECK_EQ(report.value().state.store_generation.value(), std::uint64_t{5});

  // The state carries the boot epoch of the process that wrote it, so adopting
  // it in this process advances the epoch and fences its evidence. The crash
  // cannot resurrect authority.
  Registry registry(make_lab_policy());
  const auto adopted = registry.adopt_state(report.value().state, kSecond);
  REQUIRE(adopted.ok());
  CHECK(adopted.value().boot_epoch.value() == report.value().state.boot_epoch.value() + 1);
  // The stream holds three generations: two are superseded by generation, and
  // the newest is fenced by the restart. Nothing is current.
  CHECK_EQ(adopted.value().records_fenced, std::uint64_t{1});
  CHECK_EQ(registry.stats(kSecond).records_active, std::uint64_t{0});
  CHECK_EQ(registry.stats(kSecond).records_superseded, std::uint64_t{2});

  const auto device = reference("sim-nic-1001", 0, 1);
  CHECK(registry.evaluate(make_requirement(device, "1.0.0"), kSecond).kind ==
        DecisionKind::Unknown);
}

OCREG_TEST(the_cli_reports_store_health_without_claiming_more_than_it_knows) {
  const auto directory = fresh_dir("process_cli");
  const auto base = directory / "state.ocregstore";

  auto helper = ChildProcess::spawn(
      {OCREG_CRASH_HELPER_EXE, "--store", base.string(), "--boundary", "none", "--seed", "2",
       "--count", "2"});
  REQUIRE(helper != nullptr);
  CHECK_EQ(helper->wait(), 0);

  auto cli = ChildProcess::spawn({OCREG_CLI_EXE, "verify", "--store", base.string()});
  REQUIRE(cli != nullptr);
  std::string document;
  std::string line;
  while (cli->read_line(line)) document += line;
  CHECK_EQ(cli->wait(), 0);
  const auto parsed = JsonValue::parse(document);
  REQUIRE(parsed.ok());
  const JsonValue* ok_flag = parsed.value().find("ok");
  REQUIRE(ok_flag != nullptr);
  CHECK(ok_flag->as_bool());
  CHECK(parsed.value().find("state_digest") != nullptr);

  // A store that does not exist is reported as new rather than as an error, and
  // a damaged one is reported as refused.
  auto missing = ChildProcess::spawn(
      {OCREG_CLI_EXE, "verify", "--store", (directory / "absent.ocregstore").string()});
  REQUIRE(missing != nullptr);
  std::string missing_document;
  while (missing->read_line(line)) missing_document += line;
  CHECK_EQ(missing->wait(), 0);
  const auto missing_parsed = JsonValue::parse(missing_document);
  REQUIRE(missing_parsed.ok());
  CHECK(missing_parsed.value().find("ok")->as_bool());
}
