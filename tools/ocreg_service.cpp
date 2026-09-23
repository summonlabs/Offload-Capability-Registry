// Offload Capability Registry - service executable.
// Copyright 2026 Summon Software Labs.
//
// Runs the registry as a process-local service over a loopback TCP socket.
// The process loads durable state, serves the framed protocol and commits a
// final durable snapshot before exiting. It never probes hardware, schedules
// work or programs a device.
#include <csignal>
#include <cstdint>
#include <iostream>
#include <string>

#include "ocreg/persist.hpp"
#include "ocreg/registry.hpp"
#include "ocreg/service.hpp"
#include "tool_support.hpp"

namespace {

ocreg::Service* g_service = nullptr;

void handle_signal(int) {
  if (g_service != nullptr) g_service->stop();
}

[[nodiscard]] ocreg::RegistryPolicy load_policy(const ocreg::tools::Arguments& arguments) {
  const auto path = arguments.get("policy");
  if (!path.has_value()) return ocreg::make_lab_policy();
  std::string document;
  if (!ocreg::tools::read_text_file(*path, document)) {
    std::cerr << "policy file could not be read: " << *path << '\n';
    return ocreg::make_lab_policy();
  }
  auto parsed = ocreg::parse_policy_document(document);
  if (!parsed.ok()) {
    std::cerr << "policy rejected: " << ocreg::to_string(parsed.reason()) << '\n';
    return ocreg::make_lab_policy();
  }
  return parsed.value();
}

}  // namespace

int main(int argc, char** argv) {
  const ocreg::tools::Arguments arguments = ocreg::tools::parse_arguments(argc, argv);
  if (arguments.command == "help" || arguments.command == "--help") {
    std::cout << "usage: ocreg_service --store PATH [--port N] [--bind ADDR] [--workers N]\n"
                 "                    [--connections N] [--policy FILE] [--tick N]\n"
                 "Prints 'PORT <n>' once listening and exits after a Shutdown request.\n";
    return 0;
  }

  const auto store_path = arguments.get("store");
  if (!store_path.has_value()) {
    std::cerr << "a --store path is required\n";
    return 2;
  }

  ocreg::RegistryPolicy policy = load_policy(arguments);
  ocreg::RegistryState state;
  bool state_loaded = false;
  {
    ocreg::StoreOptions options;
    options.base_path = *store_path;
    ocreg::RecoverySummary summary;
    auto loaded = ocreg::load_state(options, summary);
    if (loaded.ok()) {
      state = std::move(loaded.value());
      // A brand-new store carries no state to adopt; adopting it would replace
      // the configured policy with an empty one.
      const bool carries_state = !state.records.empty() || !state.incarnations.empty() ||
                                 !state.tombstones.empty() || !state.conflicts.empty() ||
                                 summary.classification == ocreg::RecoveryClass::JournalReplayed ||
                                 summary.classification == ocreg::RecoveryClass::TornTailTruncated ||
                                 summary.classification == ocreg::RecoveryClass::TrailingCorruptDropped;
      state_loaded = carries_state;
      if (state_loaded && !state.policy.sources.empty()) policy = state.policy;
    } else if (loaded.reason() != ocreg::ReasonCode::StoreEmptyNew) {
      std::cerr << "store rejected: " << ocreg::to_string(loaded.reason());
      if (!loaded.detail().empty()) std::cerr << ": " << loaded.detail();
      std::cerr << '\n';
      return 1;
    }
  }

  ocreg::Tick now{};
  {
    const auto tick_text = arguments.get("tick");
    if (tick_text.has_value()) {
      bool ok = false;
      const std::uint64_t value = ocreg::tools::parse_unsigned(*tick_text, ok);
      if (ok) now = ocreg::Tick{value};
    }
  }

  ocreg::Registry registry(policy);
  if (state_loaded) {
    auto adopted = registry.adopt_state(state, now);
    if (!adopted.ok()) {
      std::cerr << "state rejected: " << ocreg::to_string(adopted.reason()) << '\n';
      return 1;
    }
  }

  ocreg::ServerOptions options;
  options.bind_address = arguments.get_or("bind", "127.0.0.1");
  {
    const auto port_text = arguments.get("port");
    bool ok = !port_text.has_value();
    std::uint64_t port = 0;
    if (port_text.has_value()) port = ocreg::tools::parse_unsigned(*port_text, ok);
    if (!ok || port > 65535) {
      std::cerr << "port must be in 0..65535\n";
      return 2;
    }
    options.port = static_cast<std::uint16_t>(port);
  }
  const auto workers = arguments.get("workers");
  if (workers.has_value()) {
    bool ok = false;
    const std::uint64_t value = ocreg::tools::parse_unsigned(*workers, ok);
    if (ok && value > 0 && value <= 64) options.max_workers = static_cast<std::size_t>(value);
  }
  const auto connections = arguments.get("connections");
  if (connections.has_value()) {
    bool ok = false;
    const std::uint64_t value = ocreg::tools::parse_unsigned(*connections, ok);
    if (ok && value > 0 && value <= 4096) options.max_connections = static_cast<std::size_t>(value);
  }

  ocreg::Service service(registry, options);
  auto started = service.start();
  if (!started.ok()) {
    std::cerr << "service failed to start: " << ocreg::to_string(started.reason()) << '\n';
    return 1;
  }
  g_service = &service;
  (void)std::signal(SIGINT, handle_signal);
  (void)std::signal(SIGTERM, handle_signal);

  std::cout << "PORT " << started.value() << '\n' << std::flush;

  service.wait_for_shutdown();
  service.stop();
  g_service = nullptr;

  ocreg::RegistryState final_state;
  auto snapshot = registry.snapshot_state();
  if (!snapshot.ok()) {
    std::cerr << "final snapshot refused: " << ocreg::to_string(snapshot.reason()) << '\n';
    return 1;
  }
  final_state = std::move(snapshot.value());
  final_state.store_generation = ocreg::StoreGeneration(final_state.store_generation.value() + 1);

  ocreg::StoreOptions store_options;
  store_options.base_path = *store_path;
  auto bound = ocreg::Store::bind(store_options);
  if (!bound.ok()) {
    std::cerr << "store bind failed: " << ocreg::to_string(bound.reason()) << '\n';
    return 1;
  }
  std::vector<ocreg::ReasonCode> notes;
  auto committed = bound.value()->commit(final_state, now, notes);
  if (!committed.ok()) {
    std::cerr << "final commit failed: " << ocreg::to_string(committed.reason()) << '\n';
    return 1;
  }
  std::cout << "SERVED " << service.requests_served() << '\n';
  std::cout << "COMMITTED " << committed.value().payload_digest.hex() << '\n' << std::flush;
  return 0;
}
