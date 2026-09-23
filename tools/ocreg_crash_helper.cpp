// Offload Capability Registry - durable-boundary crash helper.
// Copyright 2026 Summon Software Labs.
//
// Performs a durable commit and then kills the process at a caller-selected
// boundary, without unwinding, flushing or closing anything. It exists only so
// that the recovery tests can exercise a real abrupt process death at a
// meaningful durable boundary rather than simulating one.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "ocreg/codec.hpp"
#include "ocreg/export.hpp"
#include "ocreg/json.hpp"
#include "ocreg/persist.hpp"
#include "ocreg/registry.hpp"
#include "tool_support.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

[[noreturn]] void hard_kill(int code) {
#if defined(_WIN32)
  (void)std::fflush(nullptr);
  ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(code));
  // TerminateProcess does not return for the calling thread.
  ::_exit(code);
#else
  ::_exit(code);
#endif
}

[[nodiscard]] ocreg::RegistryState build_state(std::uint64_t seed, std::size_t count) {
  ocreg::RegistryPolicy policy = ocreg::make_lab_policy();
  // Synthetic fixtures only. Nothing here describes real hardware.
  policy.default_max_age = ocreg::Tick{0};
  policy.retention_horizon = ocreg::Tick{0};
  ocreg::Registry registry(policy);

  ocreg::DeviceIdentity device;
  device.provider = *ocreg::ProviderId::parse("fixture-sim");
  device.model = *ocreg::DeviceModelId::parse("sim-nic-100");
  device.unit_index = 0;
  ocreg::DeviceIncarnationRef reference;
  reference.device = device;
  reference.incarnation = ocreg::IncarnationId(1);

  const ocreg::SourceId source = *ocreg::SourceId::parse("fixture-sim");
  for (std::size_t index = 0; index < count; ++index) {
    ocreg::AdmissionRequest request;
    request.device = reference;
    request.kind = ocreg::CapabilityKind::ChecksumOffload;
    request.source = ocreg::SourceIncarnation{source, ocreg::SourceIncarnationCounter(1)};
    request.capability_version = *ocreg::SemVer::parse("1." + std::to_string(index % 8) + ".0");
    request.features = ocreg::FeatureSet::from_validated(
        {ocreg::FeatureCode::ChecksumIpv4HeaderTx, ocreg::FeatureCode::ChecksumL4Tx});
    request.limits = ocreg::LimitSet::from_validated(
        {ocreg::LimitValue{ocreg::LimitCode::MaximumTransmissionUnit,
                           ocreg::unity(ocreg::UnitCode::Byte), 9000}});
    request.firmware_version = *ocreg::SemVer::parse("3.0.0");
    request.firmware_generation = ocreg::FirmwareGeneration(seed + index);
    request.observed_at = ocreg::Tick{1000 + index};
    request.generation = ocreg::RecordGeneration(index + 1);
    auto outcome = registry.admit(request, ocreg::Tick{1000 + count});
    if (!outcome.ok()) {
      std::fprintf(stderr, "synthetic admission refused: %s\n",
                   std::string(ocreg::to_string(outcome.reason())).c_str());
      std::exit(4);
    }
  }
  auto snapshot = registry.snapshot_state();
  if (!snapshot.ok()) {
    std::fprintf(stderr, "synthetic snapshot refused\n");
    std::exit(4);
  }
  ocreg::RegistryState state = std::move(snapshot.value());
  state.store_generation = ocreg::StoreGeneration(seed);
  return state;
}

}  // namespace

int main(int argc, char** argv) {
  const ocreg::tools::Arguments arguments = ocreg::tools::parse_arguments(argc, argv);
  const auto store_path = arguments.get("store");
  const auto boundary = arguments.get("boundary");
  if (!store_path.has_value() || !boundary.has_value()) {
    std::cerr << "usage: ocreg_crash_helper --store PATH --boundary B [--seed N] [--count N]\n"
                 "boundaries: none, before-commit, partial-header, payload-no-trailer,\n"
                 "            after-commit-before-ack, after-ack, mid-snapshot\n";
    return 2;
  }

  std::uint64_t seed = 1;
  std::size_t count = 4;
  {
    bool ok = false;
    const auto seed_text = arguments.get("seed");
    if (seed_text.has_value()) {
      const std::uint64_t value = ocreg::tools::parse_unsigned(*seed_text, ok);
      if (ok) seed = value;
    }
    const auto count_text = arguments.get("count");
    if (count_text.has_value()) {
      const std::uint64_t value = ocreg::tools::parse_unsigned(*count_text, ok);
      if (ok && value > 0 && value <= 4096) count = static_cast<std::size_t>(value);
    }
  }

  const std::string store = *store_path;
  const std::string where = *boundary;
  const std::string journal = store + ".ocregjournal";

  if (where == "none") {
    ocreg::RegistryState state = build_state(seed, count);
    ocreg::StoreOptions options;
    options.base_path = store;
    auto bound = ocreg::Store::bind(options);
    if (!bound.ok()) return 1;
    std::vector<ocreg::ReasonCode> notes;
    auto committed = bound.value()->commit(state, ocreg::Tick{0}, notes);
    if (!committed.ok()) return 1;
    std::cout << "COMMITTED " << committed.value().payload_digest.hex() << '\n' << std::flush;
    return 0;
  }

  if (where == "before-commit") {
    // The state is built but nothing durable is written.
    ocreg::RegistryState state = build_state(seed, count);
    (void)state;
    hard_kill(9);
  }

  if (where == "partial-header") {
    // Ten bytes of a journal header: shorter than any valid header, exactly
    // what a power loss in the middle of a header write leaves behind.
    std::FILE* file = std::fopen(journal.c_str(), "ab");
    if (file == nullptr) return 1;
    const unsigned char bytes[10] = {0x4F, 0x43, 0x4A, 0x52, 0x00, 0x01, 0x00, 0x01, 0, 0};
    (void)std::fwrite(bytes, 1, sizeof(bytes), file);
    (void)std::fflush(file);
    hard_kill(9);
  }

  if (where == "payload-no-trailer") {
    ocreg::RegistryState state = build_state(seed, count);
    ocreg::Writer writer;
    ocreg::encode(writer, state);
    std::FILE* file = std::fopen(journal.c_str(), "ab");
    if (file == nullptr) return 1;
    // A complete-looking header and payload, but the trailer never lands.
    std::vector<unsigned char> frame;
    frame.push_back(0x4F);
    frame.push_back(0x43);
    frame.push_back(0x4A);
    frame.push_back(0x52);
    frame.push_back(0x00);
    frame.push_back(0x01);
    frame.push_back(0x00);
    frame.push_back(0x01);
    for (int i = 0; i < 8; ++i) frame.push_back(0);  // sequence
    for (int i = 0; i < 8; ++i) frame.push_back(0);  // created_at
    for (int i = 0; i < 8; ++i) frame.push_back(0);  // store_generation
    const std::uint32_t length = static_cast<std::uint32_t>(writer.size());
    frame.push_back(static_cast<unsigned char>((length >> 24) & 0xFF));
    frame.push_back(static_cast<unsigned char>((length >> 16) & 0xFF));
    frame.push_back(static_cast<unsigned char>((length >> 8) & 0xFF));
    frame.push_back(static_cast<unsigned char>(length & 0xFF));
    for (int i = 0; i < 32; ++i) frame.push_back(0);
    for (int i = 0; i < 4; ++i) frame.push_back(0);
    (void)std::fwrite(frame.data(), 1, frame.size(), file);
    (void)std::fwrite(writer.buffer().data(), 1, writer.size(), file);
    (void)std::fflush(file);
    hard_kill(9);
  }

  if (where == "mid-snapshot") {
    ocreg::RegistryState state = build_state(seed, count);
    ocreg::Writer writer;
    ocreg::encode(writer, state);
    const std::string temporary = store + ".ocregtmp";
    std::FILE* file = std::fopen(temporary.c_str(), "wb");
    if (file == nullptr) return 1;
    const std::size_t partial = writer.size() / 2;
    (void)std::fwrite(writer.buffer().data(), 1, partial, file);
    (void)std::fflush(file);
    hard_kill(9);
  }

  if (where == "after-commit-before-ack" || where == "after-ack") {
    ocreg::RegistryState state = build_state(seed, count);
    ocreg::StoreOptions options;
    options.base_path = store;
    auto bound = ocreg::Store::bind(options);
    if (!bound.ok()) return 1;
    std::vector<ocreg::ReasonCode> notes;
    auto committed = bound.value()->commit(state, ocreg::Tick{0}, notes);
    if (!committed.ok()) return 1;
    if (where == "after-ack") {
      std::cout << "COMMITTED " << committed.value().payload_digest.hex() << '\n' << std::flush;
    }
    hard_kill(9);
  }

  std::cerr << "unknown boundary: " << where << '\n';
  return 2;
}
