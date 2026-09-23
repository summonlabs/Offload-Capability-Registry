// Offload Capability Registry - protocol and in-process service tests.
// Copyright 2026 Summon Software Labs.
#include <array>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "net.hpp"
#include "ocreg/client.hpp"
#include "ocreg/json.hpp"
#include "ocreg/persist.hpp"
#include "ocreg/protocol.hpp"
#include "ocreg/registry.hpp"
#include "ocreg/service.hpp"
#include "registry_harness.hpp"
#include "test_support.hpp"

using namespace ocreg;
using namespace ocreg::test;

namespace {

[[nodiscard]] Frame request_frame(OpCode opcode, std::uint64_t request_id,
                                  const std::vector<std::uint8_t>& payload) {
  Frame frame;
  frame.header.opcode = opcode;
  frame.header.request_id = request_id;
  frame.payload = payload;
  return frame;
}

}  // namespace

OCREG_TEST(frame_headers_round_trip_and_reject_impossibilities) {
  FrameHeader header;
  header.opcode = OpCode::Query;
  header.request_id = 0x0123456789ABCDEFull;
  header.flags = static_cast<std::uint16_t>(FrameFlags::Response);
  std::array<std::uint8_t, kFrameHeaderSize> bytes{};
  REQUIRE(encode_frame_header(header, bytes));

  FrameHeader decoded;
  ReasonCode reason = ReasonCode::Ok;
  REQUIRE(decode_frame_header(bytes, decoded, reason));
  CHECK(decoded.opcode == OpCode::Query);
  CHECK_EQ(decoded.request_id, header.request_id);
  CHECK_EQ(decoded.flags, header.flags);

  {
    auto damaged = bytes;
    damaged[0] = 0;
    FrameHeader ignored;
    CHECK(!decode_frame_header(damaged, ignored, reason));
    CHECK(reason == ReasonCode::ProtocolFrameMalformed);
  }
  {
    auto damaged = bytes;
    damaged[8] = 0x7F;
    FrameHeader ignored;
    CHECK(!decode_frame_header(damaged, ignored, reason));
    CHECK(reason == ReasonCode::ProtocolChecksumMismatch);
  }
  {
    auto damaged = bytes;
    damaged[4] = 0;
    damaged[5] = 99;
    const std::span<const std::uint8_t> prefix(damaged.data(), kFrameHeaderSize - 4);
    const std::uint32_t crc = crc32c(prefix);
    damaged[kFrameHeaderSize - 4] = static_cast<std::uint8_t>((crc >> 24) & 0xFF);
    damaged[kFrameHeaderSize - 3] = static_cast<std::uint8_t>((crc >> 16) & 0xFF);
    damaged[kFrameHeaderSize - 2] = static_cast<std::uint8_t>((crc >> 8) & 0xFF);
    damaged[kFrameHeaderSize - 1] = static_cast<std::uint8_t>(crc & 0xFF);
    FrameHeader ignored;
    CHECK(!decode_frame_header(damaged, ignored, reason));
    CHECK(reason == ReasonCode::ProtocolVersionUnsupported);
  }
  {
    auto damaged = bytes;
    damaged[8] = 0xFF;
    damaged[9] = 0xFF;
    const std::span<const std::uint8_t> prefix(damaged.data(), kFrameHeaderSize - 4);
    const std::uint32_t crc = crc32c(prefix);
    damaged[kFrameHeaderSize - 4] = static_cast<std::uint8_t>((crc >> 24) & 0xFF);
    damaged[kFrameHeaderSize - 3] = static_cast<std::uint8_t>((crc >> 16) & 0xFF);
    damaged[kFrameHeaderSize - 2] = static_cast<std::uint8_t>((crc >> 8) & 0xFF);
    damaged[kFrameHeaderSize - 1] = static_cast<std::uint8_t>(crc & 0xFF);
    FrameHeader ignored;
    CHECK(!decode_frame_header(damaged, ignored, reason));
    CHECK(reason == ReasonCode::ProtocolUnknownOpcode);
  }
  {
    FrameHeader huge;
    huge.opcode = OpCode::Ping;
    huge.payload_len = static_cast<std::uint32_t>(kMaxFramePayload + 1);
    std::array<std::uint8_t, kFrameHeaderSize> ignored{};
    CHECK(!encode_frame_header(huge, ignored));
  }
  {
    FrameHeader reserved;
    reserved.opcode = OpCode::Ping;
    reserved.reserved = 7;
    std::array<std::uint8_t, kFrameHeaderSize> ignored{};
    CHECK(!encode_frame_header(reserved, ignored));
  }
}

OCREG_TEST(service_and_client_exchange_registry_answers) {
  RegistryPolicy policy = make_lab_policy();
  Registry registry(policy);
  ServerOptions options;
  options.max_workers = 4;
  Service service(registry, options);
  const auto started = service.start();
  REQUIRE(started.ok());
  CHECK(started.value() != 0);

  ClientOptions client_options;
  client_options.host = "127.0.0.1";
  client_options.port = started.value();
  auto client = Client::connect(client_options);
  REQUIRE(client.ok());
  const Tick now = kSecond;
  const auto pong = client.value()->ping(now);
  REQUIRE(pong.ok());
  CHECK(pong.value().value);
  const auto device = reference("sim-nic-900", 0, 1);
  const auto admitted =
      client.value()->admit(make_request(device, "fixture-sim", "1.4.0", 1, now), now);
  REQUIRE(admitted.ok());
  CHECK(admitted.value().state == EvidenceState::Active);

  // Duplicate delivery over the transport is idempotent, exactly as in-process.
  const auto duplicate =
      client.value()->admit(make_request(device, "fixture-sim", "1.4.0", 1, now), now);
  REQUIRE(duplicate.ok());
  CHECK(duplicate.value().idempotent);
  CHECK(duplicate.value().id == admitted.value().id);
  const auto queried = client.value()->query(
      CapabilityQuery{device, CapabilityKind::ChecksumOffload, Tick{}, true}, now);
  REQUIRE(queried.ok());
  CHECK(queried.value().kind == DecisionKind::Compatible);
  const auto evaluated = client.value()->evaluate(make_requirement(device, "1.0.0"), now);
  REQUIRE(evaluated.ok());
  CHECK(evaluated.value().kind == DecisionKind::Compatible);
  const auto explained = client.value()->explain(evaluated.value().id);
  REQUIRE(explained.ok());
  CHECK(explained.value().available);
  ExportOptions export_options;
  const auto exported = client.value()->export_state(export_options, now);
  REQUIRE(exported.ok());
  CHECK(!exported.value().document.empty());
  const auto ledger = client.value()->eviction_ledger(now);
  REQUIRE(ledger.ok());
  const auto remote_stats = client.value()->stats(now);
  REQUIRE(remote_stats.ok());
  CHECK(remote_stats.value().records_total == 1);
  // A transport refusal carries the registry's own reason code.
  AdmissionRequest unknown_source = make_request(device, "not-configured", "1.0.0", 2, now);
  const auto refused = client.value()->admit(unknown_source, now);
  CHECK(!refused.ok());
  CHECK(refused.reason() == ReasonCode::RejectedUnknownSource);

  CHECK_EQ(service.shutdown_requests(), std::uint64_t{0});
  const auto stopped = client.value()->shutdown(now);
  REQUIRE(stopped.ok());
  CHECK(service.shutdown_requested());
  service.stop();
  CHECK_EQ(service.shutdown_requests(), std::uint64_t{1});
  CHECK(service.requests_served() >= 8);
  CHECK(service.bytes_written() > 0);
}

OCREG_TEST(malformed_frames_are_rejected_and_accounted) {
  RegistryPolicy policy = make_lab_policy();
  Registry registry(policy);
  ServerOptions options;
  options.max_workers = 2;
  Service service(registry, options);
  const auto started = service.start();
  REQUIRE(started.ok());

  auto socket = net::connect_to("127.0.0.1", started.value());
  REQUIRE(socket.ok());

  // A frame whose header checksum does not match is refused and the connection
  // is closed after a single failure response.
  std::array<std::uint8_t, kFrameHeaderSize> header{};
  FrameHeader good;
  good.opcode = OpCode::Ping;
  good.request_id = 5;
  good.payload_len = 0;
  REQUIRE(encode_frame_header(good, header));
  header[8] = 0x11;
  REQUIRE(net::send_all(socket.value(), header));

  std::array<std::uint8_t, kFrameHeaderSize> reply_header{};
  REQUIRE(net::recv_exact(socket.value(), reply_header) == net::IoResult::Ok);
  FrameHeader decoded;
  ReasonCode reason = ReasonCode::Ok;
  REQUIRE(decode_frame_header(reply_header, decoded, reason));
  CHECK(decoded.flags & static_cast<std::uint16_t>(FrameFlags::Failure));
  // No field of a frame whose header checksum failed is trusted, so the reply
  // carries a zero request identifier rather than echoing corrupt data.
  CHECK_EQ(decoded.request_id, std::uint64_t{0});
  std::vector<std::uint8_t> payload(decoded.payload_len);
  if (!payload.empty()) {
    REQUIRE(net::recv_exact(socket.value(), payload) == net::IoResult::Ok);
  }
  Reader reader(std::span<const std::uint8_t>(payload.data(), payload.size()));
  ResponseEnvelope envelope;
  REQUIRE(decode(reader, envelope));
  CHECK(envelope.reason == ReasonCode::ProtocolChecksumMismatch);

  // The server closes the connection after a protocol violation.
  std::array<std::uint8_t, 1> trailing{};
  CHECK(net::recv_exact(socket.value(), trailing) != net::IoResult::Ok);
  net::close_socket(socket.value());

  // A well-formed frame whose payload digest does not match the payload is
  // refused as well.
  auto second = net::connect_to("127.0.0.1", started.value());
  REQUIRE(second.ok());
  Frame frame = request_frame(OpCode::Ping, 9, {1, 2, 3});
  std::vector<std::uint8_t> bytes = serialize_frame(frame);
  REQUIRE(bytes.size() > kFrameHeaderSize);
  bytes[kFrameHeaderSize] ^= 0xFF;
  REQUIRE(net::send_all(second.value(), bytes));
  REQUIRE(net::recv_exact(second.value(), reply_header) == net::IoResult::Ok);
  REQUIRE(decode_frame_header(reply_header, decoded, reason));
  CHECK(decoded.flags & static_cast<std::uint16_t>(FrameFlags::Failure));
  // Here the header is intact, so the request identifier is echoed.
  CHECK_EQ(decoded.request_id, std::uint64_t{9});
  std::vector<std::uint8_t> second_payload(decoded.payload_len);
  if (!second_payload.empty()) {
    REQUIRE(net::recv_exact(second.value(), second_payload) == net::IoResult::Ok);
  }
  Reader second_reader(std::span<const std::uint8_t>(second_payload.data(), second_payload.size()));
  ResponseEnvelope second_envelope;
  REQUIRE(decode(second_reader, second_envelope));
  CHECK(second_envelope.reason == ReasonCode::ProtocolChecksumMismatch);
  net::close_socket(second.value());

  service.stop();
  CHECK_EQ(service.frames_rejected(), std::uint64_t{2});
}

OCREG_TEST(the_service_survives_repeated_start_and_stop) {
  RegistryPolicy policy = make_lab_policy();
  Registry registry(policy);
  ServerOptions options;
  options.max_workers = 2;
  Service service(registry, options);

  for (int round = 0; round < 5; ++round) {
    const auto started = service.start();
    REQUIRE(started.ok());
    CHECK(service.running());

    ClientOptions client_options;
    client_options.port = started.value();
    auto client = Client::connect(client_options);
    REQUIRE(client.ok());
    const auto pong = client.value()->ping(kSecond);
    REQUIRE(pong.ok());
    CHECK(pong.value().value);
    service.stop();
    CHECK(!service.running());
    // Stopping twice is a no-op rather than an error.
    service.stop();
  }
  CHECK_EQ(service.requests_served(), std::uint64_t{5});
}

OCREG_TEST(connection_and_worker_bounds_are_enforced_and_reported) {
  RegistryPolicy policy = make_lab_policy();
  Registry registry(policy);
  ServerOptions options;
  options.max_connections = 1;
  options.max_workers = 1;
  options.max_queued_requests = 1;
  Service service(registry, options);
  const auto started = service.start();
  REQUIRE(started.ok());

  // Occupy the single connection slot and keep it busy.
  auto held = net::connect_to("127.0.0.1", started.value());
  REQUIRE(held.ok());
  const Frame frame = request_frame(OpCode::Ping, 1, {});
  const std::vector<std::uint8_t> bytes = serialize_frame(frame);
  REQUIRE(net::send_all(held.value(), bytes));
  std::array<std::uint8_t, kFrameHeaderSize> reply_header{};
  REQUIRE(net::recv_exact(held.value(), reply_header) == net::IoResult::Ok);
  FrameHeader decoded;
  ReasonCode reason = ReasonCode::Ok;
  REQUIRE(decode_frame_header(reply_header, decoded, reason));
  std::vector<std::uint8_t> payload(decoded.payload_len);
  if (!payload.empty()) {
    REQUIRE(net::recv_exact(held.value(), payload) == net::IoResult::Ok);
  }

  // The second connection is queued; the third is refused outright once the
  // queue is full, and the refusal is accounted for.
  auto queued = net::connect_to("127.0.0.1", started.value());
  REQUIRE(queued.ok());
  auto refused = net::connect_to("127.0.0.1", started.value());
  if (refused.ok()) {
    // The server accepts then immediately closes a refused connection.
    std::array<std::uint8_t, 1> probe{};
    CHECK(net::recv_exact(refused.value(), probe) != net::IoResult::Ok);
    net::close_socket(refused.value());
  }

  net::close_socket(queued.value());
  net::close_socket(held.value());
  service.stop();
  CHECK(service.connections_refused() >= 1);
  CHECK(service.connections_accepted() >= 1);
}
