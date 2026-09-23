// Offload Capability Registry - protocol client.
// Copyright 2026 Summon Software Labs.
#include "ocreg/client.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "net.hpp"
#include "ocreg/codec.hpp"

namespace ocreg {
namespace {

[[nodiscard]] Outcome<std::vector<std::uint8_t>> read_frame(net::Socket socket,
                                                            std::size_t max_payload,
                                                            const FrameHeader& request) {
  std::array<std::uint8_t, kFrameHeaderSize> header_bytes{};
  const net::IoResult header_result = net::recv_exact(socket, header_bytes);
  if (header_result == net::IoResult::Closed) {
    return Outcome<std::vector<std::uint8_t>>(
        Status::failure(ReasonCode::TransportClosed, "peer closed before replying"));
  }
  if (header_result == net::IoResult::Error) {
    return Outcome<std::vector<std::uint8_t>>(
        Status::failure(ReasonCode::TransportClosed, "header read failed"));
  }
  FrameHeader header;
  ReasonCode reason = ReasonCode::Ok;
  if (!decode_frame_header(header_bytes, header, reason)) {
    return Outcome<std::vector<std::uint8_t>>(Status::failure(reason, "response header rejected"));
  }
  if (!(header.flags & static_cast<std::uint16_t>(FrameFlags::Response))) {
    return Outcome<std::vector<std::uint8_t>>(
        Status::failure(ReasonCode::ProtocolSequenceViolation, "reply is not a response"));
  }
  if (header.request_id != request.request_id) {
    return Outcome<std::vector<std::uint8_t>>(
        Status::failure(ReasonCode::ProtocolSequenceViolation, "reply carries another request id"));
  }
  if (!(header.opcode == request.opcode)) {
    return Outcome<std::vector<std::uint8_t>>(
        Status::failure(ReasonCode::ProtocolSequenceViolation, "reply carries another opcode"));
  }
  if (header.payload_len > max_payload) {
    return Outcome<std::vector<std::uint8_t>>(
        Status::failure(ReasonCode::ProtocolFrameTooLarge, "reply payload exceeds the bound"));
  }
  std::vector<std::uint8_t> payload(header.payload_len);
  if (!payload.empty()) {
    const net::IoResult body_result = net::recv_exact(socket, payload);
    if (body_result != net::IoResult::Ok) {
      return Outcome<std::vector<std::uint8_t>>(
          Status::failure(ReasonCode::TransportClosed, "reply body could not be read"));
    }
  }
  if (!(Digest256::of(payload) == header.payload_digest)) {
    return Outcome<std::vector<std::uint8_t>>(
        Status::failure(ReasonCode::ProtocolChecksumMismatch, "reply payload digest mismatch"));
  }
  return Outcome<std::vector<std::uint8_t>>(std::move(payload));
}

}  // namespace

struct Client::Impl {
  net::Socket socket = net::kInvalidSocket;
  std::size_t max_frame_payload = kMaxFramePayload;
  std::uint64_t next_request_id = 1;
  std::mutex mutex{};
};

Client::Client(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

Client::~Client() {
  if (impl_ && impl_->socket != net::kInvalidSocket) {
    net::close_socket(impl_->socket);
    impl_->socket = net::kInvalidSocket;
  }
}

Outcome<std::unique_ptr<Client>> Client::connect(const ClientOptions& options) {
  net::ensure_initialised();
  if (options.port == 0) {
    return Outcome<std::unique_ptr<Client>>(
        Status::failure(ReasonCode::TransportUnavailable, "port must be non-zero"));
  }
  auto socket = net::connect_to(options.host, options.port);
  if (!socket.ok()) return Outcome<std::unique_ptr<Client>>(socket.status());
  auto impl = std::make_unique<Impl>();
  impl->socket = socket.value();
  impl->max_frame_payload = options.max_frame_payload;
  return Outcome<std::unique_ptr<Client>>(std::unique_ptr<Client>(new Client(std::move(impl))));
}

Outcome<std::vector<std::uint8_t>> Client::call(OpCode opcode,
                                                std::span<const std::uint8_t> payload) {
  if (!impl_ || impl_->socket == net::kInvalidSocket) {
    return Outcome<std::vector<std::uint8_t>>(
        Status::failure(ReasonCode::TransportClosed, "client is not connected"));
  }
  if (payload.size() > impl_->max_frame_payload) {
    return Outcome<std::vector<std::uint8_t>>(
        Status::failure(ReasonCode::ProtocolFrameTooLarge, "request payload exceeds the bound"));
  }
  // One request is in flight per client object at a time; the mutex makes a
  // shared client safe without interleaving frames on the stream.
  std::lock_guard<std::mutex> guard(impl_->mutex);

  Frame request;
  request.header.opcode = opcode;
  request.header.flags = 0;
  request.header.request_id = impl_->next_request_id++;
  request.payload.assign(payload.begin(), payload.end());

  const std::vector<std::uint8_t> bytes = serialize_frame(request);
  if (bytes.empty()) {
    return Outcome<std::vector<std::uint8_t>>(
        Status::failure(ReasonCode::ProtocolFrameMalformed, "request frame is not representable"));
  }
  if (!net::send_all(impl_->socket, bytes)) {
    return Outcome<std::vector<std::uint8_t>>(
        Status::failure(ReasonCode::TransportClosed, "request could not be sent"));
  }

  auto reply = read_frame(impl_->socket, impl_->max_frame_payload, request.header);
  if (!reply.ok()) return reply;

  Reader reader(std::span<const std::uint8_t>(reply.value().data(), reply.value().size()));
  ResponseEnvelope envelope;
  if (!decode(reader, envelope) || !reader.at_end()) {
    return Outcome<std::vector<std::uint8_t>>(Status::failure(
        reader.ok() ? ReasonCode::ProtocolFrameMalformed : reader.failure(),
        "response envelope rejected"));
  }
  if (is_failure(envelope.reason)) {
    return Outcome<std::vector<std::uint8_t>>(Status::failure(envelope.reason, envelope.detail));
  }
  return Outcome<std::vector<std::uint8_t>>(std::move(envelope.body));
}

namespace {

template <class T, class Fn>
[[nodiscard]] Outcome<T> decode_body(const Outcome<std::vector<std::uint8_t>>& body, Fn&& decode_fn,
                                     ReasonCode failure_reason) {
  if (!body.ok()) return Outcome<T>(body.status());
  Reader reader(std::span<const std::uint8_t>(body.value().data(), body.value().size()));
  T value{};
  if (!decode_fn(reader, value) || !reader.at_end()) {
    return Outcome<T>(Status::failure(reader.ok() ? failure_reason : reader.failure(),
                                      "response body rejected"));
  }
  return Outcome<T>(std::move(value));
}

template <class Request>
[[nodiscard]] std::vector<std::uint8_t> encode_request(const Request& request) {
  Writer writer;
  encode(writer, request);
  return writer.buffer();
}

}  // namespace

Outcome<BoolResponse> Client::ping(Tick now) {
  return decode_body<BoolResponse>(call(OpCode::Ping, encode_request(NowRequest{now})),
                                   [](Reader& r, BoolResponse& v) { return decode(r, v); },
                                   ReasonCode::ProtocolFrameMalformed);
}

Outcome<RegistryStats> Client::stats(Tick now) {
  return decode_body<RegistryStats>(call(OpCode::Stats, encode_request(NowRequest{now})),
                                    [](Reader& r, RegistryStats& v) { return decode(r, v); },
                                    ReasonCode::ProtocolFrameMalformed);
}

Outcome<AdmissionOutcome> Client::admit(const AdmissionRequest& request, Tick now) {
  (void)now;
  return decode_body<AdmissionOutcome>(call(OpCode::Admit, encode_request(request)),
                                       [](Reader& r, AdmissionOutcome& v) { return decode(r, v); },
                                       ReasonCode::ProtocolFrameMalformed);
}

Outcome<RetirementOutcome> Client::retire(const RetirementRequest& request, Tick now) {
  (void)now;
  return decode_body<RetirementOutcome>(call(OpCode::Retire, encode_request(request)),
                                        [](Reader& r, RetirementOutcome& v) { return decode(r, v); },
                                        ReasonCode::ProtocolFrameMalformed);
}

Outcome<QueryResult> Client::query(const CapabilityQuery& query, Tick now) {
  QueryRequest request;
  request.query = query;
  request.now = now;
  return decode_body<QueryResult>(call(OpCode::Query, encode_request(request)),
                                  [](Reader& r, QueryResult& v) { return decode(r, v); },
                                  ReasonCode::ProtocolFrameMalformed);
}

Outcome<CompatibilityDecision> Client::evaluate(const CapabilityRequirement& requirement, Tick now) {
  EvaluateRequest request;
  request.requirement = requirement;
  request.now = now;
  return decode_body<CompatibilityDecision>(call(OpCode::Evaluate, encode_request(request)),
                                            [](Reader& r, CompatibilityDecision& v) {
                                              return decode(r, v);
                                            },
                                            ReasonCode::ProtocolFrameMalformed);
}

Outcome<ExplanationResponse> Client::explain(const DecisionId& id) {
  ExplainRequest request;
  request.id = id;
  return decode_body<ExplanationResponse>(call(OpCode::Explain, encode_request(request)),
                                          [](Reader& r, ExplanationResponse& v) {
                                            if (!decode(r, v.explanation)) return false;
                                            v.available = true;
                                            v.reason = ReasonCode::Ok;
                                            return true;
                                          },
                                          ReasonCode::ProtocolFrameMalformed);
}

Outcome<ExportResponse> Client::export_state(const ExportOptions& options, Tick now) {
  ExportRequest request;
  request.options = options;
  request.now = now;
  return decode_body<ExportResponse>(call(OpCode::Export, encode_request(request)),
                                     [](Reader& r, ExportResponse& v) { return decode(r, v); },
                                     ReasonCode::ProtocolFrameMalformed);
}

Outcome<BoolResponse> Client::revoke_source(const SourceId& source, Tick now) {
  SourceRequest request;
  request.source = source;
  request.now = now;
  return decode_body<BoolResponse>(call(OpCode::RevokeSource, encode_request(request)),
                                   [](Reader& r, BoolResponse& v) { return decode(r, v); },
                                   ReasonCode::ProtocolFrameMalformed);
}

Outcome<BoolResponse> Client::restore_source(const SourceId& source, Tick now) {
  SourceRequest request;
  request.source = source;
  request.now = now;
  return decode_body<BoolResponse>(call(OpCode::RestoreSource, encode_request(request)),
                                   [](Reader& r, BoolResponse& v) { return decode(r, v); },
                                   ReasonCode::ProtocolFrameMalformed);
}

Outcome<BoolResponse> Client::set_source_authority(const SourceId& source, AuthorityRank authority,
                                                   Tick now) {
  AuthorityRequest request;
  request.source = source;
  request.authority = authority;
  request.now = now;
  return decode_body<BoolResponse>(call(OpCode::SetSourceAuthority, encode_request(request)),
                                   [](Reader& r, BoolResponse& v) { return decode(r, v); },
                                   ReasonCode::ProtocolFrameMalformed);
}

Outcome<SourcePolicy> Client::upsert_source_policy(const SourcePolicy& policy, Tick now) {
  SourcePolicyRequest request;
  request.policy = policy;
  request.now = now;
  return decode_body<SourcePolicy>(call(OpCode::UpsertSourcePolicy, encode_request(request)),
                                   [](Reader& r, SourcePolicy& v) { return decode(r, v); },
                                   ReasonCode::ProtocolFrameMalformed);
}

Outcome<IdResponse> Client::begin_device_incarnation(const DeviceIdentity& device, Tick now) {
  IncarnationRequest request;
  request.device = device;
  request.now = now;
  return decode_body<IdResponse>(call(OpCode::BeginDeviceIncarnation, encode_request(request)),
                                 [](Reader& r, IdResponse& v) { return decode(r, v); },
                                 ReasonCode::ProtocolFrameMalformed);
}

Outcome<IdResponse> Client::current_incarnation(const DeviceIdentity& device, Tick now) {
  IncarnationRequest request;
  request.device = device;
  request.now = now;
  return decode_body<IdResponse>(call(OpCode::CurrentIncarnation, encode_request(request)),
                                 [](Reader& r, IdResponse& v) { return decode(r, v); },
                                 ReasonCode::ProtocolFrameMalformed);
}

Outcome<ConflictResolution> Client::resolve_conflict(const ResolveConflictRequest& request) {
  return decode_body<ConflictResolution>(call(OpCode::ResolveConflict, encode_request(request)),
                                         [](Reader& r, ConflictResolution& v) {
                                           return decode(r, v);
                                         },
                                         ReasonCode::ProtocolFrameMalformed);
}

Outcome<EvictionLedgerResponse> Client::eviction_ledger(Tick now) {
  return decode_body<EvictionLedgerResponse>(
      call(OpCode::EvictionLedger, encode_request(NowRequest{now})),
      [](Reader& r, EvictionLedgerResponse& v) { return decode(r, v); },
      ReasonCode::ProtocolFrameMalformed);
}

Outcome<BoolResponse> Client::shutdown(Tick now) {
  return decode_body<BoolResponse>(call(OpCode::Shutdown, encode_request(NowRequest{now})),
                                   [](Reader& r, BoolResponse& v) { return decode(r, v); },
                                   ReasonCode::ProtocolFrameMalformed);
}

}  // namespace ocreg
