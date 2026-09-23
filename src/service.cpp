// Offload Capability Registry - service surface.
// Copyright 2026 Summon Software Labs.
#include "ocreg/service.hpp"

#include <algorithm>
#include <array>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include "net.hpp"
#include "ocreg/codec.hpp"

namespace ocreg {
namespace {

[[nodiscard]] ResponseEnvelope failure_envelope(ReasonCode reason, std::string detail) {
  ResponseEnvelope envelope;
  envelope.reason = reason;
  envelope.detail = std::move(detail);
  return envelope;
}

template <class T, class EncodeFn>
[[nodiscard]] ResponseEnvelope success_envelope(ReasonCode reason, const T& value,
                                                EncodeFn&& encode_fn) {
  Writer writer;
  encode_fn(writer, value);
  ResponseEnvelope envelope;
  envelope.reason = reason;
  envelope.body = writer.buffer();
  return envelope;
}

}  // namespace

namespace {

// One accepted connection. Closing it is idempotent and is safe to perform from
// the stopping thread while a worker is blocked reading it: on every supported
// platform closing the handle cancels the pending read, which a half-close does
// not reliably do.
struct Connection {
  explicit Connection(net::Socket handle) : socket(handle) {}

  void close_once() {
    std::lock_guard<std::mutex> guard(mutex);
    if (closed) return;
    closed = true;
    net::shutdown_both(socket);
    net::close_socket(socket);
  }

  net::Socket socket = net::kInvalidSocket;
  std::mutex mutex{};
  bool closed = false;
};

}  // namespace

struct Service::Impl {
  Registry* registry = nullptr;
  ServerOptions options{};
  net::Socket listener = net::kInvalidSocket;
  std::uint16_t bound_port = 0;

  std::atomic<bool> running{false};
  std::atomic<bool> stopping{false};
  std::atomic<bool> shutdown_flag{false};

  std::thread acceptor{};
  std::vector<std::thread> workers{};

  std::mutex mutex{};
  std::condition_variable queue_ready{};
  std::condition_variable shutdown_ready{};
  std::deque<net::Socket> queue{};
  std::vector<std::shared_ptr<Connection>> active{};

  std::atomic<std::uint64_t> requests_served{0};
  std::atomic<std::uint64_t> connections_accepted{0};
  std::atomic<std::uint64_t> connections_refused{0};
  std::atomic<std::uint64_t> frames_rejected{0};
  std::atomic<std::uint64_t> bytes_read{0};
  std::atomic<std::uint64_t> bytes_written{0};
  std::atomic<std::uint64_t> shutdown_requests{0};

  [[nodiscard]] ResponseEnvelope dispatch(const FrameHeader& header,
                                          std::span<const std::uint8_t> payload);

  void serve_connection(const std::shared_ptr<Connection>& connection);
  void accept_loop();
  void worker_loop();
};

ResponseEnvelope Service::Impl::dispatch(const FrameHeader& header,
                                         std::span<const std::uint8_t> payload) {
  Reader reader(payload);
  switch (header.opcode) {
    case OpCode::Ping: {
      NowRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "ping payload rejected");
      }
      BoolResponse response;
      response.value = true;
      response.reason = ReasonCode::Ok;
      return success_envelope(ReasonCode::Ok, response,
                              [](Writer& w, const BoolResponse& v) { encode(w, v); });
    }
    case OpCode::Stats: {
      NowRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "stats payload rejected");
      }
      const RegistryStats result = registry->stats(request.now);
      return success_envelope(ReasonCode::Ok, result,
                              [](Writer& w, const RegistryStats& v) { encode(w, v); });
    }
    case OpCode::Admit: {
      AdmissionRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "admission payload rejected");
      }
      const Outcome<AdmissionOutcome> outcome = registry->admit(request, request.observed_at);
      if (!outcome.ok()) return failure_envelope(outcome.reason(), outcome.detail());
      return success_envelope(outcome.value().reason, outcome.value(),
                              [](Writer& w, const AdmissionOutcome& v) { encode(w, v); });
    }
    case OpCode::Retire: {
      RetirementRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "retirement payload rejected");
      }
      const Outcome<RetirementOutcome> outcome = registry->retire(request, request.retired_at);
      if (!outcome.ok()) return failure_envelope(outcome.reason(), outcome.detail());
      return success_envelope(outcome.value().reason, outcome.value(),
                              [](Writer& w, const RetirementOutcome& v) { encode(w, v); });
    }
    case OpCode::Query: {
      QueryRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "query payload rejected");
      }
      const Outcome<QueryResult> outcome = registry->query(request.query, request.now);
      if (!outcome.ok()) return failure_envelope(outcome.reason(), outcome.detail());
      BoolResponse unused{};
      (void)unused;
      return success_envelope(ReasonCode::Ok, outcome.value(),
                              [](Writer& w, const QueryResult& v) { encode(w, v); });
    }
    case OpCode::Evaluate: {
      EvaluateRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "evaluation payload rejected");
      }
      const CompatibilityDecision decision = registry->evaluate(request.requirement, request.now);
      return success_envelope(ReasonCode::Ok, decision,
                              [](Writer& w, const CompatibilityDecision& v) { encode(w, v); });
    }
    case OpCode::Explain: {
      ExplainRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "explain payload rejected");
      }
      const Outcome<Explanation> outcome = registry->explain(request.id);
      if (!outcome.ok()) return failure_envelope(outcome.reason(), outcome.detail());
      return success_envelope(ReasonCode::Ok, outcome.value(),
                              [](Writer& w, const Explanation& v) { encode(w, v); });
    }
    case OpCode::Export: {
      ExportRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "export payload rejected");
      }
      ExportOptions export_options = request.options;
      if (export_options.max_bytes == 0) export_options.max_bytes = kMaxFramePayload;
      const Outcome<ExportResult> outcome = export_registry(*registry, export_options, request.now);
      if (!outcome.ok()) return failure_envelope(outcome.reason(), outcome.detail());
      ExportResponse response;
      response.document = outcome.value().document;
      response.digest = outcome.value().digest;
      response.truncated = outcome.value().truncated;
      response.notes = outcome.value().notes;
      return success_envelope(ReasonCode::Ok, response,
                              [](Writer& w, const ExportResponse& v) { encode(w, v); });
    }
    case OpCode::RevokeSource: {
      SourceRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "revoke payload rejected");
      }
      const Outcome<bool> outcome = registry->revoke_source(request.source, request.now);
      if (!outcome.ok()) return failure_envelope(outcome.reason(), outcome.detail());
      BoolResponse response;
      response.value = outcome.value();
      response.reason = outcome.status().code;
      return success_envelope(ReasonCode::Ok, response,
                              [](Writer& w, const BoolResponse& v) { encode(w, v); });
    }
    case OpCode::RestoreSource: {
      SourceRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "restore payload rejected");
      }
      const Outcome<bool> outcome = registry->restore_source(request.source, request.now);
      if (!outcome.ok()) return failure_envelope(outcome.reason(), outcome.detail());
      BoolResponse response;
      response.value = outcome.value();
      response.reason = outcome.status().code;
      return success_envelope(ReasonCode::Ok, response,
                              [](Writer& w, const BoolResponse& v) { encode(w, v); });
    }
    case OpCode::SetSourceAuthority: {
      AuthorityRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "authority payload rejected");
      }
      const Outcome<bool> outcome =
          registry->set_source_authority(request.source, request.authority, request.now);
      if (!outcome.ok()) return failure_envelope(outcome.reason(), outcome.detail());
      BoolResponse response;
      response.value = outcome.value();
      response.reason = outcome.status().code;
      return success_envelope(ReasonCode::Ok, response,
                              [](Writer& w, const BoolResponse& v) { encode(w, v); });
    }
    case OpCode::UpsertSourcePolicy: {
      SourcePolicyRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "policy payload rejected");
      }
      const Outcome<SourcePolicy> outcome =
          registry->upsert_source_policy(request.policy, request.now);
      if (!outcome.ok()) return failure_envelope(outcome.reason(), outcome.detail());
      return success_envelope(ReasonCode::Ok, outcome.value(),
                              [](Writer& w, const SourcePolicy& v) { encode(w, v); });
    }
    case OpCode::BeginDeviceIncarnation: {
      IncarnationRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "incarnation payload rejected");
      }
      const Outcome<IncarnationId> outcome =
          registry->begin_device_incarnation(request.device, request.now);
      if (!outcome.ok()) return failure_envelope(outcome.reason(), outcome.detail());
      IdResponse response;
      response.incarnation = outcome.value();
      response.reason = ReasonCode::AcceptedNew;
      return success_envelope(ReasonCode::Ok, response,
                              [](Writer& w, const IdResponse& v) { encode(w, v); });
    }
    case OpCode::CurrentIncarnation: {
      IncarnationRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "incarnation payload rejected");
      }
      const Outcome<IncarnationId> outcome = registry->current_incarnation(request.device);
      if (!outcome.ok()) return failure_envelope(outcome.reason(), outcome.detail());
      IdResponse response;
      response.incarnation = outcome.value();
      response.reason = ReasonCode::Ok;
      return success_envelope(ReasonCode::Ok, response,
                              [](Writer& w, const IdResponse& v) { encode(w, v); });
    }
    case OpCode::ResolveConflict: {
      ResolveConflictRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "resolution payload rejected");
      }
      const Outcome<ConflictResolution> outcome = registry->resolve_conflict(
          request.conflict, request.chosen, request.resolver, request.now);
      if (!outcome.ok()) return failure_envelope(outcome.reason(), outcome.detail());
      return success_envelope(ReasonCode::Ok, outcome.value(),
                              [](Writer& w, const ConflictResolution& v) { encode(w, v); });
    }
    case OpCode::EvictionLedger: {
      NowRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "ledger payload rejected");
      }
      (void)request;
      EvictionLedgerResponse response;
      response.entries = registry->eviction_ledger();
      response.truncated = false;
      return success_envelope(ReasonCode::Ok, response,
                              [](Writer& w, const EvictionLedgerResponse& v) { encode(w, v); });
    }
    case OpCode::Snapshot: {
      NowRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "snapshot payload rejected");
      }
      (void)request;
      const Digest256 digest = registry->state_digest();
      Writer writer;
      writer.digest(digest);
      ResponseEnvelope envelope;
      envelope.reason = ReasonCode::Ok;
      envelope.body = writer.buffer();
      return envelope;
    }
    case OpCode::Shutdown: {
      NowRequest request;
      if (!decode(reader, request) || !reader.at_end()) {
        return failure_envelope(ReasonCode::ProtocolFrameMalformed, "shutdown payload rejected");
      }
      BoolResponse response;
      response.value = true;
      response.reason = ReasonCode::Ok;
      ResponseEnvelope envelope = success_envelope(
          ReasonCode::Ok, response, [](Writer& w, const BoolResponse& v) { encode(w, v); });
      shutdown_requests.fetch_add(1);
      // The flag that satisfies the wait predicate is stored while holding the
      // mutex that guards that predicate. Storing it without the lock would
      // allow a notification to be lost between the predicate check and the
      // wait.
      {
        std::lock_guard<std::mutex> guard(mutex);
        shutdown_flag.store(true);
      }
      shutdown_ready.notify_all();
      return envelope;
    }
  }
  return failure_envelope(ReasonCode::ProtocolUnknownOpcode, "unhandled opcode");
}

void Service::Impl::serve_connection(const std::shared_ptr<Connection>& connection) {
  const net::Socket socket = connection->socket;
  std::uint64_t served = 0;
  for (;;) {
    if (stopping.load()) break;
    std::array<std::uint8_t, kFrameHeaderSize> header_bytes{};
    const net::IoResult header_result = net::recv_exact(socket, header_bytes);
    if (header_result != net::IoResult::Ok) break;
    bytes_read.fetch_add(kFrameHeaderSize);

    FrameHeader header;
    ReasonCode reason = ReasonCode::Ok;
    if (!decode_frame_header(header_bytes, header, reason)) {
      frames_rejected.fetch_add(1);
      ResponseEnvelope envelope = failure_envelope(reason, "frame header rejected");
      Writer writer;
      encode(writer, envelope);
      Frame reply;
      reply.header.opcode = header.opcode;
      reply.header.request_id = header.request_id;
      reply.header.flags = static_cast<std::uint16_t>(FrameFlags::Response) |
                           static_cast<std::uint16_t>(FrameFlags::Failure) |
                           static_cast<std::uint16_t>(FrameFlags::Final);
      reply.payload = writer.buffer();
      const std::vector<std::uint8_t> bytes = serialize_frame(reply);
      (void)net::send_all(socket, bytes);
      break;
    }
    if (header.payload_len > options.max_frame_payload) {
      frames_rejected.fetch_add(1);
      break;
    }
    std::vector<std::uint8_t> payload(header.payload_len);
    if (!payload.empty()) {
      if (net::recv_exact(socket, payload) != net::IoResult::Ok) break;
      bytes_read.fetch_add(payload.size());
    }
    if (!(Digest256::of(payload) == header.payload_digest)) {
      frames_rejected.fetch_add(1);
      ResponseEnvelope envelope =
          failure_envelope(ReasonCode::ProtocolChecksumMismatch, "payload digest mismatch");
      Writer writer;
      encode(writer, envelope);
      Frame reply;
      reply.header.opcode = header.opcode;
      reply.header.request_id = header.request_id;
      reply.header.flags = static_cast<std::uint16_t>(FrameFlags::Response) |
                           static_cast<std::uint16_t>(FrameFlags::Failure) |
                           static_cast<std::uint16_t>(FrameFlags::Final);
      reply.payload = writer.buffer();
      const std::vector<std::uint8_t> bytes = serialize_frame(reply);
      (void)net::send_all(socket, bytes);
      break;
    }

    const ResponseEnvelope envelope = dispatch(header, payload);
    Writer writer;
    encode(writer, envelope);
    Frame reply;
    reply.header.opcode = header.opcode;
    reply.header.request_id = header.request_id;
    reply.header.flags = static_cast<std::uint16_t>(FrameFlags::Response) |
                         static_cast<std::uint16_t>(FrameFlags::Final);
    if (is_failure(envelope.reason)) {
      reply.header.flags |= static_cast<std::uint16_t>(FrameFlags::Failure);
    }
    reply.payload = writer.buffer();
    if (reply.payload.size() > options.max_frame_payload) {
      frames_rejected.fetch_add(1);
      ResponseEnvelope too_large =
          failure_envelope(ReasonCode::ProtocolFrameTooLarge, "response exceeds the frame bound");
      Writer fallback;
      encode(fallback, too_large);
      reply.payload = fallback.buffer();
      reply.header.flags |= static_cast<std::uint16_t>(FrameFlags::Failure);
    }
    const std::vector<std::uint8_t> bytes = serialize_frame(reply);
    if (!net::send_all(socket, bytes)) break;
    bytes_written.fetch_add(bytes.size());
    requests_served.fetch_add(1);
    ++served;
    if (options.max_requests_per_connection != 0 && served >= options.max_requests_per_connection) {
      break;
    }
  }
  connection->close_once();
  {
    std::lock_guard<std::mutex> guard(mutex);
    active.erase(std::remove(active.begin(), active.end(), connection), active.end());
  }
}

void Service::Impl::accept_loop() {
  for (;;) {
    auto accepted = net::accept_one(listener);
    if (!accepted.ok()) {
      if (stopping.load()) break;
      continue;
    }
    const net::Socket socket = accepted.value();
    if (stopping.load()) {
      net::close_socket(socket);
      break;
    }
    bool queued = false;
    {
      std::lock_guard<std::mutex> guard(mutex);
      if (active.size() + queue.size() < options.max_connections) {
        queue.push_back(socket);
        queued = true;
      }
    }
    if (queued) {
      connections_accepted.fetch_add(1);
      queue_ready.notify_one();
    } else {
      connections_refused.fetch_add(1);
      net::shutdown_both(socket);
      net::close_socket(socket);
    }
  }
}

void Service::Impl::worker_loop() {
  for (;;) {
    std::shared_ptr<Connection> connection;
    {
      std::unique_lock<std::mutex> lock(mutex);
      queue_ready.wait(lock, [this] { return stopping.load() || !queue.empty(); });
      if (queue.empty()) {
        if (stopping.load()) return;
        continue;
      }
      const net::Socket socket = queue.front();
      queue.pop_front();
      connection = std::make_shared<Connection>(socket);
      active.push_back(connection);
      if (stopping.load()) {
        active.erase(std::remove(active.begin(), active.end(), connection), active.end());
        lock.unlock();
        connection->close_once();
        return;
      }
    }
    serve_connection(connection);
    if (stopping.load() && queue.empty()) return;
  }
}

Service::Service(Registry& registry, ServerOptions options)
    : impl_(std::make_unique<Impl>()) {
  impl_->registry = &registry;
  impl_->options = std::move(options);
}

Service::~Service() { stop(); }

Outcome<std::uint16_t> Service::start() {
  if (impl_->running.load()) {
    return Outcome<std::uint16_t>(
        Status::failure(ReasonCode::AlreadyPresent, "service is already running"));
  }
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    impl_->stopping.store(false);
    impl_->shutdown_flag.store(false);
  }

  std::uint16_t bound_port = 0;
  auto listener = net::listen_on(impl_->options.bind_address, impl_->options.port,
                                 std::max<std::size_t>(impl_->options.max_connections, 8),
                                 impl_->options.reuse_address, bound_port);
  if (!listener.ok()) return Outcome<std::uint16_t>(listener.status());
  impl_->listener = listener.value();
  impl_->bound_port = bound_port;
  impl_->running.store(true);

  impl_->acceptor = std::thread([this] { impl_->accept_loop(); });
  const std::size_t worker_count = impl_->options.max_workers == 0 ? 1 : impl_->options.max_workers;
  impl_->workers.reserve(worker_count);
  for (std::size_t i = 0; i < worker_count; ++i) {
    impl_->workers.emplace_back([this] { impl_->worker_loop(); });
  }
  return Outcome<std::uint16_t>(bound_port);
}

void Service::wait_for_shutdown() {
  std::unique_lock<std::mutex> lock(impl_->mutex);
  impl_->shutdown_ready.wait(lock, [this] {
    return impl_->shutdown_flag.load() || impl_->stopping.load();
  });
}

bool Service::shutdown_requested() const noexcept { return impl_->shutdown_flag.load(); }

void Service::stop() {
  if (!impl_) return;
  {
    // The stop flag satisfies two wait predicates (the acceptor queue and the
    // shutdown barrier), so it is set under the mutex that guards them.
    std::lock_guard<std::mutex> guard(impl_->mutex);
    if (impl_->stopping.exchange(true)) {
      return;
    }
    impl_->running.store(false);
  }
  impl_->shutdown_ready.notify_all();
  impl_->queue_ready.notify_all();

  // Unblock the acceptor deterministically. Shutting the listener down is not
  // guaranteed to make a blocked accept() return on every platform, so the
  // service also connects to itself: whichever accept() observes that
  // connection sees the stop flag and leaves the loop. This is a real
  // synchronisation, not a poll and not a timeout.
  if (impl_->listener != net::kInvalidSocket) {
    const std::string address =
        impl_->options.bind_address.empty() ? std::string("127.0.0.1") : impl_->options.bind_address;
    auto wake = net::connect_to(address, impl_->bound_port);
    if (wake.ok()) net::close_socket(wake.value());
    net::shutdown_both(impl_->listener);
  }
  if (impl_->acceptor.joinable()) impl_->acceptor.join();
  if (impl_->listener != net::kInvalidSocket) {
    net::close_socket(impl_->listener);
    impl_->listener = net::kInvalidSocket;
  }

  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    // Closing, not half-closing: a worker blocked in a read is released by the
    // close. A half-close alone does not reliably release it everywhere.
    for (const auto& connection : impl_->active) connection->close_once();
    for (const auto socket : impl_->queue) {
      net::shutdown_both(socket);
      net::close_socket(socket);
    }
    impl_->queue.clear();
  }
  impl_->queue_ready.notify_all();
  for (auto& worker : impl_->workers) {
    if (worker.joinable()) worker.join();
  }
  impl_->workers.clear();
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    for (const auto& connection : impl_->active) connection->close_once();
    impl_->active.clear();
  }
}

bool Service::running() const noexcept { return impl_->running.load(); }
std::uint16_t Service::port() const noexcept { return impl_->bound_port; }
std::uint64_t Service::requests_served() const noexcept { return impl_->requests_served.load(); }
std::uint64_t Service::connections_accepted() const noexcept {
  return impl_->connections_accepted.load();
}
std::uint64_t Service::connections_refused() const noexcept {
  return impl_->connections_refused.load();
}
std::uint64_t Service::frames_rejected() const noexcept { return impl_->frames_rejected.load(); }
std::uint64_t Service::bytes_read() const noexcept { return impl_->bytes_read.load(); }
std::uint64_t Service::bytes_written() const noexcept { return impl_->bytes_written.load(); }
std::uint64_t Service::shutdown_requests() const noexcept {
  return impl_->shutdown_requests.load();
}

}  // namespace ocreg
