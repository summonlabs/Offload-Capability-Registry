// Offload Capability Registry - framed bounded wire protocol.
// Copyright 2026 Summon Software Labs.
//
// The transport is a length-prefixed request/response protocol over a stream
// socket. Every frame is bounded, version-tagged, request-tagged and carries
// both a payload digest and a header checksum, so a truncated, oversized,
// corrupted or replayed frame is rejected with a stable reason code.
//
// The protocol surface is deliberately thin: it transports registry requests
// and registry answers. It never schedules work, programs a device or grants
// authority of its own.
#ifndef OCREG_PROTOCOL_HPP
#define OCREG_PROTOCOL_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "ocreg/codec.hpp"
#include "ocreg/export.hpp"
#include "ocreg/hash.hpp"
#include "ocreg/outcome.hpp"
#include "ocreg/reason.hpp"
#include "ocreg/registry.hpp"
#include "ocreg/version.hpp"

namespace ocreg {

inline constexpr std::uint32_t kFrameMagic = 0x4F435046u;  // "OCPF"
inline constexpr std::size_t kFrameHeaderSize = 60;
inline constexpr std::size_t kMaxFramePayload = 4u * 1024u * 1024u;

// Stable numeric opcodes. Never renumbered.
enum class OpCode : std::uint16_t {
  Ping = 1,
  Stats = 2,
  Admit = 3,
  Retire = 4,
  Query = 5,
  Evaluate = 6,
  Explain = 7,
  Export = 8,
  RevokeSource = 9,
  RestoreSource = 10,
  SetSourceAuthority = 11,
  UpsertSourcePolicy = 12,
  BeginDeviceIncarnation = 13,
  CurrentIncarnation = 14,
  ResolveConflict = 15,
  EvictionLedger = 16,
  Snapshot = 17,
  Shutdown = 18,
};

[[nodiscard]] std::string_view to_string(OpCode code) noexcept;
[[nodiscard]] bool parse_opcode(std::string_view text, OpCode& out) noexcept;
[[nodiscard]] bool parse_opcode(std::uint16_t raw, OpCode& out) noexcept;

enum class FrameFlags : std::uint16_t {
  None = 0,
  Response = 1,
  Failure = 2,
  Final = 4,
};

struct FrameHeader {
  std::uint16_t version = static_cast<std::uint16_t>(kProtocolVersion);
  std::uint16_t flags = 0;
  OpCode opcode = OpCode::Ping;
  std::uint16_t reserved = 0;
  std::uint64_t request_id = 0;
  std::uint32_t payload_len = 0;
  Digest256 payload_digest{};
  std::uint32_t header_crc = 0;
};

// Serialises the header. Returns false when any field is out of range.
[[nodiscard]] bool encode_frame_header(const FrameHeader& header,
                                       std::span<std::uint8_t, kFrameHeaderSize> out) noexcept;
[[nodiscard]] bool decode_frame_header(std::span<const std::uint8_t, kFrameHeaderSize> in,
                                       FrameHeader& out, ReasonCode& reason) noexcept;

struct Frame {
  FrameHeader header{};
  std::vector<std::uint8_t> payload{};

  [[nodiscard]] bool is_response() const noexcept {
    return (header.flags & static_cast<std::uint16_t>(FrameFlags::Response)) != 0;
  }
  [[nodiscard]] bool is_failure() const noexcept {
    return (header.flags & static_cast<std::uint16_t>(FrameFlags::Failure)) != 0;
  }
};

struct ServerOptions {
  std::string bind_address = "127.0.0.1";
  std::uint16_t port = 0;  // 0 selects an ephemeral port reported by start()
  std::size_t max_connections = 16;
  std::size_t max_workers = 4;
  std::size_t max_frame_payload = kMaxFramePayload;
  std::size_t max_queued_requests = 256;
  std::size_t max_requests_per_connection = 0;  // 0 means unbounded
  std::size_t max_export_bytes = 32u * 1024u * 1024u;
  bool reuse_address = true;
};

struct ClientOptions {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;
  std::size_t max_frame_payload = kMaxFramePayload;
};

// --- Request/response payloads ---------------------------------------------

struct NowRequest {
  Tick now{};
};

struct QueryRequest {
  CapabilityQuery query{};
  Tick now{};
};

struct EvaluateRequest {
  CapabilityRequirement requirement{};
  Tick now{};
};

struct ExplainRequest {
  DecisionId id{};
};

struct ExportRequest {
  ExportOptions options{};
  Tick now{};
};

struct SourceRequest {
  SourceId source{};
  Tick now{};
};

struct AuthorityRequest {
  SourceId source{};
  AuthorityRank authority = AuthorityRank::None;
  Tick now{};
};

struct SourcePolicyRequest {
  SourcePolicy policy{};
  Tick now{};
};

struct IncarnationRequest {
  DeviceIdentity device{};
  Tick now{};
};

struct ResolveConflictRequest {
  ConflictId conflict{};
  EvidenceId chosen{};
  SourceId resolver{};
  Tick now{};
};

struct BoolResponse {
  bool value = false;
  ReasonCode reason = ReasonCode::Ok;
};

struct IdResponse {
  IncarnationId incarnation{};
  ReasonCode reason = ReasonCode::Ok;
};

struct ExportResponse {
  std::string document{};
  Digest256 digest{};
  bool truncated = false;
  std::vector<ReasonCode> notes{};
};

struct ExplanationResponse {
  Explanation explanation{};
  bool available = false;
  ReasonCode reason = ReasonCode::UnknownNoEvidence;
};

struct EvictionLedgerResponse {
  std::vector<EvictionEntry> entries{};
  bool truncated = false;
};

// A registry answer always travels inside this envelope. 'reason' is a failure
// code when the request itself could not be processed; otherwise it is the
// registry's own outcome code (which may be an explicit refusal such as
// AlreadyPresent or RejectedSupersededGeneration).
struct ResponseEnvelope {
  ReasonCode reason = ReasonCode::Ok;
  std::string detail{};
  std::vector<std::uint8_t> body{};
};

void encode(Writer& w, const ResponseEnvelope& value);
bool decode(Reader& r, ResponseEnvelope& value);

// Payload codecs.
void encode(Writer& w, const NowRequest& value);
bool decode(Reader& r, NowRequest& value);
void encode(Writer& w, const QueryRequest& value);
bool decode(Reader& r, QueryRequest& value);
void encode(Writer& w, const EvaluateRequest& value);
bool decode(Reader& r, EvaluateRequest& value);
void encode(Writer& w, const ExplainRequest& value);
bool decode(Reader& r, ExplainRequest& value);
void encode(Writer& w, const ExportRequest& value);
bool decode(Reader& r, ExportRequest& value);
void encode(Writer& w, const SourceRequest& value);
bool decode(Reader& r, SourceRequest& value);
void encode(Writer& w, const AuthorityRequest& value);
bool decode(Reader& r, AuthorityRequest& value);
void encode(Writer& w, const SourcePolicyRequest& value);
bool decode(Reader& r, SourcePolicyRequest& value);
void encode(Writer& w, const IncarnationRequest& value);
bool decode(Reader& r, IncarnationRequest& value);
void encode(Writer& w, const ResolveConflictRequest& value);
bool decode(Reader& r, ResolveConflictRequest& value);

void encode(Writer& w, const BoolResponse& value);
bool decode(Reader& r, BoolResponse& value);
void encode(Writer& w, const IdResponse& value);
bool decode(Reader& r, IdResponse& value);
void encode(Writer& w, const ExportResponse& value);
bool decode(Reader& r, ExportResponse& value);
void encode(Writer& w, const EvictionLedgerResponse& value);
bool decode(Reader& r, EvictionLedgerResponse& value);

void encode(Writer& w, const QueryResult& value);
bool decode(Reader& r, QueryResult& value);
void encode(Writer& w, const RegistryStats& value);
bool decode(Reader& r, RegistryStats& value);
void encode(Writer& w, const Explanation& value);
bool decode(Reader& r, Explanation& value);
void encode(Writer& w, const AdmissionOutcome& value);
bool decode(Reader& r, AdmissionOutcome& value);
void encode(Writer& w, const RetirementOutcome& value);
bool decode(Reader& r, RetirementOutcome& value);
void encode(Writer& w, const CompatibilityDecision& value);
bool decode(Reader& r, CompatibilityDecision& value);
void encode(Writer& w, const EvidenceStateFact& value);
bool decode(Reader& r, EvidenceStateFact& value);
void encode(Writer& w, const AdmissionRequest& value);
bool decode(Reader& r, AdmissionRequest& value);
void encode(Writer& w, const RetirementRequest& value);
bool decode(Reader& r, RetirementRequest& value);
void encode(Writer& w, const ConflictResolution& value);
bool decode(Reader& r, ConflictResolution& value);
void encode(Writer& w, const ConflictGroup& value);
bool decode(Reader& r, ConflictGroup& value);
void encode(Writer& w, const EvictionEntry& value);
bool decode(Reader& r, EvictionEntry& value);
void encode(Writer& w, const Status& value);
bool decode(Reader& r, Status& value);
void encode(Writer& w, const RuleGeneration& value);
bool decode(Reader& r, RuleGeneration& value);

// Serialises a complete frame (header plus payload). Returns an empty vector
// when the frame is not representable (for example an oversized payload).
[[nodiscard]] std::vector<std::uint8_t> serialize_frame(const Frame& frame);

}  // namespace ocreg

#endif  // OCREG_PROTOCOL_HPP
