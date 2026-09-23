// Offload Capability Registry - framed bounded wire protocol.
// Copyright 2026 Summon Software Labs.
#include "ocreg/protocol.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ocreg {
namespace {

[[nodiscard]] bool opcode_from(std::uint16_t raw, OpCode& out) noexcept {
  if (raw < 1 || raw > static_cast<std::uint16_t>(OpCode::Shutdown)) return false;
  out = static_cast<OpCode>(raw);
  return true;
}

}  // namespace

std::string_view to_string(OpCode code) noexcept {
  switch (code) {
    case OpCode::Ping: return "ping";
    case OpCode::Stats: return "stats";
    case OpCode::Admit: return "admit";
    case OpCode::Retire: return "retire";
    case OpCode::Query: return "query";
    case OpCode::Evaluate: return "evaluate";
    case OpCode::Explain: return "explain";
    case OpCode::Export: return "export";
    case OpCode::RevokeSource: return "revoke_source";
    case OpCode::RestoreSource: return "restore_source";
    case OpCode::SetSourceAuthority: return "set_source_authority";
    case OpCode::UpsertSourcePolicy: return "upsert_source_policy";
    case OpCode::BeginDeviceIncarnation: return "begin_device_incarnation";
    case OpCode::CurrentIncarnation: return "current_incarnation";
    case OpCode::ResolveConflict: return "resolve_conflict";
    case OpCode::EvictionLedger: return "eviction_ledger";
    case OpCode::Snapshot: return "snapshot";
    case OpCode::Shutdown: return "shutdown";
  }
  return "ping";
}

bool parse_opcode(std::string_view text, OpCode& out) noexcept {
  for (std::uint16_t raw = 1; raw <= static_cast<std::uint16_t>(OpCode::Shutdown); ++raw) {
    const auto candidate = static_cast<OpCode>(raw);
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

bool parse_opcode(std::uint16_t raw, OpCode& out) noexcept { return opcode_from(raw, out); }

bool encode_frame_header(const FrameHeader& header,
                         std::span<std::uint8_t, kFrameHeaderSize> out) noexcept {
  if (header.payload_len > kMaxFramePayload) return false;
  if (header.reserved != 0) return false;
  OpCode verified{};
  if (!opcode_from(static_cast<std::uint16_t>(header.opcode), verified)) return false;
  if (!(verified == header.opcode)) return false;
  std::vector<std::uint8_t> buffer;
  buffer.reserve(kFrameHeaderSize);
  const auto put_u16 = [&buffer](std::uint16_t value) {
    buffer.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
    buffer.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  };
  const auto put_u32 = [&buffer](std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
      buffer.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
    }
  };
  const auto put_u64 = [&buffer](std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
      buffer.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
    }
  };
  put_u32(kFrameMagic);
  put_u16(header.version);
  put_u16(header.flags);
  put_u16(static_cast<std::uint16_t>(header.opcode));
  put_u16(0);
  put_u64(header.request_id);
  put_u32(header.payload_len);
  buffer.insert(buffer.end(), header.payload_digest.bytes().begin(),
                header.payload_digest.bytes().end());
  put_u32(crc32c(buffer));
  if (buffer.size() != kFrameHeaderSize) return false;
  for (std::size_t i = 0; i < kFrameHeaderSize; ++i) out[i] = buffer[i];
  return true;
}

bool decode_frame_header(std::span<const std::uint8_t, kFrameHeaderSize> in, FrameHeader& out,
                         ReasonCode& reason) noexcept {
  const auto get_u16 = [&in](std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(in[offset]) << 8) |
                                      static_cast<std::uint16_t>(in[offset + 1]));
  };
  const auto get_u32 = [&in](std::size_t offset) {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4; ++i) value = (value << 8) | static_cast<std::uint32_t>(in[offset + i]);
    return value;
  };
  const auto get_u64 = [&in](std::size_t offset) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) value = (value << 8) | static_cast<std::uint64_t>(in[offset + i]);
    return value;
  };
  if (get_u32(0) != kFrameMagic) {
    reason = ReasonCode::ProtocolFrameMalformed;
    return false;
  }
  const std::uint32_t stored_crc = get_u32(kFrameHeaderSize - 4);
  if (crc32c(std::span<const std::uint8_t>(in.data(), kFrameHeaderSize - 4)) != stored_crc) {
    reason = ReasonCode::ProtocolChecksumMismatch;
    return false;
  }
  if (get_u16(4) != static_cast<std::uint16_t>(kProtocolVersion)) {
    reason = ReasonCode::ProtocolVersionUnsupported;
    return false;
  }
  if (get_u16(10) != 0) {
    reason = ReasonCode::ProtocolFrameMalformed;
    return false;
  }
  OpCode opcode{};
  if (!opcode_from(get_u16(8), opcode)) {
    reason = ReasonCode::ProtocolUnknownOpcode;
    return false;
  }
  const std::uint32_t payload_len = get_u32(20);
  if (payload_len > kMaxFramePayload) {
    reason = ReasonCode::ProtocolFrameTooLarge;
    return false;
  }
  out.version = get_u16(4);
  out.flags = get_u16(6);
  out.opcode = opcode;
  out.reserved = get_u16(10);
  out.request_id = get_u64(12);
  out.payload_len = payload_len;
  std::array<std::uint8_t, kDigestBytes> digest_bytes{};
  for (std::size_t i = 0; i < kDigestBytes; ++i) digest_bytes[i] = in[24 + i];
  out.payload_digest = Digest256(digest_bytes);
  out.header_crc = stored_crc;
  reason = ReasonCode::Ok;
  return true;
}

std::vector<std::uint8_t> serialize_frame(const Frame& frame) {
  std::vector<std::uint8_t> bytes(kFrameHeaderSize, 0);
  FrameHeader header = frame.header;
  header.payload_len = static_cast<std::uint32_t>(frame.payload.size());
  header.payload_digest = Digest256::of(frame.payload);
  if (!encode_frame_header(header, std::span<std::uint8_t, kFrameHeaderSize>(bytes.data(),
                                                                            kFrameHeaderSize))) {
    return {};
  }
  bytes.insert(bytes.end(), frame.payload.begin(), frame.payload.end());
  return bytes;
}

// --- Envelope and payload codecs --------------------------------------------

void encode(Writer& w, const ResponseEnvelope& value) {
  w.reason(value.reason);
  w.str(value.detail);
  w.u32(static_cast<std::uint32_t>(value.body.size()));
  for (const auto byte : value.body) w.u8(byte);
}

bool decode(Reader& r, ResponseEnvelope& value) {
  if (!r.reason(value.reason)) return false;
  const std::string_view detail = r.bytes();
  if (!r.ok()) return false;
  if (detail.size() > 4096) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.detail.assign(detail);
  const std::uint32_t length = r.u32();
  if (!r.ok()) return false;
  if (length > kMaxFramePayload) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.body.clear();
  value.body.reserve(length);
  for (std::uint32_t i = 0; i < length; ++i) {
    const std::uint8_t byte = r.u8();
    if (!r.ok()) return false;
    value.body.push_back(byte);
  }
  return true;
}

void encode(Writer& w, const NowRequest& value) { w.strong(value.now); }
bool decode(Reader& r, NowRequest& value) { return r.strong(value.now); }

void encode(Writer& w, const QueryRequest& value) {
  encode(w, value.query.device);
  encode(w, value.query.kind);
  w.strong(value.query.max_evidence_age);
  w.boolean(value.query.include_history);
  w.strong(value.now);
}
bool decode(Reader& r, QueryRequest& value) {
  if (!decode(r, value.query.device)) return false;
  if (!decode(r, value.query.kind)) return false;
  if (!r.strong(value.query.max_evidence_age)) return false;
  value.query.include_history = r.boolean();
  if (!r.ok()) return false;
  return r.strong(value.now);
}

void encode(Writer& w, const EvaluateRequest& value) {
  encode(w, value.requirement);
  w.strong(value.now);
}
bool decode(Reader& r, EvaluateRequest& value) {
  if (!decode(r, value.requirement)) return false;
  return r.strong(value.now);
}

void encode(Writer& w, const ExplainRequest& value) { encode(w, value.id); }
bool decode(Reader& r, ExplainRequest& value) { return decode(r, value.id); }

void encode(Writer& w, const ExportRequest& value) {
  w.boolean(value.options.include_history);
  w.boolean(value.options.include_rejected);
  w.boolean(value.options.include_evictions);
  w.boolean(value.options.include_policy);
  w.boolean(value.options.pretty);
  w.u64(value.options.max_records);
  w.u64(value.options.max_bytes);
  w.strong(value.now);
}
bool decode(Reader& r, ExportRequest& value) {
  value.options.include_history = r.boolean();
  value.options.include_rejected = r.boolean();
  value.options.include_evictions = r.boolean();
  value.options.include_policy = r.boolean();
  value.options.pretty = r.boolean();
  if (!r.ok()) return false;
  const std::uint64_t max_records = r.u64();
  const std::uint64_t max_bytes = r.u64();
  if (!r.ok()) return false;
  std::size_t narrowed = 0;
  if (!checked_narrow<std::size_t, std::uint64_t>(max_records, narrowed)) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.options.max_records = narrowed;
  if (!checked_narrow<std::size_t, std::uint64_t>(max_bytes, narrowed)) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.options.max_bytes = narrowed;
  return r.strong(value.now);
}

void encode(Writer& w, const SourceRequest& value) {
  w.name_id(value.source);
  w.strong(value.now);
}
bool decode(Reader& r, SourceRequest& value) {
  if (!r.name_id(value.source)) return false;
  return r.strong(value.now);
}

void encode(Writer& w, const AuthorityRequest& value) {
  w.name_id(value.source);
  w.u16(static_cast<std::uint16_t>(value.authority));
  w.strong(value.now);
}
bool decode(Reader& r, AuthorityRequest& value) {
  if (!r.name_id(value.source)) return false;
  const std::uint16_t raw = r.u16();
  if (!r.ok()) return false;
  if (raw > static_cast<std::uint16_t>(AuthorityRank::Operator)) {
    r.fail(ReasonCode::RejectedMalformedDocument);
    return false;
  }
  value.authority = static_cast<AuthorityRank>(raw);
  return r.strong(value.now);
}

void encode(Writer& w, const SourcePolicyRequest& value) {
  encode(w, value.policy);
  w.strong(value.now);
}
bool decode(Reader& r, SourcePolicyRequest& value) {
  if (!decode(r, value.policy)) return false;
  return r.strong(value.now);
}

void encode(Writer& w, const IncarnationRequest& value) {
  encode(w, value.device);
  w.strong(value.now);
}
bool decode(Reader& r, IncarnationRequest& value) {
  if (!decode(r, value.device)) return false;
  return r.strong(value.now);
}

void encode(Writer& w, const ResolveConflictRequest& value) {
  encode(w, value.conflict);
  encode(w, value.chosen);
  w.name_id(value.resolver);
  w.strong(value.now);
}
bool decode(Reader& r, ResolveConflictRequest& value) {
  if (!decode(r, value.conflict)) return false;
  if (!decode(r, value.chosen)) return false;
  if (!r.name_id(value.resolver)) return false;
  return r.strong(value.now);
}

void encode(Writer& w, const BoolResponse& value) {
  w.boolean(value.value);
  w.reason(value.reason);
}
bool decode(Reader& r, BoolResponse& value) {
  value.value = r.boolean();
  if (!r.ok()) return false;
  return r.reason(value.reason);
}

void encode(Writer& w, const IdResponse& value) {
  w.strong(value.incarnation);
  w.reason(value.reason);
}
bool decode(Reader& r, IdResponse& value) {
  if (!r.strong(value.incarnation)) return false;
  return r.reason(value.reason);
}

void encode(Writer& w, const ExportResponse& value) {
  w.str(value.document);
  w.digest(value.digest);
  w.boolean(value.truncated);
  w.u32(static_cast<std::uint32_t>(value.notes.size()));
  for (const auto reason : value.notes) w.reason(reason);
}
bool decode(Reader& r, ExportResponse& value) {
  const std::string_view document = r.bytes();
  if (!r.ok()) return false;
  if (document.size() > kMaxFramePayload) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.document.assign(document);
  if (!r.digest(value.digest)) return false;
  value.truncated = r.boolean();
  if (!r.ok()) return false;
  const std::uint32_t count = r.u32();
  if (!r.ok()) return false;
  if (count > 64) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.notes.clear();
  for (std::uint32_t i = 0; i < count; ++i) {
    ReasonCode reason{};
    if (!r.reason(reason)) return false;
    value.notes.push_back(reason);
  }
  return true;
}

void encode(Writer& w, const EvictionLedgerResponse& value) {
  w.boolean(value.truncated);
  w.u32(static_cast<std::uint32_t>(value.entries.size()));
  for (const auto& entry : value.entries) encode(w, entry);
}
bool decode(Reader& r, EvictionLedgerResponse& value) {
  value.truncated = r.boolean();
  if (!r.ok()) return false;
  const std::uint32_t count = r.u32();
  if (!r.ok()) return false;
  if (count > 1048576u) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.entries.clear();
  value.entries.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!decode(r, value.entries[i])) return false;
  }
  return true;
}

void encode(Writer& w, const QueryResult& value) {
  w.u16(static_cast<std::uint16_t>(value.kind));
  encode(w, value.device);
  encode(w, value.kind_requested);
  w.u32(static_cast<std::uint32_t>(value.reasons.size()));
  for (const auto reason : value.reasons) w.reason(reason);
  w.u32(static_cast<std::uint32_t>(value.facts.size()));
  for (const auto& fact : value.facts) encode(w, fact);
  w.optional(value.selected, [&w](const EvidenceId& id) { encode(w, id); });
  w.optional(value.conflict, [&w](const ConflictId& id) { encode(w, id); });
  encode(w, value.rule_generation);
  w.strong(value.registry_epoch);
  w.strong(value.policy_revision);
  w.strong(value.evaluated_at);
}

bool decode(Reader& r, QueryResult& value) {
  const std::uint16_t kind = r.u16();
  if (!r.ok()) return false;
  if (kind < 1 || kind > 4) {
    r.fail(ReasonCode::RejectedMalformedDocument);
    return false;
  }
  value.kind = static_cast<DecisionKind>(kind);
  if (!decode(r, value.device)) return false;
  if (!decode(r, value.kind_requested)) return false;
  const std::uint32_t reason_count = r.u32();
  if (!r.ok()) return false;
  if (reason_count > 4096u) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.reasons.clear();
  value.reasons.resize(reason_count);
  for (std::uint32_t i = 0; i < reason_count; ++i) {
    if (!r.reason(value.reasons[i])) return false;
  }
  canonicalize_reasons(value.reasons);
  const std::uint32_t fact_count = r.u32();
  if (!r.ok()) return false;
  if (fact_count > 1048576u) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.facts.clear();
  value.facts.resize(fact_count);
  for (std::uint32_t i = 0; i < fact_count; ++i) {
    if (!decode(r, value.facts[i])) return false;
  }
  if (!r.optional(value.selected, [&r](EvidenceId& id) { return decode(r, id); })) return false;
  if (!r.optional(value.conflict, [&r](ConflictId& id) { return decode(r, id); })) return false;
  if (!decode(r, value.rule_generation)) return false;
  if (!r.strong(value.registry_epoch)) return false;
  if (!r.strong(value.policy_revision)) return false;
  return r.strong(value.evaluated_at);
}

void encode(Writer& w, const RegistryStats& value) {
  const std::uint64_t fields[] = {
      value.devices,           value.incarnations,        value.streams,
      value.records_total,     value.records_active,      value.records_superseded,
      value.records_retired,   value.records_rejected,    value.records_fenced,
      value.records_stale,     value.records_outranked,   value.records_evicted,
      value.conflicts_open,    value.conflicts_resolved,  value.tombstones,
      value.resolutions,       value.eviction_ledger_dropped, value.conflicts_dropped,
      value.resolutions_dropped, value.tombstones_dropped,
      value.decisions_emitted, value.decisions_evicted,   value.admissions_accepted,
      value.admissions_idempotent, value.admissions_rejected, value.retirements_accepted,
      value.retirements_rejected};
  for (const auto field : fields) w.u64(field);
  encode(w, value.registry_epoch);
  encode(w, value.rule_generation);
  w.strong(value.policy_revision);
  w.strong(value.boot_epoch);
  w.strong(value.logical_tick);
}

bool decode(Reader& r, RegistryStats& value) {
  std::uint64_t* fields[] = {
      &value.devices,           &value.incarnations,        &value.streams,
      &value.records_total,     &value.records_active,      &value.records_superseded,
      &value.records_retired,   &value.records_rejected,    &value.records_fenced,
      &value.records_stale,     &value.records_outranked,   &value.records_evicted,
      &value.conflicts_open,    &value.conflicts_resolved,  &value.tombstones,
      &value.resolutions,       &value.eviction_ledger_dropped, &value.conflicts_dropped,
      &value.resolutions_dropped, &value.tombstones_dropped,
      &value.decisions_emitted, &value.decisions_evicted,   &value.admissions_accepted,
      &value.admissions_idempotent, &value.admissions_rejected, &value.retirements_accepted,
      &value.retirements_rejected};
  for (auto* field : fields) {
    *field = r.u64();
    if (!r.ok()) return false;
  }
  if (!decode(r, value.registry_epoch)) return false;
  if (!decode(r, value.rule_generation)) return false;
  if (!r.strong(value.policy_revision)) return false;
  if (!r.strong(value.boot_epoch)) return false;
  return r.strong(value.logical_tick);
}

void encode(Writer& w, const Explanation& value) {
  encode(w, value.decision);
  w.boolean(value.decision_available);
  w.reason(value.reason);
  w.u32(static_cast<std::uint32_t>(value.involved_sources.size()));
  for (const auto& source : value.involved_sources) encode(w, source);
  w.optional(value.conflict, [&w](const ConflictGroup& group) { encode(w, group); });
  w.optional(value.resolution,
             [&w](const ConflictResolution& resolution) { encode(w, resolution); });
}

bool decode(Reader& r, Explanation& value) {
  if (!decode(r, value.decision)) return false;
  value.decision_available = r.boolean();
  if (!r.ok()) return false;
  if (!r.reason(value.reason)) return false;
  const std::uint32_t count = r.u32();
  if (!r.ok()) return false;
  if (count > 4096u) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.involved_sources.clear();
  value.involved_sources.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!decode(r, value.involved_sources[i])) return false;
  }
  if (!r.optional(value.conflict, [&r](ConflictGroup& group) { return decode(r, group); })) {
    return false;
  }
  return r.optional(value.resolution,
                    [&r](ConflictResolution& resolution) { return decode(r, resolution); });
}

void encode(Writer& w, const AdmissionOutcome& value) {
  encode(w, value.id);
  w.u16(static_cast<std::uint16_t>(value.state));
  w.reason(value.reason);
  w.boolean(value.idempotent);
  w.u32(static_cast<std::uint32_t>(value.superseded.size()));
  for (const auto& id : value.superseded) encode(w, id);
  w.u32(static_cast<std::uint32_t>(value.evicted.size()));
  for (const auto& id : value.evicted) encode(w, id);
  w.optional(value.conflict, [&w](const ConflictId& id) { encode(w, id); });
  encode(w, value.stream_generation);
  w.u64(value.conflicts_opened);
}

bool decode(Reader& r, AdmissionOutcome& value) {
  if (!decode(r, value.id)) return false;
  const std::uint16_t state = r.u16();
  if (!r.ok()) return false;
  if (state < 1 || state > 8) {
    r.fail(ReasonCode::RejectedMalformedDocument);
    return false;
  }
  value.state = static_cast<EvidenceState>(state);
  if (!r.reason(value.reason)) return false;
  value.idempotent = r.boolean();
  if (!r.ok()) return false;
  const auto read_ids = [&r](std::vector<EvidenceId>& target) {
    const std::uint32_t count = r.u32();
    if (!r.ok()) return false;
    if (count > 1048576u) {
      r.fail(ReasonCode::RejectedOversizedInput);
      return false;
    }
    target.clear();
    target.resize(count);
    for (std::uint32_t i = 0; i < count; ++i) {
      if (!decode(r, target[i])) return false;
    }
    return true;
  };
  if (!read_ids(value.superseded)) return false;
  if (!read_ids(value.evicted)) return false;
  if (!r.optional(value.conflict, [&r](ConflictId& id) { return decode(r, id); })) return false;
  if (!decode(r, value.stream_generation)) return false;
  value.conflicts_opened = r.u64();
  return r.ok();
}

void encode(Writer& w, const RetirementOutcome& value) {
  encode(w, value.key);
  encode(w, value.generation);
  w.reason(value.reason);
  w.boolean(value.idempotent);
  w.u32(static_cast<std::uint32_t>(value.retired.size()));
  for (const auto& id : value.retired) encode(w, id);
  w.u32(static_cast<std::uint32_t>(value.evicted.size()));
  for (const auto& id : value.evicted) encode(w, id);
}

bool decode(Reader& r, RetirementOutcome& value) {
  if (!decode(r, value.key)) return false;
  if (!decode(r, value.generation)) return false;
  if (!r.reason(value.reason)) return false;
  value.idempotent = r.boolean();
  if (!r.ok()) return false;
  const auto read_ids = [&r](std::vector<EvidenceId>& target) {
    const std::uint32_t count = r.u32();
    if (!r.ok()) return false;
    if (count > 1048576u) {
      r.fail(ReasonCode::RejectedOversizedInput);
      return false;
    }
    target.clear();
    target.resize(count);
    for (std::uint32_t i = 0; i < count; ++i) {
      if (!decode(r, target[i])) return false;
    }
    return true;
  };
  if (!read_ids(value.retired)) return false;
  return read_ids(value.evicted);
}

void encode(Writer& w, const EvidenceStateFact& value) {
  encode(w, value.id);
  w.u16(static_cast<std::uint16_t>(value.lifecycle));
  w.u16(static_cast<std::uint16_t>(value.state));
  w.reason(value.reason);
  w.strong(value.observed_at);
  w.strong(value.age);
  w.u16(static_cast<std::uint16_t>(value.authority));
  encode(w, value.generation);
  encode(w, value.source_incarnation);
  encode(w, value.capability_version);
  encode(w, value.features);
  encode(w, value.limits);
  w.optional(value.firmware_version, [&w](const SemVer& version) { encode(w, version); });
  w.optional(value.runtime_version, [&w](const SemVer& version) { encode(w, version); });
}

bool decode(Reader& r, EvidenceStateFact& value) {
  if (!decode(r, value.id)) return false;
  const std::uint16_t lifecycle = r.u16();
  const std::uint16_t state = r.u16();
  if (!r.ok()) return false;
  if (lifecycle < 1 || lifecycle > 3 || state < 1 || state > 8) {
    r.fail(ReasonCode::RejectedMalformedDocument);
    return false;
  }
  value.lifecycle = static_cast<EvidenceLifecycle>(lifecycle);
  value.state = static_cast<EvidenceState>(state);
  if (!r.reason(value.reason)) return false;
  if (!r.strong(value.observed_at)) return false;
  if (!r.strong(value.age)) return false;
  const std::uint16_t authority = r.u16();
  if (!r.ok()) return false;
  if (authority > static_cast<std::uint16_t>(AuthorityRank::Operator)) {
    r.fail(ReasonCode::RejectedMalformedDocument);
    return false;
  }
  value.authority = static_cast<AuthorityRank>(authority);
  if (!decode(r, value.generation)) return false;
  if (!decode(r, value.source_incarnation)) return false;
  if (!decode(r, value.capability_version)) return false;
  if (!decode(r, value.features)) return false;
  if (!decode(r, value.limits)) return false;
  if (!r.optional(value.firmware_version, [&r](SemVer& version) { return decode(r, version); })) {
    return false;
  }
  return r.optional(value.runtime_version, [&r](SemVer& version) { return decode(r, version); });
}

void encode(Writer& w, const CompatibilityDecision& value) {
  encode(w, value.id);
  w.u16(static_cast<std::uint16_t>(value.kind));
  encode(w, value.device);
  encode(w, value.capability);
  encode(w, value.requirement);
  w.u32(static_cast<std::uint32_t>(value.reasons.size()));
  for (const auto reason : value.reasons) w.reason(reason);
  w.u32(static_cast<std::uint32_t>(value.evidence.size()));
  for (const auto& id : value.evidence) encode(w, id);
  w.u32(static_cast<std::uint32_t>(value.evidence_facts.size()));
  for (const auto& fact : value.evidence_facts) encode(w, fact);
  w.optional(value.selected, [&w](const EvidenceId& id) { encode(w, id); });
  w.optional(value.conflict, [&w](const ConflictId& id) { encode(w, id); });
  w.u16(static_cast<std::uint16_t>(value.selected_authority));
  encode(w, value.rule_generation);
  w.strong(value.registry_epoch);
  w.strong(value.policy_revision);
  w.strong(value.evaluated_at);
}

bool decode(Reader& r, CompatibilityDecision& value) {
  if (!decode(r, value.id)) return false;
  const std::uint16_t kind = r.u16();
  if (!r.ok()) return false;
  if (kind < 1 || kind > 4) {
    r.fail(ReasonCode::RejectedMalformedDocument);
    return false;
  }
  value.kind = static_cast<DecisionKind>(kind);
  if (!decode(r, value.device)) return false;
  if (!decode(r, value.capability)) return false;
  if (!decode(r, value.requirement)) return false;
  const std::uint32_t reason_count = r.u32();
  if (!r.ok()) return false;
  if (reason_count > 4096u) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.reasons.clear();
  value.reasons.resize(reason_count);
  for (std::uint32_t i = 0; i < reason_count; ++i) {
    if (!r.reason(value.reasons[i])) return false;
  }
  canonicalize_reasons(value.reasons);
  const std::uint32_t evidence_count = r.u32();
  if (!r.ok()) return false;
  if (evidence_count > 1048576u) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.evidence.clear();
  value.evidence.resize(evidence_count);
  for (std::uint32_t i = 0; i < evidence_count; ++i) {
    if (!decode(r, value.evidence[i])) return false;
  }
  const std::uint32_t fact_count = r.u32();
  if (!r.ok()) return false;
  if (fact_count > 1048576u) {
    r.fail(ReasonCode::RejectedOversizedInput);
    return false;
  }
  value.evidence_facts.clear();
  value.evidence_facts.resize(fact_count);
  for (std::uint32_t i = 0; i < fact_count; ++i) {
    if (!decode(r, value.evidence_facts[i])) return false;
  }
  if (!r.optional(value.selected, [&r](EvidenceId& id) { return decode(r, id); })) return false;
  if (!r.optional(value.conflict, [&r](ConflictId& id) { return decode(r, id); })) return false;
  const std::uint16_t authority = r.u16();
  if (!r.ok()) return false;
  if (authority > static_cast<std::uint16_t>(AuthorityRank::Operator)) {
    r.fail(ReasonCode::RejectedMalformedDocument);
    return false;
  }
  value.selected_authority = static_cast<AuthorityRank>(authority);
  if (!decode(r, value.rule_generation)) return false;
  if (!r.strong(value.registry_epoch)) return false;
  if (!r.strong(value.policy_revision)) return false;
  return r.strong(value.evaluated_at);
}

}  // namespace ocreg
