// Offload Capability Registry - protocol client.
// Copyright 2026 Summon Software Labs.
#ifndef OCREG_CLIENT_HPP
#define OCREG_CLIENT_HPP

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "ocreg/outcome.hpp"
#include "ocreg/protocol.hpp"

namespace ocreg {

class Client {
 public:
  static Outcome<std::unique_ptr<Client>> connect(const ClientOptions& options);

  ~Client();
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;

  // Sends one request and waits for the matching response. The wait is a real
  // blocking read on the socket; there is no polling and no timeout.
  Outcome<std::vector<std::uint8_t>> call(OpCode opcode, std::span<const std::uint8_t> payload);

  Outcome<BoolResponse> ping(Tick now);
  Outcome<RegistryStats> stats(Tick now);
  Outcome<AdmissionOutcome> admit(const AdmissionRequest& request, Tick now);
  Outcome<RetirementOutcome> retire(const RetirementRequest& request, Tick now);
  Outcome<QueryResult> query(const CapabilityQuery& query, Tick now);
  Outcome<CompatibilityDecision> evaluate(const CapabilityRequirement& requirement, Tick now);
  Outcome<ExplanationResponse> explain(const DecisionId& id);
  Outcome<ExportResponse> export_state(const ExportOptions& options, Tick now);
  Outcome<BoolResponse> revoke_source(const SourceId& source, Tick now);
  Outcome<BoolResponse> restore_source(const SourceId& source, Tick now);
  Outcome<BoolResponse> set_source_authority(const SourceId& source, AuthorityRank authority,
                                             Tick now);
  Outcome<SourcePolicy> upsert_source_policy(const SourcePolicy& policy, Tick now);
  Outcome<IdResponse> begin_device_incarnation(const DeviceIdentity& device, Tick now);
  Outcome<IdResponse> current_incarnation(const DeviceIdentity& device, Tick now);
  Outcome<ConflictResolution> resolve_conflict(const ResolveConflictRequest& request);
  Outcome<EvictionLedgerResponse> eviction_ledger(Tick now);
  Outcome<BoolResponse> shutdown(Tick now);

 private:
  struct Impl;
  explicit Client(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

}  // namespace ocreg

#endif  // OCREG_CLIENT_HPP
