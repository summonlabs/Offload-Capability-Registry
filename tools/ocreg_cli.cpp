// Offload Capability Registry - inspection and driver CLI.
// Copyright 2026 Summon Software Labs.
#include <cstdint>
#include <functional>
#include <iostream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "ocreg/client.hpp"
#include "ocreg/export.hpp"
#include "ocreg/json.hpp"
#include "ocreg/persist.hpp"
#include "ocreg/registry.hpp"
#include "tool_support.hpp"

namespace {

using ocreg::AuthorityRank;
using ocreg::CapabilityKind;
using ocreg::DecisionId;
using ocreg::EvidenceLifecycle;
using ocreg::EvidenceState;
using ocreg::JsonValue;
using ocreg::ReasonCode;
using ocreg::Registry;
using ocreg::RegistryPolicy;
using ocreg::RegistryState;
using ocreg::StoreOptions;
using ocreg::Tick;
using ocreg::tools::Arguments;

constexpr int kExitOk = 0;
constexpr int kExitUsage = 2;
constexpr int kExitFailure = 1;

void print_usage() {
  std::cout <<
      "ocreg - Offload Capability Registry inspection tool\n"
      "\n"
      "usage: ocreg <command> [options]\n"
      "\n"
      "commands:\n"
      "  verify   --store PATH                          validate a store and report recovery\n"
      "  stats    --store PATH [--tick N]               print registry statistics\n"
      "  export   --store PATH [--pretty]               print the canonical state document\n"
      "  import   --store PATH --document FILE          create or replace a store from a document\n"
      "  ingest   --store PATH --document FILE          admit each record through the registry\n"
      "  query    --store PATH --provider P --model M --unit N --incarnation I --kind K\n"
      "                                                  [--tick N] [--history]\n"
      "  evaluate --store PATH --requirement FILE [--tick N]\n"
      "  explain  --store PATH --decision HEX           reprint a retained decision\n"
      "  remote-ping   --host H --port P\n"
      "  remote-stats  --host H --port P [--tick N]\n"
      "  remote-export --host H --port P [--pretty] [--tick N]\n"
      "\n"
      "Every command writes canonical JSON to stdout and exits non-zero on refusal.\n";
}

[[nodiscard]] JsonValue reason_array(const std::vector<ReasonCode>& reasons) {
  JsonValue array = JsonValue::array();
  for (const auto reason : reasons) array.push(JsonValue::string(std::string(ocreg::to_string(reason))));
  return array;
}

[[nodiscard]] JsonValue stats_to_json(const ocreg::RegistryStats& stats) {
  JsonValue object = JsonValue::object();
  object.set("admissions_accepted", JsonValue::integer(static_cast<std::int64_t>(stats.admissions_accepted)));
  object.set("admissions_idempotent", JsonValue::integer(static_cast<std::int64_t>(stats.admissions_idempotent)));
  object.set("admissions_rejected", JsonValue::integer(static_cast<std::int64_t>(stats.admissions_rejected)));
  object.set("retirements_accepted", JsonValue::integer(static_cast<std::int64_t>(stats.retirements_accepted)));
  object.set("retirements_rejected", JsonValue::integer(static_cast<std::int64_t>(stats.retirements_rejected)));
  object.set("devices", JsonValue::integer(static_cast<std::int64_t>(stats.devices)));
  object.set("incarnations", JsonValue::integer(static_cast<std::int64_t>(stats.incarnations)));
  object.set("streams", JsonValue::integer(static_cast<std::int64_t>(stats.streams)));
  object.set("records_total", JsonValue::integer(static_cast<std::int64_t>(stats.records_total)));
  object.set("records_active", JsonValue::integer(static_cast<std::int64_t>(stats.records_active)));
  object.set("records_superseded", JsonValue::integer(static_cast<std::int64_t>(stats.records_superseded)));
  object.set("records_retired", JsonValue::integer(static_cast<std::int64_t>(stats.records_retired)));
  object.set("records_rejected", JsonValue::integer(static_cast<std::int64_t>(stats.records_rejected)));
  object.set("records_fenced", JsonValue::integer(static_cast<std::int64_t>(stats.records_fenced)));
  object.set("records_stale", JsonValue::integer(static_cast<std::int64_t>(stats.records_stale)));
  object.set("records_outranked", JsonValue::integer(static_cast<std::int64_t>(stats.records_outranked)));
  object.set("records_evicted", JsonValue::integer(static_cast<std::int64_t>(stats.records_evicted)));
  object.set("eviction_ledger_dropped", JsonValue::integer(static_cast<std::int64_t>(stats.eviction_ledger_dropped)));
  object.set("conflicts_open", JsonValue::integer(static_cast<std::int64_t>(stats.conflicts_open)));
  object.set("conflicts_resolved", JsonValue::integer(static_cast<std::int64_t>(stats.conflicts_resolved)));
  object.set("conflicts_dropped", JsonValue::integer(static_cast<std::int64_t>(stats.conflicts_dropped)));
  object.set("tombstones", JsonValue::integer(static_cast<std::int64_t>(stats.tombstones)));
  object.set("tombstones_dropped", JsonValue::integer(static_cast<std::int64_t>(stats.tombstones_dropped)));
  object.set("resolutions", JsonValue::integer(static_cast<std::int64_t>(stats.resolutions)));
  object.set("resolutions_dropped", JsonValue::integer(static_cast<std::int64_t>(stats.resolutions_dropped)));
  object.set("decisions_emitted", JsonValue::integer(static_cast<std::int64_t>(stats.decisions_emitted)));
  object.set("decisions_evicted", JsonValue::integer(static_cast<std::int64_t>(stats.decisions_evicted)));
  object.set("registry_epoch", JsonValue::integer(static_cast<std::int64_t>(stats.registry_epoch.value())));
  object.set("rule_generation", JsonValue::integer(static_cast<std::int64_t>(stats.rule_generation.value())));
  object.set("policy_revision", JsonValue::integer(static_cast<std::int64_t>(stats.policy_revision.value())));
  object.set("boot_epoch", JsonValue::integer(static_cast<std::int64_t>(stats.boot_epoch.value())));
  object.set("logical_tick", JsonValue::integer(static_cast<std::int64_t>(stats.logical_tick.value())));
  return object;
}

struct StoreLoad {
  bool ok = false;
  ReasonCode reason = ReasonCode::Ok;
  std::string detail{};
  RegistryState state{};
  ocreg::RecoverySummary recovery{};
};

[[nodiscard]] StoreLoad load_store(const std::string& path) {
  StoreLoad result;
  StoreOptions options;
  options.base_path = path;
  ocreg::RecoverySummary summary;
  auto outcome = ocreg::load_state(options, summary);
  if (!outcome.ok()) {
    result.reason = outcome.reason();
    result.detail = outcome.detail();
    return result;
  }
  result.state = std::move(outcome.value());
  result.recovery = summary;
  result.ok = true;
  return result;
}

[[nodiscard]] RegistryPolicy policy_from(const Arguments& arguments) {
  const auto path = arguments.get("policy");
  if (!path.has_value()) return ocreg::make_lab_policy();
  std::string document;
  if (!ocreg::tools::read_text_file(*path, document)) return ocreg::make_lab_policy();
  auto parsed = ocreg::parse_policy_document(document);
  if (!parsed.ok()) return ocreg::make_lab_policy();
  return parsed.value();
}

[[nodiscard]] Tick tick_from(const Arguments& arguments) {
  const auto text = arguments.get("tick");
  if (!text.has_value()) return Tick{};
  bool ok = false;
  const std::uint64_t value = ocreg::tools::parse_unsigned(*text, ok);
  return ok ? Tick{value} : Tick{};
}

[[nodiscard]] int command_verify(const Arguments& arguments) {
  const auto store = arguments.get("store");
  if (!store.has_value()) {
    std::cerr << "verify requires --store\n";
    return kExitUsage;
  }
  StoreOptions options;
  options.base_path = *store;
  auto report = ocreg::Store::open(options);
  JsonValue root = JsonValue::object();
  if (!report.ok()) {
    root.set("ok", JsonValue::boolean(false));
    root.set("reason", JsonValue::string(std::string(ocreg::to_string(report.reason()))));
    root.set("detail", JsonValue::string(report.detail()));
    std::cout << root.dump(true) << '\n';
    return kExitFailure;
  }
  const auto& value = report.value();
  root.set("ok", JsonValue::boolean(true));
  root.set("recovery_class", JsonValue::string(std::string(ocreg::to_string(value.classification))));
  root.set("reason", JsonValue::string(std::string(ocreg::to_string(value.reason))));
  root.set("existed", JsonValue::boolean(value.existed));
  root.set("snapshot_present", JsonValue::boolean(value.snapshot_present));
  root.set("journal_present", JsonValue::boolean(value.journal_present));
  root.set("snapshot_bytes", JsonValue::integer(static_cast<std::int64_t>(value.snapshot_bytes)));
  root.set("journal_bytes", JsonValue::integer(static_cast<std::int64_t>(value.journal_bytes)));
  root.set("bytes_discarded", JsonValue::integer(static_cast<std::int64_t>(value.bytes_discarded)));
  root.set("journal_entries_scanned", JsonValue::integer(static_cast<std::int64_t>(value.journal_entries_scanned)));
  root.set("journal_entries_valid", JsonValue::integer(static_cast<std::int64_t>(value.journal_entries_valid)));
  root.set("journal_entries_dropped", JsonValue::integer(static_cast<std::int64_t>(value.journal_entries_dropped)));
  root.set("record_count", JsonValue::integer(static_cast<std::int64_t>(value.state.records.size())));
  root.set("state_digest", JsonValue::string(ocreg::state_digest(value.state).hex()));
  std::cout << root.dump(true) << '\n';
  return kExitOk;
}

[[nodiscard]] int command_stats(const Arguments& arguments) {
  const auto store = arguments.get("store");
  if (!store.has_value()) {
    std::cerr << "stats requires --store\n";
    return kExitUsage;
  }
  StoreLoad loaded = load_store(*store);
  if (!loaded.ok) {
    ocreg::tools::print_error(loaded.reason, loaded.detail);
    return kExitFailure;
  }
  Registry registry(loaded.state.policy, loaded.state);
  ocreg::RecoverySummary summary;
  auto adopted = registry.adopt_state(loaded.state, tick_from(arguments));
  if (!adopted.ok()) {
    ocreg::tools::print_error(adopted.reason(), adopted.detail());
    return kExitFailure;
  }
  std::cout << stats_to_json(registry.stats(tick_from(arguments))).dump(true) << '\n';
  return kExitOk;
}

[[nodiscard]] int command_export(const Arguments& arguments) {
  const auto store = arguments.get("store");
  if (!store.has_value()) {
    std::cerr << "export requires --store\n";
    return kExitUsage;
  }
  StoreLoad loaded = load_store(*store);
  if (!loaded.ok) {
    ocreg::tools::print_error(loaded.reason, loaded.detail);
    return kExitFailure;
  }
  Registry registry(loaded.state.policy, loaded.state);
  auto adopted = registry.adopt_state(loaded.state, tick_from(arguments));
  if (!adopted.ok()) {
    ocreg::tools::print_error(adopted.reason(), adopted.detail());
    return kExitFailure;
  }
  ocreg::ExportOptions options;
  options.pretty = arguments.flag("pretty");
  auto exported = ocreg::export_registry(registry, options, tick_from(arguments));
  if (!exported.ok()) {
    ocreg::tools::print_error(exported.reason(), exported.detail());
    return kExitFailure;
  }
  std::cout << exported.value().document << '\n';
  return kExitOk;
}

[[nodiscard]] int command_import(const Arguments& arguments) {
  const auto store = arguments.get("store");
  const auto document = arguments.get("document");
  if (!store.has_value() || !document.has_value()) {
    std::cerr << "import requires --store and --document\n";
    return kExitUsage;
  }
  std::string text;
  if (!ocreg::tools::read_text_file(*document, text)) {
    std::cerr << "import could not read " << *document << '\n';
    return kExitFailure;
  }
  auto imported = ocreg::import_document(text);
  if (!imported.ok()) {
    ocreg::tools::print_error(imported.reason(), imported.detail());
    return kExitFailure;
  }
  RegistryState state = std::move(imported.value().state);
  if (arguments.flag("policy")) state.policy = policy_from(arguments);
  state.store_generation = ocreg::StoreGeneration(state.store_generation.value() + 1);
  StoreOptions options;
  options.base_path = *store;
  auto bound = ocreg::Store::bind(options);
  if (!bound.ok()) {
    ocreg::tools::print_error(bound.reason(), bound.detail());
    return kExitFailure;
  }
  auto committed = bound.value()->compact(state, tick_from(arguments));
  if (!committed.ok()) {
    ocreg::tools::print_error(committed.reason(), committed.detail());
    return kExitFailure;
  }
  JsonValue root = JsonValue::object();
  root.set("ok", JsonValue::boolean(true));
  root.set("records", JsonValue::integer(static_cast<std::int64_t>(state.records.size())));
  root.set("store_generation", JsonValue::integer(static_cast<std::int64_t>(state.store_generation.value())));
  root.set("payload_digest", JsonValue::string(committed.value().payload_digest.hex()));
  std::cout << root.dump(true) << '\n';
  return kExitOk;
}

[[nodiscard]] int command_ingest(const Arguments& arguments) {
  const auto store = arguments.get("store");
  const auto document = arguments.get("document");
  if (!store.has_value() || !document.has_value()) {
    std::cerr << "ingest requires --store and --document\n";
    return kExitUsage;
  }
  std::string text;
  if (!ocreg::tools::read_text_file(*document, text)) {
    std::cerr << "ingest could not read " << *document << '\n';
    return kExitFailure;
  }
  auto imported = ocreg::import_document(text);
  if (!imported.ok()) {
    ocreg::tools::print_error(imported.reason(), imported.detail());
    return kExitFailure;
  }
  RegistryState source = std::move(imported.value().state);
  RegistryPolicy policy = arguments.flag("policy") ? policy_from(arguments) : source.policy;
  const Tick now = tick_from(arguments);

  Registry registry(policy);
  std::uint64_t accepted = 0;
  std::uint64_t idempotent = 0;
  std::uint64_t refused = 0;
  std::vector<ReasonCode> refusals;
  // Install the recorded incarnation layout first so that evidence attached to
  // a superseded incarnation is admitted and fenced rather than misattributed.
  for (const auto& entry : source.incarnations) {
    auto installed = registry.set_device_incarnation(entry.device, entry.current, now);
    if (!installed.ok()) {
      ocreg::tools::print_error(installed.reason(), installed.detail());
      return kExitFailure;
    }
  }
  for (const auto& record : source.records) {
    const ocreg::CapabilityEvidence& evidence = record.evidence;
    ocreg::AdmissionRequest request;
    request.device = evidence.key.device;
    request.kind = evidence.key.kind;
    request.source = evidence.source_incarnation;
    request.capability_version = evidence.capability_version;
    request.features = evidence.features;
    request.limits = evidence.limits;
    request.firmware_version = evidence.firmware_version;
    request.firmware_generation = evidence.firmware_generation;
    request.runtime_version = evidence.runtime_version;
    request.runtime_generation = evidence.runtime_generation;
    request.observed_at = evidence.observed_at;
    request.valid_until = evidence.valid_until;
    request.generation = evidence.generation;
    auto outcome = registry.admit(request, now);
    if (!outcome.ok()) {
      ++refused;
      refusals.push_back(outcome.reason());
      continue;
    }
    if (outcome.value().idempotent) {
      ++idempotent;
    } else if (outcome.value().state == EvidenceState::Rejected) {
      ++refused;
      refusals.push_back(outcome.value().reason);
    } else {
      ++accepted;
    }
  }

  RegistryState committed_state;
  {
    auto snapshot = registry.snapshot_state();
    if (!snapshot.ok()) {
      ocreg::tools::print_error(snapshot.reason(), snapshot.detail());
      return kExitFailure;
    }
    committed_state = std::move(snapshot.value());
    committed_state.store_generation = ocreg::StoreGeneration(source.store_generation.value() + 1);
  }
  StoreOptions options;
  options.base_path = *store;
  auto bound = ocreg::Store::bind(options);
  if (!bound.ok()) {
    ocreg::tools::print_error(bound.reason(), bound.detail());
    return kExitFailure;
  }
  auto committed = bound.value()->compact(committed_state, now);
  if (!committed.ok()) {
    ocreg::tools::print_error(committed.reason(), committed.detail());
    return kExitFailure;
  }
  JsonValue root = JsonValue::object();
  root.set("ok", JsonValue::boolean(true));
  root.set("accepted", JsonValue::integer(static_cast<std::int64_t>(accepted)));
  root.set("idempotent", JsonValue::integer(static_cast<std::int64_t>(idempotent)));
  root.set("refused", JsonValue::integer(static_cast<std::int64_t>(refused)));
  root.set("refusal_reasons", reason_array(ocreg::canonical_reasons(refusals)));
  root.set("state_digest", JsonValue::string(registry.state_digest().hex()));
  std::cout << root.dump(true) << '\n';
  return kExitOk;
}

[[nodiscard]] bool parse_device(const Arguments& arguments, ocreg::DeviceIncarnationRef& out) {
  const auto provider = arguments.get("provider");
  const auto model = arguments.get("model");
  const auto unit = arguments.get("unit");
  const auto incarnation = arguments.get("incarnation");
  if (!provider.has_value() || !model.has_value() || !unit.has_value() || !incarnation.has_value()) {
    return false;
  }
  const auto parsed_provider = ocreg::ProviderId::parse(*provider);
  const auto parsed_model = ocreg::DeviceModelId::parse(*model);
  if (!parsed_provider.has_value() || !parsed_model.has_value()) return false;
  bool ok = false;
  const std::uint64_t unit_index = ocreg::tools::parse_unsigned(*unit, ok);
  if (!ok) return false;
  const std::uint64_t incarnation_id = ocreg::tools::parse_unsigned(*incarnation, ok);
  if (!ok || incarnation_id == 0) return false;
  out.device.provider = *parsed_provider;
  out.device.model = *parsed_model;
  out.device.unit_index = static_cast<std::uint32_t>(unit_index);
  out.incarnation = ocreg::IncarnationId(incarnation_id);
  return true;
}

[[nodiscard]] int command_query(const Arguments& arguments) {
  const auto store = arguments.get("store");
  const auto kind_text = arguments.get("kind");
  if (!store.has_value() || !kind_text.has_value()) {
    std::cerr << "query requires --store and --kind\n";
    return kExitUsage;
  }
  ocreg::DeviceIncarnationRef device;
  if (!parse_device(arguments, device)) {
    std::cerr << "query requires --provider --model --unit --incarnation\n";
    return kExitUsage;
  }
  CapabilityKind kind{};
  if (!ocreg::parse_capability_kind(*kind_text, kind)) {
    std::cerr << "unknown capability kind: " << *kind_text << '\n';
    return kExitUsage;
  }
  StoreLoad loaded = load_store(*store);
  if (!loaded.ok) {
    ocreg::tools::print_error(loaded.reason, loaded.detail);
    return kExitFailure;
  }
  Registry registry(loaded.state.policy, loaded.state);
  auto adopted = registry.adopt_state(loaded.state, tick_from(arguments));
  if (!adopted.ok()) {
    ocreg::tools::print_error(adopted.reason(), adopted.detail());
    return kExitFailure;
  }
  ocreg::CapabilityQuery query;
  query.device = device;
  query.kind = kind;
  query.include_history = arguments.flag("history");
  auto result = registry.query(query, tick_from(arguments));
  if (!result.ok()) {
    ocreg::tools::print_error(result.reason(), result.detail());
    return kExitFailure;
  }
  JsonValue root = JsonValue::object();
  root.set("decision", JsonValue::string(std::string(ocreg::to_string(result.value().kind))));
  root.set("reasons", reason_array(result.value().reasons));
  JsonValue facts = JsonValue::array();
  for (const auto& fact : result.value().facts) {
    JsonValue item = JsonValue::object();
    item.set("id", JsonValue::string(fact.id.hex()));
    item.set("state", JsonValue::string(std::string(ocreg::to_string(fact.state))));
    item.set("reason", JsonValue::string(std::string(ocreg::to_string(fact.reason))));
    item.set("generation", JsonValue::integer(static_cast<std::int64_t>(fact.generation.value())));
    item.set("observed_at", JsonValue::integer(static_cast<std::int64_t>(fact.observed_at.value())));
    item.set("age", JsonValue::integer(static_cast<std::int64_t>(fact.age.value())));
    item.set("authority", JsonValue::string(std::string(ocreg::to_string(fact.authority))));
    item.set("capability_version", JsonValue::string(fact.capability_version.str()));
    facts.push(std::move(item));
  }
  root.set("evidence", std::move(facts));
  if (result.value().selected.has_value()) {
    root.set("selected", JsonValue::string(result.value().selected->hex()));
  }
  if (result.value().conflict.has_value()) {
    root.set("conflict", JsonValue::string(result.value().conflict->hex()));
  }
  std::cout << root.dump(true) << '\n';
  return kExitOk;
}

[[nodiscard]] int command_evaluate(const Arguments& arguments) {
  const auto store = arguments.get("store");
  const auto requirement_path = arguments.get("requirement");
  if (!store.has_value() || !requirement_path.has_value()) {
    std::cerr << "evaluate requires --store and --requirement\n";
    return kExitUsage;
  }
  std::string text;
  if (!ocreg::tools::read_text_file(*requirement_path, text)) {
    std::cerr << "evaluate could not read " << *requirement_path << '\n';
    return kExitFailure;
  }
  auto requirement = ocreg::parse_requirement_document(text);
  if (!requirement.ok()) {
    ocreg::tools::print_error(requirement.reason(), requirement.detail());
    return kExitFailure;
  }

  StoreLoad loaded = load_store(*store);
  if (!loaded.ok) {
    ocreg::tools::print_error(loaded.reason, loaded.detail);
    return kExitFailure;
  }
  const Tick now = tick_from(arguments);
  Registry registry(loaded.state.policy, loaded.state);
  auto adopted = registry.adopt_state(loaded.state, now);
  if (!adopted.ok()) {
    ocreg::tools::print_error(adopted.reason(), adopted.detail());
    return kExitFailure;
  }

  const ocreg::CompatibilityDecision decision = registry.evaluate(requirement.value(), now);
  JsonValue root = JsonValue::object();
  root.set("decision", JsonValue::string(std::string(ocreg::to_string(decision.kind))));
  root.set("decision_id", JsonValue::string(decision.id.hex()));
  root.set("reasons", reason_array(decision.reasons));
  root.set("registry_epoch", JsonValue::integer(static_cast<std::int64_t>(decision.registry_epoch.value())));
  root.set("rule_generation", JsonValue::integer(static_cast<std::int64_t>(decision.rule_generation.value())));
  root.set("policy_revision", JsonValue::integer(static_cast<std::int64_t>(decision.policy_revision.value())));
  root.set("evaluated_at", JsonValue::integer(static_cast<std::int64_t>(decision.evaluated_at.value())));
  root.set("selected_authority",
           JsonValue::string(std::string(ocreg::to_string(decision.selected_authority))));
  if (decision.selected.has_value()) {
    root.set("selected", JsonValue::string(decision.selected->hex()));
  }
  if (decision.conflict.has_value()) {
    root.set("conflict", JsonValue::string(decision.conflict->hex()));
  }
  JsonValue facts = JsonValue::array();
  for (const auto& fact : decision.evidence_facts) {
    JsonValue item = JsonValue::object();
    item.set("id", JsonValue::string(fact.id.hex()));
    item.set("state", JsonValue::string(std::string(ocreg::to_string(fact.state))));
    item.set("reason", JsonValue::string(std::string(ocreg::to_string(fact.reason))));
    item.set("age", JsonValue::integer(static_cast<std::int64_t>(fact.age.value())));
    item.set("authority", JsonValue::string(std::string(ocreg::to_string(fact.authority))));
    facts.push(std::move(item));
  }
  root.set("evidence", std::move(facts));
  std::cout << root.dump(true) << '\n';
  return kExitOk;
}

[[nodiscard]] int command_explain(const Arguments& arguments) {
  const auto store = arguments.get("store");
  const auto decision_text = arguments.get("decision");
  if (!store.has_value() || !decision_text.has_value()) {
    std::cerr << "explain requires --store and --decision\n";
    return kExitUsage;
  }
  ocreg::Digest256 digest;
  if (!ocreg::Digest256::parse(*decision_text, digest)) {
    std::cerr << "decision must be a 64 character lower-case hex digest\n";
    return kExitUsage;
  }
  StoreLoad loaded = load_store(*store);
  if (!loaded.ok) {
    ocreg::tools::print_error(loaded.reason, loaded.detail);
    return kExitFailure;
  }
  Registry registry(loaded.state.policy, loaded.state);
  auto adopted = registry.adopt_state(loaded.state, tick_from(arguments));
  if (!adopted.ok()) {
    ocreg::tools::print_error(adopted.reason(), adopted.detail());
    return kExitFailure;
  }
  auto explanation = registry.explain(DecisionId(digest));
  JsonValue root = JsonValue::object();
  root.set("available", JsonValue::boolean(explanation.ok()));
  root.set("reason", JsonValue::string(std::string(
                         ocreg::to_string(explanation.ok() ? ReasonCode::Ok : explanation.reason()))));
  if (explanation.ok()) {
    root.set("decision", JsonValue::string(std::string(ocreg::to_string(explanation.value().decision.kind))));
    root.set("reasons", reason_array(explanation.value().decision.reasons));
    JsonValue ids = JsonValue::array();
    for (const auto& id : explanation.value().decision.evidence) {
      ids.push(JsonValue::string(id.hex()));
    }
    root.set("evidence", std::move(ids));
  }
  std::cout << root.dump(true) << '\n';
  return explanation.ok() ? kExitOk : kExitFailure;
}

[[nodiscard]] int with_client(const Arguments& arguments,
                              const std::function<int(ocreg::Client&, Tick)>& body) {
  const auto host = arguments.get_or("host", "127.0.0.1");
  const auto port_text = arguments.get("port");
  if (!port_text.has_value()) {
    std::cerr << "a --port is required\n";
    return kExitUsage;
  }
  bool ok = false;
  const std::uint64_t port = ocreg::tools::parse_unsigned(*port_text, ok);
  if (!ok || port == 0 || port > 65535) {
    std::cerr << "port must be in 1..65535\n";
    return kExitUsage;
  }
  ocreg::ClientOptions options;
  options.host = host;
  options.port = static_cast<std::uint16_t>(port);
  auto client = ocreg::Client::connect(options);
  if (!client.ok()) {
    ocreg::tools::print_error(client.reason(), client.detail());
    return kExitFailure;
  }
  return body(*client.value(), tick_from(arguments));
}

}  // namespace

int main(int argc, char** argv) {
  const Arguments arguments = ocreg::tools::parse_arguments(argc, argv);
  if (arguments.command.empty() || arguments.command == "help" || arguments.command == "--help") {
    print_usage();
    return arguments.command.empty() ? kExitUsage : kExitOk;
  }
  if (arguments.command == "verify") return command_verify(arguments);
  if (arguments.command == "stats") return command_stats(arguments);
  if (arguments.command == "export") return command_export(arguments);
  if (arguments.command == "import") return command_import(arguments);
  if (arguments.command == "ingest") return command_ingest(arguments);
  if (arguments.command == "query") return command_query(arguments);
  if (arguments.command == "evaluate") return command_evaluate(arguments);
  if (arguments.command == "explain") return command_explain(arguments);
  if (arguments.command == "remote-ping") {
    return with_client(arguments, [](ocreg::Client& client, Tick now) {
      auto reply = client.ping(now);
      if (!reply.ok()) {
        ocreg::tools::print_error(reply.reason(), reply.detail());
        return kExitFailure;
      }
      JsonValue root = JsonValue::object();
      root.set("pong", JsonValue::boolean(reply.value().value));
      std::cout << root.dump(true) << '\n';
      return kExitOk;
    });
  }
  if (arguments.command == "remote-stats") {
    return with_client(arguments, [](ocreg::Client& client, Tick now) {
      auto reply = client.stats(now);
      if (!reply.ok()) {
        ocreg::tools::print_error(reply.reason(), reply.detail());
        return kExitFailure;
      }
      std::cout << stats_to_json(reply.value()).dump(true) << '\n';
      return kExitOk;
    });
  }
  if (arguments.command == "remote-export") {
    return with_client(arguments, [&arguments](ocreg::Client& client, Tick now) {
      ocreg::ExportOptions options;
      options.pretty = arguments.flag("pretty");
      auto reply = client.export_state(options, now);
      if (!reply.ok()) {
        ocreg::tools::print_error(reply.reason(), reply.detail());
        return kExitFailure;
      }
      std::cout << reply.value().document << '\n';
      return kExitOk;
    });
  }
  std::cerr << "unknown command: " << arguments.command << '\n';
  print_usage();
  return kExitUsage;
}