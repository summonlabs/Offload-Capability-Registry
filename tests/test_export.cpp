// Offload Capability Registry - canonical export and import tests.
// Copyright 2026 Summon Software Labs.
#include <string>
#include <vector>

#include "ocreg/export.hpp"
#include "ocreg/json.hpp"
#include "ocreg/registry.hpp"
#include "registry_harness.hpp"
#include "test_support.hpp"

using namespace ocreg;
using namespace ocreg::test;

namespace {

struct Built {
  RegistryPolicy policy = make_lab_policy();
  Registry registry{policy};
  DeviceIncarnationRef device = reference("sim-nic-700", 0, 1);
  Tick now = kSecond;

  Built() {
    for (std::uint64_t generation = 1; generation <= 4; ++generation) {
      (void)registry.admit(
          make_request(device, "fixture-sim", "1." + std::to_string(generation) + ".0", generation,
                       now),
          now);
    }
    (void)registry.admit(make_request(reference("sim-nic-701", 0, 1), "operator-declared", "2.0.0",
                                      1, now),
                         now);
  }
};

}  // namespace

OCREG_TEST(canonical_export_round_trips_without_semantic_loss) {
  Built built;
  ExportOptions options;
  const auto exported = export_registry(built.registry, options, built.now);
  REQUIRE(exported.ok());
  CHECK(!exported.value().truncated);
  CHECK(exported.value().records_written >= 5);
  CHECK(exported.value().digest == built.registry.state_digest());

  const auto imported = import_document(exported.value().document);
  REQUIRE(imported.ok());
  CHECK(state_digest(imported.value().state) == built.registry.state_digest());

  // A second export of the imported state is byte-identical.
  Registry restored(imported.value().state.policy, imported.value().state);
  const auto reexported = export_registry(restored, options, built.now);
  REQUIRE(reexported.ok());
  CHECK(reexported.value().document == exported.value().document);

  // The same evidence is reachable after a round trip.
  const auto before = built.registry.query(
      CapabilityQuery{built.device, CapabilityKind::ChecksumOffload, Tick{}, true}, built.now);
  const auto after = restored.query(
      CapabilityQuery{built.device, CapabilityKind::ChecksumOffload, Tick{}, true}, built.now);
  REQUIRE(before.ok());
  REQUIRE(after.ok());
  CHECK(before.value().selected == after.value().selected);
  CHECK(before.value().reasons == after.value().reasons);
}

OCREG_TEST(export_is_deterministic_and_orders_its_collections_canonically) {
  Built left;
  Built right;
  ExportOptions options;
  const auto left_document = export_registry(left.registry, options, left.now);
  const auto right_document = export_registry(right.registry, options, right.now);
  REQUIRE(left_document.ok());
  REQUIRE(right_document.ok());
  CHECK(left_document.value().document == right_document.value().document);
  CHECK(left_document.value().digest == right_document.value().digest);

  // Object keys are sorted; the digest is stable.
  const auto parsed = JsonValue::parse(left_document.value().document);
  REQUIRE(parsed.ok());
  const auto& object = parsed.value().as_object();
  for (std::size_t index = 1; index < object.size(); ++index) {
    CHECK(object[index - 1].first < object[index].first);
  }
  const auto reparsed = JsonValue::parse(left_document.value().document);
  REQUIRE(reparsed.ok());
  CHECK(reparsed.value().dump(false) == left_document.value().document);
}

OCREG_TEST(import_refuses_every_malformed_or_tampered_document) {
  Built built;
  ExportOptions options;
  const auto exported = export_registry(built.registry, options, built.now);
  REQUIRE(exported.ok());
  const std::string& document = exported.value().document;

  // Truncation at every prefix must be refused, never partially accepted.
  for (std::size_t length = 0; length < document.size(); length += 37) {
    const auto truncated = import_document(std::string_view(document).substr(0, length));
    CHECK_MSG(!truncated.ok(), std::to_string(length));
  }

  CHECK(!import_document("").ok());
  CHECK(!import_document("[]").ok());
  CHECK(!import_document("{}").ok());
  CHECK(import_document(document + " ").ok());
  CHECK(!import_document(document + "{}").ok());

  // A wrong format name, format version or API generation is refused.
  auto replace_once = [](std::string text, const std::string& from, const std::string& to) {
    const std::size_t position = text.find(from);
    if (position == std::string::npos) return text;
    text.replace(position, from.size(), to);
    return text;
  };
  CHECK(!import_document(replace_once(document, "ocreg.canonical-state", "ocreg.other-state")).ok());
  CHECK(!import_document(replace_once(document, "\"format_version\":1", "\"format_version\":2")).ok());
  CHECK(!import_document(replace_once(document, "\"api_generation\":1", "\"api_generation\":9")).ok());
  CHECK(!import_document(replace_once(document, "\"catalog_fingerprint\":", "\"catalog_fingerprint\":0,")).ok());

  // A truncated export is refused outright rather than half-applied.
  CHECK(!import_document(replace_once(document, "\"truncated\":false", "\"truncated\":true")).ok());

  // Tampering with the declared state digest is detected.
  const std::size_t digest_position = document.find("\"state_digest\":\"");
  REQUIRE(digest_position != std::string::npos);
  std::string tampered = document;
  tampered[digest_position + 16] = tampered[digest_position + 16] == 'a' ? 'b' : 'a';
  CHECK(!import_document(tampered).ok());

  // Tampering with an evidence body without updating its identifier is caught
  // by the content-addressed identifier check.
  const std::size_t mtu_position = document.find("\"value\":9000");
  REQUIRE(mtu_position != std::string::npos);
  std::string altered = document;
  altered.replace(mtu_position, std::string("\"value\":9000").size(), "\"value\":8000");
  const auto altered_result = import_document(altered);
  CHECK(!altered_result.ok());

  // A missing required member is refused.
  CHECK(!import_document(replace_once(document, "\"evidence\":[", "\"evidence_renamed\":[")).ok());
}

OCREG_TEST(export_reports_truncation_instead_of_silently_dropping_records) {
  Built built;
  ExportOptions options;
  options.max_records = 2;
  const auto exported = export_registry(built.registry, options, built.now);
  REQUIRE(exported.ok());
  CHECK(exported.value().truncated);
  CHECK_EQ(exported.value().records_written, std::uint64_t{2});
  CHECK(std::find(exported.value().notes.begin(), exported.value().notes.end(),
                  ReasonCode::ExportTruncated) != exported.value().notes.end());

  // A truncated export declares itself and import refuses it: a partial
  // document never becomes a valid-looking state.
  const auto imported = import_document(exported.value().document);
  CHECK(!imported.ok());
  CHECK(imported.reason() == ReasonCode::ExportTruncated);

  ExportOptions tight;
  tight.max_bytes = 64;
  const auto oversize = export_registry(built.registry, tight, built.now);
  CHECK(!oversize.ok());
  CHECK(oversize.reason() == ReasonCode::RejectedOversizedInput);
}

OCREG_TEST(policy_and_requirement_documents_round_trip) {
  const RegistryPolicy policy = make_lab_policy();
  const std::string policy_document = render_policy_document(policy, false);
  const auto parsed_policy = parse_policy_document(policy_document);
  REQUIRE(parsed_policy.ok());
  CHECK(parsed_policy.value().sources.size() == policy.sources.size());
  CHECK(parsed_policy.value().policy_name == policy.policy_name);
  CHECK(parsed_policy.value().boot_policy == policy.boot_policy);
  CHECK(parsed_policy.value().default_max_age == policy.default_max_age);
  CHECK(parsed_policy.value().limits.max_records == policy.limits.max_records);
  CHECK(render_policy_document(parsed_policy.value(), false) == policy_document);

  CHECK(!parse_policy_document("{}").ok());
  CHECK(!parse_policy_document("not json").ok());

  CapabilityRequirement requirement = make_requirement(reference("sim-nic-700", 0, 1), "1.2.0");
  requirement.minimum_firmware_version = *SemVer::parse("3.0.0");
  requirement.minimum_runtime_generation = RuntimeGeneration(4);
  requirement.max_evidence_age = Tick{500};
  const std::string requirement_document = render_requirement_document(requirement, false);
  const auto parsed_requirement = parse_requirement_document(requirement_document);
  REQUIRE_MSG(parsed_requirement.ok(),
              std::string(to_string(parsed_requirement.reason())) + ": " +
                  parsed_requirement.detail());
  CHECK(parsed_requirement.value().capability == requirement.capability);
  CHECK(parsed_requirement.value().version.minimum == requirement.version.minimum);
  CHECK(requirement_digest(parsed_requirement.value()) == requirement_digest(requirement));
  CHECK(render_requirement_document(parsed_requirement.value(), false) == requirement_document);

  CHECK(!parse_requirement_document("{}").ok());
  // A requirement that names a limit the capability kind does not have is
  // refused rather than evaluated against nothing.
  std::string wrong_kind = requirement_document;
  const std::size_t kind_position = wrong_kind.find("\"checksum_offload\"");
  REQUIRE(kind_position != std::string::npos);
  wrong_kind.replace(kind_position, std::string("\"checksum_offload\"").size(),
                     "\"rdma_transport\"");
  CHECK(!parse_requirement_document(wrong_kind).ok());
}
