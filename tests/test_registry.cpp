// Offload Capability Registry - registry semantics tests.
// Copyright 2026 Summon Software Labs.
#include <algorithm>
#include <string>
#include <thread>
#include <vector>

#include "ocreg/export.hpp"
#include "ocreg/persist.hpp"
#include "ocreg/registry.hpp"
#include "registry_harness.hpp"
#include "test_support.hpp"

using namespace ocreg;
using namespace ocreg::test;

namespace {

struct Fixture {
  RegistryPolicy policy = make_lab_policy();
  Registry registry{policy};
  DeviceIncarnationRef device = reference("sim-nic-100", 0, 1);
};

[[nodiscard]] DecisionKind query_kind(const Registry& registry, const DeviceIncarnationRef& device,
                                      Tick now, bool history = false) {
  CapabilityQuery query;
  query.device = device;
  query.kind = CapabilityKind::ChecksumOffload;
  query.include_history = history;
  const auto result = registry.query(query, now);
  if (!result.ok()) return DecisionKind::Unknown;
  return result.value().kind;
}

}  // namespace

OCREG_TEST(admission_produces_a_current_fact_and_explains_it) {
  Fixture fixture;
  const Tick now = kSecond;
  const auto outcome = fixture.registry.admit(
      make_request(fixture.device, "fixture-sim", "1.4.0", 1, now), now);
  REQUIRE(outcome.ok());
  CHECK(outcome.value().reason == ReasonCode::AcceptedNew);
  CHECK(outcome.value().state == EvidenceState::Active);

  CHECK(query_kind(fixture.registry, fixture.device, now) == DecisionKind::Compatible);

  const auto decision = fixture.registry.evaluate(
      make_requirement(fixture.device, "1.0.0"), now);
  CHECK(decision.kind == DecisionKind::Compatible);
  CHECK(decision.selected.has_value());
  CHECK(decision.selected_authority == AuthorityRank::Synthetic);
  CHECK(decision.registry_epoch.value() >= 1);
  CHECK(!decision.id.hex().empty());

  const auto explanation = fixture.registry.explain(decision.id);
  REQUIRE(explanation.ok());
  CHECK(explanation.value().decision_available);
  CHECK(!explanation.value().involved_sources.empty());
  CHECK(explanation.value().involved_sources.front().id == source_id("fixture-sim"));
  CHECK(explanation.value().decision.kind == DecisionKind::Compatible);

  // An unknown decision is still explainable.
  const auto missing = fixture.registry.evaluate(
      make_requirement(reference("sim-nic-999", 0, 1), "1.0.0"), now);
  CHECK(missing.kind == DecisionKind::Unknown);
  CHECK(std::find(missing.reasons.begin(), missing.reasons.end(),
                  ReasonCode::UnknownDeviceNotRegistered) != missing.reasons.end());
}

OCREG_TEST(duplicate_delivery_is_idempotent_and_a_generation_collision_is_not) {
  Fixture fixture;
  const Tick now = kSecond;
  const AdmissionRequest request = make_request(fixture.device, "fixture-sim", "1.4.0", 5, now);

  const auto first = fixture.registry.admit(request, now);
  REQUIRE(first.ok());
  CHECK(!first.value().idempotent);

  const auto duplicate = fixture.registry.admit(request, now);
  REQUIRE(duplicate.ok());
  CHECK(duplicate.value().idempotent);
  CHECK(duplicate.value().reason == ReasonCode::AlreadyPresent);
  CHECK(duplicate.value().id == first.value().id);

  const auto stats = fixture.registry.stats(now);
  CHECK_EQ(stats.records_total, std::uint64_t{1});
  CHECK_EQ(stats.admissions_idempotent, std::uint64_t{1});

  // The same generation carrying different content is a collision: it is
  // refused and retained, never merged.
  AdmissionRequest colliding = request;
  colliding.limits = LimitSet::from_validated(
      {LimitValue{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 1400}});
  const auto collision = fixture.registry.admit(colliding, now);
  REQUIRE(collision.ok());
  CHECK(collision.value().state == EvidenceState::Rejected);
  CHECK(collision.value().reason == ReasonCode::RejectedGenerationCollision);

  // A lower generation replayed after a higher one is refused.
  const auto higher = fixture.registry.admit(
      make_request(fixture.device, "fixture-sim", "1.5.0", 9, now), now);
  REQUIRE(higher.ok());
  const auto regression = fixture.registry.admit(
      make_request(fixture.device, "fixture-sim", "1.1.0", 4, now), now);
  REQUIRE(regression.ok());
  CHECK(regression.value().reason == ReasonCode::RejectedSupersededGeneration);

  // The current fact is still the highest generation.
  const auto decision = fixture.registry.evaluate(make_requirement(fixture.device, "1.0.0"), now);
  CHECK(decision.kind == DecisionKind::Compatible);
  CHECK(decision.selected.has_value());
  // The accessor returns by value, so the copy is held in a named local: a
  // pointer into a temporary would dangle.
  const std::vector<StoredEvidence> records = fixture.registry.records();
  const CapabilityEvidence* selected = nullptr;
  for (const auto& record : records) {
    if (record.evidence.id() == *decision.selected) selected = &record.evidence;
  }
  REQUIRE(selected != nullptr);
  CHECK(selected->generation == RecordGeneration(9));
}

OCREG_TEST(superseded_evidence_cannot_satisfy_a_current_requirement) {
  Fixture fixture;
  const Tick now = kSecond;
  const auto old_record = fixture.registry.admit(
      make_request(fixture.device, "fixture-sim", "1.4.0", 1, now), now);
  REQUIRE(old_record.ok());
  const auto retired_record = fixture.registry.admit(
      make_request(fixture.device, "fixture-sim", "9.9.9", 2, now), now);
  REQUIRE(retired_record.ok());
  // The newest record lacks the required feature, so a requirement that needs
  // it must be answered from the newest record only.
  AdmissionRequest narrowed = make_request(fixture.device, "fixture-sim", "9.9.9", 3, now);
  narrowed.features = FeatureSet::from_validated({FeatureCode::ChecksumIpv4HeaderTx});
  const auto newest = fixture.registry.admit(narrowed, now);
  REQUIRE(newest.ok());

  const auto decision = fixture.registry.evaluate(make_requirement(fixture.device, "1.0.0"), now);
  CHECK(decision.kind == DecisionKind::Incompatible);
  CHECK(std::find(decision.reasons.begin(), decision.reasons.end(),
                  ReasonCode::IncompatibleFeatureAbsent) != decision.reasons.end());
  REQUIRE(decision.selected.has_value());
  CHECK(*decision.selected == newest.value().id);

  // The superseded record is still retained and reported as history, but it is
  // not the selected evidence.
  const auto with_history = fixture.registry.query(
      CapabilityQuery{fixture.device, CapabilityKind::ChecksumOffload, Tick{}, true}, now);
  REQUIRE(with_history.ok());
  bool saw_superseded = false;
  for (const auto& fact : with_history.value().facts) {
    if (fact.id == old_record.value().id) {
      CHECK(fact.state == EvidenceState::Superseded);
      saw_superseded = true;
    }
  }
  CHECK(saw_superseded);
}

OCREG_TEST(stale_evidence_is_not_current) {
  RegistryPolicy policy = make_lab_policy();
  Fixture fixture;
  fixture.policy = policy;
  Registry registry(policy);

  const Tick observed = Tick{1'000'000'000ull};
  const auto outcome = registry.admit(
      make_request(fixture.device, "fixture-sim", "1.4.0", 1, observed), observed);
  REQUIRE(outcome.ok());
  CHECK(query_kind(registry, fixture.device, observed) == DecisionKind::Compatible);

  // One tick past the source freshness bound.
  const Tick later = Tick{observed.value() + policy.default_max_age.value() + 1};
  CHECK(query_kind(registry, fixture.device, later) == DecisionKind::Unknown);

  const auto decision = registry.evaluate(make_requirement(fixture.device, "1.0.0"), later);
  CHECK(decision.kind == DecisionKind::Unknown);
  CHECK(std::find(decision.reasons.begin(), decision.reasons.end(),
                  ReasonCode::UnknownStaleEvidence) != decision.reasons.end());
  CHECK(decision.selected.has_value() == false);

  // Operator declarations never expire, and that is a policy statement, not a
  // property of the registry.
  RegistryPolicy operator_policy = policy;
  Registry operated(operator_policy);
  const auto durable = operated.admit(
      make_request(fixture.device, "operator-declared", "1.4.0", 1, observed), observed);
  REQUIRE(durable.ok());
  const Tick much_later = Tick{observed.value() + 1000 * kSecond.value()};
  CHECK(query_kind(operated, fixture.device, much_later) == DecisionKind::Compatible);
}

OCREG_TEST(a_validity_window_ends_the_fact) {
  Fixture fixture;
  const Tick now = kSecond;
  AdmissionRequest request = make_request(fixture.device, "fixture-sim", "1.4.0", 1, now);
  request.valid_until = Tick{now.value() + 10};
  const auto outcome = fixture.registry.admit(request, now);
  REQUIRE(outcome.ok());
  CHECK(query_kind(fixture.registry, fixture.device, Tick{now.value() + 10}) ==
        DecisionKind::Compatible);
  CHECK(query_kind(fixture.registry, fixture.device, Tick{now.value() + 11}) == DecisionKind::Unknown);
}

OCREG_TEST(missing_evidence_is_never_zero_false_or_success) {
  Fixture fixture;
  const Tick now = kSecond;
  const auto outcome = fixture.registry.admit(
      make_request(fixture.device, "fixture-sim", "1.4.0", 1, now), now);
  REQUIRE(outcome.ok());

  // The device never reported a bandwidth limit. A requirement on it must be
  // an explicit unknown, not "zero, therefore below".
  CapabilityRequirement requirement = make_requirement(fixture.device, "1.0.0");
  requirement.required_limits.clear();
  requirement.required_limits.push_back(
      LimitRequirement{LimitCode::Bandwidth, Unit{UnitCode::BitPerSecond, UnitScale::Decimal, 3},
                       1000});
  const auto decision = fixture.registry.evaluate(requirement, now);
  CHECK(decision.kind == DecisionKind::Unknown);
  CHECK(std::find(decision.reasons.begin(), decision.reasons.end(),
                  ReasonCode::UnknownLimitNotReported) != decision.reasons.end());

  // A requirement on a capability with no evidence at all is unknown, not
  // incompatible.
  CapabilityRequirement absent = make_requirement(fixture.device, "1.0.0");
  absent.capability = CapabilityKind::Timestamping;
  absent.required_features = FeatureSet{};
  absent.required_limits.clear();
  const auto absent_decision = fixture.registry.evaluate(absent, now);
  CHECK(absent_decision.kind == DecisionKind::Unknown);
  CHECK(std::find(absent_decision.reasons.begin(), absent_decision.reasons.end(),
                  ReasonCode::UnknownNoEvidence) != absent_decision.reasons.end());

  // No firmware version reported is unknown, not "too old".
  AdmissionRequest no_firmware =
      make_request(fixture.device, "fixture-sim", "1.4.0", 2, now);
  no_firmware.firmware_version.reset();
  no_firmware.firmware_generation = FirmwareGeneration{};
  const auto second = fixture.registry.admit(no_firmware, now);
  REQUIRE(second.ok());
  CapabilityRequirement firmware_requirement = make_requirement(fixture.device, "1.0.0");
  firmware_requirement.minimum_firmware_version = *SemVer::parse("1.0.0");
  const auto firmware_decision = fixture.registry.evaluate(firmware_requirement, now);
  CHECK(firmware_decision.kind == DecisionKind::Unknown);
  CHECK(std::find(firmware_decision.reasons.begin(), firmware_decision.reasons.end(),
                  ReasonCode::UnknownFirmwareGenerationAbsent) != firmware_decision.reasons.end());
}

OCREG_TEST(incompatible_and_unknown_are_distinct_and_ordered) {
  Fixture fixture;
  const Tick now = kSecond;
  const auto outcome = fixture.registry.admit(
      make_request(fixture.device, "fixture-sim", "1.4.0", 1, now), now);
  REQUIRE(outcome.ok());

  // A version below the requirement is positively incompatible.
  const auto too_low = fixture.registry.evaluate(make_requirement(fixture.device, "2.0.0"), now);
  CHECK(too_low.kind == DecisionKind::Incompatible);
  CHECK(std::find(too_low.reasons.begin(), too_low.reasons.end(),
                  ReasonCode::IncompatibleVersionTooLow) != too_low.reasons.end());

  // A limit below the requirement is positively incompatible.
  CapabilityRequirement high_mtu = make_requirement(fixture.device, "1.0.0");
  high_mtu.required_limits.clear();
  high_mtu.required_limits.push_back(
      LimitRequirement{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 64000});
  const auto mtu_decision = fixture.registry.evaluate(high_mtu, now);
  CHECK(mtu_decision.kind == DecisionKind::Incompatible);
  CHECK(std::find(mtu_decision.reasons.begin(), mtu_decision.reasons.end(),
                  ReasonCode::IncompatibleLimitBelowRequirement) != mtu_decision.reasons.end());

  // A requirement expressed in a different dimension is an explicit unknown.
  CapabilityRequirement wrong_unit = make_requirement(fixture.device, "1.0.0");
  wrong_unit.required_limits.clear();
  wrong_unit.required_limits.push_back(
      LimitRequirement{LimitCode::Latency, unity(UnitCode::NanoSecond), 1000});
  const auto unit_decision = fixture.registry.evaluate(wrong_unit, now);
  CHECK(unit_decision.kind == DecisionKind::Unknown);
  CHECK(std::find(unit_decision.reasons.begin(), unit_decision.reasons.end(),
                  ReasonCode::UnknownLimitNotReported) != unit_decision.reasons.end());
}

OCREG_TEST(numeric_limits_use_exact_units_and_checked_arithmetic) {
  Fixture fixture;
  const Tick now = kSecond;
  AdmissionRequest request = make_request(fixture.device, "fixture-sim", "1.4.0", 1, now);
  // 9 kibit/s expressed exactly, plus an MTU in kibibytes.
  request.limits = LimitSet::from_validated(
      {LimitValue{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 9000},
       LimitValue{LimitCode::Bandwidth, Unit{UnitCode::BitPerSecond, UnitScale::Binary, 1},
                  9}});
  const auto outcome = fixture.registry.admit(request, now);
  REQUIRE(outcome.ok());

  // 1000 bit/s <= 9 kibibit/s exactly, with a non-trivial conversion.
  CapabilityRequirement requirement = make_requirement(fixture.device, "1.0.0");
  requirement.required_limits.clear();
  requirement.required_limits.push_back(
      LimitRequirement{LimitCode::Bandwidth, unity(UnitCode::BitPerSecond), 1000});
  const auto decision = fixture.registry.evaluate(requirement, now);
  CHECK(decision.kind == DecisionKind::Compatible);

  // An inexact conversion is an explicit unknown, never a rounded comparison.
  CapabilityRequirement inexact = make_requirement(fixture.device, "1.0.0");
  inexact.required_limits.clear();
  inexact.required_limits.push_back(
      LimitRequirement{LimitCode::Bandwidth, Unit{UnitCode::BitPerSecond, UnitScale::Decimal, 1}, 1});
  const auto inexact_decision = fixture.registry.evaluate(inexact, now);
  CHECK(inexact_decision.kind == DecisionKind::Unknown);
  CHECK(std::find(inexact_decision.reasons.begin(), inexact_decision.reasons.end(),
                  ReasonCode::UnknownInexactUnitConversion) != inexact_decision.reasons.end());

  // A declared limit with a value above the source freshness bound is still
  // compared with checked arithmetic, so the extremes do not wrap.
  AdmissionRequest extreme = make_request(fixture.device, "fixture-sim", "1.4.0", 2, now);
  extreme.limits = LimitSet::from_validated({LimitValue{
      LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte),
      std::numeric_limits<std::int64_t>::max()}});
  const auto extreme_outcome = fixture.registry.admit(extreme, now);
  REQUIRE(extreme_outcome.ok());
  CapabilityRequirement extremes = make_requirement(fixture.device, "1.0.0");
  extremes.required_limits.clear();
  extremes.required_limits.push_back(LimitRequirement{
      LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte),
      std::numeric_limits<std::int64_t>::max()});
  CHECK(fixture.registry.evaluate(extremes, now).kind == DecisionKind::Compatible);
}

OCREG_TEST(equal_authority_disagreement_is_never_fabricated_into_a_fact) {
  RegistryPolicy policy = make_lab_policy();
  // Two distinct sources with identical authority.
  const auto second = SourceId::parse("fixture-sim-b");
  REQUIRE(second.has_value());
  SourcePolicy extra;
  extra.id = *second;
  extra.kind = SourceKind::Synthetic;
  extra.authority = AuthorityRank::Synthetic;
  extra.max_age = kSecond;
  policy.sources.push_back(extra);
  std::sort(policy.sources.begin(), policy.sources.end());

  Registry registry(policy);
  const auto device = reference("sim-nic-200", 0, 1);
  const Tick now = kSecond;
  const auto left = registry.admit(make_request(device, "fixture-sim", "1.4.0", 1, now), now);
  REQUIRE(left.ok());
  CHECK(left.value().state == EvidenceState::Active);
  CHECK(!left.value().conflict.has_value());

  AdmissionRequest right_request = make_request(device, "fixture-sim-b", "1.9.0", 1, now);
  right_request.limits = LimitSet::from_validated(
      {LimitValue{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 1500}});
  const auto right = registry.admit(right_request, now);
  REQUIRE(right.ok());
  CHECK(right.value().conflict.has_value());

  CHECK(query_kind(registry, device, now) == DecisionKind::Conflicted);
  const auto decision = registry.evaluate(make_requirement(device, "1.0.0"), now);
  CHECK(decision.kind == DecisionKind::Conflicted);
  CHECK(decision.conflict.has_value());
  CHECK(!decision.selected.has_value());
  CHECK(std::find(decision.reasons.begin(), decision.reasons.end(),
                  ReasonCode::ConflictEqualAuthority) != decision.reasons.end());
  CHECK_EQ(decision.evidence_facts.size(), std::size_t{2});

  // An explicit operator resolution picks one member; the disagreement is still
  // retained in the conflict table.
  const auto resolution = registry.resolve_conflict(
      *decision.conflict, right.value().id, source_id("operator-declared"), now);
  REQUIRE(resolution.ok());
  const auto resolved = registry.evaluate(make_requirement(device, "3.0.0"), now);
  CHECK(resolved.kind == DecisionKind::Incompatible);
  CHECK(resolved.selected.has_value());
  CHECK(*resolved.selected == right.value().id);
  CHECK(std::find(resolved.reasons.begin(), resolved.reasons.end(),
                  ReasonCode::ConflictResolvedByResolution) != resolved.reasons.end());
  CHECK_EQ(registry.conflict_groups().size(), std::size_t{1});
  CHECK_EQ(registry.resolutions().size(), std::size_t{1});
}

OCREG_TEST(higher_authority_outranks_equal_authority_disagreement) {
  RegistryPolicy policy = make_lab_policy();
  Registry registry(policy);
  const auto device = reference("sim-nic-201", 0, 1);
  const Tick now = kSecond;

  const auto synthetic =
      registry.admit(make_request(device, "fixture-sim", "1.4.0", 1, now), now);
  REQUIRE(synthetic.ok());
  const auto relayed =
      registry.admit(make_request(device, "topology-relay", "1.0.0", 1, now), now);
  REQUIRE(relayed.ok());

  // The two sources disagree but the relayed source outranks the fixture.
  const auto decision = registry.evaluate(make_requirement(device, "1.0.0"), now);
  CHECK(decision.kind == DecisionKind::Compatible);
  CHECK(decision.selected_authority == AuthorityRank::AdjacentRuntime);
  REQUIRE(decision.selected.has_value());
  CHECK(*decision.selected == relayed.value().id);

  bool saw_outranked = false;
  for (const auto& fact : decision.evidence_facts) {
    if (fact.id == synthetic.value().id) {
      CHECK(fact.state == EvidenceState::Outranked);
      saw_outranked = true;
    }
  }
  CHECK(saw_outranked);
  CHECK_EQ(registry.conflict_groups().size(), std::size_t{0});

  // Revoking the outranking source re-ranks the surviving evidence live: the
  // relayed record is fenced and the fixture record becomes current again. It
  // was never revoked, so it is not "resurrected" from an invalid state.
  const auto revoked = registry.revoke_source(source_id("topology-relay"), now);
  REQUIRE(revoked.ok());
  const auto after = registry.evaluate(make_requirement(device, "1.0.0"), now);
  CHECK(after.kind == DecisionKind::Compatible);
  CHECK(after.selected_authority == AuthorityRank::Synthetic);
  REQUIRE(after.selected.has_value());
  CHECK(*after.selected == synthetic.value().id);
  bool relay_fenced = false;
  for (const auto& fact : after.evidence_facts) {
    if (fact.id == relayed.value().id) {
      CHECK(fact.state == EvidenceState::Fenced);
      relay_fenced = true;
    }
  }
  CHECK(relay_fenced);
}

OCREG_TEST(retirement_fences_the_stream_and_a_later_generation_revives_it) {
  Fixture fixture;
  const Tick now = kSecond;
  const auto first = fixture.registry.admit(
      make_request(fixture.device, "fixture-sim", "1.4.0", 1, now), now);
  REQUIRE(first.ok());

  RetirementRequest retirement;
  retirement.device = fixture.device;
  retirement.kind = CapabilityKind::ChecksumOffload;
  retirement.source = source_id("fixture-sim");
  retirement.generation = RecordGeneration(2);
  retirement.retired_at = now;
  retirement.reason = ReasonCode::UnknownCapabilityRetired;
  const auto retired = fixture.registry.retire(retirement, now);
  REQUIRE(retired.ok());
  CHECK(!retired.value().idempotent);

  CHECK(query_kind(fixture.registry, fixture.device, now) == DecisionKind::Unknown);
  const auto decision = fixture.registry.evaluate(make_requirement(fixture.device, "1.0.0"), now);
  CHECK(decision.kind == DecisionKind::Unknown);
  CHECK(std::find(decision.reasons.begin(), decision.reasons.end(),
                  ReasonCode::UnknownCapabilityRetired) != decision.reasons.end());

  // Repeating the same retirement is idempotent.
  const auto repeated = fixture.registry.retire(retirement, now);
  REQUIRE(repeated.ok());
  CHECK(repeated.value().idempotent);

  // A record at or below the tombstone generation cannot revive the stream.
  const auto blocked = fixture.registry.admit(
      make_request(fixture.device, "fixture-sim", "1.4.0", 2, now), now);
  CHECK(!blocked.ok());
  CHECK(blocked.reason() == ReasonCode::RejectedRetiredStream);

  // A strictly later generation is a new fact and is admitted.
  const auto revived = fixture.registry.admit(
      make_request(fixture.device, "fixture-sim", "1.6.0", 3, now), now);
  REQUIRE(revived.ok());
  CHECK(query_kind(fixture.registry, fixture.device, now) == DecisionKind::Compatible);

  // Retiring below the newest admitted generation is refused.
  RetirementRequest stale_retirement = retirement;
  stale_retirement.generation = RecordGeneration(3);
  const auto refused = fixture.registry.retire(stale_retirement, now);
  CHECK(!refused.ok());
  CHECK(refused.reason() == ReasonCode::RejectedSupersededGeneration);
}

OCREG_TEST(reincarnation_fences_evidence_from_the_previous_incarnation) {
  Fixture fixture;
  const Tick now = kSecond;
  const auto first = fixture.registry.admit(
      make_request(fixture.device, "fixture-sim", "1.4.0", 1, now), now);
  REQUIRE(first.ok());
  CHECK(query_kind(fixture.registry, fixture.device, now) == DecisionKind::Compatible);

  const auto next = fixture.registry.begin_device_incarnation(fixture.device.device, now);
  REQUIRE(next.ok());
  CHECK(!(next.value() == fixture.device.incarnation));

  const DeviceIncarnationRef current{fixture.device.device, next.value()};
  const auto after = fixture.registry.evaluate(make_requirement(current, "1.0.0"), now);
  CHECK(after.kind == DecisionKind::Unknown);
  CHECK(std::find(after.reasons.begin(), after.reasons.end(), ReasonCode::UnknownNoEvidence) !=
        after.reasons.end());
  CHECK(after.evidence_facts.empty());

  // Evidence about the previous incarnation is retained but fenced.
  const auto previous = fixture.registry.evaluate(make_requirement(fixture.device, "1.0.0"), now);
  CHECK(previous.kind == DecisionKind::Unknown);
  bool saw_fenced = false;
  for (const auto& fact : previous.evidence_facts) {
    if (fact.state == EvidenceState::Fenced) saw_fenced = true;
  }
  CHECK(saw_fenced);

  // New evidence for the current incarnation is current again.
  const auto revived = fixture.registry.admit(
      make_request(current, "fixture-sim", "1.6.0", 1, now), now);
  REQUIRE(revived.ok());
  CHECK(revived.value().state == EvidenceState::Active);
}

OCREG_TEST(equivalent_inputs_produce_identical_decisions_and_digests) {
  const Tick now = kSecond;
  const auto device = reference("sim-nic-300", 0, 1);
  const auto build = [now, device](Registry& registry) {
    for (std::uint64_t generation = 1; generation <= 6; ++generation) {
      const auto outcome = registry.admit(
          make_request(device, "fixture-sim", "1." + std::to_string(generation) + ".0", generation,
                       now),
          now);
      (void)outcome;
    }
  };

  Registry left(make_lab_policy());
  Registry right(make_lab_policy());
  build(left);
  build(right);

  const auto left_decision = left.evaluate(make_requirement(device, "1.3.0"), now);
  const auto right_decision = right.evaluate(make_requirement(device, "1.3.0"), now);
  CHECK(left_decision.kind == right_decision.kind);
  CHECK(left_decision.reasons == right_decision.reasons);
  CHECK(left_decision.id == right_decision.id);
  CHECK(left_decision.compute_digest() == right_decision.compute_digest());
  CHECK(left.state_digest() == right.state_digest());

  // A second evaluation of the same inputs is still identical.
  const auto repeat = left.evaluate(make_requirement(device, "1.3.0"), now);
  CHECK(repeat.id == left_decision.id);

  // Changing only the logical tick changes the digest, because the tick is an
  // input and the decision states which tick it was taken at.
  const auto later = left.evaluate(make_requirement(device, "1.3.0"), Tick{now.value() + 1});
  CHECK(!(later.id == left_decision.id) || later.kind != left_decision.kind);
}

OCREG_TEST(admission_order_does_not_change_the_accepted_state) {
  const Tick now = kSecond;
  const auto device = reference("sim-nic-301", 0, 1);
  std::vector<AdmissionRequest> requests;
  for (std::uint64_t generation = 1; generation <= 8; ++generation) {
    requests.push_back(make_request(device, "fixture-sim",
                                    "1." + std::to_string(generation) + ".0", generation, now));
  }

  Registry forward(make_lab_policy());
  Registry backward(make_lab_policy());
  for (const auto& request : requests) (void)forward.admit(request, now);
  for (auto it = requests.rbegin(); it != requests.rend(); ++it) (void)backward.admit(*it, now);

  // The accepted (current) state is identical regardless of delivery order.
  const auto forward_query =
      forward.query(CapabilityQuery{device, CapabilityKind::ChecksumOffload, Tick{}, true}, now);
  const auto backward_query =
      backward.query(CapabilityQuery{device, CapabilityKind::ChecksumOffload, Tick{}, true}, now);
  REQUIRE(forward_query.ok());
  REQUIRE(backward_query.ok());
  CHECK(forward_query.value().selected == backward_query.value().selected);
  CHECK_EQ(forward.stats(now).records_active, backward.stats(now).records_active);
  CHECK_EQ(forward.stats(now).records_total, backward.stats(now).records_total);
  CHECK(forward.evaluate(make_requirement(device, "1.0.0"), now).id ==
        backward.evaluate(make_requirement(device, "1.0.0"), now).id);

  // Out-of-order delivery is refused rather than silently reordered, and the
  // refusal is retained as explicit rejected evidence. That is an observable,
  // accounted difference in history, not a difference in the current fact.
  const auto forward_stats = forward.stats(now);
  const auto backward_stats = backward.stats(now);
  CHECK_EQ(forward_stats.records_superseded, std::uint64_t{7});
  CHECK_EQ(forward_stats.records_rejected, std::uint64_t{0});
  CHECK_EQ(backward_stats.records_superseded, std::uint64_t{0});
  CHECK_EQ(backward_stats.records_rejected, std::uint64_t{7});
  CHECK_EQ(forward_stats.admissions_rejected, std::uint64_t{0});
  CHECK_EQ(backward_stats.admissions_rejected, std::uint64_t{7});
}

OCREG_TEST(bounded_eviction_is_observable_and_accounted_for) {
  RegistryPolicy policy = make_lab_policy();
  policy.limits.max_records_per_stream = 2;
  policy.limits.max_eviction_ledger = 8;
  Registry registry(policy);
  const auto device = reference("sim-nic-400", 0, 1);
  const Tick now = kSecond;

  for (std::uint64_t generation = 1; generation <= 10; ++generation) {
    const auto outcome = registry.admit(
        make_request(device, "fixture-sim", "1." + std::to_string(generation) + ".0", generation,
                     now),
        now);
    REQUIRE(outcome.ok());
  }

  const auto stats = registry.stats(now);
  CHECK_EQ(stats.records_total, std::uint64_t{2});
  CHECK_EQ(stats.records_evicted, std::uint64_t{8});
  const auto ledger = registry.eviction_ledger();
  CHECK_EQ(ledger.size(), std::size_t{8});
  for (const auto& entry : ledger) {
    CHECK(entry.evicted_at == now);
    CHECK(entry.reason == ReasonCode::EvictedSuperseded ||
          entry.reason == ReasonCode::EvictedBudgetPressure);
  }

  // The ledger itself is bounded, and its own truncation is accounted.
  RegistryPolicy small = policy;
  small.limits.max_eviction_ledger = 3;
  Registry bounded(small);
  for (std::uint64_t generation = 1; generation <= 10; ++generation) {
    REQUIRE(bounded.admit(make_request(device, "fixture-sim",
                                       "1." + std::to_string(generation) + ".0", generation, now),
                          now)
                .ok());
  }
  const auto bounded_stats = bounded.stats(now);
  CHECK_EQ(bounded.eviction_ledger().size(), std::size_t{3});
  CHECK_EQ(bounded_stats.eviction_ledger_dropped, std::uint64_t{5});
  CHECK_EQ(bounded_stats.records_evicted, std::uint64_t{8});
}

OCREG_TEST(a_full_record_budget_refuses_rather_than_discarding_current_evidence) {
  RegistryPolicy policy = make_lab_policy();
  policy.limits.max_records = 2;
  policy.limits.max_records_per_stream = 2;
  Registry registry(policy);
  const Tick now = kSecond;

  const auto first = registry.admit(
      make_request(reference("sim-nic-401", 0, 1), "fixture-sim", "1.0.0", 1, now), now);
  REQUIRE(first.ok());
  const auto second = registry.admit(
      make_request(reference("sim-nic-402", 0, 1), "fixture-sim", "1.0.0", 1, now), now);
  REQUIRE(second.ok());

  const auto third = registry.admit(
      make_request(reference("sim-nic-403", 0, 1), "fixture-sim", "1.0.0", 1, now), now);
  CHECK(!third.ok());
  CHECK(third.reason() == ReasonCode::RejectedRecordBudgetExhausted);

  // The refusal did not damage the two records that are already current.
  CHECK(query_kind(registry, reference("sim-nic-401", 0, 1), now) == DecisionKind::Compatible);
  CHECK(query_kind(registry, reference("sim-nic-402", 0, 1), now) == DecisionKind::Compatible);
  CHECK_EQ(registry.stats(now).records_total, std::uint64_t{2});
}

OCREG_TEST(unknown_sources_and_untrusted_sources_are_refused) {
  Fixture fixture;
  const Tick now = kSecond;
  const auto unknown = fixture.registry.admit(
      make_request(fixture.device, "not-configured", "1.0.0", 1, now), now);
  CHECK(!unknown.ok());
  CHECK(unknown.reason() == ReasonCode::RejectedUnknownSource);

  const auto untrusted = fixture.registry.admit(
      make_request(fixture.device, "topology-relay", "1.0.0", 1, now), now);
  REQUIRE(untrusted.ok());
  const auto revoked = fixture.registry.revoke_source(source_id("topology-relay"), now);
  REQUIRE(revoked.ok());
  const auto after_revocation = fixture.registry.admit(
      make_request(fixture.device, "topology-relay", "1.1.0", 2, now), now);
  CHECK(!after_revocation.ok());
  CHECK(after_revocation.reason() == ReasonCode::RejectedSourceRevoked);
  const auto restored = fixture.registry.restore_source(source_id("topology-relay"), now);
  REQUIRE(restored.ok());
  CHECK(fixture.registry
            .admit(make_request(fixture.device, "topology-relay", "1.2.0", 3, now), now)
            .ok());
}

OCREG_TEST(observations_outside_the_horizon_or_ahead_of_the_clock_are_refused) {
  RegistryPolicy policy = make_lab_policy();
  policy.retention_horizon = Tick{100};
  policy.max_future_skew = Tick{10};
  Registry registry(policy);
  const auto device = reference("sim-nic-500", 0, 1);

  const auto too_old = registry.admit(make_request(device, "fixture-sim", "1.0.0", 1, Tick{1}),
                                      Tick{1000});
  CHECK(!too_old.ok());
  CHECK(too_old.reason() == ReasonCode::RejectedBeyondRetentionHorizon);

  const auto ahead =
      registry.admit(make_request(device, "fixture-sim", "1.0.0", 1, Tick{1000}), Tick{950});
  CHECK(!ahead.ok());
  CHECK(ahead.reason() == ReasonCode::RejectedFutureObservation);

  const auto inverted = [&]() {
    AdmissionRequest request = make_request(device, "fixture-sim", "1.0.0", 1, Tick{1000});
    request.valid_until = Tick{999};
    return registry.admit(request, Tick{1000});
  }();
  CHECK(!inverted.ok());
  CHECK(inverted.reason() == ReasonCode::RejectedValidityWindowInverted);

  const auto zero_generation = [&]() {
    AdmissionRequest request = make_request(device, "fixture-sim", "1.0.0", 0, Tick{1000});
    return registry.admit(request, Tick{1000});
  }();
  CHECK(!zero_generation.ok());
  CHECK(zero_generation.reason() == ReasonCode::RejectedGenerationRegression);
}

OCREG_TEST(restart_fences_evidence_and_never_resurrects_authority) {
  const Tick now = kSecond;
  RegistryPolicy policy = make_lab_policy();
  Registry original(policy);
  const auto device = reference("sim-nic-600", 0, 1);
  REQUIRE(original.admit(make_request(device, "fixture-sim", "1.4.0", 1, now), now).ok());
  CHECK(query_kind(original, device, now) == DecisionKind::Compatible);

  const auto snapshot = original.snapshot_state();
  REQUIRE(snapshot.ok());
  CHECK(snapshot.value().records.size() == 1);

  Registry restored(policy);
  const auto summary = restored.adopt_state(snapshot.value(), now);
  REQUIRE(summary.ok());
  CHECK(summary.value().boot_epoch.value() == snapshot.value().boot_epoch.value() + 1);
  CHECK_EQ(summary.value().records_fenced, std::uint64_t{1});
  CHECK_EQ(summary.value().records_carried_forward, std::uint64_t{0});

  // The evidence survived as history but not as authority.
  CHECK(query_kind(restored, device, now) == DecisionKind::Unknown);
  const auto decision = restored.evaluate(make_requirement(device, "1.0.0"), now);
  CHECK(decision.kind == DecisionKind::Unknown);
  bool saw_fenced = false;
  for (const auto& fact : decision.evidence_facts) {
    if (fact.state == EvidenceState::Fenced) saw_fenced = true;
  }
  CHECK(saw_fenced);

  // Re-attestation under the new boot epoch restores authority, and only for a
  // strictly later generation.
  const auto reattested = restored.admit(
      make_request(device, "fixture-sim", "1.5.0", 2, now), now);
  REQUIRE(reattested.ok());
  CHECK(reattested.value().state == EvidenceState::Active);
  CHECK(query_kind(restored, device, now) == DecisionKind::Compatible);
}

OCREG_TEST(durable_operator_declarations_survive_a_restart_while_dynamic_evidence_does_not) {
  const Tick now = kSecond;
  RegistryPolicy policy = make_lab_policy();
  Registry original(policy);
  const auto device = reference("sim-nic-601", 0, 1);
  REQUIRE(original.admit(make_request(device, "operator-declared", "1.4.0", 1, now), now).ok());
  REQUIRE(original.admit(make_request(device, "fixture-sim", "1.4.0", 1, now), now).ok());

  const auto snapshot = original.snapshot_state();
  REQUIRE(snapshot.ok());

  Registry restored(policy);
  const auto summary = restored.adopt_state(snapshot.value(), now);
  REQUIRE(summary.ok());
  CHECK_EQ(summary.value().records_carried_forward, std::uint64_t{1});
  CHECK_EQ(summary.value().records_fenced, std::uint64_t{1});

  const auto decision = restored.evaluate(make_requirement(device, "1.0.0"), now);
  CHECK(decision.kind == DecisionKind::Compatible);
  CHECK(decision.selected_authority == AuthorityRank::Operator);
}

OCREG_TEST(persisted_dynamic_evidence_does_not_silently_become_fresh) {
  const Tick observed = kSecond;
  RegistryPolicy policy = make_lab_policy();
  Registry original(policy);
  const auto device = reference("sim-nic-602", 0, 1);
  REQUIRE(original.admit(make_request(device, "fixture-sim", "1.4.0", 1, observed), observed).ok());

  const auto snapshot = original.snapshot_state();
  REQUIRE(snapshot.ok());

  Registry restored(policy);
  // The restart happens a long time later. The logical clock resumes no earlier
  // than the state it recovered, so the evidence is stale, not fresh.
  const Tick long_after = Tick{observed.value() + 10 * kSecond.value()};
  REQUIRE(restored.adopt_state(snapshot.value(), long_after).ok());
  CHECK(restored.logical_tick() >= long_after);

  const auto decision = restored.evaluate(make_requirement(device, "1.0.0"), long_after);
  CHECK(decision.kind == DecisionKind::Unknown);
}

OCREG_TEST(the_logical_clock_is_monotonic) {
  Fixture fixture;
  CHECK(fixture.registry.set_logical_tick(Tick{100}).ok());
  CHECK(fixture.registry.set_logical_tick(Tick{100}).ok());
  CHECK(!fixture.registry.set_logical_tick(Tick{99}).ok());
  CHECK_EQ(fixture.registry.logical_tick().value(), std::uint64_t{100});
}

OCREG_TEST(rule_generation_and_epoch_are_explicit_and_monotonic) {
  Fixture fixture;
  const Tick now = kSecond;
  const auto initial = fixture.registry.rule_generation();
  CHECK(!fixture.registry.set_rule_generation(RuleGeneration(0), now).ok());
  CHECK(fixture.registry.set_rule_generation(initial, now).ok());
  CHECK(!fixture.registry.set_rule_generation(RuleGeneration(initial.value() - 1), now).ok());
  CHECK(fixture.registry.set_rule_generation(RuleGeneration(initial.value() + 4), now).ok());
  CHECK_EQ(fixture.registry.rule_generation().value(), initial.value() + 4);

  const auto epoch = fixture.registry.epoch();
  CHECK(fixture.registry.advance_epoch(ReasonCode::AcceptedNew, now).ok());
  CHECK(fixture.registry.epoch() > epoch);
}

OCREG_TEST(queries_for_unregistered_devices_are_explicit_unknowns) {
  Fixture fixture;
  const auto result = fixture.registry.query(
      CapabilityQuery{reference("sim-unknown", 0, 7), CapabilityKind::ChecksumOffload, Tick{}, false},
      kSecond);
  CHECK(!result.ok());
  CHECK(result.reason() == ReasonCode::UnknownDeviceNotRegistered);
  // A legitimate "no evidence" answer is a success carrying an unknown code,
  // which is different from a refused operation.
  const auto absent = fixture.registry.query(
      CapabilityQuery{reference("sim-unknown", 0, 7), CapabilityKind::ChecksumOffload, Tick{}, false},
      kSecond);
  CHECK(!absent.status().ok());
}
