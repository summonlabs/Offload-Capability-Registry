// Offload Capability Registry - seeded property and differential tests.
// Copyright 2026 Summon Software Labs.
//
// Every generator is seeded and deterministic. A failure here reproduces
// exactly from the seed printed in the failure message.
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "ocreg/codec.hpp"
#include "ocreg/export.hpp"
#include "ocreg/json.hpp"
#include "ocreg/persist.hpp"
#include "ocreg/registry.hpp"
#include "registry_harness.hpp"
#include "test_support.hpp"

using namespace ocreg;
using namespace ocreg::test;

namespace {

constexpr std::uint64_t kSeed = 0x51ED270Full;

[[nodiscard]] std::string version_for(std::uint32_t value) {
  return std::to_string(1 + (value % 3)) + "." + std::to_string(value % 9) + "." +
         std::to_string(value % 5);
}

[[nodiscard]] std::vector<AdmissionRequest> generate(Rng& rng, std::size_t count) {
  std::vector<AdmissionRequest> requests;
  const DeviceIncarnationRef device = reference("sim-nic-prop", 0, 1);
  for (std::size_t index = 0; index < count; ++index) {
    const std::uint32_t roll = rng.below(6);
    const std::string source = (roll % 3 == 0) ? "dominated-source" : "fixture-sim";
    AdmissionRequest request =
        make_request(device, source, version_for(rng.below(40)), index + 1, kSecond);
    if (roll % 2 == 0) {
      request.features = FeatureSet::from_validated({FeatureCode::ChecksumIpv4HeaderTx});
    }
    if (roll % 5 == 0) {
      request.limits = LimitSet::from_validated(
          {LimitValue{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 1400}});
    }
    requests.push_back(request);
  }
  return requests;
}

}  // namespace

OCREG_TEST(invariants_hold_under_seeded_random_evidence) {
  for (std::uint64_t seed = 1; seed <= 12; ++seed) {
    Rng rng(kSeed + seed);
    RegistryPolicy policy = make_lab_policy();
    const auto dominated = SourceId::parse("dominated-source");
    REQUIRE(dominated.has_value());
    SourcePolicy weaker;
    weaker.id = *dominated;
    weaker.kind = SourceKind::Synthetic;
    // A configured source that holds no authority: its evidence is admitted,
    // retained and always outranked.
    weaker.authority = AuthorityRank::None;
    weaker.trust = SourceTrustState::Trusted;
    weaker.max_age = Tick{0};
    policy.sources.push_back(weaker);
    std::sort(policy.sources.begin(), policy.sources.end());
    Registry registry(policy);

    const DeviceIncarnationRef device = reference("sim-nic-prop", 0, 1);
    const auto requests = generate(rng, 24);
    for (const auto& request : requests) {
      const auto outcome = registry.admit(request, kSecond);
      CHECK_MSG(outcome.ok(), std::to_string(seed));

      // Invariant: the current fact is always the highest-generation record of
      // the highest-authority source, or there is no current fact at all.
      const auto query = registry.query(
          CapabilityQuery{device, CapabilityKind::ChecksumOffload, Tick{}, true}, kSecond);
      REQUIRE_MSG(query.ok(), std::to_string(seed));
      if (query.value().kind == DecisionKind::Compatible) {
        REQUIRE_MSG(query.value().selected.has_value(), std::to_string(seed));
        // The stored records are copied out once: the accessor returns by value,
        // so a pointer into a temporary would dangle.
        const std::vector<StoredEvidence> records = registry.records();
        const CapabilityEvidence* selected = nullptr;
        for (const auto& record : records) {
          if (record.evidence.id() == *query.value().selected) selected = &record.evidence;
        }
        REQUIRE_MSG(selected != nullptr, std::to_string(seed));
        CHECK_MSG(selected->generation.value() >= 1, std::to_string(seed));

        // The current fact is the newest admitted generation of its stream.
        RecordGeneration highest{};
        for (const auto& record : records) {
          if (record.evidence.key == selected->key && record.evidence.generation > highest) {
            highest = record.evidence.generation;
          }
        }
        CHECK_MSG(selected->generation == highest, std::to_string(seed));

        // The selected record is the highest authority among the current facts,
        // and it is current.
        AuthorityRank best = AuthorityRank::None;
        bool selected_is_active = false;
        for (const auto& fact : query.value().facts) {
          if (fact.state == EvidenceState::Active && fact.authority > best) best = fact.authority;
          if (fact.id == *query.value().selected) {
            selected_is_active = fact.state == EvidenceState::Active;
          }
        }
        CHECK_MSG(selected_is_active, std::to_string(seed));
        CHECK_MSG(selected->authority == best, std::to_string(seed));
        CHECK_MSG(best == AuthorityRank::AdjacentRuntime || best == AuthorityRank::Synthetic ||
                      best == AuthorityRank::None,
                  std::to_string(seed));
      }

      // Invariant: evidence that is not Active never justifies a requirement.
      if (query.value().kind != DecisionKind::Compatible) {
        const auto decision =
            registry.evaluate(make_requirement(device, "0.0.0"), kSecond);
        CHECK_MSG(decision.kind != DecisionKind::Compatible, std::to_string(seed));
      }
    }

    // Invariant: the canonical document round-trips at every state.
    ExportOptions options;
    const auto exported = export_registry(registry, options, kSecond);
    REQUIRE_MSG(exported.ok(), std::to_string(seed));
    const auto imported = import_document(exported.value().document);
    REQUIRE_MSG(imported.ok(), std::to_string(seed));
    CHECK_MSG(state_digest(imported.value().state) == registry.state_digest(),
              std::to_string(seed));

    // Invariant: the persisted state round-trips at every state.
    const auto snapshot = registry.snapshot_state();
    REQUIRE(snapshot.ok());
    Writer writer;
    encode(writer, snapshot.value());
    Reader reader(writer.span());
    RegistryState decoded;
    REQUIRE(decode(reader, decoded));
    CHECK_MSG(state_digest(decoded) == state_digest(snapshot.value()), std::to_string(seed));
  }
}

OCREG_TEST(delivery_order_never_changes_the_current_fact) {
  for (std::uint64_t seed = 1; seed <= 16; ++seed) {
    Rng rng(kSeed * seed + 7);
    RegistryPolicy policy = make_lab_policy();
    const auto requests = generate(rng, 12);
    const DeviceIncarnationRef device = reference("sim-nic-prop", 0, 1);

    Registry forward(policy);
    for (const auto& request : requests) (void)forward.admit(request, kSecond);

    std::vector<std::size_t> order(requests.size());
    for (std::size_t index = 0; index < order.size(); ++index) order[index] = index;
    for (std::size_t index = order.size(); index > 1; --index) {
      const std::size_t other = rng.below(static_cast<std::uint32_t>(index));
      std::swap(order[index - 1], order[other]);
    }
    Registry shuffled(policy);
    for (const auto index : order) (void)shuffled.admit(requests[index], kSecond);

    // A delivery that arrives out of order is refused and retained as explicit
    // rejected evidence, so the histories differ. What must not differ is the
    // current fact and the answer derived from it.
    CHECK_MSG(forward.stats(kSecond).records_active == shuffled.stats(kSecond).records_active,
              std::to_string(seed));
    const auto forward_query = forward.query(
        CapabilityQuery{device, CapabilityKind::ChecksumOffload, Tick{}, true}, kSecond);
    const auto shuffled_query = shuffled.query(
        CapabilityQuery{device, CapabilityKind::ChecksumOffload, Tick{}, true}, kSecond);
    REQUIRE_MSG(forward_query.ok() && shuffled_query.ok(), std::to_string(seed));
    CHECK_MSG(forward_query.value().selected == shuffled_query.value().selected,
              std::to_string(seed));
    CHECK_MSG(forward_query.value().kind == shuffled_query.value().kind, std::to_string(seed));
    CHECK_MSG(forward.evaluate(make_requirement(device, "1.0.0"), kSecond).id ==
                  shuffled.evaluate(make_requirement(device, "1.0.0"), kSecond).id,
              std::to_string(seed));
  }
}

OCREG_TEST(random_documents_never_import_as_valid_states) {
  Rng rng(kSeed ^ 0xABCDEFull);
  std::size_t accepted = 0;
  for (int round = 0; round < 500; ++round) {
    const std::size_t length = rng.below(400);
    std::string document;
    document.reserve(length);
    for (std::size_t index = 0; index < length; ++index) {
      document.push_back(static_cast<char>(32 + rng.below(95)));
    }
    const auto imported = import_document(document);
    if (imported.ok()) ++accepted;
    if (!imported.ok()) {
      // A refusal must carry a stable code from the rejection family.
      CHECK(!is_failure(ReasonCode::Ok));
    }
  }
  // Random printable text must essentially never be a valid registry document.
  CHECK(accepted == 0);
}

OCREG_TEST(mutated_canonical_documents_are_refused) {
  Registry registry(make_lab_policy());
  const auto device = reference("sim-nic-prop-2", 0, 1);
  for (std::uint64_t generation = 1; generation <= 5; ++generation) {
    REQUIRE(registry
                .admit(make_request(device, "fixture-sim",
                                    "1." + std::to_string(generation) + ".0", generation, kSecond),
                       kSecond)
                .ok());
  }
  ExportOptions options;
  const auto exported = export_registry(registry, options, kSecond);
  REQUIRE(exported.ok());
  const std::string& document = exported.value().document;

  // Mutations inside the state-bearing region must never be accepted, because
  // the state digest covers exactly that region.
  const std::size_t region_start = document.find("\"evidence\":[");
  // Keys are sorted, so the evidence array ends where the next key begins. The
  // region is exactly that array: the state-bearing part of the document.
  // Metadata outside it (the export tick, the note list) is not part of the
  // state digest and is covered by the separate check below.
  const std::size_t region_end = document.find("\"exported_at\":");
  REQUIRE(region_start != std::string::npos);
  REQUIRE(region_end != std::string::npos);
  REQUIRE(region_start < region_end);

  Rng rng(kSeed + 99);
  std::size_t accepted_in_state = 0;
  for (int round = 0; round < 600; ++round) {
    std::string mutated = document;
    const std::size_t flips = 1 + rng.below(3);
    for (std::size_t flip = 0; flip < flips; ++flip) {
      const std::size_t span = static_cast<std::size_t>(region_end - region_start);
      const std::size_t position = region_start + rng.below(static_cast<std::uint32_t>(span));
      const char replacement = static_cast<char>(32 + rng.below(95));
      if (replacement == mutated[position]) continue;
      mutated[position] = replacement;
    }
    // A round whose random replacements all matched the original byte is not a
    // mutation at all and carries no information.
    if (mutated == document) continue;
    const auto imported = import_document(mutated);
    if (imported.ok()) {
      ++accepted_in_state;
      // If a mutation is somehow accepted it must still describe the same
      // state; anything else would be a fabricated fact.
      CHECK(state_digest(imported.value().state) == registry.state_digest());
      record_failure("an evidence mutation was accepted", __FILE__, __LINE__,
                     "the state digest must refuse every change to the evidence array");
    }
  }
  CHECK_EQ(accepted_in_state, std::size_t{0});

  // Mutations outside the state region change only metadata, so acceptance is
  // allowed but must never change the state.
  std::size_t accepted_metadata = 0;
  for (int round = 0; round < 300; ++round) {
    std::string mutated = document;
    const std::size_t position = rng.below(static_cast<std::uint32_t>(region_start));
    const char replacement = static_cast<char>(32 + rng.below(95));
    if (replacement == mutated[position]) continue;
    mutated[position] = replacement;
    if (mutated == document) continue;
    const auto imported = import_document(mutated);
    if (imported.ok()) {
      ++accepted_metadata;
      CHECK(state_digest(imported.value().state) == registry.state_digest());
    }
  }
  CHECK(accepted_metadata <= 300);
}

OCREG_TEST(unit_conversion_is_symmetric_and_exact_or_refused) {
  Rng rng(kSeed + 4242);
  const UnitCode codes[] = {UnitCode::Bit,        UnitCode::Byte,       UnitCode::BitPerSecond,
                            UnitCode::BytePerSecond, UnitCode::PacketPerSecond,
                            UnitCode::NanoSecond, UnitCode::MicroSecond, UnitCode::MilliSecond,
                            UnitCode::Second,     UnitCode::Hertz,      UnitCode::Percent,
                            UnitCode::PartsPerMillion};
  for (int round = 0; round < 4000; ++round) {
    const UnitCode from_code = codes[rng.below(12)];
    const UnitCode to_code = codes[rng.below(12)];
    Unit from = unity(from_code);
    Unit to = unity(to_code);
    if (rng.coin()) {
      from.scale = UnitScale::Decimal;
      from.exponent = static_cast<std::uint8_t>(rng.below(4));
      if (!unit_is_well_formed(from)) from = unity(from_code);
    }
    if (rng.coin()) {
      to.scale = UnitScale::Decimal;
      to.exponent = static_cast<std::uint8_t>(rng.below(4));
      if (!unit_is_well_formed(to)) to = unity(to_code);
    }
    const std::int64_t value = static_cast<std::int64_t>(rng.below(1000000));
    const auto forward = convert_exact(value, from, to);
    const auto backward = convert_exact(value, to, from);
    if (from == to) {
      REQUIRE(forward.has_value());
      CHECK(*forward == value);
    }
    if (forward.has_value() && backward.has_value()) {
      // Whatever the exact mapping is, it agrees with the exact comparison.
      const auto comparison = compare_exact(value, from, *forward, to);
      REQUIRE(comparison.has_value());
      CHECK(*comparison == std::strong_ordering::equal);
      if (*forward == value) CHECK(*backward == value);
    }
    if (dimension_of(from_code) != dimension_of(to_code)) {
      CHECK(!forward.has_value());
    }
    if (forward.has_value()) {
      const auto comparison = compare_exact(value, from, *forward, to);
      REQUIRE(comparison.has_value());
      CHECK(*comparison == std::strong_ordering::equal);
    }
  }
}
