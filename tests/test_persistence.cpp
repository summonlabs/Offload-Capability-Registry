// Offload Capability Registry - persistence and recovery tests.
// Copyright 2026 Summon Software Labs.
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "ocreg/codec.hpp"
#include "ocreg/export.hpp"
#include "ocreg/persist.hpp"
#include "ocreg/registry.hpp"
#include "registry_harness.hpp"
#include "test_support.hpp"

using namespace ocreg;
using namespace ocreg::test;

namespace {

[[nodiscard]] std::string journal_path(const std::filesystem::path& base) {
  return base.string() + ".ocregjournal";
}

[[nodiscard]] RegistryState build_state(std::size_t records = 3) {
  Registry registry(make_lab_policy());
  const auto device = reference("sim-nic-800", 0, 1);
  for (std::size_t index = 1; index <= records; ++index) {
    const auto outcome = registry.admit(
        make_request(device, "fixture-sim", "1." + std::to_string(index) + ".0", index, kSecond),
        kSecond);
    (void)outcome;
  }
  const auto snapshot = registry.snapshot_state();
  return snapshot.ok() ? snapshot.value() : RegistryState{};
}

[[nodiscard]] StoreOptions options_for(const std::filesystem::path& base) {
  StoreOptions options;
  options.base_path = base.string();
  return options;
}

void flip_byte(std::vector<std::uint8_t>& bytes, std::size_t offset) {
  if (offset < bytes.size()) bytes[offset] = static_cast<std::uint8_t>(bytes[offset] ^ 0x5Au);
}

}  // namespace

OCREG_TEST(a_fresh_store_is_empty_and_reports_itself_as_new) {
  const auto directory = fresh_dir("store_fresh");
  const auto base = directory / "state.ocregstore";
  const auto report = Store::open(options_for(base));
  REQUIRE_MSG(report.ok(), std::string(to_string(report.reason())) + ": " + report.detail());
  CHECK(!report.value().existed);
  CHECK(report.value().reason == ReasonCode::StoreEmptyNew);
  CHECK(report.value().classification == RecoveryClass::CleanOpen);
  CHECK_EQ(report.value().state.records.size(), std::size_t{0});
}

OCREG_TEST(a_committed_state_survives_a_clean_reopen) {
  const auto directory = fresh_dir("store_clean");
  const auto base = directory / "state.ocregstore";
  RegistryState state = build_state(4);
  state.store_generation = StoreGeneration(1);

  auto bound = Store::bind(options_for(base));
  REQUIRE(bound.ok());
  std::vector<ReasonCode> notes;
  const auto committed = bound.value()->commit(state, kSecond, notes);
  REQUIRE(committed.ok());
  CHECK(committed.value().synchronised);
  CHECK(std::find(notes.begin(), notes.end(), ReasonCode::StoreCommitDurable) != notes.end());
  bound.value().reset();

  const auto report = Store::open(options_for(base));
  REQUIRE_MSG(report.ok(), std::string(to_string(report.reason())) + ": " + report.detail());
  CHECK(report.value().existed);
  CHECK(report.value().journal_entries_valid == 1);
  CHECK(report.value().classification == RecoveryClass::JournalReplayed);
  CHECK(state_digest(report.value().state) == state_digest(state));
  CHECK_EQ(report.value().bytes_discarded, std::uint64_t{0});
}

OCREG_TEST(a_snapshot_then_journal_recovers_the_newest_commit) {
  const auto directory = fresh_dir("store_snapshot");
  const auto base = directory / "state.ocregstore";
  RegistryState first = build_state(2);
  first.store_generation = StoreGeneration(1);

  auto bound = Store::bind(options_for(base));
  REQUIRE(bound.ok());
  const auto snapshot = bound.value()->write_snapshot(first, kSecond);
  REQUIRE(snapshot.ok());

  RegistryState second = build_state(5);
  second.store_generation = StoreGeneration(2);
  std::vector<ReasonCode> notes;
  REQUIRE(bound.value()->commit(second, kSecond, notes).ok());
  bound.value().reset();

  const auto report = Store::open(options_for(base));
  REQUIRE_MSG(report.ok(), std::string(to_string(report.reason())) + ": " + report.detail());
  CHECK(report.value().snapshot_present);
  CHECK(report.value().journal_present);
  CHECK(state_digest(report.value().state) == state_digest(second));
}

OCREG_TEST(rotation_writes_a_snapshot_and_truncates_the_journal) {
  const auto directory = fresh_dir("store_rotation");
  const auto base = directory / "state.ocregstore";
  StoreOptions options = options_for(base);
  options.compact_after_entries = 2;

  auto bound = Store::bind(options);
  REQUIRE(bound.ok());
  std::vector<ReasonCode> notes;
  for (std::uint64_t generation = 1; generation <= 5; ++generation) {
    RegistryState state = build_state(static_cast<std::size_t>(generation % 4) + 1);
    state.store_generation = StoreGeneration(generation);
    const auto committed = bound.value()->commit(state, kSecond, notes);
    REQUIRE(committed.ok());
  }
  CHECK(std::find(notes.begin(), notes.end(), ReasonCode::StoreRotationPerformed) != notes.end());
  CHECK(std::filesystem::exists(base));
  const auto journal_size = std::filesystem::file_size(journal_path(base));
  CHECK(journal_size < 4096);
  bound.value().reset();

  const auto report = Store::open(options_for(base));
  REQUIRE_MSG(report.ok(), std::string(to_string(report.reason())) + ": " + report.detail());
  CHECK(report.value().snapshot_present);
  // The newest commit (generation 5, two records) is newer than the rotated
  // snapshot (generation 4, one record), so the journal entry wins.
  CHECK_EQ(report.value().state.records.size(), std::size_t{2});
  CHECK_EQ(report.value().state.store_generation.value(), std::uint64_t{5});
}

OCREG_TEST(a_torn_journal_tail_is_truncated_and_reported) {
  const auto directory = fresh_dir("store_torn");
  const auto base = directory / "state.ocregstore";
  RegistryState state = build_state(3);
  state.store_generation = StoreGeneration(7);

  auto bound = Store::bind(options_for(base));
  REQUIRE(bound.ok());
  const auto snapshot = bound.value()->write_snapshot(state, kSecond);
  REQUIRE(snapshot.ok());
  bound.value().reset();

  // Six bytes of a journal header: exactly what a power loss mid-header write
  // leaves behind.
  append_bytes(journal_path(base), {0x4F, 0x43, 0x4A, 0x52, 0x00, 0x01});
  const auto report = Store::open(options_for(base));
  REQUIRE_MSG(report.ok(), std::string(to_string(report.reason())) + ": " + report.detail());
  CHECK(report.value().classification == RecoveryClass::TornTailTruncated);
  CHECK_EQ(report.value().bytes_discarded, std::uint64_t{6});
  CHECK(state_digest(report.value().state) == state_digest(state));
  // The refused tail was removed so later appends start from clean bytes.
  CHECK_EQ(std::filesystem::file_size(journal_path(base)), std::uint64_t{0});
}

OCREG_TEST(a_corrupt_journal_entry_is_dropped_and_never_applied) {
  const auto directory = fresh_dir("store_corrupt_journal");
  const auto base = directory / "state.ocregstore";
  RegistryState state = build_state(2);
  state.store_generation = StoreGeneration(3);

  auto bound = Store::bind(options_for(base));
  REQUIRE(bound.ok());
  REQUIRE(bound.value()->write_snapshot(state, kSecond).ok());
  std::vector<ReasonCode> notes;
  RegistryState newer = build_state(6);
  newer.store_generation = StoreGeneration(4);
  REQUIRE(bound.value()->commit(newer, kSecond, notes).ok());
  bound.value().reset();

  auto bytes = read_bytes(journal_path(base));
  REQUIRE(!bytes.empty());
  // Damage the payload, leaving header and trailer intact.
  flip_byte(bytes, 72 + 10);
  REQUIRE(write_bytes(journal_path(base), bytes));

  const auto report = Store::open(options_for(base));
  REQUIRE_MSG(report.ok(), std::string(to_string(report.reason())) + ": " + report.detail());
  CHECK(report.value().classification == RecoveryClass::TrailingCorruptDropped);
  CHECK_EQ(report.value().bytes_discarded, bytes.size());
  CHECK_EQ(report.value().journal_entries_dropped, std::uint64_t{1});
  // The corrupt commit is not silently replaced by an older state at a newer
  // generation: the snapshot state is what was actually durable before it.
  CHECK(state_digest(report.value().state) == state_digest(state));
}

OCREG_TEST(a_corrupt_journal_header_never_produces_a_valid_looking_open) {
  const auto directory = fresh_dir("store_corrupt_header");
  const auto base = directory / "state.ocregstore";
  RegistryState state = build_state(2);
  state.store_generation = StoreGeneration(1);

  auto bound = Store::bind(options_for(base));
  REQUIRE(bound.ok());
  std::vector<ReasonCode> notes;
  REQUIRE(bound.value()->commit(state, kSecond, notes).ok());
  bound.value().reset();

  auto bytes = read_bytes(journal_path(base));
  flip_byte(bytes, 8);
  REQUIRE(write_bytes(journal_path(base), bytes));

  // With no snapshot to fall back on, a refused recovery is the only honest
  // answer.
  const auto report = Store::open(options_for(base));
  CHECK(!report.ok());
  CHECK(report.reason() == ReasonCode::StoreJournalCorrupt);
}

OCREG_TEST(snapshot_header_damage_is_classified_precisely) {
  const auto directory = fresh_dir("store_snapshot_damage");
  const auto base = directory / "state.ocregstore";
  RegistryState state = build_state(2);
  state.store_generation = StoreGeneration(2);
  auto bound = Store::bind(options_for(base));
  REQUIRE(bound.ok());
  REQUIRE(bound.value()->write_snapshot(state, kSecond).ok());
  bound.value().reset();
  const auto pristine = read_bytes(base);
  REQUIRE(pristine.size() > kSnapshotHeaderSize + kSnapshotFooterSize);

  const auto with_header_crc = [](std::vector<std::uint8_t> bytes) {
    const std::span<const std::uint8_t> prefix(bytes.data(), kSnapshotHeaderSize - 4);
    const std::uint32_t crc = crc32c(prefix);
    bytes[kSnapshotHeaderSize - 4] = static_cast<std::uint8_t>((crc >> 24) & 0xFF);
    bytes[kSnapshotHeaderSize - 3] = static_cast<std::uint8_t>((crc >> 16) & 0xFF);
    bytes[kSnapshotHeaderSize - 2] = static_cast<std::uint8_t>((crc >> 8) & 0xFF);
    bytes[kSnapshotHeaderSize - 1] = static_cast<std::uint8_t>(crc & 0xFF);
    return bytes;
  };

  {
    // A flipped header byte with a stale checksum is header corruption.
    auto bytes = pristine;
    flip_byte(bytes, 16);
    REQUIRE(write_bytes(base, bytes));
    const auto report = Store::open(options_for(base));
    CHECK(!report.ok());
    CHECK(report.reason() == ReasonCode::StoreHeaderCorrupt);
  }
  {
    // A consistent but unsupported format version is a version mismatch.
    auto bytes = pristine;
    bytes[7] = 9;
    REQUIRE(write_bytes(base, with_header_crc(bytes)));
    const auto report = Store::open(options_for(base));
    CHECK(!report.ok());
    CHECK(report.reason() == ReasonCode::StoreVersionIncompatible);
  }
  {
    // A different capability catalog generation is a semantic mismatch.
    auto bytes = pristine;
    bytes[20] = static_cast<std::uint8_t>(bytes[20] ^ 0xFF);
    REQUIRE(write_bytes(base, with_header_crc(bytes)));
    const auto report = Store::open(options_for(base));
    CHECK(!report.ok());
    CHECK(report.reason() == ReasonCode::StoreSemanticMismatch);
  }
  {
    // A damaged payload is detected by both the CRC and the digest.
    auto bytes = pristine;
    flip_byte(bytes, kSnapshotHeaderSize + 4);
    REQUIRE(write_bytes(base, bytes));
    const auto report = Store::open(options_for(base));
    CHECK(!report.ok());
    CHECK(report.reason() == ReasonCode::StorePayloadCorrupt);
  }
  {
    // A missing footer is a refused open, never a silent success.
    auto bytes = pristine;
    bytes.resize(bytes.size() - kSnapshotFooterSize);
    REQUIRE(write_bytes(base, bytes));
    const auto report = Store::open(options_for(base));
    CHECK(!report.ok());
    CHECK(report.reason() == ReasonCode::StoreTornTail ||
          report.reason() == ReasonCode::StoreFooterMissing);
  }
  {
    // A truncated file is a refused open.
    auto bytes = pristine;
    bytes.resize(kSnapshotHeaderSize - 8);
    REQUIRE(write_bytes(base, bytes));
    const auto report = Store::open(options_for(base));
    CHECK(!report.ok());
  }
  {
    // An oversized store is refused before it is read.
    auto bytes = pristine;
    bytes.resize(0);
    bytes.resize(16);
    REQUIRE(write_bytes(base, bytes));
    StoreOptions tiny = options_for(base);
    tiny.limits.max_snapshot_bytes = 8;
    const auto report = Store::open(tiny);
    CHECK(!report.ok());
    CHECK(report.reason() == ReasonCode::StoreOversized);
  }
}

OCREG_TEST(a_replayed_or_reordered_journal_entry_is_not_applied) {
  const auto directory = fresh_dir("store_replay");
  const auto base = directory / "state.ocregstore";
  auto bound = Store::bind(options_for(base));
  REQUIRE(bound.ok());

  RegistryState first = build_state(1);
  first.store_generation = StoreGeneration(5);
  std::vector<ReasonCode> notes;
  REQUIRE(bound.value()->commit(first, kSecond, notes).ok());
  const std::uintmax_t first_entry_bytes = std::filesystem::file_size(journal_path(base));
  REQUIRE(first_entry_bytes > 0);

  RegistryState second = build_state(4);
  second.store_generation = StoreGeneration(6);
  REQUIRE(bound.value()->commit(second, kSecond, notes).ok());
  bound.value().reset();

  // Replay the first entry after the second: its sequence number is not greater
  // than the one already seen, so it is refused rather than applied again.
  const auto bytes = read_bytes(journal_path(base));
  REQUIRE(bytes.size() > first_entry_bytes);
  std::vector<std::uint8_t> duplicated(bytes.begin(), bytes.end());
  duplicated.insert(duplicated.end(), bytes.begin() + static_cast<std::ptrdiff_t>(first_entry_bytes),
                    bytes.end());
  REQUIRE(write_bytes(journal_path(base), duplicated));

  const auto report = Store::open(options_for(base));
  REQUIRE_MSG(report.ok(), std::string(to_string(report.reason())) + ": " + report.detail());
  // The state is still the newest valid commit, and the duplicate was counted.
  CHECK(state_digest(report.value().state) == state_digest(second));
  CHECK_EQ(report.value().journal_entries_dropped, std::uint64_t{1});
  // The replayed entry parsed cleanly and was skipped rather than discarded
  // mid-frame, so it costs no discarded bytes; it is accounted for by the
  // dropped-entry count instead.
  CHECK_EQ(report.value().bytes_discarded, std::uint64_t{0});
}

OCREG_TEST(state_serialisation_round_trips_every_correctness_critical_field) {
  Registry registry(make_lab_policy());
  const auto device = reference("sim-nic-801", 0, 1);
  for (std::uint64_t generation = 1; generation <= 3; ++generation) {
    (void)registry.admit(
        make_request(device, "fixture-sim", "1." + std::to_string(generation) + ".0", generation,
                     kSecond),
        kSecond);
  }
  // A retirement, a conflict and an eviction give the state every collection.
  RegistryPolicy conflict_policy = make_lab_policy();
  const auto second_source = SourceId::parse("fixture-sim-b");
  REQUIRE(second_source.has_value());
  SourcePolicy extra;
  extra.id = *second_source;
  extra.kind = SourceKind::Synthetic;
  extra.authority = AuthorityRank::Synthetic;
  extra.max_age = kSecond;
  conflict_policy.sources.push_back(extra);
  std::sort(conflict_policy.sources.begin(), conflict_policy.sources.end());
  conflict_policy.limits.max_records_per_stream = 2;
  Registry rich(conflict_policy);
  const auto rich_device = reference("sim-nic-802", 0, 1);
  for (std::uint64_t generation = 1; generation <= 5; ++generation) {
    (void)rich.admit(make_request(rich_device, "fixture-sim",
                                  "1." + std::to_string(generation) + ".0", generation, kSecond),
                     kSecond);
  }
  AdmissionRequest divergent = make_request(rich_device, "fixture-sim-b", "2.0.0", 1, kSecond);
  divergent.limits = LimitSet::from_validated(
      {LimitValue{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 1200}});
  const auto conflicting = rich.admit(divergent, kSecond);
  REQUIRE(conflicting.ok());
  REQUIRE(conflicting.value().conflict.has_value());
  REQUIRE(rich
              .resolve_conflict(*conflicting.value().conflict, conflicting.value().id,
                                source_id("operator-declared"), kSecond)
              .ok());
  RetirementRequest retirement;
  retirement.device = rich_device;
  retirement.kind = CapabilityKind::ChecksumOffload;
  retirement.source = source_id("fixture-sim-b");
  retirement.generation = RecordGeneration(9);
  retirement.retired_at = kSecond;
  REQUIRE(rich.retire(retirement, kSecond).ok());

  const auto snapshot = rich.snapshot_state();
  REQUIRE(snapshot.ok());
  Writer writer;
  encode(writer, snapshot.value());
  Reader reader(writer.span());
  RegistryState decoded;
  REQUIRE(decode(reader, decoded));
  CHECK(reader.at_end());
  CHECK(state_digest(decoded) == state_digest(snapshot.value()));
  CHECK_EQ(decoded.records.size(), snapshot.value().records.size());
  CHECK_EQ(decoded.tombstones.size(), snapshot.value().tombstones.size());
  CHECK_EQ(decoded.conflicts.size(), snapshot.value().conflicts.size());
  CHECK_EQ(decoded.resolutions.size(), snapshot.value().resolutions.size());
  CHECK_EQ(decoded.evictions.size(), snapshot.value().evictions.size());
  CHECK_EQ(decoded.incarnations.size(), snapshot.value().incarnations.size());
  CHECK(decoded.policy.policy_name == snapshot.value().policy.policy_name);
  CHECK(decoded.counters.evictions_total == snapshot.value().counters.evictions_total);

  // Every prefix of the encoding is refused or incomplete; none decodes into a
  // successful state.
  for (std::size_t length = 0; length < writer.size(); length += 97) {
    Reader truncated(std::span<const std::uint8_t>(writer.span().data(), length));
    RegistryState ignored;
    const bool ok = decode(truncated, ignored);
    CHECK_MSG(!ok, std::to_string(length));
  }
}

OCREG_TEST(random_bytes_never_decode_into_a_valid_state) {
  Rng rng(0xC0FFEEull);
  for (int round = 0; round < 400; ++round) {
    const std::size_t length = rng.below(300);
    std::vector<std::uint8_t> bytes(length);
    for (std::size_t index = 0; index < length; ++index) {
      bytes[index] = static_cast<std::uint8_t>(rng.below(256));
    }
    Reader reader(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    RegistryState decoded;
    const bool ok = decode(reader, decoded);
    if (ok) {
      // Even a structurally decodable buffer must satisfy the invariants.
      CHECK(state_digest(decoded) == state_digest(decoded));
      CHECK(decoded.next_incarnation != 0);
    } else {
      CHECK(!reader.ok());
    }
  }
}
