// Offload Capability Registry - versioned, integrity-checked persistence.
// Copyright 2026 Summon Software Labs.
//
// Layout on disk:
//   <base>                    snapshot: fixed header, payload, fixed footer
//   <base>.ocregjournal       append-only journal of committed mutations
//
// Every frame carries a SHA-256 digest of its payload and a CRC-32C of the
// frame. A commit is acknowledged only after the frame is durably written.
// Recovery never fabricates a successful open: it classifies what it found and
// reports every byte it refused or discarded.
#ifndef OCREG_PERSIST_HPP
#define OCREG_PERSIST_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "ocreg/outcome.hpp"
#include "ocreg/reason.hpp"
#include "ocreg/registry.hpp"
#include "ocreg/strong.hpp"

namespace ocreg {

inline constexpr std::uint32_t kSnapshotMagic = 0x4F435253u;  // "OCRS"
inline constexpr std::uint32_t kSnapshotFooterMagic = 0x4F435246u;  // "OCRF"
inline constexpr std::uint32_t kJournalMagic = 0x4F434A52u;  // "OCJR"
// Snapshot header: magic u32, format version u32, header size u32, flags u32,
// API generation u32, catalog fingerprint u32, reason-table fingerprint u32,
// payload length u64, created tick u64, store generation u64, registry epoch
// u64, rule generation u64, boot epoch u64, payload SHA-256 (32 bytes),
// header CRC-32C u32.
inline constexpr std::uint32_t kSnapshotHeaderSize = 112;
inline constexpr std::uint32_t kSnapshotFooterSize = 32;
inline constexpr std::uint32_t kJournalHeaderSize = 72;
inline constexpr std::uint32_t kJournalTrailerSize = 8;

// Journal entry kinds. Stable numeric codes.
enum class JournalKind : std::uint16_t {
  StateSnapshot = 1,
  Admission = 2,
  Retirement = 3,
  SourcePolicyChange = 4,
  SourceRevocation = 5,
  RuleGenerationChange = 6,
  EpochAdvance = 7,
  ConflictResolution = 8,
  DeviceIncarnation = 9,
  LimitChange = 10,
};

[[nodiscard]] std::string_view to_string(JournalKind kind) noexcept;

struct StoreLimits {
  std::size_t max_snapshot_bytes = 64u * 1024u * 1024u;
  std::size_t max_journal_entry_bytes = 1u * 1024u * 1024u;
  std::size_t max_journal_bytes = 16u * 1024u * 1024u;
  std::size_t max_journal_entries = 65536;
  std::size_t max_replay_entries = 65536;
};

struct StoreOptions {
  std::string base_path{};
  StoreLimits limits{};
  // When true (default) each commit is flushed and synchronised before the
  // acknowledgement is returned.
  bool sync_on_commit = true;
  // Journal entries are compacted into a fresh snapshot once this many
  // committed entries have accumulated. Zero disables automatic compaction.
  std::size_t compact_after_entries = 4096;
};

// A durable commit acknowledgement. The token exists only if the bytes are on
// stable storage (or the caller explicitly disabled synchronisation).
struct CommitToken {
  StoreGeneration generation{};
  std::uint64_t sequence = 0;
  std::uint64_t bytes = 0;
  Digest256 payload_digest{};
  bool synchronised = false;
};

// Outcome of opening and validating a store.
struct OpenReport {
  ReasonCode reason = ReasonCode::StoreEmptyNew;
  bool existed = false;
  bool snapshot_present = false;
  bool journal_present = false;
  std::uint64_t snapshot_bytes = 0;
  std::uint64_t journal_bytes = 0;
  std::uint64_t bytes_discarded = 0;
  std::uint64_t journal_entries_scanned = 0;
  std::uint64_t journal_entries_valid = 0;
  std::uint64_t journal_entries_dropped = 0;
  // True when an incomplete temporary snapshot from an interrupted write was
  // found and removed. It is reported rather than silently discarded.
  bool stale_temp_removed = false;
  RecoveryClass classification = RecoveryClass::CleanOpen;
  RegistryState state{};
};

class Store {
 public:
  // Opens (creating if absent) the store at 'options.base_path' and returns the
  // validated in-memory state. A corrupt or incompatible store is refused with
  // a stable reason code; it is never silently reset.
  static Outcome<OpenReport> open(const StoreOptions& options);

  // Creates a store object bound to the path. The object does not own the
  // registry; it serialises states handed to it.
  static Outcome<std::unique_ptr<Store>> bind(const StoreOptions& options);

  ~Store();
  Store(const Store&) = delete;
  Store& operator=(const Store&) = delete;

  // Writes a complete snapshot atomically (temp file, sync, rename).
  Outcome<CommitToken> write_snapshot(const RegistryState& state, Tick now);

  // The durable commit point. Appends the full encoded state as a
  // StateSnapshot journal entry and synchronises it before returning. When the
  // journal passes its rotation bound the snapshot file is rewritten and the
  // journal truncated; the rotation is reported in 'notes'.
  Outcome<CommitToken> commit(const RegistryState& state, Tick now,
                              std::vector<ReasonCode>& notes);

  // Appends one journal entry and (by default) synchronises it.
  Outcome<CommitToken> append(JournalKind kind, std::span<const std::uint8_t> payload, Tick now);

  // Truncates the journal and writes a fresh snapshot, reclaiming space.
  Outcome<CommitToken> compact(const RegistryState& state, Tick now);

  [[nodiscard]] const StoreOptions& options() const noexcept;
  [[nodiscard]] std::uint64_t journal_entry_count() const noexcept;
  [[nodiscard]] std::uint64_t journal_bytes() const noexcept;
  [[nodiscard]] std::uint64_t bytes_written() const noexcept;

 private:
  struct Impl;
  explicit Store(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

// Convenience: open, then build a registry that adopts the recovered state.
Outcome<RegistryState> load_state(const StoreOptions& options, RecoverySummary& summary);

// Encode/decode a full registry state through the canonical codec.
void encode(Writer& w, const RegistryState& value);
bool decode(Reader& r, RegistryState& value);

// Canonical digest of a registry state.
[[nodiscard]] Digest256 state_digest(const RegistryState& state);

// Journal payload codecs.
void encode(Writer& w, const AdmissionRequest& value);
void encode(Writer& w, const RetirementRequest& value);

}  // namespace ocreg

#endif  // OCREG_PERSIST_HPP
