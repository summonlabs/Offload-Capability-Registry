// Offload Capability Registry - versioned, integrity-checked persistence.
// Copyright 2026 Summon Software Labs.
#include "ocreg/persist.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "ocreg/codec.hpp"
#include "ocreg/version.hpp"

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

namespace ocreg {
namespace {

[[nodiscard]] std::string journal_path(const std::string& base) { return base + ".ocregjournal"; }
[[nodiscard]] std::string temp_path(const std::string& base) { return base + ".ocregtmp"; }

class FileHandle {
 public:
  FileHandle() = default;
  FileHandle(std::FILE* file, std::string path) : file_(file), path_(std::move(path)) {}
  ~FileHandle() {
    if (file_ != nullptr) std::fclose(file_);
  }
  FileHandle(const FileHandle&) = delete;
  FileHandle& operator=(const FileHandle&) = delete;
  FileHandle(FileHandle&& other) noexcept
      : file_(other.file_), path_(std::move(other.path_)) {
    other.file_ = nullptr;
  }
  FileHandle& operator=(FileHandle&& other) noexcept {
    if (this != &other) {
      if (file_ != nullptr) std::fclose(file_);
      file_ = other.file_;
      path_ = std::move(other.path_);
      other.file_ = nullptr;
    }
    return *this;
  }

  [[nodiscard]] std::FILE* get() const noexcept { return file_; }
  [[nodiscard]] bool valid() const noexcept { return file_ != nullptr; }
  void close() {
    if (file_ != nullptr) {
      std::fclose(file_);
      file_ = nullptr;
    }
  }

  [[nodiscard]] bool sync() {
    if (file_ == nullptr) return false;
    if (std::fflush(file_) != 0) return false;
#if defined(_WIN32)
    return _commit(_fileno(file_)) == 0;
#else
    return ::fsync(::fileno(file_)) == 0;
#endif
  }

 private:
  std::FILE* file_ = nullptr;
  std::string path_{};
};

[[nodiscard]] Outcome<FileHandle> open_file(const std::string& path, const char* mode) {
  std::FILE* file = nullptr;
#if defined(_WIN32)
  if (::fopen_s(&file, path.c_str(), mode) != 0) file = nullptr;
#else
  file = std::fopen(path.c_str(), mode);
#endif
  if (file == nullptr) {
    return Outcome<FileHandle>(Status::failure(ReasonCode::StoreReadFailed, path));
  }
  return Outcome<FileHandle>(FileHandle(file, path));
}

// --- Little helpers for fixed-width writes into a byte vector ----------------

void put_u16(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
}

void put_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

void put_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

[[nodiscard]] std::uint16_t get_u16(const std::uint8_t* data) noexcept {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8) |
                                    static_cast<std::uint16_t>(data[1]));
}

[[nodiscard]] std::uint32_t get_u32(const std::uint8_t* data) noexcept {
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) value = (value << 8) | static_cast<std::uint32_t>(data[i]);
  return value;
}

[[nodiscard]] std::uint64_t get_u64(const std::uint8_t* data) noexcept {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) value = (value << 8) | static_cast<std::uint64_t>(data[i]);
  return value;
}

void put_digest(std::vector<std::uint8_t>& out, const Digest256& digest) {
  out.insert(out.end(), digest.bytes().begin(), digest.bytes().end());
}

[[nodiscard]] Outcome<std::vector<std::uint8_t>> read_whole_file(const std::string& path,
                                                                 std::size_t max_bytes) {
  std::error_code error;
  const auto size = std::filesystem::file_size(path, error);
  if (error) {
    return Outcome<std::vector<std::uint8_t>>(
        Status::failure(ReasonCode::StoreReadFailed, "file size unavailable"));
  }
  if (size > max_bytes) {
    return Outcome<std::vector<std::uint8_t>>(
        Status::failure(ReasonCode::StoreOversized, "file exceeds the configured bound"));
  }
  auto handle = open_file(path, "rb");
  if (!handle.ok()) return Outcome<std::vector<std::uint8_t>>(handle.status());
  std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
  if (!data.empty()) {
    const std::size_t read = std::fread(data.data(), 1, data.size(), handle.value().get());
    if (read != data.size()) {
      return Outcome<std::vector<std::uint8_t>>(
          Status::failure(ReasonCode::StoreReadFailed, "short read"));
    }
  }
  return Outcome<std::vector<std::uint8_t>>(std::move(data));
}

// --- Snapshot layout --------------------------------------------------------

struct SnapshotHeader {
  std::uint32_t format_version = kStoreFormatVersion;
  std::uint32_t header_size = kSnapshotHeaderSize;
  std::uint32_t flags = 0;
  std::uint32_t api_generation = kApiGeneration;
  std::uint32_t catalog_fingerprint = 0;
  std::uint32_t reason_fingerprint = 0;
  std::uint64_t payload_len = 0;
  std::uint64_t created_at = 0;
  std::uint64_t store_generation = 0;
  std::uint64_t registry_epoch = 0;
  std::uint64_t rule_generation = 0;
  std::uint64_t boot_epoch = 0;
  Digest256 payload_digest{};
};

[[nodiscard]] std::vector<std::uint8_t> serialize_header(const SnapshotHeader& header) {
  std::vector<std::uint8_t> out;
  out.reserve(kSnapshotHeaderSize);
  put_u32(out, kSnapshotMagic);
  put_u32(out, header.format_version);
  put_u32(out, header.header_size);
  put_u32(out, header.flags);
  put_u32(out, header.api_generation);
  put_u32(out, header.catalog_fingerprint);
  put_u32(out, header.reason_fingerprint);
  put_u64(out, header.payload_len);
  put_u64(out, header.created_at);
  put_u64(out, header.store_generation);
  put_u64(out, header.registry_epoch);
  put_u64(out, header.rule_generation);
  put_u64(out, header.boot_epoch);
  put_digest(out, header.payload_digest);
  put_u32(out, crc32c(out));
  return out;
}

[[nodiscard]] bool parse_header(const std::vector<std::uint8_t>& data, SnapshotHeader& out,
                                ReasonCode& reason) {
  if (data.size() < kSnapshotHeaderSize) {
    reason = ReasonCode::StoreHeaderCorrupt;
    return false;
  }
  if (get_u32(data.data()) != kSnapshotMagic) {
    reason = ReasonCode::StoreHeaderCorrupt;
    return false;
  }
  const std::uint32_t stored_crc = get_u32(data.data() + kSnapshotHeaderSize - 4);
  std::vector<std::uint8_t> prefix(data.begin(), data.begin() + (kSnapshotHeaderSize - 4));
  if (crc32c(prefix) != stored_crc) {
    reason = ReasonCode::StoreHeaderCorrupt;
    return false;
  }
  if (get_u32(data.data() + 4) != kStoreFormatVersion) {
    reason = ReasonCode::StoreVersionIncompatible;
    return false;
  }
  if (get_u32(data.data() + 8) != kSnapshotHeaderSize) {
    reason = ReasonCode::StoreHeaderCorrupt;
    return false;
  }
  if (get_u32(data.data() + 12) != 0) {
    reason = ReasonCode::StoreSemanticMismatch;
    return false;
  }
  if (get_u32(data.data() + 16) != kApiGeneration) {
    reason = ReasonCode::StoreVersionIncompatible;
    return false;
  }
  if (get_u32(data.data() + 20) != catalog_fingerprint()) {
    reason = ReasonCode::StoreSemanticMismatch;
    return false;
  }
  if (get_u32(data.data() + 24) != reason_table_fingerprint()) {
    reason = ReasonCode::StoreSemanticMismatch;
    return false;
  }
  out.format_version = get_u32(data.data() + 4);
  out.header_size = get_u32(data.data() + 8);
  out.flags = get_u32(data.data() + 12);
  out.api_generation = get_u32(data.data() + 16);
  out.catalog_fingerprint = get_u32(data.data() + 20);
  out.reason_fingerprint = get_u32(data.data() + 24);
  out.payload_len = get_u64(data.data() + 28);
  out.created_at = get_u64(data.data() + 36);
  out.store_generation = get_u64(data.data() + 44);
  out.registry_epoch = get_u64(data.data() + 52);
  out.rule_generation = get_u64(data.data() + 60);
  out.boot_epoch = get_u64(data.data() + 68);
  std::array<std::uint8_t, kDigestBytes> digest_bytes{};
  for (std::size_t i = 0; i < kDigestBytes; ++i) digest_bytes[i] = data[76 + i];
  out.payload_digest = Digest256(digest_bytes);
  return true;
}

// --- Journal layout ---------------------------------------------------------

struct JournalHeader {
  std::uint16_t format_version = static_cast<std::uint16_t>(kStoreFormatVersion);
  JournalKind kind = JournalKind::StateSnapshot;
  std::uint64_t sequence = 0;
  std::uint64_t created_at = 0;
  std::uint64_t store_generation = 0;
  std::uint32_t payload_len = 0;
  Digest256 payload_digest{};
};

[[nodiscard]] std::vector<std::uint8_t> serialize_journal_header(const JournalHeader& header) {
  std::vector<std::uint8_t> out;
  out.reserve(kJournalHeaderSize);
  put_u32(out, kJournalMagic);
  put_u16(out, header.format_version);
  put_u16(out, static_cast<std::uint16_t>(header.kind));
  put_u64(out, header.sequence);
  put_u64(out, header.created_at);
  put_u64(out, header.store_generation);
  put_u32(out, header.payload_len);
  put_digest(out, header.payload_digest);
  put_u32(out, crc32c(out));
  return out;
}

[[nodiscard]] bool parse_journal_header(const std::uint8_t* data, JournalHeader& out,
                                        ReasonCode& reason) noexcept {
  if (get_u32(data) != kJournalMagic) {
    reason = ReasonCode::StoreJournalCorrupt;
    return false;
  }
  const std::uint32_t stored_crc = get_u32(data + kJournalHeaderSize - 4);
  if (crc32c(std::span<const std::uint8_t>(data, kJournalHeaderSize - 4)) != stored_crc) {
    reason = ReasonCode::StoreJournalCorrupt;
    return false;
  }
  if (get_u16(data + 4) != static_cast<std::uint16_t>(kStoreFormatVersion)) {
    reason = ReasonCode::StoreVersionIncompatible;
    return false;
  }
  const std::uint16_t kind = get_u16(data + 6);
  if (kind < 1 || kind > static_cast<std::uint16_t>(JournalKind::LimitChange)) {
    reason = ReasonCode::StoreJournalCorrupt;
    return false;
  }
  out.format_version = get_u16(data + 4);
  out.kind = static_cast<JournalKind>(kind);
  out.sequence = get_u64(data + 8);
  out.created_at = get_u64(data + 16);
  out.store_generation = get_u64(data + 24);
  out.payload_len = get_u32(data + 32);
  std::array<std::uint8_t, kDigestBytes> digest_bytes{};
  for (std::size_t i = 0; i < kDigestBytes; ++i) digest_bytes[i] = data[36 + i];
  out.payload_digest = Digest256(digest_bytes);
  return true;
}

[[nodiscard]] bool write_all(std::FILE* file, const std::vector<std::uint8_t>& data) {
  if (data.empty()) return true;
  return std::fwrite(data.data(), 1, data.size(), file) == data.size();
}

struct JournalScan {
  std::uint64_t valid_bytes = 0;
  std::uint64_t entries_seen = 0;
  std::uint64_t entries_valid = 0;
  std::uint64_t entries_dropped = 0;
  std::uint64_t bytes_discarded = 0;
  bool truncated_tail = false;
  bool corrupt = false;
  ReasonCode reason = ReasonCode::Ok;
  std::vector<std::uint8_t> last_snapshot_payload{};
  std::uint64_t last_snapshot_generation = 0;
  std::vector<ReasonCode> notes{};
};

void scan_journal(const std::vector<std::uint8_t>& data, const StoreLimits& limits,
                  JournalScan& scan) {
  std::size_t position = 0;
  std::uint64_t previous_sequence = 0;
  std::uint64_t previous_generation = 0;
  while (position < data.size()) {
    const std::size_t remaining = data.size() - position;
    if (remaining < kJournalHeaderSize) {
      scan.truncated_tail = true;
      scan.bytes_discarded += remaining;
      break;
    }
    JournalHeader header;
    ReasonCode header_reason = ReasonCode::Ok;
    if (!parse_journal_header(data.data() + position, header, header_reason)) {
      scan.corrupt = true;
      scan.reason = header_reason;
      scan.bytes_discarded += remaining;
      break;
    }
    ++scan.entries_seen;
    if (header.payload_len > limits.max_journal_entry_bytes) {
      scan.corrupt = true;
      scan.reason = ReasonCode::StoreOversized;
      scan.bytes_discarded += remaining;
      break;
    }
    const std::size_t total =
        kJournalHeaderSize + static_cast<std::size_t>(header.payload_len) + kJournalTrailerSize;
    if (remaining < total) {
      scan.truncated_tail = true;
      scan.bytes_discarded += remaining;
      break;
    }
    const std::uint8_t* payload = data.data() + position + kJournalHeaderSize;
    const std::uint8_t* trailer = payload + header.payload_len;
    const std::uint32_t payload_crc = get_u32(trailer);
    const std::span<const std::uint8_t> payload_span(payload, header.payload_len);
    if (crc32c(payload_span) != payload_crc) {
      scan.corrupt = true;
      scan.reason = ReasonCode::StorePayloadCorrupt;
      scan.bytes_discarded += remaining;
      break;
    }
    if (!(Digest256::of(payload_span) == header.payload_digest)) {
      scan.corrupt = true;
      scan.reason = ReasonCode::StorePayloadCorrupt;
      scan.bytes_discarded += remaining;
      break;
    }
    // Sequence and generation must advance; a replayed or reordered entry is
    // refused rather than applied.
    if (header.sequence <= previous_sequence && scan.entries_valid > 0) {
      scan.notes.push_back(ReasonCode::ProtocolSequenceViolation);
      position += total;
      continue;
    }
    if (header.store_generation < previous_generation) {
      scan.notes.push_back(ReasonCode::StoreGenerationReplay);
      position += total;
      continue;
    }
    previous_sequence = header.sequence;
    previous_generation = header.store_generation;
    ++scan.entries_valid;
    if (header.kind == JournalKind::StateSnapshot) {
      if (header.store_generation >= scan.last_snapshot_generation) {
        scan.last_snapshot_generation = header.store_generation;
        scan.last_snapshot_payload.assign(payload, payload + header.payload_len);
      }
    }
    position += total;
    scan.valid_bytes = position;
  }
  // Every scanned entry that was not applied is accounted for, including the
  // ones lost to a torn or corrupt tail.
  scan.entries_dropped = scan.entries_seen > scan.entries_valid
                             ? scan.entries_seen - scan.entries_valid
                             : 0;
  if (!scan.corrupt && !scan.truncated_tail) scan.reason = ReasonCode::RecoveryCleanOpen;
}

// Truncates the journal, creating it when it does not exist yet. An absent
// journal is not an error: it simply means nothing has been appended.
[[nodiscard]] bool truncate_journal(const std::string& path) {
  std::error_code error;
  if (!std::filesystem::exists(path, error) || error) {
    error.clear();
    auto handle = open_file(path, "wb");
    return handle.ok();
  }
  error.clear();
  std::filesystem::resize_file(path, 0, error);
  return !error;
}

}  // namespace

std::string_view to_string(JournalKind kind) noexcept {
  switch (kind) {
    case JournalKind::StateSnapshot: return "state_snapshot";
    case JournalKind::Admission: return "admission";
    case JournalKind::Retirement: return "retirement";
    case JournalKind::SourcePolicyChange: return "source_policy_change";
    case JournalKind::SourceRevocation: return "source_revocation";
    case JournalKind::RuleGenerationChange: return "rule_generation_change";
    case JournalKind::EpochAdvance: return "epoch_advance";
    case JournalKind::ConflictResolution: return "conflict_resolution";
    case JournalKind::DeviceIncarnation: return "device_incarnation";
    case JournalKind::LimitChange: return "limit_change";
  }
  return "state_snapshot";
}

struct Store::Impl {
  StoreOptions options{};
  std::uint64_t sequence = 0;
  std::uint64_t entry_count = 0;
  std::uint64_t journal_size = 0;
  std::uint64_t written = 0;
  StoreGeneration generation{};
};

Store::Store(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

Store::~Store() = default;

const StoreOptions& Store::options() const noexcept { return impl_->options; }
std::uint64_t Store::journal_entry_count() const noexcept { return impl_->entry_count; }
std::uint64_t Store::journal_bytes() const noexcept { return impl_->journal_size; }
std::uint64_t Store::bytes_written() const noexcept { return impl_->written; }

Outcome<OpenReport> Store::open(const StoreOptions& options) {
  OpenReport report;
  if (options.base_path.empty()) {
    return Outcome<OpenReport>(
        Status::failure(ReasonCode::StoreNotFound, "store base path is empty"));
  }
  const std::string snapshot_file = options.base_path;
  const std::string journal_file = journal_path(options.base_path);

  std::error_code error;
  const bool snapshot_exists = std::filesystem::exists(snapshot_file, error) && !error;
  error.clear();
  const bool journal_exists = std::filesystem::exists(journal_file, error) && !error;
  error.clear();

  // An interrupted snapshot write leaves a temporary file that is never a valid
  // store. Removing it is reported so the interruption stays observable.
  const std::string temporary = temp_path(options.base_path);
  if (std::filesystem::exists(temporary, error) && !error) {
    error.clear();
    std::filesystem::remove(temporary, error);
    if (!error) report.stale_temp_removed = true;
  }
  error.clear();

  report.existed = snapshot_exists || journal_exists;
  report.snapshot_present = snapshot_exists;
  report.journal_present = journal_exists;

  RegistryState state;
  bool have_state = false;

  if (snapshot_exists) {
    auto bytes = read_whole_file(snapshot_file, options.limits.max_snapshot_bytes);
    if (!bytes.ok()) return Outcome<OpenReport>(bytes.status());
    const std::vector<std::uint8_t>& data = bytes.value();
    report.snapshot_bytes = data.size();
    SnapshotHeader header;
    ReasonCode header_reason = ReasonCode::Ok;
    if (!parse_header(data, header, header_reason)) {
      return Outcome<OpenReport>(Status::failure(header_reason, "snapshot header rejected"));
    }
    if (data.size() < kSnapshotHeaderSize + kSnapshotFooterSize) {
      return Outcome<OpenReport>(
          Status::failure(ReasonCode::StoreTornTail, "snapshot is shorter than header plus footer"));
    }
    if (static_cast<std::uint64_t>(header.payload_len) !=
        static_cast<std::uint64_t>(data.size()) - kSnapshotHeaderSize - kSnapshotFooterSize) {
      return Outcome<OpenReport>(
          Status::failure(ReasonCode::StoreTornTail, "snapshot payload length disagrees with size"));
    }
    const std::size_t footer_offset = kSnapshotHeaderSize + static_cast<std::size_t>(header.payload_len);
    if (data.size() < footer_offset + kSnapshotFooterSize) {
      return Outcome<OpenReport>(
          Status::failure(ReasonCode::StoreFooterMissing, "snapshot footer is absent"));
    }
    if (get_u32(data.data() + footer_offset) != kSnapshotFooterMagic) {
      return Outcome<OpenReport>(
          Status::failure(ReasonCode::StoreFooterMissing, "snapshot footer magic mismatch"));
    }
    {
      const std::span<const std::uint8_t> footer_span(data.data() + footer_offset, 24);
      if (crc32c(footer_span) != get_u32(data.data() + footer_offset + 24)) {
        return Outcome<OpenReport>(
            Status::failure(ReasonCode::StorePayloadCorrupt, "snapshot footer checksum mismatch"));
      }
      if (get_u32(data.data() + footer_offset + 28) != 0) {
        return Outcome<OpenReport>(
            Status::failure(ReasonCode::StoreSemanticMismatch, "snapshot footer reserved field set"));
      }
    }
    const std::uint64_t footer_len = get_u64(data.data() + footer_offset + 4);
    if (footer_len != header.payload_len) {
      return Outcome<OpenReport>(
          Status::failure(ReasonCode::StoreTornTail, "snapshot footer length mismatch"));
    }
    const std::span<const std::uint8_t> payload(data.data() + kSnapshotHeaderSize,
                                                static_cast<std::size_t>(header.payload_len));
    if (crc32c(payload) != get_u32(data.data() + footer_offset + 12)) {
      return Outcome<OpenReport>(
          Status::failure(ReasonCode::StorePayloadCorrupt, "snapshot payload CRC mismatch"));
    }
    if (!(Digest256::of(payload) == header.payload_digest)) {
      return Outcome<OpenReport>(
          Status::failure(ReasonCode::StorePayloadCorrupt, "snapshot payload digest mismatch"));
    }
    Reader reader(payload);
    RegistryState decoded;
    if (!decode(reader, decoded)) {
      return Outcome<OpenReport>(Status::failure(reader.failure(), "snapshot payload rejected"));
    }
    if (!reader.at_end()) {
      return Outcome<OpenReport>(
          Status::failure(ReasonCode::StoreSemanticMismatch, "snapshot payload has trailing bytes"));
    }
    state = std::move(decoded);
    have_state = true;
    report.journal_entries_valid = 0;
  }

  if (journal_exists) {
    auto bytes = read_whole_file(journal_file, options.limits.max_journal_bytes + kJournalHeaderSize);
    if (!bytes.ok()) return Outcome<OpenReport>(bytes.status());
    const std::vector<std::uint8_t>& data = bytes.value();
    report.journal_bytes = data.size();
    JournalScan scan;
    scan_journal(data, options.limits, scan);
    report.journal_entries_scanned = scan.entries_seen;
    report.journal_entries_dropped = scan.entries_dropped;
    report.bytes_discarded = scan.bytes_discarded;
    if (!scan.last_snapshot_payload.empty()) {
      Reader reader(std::span<const std::uint8_t>(scan.last_snapshot_payload.data(),
                                                  scan.last_snapshot_payload.size()));
      RegistryState decoded;
      if (!decode(reader, decoded)) {
        return Outcome<OpenReport>(
            Status::failure(reader.failure(), "journal snapshot payload rejected"));
      }
      if (!reader.at_end()) {
        return Outcome<OpenReport>(Status::failure(ReasonCode::StoreSemanticMismatch,
                                                   "journal payload has trailing bytes"));
      }
      const std::uint64_t snapshot_generation =
          have_state ? state.store_generation.value() : 0;
      if (!have_state || scan.last_snapshot_generation >= snapshot_generation) {
        state = std::move(decoded);
        have_state = true;
        report.journal_entries_valid = scan.entries_valid;
      } else {
        report.journal_entries_dropped += scan.entries_valid;
        report.journal_entries_valid = 0;
      }
    } else {
      report.journal_entries_valid = scan.entries_valid;
    }

    // Remove the refused tail so subsequent appends start from clean bytes.
    if (scan.bytes_discarded > 0) {
      std::error_code resize_error;
      std::filesystem::resize_file(journal_file, scan.valid_bytes, resize_error);
      if (resize_error) {
        return Outcome<OpenReport>(
            Status::failure(ReasonCode::StoreWriteFailed, "journal tail could not be truncated"));
      }
      report.journal_bytes = scan.valid_bytes;
    }

    if (scan.corrupt) {
      report.classification = scan.truncated_tail ? RecoveryClass::TornTailTruncated
                                                  : RecoveryClass::TrailingCorruptDropped;
      report.reason = scan.reason;
    } else if (scan.truncated_tail) {
      report.classification = RecoveryClass::TornTailTruncated;
      report.reason = ReasonCode::StoreTornTail;
    } else if (scan.entries_valid > 0) {
      report.classification = RecoveryClass::JournalReplayed;
      report.reason = ReasonCode::RecoveryJournalReplayed;
    } else {
      report.classification = RecoveryClass::CleanOpen;
      report.reason = ReasonCode::RecoveryCleanOpen;
    }
  } else if (snapshot_exists) {
    report.classification = RecoveryClass::CleanOpen;
    report.reason = ReasonCode::RecoveryCleanOpen;
  } else {
    report.classification = RecoveryClass::CleanOpen;
    report.reason = ReasonCode::StoreEmptyNew;
  }

  if (!have_state && report.existed) {
    // Refuse with the precise cause when one is known; a refusal that hides why
    // it happened would be as unhelpful as a fabricated success.
    const ReasonCode cause = report.reason == ReasonCode::StoreEmptyNew || report.reason == ReasonCode::Ok
                                 ? ReasonCode::RecoveryRefused
                                 : report.reason;
    return Outcome<OpenReport>(
        Status::failure(cause, "store exists but holds no recoverable state"));
  }
  report.state = std::move(state);
  return Outcome<OpenReport>(std::move(report));
}

Outcome<std::unique_ptr<Store>> Store::bind(const StoreOptions& options) {
  if (options.base_path.empty()) {
    return Outcome<std::unique_ptr<Store>>(
        Status::failure(ReasonCode::StoreNotFound, "store base path is empty"));
  }
  auto impl = std::make_unique<Impl>();
  impl->options = options;
  const std::string journal_file = journal_path(options.base_path);
  std::error_code error;
  if (std::filesystem::exists(journal_file, error) && !error) {
    impl->journal_size = std::filesystem::file_size(journal_file, error);
    if (error) impl->journal_size = 0;
  }
  return Outcome<std::unique_ptr<Store>>(std::unique_ptr<Store>(new Store(std::move(impl))));
}

Outcome<CommitToken> Store::write_snapshot(const RegistryState& state, Tick now) {
  Writer writer;
  encode(writer, state);
  if (writer.size() > impl_->options.limits.max_snapshot_bytes) {
    return Outcome<CommitToken>(Status::failure(ReasonCode::StoreOversized,
                                                "encoded state exceeds the snapshot bound"));
  }

  SnapshotHeader header;
  header.api_generation = kApiGeneration;
  header.catalog_fingerprint = catalog_fingerprint();
  header.reason_fingerprint = reason_table_fingerprint();
  header.payload_len = writer.size();
  header.created_at = now.value();
  header.store_generation = state.store_generation.value();
  header.registry_epoch = state.epoch.value();
  header.rule_generation = state.rule_generation.value();
  header.boot_epoch = state.boot_epoch.value();
  header.payload_digest = Digest256::of(writer.span());

  // Footer layout (32 bytes): magic u32, payload length u64, payload CRC u32,
  // record count u64, footer CRC u32, reserved u32. The footer CRC covers the
  // first 28 bytes of the footer.
  std::vector<std::uint8_t> file_bytes = serialize_header(header);
  file_bytes.insert(file_bytes.end(), writer.buffer().begin(), writer.buffer().end());
  put_u32(file_bytes, kSnapshotFooterMagic);
  put_u64(file_bytes, header.payload_len);
  put_u32(file_bytes, crc32c(writer.span()));
  put_u64(file_bytes, state.records.size());
  put_u32(file_bytes, 0);
  put_u32(file_bytes, 0);
  const std::size_t footer_offset = file_bytes.size() - kSnapshotFooterSize;
  // The footer CRC covers the 24 bytes before it: magic, payload length,
  // payload CRC and record count.
  const std::span<const std::uint8_t> footer_span(file_bytes.data() + footer_offset, 24);
  const std::uint32_t footer_crc = crc32c(footer_span);
  file_bytes[footer_offset + 24] = static_cast<std::uint8_t>((footer_crc >> 24) & 0xFFu);
  file_bytes[footer_offset + 25] = static_cast<std::uint8_t>((footer_crc >> 16) & 0xFFu);
  file_bytes[footer_offset + 26] = static_cast<std::uint8_t>((footer_crc >> 8) & 0xFFu);
  file_bytes[footer_offset + 27] = static_cast<std::uint8_t>(footer_crc & 0xFFu);

  const std::string temporary = temp_path(impl_->options.base_path);
  {
    auto handle = open_file(temporary, "wb");
    if (!handle.ok()) return Outcome<CommitToken>(handle.status());
    if (!write_all(handle.value().get(), file_bytes)) {
      return Outcome<CommitToken>(
          Status::failure(ReasonCode::StoreWriteFailed, "snapshot payload write failed"));
    }
    if (impl_->options.sync_on_commit && !handle.value().sync()) {
      return Outcome<CommitToken>(
          Status::failure(ReasonCode::StoreSyncFailed, "snapshot synchronisation failed"));
    }
    handle.value().close();
  }
  if (impl_->options.sync_on_commit) {
    std::error_code sync_error;
    std::filesystem::rename(temporary, impl_->options.base_path, sync_error);
    if (sync_error) {
      std::filesystem::remove(impl_->options.base_path, sync_error);
      sync_error.clear();
      std::filesystem::rename(temporary, impl_->options.base_path, sync_error);
      if (sync_error) {
        return Outcome<CommitToken>(
            Status::failure(ReasonCode::StoreWriteFailed, "snapshot rename failed"));
      }
    }
  } else {
    std::error_code rename_error;
    std::filesystem::rename(temporary, impl_->options.base_path, rename_error);
    if (rename_error) {
      return Outcome<CommitToken>(
          Status::failure(ReasonCode::StoreWriteFailed, "snapshot rename failed"));
    }
  }

  CommitToken token;
  token.generation = state.store_generation;
  token.sequence = impl_->sequence;
  token.bytes = file_bytes.size();
  token.payload_digest = header.payload_digest;
  token.synchronised = impl_->options.sync_on_commit;
  impl_->written += file_bytes.size();
  return Outcome<CommitToken>(token);
}

Outcome<CommitToken> Store::append(JournalKind kind, std::span<const std::uint8_t> payload, Tick now) {
  if (payload.size() > impl_->options.limits.max_journal_entry_bytes) {
    return Outcome<CommitToken>(
        Status::failure(ReasonCode::StoreOversized, "journal entry exceeds the entry bound"));
  }
  if (impl_->journal_size + payload.size() + kJournalHeaderSize + kJournalTrailerSize >
      impl_->options.limits.max_journal_bytes) {
    return Outcome<CommitToken>(
        Status::failure(ReasonCode::StoreRotationPerformed, "journal byte bound reached"));
  }
  if (impl_->entry_count >= impl_->options.limits.max_journal_entries) {
    return Outcome<CommitToken>(
        Status::failure(ReasonCode::StoreRotationPerformed, "journal entry bound reached"));
  }

  JournalHeader header;
  header.kind = kind;
  header.sequence = impl_->sequence + 1;
  header.created_at = now.value();
  header.store_generation = impl_->generation.value();
  header.payload_len = static_cast<std::uint32_t>(payload.size());
  header.payload_digest = Digest256::of(payload);

  std::vector<std::uint8_t> frame = serialize_journal_header(header);
  frame.insert(frame.end(), payload.begin(), payload.end());
  put_u32(frame, crc32c(payload));
  put_u32(frame, 0);

  const std::string journal_file = journal_path(impl_->options.base_path);
  auto handle = open_file(journal_file, "ab");
  if (!handle.ok()) return Outcome<CommitToken>(handle.status());
  if (!write_all(handle.value().get(), frame)) {
    return Outcome<CommitToken>(
        Status::failure(ReasonCode::StoreWriteFailed, "journal append failed"));
  }
  if (impl_->options.sync_on_commit && !handle.value().sync()) {
    return Outcome<CommitToken>(
        Status::failure(ReasonCode::StoreSyncFailed, "journal synchronisation failed"));
  }
  handle.value().close();

  impl_->sequence = header.sequence;
  ++impl_->entry_count;
  impl_->journal_size += frame.size();
  impl_->written += frame.size();

  CommitToken token;
  token.generation = impl_->generation;
  token.sequence = header.sequence;
  token.bytes = frame.size();
  token.payload_digest = header.payload_digest;
  token.synchronised = impl_->options.sync_on_commit;
  return Outcome<CommitToken>(token);
}

Outcome<CommitToken> Store::commit(const RegistryState& state, Tick now,
                                   std::vector<ReasonCode>& notes) {
  impl_->generation = state.store_generation;
  Writer writer;
  encode(writer, state);
  if (writer.size() > impl_->options.limits.max_journal_entry_bytes) {
    // The state no longer fits one journal entry, so the durable commit is the
    // snapshot file itself.
    auto written = write_snapshot(state, now);
    if (!written.ok()) return written;
    notes.push_back(ReasonCode::StoreCommitDurable);
    notes.push_back(ReasonCode::StoreRotationPerformed);
    if (!truncate_journal(journal_path(impl_->options.base_path))) {
      return Outcome<CommitToken>(
          Status::failure(ReasonCode::StoreWriteFailed, "journal rotation failed"));
    }
    impl_->entry_count = 0;
    impl_->journal_size = 0;
    canonicalize_reasons(notes);
    return written;
  }

  auto appended = append(JournalKind::StateSnapshot, writer.span(), now);
  if (!appended.ok()) return appended;
  notes.push_back(ReasonCode::StoreCommitDurable);

  const bool rotate =
      impl_->options.compact_after_entries != 0 &&
      impl_->entry_count >= impl_->options.compact_after_entries;
  if (rotate) {
    auto written = write_snapshot(state, now);
    if (!written.ok()) return written;
    if (!truncate_journal(journal_path(impl_->options.base_path))) {
      return Outcome<CommitToken>(
          Status::failure(ReasonCode::StoreWriteFailed, "journal rotation failed"));
    }
    impl_->entry_count = 0;
    impl_->journal_size = 0;
    notes.push_back(ReasonCode::StoreRotationPerformed);
  }
  canonicalize_reasons(notes);
  return appended;
}

Outcome<CommitToken> Store::compact(const RegistryState& state, Tick now) {
  auto written = write_snapshot(state, now);
  if (!written.ok()) return written;
  if (!truncate_journal(journal_path(impl_->options.base_path))) {
    return Outcome<CommitToken>(
        Status::failure(ReasonCode::StoreWriteFailed, "journal truncation failed"));
  }
  impl_->entry_count = 0;
  impl_->journal_size = 0;
  return written;
}

Outcome<RegistryState> load_state(const StoreOptions& options, RecoverySummary& summary) {
  auto report = Store::open(options);
  if (!report.ok()) {
    summary.classification = RecoveryClass::Refused;
    summary.reason = report.reason();
    return Outcome<RegistryState>(report.status());
  }
  OpenReport& value = report.value();
  summary.classification = value.classification;
  summary.reason = value.reason;
  summary.journal_records_replayed = value.journal_entries_valid;
  summary.journal_records_dropped = value.journal_entries_dropped;
  summary.bytes_discarded = value.bytes_discarded;
  summary.records_adopted = value.state.records.size();
  summary.tombstones_adopted = value.state.tombstones.size();
  summary.snapshot_generation = value.state.store_generation.value();
  summary.boot_epoch = value.state.boot_epoch;
  if (value.journal_entries_dropped > 0) {
    summary.notes.push_back(ReasonCode::RecoveryTrailingCorruptDropped);
  }
  if (value.bytes_discarded > 0) {
    summary.notes.push_back(ReasonCode::RecoveryTornTailTruncated);
  }
  canonicalize_reasons(summary.notes);
  return Outcome<RegistryState>(std::move(value.state));
}

}  // namespace ocreg
