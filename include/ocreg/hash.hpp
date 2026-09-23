// Offload Capability Registry - canonical digests and integrity checksums.
// Copyright 2026 Summon Software Labs.
#ifndef OCREG_HASH_HPP
#define OCREG_HASH_HPP

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace ocreg {

inline constexpr std::size_t kDigestBytes = 32;

// SHA-256 digest. The canonical identity of every derived artifact.
class Digest256 {
 public:
  constexpr Digest256() noexcept = default;
  constexpr explicit Digest256(std::array<std::uint8_t, kDigestBytes> bytes) noexcept
      : bytes_(bytes) {}

  [[nodiscard]] static Digest256 of(std::span<const std::uint8_t> data) noexcept;
  [[nodiscard]] static Digest256 of(std::string_view data) noexcept;

  // Parses exactly 64 lower-case hex characters. Rejects everything else,
  // including upper case, so canonical form has a single spelling.
  [[nodiscard]] static bool parse(std::string_view hex, Digest256& out) noexcept;

  [[nodiscard]] std::string hex() const;
  [[nodiscard]] constexpr const std::array<std::uint8_t, kDigestBytes>& bytes() const noexcept {
    return bytes_;
  }
  [[nodiscard]] constexpr bool is_zero() const noexcept {
    for (const auto byte : bytes_) {
      if (byte != 0) return false;
    }
    return true;
  }

  friend constexpr bool operator==(const Digest256&, const Digest256&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const Digest256& a,
                                                    const Digest256& b) noexcept {
    for (std::size_t i = 0; i < kDigestBytes; ++i) {
      if (a.bytes_[i] != b.bytes_[i]) {
        return a.bytes_[i] < b.bytes_[i] ? std::strong_ordering::less
                                         : std::strong_ordering::greater;
      }
    }
    return std::strong_ordering::equal;
  }

 private:
  std::array<std::uint8_t, kDigestBytes> bytes_{};
};

// Streaming SHA-256. Never throws; update() accepts arbitrarily long input.
class Sha256 {
 public:
  Sha256() noexcept;

  void update(std::span<const std::uint8_t> data) noexcept;
  void update(std::string_view data) noexcept;
  void update_byte(std::uint8_t byte) noexcept;

  // Big-endian fixed-width integer encodings used by canonical writers.
  void update_u16(std::uint16_t value) noexcept;
  void update_u32(std::uint32_t value) noexcept;
  void update_u64(std::uint64_t value) noexcept;
  // Length-prefixed byte string: u32 length followed by the bytes.
  void update_bytes(std::string_view data) noexcept;

  [[nodiscard]] Digest256 finish() noexcept;

 private:
  void compress(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, 64> buffer_{};
  std::size_t buffered_ = 0;
  std::uint64_t total_bytes_ = 0;
  bool finished_ = false;
};

// CRC-32C (Castagnoli), used for cheap structural integrity of stored frames.
[[nodiscard]] std::uint32_t crc32c(std::span<const std::uint8_t> data) noexcept;
[[nodiscard]] std::uint32_t crc32c(std::string_view data) noexcept;

class Crc32c {
 public:
  void update(std::span<const std::uint8_t> data) noexcept;
  void update(std::string_view data) noexcept;
  [[nodiscard]] std::uint32_t value() const noexcept { return state_ ^ 0xFFFFFFFFu; }
  void reset() noexcept { state_ = 0xFFFFFFFFu; }

 private:
  std::uint32_t state_ = 0xFFFFFFFFu;
};

// FNV-1a 64-bit. Used only for non-persisted, in-process hashing (for example
// hash-bucket placement); never for integrity claims.
[[nodiscard]] std::uint64_t fnv1a64(std::string_view data) noexcept;

}  // namespace ocreg

#endif  // OCREG_HASH_HPP
