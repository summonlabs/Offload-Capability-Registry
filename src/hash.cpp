// Offload Capability Registry - canonical digests and integrity checksums.
// Copyright 2026 Summon Software Labs.
//
// Implementation of the SHA-256 (FIPS 180-4), CRC-32C (Castagnoli) and
// FNV-1a 64-bit primitives declared in <ocreg/hash.hpp>. Standard library
// only: no dynamic allocation, no undefined behaviour, no shared mutable
// state, and every word operation is unsigned so it wraps by definition.

#include "ocreg/hash.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace ocreg {
namespace {

// Rotate right. Every call site passes a shift in [1, 31]; the mask keeps the
// shift count well defined for shift == 0 as well, so the helper is total.
[[nodiscard]] constexpr std::uint32_t rotr(std::uint32_t value,
                                           unsigned int shift) noexcept {
  return (value >> shift) | (value << ((32U - shift) & 31U));
}

// Reinterpreting a char range as unsigned bytes is explicitly permitted by the
// aliasing rules, and no arithmetic is done through the aliased pointer.
[[nodiscard]] std::span<const std::uint8_t> as_bytes(std::string_view data) noexcept {
  return std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

// Lower-case hexadecimal value of a character, or 0xFF when it is not one.
// Upper case is deliberately not accepted: canonical form has one spelling.
[[nodiscard]] constexpr std::uint8_t hex_digit_value(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return static_cast<std::uint8_t>(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return static_cast<std::uint8_t>(c - 'a' + 10);
  }
  return 0xFFU;
}

inline constexpr char kHexDigits[] = "0123456789abcdef";

// --- SHA-256 constants (FIPS 180-4, sections 4.2.2 and 5.3.3) --------------

inline constexpr std::array<std::uint32_t, 64> kSha256K{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
    0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
    0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
    0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
    0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
    0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
    0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
    0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

// --- CRC-32C (Castagnoli) --------------------------------------------------
//
// Reflected polynomial 0x82F63B78 (the reflection of 0x1EDC6F41), reflected
// input and output, init 0xFFFFFFFF and final xor 0xFFFFFFFF. The table is
// built at compile time, so there is no static initialisation order question
// and no data race on first use.
[[nodiscard]] constexpr std::array<std::uint32_t, 256> make_crc32c_table() noexcept {
  std::array<std::uint32_t, 256> table{};
  for (std::size_t i = 0; i < table.size(); ++i) {
    std::uint32_t crc = static_cast<std::uint32_t>(i);
    for (int bit = 0; bit < 8; ++bit) {
      crc = ((crc & 1U) != 0U) ? ((crc >> 1) ^ 0x82F63B78U) : (crc >> 1);
    }
    table[i] = crc;
  }
  return table;
}

inline constexpr std::array<std::uint32_t, 256> kCrc32cTable = make_crc32c_table();

[[nodiscard]] constexpr std::uint32_t crc32c_update_byte(std::uint32_t crc,
                                                         std::uint8_t byte) noexcept {
  return kCrc32cTable[(crc ^ static_cast<std::uint32_t>(byte)) & 0xFFU] ^ (crc >> 8);
}

}  // namespace

// --- Sha256 ----------------------------------------------------------------

Sha256::Sha256() noexcept
    : state_{0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU,
             0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U},
      buffer_{},
      buffered_(0),
      total_bytes_(0),
      finished_(false) {}

void Sha256::compress(const std::uint8_t* block) noexcept {
  std::array<std::uint32_t, 64> w{};
  for (std::size_t i = 0; i < 16; ++i) {
    const std::size_t j = i * 4;
    // Big-endian byte-wise assembly: no unaligned word loads, no punning.
    w[i] = (static_cast<std::uint32_t>(block[j]) << 24) |
           (static_cast<std::uint32_t>(block[j + 1]) << 16) |
           (static_cast<std::uint32_t>(block[j + 2]) << 8) |
           static_cast<std::uint32_t>(block[j + 3]);
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t x = w[i - 15];
    const std::uint32_t y = w[i - 2];
    const std::uint32_t sigma0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    const std::uint32_t sigma1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10);
    w[i] = w[i - 16] + sigma0 + w[i - 7] + sigma1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t big_sigma1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const std::uint32_t choose = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + big_sigma1 + choose + kSha256K[i] + w[i];
    const std::uint32_t big_sigma0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = big_sigma0 + majority;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(std::span<const std::uint8_t> data) noexcept {
  // After finish() the object is final: further input is ignored so that the
  // digest can never change under the caller's feet and finish() stays
  // idempotent. Empty input is always a no-op.
  if (finished_ || data.empty()) {
    return;
  }

  // The byte counter wraps modulo 2^64 exactly as FIPS 180-4 requires.
  total_bytes_ += static_cast<std::uint64_t>(data.size());

  const std::uint8_t* cursor = data.data();
  std::size_t remaining = data.size();

  if (buffered_ != 0) {
    const std::size_t room = buffer_.size() - buffered_;
    const std::size_t take = (remaining < room) ? remaining : room;
    for (std::size_t i = 0; i < take; ++i) {
      buffer_[buffered_ + i] = cursor[i];
    }
    buffered_ += take;
    cursor += take;
    remaining -= take;
    if (buffered_ < buffer_.size()) {
      // The buffer is not full, so the caller's data was consumed entirely.
      return;
    }
    compress(buffer_.data());
    buffered_ = 0;
  }

  while (remaining >= buffer_.size()) {
    compress(cursor);
    cursor += buffer_.size();
    remaining -= buffer_.size();
  }

  for (std::size_t i = 0; i < remaining; ++i) {
    buffer_[i] = cursor[i];
  }
  buffered_ = remaining;
}

void Sha256::update(std::string_view data) noexcept { update(as_bytes(data)); }

void Sha256::update_byte(std::uint8_t byte) noexcept {
  if (finished_) {
    return;
  }
  buffer_[buffered_] = byte;
  ++buffered_;
  ++total_bytes_;
  if (buffered_ == buffer_.size()) {
    compress(buffer_.data());
    buffered_ = 0;
  }
}

void Sha256::update_u16(std::uint16_t value) noexcept {
  update_byte(static_cast<std::uint8_t>(value >> 8));
  update_byte(static_cast<std::uint8_t>(value & 0xFFU));
}

void Sha256::update_u32(std::uint32_t value) noexcept {
  update_byte(static_cast<std::uint8_t>(value >> 24));
  update_byte(static_cast<std::uint8_t>(value >> 16));
  update_byte(static_cast<std::uint8_t>(value >> 8));
  update_byte(static_cast<std::uint8_t>(value & 0xFFU));
}

void Sha256::update_u64(std::uint64_t value) noexcept {
  update_byte(static_cast<std::uint8_t>(value >> 56));
  update_byte(static_cast<std::uint8_t>(value >> 48));
  update_byte(static_cast<std::uint8_t>(value >> 40));
  update_byte(static_cast<std::uint8_t>(value >> 32));
  update_byte(static_cast<std::uint8_t>(value >> 24));
  update_byte(static_cast<std::uint8_t>(value >> 16));
  update_byte(static_cast<std::uint8_t>(value >> 8));
  update_byte(static_cast<std::uint8_t>(value & 0xFFU));
}

void Sha256::update_bytes(std::string_view data) noexcept {
  // A byte string longer than 2^32-1 cannot be length-prefixed faithfully; the
  // length is truncated to its low 32 bits rather than trapping.
  update_u32(static_cast<std::uint32_t>(data.size()));
  update(data);
}

Digest256 Sha256::finish() noexcept {
  if (!finished_) {
    // Message padding: 0x80, then zeros to 56 mod 64, then the 64-bit
    // big-endian message bit length (which wraps modulo 2^64).
    const std::uint64_t bit_length = total_bytes_ << 3;
    buffer_[buffered_] = static_cast<std::uint8_t>(0x80U);
    ++buffered_;
    if (buffered_ > 56) {
      while (buffered_ < buffer_.size()) {
        buffer_[buffered_] = 0;
        ++buffered_;
      }
      compress(buffer_.data());
      buffered_ = 0;
    }
    while (buffered_ < 56) {
      buffer_[buffered_] = 0;
      ++buffered_;
    }
    for (std::size_t i = 0; i < 8; ++i) {
      const unsigned int shift = static_cast<unsigned int>(56 - (i * 8));
      buffer_[56 + i] = static_cast<std::uint8_t>(bit_length >> shift);
    }
    compress(buffer_.data());
    buffered_ = 0;
    finished_ = true;
  }

  // Serialising the (now final) state is idempotent, so calling finish() more
  // than once yields the same digest.
  std::array<std::uint8_t, kDigestBytes> bytes{};
  for (std::size_t i = 0; i < state_.size(); ++i) {
    bytes[i * 4] = static_cast<std::uint8_t>(state_[i] >> 24);
    bytes[i * 4 + 1] = static_cast<std::uint8_t>(state_[i] >> 16);
    bytes[i * 4 + 2] = static_cast<std::uint8_t>(state_[i] >> 8);
    bytes[i * 4 + 3] = static_cast<std::uint8_t>(state_[i] & 0xFFU);
  }
  return Digest256{bytes};
}

// --- Digest256 -------------------------------------------------------------

Digest256 Digest256::of(std::span<const std::uint8_t> data) noexcept {
  Sha256 hasher;
  hasher.update(data);
  return hasher.finish();
}

Digest256 Digest256::of(std::string_view data) noexcept {
  Sha256 hasher;
  hasher.update(data);
  return hasher.finish();
}

bool Digest256::parse(std::string_view hex, Digest256& out) noexcept {
  if (hex.size() != kDigestBytes * 2) {
    return false;
  }
  std::array<std::uint8_t, kDigestBytes> bytes{};
  for (std::size_t i = 0; i < kDigestBytes; ++i) {
    const std::uint8_t hi = hex_digit_value(hex[i * 2]);
    const std::uint8_t lo = hex_digit_value(hex[i * 2 + 1]);
    if (hi == 0xFFU || lo == 0xFFU) {
      return false;
    }
    bytes[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  out = Digest256{bytes};
  return true;
}

std::string Digest256::hex() const {
  std::string out(kDigestBytes * 2, '0');
  for (std::size_t i = 0; i < bytes_.size(); ++i) {
    out[i * 2] = kHexDigits[(bytes_[i] >> 4) & 0x0FU];
    out[i * 2 + 1] = kHexDigits[bytes_[i] & 0x0FU];
  }
  return out;
}

// --- CRC-32C ---------------------------------------------------------------

void Crc32c::update(std::span<const std::uint8_t> data) noexcept {
  std::uint32_t crc = state_;
  for (const std::uint8_t byte : data) {
    crc = crc32c_update_byte(crc, byte);
  }
  state_ = crc;
}

void Crc32c::update(std::string_view data) noexcept { update(as_bytes(data)); }

std::uint32_t crc32c(std::span<const std::uint8_t> data) noexcept {
  Crc32c checksum;
  checksum.update(data);
  return checksum.value();
}

std::uint32_t crc32c(std::string_view data) noexcept {
  Crc32c checksum;
  checksum.update(data);
  return checksum.value();
}

// --- FNV-1a 64-bit ---------------------------------------------------------

std::uint64_t fnv1a64(std::string_view data) noexcept {
  constexpr std::uint64_t kOffsetBasis = 14695981039346656037ULL;
  constexpr std::uint64_t kPrime = 1099511628211ULL;
  std::uint64_t hash = kOffsetBasis;
  for (const char c : data) {
    hash ^= static_cast<std::uint64_t>(static_cast<std::uint8_t>(c));
    hash *= kPrime;
  }
  return hash;
}

}  // namespace ocreg
