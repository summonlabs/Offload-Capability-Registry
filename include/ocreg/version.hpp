// Offload Capability Registry - version and build identity.
// Copyright 2026 Summon Software Labs.
#ifndef OCREG_VERSION_HPP
#define OCREG_VERSION_HPP

#include <cstdint>
#include <string_view>

namespace ocreg {

inline constexpr std::uint32_t kVersionMajor = 1;
inline constexpr std::uint32_t kVersionMinor = 0;
inline constexpr std::uint32_t kVersionPatch = 0;

// Numeric, monotonic library ABI/API generation.
inline constexpr std::uint32_t kApiGeneration = 1;

// On-disk store format version. Independent of the library version.
inline constexpr std::uint32_t kStoreFormatVersion = 1;

// Wire protocol version for the service transport.
inline constexpr std::uint32_t kProtocolVersion = 1;

// Canonical export document version.
inline constexpr std::uint32_t kExportFormatVersion = 1;

// Canonical dotted version string of this library generation.
inline constexpr std::string_view kVersionString = "1.0.0";

inline constexpr std::string_view version_string() noexcept { return kVersionString; }

}  // namespace ocreg

#endif  // OCREG_VERSION_HPP
