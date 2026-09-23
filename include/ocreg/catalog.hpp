// Offload Capability Registry - the closed capability catalog.
// Copyright 2026 Summon Software Labs.
//
// Capability kinds, features and limits are enumerated with stable numeric
// codes and canonical spellings. Using enumerated codes rather than free-form
// strings makes "this feature does not exist", "this feature is not part of
// this capability kind" and "this limit has the wrong unit" decidable errors
// instead of silent acceptance.
#ifndef OCREG_CATALOG_HPP
#define OCREG_CATALOG_HPP

#include <compare>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "ocreg/reason.hpp"
#include "ocreg/strong.hpp"
#include "ocreg/units.hpp"

namespace ocreg {

// Firmware build generation reported by a device incarnation.
struct FirmwareGenerationTag;
using FirmwareGeneration = Strong<FirmwareGenerationTag, std::uint64_t>;

// Device runtime/driver generation reported by a device incarnation.
struct RuntimeGenerationTag;
using RuntimeGeneration = Strong<RuntimeGenerationTag, std::uint64_t>;

inline constexpr std::size_t kMaxFeaturesPerRecord = 64;
inline constexpr std::size_t kMaxLimitsPerRecord = 64;

// Stable numeric capability kind codes. Never renumbered.
enum class CapabilityKind : std::uint16_t {
  PacketClassification = 1,
  ChecksumOffload = 2,
  TlsRecordCrypto = 3,
  IpsecEsp = 4,
  RdmaTransport = 5,
  OvsDatapath = 6,
  ProgrammablePipeline = 7,
  CompressionOffload = 8,
  BulkCrypto = 9,
  Timestamping = 10,
  VirtualSwitch = 11,
  StorageOffload = 12,
  DmaEngine = 13,
  FlowSteering = 14,
};

inline constexpr std::size_t kCapabilityKindCount = 14;

// Stable numeric feature codes. Never renumbered. The value 0 is reserved and
// is not a valid feature.
enum class FeatureCode : std::uint32_t {
  // PacketClassification
  ClassifyL2Ethertype = 1,
  ClassifyL3Ipv4 = 2,
  ClassifyL3Ipv6 = 3,
  ClassifyL4TcpUdp = 4,
  ClassifyTunnelVxlan = 5,
  ClassifyTunnelGeneve = 6,
  ClassifyInnerHeader = 7,
  ClassifyMpls = 8,
  // ChecksumOffload
  ChecksumIpv4HeaderTx = 20,
  ChecksumIpv4HeaderRx = 21,
  ChecksumL4Tx = 22,
  ChecksumL4Rx = 23,
  ChecksumOuterL4 = 24,
  ChecksumLargeReceiveOffload = 25,
  ChecksumReceiveCoalescing = 26,
  // TlsRecordCrypto
  Tls12 = 40,
  Tls13 = 41,
  TlsAesGcm128 = 42,
  TlsAesGcm256 = 43,
  TlsChacha20Poly1305 = 44,
  TlsRecordAlignment = 45,
  TlsKeyUpdate = 46,
  // IpsecEsp
  IpsecEspTransport = 60,
  IpsecEspTunnel = 61,
  IpsecAesGcm128 = 62,
  IpsecAesGcm256 = 63,
  IpsecAesCbcSha256 = 64,
  IpsecAntiReplay = 65,
  IpsecNatTraversal = 66,
  // RdmaTransport
  RdmaRoceV1 = 80,
  RdmaRoceV2 = 81,
  RdmaIwrap = 82,
  RdmaReliableConnection = 83,
  RdmaUnreliableDatagram = 84,
  RdmaAtomicOperations = 85,
  RdmaMemoryWindows = 86,
  RdmaScatterGather = 87,
  // OvsDatapath
  OvsKernelDatapath = 100,
  OvsUserspaceDatapath = 101,
  OvsConntrack = 102,
  OvsMeter = 103,
  OvsTunnelVxlan = 104,
  OvsTunnelGeneve = 105,
  OvsRecirculation = 106,
  // ProgrammablePipeline
  PipelineP4_16 = 120,
  PipelineP4_14 = 121,
  PipelinePsaArchitecture = 122,
  PipelineV1ModelArchitecture = 123,
  PipelineParserState = 124,
  PipelineRegisterArray = 125,
  PipelineMeterArray = 126,
  PipelineDigestExport = 127,
  PipelineExternFunction = 128,
  // CompressionOffload
  CompressionDeflate = 140,
  CompressionLz4 = 141,
  CompressionZstd = 142,
  CompressionSnappy = 143,
  CompressionStateless = 144,
  CompressionStateful = 145,
  // BulkCrypto
  CryptoAesCbc128 = 160,
  CryptoAesCbc256 = 161,
  CryptoAesXts256 = 162,
  CryptoAesGcm128 = 163,
  CryptoAesGcm256 = 164,
  CryptoSha1Hmac = 165,
  CryptoSha256Hmac = 166,
  CryptoChacha20Poly1305 = 167,
  CryptoKeyWrap = 168,
  // Timestamping
  TimestampPtpV2 = 180,
  TimestampHardwareTx = 181,
  TimestampHardwareRx = 182,
  TimestampOneStep = 183,
  TimestampTwoStep = 184,
  TimestampPhc = 185,
  // VirtualSwitch
  VirtualSwitchSriovVf = 200,
  VirtualSwitchVirtioNet = 201,
  VirtualSwitchVdpa = 202,
  VirtualSwitchMacLearning = 203,
  VirtualSwitchVlanTagging = 204,
  VirtualSwitchPortMirroring = 205,
  VirtualSwitchLagBonding = 206,
  // StorageOffload
  StorageNvmeTcp = 220,
  StorageNvmeRdma = 221,
  StorageIscsi = 222,
  StorageT10Dif = 223,
  StorageErasureCoding = 224,
  StorageReplication = 225,
  // DmaEngine
  DmaDescriptorRing = 240,
  DmaScatterGather = 241,
  DmaInterruptCoalescing = 242,
  DmaAtomicTransfer = 243,
  // FlowSteering
  FlowSteeringRss = 260,
  FlowSteeringRssHashIpv4 = 261,
  FlowSteeringRssHashIpv6 = 262,
  FlowSteeringFlowDirector = 263,
  FlowSteeringTcFlower = 264,
  FlowSteeringActionMark = 265,
  FlowSteeringActionMirror = 266,
  FlowSteeringActionDrop = 267,
};

// Stable numeric limit codes. Never renumbered; 0 is reserved.
enum class LimitCode : std::uint32_t {
  ClassifierEntries = 1,
  ClassifierEntriesIpv6 = 2,
  AclRules = 3,
  FlowTableEntries = 4,
  MeterCount = 5,
  RegisterCells = 6,
  ParserStates = 7,
  ParserDepth = 8,
  Bandwidth = 9,
  PacketRate = 10,
  ConntrackEntries = 11,
  TlsSessions = 12,
  IpsecSecurityAssociations = 13,
  RdmaQueuePairs = 14,
  RdmaCompletionQueues = 15,
  RdmaMemoryRegionBytes = 16,
  DmaChannels = 17,
  DmaDescriptorDepth = 18,
  MaximumTransmissionUnit = 19,
  MaximumRecordSize = 20,
  CryptoThroughput = 21,
  CompressionThroughput = 22,
  CompressionRatio = 23,
  Latency = 24,
  Jitter = 25,
  PhcClockAccuracy = 26,
  TimestampResolution = 27,
  VirtualFunctions = 28,
  QueueCount = 29,
  ReceiveQueues = 30,
  TransmitQueues = 31,
  StorageIops = 32,
  StorageThroughput = 33,
  NvmeQueueDepth = 34,
  ErasureCodeFragments = 35,
  SharedMemoryBytes = 36,
  FirmwareImageBytes = 37,
};

struct FeatureInfo {
  FeatureCode code;
  std::string_view name;
  std::uint16_t kind_mask;
};

struct LimitInfo {
  LimitCode code;
  std::string_view name;
  std::uint16_t kind_mask;
  UnitCode unit;
  bool decimal_scale_permitted;
  bool binary_scale_permitted;
};

[[nodiscard]] constexpr std::uint16_t kind_bit(CapabilityKind kind) noexcept {
  return static_cast<std::uint16_t>(1u << (static_cast<std::uint16_t>(kind) - 1u));
}

[[nodiscard]] std::span<const CapabilityKind> all_capability_kinds() noexcept;
[[nodiscard]] std::span<const FeatureInfo> all_features() noexcept;
[[nodiscard]] std::span<const LimitInfo> all_limits() noexcept;

[[nodiscard]] std::string_view to_string(CapabilityKind kind) noexcept;
[[nodiscard]] std::string_view to_string(FeatureCode code) noexcept;
[[nodiscard]] std::string_view to_string(LimitCode code) noexcept;

[[nodiscard]] bool parse_capability_kind(std::string_view text, CapabilityKind& out) noexcept;
[[nodiscard]] bool parse_feature_code(std::string_view text, FeatureCode& out) noexcept;
[[nodiscard]] bool parse_limit_code(std::string_view text, LimitCode& out) noexcept;

[[nodiscard]] const FeatureInfo* feature_info(FeatureCode code) noexcept;
[[nodiscard]] const LimitInfo* limit_info(LimitCode code) noexcept;

[[nodiscard]] bool feature_allowed_for(FeatureCode code, CapabilityKind kind) noexcept;
[[nodiscard]] bool limit_allowed_for(LimitCode code, CapabilityKind kind) noexcept;

// The canonical unit of a limit code, with no scale applied.
[[nodiscard]] std::optional<Unit> canonical_unit_for(LimitCode code) noexcept;

// Validates that a unit is acceptable for a limit code: matching unit code,
// permitted scale, exponent within bounds.
[[nodiscard]] bool unit_valid_for_limit(LimitCode code, const Unit& unit) noexcept;

// Fingerprint of the whole catalog table (codes, spellings, kind masks, units).
[[nodiscard]] std::uint32_t catalog_fingerprint() noexcept;

// A sorted, de-duplicated, closed set of feature codes.
class FeatureSet {
 public:
  FeatureSet() = default;

  // Validates membership, de-duplicates and sorts. Returns false and sets
  // 'reason' on the first problem found in canonical order.
  [[nodiscard]] static bool make(const std::vector<FeatureCode>& codes, CapabilityKind kind,
                                 FeatureSet& out, ReasonCode& reason);

  // Builds from codes already validated against 'kind'.
  [[nodiscard]] static FeatureSet from_validated(std::vector<FeatureCode> codes);

  [[nodiscard]] bool contains(FeatureCode code) const noexcept;
  // True when every code in 'required' is present here.
  [[nodiscard]] bool contains_all(const FeatureSet& required) const noexcept;
  [[nodiscard]] const std::vector<FeatureCode>& codes() const noexcept { return codes_; }
  [[nodiscard]] bool empty() const noexcept { return codes_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return codes_.size(); }

  friend bool operator==(const FeatureSet&, const FeatureSet&) noexcept = default;
  friend std::strong_ordering operator<=>(const FeatureSet&, const FeatureSet&) noexcept;

 private:
  std::vector<FeatureCode> codes_{};
};

// A single limit assertion: code, exact unit and value.
struct LimitValue {
  LimitCode code = LimitCode::ClassifierEntries;
  Unit unit{};
  std::int64_t value = 0;

  friend bool operator==(const LimitValue& a, const LimitValue& b) noexcept {
    return a.code == b.code && a.unit == b.unit && a.value == b.value;
  }
  friend std::strong_ordering operator<=>(const LimitValue& a, const LimitValue& b) noexcept {
    return a.code <=> b.code;
  }
};

// A sorted, de-duplicated set of limit assertions, at most one per limit code.
class LimitSet {
 public:
  LimitSet() = default;

  [[nodiscard]] static bool make(const std::vector<LimitValue>& values, CapabilityKind kind,
                                 LimitSet& out, ReasonCode& reason);
  [[nodiscard]] static LimitSet from_validated(std::vector<LimitValue> values);

  [[nodiscard]] const LimitValue* find(LimitCode code) const noexcept;
  [[nodiscard]] const std::vector<LimitValue>& values() const noexcept { return values_; }
  [[nodiscard]] bool empty() const noexcept { return values_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return values_.size(); }

  friend bool operator==(const LimitSet&, const LimitSet&) noexcept = default;
  friend std::strong_ordering operator<=>(const LimitSet&, const LimitSet&) noexcept;

 private:
  std::vector<LimitValue> values_{};
};

}  // namespace ocreg

#endif  // OCREG_CATALOG_HPP
