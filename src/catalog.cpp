// Offload Capability Registry - the closed capability catalog.
// Copyright 2026 Summon Software Labs.
#include "ocreg/catalog.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>

#include "ocreg/hash.hpp"

namespace ocreg {
namespace {

// Kind masks. Declared as plain constants so the tables below stay readable.
constexpr std::uint16_t kPC = kind_bit(CapabilityKind::PacketClassification);
constexpr std::uint16_t kCO = kind_bit(CapabilityKind::ChecksumOffload);
constexpr std::uint16_t kTLS = kind_bit(CapabilityKind::TlsRecordCrypto);
constexpr std::uint16_t kIPSEC = kind_bit(CapabilityKind::IpsecEsp);
constexpr std::uint16_t kRDMA = kind_bit(CapabilityKind::RdmaTransport);
constexpr std::uint16_t kOVS = kind_bit(CapabilityKind::OvsDatapath);
constexpr std::uint16_t kPP = kind_bit(CapabilityKind::ProgrammablePipeline);
constexpr std::uint16_t kCOMP = kind_bit(CapabilityKind::CompressionOffload);
constexpr std::uint16_t kCRYPTO = kind_bit(CapabilityKind::BulkCrypto);
constexpr std::uint16_t kTS = kind_bit(CapabilityKind::Timestamping);
constexpr std::uint16_t kVS = kind_bit(CapabilityKind::VirtualSwitch);
constexpr std::uint16_t kSTOR = kind_bit(CapabilityKind::StorageOffload);
constexpr std::uint16_t kDMA = kind_bit(CapabilityKind::DmaEngine);
constexpr std::uint16_t kFS = kind_bit(CapabilityKind::FlowSteering);
constexpr std::uint16_t kAllKinds = static_cast<std::uint16_t>(kPC | kCO | kTLS | kIPSEC | kRDMA |
                                                               kOVS | kPP | kCOMP | kCRYPTO | kTS |
                                                               kVS | kSTOR | kDMA | kFS);

constexpr std::array<CapabilityKind, kCapabilityKindCount> kKinds = {
    CapabilityKind::PacketClassification, CapabilityKind::ChecksumOffload,
    CapabilityKind::TlsRecordCrypto,      CapabilityKind::IpsecEsp,
    CapabilityKind::RdmaTransport,        CapabilityKind::OvsDatapath,
    CapabilityKind::ProgrammablePipeline, CapabilityKind::CompressionOffload,
    CapabilityKind::BulkCrypto,           CapabilityKind::Timestamping,
    CapabilityKind::VirtualSwitch,        CapabilityKind::StorageOffload,
    CapabilityKind::DmaEngine,            CapabilityKind::FlowSteering,
};

constexpr std::array<FeatureInfo, 101> kFeatures = {{
    {FeatureCode::ClassifyL2Ethertype, "classify_l2_ethertype", kPC},
    {FeatureCode::ClassifyL3Ipv4, "classify_l3_ipv4", kPC},
    {FeatureCode::ClassifyL3Ipv6, "classify_l3_ipv6", kPC},
    {FeatureCode::ClassifyL4TcpUdp, "classify_l4_tcp_udp", kPC},
    {FeatureCode::ClassifyTunnelVxlan, "classify_tunnel_vxlan", kPC},
    {FeatureCode::ClassifyTunnelGeneve, "classify_tunnel_geneve", kPC},
    {FeatureCode::ClassifyInnerHeader, "classify_inner_header", kPC},
    {FeatureCode::ClassifyMpls, "classify_mpls", kPC},
    {FeatureCode::ChecksumIpv4HeaderTx, "checksum_ipv4_header_tx", kCO},
    {FeatureCode::ChecksumIpv4HeaderRx, "checksum_ipv4_header_rx", kCO},
    {FeatureCode::ChecksumL4Tx, "checksum_l4_tx", kCO},
    {FeatureCode::ChecksumL4Rx, "checksum_l4_rx", kCO},
    {FeatureCode::ChecksumOuterL4, "checksum_outer_l4", kCO},
    {FeatureCode::ChecksumLargeReceiveOffload, "checksum_large_receive_offload", kCO},
    {FeatureCode::ChecksumReceiveCoalescing, "checksum_receive_coalescing", kCO},
    {FeatureCode::Tls12, "tls_1_2", kTLS},
    {FeatureCode::Tls13, "tls_1_3", kTLS},
    {FeatureCode::TlsAesGcm128, "tls_aes_gcm_128", kTLS},
    {FeatureCode::TlsAesGcm256, "tls_aes_gcm_256", kTLS},
    {FeatureCode::TlsChacha20Poly1305, "tls_chacha20_poly1305", kTLS},
    {FeatureCode::TlsRecordAlignment, "tls_record_alignment", kTLS},
    {FeatureCode::TlsKeyUpdate, "tls_key_update", kTLS},
    {FeatureCode::IpsecEspTransport, "ipsec_esp_transport", kIPSEC},
    {FeatureCode::IpsecEspTunnel, "ipsec_esp_tunnel", kIPSEC},
    {FeatureCode::IpsecAesGcm128, "ipsec_aes_gcm_128", kIPSEC},
    {FeatureCode::IpsecAesGcm256, "ipsec_aes_gcm_256", kIPSEC},
    {FeatureCode::IpsecAesCbcSha256, "ipsec_aes_cbc_sha256", kIPSEC},
    {FeatureCode::IpsecAntiReplay, "ipsec_anti_replay", kIPSEC},
    {FeatureCode::IpsecNatTraversal, "ipsec_nat_traversal", kIPSEC},
    {FeatureCode::RdmaRoceV1, "rdma_roce_v1", kRDMA},
    {FeatureCode::RdmaRoceV2, "rdma_roce_v2", kRDMA},
    {FeatureCode::RdmaIwrap, "rdma_iwarp", kRDMA},
    {FeatureCode::RdmaReliableConnection, "rdma_reliable_connection", kRDMA},
    {FeatureCode::RdmaUnreliableDatagram, "rdma_unreliable_datagram", kRDMA},
    {FeatureCode::RdmaAtomicOperations, "rdma_atomic_operations", kRDMA},
    {FeatureCode::RdmaMemoryWindows, "rdma_memory_windows", kRDMA},
    {FeatureCode::RdmaScatterGather, "rdma_scatter_gather", kRDMA},
    {FeatureCode::OvsKernelDatapath, "ovs_kernel_datapath", kOVS},
    {FeatureCode::OvsUserspaceDatapath, "ovs_userspace_datapath", kOVS},
    {FeatureCode::OvsConntrack, "ovs_conntrack", kOVS},
    {FeatureCode::OvsMeter, "ovs_meter", kOVS},
    {FeatureCode::OvsTunnelVxlan, "ovs_tunnel_vxlan", kOVS},
    {FeatureCode::OvsTunnelGeneve, "ovs_tunnel_geneve", kOVS},
    {FeatureCode::OvsRecirculation, "ovs_recirculation", kOVS},
    {FeatureCode::PipelineP4_16, "pipeline_p4_16", kPP},
    {FeatureCode::PipelineP4_14, "pipeline_p4_14", kPP},
    {FeatureCode::PipelinePsaArchitecture, "pipeline_psa_architecture", kPP},
    {FeatureCode::PipelineV1ModelArchitecture, "pipeline_v1model_architecture", kPP},
    {FeatureCode::PipelineParserState, "pipeline_parser_state", kPP},
    {FeatureCode::PipelineRegisterArray, "pipeline_register_array", kPP},
    {FeatureCode::PipelineMeterArray, "pipeline_meter_array", kPP},
    {FeatureCode::PipelineDigestExport, "pipeline_digest_export", kPP},
    {FeatureCode::PipelineExternFunction, "pipeline_extern_function", kPP},
    {FeatureCode::CompressionDeflate, "compression_deflate", kCOMP},
    {FeatureCode::CompressionLz4, "compression_lz4", kCOMP},
    {FeatureCode::CompressionZstd, "compression_zstd", kCOMP},
    {FeatureCode::CompressionSnappy, "compression_snappy", kCOMP},
    {FeatureCode::CompressionStateless, "compression_stateless", kCOMP},
    {FeatureCode::CompressionStateful, "compression_stateful", kCOMP},
    {FeatureCode::CryptoAesCbc128, "crypto_aes_cbc_128", kCRYPTO},
    {FeatureCode::CryptoAesCbc256, "crypto_aes_cbc_256", kCRYPTO},
    {FeatureCode::CryptoAesXts256, "crypto_aes_xts_256", kCRYPTO},
    {FeatureCode::CryptoAesGcm128, "crypto_aes_gcm_128", kCRYPTO},
    {FeatureCode::CryptoAesGcm256, "crypto_aes_gcm_256", kCRYPTO},
    {FeatureCode::CryptoSha1Hmac, "crypto_sha1_hmac", kCRYPTO},
    {FeatureCode::CryptoSha256Hmac, "crypto_sha256_hmac", kCRYPTO},
    {FeatureCode::CryptoChacha20Poly1305, "crypto_chacha20_poly1305", kCRYPTO},
    {FeatureCode::CryptoKeyWrap, "crypto_key_wrap", kCRYPTO},
    {FeatureCode::TimestampPtpV2, "timestamp_ptp_v2", kTS},
    {FeatureCode::TimestampHardwareTx, "timestamp_hardware_tx", kTS},
    {FeatureCode::TimestampHardwareRx, "timestamp_hardware_rx", kTS},
    {FeatureCode::TimestampOneStep, "timestamp_one_step", kTS},
    {FeatureCode::TimestampTwoStep, "timestamp_two_step", kTS},
    {FeatureCode::TimestampPhc, "timestamp_phc", kTS},
    {FeatureCode::VirtualSwitchSriovVf, "virtual_switch_sriov_vf", kVS},
    {FeatureCode::VirtualSwitchVirtioNet, "virtual_switch_virtio_net", kVS},
    {FeatureCode::VirtualSwitchVdpa, "virtual_switch_vdpa", kVS},
    {FeatureCode::VirtualSwitchMacLearning, "virtual_switch_mac_learning", kVS},
    {FeatureCode::VirtualSwitchVlanTagging, "virtual_switch_vlan_tagging", kVS},
    {FeatureCode::VirtualSwitchPortMirroring, "virtual_switch_port_mirroring", kVS},
    {FeatureCode::VirtualSwitchLagBonding, "virtual_switch_lag_bonding", kVS},
    {FeatureCode::StorageNvmeTcp, "storage_nvme_tcp", kSTOR},
    {FeatureCode::StorageNvmeRdma, "storage_nvme_rdma", kSTOR},
    {FeatureCode::StorageIscsi, "storage_iscsi", kSTOR},
    {FeatureCode::StorageT10Dif, "storage_t10_dif", kSTOR},
    {FeatureCode::StorageErasureCoding, "storage_erasure_coding", kSTOR},
    {FeatureCode::StorageReplication, "storage_replication", kSTOR},
    {FeatureCode::DmaDescriptorRing, "dma_descriptor_ring", kDMA},
    {FeatureCode::DmaScatterGather, "dma_scatter_gather", kDMA},
    {FeatureCode::DmaInterruptCoalescing, "dma_interrupt_coalescing", kDMA},
    {FeatureCode::DmaAtomicTransfer, "dma_atomic_transfer", kDMA},
    {FeatureCode::FlowSteeringRss, "flow_steering_rss", kFS},
    {FeatureCode::FlowSteeringRssHashIpv4, "flow_steering_rss_hash_ipv4", kFS},
    {FeatureCode::FlowSteeringRssHashIpv6, "flow_steering_rss_hash_ipv6", kFS},
    {FeatureCode::FlowSteeringFlowDirector, "flow_steering_flow_director", kFS},
    {FeatureCode::FlowSteeringTcFlower, "flow_steering_tc_flower", kFS},
    {FeatureCode::FlowSteeringActionMark, "flow_steering_action_mark", kFS},
    {FeatureCode::FlowSteeringActionMirror, "flow_steering_action_mirror", kFS},
    {FeatureCode::FlowSteeringActionDrop, "flow_steering_action_drop", kFS},
}};

constexpr std::array<LimitInfo, 37> kLimits = {{
    {LimitCode::ClassifierEntries, "classifier_entries", static_cast<std::uint16_t>(kPC | kFS | kOVS),
     UnitCode::Count, false, false},
    {LimitCode::ClassifierEntriesIpv6, "classifier_entries_ipv6",
     static_cast<std::uint16_t>(kPC | kFS | kOVS), UnitCode::Count, false, false},
    {LimitCode::AclRules, "acl_rules", static_cast<std::uint16_t>(kPC | kFS | kOVS), UnitCode::Count,
     false, false},
    {LimitCode::FlowTableEntries, "flow_table_entries",
     static_cast<std::uint16_t>(kOVS | kFS | kPP), UnitCode::Count, false, false},
    {LimitCode::MeterCount, "meter_count", static_cast<std::uint16_t>(kOVS | kPP | kFS),
     UnitCode::Count, false, false},
    {LimitCode::RegisterCells, "register_cells", kPP, UnitCode::Count, false, false},
    {LimitCode::ParserStates, "parser_states", kPP, UnitCode::Count, false, false},
    {LimitCode::ParserDepth, "parser_depth", kPP, UnitCode::Count, false, false},
    {LimitCode::Bandwidth, "bandwidth",
     static_cast<std::uint16_t>(kPC | kCO | kTLS | kIPSEC | kRDMA | kOVS | kVS | kFS | kDMA | kCRYPTO |
                                kCOMP | kSTOR),
     UnitCode::BitPerSecond, true, true},
    {LimitCode::PacketRate, "packet_rate", static_cast<std::uint16_t>(kPC | kCO | kOVS | kFS | kVS),
     UnitCode::PacketPerSecond, true, true},
    {LimitCode::ConntrackEntries, "conntrack_entries", static_cast<std::uint16_t>(kOVS | kVS | kFS),
     UnitCode::Count, false, false},
    {LimitCode::TlsSessions, "tls_sessions", kTLS, UnitCode::Count, false, false},
    {LimitCode::IpsecSecurityAssociations, "ipsec_security_associations", kIPSEC, UnitCode::Count,
     false, false},
    {LimitCode::RdmaQueuePairs, "rdma_queue_pairs", kRDMA, UnitCode::Count, false, false},
    {LimitCode::RdmaCompletionQueues, "rdma_completion_queues", kRDMA, UnitCode::Count, false, false},
    {LimitCode::RdmaMemoryRegionBytes, "rdma_memory_region_bytes", kRDMA, UnitCode::Byte, true, true},
    {LimitCode::DmaChannels, "dma_channels", kDMA, UnitCode::Count, false, false},
    {LimitCode::DmaDescriptorDepth, "dma_descriptor_depth", kDMA, UnitCode::Count, false, false},
    {LimitCode::MaximumTransmissionUnit, "maximum_transmission_unit",
     static_cast<std::uint16_t>(kPC | kCO | kTLS | kIPSEC | kOVS | kVS | kFS), UnitCode::Byte, false,
     false},
    {LimitCode::MaximumRecordSize, "maximum_record_size", kTLS, UnitCode::Byte, true, true},
    {LimitCode::CryptoThroughput, "crypto_throughput", static_cast<std::uint16_t>(kCRYPTO | kIPSEC | kTLS),
     UnitCode::BytePerSecond, true, true},
    {LimitCode::CompressionThroughput, "compression_throughput", kCOMP, UnitCode::BytePerSecond, true,
     true},
    {LimitCode::CompressionRatio, "compression_ratio", kCOMP, UnitCode::Percent, false, false},
    {LimitCode::Latency, "latency", kAllKinds, UnitCode::NanoSecond, true, false},
    {LimitCode::Jitter, "jitter", kAllKinds, UnitCode::NanoSecond, true, false},
    {LimitCode::PhcClockAccuracy, "phc_clock_accuracy", kTS, UnitCode::NanoSecond, true, false},
    {LimitCode::TimestampResolution, "timestamp_resolution", kTS, UnitCode::NanoSecond, true, false},
    {LimitCode::VirtualFunctions, "virtual_functions", static_cast<std::uint16_t>(kVS | kPC | kFS),
     UnitCode::Count, false, false},
    {LimitCode::QueueCount, "queue_count", static_cast<std::uint16_t>(kRDMA | kVS | kCO | kDMA), UnitCode::Count,
     false, false},
    {LimitCode::ReceiveQueues, "receive_queues", static_cast<std::uint16_t>(kCO | kVS | kFS | kRDMA),
     UnitCode::Count, false, false},
    {LimitCode::TransmitQueues, "transmit_queues", static_cast<std::uint16_t>(kCO | kVS | kFS | kRDMA),
     UnitCode::Count, false, false},
    {LimitCode::StorageIops, "storage_iops", kSTOR, UnitCode::OperationPerSecond, true, false},
    {LimitCode::StorageThroughput, "storage_throughput", kSTOR, UnitCode::BytePerSecond, true, true},
    {LimitCode::NvmeQueueDepth, "nvme_queue_depth", kSTOR, UnitCode::Count, false, false},
    {LimitCode::ErasureCodeFragments, "erasure_code_fragments", kSTOR, UnitCode::Count, false, false},
    {LimitCode::SharedMemoryBytes, "shared_memory_bytes",
     static_cast<std::uint16_t>(kRDMA | kDMA | kPP | kVS), UnitCode::Byte, true, true},
    {LimitCode::FirmwareImageBytes, "firmware_image_bytes", kAllKinds, UnitCode::Byte, true, true},
}};

}  // namespace

std::span<const CapabilityKind> all_capability_kinds() noexcept { return kKinds; }

std::span<const FeatureInfo> all_features() noexcept { return kFeatures; }

std::span<const LimitInfo> all_limits() noexcept { return kLimits; }

std::string_view to_string(CapabilityKind kind) noexcept {
  switch (kind) {
    case CapabilityKind::PacketClassification: return "packet_classification";
    case CapabilityKind::ChecksumOffload: return "checksum_offload";
    case CapabilityKind::TlsRecordCrypto: return "tls_record_crypto";
    case CapabilityKind::IpsecEsp: return "ipsec_esp";
    case CapabilityKind::RdmaTransport: return "rdma_transport";
    case CapabilityKind::OvsDatapath: return "ovs_datapath";
    case CapabilityKind::ProgrammablePipeline: return "programmable_pipeline";
    case CapabilityKind::CompressionOffload: return "compression_offload";
    case CapabilityKind::BulkCrypto: return "bulk_crypto";
    case CapabilityKind::Timestamping: return "timestamping";
    case CapabilityKind::VirtualSwitch: return "virtual_switch";
    case CapabilityKind::StorageOffload: return "storage_offload";
    case CapabilityKind::DmaEngine: return "dma_engine";
    case CapabilityKind::FlowSteering: return "flow_steering";
  }
  return "unknown";
}

std::string_view to_string(FeatureCode code) noexcept {
  const FeatureInfo* info = feature_info(code);
  return info == nullptr ? std::string_view("unknown") : info->name;
}

std::string_view to_string(LimitCode code) noexcept {
  const LimitInfo* info = limit_info(code);
  return info == nullptr ? std::string_view("unknown") : info->name;
}

bool parse_capability_kind(std::string_view text, CapabilityKind& out) noexcept {
  for (const auto kind : kKinds) {
    if (to_string(kind) == text) {
      out = kind;
      return true;
    }
  }
  return false;
}

bool parse_feature_code(std::string_view text, FeatureCode& out) noexcept {
  for (const auto& info : kFeatures) {
    if (info.name == text) {
      out = info.code;
      return true;
    }
  }
  return false;
}

bool parse_limit_code(std::string_view text, LimitCode& out) noexcept {
  for (const auto& info : kLimits) {
    if (info.name == text) {
      out = info.code;
      return true;
    }
  }
  return false;
}

const FeatureInfo* feature_info(FeatureCode code) noexcept {
  for (const auto& info : kFeatures) {
    if (info.code == code) return &info;
  }
  return nullptr;
}

const LimitInfo* limit_info(LimitCode code) noexcept {
  for (const auto& info : kLimits) {
    if (info.code == code) return &info;
  }
  return nullptr;
}

bool capability_kind_from_code(std::uint16_t raw, CapabilityKind& out) noexcept {
  for (const auto kind : kKinds) {
    if (static_cast<std::uint16_t>(kind) == raw) {
      out = kind;
      return true;
    }
  }
  return false;
}

bool feature_from_code(std::uint32_t raw, FeatureCode& out) noexcept {
  for (const auto& info : kFeatures) {
    if (static_cast<std::uint32_t>(info.code) == raw) {
      out = info.code;
      return true;
    }
  }
  return false;
}

bool limit_from_code(std::uint32_t raw, LimitCode& out) noexcept {
  for (const auto& info : kLimits) {
    if (static_cast<std::uint32_t>(info.code) == raw) {
      out = info.code;
      return true;
    }
  }
  return false;
}

bool feature_allowed_for(FeatureCode code, CapabilityKind kind) noexcept {
  const FeatureInfo* info = feature_info(code);
  if (info == nullptr) return false;
  return (info->kind_mask & kind_bit(kind)) != 0;
}

bool limit_allowed_for(LimitCode code, CapabilityKind kind) noexcept {
  const LimitInfo* info = limit_info(code);
  if (info == nullptr) return false;
  return (info->kind_mask & kind_bit(kind)) != 0;
}

std::optional<Unit> canonical_unit_for(LimitCode code) noexcept {
  const LimitInfo* info = limit_info(code);
  if (info == nullptr) return std::nullopt;
  return unity(info->unit);
}

bool unit_valid_for_limit(LimitCode code, const Unit& unit) noexcept {
  const LimitInfo* info = limit_info(code);
  if (info == nullptr) return false;
  if (unit.code != info->unit) return false;
  if (!unit_is_well_formed(unit)) return false;
  switch (unit.scale) {
    case UnitScale::Unity: return unit.exponent == 0;
    case UnitScale::Decimal: return info->decimal_scale_permitted;
    case UnitScale::Binary: return info->binary_scale_permitted;
  }
  return false;
}

std::uint32_t catalog_fingerprint() noexcept {
  Sha256 hash;
  hash.update_u32(kCapabilityKindCount);
  for (const auto kind : kKinds) {
    hash.update_u16(static_cast<std::uint16_t>(kind));
    hash.update_bytes(to_string(kind));
  }
  hash.update_u32(static_cast<std::uint32_t>(kFeatures.size()));
  for (const auto& info : kFeatures) {
    hash.update_u32(static_cast<std::uint32_t>(info.code));
    hash.update_bytes(info.name);
    hash.update_u16(info.kind_mask);
  }
  hash.update_u32(static_cast<std::uint32_t>(kLimits.size()));
  for (const auto& info : kLimits) {
    hash.update_u32(static_cast<std::uint32_t>(info.code));
    hash.update_bytes(info.name);
    hash.update_u16(info.kind_mask);
    hash.update_u16(static_cast<std::uint16_t>(info.unit));
    hash.update_byte(info.decimal_scale_permitted ? 1 : 0);
    hash.update_byte(info.binary_scale_permitted ? 1 : 0);
  }
  const auto digest = hash.finish();
  const auto& bytes = digest.bytes();
  return (static_cast<std::uint32_t>(bytes[0]) << 24) |
         (static_cast<std::uint32_t>(bytes[1]) << 16) |
         (static_cast<std::uint32_t>(bytes[2]) << 8) | static_cast<std::uint32_t>(bytes[3]);
}

// --- FeatureSet -------------------------------------------------------------

bool FeatureSet::make(const std::vector<FeatureCode>& codes, CapabilityKind kind, FeatureSet& out,
                      ReasonCode& reason) {
  if (codes.size() > kMaxFeaturesPerRecord) {
    reason = ReasonCode::RejectedFeatureBudgetExceeded;
    return false;
  }
  std::vector<FeatureCode> sorted(codes);
  std::sort(sorted.begin(), sorted.end(),
            [](FeatureCode a, FeatureCode b) {
              return static_cast<std::uint32_t>(a) < static_cast<std::uint32_t>(b);
            });
  for (std::size_t i = 0; i < sorted.size(); ++i) {
    if (i > 0 && sorted[i] == sorted[i - 1]) {
      reason = ReasonCode::RejectedDuplicateKey;
      return false;
    }
    if (!feature_allowed_for(sorted[i], kind)) {
      reason = feature_info(sorted[i]) == nullptr ? ReasonCode::RejectedUnknownFeatureCode
                                                  : ReasonCode::RejectedFeatureNotInKind;
      return false;
    }
  }
  out.codes_ = std::move(sorted);
  reason = ReasonCode::Ok;
  return true;
}

FeatureSet FeatureSet::from_validated(std::vector<FeatureCode> codes) {
  FeatureSet set;
  std::sort(codes.begin(), codes.end(), [](FeatureCode a, FeatureCode b) {
    return static_cast<std::uint32_t>(a) < static_cast<std::uint32_t>(b);
  });
  codes.erase(std::unique(codes.begin(), codes.end()), codes.end());
  set.codes_ = std::move(codes);
  return set;
}

bool FeatureSet::contains(FeatureCode code) const noexcept {
  return std::binary_search(codes_.begin(), codes_.end(), code, [](FeatureCode a, FeatureCode b) {
    return static_cast<std::uint32_t>(a) < static_cast<std::uint32_t>(b);
  });
}

bool FeatureSet::contains_all(const FeatureSet& required) const noexcept {
  for (const auto code : required.codes_) {
    if (!contains(code)) return false;
  }
  return true;
}

std::strong_ordering operator<=>(const FeatureSet& a, const FeatureSet& b) noexcept {
  const std::size_t common = a.codes_.size() < b.codes_.size() ? a.codes_.size() : b.codes_.size();
  for (std::size_t i = 0; i < common; ++i) {
    const auto lhs = static_cast<std::uint32_t>(a.codes_[i]);
    const auto rhs = static_cast<std::uint32_t>(b.codes_[i]);
    if (lhs != rhs) return lhs < rhs ? std::strong_ordering::less : std::strong_ordering::greater;
  }
  return a.codes_.size() <=> b.codes_.size();
}

// --- LimitSet ---------------------------------------------------------------

bool LimitSet::make(const std::vector<LimitValue>& values, CapabilityKind kind, LimitSet& out,
                    ReasonCode& reason) {
  if (values.size() > kMaxLimitsPerRecord) {
    reason = ReasonCode::RejectedLimitBudgetExceeded;
    return false;
  }
  std::vector<LimitValue> sorted(values);
  std::sort(sorted.begin(), sorted.end());
  for (std::size_t i = 0; i < sorted.size(); ++i) {
    const LimitValue& value = sorted[i];
    if (i > 0 && sorted[i].code == sorted[i - 1].code) {
      reason = ReasonCode::RejectedDuplicateKey;
      return false;
    }
    if (limit_info(value.code) == nullptr) {
      reason = ReasonCode::RejectedUnknownLimitCode;
      return false;
    }
    if (!limit_allowed_for(value.code, kind)) {
      reason = ReasonCode::RejectedLimitNotInKind;
      return false;
    }
    if (value.value < 0) {
      reason = ReasonCode::RejectedNegativeLimit;
      return false;
    }
    if (value.unit.code != limit_info(value.code)->unit) {
      reason = ReasonCode::RejectedLimitUnitInvalid;
      return false;
    }
    if (!unit_is_well_formed(value.unit)) {
      reason = ReasonCode::RejectedLimitUnitScaleInvalid;
      return false;
    }
    if (!unit_valid_for_limit(value.code, value.unit)) {
      reason = ReasonCode::RejectedLimitScaleNotPermitted;
      return false;
    }
  }
  out.values_ = std::move(sorted);
  reason = ReasonCode::Ok;
  return true;
}

LimitSet LimitSet::from_validated(std::vector<LimitValue> values) {
  LimitSet set;
  std::sort(values.begin(), values.end());
  values.erase(std::unique(values.begin(), values.end(),
                           [](const LimitValue& a, const LimitValue& b) { return a.code == b.code; }),
               values.end());
  set.values_ = std::move(values);
  return set;
}

const LimitValue* LimitSet::find(LimitCode code) const noexcept {
  for (const auto& value : values_) {
    if (value.code == code) return &value;
  }
  return nullptr;
}

std::strong_ordering operator<=>(const LimitSet& a, const LimitSet& b) noexcept {
  const std::size_t common = a.values_.size() < b.values_.size() ? a.values_.size() : b.values_.size();
  for (std::size_t i = 0; i < common; ++i) {
    const auto lhs = static_cast<std::uint32_t>(a.values_[i].code);
    const auto rhs = static_cast<std::uint32_t>(b.values_[i].code);
    if (lhs != rhs) return lhs < rhs ? std::strong_ordering::less : std::strong_ordering::greater;
    if (a.values_[i].unit != b.values_[i].unit) {
      return a.values_[i].unit < b.values_[i].unit ? std::strong_ordering::less
                                                   : std::strong_ordering::greater;
    }
    if (a.values_[i].value != b.values_[i].value) {
      return a.values_[i].value < b.values_[i].value ? std::strong_ordering::less
                                                     : std::strong_ordering::greater;
    }
  }
  return a.values_.size() <=> b.values_.size();
}

}  // namespace ocreg
