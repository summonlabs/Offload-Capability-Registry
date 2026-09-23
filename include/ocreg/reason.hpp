// Offload Capability Registry - stable reason codes.
// Copyright 2026 Summon Software Labs.
//
// Every accept/refuse/unknown outcome carries a stable numeric code with a
// single canonical spelling. Codes are wire-visible (persistence, export,
// protocol) and are never renumbered; the accompanying test asserts the
// complete table.
#ifndef OCREG_REASON_HPP
#define OCREG_REASON_HPP

#include <cstdint>
#include <string_view>

namespace ocreg {

enum class ReasonCategory : std::uint8_t {
  Acceptance = 0,
  Idempotent = 1,
  Rejection = 2,
  Unknown = 3,
  Incompatible = 4,
  Conflict = 5,
  Persistence = 6,
  Recovery = 7,
  Accounting = 8,
  Transport = 9,
  Cancellation = 10,
};

// X(code, numeric, category, is_failure)
#define OCREG_REASON_TABLE(X) \
X(Ok,                                    0,   Acceptance,   0) \
X(AcceptedNew,                           1,   Acceptance,   0) \
X(AcceptedSuperseding,                   2,   Acceptance,   0) \
X(AlreadyPresent,                        3,   Idempotent,   0) \
X(AcceptedAuthoritativeOverride,         4,   Acceptance,   0) \
X(AcceptedAfterRetirement,               5,   Acceptance,   0) \
X(RejectedMalformedName,                 16,  Rejection,    1) \
X(RejectedMalformedVersion,              17,  Rejection,    1) \
X(RejectedMalformedFeature,              18,  Rejection,    1) \
X(RejectedMalformedLimit,                19,  Rejection,    1) \
X(RejectedMalformedDocument,             20,  Rejection,    1) \
X(RejectedOversizedInput,                21,  Rejection,    1) \
X(RejectedTruncatedInput,                22,  Rejection,    1) \
X(RejectedDuplicateKey,                  23,  Rejection,    1) \
X(RejectedInvalidUtf8,                   24,  Rejection,    1) \
X(RejectedNestingTooDeep,                25,  Rejection,    1) \
X(RejectedUnexpectedField,               26,  Rejection,    1) \
X(RejectedMissingField,                  27,  Rejection,    1) \
X(RejectedTrailingGarbage,               28,  Rejection,    1) \
X(RejectedUnknownCapabilityKind,         32,  Rejection,    1) \
X(RejectedUnknownFeatureCode,            33,  Rejection,    1) \
X(RejectedUnknownLimitCode,              34,  Rejection,    1) \
X(RejectedFeatureNotInKind,              35,  Rejection,    1) \
X(RejectedLimitNotInKind,                36,  Rejection,    1) \
X(RejectedLimitUnitInvalid,              37,  Rejection,    1) \
X(RejectedLimitUnitScaleInvalid,         38,  Rejection,    1) \
X(RejectedNegativeLimit,                 39,  Rejection,    1) \
X(RejectedLimitScaleNotPermitted,        40,  Rejection,    1) \
X(RejectedUnsupportedSemanticVersion,    41,  Rejection,    1) \
X(RejectedZeroIncarnation,               42,  Rejection,    1) \
X(RejectedUnknownSource,                 48,  Rejection,    1) \
X(RejectedSourceRevoked,                 49,  Rejection,    1) \
X(RejectedSourceUntrusted,               50,  Rejection,    1) \
X(RejectedAuthorityInsufficient,         51,  Rejection,    1) \
X(RejectedGenerationRegression,          52,  Rejection,    1) \
X(RejectedGenerationCollision,           53,  Rejection,    1) \
X(RejectedSupersededGeneration,          54,  Rejection,    1) \
X(RejectedStaleObservation,              55,  Rejection,    1) \
X(RejectedFutureObservation,             56,  Rejection,    1) \
X(RejectedValidityWindowInverted,        57,  Rejection,    1) \
X(RejectedRetiredStream,                 58,  Rejection,    1) \
X(RejectedDeviceIncarnationFenced,       59,  Rejection,    1) \
X(RejectedEpochOutOfRange,               60,  Rejection,    1) \
X(RejectedRuleGenerationOutOfRange,      61,  Rejection,    1) \
X(RejectedFeatureBudgetExceeded,         62,  Rejection,    1) \
X(RejectedLimitBudgetExceeded,           63,  Rejection,    1) \
X(RejectedRecordBudgetExhausted,         64,  Rejection,    1) \
X(RejectedHistoryBudgetExhausted,        65,  Rejection,    1) \
X(RejectedStreamBudgetExhausted,         66,  Rejection,    1) \
X(RejectedDeviceBudgetExhausted,         67,  Rejection,    1) \
X(RejectedBeyondRetentionHorizon,        68,  Rejection,    1) \
X(UnknownNoEvidence,                     80,  Unknown,      0) \
X(UnknownStaleEvidence,                  81,  Unknown,      0) \
X(UnknownConflictingEvidence,            82,  Unknown,      0) \
X(UnknownEvidenceEvicted,                83,  Unknown,      0) \
X(UnknownFencedEvidence,                 84,  Unknown,      0) \
X(UnknownUnitMismatch,                   85,  Unknown,      0) \
X(UnknownInexactUnitConversion,          86,  Unknown,      0) \
X(UnknownLimitNotReported,               87,  Unknown,      0) \
X(UnknownDeviceNotRegistered,            88,  Unknown,      0) \
X(UnknownIncarnationNotCurrent,          89,  Unknown,      0) \
X(UnknownSourceNotConfigured,            90,  Unknown,      0) \
X(UnknownPolicyNotConfigured,            91,  Unknown,      0) \
X(UnknownCapabilityRetired,              92,  Unknown,      0) \
X(UnknownRuleGenerationMismatch,         93,  Unknown,      0) \
X(UnknownFirmwareGenerationAbsent,       94,  Unknown,      0) \
X(UnknownRuntimeGenerationAbsent,        95,  Unknown,      0) \
X(UnknownTruncatedHistory,               96,  Unknown,      0) \
X(IncompatibleVersionTooLow,             112, Incompatible, 0) \
X(IncompatibleFeatureAbsent,             113, Incompatible, 0) \
X(IncompatibleLimitBelowRequirement,     114, Incompatible, 0) \
X(IncompatibleFirmwareGenerationTooLow,  115, Incompatible, 0) \
X(IncompatibleRuntimeGenerationTooLow,   116, Incompatible, 0) \
X(IncompatibleCapabilityRetired,         117, Incompatible, 0) \
X(IncompatibleDeviceReincarnated,        118, Incompatible, 0) \
X(IncompatibleSourceRevoked,             119, Incompatible, 0) \
X(ConflictEqualAuthority,                144, Conflict,     0) \
X(ConflictOutranked,                     145, Conflict,     0) \
X(ConflictResolvedByAuthority,           146, Conflict,     0) \
X(ConflictResolvedByResolution,          147, Conflict,     0) \
X(ConflictUnresolved,                    148, Conflict,     0) \
X(EvictedSuperseded,                     160, Accounting,   0) \
X(EvictedRetired,                        161, Accounting,   0) \
X(EvictedBudgetPressure,                 162, Accounting,   0) \
X(EvictionRecorded,                      163, Accounting,   0) \
X(ExportTruncated,                       164, Accounting,   0) \
X(ExportComplete,                        165, Accounting,   0) \
X(StoreNotFound,                         176, Persistence,  1) \
X(StoreEmptyNew,                         177, Persistence,  0) \
X(StoreHeaderCorrupt,                    178, Persistence,  1) \
X(StoreVersionIncompatible,              179, Persistence,  1) \
X(StoreSemanticMismatch,                 180, Persistence,  1) \
X(StorePayloadCorrupt,                   181, Persistence,  1) \
X(StoreTornTail,                         182, Persistence,  0) \
X(StoreJournalCorrupt,                   183, Persistence,  1) \
X(StoreFooterMissing,                    184, Persistence,  1) \
X(StoreOversized,                        185, Persistence,  1) \
X(StoreWriteFailed,                      186, Persistence,  1) \
X(StoreReadFailed,                       187, Persistence,  1) \
X(StoreSyncFailed,                       188, Persistence,  1) \
X(StoreEpochReplay,                      189, Persistence,  1) \
X(StoreBootReplay,                       190, Persistence,  1) \
X(StoreIncarnationReplay,                191, Persistence,  1) \
X(StoreGenerationReplay,                 192, Persistence,  1) \
X(StoreRotationPerformed,                193, Persistence,  0) \
X(StoreCommitDurable,                    194, Persistence,  0) \
X(RecoveryCleanOpen,                     208, Recovery,     0) \
X(RecoveryTornTailTruncated,             209, Recovery,     0) \
X(RecoveryTrailingCorruptDropped,        210, Recovery,     0) \
X(RecoveryRefused,                       211, Recovery,     1) \
X(RecoveryRebuiltFromSnapshot,           212, Recovery,     0) \
X(RecoveryJournalReplayed,               213, Recovery,     0) \
X(ProtocolFrameTooLarge,                 224, Transport,    1) \
X(ProtocolFrameMalformed,                225, Transport,    1) \
X(ProtocolVersionUnsupported,            226, Transport,    1) \
X(ProtocolChecksumMismatch,              227, Transport,    1) \
X(ProtocolSequenceViolation,             228, Transport,    1) \
X(ProtocolUnknownOpcode,                 229, Transport,    1) \
X(ProtocolConnectionLimit,               230, Transport,    1) \
X(ProtocolBackpressure,                  231, Transport,    1) \
X(ProtocolShutdownInProgress,            232, Transport,    1) \
X(ProtocolRequestIdReplay,               233, Transport,    1) \
X(TransportClosed,                       234, Transport,    1) \
X(TransportUnavailable,                  235, Transport,    1) \
X(TransportListening,                    236, Transport,    0) \
X(TransportAccepted,                     237, Transport,    0) \
X(Cancelled,                             248, Cancellation, 1) \
X(CancelTooLate,                         249, Cancellation, 0) \
X(InternalInvariantViolated,             250, Rejection,    1)

enum class ReasonCode : std::uint16_t {
#define OCREG_REASON_ENUM(code, numeric, category, failure) code = numeric,
  OCREG_REASON_TABLE(OCREG_REASON_ENUM)
#undef OCREG_REASON_ENUM
};

// Canonical upper-snake spelling, for example "REJECTED_SOURCE_REVOKED".
[[nodiscard]] std::string_view to_string(ReasonCode code) noexcept;

// True when the code denotes a hard failure of the operation.
[[nodiscard]] bool is_failure(ReasonCode code) noexcept;

[[nodiscard]] ReasonCategory category_of(ReasonCode code) noexcept;
[[nodiscard]] std::string_view to_string(ReasonCategory category) noexcept;

// Parses the canonical spelling. Case sensitive.
[[nodiscard]] bool parse_reason_code(std::string_view text, ReasonCode& out) noexcept;

// Number of distinct reason codes in the table.
[[nodiscard]] std::size_t reason_code_count() noexcept;

// Digest over the canonical (numeric, spelling) table. Persistence and tests
// use it to detect an incompatible reason-table generation.
[[nodiscard]] std::uint32_t reason_table_fingerprint() noexcept;

}  // namespace ocreg

#endif  // OCREG_REASON_HPP
