// Offload Capability Registry - core value type tests.
// Copyright 2026 Summon Software Labs.
#include <limits>
#include <string>
#include <vector>

#include "ocreg/catalog.hpp"
#include "ocreg/checked.hpp"
#include "ocreg/codec.hpp"
#include "ocreg/hash.hpp"
#include "ocreg/json.hpp"
#include "ocreg/name.hpp"
#include "ocreg/reason.hpp"
#include "ocreg/semver.hpp"
#include "ocreg/units.hpp"
#include "ocreg/version.hpp"
#include "test_support.hpp"

using namespace ocreg;

OCREG_TEST(name_tokens_follow_the_documented_grammar) {
  CHECK(Name::parse("fixture-sim").has_value());
  CHECK(Name::parse("a").has_value());
  CHECK(Name::parse("a.b_c-d0").has_value());
  CHECK(Name::parse("0zero").has_value());
  CHECK(!Name::parse("").has_value());
  CHECK(!Name::parse("Upper").has_value());
  CHECK(!Name::parse("-leading").has_value());
  CHECK(!Name::parse("trailing-").has_value());
  CHECK(!Name::parse("double..dot").has_value());
  CHECK(!Name::parse("with space").has_value());
  CHECK(!Name::parse(std::string(kMaxNameLength + 1, 'a')).has_value());
  CHECK(Name::parse(std::string(kMaxNameLength, 'a')).has_value());

  const auto left = Name::parse("alpha");
  const auto right = Name::parse("beta");
  REQUIRE(left.has_value());
  REQUIRE(right.has_value());
  CHECK(*left < *right);
  CHECK(*left == *left);
}

OCREG_TEST(semver_parses_and_orders_per_the_specification) {
  const auto basic = SemVer::parse("1.2.3");
  REQUIRE(basic.has_value());
  CHECK_EQ(basic->major(), 1u);
  CHECK_EQ(basic->minor(), 2u);
  CHECK_EQ(basic->patch(), 3u);
  CHECK_EQ(basic->str(), std::string("1.2.3"));

  CHECK(!SemVer::parse("").has_value());
  CHECK(!SemVer::parse("1.2").has_value());
  CHECK(!SemVer::parse("1.2.3.4").has_value());
  CHECK(!SemVer::parse("01.2.3").has_value());
  CHECK(!SemVer::parse("1.2.3-").has_value());
  CHECK(!SemVer::parse("1.2.3+").has_value());
  CHECK(!SemVer::parse("1.2.x").has_value());
  CHECK(!SemVer::parse("v1.2.3").has_value());
  CHECK(!SemVer::parse("1.2.3-alpha..1").has_value());
  CHECK(!SemVer::parse("1.2.3-01").has_value());

  const auto prerelease = SemVer::parse("1.2.3-alpha.1+build.7");
  REQUIRE(prerelease.has_value());
  CHECK_EQ(std::string(prerelease->prerelease()), std::string("alpha.1"));
  CHECK_EQ(std::string(prerelease->build()), std::string("build.7"));
  CHECK_EQ(prerelease->str(), std::string("1.2.3-alpha.1+build.7"));

  const auto release = *SemVer::parse("1.2.3");
  const auto alpha = *SemVer::parse("1.2.3-alpha");
  CHECK(alpha.precedence_compare(release) == std::strong_ordering::less);
  CHECK(release.precedence_compare(alpha) == std::strong_ordering::greater);

  const auto alpha1 = *SemVer::parse("1.2.3-alpha.1");
  const auto alpha2 = *SemVer::parse("1.2.3-alpha.2");
  CHECK(alpha1.precedence_compare(alpha2) == std::strong_ordering::less);

  const auto numeric = *SemVer::parse("1.2.3-1");
  const auto alphanumeric = *SemVer::parse("1.2.3-alpha");
  CHECK(numeric.precedence_compare(alphanumeric) == std::strong_ordering::less);

  const auto shorter = *SemVer::parse("1.2.3-alpha");
  const auto longer = *SemVer::parse("1.2.3-alpha.1");
  CHECK(shorter.precedence_compare(longer) == std::strong_ordering::less);

  // Build metadata is ignored for precedence but participates in identity.
  const auto with_build = *SemVer::parse("1.2.3+build.9");
  CHECK(release.precedence_compare(with_build) == std::strong_ordering::equal);
  CHECK(!(release == with_build));

  VersionRequirement requirement;
  requirement.minimum = release;
  CHECK(requirement.satisfied_by(release));
  CHECK(requirement.satisfied_by(with_build));
  CHECK(!requirement.satisfied_by(alpha));
  const auto upper = *SemVer::parse("2.0.0");
  requirement.maximum_exclusive = upper;
  CHECK(requirement.satisfied_by(*SemVer::parse("1.9.9")));
  CHECK(!requirement.satisfied_by(*SemVer::parse("2.0.0")));
}

OCREG_TEST(units_convert_exactly_or_refuse) {
  const Unit byte = unity(UnitCode::Byte);
  const Unit bit = unity(UnitCode::Bit);
  const Unit kib = Unit{UnitCode::Byte, UnitScale::Binary, 1};
  const Unit second = unity(UnitCode::Second);
  const Unit milli = unity(UnitCode::MilliSecond);
  const Unit percent = unity(UnitCode::Percent);
  const Unit ppm = unity(UnitCode::PartsPerMillion);

  const auto bytes_to_bits = convert_exact(4, byte, bit);
  REQUIRE(bytes_to_bits.has_value());
  CHECK_EQ(*bytes_to_bits, std::int64_t{32});

  const auto kib_to_bytes = convert_exact(2, kib, byte);
  REQUIRE(kib_to_bytes.has_value());
  CHECK_EQ(*kib_to_bytes, std::int64_t{2048});

  const auto seconds_to_millis = convert_exact(3, second, milli);
  REQUIRE(seconds_to_millis.has_value());
  CHECK_EQ(*seconds_to_millis, std::int64_t{3000});

  // A conversion that would round is refused rather than truncated.
  CHECK(!convert_exact(1, milli, second).has_value());
  CHECK(!compare_exact(1500, milli, 2, second).has_value() == false);

  const auto percentile_to_ppm = convert_exact(1, percent, ppm);
  REQUIRE(percentile_to_ppm.has_value());
  CHECK_EQ(*percentile_to_ppm, std::int64_t{10000});

  // Cross-dimension conversion is an explicit unknown.
  CHECK(!convert_exact(1, byte, second).has_value());

  const auto ordering = compare_exact(1500, milli, 2, second);
  REQUIRE(ordering.has_value());
  CHECK(*ordering == std::strong_ordering::less);

  const auto equal = compare_exact(2000, milli, 2, second);
  REQUIRE(equal.has_value());
  CHECK(*equal == std::strong_ordering::equal);

  // A malformed unit is refused everywhere.
  const Unit malformed{UnitCode::Byte, UnitScale::Unity, 3};
  CHECK(!unit_is_well_formed(malformed));
  CHECK(!factor_to_base(malformed).has_value());
  // A binary scale is not meaningful for time.
  const Unit bad_time{UnitCode::Second, UnitScale::Binary, 1};
  CHECK(!unit_is_well_formed(bad_time));

  // Canonical spelling round-trips.
  for (const Unit& unit : {byte, bit, kib, second, milli, percent, ppm,
                           Unit{UnitCode::BitPerSecond, UnitScale::Decimal, 3}}) {
    const std::string text = unit_to_string(unit);
    Unit reparsed{};
    CHECK_MSG(parse_unit(text, reparsed), text);
    CHECK(reparsed == unit);
  }
  Unit parsed{};
  CHECK(!parse_unit("byte.hex2", parsed));
  CHECK(!parse_unit("byte.bin9", parsed));
  CHECK(!parse_unit("nonsense", parsed));
  CHECK(!parse_unit("byte.bin", parsed));
}

OCREG_TEST(checked_arithmetic_never_wraps) {
  std::uint64_t u64 = 0;
  CHECK(checked_add<std::uint64_t>(1, 2, u64));
  CHECK_EQ(u64, std::uint64_t{3});
  CHECK(!checked_add<std::uint64_t>(std::numeric_limits<std::uint64_t>::max(), 1, u64));
  CHECK(!checked_sub<std::uint64_t>(0, 1, u64));
  CHECK(checked_sub<std::uint64_t>(5, 5, u64));
  CHECK_EQ(u64, std::uint64_t{0});
  CHECK(checked_mul<std::uint64_t>(6, 7, u64));
  CHECK_EQ(u64, std::uint64_t{42});
  CHECK(!checked_mul<std::uint64_t>(std::numeric_limits<std::uint64_t>::max(), 2, u64));
  CHECK(!checked_div<std::uint64_t>(1, 0, u64));

  std::int64_t i64 = 0;
  CHECK(!checked_add<std::int64_t>(std::numeric_limits<std::int64_t>::max(), 1, i64));
  CHECK(!checked_add<std::int64_t>(std::numeric_limits<std::int64_t>::min(), -1, i64));
  CHECK(!checked_mul<std::int64_t>(std::numeric_limits<std::int64_t>::min(), -1, i64));
  CHECK(!checked_div<std::int64_t>(std::numeric_limits<std::int64_t>::min(), -1, i64));
  CHECK(checked_mul<std::int64_t>(-6, 7, i64));
  CHECK_EQ(i64, std::int64_t{-42});

  std::uint8_t narrow = 0;
  CHECK(checked_narrow<std::uint8_t>(255, narrow));
  CHECK(!checked_narrow<std::uint8_t>(256, narrow));
  CHECK(!checked_narrow<std::uint8_t>(-1, narrow));

  BoundedCounter counter(3);
  CHECK(counter.try_add());
  CHECK(counter.try_add());
  CHECK(counter.try_add());
  CHECK(!counter.try_add());
  CHECK_EQ(counter.value(), std::uint64_t{3});
}

OCREG_TEST(catalog_is_closed_and_typed) {
  CHECK_EQ(all_capability_kinds().size(), kCapabilityKindCount);
  CHECK_EQ(all_features().size(), std::size_t{101});
  CHECK_EQ(all_limits().size(), std::size_t{37});
  CHECK(catalog_fingerprint() != 0);

  CapabilityKind kind{};
  CHECK(parse_capability_kind("checksum_offload", kind));
  CHECK(kind == CapabilityKind::ChecksumOffload);
  CHECK(!parse_capability_kind("not_a_kind", kind));

  FeatureCode feature{};
  CHECK(parse_feature_code("checksum_l4_tx", feature));
  CHECK(feature == FeatureCode::ChecksumL4Tx);
  CHECK(!parse_feature_code("nonsense", feature));

  LimitCode limit{};
  CHECK(parse_limit_code("maximum_transmission_unit", limit));
  CHECK(limit == LimitCode::MaximumTransmissionUnit);

  // Feature and kind membership is decidable, not conventional.
  CHECK(feature_allowed_for(FeatureCode::ChecksumL4Tx, CapabilityKind::ChecksumOffload));
  CHECK(!feature_allowed_for(FeatureCode::ChecksumL4Tx, CapabilityKind::RdmaTransport));
  CHECK(limit_allowed_for(LimitCode::MaximumTransmissionUnit, CapabilityKind::ChecksumOffload));
  CHECK(!limit_allowed_for(LimitCode::RdmaQueuePairs, CapabilityKind::ChecksumOffload));

  ReasonCode reason = ReasonCode::Ok;
  FeatureSet features;
  CHECK(FeatureSet::make({FeatureCode::ChecksumL4Tx, FeatureCode::ChecksumIpv4HeaderTx},
                         CapabilityKind::ChecksumOffload, features, reason));
  CHECK_EQ(features.size(), std::size_t{2});
  CHECK(features.contains(FeatureCode::ChecksumL4Tx));
  CHECK(canonical_order_ok(features));
  CHECK(features.codes()[0] == FeatureCode::ChecksumIpv4HeaderTx);

  // Duplicates, unknown codes, foreign kinds and width bounds are all refused
  // with distinct reason codes.
  FeatureSet duplicate;
  CHECK(!FeatureSet::make({FeatureCode::ChecksumL4Tx, FeatureCode::ChecksumL4Tx},
                          CapabilityKind::ChecksumOffload, duplicate, reason));
  CHECK(reason == ReasonCode::RejectedDuplicateKey);
  FeatureSet foreign;
  CHECK(!FeatureSet::make({FeatureCode::RdmaRoceV2}, CapabilityKind::ChecksumOffload, foreign,
                          reason));
  CHECK(reason == ReasonCode::RejectedFeatureNotInKind);
  FeatureSet oversized;
  CHECK(!FeatureSet::make(std::vector<FeatureCode>(kMaxFeaturesPerRecord + 1,
                                                   FeatureCode::ChecksumL4Tx),
                          CapabilityKind::ChecksumOffload, oversized, reason));
  CHECK(reason == ReasonCode::RejectedFeatureBudgetExceeded);

  LimitSet limits;
  CHECK(LimitSet::make({LimitValue{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 9000}},
                       CapabilityKind::ChecksumOffload, limits, reason));
  REQUIRE(limits.find(LimitCode::MaximumTransmissionUnit) != nullptr);
  CHECK_EQ(limits.find(LimitCode::MaximumTransmissionUnit)->value, std::int64_t{9000});
  // A limit that was never reported is absent, not zero.
  CHECK(limits.find(LimitCode::QueueCount) == nullptr);

  LimitSet wrong_unit;
  CHECK(!LimitSet::make({LimitValue{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Bit), 9000}},
                        CapabilityKind::ChecksumOffload, wrong_unit, reason));
  CHECK(reason == ReasonCode::RejectedLimitUnitInvalid);

  LimitSet wrong_scale;
  CHECK(!LimitSet::make(
      {LimitValue{LimitCode::MaximumTransmissionUnit,
                  Unit{UnitCode::Byte, UnitScale::Decimal, 1}, 9000}},
      CapabilityKind::ChecksumOffload, wrong_scale, reason));
  CHECK(reason == ReasonCode::RejectedLimitScaleNotPermitted);

  LimitSet negative;
  CHECK(!LimitSet::make({LimitValue{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), -1}},
                        CapabilityKind::ChecksumOffload, negative, reason));
  CHECK(reason == ReasonCode::RejectedNegativeLimit);

  LimitSet foreign_limit;
  CHECK(!LimitSet::make({LimitValue{LimitCode::RdmaQueuePairs, unity(UnitCode::Count), 4}},
                        CapabilityKind::ChecksumOffload, foreign_limit, reason));
  CHECK(reason == ReasonCode::RejectedLimitNotInKind);
}

OCREG_TEST(reason_codes_have_stable_spellings) {
  CHECK_EQ(std::string(to_string(ReasonCode::Ok)), std::string("OK"));
  CHECK_EQ(std::string(to_string(ReasonCode::AlreadyPresent)), std::string("ALREADY_PRESENT"));
  CHECK_EQ(std::string(to_string(ReasonCode::RejectedSupersededGeneration)),
           std::string("REJECTED_SUPERSEDED_GENERATION"));
  CHECK_EQ(std::string(to_string(ReasonCode::UnknownNoEvidence)), std::string("UNKNOWN_NO_EVIDENCE"));
  CHECK_EQ(std::string(to_string(ReasonCode::IncompatibleFeatureAbsent)),
           std::string("INCOMPATIBLE_FEATURE_ABSENT"));
  CHECK_EQ(std::string(to_string(ReasonCode::StoreTornTail)), std::string("STORE_TORN_TAIL"));
  CHECK_EQ(std::string(to_string(ReasonCode::RecoveryTornTailTruncated)),
           std::string("RECOVERY_TORN_TAIL_TRUNCATED"));
  CHECK_EQ(std::string(to_string(ReasonCode::ProtocolChecksumMismatch)),
           std::string("PROTOCOL_CHECKSUM_MISMATCH"));
  CHECK_EQ(std::string(to_string(ReasonCode::Cancelled)), std::string("CANCELLED"));

  CHECK_EQ(static_cast<std::uint16_t>(ReasonCode::Ok), std::uint16_t{0});
  CHECK_EQ(static_cast<std::uint16_t>(ReasonCode::RejectedMalformedName), std::uint16_t{16});
  CHECK_EQ(static_cast<std::uint16_t>(ReasonCode::UnknownNoEvidence), std::uint16_t{80});

  CHECK(!is_failure(ReasonCode::Ok));
  CHECK(!is_failure(ReasonCode::AlreadyPresent));
  CHECK(is_failure(ReasonCode::RejectedMalformedName));
  CHECK(category_of(ReasonCode::ConflictEqualAuthority) == ReasonCategory::Conflict);

  // Every code round-trips through its canonical spelling.
  std::size_t checked = 0;
  for (std::uint16_t raw = 0; raw < 512; ++raw) {
    const auto code = static_cast<ReasonCode>(raw);
    const std::string_view text = to_string(code);
    if (text == "UNKNOWN_REASON_CODE") continue;
    ReasonCode parsed = ReasonCode::Ok;
    CHECK_MSG(parse_reason_code(text, parsed), std::string(text));
    CHECK(parsed == code);
    ++checked;
  }
  CHECK_EQ(checked, reason_code_count());
  CHECK(reason_table_fingerprint() != 0);
}

OCREG_TEST(digests_match_published_vectors) {
  CHECK_EQ(Digest256::of(std::string_view("")).hex(),
           std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  CHECK_EQ(Digest256::of(std::string_view("abc")).hex(),
           std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  CHECK_EQ(crc32c(std::string_view("123456789")), 0xE3069283u);
  CHECK_EQ(crc32c(std::string_view("")), 0x00000000u);

  Digest256 parsed;
  CHECK(Digest256::parse("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", parsed));
  CHECK(parsed == Digest256::of(std::string_view("")));
  CHECK(!Digest256::parse("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", parsed));
  CHECK(!Digest256::parse("e3b0", parsed));

  // Streaming and one-shot agree for every split point.
  const std::string sample = "the quick brown fox jumps over the lazy dog";
  const Digest256 one_shot = Digest256::of(std::string_view(sample));
  for (std::size_t split = 0; split <= sample.size(); ++split) {
    Sha256 stream;
    stream.update(std::string_view(sample).substr(0, split));
    stream.update(std::string_view(sample).substr(split));
    CHECK(stream.finish() == one_shot);
  }
}

OCREG_TEST(json_is_strict_and_canonical) {
  const auto parsed = JsonValue::parse(R"({"b":1,"a":[true,null,"x"],"c":{"z":2}})");
  REQUIRE(parsed.ok());
  const std::string canonical = parsed.value().dump(false);
  CHECK_EQ(canonical, std::string(R"({"a":[true,null,"x"],"b":1,"c":{"z":2}})"));

  const auto reparsed = JsonValue::parse(canonical);
  REQUIRE(reparsed.ok());
  CHECK(reparsed.value() == parsed.value());

  // Duplicate keys would silently pick a winner, so they are refused.
  CHECK(!JsonValue::parse(R"({"a":1,"a":2})").ok());
  // Trailing whitespace is insignificant; trailing content is not.
  CHECK(JsonValue::parse("{\"a\":1}  \n\t").ok());
  CHECK(!JsonValue::parse("{\"a\":1} x").ok());
  CHECK(!JsonValue::parse("{\"a\":1}{\"b\":2}").ok());
  // Floating point cannot be represented exactly, so it is refused.
  CHECK(!JsonValue::parse(R"({"a":1.5})").ok());
  CHECK(!JsonValue::parse(R"({"a":1e3})").ok());
  // Leading zeros are not canonical.
  CHECK(!JsonValue::parse(R"({"a":01})").ok());
  // Over-long integers are refused rather than wrapped.
  CHECK(!JsonValue::parse(R"({"a":99999999999999999999999})").ok());
  // Control characters must be escaped.
  CHECK(!JsonValue::parse("{\"a\":\"\x01\"}").ok());
  // Unknown escapes are refused.
  CHECK(!JsonValue::parse("{\"a\":\"\\q\"}").ok());
  // Lone surrogates are refused; a matched pair is not.
  CHECK(!JsonValue::parse("{\"a\":\"\\ud800\"}").ok());
  CHECK(!JsonValue::parse("{\"a\":\"\\udc00\"}").ok());
  CHECK(!JsonValue::parse("{\"a\":\"\\ud800\\ud800\"}").ok());
  CHECK(JsonValue::parse("{\"a\":\"\\ud83d\\ude00\"}").ok());
  // Depth and size bounds.
  std::string deep = "[";
  for (int i = 0; i < 64; ++i) deep.push_back('[');
  for (int i = 0; i < 64; ++i) deep.push_back(']');
  deep.push_back(']');
  CHECK(!JsonValue::parse(deep).ok());
  JsonLimits tight;
  tight.max_bytes = 8;
  CHECK(!JsonValue::parse(R"({"a":123456789})", tight).ok());
  // Bare values and empty input.
  CHECK(!JsonValue::parse("").ok());
  CHECK(!JsonValue::parse("nul").ok());
  CHECK(JsonValue::parse("null").ok());
  CHECK(JsonValue::parse("-9223372036854775808").ok());
  CHECK(!JsonValue::parse("9223372036854775808").ok());
}

OCREG_TEST(codec_round_trips_core_values_without_semantic_loss) {
  Writer writer;
  const auto version = *SemVer::parse("2.5.1-rc.3+build.11");
  encode(writer, version);
  const Unit unit{UnitCode::BitPerSecond, UnitScale::Decimal, 3};
  encode(writer, unit);
  const FeatureSet features = FeatureSet::from_validated(
      {FeatureCode::ChecksumL4Tx, FeatureCode::ChecksumIpv4HeaderRx});
  encode(writer, features);
  const LimitSet limits = LimitSet::from_validated(
      {LimitValue{LimitCode::MaximumTransmissionUnit, unity(UnitCode::Byte), 9000}});
  encode(writer, limits);

  Reader reader(writer.span());
  SemVer parsed_version;
  Unit parsed_unit;
  FeatureSet parsed_features;
  LimitSet parsed_limits;
  CHECK(decode(reader, parsed_version));
  CHECK(decode(reader, parsed_unit));
  CHECK(decode(reader, parsed_features));
  CHECK(decode(reader, parsed_limits));
  CHECK(reader.at_end());
  CHECK(parsed_version == version);
  CHECK(parsed_unit == unit);
  CHECK(parsed_features == features);
  CHECK(parsed_limits == limits);

  // A truncated buffer can never yield the complete value sequence.
  for (std::size_t length = 0; length < writer.size(); ++length) {
    Reader truncated(std::span<const std::uint8_t>(writer.span().data(), length));
    SemVer value_version;
    Unit value_unit;
    FeatureSet value_features;
    LimitSet value_limits;
    std::size_t decoded_count = 0;
    if (decode(truncated, value_version)) ++decoded_count;
    if (decode(truncated, value_unit)) ++decoded_count;
    if (decode(truncated, value_features)) ++decoded_count;
    if (decode(truncated, value_limits)) ++decoded_count;
    CHECK_MSG(decoded_count < 4, std::to_string(length));
  }

  // An impossible enum never decodes into a valid-looking value.
  Writer bad;
  bad.u16(0xFFFF);
  Reader bad_reader(bad.span());
  CapabilityKind kind{};
  CHECK(!decode(bad_reader, kind));
  CHECK(bad_reader.failure() == ReasonCode::RejectedUnknownCapabilityKind);
}
