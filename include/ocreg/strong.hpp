// Offload Capability Registry - strongly typed identity scalars.
// Copyright 2026 Summon Software Labs.
//
// Every correctness-critical scalar identity in the registry is a distinct
// type. Two identities of different kinds are never interchangeable and never
// compare equal, so authority, generation and incarnation values cannot be
// silently substituted for one another.
#ifndef OCREG_STRONG_HPP
#define OCREG_STRONG_HPP

#include <compare>
#include <cstdint>
#include <functional>
#include <limits>
#include <type_traits>

namespace ocreg {

// A distinct, ordered, explicitly constructed identity scalar.
template <class Tag, class Rep = std::uint64_t>
class Strong {
 public:
  using rep_type = Rep;

  constexpr Strong() noexcept = default;
  constexpr explicit Strong(Rep value) noexcept : value_(value) {}

  [[nodiscard]] constexpr Rep value() const noexcept { return value_; }

  // The reserved "unset" representation. Distinct from any real value because
  // every generator rejects zero when allocating identities.
  [[nodiscard]] constexpr bool is_unset() const noexcept { return value_ == Rep{0}; }

  friend constexpr bool operator==(Strong a, Strong b) noexcept { return a.value_ == b.value_; }
  friend constexpr std::strong_ordering operator<=>(Strong a, Strong b) noexcept {
    return a.value_ <=> b.value_;
  }

 private:
  Rep value_{};
};

template <class Tag, class Rep>
struct StrongHash {
  std::size_t operator()(Strong<Tag, Rep> value) const noexcept {
    return std::hash<Rep>{}(value.value());
  }
};

// Monotonic registry epoch. Bumped by any authority- or policy-affecting
// mutation and by process restart.
struct RegistryEpochTag;
using RegistryEpoch = Strong<RegistryEpochTag, std::uint64_t>;

// Generation of the compatibility rule set.
struct RuleGenerationTag;
using RuleGeneration = Strong<RuleGenerationTag, std::uint64_t>;

// Generation of the persisted store lifecycle. Advanced on every successful
// durable commit.
struct StoreGenerationTag;
using StoreGeneration = Strong<StoreGenerationTag, std::uint64_t>;

// Process boot epoch of the registry runtime.
struct BootEpochTag;
using BootEpoch = Strong<BootEpochTag, std::uint64_t>;

// Registry-assigned device incarnation counter.
struct IncarnationIdTag;
using IncarnationId = Strong<IncarnationIdTag, std::uint64_t>;

// Monotonic incarnation counter owned by an observation source.
struct SourceIncarnationTag;
using SourceIncarnationCounter = Strong<SourceIncarnationTag, std::uint64_t>;

// Per-stream evidence revision. Monotonic per (device incarnation, capability
// kind, source).
struct RecordGenerationTag;
using RecordGeneration = Strong<RecordGenerationTag, std::uint64_t>;

// Logical observation tick, nanoseconds on the registry logical clock.
struct TickTag;
using Tick = Strong<TickTag, std::uint64_t>;

// Identifier of the current registry configuration/policy epoch snapshot.
struct PolicyRevisionTag;
using PolicyRevision = Strong<PolicyRevisionTag, std::uint64_t>;

}  // namespace ocreg

#endif  // OCREG_STRONG_HPP
