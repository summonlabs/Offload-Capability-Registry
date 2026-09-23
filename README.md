# Offload Capability Registry

A standalone, vendor-neutral C++20 runtime that records the exact offload
semantics a host, NIC, SmartNIC or DPU is claimed to provide, together with the
provenance, generation and authority needed to decide whether that claim may be
used right now.

The registry is a **fact store, not a control plane**. It answers questions from
evidence and refuses to answer when it has none.

---

## What this runtime owns

* The authoritative representation of an offload capability claim: capability
  kind, semantic version, feature set, limit set, firmware and runtime
  generation, and the observation window it is valid for.
* Provenance: which observation source made the claim, under which source
  incarnation, at which logical tick, with which authority, under which registry
  epoch and policy revision.
* Versioning and generation: per-stream evidence generations, device
  incarnations, registry epochs, policy revisions, rule generations, store
  generations and boot epochs.
* Compatibility evaluation: an exact comparison of a requirement against
  admitted evidence, producing one of four answers and a stable explanation.
* Historical state: bounded, accounted-for history including superseded,
  retired, rejected, fenced, stale, outranked and evicted evidence.

## What this runtime deliberately does not do

* It does not probe hardware. No adapter to a real device is implemented, so no
  hardware behaviour is claimed anywhere in this repository.
* It does not assign work, schedule flows, deploy functions or program devices.
* It does not own topology, policy authority or execution state. An adjacent
  runtime supplies those; the registry consumes their observations as evidence
  and records which source said what.
* It does not treat a recommendation as an authorisation, an authorisation as an
  application, or an acknowledgement as a verified effect. The registry's
  answers describe the registry's own admitted evidence and nothing further.

If a neighbouring product needs topology or execution state, this runtime is a
peer it can feed, not a replacement for it.

---

## REAL / SYNTHETIC / UNSUPPORTED

| Area | Status |
| --- | --- |
| Registry core, evaluation, persistence, canonical export, protocol | **REAL** - fully implemented and exercised by the shipped tests |
| Durable persistence and crash recovery | **REAL** - proven with real processes hard-killed at durable boundaries |
| Framed transport over loopback TCP | **REAL** - proven with independent OS processes and real sockets |
| Device, NIC, SmartNIC and DPU adapters | **UNSUPPORTED** - none exists |
| Switch, ASIC, RDMA, InfiniBand, NVLink, multi-host and CUDA behaviour | **UNSUPPORTED** - nothing of the kind is claimed |
| Vendor protocols and firmware interaction | **UNSUPPORTED** |
| Test devices, sources and fixture documents | **SYNTHETIC** - every device in the test suite is a simulated fixture |

Every capability record in every test, benchmark and example is produced by a
source whose policy entry declares `synthetic`. No test asserts anything about
real hardware, and no result in this repository should be read as hardware
validation.

---

## Architecture

    include/ocreg/          public headers (installed)
    src/                    library implementation
    tools/                  ocreg_cli, ocreg_service, ocreg_crash_helper
    tests/                  eight ctest targets, no timeouts anywhere
    benchmarks/             three benchmarks that assert completed work
    examples/downstream/    independent find_package consumer

### Layers

| Layer | Header | Responsibility |
| --- | --- | --- |
| Foundations | `strong.hpp`, `checked.hpp`, `name.hpp`, `semver.hpp`, `units.hpp` | Typed identities, checked arithmetic, exact units |
| Catalog | `catalog.hpp` | Closed enumeration of capability kinds, features and limits |
| Reasons | `reason.hpp` | Stable numeric reason codes with canonical spellings |
| Integrity | `hash.hpp` | SHA-256, CRC-32C, canonical digests |
| Encoding | `codec.hpp` | One canonical binary encoding shared by persistence, the wire and digests |
| Text | `json.hpp` | Strict canonical JSON with hard bounds |
| Model | `evidence.hpp`, `decision.hpp` | Evidence, provenance, requirements, decisions |
| Engine | `registry.hpp` | Admission, retirement, conflict, query, evaluation, explanation |
| Durability | `persist.hpp` | Versioned, integrity-checked snapshot and journal |
| Exchange | `export.hpp` | Canonical machine-readable document |
| Service | `protocol.hpp`, `client.hpp`, `service.hpp` | Framed bounded request/response over a stream socket |

### Data flow

    observation source  ->  admission request  ->  registry
                                                     |
                        admitted evidence + provenance + generation
                                                     |
    requirement  ------------------------------>  evaluation  ->  decision
                                                     |              |
                                              explanation    canonical export
                                                     |
                                              snapshot + journal

Nothing enters the registry except through an admission request carrying an
explicit source, an explicit generation and an explicit observation tick.

---

## Core state model

Every correctness-critical identity is a distinct type. A `ProviderId` is not a
`DeviceModelId`, an `IncarnationId` is not a `RecordGeneration`, and a `Tick` is
not a `RegistryEpoch`; the compiler refuses to substitute one for another.

| Concept | Type | Meaning |
| --- | --- | --- |
| Device identity | `DeviceIdentity` | provider, model, unit index, optional serial |
| Device incarnation | `DeviceIncarnationRef` | a specific incarnation of a device |
| Capability kind | `CapabilityKind` | one of fourteen enumerated kinds |
| Semantic version | `SemVer` | full Semantic Versioning 2.0.0, including pre-release and build metadata |
| Feature set | `FeatureSet` | sorted, de-duplicated, closed set of `FeatureCode` |
| Limit set | `LimitSet` | sorted set of `LimitValue` (code, exact unit, value) |
| Firmware and runtime generation | `FirmwareGeneration`, `RuntimeGeneration`, `SemVer` | reported build identity |
| Observation source | `SourceId`, `SourceKind`, `SourceIncarnation` | who is speaking, and from which incarnation |
| Authority | `AuthorityRank` | policy-assigned rank, not a property of the source |
| Freshness | `Tick` observation, optional `valid_until` | how long a claim stands |
| Evidence generation | `RecordGeneration` | monotonic within one stream |
| Registry epoch | `RegistryEpoch` | advanced by every authority-affecting change |
| Policy revision | `PolicyRevision` | advanced with the epoch |
| Rule generation | `RuleGeneration` | the compatibility rule set generation |
| Store generation | `StoreGeneration` | the durable commit generation |
| Boot epoch | `BootEpoch` | advanced by every process start |
| Decision | `DecisionKind` and `DecisionId` | the answer and its content-derived identity |

### Evidence states

Effective state is derived at evaluation time, never stored as a mutable flag:

`active`, `superseded`, `retired`, `rejected`, `fenced`, `stale`, `outranked`,
`evicted`.

Only `active` evidence can satisfy a requirement. The precedence is fixed and
deterministic: rejected, retired, superseded, fenced, stale, then authority
resolution which distinguishes `active` from `outranked`.

---

## Capability catalog

The catalog is closed and typed. Fourteen capability kinds, 101 features and 37
limit codes are enumerated with stable numeric values and canonical spellings.

* Each feature belongs to a set of capability kinds. Declaring
  `checksum_l4_tx` on an `rdma_transport` record is
  `REJECTED_FEATURE_NOT_IN_KIND`, not a silently accepted string.
* Each limit code has one canonical unit. `maximum_transmission_unit` is bytes
  and nothing else; declaring it in bits is `REJECTED_LIMIT_UNIT_INVALID`.
* Each limit code permits a specific set of scales. A kibit/s bandwidth is
  `bit_per_second.bin1`; a kibibyte MTU is not permitted at all.
* `catalog_fingerprint()` covers the whole table. A persisted store or exported
  document written under a different catalog generation is refused with
  `STORE_SEMANTIC_MISMATCH`.

## Exact units and checked arithmetic

Limits are compared with exact integer arithmetic only:

* Conversion is attempted in both directions and succeeds only when the ratio
  between the two units is an exact integer mapping.
* A unit mismatch in dimension is `UNKNOWN_UNIT_MISMATCH`.
* A conversion that would round is `UNKNOWN_INEXACT_UNIT_CONVERSION`.
* A limit that was never reported is absent. It is never zero, and a requirement
  on it is `UNKNOWN_LIMIT_NOT_REPORTED`, never "below the requirement".
* Every multiplication, addition and division of externally derived sizes,
  timestamps, counters and limits goes through checked helpers. Overflow is a
  reported failure; it never wraps into a plausible value.

---

## Decisions

Four answers exist, and no fifth:

| Kind | Meaning |
| --- | --- |
| `compatible` | Admitted, current, authoritative evidence satisfies every part of the requirement |
| `incompatible` | Admitted evidence positively shows a requirement is unmet |
| `unknown` | The registry has no basis to answer; the reason codes say why |
| `conflicted` | Equal-authority evidence disagrees and no resolution exists |

The distinction that matters most is between `unknown` and `incompatible`.
Absence of evidence is `unknown`; evidence that says "no" is `incompatible`.

Every decision carries its reason codes, the evidence identifiers it considered,
a per-record state fact for each, the selected record, the conflict if any, the
rule generation, registry epoch and policy revision it was taken under, the
logical tick, and a content-derived `DecisionId`. Identical inputs produce an
identical identifier.

### Explanations

`Registry::explain(DecisionId)` returns the retained decision together with the
source policies that made it legal, the conflict group and any operator
resolution. Decisions are retained in a bounded store; eviction from that store
is counted in `decisions_evicted`, and asking for an evicted decision returns
`UNKNOWN_NO_EVIDENCE` rather than a guess.

---

## Provenance, authority and freshness

* **Authority is policy, not a property.** `AuthorityRank` is assigned per source
  in `RegistryPolicy`. Changing it bumps the epoch and re-ranks every group.
* **Outranking is live.** Among currently active records the highest authority
  wins; equals must agree or the group is conflicted; lower ranks are `outranked`
  and reported but never selected.
* **Freshness is an input.** The registry never reads a wall clock on a decision
  path. Every call takes an explicit `Tick`, so a run is reproducible. A record
  is stale when `now - observed_at` exceeds the effective bound for its source,
  or when `valid_until` has passed.
* **A refused record stays visible.** A delivery that arrives out of order is
  retained as `rejected` evidence, so a later query can explain the refusal.
  Bounds on that retention are enforced and counted.

---

## Conflicts

Two sources of equal authority that disagree about the same capability of the
same device incarnation produce a **conflict group**. The registry retains both
records, reports `conflicted` and never fabricates a fact from the disagreement.

Resolution is an explicit operator act referencing the conflict identifier, the
chosen member and a trusted resolver source. The resolution is content-addressed
and idempotent. A resolution that no longer matches the current member set stops
applying, so a stale resolution cannot silently select a record that has since
changed.

---

## Persistence and restart

    <store>                 snapshot: header, payload, footer
    <store>.ocregjournal    append-only journal of durable commits
    <store>.ocregtmp        temporary file used during a snapshot write

* One canonical encoding is shared by the snapshot payload, the journal entry
  and the state digest.
* The snapshot header carries the format version, API generation, catalog
  fingerprint, reason-table fingerprint, payload length, commit metadata, a
  SHA-256 of the payload and a CRC-32C of the header. The footer carries the
  header's payload length, a CRC-32C of the payload, the record count and its
  own CRC-32C.
* The durable commit point is a `StateSnapshot` journal entry that is
  synchronised before the acknowledgement is returned. Rotation writes a fresh
  snapshot atomically (temporary file, synchronise, rename) and truncates the
  journal.
* Recovery classifies what it found and accounts for every byte it refused:
  clean open, journal replayed, torn tail truncated, trailing corruption
  dropped, rebuilt from snapshot, or refused.
* **Conservative restart is the default.** Every record loaded from a store is
  fenced until its source re-attests under the new boot epoch, because the
  registry cannot know whether a device is still present. Sources whose policy
  declares `durable_across_boot` are exempt. Either way the logical clock
  resumes no earlier than the state it recovered, so persisted dynamic evidence
  never becomes fresh again by itself.
* A store that exists but holds no recoverable state is **refused** with the
  precise cause. It is never silently reset to empty.

---

## Canonical export

`ocreg.canonical-state` documents are canonical JSON: object keys sorted, no
insignificant whitespace, integers only, no floating point, arrays in canonical
order. The document declares the format version, API generation, catalog and
reason-table fingerprints, the full policy, devices, evidence, tombstones,
conflicts, resolutions, evictions, counters, and the digest of the binary state
it was produced from.

Import re-derives the state, recomputes the digest and refuses any mismatch.
Truncation is declared in the document and refused on import, so a partial
document can never become a valid-looking state.

`ocreg.policy` and `ocreg.requirement` documents use the same vocabulary and
the same strict parser.

---

## Service and transport

The runtime exposes a framed, bounded request/response protocol over a stream
socket for callers that need the registry as a separate process.

Every frame carries a magic value, a protocol version, flags, an opcode, a
request identifier, a bounded payload length, a SHA-256 of the payload and a
CRC-32C of the header. A frame with a bad magic, a bad header checksum, a bad
payload digest, an unsupported version, an unknown opcode or an oversized
payload is refused with a stable code, and the connection is closed after the
refusal is reported.

Answers travel in an envelope whose reason code distinguishes a request that
could not be processed from a registry outcome that is itself a refusal (an
unknown source, a superseded generation). "No evidence" is a successful answer
carrying an unknown code.

Connection count, worker count, queue depth, frame size and per-connection
request count are all bounded, and every refusal is counted.

---

## Command line tools

    ocreg_cli verify    --store PATH
    ocreg_cli stats     --store PATH [--tick N]
    ocreg_cli export    --store PATH [--pretty]
    ocreg_cli import    --store PATH --document FILE [--policy FILE]
    ocreg_cli ingest    --store PATH --document FILE
    ocreg_cli query     --store PATH --provider P --model M --unit N \
                        --incarnation I --kind K [--tick N] [--history]
    ocreg_cli evaluate  --store PATH --requirement FILE [--tick N]
    ocreg_cli explain   --store PATH --decision HEX
    ocreg_cli remote-ping   --host H --port P
    ocreg_cli remote-stats  --host H --port P [--tick N]
    ocreg_cli remote-export --host H --port P [--pretty] [--tick N]

    ocreg_service --store PATH [--port N] [--bind ADDR] [--workers N] \
                  [--connections N] [--policy FILE] [--tick N]

`ocreg_service` prints `PORT <n>` once listening, serves until a `Shutdown`
request, commits a final durable snapshot and exits.

`ocreg_crash_helper` exists solely so the recovery tests can hard-kill a process
at a meaningful durable boundary. It offers no other behaviour.

---

## Building

Requirements: a C++20 compiler and CMake 3.21 or newer. There are no third-party
dependencies.

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    ctest --test-dir build --output-on-failure

On Windows, configure from a Visual Studio developer environment (or any shell
where `cl` is on `PATH`). First-party code is compiled with `/W4 /WX /permissive-`
on MSVC and with `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
-Wold-style-cast -Werror` elsewhere.

Options:

| Option | Default | Effect |
| --- | --- | --- |
| `OCREG_BUILD_TOOLS` | `ON` | Build the CLI, service and crash helper |
| `OCREG_BUILD_TESTS` | `ON` | Build the test suite |
| `OCREG_BUILD_BENCHMARKS` | `ON` | Build the benchmarks |
| `OCREG_WARNINGS_AS_ERRORS` | `ON` | Treat first-party warnings as errors |
| `OCREG_ENABLE_ASAN` | `OFF` | Build with `/fsanitize=address` on MSVC |

## Installing and consuming

    cmake --install build --prefix /some/prefix

The install exports `OCRegConfig.cmake`, `OCRegConfigVersion.cmake`, the
exported target `OCReg::ocreg` and the public headers. Warning flags are applied
`PRIVATE` and never leak downstream.

An independent consumer lives in `examples/downstream`. It adds no upstream
source, includes only installed headers, and builds with its own strict flags:

    cmake -S examples/downstream -B out/downstream \
          -DCMAKE_PREFIX_PATH=/some/prefix
    cmake --build out/downstream
    ctest --test-dir out/downstream --output-on-failure

---

## Testing

Eight ctest targets, none of which uses a timeout. Every wait in the suite
synchronises on completed work, a joined thread, end-of-stream or a protocol
exchange; a hang would be a defect rather than something to bound.

| Target | Covers |
| --- | --- |
| `ocreg_test_core` | Identities, checked arithmetic, units, semantic versions, catalog, reason codes, digests, JSON, codec round trips |
| `ocreg_test_registry` | Admission, idempotency, supersession, staleness, retirement, revocation, reincarnation, conflicts, resolutions, eviction accounting, restart fencing, determinism |
| `ocreg_test_export` | Canonical round trip, determinism, truncation reporting, tampering, policy and requirement documents |
| `ocreg_test_persistence` | Clean reopen, journal replay, torn tail, corruption, truncation, version and semantic mismatch, rotation, replay refusal, full state round trip, random-byte decoding |
| `ocreg_test_transport` | Frame codec, malformed and oversized frames, in-process service and client, repeated start and stop, connection bounds |
| `ocreg_test_property` | Seeded randomized invariants, differential delivery order, random documents, mutation fuzzing, unit conversion properties |
| `ocreg_test_concurrency` | Concurrent ingest against a serial reference, queries during ingest, many clients, shutdown with work in flight, repeated start and stop |
| `ocreg_test_process` | Independent `ocreg_service` processes over loopback TCP, restart across processes, hard kill at every durable boundary, CLI behaviour |

### Proof obligations and where they are demonstrated

| Obligation | Demonstrated by |
| --- | --- |
| Stale or superseded capabilities cannot satisfy current requirements | `superseded_evidence_cannot_satisfy_a_current_requirement`, `stale_evidence_is_not_current` |
| Conflicting equal-authority evidence never becomes a fact | `equal_authority_disagreement_is_never_fabricated_into_a_fact` |
| Numeric limits use checked arithmetic and exact units | `numeric_limits_use_exact_units_and_checked_arithmetic`, `unit_conversion_is_symmetric_and_exact_or_refused` |
| Serialization round-trips without semantic loss | `state_serialisation_round_trips_every_correctness_critical_field`, `canonical_export_round_trips_without_semantic_loss` |
| Persisted dynamic evidence is not silently fresh | `persisted_dynamic_evidence_does_not_silently_become_fresh` |
| Equivalent inputs produce stable decisions and digests | `equivalent_inputs_produce_identical_decisions_and_digests`, `delivery_order_never_changes_the_current_fact` |
| Accepted state is deterministic from accepted evidence and policy | `admission_order_does_not_change_the_accepted_state`, `concurrent_ingest_matches_serial_ingest_exactly` |
| Missing evidence never becomes false, zero or success | `missing_evidence_is_never_zero_false_or_success` |
| Duplicate delivery is idempotent and collisions are fenced | `duplicate_delivery_is_idempotent_and_a_generation_collision_is_not` |
| Every truncation, refusal and eviction is observable | `bounded_eviction_is_observable_and_accounted_for`, `a_full_record_budget_refuses_rather_than_discarding_current_evidence`, `export_reports_truncation_instead_of_silently_dropping_records` |
| Conservative restart does not resurrect liveness or authority | `restart_fences_evidence_and_never_resurrects_authority`, `durable_operator_declarations_survive_a_restart_while_dynamic_evidence_does_not` |
| Malformed input cannot produce valid-looking success | `import_refuses_every_malformed_or_tampered_document`, `random_bytes_never_decode_into_a_valid_state`, `hard_kill_at_every_durable_boundary_never_fabricates_success` |
| Duplicate and reordered delivery is fenced, never merged | `a_replayed_or_reordered_journal_entry_is_not_applied` |
| A durable commit survives a process that dies before acknowledging | `a_durable_commit_is_visible_even_when_the_process_dies_before_acknowledging` |
| Multiprocess behaviour is proven with real processes and sockets | `a_service_process_serves_a_client_over_a_real_socket`, `a_second_service_process_reads_what_the_first_committed` |

### Concurrency and locking

* Every public registry entry point takes exactly one lock: shared for reads,
  exclusive for mutations. No helper called while a lock is held takes a lock
  again, so there is no read-to-write reacquisition and no nested acquisition.
* No callback, user code or I/O runs while a lock is held. The service never
  calls back into the registry from inside a lock.
* Where a caller holds two locks the order is always (registry, store).
* Shutdown is a real barrier: the acceptor is unblocked by a self-connection
  rather than by a timeout, in-flight connections are shut down so blocked reads
  return, and every worker is joined.

## Benchmarks

Three benchmarks, each of which asserts the expected number of operations
completed before reporting. Nothing measures enqueue latency.

    cmake --build build --target ocreg_bench_registry ocreg_bench_persistence ocreg_bench_transport
    ./build/ocreg_bench_registry
    ./build/ocreg_bench_persistence
    ./build/ocreg_bench_transport

| Benchmark | Measures |
| --- | --- |
| `ocreg_bench_registry` | Admission, evaluation, query, canonical round trip and durable commit throughput |
| `ocreg_bench_persistence` | Durable snapshot writes and torn-tail recovery opens |
| `ocreg_bench_transport` | Completed request/response exchanges over loopback, sequential and concurrent |

---

## Determinism and canonical form

* Every container the registry exposes is in a canonical order: streams by
  (device incarnation, capability kind, source), records by (generation, then
  content identifier), reason codes by numeric value, feature and limit sets by
  code, object keys lexicographically.
* Every identifier that describes content is derived from that content
  (`EvidenceId`, `DecisionId`, `ConflictId`, `ResolutionId`), which is what makes
  duplicate delivery idempotent and decisions reproducible.
* Digests are computed over the canonical binary encoding, never over a textual
  rendering that could vary.
* Logic that could depend on the clock takes an explicit `Tick`.

## Bounds

Every bound is enforced before allocation and every enforcement is reported.
Devices, incarnations per device, streams, records, records per stream,
tombstones, conflict groups, resolutions, eviction-ledger entries, sources,
retained decisions, features per record, limits per record and limits per
requirement are all bounded by `RegistryLimits`. Store snapshot size, journal
entry size, journal size, journal entry count and replay count are bounded by
`StoreLimits`. Frame payload, connections, workers, queue depth and export size
are bounded on the service side.

When a bound is reached, the registry either evicts a record that is provably
not current and records the eviction, or refuses the operation with a specific
code. It never discards current evidence to make room.

## Known limitations

* No device, NIC, SmartNIC, DPU, switch, ASIC, RDMA, InfiniBand, NVLink,
  multi-host or CUDA adapter exists. Every capability record this runtime has
  ever validated was produced by a synthetic fixture or an operator declaration.
* The transport is loopback-oriented. It has been exercised across independent
  processes on one host and real sockets; it has not been exercised across hosts
  or through a network that reorders or drops connections.
* `SemVer` implements Semantic Versioning 2.0.0 including pre-release and build
  metadata. Precedence follows the specification; identity compares every field,
  so versions differing only in build metadata are distinct identities.
* Freshness bounds are logical ticks. The registry does not know how fast a tick
  is; a caller that chooses `ClockMode::SystemMonotonic` is responsible for the
  mapping between ticks and real time.
* Conflict resolution is a record of an operator act. The registry does not
  verify that the resolver had the standing to make it beyond source trust.
* Canonical export is a full-state document. There is no partial or incremental
  export format.
* The journal stores whole committed states. It is compacted by rotation rather
  than by deltas, so a very high commit rate with a large state is bounded by
  the rotation threshold rather than by a delta encoding.
* AddressSanitizer coverage was exercised on this project's compiler and
  platform only; no claim is made about sanitizer runs elsewhere.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
