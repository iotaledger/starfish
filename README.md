# DAG-based BFT protocols

[![rustc](https://img.shields.io/badge/rustc-1.85+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

## Overview

This repository is a benchmarking framework for DAG-based BFT
consensus protocols in the partially synchronous model, implemented
in Rust.
It includes 10 protocol implementations with configurable
dissemination strategies, storage backends, and Byzantine fault
injection.

## Protocols

| Protocol | CLI name | Latency | DAG | Tx data | Default dissemination | Metadata (happy) | Metadata (worst) | Reference |
|---|---|---|---|---|---|---|---|---|
| Mysticeti | `mysticeti` | 4.5δ | Uncertified | Full | Pull | O(n³) | O(n⁴) | [arxiv.org/abs/2310.14821](https://arxiv.org/abs/2310.14821) |
| Mysticeti-BLS | `mysticeti-bls` | 4.5δ | Uncertified | Full | Pull | O(n²) | O(n³) | [eprint.iacr.org/2025/567](https://eprint.iacr.org/2025/567)* |
| Bluestreak | `bluestreak` | 4.5δ | Uncertified | Full | Pull | O(n²) | O(n³) | [paper](papers/bluestreak.pdf) |
| Starfish-Speed | `starfish-speed` | 4.5δ | Uncertified | Encoded | Push | O(n⁴) | O(n⁴) | -- |
| Sparse-Starfish-Speed | `sparse-starfish-speed` | 4.5δ | Uncertified | Encoded | Push | O(n²) | O(n³) | -- |
| Starfish | `starfish` | 5.5δ | Uncertified | Encoded | Push | O(n⁴) | O(n⁴) | [eprint.iacr.org/2025/567](https://eprint.iacr.org/2025/567) |
| Starfish-RBC (prototype) | `starfish-rbc` | TBD | RBC-certified headers | Encoded | Push | TBD | TBD | [design](docs/starfish-rbc-protocol.md) |
| Cordial Miners | `cordial-miners` | 6δ | Uncertified | Full | Push | O(n³) | O(n⁴) | [arxiv.org/pdf/2205.09174](https://arxiv.org/pdf/2205.09174) |
| Sailfish++ | `sailfish-pp` | 6δ | Certified | Full | Pull | O(n³) | O(n⁴) | [arxiv.org/abs/2505.02761](https://arxiv.org/abs/2505.02761) |
| Starfish-BLS | `starfish-bls` | 6.5δ | Uncertified | Encoded | Push | O(n²) | O(n³) | [eprint.iacr.org/2025/567](https://eprint.iacr.org/2025/567)* |

Transaction data cost is O(Mn) in the happy case for all protocols, but it gets to O(Mn²) for full-block protocols while stays O(Mn) for
encoded (Reed-Solomon) protocols, where M is the total payload per
round.

\* Practical instantiation of Starfish-L and Mysticeti-L with BLS aggregate
signatures.

**Mysticeti** uses bandwidth-efficient pull-based dissemination:
validators push their own blocks and request missing ancestors.
**Cordial Miners** pushes the full unknown block history to peers;
tolerant to Byzantine attacks but less scalable.
**Mysticeti-BLS** extends Mysticeti with BLS aggregate signatures
and compressed block references.
**Bluestreak** uses compressed block references and unprovable
certificate tracking, similar in architecture to Mysticeti-BLS, but with cheaper certification.
**Starfish** uses push dissemination for headers and Reed-Solomon encoded shards with
acknowledgment references between validators.
**Starfish-RBC** composes plain Starfish with direct Bracha reliable broadcast of canonical
headers. ECHO and READY are recipient-authenticated with pairwise MACs; the author's INIT can use
Ed25519, ML-DSA-44, ML-DSA-65, or one recipient-specific MAC. It is a correctness-oriented research
prototype with the limitations documented in its [protocol specification](docs/starfish-rbc-protocol.md).
**Starfish-RBC-DAG** is the standalone follow-up that carries authentication, reliable-broadcast
control, application headers, and logical Starfish vertices in one optimistic carrier DAG. Run the
comparison plane with `--consensus starfish-rbc --starfish-rbc-dag-shadow`; add
`--starfish-rbc-dag-autonomous-clock --starfish-rbc-dag-embedded-rbc-authority` to make that carrier
plane the sole reliable-broadcast, consensus, ordering, and output authority. In this mode the direct
Starfish-RBC service is not started: direct INIT/phase/header-recovery messages, generic block
batches, and legacy parent/transaction pulls cannot certify or order an application. Application
bytes travel with the carrier envelope when available, or through the dedicated RBC-DAG payload
request/response path, and are accepted only after commitment verification.

The implemented MAC-vector RBC uses four embedded phases. For target-author stake `a` and total
stake `W`, ECHO, VOTE, and ACK exclude the target author; weighted thresholds `M`, `C`, and `O`
drive VOTE, ACK/READY convergence, and authoritative optimistic delivery. Reaching `O` ECHO stake
is sufficient for the fast delivery latch, while `Q = W - floor((W - 1) / 3)` READY stake records a
separate slower certification latch. If `a > floor((W - 1) / 3)`, the fault model makes the author
honest and receiver-authenticated exact content can take the fast latch directly. All four phases
use per-sender and local slot-global locks, and threshold evidence without content triggers exact
carrier recovery before a local follow-up is exposed. The full definitions and safety boundary are
in the [protocol design](docs/starfish-rbc-dag-protocol.md).

Autonomous carriers embed durably locked consensus vertices with quorum strong parents, explicit
Vote/NoVote choices, and exact delivery frontiers. Authoritative delivery alone is not application
data availability: projection and output wait until Core has materialized the concrete application
block and its committed payload is available. Each committed anchor is componentwise joined into a
cumulative committed frontier; only the new exact, data-available prefix delta is released, and
the legacy Starfish committer is disabled. The prototype admits at most two carrier rounds ahead,
retains canonical unsolicited carrier content up to 64 rounds ahead, and offers rate-limited
single-slot exact synchronization rather than checkpoint or proof-safe late-node state transfer.
Its current authoritative journal uses the V4 autonomous WAL namespace with `SRD5` raw records so
older traces cannot be reinterpreted under the optimistic-delivery rules.

Strict two-level Starfish finality remains the default. The local benchmark additionally exposes
`--starfish-rbc-dag-vote-qc-fast-path`, a deliberately flagged testbed experiment that commits an
exact projected leader as soon as its projected vote quorum is present instead of waiting for the
second certifier wave. It sends no additional protocol messages, but changes the proof shape and
must not be reported as the strict or production Starfish result.

The default WAL syncs every transition. `--starfish-rbc-dag-shadow-buffered-wal` preserves ordered
frames but syncs only on clean shutdown and is not crash-safe. Actor replay covers the state
explicitly documented in the protocol design; full validator crash recovery, bounded checkpoint
transfer, and proof-safe state retirement are not claimed. Shadow traffic shares the validator's
network socket and bandwidth, and deployment requires a homogeneous new-binary committee. Idle
carrier heartbeats reuse Starfish's resolved leader timeout (600 ms for Starfish-RBC by default);
application and encodable phase carriers are emitted immediately.
For a direct-header shadow comparison,
`starfish_rbc_dag_shadow_comparison_valid` must stay at `1`; a value of `0` means the bounded
observational path was disabled or shed work and the comparison must be discarded. Healthy live
production retains a short embedded-RBC pipeline tail, so benchmark validation uses bounded
unpaired-count and oldest-round-lag gauges rather than requiring instantaneous equality between
the cumulative direct and shadow delivery counters. Autonomous runs instead require
`starfish_rbc_dag_shadow_clock_valid == 1`, local-carrier/WAL progress, advancing carrier rounds,
in-window local carrier, embedded-RBC delivery, projected-vertex, clean projected-commit, and
committed-frontier application progress, plus bounded clock-state gauges. The current queue budget
supports at most 60 validators in mirror mode and 20 in autonomous mode.

A matched 10-validator, 60-second-active-window local run on 2026-08-11 used the AWS RTT emulator,
nominal 1,000 tx/s load, MAC authentication, the buffered benchmark WAL, and Starfish's shared
600 ms leader/idle-carrier timeout. These milestone rows predate the current four-phase V4
authority model and are retained as historical measurements.

| Profile | Verdict | TPS | Block latency | E2E latency | Outbound BW |
|---|---:|---:|---:|---:|---:|
| Direct Starfish-RBC, shadow off | n/a | 972.25 | 1,508.0 ms | 1,724.0 ms | 0.53 MB/s |
| Autonomous comparison, direct RBC authoritative | VALID 10/10 | 971.37 | 1,498.9 ms | 1,714.0 ms | 0.58 MB/s |
| Embedded RBC authoritative (milestone five) | VALID 10/10 | 861.92 | 3,539.3 ms | 5,477.5 ms | 0.52 MB/s |
| Certified projection (milestone six) | VALID 10/10 | 799.07 | 5,102.9 ms | 8,650.9 ms | 0.50 MB/s |
| Frontier output authority (milestone seven) | VALID 10/10 | 950.25 | 2,020.9 ms | 2,082.6 ms | 0.70 MB/s |

The milestone-five run produced 10,722 embedded application deliveries, reached carrier rounds
458–459, and ended with zero pending recovery. It also proves that the earlier 250 ms experimental
heartbeat was not the latency cause: application and phase carriers are already event-driven, and
using the shared 600 ms timeout did not restore the direct baseline. The remaining slowdown is an
expected warning about the transitional architecture—the old direct DAG still serializes proposal
creation on embedded RBC cleanliness. Milestone six lets the optimistic carrier clock advance
independently and feeds only certified vertices into the logical committer; its result motivated
milestone seven's removal of the remaining legacy output gate.
The milestone-six run reached carrier rounds 356–359 with 35,506 carrier deliveries, 8,059
application deliveries, 8,487 projected vertices, 830 clean direct commits, and zero pending
recovery. Its further latency increase is a structural red flag, not a projection-speed claim:
certified decisions currently run alongside the old clean-predecessor/output path, so the benchmark
still pays for both. Milestone seven's measurement below is the first one after removing that
legacy gate.
Milestone seven disables the legacy committer in embedded-authority mode, advances application
production from the optimistic carrier clock, and releases exact application headers only through
committed frontier deltas. Its run reached carrier round 795 on every validator, delivered 79,035
application carriers, released 77,870 applications through 1,880 committed frontiers, and ended
with zero pending recovery. This recovers 60.4% of milestone six's block-latency regression and
75.9% of its E2E regression, but 2.02/2.08 seconds is still well above the roughly 600 ms unsafe
Starfish-MAC target. The next performance work must measure and shorten the certified-projection
round/commit pipeline rather than reintroducing legacy certification or ordering.
The local harness starts its timer after transaction-generator warmup, subtracts warmup counters,
and drains the final latency samples.
**Starfish-Speed** adds strong-vote optimistic sequencing for lower
latency when validators share the leader's acknowledgments.
**Sparse-Starfish-Speed** (work in progress) combines Bluestreak's
lean DAG with Starfish-Speed's strong-vote mechanism: only the round
leader carries an explicit acknowledgment list, non-leader voters
emit a constant-size strong-vote bitmask, and the linearizer derives
global acks from `(leader.acks, voter.strong_vote)`. The block-header
unprovable certificate is generalized with a strong/standard flavor
tag (`Option<(BlockReference, bool)>`).
**Sailfish++** is a certified DAG protocol using signature-free
optimistic reliable broadcast (RBC) for vertex certification,
achieving 2-round optimistic commit latency.
**Starfish-BLS** embeds compact BLS aggregate certificates (round,
leader, data availability) in block headers, with async verification
offloaded from the critical path.

### Block authentication

Every consensus protocol can select its public block-signature scheme independently.
Starfish-RBC additionally supports a receiver-specific MAC for the author's initial header:

| Scheme | CLI option |
|---|---|
| Ed25519 (default) | `--block-authentication ed25519` or omit the option |
| ML-DSA-44 | `--block-authentication ml-dsa-44` |
| ML-DSA-65 | `--block-authentication ml-dsa-65` |
| Pairwise MAC (Starfish-RBC only) | `--block-authentication mac` |

For example, `--consensus mysticeti --block-authentication ml-dsa-65` changes
Mysticeti's block signature without creating another consensus protocol. This
selection is also available through the orchestrator. Protocol-specific BLS
certificates are unaffected. These digital-signature selections retain the
transferable public verification assumed by the protocols and do not change
their message flow or proof structure. The same value can be set as
`block_authentication` in the node-parameters YAML; the CLI option overrides
that setting.

`BlockReference.digest` is the BLAKE3 hash of the canonical block content only.
The modular authentication proof is a separate header field and does not change
the block reference. Benchmark genesis generates all Ed25519 and ML-DSA key
material regardless of the selected signature scheme.

The ML-DSA wrappers are generated from a common parameter-set definition.
ML-DSA-44 uses 1,312-byte public keys and 2,420-byte signatures; ML-DSA-65
uses 1,952-byte public keys and 3,309-byte signatures.

This is research/benchmark code. The RustCrypto `ml-dsa` implementation used
here states that it has not been independently audited and should not be
treated as production-ready cryptography.

#### Experimental MAC protocols

`--consensus starfish-rbc --block-authentication mac` runs the reliable-header-broadcast
prototype. It sends one author tag to each intended recipient, then runs the same pairwise-MAC
ECHO/READY flow used by Starfish-RBC's signature-authenticated modes. Only locally delivered,
dependency-closed headers enter the clean consensus DAG.

`starfish-mac`, `starfish-speed-mac`, `sparse-starfish-speed-mac`, and
`bluestreak-mac` remain separate work-in-progress benchmark protocols. They are
not interchangeable signature selections and cannot be combined with
`--block-authentication`.

These variants measure a lower bound for pairwise-MAC authentication. Direct
author streaming carries the full committee-sized MAC vector; relays and
synchronization responses carry only the destination's tag. Pairwise MACs do
not provide transferable authorship, and a Byzantine author can give different
recipients valid and invalid tags for the same block reference. These lower-bound modes do not add
the quorum-authentication/RBC exchange needed to bind
the author to an available authenticator. It therefore makes no safety or
liveness claim and must not be treated as a proven variant of the underlying
protocol.

## Dissemination Modes

Every protocol can run with any of three dissemination strategies
(override with `--dissemination-mode`):

- **Pull** -- push own blocks only; request missing ancestors on
  demand
- **Push-causal** -- push blocks together with their causal history
- **Push-useful** -- push only blocks the receiver hasn't seen yet
  (uses cordial knowledge tracking; nodes hint peers about which
  authorities could be useful for them). Consumes less bandwidth
  than push-causal, but push-causal has benefits when nodes
  experience network issues. Used in production in
  [iotaledger/iota](https://github.com/iotaledger/iota/tree/develop/crates/starfish)

Use `protocol-default` to select each protocol's native strategy
(see table above).

## Configuration

**Storage backends**: RocksDB (default) or
[Tidehunter](https://github.com/MystenLabs/tidehunter)
(`--storage-backend tidehunter`, requires the `tidehunter` feature).
Both are configured for benchmark performance.

**Transaction modes**: `all-zero` (timestamp + counter + zero
padding) or `random` (timestamp + random bytes)
(`--transaction-mode`).

**Network compression**: lz4 compression is enabled by default
(`--compress-network`).

**Committee size**: up to 512 validators. To support larger
committees, increase `MAX_COMMITTEE_SIZE`.

## Implementation Details

The framework is implemented in Rust, building upon the
[Mysticeti testbed](https://github.com/asonnino/mysticeti/tree/paper).
The implementation includes:

- **Networking**: Every validator maintains a direct persistent TCP
  connection to every other validator (full mesh). Messages are
  serialized with [bincode](https://docs.rs/bincode/) and exchanged
  over these connections without RPC frameworks.
  Asynchronous I/O is handled by [tokio](https://tokio.rs)
- **Cryptography**:
  - [ed25519-consensus](https://docs.rs/ed25519-consensus/) for
    digital signatures
  - [blst](https://docs.rs/blst/) for BLS aggregate signatures
    (Starfish-BLS, Mysticeti-BLS)
  - [blake3](https://docs.rs/blake3/) for high-performance
    cryptographic hashing
- **Storage**: [RocksDB](https://rocksdb.org/) (default) or
  [Tidehunter](https://github.com/MystenLabs/tidehunter) for
  persistent storage of consensus data
- **Transaction Encoding** (Starfish family only):
  [Reed-Solomon-SIMD](https://crates.io/crates/reed-solomon-simd)
  implementing erasure codes over F_{2^16} with FFT-based decoding
  and SIMD optimization

Like other consensus testbeds, this prototype focuses solely on
consensus performance measurement without execution or ledger
storage components.

## Requirements

### Dependencies

The framework requires the following core dependencies:

- **Rust 1.85+**: For building and running the project
- **Build essentials**: `build-essential`, `libssl-dev`, `pkg-config`
- **Clang tools**: `clang`, `libclang-dev` (for compiling RocksDB
  and other native dependencies)

### Mac

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install dependencies via Homebrew
brew install \
    curl \
    openssl \
    pkg-config \
    llvm
```

### Ubuntu

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Update package index
sudo apt-get update

# Install essential dependencies
sudo apt-get install -y \
    build-essential \
    curl \
    libssl-dev \
    pkg-config \
    clang \
    libclang-dev
```

For more advanced usage scenarios (distributed testing, metrics
visualization, etc.), additional tools may be required.

## Quick Start

```bash
# Clone and build
git clone https://github.com/iotaledger/starfish.git
cd ./starfish
cargo build --release
```

### Run local benchmark

```bash
cargo run --release --bin starfish -- local-benchmark \
        --committee-size 7 \
        --load 1000 \
        --consensus starfish \
        --mimic-extra-latency \
        --duration-secs 100
```

Additional flags: `--dissemination-mode`, `--adversarial-latency`,
`--uniform-latency-ms`.

For the authoritative embedded-RBC benchmark profile:

```bash
cargo run --release --bin starfish -- local-benchmark \
        --committee-size 10 --load 1000 --consensus starfish-rbc \
        --block-authentication mac --mimic-extra-latency \
        --starfish-rbc-dag-shadow --starfish-rbc-dag-autonomous-clock \
        --starfish-rbc-dag-embedded-rbc-authority \
        --starfish-rbc-dag-shadow-buffered-wal --duration-secs 60
```

The buffered WAL is benchmark-only and is not crash-safe.

To measure the separately labelled testbed fast path, append
`--starfish-rbc-dag-vote-qc-fast-path`. Omitting it always measures the strict two-level rule.

### Local dryrun with monitoring and dashboard

The dryrun script launches a Docker-based local testbed with
Prometheus and Grafana:

```bash
./local-dryrun/dryrun.sh
```

```bash
NUM_NODES=10 CONSENSUS=starfish DESIRED_TPS=1000 \
  ./local-dryrun/dryrun.sh
```

Grafana is available at `http://localhost:3001` (admin/admin).
See [local-dryrun/README.md](./local-dryrun/README.md) for the
full parameter reference.

#### Local dryrun benchmark

The following numbers are from a local Docker dryrun with 10 validators,
1000 TPS, 60 seconds, default protocol dissemination modes, RocksDB,
random transaction payloads, lz4 network compression, and WAN latency
emulation enabled. Latencies and header sizes are p50 values.

| Protocol | Block latency (ms) | Transaction latency (ms) | Header size (B) |
|---|---:|---:|---:|
| Mysticeti | 417.1 | 475.2 | 493 |
| Mysticeti-BLS | 410.4 | 470.3 | 687 |
| Bluestreak | 414.4 | 473.0 | 279 |
| Starfish-Speed | 439.3 | 505.1 | 797 |
| Sparse-Starfish-Speed | 425.2 | 486.8 | 393 |
| Starfish | 569.0 | 621.6 | 673 |
| Cordial Miners | 547.2 | 737.6 | 462 |
| Sailfish++ | 557.1 | 909.2 | 490 |
| Starfish-BLS | 662.5 | 710.5 | 903 |

### Distributed Testing using Orchestrator

To run tests on a geo-distributed network, look at instructions in
[crates/orchestrator/README.md](crates/orchestrator/README.md).

## License

[Apache 2.0](LICENSE)
