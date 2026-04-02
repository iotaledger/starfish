# DAG-based BFT protocols

[![rustc](https://img.shields.io/badge/rustc-1.85+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

## Overview

This repository is a benchmarking framework for DAG-based BFT
consensus protocols in the partially synchronous model, implemented
in Rust.
It includes 8 protocol implementations with configurable
dissemination strategies, storage backends, and Byzantine fault
injection.

## Protocols

| Protocol | CLI name | Latency | DAG | Tx data | Default dissemination | Metadata (happy) | Metadata (worst) | Reference |
|---|---|---|---|---|---|---|---|---|
| Mysticeti | `mysticeti` | 4.5δ | Uncertified | Full | Pull | O(n³) | O(n⁴) | [arxiv.org/abs/2310.14821](https://arxiv.org/abs/2310.14821) |
| Mysticeti-BLS | `mysticeti-bls` | 4.5δ | Uncertified | Full | Pull | O(n²) | O(n³) | [eprint.iacr.org/2025/567](https://eprint.iacr.org/2025/567)* |
| Bluestreak | `bluestreak` | 4.5δ | Uncertified | Full | Pull | O(n²) | O(n³) | -- |
| Starfish-Speed | `starfish-speed` | 4.5δ | Uncertified | Encoded | Push | O(n⁴) | O(n⁴) | -- |
| Starfish | `starfish` | 5.5δ | Uncertified | Encoded | Push | O(n⁴) | O(n⁴) | [eprint.iacr.org/2025/567](https://eprint.iacr.org/2025/567) |
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
**Starfish-Speed** adds strong-vote optimistic sequencing for lower
latency when validators share the leader's acknowledgments.
**Sailfish++** is a certified DAG protocol using signature-free
optimistic reliable broadcast (RBC) for vertex certification,
achieving 2-round optimistic commit latency.
**Starfish-BLS** embeds compact BLS aggregate certificates (round,
leader, data availability) in block headers, with async verification
offloaded from the critical path.

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

### Distributed Testing using Orchestrator

To run tests on a geo-distributed network, look at instructions in
[crates/orchestrator/README.md](crates/orchestrator/README.md).

## License

[Apache 2.0](LICENSE)

