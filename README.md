# Starfish

[![rustc](https://img.shields.io/badge/rustc-1.85+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

## Overview

The code in this repository is a prototype of Starfish,
a partially synchronous BFT protocol in which validators employ an uncertified DAG.
The theoretical description of Starfish is available
at https://eprint.iacr.org/2025/567.

Four versions of Starfish are available in this repository:

- **`starfish`**: Theory-aligned version
  - By default uses Push dissemination strategy for headers and shards
  - Better latency guarantees with Byzantine nodes

- **`starfish-s`**: Strong-vote optimistic variant
  - Uses strong votes for optimistic transaction sequencing
  - Lower latency when validators have same acknowledgments as a leader

- **`starfish-l`**: BLS-optimized variant
  - Uses BLS aggregate signatures to reduce communication complexity for header metadata
  - Embeds compact aggregate certificates (round, leader, data availability) in block headers
  - Async BLS verification service offloads signature processing from the critical path

The repository also supports other partially synchronous uncertified DAG-based consensus protocols:

- **`mysticeti`**: Implementation of [Mysticeti](https://www.cs.cornell.edu/~babel/papers/mysticeti.pdf).
Validators use a bandwidth efficient pull-based block dissemination strategy:
they push their own blocks and request the peers about missing ancestors only. 
- **`cordial-miners`**: Implementation of [Cordial Miners](https://arxiv.org/pdf/2205.09174).
Validators use a push-based block dissemination strategy,
pushing all unknown history of blocks to their peers.
Due to the push strategy, Cordial Miners can tolerate Byzantine attacks,
but it is overall a less scalable solution.

## Key Features of Starfish

- Starfish is a Byzantine Fault Tolerant protocol capable of tolerating up to 1/3 of Byzantine nodes in a partially synchronous network.
- It supports four configurable block dissemination modes:
  - `protocol-default` — uses the protocol's native strategy
    (pull for Mysticeti, push-causal for Starfish/CordialMiners)
  - `pull` — push own blocks only; request missing ancestors
  - `push-causal` — push blocks with their causal history
  - `push-useful` — push blocks likely unknown to the receiver
- It incorporates Reed-Solomon coding for transaction data
  to amortize communication costs
- It provides a linear amortized communication complexity for a large enough transaction load
- It achieves high throughput (~200-300K tx/sec for 10-100 validators) and subsecond end-to-end latency for up to 150K tx/sec

## Byzantine strategies

The testbed implements several Byzantine behaviors to evaluate consensus robustness.
The number of Byzantine nodes can be set using `--num-byzantine-nodes`
and has to be less than 1/3 of the total number of validators.
The Byzantine strategies include:

- `timeout-leader`: Byzantine validators time out when elected as leader to slow down consensus
- `leader-withholding`: Byzantine leaders withhold block proposals and send it to only a few other validators to delay the commit rule
- `chain-bomb`: Attackers attempt to disrupt the network by flooding some validators with their generated chains of blocks
- `equivocating-two-chains`: Byzantine validators create two equivocating blocks
and disseminate them to half of network, not allowing to directly skip their proposals
- `equivocating-chains`: Malicious validators create equivocating blocks and disseminate them to the respected validators
- `equivocating-chains-bomb`: Byzantine validator create chains of equivocating blocks
and send the chain just before the respected validator is elected as a leader.
Recommend to use 1 Byzantine validator as they are not coordinated
- `random-drop`: Byzantine validators randomly drop outgoing messages with probability `1/n` where `n` is the committee size

## Implementation Details

Starfish is implemented in Rust, building upon the [Mysticeti testbed](https://github.com/asonnino/mysticeti/tree/paper). The implementation includes:

- **Networking**: [tokio](https://tokio.rs) for asynchronous programming with direct TCP socket communication (no RPC frameworks)
- **Cryptography**:
  - [ed25519-consensus](https://docs.rs/ed25519-consensus/) for digital signatures
  - [blake3](https://docs.rs/blake3/) for high-performance cryptographic hashing
- **Data Handling**:
  - [bincode](https://docs.rs/bincode/) for efficient serialization of protocol messages
  - [RocksDB](https://rocksdb.org/) for persistent storage of consensus data (replacing Mysticeti's WAL storage)
- **Transaction Encoding**: [Reed-Solomon-SIMD](https://crates.io/crates/reed-solomon-simd) implementing:
  - Erasure codes over field `F_{2^16}`
  - Fast-Fourier transform-based decoding
  - SIMD instruction optimization for larger shards

Like other consensus testbed, our prototype focuses solely on consensus performance measurement without execution or ledger storage components.

## Requirements

### Dependencies

Starfish requires the following core dependencies:

- **Rust 1.85+**: For building and running the project
- **Build essentials**: `build-essential`, `libssl-dev`, `pkg-config`
- **Clang tools**: `clang`, `libclang-dev` (for compiling RocksDB and other native dependencies)

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

For more advanced usage scenarios (distributed testing, metrics visualization, etc.), additional tools may be required.

## Quick Start

```bash
# Clone and build
git clone https://github.com/iotaledger/starfish.git
cd ./starfish
cargo build --release
```

### Run local benchmark and output the basic metrics

```bash
cargo run --release --bin starfish -- local-benchmark \
        --committee-size 7 \
        --load 10000 \
        --consensus starfish \
        --num-byzantine-nodes 0 \
        --byzantine-strategy chain-bomb \
        --mimic-extra-latency \
        --duration-secs 100
```

Additional local-benchmark flags:

- `--dissemination-mode <MODE>` — override dissemination strategy
  (`protocol-default`, `pull`, `push-causal`, `push-useful`)
- `--adversarial-latency` — overlay 10s latency on f farthest peers
- `--uniform-latency-ms <FLOAT>` — uniform latency instead of
  AWS RTT table

### Local dryrun with monitoring

The dryrun script launches a Docker-based local testbed with Prometheus and Grafana:

```bash
./scripts/dryrun.sh
```

Configuration via environment variables:

```bash
NUM_VALIDATORS=10 DESIRED_TPS=1000 CONSENSUS=starfish-s \
  NUM_BYZANTINE_NODES=2 BYZANTINE_STRATEGY=random-drop \
  TEST_TIME=3000 ./scripts/dryrun.sh
```

| Variable | Default | Description |
|---|---|---|
| `NUM_VALIDATORS` | 10 | Number of validators (recommend < physical cores, max 128) |
| `DESIRED_TPS` | 1000 | Target transactions per second |
| `CONSENSUS` | starfish-s | Protocol: `starfish`, `starfish-s`, `starfish-l`, `cordial-miners`, `mysticeti` |
| `NUM_BYZANTINE_NODES` | 0 | Must be < `NUM_VALIDATORS / 3` |
| `BYZANTINE_STRATEGY` | random-drop | See [Byzantine strategies](#byzantine-strategies) |
| `TEST_TIME` | 3000 | Duration in seconds |
| `DISSEMINATION_MODE` | push-causal | `protocol-default`, `pull`, `push-causal`, `push-useful` |
| `STORAGE_BACKEND` | rocksdb | `rocksdb` or `tidehunter` |
| `TRANSACTION_MODE` | all_zero | `all_zero` or `random` |
| `ADVERSARIAL_LATENCY` | _(unset)_ | Set to `1` to overlay 10s latency on f farthest peers |
| `UNIFORM_LATENCY_MS` | _(unset)_ | Uniform network latency in ms; overrides AWS RTT table |
| `CLEAN_MONITORING` | 0 | Set to 1 to wipe Prometheus/Grafana data between runs |
| `REMOVE_VOLUMES` | 1 | Set to 0 to preserve RocksDB volumes between runs |
| `PROMETHEUS_PORT` | 9091 | Host port for Prometheus UI |
| `GRAFANA_PORT` | 3001 | Host port for Grafana UI |

Grafana is available at `http://localhost:3001` (admin/admin). Ctrl+C stops validators but preserves the monitoring stack.

### Docker

Build locally:

```bash
docker build -t starfish .
```

Or pull the latest image from GHCR:

```bash
docker pull ghcr.io/iotaledger/starfish:latest
```

Run a local benchmark via Docker:

```bash
docker run --rm starfish local-benchmark \
    --committee-size 7 --load 10000 --consensus starfish \
    --duration-secs 60
```

Pre-built Linux binaries are published as
[nightly releases](https://github.com/iotaledger/starfish/releases/tag/nightly)
(extracted from the Docker image).

### Distributed Testing using Orchestrator

To run tests on a geo-distributed network, look at instructions in [crates/orchestrator/readme.md](./crates/orchestrator/readme.md).

## License

[Apache 2.0](LICENSE)
