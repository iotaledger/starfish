# Starfish

[![rustc](https://img.shields.io/badge/rustc-1.78+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

## Overview

The code in this repository is a prototype of Starfish,
a partially synchronous BFT protocol in which validators employ an uncertified DAG.
The theoretical description of Starfish is available
at https://eprint.iacr.org/2025/567.

Three versions of Starfish are available in this repository:

- **`starfish`**: Theory-aligned version
  - Higher bandwidth usage (up to 4x)
  - Better latency guarantees with Byzantine nodes under low load

- **`starfish-pull`**: More scalable version
  - Lower bandwidth usage in happy case
  - Better handling of higher throughput and larger number of validators

- **`starfish-s`**: Strong-vote optimistic variant
  - Uses strong votes for optimistic transaction sequencing
  - Lower latency when validators hold full leader payloads

The repository also supports other partially synchronous uncertified DAG-based consensus protocols:

- **`mysticeti`**: Implementation of [Mysticeti](https://www.cs.cornell.edu/~babel/papers/mysticeti.pdf).
Validators use a bandwidth efficient pull-based block dissemination strategy:
they push their own blocks and request the peers about missing ancestors only. A scalable BFT protocol.
- **`cordial-miners`**: Implementation of [Cordial Miners](https://arxiv.org/pdf/2205.09174).
Validators use a push-based block dissemination strategy,
pushing all unknown history of blocks to their peers.
Due to the push strategy, Cordial Miners can tolerate Byzantine attacks,
but it is overall a less scalable solution.

## Key Features of Starfish

- Starfish is a Byzantine Fault Tolerant protocol capable of tolerating up to 1/3 of Byzantine nodes in a partially synchronous network.
- It uses push-based dissemination strategy that incorporates Reed-Solomon coding for the transaction data to amortize communication costs
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

- **Rust 1.78+**: For building and running the project
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

### Local dryrun with monitoring

The dryrun script launches a Docker-based local testbed with Prometheus and Grafana:

```bash
./scripts/dryrun.sh
```

Configuration via environment variables:

```bash
NUM_VALIDATORS=10 DESIRED_TPS=100 CONSENSUS=starfish-s \
  NUM_BYZANTINE_NODES=2 BYZANTINE_STRATEGY=random-drop \
  TEST_TIME=300 ./scripts/dryrun.sh
```

| Variable | Default | Description |
|---|---|---|
| `NUM_VALIDATORS` | 10 | Number of validators (recommend < physical cores, max 128) |
| `DESIRED_TPS` | 100 | Target transactions per second |
| `CONSENSUS` | starfish | Protocol: `starfish`, `starfish-s`, `starfish-pull`, `cordial-miners`, `mysticeti` |
| `NUM_BYZANTINE_NODES` | 2 | Must be < `NUM_VALIDATORS / 3` |
| `BYZANTINE_STRATEGY` | random-drop | See [Byzantine strategies](#byzantine-strategies) |
| `TEST_TIME` | 300 | Duration in seconds |
| `UNIFORM_LATENCY_MS` | _(unset)_ | Uniform network latency in ms; overrides AWS RTT table |
| `CLEAN_MONITORING` | 0 | Set to 1 to wipe Prometheus/Grafana data between runs |
| `REMOVE_VOLUMES` | 1 | Set to 0 to preserve RocksDB volumes between runs |

Grafana is available at `http://localhost:3000` (admin/admin). Ctrl+C stops validators but preserves the monitoring stack.

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
