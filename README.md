# Starfish

[![rustc](https://img.shields.io/badge/rustc-1.78+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

## Overview

The code in this repository is a prototype of Starfish, a partially synchronous BFT protocol in which validators employ an uncertified DAG. Two versions are available:
- **`starfish`**: Theory-aligned version
  - Higher bandwidth usage (up to 4x)
  - Better latency guarantees with Byzantine nodes under low load

- **`starfish-pull`**: More scalable version
  - Lower bandwidth usage in happy case
  - Better handling of higher throughput and larger number of validators

The repository also supports other partially synchronous uncertified DAG-based consensus protocols:
- **`mysticeti`**: Implementation of [Mysticeti](https://www.cs.cornell.edu/~babel/papers/mysticeti.pdf)
- **`cordial-miners`**: Implementation of [Cordial Miners](https://arxiv.org/pdf/2205.09174)

## Key Features of Starfish

- Starfish is a Byzantine Fault Tolerant protocol capable of tolerating up to 1/3 of Byzantine nodes in a partially syncrhonous network.
- It uses push-based dissemination strategy that incorporates Reed-Solomon coding for the transction data to amortize communication costs
- It provides a linear amortized communication complexity for a large enough transaction load
- It achieves high throughput (~200-300K tx/sec for 10-100 validators) and subsecond end-to-end latency for up to 150K tx/sec 

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
- **Build essentials**: build-essential, libssl-dev, pkg-config
- **Clang tools**: clang, libclang-dev (for compiling RocksDB and other native dependencies)

Note: RocksDB and its dependencies will be automatically compiled during the build process.

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
### Local dryrun with availability to look at metrics
```bash
./scripts/dryrun.sh
```
### Distributed Testing using Orchestrator

To run tests on a geo-distributed network, look at instructions in `./crates/orchestrator/readme.md`


## License
[Apache 2.0](LICENSE)