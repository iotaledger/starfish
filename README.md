# Starfish

[![rustc](https://img.shields.io/badge/rustc-1.78+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

The code in this repository is a prototype of Starfish. Two versions are available:
- `starfish`: Theory-aligned version
  - Higher bandwidth usage (up to 4x)
  - Better latency guarantees with Byzantine nodes
- `starfish-pull`: More scalable version
  - Lower bandwidth usage in happy case
  - Handling of higher throughput
  - Latency increased up to 3 times with Byzantine nodes

The repository supports other partially synchronous uncertified DAG-based BFT protocols:
- `mysticeti`: [Mysticeti](https://www.cs.cornell.edu/~babel/papers/mysticeti.pdf)
- `cordial-miners`: [Cordial Miners](https://arxiv.org/pdf/2205.09174)

The goal of Starfish is to mitigate Byzantine behavior, ensure consensus liveness, and provide linear communication complexity with validator number.

## Requirements

### Mac
```bash
# Install dependencies
brew install rust docker tmux bc

# Enable Docker Desktop
```

### Ubuntu
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Docker and tools
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo apt-get install -y tmux bc

# Setup Docker permissions
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker
```

## Quick Start

```bash
# Clone and build
git clone <repo>
cd <repo>
cargo build --release


# Run local benchmark and see the basic metrics
cargo run --release --bin starfish -- local-benchmark \
        --committee-size 7 \
        --load 10000 \
        --consensus starfish \
        --num-byzantine-nodes 0 \
        --byzantine-strategy chain-bomb \
        --mimic-extra-latency \
        --duration-secs 100


# Local dryrun with availability to look at metrics
cd scripts
./dryrun.sh
```
Monitor at: http://localhost:3000  
Credentials: admin/admin

## License
[Apache 2.0](LICENSE)
```