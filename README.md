# Starfish

[![rustc](https://img.shields.io/badge/rustc-1.78+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

The code in this repository is a prototype of Starfish. Two versions are available:
- `starfish-push`: Theory-aligned version
  - Higher bandwidth usage (up to 4x)
  - Better latency guarantees with Byzantine nodes
- `starfish`: Production-optimized version
  - Lower bandwidth usage in happy case
  - Latency increased up to 3 times with Byzantine nodes

Also supports other BFT protocols based on uncertified DAGs:
- [Mysticeti](https://www.cs.cornell.edu/~babel/papers/mysticeti.pdf)
- [Cordial Miners](https://arxiv.org/pdf/2205.09174)

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

# Run test with default settings
cd scripts
./dryrun.sh
```

### Available Parameters
- `NUM_VALIDATORS`: Validator count (default: 5)
- `DESIRED_TPS`: Target transactions/sec (default: 15000)
- `CONSENSUS`: Protocol (mysticeti, starfish, cordial-miners, starfish-push)
- `NUM_BYZANTINE_NODES`: Byzantine nodes (default: 0)
- `BYZANTINE_STRATEGY`: Attack strategy

Monitor at: http://localhost:3000  
Credentials: admin/supers3cret

## License
[Apache 2.0](LICENSE)
```