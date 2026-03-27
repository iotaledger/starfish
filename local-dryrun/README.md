# Local Dryrun

Docker-based local testbed with Prometheus and Grafana monitoring.
Builds the `starfish` Docker image, generates a `docker-compose.yml`
with one container per validator, and runs the experiment for the
configured duration.

## Prerequisites

- Docker (started automatically on macOS / systemd)

## Usage

```bash
./local-dryrun/dryrun.sh
```

```bash
NUM_NODES=10 DESIRED_TPS=1000 CONSENSUS=starfish \
  ./local-dryrun/dryrun.sh
```

## Environment Variables

### Core

| Variable | Default | Description |
|---|---|---|
| `NUM_NODES` | `10` | Number of validators (1--256, recommend < physical cores) |
| `DESIRED_TPS` | `1000` | Target transactions per second (split evenly across nodes) |
| `CONSENSUS` | `bluestreak` | Consensus protocol (see below) |
| `TEST_TIME` | `3000` | Experiment duration in seconds |

Supported `CONSENSUS` values: `starfish`, `starfish-speed`,
`starfish-bls`, `cordial-miners`, `mysticeti`, `sailfish-pp`,
`bluestreak`, `mysticeti-bls`.

### Protocol Tuning

| Variable | Default | Description |
|---|---|---|
| `DISSEMINATION_MODE` | `protocol-default` | `protocol-default`, `pull`, `push-causal`, `push-useful` |
| `STORAGE_BACKEND` | `rocksdb` | `rocksdb` or `tidehunter` |
| `TRANSACTION_MODE` | `random` | `all_zero` or `random` |
| `COMPRESS_NETWORK` | *(auto)* | `1` to enable lz4 compression, `0` to disable. Auto-enabled when `TRANSACTION_MODE=random` |

### Byzantine Fault Testing

| Variable | Default | Description |
|---|---|---|
| `NUM_BYZANTINE_NODES` | `1` | Must be < `NUM_NODES / 3` |
| `BYZANTINE_STRATEGY` | `equivocating-chains-bomb` | See strategies below |

Strategies: `timeout-leader`, `leader-withholding`,
`equivocating-chains`, `equivocating-two-chains`, `chain-bomb`,
`equivocating-chains-bomb`, `random-drop`.

### Network Simulation

| Variable | Default | Description |
|---|---|---|
| `ADVERSARIAL_LATENCY` | *(unset)* | Set to `1` to overlay 10 s latency on f farthest peers |
| `UNIFORM_LATENCY_MS` | *(unset)* | Uniform latency in ms; overrides the AWS RTT table |

### Docker / Infrastructure

| Variable | Default | Description |
|---|---|---|
| `REMOVE_VOLUMES` | `1` | Set to `0` to preserve RocksDB volumes between runs |
| `CLEAN_MONITORING` | `0` | Set to `1` to wipe Prometheus/Grafana data |
| `PROMETHEUS_PORT` | `9091` | Host port for Prometheus UI |
| `GRAFANA_PORT` | `3001` | Host port for Grafana UI |
| `COMPOSE_PROJECT_NAME` | `starfish-dryrun` | Docker Compose project name |
| `BASE_IP` | *(auto)* | Base IPv4 address for validator containers |
| `SUBNET` | *(auto)* | Docker network subnet (CIDR, e.g. `172.28.0.0/23`) |

## Monitoring

- Grafana: `http://localhost:3001` (admin / admin)
- Prometheus: `http://localhost:9091`

Ctrl+C stops validators but preserves the monitoring stack. To stop
everything:

```bash
docker compose -p starfish-dryrun \
  -f local-dryrun/data/docker-compose.yml down
```

## Examples

```bash
# Starfish with 20 validators, high load
NUM_NODES=10 DESIRED_TPS=10000 CONSENSUS=starfish \
  ./local-dryrun/dryrun.sh

# Mysticeti with tidehunter storage
NUM_NODES=7 CONSENSUS=mysticeti STORAGE_BACKEND=tidehunter \
  ./local-dryrun/dryrun.sh

# Byzantine fault testing
NUM_NODES=10 NUM_BYZANTINE_NODES=3 \
  BYZANTINE_STRATEGY=chain-bomb CONSENSUS=starfish-speed \
  ./local-dryrun/dryrun.sh

# Uniform latency simulation
NUM_NODES=10 UNIFORM_LATENCY_MS=100 CONSENSUS=bluestreak \
  ./local-dryrun/dryrun.sh
```
