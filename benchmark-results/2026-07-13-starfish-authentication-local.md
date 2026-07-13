# Starfish authentication comparison — local Apple Silicon

Date: 2026-07-13  
Source revision: `8a3bded` plus the Sparse authentication changes committed with this report<br>
Host: Apple Silicon (`arm64`), macOS 15.7.4  
Build: Rust 1.86.0, release profile

## Configuration

- 10 honest validators in one local process
- 1,000 tx/s offered load (100 tx/s per validator)
- 20-second measurement window
- Uniform 0 ms added network latency
- Default protocol dissemination mode (`push-useful` for all three protocols)
- One run per configuration

Command template:

```text
target/release/starfish local-benchmark \
  --committee-size 10 \
  --load 1000 \
  --consensus <variant> \
  --duration-secs 20 \
  --uniform-latency-ms 0
```

## Results

| Protocol | Authentication | Block latency (ms) | E2E latency (ms) | TPS | BPS | Bandwidth out (MB/s) | Bandwidth in (MB/s) | Bandwidth efficiency |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Starfish | Ed25519 | 12.1 | 13.9 | 446.50 | 4,573.30 | 14.33 | 14.30 | 65.74 |
| Starfish | MAC vector | 12.8 | 14.8 | 433.60 | 4,494.05 | 14.04 | 14.01 | 66.34 |
| Starfish | ML-DSA-44 | 15.7 | 18.0 | 432.50 | 4,125.75 | 57.11 | 57.08 | 270.44 |
| Starfish Speed | Ed25519 | 10.2 | 12.3 | 442.75 | 4,201.30 | 14.61 | 14.58 | 67.60 |
| Starfish Speed | MAC vector | 9.4 | 11.4 | 439.15 | 4,114.10 | 14.12 | 14.09 | 65.85 |
| Starfish Speed | ML-DSA-44 | 13.4 | 17.4 | 453.80 | 2,868.60 | 39.84 | 39.82 | 179.82 |
| Sparse-Starfish-Speed | Ed25519 | 5.5 | 10.8 | 430.00 | 4,867.50 | 8.99 | 8.96 | 42.84 |
| Sparse-Starfish-Speed | MAC vector | 5.2 | 10.5 | 430.75 | 5,211.95 | 9.73 | 9.69 | 46.25 |
| Sparse-Starfish-Speed | ML-DSA-44 | 5.5 | 10.1 | 440.05 | 4,335.90 | 37.85 | 37.82 | 176.16 |

## Relative to Ed25519 within each protocol

| Protocol | Authentication | Block latency | E2E latency | TPS | BPS | Bandwidth out |
|---|---|---:|---:|---:|---:|---:|
| Starfish | MAC vector | +5.8% | +6.5% | -2.9% | -1.7% | -2.0% |
| Starfish | ML-DSA-44 | +29.8% | +29.5% | -3.1% | -9.8% | +298.5% |
| Starfish Speed | MAC vector | -7.8% | -7.3% | -0.8% | -2.1% | -3.4% |
| Starfish Speed | ML-DSA-44 | +31.4% | +41.5% | +2.5% | -31.7% | +172.7% |
| Sparse-Starfish-Speed | MAC vector | -5.5% | -2.8% | +0.2% | +7.1% | +8.2% |
| Sparse-Starfish-Speed | ML-DSA-44 | 0.0% | -6.5% | +2.3% | -10.9% | +321.0% |

## Starfish Speed relative to Starfish

| Authentication | Block latency | E2E latency | TPS | BPS | Bandwidth out |
|---|---:|---:|---:|---:|---:|
| Ed25519 | -15.7% | -11.5% | -0.8% | -8.1% | +2.0% |
| MAC vector | -26.6% | -23.0% | +1.3% | -8.5% | +0.6% |
| ML-DSA-44 | -14.6% | -3.3% | +4.9% | -30.5% | -30.2% |

## Sparse-Starfish-Speed relative to Starfish

| Authentication | Block latency | E2E latency | TPS | BPS | Bandwidth out |
|---|---:|---:|---:|---:|---:|
| Ed25519 | -54.5% | -22.3% | -3.7% | +6.4% | -37.3% |
| MAC vector | -59.4% | -29.1% | -0.7% | +16.0% | -30.7% |
| ML-DSA-44 | -65.0% | -43.9% | +1.7% | +5.1% | -33.7% |

## Interpretation

- The Starfish and Starfish Speed MAC variants remained close to Ed25519: TPS
  was within 3%, BPS within 2.1%, and bandwidth was slightly lower in this
  sample. The latency changes are small enough that repeated runs are needed
  before treating their sign as meaningful.
- ML-DSA-44 materially increased latency and bandwidth. Its signature is 2,420
  bytes, versus 64 bytes for Ed25519. Outbound bandwidth increased about 4.0x
  for Starfish, 2.7x for Starfish Speed, and 4.2x for Sparse-Starfish-Speed.
- Starfish Speed with ML-DSA-44 produced 31.7% fewer blocks than its Ed25519
  variant while committing 2.5% more transactions. This indicates more
  transactions per block in this run; it should not be read as evidence that
  ML-DSA improves throughput without repeated trials.
- Against matching Starfish authentication variants, Starfish Speed had lower
  latency in all three samples and essentially equal TPS for Ed25519 and MAC.
  Its ML-DSA-44 run used about 30% less bandwidth, alongside about 30% fewer
  blocks, than Starfish ML-DSA-44.
- Sparse-Starfish-Speed preserved roughly the same TPS as plain Starfish while
  reducing outbound bandwidth by 31-37% and block latency by 55-65% across the
  three authentication schemes. Its lean headers therefore remain beneficial
  with either signatures or MACs in this local sample.
- Sparse MAC remained close to Sparse Ed25519: TPS differed by 0.2%, while
  outbound bandwidth was 8.2% higher. Sparse ML-DSA-44 used 4.2x the outbound
  bandwidth of Sparse Ed25519 despite Sparse's lower protocol overhead.
- All variants achieved roughly 430–454 TPS from the 1,000 tx/s offered load.
  Ten validators share one laptop and therefore contend for the same CPU,
  storage, and network stack. These results are useful for directional local
  comparison, not distributed capacity claims.

## Benchmark harness fix

The previous local benchmark shutdown aborted validator tasks and immediately
deleted their RocksDB directories. On macOS this left benchmark parents stuck
in an uninterruptible exiting state. The harness now uses a `JoinSet`, aborts
all validator tasks, drains them completely, and only then removes storage.
The validation run and all nine measured protocol/authentication combinations
exited normally.

During the first Sparse MAC run, the receiver-side transport guard exposed a
round-gap response that still carried full MAC vectors. The sender now routes
round-gap blocks through the same recipient-tag preparation used by relay and
missing-parent paths. The rejected run was discarded; the Sparse MAC row above
is the clean rerun, which emitted no transport rejections.
