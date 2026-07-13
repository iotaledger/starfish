# Starfish authentication comparison — 60-second geographic emulation

Date: 2026-07-13<br>
Source revision: `d3f57c2`<br>
Host: Apple Silicon (`arm64`), macOS 15.7.4<br>
Build: Rust 1.86.0, release profile

## Configuration

- 10 honest validators in one local process
- 1,000 tx/s offered load (100 tx/s per validator)
- 60-second measurement window
- Default `push-useful` dissemination for all three protocols
- One run per configuration
- Geographic latency emulation enabled; no uniform-latency override

The ten validators map in order to `us-east-1`, `us-west-1`,
`ca-central-1`, `eu-west-1`, `eu-south-1`, `eu-north-1`, `sa-east-1`,
`ap-south-1`, `ap-southeast-1`, and `ap-northeast-1`. The harness converts
its AWS RTT table to one-way delay by dividing each cell by two, then applies
independent ±3% per-message jitter. The resulting base one-way delays range
from 0.5 ms within a region to 154.5 ms between the most distant pair.

This is a single-machine latency emulation, not a deployment on ten remote
hosts. CPU, storage, and the physical network stack remain shared.

Command template:

```text
target/release/starfish local-benchmark \
  --committee-size 10 \
  --load 1000 \
  --consensus <variant> \
  --duration-secs 60
```

## Results

| Protocol | Authentication | Block latency (ms) | E2E latency (ms) | TPS | BPS | Bandwidth out (MB/s) | Bandwidth in (MB/s) | Bandwidth efficiency |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Starfish | Ed25519 | 553.4 | 603.7 | 816.25 | 100.05 | 0.49 | 0.49 | 1.23 |
| Starfish | MAC vector | 559.7 | 612.1 | 815.75 | 94.93 | 0.53 | 0.53 | 1.34 |
| Starfish | ML-DSA-44 | 554.1 | 604.2 | 814.70 | 97.00 | 0.76 | 0.76 | 1.92 |
| Starfish Speed | Ed25519 | 460.6 | 519.7 | 814.83 | 94.33 | 0.51 | 0.51 | 1.29 |
| Starfish Speed | MAC vector | 458.6 | 522.6 | 816.08 | 95.18 | 0.54 | 0.54 | 1.35 |
| Starfish Speed | ML-DSA-44 | 457.7 | 518.5 | 817.83 | 94.13 | 0.77 | 0.77 | 1.93 |
| Sparse-Starfish-Speed | Ed25519 | 417.6 | 485.1 | 818.25 | 95.42 | 0.45 | 0.45 | 1.13 |
| Sparse-Starfish-Speed | MAC vector | 418.7 | 483.5 | 816.25 | 92.70 | 0.47 | 0.47 | 1.18 |
| Sparse-Starfish-Speed | ML-DSA-44 | 420.3 | 486.9 | 817.95 | 92.85 | 0.71 | 0.71 | 1.78 |

## Relative to Ed25519 within each protocol

| Protocol | Authentication | Block latency | E2E latency | TPS | BPS | Bandwidth out |
|---|---|---:|---:|---:|---:|---:|
| Starfish | MAC vector | +1.1% | +1.4% | -0.1% | -5.1% | +8.2% |
| Starfish | ML-DSA-44 | +0.1% | +0.1% | -0.2% | -3.0% | +55.1% |
| Starfish Speed | MAC vector | -0.4% | +0.6% | +0.2% | +0.9% | +5.9% |
| Starfish Speed | ML-DSA-44 | -0.6% | -0.2% | +0.4% | -0.2% | +51.0% |
| Sparse-Starfish-Speed | MAC vector | +0.3% | -0.3% | -0.2% | -2.9% | +4.4% |
| Sparse-Starfish-Speed | ML-DSA-44 | +0.6% | +0.4% | 0.0% | -2.7% | +57.8% |

## Protocol relative to matching Starfish authentication

| Protocol | Authentication | Block latency | E2E latency | TPS | BPS | Bandwidth out |
|---|---|---:|---:|---:|---:|---:|
| Starfish Speed | Ed25519 | -16.8% | -13.9% | -0.2% | -5.7% | +4.1% |
| Starfish Speed | MAC vector | -18.1% | -14.6% | 0.0% | +0.3% | +1.9% |
| Starfish Speed | ML-DSA-44 | -17.4% | -14.2% | +0.4% | -3.0% | +1.3% |
| Sparse-Starfish-Speed | Ed25519 | -24.5% | -19.6% | +0.2% | -4.6% | -8.2% |
| Sparse-Starfish-Speed | MAC vector | -25.2% | -21.0% | +0.1% | -2.3% | -11.3% |
| Sparse-Starfish-Speed | ML-DSA-44 | -24.1% | -19.4% | +0.4% | -4.3% | -6.6% |

## Interpretation

- Authentication did not materially change throughput or latency under the
  emulated wide-area delays. Within each protocol, TPS differed by at most
  0.4%, block latency by at most 1.1%, and end-to-end latency by at most 1.4%.
  These small changes are below what should be interpreted without repeated
  trials and variance estimates.
- MAC vectors increased outbound bandwidth by 4.4-8.2% relative to Ed25519,
  while ML-DSA-44 increased it by 51.0-57.8%. At the geo-limited block rate,
  payload and protocol traffic dominate more of the total than in the
  zero-latency runs, so ML-DSA's relative bandwidth multiplier is smaller.
- Starfish Speed reduced block latency by 16.8-18.1% and end-to-end latency by
  13.9-14.6% against matching plain-Starfish authentication, with essentially
  identical TPS.
- Sparse-Starfish-Speed reduced block latency by 24.1-25.2%, end-to-end
  latency by 19.4-21.0%, and outbound bandwidth by 6.6-11.3% against matching
  plain-Starfish authentication, again with essentially identical TPS.
- All variants committed roughly 815-818 TPS from the offered 1,000 tx/s.
  This experiment measures a local machine under injected network delay; it
  does not establish capacity on physically distributed hardware.

## Caveats

- There is one run per configuration and no warm-up exclusion, so these are
  directional comparisons rather than confidence intervals.
- The reported metrics were emitted before shutdown. Validator task abortion
  logs expected `JoinError::Cancelled` messages afterward. Two runs also
  printed a macOS `pthread lock` teardown error after their metrics; process
  and benchmark-directory checks showed no active or overlapping benchmark.
  The shutdown path should still be hardened before unattended batch runs.
