# Authentication comparison — 60-validator geographic emulation

Date: 2026-07-14<br>
Source revision: `4553e5e`<br>
Host: Apple Silicon (`arm64`), macOS 15.7.4<br>
Build: Rust 1.86.0, release profile

## Configuration

- 60 honest validators in one local process
- 600 tx/s aggregate offered load (exactly 10 tx/s per validator)
- 60-second measurement window
- Protocol-default dissemination: `push-useful` for the Starfish families and
  `pull` for Bluestreak
- One run per configuration
- Geographic latency emulation enabled; no uniform-latency override

The harness has ten AWS region profiles. Validator indices map to profiles
modulo ten, so this experiment models six validators per region. RTT values
are divided by two to obtain one-way delays and independent ±3% per-message
jitter is applied. Base one-way delays range from 0.5 ms to 154.5 ms.

This is a single-machine latency emulation, not a 60-host deployment. The
validators share CPU, memory, storage, loopback networking, and kernel socket
resources. They form 3,540 directed peer relationships and use one RocksDB
instance each.

Command template:

```text
target/release/starfish local-benchmark \
  --committee-size 60 \
  --load 600 \
  --consensus <variant> \
  --duration-secs 60
```

## Results

| Protocol | Authentication | Block latency (ms) | E2E latency (ms) | TPS | BPS | Bandwidth out (MB/s) | Bandwidth in (MB/s) | Bandwidth efficiency |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Starfish | Ed25519 | 664.45 | 728.77 | 444.30 | 515.02 | 8.59 | 8.58 | 39.59 |
| Starfish | MAC vector | 680.68 | 753.42 | 414.87 | 449.23 | 8.35 | 8.34 | 41.21 |
| Starfish | ML-DSA-44 | 849.38 | 937.02 | 427.77 | 417.95 | 9.72 | 9.71 | 46.53 |
| Starfish Speed | Ed25519 | 592.13 | 673.87 | 460.37 | 467.12 | 6.63 | 6.62 | 29.49 |
| Starfish Speed | MAC vector | 670.80 | 783.93 | 430.95 | 439.30 | 7.30 | 7.30 | 34.70 |
| Starfish Speed | ML-DSA-44 | 641.70 | 726.03 | 433.63 | 461.57 | 11.06 | 11.05 | 52.22 |
| Sparse-Starfish-Speed | Ed25519 | 467.70 | 525.98 | 466.22 | 535.57 | 0.88 | 0.88 | 3.87 |
| Sparse-Starfish-Speed | MAC vector | 467.67 | 528.23 | 466.62 | 551.88 | 1.84 | 1.84 | 8.08 |
| Sparse-Starfish-Speed | ML-DSA-44 | 464.87 | 526.97 | 467.07 | 528.88 | 2.98 | 2.98 | 13.08 |
| Bluestreak | Ed25519 | 422.53 | 480.58 | 468.22 | 551.08 | 0.52 | 0.52 | 2.28 |
| Bluestreak | MAC vector | 421.62 | 480.37 | 467.63 | 545.72 | 1.47 | 1.46 | 6.42 |
| Bluestreak | ML-DSA-44 | 422.72 | 481.70 | 467.88 | 547.13 | 1.75 | 1.75 | 7.67 |

All twelve commands exited successfully after emitting their metrics. No
authentication, deserialize, socket-buffer, or transport errors were observed.

## Warm-up-adjusted offered-rate utilization

The transaction generators wait 13 seconds before submitting: the default
10-second delay plus 3 seconds for a 60-validator committee. The displayed TPS
uses the complete 60-second window, leaving approximately 47 active submission
seconds. The following values estimate the active rate as `TPS × 60 / 47`.

| Protocol | Authentication | Estimated active TPS | Offered rate sustained |
|---|---|---:|---:|
| Starfish | Ed25519 | 567.19 | 94.5% |
| Starfish | MAC vector | 529.62 | 88.3% |
| Starfish | ML-DSA-44 | 546.09 | 91.0% |
| Starfish Speed | Ed25519 | 587.71 | 98.0% |
| Starfish Speed | MAC vector | 550.15 | 91.7% |
| Starfish Speed | ML-DSA-44 | 553.57 | 92.3% |
| Sparse-Starfish-Speed | Ed25519 | 595.17 | 99.2% |
| Sparse-Starfish-Speed | MAC vector | 595.69 | 99.3% |
| Sparse-Starfish-Speed | ML-DSA-44 | 596.26 | 99.4% |
| Bluestreak | Ed25519 | 597.73 | 99.6% |
| Bluestreak | MAC vector | 596.97 | 99.5% |
| Bluestreak | ML-DSA-44 | 597.29 | 99.5% |

## Relative to Ed25519 within each protocol

| Protocol | Authentication | Block latency | E2E latency | TPS | BPS | Bandwidth out |
|---|---|---:|---:|---:|---:|---:|
| Starfish | MAC vector | +2.4% | +3.4% | -6.6% | -12.8% | -2.8% |
| Starfish | ML-DSA-44 | +27.8% | +28.6% | -3.7% | -18.8% | +13.2% |
| Starfish Speed | MAC vector | +13.3% | +16.3% | -6.4% | -6.0% | +10.1% |
| Starfish Speed | ML-DSA-44 | +8.4% | +7.7% | -5.8% | -1.2% | +66.8% |
| Sparse-Starfish-Speed | MAC vector | 0.0% | +0.4% | +0.1% | +3.0% | +109.1% |
| Sparse-Starfish-Speed | ML-DSA-44 | -0.6% | +0.2% | +0.2% | -1.2% | +238.6% |
| Bluestreak | MAC vector | -0.2% | 0.0% | -0.1% | -1.0% | +182.7% |
| Bluestreak | ML-DSA-44 | 0.0% | +0.2% | -0.1% | -0.7% | +236.5% |

Raw bandwidth can fall despite a larger authentication proof when a run
produces fewer blocks, as in plain Starfish MAC. The bandwidth-efficiency
metric—the ratio of bytes sent to committed transaction-payload bytes—rises
from 39.59 to 41.21 and captures the normalized increase.

## Interpretation

- Sixty validators are feasible on this machine at a 600 tx/s aggregate
  offered load, but headroom depends strongly on the protocol family.
- Sparse-Starfish-Speed and Bluestreak sustain 99.2-99.6% of the active offered
  rate for every authentication scheme. Their latency and throughput vary by
  at most 0.6% and 0.2%, respectively, within each family.
- Plain Starfish sustains 88.3-94.5% of the active offered rate, while
  Starfish Speed sustains 91.7-98.0%. Their authentication comparisons are
  therefore partly measurements of shared-host contention. In particular,
  plain Starfish ML-DSA-44 has 27.8% higher block latency than its Ed25519 run.
- Bluestreak has the lowest latency and absolute bandwidth across every
  authentication scheme: 422-423 ms block latency, 480-482 ms end-to-end
  latency, and 0.52-1.75 MB/s outbound.
- Relative to matching Sparse-Starfish-Speed authentication, Bluestreak lowers
  block latency by 9.1-9.8%, end-to-end latency by 8.6-9.1%, and outbound
  bandwidth by 20.1-41.3%, with nearly identical throughput.
- At 60 validators, a full author MAC vector contains 60 × 32 = 1,920 bytes,
  compared with a 64-byte Ed25519 signature and a 2,420-byte ML-DSA-44
  signature. Relays and synchronization responses still carry only one
  32-byte recipient tag. Because Bluestreak and Sparse-Starfish-Speed remove
  most other traffic, these authentication bytes produce large percentages
  while their absolute bandwidth remains well below the denser protocols.
- For repeatable all-protocol authentication comparisons on this single host,
  40 validators remains the safer configuration. Sixty validators is a useful
  stress configuration and a clean operating point for the sparse and
  Bluestreak families; denser families should move to multiple machines for
  stronger conclusions.

## Caveats

- There is one sequential run per configuration, with no randomized order or
  confidence interval. Host scheduling and thermal state can affect results.
- The 600 tx/s load differs from the earlier 40-validator 1,000 tx/s matrix;
  the two experiments should not be treated as a pure committee-size scaling
  comparison.
- Six validators share each synthetic AWS region profile. The harness injects
  the delay distribution but does not model independent machines or WAN
  bandwidth constraints.
- Displayed TPS includes the 13-second startup delay. Warm-up-adjusted TPS is
  derived rather than measured in a separately gated metrics window.
