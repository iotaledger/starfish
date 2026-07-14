# Starfish and Bluestreak authentication comparison — 40-validator geographic emulation

Date: 2026-07-13–14<br>
Source revisions: `c90f8fb` (original Starfish families), `3562890`
(original Bluestreak), `3a82c04` (ML-DSA-65 extension)<br>
Host: Apple Silicon (`arm64`), macOS 15.7.4<br>
Build: Rust 1.86.0, release profile

## Configuration

- 40 honest validators in one local process
- 1,000 tx/s aggregate offered load (25 tx/s per validator)
- 60-second measurement window
- Protocol-default dissemination: `push-useful` for the Starfish families and
  `pull` for Bluestreak
- One run per configuration
- Geographic latency emulation enabled; no uniform-latency override

The latency harness has ten AWS region profiles. At 40 validators, validator
indices are mapped modulo ten, producing four validators per modeled region.
The RTT values are divided by two to obtain one-way delays and independent
±3% per-message jitter is applied. Base one-way delays range from 0.5 ms to
154.5 ms.

This is a single-machine latency emulation, not a deployment on 40 remote
hosts. All validators share the host's CPU, memory, storage, loopback network,
and kernel socket resources.

In this report, **Sparse-Starfish-Speed means the sparse implementation of
Starfish Speed; it is not Bluestreak.**

Command template:

```text
target/release/starfish local-benchmark \
  --committee-size 40 \
  --load 1000 \
  --consensus <variant> \
  --duration-secs 60
```

## Results

| Protocol | Authentication | Block latency (ms) | E2E latency (ms) | TPS | BPS | Bandwidth out (MB/s) | Bandwidth in (MB/s) | Bandwidth efficiency |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Starfish | Ed25519 | 590.92 | 644.60 | 790.63 | 407.02 | 5.28 | 5.27 | 13.67 |
| Starfish | MAC vector | 592.98 | 646.42 | 792.77 | 393.48 | 5.63 | 5.63 | 14.54 |
| Starfish | ML-DSA-44 | 571.38 | 627.02 | 792.33 | 399.95 | 7.44 | 7.44 | 19.22 |
| Starfish | ML-DSA-65 | 567.80 | 624.50 | 794.25 | 406.15 | 7.81 | 7.81 | 20.15 |
| Starfish Speed | Ed25519 | 712.02 | 843.95 | 794.25 | 338.55 | 4.39 | 4.39 | 11.32 |
| Starfish Speed | MAC vector | 679.67 | 788.67 | 794.10 | 344.63 | 4.68 | 4.67 | 12.06 |
| Starfish Speed | ML-DSA-44 | 648.98 | 733.05 | 794.35 | 354.83 | 6.54 | 6.53 | 16.85 |
| Starfish Speed | ML-DSA-65 | 520.70 | 601.35 | 795.93 | 367.73 | 7.61 | 7.60 | 19.57 |
| Sparse-Starfish-Speed | Ed25519 | 446.98 | 507.93 | 795.08 | 367.70 | 0.85 | 0.85 | 2.19 |
| Sparse-Starfish-Speed | MAC vector | 441.60 | 502.15 | 790.58 | 366.55 | 1.23 | 1.23 | 3.19 |
| Sparse-Starfish-Speed | ML-DSA-44 | 435.23 | 499.48 | 794.33 | 371.28 | 2.38 | 2.38 | 6.14 |
| Sparse-Starfish-Speed | ML-DSA-65 | 434.75 | 495.95 | 788.70 | 377.72 | 2.92 | 2.92 | 7.59 |
| Bluestreak | Ed25519 | 417.65 | 477.93 | 793.48 | 389.53 | 0.59 | 0.59 | 1.53 |
| Bluestreak | MAC vector | 418.95 | 478.07 | 793.38 | 363.75 | 0.99 | 0.99 | 2.56 |
| Bluestreak | ML-DSA-44 | 420.70 | 478.43 | 795.43 | 368.57 | 1.41 | 1.41 | 3.62 |
| Bluestreak | ML-DSA-65 | 421.02 | 479.50 | 796.03 | 364.83 | 1.71 | 1.70 | 4.39 |

All sixteen commands exited successfully after printing their metrics. No
deserialize, socket-buffer, or transport errors were observed during these
runs.

## Relative to Ed25519 within each protocol

| Protocol | Authentication | Block latency | E2E latency | TPS | BPS | Bandwidth out |
|---|---|---:|---:|---:|---:|---:|
| Starfish | MAC vector | +0.3% | +0.3% | +0.3% | -3.3% | +6.6% |
| Starfish | ML-DSA-44 | -3.3% | -2.7% | +0.2% | -1.7% | +40.9% |
| Starfish | ML-DSA-65 | -3.9% | -3.1% | +0.5% | -0.2% | +47.9% |
| Starfish Speed | MAC vector | -4.5% | -6.6% | 0.0% | +1.8% | +6.6% |
| Starfish Speed | ML-DSA-44 | -8.9% | -13.1% | 0.0% | +4.8% | +49.0% |
| Starfish Speed | ML-DSA-65 | -26.9% | -28.7% | +0.2% | +8.6% | +73.3% |
| Sparse-Starfish-Speed | MAC vector | -1.2% | -1.1% | -0.6% | -0.3% | +44.7% |
| Sparse-Starfish-Speed | ML-DSA-44 | -2.6% | -1.7% | -0.1% | +1.0% | +180.0% |
| Sparse-Starfish-Speed | ML-DSA-65 | -2.7% | -2.4% | -0.8% | +2.7% | +243.5% |
| Bluestreak | MAC vector | +0.3% | 0.0% | 0.0% | -6.6% | +67.8% |
| Bluestreak | ML-DSA-44 | +0.7% | +0.1% | +0.2% | -5.4% | +139.0% |
| Bluestreak | ML-DSA-65 | +0.8% | +0.3% | +0.3% | -6.3% | +189.8% |

The lower latency values in some MAC and ML-DSA runs must not be interpreted
as an authentication speedup. These are single, sequential trials without a
randomized order or variance estimates.

## Protocol relative to matching Starfish authentication

| Protocol | Authentication | Block latency | E2E latency | TPS | BPS | Bandwidth out |
|---|---|---:|---:|---:|---:|---:|
| Starfish Speed | Ed25519 | +20.5% | +30.9% | +0.5% | -16.8% | -16.9% |
| Starfish Speed | MAC vector | +14.6% | +22.0% | +0.2% | -12.4% | -16.9% |
| Starfish Speed | ML-DSA-44 | +13.6% | +16.9% | +0.3% | -11.3% | -12.1% |
| Starfish Speed | ML-DSA-65 | -8.3% | -3.7% | +0.2% | -9.5% | -2.6% |
| Sparse-Starfish-Speed | Ed25519 | -24.4% | -21.2% | +0.6% | -9.7% | -83.9% |
| Sparse-Starfish-Speed | MAC vector | -25.5% | -22.3% | -0.3% | -6.8% | -78.2% |
| Sparse-Starfish-Speed | ML-DSA-44 | -23.8% | -20.3% | +0.3% | -7.2% | -68.0% |
| Sparse-Starfish-Speed | ML-DSA-65 | -23.4% | -20.6% | -0.7% | -7.0% | -62.6% |
| Bluestreak | Ed25519 | -29.3% | -25.9% | +0.4% | -4.3% | -88.8% |
| Bluestreak | MAC vector | -29.3% | -26.0% | +0.1% | -7.6% | -82.4% |
| Bluestreak | ML-DSA-44 | -26.4% | -23.7% | +0.4% | -7.8% | -81.0% |
| Bluestreak | ML-DSA-65 | -25.9% | -23.2% | +0.2% | -10.2% | -78.1% |

## Interpretation

- The corrected workload is 1,000 tx/s total, not 4,000 tx/s. The harness
  divides the total evenly, so every validator generates 25 tx/s.
- Authentication choice did not materially affect committed throughput. All
  variants reported 788.70-796.03 TPS, a spread of 0.9% across the complete
  matrix.
- The local harness includes the 12-second connection warm-up in its
  60-second TPS denominator: the default 10 seconds plus 2 seconds for a
  40-validator committee. Roughly 48 seconds therefore submit transactions;
  the measured 788.70-796.03 TPS corresponds to about 986-995 tx/s during the
  active submission window, close to the offered 1,000 tx/s.
- For plain Starfish and Starfish Speed, MAC raises outbound bandwidth by
  6.6% over Ed25519. ML-DSA-44 raises it by 40.9% and 49.0%, while ML-DSA-65
  raises it by 47.9% and 73.3%, respectively.
- Bluestreak's baseline protocol traffic is even leaner. Its MAC vector raises
  outbound bandwidth from 0.59 to 0.99 MB/s (+67.8%), while ML-DSA-44 raises
  it to 1.41 MB/s (+139.0%) and ML-DSA-65 to 1.71 MB/s (+189.8%). Latency and
  throughput remain within 0.8% of its Ed25519 baseline.
- Sparse-Starfish-Speed removes so much baseline protocol traffic that
  authentication bytes become a larger fraction of the remainder. Its MAC
  variant rises from 0.85 to 1.23 MB/s (+44.7%), and ML-DSA-44 rises to
  2.38 MB/s (+180.0%); ML-DSA-65 reaches 2.92 MB/s (+243.5%). The absolute
  traffic remains below every matching non-sparse variant.
- The signature sizes explain the incremental ML-DSA bandwidth: Ed25519 is
  64 bytes, ML-DSA-44 is 2,420 bytes, and ML-DSA-65 is 3,309 bytes. ML-DSA-65
  public keys are 1,952 bytes but are provisioned in the committee config,
  not sent in every block.
- The MAC result is consistent with the current design: direct author block
  streaming carries the full committee-sized MAC vector, while relay and
  synchronization paths carry one recipient tag. Consequently, the remaining
  author-stream authentication cost grows with committee size.
- Bluestreak is the strongest 40-validator result in this local emulation:
  418-421 ms block latency, 478-480 ms end-to-end latency, and
  0.59-1.71 MB/s outbound across the four authentication schemes. Relative
  to matching Sparse-Starfish-Speed authentication, it reduces block latency
  by 3.2-6.6%, end-to-end latency by 3.3-5.9%, and outbound bandwidth by
  19.5-41.4%.
- Starfish Speed alone was slower than plain Starfish at 40 validators even
  though it was faster in the earlier 10-validator experiment. This reversal
  points to a single-host scaling or run-variance effect and needs randomized,
  repeated trials before it is treated as a protocol conclusion.

## Caveats

- There is one run per configuration and no randomized run order, warm-up
  exclusion, or confidence interval. Relative authentication bandwidth is the
  clearest result; latency differences need repeated trials.
- The Bluestreak runs were made one day after the Starfish-family runs using
  the same host and benchmark configuration but a newer source revision.
- The ML-DSA-65 rows were appended after the original matrix on source
  revision `3a82c04`; they use the same host, release profile, and command
  template.
- Four validators share each synthetic region profile. This produces the AWS
  delay distribution but does not model independent machines or real WAN
  bandwidth constraints.
- The 40 validators form a full mesh of 1,560 directed peer relationships and
  use one RocksDB instance each. Host contention is part of the measurement.
- The progress window starts before transaction generation, which explains
  why displayed TPS is below the aggregate offered rate.
