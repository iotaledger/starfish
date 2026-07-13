# Local validator-count scaling probe

Date: 2026-07-13<br>
Source revision: `dee67ee`<br>
Host: Apple Silicon (`arm64`), macOS 15.7.4, 64 GiB RAM, 16 logical CPU cores

## Purpose

Find a practical committee-size limit for geographic latency emulation on one
machine. Offered load stays at 100 tx/s per validator. The 20-80-validator
probes run for 30 seconds under the AWS RTT latency model. The 10-validator
row is the earlier 60-second baseline and is included only for orientation.

## Sparse-Starfish-Speed MAC results

| Validators | Offered load | Duration | Block latency (ms) | E2E latency (ms) | TPS | BPS | Outbound (MB/s) | Outcome |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 10 | 1,000 | 60 s | 418.7 | 483.5 | 816.25 | 92.70 | 0.47 | Clean baseline |
| 20 | 2,000 | 30 s | 435.85 | 501.05 | 1,240.83 | 191.67 | 0.88 | Clean |
| 40 | 4,000 | 30 s | 461.45 | 545.75 | 2,336.33 | 364.13 | 1.96 | Clean |
| 64 | 6,400 | 30 s | 480.42 | 540.67 | 3,435.23 | 591.83 | 3.47 | Clean, near resource saturation |
| 80 | 8,000 | 30 s | 662.36 | 752.25 | 2,238.30 | 470.77 | 2.86 | Unhealthy: socket-buffer and decode errors |

During the active 64-validator run, the process reached about 1,032% CPU
(roughly 10 cores) and 17.7 GiB resident memory. At 80 validators the network
failed to establish and sustain the full mesh reliably: the run emitted
deserialization warnings and repeated macOS `No buffer space available`
errors. Its throughput regression and latency jump therefore mark it as an
invalid benchmark configuration on this host.

## Common-size check with plain Starfish MAC

| Validators | Offered load | Duration | Block latency (ms) | E2E latency (ms) | TPS | BPS | Outbound (MB/s) | Cancelled reconstructions |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 40 | 4,000 | 30 s | 596.08 | 650.00 | 2,331.33 | 366.10 | 5.71 | 184 |

Plain Starfish completed cleanly at 40 validators but used about 2.9x the
outbound bandwidth of Sparse-Starfish-Speed MAC at the same committee size.
It therefore provides the more conservative limit for a matrix that compares
all protocol families.

## Limits and recommendation

- The hard code limit is 512 validators (`MAX_COMMITTEE_SIZE`). This is a type
  and data-structure bound, not a realistic single-machine target.
- The process file-descriptor limit is 1,048,575, and benchmark ports remain
  well within `u16` even at 512 validators. Neither is the first constraint.
- The local network is a full mesh, so peer relationships grow as `n(n-1)`:
  1,560 at 40 validators, 4,032 at 64, and 6,320 at 80. Each validator also
  owns a RocksDB instance. Socket buffers, connection tasks, and database
  memory dominate before the hard committee or descriptor limits.
- Use 20 validators for quick, low-risk development comparisons.
- Use 40 validators as the recommended maximum for repeatable comparisons
  across Starfish, Starfish Speed, Sparse, and all authentication schemes.
- Treat 64 as a Sparse-only local stress configuration, not a comfortable
  full-matrix setting.
- Use multiple machines through the orchestrator beyond 40 validators. For
  committees above ten, the local AWS table repeats the same ten regions while
  all validators still share one kernel and physical host.

The 30-second probes have different warm-up proportions from the 60-second
baseline, so their TPS values should not be used as a formal scaling curve.
The clean/error boundary and sampled resource usage are the relevant signals.
