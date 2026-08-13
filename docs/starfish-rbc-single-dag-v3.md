# Single-DAG Starfish-RBC V3

## Status

This is the active experimental successor to the two-plane carrier prototype
documented in `starfish-rbc-dag-protocol.md`. It is selected as
`starfish-rbc-single-dag`. The old implementation remains available as a
benchmark baseline; its carrier and projection formats are frozen and are not
reinterpreted as V3.

V3 is a research-testbed protocol. Crash recovery, bounded retirement and the
complete asynchronous safety/liveness proof remain required before production
use.

## One identity and one DAG

Every protocol vertex is an ordinary Starfish `VerifiedBlock`. Its canonical
`BlockReference` simultaneously identifies:

1. the author's reliable-broadcast proposal;
2. the dirty/authenticated DAG vertex;
3. the delivered/clean DAG vertex; and
4. the vertex considered by the existing Starfish committer.

V3 has no `CandidateCarrierV1`, nested `ConsensusVertexV1`, carrier clock,
delivery frontier, or physical-to-logical projection. Dirty and clean are
monotone states of the same vertex, not separate DAG identities.

## Typed RBC references

The V3 block header contains a canonical `StarfishRbcFieldsV3` list. Each item
is one of:

- `Echo(BlockReference)`; or
- `Ready(BlockReference)`.

The carrying block's authenticated author is the statement sender. The list is
part of that ordinary block's content digest. Consequently the default path
needs no standalone phase MAC, signature, or phase network message. The
flagged MAC-witness experiment adds exact references to ECHO-carrying ordinary
blocks, but still adds neither a signature nor a phase message.

References are sorted, duplicate-free and bounded by `6 * committee_size` per
block. A sender may name at most one digest for each `(phase, target author,
target round)`. Targets must be non-genesis, known-authority references no newer
than the carrying block.

## Progress and cleanliness

Block production follows the authenticated dirty threshold clock: a V3 block
may causally reference authenticated previous-round blocks that have not yet
been RBC-delivered. This is necessary to prevent a circular wait in which RBC
evidence needs a later block while later blocks require earlier RBC delivery.

The existing clean DAG remains fail-closed. A block becomes consensus-visible
only after:

1. its own RBC instance delivers the exact canonical header;
2. its payload is data-available where required; and
3. every causal parent and ordering acknowledgment is clean.

Typed RBC evidence references are testimony, not causal parents. Missing or
selectively supplied Byzantine evidence therefore cannot contaminate the
carrying block's clean dependency cone.

## Communication

Normal communication consists only of ordinary Starfish block proposals. RBC
ECHO/READY statements ride in later blocks. Header, payload and missing-parent
requests are synchronization/recovery traffic and remain permitted. A V3 node
must neither emit nor count the legacy standalone `RbcPhase` messages.

## Initial pipeline

After authenticating a proposal, a validator locks an ECHO and queues its typed
reference for the next ordinary block. Observing quorum ECHO references locks a
READY reference for a later ordinary block. Quorum READY references deliver the
original block. These waves pipeline across normal Starfish rounds; they do not
create a second physical round counter.

## Safety boundaries

- Block authentication and the V3 digest bind every embedded statement to its
  sender.
- Sender locks prohibit conflicting ECHO or READY references for one target
  slot.
- RBC delivery never follows from dirty-DAG admission alone.
- Consensus parent selection and commitment use only clean vertices.
- Recovery content must recompute to the exact requested `BlockReference`.
- Frozen direct-RBC and carrier-DAG formats retain their old domains.

### Portable ECHO-QC fast path

Finite benchmarks may opt into
`--starfish-rbc-single-dag-echo-qc-fast-path`. In that mode a certificate is the
target plus a quorum of exact ordinary-block references whose authenticated
headers contain `Echo(target)`. It contains no BLS, Ed25519, ML-DSA or other
digital signature. The certificate rides in an ordinary DAG block; there is no
standalone ECHO or READY message.

For synchronization, fast-path MAC proposals retain the author's complete MAC
vector. A holder may relay the exact header and vector, and each receiver checks
only its own pairwise entry before accepting that witness. Normal delivery adds
no message; exact header/vector requests occur only when a named witness is
missing.

This flag is deliberately a **latency lower bound, not the Byzantine-totality
mode**. A Byzantine witness author can make its vector valid for the first QC
builder but invalid for another receiver. Requiring every named quorum witness
therefore can prevent that receiver from accepting an otherwise observed QC;
accepting fewer witnesses would instead lose quorum-intersection safety. Public
signatures solve transferability but violate the signature-free requirement.
The default quorum-ECHO then quorum-READY path remains the signature-free,
totality-safe candidate.

## Required validation

Before using V3 benchmark results, tests must cover canonical identity,
conflicting sender locks, dirty-clock progress, clean dependency closure,
embedded ECHO/READY delivery, absence of normal phase messages, Byzantine
withholding with bounded recovery, restart replay and deterministic Starfish
commit order. Matched n=10 and n=40 zero/AWS runs must compare V3 against the
frozen carrier baseline using identical load and duration.

## Initial n=10 testbed checkpoint

The first matched local runs used 1,000 offered transactions/s for 20 seconds
with MAC authentication and the fixed 50 ms V3 round limiter:

| Protocol/profile | Network | p50 E2E | Eventual TPS | Outbound/node |
| --- | ---: | ---: | ---: | ---: |
| `starfish-rbc-single-dag` | zero | 498.3 ms | 1,000 | 0.79 MB/s |
| `starfish-rbc-single-dag` | AWS table | 1,285.7 ms | 1,000 | 0.61 MB/s |
| V3 + old receiver-local ECHO-QC | AWS table | 961.0 ms | 1,000 | 0.61 MB/s |
| V3 + old receiver-local ECHO-QC, n=40 | AWS table | 977.35 ms | 1,000 | 3.04 MB/s |
| V3 + rejected BLS aggregate ECHO-QC | zero | 405.8 ms | 1,000 | 1.06 MB/s |
| V3 + rejected BLS aggregate ECHO-QC | AWS table | 983.7 ms | 1,000 | 0.74 MB/s |
| V3 + signature-free MAC-witness ECHO-QC | zero | 397.1 ms | 1,000 | 1.38 MB/s |
| V3 + signature-free MAC-witness ECHO-QC | AWS table | 955.3 ms | 1,000 | 0.91 MB/s |
| `starfish-mac` lower bound | AWS table | 610.0 ms | 1,000 | 0.61 MB/s |

All exact offered transactions committed during the bounded drain. These are
single-machine research measurements, not production claims. The two old
receiver-local rows preserve the historical totality caveat. The BLS rows are
retained only as historical latency data and are not part of the signature-free
design. The MAC-witness rows are also a flagged lower bound: unlike the strict
default path, they assume every named witness supplied a valid complete MAC
vector for every honest receiver.
