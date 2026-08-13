# Single-DAG Starfish-RBC V3

## Status

This is the active experimental one-block design built on the direct-header
Starfish-RBC implementation. It is selected as `starfish-rbc-single-dag`.

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
part of that ordinary block's content digest. Consequently no standalone phase
MAC, signature, or phase network message is needed.

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
- Direct-RBC formats retain their existing domains.

### Receiver-local quorum-ECHO latency lower bound

Finite benchmarks may opt into
`--starfish-rbc-single-dag-echo-qc-fast-path`. In that mode a node delivers an
exact header as soon as it has quorum locked ECHO statements, while still
emitting the normal READY statement. There is no portable QC object, witness
vector, public signature, standalone phase message, or additional fast-path
communication: each receiver acts only on ordinary DAG blocks that it
authenticated directly with its recipient-specific MAC.

Quorum intersection and the per-sender slot locks prevent two conflicting
headers from both obtaining honest receiver-local quorums, so the experiment
retains integrity and agreement/uniqueness. It does **not** provide normal RBC
totality: Byzantine ECHO senders can selectively reveal their statements so
one honest node obtains quorum and delivers while another honest node never
can. Relaying header bytes does not transfer pairwise-MAC testimony. The flag
is therefore a finite-testbed latency lower bound, is rejected for unbounded
or production runs, and must not be described as a Byzantine-totality-safe
RBC. The default V3 path continues to require quorum READY.

Two attempted ways to make this fast-path evidence portable were removed. A
public aggregate-signature certificate violated the signature-free design
constraint. A complete per-recipient MAC vector plus exact witness references
remained signature-free, but made proposals and certificates grow with the
committee and overloaded the n=40 single-machine testbed. Neither proof format
is part of the current V3 wire protocol.

## Required validation

Before using V3 benchmark results, tests must cover canonical identity,
conflicting sender locks, dirty-clock progress, clean dependency closure,
embedded ECHO/READY delivery, absence of normal phase messages, Byzantine
withholding with bounded recovery, restart replay and deterministic Starfish
commit order. Matched n=10 and n=40 zero/AWS runs must compare V3 against the
direct-RBC baseline using identical load and duration.

## Testbed checkpoint

Matched local runs used 1,000 offered transactions/s for 20 seconds with MAC
authentication and the fixed 50 ms V3 round limiter:

| Protocol/profile | Network | p50 E2E | Eventual TPS | Outbound/node |
| --- | ---: | ---: | ---: | ---: |
| `starfish-rbc-single-dag` | zero | 498.3 ms | 1,000 | 0.79 MB/s |
| `starfish-rbc-single-dag` | AWS table | 1,285.7 ms | 1,000 | 0.61 MB/s |
| V3 + receiver-local quorum-ECHO, n=10 | zero | 400.5 ms | 1,000 | 0.79 MB/s |
| V3 + receiver-local quorum-ECHO, n=10 | AWS table | 956.0 ms | 1,000 | 0.61 MB/s |
| V3 + receiver-local quorum-ECHO, n=40 | zero | 390.2 ms | 1,000 | 5.88 MB/s |
| V3 + receiver-local quorum-ECHO, n=40 | AWS table | 968.2 ms | 1,000 | 3.07 MB/s |
| `starfish-mac` lower bound | AWS table | 610.0 ms | 1,000 | 0.61 MB/s |

All exact offered transactions committed during the bounded drain. These are
single-machine research measurements, not production claims. In particular,
the receiver-local rows preserve integrity and agreement but carry the
Byzantine-totality limitation above.
