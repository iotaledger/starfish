# Starfish-RBC-DAG protocol design

Status: standalone MAC-vector RBC-DAG prototype with authoritative optimistic delivery and
committed-frontier output; the end-to-end proof, proof-safe retirement, checkpoint transfer, and
full validator recovery remain incomplete

The provisional CLI name for the eventual protocol is `starfish-rbc-dag`; that selector is not yet
implemented. The prototype runs under `starfish-rbc`: direct-header comparison uses
`--starfish-rbc-dag-shadow`, and standalone authority additionally enables
`--starfish-rbc-dag-autonomous-clock --starfish-rbc-dag-embedded-rbc-authority`. In standalone
mode the direct Starfish-RBC service is not started. Direct INIT, direct phase messages, direct
header pull, generic block batches, legacy missing-parent pull, and legacy transaction-data pull
have no certification, consensus, ordering, or output authority. Canonical application headers are
inside carriers; optional application bytes use the carrier envelope or the dedicated RBC-DAG
payload request/response path. Committed projected anchors release cumulative exact
carrier-frontier deltas, and those deltas are the sole application-ordering/output authority.

The implemented direct [`starfish-rbc`](starfish-rbc-protocol.md) prototype remains a separate
historical baseline: it sends INIT/ECHO/READY as direct messages and advances Starfish only through
its direct delivery path. This document specifies the standalone optimistic carrier DAG, its
four-phase weighted ECHO/VOTE/ACK/READY broadcast, its complete committee-sized MAC-vector
sidecar, and the separation between fast carrier pacing and logical consensus ordering.

The two designs may share canonicalization, cryptography, storage, and benchmark code, but they are
not wire-compatible and do not have the same proof obligations. Nothing in this document changes
the behavior of `starfish-rbc` or any existing protocol.

## 1. Objective and non-claims

The objective is to recover the pipelining of an uncertified Starfish DAG without allowing
optimistically received Byzantine blocks to affect safety:

- a fast physical carrier DAG advances on a quorum of locally authenticated carriers;
- every carrier is the exact value of a weighted reliable-broadcast slot;
- later carriers batch ECHO, VOTE, ACK, and READY statements for earlier carriers;
- only authoritatively delivered, data-available exact prefixes enter the logical consensus
  projection; and
- committed consensus frontiers eventually order every honest on-prefix application carrier.

The initial research mode sends the complete ordered MAC vector with every carrier. The vector is
an authentication sidecar and is not part of the carrier digest. Ed25519, ML-DSA-44, and ML-DSA-65
remain selectable outer-authentication baselines; changing that selector does not change the
embedded RBC or consensus rules.

The implemented composition includes the canonical codec, deterministic four-phase reducer,
durable proof-critical journal, autonomous carrier clock, exact carrier recovery, optimistic and
certification latches, consensus projection, and cumulative committed-frontier output. Idle control
heartbeats use the resolved Starfish leader timeout (600 ms for Push/Starfish-RBC by default), but
application carriers and encodable phase follow-ups are event-driven. The V4 authoritative mode
promotes the proved `O`-ECHO predicate to delivery authority; `Q` READY remains a distinct slower
certification fact rather than a prerequisite for fast projection.
The research harness may override the logical C2 fallback timeout independently for controlled
latency experiments. This does not change the physical heartbeat, carrier pacing, C1/C3 rules, or
wire format; absent an override, C2 continues to use the resolved Starfish leader timeout.

Standalone authority is an end-to-end boundary. The direct Starfish-RBC actor is absent, generic
block dissemination and legacy pull messages are rejected or ignored, and the legacy Starfish
committer is disabled. Only durably authoritatively delivered carrier content, the typed
verified-payload ingress, projected consensus decisions, and committed frontier deltas can affect
application output.

Restart coverage is deliberately scoped. The actor WAL replays retained exact content, ordered
ingress, local ECHO/VOTE/ACK/READY locks, delivery/promise locks, local outbound bytes, consensus
choices, projection state, and committed frontiers. Exact-slot responses are byte-identical when
the requested locally authored outbound carrier remains retained. This is not yet a full validator
crash-recovery, checkpoint-transfer, proof-safe retirement, or arbitrary late-node catch-up claim.

The carrier plane shares the validator's existing TCP connections, outbound queues, bandwidth, and
CPU process. There is no feature handshake, so every validator in a run must understand the
append-only carrier messages and enable a homogeneous configuration. Mirror and autonomous modes
derive distinct authentication protocol instances. The authoritative durable path additionally
uses the V4 autonomous WAL filename and `SRD5` raw-record magic, preventing older promise semantics
or record layouts from being silently replayed as the current protocol. These fail-closed
namespaces are not a substitute for deployment negotiation.

Shadow shutdown is bounded so an observational WAL failure cannot indefinitely block validator
shutdown. If that timeout fires, the blocking worker may still hold the shadow WAL's single-writer
handle even after its async supervisor is detached. A same-process restart against that storage is
therefore forbidden until the worker has exited; process exit remains safe. A production-quality
same-process restart path needs an operating-system file lock or a fully cancellable storage task.

The shadow runtime is not a proof or a production performance implementation. Its default
crash-safe profile intentionally fsyncs every accepted transition. The live fail-stop reducer now
applies preflighted transitions and journal deltas in place, then exposes effects only after WAL
append, avoiding the former full-history clone on every carrier. It still retains unbounded run
history and performs synchronous reducer/storage work. A separate explicit benchmark profile writes the same ordered,
checksummed frames but syncs them only on clean shutdown; it reports appended and durable records
separately and makes no crash-safety claim. This removes the known persistence observer effect
without changing the protocol reducer. The runtime also uses a fixed unsolicited-retention window
only as a benchmark resource guard; that window is not a safe asynchronous pruning rule. Until the
composition and resource bounds are completed, `starfish-rbc-dag` remains an experimental
reference implementation rather than a proven signature-free Starfish variant.

Application bytes remain outside canonical carrier identity. The optional proactive bytes and
dedicated payload responses are untrusted transport until the sole verifier checks them against the
canonical application header and transaction commitment. The actor receives `DataAvailable` only
after Core has materialized the concrete block and its existing availability predicate succeeds;
neither carrier delivery nor a raw payload response may bypass that application DA gate.

## 2. Model and notation

The current prototype assumes:

- one static, ordered, stake-weighted committee for a run;
- Byzantine stake strictly below one third of total stake;
- pairwise symmetric keys for every ordered validator pair;
- reliable authenticated point-to-point communication after GST;
- a fresh nonzero protocol-instance identifier shared through genesis configuration;
- no committee reconfiguration; and
- no state retirement until a safe recovery watermark is proved.

For one target slot, let `W` be total committee stake and `a` the target author's stake. The
implementation derives all weighted thresholds with checked integer arithmetic:

```text
F = floor((W - 1) / 3)       maximum Byzantine stake under faults < W/3
V = F + 1                    READY validity/amplification threshold
Q = W - F                    READY certification and carrier quorum threshold

U = W - a                    stake outside the target author
b = F - a                    residual Byzantine non-author stake, when a <= F
M = floor(U / 2) + 1         strict non-author majority
C = floor((U + b) / 2) + 1  convergence threshold
O = M + b                    authoritative optimistic ECHO threshold
```

`M`, `C`, and `O` apply when `a <= F`, so the target author may be Byzantine. ECHO, VOTE, and ACK
stake exclude that author. If `a > F`, the global fault bound makes the target author honest; the
receiver-specific authenticator on exact content is then an immediate authoritative-delivery
predicate, and the locally fixed high-stake author seeds READY for the independent certificate
path. READY always counts the whole committee. For equal stake and `n = 3f + 1`, `Q = 2f + 1` and
`V = f + 1`.

Two independent round numbers are used:

- `carrier_round` belongs to the fast physical DAG and advances from authenticated admission;
- `consensus_round` belongs to the authoritative logical Starfish projection.

There is no fixed mapping between them. Carrier rounds may run ahead while a consensus vertex is
waiting for authoritative carrier delivery, application data availability, a leader decision, or
eligible strong parents.

## 3. One physical DAG, two logical projections

The only network DAG objects are carriers. A carrier contains application-header data, a bounded
batch of RBC control statements, and optionally one consensus vertex.

The same stored objects have two disjoint interpretations:

1. **Optimistic carrier projection.** Authenticated carriers and their weak parent references pace
   carrier creation and transport RBC statements. This projection is allowed to differ temporarily
   between honest validators.
2. **Authoritative consensus projection.** Authoritatively delivered and data-available consensus
   vertices, immutable strong parents, and exact delivery frontiers drive Starfish voting,
   certification, skip/commit decisions, and linearization. The `O` fast-delivery rule may admit a
   vertex before its independent `Q`-READY certificate; honest validators eventually agree on the
   safe projection.

Weak carrier edges never become strong/order edges, even if their targets later deliver. A node
must not construct its own filtered consensus parent set from an optimistic carrier after the fact:
that would make the authenticated content have different consensus meaning at different nodes.

This separation prevents a Byzantine carrier from poisoning an honest carrier. A quorum-sized weak
parent set can contain selectively disseminated or invented Byzantine references. Waiting for all
such references to become authoritatively delivered would make the honest child permanently unusable.
Weak edges are therefore permanently nonblocking and nonordering. Only the explicitly encoded
strong parents and the authoritative exact frontier constrain consensus.

## 4. Canonical objects

The canonical codec implements the following logical types. Field widths, enum codes, maximum
lengths, and golden bytes are part of the implemented runtime contract.

```rust
struct CarrierHeaderV1 {
    author: AuthorityIndex,
    carrier_round: RoundNumber,

    // Physical pacing only. `own_prev` is not repeated in `weak_parents`.
    own_prev: BlockReference,
    weak_parents: Vec<BlockReference>,

    transactions_commitment: TransactionsCommitment,
    application_header: Option<RbcCanonicalHeader>,
    data_acknowledgments: Vec<BlockReference>,
    phase_batch: Vec<RbcPhaseStatementV1>,
    consensus_vertex: Option<ConsensusVertexV1>,
    creation_time_ns: TimestampNs,
}

enum RbcPhaseStatementV1 {
    Echo { target: BlockReference },
    Ready { target: BlockReference },
    Vote { target: BlockReference },
    Ack { target: BlockReference },
}

struct ConsensusVertexV1 {
    consensus_round: RoundNumber,
    strong_parents: Vec<ConsensusVertexReference>,
    delivery_frontier: Vec<Option<BlockReference>>,
    leader_choice: LeaderChoiceV1,
}

struct ConsensusVertexReference {
    carrier: BlockReference,
    consensus_round: RoundNumber,
}

enum LeaderChoiceV1 {
    Vote { leader: ConsensusVertexReference },
    NoVote { leader_author: AuthorityIndex, leader_round: RoundNumber },
}
```

The author of an embedded phase statement or consensus vertex is the author of its enclosing
carrier. An outer authenticator therefore authenticates the ordered batch without a separate tag
or signature per statement. `application_header = None` is a control-only V1 carrier;
`Some(exact_header)` selects the V2 identity/wire grammar and binds the complete canonical
application header into the carrier digest.

For non-genesis carrier round `r`:

- `own_prev` has the same author and carrier round `r - 1`;
- every weak parent has carrier round `r - 1` and a distinct non-local author;
- the stake of `{ own_prev } union weak_parents` reaches `Q`;
- phase targets have carrier rounds strictly below `r`; and
- weak parents are in strict authority order and duplicate-free;
- acknowledgments commit to the unique normalized sequence described below, and phase batches are
  order-significant logs whose exact order is committed;
- a phase batch contains at most one statement for each `(phase, target author, target round)`; and
- strong-parent ordering, frontier indexing, and leader-choice validity are checked only when the
  optional consensus vertex is projected, so an ineligible vertex cannot invalidate its carrier.

The first encoded carrier has round one and names the fixed virtual round-zero carrier reference of
its author as `own_prev`; no round-zero carrier is sent on the wire. Consensus genesis is likewise
virtual. Every embedded consensus vertex has a positive consensus round and an explicit leader
choice. These conventions avoid making genesis a second, partially authenticated wire format.

Weak references are syntax and pacing declarations, not availability assertions. Their target
headers need not be present to authenticate, admit, process, or authoritatively deliver the
enclosing carrier.

Acknowledgments have one canonical logical order: first the unique maximal suffix shared with
`[own_prev] || weak_parents`, then all remaining acknowledgments in their original relative order.
The content digest commits to this expanded, suffix-first sequence, while the wire codec stores the
shared suffix as an intersection index and retains the order-significant extras. Non-canonical wire
aliases and duplicate acknowledgments are rejected. The current standalone runtime emits this
field empty. In particular, a carrier acknowledgment is not an application-DA oracle and cannot
bypass the concrete Core gate described below.

`delivery_frontier` has exactly one indexed entry per committee authority. `None` denotes that
authority's fixed genesis/empty prefix. A `Some(reference)` entry must name the same authority as
its vector index. The frontier rules in Section 10 are stateful eligibility rules; they are not
part of context-free carrier decoding.

### 4.1 Carrier identity

The carrier reference remains content-only:

```text
BlockReference = (author, carrier_round, BLAKE3(canonical_carrier_content))
```

Canonical carrier content includes every field of `CarrierHeaderV1`, including the ordered RBC
phase batch and optional consensus vertex. It excludes:

- the MAC vector or public signature;
- protocol instance and committee ID;
- transaction bytes and erasure-coded shards;
- receipt peer, arrival time, and local admission state; and
- recovery or transport metadata.

The byte grammar uses a one-byte format version, fixed field markers, big-endian fixed-width
integers, and explicit vector lengths. It does not add a mutable string domain to the block
identity. Control-only carriers retain the frozen V1 content/wire versions (`01`/`81`); a carrier
with an exact application header uses V2 (`02`/`82`). The canonical identity codec is handwritten;
serde or bincode framing is never hashed.

`Ref` is `author:u16 || carrier_round:u32 || digest:[u8;32]`; every integer is big-endian and every
vector count is `u16`. The expanded identity grammar is:

```text
00 version                            // 01 control-only, 02 with application header
01 author:u16
02 carrier_round:u32
03 own_prev:Ref
04 weak_count:u16 weak:Ref[]
05 transactions_commitment:[u8;32]
0A canonical_application_header      // present exactly for version 02
06 acknowledgment_count:u16 expanded_acknowledgments:Ref[]
07 phase_count:u16 (phase:u8 target:Ref)[]       // ECHO=0, READY=1, VOTE=2, ACK=3
08 consensus_present:u8 [ConsensusVertexV1]
09 creation_time_ns:u64
```

The optional consensus encoding uses markers `01` through `04` for consensus round, strong
parents, delivery frontier, and leader choice. A strong reference is `Ref || consensus_round:u32`;
frontier entries use `0=None` and `1=Some(Ref)`; leader choices use `1=Vote` and `2=NoVote` (`0` is
reserved for virtual genesis and is rejected on the wire). The canonical transport codec replaces
the expanded acknowledgment field with `intersection_start:u16 || extra_count:u16 || extras`, where
the intersection is the unique maximal suffix of `[own_prev] || weak_parents`. Decoding expands and
recompresses this field and rejects aliases. The compressed transport versions set the high bit:
`81` for control-only V1 and `82` for application-bearing V2.

The codec caps canonical carrier content at 4 MiB, weak and strong parents at the committee size,
the frontier at exactly the committee size when projected, and encoded phase batches at
`min(6n, 2048)`. Six entries per authority leave bounded spillover above the four-phase steady-state
arrival rate; the scheduler limitations are described in Section 8.3.

Consensus vertices are referenced by their exact enclosing `BlockReference` plus their declared
`consensus_round`. Because there is at most one consensus vertex per carrier, that pair identifies
the immutable embedded value without a second mutable lookup key.

## 5. Authentication sidecar

Authentication is outside the carrier reference:

```rust
enum CarrierAuthenticationV1 {
    Ed25519(Ed25519Signature),
    MlDsa44(MlDsa44Signature),
    MlDsa65(MlDsa65Signature),
    MacVector(FlatMacVector),
}

struct FlatMacVector {
    // Exactly committee.len() consecutive 32-byte tags in authority-index order.
    tags: Vec<u8>,
}
```

In MAC mode, author `A` computes entry `q` for recipient `Q_q` over a fixed-width statement that
binds at least:

```text
STARFISH_RBC_DAG_V2
carrier-authentication kind and scheme
protocol_instance
committee_id
author A
recipient Q_q
carrier_round
canonical carrier content digest
```

The full vector accompanies every normally disseminated MAC carrier in the current prototype,
including relayed carriers. A receiver verifies only the entry at its own committee index. It
neither verifies nor vouches for the remaining entries.

A carrier received directly from its author and the same carrier received through a relay are both
authentication-eligible when the local entry verifies. This is receiver-specific transferable
authentication: it survives a relay for its intended recipient, but it is not a publicly verifiable
signature and provides no non-repudiation.

The vector is deliberately not an RBC value and has no consistency invariant. A Byzantine author
may attach different vectors to the same content reference, including a vector with a valid tag for
one recipient and garbage for another. Correctness therefore depends only on the local entry and on
the embedded four-phase protocol, never on agreement about the vector bytes.

Each node persists one exact vector variant with an authenticated carrier for restart and relay:
the locally generated sidecar for its own carrier, otherwise the first inbound variant whose local
entry verifies. The implementation never replaces that variant by arrival provenance and never
merges entries from different vectors. Exact carrier recovery after phase evidence prefers a new,
appended envelope-response message carrying the holder's persisted variant. If the requester's
local entry verifies, the response follows the ordinary relayed-ingress predicate and may create
authenticated admission, ECHO, and fast-clock stake. If the entry is absent, malformed, or invalid,
the same canonical bytes retain the legacy content-only authority and can still unblock phase
progress, authoritative delivery, and READY certification. The frozen content-only response remains
accepted for compatibility. A failed MAC check assigns no blame to either carrier author or holder.

Public-signature modes use the same context-bound carrier statement without a recipient field and
the same embedded RBC/consensus logic. They exist for controlled performance comparison, not as
separate consensus protocols.

## 6. Local lifecycle and authority matrix

The implementation must represent these predicates separately:

```text
Candidate
    canonical carrier content and reference are valid

Authenticated
    local author, valid public signature, or valid local MAC-vector entry

CarrierAdmitted
    Candidate && Authenticated && accepted by the carrier admission window

AuthoritativeDelivered
    exact content is locally fixed, authenticated from a necessarily honest author, supported by
    O author-excluding ECHO stake, or certified by Q READY

ReadyCertified
    Q READY stake names the exact retained content; recorded independently even if fast delivery
    happened earlier

DataAvailable
    control-only carrier, or Core has materialized the exact application block and verified its
    committed payload

PrefixClosed
    AuthoritativeDelivered && DataAvailable && exact own_prev prefix is closed

VertexProjected (orthogonal to the carrier lifecycle)
    this carrier's optional consensus vertex is eligible in the authoritative projection

Included
    a committed Starfish anchor frontier names this carrier in its deterministic delta

Ordered
    the complete included delta is available and the carrier has been deterministically output
```

`Candidate` alone permits bounded staging and exact-reference recovery. `CarrierAdmitted` permits
immediate phase-batch processing and fast-pacemaker counting. `AuthoritativeDelivered` permits
phase replay even at a node whose author MAC entry was poisoned. `ReadyCertified` is useful audit
and fallback evidence but is not a second output gate after a valid fast delivery.
`PrefixClosed` permits frontier inclusion.
`VertexProjected` alone permits the optional vertex to supply Starfish
vote/certifier/leader evidence. It is not a later state of every carrier: a carrier with no eligible
optional vertex may still become prefix-closed, included by another anchor's frontier, and ordered.

The existing generic `dirty` bit is not a synonym for `CarrierAdmitted`: current RBC code may stage
content after invalid initial authentication or during recovery. Reusing that bit would let an
unauthenticated candidate advance the fast clock.

| Consumer | Required local authority |
|---|---|
| Header retention/recovery | `Candidate` |
| Process embedded RBC statements | `CarrierAdmitted`, or `AuthoritativeDelivered` for replay |
| Fast carrier clock | `CarrierAdmitted` |
| Exact carrier recovery | requested `Candidate` whose bytes recompute the target reference |
| Accept application payload | carrier-authorized header plus commitment-verified bytes |
| Application data-availability fact | concrete, data-available Core block only |
| Delivery frontier | `PrefixClosed` target carrier |
| Starfish QC, skip, and anchor commit | `VertexProjected` consensus vertex |
| Application payload output | cumulative `Included` delta, with every member authoritatively delivered and application-data-available |

Fast-pacemaker counting is exactly `CarrierAdmitted`. Authoritative delivery is intentionally not a
second pacing input because it would change the sequential per-author slot accounting.

## 7. Fast carrier pacemaker

The carrier clock is sequential and does not use the current threshold-clock helper's ability to
jump to a far-future round after one message.

For each carrier round, a validator records at most one admitted reference per author. Byzantine
equivocations may make different honest validators record different references for a Byzantine
author, but each author contributes stake once. A validator advances from carrier round `r` to
`r + 1` only after:

1. its own carrier at round `r` has been fixed and persisted; and
2. it has admitted distinct-author carrier stake `Q` at round `r`.

The executable prototype admits authenticated carriers at most two rounds ahead of the local open
round and retains canonical unsolicited carrier content up to 64 rounds ahead. Authenticated
retained carriers may later be promoted sequentially; candidate-only content retains no admission
authority.
Farther unsolicited values are discarded by the benchmark resource guard. Buffered carriers never
skip missing local rounds. These values are engineering bounds, not a proof-safe asynchronous
retirement rule. The next local carrier records the selected quorum as
`{ own_prev } union weak_parents`; a missing weak-parent body never blocks later action.

This clock replaces the current `starfish-rbc` rule that requires a quorum of RBC-clean previous
round headers before proposal. It does not make admitted carriers consensus votes. Leader/vote/skip
waiting conditions move to the independent consensus projection and cannot block the creation of a
carrier needed to transport ECHO, VOTE, ACK, or READY.

Honest validators emit empty control heartbeats when they have no application transactions.
Without heartbeats, low load can stop the four-phase waves and violate RBC liveness. Every carrier,
including an empty heartbeat, is itself an RBC value and has an authenticator sidecar.

The first prototype retains the current run's carrier/RBC state and rate-limits carrier creation.
A production design needs a proved runahead and backpressure rule. A hard carrier/consensus skew cap
must not suppress control heartbeats, because those heartbeats may be exactly what allows the
authoritative projection and committed frontier to catch up.

## 8. Embedded all-carrier reliable broadcast

There is one RBC slot for every physical carrier:

```text
RbcSlot = (protocol_instance, committee_id, carrier_author, carrier_round)
RbcValue = BlockReference
```

Receiver authentication is the admission capability for that exact value. A non-author that first
admits a value durably locks and queues ECHO. The target author never contributes ECHO, VOTE, or ACK
stake, and target-authored statements in those phases are ignored. Locally fixing a carrier is an
authoritative delivery predicate for its creator, but it does not manufacture author stake in an
author-excluding certificate.

For a potentially Byzantine target (`a <= F`), the reducer applies these weighted transitions:

```text
admit exact content                          -> ECHO
ECHO stake >= M                             -> VOTE
ECHO stake >= C or VOTE stake >= C          -> ACK
ACK stake >= C or READY stake >= V          -> READY
ECHO stake >= O                             -> authoritative optimistic delivery
READY stake >= Q                            -> independent READY certification
```

ECHO, VOTE, and ACK use distinct-author stake outside the target author; READY uses the full
committee. VOTE does not require local carrier admission, only the latched ECHO evidence and exact
retained target content. ACK may arise from `C` ECHO or `C` VOTE and does not require the node to
have sent VOTE. READY may arise from `C` ACK or the standard `V` READY amplification path. Local
phase evidence counts immediately after its durable lock, before later carrier dissemination.

If `a > F`, the target author is necessarily honest. A valid receiver-bound authenticator on the
exact author value is therefore an immediate authoritative delivery predicate. The locally fixed
high-stake author also seeds READY; because its stake is at least `V`, the ordinary amplification
and `Q` certification path still completes independently.

Reaching `O` is authoritative delivery, not a speculative hint. The reducer pins the exact carrier,
advances its delivered prefix when the DA and predecessor conditions hold, and may use its optional
vertex in the authoritative projection. `Q` READY records the slower certificate even if the same
value already delivered through the fast predicate. A certificate reached first also satisfies the
delivery predicate. No threshold over a bare digest can expose a phase or deliver a placeholder.

For every local slot, ECHO, VOTE, ACK, READY, delivery, and READY certification each lock at most
one target; different phases may safely name different targets. For every remote sender, the node
also records at most one target per phase and slot. Exact replay is idempotent, and a later
same-sender equivocation is ignored before it can add stake or allocate a second phase choice.

### 8.1 Processing rule

After canonical validation and admission of the outer authenticator, a receiver processes the
phase batch in canonical encoded order immediately. An authenticated carrier beyond the two-round
admission window is retained but neither contributes pacemaker stake nor creates ECHO; its batch
gains authority only after sequential promotion or an independent authoritative-delivery predicate.
A retained candidate alone has no phase authority. Once authorized, processing does not wait for
the enclosing carrier's READY certificate, application DA, prefix closure, or projection. Waiting
would create a recursion because its controls are needed to deliver earlier carriers.

If the local carrier authenticator is missing or invalid, its phase batch is not processed on
candidate receipt. If that exact outer carrier later becomes authoritatively delivered, the stored
batch is replayed under that delivery capability. Thus poisoned vector entries delay optimistic
admission but cannot permanently suppress controls selected by the four-phase protocol. Direct
phase messages are never an alternative authority source.

Phase targets are strictly older carrier rounds, making a single carrier's replay acyclic. Local
arrival order between different authenticated carriers is still observable and can affect which
Byzantine equivocation encounters a slot-global guard first. The ordered journal persists each
batch entry and its replay cursor; recovery must replay that order, never reconstruct choices by
sorting carriers after a restart.

### 8.2 Header recovery

An honest ECHO, VOTE, ACK, or READY author retains the exact target carrier content before exposing
that phase. A validator may therefore latch threshold evidence before it has the bytes, record the
union of phase senders as candidate holders, and request the target from those holders. Recovery
content is accepted only when canonical decoding recomputes the requested `BlockReference` and the
context/committee checks succeed. Retention precedes any new local phase lock.

Recovery request/response is out-of-band byte transfer, not quorum testimony or a new phase. A
response can satisfy only an already allocated evidence obligation and cannot create one. A
vector-bearing response additionally grants ordinary carrier admission only when the exact
receiver-specific authenticator verifies under the same committee/context predicate as proactive
relayed ingress; otherwise it is content-only. The prototype retries recorded holders after GST.
Its separate carrier catch-up mechanism requests one exact `(author, round)` at a time and serves
only retained locally authored outbound bytes; it does not transfer ranges, certificates,
checkpoints, committed observer history, or arbitrary late state.

### 8.3 Batching and fairness

Phase batches are bounded. The encoded order is preserved and processed as an authenticated log;
two different orders intentionally identify different carriers. A deterministic fair queue must
prevent Byzantine traffic for one slot
from starving honest ECHO/VOTE/ACK/READY actions for other slots. In steady state, one authority can
owe up to four actions for each of `n` previous carriers. The executable model retains an unbounded
pending FIFO and drains the first `6n` statements eligible for the carrier being built (capped at
2,048 statements). A temporarily ineligible future-round statement remains in its stable queue
position but does not block older eligible work behind it. This exercises backlog, runahead, and
batching without pretending to solve adversarial fairness. A bounded runtime must use a fair
per-slot scheduler, reserve spillover above the four-phase arrival rate, and enforce an
active-slot window so delayed work drains instead of remaining at permanent saturation.

## 9. Authoritative consensus vertices

A carrier contains zero or one `ConsensusVertexV1`. The carrier remains valid and pace-eligible if
the optional vertex is malformed relative to authoritative projection state; only the optional
vertex is excluded from the consensus projection.

A consensus vertex authored by `A` at consensus round `c > 0` is eligible only when:

1. its enclosing carrier is authoritatively delivered by a local-fixed, honest-author,
   `O`-ECHO, or `Q`-READY predicate;
2. its enclosing carrier's transaction data is available and it closes `A`'s carrier prefix as
   defined in Section 10;
3. its strong parents name distinct-author eligible consensus vertices at exactly `c - 1` whose
   stake reaches `Q`;
4. the strong-parent set includes `A`'s preceding consensus vertex for non-genesis `c`;
5. its delivery frontier is closed and dominates every strong parent's effective frontier; and
6. its leader choice is valid for the deterministic leader role at `c - 1`.

For a vote, the exact leader must be an eligible strong parent at `c - 1`. No-vote validation is
objective and structural: it names the correct leader slot and no value from that slot appears in
the immutable strong-parent set. Remote validators do not attempt to verify that the author's local
timeout expired. If the strong-parent frontiers contain incomparable components, their join is
undefined and the optional vertex is ineligible; honest construction waits for a compatible quorum
rather than importing the fork into consensus.

Strong parents and voted leaders decrease strictly in `consensus_round`, which makes the consensus
projection acyclic. Their enclosing `carrier_round` may be numerically higher than the child's
because the clocks are independent and honest carrier authors can be skewed. Strong edges are never
interpreted as physical weak/self edges or application-order dependencies.

Consensus references and strong parents are immutable authenticated content. Missing or ineligible
strong parents block only this optional vertex. They never block the enclosing carrier, its phase
batch, the fast clock, or later honest RBC progress.

The consensus pacemaker preserves Starfish's separate advance and creation conditions, evaluated
only over eligible consensus vertices. A `Q`-READY certificate is not additionally required after
an authoritative optimistic delivery:

- **A1:** advance from `c - 1` to `c` after eligible distinct-author stake `Q` at `c - 1`;
- **A2:** do not advance until the local consensus vertex at `c - 1` has been fixed;
- **C1:** create at `c` after the eligible leader at `c - 1` is present and the eligible projection
  contains either `Q` votes for an exact leader value or a valid explicit direct-skip pattern for
  the leader slot at `c - 2`;
- **C2:** create after the logical consensus timeout, which defaults to the resolved Starfish
  leader timeout; or
- **C3:** catch up and create after observing eligible distinct-author stake `Q` already at `c`.

The strong-parent set chosen under C1 must itself contain the immutable L2 witness: the exact `Q`
voter vertices for a certificate, or the union of explicit negative-choice witnesses required by
the direct-skip evaluator. It must also contain the eligible leader at `c - 1`. Strong-parent sets
therefore contain between `Q` and `n` distinct authors. Merely observing the witness elsewhere in
the local projection is insufficient, because later certifiers must inherit it through the new
vertex's strong history.

If the eligible leader at `c - 1` is present when the local vertex at `c` is fixed, the vertex must
include that exact leader as a strong parent and record `Vote`. It may record `NoVote` only when it
is created through the timeout/catch-up path without that leader in its immutable strong-parent
set. This timeout/catch-up restriction is an honest-author creation rule; Byzantine authors may
emit structurally valid no-votes arbitrarily. These conditions prevent an adversarially scheduled
quorum that excludes each just-late leader from turning every consensus round into a skip.

The next local consensus vertex is embedded whenever the carrier scheduler next runs after its
creation condition becomes true. There is no requirement that its carrier round equal `c`, `c + 1`,
or any other fixed offset. Fast carrier production continues while C1/C2/C3 are unsatisfied.

A Byzantine author may embed conflicting consensus values for the same `(author, consensus_round)`
in different carrier rounds. All structurally eligible conflicts remain visible as equivocation;
there is no local first-arrival or anchor-time pruning rule. An honest author creates at most one
value in its local slot, every strong-parent or evidence set contains at most one value per author,
and stake aggregation counts each author once. Votes and committed leaders name exact references,
so the existing equivocation-aware Starfish safety argument—not an invented canonical
choice—must resolve Byzantine conflicts.

## 10. Closed delivery prefixes and frontiers

Authoritative carrier delivery alone is not application data availability and is not a compact
availability proof for a Byzantine author's later carrier. A
Byzantine author may deliver round `r` with an `own_prev` that names an unavailable fork at
`r - 1`. Therefore a frontier component is a contiguous exact prefix, not simply the highest
delivered round.

For authority `A`, begin at its fixed genesis/empty prefix. A carrier `(A, r, R)` extends the local
closed prefix only when:

- `R` is authoritatively delivered;
- for an application carrier, Core has materialized the exact application block and its committed
  transaction data satisfies the existing Starfish availability predicate;
- `r` is exactly one more than the current prefix round; and
- `R.own_prev` equals the exact current prefix tip.

Later delivered carriers above a gap remain stored but do not advance the prefix. A Byzantine
off-prefix fork may be discarded from application ordering without affecting honest-carrier
liveness.

The join of strong-parent effective frontiers is computed componentwise. A child frontier dominates
that join only when each entry is the same exact tip or an exact self-chain extension of it;
comparing round numbers alone is insufficient. Including each parent's enclosing carrier prevents a
child from omitting a strong parent from its eventual frontier closure. Honest authors advertise the
newest locally closed tip for every authority, subject to that dominance rule. This monotonic rule
ensures that committed frontiers never regress or switch Byzantine forks.

The containing carrier cannot name itself in its encoded frontier. For an eligible consensus
vertex, its declared author component must equal its carrier's `own_prev` prefix tip. Once the
enclosing carrier is authoritatively delivered and data-available, its **effective frontier**
replaces that one component with the enclosing carrier. This makes a committed anchor's own
application payload eligible without waiting for a later anchor while preserving exact prefix
continuity.

The liveness target is deliberately precise:

> Every honest carrier that authoritatively delivers and becomes data-available eventually appears in a
> committed effective-frontier delta.

No guarantee is made for a malformed or permanently off-prefix Byzantine carrier. Guaranteeing all
authoritatively delivered Byzantine forks would require an antichain or sparse exception structure
rather than one compact prefix tip per authority.

## 11. Starfish certification, commit, and skip

Starfish's logical leader schedule and commit rules run over eligible consensus vertices only.
Carrier admission, weak parents, phase targets, candidate headers, and merely retained carriers
cannot act as voters, certifiers, leaders, non-votes, or reachability evidence.

For a scheduled leader slot at consensus round `c`, every eligible voter publishes one immutable
slot choice. `Vote(L)` is positive evidence only for the exact leader value `L` and explicit
negative evidence for every conflicting value in that leader slot. `NoVote(slot)` is negative
evidence for every value in the slot. Thus a late Byzantine equivocation cannot turn an earlier
omission into a new choice.

The existing Starfish patterns are then evaluated from these explicit choices:

- an eligible vertex at `c + 1` explicitly records `Vote(L)` or `NoVote(leader_slot)`;
- `Q` distinct-author votes certify `L`;
- an eligible vertex at `c + 2` whose certified history contains `Q` such votes is a certifier;
- `Q` distinct certifier authors provide the direct-commit condition; and
- a per-candidate quorum of explicit negative choices provides the direct-skip pattern.

If the leader produces no value, `Q` immutable `NoVote(slot)` choices are a self-contained direct
skip witness. If a Byzantine leader equivocates, `Vote(L)` is negative evidence for every other
candidate, and the current Starfish per-candidate evaluator decides whether the collected explicit
choices form a direct-skip pattern; otherwise the slot remains for indirect decision.

Indirect commit/skip follows the existing Starfish rule over this same eligible strong-parent
projection. An omission from a phase batch, weak parent list, missing carrier, or locally filtered
view is never a no-vote. `NoVote` is explicit, authenticated, immutable, and slot-locked.
An honest validator persists its leader-choice lock before exposing the carrier that contains it;
it cannot emit `NoVote` and later vote for a late leader in the same logical voting slot.

Decision planning follows the existing Starfish newest-to-oldest rule. For an undecided slot, the
deciding anchor is the first committed leader in the already-decided later sequence at least three
rounds ahead. Final skips are traversed, but an intervening undecided slot is a hard barrier; a
validator must not scan past it to whichever later direct certificate happens to be visible first.
Only the longest finalized prefix is published. Direct versus indirect evidence may be observed at
different times, but it cannot change the committed-leader sequence.

Skipping a Byzantine leader role discards only that optional consensus value. It does not discard
the enclosing application carrier. If that carrier later becomes part of a closed prefix, a later
committed frontier orders its payload.

Every consensus consumer enforces this type boundary: voter caches, leader support, potential
certificates, direct/indirect decisions, reachability, and the linearizer reject non-projected
carrier facts. Application data availability is not inferred from this projection or from carrier
acknowledgment references; it enters only through the typed Core materialization callback.

## 12. Frontier-delta linearization

Let `A_k` be the `k`th committed leader in the finalized leader sequence, whether directly or
indirectly committed, `F_k` its effective frontier, `J_k` the cumulative joined committed frontier,
and `Closure(F)` the union of the exact per-author self-chain prefixes named by `F`. Maintain:

```text
J_0   = [None; committee_size]
J_k   = componentwise_exact_join(J_(k-1), F_k)
Delta = Closure(J_k) \ Closure(J_(k-1))
```

The join compares exact self-chain lineage, not round numbers. It accumulates advances from
concurrent committed anchors and prevents a later partial frontier from erasing or regressing a
component already committed. Before outputting `Delta`, a validator requires every exact carrier
to be authoritatively delivered and every application member to pass the concrete Core DA gate.
Exact carrier recovery and the dedicated verified-payload path supply missing material.

Frontiers are applied strictly in increasing finalized-leader order. A later leader used to decide
an older slot is planning evidence only until every older slot has resolved; its frontier is not
applied ahead of an indirectly committed older leader. Thus different projection arrival orders
may classify a leader as direct or indirect at different times, but produce the same ordered anchor
and frontier-delta sequence.

All validators deterministically order the same delta by
`(carrier_round, author, content_digest)`. Because a closed author prefix advances by exactly one
carrier round, this key already preserves mandatory `own_prev` order.

Weak parents, strong consensus edges, optional-vertex projection time,
ECHO/VOTE/ACK/READY target references,
recovery provenance, and MAC-vector variants never constrain application payload ordering. Strong
edges order consensus decisions and dominate frontiers, but a late-projecting optional vertex must
not retroactively add an edge between payloads already output. This fixed ordering also ensures that
a dangling Byzantine weak edge cannot reintroduce the liveness failure that the two-projection
design removes.

## 13. Expected optimistic schedule

In an all-honest synchronous interval, batching can realize this conceptual schedule:

```text
t = 0       carrier k authenticates an exact application header; non-authors lock ECHO
t = delta   ECHO stake reaches O: authoritative delivery; VOTE/ACK obligations are queued
t = 2delta  ACK stake reaches C: READY is queued
t = 3delta  READY stake reaches Q: the independent certificate is recorded
```

The `O` fast path deliberately makes authoritative delivery available after the ECHO wave instead
of waiting for the READY certificate. The VOTE/ACK/READY path remains necessary for convergence,
totality, and independent certification under adverse schedules. For `a > F`, receiver-authenticated
exact content takes the honest-author fast branch even before the ECHO threshold. Application
output still waits for DA, logical consensus, and the cumulative committed frontier, so the RBC
delivery schedule is not itself a transaction-latency claim.

Implementation ordering is latency-critical. On carrier ingress, authenticate, apply its phase
batch, execute newly enabled delivery/prefix/projection transitions, and only then decide what the
next local carrier should contain. Constructing the next carrier first would accidentally add a
full carrier round to every RBC wave.

The complete vector costs `32n` bytes in every MAC carrier copy. Under all-to-all dissemination this
can erase much of the batching gain. The first benchmark is therefore a whole-protocol result, not
evidence that full-vector all-to-all transport is asymptotically better. Tree or bounded-fanout
vector dissemination is a later optimization and requires redundant routes or direct fallback.

## 14. Persistence, recovery, and boundedness

An authoritative implementation must persist proof-critical choices before exposing effects:

1. journal typed authenticated inbound provenance, exact bytes, and its local ingress sequence;
2. before fixing a local slot, construct and persist the typed candidate plus its exact canonical
   carrier bytes and reference;
3. persist local ECHO, VOTE, ACK, READY, delivery-promise, READY-certificate, explicit
   leader-choice, carrier-slot, and consensus-slot locks that match retained exact content;
4. persist the exact authentication sidecar and an outbound-exposure marker, and only then send the
   carrier; and
5. after restart, replay the journal in recorded order and retransmit the identical carrier and
   sidecar.

Persisting a bare local reference before its canonical carrier bytes is not sufficient: a crash in
that gap would leave the slot fixed without the data needed to reconstruct the exact carrier. The
write-ahead model therefore makes content retention precede slot fixation and prevents exposure
until every lock encoded by that carrier is durable.

Every persisted slot, candidate, lifecycle predicate, journal entry, and outbound-carrier key is
namespaced by both `protocol_instance` and `committee_id`; storage from another run or committee
cannot satisfy a local lock or quorum. The current authoritative storage path is additionally
separated as autonomous WAL V4, and raw journal records start with `SRD5`. V4 prevents traces from
the older planning-only promise semantics from being reinterpreted as authoritative fast delivery;
`SRD5` prevents older record layouts from decoding as the current ECHO/VOTE/ACK/READY journal.

Hash-sorting recovered carriers is not a valid reconstruction rule. Byzantine equivocation can make
arrival order determine which value a local slot-global guard selects, and a different restart order
could make one honest authority appear to send conflicting phases.

The Core store has a bounded latest-frontier receipt shape and can atomically persist an application
commit with that receipt, but that alone is not a complete actor-to-Core recovery handshake. Until
startup re-emits exactly the actor-WAL frontier suffix newer than Core's durable cursor, applies it
before the `Ready`/application-production barrier, and rejects a cursor the actor cannot reconcile,
a crash between actor durability and Core application remains a fail-stop boundary. Actor replay
must not be described as exactly-once output without that composed contract.

The proof model retains all proof-critical carrier, phase, prefix, and consensus state for the run.
The executable runtime admits at lookahead `2` and bounds newly arriving unsolicited content at
lookahead `64` solely to keep a faulty or descheduled peer from growing the benchmark process
without limit. This is not a protocol-safe retirement rule: an honest carrier may be delayed more
than 64 rounds under asynchrony. Recovery of an exact already-requested value is exempt. Before
authoritative garbage collection is enabled, the design needs a common certified or committed
retirement watermark that preserves:

- pending four-phase totality and exact-content recovery;
- exact self-prefix expansion from the last committed frontier;
- committed-anchor reconstruction for a late validator; and
- deterministic replay of local locks.

Resource bounds still required before authoritative deployment include a proof-safe future and
retirement window, per-peer candidate caps, a fair bounded phase backlog, bounded peer/network
bridges, a rate-limited control heartbeat, a bounded payload runahead policy, and checkpointed
disk-backed recovery. The actor's primary ingress is bounded, but not every bridge, per-peer outbox,
or retained reducer collection is yet bounded end to end. Resource exhaustion is excluded from the
initial proof model and must be measured in the prototype. Any run in which work is shed is invalid
for direct/shadow comparison;
`starfish_rbc_dag_shadow_comparison_valid` must remain `1` for the entire measured interval. A live
pipeline does not have equal cumulative direct and shadow delivery counters at an arbitrary
instant: the embedded four-phase protocol normally leaves a short shadow tail. Benchmark verification therefore
requires monotone nonzero direct, shadow, and paired-match progress, no conflict outcome, and bounds
both the current unpaired slots (`<= 4n` per validator) and the oldest unpaired round lag against the
newest current-process observation (`<= 4`). These are empirical benchmark coverage guards, not
asynchronous protocol bounds; a run exceeding either guard is discarded rather than treated as
proof of a protocol failure.

The actor reserves the full hard 64-entry queue so several fan-in bursts can wait behind a slow
reference transition (including synchronous fsync in the crash-safe profile), capping queued
maximum-sized carrier bodies at 256 MiB (plus sidecars and allocator overhead). Mirror mode budgets
one peer fan-in plus five local/control inputs and accepts
at most 60 validators. Autonomous mode budgets a simultaneous carrier, exact-slot request, and
exact-slot response per peer plus five control inputs and accepts at most 20 validators. Larger runs
are rejected rather than silently producing incomplete evidence. Timer notifications are coalesced,
healthy proactive rounds receive a repair grace period, and exact synchronization is rate-limited
per peer. Exact synchronization transfers only one requested `(author, round)` and only from the
author's retained local outbound map. It has no range response, certified checkpoint, observer
history, or bounded-suffix state-transfer protocol; a sufficiently late or fresh node cannot be
reconstructed by this mechanism alone.

Autonomous benchmark validity is separate from delivery comparison validity.
`starfish_rbc_dag_shadow_clock_valid` must remain `1`, the appended-WAL and local-carrier counters
must progress, an idle heartbeat must have been observed, the carrier round and embedded-RBC
delivery count must advance during the measured interval,
recovery must drain, and the reported clock-state/backlog and cross-node skew must remain within the
configured empirical guards. These checks establish that the observational carrier plane stayed
live and bounded; they are not a partial-synchrony proof.

## 15. Safety obligations

The design is not complete until at least the following claims are proved or falsified by a model:

1. **Receiver-authentication integrity.** An honest receiver admits a carrier attributed to an
   honest author only if that author created the public proof or the receiver's MAC entry. A MAC is
   not public non-repudiation, and a Byzantine endpoint knows its own pairwise key.
2. **Four-phase agreement and integrity.** Target-author exclusion, the `M/C/O/V/Q` intersections,
   slot-global ECHO/VOTE/ACK/READY locks, per-sender phase locks, and exact value binding prevent
   conflicting authoritative deliveries at honest validators.
3. **Fast-predicate safety.** `a > F` really implies an honest author, and an `O = M + b` ECHO set
   contains enough honest non-author support to make the value unique and force the fallback to
   converge on it.
4. **RBC totality and certification.** If one honest validator authoritatively delivers a value,
   VOTE/ACK convergence, READY amplification, heartbeats, and exact holder recovery cause every
   honest validator to deliver it and eventually record the same `Q`-READY certificate.
5. **Admission isolation.** Mere authentication/admission can change fast pacing and phase replay,
   but cannot alter a QC, leader decision, skip, commit, or output. Only a proved authoritative
   delivery predicate plus prefix/DA/projection gates crosses that boundary.
6. **Weak-edge non-poisoning.** A missing or equivocating weak parent cannot block delivery,
   projection of unrelated honest vertices, or application ordering.
7. **Consensus-slot uniqueness.** Honest validators create/vote once per
   `(author, consensus_round)`, and Byzantine conflicts cannot both acquire honest quorum support.
8. **Prefix and join comparability.** Every accepted frontier component is an exact extension of
   its strong ancestors, and every cumulative committed join is monotone on exact lineage.
9. **Projection safety.** Erasing weak edges and optional consensus metadata that is not
   `VertexProjected` leaves a valid execution of the Starfish commit/skip rules over immutable
   strong edges; it does not erase otherwise orderable carrier payloads.
10. **Deterministic ordering.** Equal committed-anchor histories imply equal cumulative frontier
    joins, closures, deltas, and transaction order at all honest validators.
11. **Data availability.** No application enters an output delta until Core contains the concrete
    block and its committed transaction root has been reconstructed and verified.

## 16. Liveness obligations

Under partial synchrony and fair processing, the design must establish:

1. Honest authors of aggregate stake at least `Q` continually create authenticated carriers after
   GST, so the sequential fast clock advances without Byzantine participation.
2. Empty heartbeat carriers drain every honest ECHO/VOTE/ACK/READY backlog even when application load is
   zero.
3. Every honest carrier is authoritatively delivered and eventually `Q`-READY certified at every
   honest validator.
4. Existing Starfish data availability eventually closes every honest author's exact carrier
   prefix.
5. Honest consensus vertices with quorum strong parents continue to appear despite arbitrary
   Byzantine weak parents, malformed optional vertices, and carrier/consensus round skew.
6. The projected Starfish pacemaker eventually commits infinitely many honest anchors.
7. Honest frontier construction is fair: every newly closed honest carrier prefix is eventually
   included in a committed frontier.
8. Waiting for a committed delta cannot block forever for honest applications because every named
   exact carrier is already authoritatively delivered and the concrete application DA condition is
   part of frontier eligibility.

The guaranteed payload-liveness statement covers every honest on-prefix carrier. Selectively
disseminated, malformed, or off-prefix Byzantine carriers may be ignored.

## 17. Required executable tests

The executable model and composed runtime tests should cover at minimum:

- `n = 4, f = 1` and `n = 7, f = 2` all-honest progress;
- split Byzantine author values and receiver-selective poisoned vector entries;
- valid relayed local MAC entries and invalid vector variants;
- weighted and unequal-stake `F/a/U/b/M/C/O/V/Q` threshold goldens, including `a > F`;
- ECHO/VOTE/ACK/READY local locks, per-sender replay/equivocation, ordered batch replay, and restart;
- `M` ECHO to VOTE, `C` ECHO-or-VOTE to ACK, `C` ACK to READY, `O` authoritative delivery, and
  independent `Q`-READY certification;
- evidence-before-content recovery from phase holders, including VOTE/ACK without local admission;
- vector-bearing phase-holder recovery that grants normal relayed admission only for a valid local
  authenticator entry, falls back without blame for poisoned variants, preserves the frozen
  content-only response, and replays the exact relayed provenance and sidecar after restart;
- zero application load with heartbeat-only RBC completion;
- independent logical-C2 timeout scheduling without changing the physical heartbeat, plus
  coalesced producer notification ordering in which an already-published application wins a newly
  opened carrier round before queued phase-only work;
- two-round admission, 64-round authenticated retention, and future carriers that cannot jump the
  local sequential clock;
- `f` permanently missing weak parents without blocking honest carrier or consensus progress;
- an authoritatively delivered Byzantine carrier above an unavailable self-chain gap;
- conflicting Byzantine consensus vertices in one logical slot;
- explicit vote/no-vote conflicts and direct plus indirect commit/skip;
- different projection arrival orders where a later direct certificate precedes an earlier
  indirect anchor, with byte-identical committed-leader and cumulative frontier-delta sequences;
- frontier fork, regression, and strong-parent dominance rejection;
- concurrent committed anchors producing the same cumulative joined frontier and byte-identical
  output deltas without regression;
- delayed concrete Core data availability followed by eventual prefix inclusion, with raw payload
  receipt unable to bypass the gate;
- crash points before and after each persisted lock and outbound-carrier write; and
- crash points before and after Core frontier application, including atomic receipt/commit,
  exact-replay idempotence, conflicting/stale cursor rejection, suffix replay before `Ready`, and
  explicit failure of the buffered-WAL crash-safety case; and
- persisted actor restart with byte-identical local retransmission, poisoned-tag candidate
  retention, exact recovery, and no phase/output exposure before its matching durable locks; and
- autonomous actor progress at `n = 4` and `n = 7`, no steady-state repair polling on healthy
  proactive rounds, exact-slot synchronization with idempotent late responses and per-peer rate
  limiting, multi-round convergence after a validator falls behind, control-only WAL reopen,
  distinct authentication namespace, V4/`SRD5` stale-trace rejection, and bounded exact-slot sync
  that does not pretend to be checkpoint transfer; and
- composed frontier-authority runs in which every exact application header is authoritatively
  delivered, all honest nodes release the same deterministic application order without duplicates,
  the direct INIT/phase/batch/pull paths and legacy committer have no authority, and the
  frontier/application/WAL progress gates remain valid.

Property tests should mutate every canonical field and verify carrier-reference binding, while
golden tests freeze the V1 control and V2 application encodings, append-only phase codes, and flat
vector length.

## 18. Complexity and benchmark plan

The first fair benchmark matrix includes:

- plain Starfish with Ed25519 and each ML-DSA choice;
- the unsafe `starfish-mac` dissemination lower bound;
- implemented direct `starfish-rbc` with the same authentication choices;
- `starfish-rbc-dag` in MAC-vector and signature modes; and
- Sailfish++ as a certified signature-free comparison.

Hold committee, load, transaction size, topology, latency injection, dissemination fanout, duration,
timeouts, and build constant. Report carrier, vector, ECHO, VOTE, ACK, READY, content-only recovery,
vector-bearing recovery, payload, and synchronization bytes separately. Also report authentication CPU, fast-admission-to-delivery
latency, carrier/consensus round skew, prefix lag, commit latency, throughput, and peak retained
state.

Batching can reduce the number of separately scheduled RBC control messages, but it does not remove
their logical quorum evidence. Full-vector all-to-all transport sends `n` tags in each of `n - 1`
copies per carrier, so it is not expected to improve author egress until a tree or bounded-fanout
transport is added. Comparison mode sends both direct and embedded transcripts; standalone mode
does not. The default crash-safe reference profile applies preflighted transitions in place but
fsyncs every accepted transition and still performs synchronous reducer/storage work, so it is a
correctness/replay instrument rather than a fair latency profile. The explicit buffered-WAL profile
keeps the exact framed event path but syncs only on clean shutdown and therefore cannot support
crash-safety claims. Benchmark output reports appended and durable WAL work separately.

A matched 10-validator local sequence on 2026-08-11 used a full 60-second active transaction
window, the AWS RTT emulator, nominal 1,000 tx/s load, MAC authentication, and the buffered
benchmark WAL. Milestone-five idle carriers use the same resolved 600 ms Push leader timeout as
Starfish-RBC; application and encodable phase carriers are immediate. The harness waits through
generator warmup, snapshots cumulative counters at the active boundary, and drains final latency
samples. The table and milestone narrative below predate the current four-phase V4 authority model
and remain historical evidence rather than a current-protocol result.

| Profile | Verdict | TPS | Block latency | E2E latency | Outbound |
|---|---:|---:|---:|---:|---:|
| Direct Starfish-RBC, shadow off | n/a | 972.25 | 1,508.0 ms | 1,724.0 ms | 0.53 MB/s |
| Autonomous RBC-DAG, buffered WAL | VALID 10/10 | 971.37 | 1,498.9 ms | 1,714.0 ms | 0.58 MB/s |
| Embedded RBC authoritative (milestone five) | VALID 10/10 | 861.92 | 3,539.3 ms | 5,477.5 ms | 0.52 MB/s |
| Certified projection (milestone six) | VALID 10/10 | 799.07 | 5,102.9 ms | 8,650.9 ms | 0.50 MB/s |
| Frontier output authority (milestone seven) | VALID 10/10 | 950.25 | 2,020.9 ms | 2,082.6 ms | 0.70 MB/s |
| Autonomous RBC-DAG, per-transition fsync | INVALID 9/10 | 948.83 | 2,569.1 ms | 3,067.4 ms | 0.54 MB/s |

The valid buffered run reached carrier round 275 at every validator, with 2,749 accepted
heartbeats, 27,180 embedded-RBC deliveries, 27,424 appended batches, zero round skew, and zero
pending recovery. Its latency and throughput match the shadow-off baseline while making the
expected extra carrier traffic visible. The crash-safe run shed shadow work and is reported only
as a diagnostic: it isolates synchronous persistence as a severe observer effect and must not be
cited as a protocol result.

The milestone-five run delivered 10,722 application headers through embedded RBC, reached carrier
rounds 458–459, and ended with zero pending recovery. Its direct ECHO and READY paths were disabled;
the composed four-validator test also asserts zero such outbound messages. Its higher latency is
not evidence for a bad 250 ms timer—the independent timer was removed, and the same Starfish
timeout was used. It exposes the transitional clean-predecessor gate: the existing direct Starfish
DAG still serializes proposal creation on embedded delivery.

The milestone-six run reached carrier rounds 356–359 with 35,506 carrier deliveries, 8,059
application deliveries, 8,487 clean projected vertices, 830 clean direct commits, and zero pending
recovery. It validates the certified-projection structure, not final performance. The logical
committer currently runs beside the legacy clean-predecessor/output path, so this transitional run
pays for both and its 5.1/8.7-second latency is a red flag rather than a protocol target. Milestone
seven must make committed frontier deltas the sole ordering/output path before latency is compared
as the complete RBC-DAG protocol.

Milestone seven removes that legacy output gate. Its valid run reached carrier round 795 at every
validator, delivered 79,035 application carriers, released 77,870 exact applications through 1,880
committed frontiers, projected 19,000 vertices, and ended with zero pending recovery. The in-place
fail-stop reducer, incremental projection indexes, and event-local delivery/data-availability paths
also remove the prototype's history-wide hot-path scans. Block/E2E latency fell by 60.4%/75.9% from
milestone six while throughput recovered to 950.25 tx/s. The remaining 2.02/2.08-second latency is
not the target: follow-up profiling must shorten the certified consensus-round/frontier pipeline
toward the roughly 600 ms unsafe Starfish-MAC reference without weakening RBC or frontier safety.

## 19. Contained implementation milestones

The historical milestones produced the current bounded prototype:

1. **Canonical carrier plane (implemented):** V1 control and V2 application carrier identities,
   full-vector sidecars, two independent clocks, ordered phase batches, exact recovery, and
   deterministic codec/model/journal tests.
2. **Weighted optimistic RBC (implemented):** author-excluding ECHO/VOTE/ACK thresholds, READY
   fallback/certification, the high-stake honest-author branch, `O` authoritative delivery, and
   durable slot-global locks for every phase.
3. **Standalone authority boundary (implemented, opt-in):** carriers and the dedicated verified
   application-payload path are the only ingress authority. The direct INIT/phase/header service,
   generic batch/pull path, and legacy application committer are absent or rejected.
4. **Logical consensus and output (implemented):** independently numbered vertices, quorum strong
   parents, explicit Vote/NoVote choices, exact prefixes, authoritative projection, Starfish
   commit/skip, cumulative joined committed frontiers, and deterministic application deltas.
5. **Durable actor replay (implemented within the documented scope):** V4/`SRD5` WAL replay restores
   retained content, phase/delivery/consensus locks, locally authored outbound bytes, and projection
   state. This is not a claim of full validator restart or general late-node state transfer.
6. **Remaining production work:** complete the end-to-end proof; bound every queue and retained
   collection; add proof-safe checkpoints, state transfer, retirement, and graceful shutdown; then
   compare latency with direct `starfish-rbc`, unsafe `starfish-mac`, signature variants, and
   Sailfish++ before attempting tree dissemination.

## 20. Decisions intentionally deferred

The following production choices remain unresolved and must be proved or measured:

- production maximum future-carrier buffer and payload runahead (the executable prototype keeps
  admission lookahead `2`, retains at most `64` future rounds for temporarily descheduled peers,
  and discards farther unsolicited carriers before admission/retention; these are benchmark resource
  parameters rather than protocol safety constants);
- whether the logical C2 timeout needs a separately proved adaptive low-load rule; the prototype
  exposes an experimental override but intentionally does not introduce a second physical
  heartbeat timeout;
- a safe state-retirement, garbage-collection, and late-catch-up watermark;
- whether all supported storage backends are required before authoritative mode;
- quantitative shadow-promotion thresholds and acceptable latency/bandwidth regression; and
- the tree topology, redundancy, and fallback timers.

Mixed direct/standalone or incompatible carrier/WAL deployments must be rejected. The current code
has fail-closed protocol/storage namespaces but no feature handshake, so homogeneous configuration
is an operational precondition. A dedicated `starfish-rbc-dag` selector should be added only with
explicit capability/version negotiation.
