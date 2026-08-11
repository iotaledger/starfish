# Starfish-RBC-DAG protocol design

Status: milestone-four persisted, non-authoritative optimistic carrier-clock shadow; no
authoritative protocol, safety/liveness, or performance claim

The provisional CLI name for the eventual protocol is `starfish-rbc-dag`. That selector is not
implemented. The milestone-three direct-header comparison runtime is enabled with `--consensus
starfish-rbc --starfish-rbc-dag-shadow`. Milestone four adds a separate control-only runtime with
`--starfish-rbc-dag-autonomous-clock`; its carrier rounds advance independently through
authenticated admission and empty heartbeats. Performance experiments may add
`--starfish-rbc-dag-shadow-buffered-wal` to remove per-transition disk synchronization; that
profile is explicitly not crash-safe. Both modes leave the direct prototype's DAG,
pacemaker, commit, and output unchanged. The eventual protocol is new, not a transport option or a
version-two alias for `starfish-rbc`.

The implemented [`starfish-rbc`](starfish-rbc-protocol.md) prototype remains the conservative
baseline: it sends Bracha INIT/ECHO/READY as direct network messages, advances Starfish only through
RBC-delivered dependency-closed headers, and sends one initial MAC tag to each recipient. This
document instead specifies an optimistic carrier DAG that embeds the reliable-broadcast transcript,
uses a complete committee-sized MAC vector on every MAC-authenticated carrier, and separates fast
carrier pacing from certified consensus ordering.

The two designs may share canonicalization, cryptography, storage, and benchmark code, but they are
not wire-compatible and do not have the same proof obligations. Nothing in this document changes
the behavior of `starfish-rbc` or any existing protocol.

## 1. Objective and non-claims

The objective is to recover the pipelining of an uncertified Starfish DAG without allowing
optimistically received Byzantine blocks to affect safety:

- a fast physical carrier DAG advances on a quorum of locally authenticated carriers;
- every application carrier is also the value of a Bracha reliable-broadcast instance;
- later carriers batch ECHO and READY statements for earlier carriers;
- only RBC-delivered, data-available information enters the logical consensus projection; and
- committed consensus frontiers eventually order every honest on-prefix application carrier.

The initial research mode sends the complete ordered MAC vector with every carrier. The vector is
an authentication sidecar and is not part of the carrier digest. Ed25519, ML-DSA-44, and ML-DSA-65
remain selectable outer-authentication baselines; changing that selector does not change the
embedded RBC or consensus rules.

This is a proposed composition. The reliable-broadcast thresholds are standard, and the Starfish
commit rules already exist. Milestone two provides a canonical codec plus deterministic
carrier/RBC, certified-projection, decision, and crash-journal models. Milestone three adds an
opt-in persisted shadow actor, full-vector carrier transport, recovery messages, and paired
direct/shadow delivery observations. Milestone four adds an independently authenticated autonomous
heartbeat namespace, sequential `Q`-admitted carrier clock, bounded future buffering, exact-slot
synchronization, and clock-state metrics. The direct `starfish-rbc` service remains the only
authority: shadow admission, delivery, recovery, clock advancement, or failure cannot advance a
proposal, mark a DAG vertex clean, vote, commit, or order output.

Autonomous mode is intentionally control-only at this milestone. It ignores direct application
headers and uses a distinct WAL and authentication protocol instance. This avoids falsely equating
direct consensus rounds with faster carrier rounds, but also means milestone four does not yet
measure application latency through the new carrier DAG. Application-origin assignment and the
certified consensus projection remain later milestones.

Shadow restart coverage is deliberately scoped to reopening the actor and its WAL: mirror mode
requires an identical recovered direct-header history, while autonomous mode reopens its
control-only heartbeat history without direct headers and serves byte-identical exact-slot
responses. This is not a full validator crash-recovery claim. The authoritative direct
`starfish-rbc` baseline does not yet durably record its remote-slot
ECHO/READY choices, delivery locks, or retained phase evidence. Restarting that baseline after it
has proposed a non-genesis block can therefore forget proof-critical choices and leave the newest
recovered own header dirty. Full validator restart remains fail-stop until those direct-RBC locks
are persisted and replayed; replaying only the observational shadow WAL cannot repair or safely
substitute for them.

That isolation is logical, not physical: shadow frames share the validator's existing TCP
connections, outbound queues, bandwidth, and CPU process with direct RBC, so enabling the shadow
can perturb authoritative timing even though no shadow result is consumed by consensus. Version
one has no feature handshake. Every validator in a shadow run must use a binary that understands
the append-only shadow wire variants and the flag must be deployed committee-wide; an older peer
will reject an unknown bincode variant and may close the shared connection. Mixed-version or
partially enabled runs are not valid comparisons. Mirror and autonomous carriers derive distinct
authentication protocol instances so they cannot cross-admit, but this fail-closed boundary is not
a substitute for capability negotiation.

Shadow shutdown is bounded so an observational WAL failure cannot indefinitely block validator
shutdown. If that timeout fires, the blocking worker may still hold the shadow WAL's single-writer
handle even after its async supervisor is detached. A same-process restart against that storage is
therefore forbidden until the worker has exited; process exit remains safe. A production-quality
same-process restart path needs an operating-system file lock or a fully cancellable storage task.

The shadow runtime is not a proof or a production performance implementation. Its default
crash-safe profile intentionally fsyncs every accepted transition, and its reference reducer clones
retained model/journal history. A separate explicit benchmark profile writes the same ordered,
checksummed frames but syncs them only on clean shutdown; it reports appended and durable records
separately and makes no crash-safety claim. This removes the known persistence observer effect
without changing the protocol reducer. The runtime also uses a fixed unsolicited-retention window
only as a benchmark resource guard; that window is not a safe asynchronous pruning rule. Until the
composition and resource bounds are completed, `starfish-rbc-dag` remains an experimental
shadow/reference implementation rather than a proven signature-free Starfish variant.

The milestone-two model accepts `DataAvailable` as a trusted input from the existing verified
Reed-Solomon/reconstruction layer. It models the resulting prefix and ordering transitions, but not
payload reconstruction or the runtime transition from delivered acknowledgments to that input.

Transaction bytes remain outside header RBC. The existing Reed-Solomon dissemination,
acknowledgment, reconstruction, and transaction-commitment checks remain responsible for data
availability.

## 2. Model and notation

Version one assumes:

- one static, ordered, stake-weighted committee for a run;
- Byzantine stake strictly below one third of total stake;
- pairwise symmetric keys for every ordered validator pair;
- reliable authenticated point-to-point communication after GST;
- a fresh nonzero protocol-instance identifier shared through genesis configuration;
- no committee reconfiguration; and
- no state retirement until a safe recovery watermark is proved.

For total committee stake `W`, use the repository's integer thresholds:

```text
Q = floor(2W / 3) + 1
V = floor(W / 3) + 1
```

For equal stake and `n = 3f + 1`, these are `Q = 2f + 1` and `V = f + 1`.

Two independent round numbers are used:

- `carrier_round` belongs to the fast physical DAG and advances from authenticated admission;
- `consensus_round` belongs to the certified logical Starfish projection.

There is no fixed mapping between them. Carrier rounds may run ahead while a consensus vertex is
waiting for RBC delivery, data availability, a leader decision, or certified strong parents.

## 3. One physical DAG, two logical projections

The only network DAG objects are carriers. A carrier contains application-header data, a bounded
batch of RBC control statements, and optionally one consensus vertex.

The same stored objects have two disjoint interpretations:

1. **Optimistic carrier projection.** Authenticated carriers and their weak parent references pace
   carrier creation and transport RBC statements. This projection is allowed to differ temporarily
   between honest validators.
2. **Certified consensus projection.** Eligible consensus vertices, immutable strong parents, and
   certified delivery frontiers drive Starfish voting, certification, skip/commit decisions, and
   linearization. Honest validators eventually agree on this projection.

Weak carrier edges never become strong/order edges, even if their targets later deliver. A node
must not construct its own filtered consensus parent set from an optimistic carrier after the fact:
that would make the authenticated content have different consensus meaning at different nodes.

This separation prevents a Byzantine carrier from poisoning an honest carrier. A quorum-sized weak
parent set can contain up to `f` selectively disseminated or invented Byzantine references. Waiting
for all such references to become RBC-delivered would make the honest child permanently unusable.
Weak edges are therefore permanently nonblocking and nonordering. Only the explicitly encoded
strong parents and certified frontier constrain consensus.

## 4. Canonical objects

The milestone-two codec implements the following logical types. Field widths, enum codes, maximum
lengths, and golden bytes are frozen before runtime integration.

```rust
struct CarrierHeaderV1 {
    author: AuthorityIndex,
    carrier_round: RoundNumber,

    // Physical pacing only. `own_prev` is not repeated in `weak_parents`.
    own_prev: BlockReference,
    weak_parents: Vec<BlockReference>,

    transactions_commitment: TransactionsCommitment,
    data_acknowledgments: Vec<BlockReference>,
    phase_batch: Vec<RbcPhaseStatementV1>,
    consensus_vertex: Option<ConsensusVertexV1>,
    creation_time_ns: TimestampNs,
}

enum RbcPhaseStatementV1 {
    Echo { target: BlockReference },
    Ready { target: BlockReference },
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
carrier. An outer authenticator therefore authenticates the whole batch without a separate tag or
signature per statement.

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
headers need not be present to authenticate, admit, process, or RBC-deliver the enclosing carrier.

Acknowledgments have one canonical logical order: first the unique maximal suffix shared with
`[own_prev] || weak_parents`, then all remaining acknowledgments in their original relative order.
The content digest commits to this expanded, suffix-first sequence, while the wire codec stores the
shared suffix as an intersection index and retains the order-significant extras. Non-canonical wire
aliases and duplicate acknowledgments are rejected. An honest author creates an acknowledgment
only after the exact target is locally RBC-delivered and its transaction data reconstructs to the
committed root. The acknowledgment becomes usable as data-availability evidence only after its
enclosing carrier is also locally RBC-delivered; an optimistically admitted Byzantine carrier
cannot create inconsistent availability facts at different validators.

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
integers, and explicit vector lengths. It does not add a `starfish:block-ref:v2` string to the block
identity. The format byte and unambiguous grammar distinguish this carrier layout; changing the
layout requires a new version and new golden vectors. The canonical identity codec is handwritten;
serde or bincode framing is never hashed.

Milestone two freezes the version-one identity grammar as follows. `Ref` is
`author:u16 || carrier_round:u32 || digest:[u8;32]`; every integer is big-endian and every vector
count is `u16`.

```text
00 01
01 author:u16
02 carrier_round:u32
03 own_prev:Ref
04 weak_count:u16 weak:Ref[]
05 transactions_commitment:[u8;32]
06 acknowledgment_count:u16 expanded_acknowledgments:Ref[]
07 phase_count:u16 (phase:u8 target:Ref)[]       // ECHO=0, READY=1
08 consensus_present:u8 [ConsensusVertexV1]
09 creation_time_ns:u64
```

The optional consensus encoding uses markers `01` through `04` for consensus round, strong
parents, delivery frontier, and leader choice. A strong reference is `Ref || consensus_round:u32`;
frontier entries use `0=None` and `1=Some(Ref)`; leader choices use `1=Vote` and `2=NoVote` (`0` is
reserved for virtual genesis and is rejected on the wire). The canonical transport codec replaces
the expanded acknowledgment field with `intersection_start:u16 || extra_count:u16 || extras`, where
the intersection is the unique maximal suffix of `[own_prev] || weak_parents`. Decoding expands and
recompresses this field and rejects aliases. To keep the two byte grammars self-describing, this
compressed transport form starts with `00 81`; only expanded identity content starts with `00 01`.

Version one caps canonical carrier content at 4 MiB, weak and strong parents at the committee size,
the frontier at exactly the committee size when projected, and encoded phase batches at
`min(4n, 2048)`. The `4n` bound gives two times the expected `2n` steady-state phase arrival rate;
the scheduler still needs the fair-prefix and active-window rules described in Section 8.3.

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
STARFISH_RBC_DAG_V1
carrier-authentication kind and scheme
protocol_instance
committee_id
author A
recipient Q_q
carrier_round
canonical carrier content digest
```

The full vector accompanies every normally disseminated MAC carrier in version one, including
relayed carriers. A receiver verifies only the entry at its own committee index. It neither verifies
nor vouches for the remaining entries.

A carrier received directly from its author and the same carrier received through a relay are both
authentication-eligible when the local entry verifies. This is receiver-specific transferable
authentication: it survives a relay for its intended recipient, but it is not a publicly verifiable
signature and provides no non-repudiation.

The vector is deliberately not an RBC value and has no consistency invariant. A Byzantine author
may attach different vectors to the same content reference, including a vector with a valid tag for
one recipient and garbage for another. Correctness therefore depends only on the local entry and on
the embedded Bracha protocol, never on agreement about the vector bytes.

Each node persists one exact vector variant with its carrier for restart and relay. The preference
order is locally generated, directly author-received, then first relayed variant with a valid local
entry. Version one does not merge unverified entries from different vectors. Header recovery after
authenticated quorum phase evidence may return canonical content without a vector; that recovery
can unblock RBC delivery but does not create optimistic carrier admission.

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

Delivered
    local Bracha instance reached Q READY and pinned matching canonical content

PrefixClosed
    Delivered && DataAvailable && exact own_prev prefix is closed

VertexProjected (orthogonal to the carrier lifecycle)
    this carrier's optional consensus vertex is eligible in the certified projection

Included
    a committed Starfish anchor frontier names this carrier in its deterministic delta

Ordered
    the complete included delta is available and the carrier has been deterministically output
```

`Candidate` alone permits bounded staging and digest-based recovery. `CarrierAdmitted` permits
immediate phase-batch processing and fast-pacemaker counting. `Delivered` permits phase replay even
at a node whose author MAC entry was poisoned. `PrefixClosed` permits frontier inclusion.
`VertexProjected` alone permits the optional vertex to supply Starfish
vote/certifier/leader evidence. It is not a later state of every carrier: a carrier with no eligible
optional vertex may still become prefix-closed, included by another anchor's frontier, and ordered.

The existing generic `dirty` bit is not a synonym for `CarrierAdmitted`: current RBC code may stage
content after invalid initial authentication or during recovery. Reusing that bit would let an
unauthenticated candidate advance the fast clock.

| Consumer | Required local authority |
|---|---|
| Header retention/recovery | `Candidate` |
| Process embedded RBC statements | `CarrierAdmitted`, or `Delivered` for replay |
| Fast carrier clock | `CarrierAdmitted` |
| Transaction/shard synchronization | `Candidate` |
| Count a data-availability acknowledgment | `Delivered` enclosing carrier |
| Delivery frontier | `PrefixClosed` target carrier |
| Starfish QC, skip, and anchor commit | `VertexProjected` consensus vertex |
| Application payload output | `Included` delta, with every member delivered/data-available |

The initial implementation should keep fast-pacemaker counting exactly at `CarrierAdmitted`; using
`Delivered` as an additional stronger pacing input can be added only if the executable model shows
that it cannot change the sequential slot accounting.

## 7. Fast carrier pacemaker

The carrier clock is sequential and does not use the current threshold-clock helper's ability to
jump to a far-future round after one message.

For each carrier round, a validator records at most one admitted reference per author. Byzantine
equivocations may make different honest validators record different references for a Byzantine
author, but each author contributes stake once. A validator advances from carrier round `r` to
`r + 1` only after:

1. its own carrier at round `r` has been fixed and persisted; and
2. it has admitted distinct-author carrier stake `Q` at round `r`.

Future carriers are bounded and buffered; they do not skip missing local rounds. The next local
carrier records the selected quorum as `{ own_prev } union weak_parents`. A missing weak-parent body
never blocks the next carrier or any later consensus action.

This clock replaces the current `starfish-rbc` rule that requires a quorum of RBC-clean previous
round headers before proposal. It does not make admitted carriers consensus votes. Leader/vote/skip
waiting conditions move to the independent consensus projection and cannot block the creation of a
carrier needed to transport ECHO or READY.

Honest validators emit empty control heartbeats when they have no application transactions.
Without heartbeats, low load can stop the ECHO/READY waves and violate RBC liveness. Every carrier,
including an empty heartbeat, is itself an RBC value and has an authenticator sidecar.

The first prototype retains the current run's carrier/RBC state and rate-limits carrier creation.
A production design needs a proved runahead and backpressure rule. A hard carrier/consensus skew cap
must not suppress control heartbeats, because those heartbeats may be exactly what allows the
certified frontier to catch up.

## 8. Embedded all-carrier reliable broadcast

There is one RBC slot for every physical carrier:

```text
RbcSlot = (protocol_instance, committee_id, carrier_author, carrier_round)
RbcValue = BlockReference
```

Authenticating the carrier is INIT for that value. The local author records its own ECHO when it
atomically fixes and persists the carrier. An honest non-author that first admits a value queues one
ECHO for that slot.

INIT is not silently counted as the author's ECHO at remote validators. The author's recorded local
ECHO is queued into a later carrier like every other phase action; it counts locally immediately and
remotely only after the enclosing carrier is admitted or delivered. This preserves the standard
quorum accounting without excluding the broadcaster's stake.

Local phase actions are inserted into the next possible carrier's `phase_batch`. The enclosing
carrier's authentication makes its author the phase sender. For each target slot:

- an authority emits at most one ECHO;
- an authority emits at most one READY;
- ECHO and READY choices may differ;
- `Q` ECHO stake creates a READY obligation;
- `V` READY stake creates a READY obligation; and
- `Q` READY stake plus pinned matching content locally delivers the exact carrier.

A READY obligation is not yet a local READY. If the target content is absent, the validator first
recovers it from authenticated ECHO/READY authors, validates the exact reference, and durably pins
it. Only then does it persist the slot-global READY lock, count its local READY, and enqueue the
statement. Consequently every honest READY author is a real content holder. A quorum trigger remains
latched while recovery is pending.

Local ECHO and READY count toward their thresholds before network dissemination. Evidence is
tracked per candidate, while local send and delivery locks are slot-global. Each remote authority
contributes stake at most once per phase and target slot; exact replay is idempotent and a later
equivocation is ignored before allocating another candidate.

### 8.1 Processing rule

After canonical validation and outer authentication, a receiver processes the phase batch in its
canonical encoded order immediately. It must not wait for the enclosing carrier itself to be RBC
delivered, data-available, dependency-closed, or projected. Waiting would create a recursion: a
carrier's controls are required to deliver earlier carriers, while those earlier deliveries may be
required to create the next consensus vertex.

If the local carrier authenticator is missing or invalid, its phase batch is not processed on
candidate receipt. If that exact outer carrier later becomes locally RBC-delivered, the stored batch
may be replayed under the local delivery capability. Thus poisoned vector entries delay optimistic
admission but cannot permanently suppress controls selected by RBC.

Phase targets are strictly older carrier rounds, making a single carrier's replay acyclic. Local
arrival order between different authenticated carriers is still observable and can affect which
Byzantine equivocation encounters a slot-global guard first. Recovery must replay the persisted
ingress journal, never reconstruct choices by sorting carriers after a restart.

### 8.2 Header recovery

An honest ECHO or READY author must retain the target carrier content. A validator that observes a
threshold before receiving the target requests it from several recorded phase authors. Recovery
content is accepted only when canonical validation recomputes the requested reference.

Recovery request/response remains an out-of-band data-transfer optimization in the first
prototype. It is not quorum testimony and does not change the on-DAG phase transcript. A `Q` ECHO
set contains honest holders, and a `V` READY set contains at least one honest holder, so retrying
authenticated holders eventually obtains the value after GST.

### 8.3 Batching and fairness

Phase batches are bounded. The encoded order is preserved and processed as an authenticated log;
two different orders intentionally identify different carriers. A deterministic fair queue must
prevent Byzantine traffic for one slot
from starving honest ECHO/READY actions for other slots. In steady state, one authority can owe one
ECHO and one READY for each of `n` previous-round carriers, so `2n` is the expected arrival rate and
not a safe capacity. The executable model retains an unbounded pending FIFO and drains the first
`4n` statements eligible for the carrier being built (capped by the version-one codec limit of
2,048 statements). A temporarily ineligible future-round statement remains in its stable queue
position but does not block older eligible work behind it. This exercises backlog, runahead, and
batching without pretending to solve adversarial fairness. A bounded runtime must use a fair
per-slot scheduler, reserve strictly more than `2n` statements per carrier, and enforce an
active-slot window so delayed work drains instead of remaining at permanent saturation.

## 9. Certified consensus vertices

A carrier contains zero or one `ConsensusVertexV1`. The carrier remains valid and pace-eligible if
the optional vertex is malformed relative to local certified state; only the optional vertex is
excluded from the consensus projection.

A consensus vertex authored by `A` at consensus round `c > 0` is eligible only when:

1. its enclosing carrier is locally RBC-delivered;
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
only over eligible consensus vertices:

- **A1:** advance from `c - 1` to `c` after eligible distinct-author stake `Q` at `c - 1`;
- **A2:** do not advance until the local consensus vertex at `c - 1` has been fixed;
- **C1:** create at `c` after the eligible leader at `c - 1` is present and the eligible projection
  contains either `Q` votes for an exact leader value or a valid explicit direct-skip pattern for
  the leader slot at `c - 2`;
- **C2:** create after the consensus leader timeout; or
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

RBC delivery alone is not a compact availability proof for a Byzantine author's later carrier. A
Byzantine author may deliver round `r` with an `own_prev` that names an unavailable fork at
`r - 1`. Therefore a frontier component is a contiguous exact prefix, not simply the highest
delivered round.

For authority `A`, begin at its fixed genesis/empty prefix. A carrier `(A, r, R)` extends the local
closed prefix only when:

- `R` is locally RBC-delivered;
- its transaction data satisfies the existing Starfish availability predicate;
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
enclosing carrier is delivered and data-available, its **effective frontier** replaces that one
component with the enclosing carrier. This makes a committed anchor's own application payload
eligible without waiting for a later anchor while preserving exact prefix continuity.

The liveness target is deliberately precise:

> Every honest carrier that RBC-delivers and becomes data-available eventually appears in a
> committed effective-frontier delta.

No guarantee is made for a malformed or permanently off-prefix Byzantine carrier. Guaranteeing all
RBC-delivered Byzantine forks would require an antichain or sparse exception structure rather than
one compact prefix tip per authority.

## 11. Starfish certification, commit, and skip

Starfish's logical leader schedule and commit rules run over eligible consensus vertices only.
Carrier admission, weak parents, phase targets, candidate headers, and merely delivered carriers
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

Skipping a Byzantine leader role discards only that optional consensus value. It does not discard
the enclosing application carrier. If that carrier later becomes part of a closed prefix, a later
committed frontier orders its payload.

Every consensus consumer in the current Starfish committer must be audited for the new type
boundary: voter caches, leader support, potential certificates, direct/indirect decisions,
reachability, and the linearizer must reject non-projected carrier facts. Data-availability
acknowledgments are the deliberate exception: they become usable when their enclosing carrier is
RBC-delivered, which breaks a projection/availability circularity while still excluding merely
optimistic evidence.

## 12. Frontier-delta linearization

Let `F_k` be the effective frontier carried by committed anchor `A_k`, and let `Closure(F_k)` be the
union of the exact per-author self-chain prefixes named by `F_k`. Maintain:

```text
C_0   = fixed genesis carriers
C_k   = C_(k-1) union Closure(F_k)
Delta = C_k \ C_(k-1)
```

Before outputting `Delta`, a validator waits until every exact member is locally RBC-delivered and
data-available. RBC totality and erasure-coded recovery supply missing content for honest committed
frontiers.

All validators deterministically order the same delta by
`(carrier_round, author, content_digest)`. Because a closed author prefix advances by exactly one
carrier round, this key already preserves mandatory `own_prev` order.

Weak parents, strong consensus edges, optional-vertex projection time, ECHO/READY target references,
recovery provenance, and MAC-vector variants never constrain application payload ordering. Strong
edges order consensus decisions and dominate frontiers, but a late-projecting optional vertex must
not retroactively add an edge between payloads already output. This fixed ordering also ensures that
a dangling Byzantine weak edge cannot reintroduce the liveness failure that the two-projection
design removes.

## 13. Expected optimistic schedule

In an all-honest synchronous interval, batching can realize this conceptual schedule:

```text
t = 0       carrier k contains a new application header (RBC INIT)
t = delta   carrier k+1 contains ECHOs for k
t = 2delta  carrier k+2 contains READYs for k
t = 3delta  carrier k is RBC-delivered; a later carrier may project new consensus work
```

The embedded design does not make Bracha RBC require fewer communication delays than the direct
baseline. Its performance hypothesis is that carrier batching reduces frames, scheduling work, and
duplicated control metadata while the fast carrier clock overlaps certification with dissemination.

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
3. persist local ECHO, READY, explicit leader-choice, delivery, carrier-slot, and consensus-slot
   locks that match that retained candidate (recovered content is likewise retained before READY);
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
cannot satisfy a local lock or quorum.

Hash-sorting recovered carriers is not a valid reconstruction rule. Byzantine equivocation can make
arrival order determine which value a local slot-global guard selects, and a different restart order
could make one honest authority appear to send conflicting phases.

The proof model retains all proof-critical carrier, phase, prefix, and consensus state for the run.
The milestone-three shadow bounds newly arriving unsolicited content to a fixed recent-round
window solely to keep a faulty peer from growing an observational benchmark process without limit.
This is not a protocol-safe retirement rule: an honest INIT may be delayed longer than that under
asynchrony. Recovery of an exact already-requested value is exempt. Before authoritative garbage
collection is enabled, the design needs a common certified or committed retirement watermark that
preserves:

- pending Bracha totality and header recovery;
- exact self-prefix expansion from the last committed frontier;
- committed-anchor reconstruction for a late validator; and
- deterministic replay of local locks.

Resource bounds still required before authoritative deployment include a proof-safe future and
retirement window, per-peer candidate caps, a fair phase backlog, a rate-limited control heartbeat,
a bounded payload runahead policy, and checkpointed disk-backed recovery. Shadow input and output
channels are bounded and shed observational work instead of backpressuring direct consensus, but
the reference reducer's retained history and per-transition validation are not yet bounded-runtime
architecture. Resource exhaustion is excluded from the initial proof model and must be measured in
the prototype. Any run in which work is shed is invalid for direct/shadow comparison;
`starfish_rbc_dag_shadow_comparison_valid` must remain `1` for the entire measured interval. A live
pipeline does not have equal cumulative direct and shadow delivery counters at an arbitrary
instant: embedded ECHO/READY normally leaves a short shadow tail. Benchmark verification therefore
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
per peer. Requested historical slots remain recoverable beyond the benchmark-only unsolicited
retention window.

Autonomous benchmark validity is separate from delivery comparison validity.
`starfish_rbc_dag_shadow_clock_valid` must remain `1`, the appended-WAL and heartbeat counters must progress,
the carrier round and embedded-RBC delivery count must advance during the measured interval,
recovery must drain, and the reported clock-state/backlog and cross-node skew must remain within the
configured empirical guards. These checks establish that the observational carrier plane stayed
live and bounded; they are not a partial-synchrony proof.

## 15. Safety obligations

The design is not complete until at least the following claims are proved or falsified by a model:

1. **Receiver-authentication integrity.** An honest receiver admits a carrier attributed to an
   honest author only if that author created the public proof or the receiver's MAC entry. A MAC is
   not public non-repudiation, and a Byzantine endpoint knows its own pairwise key.
2. **RBC agreement and integrity.** Slot-global ECHO/READY locks, quorum intersection, and exact
   value binding prevent two conflicting carrier values from being delivered by honest validators.
3. **RBC totality.** If one honest validator delivers a value, heartbeats, READY amplification, and
   holder recovery cause every honest validator eventually to deliver the same value.
4. **Optimistic isolation.** Carrier admission can change only fast pacing and RBC processing; it
   cannot alter a QC, leader decision, skip, commit, acknowledgment certificate, or output order.
5. **Weak-edge non-poisoning.** A missing or equivocating weak parent cannot block delivery,
   projection of unrelated honest vertices, or application ordering.
6. **Consensus-slot uniqueness.** Honest validators create/vote once per
   `(author, consensus_round)`, and Byzantine conflicts cannot both acquire honest quorum support.
7. **Prefix comparability.** Every accepted frontier component is an exact extension of its strong
   ancestors and of every earlier committed component.
8. **Projection safety.** Erasing weak edges and optional consensus metadata that is not
   `VertexProjected` leaves a valid execution of the Starfish commit/skip rules over immutable
   strong edges; it does not erase otherwise orderable carrier payloads.
9. **Deterministic ordering.** Equal committed anchors imply equal frontier closures, deltas, and
   transaction order at all honest validators.
10. **Data availability.** No carrier enters an output delta until its committed transaction root
    can be reconstructed and verified.

## 16. Liveness obligations

Under partial synchrony and fair processing, the design must establish:

1. `Q` honest authors continually create authenticated carriers after GST, so the sequential fast
   clock advances without Byzantine participation.
2. Empty heartbeat carriers drain every honest ECHO/READY backlog even when application load is
   zero.
3. Every honest carrier is RBC-delivered at every honest validator.
4. Existing Starfish data availability eventually closes every honest author's exact carrier
   prefix.
5. Honest consensus vertices with quorum strong parents continue to appear despite arbitrary
   Byzantine weak parents, malformed optional vertices, and carrier/consensus round skew.
6. The projected Starfish pacemaker eventually commits infinitely many honest anchors.
7. Honest frontier construction is fair: every newly closed honest carrier prefix is eventually
   included in a committed frontier.
8. Waiting for a committed delta cannot block forever because every named exact carrier is already
   RBC-delivered and data-available by frontier eligibility.

The guaranteed payload-liveness statement covers every honest on-prefix carrier. Selectively
disseminated, malformed, or off-prefix Byzantine carriers may be ignored.

## 17. Required executable tests

Milestone two begins with an isolated deterministic model, not production network wiring. At
minimum it must cover:

- `n = 4, f = 1` and `n = 7, f = 2` all-honest progress;
- split Byzantine INIT values and receiver-selective poisoned vector entries;
- valid relayed local MAC entries and invalid vector variants;
- ECHO/READY equivocation, replay, reordering, and evidence-before-header recovery;
- zero application load with heartbeat-only RBC completion;
- future carriers that cannot jump the local sequential clock;
- `f` permanently missing weak parents without blocking honest carrier or consensus progress;
- a delivered Byzantine carrier above an unavailable self-chain gap;
- conflicting Byzantine consensus vertices in one logical slot;
- explicit vote/no-vote conflicts and direct plus indirect commit/skip;
- frontier fork, regression, and strong-parent dominance rejection;
- equal committed anchors producing byte-identical output deltas;
- delayed data availability followed by eventual prefix inclusion;
- crash points before and after each persisted lock and outbound-carrier write; and
- persisted shadow-actor restart with byte-identical retransmission against an identical recovered
  direct-header history, bounded overload, poisoned-tag candidate retention, exact recovery, and
  paired delivery observations against the current direct RBC kernel. Full validator restart is
  excluded until the authoritative direct-RBC locks are durable; and
- autonomous actor progress at `n = 4` and `n = 7`, no steady-state repair polling on healthy
  proactive rounds, exact-slot synchronization with idempotent late responses and per-peer rate
  limiting, multi-round convergence after a validator falls behind, control-only WAL reopen,
  distinct authentication namespace, and an integration check that direct Starfish-RBC continues
  committing while the observational carrier clock advances.

Property tests should mutate every canonical field and verify carrier-reference binding, while
golden tests freeze the version-one encoding and flat vector length.

## 18. Complexity and benchmark plan

The first fair benchmark matrix includes:

- plain Starfish with Ed25519 and each ML-DSA choice;
- the unsafe `starfish-mac` dissemination lower bound;
- implemented direct `starfish-rbc` with the same authentication choices;
- `starfish-rbc-dag` in MAC-vector and signature modes; and
- Sailfish++ as a certified signature-free comparison.

Hold committee, load, transaction size, topology, latency injection, dissemination fanout, duration,
timeouts, and build constant. Report carrier/INIT, vector, ECHO, READY, recovery, transaction/shard,
and synchronization bytes separately. Also report authentication CPU, fast-admission-to-delivery
latency, carrier/consensus round skew, prefix lag, commit latency, throughput, and peak retained
state.

Batching can reduce the number of separately scheduled RBC control messages, but it does not remove
their logical quorum evidence. Full-vector all-to-all transport sends `n` tags in each of `n - 1`
copies per carrier, so it is not expected to improve author egress until a tree or bounded-fanout
transport is added. Shadow mode also sends both direct and embedded transcripts. The default
crash-safe reference profile fsyncs each accepted transition and validates through a clone-based
reducer; it is a correctness/replay instrument, not a protocol-performance result. The explicit
buffered-WAL profile keeps the exact framed event path but syncs only on clean shutdown and therefore
cannot be used for crash-safety claims. Benchmark output reports appended and durable WAL work
separately. The clone-based reducer remains intentionally unoptimized until measurement shows it
matters.

A matched 10-validator local A/B on 2026-08-11 used a full 60-second active transaction window,
the AWS RTT emulator, nominal 1,000 tx/s load, MAC authentication, and a 250 ms autonomous
heartbeat. The harness waits through generator warmup, snapshots cumulative counters at the active
boundary, and drains final latency samples.

| Profile | Verdict | TPS | p50 block | p50 E2E | Outbound |
|---|---:|---:|---:|---:|---:|
| Direct Starfish-RBC, shadow off | n/a | 972.25 | 1,508.0 ms | 1,724.0 ms | 0.53 MB/s |
| Autonomous RBC-DAG, buffered WAL | VALID 10/10 | 971.37 | 1,498.9 ms | 1,714.0 ms | 0.58 MB/s |
| Autonomous RBC-DAG, per-transition fsync | INVALID 9/10 | 948.83 | 2,569.1 ms | 3,067.4 ms | 0.54 MB/s |

The valid buffered run reached carrier round 275 at every validator, with 2,749 accepted
heartbeats, 27,180 embedded-RBC deliveries, 27,424 appended batches, zero round skew, and zero
pending recovery. Its latency and throughput match the shadow-off baseline while making the
expected extra carrier traffic visible. The crash-safe run shed shadow work and is reported only
as a diagnostic: it isolates synchronous persistence as a severe observer effect and must not be
cited as a protocol result. Neither run measures application latency through the carrier DAG yet,
because the direct Starfish-RBC path remains authoritative in milestone four.

## 19. Contained implementation milestones

Every milestone is committed separately.

1. **Protocol specification (this document):** lock the two clocks, lifecycle, full-vector sidecar,
   embedded Bracha transitions, certified prefix/frontier, commit/skip boundary, proof obligations,
   and experiment plan. No protocol code or CLI selector is added.
2. **Canonical codec and executable model (implemented):** isolated carrier, phase, consensus,
   frontier, and sidecar types; golden encodings; pure carrier/RBC, projection/decision, and durable
   journal models; and deterministic adversarial simulations. No network or existing consensus path
   changes.
3. **Persisted shadow carrier path (implemented, opt-in):** build and store carriers alongside the
   current direct `starfish-rbc` service, cache the validated committee/domain identity rather than
   re-hashing all public keys per carrier, journal ingress and local locks, and compare embedded
   versus direct RBC delivery through current-process paired observations. Direct RBC remains
   authoritative; shadow results never affect proposals or commits. The reference WAL/reducer is a
   correctness instrument, not yet an interpretable protocol-performance path.
4. **Optimistic carrier clock (implemented, opt-in control shadow):** run a separately namespaced,
   control-only heartbeat carrier plane with the distinct authenticated-admission latch, sequential
   quorum clock, bounded future buffer, exact-slot synchronization, durable restart, and clock
   validity metrics while consensus still uses the current direct baseline. Application headers are
   not assigned to autonomous carrier rounds yet.
5. **Authoritative embedded RBC:** remove direct ECHO/READY authority only after shadow tests show
   identical delivery under reordering, loss, equivocation, poisoned tags, and restart.
6. **Certified consensus projection:** add optional consensus vertices, strong parents, explicit
   leader choice, contiguous delivery frontiers, and strict clean-only committer consumers.
7. **Frontier linearizer and recovery:** commit deterministic frontier deltas, persist/reconstruct
   prefixes and anchors, and add late-node and crash/restart tests.
8. **Benchmarks:** compare the complete protocol with direct `starfish-rbc`, unsafe `starfish-mac`,
   signature Starfish variants, and Sailfish++ before attempting tree dissemination.
9. **Tree dissemination:** distribute vector sub-bundles with redundant routing and a direct timeout
   fallback; do not change RBC or consensus semantics.

## 20. Decisions intentionally deferred

The following values are not safe to guess in the documentation milestone and must be resolved by
the executable model or measured prototype:

- production maximum future-carrier buffer and payload runahead (the executable model deliberately
  uses admission lookahead `2` and hard buffer lookahead `4` only as test parameters);
- the production control-heartbeat rate under low load and backpressure (the autonomous shadow's
  configurable 250 ms default is an empirical test value, not a protocol constant);
- a safe state-retirement, garbage-collection, and late-catch-up watermark;
- whether all supported storage backends are required before authoritative mode;
- quantitative shadow-promotion thresholds and acceptable latency/bandwidth regression; and
- the tree topology, redundancy, and fallback timers.

Mixed `starfish-rbc`, `starfish-rbc-dag`, and version-one/version-two deployments must be rejected
by protocol-instance negotiation. The provisional `starfish-rbc-dag` selector is added only after
the codec/model milestone establishes a distinct stable version.
