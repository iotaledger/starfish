# Starfish-RBC protocol specification

Status: design milestone, not implemented

This document specifies the first correctness-oriented prototype of Starfish with reliable header
certification and a signature-free MAC configuration. The provisional CLI name is `starfish-rbc`.

The protocol is intentionally conservative. It reuses plain Starfish for transaction-data
availability, DAG ordering, and commitment, while adding a Bracha reliable-broadcast layer for
block headers. It uses the same validator, committee, networking, storage, orchestrator, and
benchmark setup as the other protocols in this repository.

This document is not a claim that the protocol is already proved or implemented. The motivating
work-in-progress note gives reliable-delivery and MAC-vector ingredients, but does not prove their
composition with Starfish. The proof obligations below must be discharged before making a safety
or liveness claim.

## 1. Goals

The first prototype has five goals:

1. Replace transferable block signatures with receiver-specific MAC authentication without
   allowing a Byzantine author to make a block permanently acceptable to only part of the honest
   committee.
2. Preserve `BlockReference.digest` as a hash of canonical block content only. Authentication
   remains a sidecar and does not change block identity.
3. Certify only the Starfish header, including its transaction commitment. Transaction payload
   availability remains the responsibility of Starfish's existing Reed-Solomon and acknowledgment
   layer.
4. Keep the reliable-broadcast message flow identical while selecting Ed25519, ML-DSA-44,
   ML-DSA-65, or a MAC vector for the author's initial header authentication. This gives an
   apples-to-apples comparison.
5. Establish a correctness baseline before adding tree dissemination, fast paths, or early
   uncertified consensus participation.

The current `starfish-mac`, `starfish-speed-mac`, `sparse-starfish-speed-mac`, and
`bluestreak-mac` modes remain lower-bound benchmark experiments. Changing only their block
authentication does not turn them into complete Byzantine protocols.

Conceptually, selection is represented as two independent fields rather than copied protocol
variants:

```text
ProtocolConfig {
    consensus: StarfishRbc,
    initial_header_authentication: Ed25519 | MlDsa44 | MlDsa65 | Mac,
}
```

The consensus selector enables RBC and the clean-DAG rules. The authentication selector changes
only `HeaderProposal.initial_authentication`.

## 2. Version-one scope

Version one assumes:

- a static committee for the duration of a run;
- Byzantine voting stake strictly below one third of total stake;
- reliable point-to-point communication after GST in the usual partially synchronous model;
- fixed pairwise MAC keys provisioned by the benchmark setup;
- honest validators remain online for the run; and
- no committee reconfiguration or epoch transition.

Let `W` be total committee stake. Version one uses the repository's exact integer thresholds:

```text
Q = floor(2W / 3) + 1
V = floor(W / 3) + 1
```

The transitions are `Q` ECHO stake to READY, `V` READY stake to READY, and `Q` READY stake to
delivery. For an equal-stake committee with `n = 3f + 1`, these are `2f + 1`, `f + 1`, and
`2f + 1`. Locally sent ECHO and READY actions count toward these thresholds.

The following are out of scope for version one:

- crash/restart safety and replay of locally observed phase evidence;
- production key establishment, rotation, or compromise recovery;
- BLS control certificates;
- Starfish-Speed, Sparse-Starfish-Speed, and Bluestreak integration;
- tree or bounded-fanout header dissemination;
- Sailfish's optimistic `VOTE`/fast-delivery path;
- the `DONE` reliable-delivery optimization;
- encoding ECHO and READY as DAG protocol blocks; and
- adversarial resource-exhaustion resistance beyond fixed message-size checks.

These exclusions constrain the first implementation, not the eventual research direction.

## 3. Protocol identity and authenticated statements

### 3.1 Slot and value

One reliable-broadcast instance exists for each slot:

```text
Slot = (protocol_instance, committee_id, author, round)
```

The value proposed in a slot is a canonical Starfish header. Its identifier is the existing:

```text
BlockReference = (author, round, content_digest)
```

`content_digest` commits to the existing canonical header content, including the transaction
commitment, parent references, acknowledgments, and other consensus-relevant fields. It does not
commit to the initial authentication sidecar or to reliable-broadcast messages.

`protocol_instance` and `committee_id` are domain-separation inputs. They are not added to
`BlockReference`. Their exact derivation must be fixed before implementation; a committee/genesis
identifier is preferable to a human-readable CLI string.

Header processing has three distinct gates:

1. **Content validation** is deterministic and view-independent. It checks the canonical digest,
   intrinsic field relationships, committee/round bounds, the committed transaction root, and
   protocol syntax without requiring the local initial proof, transaction data, a shard, or locally
   available dependencies.
2. **Initial authentication** determines only whether this validator may send ECHO for the
   candidate.
3. **DAG admission and clean activation** resolve dependencies and determine whether the delivered
   header can influence Starfish.

The implementation must not keep these gates bundled in the current all-or-nothing block verifier.

### 3.2 Initial header authentication

The configured block-authentication method applies only to the author's initial header proof:

- Ed25519 and ML-DSA sign a domain-separated statement containing the slot and content digest.
- In MAC mode, author `A` creates one receiver-specific tag for each validator `Q`:

```text
InitialTag(A, Q, block_ref) =
    MAC[k(A,Q)](INITIAL || Slot || block_ref || A || Q)
```

The ordered collection of these tags is the conceptual MAC vector. With direct dissemination,
each recipient receives only its own entry. The full vector is not transmitted to every peer.

The local author does not need to authenticate its header to itself. Local construction is the
author's ECHO eligibility evidence; only messages sent to other validators need receiver-specific
initial tags.

A valid initial proof permits an honest recipient to ECHO the header. It does not by itself make
the header clean, globally available, or safe to commit.

### 3.3 Phase-message authentication

ECHO and READY use pairwise MAC authentication for every initial header-authentication variant.
For phase sender `S` and recipient `Q`:

```text
PhaseTag(S, Q, phase, block_ref) =
    MAC[k(S,Q)](RBC_PHASE || Slot || phase || block_ref || S || Q)
```

The concrete encoding must use fixed-width, canonical fields and distinct domain values for
INITIAL, ECHO, and READY. The protocol must not rely on ambiguous string concatenation.

An inbound phase message counts only if all of the following hold:

- its recipient is the local validator;
- its sender is a known committee member;
- its claimed sender equals the peer on the direct connection;
- its pairwise MAC verifies for that sender and recipient;
- its slot fields agree with its block reference; and
- it belongs to the active protocol run and retained slot window.

A forwarded or replayed phase message received from another peer never counts, even if its bytes
contain a valid tag addressed to the receiver. Local ECHO/READY actions are counted locally and do
not require a loopback network message.

## 4. Messages

Version one uses the following logical messages:

```text
HeaderProposal {
    slot,
    canonical_header,
    initial_authentication,
}

Echo {
    slot,
    block_ref,
    sender,
    recipient,
    phase_tag,
}

Ready {
    slot,
    block_ref,
    sender,
    recipient,
    phase_tag,
}

HeaderRequest {
    slot,
    block_ref,
}

HeaderResponse {
    slot,
    canonical_header,
}
```

ECHO and READY contain a block reference, not the header. This avoids rebroadcasting each header
quadratically. Header request/response traffic transports data only and is never counted as quorum
testimony.

An honest ECHO or READY sender must possess the matching content-validated header. Consequently,
when a threshold is observed before the local header arrives, the receiver can request the header
from recorded direct ECHO or READY senders. A response is accepted only after recomputing the
content digest and validating the header's structure.

`CanonicalHeader` excludes the initial-authentication sidecar. A `HeaderResponse` therefore neither
needs nor confers a valid local initial proof. It supplies the content bytes needed for a transition
that is authorized by the receiver's own directly authenticated RBC evidence.

The RBC header-retrieval path never asserts transaction-payload availability. Shards and full
transaction data continue to use the existing Starfish paths.

## 5. Local state

State is keyed by slot, with evidence separated by candidate block reference:

```text
SlotState {
    echoed: Option<BlockReference>,
    readied: Option<BlockReference>,
    delivered: Option<BlockReference>,
    candidates: Map<BlockReference, CandidateState>,
}

CandidateState {
    header: Option<CanonicalHeader>,
    initial_authentication_valid: bool,
    echo_senders: AuthoritySet,
    ready_senders: AuthoritySet,
    echo_quorum_observed: bool,
    ready_validity_observed: bool,
    ready_quorum_observed: bool,
    dirty_admitted: bool,
    rbc_delivered: bool,
    clean: bool,
}
```

The `echoed`, `readied`, and `delivered` guards are slot-global, not per digest. Evidence is kept per
digest so that Byzantine equivocation can be observed without locking the receiver to the first
value it sees.

In particular:

- an honest validator sends at most one ECHO in a slot;
- an honest validator sends at most one READY in a slot;
- the READY value need not equal the value previously ECHOed, because a later quorum may select a
  different value; and
- an honest validator delivers at most one value in a slot.

For correctness in version one, slot-global locks, phase evidence, threshold latches, and headers
advertised by an honest local phase action are retained for the whole benchmark run. Unsupported
candidate bodies may be evicted because they can be fetched again by digest, but eviction must not
discard evidence or a pending transition. A proved retirement boundary and adversarial storage
bounds are deferred with crash/restart support; arbitrary cache eviction is not a protocol action.

Sending a local phase is one atomic state transition: set the slot-global guard, insert the local
authority into that candidate's phase-sender set, and enqueue separately authenticated messages for
all other validators. Threshold checks include this local evidence.

## 6. State machine

### 6.1 Receiving an initial header

On `HeaderProposal` for candidate `R`:

1. Validate committee membership, slot consistency, header syntax, canonical content digest,
   protocol-specific fields, and resource bounds.
2. Store the fixed-size-checked, content-valid header as a candidate even if its local initial
   authenticator is missing or invalid. This permits later RBC delivery to repair a poisoned
   recipient tag.
3. Verify that version one's proposal was received directly from the claimed author, then verify the
   selected initial authentication method for the local recipient. For the local author's own
   header, successful local construction supplies this evidence without a loopback signature or
   MAC.
4. If the direct-author check and proof are valid and the slot-global ECHO guard is empty, record the
   local ECHO immediately and send a recipient-specific ECHO for `R` to every other validator.
   Header RBC does not wait for parents, acknowledgments, transaction data, or a shard to arrive.
5. Independently, connect the candidate to the dirty DAG through the normal dependency manager once
   its dirty dependencies are present. This follows Sailfish's dirty/clean setup and does not make
   the candidate consensus-visible.

A relayed header may be retained as a content-valid candidate, but it does not trigger ECHO in
version one. Tree dissemination later changes this eligibility rule to accept a relayed
receiver-specific author proof and must extend the integrity argument accordingly.

### 6.2 Receiving ECHO

On a valid direct `Echo(R, S)`:

1. Record `S` once in `R.echo_senders`. A Byzantine sender may appear in the evidence sets of
   multiple conflicting candidates, but its stake counts only once per candidate.
2. When ECHO stake for `R` reaches `Q`, latch `echo_quorum_observed` and:
   - if the header is absent, request it from multiple recorded ECHO senders;
   - validate and store the returned header; and
   - once the header is present, send READY for `R` if the slot-global READY guard is empty.

An ECHO quorum never bypasses content validation.

Each honest validator counts its own locally recorded ECHO, including when that validator is the
slot author. It also sends ECHO to every other validator. The implementation must not inherit
Sailfish++'s current exclusion of the block author from ECHO stake: at `n = 3f + 1`, excluding an
honest author's ECHO leaves only `2f` honest non-author ECHOs and lets `f` Byzantine validators stop
honest-author progress by withholding theirs.

### 6.3 Receiving READY

On a valid direct `Ready(R, S)`:

1. Record `S` once in `R.ready_senders`.
2. When READY stake for `R` reaches `V`, latch `ready_validity_observed` and:
   - if the header is absent, request it from multiple recorded READY senders;
   - validate and store the returned header; and
   - once the header is present, send READY for `R` if the slot-global READY guard is empty.
3. When READY stake for `R` reaches `Q`, latch `ready_quorum_observed`. Once the validated header is
   present, locally deliver `R` if the slot-global delivery guard is empty. Emit a local
   RBC-delivery event; do not construct a purportedly transferable certificate from the observed
   pairwise MACs.

READY amplification and delivery are independent of whether the local initial header proof was
valid. This is the mechanism that repairs selective or poisoned author-to-recipient MAC entries.

### 6.4 Header retrieval

Every honest ECHO and READY sender is a header holder. Retrieval therefore proceeds as follows:

1. Select multiple direct phase senders as candidate sources.
2. Request the exact `BlockReference`.
3. Accept the first response whose recomputed digest and structural validation match.
4. Re-evaluate all latched ECHO/READY triggers immediately after storing the header.
5. Continue requesting while threshold progress is blocked and untried holders remain.

At least one honest holder exists in every `V`-stake READY set. At least `f + 1` honest holders exist
in an equal-stake `2f + 1` ECHO quorum. Byzantine responses can delay retrieval but cannot change
the accepted content. An honest validator that sends ECHO or READY retains the canonical header
until the instance's state is safely retired; in version one, that means the end of the run.

## 7. Dirty and clean DAG integration

Starfish-RBC follows the dual dirty/clean organization already used by Sailfish++ and other
certified variants.

The lifecycle predicates are distinct:

```text
candidate = canonical header is content-valid
dirty     = candidate is DAG-admitted but not yet clean
delivered = local READY evidence reached Q for the candidate
clean     = delivered candidate has clean referenced dependencies
```

Transaction-data availability is a separate predicate throughout this lifecycle.

### 7.1 Dirty state

A locally authenticated, dependency-connected header may enter the dirty DAG before RBC delivery.
Dirty state may support:

- candidate retention;
- parent fetching;
- header and shard synchronization; and
- RBC progress.

Dirty state must not influence proposal eligibility, parent selection, Starfish votes,
acknowledgments, leader decisions, ordering, or commitment.

### 7.2 Clean activation

A header becomes clean only when:

- the local RBC instance delivered that exact `BlockReference`;
- the header is present and content-valid;
- every direct parent is present and clean; and
- every referenced block whose acknowledgment could influence Starfish sequencing is present and
  clean.

RBC delivery and clean activation require neither transaction data nor a local shard. Here, clean
means that the canonical header is reliably delivered and dependency-closed. A Starfish
acknowledgment requires both `clean(header)` and `data_available(header)`.

RBC delivery may therefore precede clean activation. A Byzantine delivered header with a dangling
dependency remains outside the clean DAG and cannot block progress by honest clean vertices.

Local RBC delivery is an alternative admission authority to the author's initial proof. If the
local initial tag was invalid or missing, the delivered header is inserted through an
RBC-authorized path and may become clean after its dependencies do. No forwarded evidence bundle
can exercise this path; it requires the local slot state to have reached delivery.

The generic dual-DAG rule that infers cleanliness from `f + 1` references in later rounds is
disabled for `starfish-rbc`. Only local RBC delivery can supply the certification predicate;
descendant references are neither a replacement certificate nor transferable evidence of the
direct phase messages observed elsewhere.

### 7.3 Starfish-specific clean-only rules

For `starfish-rbc`:

- honest proposals select only clean parents;
- proposal-round advancement requires a clean quorum in the preceding round;
- a transaction-data acknowledgment is queued only after its target is both data-available and
  clean;
- clean activation rechecks acknowledgment eligibility when transaction data arrived first;
- voting and certifying blocks counted by the Starfish committer must be clean;
- committed leaders must be clean;
- the linearizer follows only clean parent and acknowledgment references; and
- a block cannot be committed merely because it exists in the dirty DAG.

The existing generic dual-DAG helpers are useful but do not by themselves enforce all of these
Starfish acknowledgment and linearizer rules. Each consumer must be audited explicitly.

## 8. Initial dissemination

Version one uses direct author-to-all dissemination:

- Ed25519 and ML-DSA send the same public signature to every recipient.
- MAC mode sends each recipient only its own 32-byte initial tag.
- All modes then run exactly the same pairwise-MAC ECHO/READY protocol.

Every ECHO and READY broadcast is materialized separately for each recipient because its phase tag
binds that recipient. A broadcaster must never clone one serialized, tagged phase message to all
peers. The sender records its own phase action locally instead of creating a loopback tag.

This direct strategy is the correctness baseline. It deliberately separates reliable-delivery
correctness from routing failures.

A later tree-dissemination milestone may send a relay the tags for its assigned subtree and let it
forward smaller sub-bundles. That optimization must include redundant paths or a timeout fallback;
a single tree containing a Byzantine relay is not live. Tree dissemination must not alter the RBC
state machine or its clean-DAG rules.

Under the motivating paper's broad definition, an author-to-recipient MAC that remains verifiable
after a third party relays it is transferable authentication for that intended recipient, although
it is not a publicly verifiable signature. The future tree variant therefore lies outside the
paper's no-transferable-authentication lower bound and needs its own integrity argument.

## 9. Safety argument to complete

The implementation and accompanying proof must establish at least the following lemmas.

### 9.1 Honest-author integrity

If an honest validator ECHOs a header attributed to an honest author, the author created the
matching initial proof. An adversary cannot produce an honest recipient's valid initial MAC or a
valid public signature for a different header.

The recipient of a pairwise MAC also knows its key and could fabricate a tag addressed to itself.
An honest recipient follows the protocol and never does so. Byzantine recipients control less than
one-third stake and therefore cannot create an ECHO quorum for a value that no honest recipient
authenticated. The later relayed-INIT variant must state this argument explicitly rather than
claiming public non-repudiation from a MAC.

### 9.2 Unique ECHO quorum

Two conflicting values cannot both obtain more than two-thirds ECHO stake. Their ECHO sets
intersect in more than one-third stake, which contains an honest validator; the slot-global ECHO
guard prevents that validator from ECHOing both.

### 9.3 Unique READY value

The first honest READY for a value is rooted in an ECHO quorum. Subsequent honest READY messages
are rooted either in that quorum or in more than one-third READY stake, which contains an honest
READY sender. Therefore honest READY propagation cannot originate independently for two values.

### 9.4 Reliable-delivery agreement and totality

If one honest validator delivers `R`, more than one-third honest stake sent READY for `R`. Reliable
direct delivery of those READY messages causes every honest validator to amplify READY and
eventually observe a quorum. Header-holder retrieval gives every honest validator the exact bytes
needed to deliver `R`.

### 9.5 Starfish composition

Only locally delivered, dependency-closed clean headers influence Starfish. Reliable delivery
provides a consistent value for each author/round slot and prevents false attribution to an honest
author. The Starfish safety argument must then be checked over the clean DAG, including its
acknowledgment-based linearizer.

These lemmas are proof obligations. They are not established merely by reusing Sailfish++ code.

## 10. Liveness argument to complete

For an honest author after GST:

1. Direct dissemination eventually gives every honest validator the header and a valid initial
   proof.
2. Honest parent selection ensures the referenced parent closure is eventually clean everywhere.
3. All honest validators ECHO the same reference.
4. Every honest validator observes ECHO quorum, sends READY, observes READY quorum, and delivers.
5. The header becomes clean once its already-clean dependencies are locally present.
6. At least quorum honest stake can therefore produce clean vertices in every live round, allowing
   plain Starfish to advance and commit.

The proof must also show that dirty Byzantine candidates, missing initial tags, invalid phase MACs,
and dangling Byzantine dependencies cannot influence clean Starfish state or prevent an honestly
scheduled quorum from progressing. Fair processing despite Byzantine traffic is assumed;
resource-exhaustion resistance is outside the version-one model.

## 11. Required adversarial tests

Implementation begins with deterministic tests for the failure modes, not only happy-path smoke
tests.

### 11.1 RBC unit tests

- `n = 4, f = 1`: a Byzantine author gives candidate X to one honest validator and candidate Y to
  two others. A validator that first saw X must still process quorum traffic for Y.
- A Byzantine author provides valid initial tags to enough validators to form an ECHO quorum but
  gives D an invalid or missing tag; D does not ECHO but eventually retrieves and delivers the same
  header through READY evidence.
- A Byzantine author distributes valid receiver tags for conflicting headers; at most one value is
  delivered by honest validators.
- One sender's duplicate ECHO or READY counts once.
- The slot author's locally recorded ECHO and directly received ECHOs count toward the ECHO quorum;
  excluding the author makes the `n = 3f + 1` honest-sender case non-live when all Byzantine
  validators withhold.
- Byzantine senders may equivocate across values without making an honest sender violate its
  slot-global guards.
- Invalid, wrong-recipient, wrong-phase, stale, and wrong-slot phase MACs are rejected.
- A valid phase message replayed through a different peer is not counted as direct testimony.
- ECHO or READY quorum without local header triggers retrieval and does not advance until a valid
  matching header is present.
- A threshold reached before header retrieval remains latched and fires immediately after the
  matching header is stored.
- A tampered `HeaderResponse` is rejected by content-digest validation.

### 11.2 DAG integration tests

- Locally authenticated but undelivered headers remain dirty.
- RBC-delivered headers with an unclean parent remain outside the clean DAG.
- Cleaning the parent activates the already-delivered child.
- Dirty headers cannot advance the proposal round or become proposal parents.
- Later-round references cannot infer that an RBC-undelivered header is clean.
- Data availability for an unclean target does not queue a Starfish acknowledgment.
- Starfish voting, leader selection, and linearization ignore dirty blocks.
- No honest node commits two values for one `(author, round)` slot.

### 11.3 End-to-end tests

- Four honest validators commit using Ed25519, ML-DSA-44, ML-DSA-65, and MAC initial
  authentication with identical RBC message flow.
- A poisoned-recipient-tag run still lets every honest validator clean and commit the same header.
- Byzantine equivocation does not split committed histories.
- A Byzantine dangling-parent block does not prevent quorum honest progress.
- Header recovery succeeds when quorum evidence arrives before header data.
- Existing protocols retain their current behavior and test results.

Crash/restart tests are intentionally deferred until sent-phase and delivered-slot state is made
durable.

## 12. Benchmark plan

The fair comparison holds Starfish-RBC ordering, reliable broadcast, direct dissemination, load,
committee, topology, and timeout configuration constant. Only initial header authentication varies:

- `starfish-rbc` + Ed25519;
- `starfish-rbc` + ML-DSA-44;
- `starfish-rbc` + ML-DSA-65; and
- `starfish-rbc` + MAC.

Native Starfish with Ed25519 and ML-DSA should also be measured separately. That comparison shows
the total cost of reliable delivery, but it must not be presented as an isolated authentication
comparison because the message flows differ.

Metrics should separate:

- initial header-authentication bytes and CPU;
- ECHO/READY phase-MAC bytes and CPU;
- header proposal, phase, and recovery traffic;
- time from dirty admission to RBC delivery and clean activation;
- block and transaction commit latency;
- throughput and per-node inbound/outbound bandwidth; and
- author egress versus aggregate network traffic.

MAC vectors and public signatures both require each non-author to receive the header in an
all-honest direct run. The expected MAC benefit is proof size, computation, and later author/tree
egress relative to large post-quantum signatures, not a reduction in the number of required
recipients.

Benchmark results should live in experiment artifacts or a concise PR graph/summary, not as
long-lived tables in the protocol documentation.

## 13. Contained implementation boundary

The implementation should add one `StarfishRbc` capability path and one isolated RBC service. It
may reuse networking, stake aggregation, dirty/clean storage, and event plumbing, but must not copy
the following Sailfish++ or legacy MAC behavior:

- per-digest send/delivery guards or first-seen canonical locking;
- exclusion of the block author's ECHO, optimistic `VOTE`, or Sailfish timeout semantics;
- unsigned phase messages without recipient, session context, and a phase MAC;
- cloning one identical phase message to every recipient;
- full-vector direct-author transport when one recipient tag is sufficient;
- an all-or-nothing verifier that combines canonical content with initial authentication; or
- inferred-clean promotion and pre-clean acknowledgment queuing.

Plain Starfish, Starfish-Speed, Sparse-Starfish-Speed, Bluestreak, Sailfish++, and their existing
authentication selections remain behaviorally unchanged. The first prototype does not create an
RBC copy of every protocol.

## 14. Implementation milestones

Each milestone is committed separately.

1. **Specification:** this document, with no protocol code changes.
2. **RBC kernel:** domain-separated phase MACs, slot-global ECHO/READY state, per-value evidence,
   header-holder tracking, and adversarial unit tests.
3. **Header staging and retrieval:** split content validation from initial authentication, add
   fixed-size-checked candidate staging with pending triggers, and fetch headers from direct phase
   senders.
4. **Certified Starfish integration:** add `starfish-rbc`, selectable initial authentication,
   dirty/clean lifecycle, clean-only acknowledgments, and clean-only consensus/linearization.
5. **End-to-end validation:** poisoned-tag, equivocation, dangling-parent, and all-authentication
   commit tests.
6. **Tree dissemination:** subtree tag bundles, redundant routing/fallback, and matching signature
   baselines.
7. **Recovery:** durable phase locks and delivered state, evidence replay, late-node synchronization,
   and restart tests.
8. **Benchmarks:** direct and tree comparisons with results reported outside this specification.

## 15. Decisions still required before implementation

The protocol behavior above is fixed, but implementation must still choose:

- the exact `protocol_instance` and `committee_id` derivation;
- the canonical byte encoding for phase-MAC statements;
- a safe post-v1 state-retirement and garbage-collection rule;
- header-holder request fanout and retry timing;
- the final CLI spelling for MAC authentication; and
- whether legacy unsafe `*-mac` aliases are renamed or retained as lower-bound benchmarks.

None of these choices may weaken the slot-global phase guards, direct-message checks, header
availability requirement, or clean-only Starfish boundary.
