# ADR-0007: Every metaverse property declares what settles it

- **Status:** Accepted 2026-07-31.
- **Deciders:** Project maintainer.
- **Related:** [`ADR-0002`](./0002-sealed-consensus-core.md) (the sealed
  consensus core the proof-of-work class depends on),
  [`ADR-0005`](./0005-offchain-signed-contract-channels.md) (off-chain signed
  state — explicitly *not* a settlement mechanism under this ADR),
  [`SECURITY_AND_INTEGRITY.md`](../SECURITY_AND_INTEGRITY.md),
  [`MVP.md`](../MVP.md) (the distribution gaps this ADR's Limits section
  points at).
- **Numbering note:** requested as `0003`; `0003` was already taken by the
  OS-substrate verdict, so this landed as `0007`.

---

## Context

`lib/metaverse` gives the node one vocabulary for the things it owns. A
property is `(kind, root)` where `root` is the underlying object's own
immutable root as the authoritative model already computes it, and each kind
names the **one existing model that owns its ownership truth** — the third
column of `METAVERSE_KIND_TABLE`, read back at runtime by
`metaverse_kind_authority()`.
<!-- claim: symbol-present METAVERSE_KIND_TABLE lib/metaverse -->
<!-- claim: symbol-present metaverse_kind_authority lib/metaverse -->
This layer mints no identifier of its own and never becomes an authority; it
records which authority to ask.

Naming the authority answers *who to ask*. It does not answer *what makes
that answer expensive to falsify*, and the nine kinds do not share an answer.
A blob's root is checkable by anyone holding the bytes and nobody else's
cooperation. A ZNAM registration is an ordering question that only chain state
answers. A hosted-service row is this node asserting something about itself.
Those are three different security properties wearing one word ("owned"), and
a catalog that renders them identically teaches a reader to trust the weakest
one as much as the strongest.

The distinction the project actually cares about is not "centralised versus
decentralised". It is **how a trust root fails**, which is a narrower and more
checkable question.

A directory authenticated by a fixed set of signing keys fails **silently**.
Its security property is "k of n named parties, in known jurisdictions, are
honest and uncoerced". Compel enough key holders and they emit a document that
is cryptographically perfect and false, and no client can tell from the
artifact that anything happened — the signatures verify, the format is right,
the bytes are what the protocol says they should be. Quiet legal compulsion of
named parties is a routine instrument, and it leaves no trace in the artifact
it produced.

Content addressing and proof of work fail **loudly**. A hash matches or it does
not; there is no third outcome and no party to serve an instrument on. A chain
record can be rewritten only by redoing the work, and anyone holding the
earlier headers observes the reorg. Both mechanisms move the question from
"which named parties are honest right now" to "what can be recomputed from
bytes", and neither can be subverted by an order served on a person.

That asymmetry is the whole claim being made here. It is about **directory
integrity** — who decides what is authentic — and nothing else. The Limits
section below is the other half of the record, and is not optional reading.

## Decision

**Every metaverse property declares which of exactly four mechanisms settles
its ownership, and that declaration is a readable field, not an implicit
property of its kind.** No kind is settled by a signing quorum.

### 1. The four settlement classes

| Class | What must be true for the claim to hold | Who must cooperate |
|---|---|---|
| `CONTENT_ADDRESSED` | the bytes hash to the root | nobody |
| `PROOF_OF_WORK` | a chain record exists at sufficient depth | whoever redoes the work |
| `CHAIN_ANCHORED_INCOMPLETE` | a chain object exists, but this node cannot measure the work above it | whoever redoes the work — unquantified here |
| `LOCAL_DECLARATION` | this node says so | nobody outside this node agrees or disagrees |

`CONTENT_ADDRESSED` is the strongest class and the one most easily undersold.
Verification requires no authority whatsoever, no network, no clock and no
quorum: hash the bytes you hold and compare. It is also the narrowest — it
proves byte identity and says nothing about authorship or title, which is
exactly what `METAVERSE_EVIDENCE_LOCAL_CONTENT_HASH` already documents.

`CHAIN_ANCHORED_INCOMPLETE` exists because the honest answer for one kind was
neither of the other three. It says: there really is a chain object behind this
record, and this node still cannot tell you how much work sits above it. It is
weaker than `PROOF_OF_WORK` and stronger than `LOCAL_DECLARATION`, and the
alternative — a `PROOF_OF_WORK` label with permanently unknown depth and
chainwork under it — would be a claim the numbers never back. See §3.

`LOCAL_DECLARATION` is not a defect to be engineered away. Some things
genuinely are local facts — this node runs this service, this node published
this onion. Recording that honestly is what makes the other two classes
credible, because a reader who finds one overstated claim is right to discount
all of them.

### 2. Assignment for the nine kinds

| Kind | Authority (existing) | Settlement |
|---|---|---|
| `content` | `vcs.blob_store` | `CONTENT_ADDRESSED` |
| `zcode_package` | `vcs.package_store` | `CONTENT_ADDRESSED` |
| `znam_name` | `znam.registry` | `PROOF_OF_WORK` |
| `zslp_asset` | `zslp.ledger` | `PROOF_OF_WORK` |
| `hosted_service` | `service.registry` | `LOCAL_DECLARATION` |
| `endpoint_onion` | `net.onion_service` | `LOCAL_DECLARATION` |
| `storefront_product` | `store.product` | `LOCAL_DECLARATION` |
| `contract_swap` | `swap.contract` | `CHAIN_ANCHORED_INCOMPLETE` (see §3) |
| `character_sheet` | `metaverse.character_sheet` | `CONTENT_ADDRESSED` |

<!-- claim: symbol-present CHAIN_ANCHORED_INCOMPLETE lib/metaverse -->

The table above is the prose form of `METAVERSE_KIND_TABLE` in
`lib/metaverse/include/metaverse/property_id.h`, whose fourth column carries
the settlement class. That table is the authority; if this document and it ever
disagree, the table is right.

`character_sheet` reaches `CONTENT_ADDRESSED` from a different direction than
the two above it, and the difference is worth stating. `content` and
`zcode_package` are content-addressed because a store holds the bytes and the
id is their hash. A character has **no store at all**: its id is the hash of
the birth seed plus the rules revision, and the whole sheet is recomputed from
that seed by `lib/metaverse/src/character_sheet.c`. A node that has never met
the owner verifies a visiting character by hashing what it was handed. That is
the mechanism the class names, so the class is honest — and it is also why the
kind's adapter row is `MV_UNAVAILABLE`: nothing on disk *enumerates* the seeds
this operator holds, which is a separate question from whether one can be
checked.

`znam_name` and `zslp_asset` are the clear proof-of-work members: both are
OP_RETURN records whose meaning is entirely an ordering question — first
registration wins, token supply is the ordered ledger — and ordering is what
the chain settles.

### 3. `contract_swap` — investigated, not assumed

`contract_swap` is the case that decides the shape of this ADR, so it was read
rather than guessed. What proof of work settles for a swap is the **outcome**:
whether the HTLC output is spent through the redeem branch or the refund
branch is chain state, and no party can quietly reverse it. That is a genuine
`PROOF_OF_WORK` settlement.

What proof of work does *not* settle is the local record. A row in
`app/models/include/models/swap_contract.h` is created by `swap_initiate` /
`swap_participate` before any funding exists; `funding_txid` may be all-zero,
and `app/controllers/src/swap_controller.c` will refuse to settle with *"No
funding outpoint known for this swap"*. The `swap_id` is
`hex(sha256(initiator+participant+hash))` — computed locally, not a chain
object. An unfunded swap row is therefore a local declaration wearing a
proof-of-work kind.

There is a second, independent reason the `PROOF_OF_WORK` label does not fit,
found while wiring the depth/chainwork machinery §"Open work" item 1 called
for. Measuring work above a record needs a funding **height** to anchor from,
and the swap row carries `funding_txid` and an absolute CLTV locktime but no
height; worse, `chain` may be BTC/LTC/DOGE, whose height this node explicitly
refuses to claim it can observe (`swap_controller.c`,
`swap_locktime_to_absolute`). So depth and chainwork for a swap are not merely
unimplemented — they are unanswerable here. A `PROOF_OF_WORK` label with
permanently unknown numbers underneath is a claim the evidence never arrives to
support, which is why the code carries a fourth class and this ADR now names
it.

The resolution is therefore two-part. Settlement is a **per-record field** and
not only a per-kind constant: the kind carries the default, and a record that
has not yet bound a confirmed funding outpoint must be reported at its actual
class and must not be rendered at a chain-bound evidence grade. And the kind's
default for `contract_swap` is `CHAIN_ANCHORED_INCOMPLETE`, not
`PROOF_OF_WORK`.
This composes with the machinery already in `property_view.h`, where
`METAVERSE_EVIDENCE_CHAIN_VALIDATED_LOCAL` must be *earned* by this node and
nothing upgrades a grade.
<!-- claim: symbol-present METAVERSE_EVIDENCE_CHAIN_VALIDATED_LOCAL lib/metaverse -->

### 4. Settlement is orthogonal to evidence, and both are reported

Settlement is a fact about **the mechanism** — what would have to happen in the
world for the claim to be false. Evidence grade is a fact about **this node** —
what it personally checked on this call. A record can be `PROOF_OF_WORK`
settled and still carry `PEER_REPORTED` evidence, and the operator needs both
numbers. Neither is derivable from the other, so both are emitted, and neither
is collapsed into a boolean.

The same rule already governs freshness: `has_freshness_height` is false for
every non-chain-anchored authority, because stamping the node's tip height
beside a claim the tip does not commit is a false freshness claim.
<!-- claim: symbol-present has_freshness_height lib/metaverse -->
Settlement class inherits that discipline exactly — a `LOCAL_DECLARATION`
record never acquires a chain-derived qualifier.

### 5. No kind is settled by a signing quorum

There is deliberately no fourth class for "k of n named signers vouched for
it". A signature over a root is real evidence of authorship and is already
represented (`METAVERSE_EVIDENCE_LOCAL_SIGNATURE`) — but authorship is not
settlement, because a signature can be produced under compulsion and verifies
identically either way. Admitting a quorum class would let a record inherit
the strong-sounding vocabulary of this ADR while carrying the silent-failure
mode it exists to exclude.

## Limits — what this does not buy

This section is load-bearing. A settlement claim that is quoted without it is
being misquoted.

- **This is integrity, not anonymity.** Settlement says who decides what is
  authentic. It says nothing about who published a record or who is reading
  it. Proof of work conceals no IP address from the peer on the other end of
  the socket, and a content root conceals nothing about who requested those
  bytes.

- **Reachability is a separate and harder problem.** A censor does not need to
  attack a trust root when it can drop packets. This node has no pluggable
  transports, no bridges, and easily fingerprinted traffic. Nothing in this
  ADR improves that, and a perfect answer to "what is authentic" is worth
  little to someone who cannot complete a connection.

- **Accumulated work protects deep history, not new records.** A freshly
  minted record on a small-hashrate chain is cheap to rewrite. This is
  precisely why depth is a per-record quantity rather than a boolean
  "confirmed", and why a record controlling something valuable should require
  depth proportional to that value. A one-confirmation `PROOF_OF_WORK` record
  is closer in strength to a local declaration than to a deeply buried one,
  and the class name alone does not distinguish them.

- **A small network is a small anonymity set,** and no architecture fixes
  that. Set size is a function of how many people are actually using the
  thing.

- **Software nobody can obtain has no censorship resistance at all.**
  [`MVP.md`](../MVP.md) and this repository's own sovereignty findings record
  that there is no release, that the default build cannot send shielded, and
  that the proving parameters are not shipped. Distribution is the weakest
  link in this stack and it is the first thing a serious adversary attacks —
  attacking a download is cheaper than attacking a hash function or a
  hashrate. Nothing above changes that ordering.

- **`LOCAL_DECLARATION` kinds carry no external settlement whatsoever.** Three
  of the nine kinds are in that class. For those records the node is stating
  a belief about itself; a reader who treats them as verified has been
  misled by the reader, not by the record.

- **Most kinds have no reader yet.** Five of the nine adapter rows carry an
  `unavailable_reason` instead of a `list`/`show` pair, so their settlement
  class is a declared property of the design before it is an observable
  property of the catalog output.
  <!-- claim: symbol-present unavailable_reason lib/metaverse -->

## Open work that would strengthen the claim

Framed as work, not as promises. None of it is scheduled by this ADR.

1. ~~**Expose depth and chainwork per record.**~~ **Done** — the view no
   longer carries only a freshness height. `metaverse/property_work.h` reports
   depth below tip and the accumulated work above the record
   (`tip.nChainWork - anchor.nChainWork`), each beside its own `has_` boolean
   so that "not measurable" is a stated answer rather than a zero. That last
   part is what turned §3 from a labelling question into a fourth settlement
   class: for `contract_swap` the honest value is *unknown*, permanently, and
   the type had to be able to say so.
   <!-- claim: symbol-present chainwork lib/metaverse -->
2. **A per-kind minimum depth for actions.** Availability of a transfer or
   spend action on a `PROOF_OF_WORK` record could require a depth floor scaled
   to the record's value, rather than treating one confirmation as settled.
3. **Wire the six unavailable adapters,** which is what turns each settlement
   declaration into something an operator can observe rather than read.
4. **A reproducible, verifiable distribution path,** which per the Limits
   section dominates everything else here.

## Consequences

**Positive:**

- "Owned" stops being one word covering three different security properties.
  A reader who sees `LOCAL_DECLARATION` cannot mistake it for a chain fact,
  which is what makes `CONTENT_ADDRESSED` and `PROOF_OF_WORK` worth stating.
- The failure-mode framing gives a mechanical test for any future kind: *can
  this claim be made false without anyone outside observing?* A yes routes the
  kind to `LOCAL_DECLARATION` or excludes the mechanism outright, without
  needing a judgement call about how decentralised something feels.
- Making settlement a record-level field caught `contract_swap`'s unfunded
  window, which a kind-level constant would have rendered as chain-settled.

**Negative / Risk:**

- Three classes is a coarse partition, and `PROOF_OF_WORK` in particular spans
  a one-confirmation record and a deeply buried one. The class name is not a
  strength score, and until depth is exposed per record a reader can
  over-trust a shallow record on class name alone.
- The declaration is currently stronger than the observation: six kinds have
  no reader, so their class cannot be checked against real catalog output.
- A per-record field is one more thing an adapter can fill in wrongly. The
  mitigation is the same one `property_view.h` already uses — an adapter must
  name what it earned and nothing upgrades a grade — but that is a convention
  enforced by the API shape, not by a lint gate.

## Alternatives considered

**(a) Leave settlement implicit in the kind.** Each kind's mechanism is
inferable from its authority, so a reader could work it out. Rejected: it was
inferable and it was inferred wrongly — `contract_swap` reads as chain-settled
from its kind name while an unfunded row is a purely local record. An
inference every consumer must repeat is a rule with no single owner.

**(b) One boolean, `verified` / `unverified`.** Rejected for the same reason
`property_view.h` refuses a grade meaning "verified" in the abstract: a
boolean forces content addressing and a signed local assertion into the same
bucket, which is precisely the collapse this ADR exists to prevent.

**(c) Add a signing-quorum class for kinds with no chain record.** It would
let `hosted_service` and `endpoint_onion` present something stronger than
"this node says so". Rejected: it would import the silent-failure mode
described in Context in exchange for stronger-sounding vocabulary, and the
honest label is available for free. A local declaration correctly labelled
costs nothing; a local declaration dressed as a quorum fact costs the
credibility of every other class.
