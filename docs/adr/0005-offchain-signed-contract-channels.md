# ADR-0005: Off-chain signed-contract channels over deterministic node programs

- **Status:** Proposed 2026-07-16.
- **Deciders:** Project maintainer.
- **Depends on:** [`ADR-0002`](./0002-sealed-consensus-core.md) (sealed
  consensus core — no new opcodes reach it),
  [`ADR-0004`](./0004-capability-service-fabric-and-app-checkpoints.md)
  (capability service fabric — the sandboxed program tier), the consensus
  parity doctrine ([`CONSENSUS_PARITY_DOCTRINE.md`](../CONSENSUS_PARITY_DOCTRINE.md)),
  and the software-anchoring overlay ([`SOFTWARE_ANCHORING.md`](../SOFTWARE_ANCHORING.md)).
- **Enabled by:** the overlay SDK (`engine/modules/overlay/`), the generalized
  authority-receipt idiom (`platform/modules/util/authority_receipt.*`), and the
  sandbox/hotload program tier (`engine/modules/hotswap/`, `os_sandbox`).
- **Related primitives already in tree:** `core/modules/script/src/htlc.c`
  (HTLC build/redeem/refund + secret extraction), `engine/controllers/src/anchor_controller.c`
  (ZANC on-chain software anchoring), the P2P messaging channels
  (`core/modules/net/src/zmsg.c`), and the file-market chunk-unlock-on-payment path
  (`file_service.c` → `handle_zfilepay`).

---

## Context

A network of z23 full nodes, each synced to the same PoW chain, has
three assets no single-server system has together: a shared immutable
settlement layer (the chain), a deterministic execution environment (the
sandboxed node), and a way to prove two nodes run identical code (ZANC
content-addressing). The open question this ADR answers is: **what is the
process model that lets two nodes sign an enforceable contract with each
other, execute it off-chain against programs running on the full node, and
fall back to the chain only to settle or to resolve a dispute — without ever
changing consensus?**

The constraint is absolute and is what makes this tractable rather than a
second VM: **consensus parity is inviolable** (ADR-0002). No new opcode, no
new script, no consensus rule reaches Core. Everything here is a parity-safe
*overlay* (OP_RETURN / Sapling-memo / standard HTLC scripts) plus *off-chain
signed state* plus *deterministic local computation*. The chain is used the
way Lightning and Discreet Log Contracts use Bitcoin: as a court of last
resort, not as the execution surface.

The naive alternative — put contract logic on-chain as new script — is
rejected by ADR-0002 and the parity doctrine outright. The other naive
alternative — a trusted contract server — is rejected because it reintroduces
exactly the DNS/CA/registry trust this stack exists to remove. The model
below keeps the only roots of trust the rest of the system keeps: PoW and the
compiled, content-addressed binary.

## Decision

Adopt a **three-tier signed-contract-channel process model**. Every node
participates in all three tiers; there is no privileged coordinator.

### Tier 1 — the program (what the contract computes)

A contract program is a **deterministic, sandboxed state-transition function**:
`f(state, input) -> (state', output)`, pure over its declared inputs, with no
clock, RNG, network, or filesystem authority except what the capability fabric
grants (ADR-0004). It is a hotloadable module (`engine/modules/hotswap/`) whose bytes are
**content-addressed and ZANC-anchored on-chain**, so both counterparties prove
they are running byte-identical logic by comparing one SHA3 digest against the
chain — no "did you run the real code?" trust.

Determinism is the load-bearing property: identical inputs must produce
identical output bytes on every node, or the two parties cannot co-sign a
result. This is enforced the same way the domain layer is (no raw clock/RNG,
replayable from a seed) and is the reason contract programs live under the
sandbox, not in ambient authority.

### Tier 2 — the signed-state channel (the agreement and the fast path)

Two (or N) nodes:

1. **Discover** — a node advertises which programs (by ZANC digest) it offers
   as services, gossiped via an overlay built on the OS-D1 overlay SDK.
2. **Open** — the parties agree on a program digest, fund an on-chain escrow
   (a 2-of-2 output, or an HTLC via `core/modules/script/src/htlc.c`), and exchange a
   co-signed genesis state.
3. **Execute** — off-chain, each party runs the *same* Tier-1 program locally
   on shared inputs, obtains the *same* output, and co-signs the new state.
   Each update carries a revocation of the prior state (the Lightning penalty
   construction), so a stale state cannot be profitably posted later. This
   loop is fast, free, and private — no chain interaction per step.
4. **Close (cooperative)** — the parties post the final co-signed state; the
   escrow releases funds per that state.

Each co-signed state transition is bound by the **authority-receipt idiom**
(OS-A1): a state update is a privileged transition, so it is accepted only
against an independently-derived receipt binding {program digest, prior-state
digest, the exact binary image}. Self-asserted state never authorizes —
identical to how bundle ACTIVATE and the sovereign cure gate today.

### Tier 3 — PoW settlement and dispute (the court of last resort)

If a party vanishes or posts a stale state, the counterparty posts the latest
co-signed state on-chain. A `OP_CHECKLOCKTIMEVERIFY` challenge window (the same
CLTV timeout the HTLC scripts already use) lets the other party rebut with a
newer signed state; posting a revoked state forfeits the escrow (the penalty
branch). PoW finality plus the timeout resolves the dispute deterministically.
No new opcode is required — the dispute is expressed entirely in standard
HTLC/CLTV/multisig script that the sealed core already validates.

**Summary of the trust reduction:** a contract's correctness reduces to (a)
both parties ran the same ZANC-anchored deterministic program, (b) every state
was co-signed and authority-receipt-bound, and (c) the chain enforces the last
signed state under PoW. No trusted third party, no consensus change, minimal
on-chain footprint (open + close, or open + dispute).

## Reference service: Discreet Log Contracts (DLC)

The reference instance is a **Discreet Log Contract**, chosen because it
exercises all three tiers with the least on-chain surface and the cleanest fit
to the parity doctrine (it needs *no* new opcodes — only adaptor signatures and
a standard funding output).

**Shape.** Two nodes want to contract on a future event (a price, a block
property, a sports result) resolved by an **oracle** — itself a node running a
deterministic Tier-1 program whose output is a signed outcome. At contract
time, neither party nor the oracle needs to be online simultaneously beyond the
open.

**Flow, mapped to the three tiers:**

1. **Program (Tier 1).** The oracle publishes, via a ZANC anchor, the digest of
   the deterministic resolver program and the set of possible outcomes with a
   pre-committed public nonce `R` per outcome. Because the resolver is
   content-addressed, both parties know exactly how the outcome will be
   computed before they fund anything.
2. **Open (Tier 2).** The two parties build a 2-of-2 funding output and, for
   each possible outcome `o_i`, exchange **adaptor signatures** encrypted to the
   oracle's outcome point `s_i·G = R − hash(o_i)·P_oracle`. Each party can
   complete only the settlement transaction for the outcome the oracle actually
   attests. No branch is on-chain; the whole contract is one funding output
   plus locally-held adaptor signatures.
3. **Resolve + Close (Tier 2/3).** When the event occurs, the oracle's resolver
   program runs (deterministically, verifiably against its ZANC digest) and the
   oracle publishes the scalar `s_i` for the true outcome (an OP_RETURN or
   Sapling-memo overlay). Each party can now decrypt exactly one adaptor
   signature — the winning branch — and broadcast the settlement, releasing the
   escrow per the agreed payout. Cooperative close is a single on-chain
   transaction.
4. **Dispute (Tier 3).** If a party refuses to cooperate, the CLTV refund
   branch returns funds after the timeout; a party attempting to settle on a
   *wrong* outcome cannot, because it lacks the oracle scalar for any outcome
   the oracle did not sign. The chain plus PoW plus the timeout is the whole
   enforcement.

**Why DLC first.** It is the minimal end-to-end proof of the model: an oracle
program (Tier 1, ZANC-anchored, deterministic), an off-chain adaptor-signature
contract (Tier 2, authority-receipt-bound), and a standard-script settlement
with a CLTV dispute path (Tier 3). It needs no new opcodes, leaves at most two
transactions on-chain, and generalizes: betting, insurance, prediction markets,
and parametric contracts are all DLCs over different oracle programs. The
existing `htlc.c` secret-extraction machinery and the ZANC anchor path are the
two primitives it reuses; the adaptor-signature layer and the oracle-program
registry are the new work.

## What this enables (non-exhaustive)

Each maps to a primitive already in tree, and none changes consensus:

- **Streaming file market** — the chunk-unlock-on-payment path in a channel:
  pay-per-chunk off-chain, one settlement at close (`file_service.c`).
- **Paid compute / proof-verification service** — sell deterministic work
  (verify a proof, transcode), stream micropayments, co-sign each result.
- **Storage contracts with proof-of-storage** — periodic challenge-response the
  program verifies; payment streams while proofs pass.
- **Metered API / relay / bandwidth** — pay-per-query access to a node's
  services (explorer, whole-network crawler map, proof verifier).
- **Escrowed marketplaces** — 2-of-3 with a deterministic arbiter *program*
  both parties pre-agree to.
- **Cross-chain atomic swaps** — already scaffolded (`htlc.c`, BTC/LTC/DOGE);
  the program is the swap protocol.

Identity is supplied by ZNAM (you prove *who* you contract with); reputation is
a projection folded from settled contracts.

## Consequences

- **Consensus is untouched.** Every tier is overlay + off-chain + standard
  script. This ADR cannot, by construction, propose a consensus change; if a
  future contract feature seems to need one, it is out of scope and must be
  rejected under ADR-0002 and the parity doctrine.
- **New surface to build (ordered):** (1) the overlay SDK as the
  service-advertisement and oracle-outcome-publication substrate (landed);
  (2) the authority-receipt idiom as the co-signed-state binder (landed);
  (3) an adaptor-signature primitive (`core/modules/script/`, new) — the one genuinely
  new cryptographic piece, itself consensus-parity-neutral (it produces
  standard signatures); (4) a channel state machine (`engine/services/`, new) for
  open/update/cooperative-close/dispute; (5) a deterministic oracle-program
  registry over the sandbox + ZANC.
- **Determinism becomes a hard contract, not a convention.** Contract programs
  must be lint-enforced pure (no raw clock/RNG/IO outside granted capabilities),
  reusing the domain-purity gate machinery. A non-deterministic program breaks
  co-signing and must fail the gate, not fail in production.
- **Sequencing gate.** This layer rides on "always synced + deterministic +
  sandboxed." It does not start against a node that cannot hold tip. The
  substrate (overlay SDK, authority receipts, sandbox, hotload) lands first;
  the DLC reference service is the first program built on it once the sovereign
  cure proves and the canonical node is at tip.

## Verification notes (what this ADR could and could not confirm)

- **Confirmed by reading code:** `core/modules/script/include/script/htlc.h` exposes
  `htlc_build_script`, `htlc_build_redeem_scriptsig`, `htlc_build_refund_scriptsig`,
  `htlc_extract_secret`, and `htlc_generate_secret` — the HTLC + secret
  machinery the settlement/dispute tier reuses; `engine/controllers/src/anchor_controller.c`
  provides `anchor_publish`/`anchor_verify`/`anchor_self` for ZANC content
  anchoring; the P2P messaging channels exist in `core/modules/net/src/zmsg.c`.
- **Design-only, not yet implemented:** the adaptor-signature primitive, the
  channel state machine, and the oracle-program registry do not exist in the
  tree. The overlay SDK (`engine/modules/overlay/`) and authority-receipt primitive
  (`platform/modules/util/authority_receipt.*`) are landed prerequisites this ADR builds on.
- **Not evaluated here:** the precise adaptor-signature scheme (Schnorr vs
  ECDSA adaptor) and its interaction with ZClassic's signature format — that is
  the first design question of the implementation program this ADR authorizes,
  and it is consensus-parity-neutral by requirement (the on-chain artifact must
  remain a standard signature the sealed core already validates).
