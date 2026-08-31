# Architecture North Star — one ledger per domain, views only

> **Scoped architecture decision, not a work queue.** Current task selection
> lives only in [`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md). The completed
> architecture quest board was deleted; recover it from Git history if an
> incident needs its old narrative.
>
> **Read this before touching sync, boot, import, install, or any `*frontier`
> / `*cursor` / `pindex_*` code.** It is the standing decision that governs
> how this node acquires and tracks state: the one recurring bug shape
> (below) is cloned ledgers, and this doc is the cure and the guardrail.

## Verdict: RESCUE, not rewrite

The core is correct and expensive: frozen consensus verifiers (Equihash,
Sapling), the append-only log + reducer frontier, P2P/Tor, the swarm
download engine, the bundle format. A rewrite re-earns every parity lesson
(h=478544, BLS infinity, the golden values) to arrive at this same design
with fresh bugs. **The disease is confined to ~5 seams** (import, install,
legacy paths). Fix the seams; keep the core.

## The one bug, every time

Not "too many acquisition paths" (a sovereign node MUST keep genesis-fold as
its trust root). Not "one log would fix it" (that erases the two distinct
trust mechanisms below). The actual disease:

> **A single fact ("header proven to H", "state applied to H") has two or
> three independently-writable copies. One writer updates copy A; a reader
> checks copy B; they disagree.**

The D8 defect that established this rule: `--importblockindex` PoW-verified the
headers and wrote `pindex_best_header = 3.19M`, but the install gate read the
*other* copy (the `validate_headers` stage cursor = 0), so it deferred forever
and the node folded from genesis. Same fact, two copies, drift.

## Two provenance domains — keep them SEPARATE and VISIBLE

State is trusted by two different mechanisms. Never flatten them into one
number — the difference IS the sovereignty audit trail.

- **Header spine (PoW).** Cheap, top-down. Hash-linked headers whose PoW is
  verified. This is what anchors a checkpoint: a borrowed state snapshot at
  height C is only meaningful if the header at C is real PoW and chains to
  genesis.
- **Derived state.** Expensive, bottom-up. UTXO/anchor/nullifier sets earned
  by replaying block bodies. A bundle *asserts* this at C (hash matches the
  baked root); a genesis fold *derives* it.

Every derived-state row carries a `self_derived | checkpoint` tag (the
existing `rewind_bases.self_derived` bit). "Is my tip earned or borrowed?"
must always be answerable.

```
  ╔═══════════════════════════╗       ╔═══════════════════════════╗
  ║  HEADER LEDGER (PoW spine)║       ║  STATE LEDGER             ║
  ║  append-only, hash-linked ║       ║  append-only; each row    ║
  ║  ALL writers append here: ║       ║  tagged self_derived|ckpt ║
  ║   --importblockindex,     ║       ║  bundle install = append  ║
  ║   header-seed artifact,   ║       ║  ONE ckpt row at C        ║
  ║   live P2P                ║       ║                           ║
  ╚═════════════╤═════════════╝       ╚═════════════╤═════════════╝
                │ fold                               │ fold
                ▼                                    ▼
         header_frontier H_h                  state_frontier H_s
                │       RECONCILE AT CHECKPOINT      ▲
                └── H_h ≥ C ⇒ graft ckpt ⇒ H_s:=C ──┘
                    ⇒ fold bodies C→tip ⇒ H_s → tip

  pindex_best_header · coins applied-height · install-gate · status
        = PURE VIEWS of (H_h, H_s). Not writable. Cannot drift.
```

## Acquisition is a fall-through STACK, not competitors

No ad-hoc "which path wins" precedence. Try in order; each layer that
succeeds appends the SAME facts to the SAME ledgers:

1. verified bundle (fast) → binds if the header spine reaches C
2. swarm bodies from a peer at the checkpoint (medium)
3. genesis fold (slow, sovereign floor — NEVER deleted)

The checkpoint install is not a fragile "wait for a cursor" gate. It is a
labeled splice: **spine reaches C ⇒ graft asserted state at C ⇒ fold the
gap C→tip.**

## The invariants a future LLM MUST obey

1. **Single writer per frontier.** Each frontier (`header_frontier`,
   `state_frontier`, and any shielded sub-frontier) has exactly ONE code
   path that advances it: appending a verified fact to its ledger. If you
   are about to write a height/cursor anywhere else, STOP — you are creating
   a cloned ledger. Make it a view instead.
2. **Readers read the frontier fold, never a side cursor.** Install gate,
   `status`, self-heal, and boot decisions all read the reducer frontier.
   `pindex_best_header` and `coins applied-height` are VIEWS; never gate on
   them independently.
3. **Reconcile at explicit points only.** The header/state domains meet at
   the checkpoint splice and nowhere else. No ad-hoc "if A disagrees with B"
   patches — that smell means two copies exist that shouldn't.
4. **A stall is always a named blocker with a height.** A frontier cannot
   fail to advance without a typed blocker naming why. No silent spins
   (see D7: the Sapling rebuild livelock that logged nothing).
5. **No hidden O(chain) work at boot.** If the bundle ships complete state
   (incl. shielded tree), nothing rebuilds. Boot is O(1) + fold-the-gap.
6. **Fix by DELETING a redundant copy, not adding a guard.** If your change
   reconciles two representations of one fact, you are treating the symptom.
   Demote one of them to a view.

## Regression evidence

The rescue program is complete. The single-writer ceiling is enforced by
`check_frontier_single_writer.sh`, and end-to-end state acquisition remains
observable through the named MVP stopwatch gates. Select any new work from
[`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md), then use these invariants as
constraints and focused evidence. The completed score game and quest board
were deleted; their dated results remain in Git history.
