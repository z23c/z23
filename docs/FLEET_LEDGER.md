<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# The fleet ledger

The owner's private record of what the fleet did and what it cost, held so
that any machine can answer instantly.

Every box keeps its own append-only chain and a verified replica of every
paired box's chain. A question is therefore always answered from local
files: no box is asked, no network call is made, and nothing has to be up
for the answer to arrive.

## The privacy boundary

This is the owner's own data about the owner's own machines, and the
boundary is enforced in the code rather than promised here.

- Rows move **only between paired peers over an established Noise session**.
  The stream primitive refuses a link that is not Noise and a peer whose
  pairing row does not grant the capability, and the ledger service checks
  the pairing itself before it opens a stream, so neither check stands alone.
- A paired link carries **that peer's rows and nobody else's**. A row whose
  author is not the peer on the other end of the link refuses the whole
  batch (`ledger_peer_unpaired`), so an authorised peer cannot use its own
  link to plant rows attributed to a third machine.
- Chains are stored under the datadir in an owner-only directory, and the
  chainlog files are owner-only.
- Nothing here is ever written to the public site, to the interim board, or
  to a log. Refusals are named; values are not printed.
- There is no push and no gossip. A box asks its paired peers for what it
  does not have, and answers the same question when asked. Nothing is
  volunteered to anyone.

## What a row is

A row is typed, and the vocabularies it is written in are closed — a
subject nobody declared cannot be stored, so a number in this ledger always
has a meaning somebody wrote down.

| Field | What it is |
| --- | --- |
| `seq` | position in its own box's chain, dense and one-based |
| `ts_unix` | when the writer says it happened |
| `box_id` | which machine wrote it: the delegation master public key |
| `signer` | which key signed it: the delegation online public key |
| `kind` | one of the closed row kinds below |
| `subject` | what the row is about, scoped by kind |
| pairs | up to twelve `key`/`value` measurements, ascending by key |
| `note` | a short human-readable label, such as a task id |
| `prev_hash` | the hash of the whole previous row, signature included |
| `sig` | Ed25519 over everything above, under `signer` |

The signature covers `prev_hash` and `seq`, so a row cannot be lifted out of
one chain and replayed into another, or moved within its own.

### Kinds

| Kind | What it records | Written today |
| --- | --- | --- |
| `usage` | what one provider was asked to do, and what it cost | yes |
| `task` | facts about a unit of work, including a quota | yes |
| `vitals` | one sample of one declared fleet metric | yes |
| `attest` | reserved for attested machine capability | no |
| `reward` | reserved for game rewards | no |

The reserved kinds have wire values now so that something added later
cannot collide with a chain that is already signed.

### Absent is not zero

A number the writer did not have is **absent**, never zero. A task that
reported no cached tokens and a task whose provider does not report cached
tokens are different facts, and summing them as zero loses the difference,
permanently and silently. A writer with nothing to say about a key omits the
pair; the operator surfaces print `-` for an absent value and a number for a
zero one, and a query answer says which keys were present at all.

## Which keys, and why those

There is one node identity, and it is the one the mesh pairing ceremony
already consumes: the chain-bound ZID delegation. A row carries both halves
of it, because they answer different questions.

- **`box_id`** is the delegation's master public key: *which machine*. It
  survives an online-key rotation and a renewal, so a box's history stays
  one history across both.
- **`signer`** is the delegation's online public key: *which key signed this
  row*. The short-lived key does the signing, so compromising a running node
  does not reach the master.

The delegation document binds those two and the peer's Noise static in the
same breath, so the machine that sent a row, the key that signed it and the
identity it claims are one fact, checked once, where delegations are held.
A receiver therefore checks authorship against trust it already holds: no
new trust root, no second key file, nothing extra to revoke.

A delegation that is no longer current is reported as such
(`ledger_delegation_expired`) and never as a bad signature. A lapsed or
revoked identity is ordinary lifecycle and the answer is a renewal; a
signature failure is tampering and the answer is never to accept the row.
Collapsing them would make a renewal look like an attack and an attack look
like a renewal.

That currency is checked on BOTH halves of replication, before a stream is
opened and before an inbound one is answered, because a pairing record
states only its own window and its own revocation. A master identity that
has been revoked or superseded on chain leaves every local pairing row it
was ever written into untouched, so a box that trusted the row alone would
keep exchanging the owner's private rows with an identity the rest of the
mesh no longer trusts.

The dev proof signer is deliberately not used. It identifies a development
checkout's build receipts, it is bound to no peer link, and a checkout that
proved a build is not a machine on this mesh.

## How two statements combine

A merge class is declared per field in the schema and applied on replay,
never guessed at read time.

| Class | Rule | Where it applies |
| --- | --- | --- |
| immutable | stated once, never restated | `seq`, `ts_unix`, `box_id`, `signer`, `kind`, `subject`, `prev_hash`, `sig` |
| counter | per-box, add-only; reading is a sum | `tokens_in`, `tokens_out`, `tokens_cached`, `tokens_reasoning`, `wall_ms`, `turns`, and the other add-only quantities |
| lww | the latest statement wins | `note`, `limit`, and any metric the catalog declares a gauge |
| owner\_only | only the writer box may state it | everything else |

Latest means latest in **chain order** — by sequence number within a box,
and per box across boxes — and never by wall time. A clock that is wrong or
was adjusted must not be able to decide which of two facts is newer.

This is why a gauge is not summed. A load average is the value at a moment;
adding two of them produces a number that measures nothing. The vitals
catalog already declares which metrics are gauges and which accumulate, and
the ledger takes the class from there rather than stating it twice.

## How a question is answered

Opening the ledger reads every chain once and builds an index keyed by box,
kind, subject and UTC day. After that a query is a walk over that table:
no file is opened, no lock is taken, and no peer is asked. The two costs are
reported separately, because "instant" is a claim about the second one and
adding them together would hide that.

```
z23 fleet usage --days=7
z23 fleet usage --days=7 --provider=claude-opus
z23 fleet ledger status
z23 fleet ledger add --kind=usage --subject=grok --tokens_in=... --note=<task>
```

`fleet ledger status` prints, per box, how many rows are held, the last
sequence number, and how old the newest row is. A replica answers instantly
and that is not the same as answering currently, so the age is always shown.

It also prints two counts the chains themselves cannot show:
`delegation_refused`, the peers this box neither asked nor answered because
their delegation was no longer current, and `inbox_full`, the arriving
batches that found no free commit slot. Neither names a peer.

The index keeps a bounded number of days of per-day detail; older days are
folded into a whole-history remainder, which keeps every total exact while
the table stays a fixed size. A query for a window longer than the index
keeps is refused by name (`ledger_window_exceeded`) rather than answered
from days it does not hold.

## What refuses, and what a refusal costs

Nothing is ever partial. A batch of rows is decoded, signature-checked and
chain-checked in full before one byte of it is written, so a forged row at
the end of a batch leaves the replica exactly as it was.

| Refusal | What happened |
| --- | --- |
| `ledger_chain_broken` | a row does not continue the chain it claims to |
| `ledger_sig_invalid` | the signature does not verify under its own `signer` |
| `ledger_peer_unpaired` | a row signed by a key this peer's delegation does not delegate |
| `ledger_not_owner` | a row claiming a machine that is not the peer on this link |
| `ledger_delegation_expired` | the peer's master identity is no longer ACTIVE, or its delegation has run out |
| `ledger_sequence` | sequence numbers are not dense |
| `vital_unknown` | a `vitals` subject that is not in the catalog |
| `ledger_kind_not_writable` | a kind this build reserves but does not write |
| `ledger_window_exceeded` | a query asked for more days than the index keeps |

A chain that refuses is never repaired and never skipped. The refusal is the
evidence that something was altered, and rewriting the row would destroy it.

## The vitals catalog

These are the metric ids a `vitals` row may carry. The list is closed: a
number whose id is not here is not a metric, and `fleet ledger add` refuses
it. Order is identity — rows already written carry a metric's position — so
new ids are appended and none is ever reordered or removed.

`gauge` is the value at a moment; a day keeps the last. `sum` accumulates
over the day. A cadence of "per event" means the sample exists because
something happened, not because a timer fired.

| Metric | Unit | Aggregation | Cadence | What it is for |
| --- | --- | --- | --- | --- |
| `box.load1` | load | gauge | 300 s | whether this box has room for another lane right now |
| `box.cores` | count | gauge | 86400 s | the ceiling every parallelism decision is measured against |
| `box.cores_free_for_qedc` | count | gauge | 300 s | cores a new lane may take without starving the owner's shell |
| `box.ram_used_mib` | MiB | gauge | 300 s | how close this box is to the pressure that kills a build |
| `box.ram_total_mib` | MiB | gauge | 86400 s | the denominator the used figure is only meaningful against |
| `box.disk_free_gib` | GiB | gauge | 300 s | how long this box can keep proving before it runs out of disk |
| `box.disk_free_pct` | % | gauge | 300 s | the same fact on a scale that compares across unequal disks |
| `box.builders` | count | gauge | 300 s | compiler processes on one disk, against the per-disk ceiling |
| `box.worktrees` | count | gauge | 3600 s | how many lane checkouts this box is carrying |
| `box.worktree_bytes` | bytes | gauge | 86400 s | disk a garbage collection could give back without losing work |
| `box.uptime_s` | s | gauge | 3600 s | whether a box restarted under a measurement nobody saw |
| `node.height` | blocks | gauge | 300 s | whether this node is at the tip or still catching up |
| `node.peers` | count | gauge | 300 s | whether the node has anyone to learn the tip from |
| `node.onion_reachable` | 0/1 | gauge | 900 s | whether other machines can reach this one at all |
| `node.rss_mib` | MiB | gauge | 300 s | the node's own share of the memory pressure above |
| `node.restarts_24h` | count | sum | 3600 s | a crash loop, which reads as healthy in any single sample |
| `dev.proof_wall_s` | s | sum | per event | the dominant cost of landing anything, per proof |
| `dev.proof_attempts` | count | sum | per event | how often a moved base threw a finished proof away |
| `dev.proof_slot_busy_s` | s | sum | per event | how long one box's proof lock kept every other lane waiting |
| `dev.lint_full_wall_s` | s | sum | per event | the gate cost a lane pays before it may ask for a proof |
| `dev.build_only_wall_s` | s | sum | per event | the build half of that cost, separated so a fix can be aimed |
| `dev.gate_red_count` | count | gauge | per event | how many gates a tip is failing, which is the work remaining |
| `dev.train_landed` | count | sum | per event | the only measure of the loop that is an outcome, not activity |
| `dev.train_lines` | lines | sum | per event | how much change each landing carried, against the size cap |
| `dev.lane_wall_s` | s | sum | per event | what one lane cost end to end, for the next lane's estimate |
| `dev.unit_wall_s` | s | sum | per event | the same for one dispatched unit, per executor |
| `dev.verify_wall_s` | s | sum | per event | what verification costs, which decides whether to verify twice |
| `dev.defects_found` | count | sum | per event | what verification is worth, against the line above |
| `spend.tokens_in` | tokens | sum | per event | prompt tokens, the half a shorter brief actually reduces |
| `spend.tokens_out` | tokens | sum | per event | completion tokens, the half the task's difficulty sets |
| `spend.tokens_cached` | tokens | sum | per event | tokens a cache hit made cheap, counted apart so it can be seen |
| `spend.tokens_reasoning` | tokens | sum | per event | thinking tokens, which a thinking-level choice moves directly |
| `spend.week_pct` | % | gauge | 3600 s | how much of this week's cap is already gone |
| `spend.cost_usd` | USD | sum | per event | the same spend where a provider states a price for it |
| `agent.turns` | count | sum | per event | turns to finish, which separates a hard task from a long one |
| `agent.tool_uses` | count | sum | per event | tool calls to finish, the same fact from the other side |
| `story.passage_wall_s` | s | sum | per event | what one passage of the walk cost, per passage |
| `story.predict_error` | ratio | gauge | 86400 s | how wrong the estimate was, which is whether it may be trusted |

This table is rendered from `engine/composition/fleet_vitals.def`, which is
the one declaration. `make check-fleet-vitals` fails if they disagree.

No collector runs in this build. The ids exist so that whatever samples them
writes into one ledger under one vocabulary, rather than into a file per host
that only that host can read.
