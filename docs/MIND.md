<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# The mind: one process per node owns the code index

A node's mind is a resident service that keeps this box's code indexes
current, so that nothing else has to. It is a development facility. It runs
no node, holds no datadir, opens no port, and decides nothing.

## Why it exists

Before it, every command that opened a stale code index rebuilt that index
inside the query. The caller waited for a whole-tree recompute it never asked
for, and often waited for a failure instead: while one query was building,
another writer moved the tree, and the build correctly refused to publish
evidence about a tree that had already changed. Both costs grow with the
tree.

The fix is not a faster rebuild. It is deciding who rebuilds. One process
per node does it; everything else asks and is told the truth about what it
got.

## What the mind holds

For each checkout registered with it:

- the published index generation — its content root, its age, and its size
  on disk;
- what that generation actually contains: files, symbols, include edges,
  references and groups, read from the store itself as separate facts;
- the store's own cold-build receipt, which describes the last full build
  and is never rewritten by an incremental refresh;
- when it last rebuilt that checkout and how long that took.

Files and symbols are never collapsed into one number. A file the scanner
admitted but could not parse contributes a file row and no symbols, so a
single figure for both would report coverage the index does not have.

The mind holds nothing else. It is not a memory of decisions, not a store of
verdicts, and not an authority. No gate reads it and no verdict may cite it.

## The ownership rule

While a mind is registered for a checkout and heart-beating, it is the only
process that rebuilds that checkout's index. Every other caller reads the
published generation.

The rule is enforced twice. At run time, the mind writes an owner marker
beside the store and refreshes it as a heartbeat; the index open path reads
that marker and refuses to rebuild while the claim is live. At build time,
`make check-mind-owns-rebuild` reads the tree and fails if the rebuild entry
point is called from anywhere but the code-index module that implements it,
the resident that owns it, and that module's own tests.

The claim expires. If a resident stops heart-beating, its claim goes stale
after a bounded window and every reader returns to rebuilding for itself.
Refusing for ever because a service died would brick every query on the box,
so expiry is the deliberate failure direction rather than an oversight.

## The staleness rule

A stale answer is refused, never served, and never repaired inside a query.

An index generation is stale when the source tree has moved past it. Asked
against a stale generation, `z23 dev fleet mind ask` returns the typed refusal
`INDEX_STALE`, carrying the index root it consulted, that generation's age,
and — when there is one — the owning mind's process and the age of its last
heartbeat. The two cases are distinguished in the message, because the next
action differs: wait for the owner to publish, or start an owner.

`z23 dev fleet mind status` reports staleness rather than refusing on it: its job
is to describe what this box has, including the fact that what it has is
behind. It never rebuilds either.

## How to ask

```
z23 dev fleet mind ask where_is <symbol>      # the exact definition site
z23 dev fleet mind ask owns <path-or-symbol>  # the group it belongs to
z23 dev fleet mind ask tests_for <path>       # the groups a change there touches
z23 dev fleet mind status                     # this box: heartbeat and each checkout
z23 dev fleet mind status --fleet             # every paired node's index root and age
```

Three further questions — `executor_for`, `trap_of` and `next_passage` —
answer `not_yet_available` and name what they are waiting for. The fact rows
and the story walker they need are not in this tree yet. Answering anyway
would fabricate exactly the evidence those lanes exist to measure.

`tests_for` names the groups the shared impact rules match for a path. Which
single group a proof routes to is `z23 code tests`, and that routing policy
is owned there; the mind points at it rather than restating it.

## Answering peers

A node tells its paired peers what its mind holds — index root, generation
age, checkouts owned, and group rows — inside the signed, expiring mesh
status capsule it already exchanges with them. It rides in that capsule
rather than on a wire of its own, so a mind row is exactly as trustworthy,
and exactly as fresh, as the receipt that carried it: an expired receipt
takes its mind row with it, and only paired peers ever see one.

`z23 dev fleet mind status --fleet` reads the rows peers already delivered on that
cadence. It never dials a peer itself, and with no local node it fails closed
rather than reporting an empty fleet. A peer that carried no mind row is
reported as not having reported one, which is not the same as a peer whose
index is empty.

## Running it

`platform/deploy/zcl-mind.service` is a user service, one per node, under the
same linger discipline as the rest. Register the checkouts it owns in its
state file before starting it: it refuses to start with nothing registered,
because a heartbeat claiming coverage nobody has is worse than no heartbeat.
Removing that file retires the resident, which releases every claim on the
way out. The unit file carries the install, register and retire commands.

## Related

- [`DEVELOPING.md`](DEVELOPING.md) — the developer procedure this fits inside.
- [`API_REFERENCE.md`](API_REFERENCE.md) — the generated leaf reference.
- [`AGENT_TRAPS.md`](AGENT_TRAPS.md) — traps an agent should not relearn.
