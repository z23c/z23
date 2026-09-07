<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Fleet roles

Which key may call which fleet leaf, decided by this node alone.

Every fleet leaf that acts on a signed request — a board post, an
experiment row, a row a peer replicates in — already checks that request's
signature, and a board post's SCOPE. Neither of those says which LEAVES a
key may reach. This is that missing map, and it is local: **there is no
central referee**. What this node trusts is this node's own decision,
recorded in this node's own signed store, never a fact carried in from a
peer.

## What is enforced today

Both places a signed request actually enters a node ask this store before
they keep anything: `zcl_fleet_ledger_replicate()`
(engine/modules/fleetledger/src/fleet_ledger.c) and
`db_fleet_board_post_ingest()` (engine/models/src/fleet_board_post.c). A key
with no active grant is refused there, and so is every key when no role
checker is installed at all. See **Enforcement** at the end of this page for
the leaves and kinds each ingress asks, what a refusal costs, and the one
gap an operator still closes by hand.

Every OTHER fleet leaf still runs without a role lookup: those are local CLI
calls by this node's own operator, which holds every role implicitly. What
this page restricts is bytes signed by another machine's key.

## The roles

Declared once, in `engine/composition/roles.def`, as a closed set:

| role       | may do |
|------------|--------|
| `operator` | everything on this node. This node's own key, **implicit** — it is never stored anywhere, and unsigned local CLI use by this node's operator is unaffected by anything below. |
| `worker`   | post board rows of kind `note`, `result`, `claim`, `problem`, `need` or `chat`; replicate its own ledger rows into this box; write experiment `predict`/`result` rows; read everything. |
| `observer` | read-only leaves. |
| `landing`  | the landing machine's key: post board `result` rows about trains, read the ledger. |

Each role's exact grants — which `fleet.<a>.<b>` leaf (an exact name, or a
`prefix.*` wildcard) and, for a board post, which kinds — are the
`Z23_ROLE_GRANT` rows in the same file. A key with no active grant naming a
leaf is refused before the leaf runs, at both ingress points; there is no
default-permit path, and no build in which the absence of a policy means
allow.

## The store

`tools/dev/fleet_roles.h` / `fleet_roles_store.c` hold one signed chainlog
per node, at `<datadir>/fleet_roles/roles.chain`. A row grants or revokes
one role to one key's SHA3-256 fingerprint, signed by **this node's own
operator key** — a grant is always this node's own decision, never a
statement accepted from elsewhere. Nothing is ever deleted: a revoke is its
own row, and the newest row for a (fingerprint, role) pair wins on the next
check.

## The leaves

```
z23 fleet roles list                                   # every grant this node has made
z23 fleet roles grant  --fp=<64-hex> --role=worker      # sign a grant row
z23 fleet roles revoke --fp=<64-hex> --role=worker      # sign a revoke row
z23 fleet roles check  --fp=<64-hex> --leaf=fleet.board.post --kind=result
```

`check` reports `allowed` and, on a refusal, the exact typed reason a caller
would have seen, e.g.:

```
REFUSED role: key ab3f9c12 has no role granting fleet.board.post kind=result
```

`fp` equal to this node's own operator fingerprint is always allowed —
that is `operator`'s implicit grant, checked by identity rather than by a
row in the store.

## What this is not

It is not consensus and it grants no authority beyond this one node: a
grant row here changes what THIS box will accept from that key, and
nothing else. A different box makes its own decision about the same key,
independently, from its own store. See `docs/FLEET_LEDGER.md` and
`docs/FLEET_BOARD.md` for the leaves this feature restricts.

## Enforcement

A role is only a role where something asks. Two places on this node take
bytes signed by ANOTHER machine's key, and both now ask before they keep
them:

| ingress | leaf asked | kind asked |
|---------|------------|------------|
| `zcl_fleet_ledger_replicate()` — one batch a peer replicates into this box's copy of its chain | `fleet.ledger.replicate` | the ROW kind: `usage`, `task`, `attest`, `reward`, `vitals`, `experiment` |
| `db_fleet_board_post_ingest()` — one gossiped board post | `fleet.board.post` | the POST kind: `problem`, `need`, `offer`, `claim`, `result`, `note`, `wiki` |

`worker` is granted both, with every kind on the ledger side and its
declared list of post kinds on the board side. `observer` is granted
neither: reading is not writing. `landing` may post `result` and nothing
else, exactly as before.

A ledger batch is refused WHOLE — replication was already all-or-nothing,
and one ungranted row does not get to carry the rest of the batch in with
it. The refusal is `ledger_role_refused`, counted in `fleet ledger status`
as `role_refused`. A refused board post is never stored, counted in
`fleet board status` as `role_refused`, and logged with the fingerprint
prefix to hand to `z23 fleet roles grant`. Neither log line names anything
about the row or the post: what the fleet measures is the owner's business.

**There is no default-permit path.** The engine asks through a seam
(`platform/modules/base/include/base/fleet_role_check.h`) that the top of
the tree fills in at node start, because the catalog and the store live in
`tools/dev` and nothing under `engine/` may include a `tools/` header. When
NOTHING is installed to answer — a process that has not reached that wiring,
or one that never runs it — both ingress points REFUSE and say so once. A
gate that is only closed when somebody remembered to close it is not a gate.

### Bootstrap

Enforcement must not stop a fleet that was replicating happily the day
before, and it must not need the operator to grant anything by hand. Three
paths mint the role that a decision already made implies. All three are
idempotent, so every one of them is safe to run at every boot.

* **What this node already accepted.** At node start, every key that signed
  a row in a ledger chain this box is carrying, and every key that signed a
  board post this box is storing, is granted `worker` if it holds nothing.
  Those rows and posts were accepted here, by this node, under the rules of
  the day: this writes that decision down rather than making a new one. A
  key that never had a row or a post here is not on the list and is still
  refused. Each key is logged once by fingerprint, with a count.
* **What enrolment says.** `z23 fleet join` names, in its receipt, the key
  the box will actually SIGN with — its node's online key — and signs the
  receipt with that key too, so naming it proves possession of it. `z23
  fleet admit` grants `worker` to that key AND to the box key, and says in
  its reply whether each grant landed.
* **The roster.** At every node start, every key in the machine roster that
  holds no grant is granted `worker` — both the box key and, when the
  receipt named one, the signing key.

A box that has never started a node has no signing key yet, so its receipt
names none and `fleet admit` says so. Running `z23 fleet join` again after
that box's first node start produces a receipt that does name it; admitting
that receipt grants it. Until then the box's rows are refused, and the count
in `fleet ledger status` / `fleet board status` says how many.

**On a node with no operator identity** — no delegation filed — every one of
these mints nothing, because there is no key to sign a grant with, and it
says so in the log. Enforcement still stands: every foreign-signed row and
post is refused until an operator identity exists and `z23 fleet roles
grant` can run. The node's OWN key is unaffected either way; it is
recognised by identity, never looked up in the store.

**A roster key is not a host key.** The roster records the box key from
`fleet join` (`box.ed25519` under the state root); a node signs board posts
and ledger rows with its DHT ONLINE key, in its datadir. They are two
different keys on purpose, which is why the receipt now carries both and why
the first two paths above exist: nothing on an upgraded fleet has to be
granted by hand.
