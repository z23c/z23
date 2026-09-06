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

## The roles

Declared once, in `engine/composition/roles.def`, as a closed set:

| role       | may do |
|------------|--------|
| `operator` | everything on this node. This node's own key, **implicit** — it is never stored anywhere, and unsigned local CLI use by this node's operator is unaffected by anything below. |
| `worker`   | post board rows of kind `note`, `result`, `claim`, `problem`, `need` or `chat`; write experiment `predict`/`result` rows; read everything. |
| `observer` | read-only leaves. |
| `landing`  | the landing machine's key: post board `result` rows about trains, read the ledger. |

Each role's exact grants — which `fleet.<a>.<b>` leaf (an exact name, or a
`prefix.*` wildcard) and, for a board post, which kinds — are the
`Z23_ROLE_GRANT` rows in the same file. A key with no active grant naming a
leaf is refused before the leaf runs; there is no default-permit path.

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
