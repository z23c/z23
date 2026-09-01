# Services — the declared way to add one

A **service** is a unit that registers its own native commands, owns its own
state namespace, and derives access from a ZSLP token balance — declared, not
coded into the node. Adding one never touches `core/`, and structurally cannot:
a service is refused at validation time if it declares anything that would let
it reach consensus state.

This page is the map. The authoritative text lives next to the code, so it
cannot drift:

| Question | Where the answer actually lives |
|---|---|
| What can a service declare? | `engine/modules/kernel/include/kernel/service_binding.h` |
| How do I add one? | the header comment of `engine/composition/services/bindings.def` |
| What services are declared here? | `z23 app service list` |
| What does one declare exactly? | `z23 app service inspect <name>` |
| What commands does the branch expose? | `docs/API_REFERENCE.md` — generated from `engine/composition/commands`, drift-gated |
| Does a holder qualify? | `z23 app service access <name>` |
| What state is each service in? | `z23 app service status` |

## Why a binding rather than a new registry

The process-isolation charter already existed: `zcl.service_manifest.v1`
(`engine/modules/kernel/include/kernel/service_manifest.h`, declared in
`engine/composition/services/catalog.def`) gives the six node roles their trust classes,
descriptor grants, resource budgets, and restart policy. It answers *what may
this process touch*. It does not answer *what commands does this unit register,
what state does it own, and who may call it* — and its per-manifest SHA3
identity is pinned by a golden vector, so growing that struct would rewrite an
existing identity.

`zcl.service_binding.v1` therefore **composes with** a manifest instead of
copying it. Every binding names a `host_service_id` that must be a real
`APP_BROKER` (appd) entry in that catalog, and inherits its descriptor grants
unchanged. A service can never widen them, and hosting on `core`, `wallet`, or
`init` is refused outright.

## The four declarations

1. **`command_prefix`** — must be `app.service.<name>`, and `<name>` must be the
   service's own name. It cannot reach `core.`, `dev.`, or `ops.`, and it cannot
   take one of the registry's own leaf names (`list`, `inspect`, `access`,
   `status`, `catalog`). The leaves themselves are still declared in a
   `engine/composition/commands` `.def`, so `discover` and the generated reference carry
   them for free — and their auth, effect, and risk are the catalog's
   declaration, not the service's.
2. **`state_table_prefix`** — the `node.db` table namespace it owns. Must end in
   `_`, must not overlap any reserved consensus/kernel/wallet prefix, and must
   not overlap another service's prefix in either direction.
3. **`gate`** — the token binding (below).
4. **`isolation`** — the boundary (below).

## The token binding

Access derives from a balance in **`zslp_ledger`** — the debit-correct
per-(token, outpoint) projection keyed on a 32-byte GENESIS txid and a 20-byte
hash160. It is *not* `zslp_balances`, which is a credit-only merchant ledger
keyed on hardcoded ticker strings; reading that as a token balance would be
reading a different table with a similar name.

A gate names three things: the token (`token_genesis_txid`, internal byte
order), the threshold (`min_balance`), and the snapshot
(`ZCL_SERVICE_GATE_SNAPSHOT_CONFIRMED_DEPTH` with a depth, or
`..._FIXED_HEIGHT` with an absolute height). It also names whose balance is
measured — this node's whole wallet, or one supplied address.

The verdict is reproducible by construction:

- the snapshot height is a pure function of the declared gate and the tip
  (`zcl_service_gate_snapshot_height_v1`) — a chain shorter than the declared
  depth has *no* snapshot rather than a clamped one;
- the balance is read **as of that height** from rows' `created_height` /
  `spent_height`, not as of now;
- if the ledger's backfill cursor has not reached the snapshot height, the gate
  refuses rather than answering from a partial index.

Every failure denies with a named reason. There is no path that grants without
a qualifying balance. A binding may name the reserved unminted sentinel (32
bytes of `0xFF`) so a contract can be declared and reviewed before its token
exists; that binding validates but never grants, and cannot leave `STARTING`.

## The boundary

`isolation` is not a menu. A binding declares exactly
`ZCL_SERVICE_ISOLATION_REQUIRED_V1` — all five bits, no subset (a dropped bit is
a claimed privilege) and no superset (an unknown bit is an undeclared one).
There is deliberately no way to spell "this service may write consensus state".

- never affects block validity
- never writes consensus/kernel state
- never blocks on the reducer progress lock
- entry points are command-catalog leaves, so auth/effect/risk are declared there
- writes only its own `state_table_prefix` tables

Declaring your way out fails `zcl_service_binding_validate_v1`, which fails the
catalog check, which fails `test_service_binding`.

## Lifecycle

States are `enum zcl_service_lifecycle_v1`, reused verbatim from the manifest
contract so a service and a node role read on one scale:

```
DECLARED --register--> STARTING --start--> READY <--degrade/recover--> DEGRADED
                          |                  |                            |
                          +------------------+----------- fault ----------+
                                             v
                                          BLOCKED --stop--> STOPPING --exit--> EXITED --remove--> DECLARED
```

`start` is where the token binding bites: a service reaches `READY` only on a
granted verdict, and a denial drives `FAULT` and records the gate's own reason.
`BLOCKED` is sticky — only an explicit `stop` clears it, so a failed service
stays named. `remove` returns a service to `DECLARED` and deliberately does not
drop its tables: unregistering a declaration and destroying operator data are
different acts.

The registry is in-memory and rebuilt from the compiled catalog each boot, so
every service reads `declared` until something registers it.
