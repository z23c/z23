<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Remote command channel — design

**Status: design + classification only. This increment enables no remote
execution.** There is no new listener, no new dispatch path, and no wire code
that runs anything. What lands with this document is the decision table
[`config/remote_command_classes.def`](../../config/remote_command_classes.def)
and its gate
[`tools/lint/check_remote_command_classes.sh`](../../tools/lint/check_remote_command_classes.sh).
The transport is the next increment and needs review first. See
[What this design does NOT do](#what-this-design-does-not-do-in-its-first-increment).

## The problem

An owner should be able to operate every machine they own through their own
network, from Linux, macOS or Windows, in C23, quickly. Z23 already has almost
everything that needs: a typed command registry with JSON in and JSON out, an
authenticated MAC'd session that works over clearnet and over onion, an
owner-scoped revocable capability model, and content-addressed source fetch.

One piece is missing: **the mesh transport does not carry the command
registry.** Every leaf runs only against the local process. The target verb is

```text
z23 remote <node> <leaf> --input='{...}'
```

which authenticates the caller against an owner-minted capability, checks the
leaf's remote class, runs the **existing** leaf, and returns the **existing**
typed result.

## Why a typed channel and not a shell

The instinct — "each node runs a shell so agents can tunnel through our own
network" — picks the wrong primitive for four concrete reasons.

**1. A shell is not portable, and the registry already is.** Windows has no
bash. The typed registry does not care: it is data in
[`config/commands`](../../config/commands) expanded by
[`config/src/command_catalog.c`](../../config/src/command_catalog.c) into one
immutable table, dispatched by the transport-neutral engine in
[`lib/kernel/src/command_registry.c`](../../lib/kernel/src/command_registry.c).
The same leaf, the same input schema and the same output schema exist on every
platform the binary builds for. A shell channel would need a second, different,
untested command vocabulary per operating system — which is three products, not
one.

**2. A shell is unbounded authority on a machine holding keys and consensus
state.** The registry's authority vocabulary is not decorative: every leaf
declares an auth level and a capability mask in
[`lib/kernel/include/kernel/command_registry.h`](../../lib/kernel/include/kernel/command_registry.h)
— `ZCL_COMMAND_AUTH_OWNER`, `ZCL_COMMAND_CAP_COMPILER`,
`ZCL_COMMAND_CAP_WALLET_REQUEST` and the rest. `AGENTS.md` lists what an agent
may never implicitly do: spend, export keys, mutate a canonical datadir, deploy
or restart, weaken a fail-closed refusal. Every one of those prohibitions is
enforced *inside* a leaf. A shell reaches the same effects while touching no
leaf at all — `sqlite3` on the wallet file, `cp` over `block_index.bin`, `kill`
on the node. The refusals stay perfectly intact and become irrelevant.

**3. The project is deliberately removing shell in favour of C23.** `AGENTS.md`
puts it plainly: use typed native commands to inspect and operate a running
node. `tools/deploy_guard.sh` exists to shell out *to*
`z23 agentdeployguard` — the shell is the caller of the typed decision, never
the decision. Adding a remote shell would reintroduce, over a network, the exact
layer being deleted locally.

**4. A shell cannot be audited or refused per operation.** `bash -c "$cmd"` has
one authority level: all of it. There is no answer to "may this caller do this
one thing", no typed reason when it says no, and no record of what was asked
that is not itself a string a caller chose. A leaf, by contrast, has a name a
capability can enumerate, a class this design attaches to it, an input schema
that bounds what it accepts, and an existing typed refusal shape. That is the
whole difference: **a shell exports the machine; a typed channel exports a
decision.**

## The wire shape

Reuse the file-service session unchanged. Add exactly one request tag.

The session in
[`lib/net/include/net/file_service.h`](../../lib/net/include/net/file_service.h)
already provides everything a command channel needs and nothing it does not:
`fs_handshake_until()` derives a forward-secret key with X25519 + HKDF-SHA3-256,
`fs_send_frame()` / `fs_recv_frame()` carry fixed 64 KB MAC'd frames, and
`fs_send_chunk_fast()` MACs a reply body as
`SHA3(key || counter || tag || body)` under a 32-byte tag constant. It already
runs over clearnet sockets and over Tor circuits, and the serve side already
demultiplexes several tags in one place.

**Client side** — model it on
[`lib/net/src/rom_fetch_directory.c`](../../lib/net/src/rom_fetch_directory.c),
which is the shortest correct example of this pattern in the tree:

1. connect, then stamp **one absolute deadline** for everything after connect
   and reduce every later wait to the time remaining against it. That file
   explains why in detail: a peer that accepts a connection and then never
   speaks is indistinguishable from a slow honest peer, so the cost of a lie
   must be one number, not a per-step timeout a drip-feeding peer can re-arm.
   A command call needs the same bound, sized per leaf rather than per
   transport.
2. `fs_handshake_until(&s, root, true, deadline_ms)` — never bare
   `fs_handshake()`, whose own 30 s budget would dominate.
3. `fs_send_frame(&s, FS_REQUEST, req, len)` with the request body
   `["RCX"(3)][capability_id(32)][leaf(len-prefixed)][input_json(len-prefixed)]`.
4. read size, body and MAC with the remaining budget each time.
5. recompute `SHA3(key || recv_counter || FS_REMOTE_CMD_MAC_TAG || body)` and
   compare in constant time before parsing one byte of the reply.

**Serve side** — one more branch beside the existing ones. In
[`lib/net/src/file_service.c`](../../lib/net/src/file_service.c) the request
handler already dispatches `ROM`, `RMF`, `RLS`, `ALL` and `RNG` through small
pure parsers (`fs_parse_rom_request`, `fs_parse_rom_manifest_request`,
`fs_parse_rom_list_request`, `fs_parse_serve_request`). The new tag adds
`fs_parse_remote_command_request()` in the same shape — a pure predicate over
the payload that returns the capability id, leaf name and input, and decides
nothing else — plus a `FS_REMOTE_CMD_MAC_TAG` constant alongside
`FS_ROM_LIST_MAC_TAG`, and a `FS_REMOTE_CMD_REQUEST_SIZE` bound alongside
`FS_ROM_LIST_REQUEST_SIZE`.

`"RCX"` is chosen for the same reason `"RLS"` was: three bytes, distinct from
every tag already dispatched, and a peer that does not understand it simply
fails to reply, which the caller's single deadline already handles as "this node
does not speak the command channel" rather than as an error.

Two properties of the reuse matter more than the framing itself. The reply body
is already a MAC'd blob of arbitrary bytes, so the leaf's existing
`zcl.result.v1` JSON goes over the wire byte-for-byte with no second
serialization to keep in sync. And the transport is already onion-capable, so
`z23 remote` works across NAT without any new reachability story.

## The authority model

**Default DENY, at three independent points.**

*Point one — the channel.* A node answers `"RCX"` at all only for a peer it has
paired with. Pairing is the existing mesh relationship
(`ops.mesh.pair.plan` / `.commit` / `.revoke`), and it is itself
`never_remote`: the credential that authorizes remote callers may not be edited
by a remote caller.

*Point two — the capability.* The request carries an owner-minted capability id.
No capability, or an unknown one, is a refusal.

*Point three — the class.* The named leaf is looked up in
[`config/remote_command_classes.def`](../../config/remote_command_classes.def).
Anything not classified `read_only` or `owner_capability` is refused before the
leaf is reached.

Only after all three does the existing leaf run — with **all** of its local
checks intact. The remote class only ever subtracts. `hotswap_activation_authorized()`
in [`lib/hotswap`](../../lib/hotswap) still demands `-hotswap-activate`,
`ZCL_HOTSWAP_ACTIVATE=1` and the dev datadir; the wallet grant surface still
default-denies. Nothing in this design can grant an authority a leaf would
refuse locally.

### The capability

Reuse the *shape* of `agent_session`, not the instance. `struct db_agent_session`
in [`app/models/include/models/agent_session.h`](../../app/models/include/models/agent_session.h)
already has the right skeleton, and
[`app/controllers/include/controllers/agent_session_client.h`](../../app/controllers/include/controllers/agent_session_client.h)
already has the right verbs: `agent_session_client_mint()`,
`agent_session_client_list()`, `agent_session_client_revoke()`,
`agent_session_client_authorize()`. Expiry is an `expires_at` epoch field,
revocation is a `revoked` flag checked on every authorize, and the model layer
in [`app/models/src/agent_session.c`](../../app/models/src/agent_session.c) is a
single-writer record with the usual save lifecycle.

One thing is genuinely missing and must be added rather than borrowed:
`db_agent_session` scopes a token to **amounts and recipients** —
`max_per_tx_zat`, `max_per_window_zat`, `reserve_floor_zat`,
`recipient_allowlist` — because it was built for spend authority. It has no
field naming allowed *operations*. A command capability needs exactly that: a
list of leaf names.

So the command capability is a sibling record with the same lifecycle and one
different scope field:

| field | meaning |
| --- | --- |
| `capability_id` | 32-hex primary key, presented on the wire |
| `account` | the owner principal that minted it |
| `leaves` | the exact leaf names this capability grants; never a glob, never `*` |
| `expires_at` | epoch seconds; **no zero-means-never** — a command capability must expire |
| `revoked` | 0/1, checked on every authorization, idempotent to set |
| `node_id` | the one node this capability may be presented to |

`leaves` is a list of names and not a pattern on purpose. A glob is a promise
about leaves that do not exist yet: `dev.*` written today silently grants
whatever `dev` leaf someone adds next year. Enumerated names cannot do that, and
the class table already guarantees the name space is complete and audited.

`read_only` leaves do not need to be named — any live capability for the node
reaches them. `owner_capability` leaves must appear in `leaves` explicitly.
`never_remote` leaves are unreachable whatever `leaves` says; a capability that
names one is refused at mint time, so an impossible grant never exists to be
misread later.

### The three refusals

Every refusal is a typed `zcl.result.v1` with a distinct reason, because a
refusal that does not name its blocker is the silent stall this codebase
forbids, wearing a typed error's clothes. All three are decided **before** the
leaf is looked up or run.

| situation | reason | what the caller learns |
| --- | --- | --- |
| no capability presented, or an id this node does not hold | `remote_capability_absent` | the channel is default-deny; mint one at the target |
| capability found but `expires_at` has passed, or `revoked` is set, or `node_id` is another node | `remote_capability_invalid` | which of expiry / revocation / node binding failed — never the capability's contents |
| leaf name is not in the class table, or its class is `never_remote`, or it is `owner_capability` and the capability does not name it | `remote_leaf_refused` | the leaf's class and that no capability can widen it |

An unknown leaf and a `never_remote` leaf deliberately share one reason. The
alternative distinguishes "this leaf does not exist here" from "this leaf exists
and you may not have it", which hands an unauthorized caller a map of the
target's command surface for free. The owner already has that map locally
through `z23 discover help`.

## The fleet dev loop

This is the composition the channel exists for:

```text
z23 remote <node> dev hotswap --source-root=<hash>
```

Three existing pieces, none of them new.

**Source by content hash.** `zcode.workspace.source.bundle.fetch` (declared in
[`config/commands/zcode.def`](../../config/commands/zcode.def), handler in
[`tools/command/native_zcode_source_bundle_command.c`](../../tools/command/native_zcode_source_bundle_command.c))
calls `source_bundle_fetch()` in
[`app/services/src/source_bundle_fetch.c`](../../app/services/src/source_bundle_fetch.c).
The header
[`app/services/include/services/source_bundle_fetch.h`](../../app/services/include/services/source_bundle_fetch.h)
states the rule that makes this safe to expose at all: *you may make bytes
easier to find; you may not make them easier to accept.* Acceptance is
`vcs_source_bundle_verify()` in
[`lib/vcs/src/source_bundle.c`](../../lib/vcs/src/source_bundle.c) against the
root the **caller** supplied. So the capability grants "go find these bytes",
never "trust these bytes", and the target node converges to a named source root
**itself** rather than having code pushed into it.

**Hot swap.** `dev.hotswap.probe` and `dev.hotswap.apply`
([`config/commands/dev.def`](../../config/commands/dev.def), handler
[`tools/command/native_dev_hotswap.c`](../../tools/command/native_dev_hotswap.c))
compile, ABI-validate, self-test and activate one module in the resident dev
process. [`docs/work/HOTSWAP.md`](./HOTSWAP.md) records the measured local cost:
a warm 20-edit resident bench on 2026-08-01 saw 227.280 ms p50 and 232.141 ms
p95 edit-to-visible against a 250 ms gate, against minutes for a full rebuild
and restart.

**The class table.** Both hot-swap leaves and the source fetch are
`owner_capability` — the only three leaves in that class besides the two log
reads. Everything else in `dev` and `zcode` is `never_remote`.

The composed loop is: edit locally, publish the workspace by content root, then
for each machine ask it to fetch that exact root and hot-swap to it. The remote
cost above the local loop is one bundle fetch plus verification plus the same
resident activation — which keeps the target machine's own dev loop in the same
order of magnitude as the local one, instead of a full rebuild per box. The
honest number for a fleet is not yet measured and this document does not claim
one; the local half is measured in `docs/work/HOTSWAP.md`, and the remote half
is what the next increment must measure on real hardware before anyone quotes
it.

What makes this acceptable rather than reckless is that **no code travels over
the command channel**. The wire carries a 32-byte hash. The target fetches the
bytes over the existing content-addressed path, verifies them against that hash
itself, and refuses anything that does not match. A compromised control channel
can therefore name a source root; it cannot substitute one.

## The classification and its gate

Every command leaf gets exactly one class, and there is no unclassified state.
The table covers both dispatchable surfaces: the typed dotted registry under
[`config/commands`](../../config/commands), and the flat method table in
[`app/controllers/include/controllers/agent_contracts.def`](../../app/controllers/include/controllers/agent_contracts.def)
that backs `z23 agentops`, `z23 dbquery` and `z23 agentdeployguard`
(dispatched at
[`app/controllers/src/event_controller.c`](../../app/controllers/src/event_controller.c),
handler in
[`app/controllers/src/agent_interface_controller.c`](../../app/controllers/src/agent_interface_controller.c)).
Leaving the second surface out would have left arbitrary SQL unclassified.

The counts, the per-class arguments and the per-leaf reasons live in
[`config/remote_command_classes.def`](../../config/remote_command_classes.def)
rather than being restated here, so there is one place to read and one place to
change.

[`tools/lint/check_remote_command_classes.sh`](../../tools/lint/check_remote_command_classes.sh)
(wired into `make lint`) asserts five things, all fail-closed: every registry
leaf has a row; every row names a live leaf; no leaf is classified twice; every
class token is known; and every `read_only` or `owner_capability` row states a
reason. It has no baseline — the tree is clean, and a baseline would only be
somewhere to hide the next omission. Its `--selftest` plants each defect class
in a fixture and asserts the red, because a gate nobody has watched fail is not
an assertion.

The direction that matters is the first one. The table's default is
`never_remote`, so a **missing** row is safe today — and that is exactly what
makes it dangerous: nothing breaks, nobody notices, and the table quietly stops
being where the decision is made. The gate turns registering a command leaf into
a two-file operation: register it, and say whether it may be reached remotely.

## What this design does NOT do in its first increment

Stated explicitly so the boundary is not read as an oversight:

- **No remote code execution is enabled.** No listener, no dispatcher, no wire
  code that executes anything. `"RCX"` is a name in this document; it is not
  parsed anywhere.
- **No new command leaf.** `z23 remote` is not registered. The verb described
  here does not exist yet.
- **No capability record.** The command capability above is a design, not a
  migration. `agent_session` is untouched; nothing gained a `leaves` field.
- **No transport change.** `lib/net` is untouched. `"RLS"`, `"ROM"`, `"RMF"`,
  `"ALL"` and `"RNG"` remain the only tags the file service dispatches.
- **No leaf's local authority changed.** Not one `ZCL_COMMAND_AUTH_*` or
  capability mask was edited. A class in the table has no effect on a local
  invocation, today or ever.

What did land: the classification, its justification, and the gate that keeps
it complete. Landing the decision before the mechanism is the point — when the
transport is written it inherits a table someone already argued over, instead of
an allowlist grown one hurried leaf at a time next to the code that needed it.

### The next increment, and what it must prove

1. The capability record with a `leaves` scope and a mandatory expiry, plus
   mint / list / revoke leaves for it — all three `never_remote`.
2. `fs_parse_remote_command_request()` as a pure parser with its own registered
   test group, proven before any socket calls it.
3. The three refusals above, each with a test that observes the typed reason,
   including the case where a valid capability names a `never_remote` leaf.
4. Only then the dispatch path, behind an explicit opt-in, on a dev datadir,
   with the same posture as `hotswap_activation_authorized()`.
5. A measured fleet dev-loop number to replace the estimate this document
   deliberately declines to make.

## See also

- [`AGENTS.md`](../../AGENTS.md) — authority boundaries this design sits under.
- [`docs/SECURITY_AND_INTEGRITY.md`](../SECURITY_AND_INTEGRITY.md)
- [`docs/work/HOTSWAP.md`](./HOTSWAP.md)
- [`docs/work/DIRECT_TRANSPORT.md`](./DIRECT_TRANSPORT.md)
