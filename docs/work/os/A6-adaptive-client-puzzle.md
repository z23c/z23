# OS-A6 — the adaptive client puzzle

Shipped. The primitive is `core/modules/net/src/puzzle.c` +
`core/modules/net/include/net/puzzle.h`; `tests/harness/src/test_puzzle.c` is the
behavior model (test group `puzzle`).

`struct puzzle_gate` is the one admission primitive in the tree. It owns a
server-issued challenge seed that rotates on an epoch (with a one-epoch
grace window so a solve in flight is never invalidated), a single-use ring
so one accepted solution admits exactly one request, and a difficulty that
rises with the accepted-request rate and with concurrent large serves and
falls back to an idle floor. The rate term is an EWMA, so there is no
window boundary a flood can start just after and read as idle. A
`struct puzzle_policy` lets each surface pick its own difficulty band,
seed epoch, and load thresholds without a second implementation.

The puzzle is `SHA3-256(challenge_seed || peer_token || ts || nonce)` with
D leading zero bits. Verifying costs one keccak; the requester pays
O(2^D). None of it is persisted and none of it is a consensus predicate —
a fresh process starts clean.

## Surfaces on the gate

| Surface | Instance | Token binding | Policy delta |
|---------|----------|---------------|--------------|
| file service bulk stream | `g_fs_pow_gate` (`core/modules/net/src/file_service.c`) | handshake nonce | defaults |
| onion expensive routes | `g_onion_puzzle_gate` (`core/modules/net/src/onion_ratelimit.c`) | route class | max 22 bits, 120 s epoch |
| store order mint | `g_store_pow_gate` (`engine/controllers/src/store_controller_pow.c`) | product id | floor 20 bits, max 24, 180 s epoch, 300 s skew |
| snapshot serve (load census only) | `g_snapsync_serve_load_gate` (`engine/services/src/snapshot_serve.c`) | n/a — `admit_external` | soft rate 2/s |

The store swap replaced a fixed 20-bit `fast_sync_verify_pow()` plus a
hand-rolled 4096-entry replay ring. The floor is pinned at the old fixed
difficulty on purpose: an idle node asks an honest buyer for exactly what
it asked before, and the swap only ADDS a server-issued rotating seed
(killing offline precompute against a constant challenge) and a load ramp.
The order form now carries `data-pow-seed` and `data-pow-token` alongside
`data-pow-ts` / `data-pow-bits`; the in-page JS solver hashes the 80-byte
`seed || token || ts || nonce` preimage.

## Where the nonce search starts is part of the contract

A search from zero is a pure function of `(seed, token, ts)`. Two honest
solvers that share all three — same surface, same wall second — return the
SAME nonce, and a single-use ring then refuses the second one's genuinely
solved puzzle as a replay. That is a way to break honest clients, not
attackers.

`puzzle_solve()` (from zero, deterministic, for tests and fixtures) is
therefore no longer what a real client should call:

- `puzzle_solve_random()` — from a random offset. The default for a client.
- `puzzle_solve_from()` — explicit start, when the caller owns the policy.

Costs are identical; the predicate is a leading-zero test on a hash, so no
start point is luckier. The browser solver in `contexts/explorer/views/src/store_view.c`
starts at a random offset for the same reason.

## Snapshot serve — why the verdict is not load-bearing yet

`snapsync_validate_serve_request()` (`engine/services/src/snapshot_serve.c`)
still admits on the legacy fixed-difficulty `fast_sync_verify_pow()` plus
the per-IP/global rate limiter. Every accepted request is additionally fed
to `puzzle_gate_admit_external()`, so the shared gate's load EWMA finally
sees real traffic on this surface — but the gate's answer is recorded as a
census (`snapsync_get_serve_puzzle_census`) and discarded for admission.

The reason, verified in the source rather than inherited:

- `snapsync_build_request_pow()` (`engine/services/src/snapshot_offer.c`) sets
  `peer_id = SHA3-256(peer_ip)` over a 16-byte address, then
  `fast_sync_solve_pow()` sets `timestamp` to whole wall seconds and walks
  `nonce` from 0. Every input is a pure function of (address, second), so
  two solves sharing both serialize to BYTE-IDENTICAL proof bytes.
- The address hashed is `node->addr.svc.addr.ip` at the requester's call
  site (`core/modules/net/src/msgprocessor_snapshot.c`) — the address of the peer
  being ASKED. So two DIFFERENT honest peers requesting from the same
  server in the same second also collide.
- The serve side never compares `pow.peer_id` to the connection the
  request arrived on (`peer_ip` feeds only the rate limiter), so the field
  binds nothing today.
- `tests/harness/src/test_snapshot_serve_loopback.c` runs the whole loopback
  twice in one process from one fixed loopback address, each time building
  a real `zsnapreq`; whenever the two runs land in the same wall second the
  proofs are identical. That test now asserts the request is served anyway
  and that the census accounts for it.

### The protocol revision that would make it enforceable

Out of scope for the change that added the census — it needs a
compatibility window on a live network.

1. The snapshot OFFER carries the server's live challenge:
   `challenge_seed[32] || difficulty_bits(u8) || server_time(i64)`, i.e.
   the output of `puzzle_gate_challenge()` on the serving node.
2. The requester derives
   `peer_token = SHA3-256("zsnapreq:" || its OWN advertised address || offer.block_hash)`
   — bound to the requester and to the specific offer — and solves against
   the server's seed.
3. The request carries `seed-echo || peer_token || ts || nonce`; the serve
   side calls `puzzle_gate_verify()` and gets the rotating seed, adaptive
   difficulty and single-use for free.
4. Compatibility: a peer that sends no seed echo keeps being validated by
   `fast_sync_verify_pow()` for one release window, until the census shows
   the legacy path is unused.

Step 2 is what removes the collision: distinct requesters get distinct
tokens.

Deliberately NOT done as a shortcut: randomizing the nonce start inside
`fast_sync_solve_pow()` would de-collide our own solver, but it changes
what this node puts on the live wire and does nothing for peers running the
older binary — which is the population that matters.

## Still off the gate

- **ZNAM name registration** (`contexts/explorer/controllers/src/name_site_controller.c`)
  — fixed `FAST_SYNC_POW_BITS` behind its own 4096-entry replay ring
  (`name_pow_claim_once`), the same shape the store just shed. It binds a
  per-name token already, so it is the same direct swap the store was.
- **`msgprocessor` snapshot-request PoW** (`SNAP_POW_*` in
  `core/modules/net/include/net/msgprocessor.h`, implemented in
  `core/modules/net/src/msgprocessor_snapshot_serve.c`) — a second hand-rolled
  adaptive puzzle with its own bucket epoch, difficulty ramp and grace
  window, default-disarmed.

Both are one-primitive candidates, neither is on this change.
