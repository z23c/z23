<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# 0002: Streams over the peer link

| Field | Value |
|---|---|
| ZRC | 0002 |
| Title | Streams over the peer link |
| Status | draft |
| Owner | orchestrator |
| Created | 2026-09-05 |
| Supersedes | none |

## Problem

The owner wants tunnels — starting with an SSH-style port tunnel, and later
low-latency traffic such as a game — to travel through Z23's own peer link
rather than through a separate side channel, so the transport is
authenticated by the same identity the node already uses and needs no extra
service outside the node.

A confined, paired, Noise-bound PTY terminal already exists for interactive
shell access (see Prior art below), so terminal access itself is solved.
What is still missing is a general way to carry an arbitrary, ordered,
flow-controlled byte stream between two paired nodes — the primitive an SSH
port tunnel needs, and the same primitive a future low-latency datagram path
for games would sit beside. Building that as a brand-new wire message and a
brand-new allowlist would duplicate machinery the terminal and status lanes
already proved out on the exact same peer link.

## Design

### Prior art to extend

This proposal is a third protocol multiplexed the same way two protocols
already are, and it reuses the pairing model both already trust:

- **The shared carrier.** Every protocol below rides one already-frozen P2P
  message, `"zpkgswm"` — its dispatch row lives in
  `core/modules/net/src/msgprocessor.c` and is documented in
  `core/modules/net/include/net/msgprocessor.h`. No protocol built on it adds
  a new P2P command, a new listener, or a new port; each adds its own
  fixed-string frame prefix and a one-byte frame kind inside the payload.
  `engine/composition/include/config/boot_zcode_swarm.h` and
  `engine/composition/src/boot_zcode_swarm_membership.c` show the package
  swarm's own frames on this carrier.
- **The paired terminal (the model to copy).**
  `engine/composition/src/boot_mesh_terminal.c` and
  `engine/composition/include/config/boot_mesh_terminal.h` implement a
  confined interactive shell over its own `"ZMTERM"` frame prefix on
  `"zpkgswm"`: an OPEN frame is admitted only over a live, established Noise
  session whose pairing row carries a specific capability bit, sessions live
  in a bounded table with an idle timeout and a hard concurrency cap, bytes
  move as bounded DATA frames, and every session ends with a named close
  reason. `engine/composition/src/boot_mesh_status.c` and
  `engine/composition/include/config/boot_mesh_status.h` show the same
  prefix-plus-kind framing used for a second, simpler protocol (`"ZMSTAT"`)
  on the same carrier, which is why this is a pattern to follow, not a
  one-off borrowed from a single file.
- **The pairing and capability model (the allowlist to extend).**
  `engine/models/include/models/mesh_pairing.h` and
  `engine/models/src/mesh_pairing.c` already bind an Ed25519 master identity
  to a peer's X25519 Noise static key in a durable local row
  (`db_mesh_pairing`) carrying a `capability_mask`; `MESH_PAIRING_CAP_TERMINAL_EXEC`
  is exactly this kind of bit, granted at pairing commit time and checked at
  OPEN admission in `engine/composition/src/boot_mesh_terminal_client.c` and
  `engine/composition/src/boot_mesh_terminal.c` through
  `engine/services/src/mesh_pairing_service.c` and
  `engine/controllers/src/mesh_pairing_controller.c`. This is the allowlist
  this proposal extends — a peer static key is already the pairing identity,
  and a capability bit is already the "may do X" grant — rather than a new,
  separate allow-file format keyed by the same static key a second way.
- **The raw byte pump (for the tunnel's local-socket half only).**
  `core/modules/net/src/onion_stream.c` already bridges one stream to a
  local socket with a supervised pump thread; the tunnel service's local
  half (dialing or listening on a plain TCP socket) reuses that pump pattern
  for the non-P2P side of the copy rather than writing a second one.

### Stream multiplexing on the existing carrier

Add one new frame-prefix protocol on `"zpkgswm"` — a stream-multiplexing
lane, sibling to `"ZMTERM"` and `"ZMSTAT"`, not a new top-level P2P message
and not a new dispatch row in `msgprocessor.c`. Its own frame kinds (OPEN,
DATA, WINDOW, CLOSE) carry a stream id so one link carries many concurrent
streams, the same way `"ZMTERM"` already carries up to its own bounded
number of concurrent terminal sessions on one link. A new top-level wire
command is proposed only if review finds this frame envelope genuinely
cannot express what stream credit and window semantics need; that finding,
and why, must be recorded in this ZRC before it is accepted with that
change.

- OPEN is admitted only over a link with a live, established Noise session
  bound to a pairing row that carries a new capability bit for this service
  (parallel to `MESH_PAIRING_CAP_TERMINAL_EXEC`), checked the same way and
  through the same `mesh_pairing_service.c` / `mesh_pairing_controller.c`
  path the terminal lane already uses. A stream is refused, never silently
  carried, over a link without an established session bound this way.
- Data frames are capped in size so that one stream cannot starve the shared
  link — this matters once low-latency traffic (a future game path) shares
  the same link as a bulk tunnel.
- Flow control is credit-based: a receiver grants window through a WINDOW
  frame, and the sender never sends more than the credit it currently holds.
- A stream closes with a named reason, has an idle timeout, and a link
  enforces a hard cap on how many streams it will carry at once — the same
  shape `MESH_TERMINAL_SESSIONS_MAX` and the terminal lane's admission
  ceiling already give the terminal lane.
- Opening a stream also names a service string (for example
  `tcp:<host>:<port>` for the tunnel below), so later services reuse the
  same OPEN frame with a different service name rather than their own frame
  prefix, unless a later service's framing needs genuinely diverge.

### First service: the TCP tunnel

One side of the tunnel dials a local target (for example a local SSH
daemon) and pumps bytes both ways over one stream, reusing the
`onion_stream.c` pump pattern for the local-socket half. The other side
listens on a local loopback port and maps each accepted connection onto a
new stream. The tunnel does not need to know or care what protocol runs
inside it; an SSH client on one node reaching an SSH daemon behind another
node's tunnel is the first concrete use, but the tunnel is
protocol-agnostic. Beyond the capability-bit check at OPEN, the tunnel
service carries its own target policy: loopback-only by default, with a
non-loopback target refused unless an explicit policy row names that host.

## Acceptance

- A stream OPEN request over a link without a live, established Noise
  session is refused, and the refusal names the missing authentication
  rather than failing silently or opening anyway.
- A stream OPEN request whose pairing row does not carry the service's
  capability bit is refused, and the refusal names the missing capability.
- A sender cannot push data past the receive credit its peer has granted; a
  test demonstrates credit exhaustion blocking the sender until a WINDOW
  frame arrives, and the sender resuming once it does.
- A TCP tunnel opened between two paired nodes carries bytes unchanged in
  both directions, proven by a loopback test that pumps a nontrivial amount
  of data through it and compares what went in against what came out.
- A non-loopback tunnel target is refused unless an explicit policy row
  allows that host.
- No new top-level P2P command or `msgprocessor.c` dispatch row is added
  unless this document is updated first with the specific framing gap that
  required it.
- Every new file this proposal adds is reachable by the codebase's own
  test-routing command, and its registered tests pass.

## Out of scope

The low-latency datagram path, turning the Noise transport on by default
(it stays opt-in for this proposal), any change to the existing terminal
lane (`boot_mesh_terminal.c`), and any object or file-transfer service built
on the stream lane. Each is its own follow-on ZRC.

## Landing

Not yet landed.

## Discussion

Board rows carrying `zrc-0002` (see
[`../agent/NATIVE_CHANNEL.md`](../agent/NATIVE_CHANNEL.md) for how the
interim board works today), until
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md)
lands and the wiki page for this ZRC becomes the index.
