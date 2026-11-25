<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Ephemeral onion ports and push receipts

Copyright 2026 Rhett Creighton. Licensed under the Apache License, Version 2.0.

Design only. This note does not install a port mapping, does not add a board
dial, and does not change consensus, custody, or a datadir. The implementation
belongs to a later change. Sealed `core/` stays sealed until that change has
its own unseal.

## What was measured

Capture: `/tmp/grok-goal-afe30a8fd48a/implementer/board-rtt.txt`
(host rhett2.dev, 2026-11-25). The node was the already-running devfleet
process. No canonical datadir was written and no new node was started.

Direct path. Command, three samples:

```
z23 -datadir=<devfleet datadir> -rpcport=18260 fleet board list --limit=1
```

The board client dials `127.0.0.1` only, so this is loopback RPC to that
local node, not a remote IP peer. Each sample exited 0.

| Sample | Wall ms (process start to exit) | Node `elapsed_us` |
| --- | --- | --- |
| 1 | 29.460 | 1519 |
| 2 | 24.870 | 1561 |
| 3 | 22.325 | 1547 |

Onion path. The same node reported an embedded onion service
(`core.network.onion.status`: `tor_ready`, `onion_service_ready`,
`p2p_publish_ready`, address
`n3c4bry42qzoiduhfqk33ugeptdycmnsmjnrkmjirrudtpw7xvhc5kid.onion`). The status
page truncated before a port map, so the capture does not say which ports
were mapped. Three samples asked the board list to use that onion:

```
z23 -datadir=<devfleet datadir> -rpcport=18260 \
  fleet board list --limit=1 --onion=<that onion>
```

Each attempt exited 2. The reply is `INVALID_INPUT`: unknown input key
`onion`. The client has no onion dial for `fleet board`. No onion board
round trip was measured. That path is `unreachable`. The refusal is not
a timing sample.

`core.network.onion.remote-status` was not used. It is not a board round
trip. An offline Tor stub is not a measurement either.

## What the node does today

`struct tor_onion_port_map` in `core/modules/net/include/net/tor_integration.h`
is the live virtual-port contract. The snapshot in
`tor_integration_port_map_snapshot` pins `application_virtual_port` to 80
(the HTTP route that serves `/directory.json`) and, only when
`-onion-persist` is on, expects a second route whose virtual port is the
node's own P2P listener, forwarded to `127.0.0.1:<p2p_port>`.

Default mode mints a fresh ephemeral onion every boot. That ephemeral
service gets no P2P route. `onion_directory_self_port_rule` returns 0 unless
`p2p_route_installed` is set, and it refuses virtual port 80. The comment
above that rule says an ephemeral identity has no dialable P2P port, and the
honest answer is unknown.

The file-service port is a separate stream from consensus P2P
(`docs/node/OVERLAY.md`, "Secure overlay transport"). It is not a field of
`tor_onion_port_map`. Outbound onion dials are raw dynhost streams. There is
no SOCKS listener and no second Tor process.

Board push already has a receipt. `fleet board delivery <id>` reads
`fleet_board_deliveries` (schema v93): the newest 4096 (post, peer) pairs,
each answer `stored`, `held`, `deferred`, `refused`, or `unknown`
(`no_receipt`, `peer_unsupported`, `no_record_verdict`). A post's `receipt`
field is at most 256 bytes and points at evidence. Public announce and fetch
carry no per-peer receipt. See `docs/agent/FLEET_BOARD.md`.

A landed state-offer file that `rom_fetch_verify_file` accepts against the
offer manifest is reused and not downloaded again. A missing file or a
failed verify is still fetched. That verify is the file's content receipt.

The board command menu and the running node can disagree. When the local
menu lists an op as ready and the node answers `UNKNOWN_OP` or JSON-RPC
method-not-found (`-32601`) for that op, the operator-visible failure is
`peer lacks op <op>, restart node`. An op the ready menu does not list,
including `offer_cpu`, keeps the unknown-op refusal.

## Proposal

One ephemeral onion, two extra virtual ports, and the receipts that already
exist.

### Port map

When embedded Tor mints the fresh ephemeral service, install the same two
extra routes the persistent identity should have, on that service, in the
existing dynhost map. Do not start a second Tor and do not open a SOCKS port.

- P2P. Virtual port equals the node's P2P listener. Target is
  `127.0.0.1:<p2p_port>`. Port 80 stays the directory HTTP route and is never
  this port.
- File. Virtual port equals the node's file-service listener. Target is
  `127.0.0.1:<file_port>`. It is distinct from 80 and from the P2P port.

If the file port is 0, 80, or equal to the P2P port, do not install a
colliding route. The snapshot then says that route is absent. A reader must
not invent a port from the loopback listener when the route is not installed.
`onion_directory_self_port_rule` stays the P2P rule. A separate pure rule
reports the file virtual port only when the file route is installed.

Extend `struct tor_onion_port_map` with `file_virtual_port`,
`file_target_port`, `file_route_expected`, and `file_route_installed`.
`expected_route_count` counts the file route beside the HTTP route and the
P2P route. `-onion-persist` keeps one address across restarts and gains the
file route beside the P2P route it already installs. Default mode still mints
a new onion every boot. The mapping is what changes, not the identity
lifetime. `-onion-rotate` still archives the old persistent identity.

Publishing the routes is a sealed-`core/` change (`tor_integration.c` and the
port-map struct). It waits for an explicit unseal. This note does not edit
`core/`.

### Push delivery

Board posts keep the existing Noise P2P push. Once the ephemeral onion
publishes the P2P port, a peer dials `<ephemeral>.onion:<p2p_port>` on the
existing onion stream. The receiver records the existing push receipt in
`fleet_board_deliveries`. There is no new receipt store and no new verdict.
The operator reads it with `fleet board delivery <id>`. Announce and fetch
stay without a per-peer receipt.

The board CLI does not accept an onion dial today, which is why the onion
samples above are unreachable. A later client change may name an onion as
the dial address for that push. It must not treat a loopback refusal as a
measured onion round trip. A menu-ready op the far node lacks still fails
with `peer lacks op <op>, restart node`.

File bytes use the file-service overlay on the mapped file port. The
handshake stays the one in `OVERLAY.md` (X25519, HKDF-SHA3-256, no SHA-256
fallback). Acceptance is `rom_fetch_verify_file` against the offer manifest.
That result is the file receipt. A file it accepts is not transferred again.
A file it rejects is fetched. No second content authority.

A push that gets no receipt by the deadline stays `unknown` / `no_receipt`,
as the board already records. It is not rewritten into `stored`.

## Non-goals

- Implementing the port map or the onion board dial in this change.
- A consensus predicate change, a custody change, or a canonical datadir
  edit.
- A SOCKS listener, an external `tor` process, or a second receipt table.
- Publishing port 80 as the P2P port or as the file port.
- Treating the loopback samples above as an onion measurement.

## Open measurement

The onion board round trip is still unmeasured. The direct samples are
loopback RPC: about 22–29 ms of process wall time, and about 1.5 ms inside
the node. An onion sample waits until a consenting peer can dial the mapped
P2P port on a live ephemeral service. Until then the onion section of the
capture stays `unreachable`.
