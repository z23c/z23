# Onion dial gap — local repro and root cause

Status: LIVE-REPRODUCED defect, 2026-08-23. Owner: `lib/net` connection
opening. Referee evidence cross-checked against
[`deploy/devfleet/mesh.status`](../deploy/devfleet/mesh.status)
(`INGRESS_TRIAGE_VERDICT=PEER_SIDE_DIAL_BROKEN`, capture
`node4-redial-20260823T0740Z`).

## The one-sentence finding

No code path in the node opens a P2P socket **through Tor** to a remote
`.onion` destination: `-addnode=<host>.onion:<port>` is scheduled but the
connection opener only dials numeric addresses, so every operator-directed
onion edge silently never connects while both embedded Tor clients look
perfectly healthy.

## How it was reproduced locally (two fresh isolated nodes)

Script shape (sourced isolation, regtest, `-listen -tor -onion-persist`):

1. Node A boots; persistent identity mints; hostname file appears in ~8 s.
2. Node B boots with `-addnode=<A.onion>:<A.p2p-port>`.
3. Poll `getconnectioncount` on B for 60 s.

Result, repeated across runs on the current main build:
`VERDICT=no_dial_within_60s`.

- B's tor: `Bootstrapped 100% (done)` — client healthy.
- A's tor: service published, directory traffic flowing.
- B's `node.log`: its own `onion_self_registered` line, then **not a single
  log line about attempting the A.onion dial** — no resolve, no SOCKS
  attempt, no failure. The dial is not failing; it is never issued.

Control: clearnet pairs on the same box pair in seconds; node1's hub shows
healthy clearnet ZClassic23 edges at full height while every `.onion` row
sits at `startingheight:0` and ages out.

## Why the fleet table looks half-alive

`core.network.peers.add` documents that a v3 onion is *resolved through its
Tor-served directory first, then each advertised numeric fast path is
persisted and scheduled*. So peer rows can display an onion address while
the actual socket attempt was a plain numeric dial to a directory-advertised
IP. On live machines with routable addresses that accidentally works; for
isolated/regtest nodes behind NAT there is nothing numeric to dial, so the
edge sits at height 0 forever. This explains:

- mesh referee `MESH=1/4` with three peers stuck pre-handshake;
- dev1's capture: zero inbound streams during bracketed redials;
- `PEER_SIDE_DIAL_BROKEN`: correct observation, wrong side blamed — the
  dialing side never dials *over Tor*.

## The fix (owned slice)

Route `.onion` destinations through the per-datadir embedded-tor SOCKS5
listener (`SocksPort 127.0.0.1:<auto>`, already written by the integration
to `<datadir>/torrc`) using ATYP=domainname with remote name resolution:

- in the connection opener, detect torv3 hosts; open SOCKS5 to the local
  tor SocksPort; send CONNECT with the onion host + port; proceed with P2P
  framing on the accepted stream;
- keep numeric paths byte-for-byte unchanged;
- log the attempt (`addnode <onion>:<port>: tor socks dial`) so absence of
  a dial can never again masquerade as a failed one;
- regression: two-node sourced-isolated pair over onion must reach
  `getconnectioncount >= 1` within the 120 s dial budget (the probe above,
  promoted into the test tree).

Acceptance is the fleet metric itself: after this lands, node2/3/4 join
cycles should show real inbound rows on node1 and MESH should climb past
1/4 for the first time.

## Probe artifacts

Probe script pattern and raw logs live outside the tree (`/tmp/opencode`,
ephemeral by policy); the durable record is this document plus the named
verdict fields above. Re-run cost: under two minutes on any checkout with
`make tor-full` done.
