# NAT traversal, onion hosting, and fast P2P transport — design notes (2026-07-27)

> **Owner decision (2026-08-22): onion P2P transport landed on the raw
> dynhost stream API, NO SOCKS.** zclassic23 never proxies P2P through a
> SOCKS port. Outbound onion dials use the fork's raw bidirectional stream
> API (`dynhost_stream_open/write/close`,
> `vendor/tor/src/feature/dynhost/dynhost_stream.h`) via the socketpair <!-- doc-path-ok: vendor/tor is a submodule; the dynhost fork header lives inside it -->
> bridge in `lib/net/src/onion_stream.c`, which presents the circuit to connman as an
> ordinary connected fd — the reactor, version handshake, and message layer
> are unchanged. Onion peers are **operator-directed only** (`addnode`,
> `-addnode`, seed entries): they are parsed locally
> (`net_addr_from_onion`), never DNS-resolved, never dialed over clearnet,
> and **never gossiped** — deliberately no BIP155-style addr wire change.
> Inbound P2P rides the persistent onion identity's SECOND port mapping
> (`tor_try_install_persistent_identity` in `lib/net/src/tor_integration.c`):
> virtual port = the node's P2P port, forwarded by stock hidden-service
> machinery to `127.0.0.1:<p2p_port>`; it is NOT a dynhost virtual port
> (that would land in the HTTP interception layer). The
> `MAX_OUTBOUND_ONION` diversity cap (3) bounds outbound onion slots while
> permitting all remote edges of a four-node operator mesh.
> Onion dials carry their own 120 s connect budget
> (`ONION_STREAM_CONNECT_TIMEOUT_MS`); the clearnet dialer's shared 5 s
> window is never applied to them. Everything below remains the larger
> design context.

Owner question: how to use Tor for NAT traversal, keep fast P2P networking,
and build both robustly into Z23 (onion hosts, ZNAM hosting, the
package swarm, future P2P services). All of this is P2P-layer policy — no
consensus surface anywhere in this document.

## The core insight

Tor already solves the hard half of NAT traversal: an onion service is
reachable from anywhere without port forwarding, because both sides build
OUTBOUND circuits to a rendezvous point. A node behind CGNAT can host and
dial. What Tor does not give is speed: multi-hop circuits add latency and
cap throughput, which matters for header/block exchange and the package
swarm.

So the architecture is **onion as the universal rendezvous and fallback,
clearnet as the fast path, with a coordinated upgrade between them** —
conceptually ICE-lite, but with the onion channel playing the role of the
signaling channel that is guaranteed to exist.

## What already exists (do not rebuild)

- Embedded modified Tor (dynhost fork) running in-process; ephemeral or
  persistent onion; the whole REST surface served over onion by direct C
  dispatch (`lib/net/src/onion_service.c`) — no SOCKS, no HTTP parsing.
- `/directory.json` on each onion: advertises onion address, clearnet
  IP:port, height, version. A fresh node bootstraps Tor (~10 s), fetches
  directory records from hardcoded onion seeds, extracts clearnet IPs, and
  connects directly. This IS the rendezvous layer, already deployed.
- ZNAM `ZNAM_TYPE_ONION` records — a human name can point at an onion;
  `ZNAM_TYPE_CONTENT` fits package roots. Names are pointers, never trust.
- Noise XX/NK handshake + v2 encrypted transport
  (`lib/noise/src/noise_handshake.c`, `lib/net/src/v2_transport.c`),
  armed as initiator, default OFF pending rollout.
- P2P ping wire type (game framework Type 0) — per-peer RTT measurement in
  microseconds (`core network peers latency`), exactly the signal transport
  selection needs.
- `peer_scoring` offence taxonomy — per-peer accounting to extend per
  transport.

## The transport ladder (target design)

Each peer endpoint is tried in this order, measured, and the winner cached:

1. **Direct clearnet TCP** — lowest latency when the peer is reachable
   (public IP, or the NAT already has a mapping). This is today's default.
2. **Coordinated simultaneous open ("hole punching")** — when both peers
   are behind NAT: they meet over the onion channel, exchange endpoint
   candidates (observed external IP:port as seen by the other side and by
   directory witnesses), then attempt simultaneous TCP connect with a short
   window. TCP simultaneous open works on many NATs; when it fails, nothing
   is lost — the onion session is still up. UDP-based punching is out of
   scope for the block-relay transport (reliable ordered byte stream
   required); it may later serve the latency-game traffic.
3. **Onion circuit** — always available, always works, slower. The control
   channel for (2) and the permanent fallback. Swarm bulk transfers can run
   over onion at reduced concurrency with honest bandwidth accounting.

Selection is measured, not configured: race the candidates happy-eyeballs
style on first contact, keep per-peer per-transport RTT/throughput stats
(the ping wire type), prefer the fastest that stays healthy, and demote a
transport that degrades rather than dropping the peer.

## Identity across transports (the security-critical rule)

A peer MUST present the same cryptographic identity on every transport —
otherwise "upgrade to clearnet" is a downgrade attack: an on-path NAT
neighbor could impersonate the peer once it leaves the onion circuit. The
binding options, in order of preference:

1. Noise XX with static keys — the handshake authenticates both endpoints;
   the static key IS the peer identity on clearnet, onion, and punched
   connections alike. This is the strongest argument for finishing the v2
   transport rollout (currently default OFF).
2. Until Noise is default: a challenge/response over the established
   channel binding a secp256k1 peer key to the session before any
   fast-path traffic is trusted (the `auth_challenges` machinery is the
   model).

Directory records are SIGNED by the peer key (onion + clearnet endpoints
+ port + services + height + expiry), so a poisoned directory cannot
reroute peers to attacker endpoints. The record is a `zid_doc` with body
tag `ZIDE` (`lib/zid/include/zid/zendp.h`), distributed as a blob over
the already-frozen `zpkgswm` swarm codec (`lib/vcs/include/vcs/zendp_swarm.h`)
— no new wire message. The signing key is resolved against the on-chain
identity projection (`db_zid_identity_find`), and a key that was never
anchored, was rotated away, or was revoked is refused with its own named
error; with no chain lookup registered the module fails CLOSED.

That does NOT make a record proof of who answers: binding the SESSION to
the key needs the Noise v2 transport, which is default OFF because every
peer on the live network speaks v1 today. So a record remains a HINT
about where to look. It ADDS a place to try alongside the unsigned
wallet scrape and the signed descriptor directory, and it can never
remove, filter, or rank down a peer from any other source — the only
sanctioned influence path is `addrman_publish_reputation_weights`, bounded to
a [1.0, 4.0] dial-chance multiplier. Signed sources together may fill at
most half of any discovery slate, so a flood of records cannot squeeze
out the source that always works. That discipline is explicit in
`net/onion_discovery.h` and `config/src/boot_onion_discovery.c`.

Still open on this record: the clearnet address + port it carries are
verified and unused — feeding them in as addrman candidates (via the
bounded weight above) is its own slice.

## ZNAM hosting

A node's ZNAM record can advertise its CURRENT endpoints (onion, clearnet,
supported protocol versions), which solves the ephemeral-onion discovery
problem with a stable human name: resolve name → signed endpoint record →
connect by the ladder above. Discipline unchanged: ZNAM is a pointer; the
peer's key, established in the session, is the identity. Name records are
advisory hints for FINDING endpoints, never proof you reached the right
one.

## Robustness requirements (what "built robustly" means here)

- Never a hard dependency on any single transport: clearnet-only nodes,
  onion-only nodes, and dual nodes must all remain first-class.
- Per-transport failure accounting in peer_scoring (failed punches are
  cheap and expected; they must never count as offences against the peer).
- Bounded punch attempts: one coordinated try per peer per cooldown window,
  small candidate set, hard timeout, clean fallback — punching is an
  optimization, never a blocker for sync.
- All endpoint hints (directory, ZNAM, peer-gossiped) are untrusted input:
  bounded, parsed fail-closed, and only ever used to ATTEMPT connections.
- Onion admission control (`onion_ratelimit`) already classifies routes;
  any new endpoint (directory v2, punch-coordination messages) gets
  classified there too.
- Every new wire message gets the swarm-codec treatment: pure bounded
  codec first, exact-length parsing, KAT tests, THEN transport wiring.

## Suggested slice order (when this program is scheduled)

1. ~~Signed directory records (peer-key-signed endpoint attestations) +
   consumer-side hint discipline.~~ DONE — `ZIDE` records over the blob
   swarm, chain-anchored key check, wired as an additional discovery
   source (`test_zendp`). The clearnet half of a record is carried and
   verified but not yet an addrman candidate.
2. Per-transport RTT/throughput stats wired into peer selection (the ping
   infrastructure already measures; persist and use it).
3. Noise v2 default-ON rollout plan (identity across transports depends on
   it).
4. Punch-coordination message codec (pure, tested) over the onion channel.
5. Simultaneous-open attempt + measurement, off by default behind a flag.
6. ZNAM endpoint records for stable naming of dynamic endpoints.
7. Onion-hosted service hardening for ZCODE (`/zcode*` routes classified,
   rate-limited, same projections as typed commands).

No slice touches consensus; every slice lands behind its own gate with the
existing fast-ci + lint + adversarial-test bar.
