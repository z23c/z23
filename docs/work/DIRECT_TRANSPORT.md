# Direct transports: UDP fast path, IP discovery, and disclosure control

> **Owner decision (2026-08-23): build the UDP datagram fast path, PEX-lite
> clearnet discovery, and per-node disclosure posture as one parallel wave
> beside the mesh acceptance track.** Onion remains the always-on private
> fallback ([`NAT_AND_ONION_TRANSPORT.md`](./NAT_AND_ONION_TRANSPORT.md)
> owns that landed layer); this document owns everything that makes nodes
> FAST without giving up censorship resistance or user control. Application
> plane only — no consensus surface anywhere below.

## The ladder this completes

1. TCP clearnet direct (`-addnode ip:port`) — shipped.
2. Coordinated hole-punch — deliberately deferred behind UPnP/mapping work;
   strict-NAT pairs fall back to TCP/onion until then, recorded honestly.
3. Onion circuit as always-on rendezvous/fallback — **shipped**
   (raw dynhost streams, socketpair bridge, operator-directed peers).
4. **UDP direct sessions** — this document's subject: game/voice/video-grade
   latency between discovered peers.

Racing policy per realtime session: try transports in order UDP → TCP →
onion; every attempt measured; failures are named rows, never silent
fallbacks that hide a broken path.

## Component 1 — UDP session transport

New `lib/net/udp_transport.{h,c}`:

- One bound UDP port per node (`-udpport`, defaults adjacent to the P2P
  port). The port is application-plane only; block relay never rides it.
- Minimal framing (~32-byte header): session id, sequence, ack window,
  epoch. Two per-session profiles:
  - `DATAGRAM` — lossy-tolerant (game state, telemetry). No retransmit.
  - `ORDERED_RELIABLE` — bounded retransmit window (mini-KCP-style) for
    voice/video framing. Explicitly **not** QUIC; no congestion-policy
    ambition beyond pacing caps.
- Handshake authenticates via the existing Noise integration keyed to each
  node's secp256k1 identity; proof-of-possession precedes any reply larger
  than the handshake itself (amplification refusal), plus per-source-IP
  rate limits from byte one.
- Hard byte caps per session and global. The blockchain wins contention by
  construction: UDP egress yields before chain-critical traffic, and the
  cap is enforced numerically, not by convention.

## Component 2 — discovery by IP: PEX-lite

Today onion peers are operator-directed and never gossiped — correct for
privacy, but it leaves "discover peers by IP" with no primitive at all.

- New `addr` wire message relaying **clearnet endpoints only**: addresses
  self-announced via `-externalip` plus the observed source address of
  inbound connections. Rate-capped per peer and per epoch.
- Onion endpoints are **never gossiped** — unchanged stance.
- Emission passes the node's disclosure-posture authority (component 4);
  a node whose posture forbids clearnet publication is never inserted into
  anyone's table by its own action.
- Acceptance: a fresh node connecting to ONE seed learns ≥2 dialable IPs
  without any operator file; hermit-mode capture test shows zero hits
  (below).

## Component 3 — session invites over ZMSG

`zses:v1` memo schema carried by the existing ZMSG p2p channel:
`{endpoints:{udp,tcp,onion}, app, psk}`, signed by the sender identity.

- Signaling is censorship-proof (rides the same path as fleet chat);
- Media dials the fastest endpoint the INVITE discloses, racing
  UDP → TCP → onion;
- A hermit can share exactly one direct endpoint with exactly one friend
  inside the point-to-point channel — precise sharing without public
  exposure. Broadcast posture governs directories; invite contents govern
  themselves.

## Component 4 — disclosure posture (user control)

One authority function consulted at EVERY advertisement emission point:
directory.json writer, ZDIR record builder, PEX relay hook, and invite
generator.

| Posture | Advertised | Meaning |
|---|---|---|
| `onion` (**default**) | onion endpoint only | reachable by anyone, privately |
| `clearnet` | onion + declared IP:port | fast path offered to all |
| `none` (hermit) | nothing, anywhere | dial-out only; syncs fine |

Rules:

- Default is `onion`. Clearnet publication requires an explicit operator
  act (`-externalip` present AND `-announce=clearnet`).
- Hermit nodes complete full sync, ZMSG, and UDP sessions while appearing
  in no discovery surface; a capture gate greps directory/PEX/census
  artifacts for their absence on every run.
- Honest limitation, stated once: unpublished ≠ unseen. Any direct peer
  observes the connection source. True invisibility means onion-only
  operation — which is why it is the default.
- Operator truth card in `z23 status`: one plain-language line ("the world
  can see: your .onion address") plus the single command to change posture.

## Measurement

RTT sampled per session and surfaced in census/status columns; the drill
publishes `{udp_rtt, loss%, tcp_rtt, onion_rtt}` triples per host pair to
`deploy/devfleet/session_clock.jsonl`, alongside the existing join-clock
ledger. UX and speed are managed numbers on main, not adjectives.

## Lanes, risks, and gates

| Lane | Owner | Owns | Gate |
|---|---|---|---|
| A | node2 | `lib/net/udp_transport.*`, noise handshake, PEX msg + posture hook | M1 loopback handshake prints RTT |
| B | node3 | announce plumbing, directory/ZDIR fields, census RTT column | M2 PEX learning + hermit capture-test |
| C | node4 | `zses:v1` schema, invite/accept leaves, drill script, truth card | M3 real-internet session <100 ms recorded |

Merge order A→B→C. Named risks, documented not hidden: strict-NAT pairs
fall back until mapping/UPnP lands (rung 2); amplification blocked by
proof-of-possession + rate limits; scope discipline forbids QUIC ambitions;
the UDP layer can never touch consensus or block-relay paths because it
does not share code with them.
