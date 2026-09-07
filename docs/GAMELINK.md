# gamelink — the low-latency datagram link between two fleet peers

The first piece of "gaming-level networking between fleet agents": one
unreliable-sequenced, authenticated-encrypted UDP channel between two peers
that have already paired over Noise and can already reach each other. It is
the DATAGRAM profile of [`DIRECT_TRANSPORT.md`](./work/DIRECT_TRANSPORT.md)
"Component 1", and it lives in `engine/modules/gamelink/`.

It retransmits nothing and reorders nothing. A game snapshot that arrives late
is worse than one that never arrives, so a stale datagram is dropped and
counted rather than delivered out of turn. The reliable side channel a match
setup needs is the ZSTRM mux over the paired session
(`engine/composition/src/mesh_stream.c`), which this module does not touch.

## The wire

A fixed 34-byte big-endian header, then ChaCha20-Poly1305 ciphertext, then a
16-byte tag: magic `"ZGL"` (3) | version (1) | session id (8) | sequence, also
the AEAD nonce (8) | ack, the highest sequence this sender accepted (8) | ack
bits, the 32 sequences below it (4) | flags — ping, pong (1) | reserved, must
be zero (1).

The WHOLE header is the AEAD's additional data, so a flipped bit anywhere in
it — including the sequence number an attacker would want to move — fails the
tag instead of being accepted with a shifted meaning. The payload ceiling is
1,200 bytes, which stays inside a 1,280-byte IPv6 minimum MTU and holds about
two dozen skycombat aircraft states in one datagram.

## The security argument

Each direction gets its own key. Both come from `HKDF-SHA3-256(salt =
"z23/gamelink/v1/datagram", ikm = <the paired session's material>, info =
"keys+session-id")`, split into an initiator key, a responder key and the
64-bit session id. The fixed label is the domain separation: no key derived
here opens anything else, and no key derived elsewhere opens a datagram.

The AEAD nonce IS the 64-bit sequence number, so no nonce is used twice under
one key — and at the top of the sequence space the session REFUSES to send
rather than wrapping, because a reused ChaCha20-Poly1305 nonce loses both
confidentiality and the Poly1305 key. A bounded 64-sequence replay window
drops old and duplicate datagrams before any decryption, and only ADVANCES
after a datagram authenticates, so a forged header carrying a huge sequence
number cannot push it past live traffic. Anything failing a bound or the tag
is dropped silently and counted: an open UDP port receives whatever anyone
feels like sending, so a bad datagram is weather, not an incident, and a log
line per packet would be a denial of service somebody else controls.

**The honest limitation.** `core/modules/noise` exposes no dedicated exporter —
`noise_hs_split()` zeroizes the chaining key one would derive from — so the
caller feeds the material it DOES hold: the two directional record-layer keys
and the transcript hash. HKDF is one-way, so a compromised gamelink subkey
does not reveal the record-layer key. The converse does NOT hold: an attacker
who already holds the record-layer keys can derive these. Closing that needs
an exporter inside `core/modules/noise`, a later lane's work, and it is
written down here rather than papered over.

## The probe

```
z23 fleet link probe --seconds=3                   # this box's own floor
z23 fleet link probe --mode=echo  --bind=127.0.0.1:39997 --key=<64 hex>
z23 fleet link probe --mode=probe --peer=<ip:port> --key=<64 hex>
```

It reports `rtt_us`, `jitter_us`, `loss_ppm`, `sent`, `recv` and every counter
that says why a datagram did not arrive. A probe that hears no pong FAILS
rather than printing zeros: an unreachable peer must never read as a fast one.
The round trip is measured with ONE clock — a ping carries the sender's own
send time and the peer echoes those eight bytes back untouched — so no number
here can be wrong because two machines disagree about the time. Jitter is RFC
3550's estimator held in sixteenths of a microsecond; loss comes from
receive-side sequence gaps, the only place it is visible. `link.rtt_us`,
`link.jitter_us` and `link.loss_ppm` are fleet vitals, so a latency number
becomes a signed row like every other fleet fact.

## What is missing

- **Hole punching and rendezvous.** Both peers must already be mutually
  reachable; strict-NAT pairs have no path here at all.
- **The ORDERED_RELIABLE profile** of the design note. Not started.
- **Pairing plumbing.** Nothing hands this module a live Noise session's
  material yet, which is why `echo`/`probe` take an operator-supplied hex key.
- **skycombat wiring.** The game is still single-process split-screen.
- The design note puts this at `core/modules/net/udp_transport.*`. It landed
  under `engine/modules/gamelink/` because `core/` is sealed; moving it later
  changes no caller.
