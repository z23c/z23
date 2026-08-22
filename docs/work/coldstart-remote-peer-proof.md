# Cold start to tip against a REMOTE peer

The C3 wipe-to-tip stopwatch (`tools/scripts/cold_start_to_tip_stopwatch.sh`)
has only ever been run against a peer on the same machine. Loopback is
structurally privileged on **both** sides of the wire, so a loopback pass
cannot stand in for a remote one:

- **client side** — `is_trusted_peer()` in `lib/net/src/net.c` exempts
  `127.0.0.0/8` and `-whitelist` peers from `peer_misbehaving()`, so a loopback
  client never rides the score-to-ban path;
- **server side** — the per-IP inbound sybil cap in `lib/net/src/net.c`
  ("too many inbound connections from same IP", max 3) is only ever contended
  when several clients share one source IP, which is the remote case and never
  the one-node-per-loopback case.

`make mvp-coldstart-to-tip-remote` pins the remote invocation.

## Run

```
bash tools/scripts/cold_start_to_tip_stopwatch.sh \
    --peer=198.51.100.10:8033 --budget=600 --sample=15
```

Fresh `/tmp` datadir, isolated `$HOME`, ports 39170-39173, `-listen=0`,
`-nolegacyimport`, `-nobgvalidation`, no bundle / snapshot / import flags.
Read-only P2P client: the remote's datadir and services are never touched.

## Result

**Exit 4 — STALLED-NAMED.** `WALL_CLOCK_SECONDS=607`, one boot, budget 600 s.
H\* and the provable sample never left zero across all 41 samples;
`network_tip` was never readable (`-1` in every row, `network_tip_read_ok`
never true). One active blocker the whole run:
`bootstrap.no_state_source` (owner `bootstrap`, class `dependency`).

This is a genuine stall with a named cause, not a silent stall and not a SKIP.
It is also not a SEAM: nothing climbed, so there is no forward progress to
report and no wall-clock number worth publishing.

## Named cause: the P2P handshake never completes

`dumpstate peer_lifecycle` during the run:

```
attempted 8, connected 8, version_sent 2, version_received 0,
verack_received 0, handshake_complete 0, pre_handshake_disconnects 8
```

Every attempt reached TCP and none reached the handshake; the captured
`node.log` carries 18 `protocol failure before handshake` lines over the run.

`dumpstate connman` addnode ledger for `198.51.100.10:8033`:
`tcp_failures 0`, `protocol_failures 1+`, `backoff_sec 60`. Node log:

```
Addnode 198.51.100.10:8033: protocol failure before handshake
    (remote-close, state=connecting)
```

TCP connects succeed; the peer closes the socket before any version/verack
exchange completes. A bare probe confirms it independently — connect, send
nothing, read: EOF arrives immediately, zero bytes.

Because no peer ever reaches `PEER_HANDSHAKE_COMPLETE`, no peer height is ever
advertised, `network_tip` stays unreadable, and the PASS predicate
(authoritative H\* ≥ `network_tip`) is unreachable by construction for the
whole budget — independent of any reducer-side defect.

## The peer-ban theory is refuted for this run

The client-side ban path (`lib/net/src/peer_scoring.c` weights `invalid_block`
/ `protocol_violation` at 100 against a threshold of 100) was never entered: no
`banlist.dat` is written in the wiped datadir (`banlist_present: false`), no
`peer_banned` line appears in the node log, and `peer_misbehaving()` requires a
message-layer offence that a connection dying pre-version can never produce.
The exclusion happens on the **serving** side, at `accept()`, before scoring
exists.

The fitting server-side rule is the per-IP inbound cap in `lib/net/src/net.c`:
`same_ip_count >= 3` closes the socket immediately with
`too many inbound connections from same IP`. `ss -tn state established 'dst
198.51.100.10:8033'` shows this host already holding exactly three
established sockets to that peer — the cap value — opened by the canonical node
that shares this machine's public IP. The harness node is the fourth connection
from the same source IP and is refused at accept. This is the sybil defence
working as written; the consequence is that a second node behind one IP (or any
NAT) cannot cold-start off that peer.

## Harness changes landed with this record

1. **Peer precheck** (`peer_precheck` / `classify_peer_precheck`). The old
   check treated "TCP connect succeeded" as "serving peer present" — true on
   loopback, false here. The probe now connects without sending a byte and
   classifies `unreachable` / `held_open` / `accept_close`. `accept_close`
   prints a loud warning naming the per-IP cap and the `ss` command to confirm
   it, and is recorded as `peer_precheck` in `proof.json`. It is deliberately
   **advisory**: it never converts a verdict, and an accept-closing peer is
   never laundered into a SKIP. The pure classifier is covered by `--selftest`.
2. **Network capture in the failure bundle.** Non-pass runs now write
   `net-connman.json`, `net-peer_lifecycle.json`, `net-network.json`, and
   `banlist.dat` when one exists (`banlist_present` in `proof.json`). The first
   question a remote non-pass verdict raises — did we ever handshake, and did
   we ban our only peer — was previously unanswerable from the artifact alone,
   because a loopback peer always handshakes.

## What a next remote run needs

Either a peer whose per-IP inbound allowance for this host is not already
consumed (free a slot, use a different source IP, or `-whitelist` the client on
the serving node), or a different serving peer. Until a run reaches
`peer_precheck=held_open` and a completed handshake, no remote run can measure
the reducer at all.

## Code changes landed in response (lane B)

The refusal is enforced by the **serving** node, so nothing in this tree can
unblock a run against a peer that is already at its cap for our source IP
without that peer also running the new code. What landed is the removal of the
two structural reasons a single-peer node cannot be recovered:

1. **The per-IP inbound cap is no longer a bare literal.** `accept_connection()`
   (`lib/net/src/net.c`) now reads `peer_scoring_max_inbound_per_ip()` —
   `ZCL_PEER_MAX_INBOUND_PER_IP`, default 3, clamped to `[1, 4096]`. An operator
   serving a host that legitimately runs several nodes (or any NAT) can raise it
   without a patch. The refusal log line now names the cap, the env var, and the
   fact that the dialling node can only observe a zero-byte remote-close — the
   serving side is the only side that knows why the socket died.

2. **A ban can no longer strand a node that has exactly one peer.** The offence
   weights and the ban threshold are untouched — `INVALID_BLOCK` /
   `PROTOCOL_VIOLATION` still score 100 and still cross the threshold on the
   first hit, the peer is still scored, still banned, still disconnected. What
   `peer_misbehaving()` now bounds is the ban's **duration**, and only when the
   ban would leave the manager with zero live peers: `ZCL_PEER_LAST_PEER_BAN_SECS`
   (default 600, clamped to `[60, 86400]` so it can never be harsher than the
   ordinary path) replaces `ZCL_PEER_BAN_HOURS` for that one case. With any
   second peer connected the branch is not taken and behaviour is unchanged.
   Taking it raises the typed blocker `net.last_peer_ban`, cleared at
   `peer_lifecycle_note_handshake_complete()` — the single choke point every
   completed handshake passes through, i.e. the honest witness that the route
   back to the network exists again.

The **peer-ban hypothesis was refuted for the 2026-07-27 run** and this record
should not be read as fixing it: zero `peer_banned` lines were logged, no
`banlist.dat` was written, and `peer_misbehaving()` was never entered because
the connection died before the version exchange. Change 2 closes the hazard for
the first run that *does* complete a handshake and then hits one
misclassification.

Also corrected: the comment above `peer_misbehaving()` claimed addnode peers
were exempt from penalty. `is_trusted_peer()` checks localhost and whitelisted
only — it never checked addnode. The exemption was **not** added (operator
intent to dial an address is not evidence the address serves valid consensus
data); the comment now states what the code does, and the stranding risk the
false claim implicitly covered is handled by the bounded ban above.
