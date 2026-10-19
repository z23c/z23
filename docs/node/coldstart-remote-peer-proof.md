# Cold start to tip against a REMOTE peer

The C3 wipe-to-tip stopwatch (`tools/scripts/cold_start_to_tip_stopwatch.sh`)
has only ever been run against a peer on the same machine. Loopback is
structurally privileged on **both** sides of the wire, so a loopback pass
cannot stand in for a remote one:

- **client side** — `is_trusted_peer()` in `core/modules/net/src/net.c` exempts
  `127.0.0.0/8` and `-whitelist` peers from `peer_misbehaving()`, so a loopback
  client never rides the score-to-ban path;
- **server side** — the per-IP inbound sybil cap in `core/modules/net/src/net.c`
  ("too many inbound connections from same IP", max 3) is only ever contended
  when several clients share one source IP, which is the remote case and never
  the one-node-per-loopback case.

`make mvp-coldstart-to-tip-remote` pins the remote invocation.

## Run

```
bash tools/scripts/cold_start_to_tip_stopwatch.sh \
    --peer=<host>:8033 --budget=600 --sample=15
```

Fresh isolated datadir and `$HOME`, ports 39170-39173, `-listen=0`,
`-nolegacyimport`, `-nobgvalidation`, no bundle / snapshot / import flags.
Read-only P2P client: the remote's datadir and services are never touched.

## When the serving peer refuses this host

A peer at its per-IP inbound cap closes the socket at `accept()` before any
version exchange, so nothing climbs and the verdict is **exit 4 STALLED-NAMED**
(not a SEAM and not a SKIP) with the single blocker `bootstrap.no_state_source`
(owner `bootstrap`, class `dependency`). Signature:

- `dumpstate peer_lifecycle`: `connected` > 0 with `version_received 0`,
  `verack_received 0`, `handshake_complete 0` and equal
  `pre_handshake_disconnects`; `node.log` carries `protocol failure before
  handshake` lines.
- `dumpstate connman` addnode ledger: `tcp_failures 0`, `protocol_failures 1+`.
- A bare probe (connect, send nothing, read) gets EOF immediately with zero
  bytes.
- `ss -tn state established 'dst <peer>:8033'` shows this host's public IP
  already holding as many sockets to the peer as its cap.

Because no peer reaches `PEER_HANDSHAKE_COMPLETE`, no peer height is advertised,
`network_tip` stays unreadable, and the PASS predicate (authoritative H\* >=
`network_tip`) is unreachable independent of any reducer-side defect. The
client-side ban path is not involved: no `banlist.dat` is written and
`peer_misbehaving()` needs a message-layer offence that a connection dying
before the version exchange cannot produce.

A remote run needs a peer whose per-IP inbound allowance for this host is not
consumed (free a slot, use a different source IP, or `-whitelist` the client on
the serving node), or a different serving peer. The real prerequisite is at
least one completed node handshake with an advertised height.

## Harness behavior

1. **Peer precheck** (`peer_precheck` / `classify_peer_precheck`). The probe
   connects without sending a byte and classifies `unreachable` / `held_open` /
   `protocol_idle_close` / `accept_close`. `protocol_idle_close` means the peer
   waited through the passive five-second window for a version message the
   probe never sends; it is usable-but-unproven. `accept_close` prints a loud
   warning naming the per-IP cap and the `ss` command to confirm it. Recorded as
   `peer_precheck` in `proof.json`; **advisory**: it never converts a verdict,
   and an accept-closing peer is never laundered into a SKIP. The pure
   classifier is covered by `--selftest`.
2. **Network capture in the failure bundle.** Non-pass runs write
   `net-connman.json`, `net-peer_lifecycle.json`, `net-network.json`, and
   `banlist.dat` when one exists (`banlist_present` in `proof.json`), so "did we
   ever handshake, and did we ban our only peer" is answerable from the
   artifact alone.
3. **Multiple serving peers.** Repeat `--peer=HOST:PORT` or provide a
   comma-separated value. The harness deduplicates the ordered set, passes one
   `-connect` per endpoint, and records the aggregate `peer_precheck` and every
   endpoint/classification pair in `peer_prechecks`. The legacy `peer` field
   remains the first stated endpoint.

## Serving-side controls

The refusal is enforced by the **serving** node, so a run against a peer already
at its cap needs that peer to run this code or raise the cap.

1. **The per-IP inbound cap is configurable.** `accept_connection()`
   (`core/modules/net/src/net.c`) reads `peer_scoring_max_inbound_per_ip()`:
   `ZCL_PEER_MAX_INBOUND_PER_IP`, default 3, clamped to `[1, 4096]`. An operator
   serving a host that legitimately runs several nodes (or any NAT) can raise it
   without a patch. The refusal log line names the cap, the env var, and the
   fact that the dialling node can only observe a zero-byte remote-close.
2. **A ban cannot strand a node that has exactly one peer.** Offence weights
   and the ban threshold are unchanged (`INVALID_BLOCK` / `PROTOCOL_VIOLATION`
   score 100 and cross the threshold on the first hit). `peer_misbehaving()`
   bounds the ban's **duration** only when the ban would leave the manager
   with zero live peers: `ZCL_PEER_LAST_PEER_BAN_SECS` (default 600, clamped to
   `[60, 86400]`) replaces `ZCL_PEER_BAN_HOURS` for that one case. With a
   second peer connected behaviour is unchanged. The branch raises the typed
   blocker `net.last_peer_ban`, cleared at
   `peer_lifecycle_note_handshake_complete()`, the single choke point every
   completed handshake passes through.

`is_trusted_peer()` exempts only localhost and whitelisted peers; addnode peers
are not exempt (operator intent to dial an address is not evidence the address
serves valid consensus data). The stranding risk is handled by the bounded ban
above.
