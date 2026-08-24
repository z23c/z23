# READY=1 and descriptor publication

Investigation for the cycle-3 ordered-loop halt. Not a threshold change.

## Cycle 3 (probe, not systemd)

`2026-08-23T19:49:55Z` datadir `/tmp/zcl23-pairwatch-e1O8E8`
onion `qi4klh77naxt6cugxm2cislvgcpbyzmffj2hr2zmbqn22qbjlk4pjxad.onion`

```
rpc_a_ready_s=25
onion_ready_s=31 onion=qi4klh77naxt6cugxm2cislvgcpbyzmffj2hr2zmbqn22qbjlk4pjxad.onion
spawned B pid=2616261 addnode=qi4klh77…:39350
rpc_b_ready_s=56
PAIR_PROBE=DESCRIPTOR_NOT_UPLOADED dial_attempted=true rendezvous_seen=true descriptor_uploaded=false
```

Hostname existed. The client launched. Descriptor upload was never observed.
A real stranger who dials on hostname-file presence burns the same way.

## Does READY=1 gate on confirmed upload?

Yes. The systemd Type=notify path is not the probe path.

- `tor_integration_is_ready()` is `g_tor_ready`
  (`lib/net/src/tor_integration.c`).
- `g_tor_ready` flips only after `read_onion_address()` returns true.
- `read_onion_address()` returns true only when the address is known AND
  `tor_log_has_descriptor_publication()` sees a success-only HSDir line
  (`Uploaded hidden service descriptor (status 200`, `finished with status 200`,
  `HS_DESC UPLOADED`, or `DESCRIPTOR PUBLICATION`). Hostname-only logs are
  rejected by `lib/test/src/test_tor.c`.
- `boot_sd_watchdog_maybe_notify_ready()` returns without `sd_notify_ready()`
  while Tor is enabled and `!tor_integration_is_ready()`. The pet thread
  retries that check.

`g_tor_dial_ready` becomes true at hostname so outbound circuits can
pre-warm. It does not send `READY=1` and does not weaken
`tor_integration_is_ready()`. Isolated pair-probe spawns have no
`NOTIFY_SOCKET`, so they never send `READY=1`; their old launch gate was
the hostname file. That is the probe defect this branch fixes. It is not a
READY=1 contract miss for node2's bisect.

Isolated pair-probe binds only 39250+ quads. Published `P2P_PORT` values in
`deploy/devfleet/node*.txt` (node2=39360, node3=39150, node4=39040, node1=8055)
are never bind candidates. Dialing node2's onion is a client path and does
not bind 39360 locally.
