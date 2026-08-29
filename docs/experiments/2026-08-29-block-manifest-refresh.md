<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Connected-peer block manifest refresh — 2026-08-29

## Intention

Let a node that publishes its first or a newer block-piece manifest after the
version handshake offer that generation to already-connected Z23 peers. A peer
must not need to reconnect, and an unchanged generation must not add traffic.

## Evidence

Command:

```bash
make -j2 t-fast ONLY=block_swarm_loopback
```

Result: PASS, 1 group run, 0 failures, 0 skips. The real loopback wire test
observed one initial manifest, no duplicate for the same cache generation, and
one new manifest after the serving cache generation advanced. Existing
throughput, disconnect requeue, integrity abandonment, header anchoring, and
sovereignty refusal cases remained green.

## Limit

This improves block-body swarm availability after a source reaches tip. It does
not complete automatic consensus-bundle discovery or make the contained legacy
UTXO snapshot path deployable.
