<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# DISCOVER replay checkpoint evidence

The checkpoint stores the first unprocessed DISCOVER height only after the
corresponding event-log prefix has been flushed and validated. A restart reruns
transparent discovery and verifies the saved wallet binding, generation,
endpoint, scan identity, key digest and event-log prefix before reusing it.
Witness and spend phases retain their existing behavior.

The startup coordinator saves after the first completed DISCOVER chunk and
then at most once per 30 seconds after another completed chunk. The time to
replay lost work also includes the duration of the current chunk.

## Focused host evidence

On 2026-11-07, the registered `boot_phase` and
`node_db_catchup_service` groups passed together (2/2, zero skips). The
boot fixture exercised a private writer, same-file checks, SQLite contention,
a retained connection busy handler, before- and after-commit process exit,
prefix corruption, generation change, deadline and Stop. The coordinator test
also exercised partial BUSY continuation. These results are from an isolated
fixture; they do not establish real-device restart behavior.

A later `boot_phase` run passed (1/1, zero skips) with a synthetic encrypted
Sapling seed and spending key in WKS1 envelopes. It authenticated over the
startup socket, waited for a one-second wallet lock timer, verified that a
locked wallet refused checkpoint writes, authenticated again and resumed its
persisted cursor with matching scan identity and viewing-key digest. A Stop
request refused the next write while readiness remained PENDING. This fixture
constructs its replay cursor; it does not perform a complete chain replay.

The same run measured actual checkpoint preparation and save on public
synthetic event logs. Host: AMD Ryzen 9 7950X3D, GCC 14.2.0, 2026-11-07T22:18:06Z. Three samples, in microseconds:

| Prefix bytes | Prepare | Save |
| ---: | --- | --- |
| 16,545 | 100, 91, 90 | 2,618, 1,778, 2,360 |
| 8,470,689 | 43,767, 44,928, 40,937 | 1,943, 1,987, 2,098 |

Preparation includes the prefix flush and digest; save includes the private
SQLite transaction. These are small host samples, not an Android benchmark or
an end-to-end wallet synchronization measurement. The fixture does not bound
an in-progress filesystem sync or a single large record read.

Reproduce the focused checks from the candidate checkout with the host's
admitted build wrapper:

```sh
DEVBUILD_CLASS=normal devbuild --wait make -j4 t-fast-exact ONLY=boot_phase,node_db_catchup_service
```

Real Android process interruption, private reauthentication and full replay
resume remain to be verified on an isolated device fixture.

## Android checkpoint startup stage

On 2026-11-07, an isolated Pixel fixture with a synthetic encrypted wallet
finished transparent replay and entered DISCOVER, but startup exited before
saving a checkpoint. The replay coordinator was at the chain-tip-resolved
stage while the checkpoint writer required the earlier block-index-loaded
stage. No checkpoint row was written.

The checkpoint writer now checks the replay-specific stage and the same
boot-owned database, wallet and chain identities. The installer retains its
existing earlier-stage check. The focused `boot_phase` group passed on the
reviewed change (1/1, zero skips), including adjacent-stage refusal and a
saved-cursor check. A complete Android interruption and resume test remains
necessary.

## Transparent replay for a shielded-only wallet

An isolated Android profile on 2026-11-07 found transparent replay accounted
for 71.15% inclusive CPU-cycle profile weight across 890 samples over ten seconds. The wallet contained
20 synthetic Sapling keys and no loaded transparent identities. This sample
is not an end-to-end speed measurement.

A coordinator may advance to DISCOVER without reading transparent bodies when
checked database and in-memory state contain no transparent identities or
effects. It repeats that proof in the final publication transaction. Sapling
seed, keys and notes remain eligible. Uncertain or nonempty state uses the
ordinary transparent scan.

Focused host tests passed `boot_phase` and `node_db_catchup_service` (2/2,
zero skips). They exercised encrypted startup and seed adoption, zero
transparent reads, a discovered Sapling note reaching READY, a key minted
before publication retaining PENDING, and a database-only watch identity
forcing the ordinary scan. A test retaining the former master-key restriction
failed the seeded zero-read assertion. Android timing and restart with this
optimization remain unmeasured.

## Stop during pending replay

An isolated Pixel resumed DISCOVER from its saved height and advanced. A
SIGTERM then stopped the process promptly, but startup reported a fatal error
because the replay loop returned the same result for a requested stop and a
failure. The saved checkpoint remained available and the synthetic wallet fingerprint was unchanged.

The replay loop now reports a stop only at checked boundaries and preserves
failure results. Pending-wallet shutdown uses the existing checked durability
and no-wallet-flush cleanup. Focused host tests passed the registered
`boot_phase`, `node_db_catchup_service`, and
`consensus_state_snapshot_install` groups (3/3, zero skips). They cover the
replay boundary and pending cleanup; they do not establish cancellation during
archive opening or checkpoint I/O, or a complete Android Stop flow.

A follow-up gives checkpoint preparation and saving distinct cancellation
results. Cancellation remains distinct from descriptor, database and rollback
failures, including when a shutdown request is concurrent. The focused host
`boot_phase` and `node_db_catchup_service` groups passed (2/2, zero skips),
covering cancellation and retained checkpoint state. Complete Android Stop
and archive-opening cancellation remain to be verified.

Sapling replay also recognizes Stop after a block has been committed,
delivered and revalidated. The coordinator retains PENDING and does not
advance a completed phase on this result. A stale binding or other failure
continues to take precedence. This boundary does not bound the time spent
within a block, archive opening, or filesystem operations. Android Stop latency
for this change remains unmeasured.

A subsequent isolated Pixel run exposed a cleanup-stage mismatch: replay
reported Stop, but the committed-wallet classifier rejected the later startup
stage. The STOP-only cleanup now checks the same wallet, database, binding and
generation authority at that stage. The normal installer check is unchanged.
The checked scan-state reader also accepts the existing unscanned height of
-1; malformed values and values below -1 remain invalid.

The focused host groups passed (4/4, zero skips). A real-artifact startup
fixture passed (1/1, zero skips) after saving a checkpoint, stopping and
reopening the pending wallet. On the isolated Pixel, the node resumed at the
saved height and exited successfully after Stop in approximately 19.3 seconds,
including durability cleanup; the saved checkpoint and synthetic wallet
fingerprint remained unchanged. Automatic wallet-history acquisition is not implemented on this path; complete
migration remains unverified.
