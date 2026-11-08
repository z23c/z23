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
