<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Plugin peer-to-peer distribution — 2026-10-20

## Claim

A signed plugin generation moves from one z23 process to another through the
existing package store and swarm, and the receiver installs it as a new
generation only when every check below holds. No store, cache or transport was
added: `plugin publish` files the generation as an ordinary four-file
content.v2 package root with a signed release envelope, the hosting node's
swarm serves it, and `plugin fetch` checks the delivered root out of the
receiver's own package store and hands it to `plugin_store_install`.

Neither leaf switches `current`, and neither runs the plugin. Both are
`REMOTE_CLASS_NEVER` and owner-authority, the same class as `plugin install`.

## Leaves

```sh
z23 plugin publish NAME --datadir=DD [GEN] [--dir=PACKED_DIR] --license-file=F [--spdx=MIT] \
    --release-key=K --sequence=N
z23 plugin fetch --datadir=DD --root=R --name=NAME [--allow-downgrade]
```

- `publish` takes the installed `current` generation (or `GEN`) or a packed
  `--dir`, refuses an image that does not match its signed manifest, and
  stores LICENSE, NAME, NAME.plugin.json and NAME.plugin.sig as one package
  root in the datadir's package store, pinned, with a release envelope signed
  by the 32-byte package key (secp256k1, the `z23-package-sign` key form). A
  hosting node announces only a signed, permissively licensed root, so the
  license text must be the real text of `--spdx`. One key names one root per
  `--sequence`. The reply carries `root` and `manifest_sha3` (the generation
  id, the SHA3-512 of the signed manifest).
- `fetch` works on the receiver's datadir. A root not yet there records the
  ordinary resumable download record and refuses `PLUGIN_DIST_NOT_FETCHED`
  (retryable); the hosting node loads it, the swarm delivers, and the repeat
  `fetch` verifies and installs.

## Refusals

Each has its own code and a next action. Each has a red/green witness in the
registered `plugin_dist` group (`tests/harness/src/test_plugin_dist.c`): the
check was disabled in `plugin_dist.c`, the test failed on exactly that
refusal, and the check was restored.

| Code | Check | Red (check disabled) |
| --- | --- | --- |
| `PLUGIN_DIST_ROOT_MISMATCH` | delivered root and root re-derived from the stored manifest equal the requested root | `0 != 7` |
| `PLUGIN_DIST_TRUNCATED` | the store holds every chunk before any file is materialised | `14 != 8` |
| `PLUGIN_DIST_PUBLISHER_UNPINNED` | signing key already in the receiver's `publisher_keys` | `13 != 10` |
| `PLUGIN_DIST_IMAGE_HASH` | image SHA3-512 equals the signed manifest `sha3_512` | `13 != 11` |
| `PLUGIN_DIST_DOWNGRADE` | version not lower than (and comparable with) installed current, unless `--allow-downgrade` | `0 != 12` |

Also refused by name: `PLUGIN_DIST_SHAPE` (package is not exactly the four
plugin files for NAME) and `PLUGIN_DIST_NOT_FETCHED`.

Versions compare as dotted decimals (one to four components). A prerelease or
build tail does not compare and is treated as a possible downgrade, so it
needs the owner flag over an installed current generation.

The witness test also shows: install is `new generation`, `current` stays
absent after a fetch, a repeat is `already_present`, the checkout scratch is
removed on every path, and a partial transfer (manifest plus one chunk)
refuses `PLUGIN_DIST_TRUNCATED` and then completes after the swarm resumes.

## Cross-process run

Two z23 processes on one host, isolated datadirs and isolated `HOME`
directories under `build/scratch/p2p-e2e/`, regtest, loopback only, fixture
keys, the fixture plugin `tests/harness/fixtures/plugin_call_upper.c`
(interface 2, static). The driver is `build/scratch/e2e.sh`; its commands, in
order (`Z=build/bin/z23-dev`, `N=build/bin/zclassic23-dev`):

```sh
HOME=$H_PUB $Z plugin keygen publisher.key
HOME=$H_PUB $Z plugin pack build/fixtures/plugin_call_upper --name=upper --version=1.0.0 --key=publisher.key --interface=2 --dir=dist
head -c 32 /dev/urandom > package.key; chmod 600 package.key
HOME=$H_PUB $Z -datadir=$DD_PUB -regtest plugin publish upper --dir=dist --license-file=LICENSE --spdx=Apache-2.0 --release-key=package.key --sequence=1
HOME=$H_RCV $Z plugin publisher <public_key>
HOME=$H_RCV $Z -datadir=$DD_RCV -regtest plugin fetch --root=$ROOT --name=upper     # NOT_FETCHED, records the download
$N -datadir=$DD_PUB -regtest -packagehost=1 -port=P1 ... -connect=127.0.0.1:1 &     # publisher serves
$N -datadir=$DD_RCV -regtest -packagehost=1 -port=P2 ... -connect=127.0.0.1:P1 &    # receiver dials it
$N -datadir=$DD_RCV -rpcport=R2 dumpstate zcode_store $ROOT                         # poll until complete
kill both nodes
HOME=$H_STRANGER $Z -datadir=$DD_RCV -regtest plugin fetch --root=$ROOT --name=upper   # unpinned: refused
HOME=$H_RCV $Z -datadir=$DD_RCV -regtest plugin fetch --root=$ROOT --name=upper        # installs
HOME=$H_RCV $Z plugin status upper
HOME=$H_RCV $Z plugin fetch --datadir=$DD_RCV ... again                                                # already_present
HOME=$H_RCV $Z plugin switch upper $GEN ; HOME=$H_RCV $Z plugin call upper --stdin=abc
```

Observed on R1 (first run; the second run repeated every outcome):

| Step | Result | Time |
| --- | --- | --- |
| pack | passed | 29 ms |
| publish (852301 bytes, 4 files) | passed, root and `manifest_sha3` returned | 127 ms |
| receiver fetch before any bytes | `PLUGIN_DIST_NOT_FETCHED`, download recorded | 26 ms |
| both nodes up to receiver store `complete:true` (4 of 4 chunks) | swarm transfer over loopback | 4.1 s and 3.1 s in two runs (poll granularity 1 s) |
| unpinned `fetch` of the delivered root | `PLUGIN_DIST_PUBLISHER_UNPINNED`, nothing stored | 48 ms |
| pinned `fetch` | passed, `already_present:false`, `switched:false` | 96 ms |
| `plugin status` | `current` empty, one generation | under 1 ms |
| repeat `fetch` | passed (already present) | 63 ms |
| `switch` then `call upper --stdin=abc` | `stdout` is `ABC`, exit 0, generation equals the published `manifest_sha3` | 13 ms, 8 ms |

## Limits (two-phase `plugin fetch`; superseded by the resident fetch below)

- The nodes are stopped before `plugin fetch`. A one-shot command must not
  open a package store a resident node holds, and the daemon has no RPC that
  starts a swarm fetch of a named root from a named peer. The peer is the
  hosting node's own connection, so `fetch` has no `--peer`. This is a
  two-phase flow, not a single command that dials a peer.
- Same host, regtest, loopback, unauthenticated test transport
  (`-noisetransport`). Not a cross-host, NAT, Tor or fleet-route proof.
- ZRS1: a pair pin with require-pq is not composed. A plugin signature is
  Ed25519-only by schema, so require-pq would refuse every plugin; this needs a
  hybrid signature in the plugin manifest first. Documented as next.
- Plugin signing key and package-release key are independent. The release key
  only authorises serving; trust to install is the receiver's own
  `publisher_keys`.
- The image is never executed by `publish` or `fetch`. The final `switch` and
  `call` are separate owner commands.

## Next

A real cross-host fetch needs a resident RPC that starts a bounded swarm fetch
of one root from named authenticated peers (the receiver's node, not a one-shot
process) and a resident checkout and install so the node need not stop; the
r1 to r2 tunnel carrying the NODE_ZCL23 peer link; `-packagehost=1` on both
ends; the publisher's release served from its own store; and the receiver's
`publisher_keys` pinned out of band.

## Resident fetch: no node stop (lane S1b)

The two-phase limit above is gone. A running node now fetches, verifies and
installs from its own swarm peers, and is never stopped.

```sh
z23 plugin fetch_remote --root=R --name=NAME [--peer_id=N] [--max-bytes=B] [--timeout=S] [--wait=S] [--allow-downgrade]
z23 plugin fetch_remote --job=ID [--wait=S]          # ask again
```

- `plugin_fetch_begin` (resident RPC) starts a bounded provider-directed swarm
  fetch (`vcs_swarm_engine_fetch_from_bounded`, so the engine enforces the byte
  cap before any chunk is asked for) from every connected swarm peer, or the one
  named `peer_id`, and returns a job id at once. `plugin_fetch_poll` reports the
  job. The swarm timer and every poll advance it: when the root is complete the
  resident runs `plugin_dist_receive`, the same function `plugin fetch` calls,
  on its own package store, as a NEW generation. Nothing is switched or run.
- Every `PLUGIN_DIST_*` refusal arrives as the job's `code`, `next_action` and
  `detail`, and as the leaf's error. Swarm-side failures are
  `PLUGIN_FETCH_SWARM_FAILED`, `PLUGIN_FETCH_SWARM_LOST`, `PLUGIN_FETCH_TIMEOUT`;
  start refusals are `PLUGIN_FETCH_ARGUMENT`, `_BUSY`, `_NO_SWARM`, `_NO_PEERS`,
  `_UNKNOWN_PEER`, `_SWARM_REFUSED`. `PLUGIN_DIST_ROOT_MISMATCH` and
  `_TRUNCATED` cannot be reached through a job (the swarm verifies root and
  chunks, and the job installs only a complete root); they stay covered by the
  `plugin_dist` group. `PLUGIN_DIST_TOO_LARGE` (image over 48 MiB) is new.
- Bounds: at most 2 running jobs (`PLUGIN_FETCH_BUSY` beyond), a request
  re-using a running root gets that job, default 64 MiB cap (max 256 MiB),
  default 600 s deadline (max 3600 s; at the deadline the download is
  cancelled), a 16-row table that drops only the oldest finished job, ids never
  reused.
- Owner-only and local: `plugin.fetch_remote` is `REMOTE_CLASS_NEVER`; the RPC is
  on the local cookie-authenticated listener, and takes neither datadir nor
  plugin store from input (both are the node's own). The install policy is the
  node owner's `publisher_keys` under the node's HOME, not the caller's.
- Registered group `plugin_fetch_job` (real swarm engines, shared fixture with
  `plugin_dist`): journey, UNPINNED, IMAGE_HASH, DOWNGRADE and TOO_LARGE through
  the job, begin refusals, byte cap, deadline, active limit, table bound.

### Same-host run, receiver node up throughout

Driver `build/scratch/e2e_rpc.sh` (isolated HOMEs and datadirs under
`build/scratch/rpc-e2e/`, regtest, loopback, `-noisetransport`, fixture keys,
`plugin_call_upper`). Both roots are published with the publisher node down,
then both nodes start; no one-shot `plugin fetch` is run.

| Step | Result | Time |
| --- | --- | --- |
| node start to receiver seeing 1 swarm peer | `peer_count` 1 | 3.1 s |
| `fetch_remote --root --name` (no wait) | job 1, `fetching` | 37 ms |
| `fetch_remote --job=1 --wait=60` | `installed`, 4 of 4 chunks, 852301 bytes | 1.53 s |
| `plugin status upper` | `current` empty | under 1 ms |
| repeat `fetch_remote` (root local) | job 2 `installed`, already present | 0.27 s |
| `fetch_remote` of a root signed by an unpinned key | `PLUGIN_DIST_PUBLISHER_UNPINNED`, nothing stored | 0.27 s |
| `fetch_remote --max-bytes=100` on a root already local | `PLUGIN_FETCH_SWARM_REFUSED: byte-limit` | 1.8 s |
| owner `plugin switch`, then `plugin call upper --stdin=abc` | `stdout` `ABC`, exit 0, generation equals the fetched one | 16 ms, 8 ms |

The receiver node was alive at the switch and at the end. The byte-cap row
started from a root already in the store, so the engine refused it at begin;
the in-flight cap failure (`PLUGIN_FETCH_SWARM_FAILED`) is witnessed by the
`plugin_fetch_job` group.

Limits that remain: one named peer per CLI call (the RPC takes a list); peers
are the handles connected when the job starts; same host, unauthenticated test
transport, not a cross-host or Tor proof.
