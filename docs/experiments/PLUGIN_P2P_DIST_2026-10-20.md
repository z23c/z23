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
z23 plugin publish NAME [GEN] [--dir=PACKED_DIR] --license-file=F [--spdx=MIT] \
    --release-key=K --sequence=N
z23 plugin fetch --root=R --name=NAME [--allow-downgrade]
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
HOME=$H_RCV $Z plugin fetch ... again                                                 # already_present
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

## Limits

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
