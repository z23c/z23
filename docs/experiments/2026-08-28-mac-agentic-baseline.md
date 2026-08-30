<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Mac agentic C23 baseline — 2026-08-28

Measured baseline for the first arm64 macOS development host. This is an
observation file, not a product claim; every numbered item should be re-derived
on the current tree rather than trusted.

## Host

- Machine: Mac mini (arm64, Mac16,10 equivalent)
- OS: macOS 26.0.1 (Darwin 25.0.0)
- Compiler: Apple Clang 17.0.0 (clang-1700.3.19.1)
- Shell: `/bin/bash` is 3.2; Homebrew bash is available via `#!/usr/bin/env bash`

## What passed

| Claim | Command / evidence | Result |
|---|---|---|
| Native arm64 node builds cleanly | `make -j"$(getconf _NPROCESSORS_ONLN)" z23` | PASS; Mach-O audit allows only Apple system libs/frameworks |
| Lint-fast inner gate | `make lint-fast` | PASS 21/21 gates |
| Lint gates (full focused set) | `make -j t-fast ONLY=make_lint_gates` | PASS 13/13 groups |
| BLAKE2b NEON 4-way correctness | `make -j t-fast ONLY=blake2b_batch_parity` | PASS; auto-selected tier = `NEON (4-way)` |
| BLAKE2b NEON 4-way speedup | `build/bin/simd_bench` | 1.39x faster than scalar on Equihash BLAKE2b batch |
| SHA-256 ARMv8 hardware tier | `build/bin/simd_bench` | 4.58x faster than generic; detected `sha256=ARMv8 SHA (hardware)` |
| Quality-job guard/retention selftest | `bash tools/scripts/test_quality_job_guard.sh` | PASS after bash 3.2 / BSD tool fixes |
| Regtest node boots and shuts down cleanly | Isolated `/tmp/zcl-mesh-id` node | PASS; RPC ready in ~2 s, graceful shutdown in ~5 s |
| `ops mesh identity` capsule on macOS | `z23 ops mesh identity` against running regtest node | PASS; reports `platform.os=macos`, `architecture=aarch64`, live observation fields populated |
| Native kqueue directory watcher | `make -j t-fast ONLY=directory_watcher` | PASS; `lib/platform/src/directory_watcher.c` uses kqueue and recursively watches real subdirectories |
| Embedded full Tor | `make tor-full` | PASS; builds `vendor/tor/libtor.a` from vendored OpenSSL/libevent/zlib, ~110 s, no source changes |

## What required fixes

1. **Quality-job scripts were Linux/GNU-only.**
   - `tools/scripts/test_quality_job_guard.sh` used `touch -d` (GNU-only).
   - `tools/scripts/quality_log_retention.sh` used `stat -c %s` (GNU-only).
   - Both scripts used `"${array[@]}"` expansions that bash 3.2 treats as
     unbound variables when the array is empty under `set -u`.
   - Fixed in the same slice as the launchd service support.

2. **`make test-two-node-peer-tip` does not run on macOS.**
   - The harness requires `ss(8)` from iproute2 for preflight port checks.
   - macOS has no `ss`; the script fails before spawning any node.
   - This blocks the MVP C7 full claim on macOS until the harness is ported to
     use `lsof`, `netstat`, or an equivalent macOS-native probe.

## v2 transport verification

The v2 Noise transport is implemented and works natively on arm64 macOS. It is
disabled by default and armed with the `-v2transport` flag.

Against an isolated regtest node started with `-v2transport`:

- `transport.v2_enabled=true`
- `transport.identity_loaded=true`
- `transport.local_noise_fingerprint_sha3` populated
- `authenticated_dht.disabled_reason` moved from `V2_TRANSPORT_DISABLED` to
  `IDENTITY_MATERIAL_UNAVAILABLE`
- Active blockers dropped from four to one: `AUTHENTICATED_DHT_INACTIVE`

The remaining blocker is expected on a fresh regtest node: the authenticated DHT
requires an on-chain-active operator identity provisioned through
`z23 zcode network delegate --input='{"seed_file":"/path/master.hex"}'`.
That provisioning needs a ZID identity that is ACTIVE on-chain; a regtest node at
height 0 has none.

## Open macOS agentic / P2P gaps

| Area | Current state | Next step |
|---|---|---|
| Dev watcher | Native kqueue backend landed in `lib/platform/src/directory_watcher.c`; `tools/dev/devloop_watch.c` still hard-codes inotify | Move `devloop_watch.c` onto the platform directory watcher so the dev loop gets sub-50 ms detection on macOS |
| Resident hot swap | Mach-O probe/validation landed, but `zcl_hotswap_hotfork_visit_so()` still fails closed on Darwin because descriptor-bound A/B execution is unavailable | Implement immutable executable-image staging with ad-hoc signed bundle loading, or keep activation "Unavailable" |
| `make test-two-node-peer-tip` | PASS on arm64 macOS after replacing the absent util-linux `setsid(1)` command with the in-tree C23 `process-group-exec` launcher | Keep the gate green as the sync path evolves |
| Embedded Tor | PASS on arm64 macOS; `vendor/tor/libtor.a` builds from vendored deps | Update capability docs and remove from open-gap list |

## Mesh identity detail

Against the isolated regtest node **without `-v2transport`**, `ops mesh identity`
returned:

- `platform.os=macos`, `architecture=aarch64`, `environment_observed=true`
- `build.binary_identity_available=true`, `installed_path_matches_running_image=true`
- `hotswap.status=refused`, `refusal_stage=macos`, reason:
  "native macOS hot-swap is disabled pending validated Mach-O imports and
  immutable executable-image staging"
- Active blockers for pairing: `V2_TRANSPORT_DISABLED`,
  `NOISE_IDENTITY_UNAVAILABLE`, `AUTHENTICATED_DHT_INACTIVE`.

With `-v2transport` the first two blockers drop; the remaining
`AUTHENTICATED_DHT_INACTIVE` blocker is the cross-platform requirement for a
provisioned on-chain DHT identity, not a macOS defect.

## Mainnet sync observation

Started a durable LaunchAgent against mainnet on 2026-08-28:

- Service command: `z23 -datadir=$HOME/.zclassic-c23
  -operator-lane=canonical -listen -txindex -allow-clearnet-snapshot-fetch
  -addnode=HOST:8033`
- Proven tip (`hstar`) reached **~10,000** before the snapshot path engaged.
- Network tip: **~3,232,000** blocks.
- With `-addnode=HOST:8033`, the node discovered a file-service snapshot at
  height **3,056,758** on the peer, downloaded a 514 MB consensus-state bundle
  and a 531 MB header seed, both content-verified.
- The bundle install into the canonical datadir requires
  `ZCL_DEPLOY_ALLOW_CANONICAL=1` (set via `ZCL_SERVICE_ENV_VARS`). Without it,
  the install is deferred.
- Once the validated header chain reaches the checkpoint height (3,056,758),
  the bundle installs and `hstar` jumps to that height; the remaining sync is
  only the ~176k-block tail to the network tip.
- Once this node finishes syncing, its own file service on port 18034 will
  advertise a manifest and can serve other z23 nodes.

## Slice landed

Commit `dd432ea6a` (macOS: launchd service support and quality-job portability)
adds:

- `make service-install` / `make dev-service-install` / `make service-uninstall` /
  `make service-status` for native macOS LaunchAgent management.
- `config/launchd/org.z23.zclassic.plist.template`.
- macOS service instructions in `docs/GETTING_STARTED.md`.
- macOS portability fixes for the quality-job guard/retention scripts.
- Impact-rule mapping for `config/launchd/*`.

Subsequent fixes:

- `394921b08` — fix LaunchAgent flag syntax (`-datadir=DIR`, `-operator-lane=NAME`).
- `f6afd6ed5` — support `ZCL_SERVICE_EXTRA_FLAGS` and document fast-sync snapshot option.
- `47cc9e78a` — add `ZCL_SERVICE_FILESERVICE_PEER` so Mac nodes can bootstrap from another z23 node's file service.
- `ad42404bc` — treat `-addnode=HOST:8033` peers as file-service snapshot seeds without forcing connect-only mode, so z23 nodes help each other bootstrap while keeping normal peer discovery.
- `9eb439fe4` — support `ZCL_SERVICE_ENV_VARS` in the LaunchAgent; required for `ZCL_DEPLOY_ALLOW_CANONICAL=1` so a fetched snapshot can install into the canonical datadir.
- `2348ed9eb` — add `ZCL_SERVICE_ADDNODE_PEERS` for multiple snapshot-seed peers and keep `tools/dev/grok_report.c` out of the node binary. The proposed lag-condition suppression was not retained because it coupled condition evaluation to controller-owned filesystem discovery without acceptance evidence.
- *(this slice)* — protect `-addnode` peers from being torn down mid-handshake by `peer_floor_violated`, so operator-configured snapshot seeds have time to complete their handshake.

## 2026-08-29 — body-fetch stall and macOS legacy-datadir fix

After the addnode-protection fix, the node handshaked ZCL23 peers and headers
climbed quickly (`header_admit` cursor ~638k within minutes, network tip
~3,232,890). The bottleneck moved to body fetch:

- `body_fetch` cursor stalled around **h=14,309** while `validate_headers`
  advanced to ~650k.
- `body_coverage` showed a single held range `0..14309` and a huge hole
  `14310..226732`.
- `body_fetch` idle reason was `body.missing`; the P2P download queue was
  requesting bodies but only advancing ~5 blocks/sec.

Root cause on this Mac: ZclWallet (`zclassicd`) keeps its block files in
`$HOME/Library/Application Support/Zclassic/blocks`, but the z23 auto-import
path only looked at `$HOME/.zclassic/blocks`. With no local legacy block files, the
node was trying to pull ~3.1M bodies over a small P2P set.

Fix: make `boot_legacy_default_blocks_dir()` platform-aware, checking (in
order) `%APPDATA%\Zclassic\blocks`, `$HOME/Library/Application Support/Zclassic/blocks`,
and `$HOME/.zclassic/blocks`. `config/src/boot.c` now uses the first existing
candidate for both the initial `--importblockindex` copy pass and the
warm-boot link pass. This is a read-only hardlink/copy; it does not touch the
legacy node's LevelDB or wallet.

Verification plan:

1. Build the patched binary (`make -j"$(getconf _NPROCESSORS_ONLN)" z23`).
2. `make lint-fast` and focused boot-legacy tests must pass.
3. Restart the durable LaunchAgent; boot log should report linked block files
   from `$HOME/Library/Application Support/Zclassic/blocks`.
4. `z23 dumpstate body_coverage` should show the held ranges expanding past
   the old 14k frontier, and `reducer_drive` should advance faster than the
   P2P-only ~5 bps.

Port conflict note: ZclWallet already binds mainnet P2P port 8033 on this
host, so z23's `-listen` bind fails. For now outbound P2P works and the
legacy block-file link gives the fast path. To let this z23 node accept
inbound connections, ZclWallet must be moved to a non-default port (e.g.
8034) or stopped; that is an operator-host configuration choice, not a code
change.

## 2026-08-29 — kqueue watcher, tor-full, test pointer normalization, v2 naming cleanup

Second macOS slice:

- `lib/platform/src/directory_watcher.c` got a native kqueue backend that
  recursively watches real subdirectories, drains events, and passes the
  focused `directory_watcher` test. The watcher is no longer fail-closed on
  Darwin.
- `make tor-full` completed on the first arm64 Mac host in ~110 s, producing
  `vendor/tor/libtor.a` from the vendored OpenSSL/libevent/zlib trees.
- `lib/test/include/test/test_core.h` normalizes the pointer fallback printer
  so NULL renders as `(nil)` on Darwin as well as glibc; this fixes the
  `test_test_group_selector` pointer-message assertion on macOS.
- Stale "v2 transport" strings were canonicalized to "Noise transport" and the
  LaunchAgent template now documents the real `-noisetransport` flag.

Remaining before macOS agentic parity is complete:

1. Move `tools/dev/devloop_watch.c` off raw inotify and onto the platform
   `directory_watcher_*` abstraction.
2. Decide whether to land immutable Mach-O executable-image staging for dev
   hot-swap activation, or keep the capability table honest about "Unavailable".

The previously open `make test-two-node-peer-tip` item now passes end-to-end
on macOS: B reached A at height 10, survived a kill-9/restart cycle on the
same datadir, and re-reached peer tip 15.
