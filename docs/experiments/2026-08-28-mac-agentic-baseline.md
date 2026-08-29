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

## Open macOS agentic / P2P gaps

| Area | Current state | Next step |
|---|---|---|
| Dev watcher | Polling-only (`tools/dev/watch-dev-lane.sh` falls back to 500 ms manifest poll because `lib/platform/src/directory_watcher.c` returns `ERROR` on Darwin) | Either accept polling latency (~1 s detect + 500 ms debounce) or implement a kqueue/FSEvents backend |
| Resident hot swap | `ops mesh identity` reports `status=refused`, `refusal_stage=macos`; `lib/hotswap/src/hotswap_activate.c` has `__APPLE__` dlopen paths but activation is disabled | Decide whether to validate Mach-O imports / immutable-image staging, or keep the docs/table as "Unavailable" |
| `make test-two-node-peer-tip` | Blocked by `ss(8)` dependency | Port port-probe preflight to macOS |
| Embedded Tor | Build path no longer pinned to stub, but no Mac has been observed completing `make tor-full` | Run `make tor-full` and report whether it completes |

## Mesh identity detail

Against the isolated regtest node, `ops mesh identity` returned:

- `platform.os=macos`, `architecture=aarch64`, `environment_observed=true`
- `build.binary_identity_available=true`, `installed_path_matches_running_image=true`
- `hotswap.status=refused`, `refusal_stage=macos`, reason:
  "native macOS hot-swap is disabled pending validated Mach-O imports and
  immutable executable-image staging"
- Active blockers for pairing: `V2_TRANSPORT_DISABLED`,
  `NOISE_IDENTITY_UNAVAILABLE`, `AUTHENTICATED_DHT_INACTIVE`,
  `REMOTE_STATUS_PROTOCOL_UNAVAILABLE`.

The capsule works; actual private-mesh pairing is gated on enabling v2 transport
and an authenticated DHT identity, which is the same cross-platform prerequisite
set the command reports on Linux.

## Mainnet sync observation

Started a durable LaunchAgent against mainnet on 2026-08-28:

- Service command: `z23 -datadir=/Users/rentamac/.zclassic-c23
  -operator-lane=canonical -listen -txindex -allow-clearnet-snapshot-fetch
  -addnode=205.209.104.118:8033`
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
