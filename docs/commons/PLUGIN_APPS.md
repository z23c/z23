<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Plan: every z23 app becomes a plugin

Owner directive (2026-10-20): every z23 app and feature becomes a plugin, and z23 is a platform on which many kinds of things can be built. This page tracks the remaining plugin work alongside capabilities already shipped. The mechanics are in [`dev/PLUGINS.md`](../dev/PLUGINS.md).

## 1. What a plugin is today

A plugin is a static executable under the signed plugin store. Installation verifies the publisher signature and executable digest. Interface 1 runs as a supervised resident process; interface 2 runs once through the confined lab runner, whose declared capabilities grant no additional authority. On Linux resident plugins can make bounded, capability-checked host calls; the node supplies chain tip, header-by-height and log handlers. Wallet requests remain refused. Network, process-spawn and UI descriptors are unavailable and refused by the resident runner. See [`PLUGINS.md`](../dev/PLUGINS.md), `contexts/commons/modules/plugin/src/plugin_run_control.c`, `plugin_run_spawn.c`, and `engine/services/src/plugin_host_handlers.c`.

## 2. App table

Plugin path is one of three things: **now** (possible with the current host), **needs API N** (the numbered gap in section 3), or **in-tree behind a facade** (the custody or consensus part stays in the node and a plugin reaches it through a narrow call). Evidence column cites file and line in the current tree.

| app | path | today | plugin path | blocker | evidence |
| --- | --- | --- | --- | --- | --- |
| skycombat | `apps/skycombat/` | separate C23 program, no `app.def`; a source package through `zcode-package.json` (section 4a) | needs API 2 for the game window; headless simulation could use interface 2 | no `ui.panel` descriptor | `apps/AGENTS.md:5`; PLUGINS.md 316-318; `apps/skycombat/zcode-package.json` |
| zcl-ledger | `apps/zcl-ledger/` | separate host over Linux `hidraw` | **in-tree behind a facade**: signing and custody stay out of plugins; the host remains a separate binary | custody rule; no wallet broker (API 6); no device descriptor | `apps/zcl-ledger/README.md:5`; `apps/AGENTS.md:11`; `engine/modules/framework/include/zclassic23/app.h:127` |
| z23kernel | `apps/z23kernel/` | separate freestanding RV64 image that links no node code | not a plugin candidate: it is a boot image, so it stays separate | needs a non-Linux execution host (API 9) | `apps/z23kernel/README.md:5`; PLUGINS.md 61-63 |
| wallet | `contexts/wallet/` | linked into z23 (`PRODUCT_CONTEXTS`); custody-bearing | **in-tree behind a facade** through `wallet_request` | wallet broker (API 6); `make custody-check` | `Makefile:849`; `engine/modules/framework/include/zclassic23/app.h:127` |
| explorer | `contexts/explorer/` | linked into z23; controllers, models, views | needs API 3 (chain read) and API 5 (routes) | chain-read coverage beyond tip and header; route descriptor | `Makefile:849`; `app.h:105`; PLUGINS.md 316-318 |
| naming | `contexts/naming/` | linked into z23; ZDIR publishes on chain through OP_RETURN | ZDIR publication **in-tree behind a facade**; the ZNAM overlay needs API 4 and API 6 | consensus-bearing publication; no state or event descriptor | `contexts/naming/controllers/include/controllers/zdir_controller.h:3,20`; `contexts/naming/modules/znam/include/znam/znam.h:53-56` |
| market | `contexts/market/` | linked into z23; consensus branch id and genesis hash in use | consensus-bearing offer and settlement **in-tree behind a facade**; catalogue UI needs API 4 and API 6 | consensus parity; wallet broker | `contexts/market/controllers/include/controllers/yardsale_controller.h:103`; `contexts/market/controllers/src/file_market_offer_controller.c:235` |
| messaging | `contexts/messaging/` | linked into z23; board, wiki and messaging controllers (8 tracked files) | needs API 5 (routes and topics) | no topic descriptor; `p2p_publish` is in-tree only | `engine/modules/framework/include/zclassic23/app.h:124`; PLUGINS.md 316-318 |
| commons | `contexts/commons/` | linked into z23; the app host loads each `apps/<id>/app.def` at run time | **stays in-tree**: it is the host that loads plugins, and its apps are the rows below | none for the host itself | `engine/modules/framework/src/app_catalog.c:65` |
| blog | `contexts/commons/apps/blog/` | declarative `app.def`, no `ZCL_APP_SIM` | needs API 3, 4 and 5 | broader chain reads, state and event, routes and topics | `contexts/commons/apps/blog/app.def:3-18` |
| social | `contexts/commons/apps/social/` | declarative `app.def`; posts are signed events, not transactions | needs API 2 (`net.server` for the onion), 3, 4 and 5 | same as blog, plus `net.server` | `contexts/commons/apps/social/app.def:7-25`; `contexts/commons/apps/social/README.md:8-9` |
| yardsale | `contexts/commons/apps/yardsale/` | declarative `app.def` with `WALLET_REQUESTS` | listings and UI needs API 3, 4, 5 and 6; the ceremony and settlement **stay in-tree behind a facade** | wallet broker; consensus branch id | `contexts/commons/apps/yardsale/app.def:18`; `contexts/market/controllers/include/controllers/yardsale_controller.h:103` |

**Rule.** Wallet and zcl-ledger are custody-bearing. The consensus-bearing parts of naming and market stay in the node. Each reaches the plugin side only through `wallet_request` in `engine/modules/framework/include/zclassic23/app.h`, behind a facade the plugin cannot widen.

## 3. Host APIs needed, in order

The order is the order of work: each later item depends on the earlier ones. Shipped subsets are identified alongside remaining work.

1. **Host-call channel.** Resident plugins use the control socket for bounded host calls as well as supervision; `plugin_run_control.c` dispatches capability-checked frames and `test_plugin_run_hostcall.c` exercises a confined child. Interface 2 remains a one-shot lab call with no host-call channel; any expansion needs an explicit contract.
2. **`net.client`, `net.server`, `ui.panel` descriptors.** The resident runner refuses these unavailable capabilities in `contexts/commons/modules/plugin/src/plugin_run_spawn.c`.
3. **Chain read.** Resident `chain.read` provides tip and header-by-height through `engine/services/src/plugin_host_handlers.c`; broader chain queries remain to be specified and wired for apps.
4. **State and event append.** Host-call methods are named in `contexts/commons/modules/plugin/include/plugin/plugin_hostcall.h`, but the node handler table in `engine/services/src/plugin_host_handlers.c` supplies no state or event handler.
5. **Routes and topics.** Apps declare `ZCL_APP_WEB_MOUNT` and `ZCL_APP_TOPIC` (`contexts/commons/apps/blog/app.def:17-18`). The plugin vocabulary has no route or topic capability (PLUGINS.md lines 86-87).
6. **Wallet request broker.** The host table has `wallet_request` (`app.h:127`) and apps declare `WALLET_REQUESTS`. No plugin path exists, and custody review gates any change here.
7. **Enforcing service binder.** The service catalog is shadow-only: `ZCL_SERVICE_ENFORCEMENT_SHADOW` grants no runtime authority, and promotion "needs a real binder first" (`docs/commons/EXTENSION_POINTS.md` lines 74-80).
8. **Uninstall and stop.** The command list has install, switch and rollback, but no uninstall (PLUGINS.md lines 185-195). A resident plugin stops only when its run ends or on `SIGHUP` restart (PLUGINS.md lines 261-264). An uninstall plan is a proposed task (`docs/work/C23_TASK_CATALOG.md:597`).
9. **Non-Linux execution.** `plugin run` and `plugin call` are Linux-only and refuse other hosts with `PLUGIN_RUN_PLATFORM` (PLUGINS.md lines 61-63, 265, 409). The z23kernel image and any guest runtime need a host that is not Linux.

## 4. Distribution

The command catalog in `engine/composition/commands/plugin.def` and `plugin_attest.def` provides `plugin publish`, `plugin fetch`, `plugin fetch_remote`, `plugin attest`, and `plugin attest_verify`. `tests/harness/src/test_plugin_package.c` composes two-store transfer, pinned local fixture attestations, installation and a confined resident plugin chain-tip read against a node-backed fixture chain; `tests/harness/src/test_plugin_attest.c` covers attestation verification. The local fixture does not demonstrate independent reproduction or network authentication. An attestation records a builder's signed claim; it does not by itself establish independent reproduction. The full app journey and its acceptance remain to be demonstrated.

### 4a. Fork, versions and share for source packages

Skycombat is the first app with this path. `apps/skycombat/zcode-package.json` and `LICENSE` make it an ordinary source package: `zcode package dev prepare` derives its content root, and the offline-signed release goes through `zcode package publish commit`. No second format or store is involved.

| step | command | what it reuses |
| --- | --- | --- |
| fork | `zcode package fork` `root,destination` | the verified `zcode package checkout`, then a ZVCS repository in the copy whose first commit records `zcode.fork:<parent release id>` |
| save | `zcode package version save` `dir` | one append-only ZVCS snapshot; a copy with no changes is refused |
| history | `zcode package version list` `dir` | the self-verifying ZVCS commit log, newest first, with the recorded parent |
| restore | `zcode package version restore` `dir,version` | a source-only ZVCS revert recorded as a new version; unsaved changes are refused |
| share | `zcode package share` `dir,publisher_pubkey` | the saved head is rebuilt in private scratch and prepared by `vcs_package_prepare`; the release envelope's `parent_root` is the forked release id; the offline signature goes through the local publication commit |
| lineage | `zcode commons lineage` `workspace,package_root,datadir` | lists the persisted releases of a package root with each parent release and parent package root |

Fork, save, restore and share run plan-first: a call without `confirm` returns a `plan_id`; the same call with that `plan_id` and `confirm:true` acts, so MCP `z23_run` drives them like any other plan-commit leaf. Share refuses unsaved changes, a saved head equal to the fork, a parent release not persisted in the datadir, and a copy whose recorded fork tree no longer prepares to the parent release's package root. The publisher secret never enters: share returns the signing digest, and the caller signs it offline.

`parent_root` names a release id, the same field the reward gate reads. That gate also requires the parent to share the publisher key and the sequence to increase by one, so a fork shared under a different key is not reward-eligible through lineage. Sharing grants no reward, install or execution authority. A forker under a new key also renames the package namespace in `zcode-package.json`, because the namespace is bound first-come to the original publisher's key. `tests/harness/src/test_zcode_package_fork.c` runs this journey on local fixtures and an isolated datadir.

## 5. Links

This page is linked from [`docs/README.md`](../README.md) and from [`docs/work/FORWARD_PLAN.md`](../work/FORWARD_PLAN.md).

<!-- claim: file-present docs/dev/PLUGINS.md # the plugin developer contract this plan summarises -->
<!-- claim: file-present engine/modules/framework/include/zclassic23/app.h # resident host table -->
<!-- claim: symbol-present wallet_request engine/modules/framework/include/zclassic23/app.h # the wallet broker call -->
<!-- claim: symbol-present chain_query engine/modules/framework/include/zclassic23/app.h # chain read -->
<!-- claim: file-present contexts/commons/apps/yardsale/app.def # declarative app -->
<!-- claim: file-present apps/zcl-ledger/README.md # separate custody-adjacent host -->
<!-- claim: symbol-present ZCL_SERVICE_ENFORCEMENT_SHADOW engine/composition/services/catalog.def # still shadow-only -->

<!-- claim: symbol-present pp_attested_host_journey tests/harness/src/test_plugin_package.c # local attested transfer and node-backed hostcall -->
<!-- claim: file-present apps/skycombat/zcode-package.json # skycombat source package declaration -->
<!-- claim: symbol-present zcl_native_handle_zcode_package_share tools/command/native_zcode_package_share_command.c # share with parent -->
<!-- claim: symbol-present test_zcode_package_fork tests/harness/src/test_zcode_package_fork.c # fork, versions and share journey -->

## Opening a desktop app or game today (`z23 app open`)

Until the `ui.panel` descriptor exists, a desktop app or game such as Sky Combat, the airplane game, runs as its own process. The node's launcher starts it, not the plugin runner.

```bash
z23 app list               # launchable: id, aliases, kind, installed, raise, path, running_pid
z23 app open skycombat     # also: sky, sky-combat, airplane
z23 discover search game   # finds app.open (also: airplane, skycombat)
```

- **Where launch commands come from.** The compiled-in table `tools/command/app_launch_catalog.def`, whose executables resolve only in the directory of the running `z23` binary (`make game` builds `build/bin/z23-skycombat` there), and the owner's own `$XDG_CONFIG_HOME/z23/apps.tsv` (default `~/.config/z23/apps.tsv`). Nothing is read from the network, the board, the wiki, packages or fetched source.
- **apps.tsv.** One app per line, tab-separated: `id`, `aliases` (comma-separated or `-`), absolute `executable`, `ready marker` (a log substring, or `-` for "still running after one second"), `raise` (`sigusr1` if the program brings its window to the front on `SIGUSR1`, else `-`), then up to eight fixed arguments. There is no shell and no variable expansion. The whole file is refused unless you own it and it is not group- or world-writable. Each executable must be an absolute path to a regular executable file that you or root own and that is not group- or world-writable. A path that does not exist yet is listed as not installed.
- **What open does.** It resolves the name and requires a desktop session (on Linux, `DISPLAY` or `WAYLAND_DISPLAY`). It then looks for a running copy. A copy counts only if the pid record `~/.local/state/z23/apps/<id>.pid` still matches the live process's executable and start time, or, on Linux, if a process of yours runs the same executable. If a copy is running, open reports it (see Bring to front). Otherwise open starts the program with `posix_spawn` in a new session. Its stdin is `/dev/null`, its output goes to `~/.local/state/z23/apps/<id>.log`, and open waits up to 15 seconds for the ready marker.
- **Results (`zcl.app_open.v1`).** `opened` returns pid, ready_ms, executable, sha256 and log. The sha256 identifies the bytes on disk; it does not claim which source produced them. `already_open` returns the same pid and `raise`: `delivered`, `unsupported_by_app`, `no_handler` or `failed`. A refusal names its stage: `unknown_app` (lists the known names), `not_installed` (gives the build command), `no_desktop`, `config_refused`, `spawn_failed`, `exited_early` (exit code and log tail), or `not_ready` (the program is still running; its pid is given).
- **Bring to front.** An app declares raise support in its entry: `ZCL_APP_RAISE_SIGUSR1` in the compiled-in table, or `sigusr1` in the apps.tsv raise column. The launcher signals only an app that declares it, because the default action of `SIGUSR1` ends the process. On Linux the launcher also checks that the running copy really handles the signal. `raise` is `delivered` only when the launcher sent the signal. Sky Combat is marked unsupported until the game's own handler lands, so a second open returns `already_open` with the same pid and `raise: "unsupported_by_app"`. For a later handler: with the vendored RGFW backend, raylib `SetWindowFocused` works on X11 (once the window is viewable), macOS and Win32; on Wayland it does nothing, and Windows has no `SIGUSR1`.
- **Agents.** The MCP adapter (`z23 mcp serve`) exposes `apps_list` and `apps_open`, thin wrappers over `app.list` and `app.open`. `z23_run` still refuses `app.open`, because the leaf has no confirmation flow.
- **Proof.** `make t-fast-exact ONLY=app_launch` and `ONLY=mcp_serve_apps` need no display. `ONLY=app_launch_skycombat` builds the game and drives it on a private Xvfb display; it runs only on hosts that have Xvfb.

<!-- claim: file-present tools/command/app_launch_catalog.def # the compiled-in launch table -->
<!-- claim: symbol-present mcp_policy_app_open tools/mcp/mcp_policy.c # the apps_open allowance -->
