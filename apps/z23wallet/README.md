<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# z23-wallet

A lightweight wallet window for a Z23 node, 100% C23: no C++, no Qt, no
JavaScript, no web view. It draws its own pixels through
`platform/modules/gui` and talks to the node over loopback JSON-RPC. It links
neither `core/` nor `engine/`; it uses platform modules only.

Milestone 1 (this directory): **Connect**, **Home** (balances) and **Node**
screens. All amounts are integer zatoshi from the RPC boundary on. It is
read-only: it never sends, never exports keys, never starts or stops a node, and
it refuses to start when `ZCL_AGENT_SESSION` is set (owner at the keyboard only).

Screenshots are generated, not committed: the golden tests write them to
`build/test-artifacts/z23wallet/` and `build/test-artifacts/gui/`.

## Build

```sh
make z23-wallet            # build/bin/z23-wallet (z23-wallet.exe on a Windows host)
make z23-wallet-check      # compile-only
make z23-wallet-windows    # mingw cross build (ZCL_TARGET=windows-x86_64)
make t-fast ONLY=gui
make t-fast ONLY=z23wallet
```

On Windows (MSYS2 UCRT64) `.\tools\dev\windows-make.ps1 z23-wallet` builds the
same program: `-mwindows -static -luser32 -lgdi32 -lshell32 -lws2_32`, no console.
The same sources build on Linux for the headless backend, which is what the land
proof tests. A live Linux window needs the X11 backend (lane M1x, not in M1).

## Run

```text
z23-wallet --datadir=<node folder>            # live window
z23-wallet --node=zclassicd                   # read-only view of a legacy zclassicd
z23-wallet --backend=headless --datadir=<dir> --shot=home.png --shot-after-ms=2000 --exit-after-shot
z23-wallet --script=<file> --backend=headless --shot-dir=<dir> --scale=2
z23-wallet --bench=bench.txt                  # key=value line, see below
```

Datadir discovery, first hit wins: `--datadir`, `%LOCALAPPDATA%\Z23\data` (what
`make windows-service-install` installs), `%USERPROFILE%\.zclassic-c23`,
`$HOME/.zclassic-c23`. A UNC path attaches the Windows window to a WSL2 node:
`--datadir=\\wsl.localhost\Ubuntu\home\<u>\.zclassic-c23`. The host is always
127.0.0.1; the port is `--rpcport`, then `<datadir>/.rpcport`, then 18232
(legacy 8023, or 18023 with `testnet=1`). Credentials are `<datadir>/.cookie`
(re-read once on a 401, because the cookie rotates) or, for the legacy profile,
`zclassic.conf`. Secrets live only in memory; the log withholds any line that
contains one.

Exit codes: 0 ok, 2 bad arguments, 3 window or backend unavailable, 4 shot failed,
5 agent session refused.

## Step 0 facts, confirmed on origin/main (3b7047867b)

* `walletsummary` is registered (`contexts/wallet/controllers/src/wallet_shielded_activity_rpc.c`,
  `rpc_walletsummary`). Fields used: `spendable_zat`, `pending_zat`, `public_zat`,
  `immature_zat`, `scanned_through_height`, `blocks_behind`, `current`, `locked`,
  `encrypted`, `send_allowed`, `send_blocked_reason`, `balance_available`.
* `getblockchaininfo` (`blocks`, `headers`, `chain`, `verificationprogress`),
  `getnetworkinfo` (`connections`, `inbound_connections`, `outbound_connections`,
  `version`, `subversion`). `getpeerinfo` is not used in M1.
* The RPC server replies `HTTP/1.1` with `Content-Length` and `Connection: close`
  (`engine/modules/rpc/src/httpserver_transport.c`); the cookie file holds
  `user:password`; `.rpcport` holds the bound port.
* `make windows-service-install` records its datadir as `%LOCALAPPDATA%\Z23\data`
  (`platform/packaging/windows/install-service.sh`).
* Fixtures under `tests/fixtures/z23wallet/rpc/<scenario>/` use the real reply
  shapes with edited, fixture-only values. No real address or key is committed.
  They were NOT captured from a live isolated regtest node in this lane (see
  Remaining work); the field names above come from the reply builders.

## Design in one screen

* UI thread owns the window, widget tree and model; it never blocks on I/O.
  A read worker owns the socket and posts coalesced results, then wakes the window.
* Polling: chain every 10 s synced (2 s syncing), network every 30 s, wallet on a
  tip change or every 30 s. About 10 requests per idle minute, zero wakeups between
  ticks. Failure backoff 1, 2, 4, 8, 15 s (capped), warming repolls every second.
* A node that answers `-32601` to `walletsummary` is treated as legacy
  zclassicd (latched for the session) and read through `z_gettotalbalance`.
  Sending through zclassicd is not supported.
* Redraws are dirty-rectangle only; a caret blink presents only the field.

## Measured (this lane)

Windows 10, 175% display scale, MSYS2 UCRT64 gcc 16.2, release link (`-O2 -s`):

| | z23-wallet M1 | target | legacy zclwallet beta11 (inventory) |
| --- | --- | --- | --- |
| exe size | 345,088 bytes | <= 1.5 MB | 36,566,576 bytes (22.8 MB GUI part) |
| process start to first frame | 33 to 38 ms | <= 150 ms | about 1 minute node warmup |
| first live data after first frame | 10 to 45 ms (local mock) | <= 300 ms | n/a |
| working set after 40 s idle (1925x1260 physical) | 21.6 MB | <= 20 MB at 100% | not measured |
| private bytes | 13.5 MB | | not measured |
| idle CPU over 30 s | 31 ms (0.10% of a core) | <= 0.05% | not measured |
| imports | OS DLLs only (KERNEL32, USER32, GDI32, SHELL32, WS2_32, api-ms-win-crt-* UCRT forwarders) | OS DLLs | Qt |

The legacy wallet was not measured on the same machine (not installed there), so
the comparison column is the inventory's file size only. Gaps recorded honestly:
idle CPU is 2x the target and the working set is 1.6 MB over it at this 175%
display (the framebuffer alone is 9.7 MB at 1925x1260).

## Remaining work (milestones)

M2 Receive and QR, M3 Activity, M4 Send (plan, confirm from plan, commit with an
idempotency key; needs a custody reviewer), M5 Backup, keys, settings, packaging
and the Start node button, M6a `.zui` markup and HTML export, M6b plugin actions,
M7 GPU surface for games, M1x X11 backend. See `platform/modules/gui/README.md`.
