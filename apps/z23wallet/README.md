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
make z23-wallet            # build/bin/z23-wallet (.exe on Windows) + z23-wallet.debug, release profile
make z23-wallet-check      # compile-only
make z23-wallet-windows    # mingw cross build (ZCL_TARGET=windows-x86_64)
make check-z23-wallet-size # release build against size/budget.tsv
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

## Release profile

`make z23-wallet` builds the release profile (`Z23WALLET_PROFILE=dev` keeps the
old uniform `-O2 -s` link for quick rebuilds; both draw the same pixels). Cold
code is `-Os`; the three raster files that paint every frame (`draw.c`,
`draw_text.c`, `ui_paint.c`) are `-O3`, because vectorised blending there makes
a full-page paint about 37% faster. The whole program is link-time optimised with
unused sections collected. On a UCRT toolchain the system CRT's C99
`printf`/`strtod` replace the 64 KB of static mingw copies (amounts are integer
zatoshi; nothing formats a float). Debug information goes to `z23-wallet.debug`
beside the binary, found by gdb through `.gnu_debuglink`, and the shipped image
is stripped. No executable packer (UPX and the like): packers defeat page
sharing, trip antivirus heuristics and hide the code from audit.

Measured with the integrated wallet (every page), Windows 10, MSYS2 UCRT64 gcc
16.2, headless scripted pass through every page against the fixture node,
interleaved runs, medians; the real window at 175% scale for the last rows:

| | old `-O2 -s` | release profile |
| --- | --- | --- |
| exe bytes, integrated wallet (earlier preview, the timing rows below) | 544,256 | 404,499 (-25.7%) |
| exe bytes, integrated wallet (later preview, more pages) | 586,752 | 434,707 (-25.9%) |
| exe bytes, milestone 1 sources (this branch) | 366,592 | 264,211 (-27.9%) |
| Linux x86_64 ELF (gcc 14.2), integrated / milestone 1 | 494,040 / 260,384 | 400,344 / 223,616 |
| full-page paint, median | 1.31 ms | 0.83 ms |
| full-page paint, p95 | 1.79 ms | 1.22 ms |
| all paints of the pass (94 frames) | 51.7 ms | 32.3 ms |
| process start to first frame (headless) | 12 ms | 12 ms |
| private bytes after first frame / after every page (headless) | 6.9 / 8.7 MB | 7.1 / 8.8 MB |
| first frame, real window (8 runs) | 74 ms | 63 ms |
| working set / private bytes, real window | 21.7 / 13.9 MB | 21.7 / 13.9 MB |
| golden images and tests | pass | bit-identical (46 of 46; the later preview: identical results, including its 4 not-yet-updated goldens) |

How the golden claim was shown: the registered `gui` and `z23wallet` test groups
build these sources with the test harness's own flags, not the release profile,
so they do not prove it. The identity above comes from running the wallet's test
suites, linked against release-profile objects, on Windows (and on Linux at `-O3`
and under the sanitizers). `make z23-wallet-release-goldens` does the same for
any profile: it links every `test_gui*.c` / `test_z23wallet*.c` suite against the
objects of the profile being built and runs them, goldens included (milestone 1
on Windows: 159 checks ok, 0 failed, 11 goldens identical).

Hardening, each verified in the produced binary: ASLR with high entropy and
relocations kept, DEP (`objdump -p`: `HIGH_ENTROPY_VA DYNAMIC_BASE NX_COMPAT`),
no section both writable and executable (`llvm-readobj --sections`),
`-fstack-protector-strong` (187 `__stack_chk_fail` call sites),
`_FORTIFY_SOURCE=3` (`__memcpy_chk` and friends linked), an `asInvoker`
manifest with per-monitor DPI v2 and the Windows 10 compatibility GUID plus a
version resource (one manifest in the binary: ours is language-neutral like
mingw's default, so the resource merge drops the default; `llvm-readobj
--coff-resources`), DLL search limited to
System32 (`SetDefaultDllDirectories`, and `opengl32.dll` through
`LoadLibraryExW(..., LOAD_LIBRARY_SEARCH_SYSTEM32)`). Together they cost 8 KB
(2%). Not available: Control Flow Guard (gcc has no `-mguard=cf` for
mingw-w64; lld's `--guard-cf` alone leaves `GuardFlags` 0); `-fcf-protection`
only adds `endbr64` bytes Windows does not check; `-fstack-clash-protection` is
a no-op there (the x64 ABI already probes large frames through `___chkstk_ms`).
The wallet opens no listening socket and connects only to 127.0.0.1 on the
configured port (one `connect` call site, `INADDR_LOOPBACK`; at run time no
listening or UDP endpoint, every connection 127.0.0.1 to 127.0.0.1).

On Linux the profile adds PIE, full RELRO with BIND_NOW, a non-executable stack,
`-fstack-clash-protection` and `-fcf-protection=full` (verified with `readelf`:
`DYN (Position-Independent Executable)`, `FLAGS BIND_NOW`, `FLAGS_1 NOW PIE`,
`GNU_RELRO`, `GNU_STACK RW`, `x86 feature: IBT, SHSTK`, `__stack_chk_fail` and
`__*_chk` imports). Ubuntu 24.04 gcc already enables these by default, so they
cost 0 bytes there; the flags keep them on other distributions. The tests pass
under AddressSanitizer plus UndefinedBehaviorSanitizer (Linux, `-O1`) and
UndefinedBehaviorSanitizer at `-O3` (Linux, and in trap mode on Windows).

On macOS (Apple clang 17, arm64) the same target builds with the platform's
equivalents: PIE and a non-executable stack are the default (`otool -hv`:
`PIE`), `-Wl,-dead_strip` replaces `--gc-sections`, `-fcf-protection` and the
`-z` flags do not exist there, and `dsymutil` writes `z23-wallet.dSYM` (UUID
matched with `dwarfdump --uuid`) before the debug symbols are stripped:
240,472 bytes against 268,712 for the dev profile (milestone 1 sources).

`make check-z23-wallet-size` builds the wallet and compares it with
`apps/z23wallet/size/budget.tsv`: per reference toolchain, a byte budget (the integrated
wallet plus about 3%) and the section sizes it was set from. Over budget fails
with the bytes over and the sections that grew; another toolchain is reported,
not failed, because sizes only compare on the toolchain that set them.

Measured follow-ups, largest first (not in this profile):

* Glyph cache arena: `draw_text.c` reserves 1 MiB of zero-filled static memory
  that Windows charges to private bytes untouched; a 128 KiB arena measured
  976 KB less private memory (working set unchanged). Grow it on demand.
* Inter subsets: keep only the seven tables stb_truetype reads (cmap, glyf,
  head, hhea, hmtx, loca, maxp): 40,448 bytes, all goldens bit-identical. Needs
  the vendored subset recipe and checksums in `vendor/typography/SOURCE` updated.
* winpthread: 29,416 bytes linked statically; Win32 threads, SRW locks and
  condition variables behind the existing platform layer would remove it.
* Linux: `-fno-asynchronous-unwind-tables` drops 28,672 bytes of `.eh_frame`
  (the split debug file keeps `.debug_frame` for gdb); glibc backtraces lose it.
* Control Flow Guard: only through clang (`-mguard=cf` with lld `--guard-cf`).

## Remaining work (milestones)

M2 Receive and QR, M3 Activity, M4 Send (plan, confirm from plan, commit with an
idempotency key; needs a custody reviewer), M5 Backup, keys, settings, packaging
and the Start node button, M6a `.zui` markup and HTML export, M6b plugin actions,
M7 GPU surface for games, M1x X11 backend. See `platform/modules/gui/README.md`.
