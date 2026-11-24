<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# z23-wallet

A lightweight wallet window for a Z23 node or a legacy zclassicd, 100% C23: no
C++, no Qt, no JavaScript, no web view. It draws its own pixels through
`platform/modules/gui` and talks to the node over loopback JSON-RPC. It links
neither `core/` nor `engine/`; it uses platform modules only.

It mirrors ZclWallet v2.1.2-beta13: the menu bar (File, Edit, Help), the
navigation rail (Home, Send, Receive, Activity, and Advanced behind the gear),
the beta13 palette and metrics, and the Home page (sync pill or banner, the
Summary group with the private-balance hero, Send/Receive, the amber fix-it
card, and the Address Balances table) and the Send page (pay-from, recipients
with memos, the privacy badge, beta13's validations, the confirm dialog and
the keyed z_sendmany with status polling; see "Send" below). Receive and
Activity are "Coming soon" screens that their own lanes fill. All amounts are
integer zatoshi from the RPC boundary on. It sends only from the Send page's
confirm dialog, never exports keys, never starts or stops a node, and it refuses to start when `ZCL_AGENT_SESSION` is set
(owner at the keyboard only).

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
proof tests.

## Run

```text
z23-wallet                                    # auto: a Z23 node first, then zclassicd
z23-wallet --node=zclassicd                   # a legacy zclassicd (reads; sends only from Send)
z23-wallet --datadir=<node folder>            # a Z23 node in that folder
z23-wallet --backend=headless --datadir=<dir> --shot=home.png --shot-after-ms=2000 --exit-after-shot
z23-wallet --script=<file> --backend=headless --shot-dir=<dir> --scale=2
z23-wallet --qa-frames=150 --log=run.log      # self-closing check; the log ends with
                                              # "exit: screen=... node=... status=..."
```

Node discovery records every folder it looks at with the reason it was
rejected, so a "not found" screen always lists what was searched.

* Z23 (`--node=z23`, and first under auto): `--datadir`, `%LOCALAPPDATA%\Z23\data`
  (`make windows-service-install`), `%LOCALAPPDATA%\Z23Node\data` (the per-user
  scheduled-task install), `%USERPROFILE%\.zclassic-c23`, `$HOME/.zclassic-c23`.
  Credentials are `<dir>/.cookie`; the port is `--rpcport`, then `<dir>/.rpcport`,
  then 18232.
* zclassicd (`--node=zclassicd`, and second under auto): `--datadir`, else
  `%APPDATA%\ZClassic` (Windows; also the folder the beta13 wallet's embedded
  node uses), `~/.zclassic` (Linux), `~/Library/Application Support/ZClassic`
  (macOS). `zclassic.conf` is parsed like zclassicd does: first value wins,
  keys are case-sensitive, credentials up to 1024 bytes. `rpcuser` +
  `rpcpassword` win over a `.cookie` (which zclassicd stops refreshing once a
  password is set); without a password the cookie is read from `datadir=` (or
  the folder) plus `testnet3/` or `regtest/`. Port: `rpcport`, else 8023, or
  18023 with `testnet=1` / `regtest=1`.
* Against zclassicd only these read calls are ever sent; anything else is
  refused before a byte leaves: getinfo, getblockchaininfo, getnetworkinfo,
  getpeerinfo, getnetworksolps, getwalletinfo, getwalletsummary,
  z_gettotalbalance, listunspent, z_listunspent, z_listaddresses,
  getaddressesbyaccount, listtransactions, z_listreceivedbyaddress,
  gettransaction.
* A 401 re-reads the cookie once, but only when the cookie supplied the
  credentials; refused conf credentials show "Your node refused the login in
  <conf path>." Secrets live only in memory; the log withholds any line that
  contains one.

Exit codes: 0 ok, 2 bad arguments, 3 window or backend unavailable, 4 shot failed,
5 agent session refused.

## Node facts used

* Z23 `walletsummary` (`contexts/wallet/controllers/src/wallet_shielded_activity_rpc.c`):
  `spendable_zat`, `pending_zat`, `public_zat`, `immature_zat`,
  `scanned_through_height`, `blocks_behind`, `current`, `locked`, `encrypted`,
  `send_allowed`, `send_blocked_reason`, `balance_available`.
* zclassicd beta13 `getwalletsummary [0]` (src/wallet/rpcwallet.cpp at
  v2.1.2-beta13) returns `transparent`, `private` and `total` as FormatMoney
  strings, the same fields as `z_gettotalbalance [0]`; a -32601 latches
  `z_gettotalbalance` for the session.
* `getblockchaininfo` (`blocks`, `headers`, `chain`, `verificationprogress`,
  `initialblockdownload`, `tiptime` or `mediantime`), `getnetworkinfo`
  (`connections`, `inbound_connections`, `outbound_connections`, `version`,
  `subversion`), `getinfo` (`connections`, `version`), `getnetworksolps`.
* Per-address balances are the sums of `listunspent [0]` and `z_listunspent [0]`
  (`address`, `amount`, `confirmations`); both must answer or the previous table
  stays.
* Fixtures under `tests/fixtures/z23wallet/rpc/<scenario>/` use these reply
  shapes with made-up values and addresses (`zs1fixtureaddressa000...`). They
  were not captured from a live isolated regtest node (see Remaining work).

## Design in one screen

* UI thread owns the window, widget tree and model; it never blocks on I/O.
  A read worker owns the socket and posts coalesced results, then wakes the window.
* Every request has one 5 s deadline covering connect, send and all receives.
  A 6 s first-result watchdog logs `worker: no reply after 6 s (phase=<p>,
  127.0.0.1:<port>)`, shows the refused text and restarts the worker.
* The first frame says "Looking for your node..."; a failure is shown only after
  a locate attempt has completed.
* Polling: chain every 10 s synced (2 s syncing), network every 30 s, getinfo
  every minute, wallet and balances on a tip change or every 30 s. Failure
  backoff 1, 2, 4, 8, 15 s (capped), warming repolls every second.
* Screens come from one table, `src/zw_screens.def`; each screen file builds its
  tree and publishes its bound text.
* Redraws are dirty-rectangle only; a caret blink presents only the field.

## Measured

Windows 10, 175% display scale (1925x1260 framebuffer), MSYS2 UCRT64 gcc 16.2,
release link (`-O2 -s`), 2026-11-23. beta13 numbers are from
`legacy_measurements` (read-only, same machine, same day).

| | z23-wallet (this lane) | target | ZclWallet beta13 |
| --- | --- | --- | --- |
| exe size | 380,416 bytes | <= 1.5 MB | 45,145,136 bytes + 21.8 MB node |
| process start to first frame | 38 to 50 ms | <= 150 ms | 489 to 674 ms |
| first data after first frame, mock node | 10 to 43 ms | <= 300 ms | n/a |
| first data after first frame, live zclassicd | 7 to 9 ms (Home with height) | <= 1 s | 13.9 s (embedded node start) |
| idle CPU, 10 s and 30 s windows | 0.0 ms (below the 15.6 ms timer tick) | <= 0.05% | 0.188 s per 30 s (0.63%) |
| working set after 40 s idle | 19.8 to 21.3 MB | <= 30 MB at 175% | 95.2 MB |
| private bytes | 13.2 to 13.4 MB | | 121.7 MB |
| handles / threads | 167 to 193 / 5 to 6 | <= 250 / <= 6 | 578 to 582 / 10 |
| GDI / USER objects | 9 to 10 / 11 to 13 | <= 30 / <= 30 | 88 / 50 |

One earlier 10 s window (seconds 3 to 13, with `--log`) measured 172 ms while
the second round of startup fetches repainted the full 175% frame; later
windows measured 0.0 ms.

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

## Remaining work

* P1 follow-ups: the Back up card and menu actions (custody review), the
  status-bar right-click "Refresh" menu (F5 works), page scrolling at the
  minimum window size, pill icons (shield/eye), z_listaddresses for zero-balance
  Sapling/Sprout classification, and Z23 reply shapes verified against an
  isolated regtest node.
* Fonts (lane F): until Ubuntu and DejaVu Sans Mono land, amounts use Inter and
  the non-ASCII glyphs beta13 shows are drawn by an interim map in
  `ui_layout.c` (dots and circles as shapes, the rest as ASCII look-alikes);
  the bound strings already carry the exact UTF-8 text.
* Send (lane P4, custody reviewer): the page, its dialogs and the send runner
  are in `zw_send*.c`, `zw_q_send.c` and `zw_screen_send.c`. Both profiles send
  the way beta13 does: `z_sendmany [from, [{address, amount, memo}], 1, 0.0001,
  "zq-<key>"]` with one idempotency key per confirmation, the same key again
  after an unanswered call, the unkeyed form only for a node that rejects the
  key, then `z_getoperationstatus` (and `z_listsendjournal`) polling; a Z23
  node answers the keyed call synchronously. The legacy allowlist gained
  exactly those three calls, and only the send runner's client may call
  `z_sendmany`. Developed and tested against the mock node only
  (`tests/fixtures/z23wallet/rpc/send_*`, group `z23wallet_send`). Not yet:
  auto-shielding of transparent change, the address book, custom fees, USD,
  more than three recipients, the status-bar right-click menu.
* Later lanes: P2 Receive and QR, P3 Activity, P5
  Advanced, menus, settings and backup, A agent dump/diff tools, X X11 and M
  macOS backends, M6a `.zui` markup, M7 GPU surface. See
  `platform/modules/gui/README.md`.
