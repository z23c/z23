<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Windows development

Use this page to build a native Windows `z23.exe`, or to build, test, and
operate the complete node in Windows Subsystem for Linux 2 (WSL2).
For the native lane, first install MSYS2 and select its UCRT64 environment
(the 64-bit Windows Universal C Runtime toolchain). For the Linux lane,
use Ubuntu 24.04 or newer with GCC 14+ or a Clang that accepts `-std=c23`.
Keep a separate checkout for each lane: do not mix compiled object files or
vendored archives (the built third-party dependencies).

| Lane | Purpose | Artifact status |
| --- | --- | --- |
| MSYS2 UCRT64 | Native C23 build, GCC/Clang diagnostics, and Windows API (Win32) port | Native `z23.exe`; acceptance covers qualified Windows capabilities |
| WSL2 Ubuntu | Build, test, and operate the complete node today | Linux Executable and Linkable Format (ELF) binary under WSL2 |

The UCRT64 bootstrap (initial setup), source-identity checks (checks of the
exact source bytes), compile-epoch leases (which separate build objects by
toolchain and protect them while in use), pinned static C dependencies, and
canonical GCC and Clang node builds are supported. The built binary is a
native x86-64 Portable Executable (PE) named `build/bin/z23.exe`; its release
audit allows only declared Windows system dynamic-link libraries (DLLs).
Some optional package, snapshot, and agent operations still refuse where
their Windows capability backend is not qualified. The resident dev worker
(`dev agent worker run`) runs its
executor only inside the Windows confinement backend described under
[Dev worker confinement backend](#dev-worker-confinement-backend). When
that backend cannot be set up on a host, the worker refuses and names the
missing capability. Agent operations that have no Windows backend yet,
such as `dev agent queue next`, keep refusing. Never weaken those refusals
to obtain a green build.

The native code navigator can build and refresh `.codeindex/index.kv` on
Windows. Publication stays beneath a retained private directory handle, writes
through a retained private staging-file handle, verifies the final source
stat-root (a digest of source-file metadata) and SQLite rollback-journal
format (the database's transaction format), flushes the staged bytes, and
atomically moves the retained child into place. `make windows-acceptance`
executes `z23.exe code have` through the headless runner and requires a
successful typed response; a Windows rebuild refusal is no longer accepted
as a passing result.
The same native acceptance requires the canonical warm capability query to
remain inside the command's declared 250 ms latency budget. A separate native
program bounds the unchanged source-metadata freshness root at 150 ms, using
one retained directory handle per source directory rather than reopening every
source path. It also requires the warm Merkle refresh to reuse every unchanged
leaf within 150 ms and detect same-size subsecond edits. A Merkle tree combines
file digests into one source-tree digest. Merkle comparison uses
the full native directory metadata, preserving file IDs and timestamp precision
that the C Runtime (CRT) `stat` adapter would narrow. These are executable
Windows contracts, not cross-compile claims.
The source-tree Merkle cache and territory roll-up memo use the same retained
private child transaction on Windows, so warm provenance and dispatch queries
can reuse sealed derived state after the source generation is unchanged. The
read-only SQLite generation is mapped from its retained positioned-file handle
instead of copied into a second roughly 100 MiB heap image on every command.

The C23 Commons file-service client transport is also native. Windows uses the
same bounded encrypted-frame and authenticated-chunk implementation as Linux
and macOS, carried over `platform_socket_t`; native acceptance sends a 64 KiB
encrypted frame (including padding) and a 256 KiB authenticated chunk through
a real WinSock (Windows sockets) loopback pair and verifies exact payload,
digest, counter, and byte-accounting parity. The forward-secret X25519/HKDF
handshake (key exchange and key derivation) and ROM artifact fetch dialer
(which downloads consensus-state bundles) are also native. Windows clients
do not stop at an `ENOTSUP` (unsupported operation) frame stub.
The inbound file-service server and its manifest/snapshot transaction remain
explicitly unavailable until their filesystem mutation path is qualified.

The fresh native consensus-store path is also operational. `consensus.db`,
its write-ahead log (WAL), and its shared-memory sibling are opened by the
retained-directory SQLite virtual filesystem (VFS), and the live connection
is audited against the exact validated directory handle before schema or
reducer work begins. A fresh isolated
mainnet datadir (node data directory) has reached remote procedure call (RPC)
readiness, exchanged headers and block bodies with public ZClassic peers,
and advanced the validated reducer frontier on a
native `z23.exe`. This is startup and forward-sync evidence, not a completed
sync-to-tip claim. A copied legacy datadir that has `progress.kv` but no
`consensus.db` still refuses before mutation because the legacy ATTACH/rename
migration is not handle-relative. Corrupt-store quarantine likewise refuses
in place on Windows until its rename transaction is retained-directory
qualified.

Native execution requires Windows. A Linux host can build the pinned
third-party archives into the target-qualified
`vendor/cross/x86_64-w64-mingw32` tree, then use Clang 20+ against the distro
MinGW sysroot (target headers and libraries) to link and audit an x86-64 PE:

```bash
VENDOR_TARGET=x86_64-w64-mingw32 tools/scripts/build_vendor.sh
make ZCL_TARGET=windows-x86_64 -j"$(nproc)" z23 z23-acme
platform/packaging/release/build_release.sh --platform windows-x86_64
```

That is compile, link, PE-import-audit, and package evidence only. It is not a
native Windows runtime observation and cannot close startup, service, or
filesystem semantics. The cross build uses `vendor/cross/<triple>` precisely
so its generated OpenSSL/libevent headers and archives cannot overwrite the
native host slots in `vendor/lib` and `vendor/include`. Native UCRT64 and WSL2
still need separate `build/` and host-vendor trees; move changes between them
through Git, never copied objects.

## Tor on Windows

Real Tor is the default here too. `make vendor` produces only the
offline-friendly `libtor_stub.a`, but a build that links a node establishes
the Tor archives first, so a Windows `z23.exe` reaches the onion network and
publishes its own `.onion` with no flag. `-no-tor` opts out and is refused on
a canonical, soak or standby operator lane.

Set `ZCL_TOR=stub` on a Make invocation for a development-only build. It links
the stub, prints one loud line, stamps `tor: stub` into `z23.exe -version`,
and produces a binary that refuses `-tor`, the onion flags and onion-node
mode, and that no ship or
install step will package. Its `tor_run_main` is the stub's and returns
without ever opening an onion service.

A cross build uses a clean export of the pinned Tor commit as its configure
source directory, `vendor/cross/x86_64-w64-mingw32/tor-src`. The host build
configures `vendor/tor` in place; autoconf refuses an out-of-tree configure
against an already-configured source directory.

Cross, from Linux, once the pinned OpenSSL/libevent/zlib archives above exist
under `vendor/cross/x86_64-w64-mingw32`:

```bash
make ZCL_TARGET=windows-x86_64 tor-full
make ZCL_TARGET=windows-x86_64 -j"$(nproc)" z23 z23-acme
```

Native, from UCRT64, once `make vendor` has produced the host archives:

```bash
make tor-full
make -j"$(getconf _NPROCESSORS_ONLN)" z23
```

Both invoke `tools/scripts/build_tor_full.sh` against the pinned `vendor/tor`
submodule. Tor's `configure` uses `--with-openssl-dir`, `--with-libevent-dir`,
and `--with-zlib-dir` to select the vendor tree. The cross run supplies
`--host` for the MinGW target triple (the toolchain's target name), matching
cross tools, and a separate build directory.

| Output | Native UCRT64 | Linux cross build |
| --- | --- | --- |
| `ZCL_TOR_TREE` | `vendor/tor` | `vendor/cross/x86_64-w64-mingw32/tor` |
| Main archive | `libtor.a` beneath that tree | Same relative path |
| Additional archives | Under the tree's ext directory | Same relative paths |

For the native tree the additional archives are beneath
`vendor/tor/src/ext/ed25519/donna/`, `vendor/tor/src/ext/ed25519/ref10/`, and
`vendor/tor/src/ext/keccak-tiny/`; the cross tree uses the same relative
paths.

The Makefile's `TOR_FULL` selection uses these archives on both lanes.

## Native UCRT64 lane

1. Install MSYS2 to `C:\msys64`.
2. Open **MSYS2 UCRT64** and update it. If the runtime closes the shell,
   reopen UCRT64 and repeat the update:

   ```bash
   pacman -Syu
   ```

3. Install the required packages:

   ```bash
   pacman -S --needed base-devel gcc git curl wget unzip \
     mingw-w64-ucrt-x86_64-toolchain \
     mingw-w64-ucrt-x86_64-clang \
     mingw-w64-ucrt-x86_64-clang-tools-extra \
     mingw-w64-ucrt-x86_64-lld \
     mingw-w64-ucrt-x86_64-cmake \
     mingw-w64-ucrt-x86_64-ninja \
     mingw-w64-ucrt-x86_64-libsystre
   ```

Keep the checkout on the Windows filesystem rather than inside the
MSYS2 tree, and enter it from UCRT64 through its drive mount (a path
under `C:` appears as `/c`). Do not add the MSYS2 `usr\bin` directory
globally to the Windows `PATH`; launch the editor from UCRT64 so it
inherits the UCRT64 toolchain directory.

From PowerShell, the canonical one-command bootstrap installs the required
UCRT64 packages, runs `make setup`, and builds `z23.exe`:

```powershell
.\tools\dev\windows-setup.ps1
# A non-default installation is supported end to end:
.\tools\dev\windows-setup.ps1 -Msys2Root D:\msys64
# Print the commands and converted MSYS paths without pacman/build mutations:
.\tools\dev\windows-setup.ps1 -Msys2Root D:\msys64 -DryRun
```

The unprefixed MSYS `gcc` package builds the hosted `zcc` cache courier; it
does not build product objects. `zcc` launches the UCRT64 compiler for native
Common Object File Format (COFF) objects and PE output, while Windows compile
epochs use the shell publisher because
MSYS does not provide the directory-flush contract required by zcc's native
publisher. The setup smoke proves this hosted-to-native boundary.

On Windows, `make setup` installs native receipt hooks in a content-addressed
generation and removes the obsolete `z23.windowsMsys2Root` worktree setting.
The native hooks do not re-enter a UCRT64 shell.

For later Make invocations from PowerShell, use the matching courier; it uses
the same selected root for both `bash.exe` and the UCRT64 `PATH`:

```powershell
.\tools\dev\windows-make.ps1 windows-acceptance
.\tools\dev\windows-make.ps1 -Msys2Root D:\msys64 -DryRun z23
```

If working directly inside the UCRT64 shell, use the canonical repository
setup rather than recreating its hook and dependency steps by hand:

```bash
Z23_CHECKOUT=/c/path/to/your/z23-checkout
cd "$Z23_CHECKOUT"
code .
make setup
make doctor-env
make -j"$(getconf _NPROCESSORS_ONLN)" z23
make windows-acceptance
```

On Windows, `make setup` installs the tracked shell `pre-commit` lane guard and
native PE receipt hooks. The pre-push executable reads only an immutable
exact commit/base receipt; it never opens a shell, runs Make, compiles, tests,
waits, or fetches. Its two bounded Git queries reuse the exact parent Git image,
run without a console window, and are contained by a kill-on-close Job Object
(a Windows process group with enforced resource and lifetime limits).
Until a Job-contained native proof producer exists,
post-commit/post-merge/post-checkout return immediately without launching the
full development binary; missing proof remains an honest pre-push refusal.
Native hook generations are content-addressed and
`core.hooksPath` switches atomically, so a locked running executable cannot
block an update. `make windows-acceptance` remains an explicit parity gate.

The native fleet Git capture drains the pipe after observing child exit, so a
short-lived Git command cannot lose its final answer and falsely report missing
refs. The Windows acceptance catalog checks short responses, multi-read output,
bounded truncation, and nonzero exits with their diagnostics.

Developer mail uses native owner-private files on Windows. Post appends through
a nonblocking locked handle after checking its ownership and link count; ack
atomically replaces the private cursor file. Native acceptance covers post/pull,
LF (line-feed) byte preservation, lock contention, hard-link refusal, and cursor
replacement.
Paths have an explicit 4096-byte command bound and refuse truncation. Cross-host
delivery still requires a configured transport for the local outbox and inboxes.

Install the audited canonical binary as a supervised per-user Task Scheduler
job with one command:

```bash
make windows-service-install
make windows-service-status
```

The install is under `%LOCALAPPDATA%\Z23`, restricts that tree to the current
user and Windows SYSTEM, records and verifies the exact `z23.exe` SHA-256, and
keeps the node datadir outside the checkout. The task runs with least user
privilege, starts at logon, and restarts after failure. Its only argument is
the datadir path; RPC and wallet credentials remain in protected files and do
not appear in the process command line. `make windows-service-remove` removes
the task but deliberately preserves the datadir and installed bytes.

Use both native compilers for focused C23 work. For the canonical node, pass
the compiler explicitly; the build epoch key prevents either lane from reusing
the other lane's objects:

```bash
gcc -std=c23 -Wall -Wextra -Wpedantic -pedantic-errors file.c
clang -std=c23 -Wall -Wextra -Wpedantic -pedantic-errors file.c
make -j"$(getconf _NPROCESSORS_ONLN)" CC=gcc CXX=g++ z23
make -j"$(getconf _NPROCESSORS_ONLN)" CC=clang CXX=clang++ z23
```

Never reuse `vendor/lib` or `build` across UCRT64 and WSL. Each archive and
compile epoch is bound to its producing toolchain.

## Native NVIDIA Equihash accelerator

The optional native miner accelerates the mainnet Equihash (192,7) solver on
the Windows GPU while retaining the portable C23 verifier as the final
authority. It dynamically loads the system `OpenCL.dll`; no CUDA SDK, OpenCL
SDK, compiler installation, PATH change, or redistributable DLL is required.
The NVIDIA driver compiles the bounded OpenCL C kernels (GPU programs) to the
selected GPU's native assembly. Kernel dispatches are deliberately short to
stay below the Windows display-driver timeout, and the acceptance path runs
under the same no-window, kill-on-close Job Object launcher as the node gates.

Build and measure it from PowerShell without opening an MSYS2 window:

```powershell
.\tools\dev\windows-make.ps1 gpu-miner
.\tools\dev\windows-make.ps1 gpu-miner-acceptance
```

The acceptance target probes the real adapter, solves one full nonce, and
requires the existing C23 Equihash verifier to accept the 400-byte solution.
For direct use from UCRT64:

```bash
build/bin/z23-gpu-miner.exe probe
build/bin/z23-gpu-miner.exe benchmark 4
build/bin/z23-gpu-miner.exe mine PRE_SOLUTION_HEADER_HEX 256
```

`mine` accepts the exact 108 serialized bytes preceding the nonce (216 hex
characters), searches little-endian 256-bit nonces, verifies each candidate,
and reports a solution only when the complete header double-SHA256 meets its
encoded `bits` target. It is a solver boundary, not yet a wallet or pool
client: constructing a block template, choosing a payout, and submitting the
completed block remain explicit caller responsibilities.

## Complete node lane in WSL2

Use an Ubuntu 24.04 or newer WSL2 distribution with GCC 14+ (or a Clang that
accepts `-std=c23`). Keep the Linux checkout inside the WSL ext4 filesystem;
building under `/mnt/c` is much slower and mixes host filesystem semantics
into the Linux acceptance lane.

```bash
mkdir -p "$HOME/src"
git clone https://github.com/z23c/z23.git "$HOME/src/z23"
cd "$HOME/src/z23"
make setup
make -j"$(getconf _NPROCESSORS_ONLN)" z23
make -j"$(getconf _NPROCESSORS_ONLN)" test-parallel
make lint
```

The two checkouts are separate build lanes. Move changes through Git commits,
not by copying generated archives or object trees.

## Persistent node under WSL2

WSL must have systemd enabled. The tracked service assumes a checkout at
`~/zclassic23` and requires `build/bin/zcl-nodectl` as well as `build/bin/z23`.
`platform/deploy/setup.sh` currently derives `platform/` as its repository
root and cannot install the unit from its constructed path. Inspect the unit
before configuring a service for the clone above:

```bash
cd "$HOME/src/z23"
sed -n '1,220p' platform/deploy/z23-node.service
```

Use `systemctl --user stop z23-node.service` before changing its binary or
datadir. Operator flags belong in `~/.config/zclassic23/env`; private keys,
cookies, datadirs, and credentials never belong in either checkout.

WSL distributions do not necessarily start merely because Windows booted.
If boot-without-login is required, create one Windows Task Scheduler entry,
as the owning Windows user, that runs:

```text
wsl.exe -d Ubuntu -- systemctl --user start z23-node.service
```

Use “At log on” unless unattended pre-login operation is an explicit
operator requirement. Do not store RPC credentials in the task arguments.

## Git and SSH

Use a GitHub-verified no-reply address if email privacy is enabled:

```bash
git config --global user.name "Your Name"
git config --global user.email "ID+USERNAME@users.noreply.github.com"
ssh -T git@github.com
```

Host-key verification and public-key authentication must succeed before a
push. Do not disable `StrictHostKeyChecking`, embed a token in a remote URL, or
commit credentials. Fetch current `origin/main`, integrate it, run the affected
gates, push, and verify the exact remote SHA.

## Dev worker confinement backend

`z23 dev agent worker run` runs natively on Windows only inside the
confinement backend in `platform/modules/platform/src/confined_process.c`,
which the worker drives from `tools/command/native_devagent_worker_run.c`.
At the start of every run the leaf checks that the backend can be set up.
If it cannot, the leaf refuses with `WORKER_CONFINEMENT_UNAVAILABLE`, and
the evidence names the missing capability: `missing=job-object`,
`restricted-token`, `low-integrity`, `write-label`, or `handle-list`. It
never falls back to an unconfined run.

POSIX forks a child and sets `RLIMIT_CPU` and `RLIMIT_DATA`. Windows has no
fork, so the parent writes `executor_job.json` into the run directory and
starts its own image again as
`z23.exe --z23-internal-agent-worker-child <rundir>`. Each run gets the
following:

| Guarantee | How |
| --- | --- |
| Whole tree dies with the job | Kill-on-close Job Object. The parent kills the job on the wall cap, on worker shutdown, and after the child exits, so grandchildren never outlive the run. |
| Memory cap equal to POSIX `mem_mb` | `JobMemoryLimit` = `mem_mb` MiB. A commit past it fails, which is the Windows ENOMEM. |
| CPU cap equal to POSIX `cpu_s` | `PerJobUserTimeLimit` = `cpu_s`. The job terminates at the cap. |
| Wall cap equal to POSIX `time_cap_s` | The parent polls in 25 ms slices and kills the whole job. |
| Process cap | `ActiveProcessLimit` = 64 live processes, the child included. |
| No privilege | `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE \| LUA_TOKEN)`. Administrators, Power Users, Account/Server/Print/Backup Operators and Network Configuration Operators become deny-only. |
| Low integrity | The token is labeled `S-1-16-4096`, so no-write-up denies every medium-labeled object, which covers everything the user owns by default. |
| Write scope | Only the run directory, plus the `muse-workspace:` checkout named in the brief (absolute path, holds `.git`, not a drive root, no `..`), get the inheritable low label `S:(ML;OICI;NW;;;LW)` for the run. When the run ends they are reset to medium through the whole tree, including any label the child set itself. |
| No inherited handles | `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` holds only `NUL`, used as stdin, stdout and stderr. |
| Explicit environment | An allowlist of system and path variables (`SystemRoot`, `PATH`, `USERPROFILE`, `LOCALAPPDATA`, …) plus `TEMP`/`TMP` set to the run directory. No credential, token or key variable crosses. |
| No UI reach | Job UI limits: desktop, clipboard, global atoms, USER handles, system parameters, exit-windows. |
| Fail-closed child | The child runs nothing unless it can see its own job caps, low-integrity token, and disabled Administrators group. |

The run ends in the same receipt fields and verdicts as on POSIX, because
both backends share one outcome mapping. Wall timeout gives `rc=124
executor-time-cap`. A crash gives `rc=130 executor-signaled`; on Windows a
crash is an NTSTATUS exception or fast-fail exit, or the job CPU cap. Exit
without a result gives `rc=100 executor-no-result`. A launch refusal gives
`rc=127 executor-launch-failed`. A result the executor wrote is gated the
same way, so `failed` stays `failed`. ENOMEM reaches the child as an
allocation failure in both backends, so the verdict follows what the child
does next.

What this backend does not enforce, compared with POSIX:

1. The Windows memory cap counts committed memory summed over the whole job.
   The POSIX worker instead sets a per-process `RLIMIT_DATA` ceiling.
2. The CPU cap counts user-mode time only, summed over the job. Kernel time
   is not charged, while `RLIMIT_CPU` charges both.
3. For the length of the run, any other low-integrity process of the same
   user can also write the granted run directory and worktree. If the
   release cannot relabel a root, the grant stays and
   `confinement.txt` in the run directory records `confinement-release=failed`.
4. Reads are not scoped, and neither is the network. The same is true of
   the POSIX backend.
5. The executor that runs is the one the child image's entry point wires,
   which is the Muse executor in `z23.exe`. The drive's function pointer does
   not cross the process boundary.
6. A write root that contains a reparse point is refused before launch
   (`write-label`), never relabeled.
7. The Muse executor requires a `/`-rooted `muse-workspace`. A native
   `C:\` path is therefore still refused by the executor itself, inside the
   confinement.
8. Any existing `worker.lock` that is not owner-private, for example one
   left by an older build, refuses the drive (`WORKER_BUSY`) until it is
   removed.

Native proof is the `devagent_worker_confine` program in the acceptance
catalog. It covers write scope, the memory cap, the whole-tree wall kill,
the CPU cap, the failed verdict, and the refusal to run unconfined. From
UCRT64:

```bash
make build/tests/windows/devagent_worker_confine.exe && \
  build/tests/windows/devagent_worker_confine.exe
```

Exit 77 is an honest refusal: Wine, or a named missing capability.
`make windows-acceptance` runs the same program with the rest of the
catalog. The platform-neutral half (caps, outcome mapping, job hand-off,
write-root and environment selection, and refusal when unarmed) runs on
Linux in `make t-fast ONLY=devagent_worker`.

## Remote terminal on Windows

The mesh terminal lane lets a paired machine that holds the terminal
capability open a shell on this computer. On Windows the worker
(`cognition/modules/session/src/mesh_terminal_worker.c`) starts the
configured shell on a ConPTY pseudoconsole, with these properties:

| Property | How |
| --- | --- |
| Shell path | `-terminalshell=` must be a drive-letter absolute path to an `.exe` (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`). UNC and device prefixes, relative forms, `..`, reserved characters, reserved device names (`nul`, `con`, `aux`, `prn`, `com1`-`com9`, `lpt1`-`lpt9`) as any path component, trailing separators, arguments, and values of 512 bytes or more are refused. |
| Environment | The shell receives only `APPDATA`, `ComSpec`, `LOCALAPPDATA`, `PATH`, `SystemRoot`, `TEMP`, `TMP` and `windir` from the node's own environment (each only when present), plus `HOME` and `USERPROFILE` set to the per-terminal working directory and `TERM=xterm`. No other variable crosses. |
| Input pipe | A named pipe with an unpredictable name, one instance, no remote clients, and a DACL that admits only the current user. |
| Whole tree dies | The shell starts suspended, joins a kill-on-close Job Object, and only then runs. Close, byte limit, lifetime, idle timeout and peer disconnect terminate the job, which removes every descendant. At most 32 processes live in the job. A shell that cannot be placed in the job never runs. |
| Bounded input | Input goes through an overlapped pipe. A write waits at most one second, is then cancelled, and is reported as the stalled-terminal IO refusal; the lifetime and idle limits own any kill. |
| Budgets | The same input, output, lifetime and idle budgets as the POSIX arm. |

The lane is off on Windows by default. The shell would run as the node's own
user, and the terminal contract requires a confined identity for the shell and
a refusal where confinement cannot be proven. With `-terminalshell` set to a
valid path and no further flag, the node logs `windows-shell-identity-unconfined`
and answers every terminal open with `CONFINEMENT_UNAVAILABLE`. The Job Object
and the bounded input contain the process tree, not the shell's authority.

`-terminalacceptunconfined` (default off, Windows only) is the owner's explicit
choice to turn the lane on anyway. In plain words: the remote shell runs as
your Windows user with all its rights; only peers you paired with the terminal
capability can open it. With the flag the node logs one WARN line at startup
(`terminal_confinement: unconfined-owner-accepted`), the signed grant capsule
carries `"terminal_confinement":"unconfined-owner-accepted"` as an additional
key (the wire format is unchanged), and every session open and close is logged
with the first eight hex characters of the pairing id, byte counts and
duration, never content. On any other platform the flag is refused at startup
with `unconfined-opt-in-windows-only` and the lane stays off. A
restricted-identity launch of the shell remains the intended follow-up and will
make the flag unnecessary.

Start the node outside a restrictive job. The shell is placed in its own job, so
if the node itself runs inside a job that forbids nesting, the placement fails.
The shell then never runs, and the node logs `confined spawn refused
(job-assign)` with `job-object-assign` in the message, which is distinct from
a missing shell or a refused flag. Launch the node from a normal console, a
service, or a scheduled task, not from a tool that wraps its children in a
restrictive job.

The flag is also read from `<datadir>/z23.conf` (engine/entry/main.c reads it
after the command line, which wins), so a line `terminalacceptunconfined=1`
there enables the lane. In the current code the only writer of that file is
`z23 join`, and it writes only `packagehost` and `buildworker`, preserving every
other line. `z23 fleet join`, `fleet admit` and the pairing commands carry no
configuration and write no such file, and no fleet-pushed configuration path
exists. The flag can therefore only be set by someone who can already write the
node's data directory, which Windows restricts to its owner.

Line ends and end of input: send CR (`\r`) to end a command line when a client
pipes text into a Windows shell. LF alone does not execute a command in cmd or
PowerShell on a pseudoconsole. The end-of-input byte (Ctrl-D, 0x04) is not EOF
there and does not close the session; end a session with `exit` or by closing
the terminal.

A paired machine opens the terminal with
`z23 ops mesh terminal --pairing_id=<64hex>` from a POSIX terminal; the client
itself refuses on Windows with PLATFORM_UNSUPPORTED. The `mesh_terminal_open`,
`mesh_terminal_poll` and `mesh_terminal_read` RPC methods remain available to
programs.

Native proof is the `mesh_terminal_worker` program in the acceptance catalog
(`tests/harness/src/mesh_terminal_worker_windows_acceptance.c`). On a Windows
machine it spawns `cmd.exe` and, when present, `powershell.exe`; round-trips a
command; resizes; exhausts the input, output and lifetime budgets; checks that
a started child process is gone after kill; and measures that no input write
outlives its bound against a suspended shell. It exits 77 when ConPTY is not
available. Without a Windows machine, `make windows-acceptance-compile`
cross-links it and `make t-fast-exact ONLY=mesh_terminal_worker` runs the
platform-neutral path grammar and refusal table.

## Linux-host syntax coverage of `_WIN32` code

`gcc` and `clang` on a POSIX host never take the `_WIN32` branch, so a
Windows-only syntax error or a bad `#include` sits undetected until a Windows
machine hits it. Two gates close different parts of that gap; they are not
substitutes for each other, and neither is a substitute for the native UCRT64
build.

| Gate | What a compiler actually reads | What it does not do |
| --- | --- | --- |
| `make windows-acceptance-compile` | Every active program in the source-derived catalog at `platform/modules/platform/tests/windows_acceptance.mk`; reconciliation requires the active IDs and `_SOURCES` IDs to match exactly | Does not read the rest of the `_WIN32` set or execute a native Windows program |
| `check-windows-cross-syntax` (`make lint`) | Every release-node translation unit listed by `make -s ZCL_TARGET=windows-x86_64 print-node-c23-srcs` | Syntax-only: no objects, archives, link, Wine run, or native observation |

The syntax sweep uses `x86_64-w64-mingw32-gcc -std=c2x -fsyntax-only` and
discovered `include` directories outside the script's explicitly pruned
directories (plus `-I.` and `-Itools`, so `command/native_command.h` is
findable). The file set follows the release build: a translation unit added
to `NODE_C23_SRCS` joins the gate. When MinGW is not installed, the gate
prints `SKIP` and exits 0; that is not a pass. The mandatory
`windows-portability-acceptance`, pre-push, and hosted-CI paths
set `ZCL_REQUIRE_MINGW=1`, so a missing compiler is a hard failure there. The
gate prints its current source, clean, dependency-skip, baseline, and
compiler-infrastructure counts on every run; do not copy those changing counts
into prose. Missing OpenSSL
headers are skipped by header name (`openssl/…`), not by source filename, and
are graded automatically once the vendored headers exist. The adjacent
shrink-only baseline is currently empty: every selected translation unit must
compile, while each documented generated-header skip is counted explicitly in
the verdict. Compiler/backend failure is never baseline-eligible: every worker
publishes an exit-status sidecar, and a crash, missing `cc1`, loader failure, or
nonzero exit without a source-located diagnostic makes the whole sweep
unproven.

## Native-port completion criteria

The UCRT64 lane becomes a supported full-node lane only when all of these are
observed, not merely compiled:

1. GCC and Clang build the node in strict C23 mode from separate clean epochs.
2. The dev worker's executor runs only inside the Windows confinement
   backend, and `devagent_worker_confine` passes natively; every agent
   operation without a Windows backend keeps its refusal.
3. The native dependency audit admits only declared Windows system DLLs.
4. Registered crypto, storage, network, wallet, and recovery groups pass.
5. An isolated datadir reaches RPC-ready state and shuts down cleanly.
6. A persistent Windows service preserves exact binary identity, uses a
   non-repository datadir, restarts after failure, and never exposes secrets in
   command-line arguments.
