<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Windows development

Windows development has two explicit lanes. Do not mix their objects or
vendored archives.

| Lane | Purpose | Artifact status |
| --- | --- | --- |
| MSYS2 UCRT64 | Native C23 build, GCC/Clang diagnostics, and the ongoing Win32 port | GCC and Clang build the native `z23.exe`; native runtime acceptance covers the qualified Windows seams |
| WSL2 Ubuntu | Build, test, and operate the complete node today | Linux ELF running under WSL2 |

The UCRT64 bootstrap, source-identity checks, compile-epoch leases, pinned
static C dependencies, and canonical GCC and Clang node builds are supported. The built
binary is a native x86-64 PE named `build/bin/z23.exe`; its release audit
allows only declared Windows system DLLs. Some optional package, snapshot, and
agent operations still refuse where their Windows capability backend is not
qualified. The agent adapter is deliberately unavailable because Windows
confinement is not yet implemented. Never weaken those refusals to obtain a
green build.

Native execution still requires Windows, but producing a Windows artifact no
longer does. A Linux host can build the pinned third-party archives into the
target-qualified `vendor/cross/x86_64-w64-mingw32` tree, then use Clang 20+
against the distro MinGW sysroot to link and audit an x86-64 PE:

```bash
VENDOR_TARGET=x86_64-w64-mingw32 tools/scripts/build_vendor.sh
make ZCL_TARGET=windows-x86_64 -j"$(nproc)" z23 zclassic23-acme
packaging/release/build_release.sh --platform windows-x86_64
```

That is compile, link, PE-import-audit, and package evidence only. It is not a
native Windows runtime observation and cannot close startup, service, or
filesystem semantics. The cross build uses `vendor/cross/<triple>` precisely
so its generated OpenSSL/libevent headers and archives cannot overwrite the
native host slots in `vendor/lib` and `vendor/include`. Native UCRT64 and WSL2
still need separate `build/` and host-vendor trees; move changes between them
through Git, never copied objects.

## Native UCRT64 lane

Install MSYS2 to `C:\msys64`, open **MSYS2 UCRT64**, and run:

```bash
pacman -Syu
# Reopen UCRT64 and repeat pacman -Syu if the runtime closes the shell.
pacman -S --needed base-devel git \
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

The tracked pre-push hook re-enters the UCRT64 shell once when Git launches it
from a minimal MINGW/MSYS environment, then runs `make windows-acceptance` by
default. Linux and macOS retain `make pre-push-ci`. An explicit
`ZCL_PREPUSH_CMD` override still receives the exact semantic changed-file list,
so changing the platform gate cannot turn a range-aware push into a whole-tree
guess.

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

WSL must have systemd enabled. Install the tracked user service only after the
Linux build and focused tests pass:

```bash
cd "$HOME/src/z23"
sudo bash deploy/setup.sh
systemctl --user enable --now zclassic23.service
systemctl --user status zclassic23.service
```

Use `systemctl --user stop zclassic23.service` before changing its binary or
datadir. Operator flags belong in `~/.config/zclassic23/env`; private keys,
cookies, datadirs, and credentials never belong in either checkout.

WSL distributions do not necessarily start merely because Windows booted.
If boot-without-login is required, create one Windows Task Scheduler entry,
as the owning Windows user, that runs:

```text
wsl.exe -d Ubuntu -- systemctl --user start zclassic23.service
```

Use “At log on” unless unattended pre-login operation is an explicit operator
requirement. Do not store RPC credentials in the task arguments.

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

## Linux-host syntax coverage of `_WIN32` code

`gcc` and `clang` on a POSIX host never take the `_WIN32` branch, so a
Windows-only syntax error or a bad `#include` sits undetected until a Windows
machine hits it. Two gates close different parts of that gap; they are not
substitutes for each other, and neither is a substitute for the native UCRT64
build.

| Gate | What a compiler actually reads | What it does not do |
| --- | --- | --- |
| `make windows-acceptance-compile` | Every active program in `lib/platform/tests/windows_acceptance.mk`; the reconcile gate requires the active IDs and `_SOURCES` IDs to match exactly | Does not read the rest of the `_WIN32` set or execute a native Windows program |
| `check-windows-cross-syntax` (`make lint`) | Every `.c` containing `_WIN32` under `adapters/`, `app/`, `application/`, `config/`, `core/`, `domain/`, `lib/`, `ports/`, `src/`, and release-visible `tools/command/` | Syntax-only: no objects, archives, link, Wine run, or native observation |

The syntax sweep uses `x86_64-w64-mingw32-gcc -std=c2x -fsyntax-only` and
every directory named `include` (plus `-I.` and `-Itools`, so
`command/native_command.h` is findable). The file set is self-maintaining: a
file that gains Windows code joins the gate. When mingw is not installed the
gate prints `SKIP` and exits 0; that is not a pass. The mandatory
`windows-portability-acceptance`, Linux/macOS pre-push, and hosted-CI paths
set `ZCL_REQUIRE_MINGW=1`, so a missing compiler is a hard failure there. The
current ratchet baseline is empty: every selected translation unit must
compile, and any documented generated-header skip is counted explicitly in
the verdict rather than hidden behind a remembered file total.

## Native-port completion criteria

The UCRT64 lane becomes a supported full-node lane only when all of these are
observed, not merely compiled:

1. GCC and Clang build the node in strict C23 mode from separate clean epochs.
2. The agent adapter remains unavailable until a reviewed Windows confinement
   backend exists.
3. The native dependency audit admits only declared Windows system DLLs.
4. Registered crypto, storage, network, wallet, and recovery groups pass.
5. An isolated datadir reaches RPC-ready state and shuts down cleanly.
6. A persistent Windows service preserves exact binary identity, uses a
   non-repository datadir, restarts after failure, and never exposes secrets in
   command-line arguments.
