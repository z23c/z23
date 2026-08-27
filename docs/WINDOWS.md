<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Windows development

Windows development has two explicit lanes. Do not mix their objects or
vendored archives.

| Lane | Purpose | Artifact status |
| --- | --- | --- |
| MSYS2 UCRT64 | Native C23 editing, GCC/Clang diagnostics, and the ongoing Win32 port | Native Windows `.exe`; the full node is not yet linkable |
| WSL2 Ubuntu | Build, test, and operate the complete node today | Linux ELF running under WSL2 |

The UCRT64 bootstrap, source-identity checks, compile-epoch leases, OpenSSL,
SQLite, zlib, libevent, and LevelDB builds are supported. The full native node
currently stops at POSIX APIs that still need platform adapters: signals,
users/groups, sockets, and a small set of filesystem/process calls. The agent
adapter is deliberately unavailable because Windows confinement is not yet
implemented. Never weaken that refusal to obtain a green build.

## Native UCRT64 lane

Install MSYS2 to `C:\msys64`, open **MSYS2 UCRT64**, and run:

```bash
pacman -Syu
# Reopen UCRT64 and repeat pacman -Syu if the runtime closes the shell.
pacman -S --needed base-devel git \
  mingw-w64-ucrt-x86_64-toolchain \
  mingw-w64-ucrt-x86_64-clang \
  mingw-w64-ucrt-x86_64-clang-tools-extra \
  mingw-w64-ucrt-x86_64-cmake \
  mingw-w64-ucrt-x86_64-ninja
```

Keep the checkout on the Windows filesystem, for example
`C:\Users\you\github\z23`, and enter it from UCRT64 as
`/c/Users/you/github/z23`. Do not add `C:\msys64\usr\bin` globally to the
Windows `PATH`; launch the editor from UCRT64 so it inherits
`C:\msys64\ucrt64\bin`.

```bash
cd /c/Users/you/github/z23
code .
tools/scripts/doctor.sh
tools/scripts/build_vendor.sh
tools/dev/source-identity-selftest.sh
```

Use both native compilers for focused C23 work:

```bash
gcc -std=c23 -Wall -Wextra -Wpedantic -pedantic-errors file.c
clang -std=c23 -Wall -Wextra -Wpedantic -pedantic-errors file.c
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
