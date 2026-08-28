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

One limit is worth stating plainly, because it decides where the work can
happen rather than whether it works. The vendored third-party archives —
SQLite, OpenSSL, libsecp256k1, zlib, LevelDB, and the Tor stub — build
natively under UCRT64, and that is the only supported way to build them. A
Windows artifact needs a Windows machine; a Linux host cannot stand in for
one.

That is deliberate, and it is more than one line of shell. `build_vendor.sh`
does read `uname -s` rather than the target of the compiler in `VENDOR_CC`,
but changing only that would be the worst possible half-measure: OpenSSL,
zlib, libevent, LevelDB and libsecp256k1 are each configured with no target
at all, `VENDOR_AR` is the host archiver, and there is no `VENDOR_CXX`, so
the script would select Windows behaviour while still building host objects.
The result links, and is mixed-ABI. Underneath that, `vendor/lib` and
`vendor/include` hold one slot per archive name with no target segment, and
`opensslconf.h` and `event2/event-config.h` are generated per target — so two
targets cannot coexist in one checkout even if every recipe were fixed.

Hence the rule already stated below: never reuse `vendor/lib` or `build`
across UCRT64 and WSL. Cross-building would require a per-target vendor
layout, which reaches source identity, the link lines, and the reproduce and
provenance paths. Requiring a Windows box is the cheaper correct answer, and
one is needed to run the acceptance tests regardless.

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

```bash
Z23_CHECKOUT=/c/path/to/your/z23-checkout
cd "$Z23_CHECKOUT"
code .
tools/scripts/doctor.sh
tools/scripts/build_vendor.sh
tools/dev/source-identity-selftest.sh
make -j"$(getconf _NPROCESSORS_ONLN)" z23
make windows-acceptance
```

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
