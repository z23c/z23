<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Bootstrap plan — not yet a public install path

The intended convenience commands are shown below only to define the target
interface. **Do not publish or use them yet.** The checked-in release pin is
the all-zero sentinel, the front doors refuse, and no public release is cut.

```text
FUTURE, NOT USABLE: curl -fsSL https://z23.sh | sh
FUTURE, NOT USABLE: irm https://z23.sh/install.ps1 | iex
```

The first command will always execute the bytes delivered by the TLS origin
before those bytes can verify anything else. It is therefore a convenience
path for a user who chooses to trust `z23.sh` and its TLS termination. A digest
inside that script, a DNS record under the same domain, or logic implemented by
that script cannot authenticate the first-stage script against a compromised
origin.

A bootstrap described as independently verified must start with an external
anchor: for example, a release-signing public key or exact first-stage digest
obtained outside `z23.sh`. The script must be downloaded, verified against that
anchor, and only then executed. The piped form must never be described as
providing that property.

## What exists

`packaging/release/build_release.sh` packages a `linux-x86_64` runtime and a
`windows-x86_64` runtime. It decides which by reading the object format of the
binary it is handed, not by asking what machine it is running on.
`tools/scripts/install_z23.sh` accepts a local release directory or an HTTP(S)
mirror, requires an independently supplied manifest digest for a remote
mirror, checks the exact closed manifest, verifies every payload, and installs
a systemd user unit. Its remote source is not hardcoded.

`packaging/install/install.sh` and `install.ps1` are fail-closed front-door
scaffolds. Their all-zero baked pin means no release is published. The POSIX
front door recognizes only `linux-x86_64`. The PowerShell front door publishes
no Windows platform and exits before downloading anything, even though a
Windows runtime is now built and packaged: see "Platform work" below for the
three things that stand between built and published.

The three current pin channels are:

1. a value baked into the front-door bytes;
2. a DNS TXT record;
3. a repository file fetched over HTTPS.

They provide consistency and rollout diagnostics after an honestly obtained
front door starts. They are not three cryptographically independent trust
roots. The current judge refuses any valid disagreement, refuses fewer than
two answering channels, and reports unavailable channels. The pin binds the
second-stage installer and one release manifest; it does not authenticate the
already-running front door.

## Release authority to add

Before a public bootstrap is enabled, one externally anchored signature must
bind an immutable platform index. The index must bind, for every supported
platform:

- the exact second-stage installer digest;
- the exact release-manifest digest;
- immutable release identity and expiry or rollback policy; and
- a list of interchangeable transport mirrors.

The current `z23-pin-v1` contains only one manifest digest. It cannot describe
different Linux, macOS, and Windows payload manifests. Do not enable another
platform by changing only a platform table; land and test the platform-index
format first.

DNS, the repository, and the domain may distribute the same signed index.
Their agreement improves availability and exposes partial publication, but the
external signing key is the authority. A mirror supplies bytes only. It cannot
select the release, change the accepted digest, or become trusted because it is
fast or operated by this project.

## Mirror behavior

The second-stage installer already accepts any explicitly selected node or
HTTP(S) mirror. The current front door does not discover the swarm or fail over
between mirrors: unless `Z23_RELEASE_SOURCE` is set, it downloads the runtime
from `z23.sh/release/<platform>`.

The public path must instead consume the signed platform index, try bounded
mirrors in a deterministic or randomized order, and accept the first bytes
that match the indexed manifest. Tests must cover an unavailable primary, a
tampered mirror, successful fallback, and identical installed bytes from two
unrelated mirrors. Peer discovery and mirror selection must not change release
authority.

## Platform work

- **Linux-x86_64:** packaging and the systemd installer exist. Public bootstrap
  remains disabled until the external authority, immutable hosting, and mirror
  acceptance are complete.
- **macOS:** the native node build exists, but there is no accepted release
  package or launchd installer, and no Linux host can produce a Mach-O. Linux
  confinement claims must not be made on macOS. The exact sequence a Mac
  worker runs is below.
- **Windows-x86_64:** a runtime is BUILT and PACKAGED, and still not
  published. `build_release.sh --platform windows-x86_64` produces a real
  x86-64 PE with an exact closed SHA-256 manifest. It has never been executed
  — the host that builds it has no Windows machine and no Wine — there is no
  second-stage PowerShell installer, and no service or scheduled-task
  lifecycle has been accepted. The front door stays a refusal scaffold until
  all three change.

Cross-platform acceptance requires a native package, native service lifecycle,
fresh-host install, restart persistence, exact running-image qualification,
and rollback proof on each platform. A successful build is none of those.

## Building a release for another platform

`packaging/release/build_release.sh` packages `linux-x86_64` and
`windows-x86_64`. Neither is published yet; both are produced from this
checkout and verified by an exact closed SHA256SUMS manifest.

```text
# linux-x86_64 (native)
make vendor && make tor-full
make -j"$(nproc)" z23 zclassic23-package-verify zclassic23-acme
packaging/release/build_release.sh --platform linux-x86_64

# windows-x86_64 (cross-linked on Linux; needs clang >= 20 and the
# mingw-w64 target sysroot, e.g. Debian/Ubuntu's mingw-w64 package)
VENDOR_TARGET=x86_64-w64-mingw32 tools/scripts/build_vendor.sh
make ZCL_TARGET=windows-x86_64 -j"$(nproc)" z23 zclassic23-acme
packaging/release/build_release.sh --platform windows-x86_64
```

The Windows cross build uses clang, not the mingw-w64 gcc: every mingw-w64
gcc Debian and Ubuntu package is GCC 13, which does not accept `-std=c23`,
and the C23 toolchain gate refuses it. clang reaches the same target with
`--target=x86_64-w64-mingw32` over the same sysroot headers, CRT and libgcc.

The Windows release carries three executables, not four. There is no Windows
`zclassic23-package-verify`: that worker compiles and executes downloaded
package code and is safe only because it confines every child with seccomp,
Landlock and POSIX rlimits, none of which exist for it on Windows. The
Makefile refuses to build it there rather than produce an unconfined program
under a name that promises confinement.

The Windows runtime is **built and packaged, not published**. It has never
been executed: this host has no Windows machine and no Wine, so the evidence
stops at "genuine x86-64 PE that links and imports only Windows system DLLs".
`packaging/install/install.ps1` therefore still publishes no platform, and
its second stage (`install_z23.ps1`) does not exist.

## macOS: what a Mac worker has to run

No Linux host can produce a Mach-O for this project. Cross-linking to Darwin
needs the macOS SDK — its headers and `libSystem.tbd` — which Apple does not
permit redistributing, so the SDK can only come off a Mac the operator owns.
This is a licensing wall, not a missing feature, and the packager refuses
Darwin rather than pretend otherwise.

The node itself already builds natively on macOS (see AGENTS.md, "Verified
platform baseline": arm64, macOS 26.0.1, Apple Clang 17). What is missing is
a *packaged release*. A worker on an Apple Silicon Mac can produce one by
running the following, in order.

```bash
# 0. Toolchain and the two build-time tools this repo shells out to.
xcode-select --install        # clang, ld, strip, otool, nm, make
brew install cmake coreutils  # cmake: vendored libsecp256k1-darwin.a
                              # coreutils: sha256sum(1) — see step 4

# 1. Vendor archives for this Mac. Native, not cross: leave VENDOR_TARGET
#    unset. Produces vendor/lib/libsecp256k1-darwin.a among the rest.
make vendor

# 2. The embedded Tor archives. Without them the link silently selects the
#    offline stub and the onion claim is false.
make tor-full

# 3. The node and the workers.
make -j"$(sysctl -n hw.ncpu)" z23 zclassic23-package-verify zclassic23-acme

# 4. Package. THIS STEP DOES NOT WORK YET — see the four edits below.
packaging/release/build_release.sh --platform darwin-arm64
```

Step 4 needs four small edits to `packaging/release/build_release.sh`, each
of which must be **proved on the Mac**, not written blind on Linux:

1. `platform_of_binary()` — it reads `objdump -f`. On macOS that is LLVM's
   objdump and it prints `mach-o arm64` / `mach-o 64-bit x86-64`, not an ELF
   or PE name. Add those two cases (or switch this function to
   `lipo -archs`, which ships with the command line tools). Verify by
   running the function against `build/bin/z23` and against a system binary.
2. `platform_supported()` — add `darwin-arm64` (and `darwin-x86_64` only if
   an Intel Mac actually ran the whole sequence; AGENTS.md records arm64 as
   measured and Intel as unverified).
3. `release_binaries()` — add a `darwin-*` set. It is the same four names as
   Linux with no suffix: `z23 zclassic23 zclassic23-package-verify
   zclassic23-acme`. Note that `zclassic23-package-verify` builds on macOS
   but refuses confined operations at runtime, so decide deliberately whether
   it belongs in a Darwin release rather than copying the Linux set.
4. `platform_strip()` — Apple's `strip(1)` has no `--strip-unneeded`. The
   Makefile already uses `strip -S -x` on Darwin; the packager must use the
   same flags, so the strip invocation needs a per-platform argument list,
   not only a per-platform tool name.

Two further things the Mac worker will hit:

- `tools/scripts/build_vendor.sh` and `build_release.sh` both call
  `sha256sum(1)`, which macOS does not ship. `brew install coreutils` in
  step 0 supplies it. (`shasum -a 256` is the built-in alternative; the
  front-door installer already accepts either, these two scripts do not.)
- `build_release.sh --selftest` uses `stat -c %i` to prove the
  `z23`/`zclassic23` hardlink. BSD `stat` spells that `stat -f %i`.

The Linux-only audits are already correctly skipped: `ci_symbol_floor_gate.sh`
is a glibc-symbol question and runs only for `linux-x86_64`, and
`tools/scripts/check_c23_node_binary.sh` already carries a Mach-O branch that
audits `otool -L` dependencies and weak-undefined symbols.

Nothing about macOS may be added to `PUBLISHED_PLATFORMS` on the strength of
a successful build. Publication needs the release installed on a fresh Mac,
the node started and stopped through its own launchd unit, and the exact
running image qualified — the same bar the "Platform work" list above states.

## Certificates and hosting

The public command also depends on working DNS, HTTPS, and certificate renewal.
Certificate challenge-serving work does not itself prove unattended issuance
or renewal. The accepted deployment must demonstrate initial issuance,
renewal, certificate reload without a node restart, expiry monitoring, and
failover of the small front-door files. Until that acceptance is recorded,
certificate operation remains an operator responsibility.

The four project machines may serve identical immutable files, with faster
machines preferred for transport. No machine is an authority merely because
it serves `z23.sh`. Losing any one mirror must not prevent installation when
another mirror has the exact signed release.

## Working with coding agents

Bootstrap and service setup must be non-interactive and return stable exit
codes. Every refusal must name the protected invariant. The verified
`AGENT_CARD.md` may describe the installed command surface, but fetching or
reading it does not grant deployment, wallet, consensus, or shell authority.

## Publication gate

Keep `packaging/install/RELEASE_PIN` at the all-zero sentinel until all of the
following are true:

1. an external release key and recovery/rotation procedure are documented;
2. the signed platform index and rollback rule are implemented and tested;
3. at least two independent mirrors serve byte-identical immutable artifacts;
4. the enabled platform passes fresh install, restart, qualification, fallback,
   tamper refusal, and rollback acceptance; and
5. the public documentation distinguishes TLS-origin convenience from an
   externally verified bootstrap.

A partial publish must refuse. Publication across DNS, repository, and mirrors
is not atomic, so staged rollout and rollback must be tested rather than
described as a single motion.
