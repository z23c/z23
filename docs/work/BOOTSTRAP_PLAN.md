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

`packaging/release/build_release.sh` packages a Linux-x86_64 runtime.
`tools/scripts/install_z23.sh` accepts a local release directory or an HTTP(S)
mirror, requires an independently supplied manifest digest for a remote
mirror, checks the exact closed manifest, verifies every payload, and installs
a systemd user unit. Its remote source is not hardcoded.

`packaging/install/install.sh` and `install.ps1` are fail-closed front-door
shims. Each is roughly thirty lines and makes exactly one decision: it names
the machine, fetches the one C23 bootstrap binary published for it, checks its
SHA-256 against a digest baked into the shim, and runs it with every argument
forwarded. Their all-zero baked digest is the sentinel that means no bootstrap
is published, and both refuse on it before touching a network. The PowerShell
shim additionally has no Windows row at all.

Every other front-door decision — the three pin channels, the agreement rule,
the platform refusal, the second-stage installer verification and the handoff —
lives in `tools/install/z23_bootstrap.c` over the pure `lib/install` library,
written once for every platform and executed only after a digest check. This
matters because a shim served at the domain is executing before anything has
been verified, so logic inside it is logic a compromised origin replaces for
free; the shim's remaining surface is one hash comparison. The judgement is
proved by the `z23_front_door` test group and driven end to end against the
real binary by `packaging/install/install_selftest.sh`.

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
  package or launchd installer. Linux confinement claims must not be made on
  macOS.
- **Windows:** the front door is a refusal scaffold. There is no published
  Windows runtime, second-stage PowerShell installer, or accepted service or
  scheduled-task lifecycle.

Cross-platform acceptance requires a native package, native service lifecycle,
fresh-host install, restart persistence, exact running-image qualification,
and rollback proof on each platform.

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
