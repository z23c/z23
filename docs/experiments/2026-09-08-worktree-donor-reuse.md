<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Explicit worktree dependency donor

`make worktree-prime SRC=<checkout>` now passes its selected donor to the
embedded dependency readiness helper. Previously only the generic vendor
archives used `SRC`; embedded Tor always selected the primary Git checkout.
A primary without provenance therefore caused a rebuild even when the
explicit donor held a verified bundle.

The helper retains primary-checkout discovery when no donor is specified.
It copies the four archives and their existing provenance record into
independent inodes, then verifies archive hashes and compiler identity using
the existing checker. Missing donor provenance refuses copying. Existing
destination provenance mismatches still refuse repair. Portable copying now
uses the same `cp -p` fallback for the provenance record as for archives.
This change adds no configuration compatibility claim: the readiness check
does not compare the recorded configure-argument digest or destination Git
pin. Those require a separate eligibility change.

## Verification

The existing `tools/scripts/tor_archives_ready.sh --selftest` gained fixtures
for an explicit relative donor beginning with `-`, distinct from the primary,
unchanged primary discovery,
portable copies of all five files, and execution of the actual Make priming
recipe against a recording helper. The explicit-donor fixture failed with
the prior implementation and passed after the change. The expanded selftest
also passed its retained provenance, corruption, and compiler-alias checks.

An actual `link-only` invocation copied the verified archives from
the performance integration worktree into a fresh donor-reuse fixture
checkout. All four archives
and the provenance file matched byte for byte; each destination had link
count one and a different inode from its donor. The successful `link-only`
path performed no Tor configure or archive compilation. Compiler identity
probes and the native provenance checker remain part of verification.

The observed invocation took 18,057 ms on an AMD Ryzen 7 PRO 8840U with GCC
16.1.1 (20260430), on 2026-09-08. This is one loaded-host observation including
submodule initialization and verification, not a latency target or a measured
comparison against rebuilding. Reproduce with an empty initialized recipient
and a same-host verified donor:

```bash
tools/scripts/tor_archives_ready.sh --selftest
tools/scripts/tor_archives_ready.sh link-only /absolute/verified/donor
```

Local observations are retained in `/tmp/z23-explicit-tor-donor-red.log`,
`/tmp/z23-explicit-tor-donor-final.log`, and
`/tmp/z23-explicit-tor-donor-actual.log`; the latter includes archive hashes,
inode identities, compiler version, CPU model, and the ISO-8601 timestamp.
