<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Receiver-local signed observation lookup

Date: 2026-09-25T04:38:37Z. Compiler: GCC 16.1.1. Host CPU: AMD Ryzen 7 PRO
8840U w/ Radeon 780M Graphics (16 logical CPUs).

## Intention and authority

The local receiver may inspect a bounded set of exact signed test observations
before scheduling duplicate work. The existing `zcl_dev_observation_record`
persists signed verdict leaves in the addressed ZVCS CAS;
`zcl_dev_observation_admit_known` already checks explicit proposed and
receiver-known roots, signatures and eligible PASS/FAIL contradictions. This
change retains that format and adds a receiver-local bounded CAS loader,
freshness checks, receiver-mapped independent trust domains, and exact root
indices in the result. `zcl_dev_observation_lookup_local` performs no network
operation and accepts at most 256 roots and 16 receiver-mapped signer domains.
Its `complete` input is a claim by the authoritative CAS enumerator;
an incomplete enumeration refuses instead of reporting absence. A future
signed checkpoint may establish a stronger completeness boundary.

Each object is loaded from the existing local CAS, parsed, re-rooted and verified against the receiver's local
signer policy. A receiver mapping assigns public keys to trust domains.
Freshness uses the receiver's clock and explicit age and future-skew bounds.
Eligible PASS and FAIL observations for one exact key and group remain visible
as a conflict. Invalid signatures, unmapped signers and stale observations are
counted without becoming eligible verdicts. A missing wire, wrong root, exceeded
bound or incomplete index yields `UNAVAILABLE`.

The existing signed verdict leaf does not carry artifact bytes, policy
generation, full input closure, or action binding. `PASS_EVIDENCE` therefore
cannot authorize work reuse or acceptance by itself. A caller must verify
those missing obligations and bind any reused observation to its own action.
No complete CAS enumerator, network peer query, or acceptance gate is wired
by this change. The existing producer remains responsible for signed leaves.

## Executable counterexamples

The registered `dev_proof_signer` group includes these cases in its isolated
state-root fixture:

| Defect injected | Expected receiver result |
| --- | --- |
| Same key/group, signed PASS and FAIL | `CONFLICT`, both counts retained |
| Omit known FAIL and mark root set incomplete | `UNAVAILABLE` |
| Missing CAS wire or changed signed bytes | `UNAVAILABLE` |
| Locally addressed CAS root absent | `UNAVAILABLE` without peer wait |
| Forged FAIL with a valid recalculated object root | PASS remains evidence; forged FAIL counted invalid |
| Signer mapped outside receiver trust domains | `MISS`, invalid count increments |
| Two signers mapped to one domain when policy requires two | `INSUFFICIENT_DOMAINS` |
| Both observations beyond receiver age bound | `MISS`, stale count increments |

The omitted-FAIL case depends on the CAS enumerator honestly marking an
incomplete root set. A falsely complete index remains an unsolved admission
problem; the per-issuer checkpoint lane is responsible for authenticating
history continuity. An MMR can authenticate that history, not the correctness
of an observation.

## Verification

`make CC=gcc -j2 t-fast ONLY=dev_proof_signer` passed its one selected group,
zero skips, with test body 1,061 ms. The cold build under simultaneous focused
builds spent about 31.6 minutes compiling prerequisite and runner objects.
The exact log SHA-256 is
`4027ffe45b24a00c1fabc585b145775d652977c1137c0593d4c848a2236c258f`.
In that run, 100 two-root signed in-memory lookups consumed 607,810,436 ns
wall and 604,424,000 ns process CPU: 6.08 ms wall and 6.04 ms CPU per lookup.
The post-refactor warm focused rerun passed 1/1 groups with zero skips in 11 s
for the whole command, including 827 ms test body. Its 100 two-root lookups
consumed 429,031,528 ns wall and 427,165,000 ns process CPU: 4.29 ms wall and
4.27 ms CPU per lookup. Exact warm log SHA-256:
`dbe1bbfe81c0e2509b1d81d018004cb21697a40fa18555b114434f04e98b5976`.
These lookup timings exclude CAS disk reads and network and include Ed25519
verification of both leaves on every lookup.

A separate saturated-host run measured 25 lookups through the local CAS wrapper
at 813,588,468 ns wall and 790,764,000 ns process CPU: 32.54 ms wall and
31.63 ms CPU per two-root lookup. The same run measured 100 in-memory lookups
at 3,245,415,331 ns wall and 3,186,645,000 ns CPU: 32.45 ms wall and
31.87 ms CPU each. The host was running concurrent builds; these paired
figures do not isolate a stable CAS disk cost. The registered group passed its
one selected group with zero skips, and the whole focused command took 76 s.
Exact log SHA-256:
`fa4e1b51b6013791c0ac512dffd6066bfd04c4ad7c331bc3f1a3da3620a31185`.

The final refactored source passed the same focused command, 1/1 selected
group with zero skips in 11 s, and passed all 33 `lint-fast` gates. In the
final run, 100 in-memory lookups took 435,557,946 ns wall and 431,197,000 ns
CPU (4.36/4.31 ms per lookup); 25 local CAS lookups took 103,409,155 ns wall
and 102,712,000 ns CPU (4.14/4.11 ms per lookup). These small same-run
differences do not establish that disk access is faster than memory; the CAS
objects were hot and runtime conditions vary. Focused log SHA-256:
`15312944d54a3d5d2cc81a13cbbbc423285ca111b8182af16943ff772a048c30`.
Lint log SHA-256:
`276666beeaedb8e30b473794ed638206f6e14318d5f531ef0019bdbff336ae62`.

A receiver cache keyed by exact observation roots and local policy generation
is a next measured optimization, not an implemented shortcut. This note does
not claim a fleet hit, duplicate job avoided, payload byte saved, or release
qualification.
