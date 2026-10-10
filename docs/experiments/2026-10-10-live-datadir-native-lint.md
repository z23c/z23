<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Native live-datadir isolation lint

The existing Makefile gate now uses the C23 lint runtime through its shell
compatibility entrypoint. The three source checks retain scan floors, per-file
counts, ceiling overrides, baseline comments, and FAIL/WARN/UPDATE modes.
The shared macro-argument splitter was extracted unchanged from the
blocker-remedy gate; its original caller delegates to that helper.

## Source and environment

Base: `a2da5f6d54b1cab870bb6129f3c5c4870e45fa80`.
Measured on 2026-10-10T06:57:08+00:00 (UTC), x86-64 Linux, AMD Ryzen 9 7950X3D,
GCC 14.2.0. Compilation used C23, `-O2 -Wall -Wextra -Werror -pedantic`;
the Makefile also performed its Clang syntax checks. Jobs used installed
`devbuild --wait --class normal` admission on a shared host.

SHA-256 of the measured native gate:
`0a6d705d7e3a95ed8b1f1497ebbdedc5354e8b4d517b6a8663c5c1bc1cb9c568`.
Selftest:
`30d56ab05d675eb2a0bd86ce54863b421b3629e1ffa8d21a984d92e302f196ff`.
The nine-file source manifest digest is
`32127f7520071f9590aee7e2815adf9df2802ebde9fdbc644565fdc7a9dc230e`;
timing CSV digest is
`306846f73e5fda187dd3d3e90563530124e5d9b80f98885e5d2204912f210685`.
The worker retains the versioned source manifests, logs, fixture preimages,
status/output comparisons, environment and raw timing CSV in its handoff.
These measurements preceded addition of this evidence document.

## Qualification

Strict compilation, complexity, long-function, lint wiring, architecture,
26 native fixtures, three production isolation-adapter observations, the
blocker-remedy selftest, and the real Makefile caller passed. Normal-tree
stdout/status matched the base shell gate: 1375 test files, 1191 docs/scripts,
173 datadir-taking leaves, eight prong-A sites and 13 prong-C sites.
Twenty-three matched fixture cases passed stdout/status and baseline-byte
comparisons, including UPDATE comment preservation, aliases, floors,
ceilings, staleness, WARN and multiple findings.

Registered `make_lint_gates` qualification: PASS through the canonical
`t-fast-exact ONLY=make_lint_gates` runner.

The initial V2 comparison exposed a shell defect with exactly one test file:
`grep -n` omits the filename, so A records a line number as its baseline key.
The native gate deliberately records the actual filename. Its single-file
baseline fixture proves this correction. Matched parity uses two test files,
one clean. Unreadable inputs also fail closed instead of disappearing from
the old shortlist. Universal byte parity for these corrected cases is not
claimed. V3 stopped on six new complexity violations; phase extraction fixed
them without changing or increasing any baseline. V4 passed the early gates.

## Scan cost

Three alternating parent/candidate rounds used identical roots on the shared
host. CPU is user plus system time; RSS is the timing tool's reported maximum.

| Round | Shell wall s | Native wall s | Shell CPU s | Native CPU s | Shell RSS KiB | Native RSS KiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 23.59 | 6.45 | 22.64 | 6.41 | 7424 | 7680 |
| 2 | 20.89 | 7.00 | 20.44 | 6.95 | 7680 | 7168 |
| 3 | 23.73 | 10.31 | 22.70 | 10.07 | 8756 | 7680 |

Median tree wall time was 23.59 versus 7.00 seconds, approximately 3.37 times
faster in this sample. RSS improvement is not established. Tiny fixture
native timings included 0.00 seconds at the timer's resolution; no ratio is
claimed for them. The first cold build prepared vendor dependencies; that
cost was not separately timed and is excluded from scan measurements.
Review, repair, builds and LLM input cost are not included in these scan
ratios. This experiment establishes no fourfold accepted-task or LLM-input
productivity gain and no cross-platform performance result.

## Integration repair

The first native integration attempt against `39c3fdd9` failed before
publication: two selftest string literals violated the bare-temp fixture
gate, and the flag registry could not observe five indirect environment
reads or resolve ten first-use pointers left at the retired shell reads.
The repair uses a constant fixture path outside the system temporary root,
creates actual scratch beneath `TMPDIR` or checkout-owned `test-tmp`, and
passes five literal environment reads into the existing numeric validation.
All ten registry pointers now identify their actual native reads. No scan
floor, ceiling, baseline, assertion or flag default changed.

The initial repair exceeded the complexity cap at M17; extracting scratch
setup into a separate helper closed that refusal. The corrected repair
passed complexity, bare-temp fixtures, flag registry, the native gate and
its selftest, and the registered `make_lint_gates` group. One group ran,
with zero failures, self-skips or unobserved requirements; suite wall time
was 1.9 seconds. The complete qualification log SHA256 is
`2a963d15c1e52e2e3761279a707c3bc84adc652797f1f0743a02f50df774d476`.
This repair acceptance is separate from current-base publication proof.
