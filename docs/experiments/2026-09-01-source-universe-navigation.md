<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Source-universe navigation parity

## Question

Can a fresh agent obtain one exact maintained C23 file count and descend into
every declared source root without reconciling `code corpus`, `code map`, and
the code-index database manually?

## Baseline

At source `c2931cac2973d1791b52fb9f313681a0fc3d250f`, `code corpus` reported
5,244 maintained C/H files. `code map` reported 5,272 nodes, omitted
`packages` and `examples` as navigable roots, and did not distinguish C/H
files from X-macro registries.

An exact path-set comparison explained the whole disagreement:

- 57 maintained C/H files were absent from the index, including top-level and
  module-local examples and tests.
- 23 C/H fixture files excluded by the governed corpus were indexed.
- 62 `.def` include-graph nodes were included in the map headline.

## Change

`config/source_roots.def` and `config/source_prune_dirs.def` now declare the
root and pruning policy consumed by the POSIX and Windows code-index builders,
the capability inventory, and the science corpus walk. The index scans each
declared root, prunes fixtures, and exposes `src`, `packages`, and `examples`
as direct navigation groups. `code map` reports maintained C23 files separately
from behavior-bearing `.def` registry nodes and refuses count disagreement.

## Result

The rebuilt binary produced these exact observations on 2026-09-01:

- `code corpus`: 5,248 files, 1,811,218 lines, scope agreement true.
- `code map`: 5,248 C23 files plus 100 registry nodes across 11 source roots.
- `code group packages`: found, 319 indexed nodes.
- `code group examples`: found, 12 C23 files, no truncation.
- Warm `code map`: 32 ms against a 750 ms command budget.
- `make t-fast ONLY=codeindex`: one selected group passed.
- `make z23`: C23 node build passed.
- Windows cross-syntax, generated capability-inventory, generated-artifact
  contradiction, and command-input-key gates passed.

The repository-wide capability-closure gate remains independently red on this
host: the complete 2,102-object dev epoch reports 79 unclassified GTK/WebKit
external symbols and two undeclared `wallet_gui.c` capabilities. The same 81
violations were present before and after this slice; no source-universe path
reaches those GUI objects. They remain recorded failures, not inferred
capability classifications.

The C23 count now agrees exactly across corpus, generated inventory, and map.
Registry nodes remain visible for impact analysis without being mislabeled as
C23 files.
