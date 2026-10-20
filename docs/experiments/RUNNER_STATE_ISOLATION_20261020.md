<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Registered runner state isolation

Measured on 2026-10-20, Linux 6.8.0-142-generic, AMD Ryzen 9 7950X3D,
Installed Clang 18.1.3 was observed; the compiler used by the focused build was not independently established from its quiet logs. Source base: d8a56965b063878a519328f1d79a953e48b3d8a2.
The complete three-file source patch before this document has SHA256
8ccb3503b32f6fd7c8073c9fb6f01fd2b4536a1191d7cfcaa03fdf45fc2e80f1.

## Contract

The registered runner creates a fresh owner-private absolute state directory
under test-tmp before each group attempt. It replaces XDG_STATE_HOME and,
on Windows, ZCL_STATE_ROOT before group initialization, while preserving HOME.
Fork-role descendants inherit the attempt state. This confines the default
native state resolver; it is not a sandbox against tests that explicitly
replace environment variables or address other paths.

<!-- claim: symbol-present child_state_create tests/harness/src/test_parallel.c -->
<!-- claim: symbol-present child_dispatch tests/harness/src/test_parallel.c -->
<!-- claim: symbol-present test_runner_private_state tests/harness/src/test_test_group_selector.c -->

Every attempt root is retained and its locator printed, including before
retry accounting resets. The existing test-tmp fixture model requires explicit
retirement after evidence review; no automatic success cleanup is claimed.

## Observations

Canonical complexity initially detected main growing from 185 to 189. Extracting
the existing Windows dispatch measured 180; the baseline was lowered from 185
to 180 without changing the cap. The final gate passed 86,796 functions across
5,213 files, with 3,888 exact baseline pins at cap 15.

The confined RED mutation bypassed state activation only in explicitly selected
recursive probe children. Their HOME and inherited platform state roots were
private sentinel fixtures. The outer runner remained isolated. A real probe
file appeared in the controlled caller-state directory outside its assigned
attempt root. The selector then failed its nested-command success assertion.
The precise later unset-XDG return branch is source-inferred: the nested probe
returned failure without an explicit reason diagnostic. This was not an
unknown-option failure. One cold group failed, with zero skips, unobserved
results or automatic retries. Body 57.1 s; command 75.87 s. The outer runner
advertised 28 workers but selected one exclusive group.

GREEN ran selector, SQLite and boot-phase groups cold with two workers:
three ran, zero failures, skips, unobserved results or load-flaky retries.
Both private-state controls passed, including retained first-attempt file
readback; the existing fork-role recovery groups passed. Body 76.4 s;
command 89.80 s. Both jobs used compact admission: CPU quota 2, three reserved
CPU tokens, 2 GiB RAM and one I/O token. RED/GREEN time-reported maximum child
RSS was 600736/124644 KiB, respectively; these are not aggregate cgroup peaks.
Both reported zero swap. Admission wait was 17.706756/13.558898 ms.

Windows runtime, forced automatic-retry behavior and simultaneous overlap of
the two probe groups remain NOTRUN. Full qualification and landing are separate.

## Reproduction and retained evidence

Run through the host admission rail:

```sh
make check-cyclomatic-complexity
make t-fast-exact ONLY=test_group_selector,sqlite,boot_phase \
  T_FAST_EXACT_ARGS='--no-cache --jobs=2'
```

Retained logs have these SHA256 digests:

| Log | SHA256 |
|---|---|
| complexity-final.log | f26051a7ca1a8087bf2dab24c414cf9223df27038552b3c0fe1f86bb33236895 |
| red.log | 5e7b79257c88cbf681f57083012dfcbee559adea4da43067e2fd40dc5dd7f402 |
| green.log | 018b6ad5318a43ee800c9be4046c050336cd9eaeb865146ff710e1e99c7ebe90 |

The exact RED mutation SHA256 is
077499a4f5c59634918029d5e88a3a970f8fbbbd6ce17d3a162c63a1d2a37e9e.
The misplaced probe file SHA256 is
fa05903880e77a24cc1bd5797088ccdbff8a99ce8d764a3f296f87a3621f9e74.
