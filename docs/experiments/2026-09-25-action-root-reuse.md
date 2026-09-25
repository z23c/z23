<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 -->

# Action-root reuse across real commits, 2026-09-25

Hypothesis: if each compile action has an exact v2 `action_root` that is
derived before the commit exists, most evidence survives a commit. Today's
commit-keyed identity keeps none of it.

Verdict: **supported.** Over the last 30 first-parent commits of `main`,
99.69% of compile-action roots were equal between parent and child. 0.09%
changed and 0.21% were an explicit MISS. For the same pairs, 96.31% of
cacheable test groups kept their existing content-keyed cache key. Under
today's commit-keyed dev proof receipt, 0% of evidence survives any commit.
None of the five seeded edits was reused. All five commit-invariance checks
matched on every rooted action.

These are direct counts from one run. No figure is extrapolated.

## Setup

| Item | Value |
| --- | --- |
| Host | `rhett.dev`, Linux 6.8.0-139-generic x86_64, 32 logical CPUs, shared `devbuild` slot |
| Compiler | `cc (Ubuntu 14.2.0-4ubuntu2~24.04.1) 14.2.0` |
| Study source | branch `evidence/action-root-reuse-study` at `8bef1e41d9` |
| action_root code | v2 preimage/root at `446441d266` (action_root slice 1), called unmodified |
| `main` tip studied | `origin/main` = `1ce8f9620929d647b75892ea3e42aa72d77f9574` |
| Corpus | 31 commits `a2d97c87ce53`..`1ce8f9620929` (30 first-parent pairs) plus 10 picked pairs |
| Study build | `make -j8 dev-bin` in the study worktree (dev epoch `fdd7944c76ff…`), plus the fast test harness |

Git blob hashes of the sources:

| Path | Blob |
| --- | --- |
| `tools/dev/action_root_reuse_study.c` | `b0a41c9a252e6e91057b38eb1d124b27ad84b278` |
| `tools/dev/action_root_reuse_study_eval.c` | `cd116430919e6666e55d6c24d02af6ddf94c3ae4` |
| `tools/dev/action_root_reuse_study_snap.c` | `da403aaf0d8f27f03b024eac2aa65a78e944e626` |
| `tools/dev/action_root_reuse_study.h` | `6924882db0fb281082c22d85b51915469c4e8563` |
| `contexts/commons/modules/vcs/src/build_action_v2.c` | `05674a3980774390be5fa125f65c24b9c2a9cca1` |
| `tools/dev/devloop_action_root.c` | `ce2c03bd77c388c334969d2ab31487b0f7617627` |

Commands, run as one `devbuild` admission:

```sh
devbuild --wait bash hax-batch1.sh    # which runs:
make -j8 dev-bin
make -j8 action-root-reuse-study \
  ACTION_ROOT_STUDY_SCRATCH=$HOME/.local/state/zclassic23/scratch/hax-study
```

Without overrides, the target runs the 30-commit corpus and the 10 picked
pairs named in `ACTION_ROOT_STUDY_PICKS`. It writes `pairs.tsv`,
`snapshots.tsv`, `invariance.tsv`, `adversarial.tsv`, `summary.txt` and
`study.log` under `ACTION_ROOT_STUDY_OUT`. The run took 42 min 24 s of
wall-clock time for the whole make goal, including the test-harness link.
The tool alone took 2,532 s for 61 snapshots, with 8 derivation threads.

## Method

- **Snapshots.** Each commit is extracted with `git archive` and `tar -xpf`
  into scratch outside the repository. Roots are derived only from the
  snapshot's bytes, never from the worktree.
- **Flags.** The compile argv of every dev object is taken from the
  snapshot's own Makefile. The study runs a `make -n` dry run with the
  object command replaced by an argv printer. That gives 2,360 actions per
  current snapshot, one per dev translation unit, including the `-Og` and
  `-O2` hot-directory split.
- **Immutability.** After derivation, `tar -d` must find no difference
  between the extracted tree and the archive. The only exception is uid/gid
  0, which an unprivileged extract cannot reproduce.
- **Two closure protocols.** Every action gets one of the following:
  - **A (build depfile).** The study build's `-MMD` depfile is used only when
    its prerequisite list is identical to the snapshot's own list. Otherwise
    the action is MISS `depfile-stale`.
  - **B (snapshot depfile).** The snapshot's own list, from
    `cc <flags> -E -MMD -o /dev/null`. Full preprocessing is required.
    Dependency-only `-MM` exits 0 when a `<...>` header is missing and simply
    drops that header from the list. The study hit this: a deleted header
    produced a root instead of a MISS until the switch to full
    preprocessing.
- **Derivation.** The request uses stage `c23.compile.dev-object` v1, the
  toolchain capsule root, the compiler's system dirs and sysroot, and the
  process environment, with no linker. Declared outputs are virtualized as
  `@out/object` and `@out/depfile`. The v2 preimage requires a nonzero ABI
  generation. A dev object crosses no load boundary, so the study passes a
  constant `c23_dev_object` v1. That value is identical in every snapshot,
  so it cannot cause or hide a difference.
- **Evidence per pair.** Each action is REUSE (equal roots), CHANGED, MISS
  (with reason) or ADDED. Wherever A and B both rooted, they agreed:
  `a_b_root_disagreements=0` in both sets.
- **Test groups.** The existing test cache is content keyed. After one
  baseline `--cache --cache-probe-only` run, the pair's changed paths are
  probed with `--cache-snapshot --changed-source=...`, 32 paths per run. A
  cacheable group stays unchanged unless the probe names it
  `changed-input-runs-fresh`. A change to the TEST_FAST flags or to the
  harness files would invalidate every group; neither happened in any pair.

## Results: the 30-commit corpus

| Measure | Protocol B (snapshot depfile) | Protocol A (verified build depfile) |
| --- | ---: | ---: |
| Action comparisons | 70,816 | 70,816 |
| Equal root (reusable) | 70,597 (99.69%) | 69,672 (98.38%) |
| Changed root | 67 (0.09%) | 61 (0.09%) |
| MISS | 150 (0.21%) | 1,081 (1.53%) |
| Added (new TU) | 2 | 2 |

MISS by reason, across the pairs:

| Reason | B | A |
| --- | ---: | ---: |
| `depfile-stale` (build list differs from snapshot list) | — | 916 (+1 on the parent side) |
| `derive: dependency named twice` | 120 | 120 |
| `argv-binds-source-identity` (`clientversion.c`) | 30 | 30 |
| `no-build-depfile` (TU absent from the study build) | — | 14 |

| Evidence identity | Share still valid after a commit |
| --- | ---: |
| Commit-keyed dev proof receipt (`tools/dev/dev_proof_receipt.c:396-400` refuses any other commit/base pair with `receipt_commit_or_base_mismatch`) | 0% |
| v2 `action_root`, protocol B | 99.69% of compile actions |
| Existing content-keyed test cache key | 96.31% of cacheable groups (31,463 of 32,670) |

The 0% figure is confirmed from the code. `zcl_dev_proof_receipt_validate`
compares the receipt's `local_commit` and `remote_base` bytes with the
candidate's before it checks anything else. A receipt therefore never
validates for a different commit.

The v2 root closes the `action_root=unavailable` gap for 99.79% of all dev
compile actions in the 31 snapshots (73,021 of 73,176). The remaining 155
are explicit MISS with a reason: 124 `dependency named twice` and 31
`argv-binds-source-identity`. The literal token `action_root=unavailable`
does not occur in the tree at `446441d266` or `1ce8f9620929`. The study
therefore measures the gap as a dev compile action that has no derivable
root.

Pair distribution:
- 21 of 30 pairs changed no compile root. The median is 0 and the maximum
  is 45.
- 21 of 30 pairs invalidated no cacheable test group. The worst pair
  invalidated 533 of 1,089.

### Dominant invalidation cause

- **Changed roots.** All 67 changed roots (100%) first differ in the
  `source` field. No commit changed flags, toolchain or environment for the
  dev profile.
- **Top cause.** A single header, `hotswap/hotswap_service.h`, accounts for
  45 of the 67 (67.2%). It comes from one commit, `1ece915b06cf` (pair
  c17), which also invalidated 533 test groups. Next is
  `vcs/zcode_action_input.h` with 11 actions. The remaining 19 distinct
  inputs account for 1 to 4 actions each.
- **MISS.** The dominant reason is `derive: dependency named twice`: 120 of
  150 (80%). GCC writes the same path twice in `-MMD` output when two
  lookups reach it. For example, `key.c` and `pubkey.c` include
  `<secp256k1.h>`, and `secp256k1_recovery.h`/`secp256k1_ecdh.h` include
  `"secp256k1.h"` again. The two `native_dev_*command.c` units reach
  `dev_activation.h` through two routes. The v2 derivation refuses rather
  than deduplicates. That is fail-closed and safe, but it is a false MISS on
  four TUs per snapshot. Removing repeated identical tokens while keeping
  first-occurrence order would turn these four into roots. That is a change
  for the action_root slice owner, not this lane.

Derivation cost is the wall-clock time per action, measured in microseconds
inside the 8 concurrent worker threads on the shared host:

| Stage | n | Total | p50 | p95 |
| --- | ---: | ---: | ---: | ---: |
| Snapshot preprocess (`-E -MMD`) | 73,176 | 3,786.99 s | 46,219 | 91,861 |
| Root derivation, B | 73,021 | 1,155.62 s | 12,930 | 38,070 |
| Root derivation, A | 72,058 | 1,007.21 s | 11,124 | 35,747 |

Preprocessing, not hashing, dominates. For each current snapshot, the
tool's wall-clock time was about 1 s for the archive and 3 s for the
flag parse. Derivation re-hashes each closure file for every action; no
cross-action memo exists yet.

## Results: picked small edits

| Pick (child) | Edit | B reuse | B changed | B MISS | Test groups invalidated |
| --- | --- | ---: | ---: | ---: | ---: |
| comment `34252340c472` | comment only | 2,346 | 1 | 5 | 3 |
| whitespace `bf79a0782e54` | whitespace only | 2,346 | 1 | 5 | 1 |
| body `c472356ff234` | function body | 2,354 | 1 | 5 | 0 |
| body2 `1f5790fc70f5` | function body | 2,346 | 1 | 5 | 64 |
| header `b3e9c0bddb58` | header | 2,352 | 2 | 5 | 1 |
| header2 `03558ceabb42` | header | 2,338 | 13 | 5 | 72 |
| makeflag `9ae2b83949aa` | coverage-profile CFLAGS | 2,209 | 0 | 5 | 0 |
| makefile `6ae2602c0f84` | Makefile recipe | 2,354 | 0 | 5 | 0 |
| gen-flags `247c32071629` | `flags.def` pointer regen | 2,354 | 0 | 5 | 0 |
| gen-inventory `3922dee99136` | capability inventory regen | 2,355 | 0 | 5 | 0 |

Totals: 23,354 of 23,423 (99.71%) reused, 19 changed, and 50 MISS.

Roots hash exact source bytes, so a comment or whitespace edit changes the
one action that owns the file. Within the last 1,500 first-parent commits
there is no recent edit to the dev-profile CFLAGS. The newest is
`87da148b3b` (2026-09-02). The Makefile-flag pick therefore edits the
coverage profile, and correctly reuses every dev root. The `-D` seed below
covers a dev CFLAGS edit.

In 2 of the 20 picked snapshots the immutability check failed: the makeflag
parent and child, both older trees. Their own Makefile's parse took about
38 s and changed the mode of `vendor/include/sqlite3.h`. That was the first
`tar -d` finding. Every other snapshot, all 31 corpus and 18 of 20 picked,
passed. Read the makeflag row with that caveat.

## Seeded adversarial checks

Each seed mutates the tip snapshot (`1ce8f9620929`, 2,362 actions) and
re-derives the roots. B is the snapshot's own closure. "Forced" reuses the
tip's build-time closure without re-verifying it, to show that stale
closures are refused. PASS means at least one action was affected and
neither protocol reused any affected action.

| Seed | Target | Affected | B changed / MISS / reuse | Forced changed / MISS / reuse | Verdict |
| --- | --- | ---: | ---: | ---: | --- |
| `-D` added to `DEV_CFLAGS` | `Makefile` | 2,362 | 2,357 / 5 / 0 | 2,325 / 37 / 0 | PASS (`flags` field) |
| Header edit | `base/format_attribute.h` (fan-in #1, 68.50%) | 1,618 | 1,614 / 4 / 0 | 1,593 / 25 / 0 | PASS |
| Generated input | CSS rule added to `site.css`, `site_css.h` regenerated | 9 | 9 / 0 / 0 | 9 / 0 / 0 | PASS |
| Incomplete closure | `base/log_level.h` deleted | 1,312 | 0 / 1,312 / 0 | 0 / 1,312 / 0 | PASS |
| Shadowing header | copy placed at `engine/models/include/base/format_attribute.h` | 1,618 | 1,614 / 4 / 0 | 1,593 / 25 / 0 | PASS |

The generated-input seed adds a CSS rule, not a comment. `gen_templates`
minifies comments away, so a comment-only edit leaves `site_css.h`
byte-identical, and reusing it would be correct.

## Commit invariance

For the first five corpus pairs, the study applies the child's diff to the
parent snapshot with `git diff --binary` and `git apply`, leaving it
uncommitted. It then compares that tree's B roots with the committed
child's roots.

| Child | Actions | Rooted | Equal | Differ | Missing |
| --- | ---: | ---: | ---: | ---: | ---: |
| `3922dee99136` | 2,360 | 2,355 | 2,355 | 0 | 0 |
| `77ca95fefcee` | 2,360 | 2,355 | 2,355 | 0 | 0 |
| `d1072d527988` | 2,360 | 2,355 | 2,355 | 0 | 0 |
| `1c13a38b6cdc` | 2,360 | 2,355 | 2,355 | 0 | 0 |
| `a949fdf76ecb` | 2,360 | 2,355 | 2,355 | 0 | 0 |

Roots depend on bytes, not on commit identity. They can therefore be derived
before the commit exists.

## Limits

- Test-group closures come from one code-index generation: the study
  worktree's baseline. The probe does not re-index each snapshot.
- Protocol A uses a single study build of this branch. Its 1.53% MISS rate
  reflects the distance between that build and each historical snapshot.
  A per-commit build would lower it.
- Derivation times come from one run on a shared host, measured under
  concurrent `devbuild` load.
- The study measures whether evidence could be reused. It does not change
  the receipt format or the proof admission path.
