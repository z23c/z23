# Muse vs GLM as executors on one lint-gate task (2026-09-03)

Two headless coding agents (Meta Muse, model muse-spark-1.3-contributor, and GLM-5.3 via opencode) received the identical prompt in identical worktrees from the same base commit: write the lint gate that stops an unguarded `main()` in a Windows acceptance TU from breaking the Linux test link (the regression that hit main that morning). A separate verifier ran both results through the same checks.

| | Muse (A) | GLM (B) |
|---|---|---|
| Wall time | ~20 min (out-file mtime 08:14 -> last commit 08:33:56) | 22m19s (board: started 08:14:22Z, finished 08:36:41Z) |
| Executor rc | commits present, no explicit rc token in muse_ab2.out (only 4 header lines, unlike muse_ab1.out) | rc=0 DONE (explicit trailer in oc_ab2glm.out) |
| Commits | 2 (gate + block_swarm fix) | 2 (block_swarm fix + gate) |
| Trailer | `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` exact match, both commits | same, exact match, both commits |

## Comparison table

| Check | Muse (A) | GLM (B) |
|---|---|---|
| Diffstat | Makefile +18, DEFENSIVE_CODING.md +2, gate script 387 lines, run_lint.sh +1, CAPABILITY_INVENTORY regen | Makefile +19, DEFENSIVE_CODING.md +2, gate script 420 lines, run_lint.sh +1, CAPABILITY_INVENTORY regen |
| Gate run (bare) | `clean — 35 file(s) scanned (35 guarded main, 0 main-free), floor 8`, rc=0 | `clean — 35 file(s) scanned...`, rc=0 |
| `--self-test` | 5/5 PASS: green, unguarded-main red, no-tail red, green-again, floor(exit2) | 7/7 PASS: green(real catalog), unguarded-main red (names file+line), green-again, no-tail red, undeclared-glob-stray red, no-main green, floor(exit2) — more scenarios, including the undeclared-stray-glob case A's self-test never exercises |
| `run_lint.sh check-windows-acceptance-guard` | PASS, 1155ms | PASS, 1268ms |
| `check_doc_accuracy.sh` | clean, 193 gates | clean, 193 gates |
| `make lint-fast` | OK, 27 gates, wall 13.6s (this gate 2272ms) | OK, 27 gates, wall 10.5s (this gate 1585ms) |
| Wiring (Makefile/run_lint.sh/DEFENSIVE_CODING.md) | all 3 present, correct rows | all 3 present, correct rows, doc-table prose slightly more precise/detailed (spells out the placeholder-typedef requirement and the fail-closed exit-2 cases explicitly) |
| Floor present & correct (8) | Yes, `SCAN_FLOOR=8`, enforced via `gate_require_scanned` | Yes, `SCAN_FLOOR=8`, enforced via `gate_require_scanned` |
| Partial-scan fail-closed | Missing catalog rows are folded into the ordinary offender loop and reported as exit-1 violations (`"listed in ... but missing on disk"`) rather than a distinct UNPROVEN state; a genuinely thin *count* still exits 2 via `gate_require_scanned` | Explicit UNPROVEN (exit 2) branch for: missing catalog file, catalog naming zero tests/ sources, and any catalog row naming a file absent on disk — separate from ordinary offender reporting (exit 1) |
| Handles `.mk`-listed sources + glob | Union of glob + catalog_tests_sources(), same awk parse shape | Union of glob + catalog_tests_sources(), same awk parse shape, functionally identical |
| POSIX/bash consistency with neighbours | `set -uo pipefail` (no `-e`); inline hand-rolled comment/string stripper duplicated in-script (not reusing `strip_c_comments.awk`, which exists on main) | `set -euo pipefail` (matches most other check_*.sh gates); reuses the shared `tools/lint/strip_c_comments.awk` rather than re-implementing comment stripping — better reuse/consistency with the codebase's "one shared stripper" doctrine (see de043e046/df99f3293 on main) |
| `/tmp`, python, jq, perl | none used; fixtures under `$HOME/.local/state/zclassic23/scratch` | none used; fixtures under `$HOME/.local/state/zclassic23/scratch` (also respects an override env var `ZCL_WINDOWS_ACCEPTANCE_GUARD_SCRATCH`) |
| False-positive risk: matches `main(` in comments | Explicit `code_lines()` comment/string stripper before the `main(` grep — comment mentions of "main" do not trigger | Uses `strip_c_comments.awk` for the same purpose — same protection, via the shared helper |
| Quoting bugs found | None found in review or mutation testing | None found in review or mutation testing |
| `clean` line reports count | Yes: `"...N file(s) scanned (N guarded main, N main-free), floor N"` — reports a main/no-main split | Yes: `"...N file(s) scanned; every ... TU opens with ... or defines no main()"` — reports just the total, no main/no-main split |
| Mutation (a) remove guard from `workpool_windows_acceptance.c` | rc=1, names `tests/harness/src/workpool_windows_acceptance.c:4: defines main() but first code line is not #if defined(_WIN32) (got: #include)` | rc=1, names `tests/harness/src/workpool_windows_acceptance.c:4:defines main() but the first non-comment line is not '#if defined(_WIN32)' (it is: #include "util/workpool.h")` |
| Mutation (b) move 5/8 glob files out, 3 remain | rc=1 (not the dedicated floor path — union scan set still includes the 5 catalog-declared names as "missing on disk", each reported as an offender, one line each) — gate correctly refuses to pass, but classifies the case as ordinary violations rather than an UNPROVEN/floor signal | rc=2, `UNPROVEN — catalog rows naming files not on disk:` lists all 5 by path — a distinct, more semantically correct fail-closed classification separate from real guard-shape violations |
| Mutation (c) new unguarded `zz_probe_windows_acceptance.c` | rc=1, names `tests/harness/src/zz_probe_windows_acceptance.c:2: defines main() but first code line is not #if defined(_WIN32) (got: int main(void){return 0;})` | rc=1, names `tests/harness/src/zz_probe_windows_acceptance.c:2:defines main() but the first non-comment line is not '#if defined(_WIN32)' (it is: int main(void){return 0;})` |
| Out-of-scope changes | None beyond the fix commit needed for its own gate to score clean (block_swarm_scale guard, matches sibling idiom, matches what origin/main independently did) | None beyond the fix commit needed for its own gate to score clean (block_swarm_scale guard, matches sibling idiom, matches what origin/main independently did); GLM's own honest-process note in its transcript records it also caught and fixed a `printf | grep -q` pipefail bug in its own self-test before committing (folded into the same commit, not a separate defect left behind) |

## Defects per executor

Muse (A):
- The `--self-test` covers only 5 of the shape's failure modes; it never exercises the "undeclared stray file caught by the glob alone" case that B tests explicitly (case 5 in B), even though A's `check_root` does scan the glob independently of the catalog — so the behavior is presumably correct but is unproven by A's own self-test.
- Re-implements a comment/string stripper inline (`code_lines()`) instead of reusing the repo's existing shared `tools/lint/strip_c_comments.awk`, duplicating logic the codebase has already consolidated once (main's de043e046/df99f3293 moved gates onto one shared stripper for exactly this reason).
- Collapses "catalog names a file that isn't on disk" into the same exit-1 offender path as a genuine guard-shape violation, rather than a distinct fail-closed UNPROVEN state — weaker signal to an operator diagnosing *why* the gate went red (missing file vs. bad guard shape look identical in the output).
- `muse_ab2.out` transcript has no explicit rc/wall-time marker (only 4 header lines), unlike the sibling `muse_ab1.out`; wall time here had to be inferred from file mtime vs. commit timestamp rather than read directly.

GLM (B):
- Doc-table `clean` message and gate's own `clean` message omit the main/no-main split that A's clean line reports; slightly less information density in the summary line (minor).
- Otherwise no defects found in static review or the 3 mutation tests.

## Verdict

Both gates are correct, both pass every check in this comparison (self-test,
run_lint.sh, doc-accuracy, lint-fast, and all three mutation tests), and
both are wired into lint-fast/Makefile/DEFENSIVE_CODING.md identically. GLM's
(B) implementation should land: it reuses the repo's existing shared
comment-stripper (`strip_c_comments.awk`) instead of re-implementing that
logic inline, matches the majority `set -euo pipefail` convention used by
neighbouring `check_*.sh` gates, gives partial/degraded scans (a catalog row
naming a file that's missing on disk) a distinct exit-2 UNPROVEN
classification separate from real guard-shape violations — a stronger,
more diagnosable fail-closed contract that matches this repo's stated
doctrine ("a broken glob must not read as nothing to check") — and its
7-case self-test additionally proves the undeclared-glob-stray path that
Muse's 5-case self-test leaves unexercised. Muse's version is not wrong and
is ~33 lines shorter, and its `clean` line's main/no-main split is a small
nicety worth carrying over if merging; but on correctness classification,
code reuse, and self-test coverage, B is the stronger patch to land as-is.
