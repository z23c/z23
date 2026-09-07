# Lint-gate hollowness — the fail-loud-scan-floor pattern

**Systemic risk:** a `make lint` gate that derives its scan set from a
`find` / glob / `grep -rl` / hardcoded list can report **"clean" / exit 0
while a real violation is present** — a *fail-silent* (hollow) gate — if the
scan set silently empties (a renamed symbol/marker/dir, a non-GNU grep, a
moved file) and the loop runs zero times. `set -euo pipefail` does NOT save
a `find`/`grep` inside a `< <(...)` process substitution — its nonzero exit
does not abort the parent shell. A hollow gate is worse than no gate: it
gives false "all green" confidence.

## The fix — `gate_require_scanned` (`tools/lint/gate_lib.sh`)

Every gate whose scan set can silently empty calls
`gate_require_scanned <count> <floor> <gate-name> [hint]` before reporting
clean: it aborts with exit 2 — loud, not silent — when the realized scan
count falls below a known floor. A `gate_grep` wrapper treats `grep` exit
`≥2` (a real error, e.g. a non-GNU grep rejecting a flag) as fatal instead
of swallowing it as "no match."

Gates wired to this pattern: `check_one_write_path.sh`,
`check_no_secret_printf.sh`, `gate_stage_log_reorg_unsafe_ratchet.sh`,
`check_projections_pure.sh`, `check_supervisor_domain.sh`,
`check_supervisor_registration.sh`, `check_stage_advances_or_blocks.sh`,
`check_consensus_parity.sh` (E13), `check_honest_witness.sh` (Law 7),
`check_no_silent_ready.sh` (E8), `check_coins_lookup_nullcheck.sh`.

## Two fix classes for a hollow gate

1. **Conservative preflight (zero-broadening, the default fix):** assert
   the scan target exists and the scan set is non-empty (or meets a known
   floor); check `grep`'s exit explicitly (0=match, 1=no-match, ≥2=error→
   fail) instead of `2>/dev/null || true`. Closes the hole without changing
   what is scanned.
2. **Broaden the surface (higher-risk, needs a clean-tree proof):** e.g. add
   a new directory to a `find` root, or content-discover targets instead of
   a hardcoded list. Broadening can surface grandfathered matches and
   false-positive a clean tree — key on a naming convention or a checked-in
   manifest, not a bare glob, and verify the clean tree stays green before
   shipping.

## Gates deliberately left off this pattern

`check_one_result_type.sh`, `framework_shape_check.sh`,
`check_no_new_repair_rung.sh` — these go
hollow only under a core-directory rename, which coincides with a build
break; CI still catches them red without the loud-preflight pattern. A
conservative "scanned 0 files → exit 2" preflight would still be cheap and
defensive if any of them is touched.

## Dead scan roots — the native (`tools/lint/lintc/`) equivalent

The pattern above is for shell gates walking their scan set through a
`find`/glob pipeline. The native C23 lint runtime's shared recursive walker,
`walk_src()` (`tools/lint/lintc/lib.c`), has the identical hollowness risk
one level down: it returns `0` on `ENOENT` so a directory that vanishes
mid-recursion is not an error — but a gate's own literal, hardcoded TOP-level
root silently going missing (a directory renamed out from under a gate that
still names the old token) reads the exact same way: the loop just runs zero
times and the gate reports "clean".

Found 2026-09-06: a tree rename (`app lib config src domain application
adapters` → `core engine contexts cognition platform tools`) left four
gates scanning nothing but `tools/` and reporting false-clean over roughly
4,000 unscanned production files (`check-malloc`, `check-pthread-create`,
`check-proc-self-shim`, `check-hotswap-dev-only`), plus three more scanning
a degraded subset of the real tree (`check-no-gnu-va-args`,
`check-peer-floor-single-source`, `check-no-stray-untracked-source`). Fixed
by `require_scan_root(gate, root)` / `walk_src_root(gate, root, hdrs, scan,
ctx)` in `lib.c`: FATAL with `FATAL — scan root '<root>' does not exist
(gate <name>)` the moment a gate's literal root is missing, rather than
silently walking nothing. Every gate above was re-rooted onto the real
production C tree (`core engine contexts cognition platform tools`) and now
calls `walk_src_root()` instead of the unchecked `walk_src()`; debt the
wider scan uncovered is pinned shrink-only in a per-gate
`tools/lint/<gate>_baseline.txt`. Callers that already probe an optional or
derived path themselves (`stat()`-check before walking, an env-overridable
test fixture path, a runtime-supplied directory) keep calling `walk_src()`
directly — see each such call site's own comment in `lib.c` and the gate
files.
