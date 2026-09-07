#!/usr/bin/env bash
# Lint gate #12 — long functions (god-function ratchet).
#
# Long functions are hard to reason about, hard to test, and a sign that a
# single C function is doing too many things. This gate flags any function
# whose body (signature line through its closing brace) spans more than
# LIMIT lines.
#
# Two tiers, same mechanics, different consequence (E1's file-size gate
# dropped its own tier split in 2026-08; this one keeps it):
#
#   ENFORCED (fails the build) — engine/controllers/src/*.c,
#   engine/services/src/*.c, and engine/composition/src/*.c (the composition root — same
#   tier engine/composition/src/*.c sits in for E1). RATCHET-mode: grandfathered
#   offenders (e.g. engine/composition/src/boot.c's app_init, a pre-existing
#   single-function boot sequence) are recorded in
#   tools/scripts/check_long_functions_baseline.txt at their current length
#   so the gate stays green on today's tree; new/grown functions fail.
#
#   WARN (prints, never fails) — lib/**/*.c, excluding tests/harness/include/test/ (fixtures
#   and test registrations, legitimately long and not a "god function"
#   signal). lib/ is primitives, not the app-shape surfaces this gate was
#   written to police, so a violation here is a heads-up, not a build
#   break. Baseline: tools/scripts/check_long_functions_lib_baseline.txt.
#
# Baseline format (both tiers): '<path> <function-name> <max-lines>' per
# line, lines starting with # are comments. A tier's gate flags when:
#   - a function NOT in that tier's baseline exceeds LIMIT lines, OR
#   - a baselined function grows ABOVE its recorded max-lines.
# Shrinking a baselined function below LIMIT lets you delete its baseline
# line; shrinking it while still over LIMIT earns an auto-suggestion to
# tighten (lower) the recorded number. The ENFORCED baseline is shrink-only
# — raising an existing entry needs an ADR, not this gate.
#
# Override (either tier): add `// long-function-ok:<tag>` to the function's
# signature line if a single state-machine truly belongs as one function.
# The tag must explain WHY. A tagged function is exempt entirely — no
# baseline entry needed, and it is invisible to the growth ratchet.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-long-functions "$@"
