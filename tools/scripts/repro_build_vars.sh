# tools/scripts/repro_build_vars.sh — shared reproducible-build flag profile.
#
# Sourced (NOT executed) by:
#   tools/release.sh                       — the release archive builder
#   check-reproducible-build gate (z23-lint) — the build-twice byte-identity gate
#
# Centralizing the determinism flags here means the release artifact and the
# reproducibility gate CANNOT drift apart: the gate proves the EXACT flag set a
# release uses, not an approximation of it.
#
# Sourcing this file exports three variables:
#   SOURCE_DATE_EPOCH  — pinned to the HEAD commit time (or caller-overridden),
#                        so every embedded timestamp + staged-file mtime is
#                        fixed across machines and across two builds.
#   REL_CFLAGS         — make's RESOLVED CFLAGS (every -I include path kept
#                        intact) with -march=native rewritten to the portable
#                        -march=x86-64-v3 baseline.
#   REL_LDFLAGS        — make's RESOLVED LDFLAGS with -Wl,--build-id=none
#                        appended so two links of the same source drop the
#                        nondeterministic build-id.
#
# Why rewrite -march instead of trusting the Makefile default: the Makefile DEV
# default already targets x86-64-v3 when ZCL_NATIVE is unset, BUT a host that
# exports ZCL_NATIVE=1 flips dev builds to -march=native (machine-specific). A
# release must be byte-stable across machines, so the release config ALWAYS
# forces the portable v3 baseline regardless of the dev setting. This is the
# same contract release.sh has always enforced; it now lives here once.
#
# CONTRACT: the caller has already cd'd into REPO_ROOT and `make`/`git` are on
# PATH. The helper defines no logging — callers print their own "info" lines.

# Resolve one Make variable to its fully-expanded value.  `make -pn` prints a
# recursively-expanded variable's definition, not its resolved value; parsing
# that database used to leave literal `$(REPRO_CFLAGS)` / `$(HARDEN_CFLAGS)`
# expressions in the release evidence.  Ask Make itself to expand the value at
# recipe-execution time and write it through GNU Make's `file` function.  The
# shell never evals or re-quotes compiler flags.
_repro_make_var() {
    local name="$1" capture
    capture="$(mktemp "${TMPDIR:-/tmp}/zcl-repro-make-var.XXXXXX")"
    if ! ZCL_REPRO_CAPTURE_NAME="$name" ZCL_REPRO_CAPTURE_PATH="$capture" \
            make -s --no-print-directory \
            --eval '.PHONY: __zcl_repro_capture' \
            --eval '__zcl_repro_capture: ; @$(file >$(ZCL_REPRO_CAPTURE_PATH),$($(ZCL_REPRO_CAPTURE_NAME)))true' \
            __zcl_repro_capture >/dev/null; then
        rm -f "$capture"
        return 1
    fi
    cat "$capture"
    rm -f "$capture"
}

# SOURCE_DATE_EPOCH: pin from the HEAD commit time. Allow a caller to override
# (e.g. the check-reproducible-build gate may pin to a literal constant for a stricter
# two-build test). The two-build gate sets this ONCE before sourcing so both
# builds share the identical value.
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}"
export SOURCE_DATE_EPOCH

# CFLAGS: resolved, then force the portable ISA baseline (drop -march=native).
REL_CFLAGS="$(_repro_make_var CFLAGS | sed 's/-march=native/-march=x86-64-v3/g')"
# LDFLAGS: resolved, then drop the nondeterministic linker build-id.
REL_LDFLAGS="$(_repro_make_var LDFLAGS) -Wl,--build-id=none"
export REL_CFLAGS REL_LDFLAGS
