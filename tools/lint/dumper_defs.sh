# shellcheck shell=bash
#
# The dumpstate descriptor set: the aggregator plus every per-domain .def it
# includes.
#
# WHY THIS EXISTS. `diagnostics_dumpers.def` used to hold all 151 DIAG_* rows
# directly, and three independent consumers hardcoded that one path and grepped
# its contents: check_sandbox_wired (is there a `confinement` row?),
# check_doc_counts (how many subsystems are there?), and the native-API contract
# test (does the manifest declare DIAG_ENTRY / DIAG_PROJECTION rows?). The day
# the file became a pure aggregator, all three still found the file, still read
# it happily, and all three silently stopped seeing any rows at all. Two would
# have reported a wrong number; one would have reported a real contract as
# broken. That is the same going-blind failure mode as a gate whose regex stops
# matching: the check keeps running and stops checking.
#
# So the resolution lives in ONE place. A consumer asks for the file set and
# gets the aggregator plus its includes, in include order.
#
# The include list is parsed from the aggregator rather than globbed from the
# directory ON PURPOSE. A domain file that exists but is not #included is not
# compiled into g_dumpers[] either, so it must not count toward any gate's view
# of reality — globbing would credit rows the binary never sees.

DUMPER_DEF_AGGREGATOR="engine/controllers/include/controllers/diagnostics_dumpers.def"

# Minimum number of per-domain includes expected under the aggregator. This is
# an anti-hollowness floor, not a target: it exists so that a consumer which
# resolves zero includes fails loudly instead of reporting a confident zero.
# Shrink-only — lower it deliberately if domains are genuinely merged.
DUMPER_DEF_MIN_INCLUDES=8

# dumper_def_files <out-array-name>
#
# Fills the named array with the aggregator followed by each per-domain .def it
# includes. Returns 1 (and explains on stderr) if the aggregator is missing or
# resolves to fewer than DUMPER_DEF_MIN_INCLUDES domain files, so a caller that
# checks the status can never proceed on a hollow set.
dumper_def_files() {
    local -n _out="$1"
    _out=()

    if [[ ! -f "$DUMPER_DEF_AGGREGATOR" ]]; then
        echo "dumper_defs: missing $DUMPER_DEF_AGGREGATOR (run from repo root)" >&2
        return 1
    fi

    _out+=("$DUMPER_DEF_AGGREGATOR")

    local rel match_count
    while IFS= read -r rel; do
        [[ -n "$rel" ]] || continue
        mapfile -t matches < <(git ls-files -- \
            "engine/controllers/include/controllers/$rel" \
            "cognition/controllers/include/controllers/$rel" \
            "contexts/*/controllers/include/controllers/$rel")
        match_count="${#matches[@]}"
        if (( match_count != 1 )); then
            echo "dumper_defs: $DUMPER_DEF_AGGREGATOR includes '$rel' but the feature-first controller rooms resolve $match_count owners" >&2
            return 1
        fi
        _out+=("${matches[0]}")
    done < <(sed -nE 's|^[[:space:]]*#include[[:space:]]+"controllers/(diagnostics_dumpers_[A-Za-z0-9_]+\.def)".*|\1|p' \
                 "$DUMPER_DEF_AGGREGATOR")

    local domains=$(( ${#_out[@]} - 1 ))
    if (( domains < DUMPER_DEF_MIN_INCLUDES )); then
        echo "dumper_defs: resolved only $domains per-domain .def include(s) from $DUMPER_DEF_AGGREGATOR, expected at least $DUMPER_DEF_MIN_INCLUDES — the include pattern moved and every consumer of this set has gone blind" >&2
        return 1
    fi
    return 0
}
