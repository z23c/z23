#!/usr/bin/env bash
# Gate — telemetry-ontology coverage. Every network telemetry field a covered
# dump function emits must carry a MEANING row in
# platform/modules/util/include/util/telemetry_ontology.def.
#
# Why this gate exists. `dumpstate peer_lifecycle` prints
# "pre_handshake_disconnects":27 and nothing states what that counts, what
# range is healthy, or what a bad value implies. 27-of-332 on a healthy node
# and 8-of-8 on a node that cannot start produce JSON that is identical in
# shape; only the second is the whole story. Meaning that is optional rots
# immediately, so the next field to ship must arrive with meaning attached or
# the build stops.
#
# Mechanism. tools/lint/telemetry_ontology_scan.txt declares the covered
# surface. It has TWO row kinds, because the codebase now has two ways to emit
# a telemetry field and only one of them can be proven by grepping emissions.
#
# ── row kind 1: FUNC (hand-written dumpers) ──────────────────────────────
#   <subsystem> <file> <function> <objvar> <prefix>
# For each row this gate slices the named function out of its file
# (tools/lint/telemetry_scan_lib.awk), extracts every scalar field emission
# inside it (json_push_kv_int/_str/_bool/_dbl/_uint — container pushes are
# structural, not values), maps the emission's target variable to that row's
# JSON path prefix, and requires the resulting "<subsystem>|<path>" key to
# exist in the ontology. Two ways it bites:
#
#   UNANNOTATED FIELD        a field emitted with no ontology row
#   UNMAPPED EMISSION TARGET a new json target variable the manifest does not
#                            map, so its fields could not be checked at all
#
# ── row kind 2: TABLE (table-driven domains) ─────────────────────────────
#   TABLE <domain> <path-to-fields.def> <min-rows>
#
# WHY THIS ROW KIND EXISTS. A table-driven domain (util/telemetry_render.h)
# declares its fields once in `<domain>_fields.def` as TL_LEAF rows, and ONE
# generic renderer emits every one of them. There is no per-domain function to
# slice and no per-field json_push_kv_* call to grep, so emission-grepping
# extracts exactly ZERO fields for such a domain — and the EXTRACTED floor
# still clears on the hand-written domains alone. The domain would read as
# covered while being completely unchecked. A TABLE row proves coverage
# STRUCTURALLY instead:
#
#   1. every TL_LEAF(group, member, ...) in the named .def must resolve to
#      "<domain>|values.<group>.<member>" in the merged ontology set — and that
#      set is read off the PASTE SITE (the `#define TL_SUB` / `#include
#      "util/telemetry/<d>_fields.def"` pairs in platform/modules/util/src/telemetry_ontology.c),
#      not off the domain registry, so a row naming a table the build never
#      pastes into g_fields[] fails here;
#   2. the .def's own TL_DOMAIN_META must declare the same domain the row does;
#   3. the leaf count is floored SHRINK-ONLY at <min-rows>, so a domain that
#      silently loses its fields fails instead of passing vacuously;
#   4. NO json_push_kv_* may appear in that domain's `*_fill.c` providers — a
#      fill collector that hand-writes JSON is precisely the regression this
#      row kind exists to catch — and the NUMBER of providers discovered is
#      itself asserted against tools/lint/telemetry_fill_provider_count.txt, so
#      "scanned zero files, all clean" cannot happen quietly;
#   5. the per-row content contract (non-empty `means`; non-empty `implies`
#      and `next` unless the rule is TFR_INFO) is checked on TL_LEAF rows with
#      the same logic that checks TELEMETRY_FIELD rows — the TFS_*/TFR_* tokens
#      sit in the same argument positions in both grammars.
#
# The registry (telemetry_domains.def) and the paste site must also agree in
# both directions: a domain registered but never pasted ships every leaf with
# no meaning, and a domain pasted but never registered never reaches a rollup.
#
# Anti-hollowness. Floors on the FUNC manifest row count, the TABLE manifest
# row count, the ontology row count, the registered-domain count, the
# pasted-domain count, the merged domain-table row count, the judged (non-info)
# row count, the total TABLE leaf count, the extracted field count and the
# discovered fill-provider count; a function the awk slicer cannot find is
# FATAL, never "zero fields".
#
# `--selftest` runs the whole trip/recover matrix (13 cases) against throwaway
# inputs; the C group `make_lint_gates` dispatches it.
#
# Mode: WARN | FAIL (ZCL_LINT_MODE; default FAIL).

set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/scripts/sh_str.sh
# `printf ... | grep -q` under pipefail reports a MATCH as 141, which in a lint
# gate reads a found violation as clean. Nothing added below uses that shape.
. tools/scripts/sh_str.sh

GATE=check_telemetry_ontology
MODE="${ZCL_LINT_MODE:-FAIL}"

# ── `--selftest`: prove the gate still BITES ─────────────────────────────
# The C group `make_lint_gates` (tests/harness/src/lint_gate_quality_selftests.c)
# runs the first three cases; this flag runs those plus one case per way a
# TABLE row can be violated, so the structural coverage proof can be watched
# failing without a test build. Every case that needs a bad input builds it in
# a throwaway directory — nothing is ever planted in the real tree.
if [ "${1:-}" = "--selftest" ]; then
    case "$0" in
        /*) st_self="$0" ;;
        *)  st_self="$PWD/${0#./}" ;;
    esac
    st_tmp="$(mktemp -d "${TMPDIR:-/tmp}/telemetry_gate_selftest.XXXXXX")"
    trap 'rm -rf "$st_tmp"' EXIT
    st_fail=0
    st_run() { # st_run <env-assignment>... -- runs the gate, sets st_rc/st_out
        set +e
        st_out="$(env "$@" "$st_self" 2>&1)"
        st_rc=$?
        set -e
    }
    st_expect() { # st_expect <label> <want-rc> [<want-substring>]
        if [ "$st_rc" -ne "$2" ]; then
            echo "$GATE --selftest: FAIL — $1: rc=$st_rc want=$2" >&2
            printf '%s\n' "$st_out" | sed 's/^/    | /' >&2
            st_fail=1
            return
        fi
        if [ -n "${3:-}" ] && str_lacks "$st_out" "$3"; then
            echo "$GATE --selftest: FAIL — $1: output lacks '$3'" >&2
            printf '%s\n' "$st_out" | sed 's/^/    | /' >&2
            st_fail=1
            return
        fi
        echo "  ok  $1 (rc=$st_rc)"
    }
    # A minimally valid fixture table, then the four ways to break one.
    st_table() { # st_table <file> <domain> <group> <member>
        cat > "$1" <<ST_EOF
TL_DOMAIN_META($2, "zcl.telemetry.$2.selftest", "selftest table")
TL_GROUP($3, "selftest group")
TL_LEAF($3, $4, TLC_I64, TFU_UNIX_TIME, TLV_NORMAL,
    TFR_INFO, TL_NONE, 0, TFS_INFO,
    "a leaf that exists only for the gate self-test",
    "", "")
TL_GROUP_END($3)
ST_EOF
    }

    st_run ZCL_NOOP=1; st_expect "1 real tree" 0 "PASS"

    st_run "ZCL_TELEMETRY_SCAN_EXTRA_MANIFEST=tools/lint/fixtures/telemetry_scan_extra.txt"
    st_expect "2 checked-in known-bad FUNC+TABLE fixtures" 1 \
        "runtime|values.fixture_group.leaf_that_ships_with_no_meaning"

    st_run "ZCL_TELEMETRY_SCAN_MANIFEST="
    st_expect "3 hollow scan manifest" 2 "FATAL"

    # 4 — a TL_LEAF that resolves to no ontology row. THE blind spot: this
    # domain emits from the generic renderer, so the emission scan sees zero
    # fields for it and would report PASS.
    st_table "$st_tmp/bogus_leaf.def" runtime meta not_a_registered_leaf
    printf 'TABLE runtime %s 1\n' "$st_tmp/bogus_leaf.def" > "$st_tmp/extra4.txt"
    st_run "ZCL_TELEMETRY_SCAN_EXTRA_MANIFEST=$st_tmp/extra4.txt"
    st_expect "4 TL_LEAF with no ontology row" 1 \
        "runtime|values.meta.not_a_registered_leaf"

    # 5 — the table declares a different domain than the manifest row claims.
    st_table "$st_tmp/wrong_domain.def" wallet meta collected_unix
    printf 'TABLE runtime %s 1\n' "$st_tmp/wrong_domain.def" > "$st_tmp/extra5.txt"
    st_run "ZCL_TELEMETRY_SCAN_EXTRA_MANIFEST=$st_tmp/extra5.txt"
    st_expect "5 table declares a different domain" 1 "TABLE MISMATCH"

    # 6 — shrink-only floor: a domain that lost fields.
    #
    # BOTH ends are pinned: the table is a throwaway with a KNOWN one leaf and
    # the floor is 2. An earlier form pointed the row at the real
    # runtime_fields.def with a floor of 5 and so depended on that table having
    # fewer than 5 leaves; the day the runtime domain shipped its real fields
    # the floor was satisfied, the case stopped tripping, and a green selftest
    # stopped proving the shrink-only floor works. Same defect as cases 11/12
    # below, same fix: a selftest must not depend on the state of the tree it
    # is guarding.
    st_table "$st_tmp/one_leaf.def" runtime meta collected_unix
    printf 'TABLE runtime %s 2\n' "$st_tmp/one_leaf.def" > "$st_tmp/extra6.txt"
    st_run "ZCL_TELEMETRY_SCAN_EXTRA_MANIFEST=$st_tmp/extra6.txt"
    st_expect "6 leaf count below the shrink-only floor" 1 "TABLE FLOOR BREACHED"

    # 7 — a fill provider that hand-writes JSON instead of filling the struct.
    mkdir -p "$st_tmp/fillroot"
    cat > "$st_tmp/fillroot/runtime_telemetry_fill.c" <<'ST_EOF'
bool runtime_dump_state_fill(struct runtime_snapshot *snap)
{
    json_push_kv_int(out, "smuggled_field", 1);
    return true;
}
ST_EOF
    st_run "ZCL_TELEMETRY_FILL_SCAN_ROOTS=$st_tmp/fillroot"
    st_expect "7 fill provider hand-writes JSON" 1 "PROVIDER HAND-WRITES JSON"

    # 8 — the per-row content contract still applies to TL_LEAF rows.
    cat > "$st_tmp/empty_means.def" <<'ST_EOF'
TL_DOMAIN_META(runtime, "zcl.telemetry.runtime.selftest", "selftest table")
TL_GROUP(meta, "selftest group")
TL_LEAF(meta, collected_unix, TLC_I64, TFU_UNIX_TIME, TLV_NORMAL,
    TFR_INFO, TL_NONE, 0, TFS_INFO,
    "", "", "")
TL_GROUP_END(meta)
ST_EOF
    printf 'TABLE runtime %s 1\n' "$st_tmp/empty_means.def" > "$st_tmp/extra8.txt"
    st_run "ZCL_TELEMETRY_SCAN_EXTRA_MANIFEST=$st_tmp/extra8.txt"
    st_expect "8 TL_LEAF with an empty means" 1 "empty means"

    # 9 — the g_fields[] paste site files one domain's table under another's
    # subsystem name.
    sed 's/#define TL_SUB "agents"/#define TL_SUB "wallet"/' \
        platform/modules/util/src/telemetry_ontology.c > "$st_tmp/mispaired.c"
    st_run "ZCL_TELEMETRY_ONTOLOGY_TU=$st_tmp/mispaired.c"
    st_expect "9 mis-paired TL_SUB over a field table" 1 "MIS-PAIRED PASTE"

    # 10 — a domain registered in the registry but never pasted, so its fields
    # would ship with no meaning while the registry says it is covered.
    grep -v 'telemetry/metaverse_fields.def' platform/modules/util/src/telemetry_ontology.c \
        > "$st_tmp/half_registered.c"
    st_run "ZCL_TELEMETRY_ONTOLOGY_TU=$st_tmp/half_registered.c"
    st_expect "10 registered domain never pasted" 1 "HALF-REGISTERED DOMAIN"

    # 11/12 — the fill-provider population is an assertion. Both directions of
    # drift must bite, or "0 providers scanned" is a floor that never fires.
    #
    # BOTH ends are pinned in each case. Pinning only one and letting the other
    # come from the real tree makes the case silently self-cancelling the
    # moment the real count happens to equal the planted one: these two cases
    # planted 1 against a tree that had 0 providers, and stopped detecting
    # anything at all the day the first real fill provider landed and made the
    # comparison 1 == 1. A selftest that passes because both sides moved
    # together is worse than no selftest.
    mkdir -p "$st_tmp/onefill" "$st_tmp/twofill"
    st_make_fill() { # st_make_fill <dir> <domain>
        cat > "$1/$2_telemetry_fill.c" <<ST_EOF
bool $2_dump_state_fill(struct $2_snapshot *snap)
{
    TELEMETRY_SET_I64(snap, collected_unix, telemetry_now_unix(),
                      TELEMETRY_SRC_IN_PROCESS);
    return true;
}
ST_EOF
    }
    st_make_fill "$st_tmp/onefill" runtime
    st_make_fill "$st_tmp/twofill" runtime
    st_make_fill "$st_tmp/twofill" network

    printf '1\n' > "$st_tmp/fill_count_one.txt"
    printf '2\n' > "$st_tmp/fill_count_two.txt"

    # scanned 2 > recorded 1
    st_run "ZCL_TELEMETRY_FILL_SCAN_ROOTS=$st_tmp/twofill" \
           "ZCL_TELEMETRY_FILL_PROVIDER_COUNT=$st_tmp/fill_count_one.txt"
    st_expect "11 a new fill provider must be recorded" 1 \
        "FILL PROVIDER COUNT GREW"

    # scanned 1 < recorded 2
    st_run "ZCL_TELEMETRY_FILL_SCAN_ROOTS=$st_tmp/onefill" \
           "ZCL_TELEMETRY_FILL_PROVIDER_COUNT=$st_tmp/fill_count_two.txt"
    st_expect "12 a vanished fill provider is not silently unscanned" 1 \
        "FILL PROVIDER COUNT DROPPED"

    # and the pinned pair agreeing is a PASS, so 11/12 are proved to be
    # detecting the mismatch rather than something incidental to the sandbox.
    st_run "ZCL_TELEMETRY_FILL_SCAN_ROOTS=$st_tmp/onefill" \
           "ZCL_TELEMETRY_FILL_PROVIDER_COUNT=$st_tmp/fill_count_one.txt"
    st_expect "12b a matching pinned pair passes" 0 "PASS"

    st_run ZCL_NOOP=1; st_expect "13 real tree recovers" 0 "PASS"

    if [ "$st_fail" -ne 0 ]; then
        echo "$GATE: --selftest FAILED" >&2
        exit 1
    fi
    echo "$GATE: --selftest passed (13 cases)"
    exit 0
fi

# Overridable so the gate self-test can point at a planted fixture.
# `-` not `:-` deliberately: an explicitly EMPTY override means "point the scan
# at nothing", and that must reach the readability check below and exit 2, not
# silently fall back to the real manifest and report a clean tree.
MANIFEST="${ZCL_TELEMETRY_SCAN_MANIFEST-tools/lint/telemetry_ontology_scan.txt}"
# Additional manifest rows appended to the real set. The gate self-test points
# this at a checked-in fixture that emits a field with no meaning, so the trip
# path is exercised against the REAL ontology and the REAL floors — never
# against a shrunken scan that would trip for the wrong reason.
EXTRA_MANIFEST="${ZCL_TELEMETRY_SCAN_EXTRA_MANIFEST:-}"
ONTOLOGY="${ZCL_TELEMETRY_ONTOLOGY_DEF-platform/modules/util/include/util/telemetry_ontology.def}"
AWKLIB="tools/lint/telemetry_scan_lib.awk"
# The registry of table-driven domains, and the directory holding their field
# tables. Together these produce the ontology rows a TABLE row must resolve
# against: a domain is only in the merged set because telemetry_domains.def
# registers it, which is what makes the TABLE check non-circular.
DOMAINS_DEF="${ZCL_TELEMETRY_DOMAINS_DEF-platform/modules/util/include/util/telemetry_domains.def}"
FIELDS_DIR="${ZCL_TELEMETRY_FIELDS_DIR-platform/modules/util/include/util/telemetry}"
# Where a domain's `*_fill.c` providers are looked for (check 4 above).
read -r -a FILL_SCAN_ROOTS \
    <<< "${ZCL_TELEMETRY_FILL_SCAN_ROOTS:-core engine contexts cognition platform}"

for f in "$MANIFEST" "$ONTOLOGY" "$AWKLIB" "$DOMAINS_DEF"; do
    if [ ! -r "$f" ]; then
        echo "$GATE: FATAL — required input missing or unreadable: $f" >&2
        exit 2
    fi
done
if [ -n "$EXTRA_MANIFEST" ] && [ ! -r "$EXTRA_MANIFEST" ]; then
    echo "$GATE: FATAL — ZCL_TELEMETRY_SCAN_EXTRA_MANIFEST is set but" >&2
    echo "  unreadable: $EXTRA_MANIFEST" >&2
    exit 2
fi

# ── 1. the ontology's declared keys ──────────────────────────────────────
# TELEMETRY_FIELD("<subsystem>", "<path>", ...  -> "<subsystem>|<path>"
#
# Held as a shell SET, not as a text blob re-scanned per field. The blob form
# (`printf '%s\n' "$ONTO_KEYS" | grep -qxF "$key"`) spawned one pipeline per
# emitted field, and under `set -o pipefail` that construct is a coin flip:
# `grep -q` exits the moment it matches, so a match found in the reader's
# first chunk closes the pipe while the writer still has bytes to push. The
# writer then dies of SIGPIPE (141), pipefail promotes 141 to the pipeline's
# status, and an ANNOTATED field gets reported as UNANNOTATED — naming a
# random file nobody touched. Measured 209 false failures in 1000 runs at 32
# concurrent invocations. Set membership needs no subprocess, so the whole
# failure mode is gone rather than retried around.
declare -A ONTO_SET=()
while IFS= read -r _k; do
    [ -n "$_k" ] && ONTO_SET["$_k"]=1
done < <(sed -n \
    's/^[[:space:]]*TELEMETRY_FIELD("\([^"]*\)",[[:space:]]*"\([^"]*\)".*/\1|\2/p' \
    "$ONTOLOGY" | sort -u)
ONTO_COUNT=${#ONTO_SET[@]}
gate_require_scanned "$ONTO_COUNT" 150 "$GATE" \
    "ontology row population collapsed — $ONTOLOGY parsed as $ONTO_COUNT rows"

# Judged rows: a table that is all TFR_INFO would technically be "covered"
# while judging nothing. Floor the judged population too.
JUDGED=$(grep -cE 'TFR_(EXPECT_ZERO|EXPECT_NONZERO|EXPECT_TRUE|EXPECT_FALSE|MIN_ABS|MAX_ABS|MIN_RATIO_OF|MAX_RATIO_OF)' \
    "$ONTOLOGY" || true)
gate_require_scanned "$JUDGED" 20 "$GATE" \
    "judged (non-info) ontology rows collapsed to $JUDGED"

QUESTIONS=$(grep -c '^[[:space:]]*TELEMETRY_QUESTION(' "$ONTOLOGY" || true)
gate_require_scanned "$QUESTIONS" 8 "$GATE" \
    "discovery-index question rows collapsed to $QUESTIONS"

# ── 1b. the table-driven domains' rows, merged into the same set ─────────
# A TL_LEAF row is pasted into g_fields[] as an ontology row at
# "values.<group>.<member>" under its own domain name (util/telemetry_render.h:
# `domain` MUST equal the ontology subsystem). Merging them here is what makes
# "<domain>|values.<g>.<m>" resolvable for a TABLE manifest row.
#
# THE MERGE IS READ OFF THE PASTE SITE, NOT ASSUMED. g_fields[] is built in
# platform/modules/util/src/telemetry_ontology.c by a `#define TL_SUB "<domain>"` immediately
# above `#include "util/telemetry/<domain>_fields.def"`, once per domain. This
# gate parses those pairs, so the merged set is what the COMPILER pastes rather
# than what the domain registry promises. That distinction is the whole point:
# if a domain is registered in telemetry_domains.def but its table is never
# pasted, its fields ship with no meaning row at all and every leaf renders
# UNKNOWN — and a gate that merged straight from the registry would report that
# domain as fully covered. Both halves are checked against each other below.
#
# The TL_SUB/#include pairing is also verified: a `#define TL_SUB "wallet"` over
# agents_fields.def would file one domain's fields under another's subsystem,
# which the evaluator would then never find.

# Print "<group> <member>" for every TL_LEAF row in a field table.
tl_leaf_rows() {
    awk '
        /^[[:space:]]*TL_LEAF[[:space:]]*[(]/ {
            s = $0
            sub(/^[[:space:]]*TL_LEAF[[:space:]]*[(]/, "", s)
            n = split(s, a, ",")
            if (n < 2) next
            g = a[1]; m = a[2]
            gsub(/[[:space:]]/, "", g); gsub(/[[:space:]]/, "", m)
            if (g != "" && m != "") print g " " m
        }
    ' "$1"
}

# The domain named by a field table's own TL_DOMAIN_META row (empty if absent).
tl_table_domain() {
    sed -n 's/^[[:space:]]*TL_DOMAIN_META[[:space:]]*([[:space:]]*\([A-Za-z_][A-Za-z0-9_]*\).*/\1/p' \
        "$1" | head -n1
}

declare -A REGISTERED_DOMAIN=()
while IFS= read -r _d; do
    [ -z "$_d" ] && continue
    REGISTERED_DOMAIN["$_d"]=1
done < <(sed -n 's/^[[:space:]]*TL_DOMAIN[[:space:]]*([[:space:]]*\([A-Za-z_][A-Za-z0-9_]*\).*/\1/p' \
    "$DOMAINS_DEF")
gate_require_scanned "${#REGISTERED_DOMAIN[@]}" 8 "$GATE" \
    "$DOMAINS_DEF registered ${#REGISTERED_DOMAIN[@]} domain(s) — the domain \
registry collapsed"

# Every "<TL_SUB subsystem> <included table's domain>" pair at the paste site.
ONTOLOGY_TU="${ZCL_TELEMETRY_ONTOLOGY_TU-platform/modules/util/src/telemetry_ontology.c}"
if [ ! -r "$ONTOLOGY_TU" ]; then
    echo "$GATE: FATAL — the g_fields[] paste site is missing or unreadable:" >&2
    echo "  $ONTOLOGY_TU" >&2
    exit 2
fi

declare -A PASTED_DOMAIN=()
declare -a DOMAIN_DEF_FILES=()
DOMAIN_TABLE_ROWS=0
MISPAIRED=""
while read -r _sub _tab; do
    [ -z "$_sub" ] && continue
    if [ "$_sub" != "$_tab" ]; then
        MISPAIRED="${MISPAIRED}${ONTOLOGY_TU}: #define TL_SUB \"${_sub}\" pastes ${_tab}_fields.def"$'\n'
        continue
    fi
    PASTED_DOMAIN["$_sub"]=1
    _dfile="$FIELDS_DIR/${_sub}_fields.def"
    if [ ! -r "$_dfile" ]; then
        echo "$GATE: FATAL — $ONTOLOGY_TU pastes domain '$_sub' but its field" >&2
        echo "  table is missing or unreadable: $_dfile" >&2
        exit 2
    fi
    DOMAIN_DEF_FILES+=("$_dfile")
    while read -r _g _m; do
        [ -z "$_g" ] && continue
        ONTO_SET["$_sub|values.$_g.$_m"]=1
        DOMAIN_TABLE_ROWS=$((DOMAIN_TABLE_ROWS + 1))
    done < <(tl_leaf_rows "$_dfile")
done < <(awk '
    /^[[:space:]]*#define[[:space:]]+TL_SUB[[:space:]]+"/ {
        sub(/^[^"]*"/, ""); sub(/".*$/, ""); sub_name = $0; next
    }
    sub_name != "" && /^[[:space:]]*#include[[:space:]]+".*_fields\.def"/ {
        s = $0
        sub(/^.*\//, "", s); sub(/_fields\.def".*$/, "", s)
        print sub_name " " s
        sub_name = ""
    }
' "$ONTOLOGY_TU")

if [ -n "$MISPAIRED" ]; then
    printf "%s" "$MISPAIRED" >&2
    echo "[$GATE] MIS-PAIRED PASTE — a \`#define TL_SUB\` names a different" >&2
    echo "  domain than the field table pasted under it, so that table's rows" >&2
    echo "  land in the wrong subsystem and the evaluator will never find" >&2
    echo "  them. Keep each #define adjacent to its own #include." >&2
    [ "$MODE" = "FAIL" ] && exit 1
fi
# Registry and paste site must agree, in both directions. This runs BEFORE the
# population floors on purpose: a domain that went missing from one side is a
# named, actionable failure, and reporting it that way beats aborting with the
# generic "scan set collapsed". A collapse of BOTH sides is still caught — the
# registry floor above fires first.
HALF_REGISTERED=""
for _d in "${!REGISTERED_DOMAIN[@]}"; do
    [ -z "${PASTED_DOMAIN[$_d]+set}" ] && \
        HALF_REGISTERED="${HALF_REGISTERED}${_d}: registered in $DOMAINS_DEF but never pasted into g_fields[]"$'\n'
done
for _d in "${!PASTED_DOMAIN[@]}"; do
    [ -z "${REGISTERED_DOMAIN[$_d]+set}" ] && \
        HALF_REGISTERED="${HALF_REGISTERED}${_d}: pasted into g_fields[] but not registered in $DOMAINS_DEF"$'\n'
done
if [ -n "$HALF_REGISTERED" ]; then
    printf "%s" "$HALF_REGISTERED" >&2
    echo "[$GATE] HALF-REGISTERED DOMAIN — the domain registry and the" >&2
    echo "  g_fields[] paste site disagree. A registered domain whose table is" >&2
    echo "  never pasted renders every leaf UNKNOWN with no meaning attached;" >&2
    echo "  a pasted domain that is not registered never appears in a rollup." >&2
    [ "$MODE" = "FAIL" ] && exit 1
fi

gate_require_scanned "${#PASTED_DOMAIN[@]}" 8 "$GATE" \
    "$ONTOLOGY_TU pastes ${#PASTED_DOMAIN[@]} domain field table(s) into \
g_fields[] — the paste site changed shape, so the merged ontology this gate \
checks against is not what the build produces"
gate_require_scanned "$DOMAIN_TABLE_ROWS" 8 "$GATE" \
    "the pasted field tables contributed $DOMAIN_TABLE_ROWS TL_LEAF row(s) — a \
field table was emptied or its row grammar drifted"

# ── 2. per-row content: non-empty means / implies / next ─────────────────
# One checker for BOTH grammars. TELEMETRY_FIELD and TL_LEAF put the severity,
# `means`, `implies` and `next` in the same relative argument positions, and in
# both a row spans several lines, so the row is buffered from its opening macro
# to the line that ends in `)` before it is judged. (The older same-line grep
# could only see an empty `means` written on the severity's own line; every
# real row in either grammar puts it on the next line.)
#
#   empty means         the argument right after the TFS_* severity is ""
#   empty implies/next  a JUDGED row (a TFR_* rule other than TFR_INFO) whose
#                       last one or two arguments are ""
row_content_check() { # <file> <macro-name>
    awk -v macro="$2" '
        function report(kind, b) {
            sub(/^[[:space:]]*/, "", b)
            printf "%s: [%s] %.100s...\n", FILENAME, kind, b
        }
        {
            if (buf == "" && $0 ~ ("^[[:space:]]*" macro "[[:space:]]*[(]")) {
                buf = $0
            } else if (buf != "") {
                buf = buf " " $0
            }
            if (buf != "" && $0 ~ /\)[[:space:]]*$/) {
                judged = (buf ~ /TFR_(EXPECT_ZERO|EXPECT_NONZERO|EXPECT_TRUE|EXPECT_FALSE|MIN_ABS|MAX_ABS|MIN_RATIO_OF|MAX_RATIO_OF)/)
                if (buf ~ /TFS_(INFO|WARN|CRITICAL)[[:space:]]*,[[:space:]]*""[[:space:]]*[,)]/) {
                    report("empty means", buf)
                } else if (judged &&
                           (buf ~ /,[[:space:]]*""[[:space:]]*,[[:space:]]*""[[:space:]]*\)/ ||
                            buf ~ /,[[:space:]]*""[[:space:]]*\)[[:space:]]*$/)) {
                    report("empty implies/next", buf)
                }
                buf = ""
            }
        }
    ' "$1"
}

declare -A CONTENT_CHECKED=()
FAILED_CONTENT=0
CONTENT_BAD=$(row_content_check "$ONTOLOGY" TELEMETRY_FIELD || true)
for _dfile in "${DOMAIN_DEF_FILES[@]}"; do
    CONTENT_CHECKED["$_dfile"]=1
    CONTENT_BAD="${CONTENT_BAD}$(row_content_check "$_dfile" TL_LEAF || true)"$'\n'
done
CONTENT_BAD="${CONTENT_BAD#"${CONTENT_BAD%%[![:space:]]*}"}"
CONTENT_BAD="${CONTENT_BAD%"${CONTENT_BAD##*[![:space:]]}"}"
if [ -n "$CONTENT_BAD" ]; then
    printf "%s\n" "$CONTENT_BAD" >&2
    echo "[$GATE] the row(s) above ship an EMPTY \`means\`, or carry a health" >&2
    echo "  rule while leaving \`implies\`/\`next\` empty. Every field must state" >&2
    echo "  what it counts; a judged field must also say what a bad value means" >&2
    echo "  and where to look next. See util/telemetry_ontology.h and" >&2
    echo "  util/telemetry_field_table.h." >&2
    [ "$MODE" = "FAIL" ] && exit 1
fi

# ── 3. what the dump functions actually emit ─────────────────────────────
MANIFEST_ROWS=0
TABLE_ROWS=0
declare -A PREFIX_OF=()      # "<file>|<fn>|<objvar>" -> prefix
declare -A SUBSYS_OF=()      # "<file>|<fn>|<objvar>" -> subsystem
declare -A FUNCS=()          # "<file>|<fn>" -> 1
declare -a TBL_DOMAIN=() TBL_DEF=() TBL_MIN=()

while IFS= read -r line; do
    line="${line%%#*}"
    # shellcheck disable=SC2086
    set -- $line
    [ "$#" -eq 0 ] && continue
    if [ "$1" = "TABLE" ]; then
        if [ "$#" -ne 4 ]; then
            echo "$GATE: FATAL — malformed TABLE row (want" >&2
            echo "  'TABLE <domain> <fields.def> <min-rows>'): $line" >&2
            exit 2
        fi
        tdom=$2 tdef=$3 tmin=$4
        if [ ! -r "$tdef" ]; then
            echo "$GATE: FATAL — TABLE row names an unreadable field table: $tdef" >&2
            exit 2
        fi
        case "$tmin" in
            ''|*[!0-9]*)
                echo "$GATE: FATAL — TABLE row's <min-rows> is not a number: $line" >&2
                exit 2 ;;
        esac
        TBL_DOMAIN+=("$tdom"); TBL_DEF+=("$tdef"); TBL_MIN+=("$tmin")
        TABLE_ROWS=$((TABLE_ROWS + 1))
        continue
    fi
    if [ "$#" -ne 5 ]; then
        echo "$GATE: FATAL — malformed manifest row: $line" >&2
        exit 2
    fi
    sub=$1 file=$2 fn=$3 obj=$4 prefix=$5
    [ "$prefix" = "-" ] && prefix=""
    if [ ! -r "$file" ]; then
        echo "$GATE: FATAL — manifest names an unreadable file: $file" >&2
        exit 2
    fi
    PREFIX_OF["$file|$fn|$obj"]="$prefix"
    SUBSYS_OF["$file|$fn|$obj"]="$sub"
    FUNCS["$file|$fn"]=1
    MANIFEST_ROWS=$((MANIFEST_ROWS + 1))
done < <(cat "$MANIFEST" ${EXTRA_MANIFEST:+"$EXTRA_MANIFEST"})

gate_require_scanned "$MANIFEST_ROWS" 20 "$GATE" \
    "scan manifest collapsed to $MANIFEST_ROWS FUNC rows"
# Every registered domain must carry a TABLE row, or a domain could be dropped
# from the manifest and go unchecked while the FUNC floor above stays green.
gate_require_scanned "$TABLE_ROWS" "${#REGISTERED_DOMAIN[@]}" "$GATE" \
    "scan manifest carries $TABLE_ROWS TABLE row(s) for ${#REGISTERED_DOMAIN[@]} \
registered domain(s) — every table-driven domain needs one"

EXTRACTED=0
UNANNOTATED=""
UNMAPPED=""

for key in "${!FUNCS[@]}"; do
    file="${key%%|*}"
    fn="${key##*|}"
    set +e
    slice=$(awk -v fn="$fn" -f "$AWKLIB" "$file")
    arc=$?
    set -e
    if [ "$arc" -ne 0 ]; then
        echo "$GATE: FATAL — could not slice function '$fn' out of $file" >&2
        echo "  (awk exit $arc). Refusing to report PASS off a hollow scan." >&2
        exit 2
    fi
    [ -z "$slice" ] && continue
    while read -r ln obj field; do
        [ -z "$ln" ] && continue
        mapkey="$file|$fn|$obj"
        if [ -z "${PREFIX_OF[$mapkey]+set}" ]; then
            # Only complain once per (file,fn,objvar).
            case "$UNMAPPED" in
                *"$mapkey"*) ;;
                *) UNMAPPED="${UNMAPPED}${file}:${ln}: ${fn}() emits into unmapped target '${obj}' (first field: ${field})"$'\n' ;;
            esac
            continue
        fi
        EXTRACTED=$((EXTRACTED + 1))
        path="${PREFIX_OF[$mapkey]}${field}"
        sub="${SUBSYS_OF[$mapkey]}"
        if [ -z "${ONTO_SET["$sub|$path"]+set}" ]; then
            UNANNOTATED="${UNANNOTATED}${file}:${ln}: ${sub}|${path}"$'\n'
        fi
    done <<< "$slice"
done

gate_require_scanned "$EXTRACTED" 150 "$GATE" \
    "extracted field population collapsed to $EXTRACTED — a covered dump \
function was probably renamed"

# ── 4. the TABLE rows: structural coverage, not emission-grepping ────────
TABLE_LEAVES=0
FILL_FILES_SCANNED=0
TABLE_UNRESOLVED=""
SHRUNK=""
HANDWRITTEN=""
WRONG_DOMAIN=""

# Every `*_fill.c` under the scan roots, once — the per-domain selection below
# is a basename/definition filter over this list rather than a fresh walk.
declare -a ALL_FILL_FILES=()
mapfile -t ALL_FILL_FILES < <(
    find "${FILL_SCAN_ROOTS[@]}" -type f -name '*_fill.c' 2>/dev/null \
    | grep -v '/test/' | sort)

for _i in "${!TBL_DOMAIN[@]}"; do
    dom="${TBL_DOMAIN[$_i]}"
    def="${TBL_DEF[$_i]}"
    minrows="${TBL_MIN[$_i]}"

    # (2) the table must declare the domain the manifest row claims, or the row
    # would be proving coverage of somebody else's fields.
    declared="$(tl_table_domain "$def")"
    if [ "$declared" != "$dom" ]; then
        WRONG_DOMAIN="${WRONG_DOMAIN}${def}: TL_DOMAIN_META declares '${declared:-<none>}', manifest row says '${dom}'"$'\n'
    fi

    # (1) every leaf must resolve in the merged ontology set.
    rows=0
    while read -r g m; do
        [ -z "$g" ] && continue
        rows=$((rows + 1))
        TABLE_LEAVES=$((TABLE_LEAVES + 1))
        if [ -z "${ONTO_SET["$dom|values.$g.$m"]+set}" ]; then
            TABLE_UNRESOLVED="${TABLE_UNRESOLVED}${def}: ${dom}|values.${g}.${m}"$'\n'
        fi
    done < <(tl_leaf_rows "$def")

    # (3) shrink-only floor.
    if [ "$rows" -lt "$minrows" ]; then
        SHRUNK="${SHRUNK}${def}: ${rows} TL_LEAF row(s), manifest floor is ${minrows}"$'\n'
    fi

    # (5) content contract on this table's rows. Section 2 already checked
    # every REGISTERED domain's table; this covers a TABLE row that names a
    # table the registry does not, which still has to carry meaning.
    if [ -z "${CONTENT_CHECKED["$def"]+set}" ]; then
        CONTENT_CHECKED["$def"]=1
        dc="$(row_content_check "$def" TL_LEAF || true)"
        if [ -n "$dc" ]; then
            printf "%s\n" "$dc" >&2
            echo "[$GATE] TL_LEAF row(s) above ship an empty means, or carry a" >&2
            echo "  health rule with an empty implies/next." >&2
            FAILED_CONTENT=1
        fi
    fi

    # (4) no hand-written JSON in this domain's fill providers.
    for ff in "${ALL_FILL_FILES[@]}"; do
        base="${ff##*/}"
        interesting=0
        case "$base" in "${dom}_"*) interesting=1 ;; esac
        if [ "$interesting" -eq 0 ]; then
            set +e
            grep -qE "\b${dom}_dump_state_fill[[:space:]]*[(]" -- "$ff"
            drc=$?
            set -e
            if [ "$drc" -ge 2 ]; then
                echo "$GATE: FATAL — grep failed (rc=$drc) on $ff" >&2
                exit 2
            fi
            [ "$drc" -eq 0 ] && interesting=1
        fi
        [ "$interesting" -eq 0 ] && continue
        FILL_FILES_SCANNED=$((FILL_FILES_SCANNED + 1))
        set +e
        jhits="$(grep -nE 'json_push_kv_(int|str|bool|dbl|uint)[[:space:]]*[(]' -- "$ff")"
        jrc=$?
        set -e
        if [ "$jrc" -ge 2 ]; then
            echo "$GATE: FATAL — grep failed (rc=$jrc) on $ff" >&2
            exit 2
        fi
        if [ -n "$jhits" ]; then
            while IFS= read -r hl; do
                [ -z "$hl" ] && continue
                HANDWRITTEN="${HANDWRITTEN}${ff}:${hl%%:*}: ${dom} provider hand-writes JSON"$'\n'
            done <<< "$jhits"
        fi
    done
done

gate_require_scanned "$TABLE_LEAVES" "$TABLE_ROWS" "$GATE" \
    "the TABLE rows contributed $TABLE_LEAVES leaf row(s) across $TABLE_ROWS \
row(s) — a field table parsed as empty, so its coverage proof is hollow"

# The fill-provider population is an ASSERTION, not an observation — see the
# header of the count file. Zero discovered files would otherwise mean the
# hand-written-JSON check silently protects nothing.
FILL_COUNT_FILE="${ZCL_TELEMETRY_FILL_PROVIDER_COUNT-tools/lint/telemetry_fill_provider_count.txt}"
if [ ! -r "$FILL_COUNT_FILE" ]; then
    echo "$GATE: FATAL — fill-provider count file missing: $FILL_COUNT_FILE" >&2
    exit 2
fi
FILL_EXPECTED="$(sed -n 's/^[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' \
    "$FILL_COUNT_FILE" | head -n1)"
if [ -z "$FILL_EXPECTED" ]; then
    echo "$GATE: FATAL — $FILL_COUNT_FILE carries no integer count" >&2
    exit 2
fi
if [ "$FILL_FILES_SCANNED" -ne "$FILL_EXPECTED" ]; then
    if [ "$FILL_FILES_SCANNED" -lt "$FILL_EXPECTED" ]; then
        echo "[$GATE] FILL PROVIDER COUNT DROPPED — discovered" >&2
        echo "  $FILL_FILES_SCANNED, expected $FILL_EXPECTED. A provider" >&2
        echo "  vanished or fell out of the discovery shape (most often a" >&2
        echo "  rename), so the hand-written-JSON check just went hollow for" >&2
        echo "  its domain. Find it, or lower the count in $FILL_COUNT_FILE" >&2
        echo "  deliberately if the provider really was deleted." >&2
    else
        echo "[$GATE] FILL PROVIDER COUNT GREW — discovered" >&2
        echo "  $FILL_FILES_SCANNED, expected $FILL_EXPECTED. A new provider" >&2
        echo "  is now covered by the no-hand-written-JSON rule; record it by" >&2
        echo "  setting the count in $FILL_COUNT_FILE to $FILL_FILES_SCANNED" >&2
        echo "  in the same commit." >&2
    fi
    FAILED_FILL_COUNT=1
else
    FAILED_FILL_COUNT=0
fi

FAILED="$FAILED_CONTENT"
[ "$FAILED_FILL_COUNT" -eq 1 ] && FAILED=1
if [ -n "$TABLE_UNRESOLVED" ]; then
    printf "%s" "$TABLE_UNRESOLVED" >&2
    echo "[$GATE] UNRESOLVED TABLE LEAF — the TL_LEAF row(s) above derive an" >&2
    echo "  ontology path that is in NOTHING the build pastes into g_fields[]." >&2
    echo "  A TL_LEAF is its own ontology row, so this never means \"write a" >&2
    echo "  TELEMETRY_FIELD row\" — it means the table is not wired up: either" >&2
    echo "  the manifest TABLE row names a field table that no #include in" >&2
    echo "  $ONTOLOGY_TU pastes, or the row's domain is not the domain that" >&2
    echo "  table is pasted under. Fix the wiring, not the ontology." >&2
    FAILED=1
fi
if [ -n "$WRONG_DOMAIN" ]; then
    printf "%s" "$WRONG_DOMAIN" >&2
    echo "[$GATE] TABLE ROW / TABLE MISMATCH — the manifest row and the field" >&2
    echo "  table disagree about which domain the table belongs to, so the row" >&2
    echo "  would prove coverage of the wrong domain's ontology keys." >&2
    FAILED=1
fi
if [ -n "$SHRUNK" ]; then
    printf "%s" "$SHRUNK" >&2
    echo "[$GATE] TABLE FLOOR BREACHED — a domain lost fields. The floor is" >&2
    echo "  SHRINK-ONLY: raise it when the table grows, and never lower it to" >&2
    echo "  make this pass. If the removal is intended, say so in the commit" >&2
    echo "  and lower the floor in $MANIFEST deliberately." >&2
    FAILED=1
fi
if [ -n "$HANDWRITTEN" ]; then
    printf "%s" "$HANDWRITTEN" >&2
    echo "[$GATE] PROVIDER HAND-WRITES JSON — a \`*_fill.c\` collector must fill" >&2
    echo "  the typed snapshot through the TELEMETRY_SET_* setters and emit" >&2
    echo "  nothing. telemetry_render() is the only place a telemetry field" >&2
    echo "  becomes JSON; a json_push_kv_* here reintroduces exactly the" >&2
    echo "  unannotated, un-renderable field this gate exists to prevent." >&2
    FAILED=1
fi
if [ -n "$UNMAPPED" ]; then
    printf "%s" "$UNMAPPED" >&2
    echo "[$GATE] UNMAPPED EMISSION TARGET — the scan manifest does not say" >&2
    echo "  which JSON path the target(s) above sit at, so their fields could" >&2
    echo "  not be checked for meaning at all. Add a row to $MANIFEST." >&2
    FAILED=1
fi
if [ -n "$UNANNOTATED" ]; then
    printf "%s" "$UNANNOTATED" >&2
    N=$(printf "%s" "$UNANNOTATED" | wc -l)
    echo "[$GATE] UNANNOTATED FIELD x$N — the field(s) above are emitted by a" >&2
    echo "  covered dump function with no meaning row. Add a TELEMETRY_FIELD" >&2
    echo "  row to $ONTOLOGY stating what it counts, its health rule, what an" >&2
    echo "  unhealthy value implies, and the next command to run." >&2
    FAILED=1
fi
if [ "$FAILED" -eq 1 ]; then
    [ "$MODE" = "FAIL" ] && exit 1
    # WARN mode: the findings above stand. Do NOT print the PASS line — it
    # claims "all annotated" and a scraper reading only the last line would
    # record a clean gate off a run that just named violations.
    echo "[$GATE] WARN — violations above were reported, not enforced" \
         "(ZCL_LINT_MODE=$MODE)"
    exit 0
fi

echo "[$GATE] PASS ($EXTRACTED emitted fields over $MANIFEST_ROWS FUNC rows," \
     "$TABLE_LEAVES table leaves over $TABLE_ROWS TABLE rows" \
     "(${#REGISTERED_DOMAIN[@]} registered / ${#PASTED_DOMAIN[@]} pasted" \
     "domains, $DOMAIN_TABLE_ROWS merged rows, $FILL_FILES_SCANNED fill" \
     "provider(s) checked), all annotated;" \
     "$ONTO_COUNT ontology rows, $JUDGED judged, $QUESTIONS questions)"
