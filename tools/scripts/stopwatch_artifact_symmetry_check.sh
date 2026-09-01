#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# stopwatch_artifact_symmetry_check.sh — prove the C3 stopwatch records the SAME
# per-phase evidence whether the run passed or not.
#
# THE DEFECT THIS EXISTS TO STOP FROM GROWING BACK. The C3 harness
# (tools/scripts/cold_start_to_tip_stopwatch.sh) used to capture its diagnostic
# bundle behind `[ "$verdict" != "pass" ] && capture_failure_bundle`. That is
# backwards twice over:
#   * a FAILED attempt is exactly when an operator most needs to know which
#     phase consumed the budget — and it got the full bundle, which is right;
#   * a PASSED attempt is the only artifact class worth optimizing AGAINST —
#     and it got three files and threw its measurements away. The one real PASS
#     artifact on disk (build/c3-stopwatch/20260728T000207Z-2102851/) is exactly
#     that: proof.json + node.log + node.tail.log, no per-stage profile at all.
# A baseline that only exists on failure is not a baseline. So capture is now
# unconditional, and this checker is the mechanical proof of it — in BOTH
# directions, because "the pass side got richer" and "the fail side got poorer"
# are both ways to satisfy a one-sided check.
#
# HOW IT PROVES IT WITHOUT A CHAIN, A PEER, OR A NODE. It drives the real
# harness — unmodified, no test hook, no injected behaviour — twice against a
# MOCK node binary it writes itself: once with a frontier that has already
# caught the peer tip (forces PASS), once with a frontier that climbs but never
# catches it (forces SEAM, exit 3). Both runs are then compared field by field
# and file by file. The harness cannot tell it is being mocked; every line of
# write_artifact / capture_run_bundle it executes is the real one.
#
# The mock node is a shell script, and its `agentbuild` output deliberately
# emits `source_id_sha256` TWICE ON ONE LINE with DIFFERENT values — the exact
# shape that made a greedy `sed -n 's/.*"key"...*/\1/p'` return the LAST
# occurrence and produce a false "identical identities" match on 2026-07-28.
# Check 11 asserts the harness recorded the FIRST value, so a regression to a
# greedy reader fails here rather than silently mis-labelling a baseline.
#
# ISOLATION. Everything is under a private mktemp root: the mock binary, both
# artifact roots, the isolated proving-params dir, and the header-source dir.
# The fixture peer is a `nc -l` listener THIS SCRIPT SPAWNS on an EXPLICITLY
# NAMED loopback 39xxx port, passed to the harness with --peer; nothing is
# inherited from the environment and no real node, datadir, port, or systemd
# unit is touched. The harness itself only ever dials that listener during its
# peer precheck — the mock node ignores -connect entirely, so not one byte of
# real chain data can move.
#
# Usage:
#   tools/scripts/stopwatch_artifact_symmetry_check.sh            # prove the in-tree harness
#   tools/scripts/stopwatch_artifact_symmetry_check.sh --harness=/path/to/older/copy.sh
#   tools/scripts/stopwatch_artifact_symmetry_check.sh --selftest # mutation-test THIS checker
#   tools/scripts/stopwatch_artifact_symmetry_check.sh --keep     # leave artifacts for inspection
#
# Exit codes: 0 symmetric (or selftest passed) / 1 asymmetric or broken /
#             2 prerequisite absent (no nc listener available) — a SKIP, never
#               laundered into a pass.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tools/scripts/source_identity_lib.sh
# The ONE source-identity reader — zcl_is_sha256 is used by check 11. Do NOT
# inline a local 64-hex validator here: tools/lint/check_identity_parser_single.sh
# counts those and this file carries no baseline row, so it may carry ZERO.
. "$REPO_ROOT/tools/scripts/source_identity_lib.sh"

HARNESS="$REPO_ROOT/tools/scripts/cold_start_to_tip_stopwatch.sh"
SELFTEST=0
KEEP=0
# The fixture peer port. NAMED here, never inherited: a proof lane that takes
# its peer from the environment can be pointed at a live node by accident.
FIXTURE_PEER_PORT="${ZCL_SYM_PEER_PORT:-39178}"
FIXTURE_PEER="127.0.0.1:$FIXTURE_PEER_PORT"

for arg in "$@"; do
    case "$arg" in
        --harness=*) HARNESS="${arg#--harness=}" ;;
        --selftest)  SELFTEST=1 ;;
        --keep)      KEEP=1 ;;
        *) echo "symmetry: unknown flag: $arg" >&2; exit 1 ;;
    esac
done

fail_count=0
ck() {  # desc, ok(0/1)
    if [ "$2" = 0 ]; then
        echo "  ok: $1"
    else
        echo "  FAIL: $1"
        fail_count=$((fail_count + 1))
    fi
}

# ── the comparison, as a PURE function of two artifact directories ───────────
#
# Pure on purpose: --selftest drives it against synthetic directory pairs, so
# every assertion below can be individually broken and shown to go red without
# running a node. A comparison that can only be exercised end-to-end is a
# comparison nobody can mutation-test.
#
# Sets fail_count. Echoes one `ok:`/`FAIL:` line per named check.

# pj_top_keys <proof.json> — the TOP-LEVEL key names, one per line, sorted.
# The emitter indents top-level keys with exactly two spaces and nested ones
# with four, so the anchored two-space match cannot pick up a nested key.
pj_top_keys() { grep -oE '^  "[a-z_0-9]+":' "$1" 2>/dev/null | tr -d ' ":' | sort; }
# pj_scalar <proof.json> <key> — the first top-level scalar value of <key>,
# unquoted, or empty.
pj_scalar() {
    grep -oE "\"$2\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|-?[0-9]+|true|false|null)" "$1" 2>/dev/null |
        head -1 | sed -E "s/^\"$2\"[[:space:]]*:[[:space:]]*//; s/^\"//; s/\"$//"
}
# pj_phase_names / pj_omitted_names — the multi-valued sets, sorted.
pj_phase_names() { pj_array_blob "$1" phases | grep -o '"phase":"[^"]*"' | sed 's/.*:"//; s/"$//' | sort; }
pj_omitted_names() { pj_array_blob "$1" omitted_fields | grep -o '"field":"[^"]*"' | sed 's/.*:"//; s/"$//' | sort; }
pj_count() { grep -o "$2" "$1" 2>/dev/null | wc -l | tr -d ' '; }
# pj_array_blob <proof.json> <key> — just the `"<key>": [...]` line. Counting a
# key inside an array MUST be scoped to that array: proof.json carries a
# TOP-LEVEL "reason" (the verdict's reason string) as well as one "reason" per
# omitted_fields[] row, so an unscoped `grep -c '"reason":'` returns 7 against 6
# rows and the check fails for a reason that has nothing to do with the rows.
# Both arrays are emitted on one line each, which is what makes this exact.
pj_array_blob() { grep -o "\"$2\":[[:space:]]*\[.*" "$1" 2>/dev/null | head -1; }
blob_count() { printf '%s' "$1" | grep -o "$2" 2>/dev/null | wc -l | tr -d ' '; }
dir_files() { (cd "$1" 2>/dev/null && ls -1A 2>/dev/null | sort); }

compare_artifacts() {  # pass_dir, nonpass_dir
    local pd="$1" nd="$2" pp="$1/proof.json" np="$2/proof.json" rc

    [ -s "$pp" ] && [ -s "$np" ]
    ck "both runs left a non-empty proof.json (a run with no artifact proves nothing)" $?
    if [ ! -s "$pp" ] || [ ! -s "$np" ]; then return 1; fi

    # ANTI-VACUITY, and it comes first on purpose. Two runs that both passed
    # would satisfy every remaining check trivially — that is precisely the
    # hollow-proof shape this repo has been burned by. The two artifacts must
    # genuinely straddle the pass/non-pass boundary or the symmetry claim means
    # nothing.
    local pv nv
    pv="$(pj_scalar "$pp" verdict)"; nv="$(pj_scalar "$np" verdict)"
    [ "$pv" = "pass" ] && [ -n "$nv" ] && [ "$nv" != "pass" ]
    rc=$?
    ck "the two runs straddle the pass/non-pass boundary (got verdict='$pv' vs verdict='$nv'; must be 'pass' vs a non-pass, never pass-vs-pass)" "$rc"

    # THE PARENT-FAILING CHECK. On the pre-fix harness the pass run left
    # proof.json + node.log + node.tail.log while the non-pass run left the
    # whole bundle, so these two listings differ by ~15 files.
    local pf nf
    pf="$(dir_files "$pd")"; nf="$(dir_files "$nd")"
    [ "$pf" = "$nf" ]
    ck "the two artifact dirs contain the IDENTICAL file set (capture is not gated on the verdict)" $?
    if [ "$pf" != "$nf" ]; then
        echo "      only in the pass artifact:    $(comm -23 <(printf '%s\n' "$pf") <(printf '%s\n' "$nf") | paste -sd, -)"
        echo "      only in the non-pass artifact: $(comm -13 <(printf '%s\n' "$pf") <(printf '%s\n' "$nf") | paste -sd, -)"
    fi

    [ "$(pj_top_keys "$pp")" = "$(pj_top_keys "$np")" ]
    ck "the two proof.json files carry the IDENTICAL top-level field set" $?

    # Capture must have been ATTEMPTED AND SUCCEEDED on both sides. This is the
    # behavioural half of the claim: an identical file set could in principle be
    # reached by capturing nothing on either side, and this is what rules that
    # out — bundle_capture_failed is set false only after every piece landed.
    [ "$(pj_scalar "$pp" bundle_capture_failed)" = "false" ] &&
        [ "$(pj_scalar "$np" bundle_capture_failed)" = "false" ]
    ck "bundle_capture_failed is false on BOTH runs (every bundle piece landed on the pass side too)" $?

    local ppn npn
    ppn="$(pj_phase_names "$pp")"; npn="$(pj_phase_names "$np")"
    [ -n "$ppn" ] && [ -n "$npn" ]
    ck "both proof.json carry a NON-EMPTY phases[] array" $?
    [ "$ppn" = "$npn" ]
    ck "the set of phase names is identical across the two runs" $?

    # Provenance: a phase duration with no named source is the "confident answer
    # it never earned" defect. Every element must say where its number came from.
    # NOTE ON `rc=$?` — DO NOT INLINE A COMMAND SUBSTITUTION INTO A ck
    # DESCRIPTION. `ck "... $(basename x) ..." $?` expands the arguments left to
    # right, so basename runs BEFORE $? is read and clobbers it with its own
    # (successful) status: the check then passes unconditionally and can never
    # go red. That defect was live in this file's first draft and --selftest's
    # provenance and reason mutations are what caught it. Capture rc on its own
    # line, immediately after the test, and pass "$rc".
    local pc ps_ side blob
    for f in "$pp" "$np"; do
        side="$(basename "$(dirname "$f")")"
        blob="$(pj_array_blob "$f" phases)"
        pc="$(blob_count "$blob" '"phase":')"
        ps_="$(blob_count "$blob" '"duration_source":')"
        [ "$pc" -gt 0 ] 2>/dev/null && [ "$pc" = "$ps_" ]
        rc=$?
        ck "every phases[] element in $side names its duration_source ($ps_/$pc)" "$rc"
    done

    # The per-sample series, so a run can be re-analysed instead of only
    # summarised once.
    local ph nh
    ph="$(head -1 "$pd/samples.tsv" 2>/dev/null)"; nh="$(head -1 "$nd/samples.tsv" 2>/dev/null)"
    [ -n "$ph" ] && [ "$ph" = "$nh" ]
    ck "both artifacts carry samples.tsv with an identical header row" $?
    [ "$(awk 'NR>1' "$pd/samples.tsv" 2>/dev/null | wc -l)" -gt 0 ] 2>/dev/null &&
        [ "$(awk 'NR>1' "$nd/samples.tsv" 2>/dev/null | wc -l)" -gt 0 ] 2>/dev/null
    ck "both samples.tsv carry at least one data row (the series was actually written, not just headed)" $?
    [ "$(pj_scalar "$pp" samples_tsv)" = "samples.tsv" ] &&
        [ "$(pj_scalar "$np" samples_tsv)" = "samples.tsv" ]
    ck "both proof.json point at their samples.tsv by name" $?

    # Named absence. Anything the measurement brief asked for that this run
    # could not measure must be in the artifact BY NAME — silent absence reads
    # as "measured and fine".
    local pon non
    pon="$(pj_omitted_names "$pp")"; non="$(pj_omitted_names "$np")"
    [ -n "$pon" ] && [ -n "$non" ]
    ck "both proof.json carry a NON-EMPTY omitted_fields[] array" $?
    [ "$pon" = "$non" ]
    ck "the set of omitted field names is identical across the two runs" $?
    for f in "$pp" "$np"; do
        side="$(basename "$(dirname "$f")")"
        blob="$(pj_array_blob "$f" omitted_fields)"
        pc="$(blob_count "$blob" '"field":')"
        ps_="$(blob_count "$blob" '"reason":')"
        [ "$pc" -gt 0 ] 2>/dev/null && [ "$pc" = "$ps_" ]
        rc=$?
        ck "every omitted_fields[] row in $side carries a reason ($ps_/$pc)" "$rc"
    done

    # Source identity, read through the shared lib's validator. The mock's
    # agentbuild emits source_id_sha256 twice on one line with DIFFERENT values;
    # a greedy reader returns the second. Requiring the FIRST is what makes a
    # regression to the greedy form fail here.
    local pid_ nid_
    pid_="$(pj_scalar "$pp" node_bin_source_id_sha256)"
    nid_="$(pj_scalar "$np" node_bin_source_id_sha256)"
    zcl_is_sha256 "$pid_" && zcl_is_sha256 "$nid_"
    ck "both proof.json record a well-formed 64-hex node_bin_source_id_sha256" $?
    [ -n "$pid_" ] && [ "$pid_" = "$nid_" ]
    ck "both runs recorded the SAME source identity (same binary was measured twice)" $?
    if [ -n "${ZCL_SYM_EXPECT_FIRST_ID:-}" ]; then
        [ "$pid_" = "$ZCL_SYM_EXPECT_FIRST_ID" ]
        ck "the recorded identity is the FIRST source_id_sha256 agentbuild emitted, not the last (the greedy-sed bug)" $?
    fi
    return 0
}

# ── the mock node ────────────────────────────────────────────────────────────
# A shell script that answers the handful of invocations the harness makes. It
# is NOT a test hook in the harness: the harness is driven unmodified and
# believes it is running a node binary.
FIRST_ID="a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
LAST_ID="b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"

write_mock_node() {  # dest
    cat >"$1" <<'MOCK'
#!/usr/bin/env bash
# Mock zclassic23 for stopwatch_artifact_symmetry_check.sh. Answers only what
# the C3 harness asks. ZCL_MOCK_MODE=pass|seam, ZCL_MOCK_STATE=<counter file>.
set -uo pipefail
mode="${ZCL_MOCK_MODE:-seam}"
state="${ZCL_MOCK_STATE:-/tmp/zcl-mock-state}"
leaf=""; key=""
for a in "$@"; do
    case "$a" in
        -*) [ "$a" = "--importblockindex" ] && leaf=importblockindex ;;
        agentbuild|dumpstate|ops|status) [ -z "$leaf" ] && leaf="$a" ;;
        *) [ -n "$leaf" ] && [ -z "$key" ] && key="$a" ;;
    esac
done
case "$leaf" in
    agentbuild)
        # source_id_sha256 emitted TWICE ON ONE LINE with different values, the
        # shape that makes a greedy sed return the LAST one. First = baked.
        printf '{"source_id_sha256":"%s","runtime":{"lane":{"source_id_sha256":"%s"}}}\n' \
            "${ZCL_MOCK_FIRST_ID:?}" "${ZCL_MOCK_LAST_ID:?}"
        exit 0 ;;
    importblockindex)
        echo "[mock] header import ok"
        exit 0 ;;
    dumpstate)
        case "$key" in
            reducer_frontier)
                n=0
                [ -f "$state" ] && n="$(cat "$state" 2>/dev/null)"
                case "$n" in ''|*[!0-9]*) n=0 ;; esac
                n=$((n + 1)); printf '%s' "$n" >"$state" 2>/dev/null || true
                if [ "$mode" = "pass" ]; then
                    printf '{"cached_provable_tip":3200000,"hstar":3200000,"network_tip":3200000,"network_tip_read_ok":true}\n'
                else
                    printf '{"cached_provable_tip":%s,"hstar":%s,"network_tip":3200000,"network_tip_read_ok":true}\n' \
                        "$((3100000 + n * 100))" "$((3100000 + n * 100))"
                fi
                exit 0 ;;
            blocker)
                printf '{"active_count":0,"blockers":[]}\n'; exit 0 ;;
            sync_monitor)
                # Serves a MONOTONICALLY GROWING download_bytes_received off its
                # own counter file, so the harness's window-open and window-close
                # reads differ and the end-to-end run exercises the MEASURED byte
                # path rather than only the -1 fail-closed path. The catch-all
                # below would return a doc with no byte key at all, which every
                # run would then honestly report as unavailable — green, but
                # proving nothing about the arithmetic.
                b=0
                [ -f "$state.bytes" ] && b="$(cat "$state.bytes" 2>/dev/null)"
                case "$b" in ''|*[!0-9]*) b=0 ;; esac
                b=$((b + 1048576)); printf '%s' "$b" >"$state.bytes" 2>/dev/null || true
                printf '{"last_recovery":"NONE","download_requested":10,"download_bytes_received":%s,"download_mbps_avg":1.0}\n' "$b"
                exit 0 ;;
            boot_timings)
                printf '{"last_boot_epoch":7,"stages":[{"stage":"prologue","last_ms":63,"median_ms":70},{"stage":"total","last_ms":420,"median_ms":430}]}\n'
                exit 0 ;;
            *)
                printf '{"mock_dumpstate":"%s","ok":true}\n' "$key"; exit 0 ;;
        esac ;;
    ops)
        printf '[mock] ops logs line 1\n[mock] ops logs line 2\n'; exit 0 ;;
esac
# No leaf command -> this is the node boot. Emit the same [boot] marker shapes
# engine/composition/src/boot.c does (one space = top-level, three = sub-phase), plus the
# prose "[boot] ..." decoys a looser parser would turn into invented phases.
printf '%s INFO mock node starting\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '[boot] %-30s %sms\n' prologue 63
printf '[boot]   %-28s %sms\n' sqlite.quick_check 7
printf '[boot] block_index: 1 entries, 296 bytes/entry, index=0MB\n'
printf '[boot] system_ram=95654MB block_index_estimate=1121MB (3000000 entries)\n'
printf '[boot]   %-28s %sms\n' progress_store.open 12
printf '[boot] %-30s %sms\n' total 420
exec sleep 3600
MOCK
    chmod +x "$1"
}

# ── the two real harness runs ────────────────────────────────────────────────
run_one() {  # mode(pass|seam), root, mock_bin, header_src, params_dir  -> echoes artifact dir
    local mode="$1" root="$2" mock="$3" hdr="$4" params="$5" out
    out="$(
        ZCL_MOCK_MODE="$mode" \
        ZCL_MOCK_STATE="$root/mock.counter" \
        ZCL_MOCK_FIRST_ID="$FIRST_ID" \
        ZCL_MOCK_LAST_ID="$LAST_ID" \
        ZCL_CS_ARTIFACT_ROOT="$root" \
        ZCL_CS_RUN_ID="$mode" \
        ZCL_CS_BUDGET_SECS=2 \
        ZCL_CS_SAMPLE_SECS=1 \
        ZCL_CS_HEADER_SOURCE="$hdr" \
        ZCL_CS_PARAMS_DIR="$params" \
        bash "$HARNESS" --bin="$mock" --peer="$FIXTURE_PEER" 2>&1
    )"
    printf '%s\n' "$out" >"$root/harness.$mode.log"
    printf '%s' "$root/$mode"
}

# ── --selftest: mutation-test the comparison above ───────────────────────────
#
# WHY THIS MODE IS NOT OPTIONAL. A self-test in this repo was recently found
# hollow: three "bad input is refused" assertions all passed for an unrelated
# reason, and disabling the validator entirely still printed PASS. So every
# check in compare_artifacts() is exercised here by BREAKING exactly the thing
# it claims to check on a synthetic-but-well-formed pair and requiring that the
# comparison goes red — and requiring that the UNBROKEN pair goes green, which
# is what rules out a comparison that always fails.
st_fail=0
st_expect() {  # desc, expect(pass|fail), dir_pass, dir_nonpass
    local got out
    out="$(fail_count=0; compare_artifacts "$3" "$4" >/dev/null 2>&1; echo "$fail_count")"
    if [ "$out" = "0" ]; then got=pass; else got=fail; fi
    if [ "$got" = "$2" ]; then
        echo "  ok: $1 -> $got"
    else
        echo "  FAIL: $1 -> expected $2, got $got ($out failing checks)"
        st_fail=1
    fi
}

# synth_pair <root> — a synthetic PASS/NON-PASS artifact pair that the
# comparison accepts. Every mutation below starts from a fresh copy of this.
synth_pair() {
    local root="$1" v d
    for v in pass seam; do
        d="$root/$v"; mkdir -p "$d"
        {
            printf '{\n'
            printf '  "schema": "zcl.c3_stopwatch_artifact.v1",\n'
            printf '  "verdict": "%s",\n' "$v"
            # A TOP-LEVEL "reason" on purpose: the real emitter has one (the
            # verdict's reason string) and an unscoped count of '"reason":'
            # therefore returns rows+1 and fails a healthy artifact. That
            # false-fail was live in this file's first draft; keeping the
            # top-level key in the CONTROL fixture is what stops it recurring.
            printf '  "reason": "budget expired before H* caught the peer tip",\n'
            printf '  "bundle_capture_failed": false,\n'
            printf '  "samples_tsv": "samples.tsv",\n'
            printf '  "measured_identity": {\n'
            printf '    "node_bin_source_id_sha256": "%s"\n' "$FIRST_ID"
            printf '  },\n'
            printf '  "phases": [{"phase":"harness.observed_sync","duration_ms":1000,"duration_source":"harness wall clock"},{"phase":"prologue","duration_ms":63,"duration_source":"node_log_boot_marker"}],\n'
            printf '  "omitted_fields": [{"field":"phases[].network_bytes","scope":"structural","reason":"no dumper exposes a byte counter"}]\n'
            printf '}\n'
        } >"$d/proof.json"
        printf 't_s\tunix_s\thstar\n' >"$d/samples.tsv"
        printf '0\t1\t3100000\n' >>"$d/samples.tsv"
        : >"$d/frontier.json"
        : >"$d/node.log"
    done
}

if [ "$SELFTEST" = "1" ]; then
    export ZCL_SYM_EXPECT_FIRST_ID="$FIRST_ID"
    ST_ROOT="$(mktemp -d /tmp/zcl-sym-selftest.XXXXXX)" || exit 1
    trap 'rm -rf "$ST_ROOT" 2>/dev/null || true' EXIT INT TERM
    echo "symmetry --selftest: mutation-testing the comparison"

    # The unbroken control. If this were the only check, a comparison that
    # always failed would look identical to a working one — hence the control
    # AND a mutation per assertion.
    mk() { rm -rf "$ST_ROOT/$1"; mkdir -p "$ST_ROOT/$1"; synth_pair "$ST_ROOT/$1"; }
    mk control
    st_expect "CONTROL: an untouched well-formed pair" pass "$ST_ROOT/control/pass" "$ST_ROOT/control/seam"

    mk m_noproof; rm -f "$ST_ROOT/m_noproof/seam/proof.json"
    st_expect "MUTATION: non-pass proof.json removed" fail "$ST_ROOT/m_noproof/pass" "$ST_ROOT/m_noproof/seam"

    mk m_vacuous
    st_expect "MUTATION: pass compared against ITSELF (the hollow pass-vs-pass proof)" fail \
        "$ST_ROOT/m_vacuous/pass" "$ST_ROOT/m_vacuous/pass"

    mk m_files; rm -f "$ST_ROOT/m_files/pass/frontier.json"
    st_expect "MUTATION: pass artifact missing frontier.json (the original asymmetry)" fail \
        "$ST_ROOT/m_files/pass" "$ST_ROOT/m_files/seam"

    mk m_keys; sed -i 's/  "schema":/  "scheme":/' "$ST_ROOT/m_keys/pass/proof.json"
    st_expect "MUTATION: a top-level field renamed on one side only" fail \
        "$ST_ROOT/m_keys/pass" "$ST_ROOT/m_keys/seam"

    mk m_capfail; sed -i 's/"bundle_capture_failed": false/"bundle_capture_failed": true/' \
        "$ST_ROOT/m_capfail/pass/proof.json"
    st_expect "MUTATION: pass run reports a dropped bundle piece" fail \
        "$ST_ROOT/m_capfail/pass" "$ST_ROOT/m_capfail/seam"

    mk m_nophase; sed -i 's/  "phases": \[.*\],/  "phases": [],/' "$ST_ROOT/m_nophase/pass/proof.json"
    st_expect "MUTATION: pass run has an EMPTY phases[] array" fail \
        "$ST_ROOT/m_nophase/pass" "$ST_ROOT/m_nophase/seam"

    mk m_phasename; sed -i 's/"phase":"prologue"/"phase":"prologue_x"/' "$ST_ROOT/m_phasename/seam/proof.json"
    st_expect "MUTATION: the two runs report different phase NAMES" fail \
        "$ST_ROOT/m_phasename/pass" "$ST_ROOT/m_phasename/seam"

    mk m_prov; sed -i 's/,"duration_source":"node_log_boot_marker"//' "$ST_ROOT/m_prov/pass/proof.json"
    st_expect "MUTATION: a phase carries a duration with NO provenance" fail \
        "$ST_ROOT/m_prov/pass" "$ST_ROOT/m_prov/seam"

    mk m_nosamples; rm -f "$ST_ROOT/m_nosamples/pass/samples.tsv"
    st_expect "MUTATION: pass run left no samples.tsv" fail \
        "$ST_ROOT/m_nosamples/pass" "$ST_ROOT/m_nosamples/seam"

    mk m_samplehdr; sed -i '1s/.*/t_s\tOTHER/' "$ST_ROOT/m_samplehdr/pass/samples.tsv"
    st_expect "MUTATION: the two samples.tsv have different columns" fail \
        "$ST_ROOT/m_samplehdr/pass" "$ST_ROOT/m_samplehdr/seam"

    mk m_headonly; head -1 "$ST_ROOT/m_headonly/pass/samples.tsv" >"$ST_ROOT/m_headonly/pass/samples.tsv.t"
    mv "$ST_ROOT/m_headonly/pass/samples.tsv.t" "$ST_ROOT/m_headonly/pass/samples.tsv"
    st_expect "MUTATION: samples.tsv has a header but ZERO data rows" fail \
        "$ST_ROOT/m_headonly/pass" "$ST_ROOT/m_headonly/seam"

    mk m_samplesref; sed -i 's/"samples_tsv": "samples.tsv"/"samples_tsv": null/' \
        "$ST_ROOT/m_samplesref/pass/proof.json"
    st_expect "MUTATION: proof.json does not name its samples.tsv" fail \
        "$ST_ROOT/m_samplesref/pass" "$ST_ROOT/m_samplesref/seam"

    mk m_noomit; sed -i 's/  "omitted_fields": \[.*\]/  "omitted_fields": []/' \
        "$ST_ROOT/m_noomit/pass/proof.json"
    st_expect "MUTATION: pass run has an EMPTY omitted_fields[] (silent absence returns)" fail \
        "$ST_ROOT/m_noomit/pass" "$ST_ROOT/m_noomit/seam"

    mk m_omitset; sed -i 's/"field":"phases\[\].network_bytes"/"field":"something_else"/' \
        "$ST_ROOT/m_omitset/seam/proof.json"
    st_expect "MUTATION: the two runs omit DIFFERENT fields" fail \
        "$ST_ROOT/m_omitset/pass" "$ST_ROOT/m_omitset/seam"

    mk m_omitreason; sed -i 's/,"reason":"no dumper exposes a byte counter"//' \
        "$ST_ROOT/m_omitreason/pass/proof.json"
    st_expect "MUTATION: an omitted field is named with NO reason" fail \
        "$ST_ROOT/m_omitreason/pass" "$ST_ROOT/m_omitreason/seam"

    mk m_badid; sed -i "s/$FIRST_ID/deadbeef/" "$ST_ROOT/m_badid/pass/proof.json"
    st_expect "MUTATION: source identity is not 64-hex" fail \
        "$ST_ROOT/m_badid/pass" "$ST_ROOT/m_badid/seam"

    mk m_greedy; sed -i "s/$FIRST_ID/$LAST_ID/" "$ST_ROOT/m_greedy/pass/proof.json"
    st_expect "MUTATION: the LAST source_id_sha256 was recorded instead of the first (greedy sed)" fail \
        "$ST_ROOT/m_greedy/pass" "$ST_ROOT/m_greedy/seam"

    if [ "$st_fail" = 0 ]; then
        echo "selftest: PASS"
        exit 0
    fi
    echo "selftest: FAIL" >&2
    exit 1
fi

# ── real drive ───────────────────────────────────────────────────────────────
command -v nc >/dev/null 2>&1 || {
    echo "symmetry: SKIP (no nc available to stand up the named loopback fixture peer)"
    exit 2
}
[ -f "$HARNESS" ] || { echo "symmetry: FAIL harness not found: $HARNESS" >&2; exit 1; }

ROOT="$(mktemp -d /tmp/zcl-sym.XXXXXX)" || exit 1
NC_PID=""
cleanup() {
    [ -n "$NC_PID" ] && kill -KILL "$NC_PID" 2>/dev/null || true
    if [ "$KEEP" = 1 ]; then
        echo "symmetry: artifacts kept under $ROOT"
    else
        case "$ROOT" in /tmp/zcl-sym.*) rm -rf "$ROOT" 2>/dev/null || true ;; esac
    fi
}
trap cleanup EXIT INT TERM

MOCK="$ROOT/zclassic23-mock"
write_mock_node "$MOCK"
mkdir -p "$ROOT/header-src" "$ROOT/params" "$ROOT/a-pass" "$ROOT/a-seam"

# The fixture peer: OUR listener, on the port named at the top of this file.
# The mock node ignores -connect, so this exists purely to satisfy the harness's
# peer precheck — no chain data can move across it.
nc -l -k -d 127.0.0.1 "$FIXTURE_PEER_PORT" >/dev/null 2>&1 &
NC_PID=$!
# disown so the SIGKILL in cleanup() does not print a job-control "Killed"
# line that reads like a harness crash in the captured output.
disown "$NC_PID" 2>/dev/null || true
sleep 1
if ! timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$FIXTURE_PEER_PORT" 2>/dev/null; then
    echo "symmetry: SKIP (could not stand up the fixture listener on $FIXTURE_PEER)"
    exit 2
fi

echo "symmetry: harness=$HARNESS"
echo "symmetry: fixture peer=$FIXTURE_PEER (a listener THIS script spawned; nothing inherited)"
echo "symmetry: forcing a PASS run..."
PASS_DIR="$(run_one pass "$ROOT/a-pass" "$MOCK" "$ROOT/header-src" "$ROOT/params")"
echo "symmetry: forcing a NON-PASS run..."
NONPASS_DIR="$(run_one seam "$ROOT/a-seam" "$MOCK" "$ROOT/header-src" "$ROOT/params")"
echo "symmetry: pass artifact=$PASS_DIR"
echo "symmetry: non-pass artifact=$NONPASS_DIR"

export ZCL_SYM_EXPECT_FIRST_ID="$FIRST_ID"
compare_artifacts "$PASS_DIR" "$NONPASS_DIR"

if [ "$fail_count" = 0 ]; then
    echo "symmetry: PASS (the pass and non-pass runs recorded the same evidence set)"
    exit 0
fi
echo "symmetry: FAIL ($fail_count asymmetry/provenance checks failed)" >&2
exit 1
