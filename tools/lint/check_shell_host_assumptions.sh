#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Shrink-only rail for shell commands whose spellings silently assume Linux/GNU.

set -euo pipefail

GATE=check-shell-host-assumptions
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASELINE="${ZCL_SHELL_HOST_BASELINE:-$ROOT/tools/lint/shell_host_assumptions_baseline.txt}"
FILE_FLOOR="${ZCL_SHELL_HOST_FILE_FLOOR:-400}"
SS_CEILING="${ZCL_SHELL_HOST_SS_CEILING:-63}"
NPROC_CEILING="${ZCL_SHELL_HOST_NPROC_CEILING:-36}"
STAT_CEILING="${ZCL_SHELL_HOST_STAT_CEILING:-108}"
SED_CEILING="${ZCL_SHELL_HOST_SED_CEILING:-22}"

fail()
{
    printf '[%s] FATAL — %s\n' "$GATE" "$*" >&2
    exit 2
}

scan_file()
{
    local path="$1"
    awk -v path="$path" '
    function emit_matches(kind, re, text,    before, after) {
        while (match(text, re)) {
            print kind "\t" path
            before = substr(text, 1, RSTART - 1)
            after = substr(text, RSTART + RLENGTH)
            text = before " " after
        }
    }
    function classify(line,    t) {
        t=line
        gsub(/"/," ",t)
        gsub(sprintf("%c",39)," ",t)
        emit_matches("ss","(^|[[:space:];&|()/])ss([[:space:];&|()]|$)",t)
        emit_matches("nproc","(^|[[:space:];&|()/])nproc([[:space:];&|()]|$)",t)
        emit_matches("stat","(^|[[:space:];&|()/])stat[[:space:]]+([^;&|()[:space:]]+[[:space:]]+)*-[A-Za-z]*c[^;&|()[:space:]]*",t)
        emit_matches("sed","(^|[[:space:];&|()/])sed[[:space:]]+([^;&|()[:space:]]+[[:space:]]+)*-[A-Za-z]*i[^;&|()[:space:]]*",t)
    }
    BEGIN { logical="" }
    {
        # Scan raw lexical spellings, including comments, quotes, and heredoc
        # bodies.  Shell fragments can be handed to another interpreter, and
        # a partial parser creates bypasses.  The baseline absorbs prose noise.
        code=$0
        if (code ~ /\\[[:space:]]*$/) {
            sub(/\\[[:space:]]*$/,"",code); logical=logical " " code
        } else {
            logical=logical " " code; classify(logical); logical=""
        }
    }
    END { if (logical != "") classify(logical) }
    ' "$path"
}

collect_rows()
{
    local file
    [ "${ZCL_SHELL_HOST_INJECT_SCAN_FAILURE:-0}" != 1 ] || return 9
    for file in "$@"; do
        [ -f "$file" ] || fail "tracked shell input is missing: $file"
        [ "$file" != "${ZCL_SHELL_HOST_INJECT_SCAN_PATH:-}" ] || return 9
        scan_file "$file" || return $?
    done | awk -F '\t' '{ counts[$1,$2]++ } END {
        for (key in counts) {
            split(key, fields, SUBSEP)
            print fields[1] "\t" fields[2] "\t" counts[key]
        }
    }'
}

ceiling_for()
{
    case "$1" in
        ss) printf '%s\n' "$SS_CEILING" ;;
        nproc) printf '%s\n' "$NPROC_CEILING" ;;
        stat) printf '%s\n' "$STAT_CEILING" ;;
        sed) printf '%s\n' "$SED_CEILING" ;;
        *) fail "unknown assumption kind: $1" ;;
    esac
}

run_gate()
{
    local -a files=() rows=() violations=()
    local kind path count key ceiling total file_list collected baseline_tmp bootstrap=0
    declare -A actual=() allowed=() totals=([ss]=0 [nproc]=0 [stat]=0 [sed]=0)

    if [ -n "${ZCL_SHELL_HOST_SCAN_DIR:-}" ]; then
        file_list="$(find "$ZCL_SHELL_HOST_SCAN_DIR" -type f -name '*.sh' -print | LC_ALL=C sort)" ||
            fail 'could not enumerate shell fixture inputs'
    else
        file_list="$(cd "$ROOT" && git ls-files --cached --others --exclude-standard '*.sh' | LC_ALL=C sort)" ||
            fail 'could not enumerate tracked shell inputs'
    fi
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        if [ -z "${ZCL_SHELL_HOST_SCAN_DIR:-}" ]; then
            [ "$path" = tools/lint/check_shell_host_assumptions.sh ] && continue
            path="$ROOT/$path"
        fi
        files+=("$path")
    done <<<"$file_list"
    [ "${#files[@]}" -ge "$FILE_FLOOR" ] ||
        fail "shell scan found ${#files[@]} file(s), floor is $FILE_FLOOR"

    if ! collected="$(collect_rows "${files[@]}")"; then
        fail 'shell assumption scanner failed'
    fi
    while IFS=$'\t' read -r kind path count; do
        [ -n "$kind" ] || continue
        if [[ "$path" == "$ROOT/"* ]]; then path="${path#"$ROOT/"}"; fi
        key="$kind"$'\t'"$path"
        actual["$key"]="$count"
        totals["$kind"]=$((totals[$kind] + count))
        rows+=("$kind"$'\t'"$path"$'\t'"$count")
    done <<<"$collected"

    for kind in ss nproc stat sed; do
        ceiling="$(ceiling_for "$kind")"
        [[ "$ceiling" =~ ^[0-9]+$ ]] || fail "$kind ceiling is not numeric"
        [ "${totals[$kind]}" -le "$ceiling" ] ||
            violations+=("$kind total ${totals[$kind]} exceeds ceiling $ceiling")
    done

    if [ -f "$BASELINE" ]; then
        while IFS=$'\t' read -r kind path count; do
            case "$kind" in ''|'#'*) continue ;; esac
            [[ "$count" =~ ^[0-9]+$ ]] || fail "baseline count is not numeric: $kind $path $count"
            key="$kind"$'\t'"$path"
            [ -z "${allowed[$key]+x}" ] || fail "duplicate baseline row: $kind $path"
            allowed["$key"]="$count"
        done < "$BASELINE"
    else
        if [ "${ZCL_SHELL_HOST_INJECT_TRACKED_BASELINE:-0}" = 1 ]; then
            fail "tracked baseline is missing from the worktree: $BASELINE"
        fi
        case "$BASELINE" in
            "$ROOT"/*)
                if git -C "$ROOT" ls-files --error-unmatch -- \
                    "${BASELINE#"$ROOT/"}" >/dev/null 2>&1; then
                    fail "tracked baseline is missing from the worktree: $BASELINE"
                fi ;;
        esac
        if [ "${ZCL_LINT_MODE:-FAIL}" = UPDATE ] && [ "${ZCL_SHELL_HOST_BOOTSTRAP:-0}" = 1 ]; then
            bootstrap=1
        else
            fail "baseline is missing: $BASELINE"
        fi
    fi

    for key in "${!actual[@]}"; do
        if [ -z "${allowed[$key]+x}" ] && [ "$bootstrap" != 1 ]; then
            violations+=("${key//$'\t'/ } count=${actual[$key]} is new")
        elif [ -n "${allowed[$key]+x}" ] && [ "${actual[$key]}" -gt "${allowed[$key]}" ]; then
            violations+=("${key//$'\t'/ } actual=${actual[$key]} baseline=${allowed[$key]} grew")
        elif [ "${ZCL_LINT_MODE:-FAIL}" != UPDATE ] && [ -n "${allowed[$key]+x}" ] && [ "${actual[$key]}" -ne "${allowed[$key]}" ]; then
            violations+=("${key//$'\t'/ } actual=${actual[$key]} baseline=${allowed[$key]}")
        fi
    done
    if [ "${ZCL_LINT_MODE:-FAIL}" != UPDATE ]; then
        for key in "${!allowed[@]}"; do
            [ -n "${actual[$key]+x}" ] ||
                violations+=("${key//$'\t'/ } actual=0 baseline=${allowed[$key]} (stale row)")
        done
    fi

    if [ "${#violations[@]}" -gt 0 ]; then
        printf '[%s] FAIL — shell host-assumption debt changed:\n' "$GATE" >&2
        printf '  %s\n' "${violations[@]}" | LC_ALL=C sort >&2
        printf 'Fix the command with a portable helper/fallback, then shrink with:\n' >&2
        printf '  ZCL_LINT_MODE=UPDATE tools/lint/check_shell_host_assumptions.sh\n' >&2
        return 1
    fi
    if [ "${ZCL_LINT_MODE:-FAIL}" = UPDATE ]; then
        baseline_tmp="$(mktemp "${BASELINE}.tmp.XXXXXX")" || fail 'could not create baseline temporary'
        {
            printf '# %s shrink-only baseline\n' "$GATE"
            printf '# Format: <kind> TAB <tracked path> TAB <count>. Counts may only shrink.\n'
            printf '%s\n' "${rows[@]}" | LC_ALL=C sort
        } > "$baseline_tmp"
        mv "$baseline_tmp" "$BASELINE"
        printf '[%s] baseline UPDATED: %s\n' "$GATE" "$BASELINE"
        return 0
    fi
    total=$((totals[ss] + totals[nproc] + totals[stat] + totals[sed]))
    printf '[%s] PASS files=%s sites=%s ss=%s nproc=%s stat=%s sed=%s\n' \
        "$GATE" "${#files[@]}" "$total" "${totals[ss]}" \
        "${totals[nproc]}" "${totals[stat]}" "${totals[sed]}"
}

selftest()
(
    local work fixture baseline output saved fixture_saved clean_fixture
    work="$(mktemp -d "${TMPDIR:-/tmp}/z23-shell-host-gate.XXXXXX")" || exit 2
    trap 'rm -rf -- "$work"' EXIT
    fixture="$work/fixture.sh"; baseline="$work/baseline.txt"
    cat > "$fixture" <<'EOF_FIXTURE'
#!/usr/bin/env bash
# ss nproc stat -c sed -i are prose here.
single='ss nproc stat -c sed -i'
double="ss nproc stat -c sed -i"
true;# ss nproc stat -c sed -i are comments here too.
command -v ss >/dev/null
type -P nproc >/dev/null
cat <<'IGNORED'
ss -ltn
nproc
stat -c%s x
sed -i x
IGNORED
ss -ltn
jobs="$(nproc)"
stat -Lc%s artifact
sed -Ei.bak 's/a/b/' file
EOF_FIXTURE
    ZCL_SHELL_HOST_SCAN_DIR="$work" ZCL_SHELL_HOST_FILE_FLOOR=1 \
    ZCL_SHELL_HOST_BASELINE="$baseline" ZCL_SHELL_HOST_SS_CEILING=8 \
    ZCL_SHELL_HOST_NPROC_CEILING=8 ZCL_SHELL_HOST_STAT_CEILING=8 \
    ZCL_SHELL_HOST_SED_CEILING=8 ZCL_LINT_MODE=UPDATE \
    ZCL_SHELL_HOST_BOOTSTRAP=1 "$0" >/dev/null
    grep -Fqx "ss"$'\t'"$fixture"$'\t7' "$baseline" ||
        fail 'selftest scanner did not conservatively count ss spellings'
    grep -Fqx "nproc"$'\t'"$fixture"$'\t7' "$baseline" ||
        fail 'selftest scanner did not conservatively count nproc spellings'
    for kind in stat sed; do
        grep -Fqx "$kind"$'\t'"$fixture"$'\t6' "$baseline" ||
            fail "selftest scanner did not conservatively count $kind spellings"
    done
    output="$(ZCL_SHELL_HOST_SCAN_DIR="$work" ZCL_SHELL_HOST_FILE_FLOOR=1 \
        ZCL_SHELL_HOST_BASELINE="$baseline" ZCL_SHELL_HOST_SS_CEILING=8 \
        ZCL_SHELL_HOST_NPROC_CEILING=8 ZCL_SHELL_HOST_STAT_CEILING=8 \
        ZCL_SHELL_HOST_SED_CEILING=8 "$0")" || fail 'selftest positive control failed'
    saved="$work/baseline.saved"
    fixture_saved="$work/fixture.saved"
    cp "$baseline" "$saved"
    cp "$fixture" "$fixture_saved"
    printf '\nnproc\n' >> "$fixture"
    if ZCL_SHELL_HOST_SCAN_DIR="$work" ZCL_SHELL_HOST_FILE_FLOOR=1 \
       ZCL_SHELL_HOST_BASELINE="$baseline" ZCL_SHELL_HOST_SS_CEILING=8 \
       ZCL_SHELL_HOST_NPROC_CEILING=8 ZCL_SHELL_HOST_STAT_CEILING=8 \
       ZCL_SHELL_HOST_SED_CEILING=8 "$0" >/dev/null 2>&1; then
        fail 'selftest growth mutation passed'
    fi
    if ZCL_SHELL_HOST_SCAN_DIR="$work" ZCL_SHELL_HOST_FILE_FLOOR=1 \
       ZCL_SHELL_HOST_BASELINE="$baseline" ZCL_SHELL_HOST_SS_CEILING=8 \
       ZCL_SHELL_HOST_NPROC_CEILING=8 ZCL_SHELL_HOST_STAT_CEILING=8 \
       ZCL_SHELL_HOST_SED_CEILING=8 ZCL_LINT_MODE=UPDATE "$0" >/dev/null 2>&1; then
        fail 'selftest UPDATE authorized growth'
    fi
    cmp -s "$baseline" "$saved" || fail 'selftest failed UPDATE changed baseline'
    if ZCL_SHELL_HOST_SCAN_DIR="$work" ZCL_SHELL_HOST_FILE_FLOOR=1 \
       ZCL_SHELL_HOST_BASELINE="$baseline" ZCL_SHELL_HOST_SS_CEILING=8 \
       ZCL_SHELL_HOST_NPROC_CEILING=5 ZCL_SHELL_HOST_STAT_CEILING=8 \
       ZCL_SHELL_HOST_SED_CEILING=8 ZCL_LINT_MODE=UPDATE "$0" >/dev/null 2>&1; then
        fail 'selftest UPDATE exceeded a hard ceiling'
    fi
    cmp -s "$baseline" "$saved" || fail 'selftest ceiling failure changed baseline'
    cp "$fixture_saved" "$fixture"
    if ZCL_SHELL_HOST_SCAN_DIR="$work" ZCL_SHELL_HOST_FILE_FLOOR=1 \
       ZCL_SHELL_HOST_BASELINE="$baseline" ZCL_SHELL_HOST_SS_CEILING=8 \
       ZCL_SHELL_HOST_NPROC_CEILING=8 ZCL_SHELL_HOST_STAT_CEILING=8 \
       ZCL_SHELL_HOST_SED_CEILING=8 ZCL_SHELL_HOST_INJECT_SCAN_FAILURE=1 \
       "$0" >/dev/null 2>&1; then
        fail 'selftest injected scanner failure passed'
    fi
    clean_fixture="$work/zz-clean.sh"
    printf '#!/usr/bin/env bash\n:\n' > "$clean_fixture"
    if ZCL_SHELL_HOST_SCAN_DIR="$work" ZCL_SHELL_HOST_FILE_FLOOR=1 \
       ZCL_SHELL_HOST_BASELINE="$baseline" ZCL_SHELL_HOST_SS_CEILING=8 \
       ZCL_SHELL_HOST_NPROC_CEILING=8 ZCL_SHELL_HOST_STAT_CEILING=8 \
       ZCL_SHELL_HOST_SED_CEILING=8 ZCL_SHELL_HOST_INJECT_SCAN_PATH="$fixture" \
       "$0" >/dev/null 2>&1; then
        fail 'selftest intermediate scanner failure passed'
    fi
    rm -f "$baseline"
    if ZCL_SHELL_HOST_SCAN_DIR="$work" ZCL_SHELL_HOST_FILE_FLOOR=1 \
       ZCL_SHELL_HOST_BASELINE="$baseline" ZCL_SHELL_HOST_SS_CEILING=8 \
       ZCL_SHELL_HOST_NPROC_CEILING=8 ZCL_SHELL_HOST_STAT_CEILING=8 \
       ZCL_SHELL_HOST_SED_CEILING=8 ZCL_SHELL_HOST_INJECT_TRACKED_BASELINE=1 \
       ZCL_SHELL_HOST_BOOTSTRAP=1 ZCL_LINT_MODE=UPDATE "$0" >/dev/null 2>&1; then
        fail 'selftest recreated a deleted tracked baseline'
    fi
    [ ! -e "$baseline" ] || fail 'selftest deleted-baseline refusal wrote a file'
    printf 'selftest %s: PASS lexical=true growth=red update=shrink-only scanner_failure=red\n' "$GATE"
)

case "${1:-}" in
    --selftest) selftest ;;
    '') run_gate ;;
    *) fail "usage: $0 [--selftest]" ;;
esac
