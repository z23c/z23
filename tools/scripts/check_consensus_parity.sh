#!/usr/bin/env bash
# Lint gate E13 — consensus-parity guard (HARD).
#
# zclassic23 MUST stay BIT-FOR-BIT consensus-compatible with zclassicd
# (the canonical C++ ZClassic daemon). The non-negotiable rule, stated in
# docs/CONSENSUS_PARITY_DOCTRINE.md:
#
#   Equihash (N,K) and EVERY network-upgrade activation resolve from a
#   STATIC, height-keyed table only — never from miner signaling, a
#   versionbits/BIP9/BIP8 deployment state machine, or any dynamic
#   per-height parameter override.
#
# zclassicd has no versionbits / signaling apparatus: it activates all
# upgrades purely by fixed height (nHeight >= nActivationHeight) and reads
# Equihash (N,K) from EquihashUpgradeInfo[CurrentEpoch(height)]. Introducing
# a miner-signaled override (the PR #6 "Equihash 200,9 sidegrade" class)
# would make nodes disagree on which (N,K) / which rules are valid at a
# height and FORK the chain away from zclassicd.
#
# ── SCAN CLASS 0 — forbidden mechanism tokens (original gate) ──────────────
# Fails if any such mechanism token appears in the consensus source surface.
# False positive? Add `// consensus-parity-ok:<reason>` to the line. The
# reason must explain why this is NOT a divergence from zclassicd. This is
# the ONLY escape mechanism this gate has; classes 1/2 below reuse it for
# nothing new — they get their own registry instead (see below).
#
# ── SCAN CLASS 1 — future-height literal in a height comparison ───────────
# ── SCAN CLASS 2 — wall-clock read in the consensus surface ───────────────
# Added after an adversarial review planted
#     if (n_height >= 3400000) halvings--;
# two lines below a legitimate height gate in core/consensus/src/subsidy.c.
# It is a bare integer comparison: it matches NONE of the class-0 forbidden
# tokens (no versionbits/BIP9/signaling identifier anywhere near it), so the
# class-0 scan is structurally blind to it. The bomb is set for a height
# ~170k blocks in the future, so deterministic rebuild, full-chain replay,
# and historical UTXO-root agreement all pass TODAY — the divergence only
# fires once the chain reaches the planted height.
#
# Class 1 catches the shape of that bomb directly: any integer literal
# >= HEIGHT_LITERAL_FLOOR (3,100,000 — the last baked mainnet checkpoint,
# i.e. strictly in the FUTURE relative to every height this codebase has
# ever validated) sitting next to a relational operator on a line that also
# mentions "height" — the exact shape of `n_height >= 3400000`.
#
# Class 2 catches the sibling trick: smuggling a non-deterministic,
# non-height-keyed control input (the wall clock) into the same surface.
# time(NULL)/GetTime()/GetAdjustedTime()/gettimeofday()/clock_gettime() are
# themselves legitimate in a few known places (the standard "block timestamp
# too far in the future" DoS check, the initial-block-download heuristic, a
# progress-log speed metric, and a miner setting its own candidate's nTime) —
# none of those are a divergence from zclassicd, which has the identical
# calls. But an attacker could just as easily hide
#     if (n_height >= 3400000 || time(NULL) > 1234567890) halvings--;
# and every wall-clock read in this surface deserves the same forced,
# reviewed, one-line-per-site accounting that class-0 already gives the
# versionbits family.
#
# Unlike class 0, classes 1/2 are cleared ONLY by an entry in
# tools/lint/FLAG_DAYS.txt (format documented at the top of that file), not
# by the `consensus-parity-ok:` comment: the comment marks a line the GATE
# AUTHOR could edit; classes 1/2 exist specifically to be checkable by
# someone who does NOT own the flagged file (this rollout registered four
# pre-existing wall-clock sites in core/modules/validation and core/modules/mining without
# touching either directory). A matching FLAG_DAYS.txt row still doesn't
# stop a hostile publisher who edits the registry alongside the bomb in the
# same commit — nothing textual can. What it buys is that the edit is
# VISIBLE and DIFFABLE: a weak/light node (or a human) that only checks
# "did FLAG_DAYS.txt change, and does the new row's rationale hold up" gets
# a small, targeted diff instead of having to re-audit the whole consensus
# surface. See docs/CONSENSUS_PARITY_DOCTRINE.md for the full limitations
# list — this is a textual heuristic, not a C parser, and it does not catch
# every way to hide a future-height or wall-clock dependency (named
# constants, digit-separated literals, hex-encoded heights, and macro
# indirection all evade it; see the doctrine doc).
#
# Run `./tools/scripts/check_consensus_parity.sh --selftest` to prove both
# directions: a planted, unregistered violation FAILS; the same violation,
# registered, PASSES.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh
# shellcheck source=tools/scripts/sh_str.sh
source tools/scripts/sh_str.sh

# Consensus-critical source surface. docs/ and tests/harness/include/test/ are intentionally
# NOT scanned — the doctrine and the parity test may name these tokens
# defensively without being a real mechanism.
PATHS=(core/params core/chainparams core/modules/validation core/modules/chain core/modules/mining engine/jobs engine/reducer/jobs core/consensus)

# The registry required by scan classes 1/2 (see the header above and the
# format comment at the top of the file itself).
FLAG_DAYS_FILE="tools/lint/FLAG_DAYS.txt"

# The last baked mainnet checkpoint height at the time this gate was
# written. Any bare integer literal at or above this floor is, by
# construction, a height strictly in this codebase's future — exactly the
# shape a flag-day bomb needs. Bump this only by raising it to a LATER
# real checkpoint (never lower it), and only as part of a reviewed change
# that also re-audits every class-1 registration this floor's motion could
# newly exempt or newly catch.
HEIGHT_LITERAL_FLOOR=3100000

# ── FAIL-LOUD preflight (never report "clean" off a silently-empty scan) ──
# If a consensus dir was renamed/moved/deleted, grep would scan a SMALLER
# surface and still exit 0 — a forbidden mechanism in the drifted dir would
# escape the single most sacred gate. So every PATHS entry MUST exist; a
# missing one means the consensus surface drifted and PATHS must be updated
# DELIBERATELY (and the parity boundary re-verified). A NEW consensus dir not
# in PATHS is likewise unscanned — when you add one, add it here.
preflight_paths() {
    local p
    for p in "${PATHS[@]}"; do
        if [ ! -d "$p" ]; then
            echo "check_consensus_parity: FATAL — consensus path '$p' is missing." >&2
            echo "  The consensus source surface drifted. Update PATHS in this gate" >&2
            echo "  deliberately and re-verify the zclassicd parity boundary before" >&2
            echo "  re-greening. Refusing to report 'clean' off a partial scan." >&2
            exit 2
        fi
    done
}

# ── class-0 scan: forbidden mechanism tokens (unchanged from the original
#    gate) ────────────────────────────────────────────────────────────────
# The legitimate static getters chain_params_equihash_n / chain_params_equihash_k
# are NOT matched — they carry no "_at" suffix. EquihashUpgradeInfo and the
# height-keyed epoch lookup are the CORRECT parity mechanism and stay allowed.
FORBIDDEN='versionbits|VersionBitsState|ComputeBlockVersion|ehUpgrade|eh_upgrade|nSignalBit|vbits_|equihash_n_at|equihash_k_at|BIP9|BIP8'

scan_class0() {
    # Run the scan and check grep's exit EXPLICITLY: 0=match, 1=no-match,
    # >=2=real error (bad flag, unreadable file). The old `2>/dev/null || true`
    # masked a >=2 error as an empty result and reported "clean" — a
    # fail-silent hole. Only 0/1 are valid; >=2 fails the gate LOUD.
    local raw grc hits
    set +e
    raw=$(grep -rnE "$FORBIDDEN" "${PATHS[@]}" --include='*.c' --include='*.h' "${LINT_GREP_EXCLUDE_ARGS[@]}")
    grc=$?
    set -e
    if [ "$grc" -ge 2 ]; then
        echo "check_consensus_parity: FATAL — scan grep failed (exit $grc) over the" >&2
        echo "  consensus surface; refusing to report 'clean' off a broken scan." >&2
        exit 2
    fi

    hits=""
    if [ -n "$raw" ]; then
        hits=$(printf '%s\n' "$raw" \
            | grep -vE '(//|/\*) ?consensus-parity-ok:[A-Za-z][A-Za-z0-9_-]+' || true)
    fi

    if [ -n "$hits" ]; then
        echo "$hits"
        echo ""
        echo "FAIL: a non-zclassicd consensus mechanism appears in the consensus path."
        echo "  zclassic23 MUST stay bit-for-bit consensus-compatible with zclassicd."
        echo "  See docs/CONSENSUS_PARITY_DOCTRINE.md. Equihash (N,K) and every upgrade"
        echo "  activation resolve from the STATIC, height-keyed table ONLY — never from"
        echo "  miner signaling / versionbits / a dynamic per-height override."
        echo "  If this is genuinely not a divergence, mark the line:"
        echo "      // consensus-parity-ok:<reason>"
        return 1
    fi
    return 0
}

# ── classes 1/2 scan: future-height literals + wall-clock reads ───────────

CANDIDATE_HEIGHT_RE='(>=|<=|==|<|>)[[:space:]]*[0-9]{7,}|[0-9]{7,}[[:space:]]*(>=|<=|==|<|>)'
CANDIDATE_CLOCK_RE='\btime[[:space:]]*\([[:space:]]*NULL[[:space:]]*\)|\bGetTime[[:space:]]*\([[:space:]]*\)|\bGetAdjustedTime[[:space:]]*\([[:space:]]*\)|\bgettimeofday[[:space:]]*\(|\bclock_gettime[[:space:]]*\('

# sha256 of the EXACT current source-line text (no trailing newline). This
# is the encoding used to populate tools/lint/FLAG_DAYS.txt, and the
# encoding the gate recomputes on every run — so ANY edit to a registered
# line (not just the number/call itself; whitespace, a trailing comment,
# anything) invalidates the registration and forces a fresh, reviewed row.
line_digest() {
    printf '%s' "$1" | sha256sum | awk '{print $1}'
}

# A textual heuristic, not a C parser: true for a block-comment continuation
# (" * ..."), a whole-line "//" comment, or a "/*" opener. A real executable
# line in this codebase's style never starts with a bare "* " (a pointer
# dereference like "*out_x = v;" has no space after the star) — see the
# doctrine doc's limitations section for what this does and does not catch.
is_comment_line() {
    [[ "$1" =~ ^[[:space:]]*(\*[[:space:]]|//|/\*) ]]
}

# Look up an exact (path:line, class, digest) triple in a FLAG_DAYS.txt-
# formatted registry. Reads via input redirection ("< $registry"), never a
# pipe — so this carries none of the printf|grep -q pipefail-inversion risk
# (tools/scripts/sh_str.sh) even though the registry can be multi-line and
# a found match must be reported as found, not lost to an EPIPE.
# Prints one of: ok | stale | unregistered | missing-file
flagdays_status() {
    local registry="$1" key="$2" class="$3" digest="$4"
    local rkey rclass rheight rdigest rtag rrationale seen_key=0
    if [ ! -f "$registry" ]; then
        echo "missing-file"
        return
    fi
    # shellcheck disable=SC2034  # rheight/rtag/rrationale must be read to
    # keep the pipe-delimited field split correct; only rkey/rclass/rdigest
    # are consulted for the match.
    while IFS='|' read -r rkey rclass rheight rdigest rtag rrationale; do
        case "$rkey" in ''|'#'*) continue ;; esac
        if [ "$rkey" = "$key" ] && [ "$rclass" = "$class" ]; then
            seen_key=1
            if [ "$rdigest" = "$digest" ]; then
                echo "ok"
                return
            fi
        fi
    done < "$registry"
    if [ "$seen_key" -eq 1 ]; then
        echo "stale"
    else
        echo "unregistered"
    fi
}

# Scans ONE file for class-1 (HEIGHT) and class-2 (CLOCK) violations against
# the given registry file. Prints a FAIL block per unresolved hit. Returns
# 1 if any unresolved hit was found, 0 otherwise. Factored out of the main
# PATHS-walking loop so --selftest can call it directly on a scratch file
# and a scratch registry without touching the real tree.
scan_file_for_new_classes() {
    local file="$1" registry="$2"
    local fail=0
    [ -f "$file" ] || return 0

    # ---- class HEIGHT ----
    local raw grc
    set +e
    raw=$(grep -nE "$CANDIDATE_HEIGHT_RE" "$file")
    grc=$?
    set -e
    if [ "$grc" -ge 2 ]; then
        echo "check_consensus_parity: FATAL — HEIGHT scan grep failed (exit $grc) on $file" >&2
        exit 2
    fi
    if [ -n "$raw" ]; then
        local entry lineno content lower matched_tokens token digest status
        while IFS= read -r entry; do
            lineno="${entry%%:*}"
            content="${entry#*:}"
            is_comment_line "$content" && continue
            lower="${content,,}"
            str_contains "$lower" "height" || continue
            matched_tokens=$(grep -oE '[0-9]{7,}' <<<"$content" || true)
            while IFS= read -r token; do
                [ -n "$token" ] || continue
                # Skip the decimal tail of a hex literal (0x3400000 is NOT
                # decimal 3,400,000) — see doctrine doc: hex heights are a
                # known, documented blind spot of this scanner, not silently
                # mis-valued.
                case "$content" in
                    *0x"$token"*|*0X"$token"*) continue ;;
                esac
                (( 10#$token >= HEIGHT_LITERAL_FLOOR )) || continue
                if [[ "$content" =~ (\>=|\<=|==)[[:space:]]*${token} ]] \
                    || [[ "$content" =~ ${token}[[:space:]]*(\>=|\<=|==) ]] \
                    || [[ "$content" =~ \>[[:space:]]*${token} ]] \
                    || [[ "$content" =~ \<[[:space:]]*${token} ]] \
                    || [[ "$content" =~ ${token}[[:space:]]*\> ]] \
                    || [[ "$content" =~ ${token}[[:space:]]*\< ]]; then
                    digest=$(line_digest "$content")
                    status=$(flagdays_status "$registry" "$file:$lineno" "HEIGHT" "$digest")
                    if [ "$status" != "ok" ]; then
                        echo "FAIL[HEIGHT:$status] $file:$lineno: $content"
                        echo "    literal $token >= floor $HEIGHT_LITERAL_FLOOR in a height comparison."
                        echo "    Register in $FLAG_DAYS_FILE:"
                        echo "        $file:$lineno|HEIGHT|$token|$digest|<tag>|<one-line rationale>"
                        fail=1
                    fi
                fi
            done <<< "$matched_tokens"
        done <<< "$raw"
    fi

    # ---- class CLOCK ----
    set +e
    raw=$(grep -nE "$CANDIDATE_CLOCK_RE" "$file")
    grc=$?
    set -e
    if [ "$grc" -ge 2 ]; then
        echo "check_consensus_parity: FATAL — CLOCK scan grep failed (exit $grc) on $file" >&2
        exit 2
    fi
    if [ -n "$raw" ]; then
        local entry lineno content digest status
        while IFS= read -r entry; do
            lineno="${entry%%:*}"
            content="${entry#*:}"
            is_comment_line "$content" && continue
            digest=$(line_digest "$content")
            status=$(flagdays_status "$registry" "$file:$lineno" "CLOCK" "$digest")
            if [ "$status" != "ok" ]; then
                echo "FAIL[CLOCK:$status] $file:$lineno: $content"
                echo "    wall-clock read in the consensus surface."
                echo "    Register in $FLAG_DAYS_FILE:"
                echo "        $file:$lineno|CLOCK|-|$digest|<tag>|<one-line rationale>"
                fail=1
            fi
        done <<< "$raw"
    fi

    return $fail
}

scan_classes_1_and_2() {
    local registry="$1"
    local fail=0 f
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        scan_file_for_new_classes "$f" "$registry" || fail=1
    done < <(find "${PATHS[@]}" -type f \( -name '*.c' -o -name '*.h' \) "${LINT_FIND_PRUNE_ARGS[@]}" 2>/dev/null | sort)
    return $fail
}

# ── FLAG_DAYS.txt digest — for a release record to carry ──────────────────
# Emits the whole-registry digest so a weak node (or a human comparing two
# releases) can see, from a single line, whether the registry moved between
# releases — without needing to diff the file itself. This does not prove
# anything about what changed, only THAT it changed; see the header comment
# above and docs/CONSENSUS_PARITY_DOCTRINE.md for what this mechanism does
# and does not guarantee.
emit_flag_days_digest() {
    if [ -f "$FLAG_DAYS_FILE" ]; then
        echo "FLAG_DAYS_REGISTRY_DIGEST: sha256:$(sha256sum "$FLAG_DAYS_FILE" | awk '{print $1}')"
    else
        echo "FLAG_DAYS_REGISTRY_DIGEST: MISSING — $FLAG_DAYS_FILE does not exist" >&2
    fi
}

main() {
    preflight_paths

    if [ ! -f "$FLAG_DAYS_FILE" ]; then
        echo "check_consensus_parity: FATAL — registry '$FLAG_DAYS_FILE' is missing." >&2
        echo "  Scan classes 1 (future-height literal) and 2 (wall-clock read) can" >&2
        echo "  only clear a hit against this registry. Refusing to report 'clean'" >&2
        echo "  off a scan with nothing to check hits against." >&2
        exit 2
    fi

    local class0_ok=0 class12_ok=0
    scan_class0 || class0_ok=1
    scan_classes_1_and_2 "$FLAG_DAYS_FILE" || class12_ok=1

    if [ "$class0_ok" -ne 0 ] || [ "$class12_ok" -ne 0 ]; then
        emit_flag_days_digest
        exit 1
    fi

    echo "check_consensus_parity: clean — no non-zclassicd consensus mechanism, no"
    echo "  unregistered future-height literal, no unregistered wall-clock read in"
    echo "  the consensus path"
    emit_flag_days_digest
    exit 0
}

# ── --selftest: prove both scan directions on a scratch copy ──────────────
# Never touches the real tree or the real registry. Class 1 (HEIGHT) is the
# one the brief for this gate names explicitly: plant
#     if (n_height >= 3400000) halvings--;
# unregistered -> must FAIL; register it (matching digest) -> must PASS.
# Class 2 (CLOCK) gets the same round trip for the same reason.
selftest() {
    local fixture registry failures=0
    fixture="$(mktemp -d)"
    registry="$fixture/FLAG_DAYS.txt"
    cleanup_consensus_parity_selftest() {
        [ ! -d "$fixture" ] || rm -rf -- "$fixture"
    }
    trap cleanup_consensus_parity_selftest RETURN

    local height_file="$fixture/subsidy_fixture.c"
    cat > "$height_file" <<'EOF'
/* selftest fixture — not part of the build */
int consensus_halving(int n_height)
{
    int halvings = n_height / 100;
    if (n_height >= 3400000)
        halvings--;
    return halvings;
}
EOF
    : > "$registry"

    echo "== class-1 (HEIGHT) selftest =="
    if scan_file_for_new_classes "$height_file" "$registry" >/tmp/consensus_parity_selftest_height_unreg.$$; then
        echo "FAIL: selftest expected the unregistered planted height bomb to trip the gate, but it passed clean." >&2
        cat /tmp/consensus_parity_selftest_height_unreg.$$ >&2
        failures=1
    else
        echo "-- unregistered planted bomb correctly FAILED:"
        cat /tmp/consensus_parity_selftest_height_unreg.$$
    fi
    rm -f /tmp/consensus_parity_selftest_height_unreg.$$

    local bomb_line bomb_digest
    bomb_line="$(sed -n '5p' "$height_file")"
    bomb_digest="$(line_digest "$bomb_line")"
    printf '%s\n' "$height_file:5|HEIGHT|3400000|$bomb_digest|selftest-bomb|selftest fixture: deliberately planted, this row exists only to prove the registered form passes." >> "$registry"

    if scan_file_for_new_classes "$height_file" "$registry" >/tmp/consensus_parity_selftest_height_reg.$$; then
        echo "-- registered form correctly PASSED (no output)."
    else
        echo "FAIL: selftest expected the REGISTERED height bomb to pass, but the gate still tripped:" >&2
        cat /tmp/consensus_parity_selftest_height_reg.$$ >&2
        failures=1
    fi
    rm -f /tmp/consensus_parity_selftest_height_reg.$$

    echo ""
    echo "== class-2 (CLOCK) selftest =="
    local clock_file="$fixture/clock_fixture.c"
    cat > "$clock_file" <<'EOF'
/* selftest fixture — not part of the build */
bool clock_fixture_reject(void)
{
    return time(NULL) > 1234567890;
}
EOF
    : > "$registry"

    if scan_file_for_new_classes "$clock_file" "$registry" >/tmp/consensus_parity_selftest_clock_unreg.$$; then
        echo "FAIL: selftest expected the unregistered wall-clock read to trip the gate, but it passed clean." >&2
        cat /tmp/consensus_parity_selftest_clock_unreg.$$ >&2
        failures=1
    else
        echo "-- unregistered wall-clock read correctly FAILED:"
        cat /tmp/consensus_parity_selftest_clock_unreg.$$
    fi
    rm -f /tmp/consensus_parity_selftest_clock_unreg.$$

    local clock_line clock_digest
    clock_line="$(sed -n '4p' "$clock_file")"
    clock_digest="$(line_digest "$clock_line")"
    printf '%s\n' "$clock_file:4|CLOCK|-|$clock_digest|selftest-clock|selftest fixture: deliberately planted, this row exists only to prove the registered form passes." >> "$registry"

    if scan_file_for_new_classes "$clock_file" "$registry" >/tmp/consensus_parity_selftest_clock_reg.$$; then
        echo "-- registered form correctly PASSED (no output)."
    else
        echo "FAIL: selftest expected the REGISTERED wall-clock read to pass, but the gate still tripped:" >&2
        cat /tmp/consensus_parity_selftest_clock_reg.$$ >&2
        failures=1
    fi
    rm -f /tmp/consensus_parity_selftest_clock_reg.$$

    echo ""
    if [ "$failures" -ne 0 ]; then
        echo "check_consensus_parity --selftest: FAIL"
        return 1
    fi
    echo "check_consensus_parity --selftest: PASS"
}

case "${1:-}" in
    --selftest)
        selftest
        ;;
    "")
        main
        ;;
    *)
        echo "check_consensus_parity: unknown argument: $1" >&2
        exit 2
        ;;
esac
