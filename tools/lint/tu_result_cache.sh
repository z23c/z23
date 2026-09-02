# shellcheck shell=bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# tu_result_cache.sh — a per-TRANSLATION-UNIT result cache shared by the two
# compile-sweep lint gates, check_clang_portability.sh (2108 TUs) and
# check_windows_cross_syntax.sh (233 TUs).
#
# WHY THIS EXISTS
# Those two gates are the most expensive things in `make lint`: measured
# 2026-09-02 under a full 24-job umbrella run they cost 130.2 s and 55.5 s of
# a 170 s wall. Several agents run `make lint` many times an hour on several
# machines, so every second here is multiplied by the fleet.
#
# tools/lint/lint_cache.sh already caches at GATE granularity, but its key is
# the WHOLE tree: edit one .c and every gate's stored PASS is void, so the
# 2108-TU sweep is paid again in full to re-check 2107 unchanged files. That
# key was chosen when the whole umbrella cost 25 s (see that file's header);
# at 170 s it no longer holds. This file adds the finer grain UNDERNEATH it,
# without touching lint_cache.sh, run_lint.sh, or the Makefile.
#
# WHAT IT CACHES, AND WHY THE GATES CANNOT TELL
# A -fsyntax-only compile of one TU produces exactly two observable things:
# an exit status and a combined stdout/stderr stream. Both gates already
# funnel every TU through `"$CC" "${flags[@]}" "$src" > "$log" 2>&1` plus a
# recorded rc file, and then grade the tree by parsing those artifacts. So
# the cache stores the rc and the byte-exact log, and on a hit REPLAYS them
# into the same paths the compiler would have written. Every downstream
# stage — the baseline ratchet, the diagnostic-site dedup, the
# compiler-infrastructure classifier, the log/rc count floors — sees input
# that is indistinguishable from a fresh compile, because it is the same
# bytes. No grading logic changes, so no grading logic can be weakened.
#
# WHERE THE WORK HAPPENS, AND WHY IT IS NOT IN THE WORKERS
# The first draft looked the cache up inside each xargs worker. That made a
# fully warm run cost 17 s for the clang gate: every one of 2108 workers
# forked a bash, sourced this file, and ran three sha256sums to discover it
# had nothing to do. Process creation had become the entire wall.
#
# So the lookup is a single PARENT pass, tu_cache_plan:
#   * ONE sha256sum invocation hashes every source in the scan set;
#   * each entry's identity is its (salt, source path, content sha), which
#     is also its FILE NAME — <cache>/<gate>/<salt>/<src path>.<content sha>
#     — so a lookup is a path test, with no per-TU hashing at all;
#   * a hit is replayed with shell builtins: the status is one `printf` and
#     the overwhelmingly common empty log is one `: >` truncation. Only a TU
#     that actually produced diagnostics costs a fork (`tail -n +2`), and in
#     this tree that is 8 of 2108;
#   * only the MISSES are written to the list xargs then forks over.
# A fully warm run therefore forks a handful of processes in total instead
# of 2108, and the gates keep their existing worker loops unchanged apart
# from the list they iterate.
#
# WHY THE KEY IS SOUND
# clang/gcc -fsyntax-only over one TU is a pure function of
#
#   (1) the compiler                 -> "$CC --version" first line
#   (2) the flag list                -> sha256 of the gate's flags.nul
#   (3) the rules that turn a path   -> sha256 of the gate script and of
#       into the final argv             this helper. Both gates append per-TU
#                                       flags (an inert identity define for
#                                       one bootstrap TU; -DZCL_TESTING and a
#                                       force-included compat header for test
#                                       sources) as a pure function of the
#                                       source path, so hashing the path plus
#                                       the script that derives those extras
#                                       pins the exact argv without having to
#                                       rebuild it.
#   (4) the TU's own bytes           -> sha256 of the source file
#   (5) every file it can textually  -> the INCLUDE-SET DIGEST below
#       include
#
# (1), (2), (3) and (5) fold into one per-run SALT, which names the cache
# generation directory. (3)'s path component and (4) name the entry inside
# it. Nothing a TU can see is outside that set.
#
# The include-set digest is the sha256 of the sorted "<path>\t<sha256>" list
# of every file in the tree a scanned TU could textually include. That is
# NOT "the headers this TU includes" — computing that needs a preprocessor
# pass, which is most of the cost we are trying to avoid — it is a SUPERSET,
# so it can only over-invalidate, never under-invalidate. Editing any header
# busts every TU (correct, and rare); editing one .c busts exactly that TU.
#
# The digest set is built from the FILESYSTEM, not from `git ls-files`: an
# untracked header that a production scan can see is on the include path and
# does change compiler output, and a digest that ignored it would serve a
# stale verdict. It covers *.h, *.inc and *.def — .def files are #included
# 253 times in this tree (the command tables) — plus any *.c that some file
# #includes by name (platform/modules/encoding/src/qrcodegen_backend.c
# includes vendor/qrcodegen/qrcodegen.c, which is inside the clang gate's
# scan set). Matching those by BASENAME is again a deliberate superset.
#
# WHAT IT DOES NOT COVER, ON PURPOSE
# * The compiler's own installed files beyond its version string. Upgrading
#   clang in place without a version change is out of scope, exactly as it is
#   for the recorded portability baseline, which is a statement about one
#   compiler version (see check_clang_portability.sh, "compiler VERSION
#   skew").
# * Anything reached through an absolute include path outside the repo. Both
#   gates compile with repo-relative -I only, plus the system include set,
#   which moves with the compiler version.
#
# FAIL-SAFE, NOT FAIL-OPEN
# Every failure mode here turns the cache OFF and says so on the summary
# line; none of them can turn a red gate green. Only a completed compile is
# ever stored, and a stored FAIL replays as a FAIL (a compile-sweep gate's
# failures are per-TU diagnostics, not flakes — the whole point of the
# ratchet is that the same source under the same compiler yields the same
# diagnostics). A store is one rename of a fully written temp file, so a
# concurrent reader sees an entry either complete or not at all.
#
# ENV
#   ZCL_LINT_TU_CACHE=0        disable (default: on)
#   ZCL_LINT_TU_CACHE_DIR      cache root (default: <repo>/.cache/lint-tu)
#   ZCL_LINT_CACHE_MODE=audit  set by run_lint.sh --cold-audit; disables the
#                              cache, because a cold audit that replayed a
#                              cached compile would be auditing the cache
#                              against itself.
#
# PARENT-SIDE API (the gate, once, before it forks workers)
#   tu_cache_setup <gate> <gate-script> <cc> <flags-nul> <scratch> \
#                  [scan-root] [cache-root]
#       Derive the salt, open the cache generation, export the worker
#       contract. Never fails the gate: on any problem it disables and
#       records why.
#   tu_cache_paths_for <src>          — DEFINED BY THE GATE, not here.
#       Must set TU_LOG and TU_RC to the two artifact paths that gate's
#       worker would have written for <src>. tu_cache_plan replays hits into
#       exactly those paths, which is the whole reason the gate's grading
#       code needs no change.
#   tu_cache_plan <src-list> <miss-list>
#       Replay every hit; write the paths that still need compiling to
#       <miss-list>, which is what the gate hands to xargs.
#   tu_cache_summary
#       Print "  tu-cache: N hit, M miss, K stored" (or the disabled form).
#   tu_cache_selftest <gate> <gate-script> <cc> <flags-nul> <scratch> <src>
#       The eight soundness proofs; exits 1 naming the one that failed.
#
# WORKER-SIDE API (each xargs worker, after sourcing this file)
#   tu_cache_run <log> <rc-file> <cc> <arg>...
#       Behaves exactly like
#           "$cc" "$@" > "$log" 2>&1; printf '%s\n' "$?" > "$rc-file"
#       and then stores the result. The parent has already established that
#       this TU is a miss, so there is no lookup here. Always returns 0.
#
# Sourcing contract: source AFTER the gate's `cd` to the repo root. Safe
# under `set -euo pipefail` (check_windows_cross_syntax.sh) and under
# `set -uo pipefail` (check_clang_portability.sh).

# Absolute path to this file, so a forked worker can source it by name.
# Resolving it costs a subshell, so a worker reuses the exported answer.
if [ -n "${ZCL_TU_CACHE_LIB:-}" ]; then
    TU_CACHE_LIB_PATH="$ZCL_TU_CACHE_LIB"
else
    TU_CACHE_LIB_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
fi
TU_CACHE_OFF_REASON=""

# How many cache GENERATIONS to keep. One generation is one salt: one
# compiler, one flag set, one include-set state. A header edit starts a new
# one, and the old one is what makes `git stash`/rebase round trips free, so
# a few are worth keeping — but only a few, since each holds an entry per TU.
TU_CACHE_KEEP_GENERATIONS="${ZCL_LINT_TU_CACHE_GENERATIONS:-6}"

tu_cache__sha_stdin() { sha256sum | cut -c1-64; }

tu_cache__sha_file() {
    if [ -f "$1" ]; then sha256sum -- "$1" | cut -c1-64; else printf 'absent'; fi
}

tu_cache__disable() {
    TU_CACHE_OFF_REASON="$1"
    ZCL_TU_CACHE_ON=0
    export ZCL_TU_CACHE_ON
    return 0
}

# Print the include-set digest for <root> (default "."), using <scratch> for
# its work files. Prints nothing and returns 1 when the set cannot be built
# soundly — the caller then disables the cache rather than guessing.
tu_cache_include_digest() {
    local scratch="$1" root="${2:-.}"
    local all="$scratch/tu-cache-all-text.txt"
    local list="$scratch/tu-cache-include-set.txt"
    local names="$scratch/tu-cache-included-c.txt"
    local pruned=(
        -path "$root/.git" -o -path "$root/.git/*"
        -o -path "$root/build" -o -path "$root/build/*"
        -o -path "$root/test-tmp" -o -path "$root/test-tmp/*"
        -o -path "$root/.claude" -o -path "$root/.claude/*"
        -o -path "$root/.cache" -o -path "$root/.cache/*"
        -o -path "$root/vendor/tor" -o -path "$root/vendor/tor/*"
    )

    # ONE walk of the tree. Every later step reads this list instead of
    # walking again: at ~5000 files a redundant traversal is real CPU on a
    # gate that now runs in about a second.
    find "$root" \( "${pruned[@]}" \) -prune -o -type f \
        \( -name '*.c' -o -name '*.h' -o -name '*.inc' -o -name '*.def' \) \
        -print > "$all" 2>/dev/null || true
    [ -s "$all" ] || return 1

    # sha256sum escapes backslashes and newlines in names, which would make
    # the digest ambiguous, and a whitespace path would break the `read`
    # that consumes it. No such path exists in this tree; refuse rather than
    # hash an ambiguous list.
    if grep -qE '[[:space:]\\]' "$all"; then return 1; fi

    # (1) every file that is an include target by extension.
    grep -E '\.(h|inc|def)$' "$all" > "$list" || true
    [ -s "$list" ] || return 1

    # (2) plus every *.c some file names in an #include. A .c pulled in as
    #     text is a header in everything but its extension, and one such
    #     edge lives inside the clang gate's scan set today. Matching by
    #     BASENAME is a deliberate superset: it can only over-invalidate.
    tr '\n' '\0' < "$all" |
        xargs -0 -r grep -hoE '#[[:space:]]*include[[:space:]]*"[^"]*\.c"' 2>/dev/null |
        sed 's|.*/||; s|"$||; s|^|/|; s|$|$|' | LC_ALL=C sort -u > "$names" || true
    if [ -s "$names" ]; then
        grep -E '\.c$' "$all" | grep -F -f "$names" >> "$list" || true
    fi

    # The gate's own transient fixtures are excluded from a PRODUCTION scan
    # for the same reason scan_exclusions.sh excludes them from the scan
    # itself: another process's selftest plants `_<name>fixture<name>.h` into
    # a real directory and unlinks it seconds later, and a digest that saw it
    # would void every entry twice for a file no production TU includes.
    # Outside a production scan nothing is filtered, so a selftest still sees
    # the unfiltered tree. The regex comes from scan_exclusions.sh, sourced
    # lazily so neither gate has to take on that file's other globals.
    if [ "${ZCL_LINT_PRODUCTION_SCAN:-0}" = "1" ] &&
       [ -z "${LINT_FIXTURE_REGEX:-}" ] &&
       [ -f tools/lint/scan_exclusions.sh ]; then
        # shellcheck source=tools/lint/scan_exclusions.sh
        . tools/lint/scan_exclusions.sh
    fi
    if [ "${ZCL_LINT_PRODUCTION_SCAN:-0}" = "1" ] && [ -n "${LINT_FIXTURE_REGEX:-}" ]; then
        grep -vE "$LINT_FIXTURE_REGEX" "$list" > "$list.f" 2>/dev/null || true
        if [ -s "$list.f" ]; then mv -f "$list.f" "$list"; else rm -f "$list.f"; fi
    fi

    LC_ALL=C sort -u "$list" | tr '\n' '\0' |
        xargs -0 -r sha256sum 2>/dev/null |
        awk '{ h = $1; $1 = ""; sub(/^ +/, "", $0); printf "%s\t%s\n", $0, h }' |
        LC_ALL=C sort | tu_cache__sha_stdin
}
# Keep the newest N generations under <gate-root>, drop the rest whole. A
# generation is a directory named by its salt, so this is the only pruning
# the cache needs: an obsolete compiler, flag set or header state takes its
# entire population with it instead of ageing out file by file.
tu_cache__prune_generations() {
    local gate_root="$1" keep="$2" d
    [ -d "$gate_root" ] || return 0
    case "$keep" in ''|*[!0-9]*) keep=6 ;; esac
    [ "$keep" -ge 1 ] || keep=1
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        case "$d" in "$gate_root"/*) rm -rf "$d" 2>/dev/null || true ;; esac
    done < <(ls -1dt "$gate_root"/*/ 2>/dev/null | tail -n "+$((keep + 1))" | sed 's|/$||')
    return 0
}

tu_cache_setup() {
    local gate="$1" gate_script="$2" cc="$3" flags_nul="$4" scratch="$5"
    local root="${6:-.}" cachedir="${7:-}"
    local cc_id lib_sha gate_sha flags_sha digest salt gate_root dir

    TU_CACHE_OFF_REASON=""
    ZCL_TU_CACHE_ON=0
    ZCL_TU_CACHE_DIR=""
    ZCL_TU_CACHE_STATS=""
    ZCL_TU_CACHE_SCRATCH="$scratch"
    ZCL_TU_CACHE_LIB="$TU_CACHE_LIB_PATH"
    export ZCL_TU_CACHE_ON ZCL_TU_CACHE_DIR ZCL_TU_CACHE_STATS \
           ZCL_TU_CACHE_SCRATCH ZCL_TU_CACHE_LIB

    # A selftest sandbox has to be able to PROVE the cache even when the
    # operator turned the cache off, or when --cold-audit turned it off:
    # otherwise `ZCL_LINT_TU_CACHE=0 make check-clang-portability` would fail
    # the gate on a proof about the very feature the operator just disabled,
    # instead of leaving the gate exactly as it was before this cache
    # existed. The override is honoured ONLY together with an explicit
    # private cache directory, which nothing but tu_cache_selftest ever
    # passes, so no production path can reach it.
    if [ -z "$cachedir" ] || [ "${ZCL_TU_CACHE_SELFTEST_FORCE:-0}" != "1" ]; then
        if [ "${ZCL_LINT_TU_CACHE:-1}" = "0" ]; then
            tu_cache__disable "ZCL_LINT_TU_CACHE=0"; return 0
        fi
        if [ "${ZCL_LINT_CACHE_MODE:-off}" = "audit" ]; then
            tu_cache__disable "--cold-audit runs everything fresh"; return 0
        fi
    fi
    if ! command -v sha256sum >/dev/null 2>&1; then
        tu_cache__disable "sha256sum is not installed"; return 0
    fi

    cc_id="$("$cc" --version 2>/dev/null | head -1)"
    if [ -z "$cc_id" ]; then
        tu_cache__disable "'$cc' printed no version line"; return 0
    fi
    if ! digest="$(tu_cache_include_digest "$scratch" "$root")" || [ -z "$digest" ]; then
        tu_cache__disable "could not digest the include set under '$root'"; return 0
    fi

    lib_sha="$(tu_cache__sha_file "$TU_CACHE_LIB_PATH")"
    gate_sha="$(tu_cache__sha_file "$gate_script")"
    flags_sha="$(tu_cache__sha_file "$flags_nul")"
    salt="$(printf 'tu-result-cache/v2\n%s\n%s\n%s\n%s\n%s\n%s\n' \
        "$gate" "$lib_sha" "$gate_sha" "$cc_id" "$flags_sha" "$digest" |
        tu_cache__sha_stdin)"
    if [ "${#salt}" -ne 64 ]; then
        tu_cache__disable "salt derivation produced no digest"; return 0
    fi

    if [ -n "$cachedir" ]; then
        gate_root="$cachedir/$gate"
    else
        gate_root="${ZCL_LINT_TU_CACHE_DIR:-$PWD/.cache/lint-tu}/$gate"
    fi
    dir="$gate_root/$salt"
    if ! mkdir -p "$dir" 2>/dev/null; then
        tu_cache__disable "cannot create '$dir'"; return 0
    fi
    # Touch the generation so the newest-first prune below keeps the one this
    # run is about to use, whatever order the others were written in.
    touch -- "$dir" 2>/dev/null || true
    tu_cache__prune_generations "$gate_root" "$TU_CACHE_KEEP_GENERATIONS"
    rm -f "$dir"/.tmp.* 2>/dev/null || true

    ZCL_TU_CACHE_DIR="$dir"
    ZCL_TU_CACHE_STATS="$scratch/tu-cache.events"
    : > "$ZCL_TU_CACHE_STATS" 2>/dev/null || {
        tu_cache__disable "cannot write '$ZCL_TU_CACHE_STATS'"; return 0; }
    ZCL_TU_CACHE_ON=1
    export ZCL_TU_CACHE_ON ZCL_TU_CACHE_DIR ZCL_TU_CACHE_STATS \
           ZCL_TU_CACHE_SCRATCH ZCL_TU_CACHE_LIB
    return 0
}

# ── The parent pass ───────────────────────────────────────────────────────

tu_cache_plan() {
    local src_list="$1" miss_list="$2"
    local sha_list count_src count_sha sha path ent erc elen
    local hits=0 misses=0
    local -a miss=()

    : > "$miss_list"
    if [ "${ZCL_TU_CACHE_ON:-0}" != "1" ]; then
        cat -- "$src_list" > "$miss_list"
        return 0
    fi
    if ! declare -F tu_cache_paths_for >/dev/null 2>&1; then
        tu_cache__disable "the gate defined no tu_cache_paths_for callback"
        cat -- "$src_list" > "$miss_list"
        return 0
    fi

    # ONE hashing pass over the whole scan set. This is the only per-TU
    # cryptography a warm run performs.
    sha_list="$ZCL_TU_CACHE_SCRATCH/tu-cache-src-sha.txt"
    : > "$sha_list"
    tr '\n' '\0' < "$src_list" | xargs -0 -r sha256sum > "$sha_list" 2>/dev/null || true
    count_src="$(grep -c . "$src_list" || true)"; [ -n "$count_src" ] || count_src=0
    count_sha="$(grep -c . "$sha_list" || true)"; [ -n "$count_sha" ] || count_sha=0
    if [ "$count_sha" -ne "$count_src" ]; then
        # Hashing is the cache's whole basis. If it did not cover the scan
        # set, serve nothing rather than serve part of it.
        tu_cache__disable "hashed $count_sha of $count_src source(s)"
        cat -- "$src_list" > "$miss_list"
        return 0
    fi

    while read -r sha path; do
        [ -n "$path" ] || continue
        if [ "${#sha}" -eq 64 ]; then
            ent="$ZCL_TU_CACHE_DIR/$path.$sha"
            erc=""
            elen=""
            if [ -f "$ent" ]; then
                read -r erc elen < "$ent" || { erc=""; elen=""; }
            fi
            if [ -n "$erc" ] && [ -z "${erc//[0-9]/}" ] &&
               { [ "$elen" = 0 ] || [ "$elen" = 1 ]; }; then
                tu_cache_paths_for "$path"
                printf '%s\n' "$erc" > "$TU_RC"
                if [ "$elen" = 0 ]; then
                    : > "$TU_LOG"
                else
                    tail -n +2 -- "$ent" > "$TU_LOG"
                fi
                hits=$((hits + 1))
                continue
            fi
        fi
        miss+=("$path")
        misses=$((misses + 1))
    done < "$sha_list"

    if [ "$misses" -gt 0 ]; then
        printf '%s\n' "${miss[@]}" > "$miss_list"
        # Pre-create the entry directories once here so the workers, which
        # run 32-wide, do not each fork a mkdir.
        sed 's|/[^/]*$||' "$miss_list" | LC_ALL=C sort -u |
            sed "s|^|$ZCL_TU_CACHE_DIR/|" | tr '\n' '\0' |
            xargs -0 -r mkdir -p 2>/dev/null || true
    fi
    printf 'H %s\nM %s\n' "$hits" "$misses" >> "$ZCL_TU_CACHE_STATS"
    return 0
}

tu_cache_counts() {
    local out
    if [ -z "${ZCL_TU_CACHE_STATS:-}" ] || [ ! -f "$ZCL_TU_CACHE_STATS" ]; then
        printf '0 0 0'
        return 0
    fi
    out="$(awk '$1 == "H" { h += $2 } $1 == "M" { m += $2 } $0 == "s" { s++ }
                END { printf "%d %d %d", h + 0, m + 0, s + 0 }' \
          "$ZCL_TU_CACHE_STATS" 2>/dev/null)"
    [ -n "$out" ] || out="0 0 0"
    printf '%s' "$out"
}

tu_cache_summary() {
    local h m s
    if [ "${ZCL_TU_CACHE_ON:-0}" != "1" ]; then
        echo "  tu-cache: 0 hit, 0 miss, 0 stored (off: ${TU_CACHE_OFF_REASON:-not enabled})"
        return 0
    fi
    read -r h m s <<<"$(tu_cache_counts)"
    echo "  tu-cache: $h hit, $m miss, $s stored"
    return 0
}

# ── Worker side ───────────────────────────────────────────────────────────

tu_cache__event() {
    [ -n "${ZCL_TU_CACHE_STATS:-}" ] || return 0
    # One line, appended O_APPEND: atomic well under PIPE_BUF, so concurrent
    # workers cannot tear each other's tallies.
    printf '%s\n' "$1" >> "$ZCL_TU_CACHE_STATS" 2>/dev/null || true
    return 0
}

# One file per entry, named <src path>.<content sha> inside the generation
# directory. The name carries the whole identity, so the reader in
# tu_cache_plan needs no hashing of its own. Line 1 is "<rc> <has-log>"; the
# log bytes, when there are any, follow verbatim. Written to a temp file and
# renamed, so an entry is complete or absent, never partial.
tu_cache__store() {
    local src="$1" rc="$2" log="$3" sha ent tmp haslog=0
    sha="$(sha256sum -- "$src" 2>/dev/null)"
    sha="${sha%% *}"
    [ "${#sha}" -eq 64 ] || return 1
    ent="$ZCL_TU_CACHE_DIR/$src.$sha"
    if [ ! -d "${ent%/*}" ]; then
        mkdir -p "${ent%/*}" 2>/dev/null || return 1
    fi
    if [ -s "$log" ]; then haslog=1; fi
    tmp="$ZCL_TU_CACHE_DIR/.tmp.$$.${RANDOM}${RANDOM}"
    if [ "$haslog" = 1 ]; then
        { printf '%s %s\n' "$rc" "$haslog"; cat -- "$log"; } > "$tmp" 2>/dev/null || {
            rm -f "$tmp"; return 1; }
    else
        printf '%s %s\n' "$rc" "$haslog" > "$tmp" 2>/dev/null || {
            rm -f "$tmp"; return 1; }
    fi
    mv -f "$tmp" "$ent" 2>/dev/null || { rm -f "$tmp"; return 1; }
    return 0
}

tu_cache_run() {
    local log="$1" rcf="$2" cc="$3"
    shift 3
    local src rc=0 had_errexit=0
    src="${!#}"

    # Save and restore errexit rather than assuming it: the two callers
    # differ (check_windows_cross_syntax.sh runs under `set -e`, the
    # check_clang_portability.sh worker does not), and a helper that turned
    # errexit ON in a worker that never asked for it would abort that worker
    # mid-sweep on the first nonzero status.
    case "$-" in *e*) had_errexit=1 ;; esac
    set +e
    "$cc" "$@" > "$log" 2>&1
    rc=$?
    [ "$had_errexit" = 1 ] && set -e
    printf '%s\n' "$rc" > "$rcf"
    if [ "${ZCL_TU_CACHE_ON:-0}" = "1" ] && tu_cache__store "$src" "$rc" "$log"; then
        tu_cache__event s
    fi
    return 0
}

# ── Soundness selftest ────────────────────────────────────────────────────
# Eight proofs, run from each gate's own --self-test so `make lint` grades
# them on every run. Seven drive a SYNTHETIC tree through the SAME
# plan-then-fork-the-misses loop the gates use, with a stub compiler in
# place of clang: the properties under test are properties of the key and of
# the store, and proving them against the real tree would mean editing a
# real header mid-lint and paying for a whole extra 2108-TU sweep. The
# eighth runs the gate's REAL compiler and REAL flag set over one REAL
# source, which is what ties the synthetic loop to the gate it stands in
# for.
#
# SIZE IS A BUDGET, NOT A DETAIL. This runs on EVERY `make lint`, so it is
# kept to 16 units at 4 workers: enough that stores are genuinely concurrent
# (a store that does not survive its own run is the defect a serial fixture
# cannot see) and small enough that the whole block costs well under a
# second. An earlier draft used 200 units at 16 workers and became the
# gate's own floor — a selftest is not allowed to cost more than the thing
# it protects.
#
# The proofs run even when the operator disabled the cache: they use a
# private cache directory and ZCL_TU_CACHE_SELFTEST_FORCE, so
# `ZCL_LINT_TU_CACHE=0 make check-clang-portability` still leaves the gate
# exactly as it was before this cache existed — a full compile and a PASS —
# instead of failing on a proof about a feature that is switched off.

tu_cache__self_fail() {
    echo "FAIL: --self-test — tu-cache: $1" >&2
    exit 1
}

# The gate callback, for the synthetic sweep.
tu_cache__self_paths_for() {
    local k="${1//[^[:alnum:]]/_}"
    TU_LOG="$TU_SELF_OUT/$k.log"
    TU_RC="$TU_SELF_OUT/$k.rc"
}

# One synthetic sweep: plan in the parent, fork workers for the misses only,
# exactly as check_clang_portability.sh does. Echoes "<hit> <miss> <stored>".
tu_cache__self_sweep() {
    local base="$1" stub="$2" root="$3" flags="$4" srclist="$5"
    tu_cache_setup tu-cache-selftest "$stub" "$stub" "$flags" "$base" \
        "$root" "$base/cachedir"
    [ "${ZCL_TU_CACHE_ON:-0}" = "1" ] || tu_cache__self_fail \
        "the cache refused to enable on a synthetic root (${TU_CACHE_OFF_REASON:-?})"
    TU_SELF_OUT="$base/out"
    tu_cache_paths_for() { tu_cache__self_paths_for "$@"; }
    tu_cache_plan "$srclist" "$base/miss.txt"
    xargs -a "$base/miss.txt" -r -P 4 -n 1 -I '{}' \
        env ZCL_TU_SELF_OUT="$TU_SELF_OUT" ZCL_TU_SELF_CC="$stub" \
        bash -c '. "$ZCL_TU_CACHE_LIB"
                 k="${1//[^[:alnum:]]/_}"
                 tu_cache_run "$ZCL_TU_SELF_OUT/$k.log" \
                              "$ZCL_TU_SELF_OUT/$k.rc" \
                              "$ZCL_TU_SELF_CC" -c "$1"
                 exit 0' _ '{}' >/dev/null 2>&1
    tu_cache_counts
}

tu_cache_selftest() {
    local gate="$1" gate_script="$2" real_cc="$3" real_flags="$4"
    local scratch="$5" real_src="$6"
    local base root stub flags srclist h m s runs_before runs_after rdir i n

    [ -f "$real_src" ] || tu_cache__self_fail \
        "no real source was handed to the wiring proof (got '$real_src'); the gate's scan set is empty or moved"

    n=16
    base="$scratch/tu-cache-selftest"
    root="$base/root"
    rm -rf "$base"
    mkdir -p "$root/src" "$base/out" "$base/cachedir"

    ZCL_TU_CACHE_SELFTEST_FORCE=1
    export ZCL_TU_CACHE_SELFTEST_FORCE

    printf '#define TU_SELFTEST_SHARED 1\n' > "$root/src/shared.h"
    srclist="$base/srcs.txt"
    : > "$srclist"
    i=0
    while [ "$i" -lt "$n" ]; do
        printf '#include "shared.h"\nint unit_%s(void);\n' "$i" \
            > "$root/src/u$i.c"
        printf '%s\n' "$root/src/u$i.c" >> "$srclist"
        i=$((i + 1))
    done

    # Stub compiler: counts its own invocations and FAILS on one unit, so a
    # replay is distinguishable from a re-run by the invocation counter and
    # the replayed bytes and status are checkable against the cold ones.
    stub="$base/stub_cc.sh"
    cat > "$stub" <<'END_STUB'
#!/usr/bin/env bash
set -uo pipefail
if [ "${1:-}" = "--version" ]; then echo "tu-cache stub compiler 1.0"; exit 0; fi
src="${!#}"
echo x >> "$ZCL_TU_STUB_RUNS"
case "$src" in
    *u7.c)
        printf '%s\n' "$src:1:1: error: stub planted rejection" >&2
        exit 1
        ;;
esac
exit 0
END_STUB
    chmod +x "$stub"
    ZCL_TU_STUB_RUNS="$base/runs"
    export ZCL_TU_STUB_RUNS
    : > "$ZCL_TU_STUB_RUNS"

    flags="$base/flags.nul"
    printf '%s\0' -c > "$flags"

    # (1) COLD: nothing cached, every unit compiled and stored.
    read -r h m s <<<"$(tu_cache__self_sweep "$base" "$stub" "$root" "$flags" "$srclist")"
    { [ "$h" = 0 ] && [ "$m" = "$n" ] && [ "$s" = "$n" ]; } || tu_cache__self_fail \
        "a cold run over $n synthetic TUs reported '$h' hit / '$m' miss / '$s' stored, wanted 0/$n/$n"
    cp -r "$base/out" "$base/cold-out"
    [ "$(cat "$base/out/${root//[^[:alnum:]]/_}_src_u7_c.rc")" = 1 ] ||
        tu_cache__self_fail "the planted failing unit did not fail on the cold run"

    # (2) TWICE ON AN UNCHANGED TREE IS 100% HIT, and every stored entry is
    #     durable under concurrent writers: nothing recompiles, and the
    #     replayed artifacts are byte-identical to the cold ones — including
    #     the stored FAIL, which replays as a FAIL.
    runs_before="$(wc -l < "$ZCL_TU_STUB_RUNS")"
    read -r h m s <<<"$(tu_cache__self_sweep "$base" "$stub" "$root" "$flags" "$srclist")"
    runs_after="$(wc -l < "$ZCL_TU_STUB_RUNS")"
    { [ "$h" = "$n" ] && [ "$m" = 0 ] && [ "$s" = 0 ]; } || tu_cache__self_fail \
        "a second run over an UNCHANGED tree reported '$h' hit / '$m' miss / '$s' stored, wanted $n/0/0 — a store did not survive the run that made it"
    [ "$runs_before" = "$runs_after" ] || tu_cache__self_fail \
        "a warm run still invoked the compiler ($runs_before -> $runs_after)"
    diff -r "$base/cold-out" "$base/out" >/dev/null 2>&1 || tu_cache__self_fail \
        "a replayed artifact differs from the cold artifact"

    # (3) A THIRD identical run is still 100% hit: serving an entry must not
    #     consume it.
    read -r h m s <<<"$(tu_cache__self_sweep "$base" "$stub" "$root" "$flags" "$srclist")"
    { [ "$h" = "$n" ] && [ "$m" = 0 ]; } || tu_cache__self_fail \
        "a third run over an UNCHANGED tree reported '$h' hit / '$m' miss, wanted $n/0"

    # (4) EDITING A HEADER BUSTS EVERY TU.
    printf '#define TU_SELFTEST_SHARED 2\n' > "$root/src/shared.h"
    read -r h m s <<<"$(tu_cache__self_sweep "$base" "$stub" "$root" "$flags" "$srclist")"
    { [ "$h" = 0 ] && [ "$m" = "$n" ]; } || tu_cache__self_fail \
        "editing a header left '$h' of $n TUs on a stale cache entry"

    # (5) EDITING ONE TU BUSTS ONLY THAT TU.
    printf '#include "shared.h"\nint unit_3(int);\n' > "$root/src/u3.c"
    read -r h m s <<<"$(tu_cache__self_sweep "$base" "$stub" "$root" "$flags" "$srclist")"
    { [ "$h" = "$((n - 1))" ] && [ "$m" = 1 ]; } || tu_cache__self_fail \
        "editing one of $n TUs produced '$h' hit / '$m' miss, wanted $((n - 1))/1"

    # (6) REVERTING THAT TU IS A HIT AGAIN: a generation keeps one entry per
    #     content, so a stash or rebase round trip is free.
    printf '#include "shared.h"\nint unit_3(void);\n' > "$root/src/u3.c"
    read -r h m s <<<"$(tu_cache__self_sweep "$base" "$stub" "$root" "$flags" "$srclist")"
    { [ "$h" = "$n" ] && [ "$m" = 0 ]; } || tu_cache__self_fail \
        "reverting one TU produced '$h' hit / '$m' miss, wanted $n/0"

    # (7) ZCL_LINT_TU_CACHE=0 neither serves nor stores, and still compiles.
    #     The force override is dropped here: this proof is about the switch.
    runs_before="$(wc -l < "$ZCL_TU_STUB_RUNS")"
    ZCL_TU_CACHE_SELFTEST_FORCE=0 ZCL_LINT_TU_CACHE=0 \
        tu_cache_setup tu-cache-selftest "$stub" "$stub" "$flags" "$base" \
        "$root" "$base/cachedir-off"
    ZCL_TU_CACHE_SELFTEST_FORCE=1
    export ZCL_TU_CACHE_SELFTEST_FORCE
    [ "${ZCL_TU_CACHE_ON:-0}" = "1" ] && tu_cache__self_fail \
        "ZCL_LINT_TU_CACHE=0 did not disable the cache"
    TU_SELF_OUT="$base/out"
    tu_cache_paths_for() { tu_cache__self_paths_for "$@"; }
    tu_cache_plan "$srclist" "$base/miss-off.txt"
    [ "$(grep -c . "$base/miss-off.txt" || true)" = "$n" ] || tu_cache__self_fail \
        "a disabled cache did not send every TU to the compiler"
    tu_cache_run "$base/out/off.log" "$base/out/off.rc" "$stub" -c "$root/src/u0.c"
    runs_after="$(wc -l < "$ZCL_TU_STUB_RUNS")"
    [ "$runs_before" != "$runs_after" ] || tu_cache__self_fail \
        "a disabled cache did not invoke the compiler"
    [ -d "$base/cachedir-off" ] && tu_cache__self_fail \
        "a disabled cache still opened a cache directory"

    # (8) THE REAL WIRING: the gate's own compiler, its own flag set, one
    #     real source of this gate's, in a private cache dir. Cold, then
    #     warm; the warm pass must be a hit and byte-identical.
    rdir="$base/real"
    mkdir -p "$rdir/out"
    tu_cache_setup "$gate" "$gate_script" "$real_cc" "$real_flags" "$rdir" \
        "." "$rdir/cachedir"
    [ "${ZCL_TU_CACHE_ON:-0}" = "1" ] || tu_cache__self_fail \
        "the real gate configuration disabled the cache (${TU_CACHE_OFF_REASON:-?})"
    local rflags=()
    mapfile -t -d '' rflags < "$real_flags"
    if [ "${#rflags[@]}" -gt 0 ] &&
       [ -z "${rflags[$(( ${#rflags[@]} - 1 ))]}" ]; then
        unset "rflags[$(( ${#rflags[@]} - 1 ))]"
    fi
    printf '%s\n' "$real_src" > "$rdir/srcs.txt"
    TU_SELF_OUT="$rdir/out"
    tu_cache_paths_for() { tu_cache__self_paths_for "$@"; }
    tu_cache_plan "$rdir/srcs.txt" "$rdir/miss.txt"
    [ "$(grep -c . "$rdir/miss.txt" || true)" = 1 ] || tu_cache__self_fail \
        "a fresh generation served $real_src without ever compiling it"
    tu_cache__self_paths_for "$real_src"
    tu_cache_run "$TU_LOG" "$TU_RC" "$real_cc" "${rflags[@]}" "$real_src"
    cp -- "$TU_LOG" "$rdir/cold.log"
    cp -- "$TU_RC" "$rdir/cold.rc"
    rm -f -- "$TU_LOG" "$TU_RC"
    tu_cache_plan "$rdir/srcs.txt" "$rdir/miss2.txt"
    [ "$(grep -c . "$rdir/miss2.txt" || true)" = 0 ] || tu_cache__self_fail \
        "$real_cc's stored result for $real_src did not replay"
    cmp -s "$rdir/cold.log" "$TU_LOG" || tu_cache__self_fail \
        "the real compiler's replayed log differs from its cold log"
    cmp -s "$rdir/cold.rc" "$TU_RC" || tu_cache__self_fail \
        "the real compiler's replayed status differs from its cold status"

    unset ZCL_TU_STUB_RUNS
    unset ZCL_TU_CACHE_SELFTEST_FORCE
    unset -f tu_cache_paths_for
    rm -rf "$base"
    echo "  OK: --self-test — tu-cache over $n synthetic TUs at 4 workers:"
    echo "      two consecutive runs on an unchanged tree are 100% hit and"
    echo "      byte-identical (a third too), a header edit busts all $n, a"
    echo "      .c edit busts exactly 1 and reverting it hits again, a stored"
    echo "      FAIL replays as FAIL, ZCL_LINT_TU_CACHE=0 stores none, and"
    echo "      $real_cc replays a real TU byte-for-byte"
    return 0
}
