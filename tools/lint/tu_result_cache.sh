# shellcheck shell=bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# tu_result_cache.sh — a per-TRANSLATION-UNIT result cache shared by the two
# compile-sweep lint gates, check_clang_portability.sh (2104 TUs) and
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
# 2104-TU sweep is paid again in full to re-check 2103 unchanged files. That
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
# WHY THE KEY IS SOUND
# clang/gcc -fsyntax-only over one TU is a pure function of
#
#   (1) the compiler                 -> "$CC --version" first line
#   (2) the exact argv               -> sha256 of the NUL-joined final argv,
#                                       which includes every flag, every -I,
#                                       every -D, the per-TU extras the gate
#                                       workers append, and the source path
#   (3) the TU's own bytes           -> sha256 of the source file
#   (4) every file it can textually  -> the INCLUDE-SET DIGEST below
#       include
#   (5) the rules that derive 1-4    -> sha256 of the gate script and of this
#                                       helper, so any edit to either voids
#                                       every entry
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
# diagnostics).
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
#       Derive the salt, open the cache dir, export the worker contract.
#       Never fails the gate: on any problem it disables and records why.
#   tu_cache_summary
#       Print "  tu-cache: N hit, M miss, K stored" (or the disabled form).
#   tu_cache_selftest <gate> <gate-script> <cc> <flags-nul> <scratch> <src>
#       The six soundness proofs; exits 1 naming the one that failed.
#
# WORKER-SIDE API (each xargs worker, after sourcing this file)
#   tu_cache_run <log> <rc-file> <cc> <arg>...
#       Behaves exactly like
#           "$cc" "$@" > "$log" 2>&1; printf '%s\n' "$?" > "$rc-file"
#       serving from / storing into the cache when it is on. Always 0.
#
# Sourcing contract: source AFTER the gate's `cd` to the repo root. Safe
# under `set -euo pipefail` (check_windows_cross_syntax.sh) and under
# `set -uo pipefail` (check_clang_portability.sh).

# Absolute path to this file, so a forked worker can source it by name. Every
# worker sources this file, so resolving the path costs one subshell per
# translation unit unless the already-exported answer is reused.
if [ -n "${ZCL_TU_CACHE_LIB:-}" ]; then
    TU_CACHE_LIB_PATH="$ZCL_TU_CACHE_LIB"
else
    TU_CACHE_LIB_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
fi
TU_CACHE_OFF_REASON=""

# Entries unused for this many days are swept at setup, and the whole gate
# dir is dropped once it passes the cap. One header edit writes a fresh
# generation of every entry, so an unbounded dir would grow by ~2300 files
# per header touch and never shrink.
TU_CACHE_MAX_AGE_DAYS="${ZCL_LINT_TU_CACHE_MAX_AGE_DAYS:-7}"
TU_CACHE_MAX_ENTRIES="${ZCL_LINT_TU_CACHE_MAX_ENTRIES:-120000}"

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

    # (1) every file that is an include target by extension.
    find "$root" \( "${pruned[@]}" \) -prune -o -type f \
        \( -name '*.h' -o -name '*.inc' -o -name '*.def' \) -print \
        > "$list" 2>/dev/null || true

    # (2) plus every *.c some file names in an #include. A .c pulled in as
    #     text is a header in everything but its extension, and one such
    #     edge lives inside the clang gate's scan set today.
    if [ -s "$list" ]; then
        find "$root" \( "${pruned[@]}" \) -prune -o -type f \
            \( -name '*.c' -o -name '*.h' -o -name '*.inc' -o -name '*.def' \) -print0 2>/dev/null |
            xargs -0 -r grep -hoE '#[[:space:]]*include[[:space:]]*"[^"]*\.c"' 2>/dev/null |
            sed 's|.*/||; s|"$||' | LC_ALL=C sort -u > "$names" || true
        if [ -s "$names" ]; then
            local base
            while IFS= read -r base; do
                [ -n "$base" ] || continue
                find "$root" \( "${pruned[@]}" \) -prune -o -type f \
                    -name "$base" -print >> "$list" 2>/dev/null || true
            done < "$names"
        fi
    fi

    [ -s "$list" ] || return 1

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

    # sha256sum escapes backslashes and newlines in names, which would make
    # the digest ambiguous. No such path exists in this tree; refuse rather
    # than hash an ambiguous list.
    if grep -qE '[[:space:]\\]' "$list"; then return 1; fi

    LC_ALL=C sort -u "$list" | tr '\n' '\0' |
        xargs -0 -r sha256sum 2>/dev/null |
        awk '{ h = $1; $1 = ""; sub(/^ +/, "", $0); printf "%s\t%s\n", $0, h }' |
        LC_ALL=C sort | tu_cache__sha_stdin
}

tu_cache__prune() {
    local dir="$1" n
    find "$dir" -maxdepth 1 -type f -mtime "+$TU_CACHE_MAX_AGE_DAYS" -delete 2>/dev/null || true
    n="$(find "$dir" -maxdepth 1 -type f 2>/dev/null | wc -l)"
    [ -n "$n" ] || n=0
    if [ "$n" -gt "$TU_CACHE_MAX_ENTRIES" ]; then
        find "$dir" -maxdepth 1 -type f -delete 2>/dev/null || true
    fi
    return 0
}

tu_cache_setup() {
    local gate="$1" gate_script="$2" cc="$3" flags_nul="$4" scratch="$5"
    local root="${6:-.}" cachedir="${7:-}"
    local cc_id lib_sha gate_sha flags_sha digest salt dir

    TU_CACHE_OFF_REASON=""
    ZCL_TU_CACHE_ON=0
    ZCL_TU_CACHE_DIR=""
    ZCL_TU_CACHE_SALT=""
    ZCL_TU_CACHE_STATS=""
    ZCL_TU_CACHE_LIB="$TU_CACHE_LIB_PATH"
    export ZCL_TU_CACHE_ON ZCL_TU_CACHE_DIR ZCL_TU_CACHE_SALT ZCL_TU_CACHE_STATS ZCL_TU_CACHE_LIB

    if [ "${ZCL_LINT_TU_CACHE:-1}" = "0" ]; then
        tu_cache__disable "ZCL_LINT_TU_CACHE=0"; return 0
    fi
    if [ "${ZCL_LINT_CACHE_MODE:-off}" = "audit" ]; then
        tu_cache__disable "--cold-audit runs everything fresh"; return 0
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
    salt="$(printf 'tu-result-cache/v1\n%s\n%s\n%s\n%s\n%s\n%s\n' \
        "$gate" "$lib_sha" "$gate_sha" "$cc_id" "$flags_sha" "$digest" |
        tu_cache__sha_stdin)"
    if [ "${#salt}" -ne 64 ]; then
        tu_cache__disable "salt derivation produced no digest"; return 0
    fi

    if [ -n "$cachedir" ]; then
        dir="$cachedir/$gate"
    else
        dir="${ZCL_LINT_TU_CACHE_DIR:-$PWD/.cache/lint-tu}/$gate"
    fi
    if ! mkdir -p "$dir" 2>/dev/null; then
        tu_cache__disable "cannot create '$dir'"; return 0
    fi
    tu_cache__prune "$dir"

    ZCL_TU_CACHE_DIR="$dir"
    ZCL_TU_CACHE_SALT="$salt"
    ZCL_TU_CACHE_STATS="$scratch/tu-cache.events"
    : > "$ZCL_TU_CACHE_STATS" 2>/dev/null || {
        tu_cache__disable "cannot write '$ZCL_TU_CACHE_STATS'"; return 0; }
    ZCL_TU_CACHE_ON=1
    export ZCL_TU_CACHE_ON ZCL_TU_CACHE_DIR ZCL_TU_CACHE_SALT ZCL_TU_CACHE_STATS ZCL_TU_CACHE_LIB
    return 0
}

tu_cache_counts() {
    local h=0 m=0 s=0
    if [ -n "${ZCL_TU_CACHE_STATS:-}" ] && [ -f "$ZCL_TU_CACHE_STATS" ]; then
        h="$(grep -c '^h$' "$ZCL_TU_CACHE_STATS" 2>/dev/null || true)"
        m="$(grep -c '^m$' "$ZCL_TU_CACHE_STATS" 2>/dev/null || true)"
        s="$(grep -c '^s$' "$ZCL_TU_CACHE_STATS" 2>/dev/null || true)"
    fi
    printf '%s %s %s' "${h:-0}" "${m:-0}" "${s:-0}"
}

tu_cache_summary() {
    local counts h m s
    if [ "${ZCL_TU_CACHE_ON:-0}" != "1" ]; then
        echo "  tu-cache: 0 hit, 0 miss, 0 stored (off: ${TU_CACHE_OFF_REASON:-not enabled})"
        return 0
    fi
    counts="$(tu_cache_counts)"
    read -r h m s <<<"$counts"
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

# ONE key, ONE pipeline. The naive spelling (hash the argv, hash the source,
# hash the two hashes) costs six forks per translation unit; on a fully warm
# 2104-TU sweep that is more process creation than the work it replaces.
# Streaming salt + argc + argv + source bytes through a single sha256sum
# costs two, and the explicit argc makes the framing unambiguous: nothing
# the source contains can forge a different argv split, because the number
# of NUL-delimited fields is fixed before the content starts.
tu_cache__key() {
    local src digest
    [ "$#" -ge 2 ] || return 1
    src="${!#}"
    [ -f "$src" ] || return 1
    digest="$( { printf '%s\0' "$ZCL_TU_CACHE_SALT" "$#" "$@"
                 cat -- "$src"; } 2>/dev/null | sha256sum 2>/dev/null )"
    digest="${digest%% *}"
    [ "${#digest}" -eq 64 ] || return 1
    printf '%s' "$digest"
}

# One file per entry: the compiler's exit status on line 1, its combined
# stdout/stderr verbatim after it. One file means the store is a SINGLE
# rename, so a reader can never catch an entry half-written, and the replay
# is one read plus one copy instead of four file operations.
tu_cache__store() {
    local key="$1" rc="$2" log="$3" ent tmp
    ent="$ZCL_TU_CACHE_DIR/$key"
    tmp="$ZCL_TU_CACHE_DIR/.tmp.$$.${RANDOM}"
    if ! { printf '%s\n' "$rc"; cat -- "$log"; } > "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        return 1
    fi
    if ! mv -f "$tmp" "$ent" 2>/dev/null; then
        rm -f "$tmp"
        return 1
    fi
    return 0
}

tu_cache_run() {
    local log="$1" rcf="$2" cc="$3"
    shift 3
    local key="" ent rc=0 cached_rc=""

    if [ "${ZCL_TU_CACHE_ON:-0}" = "1" ]; then
        key="$(tu_cache__key "$cc" "$@" 2>/dev/null)" || key=""
    fi
    if [ -n "$key" ]; then
        ent="$ZCL_TU_CACHE_DIR/$key"
        if [ -f "$ent" ] &&
           { IFS= read -r cached_rc && cat; } < "$ent" > "$log" 2>/dev/null &&
           [ -n "$cached_rc" ] && [ -z "${cached_rc//[0-9]/}" ]; then
            printf '%s\n' "$cached_rc" > "$rcf"
            # Keep a served entry young: the age sweep must drop only what the
            # tree has genuinely stopped compiling, not what it keeps using.
            touch -- "$ent" 2>/dev/null || true
            tu_cache__event h
            return 0
        fi
        tu_cache__event m
    fi

    # Save and restore errexit rather than assuming it: the two callers
    # differ (check_windows_cross_syntax.sh runs under `set -e`, the
    # check_clang_portability.sh worker does not), and a helper that turned
    # errexit ON in a worker that never asked for it would abort that worker
    # mid-sweep on the first nonzero status.
    local had_errexit=0
    case "$-" in *e*) had_errexit=1 ;; esac
    set +e
    "$cc" "$@" > "$log" 2>&1
    rc=$?
    [ "$had_errexit" = 1 ] && set -e
    printf '%s\n' "$rc" > "$rcf"
    if [ -n "$key" ] && tu_cache__store "$key" "$rc" "$log"; then
        tu_cache__event s
    fi
    return 0
}
# ── Soundness selftest ────────────────────────────────────────────────────
# Six proofs, run from each gate's own --self-test so `make lint` exercises
# them on every run. Five run against a SYNTHETIC root and a stub compiler:
# the properties under test are properties of the KEY, and proving them
# against the real tree would mean editing a real header mid-lint and paying
# for a whole extra 2104-TU sweep. The sixth runs the gate's REAL compiler
# and REAL flag set over one REAL source, which is what proves the wiring
# between the two.

tu_cache__self_fail() {
    echo "FAIL: --self-test — tu-cache: $1" >&2
    exit 1
}

# One pass of the stub compiler over the synthetic sources; echoes
# "<hit> <miss> <stored>". Runs inside a command substitution, so the
# exports tu_cache_setup makes are confined to that subshell while the cache
# entries it writes land on the real filesystem — exactly the shape a real
# gate has, where the parent derives the salt and forked workers do the I/O.
tu_cache__self_pass_over() {
    local base="$1" stub="$2" flags="$3" root="$4"
    shift 4
    local src
    tu_cache_setup tu-cache-selftest "$stub" "$stub" "$flags" "$base" \
        "$root" "$base/cachedir"
    [ "${ZCL_TU_CACHE_ON:-0}" = "1" ] || tu_cache__self_fail \
        "the cache refused to enable on a synthetic root (${TU_CACHE_OFF_REASON:-?})"
    for src in "$@"; do
        tu_cache_run "$base/out/$(basename "$src").log" \
                     "$base/out/$(basename "$src").rc" "$stub" -c "$src"
    done
    tu_cache_counts
}

tu_cache_selftest() {
    local gate="$1" gate_script="$2" real_cc="$3" real_flags="$4"
    local scratch="$5" real_src="$6"
    local base root stub flags h m s runs_before runs_after rdir
    [ -f "$real_src" ] || tu_cache__self_fail \
        "no real source was handed to the wiring proof (got '$real_src'); the gate's scan set is empty or moved"
    base="$scratch/tu-cache-selftest"
    root="$base/root"
    rm -rf "$base"
    mkdir -p "$root" "$base/out" "$base/cachedir"

    printf '#define TU_SELFTEST_SHARED 1\n' > "$root/shared.h"
    printf '#include "shared.h"\nint a(void);\n' > "$root/a.c"
    printf '#include "shared.h"\nint b(void);\n' > "$root/b.c"

    # Stub compiler: counts its own invocations, prints a body derived from
    # the source it was handed, and FAILS on b.c. A replay is therefore
    # distinguishable from a re-run by the invocation counter, and the
    # replayed bytes and status are checkable against the cold ones.
    stub="$base/stub_cc.sh"
    cat > "$stub" <<'END_STUB'
#!/usr/bin/env bash
set -uo pipefail
if [ "${1:-}" = "--version" ]; then echo "tu-cache stub compiler 1.0"; exit 0; fi
src="${!#}"
printf '%s\n' "$src: stub diagnostic" >&2
printf 'runs so far: %s\n' "$(wc -l < "$ZCL_TU_STUB_RUNS")"
echo x >> "$ZCL_TU_STUB_RUNS"
case "$src" in *b.c) exit 1 ;; esac
exit 0
END_STUB
    chmod +x "$stub"
    ZCL_TU_STUB_RUNS="$base/runs"
    export ZCL_TU_STUB_RUNS
    : > "$ZCL_TU_STUB_RUNS"

    flags="$base/flags.nul"
    printf '%s\0' -c > "$flags"

    # (1) COLD: nothing cached, both TUs compiled and stored.
    read -r h m s <<<"$(tu_cache__self_pass_over "$base" "$stub" "$flags" \
        "$root" "$root/a.c" "$root/b.c")"
    { [ "$h" = 0 ] && [ "$m" = 2 ] && [ "$s" = 2 ]; } || tu_cache__self_fail \
        "a cold run over 2 synthetic TUs reported '$h' hit / '$m' miss / '$s' stored, wanted 0/2/2"
    cp "$base/out/a.c.log" "$base/cold-a.log"
    cp "$base/out/b.c.log" "$base/cold-b.log"
    cp "$base/out/b.c.rc"  "$base/cold-b.rc"

    # (2) A HIT REPLAYS THE COLD VERDICT: byte-identical log, same status,
    #     and the compiler was not invoked again.
    runs_before="$(wc -l < "$ZCL_TU_STUB_RUNS")"
    read -r h m s <<<"$(tu_cache__self_pass_over "$base" "$stub" "$flags" \
        "$root" "$root/a.c" "$root/b.c")"
    runs_after="$(wc -l < "$ZCL_TU_STUB_RUNS")"
    { [ "$h" = 2 ] && [ "$m" = 0 ]; } || tu_cache__self_fail \
        "a warm run reported '$h' hit / '$m' miss, wanted 2/0"
    [ "$runs_before" = "$runs_after" ] || tu_cache__self_fail \
        "a warm run still invoked the compiler ($runs_before -> $runs_after)"
    cmp -s "$base/out/a.c.log" "$base/cold-a.log" || tu_cache__self_fail \
        "a replayed log differs from the cold log"

    # (3) A STORED FAIL REPLAYS AS A FAIL, never as a pass.
    cmp -s "$base/out/b.c.rc" "$base/cold-b.rc" || tu_cache__self_fail \
        "a replayed exit status differs from the cold one"
    [ "$(cat "$base/out/b.c.rc")" = 1 ] || tu_cache__self_fail \
        "a stored FAIL (rc=1) did not replay as a FAIL"
    cmp -s "$base/out/b.c.log" "$base/cold-b.log" || tu_cache__self_fail \
        "a replayed FAIL log differs from the cold FAIL log"

    # (4) EDITING A HEADER BUSTS EVERY TU.
    printf '#define TU_SELFTEST_SHARED 2\n' > "$root/shared.h"
    read -r h m s <<<"$(tu_cache__self_pass_over "$base" "$stub" "$flags" \
        "$root" "$root/a.c" "$root/b.c")"
    { [ "$h" = 0 ] && [ "$m" = 2 ]; } || tu_cache__self_fail \
        "editing a header left '$h' of 2 TUs on a stale cache entry"

    # (5) EDITING ONE TU BUSTS ONLY THAT TU.
    printf '#include "shared.h"\nint a(int);\n' > "$root/a.c"
    read -r h m s <<<"$(tu_cache__self_pass_over "$base" "$stub" "$flags" \
        "$root" "$root/a.c" "$root/b.c")"
    { [ "$h" = 1 ] && [ "$m" = 1 ]; } || tu_cache__self_fail \
        "editing one of 2 TUs produced '$h' hit / '$m' miss, wanted 1/1"

    # (5b) ZCL_LINT_TU_CACHE=0 neither serves nor stores, and still compiles.
    runs_before="$(wc -l < "$ZCL_TU_STUB_RUNS")"
    ZCL_LINT_TU_CACHE=0 \
        tu_cache_setup tu-cache-selftest "$stub" "$stub" "$flags" "$base" \
        "$root" "$base/cachedir-off"
    [ "${ZCL_TU_CACHE_ON:-0}" = "1" ] && tu_cache__self_fail \
        "ZCL_LINT_TU_CACHE=0 did not disable the cache"
    tu_cache_run "$base/out/off.log" "$base/out/off.rc" "$stub" -c "$root/a.c"
    runs_after="$(wc -l < "$ZCL_TU_STUB_RUNS")"
    [ "$runs_before" != "$runs_after" ] || tu_cache__self_fail \
        "a disabled cache did not invoke the compiler"
    [ -d "$base/cachedir-off" ] && tu_cache__self_fail \
        "a disabled cache still opened a cache directory"

    # (6) THE REAL WIRING: the gate's own compiler, its own flag set, one
    #     real source of this gate's, in a private cache dir. Cold, then
    #     warm; the warm pass must be a hit and byte-identical.
    rdir="$base/real"
    mkdir -p "$rdir"
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
    tu_cache_run "$rdir/cold.log" "$rdir/cold.rc" "$real_cc" "${rflags[@]}" "$real_src"
    tu_cache_run "$rdir/warm.log" "$rdir/warm.rc" "$real_cc" "${rflags[@]}" "$real_src"
    read -r h m s <<<"$(tu_cache_counts)"
    { [ "$h" = 1 ] && [ "$m" = 1 ] && [ "$s" = 1 ]; } || tu_cache__self_fail \
        "the real compiler cold+warm pair over $real_src reported '$h' hit / '$m' miss / '$s' stored, wanted 1/1/1"
    cmp -s "$rdir/cold.log" "$rdir/warm.log" || tu_cache__self_fail \
        "the real compiler's replayed log differs from its cold log"
    cmp -s "$rdir/cold.rc" "$rdir/warm.rc" || tu_cache__self_fail \
        "the real compiler's replayed status differs from its cold status"

    unset ZCL_TU_STUB_RUNS
    rm -rf "$base"
    echo "  OK: --self-test — tu-cache: a hit replays the cold verdict"
    echo "      byte-for-byte (stub compiler AND $real_cc on a real TU), a"
    echo "      header edit busts every TU, a .c edit busts only that TU, a"
    echo "      stored FAIL replays as FAIL, ZCL_LINT_TU_CACHE=0 stores none"
    return 0
}
