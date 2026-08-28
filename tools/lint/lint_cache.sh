# shellcheck shell=bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# lint_cache.sh — the content-addressed per-gate lint result cache.
#
# Bazel-style, and a direct mirror of lib/test/src/testcache.c (the test-group
# cache) down to its safety properties: a gate is SKIPPED when the exact input
# it can see is byte-identical to the last time that gate PASSED. The key is
# SHA-256 over the whole scannable tree plus the gate's own invocation, and a
# stored PASS at that key is a proof the gate would pass again.
#
# SOUNDNESS is the whole point. A cached SKIP must be provably equivalent to a
# fresh PASS, so this module NEVER caches a gate whose real inputs it cannot
# bound:
#   - the gate is not on the classified-cacheable allowlist  -> NEVER CACHED
#     (a NEW gate is therefore uncached until somebody classifies it)
#   - the gate builds something, runs a compiler, or reads build/ -> NEVER
#   - the gate reads a built binary, git history, git config, /proc,
#     $HOME, or untracked/ignored worktree state                 -> NEVER
#   - any tracked file cannot be hashed, or the manifest comes back short
#     of the tracked-file count                                  -> the whole
#     cache reports itself UNAVAILABLE and every gate runs
#   - only PASS (rc 0) is ever stored; a failure is never cached
# A never-cached gate ALWAYS runs.
#
# WHY THE KEY IS THE WHOLE TREE, not a per-gate scan set. `make lint` already
# runs 8-way parallel, so its wall clock is floored by the single slowest gate,
# not by total work. Narrowing each gate to its own scan set would let a
# one-file edit skip the gates that cannot see that file — but the slowest
# gates are source scanners that must re-run on any source edit anyway, so the
# measured saving is ~2 s of a ~25 s wall. That is not worth 116 hand-declared
# closures, each of which is a chance to under-declare an input and cache a
# PASS over a real violation. Keying on everything cannot under-declare.
#
# What the tree key covers, and why each part is needed:
#   - every tracked file's CONTENT, keyed by path, so an edit anywhere busts it
#   - the tracked PATH SET (paths are in the manifest lines), so an added,
#     renamed or deleted file busts it — this is the answer to "a gate that
#     reads `git ls-files` output has the file set itself as an input"
#   - every UNTRACKED, non-ignored file a production scan can see, content and
#     all. ~85 of the gates enumerate their scan set with bare `find` / `grep
#     -r` rather than `git grep`, so untracked debris sitting in app/ or lib/
#     genuinely changes their verdict. Hashing it closes that hole outright
#     instead of reasoning case by case. The filter mirrors
#     scan_exclusions.sh's production contract exactly, so a concurrent
#     selftest's transient `_*fixture*.c` — which no production scan can see —
#     does not spuriously bust the cache either.
# Everything the gates themselves are made of is tracked and therefore already
# inside the key: run_lint.sh, this file, every gate script, gate_lib.sh,
# scan_exclusions.sh, every *_baseline.txt / allowlist, telemetry_scan_lib.awk,
# and the Makefile. There is no "did I remember to list the helper?" failure
# mode, because nothing is listed — everything is included.
#
# RESIDUAL ASSUMPTION (stated, not hidden): gitignored content sitting inside a
# scanned source root is not in the key. scan_exclusions.sh prunes build/,
# vendor/, .claude/ and test-tmp/ from every production scan, and the remaining
# ignored paths (.cache/, vendor/.cache/) are machine-local scratch that holds
# no source. This is the one gap, it is bounded to one directory, and it is
# exactly what --cold-audit re-checks by running everything fresh.
#
# Default OFF. `make lint`, `make ci` and the pre-push gate stay COLD unless
# --cache / ZCL_LINT_CACHE=1 is passed, so a cached SKIP never gates a push.

# ── cache identity ───────────────────────────────────────────────────────
# Bump on ANY change to what the key covers or how a verdict is decided; it
# partitions the keyspace so an old record can never be read by new logic.
LINT_CACHE_SCHEMA="zcl.lint_cache.v1"

LINT_CACHE_AVAILABLE=0    # 1 only when the tree key was fully derived
LINT_CACHE_TREE_KEY=""    # SHA-256 over everything a production scan can see
LINT_CACHE_DIR=""
LINT_CACHE_TRACKED_N=0
LINT_CACHE_UNTRACKED_N=0

lint_cache_note() { printf 'lint-cache: %s\n' "$*" >&2; }

# ── cacheability classification ──────────────────────────────────────────
# ALLOWLIST POLARITY, deliberately: a gate is cacheable only if it is named
# here. A gate added to LINT_GATES tomorrow is never-cached until somebody
# reads it and classifies it. The fail-safe direction is "runs anyway".
#
# Every gate below was read end to end (script + every helper it sources) and
# confirmed to be a pure function of what the tree key covers. The ones that
# are NOT are listed underneath, each with the reason it can never be cached.
LINT_CACHE_OK_GATES="
check-no-retired-agent-protocol check-scanner-immunity check-malloc
check-hotswap-dev-only check-hotswap-eligible-scope check-hotswap-static-state
check-hotswap-service-islands check-hotswap-swappable-shape check-stable-publish-contained check-raw-sqlite
check-raw-malloc check-json-value-init check-blob-read-bounds check-byte-order-codec-single
check-coins-lookup-nullcheck check-silent-errors-services
check-silent-errors-controllers check-silent-errors-jobs
check-silent-errors-conditions check-silent-errors-bool
check-log-macro-return-type check-no-runtime-abort check-wallet-raw-prepare-log
check-before-save-hooks check-pthread-create check-model-validation
check-model-ar-lifecycle check-long-functions check-rpc-registrar
check-lag-slo-observable check-lib-layering check-shape-include-direction
check-accel-oracle-pinned check-domain-purity check-core-include-boundary check-supervisor-registration
check-test-registration check-typed-blocker check-blocker-escape-registered
check-blocker-remedy check-blocker-handoff-declared
check-supervisor-progress-declared check-framework-shape
check-framework-filename-suffix check-no-raw-clock-outside-platform
check-sysinit-ordering check-sandbox-wired check-no-shellouts
check-no-writer-below-sealed-frontier check-peer-floor-single-source
check-proc-self-shim check-no-raw-sqlite-in-controllers check-supervisor-domain
check-thread-supervision check-file-purpose check-group-purpose
check-no-orphan-placement check-file-size-ceiling check-operator-needed-sink
check-condition-cooldown check-doc-accuracy check-doc-counts
check-no-stale-pinned-facts check-no-uncited-victory check-error-doc-refs
check-markdown-links check-doc-inline-paths check-hex-codec-single
check-one-result-type check-service-result-convergence
check-shape-includes-header check-projections-pure check-one-write-path
check-frontier-single-writer check-dumper-never-blocks check-no-block-index-flat
check-no-utxo-projection check-no-utxos-mirror-read
check-no-authoritative-ram-state check-no-dev-history-in-contracts
check-no-live-lab-history
check-stage-advances-or-blocks check-no-silent-ready check-honest-witness
check-consensus-parity check-no-new-repair-rung check-no-new-borrowed-seed
check-no-new-coin-backfill-caller check-route-command-parity
check-zclassicd-reach-allowlist check-stage-log-reorg-unsafe
check-no-csr-lock-on-finalize-drive check-mint-skip-crypto-offline-only
check-wire-harness-security-gate check-vcs-no-git check-vcs-no-sha1
check-vendor-provenance check-command-contract check-command-availability-truthful
check-command-input-keys
check-telemetry-ontology check-privileged-transition-receipt
check-c23-only
check-no-python
check-no-trust-state-ordering check-no-gnu-va-args check-no-warning-suppression
check-result-discard
"

# Why each never-cached gate can never be cached. A reason is MANDATORY —
# "it felt risky" is not a classification, and an unlisted gate falls through
# to the same never-cached outcome with a note.
lint_cache_never_reason() {
    case "$1" in
        check-standalone-tools-link)
            echo "runs 'make' and links 18 tool binaries — depends on build/ state and the toolchain" ;;
        check-build-epoch-integrity)
            echo "keys on the installed compiler id and 'make --version', and runs cc probes on a miss" ;;
        check-clang-portability)
            echo "invokes clang/gcc over ~1174 translation units; skips or fails on the installed clang major version" ;;
        check-api-reference-generated)
            echo "compiles and runs a C generator with cc" ;;
        check-describe-budget)
            echo "compiles and links the real command registry with cc, twice (once against a padded catalog for its selftest)" ;;
        check-lib-module-order)
            echo "reads the link graph out of build/obj via nm" ;;
        check-release-no-dev-symbols)
            echo "runs 'nm -D' over build/bin/zclassic23" ;;
        check-doc-no-false-deleted)
            echo "reads the byte size of build/bin/zclassic23" ;;
        check-observability-pairing)
            echo "runs a built binary that scans git history via merge-base/diff" ;;
        check-core-seal)
            echo "runs the built core_seal binary and reads the untracked .core-unseal-token; core/ is byte-sealed" ;;
        check-git-hooks-installed)
            echo "reads and WRITES git config core.hooksPath — per-clone metadata, not tracked content" ;;
        check-checkout-lock)
            echo "selftest of OS process/signal and lock behavior, not of tracked content" ;;
        check-systemd-memory-budget)
            echo "reads /proc/meminfo — the verdict depends on host RAM" ;;
        check-doc-claims)
            echo "expands ~ to \$HOME and probes paths outside the repo, and executes other lint gates as oracles" ;;
        check-no-stray-untracked-source)
            echo "its entire job is reading untracked and ignored worktree state; also the always-fresh backstop" ;;
        check-no-stray-root-files)
            echo "'ls -A .' reads the real root directory listing, ignored entries included" ;;
        check-fuzz-artifact-ledger)
            echo "enumerates UNTRACKED repro files left in lib/test/fuzz_seeds/ and resolves each corpus to a build/bin/fuzz_* target" ;;
        check-live-datadir-isolation)
            echo "reads lib/test/src by filesystem glob rather than git ls-files, on purpose: it must see an UNCOMMITTED test file, which is exactly when a live-datadir read gets introduced" ;;
        *)
            case " $(echo $LINT_CACHE_OK_GATES) " in
                *" $1 "*) return 1 ;;   # classified cacheable
                *) echo "not classified — a new gate is never cached until it is read and classified" ;;
            esac ;;
    esac
    return 0
}

# True (0) when the gate may be cached at all.
lint_cache_gate_is_cacheable() {
    ! lint_cache_never_reason "$1" >/dev/null
}

# ── tree key derivation ──────────────────────────────────────────────────
# Hash every tracked file's content (paths included, so an add/rename/delete
# moves the key), then every untracked file a production scan could see. Any
# stumble anywhere leaves the cache UNAVAILABLE, which means every gate runs.
lint_cache_derive_tree_key() {
    local root="$1" tmp tracked_manifest untracked_manifest expect got
    command -v sha256sum >/dev/null 2>&1 || {
        lint_cache_note "unavailable: sha256sum not found"; return 1; }

    tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-lint-cache.XXXXXX")" || {
        lint_cache_note "unavailable: could not create a temp dir"; return 1; }
    tracked_manifest="$tmp/tracked"
    untracked_manifest="$tmp/untracked"

    # Tracked content. Mode 160000 is the vendor/tor gitlink (a submodule
    # pointer, not a file) — dropped, and no cacheable gate reads it.
    expect="$(git -C "$root" ls-files -s -z 2>/dev/null \
        | awk -v RS='\0' '$1 != "160000"' | wc -l)"
    if ! git -C "$root" ls-files -s -z 2>/dev/null \
            | awk -v RS='\0' -v ORS='\0' '$1 != "160000" { sub(/^[^\t]*\t/, ""); print }' \
            | (cd "$root" && xargs -0 -r sha256sum) 2>/dev/null \
            | LC_ALL=C sort > "$tracked_manifest"; then
        lint_cache_note "unavailable: could not hash the tracked tree (a tracked file is missing or unreadable)"
        rm -rf "$tmp"; return 1
    fi
    got="$(wc -l < "$tracked_manifest")"
    # Anti-hollow floor, in the spirit of gate_lib.sh's gate_require_scanned:
    # a short manifest means a partial input set, and a key over a partial
    # input set is exactly how a cache starts hiding violations.
    if [ "$got" -ne "$expect" ] || [ "$got" -lt 100 ]; then
        lint_cache_note "unavailable: hashed $got of $expect tracked files — refusing to key off a partial tree"
        rm -rf "$tmp"; return 1
    fi
    LINT_CACHE_TRACKED_N="$got"

    # Untracked, non-ignored files, filtered to exactly what a production scan
    # can see (scan_exclusions.sh's contract: transient fixtures and
    # build/vendor/.claude/test-tmp noise are invisible to every gate, so they
    # must not move the key either).
    # awk, not `grep -v`, for the filter: grep exits 1 when it drops every
    # line, and under `set -o pipefail` a clean tree would then look like a
    # hashing failure and disable the cache on exactly the runs it exists for.
    if ! git -C "$root" ls-files -z --others --exclude-standard 2>/dev/null \
            | awk -v RS='\0' -v ORS='\0' '
                  /(^|\/)_[^\/]*fixture[^\/]*\.[ch]$/ { next }
                  /(^|\/)(tools\/lint\/fixtures\/planted|build|vendor|\.claude|test-tmp)\// { next }
                  { print }' \
            | (cd "$root" && xargs -0 -r sha256sum) 2>/dev/null \
            | LC_ALL=C sort > "$untracked_manifest"; then
        lint_cache_note "unavailable: could not hash the visible untracked set"
        rm -rf "$tmp"; return 1
    fi
    LINT_CACHE_UNTRACKED_N="$(wc -l < "$untracked_manifest")"

    LINT_CACHE_TREE_KEY="$( { printf '%s\ntracked %s\nuntracked %s\n' \
            "$LINT_CACHE_SCHEMA" "$LINT_CACHE_TRACKED_N" "$LINT_CACHE_UNTRACKED_N"
          cat "$tracked_manifest" "$untracked_manifest"; } \
        | sha256sum | awk '{print $1}')"
    rm -rf "$tmp"
    [[ "$LINT_CACHE_TREE_KEY" =~ ^[0-9a-f]{64}$ ]] || {
        lint_cache_note "unavailable: tree key is not a sha256"; return 1; }
    return 0
}

# Open the cache. Sets LINT_CACHE_AVAILABLE=1 only on complete success;
# every failure path leaves it 0, which makes every gate run.
lint_cache_open() {
    local root="$1"
    LINT_CACHE_AVAILABLE=0
    LINT_CACHE_DIR="${ZCL_LINT_CACHE_DIR:-$root/.cache/lint-cache/$LINT_CACHE_SCHEMA}"
    lint_cache_derive_tree_key "$root" || return 1
    mkdir -p "$LINT_CACHE_DIR" 2>/dev/null || {
        lint_cache_note "unavailable: cannot create $LINT_CACHE_DIR"; return 1; }
    [ -w "$LINT_CACHE_DIR" ] || {
        lint_cache_note "unavailable: $LINT_CACHE_DIR is not writable"; return 1; }
    LINT_CACHE_AVAILABLE=1
    return 0
}

# The per-gate key. Folds in everything that changes a verdict without
# changing a tracked byte: the exact command string (so a ZCL_LINT_MODE prefix
# or a changed argument re-keys), and the two env vars the driver exports into
# every gate.
lint_cache_key() {
    local gate="$1" cmd="$2"
    printf '%s|%s|%s|%s|%s|%s' \
        "$LINT_CACHE_SCHEMA" "$gate" "$cmd" "$LINT_CACHE_TREE_KEY" \
        "${ZCL_LINT_PRODUCTION_SCAN:-}" "${ZCL_LINT_BIN_DIR:-}" \
        | sha256sum | awk '{print $1}'
}

lint_cache_record_path() {
    printf '%s/%s/%s' "$LINT_CACHE_DIR" "${1:0:2}" "${1:2}"
}

# True (0) iff a stored PASS exists at this key.
lint_cache_has_pass() {
    local rec; rec="$(lint_cache_record_path "$1")"
    [ -f "$rec" ] && grep -q "^schema=$LINT_CACHE_SCHEMA\$" "$rec" 2>/dev/null
}

# Store a PASS. Best effort by design — a failed store only costs a future
# re-run, never correctness. ONLY ever called for a gate that just exited 0.
lint_cache_store_pass() {
    local gate="$1" key="$2" rec dir
    rec="$(lint_cache_record_path "$key")"
    dir="$(dirname "$rec")"
    mkdir -p "$dir" 2>/dev/null || return 0
    { printf 'schema=%s\ngate=%s\nkey=%s\nstored_at_utc=%s\n' \
        "$LINT_CACHE_SCHEMA" "$gate" "$key" "$(date -u +%FT%TZ)"
    } > "$rec.tmp.$$" 2>/dev/null && mv -f "$rec.tmp.$$" "$rec" 2>/dev/null
    rm -f "$rec.tmp.$$" 2>/dev/null
    return 0
}

# Diagnostic surface: what does this gate key on, and is it a hit right now?
lint_cache_dump() {
    local gate="$1" cmd="$2" reason key
    echo "gate:            $gate"
    echo "command:         $cmd"
    if reason="$(lint_cache_never_reason "$gate")"; then
        echo "cacheable:       NO"
        echo "reason:          $reason"
        return 0
    fi
    echo "cacheable:       yes"
    if [ "$LINT_CACHE_AVAILABLE" != "1" ]; then
        echo "cache:           UNAVAILABLE (every gate would run)"
        return 0
    fi
    echo "schema:          $LINT_CACHE_SCHEMA"
    echo "tracked files:   $LINT_CACHE_TRACKED_N"
    echo "untracked files: $LINT_CACHE_UNTRACKED_N (visible to a production scan)"
    echo "tree key:        $LINT_CACHE_TREE_KEY"
    echo "production scan: ${ZCL_LINT_PRODUCTION_SCAN:-}"
    echo "bin dir:         ${ZCL_LINT_BIN_DIR:-}"
    key="$(lint_cache_key "$gate" "$cmd")"
    echo "gate key:        $key"
    echo "record:          $(lint_cache_record_path "$key")"
    if lint_cache_has_pass "$key"; then
        echo "state:           HIT (a stored PASS exists at this exact key)"
    else
        echo "state:           MISS (this gate would run)"
    fi
}
