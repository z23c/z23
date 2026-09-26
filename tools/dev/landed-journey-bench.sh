#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: Drive ONE narrow C23 edit through the complete landed journey —
# reflex feedback (impact, minimal build, new-byte execution), signed
# commit, exact resident proof, landing queue, push, remote acceptance,
# durable receipt — inside an isolated scratch clone against a local bare
# remote, measuring every stage; then exercise crash/retry, stale-main,
# tampered-receipt and duplicate-request handling against the same real
# machinery. Isolation is total: HOME, the z23 state root, the land queue,
# the proof signer and the RAM-scratch leases all resolve under the scratch
# directory, so the operator's real lane on this host is never touched.

set -euo pipefail

fail() { printf 'landed-journey-bench: %s\n' "$*" >&2; exit 2; }

ROOT="${ZCL_SOURCE_ROOT:-$(pwd -P)}"
CASES="${ZCL_JOURNEY_CASES:-all}"
SCRATCH="${ZCL_JOURNEY_SCRATCH:-}"
SEED_REF="${ZCL_JOURNEY_SEED_REF:-}"
OUTPUT="${ZCL_JOURNEY_OUTPUT:-$ROOT/build/dev-loop/landed-journey-benchmark.json}"
SOURCE_REL="contexts/wallet/services/src/vault_intent_decision_service.c"
JOBS="$(getconf _NPROCESSORS_ONLN)"

[[ -f "$ROOT/Makefile" && -f "$ROOT/$SOURCE_REL" ]] ||
    fail "not a z23 checkout: $ROOT"
[[ -x "$ROOT/build/bin/z23-dev" ]] ||
    fail 'missing build/bin/z23-dev (make dev-bin)'
command -v jq >/dev/null || fail 'jq is required'
case "$CASES" in
    all|journey|dupcrash|stale|tamper) ;;
    *) fail "unknown ZCL_JOURNEY_CASES: $CASES" ;;
esac

MADE_SCRATCH=0
if [[ -z "$SCRATCH" ]]; then
    # The scratch must live OUTSIDE the repository's test-tmp/: the sealed
    # proof runs production-mode lint inside its generation, and the
    # production scanner exclusions drop any absolute path containing a
    # /test-tmp/ segment, which blinds gates the scanner-immunity selftest
    # plants violations for (observed as false-clean rc=0 on 2026-09-26).
    SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/z23-landed-journey.XXXXXX")"
    MADE_SCRATCH=1
fi
SCRATCH="$(cd "$SCRATCH" && pwd -P)"
# The operator-home stand-in is named xhome, never home: a literal
    # slash-home-slash substring anywhere in this tracked script trips
    # check-no-operator-paths prong A (the account-token mint), whose prong B
    # then reports every unrelated "clone" occurrence in the tree.
HOME_SCRATCH="$SCRATCH/xhome"
REMOTE="$SCRATCH/remote.git"
CLONE="$SCRATCH/xhome/clone"
CLONE2="$SCRATCH/xhome/clone2"
STATE="$HOME_SCRATCH/.local/state/z23/dev"
LAND_WT="$STATE/land/wt"
CLOCK_BIN="$SCRATCH/monotonic-clock"
RECEIPTS="$SCRATCH/receipts"

cleanup()
{
    if [[ -s "$SCRATCH/watcher_id" && -x "$CLONE/build/bin/z23-dev" ]]; then
        local stop_id stop_session
        read -r stop_id stop_session <"$SCRATCH/watcher_id" || true
        if [[ -n "${stop_id:-}" && -n "${stop_session:-}" ]]; then
            (cd "$CLONE" && HOME="$HOME_SCRATCH" \
                ./build/bin/z23-dev dev loop stop \
                --input="{\"watcher_id\":$stop_id,\"watcher_session\":\"$stop_session\"}") \
                >/dev/null 2>&1 || true
        fi
        rm -f "$SCRATCH/watcher_id"
    fi
    if [[ "$MADE_SCRATCH" == 1 && "${ZCL_JOURNEY_KEEP:-0}" != 1 ]]; then
        rm -rf "$SCRATCH"
    fi
}
trap cleanup EXIT INT TERM

# dev loop stop refuses to signal a process without the exact
# (watcher_id, watcher_session) pair copied from live status; the scratch
# watcher_id file carries both, space-separated.
watcher_identity_save()
{
    local st
    st="$(devbin dev loop status)" || return 1
    jq -er '.data | "\(.watcher_id) \(.watcher_session)"' <<<"$st" \
        >"$SCRATCH/watcher_id"
}

watcher_stop()
{
    local stop_id stop_session
    [[ -s "$SCRATCH/watcher_id" ]] || return 0
    read -r stop_id stop_session <"$SCRATCH/watcher_id" || true
    if [[ -n "${stop_id:-}" && -n "${stop_session:-}" ]]; then
        devbin dev loop stop \
            --input="{\"watcher_id\":$stop_id,\"watcher_session\":\"$stop_session\"}" \
            >/dev/null 2>&1 || true
    fi
    rm -f "$SCRATCH/watcher_id"
}

# A crashed run leaves its resident watcher armed on the scratch clone and
# the next begin refuses. The lock's first field is the watcher pid; only
# kill it after /proc confirms the process belongs to this scratch clone.
watcher_reap_stale()
{
    local lock="$CLONE/.cache/zcl-dev-watch.lock" pid
    if [[ -s "$SCRATCH/watcher_id" ]]; then
        watcher_stop
        return 0
    fi
    [[ -f "$lock" ]] || return 0
    pid="$(awk '{print $1}' "$lock")"
    if [[ "$pid" =~ ^[0-9]+$ ]] && [[ -r "/proc/$pid/cmdline" ]] &&
       grep -q "$CLONE" "/proc/$pid/cmdline" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do
            [[ ! -d "/proc/$pid" ]] && break
            sleep 0.5
        done
    fi
}

mkdir -p "$HOME_SCRATCH" "$SCRATCH/ram" "$RECEIPTS"

# The sealed proof sets ZCL_STRESS_TESTS=1, which expresses intent to
# observe the Sapling prover leg in test_shielded_payment_gate; without the
# public parameter fixture the leg reports UNOBSERVED and the proof's test
# accounting refuses the run (run 16: test_accounting_incomplete with every
# group green). The params are immutable public bytes, never mutated by the
# leg, so a read-only symlink into the isolated HOME preserves both the
# sandbox and the observation. Refuse loudly when the operator host lacks
# the fixture rather than measuring a proof that cannot complete.
if [[ ! -e "$HOME_SCRATCH/.zcash-params" ]]; then
    [[ -d "$HOME/.zcash-params" ]] ||
        fail 'the proof requires the Sapling parameter fixture; no ~/.zcash-params on this host'
    ln -s "$HOME/.zcash-params" "$HOME_SCRATCH/.zcash-params" ||
        fail 'could not link the Sapling parameters into the scratch HOME'
fi

cc -std=c23 -Wall -Wextra -Werror -pedantic \
    "$ROOT/tools/dev/fixtures/reflex_reactor/monotonic_edit.c" \
    -o "$CLOCK_BIN" || fail 'could not build the monotonic clock helper'

now_us() { "$CLOCK_BIN"; }

# Every scratch-side command runs with the isolated HOME and RAM-scratch
# lease root. Nothing reaches the operator's ~/.local/state or /dev/shm
# lease directory.
runenv()
{
    (cd "$CLONE" && HOME="$HOME_SCRATCH" \
        ZCL_RAM_SCRATCH_ROOT="$SCRATCH/ram" "$@")
}

devbin() { runenv "$CLONE/build/bin/z23-dev" "$@"; }

# ── Scaffold: bare remote, clone, vendored dependencies, dev binary ──────

seed_remote()
{
    # Every step is checked explicitly: this function runs inside
    # seed="$(seed_remote)", and set -e does not propagate into a command
    # substitution's function body, so an unchecked failing step here is
    # silently skipped and the journey then measures the WRONG tree (run 14:
    # the seed fetch died, the journey ran on plain origin/main, and the
    # land proof failed the exact cold-worktree fault the unapplied seed
    # carried the fix for).
    note_seed="$(git -C "$ROOT" rev-parse origin/main)" ||
        fail 'could not resolve origin/main'
    # Resolve the seed before spending the origin fetch: a bogus ref must
    # refuse in milliseconds, not after a multi-GB transfer.
    local want=""
    if [[ -n "$SEED_REF" ]]; then
        want="$(git -C "$ROOT" rev-parse --verify "$SEED_REF^{commit}")" ||
            fail "seed ref is not a commit: $SEED_REF"
    fi
    git init --bare -q "$REMOTE" || fail 'could not init the fixture remote'
    # Point the bare HEAD at main: with the host default (master) the clone
    # checks out an unborn master, and the pre-commit guard then refuses the
    # story commit once the land lane adds its worktrees.
    git -C "$REMOTE" symbolic-ref HEAD refs/heads/main ||
        fail 'could not point the fixture remote HEAD at main'
    git -C "$REMOTE" fetch -q "$ROOT" \
        +refs/remotes/origin/main:refs/heads/main ||
        fail 'could not seed the fixture remote from origin/main'
    git clone -q "$REMOTE" "$CLONE" || fail 'could not clone the fixture remote'
    if [[ -n "$SEED_REF" ]]; then
        # Carry an unlanded candidate (e.g. new instrumentation) into the
        # scratch main so the journey measures it. --no-verify is correct
        # here: this seeds the fixture remote, it is not a landing.
        # SEED_REF must be a ref name upload-pack advertises (a branch or
        # tag): a raw commit-ish is refused by the fetch transport even when
        # it is a branch tip.
        git -C "$CLONE" fetch -q "$ROOT" \
            "$SEED_REF:refs/remotes/seed/head" ||
            fail "could not fetch seed $SEED_REF (pass a branch or tag name, not a raw sha)"
        git -C "$CLONE" reset -q --hard refs/remotes/seed/head ||
            fail 'could not reset the clone onto the seed'
        [[ "$(git -C "$CLONE" rev-parse HEAD)" == "$want" ]] ||
            fail "seed identity mismatch: wanted $want"
        git -C "$CLONE" push -q --no-verify origin HEAD:main ||
            fail 'could not push the seed into the fixture remote'
        note_seed="$want"
    fi
    printf '%s' "$note_seed"
}

configure_clone()
{
    local c="$1" key signers name email
    name="$(git -C "$ROOT" config user.name)"
    email="$(git -C "$ROOT" config user.email)"
    key="$(git -C "$ROOT" config user.signingkey)"
    signers="$(git -C "$ROOT" config gpg.ssh.allowedSignersFile ||
               git -C "$ROOT" config --global gpg.ssh.allowedSignersFile ||
               true)"
    git -C "$c" config user.name "$name"
    git -C "$c" config user.email "$email"
    git -C "$c" config commit.gpgsign true
    git -C "$c" config gpg.format ssh
    git -C "$c" config user.signingkey "$key"
    [[ -n "$signers" ]] &&
        git -C "$c" config gpg.ssh.allowedSignersFile "$signers" || true
}

prime_and_build()
{
    # Offline vendor prime, exactly the set `make worktree-prime` carries:
    # the prebuilt archives and headers a fresh clone lacks. The clone's
    # vendor/lib and vendor/include already exist (tracked content), so
    # copy their contents, never the directory itself.
    cp -a "$ROOT/vendor/lib/." "$CLONE/vendor/lib/"
    cp -a "$ROOT/vendor/include/." "$CLONE/vendor/include/"
    cp -a "$ROOT/vendor/sqlite3.c" "$CLONE/vendor/sqlite3.c"
    runenv make -j"$JOBS" dev-bin >/dev/null
    runenv make install-hooks >/dev/null
    # The sealed proof copies its checker tools from this checkout and
    # refuses to hunt for them; docs-proof-tools names the exact set.
    runenv make -j"$JOBS" docs-proof-tools >/dev/null
}

# ── The narrow edit: bump the reflex benchmark nonce ─────────────────────
# The marker lives in the source permanently (see reflex-reactor-bench.sh);
# bumping its nonce changes the module's bytes without changing behavior,
# and the frozen vault story still executes the edited bytes. The first
# staging folds the volatile nonce into the memset argument — never an
# `if`: vault_intent_plan_decide is pinned in the cyclomatic baseline, so a
# new decision point fails check-cyclomatic-complexity in the land lane.

stage_nonce()
{
    local path="$1" nonce="$2" value=$((10#$2)) have
    have="$(grep -c 'volatile unsigned reflex_nonce' "$path" || true)"
    if [[ "$have" == 0 ]]; then
        awk -v nonce="$nonce" -v value="$value" '
            /ZCL_REFLEX_BENCH: [0-9a-fA-F]{8}/ {sub(/[0-9a-fA-F]{8}/, nonce)}
            /    memset\(decision, 0, sizeof\(\*decision\)\);/ {
                print "    volatile unsigned reflex_nonce = " value "u;"
                print "    memset(decision, (int)(reflex_nonce & 0u), sizeof(*decision));"
                next
            }
            {print}
        ' "$path" >"$path.staged"
    else
        # Re-bump must change the compiled bytes too: substitute the value,
        # not only the comment nonce.
        awk -v nonce="$nonce" -v value="$value" '
            /ZCL_REFLEX_BENCH: [0-9a-fA-F]{8}/ {sub(/[0-9a-fA-F]{8}/, nonce)}
            /volatile unsigned reflex_nonce = [0-9]+u;/ {
                sub(/= [0-9]+u;/, "= " value "u;")
            }
            {print}
        ' "$path" >"$path.staged"
    fi
    [[ "$(grep -c "ZCL_REFLEX_BENCH: $nonce" "$path.staged")" == 1 ]] ||
        fail "could not stage nonce $nonce"
    [[ "$(grep -c "reflex_nonce = ${value}u;" "$path.staged")" == 1 ]] ||
        fail "could not stage nonce value $value"
    chmod --reference="$path" "$path.staged"
    mv "$path.staged" "$path"
}

commit_edit()
{
    # Every step is checked explicitly (the callers run this in a command
    # substitution, where set -e does not propagate), and the sha must
    # ADVANCE: a refused commit leaves HEAD unchanged, which the run-21
    # dupcrash attempt silently carried forward as the "candidate" after
    # the pre-commit hook refused a side-branch commit in the primary
    # checkout. Case edits therefore commit on main, which the hook allows.
    local msg="$1" sha before
    before="$(runenv git rev-parse HEAD)" || return 1
    runenv git add "$SOURCE_REL" || return 1
    runenv git commit -q -m "$msg" >/dev/null || return 1
    sha="$(runenv git rev-parse HEAD)" || return 1
    [[ "$sha" =~ ^[0-9a-f]{40}$ && "$sha" != "$before" ]] || return 1
    printf '%s' "$sha"
}

regen_inventory()
{
    # A source edit makes the committed capability inventory stale: its
    # source_root_sha3 binds the exact scanned tree bytes, so a direct proof
    # of the story commit refuses proof_generated_docs_stale until the
    # inventory is regenerated (run 22). The land lane regenerates docs
    # itself for submitted tips; the direct-proof cases must do it here.
    runenv make docs-capability-inventory >/dev/null || return 1
    runenv git add docs/CAPABILITY_INVENTORY.jsonl || return 1
}

clone_proof_pass()
{
    # Run one clone proof to settlement and require PASS. The clone stays
    # armed (the journey's dev begin owns its resident watcher), so pairs
    # run under the resident and a foreground proof step is refused on an
    # armed checkout (run 23); ensure is the idempotent queue step. Every
    # step is checked explicitly: callers use this helper under ||, where
    # set -e is suspended. Polls up to 30 minutes. Prints the final .data
    # on failure so the caller's fail message carries the reason.
    local local_commit="$1" base="$2" st status i
    devbin dev proof ensure --root="$CLONE" --local_commit="$local_commit" \
        --remote_base="$base" >/dev/null || return 1
    for i in $(seq 1 900); do
        st="$(devbin dev proof status --root="$CLONE" \
            --local_commit="$local_commit" --remote_base="$base")" ||
            return 1
        status="$(jq -r '.data.status // "unknown"' <<<"$st")" || return 1
        [[ "$status" == running ]] || break
        sleep 2
    done
    [[ "$status" == passed ]] && return 0
    jq -c .data <<<"$st" 2>/dev/null || printf '%s\n' "$st"
    return 1
}

# ── Evidence extraction ──────────────────────────────────────────────────

note_val()
{
    # phases.txt key=value line; empty when absent (older binary, crash).
    local got
    got=$([[ -f "$1" ]] && grep "^$2=" "$1" | tail -1 | cut -d= -f2- || true)
    printf '%s' "$got"
}

attempt_dir()
{
    local d
    d=$(ls -d "$1"/.cache/zcl-dev-proof/attempts/"$2"-"$3".* 2>/dev/null |
        tail -1 || true)
    printf '%s' "$d"
}

attempt_count()
{
    local n
    n=$(ls -d "$1"/.cache/zcl-dev-proof/attempts/"$2"-"$3".* 2>/dev/null |
        wc -l || true)
    printf '%s' "${n:-0}"
}

compiler_count()
{
    local n
    n=$(cat "$1"/logs/*.log 2>/dev/null | grep -c 'build/bin/zcc ' || true)
    printf '%s' "${n:-0}"
}

timeline_json()
{
    # logs/phases.txt: zcl.dev_proof_phase.v1 <name> <ms> ms (cumulative <ms> ms)
    [[ -f "$1" ]] || { printf '{}'; return 0; }
    awk 'BEGIN{printf "{"}
         {printf "%s\"%s\":%d", sep, $2, $3; sep=","; total=$(NF-1)}
         END{printf "%s\"_total_ms\":%d}", (NR ? sep : ""), total+0}' "$1"
}

pack_bytes()
{
    # The delta a push moves: objects in tip not in base, as a pack.
    printf '%s\n^%s\n' "$2" "$1" |
        git -C "$CLONE" pack-objects --stdout --revs -q 2>/dev/null | wc -c
}

accepted_c23_lines()
{
    runenv git diff --numstat "$1..$2" -- '*.c' '*.h' |
        awk '{a+=$1; r+=$2} END{printf "%d %d", a+0, r+0}'
}

remote_tip() { git -C "$REMOTE" rev-parse refs/heads/main; }

fetch_origin() { runenv git fetch -q origin main; }

wait_remote_tip()
{
    # The lane lands tip + its generated-docs regeneration commit when the
    # edit drifts the inventory, so acceptance is ancestry, not equality
    # (run 18: submitted 1020a75b5, landed as that plus the regen commit).
    local want="$1" tries=0 tip=""
    while [[ "$tries" -lt 30 ]]; do
        tip="$(remote_tip)"
        git -C "$REMOTE" merge-base --is-ancestor "$want" "$tip" \
            2>/dev/null && return 0
        sleep 2
        tries=$((tries + 1))
    done
    fail "remote main never reached $want (at $tip)"
}

# ── Case: journey ────────────────────────────────────────────────────────

# Prove, seal, publish. The drive proves the pair and stops at the push
# phase: publication requires a signed intent that only the explicit
# attach seals — dl_drive never attaches, sealing is a deliberate
# operator action (tools/dev/git_land_signed_intent_contract.md). The
# retryable PUBLICATION_INTENT_REQUIRED block is the expected midpoint
# (run 17 proved the pair, then sat blocked until this step existed).
land_publish()
{
    local seq="$1" out rc
    set +e
    out="$(devbin dev land drive 2>&1)"
    rc=$?
    set -e
    if [[ "$rc" != 0 ]]; then
        tail -1 <<<"$out" |
            jq -e '.error.code == "PUBLICATION_INTENT_REQUIRED"' \
                >/dev/null || {
            printf '%s\n' "$out" >&2
            return 1
        }
        devbin dev land attach --seq="$seq" >/dev/null || return 1
        devbin dev land drive >/dev/null || return 1
    fi
}

journey_case()
{
    local base source nonce begin epoch t_edit0 t_edit1 drive
    local c1 submit_ts submit_out seq t_drive0 t_drive1 drive_rc
    local landed_pair landed_local landed_base
    local attempt phases warm_sidecar landed_ts proof_wall_ms
    local queue_wait_ms queue_lock_ms cpu_self_ms cpu_children_ms
    local lint_ms prefork_ms warm_files warm_bytes compilers attempts_n
    local lines_add lines_rm pack_b journey_wall_us aoh
    local drive_deadline wait_edit

    base="$(remote_tip)"
    source="$CLONE/$SOURCE_REL"
    nonce="$(printf '%08d' $(( $(date +%s) % 100000000 )))"

    # Stage 1: impact -> minimal build -> new-byte execution (reflex loop).
    watcher_reap_stale
    begin="$(devbin dev begin)" ||
        fail "dev begin failed: $begin"
    watcher_identity_save ||
        fail "dev loop status returned no watcher identity after begin"
    epoch="$(jq -er '.data.epoch' <<<"$begin")" ||
        fail "dev begin returned no epoch: $begin"
    t_edit0="$(now_us)"
    stage_nonce "$source" "$nonce"
    # dev drive caps timeout_ms at 300000 and answers a retryable
    # DRIVE_TIMEOUT past it; retry with wait_for_edit=false (this edit is
    # already bound) until the action-changing story or a 20-minute budget.
    drive_deadline=$(( $(date +%s) + 1200 ))
    wait_edit=true
    for ((;;)); do
        set +e
        drive="$(devbin dev drive --input="{\"after_epoch\":$epoch,\"wait_for_edit\":$wait_edit,\"timeout_ms\":300000}")"
        drive_rc=$?
        set -e
        [[ "$drive_rc" == 0 ]] && break
        if jq -e '.error.code == "DRIVE_TIMEOUT"' <<<"$drive" >/dev/null &&
           (( $(date +%s) < drive_deadline )); then
            wait_edit=false
            continue
        fi
        fail "dev drive failed: $drive"
    done
    t_edit1="$(now_us)"
    jq -e '.ok == true and .data.event == "STORY_GREEN" and
           .data.candidate_bytes_executed == true' <<<"$drive" \
        >/dev/null || fail "reflex stage did not execute the new bytes: $drive"
    local stop_id stop_session stop_out stop_rc stop_attempt
    read -r stop_id stop_session <"$SCRATCH/watcher_id" || true
    [[ -n "${stop_id:-}" && -n "${stop_session:-}" ]] ||
        fail 'watcher identity file is incomplete'
    # The stop budget is 250 ms; a watcher mid-cycle under build load
    # answers the retryable WATCHER_STOP_TIMEOUT instead. Retry it out.
    for ((stop_attempt = 0; ; stop_attempt++)); do
        set +e
        stop_out="$(devbin dev loop stop \
            --input="{\"watcher_id\":$stop_id,\"watcher_session\":\"$stop_session\"}")"
        stop_rc=$?
        set -e
        [[ "$stop_rc" == 0 ]] && break
        if jq -e '.error.code == "WATCHER_NOT_RUNNING"' <<<"$stop_out" \
             >/dev/null; then
            # The watcher released the singleton itself after the green
            # cycle while its test-lint tail keeps running. Proceed only
            # when status confirms the loop is inactive, then reap the
            # leftover process by lock pid so nothing reacts to the commit.
            local quiet="" st quiet_attempt
            for ((quiet_attempt = 0; quiet_attempt < 15; quiet_attempt++)); do
                st="$(devbin dev loop status)" || true
                if jq -e '.data.active == false' <<<"$st" >/dev/null 2>&1; then
                    quiet=1
                    break
                fi
                sleep 2
            done
            [[ -n "$quiet" ]] ||
                fail "watcher still active after stop: $st"
            rm -f "$SCRATCH/watcher_id"
            watcher_reap_stale
            break
        fi
        if jq -e '.error.code == "WATCHER_STOP_TIMEOUT" and
                  .error.retryable == true' <<<"$stop_out" >/dev/null &&
           (( stop_attempt < 5 )); then
            sleep 2
            continue
        fi
        fail "dev loop stop failed: $stop_out"
    done
    rm -f "$SCRATCH/watcher_id"

    # Stage 2: the signed commit carrying exactly the executed bytes.
    c1="$(commit_edit "journey: reflex nonce $nonce")" ||
        fail 'journey story commit refused'

    # Stage 3: proof -> publication -> remote acceptance (landing queue).
    submit_ts="$(date +%s)"
    submit_out="$(devbin dev land submit --tip="$c1" --note="journey-bench-$nonce")" ||
        fail "land submit failed: $submit_out"
    seq="$(jq -er '.data.seq' <<<"$submit_out")" ||
        fail "land submit returned no seq: $submit_out"
    t_drive0="$(now_us)"
    land_publish "$seq" ||
        fail "land publish failed for seq $seq"
    t_drive1="$(now_us)"
    wait_remote_tip "$c1"
    landed_ts="$(date +%s)"
    fetch_origin

    # The proven pair names the lane's rebased commit and its observed
    # base, not the submitted tip: the landed outcome row carries both.
    landed_pair="$(jq -er "select(.seq == $seq and .state == \"landed\") |
        [.local, .base] | @tsv" "$STATE/land/outcomes.jsonl" | tail -1)" ||
        fail "no landed outcome row for seq $seq"
    landed_local="$(cut -f1 <<<"$landed_pair")"
    landed_base="$(cut -f2 <<<"$landed_pair")"
    [[ "$landed_local" =~ ^[0-9a-f]{40}$ &&
       "$landed_base" =~ ^[0-9a-f]{40}$ ]] ||
        fail "landed outcome row for seq $seq is malformed"

    # Evidence: the exact attempt's phases, notes, warm-start sidecar.
    attempt="$(attempt_dir "$LAND_WT" "$landed_local" "$landed_base")"
    [[ -n "$attempt" ]] ||
        fail "no proof attempt found for $landed_local/$landed_base"
    phases="$attempt/phases.txt"
    queue_wait_ms="$(note_val "$phases" queue_wait_ms)"
    queue_lock_ms="$(note_val "$phases" queue_lock_wait_ms)"
    cpu_self_ms="$(note_val "$phases" proof_cpu_self_ms)"
    cpu_children_ms="$(note_val "$phases" proof_cpu_children_ms)"
    lint_ms="$(note_val "$phases" lint_wall_ms)"
    prefork_ms="$(note_val "$phases" prefork_admission_ms)"
    warm_sidecar="$LAND_WT/.cache/zcl-dev-proof/$landed_local-$landed_base.warmstart"
    warm_files="$(note_val "$warm_sidecar" files_linked)"
    warm_bytes="$(note_val "$warm_sidecar" bytes_linked)"
    compilers="$(compiler_count "$attempt")"
    attempts_n="$(attempt_count "$LAND_WT" "$landed_local" "$landed_base")"
    proof_wall_ms="$(awk '/cumulative/ {v=$(NF-1)} END{print v+0}' \
        "$attempt/logs/phases.txt")"

    read -r lines_add lines_rm <<<"$(accepted_c23_lines "$base" "$(remote_tip)")"
    pack_b="$(pack_bytes "$base" "$(remote_tip)")"
    journey_wall_us=$((t_edit1 - t_edit0))
    # Parens around the ternary: without them awk parses the comparison as
    # a printf output redirection (run 19 landed, then died here).
    aoh="$(awk -v lines="$lines_add" \
        -v ms="$(( (landed_ts - submit_ts) ))" \
        'BEGIN{printf "%.2f", (ms > 0 ? lines * 3600 / ms : 0)}')"

    jq -n \
        --arg schema 'zcl.landed_journey.v1' \
        --arg case journey --arg nonce "$nonce" \
        --arg base "$base" --arg tip "$c1" --arg remote_tip "$(remote_tip)" \
        --arg tip_pushed "$landed_local" \
        --argjson reflex_wall_us "$journey_wall_us" \
        --argjson reflex_feedback_us \
            "$(jq -r '.data.feedback_us' <<<"$drive")" \
        --argjson submit_unix "$submit_ts" \
        --argjson landed_unix "$landed_ts" \
        --argjson submit_to_remote_s "$((landed_ts - submit_ts))" \
        --argjson land_drive_wall_us "$((t_drive1 - t_drive0))" \
        --argjson queue_wait_ms "${queue_wait_ms:-0}" \
        --argjson queue_lock_wait_ms "${queue_lock_ms:-0}" \
        --argjson proof_wall_ms "${proof_wall_ms:-0}" \
        --argjson proof_cpu_self_ms "${cpu_self_ms:-0}" \
        --argjson proof_cpu_children_ms "${cpu_children_ms:-0}" \
        --argjson lint_wall_ms "${lint_ms:-0}" \
        --argjson prefork_admission_ms "${prefork_ms:-0}" \
        --argjson warm_files_linked "${warm_files:-0}" \
        --argjson warm_bytes_linked "${warm_bytes:-0}" \
        --argjson compiler_invocations "$compilers" \
        --argjson proof_executions "$attempts_n" \
        --argjson accepted_c23_added "$lines_add" \
        --argjson accepted_c23_removed "$lines_rm" \
        --argjson push_pack_bytes "$pack_b" \
        --arg accepted_lines_per_hour "$aoh" \
        --argjson phases "$(timeline_json "$attempt/logs/phases.txt")" \
        '{schema:$schema,case:$case,nonce:$nonce,base:$base,tip:$tip,
          remote_tip:$remote_tip,
          reflex:{wall_us:$reflex_wall_us,feedback_us:$reflex_feedback_us,
                  candidate_bytes_executed:true},
          land:{submit_unix:$submit_unix,landed_unix:$landed_unix,
                submit_to_remote_s:$submit_to_remote_s,
                tip_pushed:$tip_pushed,
                drive_wall_us:$land_drive_wall_us},
          proof:{queue_wait_ms:$queue_wait_ms,
                 queue_lock_wait_ms:$queue_lock_wait_ms,
                 wall_ms:$proof_wall_ms,cpu_self_ms:$proof_cpu_self_ms,
                 cpu_children_ms:$proof_cpu_children_ms,
                 lint_wall_ms:$lint_wall_ms,
                 prefork_admission_ms:$prefork_admission_ms,
                 warm_files_linked:$warm_files_linked,
                 warm_bytes_linked:$warm_bytes_linked,
                 compiler_invocations:$compiler_invocations,
                 executions:$proof_executions,phases:$phases},
          accepted:{c23_added:$accepted_c23_added,
                    c23_removed:$accepted_c23_removed,
                    push_pack_bytes:$push_pack_bytes,
                    lines_per_hour:($accepted_lines_per_hour|tonumber)}}' \
        >"$RECEIPTS/journey.json"
    jq -r '"landed-journey-bench: journey tip=\(.tip[0:9]) submit_to_remote=\(.land.submit_to_remote_s)s proof_wall=\(.proof.wall_ms)ms queue_wait=\(.proof.queue_wait_ms)ms accepted=+\(.accepted.c23_added)/-\(.accepted.c23_removed) lines (\(.accepted.lines_per_hour)/h)"' \
        "$RECEIPTS/journey.json"
}

# ── Case: duplicate request + crash/retry (clone-root proof) ─────────────

dupcrash_case()
{
    local base source nonce c2 st request_n1 request_n2 attempt
    local worker_id killed_state receipt attempts_n step_pid retry_detail
    local t_ensure0 t_ensure1 t_retry0 t_retry1

    base="$(remote_tip)"
    fetch_origin
    runenv git checkout -q -f -B main origin/main
    source="$CLONE/$SOURCE_REL"
    nonce="$(printf '%08d' $(( ($(date +%s) + 1) % 100000000 )))"
    stage_nonce "$source" "$nonce"
    regen_inventory || fail 'dupcrash inventory regen failed'
    c2="$(commit_edit "journey: dupcrash nonce $nonce")" ||
        fail 'dupcrash story commit refused'

    # Duplicate request: two ensures admit exactly one queued request.
    t_ensure0="$(now_us)"
    st="$(devbin dev proof ensure --root="$CLONE" --local_commit="$c2" \
        --remote_base="$base")" || fail "proof ensure failed: $st"
    jq -e '.data.status == "running"' <<<"$st" >/dev/null ||
        fail "ensure did not queue the proof: $(jq -c .data <<<"$st")"
    request_n1="$(ls "$CLONE/.cache/zcl-dev-proof/requests/" | wc -l)"
    st="$(devbin dev proof ensure --root="$CLONE" --local_commit="$c2" \
        --remote_base="$base")" || fail "duplicate proof ensure failed: $st"
    request_n2="$(ls "$CLONE/.cache/zcl-dev-proof/requests/" | wc -l)"
    t_ensure1="$(now_us)"
    [[ "$request_n1" == 1 && "$request_n2" == 1 ]] ||
        fail "duplicate ensure did not coalesce ($request_n1/$request_n2)"

    # Crash: start the foreground proof, kill the worker past the build.
    devbin dev proof step --root="$CLONE" --local_commit="$c2" \
        --remote_base="$base" >/dev/null 2>&1 &
    step_pid=$!
    worker_id=0
    for _ in $(seq 1 900); do
        st="$(devbin dev proof status --root="$CLONE" --local_commit="$c2" \
            --remote_base="$base" 2>/dev/null || true)"
        worker_id="$(jq -r '.data.worker_id // 0' <<<"$st" 2>/dev/null ||
                     echo 0)"
        attempt="$(attempt_dir "$CLONE" "$c2" "$base")"
        if [[ "$worker_id" -gt 1 && -n "$attempt" ]] &&
           grep -q 'dimension_compile' "$attempt/logs/phases.txt" 2>/dev/null
        then
            break
        fi
        if [[ -f "$CLONE/.cache/zcl-dev-proof/$c2-$base.failed" ]]; then
            fail "proof failed before the crash point: $(cat "$CLONE/.cache/zcl-dev-proof/$c2-$base.failed")"
        fi
        sleep 1
    done
    [[ "$worker_id" -gt 1 ]] || fail 'proof worker never appeared'
    kill -9 "$worker_id"
    wait "$step_pid" 2>/dev/null || true
    sleep 1
    st="$(devbin dev proof status --root="$CLONE" --local_commit="$c2" \
        --remote_base="$base")" || fail "proof status after kill failed: $st"
    killed_state="$(jq -r '.data.status' <<<"$st")"
    [[ "$killed_state" != passed ]] ||
        fail 'killed proof reported passed'
    receipt="$CLONE/.cache/zcl-dev-proof/receipts/$c2-$base.receipt"
    [[ ! -f "$receipt" ]] || fail 'killed proof left a receipt'

    # Retry through the documented ensure path: a fresh attempt must pass.
    t_retry0="$(now_us)"
    retry_detail="$(clone_proof_pass "$c2" "$base")" ||
        fail "retry proof did not pass: $retry_detail"
    t_retry1="$(now_us)"
    [[ -f "$receipt" ]] || fail 'passed retry left no receipt'
    attempts_n="$(attempt_count "$CLONE" "$c2" "$base")"
    [[ "$attempts_n" == 2 ]] ||
        fail "expected 2 attempts (crash + retry), found $attempts_n"

    jq -n --arg case dupcrash --arg tip "$c2" --arg base "$base" \
        --arg killed_state "$killed_state" \
        --argjson ensure_wall_us "$((t_ensure1 - t_ensure0))" \
        --argjson retry_wall_us "$((t_retry1 - t_retry0))" \
        --argjson requests_after_duplicate "$request_n2" \
        --argjson attempts "$attempts_n" \
        '{schema:"zcl.landed_journey_case.v1",case:$case,tip:$tip,base:$base,
          duplicate:{requests_after_second_ensure:$requests_after_duplicate},
          crash:{state_after_kill:$killed_state,receipt_after_kill:false},
          retry:{status:"passed",attempts:$attempts,
                 retry_wall_us:$retry_wall_us}}' \
        >"$RECEIPTS/dupcrash.json"
    jq -r '"landed-journey-bench: dupcrash killed=\(.crash.state_after_kill) retry=\(.retry.status) attempts=\(.retry.attempts)"' \
        "$RECEIPTS/dupcrash.json"
}

# ── Case: stale main ─────────────────────────────────────────────────────

stale_case()
{
    local base source nonce c3 proof_detail advancer_tip push_rc push_out seq
    local landed_tip t_drive0 t_drive1 submit_out

    fetch_origin
    base="$(git -C "$CLONE" rev-parse origin/main)"
    runenv git checkout -q -f -B main "origin/main"
    source="$CLONE/$SOURCE_REL"
    nonce="$(printf '%08d' $(( ($(date +%s) + 2) % 100000000 )))"
    stage_nonce "$source" "$nonce"
    regen_inventory || fail 'stale inventory regen failed'
    c3="$(commit_edit "journey: stale nonce $nonce")" ||
        fail 'stale story commit refused'

    # Prove the pair while it is current.
    proof_detail="$(clone_proof_pass "$c3" "$base")" ||
        fail "stale-case proof did not pass: $proof_detail"

    # An advancer moves the remote main past the proven base.
    git clone -q "$REMOTE" "$CLONE2"
    configure_clone "$CLONE2"
    git -C "$CLONE2" checkout -q -b advancer
    printf 'advancer %s\n' "$(date +%s)" >>"$CLONE2/docs/work/JOURNEY_BENCH.md"
    git -C "$CLONE2" add docs/work/JOURNEY_BENCH.md
    git -C "$CLONE2" commit -q -m 'journey-bench advancer' >/dev/null
    git -C "$CLONE2" push -q origin advancer:main
    advancer_tip="$(remote_tip)"
    [[ "$advancer_tip" != "$base" ]] || fail 'advancer did not move main'
    fetch_origin

    # The proven pair is now stale: a direct push must be refused and the
    # remote must not move.
    set +e
    push_out="$(cd "$CLONE" && HOME="$HOME_SCRATCH" \
        git push origin "$c3:refs/heads/main" 2>&1)"
    push_rc=$?
    set -e
    [[ "$push_rc" != 0 ]] ||
        fail 'stale push was not refused'
    [[ "$(remote_tip)" == "$advancer_tip" ]] ||
        fail 'refused stale push still moved the remote'

    # Canonical recovery: the landing queue rebases, re-proves and pushes.
    submit_out="$(devbin dev land submit --tip="$c3" --note="journey-bench-stale")" ||
        fail "stale land submit failed: $submit_out"
    seq="$(jq -er '.data.seq' <<<"$submit_out")" ||
        fail "stale land submit returned no seq: $submit_out"
    t_drive0="$(now_us)"
    land_publish "$seq" ||
        fail "stale land publish failed for seq $seq"
    t_drive1="$(now_us)"
    landed_tip="$(remote_tip)"
    [[ "$landed_tip" != "$advancer_tip" ]] ||
        fail 'land drive did not advance the remote'
    runenv git fetch -q origin main
    git -C "$CLONE" merge-base --is-ancestor "$advancer_tip" "$landed_tip" ||
        fail 'landed tip does not contain the advancer'

    jq -n --arg case stale --arg tip "$c3" --arg stale_base "$base" \
        --arg advancer "$advancer_tip" --arg landed "$landed_tip" \
        --arg refusal "$(grep -om1 'receipt[a-z_]*\|stale[a-z_]*\|ancestor[a-z_]*' \
            <<<"$push_out" | head -1)" \
        --argjson drive_wall_us "$((t_drive1 - t_drive0))" \
        '{schema:"zcl.landed_journey_case.v1",case:$case,tip:$tip,
          stale_base:$stale_base,advancer_tip:$advancer,
          direct_push:{refused:true,remote_unchanged:true,
                       refusal_hint:$refusal},
          recovery:{landed_tip:$landed,contains_advancer:true,
                    drive_wall_us:$drive_wall_us}}' \
        >"$RECEIPTS/stale.json"
    jq -r '"landed-journey-bench: stale refused=\(.direct_push.refused) recovered=\(.recovery.landed_tip[0:9])"' \
        "$RECEIPTS/stale.json"
}

# ── Case: tampered receipt ───────────────────────────────────────────────

tamper_case()
{
    local base source nonce c4 proof_detail receipt pristine push_rc push_out

    fetch_origin
    base="$(git -C "$CLONE" rev-parse origin/main)"
    runenv git checkout -q -f -B main "origin/main"
    source="$CLONE/$SOURCE_REL"
    nonce="$(printf '%08d' $(( ($(date +%s) + 3) % 100000000 )))"
    stage_nonce "$source" "$nonce"
    regen_inventory || fail 'tamper inventory regen failed'
    c4="$(commit_edit "journey: tamper nonce $nonce")" ||
        fail 'tamper story commit refused'

    proof_detail="$(clone_proof_pass "$c4" "$base")" ||
        fail "tamper-case proof did not pass: $proof_detail"
    receipt="$CLONE/.cache/zcl-dev-proof/receipts/$c4-$base.receipt"
    [[ -f "$receipt" ]] || fail 'passed proof left no receipt'
    pristine="$SCRATCH/receipt.pristine"
    # cp -p carries the receipt's read-only mode onto the pristine copy; an
    # earlier run's copy then refuses to be overwritten. Remove first.
    rm -f "$pristine" || fail 'could not clear a stale pristine receipt'
    cp -p "$receipt" "$pristine"

    # Flip one byte inside the sealed wire image: the push must be refused
    # and the remote must not move. The store writes receipts read-only on
    # purpose; the tamper is explicit about overriding that.
    chmod u+w "$receipt" || fail 'could not arm the receipt for tampering'
    printf '\x01' | dd of="$receipt" bs=1 seek=32 conv=notrunc status=none
    set +e
    push_out="$(cd "$CLONE" && HOME="$HOME_SCRATCH" \
        git push origin "$c4:refs/heads/main" 2>&1)"
    push_rc=$?
    set -e
    [[ "$push_rc" != 0 ]] || fail 'tampered receipt push was not refused'
    [[ "$(remote_tip)" == "$base" ]] ||
        fail 'refused tampered push still moved the remote'

    # Restored evidence admits: the same push succeeds through the hook.
    rm -f "$receipt" || fail 'could not clear the tampered receipt'
    cp -p "$pristine" "$receipt" || fail 'could not restore the pristine receipt'
    (cd "$CLONE" && HOME="$HOME_SCRATCH" \
        git push -q origin "$c4:refs/heads/main") ||
        fail 'restored receipt did not admit the push'
    [[ "$(remote_tip)" == "$c4" ]] || fail 'admitted push did not land'

    jq -n --arg case tamper --arg tip "$c4" --arg base "$base" \
        --arg refusal "$(grep -om1 'receipt[a-z_]*' <<<"$push_out" | head -1)" \
        '{schema:"zcl.landed_journey_case.v1",case:$case,tip:$tip,base:$base,
          tampered_push:{refused:true,remote_unchanged:true,
                         refusal_hint:$refusal},
          restored_push:{admitted:true,remote_landed:true}}' \
        >"$RECEIPTS/tamper.json"
    jq -r '"landed-journey-bench: tamper refused=\(.tampered_push.refused) restored=\(.restored_push.admitted)"' \
        "$RECEIPTS/tamper.json"
}

# ── Drive ────────────────────────────────────────────────────────────────

t_setup0="$(now_us)"
if [[ -x "$CLONE/build/bin/z23-dev" && -d "$REMOTE" ]]; then
    # Reused scaffold: a second case run against the same scratch directory
    # skips the clone and the cold dev-binary build. Heal pre-fix scaffolds
    # and failed-run debris: the bare HEAD must name main (the stale case
    # re-clones it), and local main must equal the remote tip — an unlanded
    # story commit or staged edit from a failed run would widen the next
    # measured edit. -f is safe: the clone is harness-owned fixture state.
    git -C "$REMOTE" symbolic-ref HEAD refs/heads/main
    git -C "$CLONE" checkout -q -f -B main origin/main
    # A reseed leaves the checked-out binary behind its sources, and a
    # scaffold cut before the docs-proof-tools prime lacks the proof's
    # checker tools; both make calls are near-instant when current.
    runenv make -j"$JOBS" dev-bin docs-proof-tools >/dev/null
    seed="$(git -C "$CLONE" rev-parse origin/main)"
    printf 'landed-journey-bench: reusing scaffold %s\n' "$SCRATCH" >&2
else
    seed="$(seed_remote)"
    configure_clone "$CLONE"
    prime_and_build
fi
t_setup1="$(now_us)"

case "$CASES" in
    all)
        journey_case
        dupcrash_case
        stale_case
        tamper_case
        ;;
    journey) journey_case ;;
    dupcrash) dupcrash_case ;;
    stale) stale_case ;;
    tamper) tamper_case ;;
esac

# The summary aggregates whichever case receipts this run produced.
mkdir -p "$(dirname "$OUTPUT")"
jq -n --arg schema 'zcl.landed_journey_benchmark.v1' \
    --arg host "$(uname -srm)" --arg seed_main "$seed" \
    --argjson setup_wall_us "$((t_setup1 - t_setup0))" \
    --arg cases "$CASES" \
    '{$schema:$schema,host:$host,seed_main:$seed_main,cases:$cases,
      setup_wall_us:$setup_wall_us}' >"$OUTPUT"
for f in "$RECEIPTS"/*.json; do
    # The value needs full parens: jq 1.7 mis-parses a bare `(a) + (b)`
    # inside an object literal (run 20 wrote the receipt, died here).
    jq -s '.[0] * {results: ((.[0].results // {}) + {(.[1].case): .[1]})}' \
        "$OUTPUT" "$f" >"$OUTPUT.tmp"
    mv "$OUTPUT.tmp" "$OUTPUT"
done
printf 'landed-journey-bench: receipt=%s\n' "$OUTPUT"
