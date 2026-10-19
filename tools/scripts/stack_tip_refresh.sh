#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Refresh stack-tip projections in dependency order using canonical generators.
set -Eeuo pipefail

# A stack caller may retain this source before checkout removes its pathname.
# In that case bash -c supplies the original repository pathname as argv[0].
ROOT="$(CDPATH= cd -P -- "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd -P)"
MODE=refresh
case "${1:-}" in
    '') ;;
    --check) MODE=check ;;
    --selftest) MODE=selftest ;;
    *) echo 'usage: stack_tip_refresh.sh [--check|--selftest]' >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { echo 'stack-tip-refresh: too many arguments' >&2; exit 2; }
cd "$ROOT"
# Direct and retained-source entry points have the same physical-tree boundary.
for git_env in ${!GIT_@}; do
    case "$git_env" in
        GIT_PAGER|GIT_TERMINAL_PROMPT) continue ;;
        *) ;;
    esac
    printf 'stack tool: refusing inherited Git environment: %s\n' "$git_env" >&2
    exit 2
done
if [ "$(git rev-parse --show-toplevel)" != "$ROOT" ]; then
    echo 'stack tool: Git worktree does not match the script root' >&2
    exit 2
fi

# Make may also regenerate tracked view headers. Compare against the initial
# working contents, not HEAD, without hashing every unchanged source file.
list_changes() {
    local manifest
    git diff --name-only -z -- || return $?
    git ls-files -z --others --exclude-standard -- || return $?
    # The registry also discovers ignored, untracked package manifests.
    for manifest in contexts/commons/packages/*/zcode-package.json; do
        [ -f "$manifest" ] || continue
        printf '%s\0' "$manifest"
    done
    find engine/composition -type f -name '*.def' -print0
}
content_id() {
    if [ -f "$1" ]; then git hash-object --no-filters -- "$1"
    elif [ ! -e "$1" ]; then printf 'missing\n'
    else echo "stack-tip-refresh: not a regular output: $1" >&2; return 2
    fi
}

# The canonical gate owns measurement. Repair only its numeric mismatch rows;
# every other failure remains a refusal, including a mismatch mixed with prose.
repair_counts() (
    local doc=docs/dev/CODEBASE_MAP.md tmp rc key old new before message
    tmp="$(mktemp -d docs/.stack-counts.XXXXXX)"
    trap 'rm -rf "$tmp"' EXIT
    rc=0
    bash tools/scripts/check_doc_counts.sh > "$tmp/gate" 2>&1 || rc=$?
    cat "$tmp/gate"
    [ "$rc" -ne 0 ] || return 0
    [ "$rc" -eq 1 ] || return "$rc"
    if ! awk '
        /^FAIL:/ {
            if ($0 != "FAIL: doc-count drift detected." || section) exit 1
            section=1; in_rows=1; next
        }
        in_rows && /^$/ {in_rows=0; next}
        in_rows {
            if ($0 !~ /^    (test_groups|port_interfaces|persistence_adapters|condition_registrations|command_bundles|command_roots|dumpstate_subsystems|app_shape_folders) MISMATCH — code=[0-9]+ doc-says=[0-9]+ \(update the DOC-COUNTS block in docs\/CODEBASE_MAP\.md\)$/) exit 1
            # Leading whitespace is discarded explicitly for portable awk.
            line=$0; sub(/^ +/, "", line); split(line, a, /[[:space:]]+/)
            key=a[1]; new=a[4]; old=a[5]
            sub(/^code=/, "", new); sub(/^doc-says=/, "", old)
            if (seen[key]++ || ("x" old) == ("x" new)) exit 1
            print key, old, new; rows++
        }
        END {if (!section || !rows) exit 1}
    ' "$tmp/gate" > "$tmp/changes"; then
        echo 'stack-tip-refresh: doc-count failure is not exclusively numeric count drift' >&2
        return "$rc"
    fi
    # A path-only commit preserves unrelated staged work, but must not include
    # someone else's pending changes in the same documentation file.
    if [ -L "$doc" ] || ! git diff --quiet -- "$doc" ||
        ! git diff --cached --quiet -- "$doc" || ! git cat-file -e "HEAD:$doc"; then
        echo "stack-tip-refresh: refusing pending or symlink changes in $doc" >&2
        return 2
    fi
    if [ "$(tail -c 1 "$doc"; printf x)" != $'\nx' ]; then
        echo 'stack-tip-refresh: count document must retain its final newline' >&2
        return 2
    fi
    cp -p "$doc" "$tmp/old"
    cp -p "$doc" "$tmp/new"
    if ! awk -v changes="$tmp/changes" '
        BEGIN {while ((getline < changes) > 0) {old[$1]=$2; new[$1]=$3}}
        /<!-- DOC-COUNTS-BEGIN -->/ {inside=1; begins++; print; next}
        /<!-- DOC-COUNTS-END -->/ {inside=0; ends++; print; next}
        inside {
            for (key in new) {
                if ($0 ~ "^[[:space:]]*" key "[[:space:]]*:") {
                    if ($0 !~ "^[[:space:]]*" key "[[:space:]]*:[[:space:]]*" old[key] "[[:space:]]*$" || seen[key]++) exit 1
                    match($0, /[0-9]+/)
                    $0=substr($0, 1, RSTART-1) new[key] substr($0, RSTART+RLENGTH)
                }
            }
        }
        {print}
        END {
            if (begins != 1 || ends != 1 || inside) exit 1
            for (key in new) if (seen[key] != 1) exit 1
        }
    ' "$doc" > "$tmp/new"; then
        echo 'stack-tip-refresh: count block is ambiguous; refusing repair' >&2
        return 2
    fi
    before="$(git rev-parse HEAD)"
    mv "$tmp/new" "$doc"
    if ! bash tools/scripts/check_doc_counts.sh > "$tmp/recheck" 2>&1; then
        cat "$tmp/recheck"
        cp -p "$tmp/old" "$doc"
        return 1
    fi
    cat "$tmp/recheck"
    message="$tmp/message"
    printf 'Update measured documentation counts\n\n' > "$message"
    while read -r key old new; do
        printf '%s: %s -> %s\n' "$key" "$old" "$new" >> "$message"
    done < "$tmp/changes"
    if git commit --only -S -F "$message" -- "$doc"; then
        echo 'stack-tip-refresh: signed count-only correction committed before inventory'
    else
        rc=$?
        # Never reset a commit that may already exist or retry signing.
        if [ "$(git rev-parse HEAD)" = "$before" ]; then cp -p "$tmp/old" "$doc"; fi
        echo 'stack-tip-refresh: count commit failed; inventory not started' >&2
        return "$rc"
    fi
)

selftest() (
    bash "$ROOT/tools/scripts/stack_git_environment_test.sh"
    local tmp script="$ROOT/tools/scripts/stack_tip_refresh.sh"
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-stack-refresh.XXXXXX")"
    trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "SELFTEST FAIL exit=$rc" >&2; [ ! -f "${out:-}" ] || cat "$out" >&2; fi; rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/tools/scripts" "$tmp/tools/dev" "$tmp/docs" \
        "$tmp/engine/composition" "$tmp/contexts/commons/packages/fixture"
    cp "$script" "$tmp/tools/scripts/stack_tip_refresh.sh"
    cp "$ROOT/tools/dev/checkout-lock.sh" "$tmp/tools/dev/checkout-lock.sh"
    git -C "$tmp" init -q
    printf 'old\n' > "$tmp/engine/composition/fixture.def"
    printf 'old\n' > "$tmp/docs/CAPABILITY_INVENTORY.jsonl"
    printf 'untouched\n' > "$tmp/unrelated"
    printf 'old\n' > "$tmp/docs/transitive-generated.h"
    printf '/order\n/output\n/fail-*\n/build/\n' > "$tmp/.gitignore"
    cat > "$tmp/tools/scripts/zcode_registry_rederive.sh" <<'FIXTURE'
set -eu
printf 'registry\n' >> order
[ ! -f fail-registry ] || exit 7
if [ "${1:-}" = --check ]; then
    grep -qx fresh engine/composition/fixture.def
else
    printf 'fresh\n' > engine/composition/fixture.def
    printf 'new manifest\n' > contexts/commons/packages/fixture/zcode-package.json
    printf 'fresh\n' > docs/transitive-generated.h
fi
FIXTURE
    cat > "$tmp/Makefile" <<'FIXTURE'
.PHONY: docs-capability-inventory check-capability-inventory-generated check-doc-counts
docs-capability-inventory:
	@echo inventory >> order
	@test ! -f fail-inventory
	@echo fresh > docs/CAPABILITY_INVENTORY.jsonl
check-capability-inventory-generated:
	@echo inventory >> order
	@grep -qx fresh docs/CAPABILITY_INVENTORY.jsonl
check-doc-counts:
	@bash tools/scripts/check_doc_counts.sh
FIXTURE
    cat > "$tmp/tools/scripts/check_doc_counts.sh" <<'FIXTURE'
set -eu
printf 'counts\n' >> order
echo 'code-measured: test_groups=2'
if [ -f fail-counts ]; then
    printf '\nFAIL: doc-count drift detected.\n'
    printf '    test_groups MISMATCH — code=2 doc-says=1 (update the DOC-COUNTS block in docs/dev/CODEBASE_MAP.md)\n'
    printf '    stale prose cannot be repaired as a count\n\n'
    exit 1
fi
declared=$(sed -n 's/^test_groups: //p' docs/dev/CODEBASE_MAP.md)
if [ "$declared" != 2 ]; then
    printf '\nFAIL: doc-count drift detected.\n'
    printf '    test_groups MISMATCH — code=2 doc-says=%s (update the DOC-COUNTS block in docs/dev/CODEBASE_MAP.md)\n\n' "$declared"
    exit 1
fi
echo 'check_doc_counts: clean'
FIXTURE
    printf '<!-- DOC-COUNTS-BEGIN -->\ntest_groups: 2\n<!-- DOC-COUNTS-END -->\n' > "$tmp/docs/dev/CODEBASE_MAP.md"
    local key value
    for key in user.name user.email user.signingkey gpg.format gpg.ssh.program gpg.ssh.allowedSignersFile; do
        value="$(git config --get "$key" || true)"
        [ -z "$value" ] || git -C "$tmp" config "$key" "$value"
    done
    git -C "$tmp" add .
    git -C "$tmp" -c user.name=Fixture -c user.email=fixture@invalid -c commit.gpgSign=false commit --allow-empty -qm baseline
    local out="$tmp/output" rc path before after scenario mode
    local cli=(bash "$tmp/tools/scripts/stack_tip_refresh.sh")
    # B1: each dirty input refuses before generators, preserving bytes/index/refs.
    for scenario in staged unstaged deleted untracked ignored-manifest; do
        case "$scenario" in
            staged) printf 'dirty\n' > "$tmp/unrelated"; git -C "$tmp" add unrelated ;;
            unstaged) printf 'dirty\n' > "$tmp/unrelated" ;;
            deleted) rm "$tmp/unrelated" ;;
            untracked) printf 'dirty\n' > "$tmp/new-source" ;;
            ignored-manifest) printf 'contexts/commons/packages/*/zcode-package.json\n' >> "$tmp/.git/info/exclude"; printf 'ignored\n' > "$tmp/contexts/commons/packages/fixture/zcode-package.json" ;;
        esac
        before="$(git -C "$tmp" status --porcelain=v1; git -C "$tmp" ls-files --stage; git -C "$tmp" show-ref; find "$tmp" \( -path "$tmp/.git" -o -path "$tmp/build" \) -prune -o -type f ! -name output ! -name order -exec sha256sum {} +)"
        for mode in refresh check; do
            : > "$tmp/order"
            rc=0
            if [ "$mode" = check ]; then "${cli[@]}" --check >"$out" 2>&1 || rc=$?; else "${cli[@]}" >"$out" 2>&1 || rc=$?; fi
            [ "$rc" -eq 2 ] && [ ! -s "$tmp/order" ] || { echo "B1 RED: $scenario $mode"; return 1; }
            after="$(git -C "$tmp" status --porcelain=v1; git -C "$tmp" ls-files --stage; git -C "$tmp" show-ref; find "$tmp" \( -path "$tmp/.git" -o -path "$tmp/build" \) -prune -o -type f ! -name output ! -name order -exec sha256sum {} +)"
            [ "$before" = "$after" ] || return 1
        done
        git -C "$tmp" restore --source=HEAD --staged --worktree -- unrelated
        rm -f "$tmp/new-source" "$tmp/contexts/commons/packages/fixture/zcode-package.json"
    done
    : > "$tmp/.git/info/exclude"
    echo 'B1 PASS: dirty inputs refuse without effects'
    # B2/B3: assertions bind the real operator documentation, not fake Make.
    grep -Fq 'devbuild --wait bash tools/scripts/stack_tip_refresh.sh`' "$ROOT/docs/dev/DEVELOPING.md" || { echo 'B2 RED: nonexistent documented entry'; return 1; }
    echo 'B2 PASS: existing script entry documented'
    grep -Fq 'Helper builds may regenerate tracked view headers before checking' "$ROOT/docs/dev/DEVELOPING.md" || { echo 'B3 RED: source-preserving promise'; return 1; }
    echo 'B3 PASS: prerequisite-write limitation documented'
    # Stale registry refuses before touching inventory; check never rewrites.
    if "${cli[@]}" --check >"$out" 2>&1; then return 1; fi
    grep -qx old "$tmp/engine/composition/fixture.def"
    grep -qx old "$tmp/docs/CAPABILITY_INVENTORY.jsonl"
    [ "$(cat "$tmp/order")" = registry ]
    # Refresh reports its changes, including an untracked generated manifest.
    : > "$tmp/order"
    "${cli[@]}" >"$out" 2>&1
    [ "$(cat "$tmp/order")" = $'registry\ncounts\ninventory\ncounts' ]
    for path in engine/composition/fixture.def docs/CAPABILITY_INVENTORY.jsonl \
        contexts/commons/packages/fixture/zcode-package.json docs/transitive-generated.h; do
        grep -Fxq "  $path" "$out" || { echo "SELFTEST FAIL: omitted changed file $path" >&2; return 1; }
    done
    if grep -q '  unrelated' "$out"; then return 1; fi
    git -C "$tmp" add .
    git -C "$tmp" -c user.name=Fixture -c user.email=fixture@invalid -c commit.gpgSign=false commit --allow-empty -qm generated
    "${cli[@]}" >"$out" 2>&1
    grep -Fxq 'stack-tip-refresh: changed files: none' "$out"
    "${cli[@]}" --check >"$out" 2>&1
    # Inventory drift alone refuses without rewriting it or running counts.
    printf 'stale\n' > "$tmp/docs/CAPABILITY_INVENTORY.jsonl"
    git -C "$tmp" add docs
    git -C "$tmp" -c user.name=Fixture -c user.email=fixture@invalid -c commit.gpgSign=false commit --allow-empty -qm stale
    : > "$tmp/order"
    if "${cli[@]}" --check >"$out" 2>&1; then return 1; fi
    [ "$(cat "$tmp/order")" = $'registry\ninventory' ]
    grep -qx stale "$tmp/docs/CAPABILITY_INVENTORY.jsonl"
    # Each failed step stops the sequence; partial changes remain reported.
    touch "$tmp/fail-inventory"
    printf 'dirty\n' > "$tmp/engine/composition/fixture.def"
    git -C "$tmp" add engine
    git -C "$tmp" -c user.name=Fixture -c user.email=fixture@invalid -c commit.gpgSign=false commit --allow-empty -qm drift
    : > "$tmp/order"
    if "${cli[@]}" >"$out" 2>&1; then return 1; fi
    [ "$(cat "$tmp/order")" = $'registry\ncounts\ninventory' ]
    grep -Fxq '  engine/composition/fixture.def' "$out"
    rm "$tmp/fail-inventory"
    git -C "$tmp" add .
    git -C "$tmp" -c user.name=Fixture -c user.email=fixture@invalid -c commit.gpgSign=false commit --allow-empty -qm partial
    touch "$tmp/fail-registry"
    : > "$tmp/order"
    rc=0
    "${cli[@]}" >"$out" 2>&1 || rc=$?
    [ "$rc" -eq 7 ]
    [ "$(cat "$tmp/order")" = registry ]
    rm "$tmp/fail-registry"
    # Count drift begins at a clean committed tip; only the document is committed.
    local before after staged
    staged="$(git -C "$tmp" ls-files --stage -- ':!docs/dev/CODEBASE_MAP.md')"
    sed 's/test_groups: 2/test_groups: 1/' "$tmp/docs/dev/CODEBASE_MAP.md" > "$tmp/count-doc"
    mv "$tmp/count-doc" "$tmp/docs/dev/CODEBASE_MAP.md"
    git -C "$tmp" -c commit.gpgSign=false commit --only -qm 'Fixture count drift' -- docs/dev/CODEBASE_MAP.md
    before="$(git -C "$tmp" rev-parse HEAD)"
    : > "$tmp/order"
    "${cli[@]}" >"$out" 2>&1
    after="$(git -C "$tmp" rev-parse HEAD)"
    [ "$before" != "$after" ]
    [ "$(git -C "$tmp" show -s --format=%G? HEAD)" = G ]
    [ "$(git -C "$tmp" diff-tree --no-commit-id --name-only -r HEAD)" = docs/dev/CODEBASE_MAP.md ]
    value="$(git -C "$tmp" log -1 --format=%B)"
    grep -q 'test_groups.*1.*2' <<< "$value"
    [ "$(git -C "$tmp" ls-files --stage -- ':!docs/dev/CODEBASE_MAP.md')" = "$staged" ]
    [ "$(cat "$tmp/order")" = $'registry\ncounts\ncounts\ninventory\ncounts' ]
    echo 'COUNTS PASS: signed document-only correction 1 -> 2 before inventory'
    git -C "$tmp" add .
    git -C "$tmp" -c user.name=Fixture -c user.email=fixture@invalid -c commit.gpgSign=false commit --allow-empty -qm 'Fixture generated outputs'
    after="$(git -C "$tmp" rev-parse HEAD)"
    "${cli[@]}" >"$out" 2>&1
    [ "$(git -C "$tmp" rev-parse HEAD)" = "$after" ]
    grep -qx 'test_groups: 2' "$tmp/docs/dev/CODEBASE_MAP.md"
    echo 'COUNTS PASS: no drift leaves HEAD unchanged'
    # Match the reported old value so an ignored prose row could be repaired.
    sed 's/test_groups: 2/test_groups: 1/' "$tmp/docs/dev/CODEBASE_MAP.md" > "$tmp/count-doc"
    mv "$tmp/count-doc" "$tmp/docs/dev/CODEBASE_MAP.md"
    git -C "$tmp" -c user.name=Fixture -c user.email=fixture@invalid -c commit.gpgSign=false commit --only -qm 'Fixture mixed drift' -- docs/dev/CODEBASE_MAP.md
    after="$(git -C "$tmp" rev-parse HEAD)"
    touch "$tmp/fail-counts"
    : > "$tmp/order"
    if "${cli[@]}" >"$out" 2>&1; then return 1; fi
    [ "$(cat "$tmp/order")" = $'registry\ncounts' ]
    [ "$(git -C "$tmp" rev-parse HEAD)" = "$after" ]
    grep -qx 'test_groups: 1' "$tmp/docs/dev/CODEBASE_MAP.md"
    grep -Fq 'stale prose cannot be repaired as a count' "$out"
    grep -Fq 'stack-tip-refresh: doc-count failure is not exclusively numeric count drift' "$out"
    echo 'COUNTS PASS: mixed numeric/prose failure refuses without correction or inventory'
    git -C "$tmp" add .
    git -C "$tmp" -c user.name=Fixture -c user.email=fixture@invalid -c commit.gpgSign=false commit --allow-empty -qm complete
    if "${cli[@]}" --check >"$out" 2>&1; then return 1; fi
    echo 'stack-tip-refresh: SELFTEST PASS (order, drift, failure, changes, idempotence)'
)

if [ "$MODE" = selftest ]; then selftest; exit 0; fi
# The existing wrapper carries its lock into recursive Make and registry builds.
if [ "${ZCL_CHECKOUT_LOCK_HELD:-0}" != 1 ]; then
    exec bash tools/dev/checkout-lock.sh foreground build/.checkout.lock -- \
        bash "$ROOT/tools/scripts/stack_tip_refresh.sh" "$@"
fi

if ! dirty_state="$(git status --porcelain=v1 --untracked-files=all)"; then
    echo 'stack-tip-refresh: could not inspect checkout cleanliness' >&2
    exit 2
fi
if [ -n "$dirty_state" ]; then
    echo 'stack-tip-refresh: refusing dirty checkout; preserve and resolve owned work first' >&2
    exit 2
fi
for manifest in contexts/commons/packages/*/zcode-package.json; do
    [ -f "$manifest" ] || continue
    if ! git ls-files --error-unmatch -- "$manifest" >/dev/null 2>&1; then
        printf 'stack-tip-refresh: refusing untracked package manifest: %s\n' "$manifest" >&2
        exit 2
    fi
done

if [ "$MODE" = check ]; then
    bash tools/scripts/zcode_registry_rederive.sh --check
    make --no-print-directory check-capability-inventory-generated
    make --no-print-directory check-doc-counts
    echo 'stack-tip-refresh: CHECK PASS'
    exit 0
fi

declare -A BEFORE=() SEEN=()
ORIGINAL_CHANGED=()
OUTPUTS="$(mktemp "${TMPDIR:-/tmp}/zcl-stack-outputs.XXXXXX")"
trap 'rm -f "$OUTPUTS"' EXIT
git ls-files --stage -z > "$OUTPUTS"
while IFS= read -r -d '' entry; do
    path="${entry#*$'\t'}"
    read -r mode digest stage <<< "${entry%%$'\t'*}"
    [ "$stage" = 0 ] || { echo 'stack-tip-refresh: unresolved index conflict' >&2; exit 2; }
    if [ "$mode" = 120000 ]; then digest="$(content_id "$path")"; fi
    BEFORE["$path"]="$digest"
done < "$OUTPUTS"
list_changes > "$OUTPUTS"
while IFS= read -r -d '' path; do
    ORIGINAL_CHANGED+=("$path")
    BEFORE["$path"]="$(content_id "$path")"
done < "$OUTPUTS"
report_changes() {
    local rc=$? path after count=0
    trap - EXIT
    if ! list_changes > "$OUTPUTS"; then rc=2; fi
    # The original set includes removed outputs; the new set includes additions.
    for path in "${ORIGINAL_CHANGED[@]}"; do printf '%s\0' "$path" >> "$OUTPUTS"; done
    while IFS= read -r -d '' path; do
        [ "${SEEN[$path]:-0}" = 0 ] || continue
        SEEN["$path"]=1
        if ! after="$(content_id "$path")"; then rc=2; continue; fi
        if [ "$after" != "${BEFORE[$path]:-missing}" ]; then
            if [ "$count" -eq 0 ]; then echo 'stack-tip-refresh: changed files:'; fi
            printf '  %s\n' "$path"
            count=$((count + 1))
        fi
    done < "$OUTPUTS"
    if [ "$count" -eq 0 ]; then echo 'stack-tip-refresh: changed files: none'; fi
    rm -f "$OUTPUTS"
    exit "$rc"
}
trap report_changes EXIT
bash tools/scripts/zcode_registry_rederive.sh
ORIGINAL_CHANGED+=(docs/dev/CODEBASE_MAP.md)
repair_counts
make --no-print-directory docs-capability-inventory
make --no-print-directory check-doc-counts
