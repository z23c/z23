#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Three-worktree acceptance for the Git/receipt-only dev.fleet command.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fleet_bin="$repo/build/bin/z23-dev"
sha3_bin="$repo/build/bin/agent_sha3"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/z23-dev-fleet.XXXXXX")"

cleanup() {
    case "$fixture" in
        "${TMPDIR:-/tmp}"/z23-dev-fleet.*) ;;
        *) echo "dev-fleet-selftest: refusing unsafe cleanup: $fixture" >&2; exit 2 ;;
    esac
    if [ -d "$fixture/main/.git" ] || [ -f "$fixture/main/.git" ]; then
        git -C "$fixture/main" worktree remove --force "$fixture/alpha" >/dev/null 2>&1 || true
        git -C "$fixture/main" worktree remove --force "$fixture/beta" >/dev/null 2>&1 || true
    fi
    find "$fixture" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

die() { echo "dev-fleet-selftest: $*" >&2; exit 1; }
gitq() { git "$@" >/dev/null; }

gitq -c init.defaultBranch=main init --bare "$fixture/origin.git"
gitq -c init.defaultBranch=main init "$fixture/main"
git -C "$fixture/main" config user.name "Fleet Acceptance"
git -C "$fixture/main" config user.email "fleet@example.invalid"
mkdir -p "$fixture/main/engine/composition/commands" "$fixture/main/tools/dev"
printf 'fixture:\n\t@true\n' > "$fixture/main/Makefile"
printf '/* root marker */\n' > "$fixture/main/engine/composition/commands/root.def"
printf '/* catalog marker */\n' > "$fixture/main/tools/dev/test_group_catalog.def"
gitq -C "$fixture/main" add Makefile engine tools
gitq -C "$fixture/main" commit -m base
gitq -C "$fixture/main" branch -M main
gitq -C "$fixture/main" remote add origin "$fixture/origin.git"
gitq -C "$fixture/main" push -u origin main

gitq -C "$fixture/main" worktree add -b agent/alpha "$fixture/alpha" main
git -C "$fixture/alpha" config user.name "Fleet Acceptance"
git -C "$fixture/alpha" config user.email "fleet@example.invalid"
mkdir -p "$fixture/alpha/tools"
printf 'alpha\n' > "$fixture/alpha/tools/alpha.c"
gitq -C "$fixture/alpha" add tools/alpha.c
gitq -C "$fixture/alpha" commit -m alpha
gitq -C "$fixture/alpha" push -u origin agent/alpha

gitq -C "$fixture/main" worktree add -b agent/beta "$fixture/beta" main
git -C "$fixture/beta" config user.name "Fleet Acceptance"
git -C "$fixture/beta" config user.email "fleet@example.invalid"
mkdir -p "$fixture/beta/core"
printf 'beta\n' > "$fixture/beta/core/beta.c"
gitq -C "$fixture/beta" add core/beta.c
gitq -C "$fixture/beta" commit -m beta
gitq -C "$fixture/beta" push -u origin agent/beta

gitq -C "$fixture/main" branch feature/ignored main
gitq -C "$fixture/main" push origin feature/ignored
mkdir -p "$fixture/alpha/docs"
printf 'dirty alpha\n' > "$fixture/alpha/docs/alpha.txt"
gitq -C "$fixture/main" fetch origin

write_receipt() {
    local worktree="$1"
    shift
    local receipt_dir="$worktree/.cache/agent-receipts"
    local log="$receipt_dir/000000-lint-fixture.log"
    local receipt="$receipt_dir/000000-lint-fixture.receipt"
    local head branch status diff output_sha body body_sha verdict exit_status expect_missing line
    mkdir -p "$receipt_dir"
    verdict=PASS
    exit_status=0
    expect_missing=0
    for line in "$@"; do
        case "$line" in FAIL\ check-*) verdict=FAIL; exit_status=1; expect_missing=1 ;; esac
        printf '%s\n' "$line" >> "$log"
    done
    if [ "$verdict" = PASS ]; then
        printf '%s\n' 'LINT: all checks passed' >> "$log"
    fi
    head="$(git -C "$worktree" rev-parse HEAD)"
    branch="$(git -C "$worktree" rev-parse --abbrev-ref HEAD)"
    status="$(git -C "$worktree" status --porcelain)"
    status="$(printf '%s' "$status" | "$sha3_bin" -)"
    diff="$(git -C "$worktree" diff HEAD | "$sha3_bin" -)"
    output_sha="$("$sha3_bin" "$log" | cut -d' ' -f1)"
    body="$(printf '%s\n' \
        'receipt_schema=zcl.gate_receipt.v1' \
        'chain_index=0' \
        'prev_receipt_sha3=GENESIS' \
        'gate=lint' \
        "branch=$branch" \
        "worktree_path=$worktree" \
        "head_sha=$head" \
        "head_sha_after=$head" \
        "tree_status_sha3=$status" \
        "tree_diff_sha3_after=$diff" \
        'output_path=000000-lint-fixture.log' \
        "output_sha3=$output_sha" \
        "exit_status=$exit_status" \
        "expect_missing=$expect_missing" \
        'forbid_present=0' \
        "verdict=$verdict")"
    body_sha="$(printf '%s\n' "$body" | "$sha3_bin" -)"
    printf '%s\nreceipt_sha3=%s\n' "$body" "$body_sha" > "$receipt"
}

write_receipt "$fixture/main" 'PASS check-format'
write_receipt "$fixture/alpha" 'FAIL check-format'
write_receipt "$fixture/beta" 'FAIL check-core-seal' 'FAIL check-git-hooks-installed'

result="$fixture/fleet.json"
(cd "$fixture/main" && "$fleet_bin" dev fleet > "$result")

main_head="$(git -C "$fixture/main" rev-parse HEAD)"
alpha_head="$(git -C "$fixture/alpha" rev-parse HEAD)"
beta_head="$(git -C "$fixture/beta" rev-parse HEAD)"
grep -Fq '"lane_count":3' "$result" || die "did not enumerate exactly three lanes"
grep -Fq '"live_node_read":false' "$result" || die "node-free source declaration missing"
grep -Fq "\"main_head\":\"$main_head\"" "$result" || die "main head missing"
grep -Fq "\"branch\":\"agent/alpha\"" "$result" || die "alpha lane missing"
grep -Fq "\"head\":\"$alpha_head\"" "$result" || die "alpha head missing"
grep -Fq "\"since_commit\":\"$alpha_head\"" "$result" || die "alpha red-since missing"
grep -Fq 'docs/alpha.txt' "$result" || die "alpha dirty file missing"
grep -Fq 'tools/alpha.c' "$result" || die "alpha remote delta missing"
grep -Fq "\"head\":\"$beta_head\"" "$result" || die "beta head missing"
grep -Fq 'core/beta.c' "$result" || die "beta remote delta missing"
grep -Fq '"gate":"check-core-seal","since_commit"' "$result" || die "core seal red missing"
grep -Fq '"gate":"check-git-hooks-installed","since_commit"' "$result" || die "hooks red missing"
grep -Fq '"owner_only_red_gate_count":2' "$result" || die "owner-only total missing"
grep -Eq '"branch":"main"[^}]*"lint_status":"green"' "$result" || die "main current green receipt missing"
grep -Eq '"branch":"agent/alpha"[^}]*"lint_status":"red"' "$result" || die "alpha current red receipt missing"
grep -Eq '"branch":"agent/beta"[^}]*"lint_status":"red"' "$result" || die "beta current red receipt missing"
if grep -Fq 'feature/ignored' "$result"; then
    die "non-agent remote branch leaked into fleet"
fi

# Receipt freshness and log integrity are part of the same three-worktree
# proof. Changing alpha after its receipt must demote it to stale; changing
# beta's sealed log must make its lint evidence invalid, never green.
printf 'newer tracked dirt\n' >> "$fixture/alpha/tools/alpha.c"
(cd "$fixture/main" && "$fleet_bin" dev fleet > "$fixture/fleet-stale.json")
grep -Eq '"branch":"agent/alpha"[^}]*"lint_status":"stale"' \
    "$fixture/fleet-stale.json" || die "alpha stale receipt was trusted"
printf 'tamper\n' >> "$fixture/beta/.cache/agent-receipts/000000-lint-fixture.log"
(cd "$fixture/main" && "$fleet_bin" dev fleet > "$fixture/fleet-invalid.json")
grep -Eq '"branch":"agent/beta"[^}]*"lint_status":"invalid"' \
    "$fixture/fleet-invalid.json" || die "tampered beta log was trusted"

echo "dev-fleet-selftest: PASS — three worktrees, exact heads/files/red-since, owner-only gates, freshness, and log integrity"
