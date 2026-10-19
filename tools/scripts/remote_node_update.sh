#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Read-only remote node source/service status and update planning.
#
# Phase-0 containment deliberately keeps this compatibility-named script free
# of fetch, merge, build, install, and restart implementations.  It observes
# origin/main with `git ls-remote` (which does not update the checkout) and
# reports what a future, proof-bound release transaction would need to do.
# Canonical deployment remains the separate owner-gated `make deploy` path.

set -euo pipefail

SCHEMA="zcl.remote_node_update.v1"

is_true() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

log() {
    if is_true "${ZCL_REMOTE_JSON:-0}"; then
        printf 'remote_node_update: %s\n' "$*" >&2
    else
        printf 'remote_node_update: %s\n' "$*"
    fi
}

fail() {
    printf 'remote_node_update: REFUSE: %s\n' "$*" >&2
    exit 1
}

publication_refused() {
    local reason="$1"
    if is_true "${ZCL_REMOTE_JSON:-0}"; then
        printf '{"schema":"%s","api_version":"v1","status":"blocked",' \
            "$SCHEMA"
        printf '"error":"runtime_publication_contained",'
        printf '"reason":"%s","runtime_publication":false,' \
            "$(json_escape "$reason")"
        printf '"mutation_contained":true,'
        printf '"safe_next_action":"use remote-node-plan; canonical deployment remains owner-gated make deploy"}\n'
    fi
    printf 'remote_node_update: REFUSE: runtime publication is contained: %s\n' \
        "$reason" >&2
    exit 3
}

json_escape() {
    local s="${1:-}"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

usage() {
    cat <<'USAGE'
usage: tools/scripts/remote_node_update.sh [--json] HOST [HOST...]
       ZCL_REMOTE_HOSTS='host1 host2' tools/scripts/remote_node_update.sh
       tools/scripts/remote_node_update.sh self

Read remote source/service status and print a non-authoritative update plan.
The script never fetches, merges, builds, installs, or restarts.

Read-only inputs:
  ZCL_REMOTE_DRY_RUN=1            required; mutation mode is contained
  ZCL_REMOTE_BRANCH=main          refuse any other checked-out branch
  ZCL_REMOTE_MAIN_REF=origin/main refuse any other remote ref
  ZCL_REMOTE_BUILD=fast-rebuild   requested future build shown in the plan
  ZCL_REMOTE_UNIT=z23-test.service
  ZCL_REMOTE_JSON=0               line logs; set 1 or pass --json for JSON

Contained requests (all refuse before SSH or local/remote file mutation):
  ZCL_REMOTE_DRY_RUN=0
  ZCL_REMOTE_INSTALL_BIN=...
  ZCL_REMOTE_INSTALL_ARTIFACT=...
  ZCL_REMOTE_RESTART=1
  ZCL_DEPLOY_ALLOW_CANONICAL=1

No Python or jq is required. Canonical deployment is available only through
the separate owner-gated `make deploy` transaction.
USAGE
}

is_self_host() {
    case "${1:-}" in
        self|local|localhost|127.0.0.1|.) return 0 ;;
        *) return 1 ;;
    esac
}

shell_quote() {
    printf '%q' "$1"
}

ensure_local_main() {
    local root branch
    root="$(GIT_OPTIONAL_LOCKS=0 git rev-parse --show-toplevel 2>/dev/null || true)"
    [ -n "$root" ] || return 0
    branch="$(GIT_OPTIONAL_LOCKS=0 git -C "$root" symbolic-ref --short HEAD 2>/dev/null || true)"
    [ -z "$branch" ] || [ "$branch" = "main" ] ||
        fail "local checkout must be main before remote planning (got $branch)"
}

refuse_public_mutation_request() {
    if ! is_true "${ZCL_REMOTE_DRY_RUN:-1}"; then
        publication_refused "ZCL_REMOTE_DRY_RUN must remain 1"
    fi
    [ -z "${ZCL_REMOTE_INSTALL_BIN:-}" ] ||
        publication_refused "ZCL_REMOTE_INSTALL_BIN is not plan authority"
    [ -z "${ZCL_REMOTE_INSTALL_ARTIFACT:-}" ] ||
        publication_refused "ZCL_REMOTE_INSTALL_ARTIFACT is not plan authority"
    if is_true "${ZCL_REMOTE_RESTART:-0}"; then
        publication_refused "ZCL_REMOTE_RESTART is not plan authority"
    fi
    if is_true "${ZCL_DEPLOY_ALLOW_CANONICAL:-0}"; then
        publication_refused "canonical authority cannot be delegated to the remote planner"
    fi
    [ -z "${ZCL_REMOTE_GUARD_ACTION:-}" ] ||
        publication_refused "deploy-guard actions are not accepted by the remote planner"
}

remote_payload() {
    cat <<'REMOTE_PAYLOAD'
set -euo pipefail

is_true() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

log() {
    if is_true "${ZCL_REMOTE_JSON:-0}"; then
        printf 'remote_node_update: %s\n' "$*" >&2
    else
        printf 'remote_node_update: %s\n' "$*"
    fi
}

fail() {
    printf 'remote_node_update: REFUSE: %s\n' "$*" >&2
    exit 1
}

json_escape() {
    local s="${1:-}"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

service_active() {
    local unit="$1"
    [ -n "$unit" ] || return 0
    systemctl --user is-active "$unit" 2>/dev/null || true
}

service_execstart() {
    local unit="$1"
    [ -n "$unit" ] || return 0
    systemctl --user show "$unit" -p ExecStart --value 2>/dev/null |
        sed -n '1p' || true
}

emit_json_summary() {
    local host_name json
    is_true "${ZCL_REMOTE_JSON:-0}" || return 0
    host_name="$(hostname -f 2>/dev/null || hostname)"
    json="{\"schema\":\"zcl.remote_node_update.v1\""
    json="${json},\"api_version\":\"v1\""
    json="${json},\"status\":\"ok\""
    json="${json},\"host\":\"$(json_escape "$host_name")\""
    json="${json},\"repo\":\"$(json_escape "$repo")\""
    json="${json},\"branch\":\"$(json_escape "$branch")\""
    json="${json},\"head\":\"$(json_escape "$head")\""
    json="${json},\"origin_main\":\"$(json_escape "$origin_head")\""
    json="${json},\"dry_run\":true"
    json="${json},\"requested_build\":\"$(json_escape "$build")\""
    json="${json},\"unit\":\"$(json_escape "$unit")\""
    json="${json},\"unit_active\":\"$(json_escape "$active")\""
    json="${json},\"unit_execstart\":\"$(json_escape "$execstart")\""
    json="${json},\"plan\":\"$(json_escape "$plan")\""
    json="${json},\"relationship\":\"$(json_escape "$relationship")\""
    json="${json},\"remote_observation\":\"git_ls_remote_no_fetch\""
    json="${json},\"runtime_publication\":false"
    json="${json},\"mutation_contained\":true"
    json="${json},\"safe_next_action\":\"review the plan; use owner-gated make deploy only for canonical deployment\"}"
    printf '%s\n' "$json"
}

main() {
    local repo branch expect_branch main_ref build allow_dirty unit dirty
    local head origin_head active execstart relationship plan remote_row

    # Defense in depth for direct execution of the embedded payload. The outer
    # script performs the same checks before SSH is opened.
    is_true "${ZCL_REMOTE_DRY_RUN:-1}" ||
        fail "runtime publication is contained; ZCL_REMOTE_DRY_RUN must remain 1"
    [ -z "${ZCL_REMOTE_INSTALL_BIN:-}" ] ||
        fail "runtime publication is contained; install target rejected"
    [ -z "${ZCL_REMOTE_INSTALL_ARTIFACT:-}" ] ||
        fail "runtime publication is contained; install artifact rejected"
    ! is_true "${ZCL_REMOTE_RESTART:-0}" ||
        fail "runtime publication is contained; restart rejected"
    ! is_true "${ZCL_DEPLOY_ALLOW_CANONICAL:-0}" ||
        fail "runtime publication is contained; canonical authority rejected"

    repo="${ZCL_REMOTE_REPO:-$HOME/github/zclassic23}"
    expect_branch="${ZCL_REMOTE_BRANCH:-main}"
    main_ref="${ZCL_REMOTE_MAIN_REF:-origin/main}"
    build="${ZCL_REMOTE_BUILD:-fast-rebuild}"
    allow_dirty="${ZCL_REMOTE_ALLOW_DIRTY:-0}"
    unit="${ZCL_REMOTE_UNIT:-zclassic23-test.service}"

    case "$main_ref" in
        origin/main|refs/remotes/origin/main) ;;
        *) fail "only origin/main may be used for remote node planning (got $main_ref)" ;;
    esac
    [ -d "$repo/.git" ] || fail "repo not found: $repo"
    cd "$repo"

    branch="$(GIT_OPTIONAL_LOCKS=0 git symbolic-ref --short HEAD 2>/dev/null || true)"
    [ "$branch" = "$expect_branch" ] ||
        fail "remote checkout must be $expect_branch (got ${branch:-detached})"
    [ "$expect_branch" = "main" ] ||
        fail "remote planning branch must be main (got $expect_branch)"

    dirty="$(GIT_OPTIONAL_LOCKS=0 git status --porcelain=v1 --untracked-files=no)"
    if [ -n "$dirty" ] && ! is_true "$allow_dirty"; then
        printf '%s\n' "$dirty" >&2
        fail "remote checkout has tracked local changes; plan requires explicit ZCL_REMOTE_ALLOW_DIRTY=1 acknowledgement"
    fi

    head="$(GIT_OPTIONAL_LOCKS=0 git rev-parse HEAD)"
    remote_row="$(GIT_OPTIONAL_LOCKS=0 git ls-remote --exit-code origin refs/heads/main 2>/dev/null | sed -n '1p')" ||
        fail "could not observe origin/main with read-only git ls-remote"
    origin_head="${remote_row%%[[:space:]]*}"
    case "$origin_head" in
        ''|*[!0-9a-fA-F]*) fail "origin/main returned an invalid object id" ;;
    esac

    if [ "$head" = "$origin_head" ]; then
        relationship="current"
        plan="already_current"
    elif GIT_OPTIONAL_LOCKS=0 git cat-file -e "${origin_head}^{commit}" 2>/dev/null &&
         GIT_OPTIONAL_LOCKS=0 git merge-base --is-ancestor "$head" "$origin_head" 2>/dev/null; then
        relationship="fast_forward_known"
        plan="future_transaction_may_fast_forward_then_prove"
    else
        relationship="remote_head_observed_unfetched"
        plan="review_remote_head_then_prepare_immutable_candidate"
    fi

    active="$(service_active "$unit")"
    execstart="$(service_execstart "$unit")"
    log "schema=zcl.remote_node_update.v1"
    log "repo=$repo branch=$branch head=$head origin_main=$origin_head"
    log "plan=$plan relationship=$relationship requested_build=$build"
    log "runtime_publication=false mutation_contained=true"
    [ -z "$execstart" ] || log "unit=$unit active=${active:-unknown} execstart=$execstart"
    emit_json_summary
}

main "$@"
REMOTE_PAYLOAD
}

run_one_host() {
    local host="$1" ssh_bin env_prefix
    [ -n "$host" ] || fail "empty host"
    log "target=$host schema=$SCHEMA"

    env_prefix="ZCL_REMOTE_REPO=$(shell_quote "${ZCL_REMOTE_REPO:-}")"
    env_prefix="$env_prefix ZCL_REMOTE_BRANCH=$(shell_quote "${ZCL_REMOTE_BRANCH:-main}")"
    env_prefix="$env_prefix ZCL_REMOTE_MAIN_REF=$(shell_quote "${ZCL_REMOTE_MAIN_REF:-origin/main}")"
    env_prefix="$env_prefix ZCL_REMOTE_BUILD=$(shell_quote "${ZCL_REMOTE_BUILD:-fast-rebuild}")"
    env_prefix="$env_prefix ZCL_REMOTE_DRY_RUN=1"
    env_prefix="$env_prefix ZCL_REMOTE_ALLOW_DIRTY=$(shell_quote "${ZCL_REMOTE_ALLOW_DIRTY:-0}")"
    env_prefix="$env_prefix ZCL_REMOTE_UNIT=$(shell_quote "${ZCL_REMOTE_UNIT:-zclassic23-test.service}")"
    env_prefix="$env_prefix ZCL_REMOTE_JSON=$(shell_quote "${ZCL_REMOTE_JSON:-0}")"

    if is_self_host "$host"; then
        remote_payload | env \
            ZCL_REMOTE_REPO="${ZCL_REMOTE_REPO:-}" \
            ZCL_REMOTE_BRANCH="${ZCL_REMOTE_BRANCH:-main}" \
            ZCL_REMOTE_MAIN_REF="${ZCL_REMOTE_MAIN_REF:-origin/main}" \
            ZCL_REMOTE_BUILD="${ZCL_REMOTE_BUILD:-fast-rebuild}" \
            ZCL_REMOTE_DRY_RUN=1 \
            ZCL_REMOTE_ALLOW_DIRTY="${ZCL_REMOTE_ALLOW_DIRTY:-0}" \
            ZCL_REMOTE_UNIT="${ZCL_REMOTE_UNIT:-zclassic23-test.service}" \
            ZCL_REMOTE_JSON="${ZCL_REMOTE_JSON:-0}" \
            bash -s
        return
    fi

    ssh_bin="${ZCL_REMOTE_SSH:-ssh}"
    remote_payload | "$ssh_bin" "$host" "$env_prefix bash -s"
}

selftest_refusal() {
    local name="$1" sandbox="$2" fake_ssh="$3"
    shift 3
    local out="$sandbox/$name.out" rc=0
    env -u ZCL_REMOTE_SELFTEST \
        ZCL_REMOTE_SSH="$fake_ssh" ZCL_REMOTE_JSON=1 "$@" \
        "$0" example.invalid >"$out" 2>&1 || rc=$?
    [ "$rc" -eq 3 ] ||
        fail "selftest $name expected contained exit 3, got $rc"
    grep -q 'runtime_publication_contained' "$out" ||
        fail "selftest $name omitted structured containment refusal"
    [ ! -e "$sandbox/ssh-called" ] ||
        fail "selftest $name reached SSH before refusing mutation"
}

selftest() {
    local sandbox fake_ssh
    sandbox="$(mktemp -d "${TMPDIR:-/tmp}/zcl-remote-plan-selftest.XXXXXX")"
    ZCL_REMOTE_SELFTEST_SANDBOX="$sandbox"
    trap 'rm -rf "${ZCL_REMOTE_SELFTEST_SANDBOX:-}"' EXIT HUP INT TERM
    fake_ssh="$sandbox/ssh"
    {
        printf '#!/usr/bin/env bash\n'
        printf 'touch %q\n' "$sandbox/ssh-called"
        printf 'exit 99\n'
    } > "$fake_ssh"
    chmod 700 "$fake_ssh"

    selftest_refusal apply "$sandbox" "$fake_ssh" ZCL_REMOTE_DRY_RUN=0
    selftest_refusal install "$sandbox" "$fake_ssh" \
        ZCL_REMOTE_INSTALL_BIN="$sandbox/node"
    selftest_refusal artifact "$sandbox" "$fake_ssh" \
        ZCL_REMOTE_INSTALL_ARTIFACT="$sandbox/candidate"
    selftest_refusal restart "$sandbox" "$fake_ssh" ZCL_REMOTE_RESTART=1
    selftest_refusal canonical "$sandbox" "$fake_ssh" \
        ZCL_DEPLOY_ALLOW_CANONICAL=1
    printf 'remote-node-plan selftest PASS\n'
    rm -rf "$sandbox"
    ZCL_REMOTE_SELFTEST_SANDBOX=""
    trap - EXIT HUP INT TERM
}

main() {
    while [ "$#" -gt 0 ]; do
        case "${1:-}" in
            --json)
                ZCL_REMOTE_JSON=1
                export ZCL_REMOTE_JSON
                shift
                ;;
            --selftest)
                ZCL_REMOTE_SELFTEST=1
                export ZCL_REMOTE_SELFTEST
                shift
                ;;
            --)
                shift
                break
                ;;
            *) break ;;
        esac
    done

    if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
        usage
        exit 0
    fi
    if is_true "${ZCL_REMOTE_SELFTEST:-0}"; then
        selftest
        exit 0
    fi

    # This gate runs before branch inspection, SSH, or the embedded payload.
    refuse_public_mutation_request
    ensure_local_main

    if [ "$#" -eq 0 ]; then
        # shellcheck disable=SC2086
        set -- ${ZCL_REMOTE_HOSTS:-}
    fi
    [ "$#" -gt 0 ] || {
        usage >&2
        fail "provide HOST or ZCL_REMOTE_HOSTS"
    }

    local host
    for host in "$@"; do
        run_one_host "$host"
    done
}

main "$@"
