#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Bootstrap one checksummed Z23 release on fresh remote hosts, sequentially.
# The release is built elsewhere; remote hosts only verify, install, activate,
# and qualify the exact transferred runtime bytes. Each host receives the
# complete runtime set in one bounded archive stream, not five SSH handshakes.
#
# Usage:
#   deploy_z23_release.sh --hosts='host1 host2' [--release-dir=DIR]
#   Z23_RELEASE_HOSTS='host1 host2' deploy_z23_release.sh
#   deploy_z23_release.sh --selftest
#
# The normal build-once front door is:
#   make release-deploy Z23_RELEASE_HOSTS='host1 host2'
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALLER="$SCRIPT_DIR/install_z23.sh"
SSH_BIN="${Z23_DEPLOY_SSH:-ssh}"
# The remote activation can spend five minutes qualifying a cold spinning-disk
# host without writing stdout. Keepalives prove the encrypted peer is alive;
# forty missed 15-second replies still bound a genuinely dead connection, but
# transient disk/CPU starvation no longer tears down a healthy activation.
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15
          -o ServerAliveCountMax=40)

die() { printf 'deploy_z23_release: REFUSE: %s\n' "$*" >&2; exit 1; }
say() { printf 'deploy_z23_release: %s\n' "$*" >&2; }

usage() {
    sed -n '2,17p' "$0"
}

verify_release() {
    local dir="$1" names
    [ -d "$dir" ] || die "release directory missing: $dir"
    [ -f "$dir/SHA256SUMS" ] || die "SHA256SUMS missing in $dir"
    names="$(awk '{print $2}' "$dir/SHA256SUMS" | LC_ALL=C sort)"
    [ "$names" = $'AGENT_CARD.md\nz23\nzclassic23\nzclassic23-acme\nzclassic23-package-verify' ] \
        || die "SHA256SUMS must name exactly AGENT_CARD.md, z23, zclassic23, zclassic23-acme, and zclassic23-package-verify"
    (cd "$dir" && sha256sum -c --strict SHA256SUMS >/dev/null) \
        || die "release SHA256SUMS mismatch"
    [ -x "$INSTALLER" ] || die "installer missing or not executable: $INSTALLER"
}

prepare_host() {
    local host="$1" manifest="$2"
    "$SSH_BIN" "${SSH_OPTS[@]}" "$host" bash -s -- "$manifest" <<'REMOTE_PREPARE'
set -eu
manifest="$1"
case "$manifest" in *[!0-9a-f]*|'') exit 2 ;; esac
[ "${#manifest}" -eq 64 ] || exit 2
if systemctl --user is-active --quiet zclassic23.service 2>/dev/null; then
    echo "active zclassic23.service owns the canonical node" >&2
    exit 3
fi
if systemctl --user cat z23.service >/dev/null 2>&1 ||
   [ -e "$HOME/.config/systemd/user/z23.service" ]; then
    echo "z23.service already exists; use the canonical upgrade path" >&2
    exit 4
fi
for path in "$HOME/.local/bin/z23" "$HOME/.local/bin/zclassic23" \
            "$HOME/.local/bin/zclassic23-package-verify" \
            "$HOME/.local/bin/zclassic23-acme"; do
    [ ! -e "$path" ] || {
        echo "fresh bootstrap target already exists: $path" >&2
        exit 5
    }
done
base="$HOME/.cache/z23/releases"
stage="$base/$manifest"
incoming="$base/.incoming-$manifest-$$"
[ ! -e "$stage" ] || {
    echo "manifest-addressed release already exists: $stage" >&2
    exit 6
}
mkdir -p "$incoming"
printf '%s\n%s\n' "$stage" "$incoming"
REMOTE_PREPARE
}

copy_release() {
    local host="$1" incoming="$2" release_dir="$3"
    command -v tar >/dev/null 2>&1 || die "tar is required for release transfer"
    # Exact, fixed member names only. The receiving directory was minted and
    # path-checked by prepare_host; activate_host independently re-hashes the
    # manifest, installer, and every extracted payload before installation.
    tar -C "$release_dir" -cf - \
        SHA256SUMS AGENT_CARD.md z23 zclassic23 zclassic23-package-verify \
        zclassic23-acme \
        -C "$SCRIPT_DIR" install_z23.sh \
        | "$SSH_BIN" "${SSH_OPTS[@]}" "$host" \
            tar -C "$incoming" -xf -
}

discard_incoming() {
    local host="$1" incoming="$2" manifest="$3"
    "$SSH_BIN" "${SSH_OPTS[@]}" "$host" bash -s -- \
        "$incoming" "$manifest" <<'REMOTE_DISCARD'
set -eu
incoming="$1"
manifest="$2"
case "$manifest" in *[!0-9a-f]*|'') exit 2 ;; esac
[ "${#manifest}" -eq 64 ] || exit 2
prefix="$HOME/.cache/z23/releases/.incoming-$manifest-"
case "$incoming" in "$prefix"*) ;; *) exit 2 ;; esac
suffix="${incoming#"$prefix"}"
case "$suffix" in ''|*[!0-9]*) exit 2 ;; esac
find "$incoming" -depth -delete 2>/dev/null || true
REMOTE_DISCARD
}

activate_host() {
    local host="$1" incoming="$2" stage="$3" manifest="$4" installer_sha="$5"
    local health_seconds="${Z23_RELEASE_HEALTH_SECONDS:-300}"
    "$SSH_BIN" "${SSH_OPTS[@]}" "$host" bash -s -- \
        "$incoming" "$stage" "$manifest" "$installer_sha" "$health_seconds" <<'REMOTE_ACTIVATE'
set -eu
incoming="$1"; stage="$2"; manifest="$3"; installer_sha="$4"
health_seconds="$5"
prefix="$HOME/.local"
unit="$HOME/.config/systemd/user/z23.service"
cleanup_armed=1

case "$manifest" in *[!0-9a-f]*|'') exit 2 ;; esac
[ "${#manifest}" -eq 64 ] || exit 2
[ "$stage" = "$HOME/.cache/z23/releases/$manifest" ] || {
    echo "refusing unsafe release stage path: $stage" >&2
    exit 2
}
case "$incoming" in
    "$HOME/.cache/z23/releases/.incoming-$manifest-"*) ;;
    *) echo "refusing unsafe incoming path: $incoming" >&2; exit 2 ;;
esac
case "$health_seconds" in *[!0-9]*|'') exit 2 ;; esac
[ "$health_seconds" -gt 0 ] || exit 2

cleanup() {
    rc=$?
    trap - EXIT HUP INT TERM
    if [ "$cleanup_armed" -eq 1 ]; then
        systemctl --user disable --now z23.service >/dev/null 2>&1 || true
        # -type l as well as -type f: zclassic23 is a symlink to z23, and a
        # plain -type f rollback left it behind dangling, pointing at bytes
        # this cleanup had just deleted.
        find "$prefix/bin/z23" "$prefix/bin/zclassic23" \
             "$prefix/bin/zclassic23-package-verify" \
             "$prefix/bin/zclassic23-acme" "$unit" \
             -maxdepth 0 \( -type f -o -type l \) -delete 2>/dev/null || true
        find "$incoming" "$stage" -depth -delete 2>/dev/null || true
        systemctl --user daemon-reload >/dev/null 2>&1 || true
    fi
    exit "$rc"
}
trap cleanup EXIT HUP INT TERM

got_manifest="$(sha256sum "$incoming/SHA256SUMS" | awk '{print $1}')"
[ "$got_manifest" = "$manifest" ] || {
    echo "transferred manifest bytes differ" >&2
    exit 10
}
got_installer="$(sha256sum "$incoming/install_z23.sh" | awk '{print $1}')"
[ "$got_installer" = "$installer_sha" ] || {
    echo "transferred installer bytes differ" >&2
    exit 11
}
(cd "$incoming" && sha256sum -c --strict SHA256SUMS >/dev/null) || {
    echo "transferred release bytes differ" >&2
    exit 12
}
mv "$incoming" "$stage"
chmod 755 "$stage/install_z23.sh"
Z23_INSTALL_PREFIX="$prefix" \
Z23_UNIT_DIR="$HOME/.config/systemd/user" \
    "$stage/install_z23.sh" --source="$stage" >/dev/null
systemctl --user enable z23.service
# Do not inherit the unit's four-hour readiness timeout. The bounded
# qualification loop below owns the bootstrap deadline and cleanup.
systemctl --user start --no-block z23.service

want_node="$(sha256sum "$stage/zclassic23" | awk '{print $1}')"
want_z23="$(sha256sum "$stage/z23" | awk '{print $1}')"
want_verifier="$(sha256sum "$stage/zclassic23-package-verify" | awk '{print $1}')"
want_acme="$(sha256sum "$stage/zclassic23-acme" | awk '{print $1}')"
deadline=$(( $(date +%s) + health_seconds ))
qualified=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    pid="$(systemctl --user show z23.service -p MainPID --value 2>/dev/null || true)"
    case "$pid" in
        ''|*[!0-9]*|0) ;;
        *)
            running="$(sha256sum "/proc/$pid/exe" 2>/dev/null | awk '{print $1}' || true)"
            running_path="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
            installed_z23_path="$(readlink -f "$prefix/bin/z23" 2>/dev/null || true)"
            installed_z23="$(sha256sum "$prefix/bin/z23" 2>/dev/null | awk '{print $1}' || true)"
            installed_verifier="$(sha256sum "$prefix/bin/zclassic23-package-verify" 2>/dev/null | awk '{print $1}' || true)"
            installed_acme="$(sha256sum "$prefix/bin/zclassic23-acme" 2>/dev/null | awk '{print $1}' || true)"
            # The unit execs $prefix/bin/zclassic23, which install_z23.sh now
            # creates as a SYMLINK to z23 rather than a second 27.8 MB copy.
            # So /proc/<pid>/exe resolves to z23, and the old assertion that it
            # equalled the zclassic23 path could never pass again. Assert both
            # halves instead: the running image is the installed z23, AND the
            # name the unit actually execs resolves to that same file. That is
            # strictly more than the old check proved -- it now also proves the
            # alias points where it claims to.

            if [ "$running" = "$want_node" ] && \
               [ -n "$installed_z23_path" ] && \
               [ "$running_path" = "$installed_z23_path" ] && \
               [ "$(readlink -f "$prefix/bin/zclassic23" 2>/dev/null || true)" \
                 = "$installed_z23_path" ] && \
               [ "$installed_z23" = "$want_z23" ] && \
               [ "$installed_verifier" = "$want_verifier" ] && \
               [ -x "$prefix/bin/zclassic23-package-verify" ] && \
               [ "$installed_acme" = "$want_acme" ] && \
               [ -x "$prefix/bin/zclassic23-acme" ] && \
               timeout 20 "/proc/$pid/exe" status >/dev/null 2>&1; then
                pid_after="$(systemctl --user show z23.service -p MainPID --value 2>/dev/null || true)"
                running_after="$(sha256sum "/proc/$pid/exe" 2>/dev/null | awk '{print $1}' || true)"
                if [ "$pid_after" = "$pid" ] && [ "$running_after" = "$want_node" ]; then
                    qualified=1
                    break
                fi
            fi
            ;;
    esac
    sleep 2
done
[ "$qualified" -eq 1 ] || {
    echo "new z23.service failed exact process/status/verifier qualification" >&2
    exit 13
}
cleanup_armed=0
trap - EXIT HUP INT TERM
printf 'qualified manifest=%s pid=%s node_sha256=%s verifier_sha256=%s acme_sha256=%s\n' \
    "$manifest" "$pid" "$want_node" "$want_verifier" "$want_acme"
REMOTE_ACTIVATE
}

deploy_all() {
    local release_dir="$1" hosts="$2"
    local manifest installer_sha host prepared stage incoming result
    [ -n "$hosts" ] || die "no hosts: pass --hosts='host1 host2' or set Z23_RELEASE_HOSTS"
    verify_release "$release_dir"
    manifest="$(sha256sum "$release_dir/SHA256SUMS" | awk '{print $1}')"
    installer_sha="$(sha256sum "$INSTALLER" | awk '{print $1}')"
    say "release manifest $manifest"
    for host in $hosts; do
        case "$host" in *[!A-Za-z0-9._@-]*|'') die "invalid SSH host: $host" ;; esac
        say "$host: preflight"
        prepared="$(prepare_host "$host" "$manifest")" \
            || die "$host: fresh-node preflight failed"
        stage="$(printf '%s\n' "$prepared" | sed -n '1p')"
        incoming="$(printf '%s\n' "$prepared" | sed -n '2p')"
        [ -n "$stage" ] && [ -n "$incoming" ] \
            || die "$host: preflight returned invalid staging paths"
        if ! copy_release "$host" "$incoming" "$release_dir"; then
            discard_incoming "$host" "$incoming" "$manifest" || true
            die "$host: artifact transfer failed"
        fi
        result="$(activate_host "$host" "$incoming" "$stage" \
            "$manifest" "$installer_sha")" \
            || die "$host: activation failed; later hosts were not touched"
        say "$host: $result"
    done
    say "PASS hosts=$hosts manifest=$manifest"
}

selftest_make_release() {
    local tmp="$1"
    cat >"$tmp/node.c" <<'EOF'
#include <signal.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "status") == 0) return 0;
    for (;;) pause();
}
EOF
    cc -std=c23 -O0 "$tmp/node.c" -o "$tmp/release/z23"
    cp "$tmp/release/z23" "$tmp/release/zclassic23"
    printf '# card\n' >"$tmp/release/AGENT_CARD.md"
    printf '#!/bin/sh\nexit 0\n' >"$tmp/release/zclassic23-package-verify"
    chmod 755 "$tmp/release/zclassic23-package-verify"
    printf '#!/bin/sh\nexit 0\n' >"$tmp/release/zclassic23-acme"
    chmod 755 "$tmp/release/zclassic23-acme"
    (cd "$tmp/release" && \
        sha256sum AGENT_CARD.md z23 zclassic23 zclassic23-package-verify \
            zclassic23-acme >SHA256SUMS)
}

selftest_make_ssh_mock() {
    local tmp="$1"
    cat >"$tmp/mockbin/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
while [ "${1:-}" = -o ]; do shift 2; done
host="$1"; shift
home="$Z23_DEPLOY_TEST_ROOT/hosts/$host"
mkdir -p "$home"
printf 'ssh %s %s\n' "$host" "$*" >>"$Z23_DEPLOY_TEST_ROOT/transport.log"
HOME="$home" Z23_DEPLOY_TEST_HOST="$host" \
PATH="$Z23_DEPLOY_TEST_ROOT/mockbin:$PATH" "$@"
EOF
}

selftest_make_systemctl_mock() {
    local tmp="$1"
    cat >"$tmp/mockbin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" != --user ] || shift
cmd="${1:-}"; shift || true
printf 'systemctl %s %s %s\n' "$Z23_DEPLOY_TEST_HOST" "$cmd" "$*" \
    >>"$Z23_DEPLOY_TEST_ROOT/systemctl.log"
case "$cmd" in
    is-active)
        [ ! -e "$HOME/canonical-active" ] || exit 0
        exit 3
        ;;
    cat)
        [ -f "$HOME/.config/systemd/user/z23.service" ] || exit 1
        cat "$HOME/.config/systemd/user/z23.service"
        ;;
    daemon-reload) ;;
    enable) ;;
    start)
        [ "${Z23_DEPLOY_TEST_FAIL_HOST:-}" != "$Z23_DEPLOY_TEST_HOST" ] || exit 1
        "$HOME/.local/bin/zclassic23" >/dev/null 2>&1 &
        printf '%s\n' "$!" >"$HOME/z23.pid"
        ;;
    show)
        [ -s "$HOME/z23.pid" ] || exit 1
        cat "$HOME/z23.pid"
        ;;
    disable)
        if [ -s "$HOME/z23.pid" ]; then
            kill "$(cat "$HOME/z23.pid")" 2>/dev/null || true
        fi
        ;;
    *) exit 2 ;;
esac
EOF
}

selftest_make_fixtures() {
    local tmp="$1"
    mkdir -p "$tmp/release" "$tmp/mockbin" "$tmp/hosts"
    selftest_make_release "$tmp"
    selftest_make_ssh_mock "$tmp"
    selftest_make_systemctl_mock "$tmp"
    chmod 755 "$tmp/mockbin/ssh" "$tmp/mockbin/systemctl"
}

SELFTEST_TMP=""

selftest_run_deploy() {
    Z23_DEPLOY_TEST_ROOT="$SELFTEST_TMP" \
    Z23_DEPLOY_TEST_FAIL_HOST="${Z23_DEPLOY_TEST_FAIL_HOST:-}" \
    Z23_DEPLOY_SSH="$SELFTEST_TMP/mockbin/ssh" \
    Z23_RELEASE_HEALTH_SECONDS=5 \
        "$0" --release-dir="$SELFTEST_TMP/release" --hosts="$1"
}

selftest_assert_success() {
    local tmp="$1" manifest host stage alpha_line beta_line transfer_count
    : >"$tmp/transport.log"; : >"$tmp/systemctl.log"
    selftest_run_deploy "alpha beta" >/dev/null
    manifest="$(sha256sum "$tmp/release/SHA256SUMS" | awk '{print $1}')"
    for host in alpha beta; do
        stage="$tmp/hosts/$host/.cache/z23/releases/$manifest"
        (cd "$stage" && sha256sum -c --strict SHA256SUMS >/dev/null)
        cmp -s "$stage/zclassic23" "$tmp/hosts/$host/.local/bin/zclassic23"
        cmp -s "$stage/zclassic23-package-verify" \
            "$tmp/hosts/$host/.local/bin/zclassic23-package-verify"
        cmp -s "$stage/zclassic23-acme" \
            "$tmp/hosts/$host/.local/bin/zclassic23-acme"
    done
    alpha_line="$(grep -n 'systemctl alpha start' "$tmp/systemctl.log" | cut -d: -f1)"
    beta_line="$(grep -n 'systemctl beta start' "$tmp/systemctl.log" | cut -d: -f1)"
    [ "$alpha_line" -lt "$beta_line" ] \
        || die "selftest: hosts were not activated sequentially"
    transfer_count="$(awk -v manifest="$manifest" \
        '$1 == "ssh" && $3 == "tar" && index($0, manifest) \
            { count++ } END { print count + 0 }' \
        "$tmp/transport.log")"
    [ "$transfer_count" -eq 2 ] \
        || die "selftest: each host did not receive one manifest-addressed archive stream"
    ! grep -q '^scp ' "$tmp/transport.log" \
        || die "selftest: release transfer opened per-file scp sessions"
    ! grep -Eq '(^| )(make|cc)( |$)' "$tmp/transport.log" \
        || die "selftest: remote build command observed"
}

selftest_assert_failures() {
    local tmp="$1"
    : >"$tmp/transport.log"; : >"$tmp/systemctl.log"
    if Z23_DEPLOY_TEST_FAIL_HOST=fail selftest_run_deploy "fail never" >/dev/null 2>&1; then
        die "selftest: injected first-host activation failure passed"
    fi
    ! grep -q ' never ' "$tmp/transport.log" \
        || die "selftest: later host was touched after first failure"
    [ ! -e "$tmp/hosts/fail/.config/systemd/user/z23.service" ] \
        || die "selftest: failed fresh activation left its unit installed"
    mkdir -p "$tmp/hosts/active"
    : >"$tmp/hosts/active/canonical-active"
    ! selftest_run_deploy active >/dev/null 2>&1 \
        || die "selftest: active zclassic23.service was not refused"
    mkdir -p "$tmp/hosts/existing/.config/systemd/user"
    : >"$tmp/hosts/existing/.config/systemd/user/z23.service"
    ! selftest_run_deploy existing >/dev/null 2>&1 \
        || die "selftest: pre-existing z23.service was not refused"
}

selftest_assert_cleanup_guard() {
    local tmp="$1" manifest old_ssh unsafe wrong valid
    manifest="$(sha256sum "$tmp/release/SHA256SUMS" | awk '{print $1}')"
    old_ssh="$SSH_BIN"; SSH_BIN="$tmp/mockbin/ssh"
    export Z23_DEPLOY_TEST_ROOT="$tmp"
    unsafe="$tmp/hosts/unsafe/do-not-delete"
    wrong="$tmp/hosts/unsafe/.cache/z23/releases/.incoming-wrong-123"
    valid="$tmp/hosts/unsafe/.cache/z23/releases/.incoming-$manifest-123"
    mkdir -p "$unsafe" "$wrong" "$valid"
    : >"$unsafe/sentinel"; : >"$wrong/sentinel"; : >"$valid/payload"
    ! discard_incoming unsafe "$unsafe" "$manifest" >/dev/null 2>&1 \
        || die "selftest: cleanup accepted a path outside the release cache"
    [ -f "$unsafe/sentinel" ] || die "selftest: unsafe cleanup deleted outside data"
    ! discard_incoming unsafe "$wrong" "$manifest" >/dev/null 2>&1 \
        || die "selftest: cleanup accepted a different manifest path"
    [ -f "$wrong/sentinel" ] || die "selftest: wrong-manifest cleanup deleted data"
    discard_incoming unsafe "$valid" "$manifest" >/dev/null
    [ ! -e "$valid" ] || die "selftest: valid incoming cleanup left data"
    SSH_BIN="$old_ssh"
    unset Z23_DEPLOY_TEST_ROOT
}

selftest_stop_nodes() {
    local tmp="$1" host
    for host in alpha beta; do
        if [ -s "$tmp/hosts/$host/z23.pid" ]; then
            kill "$(cat "$tmp/hosts/$host/z23.pid")" 2>/dev/null || true
        fi
    done
}

selftest_cleanup() {
    case "${SELFTEST_TMP:-}" in
        /tmp/z23-release-deploy-selftest.*)
            find "$SELFTEST_TMP" -depth -delete 2>/dev/null || true ;;
    esac
}

selftest() {
    local tmp
    tmp="$(mktemp -d /tmp/z23-release-deploy-selftest.XXXXXX)" \
        || die "selftest: mktemp failed"
    SELFTEST_TMP="$tmp"
    trap selftest_cleanup EXIT
    selftest_make_fixtures "$tmp"
    if [ ! -e /proc/self/exe ]; then
        selftest_assert_cleanup_guard "$tmp"
        say "UNOBSERVED Linux process-image activation: /proc/self/exe is unavailable"
        say "selftest PARTIAL (cleanup refusal/ownership guard PASS)"
        trap - EXIT
        selftest_cleanup
        SELFTEST_TMP=""
        return 0
    fi
    selftest_assert_success "$tmp"
    selftest_assert_failures "$tmp"
    selftest_assert_cleanup_guard "$tmp"
    selftest_stop_nodes "$tmp"
    say "selftest PASS"
    trap - EXIT
    selftest_cleanup
    SELFTEST_TMP=""
}

# One vocabulary for platform names. build_release.sh now packages more than
# one target and names each directory by the SAME platform string the install
# front doors use (packaging/install/install.sh's PUBLISHED_PLATFORMS), so
# there is no second spelling of x86-64 Linux to keep in sync with the first.
# This deployer stays Linux-only: it installs a systemd user unit.
RELEASE_DIR="$REPO_ROOT/build/release/z23-linux-x86_64"
HOSTS="${Z23_RELEASE_HOSTS:-}"
while [ $# -gt 0 ]; do
    case "$1" in
        --selftest) selftest; exit 0 ;;
        --release-dir=*) RELEASE_DIR="${1#*=}"; shift ;;
        --release-dir) [ $# -ge 2 ] || die "--release-dir needs a path"; RELEASE_DIR="$2"; shift 2 ;;
        --hosts=*) HOSTS="${1#*=}"; shift ;;
        --hosts) [ $# -ge 2 ] || die "--hosts needs a list"; HOSTS="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

deploy_all "$RELEASE_DIR" "$HOSTS"
