#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# install_selftest.sh — mutation tests for the front door (install.sh).
#
# It lives OUT of install.sh on purpose: that script is served at the domain
# and has to stay short enough that a careful person reads it before handing
# it to a shell, so no test code ships in the bytes a stranger reads.
#
# Every verification the front door performs is exercised in BOTH directions:
# the agreeing case installs, and each way of breaking agreement refuses
# without the fetched installer ever being executed. Run from
# `tools/scripts/install_z23.sh --selftest`, which the check-z23-release-install
# lint gate already runs.
#
# Status-carrying matches use `grep -q PATTERN FILE` (a file argument, not a
# pipeline), so nothing here can invert on SIGPIPE under pipefail.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONT_DOOR="$SCRIPT_DIR/install.sh"

die() { printf 'install_selftest: FAIL: %s\n' "$*" >&2; exit 1; }
say() { printf 'install_selftest: %s\n' "$*" >&2; }

ROOT=""
cleanup() { [ -z "$ROOT" ] || rm -rf "$ROOT"; }

MANIFEST_SHA=1234567812345678123456781234567812345678123456781234567812345678
OTHER_SHA=fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98

prepare() {
    ROOT="$(mktemp -d "${TMPDIR:-/tmp}/z23-front-door-selftest.XXXXXX")" \
        || die "mktemp failed"
    trap cleanup EXIT
    mkdir -p "$ROOT/http/front" "$ROOT/http/repo" "$ROOT/minbin" \
        "$ROOT/dnsbin" "$ROOT/unamebin" "$ROOT/dns"

    # The real installer is never run here: a stub records the argv it was
    # handed, which is how the handoff (source, manifest digest, and one
    # attestation record per source) is proved.
    cat >"$ROOT/http/front/install_z23.sh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$Z23_FD_TEST_ARGV_LOG"
STUB
    INSTALLER_SHA="$(sha256sum "$ROOT/http/front/install_z23.sh" | cut -d' ' -f1)"
    GOOD_PIN="z23-pin-v1:$MANIFEST_SHA:$INSTALLER_SHA"
    OTHER_PIN="z23-pin-v1:$OTHER_SHA:$INSTALLER_SHA"

    printf '%s\n' "$GOOD_PIN" >"$ROOT/http/repo/RELEASE_PIN"
    printf '%s\n' "$OTHER_PIN" >"$ROOT/http/repo/RELEASE_PIN.other"
    printf '<html>404</html>\n' >"$ROOT/http/repo/RELEASE_PIN.html"
    ZERO_PIN="z23-pin-v1:$(printf '0%.0s' {1..64}):$(printf '0%.0s' {1..64})"
    printf '%s\n' "$ZERO_PIN" >"$ROOT/http/repo/RELEASE_PIN.unset"
    printf '"%s"\n' "$GOOD_PIN" >"$ROOT/dns/good"
    printf '"%s"\n' "$OTHER_PIN" >"$ROOT/dns/other"
    printf '"this-domain-is-parked"\n' >"$ROOT/dns/portal"

    # A deliberately minimal PATH: exactly the commands install.sh may use on
    # a bare machine. Nothing else is reachable, so "no DNS tool present" is
    # a real condition here and not a mocked one.
    local tool
    for tool in sh bash uname mktemp rm cp cat sed cut wc sha256sum; do
        ln -sf "$(command -v "$tool")" "$ROOT/minbin/$tool"
    done

    cat >"$ROOT/minbin/curl" <<'MOCKCURL'
#!/usr/bin/env bash
set -euo pipefail
[ "$#" -eq 10 ] || exit 2
[ "$1" = --connect-timeout ] && [ "$3" = --max-time ] || exit 2
[ "$5" = --max-filesize ] && [ "$7" = -fsSL ] && [ "$9" = -o ] || exit 2
max_bytes="$6"; url="$8"; dest="${10}"
printf '%s max-bytes=%s\n' "$url" "$max_bytes" >>"$Z23_FD_TEST_CURL_LOG"
case "$url" in
    https://front.invalid/install_z23.sh)
        path="$Z23_FD_TEST_HTTP/front/${Z23_FD_TEST_INSTALLER:-install_z23.sh}" ;;
    https://repo.invalid/RELEASE_PIN)
        [ -n "${Z23_FD_TEST_REPO_PIN:-}" ] || exit 7
        path="$Z23_FD_TEST_HTTP/repo/$Z23_FD_TEST_REPO_PIN" ;;
    *) exit 22 ;;
esac
[ -f "$path" ] || exit 22
[ "$(wc -c <"$path")" -le "$max_bytes" ] || exit 63
cp -- "$path" "$dest"
MOCKCURL
    chmod 755 "$ROOT/minbin/curl"

    cat >"$ROOT/dnsbin/dig" <<'MOCKDIG'
#!/usr/bin/env bash
set -euo pipefail
[ -n "${Z23_FD_TEST_DNS:-}" ] || exit 9
cat "$Z23_FD_TEST_DNS"
MOCKDIG
    chmod 755 "$ROOT/dnsbin/dig"

    cat >"$ROOT/unamebin/uname" <<'MOCKUNAME'
#!/usr/bin/env bash
case "${1:-}" in -s) echo Darwin ;; -m) echo arm64 ;; *) echo Darwin ;; esac
MOCKUNAME
    chmod 755 "$ROOT/unamebin/uname"
}

# run <case> <path-prefix> [env assignments...] — runs the front door with a
# controlled PATH and returns its exit status in RC, with stdout/stderr and
# the argv/curl logs captured per case.
RC=0
run() {
    local name="$1" path_prefix="$2"
    shift 2
    OUT="$ROOT/$name.out"; ERR="$ROOT/$name.err"
    ARGV="$ROOT/$name.argv"; CURL="$ROOT/$name.curl"
    rm -f "$ARGV"
    : >"$CURL"
    RC=0
    env -i PATH="$path_prefix$ROOT/minbin" HOME="$ROOT" \
        TMPDIR="$ROOT" \
        Z23_FD_TEST_HTTP="$ROOT/http" \
        Z23_FD_TEST_ARGV_LOG="$ARGV" \
        Z23_FD_TEST_CURL_LOG="$CURL" \
        Z23_INSTALL_TEST_ORIGIN=https://front.invalid \
        Z23_INSTALL_TEST_PIN_DNS=_z23-pin.front.invalid \
        Z23_INSTALL_TEST_PIN_REPO_URL=https://repo.invalid/RELEASE_PIN \
        "$@" \
        sh "$FRONT_DOOR" >"$OUT" 2>"$ERR" || RC=$?
}

# ── Direction 1: everything agrees, and the handoff carries the evidence ──
case_all_agree() {
    run all-agree "$ROOT/dnsbin:" \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_FD_TEST_DNS="$ROOT/dns/good" \
        Z23_FD_TEST_REPO_PIN=RELEASE_PIN
    [ "$RC" -eq 0 ] || die "three agreeing sources must install (rc=$RC): $(cat "$ERR")"
    [ -f "$ARGV" ] || die "three agreeing sources never reached the installer"
    grep -qx -- "--manifest-sha256=$MANIFEST_SHA" "$ARGV" \
        || die "the agreed manifest digest was not handed to the installer"
    grep -qx -- "--source=https://front.invalid/release/linux-x86_64" "$ARGV" \
        || die "the release source was not handed to the installer"
    local origin
    for origin in baked dns repo; do
        grep -qx -- "--attest=$origin=$GOOD_PIN" "$ARGV" \
            || die "attestation for $origin was not passed through"
    done
    grep -q 'install_z23.sh max-bytes=262144' "$CURL" \
        || die "the installer fetch was not bounded"
    say "PASS all three sources agree -> installs, evidence passed through"
}

# ── Direction 2: one source disagrees. Never a majority vote. ─────────────
case_dns_disagrees() {
    run dns-split "$ROOT/dnsbin:" \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_FD_TEST_DNS="$ROOT/dns/other" \
        Z23_FD_TEST_REPO_PIN=RELEASE_PIN
    [ "$RC" -eq 1 ] || die "a disagreeing DNS record must refuse (rc=$RC)"
    grep -q 'release pin disagreement between baked and dns' "$ERR" \
        || die "the disagreement must name both origins"
    [ ! -f "$ARGV" ] || die "a disagreement still ran the installer"
    if grep -q 'install_z23.sh' "$CURL"; then
        die "a disagreement still downloaded the installer"
    fi

    run repo-split "$ROOT/dnsbin:" \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_FD_TEST_DNS="$ROOT/dns/good" \
        Z23_FD_TEST_REPO_PIN=RELEASE_PIN.other
    [ "$RC" -eq 1 ] || die "a disagreeing repository pin must refuse (rc=$RC)"
    grep -q 'release pin disagreement between baked and repo' "$ERR" \
        || die "the repository disagreement must name both origins"
    [ ! -f "$ARGV" ] || die "a repository disagreement still ran the installer"
    say "PASS one dissenting source -> refuses, 2-against-1 never wins"
}

# ── Unreachable is not disagreement, and two is the floor ─────────────────
case_unreachable() {
    # No dig, no host, no nslookup anywhere on PATH. Baked + repository still
    # carry a quorum, and the refusal-free path says so out loud.
    run no-dns-tool "" \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_FD_TEST_REPO_PIN=RELEASE_PIN
    [ "$RC" -eq 0 ] || die "two agreeing sources must install (rc=$RC): $(cat "$ERR")"
    grep -q 'agreed by 2 of 3 sources (unreachable: dns=no-dns-tool)' "$ERR" \
        || die "a degraded quorum must be announced"
    grep -qx -- '--attest-unreachable=dns=no-dns-tool' "$ARGV" \
        || die "the unreachable source must be declared to the installer"

    # A captive portal answers with something that is not a pin. That is
    # unreachable, NOT a disagreement.
    run portal "$ROOT/dnsbin:" \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_FD_TEST_DNS="$ROOT/dns/portal" \
        Z23_FD_TEST_REPO_PIN=RELEASE_PIN
    [ "$RC" -eq 0 ] || die "a portal TXT answer must not break a real quorum"
    grep -q 'unreachable: dns=malformed-answer' "$ERR" \
        || die "a non-pin TXT answer must be reported as malformed"
    if grep -q 'disagreement' "$ERR"; then
        die "a non-pin TXT answer was reported as a disagreement"
    fi

    # An HTML error page from the repository host is the same class.
    run repo-html "" \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_FD_TEST_REPO_PIN=RELEASE_PIN.html
    [ "$RC" -eq 1 ] || die "baked alone must not install (rc=$RC)"
    grep -q 'release pin quorum: 1 of 3 sources answered' "$ERR" \
        || die "a single answering source must be refused by count"
    grep -q 'repo=malformed-answer' "$ERR" \
        || die "an HTML answer must be reported as malformed"

    # Nothing reachable but the baked value: still a refusal, never a silent
    # degradation to one source.
    run alone "" Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN"
    [ "$RC" -eq 1 ] || die "one source must never be enough (rc=$RC)"
    grep -q 'two independent sources are required' "$ERR" \
        || die "the quorum refusal must state the requirement"
    grep -q 'repo=fetch-failed' "$ERR" \
        || die "an unreachable repository must be named with its reason"
    [ ! -f "$ARGV" ] || die "a failed quorum still ran the installer"

    # No release pinned into these bytes at all: the sentinel is a missing
    # source, not a pin, and DNS + repository carry the quorum without it.
    run unpinned "$ROOT/dnsbin:" \
        Z23_FD_TEST_DNS="$ROOT/dns/good" \
        Z23_FD_TEST_REPO_PIN=RELEASE_PIN
    [ "$RC" -eq 0 ] || die "dns+repo must carry a quorum without a baked pin"
    grep -q 'unreachable: baked=no-release-pinned' "$ERR" \
        || die "an unpinned script must say so"
    # Before the first release is cut, the repository file carries the unset
    # sentinel. That is "nothing is pinned here", not a dissenting pin.
    run repo-unset "$ROOT/dnsbin:" \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_FD_TEST_DNS="$ROOT/dns/good" \
        Z23_FD_TEST_REPO_PIN=RELEASE_PIN.unset
    [ "$RC" -eq 0 ] || die "an unset repository pin must not break a real quorum"
    grep -q 'unreachable: repo=malformed-answer' "$ERR" \
        || die "the unset sentinel must be reported as no pin"
    if grep -q 'disagreement' "$ERR"; then
        die "the unset sentinel was reported as a disagreement"
    fi

    # The checked-in repository pin must always be a well-formed pin record,
    # sentinel or real, or source 3 is dead the moment a release lands.
    grep -qxE 'z23-pin-v1:[0-9a-f]{64}:[0-9a-f]{64}' "$SCRIPT_DIR/RELEASE_PIN" \
        || die "packaging/install/RELEASE_PIN is not a z23-pin-v1 record"
    say "PASS unreachable is counted, named, and never called disagreement"
}

# ── The installer's own bytes are pinned too ──────────────────────────────
case_installer_digest() {
    printf '#!/bin/sh\ntouch "$Z23_FD_TEST_ARGV_LOG"\n' \
        >"$ROOT/http/front/tampered.sh"
    run tampered-installer "$ROOT/dnsbin:" \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_FD_TEST_DNS="$ROOT/dns/good" \
        Z23_FD_TEST_REPO_PIN=RELEASE_PIN \
        Z23_FD_TEST_INSTALLER=tampered.sh
    [ "$RC" -eq 1 ] || die "a swapped installer must refuse (rc=$RC)"
    grep -q 'installer digest mismatch' "$ERR" \
        || die "a swapped installer must name the digest mismatch"
    [ ! -f "$ARGV" ] || die "a swapped installer was executed anyway"
    say "PASS the served installer is verified before it runs"
}

# ── A machine we do not publish for is told so, by name ───────────────────
case_platform() {
    run unpublished "$ROOT/unamebin:$ROOT/dnsbin:" \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_FD_TEST_DNS="$ROOT/dns/good" \
        Z23_FD_TEST_REPO_PIN=RELEASE_PIN
    [ "$RC" -eq 1 ] || die "an unpublished platform must refuse (rc=$RC)"
    grep -q 'no Z23 runtime is published for darwin-aarch64' "$ERR" \
        || die "the refusal must name this machine"
    grep -q 'published: linux-x86_64' "$ERR" \
        || die "the refusal must name what we do publish"
    if [ -s "$CURL" ]; then
        die "an unpublished platform still made a request"
    fi
    say "PASS an unpublished platform is refused by name, before any request"
}

prepare
case_all_agree
case_dns_disagrees
case_unreachable
case_installer_digest
case_platform
say "front door selftest PASS"
