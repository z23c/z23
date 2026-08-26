#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# install_z23.sh — fetch a packaged Z23 runtime set, verify SHA256SUMS
# fail-closed, install to ~/.local/bin, write a systemd --user unit, and print
# ONE next command.
#
# Artifact source is taken from the first argument or Z23_RELEASE_SOURCE
# (a node URL or a local directory). Never hardcoded: any node that serves
# z23, zclassic23, zclassic23-package-verify, and SHA256SUMS is a valid source.
# There is no registry.
#
# Checksum mismatch is a loud refusal. Nothing is copied to the destination
# until SHA256SUMS --strict passes.
#
# Usage:
#   install_z23.sh --source=<url> --manifest-sha256=<sha256-of-SHA256SUMS>
#   install_z23.sh --source=<local-dir>
#   install_z23.sh <url> --manifest-sha256=<sha256-of-SHA256SUMS>
#   install_z23.sh <local-dir>
#   Z23_RELEASE_SOURCE=<url> Z23_RELEASE_MANIFEST_SHA256=<sha256> install_z23.sh
#   Z23_RELEASE_SOURCE=<local-dir> install_z23.sh
#   install_z23.sh --selftest
#
# Env:
#   Z23_RELEASE_MANIFEST_SHA256
#                        expected SHA-256 of a remote SHA256SUMS (required
#                        for http(s); obtain independently of the mirror)
#   Z23_INSTALL_PREFIX   default $HOME/.local
#   Z23_UNIT_DIR         default $HOME/.config/systemd/user
#   Z23_SKIP_SYSTEMD=1   skip unit install (tests)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { printf 'install_z23: REFUSE: %s\n' "$*" >&2; exit 1; }
say() { printf 'install_z23: %s\n' "$*" >&2; }

NEXT_COMMAND="z23 status"

# Public fetch ceilings. The manifest has exactly three short checksum rows;
# 1 KiB leaves ample format headroom. Node aliases are currently below 32 MiB
# and the confined verifier below 96 MiB; these limits allow growth without
# permitting an untrusted mirror to stream without bound. Deadlines apply to
# every HTTP transaction independently.
REMOTE_MANIFEST_MAX_BYTES=1024
REMOTE_NODE_MAX_BYTES=$((64 * 1024 * 1024))
REMOTE_VERIFIER_MAX_BYTES=$((128 * 1024 * 1024))
REMOTE_CONNECT_TIMEOUT_SECONDS=10
REMOTE_MANIFEST_MAX_TIME_SECONDS=30
REMOTE_PAYLOAD_MAX_TIME_SECONDS=300
CURL_MINIMUM_VERSION="8.4.0"

INSTALL_STAGE=""
INSTALL_STAGE_PARENT=""

cleanup_install_stage() {
    [ -n "$INSTALL_STAGE" ] || return 0
    case "$INSTALL_STAGE" in
        "$INSTALL_STAGE_PARENT"/zcl-install-z23.??????) ;;
        *)
            printf 'install_z23: REFUSE: internal cleanup path escaped the install staging directory\n' >&2
            return 1
            ;;
    esac
    [ ! -e "$INSTALL_STAGE" ] \
        || find "$INSTALL_STAGE" -xdev -depth -delete
    INSTALL_STAGE=""
}

payload_max_bytes() {
    case "$1" in
        z23|zclassic23) printf '%s\n' "$REMOTE_NODE_MAX_BYTES" ;;
        zclassic23-package-verify) printf '%s\n' "$REMOTE_VERIFIER_MAX_BYTES" ;;
        *) return 1 ;;
    esac
}

validate_manifest_contract() {
    local manifest="$1" bytes lines matching names
    [ -f "$manifest" ] || die "SHA256SUMS missing after fetch"
    bytes="$(wc -c <"$manifest" | tr -d ' ')"
    [ "$bytes" -le "$REMOTE_MANIFEST_MAX_BYTES" ] \
        || die "SHA256SUMS exceeds $REMOTE_MANIFEST_MAX_BYTES bytes"
    lines="$(wc -l <"$manifest" | tr -d ' ')"
    matching="$(LC_ALL=C grep -Ec \
        '^[0-9a-f]{64}  (z23|zclassic23|zclassic23-package-verify)$' \
        "$manifest" || true)"
    [ "$lines" -eq 3 ] && [ "$matching" -eq 3 ] \
        || die "SHA256SUMS must contain exactly three strict lowercase SHA-256 rows"
    names="$(awk '{print $2}' "$manifest" | LC_ALL=C sort)"
    [ "$names" = $'z23\nzclassic23\nzclassic23-package-verify' ] \
        || die "SHA256SUMS must name each required payload exactly once"
}

validate_payload_sizes() {
    local dir="$1" name bytes maximum
    for name in z23 zclassic23 zclassic23-package-verify; do
        [ -f "$dir/$name" ] || die "verified payload missing $name"
        maximum="$(payload_max_bytes "$name")"
        bytes="$(wc -c <"$dir/$name" | tr -d ' ')"
        [ "$bytes" -le "$maximum" ] \
            || die "$name exceeds its $maximum-byte release ceiling"
    done
}

curl_bounded() {
    local url="$1" dest="$2" maximum_bytes="$3" maximum_seconds="$4"
    curl --connect-timeout "$REMOTE_CONNECT_TIMEOUT_SECONDS" \
        --max-time "$maximum_seconds" --max-filesize "$maximum_bytes" \
        -fsSL "$url" -o "$dest"
}

require_bounded_curl() {
    local first version major minor
    first="$(curl --version 2>/dev/null | sed -n '1p')" \
        || die "curl $CURL_MINIMUM_VERSION or newer is required for bounded remote fetches"
    version="${first#curl }"
    [ "$version" != "$first" ] || die "could not parse curl version; $CURL_MINIMUM_VERSION or newer is required"
    version="${version%% *}"
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "could not parse curl version '$version'; $CURL_MINIMUM_VERSION or newer is required"
    IFS=. read -r major minor _ <<<"$version"
    if [ "$major" -lt 8 ] || { [ "$major" -eq 8 ] && [ "$minor" -lt 4 ]; }; then
        die "curl $version is too old; $CURL_MINIMUM_VERSION or newer is required for bounded remote fetches"
    fi
}

fetch_into() {
    local src="$1" dest="$2" expected_manifest_sha256="$3"
    mkdir -p "$dest"
    case "$src" in
        http://*|https://*)
            case "$expected_manifest_sha256" in
                ''|*[!0-9a-f]*)
                    die "remote source requires --manifest-sha256=<64 lowercase hex>, obtained independently of the mirror"
                    ;;
            esac
            [ "${#expected_manifest_sha256}" -eq 64 ] \
                || die "remote source requires --manifest-sha256=<64 lowercase hex>, obtained independently of the mirror"
            command -v curl >/dev/null 2>&1 || die "curl is required to fetch $src"
            require_bounded_curl
            curl_bounded "$src/SHA256SUMS" "$dest/SHA256SUMS" \
                "$REMOTE_MANIFEST_MAX_BYTES" \
                "$REMOTE_MANIFEST_MAX_TIME_SECONDS" \
                || die "could not fetch $src/SHA256SUMS"
            [ -s "$dest/SHA256SUMS" ] || die "empty SHA256SUMS from $src"
            local got_manifest_sha256 name
            got_manifest_sha256="$(sha256sum "$dest/SHA256SUMS" | awk '{print $1}')"
            [ "$got_manifest_sha256" = "$expected_manifest_sha256" ] \
                || die "remote SHA256SUMS digest mismatch — refusing to fetch payloads"
            validate_manifest_contract "$dest/SHA256SUMS"
            while read -r _ name; do
                curl_bounded "$src/$name" "$dest/$name" \
                    "$(payload_max_bytes "$name")" \
                    "$REMOTE_PAYLOAD_MAX_TIME_SECONDS" \
                    || die "could not fetch $src/$name"
            done <"$dest/SHA256SUMS"
            ;;
        *)
            [ -d "$src" ] || die "source is not a directory or http(s) URL: $src"
            [ -f "$src/SHA256SUMS" ] || die "SHA256SUMS missing in $src"
            cp -f -- "$src/SHA256SUMS" "$dest/SHA256SUMS"
            validate_manifest_contract "$dest/SHA256SUMS"
            local name
            while read -r _ name; do
                [ -f "$src/$name" ] || die "listed file missing: $src/$name"
                cp -f -- "$src/$name" "$dest/$name"
            done <"$dest/SHA256SUMS"
            ;;
    esac
}

verify_strict() {
    local dir="$1"
    validate_payload_sizes "$dir"
    (cd "$dir" && sha256sum -c --strict SHA256SUMS >/dev/null) \
        || die "SHA256SUMS mismatch — refusing to install"
}

install_payload() {
    local stage="$1" prefix="$2"
    local bindir="$prefix/bin"
    mkdir -p "$bindir"
    [ -f "$stage/z23" ] || die "verified payload missing z23"
    [ -f "$stage/zclassic23" ] || die "verified payload missing zclassic23"
    [ -f "$stage/zclassic23-package-verify" ] \
        || die "verified payload missing zclassic23-package-verify"
    install -m 755 "$stage/z23" "$bindir/z23"
    install -m 755 "$stage/zclassic23" "$bindir/zclassic23"
    install -m 755 "$stage/zclassic23-package-verify" \
        "$bindir/zclassic23-package-verify"
}

write_unit() {
    local prefix="$1" unit_dir="$2"
    local bin="$prefix/bin/zclassic23"
    mkdir -p "$unit_dir"
    # z23.service — never overwrite the production zclassic23.service.
    cat >"$unit_dir/z23.service" <<EOF
[Unit]
Description=Z23 node
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
# First-boot onion: -tor -onion-persist so a stranger is reachable, and
# Type=notify holds activating until READY=1. READY waits for onion
# DESCRIPTOR PUBLICATION (not hostname-only) so cold-boot clients do not
# dial before HSDirs have the descriptor.
ExecStart=$bin -datadir=%h/.zclassic-c23 -listen -tor -onion-persist
# Restart=always (not on-failure): a new node clean-exits once to install the
# checkpoint bundle (install-on-next-boot). on-failure would drop that boot.
Restart=always
RestartSec=5
TimeoutStartSec=14400
NotifyAccess=main

[Install]
WantedBy=default.target
EOF
    if [ "${Z23_SKIP_SYSTEMD:-0}" != "1" ]; then
        systemctl --user daemon-reload 2>/dev/null || true
    fi
}

install_from_source() {
    local src="$1" expected_manifest_sha256="$2"
    [ -n "$src" ] || die "no source: pass --source=<url-or-dir> or set Z23_RELEASE_SOURCE"
    local prefix="${Z23_INSTALL_PREFIX:-$HOME/.local}"
    local unit_dir="${Z23_UNIT_DIR:-$HOME/.config/systemd/user}"
    local install_tmp="${TMPDIR:-/tmp}"
    [ -d "$install_tmp" ] || die "temporary directory does not exist: $install_tmp"
    INSTALL_STAGE_PARENT="$(cd "$install_tmp" && pwd -P)"
    INSTALL_STAGE="$(mktemp -d "$INSTALL_STAGE_PARENT/zcl-install-z23.XXXXXX")" \
        || die "mktemp failed"
    trap 'cleanup_install_stage' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    fetch_into "$src" "$INSTALL_STAGE" "$expected_manifest_sha256"
    verify_strict "$INSTALL_STAGE"
    install_payload "$INSTALL_STAGE" "$prefix"
    cleanup_install_stage
    trap - EXIT HUP INT TERM
    if [ "${Z23_SKIP_SYSTEMD:-0}" != "1" ]; then
        write_unit "$prefix" "$unit_dir"
    fi
    say "installed $prefix/bin/z23"
    printf '%s\n' "$NEXT_COMMAND"
}

run_install() {
    # Drive the shipped entry point in a child so die()/exit is the real path.
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$1" Z23_UNIT_DIR="$2" \
        "$SCRIPT_DIR/install_z23.sh" --source="$3"
}

SELFTEST_TMP=""
SELFTEST_MANIFEST_SHA=""

selftest_prepare() {
    local tmp
    tmp="$(mktemp -d /tmp/zcl-install-z23-selftest.XXXXXX)" || die "mktemp failed"
    SELFTEST_TMP="$tmp"
    trap 'rm -rf "$SELFTEST_TMP"' EXIT

    mkdir -p "$tmp/good" "$tmp/bad" "$tmp/prefix" "$tmp/units" \
        "$tmp/stages"
    export TMPDIR="$tmp/stages"

    printf 'payload-a\n' >"$tmp/good/z23"
    printf 'payload-a\n' >"$tmp/good/zclassic23"
    printf 'confined-verifier\n' >"$tmp/good/zclassic23-package-verify"
    (cd "$tmp/good" && \
        sha256sum z23 zclassic23 zclassic23-package-verify >SHA256SUMS)

    # Shell-only curl fixture: map https://mirror.invalid/<path> into the
    # selftest tree and record every requested object. This proves a bad
    # manifest pin is rejected before any executable payload is downloaded.
    mkdir -p "$tmp/mockbin" "$tmp/http/good" "$tmp/http/replaced" \
        "$tmp/http/oversized" "$tmp/http/oversized-payload" \
        "$tmp/http/duplicate" "$tmp/http/malformed" "$tmp/http/signal"
    cp -f -- "$tmp/good/"* "$tmp/http/good/"
    cp -f -- "$tmp/good/"* "$tmp/http/signal/"
    printf 'replacement-node\n' >"$tmp/http/replaced/z23"
    printf 'replacement-node\n' >"$tmp/http/replaced/zclassic23"
    printf 'replacement-verifier\n' \
        >"$tmp/http/replaced/zclassic23-package-verify"
    (cd "$tmp/http/replaced" && \
        sha256sum z23 zclassic23 zclassic23-package-verify >SHA256SUMS)
    dd if=/dev/zero bs=1025 count=1 2>/dev/null | tr '\0' x \
        >"$tmp/http/oversized/SHA256SUMS"
    truncate -s $((REMOTE_NODE_MAX_BYTES + 1)) \
        "$tmp/http/oversized-payload/z23"
    cp -f -- "$tmp/good/zclassic23" \
        "$tmp/http/oversized-payload/zclassic23"
    cp -f -- "$tmp/good/zclassic23-package-verify" \
        "$tmp/http/oversized-payload/zclassic23-package-verify"
    (cd "$tmp/http/oversized-payload" && \
        sha256sum z23 zclassic23 zclassic23-package-verify >SHA256SUMS)
    {
        sed -n '1p' "$tmp/good/SHA256SUMS"
        sed -n '1p' "$tmp/good/SHA256SUMS"
        sed -n '2p' "$tmp/good/SHA256SUMS"
    } >"$tmp/http/duplicate/SHA256SUMS"
    sed 's/  / /' "$tmp/good/SHA256SUMS" \
        >"$tmp/http/malformed/SHA256SUMS"
}

selftest_prepare_curl_mock() {
    local tmp="$SELFTEST_TMP"
    cat >"$tmp/mockbin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = --version ]; then
    printf 'curl %s mock\n' "${Z23_INSTALL_TEST_CURL_VERSION:-8.4.0}"
    exit 0
fi
[ "$#" -eq 10 ] || exit 2
[ "$1" = --connect-timeout ] && [ "$2" = 10 ] || exit 2
[ "$3" = --max-time ] || exit 2
[ "$5" = --max-filesize ] || exit 2
[ "$7" = -fsSL ] && [ "$9" = -o ] || exit 2
maximum_seconds="$4"; maximum_bytes="$6"; url="$8"; dest="${10}"
case "$url" in https://mirror.invalid/*) ;; *) exit 3 ;; esac
rel="${url#https://mirror.invalid/}"
case "$rel" in
    */SHA256SUMS)
        [ "$maximum_seconds" = 30 ] && [ "$maximum_bytes" = 1024 ] || exit 4
        ;;
    */z23|*/zclassic23)
        [ "$maximum_seconds" = 300 ] && \
            [ "$maximum_bytes" = 67108864 ] || exit 4
        ;;
    */zclassic23-package-verify)
        [ "$maximum_seconds" = 300 ] && \
            [ "$maximum_bytes" = 134217728 ] || exit 4
        ;;
    *) exit 4 ;;
esac
printf '%s connect=%s time=%s bytes=%s\n' \
    "$rel" "$2" "$maximum_seconds" "$maximum_bytes" \
    >>"$Z23_INSTALL_TEST_CURL_LOG"
if [ "$rel" = signal/SHA256SUMS ]; then
    : >"$Z23_INSTALL_TEST_SIGNAL_READY"
    while [ ! -e "$Z23_INSTALL_TEST_SIGNAL_RELEASE" ]; do sleep 0.02; done
fi
actual_bytes="$(wc -c <"$Z23_INSTALL_TEST_HTTP_ROOT/$rel" | tr -d ' ')"
[ "$actual_bytes" -le "$maximum_bytes" ] || exit 63
cp -- "$Z23_INSTALL_TEST_HTTP_ROOT/$rel" "$dest"
EOF
    chmod 755 "$tmp/mockbin/curl"
}

selftest_local_refusals() {
    local tmp="$SELFTEST_TMP" rc

    # Missing source refuses.
    rc=0
    run_install "$tmp/prefix" "$tmp/units" "$tmp/no-such" \
        >/dev/null 2>"$tmp/missing.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: missing source must exit 1"
    grep -q 'not a directory' "$tmp/missing.err" \
        || die "selftest: missing source must name the refusal"

    # Missing SHA256SUMS refuses.
    mkdir -p "$tmp/nosums"
    printf 'x\n' >"$tmp/nosums/z23"
    rc=0
    run_install "$tmp/prefix" "$tmp/units" "$tmp/nosums" \
        >/dev/null 2>"$tmp/nosums.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: missing SHA256SUMS must exit 1"
    grep -q 'SHA256SUMS missing' "$tmp/nosums.err" \
        || die "selftest: missing SHA256SUMS must be named"

    # Mismatch: dest must stay empty.
    cp -f -- "$tmp/good/z23" "$tmp/bad/z23"
    cp -f -- "$tmp/good/zclassic23" "$tmp/bad/zclassic23"
    cp -f -- "$tmp/good/zclassic23-package-verify" \
        "$tmp/bad/zclassic23-package-verify"
    cp -f -- "$tmp/good/SHA256SUMS" "$tmp/bad/SHA256SUMS"
    printf 'TAMPERED\n' >"$tmp/bad/z23"
    rc=0
    run_install "$tmp/empty-dest" "$tmp/units" "$tmp/bad" \
        >/dev/null 2>"$tmp/mismatch.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: checksum mismatch must exit 1"
    grep -qi 'mismatch' "$tmp/mismatch.err" \
        || die "selftest: mismatch must be named"
    if [ -e "$tmp/empty-dest/bin/z23" ]; then
        die "selftest: mismatch installed z23 anyway"
    fi
}

selftest_remote_authority() {
    local tmp="$SELFTEST_TMP" rc curl_version

    # A remote mirror is not the authority for its own checksum manifest.
    # Missing expectation refuses before even fetching SHA256SUMS.
    : >"$tmp/curl.log"
    rc=0
    PATH="$tmp/mockbin:$PATH" \
    Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
    Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-missing" \
    Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/good \
        >/dev/null 2>"$tmp/remote-missing.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: remote source without manifest digest must exit 1"
    [ ! -s "$tmp/curl.log" ] \
        || die "selftest: missing remote manifest digest still made a request"
    [ ! -e "$tmp/remote-missing/bin/z23" ] \
        || die "selftest: unpinned remote source installed z23"

    # curl 8.4.0 is the first release where --max-filesize also bounds
    # responses without a known Content-Length. Refuse older or unreadable
    # versions before making a transfer request.
    for curl_version in 8.3.0 unreadable; do
        : >"$tmp/curl.log"
        rc=0
        PATH="$tmp/mockbin:$PATH" \
        Z23_INSTALL_TEST_CURL_VERSION="$curl_version" \
        Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
        Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
        Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/curl-$curl_version" \
        Z23_UNIT_DIR="$tmp/units" \
            "$SCRIPT_DIR/install_z23.sh" \
            --source=https://mirror.invalid/good \
            --manifest-sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
            >/dev/null 2>"$tmp/curl-$curl_version.err" || rc=$?
        [ "$rc" -eq 1 ] || die "selftest: curl $curl_version must refuse"
        [ ! -s "$tmp/curl.log" ] \
            || die "selftest: curl $curl_version refusal made a request"
    done
}

selftest_remote_pins() {
    local tmp="$SELFTEST_TMP" rc

    # A wrong expectation may fetch the manifest to compare it, but must not
    # fetch any payload or install anything.
    : >"$tmp/curl.log"
    rc=0
    PATH="$tmp/mockbin:$PATH" \
    Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
    Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-wrong" \
    Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/good \
        --manifest-sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        >/dev/null 2>"$tmp/remote-wrong.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: wrong remote manifest digest must exit 1"
    [ "$(cat "$tmp/curl.log")" = \
        "good/SHA256SUMS connect=10 time=30 bytes=1024" ] \
        || die "selftest: wrong manifest digest fetched a payload"
    [ ! -e "$tmp/remote-wrong/bin/z23" ] \
        || die "selftest: wrong manifest digest installed z23"

    # Replacing both payloads and SHA256SUMS does not help a hostile mirror:
    # the independently obtained digest still binds the selected manifest.
    SELFTEST_MANIFEST_SHA="$(sha256sum "$tmp/http/good/SHA256SUMS" | awk '{print $1}')"
    : >"$tmp/curl.log"
    rc=0
    PATH="$tmp/mockbin:$PATH" \
    Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
    Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-replaced" \
    Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/replaced \
        --manifest-sha256="$SELFTEST_MANIFEST_SHA" \
        >/dev/null 2>"$tmp/remote-replaced.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: replaced remote release must exit 1"
    [ "$(cat "$tmp/curl.log")" = \
        "replaced/SHA256SUMS connect=10 time=30 bytes=1024" ] \
        || die "selftest: replaced manifest fetched a payload"
    [ ! -e "$tmp/remote-replaced/bin/z23" ] \
        || die "selftest: replaced remote release installed z23"
}

selftest_remote_success() {
    local tmp="$SELFTEST_TMP" out

    # Positive remote path: the selected manifest downloads and installs the
    # same verified files regardless of which mirror served them.
    : >"$tmp/curl.log"
    out="$(PATH="$tmp/mockbin:$PATH" \
        Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
        Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
        Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-good" \
        Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/good \
        --manifest-sha256="$SELFTEST_MANIFEST_SHA" 2>"$tmp/remote-good.err")" \
        || die "selftest: correctly pinned remote release failed"
    [ "$out" = "$NEXT_COMMAND" ] \
        || die "selftest: pinned remote install next command drifted"
    cmp -s "$tmp/good/z23" "$tmp/remote-good/bin/z23" \
        || die "selftest: pinned remote z23 bytes differ"
    [ "$(cat "$tmp/curl.log")" = \
        $'good/SHA256SUMS connect=10 time=30 bytes=1024\ngood/z23 connect=10 time=300 bytes=67108864\ngood/zclassic23 connect=10 time=300 bytes=67108864\ngood/zclassic23-package-verify connect=10 time=300 bytes=134217728' ] \
        || die "selftest: bounded remote request sequence drifted"
}

selftest_remote_bounds() {
    local tmp="$SELFTEST_TMP" rc oversized_manifest_sha256
    local oversized_payload_manifest_sha256

    # The transport ceiling is enforced even when a mirror advertises no
    # useful HTTP metadata: the fake curl applies the exact --max-filesize it
    # received and refuses the 1025-byte manifest without copying it.
    oversized_manifest_sha256="$(sha256sum "$tmp/http/oversized/SHA256SUMS" | awk '{print $1}')"
    : >"$tmp/curl.log"
    rc=0
    PATH="$tmp/mockbin:$PATH" \
    Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
    Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-oversized" \
    Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/oversized \
        --manifest-sha256="$oversized_manifest_sha256" \
        >/dev/null 2>"$tmp/remote-oversized.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: oversized remote manifest must exit 1"
    [ "$(cat "$tmp/curl.log")" = \
        "oversized/SHA256SUMS connect=10 time=30 bytes=1024" ] \
        || die "selftest: oversized manifest request was not bounded"
    [ ! -e "$tmp/remote-oversized/bin/z23" ] \
        || die "selftest: oversized remote manifest installed z23"

    oversized_payload_manifest_sha256="$(sha256sum \
        "$tmp/http/oversized-payload/SHA256SUMS" | awk '{print $1}')"
    : >"$tmp/curl.log"
    rc=0
    PATH="$tmp/mockbin:$PATH" \
    Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
    Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-oversized-payload" \
    Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/oversized-payload \
        --manifest-sha256="$oversized_payload_manifest_sha256" \
        >/dev/null 2>"$tmp/remote-oversized-payload.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: oversized remote payload must exit 1"
    [ "$(cat "$tmp/curl.log")" = \
        $'oversized-payload/SHA256SUMS connect=10 time=30 bytes=1024\noversized-payload/z23 connect=10 time=300 bytes=67108864' ] \
        || die "selftest: oversized payload request was not bounded"
    [ ! -e "$tmp/remote-oversized-payload/bin/z23" ] \
        || die "selftest: oversized remote payload installed z23"
}

selftest_remote_manifest_and_signal() {
    local tmp="$SELFTEST_TMP" rc invalid_kind invalid_sha

    # Grammar and member-set checks happen after the pinned manifest fetch but
    # before the first payload request.
    for invalid_kind in duplicate malformed; do
        invalid_sha="$(sha256sum "$tmp/http/$invalid_kind/SHA256SUMS" | awk '{print $1}')"
        : >"$tmp/curl.log"
        rc=0
        PATH="$tmp/mockbin:$PATH" \
        Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
        Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
        Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-$invalid_kind" \
        Z23_UNIT_DIR="$tmp/units" \
            "$SCRIPT_DIR/install_z23.sh" \
            --source="https://mirror.invalid/$invalid_kind" \
            --manifest-sha256="$invalid_sha" \
            >/dev/null 2>"$tmp/remote-$invalid_kind.err" || rc=$?
        [ "$rc" -eq 1 ] \
            || die "selftest: $invalid_kind remote manifest must exit 1"
        [ "$(cat "$tmp/curl.log")" = \
            "$invalid_kind/SHA256SUMS connect=10 time=30 bytes=1024" ] \
            || die "selftest: $invalid_kind manifest fetched a payload"
        [ ! -e "$tmp/remote-$invalid_kind/bin/z23" ] \
            || die "selftest: $invalid_kind remote manifest installed z23"
    done

    # A signal while curl is active preserves the signal exit status and the
    # validated EXIT trap removes the partially populated staging directory.
    rm -f "$tmp/signal.ready" "$tmp/signal.release"
    : >"$tmp/curl.log"
    PATH="$tmp/mockbin:$PATH" \
    Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
    Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
    Z23_INSTALL_TEST_SIGNAL_READY="$tmp/signal.ready" \
    Z23_INSTALL_TEST_SIGNAL_RELEASE="$tmp/signal.release" \
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-signal" \
    Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/signal \
        --manifest-sha256="$SELFTEST_MANIFEST_SHA" \
        >/dev/null 2>"$tmp/remote-signal.err" &
    local signal_pid=$! signal_wait=0
    while [ ! -e "$tmp/signal.ready" ] && [ "$signal_wait" -lt 100 ]; do
        sleep 0.02
        signal_wait=$((signal_wait + 1))
    done
    [ -e "$tmp/signal.ready" ] || die "selftest: signal fixture did not enter curl"
    kill -TERM "$signal_pid"
    : >"$tmp/signal.release"
    rc=0
    wait "$signal_pid" || rc=$?
    [ "$rc" -eq 143 ] || die "selftest: TERM must exit 143, got $rc"
    [ ! -e "$tmp/remote-signal/bin/z23" ] \
        || die "selftest: signalled install installed z23"
}

selftest_local_success() {
    local tmp="$SELFTEST_TMP" rc out

    # Happy path: dest gets the files; stdout is exactly one next command.
    out="$(run_install "$tmp/prefix" "$tmp/units" "$tmp/good" 2>"$tmp/ok.err")" \
        || die "selftest: good install failed"
    [ "$out" = "$NEXT_COMMAND" ] || die "selftest: stdout must be exactly '$NEXT_COMMAND', got '$out'"
    cmp -s "$tmp/good/z23" "$tmp/prefix/bin/z23" || die "selftest: installed z23 bytes differ"
    cmp -s "$tmp/good/zclassic23" "$tmp/prefix/bin/zclassic23" \
        || die "selftest: installed zclassic23 bytes differ"
    cmp -s "$tmp/good/zclassic23-package-verify" \
        "$tmp/prefix/bin/zclassic23-package-verify" \
        || die "selftest: installed zclassic23-package-verify bytes differ"

    # A valid checksum manifest that omits the worker is still an incomplete
    # release and must refuse before any payload reaches a fresh destination.
    mkdir -p "$tmp/no-verifier"
    cp -f -- "$tmp/good/z23" "$tmp/no-verifier/z23"
    cp -f -- "$tmp/good/zclassic23" "$tmp/no-verifier/zclassic23"
    (cd "$tmp/no-verifier" && sha256sum z23 zclassic23 >SHA256SUMS)
    rc=0
    run_install "$tmp/no-verifier-dest" "$tmp/units" "$tmp/no-verifier" \
        >/dev/null 2>"$tmp/no-verifier.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: missing verifier must exit 1"
    grep -Eq 'exactly three|exactly once' "$tmp/no-verifier.err" \
        || die "selftest: missing verifier must name the strict manifest refusal"
    if [ -e "$tmp/no-verifier-dest/bin/z23" ]; then
        die "selftest: incomplete release installed z23 anyway"
    fi

    # Idempotent re-run.
    out="$(run_install "$tmp/prefix" "$tmp/units" "$tmp/good" 2>"$tmp/ok2.err")" \
        || die "selftest: second install failed"
    [ "$out" = "$NEXT_COMMAND" ] || die "selftest: re-run stdout drifted"

    # The shipped unit must Restart=always so checkpoint install-on-next-boot
    # (a clean exit) is brought back. on-failure would strand a new node.
    grep -qx 'Restart=always' "$0" \
        || die "selftest: z23.service must Restart=always (install-on-next-boot)"

    # Drive the shipped write_unit path (run_install skips it under
    # Z23_SKIP_SYSTEMD=1). First-boot Type=notify READY must wait for onion
    # DESCRIPTOR PUBLICATION: hostname-only readiness lets systemd declare
    # started before HSDir upload, which is why "always connects" fails on
    # cold boots.
    write_unit "$tmp/prefix" "$tmp/units"
    [ -f "$tmp/units/z23.service" ] || die "selftest: write_unit did not emit z23.service"
    grep -q 'DESCRIPTOR PUBLICATION' "$tmp/units/z23.service" \
        || die "selftest: unit must wait for onion DESCRIPTOR PUBLICATION before ready"
    grep -q -- '-listen -tor -onion-persist' "$tmp/units/z23.service" \
        || die "selftest: z23.service must boot with -listen -tor -onion-persist"
}

selftest_local_manifest_refusals() {
    local tmp="$SELFTEST_TMP" rc
    # Unexpected SHA256SUMS member refuses before copy.
    mkdir -p "$tmp/extra"
    printf 'x\n' >"$tmp/extra/z23"
    printf 'x\n' >"$tmp/extra/zclassic23"
    printf 'x\n' >"$tmp/extra/zclassic23-package-verify"
    printf 'x\n' >"$tmp/extra/evil"
    (cd "$tmp/extra" && \
        sha256sum z23 zclassic23 zclassic23-package-verify evil >SHA256SUMS)
    rc=0
    run_install "$tmp/prefix2" "$tmp/units" "$tmp/extra" \
        >/dev/null 2>"$tmp/extra.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: extra SHA256SUMS member must refuse"
    grep -Eq 'exactly three|exactly once' "$tmp/extra.err" \
        || die "selftest: extra member must name the strict manifest refusal"

    [ -z "$(find "$tmp/stages" -mindepth 1 -maxdepth 1 \
        -name 'zcl-install-z23.*' -print -quit)" ] \
        || die "selftest: a negative install path leaked its staging directory"
}

selftest() {
    selftest_prepare
    selftest_prepare_curl_mock
    selftest_local_refusals
    selftest_remote_authority
    selftest_remote_pins
    selftest_remote_success
    selftest_remote_bounds
    selftest_remote_manifest_and_signal
    selftest_local_success
    selftest_local_manifest_refusals

    say "selftest PASS"
    trap - EXIT
    rm -rf "$SELFTEST_TMP"
    SELFTEST_TMP=""
}

SOURCE="${Z23_RELEASE_SOURCE:-}"
EXPECTED_MANIFEST_SHA256="${Z23_RELEASE_MANIFEST_SHA256:-}"
while [ $# -gt 0 ]; do
    case "$1" in
        --selftest) selftest; exit 0 ;;
        --source=*) SOURCE="${1#--source=}"; shift ;;
        --source)
            [ $# -ge 2 ] || die "--source needs a url or directory"
            SOURCE="$2"
            shift 2
            ;;
        --manifest-sha256=*) EXPECTED_MANIFEST_SHA256="${1#*=}"; shift ;;
        --manifest-sha256)
            [ $# -ge 2 ] || die "--manifest-sha256 needs a SHA-256 digest"
            EXPECTED_MANIFEST_SHA256="$2"
            shift 2
            ;;
        -h|--help)
            sed -n '2,22p' "$0"
            exit 0
            ;;
        --*) die "unknown argument: $1" ;;
        *)
            if [ -z "$SOURCE" ]; then
                SOURCE="$1"
                shift
            else
                die "unexpected extra argument: $1"
            fi
            ;;
    esac
done

install_from_source "$SOURCE" "$EXPECTED_MANIFEST_SHA256"
