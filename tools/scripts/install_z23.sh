#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# install_z23.sh — fetch a packaged Z23 release, verify SHA256SUMS fail-closed,
# install to ~/.local/bin, write a systemd --user unit, print ONE next command.
#
# Artifact source is taken from the first argument or Z23_RELEASE_SOURCE
# (a node URL or a local directory). Never hardcoded: any node that serves
# z23, zclassic23, and SHA256SUMS is a valid source. There is no registry.
#
# Checksum mismatch is a loud refusal. Nothing is copied to the destination
# until SHA256SUMS --strict passes.
#
# Usage:
#   install_z23.sh --source=<url-or-dir>
#   install_z23.sh <url-or-dir>
#   Z23_RELEASE_SOURCE=<url-or-dir> install_z23.sh
#   install_z23.sh --selftest
#
# Env:
#   Z23_INSTALL_PREFIX   default $HOME/.local
#   Z23_UNIT_DIR         default $HOME/.config/systemd/user
#   Z23_SKIP_SYSTEMD=1   skip unit install (tests)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { printf 'install_z23: REFUSE: %s\n' "$*" >&2; exit 1; }
say() { printf 'install_z23: %s\n' "$*" >&2; }

NEXT_COMMAND="z23 status"

fetch_into() {
    local src="$1" dest="$2"
    mkdir -p "$dest"
    case "$src" in
        http://*|https://*)
            command -v curl >/dev/null 2>&1 || die "curl is required to fetch $src"
            curl -fsSL "$src/SHA256SUMS" -o "$dest/SHA256SUMS" \
                || die "could not fetch $src/SHA256SUMS"
            [ -s "$dest/SHA256SUMS" ] || die "empty SHA256SUMS from $src"
            local name
            while read -r _ name; do
                [ -n "${name:-}" ] || continue
                case "$name" in
                    z23|zclassic23) ;;
                    *) die "SHA256SUMS names unexpected file: $name" ;;
                esac
                curl -fsSL "$src/$name" -o "$dest/$name" \
                    || die "could not fetch $src/$name"
            done <"$dest/SHA256SUMS"
            ;;
        *)
            [ -d "$src" ] || die "source is not a directory or http(s) URL: $src"
            [ -f "$src/SHA256SUMS" ] || die "SHA256SUMS missing in $src"
            cp -f -- "$src/SHA256SUMS" "$dest/SHA256SUMS"
            local name
            while read -r _ name; do
                [ -n "${name:-}" ] || continue
                case "$name" in
                    z23|zclassic23) ;;
                    *) die "SHA256SUMS names unexpected file: $name" ;;
                esac
                [ -f "$src/$name" ] || die "listed file missing: $src/$name"
                cp -f -- "$src/$name" "$dest/$name"
            done <"$dest/SHA256SUMS"
            ;;
    esac
}

verify_strict() {
    local dir="$1"
    [ -f "$dir/SHA256SUMS" ] || die "SHA256SUMS missing after fetch"
    (cd "$dir" && sha256sum -c --strict SHA256SUMS >/dev/null) \
        || die "SHA256SUMS mismatch — refusing to install"
}

install_payload() {
    local stage="$1" prefix="$2"
    local bindir="$prefix/bin"
    mkdir -p "$bindir"
    [ -f "$stage/z23" ] || die "verified payload missing z23"
    [ -f "$stage/zclassic23" ] || die "verified payload missing zclassic23"
    install -m 755 "$stage/z23" "$bindir/z23"
    install -m 755 "$stage/zclassic23" "$bindir/zclassic23"
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
# dial before HSDirs have the descriptor (docs/work/ONION_DIAL_GAP.md).
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
    local src="$1"
    [ -n "$src" ] || die "no source: pass --source=<url-or-dir> or set Z23_RELEASE_SOURCE"
    local prefix="${Z23_INSTALL_PREFIX:-$HOME/.local}"
    local unit_dir="${Z23_UNIT_DIR:-$HOME/.config/systemd/user}"
    local stage
    stage="$(mktemp -d /tmp/zcl-install-z23.XXXXXX)" || die "mktemp failed"
    fetch_into "$src" "$stage"
    verify_strict "$stage"
    install_payload "$stage" "$prefix"
    rm -rf "$stage"
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

selftest() {
    local tmp rc out
    tmp="$(mktemp -d /tmp/zcl-install-z23-selftest.XXXXXX)" || die "mktemp failed"
    trap 'rm -rf "$tmp"' EXIT

    mkdir -p "$tmp/good" "$tmp/bad" "$tmp/prefix" "$tmp/units"

    printf 'payload-a\n' >"$tmp/good/z23"
    printf 'payload-a\n' >"$tmp/good/zclassic23"
    (cd "$tmp/good" && sha256sum z23 zclassic23 >SHA256SUMS)

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

    # Happy path: dest gets the files; stdout is exactly one next command.
    out="$(run_install "$tmp/prefix" "$tmp/units" "$tmp/good" 2>"$tmp/ok.err")" \
        || die "selftest: good install failed"
    [ "$out" = "$NEXT_COMMAND" ] || die "selftest: stdout must be exactly '$NEXT_COMMAND', got '$out'"
    cmp -s "$tmp/good/z23" "$tmp/prefix/bin/z23" || die "selftest: installed z23 bytes differ"
    cmp -s "$tmp/good/zclassic23" "$tmp/prefix/bin/zclassic23" \
        || die "selftest: installed zclassic23 bytes differ"

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
    # cold boots (docs/work/ONION_DIAL_GAP.md).
    write_unit "$tmp/prefix" "$tmp/units"
    [ -f "$tmp/units/z23.service" ] || die "selftest: write_unit did not emit z23.service"
    grep -q 'DESCRIPTOR PUBLICATION' "$tmp/units/z23.service" \
        || die "selftest: unit must wait for onion DESCRIPTOR PUBLICATION before ready"
    grep -q -- '-listen -tor -onion-persist' "$tmp/units/z23.service" \
        || die "selftest: z23.service must boot with -listen -tor -onion-persist"
    repo_root="$(cd "$SCRIPT_DIR/../.." && pwd)"
    if [ -f "$repo_root/lib/net/src/tor_integration.c" ]; then
        grep -q 'tor_log_has_descriptor_publication' \
            "$repo_root/lib/net/src/tor_integration.c" \
            || die "selftest: missing shipped tor_log_has_descriptor_publication"
        grep -q 'DESCRIPTOR PUBLICATION' \
            "$repo_root/lib/net/src/tor_integration.c" \
            || die "selftest: first-boot must wait for DESCRIPTOR PUBLICATION in tor_integration.c"
        grep -q 'DESCRIPTOR PUBLICATION' \
            "$repo_root/config/src/boot_sd_watchdog.c" \
            || die "selftest: sd_notify READY must wait for DESCRIPTOR PUBLICATION"
        grep -q 'boot_sd_watchdog_maybe_notify_ready' \
            "$repo_root/config/src/boot_sd_watchdog.c" \
            || die "selftest: missing READY hold until onion publication"
    fi

    # Unexpected SHA256SUMS member refuses before copy.
    mkdir -p "$tmp/extra"
    printf 'x\n' >"$tmp/extra/z23"
    printf 'x\n' >"$tmp/extra/zclassic23"
    printf 'x\n' >"$tmp/extra/evil"
    (cd "$tmp/extra" && sha256sum z23 zclassic23 evil >SHA256SUMS)
    rc=0
    run_install "$tmp/prefix2" "$tmp/units" "$tmp/extra" \
        >/dev/null 2>"$tmp/extra.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: extra SHA256SUMS member must refuse"
    grep -q 'unexpected file' "$tmp/extra.err" \
        || die "selftest: extra member must be named"

    say "selftest PASS"
    trap - EXIT
    rm -rf "$tmp"
}

SOURCE="${Z23_RELEASE_SOURCE:-}"
while [ $# -gt 0 ]; do
    case "$1" in
        --selftest) selftest; exit 0 ;;
        --source=*) SOURCE="${1#--source=}"; shift ;;
        --source)
            [ $# -ge 2 ] || die "--source needs a url or directory"
            SOURCE="$2"
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

install_from_source "$SOURCE"
