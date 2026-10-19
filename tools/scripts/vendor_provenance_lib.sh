#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Shared deterministic stamp primitives for vendored static archives.
# This file deliberately knows nothing about dependency versions or recipes;
# build_vendor.sh supplies the checked expected descriptor, and dep_audit.sh
# asks that same builder contract to verify the installed archive byte-for-byte.

VP_SCHEMA="zclassic23.vendor-provenance.v1"

vp_sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

vp_sha256_text() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    else
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    fi
}

# Version text and target triples do not identify a compiler wrapper: its
# injected sysroot, ABI, CPU, sanitizer, or reproducibility flags can change
# while both probes stay identical. Bind the executable bytes as well. This
# also invalidates vendor archives after an in-place compiler package upgrade.
vp_executable_identity_sha() {
    local command_word="$1" executable
    executable="$(command -v "$command_word" 2>/dev/null || true)"
    if [[ -n "$executable" && -f "$executable" ]]; then
        vp_sha256_file "$executable"
    else
        vp_sha256_text "unresolved=$command_word"
    fi
}

# Hash a tool's stable identity without assuming it implements compiler-only
# options.  In particular, `perl -dumpmachine` means "start the debugger for
# umpmachine" and can wedge an unattended vendor build at a DB<1> prompt.
vp_tool_identity_sha() {
    local command_name="$1" version executable_sha
    local -a command_argv
    read -r -a command_argv <<<"$command_name"
    [[ ${#command_argv[@]} -gt 0 ]] || return 1
    version="$("${command_argv[@]}" --version 2>/dev/null |
        sed -n '/[^[:space:]]/{p;q;}' || true)"
    executable_sha="$(vp_executable_identity_sha "${command_argv[0]}")"
    vp_sha256_text "command=$command_name
version=$version
executable_sha256=$executable_sha"
}

# Compiler identity additionally binds the target triple.  Keep this separate
# from vp_tool_identity_sha so generic build tools are never probed with
# compiler flags.
vp_compiler_identity_sha() {
    local command_name="$1" version machine executable_sha
    local -a command_argv
    read -r -a command_argv <<<"$command_name"
    [[ ${#command_argv[@]} -gt 0 ]] || return 1
    version="$("${command_argv[@]}" --version 2>/dev/null |
        sed -n '/[^[:space:]]/{p;q;}' || true)"
    machine="$("${command_argv[@]}" -dumpmachine 2>/dev/null |
        sed -n '1p' || true)"
    executable_sha="$(vp_executable_identity_sha "${command_argv[0]}")"
    vp_sha256_text "command=$command_name
version=$version
machine=$machine
executable_sha256=$executable_sha"
}

vp_stamp_path() {
    local lib_dir="$1" archive="$2"
    printf '%s/.provenance/%s.stamp' "$lib_dir" "$archive"
}

vp_render_stamp() {
    local archive_path="$1" descriptor="$2"
    printf '%s\n' "$descriptor"
    printf 'artifact_sha256=%s\n' "$(vp_sha256_file "$archive_path")"
    printf 'artifact_size=%s\n' "$(wc -c <"$archive_path" | tr -d ' ')"
}

vp_write_stamp() {
    local lib_dir="$1" archive="$2" descriptor="$3"
    local archive_path="$lib_dir/$archive" stamp tmp
    [[ -f "$archive_path" ]] || return 1
    stamp="$(vp_stamp_path "$lib_dir" "$archive")"
    mkdir -p "$(dirname "$stamp")"
    tmp="${stamp}.tmp.$$"
    vp_render_stamp "$archive_path" "$descriptor" >"$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$stamp"
}

vp_verify_stamp() {
    local lib_dir="$1" archive="$2" descriptor="$3"
    local archive_path="$lib_dir/$archive" stamp expected
    archive_path="$lib_dir/$archive"
    stamp="$(vp_stamp_path "$lib_dir" "$archive")"
    [[ -f "$archive_path" && -f "$stamp" ]] || return 1
    expected="${stamp}.verify.$$"
    vp_render_stamp "$archive_path" "$descriptor" >"$expected"
    if cmp -s "$expected" "$stamp"; then
        rm -f "$expected"
        return 0
    fi
    rm -f "$expected"
    return 1
}

vp_stamp_sha256() {
    local stamp
    stamp="$(vp_stamp_path "$1" "$2")"
    [[ -f "$stamp" ]] || return 1
    vp_sha256_file "$stamp"
}

# Integrity lock for the one prebuilt archive committed to git. Its manifest
# is intentionally explicit when upstream source provenance is unresolved;
# changing the bytes requires a reviewed manifest change, and the manifest's
# replacement policy forbids blessing new bytes without proven source inputs.
vp_verify_locked_manifest() {
    local archive_path="$1" manifest="$2" expected_archive="$3"
    [[ -f "$archive_path" && -f "$manifest" ]] || return 1
    grep -qx "schema=zclassic23.committed-vendor-manifest.v1" "$manifest" ||
        return 1
    grep -qx "archive=$expected_archive" "$manifest" || return 1
    grep -qx 'replacement_policy=source-proof-required' "$manifest" ||
        return 1
    local want_sha want_size got_sha got_size
    want_sha="$(sed -n 's/^archive_sha256=//p' "$manifest")"
    want_size="$(sed -n 's/^archive_size=//p' "$manifest")"
    [[ "$want_sha" =~ ^[0-9a-f]{64}$ && "$want_size" =~ ^[0-9]+$ ]] ||
        return 1
    got_sha="$(vp_sha256_file "$archive_path")"
    got_size="$(wc -c <"$archive_path" | tr -d ' ')"
    [[ "$got_sha" == "$want_sha" && "$got_size" == "$want_size" ]]
}

# ---------------------------------------------------------------------------
# Vendor archive cache. A fresh worktree rebuilt OpenSSL, libevent, SQLite and
# LevelDB from source before its first compile could start: MEASURED 48 s of a
# 93 s fully zcc-cached build (52 %), serial, because zcc caches compiler
# invocations and these archives are built by configure/make recipes it never
# sees. The archives are byte-reproducible, and every one carries a stamp that
# binds the exact descriptor and the archive SHA-256, so a bundle saved from a
# verified build can be handed to any other tree. Restoring never replaces the
# stamp check: the caller re-verifies every restored archive against the
# descriptor it computes itself, and a mismatch is a rebuild.
#
#   <cache>/<group>/<key>/bundle.tar + bundle.sha256
#
# key = SHA-256 of the group's descriptors, so any pin, recipe, flag,
# dependency or toolchain change selects a different entry.
vp_cache_root() {
    if [[ -n "${VENDOR_ARCHIVE_CACHE:-}" ]]; then
        printf '%s' "$VENDOR_ARCHIVE_CACHE"
    elif [[ -n "${ZCC_DIR:-}" ]]; then
        printf '%s/vendor' "$ZCC_DIR"
    elif [[ -n "${XDG_CACHE_HOME:-}" ]]; then
        printf '%s/zcc/vendor' "$XDG_CACHE_HOME"
    elif [[ -n "${HOME:-}" ]]; then
        printf '%s/.cache/zcc/vendor' "$HOME"
    else
        return 1
    fi
}

# Off for forced rebuilds and for the hermetic goals, which export
# ZCL_USE_CCACHE=0 precisely so that no reproducibility claim is served from a
# cache.
vp_cache_enabled() {
    [[ "${ZCL_USE_CCACHE:-1}" != "0" && "${VENDOR_NO_CACHE:-0}" != "1" &&
       "${VENDOR_FORCE:-0}" != "1" ]]
}

# vp_cache_save VENDOR_DIR GROUP KEY MARKER FILE...   (FILE relative to VENDOR_DIR)
# Headers installed by the build are every file under include/ newer than MARKER.
vp_cache_save() {
    local vendor="$1" group="$2" key="$3" marker="$4"
    shift 4
    local root dir tmp list f old
    root="$(vp_cache_root)" || return 0
    dir="$root/$group/$key"
    [[ -d "$dir" ]] && return 0
    mkdir -p "$root/$group" || return 0
    tmp="$(mktemp -d "$root/$group/.tmp.XXXXXX")" || return 0
    list="$tmp/list"
    for f in "$@"; do
        [[ -f "$vendor/$f" ]] || { rm -rf "$tmp"; return 0; }
        printf '%s\n' "$f" >>"$list"
    done
    (cd "$vendor" && find include -type f -newer "$marker" 2>/dev/null) \
        >>"$list" || true
    if tar -C "$vendor" -cf "$tmp/bundle.tar" -T "$list" &&
       printf '%s\n' "$(vp_sha256_file "$tmp/bundle.tar")" \
           >"$tmp/bundle.sha256" &&
       rm -f "$list" && mv "$tmp" "$dir" 2>/dev/null; then
        :
    else
        rm -rf "$tmp"
        return 0
    fi
    # Keep the newest three keys per group; a changed pin or toolchain would
    # otherwise grow the store forever.
    # shellcheck disable=SC2012
    for old in $(ls -t "$root/$group" 2>/dev/null | tail -n +4); do
        rm -rf "${root:?}/$group/${old:?}"
    done
    return 0
}

# vp_cache_restore VENDOR_DIR GROUP KEY: extract a digest-checked bundle.
vp_cache_restore() {
    local vendor="$1" group="$2" key="$3" root dir
    root="$(vp_cache_root)" || return 1
    dir="$root/$group/$key"
    [[ -f "$dir/bundle.tar" && -f "$dir/bundle.sha256" ]] || return 1
    [[ "$(vp_sha256_file "$dir/bundle.tar")" == "$(cat "$dir/bundle.sha256")" ]] ||
        return 1
    # Only relative member names under lib/ or include/, never "..".
    if tar -tf "$dir/bundle.tar" | grep -Ev '^(lib|include)/' >/dev/null ||
       tar -tf "$dir/bundle.tar" | grep -E '(^|/)\.\.(/|$)' >/dev/null; then
        return 1
    fi
    tar -C "$vendor" -xf "$dir/bundle.tar" || return 1
    touch "$dir" 2>/dev/null || true
    return 0
}
