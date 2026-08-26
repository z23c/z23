#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# zcash_params.sh — work with the Zcash proving parameters.
#
# READ THIS FIRST, because it changes what you need:
#
#   A validating node does NOT need these files.
#
# The ~777 MB parameter set contains two different things glued together.
# The leading ~6 KB of each file is the *verifying* key; everything after it
# is the *proving* key. Consensus validation — checking the shielded proofs
# in blocks other people made — uses only the verifying keys, and those are
# compiled into this node (lib/sapling/src/params_vk_embedded.c). A node with
# an empty $HOME syncs, validates every shielded proof, and serves peers with
# nothing downloaded.
#
# The proving keys are needed for exactly one thing: CREATING a shielded
# transaction of your own. That is the only capability this script restores.
#
# Subcommands:
#   verify [dir]          check the four files in dir against the pinned
#                         sha256 digests (default dir: $HOME/.zcash-params)
#   install <src> [dir]   copy from a directory you already trust, verifying
#                         every file before and after the copy
#   vk-extract <src> <out.c>
#                         MAINTAINER ONLY. Re-derive the embedded verifying
#                         keys from a verified parameter set and emit the
#                         generated C source. Committed output must be
#                         reproducible; see docs/PARAMS.md.
#
# Sovereignty note: this script pins no download host, no DNS name and no
# certificate authority. It moves bytes you already have and checks them
# against digests pinned in this repository. Where the bytes came from is
# your choice; whether they are the right bytes is not negotiable.

set -euo pipefail

# ── Pinned digests ──────────────────────────────────────────────────────
# These are the public outputs of the Zcash multi-party parameter
# ceremonies. They are the trust anchor. A file that does not match is
# refused; there is no override flag, deliberately.
PARAM_FILES=(
    "sapling-spend.params"
    "sapling-output.params"
    "sprout-groth16.params"
    "sprout-verifying.key"
)
PARAM_SHA256=(
    "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13"
    "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4"
    "b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50"
    "4bd498dae0aacfd8e98dc306338d017d9c08dd0918ead18172bd0aec2fc5df82"
)
PARAM_BYTES=(47958396 3592860 725523612 1449)

# Groth16 verifying-key prefix layout, matching groth16_vk_read_raw() in
# lib/sapling/src/bls12_381.c:
#   alpha_g1(96) beta_g1(96) beta_g2(192) gamma_g2(192)
#   delta_g1(96) delta_g2(192) ic_len(4, big-endian) ic[](96 each)
VK_HEADER_BYTES=868
VK_IC_LEN_OFFSET=864
VK_IC_POINT_BYTES=96

die() { printf 'zcash_params: %s\n' "$*" >&2; exit 1; }
note() { printf 'zcash_params: %s\n' "$*"; }

file_sha256() {
    # Deliberately not in a pipeline with grep -q: under `set -o pipefail`
    # a short-circuiting reader turns a successful match into exit 141.
    local out
    out=$(sha256sum -- "$1")
    printf '%s' "${out%% *}"
}

# -L so a symlinked parameter file reports the size of its target, not the
# 46-byte size of the link. sha256sum already follows links, so without this
# the two checks disagree and the size check rejects a good file.
file_size() { stat -Lc%s -- "$1"; }

# Verify one file against its pinned size and digest. Returns non-zero and
# says exactly what was wrong; never prints a bare "failed".
verify_one() {
    local dir="$1" idx="$2"
    local name="${PARAM_FILES[$idx]}"
    local want="${PARAM_SHA256[$idx]}"
    local want_bytes="${PARAM_BYTES[$idx]}"
    local path="$dir/$name"

    if [ ! -r "$path" ]; then
        printf '  MISSING  %s\n' "$name"
        return 1
    fi
    local got_bytes
    got_bytes=$(file_size "$path")
    if [ "$got_bytes" != "$want_bytes" ]; then
        printf '  BAD SIZE %s (expected %s bytes, got %s)\n' \
            "$name" "$want_bytes" "$got_bytes"
        return 1
    fi
    local got
    got=$(file_sha256 "$path")
    if [ "$got" != "$want" ]; then
        printf '  BAD HASH %s\n    expected %s\n    actual   %s\n' \
            "$name" "$want" "$got"
        return 1
    fi
    printf '  ok       %s (%s bytes)\n' "$name" "$got_bytes"
    return 0
}

cmd_verify() {
    local dir="${1:-$HOME/.zcash-params}"
    note "verifying proving parameters in $dir"
    local rc=0 i
    for i in "${!PARAM_FILES[@]}"; do
        verify_one "$dir" "$i" || rc=1
    done
    if [ "$rc" -ne 0 ]; then
        printf '\n'
        die "parameter set in $dir is NOT usable (see above).
  These are cryptographic proving parameters: wrong bytes are a security
  failure, not an inconvenience. Nothing was installed.
  Note that you only need these to CREATE shielded transactions — a
  validating node does not need them at all."
    fi
    note "all four files match their pinned digests"
}

cmd_install() {
    local src="${1:?usage: zcash_params.sh install <src-dir> [dest-dir]}"
    local dst="${2:-$HOME/.zcash-params}"
    [ -d "$src" ] || die "source directory does not exist: $src"

    note "checking source $src before copying anything"
    local rc=0 i
    for i in "${!PARAM_FILES[@]}"; do
        verify_one "$src" "$i" || rc=1
    done
    [ "$rc" -eq 0 ] || die "source set is not trustworthy; refusing to install"

    mkdir -p "$dst"
    for i in "${!PARAM_FILES[@]}"; do
        local name="${PARAM_FILES[$i]}"
        note "copying $name"
        cp -f -- "$src/$name" "$dst/$name.partial"
        mv -f -- "$dst/$name.partial" "$dst/$name"
    done

    note "re-verifying destination $dst after copy"
    rc=0
    for i in "${!PARAM_FILES[@]}"; do
        verify_one "$dst" "$i" || rc=1
    done
    [ "$rc" -eq 0 ] || die "destination failed verification after copy; \
the copy is corrupt and must not be used"
    note "installed and verified in $dst — shielded spend capability available"
}

# ── Maintainer: re-derive the embedded verifying keys ───────────────────

# Read a big-endian uint32 at a byte offset.
read_be32() {
    local path="$1" off="$2" out
    out=$(dd if="$path" bs=1 skip="$off" count=4 status=none | \
          od -An -tu4 --endian=big)
    printf '%s' "${out//[[:space:]]/}"
}

# Emit a C byte array literal for the first $2 bytes of $1.
emit_c_array() {
    local path="$1" count="$2" symbol="$3"
    printf 'static const uint8_t %s[%s] = {\n' "$symbol" "$count"
    dd if="$path" bs=1 count="$count" status=none | \
        od -An -tx1 -v | \
        awk '{ for (i = 1; i <= NF; i++) printf "%s0x%s,", (n++ % 12 == 0 ? "\n    " : " "), $i } END { print "" }'
    printf '};\n\n'
}

cmd_vk_extract() {
    local src="${1:?usage: zcash_params.sh vk-extract <src-dir> <out.c>}"
    local out="${2:?usage: zcash_params.sh vk-extract <src-dir> <out.c>}"

    note "verifying source parameter set before extracting verifying keys"
    local rc=0 i
    for i in "${!PARAM_FILES[@]}"; do
        verify_one "$src" "$i" || rc=1
    done
    [ "$rc" -eq 0 ] || die "refusing to extract verifying keys from an \
unverified parameter set"

    local tmp="$out.tmp.$$"
    {
        cat <<'HEADER'
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * GENERATED FILE — do not edit by hand.
 * Regenerate with:
 *   tools/scripts/zcash_params.sh vk-extract <params-dir> \
 *       lib/sapling/src/params_vk_embedded.c
 *
 * Embedded Groth16 / PHGR13 VERIFYING keys.
 *
 * Why these are in the repository at all:
 *
 * A Zcash parameter file is a verifying key followed by a proving key. The
 * verifying key is the leading
 *     868 + ic_len * 96
 * bytes — the exact prefix groth16_vk_read_raw() consumes and nothing more.
 * Consensus validation needs only that prefix. The remaining ~777 MB is
 * proving-key material used solely to CREATE shielded transactions.
 *
 * These prefixes are consensus constants, in the same sense the checkpoint
 * table is: every node must agree on them or it is on a different network.
 * A constant that every node must agree on belongs in the source tree, not
 * in a 777 MB file fetched from a host we do not control. Compiling them in
 * removes the last acquisition dependency from a validating node.
 *
 * Each blob is checked against its own SHA-256 at install time, so a build
 * that patches these arrays fails closed instead of validating proofs
 * against an attacker's key.
 */

#include "sapling/params_vk_embedded.h"

#include <stdint.h>

HEADER

        local names=(spend output sprout_groth16)
        local files=("sapling-spend.params" "sapling-output.params" \
                     "sprout-groth16.params")
        local j
        for j in "${!names[@]}"; do
            local f="$src/${files[$j]}"
            local ic_len vk_bytes
            ic_len=$(read_be32 "$f" "$VK_IC_LEN_OFFSET")
            [ -n "$ic_len" ] || die "could not read ic_len from ${files[$j]}"
            vk_bytes=$((VK_HEADER_BYTES + ic_len * VK_IC_POINT_BYTES))
            printf '/* %s: ic_len=%s -> verifying-key prefix is %s bytes\n' \
                "${files[$j]}" "$ic_len" "$vk_bytes"
            printf ' * (out of %s bytes of parameter file). */\n' \
                "$(file_size "$f")"
            emit_c_array "$f" "$vk_bytes" "zcl_vk_${names[$j]}_bytes"
        done

        # sprout-verifying.key is already a standalone PHGR13 verifying key.
        local svk="$src/sprout-verifying.key"
        printf '/* sprout-verifying.key: a standalone PHGR13 verifying key,\n'
        printf ' * embedded whole (%s bytes). */\n' "$(file_size "$svk")"
        emit_c_array "$svk" "$(file_size "$svk")" "zcl_vk_sprout_phgr_bytes"

        cat <<'TABLE'
/* SHA-256 of each embedded blob, so a tampered build is caught at install
 * time rather than trusted. Verified by sapling_install_embedded_vks(). */
TABLE
        for j in "${!names[@]}"; do
            local f="$src/${files[$j]}"
            local ic_len vk_bytes d
            ic_len=$(read_be32 "$f" "$VK_IC_LEN_OFFSET")
            vk_bytes=$((VK_HEADER_BYTES + ic_len * VK_IC_POINT_BYTES))
            d=$(dd if="$f" bs=1 count="$vk_bytes" status=none | sha256sum)
            printf 'static const char zcl_vk_%s_sha256[] =\n    "%s";\n' \
                "${names[$j]}" "${d%% *}"
        done
        local d
        d=$(sha256sum -- "$svk")
        printf 'static const char zcl_vk_sprout_phgr_sha256[] =\n    "%s";\n\n' \
            "${d%% *}"

        cat <<'ACCESS'
const struct zcl_embedded_vk zcl_embedded_vks[ZCL_EMBEDDED_VK_COUNT] = {
    { "sapling-spend",  zcl_vk_spend_bytes,
      sizeof(zcl_vk_spend_bytes),  zcl_vk_spend_sha256 },
    { "sapling-output", zcl_vk_output_bytes,
      sizeof(zcl_vk_output_bytes), zcl_vk_output_sha256 },
    { "sprout-groth16", zcl_vk_sprout_groth16_bytes,
      sizeof(zcl_vk_sprout_groth16_bytes), zcl_vk_sprout_groth16_sha256 },
    { "sprout-phgr",    zcl_vk_sprout_phgr_bytes,
      sizeof(zcl_vk_sprout_phgr_bytes), zcl_vk_sprout_phgr_sha256 },
};
ACCESS
    } > "$tmp"

    mv -f -- "$tmp" "$out"
    note "wrote $out ($(file_size "$out") bytes of generated C)"
}

usage() {
    sed -n '3,40p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

main() {
    local cmd="${1:-}"
    [ -n "$cmd" ] || usage
    shift
    case "$cmd" in
        verify)     cmd_verify "$@" ;;
        install)    cmd_install "$@" ;;
        vk-extract) cmd_vk_extract "$@" ;;
        -h|--help|help) usage ;;
        *) die "unknown subcommand '$cmd' (try: verify, install, vk-extract)" ;;
    esac
}

main "$@"
