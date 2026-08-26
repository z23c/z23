#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# hotswap-package.sh — write or check a sidecar MANIFEST beside an
# already-built hot-swap module .so.
#
#   tools/dev/hotswap-package.sh <module.so>            # write <module.so>.manifest
#   tools/dev/hotswap-package.sh --verify <module.so>    # re-check it, exit 1 on any mismatch
#   tools/dev/hotswap-package.sh --verify --all          # re-check every build/hotswap/*.so
#   tools/dev/hotswap-package.sh --all                   # write a manifest for every .so there
#
# ── THE MANIFEST IS A RECORD, NOT AN AUTHORIZATION ─────────────────────────
# Nothing in lib/hotswap reads this file. hotswap_activate() decides whether a
# module mounts by dlsym'ing the REAL `zcl_hotswap_module` struct out of the
# .so itself and running hotswap_module_admit() against it — the sidecar
# manifest never enters that path and never will as shipped here. It exists so
# a human or a later tool can see, without re-deriving it, what a specific
# built artifact claims to be: which allowlist row it came from, which leaves
# it carries, which consensus core it was sealed against, and the exact bytes
# it is. Treat it exactly the way you would treat a shipping label on a
# sealed crate: useful for finding the right crate, worthless as a substitute
# for opening it and checking the contents, and actively dangerous the moment
# anything downstream starts trusting the label instead of the crate. If a
# future change ever makes the loader CONSUME this file instead of just
# recording alongside it, forging a manifest becomes equivalent to handing
# that loader arbitrary code to mount — at that point this file needs a
# signature and a trust root, and this comment is the flag that it does not
# have either today.
#
# ── WHERE source_tu / leaves COME FROM ─────────────────────────────────────
# Both are read by driving tools/dev/hotswap_verify_so (built the same way
# tools/dev/hotswap-verify.sh builds it: lib/hotswap/src/hotswap_activate.c +
# hotswap_islands.c, the real hotswap_verify_module_so()) and parsing its
# `source_tu   :` and `  leaf[ N]  :` lines. That is deliberate: it is the
# SAME dlopen + dlsym + hotswap_module_admit() code path the resident loader
# runs, not a second, independent ELF reader that could quietly drift from it.
# A module that does not ADMIT through that gauntlet has nothing this tool
# will package — there is no such thing as a manifest for an artifact that
# cannot load.
#
# hotswap_verify_so cannot dlopen the SHIPPED artifact directly: the shipped
# .so links -Wl,-z,now (Makefile HOTSWAP_MODULE_LDFLAGS), which makes the
# dynamic linker resolve every symbol at dlopen time regardless of the RTLD_*
# flags the caller passes, and the small verifier process never links the
# resident's kernel entry points (json_*, node_rpc_call_*, ...) the module
# calls — so a direct dlopen fails for a reason that says nothing about the
# module. hotswap-verify.sh works around this by relinking the module's
# cached OBJECT file with -Wl,-z,lazy instead of -Wl,-z,now (same object, same
# -Bsymbolic, only the bind-now flag changes) and dlopening THAT. This script
# reuses the identical relink recipe — CC and DEV_CFLAGS come from the same
# build/hotswap/fast/flags.env the module build wrote — but points it at a
# DIFFERENT object than hotswap-verify.sh does: not the mutable
# build/hotswap/fast/<safe>.o cache (which holds only the MOST RECENTLY built
# object for that source file and can silently belong to a different
# BUILD_SOURCE_ID than the specific .so this script was asked to package), but
# the immutable, per-artifact object `make hotswap-module-so` also writes and
# never overwrites: build/hotswap-obj/mod-<safe>-<BUILD_SOURCE_ID>.o. That
# name is derived from the .so's OWN filename, so the object relinked here is
# provably the one that produced the exact bytes being packaged. If that
# object is gone (build/hotswap-obj pruned by the epoch keeper), this refuses
# rather than substitute a different build's object for a stand-in — see
# HARD RULES below.
#
# ── WHERE core_seal_root / abi_version COME FROM ───────────────────────────
# hotswap_verify_so's CLI does not print either of these, so they cannot be
# read by parsing its output the way source_tu/leaves are. Both are read
# directly from the .so's own ELF structure instead, precisely rather than by
# scanning the whole binary for a plausible-looking value:
#
#   core_seal_root: `nm -D --defined-only` gives the EXACT virtual address of
#   the `zcl_hotswap_module_core_seal_root` symbol (the same symbol
#   hotswap_activate.c's module_consensus_pin_ok() resolves with dlsym before
#   any leaf is admitted). `readelf -SW` gives every allocated section's
#   address/file-offset/size; mapping the symbol's address into the one
#   section that contains it converts virtual address to file offset exactly
#   the way the loader's own segment mapping does. `dd` then reads precisely
#   the 64 bytes at that offset, and this script additionally checks that the
#   65th byte is the C string's NUL terminator — proof this is the WHOLE
#   string, not a truncated or run-on read. This is deliberately NOT
#   `strings <so> | grep -E '^[0-9a-f]{64}$'`: a whole-binary hex scan would
#   report any 64-hex-character run in the file (debug info, an unrelated
#   constant, padding that happens to decode as hex) with no way to tell it
#   apart from the real pin. Anchoring to the symbol's own address rules that
#   out by construction.
#
#   abi_version: `struct zcl_hotswap_module` (lib/hotswap/include/hotswap/
#   hotswap_module.h) declares `uint32_t abi_version` as its FIRST member.
#   C guarantees a struct's first named member starts at offset 0 with no
#   leading padding — that is the one struct-layout fact that does not depend
#   on compiler, alignment, or any other member's size, so reading 4 bytes at
#   the `zcl_hotswap_module` symbol's own address (found and offset-mapped the
#   same way as the seal root, above) and decoding them little-endian is a
#   precise read of exactly that field, not a hand-rolled struct parser that
#   could drift if the struct grows.
#
# Both reads are believed only as far as this comment claims: reading the
# CORRECT bytes at the CORRECT offset, nothing about the ABI's future
# stability. If ZCL_HOTSWAP_MODULE_ABI_V2 is ever retired for a v3 whose first
# member is not abi_version, this file's offset-0 assumption breaks with it —
# by construction, since that same layout is what hotswap_module_admit()
# itself must agree on. Fix in lockstep with hotswap_module.h, not in
# isolation from it.
#
# ── SHA3-256 ────────────────────────────────────────────────────────────────
# Computed IN-TREE, by the same hotswap_verify_so binary this script already
# builds and drives: `hotswap_verify_so --sha3 <file>` opens the file, hashes
# the descriptor with hotswap_artifact_sha3_fd() (lib/hotswap/src/
# hotswap_artifact_digest.c over the FIPS-202 SHA3-256 in lib/sha3), and
# prints one `artifact_sha3 : <64 hex>` line. No dlopen, no admission claim —
# just the bytes.
#
# This deliberately depends on NO host tool. The earlier form shelled out to
# `sha3sum -a 256` or `openssl dgst -sha3-256` and refused when neither
# existed, which made packaging impossible on a host that has neither (this
# repo's own build hosts among them) and made a security receipt hostage to
# whatever the distribution happened to ship. The repository rule is that we
# write our own C rather than acquire a dependency, and the SHA3-256 the
# loader itself uses was already sitting in the tree with zero callers.
#
# The digest is taken from the SHIPPED .so, never from the -z lazy re-link the
# admission check dlopens: those are different bytes, and the receipt has to
# describe the file that ships. Hence the separate --sha3 invocation on the
# artifact path rather than a field scraped out of the admission run.
#
# FAIL-CLOSED: a missing `artifact_sha3 :` line, or one that is not exactly 64
# lowercase hex characters, is fatal. There is no fallback hash and no second
# tool to try — a manifest that claims `artifact_sha3_256` while holding
# anything else would look valid and would either falsely pass (if the same
# substitution ran both times) or falsely fail, and neither announces itself.
#
# ── HARD RULES (this script refuses rather than guesses) ───────────────────
#   - zero .so files under build/hotswap/ for --all
#   - a .so path that is missing, unreadable, or whose filename does not match
#     <safe>-<64 lowercase hex>.so (the exact shape `make hotswap-module-so`
#     produces)
#   - the immutable object build/hotswap-obj/mod-<safe>-<id>.o for that exact
#     .so is missing
#   - build/hotswap/fast/flags.env (the frozen CC/DEV_CFLAGS the module was
#     built with) is missing
#   - the verifier or the lazy relink fails to build
#   - hotswap_verify_so does not report ADMITTED for the relinked object
#   - any manifest field would come out empty
#   - the verifier does not print a well-formed `artifact_sha3 :` line
# Every one of these prints a specific reason and refuses; none of them is a
# silent pass. `--verify` additionally treats any field mismatch (including a
# manifest that does not exist yet) as a FAIL, not a crash.
#
# Scratch lives under ZCL_HOTSWAP_PACKAGE_DIR (default
# ~/.local/state/zclassic23/scratch/hotswap-package), never /tmp and never
# under build/ — the lazily-bound relink artifact this script builds must
# never be mistakable for a shippable one, exactly the same reason
# hotswap-verify.sh keeps its own relinks out of build/.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

# str_contains/str_lacks — pipeline-free substring predicates. See
# tools/scripts/sh_str.sh: this script runs under `set -o pipefail`, and a
# `printf | grep -q` pipeline can report a SUCCESSFUL match as failure.
# shellcheck source=tools/scripts/sh_str.sh
. tools/scripts/sh_str.sh

SCRATCH="${ZCL_HOTSWAP_PACKAGE_DIR:-$HOME/.local/state/zclassic23/scratch/hotswap-package}"
mkdir -p "$SCRATCH" || { echo "hotswap-package: FATAL — cannot create $SCRATCH" >&2; exit 2; }

FLAGS_ENV="build/hotswap/fast/flags.env"
HOTSWAP_SO_DIR="build/hotswap"
HOTSWAP_OBJ_DIR="build/hotswap-obj"

usage() {
    echo "usage: tools/dev/hotswap-package.sh <module.so>" >&2
    echo "       tools/dev/hotswap-package.sh --verify <module.so>" >&2
    echo "       tools/dev/hotswap-package.sh --verify --all" >&2
    echo "       tools/dev/hotswap-package.sh --all" >&2
}

fatal() { echo "hotswap-package: FATAL — $*" >&2; exit 2; }

# ── SHA3-256, in-tree, no host tool, no fallback ────────────────────────────
# See the SHA3-256 section of the header comment. Two distinct failure classes,
# kept distinct on purpose:
#   - the verifier exits non-zero (unreadable file, hash failed): a PER-ARTIFACT
#     failure, reported by the caller and counted against that artifact only.
#   - the verifier exits zero but printed no well-formed `artifact_sha3 :`
#     line: the tool's own contract is broken, which is true for every artifact
#     in the run, so refuse the whole run rather than write manifests around it.
# Sets the global SHA3_DIGEST (never stdout): `fatal` must abort the WHOLE run,
# and `exit` inside a $(...) command substitution only kills the subshell,
# which would silently demote a broken-tool FATAL to a per-artifact FAIL.
SHA3_DIGEST=""
compute_sha3() {  # <file> -> 0 with SHA3_DIGEST set, 1 on a per-artifact failure
    local f="$1"
    SHA3_DIGEST=""
    ensure_verifier_built
    if ! "$VERIFIER_BIN" --sha3 "$f" >"$SCRATCH/sha3.out" 2>"$SCRATCH/sha3.err"; then
        sed 's/^/    /' "$SCRATCH/sha3.err" >&2
        return 1
    fi
    local digest
    digest="$(sed -n 's/^artifact_sha3 : //p' "$SCRATCH/sha3.out")"
    if [ -z "$digest" ]; then
        fatal "hotswap_verify_so --sha3 '$f' printed no 'artifact_sha3 :' line; refusing to write a manifest without an artifact digest"
    fi
    if [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
        fatal "hotswap_verify_so --sha3 '$f' printed a malformed digest '$digest' (want exactly 64 lowercase hex characters); refusing to record it"
    fi
    SHA3_DIGEST="$digest"
    return 0
}

command -v nm >/dev/null 2>&1 || fatal "nm not found; cannot read the module's symbol table"
command -v readelf >/dev/null 2>&1 || fatal "readelf not found; cannot map a symbol address to a file offset"
command -v dd >/dev/null 2>&1 || fatal "dd not found; cannot read exact bytes from the .so"

# ── ELF address -> file-offset plumbing ─────────────────────────────────────

# symbol_addr <so> <symbol> -> hex address on stdout; empty + return 1 if the
# symbol is not a defined dynamic symbol.
symbol_addr() {
    local so="$1" sym="$2"
    if ! nm -D --defined-only "$so" >"$SCRATCH/nm.out" 2>"$SCRATCH/nm.err"; then
        return 1
    fi
    local addr
    addr="$(awk -v s="$sym" '$3==s{print $1}' "$SCRATCH/nm.out")"
    [ -n "$addr" ] || return 1
    printf '%s\n' "$addr"
}

# build_section_table <so> -> writes bracket-stripped `readelf -SW` rows to
# $SCRATCH/sections.txt, one section per line: Name Type Address Off Size ...
# readelf -SW's own "[ N]"/"[NN]" index column loses its separating space once
# the index reaches two digits, which silently shifts every later awk field by
# one for section 10 onward. Stripping the whole bracket group up front before
# any field-number-based parsing avoids that trap entirely.
build_section_table() {
    local so="$1"
    if ! readelf -SW "$so" >"$SCRATCH/readelf.out" 2>"$SCRATCH/readelf.err"; then
        return 1
    fi
    sed -E 's/^ *\[[ 0-9]+\] *//' "$SCRATCH/readelf.out" > "$SCRATCH/sections.txt"
    return 0
}

# file_offset_for_addr <hex_addr> -> file offset (decimal) on stdout, using
# the table build_section_table just wrote. Only ALLOC sections with real
# file content (PROGBITS) can be mapped this way; NOBITS (.bss) has no file
# bytes and PROGBITS/NOBITS sections without the 'A' flag are debug sections
# whose Address column is always 0 and would otherwise collide.
file_offset_for_addr() {
    local addr_hex="$1"
    local off
    off="$(awk -v ah="$addr_hex" '
        NF>=7 && $2=="PROGBITS" && $7 ~ /A/ {
            sec_addr = strtonum("0x" $3)
            sec_off  = strtonum("0x" $4)
            sec_size = strtonum("0x" $5)
            a = strtonum("0x" ah)
            if (a >= sec_addr && a < sec_addr + sec_size) {
                printf "%d\n", sec_off + (a - sec_addr)
            }
        }
    ' "$SCRATCH/sections.txt")"
    [ -n "$off" ] || return 1
    printf '%s\n' "$off"
}

# read_core_seal_root <so> -> 64 lowercase hex on stdout
read_core_seal_root() {
    local so="$1" addr off val nul
    addr="$(symbol_addr "$so" zcl_hotswap_module_core_seal_root)" || return 1
    off="$(file_offset_for_addr "$addr")" || return 1
    if ! dd if="$so" bs=1 skip="$off" count=64 of="$SCRATCH/seal.bin" 2>"$SCRATCH/dd.err"; then
        return 1
    fi
    [ "$(stat -c%s "$SCRATCH/seal.bin" 2>/dev/null)" = "64" ] || return 1
    val="$(cat "$SCRATCH/seal.bin")"
    [[ "$val" =~ ^[0-9a-f]{64}$ ]] || return 1
    # Confirm the 65th byte is the string's NUL terminator, i.e. this is the
    # WHOLE string and not a truncated read of a longer one.
    if ! dd if="$so" bs=1 skip=$((off + 64)) count=1 of="$SCRATCH/seal.nul" 2>"$SCRATCH/dd2.err"; then
        return 1
    fi
    nul="$(od -An -tu1 "$SCRATCH/seal.nul" | tr -d ' \n')"
    [ "$nul" = "0" ] || return 1
    printf '%s\n' "$val"
}

# read_abi_version <so> -> decimal integer on stdout
read_abi_version() {
    local so="$1" addr off b0 b1 b2 b3
    addr="$(symbol_addr "$so" zcl_hotswap_module)" || return 1
    off="$(file_offset_for_addr "$addr")" || return 1
    if ! dd if="$so" bs=1 skip="$off" count=4 of="$SCRATCH/abi.bin" 2>"$SCRATCH/dd3.err"; then
        return 1
    fi
    [ "$(stat -c%s "$SCRATCH/abi.bin" 2>/dev/null)" = "4" ] || return 1
    read -r b0 b1 b2 b3 <<<"$(od -An -tu1 "$SCRATCH/abi.bin")"
    [ -n "${b3:-}" ] || return 1
    printf '%d\n' "$((b0 + (b1 << 8) + (b2 << 16) + (b3 << 24)))"
}

# ── verifier (built once per run, on first need) ────────────────────────────
VERIFIER_BUILT=0
VERIFIER_BIN="$SCRATCH/hotswap_verify_so"
ensure_verifier_built() {
    [ "$VERIFIER_BUILT" -eq 1 ] && return 0
    [ -r "$FLAGS_ENV" ] || fatal "$FLAGS_ENV missing — run 'make hotswap-module-so FILE=<tu>' once first"
    local cc cflags
    cc="$(sed -n 's/^CC=//p' "$FLAGS_ENV")"
    cflags="$(sed -n 's/^DEV_CFLAGS=//p' "$FLAGS_ENV")"
    { [ -n "$cc" ] && [ -n "$cflags" ]; } || fatal "could not parse CC/DEV_CFLAGS from $FLAGS_ENV"
    # shellcheck disable=SC2086
    if ! $cc $cflags -ffunction-sections -fdata-sections \
            -o "$VERIFIER_BIN" \
            tools/dev/hotswap_verify_so.c \
            lib/hotswap/src/hotswap_activate.c \
            lib/hotswap/src/hotswap_islands.c \
            lib/hotswap/src/hotswap_artifact_digest.c \
            lib/sha3/src/sha3.c \
            -Wl,--gc-sections -ldl 2>"$SCRATCH/verifier_build.log"; then
        sed 's/^/    /' "$SCRATCH/verifier_build.log" >&2
        fatal "verifier build failed"
    fi
    CC_CACHED="$cc"
    VERIFIER_BUILT=1
    return 0
}

# relink_lazy <object> <out_so> -> re-link the module object with -z lazy
# instead of -z now, the same recipe hotswap-verify.sh uses (same object, same
# -Bsymbolic, only the bind-now flag changes) so the small verifier process
# (which never exports the resident node's kernel symbols) can dlopen it.
relink_lazy() {
    local obj="$1" out="$2"
    # CC_CACHED may be a multi-word compiler wrapper (e.g. "zcc cc"), same as
    # every other CC-driving recipe in this tree, so it must be word-split,
    # not quoted as one token.
    # shellcheck disable=SC2086
    if ! $CC_CACHED -shared -Wl,--build-id=none -Wl,-z,relro -Wl,-z,lazy \
             -Wl,-z,noexecstack -Wl,-Bsymbolic \
             -o "$out" "$obj" 2>"$SCRATCH/link.log"; then
        return 1
    fi
    return 0
}

# ── per-artifact field extraction ───────────────────────────────────────────
# Globals filled by extract_fields on success: F_SOURCE_TU F_LEAVES
# F_CORE_SEAL_ROOT F_ARTIFACT_SHA3 F_ABI_VERSION F_BUILT_FROM
F_SOURCE_TU=""; F_LEAVES=""; F_CORE_SEAL_ROOT=""; F_ARTIFACT_SHA3=""
F_ABI_VERSION=""; F_BUILT_FROM=""

# extract_fields <so> -> 0 on success (globals filled), 1 on any per-artifact
# failure (message already printed to stderr — never silent).
extract_fields() {
    local so="$1" base safe build_id obj lazy_so digest seal abi source_tu leaves

    [ -r "$so" ] || { echo "  FAIL: $so is not a readable file" >&2; return 1; }

    base="$(basename "$so")"
    if [[ ! "$base" =~ ^(.+)-([0-9a-f]{64})\.so$ ]]; then
        echo "  FAIL: $base does not match <safe_tu>-<64 lowercase hex>.so" >&2
        return 1
    fi
    safe="${BASH_REMATCH[1]}"
    build_id="${BASH_REMATCH[2]}"

    compute_sha3 "$so" || { echo "  FAIL: sha3 digest of $so failed" >&2; return 1; }
    digest="$SHA3_DIGEST"

    obj="$HOTSWAP_OBJ_DIR/mod-$safe-$build_id.o"
    [ -f "$obj" ] || {
        echo "  FAIL: no matching immutable object $obj for this artifact" >&2
        echo "        (build/hotswap-obj may have been pruned; rebuild this exact" >&2
        echo "        module with 'make hotswap-module-so' to regenerate it)" >&2
        return 1
    }

    ensure_verifier_built

    lazy_so="$SCRATCH/$safe-$build_id.verify.so"
    if ! relink_lazy "$obj" "$lazy_so"; then
        echo "  FAIL: verification re-link of $obj failed" >&2
        sed 's/^/    /' "$SCRATCH/link.log" >&2
        return 1
    fi

    if ! "$VERIFIER_BIN" "$lazy_so" >"$SCRATCH/verify.out" 2>&1; then
        echo "  FAIL: $so did not ADMIT (hotswap_verify_module_so):" >&2
        sed 's/^/    /' "$SCRATCH/verify.out" >&2
        return 1
    fi

    source_tu="$(sed -n 's/^source_tu   : //p' "$SCRATCH/verify.out")"
    [ -n "$source_tu" ] || { echo "  FAIL: $so: verifier printed no source_tu" >&2; return 1; }

    leaves="$(sed -n 's/^  leaf\[[ 0-9]*\]  : //p' "$SCRATCH/verify.out" | tr '\n' ' ')"
    leaves="${leaves% }"
    [ -n "$leaves" ] || { echo "  FAIL: $so: verifier printed zero leaves" >&2; return 1; }

    build_section_table "$so" || { echo "  FAIL: $so: readelf -SW failed" >&2; return 1; }

    seal="$(read_core_seal_root "$so")" || {
        echo "  FAIL: $so: could not read zcl_hotswap_module_core_seal_root" >&2
        return 1
    }
    abi="$(read_abi_version "$so")" || {
        echo "  FAIL: $so: could not read abi_version from zcl_hotswap_module" >&2
        return 1
    }

    F_SOURCE_TU="$source_tu"
    F_LEAVES="$leaves"
    F_CORE_SEAL_ROOT="$seal"
    F_ARTIFACT_SHA3="$digest"
    F_ABI_VERSION="$abi"
    F_BUILT_FROM="$build_id"
    return 0
}

write_manifest_lines() {
    # Sorted, one key=value per line. Plain `sort` orders these correctly by
    # key because '=' (0x3D) sorts before every lowercase letter, so no two
    # keys' prefixes can cross.
    {
        printf 'abi_version=%s\n' "$F_ABI_VERSION"
        printf 'artifact_sha3_256=%s\n' "$F_ARTIFACT_SHA3"
        printf 'built_from=%s\n' "$F_BUILT_FROM"
        printf 'core_seal_root=%s\n' "$F_CORE_SEAL_ROOT"
        printf 'leaves=%s\n' "$F_LEAVES"
        printf 'schema=zcl.hotswap_package.v1\n'
        printf 'source_tu=%s\n' "$F_SOURCE_TU"
    } | sort
}

# ── modes ────────────────────────────────────────────────────────────────────

do_write() {  # <so> -> 0 on success, 1 on failure (already reported)
    local so="$1" manifest tmp
    extract_fields "$so" || return 1
    manifest="$so.manifest"
    tmp="$(mktemp "$SCRATCH/.manifest.XXXXXX")"
    write_manifest_lines > "$tmp"
    if ! mv -f "$tmp" "$manifest"; then
        echo "  FAIL: could not write $manifest" >&2
        rm -f "$tmp"
        return 1
    fi
    echo "  OK: wrote $manifest"
    sed 's/^/    /' "$manifest"
    return 0
}

do_verify() {  # <so> -> 0 on match, 1 on any mismatch/missing manifest
    local so="$1" manifest fresh_digest stored_digest mismatch=0
    manifest="$so.manifest"
    [ -r "$manifest" ] || {
        echo "  FAIL: $manifest does not exist (run without --verify to create it)" >&2
        return 1
    }

    compute_sha3 "$so" || {
        echo "  FAIL: sha3 digest of $so failed" >&2
        return 1
    }
    fresh_digest="$SHA3_DIGEST"
    stored_digest="$(sed -n 's/^artifact_sha3_256=//p' "$manifest")"
    if [ "$fresh_digest" != "$stored_digest" ]; then
        echo "  FAIL: $so: artifact_sha3_256 mismatch" >&2
        echo "        manifest : ${stored_digest:-<missing>}" >&2
        echo "        actual   : $fresh_digest" >&2
        echo "        the artifact bytes changed since this manifest was written" >&2
        return 1
    fi

    # Digest matches, so the artifact is byte-identical to what produced the
    # stored manifest. Recompute everything else anyway: a manifest can be
    # hand-edited to keep a correct digest while lying about the rest.
    extract_fields "$so" || return 1

    declare -A stored
    while IFS='=' read -r k v; do
        [ -n "$k" ] || continue
        stored["$k"]="$v"
    done < "$manifest"

    check_field() {
        local name="$1" actual="$2"
        if [ "${stored[$name]-}" != "$actual" ]; then
            echo "  FAIL: $so: $name mismatch" >&2
            echo "        manifest : ${stored[$name]-<missing>}" >&2
            echo "        actual   : $actual" >&2
            mismatch=1
        fi
    }
    check_field "source_tu" "$F_SOURCE_TU"
    check_field "leaves" "$F_LEAVES"
    check_field "core_seal_root" "$F_CORE_SEAL_ROOT"
    check_field "artifact_sha3_256" "$F_ARTIFACT_SHA3"
    check_field "abi_version" "$F_ABI_VERSION"
    check_field "built_from" "$F_BUILT_FROM"
    check_field "schema" "zcl.hotswap_package.v1"

    [ "$mismatch" -eq 0 ] || return 1
    echo "  OK: $manifest matches $so"
    return 0
}

# ── argument parsing ─────────────────────────────────────────────────────────
MODE="write"
TARGETS=()

case "${1:-}" in
    -h|--help|"")
        usage; exit 2 ;;
    --verify)
        MODE="verify"
        case "${2:-}" in
            --all)
                mapfile -t TARGETS < <(ls -1 "$HOTSWAP_SO_DIR"/*.so 2>/dev/null)
                ;;
            "")
                usage; exit 2 ;;
            *)
                TARGETS=("$2") ;;
        esac
        ;;
    --all)
        mapfile -t TARGETS < <(ls -1 "$HOTSWAP_SO_DIR"/*.so 2>/dev/null)
        ;;
    -*)
        usage; exit 2 ;;
    *)
        TARGETS=("$1") ;;
esac

if [ "${#TARGETS[@]}" -eq 0 ]; then
    fatal "no .so files found under $HOTSWAP_SO_DIR/ — nothing to $MODE"
fi

echo "══ hot-swap module packaging ($MODE, ${#TARGETS[@]} artifact(s)) ══"

pass=0
fail=0
for so in "${TARGETS[@]}"; do
    [ -n "$so" ] || continue
    echo
    echo "── $so"
    if [ "$MODE" = "write" ]; then
        if do_write "$so"; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
    else
        if do_verify "$so"; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
    fi
done

echo
if [ "$fail" -ne 0 ]; then
    echo "FAIL: $fail of $((pass + fail)) artifact(s) failed to $MODE"
    exit 1
fi
if [ "$pass" -eq 0 ]; then
    echo "hotswap-package: FATAL — zero artifacts processed; refusing to report success" >&2
    exit 2
fi
echo "OK: $pass artifact(s) processed successfully ($MODE)"
exit 0
