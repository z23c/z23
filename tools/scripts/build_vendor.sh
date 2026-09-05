#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# tools/scripts/build_vendor.sh — produce every vendor/lib/*.a from source.
#
# Goal: `git clone && make vendor && make zclassic23` LINKS in one shot.
# zclassic23 links against a fixed set of static third-party archives in
# vendor/lib/. Only libsecp256k1.a is committed to git; the rest are built
# here, from source, with pinned versions + SHA256-verified downloads.
#
# Two source classes:
#   IN-TREE  — built from a source file already in the repo (no network):
#                libtor_stub.a  <- vendor/tor_stub.c
#   FETCHED  — no in-tree source; tarball pulled from a pinned URL, verified
#              against a pinned SHA256, then built static:
#                libsqlite3.a                          (SQLite amalgamation)
#                libcrypto.a, libssl.a                 (OpenSSL)
#                libevent.a, libevent_openssl.a,
#                libevent_pthreads.a                   (libevent)
#                libleveldb.a                          (LevelDB)
#                libz.a                                (zlib)
#
# Idempotent by PROVENANCE, not existence: an archive is skipped only when its
# deterministic stamp matches the source pin, recipe revision/flags, relevant
# dependency stamps, toolchain identity, and the archive's current SHA256.
# Missing/mismatched stamps rebuild. Force a full rebuild with VENDOR_FORCE=1.
# Downloads are cached under vendor/.cache/ (gitignored).
#
# Usage:
#   tools/scripts/build_vendor.sh            # build only what's missing
#   VENDOR_FORCE=1 tools/scripts/build_vendor.sh
#   tools/scripts/build_vendor.sh libz.a libsqlite3.a   # build a subset
#   tools/scripts/build_vendor.sh --check-provenance    # read-only verification

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENDOR="$REPO_ROOT/vendor"
LIB="$VENDOR/lib"
INC="$VENDOR/include"
CACHE="$VENDOR/.cache"
WORK="$VENDOR/.build"
SECP_MANIFEST="$VENDOR/provenance/libsecp256k1.manifest"
LIBEVENT_PATCH="$VENDOR/patches/libevent-2.1.12-secure-rng-abi.patch"

# --- cross targets ---------------------------------------------------------
# vendor/lib holds ONE target: a single slot per archive name, no target
# segment, so a host libz.a and a cross libz.a would occupy the same path (see
# vendor_require_same_machine below, which exists because that collision is
# otherwise silent). A release for another platform therefore cannot reuse
# that tree — it needs its own.
#
# VENDOR_TARGET=<triple> gives it one: every output moves under
# vendor/cross/<triple>/{lib,include}, the build scratch and the build lock
# move with it, and the compiler defaults to <triple>-gcc / <triple>-ar. The
# pinned versions, SHA256s, patches and recipes above stay the single copy —
# a second script restating them is exactly the divergence this repository
# refuses. Downloads stay in the shared vendor/.cache: a source tarball is
# target-independent, and its pin is verified on every read.
#
# The host build is unchanged when VENDOR_TARGET is unset: same paths, same
# defaults, and — because nothing below appends cross-only text to a recipe
# unless VENDOR_TARGET is set — the same provenance descriptors, so no
# existing stamp is invalidated by this capability existing.
VENDOR_TARGET="${VENDOR_TARGET:-}"
if [[ -n "$VENDOR_TARGET" ]]; then
    case "$VENDOR_TARGET" in
        *[!A-Za-z0-9_.-]*|"")
            printf '\033[31m[vendor] ERROR:\033[0m VENDOR_TARGET must be a bare toolchain triple\n' >&2
            exit 1
            ;;
    esac
    LIB="$VENDOR/cross/$VENDOR_TARGET/lib"
    INC="$VENDOR/cross/$VENDOR_TARGET/include"
    WORK="$VENDOR/.build-$VENDOR_TARGET"
    VENDOR_CC="${VENDOR_CC:-$VENDOR_TARGET-gcc}"
    VENDOR_AR="${VENDOR_AR:-$VENDOR_TARGET-ar}"
    VENDOR_LOCK_DIR="${VENDOR_LOCK_DIR:-$VENDOR/.build-$VENDOR_TARGET.lock}"
fi

# shellcheck source=tools/scripts/vendor_provenance_lib.sh
. "$SCRIPT_DIR/vendor_provenance_lib.sh"

# JOBS: an explicit value from the environment always wins (the caller, or a
# Makefile that exports JOBS=<n> ahead of this script). Otherwise honour the
# caller's `make -jN`: the Makefile invokes this script with no argument, but
# GNU Make exports MAKEFLAGS into the environment of every recipe subprocess
# it spawns, this script included, so `make -j2 vendor` must not spawn one
# submake per core. Only when neither is given do we fall back to a default
# that leaves headroom on big boxes.
CPU_COUNT="$(nproc 2>/dev/null || echo 4)"
if [[ -z "${JOBS:-}" ]]; then
    if [[ "${MAKEFLAGS:-}" =~ (^|[[:space:]])-j([0-9]+) ]]; then
        JOBS="${BASH_REMATCH[2]}"
    elif [[ "${MAKEFLAGS:-}" =~ --jobs=([0-9]+) ]]; then
        JOBS="${BASH_REMATCH[1]}"
    elif [[ "$CPU_COUNT" -ge 16 ]]; then
        JOBS=$((CPU_COUNT - 8))
    else
        JOBS="$CPU_COUNT"
    fi
fi
FORCE="${VENDOR_FORCE:-0}"
OFFLINE="${ZCL_VENDOR_OFFLINE:-0}"
VENDOR_LOCK_DIR="${VENDOR_LOCK_DIR:-$VENDOR/.build.lock}"
VENDOR_LOCK_TIMEOUT_SEC="${VENDOR_LOCK_TIMEOUT_SEC:-600}"
[[ "$OFFLINE" == "0" || "$OFFLINE" == "1" ]] || {
    printf '\033[31m[vendor] ERROR:\033[0m ZCL_VENDOR_OFFLINE must be 0 or 1\n' >&2
    exit 1
}

# --- pinned versions + SHA256 (verified upstream-published hashes) ----------
SQLITE_YEAR="2025"
SQLITE_AMALG="sqlite-amalgamation-3490000"   # SQLite 3.49.0
SQLITE_URL="https://www.sqlite.org/${SQLITE_YEAR}/${SQLITE_AMALG}.zip"
SQLITE_SHA="cb6851ebad74913672014c20f642bbd7883552c4747780583a54ee1cd493f13b"
SQLITE_C_SHA="032f545fd56206903bf25309714acb924504ab599f80b51002b89d08579b0485"
SQLITE_H_SHA="003d87c193f4a0e363543905deabd377924f03437e068823ec6b674a0fe31eba"

OPENSSL_VER="3.0.16"                          # >= project min-safe floor (3.0.16)
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VER}/openssl-${OPENSSL_VER}.tar.gz"
OPENSSL_SHA="57e03c50feab5d31b152af2b764f10379aecd8ee92f16c985983ce4a99f7ef86"

LIBEVENT_VER="2.1.12"
LIBEVENT_URL="https://github.com/libevent/libevent/releases/download/release-${LIBEVENT_VER}-stable/libevent-${LIBEVENT_VER}-stable.tar.gz"
LIBEVENT_SHA="92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb"

LEVELDB_VER="1.23"                            # C API (leveldb/c.h) compatible w/ tracked 1.18 headers
LEVELDB_URL="https://github.com/google/leveldb/archive/refs/tags/${LEVELDB_VER}.tar.gz"
LEVELDB_SHA="9a37f8a6174f09bd622bc723b55881dc541cd50747cbd08831c2a82d620f6d76"

SECP_VER="0.8.0"
SECP_URL="https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v${SECP_VER}.tar.gz"
SECP_SHA="eb52b0e9239dff7dc26be5f9623567141b8720ec47da29eb3c1e0a660d17c8bb"

ZLIB_VER="1.3.1"                              # 1.3 line, clean of CVE-2022-37434
ZLIB_URL="https://github.com/madler/zlib/releases/download/v${ZLIB_VER}/zlib-${ZLIB_VER}.tar.gz"
ZLIB_SHA="9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"

# Reproducibility: pin the build epoch + strip nondeterministic ar metadata.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"
export TZ=UTC LC_ALL=C
ARFLAGS_DET="Dcr"   # D = deterministic (zero mtime/uid/gid) when supported
VENDOR_CC="${VENDOR_CC:-cc}"
VENDOR_AR="${VENDOR_AR:-ar}"

# Every archive in vendor/lib must be built by ONE toolchain targeting ONE
# machine. Nothing downstream can tell otherwise: vendor/lib holds a single
# slot per archive name with no target segment, so a host-built libz.a and a
# cross-built libz.a occupy the same path and link into the same binary. The
# checks below refuse the mixed-toolchain cases that are otherwise silent.
vendor_cc_machine()
{
    # Only a selector input is derived here. vp_compiler_identity_sha folds
    # -dumpmachine into the provenance hash too, but it deliberately swallows
    # failure into an empty string, which is fine for a hash and useless for a
    # decision. So probe separately and fail closed.
    "$1" -dumpmachine 2>/dev/null | sed -n '1p'
}

VENDOR_CC_MACHINE="$(vendor_cc_machine "$VENDOR_CC")"

# LevelDB is the one C++ archive. leveldb_cxx_compiler() falls back to $CXX,
# then c++, then g++ -- none of which consults VENDOR_CC. Setting VENDOR_CC to
# a cross compiler and leaving CXX unset therefore produced a host-targeted
# libleveldb.a beside cross-targeted C archives, with no diagnostic anywhere.
vendor_require_same_machine()
{
    local what="$1" tool="$2" machine
    [ -n "$VENDOR_CC_MACHINE" ] || return 0
    command -v "$tool" >/dev/null 2>&1 || return 0
    machine="$(vendor_cc_machine "$tool")"
    [ -n "$machine" ] || return 0
    [ "$machine" = "$VENDOR_CC_MACHINE" ] && return 0
    die "$what ($tool) targets $machine but VENDOR_CC ($VENDOR_CC) targets \
$VENDOR_CC_MACHINE -- vendor/lib cannot hold two targets at once"
}
# Which OS the archives are FOR — read from the compiler's own target, never
# from uname. On a native MSYS2/Darwin host the two agree, so this changes no
# existing decision; on a cross build uname describes the wrong machine and
# would silently select the POSIX recipes for a Windows archive set.
vendor_target_os() {
    case "$VENDOR_CC_MACHINE" in
        *mingw*|*cygwin*|*windows*) printf 'windows'; return ;;
        *darwin*|*apple*) printf 'darwin'; return ;;
        ?*) printf 'posix'; return ;;
    esac
    # -dumpmachine failed (it is allowed to: see vendor_cc_machine). Fall back
    # to the host, which is what every decision here used before.
    case "$(uname -s 2>/dev/null)" in
        MINGW*|MSYS*|CYGWIN*) printf 'windows' ;;
        Darwin) printf 'darwin' ;;
        *) printf 'posix' ;;
    esac
}
VENDOR_TARGET_OS="$(vendor_target_os)"
if [[ "$VENDOR_TARGET_OS" == darwin ]]; then
    MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
    [[ "$MACOSX_DEPLOYMENT_TARGET" == "14.0" ]] ||
        die "Darwin vendor archives require MACOSX_DEPLOYMENT_TARGET=14.0"
    export MACOSX_DEPLOYMENT_TARGET
fi

# OpenSSL cannot infer a supported target from the MSYS2 host name even for a
# native MinGW build, and it cannot probe any cross target. Name Windows
# targets in both cases. Native Darwin and POSIX builds retain autodetection;
# Darwin cross builds still name their target explicitly.
OPENSSL_CONFIG_TARGET=""
if [[ "$VENDOR_TARGET_OS" == windows ]]; then
    case "$VENDOR_TARGET_OS:$VENDOR_CC_MACHINE" in
        windows:x86_64-*) OPENSSL_CONFIG_TARGET="mingw64" ;;
        windows:i686-*|windows:i586-*) OPENSSL_CONFIG_TARGET="mingw" ;;
        *)
            printf '\033[31m[vendor] ERROR:\033[0m no OpenSSL config target known for native Windows compiler %s\n' \
                "$VENDOR_CC_MACHINE" >&2
            exit 1
            ;;
    esac
elif [[ -n "$VENDOR_TARGET" ]]; then
    case "$VENDOR_TARGET_OS:$VENDOR_CC_MACHINE" in
        darwin:x86_64-*) OPENSSL_CONFIG_TARGET="darwin64-x86_64-cc" ;;
        darwin:arm64-*|darwin:aarch64-*) OPENSSL_CONFIG_TARGET="darwin64-arm64-cc" ;;
        *)
            printf '\033[31m[vendor] ERROR:\033[0m no OpenSSL config target known for %s (%s)\n' \
                "$VENDOR_TARGET" "$VENDOR_CC_MACHINE" >&2
            exit 1
            ;;
    esac
fi
# C23 has two spellings: GCC 14+ accepts -std=c23, GCC 13 only the earlier
# -std=c2x for the same language mode. The Debian/Ubuntu mingw-w64 packages
# are GCC 13, so a cross build must ask the compiler rather than assume. The
# host compiler answers c23 first, so the host flag string — and therefore the
# host provenance descriptor — is exactly what it was.
vendor_c_std() {
    local std
    for std in c23 c2x; do
        if printf 'int main(void){return 0;}\n' |
            "$VENDOR_CC" -std="$std" -fsyntax-only -x c - 2>/dev/null; then
            printf -- '-std=%s' "$std"
            return 0
        fi
    done
    printf '\033[31m[vendor] ERROR:\033[0m %s accepts neither -std=c23 nor -std=c2x\n' \
        "$VENDOR_CC" >&2
    exit 1
}
VENDOR_C_STD="$(vendor_c_std)"

# Every cross builder below takes the same autotools/cmake host argument; the
# host build passes none, so its command lines are byte-identical to before.
VENDOR_CROSS_HOST_ARGS=()
[[ -n "$VENDOR_TARGET" ]] && VENDOR_CROSS_HOST_ARGS=(--host="$VENDOR_TARGET")
VENDOR_RANLIB="${VENDOR_RANLIB:-$(if [[ -n "$VENDOR_TARGET" ]]; then printf '%s' "$VENDOR_TARGET-ranlib"; else printf 'ranlib'; fi)}"

# libevent's configure decides whether to build libevent_openssl.a by LINKING
# a probe against SSL_new. A static OpenSSL on Windows pulls in crypt32,
# ws2_32 and friends, so without them the probe fails to link, configure
# reports "openssl is a must but can not be found" while its own header checks
# passed, and the archive the node links would silently not exist. These are
# the same system libraries ZCL_PLATFORM_NODE_LIBS hands the final link.
# Empty off Windows, so the host configure environment is unchanged.
LIBEVENT_CONFIGURE_LIBS=""
LIBEVENT_CPPFLAGS="-I$INC"
LIBEVENT_THREAD_ARCHIVE="libevent_pthreads.a"
LEVELDB_PLATFORM="LEVELDB_PLATFORM_POSIX; env_posix.cc"
case "$VENDOR_TARGET_OS" in
    windows)
        # Current MinGW-w64 headers expose the iphlpapi declarations used by
        # libevent only when the supported Windows API floor is explicit.
        LIBEVENT_CPPFLAGS="$LIBEVENT_CPPFLAGS -D_WIN32_WINNT=0x0600"
        LIBEVENT_THREAD_ARCHIVE="windows-threads-in-libevent.a; empty compatibility archive"
        LIBEVENT_CONFIGURE_LIBS="-lssl -lcrypto -lcrypt32 -lws2_32 -lgdi32 -ladvapi32 -luser32"
        LEVELDB_PLATFORM="LEVELDB_PLATFORM_WINDOWS; env_windows.cc"
        ;;
esac

# Recipe revisions are part of every expected stamp. Bump the affected value
# whenever its commands or semantic flags change. Exact flags and toolchain
# identities are bound separately, so pin/tool upgrades invalidate without a
# manual revision bump.
PROVENANCE_CONTRACT_REV="vp3"
RECIPE_TOR_STUB="tor-stub-r2"
RECIPE_SQLITE="sqlite-r2"
RECIPE_ZLIB="zlib-r2"
RECIPE_OPENSSL="openssl-r5"
# r6: the pinned secure-rng ABI patch grew a second hunk (it now unguards the
# evutil_secure_rng_add_bytes DECLARATION in include/event2/util.h, not only its
# definition in evutil_rand.c), and the recipe now stages event2/ headers. The
# patch is a semantic input to the compile, so the revision moves with it.
RECIPE_LIBEVENT="libevent-r6"
RECIPE_LEVELDB="leveldb-r7"
RECIPE_SECP_NATIVE="secp-native-r1"

# --- logging (to stderr; stdout is reserved for fetch() to echo a path) -----
say()  { printf '\033[36m[vendor]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[32m[vendor]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[vendor] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"; }

release_vendor_lock() {
    if [[ "${VENDOR_LOCK_HELD:-0}" == "1" ]]; then
        rmdir "$VENDOR_LOCK_DIR" 2>/dev/null || true
        VENDOR_LOCK_HELD=0
    fi
}

acquire_vendor_lock() {
    local waited=0
    while ! mkdir "$VENDOR_LOCK_DIR" 2>/dev/null; do
        if (( waited >= VENDOR_LOCK_TIMEOUT_SEC )); then
            die "timed out waiting for vendor build lock: $VENDOR_LOCK_DIR"
        fi
        sleep 1
        waited=$((waited + 1))
    done
    VENDOR_LOCK_HELD=1
    trap release_vendor_lock EXIT INT TERM
}

# --- download + verify ------------------------------------------------------
fetch() {
    # fetch <url> <sha256> <dest-filename>  -> echoes cached path
    local url="$1" sha="$2" dest="$CACHE/$3"
    mkdir -p "$CACHE"
    if [[ -f "$dest" && "$(vp_sha256_file "$dest")" == "$sha" ]]; then
        say "cached  $(basename "$dest")"
    else
        [[ "$OFFLINE" == "1" ]] &&
            die "offline cache miss or checksum failure: $(basename "$dest")"
        say "fetch   $url"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL --retry 3 -o "$dest.tmp" "$url"
        else
            need wget; wget -q -O "$dest.tmp" "$url"
        fi
        [[ "$(vp_sha256_file "$dest.tmp")" == "$sha" ]] \
            || die "SHA256 mismatch for $url (expected $sha)"
        mv "$dest.tmp" "$dest"
    fi
    echo "$dest"
}

archive_group() {
    case "$1" in
        libtor_stub.a) printf 'tor_stub' ;;
        libsqlite3.a) printf 'sqlite' ;;
        libz.a) printf 'zlib' ;;
        libcrypto.a|libssl.a) printf 'openssl' ;;
        libevent.a|libevent_openssl.a|libevent_pthreads.a) printf 'libevent' ;;
        libleveldb.a) printf 'leveldb' ;;
        libsecp256k1-darwin.a|libsecp256k1-windows.a) printf 'secp_native' ;;
        *) return 1 ;;
    esac
}

recipe_revision() {
    case "$1" in
        tor_stub) printf '%s' "$RECIPE_TOR_STUB" ;;
        sqlite) printf '%s' "$RECIPE_SQLITE" ;;
        zlib) printf '%s' "$RECIPE_ZLIB" ;;
        openssl) printf '%s' "$RECIPE_OPENSSL" ;;
        libevent) printf '%s' "$RECIPE_LIBEVENT" ;;
        leveldb) printf '%s' "$RECIPE_LEVELDB" ;;
        secp_native) printf '%s' "$RECIPE_SECP_NATIVE" ;;
        *) return 1 ;;
    esac
}

recipe_source_fields() {
    case "$1" in
        tor_stub)
            printf 'version=in-tree\nsource_url=in-tree:vendor/tor_stub.c\nsource_sha256=%s\n' \
                "$(vp_sha256_file "$VENDOR/tor_stub.c")"
            ;;
        sqlite)
            printf 'version=%s\nsource_url=%s\nsource_sha256=%s\n' \
                "${SQLITE_AMALG#sqlite-amalgamation-}" "$SQLITE_URL" "$SQLITE_SHA"
            ;;
        zlib)
            printf 'version=%s\nsource_url=%s\nsource_sha256=%s\n' \
                "$ZLIB_VER" "$ZLIB_URL" "$ZLIB_SHA"
            ;;
        openssl)
            printf 'version=%s\nsource_url=%s\nsource_sha256=%s\n' \
                "$OPENSSL_VER" "$OPENSSL_URL" "$OPENSSL_SHA"
            ;;
        libevent)
            printf 'version=%s\nsource_url=%s\nsource_sha256=%s\nsource_patch=%s\nsource_patch_sha256=%s\n' \
                "$LIBEVENT_VER" "$LIBEVENT_URL" "$LIBEVENT_SHA" \
                "vendor/patches/$(basename "$LIBEVENT_PATCH")" \
                "$(vp_sha256_file "$LIBEVENT_PATCH")"
            ;;
        leveldb)
            printf 'version=%s\nsource_url=%s\nsource_sha256=%s\n' \
                "$LEVELDB_VER" "$LEVELDB_URL" "$LEVELDB_SHA"
            ;;
        secp_native)
            printf 'version=%s\nsource_url=%s\nsource_sha256=%s\n' \
                "$SECP_VER" "$SECP_URL" "$SECP_SHA"
            ;;
        *) return 1 ;;
    esac
}

recipe_flags() {
    local group="$1" flags
    # A cross build compiles the same pinned source with a different target,
    # so the target belongs in the recipe the stamp hashes. Appended only when
    # cross: the host descriptor stays byte-identical to the one every existing
    # vendor/lib stamp was written against.
    flags="$(recipe_flags_host "$group")" || return 1
    printf '%s' "$flags"
    if [[ -n "$VENDOR_TARGET" ]]; then
        printf '; target=%s' "$VENDOR_TARGET"
    fi
    if [[ "$group" == openssl && -n "$OPENSSL_CONFIG_TARGET" ]]; then
        printf '; config_target=%s' "$OPENSSL_CONFIG_TARGET"
    fi
    if [[ "$VENDOR_TARGET_OS" == darwin ]]; then
        printf '; macosx_deployment_target=%s' "$MACOSX_DEPLOYMENT_TARGET"
    fi
}

recipe_flags_host() {
    local group="$1"
    case "$group" in
        tor_stub) printf '%s' "$VENDOR_C_STD -O2 -fPIC; ar=Dcr" ;;
        sqlite) printf '%s' '-O2 -fPIC -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_RTREE -DSQLITE_ENABLE_JSON1 -DSQLITE_ENABLE_COLUMN_METADATA -DSQLITE_OMIT_DEPRECATED -DSQLITE_DEFAULT_FOREIGN_KEYS=1; ar=Dcr' ;;
        zlib) printf '%s' 'CFLAGS=-O2 -fPIC; ./configure --static; make libz.a' ;;
        openssl) printf '%s' './Configure no-shared no-tests --prefix=/usr/local --openssldir=/etc/ssl --libdir=lib; make build_libs' ;;
        libevent) printf '%s' "apply pinned secure-rng ABI patch (evutil_rand.c definition + event2/util.h declaration); CFLAGS=-O2 -fPIC -Ivendor/include; LDFLAGS=-Lvendor/lib; CPPFLAGS=$LIBEVENT_CPPFLAGS; ./configure --disable-shared --enable-static --disable-samples --disable-libevent-regress; thread_archive=$LIBEVENT_THREAD_ARCHIVE; require=evutil_secure_rng_add_bytes; stage=include/event2" ;;
        leveldb) printf '%s' "route=direct-cxx11; -std=c++11 -O2 -DNDEBUG -fPIC -fno-exceptions -fno-rtti; $LEVELDB_PLATFORM; crc32c=off; snappy=off"
            ;;
        secp_native) printf '%s' 'cmake static; recovery=on; ecdh=on; tests=off; benchmarks=off; examples=off' ;;
        *) return 1 ;;
    esac
}

recipe_toolchain_sha() {
    local group="$1" cxx identities
    identities="cc=$(vp_compiler_identity_sha "$VENDOR_CC")
ar=$(vp_tool_identity_sha "$VENDOR_AR")"
    case "$group" in
        openssl)
            identities="$identities
perl=$(vp_tool_identity_sha perl)
make=$(vp_tool_identity_sha make)"
            ;;
        libevent|zlib)
            identities="$identities
make=$(vp_tool_identity_sha make)"
            ;;
        secp_native)
            identities="$identities
cmake=$(vp_tool_identity_sha cmake)"
            ;;
        leveldb)
            cxx="$(leveldb_cxx_compiler)"
            identities="cxx=$(vp_compiler_identity_sha "$cxx")
ar=$(vp_tool_identity_sha "$VENDOR_AR")"
            ;;
        tor_stub|sqlite) ;;
        *) return 1 ;;
    esac
    vp_sha256_text "$identities"
}

recipe_dependencies() {
    local group="$1" archive sha
    if [[ "$group" != "libevent" ]]; then
        printf 'none'
        return
    fi
    for archive in libcrypto.a libssl.a; do
        sha="$(vp_stamp_sha256 "$LIB" "$archive" 2>/dev/null || printf 'missing')"
        printf '%s=%s\n' "$archive" "$sha"
    done
}

archive_descriptor() {
    local archive="$1" group source_fields flags dependencies
    group="$(archive_group "$archive")" || return 1
    source_fields="$(recipe_source_fields "$group")" || return 1
    flags="$(recipe_flags "$group")" || return 1
    dependencies="$(recipe_dependencies "$group")"
    printf 'schema=%s\n' "$VP_SCHEMA"
    printf 'archive=%s\n' "$archive"
    printf 'component=%s\n' "$group"
    printf '%s\n' "$source_fields"
    printf 'provenance_contract_revision=%s\n' "$PROVENANCE_CONTRACT_REV"
    printf 'recipe_revision=%s\n' "$(recipe_revision "$group")"
    printf 'recipe_flags_sha256=%s\n' "$(vp_sha256_text "$flags")"
    printf 'source_date_epoch=%s\n' "$SOURCE_DATE_EPOCH"
    printf 'toolchain_sha256=%s\n' "$(recipe_toolchain_sha "$group")"
    printf 'dependencies_sha256=%s' "$(vp_sha256_text "$dependencies")"
}

archive_current() {
    local archive="$1" descriptor
    [[ -f "$LIB/$archive" ]] || return 1
    descriptor="$(archive_descriptor "$archive")" || return 1
    vp_verify_stamp "$LIB" "$archive" "$descriptor"
}

have() {
    [[ "$FORCE" != "1" ]] && archive_current "$1"
}

invalidate_stamps() {
    local archive
    for archive in "$@"; do
        rm -f "$(vp_stamp_path "$LIB" "$archive")"
    done
}

stamp_archives() {
    local archive descriptor
    for archive in "$@"; do
        descriptor="$(archive_descriptor "$archive")" ||
            die "cannot compute provenance descriptor for $archive"
        vp_write_stamp "$LIB" "$archive" "$descriptor" ||
            die "cannot write provenance stamp for $archive"
    done
}

install_archive() {
    local source="$1" archive="$2" tmp
    tmp="$LIB/.${archive}.tmp.$$"
    cp -f "$source" "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$LIB/$archive"
}

install_vendor_companion() {
    local source="$1" destination="$2" expected_sha="$3" tmp
    [[ "$(vp_sha256_file "$source")" == "$expected_sha" ]] ||
        die "pinned companion hash mismatch: ${source#"$VENDOR"/}"
    tmp="${destination}.tmp.$$"
    cp -f "$source" "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$destination"
    [[ "$(vp_sha256_file "$destination")" == "$expected_sha" ]] ||
        die "installed companion hash mismatch: ${destination#"$VENDOR"/}"
}

verify_committed_secp() {
    vp_verify_locked_manifest "$LIB/libsecp256k1.a" "$SECP_MANIFEST" \
        libsecp256k1.a
}

# --- per-library builders ---------------------------------------------------

build_tor_stub() {     # IN-TREE: vendor/tor_stub.c
    have libtor_stub.a && { say "skip    libtor_stub.a (provenance current)"; return; }
    say "build   libtor_stub.a  (in-tree: vendor/tor_stub.c)"
    [[ -f "$VENDOR/tor_stub.c" ]] || die "vendor/tor_stub.c missing (tracked source expected)"
    invalidate_stamps libtor_stub.a
    local o="$WORK/tor_stub.o" built="$WORK/libtor_stub.a"
    mkdir -p "$WORK"
    "$VENDOR_CC" "$VENDOR_C_STD" -O2 -fPIC -c "$VENDOR/tor_stub.c" -o "$o"
    rm -f "$built"
    "$VENDOR_AR" $ARFLAGS_DET "$built" "$o" 2>/dev/null ||
        "$VENDOR_AR" cr "$built" "$o"
    install_archive "$built" libtor_stub.a
    stamp_archives libtor_stub.a
    ok "built   libtor_stub.a"
}

build_sqlite() {       # FETCHED: SQLite amalgamation
    local archive_ready=0
    if have libsqlite3.a; then
        if [[ -f "$VENDOR/sqlite3.c" && -f "$INC/sqlite3.h" &&
              "$(vp_sha256_file "$VENDOR/sqlite3.c")" == "$SQLITE_C_SHA" &&
              "$(vp_sha256_file "$INC/sqlite3.h")" == "$SQLITE_H_SHA" ]]; then
            say "skip    libsqlite3.a (provenance current)"
            return
        fi
        archive_ready=1
        say "repair  SQLite amalgamation source beside current archive"
    fi
    local zip; zip="$(fetch "$SQLITE_URL" "$SQLITE_SHA" "${SQLITE_AMALG}.zip")"
    local d="$WORK/$SQLITE_AMALG"
    rm -rf "$d"; need unzip; unzip -q -o "$zip" -d "$WORK"
    # The cross-platform acceptance programs compile the pinned amalgamation
    # directly. A restored archive without these companion sources is not a
    # complete vendor cache hit, even though native links can consume it.
    install_vendor_companion "$d/sqlite3.c" "$VENDOR/sqlite3.c" \
        "$SQLITE_C_SHA"
    install_vendor_companion "$d/sqlite3.h" "$INC/sqlite3.h" \
        "$SQLITE_H_SHA"
    if [[ "$archive_ready" == "1" ]]; then
        ok "restored SQLite amalgamation source (archive provenance current)"
        return
    fi
    say "build   libsqlite3.a  (SQLite ${SQLITE_AMALG#sqlite-amalgamation-})"
    invalidate_stamps libsqlite3.a
    # Build flags mirror a typical Bitcoin/Zcash sqlite vendor build.
    local FLAGS="-DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_RTREE \
        -DSQLITE_ENABLE_JSON1 -DSQLITE_ENABLE_COLUMN_METADATA -DSQLITE_OMIT_DEPRECATED \
        -DSQLITE_DEFAULT_FOREIGN_KEYS=1"
    "$VENDOR_CC" -O2 -fPIC $FLAGS -c "$d/sqlite3.c" -o "$WORK/sqlite3.o"
    local built="$WORK/libsqlite3.a"
    rm -f "$built"
    "$VENDOR_AR" $ARFLAGS_DET "$built" "$WORK/sqlite3.o" 2>/dev/null ||
        "$VENDOR_AR" cr "$built" "$WORK/sqlite3.o"
    install_archive "$built" libsqlite3.a
    # Keep the amalgamation source in vendor/ (gitignored) so the rest of the
    # build (tools/sqlq.c etc.) and the header stay in sync.
    stamp_archives libsqlite3.a
    ok "built   libsqlite3.a"
}

build_zlib() {         # FETCHED: zlib
    have libz.a && { say "skip    libz.a (provenance current)"; return; }
    say "build   libz.a  (zlib ${ZLIB_VER})"
    invalidate_stamps libz.a
    local tb; tb="$(fetch "$ZLIB_URL" "$ZLIB_SHA" "zlib-${ZLIB_VER}.tar.gz")"
    local d="$WORK/zlib-${ZLIB_VER}"
    rm -rf "$d"; tar -C "$WORK" -xzf "$tb"
    # zlib's configure has no --host: it takes the toolchain from the
    # environment and only ever COMPILES its probes, never runs them, so the
    # cross build differs from the host build by the toolchain alone.
    ( cd "$d" && CC="$VENDOR_CC" AR="$VENDOR_AR" RANLIB="$VENDOR_RANLIB" \
        CFLAGS="-O2 -fPIC" \
        ./configure --static >/dev/null \
        && make -j"$JOBS" libz.a >/dev/null )
    install_archive "$d/libz.a" libz.a
    cp -f "$d/zlib.h" "$d/zconf.h" "$INC/"
    stamp_archives libz.a
    ok "built   libz.a"
}

build_openssl() {      # FETCHED: OpenSSL -> libcrypto.a + libssl.a
    need perl
    { have libcrypto.a && have libssl.a; } && { say "skip    libcrypto.a/libssl.a (provenance current)"; return; }
    say "build   libcrypto.a + libssl.a  (OpenSSL ${OPENSSL_VER}) — this is the slow one"
    invalidate_stamps libcrypto.a libssl.a
    local tb; tb="$(fetch "$OPENSSL_URL" "$OPENSSL_SHA" "openssl-${OPENSSL_VER}.tar.gz")"
    local d="$WORK/openssl-${OPENSSL_VER}"
    rm -rf "$d"; tar -C "$WORK" -xzf "$tb"
    # no-docs/no-apps don't exist in OpenSSL 3.0.x; build only the libs target.
    #
    # Use NEUTRAL, non-$HOME prefix/openssldir so libcrypto.a carries NO
    # absolute build-machine path. OpenSSL bakes OPENSSLDIR / ENGINESDIR /
    # MODULESDIR string constants — derived from --prefix/--openssldir — into
    # the static library; with the old --prefix="$d/_install" (under the build
    # tree, i.e. /home/<user>/...) those leaked the build user's $HOME into the
    # final zclassic23 binary, failing test_no_hardcoded_home. This leakage is
    # exactly what the build-twice byte-identity gate catches
    # (tools/scripts/check_reproducible_build.sh, exposed as `make
    # ci-reproducible`): a non-neutral prefix bakes a per-build path into the
    # .a, so two builds of zclassic23 fail byte-identity. We only ever copy the
    # .a files (never `make install`), so these paths affect ONLY the embedded strings — the
    # canonical /usr/local + /etc/ssl values are relocatable and operator-
    # agnostic. (Do NOT pass -DOPENSSLDIR etc — Configure already defines them
    # from --prefix/--openssldir, and a -D redefine errors the build.)
    # $OPENSSL_CONFIG_TARGET is empty on native POSIX/Darwin builds. Windows
    # and cross builds name the target because Configure cannot infer it from
    # the execution environment.
    # shellcheck disable=SC2086
    ( cd "$d" \
        && export CC="$VENDOR_CC" AR="$VENDOR_AR" RANLIB="$VENDOR_RANLIB" \
        && ./Configure $OPENSSL_CONFIG_TARGET no-shared no-tests \
             --prefix=/usr/local --openssldir=/etc/ssl --libdir=lib >/dev/null \
        && make -j"$JOBS" build_libs >/dev/null 2>&1 )
    # OpenSSL also records the literal compiler command in its version data.
    # Reject an absolute checkout/home compiler here, before the archive can
    # reach the node; test_no_hardcoded_home remains the final backstop.
    local archive forbidden
    for archive in "$d/libcrypto.a" "$d/libssl.a"; do
        for forbidden in "$REPO_ROOT" "$WORK" "${HOME:-}"; do
            [[ -n "$forbidden" ]] || continue
            if LC_ALL=C grep -aF "$forbidden" "$archive" >/dev/null; then
                die "$(basename "$archive") embeds build-host path: $forbidden"
            fi
        done
    done
    install_archive "$d/libcrypto.a" libcrypto.a
    install_archive "$d/libssl.a" libssl.a
    rm -rf "$INC/openssl"; mkdir -p "$INC/openssl"
    cp -f "$d/include/openssl/"*.h "$INC/openssl/" 2>/dev/null || true
    stamp_archives libcrypto.a libssl.a
    ok "built   libcrypto.a + libssl.a"
}

build_libevent() {     # FETCHED: libevent -> libevent.a + libevent_openssl.a + libevent_pthreads.a
    # Validate/rebuild OpenSSL first. Its stamp digests are bound into every
    # libevent descriptor, so a dependency upgrade invalidates all outputs.
    build_openssl
    # The skip also requires the staged event2 headers (see the install step
    # below). This is an ADDITIONAL condition on an existing fast path, never a
    # relaxation of one: a tree whose archives are current but whose headers
    # were never installed cannot build the embedded Tor archive, and silently
    # skipping would hand `make tor-full` a configure failure it cannot
    # explain. event-config.h is generated by libevent's own configure, so the
    # headers can only come from a real build of this exact pinned source.
    { have libevent.a && have libevent_openssl.a && have libevent_pthreads.a &&
      [[ -f "$INC/event2/event.h" && -f "$INC/event2/event-config.h" ]]; } \
        && { say "skip    libevent*.a (provenance current)"; return; }
    say "build   libevent.a + libevent_openssl.a + libevent_pthreads.a  (libevent ${LIBEVENT_VER})"
    need nm; need patch
    [[ -f "$LIBEVENT_PATCH" ]] || die "missing libevent patch: $LIBEVENT_PATCH"
    invalidate_stamps libevent.a libevent_openssl.a libevent_pthreads.a
    # Drop any previously staged event2/ BEFORE the build, not after. The build
    # puts -I$INC on the compile line (LIBEVENT_CPPFLAGS), so leaving a stale
    # copy of libevent's own headers there is a shadowing hazard with no
    # upside — nothing in this build reads them. If the build then fails, the
    # tree is left with no staged headers, which the skip condition above reads
    # as "must rebuild": fail-closed, not a half-installed header set.
    rm -rf "$INC/event2"
    local tb; tb="$(fetch "$LIBEVENT_URL" "$LIBEVENT_SHA" "libevent-${LIBEVENT_VER}.tar.gz")"
    local d="$WORK/libevent-${LIBEVENT_VER}-stable"
    local build_log="$WORK/libevent-build.log"
    local symbols="$WORK/libevent.symbols"
    rm -rf "$d"; tar -C "$WORK" -xzf "$tb"
    # Newer glibc exposes arc4random() but not arc4random_addrandom(). In that
    # combination libevent 2.1.12 omits evutil_secure_rng_add_bytes from BOTH
    # the archive and the public header — the same
    #   #if !defined(EVENT__HAVE_ARC4RANDOM) || defined(EVENT__HAVE_ARC4RANDOM_ADDRANDOM)
    # guards the definition in evutil_rand.c and the declaration in
    # include/event2/util.h. (An earlier revision of this comment said the
    # header still declared it. It does not, and that was only invisible while
    # the vendored Tor build read the SYSTEM libevent headers instead of the
    # staged ones below.) The embedded Tor archive requires the symbol, so the
    # pinned patch unguards both: the definition becomes a no-op on platforms
    # whose system arc4random has no entropy-injection primitive, and the
    # declaration is always visible so callers compile. That matches current
    # upstream behavior while retaining the pinned release.
    if ! ( cd "$d" \
            && patch -p1 --forward <"$LIBEVENT_PATCH" \
            && CC="$VENDOR_CC" AR="$VENDOR_AR" RANLIB="$VENDOR_RANLIB" \
               CFLAGS="-O2 -fPIC -I$INC" LDFLAGS="-L$LIB" \
               CPPFLAGS="$LIBEVENT_CPPFLAGS" LIBS="$LIBEVENT_CONFIGURE_LIBS" \
               ./configure --disable-shared --enable-static \
                 --disable-samples --disable-libevent-regress \
                 ${VENDOR_CROSS_HOST_ARGS[@]+"${VENDOR_CROSS_HOST_ARGS[@]}"} \
            && make -j"$JOBS" \
        ) >"$build_log" 2>&1; then
        tail -200 "$build_log" >&2 || true
        die "libevent build failed (log: $build_log)"
    fi
    nm -g --defined-only "$d/.libs/libevent.a" >"$symbols" 2>/dev/null ||
        die "could not inspect rebuilt libevent.a"
    grep -qE ' [Tt] _?evutil_secure_rng_add_bytes$' "$symbols" ||
        die "libevent.a lacks Tor-required evutil_secure_rng_add_bytes"
    install_archive "$d/.libs/libevent.a" libevent.a
    install_archive "$d/.libs/libevent_openssl.a" libevent_openssl.a
    if [[ -f "$d/.libs/libevent_pthreads.a" ]]; then
        install_archive "$d/.libs/libevent_pthreads.a" libevent_pthreads.a
    else
        # Libevent compiles its Win32 thread backend directly into libevent.a
        # and intentionally emits no pthread companion archive. Preserve the
        # fixed link manifest with a deterministic empty archive, but only
        # after proving the native backend symbol is present.
        grep -qE ' [Tt] _?evthread_use_windows_threads$' "$symbols" ||
            die "libevent emitted neither pthread nor Win32 thread support"
        "$VENDOR_AR" $ARFLAGS_DET "$WORK/libevent_pthreads.a" ||
            die "could not create Win32 libevent thread compatibility archive"
        install_archive "$WORK/libevent_pthreads.a" libevent_pthreads.a
    fi
    # event2/* headers are not needed for the zclassic23 link itself — no app
    # TU includes them — but the vendored Tor archive (`make tor-full`) does,
    # and on macOS there is no system libevent for Tor's configure to discover,
    # so these staged headers are the ONLY libevent headers a Mac has. They
    # must come from THIS configured tree: event2/event-config.h is generated
    # by libevent's configure and encodes the exact host feature set the
    # archive above was compiled with, so shipping a copy from anywhere else
    # would let Tor compile against a different ABI than it links.
    mkdir -p "$INC/event2"
    cp -f "$d/include/event2/"*.h "$INC/event2/" ||
        die "could not stage vendored event2 headers into $INC/event2"
    [[ -f "$INC/event2/event.h" && -f "$INC/event2/event-config.h" ]] ||
        die "staged event2 headers are incomplete (event.h/event-config.h)"
    # Header-side twin of the archive check above. The archive is required to
    # EXPORT evutil_secure_rng_add_bytes; the header must therefore also
    # DECLARE it, or a Tor TU that calls it compiles as an implicit
    # declaration and the build stops. Stock libevent 2.1.12 hides the
    # declaration behind
    #   #if !defined(EVENT__HAVE_ARC4RANDOM) || defined(EVENT__HAVE_ARC4RANDOM_ADDRANDOM)
    # which is false on a host whose libc has arc4random but no
    # arc4random_addrandom — so the pinned patch unguards the declaration to
    # match the definition it already unguards. Asserting it here means the
    # header/archive disagreement is caught while building libevent, not
    # hundreds of TUs into `make tor-full`.
    grep -qE '^void[[:space:]]+evutil_secure_rng_add_bytes' \
        "$INC/event2/util.h" ||
        die "staged event2/util.h does not declare evutil_secure_rng_add_bytes (the pinned secure-rng ABI patch did not reach the header)"
    stamp_archives libevent.a libevent_openssl.a libevent_pthreads.a
    ok "built   libevent*.a"
}

leveldb_cxx_compiler() {
    if [[ -n "${CXX:-}" ]]; then
        command -v "$CXX" >/dev/null 2>&1 || die "CXX not found: $CXX"
        vendor_require_same_machine "CXX" "$CXX"
        printf '%s' "$CXX"
        return
    fi
    if command -v c++ >/dev/null 2>&1; then
        vendor_require_same_machine "c++" c++
        printf '%s' c++
        return
    fi
    if command -v g++ >/dev/null 2>&1; then
        vendor_require_same_machine "g++" g++
        printf '%s' g++
        return
    fi
    die "required tool not found: c++ or g++ (LevelDB direct fallback)"
}

build_leveldb_direct() {
    local d="$1" cxx gen objdir src obj platform_define
    local objs=()
    local sources=(
        db/builder.cc
        db/c.cc
        db/db_impl.cc
        db/db_iter.cc
        db/dbformat.cc
        db/dumpfile.cc
        db/filename.cc
        db/log_reader.cc
        db/log_writer.cc
        db/memtable.cc
        db/repair.cc
        db/table_cache.cc
        db/version_edit.cc
        db/version_set.cc
        db/write_batch.cc
        table/block_builder.cc
        table/block.cc
        table/filter_block.cc
        table/format.cc
        table/iterator.cc
        table/merger.cc
        table/table_builder.cc
        table/table.cc
        table/two_level_iterator.cc
        util/arena.cc
        util/bloom.cc
        util/cache.cc
        util/coding.cc
        util/comparator.cc
        util/crc32c.cc
        util/env.cc
        util/filter_policy.cc
        util/hash.cc
        util/logging.cc
        util/options.cc
        util/status.cc
        helpers/memenv/memenv.cc
    )

    case "$VENDOR_TARGET_OS" in
        windows)
            sources+=(util/env_windows.cc)
            platform_define=LEVELDB_PLATFORM_WINDOWS
            ;;
        *)
            sources+=(util/env_posix.cc)
            platform_define=LEVELDB_PLATFORM_POSIX
            ;;
    esac

    cxx="$(leveldb_cxx_compiler)"
    say "build   libleveldb.a  (fixed direct C++11 route)"
    gen="$WORK/leveldb-direct/include/port"
    objdir="$WORK/leveldb-direct/obj"
    rm -rf "$WORK/leveldb-direct"
    mkdir -p "$gen" "$objdir"
    cat > "$gen/port_config.h" <<'EOF'
#ifndef STORAGE_LEVELDB_PORT_PORT_CONFIG_H_
#define STORAGE_LEVELDB_PORT_PORT_CONFIG_H_
#if defined(_WIN32)
#define HAVE_FDATASYNC 0
#define HAVE_FULLFSYNC 0
#elif defined(__APPLE__)
#define HAVE_FDATASYNC 0
#define HAVE_FULLFSYNC 1
#else
#define HAVE_FDATASYNC 1
#define HAVE_FULLFSYNC 0
#endif
#if defined(_WIN32)
#define HAVE_O_CLOEXEC 0
#elif !defined(HAVE_O_CLOEXEC)
#define HAVE_O_CLOEXEC 1
#endif
#ifndef HAVE_CRC32C
#define HAVE_CRC32C 0
#endif
#ifndef HAVE_SNAPPY
#define HAVE_SNAPPY 0
#endif
#endif
EOF

    for src in "${sources[@]}"; do
        obj="$objdir/${src//\//_}.o"
        # Compile the source by its stable relative name.  Besides simplifying
        # the tool graph, this prevents __FILE__ from embedding the random
        # vendor scratch path in an otherwise deterministic archive.
        ( cd "$d" && "$cxx" -std=c++11 -O2 -DNDEBUG -fPIC \
            -fno-exceptions -fno-rtti \
            -D"$platform_define"=1 -DLEVELDB_COMPILE_LIBRARY \
            -I"$WORK/leveldb-direct/include" -I. -Iinclude \
            -c "$src" -o "$obj" )
        objs+=("$obj")
    done
    rm -f "$WORK/libleveldb.a"
    "$VENDOR_AR" $ARFLAGS_DET "$WORK/libleveldb.a" "${objs[@]}" 2>/dev/null ||
        "$VENDOR_AR" cr "$WORK/libleveldb.a" "${objs[@]}"
}

build_leveldb() {      # FETCHED: LevelDB -> libleveldb.a
    have libleveldb.a && { say "skip    libleveldb.a (provenance current)"; return; }
    say "build   libleveldb.a  (LevelDB ${LEVELDB_VER})"
    invalidate_stamps libleveldb.a
    local tb; tb="$(fetch "$LEVELDB_URL" "$LEVELDB_SHA" "leveldb-${LEVELDB_VER}.tar.gz")"
    local d="$WORK/leveldb-${LEVELDB_VER}"
    rm -rf "$d"; tar -C "$WORK" -xzf "$tb"
    # One route is part of the release contract.  Selecting CMake merely
    # because it happens to be installed made identical hosts produce
    # different archive bytes and therefore different node action identities.
    build_leveldb_direct "$d"
    install_archive "$WORK/libleveldb.a" libleveldb.a
    # Tracked vendor/include/leveldb/*.h (1.18) expose the same stable C API
    # (leveldb/c.h) the repo uses; we intentionally do NOT overwrite them.
    stamp_archives libleveldb.a
    ok "built   libleveldb.a"
}

build_secp_native() {
    local archive
    case "$VENDOR_TARGET_OS" in
        darwin) archive=libsecp256k1-darwin.a ;;
        windows) archive=libsecp256k1-windows.a ;;
        *) die "native libsecp256k1 archive requires Darwin or Windows" ;;
    esac
    have "$archive" && {
        say "skip    $archive (provenance current)"; return;
    }
    need cmake
    say "build   $archive  (secp256k1 ${SECP_VER})"
    invalidate_stamps "$archive"
    local tb d
    tb="$(fetch "$SECP_URL" "$SECP_SHA" "secp256k1-${SECP_VER}.tar.gz")"
    d="$WORK/secp256k1-${SECP_VER}"
    rm -rf "$d" "$WORK/secp-native-build"
    tar -C "$WORK" -xzf "$tb"
    # CMAKE_SYSTEM_NAME is what puts CMake in cross mode: without it CMake
    # keeps probing (and trying to RUN) host binaries and silently grades the
    # wrong machine. Empty on a host build, so its command line is unchanged.
    local -a secp_cross=()
    if [[ -n "$VENDOR_TARGET" ]]; then
        case "$VENDOR_TARGET_OS" in
            windows) secp_cross=(-DCMAKE_SYSTEM_NAME=Windows) ;;
            darwin) secp_cross=(-DCMAKE_SYSTEM_NAME=Darwin) ;;
        esac
        secp_cross+=(-DCMAKE_RANLIB="$VENDOR_RANLIB")
    fi
    cmake -S "$d" -B "$WORK/secp-native-build" \
        ${secp_cross[@]+"${secp_cross[@]}"} \
        -DCMAKE_C_COMPILER="$VENDOR_CC" -DCMAKE_AR="$VENDOR_AR" \
        -DBUILD_SHARED_LIBS=OFF \
        -DSECP256K1_ENABLE_MODULE_RECOVERY=ON \
        -DSECP256K1_ENABLE_MODULE_ECDH=ON \
        -DSECP256K1_BUILD_TESTS=OFF \
        -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
        -DSECP256K1_BUILD_BENCHMARK=OFF \
        -DSECP256K1_BUILD_EXAMPLES=OFF >/dev/null
    cmake --build "$WORK/secp-native-build" -j"$JOBS" >/dev/null
    install_archive "$WORK/secp-native-build/lib/libsecp256k1.a" \
        "$archive"
    stamp_archives "$archive"
    ok "built   $archive"
}

# --- orchestration ----------------------------------------------------------
need "$VENDOR_CC"; need "$VENDOR_AR"; need tar; need make
if ! command -v sha256sum >/dev/null 2>&1 &&
   ! command -v shasum >/dev/null 2>&1; then
    die "need sha256sum or shasum"
fi

# ar carries no -dumpmachine, so its target can only be read from its name.
# A cross VENDOR_CC left beside the host's plain `ar` is silent today: ar
# writes an archive index in the host's format and the cross linker rejects
# or misreads it. Refuse the mismatch rather than discover it at link time.
if [ -n "$VENDOR_CC_MACHINE" ] && [ "$VENDOR_CC_MACHINE" != "$(vendor_cc_machine cc)" ]; then
    case "$(basename "$VENDOR_AR")" in
        "$VENDOR_CC_MACHINE"-*) ;;
        *) die "VENDOR_CC targets $VENDOR_CC_MACHINE but VENDOR_AR is \
'$VENDOR_AR' -- pass the matching ${VENDOR_CC_MACHINE}-ar" ;;
    esac
fi
mkdir -p "$LIB" "$INC" "$WORK"
acquire_vendor_lock

REQUIRED=(libsecp256k1.a libcrypto.a libssl.a libevent.a libevent_openssl.a
          libevent_pthreads.a libleveldb.a libsqlite3.a libz.a
          libtor_stub.a)
case "$VENDOR_TARGET_OS" in
    darwin) REQUIRED+=(libsecp256k1-darwin.a) ;;
    windows) REQUIRED+=(libsecp256k1-windows.a) ;;
esac
# Two archives leave the cross set, neither by relaxing anything:
#   libsecp256k1.a  — the ONE committed archive, an ELF for this host. A cross
#     tree neither has it nor could link it, and its per-target replacement
#     (libsecp256k1-windows.a / -darwin.a) is already REQUIRED above.
#   libleveldb.a    — the one C++ archive, and the node never links it: it is a
#     differential test oracle (NODE_C23_LIBS in the Makefile names every
#     archive the shipped binary consumes and does not name this one). A cross
#     tree exists to link a release, so it needs no cross C++ toolchain.
if [[ -n "$VENDOR_TARGET" ]]; then
    REQUIRED_CROSS=()
    for a in "${REQUIRED[@]}"; do
        case "$a" in libsecp256k1.a|libleveldb.a) continue ;; esac
        REQUIRED_CROSS+=("$a")
    done
    REQUIRED=("${REQUIRED_CROSS[@]}")
fi

check_one_provenance() {
    local archive="$1" descriptor
    if [[ "$archive" == "libsecp256k1.a" ]]; then
        verify_committed_secp
        return
    fi
    descriptor="$(archive_descriptor "$archive")" || return 1
    vp_verify_stamp "$LIB" "$archive" "$descriptor"
}

check_provenance_set() {
    local archive failed=0
    for archive in "$@"; do
        if check_one_provenance "$archive"; then
            [[ "${VENDOR_PROVENANCE_QUIET:-0}" == "1" ]] ||
                ok "verify  $archive provenance current"
        else
            [[ "${VENDOR_PROVENANCE_QUIET:-0}" == "1" ]] ||
                say "STALE   $archive (missing/mismatched provenance or bytes)"
            failed=1
        fi
    done
    return "$failed"
}

if [[ "${1:-}" == "--check-provenance" ]]; then
    shift
    if [[ $# -gt 0 ]]; then
        check_provenance_set "$@" ||
            die "vendor provenance verification failed"
    else
        check_provenance_set "${REQUIRED[@]}" ||
            die "vendor provenance verification failed"
    fi
    ok "vendor provenance verification passed"
    exit 0
fi

# Build order: openssl before libevent (libevent_openssl needs its headers).
ALL=(build_tor_stub build_zlib build_sqlite build_openssl build_libevent build_leveldb)
# Darwin and Windows both need secp built here; Linux takes the pinned
# archive. One condition, because both arms appended the same builder.
case "$VENDOR_TARGET_OS" in
    darwin|windows) ALL+=(build_secp_native) ;;
esac
# LevelDB leaves the cross build for the reason given at REQUIRED above: the
# shipped node does not link it, so a cross tree neither builds it nor needs a
# cross C++ toolchain to exist.
if [[ -n "$VENDOR_TARGET" ]]; then
    ALL_KEPT=()
    for b in "${ALL[@]}"; do
        [[ "$b" == "build_leveldb" ]] && continue
        ALL_KEPT+=("$b")
    done
    ALL=("${ALL_KEPT[@]}")
fi

# Map .a names -> builder for the subset form.
declare -A BUILDER=(
    [libtor_stub.a]=build_tor_stub
    [libz.a]=build_zlib
    [libsqlite3.a]=build_sqlite
    [libcrypto.a]=build_openssl [libssl.a]=build_openssl
    [libevent.a]=build_libevent [libevent_openssl.a]=build_libevent [libevent_pthreads.a]=build_libevent
    [libleveldb.a]=build_leveldb
    [libsecp256k1-darwin.a]=build_secp_native
    [libsecp256k1-windows.a]=build_secp_native
)

if [[ $# -gt 0 ]]; then
    seen=""
    for a in "$@"; do
        b="${BUILDER[$a]:-}"
        [[ -n "$b" ]] || die "unknown vendor archive: $a"
        case " $seen " in *" $b "*) ;; *) "$b"; seen="$seen $b";; esac
    done
else
    for b in "${ALL[@]}"; do "$b"; done
fi

# --- verify the full set ----------------------------------------------------
stale=()
for a in "${REQUIRED[@]}"; do
    check_one_provenance "$a" || stale+=("$a")
done
if [[ ${#stale[@]} -gt 0 ]]; then
    if [[ $# -gt 0 ]]; then
        say "subset build complete; still missing/stale: ${stale[*]}"
    else
        die "vendor build finished but provenance is stale: ${stale[*]}"
    fi
else
    rm -rf "$WORK"
    ok "all vendor/lib archives provenance-verified:"
    ( cd "$LIB" && ls -1 *.a | sed 's/^/        /' )
fi
