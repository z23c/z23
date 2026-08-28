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

# shellcheck source=tools/scripts/vendor_provenance_lib.sh
. "$SCRIPT_DIR/vendor_provenance_lib.sh"

JOBS="$(nproc 2>/dev/null || echo 4)"
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
LIBEVENT_CPPFLAGS="-I$INC"
LIBEVENT_THREAD_ARCHIVE="libevent_pthreads.a"
LEVELDB_PLATFORM="LEVELDB_PLATFORM_POSIX; env_posix.cc"
case "$(uname -s)" in
    MINGW*|MSYS*)
        # Current MinGW-w64 headers expose the iphlpapi declarations used by
        # libevent only when the supported Windows API floor is explicit.
        LIBEVENT_CPPFLAGS="$LIBEVENT_CPPFLAGS -D_WIN32_WINNT=0x0600"
        LIBEVENT_THREAD_ARCHIVE="windows-threads-in-libevent.a; empty compatibility archive"
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
RECIPE_OPENSSL="openssl-r4"
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
    if [[ -f "$dest" ]] && echo "$sha  $dest" | sha256sum -c - >/dev/null 2>&1; then
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
        echo "$sha  $dest.tmp" | sha256sum -c - >/dev/null 2>&1 \
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
    local group="$1"
    case "$group" in
        tor_stub) printf '%s' '-std=c23 -O2 -fPIC; ar=Dcr' ;;
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
    "$VENDOR_CC" -std=c23 -O2 -fPIC -c "$VENDOR/tor_stub.c" -o "$o"
    rm -f "$built"
    "$VENDOR_AR" $ARFLAGS_DET "$built" "$o" 2>/dev/null ||
        "$VENDOR_AR" cr "$built" "$o"
    install_archive "$built" libtor_stub.a
    stamp_archives libtor_stub.a
    ok "built   libtor_stub.a"
}

build_sqlite() {       # FETCHED: SQLite amalgamation
    have libsqlite3.a && { say "skip    libsqlite3.a (provenance current)"; return; }
    say "build   libsqlite3.a  (SQLite ${SQLITE_AMALG#sqlite-amalgamation-})"
    invalidate_stamps libsqlite3.a
    local zip; zip="$(fetch "$SQLITE_URL" "$SQLITE_SHA" "${SQLITE_AMALG}.zip")"
    local d="$WORK/$SQLITE_AMALG"
    rm -rf "$d"; need unzip; unzip -q -o "$zip" -d "$WORK"
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
    cp -f "$d/sqlite3.c" "$VENDOR/sqlite3.c"
    cp -f "$d/sqlite3.h" "$INC/sqlite3.h"
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
    ( cd "$d" && CC="$VENDOR_CC" AR="$VENDOR_AR" CFLAGS="-O2 -fPIC" \
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
    ( cd "$d" \
        && export CC="$VENDOR_CC" AR="$VENDOR_AR" \
        && ./Configure no-shared no-tests \
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
            && CC="$VENDOR_CC" AR="$VENDOR_AR" \
               CFLAGS="-O2 -fPIC -I$INC" LDFLAGS="-L$LIB" \
               CPPFLAGS="$LIBEVENT_CPPFLAGS" \
               ./configure --disable-shared --enable-static \
                 --disable-samples --disable-libevent-regress \
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
        printf '%s' "$CXX"
        return
    fi
    if command -v c++ >/dev/null 2>&1; then
        printf '%s' c++
        return
    fi
    if command -v g++ >/dev/null 2>&1; then
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

    case "$(uname -s)" in
        MINGW*|MSYS*)
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
    local host archive
    host="$(uname -s 2>/dev/null)"
    case "$host" in
        Darwin) archive=libsecp256k1-darwin.a ;;
        MINGW*|MSYS*) archive=libsecp256k1-windows.a ;;
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
    cmake -S "$d" -B "$WORK/secp-native-build" \
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
need "$VENDOR_CC"; need "$VENDOR_AR"; need sha256sum; need tar; need make
mkdir -p "$LIB" "$INC" "$WORK"
acquire_vendor_lock

REQUIRED=(libsecp256k1.a libcrypto.a libssl.a libevent.a libevent_openssl.a
          libevent_pthreads.a libleveldb.a libsqlite3.a libz.a
          libtor_stub.a)
if [[ "$(uname -s 2>/dev/null)" == Darwin ]]; then
    REQUIRED+=(libsecp256k1-darwin.a)
elif [[ "$(uname -s 2>/dev/null)" == MINGW* ||
        "$(uname -s 2>/dev/null)" == MSYS* ]]; then
    REQUIRED+=(libsecp256k1-windows.a)
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
if [[ "$(uname -s 2>/dev/null)" == Darwin ]]; then
    ALL+=(build_secp_native)
elif [[ "$(uname -s 2>/dev/null)" == MINGW* ||
        "$(uname -s 2>/dev/null)" == MSYS* ]]; then
    ALL+=(build_secp_native)
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
