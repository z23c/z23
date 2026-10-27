#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# install_from_source.sh — the source-build installer served at /install.sh
# (core/modules/net/include/net/site_routes.def): `curl -fsSL
# https://<site>/install.sh | sh` clones the source over git and compiles it
# with this machine's toolchain. It downloads NO BINARY and never touches the
# digest-pinned binary bootstrap (install.sh + tools/install/z23_bootstrap.c).
#
# POSIX /bin/sh only. It never reads its own stdin (it runs piped from curl,
# so that would eat the script) and never names $0 (a pipe has no name).

set -euf

REPO_URL="https://github.com/z23c/z23.git"
SRC="${Z23_SRC:-$HOME/z23}"
# The server that serves this file rewrites this literal placeholder to
# its own build commit before responding; an empty value means the
# running node could not name one, and this script falls back to main.
Z23_PIN="__Z23_PIN__"

die() {
    echo "install_from_source: $*" >&2
    exit 2
}

say() {
    echo "install_from_source: $*" >&2
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

# All git and build output goes to a log file, not the terminal. Until
# the clone exists it is a temp file; it then moves to $SRC/build/install.log.
# A failed step shows the last 20 lines of it and exits non-zero.
TMPLOG=$(mktemp "${TMPDIR:-/tmp}/z23-install.XXXXXX") ||
    die "cannot create a temporary log file"
LOG="$TMPLOG"
# The temp log never outlives the script, on success or on any failure.
trap 'rm -f "$TMPLOG"' EXIT

run() {
    "$@" >>"$LOG" 2>&1 || {
        say "FAILED: $*"
        say "last 20 lines of the log:"
        tr '\r' '\n' <"$LOG" | tail -n 20 >&2
        [ "$LOG" = "$TMPLOG" ] || say "full log: $LOG"
        exit 1
    }
}

say "1/4 Checking tools (git, make, a C23 compiler)..."
need git
need make

cc_ok=""
probe="./.z23-cc-probe.$$"
mkdir -p "$probe" 2>/dev/null ||
    die "cannot create a working directory to probe the C compiler"
printf 'int main(void){return 0;}\n' >"$probe/probe.c"
for candidate in cc gcc clang; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    if "$candidate" -std=c23 -o "$probe/probe" "$probe/probe.c" \
            >/dev/null 2>&1; then
        cc_ok="$candidate"
        break
    fi
done
rm -rf "$probe"
[ -n "$cc_ok" ] ||
    die "missing required command: a C compiler (cc, gcc, or clang) accepting -std=c23"

if [ -d "$SRC" ]; then
    [ -d "$SRC/.git" ] ||
        die "$SRC exists and is not a z23 git clone; set Z23_SRC to pick another path"
    url=$(git -C "$SRC" remote get-url origin 2>/dev/null || echo "")
    case "$url" in
    "$REPO_URL" | "${REPO_URL%.git}") ;;
    *)
        die "$SRC is a git clone of '$url', not $REPO_URL; set Z23_SRC to pick another path"
        ;;
    esac
    say "2/4 Getting the source: updating the existing clone in $SRC..."
    run git -C "$SRC" fetch origin
else
    say "2/4 Getting the source: cloning $REPO_URL into $SRC..."
    run git clone "$REPO_URL" "$SRC"
fi

if [ -n "$Z23_PIN" ]; then
    echo "checking out pinned commit $Z23_PIN" >>"$LOG"
    run git -C "$SRC" checkout "$Z23_PIN"
else
    echo "no commit pin was served; building main instead" >>"$LOG"
    run git -C "$SRC" checkout main
    run git -C "$SRC" pull --ff-only origin main
fi

mkdir -p "$SRC/build" || die "cannot create $SRC/build"
cat "$LOG" >>"$SRC/build/install.log"
rm -f "$TMPLOG"
LOG="$SRC/build/install.log"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
say "3/4 Building (several minutes the first time; full output: $LOG)..."
run env CC="$cc_ok" make -C "$SRC" setup
run env CC="$cc_ok" make -C "$SRC" -j"$jobs" z23

say "4/4 Done"
echo ""
echo "Source:  $SRC"
echo "Binary:  $SRC/build/bin/z23"
echo "Start:   (cd \"$SRC\" && build/bin/z23)"
echo "Check:   (cd \"$SRC\" && build/bin/z23 status)   # in a second terminal"
echo "Log:     $LOG"
echo "Next steps: https://z23.sh/start"
echo "Want to contribute? Read .github/CONTRIBUTING.md in $SRC, then post a claim in board room contrib (https://z23.sh/start)."
