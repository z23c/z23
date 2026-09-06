#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# install_from_source.sh — the source-build installer served at
# /install.sh (core/modules/net/include/net/site_routes.def), so
# `curl -fsSL https://<site>/install.sh | sh` builds a Z23 node from
# source and downloads NO BINARY: it clones the source tree over git and
# compiles it locally with the toolchain already on this machine.
#
# This is a SEPARATE, simpler front door from the digest-verified binary
# bootstrap (platform/packaging/install/install.sh + tools/install/z23_bootstrap.c). That
# chain fetches one prebuilt binary after checking its SHA-256 against a
# pin baked into the release, and stays unpublished until its signing
# gate is met (docs/work/BOOTSTRAP_PLAN.md:299-309). Nothing here reads
# that pin or touches that chain.
#
# POSIX /bin/sh only: no bash-isms, and this script never reads its own
# stdin (it is meant to run piped from curl, and consuming that pipe
# would eat the rest of the script). It never refers to $0 either, since
# a piped script has no reliable name.

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

need() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

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
    git -C "$SRC" fetch origin
else
    git clone "$REPO_URL" "$SRC"
fi

if [ -n "$Z23_PIN" ]; then
    echo "install_from_source: checking out pinned commit $Z23_PIN"
    git -C "$SRC" checkout "$Z23_PIN"
else
    echo "install_from_source: no commit pin was served; building main instead"
    git -C "$SRC" checkout main
    git -C "$SRC" pull --ff-only origin main
fi

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)

(
    cd "$SRC"
    CC="$cc_ok" make setup
    CC="$cc_ok" make -j"$jobs" z23
)

echo "Built. Next: (cd \"$SRC\" && build/bin/z23) to start your node, then (cd \"$SRC\" && build/bin/z23 join) to join the C23 software commons."
