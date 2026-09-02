#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# new_app.sh — turn contexts/commons/packages/zhello into a new GUI package, in one command.
#
#   usage: tools/scripts/new_app.sh <name>          (also: make new-app NAME=<name>)
#
# contexts/commons/packages/zhello is the template of record: window + animated canvas + a
# headless `--frames=N` selftest, two application C23 translation units, no
# node objects. Shared PNG/support objects are reused by every GUI package.
# A new app is that same program under a different name, so this script does
# ONLY what a copy cannot do for itself:
#
#   1. contexts/commons/packages/zhello -> contexts/commons/packages/<name>, with zhello spelled <name>
#      everywhere it names itself: symbols, header guards, log strings, usage
#      text and README. The app is not a fork of zhello, it IS zhello under
#      its own name.
#   2. One registration block appended to contexts/commons/apps/local_gui_apps.mk (gitignored: a
#      scaffolded app is user-local content, not tree content). The Makefile
#      -includes that file and generates the build rules from it, so the new
#      app's five targets exist with zero manual Makefile edits.
#
# The Makefile owns the build rules; this script owns the files. It never
# edits the top-level Makefile — avoiding that edit is the reason
# contexts/commons/apps/local_gui_apps.mk exists.
#
# IDEMPOTENCE: refusing, not resuming. Every step fails loudly when its
# output already exists — the package directory, an existing registry entry,
# a make target name that is already taken. A half-written scaffold is the
# failure this refuses to create: the tree is transformed in a staging
# directory, moved into place only once complete, and rolled back if
# registration fails.
#
# Exit: 0 and the next three commands on stdout; nonzero with a
# `new_app:` message on stderr otherwise.
#
# SELFTEST: --selftest proves the refusals and the rollback are load-bearing
# inside a throwaway git repo (a scaffold that quietly overwrote something, or
# that left a half-written package behind after a failure, would be exactly
# the defect this script exists to avoid). Run it before touching the
# scaffolder: tools/scripts/new_app.sh --selftest

set -euo pipefail
export LC_ALL=C

die() {
    echo "new_app: $1" >&2
    exit 1
}

# This script's own absolute path (--selftest re-invokes it from a temp repo
# whose cwd is not the one it was launched from).
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

# ── selftest ────────────────────────────────────────────────────────────────
# Every negative here must be a refusal, and every failure must leave nothing
# behind. A selftest that only exercises the happy path would pass on a
# scaffolder that clobbers user work.
selftest() {
    # A global, not a local: the cleanup trap fires at EXIT, after selftest's
    # scope is gone, and `set -u` would call that a bug rather than a cleanup.
    SELFTEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/zcl-new-app-selftest.XXXXXX")" ||
        die "could not create a selftest directory"
    trap 'rm -rf "$SELFTEST_TMP"' EXIT INT TERM
    local tmp="$SELFTEST_TMP"

    # A minimal stand-in repo: the real template, a Makefile with a couple of
    # targets to collide against, nothing else. The script needs `git` to find
    # the root and nothing more.
    git init -q "$tmp/repo"
    mkdir -p "$tmp/repo/contexts/commons/packages"
    cp -R "$ROOT/contexts/commons/packages/zhello" "$tmp/repo/contexts/commons/packages/zhello"
    printf 'lint:\n\t@true\nclean:\n\t@true\n' > "$tmp/repo/Makefile"
    mkdir -p "$tmp/repo/contexts/commons/apps"

    local run="bash $SELF"
    # $0 is relative in the common invocation, and the inner run happens in
    # the temp repo, where the relative path names nothing.

    # 1. The happy path: scaffolded, renamed everywhere, registered.
    (cd "$tmp/repo" && $run zdemo > "$tmp/run.out" 2>&1) ||
        { echo "$0: selftest FAIL — a clean scaffold exited nonzero" >&2; return 1; }
    [ -f "$tmp/repo/contexts/commons/packages/zdemo/src/zdemo.c" ] ||
        { echo "$0: selftest FAIL — src/zdemo.c missing after the scaffold" >&2; return 1; }
    [ -f "$tmp/repo/contexts/commons/packages/zdemo/include/zdemo/zdemo.h" ] ||
        { echo "$0: selftest FAIL — include/zdemo/zdemo.h missing after the scaffold" >&2; return 1; }
    if grep -rq "zhello" "$tmp/repo/contexts/commons/packages/zdemo"; then
        echo "$0: selftest FAIL — the scaffold still names zhello somewhere" >&2
        return 1
    fi
    # (contexts/commons/apps/local_gui_apps.mk may legitimately name zhello: its one-time header
    # explains why the template itself is not registered there.)
    grep -q "^GUI_APPS += zdemo$" "$tmp/repo/contexts/commons/apps/local_gui_apps.mk" ||
        { echo "$0: selftest FAIL — zdemo was not registered" >&2; return 1; }

    # 2. Refusals: same name, template name, taken make target, bad name.
    for attempt in zdemo zhello lint Zdemo; do
        if (cd "$tmp/repo" && $run "$attempt" >/dev/null 2>&1); then
            echo "$0: selftest FAIL — '$attempt' should have been refused" >&2
            return 1
        fi
    done
    [ -f "$tmp/repo/contexts/commons/packages/zdemo/src/zdemo.c" ] ||
        { echo "$0: selftest FAIL — a refusal damaged the existing scaffold" >&2; return 1; }

    # 3. A failure mid-run must leave neither package nor registration: once
    #    before the move (a registry the script cannot write) and once after
    #    it (the documented test hook), which is the harder rollback.
    chmod 444 "$tmp/repo/contexts/commons/apps/local_gui_apps.mk"
    if (cd "$tmp/repo" && $run other_app >/dev/null 2>&1); then
        echo "$0: selftest FAIL — an unwritable registry did not fail the run" >&2
        return 1
    fi
    chmod 644 "$tmp/repo/contexts/commons/apps/local_gui_apps.mk"
    if (cd "$tmp/repo" && NEW_APP_FAIL_AFTER_MOVE=1 $run other_app >/dev/null 2>&1); then
        echo "$0: selftest FAIL — a simulated post-move failure did not fail the run" >&2
        return 1
    fi
    [ -d "$tmp/repo/contexts/commons/packages/other_app" ] &&
        { echo "$0: selftest FAIL — a failed run left a package behind" >&2; return 1; }
    grep -q "other_app" "$tmp/repo/contexts/commons/apps/local_gui_apps.mk" &&
        { echo "$0: selftest FAIL — a failed run left a registration behind" >&2; return 1; }

    rm -rf "$tmp"
    trap - EXIT INT TERM
    echo "$0: selftest OK — clean scaffold accepted, zhello fully renamed, four refusals held, failed run rolled back"
}

# ── argument shape ──────────────────────────────────────────────────────────
# --help needs nothing from the checkout; everything else does, so --selftest
# dispatches only after ROOT below is resolved.
case "${1:-}" in
    --help|-h)  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --selftest|'') ;;
    *) [ "$#" -eq 1 ] ||
        die "unknown argument '${1:-}' (expected --selftest, --help, or a NAME)" ;;
esac

NAME="${1:-}"
# The checkout root, resolved before anything else: --selftest copies the
# template out of it, and every path below is relative to it.
ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" ||
    die "not inside a z23 checkout (git rev-parse --show-toplevel failed)"
cd "$ROOT"

if [ "${1:-}" = "--selftest" ]; then
    selftest
    exit $?
fi

TEMPLATE="contexts/commons/packages/zhello"
PKG_DIR="contexts/commons/packages/$NAME"
REGISTRY="contexts/commons/apps/local_gui_apps.mk"
BUILD_OUT="build/app-bundle"

[ -d "$TEMPLATE" ] ||
    die "template $TEMPLATE is missing — it is the template of record; restore it rather than scaffold from nothing"

# ── the name ────────────────────────────────────────────────────────────────
# A lowercase C identifier: package name, make target name and symbol prefix
# in one. The other two spellings are derived here, never asked for — <NAME>
# for header guards and Makefile variables, <Title> for the .app's name.
case "$NAME" in
    zhello)
        die "'zhello' is the template — scaffold a new name from it, do not re-create it"
        ;;
    ''|[0-9]*|*[!a-z0-9_]*)
        die "NAME must match ^[a-z][a-z0-9_]*\$ — got '$NAME'"
        ;;
esac

UPPER="$(printf '%s' "$NAME" | tr 'a-z' 'A-Z')"
TITLE="$(printf '%s' "$NAME" | cut -c1 | tr 'a-z' 'A-Z')$(printf '%s' "$NAME" | cut -c2-)"

# ── collisions: each of these is a refused scaffold, never an overwrite ─────
if [ -e "$PKG_DIR" ]; then
    die "$PKG_DIR already exists — refusing to overwrite it"
fi
if [ -f "$REGISTRY" ] && grep -qE "^GUI_APPS \+= $NAME\$" "$REGISTRY"; then
    die "$REGISTRY already registers '$NAME' — refusing to register it twice"
fi
# A scaffolded app claims four named targets (plus the `build/bin/<name>`
# file target). If any of them is already taken (lint, clean, install,
# test-parallel, …) the scaffold would shadow a real target, so it stops here.
for goal in "$NAME" "$NAME-selftest" "$NAME-clean" "$NAME-app"; do
    if grep -qE "^$goal[[:space:]]*:" Makefile; then
        die "target '$goal' already exists in the Makefile — pick another NAME"
    fi
done

# ── stage the tree, transform it, then move it into place ──────────────────
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/zcl-new-app.XXXXXX")" ||
    die "could not create a staging directory"
rollback() {
    rm -rf "$STAGE"
    # Put the registry back to its pre-run length (head -c, not truncate:
    # `truncate` is not in Apple's command-line tools).
    if [ -n "${REGISTRY_LEN_BEFORE:-}" ] && [ -f "$REGISTRY" ]; then
        now="$(wc -c < "$REGISTRY" | tr -d ' ')"
        if [ "$now" -gt "$REGISTRY_LEN_BEFORE" ]; then
            head -c "$REGISTRY_LEN_BEFORE" "$REGISTRY" > "$REGISTRY.rollback" &&
                mv "$REGISTRY.rollback" "$REGISTRY" ||
                rm -f "$REGISTRY.rollback"
        fi
    fi
    if [ -d "$PKG_DIR" ]; then
        rm -rf "$PKG_DIR"
        echo "new_app: rolled the partial scaffold back out of $PKG_DIR" >&2
    fi
}
trap rollback EXIT INT TERM

cp -R "$TEMPLATE" "$STAGE/$NAME" || die "copying $TEMPLATE failed"

# Rewrite the name in place. `sed -i` is not portable across BSD and GNU, so
# each file goes through a sibling temp file — which also leaves the tree
# either fully renamed or untouched, never half-renamed.
while IFS= read -r -d '' f; do
    sed -e "s/zhello/$NAME/g" \
        -e "s/ZHELLO/$UPPER/g" \
        -e "s/Zhello/$TITLE/g" "$f" > "$f.renamed" ||
        die "rewriting $f failed"
    mv "$f.renamed" "$f"
done < <(find "$STAGE/$NAME" -type f -print0 | LC_ALL=C sort -z)

renamed_hits="$(grep -rl "zhello" "$STAGE/$NAME" || true)"
if [ -n "$renamed_hits" ]; then
    die "internal error: these files still name zhello after the rewrite: $(printf '%s ' $renamed_hits)"
fi

# Same rename for the paths themselves — the primary TU is src/<name>.c and
# the public header include/<name>/<name>.h, which is what the generated
# build rules glob by name. -depth so a directory is renamed after whatever
# is inside it, and no stale path is ever revisited.
while IFS= read -r -d '' p; do
    newbase="$(printf '%s' "$(basename "$p")" |
        sed -e "s/zhello/$NAME/g" -e "s/ZHELLO/$UPPER/g" -e "s/Zhello/$TITLE/g")"
    mv "$p" "$(dirname "$p")/$newbase" || die "renaming $p failed"
done < <(find "$STAGE/$NAME" -depth -name '*zhello*' -print0)

# The build contract of a GUI package, checked before anything is registered:
# two application translation units and one namespaced public header, spelled
# <name>. Shared utility objects stay outside the package.
for required in "src/$NAME.c" "app/main.c" "include/$NAME/$NAME.h" "README.md"; do
    [ -f "$STAGE/$NAME/$required" ] ||
        die "scaffold is incomplete: $STAGE/$NAME/$required is missing"
done

# ── registration: the one block that puts the app on the build ─────────────
# The package moves into place first and the registry is appended last, so a
# failure anywhere leaves either "nothing" or "package + registration", and
# the rollback below can always take both back.
mkdir -p "$(dirname "$REGISTRY")"
touch "$REGISTRY"
REGISTRY_LEN_BEFORE="$(wc -c < "$REGISTRY" | tr -d ' ')"

mv "$STAGE/$NAME" "$PKG_DIR" || die "moving the scaffold into $PKG_DIR failed"

# Test hook (--selftest): fail here, with the package already in place and the
# registration not yet written, to prove the rollback takes both halves back.
if [ "${NEW_APP_FAIL_AFTER_MOVE:-}" = "1" ]; then
    die "NEW_APP_FAIL_AFTER_MOVE: simulated failure after the move"
fi

if [ ! -s "$REGISTRY" ]; then
    {
        echo '# contexts/commons/apps/local_gui_apps.mk — scaffolded GUI apps, one block per app.'
        echo '#'
        echo '# Gitignored on purpose: an app created by `make new-app` is user-local'
        echo '# content, not tree content. The top-level Makefile -includes this file'
        echo '# and generates every <app>, <app>-selftest, <app>-clean and <app>-app'
        echo '# rule from GUI_APPS, so registering an app here IS the whole build'
        echo '# integration — no Makefile edit. zhello is deliberately absent: it is'
        echo '# tracked in the Makefile itself, as the template of record.'
        echo
    } > "$REGISTRY" || die "creating $REGISTRY failed"
fi
{
    echo "# ── $NAME ──"
    echo "GUI_APPS += $NAME"
    echo "# Per-app variables are keyed by the package name exactly as spelled"
    echo "# (lowercase); the top-level Makefile's template has no case conversion."
    printf '%s_APP_TITLE := %s\n' "$NAME" "$TITLE"
    echo "# Run arguments: \`make $NAME ${UPPER}_ARGS=--seconds=2\`. The uppercased"
    echo "# spelling is the documented one; this alias is what makes it work."
    printf '%s_ARGS = $(%s_ARGS)\n' "$NAME" "$UPPER"
    echo
} >> "$REGISTRY" || die "appending to $REGISTRY failed"

rm -rf "$STAGE"
trap - EXIT INT TERM

echo "new_app: scaffolded $PKG_DIR from $TEMPLATE"
echo "new_app: registered '$NAME' in $REGISTRY"
echo ""
echo "Next:"
echo "  make $NAME              # build it and open the window"
echo "  make $NAME-selftest     # headless proof: N frames, no window, exit 0"
echo "  make $NAME-app          # reproducible $TITLE.app under $ROOT/$BUILD_OUT"
