#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_no_stray_root_files.sh — the repository root is a curated list.
#
# `ls` at the root is the first thing a newcomer reads. It should show the
# source areas and the top-level docs, nothing else. What it used to show
# instead was a stray SQLite database (`node.db`), a per-pid test database
# (`test_frontier_cap_<pid>.db`), a `nohup` capture from an ad-hoc script
# (`revertproof.nohup.log`), and a second scratch directory sitting beside
# the sanctioned one (`test-tmp-reclaim/`). Every one of those was
# gitignored, so `git status` was clean and nothing ever objected — the
# .gitignore was hiding the mess rather than preventing it.
#
# This gate is the thing that objects. It compares the root's directory
# entries against two sets:
#
#   1. Everything git tracks at the top level (derived, never hand-listed —
#      so a folder move or a new top-level area needs no edit here).
#   2. ROOT_ALLOWED below: the small, explicit set of generated or
#      developer-local root entries that legitimately exist untracked
#      (build output, the vendor tree, editor/tool caches, the one
#      sanctioned test scratch root, the clangd compilation database).
#
# Anything else in the root is a stray: name it, and say where it belongs.
# The fix is almost never "add it to the allowlist" — it is to make whatever
# wrote it write into a per-run scratch dir (`./test-tmp/<prefix>_<pid>_<tag>`
# via test_make_tmpdir) or a state/log directory instead.
#
# Scope is DEPTH 1 ONLY. What lives inside build/, test-tmp/, or vendor/ is
# not this gate's business; check-no-stray-untracked-source covers stray .c
# and .h files inside the scanned source dirs.
#
# Mode is always FAIL (no baseline): a stray root file is never something to
# grandfather, only something to delete or to re-home at its writer.
#
# Selftest override: ZCL_ROOT_STRAY_EXTRA_FOR_TEST names one additional
# root-relative entry to treat as a stray candidate even if it would
# otherwise be allowed. The selftest in tests/harness/src/test_make_lint_gates.c
# uses the plain plant/trip/recover path and does not need it; the variable
# exists so a future probe can trip the gate without writing to the tree.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"

# Untracked root entries that are legitimately there. Keep this SHORT and
# keep each line's reason obvious; a growing allowlist means the root is
# drifting back into a junk drawer.
ROOT_ALLOWED=(
    .git                  # the repo itself (a file in a linked worktree)
    build                 # all build output
    vendor                # vendored deps, built by `make vendor`
    test-tmp              # THE per-run test scratch root (test_make_tmpdir)
    compile_commands.json # `make compdb` — clangd/editor database
    .cache                # lint timings, clangd index, other tool caches
    .codeindex            # the source navigator's derived index
    .zvcs                 # in-tree version-control state
    .core-unseal-token    # owner unseal ritual token (never tracked)
    .zcl_test_render      # render-test scratch dir
    chaos-output          # chaos harness run artifacts
    .antigravitycli .gemini .aider .vscode .idea  # other tools' local state
    tags TAGS             # ctags output
    .DS_Store             # macOS finder droppings
)

declare -A allowed=()
for a in "${ROOT_ALLOWED[@]}"; do allowed["$a"]=1; done

# Tracked top-level entries, derived from git. In a checkout with no git
# (tarball, hardlink sandbox) this comes back empty and the floor below
# turns that into a LOUD failure rather than a flood of false strays.
tracked_count=0
while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    allowed["${p%%/*}"]=1
    tracked_count=$((tracked_count + 1))
done < <(git ls-files 2>/dev/null || true)

gate_require_scanned "$tracked_count" 100 check-no-stray-root-files \
    "git ls-files returned almost nothing — not a git checkout, or the wrong cwd."

extra="${ZCL_ROOT_STRAY_EXTRA_FOR_TEST:-}"
[[ -n "$extra" ]] && unset "allowed[$extra]"

strays=()
scanned=0
while IFS= read -r name; do
    [[ -z "$name" || "$name" == "." || "$name" == ".." ]] && continue
    scanned=$((scanned + 1))
    # `.aider*` and friends: allow a prefix match for the tool-state entries
    # that append a suffix (.aider.chat.history.md, .aider.tags.cache.v3).
    base="$name"
    [[ "$base" == .aider* ]] && base=".aider"
    [[ -n "${allowed[$base]:-}" ]] && continue
    # A crash dump is transient debugging state, not project debris.
    [[ "$name" == core.* || "$name" == vgcore.* ]] && continue
    strays+=("$name")
done < <(ls -A . 2>/dev/null | sort)

gate_require_scanned "$scanned" 20 check-no-stray-root-files \
    "the repo root listed fewer than 20 entries — wrong cwd?"

if (( ${#strays[@]} > 0 )); then
    echo "FAIL: ${#strays[@]} stray entr(y/ies) in the repository root" >&2
    echo "  The root is a curated list: source areas, top-level docs, and a" >&2
    echo "  short allowlist of generated/local entries. These are neither." >&2
    echo "  They are gitignored, so 'git status' stays clean while 'ls' shows" >&2
    echo "  a junk drawer — that is exactly what this gate exists to stop." >&2
    for f in "${strays[@]}"; do
        echo "    $f [stray root entry]" >&2
    done
    echo "  Fix at the WRITER, not here: a test writes its scratch under" >&2
    echo "  ./test-tmp/ (test_make_tmpdir in tests/harness/include/test/test_core.h)," >&2
    echo "  a script writes its log under a state/log dir. 'git add' it if it" >&2
    echo "  is real new content; delete it if it is debris." >&2
    exit 1
fi

echo "[check_no_stray_root_files] scanned $scanned root entr(y/ies); 0 strays"
exit 0
