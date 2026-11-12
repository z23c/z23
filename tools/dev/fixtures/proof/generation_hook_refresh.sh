#!/bin/sh
# Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
# purpose: Prove generation arming permits the actual native-hook refresher.
set -eu
source_root=${1:?source root}; donor=${2:?donor}; generation=${3:?generation}
native="$source_root/build/bin/z23-git-hook"
refresh="$source_root/build/bin/refresh-git-hooks"
installer="$source_root/tools/scripts/install_git_hooks.sh"
[ -x "$native" ] && [ -x "$refresh" ] && [ -x "$installer" ] || {
    echo 'generation hook fixture: required native hook or installer absent' >&2; exit 1;
}
# All writes are inside the caller-created disposable repositories. Never
# execute the changed image: this is the existing installer-selftest rebuild
# convention, using actual native bytes plus a distinguishable trailing marker.
mkdir -p "$generation/build/bin" "$generation/build/githooks"
cp -- "$native" "$generation/build/githooks/z23-git-hook"
cp -- "$native" "$generation/build/bin/z23-git-hook.rebuilt"
printf 'rebuilt\n' >> "$generation/build/bin/z23-git-hook.rebuilt"
rebuilt="$generation/build/bin/z23-git-hook.rebuilt"
for hook in pre-push post-commit post-merge post-checkout; do
    rm -f -- "$generation/build/githooks/$hook"
    ln -s z23-git-hook "$generation/build/githooks/$hook"
done
shared_before=$(git -C "$donor" config --local --get core.hooksPath || true)
donor_before=$(git -C "$donor" config --worktree --get core.hooksPath)
config=$(git -C "$donor" rev-parse --absolute-git-dir)/config.worktree
cp -- "$config" "$generation/donor-config-before"
run_refresh() {
    ZCL_GIT_HOOK_SOURCE_ROOT="$source_root" ZCL_GIT_HOOK_ROOT="$generation" \
        ZCL_GIT_HOOK_NATIVE_BIN="$rebuilt" "$refresh"
}
# Reused-bundle helper path: git-hook rebuild calls REFRESH, not INSTALLER.
if cmp -s "$rebuilt" "$generation/build/githooks/z23-git-hook"; then
    echo 'generation hook fixture: expected stale installed hook bytes' >&2
    exit 1
fi
run_refresh
cmp -s "$rebuilt" "$generation/build/githooks/z23-git-hook"
[ "$(git -C "$generation" config --worktree --get core.hooksPath)" = build/githooks ]
for hook in pre-push post-commit post-merge post-checkout; do
    [ "$(readlink "$generation/build/githooks/$hook")" = z23-git-hook ]
done
# Full-bundle control explicitly invokes the installer, even from an absolute
# generation-local configuration. It repairs stale bytes in either version.
cp -- "$native" "$generation/build/githooks/z23-git-hook"
git -C "$generation" config --worktree core.hooksPath "$generation/build/githooks"
ZCL_GIT_HOOK_SOURCE_ROOT="$source_root" ZCL_GIT_HOOK_ROOT="$generation" \
    ZCL_GIT_HOOK_NATIVE_BIN="$rebuilt" ZCL_GIT_HOOK_HOST=posix "$installer"
cmp -s "$rebuilt" "$generation/build/githooks/z23-git-hook"
[ "$(git -C "$generation" config --worktree --get core.hooksPath)" = build/githooks ]
# An arbitrary external hook path stays unrecognized, untouched and unarmed.
external="$generation/external-hooks"
mkdir -p "$external"
printf 'external sentinel\n' > "$external/sentinel"
git -C "$generation" config --worktree core.hooksPath "$external"
cp -- "$native" "$generation/build/githooks/z23-git-hook"
run_refresh
cmp -s "$native" "$generation/build/githooks/z23-git-hook"
[ "$(git -C "$generation" config --worktree --get core.hooksPath)" = "$external" ]
[ "$(cat "$external/sentinel")" = 'external sentinel' ]
[ ! -e "$external/z23-git-hook" ]
[ "$(git -C "$donor" config --local --get core.hooksPath || true)" = "$shared_before" ]
[ "$(git -C "$donor" config --worktree --get core.hooksPath)" = "$donor_before" ]
cmp -s "$config" "$generation/donor-config-before"
git -C "$generation" config --worktree core.hooksPath build/githooks
# Leave only disposable state; no hook is executed during fixture teardown.
printf 'generation hook refresh: reused refresh, full install, external refusal PASS\n'
