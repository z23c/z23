#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Purpose: prove complete portable lint-cache enumeration and refusal paths.
set -euo pipefail
umask 077
here="$(cd "${0%/*}" && pwd)"
module="${1:-$here/lint_cache.sh}"
work="$(mktemp -d "${TMPDIR:-/tmp}/lint-cache-selftest.XXXXXX")"
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM
trap 'printf "lint-cache-selftest: FAIL at line %s\n" "$LINENO" >&2' ERR
mkdir "$work/bin"
if [ "$(uname -s)" = Darwin ]; then ln -s /usr/bin/awk "$work/bin/awk"; fi
export PATH="$work/bin:$PATH"
tracked_names=('space name' '-leading')
untracked_names=('untracked space' '-untracked')
case "$(uname -s)" in
 MINGW*|MSYS*|CYGWIN*)
  echo 'BOUNDARY: Win32 forbids newline/tab filenames; all other cache checks remain required'
  ;;
 *) tracked_names+=($'line\nbreak' $'tab\tname')
    untracked_names+=($'untracked\nline' $'untracked\ttab') ;;
esac
repo="$work/repo"
git init -q "$repo"
for ((i=0;i<100;i++)); do printf '%s\n' "$i" > "$repo/file$i"; done
for path in "${tracked_names[@]}"; do printf original > "$repo/$path"; done
git -C "$repo" add -- .
git -C "$repo" update-index --add --cacheinfo 160000,1111111111111111111111111111111111111111,vendor/tor
source "$module"
lint_cache_derive_tree_key "$repo"
[[ "$LINT_CACHE_TRACKED_N" -eq $((100 + ${#tracked_names[@]})) ]]
echo 'PASS: tracked special-name files counted; gitlink excluded'
[[ "$LINT_CACHE_UNTRACKED_N" -eq 0 ]]
echo 'PASS: empty untracked set is valid'
first="$LINT_CACHE_TREE_KEY"
for path in "${tracked_names[@]}"; do
 printf changed > "$repo/$path"
 lint_cache_derive_tree_key "$repo"
 [[ "$LINT_CACHE_TREE_KEY" != "$first" ]]
 printf original > "$repo/$path"
 lint_cache_derive_tree_key "$repo"
 [[ "$LINT_CACHE_TREE_KEY" == "$first" ]]
done
echo 'PASS: every special tracked filename changes/restores key'
for path in "${untracked_names[@]}"; do printf original > "$repo/$path"; done
mkdir -p "$repo/build" "$repo/tools/lint/fixtures/planted"
printf hidden > "$repo/build/ignored.c"
printf hidden > "$repo/_test_fixture.c"
printf hidden > "$repo/tools/lint/fixtures/planted/ignored.c"
lint_cache_derive_tree_key "$repo"
[[ "$LINT_CACHE_UNTRACKED_N" -eq ${#untracked_names[@]} ]]
second="$LINT_CACHE_TREE_KEY"
for path in "${untracked_names[@]}"; do
 printf changed > "$repo/$path"
 lint_cache_derive_tree_key "$repo"
 [[ "$LINT_CACHE_TREE_KEY" != "$second" ]]
 printf original > "$repo/$path"
done
echo 'PASS: special untracked filenames keyed; exclusions preserved'
# Real Git supplies >100 complete records; the wrapper appends an incomplete
# final record yet returns success, exercising record completeness separately.
export PROBE_REAL_GIT="$(command -v git)"
cat > "$work/bin/git" <<'WRAPPER'
#!/usr/bin/env bash
"$PROBE_REAL_GIT" "$@" || exit $?
case "${PROBE_TRUNCATE:-}:$*" in
 tracked:*'ls-files -s -z'*) printf '100644 1111111111111111111111111111111111111111 0\ttruncated' ;;
 untracked:*'ls-files -z --others --exclude-standard'*) printf 'truncated-visible' ;;
esac
exit 0
WRAPPER
chmod 0755 "$work/bin/git"
hash -r
for mode in tracked untracked; do
 export PROBE_TRUNCATE="$mode"
 if lint_cache_derive_tree_key "$repo" > "$work/truncated-$mode.log" 2>&1; then
  echo "FAIL: unterminated $mode record accepted"; exit 1
 fi
 grep -q "unterminated $mode" "$work/truncated-$mode.log"
 echo "PASS: unterminated $mode record refuses despite successful Git exit"
done
unset PROBE_TRUNCATE
for pipe_mode in on off; do
 (
  if [ "$pipe_mode" = off ]; then set +o pipefail; fi
  cat() { return 1; }
  if lint_cache_derive_tree_key "$repo" > "$work/aggregate-$pipe_mode.log" 2>&1; then
   echo 'FAIL: aggregate manifest read failure accepted'; exit 1
  fi
  [[ -z "$LINT_CACHE_TREE_KEY" ]]
  grep -q 'cannot hash complete manifests' "$work/aggregate-$pipe_mode.log"
 )
done
echo 'PASS: aggregate manifest read failure refuses regardless of caller pipefail'
rm "$repo/file0"
if lint_cache_derive_tree_key "$repo" > "$work/missing.log" 2>&1; then echo 'FAIL: missing tracked file accepted'; exit 1; fi
echo 'PASS: missing tracked file refuses'
git init -q "$work/short"
printf short > "$work/short/one"
git -C "$work/short" add one
if lint_cache_derive_tree_key "$work/short" > "$work/short.log" 2>&1; then echo 'FAIL: short tree accepted'; exit 1; fi
echo 'PASS: anti-hollow floor refuses one-file tree'
(
 set +o pipefail
 if lint_cache_derive_tree_key "$repo" > "$work/no-pipefail.log" 2>&1; then exit 1; fi
)
echo 'PASS: missing-file hash failure refuses with caller pipefail disabled'
