#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Supersession identity for the complete current build-source inventory. Git is
# used only to enumerate tracked/untracked paths and inspect index flags; its
# object ids and commit history are never hashed or trusted. This is a
# verify-loop diagnostic, not the immutable Phase-3 publication epoch schema.
# Initialized gitlinks are inventoried recursively. Exact static archives and
# generated vendor headers selected by the current build are included even when
# Git-ignored. Every file beneath the C23 source/include/template roots is also
# inventoried independently of `.gitignore` and `.git/info/exclude`, because
# Make wildcards and compiler includes do not honor Git ignore rules. The
# compiler/toolchain state, environment, and full build configuration remain
# deferred. Hidden index bits, discovery errors, and unsupported source types
# fail closed. Linked binaries must also `verify-record` after linking; capture
# alone is not a filesystem snapshot or publication receipt. `verify-mutation`
# is the bounded post-proof CAS: it re-enumerates the complete inventory and
# compares ABA-resistant file, directory/index, and Git exclude-policy epochs
# around that scan, but does not redundantly re-hash proved source contents.

set -euo pipefail

MODE="${1:-capture}"
EXPECTED="${2:-}"
EXPECTED_CLEAN="${3:-}"
EXPECTED_MUTATION="${4:-}"
NEED_DIRTY_PATHS=0
[ "$MODE" = paths ] && NEED_DIRTY_PATHS=1
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 2
SELF="$SELF_DIR/$(basename "${BASH_SOURCE[0]}")"
if [ -n "${ZCL_SOVEREIGN_SOURCE_ROOT:-}" ]; then
    exec "$SELF_DIR/sovereign-source-identity.sh" "$@"
fi
ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "source-identity: not inside a Git worktree" >&2
    exit 2
}
cd "$ROOT"

# Optional host-local, per-Make-invocation memoization for capture-record and
# verify-record (see capture_record_cached() below). One plain `make
# build-only` or `make t-fast` calls one of those two modes 4-5 times even
# with zero source changes (Makefile parse-time BUILD_SOURCE_RECORD, the
# mutation/identity stamps, and every build-epoch-session.sh acquire/verify),
# and each call is a full git-ls-files+find+sha256 walk of every build input.
# A caller opts in by setting ZCL_SOURCE_IDENTITY_SESSION to a `pid:start`
# token identifying the ONE live Make process driving the whole invocation
# (Make's own pid plus its /proc start-time in clock ticks, so a later
# process that reuses the same pid never collides with a stale entry). Unset
# or malformed disables memoization for that call -- always safe, just slower.
ZCL_SOURCE_IDENTITY_SESSION="${ZCL_SOURCE_IDENTITY_SESSION:-}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-source-identity.XXXXXX")" || exit 2
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

fail()
{
    echo "source-identity: $*" >&2
    exit 3
}

GIT_INDEX_PATH=""
if [ "$MODE" = verify-mutation ]; then
    GIT_INDEX_PATH="$(git rev-parse --git-path index 2>/dev/null)" ||
        fail "could not resolve Git index path"
    case "$GIT_INDEX_PATH" in
        /*) ;;
        *) GIT_INDEX_PATH="$ROOT/$GIT_INDEX_PATH" ;;
    esac
    [ -f "$GIT_INDEX_PATH" ] || fail "Git index is unavailable"
    : > "$WORK/epoch-indexes"
    printf '%s\0' "$GIT_INDEX_PATH" >> "$WORK/epoch-indexes"
    : > "$WORK/epoch-repos"
    printf '.\0' >> "$WORK/epoch-repos"
fi

sha256_stream()
{
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | awk '{print $1}'
    else
        fail "no SHA-256 implementation is available"
    fi
}

sha256_file()
{
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum < "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 < "$1" | awk '{print $1}'
    else
        fail "no SHA-256 implementation is available"
    fi
}

# Collapse host permission details into the modes Git can represent. Special
# bits and group/other write bits are not source identity; executable intent is.
canonical_source_mode()
{
    local kind="$1" raw="$2" out_name="$3" value canonical
    [[ "$raw" =~ ^[0-9a-fA-F]+$ ]] || return 1
    value=$((16#$raw))
    case "$kind" in
        L)
            [ $((value & 0170000)) -eq $((0120000)) ] || return 1
            canonical=120000
            ;;
        F)
            [ $((value & 0170000)) -eq $((0100000)) ] || return 1
            if [ $((value & 0111)) -ne 0 ]; then
                canonical=100755
            else
                canonical=100644
            fi
            ;;
        *) return 1 ;;
    esac
    printf -v "$out_name" '%s' "$canonical"
}

# readlink writes one record-terminating newline. Command substitution normally
# strips every trailing newline, including legal newlines that are part of the
# symlink target. Append a non-newline sentinel, then remove exactly the
# sentinel and readlink's one delimiter while preserving target bytes.
read_symlink_target()
{
    local link_path="$1" out_name="$2" raw sentinel=$'\x1f'
    raw="$(
        readlink -- "$link_path" || exit 1
        printf '%s' "$sentinel"
    )" || return 1
    [ "${raw: -1}" = "$sentinel" ] || return 1
    raw="${raw%"$sentinel"}"
    [ "${raw: -1}" = $'\n' ] || return 1
    raw="${raw%$'\n'}"
    printf -v "$out_name" '%s' "$raw"
}

# `git diff` deliberately does not reveal content hidden by assume-unchanged
# or skip-worktree.  Refuse the entire publication epoch if either bit exists;
# silently trusting those flags would let a sealed edit evade the dirty set.
git ls-files -v -z > "$WORK/index-tags" ||
    fail "could not inspect Git index flags"
while IFS= read -r -d '' record; do
    tag="${record:0:1}"
    path="${record:2}"
    case "$tag" in
        S|[a-z]) fail "hidden Git index bit on path: $path (clear skip-worktree/assume-unchanged before publication)" ;;
    esac
done < "$WORK/index-tags"

git ls-files --others --exclude-standard -z -- > "$WORK/untracked" ||
    fail "untracked dirty-set discovery failed"
: > "$WORK/paths"
if [ "$NEED_DIRTY_PATHS" = 1 ]; then
    git diff --name-only --no-renames -z HEAD -- > "$WORK/tracked" ||
        fail "tracked dirty-set discovery failed"
    {
        cat "$WORK/tracked"
        cat "$WORK/untracked"
    } | LC_ALL=C sort -zu > "$WORK/paths"
fi

# Build the COMPLETE current source inventory separately from the dirty-path
# API above. A clean tree derives its identity from file bytes, never a Git
# object id. An initialized gitlink is recursively inventoried from its current
# tracked and nonignored-untracked bytes; a missing gitlink gets a distinct
# marker. Direct vendored archive and generated-header inputs are included even
# when ignored, so an active vendor input change supersedes the build identity.
: > "$WORK/tracked-source"
declare -A GITLINK_STATE=()
GITLINK_SEQ=0
if [ "$MODE" = verify-mutation ]; then
    : > "$WORK/source-dirs"
    printf '.\0' >> "$WORK/source-dirs"
fi

append_prefixed_nul()
{
    local input="$1" prefix="$2" output="$3" relative
    while IFS= read -r -d '' relative; do
        printf '%s/%s\0' "$prefix" "$relative" >> "$output"
    done < "$input"
}

collect_gitlink()
{
    local prefix="$1" top physical record meta relative mode stage tag path
    local gitlink_index
    local seq=$GITLINK_SEQ
    GITLINK_SEQ=$((GITLINK_SEQ + 1))
    printf '%s\0' "$prefix" >> "$WORK/tracked-source"
    GITLINK_STATE["$prefix"]=absent
    if [ ! -e "$prefix" ] && [ ! -L "$prefix" ]; then
        return 0
    fi
    [ -d "$prefix" ] && [ ! -L "$prefix" ] ||
        fail "invalid gitlink worktree: $prefix"
    if [ ! -e "$prefix/.git" ]; then
        if find "$prefix" -mindepth 1 -maxdepth 1 -print -quit \
                > "$WORK/gitlink-uninitialized-$seq" 2>/dev/null &&
           [ ! -s "$WORK/gitlink-uninitialized-$seq" ]; then
            GITLINK_STATE["$prefix"]=uninitialized-empty
            return 0
        fi
        fail "nonempty uninitialized gitlink would omit bytes: $prefix"
    fi
    top="$(git -C "$prefix" rev-parse --show-toplevel 2>/dev/null)" ||
        fail "could not resolve gitlink worktree: $prefix"
    top="$(cd "$top" && pwd -P)" ||
        fail "could not canonicalize gitlink worktree: $prefix"
    physical="$(cd "$prefix" && pwd -P)" ||
        fail "could not enter gitlink worktree: $prefix"
    [ "$top" = "$physical" ] ||
        fail "gitlink resolves to a foreign worktree: $prefix"
    GITLINK_STATE["$prefix"]=present
    if [ "$MODE" = verify-mutation ]; then
        gitlink_index="$(git -C "$prefix" rev-parse --git-path index \
            2>/dev/null)" ||
            fail "could not resolve gitlink index path: $prefix"
        case "$gitlink_index" in
            /*) ;;
            *) gitlink_index="$physical/$gitlink_index" ;;
        esac
        [ -f "$gitlink_index" ] ||
            fail "gitlink index is unavailable: $prefix"
        printf '%s\0' "$gitlink_index" >> "$WORK/epoch-indexes"
        printf '%s\0' "$prefix" >> "$WORK/epoch-repos"
        find "$prefix" -name .git -prune -o -type d -print0 \
            >> "$WORK/source-dirs" 2>/dev/null ||
            fail "gitlink directory inventory failed: $prefix"
    fi

    git -C "$prefix" ls-files -v -z > "$WORK/gitlink-tags-$seq" ||
        fail "could not inspect gitlink index flags: $prefix"
    while IFS= read -r -d '' record; do
        tag="${record:0:1}"
        path="${record:2}"
        case "$tag" in
            S|[a-z]) fail "hidden Git index bit in gitlink path: $prefix/$path" ;;
        esac
    done < "$WORK/gitlink-tags-$seq"

    git -C "$prefix" ls-files --others --exclude-standard -z -- \
        > "$WORK/gitlink-untracked-$seq" ||
        fail "gitlink untracked discovery failed: $prefix"
    if [ "$NEED_DIRTY_PATHS" = 1 ]; then
        git -C "$prefix" diff --name-only --no-renames -z HEAD -- \
            > "$WORK/gitlink-dirty-$seq" ||
            fail "gitlink dirty-set discovery failed: $prefix"
        append_prefixed_nul "$WORK/gitlink-dirty-$seq" "$prefix" \
            "$WORK/paths"
        append_prefixed_nul "$WORK/gitlink-untracked-$seq" "$prefix" \
            "$WORK/paths"
    fi
    append_prefixed_nul "$WORK/gitlink-untracked-$seq" "$prefix" \
        "$WORK/tracked-source"

    git -C "$prefix" ls-files --stage -z -- \
        > "$WORK/gitlink-index-$seq" ||
        fail "gitlink tracked-source discovery failed: $prefix"
    while IFS= read -r -d '' record; do
        meta="${record%%$'\t'*}"
        relative="${record#*$'\t'}"
        mode="${meta%% *}"
        stage="${meta##* }"
        [ "$stage" = 0 ] ||
            fail "unmerged gitlink index stage $stage for path: $prefix/$relative"
        case "$mode" in
            100644|100755|120000)
                printf '%s/%s\0' "$prefix" "$relative" \
                    >> "$WORK/tracked-source"
                ;;
            160000) collect_gitlink "$prefix/$relative" ;;
            *) fail "unsupported gitlink index mode $mode for path: $prefix/$relative" ;;
        esac
    done < "$WORK/gitlink-index-$seq"
}

git ls-files --stage -z -- > "$WORK/tracked-index" ||
    fail "tracked source discovery failed"
while IFS= read -r -d '' record; do
    meta="${record%%$'\t'*}"
    path="${record#*$'\t'}"
    mode="${meta%% *}"
    stage="${meta##* }"
    [ "$stage" = 0 ] ||
        fail "unmerged index stage $stage for path: $path"
    case "$mode" in
        100644|100755|120000) printf '%s\0' "$path" >> "$WORK/tracked-source" ;;
        160000) collect_gitlink "$path" ;;
        *) fail "unsupported tracked index mode $mode for path: $path" ;;
    esac
done < "$WORK/tracked-index"

# Git ignore policy is not build policy. GNU Make selects C sources with
# wildcards and the compiler recursively opens headers/templates beneath these
# roots even when `.gitignore` or the local `.git/info/exclude` hides them from
# `git ls-files --others --exclude-standard`. Inventory every regular file in
# those roots independently. Reject symlinks, sockets, FIFOs, and other special
# nodes there: a compiler-followed symlink would bind only its target pathname,
# not the mutable target bytes. `.git` metadata inside a future nested worktree
# is pruned; initialized gitlinks are handled by collect_gitlink() above.
BUILD_INPUT_ROOTS=(adapters app application config core domain lib ports src tools)
existing_build_roots=()
for path in "${BUILD_INPUT_ROOTS[@]}"; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        [ -d "$path" ] && [ ! -L "$path" ] ||
            fail "build input root is not a real directory: $path"
        existing_build_roots+=("$path")
    fi
done
if [ "$MODE" = verify-mutation ]; then
    for path in vendor vendor/lib vendor/tor \
                vendor/tor/src/ext/ed25519/donna \
                vendor/tor/src/ext/ed25519/ref10 \
                vendor/tor/src/ext/keccak-tiny; do
        if [ -d "$path" ] && [ ! -L "$path" ]; then
            printf '%s\0' "$path" >> "$WORK/source-dirs"
        fi
    done
fi
if [ "${#existing_build_roots[@]}" -gt 0 ]; then
    find "${existing_build_roots[@]}" -name .git -prune -o \
        ! -type d ! -type f -print0 \
        > "$WORK/build-root-unsupported" 2>/dev/null ||
        fail "build input root discovery failed"
    if [ -s "$WORK/build-root-unsupported" ]; then
        IFS= read -r -d '' path < "$WORK/build-root-unsupported" || true
        fail "unsupported compiler input beneath build roots: ${path:-unknown}"
    fi
    find "${existing_build_roots[@]}" -name .git -prune -o \
        -type f -print0 >> "$WORK/tracked-source" 2>/dev/null ||
        fail "build input inventory failed"
    if [ "$MODE" = verify-mutation ]; then
        find "${existing_build_roots[@]}" -name .git -prune -o \
            -type d -print0 >> "$WORK/source-dirs" 2>/dev/null ||
            fail "build input directory inventory failed"
    fi
fi

# Gitlink discovery appends its own paths after the root diagnostic list was
# sorted. Restore one canonical set for the explicit `paths` mode. Authority
# modes never execute the HEAD-relative diagnostic at all.
if [ "$NEED_DIRTY_PATHS" = 1 ]; then
    LC_ALL=C sort -zu "$WORK/paths" > "$WORK/paths.sorted" ||
        fail "could not canonicalize dirty source inventory"
    mv -- "$WORK/paths.sorted" "$WORK/paths" ||
        fail "could not publish dirty source inventory"
fi

for path in vendor/lib/*.a \
            vendor/tor/libtor.a \
            vendor/tor/src/ext/ed25519/donna/libed25519_donna.a \
            vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a \
            vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a; do
    [ -L "$path" ] && fail "linked archive must not be a symlink: $path"
    if [ -e "$path" ] && [ ! -f "$path" ]; then
        fail "linked archive is not a regular file: $path"
    fi
    [ -f "$path" ] && printf '%s\0' "$path" >> "$WORK/tracked-source"
done

# `-Ivendor/include` is global. Several OpenSSL/zlib headers are generated and
# ignored, but they are compiler inputs just as surely as the linked archives.
# Recursively inventory their exact current bytes; never allow a socket/FIFO or
# another unsupported type to hide beneath the include root.
if [ -e vendor/include ] || [ -L vendor/include ]; then
    [ -d vendor/include ] && [ ! -L vendor/include ] ||
        fail "vendor include root is not a real directory"
    find vendor/include -mindepth 1 ! -type d ! -type f \
        -print -quit > "$WORK/vendor-include-unsupported" 2>/dev/null ||
        fail "vendor include input discovery failed"
    [ ! -s "$WORK/vendor-include-unsupported" ] ||
        fail "unsupported compiler input beneath vendor/include"
    find vendor/include -mindepth 1 -type f -print0 \
        >> "$WORK/tracked-source" 2>/dev/null ||
        fail "vendor include inventory failed"
    if [ "$MODE" = verify-mutation ]; then
        printf 'vendor/include\0' >> "$WORK/source-dirs"
        find vendor/include -mindepth 1 -type d -print0 \
            >> "$WORK/source-dirs" 2>/dev/null ||
            fail "vendor include directory inventory failed"
    fi
fi
{
    cat "$WORK/tracked-source"
    cat "$WORK/untracked"
} | LC_ALL=C sort -zu > "$WORK/source-paths"

if [ "$MODE" = verify-mutation ]; then
    # Directory epochs close the inventory scanner's traversal race. Derive
    # every current input's ancestors, and keep every directory beneath the
    # recursive compiler roots above (including empty/ignored directories).
    # An input created behind the fresh scan therefore changes a directory at
    # the final post-scan observation even though neither path set contains it.
    while IFS= read -r -d '' path; do
        while [[ "$path" == */* ]]; do
            path="${path%/*}"
            printf '%s\0' "$path" >> "$WORK/source-dirs"
        done
    done < "$WORK/source-paths"

    # The global nonignored-untracked selector can discover a future file in
    # an otherwise empty directory outside the recursive compiler roots. Walk
    # only top-level worktree directories and prune every Git-ignored directory
    # by exact inode identity, so nested agent worktrees/build/test debris are
    # never traversed while every directory capable of yielding an authoritative
    # untracked path gets an epoch record.
    git ls-files --others --ignored --exclude-standard --directory -z -- \
        > "$WORK/ignored-inventory" ||
        fail "ignored directory discovery failed"
    ignored_dirs=()
    while IFS= read -r -d '' path; do
        case "$path" in
            */)
                path="${path%/}"
                if [ -d "$path" ] && [ ! -L "$path" ]; then
                    ignored_dirs+=("./$path")
                fi
                ;;
        esac
    done < "$WORK/ignored-inventory"
    shopt -s nullglob dotglob
    top_dirs=(*/)
    shopt -u nullglob dotglob
    scan_roots=()
    for path in "${top_dirs[@]}"; do
        path="${path%/}"
        [ "$path" = .git ] || scan_roots+=("./$path")
    done
    if [ "${#scan_roots[@]}" -gt 0 ]; then
        find_args=("${scan_roots[@]}")
        for path in "${ignored_dirs[@]}"; do
            find_args+=(-samefile "$path" -prune -o)
        done
        find_args+=(-type d -print0)
        find "${find_args[@]}" >> "$WORK/source-dirs" 2>/dev/null ||
            fail "nonignored source directory inventory failed"
    fi

    LC_ALL=C sort -zu "$WORK/source-dirs" > "$WORK/source-dirs.sorted" ||
        fail "could not canonicalize source directory inventory"
    {
        cat "$WORK/source-dirs"
        # Git may compress a directory whose every child is ignored into one
        # trailing-slash record even when a self-hidden .gitignore inside that
        # directory supplied the rules. Bind that boundary selector without
        # recursively traversing or epoch-watching ignored build/test/worktree
        # debris.
        for path in "${ignored_dirs[@]}"; do
            printf '%s\0' "${path#./}"
        done
    } | LC_ALL=C sort -zu > "$WORK/selector-dirs.sorted" ||
        fail "could not canonicalize Git selector directory inventory"
    LC_ALL=C sort -zu "$WORK/epoch-indexes" > "$WORK/epoch-indexes.sorted" ||
        fail "could not canonicalize source index inventory"
    LC_ALL=C sort -zu "$WORK/epoch-repos" > "$WORK/epoch-repos.sorted" ||
        fail "could not canonicalize source repository inventory"
    mv -- "$WORK/source-dirs.sorted" "$WORK/source-dirs" ||
        fail "could not publish source directory inventory"
    mv -- "$WORK/selector-dirs.sorted" "$WORK/selector-dirs" ||
        fail "could not publish Git selector directory inventory"
    mv -- "$WORK/epoch-indexes.sorted" "$WORK/epoch-indexes" ||
        fail "could not publish source index inventory"
    mv -- "$WORK/epoch-repos.sorted" "$WORK/epoch-repos" ||
        fail "could not publish source repository inventory"
fi

emit_paths()
{
    local path
    while IFS= read -r -d '' path; do
        case "$path" in
            *$'\n'*|*$'\r'*) fail "control character in dirty path" ;;
        esac
        printf '%s\n' "$path"
    done < "$WORK/paths"
}

capture_portable()
{
    local path mode raw_mode digest target state
    {
        printf 'zcl.dev_source_identity.v2\0'
        while IFS= read -r -d '' path; do
            printf 'P\0%s\0' "$path"
            if [ "${GITLINK_STATE[$path]+known}" = known ]; then
                state="${GITLINK_STATE[$path]}"
                printf 'G\0%s\0' "$state"
            elif [ -L "$path" ]; then
                raw_mode="$(stat -c '%f' -- "$path" 2>/dev/null)" ||
                    fail "could not stat symlink: $path"
                canonical_source_mode L "$raw_mode" mode ||
                    fail "noncanonical symlink mode: $path"
                read_symlink_target "$path" target ||
                    fail "could not read symlink: $path"
                digest="$(printf '%s' "$target" | sha256_stream)" ||
                    fail "could not hash symlink: $path"
                printf 'L\0%s\0%s\0' "$mode" "$digest"
            elif [ -f "$path" ]; then
                raw_mode="$(stat -c '%f' -- "$path" 2>/dev/null)" ||
                    fail "could not stat source: $path"
                canonical_source_mode F "$raw_mode" mode ||
                    fail "noncanonical regular-file mode: $path"
                digest="$(sha256_file "$path")" ||
                    fail "could not hash source: $path"
                printf 'F\0%s\0%s\0' "$mode" "$digest"
            elif [ ! -e "$path" ]; then
                printf 'D\0'
            else
                fail "unsupported dirty source type: $path"
            fi
        done < "$WORK/source-paths"
    } > "$WORK/preimage"
    sha256_file "$WORK/preimage"
}

# GNU coreutils can hash every regular dirty file in one process and stat every
# extant path in one process.  The portable implementation above spawned both
# tools once per file; on a 200-file working overlay that consumed ~0.75 s per
# identity, and a verify cycle needs at least capture + compare.  Keep the
# canonical preimage byte-for-byte identical while removing that process storm.
capture_batched()
{
    local path target digest record emitted mode raw_mode
    local path_i=0 existing_i=0 regular_i=0 hash_i=0 batch_start=0
    local batch_size=128
    local -a paths=() types=() existing_paths=() existing_modes=()
    local -a regular_paths=() regular_digests=() batch=()

    while IFS= read -r -d '' path; do
        paths+=("$path")
        if [ "${GITLINK_STATE[$path]+known}" = known ]; then
            types+=(G)
        elif [ -L "$path" ]; then
            types+=(L)
            existing_paths+=("$path")
        elif [ -f "$path" ]; then
            types+=(F)
            existing_paths+=("$path")
            regular_paths+=("$path")
        elif [ ! -e "$path" ]; then
            types+=(D)
        else
            fail "unsupported dirty source type: $path"
        fi
    done < "$WORK/source-paths"

    if [ "${#existing_paths[@]}" -gt 0 ]; then
        : > "$WORK/modes"
        for ((batch_start = 0; batch_start < ${#existing_paths[@]};
              batch_start += batch_size)); do
            batch=("${existing_paths[@]:batch_start:batch_size}")
            stat -c '%f' -- "${batch[@]}" >> "$WORK/modes" 2>/dev/null ||
                fail "dirty source changed while collecting file modes"
        done
        mapfile -t existing_modes < "$WORK/modes"
        [ "${#existing_modes[@]}" -eq "${#existing_paths[@]}" ] ||
            fail "file-mode batch was incomplete"
    fi

    if [ "${#regular_paths[@]}" -gt 0 ]; then
        : > "$WORK/hashes"
        for ((batch_start = 0; batch_start < ${#regular_paths[@]};
              batch_start += batch_size)); do
            batch=("${regular_paths[@]:batch_start:batch_size}")
            sha256sum --zero -- "${batch[@]}" >> "$WORK/hashes" ||
                fail "dirty source changed while hashing regular files"
        done
        while IFS= read -r -d '' record; do
            [ "$hash_i" -lt "${#regular_paths[@]}" ] ||
                fail "regular-file hash batch returned extra rows"
            digest="${record:0:64}"
            emitted="${record:66}"
            [[ "$digest" =~ ^[0-9a-f]{64}$ ]] &&
                [ "${record:64:2}" = "  " ] &&
                [ "$emitted" = "${regular_paths[$hash_i]}" ] ||
                fail "regular-file hash batch was malformed or reordered"
            regular_digests+=("$digest")
            hash_i=$((hash_i + 1))
        done < "$WORK/hashes"
        [ "$hash_i" -eq "${#regular_paths[@]}" ] ||
            fail "regular-file hash batch was incomplete"
    fi

    {
        printf 'zcl.dev_source_identity.v2\0'
        for ((path_i = 0; path_i < ${#paths[@]}; path_i++)); do
            path="${paths[$path_i]}"
            printf 'P\0%s\0' "$path"
            case "${types[$path_i]}" in
                G)
                    printf 'G\0%s\0' "${GITLINK_STATE[$path]}"
                    ;;
                L)
                    raw_mode="${existing_modes[$existing_i]}"
                    existing_i=$((existing_i + 1))
                    canonical_source_mode L "$raw_mode" mode ||
                        fail "noncanonical symlink mode: $path"
                    read_symlink_target "$path" target ||
                        fail "could not read symlink: $path"
                    digest="$(printf '%s' "$target" | sha256_stream)" ||
                        fail "could not hash symlink: $path"
                    printf 'L\0%s\0%s\0' "$mode" "$digest"
                    ;;
                F)
                    raw_mode="${existing_modes[$existing_i]}"
                    existing_i=$((existing_i + 1))
                    canonical_source_mode F "$raw_mode" mode ||
                        fail "noncanonical regular-file mode: $path"
                    digest="${regular_digests[$regular_i]}"
                    regular_i=$((regular_i + 1))
                    printf 'F\0%s\0%s\0' "$mode" "$digest"
                    ;;
                D)
                    printf 'D\0'
                    ;;
                *)
                    fail "internal dirty-source classification failure: $path"
                    ;;
            esac
        done
    } > "$WORK/preimage"
    [ "$existing_i" -eq "${#existing_modes[@]}" ] &&
        [ "$regular_i" -eq "${#regular_digests[@]}" ] ||
        fail "dirty-source batch consumption was incomplete"
    sha256_file "$WORK/preimage"
}

capture()
{
    local help
    if [ "${ZCL_SOURCE_IDENTITY_FORCE_PORTABLE:-0}" != 1 ] &&
       command -v sha256sum >/dev/null 2>&1; then
        help="$(sha256sum --help 2>/dev/null || true)"
        if [[ "$help" == *"--zero"* ]]; then
            capture_batched
            return
        fi
    fi
    capture_portable
}

# Build-session mutation token. Unlike the portable content identity, this is
# deliberately host-local and short-lived: inode + nanosecond mtime/ctime make
# an edit/revert (ABA) visible between pre-build capture and post-link verify.
# It is never baked as a release/source identifier.
mutation_token()
{
    local path record path_i=0 existing_i=0 batch_start=0
    local batch_size=128
    local -a paths=() types=() existing_paths=() metadata=() batch=()
    while IFS= read -r -d '' path; do
        paths+=("$path")
        if [ "${GITLINK_STATE[$path]+known}" = known ]; then
            types+=(G)
        elif [ -L "$path" ] || [ -f "$path" ]; then
            types+=(E)
            existing_paths+=("$path")
        elif [ ! -e "$path" ]; then
            types+=(D)
        else
            fail "unsupported source type while capturing mutation token: $path"
        fi
    done < "$WORK/source-paths"

    : > "$WORK/mutation-metadata"
    for ((batch_start = 0; batch_start < ${#existing_paths[@]};
          batch_start += batch_size)); do
        batch=("${existing_paths[@]:batch_start:batch_size}")
        stat --printf='%d:%i:%s:%f:%y:%z\0' -- "${batch[@]}" \
            >> "$WORK/mutation-metadata" 2>/dev/null ||
            fail "source changed while collecting mutation metadata"
    done
    mapfile -d '' -t metadata < "$WORK/mutation-metadata"
    [ "${#metadata[@]}" -eq "${#existing_paths[@]}" ] ||
        fail "mutation metadata batch was incomplete"

    {
        printf 'zcl.dev_source_mutation.v1\0'
        for ((path_i = 0; path_i < ${#paths[@]}; path_i++)); do
            path="${paths[$path_i]}"
            printf 'P\0%s\0' "$path"
            case "${types[$path_i]}" in
                G) printf 'G\0%s\0' "${GITLINK_STATE[$path]}" ;;
                E)
                    record="${metadata[$existing_i]}"
                    existing_i=$((existing_i + 1))
                    printf 'E\0%s\0' "$record"
                    ;;
                D) printf 'D\0' ;;
                *) fail "internal mutation-token classification failure" ;;
            esac
        done
    } > "$WORK/mutation-preimage"
    [ "$existing_i" -eq "${#metadata[@]}" ] ||
        fail "mutation metadata consumption was incomplete"
    sha256_file "$WORK/mutation-preimage"
}

# Hash the enumerated source set and gitlink presence separately from
# file bytes. The normal mutation token deliberately operates on the captured
# path set; this guard lets capture-record detect a new untracked file, newly
# selected ignored archive, or submodule inventory change that appeared after
# that set was collected.
inventory_token()
{
    local path
    {
        printf 'zcl.dev_source_inventory.v1\0'
        while IFS= read -r -d '' path; do
            printf 'S\0%s\0' "$path"
            if [ "${GITLINK_STATE[$path]+known}" = known ]; then
                printf 'G\0%s\0' "${GITLINK_STATE[$path]}"
            fi
        done < "$WORK/source-paths"
    } > "$WORK/inventory-preimage"
    sha256_file "$WORK/inventory-preimage"
}

# Files created after an inventory walk has passed their directory are absent
# from that walk's path set. Bind the complete rescan to the metadata epoch of
# every recursive compiler directory, every current input ancestor, and the
# worktree index. This token is local to one verifier call: unlike the file
# mutation token it is not compared with the pre-operation record, so a test
# that creates and removes a fixture before verification does not self-refuse.
inventory_epoch_token()
{
    local batch_start=0 batch_size=128 path_i index_i
    local -a paths=() metadata=() indexes=() index_metadata=() batch=()
    mapfile -d '' -t paths < "$WORK/source-dirs"
    : > "$WORK/inventory-epoch-metadata"
    for ((batch_start = 0; batch_start < ${#paths[@]};
          batch_start += batch_size)); do
        batch=("${paths[@]:batch_start:batch_size}")
        stat --printf='%d:%i:%s:%f:%y:%z\0' -- "${batch[@]}" \
            >> "$WORK/inventory-epoch-metadata" 2>/dev/null ||
            fail "source directory changed during inventory verification"
    done
    mapfile -d '' -t metadata < "$WORK/inventory-epoch-metadata"
    [ "${#metadata[@]}" -eq "${#paths[@]}" ] ||
        fail "source directory metadata batch was incomplete"
    mapfile -d '' -t indexes < "$WORK/epoch-indexes"
    : > "$WORK/inventory-index-metadata"
    if [ "${#indexes[@]}" -gt 0 ]; then
        stat --printf='%d:%i:%s:%f:%y:%z\0' -- "${indexes[@]}" \
            > "$WORK/inventory-index-metadata" 2>/dev/null ||
            fail "Git index changed during inventory verification"
    fi
    mapfile -d '' -t index_metadata < "$WORK/inventory-index-metadata"
    [ "${#index_metadata[@]}" -eq "${#indexes[@]}" ] ||
        fail "Git index metadata batch was incomplete"
    {
        printf 'zcl.dev_source_inventory_epoch.v1\0'
        for ((index_i = 0; index_i < ${#indexes[@]}; index_i++)); do
            printf 'I\0%s\0%s\0' "${indexes[$index_i]}" \
                "${index_metadata[$index_i]}"
        done
        for ((path_i = 0; path_i < ${#paths[@]}; path_i++)); do
            printf 'D\0%s\0%s\0' "${paths[$path_i]}" \
                "${metadata[$path_i]}"
        done
    } > "$WORK/inventory-epoch-preimage"
    sha256_file "$WORK/inventory-epoch-preimage"
}

append_selector_file()
{
    local label="$1" path="$2" output="$3" digest
    printf 'F\0%s\0%s\0' "$label" "$path" >> "$output"
    if [ -f "$path" ]; then
        digest="$(sha256_file "$path")" ||
            fail "could not hash Git exclude selector: $path"
        printf 'P\0%s\0' "$digest" >> "$output"
    elif [ ! -e "$path" ] && [ ! -L "$path" ]; then
        printf 'M\0' >> "$output"
    else
        fail "unsupported Git exclude selector: $path"
    fi
}

# `--exclude-standard` is itself an inventory selector. Bind the effective Git
# configuration, every traversable directory's .gitignore, and every
# repo/gitlink's info/exclude and resolved global excludes file; changing
# policy can reveal pre-existing bytes without touching any worktree directory
# or index.
selector_policy_token()
{
    local directory repo physical info_exclude global_exclude config_digest
    local rc seq=0
    local -a configured=()
    : > "$WORK/selector-policy-preimage"
    printf 'zcl.dev_source_selector_policy.v1\0' \
        >> "$WORK/selector-policy-preimage"

    # An untracked .gitignore may ignore itself as well as another pre-existing
    # path, so it need not appear in source-paths. selector-dirs is the bounded
    # superset of directories Git can traverse for the superproject and
    # initialized gitlinks, plus compressed ignored-directory boundaries; bind
    # presence and bytes even for a self-hidden selector.
    while IFS= read -r -d '' directory; do
        append_selector_file directory-gitignore "$directory/.gitignore" \
            "$WORK/selector-policy-preimage"
    done < "$WORK/selector-dirs"

    while IFS= read -r -d '' repo; do
        physical="$(cd "$repo" && pwd -P)" ||
            fail "could not canonicalize selector repository: $repo"
        printf 'R\0%s\0' "$repo" >> "$WORK/selector-policy-preimage"
        git -C "$repo" config --null --list \
            > "$WORK/selector-config-$seq" ||
            fail "could not read effective Git configuration: $repo"
        config_digest="$(sha256_file "$WORK/selector-config-$seq")" ||
            fail "could not hash effective Git configuration: $repo"
        printf 'C\0%s\0' "$config_digest" \
            >> "$WORK/selector-policy-preimage"

        info_exclude="$(git -C "$repo" rev-parse --git-path info/exclude \
            2>/dev/null)" ||
            fail "could not resolve info/exclude: $repo"
        case "$info_exclude" in
            /*) ;;
            *) info_exclude="$physical/$info_exclude" ;;
        esac
        append_selector_file info-exclude "$info_exclude" \
            "$WORK/selector-policy-preimage"

        configured=()
        if git -C "$repo" config --path --null --get core.excludesFile \
                > "$WORK/selector-global-$seq" 2>/dev/null; then
            mapfile -d '' -t configured < "$WORK/selector-global-$seq"
            [ "${#configured[@]}" -eq 1 ] ||
                fail "core.excludesFile did not resolve exactly once: $repo"
            global_exclude="${configured[0]}"
        else
            rc=$?
            [ "$rc" -eq 1 ] ||
                fail "could not resolve core.excludesFile: $repo"
            if [ -n "${XDG_CONFIG_HOME:-}" ]; then
                global_exclude="$XDG_CONFIG_HOME/git/ignore"
            elif [ -n "${HOME:-}" ]; then
                global_exclude="$HOME/.config/git/ignore"
            else
                fail "HOME/XDG_CONFIG_HOME unavailable for global Git excludes"
            fi
        fi
        case "$global_exclude" in
            /*) ;;
            *) global_exclude="$physical/$global_exclude" ;;
        esac
        append_selector_file global-excludes "$global_exclude" \
            "$WORK/selector-policy-preimage"
        seq=$((seq + 1))
    done < "$WORK/epoch-repos"
    sha256_file "$WORK/selector-policy-preimage"
}

capture_record()
{
    local identity clean inventory_before inventory_after
    local mutation_before mutation_after
    inventory_before="$(inventory_token)" || exit $?
    mutation_before="$(mutation_token)" || exit $?
    identity="$(capture)" || exit $?
    mutation_after="$(mutation_token)" || exit $?
    [ "$mutation_before" = "$mutation_after" ] ||
        fail "source mutated during identity capture"
    inventory_after="$("$SELF" inventory-token)" || exit $?
    [ "$inventory_before" = "$inventory_after" ] ||
        fail "source inventory changed during identity capture"
    # The legacy-named `clean` slot is a v2 capture-completeness bit, not a Git
    # cleanliness claim. Exact current bytes already identify dirty worktrees;
    # deriving authority from Git HEAD/gitlink object ids would reintroduce the
    # legacy object-hash dependency this v2 record removes.
    clean=1
    printf '%s %s %s\n' "$identity" "$clean" "$mutation_after"
}

# Post-operation source CAS. A caller that already captured the complete byte
# identity before doing work only needs to prove that exact source epoch did
# not move while the work ran. The mutation token covers the canonical path set
# plus device/inode/size/mode and nanosecond mtime+ctime for every extant input;
# ctime makes edit/revert ABA visible even when bytes and mtime are restored.
# Re-scan inventory in a fresh process so a newly selected untracked/ignored
# input cannot hide behind the path set this invocation opened at startup.
verify_mutation()
{
    local expected="$1" inventory_before inventory_after
    local mutation_before mutation_after epoch_before epoch_after
    local policy_before policy_after
    inventory_before="$(inventory_token)" || exit $?
    mutation_before="$(mutation_token)" || exit $?
    epoch_before="$(inventory_epoch_token)" || exit $?
    policy_before="$(selector_policy_token)" || exit $?
    inventory_after="$(ZCL_SOURCE_IDENTITY_POST_RESCAN=1 \
        "$SELF" inventory-token)" || exit $?
    mutation_after="$(mutation_token)" || exit $?
    epoch_after="$(inventory_epoch_token)" || exit $?
    policy_after="$(selector_policy_token)" || exit $?
    [ "$inventory_before" = "$inventory_after" ] ||
        fail "source inventory changed during post-proof verification"
    [ "$mutation_before" = "$mutation_after" ] ||
        fail "source mutated during post-proof verification"
    [ "$epoch_before" = "$epoch_after" ] ||
        fail "source directory or index changed during post-proof verification"
    [ "$policy_before" = "$policy_after" ] ||
        fail "source exclude policy changed during post-proof verification"
    if [ "${mutation_after,,}" != "${expected,,}" ]; then
        fail "source epoch superseded: expected mutation=${expected,,} actual=${mutation_after,,}"
    fi
    printf '%s\n' "${mutation_after,,}"
}

# See ZCL_SOURCE_IDENTITY_SESSION above. Returns the cache file path for a
# token, or fails (caller falls back to an uncached capture) when the token is
# unset or does not match the exact `pid:start` shape this script mints --
# never trust an unrecognized shape as a cache key.
session_cache_path()
{
    local token="$1"
    [[ "$token" =~ ^[1-9][0-9]*:[0-9]+$ ]] || return 1
    printf '%s/build/identity/.session-cache/capture.%s.record' \
        "$ROOT" "${token/:/.}"
}

# A session's cache entry outlives the Make process that minted it (a new
# token every invocation), so entries for dead sessions would otherwise
# accumulate forever. Prune any entry whose encoded pid is no longer the
# exact live process that token identifies -- the same liveness test
# tools/dev/build-epoch-session.sh uses for its epoch leases.
prune_session_cache()
{
    local dir="$1" f base token pid start actual
    [ -d "$dir" ] || return 0
    for f in "$dir"/capture.*.record; do
        [ -e "$f" ] || continue
        base="$(basename -- "$f")"
        token="${base#capture.}"
        token="${token%.record}"
        pid="${token%%.*}"
        start="${token#*.}"
        actual=""
        if [[ "$pid" =~ ^[1-9][0-9]*$ ]] && [[ "$start" =~ ^[0-9]+$ ]]; then
            actual="$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)" || actual=""
        fi
        [ -n "$actual" ] && [ "$actual" = "$start" ] && continue
        rm -f -- "$f" 2>/dev/null || true
    done
}

# Read-through memoization wrapper around capture_record(). The FIRST call in
# a given ZCL_SOURCE_IDENTITY_SESSION pays the full walk and caches it; every
# later call in the SAME session (the same live Make process) reads the cache
# instead of re-walking. A new session (a new `make` invocation) always misses
# and re-derives from scratch, so this never weakens cross-invocation
# supersession detection -- it only removes repeat work within one process.
capture_record_cached()
{
    local cache tmp record
    cache="$(session_cache_path "$ZCL_SOURCE_IDENTITY_SESSION")" || {
        capture_record
        return
    }
    if [ -f "$cache" ]; then
        cat -- "$cache"
        return
    fi
    record="$(capture_record)" || return $?
    if mkdir -p "$(dirname -- "$cache")" 2>/dev/null; then
        prune_session_cache "$(dirname -- "$cache")"
        tmp="$(mktemp "$(dirname -- "$cache")/.tmp.XXXXXX" 2>/dev/null)" || tmp=""
        if [ -n "$tmp" ]; then
            printf '%s\n' "$record" > "$tmp" && mv -f -- "$tmp" "$cache" ||
                rm -f -- "$tmp"
        fi
    fi
    printf '%s\n' "$record"
}

case "$MODE" in
    paths)
        emit_paths
        ;;
    session-cache-drop)
        # A Makefile parse/restart boundary (the vendor/view bootstrap
        # includes) establishes or repairs build inputs AFTER this session's
        # first capture may already have cached a record that cannot see them.
        # Drop the pre-boundary record so the post-restart parse re-derives
        # the identity from the final input bytes. Best-effort by design: an
        # unset/malformed session token means there is no cache to drop, and
        # a failed removal still leaves every later verify-record fail-closed.
        if cache="$(session_cache_path "$ZCL_SOURCE_IDENTITY_SESSION")"; then
            rm -f -- "$cache" ||
                echo "source-identity: could not drop session cache: $cache" >&2
        fi
        exit 0
        ;;
    capture)
        capture
        ;;
    capture-record)
        capture_record_cached
        ;;
    inventory-token)
        inventory_token
        ;;
    verify)
        [[ "$EXPECTED" =~ ^[0-9a-fA-F]{64}$ ]] ||
            fail "verify requires a 64-hex expected identity"
        actual="$(capture)" || exit $?
        if [ "${actual,,}" != "${EXPECTED,,}" ]; then
            fail "source epoch superseded: expected=${EXPECTED,,} actual=${actual,,}"
        fi
        printf '%s\n' "${actual,,}"
        ;;
    verify-record)
        [[ "$EXPECTED" =~ ^[0-9a-fA-F]{64}$ ]] ||
            fail "verify-record requires a 64-hex expected identity"
        [ "$EXPECTED_CLEAN" = 1 ] ||
            fail "verify-record requires v2 capture-completeness bit 1"
        [[ "$EXPECTED_MUTATION" =~ ^[0-9a-fA-F]{64}$ ]] ||
            fail "verify-record requires a 64-hex mutation token"
        actual_record="$(capture_record_cached)" || exit $?
        read -r actual actual_clean actual_mutation <<< "$actual_record"
        if [ "${actual,,}" != "${EXPECTED,,}" ] ||
           [ "$actual_clean" != "$EXPECTED_CLEAN" ] ||
           [ "${actual_mutation,,}" != "${EXPECTED_MUTATION,,}" ]; then
            fail "source build superseded: expected=${EXPECTED,,}/clean=${EXPECTED_CLEAN}/mutation=${EXPECTED_MUTATION,,} actual=${actual,,}/clean=${actual_clean}/mutation=${actual_mutation,,}"
        fi
        printf '%s %s %s\n' "${actual,,}" "$actual_clean" \
            "${actual_mutation,,}"
        ;;
    verify-mutation)
        [[ "$EXPECTED" =~ ^[0-9a-fA-F]{64}$ ]] ||
            fail "verify-mutation requires a 64-hex mutation token"
        verify_mutation "$EXPECTED"
        ;;
    *)
        echo "usage: tools/dev/source-identity.sh paths|capture|capture-record|session-cache-drop|verify EXPECTED|verify-record EXPECTED CLEAN MUTATION|verify-mutation EXPECTED_MUTATION" >&2
        exit 2
        ;;
esac
