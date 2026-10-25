#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: admit an existing-package patch only after a compiled red/green test.
# Usage: commons_fix_admit.sh PATCH PACKAGE | --selftest
# Baseline is the caller repository's HEAD, never its dirty/index contents.
# Compiler/tests use the existing confined package verifier, never a bare exec.
set -u
export LC_ALL=C
tool_root=$(cd "$(dirname "$0")/../.." && pwd -P) || exit 1
refuse() { printf 'REFUSE %s\n' "$1"; exit 1; }
# Bind trusted helper identity before Git can consult ambient routing/config.
# Do not print values: they may contain private paths or configuration.
for git_env in ${!GIT_@}; do
    case "$git_env" in
        GIT_PAGER|GIT_TERMINAL_PROMPT) continue ;;
    esac
    refuse inherited-git-selector
done
[[ "$(git -C "$tool_root" rev-parse --show-toplevel 2>/dev/null)" == "$tool_root" ]] ||
    refuse toolkit-root-mismatch
helper_inputs=(tools/jsonq.c tools/jsonq_standalone.c tools/multicall.h contexts/commons/packages/zjsonp/include
    contexts/commons/packages/zjsonp/src/zjsonp.c contexts/commons/packages/zutf8/include
    contexts/commons/packages/zutf8/src/zutf8.c)
archive_helper() { git -C "$tool_root" archive HEAD "${helper_inputs[@]}" > "$1" 2>/dev/null; }

selftest_helper() {
    local fixture=$1 subject=$2 toolkit=$1/toolkit
    mkdir -p "$toolkit/tools/scripts" "$toolkit/build/bin" || return 1
    archive_helper "$fixture/tool-helper.tar" || return 1
    tar -xf "$fixture/tool-helper.tar" -C "$toolkit" || return 1
    awk '/^tool_root=/ {print "tool_root=$(cd \"$(dirname \"$0\")/../..\" && pwd -P) || exit 1";next} {print}' \
        "$subject" > "$toolkit/tools/scripts/commons_fix_admit.sh" || return 1
    chmod +x "$toolkit/tools/scripts/commons_fix_admit.sh" || return 1
    cp "$tool_root/build/bin/z23-package-verify-dev" "$toolkit/build/bin/" || return 1
    git -C "$toolkit" init -q || return 1
    git -C "$toolkit" add tools/jsonq.c tools/jsonq_standalone.c tools/multicall.h contexts || return 1
    git -C "$toolkit" -c user.name=Fixture -c user.email=fixture@example.invalid \
        -c core.hooksPath=/dev/null -c commit.gpgsign=false commit -qm trusted-helper || return 1
    # This is a dirty proposal in the toolkit, not an accepted helper input.
    printf '#include <stdio.h>\n__attribute__((constructor)) static void dirty_helper(void) { FILE *f=fopen("%s/outside","w"); if(f) { fputs("corrupted",f); fclose(f); } }\n' \
        "$fixture" >> "$toolkit/contexts/commons/packages/zutf8/src/zutf8.c" || return 1
}

selftest_git_environment() {
    local fixture=$1 script=$2 patch=$3 test_root=$1/git-environment
    local toolkit alternate selector value rc output
    mkdir "$test_root" || return 1
    printf 'outside\n' > "$test_root/outside" || return 1
    selftest_helper "$test_root" "$script" || return 1
    toolkit=$test_root/toolkit
    alternate=$test_root/alternate
    mkdir "$alternate" || return 1
    tar -xf "$test_root/tool-helper.tar" -C "$alternate" || return 1
    git archive HEAD contexts/commons/packages > "$test_root/packages.tar" || return 1
    tar -xf "$test_root/packages.tar" -C "$alternate" || return 1
    # Committed replacement helper: executing its constructor escapes the
    # package child's grants because the parser itself is a trusted helper.
    printf '#include <stdio.h>\n__attribute__((constructor)) static void replaced_helper(void) { FILE *f=fopen("%s/outside","w"); if(f) { fputs("corrupted",f); fclose(f); } }\n' \
        "$test_root" >> "$alternate/contexts/commons/packages/zutf8/src/zutf8.c" || return 1
    git -C "$alternate" init -q || return 1
    git -C "$alternate" add tools/jsonq.c contexts || return 1
    git -C "$alternate" -c user.name=Fixture -c user.email=fixture@example.invalid \
        -c core.hooksPath=/dev/null -c commit.gpgsign=false commit -qm replacement-helper || return 1
    git diff > "$test_root/before" || return 1
    git ls-files --stage > "$test_root/index-before" || return 1
    if [[ ${COMMONS_FIX_ADMIT_SELFTEST_CASES:-} != git-replacement ]]; then
    for selector in GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE \
        GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG_COUNT \
        GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 GIT_CONFIG_PARAMETERS GIT_CONFIG \
        GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM \
        GIT_CEILING_DIRECTORIES GIT_DISCOVERY_ACROSS_FILESYSTEM \
        GIT_NAMESPACE GIT_TRACE GIT_FUTURE_SELECTOR; do
        case "$selector" in
            GIT_DIR|GIT_COMMON_DIR) value=$alternate/.git ;;
            GIT_WORK_TREE|GIT_CEILING_DIRECTORIES) value=$alternate ;;
            GIT_INDEX_FILE) value=$alternate/.git/index ;;
            GIT_OBJECT_DIRECTORY|GIT_ALTERNATE_OBJECT_DIRECTORIES) value=$alternate/.git/objects ;;
            GIT_CONFIG_COUNT) value=0 ;;
            GIT_CONFIG_KEY_0) value=core.worktree ;;
            GIT_CONFIG_VALUE_0) value=$alternate ;;
            GIT_CONFIG_PARAMETERS) value="'core.worktree'='$alternate'" ;;
            GIT_CONFIG|GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM) value=$alternate/.git/config ;;
            GIT_TRACE) value=$test_root/trace ;;
            *) value= ;;
        esac
        rc=0
        output=$(env "$selector=$value" "$toolkit/tools/scripts/commons_fix_admit.sh" "$patch" tiny) || rc=$?
        [[ $rc == 1 && "$output" == 'REFUSE inherited-git-selector' ]] || {
            printf 'selftest git-environment %s: expected selector refusal, got %s (exit %s)\n' "$selector" "$output" "$rc" >&2
            return 1
        }
        [[ ! -e "$test_root/trace" && "$(cat "$test_root/outside")" == outside ]] || return 1
        printf 'commons-fix-admit selftest git-environment %s: PASS\n' "$selector"
    done
    git -C "$toolkit" config core.worktree "$alternate" || return 1
    rc=0
    output=$("$toolkit/tools/scripts/commons_fix_admit.sh" "$patch" tiny) || rc=$?
    git --git-dir="$toolkit/.git" config --unset core.worktree || return 1
    [[ $rc == 1 && "$output" == 'REFUSE toolkit-root-mismatch' ]] || return 1
    [[ "$(cat "$test_root/outside")" == outside ]] || return 1
    printf 'commons-fix-admit selftest git-environment toolkit-root: PASS\n'
    fi
    # A usable alternate repository, with the toolkit pathname still matching
    # --show-toplevel. Without the environment guard, its helper executes.
    rc=0
    output=$(env GIT_DIR="$alternate/.git" GIT_WORK_TREE="$toolkit" \
        "$toolkit/tools/scripts/commons_fix_admit.sh" "$patch" tiny) || rc=$?
    if [[ $rc != 1 || "$output" != 'REFUSE inherited-git-selector' ||
          "$(cat "$test_root/outside")" != outside ]]; then
        printf 'selftest git-environment replacement-helper: got %s (exit %s), sentinel=%s\n' \
            "$output" "$rc" "$(cat "$test_root/outside")" >&2
        return 1
    fi
    git diff > "$test_root/after" || return 1
    git ls-files --stage > "$test_root/index-after" || return 1
    cmp -s "$test_root/before" "$test_root/after" || return 1
    cmp -s "$test_root/index-before" "$test_root/index-after" || return 1
    printf 'commons-fix-admit selftest git-environment replacement-helper: PASS\n'
}

selftest_native() {
    local fixture=$1 mode rc verifier=$tool_root/build/bin/z23-package-verify-dev
    mkdir "$fixture/native-source" "$fixture/native-build" || return 1
    printf 'source\n' > "$fixture/native-source/sentinel" || return 1
    printf 'evidence\n' > "$fixture/native-evidence" || return 1
    for mode in --fix-admit-compile --fix-admit-test; do
        "$verifier" "$mode" "$fixture/native-source" "$fixture/native-build" /bin/sh -c \
            'for p in "$@"; do if (printf corrupted > "$p") 2>/dev/null; then exit 42; fi; done; printf permitted > allowed' \
            control "$fixture/native-source/sentinel" "$fixture/native-evidence" || return 1
        [[ "$(cat "$fixture/native-source/sentinel")" == source &&
           "$(cat "$fixture/native-evidence")" == evidence &&
           "$(cat "$fixture/native-build/allowed")" == permitted ]] || return 1
        rc=0
        "$verifier" "$mode" "$fixture/native-source" "$fixture/native-build" /does-not-exist \
            > "$fixture/native-refusal" 2>&1 || rc=$?
        [[ $rc == 5 ]] || return 1
        rc=0
        "$verifier" "$mode" "$fixture/native-source" "$fixture/native-source" /bin/true \
            > "$fixture/native-refusal" 2>&1 || rc=$?
        [[ $rc == 5 ]] || return 1
        rc=0
        "$verifier" "$mode" "$fixture/native-source" / /bin/true \
            > "$fixture/native-refusal" 2>&1 || rc=$?
        [[ $rc == 5 ]] || return 1
        printf 'commons-fix-admit selftest %s immutable-grants/launch-refusal: PASS\n' "$mode"
    done
    # A regular-file RLIMIT_FSIZE death must not become an ordinary red exit.
    printf '#include <stdio.h>\nint main(void) { FILE *f=fopen("limit-file", "wb"); if(!f) return 0; char block[65536]={0}; for(int i=0;i<1025;i++) if(fwrite(block, 1, sizeof(block), f) != sizeof(block)) { fclose(f); return 0; } fclose(f); return 0; }\n' > "$fixture/native-source/file-limit.c" || return 1
    "$verifier" --fix-admit-compile "$fixture/native-source" "$fixture/native-build" "${CC:-gcc-14}" \
        -std=c23 -O1 -Wall -Wextra -Werror -pedantic "$fixture/native-source/file-limit.c" \
        -o "$fixture/native-build/file-limit" || return 1
    rc=0
    "$verifier" --fix-admit-test "$fixture/native-source" "$fixture/native-build" \
        "$fixture/native-build/file-limit" > "$fixture/native-refusal" 2>&1 || rc=$?
    [[ $rc == 5 ]] || { cat "$fixture/native-refusal" >&2; return 1; }
    printf 'commons-fix-admit selftest native-file-limit: PASS\n'
}

# The compile and run legs execute under the package verifier, whose qualified
# confinement (Landlock and seccomp) exists on Linux only. Elsewhere those
# cases are reported UNOBSERVED, never passed; Linux runs all of them.
selftest_needs_confinement() {
    [[ "$(uname -s)" != Linux ]] || return 1
    case "$1" in
        admit|assertion|assertion-signal|signal|file-limit|passes|compile-red|compile-green|fails|outside-write|evidence-write|outside-include|dirty-helper) return 0;;
    esac
    return 1
}

selftest() (
    local fixture script subject result rc patch case_name
    script=${COMMONS_FIX_ADMIT_SELFTEST_SUBJECT:-$(cd "$(dirname "$0")" && pwd)/$(basename "$0")}
    fixture=$(mktemp -d) || return 1
    trap 'rm -rf "$fixture"' EXIT
    mkdir -p "$fixture/contexts/commons/packages/tiny/"{src,include,tests}
    mkdir -p "$fixture/contexts/commons/packages/leaf/"{src,include}
    mkdir -p "$fixture/contexts/commons/packages/Upper/"{src,include}
    cd "$fixture" || return 1
    git init -q || return 1
    printf 'int helper(void); int value(void) { return helper(); }\n' > contexts/commons/packages/tiny/src/tiny.c
    printf 'int value(void); int main(void) { return value() != 0; }\n' > contexts/commons/packages/tiny/tests/test_tiny.c
    printf '{"name":"tiny/tiny","dependencies":[{"name":"leaf/leaf"}]}\n' > contexts/commons/packages/tiny/zcode-package.json
    printf 'int helper(void) { return 0; }\n' > contexts/commons/packages/leaf/src/leaf.c
    printf '{"name":"leaf/leaf","dependencies":[]}\n' > contexts/commons/packages/leaf/zcode-package.json
    printf 'int helper(void) { return 0; }\n' > contexts/commons/packages/Upper/src/upper.c
    printf '{"name":"Upper/Upper","dependencies":[]}\n' > contexts/commons/packages/Upper/zcode-package.json
    printf 'tracked README\n' > contexts/commons/packages/tiny/tests/README
    printf 'int external;\n' > "$fixture/external.h"
    printf 'outside\n' > outside
    printf 'baseline\n' > staged-sentinel
    printf 'baseline\n' > unstaged-sentinel
    git add . || return 1
    git -c user.name=Fixture -c user.email=fixture@example.invalid -c core.hooksPath=/dev/null commit -qm baseline || return 1
    for case_name in ${COMMONS_FIX_ADMIT_SELFTEST_CASES:-admit assertion assertion-signal signal file-limit outside adds deletes no-test passes compile-red compile-green fails traversal-dependency invalid-dependency mismatched-dependency nul-dependency unused-test outside-write evidence-write outside-include dirty-helper git-environment}; do
        if selftest_needs_confinement "$case_name"; then
            printf 'commons-fix-admit selftest %s: UNOBSERVED (qualified package confinement backend absent on this platform; the verifier path was not exercised)\n' "$case_name"
            continue
        fi
        subject=$script
        git reset -q || return 1
        git restore . || return 1
        rm -f contexts/commons/packages/tiny/src/new.c
        printf 'int value(void) { return 1; }\n' > contexts/commons/packages/tiny/src/tiny.c
        printf 'int value(void); int main(void) { return value() != 1; }\n' > contexts/commons/packages/tiny/tests/test_tiny.c
        case "$case_name" in
            git-environment|git-replacement)
                printf '/* repository selector control */\nint value(void); int main(void) { return value() != 1; }\n' > contexts/commons/packages/tiny/tests/test_tiny.c
                git diff > "$fixture/item.patch" || return 1
                selftest_git_environment "$fixture" "$script" "$fixture/item.patch" || return 1
                continue;;
            outside) printf 'changed\n' > outside; result='REFUSE touches-files-outside-package';;
            adds) printf 'int other;\n' > contexts/commons/packages/tiny/src/new.c; git add -N contexts/commons/packages/tiny/src/new.c || return 1; result='REFUSE adds-file';;
            deletes) rm contexts/commons/packages/tiny/src/tiny.c; result='REFUSE changes-file-type-or-name';;
            no-test) git restore contexts/commons/packages/tiny/tests; result='REFUSE no-test-change';;
            passes) printf 'int main(void) { return 0; }\n' > contexts/commons/packages/tiny/tests/test_tiny.c; result='REFUSE test-passes-without-fix';;
            compile-red) printf 'invalid C\n' > contexts/commons/packages/tiny/tests/test_tiny.c; result='REFUSE does-not-compile';;
            compile-green) printf 'invalid C\n' > contexts/commons/packages/tiny/src/tiny.c; result='REFUSE does-not-compile';;
            fails) printf 'int value(void) { return 2; }\n' > contexts/commons/packages/tiny/src/tiny.c; result='REFUSE test-fails-with-fix';;
            admit) result=ADMIT;;
            assertion) printf '#include <stdio.h>\nint value(void); int main(void) { if(value() != 1) { fputs("test assertion failed: value() == 1\\n", stderr); return 1; } return 0; }\n' > contexts/commons/packages/tiny/tests/test_tiny.c; result=ADMIT;;
            assertion-signal) printf '#include <assert.h>\nint value(void); int main(void) { assert(value() == 1); return 0; }\n' > contexts/commons/packages/tiny/tests/test_tiny.c; result='REFUSE test-did-not-complete';;
            signal) printf 'int value(void); int main(void) { if(value() == 1) return 0; volatile int numerator=42, denominator=value(); return numerator/denominator; }\n' > contexts/commons/packages/tiny/tests/test_tiny.c; result='REFUSE test-did-not-complete';;
            file-limit) printf '#include <stdio.h>\nint value(void); int main(void) { if(value() == 1) return 0; FILE *f=fopen("limit-file", "wb"); if(!f) return 0; char block[65536]={0}; for(int i=0;i<1025;i++) if(fwrite(block, 1, sizeof(block), f) != sizeof(block)) { fclose(f); return 0; } fclose(f); return 0; }\n' > contexts/commons/packages/tiny/tests/test_tiny.c; result='REFUSE test-did-not-complete';;
            traversal-dependency) printf '{"name":"tiny/tiny","dependencies":[{"name":"../outside"}]}\n' > contexts/commons/packages/tiny/zcode-package.json; result='REFUSE does-not-compile';;
            invalid-dependency) printf '{"name":"tiny/tiny","dependencies":[{"name":"Upper/Upper"}]}\n' > contexts/commons/packages/tiny/zcode-package.json; result='REFUSE does-not-compile';;
            mismatched-dependency) printf '{"name":"tiny/tiny","dependencies":[{"name":"leaf/other"}]}\n' > contexts/commons/packages/tiny/zcode-package.json; result='REFUSE does-not-compile';;
            nul-dependency) printf '%s\n' '{"name":"tiny/tiny","dependencies":[{"name":"leaf/\u0000leaf"}]}' > contexts/commons/packages/tiny/zcode-package.json; result='REFUSE does-not-compile';;
            unused-test)
                # Create a genuinely failing baseline without changing its compiled test.
                printf 'int value(void); int main(void) { return value() != 1; }\n' > contexts/commons/packages/tiny/tests/test_tiny.c
                git add contexts/commons/packages/tiny/tests/test_tiny.c || return 1
                git -c user.name=Fixture -c user.email=fixture@example.invalid -c core.hooksPath=/dev/null -c commit.gpgsign=false commit -qm failing-baseline || return 1
                printf 'changed README\n' > contexts/commons/packages/tiny/tests/README
                result='REFUSE no-test-change';;
            outside-write)
                printf '#include <stdio.h>\nint value(void); int main(void) { FILE *f=fopen("%s/outside", "w"); if(f) { fputs("corrupted",f); fclose(f); return 42; } return value()!=1; }\n' "$fixture" > contexts/commons/packages/tiny/tests/test_tiny.c
                result=ADMIT;;
            evidence-write)
                printf '#include <stdio.h>\nint value(void); int main(void) { const char *p[]={"../patch","../source.tar","../jsonq"}; for(int i=0;i<3;i++) { FILE *f=fopen(p[i],"w"); if(f) { fputs("corrupted",f); fclose(f); return 42; } } return value()!=1; }\n' > contexts/commons/packages/tiny/tests/test_tiny.c
                result=ADMIT;;
            outside-include)
                printf '#include "%s/external.h"\nint value(void); int main(void) { return value()!=1; }\n' "$fixture" > contexts/commons/packages/tiny/tests/test_tiny.c
                result='REFUSE does-not-compile';;
            dirty-helper)
                # Remain a compiled-test change after unused-test commits its baseline.
                printf '/* dirty-helper positive control */\nint value(void); int main(void) { return value() != 1; }\n' > contexts/commons/packages/tiny/tests/test_tiny.c
                selftest_helper "$fixture" "$script" || return 1
                subject=$fixture/toolkit/tools/scripts/commons_fix_admit.sh
                result=ADMIT;;
        esac
        patch="$fixture/item.patch"
        git diff > "$patch" || return 1
        git reset -q || return 1
        git restore outside || return 1
        printf 'staged\n' > staged-sentinel
        git add staged-sentinel || return 1
        printf 'unstaged\n' > unstaged-sentinel
        printf 'untracked\n' > untracked-sentinel
        # A dirty caller must remain byte-for-byte dirty, with its index intact.
        git diff > "$fixture/before"
        git ls-files --stage > "$fixture/index-before"
        rc=0
        output=$("$subject" "$patch" tiny) || rc=$?
        if [[ "$output" != "$result" ]] || [[ "$rc" != "$([[ "$result" == ADMIT ]] && printf 0 || printf 1)" ]]; then
            printf 'selftest %s: expected %s, got %s (exit %s)\n' "$case_name" "$result" "$output" "$rc" >&2
            printf 'selftest caller sentinel: %s\n' "$(cat outside)" >&2
            return 1
        fi
        git diff > "$fixture/after"
        git ls-files --stage > "$fixture/index-after"
        cmp -s "$fixture/before" "$fixture/after" && cmp -s "$fixture/index-before" "$fixture/index-after" || return 1
        [[ "$(cat outside)" == outside ]] || { printf 'selftest %s: caller sentinel mutated\n' "$case_name" >&2; return 1; }
        [[ "$(cat untracked-sentinel)" == untracked ]] || return 1
        printf 'commons-fix-admit selftest %s: PASS\n' "$case_name"
    done
    if [[ "$(uname -s)" == Linux ]]; then
        selftest_native "$fixture" || return 1
    else
        printf 'commons-fix-admit selftest native-file-limit: UNOBSERVED (qualified package confinement backend absent on this platform)\n'
    fi
    printf 'commons-fix-admit selftest: PASS\n'
)
if [[ "${1:-}" == --selftest && $# == 1 ]]; then selftest; exit $?; fi
[[ $# == 2 ]] || refuse usage
patch=$1
package=$2
[[ "$package" =~ ^[a-z][a-z0-9_]*$ ]] || refuse invalid-package
[[ -s "$patch" ]] || refuse missing-patch
[[ $(wc -c < "$patch") -le 8388608 ]] || refuse patch-too-large
root=$(git rev-parse --show-toplevel 2>/dev/null) || refuse no-repository
scratch=$(mktemp -d) || refuse temporary-copy-failed
trap 'rm -rf "$scratch"' EXIT
cp "$patch" "$scratch/patch" || refuse temporary-copy-failed
compiler=${CC:-gcc-14}
verifier=$tool_root/build/bin/z23-package-verify-dev
[[ -x "$verifier" ]] || refuse confinement-unavailable
if ! command -v "$compiler" >/dev/null 2>&1; then refuse compiler-unavailable; fi
# Pin the toolkit's accepted helper inputs; caller proposals remain inert even
# when the caller is the toolkit checkout and has dirty parser-library files.
mkdir "$scratch/helper" || refuse temporary-copy-failed
archive_helper "$scratch/helper.tar" || refuse helper-source-unavailable
tar -xf "$scratch/helper.tar" -C "$scratch/helper" || refuse helper-source-unavailable
"$compiler" -std=c23 -O1 -I"$scratch/helper/contexts/commons/packages/zjsonp/include" \
    -I"$scratch/helper/contexts/commons/packages/zutf8/include" \
    "$scratch/helper/tools/jsonq.c" "$scratch/helper/tools/jsonq_standalone.c" "$scratch/helper/contexts/commons/packages/zjsonp/src/zjsonp.c" \
    "$scratch/helper/contexts/commons/packages/zutf8/src/zutf8.c" \
    -o "$scratch/jsonq" > "$scratch/jsonq.build" 2>&1 || refuse helper-does-not-compile
patch=$scratch/patch
prefix=contexts/commons/packages/$package
# Ask Git to parse the patch; never infer paths from added hunk text.
git apply --numstat "$patch" > "$scratch/paths" 2> "$scratch/error" || refuse invalid-patch
[[ -s "$scratch/paths" ]] || refuse invalid-patch
while IFS=$'\t' read -r added removed path; do
    [[ "$path" == "$prefix/"* && "$path" != *'/../'* && "$path" != *'/./'* && "$path" != *'//'* ]] 2>/dev/null || refuse touches-files-outside-package
done < "$scratch/paths"
git apply --summary "$patch" > "$scratch/summary" 2> "$scratch/error" || refuse invalid-patch
if grep -q 'create mode' "$scratch/summary"; then refuse adds-file; fi
[[ ! -s "$scratch/summary" ]] || refuse changes-file-type-or-name
mkdir "$scratch/tree" || refuse temporary-copy-failed
git -C "$root" archive HEAD contexts/commons/packages > "$scratch/source.tar" 2> "$scratch/error" || refuse temporary-copy-failed
[[ $(wc -c < "$scratch/source.tar") -le 268435456 ]] || refuse source-too-large
tar -xf "$scratch/source.tar" -C "$scratch/tree" 2> "$scratch/error" || refuse temporary-copy-failed
cd "$scratch/tree" || refuse temporary-copy-failed
[[ -f "$prefix/tests/test_$package.c" && -f "$prefix/zcode-package.json" ]] || refuse invalid-package
# Refuse symlinks before applying or compiling anything in this private copy.
[[ -z "$(find contexts/commons/packages -type l -print)" ]] || refuse symlink
 git apply --check "$patch" 2> "$scratch/error" || refuse patch-does-not-apply
if ! awk -F '\t' -v p="$prefix/tests/test_$package.c" '$3==p {found=1} END {exit !found}' "$scratch/paths"; then refuse no-test-change; fi
build_test() {
    local name=$1 dep manifest token count i
    local -a includes=() sources=() pending=("$package") seen=()
    while ((${#pending[@]})); do
        dep=${pending[0]}; pending=("${pending[@]:1}")
        [[ " ${seen[*]} " != *" $dep "* ]] || continue
        seen+=("$dep")
        ((${#seen[@]} <= 128)) || return 1
        manifest=contexts/commons/packages/$dep/zcode-package.json
        [[ -f "$manifest" ]] || return 1
        includes+=("-Icontexts/commons/packages/$dep/include")
        for token in contexts/commons/packages/"$dep"/src/*.c; do
            [[ -f "$token" ]] && sources+=("$token")
        done
        count=$("$scratch/jsonq" count dependencies < "$manifest") || return 1
        [[ "$count" =~ ^[0-9]+$ && ${#count} -le 3 ]] || return 1
        for ((i=0; i<count; i++)); do
            token=$("$scratch/jsonq" raw "dependencies[$i].name" < "$manifest") || return 1
            [[ "$token" =~ ^\"[a-z][a-z0-9_]*/[a-z][a-z0-9_]*\"$ ]] || return 1
            token=${token:1:${#token}-2}
            [[ "${token%%/*}" == "${token#*/}" ]] || return 1
            pending+=("${token%%/*}")
        done
    done
    mkdir "$scratch/$name" || return 1
    local -a absolute_includes=() absolute_sources=()
    for token in "${includes[@]}"; do absolute_includes+=("-I$scratch/tree/${token#-I}"); done
    for token in "${sources[@]}"; do absolute_sources+=("$scratch/tree/$token"); done
    "$verifier" --fix-admit-compile "$scratch/tree" "$scratch/$name" "$compiler" \
        -std=c23 -O1 -Wall -Wextra -Werror -pedantic "${absolute_includes[@]}" "${absolute_sources[@]}" \
        "$scratch/tree/$prefix/tests/test_$package.c" -lm -o "$scratch/$name/test" > "$scratch/$name.build" 2>&1
}
git apply --include="$prefix/tests/*" "$patch" 2> "$scratch/error" || refuse patch-does-not-apply
build_test red || refuse does-not-compile
rc=0
"$verifier" --fix-admit-test "$scratch/tree" "$scratch/red" "$scratch/red/test" > "$scratch/red.run" 2>&1 || rc=$?
[[ $rc != 0 ]] || refuse test-passes-without-fix
[[ $rc == 10 ]] || refuse test-did-not-complete
# Re-extract the baseline so overlapping test hunks are applied exactly once.
rm -rf contexts
 tar -xf "$scratch/source.tar" 2> "$scratch/error" || refuse temporary-copy-failed
git apply "$patch" 2> "$scratch/error" || refuse patch-does-not-apply
build_test green || refuse does-not-compile
"$verifier" --fix-admit-test "$scratch/tree" "$scratch/green" "$scratch/green/test" > "$scratch/green.run" 2>&1 || refuse test-fails-with-fix
printf 'ADMIT\n'
