#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Focused, private fixtures; no node, vendor build, display or system mutation.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-x11-selftest.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT
fixture="$tmp/repo"
mkdir -p "$fixture/tools/lint" "$fixture/tools/agent" "$fixture/vendor/x11" \
    "$fixture/platform/modules/platform/tests" "$fixture/build/bin" "$tmp/bin" "$tmp/lib"
cp -R "$ROOT/vendor/x11/include" "$fixture/vendor/x11/"
printf '#include <X11/Xlib.h>\n#ifndef PR72_PLATFORM\n#error missing platform flag\n#endif\nint main(void){return XOpenDisplay(0)==0;}\n' > "$tmp/good.c"
cp "$tmp/good.c" "$fixture/tools/native_ui_driver.c"
printf '#!/usr/bin/env bash\necho fixture-receipt-helper\n' > "$fixture/tools/agent/gate-receipt.sh"
chmod +x "$fixture/tools/agent/gate-receipt.sh"
# The outer suite tests the real X11 policy. Its normal-mode child gates use
# a trivial selftest command, avoiding recursive execution of this same suite.
printf '#!/usr/bin/env bash\necho fixture-x11-selftest\n' > "$fixture/tools/lint/selftest_standalone_tools_x11.sh"
chmod +x "$fixture/tools/lint/selftest_standalone_tools_x11.sh"
printf 'ZCL_WINDOWS_ACCEPTANCE_TESTS := headless_run\nZCL_WINDOWS_ACCEPTANCE_headless_run_SOURCES := tools/dev/windows_headless_run.c\n' > "$fixture/platform/modules/platform/tests/windows_acceptance.mk"
{
    printf 'CC = cc\nZCL_PLATFORM_CPPFLAGS = -DPR72_PLATFORM=1\nBIN_DIR = build/bin\nFUZZ_TARGETS = $(BIN_DIR)/fuzz_block $(BIN_DIR)/fuzz_script $(BIN_DIR)/fuzz_p2p $(BIN_DIR)/fuzz_http $(BIN_DIR)/fuzz_compactblock $(BIN_DIR)/fuzz_snapshot $(BIN_DIR)/fuzz_tx_bundle $(BIN_DIR)/fuzz_rom_manifest $(BIN_DIR)/fuzz_overlay $(BIN_DIR)/fuzz_ecdsa $(BIN_DIR)/fuzz_zcode_commons $(BIN_DIR)/fuzz_zcode_dht $(BIN_DIR)/fuzz_zcode_science $(BIN_DIR)/fuzz_mesh_status_proto $(BIN_DIR)/fuzz_semantic_manifest\nfuzz-ci: check-fuzz-ci-tools $(FUZZ_TARGETS)\n'
for name in fuzz_zcode_commons fuzz_zcode_dht fuzz_zcode_science fuzz_mesh_status_proto fuzz_semantic_manifest; do
    printf '$(BIN_DIR)/%s:\n\t@mkdir -p build/bin; touch $@\n' "$name"
done
    # Copy the actual canonical rule, so changing the recipe changes the test.
    awk '/^NATIVE_UI_DRIVER_BIN = / { active=1 } active { if (/^# Crash recovery/) exit; print }' "$ROOT/Makefile"
    for n in {1..20}; do
        printf '$(BIN_DIR)/fixture_%s:\n\t@mkdir -p build/bin; touch $@\n' "$n"
    done
    printf '$(BIN_DIR)/z23-headless-run.exe:\n\t@mkdir -p build/bin; touch $@\n'
} > "$fixture/Makefile"
cp "$fixture/Makefile" "$tmp/Makefile.good"
REAL_CC="$(command -v cc)"
export REAL_CC PR72_FIXTURE_LIB="$tmp/lib" PR72_CC_LOG="$tmp/compiler.log"
printf 'void *XOpenDisplay(const char *name){(void)name;return 0;}\n' > "$tmp/x11.c"
"$REAL_CC" -shared -fPIC "$tmp/x11.c" -o "$tmp/lib/libX11.so.6"
cat > "$tmp/bin/compiler" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$PR72_CC_LOG"
runtime=0; cover=0
for arg in "$@"; do
    [[ "$arg" != -Wl,-l:libX11.so.6 ]] || runtime=1
    [[ "$arg" != tools/native_ui_driver.c ]] || cover=1
done
output=""; next_output=0
for arg in "$@"; do
    if ((next_output)); then output="$arg"; next_output=0; fi
    [[ "$arg" != -o ]] || next_output=1
done
case "${PR72_FAULT:-}" in
    baseline-run)
        if ((!runtime && !cover)); then
            printf '#!/usr/bin/env bash\nexit 7\n' > "$output"
            chmod +x "$output"
            exit 0
        fi ;;
    partial-baseline)
        if ((!runtime && !cover)); then
            printf '#!/usr/bin/env bash\nexit 0\n' > "$output"
            chmod +x "$output"
            exit 7
        fi ;;
    partial-object)
        if ((cover)); then
            printf 'partial object output' > "$output"
            exit 7
        fi ;;
    compile) echo 'fixture compiler failure' >&2; exit 1 ;;
    wrong-target) "$REAL_CC" "$@" -D__linux__=0 -U__linux__; exit $? ;;
    generic-link) if ((runtime)); then echo 'ld: internal error' >&2; exit 1; fi ;;
    mixed-link) if ((runtime)); then echo 'ld: cannot find -l:libX11.so.6: No such file or directory' >&2; echo 'ld: internal error' >&2; exit 1; fi ;;
    object) if ((cover)); then exit 1; fi ;;
    empty-object) if ((cover)); then exit 0; fi ;;
esac
if ((runtime)) && [[ "${PR72_FAULT:-}" != present ]]; then
    args=()
    for arg in "$@"; do
        [[ "$arg" != -Wl,-l:libX11.so.6 ]] || arg=-Wl,-l:zcl_pr72_missing_fixture.so
        args+=("$arg")
    done
    set +e
    "$REAL_CC" "${args[@]}" 2>"$PR72_CC_LOG.link"
    rc=$?
    set -e
    sed 's/zcl_pr72_missing_fixture.so/libX11.so.6/g' "$PR72_CC_LOG.link" >&2
    exit "$rc"
fi
exec "$REAL_CC" "$@" -L"$PR72_FIXTURE_LIB"
EOF
chmod +x "$tmp/bin/compiler"
export PR72_FAULT=absent
cases=0
refute() {
    local rc=0
    "$@" || rc=$?
    if [[ "$rc" != 1 ]]; then
        echo "FAIL: negative match assertion returned $rc: $*" >&2
        exit 1
    fi
}
check() {
    local label="$1" expected="$2" rc=0
    shift 2
    (cd "$fixture"; "$@") >"$tmp/out" 2>"$tmp/err" || rc=$?
    if [[ "$rc" != "$expected" ]]; then
        cat "$tmp/out" "$tmp/err" >&2
        echo "FAIL $label: expected $expected, got $rc" >&2
        exit 1
    fi
    cases=$((cases + 1))
    echo "PASS $label"
}
gate=(env "MAKEFLAGS=CC=$tmp/bin/compiler" "ZCL_LINT_REPO_ROOT=$fixture" "$ROOT/build/bin/z23-lint" check-standalone-tools-link)
for mode in normal build-only list-targets; do
    args=(); [[ "$mode" == normal ]] || args+=("--$mode")
    export PR72_FAULT=absent
    check "absent/$mode" 0 "${gate[@]}" "${args[@]}"
    grep -q 'no-x11-runtime-exempt native_ui_driver' "$tmp/err"
    if [[ "$mode" == list-targets ]]; then refute grep -q '^build/bin/native_ui_driver$' "$tmp/out"; fi
    rm -f "$fixture/build/bin/native_ui_driver"
    export PR72_FAULT=present
    check "present/$mode, DISPLAY unset" 0 env -u DISPLAY "${gate[@]}" "${args[@]}"
    refute grep -q 'no-x11-runtime-exempt' "$tmp/err"
    if [[ "$mode" == list-targets ]]; then grep -q '^build/bin/native_ui_driver$' "$tmp/out"; else test -s "$fixture/build/bin/native_ui_driver"; fi
done
# The derived catalog skips the five CI fuzzers but keeps unrelated tools.
printf '$(BIN_DIR)/fuzz_unknown_fixture:\n\t@mkdir -p build/bin; touch $@\n' >> "$fixture/Makefile"
printf '#!/usr/bin/env bash\nprintf "%%s\n" "$PR72_HOST"\n' > "$tmp/bin/uname"
chmod +x "$tmp/bin/uname"
check 'CI fuzzers excluded on Linux' 0 env PR72_HOST=Linux "PATH=$tmp/bin:$PATH" PR72_FAULT=absent "${gate[@]}" --list-targets
for name in fuzz_zcode_commons fuzz_zcode_dht fuzz_zcode_science fuzz_mesh_status_proto fuzz_semantic_manifest; do
    refute grep -q "^build/bin/$name$" "$tmp/out"
done
grep -q '^build/bin/fuzz_unknown_fixture$' "$tmp/out"
grep -q '^build/bin/fixture_1$' "$tmp/out"
check 'unknown fuzzer refused on Darwin' 2 env PR72_HOST=Darwin "PATH=$tmp/bin:$PATH" PR72_FAULT=absent "${gate[@]}" --list-targets
sed 's@ \$(BIN_DIR)/fuzz_zcode_dht@@' "$tmp/Makefile.good" > "$fixture/Makefile"
check 'removed CI fuzzer is built on Linux' 0 env PR72_HOST=Linux "PATH=$tmp/bin:$PATH" PR72_FAULT=absent "${gate[@]}" --list-targets
grep -q '^build/bin/fuzz_zcode_dht$' "$tmp/out"
check 'removed CI fuzzer refused on Darwin' 2 env PR72_HOST=Darwin "PATH=$tmp/bin:$PATH" PR72_FAULT=absent "${gate[@]}" --list-targets
cp "$tmp/Makefile.good" "$fixture/Makefile"
printf 'FUZZ_TARGETS += $(BIN_DIR)/other\n' >> "$fixture/Makefile"
check 'ambiguous CI fuzzer assignment refuses' 2 env PR72_HOST=Linux "PATH=$tmp/bin:$PATH" PR72_FAULT=absent "${gate[@]}" --list-targets
sed 's@$(BIN_DIR)/fuzz_zcode_dht@invalid@' "$tmp/Makefile.good" > "$fixture/Makefile"
check 'invalid CI fuzzer token refuses' 2 env PR72_HOST=Linux "PATH=$tmp/bin:$PATH" PR72_FAULT=absent "${gate[@]}" --list-targets
sed 's/^fuzz-ci:.*/fuzz-ci:/' "$tmp/Makefile.good" > "$fixture/Makefile"
check 'missing fuzz-ci prerequisite refuses' 2 env PR72_HOST=Linux "PATH=$tmp/bin:$PATH" PR72_FAULT=absent "${gate[@]}" --list-targets
cp "$tmp/Makefile.good" "$fixture/Makefile"
rm "$tmp/bin/uname"

# Make's ignored errors must not admit a failed native run or a failed
# compiler that leaves a nonempty output. Exercise every public gate mode,
# both option spellings and both supported inherited flag variables.
for mode in normal build-only list-targets; do
    args=(); [[ "$mode" == normal ]] || args+=("--$mode")
    for fault in baseline-run partial-object partial-baseline; do
        for spelling in i --ignore-errors; do
            check "$mode/$fault/MAKEFLAGS=$spelling" 2 env "MAKEFLAGS=$spelling CC=$tmp/bin/compiler" "PR72_FAULT=$fault" "ZCL_LINT_REPO_ROOT=$fixture" "$ROOT/build/bin/z23-lint" check-standalone-tools-link "${args[@]}"
            check "$mode/$fault/GNUMAKEFLAGS=$spelling" 2 env "GNUMAKEFLAGS=$spelling" "PR72_FAULT=$fault" "${gate[@]}" "${args[@]}"
        done
    done
    for flag in n t q; do
        check "$mode/non-execution MAKEFLAGS=$flag" 2 env "MAKEFLAGS=$flag CC=$tmp/bin/compiler" PR72_FAULT=absent "ZCL_LINT_REPO_ROOT=$fixture" "$ROOT/build/bin/z23-lint" check-standalone-tools-link "${args[@]}"
    done
done
export PR72_FAULT=absent
check 'successful compiler override survives MAKEFLAGS ignore-errors' 0 env "MAKEFLAGS=i CC=$tmp/bin/compiler ZCL_PLATFORM_CPPFLAGS=-DPR72_PLATFORM=2" PR72_FAULT=absent "ZCL_LINT_REPO_ROOT=$fixture" "$ROOT/build/bin/z23-lint" check-standalone-tools-link --list-targets
check 'successful compiler override survives GNUMAKEFLAGS ignore-errors' 0 env GNUMAKEFLAGS=--ignore-errors "${gate[@]}" --list-targets
check 'default compiler' 0 env -u MAKEFLAGS "ZCL_LINT_REPO_ROOT=$fixture" "$ROOT/build/bin/z23-lint" check-standalone-tools-link --list-targets
check 'inherited probe variables cannot exempt present runtime' 0 env PR72_FAULT=present X11_PROBE_DONE=1 X11_RUNTIME_OK=0 "${gate[@]}" --list-targets
grep -q '^build/bin/native_ui_driver$' "$tmp/out"
check 'inherited probe variables cannot hide failure' 2 env PR72_FAULT=generic-link X11_PROBE_DONE=1 X11_RUNTIME_OK=0 "${gate[@]}" --list-targets
for fault in compile wrong-target generic-link mixed-link object empty-object; do
    check "$fault is fatal" 2 env "PR72_FAULT=$fault" "${gate[@]}" --list-targets
done
check 'missing compiler is fatal' 2 env "MAKEFLAGS=CC=$tmp/no-such-compiler" "ZCL_LINT_REPO_ROOT=$fixture" "$ROOT/build/bin/z23-lint" check-standalone-tools-link --list-targets
for defect in syntax warning pedantic; do
    cp "$tmp/good.c" "$fixture/tools/native_ui_driver.c"
    case "$defect" in
        syntax) printf 'this is not C;\n' >> "$fixture/tools/native_ui_driver.c" ;;
        warning) printf 'static int unused(void){return 0;}\n' >> "$fixture/tools/native_ui_driver.c" ;;
        pedantic) printf 'int extension(void){return ({1;});}\n' >> "$fixture/tools/native_ui_driver.c" ;;
    esac
    check "$defect remains fatal when X11 absent" 2 "${gate[@]}" --list-targets
done
cp "$tmp/good.c" "$fixture/tools/native_ui_driver.c"
mv "$fixture/vendor/x11/include/X11/Xlib.h" "$tmp/Xlib.h"
# Prevent the system Xlib.h from accidentally covering the missing vendor file.
printf '#include "../vendor/x11/include/X11/Xlib.h"\n' > "$fixture/tools/native_ui_driver.c"
check 'missing vendor header is fatal' 2 "${gate[@]}" --list-targets
mv "$tmp/Xlib.h" "$fixture/vendor/x11/include/X11/Xlib.h"
cp "$tmp/good.c" "$fixture/tools/native_ui_driver.c"
check 'platform flags selected by Make' 0 env "MAKEFLAGS=CC=$tmp/bin/compiler ZCL_PLATFORM_CPPFLAGS=-DPR72_PLATFORM=2" "PR72_FAULT=absent" "ZCL_LINT_REPO_ROOT=$fixture" "$ROOT/build/bin/z23-lint" check-standalone-tools-link --list-targets
grep -q -- '-std=c23 -O2 -Wall -Wextra -Werror -pedantic' "$PR72_CC_LOG"
grep -q -- '-DPR72_PLATFORM=2' "$PR72_CC_LOG"
grep -q -- '-c tools/native_ui_driver.c' "$PR72_CC_LOG"
# The gate makes its scratch directories with mkdtemp under TMPDIR; an
# unusable TMPDIR (missing, or not a directory) must be fatal, never a skip.
printf 'not a directory\n' > "$tmp/not-directory"
check 'temp creation failure is fatal' 2 env "TMPDIR=$tmp/no-such-dir" "${gate[@]}" --list-targets
check 'temp write failure is fatal' 2 env "TMPDIR=$tmp/not-directory" "${gate[@]}" --list-targets
printf '$(BIN_DIR)/unknown_fixture:\n\t@exit 1\n' >> "$fixture/Makefile"
for host in Darwin MSYS_NT-10.0; do
    printf '#!/usr/bin/env bash\nprintf "%%s\\n" "%s"\n' "$host" > "$tmp/bin/uname"
    chmod +x "$tmp/bin/uname"
    check "$host routing (no Linux exemption)" 0 env "PATH=$tmp/bin:$PATH" PR72_FAULT=compile "${gate[@]}" --list-targets
    refute grep -q 'no-x11-runtime-exempt' "$tmp/err"
    grep -q '^build/bin/unknown_fixture$' "$tmp/out"
done
rm "$tmp/bin/uname"
check 'unknown tool remains covered' 0 "${gate[@]}" --list-targets
grep -q '^build/bin/unknown_fixture$' "$tmp/out"
check 'unknown tool build fails' 1 "${gate[@]}" --build-only
cp "$tmp/Makefile.good" "$fixture/Makefile"
printf 'ZCL_WINDOWS_ACCEPTANCE_TESTS := unrelated\n' > "$fixture/platform/modules/platform/tests/windows_acceptance.mk"
check 'replacement coverage loss is fatal' 2 "${gate[@]}" --list-targets
printf 'CC = cc\n' > "$fixture/Makefile"
check 'tool floor is fatal' 2 "${gate[@]}" --list-targets
check 'unknown argument is fatal' 2 "${gate[@]}" --bogus
echo "standalone X11 selftest: $cases cases passed"
