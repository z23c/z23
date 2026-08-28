#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check-app-bundle-reproducible: the macOS .app bundler is reproducible AND
# its product actually launches.
#
# ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
# tools/scripts/make_app_bundle.sh wraps a built tool binary in the minimal
# launchable .app (Contents/{MacOS/<exe>,Info.plist,PkgInfo}) and ad-hoc signs
# it — arm64 macOS refuses to execute an unsigned binary at all, so "no
# signature" is not an option and "whatever codesign feels like" is not
# reproducible. Two things can silently rot there and neither is caught by
# reading the script:
#
#   1. The signature stops being deterministic. `codesign` stamps a
#      trusted-timestamp into the signature when the timestamp server is not
#      disabled, and any input-dependent field (identifier, plist value,
#      embedded hash) drifting between runs makes two bundles of identical
#      input differ. Nothing but building twice and hashing everything can
#      see that.
#   2. The bundle stops launching. A bundle whose signature does not verify
#      is killed by the kernel (SIGKILL, not a nonzero exit), so a smoke test
#      that only checks an exit status cannot tell "ran and said no" from
#      "never ran". The probe below asserts BOTH the exact printed output and
#      the exit status of the bundled executable.
#
# ── WHAT IS PROVEN (all fail-closed) ────────────────────────────────────────
#   A. The subject tool compiles twice into two temp dirs byte-identically
#      (else the proof below would be comparing different inputs and the gate
#      says so instead of passing).
#   B. `make_app_bundle.sh` run twice over those identical binaries, into two
#      different out-dirs, yields byte-identical trees: shasum -a 256 of
#      EVERY file, the embedded signature included (codesign embeds it in the
#      Mach-O and writes CodeResources), plus file modes and mtimes and the
#      directory shape. A single differing file fails the gate, named.
#   C. `codesign --verify --strict` accepts the bundle and `-dv` reports the
#      ad-hoc signature (flags=0x2(adhoc), Signature=adhoc).
#   D. The bundled executable LAUNCHES on this host: it is fed a JSON
#      document and must print the exact expected value and exit 0. Subject
#      is build/bin/jsonq's source (tools/jsonq.c + zjsonp + zutf8): a real
#      in-tree C23 tool with no vendor dependency, and one whose stdin/args
#      contract makes it print and exit deterministically —
#        printf '{"a":{"b":"hello-bundle"}}' | <bundled jsonq> get a.b
#      prints `hello-bundle` and exits 0. (sqlq — the other bundler subject —
#      needs the vendored sqlite lib and only has a usage exit of 1, so it is
#      the `make app-bundle` smoke subject, not this gate's launch probe.)
#
# ── SELFTEST ────────────────────────────────────────────────────────────────
#   --selftest proves the assertions are load-bearing before this gate is
#   allowed to report clean: a tampered PkgInfo must be caught and NAMED by
#   the manifest compare, a flipped byte in the signed Mach-O must be caught
#   by the signature verify, and a probe payload printing the WRONG value
#   must be rejected. A gate whose every negative is still a pass is
#   decoration.
#
# Mode: default | --selftest.
# Host: Darwin with codesign (the bundle format is macOS-only). Anywhere else
# the gate prints SKIP and exits 0 — the same host-bound shape
# check_standalone_tools_link.sh uses for its DARWIN_EXEMPT set, not a silent
# pass on a host that could have run it.
#
# Exit: 0 clean/skip, 1 on any violation, 2 on a malformed run.

set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"

GATE_NAME="check_app_bundle_reproducible"
BUNDLER="tools/scripts/make_app_bundle.sh"
SUBJECT_APP_NAME="jsonq"
PROBE_JSON='{"a":{"b":"hello-bundle"}}'
PROBE_EXPECT="hello-bundle"

TMP_ROOT=""
cleanup() {
    [ -n "$TMP_ROOT" ] && rm -rf "$TMP_ROOT"
    return 0
}
trap cleanup EXIT

die() {
    echo "$GATE_NAME: FATAL — $1" >&2
    exit 2
}

need_tool() {
    command -v "$1" >/dev/null 2>&1 || die "required tool '$1' not found on PATH"
}

# ── subject build ───────────────────────────────────────────────────────────
# The gate compiles its own subject rather than reaching into build/: a gate
# that depends on whatever a previous `make` left behind proves nothing on a
# cold tree and hides drift on a warm one. The flag set is the gate's own,
# fixed, and applied identically to both runs — this gate proves the BUNDLE
# step is a pure function of its input; the tool's own build contract is
# check-standalone-tools-link's job.
compile_subject() {
    local out="$1"
    cc -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
        -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE -fblocks \
        -Ipackages/zjsonp/include -Ipackages/zutf8/include \
        -o "$out" tools/jsonq.c packages/zjsonp/src/zjsonp.c \
        packages/zutf8/src/zutf8.c || die "subject compile failed"
    [ -x "$out" ] || die "subject compile produced no executable at $out"
}

# ── manifests ───────────────────────────────────────────────────────────────
# Content: every file under the tree, path-sorted, sha256 — the signature is
# inside those bytes. Metadata: mode + mtime, which the bundler pins.
manifest_content_of() {
    (cd "$1" && find . -type f | LC_ALL=C sort | xargs shasum -a 256 > "$2")
}
manifest_meta_of() {
    (cd "$1" && find . -type f -exec /usr/bin/stat -f '%m %Sp %N' {} + | LC_ALL=C sort > "$2")
}
tree_shape_of() {
    (cd "$1" && find . -type d | LC_ALL=C sort > "$2")
}

# Compare one manifest pair. On a difference, name the offending files (the
# trailing token of each changed manifest line) and return 1 — never a bare
# "differ".
compare_pair() {
    local label="$1" a="$2" b="$3" rc=1
    if diff -u "$a" "$b" > "$TMP_ROOT/diff.out" 2>&1; then
        return 0
    fi
    echo "$GATE_NAME: FAIL — $label differs between the two bundle runs." >&2
    echo "  Differing entries:" >&2
    awk '/^[+-][^+-]/ { print "    " $NF }' "$TMP_ROOT/diff.out" | sort -u >&2
    echo "  Full diff:" >&2
    sed 's/^/    /' "$TMP_ROOT/diff.out" >&2
    return "$rc"
}

# ── signature + launch assertions ───────────────────────────────────────────
verify_signature() {
    local bundle="$1" info
    codesign --verify --strict "$bundle" >/dev/null 2>&1 || {
        echo "$GATE_NAME: FAIL — codesign --verify --strict rejected $bundle" >&2
        return 1
    }
    info="$(codesign -dv "$bundle" 2>&1 || true)"
    case "$info" in
        *"Signature=adhoc"*) : ;;
        *)
            echo "$GATE_NAME: FAIL — $bundle is not ad-hoc signed:" >&2
            printf '%s\n' "$info" | sed 's/^/    /' >&2
            return 1
            ;;
    esac
}

PROBE_OUT=""
PROBE_RC=""
# Run the probe: the bundled executable must print exactly $PROBE_EXPECT on
# stdout and exit 0. Input comes from a file, never a pipe: a pipeline whose
# exit status is a decision is the trap sh_str.sh exists for (A3), and a
# kernel signature rejection shows up here as a signal, not an exit code.
probe_ok() {
    local exe="$1" json_file="$2"
    PROBE_OUT=""
    PROBE_RC=""
    if PROBE_OUT="$("$exe" get a.b < "$json_file")"; then
        PROBE_RC=0
    else
        PROBE_RC=$?
    fi
    if [ "$PROBE_RC" -ne 0 ]; then
        echo "$GATE_NAME: FAIL — bundled $SUBJECT_APP_NAME exited $PROBE_RC (wanted 0); a kernel signature rejection kills rather than exits" >&2
        return 1
    fi
    if [ "$PROBE_OUT" != "$PROBE_EXPECT" ]; then
        echo "$GATE_NAME: FAIL — bundled $SUBJECT_APP_NAME printed '$PROBE_OUT' (wanted '$PROBE_EXPECT')" >&2
        return 1
    fi
    return 0
}

# ── the proof ───────────────────────────────────────────────────────────────
# Two runs, end to end, into two temp dirs. Returns 0 iff identical.
prove_two_runs() {
    local run_a="$TMP_ROOT/a" run_b="$TMP_ROOT/b"
    mkdir -p "$run_a" "$run_b"

    compile_subject "$run_a/$SUBJECT_APP_NAME"
    compile_subject "$run_b/$SUBJECT_APP_NAME"

    # A: identical inputs, or the rest of the proof is void.
    if ! cmp -s "$run_a/$SUBJECT_APP_NAME" "$run_b/$SUBJECT_APP_NAME"; then
        echo "$GATE_NAME: FAIL — the subject compiler itself is not deterministic:" >&2
        echo "  two compiles of the same sources differ, so the two bundles below" >&2
        echo "  would not be comparable. Fix the compile flags before trusting the" >&2
        echo "  bundle proof." >&2
        return 1
    fi

    local bundle_a bundle_b
    bundle_a="$("$BUNDLER" "$run_a/$SUBJECT_APP_NAME" "$SUBJECT_APP_NAME" "$run_a/out")" ||
        die "bundler failed on run A"
    bundle_b="$("$BUNDLER" "$run_b/$SUBJECT_APP_NAME" "$SUBJECT_APP_NAME" "$run_b/out")" ||
        die "bundler failed on run B"
    [ "$bundle_a" != "$bundle_b" ] || die "the two runs wrote to the same bundle path — the proof is void"

    manifest_content_of "$bundle_a" "$TMP_ROOT/content.a"
    manifest_content_of "$bundle_b" "$TMP_ROOT/content.b"
    manifest_meta_of "$bundle_a" "$TMP_ROOT/meta.a" || true
    manifest_meta_of "$bundle_b" "$TMP_ROOT/meta.b" || true
    tree_shape_of "$bundle_a" "$TMP_ROOT/shape.a"
    tree_shape_of "$bundle_b" "$TMP_ROOT/shape.b"

    # Anti-hollow floor: executable + Info.plist + PkgInfo + CodeResources is
    # the minimum launchable signed bundle. Fewer lines than that means the
    # manifest is not describing a bundle and "identical" would be hollow.
    local lines
    lines="$(wc -l < "$TMP_ROOT/content.a" | tr -d ' ')"
    gate_require_scanned "$lines" 4 "$GATE_NAME" \
        "a signed .app bundle has at least MacOS/<exe>, Info.plist, PkgInfo and _CodeSignature/CodeResources"

    local fail=0
    compare_pair "file content (sha256, signature included)" "$TMP_ROOT/content.a" "$TMP_ROOT/content.b" || fail=1
    if [ -f "$TMP_ROOT/meta.a" ]; then
        compare_pair "file mode + mtime" "$TMP_ROOT/meta.a" "$TMP_ROOT/meta.b" || fail=1
    fi
    compare_pair "directory shape" "$TMP_ROOT/shape.a" "$TMP_ROOT/shape.b" || fail=1
    [ "$fail" -eq 0 ] || return 1

    verify_signature "$bundle_a" || return 1
    verify_signature "$bundle_b" || return 1

    PROBE_JSON_FILE="$TMP_ROOT/probe.json"
    printf '%s' "$PROBE_JSON" > "$PROBE_JSON_FILE"
    probe_ok "$bundle_a/Contents/MacOS/$SUBJECT_APP_NAME" "$PROBE_JSON_FILE" || return 1
    probe_ok "$bundle_b/Contents/MacOS/$SUBJECT_APP_NAME" "$PROBE_JSON_FILE" || return 1

    LAST_MANIFEST_SHA="$(shasum -a 256 "$TMP_ROOT/content.a" | awk '{print $1}')"
    LAST_MANIFEST_LINES="$lines"
    return 0
}

# ── selftest: prove every negative is catchable ─────────────────────────────
selftest() {
    local st="$TMP_ROOT/selftest"
    mkdir -p "$st"
    compile_subject "$st/$SUBJECT_APP_NAME"

    local bundle good bad
    bundle="$("$BUNDLER" "$st/$SUBJECT_APP_NAME" "$SUBJECT_APP_NAME" "$st")" ||
        die "bundler failed during selftest"
    good="$st/good"
    bad="$st/bad"
    cp -R "$bundle" "$good"
    cp -R "$bundle" "$bad"

    # 1. A tampered file must be caught and NAMED.
    printf 'APPL??XX' > "$bad/Contents/PkgInfo"
    manifest_content_of "$good" "$st/good.m"
    manifest_content_of "$bad" "$st/bad.m"
    local out1
    if out1="$(compare_pair "selftest" "$st/good.m" "$st/bad.m" 2>&1)"; then
        echo "$GATE_NAME: FAIL (selftest) — the manifest compare ACCEPTED a tampered PkgInfo" >&2
        return 1
    fi
    case "$out1" in
        *"PkgInfo"*) : ;;
        *)
            echo "$GATE_NAME: FAIL (selftest) — the manifest compare caught a difference but did not name the file:" >&2
            printf '%s\n' "$out1" | sed 's/^/    /' >&2
            return 1
            ;;
    esac

    # 2. A broken embedded signature must be caught by the verify step.
    local tampered="$st/tampered"
    cp -R "$bundle" "$tampered"
    printf 'X' | dd of="$tampered/Contents/MacOS/$SUBJECT_APP_NAME" bs=1 seek=4096 conv=notrunc status=none
    if verify_signature "$tampered" 2>/dev/null; then
        echo "$GATE_NAME: FAIL (selftest) — the signature check ACCEPTED a Mach-O with a flipped byte" >&2
        return 1
    fi

    # 3. A probe that prints the WRONG value must be rejected.
    printf '{"a":{"b":"not-the-expected-value"}}' > "$st/wrong.json"
    if probe_ok "$good/Contents/MacOS/$SUBJECT_APP_NAME" "$st/wrong.json" 2>/dev/null; then
        echo "$GATE_NAME: FAIL (selftest) — the launch probe ACCEPTED a wrong probe value" >&2
        return 1
    fi
    # ...and the right one must still pass, so the negative above proves the
    # probe is discriminating rather than broken.
    printf '%s' "$PROBE_JSON" > "$st/right.json"
    probe_ok "$good/Contents/MacOS/$SUBJECT_APP_NAME" "$st/right.json" ||
        {
            echo "$GATE_NAME: FAIL (selftest) — the launch probe now rejects a CORRECT probe value" >&2
            return 1
        }

    echo "$GATE_NAME: selftest OK — tampered file named, flipped-byte signature rejected, wrong probe value rejected"
}

# ── main ────────────────────────────────────────────────────────────────────
# Host guard FIRST: on a non-Darwin host there is no codesign to demand, and
# demanding it would exit 2 and take the whole umbrella red over an artifact
# that host can never produce.
if [ "$(uname -s)" != "Darwin" ] || ! command -v codesign >/dev/null 2>&1; then
    echo "$GATE_NAME: SKIP — .app bundles are a macOS artifact (need Darwin + codesign)"
    exit 0
fi

need_tool cc
need_tool plutil
need_tool shasum

[ -f "$BUNDLER" ] || die "bundler not found at $BUNDLER"
[ -f "tools/jsonq.c" ] || die "subject source tools/jsonq.c not found — the subject moved, update this gate"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/zcl-app-bundle-repro.XXXXXX")" ||
    die "could not create a temp dir"

if [ "${1:-}" = "--selftest" ]; then
    selftest
    exit 0
fi
[ "${1:-}" = "" ] || die "unknown argument '${1:-}' (expected --selftest or nothing)"

if prove_two_runs; then
    echo "$GATE_NAME: PASS — two independent bundle runs are byte-identical" \
         "($LAST_MANIFEST_LINES files, signature included, manifest sha256 $LAST_MANIFEST_SHA)" \
         "and the bundled $SUBJECT_APP_NAME launches (printed '$PROBE_EXPECT', exit 0)"
    exit 0
fi
exit 1
