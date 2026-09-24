#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Replay one failure against frozen factory executables and isolated stores.
set -euo pipefail
if [[ $# != 3 ]]; then
    printf 'usage: %s QUALIFICATION_EVIDENCE MODE NEW_OUTPUT_DIR\n' "$0" >&2
    printf 'modes: wrong interface stale contradictory partial dependency worker publisher duplicate revoked resource\n' >&2
    exit 2
fi
root=$(cd "$(dirname "$0")/../.." && pwd -P)
evidence=$(realpath "$1")
mode=$2
output=$(realpath -m "$3")
[[ ! -e $output ]] || { printf 'output exists: %s\n' "$output" >&2; exit 2; }
mkdir -m 700 -p "$output"
bin="$evidence/bin"
package="$evidence/revision-2/pkg"
report="$output/report.json"

case $mode in
    wrong) package="$evidence/wrong-prefix-2/pkg" ;;
    interface)
        cp -a "$package" "$output/pkg"
        package="$output/pkg"
        for file in "$package/include/history.h" "$package/src/history.c" \
                    "$package/tests/test_history.c"; do
            sed 's/history_prefix/history_prefix_v2/g' "$file" > "$file.next"
            mv "$file.next" "$file"
            chmod 644 "$file"
        done
        cat > "$output/old-client.c" <<'EOF'
/* Copyright 2026 Rhett Creighton - MIT License */
#include "history.h"
int main(void)
{
    unsigned sum = 0;
    return history_prefix(2, &sum) && sum == 3 ? 0 : 1;
}
EOF
        ;;
    stale|contradictory|partial)
        cp "$evidence/revision-2/report.json" "$report"
        if [[ $mode != partial ]]; then
            ln -s "$evidence/revision-2/store-a" "$output/store-a"
            ln -s "$evidence/revision-2/store-b" "$output/store-b"
        fi
        if [[ $mode == contradictory ]]; then
            quick=$("$bin/jsonq" get stores.a.receipt_quick < "$report")
            sed "s/\"receipt_quick\":\"$quick\"/\"receipt_quick\":\"0000000000000000000000000000000000000000000000000000000000000000\"/" \
                "$report" > "$output/altered.json"
            report="$output/altered.json"
        fi
        if [[ $mode == stale ]]; then package="$evidence/revision-3/pkg"; fi
        set +e
        "$root/tools/dev/factory-evidence-audit.sh" "$report" "$package" "$bin" \
            > "$output/verdict.log" 2>&1
        rc=$?
        set -e
        cat "$output/verdict.log"
        [[ $rc != 0 ]] || exit 1
        printf 'counterexample=%s verdict=refused report_sha256=%s\n' \
            "$mode" "$(sha256sum "$report" | cut -d' ' -f1)"
        exit 0
        ;;
    dependency)
        cp -a "$package" "$output/pkg"
        package="$output/pkg"
        sed 's/"dependencies": \[\]/"dependencies": [{"root":"339c8bba0c9c92085bd36fd783035827d1c7ae48db50f71a18cc09c27dde4cc1","name":"zmap\/zmap","semver":"0.1.0"}]/' \
            "$package/zcode-package.json" > "$output/manifest.json"
        mv "$output/manifest.json" "$package/zcode-package.json"
        chmod 644 "$package/zcode-package.json"
        ;;
    worker|publisher)
        mkdir "$output/bin"
        for name in package-factory zclassic23 zclassic23-package-sign \
                    zclassic23-package-verify jsonq; do
            ln -s "$bin/$name" "$output/bin/$name"
        done
        bin="$output/bin"
        if [[ $mode == worker ]]; then
            rm "$bin/zclassic23-package-verify"
            printf '#!/bin/sh\nkill -KILL "$$"\n' \
                > "$bin/zclassic23-package-verify"
            chmod +x "$bin/zclassic23-package-verify"
        else
            rm "$bin/zclassic23"
            printf '#!/bin/sh\ncase "$*" in\n  *"zcode package publish commit"*) kill -KILL "$PPID"; exit 137;;\nesac\nexec "%s/zclassic23" "$@"\n' "$evidence/bin" \
                > "$bin/zclassic23"
            chmod +x "$bin/zclassic23"
        fi
        ;;
    revoked)
        cp "$evidence/publisher.key" "$output/revoked.key"
        chmod 000 "$output/revoked.key"
        ;;
    resource|duplicate) ;;
    *) printf 'unknown mode: %s\n' "$mode" >&2; exit 2 ;;
esac

key="$evidence/publisher.key"
if [[ $mode == revoked ]]; then key="$output/revoked.key"; fi
pubkey=$(cat "$evidence/publisher.pub")
run_factory()
{
    local destination=$1
    "$bin/package-factory" run --package "$package" \
        --publisher-key-file "$key" --publisher-pubkey "$pubkey" \
        --store-a "$output/store-a" --store-b "$output/store-b" \
        --report "$destination" --signer-seed-file "$output/admission.seed" \
        --bin-dir "$bin" --fast-cache "$output/cache"
}
set +e
if [[ $mode == resource ]]; then
    (ulimit -v 16384; run_factory "$report") > "$output/factory.log" 2>&1
else
    run_factory "$report" > "$output/factory.log" 2>&1
fi
rc=$?
set -e
if [[ $mode == duplicate ]]; then
    [[ $rc == 0 ]] || { cat "$output/factory.log"; exit 1; }
    run_factory "$output/duplicate.json" > "$output/duplicate.log" 2>&1
    first=$("$bin/jsonq" get package.package_root < "$report")
    second=$("$bin/jsonq" get package.package_root < "$output/duplicate.json")
    [[ $first == "$second" ]] || exit 1
    printf 'counterexample=duplicate first=ok second=ok root=%s\n' \
        "$first"
    exit 0
fi
if [[ $mode == interface ]]; then
    [[ $rc == 0 ]] || { cat "$output/factory.log"; exit 1; }
    set +e
    cc -std=c23 -Wall -Wextra -Werror -pedantic -I"$package/include" \
        "$output/old-client.c" "$package/src/history.c" \
        -o "$output/old-client" > "$output/old-client-build.log" 2>&1
    old_rc=$?
    set -e
    [[ $old_rc != 0 ]] || { printf 'old client still compiles\n' >&2; exit 1; }
    grep -q 'history_prefix' "$output/old-client-build.log"
    "$root/tools/dev/factory-evidence-audit.sh" "$report" "$package" "$bin" \
        > "$output/audit.log"
    printf 'counterexample=interface factory=ok old_client_compile_exit=%s root=%s\n' \
        "$old_rc" "$("$bin/jsonq" get package.package_root < "$report")"
    exit 0
fi
[[ $rc != 0 ]] || { printf 'unexpected factory success\n' >&2; exit 1; }
case $mode in
    wrong) grep -q 'test-fail (test exit 1)' "$output/factory.log" ;;
    dependency) grep -q 'DEPENDENCY_LOCK' "$output/factory.log" ;;
    worker) grep -Eq 'build worker exit 137|standard-profile rebuild exit -1' \
        "$output/factory.log" ;;
    publisher) [[ $rc == 137 && ! -e $report ]] ;;
    revoked) grep -q 'Permission denied' "$output/factory.log" ;;
    resource) grep -Eq 'cli stdout alloc|CLI output allocation' "$output/factory.log" ;;
esac
if [[ -f $report ]]; then
    printf 'counterexample=%s factory_exit=%s report_sha256=%s\n' \
        "$mode" "$rc" "$(sha256sum "$report" | cut -d' ' -f1)"
else
    printf 'counterexample=%s factory_exit=%s report=unavailable\n' \
        "$mode" "$rc"
fi
