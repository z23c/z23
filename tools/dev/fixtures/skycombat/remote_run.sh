#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Exercise frozen SkyCombat source roots through a fully confined verifier.
set -euo pipefail
cd "$(dirname "$0")"
[[ $(sha256sum verifier | awk '{print $1}') == 72b1a6a4487a5b7cb10e53fe0286121855c6811e03e4bbfa2ced1d0902620672 ]]
[[ $(sha256sum recipe.libm | awk '{print $1}') == 29f58718561e2683eed540e2de5c79a6a5320cfabfd5f597d5d0cb69cfb94276 ]]
date -u --iso-8601=seconds > utc-time
cc --version | head -1 > compiler
awk -F: '/model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}' /proc/cpuinfo > cpu-model
run_case()
{
    local label=$1 source_root=$2 rc=0
    mkdir -p "$label-emit"
    { TIMEFORMAT='%R %U %S'; time ./verifier "$source_root" \
        "--zbuild-package-source=$PWD/$label-pkg" \
        "--zbuild-package-recipe=$PWD/recipe.libm" \
        --zbuild-package-name=qualification/skycombat-aircraft \
        --zbuild-package-profile=standard \
        --zbuild-package-max-cpu-seconds=60 \
        "--emit=$PWD/$label-emit" \
        --lock-root=f05b2ceba7db9f0ef54d9e6f59a32609b0def8411f0c73391c672b63bc76c398 \
        --require-full-isolation > "$label.stdout" 2> "$label.stderr"; } \
        2> "$label.time" || rc=$?
    printf '%s\n' "$rc" > "$label.exit"
}
run_case good 9a2c62d39213dd36a2e05ca064ac011d100ff429f92eecedd2f2682307495acc
[[ $(cat good.exit) == 0 ]]
grep -q 'result=test-pass outputs=4 isolation=full' good.stdout
run_case wrong 9abb3e1ee4a1daaa3b9a65eebeea728aba6dfe89ae76238a70cedbc52e66994d
[[ $(cat wrong.exit) == 6 ]]
grep -q 'zbuild-package-standard-refused=1' wrong.stdout
sha256sum good-emit/build-report > good-report.sha256
printf 'good=pass wrong=refused\n'
