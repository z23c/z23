#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# Focused owner handoff: canonical wire/source fixtures and land recovery rig.
# --with-integration adds the black-box transition, RED until attach lands.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
bin=${1:-build/bin/z23-dev}
mode=${2:-core}

devbuild --wait make -j"$(getconf _NPROCESSORS_ONLN)" \
    t-fast-exact ONLY=test_zcode_dev_objects
devbuild --wait make -j"$(getconf _NPROCESSORS_ONLN)" \
    t-fast-exact ONLY=test_dev_land
printf 'git-land-owner-fixtures: GREEN canonical objects and land recovery\n'
if test "$mode" = --with-integration; then
    devbuild --wait tools/dev/git_land_signed_intent_acceptance.sh "$bin"
elif test "$mode" != core; then
    printf 'usage: %s [z23-dev binary] [--with-integration]\n' "$0" >&2
    exit 2
fi
