#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
# One-time root staging for the fixed result.c verifier. It starts no service.
# The profile is test_fast (tools/verify/fixed_result_fast.args) and the
# staged fixed_result.pins is a pins v2 file (z23verify.fixed_result.v2),
# written by `z23-fixed-result-launcher pins-encode`; the preflight below
# refuses a v1 text pins file or the retired strict profile by name.
set -euo pipefail

refuse() { printf 'fixed_result_install_refuse=%s\n' "$1" >&2; exit 2; }
(( $# == 1 )) && [[ $1 == install ]] || refuse request_shape
(( EUID == 0 )) || refuse root_required
[[ $(uname -s) == Linux ]] || refuse linux_required
stat --version >/dev/null 2>&1 || refuse gnu_stat_required
stage=/root/z23verify-staging
[[ -d $stage && ! -L $stage ]] || refuse stage_path_unsafe
[[ $(stat --format='%u:%a:%F' "$stage") == '0:700:directory' ]] ||
    refuse stage_owner_unsafe

safe_dir() {
    local path=$1
    [[ -d $path && ! -L $path &&
       $(stat --format='%u:%F' "$path") == '0:directory' ]] || return 1
    local mode
    mode=$(stat --format=%a "$path")
    [[ $mode == 700 || $mode == 755 || $mode == 750 ]]
}
for parent in / /root /etc /usr /usr/local /var /var/lib; do
    safe_dir "$parent" || refuse parent_unsafe
done
for parent in /etc/z23verify /usr/local/libexec /var/lib/z23verify \
              /var/lib/z23verify/launches; do
    [[ ! -L $parent ]] || refuse parent_unsafe
    [[ ! -e $parent ]] || safe_dir "$parent" || refuse parent_unsafe
done
hash() { openssl dgst -sha3-256 "$1" | awk '{print $NF}'; }
for name in fixed_result_launcher fixed_result_worker z23-tree-closure \
            fixed_result_fast.args fixed_result_launch_policy.v1 \
            fixed_result.seccomp.bpf fixed_result.pins; do
    [[ -f $stage/$name && ! -L $stage/$name ]] || refuse stage_file_missing
    [[ $(stat --format='%u:%h' "$stage/$name") == '0:1' ]] ||
        refuse stage_file_owner_unsafe
    mode=$(stat --format=%a "$stage/$name")
    [[ $mode == 444 || $mode == 555 ]] || refuse stage_file_mode_unsafe
done
[[ $(hash "$stage/fixed_result_fast.args") == \
   41d985cfdd672074e903b3ff05efec58f4cb4c8d0057a685207d69f007bac082 ]] ||
    refuse fast_profile_mismatch
[[ $(hash "$stage/fixed_result_launch_policy.v1") == \
   1315fa7fb2a718829a881955bf7415c3b4bdabc30d89ddeda0e0781983cc4abe ]] ||
    refuse policy_mismatch
[[ $(id -u z23verify) == 60092 && $(id -g z23verify) == 60092 &&
   $(id -u z23vcc) == 60093 && $(id -g z23vcc) == 60093 ]] ||
    refuse account_ids_mismatch
[[ -d /var/lib/z23verify/images/fixed_result/source &&
   -d /var/lib/z23verify/images/fixed_result/tool &&
   -d /var/lib/z23verify/images/fixed_result/check ]] ||
    refuse image_missing

for item in \
    "$stage/fixed_result_launcher:/usr/local/libexec/z23-fixed-result-launcher" \
    "$stage/fixed_result_worker:/usr/local/libexec/z23-fixed-result-worker" \
    "$stage/z23-tree-closure:/usr/local/libexec/z23-tree-closure" \
    "$stage/fixed_result_fast.args:/etc/z23verify/fixed_result_fast.args" \
    "$stage/fixed_result_launch_policy.v1:/etc/z23verify/fixed_result.policy" \
    "$stage/fixed_result.seccomp.bpf:/etc/z23verify/fixed_result.seccomp.bpf" \
    "$stage/fixed_result.pins:/etc/z23verify/fixed_result.pins"; do
    src=${item%%:*}
    dst=${item#*:}
    [[ ! -e $dst && ! -L $dst ]] || refuse installed_target_exists
done

ensure_dir() {
    local path=$1 mode=$2
    if [[ -e $path ]]; then
        safe_dir "$path" || refuse installed_dir_unsafe
        if [[ $path == /var/lib/z23verify/launches &&
              $(stat --format=%a "$path") != 700 ]]; then
            refuse launch_dir_mode_unsafe
        fi
    else
        install -d -o root -g root -m "$mode" "$path"
    fi
}
ensure_dir /etc/z23verify 0755
ensure_dir /usr/local/libexec 0755
ensure_dir /var/lib/z23verify 0755
ensure_dir /var/lib/z23verify/launches 0700
install -o root -g root -m 0555 "$stage/fixed_result_launcher" \
    /usr/local/libexec/z23-fixed-result-launcher
install -o root -g root -m 0555 "$stage/fixed_result_worker" \
    /usr/local/libexec/z23-fixed-result-worker
install -o root -g root -m 0555 "$stage/z23-tree-closure" \
    /usr/local/libexec/z23-tree-closure
install -o root -g root -m 0444 "$stage/fixed_result_fast.args" \
    /etc/z23verify/fixed_result_fast.args
install -o root -g root -m 0444 "$stage/fixed_result_launch_policy.v1" \
    /etc/z23verify/fixed_result.policy
install -o root -g root -m 0444 "$stage/fixed_result.seccomp.bpf" \
    /etc/z23verify/fixed_result.seccomp.bpf
install -o root -g root -m 0444 "$stage/fixed_result.pins" \
    /etc/z23verify/fixed_result.pins

set +e
/usr/local/libexec/z23-fixed-result-launcher preflight \
    > "$stage/preflight.out" 2> "$stage/preflight.err"
rc=$?
set -e
[[ $rc == 2 ]] || refuse preflight_exit_unexpected
grep -Fx 'pinned_material_ok=1 attest_eligible=0' "$stage/preflight.out" \
    >/dev/null || refuse pinned_material_unverified
grep -Fx 'fixed_result_launcher_refuse=isolation_unqualified' \
    "$stage/preflight.err" >/dev/null || refuse preflight_wrong_refusal
printf 'fixed_result_installed_material=1 service_started=0 '
printf 'signed_observation=0 attest_eligible=0\n'
