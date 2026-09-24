#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Measure distinct cumulative C23 candidates at bounded factory concurrency.
set -euo pipefail

if [[ ( $# != 3 && $# != 4 ) || ! $3 =~ ^(1|2|4|8|16|32)$ ]]; then
    printf 'usage: %s CORPUS_DIR NEW_OUTPUT_DIR WIDTH(1|2|4|8|16|32) [BIN_DIR]\n' "$0" >&2
    exit 2
fi
root=$(cd "$(dirname "$0")/../.." && pwd -P)
corpus=$(realpath "$1")
output=$(realpath -m "$2")
width=$3
bin_dir=$(realpath "${4:-$corpus/bin}")
[[ ! -e $output ]] || { printf 'output exists: %s\n' "$output" >&2; exit 2; }
for ((i=1; i<=32; i++)); do
    [[ -f $corpus/revision-$i/pkg/src/history.c ]] || exit 2
done
mkdir -m 700 -p "$output/bin"
for binary in package-factory zclassic23 zclassic23-package-sign \
    zclassic23-package-verify jsonq; do
    cp "$bin_dir/$binary" "$output/bin/$binary"
done
sha256sum "$output/bin/"* > "$output/executables.sha256"
sha256sum "$0" "$root/tools/dev/fixtures/factory_throughput/factory_rusage.c" \
    "$corpus/ledger.tsv" > "$output/inputs.sha256"
cc -std=c23 -Wall -Wextra -Werror -pedantic \
    "$root/tools/dev/fixtures/factory_throughput/factory_rusage.c" \
    -o "$output/bin/factory-rusage"
git -C "$root" rev-parse HEAD > "$output/checkout-commit"
date --iso-8601=seconds > "$output/local-time"
date -u --iso-8601=seconds > "$output/utc-time"
cc --version | head -1 > "$output/compiler"
awk -F: '/model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}' \
    /proc/cpuinfo > "$output/cpu-model"
"$output/bin/zclassic23-package-sign" --generate "$output/publisher.key" \
    > "$output/publisher.pub"
pubkey=$(cat "$output/publisher.pub")
printf 'revision\tdispatch_ns\tstart_ns\tend_ns\tsource_sha256\tpackage_root\treport_sha256\tbuildable\tpreviewed\ttested\tverified\tdev_accepted\tfully_accepted\tcompile_ns\tpreview_ns\ttest_ns\tproof_ns\tuser_s\tsystem_s\tpeak_rss_kb\tfs_in\tfs_out\n' \
    > "$output/ledger.tsv"

run_case()
{
    local revision=$1 dispatch_ns=$2
    local case_dir="$output/revision-$revision" package="$output/revision-$revision/pkg"
    local start_ns end_ns compile_start_ns compile_end_ns preview_start_ns
    local preview_end_ns test_start_ns test_end_ns proof_start_ns proof_end_ns
    local buildable=0 previewed=0 tested=0 verified=0
    local package_root=unavailable report_sha=unavailable factory_exit=0
    local user=0 system=0 rss=0 fs_in=0 fs_out=0
    start_ns=$(date +%s%N)
    mkdir -p "$case_dir"
    cp -a "$corpus/revision-$revision/pkg" "$package"
    local source_sha
    source_sha=$(sha256sum "$package/src/history.c" | cut -d' ' -f1)
    compile_start_ns=$(date +%s%N)
    if cc -std=c23 -Wall -Wextra -Werror -pedantic -I"$package/include" \
        "$package/src/history.c" "$package/src/tiny_lines.c" \
        "$package/tests/test_history.c" "$package/tests/test_tiny_lines.c" \
        -o "$case_dir/test-package" > "$case_dir/build.log" 2>&1; then
        buildable=1
    fi
    compile_end_ns=$(date +%s%N)
    preview_start_ns=$(date +%s%N)
    if ((buildable)) && "$case_dir/test-package" --help \
        > "$case_dir/preview.log" 2>&1; then
        previewed=1
    fi
    preview_end_ns=$(date +%s%N)
    test_start_ns=$(date +%s%N)
    if ((buildable)) && "$case_dir/test-package" > "$case_dir/test.log" 2>&1; then
        tested=1
    fi
    test_end_ns=$(date +%s%N)
    proof_start_ns=$(date +%s%N)
    if ((tested)); then
        "$output/bin/factory-rusage" "$case_dir/factory.time" \
            "$output/bin/package-factory" run --package "$package" \
            --publisher-key-file "$output/publisher.key" --publisher-pubkey "$pubkey" \
            --store-a "$case_dir/store-a" --store-b "$case_dir/store-b" \
            --report "$case_dir/report.json" --signer-seed-file "$output/admission.seed" \
            --bin-dir "$output/bin" --fast-cache "$output/cache" \
            > "$case_dir/factory.log" 2>&1 || factory_exit=$?
    fi
    proof_end_ns=$(date +%s%N)
    if [[ -f $case_dir/report.json ]]; then
        report_sha=$(sha256sum "$case_dir/report.json" | cut -d' ' -f1)
        package_root=$("$output/bin/jsonq" get package.package_root < "$case_dir/report.json")
        if ((factory_exit == 0)) && \
            [[ $("$output/bin/jsonq" get ok < "$case_dir/report.json") == true ]]; then
            verified=1
        fi
    fi
    if [[ -f $case_dir/factory.time ]]; then
        read -r user system rss fs_in fs_out < "$case_dir/factory.time"
    fi
    end_ns=$(date +%s%N)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t0\t0\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$revision" "$dispatch_ns" "$start_ns" "$end_ns" "$source_sha" \
        "$package_root" "$report_sha" "$buildable" "$previewed" "$tested" \
        "$verified" "$((compile_end_ns - compile_start_ns))" \
        "$((preview_end_ns - preview_start_ns))" "$((test_end_ns - test_start_ns))" \
        "$((proof_end_ns - proof_start_ns))" "$user" "$system" "$rss" \
        "$fs_in" "$fs_out" > "$case_dir/ledger.tsv"
}

batch_start_ns=$(date +%s%N)
for ((first=1; first<=32; first+=width)); do
    pids=()
    for ((revision=first; revision<first+width && revision<=32; revision++)); do
        run_case "$revision" "$batch_start_ns" &
        pids+=("$!")
    done
    for pid in "${pids[@]}"; do wait "$pid"; done
done
batch_end_ns=$(date +%s%N)
for ((revision=1; revision<=32; revision++)); do
    cat "$output/revision-$revision/ledger.tsv" >> "$output/ledger.tsv"
done
printf '%s\t%s\n' "$batch_start_ns" "$batch_end_ns" > "$output/batch-ns.tsv"
awk -F '\t' -v start="$batch_start_ns" -v end="$batch_end_ns" '
    NR == 1 {next}
    {
        jobs++; buildable += $8; previewed += $9; tested += $10; verified += $11;
        wait_ms += ($3-$2)/1000000; compile_ms += $14/1000000;
        preview_ms += $15/1000000; test_ms += $16/1000000;
        proof_ms += $17/1000000; cpu_s += $18+$19;
        if ($20 > peak_rss) peak_rss=$20;
        fs_in += $21; fs_out += $22;
        roots[$5]++;
    }
    END {
        for (root in roots) distinct++;
        wall_s=(end-start)/1000000000;
        print "wall_s\tjobs\tdistinct_sources\tbuildable\tpreviewed\ttested\tverified\tdev_accepted\tfully_accepted\tchanges_per_hour\tqueue_wait_ms\tcompile_ms\tpreview_ms\ttest_ms\tproof_ms\tcpu_s\tpeak_job_rss_kb\tfs_in\tfs_out";
        printf "%.6f\t%d\t%d\t%d\t%d\t%d\t%d\t0\t0\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%d\t%d\t%d\n",
            wall_s, jobs, distinct, buildable, previewed, tested, verified,
            verified*3600/wall_s, wait_ms, compile_ms, preview_ms, test_ms,
            proof_ms, cpu_s, peak_rss, fs_in, fs_out;
    }' "$output/ledger.tsv" > "$output/summary.tsv"
sha256sum -c "$output/executables.sha256" > "$output/executables-verified"
awk -F '\t' 'NR > 1 && ($8 != 1 || $9 != 1 || $10 != 1 || $11 != 1) {
    failed=1
} END {exit failed}' "$output/ledger.tsv"
cat "$output/summary.tsv"
