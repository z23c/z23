#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Measure bounded factory throughput for cumulative edits to the textstat package.
set -euo pipefail

if [[ $# != 2 || ! $2 =~ ^(1|2|4|8|16)$ ]]; then
    printf 'usage: %s NEW_OUTPUT_DIR CONCURRENCY(1|2|4|8|16)\n' "$0" >&2
    exit 2
fi
run_start_ns=$(date +%s%N)
root=$(cd "$(dirname "$0")/../.." && pwd -P)
output=$(realpath -m "$1")
concurrency=$2
[[ ! -e $output ]] || { printf 'output exists: %s\n' "$output" >&2; exit 2; }
mkdir -m 700 -p "$output/bin"
for binary in package-factory zclassic23 zclassic23-package-sign \
    zclassic23-package-verify jsonq; do
    cp "$root/build/bin/$binary" "$output/bin/$binary"
done
sha256sum "$output/bin/"* > "$output/executables.sha256"
cc -std=c23 -Wall -Wextra -Werror -pedantic \
    "$root/tools/dev/fixtures/factory_throughput/factory_rusage.c" \
    -o "$output/bin/factory-rusage"
sha256sum "$output/bin/factory-rusage" >> "$output/executables.sha256"
sha256sum "$0" "$root/tools/dev/fixtures/factory_throughput/factory_rusage.c" \
    > "$output/harness.sha256"
git -C "$root" rev-parse HEAD > "$output/checkout-commit"
git -C "$root" status --short > "$output/checkout-status"
date --iso-8601=seconds > "$output/local-time"
date -u --iso-8601=seconds > "$output/utc-time"
cc --version | head -1 > "$output/compiler"
awk -F: '/model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}' \
    /proc/cpuinfo > "$output/cpu-model"
"$output/bin/zclassic23-package-sign" --generate "$output/publisher.key" \
    > "$output/publisher.pub"
pubkey=$(cat "$output/publisher.pub")

# Each revision adds one user-visible statistic while retaining all earlier tests.
names=(digits tabs ascii_letters high_bytes carriage_returns spaces nuls newlines)
conditions=("c >= '0' && c <= '9'" "c == '\\t'" \
    "(c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')" \
    'c >= 128' "c == '\\r'" "c == ' '" "c == 0" "c == '\\n'")
expected=(1 1 1 1 1 1 1 1)

make_revision()
{
    local revision=$1 package=$2 i rewritten
    cp -a "$root/tools/dev/fixtures/commons_journey/textstat" "$package"
    cat > "$package/README.md" <<'EOF'
<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Textstat evolving qualification

This isolated source fork measures cumulative statistics over caller-owned
buffers. Each revision keeps the earlier package tests and adds a byte-count
operation with an exact result check.
EOF
    rewritten="$package/.zcode-package.new"
    sed '/"LICENSE",/a\    "README.md",' "$package/zcode-package.json" > "$rewritten"
    mv "$rewritten" "$package/zcode-package.json"
    for ((i=0; i<revision; i++)); do
        rewritten="$package/include/textstat/.textstat.new"
        sed "/#endif/i\\/* Count ${names[i]} in a caller-owned byte buffer. */\nsize_t textstat_${names[i]}(const char *text, size_t len);\n" \
            "$package/include/textstat/textstat.h" > "$rewritten"
        mv "$rewritten" "$package/include/textstat/textstat.h"
        cat >> "$package/src/textstat.c" <<EOF

size_t textstat_${names[i]}(const char *text, size_t len)
{
    if (!text) return 0;
    size_t count = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)text[i];
        if (${conditions[i]}) count++;
    }
    return count;
}
EOF
    done
    rewritten="$package/tests/.test_textstat.new"
    sed '/printf("textstat: OK/i\    static const char feature_sample[] = { '\''A'\'', '\''9'\'', '\''\\t'\'', (char)0x80, '\''\\r'\'', '\'' '\'', 0, '\''\\n'\'' };' \
        "$package/tests/test_textstat.c" > "$rewritten"
    mv "$rewritten" "$package/tests/test_textstat.c"
    for ((i=0; i<revision; i++)); do
        rewritten="$package/tests/.test_textstat.new"
        sed "/printf(\"textstat: OK/i\\    if (textstat_${names[i]}(feature_sample, sizeof(feature_sample)) != ${expected[i]}) return 1;" \
            "$package/tests/test_textstat.c" > "$rewritten"
        mv "$rewritten" "$package/tests/test_textstat.c"
    done
}

mkdir "$output/variants"
new_loc=(0)
for ((revision=1; revision<=8; revision++)); do
    make_revision "$revision" "$output/variants/revision-$revision"
    if ((revision == 1)); then
        prior="$root/tools/dev/fixtures/commons_journey/textstat"
    else
        prior="$output/variants/revision-$((revision - 1))"
    fi
    added=0
    for file in include/textstat/textstat.h src/textstat.c tests/test_textstat.c; do
        count=$(diff -U0 "$prior/$file" "$output/variants/revision-$revision/$file" | \
            awk '/^\+[^+]/ {n++} END {print n+0}') || true
        added=$((added + count))
    done
    new_loc[revision]=$added
done
sha256sum "$output"/variants/revision-*/src/textstat.c > "$output/variant-sources.sha256"
printf 'job\trevision\tduplicate\tdispatch_ns\tstart_ns\tend_ns\tcompile_ns\tpreview_ns\ttest_ns\tsource_sha256\tpackage_root\treport_sha256\tgenerated_loc\tbuildable_loc\tpreviewed_loc\ttested_loc\tdev_accepted_loc\tfully_accepted_loc\tfactory_ok\twall_s\tuser_s\tsystem_s\tmax_rss_kb\tfs_in\tfs_out\n' > "$output/ledger.tsv"

run_case()
{
    local job=$1 revision=$2 duplicate=$3 dispatch_ns=$4
    local case_dir="$output/job-$job" package="$output/job-$job/pkg"
    local start_ns end_ns source_sha package_root=unavailable report_sha=unavailable
    local generated_loc buildable_loc=0 previewed_loc=0 tested_loc=0
    local compile_start_ns compile_end_ns preview_start_ns preview_end_ns
    local test_start_ns test_end_ns compile_ns=0 preview_ns=0 test_ns=0
    local factory_ok=0 factory_exit=0 test_exit=0
    local factory_begin_ns=0 factory_end_ns=0
    start_ns=$(date +%s%N)
    mkdir -p "$case_dir"
    cp -a "$output/variants/revision-$revision" "$package"
    source_sha=$(sha256sum "$package/src/textstat.c" | cut -d' ' -f1)
    generated_loc=${new_loc[revision]}
    compile_start_ns=$(date +%s%N)
    if cc -std=c23 -Wall -Wextra -Werror -pedantic -I"$package/include" \
        "$package/src/textstat.c" "$package/tests/test_textstat.c" \
        -o "$case_dir/test-textstat" > "$case_dir/build.log" 2>&1; then
        buildable_loc=$generated_loc
    fi
    compile_end_ns=$(date +%s%N)
    compile_ns=$((compile_end_ns - compile_start_ns))
    if [[ $buildable_loc != 0 ]]; then
        cat > "$case_dir/preview.c" <<EOF
/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "textstat/textstat.h"
#include <stdio.h>
int main(void)
{
    const char sample[] = { 'A', '9', '\\t', (char)0x80, '\\r', ' ', 0, '\\n' };
    printf("%zu\\n", textstat_${names[revision-1]}(sample, sizeof(sample)));
    return 0;
}
EOF
        preview_start_ns=$(date +%s%N)
        if cc -std=c23 -Wall -Wextra -Werror -pedantic -I"$package/include" \
            "$package/src/textstat.c" "$case_dir/preview.c" \
            -o "$case_dir/preview" > "$case_dir/preview-build.log" 2>&1 && \
            "$case_dir/preview" > "$case_dir/preview.log" 2>&1 && \
            [[ $(cat "$case_dir/preview.log") == 1 ]]; then
            previewed_loc=$generated_loc
        fi
        preview_end_ns=$(date +%s%N)
        preview_ns=$((preview_end_ns - preview_start_ns))
        test_start_ns=$(date +%s%N)
        "$case_dir/test-textstat" > "$case_dir/test.log" 2>&1 || test_exit=$?
        if [[ $test_exit == 0 ]]; then tested_loc=$generated_loc; fi
        test_end_ns=$(date +%s%N)
        test_ns=$((test_end_ns - test_start_ns))
    fi
    if [[ $tested_loc != 0 ]]; then
        factory_begin_ns=$(date +%s%N)
        "$output/bin/factory-rusage" "$case_dir/factory.time" \
            "$output/bin/package-factory" run --package "$package" \
            --publisher-key-file "$output/publisher.key" --publisher-pubkey "$pubkey" \
            --store-a "$case_dir/store-a" --store-b "$case_dir/store-b" \
            --report "$case_dir/report.json" \
            --signer-seed-file "$output/admission.seed" --bin-dir "$output/bin" \
            --fast-cache "$output/cache" > "$case_dir/factory.log" 2>&1 || factory_exit=$?
        factory_end_ns=$(date +%s%N)
    fi
    if [[ -f $case_dir/report.json ]]; then
        report_sha=$(sha256sum "$case_dir/report.json" | cut -d' ' -f1)
        package_root=$("$output/bin/jsonq" get package.package_root < "$case_dir/report.json")
        if [[ $factory_exit == 0 && $("$output/bin/jsonq" get ok < "$case_dir/report.json") == true ]]; then
            factory_ok=1
        fi
    fi
    end_ns=$(date +%s%N)
    local wall=unavailable user=unavailable system=unavailable
    local rss=unavailable fs_in=unavailable fs_out=unavailable
    if [[ -f $case_dir/factory.time ]]; then
        wall=$(awk -v delta="$((factory_end_ns - factory_begin_ns))" \
            'BEGIN {printf "%.6f", delta / 1000000000}')
        read -r user system rss fs_in fs_out < "$case_dir/factory.time"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t0\t0\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$job" "$revision" "$duplicate" "$dispatch_ns" "$start_ns" "$end_ns" \
        "$compile_ns" "$preview_ns" "$test_ns" \
        "$source_sha" "$package_root" "$report_sha" "$generated_loc" \
        "$buildable_loc" "$previewed_loc" "$tested_loc" "$factory_ok" \
        "$wall" "$user" "$system" "$rss" "$fs_in" "$fs_out" \
        > "$case_dir/ledger.tsv"
}

batch_start_ns=$(date +%s%N)
for ((job=1; job<=concurrency; job++)); do
    revision=$(((job - 1) % 8 + 1))
    duplicate=$((job > 8 ? 1 : 0))
    dispatch_ns=$(date +%s%N)
    run_case "$job" "$revision" "$duplicate" "$dispatch_ns" &
done
wait
batch_end_ns=$(date +%s%N)
for ((job=1; job<=concurrency; job++)); do
    cat "$output/job-$job/ledger.tsv" >> "$output/ledger.tsv"
done
printf '%s\t%s\n' "$batch_start_ns" "$batch_end_ns" > "$output/batch-ns.tsv"
batch_s=$(awk -F '\t' 'NR == 1 {printf "%.6f", ($2-$1)/1000000000}' \
    "$output/batch-ns.tsv")
awk -F '\t' -v batch_s="$batch_s" '
    NR == 1 {next}
    {
        jobs++; good += $19; duplicates += $3;
        if ($3 == 0) {
            distinct++; generated += $13; buildable += $14;
            previewed += $15; tested += $16;
            dev += $17; full += $18;
        }
        cpu += $21 + $22;
        if ($23 > peak_rss) peak_rss = $23;
        fs_in += $24; fs_out += $25;
        dispatch_delay_ms += ($5 - $4) / 1000000;
        compile_ms += $7 / 1000000;
        preview_ms += $8 / 1000000;
        test_ms += $9 / 1000000;
        proof_s += $20;
    }
    END {
        print "batch_s\tjobs\tdistinct\tduplicates\tfactory_good\tgenerated_loc\tbuildable_loc\tpreviewed_loc\ttested_loc\tdev_accepted_loc\tfully_accepted_loc\tchanges_per_hour\tcpu_s\tpeak_job_rss_kb\tfs_in_blocks\tfs_out_blocks\tdispatch_delay_ms\tcompile_ms\tpreview_ms\ttest_ms\tproof_s";
        printf "%.6f\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%.3f\t%.3f\t%d\t%d\t%d\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\n",
            batch_s, jobs, distinct, duplicates, good, generated,
            buildable, previewed, tested, dev, full,
            distinct * 3600 / batch_s, cpu, peak_rss, fs_in, fs_out,
            dispatch_delay_ms, compile_ms, preview_ms, test_ms, proof_s;
    }' "$output/ledger.tsv" > "$output/summary.tsv"
printf 'job\tstep\tms\n' > "$output/step-times.tsv"
for ((job=1; job<=concurrency; job++)); do
    report="$output/job-$job/report.json"
    [[ -f $report ]] || continue
    step_count=$("$output/bin/jsonq" count steps < "$report")
    for ((step=0; step<step_count; step++)); do
        name=$("$output/bin/jsonq" get "steps[$step].name" < "$report")
        ms=$("$output/bin/jsonq" get "steps[$step].ms" < "$report")
        printf '%s\t%s\t%s\n' "$job" "$name" "$ms" \
            >> "$output/step-times.tsv"
    done
done
awk -F '\t' 'NR > 1 {sum[$2] += $3; count[$2]++}
    END {for (name in sum) printf "%s\t%d\t%.3f\n",
        name, sum[name], sum[name] / count[name]}' \
    "$output/step-times.tsv" | sort -k2,2nr > "$output/step-summary.tsv"
sha256sum -c "$output/executables.sha256" > "$output/executables-verified"
run_end_ns=$(date +%s%N)
printf '%s\t%s\n' "$run_start_ns" "$run_end_ns" > "$output/run-ns.tsv"
awk -F '\t' -v start="$run_start_ns" -v end="$run_end_ns" '
    NR == 2 {
        elapsed = (end - start) / 1000000000;
        printf "end_to_end_s\tend_to_end_distinct_changes_per_hour\n";
        printf "%.6f\t%.3f\n", elapsed, $3 * 3600 / elapsed;
    }' "$output/summary.tsv" > "$output/end-to-end.tsv"
cat "$output/ledger.tsv"
printf 'evidence=%s\n' "$output"
if ! awk -F '\t' 'NR > 1 && ($14 == 0 || $15 == 0 || $16 == 0 || $19 != 1) {
    failed = 1
} END { exit failed }' "$output/ledger.tsv"; then
    printf 'factory-throughput: one or more candidate stages failed\n' >&2
    exit 1
fi
