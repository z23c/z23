/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_codeindex_scale: the cognition/modules/codeindex/ "cheap at scale" gate.
 *
 * Proves, on generated external-workspace trees (<root>/src/...):
 *   1. cold build of 50k tiny C23 files completes and seals its own
 *      build_cold_ms / build_cold_files receipt into the store meta;
 *   2. an incremental refresh after a one-file edit leaves that receipt
 *      untouched (it describes the cold build, not the refresh);
 *   3. warm agent questions against the open 50k index — an exact-path file
 *      lookup and a symbol find — each costs under 50 ms of CPU (query time only,
 *      never the open/freshness pass);
 *   4. a 500k-file cold build completes, and its CPU time stays within 30x
 *      of the 50k build (10x the files) — generous enough for host noise,
 *      tight enough to catch a quadratic blowup.
 *
 * All scratch work happens under ./test-tmp/ (project no-/tmp convention). */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "platform/time_compat.h"
#include "test/test_timing_budget.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)

#define SCALE_CHECK(name, expr) do {                                  \
    if (expr) { printf("  codeindex_scale: %s... OK\n", (name)); }    \
    else { printf("  codeindex_scale: %s... FAIL\n", (name));         \
           failures++; }                                              \
} while (0)

#define FIX_50K "test-tmp/ci_scale_50k"
#define FIX_500K "test-tmp/ci_scale_500k"
#define SCALE_50K_FILES 50000L
#define SCALE_500K_FILES 500000L
/* Two-level fanout: ~5000 files per m-dir, ~50 per s-dir. */
#define SCALE_FILES_PER_M 5000L
#define SCALE_FILES_PER_S 50L
static_assert(SCALE_FILES_PER_M % SCALE_FILES_PER_S == 0,
              "each m directory must contain complete s directories");
/* One progress line per this many generated files. */
#define SCALE_PROGRESS_FILES 25000L
/* Warm questions must stay interactive: 50 ms each, query time only. */
#define WARM_QUESTION_BUDGET_US UINT64_C(50000)
/* 10x the files may cost at most 30x the cold-build time. */
#define SCALE_LINEARITY_BOUND UINT64_C(30)

static uint64_t scale_monotonic_us(void)
{
    int64_t now = platform_time_monotonic_us();
    return now > 0 ? (uint64_t)now : 0;
}

/* Write content to <root>/<rel>, creating parent dirs (the mk_write pattern
 * from test_codeindex.c). */
static bool scale_write(const char *root, const char *rel,
                        const char *content, size_t content_len,
                        bool ensure_parents)
{
    char full[4096];
    int n = snprintf(full, sizeof(full), "%s/%s", root, rel);
    if (n <= 0 || (size_t)n >= sizeof(full)) return false;
    if (ensure_parents) {
        for (char *p = full + 1; *p; p++) {
            if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
        }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    bool ok = fwrite(content, 1, content_len, f) == content_len;
    if (fclose(f) != 0) ok = false;
    return ok;
}

/* Write `files` tiny C23 sources under <root>/src/mNNN/sNN/fNNNNN.c, each
 * defining one unique symbol. Streams one file at a time; nothing is
 * buffered beyond one path and one content line. */
static bool scale_generate(const char *root, long files)
{
    char rel[128];
    char content[96];
    for (long i = 0; i < files; i++) {
        int rn = snprintf(rel, sizeof(rel), "src/m%03ld/s%02ld/f%05ld.c",
                          i / SCALE_FILES_PER_M,
                          (i % SCALE_FILES_PER_M) / SCALE_FILES_PER_S, i);
        int cn = snprintf(content, sizeof(content),
                          "int scale_sym_%05ld(void) { return %ld; }\n", i, i);
        if (rn <= 0 || (size_t)rn >= sizeof(rel) ||
            cn <= 0 || (size_t)cn >= sizeof(content))
            return false;
        /* All files in this subgroup share parents created by its first file. */
        if (!scale_write(root, rel, content, (size_t)cn,
                         i % SCALE_FILES_PER_S == 0))
            return false;
        /* The runner's watchdog kills a group that prints nothing for 300 s.
         * Creating 500k files on a contended disk can be silent that long
         * while still making steady progress, so say so as it goes. */
        if ((i + 1) % SCALE_PROGRESS_FILES == 0) {
            printf("  codeindex_scale: generated %ld/%ld files\n", i + 1,
                   files);
            fflush(stdout);
        }
    }
    return true;
}

static int scale_check_incremental_edit(struct codeindex **index,
                                         long long receipt50_ms)
{
    int failures = 0;
    uint8_t source_root_before[32], source_root_after[32];
    bool root_before = codeindex_source_root_sha3(*index, source_root_before);
    static const char edit[] = "int scale_edit_00000(void) { return 1; }\n";
    SCALE_CHECK("edit one indexed file",
                scale_write(FIX_50K, "src/m000/s00/f00000.c",
                            edit, sizeof(edit) - 1, true));
    codeindex_close(*index);
    *index = codeindex_open(FIX_50K);
    long long receipt_after_ms = 0, receipt_after_files = 0;
    bool receipt_after = *index &&
        codeindex_build_cold_ms(*index, &receipt_after_ms, &receipt_after_files);
    bool root_after = *index &&
        codeindex_source_root_sha3(*index, source_root_after);
    SCALE_CHECK("incremental refresh keeps the cold-build receipt",
                receipt_after && receipt_after_ms == receipt50_ms &&
                receipt_after_files == SCALE_50K_FILES);
    SCALE_CHECK("incremental edit advances the exact source root",
                root_before && root_after &&
                memcmp(source_root_before, source_root_after, 32) != 0);
    struct ci_symbol edited_syms[4];
    int edited_count = *index ? codeindex_symbols_in_file(
        *index, "src/m000/s00/f00000.c", edited_syms, 4) : -1;
    SCALE_CHECK("incremental edit replaces the indexed symbol",
                edited_count == 1 &&
                strcmp(edited_syms[0].name, "scale_edit_00000") == 0);
    return failures;
}

/* What one measured cold-build pass leaves behind: the store it opened
 * (NULL when the open failed), the receipt that store sealed, and the CPU
 * and wall timings the linearity gate compares. */
struct scale_cold_result {
    struct codeindex *index;
    long long receipt_ms;
    uint64_t cpu_us;
    uint64_t wall_us;
};

/* The two warm questions asked of the reopened 50k index, with the CPU each
 * query consumed, for the budget checks that follow them. */
struct scale_warm_answer {
    bool file_ok;
    int nfound;
    uint64_t file_cpu_us;
    uint64_t find_cpu_us;
    struct ci_symbol syms[8];
};

/* One cold-build pass: wipe <root>, generate the fixture, open the store
 * cold under both clocks, then check the exact file count and the sealed
 * self-receipt. The label strings carry each pass's size wording so the
 * 50k and 500k passes share one shape instead of two clones. Returns the
 * pass's failure count; the measurements land in *out. */
static int scale_cold_build_pass(const char *root, long files,
                                 const char *generate_label,
                                 const char *count_label,
                                 const char *receipt_label,
                                 struct scale_cold_result *out)
{
    int failures = 0;
    (void)test_rm_rf_recursive(root);
    printf("  codeindex_scale: generating %ld-file tree...\n", files);
    SCALE_CHECK(generate_label, scale_generate(root, files));

    uint64_t cold_start_us = scale_monotonic_us();
    uint64_t cold_cpu_start_us = test_process_cpu_us();
    out->index = codeindex_open(root);
    uint64_t cold_cpu_us = test_process_cpu_us() - cold_cpu_start_us;
    uint64_t cold_us = scale_monotonic_us() - cold_start_us;
    long long receipt_ms = 0, receipt_files = 0;
    bool receipt = out->index &&
        codeindex_build_cold_ms(out->index, &receipt_ms, &receipt_files);
    printf("SCALE_BUILD files=%ld ms=%llu receipt_ms=%lld\n",
           files, (unsigned long long)(cold_us / 1000), receipt_ms);
    SCALE_CHECK(count_label,
                out->index && codeindex_file_count(out->index) == (int)files);
    SCALE_CHECK(receipt_label,
                receipt && receipt_ms > 0 &&
                receipt_files == files);
    out->receipt_ms = receipt_ms;
    out->cpu_us = cold_cpu_us;
    out->wall_us = cold_us;
    return failures;
}

/* Reopen the 50k index warm, ask it the two budgeted questions and print
 * the query-cost line. Returns the reopen check's failure count; the
 * answers and their query CPU costs land in *answer. */
static int scale_warm_reopen_and_query(struct codeindex **index,
                                       struct scale_warm_answer *answer)
{
    int failures = 0;
    if (*index) { codeindex_close(*index); *index = NULL; }
    *index = codeindex_open(FIX_50K);
    SCALE_CHECK("warm reopen of the 50k index", *index != NULL);
    struct ci_file file_rec;
    bool file_found = false;
    /* Query CPU on the calling thread: the budget bounds what an indexed
     * lookup costs (no scan), so a descheduled caller must not fail it. */
    uint64_t q_file_start_us = scale_monotonic_us();
    uint64_t q_file_cpu_start_us = test_thread_cpu_us();
    bool q_file_ok = *index &&
        codeindex_file(*index, "src/m000/s00/f00042.c", &file_rec,
                       &file_found) &&
        file_found;
    uint64_t q_file_cpu_us = test_thread_cpu_us() - q_file_cpu_start_us;
    uint64_t q_file_us = scale_monotonic_us() - q_file_start_us;
    uint64_t q_find_start_us = scale_monotonic_us();
    uint64_t q_find_cpu_start_us = test_thread_cpu_us();
    answer->nfound = *index ? codeindex_find(*index, "scale_sym_49999",
                                             answer->syms, 8) : -1;
    uint64_t q_find_cpu_us = test_thread_cpu_us() - q_find_cpu_start_us;
    uint64_t q_find_us = scale_monotonic_us() - q_find_start_us;
    printf("  codeindex_scale: warm file-lookup cpu_us=%llu symbol-find cpu_us=%llu budget_us=%llu (wall_us=%llu/%llu)\n",
           (unsigned long long)q_file_cpu_us,
           (unsigned long long)q_find_cpu_us,
           (unsigned long long)WARM_QUESTION_BUDGET_US,
           (unsigned long long)q_file_us, (unsigned long long)q_find_us);
    answer->file_ok = q_file_ok;
    answer->file_cpu_us = q_file_cpu_us;
    answer->find_cpu_us = q_find_cpu_us;
    return failures;
}

/* Check both warm questions against the 50 ms CPU budget. */
static int scale_check_warm_query_budgets(const struct scale_warm_answer *answer)
{
    int failures = 0;
    SCALE_CHECK("warm exact-path lookup costs under 50 ms of CPU",
                answer->file_ok &&
                answer->file_cpu_us <= WARM_QUESTION_BUDGET_US);
    SCALE_CHECK("warm symbol find costs under 50 ms of CPU",
                answer->nfound >= 1 &&
                strcmp(answer->syms[0].name, "scale_sym_49999") == 0 &&
                answer->find_cpu_us <= WARM_QUESTION_BUDGET_US);
    return failures;
}

/* The linearity gate and the run's verdict line; the verdict must see every
 * failure so far, hence failures_so_far. Returns this check's own failure
 * count. */
static int scale_check_linearity_and_verdict(
    const struct scale_cold_result *build50,
    const struct scale_cold_result *build500, int failures_so_far)
{
    int failures = 0;
    /* The bound is about the work a cold build does, so it compares the
     * process CPU (user+system, all threads) each build consumed. The two
     * builds run minutes apart on a shared host; wall time would grade
     * whatever load each happened to meet. */
    double ratio = build50->cpu_us > 0 ? (double)build500->cpu_us /
                                        (double)build50->cpu_us : 0.0;
    bool linear = build50->cpu_us > 0 && build500->cpu_us > 0 &&
                  build500->cpu_us <= build50->cpu_us * SCALE_LINEARITY_BOUND;
    printf("SCALE_LINEARITY ratio=%.1fx bound=%llux cpu50_us=%llu "
           "cpu500_us=%llu wall50_us=%llu wall500_us=%llu\n", ratio,
           (unsigned long long)SCALE_LINEARITY_BOUND,
           (unsigned long long)build50->cpu_us,
           (unsigned long long)build500->cpu_us,
           (unsigned long long)build50->wall_us,
           (unsigned long long)build500->wall_us);
    SCALE_CHECK("500k cold build stays within 30x of the 50k build", linear);
    printf("SCALE_VERDICT=%s\n",
           linear && failures_so_far + failures == 0 ? "PASS" : "FAIL");
    return failures;
}

static int test_codeindex_scale_platform_arm(void)
{
    int failures = 0;
    struct scale_cold_result build50 = {0};
    struct scale_cold_result build500 = {0};
    struct scale_warm_answer warm = {0};

    /* ── 1: 50k-file cold build + the store's self-receipt ── */
    failures += scale_cold_build_pass(
        FIX_50K, SCALE_50K_FILES,
        "generate the 50k-file tree",
        "cold build of 50k files opens with an exact count",
        "the store seals its cold-build self-receipt", &build50);
    if (!build50.index) {
        (void)test_rm_rf_recursive(FIX_50K);
        return failures + 1;
    }

    /* ── 2: an incremental refresh leaves the cold-build receipt ── */
    failures += scale_check_incremental_edit(&build50.index,
                                             build50.receipt_ms);

    /* ── 3: warm questions, query time only ── */
    failures += scale_warm_reopen_and_query(&build50.index, &warm);
    failures += scale_check_warm_query_budgets(&warm);
    if (build50.index) { codeindex_close(build50.index); build50.index = NULL; }

    /* ── 4: 500k-file cold build ── */
    failures += scale_cold_build_pass(
        FIX_500K, SCALE_500K_FILES,
        "generate the 500k-file tree",
        "cold build of 500k files opens with an exact count",
        "the 500k store seals its cold-build self-receipt", &build500);
    if (build500.index) {
        codeindex_close(build500.index);
        build500.index = NULL;
    }

    /* ── 5: linearity — 10x the files within 30x the time ── */
    failures += scale_check_linearity_and_verdict(&build50, &build500,
                                                  failures);

    (void)test_rm_rf_recursive(FIX_50K);
    (void)test_rm_rf_recursive(FIX_500K);
    return failures;
}
#else  /* _WIN32 */
/* The scale fixture generates and walks 550k tiny files; that cost model is a
 * POSIX-local-filesystem measurement, and the neighboring codeindex group
 * already skips this host. Skipped loudly rather than faked. */
static int test_codeindex_scale_platform_arm(void)
{
    printf("codeindex_scale: SKIP (Windows): 550k-file scale fixture is a POSIX-local-filesystem measurement\n");
    return 0;
}
#endif

int test_codeindex_scale(void)
{
    return test_codeindex_scale_platform_arm();
}
