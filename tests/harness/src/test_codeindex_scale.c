/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_codeindex_scale — the cognition/modules/codeindex/ "cheap at scale"
 * gate (milestone M2).
 *
 * Proves, on generated external-workspace trees (<root>/src/...):
 *   1. cold build of 50k tiny C23 files completes and seals its own
 *      build_cold_ms / build_cold_files receipt into the store meta;
 *   2. an incremental refresh after a one-file edit leaves that receipt
 *      untouched (it describes the cold build, not the refresh);
 *   3. warm agent questions against the open 50k index — an exact-path file
 *      lookup and a symbol find — each answer within 50 ms (query time only,
 *      never the open/freshness pass);
 *   4. a 500k-file cold build completes, and its wall time stays within 30x
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
                        const char *content, size_t content_len)
{
    char full[4096];
    int n = snprintf(full, sizeof(full), "%s/%s", root, rel);
    if (n <= 0 || (size_t)n >= sizeof(full)) return false;
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
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
        if (!scale_write(root, rel, content, (size_t)cn))
            return false;
    }
    return true;
}

static int test_codeindex_scale_platform_arm(void)
{
    int failures = 0;

    /* ── 1: 50k-file cold build + the store's self-receipt ── */
    (void)test_rm_rf_recursive(FIX_50K);
    printf("  codeindex_scale: generating %ld-file tree...\n",
           SCALE_50K_FILES);
    SCALE_CHECK("generate the 50k-file tree",
                scale_generate(FIX_50K, SCALE_50K_FILES));

    uint64_t cold50_start_us = scale_monotonic_us();
    struct codeindex *ci = codeindex_open(FIX_50K);
    uint64_t cold50_us = scale_monotonic_us() - cold50_start_us;
    long long receipt50_ms = 0, receipt50_files = 0;
    bool receipt50 = ci &&
        codeindex_build_cold_ms(ci, &receipt50_ms, &receipt50_files);
    printf("SCALE_BUILD files=%ld ms=%llu receipt_ms=%lld\n",
           SCALE_50K_FILES, (unsigned long long)(cold50_us / 1000),
           receipt50_ms);
    SCALE_CHECK("cold build of 50k files opens with an exact count",
                ci && codeindex_file_count(ci) == (int)SCALE_50K_FILES);
    SCALE_CHECK("the store seals its cold-build self-receipt",
                receipt50 && receipt50_ms > 0 &&
                receipt50_files == SCALE_50K_FILES);
    if (!ci) {
        (void)test_rm_rf_recursive(FIX_50K);
        return failures + 1;
    }

    /* ── 2: an incremental refresh leaves the cold-build receipt ── */
    static const char edit[] = "int scale_sym_00000(void) { return 1; }\n";
    SCALE_CHECK("edit one indexed file",
                scale_write(FIX_50K, "src/m000/s00/f00000.c",
                            edit, sizeof(edit) - 1));
    codeindex_close(ci);
    ci = codeindex_open(FIX_50K);
    long long receipt_after_ms = 0, receipt_after_files = 0;
    bool receipt_after = ci &&
        codeindex_build_cold_ms(ci, &receipt_after_ms, &receipt_after_files);
    SCALE_CHECK("incremental refresh keeps the cold-build receipt",
                receipt_after && receipt_after_ms == receipt50_ms &&
                receipt_after_files == SCALE_50K_FILES);

    /* ── 3: warm questions, query time only ── */
    if (ci) { codeindex_close(ci); ci = NULL; }
    ci = codeindex_open(FIX_50K);
    SCALE_CHECK("warm reopen of the 50k index", ci != NULL);
    struct ci_file file_rec;
    bool file_found = false;
    uint64_t q_file_start_us = scale_monotonic_us();
    bool q_file_ok = ci &&
        codeindex_file(ci, "src/m000/s00/f00042.c", &file_rec, &file_found) &&
        file_found;
    uint64_t q_file_us = scale_monotonic_us() - q_file_start_us;
    struct ci_symbol syms[8];
    uint64_t q_find_start_us = scale_monotonic_us();
    int nfound = ci ? codeindex_find(ci, "scale_sym_49999", syms, 8) : -1;
    uint64_t q_find_us = scale_monotonic_us() - q_find_start_us;
    struct test_budget warm_q_budget =
        test_budget_scale(WARM_QUESTION_BUDGET_US);
    printf("  codeindex_scale: warm file-lookup us=%llu symbol-find us=%llu nominal_us=%llu effective_us=%llu load_factor=%.2f calib_us=%llu\n",
           (unsigned long long)q_file_us, (unsigned long long)q_find_us,
           (unsigned long long)WARM_QUESTION_BUDGET_US,
           (unsigned long long)warm_q_budget.effective_us,
           warm_q_budget.factor,
           (unsigned long long)warm_q_budget.calib_med_us);
    SCALE_CHECK("warm exact-path lookup answers within load-scaled 50 ms budget",
                q_file_ok && q_file_us <= warm_q_budget.effective_us);
    SCALE_CHECK("warm symbol find answers within load-scaled 50 ms budget",
                nfound >= 1 &&
                strcmp(syms[0].name, "scale_sym_49999") == 0 &&
                q_find_us <= warm_q_budget.effective_us);
    if (ci) { codeindex_close(ci); ci = NULL; }

    /* ── 4: 500k-file cold build ── */
    (void)test_rm_rf_recursive(FIX_500K);
    printf("  codeindex_scale: generating %ld-file tree...\n",
           SCALE_500K_FILES);
    SCALE_CHECK("generate the 500k-file tree",
                scale_generate(FIX_500K, SCALE_500K_FILES));

    uint64_t cold500_start_us = scale_monotonic_us();
    struct codeindex *ci500 = codeindex_open(FIX_500K);
    uint64_t cold500_us = scale_monotonic_us() - cold500_start_us;
    long long receipt500_ms = 0, receipt500_files = 0;
    bool receipt500 = ci500 &&
        codeindex_build_cold_ms(ci500, &receipt500_ms, &receipt500_files);
    printf("SCALE_BUILD files=%ld ms=%llu receipt_ms=%lld\n",
           SCALE_500K_FILES, (unsigned long long)(cold500_us / 1000),
           receipt500_ms);
    SCALE_CHECK("cold build of 500k files opens with an exact count",
                ci500 && codeindex_file_count(ci500) == (int)SCALE_500K_FILES);
    SCALE_CHECK("the 500k store seals its cold-build self-receipt",
                receipt500 && receipt500_ms > 0 &&
                receipt500_files == SCALE_500K_FILES);
    if (ci500) { codeindex_close(ci500); ci500 = NULL; }

    /* ── 5: linearity — 10x the files within 30x the time ── */
    double ratio = cold50_us > 0 ? (double)cold500_us / (double)cold50_us
                                 : 0.0;
    bool linear = cold50_us > 0 && cold500_us > 0 &&
                  cold500_us <= cold50_us * SCALE_LINEARITY_BOUND;
    printf("SCALE_LINEARITY ratio=%.1fx bound=%llux\n", ratio,
           (unsigned long long)SCALE_LINEARITY_BOUND);
    SCALE_CHECK("500k cold build stays within 30x of the 50k build", linear);
    printf("SCALE_VERDICT=%s\n", linear && failures == 0 ? "PASS" : "FAIL");

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
