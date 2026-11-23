/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_testcache_shadow - known-answer tests for the dev-proof shadow verdict
 * lane (tools/dev/dev_proof.c, ZCL_DEV_PROOF_SHADOW_STORE). The lane probes a
 * persistent verdict store before the cold test dimension, audits every
 * predicted-PASS group against the cold verdict afterwards, and seeds PASS
 * records only from an accepted proof. It never skips a group.
 *
 *   1. A store holding N planted PASSes for the current keys probes
 *      would_reuse = N.
 *   2. Editing one group's closure file turns exactly that prediction into a
 *      miss.
 *   3. A planted PASS contradicted by a cold FAIL is reported as a divergence
 *      in phases.txt and in the audit count; an agreeing cold log reports none.
 *   4. The cold run count must equal the probed group count (nothing skipped),
 *      and the test dimension's argv stays --no-cache with the lane enabled.
 *   5. The runner refuses --cache-seed-pass without --cache-probe-only, and
 *      the lane's own variable never perturbs the cache keyspace.
 *   6. Only a provably empty verdict store skips the advisory probe; accepted
 *      proofs still seed, while unexpected entries and invalid roots do not.
 *   7. The lane samples about one exact attempt in eight by attempt key and
 *      never a universal one; on, off or sampled out, the receipt and the
 *      test dimension's child receipt are byte-identical, and a sampled
 *      proof still audits divergences=0 and seeds.
 */

#include "test/test_core.h"
#include "test/testcache.h"
#include "dev_proof.h"
#include "platform/os_proc.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define TCS_N 3

static const char *tcs_fix(void)
{
    static char path[96];
    if (!path[0])
        (void)snprintf(path, sizeof(path), "test-tmp/tcs_fix.%ld",
                       (long)getpid());
    return path;
}

static const char *tcs_store(void)
{
    static char path[96];
    if (!path[0])
        (void)snprintf(path, sizeof(path), "test-tmp/tcs_store.%ld",
                       (long)getpid());
    return path;
}

static bool tcs_write(const char *rel, const char *content)
{
    char full[4096];
    FILE *f;
    (void)snprintf(full, sizeof(full), "%s/%s", tcs_fix(), rel);
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; (void)mkdir(full, 0755); *p = '/'; }
    }
    f = fopen(full, "wb");
    if (!f) return false;
    size_t n = strlen(content);
    bool ok = n == 0 || fwrite(content, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

static bool tcs_write_q(int i, const char *add)
{
    char rel[96], body[512];
    (void)snprintf(rel, sizeof(rel), "core/modules/net/src/tc_q%02d.c", i);
    (void)snprintf(body, sizeof(body),
                   "#include \"net/tc.h\"\n"
                   "int test_demo_q%02d(void)\n{\n"
                   "    return tc_mid() + tc_leaf()%s;\n}\n",
                   i, add);
    return tcs_write(rel, body);
}

static bool tcs_write_q_dep(int i)
{
    char rel[96], body[512];
    (void)snprintf(rel, sizeof(rel), "build/obj/tc_q%02d.d", i);
    (void)snprintf(body, sizeof(body),
                   "build/obj/tc_q%02d.o: core/modules/net/src/tc_q%02d.c "
                   "core/modules/net/include/net/tc.h\n", i, i);
    return tcs_write(rel, body);
}

static bool tcs_write_sources(const char *add_q1)
{
    bool ok = tcs_write("tests/harness/src/test_parallel.c",
                        "int main(void) { return 0; }\n") &&
              tcs_write("tests/harness/src/testcache.c",
                        "int cache_policy(void) { return 1; }\n") &&
              tcs_write("tests/harness/include/test/test_core.h",
                        "#define TEST_CORE 1\n") &&
              tcs_write("tests/harness/include/test/testcache.h",
                        "#define TEST_CACHE 1\n") &&
              tcs_write("core/modules/net/include/net/tc.h",
                        "#ifndef NET_TC_H\n#define NET_TC_H\n"
                        "int tc_mid(void);\nint tc_leaf(void);\n#endif\n") &&
              tcs_write("core/modules/net/src/tc_mid.c",
                        "#include \"net/tc.h\"\n"
                        "int tc_mid(void) { return tc_leaf() * 2; }\n") &&
              tcs_write("core/modules/net/src/tc_leaf.c",
                        "#include \"net/tc.h\"\n"
                        "int tc_leaf(void) { return 7; }\n");
    for (int i = 1; ok && i <= TCS_N; i++)
        ok = tcs_write_q(i, i == 1 ? add_q1 : "");
    return ok;
}

static bool tcs_write_depfiles(void)
{
    bool ok = tcs_write("build/obj/tc_mid.d",
                        "build/obj/tc_mid.o: core/modules/net/src/tc_mid.c "
                        "core/modules/net/include/net/tc.h\n") &&
              tcs_write("build/obj/tc_leaf.d",
                        "build/obj/tc_leaf.o: core/modules/net/src/tc_leaf.c "
                        "core/modules/net/include/net/tc.h\n") &&
              tcs_write("build/obj/test_parallel.d",
                        "build/obj/test_parallel.o: "
                        "tests/harness/src/test_parallel.c "
                        "tests/harness/include/test/test_core.h\n") &&
              tcs_write("build/obj/testcache.d",
                        "build/obj/testcache.o: tests/harness/src/testcache.c "
                        "tests/harness/include/test/testcache.h\n");
    for (int i = 1; ok && i <= TCS_N; i++)
        ok = tcs_write_q_dep(i);
    return ok;
}

/* Sources first, depfiles last: the include-graph freshness guard wants the
 * graph to be the newest bytes in the fixture. */
static bool tcs_build_fixture(const char *add_q1)
{
    return tcs_write_sources(add_q1) && tcs_write_depfiles();
}

static void tcs_name(int i, char out[32])
{
    (void)snprintf(out, 32, "test_demo_q%02d", i);
}

/* Probe all N groups against the shadow store; returns the HIT count. */
static int tcs_probe(struct testcache_probe out[TCS_N], bool store_pass)
{
    struct testcache *tc;
    (void)mkdir(tcs_store(), 0755);
    tc = testcache_open(tcs_fix());
    int hits = -1;
    if (!tc) return -1;
    hits = 0;
    for (int i = 0; i < TCS_N; i++) {
        char name[32];
        tcs_name(i + 1, name);
        testcache_probe_group(tc, name, &out[i]);
        if (store_pass && out[i].cacheable) testcache_store_pass(tc, out[i].key);
        if (out[i].hit) hits++;
    }
    testcache_close(tc);
    return hits;
}

/* The runner's --cache-probe-only text for `probes`. */
static size_t tcs_probe_log(const struct testcache_probe probes[TCS_N],
                            char *out, size_t cap)
{
    size_t used = 0;
    unsigned reuse = 0;
    for (int i = 0; i < TCS_N; i++) {
        char name[32];
        tcs_name(i + 1, name);
        used += (size_t)snprintf(out + used, cap - used,
                                 "PROBE %s %s ok 0123456789ab\n", name,
                                 probes[i].hit ? "HIT" : "MISS");
        reuse += probes[i].hit ? 1u : 0u;
    }
    used += (size_t)snprintf(out + used, cap - used,
                             "PROBE-SUMMARY groups=%d would_reuse=%u "
                             "must_run=%u uncacheable=0\n",
                             TCS_N, reuse, TCS_N - reuse);
    return used;
}

static size_t tcs_cold_log(const char *failed, unsigned ran, char *out,
                           size_t cap)
{
    size_t used = (size_t)snprintf(out, cap, "[done    ] noise\n");
    if (failed)
        used += (size_t)snprintf(
            out + used, cap - used,
            "\nFailed groups:\n  - %s: exit code=1 log=x\n"
            "      repro: make t-fast ONLY=%s\n\n", failed, failed);
    used += (size_t)snprintf(
        out + used, cap - used,
        "SUITE VERDICT mode=cold groups_total=%d groups_ran=%u "
        "groups_cached=0 groups_gated=0 groups_failed=%d self_skips=0 "
        "env_unobserved=0\n", TCS_N, ran, failed ? 1 : 0);
    return used;
}

static bool tcs_file_has(const char *path, const char *needle)
{
    char buf[4096];
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f) return false;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

static bool tcs_reset_store(void)
{
    char cmd[256];
    (void)snprintf(cmd, sizeof(cmd), "rm -rf %s", tcs_store());
    return system(cmd) == 0;
}

static int tcs_store_checks(void)
{
    int failures = 0;
    struct testcache_probe p[TCS_N];
    char old_store[512] = {0};
    const char *prev = getenv("ZCL_TESTCACHE_STORE_ROOT");
    if (prev) (void)snprintf(old_store, sizeof(old_store), "%s", prev);
    TEST("testcache shadow: N planted PASSes probe would_reuse=N; an edited closure file is one miss") {
        ASSERT(tcs_build_fixture(""));
        ASSERT(tcs_reset_store());
        ASSERT(setenv("ZCL_TESTCACHE_STORE_ROOT", tcs_store(), 1) == 0);
        ASSERT_EQ(tcs_probe(p, false), 0);
        ASSERT_EQ(tcs_probe(p, true), 0);
        ASSERT_EQ(tcs_probe(p, false), TCS_N);
        ASSERT(tcs_write_q(1, " + 1000"));
        ASSERT(tcs_write_q_dep(1));
        ASSERT_EQ(tcs_probe(p, false), TCS_N - 1);
        ASSERT(!p[0].hit && p[1].hit && p[2].hit);
        PASS();
    }
_test_next:;
    if (prev) (void)setenv("ZCL_TESTCACHE_STORE_ROOT", old_store, 1);
    else (void)unsetenv("ZCL_TESTCACHE_STORE_ROOT");
    return failures;
}

static int tcs_seed_eligibility_checks(void)
{
    int failures = 0;
    static const char probe[] = "PROBE test_a MISS ok -\n"
        "PROBE-SUMMARY groups=1 would_reuse=0 must_run=1 uncacheable=0\n";
    static const struct { const char *name, *verdict; bool seed; } cases[] = {
        {"clean", "mode=cold groups_ran=1 groups_failed=0 load_flaky=0", true},
        {"retried", "mode=cold groups_ran=1 groups_failed=0 load_flaky=1", false},
        {"missing", "mode=cold groups_ran=1 groups_failed=0", false},
        {"suffix", "mode=cold groups_ran=1 groups_failed=0 load_flaky=0x", false},
        {"leading-zero", "mode=cold groups_ran=1 groups_failed=0 load_flaky=00", false},
        {"overflow", "mode=cold groups_ran=1 groups_failed=0 load_flaky=4294967296", false},
        {"near-name", "mode=cold groups_ran=1 groups_failed=0 xload_flaky=0", false},
        {"bare-duplicate", "mode=cold groups_ran=1 groups_failed=0 load_flaky load_flaky=0", false},
        {"signed", "mode=cold groups_ran=1 groups_failed=0 load_flaky=+0", false},
        {"duplicate", "mode=cold groups_ran=1 groups_failed=0 load_flaky=0 load_flaky=1", false},
        {"duplicate-zero", "mode=cold groups_ran=1 groups_failed=0 load_flaky=0 load_flaky=0", false},
        {"bad-mode", "mode=warm groups_ran=1 groups_failed=0 load_flaky=0", false},
        {"duplicate-mode", "mode=cold mode=warm groups_ran=1 groups_failed=0 load_flaky=0", false},
        {"failed", "mode=cold groups_ran=1 groups_failed=1 load_flaky=0", false},
        {"short-count", "mode=cold groups_ran=0 groups_failed=0 load_flaky=0", false},
    };
    TEST("testcache shadow: seed refuses retry or uncertain cold evidence") {
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            char cold[512];
            struct zcl_dev_proof_shadow_audit a = {0};
            int n = snprintf(cold, sizeof(cold), "SUITE VERDICT %s\n", cases[i].verdict);
            ASSERT(n > 0 && (size_t)n < sizeof(cold));
            bool ok = zcl_dev_proof_test_shadow_audit(probe, strlen(probe), cold,
                                                      (size_t)n, NULL, &a);
            if (!ok || a.seed_cold_eligible != cases[i].seed)
                printf("shadow seed case=%s audit=%d seed=%d\n", cases[i].name,
                       ok, a.seed_cold_eligible);
            ASSERT(ok && a.seed_cold_eligible == cases[i].seed);
            bool empty_seed = zcl_dev_proof_test_shadow_seed_cold(
                cold, (size_t)n, 1, true, false, true);
            if (empty_seed != cases[i].seed)
                printf("shadow empty seed case=%s seed=%d\n", cases[i].name,
                       empty_seed);
            ASSERT(empty_seed == cases[i].seed);
            ASSERT(!zcl_dev_proof_test_shadow_seed_cold(
                cold, (size_t)n, 1, false, false, true));
            ASSERT(!zcl_dev_proof_test_shadow_seed_cold(
                cold, (size_t)n, 1, true, false, false));
        }
        static const char duplicate[] =
            "SUITE VERDICT mode=cold groups_ran=1 groups_failed=0 load_flaky=0\n"
            "SUITE VERDICT mode=cold groups_ran=1 groups_failed=0 load_flaky=0\n";
        struct zcl_dev_proof_shadow_audit a = {0};
        ASSERT(!zcl_dev_proof_test_shadow_audit(probe, strlen(probe), duplicate,
                                                sizeof(duplicate) - 1, NULL, &a));
        static const char truncated[] =
            "SUITE VERDICT mode=cold groups_ran=1 groups_failed=0 load_flaky=0";
        ASSERT(!zcl_dev_proof_test_shadow_audit(probe, strlen(probe), truncated,
                                                sizeof(truncated) - 1, NULL, &a));
        ASSERT(!zcl_dev_proof_test_shadow_seed_cold(
            duplicate, sizeof(duplicate) - 1, 1, true, false, true));
        ASSERT(!zcl_dev_proof_test_shadow_seed_cold(
            truncated, sizeof(truncated) - 1, 1, true, false, true));
        PASS();
    }
_test_next:;
    return failures;
}

static int tcs_tail_boundary_checks(void)
{
    int failures = 0;
    static const char verdict[] = "SUITE VERDICT mode=cold groups_ran=1 groups_failed=0 load_flaky=0\n";
    TEST("testcache shadow: clipped tail preserves only complete first lines") {
        char path[512];
        ASSERT(snprintf(path, sizeof(path), "%s/tail.log", tcs_fix()) < (int)sizeof(path));
        for (int aligned = 0; aligned < 2; aligned++) {
            FILE *f = fopen(path, "wb");
            ASSERT(f != NULL);
            bool ok = fputc(aligned ? '\n' : 'x', f) != EOF &&
                      fwrite(verdict, 1, sizeof(verdict) - 1, f) == sizeof(verdict) - 1;
            for (size_t i = sizeof(verdict) - 1; ok && i < 1024u * 1024u; i++)
                ok = fputc('x', f) != EOF;
            if (fclose(f) != 0) ok = false;
            ASSERT(ok);
            char *tail = NULL;
            size_t n = 0;
            ASSERT(zcl_dev_proof_test_shadow_tail_read(path, &tail, &n));
            bool correct = aligned ? n == 1024u * 1024u &&
                                      !memcmp(tail, verdict, sizeof(verdict) - 1)
                                   : n == 1024u * 1024u - (sizeof(verdict) - 1) &&
                                      !strstr(tail, "SUITE VERDICT ");
            free(tail);
            ASSERT(correct);
        }
        (void)unlink(path);
        PASS();
    }
_test_next:;
    return failures;
}

static int tcs_audit_checks(void)
{
    int failures = 0;
    struct testcache_probe p[TCS_N];
    char probe[2048], cold[2048], phases[128];
    struct zcl_dev_proof_shadow_audit a;
    char old_store[512] = {0};
    const char *prev = getenv("ZCL_TESTCACHE_STORE_ROOT");
    if (prev) (void)snprintf(old_store, sizeof(old_store), "%s", prev);
    (void)snprintf(phases, sizeof(phases), "%s/phases.txt", tcs_fix());
    TEST("testcache shadow: a planted PASS contradicted by a cold FAIL is a divergence; the cold count equals the groups") {
        ASSERT(tcs_build_fixture(""));
        ASSERT(tcs_reset_store());
        ASSERT(setenv("ZCL_TESTCACHE_STORE_ROOT", tcs_store(), 1) == 0);
        ASSERT_EQ(tcs_probe(p, true), 0);
        ASSERT_EQ(tcs_probe(p, false), TCS_N);
        size_t plen = tcs_probe_log(p, probe, sizeof(probe));
        size_t clen = tcs_cold_log("test_demo_q02", TCS_N, cold, sizeof(cold));
        (void)unlink(phases);
        ASSERT(zcl_dev_proof_test_shadow_audit(probe, plen, cold, clen,
                                               phases, &a));
        ASSERT_EQ(a.groups, (uint32_t)TCS_N);
        ASSERT_EQ(a.would_reuse, (uint32_t)TCS_N);
        ASSERT_EQ(a.hits, (uint32_t)TCS_N);
        ASSERT_EQ(a.divergences, 1u);
        ASSERT_EQ(a.cold_ran, a.groups);
        ASSERT(tcs_file_has(phases, "test_shadow_divergence=group="
                                    "test_demo_q02 predicted=PASS "
                                    "cold=FAIL\n"));
        clen = tcs_cold_log(NULL, TCS_N, cold, sizeof(cold));
        (void)unlink(phases);
        ASSERT(zcl_dev_proof_test_shadow_audit(probe, plen, cold, clen,
                                               phases, &a));
        ASSERT_EQ(a.divergences, 0u);
        ASSERT_EQ(a.cold_ran, a.groups);
        ASSERT(!tcs_file_has(phases, "test_shadow_divergence"));
        /* A cold run that ran fewer groups than were probed is visible. */
        clen = tcs_cold_log(NULL, TCS_N - 1, cold, sizeof(cold));
        ASSERT(zcl_dev_proof_test_shadow_audit(probe, plen, cold, clen,
                                               NULL, &a));
        ASSERT(a.cold_ran != a.groups);
        /* No verdict line, or two: unaccountable, never guessed. */
        ASSERT(!zcl_dev_proof_test_shadow_audit(probe, plen, "x\n", 2,
                                                NULL, &a));
        PASS();
    }
_test_next:;
    if (prev) (void)setenv("ZCL_TESTCACHE_STORE_ROOT", old_store, 1);
    else (void)unsetenv("ZCL_TESTCACHE_STORE_ROOT");
    return failures;
}

static int tcs_capture_status(const char *command, char *out, size_t cap)
{
    FILE *pipe = popen(command, "r");
    size_t n;
    int status;
    if (!pipe) return -1;
    n = fread(out, 1, cap - 1, pipe);
    out[n] = '\0';
    status = pclose(pipe);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int tcs_lane_contract_checks(void)
{
    int failures = 0;
    TEST("testcache shadow: the cold dimension stays --no-cache and the lane variable is outside the keyspace") {
        const char *argv[8] = {0};
        uint8_t before[32], after[32];
        bool no_cache = false;
        ASSERT(unsetenv("ZCL_DEV_PROOF_SHADOW_STORE") == 0);
        testcache_current_envkey(before);
        ASSERT(setenv("ZCL_DEV_PROOF_SHADOW_STORE", "/shadow/store", 1) == 0);
        testcache_current_envkey(after);
        ASSERT(memcmp(before, after, 32) == 0);
        ASSERT_EQ(zcl_dev_proof_test_dimension_argv("runner", "--only=x", argv,
                                                    8), 4u);
        for (int i = 0; argv[i]; i++) {
            ASSERT(strcmp(argv[i], "--cache") != 0);
            ASSERT(strcmp(argv[i], "--cache-seed-pass") != 0);
            no_cache |= strcmp(argv[i], "--no-cache") == 0;
        }
        ASSERT(no_cache);
        PASS();
    }
_test_next:;
    (void)unsetenv("ZCL_DEV_PROOF_SHADOW_STORE");
    return failures;
}

static int tcs_runner_flag_checks(void)
{
    int failures = 0;
    TEST("testcache shadow: the runner refuses --cache-seed-pass without --cache-probe-only") {
        char exe[PATH_MAX], command[3 * PATH_MAX], out[4096];
        ASSERT(os_proc_exe_path(exe, sizeof(exe)));
        ASSERT(snprintf(command, sizeof(command),
                        "\"%s\" --exact=test_hex_codec --cache "
                        "--cache-seed-pass 2>&1", exe) <
               (int)sizeof(command));
        ASSERT_EQ(tcs_capture_status(command, out, sizeof(out)), 2);
        ASSERT(strstr(out, "--cache-seed-pass requires --cache-probe-only") !=
               NULL);
        PASS();
    }
_test_next:;
    return failures;
}

static bool tcs_mkdirs(const char *path)
{
    char copy[PATH_MAX];
    if (snprintf(copy, sizeof(copy), "%s", path) >= (int)sizeof(copy))
        return false;
    for (char *p = copy + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(copy, 0755) != 0 && errno != EEXIST) return false;
        *p = '/';
    }
    return mkdir(copy, 0755) == 0 || errno == EEXIST;
}

static int tcs_empty_probe_checks(void)
{
    int failures = 0;
    char objects[PATH_MAX], phases[PATH_MAX];
    (void)snprintf(objects, sizeof(objects), "%s/.zvcs/objects", tcs_store());
    (void)snprintf(phases, sizeof(phases), "%s/empty-shadow.phases", tcs_fix());
    TEST("testcache shadow: only a provably empty store skips its probe; accepted proofs still seed") {
        ASSERT(tcs_build_fixture(""));
        ASSERT(tcs_reset_store());
        ASSERT(tcs_mkdirs(tcs_store()));
        (void)unlink(phases);
        ASSERT(zcl_dev_proof_test_shadow_skip_empty(tcs_store(), phases));
        ASSERT(tcs_file_has(phases,
                            "test_shadow=advisory skipped reason=empty_verdict_store\n"));
        ASSERT(!zcl_dev_proof_test_shadow_seed_decision(true, false, true, false));
        ASSERT(zcl_dev_proof_test_shadow_seed_decision(true, false, true, true));
        ASSERT(!zcl_dev_proof_test_shadow_seed_decision(false, false, true, true));
        ASSERT(!zcl_dev_proof_test_shadow_seed_decision(true, false, false, true));
        ASSERT(zcl_dev_proof_test_shadow_seed_decision(true, true, false, true));
        ASSERT(!zcl_dev_proof_test_shadow_seed_decision(true, true, false, false));

        ASSERT(tcs_mkdirs(objects));
        ASSERT(zcl_dev_proof_test_shadow_skip_empty(tcs_store(), NULL));
        char tmp[PATH_MAX];
        (void)snprintf(tmp, sizeof(tmp), "%s/tmp", objects);
        ASSERT(tcs_mkdirs(tmp));
        ASSERT(zcl_dev_proof_test_shadow_skip_empty(tcs_store(), NULL));
        char unexpected[PATH_MAX];
        (void)snprintf(unexpected, sizeof(unexpected), "%s/unexpected", objects);
        ASSERT(tcs_mkdirs(unexpected));
        ASSERT(!zcl_dev_proof_test_shadow_skip_empty(tcs_store(), NULL));
        ASSERT(tcs_reset_store());
        FILE *root = fopen(tcs_store(), "wb");
        ASSERT(root != NULL);
        ASSERT(fclose(root) == 0);
        ASSERT(!zcl_dev_proof_test_shadow_skip_empty(tcs_store(), NULL));
        PASS();
    }
_test_next:;
    (void)unlink(phases);
    return failures;
}

/* ── Sampling: the lane runs on about one exact selection in eight ── */

static int tcs_sampling_checks(void)
{
    int failures = 0;
    TEST("testcache shadow: about one exact attempt in eight is sampled, deterministically; universal never") {
        unsigned sampled = 0;
        for (unsigned i = 0; i < 4096; i++) {
            char key[64];
            (void)snprintf(key, sizeof(key), "%040u-%040u", i, i * 7u + 3u);
            bool once = zcl_dev_proof_test_shadow_sampled(key, false);
            ASSERT(once == zcl_dev_proof_test_shadow_sampled(key, false));
            ASSERT(!zcl_dev_proof_test_shadow_sampled(key, true));
            sampled += once ? 1u : 0u;
        }
        ASSERT(sampled >= 384u && sampled <= 640u);
        ASSERT(!zcl_dev_proof_test_shadow_sampled("", false));
        ASSERT(!zcl_dev_proof_test_shadow_sampled(NULL, false));
        PASS();
    }
_test_next:;
    return failures;
}

/* An attempt key the lane does (`want`) or does not sample. */
static bool tcs_lane_key(bool want, char out[64])
{
    for (unsigned i = 0; i < 4096; i++) {
        (void)snprintf(out, 64, "lane-%u-base", i);
        if (zcl_dev_proof_test_shadow_sampled(out, false) == want)
            return true;
    }
    return false;
}

/* A stub runner: the probe-only output of two groups (one predicted PASS),
 * or the seed summary when asked to seed. */
static bool tcs_lane_runner(const char *dir, char *runner, size_t cap)
{
    static const char body[] =
        "#!/bin/sh\n"
        "for a in \"$@\"; do\n"
        "  if [ \"$a\" = --cache-seed-pass ]; then\n"
        "    echo 'SEED-SUMMARY stored=2 attempted=2 failed=0'; exit 0\n"
        "  fi\n"
        "done\n"
        "echo 'PROBE test_lane_a HIT ok 0123456789ab'\n"
        "echo 'PROBE test_lane_b MISS ok 0123456789ab'\n"
        "echo 'PROBE-SUMMARY groups=2 would_reuse=1 must_run=1 uncacheable=0'\n";
    if (snprintf(runner, cap, "%s/runner", dir) >= (int)cap) return false;
    FILE *f = fopen(runner, "wb");
    if (!f) return false;
    bool ok = fwrite(body, 1, sizeof(body) - 1, f) == sizeof(body) - 1;
    return fclose(f) == 0 && ok && chmod(runner, 0700) == 0;
}

/* The cold test log the audit reads for `key`: both groups ran and passed. */
static bool tcs_lane_cold(const char *dir, const char *key)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s.test.log", dir, key) >=
        (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    int n = fprintf(f, "[done    ] noise\nSUITE VERDICT mode=cold "
                       "groups_total=2 groups_ran=2 groups_cached=0 "
                       "groups_gated=0 groups_failed=0 self_skips=0 "
                       "env_unobserved=0 load_flaky=0\n");
    return fclose(f) == 0 && n > 0;
}

static void tcs_lane_receipt(struct zcl_dev_acceptance_receipt_v1 *r)
{
    memset(r, 0, sizeof(*r));
    r->local_commit_len = 20;
    r->remote_base_len = 20;
    memset(r->local_commit, 0x11, 20);
    memset(r->remote_base, 0x22, 20);
    memset(r->source_cas_root, 0x33, sizeof(r->source_cas_root));
    r->dimensions[ZCL_DEV_PROOF_TEST].selected = 2;
    r->dimensions[ZCL_DEV_PROOF_TEST].ran = 2;
    memset(r->dimensions[ZCL_DEV_PROOF_TEST].receipt_root, 0x44,
           sizeof(r->dimensions[ZCL_DEV_PROOF_TEST].receipt_root));
    r->dimensions[ZCL_DEV_PROOF_LINT].selected = 1;
    r->dimensions[ZCL_DEV_PROOF_LINT].ran = 1;
    r->complete = 1;
    r->has_signature = true;
    memset(r->signer_pubkey, 0x55, sizeof(r->signer_pubkey));
    memset(r->signature, 0x66, sizeof(r->signature));
}

/* Run the lane once and return the serialized receipt and the test
 * dimension's child receipt it left behind. */
static bool tcs_lane_run(const struct zcl_dev_proof_shadow_lane *c,
                         uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES],
                         uint8_t child[ZCL_DEV_PROOF_CHILD_WIRE_BYTES])
{
    struct zcl_dev_acceptance_receipt_v1 r;
    tcs_lane_receipt(&r);
    (void)unlink(c->phases);
    return tcs_lane_cold(c->dir, c->key) &&
           zcl_dev_proof_test_shadow_lane(c, &r) &&
           zcl_dev_proof_receipt_serialize(&r, wire) &&
           zcl_dev_proof_child_receipt_create(
               ZCL_DEV_PROOF_TEST, &r.dimensions[ZCL_DEV_PROOF_TEST], child);
}

static int tcs_lane_checks(void)
{
    int failures = 0;
    char cwd[PATH_MAX], dir[PATH_MAX], store[PATH_MAX], objects[PATH_MAX];
    char runner[PATH_MAX], phases[PATH_MAX], on_key[64], off_key[64];
    uint8_t base_wire[ZCL_DEV_PROOF_WIRE_BYTES], wire[ZCL_DEV_PROOF_WIRE_BYTES];
    uint8_t base_child[ZCL_DEV_PROOF_CHILD_WIRE_BYTES];
    uint8_t child[ZCL_DEV_PROOF_CHILD_WIRE_BYTES];
    struct zcl_dev_proof_shadow_lane c = {0};
    TEST("testcache shadow: probe on, off and sampled out leave the receipt and test verdict byte-identical") {
        ASSERT(getcwd(cwd, sizeof(cwd)) != NULL);
        ASSERT(snprintf(dir, sizeof(dir), "%s/%s/lane", cwd, tcs_fix()) <
               (int)sizeof(dir));
        ASSERT(snprintf(store, sizeof(store), "%s/%s", cwd, tcs_store()) <
               (int)sizeof(store));
        ASSERT(snprintf(objects, sizeof(objects), "%s/.zvcs/objects/held",
                        store) < (int)sizeof(objects));
        ASSERT(snprintf(phases, sizeof(phases), "%s/phases.txt", dir) <
               (int)sizeof(phases));
        ASSERT(tcs_reset_store());
        ASSERT(tcs_mkdirs(dir) && tcs_mkdirs(objects));
        ASSERT(tcs_lane_runner(dir, runner, sizeof(runner)));
        ASSERT(tcs_lane_key(true, on_key) && tcs_lane_key(false, off_key));
        c = (struct zcl_dev_proof_shadow_lane){.runner = runner, .dir = dir,
            .key = on_key, .phases = phases, .accepted = true};

        /* Lane off: no store configured. */
        ASSERT(unsetenv("ZCL_DEV_PROOF_SHADOW_STORE") == 0);
        ASSERT(tcs_lane_run(&c, base_wire, base_child));
        ASSERT(!tcs_file_has(phases, "test_shadow"));

        /* Lane on, sampled: probed, audited with no divergence, seeded. */
        ASSERT(setenv("ZCL_DEV_PROOF_SHADOW_STORE", store, 1) == 0);
        ASSERT(tcs_lane_run(&c, wire, child));
        ASSERT(memcmp(wire, base_wire, sizeof(wire)) == 0);
        ASSERT(memcmp(child, base_child, sizeof(child)) == 0);
        ASSERT(tcs_file_has(phases, "test_shadow=groups=2 would_reuse=1 "
                                    "must_run=1 uncacheable=0\n"));
        ASSERT(tcs_file_has(phases, "test_shadow_audit=groups=2 hits=1 "
                                    "divergences=0 cold_ran=2 "
                                    "cold_matches_groups=1\n"));
        ASSERT(tcs_file_has(phases, "test_shadow_seed=stored=2 attempted=2 "
                                    "failed=0\n"));
        ASSERT(!tcs_file_has(phases, "sampled_out"));

        /* Lane on, sampled out: one note, no probe, audit or seed. */
        c.key = off_key;
        ASSERT(tcs_lane_run(&c, wire, child));
        ASSERT(memcmp(wire, base_wire, sizeof(wire)) == 0);
        ASSERT(memcmp(child, base_child, sizeof(child)) == 0);
        ASSERT(tcs_file_has(phases, "test_shadow=sampled_out\n"));
        ASSERT(!tcs_file_has(phases, "test_shadow_audit"));
        ASSERT(!tcs_file_has(phases, "test_shadow_seed"));

        /* A universal selection is never sampled, even on a sampled key. */
        c.key = on_key;
        c.universal = true;
        ASSERT(tcs_lane_run(&c, wire, child));
        ASSERT(memcmp(wire, base_wire, sizeof(wire)) == 0);
        ASSERT(memcmp(child, base_child, sizeof(child)) == 0);
        ASSERT(tcs_file_has(phases, "test_shadow=sampled_out\n"));
        ASSERT(!tcs_file_has(phases, "test_shadow_audit"));
        PASS();
    }
_test_next:;
    (void)unsetenv("ZCL_DEV_PROOF_SHADOW_STORE");
    return failures;
}

int test_testcache_shadow(void);
int test_testcache_shadow(void)
{
    int failures = 0;
    printf("\n=== testcache shadow lane tests ===\n");
    failures += tcs_store_checks();
    failures += tcs_audit_checks();
    failures += tcs_seed_eligibility_checks();
    failures += tcs_tail_boundary_checks();
    failures += tcs_lane_contract_checks();
    failures += tcs_runner_flag_checks();
    failures += tcs_empty_probe_checks();
    failures += tcs_sampling_checks();
    failures += tcs_lane_checks();
    if (!tcs_reset_store())
        failures++;
    {
        char cmd[256];
        (void)snprintf(cmd, sizeof(cmd), "rm -rf %s", tcs_fix());
        if (system(cmd) != 0) failures++;
    }
    printf("=== testcache shadow lane tests: %d failure(s) ===\n", failures);
    return failures;
}
