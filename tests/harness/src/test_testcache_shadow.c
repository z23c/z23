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
