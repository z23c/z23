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
 */

#include "test/test_core.h"
#include "test/testcache.h"
#include "dev_proof.h"
#include "platform/os_proc.h"

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

int test_testcache_shadow(void);
int test_testcache_shadow(void)
{
    int failures = 0;
    printf("\n=== testcache shadow lane tests ===\n");
    failures += tcs_store_checks();
    failures += tcs_audit_checks();
    failures += tcs_lane_contract_checks();
    failures += tcs_runner_flag_checks();
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
