/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_testcache — the content-addressed per-group test cache (tests/harness/src/
 * testcache.c). Drives the module against a tiny fixture code index + .zvcs
 * store under ./test-tmp/ (project no-/tmp convention), asserting the four
 * properties the whole design rests on:
 *
 *   1. A group with a bounded, resolvable forward closure is CACHEABLE; a fresh
 *      key has no stored PASS (miss); after store_pass the same key HITS.
 *   2. SOUNDNESS — editing any file IN the closure (a callee body OR an included
 *      header) changes the key, so the old stored PASS no longer hits.
 *   3. SELECTIVITY + persistence — editing a file OUTSIDE the closure leaves the
 *      key unchanged, so the stored PASS still hits across a reopen.
 *   4. UNCACHEABLE cases — an external-input denylisted group and an unresolved
 *      entry symbol are both reported uncacheable (=> they always run).
 *
 * The fixture models a callee chain test_demo_entry -> tc_mid -> tc_leaf plus an
 * unrelated tc_other, so the forward closure is exactly {top, mid, leaf, header}
 * and never tc_other. */

#include "test/test_core.h"
#include "test/testcache.h"
#include "dev_proof_observation_admission.h"
#include "vcs/vcs_object.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Each runner process owns its fixture tree. Two independent proof/test
 * processes can now exercise this group concurrently without deleting each
 * other's source, depfiles, signer state, or CAS objects. */
static const char *tc_path(unsigned slot)
{
    static pid_t owner;
    static char paths[5][80];
    pid_t pid = getpid();
    if (owner != pid) {
        (void)snprintf(paths[0], sizeof(paths[0]),
                       "test-tmp/tc_cache_fix.%ld", (long)pid);
        (void)snprintf(paths[1], sizeof(paths[1]),
                       "test-tmp/tc_cache_store.%ld", (long)pid);
        (void)snprintf(paths[2], sizeof(paths[2]),
                       "test-tmp/tc_cache_fix2.%ld", (long)pid);
        (void)snprintf(paths[3], sizeof(paths[3]),
                       "test-tmp/tc_capsule.%ld", (long)pid);
        (void)snprintf(paths[4], sizeof(paths[4]),
                       "test-tmp/tc_capsule2.%ld", (long)pid);
        owner = pid;
    }
    return slot < 5 ? paths[slot] : NULL;
}

static bool tc_shell(const char *fmt, ...)
{
    char cmd[512];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(cmd, sizeof(cmd), fmt, args);
    va_end(args);
    return n >= 0 && (size_t)n < sizeof(cmd) && system(cmd) == 0;
}

#define TC_FIX tc_path(0)
#define TC_STORE tc_path(1)

#define TC_CHECK(name, expr) do {                                    \
    if (expr) { printf("  testcache: %s... OK\n", (name)); }         \
    else { printf("  testcache: %s... FAIL\n", (name)); failures++; }\
} while (0)

/* Write <base>/<rel>, creating parent dirs (same idiom as the sibling tests). */
static bool mk_write(const char *base, const char *rel, const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", base, rel);
    /* create every parent component, including the fixture root itself */
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    size_t n = content ? strlen(content) : 0;
    if (n && fwrite(content, 1, n, f) != n) { fclose(f); return false; }
    fclose(f);
    return true;
}

static const char *TC_TOP =
    "/* core/modules/net/src/tc_top.c — the group entry point. */\n"
    "#include \"net/tc.h\"\n"
    "int test_demo_entry(void)\n"
    "{\n"
    "    return tc_mid() + 1;\n"
    "}\n";

static const char *TC_MID =
    "/* core/modules/net/src/tc_mid.c — middle of the callee chain. */\n"
    "#include \"net/tc.h\"\n"
    "int tc_mid(void)\n"
    "{\n"
    "    return tc_leaf() * 2;\n"
    "}\n";

static const char *TC_LEAF_A =
    "/* core/modules/net/src/tc_leaf.c — the leaf (pristine). */\n"
    "#include \"net/tc.h\"\n"
    "int tc_leaf(void)\n"
    "{\n"
    "    return 7;\n"
    "}\n";

static const char *TC_LEAF_B =
    "/* core/modules/net/src/tc_leaf.c — the leaf (edited body). */\n"
    "#include \"net/tc.h\"\n"
    "int tc_leaf(void)\n"
    "{\n"
    "    return 4242;\n"
    "}\n";

static const char *TC_OTHER_A =
    "/* core/modules/net/src/tc_other.c — NOT reachable from the entry (pristine). */\n"
    "#include \"net/tc.h\"\n"
    "int tc_other(void)\n"
    "{\n"
    "    return 99;\n"
    "}\n";

static const char *TC_OTHER_B =
    "/* core/modules/net/src/tc_other.c — NOT reachable from the entry (edited). */\n"
    "#include \"net/tc.h\"\n"
    "int tc_other(void)\n"
    "{\n"
    "    return 123456;\n"
    "}\n";

static const char *TC_H_A =
    "/* core/modules/net/include/net/tc.h — fixture header (pristine). */\n"
    "#ifndef NET_TC_H\n"
    "#define NET_TC_H\n"
    "int test_demo_entry(void);\n"
    "int tc_mid(void);\n"
    "int tc_leaf(void);\n"
    "int tc_other(void);\n"
    "#endif\n";

static const char *TC_H_B =
    "/* core/modules/net/include/net/tc.h — fixture header (edited comment). */\n"
    "#ifndef NET_TC_H\n"
    "#define NET_TC_H\n"
    "/* an added line that changes the header's content hash */\n"
    "int test_demo_entry(void);\n"
    "int tc_mid(void);\n"
    "int tc_leaf(void);\n"
    "int tc_other(void);\n"
    "#endif\n";

/* An X-macro registry, the shape of the 26 tracked *.def files (`git ls-files
 * '*.def' | wc -l`), 17 of which the compiler currently lists as a prerequisite
 * of 29 translation units. It is a compiler prerequisite exactly like a header,
 * and changing it changes the translation unit's behavior exactly like a
 * header. */
static const char *TC_DEF_A =
    "/* core/modules/net/include/net/tc_registry.def — pristine. */\n"
    "TC_ROW(alpha, 1)\n"
    "TC_ROW(beta, 2)\n";

static const char *TC_DEF_B =
    "/* core/modules/net/include/net/tc_registry.def — a row added. */\n"
    "TC_ROW(alpha, 1)\n"
    "TC_ROW(beta, 2)\n"
    "TC_ROW(gamma, 3)\n";

static const char *TC_RUNNER_A = "int main(void) { return 0; }\n";
static const char *TC_RUNNER_B = "int main(void) { return 1; }\n";

static bool write_harness_sources(const char *root)
{
    return mk_write(root, "tests/harness/src/test_parallel.c", TC_RUNNER_A) &&
           mk_write(root, "tests/harness/src/testcache.c",
                    "int cache_policy(void) { return 1; }\n") &&
           mk_write(root, "tests/harness/include/test/test_core.h",
                    "#define TEST_CORE 1\n") &&
           mk_write(root, "tests/harness/include/test/testcache.h",
                    "#define TEST_CACHE 1\n");
}

static bool write_harness_depfiles(const char *root)
{
    return mk_write(root, "build/obj/test_parallel.d",
                    "build/obj/test_parallel.o: "
                    "tests/harness/src/test_parallel.c "
                    "tests/harness/include/test/test_core.h\n") &&
           mk_write(root, "build/obj/testcache.d",
                    "build/obj/testcache.o: tests/harness/src/testcache.c "
                    "tests/harness/include/test/testcache.h\n");
}

/* Write the fixture with the given leaf/other/header/def variants + depfiles so
 * the include closure resolves. Sources are written BEFORE depfiles so the
 * depfiles are always the newest bytes in the fixture — the include-graph
 * freshness guard requires the graph to be at least as new as its inputs. */
static bool write_fixture_full(const char *leaf, const char *other,
                               const char *hdr, const char *def)
{
    return write_harness_sources(TC_FIX) &&
           mk_write(TC_FIX, "core/modules/net/src/tc_top.c", TC_TOP) &&
           mk_write(TC_FIX, "core/modules/net/src/tc_mid.c", TC_MID) &&
           mk_write(TC_FIX, "core/modules/net/src/tc_leaf.c", leaf) &&
           mk_write(TC_FIX, "core/modules/net/src/tc_other.c", other) &&
           mk_write(TC_FIX, "core/modules/net/include/net/tc.h", hdr) &&
           mk_write(TC_FIX, "core/modules/net/include/net/tc_registry.def", def) &&
           mk_write(TC_FIX, "build/obj/tc_top.d",
                    "build/obj/tc_top.o: core/modules/net/src/tc_top.c "
                    "core/modules/net/include/net/tc.h "
                    "core/modules/net/include/net/tc_registry.def\n") &&
           mk_write(TC_FIX, "build/obj/tc_mid.d",
                    "build/obj/tc_mid.o: core/modules/net/src/tc_mid.c "
                    "core/modules/net/include/net/tc.h\n") &&
           mk_write(TC_FIX, "build/obj/tc_leaf.d",
                    "build/obj/tc_leaf.o: core/modules/net/src/tc_leaf.c "
                    "core/modules/net/include/net/tc.h\n") &&
           mk_write(TC_FIX, "build/obj/tc_other.d",
                    "build/obj/tc_other.o: core/modules/net/src/tc_other.c "
                    "core/modules/net/include/net/tc.h\n") &&
           write_harness_depfiles(TC_FIX);
}

static bool write_fixture(const char *leaf, const char *other, const char *hdr)
{
    return write_fixture_full(leaf, other, hdr, TC_DEF_A);
}

/* Does `path` contain `needle`? Used by the source-contract assertions below,
 * which pin runner/gate behavior this module cannot reach from a fixture.
 *
 * Reads the WHOLE file, growing the buffer. A fixed 256 KB buffer was a silent
 * correctness hole rather than a limit: the Makefile is ~330 KB, so the last
 * ~68 KB — which is where the `ci` retry recipe this file asserts on lives —
 * was simply invisible, and a truncated read is indistinguishable from "the
 * string is absent". Every way this can fail to see the whole file now prints
 * a diagnostic instead of returning a bare false. */
static bool file_contains(const char *path, const char *needle)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        printf("  testcache: file_contains: cannot open %s\n", path);
        return false;
    }
    size_t cap = 1u << 16, len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        fclose(f);
        printf("  testcache: file_contains: out of memory reading %s\n", path);
        return false;
    }
    for (;;) {
        if (len + 1 == cap) {
            char *grown = realloc(buf, cap * 2);
            if (!grown) {
                free(buf);
                fclose(f);
                printf("  testcache: file_contains: out of memory growing to "
                       "%zu bytes for %s\n", cap * 2, path);
                return false;
            }
            buf = grown;
            cap *= 2;
        }
        size_t n = fread(buf + len, 1, cap - 1 - len, f);
        len += n;
        if (n == 0) break;
    }
    bool read_error = ferror(f) != 0;
    fclose(f);
    if (read_error) {
        free(buf);
        printf("  testcache: file_contains: read error on %s after %zu byte(s)"
               "\n", path, len);
        return false;
    }
    buf[len] = '\0';
    /* strstr stops at the first NUL. Every file scanned here is text, so a NUL
     * means the scan is not covering what the caller thinks it is — say so
     * rather than silently searching a prefix. */
    if (memchr(buf, '\0', len) != NULL)
        printf("  testcache: file_contains: %s contains a NUL byte — the scan "
               "covers only the bytes before it\n", path);
    bool found = strstr(buf, needle) != NULL;
    free(buf);
    return found;
}

/* AND several file_contains() pins into one boolean without spending an
 * extra `&&` per pin inside test_testcache() itself — that function is
 * cyclomatic-complexity-pinned, and a multi-line source-contract check
 * otherwise grows it one decision point per additional needle. */
static bool file_contains_all(const char *path, const char *const *needles,
                              size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (!file_contains(path, needles[i])) return false;
    return true;
}

/* Caller-environment preservation.
 *
 * Phase H must move ZCL_STRESS_TESTS to prove it is in the key. `test.c` runs
 * this group IN-PROCESS (test.c:1463) with 125 further group calls after it,
 * and one of those — test_shielded_spend_slice at test.c:1600 — reads
 * getenv("ZCL_STRESS_TESTS") at call time to decide whether to run its gate.
 * Clearing the variable unconditionally on the way out silently switched that
 * group onto its SKIP path under `ZCL_STRESS_TESTS=1`, and the run still exited
 * 0. test_parallel forks per group so it never saw this. One group is the
 * blast radius today only because of where the call sits in test.c — nothing
 * stops the next in-process group from landing after this one. Any variable
 * this group moves goes through this pair. */
struct tc_envsave { char *val; bool was_set; };

static void tc_env_capture(struct tc_envsave *s, const char *name)
{
    const char *v = getenv(name);
    s->was_set = (v != NULL);
    s->val = v ? strdup(v) : NULL;
    /* strdup failure would make the restore lie about the caller's value; a
     * loud abort of the assertion beats a silent downgrade to "was unset". */
    if (s->was_set && !s->val)
        printf("  testcache: tc_env_capture: strdup(%s) failed\n", name);
}

static void tc_env_restore(struct tc_envsave *s, const char *name)
{
    if (s->was_set && s->val) setenv(name, s->val, 1);
    else                      unsetenv(name);
    free(s->val);
    s->val = NULL;
    s->was_set = false;
}

/* ── Phase PB: batched proof-reuse lookup ───────────────────────────────
 * The routed-group preflight must probe a whole required set through ONE
 * process, ONE testcache_open, ONE verified dep graph, and the shared
 * path→SHA3 memo — and get byte-identical per-group verdicts. The fixture
 * below is 32 entries test_demo_q01..q32, each with a PRIVATE top file
 * calling the SHARED tc_mid()/tc_leaf() pair under the shared header and
 * registry, so every closure overlaps on 4 of 5 files and the memo has
 * something real to share. Each helper returns its own failure count so
 * test_testcache() itself stays at its pinned complexity. */
#define TC_QN 32
#define TC_FIX2 tc_path(2)

static void tc_qname(int i, char out[64])
{
    snprintf(out, 64, "test_demo_q%02d", i);
}

/* One private entry source. `add` is extra arithmetic inside the return
 * ("" pristine, " + 1000" edited) so an in-closure edit touches exactly
 * one group's closure. */
static bool tc_write_q_source(int i, const char *add)
{
    char rel[128];
    char body[576];
    snprintf(rel, sizeof(rel), "core/modules/net/src/tc_q%02d.c", i);
    snprintf(body, sizeof(body),
             "/* core/modules/net/src/tc_q%02d.c — batch entry. */\n"
             "#include \"net/tc.h\"\n"
             "int test_demo_q%02d(void)\n"
             "{\n"
             "    return tc_mid() + tc_leaf()%s;\n"
             "}\n",
             i, i, add ? add : "");
    return mk_write(TC_FIX, rel, body);
}

static bool tc_write_q_depfile(int i)
{
    char rel[128];
    char body[576];
    snprintf(rel, sizeof(rel), "build/obj/tc_q%02d.d", i);
    snprintf(body, sizeof(body),
             "build/obj/tc_q%02d.o: core/modules/net/src/tc_q%02d.c "
             "core/modules/net/include/net/tc.h "
             "core/modules/net/include/net/tc_registry.def\n",
             i, i);
    return mk_write(TC_FIX, rel, body);
}

/* The four base depfiles, byte-identical to write_fixture_full above:
 * sources are always (re)written BEFORE depfiles so the graph stays the
 * newest bytes in the fixture and the freshness guard holds. */
static bool write_batch_depfiles(void)
{
    bool ok = mk_write(TC_FIX, "build/obj/tc_top.d",
                       "build/obj/tc_top.o: core/modules/net/src/tc_top.c "
                       "core/modules/net/include/net/tc.h "
                       "core/modules/net/include/net/tc_registry.def\n") &&
              mk_write(TC_FIX, "build/obj/tc_mid.d",
                       "build/obj/tc_mid.o: core/modules/net/src/tc_mid.c "
                       "core/modules/net/include/net/tc.h\n") &&
              mk_write(TC_FIX, "build/obj/tc_leaf.d",
                       "build/obj/tc_leaf.o: core/modules/net/src/tc_leaf.c "
                       "core/modules/net/include/net/tc.h\n") &&
              mk_write(TC_FIX, "build/obj/tc_other.d",
                       "build/obj/tc_other.o: core/modules/net/src/tc_other.c "
                       "core/modules/net/include/net/tc.h\n");
    for (int i = 1; i <= TC_QN; i++)
        if (!tc_write_q_depfile(i)) ok = false;
    return write_harness_depfiles(TC_FIX) && ok;
}

static bool write_batch_fixture(void)
{
    bool ok = write_harness_sources(TC_FIX) &&
              mk_write(TC_FIX, "core/modules/net/src/tc_top.c", TC_TOP) &&
              mk_write(TC_FIX, "core/modules/net/src/tc_mid.c", TC_MID) &&
              mk_write(TC_FIX, "core/modules/net/src/tc_leaf.c", TC_LEAF_A) &&
              mk_write(TC_FIX, "core/modules/net/src/tc_other.c", TC_OTHER_A) &&
              mk_write(TC_FIX, "core/modules/net/include/net/tc.h", TC_H_A) &&
              mk_write(TC_FIX, "core/modules/net/include/net/tc_registry.def",
                       TC_DEF_A);
    if (!ok) return false;
    for (int i = 1; i <= TC_QN; i++)
        if (!tc_write_q_source(i, "")) return false;
    return write_batch_depfiles();
}

/* Field-for-field probe identity (reason text is derived from the code,
 * but compare it anyway: a divergent message is a divergent decision). */
static bool tc_probe_equal(const struct testcache_probe *a,
                           const struct testcache_probe *b)
{
    return a->key_valid == b->key_valid &&
           a->cacheable == b->cacheable &&
           a->hit == b->hit &&
           a->hit_flaky == b->hit_flaky &&
           a->n_closure == b->n_closure &&
           a->code == b->code &&
           strcmp(a->reason, b->reason) == 0 &&
           memcmp(a->key, b->key, 32) == 0;
}

static uint64_t tc_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u +
           (uint64_t)ts.tv_nsec / 1000000u;
}

/* Store one PASS per batch entry so parity covers HIT as well as MISS. */
static bool tc_batch_seed(char names[TC_QN][64])
{
    struct testcache *tc = testcache_open(TC_FIX);
    bool stored = tc != NULL;
    for (int i = 0; stored && i < TC_QN; i++) {
        struct testcache_probe p;
        testcache_probe_group(tc, names[i], &p);
        if (p.cacheable) testcache_store_pass(tc, p.key);
        else stored = false;
    }
    if (tc) testcache_close(tc);
    return stored;
}

/* Acceptance 2: one handle serving N groups returns exactly what N fresh
 * handles return — key, code, hit, cacheable — including a denylisted and
 * an unresolved slot that must not perturb their neighbours. */
static int tc_batch_parity(void)
{
    int failures = 0;
    static char names[TC_QN][64];
    static const char *ptrs[TC_QN + 2];
    for (int i = 0; i < TC_QN; i++) {
        tc_qname(i + 1, names[i]);
        ptrs[i] = names[i];
    }
    ptrs[TC_QN] = "test_explorer_index";
    ptrs[TC_QN + 1] = "test_no_such_symbol_zzz";
    TC_CHECK("batch fixture writes", write_batch_fixture());
    TC_CHECK("batch verdict store starts empty",
             tc_shell("rm -rf %s/.zvcs", TC_FIX));
    TC_CHECK("every batch entry is cacheable for seeding",
             tc_batch_seed(names));
    static struct testcache_probe solo[TC_QN + 2], batched[TC_QN + 2];
    for (size_t k = 0; k < TC_QN + 2; k++) {
        struct testcache *tc = testcache_open(TC_FIX);
        if (tc) testcache_probe_group(tc, ptrs[k], &solo[k]);
        if (tc) testcache_close(tc);
    }
    TC_CHECK("solo probes hit their seeded PASSes",
             solo[0].cacheable && solo[0].hit &&
             solo[TC_QN - 1].cacheable && solo[TC_QN - 1].hit);
    {
        struct testcache *tc = testcache_open(TC_FIX);
        bool served = false;
        if (tc) {
            served = testcache_probe_groups(tc, ptrs, NULL, TC_QN + 2,
                                            batched);
            testcache_close(tc);
        }
        TC_CHECK("one handle serves the whole 34-slot set", served);
    }
    {
        bool equal = true;
        for (size_t k = 0; k < TC_QN + 2; k++)
            if (!tc_probe_equal(&solo[k], &batched[k])) equal = false;
        TC_CHECK("batch key/code/hit/cacheable == solo for every slot",
                 equal);
    }
    TC_CHECK("denylisted slot stays uncacheable inside the batch",
             !batched[TC_QN].cacheable &&
             batched[TC_QN].code == TESTCACHE_R_EXTERNAL_INPUT);
    TC_CHECK("unresolved slot stays uncacheable inside the batch",
             !batched[TC_QN + 1].cacheable &&
             batched[TC_QN + 1].code == TESTCACHE_R_ENTRY_UNRESOLVED);
    return failures;
}

/* Acceptance 3: overlapping closures hash each unchanged file once per
 * batch — the existing path→SHA3 memo, now observable via stats. */
static int tc_batch_stats(void)
{
    int failures = 0;
    static char names[8][64];
    static const char *ptrs[8];
    for (int i = 0; i < 8; i++) {
        tc_qname(i + 1, names[i]);
        ptrs[i] = names[i];
    }
    TC_CHECK("stats fixture writes", write_batch_fixture());
    TC_CHECK("stats verdict store starts empty",
             tc_shell("rm -rf %s/.zvcs", TC_FIX));
    struct testcache *tc = testcache_open(TC_FIX);
    TC_CHECK("stats cache opens", tc != NULL);
    if (tc) {
        static struct testcache_probe out[8];
        bool served = testcache_probe_groups(tc, ptrs, NULL, 8, out);
        TC_CHECK("batch of 8 served", served);
        TC_CHECK("each closure is its 5 files (1 private + 4 shared)",
                 out[0].n_closure == 5 && out[7].n_closure == 5);
        struct testcache_stats s;
        testcache_stats(tc, &s);
        TC_CHECK("8 overlapping closures cost 8 closure queries",
                 s.closure_queries == 8);
        TC_CHECK("16 unique files read once (8 private, 4 shared, 4 harness)",
                 s.file_hash_reads == 16);
        TC_CHECK("the other 56 file visits hit the memo",
                 s.file_hash_memo_hits == 8u * 9u - 16u);
        TC_CHECK("content bytes flow through SHA3",
                 s.sha3_content_bytes > 0);
        TC_CHECK("one verdict lookup per cacheable group",
                 s.verdict_lookups == 8 && s.verdict_hits == 0);
        for (int i = 0; i < 8; i++)
            if (out[i].cacheable) testcache_store_pass(tc, out[i].key);
        bool served2 = testcache_probe_groups(tc, ptrs, NULL, 8, out);
        TC_CHECK("second batch served from the same handle", served2);
        struct testcache_stats s2;
        testcache_stats(tc, &s2);
        TC_CHECK("second batch reads no file twice",
                 s2.file_hash_reads == 16);
        TC_CHECK("stored PASSes all hit",
                 s2.verdict_lookups == 16 && s2.verdict_hits == 8);
        testcache_stats_reset(tc);
        struct testcache_stats s3;
        testcache_stats(tc, &s3);
        TC_CHECK("stats reset zeroes every counter",
                 s3.closure_queries == 0 && s3.file_hash_reads == 0 &&
                 s3.file_hash_memo_hits == 0 &&
                 s3.sha3_content_bytes == 0 && s3.verdict_lookups == 0 &&
                 s3.verdict_hits == 0);
        bool served3 = testcache_probe_groups(tc, ptrs, NULL, 8, out);
        TC_CHECK("observability reset changes no verdict",
                 served3 && out[0].hit && out[7].hit);
        testcache_close(tc);
    }
    return failures;
}

/* Acceptance 4: the invalidation matrix. Two private-top edits move only
 * their own keys; a shared-header edit moves all 32; an unrelated edit moves
 * none. Depfiles are refreshed after every content edit (as a rebuild
 * would) so the matrix measures content reach, not graph staleness. One
 * helper per matrix step so each stays under the complexity cap. */
static bool tc_inv_baseline(const char *const *ptrs, uint8_t k0[TC_QN][32])
{
    struct testcache *tc = testcache_open(TC_FIX);
    bool ok = tc != NULL;
    if (tc) {
        static struct testcache_probe out[TC_QN];
        ok = testcache_probe_groups(tc, ptrs, NULL, TC_QN, out);
        for (int i = 0; ok && i < TC_QN; i++) {
            if (!out[i].cacheable) ok = false;
            else {
                memcpy(k0[i], out[i].key, 32);
                testcache_store_pass(tc, out[i].key);
            }
        }
        testcache_close(tc);
    }
    return ok;
}

static bool tc_inv_private(const char *const *ptrs,
                           const uint8_t k0[TC_QN][32], int second)
{
    struct testcache *tc = testcache_open(TC_FIX);
    bool selective = false;
    if (tc) {
        static struct testcache_probe out[TC_QN];
        selective = testcache_probe_groups(tc, ptrs, NULL, TC_QN, out);
        for (int i = 0; selective && i < TC_QN; i++) {
            bool edited = i == 6 || i == second;
            bool moved = memcmp(k0[i], out[i].key, 32) != 0;
            if (edited ? (!moved || out[i].hit) : (moved || !out[i].hit))
                selective = false;
        }
        testcache_close(tc);
    }
    return selective;
}

static bool tc_inv_header(const char *const *ptrs,
                          const uint8_t k0[TC_QN][32],
                          uint8_t k2[TC_QN][32])
{
    struct testcache *tc = testcache_open(TC_FIX);
    bool all_moved = false;
    if (tc) {
        static struct testcache_probe out[TC_QN];
        all_moved = testcache_probe_groups(tc, ptrs, NULL, TC_QN, out);
        for (int i = 0; all_moved && i < TC_QN; i++) {
            if (memcmp(k0[i], out[i].key, 32) == 0) all_moved = false;
            if (out[i].hit) all_moved = false;
        }
        for (int i = 0; all_moved && i < TC_QN; i++)
            memcpy(k2[i], out[i].key, 32);
        testcache_close(tc);
    }
    return all_moved;
}

static bool tc_inv_unrelated(const char *const *ptrs,
                             const uint8_t k2[TC_QN][32])
{
    struct testcache *tc = testcache_open(TC_FIX);
    bool none_moved = false;
    if (tc) {
        static struct testcache_probe out[TC_QN];
        none_moved = testcache_probe_groups(tc, ptrs, NULL, TC_QN, out);
        for (int i = 0; none_moved && i < TC_QN; i++)
            if (memcmp(k2[i], out[i].key, 32) != 0) none_moved = false;
        testcache_close(tc);
    }
    return none_moved;
}

static int tc_batch_invalidation(void)
{
    int failures = 0;
    static char names[TC_QN][64];
    static const char *ptrs[TC_QN];
    for (int i = 0; i < TC_QN; i++) {
        tc_qname(i + 1, names[i]);
        ptrs[i] = names[i];
    }
    TC_CHECK("matrix fixture writes", write_batch_fixture());
    TC_CHECK("matrix verdict store starts empty",
             tc_shell("rm -rf %s/.zvcs", TC_FIX));
    static uint8_t k0[TC_QN][32];
    static uint8_t k2[TC_QN][32];
    TC_CHECK("baseline keys stored for all 32",
             tc_inv_baseline(ptrs, k0));
    TC_CHECK("private-top edit of q07", tc_write_q_source(7, " + 1000") &&
             write_batch_depfiles());
    TC_CHECK("private edit invalidates only the group that reaches it",
             tc_inv_private(ptrs, k0, -1));
    TC_CHECK("independent private-top edit of q19",
             tc_write_q_source(19, " + 2000") && write_batch_depfiles());
    TC_CHECK("both private edits invalidate only their own groups",
             tc_inv_private(ptrs, k0, 18));
    TC_CHECK("shared-header edit", mk_write(TC_FIX,
             "core/modules/net/include/net/tc.h", TC_H_B) &&
             write_batch_depfiles());
    TC_CHECK("shared-header edit moves all 32 keys to MISS",
             tc_inv_header(ptrs, k0, k2));
    TC_CHECK("unrelated-source edit",
             mk_write(TC_FIX, "core/modules/net/src/tc_other.c",
                      TC_OTHER_B) && write_batch_depfiles());
    TC_CHECK("unrelated edit moves no key", tc_inv_unrelated(ptrs, k2));
    TC_CHECK("matrix fixture restored", write_batch_fixture());
    return failures;
}

/* Acceptance 5+6: a stale or missing graph stays fail-closed per slot,
 * and the coverage-gating env keeps its key separation across the batch.
 * One helper per step so each stays under the complexity cap. */
static bool tc_fc_stale(const char *const *ptrs)
{
    struct testcache *tc = testcache_open(TC_FIX);
    bool stale = false;
    if (tc) {
        static struct testcache_probe out[8];
        stale = testcache_probe_groups(tc, ptrs, NULL, 8, out);
        for (int i = 0; stale && i < 8; i++)
            if (out[i].cacheable ||
                out[i].code != TESTCACHE_R_GRAPH_STALE) stale = false;
        testcache_close(tc);
    }
    return stale;
}

static bool tc_fc_missing(const char *const *ptrs)
{
    struct testcache *tc = testcache_open(TC_FIX);
    bool missing = false;
    if (tc) {
        static struct testcache_probe out[8];
        missing = testcache_depfile_count(tc) == 0 &&
                  testcache_probe_groups(tc, ptrs, NULL, 8, out);
        for (int i = 0; missing && i < 8; i++)
            if (out[i].cacheable ||
                out[i].code != TESTCACHE_R_NO_INCLUDE_GRAPH)
                missing = false;
        testcache_close(tc);
    }
    return missing;
}

static bool tc_fc_nonstress(const char *const *ptrs, uint8_t kn[8][32])
{
    struct testcache *tc = testcache_open(TC_FIX);
    bool ok = tc != NULL;
    if (tc) {
        static struct testcache_probe out[8];
        ok = testcache_probe_groups(tc, ptrs, NULL, 8, out);
        for (int i = 0; ok && i < 8; i++) {
            if (!out[i].cacheable) ok = false;
            else memcpy(kn[i], out[i].key, 32);
        }
        testcache_close(tc);
    }
    return ok;
}

static bool tc_fc_stress(const char *const *ptrs,
                         const uint8_t kn[8][32])
{
    struct testcache *tc = testcache_open(TC_FIX);
    bool split = false;
    if (tc) {
        static struct testcache_probe out[8];
        split = testcache_probe_groups(tc, ptrs, NULL, 8, out);
        for (int i = 0; split && i < 8; i++)
            if (!out[i].cacheable ||
                memcmp(kn[i], out[i].key, 32) == 0) split = false;
        testcache_close(tc);
    }
    return split;
}

static int tc_batch_failclosed(void)
{
    int failures = 0;
    static char names[8][64];
    static const char *ptrs[8];
    for (int i = 0; i < 8; i++) {
        tc_qname(i + 1, names[i]);
        ptrs[i] = names[i];
    }
    TC_CHECK("fail-closed fixture writes", write_batch_fixture());
    TC_CHECK("fail-closed verdict store starts empty",
             tc_shell("rm -rf %s/.zvcs", TC_FIX));
    TC_CHECK("leaf touched newer than its depfiles",
             tc_shell("touch %s/core/modules/net/src/tc_leaf.c", TC_FIX));
    TC_CHECK("stale graph fails every slot closed", tc_fc_stale(ptrs));
    TC_CHECK("depfile tree removed (fresh-clone shape)",
             tc_shell("rm -rf %s/build", TC_FIX));
    TC_CHECK("missing graph fails every slot closed", tc_fc_missing(ptrs));
    TC_CHECK("fixture restored for the env split", write_batch_fixture());
    static uint8_t kn[8][32];
    struct tc_envsave st;
    tc_env_capture(&st, "ZCL_STRESS_TESTS");
    /* The non-stress baseline must be captured with the flag absent even
     * when the ambient runner exports ZCL_STRESS_TESTS=1; otherwise the
     * baseline IS the stress key and the split below cannot separate. */
    unsetenv("ZCL_STRESS_TESTS");
    TC_CHECK("non-stress keys captured", tc_fc_nonstress(ptrs, kn));
    setenv("ZCL_STRESS_TESTS", "1", 1);
    TC_CHECK("stress env separates all 8 keys", tc_fc_stress(ptrs, kn));
    tc_env_restore(&st, "ZCL_STRESS_TESTS");
    return failures;
}

/* Acceptance 7: load-flaky PASSes still announce their flake per slot,
 * and an activated proof-contract slot keeps its never-reusable identity
 * without disturbing its neighbours. One helper per step so each stays
 * under the complexity cap; every helper opens its own handle over the
 * same on-disk verdict store. */
static bool tc_sp_activated(const char *const *ptrs,
                            const enum zcl_test_proof_contract *mixed)
{
    struct testcache *tc = testcache_open(TC_FIX);
    bool ok = tc != NULL;
    if (tc) {
        static struct testcache_probe ord[8], out[8];
        ok = testcache_probe_groups(tc, ptrs, NULL, 8, ord) &&
             testcache_probe_groups(tc, ptrs, mixed, 8, out);
        ok = ok && out[0].key_valid && !out[0].cacheable && !out[0].hit &&
             !out[0].hit_flaky &&
             out[0].code == TESTCACHE_R_ACTIVE_PROOF_CONTRACT &&
             memcmp(out[0].key, ord[0].key, 32) != 0;
        testcache_close(tc);
    }
    return ok;
}

static bool tc_sp_neighbours(const char *const *ptrs,
                             const enum zcl_test_proof_contract *mixed)
{
    struct testcache *tc = testcache_open(TC_FIX);
    bool neighbours = tc != NULL;
    if (tc) {
        static struct testcache_probe ord[8], out[8];
        neighbours = testcache_probe_groups(tc, ptrs, NULL, 8, ord) &&
                     testcache_probe_groups(tc, ptrs, mixed, 8, out);
        for (int i = 1; neighbours && i < 8; i++)
            if (!tc_probe_equal(&ord[i], &out[i])) neighbours = false;
        testcache_close(tc);
    }
    return neighbours;
}

static bool tc_sp_flaky(const char *const *ptrs)
{
    struct testcache *tc = testcache_open(TC_FIX);
    bool ok = tc != NULL;
    if (tc) {
        static struct testcache_probe out[8];
        ok = testcache_probe_groups(tc, ptrs, NULL, 8, out);
        for (int i = 1; ok && i < 8; i++) {
            if (!out[i].cacheable) ok = false;
            else testcache_store_pass(tc, out[i].key);
        }
        if (ok) testcache_store_pass_flaky(tc, out[1].key);
        ok = ok && testcache_probe_groups(tc, ptrs, NULL, 8, out);
        ok = ok && out[1].hit && out[1].hit_flaky;
        for (int i = 2; ok && i < 8; i++)
            if (!out[i].hit || out[i].hit_flaky) ok = false;
        testcache_close(tc);
    }
    return ok;
}

static int tc_batch_special(void)
{
    int failures = 0;
    static char names[8][64];
    static const char *ptrs[8];
    for (int i = 0; i < 8; i++) {
        tc_qname(i + 1, names[i]);
        ptrs[i] = names[i];
    }
    TC_CHECK("special fixture writes", write_batch_fixture());
    TC_CHECK("special verdict store starts empty",
             tc_shell("rm -rf %s/.zvcs", TC_FIX));
    static const enum zcl_test_proof_contract mixed[8] = {
        ZCL_TEST_PROOF_STRESS, ZCL_TEST_PROOF_NONE, ZCL_TEST_PROOF_NONE,
        ZCL_TEST_PROOF_NONE, ZCL_TEST_PROOF_NONE, ZCL_TEST_PROOF_NONE,
        ZCL_TEST_PROOF_NONE, ZCL_TEST_PROOF_NONE,
    };
    TC_CHECK("activated slot keeps identity but never reuses",
             tc_sp_activated(ptrs, mixed));
    TC_CHECK("neighbours unaffected by the activated slot",
             tc_sp_neighbours(ptrs, mixed));
    TC_CHECK("flaky verdicts report per slot", tc_sp_flaky(ptrs));
    return failures;
}

/* One receiver store serves an identical second candidate tree, but a real
 * shared-header edit in that tree invalidates all eight observed inputs. */
static bool tc_cross_tree_probe(const char *root, const char *const *names,
                                const uint8_t keys[8][32], bool want_hit)
{
    struct testcache *tc = testcache_open(root);
    bool ok = tc != NULL;
    if (tc) {
        struct testcache_probe out[8];
        ok = testcache_probe_groups(tc, names, NULL, 8, out);
        for (int i = 0; ok && i < 8; i++) {
            bool same = memcmp(keys[i], out[i].key, 32) == 0;
            if (!out[i].cacheable || out[i].hit != want_hit ||
                same != want_hit) ok = false;
        }
        testcache_close(tc);
    }
    return ok;
}

static bool tc_harness_graph_refuses(const char *name)
{
    struct testcache *tc = testcache_open(TC_FIX2);
    bool refused = false;
    if (tc) {
        struct testcache_probe p;
        testcache_probe_group(tc, name, &p);
        refused = !p.key_valid && !p.cacheable && !p.hit &&
                  p.code == TESTCACHE_R_HARNESS_GRAPH;
        testcache_probe_group_proof(tc, name, ZCL_TEST_PROOF_STRESS, &p);
        refused = refused && !p.key_valid && !p.cacheable && !p.hit &&
                  p.code == TESTCACHE_R_HARNESS_GRAPH;
        testcache_close(tc);
    }
    return refused;
}

/* Acceptance 8: keys and stored PASSes survive a handle restart and a
 * second physical tree; only changed actual closure bytes force a miss. */
static int tc_batch_restart_crosstree(void)
{
    int failures = 0;
    char names[8][64];
    const char *ptrs[8];
    for (int i = 0; i < 8; i++) {
        tc_qname(i + 1, names[i]);
        ptrs[i] = names[i];
    }
    TC_CHECK("restart fixture writes", write_batch_fixture());
    struct tc_envsave caller_store;
    tc_env_capture(&caller_store, "ZCL_TESTCACHE_STORE_ROOT");
    TC_CHECK("receiver verdict store starts empty",
             tc_shell("rm -rf %s", TC_STORE) &&
             mkdir(TC_STORE, 0755) == 0 &&
             setenv("ZCL_TESTCACHE_STORE_ROOT", TC_STORE, 1) == 0);
    uint8_t k1[8][32] = {{0}};
    {
        struct testcache *tc = testcache_open(TC_FIX);
        bool ok = tc != NULL;
        if (tc) {
            struct testcache_probe first[8];
            ok = testcache_probe_groups(tc, ptrs, NULL, 8, first);
            for (int i = 0; ok && i < 8; i++) {
                if (!first[i].cacheable || first[i].hit) ok = false;
                else {
                    memcpy(k1[i], first[i].key, 32);
                    testcache_store_pass(tc, first[i].key);
                }
            }
            testcache_close(tc);
        }
        TC_CHECK("first candidate stores eight exact PASS inputs", ok);
    }
    TC_CHECK("restart reuses eight eligible PASSes",
             tc_cross_tree_probe(TC_FIX, ptrs, k1, true));
    TC_CHECK("second physical tree copies the fixture",
             tc_shell("rm -rf %s && cp -pR %s %s && rm -rf %s/.zvcs",
                      TC_FIX2, TC_FIX, TC_FIX2, TC_FIX2));
    TC_CHECK("unchanged second candidate reuses eight PASSes",
             tc_cross_tree_probe(TC_FIX2, ptrs, k1, true));
    TC_CHECK("second candidate edits shared header",
             mk_write(TC_FIX2, "core/modules/net/include/net/tc.h", TC_H_B) &&
             mk_write(TC_FIX2, "build/obj/tc_q01.d",
                      "build/obj/tc_q01.o: core/modules/net/src/tc_q01.c "
                      "core/modules/net/include/net/tc.h "
                      "core/modules/net/include/net/tc_registry.def\n"));
    TC_CHECK("shared dependency invalidates all eight PASSes",
             tc_cross_tree_probe(TC_FIX2, ptrs, k1, false));
    TC_CHECK("second candidate edits common runner source",
             mk_write(TC_FIX2, "core/modules/net/include/net/tc.h", TC_H_A) &&
             mk_write(TC_FIX2, "tests/harness/src/test_parallel.c",
                      TC_RUNNER_B) && write_harness_depfiles(TC_FIX2));
    TC_CHECK("runner edit invalidates all eight PASSes",
             tc_cross_tree_probe(TC_FIX2, ptrs, k1, false));
    TC_CHECK("missing runner depfile is a named refusal",
             tc_shell("rm -f %s/build/obj/test_parallel.d", TC_FIX2) &&
             tc_harness_graph_refuses(ptrs[0]));
    TC_CHECK("second tree removed", tc_shell("rm -rf %s", TC_FIX2));
    tc_env_restore(&caller_store, "ZCL_TESTCACHE_STORE_ROOT");
    return failures;
}

/* The 1/8/32 cost shape: 32 fresh opens (today's per-group-process cost
 * in miniature) against one open serving 1, 8, and 32 groups. Timings are
 * diagnostic — the committed guarantee is the stats shape in
 * tc_batch_stats; ratios are reported, never asserted, so a loaded host
 * cannot flake the suite. */
static int tc_batch_perf(void)
{
    int failures = 0;
    static char names[TC_QN][64];
    static const char *ptrs[TC_QN];
    for (int i = 0; i < TC_QN; i++) {
        tc_qname(i + 1, names[i]);
        ptrs[i] = names[i];
    }
    TC_CHECK("perf fixture writes", write_batch_fixture());
    TC_CHECK("perf verdict store starts empty",
             tc_shell("rm -rf %s/.zvcs", TC_FIX));
    static struct testcache_probe out[TC_QN];
    uint64_t t0 = tc_now_ms();
    for (int i = 0; i < TC_QN; i++) {
        struct testcache *tc = testcache_open(TC_FIX);
        if (tc) testcache_probe_group(tc, names[i], &out[i]);
        if (tc) testcache_close(tc);
    }
    uint64_t indiv_ms = tc_now_ms() - t0;
    uint64_t each_ms[3] = {0, 0, 0};
    size_t each_n[3] = {1, 8, 32};
    bool served = true;
    for (int s = 0; s < 3; s++) {
        struct testcache *tc = testcache_open(TC_FIX);
        t0 = tc_now_ms();
        if (tc)
            served = testcache_probe_groups(tc, ptrs, NULL, each_n[s],
                                            out) && served;
        else
            served = false;
        each_ms[s] += tc_now_ms() - t0;
        if (tc) testcache_close(tc);
    }
    printf("  testcache: batch-perf: individual-32=%llums"
           " batch-1=%llums batch-8=%llums batch-32=%llums\n",
           (unsigned long long)indiv_ms, (unsigned long long)each_ms[0],
           (unsigned long long)each_ms[1], (unsigned long long)each_ms[2]);
    TC_CHECK("batch path serves 1, 8, and 32", served);
    return failures;
}

/* ── Phase PC: the probe capsule ────────────────────────────────────────
 * One proof cycle must pay graph/index setup once: the preflight batch is
 * serialized beside proof scratch (source/candidate identity, toolkey/env
 * digest, dep-graph facts, ordered slots, capsule SHA3) and the test
 * dimension consumes it instead of reopening. The capsule hash is
 * INTEGRITY ONLY — it never addresses a verdict and never gates a skip by
 * itself; every slot still carries its own key/code/cacheable/hit. Each
 * helper returns its own failure count so test_testcache() stays pinned. */
#define TC_CAP tc_path(3)
#define TC_CAP2 tc_path(4)

/* The standard 8-slot set: six ordinary entries, one activated
 * proof-contract slot, one denylisted slot. */
static void tc_cap_ptrs(char names[7][64], const char **ptrs,
                        enum zcl_test_proof_contract *mixed)
{
    for (int i = 0; i < 7; i++) {
        tc_qname(i + 1, names[i]);
        ptrs[i] = names[i];
        mixed[i] = (i == 6) ? ZCL_TEST_PROOF_STRESS : ZCL_TEST_PROOF_NONE;
    }
    ptrs[7] = "test_explorer_index";
    mixed[7] = ZCL_TEST_PROOF_NONE;
}

static void tc_cap_bindings(struct testcache_capsule_bindings *b)
{
    memset(b, 0, sizeof(*b));
    memset(b->source_id, 'a', 64);
    memset(b->mutation_id, 'b', 64);
    memset(b->source_cas, 'c', 64);
    b->source_cas_present = true;
    memset(b->graph_root, 'd', 64);
    b->graph_root_present = true;
}

/* Slot identity minus the free-text reason (the capsule carries codes,
 * not messages; the reader re-derives labels from codes). */
static bool tc_capslot_equal(const struct testcache_probe *a,
                             const struct testcache_probe *b)
{
    return a->key_valid == b->key_valid &&
           a->cacheable == b->cacheable &&
           a->hit == b->hit &&
           a->hit_flaky == b->hit_flaky &&
           a->n_closure == b->n_closure &&
           a->code == b->code &&
           memcmp(a->key, b->key, 32) == 0;
}

static bool tc_read_file(const char *path, uint8_t *buf, size_t cap,
                         size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    size_t n = 0;
    int c;
    if (!f || !buf || !len_out) {
        if (f) fclose(f);
        return false;
    }
    while ((c = fgetc(f)) != EOF) {
        if (n >= cap) {
            fclose(f);
            return false;
        }
        buf[n++] = (uint8_t)c;
    }
    fclose(f);
    *len_out = n;
    return n > 0;
}

static bool tc_write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f || !buf) {
        if (f) fclose(f);
        return false;
    }
    bool ok = fwrite(buf, 1, len, f) == len;
    fclose(f);
    return ok;
}

/* Acceptance: write → consume with identical bindings returns every slot
 * byte-identical (minus reason text), with provenance intact. */
/* Seed the batch fixture, store PASSes, reprobe: the second probe must
 * hit every stored key. */
static int tc_cap_phase_seed(const char **ptrs,
                             const enum zcl_test_proof_contract *mixed,
                             struct testcache_probe *batch)
{
    int failures = 0;
    struct testcache *tc = testcache_open(TC_FIX);
    bool ok = tc != NULL;
    if (tc) {
        ok = testcache_probe_groups(tc, ptrs, mixed, 8, batch);
        for (int i = 0; ok && i < 8; i++)
            if (batch[i].cacheable) testcache_store_pass(tc, batch[i].key);
        ok = ok && testcache_probe_groups(tc, ptrs, mixed, 8, batch);
        testcache_close(tc);
    }
    TC_CHECK("capsule batch hits its stored PASSes",
             ok && batch[0].hit && batch[5].hit);
    return failures;
}

/* Write the capsule from the batch handle under the test bindings. */
static int tc_cap_phase_write(const char **ptrs,
                              const enum zcl_test_proof_contract *mixed,
                              const struct testcache_probe *batch,
                              const struct testcache_capsule_bindings *bind)
{
    int failures = 0;
    struct testcache *tc = testcache_open(TC_FIX);
    bool written = false;
    if (tc) {
        written = testcache_capsule_write(tc, TC_CAP, ptrs, mixed, 8,
                                          batch, bind);
        testcache_close(tc);
    }
    TC_CHECK("capsule writes from the batch handle", written);
    return failures;
}

/* Consume under identical bindings: every slot byte-identical, denylist
 * and proof-contract semantics intact. */
static int tc_cap_phase_verify(const struct testcache_probe *batch,
                               const struct testcache_capsule_bindings *bind)
{
    int failures = 0;
    static struct testcache_capsule_slot slots[8];
    struct testcache_capsule_info info;
    char why[64];
    bool consumed = testcache_capsule_consume(TC_CAP, bind, slots, 8,
                                              &info, why, sizeof(why));
    bool same;
    TC_CHECK("capsule consumes with identical bindings", consumed);
    same = consumed && info.n_slots == 8 && info.dep_count == 38;
    for (int i = 0; same && i < 8; i++)
        if (!tc_capslot_equal(&batch[i], &slots[i].probe)) same = false;
    TC_CHECK("every slot returns byte-identical (34-slot parity shape)",
             same);
    TC_CHECK("denylisted + activated slots survive with semantics",
             consumed && !slots[7].probe.cacheable &&
             slots[7].probe.code == TESTCACHE_R_EXTERNAL_INPUT &&
             slots[6].probe.key_valid &&
             !slots[6].probe.cacheable &&
             slots[6].probe.code ==
                 TESTCACHE_R_ACTIVE_PROOF_CONTRACT);
    return failures;
}

/* A cap that cannot fit the slots refuses, and scratch is removed. */
static int tc_cap_phase_fit(const struct testcache_capsule_bindings *bind)
{
    int failures = 0;
    static struct testcache_capsule_slot slots[8];
    struct testcache_capsule_info info;
    char why[64];
    TC_CHECK("capsule that cannot fit its slots refuses",
             !testcache_capsule_consume(TC_CAP, bind, slots, 4, &info,
                                        why, sizeof(why)));
    TC_CHECK("capsule scratch removed", tc_shell("rm -f %s", TC_CAP));
    return failures;
}

static int tc_capsule_roundtrip(void)
{
    int failures = 0;
    static char names[7][64];
    static const char *ptrs[8];
    static enum zcl_test_proof_contract mixed[8];
    static struct testcache_probe batch[8];
    struct testcache_capsule_bindings bind;
    tc_cap_ptrs(names, ptrs, mixed);
    TC_CHECK("capsule fixture writes", write_batch_fixture());
    TC_CHECK("capsule verdict store starts empty",
             tc_shell("rm -rf %s/.zvcs", TC_FIX));
    failures += tc_cap_phase_seed(ptrs, mixed, batch);
    tc_cap_bindings(&bind);
    failures += tc_cap_phase_write(ptrs, mixed, batch, &bind);
    failures += tc_cap_phase_verify(batch, &bind);
    failures += tc_cap_phase_fit(&bind);
    return failures;
}

/* Acceptance: any corruption — flipped byte (header, bindings, or slot
 * region), truncation, trailing garbage, empty, missing — refuses. A
 * reordered capsule is byte-different, so the SHA3 over ordered slots
 * rejects it the same way the flips below do. */
static int tc_capsule_tamper(void)
{
    int failures = 0;
    static char names[7][64];
    static const char *ptrs[8];
    static enum zcl_test_proof_contract mixed[8];
    tc_cap_ptrs(names, ptrs, mixed);
    TC_CHECK("tamper fixture writes", write_batch_fixture());
    struct testcache_capsule_bindings bind;
    tc_cap_bindings(&bind);
    {
        struct testcache *tc = testcache_open(TC_FIX);
        bool written = false;
        if (tc) {
            static struct testcache_probe batch[8];
            written = testcache_probe_groups(tc, ptrs, mixed, 8, batch) &&
                      testcache_capsule_write(tc, TC_CAP, ptrs, mixed, 8,
                                              batch, &bind);
            testcache_close(tc);
        }
        TC_CHECK("tamper capsule writes", written);
    }
    static uint8_t bytes[1 << 20];
    size_t len = 0;
    TC_CHECK("tamper capsule reads back",
             tc_read_file(TC_CAP, bytes, sizeof(bytes), &len));
    static const size_t flips[] = {10, 60, 0};
    for (size_t f = 0; f < 3; f++) {
        static uint8_t bent[1 << 20];
        static struct testcache_capsule_slot slots[8];
        struct testcache_capsule_info info;
        char why[64];
        size_t at = flips[f] == 0 ? len - 40 : flips[f];
        bool rejected = false;
        if (at < len) {
            memcpy(bent, bytes, len);
            bent[at] ^= 0x01;
            if (tc_write_file(TC_CAP2, bent, len))
                rejected = !testcache_capsule_consume(TC_CAP2, &bind, slots,
                                                       8, &info, why, sizeof(why)) &&
                           why[0] != '\0';
        }
        TC_CHECK("flipped byte refuses with a reason", rejected);
    }
    {
        static struct testcache_capsule_slot slots[8];
        struct testcache_capsule_info info;
        char why[64];
        bool trunc = tc_write_file(TC_CAP2, bytes, len / 2) &&
                     !testcache_capsule_consume(TC_CAP2, &bind, slots, 8,
                                                &info, why, sizeof(why));
        TC_CHECK("truncated capsule refuses", trunc);
        static uint8_t tail[64];
        bool appended = false;
        if (len + sizeof(tail) <= sizeof(bytes)) {
            static uint8_t longer[1 << 20];
            memcpy(longer, bytes, len);
            memset(longer + len, 0x5a, sizeof(tail));
            appended = tc_write_file(TC_CAP2, longer, len + sizeof(tail)) &&
                       !testcache_capsule_consume(TC_CAP2, &bind, slots, 8,
                                                  &info, why, sizeof(why));
        }
        TC_CHECK("appended garbage refuses", appended);
        TC_CHECK("missing capsule refuses",
                 !testcache_capsule_consume("test-tmp/tc_no_capsule.bin",
                                            &bind, slots, 8, &info, why, sizeof(why)));
    }
    TC_CHECK("tamper scratch removed",
             tc_shell("rm -f %s %s", TC_CAP, TC_CAP2));
    return failures;
}

/* Acceptance: the bindings are replay protection. A different
 * source/mutation/cas/graph, or a live env that drifted since the write,
 * refuses — while the same bindings minus the optional CAS still pass. */
static int tc_capsule_bindings(void)
{
    int failures = 0;
    static char names[7][64];
    static const char *ptrs[8];
    static enum zcl_test_proof_contract mixed[8];
    tc_cap_ptrs(names, ptrs, mixed);
    TC_CHECK("bindings fixture writes", write_batch_fixture());
    struct testcache_capsule_bindings bind;
    tc_cap_bindings(&bind);
    /* The baseline capsule must be written with the flag absent even when
     * the ambient runner exports ZCL_STRESS_TESTS=1; otherwise the later
     * set-to-1 drift leg drifts nothing and the consume wrongly accepts. */
    struct tc_envsave cap_st;
    tc_env_capture(&cap_st, "ZCL_STRESS_TESTS");
    unsetenv("ZCL_STRESS_TESTS");
    {
        struct testcache *tc = testcache_open(TC_FIX);
        bool written = false;
        if (tc) {
            static struct testcache_probe batch[8];
            written = testcache_probe_groups(tc, ptrs, mixed, 8, batch) &&
                      testcache_capsule_write(tc, TC_CAP, ptrs, mixed, 8,
                                              batch, &bind);
            testcache_close(tc);
        }
        TC_CHECK("bindings capsule writes", written);
    }
    static struct testcache_capsule_slot slots[8];
    struct testcache_capsule_info info;
    char why[64];
    {
        struct testcache_capsule_bindings drift = bind;
        drift.source_id[0] ^= 0x01;
        TC_CHECK("drifted source id refuses",
                 !testcache_capsule_consume(TC_CAP, &drift, slots, 8, &info,
                                            why, sizeof(why)));
    }
    {
        struct testcache_capsule_bindings drift = bind;
        drift.mutation_id[0] ^= 0x01;
        TC_CHECK("drifted mutation refuses",
                 !testcache_capsule_consume(TC_CAP, &drift, slots, 8, &info,
                                            why, sizeof(why)));
    }
    {
        struct testcache_capsule_bindings drift = bind;
        drift.source_cas[0] ^= 0x01;
        TC_CHECK("drifted source CAS refuses",
                 !testcache_capsule_consume(TC_CAP, &drift, slots, 8, &info,
                                            why, sizeof(why)));
    }
    {
        struct testcache_capsule_bindings drift = bind;
        drift.graph_root[0] ^= 0x01;
        TC_CHECK("drifted graph root refuses",
                 !testcache_capsule_consume(TC_CAP, &drift, slots, 8, &info,
                                            why, sizeof(why)));
    }
    {
        struct testcache_capsule_bindings drift = bind;
        drift.source_cas_present = false;
        TC_CHECK("dropped CAS presence refuses",
                 !testcache_capsule_consume(TC_CAP, &drift, slots, 8, &info,
                                            why, sizeof(why)));
    }
    {
        struct tc_envsave st;
        tc_env_capture(&st, "ZCL_STRESS_TESTS");
        setenv("ZCL_STRESS_TESTS", "1", 1);
        TC_CHECK("live env drift refuses",
                 !testcache_capsule_consume(TC_CAP, &bind, slots, 8, &info,
                                            why, sizeof(why)));
        tc_env_restore(&st, "ZCL_STRESS_TESTS");
    }
    {
        struct testcache_capsule_bindings bare;
        tc_cap_bindings(&bare);
        bare.source_cas_present = false;
        bare.graph_root_present = false;
        struct testcache *tc = testcache_open(TC_FIX);
        bool ok = false;
        if (tc) {
            static struct testcache_probe batch[8];
            ok = testcache_probe_groups(tc, ptrs, mixed, 8, batch) &&
                 testcache_capsule_write(tc, TC_CAP2, ptrs, mixed, 8,
                                         batch, &bare) &&
                 testcache_capsule_consume(TC_CAP2, &bare, slots, 8, &info,
                                           why, sizeof(why));
            testcache_close(tc);
        }
        TC_CHECK("optional bindings absent both sides still pass", ok);
    }
    TC_CHECK("bindings scratch removed",
             tc_shell("rm -f %s %s", TC_CAP, TC_CAP2));
    tc_env_restore(&cap_st, "ZCL_STRESS_TESTS");
    return failures;
}

/* The consumer maps capsule slots onto the selected set by name: exact
 * slots copy through, absent groups run (NO_HANDLE uncacheable), extra
 * slots are ignored, order never matters. */
static int tc_capsule_apply(void)
{
    int failures = 0;
    static char names[3][64];
    static const char *ptrs[3];
    for (int i = 0; i < 3; i++) {
        tc_qname(i + 1, names[i]);
        ptrs[i] = names[i];
    }
    TC_CHECK("apply fixture writes", write_batch_fixture());
    static struct testcache_capsule_slot slots[3];
    {
        struct testcache *tc = testcache_open(TC_FIX);
        bool ok = tc != NULL;
        if (tc) {
            static struct testcache_probe batch[3];
            ok = testcache_probe_groups(tc, ptrs, NULL, 3, batch);
            for (int i = 0; ok && i < 3; i++) {
                snprintf(slots[i].name, sizeof(slots[i].name), "%s",
                         ptrs[i]);
                slots[i].probe = batch[i];
                if (strcmp(slots[i].name, ptrs[i]) != 0) ok = false;
            }
            testcache_close(tc);
        }
        TC_CHECK("apply slots probed", ok);
    }
    {
        static const char *want[2];
        static struct testcache_probe out[2];
        char w0[64], w1[64];
        tc_qname(3, w0);
        tc_qname(1, w1);
        want[0] = w0;
        want[1] = w1;
        testcache_capsule_apply(slots, 3, want, 2, out, TC_FIX);
        TC_CHECK("slots match by name regardless of order",
                 tc_capslot_equal(&slots[2].probe, &out[0]) &&
                 tc_capslot_equal(&slots[0].probe, &out[1]));
    }
    {
        static const char *want[2];
        static struct testcache_probe out[2];
        want[0] = names[0];
        want[1] = names[1];
        testcache_capsule_apply(slots, 3, want, 2, out, TC_FIX);
        TC_CHECK("extra slots ignored",
                 tc_capslot_equal(&slots[0].probe, &out[0]) &&
                 tc_capslot_equal(&slots[1].probe, &out[1]));
    }
    {
        static const char *want[2];
        static struct testcache_probe out[2];
        want[0] = names[0];
        want[1] = "test_demo_q09";
        testcache_capsule_apply(slots, 3, want, 2, out, TC_FIX);
        TC_CHECK("absent group runs instead of trusting",
                 tc_capslot_equal(&slots[0].probe, &out[0]) &&
                 !out[1].cacheable && !out[1].key_valid &&
                 out[1].code == TESTCACHE_R_NO_HANDLE);
    }
    return failures;
}

/* Phase RV: capsule revalidation. A consumed HIT authorizes a skip only
 * while its backing PASS record still verifies (magic/PASS/key-echo, the
 * same check a fresh probe performs). A capsule consumed after its store
 * vanished is structurally valid but must demote every HIT to MISS. */
static int tc_reverify_seed(const char **ptrs, struct testcache_probe *batch)
{
    int failures = 0;
    TC_CHECK("reverify fixture writes", write_batch_fixture());
    TC_CHECK("reverify store starts empty",
             tc_shell("rm -rf %s", TC_STORE) &&
             mkdir(TC_STORE, 0755) == 0 &&
             setenv("ZCL_TESTCACHE_STORE_ROOT", TC_STORE, 1) == 0);
    {
        struct testcache *tc = testcache_open(TC_FIX);
        bool ok = tc != NULL;
        if (tc) {
            int i = 0;
            ok = testcache_probe_groups(tc, ptrs, NULL, 2, batch);
            for (i = 0; ok && i < 2; i++)
                if (batch[i].cacheable) testcache_store_pass(tc, batch[i].key);
            ok = ok && testcache_probe_groups(tc, ptrs, NULL, 2, batch);
            testcache_close(tc);
        }
        TC_CHECK("reverify batch hits its stored PASSes",
                 ok && batch[0].hit && batch[1].hit);
    }
    return failures;
}

static int tc_reverify_backed(const struct testcache_capsule_slot *slots,
                              const char **want)
{
    int failures = 0;
    static struct testcache_probe out[2];
    testcache_capsule_apply(slots, 2, want, 2, out, TC_STORE);
    TC_CHECK("backed HITs still hit",
             out[0].hit && out[1].hit &&
             tc_capslot_equal(&slots[0].probe, &out[0]));
    return failures;
}

static int tc_reverify_unbacked(const struct testcache_capsule_slot *slots,
                                const struct testcache_probe *batch,
                                const char **want)
{
    int failures = 0;
    static struct testcache_probe out[2];
    TC_CHECK("backing store removed",
             tc_shell("rm -rf %s", TC_STORE));
    testcache_capsule_apply(slots, 2, want, 2, out, TC_STORE);
    TC_CHECK("unbacked HITs demote, flags cleared",
             !out[0].hit && !out[1].hit &&
             !out[0].hit_flaky && !out[1].hit_flaky);
    TC_CHECK("demoted slots keep identity, still runnable",
             out[0].cacheable && out[1].cacheable &&
             out[0].key_valid && out[1].key_valid &&
             memcmp(out[0].key, batch[0].key, 32) == 0 &&
             memcmp(out[1].key, batch[1].key, 32) == 0);
    return failures;
}

static int tc_capsule_reverify(void)
{
    int failures = 0;
    static char names[2][64];
    static const char *ptrs[2];
    static struct testcache_probe batch[2];
    static struct testcache_capsule_slot slots[2];
    static const char *want[2];
    for (int i = 0; i < 2; i++) {
        tc_qname(i + 1, names[i]);
        ptrs[i] = names[i];
        want[i] = names[i];
        snprintf(slots[i].name, sizeof(slots[i].name), "%s", ptrs[i]);
    }
    failures += tc_reverify_seed(ptrs, batch);
    for (int i = 0; i < 2; i++)
        slots[i].probe = batch[i];
    failures += tc_reverify_backed(slots, want);
    failures += tc_reverify_unbacked(slots, batch, want);
    unsetenv("ZCL_TESTCACHE_STORE_ROOT");
    return failures;
}

/* Phase LV: live-key revalidation. A consumed HIT keeps its skip only
 * while live bytes reproduce the slot key. Batch fixture seeded, slots
 * minted from the live batch: unchanged inputs keep both HITs; an
 * in-closure edit of exactly one group (depfile mtimes refreshed, so no
 * GRAPH_STALE refusal) demotes that slot to a MISS carrying the NEW live
 * key while the untouched slot still HITs; a NULL handle demotes all. */
static int tc_live_keep_on_unchanged(const struct testcache_capsule_slot *slots,
                                     const char **want)
{
    int failures = 0;
    static struct testcache_probe out[2];
    struct testcache *tc = testcache_open(TC_FIX);
    TC_CHECK("live handle opens", tc != NULL);
    if (tc) {
        testcache_capsule_apply(slots, 2, want, 2, out, TC_STORE);
        testcache_capsule_revalidate(tc, want, out, 2);
        testcache_close(tc);
    }
    TC_CHECK("unchanged inputs keep both HITs",
             out[0].hit && out[1].hit &&
             tc_capslot_equal(&slots[0].probe, &out[0]) &&
             tc_capslot_equal(&slots[1].probe, &out[1]));
    return failures;
}

static int tc_live_demote_null(const struct testcache_capsule_slot *slots,
                               const char **want)
{
    int failures = 0;
    static struct testcache_probe out[2];
    testcache_capsule_apply(slots, 2, want, 2, out, TC_STORE);
    TC_CHECK("backed HITs present before null revalidation",
             out[0].hit && out[1].hit);
    testcache_capsule_revalidate(NULL, want, out, 2);
    TC_CHECK("NULL handle demotes every HIT (fail closed)",
             !out[0].hit && !out[1].hit);
    return failures;
}

static int tc_live_demote_on_edit(const struct testcache_capsule_slot *slots,
                                  const char **want)
{
    int failures = 0;
    static struct testcache_probe out[2];
    static struct testcache_probe expect;
    TC_CHECK("single-group closure edit writes",
             tc_write_q_source(1, " + 1000") && write_batch_depfiles());
    {
        struct testcache *tc = testcache_open(TC_FIX);
        bool edited_miss = false;
        if (tc) {
            testcache_probe_group(tc, want[0], &expect);
            edited_miss = expect.cacheable && !expect.hit &&
                          expect.key_valid &&
                          memcmp(expect.key, slots[0].probe.key, 32) != 0;
            testcache_capsule_apply(slots, 2, want, 2, out, TC_STORE);
            testcache_capsule_revalidate(tc, want, out, 2);
            testcache_close(tc);
        }
        TC_CHECK("edited group demotes to a MISS on the new live key",
                 edited_miss && out[0].cacheable && !out[0].hit &&
                 out[0].key_valid &&
                 memcmp(out[0].key, expect.key, 32) == 0);
        TC_CHECK("untouched group still HITs its slot",
                 out[1].hit && tc_capslot_equal(&slots[1].probe, &out[1]));
    }
    return failures;
}

static int tc_capsule_live_revalidate(void)
{
    int failures = 0;
    static char names[2][64];
    static const char *ptrs[2];
    static struct testcache_probe batch[2];
    static struct testcache_capsule_slot slots[2];
    static const char *want[2];
    for (int i = 0; i < 2; i++) {
        tc_qname(i + 1, names[i]);
        ptrs[i] = names[i];
        want[i] = names[i];
        snprintf(slots[i].name, sizeof(slots[i].name), "%s", ptrs[i]);
    }
    failures += tc_reverify_seed(ptrs, batch);
    for (int i = 0; i < 2; i++)
        slots[i].probe = batch[i];
    failures += tc_live_keep_on_unchanged(slots, want);
    failures += tc_live_demote_null(slots, want);
    failures += tc_live_demote_on_edit(slots, want);
    unsetenv("ZCL_TESTCACHE_STORE_ROOT");
    return failures;
}

static int tc_non_test_controls_stable(void)
{
    int failures = 0;
    const char *const controls[] = { "ZCL_LINT_TU_CACHE" };
    for (size_t i = 0; i < sizeof(controls) / sizeof(controls[0]); i++) {
        struct tc_envsave caller;
        uint8_t keys[2][32] = {{0}};
        bool valid[2] = {false, false};
        tc_env_capture(&caller, controls[i]);
        for (size_t value = 0; value < 2; value++) {
            TC_CHECK("set non-test control",
                     setenv(controls[i], value ? "1" : "0", 1) == 0);
            struct testcache *tc = testcache_open(TC_FIX);
            TC_CHECK("non-test control fixture opens", tc != NULL);
            if (tc) {
                struct testcache_probe p;
                testcache_probe_group(tc, "test_demo_entry", &p);
                valid[value] = p.cacheable && p.key_valid;
                memcpy(keys[value], p.key, 32);
                testcache_close(tc);
            }
        }
        TC_CHECK("non-test control does not globally bust closure keys",
                 valid[0] && valid[1] &&
                 memcmp(keys[0], keys[1], 32) == 0);
        tc_env_restore(&caller, controls[i]);
    }
    return failures;
}

static int tc_missing_graph_activated(struct testcache *tc)
{
    int failures = 0;
    struct testcache_probe p;
    testcache_probe_group_proof(tc, "test_demo_entry",
                               ZCL_TEST_PROOF_STRESS, &p);
    TC_CHECK("activated proof with missing graph has no reusable key",
             !p.key_valid && !p.cacheable && !p.hit &&
             p.code == TESTCACHE_R_NO_INCLUDE_GRAPH);
    return failures;
}

static int tc_observation_forged(const uint8_t key[32], const uint8_t pass[32])
{
    int failures = 0;
    char why[96];
    size_t ineligible = 0;
    uint8_t forged[32], roots[2][32];
    struct zcl_dev_verdict_leaf_v1 bad = {0};
    memcpy(bad.key, key, 32);
    memcpy(bad.group, "test_demo_entry", sizeof("test_demo_entry"));
    bad.group_len = sizeof("test_demo_entry") - 1;
    bad.verdict = ZCL_DEV_VERDICT_LEAF_FAIL;
    bad.observed_unix = (uint64_t)time(NULL);
    bad.log_seq = 1;
    bool forged_ok = zcl_dev_verdict_leaf_sign(&bad, why, sizeof(why));
    bad.signature[0] ^= 1u;
    forged_ok = forged_ok && zcl_dev_verdict_leaf_root(&bad, forged,
        why, sizeof(why));
    uint8_t wire[ZCL_DEV_VERDICT_LEAF_WIRE_BYTES];
    forged_ok = forged_ok && zcl_dev_verdict_leaf_serialize(&bad,
        wire, why, sizeof(why)) &&
        vcs_object_put_addressed(TC_FIX, forged, wire, sizeof(wire));
    TC_CHECK("forged signed-wire fixture persists separately", forged_ok);
    if (forged_ok) {
        memcpy(roots[0], pass, 32);
        memcpy(roots[1], forged, 32);
        TC_CHECK("forged FAIL has no veto authority",
            zcl_dev_observation_admit(TC_FIX, key, "test_demo_entry",
                (const uint8_t (*)[32])roots, 2, &ineligible,
                why, sizeof(why)) == ZCL_DEV_OBSERVATION_PASS &&
                ineligible == 1);
        TC_CHECK("receiver-known forged FAIL has no veto authority",
            zcl_dev_observation_admit_known(TC_FIX, key, "test_demo_entry",
                (const uint8_t (*)[32])pass, 1,
                (const uint8_t (*)[32])forged, 1, &ineligible,
                why, sizeof(why)) == ZCL_DEV_OBSERVATION_PASS &&
                ineligible == 1);
    }
    return failures;
}

static int tc_observation_conflict(const uint8_t key[32], const uint8_t pass[32])
{
    int failures = 0;
    char why[96];
    size_t ineligible = 0;
    uint8_t fail[32], roots[2][32], absent[32] = {0};
    memcpy(roots[0], pass, 32);
    bool made_fail = zcl_dev_observation_record(TC_FIX, key,
        "test_demo_entry", ZCL_DEV_VERDICT_LEAF_FAIL, 19,
        fail, why, sizeof(why));
    TC_CHECK("real FAIL has a distinct durable root", made_fail &&
             memcmp(pass, fail, 32) != 0);
    if (made_fail) {
        memcpy(roots[1], fail, 32);
        TC_CHECK("eligible PASS and FAIL coexist and refuse",
            zcl_dev_observation_admit(TC_FIX, key, "test_demo_entry",
                (const uint8_t (*)[32])roots, 2, &ineligible,
                why, sizeof(why)) == ZCL_DEV_OBSERVATION_CONFLICT &&
                strcmp(why, "proof_observation_conflict") == 0);
        TC_CHECK("omitted receiver-known FAIL still refuses",
            zcl_dev_observation_admit_known(TC_FIX, key, "test_demo_entry",
                (const uint8_t (*)[32])pass, 1,
                (const uint8_t (*)[32])fail, 1, &ineligible,
                why, sizeof(why)) == ZCL_DEV_OBSERVATION_CONFLICT &&
                strcmp(why, "proof_observation_conflict") == 0);
    }
    memcpy(roots[1], absent, 32);
    TC_CHECK("missing required root refuses even beside PASS",
        zcl_dev_observation_admit(TC_FIX, key, "test_demo_entry",
            (const uint8_t (*)[32])roots, 2, &ineligible,
            why, sizeof(why)) == ZCL_DEV_OBSERVATION_MISSING &&
            strcmp(why, "observation_object_missing") == 0);
    uint8_t other_key[32];
    memcpy(other_key, key, 32);
    other_key[0] ^= 1u;
    TC_CHECK("changed input cannot reuse prior signed PASS",
        zcl_dev_observation_admit(TC_FIX, other_key, "test_demo_entry",
            (const uint8_t (*)[32])roots, 1, &ineligible,
            why, sizeof(why)) == ZCL_DEV_OBSERVATION_MISSING &&
            ineligible == 1);
    return failures;
}

static int tc_observation_cross_tree(const uint8_t key[32], const uint8_t pass[32])
{
    int failures = 0;
    char why[96];
    size_t ineligible = 0;
    struct testcache_probe p = {0};
    TC_CHECK("signed observation second candidate tree prepared",
        tc_shell("rm -rf %s && cp -r %s %s && rm -rf %s/.zvcs %s/signing-state",
                 TC_FIX2, TC_FIX, TC_FIX2, TC_FIX2, TC_FIX2));
    struct testcache *tc = testcache_open(TC_FIX2);
    if (tc) {
        testcache_probe_group(tc, "test_demo_entry", &p);
        testcache_close(tc);
    }
    TC_CHECK("unchanged second candidate admits signed PASS",
        p.key_valid && memcmp(p.key, key, 32) == 0 &&
        zcl_dev_observation_admit(TC_FIX, p.key, "test_demo_entry",
            (const uint8_t (*)[32])pass, 1, &ineligible,
            why, sizeof(why)) == ZCL_DEV_OBSERVATION_PASS);
    bool edited = mk_write(TC_FIX2, "core/modules/net/include/net/tc.h", TC_H_B) &&
        mk_write(TC_FIX2, "build/obj/tc_top.d",
            "build/obj/tc_top.o: core/modules/net/src/tc_top.c "
            "core/modules/net/include/net/tc.h "
            "core/modules/net/include/net/tc_registry.def\n") &&
        mk_write(TC_FIX2, "build/obj/tc_mid.d",
            "build/obj/tc_mid.o: core/modules/net/src/tc_mid.c "
            "core/modules/net/include/net/tc.h\n") &&
        mk_write(TC_FIX2, "build/obj/tc_leaf.d",
            "build/obj/tc_leaf.o: core/modules/net/src/tc_leaf.c "
            "core/modules/net/include/net/tc.h\n") &&
        mk_write(TC_FIX2, "build/obj/tc_other.d",
            "build/obj/tc_other.o: core/modules/net/src/tc_other.c "
            "core/modules/net/include/net/tc.h\n");
    TC_CHECK("second candidate shared header changes", edited);
    memset(&p, 0, sizeof(p));
    tc = edited ? testcache_open(TC_FIX2) : NULL;
    if (tc) {
        testcache_probe_group(tc, "test_demo_entry", &p);
        testcache_close(tc);
    }
    TC_CHECK("changed shared input refuses signed PASS reuse",
        p.key_valid && memcmp(p.key, key, 32) != 0 &&
        zcl_dev_observation_admit(TC_FIX, p.key, "test_demo_entry",
            (const uint8_t (*)[32])pass, 1, &ineligible,
            why, sizeof(why)) == ZCL_DEV_OBSERVATION_MISSING &&
        ineligible == 1);
    TC_CHECK("signed observation second tree removed",
             tc_shell("rm -rf %s", TC_FIX2));
    return failures;
}

static int tc_observation_roundtrip(void)
{
    int failures = 0;
    struct tc_envsave saved;
    char state[4096], why[96];
    tc_env_capture(&saved, "XDG_STATE_HOME");
    bool ready = getcwd(state, sizeof(state)) != NULL;
    if (ready) {
        size_t used = strlen(state);
        int n = snprintf(state + used, sizeof(state) - used,
                         "/%s/signing-state", TC_FIX);
        ready = n > 0 && (size_t)n < sizeof(state) - used;
    }
    ready = ready && write_fixture(TC_LEAF_A, TC_OTHER_A, TC_H_A) &&
            mkdir(state, 0700) == 0 &&
            setenv("XDG_STATE_HOME", state, 1) == 0;
    TC_CHECK("observation fixture and private signer state ready", ready);
    struct testcache_probe p = {0};
    struct testcache *tc = ready ? testcache_open(TC_FIX) : NULL;
    if (tc) {
        testcache_probe_group(tc, "test_demo_entry", &p);
        testcache_close(tc);
    }
    TC_CHECK("observation starts with a complete actual input key",
             p.key_valid && p.cacheable);
    if (p.key_valid) {
        uint8_t pass[32];
        size_t ineligible = 0;
        bool made_pass = zcl_dev_observation_record(TC_FIX, p.key,
            "test_demo_entry", ZCL_DEV_VERDICT_LEAF_PASS, 17,
            pass, why, sizeof(why));
        TC_CHECK("fresh runner PASS is signed and stored by observation root",
                 made_pass);
        if (made_pass) {
            uint8_t roots[1][32];
            memcpy(roots[0], pass, 32);
            TC_CHECK("one eligible PASS admits its exact input",
                zcl_dev_observation_admit(TC_FIX, p.key, "test_demo_entry",
                    (const uint8_t (*)[32])roots, 1, &ineligible,
                    why, sizeof(why)) == ZCL_DEV_OBSERVATION_PASS &&
                ineligible == 0);
            failures += tc_observation_cross_tree(p.key, pass);
            failures += tc_observation_forged(p.key, pass);
            failures += tc_observation_conflict(p.key, pass);
        }
    }
    tc_env_restore(&saved, "XDG_STATE_HOME");
    return failures;
}

static int tc_unadmissible_group(struct testcache *tc)
{
    int failures = 0;
    char long_name[160];
    memset(long_name, 'a', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = 0;
    struct testcache_probe p;
    testcache_probe_group(tc, long_name, &p);
    TC_CHECK("group too long for signed leaf has no reusable key",
             !p.key_valid && !p.cacheable && !p.hit &&
             p.code == TESTCACHE_R_GROUP_UNADMISSIBLE);
    testcache_probe_group(tc, "test_acme_worker", &p);
    TC_CHECK("external ACME worker requires independent execution",
             !p.key_valid && !p.cacheable && !p.hit &&
             p.code == TESTCACHE_R_EXTERNAL_INPUT);
    return failures;
}

static bool tc_acme_and_agent_policy(void)
{
    return file_contains("tests/harness/src/test_acme_worker.c",
                         "build/bin/zclassic23-acme") &&
           testcache_group_is_denylisted("test_acme_worker") &&
           testcache_group_is_denylisted("test_agent_copy_prove");
}

int test_testcache(void)
{
    int failures = 0;
    struct tc_envsave caller_store;
    tc_env_capture(&caller_store, "ZCL_TESTCACHE_STORE_ROOT");
    unsetenv("ZCL_TESTCACHE_STORE_ROOT");
    (void)tc_shell("rm -rf %s %s %s %s %s", TC_FIX, TC_STORE,
                   TC_FIX2, TC_CAP, TC_CAP2);

    /* ── Phase A: cacheable, miss, store, hit ── */
    uint8_t keyA[32];
    bool have_keyA = false;
    TC_CHECK("fixture writes", write_fixture(TC_LEAF_A, TC_OTHER_A, TC_H_A));
    {
        struct testcache *tc = testcache_open(TC_FIX);
        TC_CHECK("testcache_open succeeds", tc != NULL);
        if (tc) {
            failures += tc_unadmissible_group(tc);
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("entry is cacheable", p.cacheable);
            TC_CHECK("closure is the 5 reachable files "
                     "(top,mid,leaf,header,registry.def)",
                     p.n_closure == 5);
            TC_CHECK("fresh key is a MISS", p.cacheable && !p.hit);
            if (p.cacheable) { memcpy(keyA, p.key, 32); have_keyA = true; }

            testcache_store_pass(tc, p.key);

            struct testcache_probe p2;
            testcache_probe_group(tc, "test_demo_entry", &p2);
            TC_CHECK("same key HITS after store_pass", p2.cacheable && p2.hit);
            TC_CHECK("key is stable across identical probes",
                     have_keyA && memcmp(keyA, p2.key, 32) == 0);
            testcache_close(tc);
        }
    }

    /* Activated execution has its own identity but must run even when a PASS
     * exists at that identity. Exercise the real closure and object store. */
    {
        struct testcache *tc = testcache_open(TC_FIX);
        TC_CHECK("policy fixture cache opens", tc != NULL);
        if (tc) {
            struct testcache_probe ordinary, none, active[4], again, bad;
            testcache_probe_group(tc, "test_demo_entry", &ordinary);
            testcache_probe_group_proof(tc, "test_demo_entry",
                                       ZCL_TEST_PROOF_NONE, &none);
            TC_CHECK("NONE preserves ordinary key and stored hit",
                     ordinary.key_valid && none.key_valid && none.cacheable &&
                     none.hit && memcmp(ordinary.key, none.key, 32) == 0);
            const enum zcl_test_proof_contract modes[] = {
                ZCL_TEST_PROOF_STRESS, ZCL_TEST_PROOF_EVENT_LOG_KILL9,
                ZCL_TEST_PROOF_EVENT_LOG_BENCH, ZCL_TEST_PROOF_GOLDEN_TIMING,
            };
            const char *const names[] = {
                "ZCL_STRESS_TESTS", "ZCL_EVENT_LOG_KILL9_FUZZ",
                "ZCL_EVENT_LOG_BENCH_PROOF", "ZCL_GOLDEN_TIMING_STRICT",
            };
            for (size_t i = 0; i < 4; i++) {
                const char *name = NULL, *value = NULL;
                TC_CHECK("contract resolves exact child assignment",
                         zcl_test_proof_contract_environment(modes[i],
                                                            &name, &value) &&
                         name && value && strcmp(name, names[i]) == 0 &&
                         strcmp(value, "1") == 0);
                testcache_probe_group_proof(tc, "test_demo_entry", modes[i],
                                           &active[i]);
                TC_CHECK("activated bounded closure has identity but no reuse",
                         active[i].key_valid && !active[i].cacheable &&
                         !active[i].hit && !active[i].hit_flaky &&
                         active[i].n_closure == 5 &&
                         active[i].code == TESTCACHE_R_ACTIVE_PROOF_CONTRACT);
                TC_CHECK("activated identity differs from ordinary identity",
                         memcmp(active[i].key, ordinary.key, 32) != 0);
                for (size_t j = 0; j < i; j++)
                    TC_CHECK("different execution contracts never alias",
                             memcmp(active[i].key, active[j].key, 32) != 0);
                /* Deliberately inject a forbidden PASS through the low-level
                 * store: neither ordinary nor flaky records may skip proof. */
                testcache_store_pass_flaky(tc, active[i].key);
                testcache_probe_group_proof(tc, "test_demo_entry", modes[i],
                                           &again);
                TC_CHECK("poisoned active PASS cannot suppress fresh execution",
                         again.key_valid && !again.cacheable && !again.hit &&
                         !again.hit_flaky &&
                         memcmp(again.key, active[i].key, 32) == 0);
            }
            testcache_probe_group_proof(tc, "test_demo_entry",
                                       (enum zcl_test_proof_contract)255, &bad);
            TC_CHECK("unknown execution policy refuses identity and reuse",
                     !bad.key_valid && !bad.cacheable && !bad.hit &&
                     bad.code == TESTCACHE_R_PROOF_CONTRACT_INVALID);
            testcache_probe_group_proof(tc, "test_explorer_index",
                                       ZCL_TEST_PROOF_STRESS, &bad);
            TC_CHECK("activation cannot qualify external-input closure",
                     !bad.key_valid && !bad.cacheable && !bad.hit &&
                     bad.code == TESTCACHE_R_EXTERNAL_INPUT);
            testcache_probe_group_proof(tc, "test_no_such_symbol_zzz",
                                       ZCL_TEST_PROOF_STRESS, &bad);
            TC_CHECK("activation cannot qualify unresolved closure",
                     !bad.key_valid && !bad.cacheable && !bad.hit &&
                     bad.code == TESTCACHE_R_ENTRY_UNRESOLVED);
            testcache_close(tc);
        }
    }

    /* ── Phase A2: receipt storage is independent from source inspection ── */
    TC_CHECK("separate verdict store starts empty",
             tc_shell("rm -rf %s", TC_STORE) &&
             mkdir(TC_STORE, 0755) == 0 &&
             setenv("ZCL_TESTCACHE_STORE_ROOT", TC_STORE, 1) == 0);
    {
        struct testcache *tc = testcache_open(TC_FIX);
        TC_CHECK("cache opens with a separate verdict store", tc != NULL);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("separate store does not borrow the source-local PASS",
                     p.cacheable && !p.hit && have_keyA &&
                     memcmp(keyA, p.key, sizeof(keyA)) == 0);
            if (p.cacheable) testcache_store_pass(tc, p.key);
            testcache_close(tc);
        }
    }
    {
        struct testcache *tc = testcache_open(TC_FIX);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("separate verdict store persists its exact PASS",
                     p.cacheable && p.hit);
            testcache_close(tc);
        }
    }
    unsetenv("ZCL_TESTCACHE_STORE_ROOT");

    /* ── Phase A3: load-flaky PASS — the rerun-alone policy's cache contract.
     * test_parallel.c's rerun_load_flaky_groups gives a FAIL/WEDGED group one
     * alone rerun before it counts; when that rerun passes, the group is a
     * real PASS but must never look like an ORDINARY one on a later cache
     * hit — a cached hit must still say "this flaked once". Exercised here
     * directly against testcache (the module under test), not by forking a
     * whole suite: a flaky store sets hit_flaky, an ordinary store leaves it
     * clear, and storing over a flaky key with an ordinary PASS clears the
     * flag (a later genuine uncontended pass is not stuck flaky forever). */
    TC_CHECK("flaky-phase store starts empty",
             tc_shell("rm -rf %s", TC_STORE) &&
             mkdir(TC_STORE, 0755) == 0 &&
             setenv("ZCL_TESTCACHE_STORE_ROOT", TC_STORE, 1) == 0);
    {
        struct testcache *tc = testcache_open(TC_FIX);
        TC_CHECK("cache opens for the flaky-store phase", tc != NULL);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("flaky-phase key is cacheable", p.cacheable);
            testcache_store_pass_flaky(tc, p.key);

            struct testcache_probe p2;
            testcache_probe_group(tc, "test_demo_entry", &p2);
            TC_CHECK("a flaky-stored PASS still HITS", p2.cacheable && p2.hit);
            TC_CHECK("a flaky-stored PASS reports hit_flaky on probe",
                     p2.hit_flaky);

            /* An ordinary store_pass at the SAME key (a later, genuinely
             * uncontended run) must clear the flag — the flake is not a
             * permanent property of the key, only of the run that minted it. */
            testcache_store_pass(tc, p.key);
            struct testcache_probe p3;
            testcache_probe_group(tc, "test_demo_entry", &p3);
            TC_CHECK("an ordinary store over a flaky key clears hit_flaky",
                     p3.cacheable && p3.hit && !p3.hit_flaky);
            testcache_close(tc);
        }
    }
    unsetenv("ZCL_TESTCACHE_STORE_ROOT");

    /* ── Phase B: SOUNDNESS — edit a CLOSURE-MEMBER body => key changes, miss ── */
    TC_CHECK("rewrite leaf body", write_fixture(TC_LEAF_B, TC_OTHER_A, TC_H_A));
    {
        struct testcache *tc = testcache_open(TC_FIX);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("still cacheable after leaf edit", p.cacheable);
            TC_CHECK("leaf-body edit changes the key",
                     p.cacheable && have_keyA && memcmp(keyA, p.key, 32) != 0);
            TC_CHECK("edited-closure key MISSES the old stored PASS",
                     p.cacheable && !p.hit);
            testcache_close(tc);
        }
    }

    /* ── Phase C: SELECTIVITY — restore leaf, edit an OUT-OF-closure file ──
     * key returns to keyA and the earlier stored PASS still hits (persisted). */
    TC_CHECK("restore leaf, edit unrelated tc_other",
             write_fixture(TC_LEAF_A, TC_OTHER_B, TC_H_A));
    {
        struct testcache *tc = testcache_open(TC_FIX);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("unrelated edit leaves the key unchanged",
                     p.cacheable && have_keyA && memcmp(keyA, p.key, 32) == 0);
            TC_CHECK("unchanged key still HITS across reopen (persisted PASS)",
                     p.cacheable && p.hit);
            testcache_close(tc);
        }
    }

    /* ── Phase C2: resident snapshot mode never rebuilds or trusts an edit ──
     * The verified index still describes Phase C. An in-closure edit must run
     * fresh; an out-of-closure edit may reuse the exact stored PASS. */
    TC_CHECK("snapshot fixture edits reachable leaf without refreshing graph",
             mk_write(TC_FIX, "core/modules/net/src/tc_leaf.c", TC_LEAF_B));
    {
        const char *changed[] = {"core/modules/net/src/tc_leaf.c"};
        struct testcache *tc = testcache_open_snapshot(TC_FIX, changed, 1);
        TC_CHECK("snapshot cache opens existing verified index", tc != NULL);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("snapshot closure reaching edit is uncacheable",
                     !p.cacheable &&
                     p.code == TESTCACHE_R_CHANGED_INPUT);
            testcache_probe_group_proof(tc, "test_demo_entry",
                                       ZCL_TEST_PROOF_STRESS, &p);
            TC_CHECK("activated snapshot cannot identify an edited closure",
                     !p.key_valid && !p.cacheable && !p.hit &&
                     p.code == TESTCACHE_R_CHANGED_INPUT);
            testcache_close(tc);
        }
    }
    TC_CHECK("snapshot fixture restores closure and edits unrelated source",
             write_fixture(TC_LEAF_A, TC_OTHER_A, TC_H_A));
    {
        const char *changed[] = {"core/modules/net/src/tc_other.c"};
        struct testcache *tc = testcache_open_snapshot(TC_FIX, changed, 1);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("snapshot excludes unrelated edit and reuses exact PASS",
                     p.cacheable && p.hit && have_keyA &&
                     memcmp(keyA, p.key, 32) == 0);
            testcache_close(tc);
        }
    }

    /* ── Phase D: UNCACHEABLE cases ── */
    {
        struct testcache *tc = testcache_open(TC_FIX);
        if (tc) {
            struct testcache_probe pd;
            testcache_probe_group(tc, "test_explorer_index", &pd);
            TC_CHECK("external-input denylisted group is uncacheable",
                     !pd.cacheable);

            struct testcache_probe pu;
            testcache_probe_group(tc, "test_no_such_symbol_zzz", &pu);
            TC_CHECK("unresolved entry symbol is uncacheable", !pu.cacheable);
            testcache_close(tc);
        }
    }

    /* ── Phase E: header edit (an included file) also changes the key ── */
    TC_CHECK("edit included header", write_fixture(TC_LEAF_A, TC_OTHER_A, TC_H_B));
    {
        struct testcache *tc = testcache_open(TC_FIX);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("included-header edit changes the key",
                     p.cacheable && have_keyA && memcmp(keyA, p.key, 32) != 0);
            testcache_close(tc);
        }
    }

    /* ── Phase F: a *.def registry edit MOVES the key ──────────────────────
     * The include graph is built from the compiler's depfiles, and the depfile
     * lists tc_registry.def as a prerequisite of tc_top.c. Filtering
     * prerequisites by a .h/.hpp/.hh extension allowlist dropped every *.def
     * from the graph, so editing an X-macro registry — the command catalog, the
     * condition registry, the sync-kernel catalog — changed a group's behavior
     * and busted NO cache key, and was not flagged truncated either. */
    TC_CHECK("restore pristine fixture", write_fixture(TC_LEAF_A, TC_OTHER_A,
                                                       TC_H_A));
    uint8_t key_defA[32];
    bool have_defA = false;
    {
        struct testcache *tc = testcache_open(TC_FIX);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("registry .def is IN the closure (5 files)",
                     p.cacheable && p.n_closure == 5);
            if (p.cacheable) { memcpy(key_defA, p.key, 32); have_defA = true; }
            testcache_close(tc);
        }
    }
    TC_CHECK("edit the .def registry (add a row)",
             write_fixture_full(TC_LEAF_A, TC_OTHER_A, TC_H_A, TC_DEF_B));
    {
        struct testcache *tc = testcache_open(TC_FIX);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("a .def registry edit CHANGES the key",
                     p.cacheable && have_defA &&
                     memcmp(key_defA, p.key, 32) != 0);
            testcache_close(tc);
        }
    }

    /* ── Phase G: an absent include graph is UNCACHEABLE, not header-free ──
     * With no depfiles under build/, codeindex produces zero include edges. That
     * is not a smaller-but-complete closure — it is NO closure, and it was never
     * reported truncated, so on a fresh clone or after `make clean` every key
     * silently covered zero headers and a stale PASS could be served. */
    TC_CHECK("restore pristine fixture", write_fixture(TC_LEAF_A, TC_OTHER_A,
                                                       TC_H_A));
    TC_CHECK("remove every depfile (simulate a fresh/cleaned tree)",
             tc_shell("rm -rf %s/build", TC_FIX));
    {
        struct testcache *tc = testcache_open(TC_FIX);
        if (tc) {
            TC_CHECK("depfile count is zero", testcache_depfile_count(tc) == 0);
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("absent include graph => UNCACHEABLE (not a header-free key)",
                     !p.cacheable);
            TC_CHECK("and it says so with a stable reason code",
                     p.code == TESTCACHE_R_NO_INCLUDE_GRAPH);
            failures += tc_missing_graph_activated(tc);
            testcache_close(tc);
        }
    }

    /* ── Phase H: coverage-gating env is IN the key ────────────────────────
     * ~16 groups `return 0` from a `SKIP (set ZCL_STRESS_TESTS=1 ...)` path, so
     * their source bytes are identical whether the stress lane ran or not.
     * Without the environment in the key, a normal run stored a PASS for the
     * SKIPPING variant and a later ZCL_STRESS_TESTS=1 run got a HIT and never
     * executed the stress lane at all — a confirmed false green. */
    TC_CHECK("restore pristine fixture", write_fixture(TC_LEAF_A, TC_OTHER_A,
                                                       TC_H_A));
    /* The caller's ZCL_STRESS_TESTS is captured before anything moves it and
     * put back at the end of this phase. To keep that restore load-bearing no
     * matter what the ambient environment happens to be, the phase installs its
     * own sentinel as the value it must come back to — so the assertion below
     * fails if the restore degrades to an unconditional unsetenv, whether or
     * not the real caller had the variable set. */
    struct tc_envsave caller_stress, phase_stress;
    tc_env_capture(&caller_stress, "ZCL_STRESS_TESTS");
    setenv("ZCL_STRESS_TESTS", "tc-phase-h-sentinel", 1);
    tc_env_capture(&phase_stress, "ZCL_STRESS_TESTS");

    /* Drop every verdict the earlier phases stored. They ran under the
     * CALLER's ZCL_STRESS_TESTS, so when the suite itself is invoked with
     * ZCL_STRESS_TESTS=1 their keys are exactly the stress key this phase is
     * about to probe, and the "MISSES the non-stress PASS" assertion HITS one
     * of their records instead of missing. Restoring the pristine fixture
     * rewrites the sources but not the CAS, so the records outlive it. This
     * phase is the one place that needs an empty verdict store rather than an
     * empty source tree, and clearing it is what makes the assertion mean the
     * same thing under `make t-fast` and under ZCL_STRESS_TESTS=1. */
    TC_CHECK("clear verdicts stored by earlier phases",
             tc_shell("rm -rf %s/.zvcs/objects", TC_FIX));

    uint8_t key_nostress[32];
    bool have_nostress = false;
    unsetenv("ZCL_STRESS_TESTS");
    {
        struct testcache *tc = testcache_open(TC_FIX);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("cacheable with ZCL_STRESS_TESTS unset", p.cacheable);
            if (p.cacheable) {
                memcpy(key_nostress, p.key, 32);
                have_nostress = true;
                testcache_store_pass(tc, p.key);
            }
            testcache_close(tc);
        }
    }
    setenv("ZCL_STRESS_TESTS", "1", 1);
    {
        struct testcache *tc = testcache_open(TC_FIX);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("ZCL_STRESS_TESTS=1 changes the key",
                     p.cacheable && have_nostress &&
                     memcmp(key_nostress, p.key, 32) != 0);
            TC_CHECK("so the stress run MISSES the non-stress PASS and re-runs",
                     p.cacheable && !p.hit);
            testcache_close(tc);
        }
    }
    tc_env_restore(&phase_stress, "ZCL_STRESS_TESTS");
    {
        const char *back = getenv("ZCL_STRESS_TESTS");
        TC_CHECK("phase H puts the caller's ZCL_STRESS_TESTS back",
                 back && strcmp(back, "tc-phase-h-sentinel") == 0);
    }
    tc_env_restore(&caller_stress, "ZCL_STRESS_TESTS");

    /* Inherited flags still affect ordinary execution. The activated-key
     * extension must not remove any flag from the existing parent digest. */
    const char *const proof_flags[] = {
        "ZCL_STRESS_TESTS", "ZCL_EVENT_LOG_KILL9_FUZZ",
        "ZCL_EVENT_LOG_BENCH_PROOF", "ZCL_GOLDEN_TIMING_STRICT",
    };
    for (size_t i = 0; i < 4; i++) {
        struct tc_envsave caller_flag;
        tc_env_capture(&caller_flag, proof_flags[i]);
        TC_CHECK("clear inherited proof flag", unsetenv(proof_flags[i]) == 0);
        uint8_t unset_key[32] = {0};
        bool unset_valid = false;
        struct testcache *tc = testcache_open(TC_FIX);
        TC_CHECK("inherited flag fixture opens", tc != NULL);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            unset_valid = p.key_valid;
            memcpy(unset_key, p.key, sizeof(unset_key));
            testcache_close(tc);
        }
        const char *const values[] = {"0", "1", "2"};
        uint8_t value_keys[3][32] = {{0}};
        for (size_t v = 0; v < 3; v++) {
            TC_CHECK("set inherited proof flag",
                     setenv(proof_flags[i], values[v], 1) == 0);
            tc = testcache_open(TC_FIX);
            TC_CHECK("inherited value fixture opens", tc != NULL);
            if (tc) {
                struct testcache_probe p;
                testcache_probe_group(tc, "test_demo_entry", &p);
                TC_CHECK("inherited flag differs from unset ordinary key",
                         unset_valid && p.key_valid && p.cacheable &&
                         memcmp(unset_key, p.key, 32) != 0);
                memcpy(value_keys[v], p.key, 32);
                for (size_t earlier = 0; earlier < v; earlier++)
                    TC_CHECK("inherited values remain distinct",
                             memcmp(value_keys[earlier], p.key, 32) != 0);
                testcache_close(tc);
            }
        }
        tc_env_restore(&caller_flag, proof_flags[i]);
    }

    /* Fast-CI's frozen source record is orchestration identity, not test
     * behavior. Hashing it globally defeats the closure key: even a docs-only
     * rebase changes the record and invalidates every unrelated group. */
    struct tc_envsave caller_fast_record;
    uint8_t key_fast_a[32], key_fast_b[32];
    bool have_fast_a = false, have_fast_b = false;
    tc_env_capture(&caller_fast_record, "ZCL_FAST_BUILD_SOURCE_RECORD");
    setenv("ZCL_FAST_BUILD_SOURCE_RECORD", "source-a mutation-a", 1);
    {
        struct testcache *tc = testcache_open(TC_FIX);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            if (p.cacheable) {
                memcpy(key_fast_a, p.key, sizeof(key_fast_a));
                have_fast_a = true;
            }
            testcache_close(tc);
        }
    }
    setenv("ZCL_FAST_BUILD_SOURCE_RECORD", "source-b mutation-b", 1);
    {
        struct testcache *tc = testcache_open(TC_FIX);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            if (p.cacheable) {
                memcpy(key_fast_b, p.key, sizeof(key_fast_b));
                have_fast_b = true;
            }
            testcache_close(tc);
        }
    }
    TC_CHECK("fast-CI source-record control does not globally bust closure keys",
             have_fast_a && have_fast_b &&
             memcmp(key_fast_a, key_fast_b, sizeof(key_fast_a)) == 0);
    tc_env_restore(&caller_fast_record, "ZCL_FAST_BUILD_SOURCE_RECORD");
    /* The lint-only per-TU cache knob has no bearing on test verdicts. */
    failures += tc_non_test_controls_stable();

    /* Both branches of the capture/restore pair on a private variable, so the
     * "caller had it set" case above is not the only one covered. test.c runs
     * this group in-process ahead of 125 more groups; leaking either branch
     * silently moves those groups onto a different coverage path. */
    {
        const char *probe = "ZCL_TESTCACHE_ENV_RESTORE_PROBE";
        struct tc_envsave s;
        setenv(probe, "caller-value", 1);
        tc_env_capture(&s, probe);
        setenv(probe, "phase-value", 1);
        tc_env_restore(&s, probe);
        const char *v = getenv(probe);
        TC_CHECK("a SET caller value survives a phase that overwrites it",
                 v && strcmp(v, "caller-value") == 0);

        unsetenv(probe);
        tc_env_capture(&s, probe);
        setenv(probe, "phase-value", 1);
        tc_env_restore(&s, probe);
        TC_CHECK("an UNSET caller value is left unset, not invented",
                 getenv(probe) == NULL);
    }

    /* ── Phase I: the denylist matches EXACT names, and covers the binaries ──
     * The old strstr() form could not list "net" (it would have swallowed
     * netmask/subnet/net_bootstrap), which is exactly why test_net — a group
     * that execs built binaries and gates coverage on ZCL_STRESS_TESTS — went
     * uncovered. Exact matching makes it listable without collateral. */
    TC_CHECK("exact-name denylist covers test_net",
             testcache_group_is_denylisted("test_net"));
    TC_CHECK("and does NOT swallow the unrelated test_net_bootstrap",
             !testcache_group_is_denylisted("test_net_bootstrap"));
    TC_CHECK("bare (unprefixed) names match too",
             testcache_group_is_denylisted("net"));
    TC_CHECK("groups that exec built binaries are denylisted",
             testcache_group_is_denylisted("test_cli_argv_strict") &&
             testcache_group_is_denylisted("test_kill9_recovery") &&
             testcache_group_is_denylisted("test_wallet_view") &&
             tc_acme_and_agent_policy() &&
             testcache_group_is_denylisted("test_replay_canary_verdict"));
    TC_CHECK("a plain in-tree unit group stays cacheable",
             !testcache_group_is_denylisted("test_hkdf_sha256_rfc5869"));

    /* ── Phase J: the toolkey binds the FLAGS, not just the compiler ───────
     * BUILD_COMPILER_ID fingerprints the CC/CXX argv and tool bytes only, so
     * the -O1 fast profile and the -O3 release profile shared one keyspace and
     * a PASS recorded by `make t-fast` was honored by the release gate binary.
     * The Makefile now injects a per-profile digest over the effective compile
     * flags; a 64-hex toolkey proves that define reached this TU rather than
     * the __VERSION__ fallback. */
    {
        const char *tk = testcache_toolkey();
        size_t n = tk ? strlen(tk) : 0;
        bool hex64 = (n == 64);
        for (size_t i = 0; i < n && hex64; i++)
            if (!((tk[i] >= '0' && tk[i] <= '9') ||
                  (tk[i] >= 'a' && tk[i] <= 'f')))
                hex64 = false;
        TC_CHECK("toolkey is a 64-hex flags-bound digest (not the fallback)",
                 hex64);
        char d[13];
        testcache_toolkey_digest12(d);
        TC_CHECK("toolkey digest12 is 12 chars", strlen(d) == 12);
    }
    /* Each needle is text this change INTRODUCED. The bare variable names
     * (TEST_FAST_EPOCH_COMPILE_FLAGS et al) are not: the epoch machinery has
     * defined all three for a long time, so asserting on them pinned nothing —
     * revert the toolkey plumbing entirely and they still matched. What is new
     * is the derivation tag and the per-profile injection of it. */
    TC_CHECK("Makefile derives the toolkey per PROFILE + compile flags",
             file_contains("Makefile", "zcl.testcache.toolkey.v1") &&
             file_contains("Makefile",
                           "$(call TESTCACHE_TOOLKEY_CPPFLAGS,"
                           "$(TEST_FAST_PROFILE),"
                           "TEST_FAST_EPOCH_COMPILE_FLAGS)") &&
             file_contains("Makefile",
                           "$(call TESTCACHE_TOOLKEY_CPPFLAGS,"
                           "$(TEST_REL_PROFILE),"
                           "TEST_REL_EPOCH_COMPILE_FLAGS)") &&
             file_contains("Makefile",
                           "$(call TESTCACHE_TOOLKEY_CPPFLAGS,"
                           "$(TEST_ASAN_PROFILE),"
                           "TEST_ASAN_EPOCH_COMPILE_FLAGS)"));

    /* ── Phase K: the headline cannot claim a cold pass for a cached run ───
     * test_parallel printed "ALL TESTS PASSED" whether it ran 743 groups or 1,
     * and the push gate greps that exact string. Source-contract assertions:
     * this module cannot fork a whole suite run, but it can pin the two
     * behaviors that make the headline honest. */
    TC_CHECK("runner emits a machine-greppable SUITE VERDICT line",
             file_contains("tests/harness/src/test_parallel.c",
                           "SUITE VERDICT mode=%s"));
    TC_CHECK("runner marks a cached pass as (CACHED)",
             file_contains("tests/harness/src/test_parallel.c",
                           "ALL TESTS PASSED (CACHED)"));
    TC_CHECK("runner never stores a self-skipped group as PASS",
             file_contains("tests/harness/src/test_parallel.c",
                           "results[i].skip_markers == 0"));

    /* An environment-dependent leg that never reported is NOT a skip. The
     * group ran and hard-asserted every leg that does not depend on the
     * environment; only an observation was missing. Two things must both hold,
     * and they pull in opposite directions:
     *
     *   * It must stay OUT of the verdict cache. Caching it would let a loaded
     *     box mint a receipt that a later run reuses as if the leg had been
     *     proven — a skip laundered into a PASS.
     *   * It must NOT block the push. Grading a Tor bootstrap window FAIL
     *     measures the box's spare capacity, not the code, and would leave a
     *     busy or honestly slow machine permanently unable to push. This
     *     project keeps slow boxes precisely because they are the instrument
     *     that finds fast-hardware assumptions; a gate they can never pass
     *     destroys that signal.
     *
     * The sentinel spelling is the hinge between the two files: the runner
     * counts the literal "SKIP (" as unexecuted coverage, so if this site is
     * ever reworded back to SKIP the push gate silently starts refusing every
     * loaded run again. Pin it. */
    TC_CHECK("runner never stores an environment-unobserved group as PASS",
             file_contains("tests/harness/src/test_parallel.c",
                           "results[i].env_unobserved == 0"));
    TC_CHECK("runner reports env_unobserved in the machine verdict",
             file_contains("tests/harness/src/test_parallel.c",
                           "env_unobserved=%d load_flaky=%d toolkey=%s"));
    TC_CHECK("the onion bootstrap window prints UNOBSERVED, never SKIP",
             file_contains("tests/harness/src/test_onion_bootstrap.c",
                           "UNOBSERVED (tor bootstrap did not complete"));
    TC_CHECK("params-gated simnet legs report UNOBSERVED, never SKIP",
             file_contains(
                 "tests/harness/src/test_simnet_sapling_shielded_send.c",
                 "UNOBSERVED (params-gated shielded legs)") &&
             file_contains(
                 "tests/harness/src/test_simnet_shielded_wallet_e2e.c",
                 "UNOBSERVED (~/.zcash-params absent") &&
             file_contains("tests/harness/src/test_simnet_zmsg_onchain.c",
                           "UNOBSERVED (real-prover leg)") &&
             file_contains("tests/harness/src/test_shielded_payment_gate.c",
                           "UNOBSERVED (ZCL_STRESS_TESTS=1 but Sapling "
                           "params absent"));
    TC_CHECK("pre-push accepts an unobserved leg but still refuses a skip",
             file_contains("tools/agent_fast_ci.sh",
                           "rejected an environment-unobserved leg") &&
             file_contains("tools/agent_fast_ci.sh",
                           "accepted a runtime SKIP"));
    TC_CHECK("pre-push opts into exact per-group PASS receipts",
             file_contains("tools/agent_fast_ci.sh",
                           "T_FAST_EXACT_ARGS=--cache "
                           "--activate-proof-contracts") &&
             file_contains("Makefile",
                           "--exact=$(EXACT_ONLY_MATCHED) $(T_FAST_EXACT_ARGS)"));
    TC_CHECK("pre-push rejects skips and incomplete receipt accounting",
             file_contains("tools/agent_fast_ci.sh",
                           "focused receipt invalid reason=self_skips") &&
             file_contains("tools/agent_fast_ci.sh",
                           "focused receipt invalid reason=accounting"));
    TC_CHECK("v5 key binds shared harness and retires older PASS records",
             file_contains("tests/harness/src/testcache.c",
                           "zcl.testcache.key.v5"));
    /* The label has to describe the run, not the flag. Keying it on cache_mode
     * made `ZCL_TEST_CACHE=1 ... --only=<group>` report "mode=cached ...
     * groups_cached=0" and the (CACHED) headline for a run in which everything
     * executed — a second misreport inside the change whose whole point is that
     * the headline must say what the run did. */
    TC_CHECK("the CACHED label is derived from what was served, not the flag",
             file_contains("tests/harness/src/test_parallel.c",
                           "bool served_from_cache = (cached_count > 0);") &&
             !file_contains("tests/harness/src/test_parallel.c",
                            "(cache_mode == CACHE_ON) ? \"cached\" : \"cold\""));
    TC_CHECK("gate rejects a cached run instead of reporting GATE OK",
             file_contains("tools/scripts/gate-and-report.sh",
                           "ALL TESTS PASSED (CACHED)") &&
             file_contains("tools/scripts/gate-and-report.sh",
                           "SUITE REJECTED"));
    /* The needle is the RECIPE, not the word. "--no-cache" already appeared in
     * a prose comment near the top of the Makefile long before this change, so
     * matching it passed with the retry fix fully reverted. Only the retry
     * invocation itself distinguishes the two. */
    TC_CHECK("CI retry runs cold so a flake cannot be laundered into a PASS",
             file_contains("Makefile",
                           "$(TEST_PARALLEL_REL_ACTIVE) --no-cache"));

    /* ── Phase L: rerun-alone policy (test_parallel.c) — source-contract
     * pins. This module cannot fork a whole 8-worker suite run to reproduce
     * the actual race (that is exactly the flake the policy exists for), so
     * — same pattern as the SUITE VERDICT pins above — pin the shapes that
     * make the four scenarios true: flaky-then-pass, fail-then-fail,
     * watchdog-then-pass, and the cache-hit reprint. The behavioral half
     * (testcache_store_pass_flaky / hit_flaky round-trip) is exercised for
     * real above in Phase A3; this is the harness-side wiring around it. */
    TC_CHECK("a FAIL/WEDGED group gets exactly one alone rerun before it counts",
             file_contains("tests/harness/src/test_parallel.c",
                           "static void rerun_load_flaky_groups(") &&
             file_contains("tests/harness/src/test_parallel.c",
                           "bool first_pass = !results[i].signaled && "
                           "results[i].exit_code == 0;") &&
             file_contains("tests/harness/src/test_parallel.c",
                           "if (fu == 0) continue; /* an ordinary pass: "
                           "nothing to rerun */"));
    {
        static const char *const exclusion_pins[] = {
            "static bool group_excluded_from_rerun(",
            "group_requires_exclusive_run(name)",
            ("if (group_excluded_from_rerun(&results[i], "
             "g_groups[i].name)) continue;"),
        };
        TC_CHECK("groups that already ran exclusively are excluded from "
                 "rerun-alone",
                 file_contains_all("tests/harness/src/test_parallel.c",
                                   exclusion_pins,
                                   sizeof(exclusion_pins) /
                                       sizeof(exclusion_pins[0])));
    }
    TC_CHECK("a group SIGNALED for a reason the harness did not cause "
             "(SIGSEGV/SIGABRT/SIGBUS/SIGFPE, or a SIGKILL nobody in this "
             "process sent) stays a hard failure with no rerun — decided "
             "from the `wedged` flag the deadline kill itself sets, never "
             "inferred from the signal number alone",
             file_contains("tests/harness/src/test_parallel.c",
                           "(r->signaled && !r->wedged);"));
    TC_CHECK("flaky-then-pass: an alone PASS sets load_flaky and prints "
             "LOAD-FLAKY with first= and alone_log=",
             file_contains("tests/harness/src/test_parallel.c",
                           "results[i].load_flaky = 1;") &&
             file_contains("tests/harness/src/test_parallel.c",
                           "results[i].flaky_first_wedged = first_wedged;") &&
             file_contains("tests/harness/src/test_parallel.c",
                           "printf(\"LOAD-FLAKY %s first=%s alone=PASS "
                           "first_log=%s \""));
    TC_CHECK("fail-then-fail: a group that fails again alone stays FAIL and "
             "its preserved first-attempt log is discarded, not the new one",
             file_contains("tests/harness/src/test_parallel.c",
                           "/* Still FAIL: the alone log is the one that "
                           "matters now. */") &&
             file_contains("tests/harness/src/test_parallel.c",
                           "unlink(preserved_log);"));
    TC_CHECK("fail-then-fail records flaky_first_wedged too, so the "
             "failed-groups report can still say a deadline kill was "
             "retried alone instead of reading like a plain FAIL/signal",
             file_contains("tests/harness/src/test_parallel.c",
                           "results[i].flaky_first_wedged = first_wedged;\n"
                           "            if (preserved_log[0]) {"));
    {
        static const char *const deadline_report_pins[] = {
            "print_failed_group_prefix(const char *name,",
            ("\"  - %s: timed out after %ds under the shared "
             "pool; retried \""),
            ("printf(\"  - %s: %s\", name, r->signaled ? "
             "\"signaled\" : \"exit\");"),
        };
        TC_CHECK("the failed-groups report names a deadline kill distinctly "
                 "from an ordinary signal/exit failure",
                 file_contains_all("tests/harness/src/test_parallel.c",
                                   deadline_report_pins,
                                   sizeof(deadline_report_pins) /
                                       sizeof(deadline_report_pins[0])));
    }
    TC_CHECK("watchdog-then-pass: the printed line distinguishes a WEDGED "
             "first attempt from a plain FAIL",
             file_contains("tests/harness/src/test_parallel.c",
                           "g_groups[i].name, first_wedged ? \"WEDGED\" : "
                           "\"FAIL\","));
    TC_CHECK("a load-flaky PASS is stored with the flaky flag, never as an "
             "indistinguishable ordinary PASS",
             file_contains("tests/harness/src/test_parallel.c",
                           "if (results[i].load_flaky)") &&
             file_contains("tests/harness/src/test_parallel.c",
                           "testcache_store_pass_flaky(tc, probes[i].key);"));
    TC_CHECK("cache-hit reprint: a stored flaky PASS reprints LOAD-FLAKY on "
             "every future cache hit instead of hiding the flake",
             file_contains("tests/harness/src/test_parallel.c",
                           "if (probes[i].hit_flaky) {") &&
             file_contains("tests/harness/src/test_parallel.c",
                           "printf(\"LOAD-FLAKY %s first=CACHED alone=PASS \""));
    TC_CHECK("the suite verdict line carries load_flaky=<n>",
             file_contains("tests/harness/src/test_parallel.c",
                           "env_unobserved=%d load_flaky=%d toolkey=%s%s"));
    TC_CHECK("load_flaky is counted from results, not just this run's reruns "
             "(a cache hit sets it on the same field)",
             file_contains("tests/harness/src/test_parallel.c",
                           "if (results[i].load_flaky) load_flaky_groups++;"));

    /* ── Phase M: a PASS that prints UNOBSERVED also gets rerun alone ──────
     * The onion bootstrap window (test_onion_bootstrap) is the motivating
     * case: it can print "UNOBSERVED (" under a saturated shared pool while
     * every one of its assertions already passed. Before this phase existed,
     * that group had no second chance the way a FAIL/WEDGED group does, so
     * env_unobserved counted it against the suite verdict even though a
     * clean, uncontended rerun would have observed it fine. Same source-
     * contract-pin style as Phase L above: this module cannot fork a whole
     * pool run to reproduce the race, so it pins the shapes that make the
     * PASS-with-UNOBSERVED -> alone-and-OBSERVED path, and its never-cached
     * guarantee, true. */
    TC_CHECK("a PASS that printed UNOBSERVED also gets exactly one alone "
             "rerun, not just FAIL/WEDGED groups",
             file_contains("tests/harness/src/test_parallel.c",
                           "int fu = results[i].out_path[0]\n"
                           "                ? count_marker_lines(results[i]"
                           ".out_path, \"UNOBSERVED (\") : 0;") &&
             file_contains("tests/harness/src/test_parallel.c",
                           "first_unobserved = true;"));
    TC_CHECK("the [rerun-alone] announcement names UNOBSERVED as its own "
             "reason, distinct from FAILED/WEDGED",
             file_contains("tests/harness/src/test_parallel.c",
                           "first_unobserved ? \"printed UNOBSERVED\""));
    TC_CHECK("UNOBSERVED-then-OBSERVED prints LOAD-UNOBSERVED with first= "
             "and alone= and marks the result load_unobserved",
             file_contains("tests/harness/src/test_parallel.c",
                           "results[i].load_unobserved = 1;") &&
             file_contains("tests/harness/src/test_parallel.c",
                           "printf(\"LOAD-UNOBSERVED %s first=UNOBSERVED "
                           "alone=OBSERVED \""));
    TC_CHECK("still-UNOBSERVED or failed alone: the alone attempt's own "
             "result stands, the existing FAIL/UNOBSERVED accounting applies",
             file_contains("tests/harness/src/test_parallel.c",
                           "/* Still can't observe it (or it failed "
                           "outright) alone: the\n"
                           "                 * alone attempt's own result "
                           "is the honest one — keep it. */"));
    TC_CHECK("a load-unobserved PASS is never handed to the verdict store, "
             "unlike an ordinary load-flaky PASS",
             file_contains("tests/harness/src/test_parallel.c",
                           "!results[i].load_unobserved && probes &&"));

    /* ── Phase PB: batched proof-reuse lookup over the routed set ── */
    {
        /* The runner's capsule-flag parser must size every prefix from
         * the literal itself: a hand-counted length once silently
         * rejected --capsule-graph-root (21 counted as 22) and dropped
         * its value's first byte. If any flag goes back to a magic
         * number, its sizeof needle below vanishes and this trips. */
        static const char *const cli_len_pins[] = {
            "sizeof(\"--write-capsule=\") - 1",
            "sizeof(\"--use-capsule=\") - 1",
            "sizeof(\"--capsule-source-id=\") - 1",
            "sizeof(\"--capsule-mutation-id=\") - 1",
            "sizeof(\"--capsule-source-cas=\") - 1",
            "sizeof(\"--capsule-graph-root=\") - 1",
        };
        TC_CHECK("capsule flag prefixes are compiler-sized, never "
                 "hand-counted",
                 file_contains_all("tests/harness/src/test_parallel.c",
                                   cli_len_pins,
                                   sizeof(cli_len_pins) /
                                       sizeof(cli_len_pins[0])));
    }
    failures += tc_capsule_roundtrip();
    failures += tc_capsule_tamper();
    failures += tc_capsule_bindings();
    failures += tc_capsule_apply();
    failures += tc_capsule_reverify();
    failures += tc_capsule_live_revalidate();
    failures += tc_batch_parity();
    failures += tc_batch_stats();
    failures += tc_batch_invalidation();
    failures += tc_batch_failclosed();
    failures += tc_batch_special();
    failures += tc_batch_restart_crosstree();
    failures += tc_batch_perf();
    failures += tc_observation_roundtrip();

    (void)tc_shell("rm -rf %s %s %s %s %s", TC_FIX, TC_STORE,
                   TC_FIX2, TC_CAP, TC_CAP2);
    tc_env_restore(&caller_store, "ZCL_TESTCACHE_STORE_ROOT");
    printf("test_testcache: %d failure(s)\n", failures);
    return failures;
}
