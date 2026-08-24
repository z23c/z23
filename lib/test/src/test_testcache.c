/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_testcache — the content-addressed per-group test cache (lib/test/src/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define TC_FIX "test-tmp/tc_cache_fix"

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
    "/* lib/net/src/tc_top.c — the group entry point. */\n"
    "#include \"net/tc.h\"\n"
    "int test_demo_entry(void)\n"
    "{\n"
    "    return tc_mid() + 1;\n"
    "}\n";

static const char *TC_MID =
    "/* lib/net/src/tc_mid.c — middle of the callee chain. */\n"
    "#include \"net/tc.h\"\n"
    "int tc_mid(void)\n"
    "{\n"
    "    return tc_leaf() * 2;\n"
    "}\n";

static const char *TC_LEAF_A =
    "/* lib/net/src/tc_leaf.c — the leaf (pristine). */\n"
    "#include \"net/tc.h\"\n"
    "int tc_leaf(void)\n"
    "{\n"
    "    return 7;\n"
    "}\n";

static const char *TC_LEAF_B =
    "/* lib/net/src/tc_leaf.c — the leaf (edited body). */\n"
    "#include \"net/tc.h\"\n"
    "int tc_leaf(void)\n"
    "{\n"
    "    return 4242;\n"
    "}\n";

static const char *TC_OTHER_A =
    "/* lib/net/src/tc_other.c — NOT reachable from the entry (pristine). */\n"
    "#include \"net/tc.h\"\n"
    "int tc_other(void)\n"
    "{\n"
    "    return 99;\n"
    "}\n";

static const char *TC_OTHER_B =
    "/* lib/net/src/tc_other.c — NOT reachable from the entry (edited). */\n"
    "#include \"net/tc.h\"\n"
    "int tc_other(void)\n"
    "{\n"
    "    return 123456;\n"
    "}\n";

static const char *TC_H_A =
    "/* lib/net/include/net/tc.h — fixture header (pristine). */\n"
    "#ifndef NET_TC_H\n"
    "#define NET_TC_H\n"
    "int test_demo_entry(void);\n"
    "int tc_mid(void);\n"
    "int tc_leaf(void);\n"
    "int tc_other(void);\n"
    "#endif\n";

static const char *TC_H_B =
    "/* lib/net/include/net/tc.h — fixture header (edited comment). */\n"
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
    "/* lib/net/include/net/tc_registry.def — pristine. */\n"
    "TC_ROW(alpha, 1)\n"
    "TC_ROW(beta, 2)\n";

static const char *TC_DEF_B =
    "/* lib/net/include/net/tc_registry.def — a row added. */\n"
    "TC_ROW(alpha, 1)\n"
    "TC_ROW(beta, 2)\n"
    "TC_ROW(gamma, 3)\n";

/* Write the fixture with the given leaf/other/header/def variants + depfiles so
 * the include closure resolves. Sources are written BEFORE depfiles so the
 * depfiles are always the newest bytes in the fixture — the include-graph
 * freshness guard requires the graph to be at least as new as its inputs. */
static bool write_fixture_full(const char *leaf, const char *other,
                               const char *hdr, const char *def)
{
    return mk_write(TC_FIX, "lib/net/src/tc_top.c", TC_TOP) &&
           mk_write(TC_FIX, "lib/net/src/tc_mid.c", TC_MID) &&
           mk_write(TC_FIX, "lib/net/src/tc_leaf.c", leaf) &&
           mk_write(TC_FIX, "lib/net/src/tc_other.c", other) &&
           mk_write(TC_FIX, "lib/net/include/net/tc.h", hdr) &&
           mk_write(TC_FIX, "lib/net/include/net/tc_registry.def", def) &&
           mk_write(TC_FIX, "build/obj/tc_top.d",
                    "build/obj/tc_top.o: lib/net/src/tc_top.c "
                    "lib/net/include/net/tc.h "
                    "lib/net/include/net/tc_registry.def\n") &&
           mk_write(TC_FIX, "build/obj/tc_mid.d",
                    "build/obj/tc_mid.o: lib/net/src/tc_mid.c "
                    "lib/net/include/net/tc.h\n") &&
           mk_write(TC_FIX, "build/obj/tc_leaf.d",
                    "build/obj/tc_leaf.o: lib/net/src/tc_leaf.c "
                    "lib/net/include/net/tc.h\n") &&
           mk_write(TC_FIX, "build/obj/tc_other.d",
                    "build/obj/tc_other.o: lib/net/src/tc_other.c "
                    "lib/net/include/net/tc.h\n");
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

int test_testcache(void)
{
    int failures = 0;
    system("rm -rf " TC_FIX);

    /* ── Phase A: cacheable, miss, store, hit ── */
    uint8_t keyA[32];
    bool have_keyA = false;
    TC_CHECK("fixture writes", write_fixture(TC_LEAF_A, TC_OTHER_A, TC_H_A));
    {
        struct testcache *tc = testcache_open(TC_FIX);
        TC_CHECK("testcache_open succeeds", tc != NULL);
        if (tc) {
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
             mk_write(TC_FIX, "lib/net/src/tc_leaf.c", TC_LEAF_B));
    {
        const char *changed[] = {"lib/net/src/tc_leaf.c"};
        struct testcache *tc = testcache_open_snapshot(TC_FIX, changed, 1);
        TC_CHECK("snapshot cache opens existing verified index", tc != NULL);
        if (tc) {
            struct testcache_probe p;
            testcache_probe_group(tc, "test_demo_entry", &p);
            TC_CHECK("snapshot closure reaching edit is uncacheable",
                     !p.cacheable &&
                     p.code == TESTCACHE_R_CHANGED_INPUT);
            testcache_close(tc);
        }
    }
    TC_CHECK("snapshot fixture restores closure and edits unrelated source",
             write_fixture(TC_LEAF_A, TC_OTHER_A, TC_H_A));
    {
        const char *changed[] = {"lib/net/src/tc_other.c"};
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
             system("rm -rf " TC_FIX "/build") == 0);
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
             testcache_group_is_denylisted("test_agent_copy_prove") &&
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
             file_contains("lib/test/src/test_parallel.c",
                           "SUITE VERDICT mode=%s"));
    TC_CHECK("runner marks a cached pass as (CACHED)",
             file_contains("lib/test/src/test_parallel.c",
                           "ALL TESTS PASSED (CACHED)"));
    TC_CHECK("runner never stores a self-skipped group as PASS",
             file_contains("lib/test/src/test_parallel.c",
                           "results[i].skip_markers == 0"));
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
    TC_CHECK("v3 key retires PASS records minted before skip rejection",
             file_contains("lib/test/src/testcache.c",
                           "zcl.testcache.key.v3"));
    /* The label has to describe the run, not the flag. Keying it on cache_mode
     * made `ZCL_TEST_CACHE=1 ... --only=<group>` report "mode=cached ...
     * groups_cached=0" and the (CACHED) headline for a run in which everything
     * executed — a second misreport inside the change whose whole point is that
     * the headline must say what the run did. */
    TC_CHECK("the CACHED label is derived from what was served, not the flag",
             file_contains("lib/test/src/test_parallel.c",
                           "bool served_from_cache = (cached_count > 0);") &&
             !file_contains("lib/test/src/test_parallel.c",
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

    system("rm -rf " TC_FIX);
    printf("test_testcache: %d failure(s)\n", failures);
    return failures;
}
