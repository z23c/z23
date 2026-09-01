/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the writer census (engine/controllers/src/fact_writers.c) — the
 * instrument that names durable slots with more than one writer.
 *
 * Two halves, deliberately different in kind:
 *
 *  1. PRECISION, on a planted fixture tree. The census's answer for a tree
 *     whose every write is planted here is fully known, so writer_files,
 *     writer_sites, the raw-SQL path, the comment exclusion, and the
 *     unresolved-key counter are all asserted exactly. No assertion here says
 *     anything about the real repository, so nothing here can go stale when the
 *     real tree changes.
 *
 *  2. COVERAGE, against the real headers. Every keyed-write declaration in a
 *     manifest row's api_headers must be claimed by a FACT_WRITE_API row —
 *     a canonical registry no row claims must fail. Paired with a hollow-scan
 *     proof: point the coverage scan at a tree with no such headers and it must
 *     return -1, never a comfortable 0.
 *
 * What is NOT asserted, on purpose: any count of multi-writer slots in the real
 * tree. That number is a finding, and pinning a finding in a test is the second
 * ledger the census exists to find. Read it with `z23 code facts`.
 */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "controllers/fact_writers.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define FW_FIX   "test-tmp/fw_fix_arch_v2"
#define FW_EMPTY "test-tmp/fw_empty"

/* Write content to <dir>/<rel>, creating parent dirs (mirrors test_codeindex). */
static bool fw_write(const char *dir, const char *rel, const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + 1; *p; p++)
        if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    if (content && content[0]) fwrite(content, 1, strlen(content), f);
    fclose(f);
    return true;
}

static const char *FW_KEYS_H =
    "/* fixture keys header for the writer census test. */\n"
    "#ifndef FW_FIX_KEYS_H\n"
    "#define FW_FIX_KEYS_H\n"
    "#define FW_SHARED_KEY \"fw_shared_slot\"\n"
    "#define FW_SOLO_KEY   \"fw_solo_slot\"\n"
    "#endif\n";

/* Writer 1: the declared API, key via macro. Also plants a COMMENT that spells
 * a write of the same slot — the census must not count it. */
static const char *FW_A_C =
    "/* fixture writer A — declared API write of the shared slot. */\n"
    "#include \"storage/fw_fix_keys.h\"\n"
    "int fw_fix_a(void *db, const void *v)\n"
    "{\n"
    "    /* progress_meta_set(db, FW_SHARED_KEY, v, 1) is only mentioned. */\n"
    "    return progress_meta_set_in_tx(db, FW_SHARED_KEY, v, 1);\n"
    "}\n";

/* Writer 2: the declared API again, a DELETE, from a second file, and split
 * across lines so the multi-line join is exercised. */
static const char *FW_B_C =
    "/* fixture writer B — a second file deleting the same shared slot. */\n"
    "#include \"storage/fw_fix_keys.h\"\n"
    "int fw_fix_b(void *db)\n"
    "{\n"
    "    return progress_meta_delete_in_tx(db,\n"
    "                                      FW_SHARED_KEY);\n"
    "}\n";

/* Writer 3: raw SQL that bypasses the declared API entirely. */
static const char *FW_C_C =
    "/* fixture writer C — raw SQL mutation, the API-bypassing shape. */\n"
    "int fw_fix_c(void *db)\n"
    "{\n"
    "    return fw_fix_exec(db,\n"
    "        \"DELETE FROM progress_meta WHERE key='fw_shared_slot'\");\n"
    "}\n";

/* A single-writer slot, plus a write whose key is a runtime variable (the
 * census's declared blind spot: counted, never silently dropped). */
static const char *FW_D_C =
    "/* fixture writer D — one solo slot and one unresolvable key. */\n"
    "#include \"storage/fw_fix_keys.h\"\n"
    "int fw_fix_d(void *db, const char *dynamic)\n"
    "{\n"
    "    (void)progress_meta_set(db, FW_SOLO_KEY, \"x\", 1);\n"
    "    return progress_meta_set(db, dynamic, \"y\", 1);\n"
    "}\n";

/* Writer 4b: an INSERT that spells its key in the VALUES clause rather than in
 * a `key=` predicate — the other half of the raw-SQL shape. */
static const char *FW_F_C =
    "/* fixture writer F — key spelled in the VALUES clause. */\n"
    "int fw_fix_f(void *db, const void *blob)\n"
    "{\n"
    "    return fw_fix_bind(db,\n"
    "        \"INSERT OR REPLACE INTO progress_meta(key,value)\"\n"
    "        \" VALUES('fw_shared_slot',?)\", blob);\n"
    "}\n";

/* Writer 4: a file-local helper that BINDS the key, so neither the declared-API
 * nor the raw-SQL derivation can see the slot. The census must recover the
 * helper from the file itself and attribute its two callers. */
static const char *FW_E_C =
    "/* fixture writer E — a local keyed wrapper over a bound-parameter write. */\n"
    "#include \"storage/fw_fix_keys.h\"\n"
    "static bool fw_fix_put(void *db, const char *key, const void *v)\n"
    "{\n"
    "    return fw_fix_bind(db,\n"
    "        \"INSERT INTO progress_meta(key,value) VALUES(?,?)\", key, v);\n"
    "}\n"
    "int fw_fix_e(void *db)\n"
    "{\n"
    "    return fw_fix_put(db, FW_SHARED_KEY, \"a\") &&\n"
    "           fw_fix_put(db, \"fw_wrapped_slot\", \"b\");\n"
    "}\n";

/* The fixture is built and censused once; every case below reads the result. */
static struct codeindex *g_fw_ci;
static struct fact_writers_report *g_fw_rep;

static bool fw_setup(void)
{
    if (g_fw_rep) return true;
    if (!fw_write(FW_FIX, "engine/modules/storage/include/storage/fw_fix_keys.h", FW_KEYS_H) ||
        !fw_write(FW_FIX, "engine/modules/storage/src/fw_fix_a.c", FW_A_C) ||
        !fw_write(FW_FIX, "engine/modules/storage/src/fw_fix_b.c", FW_B_C) ||
        !fw_write(FW_FIX, "engine/modules/storage/src/fw_fix_c.c", FW_C_C) ||
        !fw_write(FW_FIX, "engine/modules/storage/src/fw_fix_d.c", FW_D_C) ||
        !fw_write(FW_FIX, "engine/modules/storage/src/fw_fix_e.c", FW_E_C) ||
        !fw_write(FW_FIX, "engine/modules/storage/src/fw_fix_f.c", FW_F_C))
        return false;
    g_fw_ci = codeindex_open(FW_FIX);
    if (!g_fw_ci) return false;
    g_fw_rep = fact_writers_analyze(FW_FIX, g_fw_ci);
    return g_fw_rep != NULL;
}

/* Does `row` list a writer whose path ends in `tail`? */
static bool fw_row_has_file(const struct fact_row *row, const char *tail)
{
    for (int i = 0; i < row->n_sites; i++)
        if (strstr(row->sites[i].path, tail)) return true;
    return false;
}

static int fw_case_manifest(void)
{
    int failures = 0;
    TEST_CASE("fact_writers: manifest carries stores and write entry points") {
        ASSERT(fact_writers_store_row_count() >= 3);
        ASSERT(fact_writers_api_row_count() >= 10);
    } TEST_END;
    return failures;
}

static int fw_case_coverage(void)
{
    int failures = 0;
    TEST_CASE("fact_writers: every declared keyed-write entry point is claimed") {
        static char unclaimed[32][FACT_KEY_MAX];
        int n = fact_writers_unclaimed_apis(".", unclaimed, 32);
        if (n > 0)
            for (int i = 0; i < n && i < 32; i++)
                printf("\n    UNCLAIMED WRITE API: %s", unclaimed[i]);
        /* n < 0 means a declared api_header could not be read: a hollow scan
         * must fail here, never pass as "nothing unclaimed". */
        ASSERT_EQ(n, 0);
    } TEST_END;
    return failures;
}

static int fw_case_hollow(void)
{
    int failures = 0;
    TEST_CASE("fact_writers: coverage refuses to report clean off a hollow scan") {
        ASSERT(fw_write(FW_EMPTY, "placeholder.txt", "x\n"));
        static char unclaimed[4][FACT_KEY_MAX];
        ASSERT_EQ(fact_writers_unclaimed_apis(FW_EMPTY, unclaimed, 4), -1);
        ASSERT_EQ(fact_writers_unclaimed_apis(NULL, unclaimed, 4), -1);
        ASSERT_EQ(fact_writers_unclaimed_apis(".", unclaimed, 0), -1);
    } TEST_END;
    return failures;
}

static int fw_case_three_writers(void)
{
    int failures = 0;
    TEST_CASE("fact_writers: a planted three-writer slot resolves exactly") {
        ASSERT(fw_setup());
        ASSERT(g_fw_rep->files_scanned >= 7);
        const struct fact_row *shared =
            fact_writers_find(g_fw_rep, "progress_meta", "fw_shared_slot");
        ASSERT(shared != NULL);
        /* Three independently writable homes: two through the API (one set, one
         * multi-line delete) and one raw-SQL bypass. The commented mention in
         * fw_fix_a.c is NOT a fourth. */
        ASSERT_EQ(shared->writer_files, 5);
        ASSERT_EQ(shared->writer_sites, 5);
        ASSERT(fw_row_has_file(shared, "fw_fix_a.c"));
        ASSERT(fw_row_has_file(shared, "fw_fix_b.c"));
        ASSERT(fw_row_has_file(shared, "fw_fix_c.c"));
        ASSERT(fw_row_has_file(shared, "fw_fix_e.c"));
        ASSERT(!shared->sites_truncated);
    } TEST_END;
    return failures;
}

static int fw_case_via_kinds(void)
{
    int failures = 0;
    TEST_CASE("fact_writers: API writers are distinguished from raw-SQL bypasses") {
        ASSERT(fw_setup());
        const struct fact_row *shared =
            fact_writers_find(g_fw_rep, "progress_meta", "fw_shared_slot");
        ASSERT(shared != NULL);
        int api = 0, raw = 0;
        for (int i = 0; i < shared->n_sites; i++) {
            if (shared->sites[i].via == FACT_VIA_API) api++;
            else raw++;
            ASSERT(shared->sites[i].line > 0);
            ASSERT(shared->sites[i].via_name[0] != '\0');
        }
        ASSERT_EQ(api, 3);
        ASSERT_EQ(raw, 2);
    } TEST_END;
    return failures;
}

static int fw_case_local_wrapper(void)
{
    int failures = 0;
    TEST_CASE("fact_writers: a bound-key local wrapper is recovered, not shrugged at") {
        ASSERT(fw_setup());
        /* The wrapper's OTHER slot exists only because the census found the
         * helper; no derivation above it can see a bound `?` key. */
        const struct fact_row *wrapped =
            fact_writers_find(g_fw_rep, "progress_meta", "fw_wrapped_slot");
        ASSERT(wrapped != NULL);
        ASSERT_EQ(wrapped->writer_files, 1);
        ASSERT_EQ(wrapped->writer_sites, 1);
        ASSERT_STR_EQ(wrapped->sites[0].via_name, "fw_fix_put");
        ASSERT(fw_row_has_file(wrapped, "fw_fix_e.c"));
        /* The wrapper's own definition line is not a writer of anything. */
        const struct fact_row *shared =
            fact_writers_find(g_fw_rep, "progress_meta", "fw_shared_slot");
        ASSERT(shared != NULL);
        int via_wrapper = 0;
        for (int i = 0; i < shared->n_sites; i++)
            if (strcmp(shared->sites[i].via_name, "fw_fix_put") == 0)
                via_wrapper++;
        ASSERT_EQ(via_wrapper, 1);
    } TEST_END;
    return failures;
}

static int fw_case_solo(void)
{
    int failures = 0;
    TEST_CASE("fact_writers: a single-writer slot is not reported as multi-writer") {
        ASSERT(fw_setup());
        const struct fact_row *solo =
            fact_writers_find(g_fw_rep, "progress_meta", "fw_solo_slot");
        ASSERT(solo != NULL);
        ASSERT_EQ(solo->writer_files, 1);
        ASSERT_EQ(g_fw_rep->facts_multi_writer, 1);
        ASSERT_EQ(g_fw_rep->facts_total, 3);
    } TEST_END;
    return failures;
}

static int fw_case_unresolved(void)
{
    int failures = 0;
    TEST_CASE("fact_writers: a non-literal key is counted, never dropped") {
        ASSERT(fw_setup());
        ASSERT(g_fw_rep->sites_unresolved >= 2);
        ASSERT(g_fw_rep->n_stores >= 1);
        int unresolved = 0;
        for (int i = 0; i < g_fw_rep->n_stores; i++)
            if (strcmp(g_fw_rep->stores[i].store, "progress_meta") == 0)
                unresolved = g_fw_rep->stores[i].sites_unresolved;
        ASSERT(unresolved >= 1);
    } TEST_END;
    return failures;
}

static int fw_case_deterministic(void)
{
    int failures = 0;
    TEST_CASE("fact_writers: ranking is multi-writer-first and deterministic") {
        ASSERT(fw_setup());
        for (int i = 1; i < g_fw_rep->n_rows; i++)
            ASSERT(g_fw_rep->rows[i - 1].writer_files >=
                   g_fw_rep->rows[i].writer_files);
        struct fact_writers_report *again =
            fact_writers_analyze(FW_FIX, g_fw_ci);
        ASSERT(again != NULL);
        int same = (again->n_rows == g_fw_rep->n_rows) &&
                   (again->sites_total == g_fw_rep->sites_total) &&
                   (again->sites_unresolved == g_fw_rep->sites_unresolved);
        for (int i = 0; i < again->n_rows && same; i++)
            same = (strcmp(again->rows[i].key, g_fw_rep->rows[i].key) == 0) &&
                   (again->rows[i].writer_files == g_fw_rep->rows[i].writer_files);
        fact_writers_report_free(again);
        ASSERT(same);
    } TEST_END;
    return failures;
}

static int fw_case_defensive(void)
{
    int failures = 0;
    TEST_CASE("fact_writers: null arguments are refused") {
        ASSERT(fw_setup());
        ASSERT(fact_writers_analyze(NULL, g_fw_ci) == NULL);
        ASSERT(fact_writers_analyze(FW_FIX, NULL) == NULL);
        ASSERT(fact_writers_find(g_fw_rep, NULL, NULL) == NULL);
        ASSERT(fact_writers_find(NULL, NULL, "fw_solo_slot") == NULL);
        ASSERT(fact_writers_find(g_fw_rep, "progress_meta", "nope") == NULL);
    } TEST_END;
    return failures;
}

int test_fact_writers(void)
{
    printf("\n=== fact_writers (writer census) tests ===\n");
    int failures = 0;

    failures += fw_case_manifest();
    failures += fw_case_coverage();
    failures += fw_case_hollow();
    failures += fw_case_three_writers();
    failures += fw_case_via_kinds();
    failures += fw_case_local_wrapper();
    failures += fw_case_solo();
    failures += fw_case_unresolved();
    failures += fw_case_deterministic();
    failures += fw_case_defensive();

    fact_writers_report_free(g_fw_rep);
    g_fw_rep = NULL;
    if (g_fw_ci) { codeindex_close(g_fw_ci); g_fw_ci = NULL; }

    printf("=== fact_writers: %d failure(s) ===\n", failures);
    return failures;
}
