/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * code_fetch — the M4 "verified warm start" contract: `z23 code fetch`
 * adopts another checkout's published codeindex generation only after its
 * sealed source roots match a fresh local computation.
 *
 * Coverage:
 *   1. happy path — two fixture trees with identical content under test-tmp;
 *      tree A is indexed through the normal build path, then A's store is
 *      fetched into B through all three `from` spellings (checkout root,
 *      .codeindex directory, index.kv file). After the install, a plain
 *      codeindex_open(B) does NOT cold-rebuild: queries answer, the sealed
 *      cold-build receipt still shows A's values, and the store inode is
 *      unchanged across the open.
 *   2. tamper — one source file in B differs; the fetch is refused with
 *      FETCH_SOURCE_ROOT, and the refusal evidence names the key.
 *   3. fresh — B already holds a fresh store; the fetch is refused with
 *      FETCH_FRESH and the store is not overwritten.
 *   4. bogus from — a missing path, an empty directory, and a non-store file
 *      all fail closed.
 *
 * All scratch work happens under ./test-tmp/ (project no-/tmp convention). */

#include "test/test_core.h"

#include "command/native_command.h"
#include "kernel/command_registry.h"
#include "codeindex/codeindex.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if !defined(_WIN32)

#define FETCH_FIX "test-tmp/ci_fetch"
#define FETCH_A   FETCH_FIX "/tree_a"
#define FETCH_B   FETCH_FIX "/tree_b"
/* The four indexed fixture files (two roots, one header). */
#define FETCH_FILE_COUNT 4

/* Write content to <dir>/<rel>, creating parent dirs (the mk_write pattern
 * from test_code_firsthour.c). */
static bool fetch_mk_write(const char *dir, const char *rel,
                           const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    if (content && content[0]) fwrite(content, 1, strlen(content), f);
    fclose(f);
    return true;
}

/* The identical twin trees. */
static bool write_fetch_fixture(void)
{
    static const char *const rels[FETCH_FILE_COUNT] = {
        "src/fetch_alpha.c",
        "src/fetch_beta.c",
        "src/fetch_beta.h",
        "docs/examples/fetch_documented.c",
    };
    static const char *const bodies[FETCH_FILE_COUNT] = {
        "/* src/fetch_alpha.c — fetch fixture. */\n"
        "int fetch_alpha(void)\n{\n    return 1;\n}\n",
        "/* src/fetch_beta.c — fetch fixture. */\n"
        "#include \"fetch_beta.h\"\n"
        "int fetch_beta(void)\n{\n    return fetch_alpha();\n}\n",
        "/* src/fetch_beta.h — fetch fixture header. */\n"
        "#ifndef FETCH_BETA_H\n#define FETCH_BETA_H\n"
        "int fetch_beta(void);\n#endif\n",
        "/* docs/examples/fetch_documented.c — fetch fixture. */\n"
        "int fetch_documented(void)\n{\n    return 3;\n}\n",
    };
    for (int i = 0; i < FETCH_FILE_COUNT; i++) {
        if (!fetch_mk_write(FETCH_A, rels[i], bodies[i]) ||
            !fetch_mk_write(FETCH_B, rels[i], bodies[i]))
            return false;
    }
    return true;
}

static void fetch_call(const char *root, const char *from,
                       struct zcl_command_reply *reply)
{
    struct zcl_command_context ctx = { .source_root = root };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    if (from) (void)json_push_kv_str(&input, "from", from);
    struct zcl_command_request request = {
        .input = &input, .context = &ctx,
        .view = "normal", .invoked_name = "code.fetch",
    };
    zcl_command_reply_init(reply, "zcl.code_fetch.v1");
    zcl_native_handle_code_fetch(&request, reply);
    json_free(&input);
}

static bool fetch_store_identity(const char *root, dev_t *dev, ino_t *ino)
{
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/.codeindex/index.kv", root);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    struct stat st;
    if (stat(path, &st) != 0) return false;
    *dev = st.st_dev;
    *ino = st.st_ino;
    return true;
}

/* ── 1: the happy path, all three from-spellings ── */
static int test_fetch_adopts(void)
{
    int failures = 0;
    TEST("code_fetch: a verified generation from a twin tree is adopted "
         "without a cold rebuild") {
        /* Index tree A through the normal build path. */
        struct codeindex *a = codeindex_open(FETCH_A);
        ASSERT(a != NULL);
        long long a_cold_ms = 0, a_cold_files = 0;
        ASSERT(codeindex_build_cold_ms(a, &a_cold_ms, &a_cold_files));
        ASSERT(a_cold_files == FETCH_FILE_COUNT);
        codeindex_close(a);

        /* Fetch A's published store into B, naming the checkout root. */
        struct zcl_command_reply reply;
        fetch_call(FETCH_B, FETCH_A, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        ASSERT(json_get_bool(json_get(&reply.data, "installed")));
        ASSERT(json_get_bool(json_get(&reply.data, "adopted")));
        ASSERT(json_get_bool(json_get(&reply.data, "dep_restamped")));
        ASSERT(json_get_int(json_get(&reply.data, "build_cold_files")) ==
               a_cold_files);
        ASSERT(json_get_int(json_get(&reply.data, "build_cold_ms")) ==
               a_cold_ms);
        ASSERT(strlen(json_get_str(json_get(&reply.data,
                                            "source_root_sha3"))) == 64);
        ASSERT(strlen(json_get_str(json_get(&reply.data,
                                            "source_merkle_root_sha3"))) == 64);
        zcl_command_reply_free(&reply);

        /* A plain open of B (WITH the depfile freshness check) must not
         * cold-rebuild: the receipt still shows A's cold build, the store
         * inode is the one fetch published, and queries answer. */
        dev_t dev_before = 0, dev_after = 0;
        ino_t ino_before = 0, ino_after = 0;
        ASSERT(fetch_store_identity(FETCH_B, &dev_before, &ino_before));
        struct codeindex *b = codeindex_open(FETCH_B);
        ASSERT(b != NULL);
        long long b_cold_ms = 0, b_cold_files = 0;
        ASSERT(codeindex_build_cold_ms(b, &b_cold_ms, &b_cold_files));
        ASSERT(b_cold_ms == a_cold_ms && b_cold_files == a_cold_files);
        struct ci_file row;
        bool found = false;
        ASSERT(codeindex_file(b, "src/fetch_alpha.c", &row, &found) && found);
        struct ci_symbol sym;
        bool sym_found = false;
        ASSERT(codeindex_symbol(b, "fetch_alpha", &sym, &sym_found) &&
               sym_found && sym.kind == 'T');
        codeindex_close(b);
        ASSERT(fetch_store_identity(FETCH_B, &dev_after, &ino_after));
        ASSERT(dev_before == dev_after && ino_before == ino_after);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fetch_from_spellings(void)
{
    int failures = 0;
    TEST("code_fetch: a .codeindex directory and a bare index.kv also fetch") {
        static const char *const froms[] = {
            FETCH_A "/.codeindex",
            FETCH_A "/.codeindex/index.kv",
        };
        for (size_t i = 0; i < sizeof(froms) / sizeof(froms[0]); i++) {
            char store[4096];
            (void)snprintf(store, sizeof(store), "%s/.codeindex", FETCH_B);
            ASSERT(test_rm_rf_recursive(store) == 0);
            struct zcl_command_reply reply;
            fetch_call(FETCH_B, froms[i], &reply);
            ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
            ASSERT(json_get_bool(json_get(&reply.data, "installed")));
            ASSERT(json_get_bool(json_get(&reply.data, "adopted")));
            zcl_command_reply_free(&reply);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3: a fresh local store is never overwritten ── */
static int test_fetch_refuses_fresh(void)
{
    int failures = 0;
    TEST("code_fetch: a fresh local store refuses the overwrite") {
        /* B's store is fresh from the previous case. */
        dev_t dev_before = 0, dev_after = 0;
        ino_t ino_before = 0, ino_after = 0;
        ASSERT(fetch_store_identity(FETCH_B, &dev_before, &ino_before));
        struct zcl_command_reply reply;
        fetch_call(FETCH_B, FETCH_A, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "FETCH_FRESH");
        zcl_command_reply_free(&reply);
        ASSERT(fetch_store_identity(FETCH_B, &dev_after, &ino_after));
        ASSERT(dev_before == dev_after && ino_before == ino_after);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2: a tampered source tree refuses, naming the key ── */
static int test_fetch_refuses_tampered(void)
{
    int failures = 0;
    TEST("code_fetch: a tampered source file fails closed naming the key") {
        ASSERT(fetch_mk_write(FETCH_B, "src/fetch_beta.c",
            "/* src/fetch_beta.c — TAMPERED. */\n"
            "#include \"fetch_beta.h\"\n"
            "int fetch_beta(void)\n{\n    return 99;\n}\n"));
        char store[4096];
        (void)snprintf(store, sizeof(store), "%s/.codeindex", FETCH_B);
        ASSERT(test_rm_rf_recursive(store) == 0);
        struct zcl_command_reply reply;
        fetch_call(FETCH_B, FETCH_A, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "FETCH_SOURCE_ROOT");
        ASSERT(strstr(reply.error.evidence, "source_root_sha3") != NULL);
        ASSERT(strstr(reply.error.evidence, "image=") != NULL);
        ASSERT(strstr(reply.error.evidence, "local=") != NULL);
        zcl_command_reply_free(&reply);
        /* The refusal installed nothing. */
        ASSERT(!fetch_store_identity(FETCH_B, &(dev_t){0}, &(ino_t){0}));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4: bogus from paths fail closed ── */
static int test_fetch_refuses_bogus_from(void)
{
    int failures = 0;
    TEST("code_fetch: bogus from paths fail closed") {
        struct zcl_command_reply reply;
        fetch_call(FETCH_B, FETCH_FIX "/no_such_tree", &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "FETCH_FROM_MISSING");
        zcl_command_reply_free(&reply);

        /* A directory with no published index.kv. */
        ASSERT(fetch_mk_write(FETCH_FIX, "empty/placeholder.txt", "x\n"));
        fetch_call(FETCH_B, FETCH_FIX "/empty", &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "FETCH_FROM_MISSING");
        zcl_command_reply_free(&reply);

        /* A regular file that is not a codeindex store (0600 so it passes
         * the ownership check and fails at the store layer). */
        ASSERT(fetch_mk_write(FETCH_FIX, "not_a_store.kv",
                              "this is not sqlite\n"));
        ASSERT(chmod(FETCH_FIX "/not_a_store.kv", 0600) == 0);
        fetch_call(FETCH_B, FETCH_FIX "/not_a_store.kv", &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "FETCH_IMAGE");
        zcl_command_reply_free(&reply);

        /* No from at all. */
        fetch_call(FETCH_B, NULL, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "MISSING_FROM");
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

int test_code_fetch(void)
{
    int failures = 0;
    (void)test_rm_rf_recursive(FETCH_FIX);
    if (!write_fetch_fixture()) {
        printf("  code_fetch: fixture write... FAIL\n");
        return 1;
    }
    failures += test_fetch_adopts();
    failures += test_fetch_from_spellings();
    failures += test_fetch_refuses_fresh();
    failures += test_fetch_refuses_tampered();
    failures += test_fetch_refuses_bogus_from();
    (void)test_rm_rf_recursive(FETCH_FIX);
    return failures;
}

#else  /* _WIN32 */
/* The install ritual is a POSIX descriptor-capability path (rebuild.lock
 * flock, staging inode identity, renameat); the native Windows publisher does
 * not expose fetch. Skipped loudly rather than faked. */
int test_code_fetch(void)
{
    printf("code_fetch: SKIP (Windows): the fetch install ritual is a "
           "POSIX-descriptor path\n");
    return 0;
}
#endif
