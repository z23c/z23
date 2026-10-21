/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * code.packet contract: the one-call work packet. Every case runs against a
 * hermetic fixture corpus under test-tmp/ so the answers do not drift with the
 * real tree.
 *
 * Coverage:
 *   a. a symbol excerpt is verbatim with the exact line span;
 *   b. a long function is elided head and tail within max_lines;
 *   c. an unknown symbol is an explicit not_found, never a failure;
 *   d. tests[] is exactly what code.tests returns for the same file;
 *   e. every input bound is a typed refusal (9 symbols, max_lines, ../ and
 *      absolute paths, malformed names, over-long goal and change);
 *   f. the markdown carries every template field, in order;
 *   g. the leaf creates no files;
 *   h. a stale or absent index is refused and never rebuilt, and the BASE
 *      roots are the ones the same index reports;
 *   i. capabilities rows, the nearest test case, and the reply-fit shrink. */

#include "test/test_core.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "codeindex/codeindex.h"
#include "command/native_command.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#include <dirent.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define PKT_FIX "test-tmp/code_packet_fix"

static bool pkt_write(const char *rel, const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", PKT_FIX, rel);
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    if (content && content[0]) fwrite(content, 1, strlen(content), f);
    fclose(f);
    return true;
}

#define PKT_SMALL \
    "/* pk_small.c -- code.packet fixture. */\n" \
    "#include \"net/pk_small.h\"\n" \
    "\n" \
    "/* Adds one to x. */\n" \
    "int pk_small_add(int x)\n" \
    "{\n" \
    "    return x + 1;\n" \
    "}\n" \
    "\n" \
    "int pk_small_other(void) { return 2; }\n"

#define PKT_SERVICE \
    "/* A service with intentionally ordinary static names. */\n" \
    "static int packet_rank(int x)\n{\n    return x + 17;\n}\n" \
    "static int packet_status(void)\n{\n    return 23;\n}\n" \
    "struct packet_ops { int (*rank)(int); int (*status)(void); };\n" \
    "static const struct packet_ops packet_table = {\n" \
    "    .rank = packet_rank,\n    .status = packet_status,\n};\n" \
    "static int pk_aux(void) { return 31; }\n" \
    "const struct packet_ops *packet_getter(void)\n{\n    return &packet_table;\n}\n"

/* A function of `body` padded lines, long enough to force elision. */
static bool pkt_write_long(const char *rel, const char *name, int body)
{
    char *buf = malloc((size_t)body * 96 + 512);
    if (!buf) return false;
    size_t n = (size_t)sprintf(buf, "/* %s fixture. */\nint %s(int x)\n{\n",
                               name, name);
    for (int i = 1; i <= body; i++)
        n += (size_t)sprintf(buf + n,
            "    x += %d; /* padding padding padding padding padding pad */\n",
            i);
    n += (size_t)sprintf(buf + n, "    return x;\n}\n");
    bool ok = pkt_write(rel, buf);
    free(buf);
    return ok;
}

static bool pkt_write_many(void)
{
    char text[8192];
    size_t used = 0;
    for (int i = 0; i < 70; i++) {
        int n = snprintf(text + used, sizeof(text) - used,
                         "static int pk_aux_%d(void) { return %d; }\n", i, i);
        if (n < 0 || (size_t)n >= sizeof(text) - used) return false;
        used += (size_t)n;
    }
    return pkt_write("core/modules/net/src/pk_many.c", text);
}

static bool pkt_fixture(void)
{
    char rel[160];
    bool ok = pkt_write("core/modules/net/src/pk_small.c", PKT_SMALL);
    ok = ok && pkt_write("core/modules/net/include/net/pk_small.h",
                         "#ifndef PK_SMALL_H\n#define PK_SMALL_H\n"
                         "int pk_small_add(int x);\n#endif\n");
    ok = ok && pkt_write_long("core/modules/net/src/pk_long.c", "pk_long", 150);
    ok = ok && pkt_write_many();
    ok = ok && pkt_write("core/modules/net/src/pk_service.c", PKT_SERVICE);
    ok = ok && pkt_write("core/modules/net/src/pk_duplicate.c",
                         "static int packet_rank(long x) { return x - 99; }\n");
    ok = ok && pkt_write("tests/harness/src/test_packet_wrong.c",
                         "static int wrong_packet_case(void)\n{\n    return packet_rank(1);\n}\n");
    for (int i = 0; i < 8; i++) {
        char name[32];
        snprintf(name, sizeof(name), "pk_wide_%d", i);
        snprintf(rel, sizeof(rel), "core/modules/net/src/pk_wide_%d.c", i);
        ok = ok && pkt_write_long(rel, name, 400);
    }
    ok = ok && pkt_write("tests/harness/src/test_pk_user.c",
                         "int pk_small_add(int x);\n\n"
                         "static int test_pk_case(void)\n{\n"
                         "    return pk_small_add(1) == 2;\n}\n");
    ok = ok && pkt_write("tools/command/native_code_capsule.c",
                         "void fixture_capsule_handler(void)\n{\n}\n");
    ok = ok && pkt_write("engine/composition/module_capabilities.def",
                         "/* fixture */\n\n"
                         "ZCL_MODULE_CAPABILITY(\"core/modules/net/src/pk_small.c\","
                         " CAP_FS_READ, \"fixture reach\")\n");
    ok = ok && pkt_write("tools/dev/test_group_catalog.def",
                         "/* fixture */\nZCL_TEST_GROUP(hex_codec)\n"
                         "ZCL_TEST_GROUP(code_capsule)\n"
                         "ZCL_TEST_GROUP(code_impact)\n"
                         "ZCL_TEST_GROUP(command_registry_catalog)\n");
    return ok;
}

static bool pkt_index_build(void)
{
    struct codeindex *ci = codeindex_open(PKT_FIX);
    if (!ci) return false;
    codeindex_close(ci);
    return true;
}

static void pkt_run_budget(const char *root, struct json_value *input,
                           size_t budget, struct zcl_command_reply *reply)
{
    struct zcl_command_context ctx = { .source_root = root };
    struct zcl_command_request request = {
        .input = input, .context = &ctx, .view = "normal",
        .invoked_name = "code.packet",
        .budget_bytes = budget,
    };
    zcl_command_reply_init(reply, "zcl.code_packet.v1");
    zcl_native_handle_code_packet(&request, reply);
}

static void pkt_run(const char *root, struct json_value *input,
                    struct zcl_command_reply *reply)
{
    pkt_run_budget(root, input, 0, reply);
}

static void pkt_push_str(struct json_value *arr, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s);
    (void)json_push_back(arr, &v);
    json_free(&v);
}

/* Build {goal, symbols[], files[], max_lines} and run it on PKT_FIX. */
static void pkt_call(const char *goal, const char *const *syms, int ns,
                     const char *const *files, int nf, int max_lines,
                     struct zcl_command_reply *reply)
{
    struct json_value in, arr;
    json_init(&in); json_set_object(&in);
    if (goal) (void)json_push_kv_str(&in, "goal", goal);
    if (ns > 0) {
        json_init(&arr); json_set_array(&arr);
        for (int i = 0; i < ns; i++) pkt_push_str(&arr, syms[i]);
        (void)json_push_kv(&in, "symbols", &arr);
        json_free(&arr);
    }
    if (nf > 0) {
        json_init(&arr); json_set_array(&arr);
        for (int i = 0; i < nf; i++) pkt_push_str(&arr, files[i]);
        (void)json_push_kv(&in, "files", &arr);
        json_free(&arr);
    }
    if (max_lines > 0) (void)json_push_kv_int(&in, "max_lines", max_lines);
    pkt_run(PKT_FIX, &in, reply);
    json_free(&in);
}

static const char *pkt_md(const struct zcl_command_reply *r)
{
    const char *m = json_get_str(json_get(&r->data, "markdown"));
    return m ? m : "";
}

static const struct json_value *pkt_first(const struct zcl_command_reply *r,
                                          const char *key)
{
    return json_at(json_get(&r->data, key), 0);
}

/* Lines [a, b] of `text`, as the fixture author sees them. */
static void pkt_slice(const char *text, int a, int b, char *out, size_t cap)
{
    size_t n = 0;
    int line = 1;
    for (const char *p = text; *p && n + 2 < cap; p++) {
        if (line >= a && line <= b) out[n++] = *p;
        if (*p == '\n') line++;
    }
    out[n] = '\0';
}

static int pkt_count_lines(const char *s, size_t len)
{
    int n = 0;
    for (size_t i = 0; i < len; i++) if (s[i] == '\n') n++;
    return n;
}

/* The fenced code between the first header containing `needle` and its close. */
static bool pkt_fence_after(const char *md, const char *needle, char *out,
                            size_t cap)
{
    const char *h = strstr(md, needle);
    if (!h) return false;
    const char *open = strstr(h, "```c\n");
    if (!open) return false;
    open += 5;
    const char *close = strstr(open, "```");
    if (!close || (size_t)(close - open) + 1 > cap) return false;
    memcpy(out, open, (size_t)(close - open));
    out[close - open] = '\0';
    return true;
}

static int test_code_packet_excerpt_verbatim(void)
{
    int failures = 0;
    TEST("code_packet: a symbol excerpt is verbatim with the exact line span") {
        test_rm_rf_recursive(PKT_FIX);
        ASSERT(pkt_fixture());
        ASSERT(pkt_index_build());
        struct zcl_command_reply reply;
        const char *syms[] = { "pk_small_add" };
        pkt_call("Fix the adder", syms, 1, NULL, 0, 0, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *ex = pkt_first(&reply, "excerpts");
        ASSERT(ex != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(ex, "status")), "ok");
        ASSERT_EQ(json_get_int(json_get(ex, "site_line")), 5);
        ASSERT_EQ(json_get_int(json_get(ex, "end_line")), 8);
        ASSERT_EQ(json_get_int(json_get(ex, "first_line")), 2);
        ASSERT_EQ(json_get_int(json_get(ex, "last_line")), 10);
        char want[1024], got[1024];
        pkt_slice(PKT_SMALL, 2, 10, want, sizeof(want));
        ASSERT(pkt_fence_after(pkt_md(&reply), "core/modules/net/src/pk_small.c:2-10",
                               got, sizeof(got)));
        ASSERT_STR_EQ(got, want);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_packet_long_function_elided(void)
{
    int failures = 0;
    TEST("code_packet: a long function keeps head and tail within max_lines") {
        struct zcl_command_reply reply;
        const char *syms[] = { "pk_long" };
        pkt_call("Trim pk_long", syms, 1, NULL, 0, 40, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *ex = pkt_first(&reply, "excerpts");
        ASSERT(json_get_int(json_get(ex, "elided_from")) > 0);
        ASSERT(json_get_int(json_get(ex, "elided_to")) >
               json_get_int(json_get(ex, "elided_from")));
        char got[8192];
        ASSERT(pkt_fence_after(pkt_md(&reply), "core/modules/net/src/pk_long.c",
                               got, sizeof(got)));
        ASSERT(pkt_count_lines(got, strlen(got)) <= 40);
        ASSERT(strstr(got, "int pk_long(int x)\n") != NULL);
        ASSERT(strstr(got, "lines elided (L") != NULL);
        ASSERT(strstr(got, "    return x;\n}\n") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_packet_file_context(void)
{
    int failures = 0;
    TEST("code_packet: explicit file expands an EOF getter without name inference") {
        struct zcl_command_reply reply;
        const char *syms[] = {"packet_getter"};
        const char *files[] = {"core/modules/net/src/pk_service.c"};
        pkt_call("Explain the actual service", syms, 1, files, 1, 120, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *ex = pkt_first(&reply, "excerpts");
        ASSERT_EQ(json_get_int(json_get(ex, "first_line")), 1);
        ASSERT(strstr(pkt_md(&reply), ".rank = packet_rank") != NULL);
        ASSERT(strstr(pkt_md(&reply), "return x + 17;") != NULL);
        ASSERT(strstr(pkt_md(&reply), "return 23;") != NULL);
        ASSERT(strstr(pkt_md(&reply), "return x - 99;") == NULL);
        ASSERT(strstr(pkt_md(&reply), "static int packet_rank(long x)") == NULL);
        ASSERT(strstr(pkt_md(&reply), "wrong_packet_case") == NULL);
        ASSERT(strstr(pkt_md(&reply), "static int packet_rank(int x)") != NULL);
        ASSERT(json_get_int(json_get(ex, "shown_lines")) <= 120);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_packet_shared_context(void)
{
    int failures = 0;
    TEST("code_packet: same-file requests share one context and added context yields before bodies") {
        const char *syms[] = {"packet_getter", "packet_rank"};
        const char *files[] = {"core/modules/net/src/pk_service.c"};
        struct zcl_command_reply reply;
        pkt_call("Read once", syms, 2, files, 1, 120, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const char *body = strstr(pkt_md(&reply), "return x + 17;");
        ASSERT(body != NULL);
        ASSERT(strstr(body + 1, "return x + 17;") == NULL);
        const struct json_value *rows = json_get(&reply.data, "excerpts");
        const struct json_value *second = json_at(rows, 1);
        ASSERT_STR_EQ(json_get_str(json_get(second, "shared_with")), "packet_getter");
        zcl_command_reply_free(&reply);

        pkt_call("Budget", syms, 1, files, 1, 120, &reply);
        size_t full_bytes = json_write(&reply.data, NULL, 0);
        ASSERT(full_bytes > 4096);
        zcl_command_reply_free(&reply);
        struct json_value in, arr;
        json_init(&in); json_set_object(&in);
        (void)json_push_kv_str(&in, "goal", "Budget");
        json_init(&arr); json_set_array(&arr); pkt_push_str(&arr, syms[0]);
        (void)json_push_kv(&in, "symbols", &arr); json_free(&arr);
        json_init(&arr); json_set_array(&arr); pkt_push_str(&arr, files[0]);
        (void)json_push_kv(&in, "files", &arr); json_free(&arr);
        (void)json_push_kv_int(&in, "max_lines", 120);
        pkt_run_budget(PKT_FIX, &in, full_bytes + 2048 - 200, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "max_lines_effective")), 120);
        ASSERT(json_get(pkt_first(&reply, "excerpts"), "context") == NULL);
        ASSERT(strstr(pkt_md(&reply), "return &packet_table;") != NULL);
        ASSERT(strstr(pkt_md(&reply), "return x + 17;") == NULL);
        json_free(&in);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_packet_unrelated_large_file(void)
{
    int failures = 0;
    TEST("code_packet: unrelated large impact files do not cap complete name lookup") {
        struct zcl_command_reply reply;
        const char *syms[] = {"packet_getter"};
        const char *files[] = {"core/modules/net/src/pk_service.c", "core/modules/net/src/pk_many.c"};
        pkt_call("Inspect service and unrelated impact", syms, 1, files, 2, 120, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *ex = pkt_first(&reply, "excerpts");
        ASSERT_STR_EQ(json_get_str(json_get(ex, "status")), "ok");
        ASSERT_STR_EQ(json_get_str(json_get(ex, "file")), files[0]);
        ASSERT(strstr(pkt_md(&reply), "return &packet_table;") != NULL);
        ASSERT_EQ(json_get(&reply.data, "files")->num_children, 2);
        zcl_command_reply_free(&reply);
        pkt_call("Unique global symbol plus unrelated impact", syms, 1, &files[1], 1, 120, &reply);
        ex = pkt_first(&reply, "excerpts");
        ASSERT_STR_EQ(json_get_str(json_get(ex, "status")), "ok");
        ASSERT_STR_EQ(json_get_str(json_get(ex, "file")), files[0]);
        zcl_command_reply_free(&reply);
        const char *capped[] = {"pk_aux"};
        pkt_call("A capped name query can use a complete supplied file", capped, 1, files, 1, 120, &reply);
        ex = pkt_first(&reply, "excerpts");
        ASSERT_STR_EQ(json_get_str(json_get(ex, "status")), "ok");
        ASSERT_STR_EQ(json_get_str(json_get(ex, "file")), files[0]);
        zcl_command_reply_free(&reply);
        pkt_call("Capped global results never prove uniqueness", capped, 1, NULL, 0, 120, &reply);
        ASSERT_STR_EQ(json_get_str(json_get(pkt_first(&reply, "excerpts"), "status")), "lookup_capped");
        zcl_command_reply_free(&reply);
        pkt_call("Capped supplied results never prove uniqueness", capped, 1, files, 2, 120, &reply);
        ASSERT_STR_EQ(json_get_str(json_get(pkt_first(&reply, "excerpts"), "status")), "lookup_capped");
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_packet_excerpt_append_failure(void)
{
    int failures = 0;
    TEST("code_packet: failed first or later excerpt append never annotates a different row") {
        struct json_value input;
        json_init(&input);
        const char *text = "{\"goal\":\"Allocation safety\",\"symbols\":[\"packet_getter\",\"packet_rank\"],"
            "\"files\":[\"core/modules/net/src/pk_service.c\"],\"max_lines\":120}";
        ASSERT(json_read(&input, text, strlen(text)));
        size_t before = json_test_live_blocks();
        /* Copy #1 is the HEAD claim. #2 and #4 are respectively the first
         * excerpt and the later excerpt, with its definition claim between. */
        for (unsigned nth = 2; nth <= 4; nth += 2) {
            struct zcl_command_reply reply;
            zcl_alloc_fault_fail_nth("json_copy_children", nth);
            pkt_run(PKT_FIX, &input, &reply);
            bool consumed = zcl_alloc_fault_armed_label() == NULL;
            zcl_alloc_fault_clear();
            ASSERT(consumed);
            ASSERT(json_write(&reply.data, NULL, 0) > 0);
            const struct json_value *rows = json_get(&reply.data, "excerpts");
            ASSERT(rows != NULL && rows->type == JSON_ARR);
            ASSERT_EQ(rows->num_children, 1);
            const struct json_value *row = json_at(rows, 0);
            ASSERT_STR_EQ(json_get_str(json_get(row, "symbol")), nth == 2 ? "packet_rank" : "packet_getter");
            const struct json_value *shared = json_get(row, "shared_with");
            if (nth == 2) ASSERT_STR_EQ(json_get_str(shared), "packet_getter");
            else ASSERT(shared == NULL);
            zcl_command_reply_free(&reply);
            ASSERT_EQ(json_test_live_blocks(), before);
        }
        json_free(&input);
        PASS();
    } _test_next:;
    zcl_alloc_fault_clear();
    return failures;
}

static int test_code_packet_static_scope(void)
{
    int failures = 0;
    TEST("code_packet: supplied files disambiguate static names and unresolved names never guess") {
        struct zcl_command_reply reply;
        const char *syms[] = {"packet_rank"};
        const char *files[] = {"core/modules/net/src/pk_service.c"};
        pkt_call("Inspect the supplied implementation", syms, 1, files, 1, 120, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *ex = pkt_first(&reply, "excerpts");
        ASSERT_STR_EQ(json_get_str(json_get(ex, "file")), files[0]);
        ASSERT(strstr(pkt_md(&reply), "return x + 17;") != NULL);
        ASSERT(strstr(pkt_md(&reply), "return x - 99;") == NULL);
        ASSERT(strstr(pkt_md(&reply), "Signature of packet_rank unless CHANGE says otherwise: static int packet_rank(int x)") != NULL);
        ASSERT(strstr(pkt_md(&reply), "static int packet_rank(long x)") == NULL);
        ASSERT_STR_EQ(json_get_str(json_get(pkt_first(&reply, "pattern"), "status")), "none_in_index_refs");
        ASSERT(strstr(pkt_md(&reply), "wrong_packet_case") == NULL);
        zcl_command_reply_free(&reply);
        pkt_call("Do not guess global statics", syms, 1, NULL, 0, 120, &reply);
        ex = pkt_first(&reply, "excerpts");
        ASSERT_STR_EQ(json_get_str(json_get(ex, "status")), "ambiguous");
        ASSERT(strstr(pkt_md(&reply), "return x - 99;") == NULL);
        zcl_command_reply_free(&reply);
        const char *both[] = {files[0], "core/modules/net/src/pk_duplicate.c"};
        pkt_call("Do not guess between supplied files", syms, 1, both, 2, 120, &reply);
        ex = pkt_first(&reply, "excerpts");
        ASSERT_STR_EQ(json_get_str(json_get(ex, "status")), "ambiguous");
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_packet_unknown_symbol(void)
{
    int failures = 0;
    TEST("code_packet: an unknown symbol is an explicit not_found") {
        struct zcl_command_reply reply;
        const char *syms[] = { "zz_pk_no_such_symbol" };
        pkt_call("Nothing here", syms, 1, NULL, 0, 0, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(pkt_first(&reply, "excerpts"),
                                            "status")), "not_found");
        ASSERT(strstr(pkt_md(&reply), "NOT AVAILABLE: not_found") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static bool pkt_same_array(const struct json_value *a, const struct json_value *b)
{
    if (!a || !b || a->num_children != b->num_children) return false;
    for (size_t i = 0; i < a->num_children; i++) {
        const char *x = json_get_str(&a->children[i]);
        const char *y = json_get_str(&b->children[i]);
        if (!x || !y || strcmp(x, y) != 0) return false;
    }
    return true;
}

static int test_code_packet_tests_match_code_tests(void)
{
    int failures = 0;
    TEST("code_packet: tests[] equals what code.tests returns for the file") {
        const char *path = "tools/command/native_code_capsule.c";
        struct json_value in;
        json_init(&in); json_set_object(&in);
        (void)json_push_kv_str(&in, "path", path);
        struct zcl_command_request rq = { .input = &in, .view = "normal",
                                          .invoked_name = "code.tests" };
        struct zcl_command_reply tests;
        zcl_command_reply_init(&tests, "zcl.code_tests.v1");
        zcl_native_handle_code_tests(&rq, &tests);
        ASSERT(tests.status == ZCL_COMMAND_STATUS_PASSED);
        struct zcl_command_reply reply;
        const char *files[] = { path };
        pkt_call("Route check", NULL, 0, files, 1, 0, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *t = pkt_first(&reply, "tests");
        ASSERT(t != NULL);
        const struct json_value *want = json_get(&tests.data, "test_groups");
        ASSERT(want && want->num_children > 0);
        ASSERT(pkt_same_array(json_get(t, "test_groups"), want));
        ASSERT_STR_EQ(json_get_str(json_get(t, "route")),
                      json_get_str(json_get(&tests.data, "route")));
        ASSERT(json_get(t, "groups")->num_children > 0);
        ASSERT(strstr(pkt_md(&reply), "test_code_capsule") != NULL);
        ASSERT(strstr(pkt_md(&reply),
                      "tools/dev/test_group_catalog.def:3") != NULL);
        zcl_command_reply_free(&reply);
        zcl_command_reply_free(&tests);
        json_free(&in);
        PASS();
    } _test_next:;
    return failures;
}

static void pkt_expect_refusal(const char *goal, const char *const *syms,
                               int ns, const char *const *files, int nf,
                               int max_lines, const char *code, int *failures)
{
    struct zcl_command_reply reply;
    pkt_call(goal, syms, ns, files, nf, max_lines, &reply);
    if (reply.status != ZCL_COMMAND_STATUS_FAILED ||
        strcmp(reply.error.code, code) != 0) {
        printf("  FAIL: expected %s, got status=%d code=%s\n", code,
               (int)reply.status, reply.error.code);
        (*failures)++;
    }
    zcl_command_reply_free(&reply);
}

static int test_code_packet_bounds_refused(void)
{
    int failures = 0;
    TEST("code_packet: every input bound is a typed refusal") {
        int bad = 0;
        const char *nine[] = { "a","b","c","d","e","f","g","h","i" };
        const char *one[] = { "pk_small_add" };
        const char *evil[] = { "../etc/passwd" };
        const char *abs[] = { "/etc/passwd" };
        const char *mid[] = { "core/../../x.c" };
        const char *badname[] = { "1bad name" };
        pkt_expect_refusal("g", nine, 9, NULL, 0, 0, "TOO_MANY_SYMBOLS", &bad);
        pkt_expect_refusal("g", one, 1, NULL, 0, 500, "MAX_LINES_RANGE", &bad);
        pkt_expect_refusal("g", one, 1, NULL, 0, 19, "MAX_LINES_RANGE", &bad);
        pkt_expect_refusal("g", NULL, 0, evil, 1, 0, "BAD_PATH", &bad);
        pkt_expect_refusal("g", NULL, 0, abs, 1, 0, "BAD_PATH", &bad);
        pkt_expect_refusal("g", NULL, 0, mid, 1, 0, "BAD_PATH", &bad);
        pkt_expect_refusal("g", badname, 1, NULL, 0, 0, "BAD_SYMBOL", &bad);
        pkt_expect_refusal(NULL, one, 1, NULL, 0, 0, "MISSING_GOAL", &bad);
        pkt_expect_refusal("g", NULL, 0, NULL, 0, 0, "EMPTY_PACKET", &bad);
        char longgoal[600];
        memset(longgoal, 'x', sizeof(longgoal) - 1);
        longgoal[sizeof(longgoal) - 1] = '\0';
        pkt_expect_refusal(longgoal, one, 1, NULL, 0, 0, "GOAL_TOO_LONG", &bad);
        ASSERT_EQ(bad, 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_packet_markdown_fields(void)
{
    int failures = 0;
    TEST("code_packet: the markdown carries every template field in order") {
        struct zcl_command_reply reply;
        const char *syms[] = { "pk_small_add" };
        pkt_call("Template check", syms, 1, NULL, 0, 0, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        static const char *const fields[] = {
            "# PACKET ", "\nROUTE:", "\nBASE:", "\nSIZE:", "\nGOAL:",
            "\nFILES AND EXACT EXCERPTS:", "\nCHANGE:", "\nKEEP UNCHANGED:",
            "\nACCEPTANCE:", "\nAUTHORITY:", "\nPACKER NOTES:",
        };
        const char *md = pkt_md(&reply);
        const char *at = md;
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
            const char *hit = i == 0 && strncmp(md, fields[0], 9) == 0
                                  ? md : strstr(at, fields[i]);
            ASSERT(hit != NULL);
            ASSERT(hit >= at);
            at = hit + 1;
        }
        ASSERT(strstr(md, "t-fast-exact ONLY=") != NULL);
        ASSERT(strstr(md, "make lint") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

/* name:size of every entry under `dir`, sorted by readdir order is unstable,
 * so each entry is hashed into a commutative sum plus a count. */
static void pkt_tree(const char *dir, unsigned long long *sum, int *count)
{
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(full, &st) != 0) continue;
        unsigned long long h = 1469598103934665603ULL;
        for (const char *p = full; *p; p++) h = (h ^ (unsigned char)*p) * 1099511628211ULL;
        *sum += h + (unsigned long long)st.st_size;
        (*count)++;
        if (S_ISDIR(st.st_mode)) pkt_tree(full, sum, count);
    }
    closedir(d);
}

static int test_code_packet_creates_no_files(void)
{
    int failures = 0;
    TEST("code_packet: the leaf creates no files") {
        unsigned long long s0 = 0, s1 = 0;
        int n0 = 0, n1 = 0;
        pkt_tree(PKT_FIX, &s0, &n0);
        struct zcl_command_reply reply;
        const char *syms[] = { "pk_small_add", "pk_long" };
        pkt_call("No writes", syms, 2, NULL, 0, 0, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        zcl_command_reply_free(&reply);
        pkt_tree(PKT_FIX, &s1, &n1);
        ASSERT_EQ(n0, n1);
        ASSERT(s0 == s1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_packet_generation_and_staleness(void)
{
    int failures = 0;
    TEST("code_packet: BASE roots come from the index; stale and absent refuse") {
        uint8_t src[32], dep[32];
        char sh[65], dh[65];
        struct codeindex *ci = codeindex_open_readonly(PKT_FIX, NULL);
        ASSERT(ci != NULL);
        ASSERT(codeindex_source_root_sha3(ci, src));
        ASSERT(codeindex_dep_root_sha3(ci, dep));
        codeindex_close(ci);
        zcl_hex_encode(src, sizeof src, sh);
        zcl_hex_encode(dep, sizeof dep, dh);
        struct zcl_command_reply reply;
        const char *syms[] = { "pk_small_add" };
        pkt_call("Roots", syms, 1, NULL, 0, 0, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "source_root_sha3")), sh);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "dep_root_sha3")), dh);
        ASSERT(strstr(pkt_md(&reply), sh) != NULL);
        ASSERT(strstr(pkt_md(&reply), dh) != NULL);
        zcl_command_reply_free(&reply);

        /* A source edit makes the sealed generation stale: refuse, no rebuild. */
        ASSERT(pkt_write("core/modules/net/src/pk_small.c",
                         PKT_SMALL "/* edited after the index was sealed */\n"));
        pkt_call("Stale", syms, 1, NULL, 0, 0, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "CODEINDEX_STALE");
        zcl_command_reply_free(&reply);
        ASSERT(pkt_write("core/modules/net/src/pk_small.c", PKT_SMALL));
        ASSERT(pkt_index_build());
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_packet_authority_and_pattern(void)
{
    int failures = 0;
    TEST("code_packet: capabilities row, nearest test case, shrink to fit") {
        struct zcl_command_reply reply;
        const char *syms[] = { "pk_small_add" };
        const char *files[] = { "core/modules/net/src/pk_long.c" };
        pkt_call("Authority", syms, 1, files, 1, 0, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *caps = json_get(&reply.data, "capabilities");
        ASSERT(caps && caps->num_children == 2);
        const struct json_value *c0 = json_at(caps, 0);
        const struct json_value *c1 = json_at(caps, 1);
        const struct json_value *with = json_get_bool(json_get(c0, "row")) ? c0 : c1;
        const struct json_value *none = with == c0 ? c1 : c0;
        ASSERT_STR_EQ(json_get_str(json_get(with, "capabilities")), "CAP_FS_READ");
        ASSERT_EQ(json_get_int(json_get(with, "line")), 3);
        ASSERT(strncmp(json_get_str(json_get(none, "capabilities")), "none:", 5) == 0);
        const struct json_value *pat = pkt_first(&reply, "pattern");
        ASSERT_STR_EQ(json_get_str(json_get(pat, "status")), "ok");
        ASSERT_STR_EQ(json_get_str(json_get(pat, "enclosing")), "test_pk_case");
        ASSERT_STR_EQ(json_get_str(json_get(pat, "file")),
                      "tests/harness/src/test_pk_user.c");
        ASSERT(strstr(pkt_md(&reply), "PATTERN for pk_small_add") != NULL);
        zcl_command_reply_free(&reply);

        /* Eight 400-line functions at max_lines=120 cannot fit 64 KiB twice
         * over: the leaf must shrink max_lines, say so, and still fit. */
        const char *wide[8] = { "pk_wide_0", "pk_wide_1", "pk_wide_2",
                                "pk_wide_3", "pk_wide_4", "pk_wide_5",
                                "pk_wide_6", "pk_wide_7" };
        pkt_call("Wide", wide, 8, NULL, 0, 120, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_int(json_get(&reply.data, "max_lines_effective")) <
               json_get_int(json_get(&reply.data, "max_lines")));
        char *buf = malloc(70000);
        ASSERT(buf != NULL);
        size_t n = json_write(&reply.data, buf, 70000);
        free(buf);
        ASSERT(n > 0 && n <= 63488);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_packet_deterministic(void)
{
    int failures = 0;
    TEST("code_packet: two runs on one generation are byte-identical") {
        struct zcl_command_reply a, b;
        const char *syms[] = { "pk_small_add", "pk_long" };
        pkt_call("Same", syms, 2, NULL, 0, 0, &a);
        pkt_call("Same", syms, 2, NULL, 0, 0, &b);
        ASSERT(a.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(pkt_md(&a), pkt_md(&b));
        zcl_command_reply_free(&a);
        zcl_command_reply_free(&b);
        PASS();
    } _test_next:;
    test_rm_rf_recursive(PKT_FIX);
    return failures;
}

int test_code_packet(void)
{
    int failures = 0;
    failures += test_code_packet_excerpt_verbatim();
    failures += test_code_packet_long_function_elided();
    failures += test_code_packet_file_context();
    failures += test_code_packet_static_scope();
    failures += test_code_packet_unrelated_large_file();
    failures += test_code_packet_excerpt_append_failure();
    failures += test_code_packet_shared_context();
    failures += test_code_packet_unknown_symbol();
    failures += test_code_packet_tests_match_code_tests();
    failures += test_code_packet_bounds_refused();
    failures += test_code_packet_markdown_fields();
    failures += test_code_packet_creates_no_files();
    failures += test_code_packet_generation_and_staleness();
    failures += test_code_packet_authority_and_pattern();
    failures += test_code_packet_deterministic();
    return failures;
}
