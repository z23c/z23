/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: contract coverage for z23-toolgen (tools/toolgen.c, built as
 * build/bin/z23-toolgen): every manifest refusal by its named reason, marker
 * recognition only inside real comments, size caps, collisions with authored
 * and generated names, idempotent --write that leaves unrelated bytes and
 * mtimes alone, and --check on hand edits, missing blocks and mixed
 * generations. Each case runs the real binary on a private fixture tree. */

#include "test/test_core.h"

#if !defined(_WIN32)

#include "util/spawn.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>

#define TG_BIN "build/bin/z23-toolgen"
#define TG_OUT 8192u

#define BEGIN_LINE(id) "/* z23-toolgen:begin " id " - generated, do not edit */\n"
#define END_LINE(id) "/* z23-toolgen:end " id " */\n"

#define VALID_JSON \
    "{\n" \
    "  \"profile\": \"readonly-local-v1\",\n" \
    "  \"path\": \"fleet.demo.list\",\n" \
    "  \"parent\": \"fleet.demo\",\n" \
    "  \"branch_summary\": \"Demo branch\",\n" \
    "  \"handler\": \"zcl_native_handle_fleet_demo_list\",\n" \
    "  \"summary\": \"Demo rows\",\n" \
    "  \"semantics\": [\"Lists \", \"the demo rows.\"],\n" \
    "  \"input_schema\": \"zcl.fleet_demo_input.v1\",\n" \
    "  \"output_schema\": \"zcl.fleet_demo.v1\",\n" \
    "  \"input_keys\": [\"datadir\"],\n" \
    "  \"example\": \"z23 fleet demo list\",\n" \
    "  \"tags\": [\"fleet\", \"demo\"],\n" \
    "  \"authority\": \"operator\",\n" \
    "  \"budget_bytes\": 4096,\n" \
    "  \"latency\": \"fast\",\n" \
    "  \"cost\": \"low\",\n" \
    "  \"test_group\": \"fleet_demo\"\n" \
    "}"

#define HANDLER_FN(name) \
    "void " name "(const struct zcl_command_request *q,\n" \
    "    struct zcl_command_reply *r)\n{\n    (void)q;\n    (void)r;\n}\n"

struct fx {
    char root[480];
};

static bool fx_path(const struct fx *f, const char *rel, char *out, size_t n)
{
    int w = snprintf(out, n, "%s/%s", f->root, rel);
    return w > 0 && (size_t)w < n;
}

static bool fx_put(const struct fx *f, const char *rel, const char *text, size_t len)
{
    char path[640];
    if (!fx_path(f, rel, path, sizeof path))
        return false;
    for (char *p = path + strlen(f->root) + 1u; *p; p++)
        if (*p == '/') {
            *p = '\0';
            if (mkdir(path, 0777) != 0 && errno != EEXIST)
                return false;
            *p = '/';
        }
    FILE *fp = fopen(path, "wb");
    if (!fp)
        return false;
    bool ok = fwrite(text, 1, len, fp) == len;
    return fclose(fp) == 0 && ok;
}

static bool fx_puts(const struct fx *f, const char *rel, const char *text)
{
    return fx_put(f, rel, text, strlen(text));
}

static bool fx_get(const struct fx *f, const char *rel, char *out, size_t cap)
{
    char path[640];
    if (!fx_path(f, rel, path, sizeof path))
        return false;
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return false;
    size_t n = fread(out, 1, cap - 1u, fp);
    fclose(fp);
    out[n] = '\0';
    return true;
}

static int fx_run(const struct fx *f, const char *mode, char *out, size_t cap)
{
    const char *argv[] = {TG_BIN, "--root", f->root, mode, NULL};
    bool timed_out = false;
    out[0] = '\0';
    return zcl_spawn_capture_merged_observed(argv, out, cap, 20000, &timed_out);
}

/* The four generated registry files, each with its authored text around an empty
 * block, plus the hand-written remote permit table (no block: a new leaf with
 * no row there is REMOTE_CLASS_NEVER). */
static bool fx_tree(struct fx *f, const char *def_x, const char *hdr_x, const char *rem_x,
                    const char *cat_x)
{
    char buf[2048];
    memset(f, 0, sizeof *f);
    if (!test_mkdtemp(f->root, sizeof f->root, "toolgen"))
        return false;
    snprintf(buf, sizeof buf,
             "ZCL_COMMAND_BRANCH(\"fleet\", \"\", \"Fleet\", ZCL_COMMAND_LAYER_OPS)\n"
             "ZCL_COMMAND_READY_READ(\n    \"fleet.old\", \"fleet\", \"\", \"Old\",\n"
             "    zcl_native_handle_fleet_old)\n%s\n" BEGIN_LINE("commands") END_LINE("commands"),
             def_x);
    bool ok = fx_puts(f, "engine/composition/commands/fleet.def", buf);
    snprintf(buf, sizeof buf, "#ifndef H\nvoid zcl_native_handle_fleet_old(void);\n%s\n"
             BEGIN_LINE("handlers") END_LINE("handlers") "#endif\n", hdr_x);
    ok = ok && fx_puts(f, "tools/command/native_fleet.h", buf);
    snprintf(buf, sizeof buf, "REMOTE_COMMAND_CLASS(\"fleet.old\", REMOTE_CLASS_READ_ONLY, \"a bounded read\")\n%s", rem_x);
    ok = ok && fx_puts(f, "engine/composition/remote_command_classes.def", buf);
    snprintf(buf, sizeof buf, "ZCL_TEST_GROUP(alpha)\nZCL_SPEC_GROUP(beta)\n%s\n"
             BEGIN_LINE("test-groups") END_LINE("test-groups") "ZCL_TEST_GROUP(omega)\n", cat_x);
    ok = ok && fx_puts(f, "tools/dev/test_group_catalog.def", buf);
    ok = ok && fx_puts(f, "tests/harness/src/test_read_leaf_no_datadir_write.c",
                       "static const int rows[] = {\n" BEGIN_LINE("datadir-leaves")
                       END_LINE("datadir-leaves") "};\n");
    return ok;
}

static bool fx_demo_test(const struct fx *f, const char *group, const char *path)
{
    char rel[128], text[256];
    snprintf(rel, sizeof rel, "tests/harness/src/test_%s.c", group);
    snprintf(text, sizeof text, "int test_%s(void);\nint test_%s(void)\n{\n    return !*\"%s\";\n}\n",
             group, group, path);
    return fx_puts(f, rel, text);
}

static bool fx_source(const struct fx *f, const char *file, const char *json, const char *handler)
{
    char rel[128], text[TG_OUT * 4u];
    snprintf(rel, sizeof rel, "tools/command/%s", file);
    snprintf(text, sizeof text, "/* Z23_TOOL_V1\n%s\n*/\n%s", json,
             handler ? handler : "");
    return fx_puts(f, rel, text);
}

static bool fx_demo(struct fx *f, const char *json)
{
    return fx_tree(f, "", "", "", "") && fx_source(f, "native_fleet_demo.c", json,
                                                    HANDLER_FN("zcl_native_handle_fleet_demo_list")) &&
           fx_demo_test(f, "fleet_demo", "fleet.demo.list");
}

static void fx_drop(struct fx *f)
{
    if (f->root[0])
        test_rm_rf_recursive(f->root);
}

static bool replace_once(const char *src, const char *from, const char *to, char *out, size_t cap)
{
    const char *at = strstr(src, from);
    if (!at)
        return false;
    int n = snprintf(out, cap, "%.*s%s%s", (int)(at - src), src, to, at + strlen(from));
    return n > 0 && (size_t)n < cap;
}

static bool has_error(const char *out, const char *code)
{
    char want[96];
    snprintf(want, sizeof want, "ERROR %s:", code);
    return strstr(out, want) != NULL;
}

/* ---- manifest refusals, one mutation of the valid manifest each ---- */

struct refusal {
    const char *from;
    const char *to;
    const char *code;
};

static const struct refusal k_refusals[] = {
    {"\"readonly-local-v1\"", "\"mutating-v1\"", "PROFILE_UNSUPPORTED"},
    {"\"cost\": \"low\"", "\"cost\": \"low\", \"frobnicate\": 1", "KEY_UNKNOWN"},
    {"\"cost\": \"low\"", "\"cost\": \"low\", \"cost\": \"tiny\"", "KEY_DUPLICATE"},
    {"\"cost\": \"low\"", "\"cost\": \"low\", \"effect\": \"mutate\"", "KEY_OUTSIDE_PROFILE"},
    {"\"cost\": \"low\"", "\"cost\": \"low\", \"remote_class\": \"read_only\"", "KEY_OUTSIDE_PROFILE"},
    {"\"cost\": \"low\"", "\"cost\": \"low\", \"module_capabilities\": [\"CAP_FS_WRITE\"]",
     "KEY_OUTSIDE_PROFILE"},
    {"\"cost\": \"low\"", "\"cost\": \"low\", \"dispatch_capabilities\": [\"process_exec\"]", "VALUE_BAD"},
    {"\"cost\": \"low\"", "\"cost\": \"low\", \"output\": \"../../x\"", "KEY_UNKNOWN"},
    {"\"path\": \"fleet.demo.list\"", "\"path\": \"Fleet.demo.list\"", "PATH_BAD"},
    {"\"path\": \"fleet.demo.list\"", "\"path\": \"fleet.demo/../list\"", "PATH_BAD"},
    {"\"path\": \"fleet.demo.list\"", "\"path\": \"other.demo.list\"", "PATH_FAMILY_UNSUPPORTED"},
    {"\"parent\": \"fleet.demo\"", "\"parent\": \"fleet.other\"", "PARENT_MISMATCH"},
    {"\"zcl_native_handle_fleet_demo_list\"", "\"evil_handler\"", "SYMBOL_BAD"},
    {"\"test_group\": \"fleet_demo\"", "\"test_group\": \"../fleet_demo\"", "TEST_GROUP_BAD"},
    {"\"summary\": \"Demo rows\",", "", "KEY_MISSING"},
    {"\"budget_bytes\": 4096", "\"budget_bytes\": \"big\"", "VALUE_BAD_TYPE"},
    {"\"cost\": \"low\"", "\"cost\": ", "MANIFEST_BAD_JSON"},
    {"\"operator\"", "\"root\"", "VALUE_BAD"},
    {"\"operator\"", "\"public\"", "VALUE_BAD"},
    {"\"Demo rows\"", "\"Demo \\u0007 rows\"", "VALUE_BAD"},
    {"\"z23 fleet demo list\"", "\"fleet demo list\"", "VALUE_BAD"},
    {"\"cost\": \"low\"", "\"cost\": \"low\", \"positional_keys\": [\"x\"]", "POSITIONAL_NOT_INPUT"},
    {"\"branch_summary\": \"Demo branch\",", "", "PARENT_UNKNOWN"},
};

static int test_tg_refusals(void)
{
    int failures = 0;
    for (size_t i = 0; i < sizeof k_refusals / sizeof k_refusals[0]; i++) {
        struct fx f = {0};
        char json[TG_OUT], out[TG_OUT];
        TEST("toolgen: a manifest mutation is refused by its named reason") {
            ASSERT(replace_once(VALID_JSON, k_refusals[i].from, k_refusals[i].to, json, sizeof json));
            ASSERT(fx_demo(&f, json));
            ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
            if (!has_error(out, k_refusals[i].code))
                printf("expected %s, got: %s\n", k_refusals[i].code, out);
            ASSERT(has_error(out, k_refusals[i].code));
            PASS();
        } _test_next:;
        fx_drop(&f);
    }
    return failures;
}

/* ---- collisions with authored and generated names ---- */

struct clash {
    const char *def_x, *hdr_x, *rem_x, *cat_x, *code;
};

static const struct clash k_clashes[] = {
    {"ZCL_COMMAND_READY_READ(\n    \"fleet.demo.list\", \"fleet.demo\", \"\")\n", "", "", "", "COLLISION_PATH"},
    {"", "", "REMOTE_COMMAND_CLASS(\"fleet.demo.list\", REMOTE_CLASS_NEVER, \"\")\n", "", "COLLISION_PATH"},
    {"", "void zcl_native_handle_fleet_demo_list(void);\n", "", "", "COLLISION_HANDLER"},
    {"", "", "", "ZCL_TEST_GROUP(fleet_demo)\n", "COLLISION_TEST_GROUP"},
    {"", "", "", "ZCL_SPEC_GROUP(fleet_demo)\n", "COLLISION_TEST_GROUP"},
    {"ZCL_COMMAND_BRANCH(\"fleet.demo\", \"fleet\", \"Hand\", ZCL_COMMAND_LAYER_OPS)\n", "", "", "",
     "COLLISION_BRANCH"},
};

static int test_tg_collisions(void)
{
    int failures = 0;
    for (size_t i = 0; i < sizeof k_clashes / sizeof k_clashes[0]; i++) {
        struct fx f = {0};
        char out[TG_OUT];
        TEST("toolgen: a name already registered by hand is refused") {
            ASSERT(fx_tree(&f, k_clashes[i].def_x, k_clashes[i].hdr_x, k_clashes[i].rem_x,
                           k_clashes[i].cat_x));
            ASSERT(fx_source(&f, "native_fleet_demo.c", VALID_JSON,
                             HANDLER_FN("zcl_native_handle_fleet_demo_list")));
            ASSERT(fx_demo_test(&f, "fleet_demo", "fleet.demo.list"));
            ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
            ASSERT(has_error(out, k_clashes[i].code));
            PASS();
        } _test_next:;
        fx_drop(&f);
    }
    return failures;
}

static int test_tg_generated_collisions(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT], json[TG_OUT], tmp[TG_OUT];
    TEST("toolgen: two sources declaring one command path are refused") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(replace_once(VALID_JSON, "zcl_native_handle_fleet_demo_list", "zcl_native_handle_fleet_other",
                            tmp, sizeof tmp));
        ASSERT(replace_once(tmp, "\"fleet_demo\"", "\"fleet_other\"", json, sizeof json));
        ASSERT(fx_source(&f, "native_fleet_other.c", json, HANDLER_FN("zcl_native_handle_fleet_other")));
        ASSERT(fx_demo_test(&f, "fleet_other", "fleet.demo.list"));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "COLLISION_PATH"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

/* ---- source, test and marker recognition ---- */

static bool put_raw_source(const struct fx *f, const char *text)
{
    return fx_puts(f, "tools/command/native_fleet_demo.c", text);
}

/* Runs --check on a demo tree whose source is replaced by `text`. */
static int check_raw(struct fx *f, const char *text, char *out, size_t cap)
{
    if (!fx_demo(f, VALID_JSON) || !put_raw_source(f, text))
        return -2;
    return fx_run(f, "--check", out, cap);
}

static int test_tg_handler_undefined(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: a handler that is declared but never defined is refused") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(fx_source(&f, "native_fleet_demo.c", VALID_JSON,
                         "void zcl_native_handle_fleet_demo_list(void);\n"));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "HANDLER_UNDEFINED"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_test_missing(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT], path[640];
    TEST("toolgen: a missing test source is refused") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(fx_path(&f, "tests/harness/src/test_fleet_demo.c", path, sizeof path));
        ASSERT(unlink(path) == 0);
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "TEST_SOURCE_MISSING"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_test_unrelated(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: a test that never names the command is refused") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(fx_demo_test(&f, "fleet_demo", "fleet.something.else"));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "TEST_NAMES_NOT_COMMAND"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_marker_in_string(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: a marker inside a string literal is not a manifest") {
        ASSERT(check_raw(&f, "const char *s = \"/* Z23_TOOL_V1 {} */\";\n", out, sizeof out) == 0);
        ASSERT(strstr(out, "check ok (0 manifests") != NULL);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_marker_after_literals(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT], src[TG_OUT * 2u];
    TEST("toolgen: digit separators and character literals do not hide the real marker") {
        snprintf(src, sizeof src, "int a = 1'000;\nchar q = '\"';\nchar r = u8'x';\n"
                 "const char *s = \"/* Z23_TOOL_V1 {} */\";\n/* Z23_TOOL_V1\n%s\n*/\n%s",
                 VALID_JSON, HANDLER_FN("zcl_native_handle_fleet_demo_list"));
        ASSERT(check_raw(&f, src, out, sizeof out) != 0);
        ASSERT(has_error(out, "BLOCK_DRIFT"));
        ASSERT(fx_run(&f, "--write", out, sizeof out) == 0);
        ASSERT(fx_run(&f, "--check", out, sizeof out) == 0);
        ASSERT(strstr(out, "check ok (1 manifest,") != NULL);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_marker_duplicate(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT], src[TG_OUT * 2u];
    TEST("toolgen: two marker comments in one source are refused") {
        snprintf(src, sizeof src, "/* Z23_TOOL_V1\n%s\n*/\n/* Z23_TOOL_V1\n%s\n*/\n", VALID_JSON,
                 VALID_JSON);
        ASSERT(check_raw(&f, src, out, sizeof out) != 0);
        ASSERT(has_error(out, "MARKER_DUPLICATE"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_marker_line_comment(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: a marker in a line comment is refused") {
        ASSERT(check_raw(&f, "// Z23_TOOL_V1 {}\n", out, sizeof out) != 0);
        ASSERT(has_error(out, "MARKER_NOT_BLOCK_COMMENT"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_unterminated_comment(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: a source that ends inside a comment is refused") {
        ASSERT(check_raw(&f, "int x;\n/* never closed\n", out, sizeof out) != 0);
        ASSERT(has_error(out, "LEX_UNTERMINATED_COMMENT"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

#define BIG_SOURCE (256u * 1024u + 64u)

static int test_tg_source_cap(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    char *text = malloc(BIG_SOURCE);
    TEST("toolgen: an over-size source that names the marker is refused") {
        ASSERT(text != NULL);
        ASSERT(fx_demo(&f, VALID_JSON));
        memset(text, ' ', BIG_SOURCE);
        memcpy(text, "/* Z23_TOOL_V1 */", 17);
        ASSERT(fx_put(&f, "tools/command/native_fleet_demo.c", text, BIG_SOURCE));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "SOURCE_TOO_LARGE"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    free(text);
    return failures;
}

static int test_tg_source_cap_unmarked(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    char *text = malloc(BIG_SOURCE);
    TEST("toolgen: an over-size source with no marker is ignored") {
        ASSERT(text != NULL);
        ASSERT(fx_demo(&f, VALID_JSON));
        memset(text, ' ', BIG_SOURCE);
        ASSERT(fx_put(&f, "tools/command/native_fleet_demo.c", text, BIG_SOURCE));
        ASSERT(fx_run(&f, "--check", out, sizeof out) == 0);
        PASS();
    } _test_next:;
    fx_drop(&f);
    free(text);
    return failures;
}

static int test_tg_manifest_cap(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    size_t pad = 17u * 1024u;
    char *src = malloc(pad + 128u);
    TEST("toolgen: an over-size manifest is refused") {
        ASSERT(src != NULL);
        ASSERT(fx_demo(&f, VALID_JSON));
        size_t n = (size_t)snprintf(src, 64, "/* Z23_TOOL_V1\n{\"pad\": \"");
        memset(src + n, 'a', pad);
        memcpy(src + n + pad, "\"}\n*/\n", 7);
        ASSERT(fx_put(&f, "tools/command/native_fleet_demo.c", src, n + pad + 6u));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "MANIFEST_TOO_LARGE"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    free(src);
    return failures;
}

static const char *const k_files[] = {
    "engine/composition/commands/fleet.def", "tools/command/native_fleet.h",
    "tools/dev/test_group_catalog.def",
    "tests/harness/src/test_read_leaf_no_datadir_write.c",
};

static bool snapshot(const struct fx *f, char (*bufs)[TG_OUT])
{
    for (size_t i = 0; i < 4; i++)
        if (!fx_get(f, k_files[i], bufs[i], TG_OUT))
            return false;
    return true;
}

#define OLD_MTIME 1000000000

/* Back-dates every registry file so a later rewrite is visible as a new mtime. */
static bool age_files(const struct fx *f)
{
    struct utimbuf old = {.actime = OLD_MTIME, .modtime = OLD_MTIME};
    for (size_t i = 0; i < 4; i++) {
        char path[640];
        if (!fx_path(f, k_files[i], path, sizeof path) || utime(path, &old) != 0)
            return false;
    }
    return true;
}

static bool all_aged(const struct fx *f)
{
    for (size_t i = 0; i < 4; i++) {
        char path[640];
        struct stat st;
        if (!fx_path(f, k_files[i], path, sizeof path) || stat(path, &st) != 0 ||
            st.st_mtime != OLD_MTIME)
            return false;
    }
    return true;
}

static int test_tg_write_content(void)
{
    int failures = 0;
    struct fx f = {0};
    static char before[4][TG_OUT], after[4][TG_OUT];
    char out[TG_OUT];
    TEST("toolgen: --write expands the manifest into every block and keeps authored bytes") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(snapshot(&f, before));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "BLOCK_DRIFT"));
        ASSERT(fx_run(&f, "--write", out, sizeof out) == 0);
        ASSERT(snapshot(&f, after));
        {
            char remote[TG_OUT];
            ASSERT(fx_get(&f, "engine/composition/remote_command_classes.def", remote, sizeof remote));
            ASSERT(strstr(remote, "fleet.demo.list") == NULL);
            ASSERT(strstr(remote, "z23-toolgen") == NULL);
        }
        ASSERT(strstr(after[0], "ZCL_COMMAND_BRANCH(\"fleet.demo\", \"fleet\",") != NULL);
        ASSERT(strstr(after[0], "\"fleet.demo.list\", \"fleet.demo\", \"\",") != NULL);
        ASSERT(strstr(after[0], "ZCL_COMMAND_AUTH_OPERATOR, ZCL_COMMAND_LATENCY_FAST") != NULL);
        ASSERT(strstr(after[0], "ZCL_COMMAND_CAP_NONE, ZCL_COMMAND_TRAIT_IDEMPOTENT") != NULL);
        ASSERT(strstr(after[0], "ZCL_COMMAND_TRANSPORT_NATIVE, zcl_native_handle_fleet_demo_list)") != NULL);
        ASSERT(strstr(after[1], "void zcl_native_handle_fleet_demo_list(") != NULL);
        ASSERT(strstr(after[2], "ZCL_TEST_GROUP(fleet_demo)\n" END_LINE("test-groups") "ZCL_TEST_GROUP(omega)") != NULL);
        ASSERT(strstr(after[3], "{ \"fleet.demo.list\",") != NULL);
        for (size_t i = 0; i < 4; i++) {
            const char *begin = strstr(after[i], "/* z23-toolgen:begin");
            ASSERT(begin != NULL);
            ASSERT(strncmp(before[i], after[i], (size_t)(begin - after[i])) == 0);
            const char *tail = strstr(before[i], "/* z23-toolgen:end");
            const char *tail2 = strstr(after[i], "/* z23-toolgen:end");
            ASSERT(tail && tail2 && strcmp(tail, tail2) == 0);
        }
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_idempotent(void)
{
    int failures = 0;
    struct fx f = {0};
    static char first[4][TG_OUT], second[4][TG_OUT];
    char out[TG_OUT];
    TEST("toolgen: a repeated --write is byte-identical and touches no mtime") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(fx_run(&f, "--write", out, sizeof out) == 0);
        ASSERT(snapshot(&f, first) && age_files(&f));
        ASSERT(fx_run(&f, "--write", out, sizeof out) == 0);
        ASSERT(strstr(out, "nothing to change") != NULL);
        ASSERT(snapshot(&f, second) && all_aged(&f));
        for (size_t i = 0; i < 4; i++)
            ASSERT(strcmp(first[i], second[i]) == 0);
        ASSERT(fx_run(&f, "--check", out, sizeof out) == 0);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static bool edit_file(const struct fx *f, const char *rel, const char *from, const char *to)
{
    char text[TG_OUT], edited[TG_OUT];
    return fx_get(f, rel, text, sizeof text) && replace_once(text, from, to, edited, sizeof edited) &&
           fx_puts(f, rel, edited);
}

static bool written_demo(struct fx *f)
{
    char out[TG_OUT];
    return fx_demo(f, VALID_JSON) && fx_run(f, "--write", out, sizeof out) == 0;
}

static int test_tg_drift_hand_edit(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: --check catches a hand edit inside a generated block") {
        ASSERT(written_demo(&f));
        ASSERT(edit_file(&f, k_files[0], "ZCL_COMMAND_AUTH_OPERATOR", "ZCL_COMMAND_AUTH_PUBLIC"));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "BLOCK_DRIFT"));
        ASSERT(strstr(out, "fleet.def") != NULL);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_drift_missing_block(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: --check catches a missing block") {
        ASSERT(written_demo(&f));
        ASSERT(edit_file(&f, k_files[2], "/* z23-toolgen:begin test-groups - generated, do not edit */\n", ""));
        ASSERT(edit_file(&f, k_files[2], "/* z23-toolgen:end test-groups */\n", ""));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "BLOCK_MISSING"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_drift_malformed_block(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: --check catches a malformed block") {
        ASSERT(written_demo(&f));
        ASSERT(edit_file(&f, k_files[1], "/* z23-toolgen:end handlers */\n", ""));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "BLOCK_MALFORMED"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_drift_mixed(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: --check catches a mixed generation") {
        ASSERT(written_demo(&f));
        ASSERT(edit_file(&f, k_files[2], "ZCL_TEST_GROUP(fleet_demo)\n", ""));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "MIXED_GENERATION"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_write_invalid(void)
{
    int failures = 0;
    struct fx f = {0};
    static char before[4][TG_OUT], after[4][TG_OUT];
    char out[TG_OUT], json[TG_OUT];
    TEST("toolgen: --write changes nothing when a manifest is invalid") {
        ASSERT(replace_once(VALID_JSON, "\"operator\"", "\"root\"", json, sizeof json));
        ASSERT(fx_demo(&f, json));
        ASSERT(snapshot(&f, before));
        ASSERT(fx_run(&f, "--write", out, sizeof out) != 0);
        ASSERT(snapshot(&f, after));
        for (size_t i = 0; i < 4; i++)
            ASSERT(strcmp(before[i], after[i]) == 0);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_write_locked(void)
{
    int failures = 0;
    struct fx f = {0};
    static char before[4][TG_OUT], after[4][TG_OUT];
    char out[TG_OUT];
    TEST("toolgen: --write refuses while another writer holds the lock") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(fx_puts(&f, "build/z23-toolgen.lock", ""));
        ASSERT(snapshot(&f, before));
        ASSERT(fx_run(&f, "--write", out, sizeof out) != 0);
        ASSERT(has_error(out, "WRITER_BUSY"));
        ASSERT(snapshot(&f, after));
        for (size_t i = 0; i < 4; i++)
            ASSERT(strcmp(before[i], after[i]) == 0);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_second_command(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT], json[TG_OUT], tmp[TG_OUT], cat[TG_OUT], def[TG_OUT];
    TEST("toolgen: a second command shares the generated branch and keeps catalog order") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(fx_run(&f, "--write", out, sizeof out) == 0);
        ASSERT(replace_once(VALID_JSON, "fleet.demo.list", "fleet.demo.show", json, sizeof json));
        ASSERT(replace_once(json, "\"branch_summary\": \"Demo branch\",", "", tmp, sizeof tmp));
        ASSERT(replace_once(tmp, "zcl_native_handle_fleet_demo_list", "zcl_native_handle_fleet_demo_show",
                            json, sizeof json));
        ASSERT(replace_once(json, "\"fleet_demo\"", "\"aaa_demo\"", tmp, sizeof tmp));
        ASSERT(fx_source(&f, "native_fleet_demo_show.c", tmp,
                         HANDLER_FN("zcl_native_handle_fleet_demo_show")));
        ASSERT(fx_demo_test(&f, "aaa_demo", "fleet.demo.show"));
        ASSERT(fx_run(&f, "--write", out, sizeof out) == 0);
        ASSERT(fx_run(&f, "--check", out, sizeof out) == 0);
        ASSERT(fx_get(&f, k_files[2], cat, sizeof cat));
        const char *first = strstr(cat, "ZCL_TEST_GROUP(fleet_demo)");
        const char *second = strstr(cat, "ZCL_TEST_GROUP(aaa_demo)");
        ASSERT(first && second && first < second);
        ASSERT(fx_get(&f, k_files[0], def, sizeof def));
        const char *branch = strstr(def, "ZCL_COMMAND_BRANCH(\"fleet.demo\"");
        ASSERT(branch && strstr(branch + 1, "ZCL_COMMAND_BRANCH(\"fleet.demo\"") == NULL);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

/* ---- emission of hostile text, diagnostics, authority and capabilities ---- */

static int test_tg_escaped_emission(void)
{
    int failures = 0;
    struct fx f = {0};
    char a[TG_OUT], b[TG_OUT], out[TG_OUT], def[TG_OUT];
    TEST("toolgen: quotes, backslashes, comment closers and trigraph-like text are emitted escaped") {
        ASSERT(replace_once(VALID_JSON, "\"summary\": \"Demo rows\"",
                            "\"summary\": \"a\\\"b\\\\c*\\/d?" "?/e\"", a, sizeof a));
        ASSERT(replace_once(a, "\"semantics\": [\"Lists \", \"the demo rows.\"]",
                            "\"semantics\": [\"Lists \", \"x\\\"y\\\\z*\\/w?" "?/\"]", b, sizeof b));
        ASSERT(replace_once(b, "\"example\": \"z23 fleet demo list\"",
                            "\"example\": \"z23 \\\"q\\\" \\\\ *\\/ ?" "?/\"", a, sizeof a));
        ASSERT(replace_once(a, "\"branch_summary\": \"Demo branch\"",
                            "\"branch_summary\": \"B\\\"r\\\\*\\/?" "?/\"", b, sizeof b));
        ASSERT(fx_demo(&f, b));
        ASSERT(fx_run(&f, "--write", out, sizeof out) == 0);
        ASSERT(fx_run(&f, "--check", out, sizeof out) == 0);
        ASSERT(fx_get(&f, k_files[0], def, sizeof def));
        ASSERT(strstr(def, "\n    \"a\\\"b\\\\c*/d?" "?/e\",\n") != NULL);
        ASSERT(strstr(def, "\n    \"Lists x\\\"y\\\\z*/w?" "?/\",\n") != NULL);
        ASSERT(strstr(def, "\n    \"z23 \\\"q\\\" \\\\ */ ?" "?/\",\n") != NULL);
        ASSERT(strstr(def, "\n    \"B\\\"r\\\\*/?" "?/\",\n") != NULL);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_diagnostics_escaped(void)
{
    int failures = 0;
    struct fx f = {0};
    char json[TG_OUT], out[TG_OUT];
    TEST("toolgen: a diagnostic carries manifest bytes escaped, never raw") {
        ASSERT(replace_once(VALID_JSON, "\"cost\": \"low\"",
                            "\"cost\": \"low\", \"bad\\u0001key\": 1", json, sizeof json));
        ASSERT(fx_demo(&f, json));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "KEY_UNKNOWN"));
        ASSERT(strstr(out, "bad\\x01key") != NULL);
        ASSERT(strchr(out, '\001') == NULL);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_capabilities_required(void)
{
    int failures = 0;
    struct fx f = {0};
    char json[TG_OUT], out[TG_OUT], def[TG_OUT];
    TEST("toolgen: dispatch_capabilities are emitted as the capabilities the caller must hold") {
        ASSERT(replace_once(VALID_JSON, "\"cost\": \"low\"",
                            "\"cost\": \"low\", \"dispatch_capabilities\": [\"chain_read\", \"dev_state_read\"]",
                            json, sizeof json));
        ASSERT(fx_demo(&f, json));
        ASSERT(fx_run(&f, "--write", out, sizeof out) == 0);
        ASSERT(fx_get(&f, k_files[0], def, sizeof def));
        ASSERT(strstr(def, "    ZCL_COMMAND_CAP_CHAIN_READ | ZCL_COMMAND_CAP_DEV_STATE_READ, "
                           "ZCL_COMMAND_TRAIT_IDEMPOTENT,\n") != NULL);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

/* ---- branch and leaf graph ---- */

static void variant_json(char *out, size_t cap, const char *path, const char *parent,
                         bool branch, const char *tag)
{
    snprintf(out, cap,
             "{\"profile\":\"readonly-local-v1\",\"path\":\"%s\",\"parent\":\"%s\",%s"
             "\"handler\":\"zcl_native_handle_%s\",\"summary\":\"S\",\"semantics\":[\"Sem\"],"
             "\"input_schema\":\"zcl.v_in.v1\",\"output_schema\":\"zcl.v_out.v1\","
             "\"input_keys\":[],\"example\":\"z23 v\",\"tags\":[\"v\"],\"authority\":\"owner\","
             "\"budget_bytes\":2048,\"latency\":\"fast\",\"cost\":\"low\",\"test_group\":\"g_%s\"}",
             path, parent, branch ? "\"branch_summary\":\"B\"," : "", tag, tag);
}

static bool add_variant(const struct fx *f, const char *path, const char *parent, bool branch,
                        const char *tag)
{
    char json[TG_OUT], file[96], fn[160], group[96];
    variant_json(json, sizeof json, path, parent, branch, tag);
    snprintf(file, sizeof file, "native_%s.c", tag);
    snprintf(fn, sizeof fn, "void zcl_native_handle_%s(void)\n{\n}\n", tag);
    snprintf(group, sizeof group, "g_%s", tag);
    return fx_source(f, file, json, fn) && fx_demo_test(f, group, path);
}

static int test_tg_leaf_on_branch_path(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: a command path equal to another manifest's generated branch is refused") {
        ASSERT(fx_tree(&f, "", "", "", ""));
        ASSERT(add_variant(&f, "fleet.a.leaf", "fleet.a", true, "one"));
        ASSERT(add_variant(&f, "fleet.a", "fleet", false, "two"));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "COLLISION_BRANCH"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_parent_is_leaf(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: a parent that is another manifest's generated leaf is refused") {
        ASSERT(fx_tree(&f, "", "", "", ""));
        ASSERT(add_variant(&f, "fleet.q.leaf", "fleet.q", true, "one"));
        ASSERT(add_variant(&f, "fleet.q.leaf.x", "fleet.q.leaf", false, "two"));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "PARENT_IS_LEAF"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_branch_chain(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT], def[TG_OUT];
    TEST("toolgen: a two-level branch chain is emitted parent before child") {
        ASSERT(fx_tree(&f, "", "", "", ""));
        ASSERT(add_variant(&f, "fleet.a.b.c", "fleet.a.b", true, "deep"));
        ASSERT(add_variant(&f, "fleet.a.w", "fleet.a", true, "shallow"));
        ASSERT(fx_run(&f, "--write", out, sizeof out) == 0);
        ASSERT(fx_run(&f, "--check", out, sizeof out) == 0);
        ASSERT(fx_get(&f, k_files[0], def, sizeof def));
        const char *outer = strstr(def, "ZCL_COMMAND_BRANCH(\"fleet.a\",");
        const char *inner = strstr(def, "ZCL_COMMAND_BRANCH(\"fleet.a.b\",");
        ASSERT(outer && inner && outer < inner);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_branch_without_grandparent(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: a generated branch whose own parent does not exist is refused") {
        ASSERT(fx_tree(&f, "", "", "", ""));
        ASSERT(add_variant(&f, "fleet.a.b.c", "fleet.a.b", true, "deep"));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "PARENT_UNKNOWN"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

/* ---- writer robustness ---- */

static int test_tg_stale_lock(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT], path[640];
    TEST("toolgen: a lock held by a pid that no longer exists is reclaimed") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(fx_puts(&f, "build/z23-toolgen.lock", "2000000000\n"));
        ASSERT(fx_run(&f, "--write", out, sizeof out) == 0);
        ASSERT(fx_path(&f, "build/z23-toolgen.lock", path, sizeof path));
        ASSERT(access(path, F_OK) != 0);
        ASSERT(fx_run(&f, "--check", out, sizeof out) == 0);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static void set_mode(const struct fx *f, const char *rel, mode_t mode)
{
    char path[640];
    if (fx_path(f, rel, path, sizeof path))
        chmod(path, mode);
}

static int test_tg_partial_write(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: a write that fails on the third target leaves a state --check calls mixed") {
        ASSERT(fx_demo(&f, VALID_JSON));
        set_mode(&f, "tools/dev", 0555);
        if (geteuid() == 0) {
            printf("toolgen: running as root; directory permissions cannot force the failure\n");
        } else {
            ASSERT(fx_run(&f, "--write", out, sizeof out) != 0);
            ASSERT(has_error(out, "WRITE_FAILED"));
            set_mode(&f, "tools/dev", 0755);
            ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
            ASSERT(has_error(out, "MIXED_GENERATION"));
            ASSERT(fx_run(&f, "--write", out, sizeof out) == 0);
            ASSERT(fx_run(&f, "--check", out, sizeof out) == 0);
        }
        PASS();
    } _test_next:;
    set_mode(&f, "tools/dev", 0755);
    fx_drop(&f);
    return failures;
}

/* ---- fail closed on target and source shape ---- */

static int test_tg_crlf_target(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: a target with CRLF line endings is refused") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(fx_puts(&f, k_files[2], "ZCL_TEST_GROUP(alpha)\r\n"
                       "/* z23-toolgen:begin test-groups - generated, do not edit */\r\n"
                       "/* z23-toolgen:end test-groups */\r\n"));
        ASSERT(fx_run(&f, "--write", out, sizeof out) != 0);
        ASSERT(has_error(out, "BLOCK_MALFORMED"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_symlink_target(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT], link[640], dest[640];
    TEST("toolgen: a symlinked target is refused") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(fx_path(&f, k_files[2], link, sizeof link));
        ASSERT(fx_path(&f, "elsewhere.def", dest, sizeof dest));
        ASSERT(rename(link, dest) == 0);
        ASSERT(symlink(dest, link) == 0);
        ASSERT(fx_run(&f, "--write", out, sizeof out) != 0);
        ASSERT(has_error(out, "SOURCE_NOT_REGULAR"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_no_trailing_newline(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT], text[TG_OUT];
    TEST("toolgen: a target whose last line has no newline is rewritten without adding one") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(fx_puts(&f, k_files[2], "ZCL_TEST_GROUP(alpha)\n" BEGIN_LINE("test-groups")
                       "/* z23-toolgen:end test-groups */"));
        ASSERT(fx_run(&f, "--write", out, sizeof out) == 0);
        ASSERT(fx_get(&f, k_files[2], text, sizeof text));
        ASSERT(strstr(text, "ZCL_TEST_GROUP(fleet_demo)\n/* z23-toolgen:end test-groups */") != NULL);
        ASSERT(text[strlen(text) - 1u] == '/');
        ASSERT(fx_run(&f, "--check", out, sizeof out) == 0);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_doc_comment(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT], src[TG_OUT * 2u];
    TEST("toolgen: a doc-style /** marker is refused, not ignored") {
        snprintf(src, sizeof src, "/** Z23_TOOL_V1\n%s\n*/\n", VALID_JSON);
        ASSERT(check_raw(&f, src, out, sizeof out) != 0);
        ASSERT(has_error(out, "MARKER_DOC_COMMENT"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_conditional_marker(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT], src[TG_OUT * 2u];
    TEST("toolgen: a marker inside #if is refused; one after a closed #if is read") {
        snprintf(src, sizeof src, "#if 0\n/* Z23_TOOL_V1\n%s\n*/\n#endif\n", VALID_JSON);
        ASSERT(check_raw(&f, src, out, sizeof out) != 0);
        ASSERT(has_error(out, "MARKER_CONDITIONAL"));
        snprintf(src, sizeof src, "#if 0\n#endif\n/* Z23_TOOL_V1\n%s\n*/\n%s", VALID_JSON,
                 HANDLER_FN("zcl_native_handle_fleet_demo_list"));
        ASSERT(check_raw(&f, src, out, sizeof out) != 0);
        ASSERT(has_error(out, "BLOCK_DRIFT"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_dotfile_source(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: a dot file in the source directory is skipped") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(fx_puts(&f, "tools/command/.#native_fleet_demo.c", "// Z23_TOOL_V1 {}\n"));
        ASSERT(fx_run(&f, "--write", out, sizeof out) == 0);
        ASSERT(fx_run(&f, "--check", out, sizeof out) == 0);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_source_name(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: a source file name outside the plain set is refused") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(fx_puts(&f, "tools/command/native$x.c", "int x;\n"));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "SOURCE_NAME_BAD"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

/* ---- orphans and test evidence ---- */

static int test_tg_orphan_rows(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT], path[640];
    TEST("toolgen: rows whose source was deleted fail --check as drift") {
        ASSERT(written_demo(&f));
        ASSERT(fx_path(&f, "tools/command/native_fleet_demo.c", path, sizeof path));
        ASSERT(unlink(path) == 0);
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "BLOCK_DRIFT"));
        ASSERT(fx_run(&f, "--write", out, sizeof out) == 0);
        ASSERT(fx_run(&f, "--check", out, sizeof out) == 0);
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

static int test_tg_test_names_in_comment(void)
{
    int failures = 0;
    struct fx f = {0};
    char out[TG_OUT];
    TEST("toolgen: a test that names the command only in a comment is refused") {
        ASSERT(fx_demo(&f, VALID_JSON));
        ASSERT(fx_puts(&f, "tests/harness/src/test_fleet_demo.c",
                       "int test_fleet_demo(void);\nint test_fleet_demo(void)\n{\n"
                       "    /* \"fleet.demo.list\" */\n    return 0;\n}\n"));
        ASSERT(fx_run(&f, "--check", out, sizeof out) != 0);
        ASSERT(has_error(out, "TEST_NAMES_NOT_COMMAND"));
        PASS();
    } _test_next:;
    fx_drop(&f);
    return failures;
}

#endif /* !_WIN32 */

int test_toolgen(void);
int test_toolgen(void)
{
    int failures = 0;
#if !defined(_WIN32)
    failures += test_tg_refusals();
    failures += test_tg_collisions();
    failures += test_tg_generated_collisions();
    failures += test_tg_handler_undefined();
    failures += test_tg_test_missing();
    failures += test_tg_test_unrelated();
    failures += test_tg_marker_in_string();
    failures += test_tg_marker_after_literals();
    failures += test_tg_marker_duplicate();
    failures += test_tg_marker_line_comment();
    failures += test_tg_unterminated_comment();
    failures += test_tg_source_cap();
    failures += test_tg_source_cap_unmarked();
    failures += test_tg_manifest_cap();
    failures += test_tg_write_content();
    failures += test_tg_idempotent();
    failures += test_tg_drift_hand_edit();
    failures += test_tg_drift_missing_block();
    failures += test_tg_drift_malformed_block();
    failures += test_tg_drift_mixed();
    failures += test_tg_write_invalid();
    failures += test_tg_write_locked();
    failures += test_tg_second_command();
    failures += test_tg_escaped_emission();
    failures += test_tg_diagnostics_escaped();
    failures += test_tg_capabilities_required();
    failures += test_tg_leaf_on_branch_path();
    failures += test_tg_parent_is_leaf();
    failures += test_tg_branch_chain();
    failures += test_tg_branch_without_grandparent();
    failures += test_tg_stale_lock();
    failures += test_tg_partial_write();
    failures += test_tg_crlf_target();
    failures += test_tg_symlink_target();
    failures += test_tg_no_trailing_newline();
    failures += test_tg_doc_comment();
    failures += test_tg_conditional_marker();
    failures += test_tg_dotfile_source();
    failures += test_tg_source_name();
    failures += test_tg_orphan_rows();
    failures += test_tg_test_names_in_comment();
#else
    printf("test_toolgen: the generator is a POSIX-hosted tool; not built here\n");
#endif
    if (failures == 0)
        printf("test_toolgen: all passed\n");
    else
        printf("test_toolgen: %d FAILED\n", failures);
    return failures;
}

