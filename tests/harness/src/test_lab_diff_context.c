/* Purpose: Preserve exact differing bytes and bounded lab receipt diagnostics. */
#include "test/test_core.h"
#include "command/lab.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "util/file_tree_ops.h"

static bool diff_input(struct json_value *input, const char *mode,
                        const char *expected, size_t count)
{
    struct json_value cases;
    json_init(&cases);
    json_set_array(&cases);
    json_set_object(input);
    bool ok = true;
    for (size_t index = 0; ok && index < count; index++) {
        struct json_value row, args, value;
        char name[32];
        snprintf(name, sizeof(name), "case-%zu", index);
        json_init(&row);
        json_init(&args);
        json_init(&value);
        json_set_object(&row);
        json_set_array(&args);
        json_set_str(&value, mode);
        ok = value.type == JSON_STR && json_push_back(&args, &value) &&
            json_push_kv_str(&row, "name", name) && json_push_kv(&row, "args", &args) &&
            json_push_kv_str(&row, "expect_stdout", expected) && json_push_back(&cases, &row);
        json_free(&value);
        json_free(&args);
        json_free(&row);
    }
    ok = ok && json_push_kv(input, "cases", &cases) &&
        json_push_kv_str(input, "file", "tests/fixtures/lab/diff_context.c") &&
        json_push_kv_bool(input, "sanitize", false);
    json_free(&cases);
    return ok;
}

static bool diff_call(const struct json_value *input, struct json_value *envelope)
{
    const struct zcl_command_registry *registry = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(registry, "lab.test", NULL);
    if (!spec)
        return false;
    struct zcl_command_context context = {
        .registry = registry, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    char output[65537];
    enum zcl_command_exit code;
    size_t length = zcl_command_registry_execute_json(registry, spec, &context, input,
        false, spec->path, "normal", 0, 0, NULL, output, sizeof(output), &code);
    return length && length < sizeof(output) && json_read(envelope, output, length);
}

static bool diff_unconfined(const struct json_value *envelope)
{
    const struct json_value *code = json_get(json_get(envelope, "error"), "code");
    return code && code->type == JSON_STR && strcmp(json_get_str(code), "LAB_UNCONFINED") == 0;
}

static const char *diff_first(const struct json_value *envelope)
{
    const struct json_value *rows = json_get(json_get(envelope, "data"), "cases");
    return json_get_str(json_get(json_at(rows, 0), "diff"));
}

static int diff_controls(void)
{
    int failures = 0;
    TEST("lab preserves short ASCII diffs and identifies late, NUL and original non-ASCII bytes") {
        char late[259], line2[264], eof[258];
        memset(late, 'a', 256);
        memcpy(late + 256, "X\n", 3);
        memcpy(line2, "same\n", 5);
        memcpy(line2 + 5, late, sizeof(late));
        memset(eof, 'a', 256);
        memcpy(eof + 256, "\n", 2);
        const struct { const char *mode, *expected, *needle; } controls[] = {
            { "short", "beta\n", "line 1: expected \"beta\\n\" got \"alpha\\n\"" },
            { "late", late, "byte 257: expected \\x58 got \\x59" },
            { "line2", line2, "line 2, byte 257:" },
            { "nul", "headX\n", "byte 5: expected \\x58 got \\x00" },
            { "nul", "head", "byte 5: expected EOF got \\x00" },
            { "invalid", "X\n", "byte 1: expected \\x58 got \\xFF" },
            { "replacement", "X\n", "byte 1: expected \\x58 got \\xEF" },
            { "invalid", "\xef\xbf\xbd\n", "byte 1: expected \\xEF got \\xFF" },
            { "late-eof", eof, "byte 257: expected LF got EOF" },
            { "short", "alpha\\n", "byte 6: expected \\x5C got LF" },
            { "short", "alpha\n<end of output>", "line 2, byte 1: expected \\x3C got EOF" },
        };
        for (size_t index = 0; index < sizeof(controls) / sizeof(controls[0]); index++) {
            struct json_value input, envelope;
            json_init(&input);
            json_init(&envelope);
            ASSERT(diff_input(&input, controls[index].mode, controls[index].expected, 1));
            ASSERT(diff_call(&input, &envelope));
            if (!lab_confinement_available()) {
                ASSERT(diff_unconfined(&envelope));
            } else {
                const struct json_value *data = json_get(&envelope, "data");
                ASSERT(json_get_bool(json_get(&envelope, "ok")));
                ASSERT_EQ(json_get_int(json_get(data, "failed")), 1);
                const char *text = diff_first(&envelope);
                ASSERT(text && strstr(text, controls[index].needle));
                if (index == 0)
                    ASSERT(strcmp(text, controls[index].needle) == 0);
                if (index == 6)
                    ASSERT(strstr(text, "\\xEF\\xBF\\xBD"));
                ASSERT(json_write(json_get(json_at(json_get(data, "cases"), 0), "diff"), NULL, 0) - 2 <= 512);
            }
            json_free(&envelope);
            json_free(&input);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int diff_matching(void)
{
    int failures = 0;
    TEST("lab keeps matching ASCII and valid replacement-character output passing") {
        const char *modes[] = { "short", "replacement" };
        const char *expected[] = { "alpha\n", "\xef\xbf\xbd\n" };
        for (size_t index = 0; index < 2; index++) {
            struct json_value input, envelope;
            json_init(&input);
            json_init(&envelope);
            ASSERT(diff_input(&input, modes[index], expected[index], 1));
            ASSERT(diff_call(&input, &envelope));
            if (!lab_confinement_available()) {
                ASSERT(diff_unconfined(&envelope));
            } else {
                const struct json_value *data = json_get(&envelope, "data");
                ASSERT(json_get_bool(json_get(&envelope, "ok")));
                ASSERT_EQ(json_get_int(json_get(data, "passed")), 1);
                ASSERT_EQ(json_get_int(json_get(data, "failed")), 0);
                ASSERT(strcmp(diff_first(&envelope), "") == 0);
            }
            json_free(&envelope);
            json_free(&input);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int diff_budget(void)
{
    int failures = 0;
    TEST("lab byte context preserves verdicts and escaped diagnostic budgets for 256 cases and cache replay") {
        struct json_value input, first, cached;
        json_init(&input);
        json_init(&first);
        json_init(&cached);
        ASSERT(diff_input(&input, "binary", "X\n", 256));
        ASSERT(diff_call(&input, &first));
        if (!lab_confinement_available()) {
            ASSERT(diff_unconfined(&first));
        } else {
            const struct json_value *data = json_get(&first, "data");
            const struct json_value *rows = json_get(data, "cases");
            ASSERT(json_get_bool(json_get(&first, "ok")));
            ASSERT_EQ(json_get_int(json_get(data, "failed")), 256);
            ASSERT(rows && rows->num_children == 256);
            size_t escaped = 0;
            for (size_t index = 0; index < rows->num_children; index++) {
                size_t cost = json_write(json_get(&rows->children[index], "diff"), NULL, 0) - 2;
                ASSERT(cost <= 512);
                escaped += cost;
                ASSERT(!json_get_bool(json_get(&rows->children[index], "pass")));
                ASSERT_EQ(json_get_int(json_get(&rows->children[index], "exit_code")), 0);
            }
            ASSERT(escaped <= 16 * 1024);
            ASSERT(json_get_int(json_get(data, "diffs_omitted")) > 0);
            size_t compiles = lab_compile_count(), runs = lab_run_count();
            ASSERT(diff_call(&input, &cached));
            const struct json_value *again = json_get(&cached, "data");
            ASSERT(json_get_bool(json_get(json_get(again, "cache"), "hit")));
            ASSERT(strcmp(diff_first(&first), diff_first(&cached)) == 0);
            ASSERT_EQ(lab_compile_count(), compiles);
            ASSERT_EQ(lab_run_count(), runs);
        }
        json_free(&cached);
        json_free(&first);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

int test_lab_diff_context(void)
{
    char directory[512];
    test_fmt_tmpdir(directory, sizeof(directory), "lab-diff-context", "state");
    if (!test_ensure_tmproot() || mkdir(directory, 0700) != 0 || setenv("Z23_LAB_DIR", directory, 1) != 0)
        return 1;
    int failures = diff_controls();
    failures += diff_matching();
    failures += diff_budget();
    (void)unsetenv("Z23_LAB_DIR");
    (void)zcl_tree_remove(directory);
    return failures;
}
