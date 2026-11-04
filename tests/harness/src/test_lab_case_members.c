/* Purpose: Reject ambiguous decoded case members before lab work begins. */
#include "test/test_core.h"
#include "command/lab.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "util/file_tree_ops.h"

static char member_directory[512], member_state[600];

static bool member_input(struct json_value *input, const char *cases, unsigned form)
{
    struct json_value array;
    json_init(&array);
    json_set_object(input);
    bool ok = json_push_kv_str(input, "file", "tests/fixtures/lab/hello.c") &&
        json_push_kv_bool(input, "sanitize", false);
    if (form == 0) {
        ok = ok && json_read(&array, cases, strlen(cases)) && json_push_kv(input, "cases", &array);
    } else if (form == 1) {
        ok = ok && json_push_kv_str(input, "cases", cases);
    } else {
        char path[600];
        snprintf(path, sizeof(path), "%s/cases.json", member_directory);
        FILE *file = fopen(path, "wb");
        bool written = file && fwrite(cases, 1, strlen(cases), file) == strlen(cases);
        int closed = file ? fclose(file) : -1;
        ok = ok && written && closed == 0 && json_push_kv_str(input, "cases", path);
    }
    json_free(&array);
    return ok;
}

static bool member_call(const char *command, const struct json_value *input,
                         struct json_value *envelope)
{
    const struct zcl_command_registry *registry = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(registry, command, NULL);
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

static bool member_refused(const struct json_value *envelope, const char *code)
{
    const struct json_value *value = json_get(json_get(envelope, "error"), "code");
    return value && value->type == JSON_STR && strcmp(json_get_str(value), code) == 0;
}

static int member_duplicates(void)
{
    int failures = 0;
    TEST("lab rejects every duplicate decoded case member in array, inline and file inputs before work") {
        static const struct { const char *key, *escaped, *first, *last; } fields[] = {
            { "name", "na\\u006de", "\"case\"", "\"other\"" },
            { "stdin", "std\\u0069n", "\"one\"", "\"two\"" },
            { "args", "ar\\u0067s", "[\"one\"]", "[\"two\"]" },
            { "expect_stdout", "expect_std\\u006fut", "\"hello, lab\\n\"", "\"wrong\"" },
            { "expect_exit", "expect_\\u0065xit", "0", "7" },
        };
        for (unsigned form = 0; form < 3; form++) {
            for (size_t field = 0; field < sizeof(fields) / sizeof(fields[0]); field++) {
                for (unsigned escaped = 0; escaped < 2; escaped++) {
                    char cases[512];
                    snprintf(cases, sizeof(cases), "[{%s\"%s\":%s,\"%s\":%s}]",
                        field ? "\"name\":\"case\"," : "", fields[field].key, fields[field].first,
                        escaped ? fields[field].escaped : fields[field].key, fields[field].last);
                    struct json_value input, envelope;
                    json_init(&input);
                    json_init(&envelope);
                    ASSERT(member_input(&input, cases, form));
                    size_t compiles = lab_compile_count(), runs = lab_run_count();
                    ASSERT(member_call("lab.test", &input, &envelope));
                    ASSERT(member_refused(&envelope, "LAB_BAD_CASES"));
                    ASSERT_EQ(lab_compile_count(), compiles);
                    ASSERT_EQ(lab_run_count(), runs);
                    ASSERT(json_get(json_get(&envelope, "data"), "root") == NULL);
                    struct stat state;
                    ASSERT(stat(member_state, &state) != 0 && errno == ENOENT);
                    json_free(&envelope);
                    json_free(&input);
                }
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

static int member_promote(void)
{
    int failures = 0;
    TEST("lab promote rejects ambiguous cases before compiler, key or output side effects") {
        char key[600], output[600];
        snprintf(key, sizeof(key), "%s/inert.key", member_directory);
        snprintf(output, sizeof(output), "%s/uncreated-output", member_directory);
        FILE *file = fopen(key, "wb");
        ASSERT(file != NULL);
        ASSERT(fputs("inert fixture; not a key\n", file) >= 0);
        ASSERT(fclose(file) == 0);
        for (unsigned form = 0; form < 3; form++) {
            struct json_value input, envelope;
            json_init(&input);
            json_init(&envelope);
            ASSERT(member_input(&input, "[{\"name\":\"case\",\"expect_exit\":0,\"expect_\\u0065xit\":7}]", form));
            ASSERT(json_push_kv_str(&input, "name", "inert-duplicate-test"));
            ASSERT(json_push_kv_str(&input, "version", "0.0.0"));
            ASSERT(json_push_kv_str(&input, "key", key));
            ASSERT(json_push_kv_str(&input, "dir", output));
            size_t compiles = lab_compile_count(), runs = lab_run_count();
            ASSERT(member_call("lab.promote", &input, &envelope));
            ASSERT(member_refused(&envelope, "LAB_BAD_CASES"));
            ASSERT_EQ(lab_compile_count(), compiles);
            ASSERT_EQ(lab_run_count(), runs);
            struct stat metadata;
            ASSERT(stat(output, &metadata) != 0 && errno == ENOENT);
            ASSERT(stat(member_state, &metadata) != 0 && errno == ENOENT);
            json_free(&envelope);
            json_free(&input);
        }
        file = fopen(key, "rb");
        char bytes[64] = "";
        ASSERT(file && fgets(bytes, sizeof(bytes), file));
        ASSERT(strcmp(bytes, "inert fixture; not a key\n") == 0);
        ASSERT(fgetc(file) == EOF && !ferror(file));
        ASSERT(fclose(file) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int member_controls(void)
{
    int failures = 0;
    TEST("lab keeps canonical roots, legitimate expectations and cached results while refusing ambiguous reuse") {
        struct json_value canonical, replay, failed, input;
        json_init(&canonical);
        json_init(&replay);
        json_init(&failed);
        json_init(&input);
        ASSERT(member_input(&input, "[{\"name\":\"case\",\"expect_exit\":0}]", 0));
        ASSERT(member_call("lab.test", &input, &canonical));
        if (!lab_confinement_available()) {
            ASSERT(member_refused(&canonical, "LAB_UNCONFINED"));
        } else {
            const struct json_value *data = json_get(&canonical, "data");
            ASSERT(json_get_bool(json_get(&canonical, "ok")));
            ASSERT_EQ(json_get_int(json_get(data, "passed")), 1);
            size_t compiles = lab_compile_count(), runs = lab_run_count();
            for (unsigned form = 0; form < 3; form++) {
                json_free(&input);
                ASSERT(member_input(&input, "[{\"name\":\"case\",\"expect_\\u0065xit\":0}]", form));
                ASSERT(member_call("lab.test", &input, &replay));
                const struct json_value *again = json_get(&replay, "data");
                ASSERT(json_get_bool(json_get(json_get(again, "cache"), "hit")));
                ASSERT(strcmp(json_get_str(json_get(data, "root")), json_get_str(json_get(again, "root"))) == 0);
                ASSERT_EQ(lab_compile_count(), compiles);
                ASSERT_EQ(lab_run_count(), runs);
                json_free(&replay);
                json_free(&input);
                ASSERT(member_input(&input, "[{\"name\":\"case\",\"expect_exit\":0,\"expect_\\u0065xit\":0}]", form));
                ASSERT(member_call("lab.test", &input, &replay));
                ASSERT(member_refused(&replay, "LAB_BAD_CASES"));
                ASSERT_EQ(lab_compile_count(), compiles);
                ASSERT_EQ(lab_run_count(), runs);
                json_free(&replay);
            }
            json_free(&input);
            ASSERT(member_input(&input, "[{\"name\":\"case\",\"expect_exit\":7}]", 0));
            ASSERT(member_call("lab.test", &input, &failed));
            const struct json_value *other = json_get(&failed, "data");
            ASSERT(json_get_bool(json_get(&failed, "ok")));
            ASSERT_EQ(json_get_int(json_get(other, "failed")), 1);
            ASSERT(strcmp(json_get_str(json_get(data, "root")), json_get_str(json_get(other, "root"))) != 0);
        }
        json_free(&input);
        json_free(&failed);
        json_free(&replay);
        json_free(&canonical);
        PASS();
    } _test_next:;
    return failures;
}

int test_lab_case_members(void)
{
    test_fmt_tmpdir(member_directory, sizeof(member_directory), "lab-case-members", "fixture");
    snprintf(member_state, sizeof(member_state), "%s/state", member_directory);
    if (!test_ensure_tmproot() || mkdir(member_directory, 0700) != 0 ||
        setenv("Z23_LAB_DIR", member_state, 1) != 0)
        return 1;
    int failures = member_duplicates();
    /* Give each refusal test an uncreated lab state, even on the red parent. */
    (void)zcl_tree_remove(member_state);
    failures += member_promote();
    (void)zcl_tree_remove(member_state);
    failures += member_controls();
    (void)unsetenv("Z23_LAB_DIR");
    (void)zcl_tree_remove(member_directory);
    return failures;
}
