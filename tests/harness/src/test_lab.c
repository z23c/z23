/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: The one-file lab: lab.run, lab.test and lab.show against the
 * fixtures in tests/fixtures/lab. A host that cannot confine a child (no
 * Landlock or seccomp) is asserted to refuse with LAB_UNCONFINED; it is never
 * skipped and the program is never run unconfined. */

#include "test/test_core.h"

#include "command/lab.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/file_tree_ops.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define LT_FIX "tests/fixtures/lab/"

typedef void (*lt_handler)(const struct zcl_command_request *,
                           struct zcl_command_reply *);

static char g_lt_dir[512];

static bool lt_open(void)
{
    test_fmt_tmpdir(g_lt_dir, sizeof(g_lt_dir), "lab", "state");
    if (!test_ensure_tmproot() ||
        (mkdir(g_lt_dir, 0700) != 0 && errno != EEXIST))
        return false;
    return setenv("Z23_LAB_DIR", g_lt_dir, 1) == 0;
}

static void lt_close(void)
{
    (void)zcl_tree_remove(g_lt_dir);
    (void)unsetenv("Z23_LAB_DIR");
}

static bool lt_call(lt_handler handler, const char *input_json,
                    const char *schema, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, input_json, strlen(input_json));
    struct zcl_command_request request = { .input = &input };
    zcl_command_reply_init(reply, schema);
    if (ok)
        handler(&request, reply);
    json_free(&input);
    return ok;
}

static const struct json_value *lt_at(const struct json_value *root,
                                      const char *a, const char *b)
{
    const struct json_value *x = json_get(root, a);
    return x && b ? json_get(x, b) : x;
}

static bool lt_streq(const struct json_value *v, const char *want)
{
    return v && v->type == JSON_STR && strcmp(json_get_str(v), want) == 0;
}

static int64_t lt_int(const struct json_value *root, const char *a,
                      const char *b)
{
    const struct json_value *v = lt_at(root, a, b);
    return v && v->type == JSON_INT ? json_get_int(v) : -9999;
}

static bool lt_flag(const struct json_value *root, const char *a, const char *b)
{
    const struct json_value *v = lt_at(root, a, b);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static bool lt_has(const struct json_value *root, const char *a, const char *b,
                   const char *needle)
{
    const struct json_value *v = lt_at(root, a, b);
    return v && v->type == JSON_STR && strstr(json_get_str(v), needle) != NULL;
}

static bool lt_failed_with(const struct zcl_command_reply *r, const char *code)
{
    return r->status == ZCL_COMMAND_STATUS_FAILED &&
           strcmp(r->error.code, code) == 0;
}

/* One run request for a fixture; extra is a JSON member list or "". */
static bool lt_run(const char *fixture, const char *extra,
                   struct zcl_command_reply *reply)
{
    char input[1024];
    (void)snprintf(input, sizeof(input), "{\"file\":\"" LT_FIX "%s\"%s%s}",
                   fixture, extra[0] ? "," : "", extra);
    return lt_call(zcl_native_handle_lab_run, input, "zcl.lab_run.v1", reply);
}

/* On a host that cannot confine, the only legal answer is the refusal. */
static bool lt_refused_or_ok(const struct zcl_command_reply *r)
{
    if (lab_confinement_available())
        return r->status == ZCL_COMMAND_STATUS_PASSED;
    return lt_failed_with(r, "LAB_UNCONFINED");
}

static int test_lab_hello(void)
{
    int failures = 0;
    TEST("lab run: hello compiles and runs confined, stdout and exit 0") {
        struct zcl_command_reply r;
        ASSERT(lt_run("hello.c", "", &r));
        ASSERT(lt_refused_or_ok(&r));
        if (lab_confinement_available()) {
            ASSERT(lt_flag(&r.data, "compile", "ok"));
            ASSERT(lt_flag(&r.data, "run", "ran"));
            ASSERT_EQ(lt_int(&r.data, "run", "exit_code"), 0);
            ASSERT_EQ(lt_int(&r.data, "run", "signal"), 0);
            ASSERT(lt_streq(lt_at(&r.data, "run", "stdout"), "hello, lab\n"));
            ASSERT(lt_streq(lt_at(&r.data, "confinement", "network"), "denied"));
            ASSERT(lt_flag(&r.data, "confinement", "landlock"));
            ASSERT(lt_flag(&r.data, "confinement", "seccomp"));
            ASSERT(lt_flag(&r.data, "confinement", "pidns") == lab_pidns_available());
            ASSERT(!lt_flag(&r.data, "cache", "hit"));
            ASSERT_EQ(strlen(json_get_str(json_get(&r.data, "root"))), LAB_ROOT_HEX);
        }
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lab_compile_error(void)
{
    int failures = 0;
    TEST("lab run: a compile error is parsed to line, column and severity") {
        struct zcl_command_reply r;
        const char *extra = "\"compile_only\":true,\"stdin\":\"hello\\n\","
                            "\"args\":[\"two words\",\"quoted\\\"arg\"]";
        ASSERT(lt_run("compile_error.c", extra, &r));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!lt_flag(&r.data, "compile", "ok"));
        ASSERT(!lt_flag(&r.data, "run", "ran"));
        const struct json_value *diag = lt_at(&r.data, "compile", "diagnostics");
        ASSERT(diag && diag->num_children >= 1);
        ASSERT_EQ(lt_int(&diag->children[0], "line", NULL), 4);
        ASSERT_EQ(lt_int(&diag->children[0], "col", NULL), 12);
        ASSERT(lt_streq(json_get(&diag->children[0], "severity"), "error"));
        ASSERT(lt_has(&diag->children[0], "message", NULL, "undefined_symbol"));
        ASSERT(lt_has(&r.data, "compile", "raw_tail", "compile_error.c:4:12"));
        ASSERT_EQ(r.next_count, 0);
        ASSERT(lt_has(&r.data, "next_action", NULL, "Fix the source"));
        zcl_command_reply_free(&r);
        ASSERT(lt_run("compile_error.c", extra, &r));
        ASSERT(lt_flag(&r.data, "cache", "hit"));
        ASSERT_EQ(r.next_count, 0);
        ASSERT(lt_has(&r.data, "next_action", NULL, "repeat your lab run command"));
        zcl_command_reply_free(&r);
        char large[700];
        ASSERT(snprintf(large, sizeof(large),
                        "\"compile_only\":true,\"stdin\":\"%0600d\"", 0) > 0);
        ASSERT(lt_run("compile_error.c", large, &r));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!lt_flag(&r.data, "compile", "ok"));
        ASSERT_EQ(r.next_count, 0);
        ASSERT(lt_has(&r.data, "next_action", NULL, "Fix the source"));
        zcl_command_reply_free(&r);
        const struct zcl_command_registry *reg = zcl_command_catalog();
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(reg, "lab.run", NULL);
        ASSERT(spec);
        struct zcl_command_context ctx = {
            .registry = reg, .granted_capabilities = ~(uint64_t)0,
            .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        };
        struct json_value input, envelope;
        json_init(&input);
        json_init(&envelope);
        const char *request = "{\"file\":\"" LT_FIX "compile_error.c\",\"compile_only\":true}";
        ASSERT(json_read(&input, request, strlen(request)));
        char output[8192];
        enum zcl_command_exit code;
        size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
            false, spec->path, "normal", 0, 0, NULL, output, sizeof(output), &code);
        ASSERT(n > 0 && n < sizeof(output));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_read(&envelope, output, n));
        ASSERT(lt_flag(&envelope, "ok", NULL));
        ASSERT(lt_has(&envelope, "data", "next_action", "Fix the source"));
        json_free(&envelope);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lab_exit_and_stderr(void)
{
    int failures = 0;
    TEST("lab run: a nonzero exit and stderr are reported as they happened") {
        struct zcl_command_reply r;
        ASSERT(lt_run("exit3.c", "", &r));
        ASSERT(lt_refused_or_ok(&r));
        if (lab_confinement_available()) {
            ASSERT_EQ(lt_int(&r.data, "run", "exit_code"), 3);
            ASSERT(lt_streq(lt_at(&r.data, "run", "stderr"), "about to fail\n"));
            ASSERT(!lt_flag(&r.data, "run", "timed_out"));
        }
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lab_crash(void)
{
    int failures = 0;
    TEST("lab run: a crash reports the signal; a sanitized crash reports a finding") {
        struct zcl_command_reply r;
        ASSERT(lt_run("crash.c", "\"sanitize\":false", &r));
        ASSERT(lt_refused_or_ok(&r));
        if (lab_confinement_available()) {
            ASSERT_EQ(lt_int(&r.data, "run", "signal"), SIGSEGV);
            ASSERT(lt_streq(lt_at(&r.data, "run", "signal_name"), "SIGSEGV"));
            ASSERT(lt_streq(lt_at(&r.data, "sanitizer", "status"), "disabled"));
        }
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

/* Sanitizers present: findings are counted. Absent: the state is reported. */
static bool lt_sanitizer_state_ok(const struct json_value *data,
                                  const char *needle)
{
    if (lt_flag(data, "sanitizer", "enabled"))
        return lt_int(data, "sanitizer", "findings") >= 1 &&
               lt_has(data, "sanitizer", "first", needle);
    return lt_streq(lt_at(data, "sanitizer", "status"), "unavailable") &&
           lt_int(data, "sanitizer", "findings") == 0;
}

static int test_lab_sanitizers(void)
{
    int failures = 0;
    TEST("lab run: UBSan and ASan findings are counted, or unavailability is reported") {
        struct zcl_command_reply ub, asan;
        ASSERT(lt_run("ub.c", "", &ub));
        ASSERT(lt_run("crash.c", "", &asan));
        ASSERT(lt_refused_or_ok(&ub));
        ASSERT(lt_refused_or_ok(&asan));
        if (lab_confinement_available()) {
            ASSERT(lt_sanitizer_state_ok(&ub.data, "signed integer overflow"));
            ASSERT(lt_sanitizer_state_ok(&asan.data, "AddressSanitizer"));
        }
        zcl_command_reply_free(&ub);
        zcl_command_reply_free(&asan);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lab_timeout(void)
{
    int failures = 0;
    TEST("lab run: a spinning program is killed at timeout_ms") {
        struct zcl_command_reply r;
        ASSERT(lt_run("spin.c", "\"sanitize\":false,\"timeout_ms\":300", &r));
        ASSERT(lt_refused_or_ok(&r));
        if (lab_confinement_available()) {
            ASSERT(lt_flag(&r.data, "run", "timed_out"));
            ASSERT_EQ(lt_int(&r.data, "run", "signal"), SIGKILL);
        }
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lab_denials(void)
{
    int failures = 0;
    TEST("lab run: a socket is denied and writes outside the workdir fail") {
        struct zcl_command_reply sock, fs;
        struct stat st;
        char probe[512], args[640];
        (void)snprintf(probe, sizeof(probe), "%s/escape_probe", g_lt_dir);
        (void)snprintf(args, sizeof(args), "\"args\":[\"%s\"]", probe);
        (void)unlink(probe);
        ASSERT(lt_run("socket_probe.c", "\"sanitize\":false", &sock));
        ASSERT(lt_run("fs_probe.c", args, &fs));
        ASSERT(lt_refused_or_ok(&sock));
        ASSERT(lt_refused_or_ok(&fs));
        if (lab_confinement_available()) {
            ASSERT_EQ(lt_int(&sock.data, "run", "signal"), SIGSYS);
            ASSERT(lt_streq(lt_at(&sock.data, "run", "stdout"), ""));
            ASSERT(lt_streq(lt_at(&fs.data, "run", "stdout"),
                            "workdir=allowed\noutside_write=denied\n"
                            "outside_read=denied\n"));
            ASSERT(stat(probe, &st) != 0);
        }
        zcl_command_reply_free(&sock);
        zcl_command_reply_free(&fs);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lab_resource_caps(void)
{
    int failures = 0;
    TEST("lab run: a disk filler is killed at the workdir cap; a program that closes stdout still times out") {
        struct zcl_command_reply fill, spin;
        ASSERT(lt_run("fill_disk.c", "\"sanitize\":false", &fill));
        ASSERT(lt_run("close_and_spin.c", "\"sanitize\":false,\"timeout_ms\":300", &spin));
        ASSERT(lt_refused_or_ok(&fill));
        ASSERT(lt_refused_or_ok(&spin));
        if (lab_confinement_available()) {
            ASSERT(lt_flag(&fill.data, "run", "disk_exceeded"));
            ASSERT_EQ(lt_int(&fill.data, "run", "signal"), SIGKILL);
            ASSERT(!lt_has(&fill.data, "run", "stdout", "filled"));
            ASSERT(lt_flag(&spin.data, "run", "timed_out"));
        }
        zcl_command_reply_free(&fill);
        zcl_command_reply_free(&spin);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lab_stdin_args(void)
{
    int failures = 0;
    TEST("lab run: stdin and args reach the program") {
        struct zcl_command_reply r;
        ASSERT(lt_run("echo.c", "\"stdin\":\"line one\\nline two\\n\","
                                "\"args\":[\"a\",\"b c\"]", &r));
        ASSERT(lt_refused_or_ok(&r));
        if (lab_confinement_available())
            ASSERT(lt_streq(lt_at(&r.data, "run", "stdout"),
                            "args=2 [a] [b c]\nline one\nline two\n"));
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lab_cache(void)
{
    int failures = 0;
    TEST("lab run: an identical request is served from the stored receipt") {
        struct zcl_command_reply a, b, c, shown;
        char input[256];
        ASSERT(lt_run("hello.c", "\"timeout_ms\":4000", &a));
        ASSERT(lt_refused_or_ok(&a));
        if (lab_confinement_available()) {
            size_t compiles = lab_compile_count(), runs = lab_run_count();
            ASSERT(lt_run("hello.c", "\"timeout_ms\":4000", &b));
            ASSERT(lt_flag(&b.data, "cache", "hit"));
            ASSERT_EQ(lab_compile_count(), compiles);
            ASSERT_EQ(lab_run_count(), runs);
            ASSERT(lt_streq(json_get(&a.data, "root"), json_get_str(json_get(&b.data, "root"))));
            ASSERT_EQ(lt_int(&a.data, "run", "wall_us"), lt_int(&b.data, "run", "wall_us"));
            ASSERT(lt_run("hello.c", "\"timeout_ms\":4000,\"fresh\":true", &c));
            ASSERT(!lt_flag(&c.data, "cache", "hit"));
            ASSERT_EQ(lab_compile_count(), compiles + 1);
            ASSERT_EQ(lab_run_count(), runs + 1);
            (void)snprintf(input, sizeof(input), "{\"root\":\"%s\"}",
                           json_get_str(json_get(&a.data, "root")));
            ASSERT(lt_call(zcl_native_handle_lab_show, input, "zcl.lab_show.v1", &shown));
            ASSERT_EQ(shown.status, ZCL_COMMAND_STATUS_PASSED);
            ASSERT(lt_streq(lt_at(&shown.data, "receipt", "run") ?
                            json_get(lt_at(&shown.data, "receipt", "run"), "stdout") : NULL,
                            "hello, lab\n"));
            zcl_command_reply_free(&b);
            zcl_command_reply_free(&c);
            zcl_command_reply_free(&shown);
        }
        zcl_command_reply_free(&a);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lab_test_cases(void)
{
    int failures = 0;
    TEST("lab test: cases pass and fail with the first differing line") {
        struct zcl_command_reply r;
        ASSERT(lt_call(zcl_native_handle_lab_test,
                       "{\"file\":\"" LT_FIX "adder.c\",\"cases\":\"" LT_FIX
                       "adder_cases.json\"}", "zcl.lab_test.v1", &r));
        if (!lab_confinement_available()) {
            ASSERT(lt_failed_with(&r, "LAB_UNCONFINED"));
        } else {
            const struct json_value *cases = json_get(&r.data, "cases");
            ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
            ASSERT_EQ(lt_int(&r.data, "passed", NULL), 3);
            ASSERT_EQ(lt_int(&r.data, "failed", NULL), 1);
            ASSERT(cases && cases->num_children == 4);
            ASSERT(lt_flag(&cases->children[0], "pass", NULL));
            ASSERT(lt_streq(lt_at(&cases->children[0], "stderr_status", NULL),
                           "not_retained"));
            ASSERT(!lt_flag(&cases->children[2], "pass", NULL));
            ASSERT(lt_has(&cases->children[2], "diff", NULL,
                          "line 1: expected \"6\\n\" got \"5\\n\""));
            ASSERT_EQ(lt_int(&cases->children[3], "exit_code", NULL), 1);
            ASSERT(lt_flag(&cases->children[3], "pass", NULL));
        }
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lab_test_inline_and_cache(void)
{
    int failures = 0;
    TEST("lab test: inline cases are accepted and the receipt is cached") {
        struct zcl_command_reply a, b;
        const char *input = "{\"file\":\"" LT_FIX "adder.c\",\"cases\":["
                            "{\"name\":\"sum\",\"stdin\":\"20 22\\n\","
                            "\"expect_stdout\":\"42\\n\"}]}";
        ASSERT(lt_call(zcl_native_handle_lab_test, input, "zcl.lab_test.v1", &a));
        if (lab_confinement_available()) {
            size_t compiles = lab_compile_count();
            ASSERT_EQ(lt_int(&a.data, "passed", NULL), 1);
            ASSERT(lt_call(zcl_native_handle_lab_test, input, "zcl.lab_test.v1", &b));
            ASSERT(lt_flag(&b.data, "cache", "hit"));
            ASSERT_EQ(lab_compile_count(), compiles);
            zcl_command_reply_free(&b);
        } else {
            ASSERT(lt_failed_with(&a, "LAB_UNCONFINED"));
        }
        zcl_command_reply_free(&a);
        PASS();
    } _test_next:;
    return failures;
}

static bool lt_stderr_input(struct json_value *input, size_t count, bool large)
{
    struct json_value cases;
    json_init(&cases);
    json_set_array(&cases);
    json_set_object(input);
    bool ok = json_push_kv_str(input, "file", LT_FIX "stderr_cases.c") &&
              json_push_kv_bool(input, "sanitize", false);
    for (size_t i = 0; ok && i < count; i++) {
        struct json_value row, args;
        char name[24];
        snprintf(name, sizeof(name), "case-%zu", i);
        json_init(&row);
        json_init(&args);
        json_set_object(&row);
        json_set_array(&args);
        struct json_value arg;
        json_init(&arg);
        json_set_str(&arg, large ? "l" : i == 0 ? "a" : "b");
        ok = json_push_back(&args, &arg) &&
             json_push_kv_str(&row, "name", name) &&
             json_push_kv(&row, "args", &args) && json_push_back(&cases, &row);
        json_free(&arg);
        json_free(&args);
        json_free(&row);
    }
    ok = ok && json_push_kv(input, "cases", &cases);
    json_free(&cases);
    return ok;
}

static bool lt_test_envelope(const struct json_value *input,
                              struct json_value *envelope)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(reg, "lab.test", NULL);
    if (!spec)
        return false;
    struct zcl_command_context ctx = {
        .registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    char output[65537];
    enum zcl_command_exit code;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, input,
        false, spec->path, "normal", 0, 0, NULL, output, sizeof(output), &code);
    if (n == 0 || n > 65536 || !json_read(envelope, output, n))
        return false;
    return lab_confinement_available()
        ? code == ZCL_COMMAND_EXIT_OK && lt_flag(envelope, "ok", NULL)
        : lt_streq(lt_at(envelope, "error", "code"), "LAB_UNCONFINED");
}

static int test_lab_test_stderr(void)
{
    int failures = 0;
    TEST("lab test: case stderr fits the registry envelope and replays without work") {
        const size_t counts[] = { 2, 1, 256 };
        for (size_t scenario = 0; scenario < 3; scenario++) {
            struct json_value input, first, replay;
            json_init(&input);
            json_init(&first);
            json_init(&replay);
            ASSERT(lt_stderr_input(&input, counts[scenario], scenario != 0));
            size_t runs_before = lab_run_count();
            ASSERT(lt_test_envelope(&input, &first));
            if (lab_confinement_available()) {
                const struct json_value *data = json_get(&first, "data");
                const struct json_value *rows = json_get(data, "cases");
                ASSERT(rows && rows->num_children == counts[scenario]);
                ASSERT_EQ(lt_int(data, "failed", NULL), counts[scenario]);
                ASSERT_EQ(lab_run_count(), runs_before + counts[scenario]);
                if (scenario == 0) {
                    ASSERT(lt_streq(lt_at(&rows->children[0], "stderr", NULL),
                                   "invalid record a at byte 17\n"));
                    ASSERT(lt_streq(lt_at(&rows->children[1], "stderr", NULL),
                                   "invalid record b at byte 17\n"));
                    ASSERT(lt_streq(lt_at(&rows->children[0], "stderr_status", NULL),
                                   "complete"));
                } else {
                    ASSERT(lt_has(&rows->children[0], "stderr", NULL, "\"\n\xef\xbf\xbd"));
                    ASSERT(lt_streq(lt_at(&rows->children[0], "stderr_status", NULL),
                                   "truncated"));
                    if (scenario == 2)
                        ASSERT(lt_streq(lt_at(&rows->children[255], "stderr_status", NULL),
                                       "omitted"));
                }
                size_t compiles = lab_compile_count(), runs = lab_run_count();
                ASSERT(lt_test_envelope(&input, &replay));
                ASSERT(lt_flag(json_get(&replay, "data"), "cache", "hit"));
                ASSERT_EQ(lab_compile_count(), compiles);
                ASSERT_EQ(lab_run_count(), runs);
                const struct json_value *again = lt_at(&replay, "data", "cases");
                ASSERT(again && again->num_children == rows->num_children);
                for (size_t i = 0; i < rows->num_children; i++) {
                    ASSERT(lt_streq(lt_at(&again->children[i], "stderr", NULL),
                        json_get_str(json_get(&rows->children[i], "stderr"))));
                    ASSERT(lt_streq(lt_at(&again->children[i], "stderr_status", NULL),
                        json_get_str(json_get(&rows->children[i], "stderr_status"))));
                }
            } else {
                ASSERT_EQ(lab_run_count(), runs_before);
            }
            json_free(&replay);
            json_free(&first);
            json_free(&input);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_lab_refusals(void)
{
    int failures = 0;
    TEST("lab: missing, non-C, symlinked and oversized sources and unknown roots are refused by name") {
        struct zcl_command_reply r;
        char path[600], input[700];
        FILE *f;
        ASSERT(lt_call(zcl_native_handle_lab_run, "{\"file\":\"nope/none.c\"}",
                       "zcl.lab_run.v1", &r));
        ASSERT(lt_failed_with(&r, "LAB_FILE_NOT_FOUND"));
        zcl_command_reply_free(&r);
        ASSERT(lt_call(zcl_native_handle_lab_run, "{\"file\":\"" LT_FIX "adder_cases.json\"}",
                       "zcl.lab_run.v1", &r));
        ASSERT(lt_failed_with(&r, "LAB_BAD_FILE"));
        zcl_command_reply_free(&r);
        ASSERT(lt_call(zcl_native_handle_lab_show, "{\"root\":\"abc\"}", "zcl.lab_show.v1", &r));
        ASSERT(lt_failed_with(&r, "LAB_BAD_ROOT"));
        zcl_command_reply_free(&r);
        (void)snprintf(input, sizeof(input), "{\"root\":\"%0128d\"}", 0);
        ASSERT(lt_call(zcl_native_handle_lab_show, input, "zcl.lab_show.v1", &r));
        ASSERT(lt_failed_with(&r, "LAB_NOT_FOUND"));
        zcl_command_reply_free(&r);
        (void)snprintf(path, sizeof(path), "%s/link.c", g_lt_dir);
        (void)unlink(path);
        ASSERT(symlink("hello.c", path) == 0);
        (void)snprintf(input, sizeof(input), "{\"file\":\"%s\"}", path);
        ASSERT(lt_call(zcl_native_handle_lab_run, input, "zcl.lab_run.v1", &r));
        ASSERT(lt_failed_with(&r, "LAB_BAD_FILE"));
        zcl_command_reply_free(&r);
        (void)snprintf(path, sizeof(path), "%s/big.c", g_lt_dir);
        f = fopen(path, "w");
        ASSERT(f != NULL);
        ASSERT(fseek(f, LAB_SRC_MAX, SEEK_SET) == 0 && fputc('\n', f) != EOF);
        ASSERT(fclose(f) == 0);
        (void)snprintf(input, sizeof(input), "{\"file\":\"%s\"}", path);
        ASSERT(lt_call(zcl_native_handle_lab_run, input, "zcl.lab_run.v1", &r));
        ASSERT(lt_failed_with(&r, "LAB_TOO_LARGE"));
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lab_unconfined_seam(void)
{
    int failures = 0;
    TEST("lab run: when confinement fails the program is refused, never run") {
        struct zcl_command_reply r, again;
        size_t runs = lab_run_count();
        lab_test_force_confinement_failure(true);
        bool called = lt_run("hello.c", "\"fresh\":true", &r);
        lab_test_force_confinement_failure(false);
        ASSERT(called);
        if (lab_confinement_available())
            ASSERT(lt_failed_with(&r, "LAB_UNCONFINED"));
        ASSERT_EQ(lab_run_count(), runs);
        ASSERT(lt_run("hello.c", "\"fresh\":true,\"compile_only\":true", &again));
        ASSERT_EQ(again.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(lt_flag(&again.data, "compile", "ok"));
        ASSERT(!lt_flag(&again.data, "run", "ran"));
        zcl_command_reply_free(&r);
        zcl_command_reply_free(&again);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lab_workload(void)
{
    int failures = 0;
    TEST("lab run: a 500-line workload runs clean under the sanitizers") {
        struct zcl_command_reply r;
        ASSERT(lt_run("workload.c", "", &r));
        ASSERT(lt_refused_or_ok(&r));
        if (lab_confinement_available()) {
            ASSERT(lt_flag(&r.data, "compile", "ok"));
            ASSERT_EQ(lt_int(&r.data, "run", "exit_code"), 0);
            ASSERT_EQ(lt_int(&r.data, "sanitizer", "findings"), 0);
            ASSERT(lt_has(&r.data, "run", "stdout", "sections: 9, failures: 0\n"));
        }
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

static bool lt_host_is_linux(void)
{
#if defined(__linux__)
    return true;
#else
    return false;
#endif
}

static int test_lab_unsupported(void)
{
    int failures = 0;
    TEST("lab run: a non-Linux host refuses by name") {
        struct zcl_command_reply r;
        ASSERT(lt_run("hello.c", "", &r));
        ASSERT(lt_failed_with(&r, "LAB_UNSUPPORTED"));
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

/* A same-uid process outside the lab, to prove the program cannot signal it. */
static pid_t lt_spawn_sleeper(void)
{
    pid_t pid = fork();
    if (pid == 0) {
        for (;;)
            pause();
    }
    return pid;
}

static int test_lab_signals(void)
{
    int failures = 0;
    TEST("lab run: a program cannot signal a process outside the lab, with and without a PID namespace") {
        for (int no_pidns = 0; no_pidns < 2; no_pidns++) {
            struct zcl_command_reply r;
            char args[64];
            /* The node binary can run non-dumpable; the lab must still confine. */
            ASSERT_EQ(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0), 0);
            lab_test_disable_pidns(no_pidns != 0);
            pid_t sleeper = lt_spawn_sleeper();
            ASSERT(sleeper > 0);
            (void)snprintf(args, sizeof(args), "\"args\":[\"%d\"]", (int)sleeper);
            ASSERT(lt_run("signal_probe.c", args, &r));
            lab_test_disable_pidns(false);
            ASSERT_EQ(prctl(PR_SET_DUMPABLE, 1, 0, 0, 0), 0);
            ASSERT(lt_refused_or_ok(&r));
            if (lab_confinement_available()) {
                bool ns = !no_pidns && lab_pidns_available();
                ASSERT(lt_flag(&r.data, "confinement", "pidns") == ns);
                ASSERT(lt_streq(lt_at(&r.data, "run", "stdout"),
                                ns ? "own_pid_small=yes\nself_signal=ok\n"
                                     "outside_kill=failed\nparent_kill=failed\n"
                                     "group_kill=failed\nsigio_owner=failed\n"
                                     "proc_scan=denied\n"
                                   : "own_pid_small=no\nself_signal=ok\n"
                                     "outside_kill=failed\nparent_kill=failed\n"
                                     "group_kill=failed\nsigio_owner=failed\n"
                                     "proc_scan=denied\n"));
            }
            ASSERT_EQ(kill(sleeper, 0), 0);
            (void)kill(sleeper, SIGKILL);
            (void)waitpid(sleeper, NULL, 0);
            zcl_command_reply_free(&r);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_lab_signal_mutant(void)
{
    int failures = 0;
    TEST("lab run: without the descriptor-owner rules the probe does kill the sibling (mutant)") {
        struct zcl_command_reply r;
        char args[64];
        int status = 0;
        lab_test_disable_pidns(true);
        lab_test_disable_fd_owner_rules(true);
        pid_t sleeper = lt_spawn_sleeper();
        ASSERT(sleeper > 0);
        (void)snprintf(args, sizeof(args), "\"args\":[\"%d\"]", (int)sleeper);
        ASSERT(lt_run("signal_probe.c", args, &r));
        lab_test_disable_fd_owner_rules(false);
        lab_test_disable_pidns(false);
        ASSERT(lt_refused_or_ok(&r));
        if (lab_confinement_available()) {
            ASSERT(lt_has(&r.data, "run", "stdout", "sigio_owner=set\n"));
            ASSERT_EQ(waitpid(sleeper, &status, 0), sleeper);
            ASSERT(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        } else {
            (void)kill(sleeper, SIGKILL);
            (void)waitpid(sleeper, NULL, 0);
        }
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    return failures;
}

int test_lab(void)
{
    int failures = 0;
    if (!lt_open()) {
        printf("lab: state directory could not be prepared... FAIL\n");
        return 1;
    }
    if (!lt_host_is_linux()) {
        failures += test_lab_unsupported();
        lt_close();
        return failures;
    }
    failures += test_lab_hello();
    failures += test_lab_compile_error();
    failures += test_lab_exit_and_stderr();
    failures += test_lab_crash();
    failures += test_lab_sanitizers();
    failures += test_lab_timeout();
    failures += test_lab_denials();
    failures += test_lab_signals();
    failures += test_lab_signal_mutant();
    failures += test_lab_resource_caps();
    failures += test_lab_stdin_args();
    failures += test_lab_cache();
    failures += test_lab_test_cases();
    failures += test_lab_test_inline_and_cache();
    failures += test_lab_test_stderr();
    failures += test_lab_refusals();
    failures += test_lab_unconfined_seam();
    failures += test_lab_workload();
    lt_close();
    return failures;
}
