/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: exercise real buffered standalone dispatch and preload ordering. */
#ifndef ZCL_UTXO_COMPARE_DISPATCH_SELFTESTS_H
#define ZCL_UTXO_COMPARE_DISPATCH_SELFTESTS_H
#include <fcntl.h>
/* Actual source twin/runtime and bounded owned-child reaper are included by
 * utxo_compare_runtime_selftests.h first. No second resolver/cleanup model. */
enum ucod_mode { UCOD_OK, UCOD_END_FAIL, UCOD_CLEANUP_FAIL, UCOD_LATE_CANCEL };
struct ucod_runtime {
    struct cli_compare_signals signals;
    enum ucod_mode mode;
    unsigned begins, ends, cleanups, phase;
    bool bad_order;
    bool late_cancel;
};
static bool ucod_begin(void *context)
{
    struct ucod_runtime *r = context; r->begins++; r->phase = 1;
    return ucrt_scope_begin(&r->signals);
}
static bool ucod_end(void *context)
{
    struct ucod_runtime *r = context; r->ends++;
    if (r->phase != 2) r->bad_order = true;
    r->phase = 3;
    bool restored = ucrt_scope_end(&r->signals);
    return restored && r->mode != UCOD_END_FAIL;
}
static bool ucod_cancel(void *context)
{
    struct ucod_runtime *r = context;
    return r->late_cancel || ucrt_scope_cancelled(&r->signals);
}
static bool ucod_reserve(void *context, unsigned count, struct zcl_command_cleanup_slot **slots)
{
    return ucrt_reserve(&((struct ucod_runtime *)context)->signals, count, slots);
}
static bool ucod_cleanup(void *context)
{
    struct ucod_runtime *r = context; r->cleanups++;
    if (r->phase != 1) r->bad_order = true;
    r->phase = 2;
    bool cleaned = ucrt_cleanup(&r->signals);
    if (r->mode == UCOD_LATE_CANCEL) r->late_cancel = true;
    return cleaned && r->mode != UCOD_CLEANUP_FAIL;
}
struct ucod_stream { char text[65536]; size_t used; bool eof, truncated, binary; };
struct ucod_capture { struct ucod_stream out, err; int status; };
static bool ucod_flush_before_fork(void)
{
    int out = fflush(stdout), err = fflush(stderr);
    return out == 0 && err == 0;
}
static bool ucod_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}
static bool ucod_read_chunk(int fd, struct ucod_stream *stream)
{
    char bytes[2048]; ssize_t n = read(fd, bytes, sizeof(bytes));
    if (n == 0) { stream->eof = true; return true; }
    if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
    if (memchr(bytes, 0, (size_t)n)) stream->binary = true;
    size_t room = sizeof(stream->text) - stream->used - 1;
    size_t take = (size_t)n < room ? (size_t)n : room;
    memcpy(stream->text + stream->used, bytes, take); stream->used += take;
    stream->text[stream->used] = 0;
    if (take != (size_t)n) stream->truncated = true;
    return true;
}
static bool ucod_drain_ready(struct pollfd fds[2], struct ucod_capture *capture)
{
    struct ucod_stream *streams[2] = {&capture->out, &capture->err};
    for (unsigned i = 0; i < 2; i++) {
        if (fds[i].revents & POLLNVAL) return false;
        if ((fds[i].revents & (POLLIN | POLLHUP | POLLERR)) &&
            !ucod_read_chunk(fds[i].fd, streams[i])) return false;
    }
    return true;
}
static bool ucod_drain_complete(const struct ucod_capture *capture)
{
    return !capture->out.truncated && !capture->err.truncated &&
        !capture->out.binary && !capture->err.binary;
}
static bool ucod_drain(int out, int err, struct ucod_capture *capture)
{
    if (!ucod_nonblocking(out) || !ucod_nonblocking(err)) return false;
    int64_t start = ucrt_now_ms();
    if (start < 0) return false;
    while (!capture->out.eof || !capture->err.eof) {
        int64_t now = ucrt_now_ms();
        if (now < 0 || now - start >= 5000) return false;
        struct pollfd fds[2] = {
            {.fd = capture->out.eof ? -1 : out, .events = POLLIN},
            {.fd = capture->err.eof ? -1 : err, .events = POLLIN}
        };
        int ready = poll(fds, 2, (int)(5000 - (now - start)));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return false;
        /* One bounded read per ready stream per iteration: a busy writer
         * cannot starve the other pipe or the shared monotonic deadline. */
        if (!ucod_drain_ready(fds, capture)) return false;
    }
    return ucod_drain_complete(capture);
}
static bool ucod_pipes(int output[2], int diagnostic[2])
{
    if (!ucod_flush_before_fork() || pipe(output) != 0) return false;
    if (pipe(diagnostic) == 0) return true;
    close(output[0]); close(output[1]); return false;
}
static void ucod_child_redirect(int output[2], int diagnostic[2])
{
    close(output[0]); close(diagnostic[0]);
    if (dup2(output[1], STDOUT_FILENO) < 0 || dup2(diagnostic[1], STDERR_FILENO) < 0) _exit(92);
    close(output[1]); close(diagnostic[1]);
}
static bool ucod_parent_capture(pid_t child, int output[2], int diagnostic[2],
                                 struct ucod_capture *capture)
{
    close(output[1]); close(diagnostic[1]);
    bool drained = child > 0 && ucod_drain(output[0], diagnostic[0], capture);
    close(output[0]); close(diagnostic[0]);
    bool reaped = ucrt_finish_child(child, &capture->status);
    return drained && reaped && WIFEXITED(capture->status);
}
static bool ucod_direct_environment(void)
{
    return unsetenv("ZCL_HOTSWAP_PRELOAD") == 0 && unsetenv("ZCL_AGENT_SESSION") == 0 &&
        unsetenv("ZCL_DEV_SOURCE_ROOT") == 0 && setenv("ZCL_OPERATOR_LANE", "dev", 1) == 0 &&
        setenv("ZCL_HUMAN", "0", 1) == 0 && setenv("TERM", "dumb", 1) == 0 &&
        setenv("NO_COLOR", "1", 1) == 0 && setenv("ZCL_CLI_TEST_NO_SERVICE_LOOKUP", "1", 1) == 0;
}
static int ucod_run_dispatch(const struct json_value *input, const char *directory, enum ucod_mode mode)
{
    char raw[8192], argument[8224];
    size_t n = json_write(input, raw, sizeof(raw));
    if (!n || n >= sizeof(raw)) return 90;
    int length = snprintf(argument, sizeof(argument), "--input=%s", raw);
    if (length < 0 || (size_t)length >= sizeof(argument)) return 90;
    struct ucod_runtime state = {.mode = mode};
    const struct zcl_native_standalone_runtime runtime = {
        .begin = ucod_begin, .end = ucod_end, .cancelled = ucod_cancel,
        .reserve_cleanup = ucod_reserve, .cleanup = ucod_cleanup, .context = &state
    };
    const char *args[] = {"consensus", "utxo", "compare", "offline", "--format=json", argument};
    if (!ucod_direct_environment()) return 96;
    int result = zcl_native_command_main_standalone("core", args, 6, directory, 1,
        CHAIN_MAIN, true, &runtime);
    if (state.begins != 1 || state.cleanups != 1 || state.ends != 1 ||
        state.signals.slots[0].owner || state.signals.slots[1].owner || state.bad_order || state.phase != 3) return 91;
    return result;
}
static bool ucod_dispatch_capture(const struct json_value *input, const char *directory,
                                  enum ucod_mode mode, struct ucod_capture *capture)
{
    int output[2], diagnostic[2];
    if (!ucod_pipes(output, diagnostic)) return false;
    pid_t child = fork();
    if (child == 0) {
        ucod_child_redirect(output, diagnostic);
        int result = ucod_run_dispatch(input, directory, mode);
        int out = fflush(stdout), err = fflush(stderr);
        _exit(out == 0 && err == 0 ? result : 95);
    }
    return ucod_parent_capture(child, output, diagnostic, capture);
}
static bool ucod_no_completed_output(const char *text)
{
    return !strstr(text, "\"complete\"") && !strstr(text, "\\\"complete\\\"") &&
        !strstr(text, "authority_count") && !strstr(text, "projection_count") &&
        !strstr(text, "authority_root") && !strstr(text, "projection_root") &&
        !strstr(text, "counts_valid") && !strstr(text, "roots_valid") && !strstr(text, "examples");
}
static bool ucod_string_is(const struct json_value *object, const char *key, const char *expected)
{
    const struct json_value *v = json_get(object, key);
    return v && v->type == JSON_STR && strcmp(json_get_str(v), expected) == 0;
}
static bool ucod_envelope(const struct json_value *root, const char *command, bool success)
{
    const struct json_value *ok = json_get(root, "ok");
    return root->type == JSON_OBJ && ucod_string_is(root, "schema", "zcl.result.v1") &&
        ucod_string_is(root, "command", command) && ok && ok->type == JSON_BOOL &&
        json_get_bool(ok) == success && ucod_string_is(root, "status", success ? "passed" : "failed");
}
static bool ucod_failure_envelope(const struct ucod_capture *capture, const char *command,
                                  const char *code, int exit_code)
{
    struct json_value envelope = {0};
    bool parsed = json_read(&envelope, capture->out.text, capture->out.used);
    const struct json_value *error = json_get(&envelope, "error");
    bool ok = parsed && WEXITSTATUS(capture->status) == exit_code &&
        ucod_envelope(&envelope, command, false) && error && error->type == JSON_OBJ &&
        ucod_string_is(error, "code", code) && ucod_string_is(error, "error_code", code) &&
        json_get(&envelope, "data") == NULL && ucod_no_completed_output(capture->out.text) &&
        ucod_no_completed_output(capture->err.text);
    json_free(&envelope); return ok;
}
static bool ucod_observed(bool ok, const struct ucod_capture *capture, enum ucod_mode mode)
{
    if (!ok) fprintf(stderr,
        "offline dispatcher fixture: mode=%d wait_status=%d stdout=%.2048s stderr=%.2048s\n",
        mode, capture->status, capture->out.text, capture->err.text);
    return ok;
}
static bool ucod_success_envelope(const struct ucod_capture *capture, const char *command)
{
    struct json_value envelope = {0};
    bool parsed = json_read(&envelope, capture->out.text, capture->out.used);
    const struct json_value *data = json_get(&envelope, "data");
    const struct json_value *complete = data ? json_get(data, "complete") : NULL;
    bool ok = parsed && WEXITSTATUS(capture->status) == ZCL_COMMAND_EXIT_OK &&
        ucod_envelope(&envelope, command, true) && data && data->type == JSON_OBJ &&
        complete && complete->type == JSON_BOOL && json_get_bool(complete) &&
        ucod_string_is(data, "comparison", "equal") && ucod_string_is(data, "authority_count", "2") &&
        ucod_no_completed_output(capture->err.text);
    json_free(&envelope); return ok;
}
static bool ucod_dispatch_case(const struct json_value *input, const char *directory, enum ucod_mode mode)
{
    struct ucod_capture capture = {0};
    if (!ucod_dispatch_capture(input, directory, mode, &capture))
        return ucod_observed(false, &capture, mode);
    const char *command = "core.consensus.utxo.compare.offline";
    if (mode == UCOD_OK) {
        return ucod_observed(ucod_success_envelope(&capture, command), &capture, mode);
    }
    const char *code = mode == UCOD_END_FAIL ? "CANCELLATION_RESTORE_FAILED" :
        mode == UCOD_CLEANUP_FAIL ? "COMPARISON_CLEANUP_FAILED" : "COMPARISON_CANCELLED";
    return ucod_observed(ucod_failure_envelope(&capture, command, code,
        ZCL_COMMAND_EXIT_INTERNAL), &capture, mode);
}
struct ucod_preload_case { const char *root; const char *words[7]; bool comparison; };
static void ucod_preload_exec(const char *binary, const char *directory,
                              const struct ucod_preload_case *test)
{
    char home[1200], datadir[1200], preload[1200];
    int h = snprintf(home, sizeof(home), "HOME=%s", directory);
    int d = snprintf(datadir, sizeof(datadir), "-datadir=%s", directory);
    int p = snprintf(preload, sizeof(preload), "ZCL_HOTSWAP_PRELOAD=%s/missing-preload.so", directory);
    if (h < 0 || d < 0 || p < 0 || (size_t)h >= sizeof(home) ||
        (size_t)d >= sizeof(datadir) || (size_t)p >= sizeof(preload)) _exit(93);
    const char *argv[13] = {binary, datadir, test->root}; size_t n = 3;
    for (unsigned i = 0; i < 7 && test->words[i]; i++) argv[n++] = test->words[i];
    argv[n++] = "--format=json"; argv[n] = NULL;
    const char *env[] = {home, preload, "PATH=/usr/bin:/bin", "ZCL_OPERATOR_LANE=dev",
        "ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1", "ZCL_HUMAN=0", "TERM=dumb", "NO_COLOR=1", NULL};
    execve(binary, (char *const *)argv, (char *const *)env); _exit(94);
}
static bool ucod_preload_capture(const char *binary, const char *directory,
                                 const struct ucod_preload_case *test)
{
    int output[2], diagnostic[2];
    if (!ucod_pipes(output, diagnostic)) return false;
    pid_t child = fork();
    if (child == 0) {
        ucod_child_redirect(output, diagnostic);
        ucod_preload_exec(binary, directory, test);
    }
    struct ucod_capture capture = {0};
    if (!ucod_parent_capture(child, output, diagnostic, &capture)) return false;
    const char *expected = test->comparison ? "COMPARISON_PRELOAD_REFUSED" : "HOTSWAP_REFUSED";
    const char *command = test->comparison ? test->root : "dev.hotswap.preload";
    return ucod_failure_envelope(&capture, command, expected, ZCL_COMMAND_EXIT_BLOCKED);
}
/* The same native-built module must activate for the ordinary pure leaf
 * and be refused before activation for the selected comparison leaf. */
static void ucod_valid_preload_exec(const char *binary, const char *home,
                                   const char *module, bool comparison)
{
    char home_env[1400], datadir[1400], preload[4600];
    int h = snprintf(home_env, sizeof(home_env), "HOME=%s", home);
    int d = snprintf(datadir, sizeof(datadir), "-datadir=%s/.zclassic-c23-dev", home);
    int p = snprintf(preload, sizeof(preload), "ZCL_HOTSWAP_PRELOAD=%s", module);
    if (h < 0 || d < 0 || p < 0 || (size_t)h >= sizeof(home_env) ||
        (size_t)d >= sizeof(datadir) || (size_t)p >= sizeof(preload)) _exit(93);
    const char *argv[] = {binary, datadir,
        comparison ? "core.consensus.utxo.compare.offline" : "zcode.package.policy.limits",
        "--input={}", "--format=json", NULL};
    const char *env[] = {home_env, preload, "PATH=/usr/bin:/bin", "ZCL_OPERATOR_LANE=dev",
        "ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1", "ZCL_HUMAN=0", "TERM=dumb", "NO_COLOR=1", NULL};
    execve(binary, (char *const *)argv, (char *const *)env); _exit(94);
}
static bool ucod_valid_preload_capture(const char *binary, const char *home,
    const char *module, bool comparison, struct ucod_capture *capture)
{
    int output[2], diagnostic[2];
    if (!ucod_pipes(output, diagnostic)) return false;
    pid_t child = fork();
    if (child == 0) {
        ucod_child_redirect(output, diagnostic);
        ucod_valid_preload_exec(binary, home, module, comparison);
    }
    return ucod_parent_capture(child, output, diagnostic, capture);
}
static bool ucod_policy_activated(const struct ucod_capture *capture)
{
    struct json_value envelope = {0};
    bool parsed = json_read(&envelope, capture->out.text, capture->out.used);
    const struct json_value *data = json_get(&envelope, "data");
    const struct json_value *booted = json_get(data, "resident_booted");
    const struct json_value *calls = json_get(data, "resident_dispatches");
    /* One real module probe before publication, then this ordinary dispatch.
     * Without activation the compiled resident leaf would report only one. */
    bool ok = parsed && WEXITSTATUS(capture->status) == ZCL_COMMAND_EXIT_OK &&
        ucod_envelope(&envelope, "zcode.package.policy.limits", true) &&
        data && data->type == JSON_OBJ && booted && booted->type == JSON_BOOL &&
        json_get_bool(booted) && calls && calls->type == JSON_INT && json_get_int(calls) == 2 &&
        ucod_string_is(data, "tier", "new-user") &&
        ucod_no_completed_output(capture->out.text) && ucod_no_completed_output(capture->err.text);
    json_free(&envelope); return ok;
}
static bool ucod_policy_module(char module[4096])
{
    struct stat st;
    return lstat("build/hotswap/zcl_offline_policy_preload.so", &st) == 0 &&
        S_ISREG(st.st_mode) && !(st.st_mode & 0222) &&
        realpath("build/hotswap/zcl_offline_policy_preload.so", module) != NULL;
}
static bool ucod_positive_preload(const char *binary, const char *directory)
{
    char module[4096], home[1200], datadir[1400];
    if (!ucod_policy_module(module)) return false;
    int n = snprintf(home, sizeof(home), "%s/preload-home-XXXXXX", directory);
    if (n < 0 || (size_t)n >= sizeof(home) || !mkdtemp(home)) return false;
    n = snprintf(datadir, sizeof(datadir), "%s/.zclassic-c23-dev", home);
    bool made = n >= 0 && (size_t)n < sizeof(datadir) && mkdir(datadir, 0700) == 0;
    struct ucod_capture ordinary = {0}, comparison = {0};
    bool ok = made && ucod_valid_preload_capture(binary, home, module, false, &ordinary) &&
        ucod_policy_activated(&ordinary) &&
        ucod_valid_preload_capture(binary, home, module, true, &comparison) &&
        ucod_failure_envelope(&comparison, "core.consensus.utxo.compare.offline",
            "COMPARISON_PRELOAD_REFUSED", ZCL_COMMAND_EXIT_BLOCKED);
    bool clean = !made || rmdir(datadir) == 0;
    if (rmdir(home) != 0) clean = false;
    return ok && clean;
}
static int csi_compare_dispatch_cases(const struct json_value *input, const char *directory)
{
    int failures = 0;
    CSI_CHECK("standalone real dispatcher publishes checked equality", ucod_dispatch_case(input, directory, UCOD_OK));
    CSI_CHECK("standalone end failure discards already buffered completed report", ucod_dispatch_case(input, directory, UCOD_END_FAIL));
    CSI_CHECK("standalone cleanup failure discards already buffered completed report", ucod_dispatch_case(input, directory, UCOD_CLEANUP_FAIL));
    CSI_CHECK("standalone final cancellation discards already buffered completed report", ucod_dispatch_case(input, directory, UCOD_LATE_CANCEL));
    char binary[4096] = {0}; bool available = realpath("build/bin/z23-dev", binary) != NULL;
    CSI_CHECK("standalone preload parity has candidate-owned declared dev binary", available);
    CSI_CHECK("real policy preload activates ordinary leaf and is refused for comparison",
        available && ucod_positive_preload(binary, directory));
    const struct ucod_preload_case tests[] = {
        {"core", {"consensus", "utxo", "compare", "offline", NULL}, true},
        {"core.consensus", {"utxo", "compare", "offline", NULL}, true},
        {"core.consensus.utxo.compare.offline", {NULL}, true},
        {"core", {"consensus", "utxo", "compare", "offline", "extra", NULL}, true},
        {"core.consensus.utxo", {NULL}, false},
        {"core.consensus.utxo.commitment", {NULL}, false},
        {"core.no_such_branch", {NULL}, false},
        {"core", {"--format=json", "consensus", "utxo", "compare", "offline", NULL}, false}
    };
    for (unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        char label[96]; snprintf(label, sizeof(label), "standalone exact preload resolver parity case %u", i);
        CSI_CHECK(label, available && ucod_preload_capture(binary, directory, &tests[i]));
    }
    return failures;
}
#endif
