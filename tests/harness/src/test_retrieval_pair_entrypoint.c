/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#define _POSIX_C_SOURCE 200809L
#include "command/native_retrieval_cli.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "test/test_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool retrieval_pair_public_fixture(const char *workspace, char root[65]);

#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
struct entrypoint_result { int status; struct json_value reply; };

static int entrypoint_wait(pid_t child)
{
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status)
        ? WEXITSTATUS(status) : -1;
}

static void entrypoint_read_reply(FILE *output, struct json_value *reply)
{
    char out[16385]; rewind(output);
    size_t count = fread(out, 1, sizeof(out), output);
    if (!ferror(output) && count < sizeof(out)) (void)json_read(reply, out, count);
}

static struct entrypoint_result entrypoint_run(const void *raw, size_t length,
    const char *verb, bool argv_input, bool fail_output)
{
    struct entrypoint_result result = {.status = -1};
    FILE *input = tmpfile(), *output = fail_output ? fopen("/dev/null", "r") : tmpfile();
    if (!input || !output) {
        if (input) fclose(input);
        if (output) fclose(output);
        return result;
    }
    char *argument = malloc(length + 9u);
    bool ready = argument && fwrite(raw, 1, length, input) == length && fflush(input) == 0;
    if (argument) {
        memcpy(argument, "--input=", 8); memcpy(argument + 8, raw, length);
        argument[length + 8u] = 0;
    }
    rewind(input); fflush(NULL);
    pid_t child = ready ? fork() : -1;
    if (child == 0) {
        if (dup2(fileno(input), STDIN_FILENO) < 0 ||
            dup2(fileno(output), STDOUT_FILENO) < 0) _exit(99);
        char *args[] = {"rank-pair", (char *)verb, argv_input ? argument : "--input=-", NULL};
        _exit(zcl_retrieval_cli_main(3, args));
    }
    result.status = entrypoint_wait(child);
    if (!fail_output) entrypoint_read_reply(output, &result.reply);
    free(argument); fclose(input); fclose(output);
    return result;
}

static bool entrypoint_error_matches(const struct json_value *error,
                                     const char *code, const char *detail)
{
    const char *actual = json_get_str(json_get(error, "code"));
    const char *phase = json_get_str(json_get(error, "phase"));
    const char *message = json_get_str(json_get(error, "message"));
    return actual && strcmp(actual, code) == 0 && phase && strcmp(phase, "normalize") == 0 &&
        (!detail || (message && strstr(message, detail)));
}

static int entrypoint_check(const char *name, struct entrypoint_result *result,
                            int status, const char *code, const char *detail)
{
    const struct json_value *error = json_get(&result->reply, "error");
    const char *actual = json_get_str(json_get(error, "code"));
    const char *phase = json_get_str(json_get(error, "phase"));
    const char *message = json_get_str(json_get(error, "message"));
    const char *schema = json_get_str(json_get(&result->reply, "schema"));
    bool ok = result->status == status && schema && strcmp(schema, "zcl.result.v1") == 0;
    if (code) ok = ok && !json_get_bool(json_get(&result->reply, "ok")) &&
        entrypoint_error_matches(error, code, detail);
    else ok = ok && json_get_bool(json_get(&result->reply, "ok"));
    printf("  entrypoint %s: status=%d code=%s phase=%s %s\n", name,
        result->status, actual ? actual : "none", phase ? phase : "none", ok ? "PASS" : "FAIL");
    if (!ok && message) printf("    observed message: %s\n", message);
    json_free(&result->reply);
    return !ok;
}

static int entrypoint_refusal(const char *name, const void *raw, size_t length,
                              const char *code, const char *detail)
{
    struct entrypoint_result result = entrypoint_run(raw, length, "pair", false, false);
    return entrypoint_check(name, &result, ZCL_COMMAND_EXIT_INVALID, code, detail);
}

static int entrypoint_boundaries(const char *input)
{
    int failures = 0;
    size_t length = strlen(input);
    char *nul = malloc(length + 4u);
    if (!nul) return 1;
    memcpy(nul, input, length); memcpy(nul + length, "\0{}", 4);
    failures += entrypoint_refusal("physical NUL after valid request", nul, length + 3u, "BAD_INPUT", NULL);
    free(nul);
    const unsigned char utf8[] = {'{', '"', 0xff, '"', ':', '0', '}'};
    failures += entrypoint_refusal("physical invalid UTF8", utf8, sizeof(utf8), "BAD_INPUT", NULL);
    failures += entrypoint_refusal("trailing input", "{} trailing", 11, "BAD_INPUT", NULL);
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "dev.retrieval.pair", NULL);
    if (!spec) return failures + 1;
    size_t budget = zcl_command_registry_input_budget_bytes(spec);
    if (budget < length) return failures + 1;
    char *padded = malloc(budget + 1u);
    if (!padded) return failures + 1;
    memcpy(padded, input, length); memset(padded + length, ' ', budget + 1u - length);
    struct entrypoint_result exact = entrypoint_run(padded, budget, "pair", false, false);
    failures += entrypoint_check("exact byte budget", &exact, ZCL_COMMAND_EXIT_OK, NULL, NULL);
    failures += entrypoint_refusal("one byte over budget", padded, budget + 1u, "BAD_INPUT", NULL);
    free(padded);
    return failures;
}
#endif

int test_retrieval_pair_entrypoint(void)
{
#ifdef _WIN32
    fputs("retrieval_pair_entrypoint: unavailable POSIX descriptor controls; host gate must refuse\n", stderr);
    return 1;
#else
    int failures = 0;
    char workspace[4096], root[65], input[8192], malformed[16384];
    test_make_tmpdir(workspace, sizeof(workspace), "retrieval", "entrypoint");
    bool ready = retrieval_pair_public_fixture(workspace, root);
    int count = ready ? snprintf(input, sizeof(input), "{\"workspace\":\"%s\",\"artifact_root\":\"%s\"}", workspace, root) : -1;
    if (count <= 0 || (size_t)count >= sizeof(input)) return 1;
    struct entrypoint_result control = entrypoint_run(input, (size_t)count, "pair", false, false);
    const struct json_value *data = json_get(&control.reply, "data");
    bool measured = json_get_int(json_get(data, "directional_delta_bp")) == 8000;
    failures += !measured;
    failures += entrypoint_check("valid stdin pair delta8000", &control, ZCL_COMMAND_EXIT_OK, NULL, NULL);
    struct entrypoint_result argv = entrypoint_run(input, (size_t)count, "pair", true, false);
    failures += entrypoint_check("valid argv pair", &argv, ZCL_COMMAND_EXIT_OK, NULL, NULL);
    int n = snprintf(malformed, sizeof(malformed), "{\"workspace\":\"%s\",\"workspace\":\"%s\",\"artifact_root\":\"%s\"}", workspace, workspace, root);
    if (n <= 0 || (size_t)n >= sizeof(malformed)) failures++;
    else failures += entrypoint_refusal("duplicate otherwise valid workspace", malformed, (size_t)n, "INVALID_INPUT", "duplicate");
    n = snprintf(malformed, sizeof(malformed), "{\"workspace\":0,\"artifact_root\":\"%s\"}", root);
    if (n <= 0 || (size_t)n >= sizeof(malformed)) failures++;
    else failures += entrypoint_refusal("wrong workspace type with valid root", malformed, (size_t)n, "INVALID_INPUT", "workspace");
    failures += entrypoint_boundaries(input);
    struct entrypoint_result unknown = entrypoint_run(input, (size_t)count, "unknown", false, false);
    failures += entrypoint_check("unknown verb", &unknown, ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_COMMAND", NULL);
    struct entrypoint_result failed = entrypoint_run(input, (size_t)count, "pair", false, true);
    printf("  entrypoint unwritable stdout after valid pair: status=%d\n", failed.status);
    failures += failed.status != ZCL_COMMAND_EXIT_INTERNAL;
    json_free(&failed.reply);
    failures += test_rm_rf_recursive(workspace) != 0;
    printf("retrieval_pair_entrypoint: %d failures\n", failures);
    return failures;
#endif
}
