/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* purpose: verify bounded QA frame arguments and unchanged output on refusal. */
#include "test/test_core.h"
#include "test/host_tool_capture.h"
#include "sky_combat/qa_frames.h"
#include "json/json.h"
#include <string.h>

#if defined(_WIN32)
#define QA_ENTRY "build/bin/skycombat-qa-entrypoint.exe"
#else
#define QA_ENTRY "build/bin/skycombat-qa-entrypoint"
#endif

#if defined(_WIN32)
static int skycombat_agent_windows_capture(const char *const args[], char *output,
    size_t capacity, struct platform_process_evidence *evidence)
{
    char cwd[PATH_MAX], image[PATH_MAX], system_root[PATH_MAX + 16], search_path[8192];
    const char *root = getenv("SystemRoot"), *path = getenv("PATH");
    if (!root || !path || !getcwd(cwd, sizeof(cwd))) return -1;
    int image_length = snprintf(image, sizeof(image), "%s/%s", cwd, args[0]);
    int root_length = snprintf(system_root, sizeof(system_root), "SystemRoot=%s", root);
    int path_length = snprintf(search_path, sizeof(search_path), "Path=%s", path);
    if (image_length < 0 || (size_t)image_length >= sizeof(image) ||
        root_length < 0 || (size_t)root_length >= sizeof(system_root) ||
        path_length < 0 || (size_t)path_length >= sizeof(search_path)) return -1;
    const char *env[] = {system_root, search_path, NULL};
    const struct platform_process_options options = {.image = image, .argv = args, .env = env};
    struct platform_process_capture_result result = {0};
    bool captured = platform_process_capture_evidence(&options, output, capacity,
                                                       5000, &result, evidence);
    return !captured || result.timed_out || result.output_truncated ? -1 : (int)result.exit_code;
}
#endif

static int skycombat_agent_capture(const char *const args[], char *output,
                                   size_t capacity, char diagnostics[513])
{
#if defined(_WIN32)
    struct platform_process_evidence evidence = {0};
    int rc = skycombat_agent_windows_capture(args, output, capacity, &evidence);
#else
    struct zcl_spawn_evidence evidence = {0};
    int rc = zcl_spawn_capture_evidence(args, output, capacity, 5000, &evidence);
    if (!evidence.exit_observed || evidence.timed_out || evidence.stdout_truncated) rc = -1;
#endif
    test_note_bytes("agent stdout", output, strlen(output));
    test_note_bytes("agent stderr", evidence.stderr_tail, evidence.stderr_len);
    if (!evidence.stderr_complete || evidence.stderr_observed != evidence.stderr_len ||
        evidence.stderr_len > 512) return -1;
    memcpy(diagnostics, evidence.stderr_tail, evidence.stderr_len);
    diagnostics[evidence.stderr_len] = '\0';
    return rc;
}

static bool skycombat_agent_reply_matches(const struct json_value *reply, unsigned index)
{
    const char *errors[] = {NULL, NULL, "STALE_REQUEST_ID", "INVALID_REQUEST",
                            "CAPTURE_READBACK", "STALE_REQUEST_ID", NULL, NULL};
    const int accepted[] = {1, 2, 2, 2, 3, 3, 4, 5};
    const int ids[] = {1, 2, 2, 3, 3, 3, 4, 5};
    if (index >= 8) return false;
    const struct json_value *error = json_get(reply, "error");
    bool same_error = errors[index] ? error && error->type == JSON_STR &&
        strcmp(json_get_str(error), errors[index]) == 0 : !error;
    return same_error && json_get_int(json_get(reply, "id")) == ids[index] &&
        json_get_int(json_get(reply, "accepted_id")) == accepted[index] &&
        json_get_int(json_get(reply, "frame")) == (index ? 2 : 0) &&
        json_get_bool(json_get(reply, "ok")) == (errors[index] == NULL) && !json_get(reply, "png");
}

static bool skycombat_agent_replies(const char *output)
{
    unsigned replies = 0;
    for (const char *line = output; *line;) {
        const char *end = strchr(line, '\n');
        if (!end) break;
        if (*line == '{') {
            struct json_value reply;
            json_init(&reply);
            bool valid = json_read(&reply, line, (size_t)(end - line)) &&
                skycombat_agent_reply_matches(&reply, replies);
            json_free(&reply);
            if (!valid) return false;
            ++replies;
        }
        line = end + 1;
    }
    return replies == 8;
}

static int skycombat_agent_session(void)
{
    int failures = 0;
    const char *script = "--fixture-agent="
        "{\"v\":1,\"id\":1,\"op\":\"observe\"}\n"
        "{\"v\":1,\"id\":2,\"op\":\"step\",\"frames\":2,\"input\":{\"move_x\":0.5,\"move_y\":-0.25}}\n"
        "{\"v\":1,\"id\":2,\"op\":\"step\",\"frames\":2,\"input\":{}}\n"
        "{\"v\":1,\"id\":3,\"op\":\"step\",\"frames\":1,\"input\":{\"move_x\":1.1}}\n"
        "{\"v\":1,\"id\":3,\"op\":\"observe\",\"capture\":true}\n"
        "{\"v\":1,\"id\":3,\"op\":\"step\",\"frames\":1,\"input\":{}}\n"
        "{\"v\":1,\"id\":4,\"op\":\"observe\"}\n"
        "{\"v\":1,\"id\":5,\"op\":\"close\"}\n";
    const char *args[] = {QA_ENTRY, script, "--agent-stdio", NULL};
    char output[16384] = {0}, diagnostics[513] = {0};
    TEST("agent: actual entrypoint preserves ticks, request identity, external input and cleanup") {
        int rc = skycombat_agent_capture(args, output, sizeof(output), diagnostics);
        if (rc) fprintf(stderr, "%s", output);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(diagnostics, "QA_AGENT ticks=2 keys=0 polls=0 stick=0.500,-0.250"));
        ASSERT(strstr(diagnostics, "closed=1 destroyed=127 unloads=1"));
        ASSERT(skycombat_agent_replies(output));
        PASS();
    }
_test_next:;
    return failures;
}

static int skycombat_agent_refusal(const char *request, const char *error, int status)
{
    int failures = 0;
    char script[4600], output[8192] = {0}, diagnostics[513] = {0};
    int length = snprintf(script, sizeof(script), "--fixture-agent=%s", request);
    const char *args[] = {QA_ENTRY, script, "--agent-stdio", NULL};
    TEST("agent: malformed or incomplete input cannot advance and cleans resources") {
        ASSERT(length > 0 && (size_t)length < sizeof(script));
        int rc = skycombat_agent_capture(args, output, sizeof(output), diagnostics);
        if (rc != status || !strstr(output, error)) fprintf(stderr, "%s", output);
        ASSERT_EQ(rc, status);
        ASSERT(strstr(output, error));
        ASSERT(strstr(output, "\"frame\":0"));
        ASSERT(strstr(output, "\"accepted_id\":null"));
        ASSERT(strstr(diagnostics, "QA_AGENT ticks=0 keys=0 polls=0"));
        ASSERT(strstr(diagnostics, "closed=1 destroyed=127 unloads=1"));
        PASS();
    }
_test_next:;
    return failures;
}

static int skycombat_agent_refusals(void)
{
    const char *invalid[] = {
        "{\"v\":1,\"id\":1,\"op\":\"step\",\"frames\":121,\"input\":{}}\n",
        "{\"v\":1,\"id\":1,\"op\":\"step\",\"frames\":0,\"input\":{}}\n",
        "{\"v\":1,\"id\":1,\"op\":\"step\",\"frames\":1,\"input\":{\"move_x\":1e9999}}\n",
        "{\"v\":1,\"id\":1,\"op\":\"step\",\"frames\":1,\"input\":{\"fire_guns\":1}}\n",
        "{\"v\":1,\"id\":1,\"op\":\"step\",\"frames\":1,\"input\":{\"move_x\":0,\"move_\\u0078\":1}}\n",
        "{\"v\":1,\"id\":1,\"op\":\"observe\\u0000step\"}\n",
        "{\"v\":1,\"id\":1,\"op\":\"close\",\"capture\":true}\n",
        "{\"v\":1,\"id\":4294967296,\"op\":\"observe\"}\n",
        "{\"v\":1,\"id\":1,\"id\":2,\"op\":\"observe\"}\n",
        "{\"v\":1,\"id\":1,\"op\":\"observe\",\"extra\":0}\n"
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        failures += skycombat_agent_refusal(invalid[i], "INVALID_REQUEST", 0);
    failures += skycombat_agent_refusal("{\"v\":1", "INCOMPLETE_REQUEST", 1);
    char oversized[4099];
    memset(oversized, ' ', sizeof(oversized) - 1);
    oversized[sizeof(oversized) - 1] = '\0';
    failures += skycombat_agent_refusal(oversized, "REQUEST_TOO_LARGE", 1);
    return failures;
}

static int skycombat_agent_resize_failure(void)
{
    int failures = 0;
    const char *args[] = {QA_ENTRY, "--fixture-resize-fails",
        "--fixture-agent={\"v\":1,\"id\":1,\"op\":\"observe\",\"capture\":true}\n"
        "{\"v\":1,\"id\":2,\"op\":\"close\"}\n", "--agent-stdio", NULL};
    char output[8192] = {0}, diagnostics[513] = {0};
    TEST("agent: failed resampler cannot publish allocated but unwritten pixels") {
        ASSERT_EQ(skycombat_agent_capture(args, output, sizeof(output), diagnostics), 0);
        ASSERT(strstr(output, "\"error\":\"CAPTURE_RESIZE\""));
        ASSERT(!strstr(output, "\"png\":"));
        ASSERT(strstr(output, "\"accepted_id\":1"));
        ASSERT(strstr(diagnostics, "QA_AGENT ticks=0 keys=0 polls=0"));
        ASSERT(strstr(diagnostics, "closed=1 destroyed=127 unloads=1"));
        PASS();
    }
_test_next:;
    return failures;
}

static int skycombat_agent_capture_retry(void)
{
    int failures = 0;
    const char *args[] = {QA_ENTRY,
        "--fixture-agent={\"v\":1,\"id\":1,\"op\":\"step\",\"frames\":2,\"input\":{},\"capture\":true}\n"
        "{\"v\":1,\"id\":1,\"op\":\"step\",\"frames\":2,\"input\":{}}\n"
        "{\"v\":1,\"id\":2,\"op\":\"observe\"}\n"
        "{\"v\":1,\"id\":3,\"op\":\"close\"}\n", "--agent-stdio", NULL};
    char output[8192] = {0}, diagnostics[513] = {0};
    TEST("agent: failed capture after step consumes id and duplicate cannot step again") {
        ASSERT_EQ(skycombat_agent_capture(args, output, sizeof(output), diagnostics), 0);
        ASSERT(strstr(output, "\"id\":1,\"ok\":false,\"frame\":2"));
        ASSERT(strstr(output, "\"accepted_id\":1,\"error\":\"CAPTURE_READBACK\""));
        ASSERT(strstr(output, "\"accepted_id\":1,\"error\":\"STALE_REQUEST_ID\""));
        ASSERT(strstr(output, "\"id\":3,\"ok\":true,\"frame\":2"));
        ASSERT(!strstr(output, "\"png\":"));
        ASSERT(strstr(diagnostics, "QA_AGENT ticks=2 keys=0 polls=0"));
        ASSERT(strstr(diagnostics, "closed=1 destroyed=127 unloads=1"));
        PASS();
    }
_test_next:;
    return failures;
}

static int skycombat_agent_physical_bytes(const char *fixture)
{
    int failures = 0;
    const char *args[] = {QA_ENTRY, fixture,
        "--fixture-agent={\"v\":1,\"id\":1,\"op\":\"observe\"}\n"
        "{\"v\":1,\"id\":2,\"op\":\"close\"}\n", "--agent-stdio", NULL};
    char output[8192] = {0}, diagnostics[513] = {0};
    TEST("agent: physical NUL or Ctrl-Z is refused, never mistaken for EOF") {
        ASSERT_EQ(skycombat_agent_capture(args, output, sizeof(output), diagnostics), 0);
        ASSERT(strstr(output, "\"accepted_id\":null,\"error\":\"INVALID_REQUEST\""));
        ASSERT(strstr(output, "\"id\":1,\"ok\":true,\"frame\":0"));
        ASSERT(strstr(output, "\"id\":2,\"ok\":true,\"frame\":0"));
        ASSERT(strstr(diagnostics, "QA_AGENT ticks=0 keys=0 polls=0"));
        ASSERT(strstr(diagnostics, "closed=1 destroyed=127 unloads=1"));
        PASS();
    }
_test_next:;
    return failures;
}

static int skycombat_agent_transport_bounds(void)
{
    int failures = 0;
    char script[16 + 4096 + 2], output[8192] = {0}, diagnostics[513] = {0};
    memcpy(script, "--fixture-agent=", 16);
    memset(script + 16, ' ', 4096);
    const char close_request[] = "{\"v\":1,\"id\":0,\"op\":\"close\"}";
    memcpy(script + 16, close_request, sizeof(close_request) - 1);
    script[16 + 4096] = '\n';
    script[16 + 4096 + 1] = '\0';
    const char *args[] = {QA_ENTRY, script, "--agent-stdio", NULL};
    TEST("agent: exact physical line boundary is accepted and closes cleanly") {
        ASSERT_EQ(skycombat_agent_capture(args, output, sizeof(output), diagnostics), 0);
        ASSERT(strstr(output, "\"id\":0,\"ok\":true,\"frame\":0"));
        ASSERT(strstr(output, "\"accepted_id\":0"));
        ASSERT(strstr(diagnostics, "closed=1 destroyed=127 unloads=1"));
        PASS();
    }
    TEST("agent: broken reply pipe fails after game and window cleanup") {
        const char *broken[] = {QA_ENTRY, "--fixture-broken-reply",
            "--fixture-agent={\"v\":1,\"id\":1,\"op\":\"observe\"}\n", "--agent-stdio", NULL};
        ASSERT_EQ(skycombat_agent_capture(broken, output, sizeof(output), diagnostics), 1);
        ASSERT(output[0] == '\0');
        ASSERT(strstr(diagnostics, "reply IO failed"));
        ASSERT(strstr(diagnostics, "closed=1 destroyed=127 unloads=1"));
        ASSERT(strstr(diagnostics, "QA_AGENT ticks=0 keys=0 polls=0"));
        PASS();
    }
_test_next:;
    return failures;
}

static int skycombat_qa_launch(const char *arg, const char *fixture,
                               unsigned frames, int status, unsigned windows)
{
    int failures = 0;
    const char *argv[4] = {QA_ENTRY, NULL, NULL, NULL};
    unsigned next = 1;
    if (fixture) argv[next++] = fixture;
    if (arg) argv[next] = arg;
    char output[2048] = {0}, expected[128];
    int length = snprintf(expected, sizeof(expected),
        "QA_TEST status=%d windows=%u frames=%u closed=%u destroyed=%u unloads=%u",
        status, windows, frames,
        fixture && strcmp(fixture, "--fixture-window-fails") == 0 ? 0u : windows,
        frames ? 127u : 0u, frames ? 1u : 0u);
    TEST("QA launch: actual entrypoint refuses before window or ends at exact frame bound") {
        ASSERT(length > 0 && (size_t)length < sizeof(expected));
        int rc = test_host_tool_capture(argv, output, sizeof(output), 5000);
        if (rc != status || !strstr(output, expected)) fprintf(stderr, "%s", output);
        ASSERT_EQ(rc, status); ASSERT(strstr(output, expected) != NULL);
        PASS();
    }
_test_next:;
    if (failures) fprintf(stderr, "QA launch argument=%s fixture=%s\n",
        arg ? arg : "interactive", fixture ? fixture : "none");
    return failures;
}

int test_skycombat_qa_frames(void);
int test_skycombat_qa_frames(void)
{
    int failures = 0;
    TEST("QA frames: absent argument preserves interactive selection") {
        char *args[] = {"skycombat", NULL};
        unsigned out = 99;
        ASSERT(sky_combat_qa_frames_parse(1, args, &out));
        ASSERT_EQ(out, 0u);
    }
    TEST("QA frames: canonical lower, ordinary and upper bounds") {
        const struct { char *arg; unsigned expected; } valid[] = {
            {"--qa-frames=1", 1}, {"--qa-frames=60", 60},
            {"--qa-frames=3599", 3599}, {"--qa-frames=3600", 3600}
        };
        for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
            char *args[] = {"skycombat", valid[i].arg};
            unsigned out = 99;
            ASSERT(sky_combat_qa_frames_parse(2, args, &out));
            ASSERT_EQ(out, valid[i].expected);
        }
    }
    TEST("QA frames: malformed, noncanonical and overflowing spans refuse unchanged") {
        char *invalid[] = {
            "--qa-frames=", "--qa-frames=0", "--qa-frames=01",
            "--qa-frames=-1", "--qa-frames=+1", "--qa-frames= 1", "--qa-frames=1 ",
            "--qa-frames=1x", "--qa-frames=1.0", "--qa-frames=3601",
            "--qa-frames=4294967296", "--qa-frames=99999999999999999999999999",
            "--qa-frames", "--help", "", "--qa-frames=1\n"
        };
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
            char *args[] = {"skycombat", invalid[i]};
            unsigned out = 99;
            ASSERT(!sky_combat_qa_frames_parse(2, args, &out));
            ASSERT_EQ(out, 99u);
        }
    }
    TEST("QA frames: duplicate, missing and invalid call shape refuse unchanged") {
        char *args[] = {"skycombat", "--qa-frames=1", "--qa-frames=2"};
        unsigned out = 99;
        ASSERT(!sky_combat_qa_frames_parse(3, args, &out));
        ASSERT_EQ(out, 99u);
        ASSERT(!sky_combat_qa_frames_parse(2, args, NULL));
        ASSERT(!sky_combat_qa_frames_parse(0, args, &out));
        ASSERT_EQ(out, 99u);
        args[1] = NULL;
        ASSERT(!sky_combat_qa_frames_parse(2, args, &out));
        ASSERT_EQ(out, 99u);
        ASSERT(!sky_combat_qa_frames_parse(1, NULL, &out));
        ASSERT_EQ(out, 99u);
    }
_test_next:;
    const char *invalid_launch[] = {"--qa-frames=0", "--qa-frames=-1",
        "--qa-frames=word", "--qa-frames=4294967296",
        "--qa-frames=99999999999999999999999999", "--qa-frames=3601"};
    for (size_t i = 0; i < sizeof(invalid_launch) / sizeof(invalid_launch[0]); ++i)
        failures += skycombat_qa_launch(invalid_launch[i], NULL, 0, 2, 0);
    failures += skycombat_qa_launch("--qa-frames=1", NULL, 1, 0, 1);
    failures += skycombat_qa_launch("--qa-frames=2", NULL, 2, 0, 1);
    failures += skycombat_qa_launch("--qa-frames=60", NULL, 60, 0, 1);
    failures += skycombat_qa_launch(NULL, "--fixture-close=2", 2, 0, 1);
    failures += skycombat_qa_launch("--qa-frames=3", "--fixture-close=2", 2, 1, 1);
    failures += skycombat_qa_launch("--qa-frames=1", "--fixture-window-fails", 0, 1, 1);
    failures += skycombat_agent_session();
    failures += skycombat_agent_refusals();
    failures += skycombat_agent_resize_failure();
    failures += skycombat_agent_capture_retry();
    failures += skycombat_agent_physical_bytes("--fixture-prefix-nul");
    failures += skycombat_agent_physical_bytes("--fixture-prefix-sub");
    failures += skycombat_agent_transport_bounds();
    return failures;
}
