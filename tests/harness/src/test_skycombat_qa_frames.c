/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* purpose: verify bounded QA frame arguments and unchanged output on refusal. */
#include "test/test_core.h"
#include "test/host_tool_capture.h"
#include "sky_combat/qa_frames.h"
#include "platform/resident_launch.h"
#include "json/json.h"
#include <string.h>
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

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
        struct json_value reply;
        json_init(&reply);
        /* Agent stdout is protocol only: every line is a v=1 JSON reply. */
        bool valid = *line == '{' && json_read(&reply, line, (size_t)(end - line)) &&
            json_get_int(json_get(&reply, "v")) == 1 &&
            skycombat_agent_reply_matches(&reply, replies);
        json_free(&reply);
        if (!valid) return false;
        ++replies;
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
        /* raylib trace output is routed to stderr by the game's own callback. */
        ASSERT(strstr(diagnostics, "raylib [INFO] QA_TRACE"));
        ASSERT(!strstr(output, "QA_TRACE"));
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

static bool skycombat_file_read(const char *path, unsigned char *bytes, size_t cap, size_t *size)
{
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    *size = fread(bytes, 1, cap, file);
    bool ok = !ferror(file);
    fclose(file);
    return ok;
}

static bool skycombat_file_exists(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file) fclose(file);
    return file != NULL;
}

static int skycombat_capture_refusal(const char *const args[], const char *path,
                                    const char *needle, const char *label)
{
    int failures = 0;
    char output[2048] = {0}, diagnostics[513] = {0};
    TEST(label) {
        int rc = skycombat_agent_capture(args, output, sizeof(output), diagnostics);
        ASSERT(rc != 0);
        ASSERT(!skycombat_file_exists(path));
        ASSERT(strstr(diagnostics, needle) != NULL);
        PASS();
    }
_test_next:;
    return failures;
}

static int skycombat_capture_file(void)
{
    int failures = 0;
    char dir[PATH_MAX], path[PATH_MAX + 16], flag[PATH_MAX + 32];
    test_make_tmpdir(dir, sizeof(dir), "skycapture", "a");
    snprintf(path, sizeof(path), "%s/p.png", dir);
    snprintf(flag, sizeof(flag), "--capture=%s", path);
    const char *good[] = {QA_ENTRY, "--fixture-capture-ok", "--qa-frames=2", flag, NULL};
    char output[2048] = {0}, diagnostics[513] = {0};
    TEST("capture: --qa-frames=2 --capture=PATH writes a PNG and names PATH and its size") {
        ASSERT_EQ(skycombat_agent_capture(good, output, sizeof(output), diagnostics), 0);
        static unsigned char png[1024u * 1024u];
        size_t size = 0;
        ASSERT(skycombat_file_read(path, png, sizeof(png), &size));
        static const unsigned char signature[8] = {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
        ASSERT(size > 33 && memcmp(png, signature, 8) == 0);
        ASSERT(memcmp(png + 12, "IHDR", 4) == 0);
        uint32_t width = (uint32_t)png[16] << 24 | (uint32_t)png[17] << 16 | (uint32_t)png[18] << 8 | png[19];
        uint32_t height = (uint32_t)png[20] << 24 | (uint32_t)png[21] << 16 | (uint32_t)png[22] << 8 | png[23];
        ASSERT(width > 0 && height > 0);
        char line[PATH_MAX + 64];
        snprintf(line, sizeof(line), "%s (%zu bytes)", path, size);
        ASSERT(strstr(output, line) != NULL);
        PASS();
    }
_test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int skycombat_capture_colour(void)
{
    int failures = 0;
    char dir[PATH_MAX], path[PATH_MAX + 16], flag[PATH_MAX + 32];
    test_make_tmpdir(dir, sizeof(dir), "skycapture", "d");
    snprintf(path, sizeof(path), "%s/p.png", dir);
    snprintf(flag, sizeof(flag), "--capture=%s", path);
    const char *good[] = {QA_ENTRY, "--fixture-capture-ok", "--qa-frames=2", flag, NULL};
    char output[2048] = {0}, diagnostics[513] = {0};
    TEST("capture: prints the player colour sampled at the projected aircraft, near PLAYER 1's RED") {
        /* RED is {230,41,55}. The fixture paints the first cube the game drew
         * (the player's fuselage, in the colour the game gave PLAYER 1) at the
         * point GetWorldToScreen reports; a game that never samples and prints
         * the pixel has no such line. */
        ASSERT_EQ(skycombat_agent_capture(good, output, sizeof(output), diagnostics), 0);
        const char *at = strstr(output, "Sky Combat: player colour ");
        ASSERT(at != NULL);
        int red = -1, green = -1, blue = -1, x = -1, y = -1;
        ASSERT_EQ(sscanf(at, "Sky Combat: player colour %d,%d,%d at %d,%d", &red, &green, &blue, &x, &y), 5);
        ASSERT(abs(red - 230) <= 8 && abs(green - 41) <= 8 && abs(blue - 55) <= 8);
        /* The 640x480 fixture frame, projected to (320,240), is resized to 480x360. */
        ASSERT(abs(x - 240) <= 2 && abs(y - 180) <= 2);
        PASS();
    }
_test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int skycombat_capture_write_failures(void)
{
    int failures = 0;
    char dir[PATH_MAX], path[PATH_MAX + 16], flag[PATH_MAX + 32], missing_flag[PATH_MAX + 48];
    test_make_tmpdir(dir, sizeof(dir), "skycapture", "c");
    snprintf(path, sizeof(path), "%s/p.png", dir);
    snprintf(flag, sizeof(flag), "--capture=%s", path);
    snprintf(missing_flag, sizeof(missing_flag), "--capture=%s/no-such-dir/p.png", dir);
    const char *unwritable[] = {QA_ENTRY, "--fixture-capture-ok", "--qa-frames=1", missing_flag, NULL};
    char output[2048] = {0}, diagnostics[513] = {0};
    TEST("capture: an unwritable PATH fails with a message that names it") {
        int rc = skycombat_agent_capture(unwritable, output, sizeof(output), diagnostics);
        ASSERT(rc != 0);
        ASSERT(strstr(diagnostics, "no-such-dir") != NULL);
        PASS();
    }
_test_next:;
    const char *no_readback[] = {QA_ENTRY, "--qa-frames=1", flag, NULL};
    failures += skycombat_capture_refusal(no_readback, path, path,
        "capture: a failed readback exits nonzero, names PATH and leaves no file");
    test_cleanup_tmpdir(dir);
    return failures;
}

static int skycombat_capture_usage(void)
{
    int failures = 0;
    char dir[PATH_MAX], path[PATH_MAX + 16], flag[PATH_MAX + 32];
    test_make_tmpdir(dir, sizeof(dir), "skycapture", "b");
    snprintf(path, sizeof(path), "%s/p.png", dir);
    snprintf(flag, sizeof(flag), "--capture=%s", path);
    const char *alone[] = {QA_ENTRY, "--fixture-capture-ok", flag, NULL};
    const char *agent[] = {QA_ENTRY, "--fixture-capture-ok",
        "--fixture-agent={\"v\":1,\"id\":1,\"op\":\"close\"}\n", "--agent-stdio", flag, NULL};
    const char *empty[] = {QA_ENTRY, "--fixture-capture-ok", "--qa-frames=1", "--capture=", NULL};
    const char *twice[] = {QA_ENTRY, "--fixture-capture-ok", "--qa-frames=1", flag, flag, NULL};
    failures += skycombat_capture_refusal(alone, path, "--capture",
        "capture: --capture without --qa-frames is refused and writes no file");
    failures += skycombat_capture_refusal(agent, path, "--capture",
        "capture: --capture with --agent-stdio is refused and writes no file");
    failures += skycombat_capture_refusal(empty, path, "--capture",
        "capture: an empty PATH is refused");
    failures += skycombat_capture_refusal(twice, path, "--capture",
        "capture: a repeated --capture is refused and writes no file");
    test_cleanup_tmpdir(dir);
    return failures;
}

#if !defined(_WIN32)
static const char sky_fixture_nonce[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
struct sky_resident_fixture {
    pid_t pid;
    int socket, diagnostics, stdout_fd;
    char stdout_text[4096];
};

static bool sky_resident_io(int fd, void *bytes, size_t size, bool writing)
{
    size_t done = 0;
    while (done < size) {
        struct pollfd p = {.fd = fd, .events = writing ? POLLOUT : POLLIN};
        int ready = poll(&p, 1, 5000);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return false;
        ssize_t got;
        if (writing) {
#if defined(MSG_NOSIGNAL)
            got = send(fd, (char *)bytes + done, size - done, MSG_NOSIGNAL);
#else
            got = send(fd, (char *)bytes + done, size - done, 0);
#endif
        } else got = read(fd, (char *)bytes + done, size - done);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return false;
        done += (size_t)got;
    }
    return true;
}

static void sky_resident_child_stdio(int sockets[2], int diagnostics[2], int standard_output[2])
{
    /* Preserve the socket while mapping fd 3 even when socketpair used 3. */
    int ipc = dup(sockets[1]);
    close(sockets[0]); close(sockets[1]); close(diagnostics[0]); close(standard_output[0]);
    if (ipc < 0 || dup2(standard_output[1], STDOUT_FILENO) < 0 ||
        dup2(diagnostics[1], STDERR_FILENO) < 0 ||
        dup2(ipc, RESIDENT_LAUNCH_CHILD_FD) < 0) _exit(125);
    close(ipc); close(diagnostics[1]); close(standard_output[1]);
    int input = open("/dev/null", O_RDONLY);
    if (input < 0 || (input != STDIN_FILENO && dup2(input, STDIN_FILENO) < 0)) _exit(125);
    if (input != STDIN_FILENO) close(input);
}

static void sky_resident_child_exec(bool window_fails, unsigned closed_mask,
                                     unsigned endpoint, bool raise_test, const char *closed_option)
{
    const char *args[12]; size_t n = 0;
    args[n++] = QA_ENTRY;
    if (window_fails) args[n++] = "--fixture-window-fails";
    if (closed_mask) args[n++] = closed_option;
    if (raise_test) args[n++] = "--fixture-raise";
    args[n++] = "--fixture-resident";
    args[n++] = "--resident"; args[n++] = sky_fixture_nonce;
    args[n++] = "--agent"; args[n++] = "--seed=4294967295"; args[n] = NULL;
    if (endpoint == 1) close(RESIDENT_LAUNCH_CHILD_FD);
    for (int fd = 0; fd < 3; fd++)
        if (closed_mask & (1u << fd)) close(fd);
    execv(QA_ENTRY, (char *const *)args);
    _exit(126);
}

static bool sky_resident_start_config(struct sky_resident_fixture *f, bool window_fails,
                                      unsigned closed_mask, unsigned endpoint, bool raise_test)
{
    int sockets[2], diagnostics[2], standard_output[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return false;
    if (pipe(diagnostics) != 0) { close(sockets[0]); close(sockets[1]); return false; }
    if (pipe(standard_output) != 0) {
        close(sockets[0]); close(sockets[1]); close(diagnostics[0]); close(diagnostics[1]);
        return false;
    }
#if defined(SO_NOSIGPIPE)
    int enabled = 1;
    if (setsockopt(sockets[0], SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
        close(sockets[0]); close(sockets[1]); close(diagnostics[0]); close(diagnostics[1]);
        close(standard_output[0]); close(standard_output[1]);
        return false;
    }
#endif
#if defined(__APPLE__)
    /* XNU: shutdown(SHUT_RD) does not make the peer's write fail, so close our end. */
    if (endpoint == 2) { close(sockets[0]); sockets[0] = -1; }
#else
    if (endpoint == 2 && shutdown(sockets[0], SHUT_RD) != 0) {
        close(sockets[0]); close(sockets[1]); close(diagnostics[0]); close(diagnostics[1]);
        close(standard_output[0]); close(standard_output[1]); return false;
    }
#endif
    char closed_option[40];
    snprintf(closed_option, sizeof(closed_option), "--fixture-closed-stdio=%u", closed_mask);
    pid_t pid = fork();
    if (pid == 0) {
        sky_resident_child_stdio(sockets, diagnostics, standard_output);
        sky_resident_child_exec(window_fails, closed_mask, endpoint, raise_test, closed_option);
    }
    close(sockets[1]); close(diagnostics[1]); close(standard_output[1]);
    if (pid < 0) { close(sockets[0]); close(diagnostics[0]); close(standard_output[0]); return false; }
    *f = (struct sky_resident_fixture){.pid = pid, .socket = sockets[0],
        .diagnostics = diagnostics[0], .stdout_fd = standard_output[0]};
    return true;
}

static bool sky_resident_start_stdio(struct sky_resident_fixture *f, bool window_fails,
                                      unsigned closed_mask, unsigned endpoint)
{
    return sky_resident_start_config(f, window_fails, closed_mask, endpoint, false);
}

static bool sky_resident_start(struct sky_resident_fixture *f, bool window_fails)
{
    return sky_resident_start_stdio(f, window_fails, 0, 0);
}

static bool sky_resident_text(int fd, char output[4096])
{
    size_t used = 0;
    for (;;) {
        ssize_t got = read(fd, output + used, 4095 - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { output[used] = '\0'; return got == 0; }
        used += (size_t)got;
        output[used] = '\0';
        if (used == 4095) return false;
    }
}

static int sky_resident_finish(struct sky_resident_fixture *f, char output[4096])
{
    int status = 0;
    pid_t reaped = 0;
    for (unsigned i = 0; i < 500; i++) {
        reaped = waitpid(f->pid, &status, WNOHANG);
        if (reaped != 0) break;
        (void)poll(NULL, 0, 10);
    }
    if (!reaped) { kill(f->pid, SIGKILL); (void)waitpid(f->pid, &status, 0); }
    bool captured = sky_resident_text(f->diagnostics, output);
    if (!sky_resident_text(f->stdout_fd, f->stdout_text)) captured = false;
    close(f->socket); close(f->diagnostics); close(f->stdout_fd); f->pid = -1;
    return captured && reaped > 0 && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static bool sky_resident_receive(struct sky_resident_fixture *f, char payload[4096])
{
    struct resident_result_header header;
    return sky_resident_io(f->socket, &header, sizeof(header), false) &&
        !memcmp(header.magic, "z23-res-run-v1\0\0", sizeof(header.magic)) &&
        !memcmp(header.nonce, sky_fixture_nonce, sizeof(header.nonce)) &&
        header.payload_len < 4096 &&
        sky_resident_io(f->socket, payload, header.payload_len, false) &&
        (payload[header.payload_len] = '\0', true);
}

static struct resident_result_header sky_resident_header(uint32_t length)
{
    struct resident_result_header header = {.magic = "z23-res-run-v1", .payload_len = length};
    memcpy(header.nonce, sky_fixture_nonce, sizeof(header.nonce));
    return header;
}

static bool sky_resident_request(struct sky_resident_fixture *f, const char *request, bool fragment)
{
    struct resident_result_header header = sky_resident_header((uint32_t)strlen(request));
    if (!fragment)
        return sky_resident_io(f->socket, &header, sizeof(header), true) &&
            sky_resident_io(f->socket, (void *)request, strlen(request), true);
    const size_t prefix = sizeof(header.magic) + sizeof(header.nonce);
    if (!sky_resident_io(f->socket, &header, 7, true)) return false;
    (void)poll(NULL, 0, 30);
    if (!sky_resident_io(f->socket, (char *)&header + 7, prefix - 7, true)) return false;
    (void)poll(NULL, 0, 30);
    if (!sky_resident_io(f->socket, (char *)&header + prefix, sizeof(header) - prefix, true) ||
        !sky_resident_io(f->socket, (void *)request, 3, true)) return false;
    (void)poll(NULL, 0, 30);
    return sky_resident_io(f->socket, (char *)request + 3, strlen(request) - 3, true);
}

static bool sky_resident_json(struct sky_resident_fixture *f, unsigned frame,
                               unsigned id, int64_t accepted, const char *error)
{
    char payload[4096]; struct json_value reply; json_init(&reply);
    bool ok = sky_resident_receive(f, payload) && json_read(&reply, payload, strlen(payload)) &&
        json_get_int(json_get(&reply, "frame")) == frame &&
        json_get_int(json_get(&reply, "id")) == id;
    const struct json_value *accepted_id = json_get(&reply, "accepted_id");
    ok = ok && accepted_id && (accepted < 0 ? accepted_id->type == JSON_NULL
        : accepted_id->type == JSON_INT && json_get_int(accepted_id) == accepted);
    const struct json_value *value = json_get(&reply, "error");
    ok = ok && (error ? value && value->type == JSON_STR && !strcmp(json_get_str(value), error)
                     : json_get_bool(json_get(&reply, "ok")));
    json_free(&reply);
    return ok;
}

static int skycombat_resident_frames(void)
{
    int failures = 0; struct sky_resident_fixture f = {.pid = -1};
    char payload[4096] = {0}, output[4096];
    TEST("resident: native fragmented framing, exact ticks, IDs and cleanup use actual entrypoint") {
        ASSERT(sky_resident_start(&f, false));
        ASSERT(sky_resident_receive(&f, payload) && !strcmp(payload, "READY"));
        ASSERT(sky_resident_request(&f, "{\"v\":1,\"id\":1,\"op\":\"observe\"}", true));
        ASSERT(sky_resident_json(&f, 0, 1, 1, NULL));
        ASSERT(sky_resident_request(&f, "{\"v\":1,\"id\":2,\"op\":\"step\",\"frames\":60,\"input\":{}}", false));
        ASSERT(sky_resident_json(&f, 60, 2, 2, NULL));
        ASSERT(sky_resident_request(&f, "{\"v\":1,\"id\":2,\"op\":\"step\",\"frames\":1,\"input\":{}}", false));
        ASSERT(sky_resident_json(&f, 60, 2, 2, "STALE_REQUEST_ID"));
        ASSERT(sky_resident_request(&f, "{\"v\":1,\"id\":3,\"op\":\"observe\"}\n", false));
        ASSERT(sky_resident_json(&f, 60, 3, 3, NULL));
        ASSERT(sky_resident_request(&f, "{\"v\":1,\"id\":4,\"op\":\"close\"}", false));
        ASSERT(sky_resident_json(&f, 60, 4, 4, NULL));
        ASSERT_EQ(sky_resident_finish(&f, output), 0);
        ASSERT(strstr(output, "closed=1 destroyed=127 unloads=1"));
        ASSERT(strstr(output, "QA_AGENT ticks=60 keys=0 polls=0"));
        ASSERT(strstr(output, "QA_RESIDENT window stdout"));
        ASSERT(strstr(output, "QA_RESIDENT close stdout"));
        ASSERT_EQ(strcmp(f.stdout_text, "QA_RESIDENT stdout restored\n"), 0);
        PASS();
    } _test_next:;
    if (f.pid > 0) { fprintf(stderr, "resident fixture: %s\n", payload); (void)sky_resident_finish(&f, output); }
    return failures;
}

static struct resident_result_header sky_resident_end_header(unsigned mode)
{
    struct resident_result_header header = sky_resident_header(mode == 4 ? 4097 : 20);
    if (mode == 0 || mode == 5) memcpy(header.magic, "z23-res-stop-v1\0", sizeof(header.magic));
    if (mode == 5) header.nonce[64] = 'x';
    if (mode == 6) header.magic[0] = 'x';
    return header;
}

/* Send one request, then make the child's reply write fail. Linux: shutdown(SHUT_RD)
 * first. macOS does not fail the peer's write on SHUT_RD, so stop the child, send the
 * request, close our end and continue the child; its reply then hits a closed peer. */
static bool sky_resident_request_peer_gone(struct sky_resident_fixture *f, const char *request)
{
#if defined(__APPLE__)
    if (kill(f->pid, SIGSTOP) != 0) return false;
    bool sent = sky_resident_request(f, request, false);
    close(f->socket); f->socket = -1;
    bool resumed = kill(f->pid, SIGCONT) == 0;
    return sent && resumed;
#else
    return shutdown(f->socket, SHUT_RD) == 0 && sky_resident_request(f, request, false);
#endif
}

static bool sky_resident_send_end(struct sky_resident_fixture *f, unsigned mode)
{
    struct resident_result_header header = sky_resident_end_header(mode);
    size_t prefix = sizeof(header.magic) + sizeof(header.nonce);
    if (mode <= 3) {
        if (mode == 0) return sky_resident_io(f->socket, &header, prefix, true);
        if (mode == 2 && !sky_resident_io(f->socket, &header, 10, true)) return false;
        if (mode == 3 && (!sky_resident_io(f->socket, &header, sizeof(header), true) ||
                         !sky_resident_io(f->socket, (void *)"{", 1, true))) return false;
        return shutdown(f->socket, SHUT_WR) == 0;
    }
    if (mode == 4) return sky_resident_io(f->socket, &header, sizeof(header), true);
    if (mode == 5 || mode == 6) return sky_resident_io(f->socket, &header, prefix, true);
    if (mode == 8)
        return sky_resident_request_peer_gone(f, "{\"v\":1,\"id\":1,\"op\":\"observe\"}");
    return true;
}

static int skycombat_resident_end(unsigned mode)
{
    int failures = 0; struct sky_resident_fixture f = {.pid = -1};
    char payload[4096] = {0}, output[4096];
    const char *errors[] = {NULL, NULL, "INCOMPLETE_REQUEST", "INCOMPLETE_REQUEST",
                            "REQUEST_TOO_LARGE", "INVALID_FRAME", "INVALID_FRAME", NULL, NULL};
    TEST("resident: stop/EOF/framing/init/broken-reply paths preserve streams and reap normally") {
        ASSERT(sky_resident_start(&f, mode == 7));
        ASSERT(sky_resident_receive(&f, payload) && !strcmp(payload, "READY"));
        ASSERT(sky_resident_send_end(&f, mode));
        if (errors[mode]) ASSERT(sky_resident_json(&f, 0, 0, -1, errors[mode]));
        ASSERT_EQ(sky_resident_finish(&f, output), errors[mode] || mode >= 7 ? 1 : 0);
        if (mode == 7) ASSERT(strstr(output, "window initialization failed"));
        else ASSERT(strstr(output, "closed=1 destroyed=127 unloads=1"));
        ASSERT(strstr(output, "QA_RESIDENT window stdout"));
        if (mode != 7) ASSERT(strstr(output, "QA_RESIDENT close stdout"));
        if (mode == 8) ASSERT(strstr(output, "Sky Combat agent: reply IO failed"));
        ASSERT_EQ(strcmp(f.stdout_text, "QA_RESIDENT stdout restored\n"), 0);
        PASS();
    } _test_next:;
    if (f.pid > 0) { (void)sky_resident_finish(&f, output); fprintf(stderr, "%s\n", output); }
    return failures;
}

static int skycombat_resident_closed_stdio(unsigned mask, unsigned mode)
{
    int failures = 0; struct sky_resident_fixture f = {.pid = -1};
    char payload[4096] = {0}, output[4096] = {0};
    TEST("resident: closed stdio normalizes access modes and restores original mask on every exit") {
        ASSERT(sky_resident_start_config(&f, mode == 2, mask, mode >= 3 ? mode - 2 : 0, true));
        if (mode < 3) ASSERT(sky_resident_receive(&f, payload) && !strcmp(payload, "READY"));
        if (mode <= 1) {
            if (mode == 1)
                ASSERT(sky_resident_request_peer_gone(&f, "{\"v\":1,\"id\":1,\"op\":\"observe\"}"));
            else
                ASSERT(sky_resident_request(&f, "{\"v\":1,\"id\":1,\"op\":\"observe\"}", false));
            if (!mode) {
                ASSERT(sky_resident_json(&f, 0, 1, 1, NULL));
                ASSERT(sky_resident_request(&f, "{\"v\":1,\"id\":2,\"op\":\"close\"}", false));
                ASSERT(sky_resident_json(&f, 0, 2, 2, NULL));
            }
        }
        ASSERT_EQ(sky_resident_finish(&f, output), mode ? 1 : 0);
        ASSERT_EQ(strcmp(f.stdout_text, mask & 2u ? "" : "QA_RESIDENT stdout restored\n"), 0);
        if (!(mask & 4u) && mode < 2) ASSERT(strstr(output, "closed=1 destroyed=127 unloads=1"));
        PASS();
    } _test_next:;
    if (f.pid > 0) (void)sky_resident_finish(&f, output);
    if (failures) fprintf(stderr, "closed stdio mask=%u mode=%u diagnostics=%s stdout=%s\n",
                           mask, mode, output, f.stdout_text);
    return failures;
}

static bool sky_resident_raise_marker(struct sky_resident_fixture *f)
{
    char line[4096]; size_t used = 0;
    while (used < sizeof(line) - 1) {
        if (!sky_resident_io(f->diagnostics, line + used, 1, false)) return false;
        line[++used] = '\0';
        if (strstr(line, "QA_RAISE applied\n")) return true;
    }
    return false;
}

static int skycombat_resident_raise(void)
{
    int failures = 0; struct sky_resident_fixture f = {.pid = -1};
    char payload[4096] = {0}, output[4096] = {0};
    TEST("raise: resident idle, partial header and partial payload dispatch without ticks/RNG") {
        ASSERT(sky_resident_start_config(&f, false, 0, 0, true));
        ASSERT(sky_resident_receive(&f, payload) && !strcmp(payload, "READY"));
        ASSERT_EQ(kill(f.pid, SIGUSR1), 0);
        ASSERT(sky_resident_raise_marker(&f)); /* No request bytes exist yet. */
        const char *request = "{\"v\":1,\"id\":1,\"op\":\"observe\"}";
        struct resident_result_header header = sky_resident_header((uint32_t)strlen(request));
        ASSERT(sky_resident_io(f.socket, &header, 7, true));
        ASSERT_EQ(kill(f.pid, SIGUSR1), 0);
        ASSERT(sky_resident_raise_marker(&f)); /* The run header is incomplete. */
        ASSERT(sky_resident_io(f.socket, (char *)&header + 7, sizeof(header) - 7, true));
        ASSERT(sky_resident_io(f.socket, (void *)request, 3, true));
        ASSERT_EQ(kill(f.pid, SIGUSR1), 0);
        ASSERT(sky_resident_raise_marker(&f)); /* The JSON payload is incomplete. */
        ASSERT(sky_resident_io(f.socket, (char *)request + 3, strlen(request) - 3, true));
        ASSERT(sky_resident_json(&f, 0, 1, 1, NULL));
        ASSERT(sky_resident_request(&f, "{\"v\":1,\"id\":2,\"op\":\"close\"}", false));
        ASSERT(sky_resident_json(&f, 0, 2, 2, NULL));
        ASSERT_EQ(sky_resident_finish(&f, output), 0);
        ASSERT(strstr(output, "QA_RAISE restore=3 focus=3 prior=1 pure=1"));
        ASSERT(strstr(output, "closed=1 destroyed=127 unloads=1"));
        PASS();
    } _test_next:;
    if (f.pid > 0) (void)sky_resident_finish(&f, output);
    if (failures) fprintf(stderr, "%s\n", output);
    return failures;
}

static int skycombat_raise_other_modes(bool stdio)
{
    int failures = 0; char output[8192] = {0}, diagnostics[513] = {0};
    const char *interactive[] = {QA_ENTRY, "--fixture-raise", "--qa-frames=2", NULL};
    const char *agent[] = {QA_ENTRY,
        "--fixture-agent={\"v\":1,\"id\":1,\"op\":\"observe\"}\n{\"v\":1,\"id\":2,\"op\":\"close\"}\n",
        "--fixture-raise", "--agent-stdio", NULL};
    TEST("raise: stdio byte waits and interactive tick dispatch preserve prior handler and input polls") {
        ASSERT_EQ(skycombat_agent_capture(stdio ? agent : interactive, output, sizeof(output), diagnostics), 0);
        ASSERT(strstr(diagnostics, stdio ? "QA_RAISE restore=2 focus=2 prior=1 pure=1"
                                        : "QA_RAISE restore=1 focus=1 prior=1 pure=1 events=0"));
        if (stdio) ASSERT(strstr(output, "\"frame\":0"));
        PASS();
    } _test_next:;
    if (failures) fprintf(stderr, "%s\n%s\n", output, diagnostics);
    return failures;
}

static int skycombat_actual_model_replay(void)
{
    int failures = 0;
    char cwd[PATH_MAX], image[PATH_MAX];
    const char *args[] = {"build/bin/z23_bounded_run", "60000", image, NULL};
    char output[32768] = {0};
    TEST("replay: native maintained models preserve full state across partition/observe/capture/delay") {
        ASSERT(getcwd(cwd, sizeof(cwd)) != NULL);
        int length = snprintf(image, sizeof(image), "%s/build/bin/skycombat-model-replay", cwd);
        ASSERT(length > 0 && (size_t)length < sizeof(image));
        int status = test_host_tool_capture(args, output, sizeof(output), 70000);
        if (status) fprintf(stderr, "%s\n", output);
        ASSERT_EQ(status, 0);
        ASSERT(strstr(output, "skycombat actual-model replay: PASS ticks=120"));
        ASSERT(strstr(output, "seed_control=changed input_control=changed"));
        ASSERT(strstr(output, "smoke=observed patrol=observed chase=observed"));
        PASS();
    } _test_next:;
    return failures;
}
#endif

static int skycombat_resident_options(void)
{
    static const char nonce[] =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const char *const invalid[][6] = {
        {"--resident", nonce, NULL}, {"--agent", NULL},
        {"--resident", "", "--agent", NULL},
        {"--resident", "abc", "--agent", NULL},
        {"--resident", "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd", "--agent", NULL},
        {"--resident", nonce, "--agent-stdio", NULL},
        {"--resident", nonce, "--agent", "--qa-frames=1", NULL},
        {"--resident", nonce, "--agent", "--seed=4294967296", NULL},
        {"--resident", nonce, "--agent", "--seed=01", NULL},
        {"--seed=1", NULL}
    };
    int failures = 0;
    TEST("resident: invalid mode/nonce/seed combinations refuse before any window") {
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
            const char *args[8] = {QA_ENTRY};
            size_t n = 0;
            while (invalid[i][n]) { args[n + 1] = invalid[i][n]; n++; }
            char output[8192] = {0}, diagnostics[513] = {0};
            ASSERT_EQ(skycombat_agent_capture(args, output, sizeof(output), diagnostics), 2);
            ASSERT(strstr(output, "windows=0 frames=0 closed=0"));
        }
        PASS();
    }
#if defined(_WIN32)
    TEST("resident: Windows names unsupported mode and keeps stdio available") {
        const char *args[] = {QA_ENTRY, "--resident", nonce, "--agent", NULL};
        char output[8192] = {0}, diagnostics[513] = {0};
        ASSERT_EQ(skycombat_agent_capture(args, output, sizeof(output), diagnostics), 2);
        ASSERT(strstr(diagnostics, "RESIDENT_UNSUPPORTED_WINDOWS"));
        ASSERT(strstr(output, "windows=0 frames=0 closed=0"));
        PASS();
    }
#endif
_test_next:;
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
    failures += skycombat_capture_file();
    failures += skycombat_capture_colour();
    failures += skycombat_capture_usage();
    failures += skycombat_capture_write_failures();
    failures += skycombat_agent_session();
    failures += skycombat_agent_refusals();
    failures += skycombat_agent_resize_failure();
    failures += skycombat_agent_capture_retry();
    failures += skycombat_agent_physical_bytes("--fixture-prefix-nul");
    failures += skycombat_agent_physical_bytes("--fixture-prefix-sub");
    failures += skycombat_agent_transport_bounds();
    failures += skycombat_resident_options();
#if !defined(_WIN32)
    failures += skycombat_resident_frames();
    for (unsigned mode = 0; mode < 9; mode++) failures += skycombat_resident_end(mode);
    for (unsigned mask = 1; mask <= 7; mask++) failures += skycombat_resident_closed_stdio(mask, 0);
    for (unsigned mode = 1; mode <= 4; mode++) failures += skycombat_resident_closed_stdio(7, mode);
    failures += skycombat_resident_raise();
    failures += skycombat_raise_other_modes(true);
    failures += skycombat_raise_other_modes(false);
    failures += skycombat_actual_model_replay();
#endif
    return failures;
}
