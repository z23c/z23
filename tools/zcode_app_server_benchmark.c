/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: measure one root-bound Codex app-server turn over JSON-RPC stdio. */

#define _POSIX_C_SOURCE 200809L

/* realpath() reaches this TU only through the glibc fortify inline that
 * -D_FORTIFY_SOURCE=2 pulls in at -O1 and above; the build's
 * -D_POSIX_C_SOURCE=200809L declares it nowhere. Without this the file
 * compiles by accident of optimisation and breaks at -O0, under
 * -U_FORTIFY_SOURCE, and on any non-glibc libc. It must precede every
 * include: after them it does nothing. See lib/util/src/hw_profile.c. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/clock.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define APP_PACKET_MAX (512u * 1024u)
#define APP_LINE_MAX (1024u * 1024u)
#define APP_STDERR_MAX (1024u * 1024u)
#define APP_TIMEOUT_MS 300000

struct app_reader {
    int fd;
    char *wire;
    size_t used;
};

struct app_metrics {
    int64_t input_tokens;
    int64_t cached_input_tokens;
    int64_t output_tokens;
    int64_t tool_calls;
    int64_t tool_output_bytes;
    int64_t server_requests_denied;
    int64_t forbidden_tool_calls;
    bool completed;
    char turn_status[32];
    char last_server_request[96];
};

static int64_t monotonic_ms(void)
{
    return clock_now_monotonic_ns() / 1000000LL;
}

static bool beneath(const char *parent, const char *child)
{
    size_t n = strlen(parent);
    return strncmp(parent, child, n) == 0 && child[n] == '/';
}

static bool write_all(int fd, const char *wire, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t wrote = write(fd, wire + off, len - off);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) return false;
        off += (size_t)wrote;
    }
    return true;
}

static bool send_json(int fd, const struct json_value *value)
{
    size_t len = json_write(value, NULL, 0);
    char *wire = len && len < APP_LINE_MAX
        ? zcl_malloc(len + 2u, "app_server.rpc") : NULL;
    if (!wire || json_write(value, wire, len + 1u) != len) {
        free(wire);
        return false;
    }
    wire[len] = '\n';
    bool ok = write_all(fd, wire, len + 1u);
    free(wire);
    return ok;
}

static bool send_request(int fd, int64_t id, const char *method,
                         const struct json_value *params)
{
    struct json_value request;
    json_init(&request); json_set_object(&request);
    bool ok = json_push_kv_str(&request, "jsonrpc", "2.0") &&
        json_push_kv_int(&request, "id", id) &&
        json_push_kv_str(&request, "method", method) &&
        (!params || json_push_kv(&request, "params", params)) &&
        send_json(fd, &request);
    json_free(&request);
    return ok;
}

static bool send_notification(int fd, const char *method)
{
    struct json_value request;
    json_init(&request); json_set_object(&request);
    bool ok = json_push_kv_str(&request, "jsonrpc", "2.0") &&
        json_push_kv_str(&request, "method", method) &&
        send_json(fd, &request);
    json_free(&request);
    return ok;
}

static bool send_denial(int fd, int64_t id)
{
    struct json_value response, error;
    json_init(&response); json_set_object(&response);
    json_init(&error); json_set_object(&error);
    bool ok = json_push_kv_int(&error, "code", -32000) &&
        json_push_kv_str(&error, "message",
                         "benchmark denies interactive requests") &&
        json_push_kv_str(&response, "jsonrpc", "2.0") &&
        json_push_kv_int(&response, "id", id) &&
        json_push_kv(&response, "error", &error) &&
        send_json(fd, &response);
    json_free(&error); json_free(&response);
    return ok;
}

static int reader_line(struct app_reader *reader, int timeout_ms,
                       char **line_out, size_t *len_out)
{
    int64_t deadline = monotonic_ms() + timeout_ms;
    while (true) {
        char *newline = memchr(reader->wire, '\n', reader->used);
        if (newline) {
            size_t len = (size_t)(newline - reader->wire);
            reader->wire[len] = '\0';
            *line_out = reader->wire;
            *len_out = len;
            return 1;
        }
        if (reader->used == APP_LINE_MAX) return -1;
        int64_t remaining = deadline - monotonic_ms();
        if (remaining <= 0) return 0;
        struct pollfd pollfd = {.fd = reader->fd, .events = POLLIN};
        int polled = poll(&pollfd, 1, remaining > INT_MAX
                                      ? INT_MAX : (int)remaining);
        if (polled < 0 && errno == EINTR) continue;
        if (polled <= 0) return polled;
        ssize_t got = read(reader->fd, reader->wire + reader->used,
                           APP_LINE_MAX - reader->used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return -1;
        reader->used += (size_t)got;
    }
}

static void reader_consume(struct app_reader *reader, size_t len)
{
    size_t consumed = len + 1u;
    if (consumed > reader->used) consumed = reader->used;
    memmove(reader->wire, reader->wire + consumed, reader->used - consumed);
    reader->used -= consumed;
}

static bool allowed_item(const char *type)
{
    return type && (strcmp(type, "userMessage") == 0 ||
        strcmp(type, "reasoning") == 0 ||
        strcmp(type, "agentMessage") == 0 ||
        strcmp(type, "commandExecution") == 0);
}

static void handle_notification(const struct json_value *message,
                                const char *thread_id, const char *turn_id,
                                struct app_metrics *metrics)
{
    const char *method = json_get_str(json_get(message, "method"));
    const struct json_value *params = json_get(message, "params");
    if (!method || !params) return;
    if (strcmp(method, "thread/tokenUsage/updated") == 0 &&
        strcmp(json_get_str(json_get(params, "threadId")), thread_id) == 0) {
        const struct json_value *usage = json_get(
            json_get(json_get(params, "tokenUsage"), "last"), "inputTokens");
        if (usage) metrics->input_tokens = json_get_int(usage);
        usage = json_get(json_get(json_get(params, "tokenUsage"), "last"),
                         "cachedInputTokens");
        if (usage) metrics->cached_input_tokens = json_get_int(usage);
        usage = json_get(json_get(json_get(params, "tokenUsage"), "last"),
                         "outputTokens");
        if (usage) metrics->output_tokens = json_get_int(usage);
        return;
    }
    if (strcmp(method, "item/completed") == 0) {
        const struct json_value *item = json_get(params, "item");
        const char *type = json_get_str(json_get(item, "type"));
        if (!allowed_item(type)) metrics->forbidden_tool_calls++;
        if (type && strcmp(type, "commandExecution") == 0) {
            const char *output = json_get_str(json_get(item,
                                                       "aggregatedOutput"));
            metrics->tool_calls++;
            if (output) metrics->tool_output_bytes += (int64_t)strlen(output);
        }
        return;
    }
    if (strcmp(method, "turn/completed") == 0) {
        const struct json_value *turn = json_get(params, "turn");
        const char *id = json_get_str(json_get(turn, "id"));
        if (id && turn_id[0] && strcmp(id, turn_id) == 0) {
            metrics->completed = true;
            const char *status = json_get_str(json_get(turn, "status"));
            (void)snprintf(metrics->turn_status,
                           sizeof(metrics->turn_status), "%s",
                           status ? status : "missing");
        }
    }
}

static int wait_response(struct app_reader *reader, int input_fd, int64_t id,
                         const char *thread_id, const char *turn_id,
                         struct app_metrics *metrics,
                         struct json_value *response_out, int timeout_ms)
{
    int64_t deadline = monotonic_ms() + timeout_ms;
    while (true) {
        char *line = NULL; size_t len = 0;
        int64_t left = deadline - monotonic_ms();
        int got = reader_line(reader, left <= 0 ? 0 : (int)left, &line, &len);
        if (got <= 0) return got;
        struct json_value message;
        json_init(&message);
        bool parsed = json_read(&message, line, len) &&
                      message.type == JSON_OBJ;
        reader_consume(reader, len);
        if (!parsed) { json_free(&message); return -1; }
        const struct json_value *message_id = json_get(&message, "id");
        const struct json_value *method_value = json_get(&message, "method");
        const char *method = json_get_str(method_value);
        if (message_id && json_get_int(message_id) == id &&
            (json_get(&message, "result") || json_get(&message, "error"))) {
            json_copy(response_out, &message);
            json_free(&message);
            return 1;
        }
        if (message_id && method_value) {
            metrics->server_requests_denied++;
            (void)snprintf(metrics->last_server_request,
                           sizeof(metrics->last_server_request), "%s",
                           method);
            bool denied = send_denial(input_fd, json_get_int(message_id));
            json_free(&message);
            if (!denied) return -1;
            continue;
        }
        handle_notification(&message, thread_id, turn_id, metrics);
        json_free(&message);
        if (id == INT64_MAX && metrics->completed) return 1;
    }
}

static bool wait_child(pid_t child, int *status)
{
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
    int64_t deadline = monotonic_ms() + 5000;
    while (monotonic_ms() < deadline) {
        pid_t waited = waitpid(child, status, WNOHANG);
        if (waited == child) return true;
        if (waited < 0) return false;
        (void)nanosleep(&pause, NULL);
    }
    if (kill(child, SIGTERM) != 0 && errno != ESRCH) return false;
    deadline = monotonic_ms() + 2000;
    while (monotonic_ms() < deadline) {
        pid_t waited = waitpid(child, status, WNOHANG);
        if (waited == child) return true;
        if (waited < 0) return false;
        (void)nanosleep(&pause, NULL);
    }
    if (kill(child, SIGKILL) != 0 && errno != ESRCH) return false;
    return waitpid(child, status, 0) == child;
}

static char *read_file(const char *path, size_t maximum, size_t *len_out)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || (uint64_t)st.st_size > maximum) {
        if (fd >= 0) close(fd);
        return NULL;
    }
    size_t len = (size_t)st.st_size;
    char *wire = zcl_malloc(len + 1u, "app_server.file");
    size_t off = 0;
    while (wire && off < len) {
        ssize_t got = read(fd, wire + off, len - off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { free(wire); wire = NULL; break; }
        off += (size_t)got;
    }
    if (fd >= 0 && close(fd) != 0) { free(wire); wire = NULL; }
    if (wire) { wire[len] = '\0'; *len_out = len; }
    return wire;
}

static bool add_text_input(struct json_value *params, const char *packet)
{
    struct json_value inputs, item;
    json_init(&inputs); json_set_array(&inputs);
    json_init(&item); json_set_object(&item);
    bool ok = json_push_kv_str(&item, "type", "text") &&
        json_push_kv_str(&item, "text", packet) &&
        json_push_back(&inputs, &item) &&
        json_push_kv(params, "input", &inputs);
    json_free(&item); json_free(&inputs);
    return ok;
}

static int run_benchmark(const char *candidate, const char *packet,
                         const char *model, const char *private_home,
                         const char *stderr_path)
{
    int to_child[2], from_child[2];
    if (pipe(to_child) != 0 || pipe(from_child) != 0) return 70;
    int stderr_fd = open(stderr_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                         0600);
    if (stderr_fd < 0) return 70;
    pid_t child = fork();
    if (child < 0) { close(stderr_fd); return 70; }
    if (child == 0) {
        if (dup2(to_child[0], STDIN_FILENO) < 0 ||
            dup2(from_child[1], STDOUT_FILENO) < 0 ||
            dup2(stderr_fd, STDERR_FILENO) < 0) _exit(70);
        close(to_child[0]); close(to_child[1]);
        close(from_child[0]); close(from_child[1]); close(stderr_fd);
        if (setenv("CODEX_HOME", private_home, 1) != 0) _exit(70);
        char external_servers[32], elicitation[40], external_apps[32];
        if (snprintf(external_servers, sizeof(external_servers), "%s%s={}",
                     "m", "cp_servers") >= (int)sizeof(external_servers) ||
            snprintf(elicitation, sizeof(elicitation), "%s%s",
                     "tool_call_m", "cp_elicitation") >=
                (int)sizeof(elicitation) ||
            snprintf(external_apps, sizeof(external_apps), "%s%s",
                     "enable_m", "cp_apps") >= (int)sizeof(external_apps))
            _exit(70);
        const char *const argv[] = {
            "codex", "app-server", "--stdio", "--strict-config",
            "-c", external_servers, "-c", "plugins={}",
            "-c", "shell_environment_policy.inherit=\"none\"",
            "-c", "shell_environment_policy.set.PATH=\"/usr/bin:/bin\"",
            "-c", "shell_environment_policy.set.HOME=\".\"",
            "-c", "shell_environment_policy.set.TMPDIR=\".zcode-adapter-tmp\"",
            "--disable", "apps", "--disable", "plugins",
            "--disable", "hooks", "--disable", "multi_agent",
            "--disable", "browser_use", "--disable", "browser_use_external",
            "--disable", "computer_use", "--disable", "image_generation",
            "--disable", "in_app_browser", "--disable", "skill_search",
            "--disable", "goals", "--disable", "guardian_approval",
            "--disable", "tool_suggest", "--disable", "view_image",
            "--disable", "web_search_request", "--disable", "standalone_web_search",
            "--disable", elicitation,
            "--disable", external_apps, "--disable", "remote_plugin",
            NULL,
        };
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(to_child[0]); close(from_child[1]); close(stderr_fd);
    struct app_reader reader = {
        .fd = from_child[0],
        .wire = zcl_malloc(APP_LINE_MAX + 1u, "app_server.line"),
    };
    struct app_metrics metrics = {0};
    (void)snprintf(metrics.turn_status, sizeof(metrics.turn_status), "missing");
    struct json_value params, response;
    json_init(&params); json_set_object(&params);
    json_init(&response);
    struct json_value client, capabilities;
    json_init(&client); json_set_object(&client);
    json_init(&capabilities); json_set_object(&capabilities);
    bool ok = reader.wire &&
        json_push_kv_str(&client, "name", "z23-adapter-benchmark") &&
        json_push_kv_str(&client, "version", "1") &&
        json_push_kv_bool(&capabilities, "experimentalApi", true) &&
        json_push_kv(&params, "clientInfo", &client) &&
        json_push_kv(&params, "capabilities", &capabilities) &&
        send_request(to_child[1], 1, "initialize", &params) &&
        wait_response(&reader, to_child[1], 1, "", "", &metrics,
                      &response, 30000) == 1 &&
        !json_get(&response, "error") &&
        send_notification(to_child[1], "initialized");
    json_free(&client); json_free(&capabilities);
    json_free(&params); json_free(&response);

    const char *base =
        "You are a contained C23 coding worker. Use only the built-in shell. "
        "Do not call external tool servers, plugins, apps, web, images, "
        "skills, subagents, or "
        "network. Operate only beneath the current working directory and obey "
        "the packet's write scopes. If the goal is outside scope, change nothing.";
    json_init(&params); json_set_object(&params);
    struct json_value config;
    json_init(&config); json_set_object(&config);
    struct json_value empty;
    json_init(&empty); json_set_object(&empty);
    char external_servers_key[24];
    if (snprintf(external_servers_key, sizeof(external_servers_key), "%s%s",
                 "m", "cp_servers") >= (int)sizeof(external_servers_key))
        ok = false;
    ok = ok && json_push_kv_str(&params, "cwd", candidate) &&
        json_push_kv_bool(&params, "ephemeral", true) &&
        json_push_kv_str(&params, "sandbox", "workspace-write") &&
        json_push_kv_str(&params, "approvalPolicy", "never") &&
        json_push_kv_str(&params, "model", model) &&
        json_push_kv_str(&params, "baseInstructions", base) &&
        json_push_kv_str(&params, "developerInstructions", base) &&
        json_push_kv(&config, external_servers_key, &empty) &&
        json_push_kv(&config, "plugins", &empty) &&
        json_push_kv(&params, "config", &config) &&
        send_request(to_child[1], 2, "thread/start", &params);
    json_init(&response);
    ok = ok && wait_response(&reader, to_child[1], 2, "", "", &metrics,
                             &response, 30000) == 1 &&
        !json_get(&response, "error");
    char thread_id[96] = {0}, model_used[96] = {0}, provider[96] = {0};
    if (ok) {
        const struct json_value *result = json_get(&response, "result");
        (void)snprintf(thread_id, sizeof(thread_id), "%s",
            json_get_str(json_get(json_get(result, "thread"), "id")));
        (void)snprintf(model_used, sizeof(model_used), "%s",
            json_get_str(json_get(result, "model")));
        (void)snprintf(provider, sizeof(provider), "%s",
            json_get_str(json_get(result, "modelProvider")));
    }
    json_free(&empty); json_free(&config); json_free(&params);
    json_free(&response);

    json_init(&params); json_set_object(&params);
    struct json_value policy, roots, root;
    json_init(&policy); json_set_object(&policy);
    json_init(&roots); json_set_array(&roots);
    json_init(&root); json_set_str(&root, candidate);
    int64_t started_ms = monotonic_ms();
    ok = ok && thread_id[0] && json_push_kv_str(&params, "threadId", thread_id) &&
        add_text_input(&params, packet) && json_push_kv_str(&params, "cwd", candidate) &&
        json_push_kv_str(&policy, "type", "workspaceWrite") &&
        json_push_kv_bool(&policy, "networkAccess", false) &&
        json_push_back(&roots, &root) &&
        json_push_kv(&policy, "writableRoots", &roots) &&
        json_push_kv(&params, "sandboxPolicy", &policy) &&
        send_request(to_child[1], 3, "turn/start", &params);
    json_init(&response);
    ok = ok && wait_response(&reader, to_child[1], 3, thread_id, "",
                             &metrics, &response, 30000) == 1 &&
        !json_get(&response, "error");
    char turn_id[96] = {0};
    if (ok) (void)snprintf(turn_id, sizeof(turn_id), "%s",
        json_get_str(json_get(json_get(json_get(&response, "result"),
                                      "turn"), "id")));
    json_free(&root); json_free(&roots); json_free(&policy);
    json_free(&params); json_free(&response);
    while (ok && !metrics.completed) {
        json_init(&response);
        int got = wait_response(&reader, to_child[1], INT64_MAX, thread_id,
                                turn_id, &metrics, &response, APP_TIMEOUT_MS);
        json_free(&response);
        if (got <= 0) ok = false;
    }
    int64_t elapsed_us = (monotonic_ms() - started_ms) * 1000;
    close(to_child[1]); close(from_child[0]); free(reader.wire);
    int status = 0;
    if (!wait_child(child, &status)) ok = false;

    size_t stderr_len = 0;
    char *stderr_wire = read_file(stderr_path, APP_STDERR_MAX, &stderr_len);
    bool bwrap_failure = stderr_wire &&
        strstr(stderr_wire, "Failed RTM_NEWADDR") != NULL;
    free(stderr_wire);
    struct json_value output, tokens, diagnostic;
    json_init(&output); json_set_object(&output);
    json_init(&tokens); json_set_object(&tokens);
    json_init(&diagnostic); json_set_object(&diagnostic);
    bool rendered = json_push_kv_str(&output, "schema",
                                      "zcl.zcode_app_server_benchmark.v1") &&
        json_push_kv_bool(&output, "completed", metrics.completed) &&
        json_push_kv_str(&output, "turn_status", metrics.turn_status) &&
        json_push_kv_int(&tokens, "input", metrics.input_tokens) &&
        json_push_kv_int(&tokens, "cached_input", metrics.cached_input_tokens) &&
        json_push_kv_int(&tokens, "output", metrics.output_tokens) &&
        json_push_kv(&output, "tokens", &tokens) &&
        json_push_kv_int(&output, "tool_calls", metrics.tool_calls) &&
        json_push_kv_int(&output, "tool_output_bytes",
                         metrics.tool_output_bytes) &&
        json_push_kv_int(&output, "server_requests_denied",
                         metrics.server_requests_denied) &&
        json_push_kv_str(&output, "last_server_request",
                         metrics.last_server_request) &&
        json_push_kv_int(&output, "forbidden_tool_calls",
                         metrics.forbidden_tool_calls) &&
        json_push_kv_str(&output, "model", model_used) &&
        json_push_kv_str(&output, "model_provider", provider) &&
        json_push_kv_int(&output, "elapsed_us", elapsed_us) &&
        json_push_kv_int(&output, "stderr_bytes", (int64_t)stderr_len) &&
        json_push_kv_bool(&diagnostic, "bwrap_loopback_failure", bwrap_failure) &&
        json_push_kv(&output, "diagnostic", &diagnostic);
    size_t output_len = rendered ? json_write(&output, NULL, 0) : 0;
    char *output_wire = output_len
        ? zcl_malloc(output_len + 1u, "app_server.output") : NULL;
    if (!output_wire || json_write(&output, output_wire,
                                   output_len + 1u) != output_len) rendered = false;
    if (rendered) printf("%s\n", output_wire);
    free(output_wire); json_free(&diagnostic);
    json_free(&tokens); json_free(&output);
    return ok && rendered && WIFEXITED(status) ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "app-server benchmark: candidate, packet and model required\n");
        return 64;
    }
    char candidate[PATH_MAX], packet_path[PATH_MAX];
    if (!realpath(argv[1], candidate) || !realpath(argv[2], packet_path) ||
        !beneath(candidate, packet_path) || !argv[3][0] ||
        strpbrk(argv[3], " \t\r\n")) {
        fprintf(stderr, "app-server benchmark: invalid bounded input\n");
        return 65;
    }
    size_t packet_len = 0;
    char *packet = read_file(packet_path, APP_PACKET_MAX, &packet_len);
    (void)packet_len;
    struct passwd pwd, *found = NULL;
    char pwd_buffer[16384], auth_source[PATH_MAX];
    const char *configured = getenv("CODEX_HOME");
    const char *home = NULL;
    if (configured && configured[0]) home = configured;
    else if (getpwuid_r(getuid(), &pwd, pwd_buffer, sizeof(pwd_buffer),
                        &found) == 0 && found) home = pwd.pw_dir;
    int n = home ? snprintf(auth_source, sizeof(auth_source), "%s/%s",
                            home, configured && configured[0]
                                  ? "auth.json" : ".codex/auth.json") : -1;
    struct stat auth_st;
    if (!packet || n <= 0 || (size_t)n >= sizeof(auth_source) ||
        lstat(auth_source, &auth_st) != 0 || !S_ISREG(auth_st.st_mode) ||
        auth_st.st_uid != getuid()) {
        free(packet);
        fprintf(stderr, "app-server benchmark: installed login unavailable\n");
        return 69;
    }
    char private_home[] = "/tmp/z23-app-server-home.XXXXXX";
    if (!mkdtemp(private_home)) { free(packet); return 73; }
    char auth_link[PATH_MAX], stderr_path[PATH_MAX], adapter_tmp[PATH_MAX];
    n = snprintf(auth_link, sizeof(auth_link), "%s/auth.json", private_home);
    int e = snprintf(stderr_path, sizeof(stderr_path), "%s/stderr", private_home);
    int t = snprintf(adapter_tmp, sizeof(adapter_tmp),
                     "%s/.zcode-adapter-tmp", candidate);
    bool prepared = n > 0 && (size_t)n < sizeof(auth_link) &&
        e > 0 && (size_t)e < sizeof(stderr_path) &&
        t > 0 && (size_t)t < sizeof(adapter_tmp) &&
        symlink(auth_source, auth_link) == 0 &&
        (mkdir(adapter_tmp, 0700) == 0 || errno == EEXIST);
    int rc = prepared ? run_benchmark(candidate, packet, argv[3], private_home,
                                      stderr_path) : 73;
    free(packet);
    if (prepared) (void)unlink(stderr_path);
    (void)unlink(auth_link);
    (void)rmdir(private_home);
    return rc;
}
