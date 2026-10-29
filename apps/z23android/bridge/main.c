/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "json/json.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LINE_CAP 131072
#define ANSWER_CAP 65536
#define INPUT_CAP 16384
struct connection { int in, out; pid_t pid; char buffer[LINE_CAP]; size_t used; int64_t deadline; };

static int64_t now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool send_all(struct connection *c, const char *text, size_t len)
{
    while (len) {
        int64_t remaining = c->deadline - now_ms();
        if (remaining <= 0 || remaining > 120000) return false;
        struct pollfd p = {.fd = c->in, .events = POLLOUT};
        int rc = poll(&p, 1, (int)remaining);
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0) return false;
        ssize_t n = write(c->in, text, len);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno == EAGAIN) continue;
        if (n <= 0) return false;
        text += n; len -= (size_t)n;
    }
    return true;
}

static bool send_json(struct connection *c, struct json_value *v)
{
    char *line = malloc(LINE_CAP);
    if (!line) return false;
    size_t n = json_write(v, line, LINE_CAP - 1);
    bool ok = n < LINE_CAP - 1;
    if (ok) { line[n++] = '\n'; ok = send_all(c, line, n); }
    free(line); return ok;
}

static bool request(struct connection *c, int id, const char *method, const struct json_value *params)
{
    struct json_value msg = {0}; json_set_object(&msg);
    bool ok = json_push_kv_int(&msg, "id", id) && json_push_kv_str(&msg, "method", method) &&
        json_push_kv(&msg, "params", params) && send_json(c, &msg);
    json_free(&msg); return ok;
}

static bool notification(struct connection *c, const char *method)
{
    struct json_value msg = {0}, params = {0}; json_set_object(&msg); json_set_object(&params);
    bool ok = json_push_kv_str(&msg, "method", method) && json_push_kv(&msg, "params", &params) && send_json(c, &msg);
    json_free(&params); json_free(&msg); return ok;
}

static bool receive(struct connection *c, struct json_value *msg)
{
    for (;;) {
        char *end = memchr(c->buffer, '\n', c->used);
        if (end) {
            size_t n = (size_t)(end - c->buffer);
            bool ok = n && !memchr(c->buffer, 0, n) && json_read(msg, c->buffer, n);
            size_t consumed = n + 1;
            memmove(c->buffer, c->buffer + consumed, c->used - consumed); c->used -= consumed;
            return ok;
        }
        if (c->used == sizeof(c->buffer)) return false;
        int64_t remaining = c->deadline - now_ms();
        if (remaining <= 0 || remaining > 120000) return false;
        struct pollfd p = {.fd = c->out, .events = POLLIN};
        int rc = poll(&p, 1, (int)remaining);
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0) return false;
        ssize_t n = read(c->out, c->buffer + c->used, sizeof(c->buffer) - c->used);
        if (n <= 0) return false;
        c->used += (size_t)n;
    }
}

static bool response(struct connection *c, int id, struct json_value *result)
{
    for (;;) {
        struct json_value msg = {0};
        if (!receive(c, &msg)) return false;
        const struct json_value *key = json_get(&msg, "id");
        if (key && key->type == JSON_INT && json_get_int(key) == id) {
            const struct json_value *v = json_get(&msg, "result");
            bool ok = v && !json_get(&msg, "error") && json_copy_checked(result, v);
            json_free(&msg); return ok;
        }
        if (key && json_get(&msg, "method")) { json_free(&msg); return false; }
        json_free(&msg);
    }
}

static bool start(struct connection *c)
{
    int a[2], b[2];
    if (pipe(a)) return false;
    if (pipe(b)) { close(a[0]); close(a[1]); return false; }
    pid_t pid = fork();
    if (pid == 0) {
        (void)setpgid(0, 0);
        if (dup2(a[0], 0) < 0 || dup2(b[1], 1) < 0) _exit(127);
        int nullfd = open("/dev/null", O_WRONLY);
        if (nullfd < 0 || dup2(nullfd, 2) < 0) _exit(127);
        close(a[0]); close(a[1]); close(b[0]); close(b[1]); close(nullfd);
        unsetenv("OPENAI_API_KEY"); unsetenv("CODEX_API_KEY"); unsetenv("CODEX_ACCESS_TOKEN");
        execlp("codex", "codex", "app-server", "--stdio", "--strict-config",
               "-c", "model_provider=\"openai\"", "-c", "mcp_servers={}", "-c", "plugins={}",
               "-c", "mcp_servers.node_repl.enabled=false", "-c", "mcp_servers.qedc.enabled=false",
               "-c", "mcp_servers.qedc-control.enabled=false", "-c", "mcp_servers.z23-steer.enabled=false",
               "-c", "mcp_servers.qedc-ast.enabled=false", "-c", "mcp_servers.qedc-wiki.enabled=false",
               "--disable", "shell_tool", "--disable", "unified_exec", "--disable", "apps",
               "--disable", "plugins", "--disable", "multi_agent", "--disable", "browser_use",
               "--disable", "browser_use_external", "--disable", "computer_use", "--disable", "in_app_browser",
               "--disable", "image_generation", "--disable", "hooks", "--disable", "remote_plugin",
               "--disable", "skill_search", "--disable", "view_image", "--disable", "tool_suggest", (char *)NULL);
        _exit(127);
    }
    close(a[0]); close(b[1]);
    if (pid < 0) { close(a[1]); close(b[0]); return false; }
    if (fcntl(a[1], F_SETFL, O_NONBLOCK) < 0) { close(a[1]); close(b[0]); (void)kill(pid, SIGKILL); (void)waitpid(pid, NULL, 0); return false; }
    c->in = a[1]; c->out = b[0]; c->pid = pid; c->deadline = now_ms() + 90000;
    return true;
}

static void stop(struct connection *c)
{
    if (c->in >= 0) close(c->in);
    if (c->out >= 0) close(c->out);
    if (c->pid > 0) {
        (void)kill(-c->pid, SIGKILL); (void)kill(c->pid, SIGKILL);
        while (waitpid(c->pid, NULL, 0) < 0 && errno == EINTR) {}
    }
}

static bool handshake(struct connection *c)
{
    struct json_value params = {0}, client = {0}, result = {0};
    json_set_object(&params); json_set_object(&client);
    bool ok = json_push_kv_str(&client, "name", "z23_android_bridge") &&
        json_push_kv_str(&client, "version", "0.1.0") && json_push_kv(&params, "clientInfo", &client) &&
        request(c, 1, "initialize", &params) && response(c, 1, &result) && notification(c, "initialized");
    json_free(&result); json_free(&client); json_free(&params); return ok;
}

static bool account(struct connection *c)
{
    struct json_value params = {0}, result = {0}; json_set_object(&params);
    bool ok = json_push_kv_bool(&params, "refreshToken", false) && request(c, 2, "account/read", &params) && response(c, 2, &result);
    const char *type = json_get_str(json_get(json_get(&result, "account"), "type"));
    ok = ok && type && !strcmp(type, "chatgpt");
    json_free(&result); json_free(&params); return ok;
}

static bool thread_start(struct connection *c, char *thread, size_t cap)
{
    struct json_value params = {0}, result = {0}; json_set_object(&params);
    bool ok = json_push_kv_bool(&params, "ephemeral", true) &&
        json_push_kv_str(&params, "sandbox", "read-only") &&
        json_push_kv_str(&params, "approvalPolicy", "never") &&
        json_push_kv_str(&params, "developerInstructions", "Answer the user directly. Do not use tools or execute commands.") &&
        request(c, 3, "thread/start", &params) && response(c, 3, &result);
    const char *id = json_get_str(json_get(json_get(&result, "thread"), "id"));
    if (!id || !id[0] || strlen(id) >= cap) ok = false;
    if (ok) memcpy(thread, id, strlen(id) + 1);
    json_free(&result); json_free(&params); return ok;
}

static bool turn_start(struct connection *c, const char *thread, const char *prompt)
{
    struct json_value params = {0}, input = {0}, text = {0};
    json_set_object(&params); json_set_array(&input); json_set_object(&text);
    bool ok = json_push_kv_str(&text, "type", "text") && json_push_kv_str(&text, "text", prompt) &&
        json_push_back(&input, &text) && json_push_kv_str(&params, "threadId", thread) &&
        json_push_kv(&params, "input", &input) && request(c, 4, "turn/start", &params);
    json_free(&text); json_free(&input); json_free(&params); return ok;
}

struct turn_state { size_t used; bool started; };
static bool turn_start_response(const struct json_value *msg, struct turn_state *state)
{
    state->started = json_get(msg, "result") && !json_get(msg, "error");
    if (!state->started) {
        const struct json_value *code = json_get(json_get(msg, "error"), "code");
        if (code && code->type == JSON_INT) fprintf(stderr, "Codex turn error code: %lld\n", (long long)json_get_int(code));
    }
    return state->started;
}
static bool turn_notification(const struct json_value *params, const char *method,
                              char *answer, size_t cap, struct turn_state *state, bool *done)
{
    if (!strcmp(method, "item/agentMessage/delta")) {
        const char *delta = json_get_str(json_get(params, "delta"));
        if (!delta || strlen(delta) >= cap - state->used) return false;
        size_t n = strlen(delta); memcpy(answer + state->used, delta, n + 1); state->used += n;
    }
    if (!strcmp(method, "turn/completed")) {
        const char *status = json_get_str(json_get(json_get(params, "turn"), "status"));
        *done = true;
        return state->started && status && !strcmp(status, "completed") && state->used > 0;
    }
    return true;
}
static bool turn_event(const struct json_value *msg, const char *thread,
                       char *answer, size_t cap, struct turn_state *state,
                       bool *done)
{
    const char *method = json_get_str(json_get(msg, "method"));
    const struct json_value *id = json_get(msg, "id");
    if (id && id->type == JSON_INT && json_get_int(id) == 4 && (!method || !method[0]) &&
        !turn_start_response(msg, state)) return false;
    if (id && method && method[0]) return false;
    const struct json_value *params = json_get(msg, "params");
    const char *tid = json_get_str(json_get(params, "threadId"));
    if (!method || !tid || strcmp(tid, thread)) return true;
    return turn_notification(params, method, answer, cap, state, done);
}
static bool turn_result(struct connection *c, const char *thread, char *answer, size_t cap)
{
    struct turn_state state = {0};
    for (;;) {
        struct json_value msg = {0};
        if (!receive(c, &msg)) return false;
        bool done = false, ok = turn_event(&msg, thread, answer, cap, &state, &done);
        json_free(&msg);
        if (!ok || done) return ok;
    }
}

static bool read_input(char *line, size_t cap)
{
    size_t used = 0; int64_t deadline = now_ms() + 5000;
    while (used + 1 < cap) {
        int64_t remaining = deadline - now_ms();
        if (remaining <= 0 || remaining > 5000) return false;
        struct pollfd p = {.fd = STDIN_FILENO, .events = POLLIN};
        int rc = poll(&p, 1, (int)remaining);
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0) return false;
        char c; ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n <= 0 || !c) return false;
        if (c == '\n') { line[used] = 0; return true; }
        line[used++] = c;
    }
    return false;
}

static bool run_prompt(struct connection *c, const char *prompt, char *answer,
                       const char **error)
{
    char thread[128] = "";
    *error = "Could not start local Codex."; if (!start(c) || !handshake(c)) return false;
    *error = "A managed ChatGPT login is required."; if (!account(c)) return false;
    *error = "Codex could not start a thread."; if (!thread_start(c, thread, sizeof(thread))) return false;
    *error = "Codex could not start the turn."; if (!turn_start(c, thread, prompt)) return false;
    *error = "Codex could not complete the turn."; return turn_result(c, thread, answer, ANSWER_CAP);
}
static const char *parse_prompt(char *line, char *answer, struct json_value *input)
{
    if (!line || !answer || !read_input(line, INPUT_CAP + 2) ||
        !json_read(input, line, strlen(line)) || input->type != JSON_OBJ || input->num_children != 1) return NULL;
    const char *prompt = json_get_str(json_get(input, "prompt"));
    return prompt && prompt[0] && strlen(prompt) <= INPUT_CAP ? prompt : NULL;
}
int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    char *line = calloc(1, INPUT_CAP + 2), *answer = calloc(1, ANSWER_CAP);
    struct json_value input = {0}, output = {0};
    struct connection c = {.in = -1, .out = -1};
    const char *error = "Invalid input."; bool ok = false;
    const char *prompt = parse_prompt(line, answer, &input);
    if (!prompt) goto done;
    ok = run_prompt(&c, prompt, answer, &error);
done:
    stop(&c); json_set_object(&output);
    bool written = json_push_kv_bool(&output, "ok", ok) && json_push_kv_str(&output, ok ? "answer" : "error", ok ? answer : error);
    char *wire = malloc(LINE_CAP); size_t size = written && wire ? json_write(&output, wire, LINE_CAP) : LINE_CAP;
    if (size < LINE_CAP) { fwrite(wire, 1, size, stdout); putchar('\n'); }
    free(wire); free(answer); free(line); json_free(&output); json_free(&input);
    return ok ? 0 : 1;
}
