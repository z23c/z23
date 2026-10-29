/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "bridge_client.h"
#include "json/json.h"
#include "base/cleanse.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define WIRE_CAP 2097152
static int64_t now_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static bool cancelled(const atomic_bool *cancel)
{
    return cancel && atomic_load_explicit(cancel, memory_order_relaxed);
}
static bool wait_socket(int fd, short events, int64_t deadline, const atomic_bool *cancel)
{
    for (;;) {
        if (cancelled(cancel)) return false;
        int64_t now = now_ms(), left = deadline - now;
        if (now < 0 || left <= 0 || left > 100000) return false;
        struct pollfd p = {.fd = fd, .events = events};
        int rc = poll(&p, 1, (int)(left > 100 ? 100 : left));
        if (rc < 0 && errno == EINTR) continue;
        if (rc == 0) continue;
        return rc > 0 && (p.revents & (events | POLLHUP)) && !(p.revents & (POLLERR | POLLNVAL));
    }
}
static bool descriptor_read(int fd, char text[512], size_t *used)
{
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == getuid() &&
        (st.st_mode & 0777) == 0600 && st.st_nlink == 1 && st.st_size > 0 && st.st_size < 512;
    while (ok && *used < (size_t)st.st_size) {
        ssize_t n = read(fd, text + *used, (size_t)st.st_size - *used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        *used += (size_t)n;
    }
    return ok;
}
static bool descriptor_parse(const char *text, size_t used, uint16_t *port, char token[65])
{
    struct json_value root = {0};
    bool ok = !memchr(text, 0, used) && !strstr(text, "\\u") &&
        json_read(&root, text, used) && root.type == JSON_OBJ && root.num_children == 2;
    const struct json_value *p = json_get(&root, "port");
    const char *t = json_get_str(json_get(&root, "token"));
    ok = ok && p && p->type == JSON_INT && json_get_int(p) > 0 && json_get_int(p) <= 65535 &&
        t && strlen(t) == 64 && strspn(t, "0123456789abcdef") == 64;
    if (ok) { *port = (uint16_t)json_get_int(p); memcpy(token, t, 65); }
    json_cleanse_strings(&root); json_free(&root);
    return ok;
}
static bool descriptor(const char *files, const char *name, uint16_t *port, char token[65])
{
    int dir = open(files, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) return false;
    int fd = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    close(dir);
    if (fd < 0) return false;
    char text[512] = ""; size_t used = 0;
    bool ok = descriptor_read(fd, text, &used);
    close(fd);
    ok = ok && descriptor_parse(text, used, port, token);
    memory_cleanse(text, sizeof(text));
    return ok;
}
static int connect_local(uint16_t port, int64_t deadline, const atomic_bool *cancel)
{
    if (cancelled(cancel)) return -1;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int rc = connect(fd, (struct sockaddr *)&address, sizeof(address));
    if (rc && errno != EINPROGRESS) { close(fd); return -1; }
    int error = 0; socklen_t length = sizeof(error);
    if ((rc && !wait_socket(fd, POLLOUT, deadline, cancel)) ||
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) || error) { close(fd); return -1; }
    return fd;
}
static bool exchange_send(int fd, const char *request, size_t length, int64_t deadline, const atomic_bool *cancel)
{
    size_t sent = 0;
    while (sent < length) {
        if (!wait_socket(fd, POLLOUT, deadline, cancel)) return false;
        ssize_t n = send(fd, request + sent, length - sent, MSG_NOSIGNAL);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}
static bool exchange_receive(int fd, char *response, int64_t deadline, const atomic_bool *cancel)
{
    size_t used = 0;
    while (used < WIRE_CAP - 1) {
        if (!wait_socket(fd, POLLIN, deadline, cancel)) return false;
        ssize_t n = recv(fd, response + used, WIRE_CAP - 1 - used, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0 || memchr(response + used, 0, (size_t)n)) return false;
        used += (size_t)n; response[used] = 0;
        char *end = memchr(response, '\n', used);
        if (end) {
            if (end != response + used - 1) return false;
            *end = 0; return true;
        }
    }
    return false;
}
static bool bridge_response(bool ok, const struct json_value *response, char *out, size_t cap)
{
    const struct json_value *success = json_get(response, "ok");
    const char *answer = json_get_str(json_get(response, "answer"));
    ok = ok && success && success->type == JSON_BOOL && json_get_bool(success) && answer && answer[0] && strlen(answer) < cap;
    if (ok) memcpy(out, answer, strlen(answer) + 1);
    else if (json_get(response, "error")) {
        const char *error = json_get_str(json_get(response, "error"));
        if (error && error[0]) snprintf(out, cap, "%s", error);
    }
    return ok;
}
static bool encode_request(struct json_value *request, char *wire, const char *token,
                           const char *prompt, size_t *size)
{
    bool ok = wire && json_push_kv_str(request, "token", token) && json_push_kv_str(request, "prompt", prompt);
    *size = ok ? json_write(request, wire, WIRE_CAP - 1) : WIRE_CAP;
    if (*size < WIRE_CAP - 1) wire[(*size)++] = '\n'; else ok = false;
    return ok;
}
struct events { bool (*fn)(const struct json_value *event, void *ctx); void *ctx; };
enum { LINE_EVENT, LINE_FINAL, LINE_BAD };
/* A line with an "event" member goes to the callback; any other line is the final reply. */
static int handle_line(const char *line, const struct events *events, struct json_value *final)
{
    if (strstr(line, "\\u0000") || !json_read(final, line, strlen(line)) || final->type != JSON_OBJ)
        return LINE_BAD;
    if (!json_get(final, "event")) return final->num_children == 2 ? LINE_FINAL : LINE_BAD;
    bool ok = events->fn(final, events->ctx);
    json_cleanse_strings(final); json_free(final); json_init(final);
    return ok ? LINE_EVENT : LINE_BAD;
}
/* Reads newline-delimited lines, each at most WIRE_CAP - 1 bytes, until the final reply, which
 * must be the last bytes received. */
static bool receive_events(int fd, char *buf, int64_t deadline, const atomic_bool *cancel,
                           const struct events *events, struct json_value *final)
{
    size_t used = 0;
    for (;;) {
        char *end = memchr(buf, '\n', used);
        if (end) {
            *end = 0;
            int line = handle_line(buf, events, final);
            if (line == LINE_FINAL) return end == buf + used - 1;
            if (line != LINE_EVENT) return false;
            used -= (size_t)(end - buf) + 1;
            memmove(buf, end + 1, used);
            continue;
        }
        if (used >= WIRE_CAP - 1 || !wait_socket(fd, POLLIN, deadline, cancel)) return false;
        ssize_t n = recv(fd, buf + used, WIRE_CAP - 1 - used, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0 || memchr(buf + used, 0, (size_t)n)) return false;
        used += (size_t)n;
    }
}
static bool read_reply(int fd, const char *wire, size_t size, char *reply, int64_t deadline,
                       const atomic_bool *cancel, const struct events *events, struct json_value *response)
{
    if (fd < 0 || !exchange_send(fd, wire, size, deadline, cancel)) return false;
    if (events) return receive_events(fd, reply, deadline, cancel, events, response) && !cancelled(cancel);
    return exchange_receive(fd, reply, deadline, cancel) && !cancelled(cancel) &&
        !strstr(reply, "\\u0000") && json_read(response, reply, strlen(reply)) &&
        response->type == JSON_OBJ && response->num_children == 2;
}
static bool bridge_exchange(const char *prompt, const char *token, uint16_t port, char *out, size_t cap,
                            const atomic_bool *cancel, const struct events *events)
{
    struct json_value request = {0}, response = {0}; json_set_object(&request);
    char *wire = calloc(1, WIRE_CAP), *reply = calloc(1, WIRE_CAP);
    size_t size = 0;
    bool ok = reply && encode_request(&request, wire, token, prompt, &size);
    int64_t now = now_ms();
    int fd = ok && now >= 0 ? connect_local(port, now + 100000, cancel) : -1;
    ok = read_reply(fd, wire, size, reply, now + 100000, cancel, events, &response);
    if (fd >= 0) close(fd);
    ok = bridge_response(ok, &response, out, cap);
    json_cleanse_strings(&request); json_free(&request);
    json_cleanse_strings(&response); json_free(&response);
    if (wire) { memory_cleanse(wire, WIRE_CAP); free(wire); }
    if (reply) { memory_cleanse(reply, WIRE_CAP); free(reply); }
    return ok;
}
bool zapp_bridge_chat(const char *files, const char *prompt, char *out, size_t cap,
                      const atomic_bool *cancel)
{
    if (!files || !prompt || !out || !cap) return false;
    snprintf(out, cap, "Connect the paired laptop over USB and keep its Z23 bridge open.");
    uint16_t port = 0; char token[65] = "";
    bool ok = !cancelled(cancel) && prompt[0] && strlen(prompt) <= 16000 &&
        descriptor(files, "codex-bridge.json", &port, token) && !cancelled(cancel);
    if (ok) ok = bridge_exchange(prompt, token, port, out, cap, cancel, NULL);
    if (cancelled(cancel)) { snprintf(out, cap, "Reply cancelled."); ok = false; }
    memory_cleanse(token, sizeof(token)); return ok;
}
static bool speech_call(const char *files, const char *request, char *out, size_t cap,
                        const atomic_bool *cancel, const struct events *events)
{
    if (!files || !request || !out || !cap) return false;
    snprintf(out, cap, "Laptop host not answering. Connect it over USB and keep it running.");
    uint16_t port = 0; char token[65] = "";
    bool ok = !cancelled(cancel) && request[0] && strlen(request) <= 1300000 &&
        descriptor(files, "speech-bridge.json", &port, token) && !cancelled(cancel);
    if (ok) ok = bridge_exchange(request, token, port, out, cap, cancel, events);
    if (cancelled(cancel)) { snprintf(out, cap, "Voice cancelled."); ok = false; }
    memory_cleanse(token, sizeof(token)); return ok;
}
bool zapp_bridge_speech(const char *files, const char *request, char *out, size_t cap,
                       const atomic_bool *cancel)
{
    return speech_call(files, request, out, cap, cancel, NULL);
}
bool zapp_bridge_speech_events(const char *files, const char *request, char *out, size_t cap,
    bool (*on_event)(const struct json_value *event, void *ctx), void *ctx, const atomic_bool *cancel)
{
    const struct events events = {on_event, ctx};
    return on_event && speech_call(files, request, out, cap, cancel, &events);
}
