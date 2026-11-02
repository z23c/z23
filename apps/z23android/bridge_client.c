/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "bridge_client.h"
#include "bridge_auth.h"
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
enum { PAIR_OK, PAIR_BAD, PAIR_STALE };
/* The port and secret every descriptor carries. */
static bool descriptor_fields(const struct json_value *root, const struct json_value **port, const char **token)
{
    *port = json_get(root, "port"); *token = json_get_str(json_get(root, "token"));
    return *port && (*port)->type == JSON_INT && json_get_int(*port) > 0 && json_get_int(*port) <= 65535 &&
        *token && strlen(*token) == 64 && strspn(*token, "0123456789abcdef") == 64;
}
/* A descriptor of protocol 2 has exactly "v", "port" and "token"; a well-formed one without "v", or with
 * another version, belongs to an older host and is stale. */
static int descriptor_version(const struct json_value *root)
{
    const struct json_value *v = json_get(root, "v");
    if (!v) return root->num_children == 2 ? PAIR_STALE : PAIR_BAD;
    if (v->type != JSON_INT || root->num_children != 3) return PAIR_BAD;
    return json_get_int(v) == ZAPP_AUTH_VERSION ? PAIR_OK : PAIR_STALE;
}
static int descriptor_parse(const char *text, size_t used, uint16_t *port, char token[65])
{
    struct json_value root = {0};
    const struct json_value *p = NULL;
    const char *t = NULL;
    int rc = PAIR_BAD;
    if (!memchr(text, 0, used) && !strstr(text, "\\u") && json_read(&root, text, used) &&
        root.type == JSON_OBJ && descriptor_fields(&root, &p, &t)) rc = descriptor_version(&root);
    if (rc == PAIR_OK) { *port = (uint16_t)json_get_int(p); memcpy(token, t, 65); }
    json_cleanse_strings(&root); json_free(&root);
    return rc;
}
static int descriptor(const char *files, const char *name, uint16_t *port, char token[65])
{
    int dir = open(files, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) return PAIR_BAD;
    int fd = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    close(dir);
    if (fd < 0) return PAIR_BAD;
    char text[512] = ""; size_t used = 0;
    bool ok = descriptor_read(fd, text, &used);
    close(fd);
    int rc = ok ? descriptor_parse(text, used, port, token) : PAIR_BAD;
    memory_cleanse(text, sizeof(text));
    return rc;
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
struct events { bool (*fn)(const struct json_value *event, void *ctx); void *ctx; };
enum { LINE_EVENT, LINE_FINAL, LINE_BAD };
/* A line with an "event" member goes to the callback; any other line is the final reply. */
static int handle_line(const char *line, const struct events *events, struct json_value *final)
{
    if (strstr(line, "\\u0000") || !json_read(final, line, strlen(line)) || final->type != JSON_OBJ)
        return LINE_BAD;
    if (!json_get(final, "event")) return final->num_children == 2 ? LINE_FINAL : LINE_BAD;
    bool ok = events && events->fn(final, events->ctx);
    json_cleanse_strings(final); json_free(final); json_init(final);
    return ok ? LINE_EVENT : LINE_BAD;
}
/* Newline-delimited lines of at most WIRE_CAP - 1 bytes; the line returned stays valid until the next call. */
struct reader { int fd; char *buf; size_t used, consumed; };
static char *read_line(struct reader *r, int64_t deadline, const atomic_bool *cancel)
{
    if (r->consumed) {
        r->used -= r->consumed;
        memmove(r->buf, r->buf + r->consumed, r->used);
        r->consumed = 0;
    }
    for (;;) {
        char *end = memchr(r->buf, '\n', r->used);
        if (end) { *end = 0; r->consumed = (size_t)(end - r->buf) + 1; return r->buf; }
        if (r->used >= WIRE_CAP - 1 || !wait_socket(r->fd, POLLIN, deadline, cancel)) return NULL;
        ssize_t n = recv(r->fd, r->buf + r->used, WIRE_CAP - 1 - r->used, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0 || memchr(r->buf + r->used, 0, (size_t)n)) return NULL;
        r->used += (size_t)n;
    }
}
static const char unverified_text[] =
    "The laptop host did not prove it holds this pairing. Pair the phone with the laptop again.";
static const char protocol_text[] =
    "The laptop host does not answer this app's bridge protocol. Update it, then pair the phone again.";
static bool parse_hello(const char *line, struct zapp_auth *a)
{
    struct json_value hello = {0};
    const char *nonce = NULL;
    const struct json_value *v = NULL;
    bool ok = line && !strstr(line, "\\u0000") && json_read(&hello, line, strlen(line)) &&
        hello.type == JSON_OBJ && (v = json_get(&hello, "v")) && v->type == JSON_INT &&
        json_get_int(v) == ZAPP_AUTH_VERSION && (nonce = json_get_str(json_get(&hello, "nonce")));
    ok = ok && strlen(nonce) == ZAPP_AUTH_HEX && zapp_auth_unhex(nonce, sizeof(a->ns), a->ns);
    json_cleanse_strings(&hello); json_free(&hello);
    return ok;
}
static bool send_nonce(struct reader *r, struct zapp_auth *a, int64_t deadline, const atomic_bool *cancel)
{
    char hex[ZAPP_AUTH_HEX + 1], answer[128];
    if (!zapp_auth_random(a->nc, sizeof(a->nc))) return false;
    zapp_auth_hex(a->nc, sizeof(a->nc), hex);
    int n = snprintf(answer, sizeof(answer), "{\"v\":%d,\"nonce\":\"%s\"}\n", ZAPP_AUTH_VERSION, hex);
    return n > 0 && exchange_send(r->fd, answer, (size_t)n, deadline, cancel);
}
/* The host speaks first. The app sends nothing but its nonce until the host's tag verifies, so a
 * server without the pairing secret receives no request and no secret. Returns the failure text. */
static const char *client_handshake(struct reader *r, struct zapp_auth *a, int64_t deadline, const atomic_bool *cancel)
{
    if (!parse_hello(read_line(r, deadline, cancel), a)) return protocol_text;
    if (!send_nonce(r, a, deadline, cancel)) return unverified_text;
    char body[32];
    snprintf(body, sizeof(body), "{\"v\":%d}", ZAPP_AUTH_VERSION);
    const char *line = read_line(r, deadline, cancel);
    const char *proof = line ? zapp_auth_open(a, "server", 0, line) : NULL;
    return proof && !strcmp(proof, body) ? NULL : unverified_text;
}
/* Every reply line is verified against the request before it is parsed or handed on; the final
 * reply must be the last bytes received. */
static bool receive_replies(struct reader *r, struct zapp_auth *a, int64_t deadline, const atomic_bool *cancel,
                            const struct events *events, struct json_value *final)
{
    for (;;) {
        const char *frame = read_line(r, deadline, cancel);
        const char *line = frame ? zapp_auth_open(a, "line", a->seq, frame) : NULL;
        if (!line) return false;
        a->seq++;
        int kind = handle_line(line, events, final);
        if (kind == LINE_FINAL) return r->used == r->consumed;
        if (kind != LINE_EVENT) return false;
    }
}
#define FRAME_HEAD (ZAPP_AUTH_HEX + 1)
/* One call on an open connection: the handshake, then the sealed request and the verified replies. */
static bool converse(int fd, char *wire, size_t size, char *reply, struct zapp_auth *auth, int64_t deadline,
                     const atomic_bool *cancel, const struct events *events, struct json_value *response,
                     const char **failure)
{
    struct reader reader = {.fd = fd, .buf = reply};
    if ((*failure = client_handshake(&reader, auth, deadline, cancel))) return false;
    size_t frame = zapp_auth_seal_request(auth, wire + FRAME_HEAD, size, wire);
    wire[frame++] = '\n';
    return exchange_send(fd, wire, frame, deadline, cancel) &&
        receive_replies(&reader, auth, deadline, cancel, events, response) && !cancelled(cancel);
}
/* Starts the session with the secret and writes the request JSON after the frame head; 0 on failure. */
static size_t encode_request(struct zapp_auth *auth, const char *secret, const char *prompt, char *wire)
{
    struct json_value request = {0}; json_set_object(&request);
    size_t size = zapp_auth_start(auth, secret) && json_push_kv_str(&request, "prompt", prompt) ?
        json_write(&request, wire + FRAME_HEAD, WIRE_CAP - FRAME_HEAD - 2) : 0;
    json_cleanse_strings(&request); json_free(&request);
    return size < WIRE_CAP - FRAME_HEAD - 2 ? size : 0;
}
static bool bridge_exchange(const char *prompt, const char *secret, uint16_t port, char *out, size_t cap,
                            const atomic_bool *cancel, const struct events *events)
{
    struct json_value response = {0};
    char *wire = calloc(1, WIRE_CAP), *reply = calloc(1, WIRE_CAP);
    struct zapp_auth auth = {0};
    const char *failure = NULL;
    size_t size = wire && reply ? encode_request(&auth, secret, prompt, wire) : 0;
    int64_t now = now_ms(), deadline = now + 100000;
    int fd = size && now >= 0 ? connect_local(port, deadline, cancel) : -1;
    bool ok = fd >= 0 && converse(fd, wire, size, reply, &auth, deadline, cancel, events, &response, &failure);
    if (fd >= 0) close(fd);
    ok = bridge_response(ok, &response, out, cap);
    if (!ok && failure && cap) snprintf(out, cap, "%s", failure);
    json_cleanse_strings(&response); json_free(&response);
    zapp_auth_wipe(&auth);
    if (wire) { memory_cleanse(wire, WIRE_CAP); free(wire); }
    if (reply) { memory_cleanse(reply, WIRE_CAP); free(reply); }
    return ok;
}
static const char stale_text[] = "This pairing is out of date. Pair the phone with the laptop again.";
bool zapp_bridge_chat(const char *files, const char *prompt, char *out, size_t cap,
                      const atomic_bool *cancel)
{
    if (!files || !prompt || !out || !cap) return false;
    snprintf(out, cap, "Connect the paired laptop over USB and keep its Z23 bridge open.");
    uint16_t port = 0; char token[65] = "";
    int paired = !cancelled(cancel) && prompt[0] && strlen(prompt) <= 16000 ?
        descriptor(files, "codex-bridge.json", &port, token) : PAIR_BAD;
    bool ok = paired == PAIR_OK && !cancelled(cancel);
    if (paired == PAIR_STALE) snprintf(out, cap, "%s", stale_text);
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
    int paired = !cancelled(cancel) && request[0] && strlen(request) <= 1300000 ?
        descriptor(files, "speech-bridge.json", &port, token) : PAIR_BAD;
    bool ok = paired == PAIR_OK && !cancelled(cancel);
    if (paired == PAIR_STALE) snprintf(out, cap, "%s", stale_text);
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
