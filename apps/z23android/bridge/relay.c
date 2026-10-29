/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "relay.h"
#include "json/json.h"
#include "base/cleanse.h"
#include "zutf8/zutf8.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define WIRE_CAP 2097152
static size_t prompt_bound = 16000, answer_bound = 65536;
static volatile sig_atomic_t stopping;
static void stop_signal(int sig) { (void)sig; stopping = 1; }
bool zapp_relay_stopping(void) { return stopping != 0; }
static int64_t now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static bool wait_fd(int fd, short events, int64_t deadline)
{
    while (!stopping) {
        int64_t now = now_ms(), left = deadline - now;
        if (now < 0 || left <= 0) return false;
        struct pollfd p = {.fd = fd, .events = events};
        int rc = poll(&p, 1, left > 100 ? 100 : (int)left);
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) return false;
        if (rc > 0) return (p.revents & events) && !(p.revents & (POLLERR | POLLNVAL));
    }
    return false;
}
static bool random_token(char token[65])
{
    unsigned char bytes[32]; size_t used = 0;
    while (used < sizeof(bytes)) {
        ssize_t n = getrandom(bytes + used, sizeof(bytes) - used, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { memory_cleanse(bytes, sizeof(bytes)); return false; }
        used += (size_t)n;
    }
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(bytes); i++) {
        token[i * 2] = hex[bytes[i] >> 4]; token[i * 2 + 1] = hex[bytes[i] & 15];
    }
    token[64] = 0; memory_cleanse(bytes, sizeof(bytes)); return true;
}
static int open_directory(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISDIR(st.st_mode) || st.st_uid != getuid() ||
        (st.st_mode & 07777) != 0700) { close(fd); return -1; }
    return fd;
}
static int listen_local(uint16_t *port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0), reuse = 1;
    if (fd < 0) return -1;
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(*port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t n = sizeof(addr);
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ||
        bind(fd, (struct sockaddr *)&addr, n) || listen(fd, 4) ||
        getsockname(fd, (struct sockaddr *)&addr, &n)) { close(fd); return -1; }
    *port = ntohs(addr.sin_port); return fd;
}
static bool same_file(int dir, const char *name, const struct stat *identity)
{
    struct stat st;
    return !fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW) &&
           st.st_dev == identity->st_dev && st.st_ino == identity->st_ino;
}
static void remove_owned(int dir, const char *name, const struct stat *identity)
{
    if (same_file(dir, name, identity)) (void)unlinkat(dir, name, 0);
}
static bool write_descriptor(int fd, uint16_t port, const char *token)
{
    char data[128]; int n = snprintf(data, sizeof(data), "{\"port\":%u,\"token\":\"%s\"}\n", port, token);
    size_t used = 0; bool ok = fchmod(fd, 0600) == 0 && n > 0 && (size_t)n < sizeof(data);
    while (ok && used < (size_t)n) {
        ssize_t wrote = write(fd, data + used, (size_t)n - used);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) { ok = false; break; }
        used += (size_t)wrote;
    }
    memory_cleanse(data, sizeof(data));
    return ok;
}
/* A persistent relay owns its fixed port, so an existing descriptor is stale and is replaced. */
static int publish(int dir, uint16_t port, const char *token, bool replace, struct stat *identity)
{
    char nonce[65], name[96];
    if (!random_token(nonce)) return -1;
    int n = snprintf(name, sizeof(name), ".codex-bridge-%s", nonce);
    memory_cleanse(nonce, sizeof(nonce));
    if (n <= 0 || (size_t)n >= sizeof(name)) return -1;
    int fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    if (fstat(fd, identity)) { close(fd); return -1; }
    bool ok = write_descriptor(fd, port, token) && same_file(dir, name, identity) &&
              (replace ? renameat(dir, name, dir, "codex-bridge.json") :
                         linkat(dir, name, dir, "codex-bridge.json", 0)) == 0 &&
              same_file(dir, "codex-bridge.json", identity);
    remove_owned(dir, name, identity);
    if (!ok) {
        remove_owned(dir, "codex-bridge.json", identity);
        close(fd); return -1;
    }
    return fd;
}
static void unpublish(int dir, const struct stat *identity)
{
    remove_owned(dir, "codex-bridge.json", identity);
}
static bool receive_line(int fd, char *wire)
{
    int64_t start = now_ms(); size_t used = 0;
    if (start < 0) return false;
    while (used < WIRE_CAP - 1 && wait_fd(fd, POLLIN, start + 5000)) {
        ssize_t n = recv(fd, wire + used, WIRE_CAP - 1 - used, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0 || memchr(wire + used, 0, (size_t)n)) return false;
        used += (size_t)n;
        char *end = memchr(wire, '\n', used);
        if (end) { if (end != wire + used - 1) return false; *end = 0; return true; }
    }
    return false;
}
static bool token_matches(const char *received, const char *token)
{
    if (!received || strlen(received) != 64) return false;
    unsigned diff = 0;
    for (size_t i = 0; i < 64; i++) diff |= (unsigned char)received[i] ^ (unsigned char)token[i];
    return diff == 0;
}
static bool no_nul_escape(const char *wire)
{
    for (size_t i = 0; wire[i]; i++) {
        if (wire[i] != '\\') continue;
        if (!wire[++i]) return false;
        if (wire[i] == 'u' && !strncmp(wire + i, "u0000", 5)) return false;
    }
    return true;
}
static const char *validated_prompt(struct json_value *root, char *wire, const char *token)
{
    if (!no_nul_escape(wire) || !json_read(root, wire, strlen(wire)) || root->type != JSON_OBJ || root->num_children != 2) return NULL;
    const char *received = json_get_str(json_get(root, "token"));
    const char *prompt = json_get_str(json_get(root, "prompt"));
    if (!token_matches(received, token) || !prompt || !prompt[0] || strlen(prompt) > prompt_bound || !zutf8_validate(prompt)) return NULL;
    return prompt;
}
static bool send_bytes(int fd, const char *data, size_t size)
{
    size_t sent = 0; int64_t now = now_ms();
    while (now >= 0 && sent < size && wait_fd(fd, POLLOUT, now + 5000)) {
        ssize_t count = send(fd, data + sent, size - sent, MSG_NOSIGNAL);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) break;
        sent += (size_t)count;
    }
    return sent == size;
}
bool zapp_relay_emit(int fd, const char *line)
{
    return line && send_bytes(fd, line, strlen(line)) && send_bytes(fd, "\n", 1);
}
static void send_response(int fd, bool ok, const char *message)
{
    struct json_value root = {0}; json_set_object(&root);
    char *wire = malloc(WIRE_CAP);
    bool built = json_push_kv_bool(&root, "ok", ok) && json_push_kv_str(&root, ok ? "answer" : "error", message);
    size_t n = built && wire ? json_write(&root, wire, WIRE_CAP - 1) : WIRE_CAP;
    if (n < WIRE_CAP - 1) {
        wire[n++] = '\n';
        (void)send_bytes(fd, wire, n);
    }
    if (wire) { memory_cleanse(wire, WIRE_CAP); free(wire); }
    json_cleanse_strings(&root); json_free(&root);
}
static void serve(int fd, const char *token,
                  bool (*answer)(int, const char *, char *, size_t, const char **))
{
    char *wire = calloc(1, WIRE_CAP), *out = calloc(1, answer_bound);
    struct json_value root = {0};
    const char *prompt = wire && out && receive_line(fd, wire) ? validated_prompt(&root, wire, token) : NULL;
    if (prompt) {
        const char *error = "Conversation unavailable.";
        bool ok = answer(fd, prompt, out, answer_bound, &error);
        if (ok && !memchr(out, 0, answer_bound)) ok = false;
        send_response(fd, ok, ok ? out : error ? error : "Conversation unavailable.");
    }
    json_cleanse_strings(&root); json_free(&root);
    if (wire) { memory_cleanse(wire, WIRE_CAP); free(wire); }
    if (out) { memory_cleanse(out, answer_bound); free(out); }
}
bool zapp_relay_client_alive(int fd)
{
    if (stopping) return false;
    if (fd < 0) return true;
    struct pollfd p = {.fd = fd, .events = POLLIN | POLLRDHUP};
    if (poll(&p, 1, 0) < 0) return errno == EINTR;
    if (p.revents & (POLLRDHUP | POLLHUP | POLLERR | POLLNVAL)) return false;
    char byte;
    ssize_t n = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
    return n > 0 || (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR));
}
static bool stored_token(int dir, char token[65])
{
    int fd = openat(dir, "host-token", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat st; ssize_t n = -1;
    if (!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == getuid() &&
        (st.st_mode & 07777) == 0600 && st.st_nlink == 1 && st.st_size == 64)
        n = read(fd, token, 64);
    close(fd); token[64] = 0;
    return n == 64 && strspn(token, "0123456789abcdef") == 64;
}
/* Reuses a valid stored token; otherwise writes a new one through a private temporary
 * file and renames it over any partial or invalid token left by an interrupted start. */
static bool persistent_token(int dir, char token[65])
{
    if (stored_token(dir, token)) return true;
    if (!random_token(token)) return false;
    (void)unlinkat(dir, ".host-token", 0);
    int fd = openat(dir, ".host-token", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    bool ok = fd >= 0 && fchmod(fd, 0600) == 0 && write(fd, token, 64) == 64 && fsync(fd) == 0;
    if (fd >= 0 && close(fd)) ok = false;
    ok = ok && renameat(dir, ".host-token", dir, "host-token") == 0;
    if (!ok && fd >= 0) (void)unlinkat(dir, ".host-token", 0);
    return ok;
}
static const int stop_signals[] = {SIGINT, SIGTERM, SIGHUP};
static bool catch_stop(struct sigaction old[3])
{
    struct sigaction sa = {.sa_handler = stop_signal};
    sigemptyset(&sa.sa_mask); stopping = 0;
    for (size_t i = 0; i < 3; ++i)
        if (sigaction(stop_signals[i], &sa, &old[i])) {
            while (i--) sigaction(stop_signals[i], &old[i], NULL);
            return false;
        }
    return true;
}
static void release_stop(const struct sigaction old[3])
{
    for (size_t i = 0; i < 3; ++i) sigaction(stop_signals[i], &old[i], NULL);
}
static int accept_loop(int server, const char *token,
                       bool (*answer)(int, const char *, char *, size_t, const char **))
{
    while (!stopping) {
        int64_t now = now_ms(); if (now < 0) return 1;
        if (!wait_fd(server, POLLIN, now + 1000)) continue;
        int client = accept4(server, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (client >= 0) { serve(client, token, answer); close(client); }
    }
    return 0;
}
static int relay_run(const char *directory, uint16_t port, bool persistent,
                     bool (*answer)(int, const char *, char *, size_t, const char **),
                     size_t prompt_limit, size_t answer_limit)
{
    if (!directory || !answer || !prompt_limit || prompt_limit > 1300000 ||
        !answer_limit || answer_limit > 1950000) return 1;
    prompt_bound = prompt_limit; answer_bound = answer_limit;
    int dir = open_directory(directory); if (dir < 0) return 1;
    char token[65] = {0}; struct stat identity;
    int server = listen_local(&port), descriptor = -1, rc = 1;
    if (server < 0 || !(persistent ? persistent_token(dir, token) : random_token(token))) goto done;
    struct sigaction old[3];
    if (!catch_stop(old)) goto done;
    descriptor = publish(dir, port, token, persistent, &identity);
    if (descriptor >= 0) {
        rc = accept_loop(server, token, answer);
        unpublish(dir, &identity); close(descriptor);
    }
    release_stop(old);
done:
    if (server >= 0) close(server);
    close(dir); memory_cleanse(token, sizeof(token)); return rc;
}
int zapp_relay_run_sized(const char *directory,
                   bool (*answer)(int, const char *, char *, size_t, const char **),
                   size_t prompt_limit, size_t answer_limit)
{
    return relay_run(directory, 0, false, answer, prompt_limit, answer_limit);
}
int zapp_relay_run_persistent(const char *directory, uint16_t port,
                   bool (*answer)(int, const char *, char *, size_t, const char **),
                   size_t prompt_limit, size_t answer_limit)
{
    return relay_run(directory, port, true, answer, prompt_limit, answer_limit);
}
int zapp_relay_run(const char *directory,
                   bool (*answer)(int, const char *, char *, size_t, const char **))
{
    return zapp_relay_run_sized(directory, answer, 16000, 65536);
}
