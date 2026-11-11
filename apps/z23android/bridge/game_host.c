/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include "game_host.h"
#include "relay.h"
#include "bridge_auth.h"
#include "zsha256/zsha256.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PATH_CAP 4096
#define LINE_CAP 1950000u
#define WAIT_MS 10000
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static char game_path[PATH_CAP];
static char snapshot_dir[PATH_CAP], snapshot_path[PATH_CAP], image_hash[65];
static pid_t child = -1;
static int input_fd = -1, output_fd = -1;
static char session_token[65];
static int64_t lease_deadline;
static unsigned generation;
static int64_t now_ms(void)
{
    struct timespec t;
    return clock_gettime(CLOCK_MONOTONIC, &t) ? -1 : (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void stop_locked(void)
{
    if (input_fd >= 0) close(input_fd);
    if (output_fd >= 0) close(output_fd);
    input_fd = output_fd = -1;
    session_token[0] = 0; lease_deadline = 0;
    if (child > 0) {
        (void)kill(child, SIGTERM);
        for (unsigned i = 0; i < 20; i++) {
            pid_t r = waitpid(child, NULL, WNOHANG);
            if (r == child || (r < 0 && errno == ECHILD)) { child = -1; break; }
            struct timespec pause = {.tv_nsec = 10000000};
            (void)nanosleep(&pause, NULL);
        }
        if (child > 0) {
            (void)kill(child, SIGKILL);
            while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
            child = -1;
        }
    }
    if (snapshot_path[0]) (void)unlink(snapshot_path);
    if (snapshot_dir[0]) (void)rmdir(snapshot_dir);
    snapshot_path[0] = snapshot_dir[0] = image_hash[0] = 0;
}
/* Execute precisely the local bytes named by this digest, even if the owner
 * rebuilds the selected path during a session. The private copy is retired
 * when the child stops; this is an image identity, not source ancestry. */
static bool copy_image(int in, int out, zsha256_ctx *hash)
{
    unsigned char buf[16384]; uint64_t total = 0;
    for (;;) {
        ssize_t r = read(in, buf, sizeof(buf));
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return false;
        if (!r) return true;
        total += (uint64_t)r;
        if (total > 268435456u) return false;
        zsha256_update(hash, buf, (size_t)r);
        for (ssize_t off = 0; off < r;) {
            ssize_t w = write(out, buf + off, (size_t)(r - off));
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) return false;
            off += w;
        }
    }
}
static bool snapshot_image(void)
{
    snprintf(snapshot_dir, sizeof(snapshot_dir), "/tmp/z23-game-XXXXXX");
    if (!mkdtemp(snapshot_dir)) { snapshot_dir[0] = 0; return false; }
    int n = snprintf(snapshot_path, sizeof(snapshot_path), "%s/image", snapshot_dir);
    if (n < 0 || (size_t)n >= sizeof(snapshot_path)) return false;
    int in = open(game_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int out = open(snapshot_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
    struct stat st;
    bool ok = in >= 0 && out >= 0 && fstat(in, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 && st.st_size <= 268435456;
    zsha256_ctx hash; zsha256_init(&hash);
    unsigned char digest[32];
    if (ok) ok = copy_image(in, out, &hash);
    if (in >= 0) close(in);
    if (out >= 0 && close(out)) ok = false;
    if (ok) { zsha256_final(&hash, digest); zapp_auth_hex(digest, sizeof(digest), image_hash); }
    return ok;
}
static bool ready(int fd, short events, int64_t deadline, int client)
{
    for (;;) {
        if (!zapp_relay_client_alive(client)) return false;
        int64_t now = now_ms(), left = deadline - now;
        if (now < 0 || left <= 0) return false;
        struct pollfd p = {.fd = fd, .events = events};
        int rc = poll(&p, 1, left > 100 ? 100 : (int)left);
        if (rc < 0 && errno == EINTR) continue;
        if (rc == 0) continue;
        return rc > 0 && (p.revents & events) && !(p.revents & (POLLERR | POLLNVAL));
    }
}
static bool send_request(int client, const char *request, size_t length, int64_t deadline)
{
    size_t sent = 0;
    while (sent < length) {
        if (!ready(input_fd, POLLOUT, deadline, client)) return false;
        ssize_t n = write(input_fd, request + sent, length - sent);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return ready(input_fd, POLLOUT, deadline, client) && write(input_fd, "\n", 1) == 1;
}
static bool receive_reply(int client, char *reply, size_t cap, int64_t deadline)
{
    size_t used = 0;
    while (used + 1 < cap && used < LINE_CAP) {
        if (!ready(output_fd, POLLIN, deadline, client)) return false;
        size_t room = cap - used - 1;
        if (room > LINE_CAP - used) room = LINE_CAP - used;
        if (room > 8192) room = 8192;
        ssize_t n = read(output_fd, reply + used, room);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0 || memchr(reply + used, 0, (size_t)n)) return false;
        char *end = memchr(reply + used, '\n', (size_t)n);
        if (end) {
            if (end != reply + used + n - 1) return false;
            *end = 0;
            return end != reply;
        }
        used += (size_t)n;
    }
    return false;
}
static bool exchange_locked(int client, const char *request, char *reply, size_t cap)
{
    size_t length = strlen(request);
    int64_t now = now_ms(), deadline = now + WAIT_MS;
    if (child <= 0 || !length || length > 4096 || strchr(request, '\n') || cap < 2 || now < 0) return false;
    return send_request(client, request, length, deadline) && receive_reply(client, reply, cap, deadline);
}
bool zapp_game_host_configure(const char *path)
{
    if (!path || path[0] != '/' || strlen(path) >= sizeof(game_path) || access(path, X_OK)) return false;
    pthread_mutex_lock(&lock);
    bool ok = child < 0;
    if (ok) memcpy(game_path, path, strlen(path) + 1);
    pthread_mutex_unlock(&lock);
    return ok;
}
static void *watchdog(void *arg)
{
    unsigned id = *(unsigned *)arg;
    free(arg);
    for (;;) {
        struct timespec pause = {.tv_nsec = 100000000};
        (void)nanosleep(&pause, NULL);
        pthread_mutex_lock(&lock);
        bool done = child < 0 || generation != id;
        if (!done && now_ms() >= lease_deadline) { stop_locked(); done = true; }
        pthread_mutex_unlock(&lock);
        if (done) return NULL;
    }
}
static bool launch_child(void)
{
    int to_child[2] = {-1, -1}, from_child[2] = {-1, -1};
    bool ok = pipe(to_child) == 0 && pipe(from_child) == 0;
    if (ok) for (unsigned i = 0; i < 2; ++i)
        if (fcntl(to_child[i], F_SETFD, FD_CLOEXEC) || fcntl(from_child[i], F_SETFD, FD_CLOEXEC)) ok = false;
    if (ok) {
        pid_t pid = fork();
        if (pid == 0) {
            if (dup2(to_child[0], STDIN_FILENO) < 0 || dup2(from_child[1], STDOUT_FILENO) < 0) _exit(127);
            close(to_child[0]); close(to_child[1]); close(from_child[0]); close(from_child[1]);
            execl(snapshot_path, snapshot_path, "--agent-stdio", (char *)NULL);
            _exit(127);
        }
        ok = pid > 0;
        if (ok) { child = pid; input_fd = to_child[1]; output_fd = from_child[0]; to_child[1] = from_child[0] = -1; }
    }
    for (unsigned i = 0; i < 2; i++) { if (to_child[i] >= 0) close(to_child[i]); if (from_child[i] >= 0) close(from_child[i]); }
    return ok;
}
static bool start_watchdog(void)
{
    unsigned *id = malloc(sizeof(*id)); pthread_t thread;
    if (!id) return false;
    *id = ++generation;
    if (pthread_create(&thread, NULL, watchdog, id)) { free(id); return false; }
    pthread_detach(thread); return true;
}
bool zapp_game_host_start(int client, char token[65], char image[65], char *reply, size_t cap)
{
    if (!token || !image || !reply || !cap) return false;
    pthread_mutex_lock(&lock);
    if (!game_path[0] || child >= 0) { pthread_mutex_unlock(&lock); return false; }
    unsigned char random[32];
    bool ok = zapp_auth_random(random, sizeof(random)) && snapshot_image() && launch_child();
    if (ok) ok = exchange_locked(client, "{\"v\":1,\"id\":0,\"op\":\"observe\",\"capture\":true}", reply, cap) && zapp_relay_client_alive(client);
    if (ok) {
        zapp_auth_hex(random, sizeof(random), session_token);
        memcpy(token, session_token, 65);
        memcpy(image, image_hash, 65);
        lease_deadline = now_ms() + 15000;
        ok = start_watchdog();
    }
    if (!ok) stop_locked();
    pthread_mutex_unlock(&lock);
    return ok;
}
bool zapp_game_host_call(int client, const char *token, const char *request, char image[65], char *reply, size_t cap)
{
    if (!token || !request || !image || !reply || !cap) return false;
    pthread_mutex_lock(&lock);
    bool owned = child > 0 && session_token[0] && !strcmp(token, session_token);
    bool ok = owned && now_ms() < lease_deadline && exchange_locked(client, request, reply, cap) && zapp_relay_client_alive(client);
    if (ok) { lease_deadline = now_ms() + 15000; memcpy(image, image_hash, 65); }
    else if (owned) stop_locked();
    pthread_mutex_unlock(&lock);
    return ok;
}
bool zapp_game_host_close(const char *token)
{
    pthread_mutex_lock(&lock);
    bool ok = token && session_token[0] && !strcmp(token, session_token);
    if (ok) stop_locked();
    pthread_mutex_unlock(&lock);
    return ok;
}
void zapp_game_host_shutdown(void) { pthread_mutex_lock(&lock); stop_locked(); pthread_mutex_unlock(&lock); }
