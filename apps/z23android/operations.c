/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "operations.h"
#include "json/json.h"
#include "base/cleanse.h"
#ifdef __ANDROID__
#include <android/log.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
/* The only read-only commands the app runs; start, stop and fleet join have their own paths. */
struct operation { const char *id; const char *args[4]; };
static const struct operation operations[] = {
    {"status", {"core", "status"}},
    {"wallet_balance", {"core", "wallet", "balance"}},
};

static int64_t milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static bool path(char *out, size_t cap, const char *dir, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return n > 0 && (size_t)n < cap;
}

static bool runtime_directory(const char *name, bool private_mode)
{
    if (mkdir(name, 0700) != 0 && errno != EEXIST) return false;
    struct stat st;
    return lstat(name, &st) == 0 && S_ISDIR(st.st_mode) &&
           st.st_uid == getuid() && (!private_mode || (st.st_mode & 077) == 0);
}

bool zapp_runtime_init(struct zapp_runtime *r, const char *files, const char *libs, bool preview)
{
    memset(r, 0, sizeof(*r));
    r->preview = preview;
    zapp_nodelog_init(&r->log, NULL, NULL);
    if (pthread_mutex_init(&r->mutex, NULL) != 0) return false;
    bool ok = path(r->directory, sizeof(r->directory), files, "node") &&
              path(r->executable, sizeof(r->executable), libs, "libz23node.so") &&
              path(r->state_root, sizeof(r->state_root), files, "state") &&
              path(r->temporary_root, sizeof(r->temporary_root), files, "tmp");
    if (ok) ok = runtime_directory(r->directory, false);
    if (ok) ok = runtime_directory(r->state_root, true);
    if (ok) ok = runtime_directory(r->temporary_root, true);
    if (!ok) pthread_mutex_destroy(&r->mutex);
    return ok;
}

static bool running_locked(struct zapp_runtime *r)
{
    if (r->node <= 0) return false;
    int status = 0;
    pid_t got = waitpid(r->node, &status, WNOHANG);
    if (got == r->node || (got < 0 && errno == ECHILD)) r->node = 0;
    return r->node > 0;
}

/* A node started by an earlier app process can outlive it. Its pid file names it, and its first
 * argument, this -datadir, confirms it: the app's own commands pass -datadir last. */
static pid_t earlier_node(const struct zapp_runtime *r)
{
    char file[1100], want[1100], args[4096] = "";
    if (!path(file, sizeof(file), r->directory, "zclassic23.pid")) return 0;
    int fd = open(file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t n = fd >= 0 ? read(fd, args, 31) : -1;
    if (fd >= 0) close(fd);
    long pid = n > 0 ? strtol(args, NULL, 10) : 0;
    if (pid <= 1 || pid > INT32_MAX) return 0;
    snprintf(file, sizeof(file), "/proc/%ld/cmdline", pid);
    fd = open(file, O_RDONLY | O_CLOEXEC);
    n = fd >= 0 ? read(fd, args, sizeof(args) - 1) : -1;
    if (fd >= 0) close(fd);
    if (n <= 0) return 0;
    args[n] = 0;
    snprintf(want, sizeof(want), "-datadir=%s", r->directory);
    size_t first = strlen(args) + 1;
    return first < (size_t)n && !strcmp(args + first, want) ? (pid_t)pid : 0;
}
static bool child_running(struct zapp_runtime *r)
{
    pthread_mutex_lock(&r->mutex);
    bool live = running_locked(r);
    pthread_mutex_unlock(&r->mutex);
    return live;
}
bool zapp_node_running(struct zapp_runtime *r)
{
    return child_running(r) || earlier_node(r) > 0;
}

static int environment_count(size_t *count)
{
    size_t bytes = 0;
    *count = 0;
    while (environ && environ[*count]) {
        size_t len = strlen(environ[*count]);
        if (*count >= 4096 || len > 1024 * 1024 - bytes) return E2BIG;
        bytes += len;
        ++*count;
    }
    return 0;
}

static bool inherited_environment(const char *entry)
{
    return strncmp(entry, "XDG_STATE_HOME=", 15) != 0 &&
           strncmp(entry, "TMPDIR=", 7) != 0 &&
           strncmp(entry, "ZCL_CATCHUP_DRAIN_BUDGET_MS=",
                   sizeof("ZCL_CATCHUP_DRAIN_BUDGET_MS=") - 1) != 0;
}

static int spawn_environment(struct zapp_runtime *r, char *const argv[], pid_t *pid,
                             posix_spawn_file_actions_t *actions, posix_spawnattr_t *attr)
{
    int rc = 0;
    char state[sizeof(r->state_root) + 16], temp[sizeof(r->temporary_root) + 8];
    int written = snprintf(state, sizeof(state), "XDG_STATE_HOME=%s", r->state_root);
    int temp_written = snprintf(temp, sizeof(temp), "TMPDIR=%s", r->temporary_root);
    size_t count = 0;
    rc = environment_count(&count);
    char **env = rc ? NULL : calloc(count + 4, sizeof(*env));
    if (!rc && (!env || written < 0 || (size_t)written >= sizeof(state) ||
                r->state_root[0] != '/' || temp_written < 0 ||
                (size_t)temp_written >= sizeof(temp) || r->temporary_root[0] != '/')) rc = EINVAL;
    size_t used = 0;
    for (size_t i = 0; !rc && i < count; ++i)
        if (inherited_environment(environ[i])) env[used++] = environ[i];
    if (!rc) {
        env[used++] = state;
        env[used++] = temp;
        env[used++] = "ZCL_CATCHUP_DRAIN_BUDGET_MS=100";
        env[used] = NULL;
        rc = posix_spawn(pid, r->executable, actions, attr, argv, env);
    }
    free(env);
    return rc;
}

static int spawn_redirect(struct zapp_runtime *r, char *const argv[], int input,
                          int output, pid_t *pid)
{
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    int rc = posix_spawn_file_actions_init(&actions);
    if (rc) return rc;
    rc = posix_spawnattr_init(&attr);
    if (rc) { posix_spawn_file_actions_destroy(&actions); return rc; }
    if (!rc) rc = posix_spawn_file_actions_adddup2(&actions, input, STDIN_FILENO);
    if (!rc) rc = posix_spawn_file_actions_adddup2(&actions, output, STDOUT_FILENO);
    if (!rc) rc = posix_spawn_file_actions_adddup2(&actions, output, STDERR_FILENO);
    if (!rc) rc = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
    if (!rc) rc = posix_spawnattr_setpgroup(&attr, 0);
    if (!rc) rc = spawn_environment(r, argv, pid, &actions, &attr);
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&actions);
    return rc;
}

/* Start node leaves a marker so the app starts the node when it next opens; Stop node removes it.
 * Closing the app is not the owner's choice and leaves it unchanged. */
static bool remember_on(const struct zapp_runtime *r, bool on)
{
    char marker[1100];
    if (!path(marker, sizeof(marker), r->state_root, "node-on")) return false;
    if (!on) return unlink(marker) == 0 || errno == ENOENT;
    int fd = open(marker, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    return fd >= 0 && close(fd) == 0;
}
bool zapp_node_wanted(const struct zapp_runtime *r)
{
    char marker[1100];
    return !r->preview && path(marker, sizeof(marker), r->state_root, "node-on") && access(marker, F_OK) == 0;
}
enum zapp_pace zapp_node_pace(const struct zapp_runtime *r)
{
    return r->pace_set ? r->pace : ZAPP_PACE_NORMAL;
}
static void pace_error(const char *step, const char *file)
{
#ifdef __ANDROID__
    __android_log_print(ANDROID_LOG_ERROR, "z23", "node pace: %s %s failed: %s", step, file, strerror(errno));
#else
    fprintf(stderr, "z23: node pace: %s %s failed: %s\n", step, file, strerror(errno));
#endif
}
static bool write_all(int fd, const char *text, size_t length)
{
    while (length) {
        ssize_t n = write(fd, text, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        text += n; length -= (size_t)n;
    }
    return true;
}
/* Writes word to a temporary file beside final and renames it into place. */
static bool replace_file(const char *final, const char *temporary, const char *word)
{
    int fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) { pace_error("open", temporary); return false; }
    bool ok = write_all(fd, word, strlen(word));
    if (!ok) pace_error("write", temporary);
    if (ok && fsync(fd) != 0) { pace_error("fsync", temporary); ok = false; }
    if (close(fd) != 0 && ok) { pace_error("close", temporary); ok = false; }
    if (ok && rename(temporary, final) != 0) { pace_error("rename", final); ok = false; }
    if (!ok) (void)unlink(temporary);
    return ok;
}
bool zapp_node_pace_write(struct zapp_runtime *r, enum zapp_pace pace)
{
    static const char *const words[] = {"normal", "gentle", "pause"};
    if (pace < ZAPP_PACE_NORMAL || pace > ZAPP_PACE_PAUSE) return false;
    if (r->pace_set && r->pace == pace) return true;
    char final[1100], temporary[1100];
    if (!path(final, sizeof(final), r->directory, "pace") || !path(temporary, sizeof(temporary), r->directory, "pace.tmp")) {
        errno = ENAMETOOLONG; pace_error("path", "pace"); return false;
    }
    if (!replace_file(final, temporary, words[pace])) return false;
    r->pace = pace; r->pace_set = true;
    return true;
}
/* Starts the node with its console in app-console.log and begins forwarding what it writes there. */
static int spawn_node(struct zapp_runtime *r)
{
    char data[1100], log[1100];
    snprintf(data, sizeof(data), "-datadir=%s", r->directory);
    bool ok = path(log, sizeof(log), r->directory, "app-console.log");
    int fd = ok ? open(log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600) : -1;
    off_t offset = fd >= 0 ? lseek(fd, 0, SEEK_END) : 0;
    int in = open("/dev/null", O_RDONLY | O_CLOEXEC);
    char *argv[] = {r->executable, data, "-operator-lane=canonical",
                    "-tor", "-onion-persist", NULL};
    int rc = fd >= 0 && in >= 0 ? spawn_redirect(r, argv, in, fd, &r->node) : EIO;
    if (fd >= 0) close(fd);
    if (in >= 0) close(in);
    if (!rc) (void)zapp_nodelog_start(&r->log, log, offset < 0 ? 0 : offset, r->node);
    return rc;
}
bool zapp_node_start(struct zapp_runtime *r, char *out, size_t cap)
{
    pthread_mutex_lock(&r->mutex);
    if (r->preview || r->stopping || running_locked(r) || earlier_node(r)) {
        snprintf(out, cap, "%s", r->preview ? "The preview app does not run a node. Use the main Z23 app." :
                 r->stopping ? "App is closing." : "The local node is already running.");
        pthread_mutex_unlock(&r->mutex); return false;
    }
    int rc = spawn_node(r);
    r->stop_sent = false;
    if (rc) { r->node = 0; snprintf(out, cap, "Could not start Z23: %s", strerror(rc)); }
    else snprintf(out, cap, "Node starting.%s",
                  remember_on(r, true) ? "" : " The app could not save this choice.");
    pthread_mutex_unlock(&r->mutex);
    return rc == 0;
}

bool zapp_node_stop(struct zapp_runtime *r, char *out, size_t cap)
{
    pthread_mutex_lock(&r->mutex);
    pid_t node = running_locked(r) ? r->node : earlier_node(r);
    int rc = node > 0 ? kill(node, SIGINT) : 0;
    r->stop_sent = node > 0 && rc == 0;
    bool kept = remember_on(r, false);
    snprintf(out, cap, "%s%s", node <= 0 ? "The local node is stopped." :
             rc == 0 ? "Node stopping. It saves its data first." : "Could not request shutdown.",
             kept ? "" : " The app could not save this choice and may start the node when reopened.");
    pthread_mutex_unlock(&r->mutex);
    return rc == 0;
}

const char *zapp_node_stage(struct zapp_runtime *r)
{
    return zapp_nodelog_stage(&r->log);
}

void zapp_runtime_signal_stop(struct zapp_runtime *r)
{
    pthread_mutex_lock(&r->mutex);
    r->stopping = true;
    if (running_locked(r)) (void)kill(r->node, SIGINT);
    pthread_mutex_unlock(&r->mutex);
}

void zapp_runtime_destroy(struct zapp_runtime *r)
{
    zapp_runtime_signal_stop(r);
    int64_t start = milliseconds();
    int64_t now = start;
    int64_t deadline = start < 0 ? -1 : start + 45000;
    while (child_running(r) && now >= 0 && now < deadline) {
        struct timespec pause = {.tv_nsec = 100000000}; nanosleep(&pause, NULL);
        now = milliseconds();
    }
    pthread_mutex_lock(&r->mutex);
    if (running_locked(r)) {
        (void)kill(r->node, SIGKILL);
        while (waitpid(r->node, NULL, 0) < 0 && errno == EINTR) {}
    }
    pthread_mutex_unlock(&r->mutex);
    zapp_nodelog_stop(&r->log);
    pthread_mutex_destroy(&r->mutex);
}

struct pump { int input, output; pid_t pid; const char *body; size_t sent, length, used; bool truncated; };

static void pump_output(struct pump *p, char *out, size_t cap)
{
    char buffer[4096];
    ssize_t n = read(p->output, buffer, sizeof(buffer));
    if (n > 0) {
        size_t room = cap - 1 - p->used;
        size_t take = (size_t)n < room ? (size_t)n : room;
        memcpy(out + p->used, buffer, take); p->used += take; out[p->used] = 0;
        if (take < (size_t)n) p->truncated = true;
    } else if (n == 0 || (errno != EINTR && errno != EAGAIN)) {
        close(p->output); p->output = -1;
    }
}

static void pump_input(struct pump *p)
{
    ssize_t n = send(p->input, p->body + p->sent, p->length - p->sent, MSG_NOSIGNAL);
    if (n > 0) p->sent += (size_t)n;
    if (p->sent == p->length || (n < 0 && errno != EAGAIN && errno != EINTR)) {
        close(p->input); p->input = -1;
    }
}

static void pump_finish(struct pump *p, char *out, size_t cap, bool ended, int *status)
{
    if (p->input >= 0) close(p->input);
    if (p->output >= 0) close(p->output);
    if (!ended) { (void)kill(-p->pid, SIGKILL); while (waitpid(p->pid, status, 0) < 0 && errno == EINTR) {} }
    if (!ended) snprintf(out + p->used, cap - p->used, "\nThe command timed out.");
    if (p->truncated && cap > 32) {
        const char marker[] = "\n[Output limit reached]\n";
        memcpy(out + cap - sizeof(marker), marker, sizeof(marker));
    }
}

static bool pump_success(const struct pump *p, bool ended, int status)
{
    return ended && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
           p->sent == p->length && !p->truncated;
}
static bool pump_command(struct pump *p, char *out, size_t cap)
{
    int status = 0; bool ended = false; int64_t start = milliseconds();
    int64_t now = start, end = start < 0 ? -1 : start + 15000;
    while ((!ended || p->output >= 0) && now >= 0 && now < end) {
        struct pollfd fds[2] = {{p->output, POLLIN, 0}, {p->input, POLLOUT, 0}};
        if (poll(fds, 2, 50) < 0 && errno != EINTR) break;
        if (p->output >= 0 && fds[0].revents) pump_output(p, out, cap);
        if (p->input >= 0 && fds[1].revents) pump_input(p);
        /* Keep the leader unreaped until its pipe closes, so a timeout can
         * never signal a recycled process-group identifier. */
        if (!ended && p->output < 0) ended = waitpid(p->pid, &status, WNOHANG) == p->pid;
        now = milliseconds();
    }
    pump_finish(p, out, cap, ended, &status);
    return pump_success(p, ended, status);
}

static bool command(struct zapp_runtime *r, const char *const *args,
                    const char *input, char *out, size_t cap)
{
    if (!out || cap < 64) return false;
    out[0] = 0;
    int pipes[2], stdin_pipe[2];
    if (pipe2(pipes, O_CLOEXEC | O_NONBLOCK) != 0) return false;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, stdin_pipe) != 0) { close(pipes[0]); close(pipes[1]); return false; }
    /* Child stdio is blocking; only the parent ends use nonblocking I/O. */
    (void)fcntl(pipes[1], F_SETFL, 0); (void)fcntl(stdin_pipe[0], F_SETFL, 0);
    char data[1100]; snprintf(data, sizeof(data), "-datadir=%s", r->directory);
    char *argv[12]; size_t n = 0; argv[n++] = r->executable;
    for (size_t i = 0; args[i] && n < 9; ++i) argv[n++] = (char *)args[i];
    argv[n++] = data;
    if (input) argv[n++] = "--input=-";
    argv[n] = NULL;
    struct pump pump = {.input = stdin_pipe[1], .output = pipes[0], .body = input ? input : "", .length = input ? strlen(input) : 0};
    pthread_mutex_lock(&r->mutex);
    int rc = r->stopping ? ECANCELED :
             spawn_redirect(r, argv, stdin_pipe[0], pipes[1], &pump.pid);
    pthread_mutex_unlock(&r->mutex);
    close(stdin_pipe[0]); close(pipes[1]);
    if (rc) { close(stdin_pipe[1]); close(pipes[0]); snprintf(out, cap, "Unable to run native Z23: %s", strerror(rc)); return false; }
    if (!pump.length) { close(pump.input); pump.input = -1; }
    return pump_command(&pump, out, cap);
}

static bool balance_amount(const char *s)
{
    if (!s || !*s) return false;
    size_t i = 0;
    while (s[i] >= '0' && s[i] <= '9' && i < 20) i++;
    if (!i || s[i++] != '.') return false;
    for (unsigned j = 0; j < 8; j++, i++)
        if (s[i] < '0' || s[i] > '9') return false;
    return s[i] == 0;
}

static bool balance_fields(const struct json_value *data)
{
    const char *source = json_get_str(json_get(data, "transparent_source"));
    const struct json_value *agree = json_get(data, "transparent_sources_agree");
    const struct json_value *wh = json_get(data, "wallet_height");
    const struct json_value *ch = json_get(data, "chain_height");
    return balance_amount(json_get_str(json_get(data, "total"))) &&
           balance_amount(json_get_str(json_get(data, "transparent"))) &&
           balance_amount(json_get_str(json_get(data, "private"))) &&
           balance_amount(json_get_str(json_get(data, "encumbered"))) &&
           source && source[0] && agree && agree->type == JSON_BOOL &&
           wh && wh->type == JSON_INT && ch && ch->type == JSON_INT;
}

/* A checked eight-decimal amount without trailing zeros: "1.25000000" reads "1.25", "0.00000000" "0". */
static const char *amount_short(const struct json_value *data, const char *key, char out[32])
{
    snprintf(out, 32, "%s", json_get_str(json_get(data, key)));
    char *dot = strchr(out, '.'), *end = out + strlen(out);
    while (dot && end > dot + 1 && end[-1] == '0') *--end = 0;
    if (dot && end == dot + 1) *dot = 0;
    return out;
}

/* One line for the total; the shielded and transparent split only when there is a balance, and the
 * reserved amount only when something is reserved. */
static bool balance_render(const struct json_value *data, char *out, size_t cap)
{
    const char *source = json_get_str(json_get(data, "transparent_source"));
    int64_t wh = json_get_int(json_get(data, "wallet_height"));
    int64_t ch = json_get_int(json_get(data, "chain_height"));
    bool stale = !strcmp(source, "unavailable") ||
        !json_get_bool(json_get(data, "transparent_sources_agree")) ||
        wh < 0 || ch < 0 || wh < ch;
    char total[32], shielded[32], open[32], reserved[32];
    amount_short(data, "total", total);
    amount_short(data, "private", shielded);
    amount_short(data, "transparent", open);
    amount_short(data, "encumbered", reserved);
    int n = snprintf(out, cap, "Balance %s ZCL%s", total, stale ? ", may be out of date" : "");
    if (n >= 0 && (size_t)n < cap && strcmp(total, "0"))
        n += snprintf(out + n, cap - (size_t)n, "\nShielded %s · Transparent %s", shielded, open);
    if (n >= 0 && (size_t)n < cap && strcmp(reserved, "0"))
        n += snprintf(out + n, cap - (size_t)n, "\nReserved %s", reserved);
    return n >= 0 && (size_t)n < cap;
}

bool zapp_balance_format(const char *json, char *out, size_t cap)
{
    if (!json || !out || !cap) return false;
    struct json_value root = {0};
    bool ok = json_read(&root, json, strlen(json));
    const struct json_value *success = json_get(&root, "ok");
    const struct json_value *data = json_get(&root, "data");
    ok = ok && success && success->type == JSON_BOOL && json_get_bool(success) &&
         balance_fields(data) && balance_render(data, out, cap);
    json_free(&root);
    if (!ok) out[0] = 0;
    return ok;
}

bool zapp_operation_run(struct zapp_runtime *r, const char *id, char *out, size_t cap)
{
    if (!r || !id || !out || !cap) return false;
    for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i)
        if (strcmp(id, operations[i].id) == 0) return command(r, operations[i].args, NULL, out, cap);
    snprintf(out, cap, "This operation is not available in the phone's permission set.");
    return false;
}

bool zapp_fleet_join_run(struct zapp_runtime *r, const char *token, char *out, size_t cap)
{
    if (!r || !token || !out || cap < 64) return false;
    struct json_value input = {0}; json_set_object(&input);
    bool ok = json_push_kv_str(&input, "token", token);
    char wire[16384]; size_t n = ok ? json_write(&input, wire, sizeof(wire)) : sizeof(wire);
    json_free(&input);
    const char *args[] = {"fleet", "join", NULL};
    ok = n < sizeof(wire) && command(r, args, wire, out, cap);
    memory_cleanse(wire, sizeof(wire));
    return ok;
}

const char *zapp_json_object(const char *text)
{
    const char *json = !text ? NULL : text[0] == '{' ? text : strstr(text, "\n{");
    return json && json[0] == '\n' ? json + 1 : json;
}

void zapp_plain_text(char *text, size_t cap)
{
    const char *json = cap ? zapp_json_object(text) : NULL;
    if (!json) return;
    struct json_value root = {0};
    const char *message = json_read(&root, json, strlen(json)) ?
        json_get_str(json_get(json_get(&root, "error"), "message")) : NULL;
    snprintf(text, cap, "%s", message && message[0] ? message : "The command did not return a readable result.");
    json_free(&root);
}

bool zapp_node_stopping(struct zapp_runtime *r)
{
    bool running = zapp_node_running(r);
    pthread_mutex_lock(&r->mutex);
    if (!running) r->stop_sent = false;
    bool stopping = r->stop_sent;
    pthread_mutex_unlock(&r->mutex);
    return stopping;
}
