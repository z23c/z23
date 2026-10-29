/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "operations.h"
#include "json/json.h"
#include "base/cleanse.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
struct operation { struct zapp_operation ui; const char *args[6]; };
static const struct operation operations[] = {
    {{"version", "Build identity", "Inspect the native executable and Tor build.", "Device"}, {"--version"}},
    {{"status", "Node status", "Read readiness, sync state, and the next action.", "Node"}, {"core", "status"}},
    {{"sync", "Sync progress", "Inspect the current validation and download state.", "Node"}, {"core", "sync", "status"}},
    {{"blockers", "Sync blockers", "See why the node is waiting and its suggested remedies.", "Node"}, {"core", "sync", "blockers"}},
    {{"health", "Health report", "Inspect the node's health rollup.", "Diagnostics"}, {"ops", "health"}},
    {{"peers", "Connected peers", "Inspect actual peer connections.", "Network"}, {"core", "network", "peers", "list"}},
    {{"network", "Network status", "Read transport and connection information.", "Network"}, {"core", "network", "status"}},
    {{"chain_tip", "Chain tip", "Read the current active chain tip.", "Node"}, {"core", "chain", "tip"}},
    {{"wallet_balance", "Wallet balance", "Inspect balances without exporting keys or sending funds.", "Wallet"}, {"core", "wallet", "balance"}},
    {{"wallet_status", "Wallet status", "Read the wallet summary and readiness.", "Wallet"}, {"core", "wallet", "status"}},
    {{"commands", "Command catalog", "Explore Z23's native command families.", "Explore"}, {"discover", "help"}},
    {{"fleet_doctor", "Fleet doctor", "Distinguish enrollment, admission, and transport readiness.", "Fleet"}, {"fleet", "doctor"}},
    {{"fleet_machines", "Fleet machines", "List machines admitted to the owner roster.", "Fleet"}, {"fleet", "machines"}}
};

static struct zapp_operation items[sizeof(operations) / sizeof(operations[0])];
static pthread_once_t catalog_once = PTHREAD_ONCE_INIT;
static void catalog_init(void)
{
    for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); ++i) items[i] = operations[i].ui;
}
const struct zapp_operation *zapp_operations(size_t *count)
{
    pthread_once(&catalog_once, catalog_init);
    if (count) *count = sizeof(items) / sizeof(items[0]);
    return items;
}

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

bool zapp_runtime_init(struct zapp_runtime *r, const char *files, const char *libs)
{
    memset(r, 0, sizeof(*r));
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

bool zapp_node_running(struct zapp_runtime *r)
{
    pthread_mutex_lock(&r->mutex);
    bool live = running_locked(r);
    pthread_mutex_unlock(&r->mutex);
    return live;
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

bool zapp_node_start(struct zapp_runtime *r, char *out, size_t cap)
{
    pthread_mutex_lock(&r->mutex);
    if (r->stopping || running_locked(r)) {
        snprintf(out, cap, "%s", r->stopping ? "App is closing." : "The local node is already running.");
        pthread_mutex_unlock(&r->mutex); return false;
    }
    char data[1100], log[1100];
    snprintf(data, sizeof(data), "-datadir=%s", r->directory);
    bool ok = path(log, sizeof(log), r->directory, "app-console.log");
    int fd = ok ? open(log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600) : -1;
    int in = open("/dev/null", O_RDONLY | O_CLOEXEC);
    char *argv[] = {r->executable, data, "-operator-lane=canonical",
                    "-tor", "-onion-persist", NULL};
    int rc = fd >= 0 && in >= 0 ? spawn_redirect(r, argv, in, fd, &r->node) : EIO;
    if (fd >= 0) close(fd);
    if (in >= 0) close(in);
    if (rc) { r->node = 0; snprintf(out, cap, "Could not start Z23: %s", strerror(rc)); }
    else snprintf(out, cap, "Node launch requested. Check Node status for Tor, peers, and synchronization.");
    pthread_mutex_unlock(&r->mutex);
    return rc == 0;
}

bool zapp_node_stop(struct zapp_runtime *r, char *out, size_t cap)
{
    pthread_mutex_lock(&r->mutex);
    bool live = running_locked(r);
    int rc = live ? kill(r->node, SIGINT) : 0;
    snprintf(out, cap, "%s", !live ? "The local node is stopped." :
             rc == 0 ? "Shutdown requested. Z23 is flushing its databases." : "Could not request shutdown.");
    pthread_mutex_unlock(&r->mutex);
    return rc == 0;
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
    while (zapp_node_running(r) && now >= 0 && now < deadline) {
        struct timespec pause = {.tv_nsec = 100000000}; nanosleep(&pause, NULL);
        now = milliseconds();
    }
    pthread_mutex_lock(&r->mutex);
    if (running_locked(r)) {
        (void)kill(r->node, SIGKILL);
        while (waitpid(r->node, NULL, 0) < 0 && errno == EINTR) {}
    }
    pthread_mutex_unlock(&r->mutex);
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
    if (!ended) snprintf(out + p->used, cap - p->used, "\nOperation timed out or the clock was unavailable.");
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

static bool balance_render(const struct json_value *data, char *out, size_t cap)
{
    const char *source = json_get_str(json_get(data, "transparent_source"));
    int64_t wh = json_get_int(json_get(data, "wallet_height"));
    int64_t ch = json_get_int(json_get(data, "chain_height"));
    bool stale = !strcmp(source, "unavailable") ||
        !json_get_bool(json_get(data, "transparent_sources_agree")) ||
        wh < 0 || ch < 0 || wh < ch;
    int n = snprintf(out, cap, "Balance%s: %s ZCL\nTransparent: %s · Shielded: %s\nReserved: %s",
                     stale ? " (may be stale)" : "", json_get_str(json_get(data, "total")),
                     json_get_str(json_get(data, "transparent")), json_get_str(json_get(data, "private")),
                     json_get_str(json_get(data, "encumbered")));
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
        if (strcmp(id, operations[i].ui.id) == 0) return command(r, operations[i].args, NULL, out, cap);
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

void zapp_device_info(char *out, size_t cap)
{
    struct utsname info;
    if (uname(&info) != 0) { snprintf(out, cap, "Device information unavailable."); return; }
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    snprintf(out, cap, "Android · %s\n%ld logical CPUs\nKernel %s\nNative C23 · app-private storage", info.machine, cpus, info.release);
}
