/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "operations.h"
#include "params.h"
#include "private.h"
#include "json/json.h"
#include "base/cleanse.h"
#include "rpc.h"
#include "setup_state.h"
#include "startup_auth.h"
#include "wallet_screens.h"
#include "private.h"
#ifdef __ANDROID__
#include <android/log.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#if defined(__linux__) && __has_include(<sys/pidfd.h>)
#include <sys/pidfd.h>
#define ZAPP_HAVE_PIDFD 1
#endif
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Per call. Loopback answers in under a millisecond, so a longer wait only delays the CLI fallback;
 * status is the only read per refresh, so a silent node costs this much at most. */
#define DIRECT_TIMEOUT_MS 2000
extern char **environ;
/* The only read-only operations the app runs; start, stop and fleet join have their own paths. args is
 * the CLI form; rpc and params are the node call that produces the same data, member the part
 * of its result the CLI reports as data. */
struct operation { const char *id; const char *args[4]; const char *rpc, *params, *member; };
static const struct operation operations[] = {
    {"status", {"core", "status"}, "dumpstate", "[\"status_frontdoor\"]", "state"},
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

/* The roots the node reads from its environment, named without links. Android names the files directory through
 * /data/user/0, a link the system keeps to /data/data, and the node refuses a state root with a link among its
 * parents, so under that name it never finds the fleet record `fleet join` keeps below XDG_STATE_HOME. */
static bool environment_roots(struct zapp_runtime *r, const char *files)
{
    char real[PATH_MAX];
    return realpath(files, real) && path(r->state_root, sizeof(r->state_root), real, "state") &&
           path(r->temporary_root, sizeof(r->temporary_root), real, "tmp");
}

bool zapp_runtime_init(struct zapp_runtime *r, const char *files, const char *libs, bool preview)
{
    memset(r, 0, sizeof(*r));
    r->preview = preview;
    zapp_nodelog_init(&r->log, NULL, NULL);
    zapp_nodelog_init(&r->installer_log, NULL, NULL);
    if (pthread_mutex_init(&r->mutex, NULL) != 0) return false;
    r->startup_auth = zapp_startup_auth_new();
    if (!r->startup_auth) { pthread_mutex_destroy(&r->mutex); return false; }
    bool ok = strlen(files) < sizeof(r->files) && snprintf(r->files, sizeof(r->files), "%s", files) > 0 &&
              path(r->directory, sizeof(r->directory), files, "node") &&
              path(r->executable, sizeof(r->executable), libs, "libz23node.so") &&
              environment_roots(r, files);
    if (ok) ok = runtime_directory(r->directory, false);
    if (ok) ok = runtime_directory(r->state_root, true);
    if (ok) ok = runtime_directory(r->temporary_root, true);
    if (!ok) { zapp_startup_auth_free(r->startup_auth); pthread_mutex_destroy(&r->mutex); }
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
bool zapp_node_installing(struct zapp_runtime *r)
{
    pthread_mutex_lock(&r->mutex); bool installing = r->installer > 0;
    pthread_mutex_unlock(&r->mutex); return installing;
}
bool zapp_installer_observe_locked(struct zapp_runtime *r, struct zapp_replay_progress *out, bool *has_progress)
{
    bool active = r->installer > 0 && !r->stopping &&
        !atomic_load(&r->start_cancel) && r->installer_epoch == r->start_epoch;
    *has_progress = active && r->installer_log.started && r->installer_log.pid == r->installer &&
        zapp_nodelog_replay(&r->installer_log, out);
    return active;
}
bool zapp_installer_observe(struct zapp_runtime *r, struct zapp_replay_progress *out, bool *has_progress)
{
    if (!r || !out || !has_progress) return false;
    pthread_mutex_lock(&r->mutex);
    bool active = zapp_installer_observe_locked(r, out, has_progress);
    pthread_mutex_unlock(&r->mutex);
    return active;
}
bool zapp_node_running(struct zapp_runtime *r)
{
    return child_running(r) || zapp_node_installing(r) || earlier_node(r) > 0;
}

bool zapp_node_start_pending(struct zapp_runtime *r)
{
    if (!r) return false;
    pthread_mutex_lock(&r->mutex);
    bool pending = r->start_pending;
    pthread_mutex_unlock(&r->mutex);
    return pending;
}

bool zapp_node_start_pending_or_running(struct zapp_runtime *r)
{
    if (!r) return false;
    pthread_mutex_lock(&r->mutex);
    bool active = r->start_pending || running_locked(r) || earlier_node(r) > 0;
    pthread_mutex_unlock(&r->mutex);
    return active;
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

/* Variables that would let the node make or fill a wallet on its own: a wallet is made by the setup commands, with the
 * passphrase on standard input, and by nothing the phone's environment can carry. */
static const char *const wallet_variables[] = {"ZCL_WALLET_PASSPHRASE=", "ZCL_ALLOW_PLAINTEXT_WALLET=",
                                                "ZCL_RECOVERY_PHRASE=", "ZCL_WALLET_NO_PHRASE_BACKUP="};
static bool inherited_wallet_variable(const char *entry)
{
    for (size_t i = 0; i < sizeof(wallet_variables) / sizeof(wallet_variables[0]); ++i)
        if (strncmp(entry, wallet_variables[i], strlen(wallet_variables[i])) == 0) return false;
    return true;
}
static bool inherited_environment(const char *entry)
{
    return inherited_wallet_variable(entry) && strncmp(entry, "ZCL_DEPLOY_ALLOW_CANONICAL=", 27) != 0 &&
           strncmp(entry, "XDG_STATE_HOME=", 15) != 0 &&
           strncmp(entry, "TMPDIR=", 7) != 0 &&
           strncmp(entry, "ZCL_CATCHUP_DRAIN_BUDGET_MS=",
                   sizeof("ZCL_CATCHUP_DRAIN_BUDGET_MS=") - 1) != 0 &&
           strncmp(entry, "ZCL_BIP_PAGE_CACHE_KIB=",
                   sizeof("ZCL_BIP_PAGE_CACHE_KIB=") - 1) != 0;
}

static bool inherited_home(const char *entry)
{
    return strncmp(entry, "HOME=", 5) == 0;
}

/* Writes "name=root" into out. The root must be absolute and the entry must fit. */
static bool app_root_entry(char *out, size_t cap, const char *name, const char *root)
{
    int n = snprintf(out, cap, "%s=%s", name, root);
    return n > 0 && (size_t)n < cap && root[0] == '/';
}

/* Copies the parent's environment entries the app does not set itself. */
static size_t copy_inherited_environment(char **env, size_t count, bool *has_home)
{
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        if (!inherited_environment(environ[i])) continue;
        *has_home = *has_home || inherited_home(environ[i]);
        env[used++] = environ[i];
    }
    return used;
}

/* Appends the fixed app entries; HOME is added only when the parent did not supply one. */
static void append_app_environment(char **env, size_t used, char *state,
                                   char *temp, char *home, bool has_home)
{
    env[used++] = state;
    env[used++] = temp;
    if (!has_home) env[used++] = home;
    env[used++] = "ZCL_CATCHUP_DRAIN_BUDGET_MS=100";
    env[used++] = "ZCL_BIP_PAGE_CACHE_KIB=32768";
    env[used] = NULL;
}

static int spawn_environment(struct zapp_runtime *r, char *const argv[], pid_t *pid,
                             posix_spawn_file_actions_t *actions, posix_spawnattr_t *attr, bool installer)
{
    char state[sizeof(r->state_root) + 16], temp[sizeof(r->temporary_root) + 8];
    char home[sizeof(r->state_root) + 8];
    size_t count = 0;
    int rc = environment_count(&count);
    if (rc) return rc;
    if (!app_root_entry(state, sizeof(state), "XDG_STATE_HOME", r->state_root) ||
        !app_root_entry(temp, sizeof(temp), "TMPDIR", r->temporary_root) ||
        !app_root_entry(home, sizeof(home), "HOME", r->state_root)) return EINVAL;
    char **env = calloc(count + 7, sizeof(*env));
    if (!env) return EINVAL;
    bool has_home = false;
    size_t used = copy_inherited_environment(env, count, &has_home);
    append_app_environment(env, used, state, temp, home, has_home);
    if (installer) {
        size_t end = used;
        while (env[end]) ++end;
        env[end++] = "ZCL_DEPLOY_ALLOW_CANONICAL=1";
        env[end] = NULL;
    }
    rc = posix_spawn(pid, r->executable, actions, attr, argv, env);
    free(env);
    return rc;
}

static int spawn_redirect_mode(struct zapp_runtime *r, char *const argv[], int input,
                          int output, pid_t *pid, bool installer, int auth_child, int auth_parent)
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
    if (!rc && auth_child >= 0) rc = posix_spawn_file_actions_addclose(&actions, auth_parent);
    if (!rc && auth_child >= 0) rc = posix_spawn_file_actions_adddup2(&actions, auth_child, 198);
    if (!rc && auth_child >= 0) rc = posix_spawn_file_actions_addclose(&actions, auth_child);
    if (!rc) rc = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
    if (!rc) rc = posix_spawnattr_setpgroup(&attr, 0);
    if (!rc) rc = spawn_environment(r, argv, pid, &actions, &attr, installer);
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
    return !r->preview && !zapp_startup_auth_refused(r->startup_auth) &&
        path(marker, sizeof(marker), r->state_root, "node-on") && access(marker, F_OK) == 0;
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
static int spawn_redirect(struct zapp_runtime *r, char *const argv[], int input,
    int output, pid_t *pid)
{
    return spawn_redirect_mode(r, argv, input, output, pid, false, -1, -1);
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
static int spawn_node_with_auth(struct zapp_runtime *r, char *const argv[], int in, int fd)
{
    int pair[2] = {-1, -1};
    int child = -1;
    if (fd >= 0 && in >= 0 && socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0)
        child = fcntl(pair[1], F_DUPFD_CLOEXEC, 199);
    if (pair[1] >= 0) close(pair[1]);
    int rc = child >= 0 ? spawn_redirect_mode(r, argv, in, fd, &r->node, false, child, pair[0]) : EIO;
    if (child >= 0) close(child);
    if (!rc && !zapp_startup_auth_start(r->startup_auth, pair[0], r->files)) {
        (void)kill(r->node, SIGKILL);
        while (waitpid(r->node, NULL, 0) < 0 && errno == EINTR) {}
        r->node = 0; rc = EIO;
    } else if (!rc) pair[0] = -1;
    if (pair[0] >= 0) close(pair[0]);
    return rc;
}
/* Starts the node with its console in app-console.log and begins forwarding what it writes there. */
static int spawn_node(struct zapp_runtime *r)
{
    char data[1100], log[1100];
    snprintf(data, sizeof(data), "-datadir=%s", r->directory);
    bool ok = path(log, sizeof(log), r->directory, "app-console.log");
    off_t cap = r->console_cap > 0 ? r->console_cap : ZAPP_CONSOLE_CAP;
    /* An oversize log moves to app-console.log.1 so the new file starts empty. A failed rename is not fatal: the reader
     * still truncates the file once it passes the cap. */
    if (ok) (void)zapp_console_rotate(log, cap);
    int fd = ok ? open(log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600) : -1;
    off_t offset = fd >= 0 ? lseek(fd, 0, SEEK_END) : 0;
    int in = open("/dev/null", O_RDONLY | O_CLOEXEC);
    /* Tor only: the node dials onion peers, resolves no DNS seed and never falls back to clearnet. */
    char params[1200], roster[ZAPP_PRIVATE_PEERS_MAX * (ZAPP_ONION_PEER_MAX + 1) + 1];
    char *argv[12 + ZAPP_PRIVATE_ARGV_MAX + ZAPP_PRIVATE_PEERS_MAX + 1] = {
        r->executable, data, "-operator-lane=canonical", "-tor", "-onion-persist", "-flysync-auto", "-nolegacyimport", "-nolegacyutxoimport"};
    size_t argc = 8;
    struct zapp_private_args private_mode;
    if (zapp_params_arg(r->files, params, sizeof(params))) argv[argc++] = params;
    argv[argc++] = "-private-listeners";
    argv[argc++] = "-observation=0";
    argv[argc++] = "-walletbackup=0";
    argv[argc++] = "-wallet-startup-auth-fd=198";
    (void)zapp_private_roster_load(r->directory, roster, sizeof(roster));
    zapp_private_args(&private_mode, roster);
    for (size_t i = 0; i < private_mode.argc; i++) argv[argc++] = private_mode.argv[i];
    int rc = spawn_node_with_auth(r, argv, in, fd);
    if (fd >= 0) close(fd);
    if (in >= 0) close(in);
    if (!rc) (void)zapp_nodelog_start(&r->log, log, offset < 0 ? 0 : offset, r->node, cap);
    return rc;
}
struct preload_result {
    char reply[8192], identity[65];
    bool valid, command_ok;
};
static void node_preload(struct zapp_runtime *, struct preload_result *);
bool zapp_node_preload_ready(const struct zapp_runtime *r)
{
    return r && atomic_load(&r->preload_ready) && zapp_setup_preload_allowed();
}
bool zapp_node_preload_get(struct zapp_runtime *r, char *out, size_t cap,
    char identity[65], uint64_t *epoch, bool *command_ok)
{
    if (!r || !out || !cap || !identity || !epoch || !command_ok) return false;
    pthread_mutex_lock(&r->mutex);
    char current[65];
    bool ok = zapp_setup_preload_allowed() &&
              zapp_setup_identity(r->files, current) &&
              zapp_setup_preload_allowed() &&
              r->preload_reply[0] && r->preload_epoch == r->start_epoch &&
              !strcmp(current, r->preload_identity) && strlen(r->preload_reply) < cap;
    if (ok) {
        snprintf(out, cap, "%s", r->preload_reply);
        memcpy(identity, r->preload_identity, 65);
        *epoch = r->preload_epoch;
        *command_ok = r->preload_ok;
    }
    pthread_mutex_unlock(&r->mutex);
    return ok;
}
/* A malformed or missing setup kind cannot prove a wrapped key is unrelated
 * to a prepared creation. Restore is distinct only with no creation nonce. */
static bool node_setup_blocks_start(struct zapp_runtime *r)
{
    if (zapp_setup_confirmed(r->files)) return false;
    enum zapp_setup_kind kind = zapp_setup_kind_read(r->files);
    return kind == ZAPP_KIND_CREATE || zapp_setup_nonce_exists(r->files) ||
           (kind == ZAPP_KIND_NONE && zapp_setup_state(r->files) == ZAPP_SETUP_INTERRUPTED);
}

static const char *node_start_refusal(struct zapp_runtime *r)
{
    if (r->preview) return "The preview app does not run a node. Use the main Z23 app.";
    if (r->stopping) return "App is closing.";
    if (!zapp_startup_auth_ready(r->startup_auth)) return "The previous authentication is still closing.";
    if (r->start_pending) return "The local node is already starting.";
    if (node_setup_blocks_start(r))
        return "Wallet setup is pending. Finish setup before starting the node.";
    if (atomic_load(&r->setup_running)) return "Wallet setup is running. The node can start when it ends.";
    if (running_locked(r) || earlier_node(r)) return "The local node is already running.";
    return NULL;
}

static bool node_start_reserve(struct zapp_runtime *r, uint64_t *ticket, char *out, size_t cap, bool resume, bool guarded, uint64_t epoch)
{
    if (!r || !ticket || !out || !cap) return false;
    pthread_mutex_lock(&r->mutex);
    if (!resume) zapp_startup_auth_reset(r->startup_auth);
    const char *refusal = guarded && r->start_epoch != epoch ? "Node start changed." :
        resume && !zapp_node_wanted(r) ? "Node is off." : node_start_refusal(r);
    if (refusal) {
        snprintf(out, cap, "%s", refusal);
        pthread_mutex_unlock(&r->mutex); return false;
    }
    if (atomic_exchange(&r->setup_running, true)) {
        snprintf(out, cap, "Wallet setup is running. The node can start when it ends.");
        pthread_mutex_unlock(&r->mutex); return false;
    }
    r->start_pending = true;
    r->start_executing = false;
    r->start_preload_allowed = zapp_setup_preload_allowed();
    r->start_resume_wanted = resume;
    atomic_store(&r->start_cancel, false);
    r->reserved_epoch = ++r->start_epoch;
    *ticket = r->reserved_epoch;
    r->preload_reply[0] = 0;
    atomic_store(&r->preload_ready, false);
    pthread_mutex_unlock(&r->mutex);
    return true;
}

bool zapp_node_start_reserve(struct zapp_runtime *r, uint64_t *ticket, char *out, size_t cap)
{
    return node_start_reserve(r, ticket, out, cap, false, false, 0);
}

bool zapp_node_resume_reserve(struct zapp_runtime *r, uint64_t *ticket, char *out, size_t cap)
{
    return node_start_reserve(r, ticket, out, cap, true, false, 0);
}

bool zapp_node_handoff_resume_reserve(struct zapp_runtime *r, uint64_t epoch, uint64_t *ticket, char *out, size_t cap)
{
    return node_start_reserve(r, ticket, out, cap, true, true, epoch);
}
void zapp_node_start_discard(struct zapp_runtime *r, uint64_t ticket)
{
    if (!r) return;
    pthread_mutex_lock(&r->mutex);
    if (r->start_pending && !r->start_executing && r->reserved_epoch == ticket) {
        r->start_pending = false;
        ++r->start_epoch;
        atomic_store(&r->setup_running, false);
        atomic_store(&r->start_cancel, true);
    }
    pthread_mutex_unlock(&r->mutex);
}
static bool install_private_file(int fd, struct stat *st, bool marker)
{
    char word[9];
    ssize_t n = read(fd, word, sizeof(word));
    return fstat(fd, st) == 0 && S_ISREG(st->st_mode) && st->st_uid == getuid() &&
        !(st->st_mode & 077) && (st->st_nlink == 1 || (marker && st->st_nlink == 2)) &&
        n == 8 && !memcmp(word, "install\n", 8);
}
static bool install_private_dir(int dir)
{
    struct stat st;
    return fstat(dir, &st) == 0 && st.st_uid == getuid() && !(st.st_mode & 077);
}
static bool install_private_bundle(int dir)
{
    int fd = openat(dir, "install-bundle.sqlite", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == getuid() &&
        !(st.st_mode & 077) && st.st_nlink == 1;
    close(fd);
    return ok;
}
static bool install_consume_link(int dir, const struct stat *request)
{
    struct stat st;
    return linkat(dir, "install-bundle.request", dir, "install-bundle.consumed", 0) == 0 &&
        fstatat(dir, "install-bundle.consumed", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        st.st_dev == request->st_dev && st.st_ino == request->st_ino && fsync(dir) == 0 &&
        unlinkat(dir, "install-bundle.request", 0) == 0 && fsync(dir) == 0;
}
/* The consumed link is only a durable at-most-once launch record. */
static int install_request_consume(struct zapp_runtime *r)
{
    int dir = open(r->directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) return -1;
    struct stat st, request_st;
    int result = -1;
    int marker = openat(dir, "install-bundle.consumed", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (marker >= 0) {
        bool valid = install_private_dir(dir) && install_private_file(marker, &st, true);
        close(marker);
        if (valid) result = 0;
        goto done;
    }
    if (errno != ENOENT) goto done;
    int fd = openat(dir, "install-bundle.request", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) { if (errno == ENOENT) result = 0; goto done; }
    bool valid = install_private_dir(dir) && install_private_file(fd, &st, false);
    if (valid) request_st = st;
    close(fd);
    if (!valid) goto done;
    if (!install_private_bundle(dir) || !install_consume_link(dir, &request_st)) goto done;
    result = 1;
done:
    close(dir);
    return result;
}
static int spawn_installer(struct zapp_runtime *r)
{
    char data[1100], bundle[1200], arg[1300], log[1100], params[1200];
    snprintf(data, sizeof(data), "-datadir=%s", r->directory);
    if (!path(bundle, sizeof(bundle), r->directory, "install-bundle.sqlite") ||
        snprintf(arg, sizeof(arg), "-install-consensus-bundle=%s", bundle) >= (int)sizeof(arg) ||
        !path(log, sizeof(log), r->directory, "app-console.log")) return EINVAL;
    int fd = open(log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    off_t offset = fd >= 0 ? lseek(fd, 0, SEEK_END) : -1;
    int in = open("/dev/null", O_RDONLY | O_CLOEXEC);
    char *argv[10] = {r->executable, data, "-operator-lane=canonical", "-nolegacyimport",
        "-nolegacyutxoimport", arg};
    size_t argc = 6;
    if (zapp_params_arg(r->files, params, sizeof(params))) argv[argc++] = params;
    argv[argc] = NULL;
    int rc = fd >= 0 && in >= 0 ? spawn_redirect_mode(r, argv, in, fd, &r->installer, true, -1, -1) : EIO;
    if (!rc && offset >= 0) {
        off_t cap = r->console_cap ? r->console_cap : ZAPP_CONSOLE_CAP;
        (void)zapp_nodelog_start(&r->installer_log, log, offset, r->installer, cap);
    }
    if (fd >= 0) close(fd);
    if (in >= 0) close(in);
    return rc;
}
static bool node_install_allowed_locked(struct zapp_runtime *r, uint64_t ticket)
{
    return !r->stopping && !atomic_load(&r->start_cancel) && ticket == r->start_epoch &&
        (!r->start_preload_allowed || zapp_setup_preload_allowed()) &&
        (!r->start_resume_wanted || zapp_node_wanted(r)) && !node_setup_blocks_start(r) &&
        !running_locked(r) && !earlier_node(r);
}

/* Called with the reservation mutex held; sleep occurs without that mutex. */
static int node_install_if_requested(struct zapp_runtime *r, uint64_t ticket)
{
    if (!node_install_allowed_locked(r, ticket)) return 0;
    pthread_mutex_unlock(&r->mutex);
    zapp_nodelog_stop(&r->log);
    pthread_mutex_lock(&r->mutex);
    if (!node_install_allowed_locked(r, ticket)) return -1;
    pthread_mutex_unlock(&r->mutex);
    int requested = install_request_consume(r);
    pthread_mutex_lock(&r->mutex);
    if (requested <= 0) return requested;
    if (!node_install_allowed_locked(r, ticket)) return -1;
    r->installer_epoch = ticket;
    int rc = spawn_installer(r);
    if (rc) return -1;
    ++r->installer_generation;
    pid_t child = r->installer;
    int status = 0; pid_t got;
    for (;;) { got = waitpid(child, &status, WNOHANG);
        if (got == child || (got < 0 && errno != EINTR)) break;
        pthread_mutex_unlock(&r->mutex);
        struct timespec pause = {.tv_nsec = 100000000}; nanosleep(&pause, NULL); pthread_mutex_lock(&r->mutex);
    }
    r->installer = 0;
    pthread_mutex_unlock(&r->mutex);
    zapp_nodelog_stop(&r->installer_log);
    pthread_mutex_lock(&r->mutex);
    return got == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 1 : -1;
}
static bool node_start_finish_locked(struct zapp_runtime *r, uint64_t ticket,
    const struct preload_result *preload, char *out, size_t cap)
{
    bool cancelled = r->stopping || atomic_load(&r->start_cancel) || ticket != r->start_epoch ||
                     (r->start_preload_allowed && !zapp_setup_preload_allowed()) ||
                     (r->start_resume_wanted && !zapp_node_wanted(r)) ||
                     (node_setup_blocks_start(r));
    r->start_pending = false;
    r->start_executing = false;
    atomic_store(&r->setup_running, false);
    if (cancelled) {
        snprintf(out, cap, "Node start cancelled.");
        return false;
    }
    if (running_locked(r) || earlier_node(r)) {
        snprintf(out, cap, "The local node is already running.");
        return false;
    }
    int rc = spawn_node(r);
    if (!rc && preload->valid) {
        memcpy(r->preload_reply, preload->reply, sizeof(r->preload_reply));
        memcpy(r->preload_identity, preload->identity, sizeof(r->preload_identity));
        r->preload_epoch = ticket;
        r->preload_ok = preload->command_ok;
        atomic_store(&r->preload_ready, true);
    }
    r->stop_sent = false;
    if (rc) { r->node = 0; snprintf(out, cap, "Could not start Z23: %s", strerror(rc)); }
    else snprintf(out, cap, "Node starting.%s",
                  remember_on(r, true) ? "" : " The app could not save this choice.");
    return rc == 0;
}

/* Caller owns runtime mutex; acquire outer admission locks without it. */
static bool node_start_enter_gate(struct zapp_runtime *r, uint64_t ticket,
    const struct zapp_start_gate *gate, uint64_t *deferred_epoch)
{
    pthread_mutex_unlock(&r->mutex);
    bool entered = gate->enter(gate->ctx);
    pthread_mutex_lock(&r->mutex);
    if (entered) return true;
    if (r->start_executing && r->reserved_epoch == ticket) {
        bool defer = r->start_pending && r->start_epoch == ticket && !atomic_load(&r->start_cancel);
        r->start_pending = r->start_executing = false;
        atomic_store(&r->setup_running, false);
        if (defer && deferred_epoch) *deferred_epoch = ++r->start_epoch;
    }
    return false;
}
static bool node_start_ticket_current(const struct zapp_runtime *r, uint64_t ticket)
{
    return r->start_pending && !r->start_executing && r->reserved_epoch == ticket &&
        r->start_epoch == ticket && !atomic_load(&r->start_cancel);
}
bool zapp_node_start_reserved_gated(struct zapp_runtime *r, uint64_t ticket, char *out, size_t cap,
    const struct zapp_start_gate *gate, uint64_t *deferred_epoch)
{
    if (!r || !out || !cap) return false;
    pthread_mutex_lock(&r->mutex);
    if (!node_start_ticket_current(r, ticket)) {
        snprintf(out, cap, "Node start cancelled.");
        pthread_mutex_unlock(&r->mutex); return false;
    }
    r->start_executing = true;
    pthread_mutex_unlock(&r->mutex);
    struct preload_result preload = {0};
    node_preload(r, &preload);
    pthread_mutex_lock(&r->mutex);
    int install = gate ? 0 : node_install_if_requested(r, ticket);
    if (install > 0) preload.valid = false;
    bool entered = false;
    if (install >= 0 && gate) {
        entered = node_start_enter_gate(r, ticket, gate, deferred_epoch);
        if (!entered) {
            snprintf(out, cap, "Node restart is waiting.");
            pthread_mutex_unlock(&r->mutex); return false;
        }
    }
    bool ok;
    if (install < 0) {
        r->start_pending = false; r->start_executing = false;
        atomic_store(&r->setup_running, false);
        snprintf(out, cap, "Bundle install stopped or refused; state may need recovery.");
        ok = false;
    } else ok = node_start_finish_locked(r, ticket, &preload, out, cap);
    pthread_mutex_unlock(&r->mutex);
    if (entered) gate->leave(gate->ctx);
    return ok;
}

bool zapp_node_start_reserved(struct zapp_runtime *r, uint64_t ticket, char *out, size_t cap)
{
    return zapp_node_start_reserved_gated(r, ticket, out, cap, NULL, NULL);
}

bool zapp_node_start(struct zapp_runtime *r, char *out, size_t cap)
{
    uint64_t ticket;
    return zapp_node_start_reserve(r, &ticket, out, cap) &&
           zapp_node_start_reserved(r, ticket, out, cap);
}

bool zapp_node_resume_if_wanted(struct zapp_runtime *r, char *out, size_t cap)
{
    uint64_t ticket;
    return zapp_node_resume_reserve(r, &ticket, out, cap) &&
           zapp_node_start_reserved(r, ticket, out, cap);
}

static bool request_stop(struct zapp_runtime *r, char *out, size_t cap, bool owner_choice)
{
    pthread_mutex_lock(&r->mutex);
    zapp_startup_auth_cancel(r->startup_auth);
    ++r->start_epoch;
    r->preload_reply[0] = 0;
    atomic_store(&r->preload_ready, false);
    if (r->start_pending) {
        atomic_store(&r->start_cancel, true);
        if (!r->start_executing) {
            r->start_pending = false;
            atomic_store(&r->setup_running, false);
        }
    }
    pid_t node = r->installer > 0 ? r->installer : (running_locked(r) ? r->node : earlier_node(r));
    int rc = node > 0 ? kill(node, SIGINT) : 0;
    r->stop_sent = node > 0 && rc == 0;
    bool kept = !owner_choice || remember_on(r, false);
    snprintf(out, cap, "%s%s", node <= 0 ? "The local node is stopped." :
             rc == 0 ? "Node stopping. It saves its data first." : "Could not request shutdown.",
             kept ? "" : " The app could not save this choice and may start the node when reopened.");
    pthread_mutex_unlock(&r->mutex);
    return rc == 0;
}

/* pidfd prevents PID reuse while proc checks bind UID, image and datadir. */
#if defined(ZAPP_HAVE_PIDFD)
static bool handoff_process_image(struct zapp_runtime *r, pid_t pid)
{
    char p[96]; struct stat proc, image, expected;
    if (snprintf(p, sizeof(p), "/proc/%ld", (long)pid) <= 0 || stat(p, &proc) ||
        proc.st_uid != getuid()) return false;
    return snprintf(p, sizeof(p), "/proc/%ld/exe", (long)pid) > 0 &&
        !stat(p, &image) && !stat(r->executable, &expected) &&
        image.st_dev == expected.st_dev && image.st_ino == expected.st_ino;
}
static bool handoff_process_start(pid_t pid, uint64_t *token)
{
    char p[96], row[4096];
    if (snprintf(p, sizeof(p), "/proc/%ld/stat", (long)pid) <= 0) return false;
    FILE *f = fopen(p, "r"); if (!f) return false;
    bool ok = fgets(row, sizeof(row), f) != NULL;
    if (fclose(f)) ok = false;
    char *s = ok ? strrchr(row, ')') : NULL;
    if (!s || s[1] != ' ') return false;
    s += 2;
    for (int field = 3; field < 22; ++field) {
        s = strchr(s, ' '); if (!s) return false; ++s;
    }
    char *end = NULL; errno = 0; unsigned long long v = strtoull(s, &end, 10);
    if (errno || end == s || !v || (*end != ' ' && *end != '\n')) return false;
    *token = (uint64_t)v; return true;
}
#endif
static bool handoff_proc(struct zapp_runtime *r, pid_t pid, uint64_t *token)
{
#if defined(ZAPP_HAVE_PIDFD)
    return handoff_process_image(r, pid) && handoff_process_start(pid, token);
#else
    (void)r; (void)pid; (void)token; return false;
#endif
}
void zapp_node_identity_close(struct zapp_node_identity *id)
{
    if (id && id->pidfd >= 0) { close(id->pidfd); id->pidfd = -1; }
}
bool zapp_node_identity(struct zapp_runtime *r, struct zapp_node_identity *id)
{
    if (!r || !id) return false;
    *id = (struct zapp_node_identity){.pidfd = -1};
#if defined(ZAPP_HAVE_PIDFD)
    pthread_mutex_lock(&r->mutex);
    pid_t pid = running_locked(r) ? r->node : earlier_node(r);
    int fd = pid > 1 ? pidfd_open(pid, 0) : -1;
    uint64_t token = 0;
    bool ok = !r->stopping && !r->stop_sent && fd >= 0 && handoff_proc(r, pid, &token) &&
        (r->node == pid || earlier_node(r) == pid);
    if (ok) *id = (struct zapp_node_identity){.pid = pid, .pidfd = fd,
        .epoch = r->start_epoch, .start_token = token};
    else if (fd >= 0) close(fd);
    pthread_mutex_unlock(&r->mutex); return ok;
#else
    return false;
#endif
}

bool zapp_node_replay_progress(struct zapp_runtime *r, const struct zapp_node_identity *id,
    struct zapp_replay_progress *out)
{
    if (!r || !id || !out) return false;
    pthread_mutex_lock(&r->mutex);
    bool ok = !r->stopping && !r->stop_sent && r->start_epoch == id->epoch &&
        r->node == id->pid && r->log.started && r->log.pid == id->pid && running_locked(r) &&
        zapp_nodelog_replay(&r->log, out);
    pthread_mutex_unlock(&r->mutex);
    return ok;
}

bool zapp_node_handoff_stop(struct zapp_runtime *r, const struct zapp_node_identity *id, uint64_t *epoch)
{
    if (!r || !id || !epoch) return false;
    pthread_mutex_lock(&r->mutex);
    uint64_t token = 0;
    bool ok = !r->stopping && !r->stop_sent && !r->start_pending && id->pidfd >= 0 &&
        r->start_epoch == id->epoch && zapp_node_wanted(r) && handoff_proc(r, id->pid, &token) &&
        token == id->start_token && (r->node == id->pid || earlier_node(r) == id->pid);
#if defined(ZAPP_HAVE_PIDFD)
    if (ok) {
        ok = pidfd_send_signal(id->pidfd, SIGINT, NULL, 0) == 0;
        if (ok) { r->stop_sent = true; *epoch = ++r->start_epoch; }
    }
#else
    ok = false;
#endif
    pthread_mutex_unlock(&r->mutex);
    return ok;
}

bool zapp_node_handoff_current(struct zapp_runtime *r, uint64_t epoch)
{
    if (!r) return false;
    pthread_mutex_lock(&r->mutex);
    bool ok = !r->stopping && r->start_epoch == epoch && zapp_node_wanted(r);
    pthread_mutex_unlock(&r->mutex);
    return ok;
}

/* The owner's Stop button: also forgets that the node should run when the app opens. */
bool zapp_node_stop(struct zapp_runtime *r, char *out, size_t cap)
{
    return request_stop(r, out, cap, true);
}
/* Wallet setup pauses the node for its files; the owner's on or off choice stays as it was. */
bool zapp_node_stop_for_setup(struct zapp_runtime *r, char *out, size_t cap)
{
    return request_stop(r, out, cap, false);
}

const char *zapp_node_stage(struct zapp_runtime *r)
{
    return zapp_nodelog_stage(&r->log);
}

void zapp_runtime_signal_stop(struct zapp_runtime *r)
{
    pthread_mutex_lock(&r->mutex);
    zapp_startup_auth_cancel(r->startup_auth);
    r->stopping = true;
    ++r->start_epoch;
    r->preload_reply[0] = 0;
    atomic_store(&r->preload_ready, false);
    if (r->start_pending) {
        atomic_store(&r->start_cancel, true);
        if (!r->start_executing) {
            r->start_pending = false;
            atomic_store(&r->setup_running, false);
        }
    }
    if (r->installer > 0) (void)kill(r->installer, SIGINT);
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
    zapp_startup_auth_free(r->startup_auth);
    pthread_mutex_destroy(&r->mutex);
}

#define COMMAND_TIMEOUT_MS 15000
struct pump { int input, output; pid_t pid; const char *body; size_t sent, length, used; bool truncated; unsigned timeout_ms;
              const char *const *args; const atomic_bool *cancel; bool cancelled; int exit_code; };

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
    memory_cleanse(buffer, sizeof(buffer));
}

static void pump_input(struct pump *p)
{
    ssize_t n = send(p->input, p->body + p->sent, p->length - p->sent, MSG_NOSIGNAL);
    if (n > 0) p->sent += (size_t)n;
    if (p->sent == p->length || (n < 0 && errno != EAGAIN && errno != EINTR)) {
        close(p->input); p->input = -1;
    }
}

/* Logs a command stopped at its limit by its first three words, which are fixed command words, never an argument the owner
 * gave. */
static void command_note(const struct pump *p)
{
    char words[64] = "";
    for (size_t i = 0, at = 0; i < 3 && p->args[i] && at < sizeof(words); ++i)
        at += (size_t)snprintf(words + at, sizeof(words) - at, "%s%s", i ? " " : "", p->args[i]);
#ifdef __ANDROID__
    __android_log_print(ANDROID_LOG_ERROR, "z23", "%s: no answer within %u ms, stopped pid %d", words, p->timeout_ms, (int)p->pid);
#else
    fprintf(stderr, "z23: %s: no answer within %u ms, stopped pid %d\n", words, p->timeout_ms, (int)p->pid);
#endif
}
/* Stops a command that did not answer in time: the child itself first, because one stuck between fork and exec has not made
 * its process group yet, then the group it made for anything it started. The child stays unreaped until here, so neither id
 * can name another process, and SIGKILL ends it even with every other signal blocked. */
static void pump_stop(struct pump *p, int *status)
{
    (void)kill(p->pid, SIGKILL);
    (void)kill(-p->pid, SIGKILL);
    while (waitpid(p->pid, status, 0) < 0 && errno == EINTR) {}
    if (!p->cancelled) command_note(p);
}
static void pump_finish(struct pump *p, char *out, size_t cap, bool ended, int *status)
{
    if (p->input >= 0) close(p->input);
    if (p->output >= 0) close(p->output);
    if (!ended) pump_stop(p, status);
    if (!ended && !p->cancelled) snprintf(out + p->used, cap - p->used, "\nThe command timed out.");
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
static bool pump_step(struct pump *p, char *out, size_t cap, bool *ended, int *status)
{
    struct pollfd fds[2] = {{p->output, POLLIN, 0}, {p->input, POLLOUT, 0}};
    if (poll(fds, 2, 50) < 0 && errno != EINTR) return false;
    if (p->output >= 0 && fds[0].revents) pump_output(p, out, cap);
    if (p->input >= 0 && fds[1].revents) pump_input(p);
    /* Do not reap while a descendant holds the pipe: the group id remains owned. */
    if (!*ended && p->output < 0) *ended = waitpid(p->pid, status, WNOHANG) == p->pid;
    return true;
}
static int pump_exit_code(const struct pump *p, bool ended, int status)
{
    return !p->cancelled && ended && WIFEXITED(status) &&
           !p->truncated && p->sent == p->length ? WEXITSTATUS(status) : -1;
}
static bool pump_command(struct pump *p, char *out, size_t cap)
{
    int status = 0; bool ended = false; int64_t start = milliseconds();
    int64_t now = start, end = start < 0 ? -1 : start + (int64_t)p->timeout_ms;
    while ((!ended || p->output >= 0) && now >= 0 && now < end) {
        if (p->cancel && atomic_load(p->cancel)) { p->cancelled = true; break; }
        if (!pump_step(p, out, cap, &ended, &status)) break;
        now = milliseconds();
    }
    if (p->cancel && atomic_load(p->cancel)) p->cancelled = true;
    pump_finish(p, out, cap, ended, &status);
    if (p->cancelled) memory_cleanse(out, cap);
    p->exit_code = pump_exit_code(p, ended, status);
    return !p->cancelled && pump_success(p, ended, status);
}

static bool command_pipes(int pipes[2], int stdin_pipe[2])
{
    if (pipe2(pipes, O_CLOEXEC | O_NONBLOCK) != 0) return false;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, stdin_pipe) != 0) {
        close(pipes[0]); close(pipes[1]); return false;
    }
    (void)fcntl(pipes[1], F_SETFL, 0); (void)fcntl(stdin_pipe[0], F_SETFL, 0);
    return true;
}
static void command_argv(struct zapp_runtime *r, const char *const *args, const char *input,
                         char *argv[12], char data[1100])
{
    snprintf(data, 1100, "-datadir=%s", r->directory);
    size_t n = 0; argv[n++] = r->executable;
    for (size_t i = 0; args[i] && n < 9; ++i) argv[n++] = (char *)args[i];
    argv[n++] = data;
    if (input) argv[n++] = "--input=-";
    argv[n] = NULL;
}
static bool command_spawn_error(int rc, const atomic_bool *cancel, bool *cancelled, char *out, size_t cap)
{
    if (cancel && atomic_load(cancel)) { if (cancelled) *cancelled = true; }
    else snprintf(out, cap, "Unable to run native Z23: %s", strerror(rc));
    return false;
}
static bool command_pump_result(struct pump *pump, char *out, size_t cap, bool *started, bool *cancelled, int *exit_code)
{
    if (started) *started = true;
    if (!pump->length) { close(pump->input); pump->input = -1; }
    bool ok = pump_command(pump, out, cap);
    if (cancelled) *cancelled = pump->cancelled;
    if (exit_code) *exit_code = pump->exit_code;
    return ok;
}

/* started is set when the process was spawned: a false return with started false means the command never ran. */
static void command_reset(bool *started, bool *cancelled, int *exit_code)
{
    if (exit_code) *exit_code = -1;
    if (cancelled) *cancelled = false;
    if (started) *started = false;
}
static bool command_run_cancel(struct zapp_runtime *r, const char *const *args, const char *input,
                               unsigned timeout_ms, char *out, size_t cap, bool *started,
                               const atomic_bool *cancel, bool *cancelled, int *exit_code)
{
    command_reset(started, cancelled, exit_code);
    if (!out || cap < 64) return false;
    out[0] = 0;
    if (cancel && atomic_load(cancel)) { if (cancelled) *cancelled = true; return false; }
    int pipes[2], stdin_pipe[2];
    if (!command_pipes(pipes, stdin_pipe)) return false;
    char data[1100]; char *argv[12]; command_argv(r, args, input, argv, data);
    struct pump pump = {.input = stdin_pipe[1], .output = pipes[0], .body = input ? input : "", .length = input ? strlen(input) : 0, .timeout_ms = timeout_ms, .args = args, .cancel = cancel};
    pthread_mutex_lock(&r->mutex);
    int rc = (cancel && atomic_load(cancel)) || r->stopping ? ECANCELED :
             spawn_redirect(r, argv, stdin_pipe[0], pipes[1], &pump.pid);
    pthread_mutex_unlock(&r->mutex);
    close(stdin_pipe[0]); close(pipes[1]);
    if (rc) { close(stdin_pipe[1]); close(pipes[0]); return command_spawn_error(rc, cancel, cancelled, out, cap); }
    return command_pump_result(&pump, out, cap, started, cancelled, exit_code);
}
static bool command_run(struct zapp_runtime *r, const char *const *args, const char *input,
                        unsigned timeout_ms, char *out, size_t cap, bool *started)
{ return command_run_cancel(r, args, input, timeout_ms, out, cap, started, NULL, NULL, NULL); }
static bool command_timed(struct zapp_runtime *r, const char *const *args, const char *input,
                          unsigned timeout_ms, char *out, size_t cap)
{
    return command_run(r, args, input, timeout_ms, out, cap, NULL);
}
static unsigned read_limit(const struct zapp_runtime *r)
{
    return r->read_ms ? r->read_ms : COMMAND_TIMEOUT_MS;
}
static bool command(struct zapp_runtime *r, const char *const *args, const char *input, char *out, size_t cap)
{
    return command_timed(r, args, input, read_limit(r), out, cap);
}

static void direct_note(const char *id, const char *why)
{
#ifdef __ANDROID__
    __android_log_print(ANDROID_LOG_WARN, "z23", "%s: node query failed, using the command line: %s", id, why);
#else
    fprintf(stderr, "z23: %s: node query failed, using the command line: %s\n", id, why);
#endif
}

/* Rewrites the node's JSON-RPC reply in out as the CLI replies: {"ok":true,"data":<result>}, where
 * data is the named member of the result when the operation has one. */
static bool direct_envelope(const struct operation *op, char *out, size_t cap)
{
    struct json_value reply = {0}, envelope = {0};
    bool ok = json_read(&reply, out, strlen(out));
    const struct json_value *error = json_get(&reply, "error");
    const struct json_value *data = json_get(&reply, "result");
    if (ok && op->member) data = json_get(data, op->member);
    const struct json_value *id = json_get(&reply, "id");
    ok = ok && id && id->type == JSON_INT && json_get_int(id) == 1 &&
         data && data->type == JSON_OBJ && (!error || json_is_null(error));
    if (ok) {
        json_set_object(&envelope);
        ok = json_push_kv_bool(&envelope, "ok", true) && json_push_kv(&envelope, "data", data) &&
             json_write(&envelope, out, cap) < cap;
    }
    json_free(&envelope);
    json_free(&reply);
    return ok;
}

/* Asks the running node over its local RPC port, which costs no process start. False leaves the
 * caller to run the CLI. A node that is not serving RPC is the normal stopped state and is not
 * logged; any other failure is logged once until a query succeeds again. */
static bool direct_query(struct zapp_runtime *r, const struct operation *op, char *out, size_t cap)
{
    pthread_mutex_lock(&r->mutex);
    bool stopping = r->stopping;
    pthread_mutex_unlock(&r->mutex);
    if (stopping) return false;
    char why[160] = "";
    enum zapp_rpc_result rc = zapp_rpc_call(r->directory, op->rpc, op->params, DIRECT_TIMEOUT_MS,
                                            out, cap, why, sizeof(why));
    if (rc == ZAPP_RPC_OK && !direct_envelope(op, out, cap)) {
        snprintf(why, sizeof(why), "the node reply has no usable %s", op->member ? op->member : "result");
        rc = ZAPP_RPC_FAILED;
    }
    if (rc == ZAPP_RPC_FAILED && !atomic_exchange(&r->direct_reported, true)) direct_note(op->id, why);
    if (rc != ZAPP_RPC_FAILED) atomic_store(&r->direct_reported, false);
    return rc == ZAPP_RPC_OK;
}

bool zapp_operation_run(struct zapp_runtime *r, const char *id, char *out, size_t cap)
{
    if (!r || !id || !out || !cap) return false;
    for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i) {
        if (strcmp(id, operations[i].id) != 0) continue;
        return direct_query(r, &operations[i], out, cap) ||
               command(r, operations[i].args, NULL, out, cap);
    }
    snprintf(out, cap, "This operation is not available in the phone's permission set.");
    return false;
}

/* The wallet commands the wallet screens run, by the id they ask with. None has a node RPC form, so
 * they go through the command line. A history page is chosen by cursor and a transaction by its id; the
 * argument is checked here as well, because it becomes a command-line argument. */
enum wallet_arg { ARG_NONE, ARG_CURSOR, ARG_TXID };
static const struct { const char *id; const char *args[5]; enum wallet_arg arg; } wallet_commands[] = {
    {"summary", {"core", "wallet", "summary"}, ARG_NONE},
    {"fleet", {"core", "wallet", "fleet", "status"}, ARG_NONE},
    {"latest", {"core", "wallet", "shielded", "latest"}, ARG_NONE},
    {"broadcast", {"core", "wallet", "broadcast", "status"}, ARG_NONE},
    {"receive", {"core", "wallet", "shielded", "receive"}, ARG_NONE},
    {"history", {"core", "wallet", "history"}, ARG_CURSOR},
    {"detail", {"core", "wallet", "history"}, ARG_TXID},
};

/* Adds the checked argument to the command line, or says why it is refused. */
static bool wallet_argument(enum wallet_arg kind, const char *arg, const char **args, size_t *n, char *value, size_t size, char *out, size_t cap)
{
    if (kind == ARG_CURSOR) {
        if (arg[0] && !wallet_cursor_valid(arg)) { snprintf(out, cap, "That is not a history cursor."); return false; }
        snprintf(value, size, "--limit=%u", WALLET_PAGE_ROWS);
        args[(*n)++] = value;
        if (arg[0]) {
            size_t at = strlen(value) + 1;
            snprintf(value + at, size - at, "--cursor=%s", arg);
            args[(*n)++] = value + at;
        }
    } else if (kind == ARG_TXID) {
        if (!wallet_txid_valid(arg)) { snprintf(out, cap, "That is not a transaction id."); return false; }
        snprintf(value, size, "--txid=%s", arg);
        args[(*n)++] = value;
    } else if (arg[0]) { snprintf(out, cap, "This wallet command takes no argument."); return false; }
    return true;
}

static bool preload_envelope_valid(const struct json_value *ok,
                                   const struct json_value *err, int exit_code)
{
    const char *code = err && err->type == JSON_OBJ ? json_get_str(json_get(err, "code")) : NULL;
    if (!ok || ok->type != JSON_BOOL) return false;
    if (json_get_bool(ok)) return exit_code == 0;
    return exit_code == 3 && code && !strcmp(code, "WALLET_LOCKED");
}
static const struct json_value *preload_address(const struct json_value *root,
                                                const struct json_value *ok, const struct json_value *err)
{
    const struct json_value *data = json_get(root, "data");
    const struct json_value *facts = err && err->type == JSON_OBJ ? json_get(err, "facts") : NULL;
    const struct json_value *source = ok && ok->type == JSON_BOOL && json_get_bool(ok) ? data : facts;
    return source && source->type == JSON_OBJ ? json_get(source, "persisted_shielded_address") : NULL;
}
static bool preload_reply_valid(const char *text, int exit_code)
{
    const char *json = zapp_json_object(text);
    struct json_value root = {0};
    bool valid = json && json_read(&root, json, strlen(json));
    const struct json_value *ok = valid ? json_get(&root, "ok") : NULL;
    const struct json_value *err = valid ? json_get(&root, "error") : NULL;
    const struct json_value *addr = valid ? preload_address(&root, ok, err) : NULL;
    valid = addr && addr->type == JSON_STR && json_get_str(addr) &&
            json_get_str(addr)[0] && preload_envelope_valid(ok, err, exit_code);
    json_free(&root);
    return valid;
}
static void node_preload(struct zapp_runtime *r, struct preload_result *result)
{
    static const char *const args[] = {"core", "wallet", "recovery", "status", NULL};
    char after[65], input[1200];
    if (!zapp_setup_preload_allowed() ||
        !zapp_setup_identity(r->files, result->identity)) return;
    struct json_value request = {0};
    json_set_object(&request);
    bool built = json_push_kv_str(&request, "datadir", r->directory);
    size_t n = built ? json_write(&request, input, sizeof(input)) : 0;
    json_free(&request);
    if (!n || n >= sizeof(input)) return;
    bool cancelled = false;
    int exit_code = -1;
    result->command_ok = command_run_cancel(r, args, input, r->preload_ms ? r->preload_ms : 2000,
        result->reply, sizeof(result->reply), NULL, &r->start_cancel, &cancelled, &exit_code);
    result->valid = !cancelled && preload_reply_valid(result->reply, exit_code) &&
        zapp_setup_preload_allowed() && zapp_setup_identity(r->files, after) &&
        !strcmp(result->identity, after) && zapp_setup_preload_allowed();
}

/* Read only while the app is not starting its node. */
static bool wallet_offline_address(struct zapp_runtime *r, char *out, size_t cap)
{
    static const char *const args[] = {"core", "wallet", "recovery", "status", NULL};
    char before[65], after[65], input[1200];
    struct json_value request = {0};
    if (r->preview || !zapp_setup_identity(r->files, before) || atomic_exchange(&r->setup_running, true)) return false;
    bool ready = !zapp_node_running(r);
    json_set_object(&request);
    bool built = ready && json_push_kv_str(&request, "datadir", r->directory);
    size_t n = built ? json_write(&request, input, sizeof(input)) : 0;
    json_free(&request);
    int exit_code = -1;
    bool ran = n && n < sizeof(input) && command_run_cancel(r, args, input, read_limit(r), out, cap, NULL, NULL, NULL, &exit_code);
    if (exit_code != 0 && exit_code != 3) out[0] = 0;
    bool same = !zapp_node_running(r) && zapp_setup_identity(r->files, after) && !strcmp(before, after);
    atomic_store(&r->setup_running, false);
    if (!same) { out[0] = 0; return false; }
    return ran;
}

bool zapp_wallet_run(struct zapp_runtime *r, const char *op, const char *arg, char *out, size_t cap)
{
    if (!r || !op || !arg || !out || cap < 64) return false;
    if (!strcmp(op, "offline_address")) return !arg[0] && wallet_offline_address(r, out, cap);
    for (size_t i = 0; i < sizeof(wallet_commands) / sizeof(wallet_commands[0]); ++i) {
        const char *args[8] = {0};
        char value[WALLET_CURSOR_MAX + 48];
        size_t n = 0;
        if (strcmp(op, wallet_commands[i].id) != 0) continue;
        if (r->preview) { snprintf(out, cap, "The preview app has no wallet."); return false; }
        /* An address is shown only once the owner has proved they hold the recovery words. */
        if (!strcmp(op, "receive") && zapp_setup_state(r->files) != ZAPP_SETUP_READY) {
            snprintf(out, cap, "Finish wallet setup first: no address is shown until the recovery words are confirmed.");
            return false;
        }
        for (size_t a = 0; wallet_commands[i].args[a]; ++a) args[n++] = wallet_commands[i].args[a];
        if (!wallet_argument(wallet_commands[i].arg, arg, args, &n, value, sizeof(value), out, cap)) return false;
        return command(r, args, NULL, out, cap);
    }
    snprintf(out, cap, "This wallet command is not available in the phone's permission set.");
    return false;
}

/* The node RPC validateaddress over loopback: the address goes in the request body, never on a command line. */
static bool validate_address_run(struct zapp_runtime *r, const char *params, char *out, size_t cap)
{
    char why[160] = "";
    if (r->preview) { snprintf(out, cap, "The preview app has no wallet."); return false; }
    bool ok = zapp_rpc_call(r->directory, "validateaddress", params, DIRECT_TIMEOUT_MS, out, cap, why, sizeof(why)) == ZAPP_RPC_OK;
    if (!ok) snprintf(out, cap, "%s", why[0] ? why : "The node did not answer.");
    return ok;
}

/* The wallet commands of a send, by the id the send adapter asks with. Their arguments are never on the
 * command line: the payment, the plan token, the idempotency key and the passphrase go on standard input. */
struct send_command { const char *id; const char *args[5]; bool input; };
static const struct send_command send_commands[] = {
    {"unlock", {"core", "wallet", "security", "unlock"}, true},
    {"lock", {"core", "wallet", "security", "lock"}, false},
    {"plan", {"core", "wallet", "shielded", "send"}, true},
    {"commit", {"core", "wallet", "shielded", "send"}, true},
    {"shieldplan", {"core", "wallet", "shielded", "shield"}, true},
    {"shieldcommit", {"core", "wallet", "shielded", "shield"}, true},
};
static const struct send_command *send_command_of(const char *op)
{
    for (size_t i = 0; i < sizeof(send_commands) / sizeof(send_commands[0]); ++i)
        if (!strcmp(op, send_commands[i].id)) return &send_commands[i];
    return NULL;
}

static bool send_args_valid(const struct send_command *c, const char *input, unsigned timeout_ms)
{
    return c->input == (input != NULL) && timeout_ms && timeout_ms <= ZAPP_WALLET_SEND_TIMEOUT_MAX_MS;
}
/* A commit builds a proof, about 100 seconds on a phone: no caller may cut it shorter than the floor. */
static unsigned send_timeout(const char *op, unsigned timeout_ms)
{
    bool commit = !strcmp(op, "commit") || !strcmp(op, "shieldcommit");
    return commit && timeout_ms < ZAPP_WALLET_COMMIT_MIN_MS ? ZAPP_WALLET_COMMIT_MIN_MS : timeout_ms;
}
bool zapp_wallet_send_run(struct zapp_runtime *r, const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap)
{
    if (!r || !op || !out || cap < 64) return false;
    if (!strcmp(op, "summary") || !strcmp(op, "fleet") || !strcmp(op, "latest") || !strcmp(op, "broadcast")) return !input && zapp_wallet_run(r, op, "", out, cap);
    if (!strcmp(op, "validateaddress")) return input && validate_address_run(r, input, out, cap);
    const struct send_command *c = send_command_of(op);
    if (!c) { snprintf(out, cap, "This wallet command is not available in the phone's permission set."); return false; }
    if (r->preview) { snprintf(out, cap, "The preview app has no wallet."); return false; }
    if (!send_args_valid(c, input, timeout_ms)) {
        snprintf(out, cap, "This wallet command was given arguments it does not take.");
        return false;
    }
    return command_timed(r, c->args, input, send_timeout(op, timeout_ms), out, cap);
}

/* The wallet setup commands, by the id the setup adapter asks with. The datadir, the passphrase and the words are in the
 * request on standard input, never in arguments. */
/* stateless: needs no datadir and no stopped node, so it runs while a node does. */
static const struct { const char *id; const char *args[5]; bool stateless; } setup_commands[] = {
    {"create", {"core", "wallet", "create"}, false},
    {"restore", {"core", "wallet", "recovery", "restore"}, false},
    {"newphrase", {"core", "wallet", "recovery", "new"}, true},
};
static bool setup_rpc(struct zapp_runtime *r, const char *method, const char *params, char *out, size_t cap)
{
    char why[160] = "";
    bool ok = zapp_rpc_call(r->directory, method, params, DIRECT_TIMEOUT_MS, out, cap, why, sizeof(why)) == ZAPP_RPC_OK;
    if (!ok) snprintf(out, cap, "%s", why[0] ? why : "The node did not answer.");
    return ok;
}
/* A refusal that ran nothing, in the node's own reply shape, so the app can tell it from a command that may have written. */
static bool setup_not_run(char *out, size_t cap, const char *message)
{
    snprintf(out, cap, "{\"ok\":false,\"error\":{\"code\":\"NOT_RUN\",\"message\":\"%s\"}}", message);
    return false;
}
/* The command runs only while no node holds the datadir; the flag is raised first, so a node that starts at the same
 * moment is either seen here or refused by zapp_node_start. */
static bool setup_command(struct zapp_runtime *r, const char *const *args, const char *input, unsigned timeout_ms, char *out, size_t cap)
{
    bool started = false, ok = false;
    if (atomic_exchange(&r->setup_running, true)) return setup_not_run(out, cap, "Wallet setup is already running.");
    if (zapp_node_running(r)) setup_not_run(out, cap, "Stop the node first: setup changes the wallet files the node holds.");
    else {
        ok = command_run(r, args, input, timeout_ms, out, cap, &started);
        if (!ok && !started) setup_not_run(out, cap, "The wallet command could not be started.");
    }
    atomic_store(&r->setup_running, false);
    return ok;
}
/* A command that touches no wallet files: it runs beside a node and takes no part in the flag that keeps a node from starting. */
static bool setup_stateless(struct zapp_runtime *r, const char *const *args, const char *input, unsigned timeout_ms, char *out, size_t cap)
{
    bool started = false;
    bool ok = command_run(r, args, input, timeout_ms, out, cap, &started);
    if (!ok && !started) setup_not_run(out, cap, "The wallet command could not be started.");
    return ok;
}
/* Whether the datadir holds a wallet, read-only, with or without a node. */
static bool setup_status(struct zapp_runtime *r, const char *input, char *out, size_t cap)
{
    static const char *const args[] = {"core", "wallet", "recovery", "status", NULL};
    return command_timed(r, args, input, read_limit(r), out, cap);
}
bool zapp_wallet_setup_run(struct zapp_runtime *r, const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap)
{
    if (!r || !op || !input || !out || cap < 64) return false;
    if (r->preview) return setup_not_run(out, cap, "The preview app has no wallet.");
    if (!strcmp(op, "blockhash")) return setup_rpc(r, "getblockhash", input, out, cap);
    if (!strcmp(op, "chaininfo")) return setup_rpc(r, "getblockchaininfo", input, out, cap);
    if (!strcmp(op, "status")) return setup_status(r, input, out, cap);
    for (size_t i = 0; i < sizeof(setup_commands) / sizeof(setup_commands[0]); ++i) {
        if (strcmp(op, setup_commands[i].id) != 0) continue;
        if (!timeout_ms || timeout_ms > ZAPP_WALLET_SETUP_TIMEOUT_MAX_MS)
            return setup_not_run(out, cap, "This wallet command was given arguments it does not take.");
        if (setup_commands[i].stateless) return setup_stateless(r, setup_commands[i].args, input, timeout_ms, out, cap);
        return setup_command(r, setup_commands[i].args, input, timeout_ms, out, cap);
    }
    return setup_not_run(out, cap, "This wallet command is not available in the phone's permission set.");
}

static bool fleet_token_run(struct zapp_runtime *r, const char *token, char *out, size_t cap)
{
    if (!r || !token || !out || cap < 64) return false;
    struct json_value input = {0}; json_set_object(&input);
    bool ok = json_push_kv_str(&input, "token", token);
    char wire[16384]; size_t n = ok ? json_write(&input, wire, sizeof(wire)) : sizeof(wire);
    json_free(&input);
    const char *args[] = {"fleet", "join", NULL};
    ok = n < sizeof(wire) && command_timed(r, args, wire, COMMAND_TIMEOUT_MS, out, cap);
    memory_cleanse(wire, sizeof(wire));
    return ok;
}

bool zapp_fleet_join_run(struct zapp_runtime *r, const char *token, char *out, size_t cap)
{ return fleet_token_run(r, token, out, cap); }
bool zapp_fleet_preview_run(struct zapp_runtime *r, const char *token, char *out, size_t cap)
{ return zapp_fleet_preview_cancelable(r, token, out, cap, NULL) == ZAPP_PREVIEW_OK; }

/* Cancellation is observed before spawn and while pumping; posix_spawn itself is synchronous. */
static enum zapp_preview_result preview_cancelable(struct zapp_runtime *r, const char *field,
                                                    const char *value, char *out, size_t cap,
                                                    const atomic_bool *cancel)
{
    if (!r || !value || !out || cap < 64) return ZAPP_PREVIEW_FAILED;
    out[0] = 0;
    if (cancel && atomic_load(cancel)) { out[0] = 0; return ZAPP_PREVIEW_CANCELLED; }
    struct json_value input = {0}; json_set_object(&input);
    bool ok = json_push_kv_str(&input, field, value);
    char wire[16384]; size_t n = ok ? json_write(&input, wire, sizeof(wire)) : sizeof(wire);
    json_free(&input);
    const char *args[] = {"fleet", "preview", NULL};
    bool cancelled = false;
    ok = n < sizeof(wire) && command_run_cancel(r, args, wire, 5000u, out, cap, NULL, cancel, &cancelled, NULL);
    memory_cleanse(wire, sizeof(wire));
    if (cancel && atomic_load(cancel)) cancelled = true;
    if (cancelled) { memory_cleanse(out, cap); return ZAPP_PREVIEW_CANCELLED; }
    return ok ? ZAPP_PREVIEW_OK : ZAPP_PREVIEW_FAILED;
}
enum zapp_preview_result zapp_fleet_preview_cancelable(struct zapp_runtime *r, const char *token,
                                                        char *out, size_t cap, const atomic_bool *cancel)
{ return preview_cancelable(r, "token", token, out, cap, cancel); }
enum zapp_preview_result zapp_fleet_machine_preview_cancelable(struct zapp_runtime *r, const char *line,
                                                                char *out, size_t cap, const atomic_bool *cancel)
{ return preview_cancelable(r, "line", line, out, cap, cancel); }

/* The node writes tor_data/onion_service/hostname once Tor has published its hidden service. */
static void onion_error(const char *step, const char *file)
{
#ifdef __ANDROID__
    __android_log_print(ANDROID_LOG_ERROR, "z23", "onion address: %s %s failed: %s", step, file, strerror(errno));
#else
    fprintf(stderr, "z23: onion address: %s %s failed: %s\n", step, file, strerror(errno));
#endif
}
/* Same closed grammar as onion_hostname_valid in core: 56 characters of a-z2-7, then ".onion". apps
 * link neither core nor engine, so the predicate is restated here. */
static bool onion_hostname_valid(const char *text, size_t length)
{
    if (length != 62 || memcmp(text + 56, ".onion", 6) != 0) return false;
    for (size_t i = 0; i < 56; ++i)
        if (!((text[i] >= 'a' && text[i] <= 'z') || (text[i] >= '2' && text[i] <= '7'))) return false;
    return true;
}
bool zapp_onion_ready(const struct zapp_runtime *r)
{
    char file[1200], text[128];
    if (!r || snprintf(file, sizeof(file), "%s/tor_data/onion_service/hostname", r->directory) >= (int)sizeof(file))
        return false;
    int fd = open(file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { if (errno != ENOENT) onion_error("open", file); return false; }
    ssize_t n = read(fd, text, sizeof(text));
    if (n < 0) onion_error("read", file);
    close(fd);
    if (n > 0 && text[n - 1] == '\n') --n;
    return n > 0 && onion_hostname_valid(text, (size_t)n);
}
bool zapp_node_serving(const struct zapp_runtime *r)
{
    char file[1200], text[ZAPP_BOOT_STATUS_MAX + 1];
    struct json_value doc = {0};
    if (!r || snprintf(file, sizeof(file), "%s/boot_status.json", r->directory) >= (int)sizeof(file)) return false;
    int fd = open(file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t n = read(fd, text, sizeof(text));
    close(fd);
    if (n <= 0 || n > ZAPP_BOOT_STATUS_MAX || !json_read(&doc, text, (size_t)n)) return false;
    const struct json_value *schema = json_get(&doc, "schema"), *serving = json_get(&doc, "serving");
    bool ok = schema && schema->type == JSON_STR && !strcmp(schema->val.s, "zcl.boot_status.v1") && serving &&
              serving->type == JSON_BOOL && json_get_bool(serving);
    json_free(&doc);
    return ok;
}
enum zapp_onion zapp_onion_wait(struct zapp_runtime *r, unsigned seconds, void (*waiting)(void *), void *arg)
{
    if (!zapp_node_running(r)) return ZAPP_ONION_NODE_STOPPED;
    for (unsigned i = 0; i <= seconds; ++i) {
        if (zapp_onion_ready(r)) return ZAPP_ONION_READY;
        if (i == 0 && waiting) waiting(arg);
        if (i == seconds) break;
        struct timespec second = {.tv_sec = 1};
        while (nanosleep(&second, &second) != 0 && errno == EINTR) {}
        if (!zapp_node_running(r)) return ZAPP_ONION_NODE_STOPPED;
    }
    return ZAPP_ONION_TIMEOUT;
}

const char *zapp_json_object(const char *text)
{
    const char *json = !text ? NULL : text[0] == '{' ? text : strstr(text, "\n{");
    return json && json[0] == '\n' ? json + 1 : json;
}

static bool fleet_preview_identity(const char *name, const char *key)
{
    return name && key && strlen(name) >= 2 && strlen(name) <= 24 &&
        strspn(name, "abcdefghijklmnopqrstuvwxyz0123456789-") == strlen(name) &&
        strlen(key) == 64 && strspn(key, "0123456789abcdef") == 64;
}

bool zapp_fleet_preview_text(const char *text, char *out, size_t cap)
{
    const char *json = zapp_json_object(text);
    if (!json || !out || !cap) return false;
    struct json_value root = {0};
    bool ok = json_read(&root, json, strlen(json));
    const struct json_value *data = json_get(&root, "data");
    const char *schema = json_get_str(json_get(data, "schema"));
    const char *name = json_get_str(json_get(data, "name"));
    const char *key = json_get_str(json_get(data, "operator_pubkey"));
    ok = ok && json_get_bool(json_get(&root, "ok")) && schema &&
        !strcmp(schema, "zcl.fleet.invite_preview.v1") && fleet_preview_identity(name, key);
    if (ok) {
        int n = snprintf(out, cap, "Phone name: %s\nManager key:\n%.16s %.16s\n%.16s %.16s\n"
                         "Check that this key matches your fleet manager before joining.",
                         name, key, key + 16, key + 32, key + 48);
        ok = n >= 0 && (size_t)n < cap;
    }
    json_free(&root);
    return ok;
}

static bool fleet_line_command(struct zapp_runtime *r, const char *value, char *out, size_t cap)
{
    struct json_value input = {0}; json_set_object(&input);
    bool ok = json_push_kv_str(&input, "line", value);
    char wire[16384]; size_t n = ok ? json_write(&input, wire, sizeof(wire)) : sizeof(wire);
    json_free(&input);
    const char *args[] = {"fleet", "import", NULL};
    ok = n < sizeof(wire) && command_timed(r, args, wire, COMMAND_TIMEOUT_MS, out, cap);
    memory_cleanse(wire, sizeof(wire));
    return ok;
}
bool zapp_fleet_machine_preview_run(struct zapp_runtime *r, const char *line, char *out, size_t cap)
{ return zapp_fleet_machine_preview_cancelable(r, line, out, cap, NULL) == ZAPP_PREVIEW_OK; }

static bool fleet_onion_valid(const char *host)
{
    if (!host) return false;
    size_t n = strlen(host);
    if (n == 62 && !memcmp(host + 56, ".onion", 6)) {
        for (size_t i = 0; i < 56; ++i)
            if (!((host[i] >= 97 && host[i] <= 122) || (host[i] >= 50 && host[i] <= 55))) return false;
        return true;
    }
    return zapp_onion_peer_valid(host);
}

static bool fleet_reply_ok(const char *text, const char *schema)
{
    const char *json = zapp_json_object(text);
    struct json_value root = {0};
    bool ok = json && json_read(&root, json, strlen(json));
    const struct json_value *data = json_get(&root, "data");
    const char *s = json_get_str(json_get(data, "schema"));
    ok = ok && json_get_bool(json_get(&root, "ok")) && s && !strcmp(s, schema);
    json_free(&root); return ok;
}

static bool fleet_machine_metadata(const struct json_value *data)
{
    const char *box = json_get_str(json_get(data, "box_pubkey"));
    const struct json_value *port = json_get(data, "relay_port"), *enrolled = json_get(data, "enrolled_at");
    return box && strlen(box) == 64 && strspn(box, "0123456789abcdef") == 64 &&
        port && port->type == JSON_INT && json_get_int(port) > 0 && json_get_int(port) <= 65535 &&
        enrolled && enrolled->type == JSON_INT && json_get_int(enrolled) > 0;
}
static bool fleet_machine_identity(const struct json_value *root, const struct json_value *data)
{
    const char *schema = json_get_str(json_get(data, "schema")), *kind = json_get_str(json_get(data, "kind"));
    const char *name = json_get_str(json_get(data, "name")), *key = json_get_str(json_get(data, "operator_pubkey"));
    return json_get_bool(json_get(root, "ok")) && schema && !strcmp(schema, "zcl.fleet.preview.v1") &&
        kind && !strcmp(kind, "machine") && fleet_preview_identity(name, key);
}
bool zapp_fleet_machine_preview_text(const char *text, char *out, size_t cap, char *onion, size_t onion_cap)
{
    const char *json = zapp_json_object(text);
    if (!json || !out || !cap || !onion || !onion_cap) return false;
    struct json_value root = {0};
    bool ok = json_read(&root, json, strlen(json));
    const struct json_value *data = json_get(&root, "data");
    const char *name = json_get_str(json_get(data, "name"));
    const char *key = json_get_str(json_get(data, "operator_pubkey"));
    const char *host = json_get_str(json_get(data, "onion"));
    ok = ok && fleet_machine_identity(&root, data) && fleet_machine_metadata(data) &&
        host && fleet_onion_valid(host) && strlen(host) < onion_cap;
    if (ok) {
        int n = snprintf(out, cap, "Fleet computer: %s\nManager key:\n%.16s %.16s\n%.16s %.16s\nCheck this key with your manager before connecting.", name, key, key + 16, key + 32, key + 48);
        ok = n >= 0 && (size_t)n < cap;
        if (ok) memcpy(onion, host, strlen(host) + 1);
    }
    json_free(&root); return ok;
}

static bool fleet_import_partial(const char *text)
{
    const char *json = zapp_json_object(text);
    struct json_value root = {0};
    bool ok = json && json_read(&root, json, strlen(json));
    const char *code = json_get_str(json_get(json_get(&root, "error"), "code"));
    ok = ok && code && !strcmp(code, "FLEET_IMPORT_PARTIAL");
    json_free(&root); return ok;
}

bool zapp_fleet_connect_run(struct zapp_runtime *r, const char *line, const char *onion, char *out, size_t cap)
{
    if (!r || !line || !onion || !fleet_onion_valid(onion) || !out || cap < 64) return false;
    if (!fleet_line_command(r, line, out, cap) || !fleet_reply_ok(out, "zcl.fleet.import.v1")) {
        bool partial = fleet_import_partial(out);
        snprintf(out, cap, "%s", partial ? "Import changed some fleet state before failing. Ask your manager to check it before retrying." :
                 "Could not confirm the import. Fleet state may have changed; ask your manager to check it before retrying.");
        return false;
    }
    struct json_value input = {0}; json_set_object(&input);
    bool ok = json_push_kv_str(&input, "address", onion);
    char wire[512]; size_t n = ok ? json_write(&input, wire, sizeof(wire)) : sizeof(wire);
    json_free(&input);
    const char *args[] = {"core", "network", "peers", "add", NULL};
    ok = n < sizeof(wire) && command_timed(r, args, wire, COMMAND_TIMEOUT_MS, out, cap) && fleet_reply_ok(out, "zcl.peer_add.v1");
    memory_cleanse(wire, sizeof(wire));
    snprintf(out, cap, "%s", ok ? "Fleet computer saved. Connecting…" :
             "The computer was imported, but connection could not be scheduled. Try Connect again.");
    return ok;
}
bool zapp_fleet_join_receipt(const char *text, char *receipt, size_t cap)
{
    const char *json = zapp_json_object(text);
    if (!json || !receipt || !cap) return false;
    struct json_value root = {0};
    bool ok = json_read(&root, json, strlen(json));
    const struct json_value *data = json_get(&root, "data");
    const char *schema = json_get_str(json_get(data, "schema"));
    const char *value = json_get_str(json_get(data, "receipt"));
    ok = ok && json_get_bool(json_get(&root, "ok")) && schema &&
        !strcmp(schema, "zcl.fleet.join.v1") && value && value[0];
    size_t length = ok ? strlen(value) : 0;
    ok = ok && length >= 128 && length < cap && length <= 2332 &&
        strspn(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == length;
    if (ok) memcpy(receipt, value, length + 1);
    json_free(&root);
    return ok;
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
