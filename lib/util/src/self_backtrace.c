/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Live self-backtrace surface. See self_backtrace.h for the contract and the
 * rationale (perf/ptrace are blocked on hardened hosts). The SIGRTMIN+2
 * handler is strictly async-signal-safe: it only calls backtrace(),
 * backtrace_symbols_fd(), write(2) (via util/async_safe_write.h), and
 * sem_post() — all documented async-signal-safe. No malloc, stdio, or locks
 * run inside the handler. */

#define _GNU_SOURCE

#include "util/self_backtrace.h"
#include "util/async_safe_write.h"
#include "util/thread_registry.h"
#include "util/util.h"       /* GetDataDir */
#include "util/log_macros.h"
#include "json/json.h"

#if defined(_WIN32)
#include "platform/private_file.h"
#include "platform/time_compat.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static _Atomic bool g_installed;
static _Atomic long g_dump_count;
static _Atomic long g_last_unix_ts;
static _Atomic int g_last_thread_count;
static atomic_flag g_dump_in_progress = ATOMIC_FLAG_INIT;
static SRWLOCK g_last_lock = SRWLOCK_INIT;
static char g_last_path[4300];

bool self_backtrace_install(void)
{
    atomic_store_explicit(&g_installed, true, memory_order_release);
    return true;
}

int self_backtrace_dump_all(char *path_out, size_t cap)
{
    if (path_out && cap) path_out[0] = '\0';
    if (!atomic_load_explicit(&g_installed, memory_order_acquire))
        return -1;
    if (atomic_flag_test_and_set_explicit(&g_dump_in_progress,
                                          memory_order_acquire))
        return -2;

    char datadir[4096];
    GetDataDir(false, datadir, sizeof(datadir));
    if (!datadir[0]) {
        atomic_flag_clear_explicit(&g_dump_in_progress, memory_order_release);
        return -1;
    }

    char path[4300] = "", parent[4096] = "";
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool created = false;
    int64_t now = platform_time_wall_unix();
    for (unsigned attempt = 0; attempt < 1000 && !created; attempt++) {
        char candidate[4300];
        int written = snprintf(candidate, sizeof(candidate),
                               "%s/backtrace-%lld-%u.log", datadir,
                               (long long)now, attempt);
        created = written > 0 && (size_t)written < sizeof(candidate) &&
                  platform_private_path_resolve(candidate, path, sizeof(path),
                                                parent, sizeof(parent)) &&
                  platform_private_file_create(path, &file);
    }
    if (!created) {
        atomic_flag_clear_explicit(&g_dump_in_progress, memory_order_release);
        return -1;
    }

    void *frames[64];
    USHORT count = CaptureStackBackTrace(0, 64, frames, NULL);
    char report[4096];
    int used = snprintf(report, sizeof(report),
                        "=== self-backtrace ts=%lld pid=%lu tid=%lu ===\n"
                        "[current-thread-only: cross-thread suspension refused]\n",
                        (long long)now, (unsigned long)GetCurrentProcessId(),
                        (unsigned long)GetCurrentThreadId());
    for (USHORT i = 0; used > 0 && (size_t)used < sizeof(report) && i < count;
         i++) {
        int n = snprintf(report + used, sizeof(report) - (size_t)used,
                         "#%u %p\n", (unsigned)i, frames[i]);
        if (n < 0 || (size_t)n >= sizeof(report) - (size_t)used) break;
        used += n;
    }
    bool ok = used > 0 && platform_private_file_write_at(
                              &file, report, (size_t)used, 0) &&
              platform_private_file_truncate(&file, (uint64_t)used) &&
              platform_private_file_flush(&file);
    platform_private_file_close(&file);
    if (ok)
        ok = platform_private_parent_flush(parent);
    if (!ok) {
        (void)platform_private_file_unlink_missing_ok(path);
        atomic_flag_clear_explicit(&g_dump_in_progress, memory_order_release);
        return -1;
    }

    AcquireSRWLockExclusive(&g_last_lock);
    snprintf(g_last_path, sizeof(g_last_path), "%s", path);
    ReleaseSRWLockExclusive(&g_last_lock);
    atomic_store_explicit(&g_last_thread_count, 1, memory_order_release);
    atomic_store_explicit(&g_last_unix_ts, (long)now, memory_order_release);
    atomic_fetch_add_explicit(&g_dump_count, 1, memory_order_relaxed);
    atomic_flag_clear_explicit(&g_dump_in_progress, memory_order_release);
    if (path_out && cap) snprintf(path_out, cap, "%s", path);
    return 1;
}

bool self_backtrace_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);
    json_push_kv_bool(out, "installed",
                      atomic_load_explicit(&g_installed, memory_order_acquire));
    json_push_kv_int(out, "dump_count", atomic_load(&g_dump_count));
    json_push_kv_int(out, "last_thread_count",
                     atomic_load(&g_last_thread_count));
    json_push_kv_int(out, "last_unix_ts", atomic_load(&g_last_unix_ts));
    char path[4300];
    AcquireSRWLockShared(&g_last_lock);
    snprintf(path, sizeof(path), "%s", g_last_path);
    ReleaseSRWLockShared(&g_last_lock);
    json_push_kv_str(out, "last_path", path);
    json_push_kv_str(out, "scope", "current_thread_only");
    return true;
}

#else
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

/* The realtime signal the dump orchestrator raises on each target thread.
 * SIGRTMIN is a glibc runtime value, so it can't be a static initializer or a
 * switch label — compute it at use. Offset +2 to sit clear of libraries that
 * grab SIGRTMIN / SIGRTMIN+1 (e.g. some timer/thread-cancel implementations). */
static int self_bt_signo(void) { return SIGRTMIN + 2; }

/* Shared handoff to the signal handler. The dump is serialized one thread at a
 * time, so a single static slot suffices. `fd` and `name` are published with
 * release/consumed with acquire so the handler observes the orchestrator's
 * stores across the signal boundary. */
static struct {
    _Atomic int          fd;      /* target log fd, or -1 when idle */
    _Atomic(const char *) name;   /* registered name of the current target */
    _Atomic(pthread_t)   target;  /* pthread_t of the thread being probed now */
    sem_t                done;    /* posted by the handler when it finishes */
} g_bt;

static _Atomic bool g_installed = false;

/* Single-flight guard: the shared g_bt slot + `done` semaphore can serve only
 * one dump at a time. A second concurrent operator invocation is rejected
 * rather than allowed to clobber the first dump's fd/name/target/semaphore. */
static atomic_flag g_dump_in_progress = ATOMIC_FLAG_INIT;

/* Last-dump introspection (dumpstate). Ints are atomic; the path string is
 * guarded by a brief mutex — never touched from the signal handler. */
static pthread_mutex_t  g_last_mu = PTHREAD_MUTEX_INITIALIZER;
static char             g_last_path[4300] = {0};
static _Atomic int      g_last_thread_count = 0;
static _Atomic long     g_last_unix_ts = 0;
static _Atomic long     g_dump_count = 0;

/* ── The async-signal-safe handler ─────────────────────────────────── */
static void self_bt_handler(int sig)
{
    (void)sig;
    /* This handler runs in LIVE threads that keep executing after it returns,
     * and it calls errno-clobbering functions (write, backtrace, syscall,
     * sem_post). Snapshot errno on entry and restore it on every return so the
     * interrupted thread's errno survives the probe. */
    int saved_errno = errno;

    int fd = atomic_load_explicit(&g_bt.fd, memory_order_acquire);
    pthread_t want = atomic_load_explicit(&g_bt.target, memory_order_acquire);

    /* Identity gate: only the thread the orchestrator is CURRENTLY probing may
     * write to the shared fd and post the semaphore. A thread whose 100 ms
     * budget already expired can wake here late — during a *later* target's
     * window — and, without this gate, would splice its backtrace into the fd
     * mislabeled as the later target and consume that target's semaphore slot.
     * A stale waker fails pthread_equal and no-ops entirely. pthread_self /
     * pthread_equal are async-signal-safe. */
    if (fd >= 0 && pthread_equal(pthread_self(), want)) {
        const char *name = atomic_load_explicit(&g_bt.name, memory_order_acquire);
        asw_write_str(fd, "[tid=");
        asw_write_uint(fd, (unsigned long)syscall(SYS_gettid));
        asw_write_str(fd, "] ");
        asw_write_str(fd, name ? name : "?");
        asw_write_str(fd, "\n");
        void *frames[64];
        int n = backtrace(frames, 64);
        backtrace_symbols_fd(frames, n, fd);
        asw_write_str(fd, "\n");
        /* Post only for the matched target so the orchestrator's wait pairs
         * with exactly this response; a post that races just past the wait's
         * timeout is discarded by the next iteration's drain. sem_post is
         * async-signal-safe. */
        sem_post(&g_bt.done);
    }

    errno = saved_errno;
}

bool self_backtrace_install(void)
{
    if (atomic_load_explicit(&g_installed, memory_order_acquire))
        return true;

    if (sem_init(&g_bt.done, 0, 0) != 0)
        LOG_FAIL("self_backtrace", "sem_init failed: %s", strerror(errno));
    atomic_store_explicit(&g_bt.fd, -1, memory_order_release);
    atomic_store_explicit(&g_bt.name, NULL, memory_order_release);
    atomic_store_explicit(&g_bt.target, (pthread_t)0, memory_order_release);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = self_bt_handler;
    /* SA_RESTART: a target thread's interrupted syscall resumes after the
     * handler, so probing it is minimally disruptive. */
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(self_bt_signo(), &sa, NULL) != 0)
        LOG_FAIL("self_backtrace", "sigaction(SIGRTMIN+2) failed: %s",
                 strerror(errno));

    /* Warm up backtrace() once so its first in-handler call cannot dlopen
     * libgcc from signal context (glibc loads the unwinder lazily). */
    void *warm[4];
    (void)backtrace(warm, 4);

    atomic_store_explicit(&g_installed, true, memory_order_release);
    return true;
}

/* Drain any stale posts left by a previously timed-out (late-waking) target so
 * the next wait only observes the current target's post. */
static void self_bt_drain(void)
{
    while (sem_trywait(&g_bt.done) == 0) { /* discard */ }
}

/* Open <datadir>/backtrace-<ts>.log with O_EXCL, retrying with a -<k> suffix
 * so two dumps in the same second still land in distinct files. Writes the
 * chosen path into path_out. Returns the fd or -1. */
static int self_bt_open_log(char *path_out, size_t cap)
{
    char datadir[4096];
    GetDataDir(false, datadir, sizeof(datadir));
    if (!datadir[0])
        return -1;

    long ts = (long)time(NULL);  // platform-ok:log-filename timestamp, no platform.clock in this diagnostic path
    for (int k = 0; k < 1000; k++) {
        char path[4300];
        if (k == 0)
            snprintf(path, sizeof(path), "%s/backtrace-%ld.log", datadir, ts);
        else
            snprintf(path, sizeof(path), "%s/backtrace-%ld-%d.log",
                     datadir, ts, k);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC,
                      0600);
        if (fd >= 0) {
            if (path_out && cap) snprintf(path_out, cap, "%s", path);
            return fd;
        }
        if (errno != EEXIST)
            return -1;
    }
    return -1;
}

int self_backtrace_dump_all(char *path_out, size_t cap)
{
    if (!atomic_load_explicit(&g_installed, memory_order_acquire))
        LOG_ERR("self_backtrace", "handler not installed; call "
                "self_backtrace_install() at boot first");

    /* Reject a concurrent invocation instead of clobbering the in-flight dump's
     * shared slot/semaphore. Distinct return (-2) so the caller can tell "busy"
     * apart from "failed". */
    if (atomic_flag_test_and_set_explicit(&g_dump_in_progress,
                                          memory_order_acquire))
        LOG_RETURN(-2, "self_backtrace",
                   "backtrace already in progress; declining concurrent dump");

    char path[4300] = {0};
    int fd = self_bt_open_log(path, sizeof(path));
    if (fd < 0) {
        atomic_flag_clear_explicit(&g_dump_in_progress, memory_order_release);
        LOG_ERR("self_backtrace", "could not open backtrace log: %s",
                strerror(errno));
    }

    /* Preamble. */
    asw_write_str(fd, "=== self-backtrace ts=");
    asw_write_uint(fd, (unsigned long)time(NULL));  // platform-ok:async-signal-safe path shares the crash-handler's raw time()
    asw_write_str(fd, " pid=");
    asw_write_uint(fd, (unsigned long)getpid());
    asw_write_str(fd, " ===\n\n");

    int count = 0;

    /* The calling thread dumps itself directly — no signal to self. */
    pthread_t self = pthread_self();
    asw_write_str(fd, "[tid=");
    asw_write_uint(fd, (unsigned long)syscall(SYS_gettid));
    asw_write_str(fd, "] (caller)\n");
    void *frames[64];
    int nf = backtrace(frames, 64);
    backtrace_symbols_fd(frames, nf, fd);
    asw_write_str(fd, "\n");
    count++;

    /* Snapshot the registry, then signal each other thread one at a time. */
    struct thread_registry_view view[ZCL_THREAD_REGISTRY_CAP];
    int nthreads = thread_registry_snapshot(view, ZCL_THREAD_REGISTRY_CAP);

    atomic_store_explicit(&g_bt.fd, fd, memory_order_release);
    for (int i = 0; i < nthreads; i++) {
        if (pthread_equal(view[i].tid, self))
            continue;  /* already dumped as (caller) */

        self_bt_drain();
        atomic_store_explicit(&g_bt.name, view[i].name, memory_order_release);
        /* Publish the target identity BEFORE the signal so the handler can
         * confirm it is the intended thread (see self_bt_handler). */
        atomic_store_explicit(&g_bt.target, view[i].tid, memory_order_release);

        int rc = pthread_kill(view[i].tid, self_bt_signo());
        if (rc != 0) {
            /* Thread exited between snapshot and signal. Record and move on. */
            asw_write_str(fd, "[name=");
            asw_write_str(fd, view[i].name);
            asw_write_str(fd, "] <gone>\n\n");
            count++;
            continue;
        }

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);  // platform-ok:sem_timedwait requires a raw CLOCK_REALTIME absolute deadline
        ts.tv_nsec += 100L * 1000L * 1000L;  /* 100 ms budget per thread */
        if (ts.tv_nsec >= 1000000000L) { ts.tv_sec += 1; ts.tv_nsec -= 1000000000L; }

        int w;
        do {
            w = sem_timedwait(&g_bt.done, &ts);
        } while (w != 0 && errno == EINTR);

        if (w != 0) {
            /* Blocked / signal-masked thread: it cannot hang the dump. */
            asw_write_str(fd, "[name=");
            asw_write_str(fd, view[i].name);
            asw_write_str(fd, "] <no response>\n\n");
        }
        count++;
    }
    atomic_store_explicit(&g_bt.fd, -1, memory_order_release);
    atomic_store_explicit(&g_bt.name, NULL, memory_order_release);
    atomic_store_explicit(&g_bt.target, (pthread_t)0, memory_order_release);

    fsync(fd);
    close(fd);

    /* Publish last-dump introspection. */
    pthread_mutex_lock(&g_last_mu);
    snprintf(g_last_path, sizeof(g_last_path), "%s", path);
    pthread_mutex_unlock(&g_last_mu);
    atomic_store_explicit(&g_last_thread_count, count, memory_order_release);
    atomic_store_explicit(&g_last_unix_ts, (long)time(NULL), memory_order_release);  // platform-ok:introspection wall-clock stamp
    atomic_fetch_add_explicit(&g_dump_count, 1, memory_order_relaxed);

    atomic_flag_clear_explicit(&g_dump_in_progress, memory_order_release);

    if (path_out && cap) snprintf(path_out, cap, "%s", path);
    return count;
}

bool self_backtrace_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    json_push_kv_bool(out, "installed",
                      atomic_load_explicit(&g_installed, memory_order_acquire));
    json_push_kv_int(out, "dump_count",
                     (int64_t)atomic_load_explicit(&g_dump_count,
                                                   memory_order_relaxed));
    json_push_kv_int(out, "last_thread_count",
                     (int64_t)atomic_load_explicit(&g_last_thread_count,
                                                   memory_order_acquire));
    json_push_kv_int(out, "last_unix_ts",
                     (int64_t)atomic_load_explicit(&g_last_unix_ts,
                                                   memory_order_acquire));
    char path[4300];
    pthread_mutex_lock(&g_last_mu);
    snprintf(path, sizeof(path), "%s", g_last_path);
    pthread_mutex_unlock(&g_last_mu);
    json_push_kv_str(out, "last_path", path);
    return true;
}
#endif
