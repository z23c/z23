/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Truthful, bounded shutdown watchdog. See util/shutdown_stagewatch.h for the
 * why. This file holds: (1) the pure decision + receipt-format helpers (unit
 * tested directly), and (2) the live wiring that the shutdown path drives.
 */

#include "util/shutdown_stagewatch.h"

#include "platform/time_compat.h"
#include "platform/file_sync.h"
#include "platform/private_file.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>
#define STAGEWATCH_CLOEXEC _O_NOINHERIT
#else
#define STAGEWATCH_CLOEXEC O_CLOEXEC
#endif

/* Bounded graces for a durability-critical stall: each grace re-arms alarm()
 * for GRACE_SECS and logs loudly, so a slow-but-progressing fsync finishes
 * rather than being abandoned, while a truly wedged fsync still terminates in
 * bounded time (budget + GRACE_MAX * GRACE_SECS). */
#define SHUTDOWN_GRACE_MAX  2
#define SHUTDOWN_GRACE_SECS 15

#define SHUTDOWN_RECEIPT_NAME "shutdown-receipt.v1"
#define SHUTDOWN_EXIT_REASON_NAME "boot-exit-reason.v1"

/* ── Pure helpers (async-signal-safe where noted) ────────────────────── */

enum shutdown_deadline_action
shutdown_deadline_decide(bool durable_secured,
                         bool current_stage_durability_critical,
                         int graces_used, int grace_max)
{
    /* Durability already secured: the remaining teardown (compaction, cache
     * writeback, frees) is resumable at next boot, so stopping now is honest
     * success — never a false failure. */
    if (durable_secured)
        return SHUTDOWN_DEADLINE_EXIT_CLEAN;

    /* Durability NOT secured. A durability-critical fsync must never be
     * skipped: grant bounded graces so it can finish, and only declare an
     * unclean exit once the grace budget is spent. */
    if (current_stage_durability_critical)
        return (graces_used < grace_max) ? SHUTDOWN_DEADLINE_GRACE
                                         : SHUTDOWN_DEADLINE_EXIT_UNCLEAN;

    /* A non-critical stage stalling before durability: waiting protects
     * nothing durable, and exiting now is honestly unclean (durability was
     * never reached). Fail fast rather than burn the grace budget. */
    return SHUTDOWN_DEADLINE_EXIT_UNCLEAN;
}

int shutdown_stagewatch_exit_code(enum shutdown_outcome outcome)
{
    /* Truthful: only a pre-durability forced exit is a failure. */
    return (outcome == SHUTDOWN_OUTCOME_FORCED_UNCLEAN) ? 1 : 0;
}

static const char *outcome_str(enum shutdown_outcome o)
{
    switch (o) {
    case SHUTDOWN_OUTCOME_CLEAN:                return "clean";
    case SHUTDOWN_OUTCOME_FORCED_AFTER_DURABLE: return "forced-after-durable";
    case SHUTDOWN_OUTCOME_FORCED_UNCLEAN:       return "forced-unclean";
    }
    return "unknown";
}

int shutdown_stagewatch_format_receipt(char *buf, size_t n,
                                       enum shutdown_outcome outcome,
                                       const char *last_stage,
                                       bool durable_secured,
                                       int64_t total_us,
                                       const struct shutdown_stage_record *stages,
                                       size_t n_stages)
{
    if (!buf || n == 0)
        return -1;

    int off = snprintf(buf, n,
                       "magic=ZCLSHUTRCPT\n"
                       "version=1\n"
                       "outcome=%s\n"
                       "durable=%d\n"
                       "last_stage=%s\n"
                       "total_ms=%lld\n"
                       "stages=%zu\n",
                       outcome_str(outcome),
                       durable_secured ? 1 : 0,
                       (last_stage && *last_stage) ? last_stage : "-",
                       (long long)(total_us / 1000),
                       n_stages);
    if (off < 0 || (size_t)off >= n)
        return -1;

    for (size_t i = 0; i < n_stages && stages; i++) {
        int w = snprintf(buf + off, n - (size_t)off,
                         "stage.%s_ms=%lld critical=%d over_budget=%d\n",
                         stages[i].name[0] ? stages[i].name : "-",
                         (long long)(stages[i].elapsed_us / 1000),
                         stages[i].durability_critical ? 1 : 0,
                         stages[i].over_budget ? 1 : 0);
        if (w < 0 || (size_t)w >= n - (size_t)off)
            return -1;
        off += w;
    }
    return off;
}

/* AS-safe: write the full NUL-terminated string, computing length by hand
 * (no strlen/libc) and retrying short/interrupted writes. */
static int as_write_str(int fd, const char *s)
{
    if (!s)
        return 0;
    size_t len = 0;
    while (s[len] != '\0')
        len++;
    size_t done = 0;
    while (done < len) {
        ssize_t w = write(fd, s + done, len - done);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        done += (size_t)w;
    }
    return (int)done;
}

int shutdown_stagewatch_write_terminal_receipt_fd(int fd,
                                                  enum shutdown_outcome outcome,
                                                  const char *stage,
                                                  bool durable)
{
    /* Minimal but truthful — every field is a static string or the fixed
     * in-flight stage-name buffer, so no formatting is needed and the whole
     * thing is async-signal-safe. */
    int total = 0, w;
    if ((w = as_write_str(fd, "magic=ZCLSHUTRCPT\nversion=1\noutcome=")) < 0)
        return -1;
    total += w;
    if ((w = as_write_str(fd, outcome_str(outcome))) < 0) return -1;
    total += w;
    if ((w = as_write_str(fd, "\ndurable=")) < 0) return -1;
    total += w;
    if ((w = as_write_str(fd, durable ? "1" : "0")) < 0) return -1;
    total += w;
    if ((w = as_write_str(fd, "\nforced_at_stage=")) < 0) return -1;
    total += w;
    if ((w = as_write_str(fd, (stage && *stage) ? stage : "-")) < 0) return -1;
    total += w;
    if ((w = as_write_str(fd, "\n")) < 0) return -1;
    total += w;
    return total;
}

/* ── Live state ──────────────────────────────────────────────────────── */

static int64_t real_clock_us(void) { return platform_time_monotonic_us(); }

static shutdown_stagewatch_clock_fn g_clock = real_clock_us;

/* Receipt path, computed once in begin() so the signal handler needs no
 * snprintf. g_receipt_ok gates whether we have a valid path. */
static char g_receipt_path[1088];
static _Atomic bool g_receipt_ok;   /* read in signal ctx */
static int g_datadir_fd = -1;       /* opened by begin; safe to fsync in SIGALRM */
static char g_datadir_path[1088];

static bool stagewatch_sync_datadir(void)
{
#ifdef _WIN32
    return g_datadir_path[0] != '\0' &&
           platform_private_parent_flush(g_datadir_path);
#else
    return g_datadir_fd >= 0 && platform_file_sync(g_datadir_fd) == 0;
#endif
}

/* Exit-reason breadcrumb path — same "compute once in begin(), signal
 * handler only ever does raw open/write/fsync of the pre-computed path"
 * pattern as g_receipt_path above. */
static char g_exit_reason_path[1088];
static _Atomic bool g_exit_reason_path_ok;   /* read in signal ctx */

static int64_t g_start_us;
static struct shutdown_stage_record g_stages[SHUTDOWN_STAGEWATCH_MAX_STAGES];
static size_t  g_n_stages;

/* In-flight (not-yet-closed) stage. g_cur_name is written only in normal
 * context and read in the handler; the handler interrupts the same thread, so
 * there is no concurrent writer. */
static char    g_cur_name[SHUTDOWN_STAGE_NAME_MAX];
static int64_t g_cur_start_us;
static bool    g_cur_critical;
static int     g_cur_budget_secs;
static char    g_last_stage[SHUTDOWN_STAGE_NAME_MAX];

static volatile sig_atomic_t g_cur_active;
static volatile sig_atomic_t g_durable;
static volatile sig_atomic_t g_graces_used;
static volatile sig_atomic_t g_active;   /* begin() called */

#ifdef _WIN32
static _Atomic uint32_t g_timer_generation;

static DWORD WINAPI stagewatch_timer_thread(LPVOID parameter)
{
    uint64_t packed = (uint64_t)(uintptr_t)parameter;
    uint32_t generation = (uint32_t)packed;
    uint32_t seconds = (uint32_t)(packed >> 32);
    HANDLE timer = CreateWaitableTimerW(NULL, TRUE, NULL);
    if (!timer)
        return 0;
    LARGE_INTEGER due;
    due.QuadPart = -(LONGLONG)10000000 * seconds;
    if (SetWaitableTimer(timer, &due, 0, NULL, NULL, FALSE) &&
        WaitForSingleObject(timer, INFINITE) == WAIT_OBJECT_0 &&
        atomic_load(&g_timer_generation) == generation)
        shutdown_stagewatch_on_alarm();
    CloseHandle(timer);
    return 0;
}

static void stagewatch_arm(unsigned seconds)
{
    uint32_t generation = atomic_fetch_add(&g_timer_generation, 1) + 1;
    uintptr_t packed = (uintptr_t)(((uint64_t)seconds << 32) | generation);
    HANDLE thread = CreateThread(NULL, 0, stagewatch_timer_thread,
                                 (LPVOID)packed, 0, NULL);
    if (thread) CloseHandle(thread);
}

static void stagewatch_cancel(void) { (void)atomic_fetch_add(&g_timer_generation, 1); }
#else
static void stagewatch_arm(unsigned seconds) { alarm(seconds); }
static void stagewatch_cancel(void) { alarm(0); }
#endif

void shutdown_stagewatch_set_clock_for_test(shutdown_stagewatch_clock_fn fn)
{
    g_clock = fn ? fn : real_clock_us;
}

void shutdown_stagewatch_reset_for_test(void)
{
    stagewatch_cancel();
    if (g_datadir_fd >= 0)
        (void)close(g_datadir_fd);
    g_datadir_fd = -1;
    g_datadir_path[0] = '\0';
    g_clock = real_clock_us;
    memset(g_receipt_path, 0, sizeof(g_receipt_path));
    atomic_store(&g_receipt_ok, false);
    memset(g_exit_reason_path, 0, sizeof(g_exit_reason_path));
    atomic_store(&g_exit_reason_path_ok, false);
    g_start_us = 0;
    memset(g_stages, 0, sizeof(g_stages));
    g_n_stages = 0;
    memset(g_cur_name, 0, sizeof(g_cur_name));
    memset(g_last_stage, 0, sizeof(g_last_stage));
    g_cur_start_us = 0;
    g_cur_critical = false;
    g_cur_budget_secs = 0;
    g_cur_active = 0;
    g_durable = 0;
    g_graces_used = 0;
    g_active = 0;
}

size_t shutdown_stagewatch_stage_count(void) { return g_n_stages; }

const struct shutdown_stage_record *shutdown_stagewatch_stage(size_t i)
{
    return (i < g_n_stages) ? &g_stages[i] : NULL;
}

bool shutdown_stagewatch_is_durable(void) { return g_durable != 0; }

void shutdown_stagewatch_begin(const char *datadir)
{
    stagewatch_cancel();
    if (g_datadir_fd >= 0)
        (void)close(g_datadir_fd);
    g_datadir_fd = -1;
    g_datadir_path[0] = '\0';
    g_start_us = g_clock();
    g_n_stages = 0;
    g_cur_active = 0;
    g_durable = 0;
    g_graces_used = 0;
    memset(g_last_stage, 0, sizeof(g_last_stage));

    atomic_store(&g_receipt_ok, false);
    atomic_store(&g_exit_reason_path_ok, false);
    if (datadir && *datadir) {
        (void)snprintf(g_datadir_path, sizeof(g_datadir_path), "%s", datadir);
#ifndef _WIN32
        g_datadir_fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
#endif
        int n = snprintf(g_receipt_path, sizeof(g_receipt_path), "%s/%s",
                         datadir, SHUTDOWN_RECEIPT_NAME);
        if (n > 0 && (size_t)n < sizeof(g_receipt_path))
            atomic_store(&g_receipt_ok, true);

        int en = snprintf(g_exit_reason_path, sizeof(g_exit_reason_path),
                          "%s/%s", datadir, SHUTDOWN_EXIT_REASON_NAME);
        if (en > 0 && (size_t)en < sizeof(g_exit_reason_path))
            atomic_store(&g_exit_reason_path_ok, true);
    }
    g_active = 1;
}

/* Close out the in-flight stage: record duration, flag over-budget against the
 * budget it ran under, and log at INFO. Normal context only. */
static void close_current_stage(void)
{
    if (!g_cur_active)
        return;
    int64_t elapsed = g_clock() - g_cur_start_us;
    if (elapsed < 0)
        elapsed = 0;
    bool over = g_cur_budget_secs > 0 &&
                elapsed > (int64_t)g_cur_budget_secs * 1000000LL;

    if (g_n_stages < SHUTDOWN_STAGEWATCH_MAX_STAGES) {
        struct shutdown_stage_record *r = &g_stages[g_n_stages++];
        memset(r, 0, sizeof(*r));
        snprintf(r->name, sizeof(r->name), "%s", g_cur_name);
        r->elapsed_us = elapsed;
        r->durability_critical = g_cur_critical;
        r->over_budget = over;
    }
    snprintf(g_last_stage, sizeof(g_last_stage), "%s", g_cur_name);
    LOG_INFO("shutdown", "stage '%s' took %lldms%s%s", g_cur_name,
             (long long)(elapsed / 1000),
             g_cur_critical ? " (durability-critical)" : "",
             over ? " OVER-BUDGET" : "");
    g_cur_active = 0;
}

void shutdown_stagewatch_enter(const char *stage, int budget_secs,
                               bool durability_critical, bool arm_alarm)
{
    close_current_stage();

    snprintf(g_cur_name, sizeof(g_cur_name), "%s", stage ? stage : "?");
    g_cur_start_us = g_clock();
    g_cur_critical = durability_critical;
    g_cur_budget_secs = budget_secs;
    /* Each stage gets its own bounded grace budget: escalation is per-stage,
     * so one slow-but-progressing stage does not starve a later one. */
    g_graces_used = 0;
    g_cur_active = 1;

    if (arm_alarm && budget_secs > 0)
        stagewatch_arm((unsigned)budget_secs);
}

void shutdown_stagewatch_mark_durable(void)
{
    g_durable = 1;   /* AS-safe */
}

/* AS-safe: open the receipt path, write the terminal receipt, fsync, close. */
static void write_terminal_receipt_signalsafe(enum shutdown_outcome outcome)
{
    if (!atomic_load(&g_receipt_ok))
        return;
    int fd = open(g_receipt_path, O_WRONLY | O_CREAT | O_TRUNC | STAGEWATCH_CLOEXEC, 0644);
    if (fd < 0)
        return;
    (void)shutdown_stagewatch_write_terminal_receipt_fd(
        fd, outcome, g_cur_name, g_durable != 0);
    (void)platform_file_sync(fd);
    (void)close(fd);
    (void)stagewatch_sync_datadir();
}

/* AS-safe: append a "forced=1" marker to the exit-reason breadcrumb (see
 * util/shutdown_stagewatch.h "Exit-reason breadcrumb"). Whoever set the
 * breadcrumb's `reason=` line (normally shutdown_stagewatch_write_exit_
 * reason(), called in normal context right after begin(), BEFORE this alarm
 * could ever fire) already recorded WHY the shutdown started; this only
 * flags that the shutdown itself did not finish inside its per-stage budget
 * and had to be force-exited from here — the exact signal a self-respawn
 * request can otherwise lose silently (see the header doc comment). O_APPEND
 * needs no read-modify-write, so this stays a single AS-safe open/write/
 * fsync/close, same shape as write_terminal_receipt_signalsafe above. */
static void mark_exit_reason_forced_signalsafe(void)
{
    if (!atomic_load(&g_exit_reason_path_ok))
        return;
    int fd = open(g_exit_reason_path,
                 O_WRONLY | O_CREAT | O_APPEND | STAGEWATCH_CLOEXEC, 0644);
    if (fd < 0)
        return;
    static const char line[] = "forced=1\n";
    (void)!write(fd, line, sizeof(line) - 1);
    (void)platform_file_sync(fd);
    (void)close(fd);
}

void shutdown_stagewatch_on_alarm(void)
{
    /* begin() never ran (offline path installs the handler but arms no
     * per-stage alarm, or a stray SIGALRM): fall back to the legacy loud
     * forced exit rather than trust uninitialised state. */
    if (!g_active) {
        static const char msg[] =
            "[shutdown] alarm fired: graceful shutdown hung - forcing exit\n";
        (void)!write(STDERR_FILENO, msg, sizeof(msg) - 1);
        _exit(1);
    }

    (void)as_write_str(STDERR_FILENO, "[shutdown] watchdog: stage '");
    (void)as_write_str(STDERR_FILENO, g_cur_name);
    (void)as_write_str(STDERR_FILENO, "' exceeded its deadline\n");

    enum shutdown_deadline_action action = shutdown_deadline_decide(
        g_durable != 0, g_cur_critical, (int)g_graces_used, SHUTDOWN_GRACE_MAX);

    switch (action) {
    case SHUTDOWN_DEADLINE_GRACE:
        g_graces_used = (sig_atomic_t)(g_graces_used + 1);
        (void)as_write_str(STDERR_FILENO,
            "[shutdown] watchdog: durability not yet secured; granting grace, "
            "durability-critical stage still running\n");
        stagewatch_arm(SHUTDOWN_GRACE_SECS);
        return;

    case SHUTDOWN_DEADLINE_EXIT_CLEAN:
        /* Durability secured — the remainder is resumable. Truthful success. */
        write_terminal_receipt_signalsafe(SHUTDOWN_OUTCOME_FORCED_AFTER_DURABLE);
        mark_exit_reason_forced_signalsafe();
        (void)as_write_str(STDERR_FILENO,
            "[shutdown] watchdog: durability secured; forcing truthful clean "
            "exit (0)\n");
        _exit(0);

    case SHUTDOWN_DEADLINE_EXIT_UNCLEAN:
        write_terminal_receipt_signalsafe(SHUTDOWN_OUTCOME_FORCED_UNCLEAN);
        mark_exit_reason_forced_signalsafe();
        (void)as_write_str(STDERR_FILENO,
            "[shutdown] watchdog: durability NOT reached; forcing unclean "
            "exit (1)\n");
        _exit(1);
    }
}

static bool shutdown_stagewatch_complete(enum shutdown_outcome outcome)
{
    close_current_stage();
    bool durable = !atomic_load(&g_receipt_ok);

    if (atomic_load(&g_receipt_ok)) {
        char content[4096];
        int64_t total = g_clock() - g_start_us;
        int clen = shutdown_stagewatch_format_receipt(
            content, sizeof(content), outcome, g_last_stage,
            g_durable != 0, total, g_stages, g_n_stages);
        if (clen > 0) {
            /* temp + fsync + atomic rename, mirroring the clean-shutdown
             * marker's crash-safe write. */
            char tmp[1152];
            int tn = snprintf(tmp, sizeof(tmp), "%s.tmp", g_receipt_path);
            if (tn > 0 && (size_t)tn < sizeof(tmp)) {
                int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | STAGEWATCH_CLOEXEC, 0644);
                if (fd >= 0) {
                    bool ok = as_write_str(fd, content) == clen &&
                              platform_file_sync(fd) == 0;
                    if (close(fd) != 0)
                        ok = false;
                    if (ok && rename(tmp, g_receipt_path) != 0)
                        ok = false;
                    if (ok && !stagewatch_sync_datadir())
                        ok = false;
                    if (!ok)
                        (void)unlink(tmp);
                    durable = ok;
                }
            }
        }
    }
    stagewatch_cancel();
    g_active = 0;
    if (g_datadir_fd >= 0)
        (void)close(g_datadir_fd);
    g_datadir_fd = -1;
    return durable;
}

bool shutdown_stagewatch_complete_clean(void)
{
    return shutdown_stagewatch_complete(SHUTDOWN_OUTCOME_CLEAN);
}

bool shutdown_stagewatch_complete_unclean(void)
{
    return shutdown_stagewatch_complete(SHUTDOWN_OUTCOME_FORCED_UNCLEAN);
}

/* ── Exit-reason breadcrumb ──────────────────────────────────────────── */

void shutdown_stagewatch_write_exit_reason(const char *reason)
{
    if (!reason || !*reason) {
        LOG_WARN("shutdown", "write_exit_reason: empty reason — not written");
        return;
    }
    if (!atomic_load(&g_exit_reason_path_ok)) {
        LOG_WARN("shutdown",
                 "write_exit_reason: no datadir (begin() received none) — "
                 "'%s' not persisted", reason);
        return;
    }

    char content[192];
    int clen = snprintf(content, sizeof(content),
                        "magic=ZCLEXITRSN\nversion=1\nreason=%.*s\nts=%lld\n",
                        SHUTDOWN_EXIT_REASON_MAX - 1, reason,
                        (long long)platform_time_wall_unix());
    if (clen <= 0 || (size_t)clen >= sizeof(content)) {
        LOG_WARN("shutdown", "write_exit_reason: format failed for '%s'", reason);
        return;
    }

    char tmp[1152];
    int tn = snprintf(tmp, sizeof(tmp), "%s.tmp", g_exit_reason_path);
    if (tn <= 0 || (size_t)tn >= sizeof(tmp)) {
        LOG_WARN("shutdown", "write_exit_reason: tmp path overflow");
        return;
    }

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | STAGEWATCH_CLOEXEC, 0644);
    if (fd < 0) {
        LOG_WARN("shutdown", "write_exit_reason: open(%s) failed: %s",
                 tmp, strerror(errno));
        return;
    }
    bool ok = (write(fd, content, (size_t)clen) == (ssize_t)clen) &&
             (platform_file_sync(fd) == 0);
    if (close(fd) != 0)
        ok = false;
    if (ok && rename(tmp, g_exit_reason_path) != 0)
        ok = false;
    if (!ok) {
        LOG_WARN("shutdown", "write_exit_reason: write/rename of %s failed: %s",
                 g_exit_reason_path, strerror(errno));
        (void)unlink(tmp);
        return;
    }
    LOG_INFO("shutdown", "exit-reason breadcrumb written: reason=%s", reason);
}

bool shutdown_stagewatch_read_exit_reason(const char *datadir,
                                          char *reason_out, size_t n,
                                          bool *forced_out)
{
    if (reason_out && n > 0) reason_out[0] = '\0';
    if (forced_out) *forced_out = false;
    if (!datadir || !*datadir || !reason_out || n == 0)
        return false;

    char path[1088];
    int pn = snprintf(path, sizeof(path), "%s/%s", datadir,
                      SHUTDOWN_EXIT_REASON_NAME);
    if (pn <= 0 || (size_t)pn >= sizeof(path))
        return false;

    FILE *f = fopen(path, "r");
    if (!f)
        return false;   /* no breadcrumb — not an error, e.g. first-ever boot */

    char line[192];
    bool have_reason = false;
    bool forced = false;
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (strncmp(line, "reason=", 7) == 0) {
            snprintf(reason_out, n, "%s", line + 7);
            have_reason = true;
        } else if (strncmp(line, "forced=1", 8) == 0) {
            forced = true;
        }
    }
    fclose(f);

    if (forced_out) *forced_out = forced;
    return have_reason;
}
