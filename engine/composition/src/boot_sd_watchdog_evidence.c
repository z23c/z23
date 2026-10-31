/* Copyright (c) 2026 The ZClassic Developers
 * Distributed under the MIT software license.
 *
 * boot_sd_watchdog_evidence.c — diagnostics the sd_watchdog pet thread emits
 * when it WITHHOLDS the systemd ping. Observation only: nothing here feeds
 * the withhold decision. Everything is a pure formatter plus a /proc reader
 * that never blocks (open/read/close of procfs files, no locks taken).
 *
 * Why: a wedged node was aborted by systemd with no record of which frame
 * was stuck. The per-thread wchan + syscall first argument (the futex word
 * address) lets an operator match a blocked thread to a known lock address.
 */

#include "config/boot_internal.h"
#include "platform/os_proc.h"
#include "util/log_macros.h"
#include "util/reducer_drive_guard.h"
#include "util/supervisor.h"
#include "storage/progress_store.h"
#include "services/chain_activation_service.h"
#include "validation/process_block.h"
#include <stdatomic.h>
#include <stdint.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EVIDENCE_MAX_THREADS 128
#define EVIDENCE_FILE_MAX    512

void boot_sd_watchdog_format_drive_fields(char *out, size_t cap,
                                          const char *active_cb,
                                          bool drive_active,
                                          const char *drive_label,
                                          int64_t drive_age_us)
{
    if (!out || cap == 0)
        return;
    snprintf(out, cap, "active_cb=%s drive_active=%d drive_label=%s "
             "drive_age_us=%lld",
             (active_cb && active_cb[0]) ? active_cb : "none",
             (int)drive_active,
             (drive_label && drive_label[0]) ? drive_label : "none",
             (long long)drive_age_us);
}

void boot_sd_watchdog_live_drive_fields(char *out, size_t cap)
{
    boot_sd_watchdog_format_drive_fields(
        out, cap, supervisor_active_callback_name(),
        reducer_drive_active(), reducer_drive_label(),
        reducer_drive_age_us());
}

/* stat is "tid (comm) S ..."; comm may itself contain spaces or ')', so the
 * name is bounded by the first '(' and the LAST ')'. */
static bool task_parse_stat(const char *stat, char *comm, size_t comm_cap,
                            char *state)
{
    const char *open = strchr(stat, '(');
    const char *close = strrchr(stat, ')');
    if (!open || !close || close <= open || close[1] != ' ' || !close[2])
        return false;
    size_t n = (size_t)(close - open - 1);
    if (n >= comm_cap)
        n = comm_cap - 1;
    memcpy(comm, open + 1, n);
    comm[n] = '\0';
    *state = close[2];
    return true;
}

/* syscall is "NR a0 a1 ..." or "running" or "-1 sp pc". Keep NR and a0. */
static void task_parse_syscall(const char *text, char *out, size_t cap)
{
    char nr[24] = "", a0[32] = "";
    if (strncmp(text, "running", 7) == 0) {
        snprintf(out, cap, "running");
        return;
    }
    int got = sscanf(text, "%23s %31s", nr, a0);
    if (got == 2)
        snprintf(out, cap, "%s a0=%s", nr, a0);
    else if (got == 1)
        snprintf(out, cap, "%s", nr);
    else
        snprintf(out, cap, "?");
}

static void trim_eol(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == ' '))
        s[--n] = '\0';
}

bool boot_sd_watchdog_format_task_line(char *out, size_t cap, long tid,
                                       const char *stat, const char *wchan,
                                       const char *syscall_text)
{
    if (!out || cap == 0 || !stat)
        return false;
    char comm[32], sc[80], wc[48] = "";
    char state = '?';
    if (!task_parse_stat(stat, comm, sizeof(comm), &state))
        return false;
    task_parse_syscall(syscall_text ? syscall_text : "", sc, sizeof(sc));
    if (wchan)
        snprintf(wc, sizeof(wc), "%s", wchan);
    trim_eol(wc);
    snprintf(out, cap, "tid=%ld comm=%s st=%c wchan=%s sys=%s", tid, comm,
             state, wc[0] ? wc : "-", sc);
    return true;
}

/* The watchdog snapshot reads every thread (not just the first
 * EVIDENCE_MAX_THREADS) so a D-state or lock-waiting thread past the print
 * cap is still found and printed first. */
#define EVIDENCE_SCAN_THREADS 2048

bool boot_sd_watchdog_format_holder_line(char *out, size_t cap, bool held,
                                         long tid, const char *comm,
                                         int64_t held_us)
{
    if (!out || cap == 0)
        return false;
    if (!held)
        snprintf(out, cap, "progress_store_tx_lock holder=free");
    else
        snprintf(out, cap,
                 "progress_store_tx_lock holder tid=%ld comm=%s held_ms=%lld",
                 tid, (comm && comm[0]) ? comm : "?",
                 (long long)(held_us / 1000));
    return true;
}

/* True when the syscall number is futex (any number where the platform has no
 * SYS_futex: the address match below is then the only filter). */
static bool syscall_nr_is_futex(const char *nr)
{
#if defined(SYS_futex)
    char *end = NULL;
    long v = strtol(nr, &end, 10);
    return end != nr && *end == '\0' && v == (long)SYS_futex;
#else
    (void)nr;
    return true;
#endif
}

unsigned boot_sd_watchdog_task_priority(const char *stat,
                                        const char *syscall_text,
                                        const void *const *locks,
                                        size_t nlocks)
{
    char comm[32];
    char state = '?';
    if (stat && task_parse_stat(stat, comm, sizeof(comm), &state) &&
        state == 'D')
        return 0;
    if (!syscall_text || !locks)
        return 1;
    char nr[24] = "", a0[32] = "";
    if (sscanf(syscall_text, "%23s %31s", nr, a0) != 2 ||
        !syscall_nr_is_futex(nr))
        return 1;
    char *end = NULL;
    unsigned long long v = strtoull(a0, &end, 0);
    if (end == a0 || *end != '\0' || v == 0)
        return 1;
    for (size_t i = 0; i < nlocks; i++)
        if (locks[i] && (unsigned long long)(uintptr_t)locks[i] == v)
            return 0;
    return 1;
}

size_t boot_sd_watchdog_order_snapshot(const unsigned char *prio, size_t n,
                                       size_t cap, size_t *order)
{
    size_t w = 0;
    if (!prio || !order)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (prio[i] == 0)
            order[w++] = i;
    for (size_t i = 0; i < n && w < cap; i++)
        if (prio[i] != 0)
            order[w++] = i;
    return w;
}

/* /proc/self/task/<tid>/stack is normally root-only; say so and move on. */
static void snapshot_task_stack(long tid)
{
    char stack[EVIDENCE_FILE_MAX];
    if (!os_proc_self_task_read(tid, "stack", stack, sizeof(stack)) ||
        stack[0] == '\0') {
        LOG_WARN("boot", "[sd_watchdog] thread tid=%ld stack unreadable", tid);
        return;
    }
    /* Walk lines by hand: strtok keeps hidden global state other threads
     * (the log path, supervisors) may also use. */
    char *s = stack;
    for (size_t lines = 0; *s != '\0' && lines < 8; lines++) {
        char *nl = strchr(s, '\n');
        if (nl)
            *nl = '\0';
        LOG_WARN("boot", "[sd_watchdog] thread tid=%ld stack %s", tid, s);
        if (!nl)
            break;
        s = nl + 1;
    }
}

static void snapshot_one_task(long tid, bool priority)
{
    char stat[EVIDENCE_FILE_MAX], wchan[64], sc[EVIDENCE_FILE_MAX];
    char line[192] = "";
    stat[0] = wchan[0] = sc[0] = '\0';
    bool ok = os_proc_self_task_read(tid, "stat", stat, sizeof(stat));
    (void)os_proc_self_task_read(tid, "wchan", wchan, sizeof(wchan));
    (void)os_proc_self_task_read(tid, "syscall", sc, sizeof(sc));
    bool fmt = ok && boot_sd_watchdog_format_task_line(line, sizeof(line), tid,
                                                       stat, wchan, sc);
    if (fmt)
        LOG_WARN("boot", "[sd_watchdog] thread %s", line);
    else
        LOG_WARN("boot", "[sd_watchdog] thread tid=%ld unreadable", tid);
    if (fmt && priority && strstr(line, " st=D "))
        snapshot_task_stack(tid);
}

static void known_locks(const void **locks)
{
    struct chain_activation_controller *ctl = process_block_activation_controller();
    locks[0] = ctl ? (const void *)&ctl->mutex : NULL;
    locks[1] = progress_store_tx_lock_addr();
}

static void log_lock_addresses(const void *const *locks)
{
    LOG_WARN("boot",
             "[sd_watchdog] lock addresses (match a futex a0): "
             "activation_mutex=%p progress_store_tx_lock=%p",
             locks[0], locks[1]);
}

static void log_tx_lock_holder(void)
{
    long tid = 0;
    int64_t held_us = 0;
    bool held = progress_store_tx_holder(&tid, &held_us);
    char stat[EVIDENCE_FILE_MAX] = "", comm[32] = "?", line[160];
    char state = '?';
    if (held && os_proc_self_task_read(tid, "stat", stat, sizeof(stat)))
        (void)task_parse_stat(stat, comm, sizeof(comm), &state);
    if (boot_sd_watchdog_format_holder_line(line, sizeof(line), held, tid,
                                            comm, held_us))
        LOG_WARN("boot", "[sd_watchdog] %s", line);
}

static void classify_tasks(const long *tids, size_t n, const void *const *locks,
                           unsigned char *prio)
{
    for (size_t i = 0; i < n; i++) {
        char stat[EVIDENCE_FILE_MAX], sc[EVIDENCE_FILE_MAX];
        bool ok = os_proc_self_task_read(tids[i], "stat", stat, sizeof(stat));
        bool has_sc = os_proc_self_task_read(tids[i], "syscall", sc,
                                             sizeof(sc));
        prio[i] = (unsigned char)boot_sd_watchdog_task_priority(
            ok ? stat : NULL, has_sc ? sc : NULL, locks, 2);
    }
}

/* The scan arrays (~35 KB) live in static storage, not on the pet thread's
 * stack. One snapshot at a time: the pet thread is the only caller, and an
 * overlapping call is refused rather than sharing the arrays. Static, not
 * malloc: a stalled thread may hold the allocator's lock. */
static struct {
    long tids[EVIDENCE_SCAN_THREADS];
    unsigned char prio[EVIDENCE_SCAN_THREADS];
    size_t order[EVIDENCE_SCAN_THREADS];
} s_scan;
static atomic_flag s_scan_busy = ATOMIC_FLAG_INIT;

static void log_thread_snapshot_scan(void)
{
    const void *locks[2];
    size_t total = 0;
    known_locks(locks);
    log_lock_addresses(locks);
    log_tx_lock_holder();
    size_t n = os_proc_self_task_ids(s_scan.tids, EVIDENCE_SCAN_THREADS, &total);
    if (n == 0) {
        LOG_WARN("boot", "[sd_watchdog] thread snapshot unavailable "
                 "(no per-thread procfs on this platform)");
        return;
    }
    classify_tasks(s_scan.tids, n, locks, s_scan.prio);
    size_t shown = boot_sd_watchdog_order_snapshot(s_scan.prio, n,
                                                   EVIDENCE_MAX_THREADS,
                                                   s_scan.order);
    for (size_t i = 0; i < shown; i++)
        snapshot_one_task(s_scan.tids[s_scan.order[i]],
                          s_scan.prio[s_scan.order[i]] == 0);
    LOG_WARN("boot", "[sd_watchdog] thread snapshot: threads=%zu "
             "truncated=%zu unscanned=%zu", shown, n - shown,
             total - n);
}

void boot_sd_watchdog_log_thread_snapshot(void)
{
    if (atomic_flag_test_and_set(&s_scan_busy)) {
        LOG_WARN("boot", "[sd_watchdog] thread snapshot already running; "
                 "skipped");
        return;
    }
    log_thread_snapshot_scan();
    atomic_flag_clear(&s_scan_busy);
}
