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
#include <pthread.h>
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

static _Atomic(const void *) s_cs_main_addr;

void boot_sd_watchdog_register_cs_main(const void *cs_main)
{
    atomic_store(&s_cs_main_addr, cs_main);
}

#define EVIDENCE_NLOCKS 3
static void known_locks(const void **locks)
{
    struct chain_activation_controller *ctl = process_block_activation_controller();
    locks[0] = ctl ? (const void *)&ctl->mutex : NULL;
    locks[1] = progress_store_tx_lock_addr();
    locks[2] = atomic_load(&s_cs_main_addr);
}

static void log_lock_addresses(const void *const *locks)
{
    LOG_WARN("boot",
             "[sd_watchdog] lock addresses (match a futex a0): "
             "activation_mutex=%p progress_store_tx_lock=%p cs_main=%p",
             locks[0], locks[1], locks[2]);
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
            ok ? stat : NULL, has_sc ? sc : NULL, locks,
            EVIDENCE_NLOCKS);
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
    const void *locks[EVIDENCE_NLOCKS];
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

/* ── Disk-stall hold: pure classifier + status counters ──────────────────
 *
 * 11-02 incident: every pillar thread (tick runner, connman msg and open)
 * sat in a futex wait, queued behind ONE thread that was st=D in pread64
 * (wchan folio_wait_bit_common) while the socket thread kept polling. The
 * futex waiters are not the evidence; the D+IO thread is. So the scan covers
 * every thread of the process (the same view the withhold snapshot prints).
 *
 * A thread parked in the kernel on disk IO is waiting on the device, not
 * wedged, and restarting makes it worse (the restart is itself heavy IO).
 * HOLD requires positive evidence on every leg; a missing /proc read, a
 * futex-only process (deadlock), a dead socket thread, a stale sweep or a
 * spent grace all say WITHHOLD, the pre-existing behavior. */

static bool wchan_is_disk_io(const char *w)
{
    static const char *const prefixes[] = {
        "folio_wait", "wait_on_page", "rq_qos", "wbt_", "io_schedule",
        "bit_wait_io", "submit_bio", "blk", "balance_dirty",
    };
    if (!w || !w[0])
        return false;
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++)
        if (strncmp(w, prefixes[i], strlen(prefixes[i])) == 0)
            return true;
    return false;
}

bool boot_sd_watchdog_task_in_disk_wait(const char *stat, const char *wchan)
{
    char comm[32], wc[64] = "";
    char state = '?';
    if (!stat || !wchan || !task_parse_stat(stat, comm, sizeof(comm), &state))
        return false;
    if (state != 'D')
        return false;
    snprintf(wc, sizeof(wc), "%s", wchan);
    trim_eol(wc);
    return wchan_is_disk_io(wc);
}

/* The connman socket thread (comm is cut to 15 chars) is alive when it is
 * running or sleeping in a non-futex wait: do_poll/ep_poll/hrtimer are the
 * healthy idle states; D or a futex wait means it too is stuck. */
bool boot_sd_watchdog_task_is_live_socket_thread(const char *stat,
                                                 const char *wchan)
{
    char comm[32], wc[64] = "";
    char state = '?';
    if (!stat || !wchan || !task_parse_stat(stat, comm, sizeof(comm), &state))
        return false;
    if (strncmp(comm, "zcl_connman_soc", 15) != 0)
        return false;
    if (state != 'R' && state != 'S')
        return false;
    snprintf(wc, sizeof(wc), "%s", wchan);
    trim_eol(wc);
    return strncmp(wc, "futex", 5) != 0;
}

void boot_sd_watchdog_hold_acc_add(struct boot_sd_hold_acc *a,
                                   const char *stat, const char *wchan)
{
    if (!a)
        return;
    a->seen++;
    if (!stat || !wchan) {
        a->unreadable++;
        return;
    }
    if (boot_sd_watchdog_task_is_live_socket_thread(stat, wchan))
        a->socket_alive = true;
}

/* A stalled pillar thread is EXPLAINED by disk IO when it is itself st=D on
 * an IO wchan, or when it is in a futex wait (syscall 202, a0 = the futex
 * word) on the address of a KNOWN lock whose recorded holder is itself st=D
 * on an IO wchan. Anything else (unknown lock, free lock, unreadable holder)
 * is unexplained, and an unexplained stall keeps the status-quo kill. On
 * success *d_tid is the D+IO thread the stall waits on. */
/* The futex word address (syscall a0) of a futex-wait syscall text, or 0. */
static unsigned long long futex_wait_addr(const char *syscall_text)
{
    char nr[24] = "", a0[32] = "";
    if (!syscall_text || sscanf(syscall_text, "%23s %31s", nr, a0) != 2 ||
        !syscall_nr_is_futex(nr))
        return 0;
    char *end = NULL;
    unsigned long long v = strtoull(a0, &end, 0);
    return (end == a0 || *end != '\0') ? 0 : v;
}

/* True when `addr` is a known lock whose recorded holder waits on disk IO. */
static bool lock_holder_waits_on_disk(const struct boot_sd_known_lock *locks,
                                      size_t nlocks, unsigned long long addr,
                                      long *d_tid)
{
    for (size_t i = 0; i < nlocks; i++) {
        if (!locks[i].addr || (unsigned long long)(uintptr_t)locks[i].addr != addr)
            continue;
        if (locks[i].holder_tid <= 0 ||
            !boot_sd_watchdog_task_in_disk_wait(locks[i].holder_stat,
                                                locks[i].holder_wchan))
            return false;
        if (d_tid)
            *d_tid = locks[i].holder_tid;
        return true;
    }
    return false;
}

bool boot_sd_watchdog_pillar_explained(const struct boot_sd_pillar_obs *p,
                                       const struct boot_sd_known_lock *locks,
                                       size_t nlocks, long *d_tid)
{
    if (!p || !p->stat || !p->wchan)
        return false;
    if (boot_sd_watchdog_task_in_disk_wait(p->stat, p->wchan)) {
        if (d_tid)
            *d_tid = p->tid;
        return true;
    }
    unsigned long long addr = futex_wait_addr(p->syscall);
    if (addr == 0 || !locks)
        return false;
    return lock_holder_waits_on_disk(locks, nlocks, addr, d_tid);
}

void boot_sd_watchdog_hold_acc_add_pillar(
    struct boot_sd_hold_acc *a, const struct boot_sd_pillar_obs *p,
    const struct boot_sd_known_lock *locks, size_t nlocks)
{
    if (!a)
        return;
    a->pillars++;
    long d = 0;
    if (boot_sd_watchdog_pillar_explained(p, locks, nlocks, &d)) {
        a->explained++;
        if (a->d_tid == 0)
            a->d_tid = d;
    }
}

enum boot_sd_disk_hold_verdict
boot_sd_watchdog_hold_acc_verdict(const struct boot_sd_hold_acc *a,
                                  bool connman_started, bool sweep_alive,
                                  int64_t held_us, int64_t grace_us)
{
    if (!a || a->seen == 0 || a->unreadable >= a->seen)
        return BOOT_SD_HOLD_NO_PROC;
    if (a->pillars == 0)
        return BOOT_SD_HOLD_NO_STALL;
    if (a->explained < a->pillars)
        return BOOT_SD_HOLD_NO_IO_WAIT;
    if (!connman_started || !sweep_alive || !a->socket_alive)
        return BOOT_SD_HOLD_NETWORK_STALE;
    if (held_us < 0 || held_us >= grace_us)
        return BOOT_SD_HOLD_GRACE_ELAPSED;
    return BOOT_SD_HOLD;
}

/* Two consecutive checks must be explained by the SAME D+IO thread. */
enum boot_sd_disk_hold_verdict
boot_sd_watchdog_hold_confirm(enum boot_sd_disk_hold_verdict v, long d_tid,
                              long *prev_d_tid)
{
    if (v != BOOT_SD_HOLD) {
        *prev_d_tid = 0;
        return v;
    }
    if (d_tid <= 0 || *prev_d_tid != d_tid) {
        *prev_d_tid = d_tid;
        return BOOT_SD_HOLD_UNCONFIRMED;
    }
    return BOOT_SD_HOLD;
}

const char *boot_sd_watchdog_disk_hold_name(enum boot_sd_disk_hold_verdict v)
{
    /* Indexed by the enum; keep in step with boot_internal.h. */
    static const char *const names[] = {
        [BOOT_SD_HOLD] = "hold",
        [BOOT_SD_HOLD_NO_PROC] = "proc-unreadable",
        [BOOT_SD_HOLD_NO_STALL] = "no-stalled-pillar",
        [BOOT_SD_HOLD_NO_IO_WAIT] = "stall-not-on-disk-io",
        [BOOT_SD_HOLD_NETWORK_STALE] = "network-stale",
        [BOOT_SD_HOLD_GRACE_ELAPSED] = "grace-elapsed",
        [BOOT_SD_HOLD_UNCONFIRMED] = "d-thread-unconfirmed",
    };
    return (unsigned)v < sizeof(names) / sizeof(names[0]) ? names[v] : "?";
}

static _Atomic unsigned long s_disk_hold_count;
static _Atomic int s_disk_hold_last = -1;

void boot_sd_watchdog_disk_hold_note(enum boot_sd_disk_hold_verdict v)
{
    if (v == BOOT_SD_HOLD)
        atomic_fetch_add(&s_disk_hold_count, 1);
    atomic_store(&s_disk_hold_last, (int)v);
}

unsigned long boot_sd_watchdog_disk_hold_count(void)
{
    return atomic_load(&s_disk_hold_count);
}

void boot_sd_watchdog_format_hold_fields(char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    int last = atomic_load(&s_disk_hold_last);
    snprintf(out, cap, "disk_hold_count=%lu disk_hold_last=%s",
             atomic_load(&s_disk_hold_count),
             last < 0 ? "none"
                      : boot_sd_watchdog_disk_hold_name(
                            (enum boot_sd_disk_hold_verdict)last));
}

/* Owner tid of a glibc mutex (the lock word's owner field, set while held,
 * 0 when free). Racy by nature: read once, and the holder's own /proc state
 * is then read independently. Other libcs report 0 = unknown = no hold. */
static long mutex_owner_tid(const void *m)
{
#if defined(__GLIBC__)
    return m ? (long)((const pthread_mutex_t *)m)->__data.__owner : 0;
#else
    (void)m;
    return 0;
#endif
}

struct hold_lock_scratch {
    char stat[EVIDENCE_NLOCKS][EVIDENCE_FILE_MAX];
    char wchan[EVIDENCE_NLOCKS][64];
};

/* Fill the known-lock table: address, recorded holder, holder's /proc text. */
static void fill_known_locks(struct boot_sd_known_lock *kl,
                             struct hold_lock_scratch *sc)
{
    const void *addrs[EVIDENCE_NLOCKS];
    known_locks(addrs);
    for (size_t i = 0; i < EVIDENCE_NLOCKS; i++) {
        long holder = 0;
        if (i == 1) {
            if (!progress_store_tx_holder(&holder, NULL))
                holder = 0;
        } else {
            holder = mutex_owner_tid(addrs[i]);
        }
        kl[i] = (struct boot_sd_known_lock){ .addr = addrs[i],
                                             .holder_tid = holder };
        sc->stat[i][0] = sc->wchan[i][0] = '\0';
        if (holder > 0 &&
            os_proc_self_task_read(holder, "stat", sc->stat[i],
                                   sizeof(sc->stat[i])) &&
            os_proc_self_task_read(holder, "wchan", sc->wchan[i],
                                   sizeof(sc->wchan[i]))) {
            kl[i].holder_stat  = sc->stat[i];
            kl[i].holder_wchan = sc->wchan[i];
        }
    }
}

/* Append " <label>[task line]" to `evidence` while it fits. */
static void evidence_append(char *evidence, size_t cap, const char *label,
                            long tid, const char *stat, const char *wchan,
                            const char *sc)
{
    char line[192];
    size_t used = evidence ? strlen(evidence) : 0;
    if (!evidence || cap == 0 || used + 16 >= cap ||
        !boot_sd_watchdog_format_task_line(line, sizeof(line), tid, stat,
                                           wchan, sc))
        return;
    snprintf(evidence + used, cap - used, "%s%s[%s]", used ? " " : "", label,
             line);
}

/* Read one stalled pillar's /proc text and feed the accumulator. */
static void scan_one_pillar(struct boot_sd_hold_acc *acc, long tid,
                            const struct boot_sd_known_lock *kl, char *evidence,
                            size_t cap)
{
    char stat[EVIDENCE_FILE_MAX], wchan[64], sc[EVIDENCE_FILE_MAX];
    stat[0] = wchan[0] = sc[0] = '\0';
    bool ok = tid > 0 &&
              os_proc_self_task_read(tid, "stat", stat, sizeof(stat)) &&
              os_proc_self_task_read(tid, "wchan", wchan, sizeof(wchan));
    (void)os_proc_self_task_read(tid, "syscall", sc, sizeof(sc));
    struct boot_sd_pillar_obs p = { .tid = tid, .stat = ok ? stat : NULL,
                                    .wchan = ok ? wchan : NULL, .syscall = sc };
    boot_sd_watchdog_hold_acc_add_pillar(acc, &p, kl, EVIDENCE_NLOCKS);
    if (ok)
        evidence_append(evidence, cap, "pillar", tid, stat, wchan, sc);
}

/* Walk every thread once for the connman socket thread's liveness. A thread
 * that exited between listing and reading is skipped: only an unreadable
 * procfs as a whole is "missing /proc". */
static void scan_all_threads(struct boot_sd_hold_acc *acc)
{
    size_t total = 0;
    size_t n = os_proc_self_task_ids(s_scan.tids, EVIDENCE_SCAN_THREADS,
                                     &total);
    for (size_t i = 0; i < n; i++) {
        char stat[EVIDENCE_FILE_MAX], wchan[64];
        stat[0] = wchan[0] = '\0';
        if (os_proc_self_task_read(s_scan.tids[i], "stat", stat,
                                   sizeof(stat)) &&
            os_proc_self_task_read(s_scan.tids[i], "wchan", wchan,
                                   sizeof(wchan)))
            boot_sd_watchdog_hold_acc_add(acc, stat, wchan);
    }
}

/* Live scan. `pillar_tids` are the stalled pillar threads (the tick runner
 * and/or the connman loops whose heartbeat is dead). Reuses the snapshot's
 * static tid array and busy flag (one scan at a time; no malloc on a stalled
 * process). */
enum boot_sd_disk_hold_verdict
boot_sd_watchdog_disk_hold_scan(bool connman_started, bool sweep_alive,
                                int64_t held_us, const long *pillar_tids,
                                size_t npillars, long *d_tid, char *evidence,
                                size_t cap)
{
    if (evidence && cap)
        evidence[0] = '\0';
    if (d_tid)
        *d_tid = 0;
    if (atomic_flag_test_and_set(&s_scan_busy))
        return BOOT_SD_HOLD_NO_PROC;
    struct boot_sd_hold_acc acc = {0};
    struct boot_sd_known_lock kl[EVIDENCE_NLOCKS];
    struct hold_lock_scratch scratch;
    fill_known_locks(kl, &scratch);
    for (size_t i = 0; i < npillars; i++)
        scan_one_pillar(&acc, pillar_tids[i], kl, evidence, cap);
    for (size_t i = 0; i < EVIDENCE_NLOCKS; i++)
        if (kl[i].holder_stat)
            evidence_append(evidence, cap, "holder", kl[i].holder_tid,
                            kl[i].holder_stat, kl[i].holder_wchan, "");
    scan_all_threads(&acc);
    atomic_flag_clear(&s_scan_busy);
    if (d_tid)
        *d_tid = acc.d_tid;
    return boot_sd_watchdog_hold_acc_verdict(&acc, connman_started,
                                             sweep_alive, held_us,
                                             BOOT_SD_DISK_HOLD_GRACE_US);
}
