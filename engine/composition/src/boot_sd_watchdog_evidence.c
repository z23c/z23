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
 * The lock-evidence block adds what the 11-16 stall lacked: which address
 * everybody waited on, its name when registered, its holder, and whether
 * the holder's IO advanced. The withhold edge may sleep for the IO sample
 * pair (BOOT_SD_LOCK_EVIDENCE_IO_GAP_US); it is already not pinging.
 */

#include "base/format_attribute.h"
#include "config/boot_internal.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/reducer_drive_guard.h"
#include "util/supervisor.h"
#include "storage/progress_store.h"
#include "services/chain_activation_service.h"
#include "validation/process_block.h"
#include <pthread.h>
#include <stdarg.h>
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

/* Evidence-only named addresses. A slot's name is claimed once (CAS) and then
 * only its address changes; a NULL address is an empty row. Names are never
 * released (a clear keeps the name for the next register), so a reader never
 * sees a name change under it and at most BOOT_SD_NAMED_LOCK_MAX distinct
 * names are ever registered. known_locks() reads exactly one slot,
 * BOOT_SD_NODE_DB_LOCK_NAME, as the hold verdict's fourth known lock; a NULL
 * (cleared or never registered) address there is skipped like any absent
 * known lock. Every other named address is evidence only. */
static struct {
    _Atomic(const char *) name;
    _Atomic(const void *) addr;
} s_named[BOOT_SD_NAMED_LOCK_MAX];

/* The slot whose name is `name`, or -1. */
static int named_slot(const char *name)
{
    for (size_t i = 0; i < BOOT_SD_NAMED_LOCK_MAX; i++) {
        const char *n = atomic_load(&s_named[i].name);
        if (n && strcmp(n, name) == 0)
            return (int)i;
    }
    return -1;
}

static bool named_lock_set_existing(const char *name, const void *addr)
{
    int i = named_slot(name);
    if (i < 0)
        return false;
    atomic_store(&s_named[i].addr, addr);
    return true;
}

/* The address registered under `name`, or NULL. */
static const void *named_lock_addr(const char *name)
{
    int i = named_slot(name);
    return i < 0 ? NULL : atomic_load(&s_named[i].addr);
}

bool boot_sd_watchdog_register_named_lock(const char *name, const void *addr)
{
    if (!name || !name[0])
        return false;
    if (named_lock_set_existing(name, addr))
        return true;
    if (!addr)
        return true; /* clearing a name that was never registered */
    for (size_t i = 0; i < BOOT_SD_NAMED_LOCK_MAX; i++) {
        const char *expect = NULL;
        if (atomic_compare_exchange_strong(&s_named[i].name, &expect, name)) {
            atomic_store(&s_named[i].addr, addr);
            return true;
        }
    }
    return false;
}

bool boot_sd_watchdog_early_warn_due(const int64_t ages_us[3],
                                     int64_t bound_us, int64_t now_us,
                                     int64_t *last_log_us)
{
    if (!ages_us || !last_log_us || bound_us <= 0)
        return false;
    bool late = false;
    for (size_t i = 0; i < 3; i++)
        if (ages_us[i] >= 0 && ages_us[i] > bound_us / 2)
            late = true;
    if (!late)
        return false;
    if (*last_log_us != 0 && now_us - *last_log_us < BOOT_SD_EARLY_WARN_LOG_US)
        return false;
    *last_log_us = now_us;
    return true;
}

/* Known locks, in this order: activation mutex, progress_store_tx_lock,
 * cs_main, node.db's SQLite connection mutex (a recursive pthread mutex whose
 * address is its futex word; registered off the pet thread, cleared before
 * node.db closes or when its handle changes). */
#define EVIDENCE_NLOCKS 4
static void known_locks(const void **locks)
{
    struct chain_activation_controller *ctl = process_block_activation_controller();
    locks[0] = ctl ? (const void *)&ctl->mutex : NULL;
    locks[1] = progress_store_tx_lock_addr();
    locks[2] = atomic_load(&s_cs_main_addr);
    locks[3] = named_lock_addr(BOOT_SD_NODE_DB_LOCK_NAME);
}

static void log_lock_addresses(const void *const *locks)
{
    LOG_WARN("boot",
             "[sd_watchdog] lock addresses (match a futex a0): "
             "activation_mutex=%p progress_store_tx_lock=%p cs_main=%p "
             "%s=%p", locks[0], locks[1], locks[2],
             BOOT_SD_NODE_DB_LOCK_NAME, locks[3]);
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

/* The scan arrays (~54 KB) live in static storage, not on the pet thread's
 * stack. One snapshot at a time: the pet thread is the only caller, and an
 * overlapping call is refused rather than sharing the arrays. Static, not
 * malloc: a stalled thread may hold the allocator's lock. `fx` is each
 * thread's futex-wait word (0 = not in a futex wait), `d` its st=D flag. */
static struct {
    long tids[EVIDENCE_SCAN_THREADS];
    unsigned char prio[EVIDENCE_SCAN_THREADS];
    size_t order[EVIDENCE_SCAN_THREADS];
    unsigned long long fx[EVIDENCE_SCAN_THREADS];
    bool d[EVIDENCE_SCAN_THREADS];
} s_scan;
static atomic_flag s_scan_busy = ATOMIC_FLAG_INIT;

static unsigned long long futex_wait_addr(const char *syscall_text);
static long mutex_owner_tid(const void *m);

static bool stat_is_d(const char *stat)
{
    char comm[32];
    char state = '?';
    return stat && task_parse_stat(stat, comm, sizeof(comm), &state) &&
           state == 'D';
}

/* One /proc read per thread feeds the print priority, the futex-word table
 * and the D-state set. */
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
        s_scan.fx[i] = has_sc ? futex_wait_addr(sc) : 0;
        s_scan.d[i] = ok && stat_is_d(stat);
    }
}

/* ── Lock evidence (withhold edge, log only) ─────────────────────────────
 *
 * 11-16 incident: ~28 threads futex-waited on one address that was then none
 * of the known locks (node.db's connection mutex, now the fourth), and the
 * snapshot could not say whose lock it was, who held
 * it, or whether the holder's IO moved. This block answers those three from
 * the per-thread rows the snapshot already reads: waiter counts per futex
 * word, the evidence-only NAMED addresses, each row's owner (read as a
 * pthread mutex owner ONLY for named and known locks; an unknown word may be
 * a condvar or an atomic and is never dereferenced), and two IO samples for
 * every D-state thread and owner. Nothing in this block feeds the hold
 * verdict (the verdict reads known_locks() itself). */

#define EVIDENCE_HOT_MIN   3
#define EVIDENCE_HOT_LINES 6
#define EVIDENCE_IO_MAX    8
#define EVIDENCE_ROWS      (EVIDENCE_HOT_LINES + BOOT_SD_NAMED_LOCK_MAX)

struct lock_row {
    unsigned long long addr;
    const char *name;   /* "unknown" when neither named nor known */
    size_t waiters;
    long owner;         /* > 0 tid, 0 = free/none, -1 = not readable */
};

static struct {
    struct lock_row rows[EVIDENCE_ROWS];
    size_t nrows, hot_total, nnamed;
} s_lk;

static const char *const k_known_names[EVIDENCE_NLOCKS] = {
    "activation_mutex", "progress_store_tx_lock", "cs_main",
    BOOT_SD_NODE_DB_LOCK_NAME,
};

static size_t count_waiters(unsigned long long addr, size_t n)
{
    size_t w = 0;
    for (size_t i = 0; i < n; i++)
        w += s_scan.fx[i] == addr;
    return w;
}

/* Keep the EVIDENCE_HOT_LINES busiest runs, most waiters first. */
static void hot_insert(unsigned long long addr, size_t waiters)
{
    size_t keep = s_lk.nrows < EVIDENCE_HOT_LINES ? s_lk.nrows + 1
                                                  : EVIDENCE_HOT_LINES;
    size_t at = s_lk.nrows < keep ? s_lk.nrows : keep;
    while (at > 0 && s_lk.rows[at - 1].waiters < waiters)
        at--;
    if (at >= keep)
        return;
    for (size_t j = keep - 1; j > at; j--)
        s_lk.rows[j] = s_lk.rows[j - 1];
    s_lk.rows[at] = (struct lock_row){ .addr = addr, .waiters = waiters };
    s_lk.nrows = keep;
}

static bool futex_word_seen_before(size_t i)
{
    for (size_t j = 0; j < i; j++)
        if (s_scan.fx[j] == s_scan.fx[i])
            return true;
    return false;
}

/* Count each distinct futex word once (first occurrence) and keep those with
 * >= EVIDENCE_HOT_MIN waiters. Quadratic over at most EVIDENCE_SCAN_THREADS
 * words and allocation-free: no qsort, whose glibc mergesort mallocs. */
static void collect_hot(size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (!s_scan.fx[i] || futex_word_seen_before(i))
            continue;
        size_t w = count_waiters(s_scan.fx[i], n);
        if (w >= EVIDENCE_HOT_MIN) {
            s_lk.hot_total++;
            hot_insert(s_scan.fx[i], w);
        }
    }
}

/* Name and owner for a row: named first, then a known lock, else unknown. */
static void label_row(struct lock_row *r, const void *const *locks)
{
    r->name = "unknown";
    r->owner = -1;
    for (size_t i = 0; i < BOOT_SD_NAMED_LOCK_MAX; i++) {
        const void *a = atomic_load(&s_named[i].addr);
        const char *nm = atomic_load(&s_named[i].name);
        if (a && nm && (unsigned long long)(uintptr_t)a == r->addr) {
            r->name = nm;
            r->owner = mutex_owner_tid(a);
            return;
        }
    }
    for (size_t i = 0; i < EVIDENCE_NLOCKS; i++) {
        if (!locks[i] || (unsigned long long)(uintptr_t)locks[i] != r->addr)
            continue;
        long holder = 0;
        if (i == 1 && !progress_store_tx_holder(&holder, NULL))
            holder = 0;
        r->name = k_known_names[i];
        r->owner = i == 1 ? holder : mutex_owner_tid(locks[i]);
        return;
    }
}

static bool row_has_addr(unsigned long long addr)
{
    for (size_t i = 0; i < s_lk.nrows; i++)
        if (s_lk.rows[i].addr == addr)
            return true;
    return false;
}

/* Hot rows, then every registered named address not already among them. */
static void collect_lock_rows(size_t n, const void *const *locks)
{
    s_lk.nrows = s_lk.hot_total = s_lk.nnamed = 0;
    collect_hot(n);
    for (size_t i = 0; i < BOOT_SD_NAMED_LOCK_MAX; i++) {
        const void *a = atomic_load(&s_named[i].addr);
        if (!a)
            continue;
        s_lk.nnamed++;
        unsigned long long addr = (unsigned long long)(uintptr_t)a;
        if (row_has_addr(addr) || s_lk.nrows >= EVIDENCE_ROWS)
            continue;
        s_lk.rows[s_lk.nrows++] = (struct lock_row){
            .addr = addr, .waiters = count_waiters(addr, n) };
    }
    for (size_t i = 0; i < s_lk.nrows; i++)
        label_row(&s_lk.rows[i], locks);
}

static bool ref_has_addr(const struct boot_sd_lock_ref *rows, size_t nrows,
                         unsigned long long addr)
{
    for (size_t r = 0; r < nrows; r++)
        if (rows[r].addr == addr)
            return true;
    return false;
}

static size_t promote_owners(unsigned char *prio, const long *tids, size_t n,
                             const struct boot_sd_lock_ref *rows, size_t nrows)
{
    size_t promoted = 0;
    for (size_t r = 0; r < nrows; r++) {
        for (size_t i = 0; rows[r].owner > 0 && i < n; i++) {
            if (tids[i] != rows[r].owner || prio[i] == 0)
                continue;
            prio[i] = 0;
            promoted++;
            break;
        }
    }
    return promoted;
}

/* Truncation rule, extended: owners always print; waiters on a row's address
 * print while the never-cut set stays within `cap`. */
size_t boot_sd_watchdog_promote_lock_threads(unsigned char *prio,
                                             const long *tids,
                                             const unsigned long long *fx,
                                             size_t n,
                                             const struct boot_sd_lock_ref *rows,
                                             size_t nrows, size_t cap)
{
    if (!prio || !tids || !fx || (!rows && nrows))
        return 0;
    size_t p0 = 0;
    for (size_t i = 0; i < n; i++)
        p0 += prio[i] == 0;
    p0 += promote_owners(prio, tids, n, rows, nrows);
    for (size_t i = 0; i < n && p0 < cap; i++) {
        if (prio[i] != 0 && fx[i] && ref_has_addr(rows, nrows, fx[i])) {
            prio[i] = 0;
            p0++;
        }
    }
    return p0;
}

static void promote_lock_threads(size_t n)
{
    struct boot_sd_lock_ref refs[EVIDENCE_ROWS];
    for (size_t r = 0; r < s_lk.nrows; r++)
        refs[r] = (struct boot_sd_lock_ref){ .addr = s_lk.rows[r].addr,
                                             .owner = s_lk.rows[r].owner };
    (void)boot_sd_watchdog_promote_lock_threads(s_scan.prio, s_scan.tids,
                                                s_scan.fx, n, refs,
                                                s_lk.nrows,
                                                EVIDENCE_MAX_THREADS);
}

struct ev_text {
    char *buf;
    size_t cap, used, lines;
};

ZCL_PRINTF_LIKE(2, 3)
static void ev_line(struct ev_text *t, const char *fmt, ...)
{
    if (t->lines >= BOOT_SD_LOCK_EVIDENCE_MAX_LINES || t->used + 2 >= t->cap)
        return;
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(t->buf + t->used, t->cap - t->used - 1, fmt, ap);
    va_end(ap);
    if (w < 0)
        return;
    size_t room = t->cap - t->used - 2;
    t->used += (size_t)w < room ? (size_t)w : room;
    t->buf[t->used++] = '\n';
    t->buf[t->used] = '\0';
    t->lines++;
}

/* "owner_tid=<tid> owner[<task line>]" or the reason there is none. */
static void format_owner(char *out, size_t cap, long owner)
{
    char stat[EVIDENCE_FILE_MAX], wchan[64], sc[EVIDENCE_FILE_MAX];
    char line[192];
    stat[0] = wchan[0] = sc[0] = '\0';
    if (owner < 0) {
        snprintf(out, cap, "owner_tid=unknown");
        return;
    }
    if (owner == 0) {
        snprintf(out, cap, "owner_tid=none");
        return;
    }
    bool ok = os_proc_self_task_read(owner, "stat", stat, sizeof(stat));
    (void)os_proc_self_task_read(owner, "wchan", wchan, sizeof(wchan));
    (void)os_proc_self_task_read(owner, "syscall", sc, sizeof(sc));
    if (ok && boot_sd_watchdog_format_task_line(line, sizeof(line), owner,
                                                stat, wchan, sc))
        snprintf(out, cap, "owner_tid=%ld owner[%s]", owner, line);
    else
        snprintf(out, cap, "owner_tid=%ld owner[unreadable]", owner);
}

static void format_lock_rows(struct ev_text *t, size_t n)
{
    ev_line(t, "hot futex addresses (>=%d waiters): hot=%zu shown=%zu "
            "named=%zu threads=%zu", EVIDENCE_HOT_MIN, s_lk.hot_total,
            s_lk.hot_total < EVIDENCE_HOT_LINES ? s_lk.hot_total
                                                : (size_t)EVIDENCE_HOT_LINES,
            s_lk.nnamed, n);
    for (size_t i = 0; i < s_lk.nrows; i++) {
        char owner[256];
        format_owner(owner, sizeof(owner), s_lk.rows[i].owner);
        ev_line(t, "lock addr=0x%llx name=%s waiters=%zu %s",
                s_lk.rows[i].addr, s_lk.rows[i].name, s_lk.rows[i].waiters,
                owner);
    }
}

struct io_pick {
    long tid;
    const char *why;
    struct boot_sd_io_sample a, b;
};

static size_t io_pick_add(struct io_pick *p, size_t k, long tid,
                          const char *why)
{
    if (tid <= 0 || k >= EVIDENCE_IO_MAX)
        return k;
    for (size_t i = 0; i < k; i++)
        if (p[i].tid == tid)
            return k;
    p[k] = (struct io_pick){ .tid = tid, .why = why };
    return k + 1;
}

/* Owners first (the holder is the question), then D-state threads. */
static size_t pick_io_tids(struct io_pick *p, size_t n)
{
    size_t k = 0;
    for (size_t r = 0; r < s_lk.nrows; r++)
        k = io_pick_add(p, k, s_lk.rows[r].owner, "owner");
    for (size_t i = 0; i < n; i++)
        if (s_scan.d[i])
            k = io_pick_add(p, k, s_scan.tids[i], "d-state");
    return k;
}

static long long io_delta(uint64_t a, uint64_t b)
{
    return (long long)(b - a);
}

/* stat fields by number (proc(5)): 3 is the state letter, then numbers;
 * tpgid (8) may be -1, so only the wanted fields are parsed as digits. */
#define IO_STAT_FIELD_STATE  3
#define IO_STAT_FIELD_MAJFLT 12
#define IO_STAT_FIELD_UTIME  14
#define IO_STAT_FIELD_STIME  15

/* Step over one space-separated token; when `v` is set it must be all
 * decimal digits without overflow. No strtoull: nothing here allocates. */
static bool stat_token(const char **p, uint64_t *v)
{
    const char *s = *p;
    while (*s == ' ')
        s++;
    const char *e = s;
    while (*e && *e != ' ' && *e != '\n')
        e++;
    if (e == s)
        return false;
    *p = e;
    if (!v)
        return true;
    uint64_t x = 0;
    for (const char *c = s; c < e; c++) {
        if (*c < '0' || *c > '9' || x > (UINT64_MAX - 9) / 10)
            return false;
        x = x * 10 + (uint64_t)(*c - '0');
    }
    *v = x;
    return true;
}

bool boot_sd_watchdog_parse_io_sample(const char *stat,
                                      struct boot_sd_io_sample *out)
{
    if (!out)
        return false;
    out->ok = false;
    const char *p = stat ? strrchr(stat, ')') : NULL;
    if (!p)
        return false;
    p++;
    uint64_t majflt = 0, utime = 0, stime = 0;
    for (int f = IO_STAT_FIELD_STATE; f <= IO_STAT_FIELD_STIME; f++) {
        uint64_t *v = f == IO_STAT_FIELD_MAJFLT ? &majflt
                    : f == IO_STAT_FIELD_UTIME  ? &utime
                    : f == IO_STAT_FIELD_STIME  ? &stime : NULL;
        if (!stat_token(&p, v))
            return false;
    }
    *out = (struct boot_sd_io_sample){ .ok = true, .cpu_ticks = utime + stime,
                                       .majflt = majflt };
    return true;
}

static void format_io_sample(char *out, size_t cap,
                             const struct boot_sd_io_sample *s)
{
    if (s && s->ok)
        snprintf(out, cap, "cpu_ticks:%llu,majflt:%llu",
                 (unsigned long long)s->cpu_ticks,
                 (unsigned long long)s->majflt);
    else
        snprintf(out, cap, "unavailable");
}

void boot_sd_watchdog_format_io_line(char *out, size_t cap, long tid,
                                     const char *why,
                                     const struct boot_sd_io_sample *a,
                                     const struct boot_sd_io_sample *b,
                                     int64_t gap_us)
{
    if (!out || cap == 0)
        return;
    const char *w = why ? why : "?";
    long long gap_ms = (long long)(gap_us / 1000);
    if (!a || !b || !a->ok || !b->ok) {
        char sa[64], sb[64];
        format_io_sample(sa, sizeof(sa), a);
        format_io_sample(sb, sizeof(sb), b);
        snprintf(out, cap, "io tid=%ld why=%s sample_a=%s sample_b=%s "
                 "blk_io_bytes=unavailable gap_ms=%lld", tid, w, sa, sb,
                 gap_ms);
        return;
    }
    snprintf(out, cap, "io tid=%ld why=%s cpu_ticks=%llu->%llu(%+lld) "
             "majflt=%llu->%llu(%+lld) blk_io_bytes=unavailable gap_ms=%lld",
             tid, w, (unsigned long long)a->cpu_ticks,
             (unsigned long long)b->cpu_ticks,
             io_delta(a->cpu_ticks, b->cpu_ticks),
             (unsigned long long)a->majflt, (unsigned long long)b->majflt,
             io_delta(a->majflt, b->majflt), gap_ms);
}

/* open/read/close of the task stat file into a stack buffer: no stdio, no
 * allocation (a stalled thread may hold the allocator's lock). */
static void read_io_sample(long tid, struct boot_sd_io_sample *s)
{
    char stat[EVIDENCE_FILE_MAX];
    s->ok = false;
    if (os_proc_self_task_read(tid, "stat", stat, sizeof(stat)))
        (void)boot_sd_watchdog_parse_io_sample(stat, s);
}

static void format_io_samples(struct ev_text *t, size_t n, int64_t gap_us)
{
    struct io_pick picks[EVIDENCE_IO_MAX];
    size_t k = pick_io_tids(picks, n);
    if (k == 0)
        return;
    for (size_t i = 0; i < k; i++)
        read_io_sample(picks[i].tid, &picks[i].a);
    int64_t waited = boot_sd_watchdog_evidence_sleep(gap_us);
    for (size_t i = 0; i < k; i++)
        read_io_sample(picks[i].tid, &picks[i].b);
    for (size_t i = 0; i < k; i++) {
        char line[256];
        boot_sd_watchdog_format_io_line(line, sizeof(line), picks[i].tid,
                                        picks[i].why, &picks[i].a,
                                        &picks[i].b, waited);
        ev_line(t, "%s", line);
    }
}

/* First line of /proc/pressure/io, or "unavailable". */
static void format_pressure(struct ev_text *t)
{
    char buf[256] = "";
    bool ok = boot_sd_watchdog_read_pressure_io(buf, sizeof(buf));
    ev_line(t, "pressure io: %s", ok ? buf : "unavailable");
}

static size_t format_lock_evidence_text(char *out, size_t cap, size_t n,
                                        int64_t io_gap_us)
{
    struct ev_text t = { .buf = out, .cap = cap };
    out[0] = '\0';
    format_lock_rows(&t, n);
    format_io_samples(&t, n, io_gap_us);
    format_pressure(&t);
    return t.lines;
}

#ifdef ZCL_TESTING
size_t boot_sd_watchdog_format_lock_evidence(char *out, size_t cap,
                                             int64_t io_gap_us)
{
    if (!out || cap == 0)
        return 0;
    out[0] = '\0';
    if (atomic_flag_test_and_set(&s_scan_busy))
        return 0;
    const void *locks[EVIDENCE_NLOCKS];
    size_t total = 0;
    known_locks(locks);
    size_t n = os_proc_self_task_ids(s_scan.tids, EVIDENCE_SCAN_THREADS, &total);
    classify_tasks(s_scan.tids, n, locks, s_scan.prio);
    collect_lock_rows(n, locks);
    size_t lines = format_lock_evidence_text(out, cap, n, io_gap_us);
    atomic_flag_clear(&s_scan_busy);
    return lines;
}
#endif

/* One WARN line per evidence line. Walked by hand (no strtok state). */
static void log_lock_evidence(size_t n, int64_t io_gap_us)
{
    static char text[8192];
    (void)format_lock_evidence_text(text, sizeof(text), n, io_gap_us);
    char *s = text;
    while (*s) {
        char *nl = strchr(s, '\n');
        if (nl)
            *nl = '\0';
        LOG_WARN("boot", "[sd_watchdog] %s", s);
        if (!nl)
            break;
        s = nl + 1;
    }
}

static int64_t elapsed_since(int64_t start_us)
{
    int64_t d = platform_time_monotonic_us() - start_us;
    return d > 0 ? d : 0;
}

/* Returns the microseconds of the lock-evidence block only (row collection
 * and promotion, then the evidence text with its IO gap and log lines); the
 * base snapshot prints between them stay untimed, as on base. */
static int64_t log_thread_snapshot_scan(int64_t io_gap_us)
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
        return 0;
    }
    classify_tasks(s_scan.tids, n, locks, s_scan.prio);
    int64_t t0 = platform_time_monotonic_us();
    collect_lock_rows(n, locks);
    promote_lock_threads(n);
    int64_t lock_us = elapsed_since(t0);
    size_t shown = boot_sd_watchdog_order_snapshot(s_scan.prio, n,
                                                   EVIDENCE_MAX_THREADS,
                                                   s_scan.order);
    for (size_t i = 0; i < shown; i++)
        snapshot_one_task(s_scan.tids[s_scan.order[i]],
                          s_scan.prio[s_scan.order[i]] == 0);
    LOG_WARN("boot", "[sd_watchdog] thread snapshot: threads=%zu "
             "truncated=%zu unscanned=%zu", shown, n - shown,
             total - n);
    int64_t t1 = platform_time_monotonic_us();
    log_lock_evidence(n, io_gap_us);
    return lock_us + elapsed_since(t1);
}

int64_t boot_sd_watchdog_log_thread_snapshot(int64_t io_gap_us)
{
    if (atomic_flag_test_and_set(&s_scan_busy)) {
        LOG_WARN("boot", "[sd_watchdog] thread snapshot already running; "
                 "skipped");
        return 0;
    }
    int64_t lock_us = log_thread_snapshot_scan(io_gap_us);
    atomic_flag_clear(&s_scan_busy);
    return lock_us;
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

#ifdef ZCL_TESTING
size_t boot_sd_watchdog_test_known_locks(struct boot_sd_known_lock *out,
                                         size_t cap)
{
    static struct hold_lock_scratch s_test_scratch;
    struct boot_sd_known_lock kl[EVIDENCE_NLOCKS];
    if (!out)
        return 0;
    fill_known_locks(kl, &s_test_scratch);
    size_t n = 0;
    for (; n < EVIDENCE_NLOCKS && n < cap; n++)
        out[n] = kl[n];
    return n;
}
#endif

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
