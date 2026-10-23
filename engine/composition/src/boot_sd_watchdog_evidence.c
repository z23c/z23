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
#include <stdio.h>
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

static void snapshot_one_task(long tid)
{
    char stat[EVIDENCE_FILE_MAX], wchan[64], sc[EVIDENCE_FILE_MAX];
    char line[192];
    bool ok = os_proc_self_task_read(tid, "stat", stat, sizeof(stat));
    (void)os_proc_self_task_read(tid, "wchan", wchan, sizeof(wchan));
    (void)os_proc_self_task_read(tid, "syscall", sc, sizeof(sc));
    if (ok && boot_sd_watchdog_format_task_line(line, sizeof(line), tid, stat,
                                                wchan, sc))
        LOG_WARN("boot", "[sd_watchdog] thread %s", line);
    else
        LOG_WARN("boot", "[sd_watchdog] thread tid=%ld unreadable", tid);
}

static void log_lock_addresses(void)
{
    struct chain_activation_controller *ctl = process_block_activation_controller();
    LOG_WARN("boot",
             "[sd_watchdog] lock addresses (match a futex a0): "
             "activation_mutex=%p progress_store_tx_lock=%p",
             ctl ? (const void *)&ctl->mutex : NULL,
             progress_store_tx_lock_addr());
}

void boot_sd_watchdog_log_thread_snapshot(void)
{
    long tids[EVIDENCE_MAX_THREADS];
    size_t total = 0;
    log_lock_addresses();
    size_t n = os_proc_self_task_ids(tids, EVIDENCE_MAX_THREADS, &total);
    if (n == 0) {
        LOG_WARN("boot", "[sd_watchdog] thread snapshot unavailable "
                 "(no per-thread procfs on this platform)");
        return;
    }
    for (size_t i = 0; i < n; i++)
        snapshot_one_task(tids[i]);
    LOG_WARN("boot", "[sd_watchdog] thread snapshot: threads=%zu "
             "truncated=%zu", n, total - n);
}
