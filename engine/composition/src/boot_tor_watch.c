/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_tor_watch — see config/boot_tor_watch.h for the contract and for the
 * 2026-09-08 incident this exists to make impossible to repeat silently. */

#include "config/boot_tor_watch.h"

#include "net/tor_integration.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

/* The armed instance, published for the tor_start_failed condition (whose
 * detect/remedy hooks take no context by construction). A registry POINTER,
 * not state: every mutable field lives in the caller's struct boot_svc_ctx.
 * Same shape as app_runtime_set_current() in config/runtime.h. */
static _Atomic(struct boot_tor_watch *) g_tor_watch;

/* ── Pure helpers ──────────────────────────────────────────────────── */

int64_t boot_tor_watch_delay_us(int attempts)
{
    int64_t delay = BOOT_TOR_RETRY_FIRST_US;
    for (int i = 0; i < attempts; i++) {
        if (delay >= BOOT_TOR_RETRY_CAP_US / BOOT_TOR_RETRY_GROWTH)
            return BOOT_TOR_RETRY_CAP_US;
        delay *= BOOT_TOR_RETRY_GROWTH;
    }
    return delay > BOOT_TOR_RETRY_CAP_US ? BOOT_TOR_RETRY_CAP_US : delay;
}

const char *boot_tor_fault_name(enum boot_tor_fault fault)
{
    switch (fault) {
    case BOOT_TOR_FAULT_NONE:           return "none";
    case BOOT_TOR_FAULT_PORT_IN_USE:    return "port_in_use";
    case BOOT_TOR_FAULT_DATADIR:        return "datadir";
    case BOOT_TOR_FAULT_CONFIG_INVALID: return "config_invalid";
    case BOOT_TOR_FAULT_EXITED:         return "exited";
    }
    return "exited";
}

enum boot_tor_fault boot_tor_fault_classify(const char *line)
{
    if (!line)
        return BOOT_TOR_FAULT_EXITED;
    /* Bind failure first: it is the CAUSE that the later config lines are
     * only the consequence of. */
    if (strstr(line, "Address already in use") ||
        strstr(line, "Could not bind to"))
        return BOOT_TOR_FAULT_PORT_IN_USE;
    if (strstr(line, "Permission denied") ||
        strstr(line, "DataDirectory") ||
        strstr(line, "lock file") ||
        strstr(line, "Could not open"))
        return BOOT_TOR_FAULT_DATADIR;
    if (strstr(line, "parse/validate config") ||
        strstr(line, "Reading config failed") ||
        strstr(line, "Unknown option"))
        return BOOT_TOR_FAULT_CONFIG_INVALID;
    return BOOT_TOR_FAULT_EXITED;
}

/* ── Onion redaction ───────────────────────────────────────────────── */

static bool tor_redact_is_base32(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
}

static void tor_redact_put(char *out, size_t cap, size_t *o,
                           const char *src, size_t n)
{
    for (size_t i = 0; i < n && *o + 1 < cap; i++)
        out[(*o)++] = src[i];
}

/* Length of the onion token starting at `s`, or 0 when there is none:
 * a base32 run followed by ".onion", or a bare 56-char v3 address. */
static size_t tor_redact_onion_span(const char *s)
{
    size_t run = 0;
    while (tor_redact_is_base32(s[run]))
        run++;
    if (run >= 16 && strncmp(s + run, ".onion", 6) == 0)
        return run + 6;
    if (run >= 56)
        return run;
    return 0;
}

bool boot_tor_redact_onion(const char *line, char *out, size_t cap)
{
    if (!out || cap == 0)
        return false;
    out[0] = '\0';
    if (!line)
        return true;

    size_t o = 0;
    for (size_t i = 0; line[i] && o + 1 < cap;) {
        size_t span = tor_redact_onion_span(line + i);
        if (span > 0) {
            tor_redact_put(out, cap, &o, "<onion>", 7);
            i += span;
            continue;
        }
        /* Not an onion: copy the whole base32 run in one go so the scan
         * cannot re-inspect its interior and mistake a suffix for an
         * address. */
        size_t run = 0;
        while (tor_redact_is_base32(line[i + run]))
            run++;
        if (run == 0)
            run = 1;
        tor_redact_put(out, cap, &o, line + i, run);
        i += run;
    }
    out[o] = '\0';
    return true;
}

/* ── tor.log scan ──────────────────────────────────────────────────── */

static bool tor_log_is_warning(const char *line)
{
    return strstr(line, "[warn]") != NULL || strstr(line, "[err]") != NULL;
}

/* Fold one line into the running (class, quote) pair. */
static void tor_log_fold_line(char *line, enum boot_tor_fault *best,
                              char *out, size_t cap)
{
    if (!tor_log_is_warning(line))
        return;
    enum boot_tor_fault got = boot_tor_fault_classify(line);
    if (*best != BOOT_TOR_FAULT_NONE && got >= *best)
        return;
    *best = got;
    (void)boot_tor_redact_onion(line, out, cap);
}

enum boot_tor_fault boot_tor_log_scan_fault(const char *path, long scan_from,
                                            char *out, size_t cap)
{
    if (out && cap > 0)
        out[0] = '\0';
    if (!path || !out || cap == 0)
        return BOOT_TOR_FAULT_NONE;

    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_WARN("onion_tor", "tor log unreadable at %s; reason unnamed",
                  path);
        return BOOT_TOR_FAULT_NONE;
    }
    if (scan_from > 0 && fseek(f, scan_from, SEEK_SET) != 0) {
        LOG_WARN("onion_tor", "tor log seek to %ld failed at %s",
                  scan_from, path);
        fclose(f);
        return BOOT_TOR_FAULT_NONE;
    }

    enum boot_tor_fault best = BOOT_TOR_FAULT_NONE;
    char line[512];
    while (fgets(line, (int)sizeof(line), f))
        tor_log_fold_line(line, &best, out, cap);
    fclose(f);

    /* fgets keeps the newline; a status/blocker string must not carry one. */
    size_t n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
    return best;
}

/* Byte offset the scan should start from: the last BOOT_TOR_LOG_TAIL_BYTES
 * of the file, so a log that has appended across many boots does not make
 * the scan quote a dead instance's warning. */
static long tor_log_tail_offset(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    long size = 0;
    if (fseek(f, 0, SEEK_END) == 0)
        size = ftell(f);
    fclose(f);
    if (size <= BOOT_TOR_LOG_TAIL_BYTES)
        return 0;
    return size - BOOT_TOR_LOG_TAIL_BYTES;
}

/* ── Arm / observe / retry ─────────────────────────────────────────── */

void boot_tor_watch_arm(struct boot_tor_watch *w, const char *datadir,
                        boot_tor_restart_fn restart, void *restart_ctx)
{
    if (!w || !datadir || !restart) {
        LOG_WARN("onion_tor",
                 "tor watch not armed (watch=%d datadir=%d restart=%d); a "
                 "failed Tor start would go unretried",
                 w != NULL, datadir != NULL, restart != NULL);
        return;
    }
    if (atomic_load(&w->armed))
        return;

    snprintf(w->datadir, sizeof(w->datadir), "%s", datadir);
    w->restart = restart;
    w->restart_ctx = restart_ctx;
    atomic_store(&w->attempts, 0);
    atomic_store(&w->fault, (int)BOOT_TOR_FAULT_NONE);
    atomic_store(&w->next_attempt_us, 0);
    atomic_store(&w->last_attempt_us, 0);
    atomic_store(&w->armed, true);
    atomic_store(&g_tor_watch, w);
}

void boot_tor_watch_disarm(struct boot_tor_watch *w)
{
    if (!w)
        return;
    /* Unpublish BEFORE clearing: the condition ring can be mid-tick. */
    struct boot_tor_watch *cur = w;
    (void)atomic_compare_exchange_strong(&g_tor_watch, &cur, NULL);
    atomic_store(&w->armed, false);
}

struct boot_tor_watch *boot_tor_watch_current(void)
{
    return atomic_load(&g_tor_watch);
}

bool boot_tor_watch_failed(const struct boot_tor_watch *w)
{
    if (!w || !atomic_load(&w->armed))
        return false;
    /* Both halves come from core's own predicates. is_requested() is sticky
     * until tor_integration_stop(), is_enabled() follows the live thread —
     * so a thread that dies long after boot reads exactly like one that
     * never started. */
    return tor_integration_is_requested() && !tor_integration_is_enabled();
}

void boot_tor_watch_capture_fault(struct boot_tor_watch *w,
                                  char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = '\0';
    if (!w)
        return;

    char path[1024];
    enum boot_tor_fault fault = BOOT_TOR_FAULT_EXITED;
    if (tor_log_path(w->datadir, path, sizeof(path))) {
        enum boot_tor_fault seen =
            boot_tor_log_scan_fault(path, tor_log_tail_offset(path), out, cap);
        if (seen != BOOT_TOR_FAULT_NONE)
            fault = seen;
    } else {
        LOG_WARN("onion_tor",
                 "tor log path does not fit under datadir; the Tor failure "
                 "reason stays unquoted");
    }
    atomic_store(&w->fault, (int)fault);
    if (out[0] == '\0')
        snprintf(out, cap, "embedded Tor exited during startup (%s)",
                 boot_tor_fault_name(fault));
}

bool boot_tor_watch_due(const struct boot_tor_watch *w, int64_t now_us)
{
    if (!w || !atomic_load(&w->armed))
        return false;
    int64_t due = atomic_load(&w->next_attempt_us);
    return due == 0 || now_us >= due;
}

bool boot_tor_watch_retry(struct boot_tor_watch *w, int64_t now_us)
{
    if (!w || !atomic_load(&w->armed) || !w->restart)
        return false;

    int attempts = atomic_load(&w->attempts);
    int64_t delay = boot_tor_watch_delay_us(attempts);
    atomic_store(&w->attempts, attempts + 1);
    atomic_store(&w->last_attempt_us, now_us);
    atomic_store(&w->next_attempt_us, now_us + delay);

    LOG_WARN("onion_tor",
             "retrying embedded Tor start: attempt=%d reason=%s "
             "next_retry_in=%llds",
             attempts + 1,
             boot_tor_fault_name((enum boot_tor_fault)atomic_load(&w->fault)),
             (long long)(delay / 1000000));
    bool ok = w->restart(w->restart_ctx);
    if (!ok)
        LOG_WARN("onion_tor",
                 "embedded Tor start attempt %d returned failure; the watch "
                 "keeps retrying", attempts + 1);
    return ok;
}

void boot_tor_watch_note_up(struct boot_tor_watch *w)
{
    if (!w)
        return;
    atomic_store(&w->attempts, 0);
    atomic_store(&w->fault, (int)BOOT_TOR_FAULT_NONE);
    atomic_store(&w->next_attempt_us, 0);
}

/* ── Status leg ────────────────────────────────────────────────────── */

void boot_tor_watch_status(const struct boot_tor_watch *w,
                           char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    if (!tor_integration_is_requested() && !tor_integration_is_enabled()) {
        snprintf(out, cap, "tor=off");
        return;
    }
    if (tor_integration_is_ready()) {
        snprintf(out, cap, "tor=ok");
        return;
    }
    if (!w || !atomic_load(&w->armed) || tor_integration_is_enabled()) {
        /* The thread is alive (or the watch is not armed yet): Tor is
         * bootstrapping. That is a different operator answer from "it never
         * came up", which is the whole point of this leg. */
        snprintf(out, cap, "tor=starting");
        return;
    }
    snprintf(out, cap, "tor=failed(%s)",
             boot_tor_fault_name((enum boot_tor_fault)atomic_load(&w->fault)));
}
