/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev_activation_verify.c — bounded post-restart verification, quarantine, and
 * rollback for the native dev-lane activation engine. Split from
 * dev_activation.c along the verify/rollback seam (file-size ceiling). Uses the
 * ops vtable for every service action, so it too is exercisable with a fake
 * ops implementation and carries no direct process exec.
 */

#define _GNU_SOURCE

#include "dev_activation.h"
#include "dev_activation_internal.h"

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Sleep for `ms` milliseconds (bounded verify poll cadence). */
static void dev_sleep_ms(long ms)
{
    struct timespec ts = { .tv_sec = ms / 1000,
                           .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

long dev_activation_verify_timeout_seconds(bool recovery_boot)
{
    long timeout_s = DEV_ACTIVATION_VERIFY_TIMEOUT_S;
    if (recovery_boot && DEV_ACTIVATION_RECOVERY_VERIFY_TIMEOUT_S > timeout_s)
        timeout_s = DEV_ACTIVATION_RECOVERY_VERIFY_TIMEOUT_S;
    const char *ev = getenv("ZCL_DEV_ACTIVATION_VERIFY_TIMEOUT_S");
    if (ev && *ev) {
        char *end = NULL;
        long v = strtol(ev, &end, 10);
        if (end && *end == '\0' && v >= 0 && v <= 3600)
            timeout_s = v;
    }
    return timeout_s;
}

bool dev_activation_verify_running(struct dev_activation_txn *txn,
                                   const char *expected)
{
    const struct dev_activation_ops *ops = txn->ops;
    char expected_bin[PATH_MAX], expected_canon[PATH_MAX];
    int n = snprintf(expected_bin, sizeof(expected_bin),
                     "%s/%s/zclassic23-dev", txn->gen_root, expected);
    if (n <= 0 || (size_t)n >= sizeof(expected_bin))
        LOG_FAIL("dev-activation", "verify expected bin path overflow");
    if (!dev_activation_canon(expected_bin, expected_canon,
                              sizeof(expected_canon)))
        return false;

    char source_id[65];
    dev_activation_generation_source_id(txn, expected, source_id);
    if (!source_id[0])
        return false;

    /* Both paths are bounded; recovery_boot remains a distinct policy input
     * even when measured full-datadir startup currently gives both 1200 s. */
    long timeout_s = dev_activation_verify_timeout_seconds(
        txn->recovery_boot);

    txn->result->running_generation[0] = 0;
    int64_t deadline = platform_time_monotonic_us() +
        (int64_t)timeout_s * 1000000;
    for (;;) {
        if (ops->service_active(ops->ctx) == 0) {
            long pid = 0;
            char exe[PATH_MAX], exe_canon[PATH_MAX];
            if (ops->service_main_pid(ops->ctx, &pid) == 0 && pid > 0 &&
                ops->running_exe(ops->ctx, pid, exe, sizeof(exe)) == 0 &&
                dev_activation_canon(exe, exe_canon, sizeof(exe_canon)) &&
                strcmp(exe_canon, expected_canon) == 0) {
                snprintf(txn->result->running_generation,
                         sizeof(txn->result->running_generation), "%s",
                         expected);
                if (ops->activation_probe(ops->ctx, expected, source_id) == 0)
                    return true;
            }
        }
        if (platform_time_monotonic_us() >= deadline)
            break;
        dev_sleep_ms(DEV_ACTIVATION_VERIFY_INTERVAL_MS);
    }
    return false;
}

static void dev_quarantine_format_now(char *now, size_t size)
{
    time_t t = platform_time_wall_time_t();
    struct tm tmv;
    if (gmtime_r(&t, &tmv))
        strftime(now, size, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    else
        snprintf(now, size, "1970-01-01T00:00:00Z");
}

/* one-line the reason to keep the value on a single JSON line */
static void dev_quarantine_clean_reason(const char *reason, char *clean,
                                        size_t size)
{
    size_t o = 0;
    for (const char *p = reason ? reason : ""; *p && o + 2 < size; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\')
            clean[o++] = '\\';
        clean[o++] = (c == '\n' || c == '\r' || c == '\t') ? ' ' : (char)c;
    }
    clean[o] = 0;
}

void dev_activation_quarantine(const struct dev_activation_txn *txn,
                               const char *reason)
{
    char marker_tmp[PATH_MAX], marker[PATH_MAX];
    int n = snprintf(marker, sizeof(marker), "%s/%s.json", txn->rejected_dir,
                     txn->candidate_generation);
    if (n <= 0 || (size_t)n >= sizeof(marker)) {
        fprintf(stderr, "[dev-activation] quarantine marker path overflow\n");
        return;
    }
    n = snprintf(marker_tmp, sizeof(marker_tmp), "%s/.%s.%ld", txn->rejected_dir,
                 txn->candidate_generation, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(marker_tmp)) {
        fprintf(stderr, "[dev-activation] quarantine tmp path overflow\n");
        return;
    }
    FILE *f = fopen(marker_tmp, "w");
    if (!f) {
        fprintf(stderr, "[dev-activation] quarantine open %s: %s\n", marker_tmp,
                strerror(errno));
        return;
    }
    char now[32];
    dev_quarantine_format_now(now, sizeof(now));
    char clean[256];
    dev_quarantine_clean_reason(reason, clean, sizeof(clean));
    fprintf(f, "{\"schema\":\"zcl.dev_rejected_generation.v1\","
               "\"generation\":\"%s\",\"sha256\":\"%s\","
               "\"rejected_at_utc\":\"%s\",\"reason\":\"%s\"}\n",
            txn->candidate_generation, txn->candidate_sha_hex, now, clean);
    fclose(f);
    if (rename(marker_tmp, marker) != 0) {
        (void)unlink(marker_tmp);
        fprintf(stderr, "[dev-activation] quarantine rename failed: %s\n",
                strerror(errno));
    }
}

bool dev_activation_rollback_previous(struct dev_activation_txn *txn,
                                      const char *reason)
{
    struct dev_activation_result *r = txn->result;
    const struct dev_activation_ops *ops = txn->ops;
    snprintf(r->rollback_status, sizeof(r->rollback_status), "started");

    (void)ops->service_stop(ops->ctx);

    if (txn->previous_generation[0] == 0 ||
        !dev_activation_link_generation(txn, "current",
                                        txn->previous_generation)) {
        (void)unlink(txn->current_link);
        (void)unlink(txn->compat_bin);
        snprintf(r->rollback_status, sizeof(r->rollback_status), "unavailable");
        snprintf(r->failure_capsule, sizeof(r->failure_capsule),
                 "%s; no prior generation available", reason ? reason : "");
        txn->activation_in_progress = false;
        dev_activation_clear_in_progress(txn);
        return false;
    }

    (void)dev_activation_refresh_compat_link(txn);
    if (!dev_activation_write_build_identity(txn,
                                             txn->previous_generation)) {
        /* The old executable/link is already restored. Even if its identity
         * drop-in cannot be rewritten, do not silently leave the lane stopped:
         * make a bounded best-effort restart and report the degraded recovery. */
        (void)ops->service_daemon_reload(ops->ctx);
        (void)ops->service_reset_failed(ops->ctx);
        int restart_rc = ops->service_start(ops->ctx);
        snprintf(r->rollback_status, sizeof(r->rollback_status),
                 "identity_failed");
        snprintf(r->failure_capsule, sizeof(r->failure_capsule),
                 "%s; could not bind last-good source identity intent; "
                 "restart %s",
                 reason ? reason : "",
                 restart_rc == 0 ? "attempted successfully" : "failed");
        txn->activation_in_progress = false;
        dev_activation_clear_in_progress(txn);
        return false;
    }
    (void)ops->service_daemon_reload(ops->ctx);
    (void)ops->service_reset_failed(ops->ctx);

    if (ops->service_start(ops->ctx) != 0) {
        snprintf(r->rollback_status, sizeof(r->rollback_status),
                 "restart_failed");
        snprintf(r->failure_capsule, sizeof(r->failure_capsule),
                 "%s; last-good restart command failed", reason ? reason : "");
        txn->activation_in_progress = false;
        dev_activation_clear_in_progress(txn);
        return false;
    }

    if (dev_activation_verify_running(txn, txn->previous_generation)) {
        (void)dev_activation_link_generation(txn, "last-good",
                                             txn->previous_generation);
        snprintf(r->rollback_status, sizeof(r->rollback_status), "verified");
        txn->activation_in_progress = false;
        dev_activation_clear_in_progress(txn);
        return true;
    }

    snprintf(r->rollback_status, sizeof(r->rollback_status),
             "verification_failed");
    snprintf(r->failure_capsule, sizeof(r->failure_capsule),
             "%s; last-good recovery probe failed", reason ? reason : "");
    txn->activation_in_progress = false;
    dev_activation_clear_in_progress(txn);
    return false;
}

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */
