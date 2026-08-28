/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_cold_start.c — the `-cold-start` staged, resumable driver. Contract +
 * rationale live in config/boot_cold_start.h.
 *
 * TWO layers, mirroring shutdown_stagewatch.c:
 *   (1) PURE helpers — stage naming, receipt path/write/read/match, and the
 *       resume decision. No child spawn, no global state; unit tested directly.
 *   (2) LIVE driver — fork/exec of each existing verb as a child, then exec of
 *       the plain serving boot. Composes the existing stages; never duplicates
 *       normal boot.
 */

#include "config/boot_cold_start.h"

#include "boot_cold_start_internal.h"

#include "platform/os_proc.h"    /* os_proc_exe_path */
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "util/file_tree_ops.h"  /* zcl_mkdir_p */
#include "util/log_macros.h"
#include "util/safe_alloc.h"     /* zcl_malloc */
#include "util/write_all.h"      /* zcl_write_all */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define COLD_START_MAGIC   "ZCLCOLDSTART"
#define COLD_START_VERSION 2 /* v2 adds outcome=/reason= (refusal receipts) */

/* ── (1) Pure helpers ─────────────────────────────────────────────────── */

const char *cold_start_stage_name(enum cold_start_stage stage)
{
    switch (stage) {
    case COLD_START_STAGE_HEADERS: return "headers";
    case COLD_START_STAGE_SEED:    return "seed";
    case COLD_START_STAGE_BUNDLE:  return "bundle";
    case COLD_START_STAGE_SERVE:   return "serve";
    }
    return "?";
}

const char *cold_start_stage_param(const struct cold_start_plan *plan,
                                   enum cold_start_stage stage)
{
    if (!plan)
        return NULL;
    const char *p = NULL;
    switch (stage) {
    case COLD_START_STAGE_HEADERS: p = plan->header_source;  break;
    case COLD_START_STAGE_SEED:    p = plan->seed_snapshot;  break;
    case COLD_START_STAGE_BUNDLE:  p = plan->install_bundle; break;
    case COLD_START_STAGE_SERVE:   p = NULL;                 break;
    }
    return (p && p[0]) ? p : NULL;
}

bool cold_start_stage_configured(const struct cold_start_plan *plan,
                                 enum cold_start_stage stage)
{
    if (stage == COLD_START_STAGE_SERVE)
        return true; /* the driver always ends by serving */
    return cold_start_stage_param(plan, stage) != NULL;
}

int cold_start_receipt_path(const char *datadir, enum cold_start_stage stage,
                            char *buf, size_t n)
{
    if (!datadir || !datadir[0] || !buf || n == 0)
        return -1;
    int w = snprintf(buf, n, "%s/coldstart/%s.receipt", datadir,
                     cold_start_stage_name(stage));
    if (w < 0 || (size_t)w >= n)
        return -1;
    return w;
}

static _Atomic uint64_t g_cold_start_receipt_nonce;

/* Copy at most `in_len` bytes of `in` into `out` (bounded by `out_n`), replacing
 * any CR/LF with a space so the result is a single line. Always NUL-terminates. */
void cold_start_singleline_bounded(const char *in, size_t in_len,
                                   char *out, size_t out_n)
{
    if (out_n == 0)
        return;
    size_t j = 0;
    for (size_t i = 0; in && i < in_len && in[i] && j + 1 < out_n; i++)
        out[j++] = (in[i] == '\n' || in[i] == '\r') ? ' ' : in[i];
    out[j] = '\0';
}

/* Single-line the NUL-terminated `in` into `out` (bounded); NULL => empty. */
static void cold_start_singleline(const char *in, char *out, size_t out_n)
{
    cold_start_singleline_bounded(in, in ? strlen(in) : 0, out, out_n);
}

bool cold_start_receipt_write(const char *datadir, enum cold_start_stage stage,
                              const char *param, bool refused,
                              const char *reason)
{
    if (!datadir || !datadir[0])
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: empty datadir");

    char dir[PATH_MAX];
    int dn = snprintf(dir, sizeof(dir), "%s/coldstart", datadir);
    if (dn < 0 || (size_t)dn >= sizeof(dir))
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: coldstart dir path too long");
    if (!platform_private_directory_ensure(dir))
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: private directory refused");

    char path[PATH_MAX];
    if (cold_start_receipt_path(datadir, stage, path, sizeof(path)) < 0)
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: path build failed");
    char resolved[PATH_MAX];
    char parent[PATH_MAX];
    if (!platform_private_path_resolve(path, resolved, sizeof(resolved), parent,
                                       sizeof(parent)))
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: path resolution failed");

    char reason_line[COLD_START_REASON_MAX];
    cold_start_singleline(refused ? reason : NULL, reason_line,
                          sizeof(reason_line));

    char content[PATH_MAX + COLD_START_REASON_MAX + 192];
    int cn = snprintf(content, sizeof(content),
                      "magic=%s\nversion=%d\nstage=%s\noutcome=%s\n"
                      "has_param=%d\nparam=%s\nreason=%s\n",
                      COLD_START_MAGIC, COLD_START_VERSION,
                      cold_start_stage_name(stage),
                      refused ? "refused" : "ok",
                      (param && param[0]) ? 1 : 0,
                      (param && param[0]) ? param : "",
                      reason_line);
    if (cn < 0 || (size_t)cn >= sizeof(content))
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: content build failed");

    struct platform_private_file staging;
    platform_private_file_init(&staging);
    char tmp[PATH_MAX];
    bool created = false;
    for (unsigned attempt = 0; attempt < 64 && !created; attempt++) {
        uint64_t nonce = atomic_fetch_add_explicit(
            &g_cold_start_receipt_nonce, 1, memory_order_relaxed);
        int tn = snprintf(tmp, sizeof(tmp), "%s.tmp.%016llx", resolved,
                          (unsigned long long)nonce);
        if (tn < 0 || (size_t)tn >= sizeof(tmp))
            LOG_FAIL(COLD_START_SUBSYS, "receipt write: tmp path too long");
        created = platform_private_file_create(tmp, &staging);
    }
    if (!created)
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: staging create failed");
    bool ok = platform_private_file_write_at(&staging, content, (size_t)cn, 0) &&
              platform_private_file_flush(&staging) &&
              platform_private_file_replace(&staging, tmp, resolved) &&
              platform_private_parent_flush(parent);
    platform_private_file_close(&staging);
    if (!ok) {
        (void)platform_private_file_unlink_missing_ok(tmp);
        LOG_FAIL(COLD_START_SUBSYS, "receipt write: durable replacement failed");
    }
    LOG_INFO(COLD_START_SUBSYS, "stage '%s' %s receipt written (%s)",
             cold_start_stage_name(stage), refused ? "REFUSAL" : "success", path);
    return true;
}

/* Extract the value of `key=` from a receipt buffer into out (bounded). Returns
 * true iff the key line is present. */
static bool cold_start_receipt_field(const char *buf, const char *key,
                                     char *out, size_t out_n)
{
    if (out_n)
        out[0] = '\0';
    size_t keylen = strlen(key);
    const char *p = buf;
    while (p && *p) {
        /* Match key= at the start of a line. */
        if (strncmp(p, key, keylen) == 0 && p[keylen] == '=') {
            const char *v = p + keylen + 1;
            const char *end = strchr(v, '\n');
            size_t len = end ? (size_t)(end - v) : strlen(v);
            if (len >= out_n)
                len = out_n ? out_n - 1 : 0;
            if (out_n) {
                memcpy(out, v, len);
                out[len] = '\0';
            }
            return true;
        }
        const char *nl = strchr(p, '\n');
        if (!nl)
            break;
        p = nl + 1;
    }
    return false;
}

/* Read + validate a receipt into `buf`: true iff it exists, carries the magic,
 * and its parameter matches `param` (both-NULL equal). Leaves the raw receipt in
 * `buf` for the caller to inspect `outcome`. */
static bool cold_start_receipt_load(const char *datadir,
                                    enum cold_start_stage stage,
                                    const char *param, char *buf, size_t buf_n)
{
    char path[PATH_MAX];
    if (cold_start_receipt_path(datadir, stage, path, sizeof(path)) < 0)
        return false;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before;
    struct platform_positioned_file_snapshot after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false;
    bool valid = platform_positioned_file_is_private(&file) &&
                 platform_positioned_file_snapshot(&file, &before) &&
                 before.size > 0 && before.size < buf_n;
    int64_t r = valid ? platform_positioned_file_read(
                            &file, buf, (size_t)before.size, 0)
                      : -1;
    bool stable = valid && r == (int64_t)before.size &&
                  platform_positioned_file_snapshot(&file, &after) &&
                  before.size == after.size &&
                  before.modified_seconds == after.modified_seconds &&
                  before.modified_nanoseconds == after.modified_nanoseconds &&
                  before.changed_seconds == after.changed_seconds &&
                  before.changed_nanoseconds == after.changed_nanoseconds &&
                  before.volume == after.volume &&
                  before.file_low == after.file_low &&
                  before.file_high == after.file_high;
    platform_positioned_file_close(&file);
    if (!stable)
        return false;
    buf[(size_t)r] = '\0';

    char magic[32];
    if (!cold_start_receipt_field(buf, "magic", magic, sizeof(magic)) ||
        strcmp(magic, COLD_START_MAGIC) != 0)
        return false;

    char has_param[8];
    bool recorded_has = cold_start_receipt_field(buf, "has_param", has_param,
                                                 sizeof(has_param)) &&
                        strcmp(has_param, "1") == 0;
    bool want_has = (param && param[0]);
    if (recorded_has != want_has)
        return false;
    if (!want_has)
        return true; /* both parameter-less — parameter matches */

    char recorded_param[PATH_MAX];
    if (!cold_start_receipt_field(buf, "param", recorded_param,
                                  sizeof(recorded_param)))
        return false;
    return strcmp(recorded_param, param) == 0;
}

/* True iff the receipt records a REFUSAL (outcome=refused); an absent outcome
 * field reads as a success receipt (forward-compatible with v1). */
static bool cold_start_receipt_is_refused(const char *buf)
{
    char outcome[16];
    return cold_start_receipt_field(buf, "outcome", outcome, sizeof(outcome)) &&
           strcmp(outcome, "refused") == 0;
}

bool cold_start_receipt_matches(const char *datadir, enum cold_start_stage stage,
                                const char *param)
{
    char buf[PATH_MAX + COLD_START_REASON_MAX + 256];
    if (!cold_start_receipt_load(datadir, stage, param, buf, sizeof(buf)))
        return false;
    return !cold_start_receipt_is_refused(buf); /* a refusal is not "stage done" */
}

bool cold_start_receipt_refused(const char *datadir, enum cold_start_stage stage,
                                const char *param, char *reason, size_t reason_n)
{
    if (reason && reason_n)
        reason[0] = '\0';
    char buf[PATH_MAX + COLD_START_REASON_MAX + 256];
    if (!cold_start_receipt_load(datadir, stage, param, buf, sizeof(buf)))
        return false;
    if (!cold_start_receipt_is_refused(buf))
        return false;
    if (reason && reason_n)
        (void)cold_start_receipt_field(buf, "reason", reason, reason_n);
    return true;
}

enum cold_start_stage cold_start_plan_next(const struct cold_start_plan *plan)
{
    static const enum cold_start_stage order[COLD_START_PREP_STAGE_COUNT] = {
        COLD_START_STAGE_HEADERS,
        COLD_START_STAGE_SEED,
        COLD_START_STAGE_BUNDLE,
    };
    if (!plan || !plan->datadir || !plan->datadir[0])
        return COLD_START_STAGE_SERVE;
    for (int i = 0; i < COLD_START_PREP_STAGE_COUNT; i++) {
        enum cold_start_stage s = order[i];
        if (!cold_start_stage_configured(plan, s))
            continue;
        if (!cold_start_receipt_matches(plan->datadir, s,
                                        cold_start_stage_param(plan, s)))
            return s;
    }
    return COLD_START_STAGE_SERVE;
}

/* Copy `src` into `dst` (bounded, single-lined, always NUL-terminated). */
void cold_start_reason_copy(char *dst, size_t dst_n, const char *src)
{
    cold_start_singleline(src, dst, dst_n);
}

enum cold_start_result cold_start_drive(const struct cold_start_plan *plan,
                                        cold_start_stage_runner_fn runner,
                                        void *user,
                                        enum cold_start_stage *out_reached,
                                        char *reason, size_t reason_n)
{
    if (reason && reason_n)
        reason[0] = '\0';
    if (out_reached)
        *out_reached = COLD_START_STAGE_SERVE;
    if (!plan || !plan->datadir || !plan->datadir[0]) {
        cold_start_reason_copy(reason, reason_n, "empty plan/datadir");
        LOG_WARN(COLD_START_SUBSYS, "drive: empty plan/datadir");
        return COLD_START_TRANSIENT;
    }
    if (!runner) {
        cold_start_reason_copy(reason, reason_n, "NULL stage runner");
        LOG_WARN(COLD_START_SUBSYS, "drive: NULL stage runner");
        return COLD_START_TRANSIENT;
    }

    /* Bounded: each iteration serves, stops (transient/blocked), or converts one
     * prep stage to "success receipt present" — at most prep-count + 1 loops. */
    for (int guard = 0; guard <= COLD_START_PREP_STAGE_COUNT; guard++) {
        enum cold_start_stage next = cold_start_plan_next(plan);
        if (out_reached)
            *out_reached = next;
        if (next == COLD_START_STAGE_SERVE)
            return COLD_START_OK;

        const char *param = cold_start_stage_param(plan, next);

        /* Sticky refusal: a prior run REFUSED this stage under this same param.
         * Refusals are decisions — never auto-retry; re-emit the verdict. */
        char sticky[COLD_START_REASON_MAX];
        if (cold_start_receipt_refused(plan->datadir, next, param, sticky,
                                       sizeof(sticky))) {
            LOG_WARN(COLD_START_SUBSYS, "stage '%s' has a sticky REFUSAL "
                     "receipt — staying blocked (change the bound parameter to "
                     "re-evaluate): %s", cold_start_stage_name(next), sticky);
            cold_start_reason_copy(reason, reason_n, sticky);
            return COLD_START_BLOCKED;
        }

        LOG_INFO(COLD_START_SUBSYS, "running stage '%s'",
                 cold_start_stage_name(next));
        char stage_reason[COLD_START_REASON_MAX];
        stage_reason[0] = '\0';
        enum cold_start_result rc =
            runner(plan, next, user, stage_reason, sizeof(stage_reason));

        if (rc == COLD_START_BLOCKED) {
            /* A decision refusal — persist a refusal receipt (verbatim) so a
             * rerun stays blocked, then report BLOCKED. */
            if (!cold_start_receipt_write(plan->datadir, next, param, true,
                                          stage_reason))
                LOG_WARN(COLD_START_SUBSYS, "stage '%s' refused but its refusal "
                         "receipt could not be persisted — a rerun will re-run "
                         "the stage", cold_start_stage_name(next));
            LOG_WARN(COLD_START_SUBSYS, "stage '%s' REFUSED (decision — not "
                     "retried): %s", cold_start_stage_name(next), stage_reason);
            cold_start_reason_copy(reason, reason_n, stage_reason);
            return COLD_START_BLOCKED;
        }
        if (rc != COLD_START_OK) {
            LOG_WARN(COLD_START_SUBSYS, "stage '%s' failed transiently — halting "
                     "(no receipt written; rerun -cold-start to resume here): %s",
                     cold_start_stage_name(next), stage_reason);
            cold_start_reason_copy(reason, reason_n, stage_reason);
            return COLD_START_TRANSIENT;
        }
        if (!cold_start_receipt_write(plan->datadir, next, param, false, NULL)) {
            LOG_WARN(COLD_START_SUBSYS, "stage '%s' succeeded but its receipt "
                     "could not be persisted — halting to avoid an unrecordable "
                     "resume point", cold_start_stage_name(next));
            cold_start_reason_copy(reason, reason_n,
                                   "success receipt could not be persisted");
            return COLD_START_TRANSIENT;
        }
    }
    cold_start_reason_copy(reason, reason_n,
                           "exceeded stage bound without reaching serve");
    LOG_WARN(COLD_START_SUBSYS, "drive: exceeded stage bound without reaching "
             "serve (a receipt is not persisting?)");
    return COLD_START_TRANSIENT;
}
