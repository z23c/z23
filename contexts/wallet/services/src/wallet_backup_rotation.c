/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet backup rotation / listing — scans `backup_dir` for
 * `wallet_backup_*` files (both plaintext .sqlite and encrypted
 * .sqlite.enc), sorts newest-first, and deletes the oldest beyond
 * `max_versions`. Extracted from wallet_backup_service.c; see
 * services/wallet_backup_service.h for the service design overview.
 *
 * Sort key: the filename already carries a monotonic
 * <unix_ts>_<usec> pair (wbs_unique_backup_timestamp_us() in
 * wallet_backup_run.c never repeats or goes backwards, even across
 * back-to-back runs inside the same wall-clock second). Parsing that
 * pair gives an exact, race-free order; falling back to st_mtime
 * (1-second resolution) for any name that doesn't parse would let two
 * backups made in the same second tie and sort arbitrarily. */

// one-result-type-ok:rotation-count-returns — E2 (one way out): both public
// entry points (`wallet_backup_list`, `wallet_backup_rotate`) return a
// non-negative count (files listed / files deleted), not a fallible
// bool/int that loses a failure reason — an unreadable or empty backup_dir
// is legitimately "0 backups", not an error. The signatures are preserved
// byte-identical from wallet_backup_service.c (extraction mandate); the
// fallible save path stays in that TU and returns struct zcl_result.

#include "services/wallet_backup_service.h"

#include "platform/file_metadata.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ── Rotation / listing ─────────────────────────────────────── */

struct wbs_file {
    char    name[256];
    int64_t sort_key; /* microseconds: parsed <ts>_<usec>, else mtime*1e6 */
};

static int wbs_cmp_key_desc(const void *a, const void *b)
{
    const struct wbs_file *fa = a;
    const struct wbs_file *fb = b;
    if (fa->sort_key > fb->sort_key) return -1; // raw-return-ok:qsort-comparator
    if (fa->sort_key < fb->sort_key) return 1;
    return 0;
}

/* Parse "wallet_backup_<unix_ts>_<usec>{.sqlite,.sqlite.enc}" into a single
 * microsecond key. Returns false (zeroing *out_us) if the name
 * cannot represent a non-negative microsecond key — the caller falls
 * back to mtime so an unrecognized-but-prefix-matching name still sorts. */
static bool wbs_parse_filename_us(const char *name, int64_t *out_us)
{
    *out_us = 0;
    const char *body = name + strlen(WALLET_BACKUP_FILENAME_PREFIX);
    char *after_ts = NULL;
    errno = 0;
    long long ts = strtoll(body, &after_ts, 10);
    if (errno == ERANGE || after_ts == body || *after_ts != '_' || ts < 0)
        return false;
    const char *usec_start = after_ts + 1;
    char *after_usec = NULL;
    errno = 0;
    long usec = strtol(usec_start, &after_usec, 10);
    if (errno == ERANGE || after_usec == usec_start ||
        usec < 0 || usec > 999999)
        return false;
    /* Whatever follows (".sqlite" or ".sqlite.enc") is already validated
     * by the caller's suffix check; no need to re-check it here. */
    if (ts > (INT64_MAX - usec) / 1000000LL)
        return false;
    *out_us = ts * 1000000LL + usec;
    return true;
}

static int wbs_scan_backup_dir(const char *dir,
                                struct wbs_file *out, int max)
{
    if (!dir || !out || max <= 0) return 0;
    DIR *d = opendir(dir);
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && n < max) {
        if (strncmp(e->d_name, WALLET_BACKUP_FILENAME_PREFIX,
                    strlen(WALLET_BACKUP_FILENAME_PREFIX)) != 0)
            continue;
        /* Accept both plaintext and encrypted backups — if .enc files
         * were invisible here they would never rotate (unbounded disk
         * growth) and never list. */
        size_t nl = strlen(e->d_name);
        size_t sl = strlen(WALLET_BACKUP_FILENAME_SUFFIX);
        size_t el = strlen(WALLET_BACKUP_FILENAME_SUFFIX_ENC);
        bool is_plain = nl >= sl &&
            strcmp(e->d_name + nl - sl, WALLET_BACKUP_FILENAME_SUFFIX) == 0;
        bool is_enc = nl >= el &&
            strcmp(e->d_name + nl - el,
                   WALLET_BACKUP_FILENAME_SUFFIX_ENC) == 0;
        if (!is_plain && !is_enc)
            continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(full, &st) != 0) continue;
        snprintf(out[n].name, sizeof(out[n].name), "%s", e->d_name);
        int64_t parsed_us = 0;
        out[n].sort_key = wbs_parse_filename_us(e->d_name, &parsed_us)
            ? parsed_us : (int64_t)st.st_mtime * 1000000LL;
        n++;
    }
    closedir(d);
    qsort(out, (size_t)n, sizeof(struct wbs_file), wbs_cmp_key_desc);
    return n;
}

int wallet_backup_list(const char *backup_dir,
                        char (*out_paths)[512], int max)
{
    struct wbs_file files[256];
    int n = wbs_scan_backup_dir(backup_dir, files,
        max < (int)(sizeof(files) / sizeof(files[0]))
            ? max : (int)(sizeof(files) / sizeof(files[0])));
    int written_paths = 0;
    for (int i = 0; i < n; i++) {
        int written = snprintf(out_paths[written_paths], 512, "%s/%s",
                               backup_dir, files[i].name);
        if (written >= 0 && written < 512)
            written_paths++;
    }
    return written_paths;
}

/* ── Stale temporary sweep ──────────────────────────────────────
 *
 * wallet_backup_run.c writes and verifies each snapshot as
 * "<final name>.tmp" and renames it only once verified, so a crash leaves at
 * most such a file. Listing never shows it (its suffix is neither of the two
 * accepted above); this sweep reclaims it.
 *
 * Bound: only a name that is EXACTLY wallet_backup_<digits>_<6 digits>
 * .sqlite.tmp, only a regular file (a symlink is refused by the metadata
 * read), and only when its modification time is at least one hour in the
 * past (a future time counts as fresh). Two nodes may share one backup
 * directory, so the file may belong to ANOTHER process's live run: a live
 * run rewrites its file throughout the copy and needs seconds, not an hour,
 * from close to rename. Even a run stalled past the bound fails closed — its
 * reopen, verify or rename finds the name gone — so the sweep can cost a
 * retry, never a listed partial file or a verified backup. One hour is the
 * shortest bound with that margin; a temporary file holds plaintext wallet
 * rows, so it should not outlive that margin by much.
 *
 * The temporary file's own SQLite rollback journal (".sqlite.tmp-journal",
 * exactly that name) joins the sweep under the same bound: a crash mid-copy
 * leaves it beside the temporary file, and it too may hold plaintext rows.
 * It belongs to a file that is never published unverified, so removing it
 * can at most cost that run a retry. Nothing else joins the sweep. */

#define WBS_TEMP_SUFFIX ".tmp"
#define WBS_TEMP_JOURNAL_SUFFIX ".tmp-journal"
#define WBS_TEMP_STALE_SECONDS 3600

static bool wbs_is_temp_name(const char *name)
{
    size_t pl = strlen(WALLET_BACKUP_FILENAME_PREFIX);
    if (strncmp(name, WALLET_BACKUP_FILENAME_PREFIX, pl) != 0)
        return false;
    const char *p = name + pl;
    const char *ts = p;
    while (*p >= '0' && *p <= '9')
        p++;
    if (p == ts || p - ts > 19 || *p != '_')
        return false;
    p++;
    for (int i = 0; i < 6; i++, p++)
        if (*p < '0' || *p > '9')
            return false;
    return strcmp(p, WALLET_BACKUP_FILENAME_SUFFIX WBS_TEMP_SUFFIX) == 0 ||
           strcmp(p, WALLET_BACKUP_FILENAME_SUFFIX WBS_TEMP_JOURNAL_SUFFIX) ==
               0;
}

static void wbs_sweep_one(const char *dir, const char *name, int64_t now_s)
{
    char full[1024];
    int n = snprintf(full, sizeof(full), "%s/%s", dir, name);
    if (n <= 0 || (size_t)n >= sizeof(full))
        return;
    struct platform_file_metadata md;
    if (platform_file_metadata_read(full, &md) != PLATFORM_FILE_METADATA_OK)
        return;
    if (md.modified_seconds > now_s ||
        now_s - md.modified_seconds < WBS_TEMP_STALE_SECONDS)
        return;
    if (unlink(full) == 0)
        LOG_INFO("wallet_backup", "removed stale temporary backup %s "
                 "(%lld s old)", full,
                 (long long)(now_s - md.modified_seconds));
    else if (errno != ENOENT)
        LOG_WARN("wallet_backup", "cannot remove stale temporary backup %s: "
                 "%s", full, strerror(errno));
}

static void wbs_sweep_stale_temps(const char *dir)
{
    if (!dir) return;
    DIR *d = opendir(dir);
    if (!d) return;
    int64_t now_s = platform_time_wall_unix();
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (wbs_is_temp_name(e->d_name))
            wbs_sweep_one(dir, e->d_name, now_s);
    closedir(d);
}

/* Rotation's rule is unchanged: keep the newest `max_versions` backups. The
 * sweep above runs first and is not counted in the return. */
int wallet_backup_rotate(const char *backup_dir, int max_versions)
{
    wbs_sweep_stale_temps(backup_dir);
    if (max_versions <= 0) return 0;
    struct wbs_file files[256];
    int n = wbs_scan_backup_dir(backup_dir, files, 256);
    int deleted = 0;
    for (int i = max_versions; i < n; i++) {
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", backup_dir, files[i].name);
        if (unlink(full) == 0)
            deleted++;
    }
    return deleted;
}
