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

#include <dirent.h>
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
 * microsecond key. Returns false (leaving *out_us untouched) if the name
 * doesn't have the expected "<digits>_<digits>" body — the caller falls
 * back to mtime so an unrecognized-but-prefix-matching name still sorts. */
static bool wbs_parse_filename_us(const char *name, int64_t *out_us)
{
    const char *body = name + strlen(WALLET_BACKUP_FILENAME_PREFIX);
    char *after_ts = NULL;
    long long ts = strtoll(body, &after_ts, 10);
    if (after_ts == body || *after_ts != '_') return false;
    const char *usec_start = after_ts + 1;
    char *after_usec = NULL;
    long usec = strtol(usec_start, &after_usec, 10);
    if (after_usec == usec_start || usec < 0 || usec > 999999) return false;
    /* Whatever follows (".sqlite" or ".sqlite.enc") is already validated
     * by the caller's suffix check; no need to re-check it here. */
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

int wallet_backup_rotate(const char *backup_dir, int max_versions)
{
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
