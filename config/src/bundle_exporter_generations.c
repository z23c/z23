/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the exporter's on-disk bundle GENERATIONS — parse the
 * "consensus-state-bundle-<height>.sqlite" filename convention, find the newest
 * generation in a bundles directory, and run the keep-N retention rotation
 * (re-validate the newest, then deregister-before-unlink each older one).
 *
 * Split out of config/src/bundle_exporter.c when that file passed its shape
 * ceiling. Pure move: the bodies below are byte-identical to the ones that file
 * carried; only the linkage of the four entry points changed (static ->
 * external) so the standing exporter can still reach them across the TU
 * boundary. Contract: config/src/bundle_exporter_generations_internal.h.
 */

#include "config/bundle_exporter.h"

#if defined(_WIN32)

/* Native Windows export/retention stays fail-closed in
 * config/src/bundle_exporter.c, so no pathname in a bundles directory is ever
 * opened, scanned, or unlinked here. */

#else

#include "bundle_exporter_generations_internal.h"

#include "config/consensus_state_bundle_validate.h"
#include "storage/consensus_state_bundle_codec.h"

#include "net/rom_seed.h"   /* deregister a rotated-out generation before unlink */
#include "util/log_macros.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Parse "consensus-state-bundle-<N>.sqlite" -> height. Returns false for any
 * other name. */
bool bx_parse_bundle_height(const char *name, long *out)
{
    size_t plen = strlen(BX_BUNDLE_PREFIX);
    size_t slen = strlen(BX_BUNDLE_SUFFIX);
    size_t nlen = strlen(name);
    if (nlen <= plen + slen)
        return false;
    if (strncmp(name, BX_BUNDLE_PREFIX, plen) != 0)
        return false;
    if (strcmp(name + nlen - slen, BX_BUNDLE_SUFFIX) != 0)
        return false;
    const char *digits = name + plen;
    size_t dcount = nlen - plen - slen;
    if (dcount == 0 || dcount >= 32)
        return false;
    for (size_t i = 0; i < dcount; i++)
        if (!isdigit((unsigned char)digits[i]))
            return false;
    char buf[32];
    memcpy(buf, digits, dcount);
    buf[dcount] = '\0';
    errno = 0;
    char *end = NULL;
    long v = strtol(buf, &end, 10);
    if (errno != 0 || (end && *end) || v < 0)
        return false;
    *out = v;
    return true;
}

/* Highest bundle height present in `dir` and the wall-clock mtime (µs) of that
 * newest generation. Returns -1 (and *out_mtime_us 0) when none / dir
 * unreadable. Seeds the standing exporter's last-export height AND time so both
 * the block-count and the time-cadence gates survive a process restart: the
 * newest on-disk generation IS the last export, and its mtime is when it was
 * produced. `out_mtime_us` may be NULL. */
int32_t bx_scan_newest(const char *dir, int64_t *out_mtime_us)
{
    if (out_mtime_us)
        *out_mtime_us = 0;
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    long max = -1;
    char maxname[128] = {0};
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        long h;
        if (bx_parse_bundle_height(e->d_name, &h) && h > max) {
            max = h;
            memcpy(maxname, e->d_name, strlen(e->d_name) + 1u);
        }
    }
    closedir(d);
    if (max >= 0 && out_mtime_us && maxname[0]) {
        char full[1300];
        snprintf(full, sizeof full, "%s/%s", dir, maxname);
        struct stat st;
        if (stat(full, &st) == 0)
            *out_mtime_us = (int64_t)st.st_mtim.tv_sec * 1000000 +
                            (int64_t)st.st_mtim.tv_nsec / 1000;
    }
    return (int32_t)max;
}

/* Belt+braces re-validation of a sealed bundle by path (read-only, immutable).
 * The export path already reopens+validates before linking; rotation only ever
 * deletes an OLDER generation after confirming the NEWEST still validates. */
static bool bx_validate_bundle_path(const char *path)
{
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL)
        != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return false;
    }
    (void)sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, NULL);
    (void)sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, NULL);
    (void)sqlite3_exec(db, "PRAGMA query_only=ON", NULL, NULL, NULL);

    struct consensus_state_bundle_manifest manifest;
    struct consensus_state_install_result validation;
    memset(&manifest, 0, sizeof manifest);
    memset(&validation, 0, sizeof validation);
    bool ok = consensus_state_bundle_validate(db, &manifest, &validation);
    sqlite3_close(db);
    return ok;
}

/* ── Rotation ───────────────────────────────────────────────────── */

int bx_gen_cmp_desc(const void *a, const void *b)
{
    const struct bx_gen *x = a;
    const struct bx_gen *y = b;
    if (x->h < y->h)
        return 1;
    if (x->h > y->h)
        return -1;
    return 0;
}

#ifdef ZCL_TESTING
/* Test-only: skip the newest-bundle re-validation guard in bx_rotate so a
 * fixture built from lightweight SQLite-shaped files (which do not pass the full
 * consensus_state_bundle_validate) can exercise the deregister+unlink rotation
 * behavior. Never set outside tests (compiled out of production entirely). */
static atomic_bool g_bx_rotate_skip_validate_for_test = false;
void bundle_exporter_set_rotate_skip_validate_for_test(bool on)
{
    atomic_store(&g_bx_rotate_skip_validate_for_test, on);
}
#endif

/* Keep the `keep` newest bundles; delete older ones — but only after the newest
 * bundle independently re-validates, and delete nothing if it does not. Each
 * rotated-out generation is DEREGISTERED from rom_seed BEFORE it is unlinked
 * (GAP-2), so a node never keeps advertising / serving a file it just deleted.
 * `datadir` is the rom_seed root; `dir` is <datadir>/bundles. */
void bx_rotate(const char *dir, int keep, const char *datadir)
{
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct bx_gen gens[BX_MAX_GENERATIONS];
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && n < BX_MAX_GENERATIONS) {
        long h;
        if (bx_parse_bundle_height(e->d_name, &h)) {
            gens[n].h = h;
            memcpy(gens[n].name, e->d_name, strlen(e->d_name) + 1u);
            n++;
        }
    }
    closedir(d);
    if (n <= keep)
        return;
    qsort(gens, (size_t)n, sizeof gens[0], bx_gen_cmp_desc);

    bool skip_validate = false;
#ifdef ZCL_TESTING
    skip_validate = atomic_load(&g_bx_rotate_skip_validate_for_test);
#endif
    if (!skip_validate) {
        char newest_path[1300];
        snprintf(newest_path, sizeof newest_path, "%s/%s", dir, gens[0].name);
        if (!bx_validate_bundle_path(newest_path)) {
            LOG_WARN("bundle_exporter",
                     "rotation: newest bundle %s failed re-validation; "
                     "deleting nothing", gens[0].name);
            return;
        }
    }

    int dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) {
        LOG_WARN("bundle_exporter", "rotation: open bundles dir failed: %s",
                 strerror(errno));
        return;
    }
    for (int i = keep; i < n; i++) {
        /* Stop serving it before removing it — deregister the "bundles/<name>"
         * reseed shape (rom_seed_deregister matches on basename, so the bare
         * name resolves the same entry). Idempotent + non-fatal. */
        if (datadir && datadir[0]) {
            char rel[ROM_SEED_NAME_MAX];
            int rn = snprintf(rel, sizeof rel, "%s/%s",
                              ROM_SEED_BUNDLES_SUBDIR, gens[i].name);
            if (rn > 0 && (size_t)rn < sizeof rel)
                (void)rom_seed_deregister(datadir, rel);
        }
        if (unlinkat(dir_fd, gens[i].name, 0) != 0)
            LOG_WARN("bundle_exporter", "rotation: unlink %s failed: %s",
                     gens[i].name, strerror(errno));
    }
    close(dir_fd);
}

#ifdef ZCL_TESTING
void bundle_exporter_rotate_for_test(const char *dir, int keep,
                                     const char *datadir)
{
    bx_rotate(dir, keep, datadir);
}
#endif

#endif /* !_WIN32 */
