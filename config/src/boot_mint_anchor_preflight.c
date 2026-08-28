/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Inspect producer containment before mutating the node datadir,
 * including committed state that exists only in a kill-9-surviving WAL. */

#define _GNU_SOURCE

#include "config/boot.h"
#include "config/mint_anchor_progress.h"

#include "chain/checkpoints.h"
#include "event/event.h"
#include "json/json.h"
#include "platform/system_memory.h"
#include "services/disk_monitor.h"
#include "storage/consensus_db.h"    /* consensus_db_kernel_store_path + names */
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#if defined(_WIN32)

#include <stdio.h>

/* The POSIX implementation below proves a stable directory-relative snapshot
 * while copying a SQLite main/WAL family into disposable storage. Windows must
 * not approximate that transaction with mutable pathnames. Refuse at each
 * exported execution boundary before creating, copying, opening, or removing
 * anything in either the datadir or a staging directory. */
bool boot_mint_anchor_normal_boot_preflight(const char *datadir)
{
    (void)datadir;
    fprintf(stderr,
            "REFUSED: mint-anchor preflight is unavailable on Windows until "
            "the directory-handle-relative containment transaction is "
            "qualified\n");
    return false;
}

bool boot_mint_anchor_preflight_run_all(const char *datadir,
                                        struct json_value *report)
{
    (void)datadir;
    (void)report;
    fprintf(stderr,
            "REFUSED: -mint-anchor is unavailable on Windows until the "
            "directory-handle-relative containment transaction is qualified\n");
    return false;
}

bool boot_mint_anchor_preflight_dump_state_json(struct json_value *out,
                                                const char *key)
{
    (void)out;
    (void)key;
    return false;
}

#else

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define PREFLIGHT_SUBSYS "mint_anchor"

struct preflight_source_file {
    const char *name;
    int fd;
    bool exists;
    struct stat identity;
};

static bool identity_equal(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_mode == b->st_mode &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static bool source_open(int dirfd, struct preflight_source_file *file)
{
    file->fd = -1;
    file->exists = false;
    struct stat named;
    errno = 0;
    if (fstatat(dirfd, file->name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT)
            return true;
        LOG_WARN(PREFLIGHT_SUBSYS, "preflight stat failed file=%s: %s",
                 file->name, strerror(errno));
        return false;
    }
    if (!S_ISREG(named.st_mode)) {
        LOG_WARN(PREFLIGHT_SUBSYS,
                 "preflight refuses non-regular file=%s", file->name);
        return false;
    }
    file->fd = openat(dirfd, file->name,
                      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat opened;
    if (file->fd < 0 || fstat(file->fd, &opened) != 0 ||
        !identity_equal(&named, &opened)) {
        LOG_WARN(PREFLIGHT_SUBSYS,
                 "preflight source identity raced file=%s", file->name);
        if (file->fd >= 0)
            close(file->fd);
        file->fd = -1;
        return false;
    }
    file->exists = true;
    file->identity = opened;
    return true;
}

static bool source_unchanged(int dirfd,
                             const struct preflight_source_file *file)
{
    struct stat named;
    errno = 0;
    if (!file->exists)
        return fstatat(dirfd, file->name, &named,
                       AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
    struct stat opened;
    return file->fd >= 0 && fstat(file->fd, &opened) == 0 &&
        fstatat(dirfd, file->name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        identity_equal(&file->identity, &opened) &&
        identity_equal(&file->identity, &named);
}

static bool copy_exact_file(const struct preflight_source_file *source,
                            const char *destination)
{
    if (!source->exists)
        return true;
    int out = open(destination,
                   O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                   S_IRUSR | S_IWUSR);
    if (out < 0)
        return false;
    uint8_t buffer[64u * 1024u];
    off_t offset = 0;
    bool ok = true;
    while (offset < source->identity.st_size) {
        size_t want = sizeof(buffer);
        off_t left = source->identity.st_size - offset;
        if (left < (off_t)want)
            want = (size_t)left;
        ssize_t got = pread(source->fd, buffer, want, offset);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            ok = false;
            break;
        }
        size_t written = 0;
        while (written < (size_t)got) {
            ssize_t n = write(out, buffer + written, (size_t)got - written);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0) {
                ok = false;
                break;
            }
            written += (size_t)n;
        }
        if (!ok)
            break;
        offset += got;
    }
    if (ok && fsync(out) != 0)
        ok = false;
    if (close(out) != 0)
        ok = false;
    return ok;
}

static bool remove_temp_family(const char *dir, const char *main_path)
{
    static const char *const suffixes[] = {"", "-wal", "-shm", "-journal"};
    bool ok = true;
    char path[2304];
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        int n = snprintf(path, sizeof(path), "%s%s", main_path, suffixes[i]);
        if (n <= 0 || (size_t)n >= sizeof(path) ||
            (unlink(path) != 0 && errno != ENOENT))
            ok = false;
    }
    if (rmdir(dir) != 0)
        ok = false;
    return ok;
}

static bool inspect_snapshot(const char *path, char *reason,
                             size_t reason_size)
{
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX,
                             NULL);
    bool ok = rc == SQLITE_OK &&
        sqlite3_exec(db, "PRAGMA query_only=ON", NULL, NULL, NULL) == SQLITE_OK;
    if (ok)
        ok = mint_anchor_normal_boot_allowed(db, reason, reason_size);
    if (db && sqlite3_close(db) != SQLITE_OK)
        ok = false;
    return ok;
}

/* A4: the mint producer writes its kernel state (coins/anchors/stage cursors)
 * to consensus.db after the flip; a pre-flip producer datadir still uses the
 * legacy progress.kv. Resolve the family basename ("consensus.db" or
 * "progress.kv") once so every preflight file op targets the right store. */
static void preflight_kernel_basename(const char *datadir, char *out, size_t cap)
{
    char kpath[PATH_MAX];
    if (consensus_db_kernel_store_path(datadir, kpath, sizeof(kpath))) {
        const char *slash = strrchr(kpath, '/');
        const char *base = slash ? slash + 1 : kpath;
        if (base[0] && (size_t)snprintf(out, cap, "%s", base) < cap)
            return;
    }
    (void)snprintf(out, cap, "%s", CONSENSUS_DB_LEGACY_KERNEL_FILENAME);
}

bool boot_mint_anchor_normal_boot_preflight(const char *datadir)
{
    if (!datadir || !datadir[0])
        LOG_FAIL(PREFLIGHT_SUBSYS, "normal boot preflight: missing datadir");
    int dirfd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0)
        LOG_FAIL(PREFLIGHT_SUBSYS, "normal boot preflight cannot open datadir");

    char kbase[64];
    char kmain[80], kwal[80], kshm[80];
    preflight_kernel_basename(datadir, kbase, sizeof(kbase));
    (void)snprintf(kmain, sizeof(kmain), "%s", kbase);
    (void)snprintf(kwal, sizeof(kwal), "%s-wal", kbase);
    (void)snprintf(kshm, sizeof(kshm), "%s-shm", kbase);
    struct preflight_source_file files[] = {
        {.name = kmain, .fd = -1},
        {.name = kwal, .fd = -1},
        {.name = kshm, .fd = -1},
    };
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(files) / sizeof(files[0]); i++)
        ok = source_open(dirfd, &files[i]);
    if (ok && !files[0].exists) {
        bool empty_family = !files[1].exists && !files[2].exists;
        for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++)
            if (files[i].fd >= 0)
                (void)close(files[i].fd);
        (void)close(dirfd);
        if (empty_family)
            return true;
        fprintf(stderr,
                "FATAL: normal node boot refused before datadir mutation: "
                "orphan %s WAL/SHM without a main database\n", kbase);
        return false;
    }

    struct stat datadir_identity;
    struct stat tmp_identity;
    if (ok && (fstat(dirfd, &datadir_identity) != 0 ||
               stat("/tmp", &tmp_identity) != 0 ||
               (datadir_identity.st_dev == tmp_identity.st_dev &&
                datadir_identity.st_ino == tmp_identity.st_ino))) {
        LOG_WARN(PREFLIGHT_SUBSYS,
                 "preflight disposable root cannot be the node datadir");
        ok = false;
    }

    char temp_dir[] = "/tmp/zcl-preflight-XXXXXX";
    if (ok && !mkdtemp(temp_dir))
        ok = false;
    char main_copy[2304];
    char wal_copy[2304];
    /* Keep the temp copy a consistent SQLite family: main + "<main>-wal" so the
     * inspect open below associates the WAL with the copied main db. */
    int n1 = snprintf(main_copy, sizeof(main_copy), "%s/%s", temp_dir, kbase);
    int n2 = snprintf(wal_copy, sizeof(wal_copy), "%s/%s-wal", temp_dir, kbase);
    if (ok && (n1 <= 0 || (size_t)n1 >= sizeof(main_copy) ||
               n2 <= 0 || (size_t)n2 >= sizeof(wal_copy)))
        ok = false;
    if (ok)
        ok = copy_exact_file(&files[0], main_copy) &&
             copy_exact_file(&files[1], wal_copy);
    for (size_t i = 0; ok && i < sizeof(files) / sizeof(files[0]); i++)
        ok = source_unchanged(dirfd, &files[i]);

    char reason[512] = {0};
    if (ok)
        ok = inspect_snapshot(main_copy, reason, sizeof(reason));
    for (size_t i = 0; ok && i < sizeof(files) / sizeof(files[0]); i++)
        ok = source_unchanged(dirfd, &files[i]);

    bool cleanup_ok = temp_dir[0] && access(temp_dir, F_OK) == 0
        ? remove_temp_family(temp_dir, main_copy) : true;
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++)
        if (files[i].fd >= 0 && close(files[i].fd) != 0)
            ok = false;
    if (close(dirfd) != 0)
        ok = false;
    if (!cleanup_ok)
        ok = false;

    if (!ok) {
        fprintf(stderr,
                "FATAL: normal node boot refused before datadir mutation: %s\n",
                reason[0] ? reason :
                    "producer evidence snapshot could not be proven stable");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "producer_evidence_preflight_refused reason=%s",
                    reason[0] ? reason : "stable_snapshot_inspection_failed");
    }
    return ok;
}

/* ── run_all: ONE preflight naming EVERY unmet -mint-anchor precondition ──
 *
 * See config/boot.h for the contract. Each check below is READ-ONLY: no
 * schema creation, no writes to node.db/progress.kv. node.db is opened
 * SQLITE_OPEN_READONLY so a missing/fresh file fails the check cleanly
 * instead of auto-vivifying an empty database. The datadir-lock check is the
 * one check that must touch the filesystem at all (flock semantics cannot be
 * probed without an open fd); it never creates the pidfile boot_datadir_lock
 * (config/src/boot_datadir_lock.c) uses if one is not already present, and
 * releases the flock it takes immediately. */

struct preflight_check {
    const char *name;
    bool (*check)(const char *datadir, char *why, size_t why_cap);
    const char *remedy;   /* one imperative sentence */
};

struct preflight_result {
    const char *name;
    bool        ok;
    char        why[256];
    const char *remedy;
};

/* ── individual checks ──────────────────────────────────────────────── */

static bool preflight_check_datadir_lock(const char *datadir, char *why,
                                         size_t why_cap)
{
    if (!datadir || !datadir[0]) {
        snprintf(why, why_cap, "datadir path is empty");
        return false;
    }
    int dirfd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) {
        snprintf(why, why_cap, "cannot open datadir %s: %s", datadir,
                 strerror(errno));
        return false;
    }
    /* Read-only probe of the SAME pidfile boot_datadir_lock_acquire() uses,
     * WITHOUT O_CREAT: absent means nothing has ever locked this datadir. If
     * present, take+immediately-release a non-blocking exclusive flock to
     * prove the lock is currently free — the real boot writes the pidfile
     * body later; this probe never does. */
    int fd = openat(dirfd, "zclassic23.pid",
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        int saved_errno = errno;
        close(dirfd);
        if (saved_errno == ENOENT) {
            snprintf(why, why_cap, "no existing lock file; acquirable");
            return true;
        }
        snprintf(why, why_cap, "cannot open %s/zclassic23.pid: %s", datadir,
                 strerror(saved_errno));
        return false;
    }
    bool acquirable = flock(fd, LOCK_EX | LOCK_NB) == 0;
    int saved_errno = errno;
    if (acquirable)
        (void)flock(fd, LOCK_UN);
    close(fd);
    close(dirfd);
    if (!acquirable) {
        snprintf(why, why_cap,
                 "datadir is locked by another process (flock: %s)",
                 strerror(saved_errno));
        return false;
    }
    snprintf(why, why_cap, "lock file present but currently unheld; acquirable");
    return true;
}

static bool preflight_check_legacy_block_index(const char *datadir, char *why,
                                                size_t why_cap)
{
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp) {
        snprintf(why, why_cap, "no compiled SHA3 UTXO checkpoint in this build");
        return false;
    }
    char path[1200];
    snprintf(path, sizeof(path), "%s/node.db", datadir ? datadir : ".");
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) {
        snprintf(why, why_cap,
                 "%s: %s (fresh datadir; no legacy block index imported yet)",
                 path, db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
        if (db)
            sqlite3_close(db);
        return false;
    }
    sqlite3_stmt *stmt = NULL;
    int64_t max_height = -1;
    bool have_row = false;
    if (sqlite3_prepare_v2(db, "SELECT MAX(height) FROM blocks", -1, &stmt,
                           NULL) == SQLITE_OK) {
        if (AR_STEP_ROW_READONLY(stmt) == SQLITE_ROW &&
            sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
            max_height = sqlite3_column_int64(stmt, 0);
            have_row = true;
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    if (!have_row) {
        snprintf(why, why_cap,
                 "%s has no 'blocks' rows (fresh datadir; no legacy block "
                 "index imported yet)", path);
        return false;
    }
    if (max_height < cp->height) {
        snprintf(why, why_cap,
                 "legacy block index only reaches height %lld, need >= "
                 "anchor height %d", (long long)max_height, cp->height);
        return false;
    }
    snprintf(why, why_cap,
             "legacy block index reaches height %lld (>= anchor %d)",
             (long long)max_height, cp->height);
    return true;
}

/* SAMPLED, coarse presence check (no O(chain) walk): counts blk*.dat files
 * and total bytes under <datadir>/blocks. node.db's `blocks.status` cannot be
 * used for this — --importblockindex ALWAYS clears BLOCK_HAVE_DATA there
 * (header-only import, app/controllers/src/snapshot_controller_import.c), and
 * the code that actually recomputes it from the .dat files
 * (config/src/boot_block_file_scan.c) runs later during app_init, after this
 * preflight. A totally empty/fresh datadir has zero blk*.dat files; that is
 * the exact "missing bodies -> stall" case this check catches upfront. */
static void preflight_scan_blk_dir(const char *blocks_dir, size_t *file_count,
                                   uint64_t *total_bytes)
{
    *file_count = 0;
    *total_bytes = 0;
    DIR *d = opendir(blocks_dir);
    if (!d)
        return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        size_t len = strlen(ent->d_name);
        if (len < 8 || strncmp(ent->d_name, "blk", 3) != 0 ||
            strcmp(ent->d_name + len - 4, ".dat") != 0)
            continue;
        char path[1200];
        snprintf(path, sizeof(path), "%s/%s", blocks_dir, ent->d_name);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            (*file_count)++;
            *total_bytes += (uint64_t)st.st_size;
        }
    }
    closedir(d);
}

static bool preflight_check_bodies_sampled(const char *datadir, char *why,
                                           size_t why_cap)
{
    char blocks_dir[1100];
    snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks",
             datadir ? datadir : ".");
    size_t file_count = 0;
    uint64_t total_bytes = 0;
    preflight_scan_blk_dir(blocks_dir, &file_count, &total_bytes);
    if (file_count > 0 && total_bytes >= 1024) {
        snprintf(why, why_cap,
                 "%s has %zu blk*.dat file(s) totaling %llu bytes (sampled; "
                 "not proof of contiguous coverage to the anchor)", blocks_dir,
                 file_count, (unsigned long long)total_bytes);
        return true;
    }

    /* The datadir has no bodies yet — but boot links them from the legacy
     * zclassicd source every boot when legacy auto-import is on
     * (boot_legacy_link_missing_block_files, config/src/boot.c). Probe the
     * same source path boot uses so the preflight matches what body_fetch
     * will actually see after boot. */
    char legacy_dir[1100];
    const char *env_legacy = getenv("ZCL_MINT_PREFLIGHT_LEGACY_BLOCKS_DIR");
    const char *home = getenv("HOME");
    if (env_legacy && env_legacy[0])
        snprintf(legacy_dir, sizeof(legacy_dir), "%s", env_legacy);
    else if (home)
        snprintf(legacy_dir, sizeof(legacy_dir), "%s/.zclassic/blocks", home);
    else
        snprintf(legacy_dir, sizeof(legacy_dir), ".zclassic/blocks");
    size_t legacy_count = 0;
    uint64_t legacy_bytes = 0;
    preflight_scan_blk_dir(legacy_dir, &legacy_count, &legacy_bytes);
    if (legacy_count > 0 && legacy_bytes >= 1024) {
        snprintf(why, why_cap,
                 "%s is empty but legacy source %s has %zu blk*.dat file(s) "
                 "totaling %llu bytes; boot links them at start (sampled)",
                 blocks_dir, legacy_dir, legacy_count,
                 (unsigned long long)legacy_bytes);
        return true;
    }

    snprintf(why, why_cap,
             "%s has %zu blk*.dat file(s) (%llu bytes) and legacy source %s "
             "has %zu; no block body data present (sampled check)",
             blocks_dir, file_count, (unsigned long long)total_bytes,
             legacy_dir, legacy_count);
    return false;
}

#define MINT_PREFLIGHT_DISK_FLOOR_BYTES   (50ULL * 1024 * 1024 * 1024)
#define MINT_PREFLIGHT_DISK_COMFORT_BYTES (100ULL * 1024 * 1024 * 1024)

static bool preflight_check_disk_headroom(const char *datadir, char *why,
                                          size_t why_cap)
{
    int64_t free_bytes = disk_monitor_free_bytes(datadir ? datadir : ".");
    if (free_bytes < 0) {
        snprintf(why, why_cap, "statvfs failed on %s; free space unknown",
                 datadir ? datadir : ".");
        return false;
    }
    double free_gb = (double)free_bytes / (1024.0 * 1024.0 * 1024.0);
    if ((uint64_t)free_bytes < MINT_PREFLIGHT_DISK_FLOOR_BYTES) {
        snprintf(why, why_cap,
                 "only %.1f GB free on the datadir filesystem (floor 50 GB)",
                 free_gb);
        return false;
    }
    if ((uint64_t)free_bytes < MINT_PREFLIGHT_DISK_COMFORT_BYTES) {
        snprintf(why, why_cap,
                 "WARN: only %.1f GB free (recommend >= 100 GB for a full "
                 "historical mint fold)", free_gb);
        return true;
    }
    snprintf(why, why_cap, "%.1f GB free", free_gb);
    return true;
}

/* Reuses the SAME orphan-detection shape as
 * boot_mint_anchor_normal_boot_preflight above (main db absent but a WAL/SHM
 * sibling present means a prior run was interrupted before the kernel-store
 * main db itself was created) as a cheap stat-only table entry — no temp-copy, no
 * inspect_snapshot: this runs BEFORE the fold starts, not as the normal-boot
 * containment gate. */
static bool preflight_check_leftover_wal(const char *datadir, char *why,
                                         size_t why_cap)
{
    const char *dir = datadir && datadir[0] ? datadir : ".";
    /* A4: a mint run writes its kernel to consensus.db post-flip; a legacy run
     * used progress.kv. An interrupted prior run of EITHER generation leaves an
     * orphaned WAL/SHM sibling without its main database — refuse before we
     * mutate the datadir. */
    static const char *const bases[] = { CONSENSUS_DB_FILENAME,
                                         CONSENSUS_DB_LEGACY_KERNEL_FILENAME };
    for (size_t b = 0; b < sizeof(bases) / sizeof(bases[0]); b++) {
        char main_path[1100], wal_path[1100], shm_path[1100];
        snprintf(main_path, sizeof(main_path), "%s/%s", dir, bases[b]);
        snprintf(wal_path, sizeof(wal_path), "%s/%s-wal", dir, bases[b]);
        snprintf(shm_path, sizeof(shm_path), "%s/%s-shm", dir, bases[b]);
        bool main_exists = access(main_path, F_OK) == 0;
        bool wal_exists = access(wal_path, F_OK) == 0;
        bool shm_exists = access(shm_path, F_OK) == 0;
        if (!main_exists && (wal_exists || shm_exists)) {
            snprintf(why, why_cap,
                     "orphaned %s WAL/SHM (wal=%d shm=%d) without its main "
                     "database — a prior run was interrupted before the main "
                     "database was created",
                     bases[b], wal_exists, shm_exists);
            return false;
        }
    }
    snprintf(why, why_cap, "no orphaned kernel-store WAL/SHM family");
    return true;
}

/* Mirrors coins_ram.c's COINS_RAM_DEFAULT_SLOTS (8M slots) * sizeof(struct
 * ram_slot) (~64 bytes) ~= 512MB for the slot array; rounded up to 576MB to
 * leave headroom for the per-coin heap scripts the fold allocates.
 * -mint-anchor defaults ZCL_FOLD_INRAM=1 unless the operator opts out
 * (src/main.c), so this check applies unless ZCL_FOLD_INRAM is explicitly
 * "0". WARN-only: never blocks the mint (the estimate is a slot-array floor,
 * not the full working-set peak, so a hard refusal here would be guessing). */
#define MINT_PREFLIGHT_FOLD_INRAM_ESTIMATE_BYTES (576ULL * 1024 * 1024)

static bool preflight_check_fold_inram_ram(const char *datadir, char *why,
                                           size_t why_cap)
{
    (void)datadir;
    const char *env = getenv("ZCL_FOLD_INRAM");
    bool inram_opted_out = env && env[0] && env[0] == '0';
    uint64_t total_ram = 0;
    if (!platform_system_memory_bytes(&total_ram)) {
        snprintf(why, why_cap,
                 "system memory query failed: %s; cannot estimate RAM",
                 strerror(errno));
        return true;   /* unmeasurable machine: do not block on it */
    }
    double total_gb = (double)total_ram / (1024.0 * 1024.0 * 1024.0);
    if (inram_opted_out) {
        snprintf(why, why_cap,
                 "ZCL_FOLD_INRAM=0: in-RAM hot store disabled; system has "
                 "%.1f GB RAM", total_gb);
        return true;
    }
    if (total_ram < MINT_PREFLIGHT_FOLD_INRAM_ESTIMATE_BYTES * 2) {
        snprintf(why, why_cap,
                 "WARN: -mint-anchor defaults to the in-RAM UTXO hot store "
                 "(~%llu MB slot array); system has only %.1f GB RAM total — "
                 "consider ZCL_FOLD_INRAM=0",
                 (unsigned long long)
                     (MINT_PREFLIGHT_FOLD_INRAM_ESTIMATE_BYTES / 1024 / 1024),
                 total_gb);
        return true;
    }
    snprintf(why, why_cap,
             "in-RAM hot store estimate ~%llu MB vs %.1f GB system RAM",
             (unsigned long long)
                 (MINT_PREFLIGHT_FOLD_INRAM_ESTIMATE_BYTES / 1024 / 1024),
             total_gb);
    return true;
}

static const struct preflight_check g_preflight_checks[] = {
    { "datadir_lock_acquirable", preflight_check_datadir_lock,
      "stop any other zclassic23 process using this datadir before starting "
      "-mint-anchor" },
    { "legacy_block_index_covers_anchor", preflight_check_legacy_block_index,
      "run: zclassic23 --importblockindex $HOME/.zclassic <datadir>/node.db "
      "(a zclassicd datadir with a header chain reaching the anchor height), "
      "then a normal boot before -mint-anchor" },
    { "bodies_present_sampled", preflight_check_bodies_sampled,
      "copy or fetch block body files (blk*.dat) into <datadir>/blocks "
      "before minting; a normal P2P boot (without -mint-anchor) fetches "
      "them lazily" },
    { "disk_headroom", preflight_check_disk_headroom,
      "free at least 50 GB on the datadir's filesystem before minting a "
      "full historical fold" },
    { "no_leftover_interrupted_run_artifacts", preflight_check_leftover_wal,
      "remove the orphaned kernel-store -wal/-shm files (consensus.db-* or "
      "legacy progress.kv-*), or restore the matching main database, before "
      "starting -mint-anchor" },
    { "fold_inram_memory_estimate", preflight_check_fold_inram_ram,
      "free memory, or pass ZCL_FOLD_INRAM=0 to fold through SQLite coins_kv "
      "instead of the in-RAM hot store" },
};
#define MINT_PREFLIGHT_NUM_CHECKS \
    (sizeof(g_preflight_checks) / sizeof(g_preflight_checks[0]))

/* Last-run snapshot for the `mint_preflight` dumpstate subsystem. Fixed-size,
 * no allocation, no threads: -mint-anchor is a single-threaded offline
 * one-shot that runs run_all before any service/thread starts. */
static struct {
    bool     valid;
    bool     all_ok;
    size_t   count;
    struct preflight_result results[MINT_PREFLIGHT_NUM_CHECKS];
} g_preflight_last;

bool boot_mint_anchor_preflight_run_all(const char *datadir,
                                        struct json_value *report)
{
    if (!datadir || !datadir[0])
        LOG_FAIL(PREFLIGHT_SUBSYS, "preflight run_all: missing datadir");

    struct json_value checks_arr = {0};
    if (report) {
        json_set_object(report);
        json_set_array(&checks_arr);
    }

    bool all_ok = true;
    size_t failed_count = 0;
    const char *failed_names[MINT_PREFLIGHT_NUM_CHECKS];

    g_preflight_last.count = MINT_PREFLIGHT_NUM_CHECKS;

    for (size_t i = 0; i < MINT_PREFLIGHT_NUM_CHECKS; i++) {
        const struct preflight_check *c = &g_preflight_checks[i];
        char why[256] = {0};
        bool ok = c->check(datadir, why, sizeof(why));

        g_preflight_last.results[i].name = c->name;
        g_preflight_last.results[i].ok = ok;
        snprintf(g_preflight_last.results[i].why,
                 sizeof(g_preflight_last.results[i].why), "%s", why);
        g_preflight_last.results[i].remedy = c->remedy;

        fprintf(stderr, "[mint-preflight] %-38s %-4s %s%s%s\n", c->name,
                ok ? "OK" : "FAIL", why, ok ? "" : " — remedy: ",
                ok ? "" : c->remedy);

        if (report) {
            struct json_value row = {0};
            json_set_object(&row);
            json_push_kv_str(&row, "name", c->name);
            json_push_kv_bool(&row, "ok", ok);
            json_push_kv_str(&row, "why", why);
            json_push_kv_str(&row, "remedy", c->remedy);
            json_push_back(&checks_arr, &row);
            json_free(&row);
        }

        if (!ok) {
            all_ok = false;
            failed_names[failed_count++] = c->name;
        }
    }
    g_preflight_last.all_ok = all_ok;
    g_preflight_last.valid = true;

    if (report) {
        json_push_kv(report, "checks", &checks_arr);
        json_free(&checks_arr);
        json_push_kv_bool(report, "all_ok", all_ok);
    }

    if (!all_ok) {
        char summary[1024] = {0};
        size_t pos = 0;
        for (size_t i = 0; i < failed_count && pos < sizeof(summary); i++) {
            int n = snprintf(summary + pos, sizeof(summary) - pos, "%s%s",
                             i ? "," : "", failed_names[i]);
            if (n > 0)
                pos += (size_t)n;
        }
        fprintf(stderr,
                "FATAL: -mint-anchor preflight found %zu unmet "
                "precondition(s) before any datadir mutation: %s — see the "
                "per-check lines above for the exact why + remedy\n",
                failed_count, summary);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "mint_anchor_preflight failed_checks=%s", summary);
    }
    return all_ok;
}

bool boot_mint_anchor_preflight_dump_state_json(struct json_value *out,
                                                const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);
    json_push_kv_bool(out, "have_report", g_preflight_last.valid);
    if (!g_preflight_last.valid)
        return true;
    json_push_kv_bool(out, "all_ok", g_preflight_last.all_ok);
    struct json_value arr = {0};
    json_set_array(&arr);
    for (size_t i = 0; i < g_preflight_last.count; i++) {
        struct json_value row = {0};
        json_set_object(&row);
        json_push_kv_str(&row, "name", g_preflight_last.results[i].name);
        json_push_kv_bool(&row, "ok", g_preflight_last.results[i].ok);
        json_push_kv_str(&row, "why", g_preflight_last.results[i].why);
        json_push_kv_str(&row, "remedy", g_preflight_last.results[i].remedy);
        json_push_back(&arr, &row);
        json_free(&row);
    }
    json_push_kv(out, "checks", &arr);
    json_free(&arr);
    return true;
}

#endif
