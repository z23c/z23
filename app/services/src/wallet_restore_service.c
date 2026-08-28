/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet Restore Service — merge a wallet backup file back into a datadir.
 * See services/wallet_restore_service.h for the contract and the three
 * things this refuses to do (touch a held datadir, install the backup as
 * node.db, overwrite an existing row).
 *
 * Order of operations, and why it is this order:
 *
 *   1. prove the datadir is free      — before anything is opened, because
 *                                       opening node.db is itself a write
 *   2. decrypt if the file is WBE1    — into a 0600 temp beside the target,
 *                                       unlinked on every exit path
 *   3. inspect the backup             — read-only; refuse a file that holds
 *                                       none of the wallet tables before
 *                                       the target is touched at all
 *   4. open the target via node_db_open — the schema path, so every wallet
 *                                       table has its real keys/constraints
 *   5. merge in ONE transaction       — dry runs roll it back and still
 *                                       report exact counts
 */

#include "services/wallet_restore_service.h"

#include "services/wallet_backup_service.h"
#include "adapters/outbound/persistence/wallet_restore_store_sqlite.h"
#include "models/database.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define WRS_TAG "wallet_restore"

/* Same name boot_datadir_lock.c writes. */
#define WRS_PIDFILE "zclassic23.pid"

/* ── datadir single-writer proof ────────────────────────────── */

/* Read the pid recorded in an open pidfile; 0 when unreadable. */
#ifndef _WIN32
static long wrs_holder_pid(int fd)
{
    char buf[32] = {0};
    if (pread(fd, buf, sizeof(buf) - 1, 0) <= 0)
        return 0;
    char *end = NULL;
    errno = 0;
    long pid = strtol(buf, &end, 10);
    if (errno != 0 || end == buf || pid <= 0)
        return 0;
    return pid;
}
#endif

struct zcl_result wallet_restore_datadir_free(const char *datadir)
{
    if (!datadir || !datadir[0]) {
        LOG_WARN(WRS_TAG, "datadir_free: datadir path is empty");
        return ZCL_ERR(-50, "datadir path is empty");
    }
#ifdef _WIN32
    return ZCL_ERR(-58,
                   "native Windows wallet restore lock queries are disabled "
                   "until current-SID single-writer qualification passes");
#else
    char path[1200];
    snprintf(path, sizeof(path), "%s/%s", datadir, WRS_PIDFILE);

    /* No pidfile at all: nothing has ever locked this datadir. A restore
     * into a fresh directory is the whole disaster-recovery case, so this
     * is the common success path, not an anomaly. */
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT)
            return ZCL_OK;
        LOG_WARN(WRS_TAG, "datadir_free: cannot open %s: %s", path,
                 strerror(errno));
        return ZCL_ERR(-51, "cannot open %s: %s", path, strerror(errno));
    }

    /* Take + immediately release a non-blocking exclusive flock. Holding it
     * would be pointless: node.db is opened later on a different fd, and a
     * node that starts mid-restore is refused by its OWN acquire. */
    bool free_now = flock(fd, LOCK_EX | LOCK_NB) == 0;
    int saved = errno;
    long pid = free_now ? 0 : wrs_holder_pid(fd);
    if (free_now)
        (void)flock(fd, LOCK_UN);
    close(fd);
    if (free_now)
        return ZCL_OK;
    if (pid > 0)
        return ZCL_ERR(-52, "a node is holding %s (pid %ld); stop it first",
                       datadir, pid);
    return ZCL_ERR(-52, "a node is holding %s (flock: %s); stop it first",
                   datadir, strerror(saved));
#endif
}

/* ── the WRITER's lock, held across check-then-write ─────────── */

/* Its own file, deliberately not the node pidfile: a fresh recovery datadir
 * has no pidfile, and minting one would look to every other tool like a
 * running node. See the contract on wallet_restore_datadir_hold. */
#define WRS_WRITE_LOCKFILE "wallet-recovery.lock"

struct zcl_result wallet_restore_datadir_hold(
    const char *datadir, struct wallet_restore_datadir_lock *lock)
{
    if (!lock) {
        LOG_WARN(WRS_TAG, "datadir_hold: lock argument is required");
        return ZCL_ERR(-55, "datadir_hold: lock argument is required");
    }
    lock->fd = -1;
    lock->path[0] = '\0';
    if (!datadir || !datadir[0]) {
        LOG_WARN(WRS_TAG, "datadir_hold: datadir path is empty");
        return ZCL_ERR(-55, "datadir path is empty");
    }
#ifdef _WIN32
    return ZCL_ERR(-58,
                   "native Windows wallet restore locking is disabled until "
                   "current-SID, no-reparse private transaction "
                   "qualification passes");
#else
    int n = snprintf(lock->path, sizeof(lock->path), "%s/%s", datadir,
                     WRS_WRITE_LOCKFILE);
    if (n <= 0 || (size_t)n >= sizeof(lock->path)) {
        lock->path[0] = '\0';
        return ZCL_ERR(-55, "datadir path too long for a recovery lock");
    }

    /* 0600: this sits beside the wallet and names what is happening to it. */
    int fd = open(lock->path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        LOG_WARN(WRS_TAG, "datadir_hold: cannot open %s: %s", lock->path,
                 strerror(errno));
        return ZCL_ERR(-56, "cannot take the recovery lock at %s: %s",
                       lock->path, strerror(errno));
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        int saved = errno;
        close(fd);
        lock->path[0] = '\0';
        LOG_WARN(WRS_TAG, "datadir_hold: %s is already held (%s)",
                 datadir, strerror(saved));
        return ZCL_ERR(-57,
            "another wallet recovery is already writing %s. Only one may "
            "run at a time: two that both checked an empty datadir would "
            "both write, and leave one wallet holding keys from two "
            "different seeds with no way to tell them apart. Wait for the "
            "other one to finish, then look at what it left", datadir);
    }
    /* Who holds it, for the next operator to read. Best-effort: the flock,
     * not this text, is the lock. */
    {
        char who[64];
        int wn = snprintf(who, sizeof(who), "%ld\n", (long)getpid());
        if (wn > 0) {
            if (ftruncate(fd, 0) != 0 || pwrite(fd, who, (size_t)wn, 0) < 0)
                LOG_WARN(WRS_TAG, "datadir_hold: could not stamp %s: %s",
                         lock->path, strerror(errno));
        }
    }
    lock->fd = fd;
    return ZCL_OK;
#endif
}

void wallet_restore_datadir_release(struct wallet_restore_datadir_lock *lock)
{
#ifdef _WIN32
    if (lock) {
        lock->fd = -1;
        lock->path[0] = '\0';
    }
    return;
#else
    if (!lock || lock->fd < 0)
        return;
    /* close() drops the flock; the unlock is explicit so the intent is
     * readable and so a future refactor that keeps the fd cannot silently
     * keep the lock. The file itself stays: unlinking it would let a second
     * writer create a NEW inode and lock that instead. */
    (void)flock(lock->fd, LOCK_UN);
    close(lock->fd);
    lock->fd = -1;
#endif
}

/* ── helpers ────────────────────────────────────────────────── */

#ifndef _WIN32
static void wrs_warn(struct wallet_restore_report *rep, const char *what)
{
    size_t used = strlen(rep->warnings);
    size_t need = strlen(what) + (used ? 1 : 0) + 1;
    if (used + need > sizeof(rep->warnings))
        return;
    if (used)
        rep->warnings[used++] = ',';
    snprintf(rep->warnings + used, sizeof(rep->warnings) - used, "%s", what);
}

/* True when the file starts with the WBE1 encrypted-backup magic. */
static bool wrs_is_encrypted(const char *path)
{
#ifdef _WIN32
    (void)path;
    return false;
#else
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    char magic[4] = {0};
    ssize_t n = read(fd, magic, sizeof(magic));
    close(fd);
    return n == (ssize_t)sizeof(magic) &&
           memcmp(magic, WALLET_BACKUP_ENC_MAGIC, sizeof(magic)) == 0;
#endif
}

/* Roll up the per-table numbers and flag manifest disagreements. */
static void wrs_summarize(struct wallet_restore_report *rep)
{
    rep->total_rows_in_backup = 0;
    rep->total_inserted = 0;
    rep->total_collided = 0;
    rep->total_rejected = 0;
    rep->tables_in_backup = 0;
    rep->manifest_rows = 0;
    rep->manifest_mismatches = 0;
    for (size_t i = 0; i < rep->n_tables; i++) {
        const struct wallet_restore_table_report *t = &rep->tables[i];
        if (t->in_backup)
            rep->tables_in_backup++;
        if (t->rows_in_backup > 0)
            rep->total_rows_in_backup += t->rows_in_backup;
        if (t->rows_inserted > 0)
            rep->total_inserted += t->rows_inserted;
        if (t->rows_collided > 0)
            rep->total_collided += t->rows_collided;
        if (t->rows_rejected > 0)
            rep->total_rejected += t->rows_rejected;
        if (t->manifest_row_count >= 0 || t->manifest_present_in_source) {
            rep->manifest_rows++;
            int64_t claimed = t->manifest_row_count;
            int64_t actual = t->rows_in_backup < 0 ? 0 : t->rows_in_backup;
            if (t->manifest_present_in_source && claimed >= 0 &&
                claimed != actual)
                rep->manifest_mismatches++;
        }
    }
    if (rep->manifest_rows == 0)
        wrs_warn(rep, "backup_has_no_manifest");
    if (rep->manifest_mismatches > 0)
        wrs_warn(rep, "manifest_mismatch_short_copy");
    if (rep->total_rejected > 0)
        wrs_warn(rep, "rows_rejected_by_target_schema");
}

/* ── the run ────────────────────────────────────────────────── */

/* Decrypt `src` to `tmp_out` when it carries the WBE1 magic. Returns
 * ZCL_OK and leaves `tmp_out` empty when the source is plaintext. */
static struct zcl_result wrs_materialize(const char *src, const char *password,
                                         char *tmp_out, size_t tmp_cap,
                                         struct wallet_restore_report *rep)
{
    tmp_out[0] = '\0';
    if (!wrs_is_encrypted(src))
        return ZCL_OK;

    rep->source_was_encrypted = true;
    const char *pw = (password && password[0])
                     ? password : getenv("WALLET_BACKUP_PASSWORD");
    if (!pw || !pw[0]) {
        LOG_WARN(WRS_TAG, "%s is encrypted and no password was supplied", src);
        return ZCL_ERR(-40,
            "backup %s is encrypted; set WALLET_BACKUP_PASSWORD (or pass "
            "password) to restore it", src);
    }

    snprintf(tmp_out, tmp_cap, "%s.restore-%ld.tmp", rep->target_db,
             (long)getpid());
    (void)unlink(tmp_out);
    struct zcl_result dr = wallet_backup_decrypt_file(src, tmp_out, pw);
    if (!dr.ok) {
        (void)unlink(tmp_out);
        tmp_out[0] = '\0';
        LOG_WARN(WRS_TAG, "decrypt of %s failed: %s", src, dr.message);
        return ZCL_ERR(-41, "cannot decrypt %s: %s", src, dr.message);
    }
    (void)chmod(tmp_out, 0600);
    return ZCL_OK;
}
#endif

struct zcl_result wallet_restore_run(const struct wallet_restore_request *req,
                                     struct wallet_restore_report *out)
{
    if (!out)
        return ZCL_ERR(-30, "restore: report argument is required");
    memset(out, 0, sizeof(*out));
    if (!req || !req->backup_path || !req->backup_path[0] ||
        !req->datadir || !req->datadir[0]) {
        LOG_WARN(WRS_TAG, "restore: backup_path and datadir are both required");
        return ZCL_ERR(-31, "restore: backup_path and datadir are required");
    }
#ifdef _WIN32
    return ZCL_ERR(-58,
                   "native Windows wallet restore is disabled until the "
                   "current-SID single-writer, no-reparse private restore "
                   "transaction passes qualification");
#else

    size_t n_tables = 0;
    const char *const *tables = wallet_backup_tables(&n_tables);
    if (n_tables > WALLET_RESTORE_TABLE_MAX) {
        LOG_WARN(WRS_TAG, "wallet table set (%zu) exceeds report capacity",
                 n_tables);
        return ZCL_ERR(-32, "restore: wallet table set exceeds report capacity");
    }
    out->n_tables = n_tables;
    out->dry_run = req->dry_run;
    snprintf(out->backup_path, sizeof(out->backup_path), "%s",
             req->backup_path);
    snprintf(out->target_db, sizeof(out->target_db), "%s/node.db",
             req->datadir);

    struct stat st;
    if (stat(req->backup_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        LOG_WARN(WRS_TAG, "backup %s is not a readable file", req->backup_path);
        return ZCL_ERR(-33, "backup %s is not a readable file",
                       req->backup_path);
    }
    out->target_created = stat(out->target_db, &st) != 0;

    /* Restoring onto a rebuilt machine means the datadir may not exist yet.
     * Create it 0700 — a directory that does not exist cannot be held by a
     * node, so this cannot race the single-writer proof below. */
    if (stat(req->datadir, &st) != 0) {
        if (mkdir(req->datadir, 0700) != 0) {
            LOG_WARN(WRS_TAG, "cannot create datadir %s: %s", req->datadir,
                     strerror(errno));
            return ZCL_ERR(-39, "cannot create datadir %s: %s", req->datadir,
                           strerror(errno));
        }
    } else if (!S_ISDIR(st.st_mode)) {
        LOG_WARN(WRS_TAG, "%s is not a directory", req->datadir);
        return ZCL_ERR(-39, "%s is not a directory", req->datadir);
    }

    /* (1) Single-writer proof BEFORE anything opens the datadir. */
    struct zcl_result lock_r = wallet_restore_datadir_free(req->datadir);
    if (!lock_r.ok) {
        LOG_WARN(WRS_TAG, "refusing restore: %s", lock_r.message);
        return ZCL_ERR(-34, "%s", lock_r.message);
    }

    /* (2) Decrypt if needed. */
    char tmp[1200];
    struct zcl_result mr = wrs_materialize(req->backup_path, req->password,
                                           tmp, sizeof(tmp), out);
    if (!mr.ok)
        return mr;
    const char *source = tmp[0] ? tmp : req->backup_path;

    struct wallet_restore_store_sqlite_ctx ctx;
    struct wallet_restore_store_port port = {0};
    (void)wallet_restore_store_sqlite_bind(&ctx, NULL, &port);

    /* (3) Inspect read-only; refuse a file that is not a wallet backup
     * before the target datadir is touched at all. */
    char err[ZCL_RESULT_MSG_MAX] = "";
    enum wallet_restore_store_status is =
        port.inspect_backup(port.self, source, tables, n_tables,
                            out->tables, err, sizeof(err));
    if (is != WR_STORE_OK) {
        if (tmp[0]) (void)unlink(tmp);
        LOG_WARN(WRS_TAG, "inspect failed: %s", err);
        return ZCL_ERR(-35, "%s", err[0] ? err : "cannot read backup file");
    }
    wrs_summarize(out);
    if (out->tables_in_backup == 0) {
        if (tmp[0]) (void)unlink(tmp);
        LOG_WARN(WRS_TAG, "%s holds none of the %zu wallet tables",
                 req->backup_path, n_tables);
        return ZCL_ERR(-36,
            "%s holds none of the %zu wallet tables — not a wallet backup",
            req->backup_path, n_tables);
    }

    /* (4) Open the TARGET through the schema path. */
    struct node_db ndb;
    if (!node_db_open(&ndb, out->target_db)) {
        if (tmp[0]) (void)unlink(tmp);
        LOG_WARN(WRS_TAG, "cannot open target %s", out->target_db);
        return ZCL_ERR(-37, "cannot open target database %s", out->target_db);
    }

    /* (5) Merge in one transaction; a dry run rolls it back. */
    (void)wallet_restore_store_sqlite_bind(&ctx, ndb.db, &port);
    enum wallet_restore_store_status ms =
        port.merge_into_target(port.self, source, tables, n_tables,
                               req->dry_run, out->tables, err, sizeof(err));
    node_db_close(&ndb);
    if (tmp[0]) (void)unlink(tmp);

    wrs_summarize(out);

    if (ms != WR_STORE_OK) {
        LOG_WARN(WRS_TAG, "merge into %s failed: %s", out->target_db, err);
        return ZCL_ERR(-38, "%s", err[0] ? err : "restore merge failed");
    }
    return ZCL_OK;
#endif
}
