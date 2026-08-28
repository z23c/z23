/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The ONE read-only <datadir>/node.db open shared by native command leaves.
 *
 * Purpose: a leaf whose declared effect is READ must be able to open the
 * node database without any chance of writing to it. Before this file every
 * such leaf hand-rolled the same twenty lines, and six leaves got it wrong
 * in the other direction — they called node_db_open(), the BOOT ceremony,
 * which opens READWRITE|CREATE and then creates schema, migrates,
 * rename()s the file aside on a failed quick_check, and DELETEs the
 * snapshot_staging rows. Because `datadir` defaults to the CLI's resolved
 * datadir, running one of those leaves with no arguments did that to the
 * operator's LIVE node. See the contract comment on
 * zcl_native_node_db_open_readonly in command/native_command.h.
 *
 * Nothing here creates, migrates, schema-initializes, quarantines, renames
 * or deletes. The only sqlite3 calls are open_v2(READONLY), the query_only
 * pragma, busy_timeout, close, and — on the immutable path only — the three
 * read-side hooks that arm the snapshot guard (see struct zcl_ro_guard). None
 * of them writes, and the guard itself only stats.
 *
 * AND SQLITE_OPEN_READONLY IS NOT ENOUGH ON ITS OWN. Both stores under a
 * datadir are WAL-mode (app/models/src/database.c sets journal_mode=WAL for
 * node.db, lib/storage/src/progress_store.c for consensus.db), and a
 * read-only connection to a WAL database still has to materialize the
 * wal-index before it can read consistently. So sqlite CREATES <db>-shm and
 * <db>-wal beside the database — and a read-only connection cannot unlink
 * them again on close, because unlinking them needs the write lock it does
 * not hold. Measured against the vendored sqlite 3.49.0: a directory holding
 * one 8192-byte node.db came out of open_v2(READONLY) + query_only +
 * schema_version + close holding node.db, node.db-shm (32768 bytes) and
 * node.db-wal (0 bytes).
 *
 * Two files appearing is not a rounding error on this project. The whole
 * recovery doctrine is copy-prove-then-trust-the-proof: copy a datadir, hash
 * it, ask a read leaf a question about the copy, and rely on the hash still
 * describing what is on disk. A read that adds two files has silently voided
 * that proof. And when the read runs as a different user than the node — an
 * operator or a CI job inspecting a copy as root — the sidecars land owned by
 * the wrong uid, where the node's own later open of that directory trips over
 * them.
 *
 * WHAT THIS FILE DOES INSTEAD is pick the open that is side-effect free for
 * the state the database is actually in, because no single open is:
 *
 *   not WAL mode        open_v2(READONLY). A rollback-journal database needs
 *                       no wal-index, so this creates nothing. (Also the
 *                       path a non-database takes, where the header touch
 *                       below is what refuses it.)
 *   WAL, wal-index
 *   already present     open_v2(READONLY). Both sidecars exist, so there is
 *                       nothing left to create, and reading through the live
 *                       wal-index is the ONLY way to see a running node's
 *                       uncheckpointed commits. This is the live-node case.
 *   WAL, no wal-index   file:...?immutable=1. Tells sqlite the database will
 *                       not change under it, which is what lets it skip the
 *                       wal-index entirely: zero files created. Safe here
 *                       precisely BECAUSE there is no wal-index — a WAL
 *                       writer holds one open for the whole life of its
 *                       connection, so its absence means no writer is
 *                       attached and no committed frame is waiting in a log
 *                       for immutable=1 to miss. That premise is an INSTANT,
 *                       not a guarantee, so this branch alone also arms the
 *                       snapshot guard that keeps re-checking it for as long
 *                       as the handle lives.
 *
 * immutable=1 is deliberately NOT the blanket answer, and the measurement is
 * why: pointed at a database a writer WAS attached to, an immutable=1 read
 * returned 1 row where the truth was 2. It does not consult the log. Reaching
 * for it unconditionally would have traded two stray files for silently stale
 * answers, which on this project is the worse bug — a diagnostic that reads a
 * running node and quietly reports its pre-WAL past.
 *
 * The one state with no side-effect-free correct read is a non-empty <db>-wal
 * with no <db>-shm: the log holds commits, and consulting it means creating
 * the wal-index. That is reported as ZCL_NODE_DB_RO_UNRECOVERED_LOG rather
 * than answered — a named refusal, never a quiet stale read and never a
 * created file. */

#define _GNU_SOURCE
#include "command/native_command.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "models/database.h"
#include "storage/consensus_db.h"
#include "platform/positioned_file.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* A locked WAL must give up rather than park a cursor on a connection the
 * live node is writing through (see the wallet write-wedge post-mortem). */
#define ZCL_NODE_DB_RO_BUSY_MS 2000

/* The longest datadir-derived path a caller hands in is 1200 bytes (see the
 * `path` buffers below), and a file: URI percent-encodes at worst 3 bytes per
 * byte, plus "file:" and "?immutable=1". */
#define ZCL_NODE_DB_RO_URI_MAX (1200 * 3 + 32)

/* Is the database at `path` in WAL mode? Header byte 18 is the "file format
 * write version": 1 for a rollback journal, 2 for WAL. Twenty bytes of read,
 * so this creates nothing, and it survives a clean close — the byte stays 2
 * on a WAL database whose sidecars have been checkpointed away, which is
 * exactly the copied-datadir case that has to be recognized.
 *
 * Anything that is short, or does not carry the magic, is reported as NOT
 * WAL. That routes a non-database through the plain open, where the header
 * touch in zcl_ro_attach is what refuses it — the same answer as before this
 * distinction existed. */
static bool zcl_ro_is_wal_database(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    unsigned char hdr[20] = { 0 };
    size_t got = fread(hdr, 1, sizeof(hdr), f);
    fclose(f);
    if (got < sizeof(hdr))
        return false;
    /* 16 bytes, NUL included — the literal is exactly the header magic. */
    if (memcmp(hdr, "SQLite format 3", 16) != 0)
        return false;
    return hdr[18] == 2;
}

/* What already sits beside the database. `wal_bytes` is -1 when there is no
 * log at all, which is a different fact from a log of length 0. */
struct zcl_ro_sidecars {
    bool wal;
    bool shm;
    long long wal_bytes;
};

static void zcl_ro_probe_sidecars(const char *path,
                                  struct zcl_ro_sidecars *out)
{
    out->wal = false;
    out->shm = false;
    out->wal_bytes = -1;

    char side[1300];
    struct stat st;
    int n = snprintf(side, sizeof(side), "%s-wal", path);
    if (n > 0 && (size_t)n < sizeof(side) && stat(side, &st) == 0) {
        out->wal = true;
        out->wal_bytes = (long long)st.st_size;
    }
    n = snprintf(side, sizeof(side), "%s-shm", path);
    if (n > 0 && (size_t)n < sizeof(side) && stat(side, &st) == 0)
        out->shm = true;
}

/* ── the immutable snapshot's guard ────────────────────────────────────
 *
 * The open-time reasoning above ("no wal-index means no writer is attached")
 * is true at the instant it is checked and NOT DURABLE. The handle outlives
 * that instant: it goes back to a leaf that prepares its own statements
 * afterwards, and immutable=1 does not consult a write-ahead log. Measured on
 * the vendored sqlite 3.49.0, with the writer arriving AFTER the open returned:
 * the handle answered 1 where the truth was 2, with no error and no log line
 * — the exact silently-stale read this file exists to refuse.
 *
 * So the premise is re-checked on the connection itself, at every statement,
 * for as long as the handle lives. Two facts are pinned at open:
 *
 *   the sidecars — a WAL writer creates <db>-wal and <db>-shm and holds them
 *                  for the life of its connection, so either one appearing (or
 *                  the log growing) is a writer that attached under this read;
 *   the main file's identity (dev/inode/size/mtime) — because a writer that
 *                  attached, committed, checkpointed and CLOSED again takes
 *                  its sidecars with it. That leaves no sidecar to see, and
 *                  measurement says it leaves no header trace either: in WAL
 *                  mode the change counter does NOT move across a commit, so
 *                  the rewritten main file is only visible as a stat change.
 *
 * Either one drifting is a named refusal, never a quiet stale answer. The
 * check reads two directory entries and one inode; it creates nothing, so the
 * guard cannot break the no-datadir-write guarantee it is defending. */
struct zcl_ro_guard {
    char path[1200];
    struct zcl_ro_sidecars at_open;
    struct platform_positioned_file_snapshot snapshot;
    /* One log line per handle: the authorizer fires per statement and a
     * drifted snapshot stays drifted, so without this a refused read would
     * repeat itself down the log. */
    bool reported;
};

/* True while the database still looks exactly as it did when the immutable
 * snapshot was justified.
 *
 * The two sidecar tests that CAN be stated absolutely are stated absolutely,
 * and not as "unchanged since the baseline", on purpose: the baseline is taken
 * a few instructions after the probe that chose the immutable open, so a writer
 * landing in that gap would be captured in the baseline as if it had always
 * been there and every later check would then read its footprint as normal. A
 * wal-index beside an immutable read is never normal — that is the whole
 * premise of the branch — so it is refused on its own terms, whatever the
 * baseline says. */
static bool zcl_ro_guard_intact(struct zcl_ro_guard *g)
{
    struct zcl_ro_sidecars now;
    zcl_ro_probe_sidecars(g->path, &now);
    const char *why = NULL;
    if (now.shm)
        why = "a wal-index (<db>-shm) is beside it";
    else if (now.wal && now.wal_bytes > 0)
        why = "it carries a non-empty write-ahead log";
    else if (now.wal != g->at_open.wal)
        why = "a write-ahead log (<db>-wal) appeared beside it";
    else if (now.wal_bytes != g->at_open.wal_bytes)
        why = "its write-ahead log changed length";

    if (!why) {
        struct platform_positioned_file file;
        struct platform_positioned_file_snapshot snapshot;
        platform_positioned_file_init(&file);
        bool opened = platform_positioned_file_open(&file, g->path);
        bool snapped = opened && platform_positioned_file_snapshot(&file, &snapshot);
        platform_positioned_file_close(&file);
        if (!snapped)
            why = "it can no longer be opened and snapshotted";
        else if (snapshot.volume != g->snapshot.volume ||
                 snapshot.file_low != g->snapshot.file_low ||
                 snapshot.file_high != g->snapshot.file_high)
            why = "it was replaced by a different file";
        else if (snapshot.size != g->snapshot.size)
            why = "its length changed";
        else if (snapshot.modified_seconds != g->snapshot.modified_seconds ||
                 snapshot.modified_nanoseconds != g->snapshot.modified_nanoseconds)
            why = "it was written to";
    }
    if (!why)
        return true;

    if (!g->reported) {
        g->reported = true;
        LOG_ERROR("cmd",
                  "%s changed while a read-only snapshot of it was open (%s), "
                  "and an immutable snapshot does not consult a write-ahead "
                  "log: refusing every further statement on this handle rather "
                  "than answering from the database's pre-change state. Retry "
                  "the read once the owning node is attached (the read then "
                  "goes through its wal-index) or once the datadir is quiet",
                  g->path, why);
    }
    return false;
}

/* Fires at every statement preparation. Restricted to the two authorizer ops a
 * query_only READONLY handle can produce as a statement ROOT — SQLITE_READ
 * fires once per column, and paying three directory lookups per column would
 * make the guard the cost of the read. */
static int zcl_ro_guard_authorize(void *arg, int op, const char *a,
                                  const char *b, const char *c, const char *d)
{
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    if (op != SQLITE_SELECT && op != SQLITE_PRAGMA)
        return SQLITE_OK;
    return zcl_ro_guard_intact((struct zcl_ro_guard *)arg) ? SQLITE_OK
                                                           : SQLITE_DENY;
}

/* And during execution, for the window the authorizer cannot see: a statement
 * prepared while the snapshot was still good and stepped after a writer
 * arrived. Best-effort by construction — sqlite counts VDBE instructions, so a
 * statement that finishes inside one interval is never sampled — which is why
 * it is the second line of defence and not the first. The interval is coarse
 * on purpose: it is a long table scan this is here to interrupt, and those
 * sample many times over. */
#define ZCL_RO_GUARD_VDBE_OPS 4096

static int zcl_ro_guard_progress(void *arg)
{
    return zcl_ro_guard_intact((struct zcl_ro_guard *)arg) ? 0 : 1;
}

/* Never called: registering a function is how the guard's lifetime is tied to
 * the CONNECTION's. Callers close these handles with a bare sqlite3_close()
 * (the kernel-store handle has no shim to close through), so there is no
 * caller-side hook to free the guard in — but sqlite runs a function's
 * destructor when the connection goes away, however it goes away. */
static void zcl_ro_guard_marker(sqlite3_context *ctx, int argc,
                                sqlite3_value **argv)
{
    (void)argc;
    (void)argv;
    sqlite3_result_null(ctx);
}

static void zcl_ro_guard_destroy(void *arg)
{
    free(arg);
}

/* Arm the guard on an immutable handle. `at_open` is the sidecar state the
 * immutable open was justified by, already re-probed by the caller. */
static enum zcl_node_db_ro_status zcl_ro_guard_arm(
    sqlite3 *db, const char *path, const struct zcl_ro_sidecars *at_open)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snapshot;
    platform_positioned_file_init(&file);
    bool snapped = platform_positioned_file_open(&file, path) &&
                   platform_positioned_file_snapshot(&file, &snapshot);
    platform_positioned_file_close(&file);
    if (!snapped)
        LOG_RETURN(ZCL_NODE_DB_RO_UNREADABLE, "cmd",
                   "cannot stat %s to pin the read-only snapshot it was just "
                   "opened from", path);

    struct zcl_ro_guard *g = zcl_calloc(1, sizeof(*g), "ro_snapshot_guard");
    if (!g)
        LOG_RETURN(ZCL_NODE_DB_RO_UNREADABLE, "cmd",
                   "out of memory pinning the read-only snapshot of %s — "
                   "refusing rather than handing back a handle that could go "
                   "stale unnoticed", path);
    size_t n = strlen(path);
    if (n >= sizeof(g->path)) {
        free(g);
        LOG_RETURN(ZCL_NODE_DB_RO_PATH_TOO_LONG, "cmd",
                   "database path does not fit the snapshot guard: %s", path);
    }
    memcpy(g->path, path, n + 1);
    g->at_open = *at_open;
    g->snapshot = snapshot;

    /* The destructor registration comes FIRST: once it is in place the guard
     * is owned by the connection and cannot leak, whatever the next call
     * does. */
    if (sqlite3_create_function_v2(db, "zcl_ro_snapshot_guard", 0,
                                   SQLITE_UTF8, g, zcl_ro_guard_marker, NULL,
                                   NULL, zcl_ro_guard_destroy) != SQLITE_OK) {
        free(g);
        LOG_RETURN(ZCL_NODE_DB_RO_UNREADABLE, "cmd",
                   "could not arm the read-only snapshot guard on %s: %s",
                   path, sqlite3_errmsg(db));
    }
    if (sqlite3_set_authorizer(db, zcl_ro_guard_authorize, g) != SQLITE_OK)
        LOG_RETURN(ZCL_NODE_DB_RO_UNREADABLE, "cmd",
                   "could not arm the read-only snapshot authorizer on %s: %s",
                   path, sqlite3_errmsg(db));
    sqlite3_progress_handler(db, ZCL_RO_GUARD_VDBE_OPS, zcl_ro_guard_progress,
                             g);
    return ZCL_NODE_DB_RO_OK;
}

/* A file: URI over an arbitrary datadir path. A datadir may legitimately hold
 * `?` or `#` — which sqlite would read as the start of the query and the
 * fragment — or `%`, which it would read as an escape, so everything outside
 * the unreserved set is percent-encoded. False means it would not fit, which
 * the caller reports as a path-too-long rather than opening some other file. */
static bool zcl_ro_immutable_uri(const char *path, char *out, size_t out_size)
{
    static const char prefix[] = "file:";
    static const char suffix[] = "?immutable=1";
    const size_t plen = sizeof(prefix) - 1;
    const size_t slen = sizeof(suffix) - 1;

    if (out_size <= plen + slen)
        return false;
    memcpy(out, prefix, plen);
    size_t n = plen;
    for (const char *p = path; *p; p++) {
        unsigned char c = (unsigned char)*p;
        bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '-' || c == '.' ||
                          c == '_' || c == '~' || c == '/';
        size_t need = unreserved ? 1u : 3u;
        if (n + need + slen + 1 > out_size)
            return false;
        if (unreserved) {
            out[n++] = (char)c;
        } else {
            /* The tree's one hex encoder; lowercase, and percent-encoding is
             * case-insensitive, so sqlite reads %2f and %2F alike. */
            char esc[3];
            zcl_hex_encode(&c, 1, esc);
            out[n++] = '%';
            out[n++] = esc[0];
            out[n++] = esc[1];
        }
    }
    memcpy(out + n, suffix, slen + 1);
    return true;
}

/* Open one DSN and arm the connection. `dsn` is either the bare path or the
 * immutable file: URI; `path` is always the bare path, for the messages. */
static enum zcl_node_db_ro_status zcl_ro_attach(const char *dsn, int flags,
                                                const char *path,
                                                sqlite3 **db_out)
{
    sqlite3 *db = NULL;
    /* READONLY only: no CREATE (a typo'd datadir must fail, never mint a
     * database) and no READWRITE (this handle answers a read leaf). */
    int rc = sqlite3_open_v2(dsn, &db, flags, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("cmd", "database present but not readable: %s: %s", path,
                  db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
        if (db)
            sqlite3_close(db);
        return ZCL_NODE_DB_RO_UNREADABLE;
    }
    /* Second, connection-wide refusal of any write that the open flags
     * somehow let through (an ATTACHed db, a temp-table INSERT). */
    (void)sqlite3_exec(db, "PRAGMA query_only=ON", NULL, NULL, NULL);
    sqlite3_busy_timeout(db, ZCL_NODE_DB_RO_BUSY_MS);

    /* Third, TOUCH THE FILE. sqlite3_open_v2 is lazy: it does not read the
     * header, so a 47-byte text file, a truncated database, or any other
     * non-database opens with SQLITE_OK and only fails later, at the first
     * statement — by which point the caller has already been told OK and is
     * inside its own query path, where "it did not open" and "it opened and
     * held nothing" are the same shape. That is the exact confusion this
     * whole helper exists to remove, so pay one page read here.
     *
     * This matters beyond tidiness: zcl_native_node_db_require_readonly's
     * callers include two pre-flights that spend a fee (core.identity.anchor,
     * the zdir register path). They treat ABSENT as "proceed, this is a
     * legitimate first anchor" and anything else as fatal. A corrupt node.db
     * returning OK made the revocation lookup fail, read as "not revoked",
     * and spent the fee on a check that never ran. */
    if (sqlite3_exec(db, "PRAGMA schema_version", NULL, NULL, NULL)
        != SQLITE_OK) {
        LOG_ERROR("cmd", "present but not a readable database: %s: %s", path,
                  sqlite3_errmsg(db));
        sqlite3_close(db);
        return ZCL_NODE_DB_RO_UNREADABLE;
    }

    *db_out = db;
    return ZCL_NODE_DB_RO_OK;
}

/* The read-only open itself, over a path the caller has already resolved.
 *
 * Everything that makes this safe lives in ONE function so a second store
 * cannot drift from the first: there are two databases under a datadir that
 * read leaves are pointed at — node.db and the consensus.db kernel store —
 * and the whole reason both had a boot-ceremony hole is that each open was
 * written out longhand at its own call site. Adding a store means adding a
 * path resolver below, never a second copy of this.
 *
 * The choice of open, and why each branch creates nothing, is the block
 * comment at the top of this file. */
static enum zcl_node_db_ro_status zcl_ro_open_existing(const char *path,
                                                       sqlite3 **db_out)
{
    /* Absent vs unreadable are answered BEFORE the open, because
     * sqlite3_open_v2 collapses both into SQLITE_CANTOPEN and a caller that
     * may proceed on "absent" must never proceed on "unreadable". F_OK only
     * stats; it creates nothing. */
    if (access(path, F_OK) != 0)
        return ZCL_NODE_DB_RO_ABSENT;

    struct zcl_ro_sidecars side;
    zcl_ro_probe_sidecars(path, &side);
    /* Only a WAL database with no wal-index of its own needs the immutable
     * open, and only there is the immutable open honest. */
    bool immutable = zcl_ro_is_wal_database(path) && !(side.wal && side.shm);

    if (immutable && side.wal && side.wal_bytes > 0)
        LOG_RETURN(ZCL_NODE_DB_RO_UNRECOVERED_LOG, "cmd",
                   "%s has a %lld-byte write-ahead log and no wal-index "
                   "(%s-shm) beside it: the log's commits can only be read by "
                   "creating that wal-index, and a read leaf creates nothing. "
                   "Copy the -shm alongside the database, or let the owning "
                   "node recover the log once",
                   path, side.wal_bytes, path);

    sqlite3 *db = NULL;
    enum zcl_node_db_ro_status st;
    if (immutable) {
        char uri[ZCL_NODE_DB_RO_URI_MAX];
        if (!zcl_ro_immutable_uri(path, uri, sizeof(uri)))
            LOG_RETURN(ZCL_NODE_DB_RO_PATH_TOO_LONG, "cmd",
                       "database path does not fit a file: URI: %s", path);
        st = zcl_ro_attach(uri, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, path,
                           &db);
    } else {
        st = zcl_ro_attach(path, SQLITE_OPEN_READONLY, path, &db);
    }
    if (st != ZCL_NODE_DB_RO_OK)
        return st;

    /* Fourth, and only on the immutable path: make sure nothing attached to
     * the database WHILE it was being read. immutable=1 does not consult a
     * write-ahead log — that is exactly what lets it create no wal-index — so
     * a writer arriving between the probe above and here would leave this
     * handle reading the database's pre-log past. A wal-index existing now
     * says that happened. Retry ONCE through the plain open, which at that
     * point creates nothing because both sidecars are already there.
     *
     * The window is a node attaching to a datadir a read leaf was pointed at
     * in the same instant, so this almost never fires; it is here because a
     * silently stale answer is the failure this file cannot ship. */
    if (immutable) {
        struct zcl_ro_sidecars now;
        zcl_ro_probe_sidecars(path, &now);
        if (now.wal && now.shm) {
            sqlite3_close(db);
            db = NULL;
            st = zcl_ro_attach(path, SQLITE_OPEN_READONLY, path, &db);
            if (st != ZCL_NODE_DB_RO_OK)
                return st;
            immutable = false;  /* reading through a live wal-index now */
        } else if (now.wal && now.wal_bytes > 0) {
            sqlite3_close(db);
            LOG_RETURN(ZCL_NODE_DB_RO_UNRECOVERED_LOG, "cmd",
                       "%s grew a %lld-byte write-ahead log while it was being "
                       "read and has no wal-index beside it, so this read may "
                       "be missing its commits: refusing rather than answering "
                       "from the database's pre-log state",
                       path, now.wal_bytes);
        }

        /* Fifth: AND THE FOURTH CHECK IS STILL ONLY ONE INSTANT. The handle
         * goes back to a leaf that queries it afterwards, so the "no writer is
         * attached" premise has to hold for the handle's whole life, not just
         * for the open. Arm the guard that re-checks it at every statement —
         * see the block comment on struct zcl_ro_guard. */
        if (immutable) {
            st = zcl_ro_guard_arm(db, path, &now);
            if (st != ZCL_NODE_DB_RO_OK) {
                sqlite3_close(db);
                return st;
            }
        }
    }

    *db_out = db;
    return ZCL_NODE_DB_RO_OK;
}

enum zcl_node_db_ro_status zcl_native_node_db_open_readonly(
    const char *datadir, sqlite3 **db_out, struct node_db *ndb_out,
    char *path_out, size_t path_size)
{
    if (path_out && path_size)
        path_out[0] = '\0';
    if (db_out)
        *db_out = NULL;
    if (ndb_out)
        memset(ndb_out, 0, sizeof(*ndb_out));

    if (!db_out || !ndb_out)
        LOG_RETURN(ZCL_NODE_DB_RO_NO_DATADIR, "cmd",
                   "read-only node.db open called without out-parameters");
    if (!datadir || !datadir[0])
        return ZCL_NODE_DB_RO_NO_DATADIR;

    char path[1200];
    int n = snprintf(path, sizeof(path), "%s/node.db", datadir);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return ZCL_NODE_DB_RO_PATH_TOO_LONG;
    if (path_out && path_size) {
        if (path_size <= (size_t)n)
            return ZCL_NODE_DB_RO_PATH_TOO_LONG;
        memcpy(path_out, path, (size_t)n + 1);
    }

    sqlite3 *db = NULL;
    enum zcl_node_db_ro_status st = zcl_ro_open_existing(path, &db);
    if (st != ZCL_NODE_DB_RO_OK)
        return st;

    *db_out = db;
    ndb_out->db = db;
    ndb_out->open = true;
    snprintf(ndb_out->path, sizeof(ndb_out->path), "%s", path);
    return ZCL_NODE_DB_RO_OK;
}

/* The kernel store — <datadir>/consensus.db, or the legacy progress.kv name
 * when that is what the datadir still carries.
 *
 * The write-side open is progress_store_open(): READWRITE|CREATE, a rename
 * migration from progress.kv, a schema ensure, and — on a failed integrity
 * check — progress_store_quarantine_corrupt(), which rename()s the
 * append-only fact log that is the authority for every stage cursor aside to
 * consensus.db.corrupt-<ts> and installs a fresh empty one. That is the
 * right behaviour for a BOOTING node, which can re-derive the store from the
 * snapshot and the anchor. It is data destruction when a read leaf does it to
 * a copied datadir the operator asked a question about, so a read leaf gets
 * this instead. It also takes no part in the process singleton: an
 * offline-copy read must not become the process's one open kernel store. */
enum zcl_node_db_ro_status zcl_native_kernel_store_open_readonly(
    const char *datadir, sqlite3 **db_out, char *path_out, size_t path_size)
{
    if (path_out && path_size)
        path_out[0] = '\0';
    if (db_out)
        *db_out = NULL;

    if (!db_out)
        LOG_RETURN(ZCL_NODE_DB_RO_NO_DATADIR, "cmd",
                   "read-only kernel store open called without a handle");
    if (!datadir || !datadir[0])
        return ZCL_NODE_DB_RO_NO_DATADIR;

    char path[1200];
    if (!consensus_db_kernel_store_path(datadir, path, sizeof(path)))
        return ZCL_NODE_DB_RO_PATH_TOO_LONG;
    size_t n = strlen(path);
    /* Reported even when the file turns out to be absent, so the caller can
     * name exactly which path it looked at. */
    if (path_out && path_size) {
        if (path_size <= n)
            return ZCL_NODE_DB_RO_PATH_TOO_LONG;
        memcpy(path_out, path, n + 1);
    }

    return zcl_ro_open_existing(path, db_out);
}

bool zcl_native_node_db_require_readonly(
    const char *datadir, struct zcl_command_reply *reply, const char *what,
    sqlite3 **db_out, struct node_db *ndb_out)
{
    if (!reply)
        LOG_FAIL("cmd", "read-only node.db require called without a reply");
    const char *noun = (what && what[0]) ? what : "the node database";

    char path[1200];
    enum zcl_node_db_ro_status st = zcl_native_node_db_open_readonly(
        datadir, db_out, ndb_out, path, sizeof(path));
    if (st == ZCL_NODE_DB_RO_OK)
        return true;

    char message[512];
    switch (st) {
    case ZCL_NODE_DB_RO_NO_DATADIR:
        snprintf(message, sizeof(message),
                 "no datadir resolved for %s — pass --datadir", noun);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false, message, "");
        return false;
    case ZCL_NODE_DB_RO_PATH_TOO_LONG:
        snprintf(message, sizeof(message),
                 "datadir path too long for %s", noun);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "DATADIR_PATH_TOO_LONG", "normalize", false,
                               false, message, datadir ? datadir : "");
        return false;
    case ZCL_NODE_DB_RO_ABSENT:
        snprintf(message, sizeof(message),
                 "no node.db at that datadir, so %s cannot be read — check "
                 "--datadir, or boot the node once to create it", noun);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "NODE_DB_UNAVAILABLE", "execute", true, false,
                               message, path);
        return false;
    case ZCL_NODE_DB_RO_UNRECOVERED_LOG:
        /* Readable in principle, and deliberately not read: consulting the
         * write-ahead log means creating the wal-index next to it, and a read
         * leaf does not modify the directory it was pointed at. Says what to
         * do about it, because "would not open" would send the operator
         * hunting permissions on a database whose permissions are fine. */
        snprintf(message, sizeof(message),
                 "node.db has a write-ahead log with no node.db-shm beside "
                 "it, so %s was NOT read: reading the log would mean creating "
                 "that file in your datadir. Copy node.db-shm alongside "
                 "node.db, or let the owning node recover the log once",
                 noun);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "NODE_DB_UNRECOVERED_LOG", "execute", true,
                               false, message, path);
        return false;
    case ZCL_NODE_DB_RO_UNREADABLE:
    default:
        /* Distinct from ABSENT on purpose: the file IS there and we could
         * not read it, which is never the same answer as "empty". */
        snprintf(message, sizeof(message),
                 "node.db exists but would not open read-only, so %s could "
                 "not be read — check permissions and that the path is a "
                 "SQLite database", noun);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "NODE_DB_UNREADABLE", "execute", true, false,
                               message, path);
        return false;
    }
}

void zcl_native_node_db_close_readonly(sqlite3 **db, struct node_db *ndb)
{
    sqlite3 *handle = db ? *db : (ndb ? ndb->db : NULL);
    if (handle)
        sqlite3_close(handle);
    if (db)
        *db = NULL;
    /* The shim never owned prepared statements, so there is nothing for
     * node_db_close to finalize — just drop the borrowed pointer. */
    if (ndb)
        memset(ndb, 0, sizeof(*ndb));
}
