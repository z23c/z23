/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression tests for database.c migration machinery.
 *
 * These tests guard the class of silent-failure bugs that the v2→v18
 * migration block previously hid: if a CREATE TABLE or ALTER TABLE
 * failed inside `node_db_migrate`, the schema_version counter still
 * advanced (or, worse, failed to persist and quietly re-applied the
 * same migration on every boot).
 */

#include "test/test_core.h"
#include "models/database.h"
#include "models/database_internal.h"
#include "models/fleet_board_post.h"
#include "session/fleet_board_proto.h"
#include "crypto/ed25519.h"
#include "sha3/sha3.h"
#include "util/fleet_role_check.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static bool db_mig_hash_file(const char *path, uint8_t out[32],
                             off_t *size_out)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return false;
    }

    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    uint8_t buf[8192];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            sha3_256_write(&sha, buf, (size_t)n);
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            close(fd);
            return false;
        }
        break;
    }
    close(fd);
    sha3_256_finalize(&sha, out);
    if (size_out)
        *size_out = st.st_size;
    return true;
}

#define DB_MIG_FAMILY_MAX 16

struct db_mig_family_file {
    char name[256];
    off_t size;
    mode_t mode;
    struct timespec mtime;
    struct timespec ctime;
    uint8_t sha3[32];
};

struct db_mig_family_snapshot {
    size_t count;
    struct timespec dir_mtime;
    struct timespec dir_ctime;
    struct db_mig_family_file files[DB_MIG_FAMILY_MAX];
};

static int db_mig_family_file_cmp(const void *a, const void *b)
{
    const struct db_mig_family_file *fa = a;
    const struct db_mig_family_file *fb = b;
    return strcmp(fa->name, fb->name);
}

/* UCRT struct stat carries second-resolution st_mtime/st_ctime and no
 * st_mtim/st_ctim; the comparison below only needs change detection, and a
 * same-second rewrite keeping the same hash is not a mutation this test is
 * trying to catch. */
static struct timespec db_mig_stat_mtime(const struct stat *st)
{
#if defined(_WIN32)
    struct timespec ts = { (time_t)st->st_mtime, 0 };
    return ts;
#else
    return st->st_mtim;
#endif
}
static struct timespec db_mig_stat_ctime(const struct stat *st)
{
#if defined(_WIN32)
    struct timespec ts = { (time_t)st->st_ctime, 0 };
    return ts;
#else
    return st->st_ctim;
#endif
}

/* Snapshot every directory entry in the SQLite database family, not merely
 * node.db.  A refusal that creates/deletes/changes WAL, SHM, rollback-journal
 * or master-journal state has mutated the database even when node.db itself
 * still hashes the same.  atime is deliberately excluded: hashing the input
 * is itself a read, while mtime/ctime and directory timestamps are avoidable. */
static bool db_mig_snapshot_family(const char *dbpath,
                                   struct db_mig_family_snapshot *out)
{
    if (!dbpath || !out)
        return false;
    memset(out, 0, sizeof(*out));

    const char *slash = strrchr(dbpath, '/');
    if (!slash || slash == dbpath || slash[1] == '\0')
        return false;
    char dir[512];
    size_t dir_len = (size_t)(slash - dbpath);
    if (dir_len >= sizeof(dir))
        return false;
    memcpy(dir, dbpath, dir_len);
    dir[dir_len] = '\0';
    const char *base = slash + 1;
    size_t base_len = strlen(base);

    struct stat dst;
    if (stat(dir, &dst) != 0)
        return false;
    out->dir_mtime = db_mig_stat_mtime(&dst);
    out->dir_ctime = db_mig_stat_ctime(&dst);

    DIR *d = opendir(dir);
    if (!d)
        return false;
    bool ok = true;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, base, base_len) != 0)
            continue;
        char next = de->d_name[base_len];
        if (next != '\0' && next != '-' && next != '.')
            continue;
        if (out->count >= DB_MIG_FAMILY_MAX) {
            ok = false;
            break;
        }
        struct db_mig_family_file *f = &out->files[out->count];
        if (snprintf(f->name, sizeof(f->name), "%s", de->d_name) <= 0) {
            ok = false;
            break;
        }
        char path[800];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        struct stat st;
        if (n <= 0 || (size_t)n >= sizeof(path) || stat(path, &st) != 0 ||
            !S_ISREG(st.st_mode) ||
            !db_mig_hash_file(path, f->sha3, &f->size)) {
            ok = false;
            break;
        }
        f->mode = st.st_mode;
        f->mtime = db_mig_stat_mtime(&st);
        f->ctime = db_mig_stat_ctime(&st);
        out->count++;
    }
    closedir(d);
    if (!ok)
        return false;
    qsort(out->files, out->count, sizeof(out->files[0]),
          db_mig_family_file_cmp);
    return true;
}

static bool db_mig_family_same(const struct db_mig_family_snapshot *a,
                               const struct db_mig_family_snapshot *b)
{
    if (!a || !b || a->count != b->count ||
        a->dir_mtime.tv_sec != b->dir_mtime.tv_sec ||
        a->dir_mtime.tv_nsec != b->dir_mtime.tv_nsec ||
        a->dir_ctime.tv_sec != b->dir_ctime.tv_sec ||
        a->dir_ctime.tv_nsec != b->dir_ctime.tv_nsec) {
        fprintf(stderr,
                "db_mig family metadata changed count=%zu/%zu "
                "dir_mtime=%lld.%09ld/%lld.%09ld "
                "dir_ctime=%lld.%09ld/%lld.%09ld\n",
                a ? a->count : 0, b ? b->count : 0,
                a ? (long long)a->dir_mtime.tv_sec : 0,
                a ? a->dir_mtime.tv_nsec : 0,
                b ? (long long)b->dir_mtime.tv_sec : 0,
                b ? b->dir_mtime.tv_nsec : 0,
                a ? (long long)a->dir_ctime.tv_sec : 0,
                a ? a->dir_ctime.tv_nsec : 0,
                b ? (long long)b->dir_ctime.tv_sec : 0,
                b ? b->dir_ctime.tv_nsec : 0);
        return false;
    }
    for (size_t i = 0; i < a->count; i++) {
        const struct db_mig_family_file *fa = &a->files[i];
        const struct db_mig_family_file *fb = &b->files[i];
        if (strcmp(fa->name, fb->name) != 0 || fa->size != fb->size ||
            fa->mode != fb->mode ||
            fa->mtime.tv_sec != fb->mtime.tv_sec ||
            fa->mtime.tv_nsec != fb->mtime.tv_nsec ||
            fa->ctime.tv_sec != fb->ctime.tv_sec ||
            fa->ctime.tv_nsec != fb->ctime.tv_nsec ||
            memcmp(fa->sha3, fb->sha3, sizeof(fa->sha3)) != 0) {
            fprintf(stderr, "db_mig family file changed: %s/%s\n",
                    fa->name, fb->name);
            return false;
        }
    }
    return true;
}

static bool db_mig_refuse_close_twice(const char *dbpath)
{
    struct node_db rejected;
    bool opened = node_db_open(&rejected, dbpath);
    bool ok = !opened && !rejected.open && rejected.db == NULL;
    node_db_close(&rejected);
    node_db_close(&rejected);
    return ok && !rejected.open && rejected.db == NULL;
}

static bool db_mig_refusal_preserves_family(const char *dbpath, int rounds)
{
    struct db_mig_family_snapshot before, after;
    if (!db_mig_snapshot_family(dbpath, &before))
        return false;
    for (int i = 0; i < rounds; i++) {
        if (!db_mig_refuse_close_twice(dbpath))
            return false;
    }
    return db_mig_snapshot_family(dbpath, &after) &&
           db_mig_family_same(&before, &after);
}

/* cwd-relative tmpdir to comply with the "no /tmp" project convention. */
static void db_mig_path(char *buf, size_t n, const char *tag)
{
    snprintf(buf, n, "./test-tmp/db_mig_%d_%s", (int)getpid(), tag);
}

static bool db_mig_stamp_schema(sqlite3 *db, int32_t version)
{
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE node_state SET value=? WHERE key='schema_version'",
        -1, &st, NULL);
    if (rc != SQLITE_OK)
        return false;
    rc = sqlite3_bind_blob(st, 1, &version, sizeof(version),
                           SQLITE_TRANSIENT);
    bool ok = rc == SQLITE_OK && sqlite3_step(st) == SQLITE_DONE &&
              sqlite3_changes(db) == 1;
    sqlite3_finalize(st);
    return ok;
}

static bool db_mig_stamp_floor(sqlite3 *db, int32_t floor)
{
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE node_state SET value=? WHERE key='schema_compat_floor'",
        -1, &st, NULL);
    if (rc != SQLITE_OK)
        return false;
    rc = sqlite3_bind_blob(st, 1, &floor, sizeof(floor), SQLITE_TRANSIENT);
    bool ok = rc == SQLITE_OK && sqlite3_step(st) == SQLITE_DONE &&
              sqlite3_changes(db) == 1;
    sqlite3_finalize(st);
    return ok;
}

/* A minimal struct node_db populated by hand (mirrors the memset(ndb, 0,
 * sizeof(*ndb)) every real node_db_open_impl() path performs) so tests can
 * drive node_db_migrate() directly against hand-stamped node_state rows,
 * without going through the open-time preflight — which would itself refuse
 * or reclassify some of the exact states these tests need to stamp. */
static bool db_mig_open_raw_handle(struct node_db *ndb, const char *dbpath)
{
    memset(ndb, 0, sizeof(*ndb));
    if (sqlite3_open(dbpath, &ndb->db) != SQLITE_OK)
        return false;
    snprintf(ndb->path, sizeof(ndb->path), "%s", dbpath);
    ndb->open = true;
    return true;
}

static void db_mig_close_raw_handle(struct node_db *ndb)
{
    if (ndb->db)
        sqlite3_close(ndb->db);
    ndb->db = NULL;
    ndb->open = false;
}

static int db_mig_count(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &st, NULL);
    if (rc != SQLITE_OK)
        return -1;
    rc = sqlite3_step(st);
    int out = rc == SQLITE_ROW ? sqlite3_column_int(st, 0) : -1;
    sqlite3_finalize(st);
    return out;
}

static bool db_mig_exec_raw(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK)
        fprintf(stderr, "db_mig raw exec failed: %s sql=%s\n",
                err ? err : "(no errmsg)", sql ? sql : "(null)");
    sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool db_mig_column_exists(sqlite3 *db, const char *table,
                                 const char *column)
{
    char sql[160];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    bool found = false;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);
        if (name && strcmp((const char *)name, column) == 0) {
            found = true;
            break;
        }
    }
    sqlite3_finalize(st);
    return found;
}

static bool db_mig_is_wal_file(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    unsigned char hdr[20] = { 0 };
    ssize_t got = read(fd, hdr, sizeof(hdr));
    close(fd);
    return got == (ssize_t)sizeof(hdr) &&
           memcmp(hdr, "SQLite format 3", 16) == 0 && hdr[18] == 2;
}

static bool db_mig_raw_schema(sqlite3 *db, int32_t *version_out)
{
    sqlite3_stmt *st = NULL;
    if (!db || !version_out || sqlite3_prepare_v2(db,
            "SELECT value FROM node_state WHERE key='schema_version'",
            -1, &st, NULL) != SQLITE_OK || !st)
        return false;
    int rc = sqlite3_step(st);
    bool ok = rc == SQLITE_ROW &&
              sqlite3_column_bytes(st, 0) == (int)sizeof(*version_out);
    if (ok)
        memcpy(version_out, sqlite3_column_blob(st, 0),
               sizeof(*version_out));
    sqlite3_finalize(st);
    return ok;
}

static bool db_mig_replace_schema_blob(sqlite3 *db, const char *hex_blob)
{
    char sql[256];
    int n = snprintf(sql, sizeof(sql),
                     "UPDATE node_state SET value=X'%s' "
                     "WHERE key='schema_version'", hex_blob);
    return n > 0 && (size_t)n < sizeof(sql) && db_mig_exec_raw(db, sql) &&
           sqlite3_changes(db) == 1;
}

static bool db_mig_write_junk(const char *path)
{
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0)
        return false;
    static const unsigned char junk[] =
        "not a SQLite database carrying a readable schema marker";
    size_t off = 0;
    while (off < sizeof(junk)) {
        ssize_t n = write(fd, junk + off, sizeof(junk) - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        close(fd);
        return false;
    }
    return close(fd) == 0;
}

static bool db_mig_seed_v20_wallet_notes_db(const char *dbpath)
{
    sqlite3 *raw = NULL;
    if (sqlite3_open(dbpath, &raw) != SQLITE_OK)
        return false;

    bool ok = true;
    ok = ok && db_mig_exec_raw(raw,
        "CREATE TABLE node_state (key TEXT PRIMARY KEY,value BLOB)");
    ok = ok && db_mig_exec_raw(raw,
        "INSERT INTO node_state(key,value) "
        "VALUES('schema_version',X'14000000')");
    ok = ok && db_mig_exec_raw(raw,
        "CREATE TABLE wallet_sapling_notes ("
        "txid BLOB NOT NULL,output_index INTEGER NOT NULL,"
        "value INTEGER NOT NULL,rcm BLOB NOT NULL,memo BLOB,"
        "ivk BLOB NOT NULL,diversifier BLOB NOT NULL,"
        "pk_d BLOB NOT NULL,cm BLOB NOT NULL,"
        "nullifier BLOB NOT NULL UNIQUE,"
        "block_height INTEGER,spent_txid BLOB,address TEXT,"
        "witness_data BLOB,witness_height INTEGER DEFAULT 0,"
        "PRIMARY KEY (txid,output_index))");
    ok = ok && db_mig_exec_raw(raw,
        "CREATE TABLE znam_names ("
        "name TEXT PRIMARY KEY,"
        "owner_address TEXT NOT NULL,"
        "target_type INTEGER NOT NULL,"
        "target_value TEXT NOT NULL,"
        "reg_txid BLOB NOT NULL,"
        "reg_height INTEGER NOT NULL,"
        "last_update_txid BLOB NOT NULL)");
    ok = ok && db_mig_exec_raw(raw,
        "INSERT INTO wallet_sapling_notes"
        "(txid,output_index,value,rcm,ivk,diversifier,pk_d,cm,"
        "nullifier,block_height,address,witness_height) "
        "VALUES(X'01',0,42,X'02',X'03',X'04',X'05',X'06',"
        "X'07',100,'zs-v20-note',100)");
    sqlite3_close(raw);
    return ok;
}

/* v81-shaped `fleet_board_posts`: the exact v80 CREATE TABLE plus the v81 ADD
 * COLUMNs, byte for byte, so seeding this and stamping schema_version=81
 * reproduces what a real fleet node's board table looked like the moment
 * before the v82 kind-ceiling rebuild ever ran. */
static bool db_mig_seed_v81_board_schema(sqlite3 *raw)
{
    bool ok = true;
    ok = ok && db_mig_exec_raw(raw,
        "CREATE TABLE node_state (key TEXT PRIMARY KEY,value BLOB)");
    ok = ok && db_mig_exec_raw(raw,
        "INSERT INTO node_state(key,value) "
        "VALUES('schema_version',X'51000000')"); /* 81, little-endian */
    ok = ok && db_mig_exec_raw(raw,
        "CREATE TABLE fleet_board_posts("
        "id BLOB PRIMARY KEY CHECK(length(id)=32),"
        "seq INTEGER NOT NULL,"
        "kind INTEGER NOT NULL CHECK(kind BETWEEN 1 AND 7),"
        "created_at INTEGER NOT NULL CHECK(created_at>0),"
        "ttl INTEGER NOT NULL CHECK(ttl BETWEEN 1 AND 2592000),"
        "expires_at INTEGER NOT NULL CHECK(expires_at>created_at),"
        "ref BLOB NOT NULL CHECK(length(ref)=32),"
        "host_pubkey BLOB NOT NULL CHECK(length(host_pubkey)=32),"
        "agent TEXT NOT NULL CHECK(length(agent)<=64),"
        "slug TEXT NOT NULL CHECK(length(slug)<=64),"
        "title TEXT NOT NULL CHECK(length(title)<=128),"
        "supersedes BLOB NOT NULL CHECK(length(supersedes)=32),"
        "receipt TEXT NOT NULL CHECK(length(receipt)<=256),"
        "text TEXT NOT NULL CHECK(length(text) BETWEEN 1 AND 16384),"
        "body_bytes INTEGER NOT NULL CHECK(body_bytes BETWEEN 1 AND 17408),"
        "signature BLOB NOT NULL CHECK(length(signature)=64),"
        "chain_prev BLOB NOT NULL CHECK(length(chain_prev)=32),"
        "chain_hash BLOB NOT NULL CHECK(length(chain_hash)=32),"
        "received_at INTEGER NOT NULL CHECK(received_at>=0),"
        "scope INTEGER NOT NULL DEFAULT 0 CHECK(scope BETWEEN 0 AND 2),"
        "room TEXT NOT NULL DEFAULT '' CHECK(length(room)<=32))");
    ok = ok && db_mig_exec_raw(raw,
        "CREATE UNIQUE INDEX idx_fleet_board_seq ON fleet_board_posts(seq)");
    return ok;
}

/* One deterministic row per kind, so the same formula both writes the seed
 * row and checks the row read back after migration without duplicating the
 * expected bytes in two places. */
static void db_mig_board_row_fill(int kind, uint8_t id[32], uint8_t ref[32],
                                  uint8_t host_pubkey[32],
                                  uint8_t supersedes[32], uint8_t sig[64],
                                  uint8_t chain_prev[32],
                                  uint8_t chain_hash[32], char *agent,
                                  size_t agent_cap, char *text,
                                  size_t text_cap)
{
    memset(id, (uint8_t)(0x10 + kind), 32);
    memset(ref, (uint8_t)(0x20 + kind), 32);
    memset(host_pubkey, (uint8_t)(0x30 + kind), 32);
    memset(supersedes, 0, 32);
    memset(sig, (uint8_t)(0x40 + kind), 64);
    memset(chain_prev, (uint8_t)(0x50 + kind), 32);
    memset(chain_hash, (uint8_t)(0x60 + kind), 32);
    snprintf(agent, agent_cap, "seed-agent-%d", kind);
    snprintf(text, text_cap, "seed row for kind %d, byte-identical after v82",
             kind);
}

static bool db_mig_seed_v81_board_row(sqlite3 *raw, int kind)
{
    uint8_t id[32], ref[32], host_pubkey[32], supersedes[32], sig[64];
    uint8_t chain_prev[32], chain_hash[32];
    char agent[32], text[96];
    db_mig_board_row_fill(kind, id, ref, host_pubkey, supersedes, sig,
                          chain_prev, chain_hash, agent, sizeof(agent), text,
                          sizeof(text));
    int64_t now = 500000 + kind;
    size_t text_len = strlen(text);

    sqlite3_stmt *st = NULL;
    const char *sql =
        "INSERT INTO fleet_board_posts(id,seq,kind,created_at,ttl,"
        "expires_at,ref,host_pubkey,agent,slug,title,supersedes,receipt,"
        "text,body_bytes,signature,chain_prev,chain_hash,received_at,"
        "scope,room) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    if (sqlite3_prepare_v2(raw, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, id, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, kind);
    sqlite3_bind_int(st, 3, kind);
    sqlite3_bind_int64(st, 4, now);
    sqlite3_bind_int(st, 5, 3600);
    sqlite3_bind_int64(st, 6, now + 3600);
    sqlite3_bind_blob(st, 7, ref, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 8, host_pubkey, 32, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, agent, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 12, supersedes, 32, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 13, "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 14, text, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 15, (int64_t)text_len);
    sqlite3_bind_blob(st, 16, sig, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 17, chain_prev, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 18, chain_hash, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 19, now);
    sqlite3_bind_int(st, 20, 0);
    sqlite3_bind_text(st, 21, "", -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* Builds a v81-shaped board with one signed-shape row of every kind 1..7,
 * exactly the non-empty table the v82 `INSERT ... SELECT *` row copy has
 * never been proven against. */
static bool db_mig_seed_v81_board_db(const char *dbpath)
{
    sqlite3 *raw = NULL;
    if (sqlite3_open(dbpath, &raw) != SQLITE_OK)
        return false;
    bool ok = db_mig_seed_v81_board_schema(raw);
    for (int kind = 1; ok && kind <= 7; kind++)
        ok = db_mig_seed_v81_board_row(raw, kind);
    sqlite3_close(raw);
    return ok;
}

/* One expected blob column: which SELECT column, and the bytes it must
 * hold. Table-driving the blob comparisons keeps the caller's decision
 * count low no matter how many columns a row copy needs proven. */
struct db_mig_blob_want {
    int col;
    const uint8_t *want;
    int len;
};

static bool db_mig_row_blobs_match(sqlite3_stmt *st,
                                   const struct db_mig_blob_want *checks,
                                   size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (sqlite3_column_bytes(st, checks[i].col) != checks[i].len)
            return false;
        if (memcmp(sqlite3_column_blob(st, checks[i].col), checks[i].want,
                   (size_t)checks[i].len) != 0)
            return false;
    }
    return true;
}

/* Reads the row for `kind` back and compares every migrated byte against the
 * same formula the seed used, proving the v82 rebuild's row copy is lossless
 * rather than merely row-count-preserving. */
static bool db_mig_board_row_matches(sqlite3 *raw, int kind)
{
    uint8_t want_id[32], want_ref[32], want_host[32], want_super[32];
    uint8_t want_sig[64], want_prev[32], want_hash[32];
    char want_agent[32], want_text[96];
    db_mig_board_row_fill(kind, want_id, want_ref, want_host, want_super,
                          want_sig, want_prev, want_hash, want_agent,
                          sizeof(want_agent), want_text, sizeof(want_text));

    sqlite3_stmt *st = NULL;
    const char *sql =
        "SELECT id,ref,host_pubkey,supersedes,signature,chain_prev,"
        "chain_hash,agent,text,kind FROM fleet_board_posts WHERE kind=?";
    if (sqlite3_prepare_v2(raw, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, kind);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return false;
    }
    const struct db_mig_blob_want checks[] = {
        {0, want_id, 32},   {1, want_ref, 32},  {2, want_host, 32},
        {3, want_super, 32}, {4, want_sig, 64},  {5, want_prev, 32},
        {6, want_hash, 32},
    };
    bool ok = db_mig_row_blobs_match(st, checks,
                                     sizeof(checks) / sizeof(checks[0])) &&
        strcmp((const char *)sqlite3_column_text(st, 7), want_agent) == 0 &&
        strcmp((const char *)sqlite3_column_text(st, 8), want_text) == 0 &&
        sqlite3_column_int(st, 9) == kind;
    sqlite3_finalize(st);
    return ok;
}

static int t_fresh_reaches_latest(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "fresh");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    TEST("db_mig: fresh open reaches latest built-in schema version") {
        ASSERT(node_db_open(&ndb, dbpath));
        int v = node_db_schema_version(&ndb);
        ASSERT(v >= 18);
        node_db_close(&ndb);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_v20_wallet_notes_upgrade_adds_source(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "v20_wallet_notes");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: v20 wallet notes upgrade adds source after schema create") {
        ASSERT(db_mig_seed_v20_wallet_notes_db(dbpath));

        struct node_db ndb;
        ASSERT(node_db_open(&ndb, dbpath));
        ASSERT_EQ(node_db_schema_version(&ndb), NODE_DB_SCHEMA_LATEST);
        node_db_close(&ndb);

        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_column_exists(raw, "wallet_sapling_notes", "source"));
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='index' AND name='idx_snote_view_address'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='021'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='022'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='023'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='index' AND name='idx_txo_hodl_scan'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='index' AND name='idx_txi_prev_height'") == 1);
        ASSERT(db_mig_column_exists(raw, "hodl_history", "calc_version"));
        ASSERT(db_mig_column_exists(raw, "hodl_history", "source_tip_height"));
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM wallet_sapling_notes "
            "WHERE address='zs-v20-note' AND source='local'") == 1);
        sqlite3_close(raw);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_reopen_is_idempotent(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "reopen");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: reopen does not re-apply migrations") {
        struct node_db ndb1;
        ASSERT(node_db_open(&ndb1, dbpath));
        int v1 = node_db_schema_version(&ndb1);
        ASSERT(v1 >= 18);
        node_db_close(&ndb1);

        struct node_db ndb2;
        ASSERT(node_db_open(&ndb2, dbpath));
        int v2 = node_db_schema_version(&ndb2);
        ASSERT_EQ(v1, v2);
        node_db_close(&ndb2);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_market_content_registry_schema(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "market_content");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: v57-v61 app and intent resources install once") {
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, dbpath));
        ASSERT_EQ(node_db_schema_version(&ndb), NODE_DB_SCHEMA_LATEST);
        node_db_close(&ndb);

        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='057'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='058'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='059'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='060'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='061'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='table' AND name='market_contents'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND "
            "name IN ('idx_market_contents_root',"
            "'idx_market_contents_registered')") == 2);
        ASSERT(db_mig_column_exists(raw, "vault_intents",
                                    "application_kind"));
        ASSERT(db_mig_column_exists(raw, "vault_intents",
                                    "idempotency_key"));
        ASSERT(db_mig_column_exists(raw, "vault_intents",
                                    "request_digest"));
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND "
            "name='idx_vault_intents_application_idempotency'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
            "name IN ('market_downloads','market_download_chunks')") == 2);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND "
            "name IN ('idx_market_downloads_state',"
            "'idx_market_download_chunks_plan')") == 2);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
            "name='vault_intent_inputs'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND "
            "name='idx_vault_intent_inputs_plan'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
            "name='vault_intents' AND instr(sql,'''test''')>0") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM pragma_foreign_key_check") == 0);
        sqlite3_close(raw);

        struct node_db reopened;
        ASSERT(node_db_open(&reopened, dbpath));
        ASSERT_EQ(node_db_schema_version(&reopened), NODE_DB_SCHEMA_LATEST);
        node_db_close(&reopened);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_memory_open(void)
{
    int failures = 0;
    TEST("db_mig: :memory: open succeeds with schema migrations") {
        struct node_db mem;
        ASSERT(node_db_open(&mem, ":memory:"));
        int v = node_db_schema_version(&mem);
        ASSERT(v >= 18);
        node_db_close(&mem);
        PASS();
    } _test_next:;
    return failures;
}

static int t_turbo_mode_roundtrip(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "turbo");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: turbo->normal mode roundtrip leaves state consistent") {
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, dbpath));
        ASSERT(node_db_ibd_turbo_mode(&ndb));

        struct node_db_status st;
        node_db_get_status(&ndb, &st);
        ASSERT(st.turbo_mode);

        ASSERT(node_db_normal_mode(&ndb));
        node_db_get_status(&ndb, &st);
        ASSERT(!st.turbo_mode);

        node_db_close(&ndb);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_newer_schema_delete_refusal_is_zero_mutation(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "newer");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: DELETE-mode newer schema refusal preserves whole family") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        ASSERT(node_db_exec(&seed,
            "INSERT INTO snapshot_staging_utxos"
            "(txid,vout,value,script,script_type,height,is_coinbase)"
            " VALUES(X'4200000000000000000000000000000000000000000000000000000000000000',0,1,X'51',0,1,0)"));
        ASSERT(node_db_state_set(&seed, "snapshot_staging_phase",
                                 "chunk_receive", strlen("chunk_receive")));
        node_db_close(&seed);

        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(raw, "PRAGMA journal_mode=DELETE"));
        ASSERT(db_mig_stamp_schema(raw, NODE_DB_MAX_SCHEMA + 1));
        /* The seed above already migrated to latest, which persists a real
         * schema_compat_floor (79) below NODE_DB_MAX_SCHEMA. Left alone that
         * floor would make this look like a read-compatible rolling upgrade
         * instead of the genuinely incompatible future schema this test
         * means to simulate, so pin the floor above LATEST too. */
        ASSERT(db_mig_stamp_floor(raw, NODE_DB_MAX_SCHEMA + 1));
        /* A future schema need not contain every table this older binary
         * knows.  Refusal must happen before create_schema() can add one. */
        ASSERT(db_mig_exec_raw(raw, "DROP TABLE peers"));
        sqlite3_close(raw);
        raw = NULL;

        /* Eight complete failure lifecycles, each followed by two unconditional
         * closes.  The full node.db family and directory metadata must remain
         * byte-for-byte and entry-for-entry identical. */
        ASSERT(db_mig_refusal_preserves_family(dbpath, 8));

        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='table' AND name='peers'") == 0);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM snapshot_staging_utxos") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM node_state "
            "WHERE key='snapshot_staging_phase'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM node_state "
            "WHERE key='schema_version'") == 1);
        sqlite3_close(raw);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_newer_schema_wal_refusal_is_zero_mutation(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "newer_wal");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: clean-WAL newer schema refusal preserves whole family") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);

        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(raw, "PRAGMA journal_mode=WAL"));
        ASSERT(db_mig_stamp_schema(raw, NODE_DB_MAX_SCHEMA + 1));
        /* Pin the floor above LATEST too: the seed's own real
         * schema_compat_floor (79) would otherwise make this look like a
         * read-compatible rolling upgrade rather than a genuinely
         * incompatible future schema. */
        ASSERT(db_mig_stamp_floor(raw, NODE_DB_MAX_SCHEMA + 1));
        sqlite3_close(raw);
        raw = NULL;

        ASSERT(db_mig_is_wal_file(dbpath));
        ASSERT(db_mig_refusal_preserves_family(dbpath, 1));
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_newer_schema_only_in_uncheckpointed_wal(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "newer_live_wal");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    sqlite3 *writer = NULL;
    TEST("db_mig: newer marker only in uncheckpointed WAL is refused unchanged") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);

        ASSERT(sqlite3_open(dbpath, &writer) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(writer,
            "PRAGMA journal_mode=WAL;PRAGMA wal_autocheckpoint=0;"
            "BEGIN IMMEDIATE"));
        ASSERT(db_mig_stamp_schema(writer, NODE_DB_MAX_SCHEMA + 1));
        /* Same transaction, same reasoning as the other two refusal tests:
         * pin the floor above LATEST too, so the seed's own real
         * schema_compat_floor (checkpointed into the base file already)
         * cannot make this look like a read-compatible rolling upgrade. */
        ASSERT(db_mig_stamp_floor(writer, NODE_DB_MAX_SCHEMA + 1));
        ASSERT(db_mig_exec_raw(writer, "COMMIT"));

        char wal[560], shm[560];
        snprintf(wal, sizeof(wal), "%s-wal", dbpath);
        snprintf(shm, sizeof(shm), "%s-shm", dbpath);
        struct stat wal_st;
        ASSERT(stat(wal, &wal_st) == 0 && wal_st.st_size > 0);
        ASSERT(access(shm, F_OK) == 0);

        /* Anti-vacuous: the ordinary live view sees the future marker, while
         * immutable=1 (main file only) still sees the supported old marker. */
        int32_t live_ver = 0, main_ver = 0;
        ASSERT(db_mig_raw_schema(writer, &live_ver));
        ASSERT_EQ(live_ver, NODE_DB_MAX_SCHEMA + 1);
        char uri[640];
        snprintf(uri, sizeof(uri), "file:%s?mode=ro&immutable=1", dbpath);
        sqlite3 *main_only = NULL;
        ASSERT(sqlite3_open_v2(uri, &main_only,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK);
        ASSERT(db_mig_raw_schema(main_only, &main_ver));
        ASSERT(main_ver <= NODE_DB_MAX_SCHEMA);
        sqlite3_close(main_only);

        ASSERT(db_mig_refusal_preserves_family(dbpath, 1));
        sqlite3_close(writer);
        writer = NULL;
        PASS();
    } _test_next:;
    if (writer)
        sqlite3_close(writer);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_wrong_width_schema_marker_refuses_unchanged(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];
    sqlite3 *raw = NULL;

    db_mig_path(dir, sizeof(dir), "schema_wrong_width");
    mkdir_p(dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    TEST("db_mig: malformed wrong-width schema marker refuses unchanged") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_replace_schema_blob(raw, "43"));
        sqlite3_close(raw); raw = NULL;
        ASSERT(db_mig_refusal_preserves_family(dbpath, 1));
        PASS();
    } _test_next:;
    if (raw) sqlite3_close(raw);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_unsupported_schema_marker_refuses_unchanged(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];
    sqlite3 *raw = NULL;
    db_mig_path(dir, sizeof(dir), "schema_unsupported");
    mkdir_p(dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    TEST("db_mig: unsupported schema marker zero refuses unchanged") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_replace_schema_blob(raw, "00000000"));
        sqlite3_close(raw); raw = NULL;
        ASSERT(db_mig_refusal_preserves_family(dbpath, 1));
        PASS();
    } _test_next:;
    if (raw) sqlite3_close(raw);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_contradictory_schema_markers_refuse_unchanged(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];
    sqlite3 *raw = NULL;
    db_mig_path(dir, sizeof(dir), "schema_contradictory");
    mkdir_p(dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    TEST("db_mig: contradictory duplicate schema markers refuse unchanged") {
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(raw,
            "CREATE TABLE node_state(key TEXT,value BLOB);"
            "INSERT INTO node_state VALUES('schema_version',X'01000000');"
            "INSERT INTO node_state VALUES('schema_version',X'02000000')"));
        sqlite3_close(raw); raw = NULL;
        ASSERT(db_mig_refusal_preserves_family(dbpath, 1));
        PASS();
    } _test_next:;
    if (raw) sqlite3_close(raw);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_unreadable_schema_store_refuses_unchanged(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];
    sqlite3 *raw = NULL;
    db_mig_path(dir, sizeof(dir), "schema_unreadable");
    mkdir_p(dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    TEST("db_mig: unreadable schema store refuses without quarantine") {
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(raw,
            "CREATE TABLE node_state(key TEXT PRIMARY KEY,value BLOB);"
            "INSERT INTO node_state VALUES('schema_version',X'01000000')"));
        sqlite3_close(raw); raw = NULL;
        ASSERT(db_mig_write_junk(dbpath));
        ASSERT(db_mig_refusal_preserves_family(dbpath, 1));
        PASS();
    } _test_next:;
    if (raw) sqlite3_close(raw);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_missing_node_state_refuses_unchanged(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];
    sqlite3 *raw = NULL;

    db_mig_path(dir, sizeof(dir), "missing_node_state");
    mkdir_p(dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    TEST("db_mig: recognized tables without node_state refuse unchanged") {
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(raw,
            "CREATE TABLE blocks(hash BLOB PRIMARY KEY,height INTEGER)"));
        sqlite3_close(raw); raw = NULL;
        ASSERT(db_mig_refusal_preserves_family(dbpath, 1));
        PASS();
    } _test_next:;
    if (raw) sqlite3_close(raw);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_existing_empty_database_may_initialize(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];
    sqlite3 *raw = NULL;
    db_mig_path(dir, sizeof(dir), "existing_empty");
    mkdir_p(dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    TEST("db_mig: genuinely empty existing SQLite database may initialize") {
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        sqlite3_close(raw); raw = NULL;
        struct node_db fresh;
        ASSERT(node_db_open(&fresh, dbpath));
        ASSERT_EQ(node_db_schema_version(&fresh), NODE_DB_SCHEMA_LATEST);
        node_db_close(&fresh);
        PASS();
    } _test_next:;
    if (raw) sqlite3_close(raw);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_supported_current_schema_reopens_normally(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "supported_current");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: supported current schema passes preflight and remains writable") {
        struct node_db first;
        ASSERT(node_db_open(&first, dbpath));
        ASSERT_EQ(node_db_schema_version(&first), NODE_DB_SCHEMA_LATEST);
        node_db_close(&first);
        for (int i = 0; i < 32; i++) {
            struct node_db reopened;
            ASSERT(node_db_open_runtime(&reopened, dbpath,
                                        "schema_preflight.reopen_stress"));
            ASSERT(node_db_state_set(&reopened, "preflight_supported",
                                     "yes", 3));
            node_db_close(&reopened);
        }
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_v29_incompatible_schema_fails_without_stamp(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "v29_incompatible");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: v29 incompatible AppEvent schema fails without stamp") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);

        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(raw,
            "DELETE FROM schema_migrations WHERE version='029';"
            "DROP INDEX idx_app_events_topic_cursor;"
            "DROP INDEX idx_app_events_author_sequence;"
            "DROP INDEX idx_app_events_previous;"
            "DROP TABLE app_events;"
            "CREATE TABLE app_events(event_id BLOB)"));
        ASSERT(db_mig_stamp_schema(raw, 28));
        sqlite3_close(raw);
        raw = NULL;

        struct node_db rejected;
        ASSERT(!node_db_open(&rejected, dbpath));
        ASSERT(!rejected.open && rejected.db == NULL);

        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='029'") == 0);
        ASSERT(!db_mig_column_exists(raw, "app_events", "app_id"));
        sqlite3_close(raw);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_v82_board_kind_ceiling_row_copy_is_lossless(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "v82_board_copy");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: v82 board rebuild copies every v81 row byte-identical") {
        ASSERT(db_mig_seed_v81_board_db(dbpath));

        sqlite3 *before = NULL;
        ASSERT(sqlite3_open(dbpath, &before) == SQLITE_OK);
        int before_count =
            db_mig_count(before, "SELECT count(*) FROM fleet_board_posts");
        sqlite3_close(before);
        printf("db_mig: v82 row copy before count = %d\n", before_count);
        ASSERT_EQ(before_count, 7);

        struct node_db ndb;
        ASSERT(node_db_open(&ndb, dbpath));
        ASSERT_EQ(node_db_schema_version(&ndb), NODE_DB_SCHEMA_LATEST);
        node_db_close(&ndb);

        sqlite3 *after = NULL;
        ASSERT(sqlite3_open(dbpath, &after) == SQLITE_OK);
        int after_count =
            db_mig_count(after, "SELECT count(*) FROM fleet_board_posts");
        printf("db_mig: v82 row copy after count = %d\n", after_count);
        ASSERT_EQ(after_count, 7);
        for (int kind = 1; kind <= 7; kind++)
            ASSERT(db_mig_board_row_matches(after, kind));
        sqlite3_close(after);

        /* Post-migration, a fresh kind-8 (`agents`) row must still write and
         * read back through the real ingest path: the widened CHECK admits
         * it, and fleet_board_post_validate() remains the actual gate. */
        struct node_db ndb2;
        ASSERT(node_db_open(&ndb2, dbpath));
        /* Ingest refuses a key that carries no role, and this group invents
         * its own key. The role gate itself is proven in fleet_roles and
         * fleet_role_enforcement; the question here is only whether the
         * widened v82 CHECK admits kind 8, so hold the gate open across the
         * ingest and shut it again once the block is done. */
        zcl_fleet_role_checker_install_permissive_for_testing();
        uint8_t seed[32], sk[32], pk[32];
        memset(seed, 0, sizeof(seed));
        seed[0] = 0x77;
        ed25519_keypair(pk, sk, seed);

        struct fleet_board_post agents_post;
        memset(&agents_post, 0, sizeof(agents_post));
        agents_post.kind = FLEET_BOARD_KIND_AGENTS;
        agents_post.created_at = 600000;
        agents_post.ttl = 3600;
        snprintf(agents_post.agent, sizeof(agents_post.agent), "node-x");
        const char *text = "v1|host=node-x|now=600000\n";
        size_t text_len = strlen(text);
        memcpy(agents_post.text, text, text_len);
        agents_post.text[text_len] = '\0';
        agents_post.text_len = (uint32_t)text_len;
        agents_post.scope = FLEET_BOARD_SCOPE_FLEET;
        ASSERT_EQ(fleet_board_post_sign(&agents_post, sk, pk), FLEET_BOARD_OK);

        bool stored = false;
        ASSERT_EQ(db_fleet_board_post_ingest(&ndb2, &agents_post, 600000,
                                             &stored),
                  FLEET_BOARD_OK);
        ASSERT(stored);

        struct fleet_board_filter filter;
        memset(&filter, 0, sizeof(filter));
        filter.kind = FLEET_BOARD_KIND_AGENTS;
        filter.scope_set = true;
        filter.scope = FLEET_BOARD_SCOPE_FLEET;
        struct db_fleet_board_post rows[2];
        ASSERT_EQ(db_fleet_board_list(&ndb2, &filter, 600000, rows, 2), 1);
        ASSERT(strcmp(rows[0].post.text, text) == 0);
        node_db_close(&ndb2);
        PASS();
    } _test_next:;
    /* Leave the process as this group found it: every other case in this
     * file proves a refusal against an empty seam. */
    zcl_fleet_role_checker_install(NULL);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_additive_migration_keeps_floor(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "additive_floor");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: an additive-only step leaves schema_compat_floor unchanged") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);

        /* v80 is the last version and is ADDITIVE (see
         * database_migrate_features_v67_up.c). Roll the database back to
         * "just before v80, floor already at 79" and confirm crossing it
         * leaves schema_compat_floor exactly where it was. */
        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_stamp_schema(raw, 79));
        ASSERT(db_mig_stamp_floor(raw, 79));
        sqlite3_close(raw);
        raw = NULL;

        struct node_db ndb;
        ASSERT(db_mig_open_raw_handle(&ndb, dbpath));
        int rc = node_db_migrate(&ndb, NULL);
        ASSERT(rc >= 0);
        ASSERT_EQ(node_db_schema_version(&ndb), NODE_DB_SCHEMA_LATEST);
        ASSERT_EQ(node_db_schema_compat_floor(&ndb), 79);
        db_mig_close_raw_handle(&ndb);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── The deferred-quick_check corruption heal ───────────────────────────
 *
 * A fleet node sat in systemd `activating (start)` for 15.9 h on this exact
 * shape. Its node.db held a damaged page; the fast-restart path had DEFERRED
 * `PRAGMA quick_check` to the background, so the open's own malformed-store
 * repair (quarantine the family, rebuild fresh) never ran. The corruption
 * instead surfaced from the first baseline DDL statement that had to read the
 * damaged table:
 *
 *   [db] schema[10] failed: database disk image is malformed
 *        (sql=CREATE INDEX IF NOT EXISTS idx_tx_block ON transactions(...))
 *
 * and that verdict used to abort the open, taking the node to its
 * node_db_unopened boot gate with a store the same file knew how to repair.
 *
 * The fixture reproduces it exactly and cheaply: build a normal store, put
 * rows in `transactions`, drop idx_tx_block so the DDL must SCAN that table,
 * fill the table's own root page with garbage, and arm a skip probe that
 * defers quick_check the way the fast restart does. */

static bool db_mig_skip_quick_check_always(const char *path)
{
    (void)path;
    return true;
}

/* Read one integer out of `sql`'s first column. False on any SQLite error. */
static bool db_mig_query_int(sqlite3 *db, const char *sql, int64_t *out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_step(st) == SQLITE_ROW;
    if (ok)
        *out = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return ok;
}

/* Overwrite the 1-based page `page` of the SQLite file at `path` with 0xA5.
 * Page 1 (the header + schema root) is deliberately left intact so the
 * store still passes the schema preflight — the damage has to be found by
 * the DDL, not by the marker read. */
static bool db_mig_scribble_page(const char *path, int64_t page,
                                 int64_t page_size)
{
    if (page < 2 || page_size < 512)
        return false;
    unsigned char *junk = malloc((size_t)page_size);
    if (!junk)
        return false;
    memset(junk, 0xA5, (size_t)page_size);
    FILE *f = fopen(path, "r+b");
    bool ok = f != NULL &&
              fseek(f, (long)((page - 1) * page_size), SEEK_SET) == 0 &&
              fwrite(junk, 1, (size_t)page_size, f) == (size_t)page_size;
    if (f && fclose(f) != 0)
        ok = false;
    free(junk);
    return ok;
}

/* True iff `dir` holds at least one quarantined `node.db.corrupt-*`. */
static bool db_mig_has_quarantined_family(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return false;
    bool found = false;
    const struct dirent *e;
    while (!found && (e = readdir(d)) != NULL)
        found = strncmp(e->d_name, "node.db.corrupt-", 16) == 0;
    closedir(d);
    return found;
}

static int t_malformed_store_heals_when_quick_check_deferred(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];
    db_mig_path(dir, sizeof(dir), "malformed_deferred_qc");
    mkdir_p(dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: malformed store heals when quick_check is deferred") {
        int64_t page_size = 0;
        int64_t rootpage = 0;
        {
            struct node_db seed;
            ASSERT(node_db_open(&seed, dbpath));
            for (int i = 0; i < 256; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql),
                         "INSERT OR IGNORE INTO transactions"
                         "(txid,block_hash,block_height,tx_index,file_num,"
                         "file_pos,is_coinbase) VALUES"
                         "(randomblob(32),randomblob(32),%d,0,0,0,0)", i);
                ASSERT(node_db_exec(&seed, sql));
            }
            /* The DDL only scans the table when the index is missing — which
             * is precisely the state the fleet node's store was in. */
            ASSERT(node_db_exec(&seed, "DROP INDEX IF EXISTS idx_tx_block"));
            ASSERT(db_mig_query_int(seed.db, "PRAGMA page_size", &page_size));
            ASSERT(db_mig_query_int(seed.db,
                "SELECT rootpage FROM sqlite_master"
                " WHERE type='table' AND name='transactions'", &rootpage));
            node_db_close(&seed);
        }
        ASSERT(rootpage >= 2 && page_size >= 512);
        ASSERT(db_mig_scribble_page(dbpath, rootpage, page_size));
        ASSERT(!db_mig_has_quarantined_family(dir));

        node_db_set_quick_check_skip_probe(db_mig_skip_quick_check_always);
        struct node_db healed;
        bool opened = node_db_open(&healed, dbpath);
        node_db_set_quick_check_skip_probe(NULL);

        /* The whole point: the boot open SUCCEEDS on a rebuilt store instead
         * of failing out to the node_db_unopened gate. */
        ASSERT(opened);
        ASSERT(healed.open);
        ASSERT_EQ(node_db_schema_version(&healed), NODE_DB_SCHEMA_LATEST);
        /* Copy-first: the damaged family was renamed aside, never deleted. */
        ASSERT(db_mig_has_quarantined_family(dir));
        /* The rebuilt store is writable, and empty of the seeded rows. */
        int64_t rows = -1;
        ASSERT(db_mig_query_int(healed.db,
                                "SELECT COUNT(*) FROM transactions", &rows));
        ASSERT_EQ(rows, 0);
        node_db_close(&healed);
        PASS();
    } _test_next:;
    node_db_set_quick_check_skip_probe(NULL);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_breaking_migration_raises_floor(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "breaking_floor");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: crossing a BREAKING step raises schema_compat_floor") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);

        /* v79 (mesh_capability_grants v2 rebuild) is classified BREAKING.
         * Roll the database back to "just before v79, floor still at 78"
         * and confirm crossing it pulls the floor up to 79 — one short of
         * the resulting schema_version, because v80 above it is additive. */
        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_stamp_schema(raw, 78));
        ASSERT(db_mig_stamp_floor(raw, 78));
        sqlite3_close(raw);
        raw = NULL;

        struct node_db ndb;
        ASSERT(db_mig_open_raw_handle(&ndb, dbpath));
        int rc = node_db_migrate(&ndb, NULL);
        ASSERT(rc >= 0);
        ASSERT_EQ(node_db_schema_version(&ndb), NODE_DB_SCHEMA_LATEST);
        ASSERT_EQ(node_db_schema_compat_floor(&ndb), 79);
        db_mig_close_raw_handle(&ndb);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_older_binary_within_floor_opens_read_compatible(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "read_compat");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: schema above LATEST with floor at/below LATEST opens read-compatible") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);

        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_stamp_schema(raw, NODE_DB_MAX_SCHEMA + 1));
        ASSERT(db_mig_stamp_floor(raw, NODE_DB_MAX_SCHEMA));
        int ledger_before = db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations");
        sqlite3_close(raw);
        raw = NULL;

        /* This is the actual rollback scenario: an older binary (this
         * process, pinned at NODE_DB_MAX_SCHEMA) opens a database a newer
         * binary already migrated one step past it, but whose own
         * compat floor says nothing BREAKING happened above this binary's
         * ceiling. The open must succeed and must not touch the schema. */
        struct node_db reopened;
        ASSERT(node_db_open(&reopened, dbpath));
        ASSERT(reopened.open);
        ASSERT_EQ(node_db_schema_version(&reopened), NODE_DB_MAX_SCHEMA + 1);
        ASSERT_EQ(node_db_schema_compat_floor(&reopened), NODE_DB_MAX_SCHEMA);
        node_db_close(&reopened);

        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        int32_t stored_version = 0;
        ASSERT(db_mig_raw_schema(raw, &stored_version));
        ASSERT_EQ(stored_version, NODE_DB_MAX_SCHEMA + 1);
        int ledger_after = db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations");
        ASSERT_EQ(ledger_after, ledger_before);
        sqlite3_close(raw);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_malformed_store_repair_is_boot_only(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];
    db_mig_path(dir, sizeof(dir), "malformed_runtime_reopen");
    mkdir_p(dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: a runtime reopen never quarantines the canonical store") {
        int64_t page_size = 0;
        int64_t rootpage = 0;
        {
            struct node_db seed;
            ASSERT(node_db_open(&seed, dbpath));
            for (int i = 0; i < 256; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql),
                         "INSERT OR IGNORE INTO transactions"
                         "(txid,block_hash,block_height,tx_index,file_num,"
                         "file_pos,is_coinbase) VALUES"
                         "(randomblob(32),randomblob(32),%d,0,0,0,0)", i);
                ASSERT(node_db_exec(&seed, sql));
            }
            ASSERT(node_db_exec(&seed, "DROP INDEX IF EXISTS idx_tx_block"));
            ASSERT(db_mig_query_int(seed.db, "PRAGMA page_size", &page_size));
            ASSERT(db_mig_query_int(seed.db,
                "SELECT rootpage FROM sqlite_master"
                " WHERE type='table' AND name='transactions'", &rootpage));
            node_db_close(&seed);
        }
        ASSERT(db_mig_scribble_page(dbpath, rootpage, page_size));

        struct node_db reopened;
        bool opened = node_db_open_runtime(&reopened, dbpath,
                                           "db_mig.malformed_runtime");
        node_db_close(&reopened);
        ASSERT(!opened);
        ASSERT(!db_mig_has_quarantined_family(dir));
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_floor_above_latest_refuses_with_typed_error(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "floor_refused");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: a compat floor above LATEST refuses even with a distinct newer version") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);

        /* floor is stamped ABOVE schema_version itself (which is already
         * above LATEST) to prove the refusal reads schema_compat_floor
         * specifically, not merely re-deriving a verdict from version. */
        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(raw, "PRAGMA journal_mode=DELETE"));
        ASSERT(db_mig_stamp_schema(raw, NODE_DB_MAX_SCHEMA + 1));
        ASSERT(db_mig_stamp_floor(raw, NODE_DB_MAX_SCHEMA + 5));
        sqlite3_close(raw);
        raw = NULL;

        ASSERT(db_mig_refusal_preserves_family(dbpath, 4));

        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        int32_t stored_version = 0;
        ASSERT(db_mig_raw_schema(raw, &stored_version));
        ASSERT_EQ(stored_version, NODE_DB_MAX_SCHEMA + 1);
        sqlite3_close(raw);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_backup_flag_writes_file_before_breaking_step(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "backup_writes");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: -db-backup-before-migrate writes node.db.schema<N>.bak before a BREAKING step") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);

        /* v75 (Yardsale plan state-CHECK rebuild) always runs its rebuild
         * unconditionally once current_ver < 75 — unlike v79, it has no
         * "already in the target shape" short-circuit, so this is a clean
         * BREAKING step to prove the backup guard against. */
        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_stamp_schema(raw, 74));
        ASSERT(db_mig_stamp_floor(raw, 74));
        sqlite3_close(raw);
        raw = NULL;

        ASSERT(setenv("ZCL_DB_BACKUP_BEFORE_MIGRATE", "1", 1) == 0);
        node_db_backup_set_free_bytes_override_for_test(
            (int64_t)16 * 1024 * 1024 * 1024);

        struct node_db ndb;
        ASSERT(db_mig_open_raw_handle(&ndb, dbpath));
        int rc = node_db_migrate(&ndb, NULL);
        db_mig_close_raw_handle(&ndb);

        node_db_backup_set_free_bytes_override_for_test(-1);
        unsetenv("ZCL_DB_BACKUP_BEFORE_MIGRATE");

        ASSERT(rc >= 0);

        /* current_ver was 74 at the moment the v75 BREAKING step's guard
         * ran, so the backup is named for the version it protected. */
        char bak_path[600];
        snprintf(bak_path, sizeof(bak_path), "%s.schema74.bak", dbpath);
        struct stat st;
        ASSERT(stat(bak_path, &st) == 0);
        ASSERT(st.st_size > 0);
        unlink(bak_path);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_backup_flag_refuses_on_insufficient_space(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "backup_refuses");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: -db-backup-before-migrate refuses the BREAKING step when free space is short") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);

        /* Same v75 boundary as the write test: its rebuild runs
         * unconditionally, so the backup guard is guaranteed to fire. */
        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_stamp_schema(raw, 74));
        ASSERT(db_mig_stamp_floor(raw, 74));
        sqlite3_close(raw);
        raw = NULL;

        ASSERT(setenv("ZCL_DB_BACKUP_BEFORE_MIGRATE", "1", 1) == 0);
        node_db_backup_set_free_bytes_override_for_test(1024);

        struct node_db ndb;
        ASSERT(db_mig_open_raw_handle(&ndb, dbpath));
        int rc = node_db_migrate(&ndb, NULL);
        int32_t version_after = (int32_t)node_db_schema_version(&ndb);
        int32_t floor_after = (int32_t)node_db_schema_compat_floor(&ndb);
        db_mig_close_raw_handle(&ndb);

        node_db_backup_set_free_bytes_override_for_test(-1);
        unsetenv("ZCL_DB_BACKUP_BEFORE_MIGRATE");

        ASSERT_EQ(rc, NODE_DB_MIGRATE_ERR_BACKUP_FAILED);
        /* Zero mutation: the guard fires before any DDL or persist call. */
        ASSERT_EQ(version_after, 74);
        ASSERT_EQ(floor_after, 74);

        char bak_path[600];
        snprintf(bak_path, sizeof(bak_path), "%s.schema74.bak", dbpath);
        struct stat st;
        ASSERT(stat(bak_path, &st) != 0);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_db_migration_idempotent(void);

int test_db_migration_idempotent(void)
{
    printf("\n=== db_migration_idempotent tests ===\n");
    int failures = 0;
    mkdir_p("./test-tmp");
    failures += t_fresh_reaches_latest();
    failures += t_v20_wallet_notes_upgrade_adds_source();
    failures += t_reopen_is_idempotent();
    failures += t_market_content_registry_schema();
    failures += t_memory_open();
    failures += t_turbo_mode_roundtrip();
    failures += t_newer_schema_delete_refusal_is_zero_mutation();
    failures += t_newer_schema_wal_refusal_is_zero_mutation();
    failures += t_newer_schema_only_in_uncheckpointed_wal();
    failures += t_wrong_width_schema_marker_refuses_unchanged();
    failures += t_unsupported_schema_marker_refuses_unchanged();
    failures += t_contradictory_schema_markers_refuse_unchanged();
    failures += t_unreadable_schema_store_refuses_unchanged();
    failures += t_missing_node_state_refuses_unchanged();
    failures += t_existing_empty_database_may_initialize();
    failures += t_supported_current_schema_reopens_normally();
    failures += t_v29_incompatible_schema_fails_without_stamp();
    failures += t_v82_board_kind_ceiling_row_copy_is_lossless();
    failures += t_additive_migration_keeps_floor();
    failures += t_breaking_migration_raises_floor();
    failures += t_older_binary_within_floor_opens_read_compatible();
    failures += t_floor_above_latest_refuses_with_typed_error();
    failures += t_backup_flag_writes_file_before_breaking_step();
    failures += t_backup_flag_refuses_on_insufficient_space();
    failures += t_malformed_store_heals_when_quick_check_deferred();
    failures += t_malformed_store_repair_is_boot_only();
    return failures;
}
