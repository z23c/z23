/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The datadir-local probe/provision half of the shop orchestration
 * (docs/work/SHOP_COMMAND.md, slice B) — split out of
 * shop_native_handler.c, which keeps the two registry handlers and the
 * reply rendering.
 *
 * Everything here is a small file/DB helper over a datadir: the wallet
 * at-rest custody probe, the products.json copy, the directory
 * announcement write, the persistent-identity read, and the Tor
 * stub-vs-real link fact. None of it assumes the shop runs in the main
 * node process, so the same helpers serve a future isolated storefront
 * worker unchanged. */

#include "controllers/shop_native_handler.h"

#include "base/compiler.h"
#include "command/native_command.h"     /* zcl_native_node_db_open_readonly */
#include "models/activerecord.h"        /* AR_STEP_ROW */
#include "models/database.h"            /* struct node_db */
#include "net/onion_service.h"
#include "net/tor_integration.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "util/ar_step_readonly.h"      /* AR_STEP_ROW_READONLY */
#include "util/log_macros.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SHOP_TAG "native.app.shop"

/* The products.json provisioning loader's own read buffer is 16 KiB
 * (store_controller_schema.c); an input that does not fit would be
 * TRUNCATED by the loader, so init refuses one rather than provisioning a
 * store whose tail products silently never load. */
#define SHOP_PRODUCTS_JSON_MAX 16383

/* Row cap for the wallet posture scan. A wallet with more rows than this
 * is not a storefront wallet; the cap only bounds how long a read leaf
 * may take, never what it may conclude: absence-of-envelope is reported
 * as PLAINTEXT only when every row was scanned (see scan_complete). */
#define SHOP_WALLET_SCAN_MAX 10000

/* ── Tor build fact ─────────────────────────────────────────────────
 * The weak reference resolves NULL against libtor_stub.a and non-NULL
 * against the real libtor.a — the same link-time fact
 * network_telemetry_fill.c's nt_real_tor_linked() reads (its comment
 * records that re-declaring this weak reference is reading an existing
 * fact, not inventing one). Without it a stub build would report "no
 * onion" in exactly the shape a real build reports "the onion is down". */
extern int dynhost_client_fetch(const char *, uint16_t, const char *,
    void (*)(int, const uint8_t *, size_t, void *), void *, int)
    ZCL_WEAK_IMPORT;

bool shop_tor_real_build_linked(void)
{
    return dynhost_client_fetch != NULL;
}

/* ── small file plumbing ────────────────────────────────────────────── */
bool shop_internal_path_join(char *out, size_t out_size, const char *dir,
                             const char *rel)
{
    int n = snprintf(out, out_size, "%s/%s", dir, rel);
    return n > 0 && (size_t)n < out_size;
}

/* mkdir(dir) tolerating an existing directory. */
static bool shp_mkdir_one(const char *path)
{
    return platform_directory_ensure(path, 0700);
}

/* Write `bytes` to `path` via a sibling temp file + rename, so a crash
 * mid-write never leaves a truncated file at the real name. */
static bool shp_write_file_atomic(const char *path, const char *bytes,
                                  size_t len)
{
    char installed[1100], parent[1100];
    if (!platform_private_destination_resolve(
            path, installed, sizeof(installed), parent, sizeof(parent)))
        LOG_FAIL(SHOP_TAG, "cannot resolve atomic-write parent: %s", path);
    char tmp[1200];
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool created = false;
    for (unsigned attempt = 0; attempt < 16 && !created; attempt++) {
        uint8_t nonce[16];
        if (!rng_fill(nonce, sizeof(nonce)))
            LOG_FAIL(SHOP_TAG, "cannot generate staging name for %s", path);
        char suffix[2 * sizeof(nonce) + 1];
        for (size_t i = 0; i < sizeof(nonce); i++)
            (void)snprintf(suffix + 2 * i, 3, "%02x", nonce[i]);
        int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%s", installed, suffix);
        if (n <= 0 || (size_t)n >= sizeof(tmp))
            LOG_FAIL(SHOP_TAG, "path too long for temp write: %s", path);
        created = platform_private_file_create(tmp, &file);
    }
    if (!created)
        LOG_FAIL(SHOP_TAG, "cannot create exclusive staging file for %s", path);
    if (!platform_private_file_write_at(&file, bytes, len, 0) ||
        !platform_private_file_flush(&file)) {
        (void)platform_private_file_retire(&file, tmp);
        platform_private_file_close(&file);
        LOG_FAIL(SHOP_TAG, "short write to %s", tmp);
    }
    if (!platform_private_file_replace(&file, tmp, installed)) {
        (void)platform_private_file_retire(&file, tmp);
        platform_private_file_close(&file);
        LOG_FAIL(SHOP_TAG, "cannot install %s: %s", path, strerror(errno));
    }
    if (!platform_private_parent_flush(parent))
        LOG_FAIL(SHOP_TAG, "cannot flush parent after installing %s", path);
    return true;
}

/* ── the persistent identity, read-only ─────────────────────────────
 * Read the seed WITHOUT minting one (status is a read leaf; only init's
 * commit may create). The address is re-derived from the seed bytes,
 * never trusted from the hostname file. */
bool shop_internal_read_identity(const char *datadir, char addr_out[64])
{
    addr_out[0] = '\0';
    char path[1024];
    if (!shop_internal_path_join(path, sizeof(path), datadir,
                                 "tor_data/onion_service/identity_seed"))
        return false;   // raw-return-ok:path-too-long-reads-as-absent
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false;   // raw-return-ok:absent-reads-as-no-identity
    uint8_t seed[32];
    uint64_t size = 0;
    int64_t n = platform_positioned_file_size(&file, &size)
                    ? platform_positioned_file_read(&file, seed, sizeof(seed), 0)
                    : -1;
    platform_positioned_file_close(&file);
    if (size != sizeof(seed) || n != (int64_t)sizeof(seed))
        return false;   // raw-return-ok:corrupt-seed-reads-as-no-identity
    char addr[57];
    if (!onion_identity_address_from_seed(seed, addr, sizeof(addr)))
        return false;   // raw-return-ok:derivation-failure-reads-as-absent
    (void)snprintf(addr_out, 64, "%s", addr);
    return true;
}

/* ── wallet posture probe ───────────────────────────────────────────── */
const char *shop_wallet_posture_name(enum shop_wallet_posture posture)
{
    switch (posture) {
    case SHOP_WALLET_ABSENT:     return "absent";
    case SHOP_WALLET_PLAINTEXT:  return "plaintext";
    case SHOP_WALLET_ENCRYPTED:  return "encrypted";
    case SHOP_WALLET_UNREADABLE: return "unreadable";
    }
    return "unknown";
}

/* True when any column of the current row is a blob carrying an at-rest
 * envelope header. The two magics are the wallet persistence layer's own:
 * WKS1 (per-secret envelope, wallet/wallet_keystore.h) and WKD1
 * (wrapped-DEK envelope, wallet/wallet_sqlite_key_crypto.h) — the same
 * markers wallet_sqlite.c's is_wks1_blob() uses to tell an encrypted
 * wallet from a plaintext one. */
static bool shp_row_has_envelope(sqlite3_stmt *s)
{
    int cols = sqlite3_column_count(s);
    for (int i = 0; i < cols; i++) {
        if (sqlite3_column_type(s, i) != SQLITE_BLOB)
            continue;
        if (sqlite3_column_bytes(s, i) < 4)
            continue;
        const unsigned char *b = sqlite3_column_blob(s, i);
        if (b && (memcmp(b, "WKS1", 4) == 0 || memcmp(b, "WKD1", 4) == 0))
            return true;
    }
    return false;
}

enum shop_wallet_posture shop_probe_wallet_posture(const char *datadir)
{
    /* The open is the shared guarded read-only one
     * (zcl_native_node_db_open_readonly, tools/command/native_node_db_ro.c).
     * A hand-rolled open_v2(READONLY) against a WAL node.db whose wal-index
     * is not live CREATES the -shm/-wal sidecars it then cannot unlink —
     * two files added to a datadir a READ probe was only asked about. The
     * helper picks the side-effect-free open for the state the database is
     * actually in, and it touches the header, so a present non-database is
     * UNREADABLE here instead of "scanned, found nothing" — the exact
     * conflation test_read_leaf_no_datadir_write's case 5 refuses. */
    sqlite3 *db = NULL;
    struct node_db ndb;
    enum zcl_node_db_ro_status ro =
        zcl_native_node_db_open_readonly(datadir, &db, &ndb, NULL, 0);
    if (ro == ZCL_NODE_DB_RO_ABSENT || ro == ZCL_NODE_DB_RO_NO_DATADIR ||
        ro == ZCL_NODE_DB_RO_PATH_TOO_LONG)
        return SHOP_WALLET_UNREADABLE;  /* no node.db: nothing to probe */
    if (ro != ZCL_NODE_DB_RO_OK)
        LOG_RETURN(SHOP_WALLET_UNREADABLE, SHOP_TAG,
                   "node.db exists but is not a readable database "
                   "(read-only open status %d)", (int)ro);

    bool any_rows = false, encrypted = false, scan_complete = true;
    static const char *const tables[] = {
        "wallet_seed", "wallet_keys", "wallet_sapling_keys"
    };
    for (size_t t = 0; t < sizeof(tables) / sizeof(tables[0]); t++) {
        char sql[80];
        (void)snprintf(sql, sizeof(sql), "SELECT * FROM %s", tables[t]);
        sqlite3_stmt *s = NULL;
        /* A missing table contributes no rows — an old node.db is probed
         * for what it has, not failed for what it lacks. */
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK || !s) { // raw-controller-sql-ok
            if (s)
                sqlite3_finalize(s);
            continue;
        }
        /* One step per row: AR_STEP_ROW_READONLY returns the raw result
         * code, so DONE and a mid-scan error are told apart without a
         * second step past the end (AR_STEP_DONE would step AGAIN). */
        int rc = SQLITE_ROW;
        long scanned = 0;
        while ((rc = AR_STEP_ROW_READONLY(s)) == SQLITE_ROW) {
            any_rows = true;
            if (shp_row_has_envelope(s))
                encrypted = true;
            if (++scanned >= SHOP_WALLET_SCAN_MAX) {
                scan_complete = false;  /* the row cap stopped the scan */
                break;
            }
        }
        sqlite3_finalize(s);
        if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
            zcl_native_node_db_close_readonly(&db, &ndb);
            LOG_RETURN(SHOP_WALLET_UNREADABLE, SHOP_TAG,
                       "wallet table %s scan failed mid-probe", tables[t]);
        }
    }

    /* The wrapped-DEK row: the WKD1 world keeps one row in
     * wallet_key_encryption, written only when keys are encrypted. */
    if (!encrypted) {
        static const char *const dek_sql =
            "SELECT 1 FROM wallet_key_encryption WHERE id=1";
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db, dek_sql, -1, &s, NULL) == SQLITE_OK && s) { // raw-controller-sql-ok
            if (AR_STEP_ROW(s))
                encrypted = true;
            sqlite3_finalize(s);
        } else if (s) {
            sqlite3_finalize(s);
        }
    }
    zcl_native_node_db_close_readonly(&db, &ndb);

    if (encrypted)
        return SHOP_WALLET_ENCRYPTED;
    /* A truncated scan can only prove "no envelope in the first N rows",
     * which must not be reported as plaintext custody. */
    if (!scan_complete)
        return SHOP_WALLET_UNREADABLE;
    if (any_rows)
        return SHOP_WALLET_PLAINTEXT;
    return SHOP_WALLET_ABSENT;
}

/* ── products.json provisioning ───────────────────────────────────────── */
bool shop_provision_products_json(const char *datadir,
                                  const char *input_path,
                                  char *err, size_t err_size)
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, input_path)) {
        (void)snprintf(err, err_size, "cannot open %s", input_path);
        LOG_FAIL(SHOP_TAG, "products input unreadable: %s", input_path);
    }
    char buf[SHOP_PRODUCTS_JSON_MAX + 1];
    uint64_t input_size = 0;
    if (!platform_positioned_file_size(&file, &input_size) ||
        input_size > sizeof(buf)) {
        platform_positioned_file_close(&file);
        (void)snprintf(err, err_size,
                       "%s exceeds the %d-byte products.json cap",
                       input_path, SHOP_PRODUCTS_JSON_MAX);
        LOG_FAIL(SHOP_TAG, "products input over cap: %s", input_path);
    }
    int64_t got = platform_positioned_file_read(&file, buf,
                                                (size_t)input_size, 0);
    platform_positioned_file_close(&file);
    if (got < 0 || (uint64_t)got != input_size) {
        (void)snprintf(err, err_size, "read failed on %s", input_path);
        LOG_FAIL(SHOP_TAG, "products input read error: %s", input_path);
    }
    size_t len = (size_t)got;
    if (len == 0) {
        (void)snprintf(err, err_size, "%s is empty", input_path);
        LOG_FAIL(SHOP_TAG, "products input is empty: %s", input_path);
    }
    char store_dir[1024];
    if (!shop_internal_path_join(store_dir, sizeof(store_dir), datadir,
                                 "store")) {
        (void)snprintf(err, err_size, "datadir path too long");
        LOG_FAIL(SHOP_TAG, "datadir path too long for store dir");
    }
    if (!shp_mkdir_one(store_dir)) {
        (void)snprintf(err, err_size, "cannot create %s", store_dir);
        LOG_FAIL(SHOP_TAG, "cannot create %s: %s", store_dir,
                 strerror(errno));
    }
    char dst[1088];
    if (!shop_internal_path_join(dst, sizeof(dst), store_dir,
                                 "products.json")) {
        (void)snprintf(err, err_size, "datadir path too long");
        LOG_FAIL(SHOP_TAG, "datadir path too long for products.json");
    }
    if (!shp_write_file_atomic(dst, buf, len)) {
        (void)snprintf(err, err_size, "cannot write %s", dst);
        return false;   /* the helper already logged */
    }
    return true;
}

/* ── directory announcement ─────────────────────────────────────────── */
bool shop_announce_directory_app(const char *datadir,
                                 char *err, size_t err_size)
{
    char csv[ONION_DIR_APPS_CSV_MAX + 1];
    (void)onion_directory_extra_apps_csv(datadir, csv, sizeof(csv));

    char merged[2 * ONION_DIR_APPS_CSV_MAX + 2];
    (void)snprintf(merged, sizeof(merged), "%s%s%s", csv,
                   csv[0] ? "," : "", SHOP_DIRECTORY_APP_ID);
    char norm[ONION_DIR_APPS_CSV_MAX + 1];
    (void)onion_directory_apps_normalize(merged, norm, sizeof(norm));
    /* "shop" validates under the one id rule, so a normalize that drops it
     * can only mean the advertisement is already full — say so, never
     * silently announce nothing. Token-exact membership: "shopify" is not
     * "shop". */
    bool present = false;
    const char *p = norm;
    while (*p && !present) {
        const char *comma = strchr(p, ',');
        size_t tl = comma ? (size_t)(comma - p) : strlen(p);
        if (tl == strlen(SHOP_DIRECTORY_APP_ID) &&
            memcmp(p, SHOP_DIRECTORY_APP_ID, tl) == 0)
            present = true;
        p += tl + (comma ? 1 : 0);
    }
    if (!present) {
        (void)snprintf(err, err_size, "the %d-id advertisement cap is full",
                       ONION_DIR_APPS_MAX);
        LOG_FAIL(SHOP_TAG, "directory apps advertisement cannot take %s",
                 SHOP_DIRECTORY_APP_ID);
    }
    if (strcmp(norm, csv) == 0 && csv[0])
        return true;    /* already announced — idempotent */

    char dir_path[1024];
    if (!shop_internal_path_join(dir_path, sizeof(dir_path), datadir,
                                 "directory")) {
        (void)snprintf(err, err_size, "datadir path too long");
        LOG_FAIL(SHOP_TAG, "datadir path too long for directory dir");
    }
    if (!shp_mkdir_one(dir_path)) {
        (void)snprintf(err, err_size, "cannot create %s", dir_path);
        LOG_FAIL(SHOP_TAG, "cannot create %s: %s", dir_path,
                 strerror(errno));
    }
    char file_path[1088];
    if (!shop_internal_path_join(file_path, sizeof(file_path), datadir,
                                 ONION_DIR_EXTRA_APPS_REL)) {
        (void)snprintf(err, err_size, "datadir path too long");
        LOG_FAIL(SHOP_TAG, "datadir path too long for apps.csv");
    }
    if (!shp_write_file_atomic(file_path, norm, strlen(norm))) {
        (void)snprintf(err, err_size, "cannot write %s", file_path);
        return false;   /* the helper already logged */
    }
    return true;
}
