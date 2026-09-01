/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * App-feature schema migrations (v14+) for node.db: store products and
 * orders, ZCL Market file offers, ZNAM name registry, ZMSG messaging,
 * ZSWP atomic-swap contracts, HODL wave history, and the
 * content-addressed blob store, and signed Blog publication records.
 * node_db_migrate() in database_migrate.c
 * owns the core chain/explorer schema versions and hands off here at
 * the v14 boundary; every block follows the same idempotent
 * versioned-block pattern documented there (check schema version, run
 * DDL, stamp schema_migrations + schema_version).
 *
 * ar-validate-skip:connection-handle-not-a-row
 *   These functions operate on the struct node_db connection handle and
 *   the schema_migrations bookkeeping — none of which are row records.
 *   Row-level validation lives on the models that use this handle (same
 *   rationale as database.c). */

#include "util/log_macros.h"
#include "models/database.h"
#include "models/database_internal.h"

#include <string.h>

#define APP_EVENTS_TABLE_BODY \
    "(receive_cursor INTEGER PRIMARY KEY AUTOINCREMENT," \
    "event_id BLOB NOT NULL UNIQUE CHECK(length(event_id)=32)," \
    "app_id TEXT NOT NULL CHECK(length(app_id) BETWEEN 1 AND 63)," \
    "topic TEXT NOT NULL CHECK(length(topic) BETWEEN 1 AND 127)," \
    "kind INTEGER NOT NULL CHECK(kind BETWEEN 1 AND 4294967295)," \
    "chain_id BLOB NOT NULL CHECK(length(chain_id)=32)," \
    "author_key_id BLOB NOT NULL CHECK(length(author_key_id)=20)," \
    "author_pubkey BLOB NOT NULL CHECK(length(author_pubkey)=33)," \
    "sequence INTEGER NOT NULL CHECK(sequence>0)," \
    "previous_event_id BLOB NOT NULL CHECK(length(previous_event_id)=32)," \
    "created_at INTEGER NOT NULL CHECK(created_at>0)," \
    "payload BLOB NOT NULL CHECK(length(payload)<=65536)," \
    "signature BLOB NOT NULL CHECK(length(signature) BETWEEN 8 AND 72)," \
    "signature_len INTEGER NOT NULL CHECK(signature_len=length(signature))," \
    "received_at INTEGER NOT NULL CHECK(received_at>0))"

static const char k_app_events_table_create[] =
    "CREATE TABLE IF NOT EXISTS app_events " APP_EVENTS_TABLE_BODY;
static const char k_app_events_table_stored[] =
    "CREATE TABLE app_events " APP_EVENTS_TABLE_BODY;
static const char k_app_events_topic_index_create[] =
    "CREATE INDEX IF NOT EXISTS idx_app_events_topic_cursor "
    "ON app_events(app_id,topic,receive_cursor)";
static const char k_app_events_topic_index_stored[] =
    "CREATE INDEX idx_app_events_topic_cursor "
    "ON app_events(app_id,topic,receive_cursor)";
static const char k_app_events_author_index_create[] =
    "CREATE INDEX IF NOT EXISTS idx_app_events_author_sequence "
    "ON app_events(app_id,author_key_id,sequence,event_id)";
static const char k_app_events_author_index_stored[] =
    "CREATE INDEX idx_app_events_author_sequence "
    "ON app_events(app_id,author_key_id,sequence,event_id)";
static const char k_app_events_previous_index_create[] =
    "CREATE INDEX IF NOT EXISTS idx_app_events_previous "
    "ON app_events(app_id,previous_event_id,event_id)";
static const char k_app_events_previous_index_stored[] =
    "CREATE INDEX idx_app_events_previous "
    "ON app_events(app_id,previous_event_id,event_id)";

#undef APP_EVENTS_TABLE_BODY

static bool migration_schema_object_matches(
    struct node_db *ndb, const char *type, const char *name,
    const char *created_sql, const char *normalized_sql)
{
    sqlite3_stmt *stmt = NULL;
    if (!ndb || !ndb->db || !type || !name || !created_sql ||
        !normalized_sql ||
        sqlite3_prepare_v2(ndb->db,
            "SELECT type,sql FROM sqlite_master WHERE name=?", -1,
            &stmt, NULL) != SQLITE_OK || !stmt) {
        if (stmt)
            sqlite3_finalize(stmt);
        LOG_FAIL("db", "migrate v29: cannot inspect schema object %s",
                 name ? name : "(null)");
    }
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt); // raw-sql-ok:migration-schema-inspection
    const char *stored_type = rc == SQLITE_ROW
        ? (const char *)sqlite3_column_text(stmt, 0) : NULL;
    const char *stored_sql = rc == SQLITE_ROW
        ? (const char *)sqlite3_column_text(stmt, 1) : NULL;
    bool matches = stored_type && stored_sql &&
        strcmp(stored_type, type) == 0 &&
        (strcmp(stored_sql, created_sql) == 0 ||
         strcmp(stored_sql, normalized_sql) == 0);
    rc = rc == SQLITE_ROW
        ? sqlite3_step(stmt) // raw-sql-ok:migration-schema-inspection
        : rc;
    sqlite3_finalize(stmt);
    if (!matches || rc != SQLITE_DONE)
        LOG_FAIL("db", "migrate v29: schema object %s is absent or incompatible",
                 name);
    return true;
}

static bool migration_app_events_schema_valid(struct node_db *ndb)
{
    return migration_schema_object_matches(
               ndb, "table", "app_events", k_app_events_table_create,
               k_app_events_table_stored) &&
           migration_schema_object_matches(
               ndb, "index", "idx_app_events_topic_cursor",
               k_app_events_topic_index_create,
               k_app_events_topic_index_stored) &&
           migration_schema_object_matches(
               ndb, "index", "idx_app_events_author_sequence",
               k_app_events_author_index_create,
               k_app_events_author_index_stored) &&
           migration_schema_object_matches(
               ndb, "index", "idx_app_events_previous",
               k_app_events_previous_index_create,
               k_app_events_previous_index_stored);
}

int node_db_migrate_features(struct node_db *ndb, int *version)
{
    int applied = 0;
    int current_ver = *version;

    if (current_ver < 14) {
        /* v14: Store product/order tables as model-owned app schema. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS products ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "name TEXT NOT NULL,"
            "description TEXT,"
            "price_zatoshi INTEGER NOT NULL,"
            "token_id TEXT,"
            "tokens_per_purchase INTEGER NOT NULL DEFAULT 1,"
            "active INTEGER NOT NULL DEFAULT 1)");

        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS orders ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "product_id INTEGER NOT NULL,"
            "customer_addr TEXT,"
            "payment_addr TEXT NOT NULL,"
            "amount_zatoshi INTEGER NOT NULL,"
            "payment_txid TEXT,"
            "mint_txid TEXT,"
            "status INTEGER NOT NULL DEFAULT 0,"
            "created_at INTEGER NOT NULL,"
            "paid_at INTEGER)");

        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_orders_status_created "
            "ON orders(status, created_at DESC)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('014')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 14);
        current_ver = 14;
        applied++;
    }

    if (current_ver < 15) {
        /* v15: ZCL Market — file offers for crypto-incentivized sharing */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS file_offers ("
            "root_hash BLOB NOT NULL PRIMARY KEY,"
            "filename TEXT NOT NULL,"
            "size_bytes INTEGER NOT NULL,"
            "num_chunks INTEGER NOT NULL,"
            "price_per_mb INTEGER NOT NULL,"
            "z_addr BLOB,"
            "peer_ip BLOB,"
            "peer_port INTEGER,"
            "last_seen INTEGER,"
            "ttl INTEGER DEFAULT 4)");

        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_file_offers_last_seen "
            "ON file_offers(last_seen DESC)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('015')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 15);
        current_ver = 15;
        applied++;
    }

    if (current_ver < 16) {
        /* v16: ZCL Names (ZNAM) — on-chain name registry */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS znam_names ("
            "name TEXT PRIMARY KEY,"
            "owner_address TEXT NOT NULL,"
            "target_type INTEGER NOT NULL,"
            "target_value TEXT NOT NULL,"
            "reg_txid BLOB NOT NULL,"
            "reg_height INTEGER NOT NULL,"
            "last_update_txid BLOB NOT NULL)");

        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_znam_owner "
            "ON znam_names(owner_address)");

        /* ENS-inspired text records (TextResolver) */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS znam_text_records ("
            "name TEXT NOT NULL,"
            "key TEXT NOT NULL,"
            "value TEXT,"
            "PRIMARY KEY(name, key))");

        /* ENS-inspired multi-coin address records (AddrResolver) */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS znam_addr_records ("
            "name TEXT NOT NULL,"
            "coin_type INTEGER NOT NULL,"
            "address TEXT NOT NULL,"
            "PRIMARY KEY(name, coin_type))");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('016')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 16);
        current_ver = 16;
        applied++;
    }

    if (current_ver < 17) {
        /* v17: ZCL Messaging (ZMSG) — encrypted P2P messages */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zmsg_messages ("
            "msg_id BLOB PRIMARY KEY,"
            "direction INTEGER NOT NULL,"
            "channel INTEGER NOT NULL,"
            "sender TEXT NOT NULL,"
            "recipient TEXT NOT NULL,"
            "body TEXT NOT NULL,"
            "timestamp INTEGER NOT NULL,"
            "txid BLOB,"
            "read INTEGER NOT NULL DEFAULT 0)");

        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zmsg_time "
            "ON zmsg_messages(timestamp DESC)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zmsg_unread "
            "ON zmsg_messages(read) WHERE read=0");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('017')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 17);
        current_ver = 17;
        applied++;
    }

    if (current_ver < 18) {
        /* v18: Atomic swaps (ZSWP) — HTLC contracts for BTC/LTC/DOGE */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zswp_contracts ("
            "swap_id TEXT PRIMARY KEY,"
            "role INTEGER NOT NULL,"
            "state INTEGER NOT NULL,"
            "chain INTEGER NOT NULL DEFAULT 0,"
            "secret_hash BLOB NOT NULL,"
            "secret BLOB,"
            "amount INTEGER NOT NULL,"
            "locktime INTEGER NOT NULL,"
            "my_address TEXT NOT NULL,"
            "counter_address TEXT NOT NULL,"
            "funding_txid BLOB,"
            "funding_vout INTEGER,"
            "redeem_script BLOB NOT NULL,"
            "redeem_script_len INTEGER NOT NULL,"
            "p2sh_address TEXT NOT NULL,"
            "created_at INTEGER NOT NULL)");

        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zswp_state "
            "ON zswp_contracts(state)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('018')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 18);
        current_ver = 18;
        applied++;
    }

    if (current_ver < 19) {
        /* v19: HODL wave history — one row per sample height, populated
         * lazily by engine/services/src/hodl_history_service.c. Each row
         * is the reconstructed UTXO snapshot as of that height:
         *   total_zat = sum of unspent output value at H
         *   older_1y_zat = subset that was older than 1 year at H
         *   older_1y_pct = older_1y_zat / total_zat * 100
         * Source: tx_outputs + tx_inputs, no current-UTXO-table dep. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS hodl_history ("
            "height INTEGER PRIMARY KEY,"
            "time INTEGER NOT NULL,"
            "total_zat INTEGER NOT NULL DEFAULT 0 CHECK(total_zat >= 0),"
            "older_1y_zat INTEGER NOT NULL DEFAULT 0 "
            "  CHECK(older_1y_zat >= 0 AND older_1y_zat <= total_zat),"
            "older_1y_pct REAL NOT NULL DEFAULT 0,"
            "calc_version INTEGER NOT NULL DEFAULT 0,"
            "source_tip_height INTEGER NOT NULL DEFAULT -1)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_hodl_history_time "
            "ON hodl_history(time)");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('019')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 19);
        current_ver = 19;
        applied++;
    }

    if (current_ver < 20) {
        /* v20: content-addressed blob store; products.content_hash NULL = none. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS store_blobs ("
            "content_hash BLOB NOT NULL PRIMARY KEY,"
            "content_type TEXT NOT NULL DEFAULT 'engine/application/octet-stream',"
            "filename TEXT,"
            "size_bytes INTEGER NOT NULL,"
            "data BLOB NOT NULL)");
        node_db_exec(ndb, "ALTER TABLE products ADD COLUMN content_hash BLOB");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('020')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 20);
        current_ver = 20;
        applied++;
    }

    if (current_ver < 21) {
        /* v21: distinguish durable wallet notes from zclassicd view-only
         * placeholders. Existing notes default to local, and only the
         * wallet-view mirror path opts into source='view'. */
        if (db_exec_tolerant(ndb->db,
            "ALTER TABLE wallet_sapling_notes "
            "ADD COLUMN source TEXT NOT NULL DEFAULT 'local'",
            "v21: add wallet_sapling_notes.source",
            "duplicate column name") != SQLITE_OK)
            LOG_ERR("db", "v21 migration failed adding wallet_sapling_notes.source");
        if (db_exec_checked(ndb->db,
            "CREATE INDEX IF NOT EXISTS idx_snote_view_address "
            "ON wallet_sapling_notes(address) "
            "WHERE spent_txid IS NULL AND source='view'",
            "v21: idx_snote_view_address") != SQLITE_OK)
            LOG_ERR("db", "v21 migration failed creating idx_snote_view_address");
        if (!node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('021')"))
            LOG_ERR("db", "v21 migration failed stamping schema_migrations");
        DB_MIGRATE_PERSIST_VERSION(ndb, 21);
        current_ver = 21;
        applied++;
    }

    if (current_ver < 22) {
        /* v22: covering indexes for HODL-history reconstruction. The
         * background filler asks historical "alive at H" questions across
         * tx_outputs/tx_inputs; these keep post-rebuild gap repair bounded. */
        if (db_exec_checked(ndb->db,
            "CREATE INDEX IF NOT EXISTS idx_txo_hodl_scan "
            "ON tx_outputs(block_height, value, txid, vout)",
            "v22: idx_txo_hodl_scan") != SQLITE_OK)
            LOG_ERR("db", "v22 migration failed creating idx_txo_hodl_scan");
        if (db_exec_checked(ndb->db,
            "CREATE INDEX IF NOT EXISTS idx_txi_prev_height "
            "ON tx_inputs(prev_txid, prev_vout, block_height)",
            "v22: idx_txi_prev_height") != SQLITE_OK)
            LOG_ERR("db", "v22 migration failed creating idx_txi_prev_height");
        if (!node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('022')"))
            LOG_ERR("db", "v22 migration failed stamping schema_migrations");
        DB_MIGRATE_PERSIST_VERSION(ndb, 22);
        current_ver = 22;
        applied++;
    }

    if (current_ver < 23) {
        /* v23: HODL history repair provenance. Existing rows default to
         * calc_version=0/source_tip=-1, so the lazy filler refreshes them
         * only after the explorer projection cursor proves source coverage. */
        if (db_exec_checked(ndb->db,
            "CREATE TABLE IF NOT EXISTS hodl_history ("
            "height INTEGER PRIMARY KEY,"
            "time INTEGER NOT NULL,"
            "total_zat INTEGER NOT NULL DEFAULT 0 CHECK(total_zat >= 0),"
            "older_1y_zat INTEGER NOT NULL DEFAULT 0 "
            "  CHECK(older_1y_zat >= 0 AND older_1y_zat <= total_zat),"
            "older_1y_pct REAL NOT NULL DEFAULT 0,"
            "calc_version INTEGER NOT NULL DEFAULT 0,"
            "source_tip_height INTEGER NOT NULL DEFAULT -1)",
            "v23: create hodl_history if missing") != SQLITE_OK)
            LOG_ERR("db", "v23 migration failed ensuring hodl_history table");
        if (db_exec_tolerant(ndb->db,
            "ALTER TABLE hodl_history "
            "ADD COLUMN calc_version INTEGER NOT NULL DEFAULT 0",
            "v23: add hodl_history.calc_version",
            "duplicate column name") != SQLITE_OK)
            LOG_ERR("db", "v23 migration failed adding hodl_history.calc_version");
        if (db_exec_tolerant(ndb->db,
            "ALTER TABLE hodl_history "
            "ADD COLUMN source_tip_height INTEGER NOT NULL DEFAULT -1",
            "v23: add hodl_history.source_tip_height",
            "duplicate column name") != SQLITE_OK)
            LOG_ERR("db", "v23 migration failed adding hodl_history.source_tip_height");
        if (db_exec_checked(ndb->db,
            "CREATE INDEX IF NOT EXISTS idx_hodl_history_time "
            "ON hodl_history(time)",
            "v23: idx_hodl_history_time") != SQLITE_OK)
            LOG_ERR("db", "v23 migration failed creating idx_hodl_history_time");
        if (!node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('023')"))
            LOG_ERR("db", "v23 migration failed stamping schema_migrations");
        DB_MIGRATE_PERSIST_VERSION(ndb, 23);
        current_ver = 23;
        applied++;
    }

    if (current_ver < 24) {
        /* v24: HODL wave history stores the same alive-at-height snapshot for
         * 6m/1y/2y/5y thresholds. Existing v19-v23 rows are left in place but
         * have calc_version < HODL_HISTORY_SNAPSHOT_CALC_VERSION, so the lazy
         * background filler recomputes them before the explorer reads them. */
        if (db_exec_tolerant(ndb->db,
            "ALTER TABLE hodl_history "
            "ADD COLUMN older_6m_zat INTEGER NOT NULL DEFAULT 0 "
            "CHECK(older_6m_zat >= 0 AND older_6m_zat <= total_zat)",
            "v24: add hodl_history.older_6m_zat",
            "duplicate column name") != SQLITE_OK)
            LOG_ERR("db", "v24 migration failed adding hodl_history.older_6m_zat");
        if (db_exec_tolerant(ndb->db,
            "ALTER TABLE hodl_history "
            "ADD COLUMN older_2y_zat INTEGER NOT NULL DEFAULT 0 "
            "CHECK(older_2y_zat >= 0 AND older_2y_zat <= total_zat)",
            "v24: add hodl_history.older_2y_zat",
            "duplicate column name") != SQLITE_OK)
            LOG_ERR("db", "v24 migration failed adding hodl_history.older_2y_zat");
        if (db_exec_tolerant(ndb->db,
            "ALTER TABLE hodl_history "
            "ADD COLUMN older_5y_zat INTEGER NOT NULL DEFAULT 0 "
            "CHECK(older_5y_zat >= 0 AND older_5y_zat <= total_zat)",
            "v24: add hodl_history.older_5y_zat",
            "duplicate column name") != SQLITE_OK)
            LOG_ERR("db", "v24 migration failed adding hodl_history.older_5y_zat");
        if (db_exec_tolerant(ndb->db,
            "ALTER TABLE hodl_history "
            "ADD COLUMN older_6m_pct REAL NOT NULL DEFAULT 0",
            "v24: add hodl_history.older_6m_pct",
            "duplicate column name") != SQLITE_OK)
            LOG_ERR("db", "v24 migration failed adding hodl_history.older_6m_pct");
        if (db_exec_tolerant(ndb->db,
            "ALTER TABLE hodl_history "
            "ADD COLUMN older_2y_pct REAL NOT NULL DEFAULT 0",
            "v24: add hodl_history.older_2y_pct",
            "duplicate column name") != SQLITE_OK)
            LOG_ERR("db", "v24 migration failed adding hodl_history.older_2y_pct");
        if (db_exec_tolerant(ndb->db,
            "ALTER TABLE hodl_history "
            "ADD COLUMN older_5y_pct REAL NOT NULL DEFAULT 0",
            "v24: add hodl_history.older_5y_pct",
            "duplicate column name") != SQLITE_OK)
            LOG_ERR("db", "v24 migration failed adding hodl_history.older_5y_pct");
        if (!node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('024')"))
            LOG_ERR("db", "v24 migration failed stamping schema_migrations");
        DB_MIGRATE_PERSIST_VERSION(ndb, 24);
        current_ver = 24;
        applied++;
    }

    if (current_ver < 25) {
        /* v25: ZNAM registration term. expiry_height records when a name's
         * registration lapses: set at REGISTER to reg_height +
         * ZNAM_REGISTRATION_TERM_BLOCKS and extended by each RENEW.
         * Overlay bookkeeping only — resolution
         * does not reap expired names, so this never affects consensus.
         * Existing rows default to 0 (pre-term); the ascending reindex
         * refreshes them from their REGISTER anchor. */
        if (db_exec_tolerant(ndb->db,
            "ALTER TABLE znam_names "
            "ADD COLUMN expiry_height INTEGER NOT NULL DEFAULT 0",
            "v25: add znam_names.expiry_height",
            "duplicate column name") != SQLITE_OK)
            LOG_ERR("db", "v25 migration failed adding znam_names.expiry_height");
        if (!node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('025')"))
            LOG_ERR("db", "v25 migration failed stamping schema_migrations");
        DB_MIGRATE_PERSIST_VERSION(ndb, 25);
        current_ver = 25;
        applied++;
    }

    if (current_ver < 26) {
        /* v26: multi-user-server identity overlay. `principals` is one row per
         * authenticated public key (address = base58check(hash160(pubkey)) is
         * the PK); role is the only authorization input and
         * granted_capabilities is a derived cache the model recomputes on every
         * save. `auth_challenges` is the single-use login-nonce store. Pure
         * app-layer overlay — sybil_proof_height is bookkeeping and is never
         * consulted by consensus. Idempotent (IF NOT EXISTS) on a pre-v26 db. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS principals ("
            "address TEXT PRIMARY KEY,"
            "pubkey_hex TEXT NOT NULL,"
            "key_kind INTEGER NOT NULL DEFAULT 0,"
            "znam_name TEXT NOT NULL DEFAULT '',"
            "role TEXT NOT NULL DEFAULT 'guest' "
            "  CHECK(role IN ('guest','member','operator','owner')),"
            "granted_capabilities INTEGER NOT NULL DEFAULT 0,"
            "created_at INTEGER NOT NULL,"
            "last_login INTEGER NOT NULL DEFAULT 0,"
            "status TEXT NOT NULL DEFAULT 'active' "
            "  CHECK(status IN ('active','suspended')),"
            "sybil_proof_height INTEGER NOT NULL DEFAULT -1)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_principals_pubkey "
            "ON principals(pubkey_hex)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_principals_role "
            "ON principals(role)");

        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS auth_challenges ("
            "nonce_hex TEXT PRIMARY KEY,"
            "address TEXT NOT NULL,"
            "issued_at INTEGER NOT NULL,"
            "expires_at INTEGER NOT NULL,"
            "consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1)))");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_auth_challenges_address "
            "ON auth_challenges(address)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_auth_challenges_expiry "
            "ON auth_challenges(expires_at)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('026')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 26);
        current_ver = 26;
        applied++;
    }

    if (current_ver < 27) {
        /* v27: network-monitor per-peer chain-intelligence history. One row
         * per sampled peer per monitor tick (best height, learnable tip hash,
         * version/user-agent, latency, first/last seen). Purely observational —
         * never read by consensus/chain selection. Bounded retention: the
         * network monitor prunes to the newest N rows. Idempotent on a pre-v27
         * db. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS peer_chain_observations ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "peer_id INTEGER NOT NULL,"
            "addr TEXT NOT NULL DEFAULT '',"
            "user_agent TEXT NOT NULL DEFAULT '',"
            "version INTEGER NOT NULL DEFAULT 0,"
            "best_height INTEGER NOT NULL DEFAULT -1,"
            "tip_hash TEXT NOT NULL DEFAULT '',"
            "latency_us INTEGER NOT NULL DEFAULT 0,"
            "inbound INTEGER NOT NULL DEFAULT 0,"
            "first_seen INTEGER NOT NULL DEFAULT 0,"
            "last_seen INTEGER NOT NULL DEFAULT 0,"
            "observed_at INTEGER NOT NULL)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_peer_chain_obs_observed_at "
            "ON peer_chain_observations(observed_at DESC)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('027')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 27);
        current_ver = 27;
        applied++;
    }

    if (current_ver < 28) {
        /* v28: Rails-style Blog reference slice. Posts are immutable signed
         * App events; publication receipts are reorg-aware observations over
         * the full-node block/transaction/OP_RETURN projections. This is an
         * application overlay only and is never consulted by consensus. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS blog_posts ("
            "event_id BLOB PRIMARY KEY CHECK(length(event_id)=32),"
            "blog_name TEXT NOT NULL,"
            "slug TEXT NOT NULL,"
            "title TEXT NOT NULL,"
            "body TEXT NOT NULL,"
            "author_key_id BLOB NOT NULL CHECK(length(author_key_id)=20),"
            "author_pubkey BLOB NOT NULL CHECK(length(author_pubkey)=33),"
            "author_address TEXT NOT NULL,"
            "chain_id BLOB NOT NULL CHECK(length(chain_id)=32),"
            "sequence INTEGER NOT NULL CHECK(sequence>0),"
            "previous_event_id BLOB NOT NULL "
            "  CHECK(length(previous_event_id)=32),"
            "event_created_at INTEGER NOT NULL CHECK(event_created_at>0),"
            "signature BLOB NOT NULL "
            "  CHECK(length(signature) BETWEEN 8 AND 72),"
            "signature_len INTEGER NOT NULL "
            "  CHECK(signature_len=length(signature)),"
            "stored_at INTEGER NOT NULL CHECK(stored_at>0))");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_blog_posts_name_sequence "
            "ON blog_posts(blog_name,sequence DESC)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_blog_posts_name_slug_event "
            "ON blog_posts(blog_name,slug,event_id)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_blog_posts_author_sequence "
            "ON blog_posts(author_key_id,sequence,event_id)");

        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS blog_publication_receipts ("
            "txid BLOB PRIMARY KEY CHECK(length(txid)=32),"
            "event_id BLOB NOT NULL CHECK(length(event_id)=32),"
            "blog_name TEXT NOT NULL,"
            "author_key_id BLOB NOT NULL CHECK(length(author_key_id)=20),"
            "znam_reg_txid BLOB NOT NULL CHECK(length(znam_reg_txid)=32),"
            "block_hash BLOB "
            "  CHECK(block_hash IS NULL OR length(block_hash)=32),"
            "block_height INTEGER NOT NULL CHECK(block_height>=-1),"
            "status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 2),"
            "observed_at INTEGER NOT NULL CHECK(observed_at>0),"
            "FOREIGN KEY(event_id) REFERENCES blog_posts(event_id) "
            "  ON DELETE CASCADE)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_blog_receipts_event "
            "ON blog_publication_receipts(event_id,observed_at DESC)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('028')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 28);
        current_ver = 28;
        applied++;
    }

    if (current_ver < 29) {
        /* v29: shared immutable signed AppEvent substrate. Blog, Social, Chat,
         * games, and future manifest-declared topics converge on this one
         * signature-verified store. receive_cursor is local anti-entropy
         * position only; projections must resolve forks from signed identity
         * and sequence, never arrival order. This application overlay is not
         * consulted by consensus. */
        if (!node_db_begin(ndb))
            LOG_ERR("db", "migrate v29: cannot begin atomic migration");
        bool ok = node_db_exec(ndb, k_app_events_table_create) &&
                  node_db_exec(ndb, k_app_events_topic_index_create) &&
                  node_db_exec(ndb, k_app_events_author_index_create) &&
                  node_db_exec(ndb, k_app_events_previous_index_create) &&
                  migration_app_events_schema_valid(ndb) &&
                  node_db_exec(ndb,
                      "INSERT OR IGNORE INTO schema_migrations(version) "
                      "VALUES('029')");
        int32_t version_29 = 29;
        if (ok)
            ok = node_db_state_set(ndb, "schema_version", &version_29,
                                   sizeof(version_29));
        if (ok)
            ok = node_db_commit(ndb);
        if (!ok) {
            if (!node_db_rollback(ndb))
                LOG_ERR("db", "migrate v29: migration and rollback failed");
            LOG_ERR("db", "migrate v29: atomic schema verification failed");
        }
        current_ver = 29;
        applied++;
    }

    int applied2 = node_db_migrate_features_v30_up(ndb, &current_ver);
    applied += applied2;

    *version = current_ver;
    return applied;
}
