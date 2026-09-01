/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * App-feature schema migrations v49+ for node.db — continuation of
 * database_migrate_features_v30_up.c (E1 file-size split; same idempotent
 * versioned-block pattern documented at the top of
 * database_migrate_features.c). node_db_migrate_features_v30_up() hands
 * off here at the v49 boundary via node_db_migrate_features_v49_up().
 *
 * ar-validate-skip:connection-handle-not-a-row
 *   Same rationale as database_migrate_features.c: operates on the
 *   struct node_db connection handle + schema_migrations bookkeeping,
 *   never a row record. */

#include "models/database.h"
#include "models/database_internal.h"

int node_db_migrate_features_v49_up(struct node_db *ndb, int *version)
{
    int applied = 0;
    int current_ver = *version;

    if (current_ver < 49) {
        /* v49: ZCODE science — the durable plan/commit idempotency ledger
         * (zcode_science_plans: exact wire + request identity + expiry +
         * result root per write) and the six rebuildable projections of the
         * canonical science CAS objects (study_spec.v1, benchmark_result.v2,
         * reproduction.v1, science_findings.v1, curation_vote.v1,
         * review.v1). Projection columns are lookup keys only; the addressed
         * wires under .zvcs/objects stay the authority and the projections
         * may be dropped and rebuilt at any time. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zcode_science_plans ("
            "plan_root TEXT PRIMARY KEY CHECK(length(plan_root)=64),"
            "kind TEXT NOT NULL CHECK(kind IN ('study','work','review','vote')),"
            "request_hash TEXT NOT NULL UNIQUE CHECK(length(request_hash)=64),"
            "wire_hex TEXT NOT NULL,"
            "result_root TEXT NOT NULL CHECK(length(result_root) IN (0,64)),"
            "state TEXT NOT NULL CHECK(state IN ('PLANNED','COMMITTED')),"
            "expires_unix INTEGER NOT NULL CHECK(expires_unix>0),"
            "created_at INTEGER NOT NULL)");
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zcode_science_studies ("
            "root TEXT PRIMARY KEY CHECK(length(root)=64),"
            "study_root TEXT NOT NULL,"
            "link_root TEXT NOT NULL,"
            "aux_root TEXT NOT NULL,"
            "author TEXT NOT NULL,"
            "code INTEGER NOT NULL,"
            "flags INTEGER NOT NULL,"
            "sequence INTEGER NOT NULL,"
            "created_at INTEGER NOT NULL,"
            "expires_at INTEGER NOT NULL)");
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zcode_science_results ("
            "root TEXT PRIMARY KEY CHECK(length(root)=64),"
            "study_root TEXT NOT NULL,"
            "link_root TEXT NOT NULL,"
            "aux_root TEXT NOT NULL,"
            "author TEXT NOT NULL,"
            "code INTEGER NOT NULL,"
            "flags INTEGER NOT NULL,"
            "sequence INTEGER NOT NULL,"
            "created_at INTEGER NOT NULL,"
            "expires_at INTEGER NOT NULL)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zcode_science_results_study "
            "ON zcode_science_results(study_root)");
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zcode_science_reproductions ("
            "root TEXT PRIMARY KEY CHECK(length(root)=64),"
            "study_root TEXT NOT NULL,"
            "link_root TEXT NOT NULL,"
            "aux_root TEXT NOT NULL,"
            "author TEXT NOT NULL,"
            "code INTEGER NOT NULL,"
            "flags INTEGER NOT NULL,"
            "sequence INTEGER NOT NULL,"
            "created_at INTEGER NOT NULL,"
            "expires_at INTEGER NOT NULL)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zcode_science_repros_study "
            "ON zcode_science_reproductions(study_root)");
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zcode_science_findings ("
            "root TEXT PRIMARY KEY CHECK(length(root)=64),"
            "study_root TEXT NOT NULL,"
            "link_root TEXT NOT NULL,"
            "aux_root TEXT NOT NULL,"
            "author TEXT NOT NULL,"
            "code INTEGER NOT NULL,"
            "flags INTEGER NOT NULL,"
            "sequence INTEGER NOT NULL,"
            "created_at INTEGER NOT NULL,"
            "expires_at INTEGER NOT NULL)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zcode_science_findings_study "
            "ON zcode_science_findings(study_root)");
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zcode_science_votes ("
            "root TEXT PRIMARY KEY CHECK(length(root)=64),"
            "study_root TEXT NOT NULL,"
            "link_root TEXT NOT NULL,"
            "aux_root TEXT NOT NULL,"
            "author TEXT NOT NULL,"
            "code INTEGER NOT NULL,"
            "flags INTEGER NOT NULL,"
            "sequence INTEGER NOT NULL,"
            "created_at INTEGER NOT NULL,"
            "expires_at INTEGER NOT NULL)");
        node_db_exec(ndb,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_zcode_science_votes_replay "
            "ON zcode_science_votes(author,sequence)");
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zcode_science_reviews ("
            "root TEXT PRIMARY KEY CHECK(length(root)=64),"
            "study_root TEXT NOT NULL,"
            "link_root TEXT NOT NULL,"
            "aux_root TEXT NOT NULL,"
            "author TEXT NOT NULL,"
            "code INTEGER NOT NULL,"
            "flags INTEGER NOT NULL,"
            "sequence INTEGER NOT NULL,"
            "created_at INTEGER NOT NULL,"
            "expires_at INTEGER NOT NULL)");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('049')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 49);
        current_ver = 49;
        applied++;
    }

    if (current_ver < 50) {
        /* v50: yardsale wallet glue — the durable plan/commit idempotency
         * ledger (yardsale_plans) behind yardsale.seller.arm and
         * yardsale.buy: request identity + the exact planned terms
         * (canonical accept-data serialization + sign root, never key
         * material) + expiry + state per wallet-touching write. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS yardsale_plans ("
            "plan_root TEXT PRIMARY KEY CHECK(length(plan_root)=64),"
            "kind TEXT NOT NULL CHECK(kind IN ('arm','buy')),"
            "request_hash TEXT NOT NULL UNIQUE CHECK(length(request_hash)=64),"
            "payload_hex TEXT NOT NULL,"
            "result TEXT NOT NULL,"
            "state TEXT NOT NULL CHECK(state IN ('PLANNED','COMMITTED','EXPIRED')),"
            "expires_unix INTEGER NOT NULL CHECK(expires_unix>0),"
            "created_at INTEGER NOT NULL)");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('050')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 50);
        current_ver = 50;
        applied++;
    }

    if (current_ver < 51) {
        /* v51: ZCODE science findings admission (G4) — extend the plan
         * ledger's kind CHECK with 'findings' for
         * zcode.science.findings.plan|commit. SQLite cannot ALTER a CHECK
         * constraint, so the table is rebuilt and rows carry over. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zcode_science_plans_v51 ("
            "plan_root TEXT PRIMARY KEY CHECK(length(plan_root)=64),"
            "kind TEXT NOT NULL CHECK(kind IN ('study','work','findings','review','vote')),"
            "request_hash TEXT NOT NULL UNIQUE CHECK(length(request_hash)=64),"
            "wire_hex TEXT NOT NULL,"
            "result_root TEXT NOT NULL CHECK(length(result_root) IN (0,64)),"
            "state TEXT NOT NULL CHECK(state IN ('PLANNED','COMMITTED')),"
            "expires_unix INTEGER NOT NULL CHECK(expires_unix>0),"
            "created_at INTEGER NOT NULL)");
        node_db_exec(ndb,
            "INSERT INTO zcode_science_plans_v51 "
            "SELECT * FROM zcode_science_plans");
        node_db_exec(ndb, "DROP TABLE zcode_science_plans");
        node_db_exec(ndb,
            "ALTER TABLE zcode_science_plans_v51 "
            "RENAME TO zcode_science_plans");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('051')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 51);
        current_ver = 51;
        applied++;
    }

    if (current_ver < 52) {
        /* v52: stable wallet identity and fail-closed agent-session binding.
         * Existing sessions receive empty binding columns deliberately: they
         * remain listable/revocable, but no money authorization can treat an
         * unbound legacy row as belonging to the current wallet. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS wallet_identity ("
            "id INTEGER PRIMARY KEY CHECK(id=1),"
            "wallet_instance_id TEXT NOT NULL UNIQUE "
            " CHECK(length(wallet_instance_id)=32),"
            "network_genesis BLOB NOT NULL CHECK(length(network_genesis)=32),"
            "operator_lane TEXT NOT NULL CHECK(length(operator_lane)>0),"
            "created_at INTEGER NOT NULL CHECK(created_at>0))");
        node_db_exec(ndb,
            "ALTER TABLE agent_sessions ADD COLUMN wallet_scope TEXT NOT NULL "
            "DEFAULT '' CHECK(wallet_scope IN ('','dev','prod'))");
        node_db_exec(ndb,
            "ALTER TABLE agent_sessions ADD COLUMN wallet_instance_id TEXT "
            "NOT NULL DEFAULT '' CHECK(length(wallet_instance_id) IN (0,32))");
        node_db_exec(ndb,
            "ALTER TABLE agent_sessions ADD COLUMN wallet_genesis TEXT NOT NULL "
            "DEFAULT '' CHECK(length(wallet_genesis) IN (0,64))");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_agent_sessions_wallet "
            "ON agent_sessions(wallet_scope,wallet_instance_id,revoked)");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('052')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 52);
        current_ver = 52;
        applied++;
    }

    if (current_ver < 53) {
        /* v53: durable, scope-wide agent allocation accounting. Unlike the
         * rolling rate window this counter never resets; it lets the dev
         * custody floor enforce a lifetime 0.05-ZCL lab allocation across
         * concurrent sessions. A failed pre-broadcast handler releases it. */
        node_db_exec(ndb,
            "ALTER TABLE agent_sessions ADD COLUMN lifetime_spent_zat INTEGER "
            "NOT NULL DEFAULT 0 CHECK(lifetime_spent_zat>=0 AND "
            "lifetime_spent_zat<=2100000000000000)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_agent_sessions_scope_lifetime "
            "ON agent_sessions(wallet_scope,lifetime_spent_zat)");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('053')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 53);
        current_ver = 53;
        applied++;
    }

    if (current_ver < 54) {
        /* v54: bind durable transaction intents to the exact custody
         * snapshot and reserve recipient value plus maximum fee. Empty
         * binding fields mark legacy owner plans; agent money paths never
         * infer an identity for them. */
        node_db_exec(ndb,
            "ALTER TABLE vault_intents ADD COLUMN wallet_scope TEXT NOT NULL "
            "DEFAULT '' CHECK(wallet_scope IN ('','dev','prod'))");
        node_db_exec(ndb,
            "ALTER TABLE vault_intents ADD COLUMN wallet_instance_id TEXT "
            "NOT NULL DEFAULT '' CHECK(length(wallet_instance_id) IN (0,32))");
        node_db_exec(ndb,
            "ALTER TABLE vault_intents ADD COLUMN wallet_genesis TEXT NOT NULL "
            "DEFAULT '' CHECK(length(wallet_genesis) IN (0,64))");
        node_db_exec(ndb,
            "ALTER TABLE vault_intents ADD COLUMN snapshot_root BLOB "
            "CHECK(snapshot_root IS NULL OR length(snapshot_root)=32)");
        node_db_exec(ndb,
            "ALTER TABLE vault_intents ADD COLUMN recipient_value_zat INTEGER "
            "NOT NULL DEFAULT 0 CHECK(recipient_value_zat>=0)");
        node_db_exec(ndb,
            "ALTER TABLE vault_intents ADD COLUMN max_fee_zat INTEGER NOT NULL "
            "DEFAULT 0 CHECK(max_fee_zat>=0)");
        node_db_exec(ndb,
            "ALTER TABLE vault_intents ADD COLUMN reserved_zat INTEGER NOT NULL "
            "DEFAULT 0 CHECK(reserved_zat>=0)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_vault_intents_wallet_reserve "
            "ON vault_intents(wallet_scope,wallet_instance_id,state)");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('054')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 54);
        current_ver = 54;
        applied++;
    }

    if (current_ver < 55) {
        /* v55: authenticated paid file offers. Mutable gossip bookkeeping
         * remains outside the signed body; every money-bearing term is
         * committed by the seller's network-bound Ed25519 contract. Legacy
         * auth_version=0 rows remain readable only when price_per_mb=0. */
        /* A few supported recovery/test fixtures carry a valid version but
         * only a subset of feature tables. Converge those stores before the
         * ALTER sequence instead of stamping v55 over a missing authority. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS file_offers ("
            "root_hash BLOB NOT NULL PRIMARY KEY,"
            "filename TEXT NOT NULL,"
            "size_bytes INTEGER NOT NULL,"
            "num_chunks INTEGER NOT NULL,"
            "price_per_mb INTEGER NOT NULL,"
            "z_addr BLOB,peer_ip BLOB,peer_port INTEGER,"
            "last_seen INTEGER,ttl INTEGER DEFAULT 4)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_file_offers_last_seen "
            "ON file_offers(last_seen DESC)");
        node_db_exec(ndb,
            "ALTER TABLE file_offers ADD COLUMN auth_version INTEGER "
            "NOT NULL DEFAULT 0 CHECK(auth_version IN (0,1))");
        node_db_exec(ndb,
            "ALTER TABLE file_offers ADD COLUMN network_genesis BLOB "
            "NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' "
            "CHECK(length(network_genesis)=32)");
        node_db_exec(ndb,
            "ALTER TABLE file_offers ADD COLUMN seller_pubkey BLOB "
            "NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' "
            "CHECK(length(seller_pubkey)=32)");
        node_db_exec(ndb,
            "ALTER TABLE file_offers ADD COLUMN nonce INTEGER NOT NULL "
            "DEFAULT 0 CHECK(nonce>=0)");
        node_db_exec(ndb,
            "ALTER TABLE file_offers ADD COLUMN issued_unix INTEGER NOT NULL "
            "DEFAULT 0 CHECK(issued_unix>=0)");
        node_db_exec(ndb,
            "ALTER TABLE file_offers ADD COLUMN expires_unix INTEGER NOT NULL "
            "DEFAULT 0 CHECK(expires_unix>=0)");
        node_db_exec(ndb,
            "ALTER TABLE file_offers ADD COLUMN seller_signature BLOB "
            "NOT NULL DEFAULT X'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' "
            "CHECK(length(seller_signature)=64)");
        node_db_exec(ndb,
            "ALTER TABLE file_offers ADD COLUMN offer_id BLOB "
            "NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' "
            "CHECK(length(offer_id)=32)");
        node_db_exec(ndb,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_file_offers_offer_id "
            "ON file_offers(offer_id) WHERE auth_version=1");
        node_db_exec(ndb,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_file_offers_seller_nonce "
            "ON file_offers(seller_pubkey,nonce) WHERE auth_version=1");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_file_offers_expires "
            "ON file_offers(expires_unix) WHERE auth_version=1");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('055')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 55);
        current_ver = 55;
        applied++;
    }

    if (current_ver < 56) {
        /* v56: durable file-market payment claim locators. The exact signed
         * claim and offer wires are retained so restart does not depend on an
         * expiring gossip-cache row. status/height/confirmations are a
         * rebuildable projection only: every paid file request rechecks the
         * canonical transaction + decrypted wallet note authorities. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS market_payment_claims ("
            "claim_id BLOB NOT NULL PRIMARY KEY CHECK(length(claim_id)=32),"
            "offer_id BLOB NOT NULL CHECK(length(offer_id)=32),"
            "txid BLOB NOT NULL CHECK(length(txid)=32),"
            "buyer_pubkey BLOB NOT NULL CHECK(length(buyer_pubkey)=32),"
            "chunk_start INTEGER NOT NULL CHECK(chunk_start>=0),"
            "chunks_paid INTEGER NOT NULL CHECK(chunks_paid>0),"
            "amount_zat INTEGER NOT NULL CHECK(amount_zat>0 AND "
            "amount_zat<=2100000000000000),"
            "claim_wire BLOB NOT NULL CHECK(length(claim_wire)=218),"
            "offer_wire BLOB NOT NULL CHECK(length(offer_wire)=535),"
            "status TEXT NOT NULL CHECK(status IN "
            "('PENDING','CONFIRMED','UNKNOWN','CONFLICTED','REJECTED')),"
            "status_reason TEXT NOT NULL,"
            "output_index INTEGER NOT NULL DEFAULT -1 "
            "CHECK(output_index>=-1),"
            "block_height INTEGER NOT NULL DEFAULT 0 "
            "CHECK(block_height>=0),"
            "confirmations INTEGER NOT NULL DEFAULT 0 "
            "CHECK(confirmations>=0),"
            "observed_at INTEGER NOT NULL CHECK(observed_at>0),"
            "reconciled_at INTEGER NOT NULL DEFAULT 0 "
            "CHECK(reconciled_at>=0))");
        node_db_exec(ndb,
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "idx_market_payment_claim_contract "
            "ON market_payment_claims(offer_id,txid,chunk_start,chunks_paid,"
            "buyer_pubkey)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_market_payment_claim_buyer "
            "ON market_payment_claims(offer_id,buyer_pubkey,status)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_market_payment_claim_txid "
            "ON market_payment_claims(txid)");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('056')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 56);
        current_ver = 56;
        applied++;
    }

    if (current_ver < 57) {
        /* v57: owner-private paid-file content registry. One atomic row binds
         * an authenticated offer_id to the canonical local regular file and
         * its complete bounded chunk-digest manifest. The private path and
         * manifest are never part of the public market projection. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS market_contents ("
            "offer_id BLOB NOT NULL PRIMARY KEY CHECK(length(offer_id)=32),"
            "root_hash BLOB NOT NULL CHECK(length(root_hash)=32),"
            "private_path TEXT NOT NULL "
            "CHECK(length(private_path)>0 AND length(private_path)<4096),"
            "size_bytes INTEGER NOT NULL CHECK(size_bytes>0),"
            "num_chunks INTEGER NOT NULL "
            "CHECK(num_chunks>0 AND num_chunks<=4096),"
            "chunk_hashes BLOB NOT NULL "
            "CHECK(length(chunk_hashes)=num_chunks*32),"
            "registered_at INTEGER NOT NULL CHECK(registered_at>0))"
            " WITHOUT ROWID");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_market_contents_root "
            "ON market_contents(root_hash)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_market_contents_registered "
            "ON market_contents(registered_at DESC)");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('057')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 57);
        current_ver = 57;
        applied++;
    }

    if (current_ver < 58) {
        /* v58: application-bound vault intents. Higher-level transactions
         * (starting with market_purchase) reuse the one wallet reservation
         * authority while gaining durable request idempotency. The request
         * digest contains no address, memo, key, or endpoint; exact private
         * plan material remains inside encrypted_payload. */
        node_db_exec(ndb,
            "ALTER TABLE vault_intents ADD COLUMN application_kind TEXT "
            "NOT NULL DEFAULT '' CHECK(length(application_kind)<=32)");
        node_db_exec(ndb,
            "ALTER TABLE vault_intents ADD COLUMN idempotency_key TEXT "
            "NOT NULL DEFAULT '' CHECK(length(idempotency_key)<=64)");
        node_db_exec(ndb,
            "ALTER TABLE vault_intents ADD COLUMN request_digest BLOB "
            "CHECK(request_digest IS NULL OR length(request_digest)=32)");
        node_db_exec(ndb,
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "idx_vault_intents_application_idempotency "
            "ON vault_intents(wallet_scope,application_kind,idempotency_key) "
            "WHERE application_kind<>'' AND idempotency_key<>''");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('058')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 58);
        current_ver = 58;
        applied++;
    }

    if (current_ver < 59) {
        /* v59: buyer-side paid-file assembly. The destination and same-dir
         * staging paths are operator-private. One parent row owns sequential
         * progress; child rows retain the authenticated digest and exact size
         * of each fsynced chunk so restart can re-verify bytes before resume.
         * No endpoint, buyer credential, address, memo, or wallet secret is
         * duplicated into this resource. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS market_downloads ("
            "plan_id BLOB NOT NULL PRIMARY KEY CHECK(length(plan_id)=32),"
            "offer_id BLOB NOT NULL CHECK(length(offer_id)=32),"
            "root_hash BLOB NOT NULL CHECK(length(root_hash)=32),"
            "private_destination TEXT NOT NULL CHECK("
            "length(private_destination)>0 AND length(private_destination)<4096),"
            "private_staging TEXT NOT NULL CHECK("
            "length(private_staging)>0 AND length(private_staging)<4096),"
            "size_bytes INTEGER NOT NULL CHECK(size_bytes>0),"
            "num_chunks INTEGER NOT NULL CHECK(num_chunks>0 AND num_chunks<=4096),"
            "chunks_received INTEGER NOT NULL DEFAULT 0 CHECK("
            "chunks_received>=0 AND chunks_received<=num_chunks),"
            "bytes_received INTEGER NOT NULL DEFAULT 0 CHECK("
            "bytes_received>=0 AND bytes_received<=size_bytes),"
            "state INTEGER NOT NULL DEFAULT 0 CHECK(state BETWEEN 0 AND 2),"
            "created_at INTEGER NOT NULL CHECK(created_at>0),"
            "updated_at INTEGER NOT NULL CHECK(updated_at>0)) WITHOUT ROWID");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_market_downloads_state "
            "ON market_downloads(state,updated_at DESC)");
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS market_download_chunks ("
            "plan_id BLOB NOT NULL CHECK(length(plan_id)=32),"
            "chunk_index INTEGER NOT NULL CHECK(chunk_index>=0 AND chunk_index<4096),"
            "size_bytes INTEGER NOT NULL CHECK(size_bytes>0 AND size_bytes<=52428800),"
            "chunk_sha3 BLOB NOT NULL CHECK(length(chunk_sha3)=32),"
            "created_at INTEGER NOT NULL CHECK(created_at>0),"
            "PRIMARY KEY(plan_id,chunk_index),"
            "FOREIGN KEY(plan_id) REFERENCES market_downloads(plan_id) "
            "ON DELETE CASCADE) WITHOUT ROWID");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_market_download_chunks_plan "
            "ON market_download_chunks(plan_id,chunk_index)");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('059')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 59);
        current_ver = 59;
        applied++;
    }

    if (current_ver < 60) {
        /* v60: exact input reservations for durable transaction intents.
         * Aggregate ZCL reservations protect the custody budget; this table
         * independently prevents concurrent prepared plans from claiming the
         * same token output, mint baton, or ordinary fee coin. Terminal-plan
         * rows are lazily released inside the next atomic reservation. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS vault_intent_inputs ("
            "plan_id BLOB NOT NULL CHECK(length(plan_id)=32),"
            "txid BLOB NOT NULL CHECK(length(txid)=32),"
            "vout INTEGER NOT NULL CHECK(vout>=0 AND vout<=4294967295),"
            "PRIMARY KEY(plan_id,txid,vout),"
            "UNIQUE(txid,vout),"
            "FOREIGN KEY(plan_id) REFERENCES vault_intents(plan_id) "
            "ON DELETE CASCADE) WITHOUT ROWID");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_vault_intent_inputs_plan "
            "ON vault_intent_inputs(plan_id)");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('060')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 60);
        current_ver = 60;
        applied++;
    }

    if (current_ver < 61) {
        /* v61: isolated wallet-local transaction intents. The broker and
         * agent-session authorities remain dev/prod-only; this widens only
         * the durable vault-intent scope so a pre-funded operator-lane=test
         * wallet can reserve and recover its own exact transaction plans.
         * SQLite cannot ALTER a CHECK constraint, so rebuild the parent
         * table atomically and preserve every existing intent and index. */
        if (!node_db_exec(ndb,
            "PRAGMA foreign_keys=OFF;"
            "BEGIN IMMEDIATE;"
            "CREATE TABLE vault_intents_v61 ("
            "plan_id BLOB PRIMARY KEY CHECK(length(plan_id)=32),"
            "digest BLOB NOT NULL CHECK(length(digest)=32),"
            "state INTEGER NOT NULL DEFAULT 0,"
            "route INTEGER NOT NULL,"
            "created_at INTEGER NOT NULL,"
            "expires_at INTEGER NOT NULL,"
            "anchor_height INTEGER NOT NULL,"
            "anchor_hash BLOB NOT NULL CHECK(length(anchor_hash)=32),"
            "encrypted_payload BLOB NOT NULL,"
            "txid BLOB CHECK(txid IS NULL OR length(txid)=32),"
            "confirm_height INTEGER NOT NULL DEFAULT -1,"
            "confirm_hash BLOB CHECK(confirm_hash IS NULL OR length(confirm_hash)=32),"
            "error_code TEXT NOT NULL DEFAULT '',"
            "updated_at INTEGER NOT NULL,"
            "wallet_scope TEXT NOT NULL DEFAULT '' "
            "CHECK(wallet_scope IN ('','dev','prod','test')),"
            "wallet_instance_id TEXT NOT NULL DEFAULT '' "
            "CHECK(length(wallet_instance_id) IN (0,32)),"
            "wallet_genesis TEXT NOT NULL DEFAULT '' "
            "CHECK(length(wallet_genesis) IN (0,64)),"
            "snapshot_root BLOB "
            "CHECK(snapshot_root IS NULL OR length(snapshot_root)=32),"
            "recipient_value_zat INTEGER NOT NULL DEFAULT 0 "
            "CHECK(recipient_value_zat>=0),"
            "max_fee_zat INTEGER NOT NULL DEFAULT 0 CHECK(max_fee_zat>=0),"
            "reserved_zat INTEGER NOT NULL DEFAULT 0 CHECK(reserved_zat>=0),"
            "application_kind TEXT NOT NULL DEFAULT '' "
            "CHECK(length(application_kind)<=32),"
            "idempotency_key TEXT NOT NULL DEFAULT '' "
            "CHECK(length(idempotency_key)<=64),"
            "request_digest BLOB "
            "CHECK(request_digest IS NULL OR length(request_digest)=32)"
            ") WITHOUT ROWID;"
            "INSERT INTO vault_intents_v61 SELECT * FROM vault_intents;"
            "DROP TABLE vault_intents;"
            "ALTER TABLE vault_intents_v61 RENAME TO vault_intents;"
            "CREATE INDEX idx_vault_intents_state_time "
            "ON vault_intents(state,created_at DESC);"
            "CREATE INDEX idx_vault_intents_wallet_reserve "
            "ON vault_intents(wallet_scope,wallet_instance_id,state);"
            "CREATE UNIQUE INDEX idx_vault_intents_application_idempotency "
            "ON vault_intents(wallet_scope,application_kind,idempotency_key) "
            "WHERE application_kind<>'' AND idempotency_key<>'';"
            "COMMIT;"
            "PRAGMA foreign_keys=ON;")) {
            (void)node_db_exec(ndb, "ROLLBACK;PRAGMA foreign_keys=ON;");
            LOG_ERR("db", "migrate v61: atomic vault-intent rebuild failed");
        }
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('061')"))
            LOG_ERR("db", "migrate v61: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 61);
        current_ver = 61;
        applied++;
    }

    if (current_ver < 62) {
        /* v62: singleton owner file-market seller signing key. The seed rests
         * only as a wallet_metadata_encrypt envelope (passphrase-wrapped DEK,
         * public key as AAD); the public key column is the non-secret signer
         * identity every local paid offer carries. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS market_seller_key ("
            "id INTEGER PRIMARY KEY CHECK(id=1),"
            "encrypted_seed BLOB NOT NULL,"
            "seller_pubkey BLOB NOT NULL CHECK(length(seller_pubkey)=32),"
            "created_at INTEGER NOT NULL CHECK(created_at>0))");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('062')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 62);
        current_ver = 62;
        applied++;
    }

    if (current_ver < 63) {
        /* v63: file-offer wire v2 (onion-routed delivery endpoint). The
         * signed offer gains endpoint_type (0=clearnet, 1=onion) and the
         * seller's Tor v3 onion_pubkey; auth_version 2 marks v2 wires.
         * SQLite cannot ALTER the v55 CHECK(auth_version IN (0,1)), so
         * rebuild the table atomically and preserve every offer and index
         * (the unique indexes widen to IN (1,2)). */
        if (!node_db_exec(ndb,
            "PRAGMA foreign_keys=OFF;"
            "BEGIN IMMEDIATE;"
            "CREATE TABLE file_offers_v63 ("
            "root_hash BLOB NOT NULL PRIMARY KEY,"
            "filename TEXT NOT NULL,"
            "size_bytes INTEGER NOT NULL,"
            "num_chunks INTEGER NOT NULL,"
            "price_per_mb INTEGER NOT NULL,"
            "z_addr BLOB,peer_ip BLOB,peer_port INTEGER,"
            "last_seen INTEGER,ttl INTEGER DEFAULT 4,"
            "auth_version INTEGER NOT NULL DEFAULT 0 "
            "CHECK(auth_version IN (0,1,2)),"
            "network_genesis BLOB NOT NULL "
            "DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' "
            "CHECK(length(network_genesis)=32),"
            "seller_pubkey BLOB NOT NULL "
            "DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' "
            "CHECK(length(seller_pubkey)=32),"
            "nonce INTEGER NOT NULL DEFAULT 0 CHECK(nonce>=0),"
            "issued_unix INTEGER NOT NULL DEFAULT 0 CHECK(issued_unix>=0),"
            "expires_unix INTEGER NOT NULL DEFAULT 0 CHECK(expires_unix>=0),"
            "seller_signature BLOB NOT NULL "
            "DEFAULT X'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' "
            "CHECK(length(seller_signature)=64),"
            "offer_id BLOB NOT NULL "
            "DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' "
            "CHECK(length(offer_id)=32),"
            "endpoint_type INTEGER NOT NULL DEFAULT 0 "
            "CHECK(endpoint_type IN (0,1)),"
            "onion_pubkey BLOB NOT NULL "
            "DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' "
            "CHECK(length(onion_pubkey)=32));"
            "INSERT INTO file_offers_v63 "
            "SELECT root_hash,filename,size_bytes,num_chunks,price_per_mb,"
            "z_addr,peer_ip,peer_port,last_seen,ttl,auth_version,"
            "network_genesis,seller_pubkey,nonce,issued_unix,expires_unix,"
            "seller_signature,offer_id,0,"
            "X'0000000000000000000000000000000000000000000000000000000000000000' "
            "FROM file_offers;"
            "DROP TABLE file_offers;"
            "ALTER TABLE file_offers_v63 RENAME TO file_offers;"
            "CREATE INDEX idx_file_offers_last_seen "
            "ON file_offers(last_seen DESC);"
            "CREATE UNIQUE INDEX idx_file_offers_offer_id "
            "ON file_offers(offer_id) WHERE auth_version IN (1,2);"
            "CREATE UNIQUE INDEX idx_file_offers_seller_nonce "
            "ON file_offers(seller_pubkey,nonce) WHERE auth_version IN (1,2);"
            "CREATE INDEX idx_file_offers_expires "
            "ON file_offers(expires_unix) WHERE auth_version IN (1,2);"
            "COMMIT;"
            "PRAGMA foreign_keys=ON;")) {
            (void)node_db_exec(ndb, "ROLLBACK;PRAGMA foreign_keys=ON;");
            LOG_ERR("db", "migrate v63: atomic file-offer rebuild failed");
        }
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('063')"))
            LOG_ERR("db", "migrate v63: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 63);
        current_ver = 63;
        applied++;
    }

    if (current_ver < 64) {
        /* v64: widen the market_payment_claims offer_wire CHECK for v2
         * (onion-endpoint) offers. v56 pinned length(offer_wire)=535 —
         * the v1 wire — before v2 wires existed; v63 introduced the 568-byte
         * v2 offer wire (FILE_MARKET_OFFER_WIRE_BYTES_V2) but only rebuilt
         * file_offers, so every claim INSERT for an onion offer failed the
         * CHECK and the seller silently never persisted the claim (delivery
         * authorization then sat at PENDING forever: no claim candidates).
         * SQLite cannot ALTER a CHECK, so rebuild atomically, preserving
         * every row and index (no stored row can violate the new CHECK:
         * the old one was strictly tighter). */
        if (!node_db_exec(ndb,
            "PRAGMA foreign_keys=OFF;"
            "BEGIN IMMEDIATE;"
            "CREATE TABLE market_payment_claims_v64 ("
            "claim_id BLOB NOT NULL PRIMARY KEY CHECK(length(claim_id)=32),"
            "offer_id BLOB NOT NULL CHECK(length(offer_id)=32),"
            "txid BLOB NOT NULL CHECK(length(txid)=32),"
            "buyer_pubkey BLOB NOT NULL CHECK(length(buyer_pubkey)=32),"
            "chunk_start INTEGER NOT NULL CHECK(chunk_start>=0),"
            "chunks_paid INTEGER NOT NULL CHECK(chunks_paid>0),"
            "amount_zat INTEGER NOT NULL CHECK(amount_zat>0 AND "
            "amount_zat<=2100000000000000),"
            "claim_wire BLOB NOT NULL CHECK(length(claim_wire)=218),"
            "offer_wire BLOB NOT NULL "
            "CHECK(length(offer_wire) IN (535,568)),"
            "status TEXT NOT NULL CHECK(status IN "
            "('PENDING','CONFIRMED','UNKNOWN','CONFLICTED','REJECTED')),"
            "status_reason TEXT NOT NULL,"
            "output_index INTEGER NOT NULL DEFAULT -1 "
            "CHECK(output_index>=-1),"
            "block_height INTEGER NOT NULL DEFAULT 0 "
            "CHECK(block_height>=0),"
            "confirmations INTEGER NOT NULL DEFAULT 0 "
            "CHECK(confirmations>=0),"
            "observed_at INTEGER NOT NULL CHECK(observed_at>0),"
            "reconciled_at INTEGER NOT NULL DEFAULT 0 "
            "CHECK(reconciled_at>=0));"
            "INSERT INTO market_payment_claims_v64 "
            "SELECT claim_id,offer_id,txid,buyer_pubkey,chunk_start,"
            "chunks_paid,amount_zat,claim_wire,offer_wire,status,"
            "status_reason,output_index,block_height,confirmations,"
            "observed_at,reconciled_at FROM market_payment_claims;"
            "DROP TABLE market_payment_claims;"
            "ALTER TABLE market_payment_claims_v64 "
            "RENAME TO market_payment_claims;"
            "CREATE UNIQUE INDEX idx_market_payment_claim_contract "
            "ON market_payment_claims(offer_id,txid,chunk_start,chunks_paid,"
            "buyer_pubkey);"
            "CREATE INDEX idx_market_payment_claim_buyer "
            "ON market_payment_claims(offer_id,buyer_pubkey,status);"
            "CREATE INDEX idx_market_payment_claim_txid "
            "ON market_payment_claims(txid);"
            "COMMIT;"
            "PRAGMA foreign_keys=ON;")) {
            (void)node_db_exec(ndb, "ROLLBACK;PRAGMA foreign_keys=ON;");
            LOG_ERR("db", "migrate v64: atomic payment-claim rebuild failed");
        }
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('064')"))
            LOG_ERR("db", "migrate v64: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 64);
        current_ver = 64;
        applied++;
    }

    if (current_ver < 65) {
        /* v65: per-node listing moderation. review_state is LOCAL-ONLY
         * curation metadata (unreviewed at ingest, reviewed_ok / sensitive
         * after the node's own zmarket_review_set). It is never gossiped
         * and never enters the signed offer wire — a hidden offer is still
         * stored, served, and tradable. ADD COLUMN is enough (no CHECK
         * widening), so no table rebuild; the constant default backfills
         * every existing row as unreviewed. */
        if (!node_db_exec(ndb,
                "ALTER TABLE file_offers ADD COLUMN review_state TEXT "
                "NOT NULL DEFAULT 'unreviewed' CHECK(review_state IN "
                "('unreviewed','reviewed_ok','sensitive'))"))
            LOG_ERR("db", "migrate v65: file_offers review_state failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('065')"))
            LOG_ERR("db", "migrate v65: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 65);
        current_ver = 65;
        applied++;
    }

    if (current_ver < 66) {
        /* v66: shop WANT ads (docs/work/SHOP_COMMAND.md slice D) — the
         * demand-side mirror of the signed offer: a buyer-posted,
         * Ed25519-signed "I will pay amount_zatoshi for a digital result
         * satisfying these criteria" advertisement. want_id commits the
         * full signed wire; wire is the exact bytes the buyer signed
         * (stored because they verified at ingress). Declared terms only —
         * no escrow, no payment channel, ZC23/ZCL transfer stays
         * simulation/plan-only. review_state is LOCAL-ONLY curation
         * metadata with the identical semantics of the v65 file_offers
         * column (community content moderation; never gossiped, never part
         * of the signed wire, a hidden want stays stored); cancelled_unix
         * marks the buyer's own key-checked cancellation. Closed rows are
         * filtered from the open board, never deleted. */
        if (!node_db_exec(ndb,
                "CREATE TABLE IF NOT EXISTS shop_wants("
                "want_id BLOB PRIMARY KEY CHECK(length(want_id)=32),"
                "wire BLOB NOT NULL,"
                "buyer_pubkey BLOB NOT NULL CHECK(length(buyer_pubkey)=32),"
                "amount_zatoshi INTEGER NOT NULL CHECK(amount_zatoshi>0),"
                "criteria TEXT NOT NULL,"
                "spec_hash BLOB NOT NULL CHECK(length(spec_hash)=32),"
                "issued_unix INTEGER NOT NULL CHECK(issued_unix>0),"
                "expires_unix INTEGER NOT NULL CHECK(expires_unix>issued_unix),"
                "review_state TEXT NOT NULL DEFAULT 'unreviewed' "
                "CHECK(review_state IN "
                "('unreviewed','reviewed_ok','sensitive')),"
                "cancelled_unix INTEGER NOT NULL DEFAULT 0 "
                "CHECK(cancelled_unix>=0),"
                "posted_unix INTEGER NOT NULL CHECK(posted_unix>0))"))
            LOG_ERR("db", "migrate v66: shop_wants table failed");
        if (!node_db_exec(ndb,
                "CREATE INDEX IF NOT EXISTS idx_shop_wants_buyer "
                "ON shop_wants(buyer_pubkey)"))
            LOG_ERR("db", "migrate v66: shop_wants buyer index failed");
        if (!node_db_exec(ndb,
                "CREATE INDEX IF NOT EXISTS idx_shop_wants_board "
                "ON shop_wants(expires_unix,cancelled_unix,posted_unix)"))
            LOG_ERR("db", "migrate v66: shop_wants board index failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('066')"))
            LOG_ERR("db", "migrate v66: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 66);
        current_ver = 66;
        applied++;
    }

    *version = current_ver;
    return applied + node_db_migrate_features_v67_up(ndb, version);
}
