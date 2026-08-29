/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * App-feature schema migrations v67+, split at the E1 file-size ceiling.
 * ar-validate-skip:connection-handle-not-a-row */

#include "models/database.h"
#include "models/database_internal.h"

static bool mesh_capability_v79_present(struct node_db *ndb)
{
    const char *type = NULL;
    return ndb && ndb->open &&
           sqlite3_table_column_metadata(
               ndb->db, NULL, "mesh_capability_grants",
               "target_master_pubkey", &type, NULL, NULL, NULL, NULL) ==
               SQLITE_OK;
}

int node_db_migrate_features_v67_up(struct node_db *ndb, int *version)
{
    int applied = 0;
    int current_ver = *version;
    if (current_ver < 67) {
        /* v67: signed seller claims bound to a want, direct artifact SHA3,
         * content.v2 CAS root, and optional node-verifiable receipts. This
         * is evidence only: no award, escrow, ZCL movement, or ZC23 issuance.
         * review_state and withdrawn_unix are local-only projection state. */
        if (!node_db_exec(ndb,
                "CREATE TABLE IF NOT EXISTS shop_fulfills("
                "fulfill_id BLOB PRIMARY KEY CHECK(length(fulfill_id)=32),"
                "want_id BLOB NOT NULL CHECK(length(want_id)=32),"
                "wire BLOB NOT NULL CHECK(length(wire)=322),"
                "seller_pubkey BLOB NOT NULL CHECK(length(seller_pubkey)=32),"
                "nonce INTEGER NOT NULL CHECK(nonce>0),"
                "artifact_root BLOB NOT NULL CHECK(length(artifact_root)=32),"
                "content_root BLOB NOT NULL CHECK(length(content_root)=32),"
                "build_receipt_id BLOB NOT NULL "
                "CHECK(length(build_receipt_id)=32),"
                "fuzz_receipt_id BLOB NOT NULL "
                "CHECK(length(fuzz_receipt_id)=32),"
                "bench_receipt_id BLOB NOT NULL "
                "CHECK(length(bench_receipt_id)=32),"
                "issued_unix INTEGER NOT NULL CHECK(issued_unix>0),"
                "expires_unix INTEGER NOT NULL CHECK(expires_unix>issued_unix),"
                "review_state TEXT NOT NULL DEFAULT 'unreviewed' "
                "CHECK(review_state IN "
                "('unreviewed','reviewed_ok','sensitive')),"
                "withdrawn_unix INTEGER NOT NULL DEFAULT 0 "
                "CHECK(withdrawn_unix>=0),"
                "posted_unix INTEGER NOT NULL CHECK(posted_unix>0))"))
            LOG_ERR("db", "migrate v67: shop_fulfills table failed");
        if (!node_db_exec(ndb,
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "idx_shop_fulfills_seller_nonce "
                "ON shop_fulfills(seller_pubkey,nonce)"))
            LOG_ERR("db", "migrate v67: seller nonce index failed");
        if (!node_db_exec(ndb,
                "CREATE INDEX IF NOT EXISTS idx_shop_fulfills_want "
                "ON shop_fulfills(want_id,posted_unix DESC)"))
            LOG_ERR("db", "migrate v67: want index failed");
        if (!node_db_exec(ndb,
                "CREATE INDEX IF NOT EXISTS idx_shop_fulfills_open "
                "ON shop_fulfills(want_id,expires_unix,withdrawn_unix)"))
            LOG_ERR("db", "migrate v67: open index failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('067')"))
            LOG_ERR("db", "migrate v67: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 67);
        current_ver = 67;
        applied++;
    }
    if (current_ver < 68) {
        /* v68: append-only requester-local async proof events. Existing
         * build_actions remain the exact work identity; signed work_receipts
         * remain evidence authority. This table is a rebuildable, root-bound
         * lifecycle projection and grants neither acceptance nor publication. */
        if (!node_db_exec(ndb,
                "CREATE TABLE IF NOT EXISTS build_proof_events("
                "event_root TEXT NOT NULL UNIQUE CHECK(length(event_root)=64),"
                "prior_event_root TEXT NOT NULL DEFAULT '' "
                "CHECK(length(prior_event_root) IN (0,64)),"
                "action_id TEXT NOT NULL REFERENCES build_actions(action_id) "
                "ON DELETE CASCADE CHECK(length(action_id)=64),"
                "task_root_sha3 TEXT NOT NULL CHECK(length(task_root_sha3)=64),"
                "candidate_root_sha3 TEXT NOT NULL "
                "CHECK(length(candidate_root_sha3)=64),"
                "proof_policy_root_sha3 TEXT NOT NULL "
                "CHECK(length(proof_policy_root_sha3)=64),"
                "context_root_sha3 TEXT NOT NULL DEFAULT '' "
                "CHECK(length(context_root_sha3) IN (0,64)),"
                "receipt_root_sha3 TEXT NOT NULL DEFAULT '' "
                "CHECK(length(receipt_root_sha3) IN (0,64)),"
                "workspace TEXT NOT NULL CHECK(length(workspace) BETWEEN 1 AND 4095),"
                "state TEXT NOT NULL CHECK(state IN ('REQUESTED',"
                "'PEER_DISCOVERED','CONTEXT_READY','RUNNING','REMOTE_GREEN','REMOTE_RED',"
                "'RECEIPT_VERIFIED','REPRODUCED','SUPERSEDED',"
                "'READY_FOR_ACCEPTANCE')),"
                "peer_id INTEGER NOT NULL CHECK(peer_id>=0),"
                "request_id BLOB NOT NULL CHECK(length(request_id)=8),"
                "deadline_at INTEGER NOT NULL CHECK(deadline_at>=0),"
                "elapsed_us INTEGER NOT NULL CHECK(elapsed_us>=0),"
                "created_at INTEGER NOT NULL CHECK(created_at>0))"))
            LOG_ERR("db", "migrate v68: build_proof_events table failed");
        if (!node_db_exec(ndb,
                "CREATE INDEX IF NOT EXISTS idx_build_proof_events_action "
                "ON build_proof_events(action_id,created_at,event_root)"))
            LOG_ERR("db", "migrate v68: action event index failed");
        if (!node_db_exec(ndb,
                "CREATE INDEX IF NOT EXISTS idx_build_proof_events_task "
                "ON build_proof_events(task_root_sha3,created_at)"))
            LOG_ERR("db", "migrate v68: task event index failed");
        if (!node_db_exec(ndb,
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "idx_build_proof_events_one_successor "
                "ON build_proof_events(prior_event_root) "
                "WHERE prior_event_root<>''"))
            LOG_ERR("db", "migrate v68: event chain index failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('068')"))
            LOG_ERR("db", "migrate v68: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 68);
        current_ver = 68;
        applied++;
    }
    if (current_ver < 69) {
        /* v69: new async events bind the candidate source root directly.
         * Existing v68 rows retain their v1 event roots and an empty source;
         * the next append upgrades that chain to the v2 root domain. */
        if (!node_db_exec(ndb,
                "CREATE TABLE build_proof_events_v69("
                "event_root TEXT NOT NULL UNIQUE CHECK(length(event_root)=64),"
                "prior_event_root TEXT NOT NULL DEFAULT '' "
                "CHECK(length(prior_event_root) IN (0,64)),"
                "action_id TEXT NOT NULL REFERENCES build_actions(action_id) "
                "ON DELETE CASCADE CHECK(length(action_id)=64),"
                "source_root_sha3 TEXT NOT NULL DEFAULT '' "
                "CHECK(length(source_root_sha3) IN (0,64)),"
                "task_root_sha3 TEXT NOT NULL CHECK(length(task_root_sha3)=64),"
                "candidate_root_sha3 TEXT NOT NULL CHECK(length(candidate_root_sha3)=64),"
                "proof_policy_root_sha3 TEXT NOT NULL CHECK(length(proof_policy_root_sha3)=64),"
                "context_root_sha3 TEXT NOT NULL DEFAULT '' "
                "CHECK(length(context_root_sha3) IN (0,64)),"
                "receipt_root_sha3 TEXT NOT NULL DEFAULT '' "
                "CHECK(length(receipt_root_sha3) IN (0,64)),"
                "workspace TEXT NOT NULL CHECK(length(workspace) BETWEEN 1 AND 4095),"
                "state TEXT NOT NULL CHECK(state IN ('REQUESTED','PEER_DISCOVERED',"
                "'CONTEXT_READY','RUNNING','REMOTE_GREEN','REMOTE_RED',"
                "'RECEIPT_VERIFIED','REPRODUCED','SUPERSEDED',"
                "'READY_FOR_ACCEPTANCE')),"
                "peer_id INTEGER NOT NULL CHECK(peer_id>=0),"
                "request_id BLOB NOT NULL CHECK(length(request_id)=8),"
                "deadline_at INTEGER NOT NULL CHECK(deadline_at>=0),"
                "elapsed_us INTEGER NOT NULL CHECK(elapsed_us>=0),"
                "created_at INTEGER NOT NULL CHECK(created_at>0))"))
            LOG_ERR("db", "migrate v69: replacement table failed");
        if (!node_db_exec(ndb,
                "INSERT INTO build_proof_events_v69 "
                "(event_root,prior_event_root,action_id,source_root_sha3,"
                "task_root_sha3,candidate_root_sha3,proof_policy_root_sha3,"
                "context_root_sha3,receipt_root_sha3,workspace,state,peer_id,"
                "request_id,deadline_at,elapsed_us,created_at) SELECT "
                "event_root,prior_event_root,action_id,'',task_root_sha3,"
                "candidate_root_sha3,proof_policy_root_sha3,context_root_sha3,"
                "receipt_root_sha3,workspace,state,peer_id,request_id,"
                "deadline_at,elapsed_us,created_at FROM build_proof_events"))
            LOG_ERR("db", "migrate v69: event copy failed");
        if (!node_db_exec(ndb, "DROP TABLE build_proof_events"))
            LOG_ERR("db", "migrate v69: prior table drop failed");
        if (!node_db_exec(ndb,
                "ALTER TABLE build_proof_events_v69 RENAME TO build_proof_events"))
            LOG_ERR("db", "migrate v69: table rename failed");
        if (!node_db_exec(ndb,
                "CREATE INDEX idx_build_proof_events_action ON "
                "build_proof_events(action_id,created_at,event_root)"))
            LOG_ERR("db", "migrate v69: action index failed");
        if (!node_db_exec(ndb,
                "CREATE INDEX idx_build_proof_events_task ON "
                "build_proof_events(task_root_sha3,created_at)"))
            LOG_ERR("db", "migrate v69: task index failed");
        if (!node_db_exec(ndb,
                "CREATE UNIQUE INDEX idx_build_proof_events_one_successor "
                "ON build_proof_events(prior_event_root) "
                "WHERE prior_event_root<>''"))
            LOG_ERR("db", "migrate v69: chain index failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('069')"))
            LOG_ERR("db", "migrate v69: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 69);
        current_ver = 69;
        applied++;
    }
    if (current_ver < 70) {
        /* v70: a worker result is quarantined together with the canonical
         * physical execution observation it names. The receipt remains in
         * the existing ledger and the bytes remain in the existing CAS;
         * this column adds no scheduler or cache authority. Empty preserves
         * historical v2 receipts, which cannot satisfy secure admission. */
        if (!node_db_exec(ndb,
                "ALTER TABLE build_receipts ADD COLUMN "
                "observation_sha3 TEXT NOT NULL DEFAULT '' "
                "CHECK(length(observation_sha3) IN (0,64))"))
            LOG_ERR("db", "migrate v70: observation root failed");
        if (!node_db_exec(ndb,
                "CREATE INDEX IF NOT EXISTS "
                "idx_build_receipts_action_observation "
                "ON build_receipts(action_id,observation_sha3,created_at)"))
            LOG_ERR("db", "migrate v70: observation index failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('070')"))
            LOG_ERR("db", "migrate v70: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 70);
        current_ver = 70;
        applied++;
    }
    if (current_ver < 71) {
        /* v71: the last verified encrypted wallet backup survives a process
         * restart as a byte-bound receipt. This is custody readiness evidence,
         * not a substitute for the external backup itself: startup reopens and
         * hashes the named regular file before restoring authority. */
        if (!node_db_exec(ndb,
                "CREATE TABLE IF NOT EXISTS wallet_backup_receipts("
                "singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),"
                "completed_unix INTEGER NOT NULL CHECK(completed_unix>0),"
                "key_count INTEGER NOT NULL CHECK(key_count>=0),"
                "tables_verified INTEGER NOT NULL CHECK(tables_verified>0),"
                "size_bytes INTEGER NOT NULL CHECK(size_bytes>0),"
                "file_sha3 BLOB NOT NULL CHECK(length(file_sha3)=32),"
                "backup_path TEXT NOT NULL CHECK(length(backup_path) BETWEEN 1 AND 511))"))
            LOG_ERR("db", "migrate v71: wallet backup receipt table failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('071')"))
            LOG_ERR("db", "migrate v71: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 71);
        current_ver = 71;
        applied++;
    }
    if (current_ver < 72) {
        /* v72: unused transparent change keys are durable state. Private key
         * rows alone cannot distinguish an unused keypool entry from an
         * already-issued receive/change key after restart. */
        if (!node_db_exec(ndb,
                "CREATE TABLE IF NOT EXISTS wallet_keypool("
                "pubkey_hash BLOB PRIMARY KEY CHECK(length(pubkey_hash)=20),"
                "generation INTEGER NOT NULL UNIQUE CHECK(generation>=0),"
                "FOREIGN KEY(pubkey_hash) REFERENCES wallet_keys(pubkey_hash) "
                "ON DELETE CASCADE)"))
            LOG_ERR("db", "migrate v72: wallet keypool table failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('072')"))
            LOG_ERR("db", "migrate v72: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 72);
        current_ver = 72;
        applied++;
    }
    if (current_ver < 73) {
        /* v73: bind a bounded agent grant to the canonical durable intent and
         * remember its exact once-only debit across crashes/retries. The full
         * bearer id never leaves node.db after the local CLI presents it. */
        if (!node_db_exec(ndb,
                "ALTER TABLE vault_intents ADD COLUMN agent_session_id "
                "TEXT NOT NULL DEFAULT '' CHECK(length(agent_session_id) "
                "IN (0,32))"))
            LOG_ERR("db", "migrate v73: intent agent binding failed");
        if (!node_db_exec(ndb,
                "ALTER TABLE vault_intents ADD COLUMN agent_debited_zat "
                "INTEGER NOT NULL DEFAULT 0 CHECK(agent_debited_zat>=0)"))
            LOG_ERR("db", "migrate v73: intent debit marker failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('073')"))
            LOG_ERR("db", "migrate v73: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 73);
        current_ver = 73;
        applied++;
    }
    if (current_ver < 74) {
        /* v74: an owner-minted dev grant may narrow the generic custody
         * policy to an explicit wallet floor. Existing grants retain the
         * historical 0.25-ZCL floor; only a newly confirmed grant can name a
         * different floor, and every grant remains wallet-identity bound. */
        if (!node_db_exec(ndb,
                "ALTER TABLE agent_sessions ADD COLUMN reserve_floor_zat "
                "INTEGER NOT NULL DEFAULT 25000000 "
                "CHECK(reserve_floor_zat>=0 AND "
                "reserve_floor_zat<=2100000000000000)"))
            LOG_ERR("db", "migrate v74: session reserve floor failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('074')"))
            LOG_ERR("db", "migrate v74: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 74);
        current_ver = 74;
        applied++;
    }
    if (current_ver < 75) {
        /* v75: an in-flight Yardsale confirmation is durable before its
         * outbound accept can leave the node. ARMING is intentionally sticky
         * across an uncertain process exit, preventing automatic replay. */
        if (!node_db_exec(ndb,
                "CREATE TABLE yardsale_plans_v75("
                "plan_root TEXT PRIMARY KEY CHECK(length(plan_root)=64),"
                "kind TEXT NOT NULL CHECK(kind IN ('arm','buy')),"
                "request_hash TEXT NOT NULL UNIQUE CHECK(length(request_hash)=64),"
                "payload_hex TEXT NOT NULL,result TEXT NOT NULL,"
                "state TEXT NOT NULL CHECK(state IN "
                "('PLANNED','ARMING','COMMITTED','EXPIRED')),"
                "expires_unix INTEGER NOT NULL CHECK(expires_unix>0),"
                "created_at INTEGER NOT NULL)"))
            LOG_ERR("db", "migrate v75: replacement table failed");
        if (!node_db_exec(ndb,
                "INSERT INTO yardsale_plans_v75 SELECT * FROM yardsale_plans"))
            LOG_ERR("db", "migrate v75: plan copy failed");
        if (!node_db_exec(ndb, "DROP TABLE yardsale_plans"))
            LOG_ERR("db", "migrate v75: prior table drop failed");
        if (!node_db_exec(ndb,
                "ALTER TABLE yardsale_plans_v75 RENAME TO yardsale_plans"))
            LOG_ERR("db", "migrate v75: replacement rename failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('075')"))
            LOG_ERR("db", "migrate v75: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 75);
        current_ver = 75;
        applied++;
    }
    if (current_ver < 76) {
        /* v76: private local machine-pairing authority. The record binds one
         * network, active ZID master, persistent Noise static key, narrow
         * capability mask, expiry, and sticky revocation generation. It holds
         * public identity only and is never published to the DHT or Commons. */
        if (!node_db_exec(ndb,
                "CREATE TABLE IF NOT EXISTS mesh_pairings("
                "pairing_id TEXT PRIMARY KEY CHECK(length(pairing_id)=64),"
                "network_genesis BLOB NOT NULL CHECK(length(network_genesis)=32),"
                "peer_master_pubkey BLOB NOT NULL "
                "CHECK(length(peer_master_pubkey)=32),"
                "peer_noise_pubkey BLOB NOT NULL "
                "CHECK(length(peer_noise_pubkey)=32),"
                "capability_mask INTEGER NOT NULL CHECK(capability_mask>0),"
                "delegation_sequence INTEGER NOT NULL "
                "CHECK(delegation_sequence>0),"
                "paired_at INTEGER NOT NULL CHECK(paired_at>0),"
                "expires_at INTEGER NOT NULL CHECK(expires_at>paired_at),"
                "revoked_at INTEGER NOT NULL DEFAULT 0 CHECK(revoked_at>=0),"
                "revocation_generation INTEGER NOT NULL DEFAULT 0 "
                "CHECK(revocation_generation>=0),"
                "UNIQUE(network_genesis,peer_master_pubkey,peer_noise_pubkey))"))
            LOG_ERR("db", "migrate v76: mesh_pairings table failed");
        if (!node_db_exec(ndb,
                "CREATE INDEX IF NOT EXISTS idx_mesh_pairings_active "
                "ON mesh_pairings(revoked_at,expires_at)"))
            LOG_ERR("db", "migrate v76: mesh_pairings index failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('076')"))
            LOG_ERR("db", "migrate v76: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 76);
        current_ver = 76;
        applied++;
    }
    if (current_ver < 77) {
        /* v77: latest exact signed status evidence for each private local
         * pairing. This is an observational projection, never authority. */
        if (!node_db_exec(ndb,
                "CREATE TABLE IF NOT EXISTS mesh_machine_observations("
                "pairing_id TEXT PRIMARY KEY REFERENCES mesh_pairings(pairing_id) "
                "ON DELETE CASCADE CHECK(length(pairing_id)=64),"
                "receipt_wire BLOB NOT NULL "
                "CHECK(length(receipt_wire) BETWEEN 400 AND 4496),"
                "receipt_root BLOB NOT NULL CHECK(length(receipt_root)=32),"
                "status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 9),"
                "observed_unix INTEGER NOT NULL CHECK(observed_unix>0),"
                "expires_unix INTEGER NOT NULL CHECK(expires_unix>observed_unix),"
                "received_unix INTEGER NOT NULL CHECK(received_unix>0))"))
            LOG_ERR("db", "migrate v77: mesh machine observations failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('077')"))
            LOG_ERR("db", "migrate v77: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 77);
        current_ver = 77;
        applied++;
    }
    if (current_ver < 78) {
        /* v78: exact, insert-only private-object receive grants. Pairing is
         * the subject authority; one-use consumption and sticky revocation
         * remain durable across retries and process restarts. */
        if (!node_db_exec(ndb,
                "CREATE TABLE IF NOT EXISTS mesh_capability_grants("
                "grant_id TEXT PRIMARY KEY CHECK(length(grant_id)=64),"
                "pairing_id TEXT NOT NULL REFERENCES mesh_pairings(pairing_id) "
                "ON DELETE CASCADE CHECK(length(pairing_id)=64),"
                "operation INTEGER NOT NULL CHECK(operation=1),"
                "plaintext_root BLOB NOT NULL CHECK(length(plaintext_root)=32),"
                "ciphertext_root BLOB NOT NULL CHECK(length(ciphertext_root)=32),"
                "object_size_bytes INTEGER NOT NULL CHECK(object_size_bytes BETWEEN 1 AND 1073741824),"
                "ciphertext_size_bytes INTEGER NOT NULL CHECK(ciphertext_size_bytes>=object_size_bytes AND ciphertext_size_bytes<=2147483648),"
                "storage_limit_bytes INTEGER NOT NULL CHECK(storage_limit_bytes>=ciphertext_size_bytes AND storage_limit_bytes<=2147483648),"
                "transfer_limit_bytes INTEGER NOT NULL CHECK(transfer_limit_bytes>=ciphertext_size_bytes AND transfer_limit_bytes<=2147483648),"
                "chunk_limit INTEGER NOT NULL CHECK(chunk_limit BETWEEN 1 AND 4096),"
                "max_chunk_bytes INTEGER NOT NULL CHECK(max_chunk_bytes BETWEEN 1 AND 4194304),"
                "wall_limit_seconds INTEGER NOT NULL CHECK(wall_limit_seconds BETWEEN 1 AND 86400),"
                "nonce BLOB NOT NULL CHECK(length(nonce)=32),"
                "deny_mask INTEGER NOT NULL CHECK(deny_mask=63),"
                "issued_at INTEGER NOT NULL CHECK(issued_at>0),"
                "not_before INTEGER NOT NULL CHECK(not_before>=issued_at),"
                "expires_at INTEGER NOT NULL CHECK(expires_at>not_before AND expires_at-issued_at<=2592000),"
                "consumed_at INTEGER NOT NULL DEFAULT 0 CHECK(consumed_at=0 OR (consumed_at>=not_before AND consumed_at<expires_at)),"
                "revoked_at INTEGER NOT NULL DEFAULT 0 CHECK(revoked_at=0 OR revoked_at>=issued_at),"
                "revocation_generation INTEGER NOT NULL DEFAULT 0 CHECK((revoked_at=0 AND revocation_generation=0) OR (revoked_at>0 AND revocation_generation>0)),"
                "CHECK(chunk_limit*max_chunk_bytes>=ciphertext_size_bytes))"))
            LOG_ERR("db", "migrate v78: mesh capability grants failed");
        if (!node_db_exec(ndb,
                "CREATE INDEX IF NOT EXISTS "
                "idx_mesh_capability_grants_pairing_state ON "
                "mesh_capability_grants(pairing_id,revoked_at,consumed_at,expires_at)"))
            LOG_ERR("db", "migrate v78: mesh capability grant index failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('078')"))
            LOG_ERR("db", "migrate v78: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 78);
        current_ver = 78;
        applied++;
    }
    if (current_ver < 79) {
        /* v79: v78 grants never named the receiving machine and consumed at
         * offer time, so they cannot safely cross the transport boundary.
         * Preserve them in a retired audit table and create fail-closed v2
         * authority with canonical sealed geometry and resumable claims. A
         * fresh baseline already has the v79 shape and skips replacement. */
        if (!mesh_capability_v79_present(ndb)) {
            if (!node_db_exec(ndb,
                    "DROP INDEX IF EXISTS "
                    "idx_mesh_capability_grants_pairing_state"))
                LOG_ERR("db", "migrate v79: prior grant index drop failed");
            if (!node_db_exec(ndb,
                    "ALTER TABLE mesh_capability_grants RENAME TO "
                    "mesh_capability_grants_v78_retired"))
                LOG_ERR("db", "migrate v79: prior grant retirement failed");
            if (!node_db_exec(ndb,
                    "CREATE TABLE mesh_capability_grants("
                    "grant_id TEXT PRIMARY KEY CHECK(length(grant_id)=64),"
                    "pairing_id TEXT NOT NULL REFERENCES mesh_pairings(pairing_id) "
                    "ON DELETE CASCADE CHECK(length(pairing_id)=64),"
                    "target_master_pubkey BLOB NOT NULL CHECK(length(target_master_pubkey)=32),"
                    "target_noise_static BLOB NOT NULL CHECK(length(target_noise_static)=32),"
                    "operation INTEGER NOT NULL CHECK(operation=1),"
                    "plaintext_root BLOB NOT NULL CHECK(length(plaintext_root)=32),"
                    "ciphertext_root BLOB NOT NULL CHECK(length(ciphertext_root)=32),"
                    "object_size_bytes INTEGER NOT NULL CHECK(object_size_bytes BETWEEN 1 AND 1073741824),"
                    "ciphertext_size_bytes INTEGER NOT NULL CHECK(ciphertext_size_bytes<=2147483648),"
                    "storage_limit_bytes INTEGER NOT NULL CHECK(storage_limit_bytes>=ciphertext_size_bytes+object_size_bytes AND storage_limit_bytes<=3221225472),"
                    "transfer_limit_bytes INTEGER NOT NULL CHECK(transfer_limit_bytes>=ciphertext_size_bytes AND transfer_limit_bytes<=2147483648),"
                    "max_chunk_bytes INTEGER NOT NULL CHECK(max_chunk_bytes=65536),"
                    "chunk_count INTEGER NOT NULL CHECK(chunk_count BETWEEN 1 AND 16389),"
                    "wall_limit_seconds INTEGER NOT NULL CHECK(wall_limit_seconds BETWEEN 1 AND 600),"
                    "nonce BLOB NOT NULL CHECK(length(nonce)=32),"
                    "deny_mask INTEGER NOT NULL CHECK(deny_mask=255),"
                    "issued_at INTEGER NOT NULL CHECK(issued_at>0),"
                    "not_before INTEGER NOT NULL CHECK(not_before>=issued_at),"
                    "expires_at INTEGER NOT NULL CHECK(expires_at>not_before AND expires_at-issued_at<=2592000),"
                    "transfer_id BLOB NOT NULL DEFAULT X'' CHECK(length(transfer_id) IN (0,32)),"
                    "claimed_at INTEGER NOT NULL DEFAULT 0 CHECK(claimed_at>=0),"
                    "consumed_at INTEGER NOT NULL DEFAULT 0 CHECK(consumed_at>=0),"
                    "revoked_at INTEGER NOT NULL DEFAULT 0 CHECK(revoked_at=0 OR revoked_at>=issued_at),"
                    "revocation_generation INTEGER NOT NULL DEFAULT 0 CHECK((revoked_at=0 AND revocation_generation=0) OR (revoked_at>0 AND revocation_generation>0)),"
                    "CHECK(chunk_count=(object_size_bytes+65519)/65520),"
                    "CHECK(ciphertext_size_bytes=object_size_bytes+16*chunk_count),"
                    "CHECK((claimed_at=0 AND length(transfer_id)=0 AND consumed_at=0) OR (claimed_at>=not_before AND claimed_at<expires_at AND length(transfer_id)=32 AND (consumed_at=0 OR (consumed_at>=claimed_at AND consumed_at<expires_at)))))"))
                LOG_ERR("db", "migrate v79: corrected grants table failed");
        }
        if (!node_db_exec(ndb,
                "CREATE INDEX IF NOT EXISTS "
                "idx_mesh_capability_grants_pairing_state ON "
                "mesh_capability_grants(pairing_id,revoked_at,consumed_at,expires_at)"))
            LOG_ERR("db", "migrate v79: grant state index failed");
        if (!node_db_exec(ndb,
                "INSERT OR IGNORE INTO schema_migrations(version) "
                "VALUES('079')"))
            LOG_ERR("db", "migrate v79: migration stamp failed");
        DB_MIGRATE_PERSIST_VERSION(ndb, 79);
        current_ver = 79;
        applied++;
    }
    *version = current_ver;
    return applied;
}
