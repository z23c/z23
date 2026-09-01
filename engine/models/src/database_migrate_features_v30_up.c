/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * App-feature schema migrations v30+ for node.db — continuation of
 * database_migrate_features.c (E1 file-size split; same idempotent
 * versioned-block pattern documented at the top of that file and in
 * database_migrate.c). node_db_migrate_features() hands off here at the
 * v30 boundary via node_db_migrate_features_v30_up().
 *
 * ar-validate-skip:connection-handle-not-a-row
 *   Same rationale as database_migrate_features.c: operates on the
 *   struct node_db connection handle + schema_migrations bookkeeping,
 *   never a row record. */

#include "models/database.h"
#include "models/database_internal.h"

int node_db_migrate_features_v30_up(struct node_db *ndb, int *version)
{
    int applied = 0;
    int current_ver = *version;

    if (current_ver < 30) {
        /* v30: ZCL Anchors (ZANC) — software/package digest anchoring. One
         * rebuildable projection row per confirmed ZANC OP_RETURN, keyed by
         * txid. Not consulted by consensus; rebuilt from block history. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zanc_anchors ("
            "txid BLOB PRIMARY KEY CHECK(length(txid)=32),"
            "height INTEGER NOT NULL,"
            "hash_type INTEGER NOT NULL,"
            "digest BLOB NOT NULL CHECK(length(digest)=32),"
            "label TEXT NOT NULL DEFAULT '') WITHOUT ROWID");

        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zanc_digest "
            "ON zanc_anchors(hash_type, digest, height)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('030')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 30);
        current_ver = 30;
        applied++;
    }

    if (current_ver < 31) {
        /* v31: OP_RETURN catalog (op_return_index) — one rebuildable
         * projection row per OP_RETURN OUTPUT (not per tx; a tx with
         * several OP_RETURN outputs gets several rows), covering ZNAM,
         * ZSLP, ZANC, and unrecognized lokad tags alike. See
         * models/op_return_index.h. Not consulted by consensus; rebuilt
         * from block history (op_return_index_truncate). */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS op_return_index ("
            "txid BLOB NOT NULL CHECK(length(txid)=32),"
            "vout_n INTEGER NOT NULL,"
            "height INTEGER NOT NULL,"
            "tag BLOB NOT NULL,"
            "tag_text TEXT NOT NULL,"
            "payload_len INTEGER NOT NULL,"
            "payload_sha3 BLOB NOT NULL CHECK(length(payload_sha3)=32),"
            "PRIMARY KEY (txid, vout_n)) WITHOUT ROWID");

        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_op_return_index_height "
            "ON op_return_index(height)");

        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_op_return_index_tag "
            "ON op_return_index(tag_text, height)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('031')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 31);
        current_ver = 31;
        applied++;
    }

    if (current_ver < 32) {
        /* v32: ZSLP per-(token, outpoint) ledger (zslp_ledger) — the
         * debit-correct token-balance projection that finally makes token
         * balances fully chain-derived (the credit-only zslp_balances is
         * left untouched). One row per token-bearing transaction output (an
         * SLP UTXO): created by GENESIS/MINT/SEND, marked spent when a later
         * tx consumes the outpoint (the always-on tx_inputs spend graph). A
         * holder's balance = SUM(amount) over their UNSPENT rows. See
         * models/zslp_ledger.h. Not consulted by consensus; rebuilt from the
         * zslp_transfers / tx_outputs / tx_inputs projections
         * (zslp_ledger_truncate). token_id is internal (node) byte order. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zslp_ledger ("
            "token_id BLOB NOT NULL CHECK(length(token_id)=32),"
            "txid BLOB NOT NULL CHECK(length(txid)=32),"
            "vout INTEGER NOT NULL,"
            "amount INTEGER NOT NULL CHECK(amount>=0),"
            "address BLOB CHECK(address IS NULL OR length(address)=20),"
            "created_height INTEGER NOT NULL,"
            "spent_by_txid BLOB "
            "  CHECK(spent_by_txid IS NULL OR length(spent_by_txid)=32),"
            "spent_height INTEGER,"
            "PRIMARY KEY (token_id, txid, vout)) WITHOUT ROWID");

        /* Reconciliation surface: SUM(amount) over a holder's unspent rows. */
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zslp_ledger_addr "
            "ON zslp_ledger(token_id, address) WHERE spent_by_txid IS NULL");

        /* Spend-marking lookup by consumed outpoint (across tokens). */
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zslp_ledger_outpoint "
            "ON zslp_ledger(txid, vout)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('032')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 32);
        current_ver = 32;
        applied++;
    }

    if (current_ver < 33) {
        /* v33: parity_samples — bounded, retained history of the mirror's
         * per-tick consensus-parity comparison against the co-located
         * zclassicd oracle (models/parity_sample.h). One row per
         * legacy_mirror_sync comparison outcome. Purely observational —
         * never consulted by consensus. Bounded retention: the mirror
         * prunes to the newest N rows. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS parity_samples ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "ts INTEGER NOT NULL,"
            "our_height INTEGER NOT NULL DEFAULT -1,"
            "oracle_height INTEGER NOT NULL DEFAULT -1,"
            "heights_equal_at INTEGER NOT NULL DEFAULT -1,"
            "hash_equal INTEGER NOT NULL DEFAULT 0 CHECK(hash_equal IN (0,1)),"
            "oracle_reachable INTEGER NOT NULL DEFAULT 0 "
            "  CHECK(oracle_reachable IN (0,1)))");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_parity_samples_ts "
            "ON parity_samples(ts DESC)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('033')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 33);
        current_ver = 33;
        applied++;
    }

    if (current_ver < 34) {
        /* v34: block_index_cache integrity envelope — one row (envelope_id=1)
         * carrying an XOR-combined SHA3-256 over every block_index_cache row
         * + its row_count, verified at load. See
         * services/block_index_cache_envelope.h and docs/work/FORWARD_PLAN.md
         * item 7.3. Appended here (not next to block_index_cache's v4 DDL in
         * database_migrate.c) because this is the next free schema slot. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS block_index_cache_envelope ("
            "envelope_id INTEGER PRIMARY KEY CHECK(envelope_id=1),"
            "row_count INTEGER NOT NULL,"
            "content_sha3 BLOB NOT NULL CHECK(length(content_sha3)=32),"
            "written_at INTEGER NOT NULL)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('034')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 34);
        current_ver = 34;
        applied++;
    }

    if (current_ver < 35) {
        /* v35: wallet_labels — the address book. One row per labeled
         * address, keyed by address so a re-label overwrites in place;
         * backs setlabel / getaddressesbylabel / listlabels and
         * core.wallet.address.label(.by-label). A plain annotation
         * overlay: never part of the wallet keystore, never consulted by
         * consensus. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS wallet_labels ("
            "address TEXT PRIMARY KEY,"
            "label TEXT NOT NULL DEFAULT '',"
            "updated_at INTEGER NOT NULL DEFAULT 0)");

        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_wallet_labels_label "
            "ON wallet_labels(label)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('035')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 35);
        current_ver = 35;
        applied++;
    }

    if (current_ver < 36) {
        /* v36: agent_sessions — scoped agent spend-authority grants. One row
         * per minted session: a revocable, expiring cap set (per-tx limit,
         * rolling-window limit, recipient allowlist) bound to a principal.
         * See docs/work/agent-spend-policy-design.md. App-layer policy only —
         * never consulted by consensus. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS agent_sessions ("
            "session_id TEXT PRIMARY KEY,"
            "account TEXT NOT NULL REFERENCES principals(address),"
            "max_per_tx_zat INTEGER NOT NULL "
            "  CHECK(max_per_tx_zat >= 0 AND max_per_tx_zat <= 2100000000000000),"
            "max_per_window_zat INTEGER NOT NULL "
            "  CHECK(max_per_window_zat >= 0 AND max_per_window_zat <= 2100000000000000),"
            /* Upper bound as well as lower: an unbounded window_seconds makes
             * the roll comparison overflow and the per-window cap vanish
             * (AGENT_SESSION_WINDOW_SECONDS_MAX, models/agent_session.h). */
            "window_seconds INTEGER NOT NULL "
            "  CHECK(window_seconds > 0 AND window_seconds <= 31536000),"
            "window_start_epoch INTEGER NOT NULL,"
            "spent_in_window_zat INTEGER NOT NULL DEFAULT 0,"
            "recipient_allowlist TEXT NOT NULL DEFAULT '',"
            "created_at INTEGER NOT NULL,"
            "expires_at INTEGER NOT NULL,"
            "revoked INTEGER NOT NULL DEFAULT 0)");

        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_agent_sessions_account "
            "ON agent_sessions(account)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('036')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 36);
        current_ver = 36;
        applied++;
    }

    if (current_ver < 37) {
        /* v37: zid_identities — the sovereign-identity projection. One
         * rebuildable row per master ed25519 key that has been anchored
         * on-chain, answering "is this 32-byte key anchored, by whom, at
         * what height, and is it still valid?". Rows arrive from two
         * sources: a ZNAM text record (source='znam_text', `name` set) or
         * the zid overlay (source='zid_overlay'). status is
         * 'active' | 'rotated' | 'revoked'; successor_pubkey is present
         * exactly when status='rotated'. See models/zid_identity.h. Not
         * consulted by consensus; rebuilt from block history. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zid_identities ("
            "master_pubkey BLOB NOT NULL CHECK(length(master_pubkey)=32) "
            "  PRIMARY KEY,"
            "anchor_txid BLOB NOT NULL CHECK(length(anchor_txid)=32),"
            "anchor_height INTEGER NOT NULL,"
            "status TEXT NOT NULL,"
            "successor_pubkey BLOB "
            "  CHECK(successor_pubkey IS NULL OR length(successor_pubkey)=32),"
            "source TEXT NOT NULL,"
            "name TEXT,"
            "owner_address TEXT,"
            "updated_height INTEGER NOT NULL) WITHOUT ROWID");

        /* Name resolution (db_zid_identity_find_by_name) — every
         * list/filter path a command exposes must have an index. */
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zid_identities_name "
            "ON zid_identities(name)");

        /* Height-ordered listing / range filters. */
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zid_identities_height "
            "ON zid_identities(anchor_height)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('037')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 37);
        current_ver = 37;
        applied++;
    }

    if (current_ver < 38) {
        /* v38: zid ANCHOR DOMAINS (zid_domains + zid_domain_leaves) — the
         * durable record of WHAT a domain batch committed. Before this,
         * `zcode release anchor` / `prove` rebuilt the domain tree by
         * scanning every .zid under <datadir>/zcode/releases on every call,
         * so adding
         * or removing one file silently changed the domain root and a
         * previously-issued inclusion proof quietly stopped matching with
         * no record of what had been anchored. The leaf set is now stored
         * in canonical sorted order alongside the root it folds to, and
         * many domains (zcode, zdesc, zdir, third-party) coexist, each
         * anchoring at its own cadence — see
         * docs/spec/sovereign-identity-layer.md and models/zid_domain.h.
         *
         * Operator-owned, not a chain projection: rows are written by the
         * anchor path, never rebuilt from block history, and never
         * consulted by consensus. anchored_txid/anchored_height stay NULL
         * until the domain root is committed on-chain. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zid_domains ("
            "domain_name TEXT PRIMARY KEY,"
            "owner_pubkey BLOB CHECK(length(owner_pubkey)=32),"
            "num_leaves INTEGER NOT NULL,"
            "root BLOB NOT NULL CHECK(length(root)=32),"
            "anchored_txid BLOB "
            "  CHECK(anchored_txid IS NULL OR length(anchored_txid)=32),"
            "anchored_height INTEGER,"
            "updated_at INTEGER NOT NULL)");

        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zid_domain_leaves ("
            "domain_name TEXT NOT NULL,"
            "leaf_index INTEGER NOT NULL,"
            "record_digest BLOB NOT NULL CHECK(length(record_digest)=32),"
            "label TEXT,"
            "PRIMARY KEY (domain_name, leaf_index)) WITHOUT ROWID");

        /* "prove this digest" is a lookup, not a scan of the leaf set. */
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zid_domain_leaves_digest "
            "ON zid_domain_leaves(record_digest)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('038')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 38);
        current_ver = 38;
        applied++;
    }

    if (current_ver < 39) {
        /* v39: the ON-CHAIN NODE DIRECTORY (onion_directory) — a rebuildable
         * projection of confirmed `ZDIR` OP_RETURNs (zdir/zdir.h), folded by
         * contexts/naming/models/src/explorer_index_zdir.c during the same
         * genesis-ascending walk that builds znam_names / zanc_anchors /
         * zid_identities.
         *
         * This is what replaces the old "ZSLP chain scan": that path read
         * db_wallet_tx_recent_raw(), so it could only ever see transactions
         * already in the LOCAL WALLET table — a node with an empty wallet
         * discovered nothing and no node ever saw another node's
         * announcement.
         *
         * A row is a HINT ABOUT WHERE TO LOOK, never proof of who is there:
         * the table only ADDS candidates alongside DNS seeds, fixed seeds,
         * addrman and the signed-descriptor source, and has no path to
         * exclude a peer. Never consulted by consensus; safe to drop and
         * refold. hostname is CHECKed to the exact Tor v3 length here and to
         * the full alphabet rule in db_onion_directory_validate. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS onion_directory ("
            "hostname TEXT PRIMARY KEY CHECK(length(hostname)=62),"
            "txid BLOB NOT NULL CHECK(length(txid)=32),"
            "height INTEGER NOT NULL,"
            "owner_address TEXT,"
            "master_pubkey BLOB "
            "  CHECK(master_pubkey IS NULL OR length(master_pubkey)=32),"
            "status TEXT NOT NULL,"
            "updated_height INTEGER NOT NULL) WITHOUT ROWID");

        /* Peer discovery reads active rows newest-registration-first; the
         * status filter and the height ordering are the whole query. */
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_onion_directory_status_height "
            "ON onion_directory(status, height DESC)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('039')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 39);
        current_ver = 39;
        applied++;
    }

    if (current_ver < 40) {
        /* v40: store_purchases — the BUYER's side of a store transaction
         * (models/store_purchase.h). `orders` is the merchant's row; this is
         * the row the buyer needs to finish a purchase it already paid for.
         *
         * It exists because a purchase is not one instant: place order, send
         * a shielded payment, wait for confirmations, download the file. A
         * buyer that stops between paying and collecting has spent money and
         * has nothing on disk, and without a persisted row that state has no
         * name and no way back. stage + last_error give it both.
         *
         * order_id is UNIQUE: one buyer row per merchant order, so retrying
         * "start this order" resumes instead of minting a second payment
         * obligation. content_hash is the expected SHA3-256 of the payload,
         * checked before any byte is written to output_path.
         *
         * App-layer projection: never read by consensus, safe to drop. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS store_purchases ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "order_id INTEGER NOT NULL,"
            "product_id INTEGER NOT NULL,"
            "product_name TEXT NOT NULL DEFAULT '',"
            "token_id TEXT NOT NULL DEFAULT '',"
            "payment_addr TEXT NOT NULL,"
            "customer_addr TEXT NOT NULL DEFAULT '',"
            "memo TEXT NOT NULL,"
            "amount_zatoshi INTEGER NOT NULL,"
            "content_hash BLOB "
            "  CHECK(content_hash IS NULL OR length(content_hash)=32),"
            "output_path TEXT NOT NULL DEFAULT '',"
            "operation_id TEXT NOT NULL DEFAULT '',"
            "stage INTEGER NOT NULL,"
            "last_error TEXT NOT NULL DEFAULT '',"
            "created_at INTEGER NOT NULL,"
            "updated_at INTEGER NOT NULL)");

        node_db_exec(ndb,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_store_purchases_order "
            "ON store_purchases(order_id)");

        /* The resume path asks exactly one question — what is unfinished —
         * so it is an index lookup, not a scan of every purchase ever made. */
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_store_purchases_stage "
            "ON store_purchases(stage, id)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('040')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 40);
        current_ver = 40;
        applied++;
    }

    if (current_ver < 41) {
        /* v41: ZBuild Fabric coordinator ledger. Build jobs own ordered
         * actions; approved workers may sign receipts binding an action to an
         * output. This is local operator/development state, never consensus. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS build_jobs ("
            "job_id TEXT PRIMARY KEY CHECK(length(job_id)=64),"
            "source_sha256 TEXT NOT NULL CHECK(length(source_sha256)=64),"
            "source_cas_sha3 TEXT NOT NULL CHECK(length(source_cas_sha3)=64),"
            "toolchain_sha3 TEXT NOT NULL CHECK(length(toolchain_sha3)=64),"
            "profile TEXT NOT NULL CHECK(length(profile) BETWEEN 1 AND 31),"
            "state TEXT NOT NULL CHECK(state IN ('PLANNED','SNAPSHOTTED',"
            "'QUEUED','CLAIMED','RUNNING','VERIFYING','ACCEPTED','CACHE_HIT',"
            "'LOCAL_FALLBACK','DISPUTED','CANCELLED','FAILED')),"
            "outcome TEXT NOT NULL DEFAULT '',"
            "cancel_requested INTEGER NOT NULL DEFAULT 0 "
            "  CHECK(cancel_requested IN (0,1)),"
            "created_at INTEGER NOT NULL CHECK(created_at>=0),"
            "updated_at INTEGER NOT NULL CHECK(updated_at>=0)) WITHOUT ROWID");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_build_jobs_state_created "
            "ON build_jobs(state,created_at DESC)");

        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS build_actions ("
            "action_id TEXT PRIMARY KEY CHECK(length(action_id)=64),"
            "job_id TEXT NOT NULL REFERENCES build_jobs(job_id) ON DELETE CASCADE,"
            "sequence INTEGER NOT NULL CHECK(sequence>=0),"
            "kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 63),"
            "state TEXT NOT NULL CHECK(state IN ('PLANNED','SNAPSHOTTED',"
            "'QUEUED','CLAIMED','RUNNING','VERIFYING','ACCEPTED','CACHE_HIT',"
            "'LOCAL_FALLBACK','DISPUTED','CANCELLED','FAILED')),"
            "outcome TEXT NOT NULL DEFAULT '',"
            "input_root_sha3 TEXT NOT NULL CHECK(length(input_root_sha3)=64),"
            "target TEXT NOT NULL CHECK(length(target) BETWEEN 1 AND 63),"
            "flags_sha3 TEXT NOT NULL CHECK(length(flags_sha3)=64),"
            "environment_sha3 TEXT NOT NULL CHECK(length(environment_sha3)=64),"
            "virtual_workdir TEXT NOT NULL "
            "  CHECK(length(virtual_workdir) BETWEEN 1 AND 255),"
            "declared_outputs TEXT NOT NULL "
            "  CHECK(length(declared_outputs) BETWEEN 1 AND 255),"
            "resource_policy TEXT NOT NULL "
            "  CHECK(length(resource_policy) BETWEEN 1 AND 255),"
            "output_root_sha3 TEXT NOT NULL DEFAULT '' "
            "  CHECK(length(output_root_sha3) IN (0,64)),"
            "worker_id TEXT NOT NULL DEFAULT '' CHECK(length(worker_id) IN (0,64)),"
            "last_error TEXT NOT NULL DEFAULT '' CHECK(length(last_error)<=255),"
            "created_at INTEGER NOT NULL CHECK(created_at>=0),"
            "updated_at INTEGER NOT NULL CHECK(updated_at>=0),"
            "UNIQUE(job_id,sequence)) WITHOUT ROWID");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_build_actions_job_sequence "
            "ON build_actions(job_id,sequence)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_build_actions_state_updated "
            "ON build_actions(state,updated_at)");

        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS build_workers ("
            "worker_id TEXT PRIMARY KEY CHECK(length(worker_id)=64),"
            "signer_pubkey TEXT NOT NULL UNIQUE CHECK(length(signer_pubkey)=64),"
            "capabilities TEXT NOT NULL DEFAULT '' CHECK(length(capabilities)<=1023),"
            "approved INTEGER NOT NULL DEFAULT 0 CHECK(approved IN (0,1)),"
            "revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),"
            "approved_at INTEGER NOT NULL DEFAULT 0 CHECK(approved_at>=0),"
            "expires_at INTEGER NOT NULL DEFAULT 0 CHECK(expires_at>=0),"
            "last_seen_at INTEGER NOT NULL DEFAULT 0 CHECK(last_seen_at>=0)) "
            "WITHOUT ROWID");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_build_workers_approval "
            "ON build_workers(approved,revoked,expires_at)");

        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS build_receipts ("
            "receipt_id TEXT PRIMARY KEY CHECK(length(receipt_id)=64),"
            "action_id TEXT NOT NULL REFERENCES build_actions(action_id) "
            "  ON DELETE CASCADE,"
            "job_id TEXT NOT NULL REFERENCES build_jobs(job_id) ON DELETE CASCADE,"
            "worker_id TEXT NOT NULL REFERENCES build_workers(worker_id),"
            "action_sha3 TEXT NOT NULL CHECK(length(action_sha3)=64),"
            "output_sha3 TEXT NOT NULL CHECK(length(output_sha3)=64),"
            "signature TEXT NOT NULL CHECK(length(signature)=128),"
            "confinement TEXT NOT NULL CHECK(length(confinement) BETWEEN 1 AND 255),"
            "exit_status INTEGER NOT NULL CHECK(exit_status BETWEEN 0 AND 255),"
            "created_at INTEGER NOT NULL CHECK(created_at>=0)) WITHOUT ROWID");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_build_receipts_job_created "
            "ON build_receipts(job_id,created_at)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_build_receipts_action "
            "ON build_receipts(action_id)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('041')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 41);
        current_ver = 41;
        applied++;
    }

    if (current_ver < 42) {
        /* v42: durable ZBuild leases. Claims are compare-and-swap writes;
         * their expiry and heartbeat make worker death recoverable after a
         * process or host restart without allowing two owners to publish. */
        node_db_exec(ndb,
            "ALTER TABLE build_actions ADD COLUMN lease_id TEXT NOT NULL "
            "DEFAULT '' CHECK(length(lease_id) IN (0,64))");
        node_db_exec(ndb,
            "ALTER TABLE build_actions ADD COLUMN lease_expires_at INTEGER "
            "NOT NULL DEFAULT 0 CHECK(lease_expires_at>=0)");
        node_db_exec(ndb,
            "ALTER TABLE build_actions ADD COLUMN lease_heartbeat_at INTEGER "
            "NOT NULL DEFAULT 0 CHECK(lease_heartbeat_at>=0)");
        node_db_exec(ndb,
            "ALTER TABLE build_actions ADD COLUMN attempt_count INTEGER "
            "NOT NULL DEFAULT 0 CHECK(attempt_count>=0)");
        node_db_exec(ndb,
            "ALTER TABLE build_actions ADD COLUMN claimed_at INTEGER "
            "NOT NULL DEFAULT 0 CHECK(claimed_at>=0)");
        node_db_exec(ndb,
            "ALTER TABLE build_actions ADD COLUMN started_at INTEGER "
            "NOT NULL DEFAULT 0 CHECK(started_at>=0)");
        node_db_exec(ndb,
            "ALTER TABLE build_actions ADD COLUMN finished_at INTEGER "
            "NOT NULL DEFAULT 0 CHECK(finished_at>=0)");
        node_db_exec(ndb,
            "ALTER TABLE build_receipts ADD COLUMN lease_id TEXT NOT NULL "
            "DEFAULT '' CHECK(length(lease_id) IN (0,64))");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_build_actions_lease_recovery "
            "ON build_actions(state,lease_expires_at,updated_at)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('042')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 42);
        current_ver = 42;
        applied++;
    }

    if (current_ver < 43) {
        /* v43: canonical ZCODE task/candidate context and the work-receipt
         * projection. Empty roots retain project-neutral legacy actions;
         * ZCODE actions require all semantic roots in model validation. */
        node_db_exec(ndb,
            "ALTER TABLE build_actions ADD COLUMN task_root_sha3 TEXT NOT NULL "
            "DEFAULT '' CHECK(length(task_root_sha3) IN (0,64))");
        node_db_exec(ndb,
            "ALTER TABLE build_actions ADD COLUMN candidate_root_sha3 TEXT NOT NULL "
            "DEFAULT '' CHECK(length(candidate_root_sha3) IN (0,64))");
        node_db_exec(ndb,
            "ALTER TABLE build_actions ADD COLUMN proof_policy_root_sha3 TEXT NOT NULL "
            "DEFAULT '' CHECK(length(proof_policy_root_sha3) IN (0,64))");
        node_db_exec(ndb,
            "ALTER TABLE build_actions ADD COLUMN context_root_sha3 TEXT NOT NULL "
            "DEFAULT '' CHECK(length(context_root_sha3) IN (0,64))");
        node_db_exec(ndb,
            "ALTER TABLE build_receipts ADD COLUMN work_receipt_sha3 TEXT NOT NULL "
            "DEFAULT '' CHECK(length(work_receipt_sha3) IN (0,64))");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_build_actions_zcode_task "
            "ON build_actions(task_root_sha3,candidate_root_sha3,state)");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('043')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 43);
        current_ver = 43;
        applied++;
    }

    if (current_ver < 44) {
        /* v44: one receipt ledger, explicit trust semantics. Existing rows
         * were admitted only through the approved local receipt path. Remote
         * canonical receipts enter as observations and cannot inherit that
         * authority merely by occupying the same indexed relationship. */
        node_db_exec(ndb,
            "ALTER TABLE build_receipts ADD COLUMN trust_state TEXT NOT NULL "
            "DEFAULT 'LOCAL_ACCEPTED' CHECK(trust_state IN "
            "('LOCAL_ACCEPTED','REMOTE_OBSERVED','LOCAL_REPRODUCED',"
            "'QUORUM_MATCHED','REJECTED'))");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_build_receipts_action_trust "
            "ON build_receipts(action_id,trust_state,created_at)");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('044')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 44);
        current_ver = 44;
        applied++;
    }

    if (current_ver < 45) {
        /* v45: rebuildable lookup projection for signed lane_receipt.v1 CAS
         * objects. Rows are append-only roots; canonical receipt bytes and
         * signatures remain the authority in the existing workspace CAS. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zcode_lane_receipts ("
            "receipt_id TEXT PRIMARY KEY CHECK(length(receipt_id)=64),"
            "source_root_sha3 TEXT NOT NULL CHECK(length(source_root_sha3)=64),"
            "task_root_sha3 TEXT NOT NULL CHECK(length(task_root_sha3)=64),"
            "candidate_root_sha3 TEXT NOT NULL CHECK(length(candidate_root_sha3)=64),"
            "proof_policy_root_sha3 TEXT NOT NULL CHECK(length(proof_policy_root_sha3)=64),"
            "proof_set_root_sha3 TEXT NOT NULL CHECK(length(proof_set_root_sha3) IN (0,64)),"
            "prior_receipt_root_sha3 TEXT NOT NULL CHECK(length(prior_receipt_root_sha3) IN (0,64)),"
            "signer_pubkey TEXT NOT NULL CHECK(length(signer_pubkey)=64),"
            "lane INTEGER NOT NULL CHECK(lane BETWEEN 1 AND 3),"
            "created_at INTEGER NOT NULL CHECK(created_at>0),"
            "UNIQUE(source_root_sha3,lane))");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zcode_lane_source "
            "ON zcode_lane_receipts(source_root_sha3,lane,created_at)");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('045')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 45);
        current_ver = 45;
        applied++;
    }

    if (current_ver < 46) {
        /* v46: strict recursive ZSLP validity. The outpoint ledger records
         * token outputs and mint batons, but only after the tri-state
         * validator admits their ancestry and quantities. */
        node_db_exec(ndb,
            "ALTER TABLE zslp_ledger ADD COLUMN role INTEGER NOT NULL "
            "DEFAULT 1 CHECK(role IN (1,2))");
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zslp_validity ("
            "txid BLOB PRIMARY KEY CHECK(length(txid)=32),"
            "token_id BLOB CHECK(token_id IS NULL OR length(token_id)=32),"
            "tx_type INTEGER NOT NULL,"
            "status INTEGER NOT NULL CHECK(status IN (0,1,2)),"
            "reason TEXT NOT NULL,"
            "block_height INTEGER NOT NULL,"
            "input_units INTEGER NOT NULL DEFAULT 0 CHECK(input_units>=0),"
            "output_units INTEGER NOT NULL DEFAULT 0 CHECK(output_units>=0),"
            "burned_units INTEGER NOT NULL DEFAULT 0 CHECK(burned_units>=0),"
            "minted_units INTEGER NOT NULL DEFAULT 0 CHECK(minted_units>=0),"
            "baton_vout INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zslp_validity_token_height "
            "ON zslp_validity(token_id,block_height,status)");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zslp_ledger_valid_role "
            "ON zslp_ledger(token_id,role,spent_by_txid)");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('046')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 46);
        current_ver = 46;
        applied++;
    }

    if (current_ver < 47) {
        /* v47: a passphrase-wrapped metadata DEK plus encrypted intent rows.
         * Sensitive bodies are application data, never consensus state. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS wallet_metadata_key ("
            "id INTEGER PRIMARY KEY CHECK(id=1),"
            "wrapped_dek BLOB NOT NULL)");
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS vault_intents ("
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
            "updated_at INTEGER NOT NULL) WITHOUT ROWID");
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_vault_intents_state_time "
            "ON vault_intents(state,created_at DESC)");
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS vault_intent_raw ("
            "plan_id BLOB PRIMARY KEY CHECK(length(plan_id)=32),"
            "raw_tx BLOB NOT NULL) WITHOUT ROWID");
        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('047')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 47);
        current_ver = 47;
        applied++;
    }

    if (current_ver < 48) {
        /* v48: zswap YARDSALE ads (zswap_ads) — the rebuildable projection
         * of verified signed "for sale by owner" ZSLP-token/ZCL gossip ads
         * (zswap_quote.v1, contexts/market/modules/zswap). One row per quote_root (the dedup
         * id): wire keeps the exact 210 signed bytes that verified at
         * ingress, the amount/time columns project the signed body, and
         * first/last_seen + seen_count are local gossip bookkeeping. A
         * yardsale cache — remembered signs, never a market or a matching
         * engine; never consulted by consensus; safe to drop. */
        node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS zswap_ads ("
            "quote_root BLOB NOT NULL PRIMARY KEY "
            "  CHECK(length(quote_root)=32),"
            "wire BLOB NOT NULL CHECK(length(wire)=210),"
            "seller_pubkey BLOB NOT NULL CHECK(length(seller_pubkey)=32),"
            "token_id BLOB NOT NULL CHECK(length(token_id)=32),"
            "token_amount INTEGER NOT NULL CHECK(token_amount>0),"
            "zcl_amount INTEGER NOT NULL CHECK(zcl_amount>0),"
            "issued_unix INTEGER NOT NULL,"
            "expires_unix INTEGER NOT NULL,"
            "first_seen_unix INTEGER NOT NULL,"
            "last_seen_unix INTEGER NOT NULL,"
            "seen_count INTEGER NOT NULL DEFAULT 1 CHECK(seen_count>=1))"
            " WITHOUT ROWID");

        /* The browse query filters one token's still-valid ads. */
        node_db_exec(ndb,
            "CREATE INDEX IF NOT EXISTS idx_zswap_ads_token_expiry "
            "ON zswap_ads(token_id, expires_unix)");

        node_db_exec(ndb,
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES('048')");
        DB_MIGRATE_PERSIST_VERSION(ndb, 48);
        current_ver = 48;
        applied++;
    }

    /* v49+ continues in database_migrate_features_v49_up.c (same E1
     * file-size split as the v30 handoff). */
    *version = current_ver;
    return applied + node_db_migrate_features_v49_up(ndb, version);
}
