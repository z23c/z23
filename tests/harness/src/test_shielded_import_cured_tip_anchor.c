/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_shielded_import_cured_tip_anchor — the cure-path trust anchor that lets
 * a shielded-history import's cured coins tip INSTALL into the active chain.
 *
 * After the -import-complete-shielded importer clears the shielded
 * anchor/nullifier wedge, the coins tip left by the transparent seed has a
 * pprev height-tear between the compiled SHA3 anchor and it. Invariant A
 * (engine/services/src/utxo_recovery_frontier_gate.c) CORRECTLY refuses to install
 * a detached island, so active_chain_tip() stays NULL and process_headers
 * builds a genesis-only getheaders locator — the tail bodies to network tip are
 * never requested. The fix registers the cured tip as a cold-import TRUST anchor
 * so Invariant A installs it.
 *
 * Two properties, hermetic (no chain, no params):
 *   GATE  — a height-torn tip at the registered (height, hash) becomes
 *           trust-rooted (Invariant A installs it → active_chain_tip returns
 *           it, not NULL); a tip at a DIFFERENT hash stays a refused island;
 *           clearing the anchor restores the refusal.
 *   HOOK  — shielded_history_import_register_cured_tip_trust_anchor derives the
 *           coins-best (height, hash) from progress.kv's own co-committed state
 *           and registers BOTH the in-memory anchor (effective this process) and
 *           the DURABLE node_db seed the boot restore path re-reads.
 */

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "core/uint256.h"
#include "jobs/reducer_frontier.h"
#include "models/database.h"
#include "services/shielded_history_import_service.h"
#include "services/utxo_recovery_service.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "util/blocker.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CTA_CHECK(name, expr) do {                                 \
    printf("  cured_tip_anchor: %s... ", (name));                  \
    if ((expr)) printf("OK\n");                                    \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

/* The trust-root floor: fixtures MUST root ABOVE this so the contiguous-prefix
 * walker does not treat them as trusted for free. */
static int32_t cta_anchor_height(void)
{
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    return cp ? cp->height : REDUCER_FRONTIER_TRUSTED_ANCHOR;
}

/* Deterministic per-(tag,height) block hash. */
static void cta_fill_hash(struct uint256 *out, int32_t height, uint8_t tag)
{
    memset(out->data, 0, 32);
    out->data[0] = tag;
    out->data[1] = (uint8_t)(height & 0xff);
    out->data[2] = (uint8_t)((height >> 8) & 0xff);
    out->data[3] = (uint8_t)((height >> 16) & 0xff);
    out->data[31] = 0xC7;
}

static void cta_make_block(struct block_index *bi, int32_t height,
                           struct block_index *prev, uint8_t tag)
{
    block_index_init(bi);
    cta_fill_hash(&bi->hashBlock, height, tag);
    bi->phashBlock = &bi->hashBlock;
    bi->nHeight = height;
    bi->pprev = prev;
}

/* progress.kv coins-best derivation prerequisites (mirrors the production
 * proven-authority triple + the validate_headers_log own-hash witness):
 *   - progress_meta.coins_applied_height  = H + 1 (LE int64 blob)
 *   - progress_meta.coins_kv_migration_complete = 1
 *   - a non-empty `coins` table
 *   - validate_headers_log row at H carrying `hash`
 * So reducer_frontier_derive_coins_best returns (H, hash). */
static bool cta_seed_coins_best(sqlite3 *db, int32_t h,
                                const struct uint256 *hash)
{
    char *err = NULL;
    if (sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB);"
            "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00');"
            "CREATE TABLE IF NOT EXISTS validate_headers_log ("
            "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
            "  fail_reason TEXT, validated_at INTEGER);",
            NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[cta] schema: %s\n", err ? err : "(null)");
        sqlite3_free(err);
        return false;
    }

    uint8_t applied_le[8];
    int64_t applied = (int64_t)h + 1;
    for (int i = 0; i < 8; i++)
        applied_le[i] = (uint8_t)((uint64_t)applied >> (8 * i));

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_applied_height", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, applied_le, 8, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) return false;

    uint8_t one = 1;
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_kv_migration_complete", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, &one, 1, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) return false;

    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO validate_headers_log(height,hash,ok) "
            "VALUES(?,?,1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, h);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

int test_shielded_import_cured_tip_anchor(void);
int test_shielded_import_cured_tip_anchor(void)
{
    int failures = 0;
    const int32_t anchor = cta_anchor_height();
    const int32_t H = anchor + 100;   /* cured coins tip, above the trust floor */

    /* ── GATE: a height-torn tip installs iff the cold-import anchor matches ── */
    {
        /* Detached island: tip at H whose pprev is height-torn (an ancestor at
         * H-50, not H-1) — exactly the shape the boot restore refuses. */
        struct block_index tip, torn_prev;
        cta_make_block(&torn_prev, H - 50, NULL, 0x20);
        cta_make_block(&tip, H, &torn_prev, 0x21);

        /* No anchor registered → refused island (baseline). */
        utxo_recovery_set_cold_import_trust_anchor(NULL, -1);
        CTA_CHECK("torn tip is a refused island before registration",
                  !utxo_recovery_block_trust_rooted(&tip));

        /* Register the cured tip's exact (height, hash) → trust-rooted. */
        utxo_recovery_set_cold_import_trust_anchor(tip.phashBlock, H);
        CTA_CHECK("torn tip becomes trust-rooted after registration",
                  utxo_recovery_block_trust_rooted(&tip));
        CTA_CHECK("ancestry_break returns NULL (no island root) for the tip",
                  utxo_recovery_block_ancestry_break(&tip) == NULL);

        /* Invariant A now installs it → active_chain_tip() returns the tip,
         * not NULL (the stall the fix removes). Model the gate the boot
         * restore applies: install only a trust-rooted tip. */
        struct active_chain chain;
        active_chain_init(&chain);
        CTA_CHECK("active_chain_tip is NULL before install",
                  active_chain_tip(&chain) == NULL);
        if (utxo_recovery_block_trust_rooted(&tip))
            (void)active_chain_install_tip_slot(&chain, &tip);
        CTA_CHECK("active_chain_tip returns the cured tip after install",
                  active_chain_tip(&chain) == &tip);
        CTA_CHECK("active_chain_height is the cured tip height",
                  active_chain_height(&chain) == H);
        active_chain_free(&chain);

        /* Security: a torn tip at the SAME height but a DIFFERENT hash is NOT
         * granted the relaxation — the detached-island guard holds. */
        struct block_index wrong;
        cta_make_block(&wrong, H, &torn_prev, 0x99);   /* different tag → hash */
        CTA_CHECK("a mismatched-hash torn tip stays a refused island",
                  !utxo_recovery_block_trust_rooted(&wrong));

        /* Clearing the anchor restores the refusal (no latent trust). */
        utxo_recovery_set_cold_import_trust_anchor(NULL, -1);
        CTA_CHECK("clearing the anchor restores the island refusal",
                  !utxo_recovery_block_trust_rooted(&tip));
    }

    /* ── HOOK: the import registers the derived coins-best in-memory + durably ── */
    {
        char pg_dir[256], ndb_path[320];
        test_make_tmpdir(pg_dir, sizeof(pg_dir), "cta_hook", "pg");
        snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", pg_dir);

        struct uint256 tip_hash;
        cta_fill_hash(&tip_hash, H, 0x42);

        utxo_recovery_set_cold_import_trust_anchor(NULL, -1);  /* clean slate */

        CTA_CHECK("progress.kv opens", progress_store_open(pg_dir));
        sqlite3 *db = progress_store_db();
        CTA_CHECK("coins-best derivation seeded",
                  db && cta_seed_coins_best(db, H, &tip_hash));

        /* Sanity: the derivation returns exactly (H, tip_hash). */
        int32_t dh = -1;
        uint8_t dhash[32];
        bool dhash_found = false, dfound = false;
        bool dok = reducer_frontier_derive_coins_best(db, &dh, dhash,
                                                      &dhash_found, &dfound);
        CTA_CHECK("derive_coins_best resolves the cured (height, hash)",
                  dok && dfound && dhash_found && dh == H &&
                  memcmp(dhash, tip_hash.data, 32) == 0);

        struct node_db ndb;
        CTA_CHECK("node.db opens", node_db_open(&ndb, ndb_path));

        CTA_CHECK("register hook succeeds",
                  shielded_history_import_register_cured_tip_trust_anchor(db,
                                                                          &ndb));

        /* In-memory: a torn tip at (H, tip_hash) is now trust-rooted. */
        struct block_index htip, hprev;
        cta_make_block(&hprev, H - 30, NULL, 0x30);
        block_index_init(&htip);
        htip.hashBlock = tip_hash;
        htip.phashBlock = &htip.hashBlock;
        htip.nHeight = H;
        htip.pprev = &hprev;
        CTA_CHECK("in-memory anchor makes the derived tip trust-rooted",
                  utxo_recovery_block_trust_rooted(&htip));

        /* Durable: the boot restore path reads these node_db seed keys. */
        int64_t seed_h = -1;
        uint8_t seed_hash[32];
        size_t seed_hn = 0;
        bool got_h = node_db_state_get_int(&ndb,
            "cold_import_seed_anchor_height", &seed_h);
        bool got_hash = node_db_state_get(&ndb, "cold_import_seed_anchor_hash",
            seed_hash, sizeof(seed_hash), &seed_hn);
        CTA_CHECK("durable seed height persisted == cured tip height",
                  got_h && seed_h == H);
        CTA_CHECK("durable seed hash persisted == cured tip hash",
                  got_hash && seed_hn == 32 &&
                  memcmp(seed_hash, tip_hash.data, 32) == 0);

        node_db_close(&ndb);
        progress_store_close();
        utxo_recovery_set_cold_import_trust_anchor(NULL, -1);  /* leave clean */
    }

    /* ── HOOK negative: no coins-best derivable → clean refusal, no seed ── */
    {
        char pg_dir[256], ndb_path[320];
        test_make_tmpdir(pg_dir, sizeof(pg_dir), "cta_hook_neg", "pg");
        snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", pg_dir);

        CTA_CHECK("progress.kv opens (neg)", progress_store_open(pg_dir));
        /* No coins_applied_height / migration stamp → not proven-authority. */
        struct node_db ndb;
        CTA_CHECK("node.db opens (neg)", node_db_open(&ndb, ndb_path));
        CTA_CHECK("register hook refuses without a derivable coins-best",
                  !shielded_history_import_register_cured_tip_trust_anchor(
                      progress_store_db(), &ndb));
        int64_t seed_h = -1;
        CTA_CHECK("no durable seed written on refusal",
                  !node_db_state_get_int(&ndb,
                      "cold_import_seed_anchor_height", &seed_h));
        node_db_close(&ndb);
        progress_store_close();
        utxo_recovery_set_cold_import_trust_anchor(NULL, -1);
    }

    /* ── RELINK FIX: a height-scrambled ancestry under intact hash-linkage is
     * relabeled in place → the coins tip becomes trust-rooted. The chain
     * descends THROUGH the node at the SHA3 anchor height (the live-datadir
     * shape), so the anchor node's OWN scrambled label must be corrected too —
     * ancestry_break trust-roots only once its descent reaches a node whose
     * height <= anchor. (Stopping one node shallow was the off-by-one that left
     * the live tip un-rooted after relabeling ~116k heights.) No cold-import
     * anchor is registered: the cure is structural, not an island exception. ── */
    {
        utxo_recovery_set_cold_import_trust_anchor(NULL, -1);   /* clean slate */

        struct main_state ms;
        main_state_init(&ms);

        enum { CHAIN = 12 };
        struct block_index blocks[CHAIN];
        /* blocks[0] IS the node at the anchor height (pprev=NULL loaded root);
         * blocks[1..] climb above it to the tip. The terminus MUST be the
         * compiled checkpoint block — the relink hash-verifies it (a wrong
         * lineage is refused, not stamped), so give blocks[0] the checkpoint
         * hash. */
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        for (int i = 0; i < CHAIN; i++) {
            cta_make_block(&blocks[i], anchor + i,
                           i > 0 ? &blocks[i - 1] : NULL, 0x40);
            if (i == 0 && cp)
                memcpy(blocks[0].hashBlock.data, cp->block_hash, 32);
            block_map_insert(&ms.map_block_index, &blocks[i].hashBlock,
                             &blocks[i]);
        }
        struct block_index *tip = &blocks[CHAIN - 1];

        CTA_CHECK("relink: contiguous chain tip is trust-rooted before scramble",
                  utxo_recovery_block_trust_rooted(tip));

        /* Scramble BOTH the anchor node (blocks[0]) and a mid ancestor
         * (blocks[5]); hash-linkage (pprev) stays intact, only labels are wrong. */
        blocks[0].nHeight = anchor + 500000;   /* anchor node label torn */
        blocks[5].nHeight = anchor + 600000;   /* mid ancestor label torn */

        CTA_CHECK("relink: scramble makes the tip a detached island",
                  !utxo_recovery_block_trust_rooted(tip) &&
                  utxo_recovery_block_ancestry_break(tip) != NULL);

        struct utxo_recovery_ancestry_repair rep =
            utxo_recovery_relink_scrambled_ancestry(&ms, tip);
        CTA_CHECK("relink: repair reports FIXED with >=2 relabels",
                  rep.result == UTXO_ANCESTRY_REPAIR_FIXED && rep.fixed >= 2);
        CTA_CHECK("relink: the anchor node's own height is corrected",
                  blocks[0].nHeight == anchor);
        CTA_CHECK("relink: the mid ancestor's height is corrected",
                  blocks[5].nHeight == anchor + 5);
        CTA_CHECK("relink: tip is trust-rooted after the repair",
                  utxo_recovery_block_trust_rooted(tip) &&
                  utxo_recovery_block_ancestry_break(tip) == NULL);

        /* Idempotent: a second call is a NOOP (island already cured). */
        struct utxo_recovery_ancestry_repair rep2 =
            utxo_recovery_relink_scrambled_ancestry(&ms, tip);
        CTA_CHECK("relink: a second pass is a NOOP (idempotent)",
                  rep2.result == UTXO_ANCESTRY_REPAIR_NOOP && rep2.fixed == 0);

        main_state_free(&ms);
    }

    /* ── RELINK REFUSE: a GENUINE hash-linkage break (a NULL parent above the
     * attested extent) is real corruption, not a label scramble — the repair
     * changes NOTHING and names a typed blocker. Two-pass guarantees a
     * higher scrambled label above the break is left untouched. ── */
    {
        utxo_recovery_set_cold_import_trust_anchor(NULL, -1);
        blocker_module_init();
        blocker_reset_for_testing();

        struct main_state ms;
        main_state_init(&ms);

        enum { CHAIN = 12 };
        struct block_index blocks[CHAIN];
        for (int i = 0; i < CHAIN; i++) {
            cta_make_block(&blocks[i], anchor + 1 + i,
                           i > 0 ? &blocks[i - 1] : NULL, 0x41);
            block_map_insert(&ms.map_block_index, &blocks[i].hashBlock,
                             &blocks[i]);
        }
        struct block_index *tip = &blocks[CHAIN - 1];

        /* Tear the pprev at a mid node ABOVE the attested extent (a genuine
         * missing/detached parent), and separately scramble a HIGHER node's
         * height to prove pass 2 never runs on a refusal. */
        const int broke = 4;                 /* blocks[4].pprev := NULL */
        const int scrambled = 9;             /* label must survive the refusal */
        blocks[broke].pprev = NULL;
        const int32_t poisoned = anchor + 777777;
        blocks[scrambled].nHeight = poisoned;

        CTA_CHECK("relink: torn ancestry presents as a detached island",
                  utxo_recovery_block_ancestry_break(tip) != NULL);

        struct utxo_recovery_ancestry_repair rep =
            utxo_recovery_relink_scrambled_ancestry(&ms, tip);
        CTA_CHECK("relink: a hash-linkage break is REFUSED",
                  rep.result == UTXO_ANCESTRY_REPAIR_REFUSED && rep.fixed == 0);
        CTA_CHECK("relink: refusal names the ancestry-tear typed blocker",
                  blocker_exists(UTXO_RECOVERY_ANCESTRY_TEAR_BLOCKER_ID));
        CTA_CHECK("relink: refusal mutates nothing (higher scramble survives)",
                  blocks[scrambled].nHeight == poisoned);
        CTA_CHECK("relink: refuse_at is the break height above the extent",
                  rep.refuse_at_h == anchor + 1 + broke);

        blocker_reset_for_testing();
        main_state_free(&ms);
    }

    /* ── RELINK CYCLE (pprev lasso): a wrong pprev pointer (the loader's
     * by-height fallback wiring a parent from a scrambled height) makes the walk
     * lap a cycle. A height relabel cannot cure wrong linkage — Floyd detection
     * REFUSES with NO mutation. ── */
    {
        utxo_recovery_set_cold_import_trust_anchor(NULL, -1);
        struct main_state ms;
        main_state_init(&ms);
        enum { CHAIN = 12 };
        struct block_index blocks[CHAIN];
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        for (int i = 0; i < CHAIN; i++) {
            cta_make_block(&blocks[i], anchor + i,
                           i > 0 ? &blocks[i - 1] : NULL, 0x42);
            if (i == 0 && cp)
                memcpy(blocks[0].hashBlock.data, cp->block_hash, 32);
            block_map_insert(&ms.map_block_index, &blocks[i].hashBlock,
                             &blocks[i]);
        }
        struct block_index *tip = &blocks[CHAIN - 1];
        /* Wire a lasso above the anchor: blocks[3].pprev jumps UP to blocks[7],
         * so 7->6->5->4->3->7 loops forever. Scramble a height so the tip
         * presents as an island first. */
        blocks[6].nHeight = anchor + 90000;
        blocks[3].pprev = &blocks[7];
        CTA_CHECK("relink cycle: tip presents as a detached island",
                  utxo_recovery_block_ancestry_break(tip) != NULL);
        struct utxo_recovery_ancestry_repair rep =
            utxo_recovery_relink_scrambled_ancestry(&ms, tip);
        CTA_CHECK("relink cycle: a pprev lasso is REFUSED (no mutation)",
                  rep.result == UTXO_ANCESTRY_REPAIR_REFUSED && rep.fixed == 0);
        CTA_CHECK("relink cycle: the scrambled height survives (nothing mutated)",
                  blocks[6].nHeight == anchor + 90000);
        main_state_free(&ms);
    }

    /* ── RELINK WRONG-TERMINUS: an acyclic chain whose anchor-height node is NOT
     * the compiled checkpoint block is a wrong lineage — REFUSED (never stamp the
     * anchor height onto a non-checkpoint block and fail-open). Only exercised
     * when a checkpoint is compiled in. ── */
    {
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        if (cp) {
            utxo_recovery_set_cold_import_trust_anchor(NULL, -1);
            struct main_state ms;
            main_state_init(&ms);
            enum { CHAIN = 12 };
            struct block_index blocks[CHAIN];
            for (int i = 0; i < CHAIN; i++) {
                cta_make_block(&blocks[i], anchor + i,
                               i > 0 ? &blocks[i - 1] : NULL, 0x43);
                block_map_insert(&ms.map_block_index, &blocks[i].hashBlock,
                                 &blocks[i]);
            }   /* blocks[0] keeps a synthetic hash != cp->block_hash */
            struct block_index *tip = &blocks[CHAIN - 1];
            blocks[5].nHeight = anchor + 600000;   /* scramble -> island */
            CTA_CHECK("relink wrong-terminus: tip presents as a detached island",
                      utxo_recovery_block_ancestry_break(tip) != NULL);
            struct utxo_recovery_ancestry_repair rep =
                utxo_recovery_relink_scrambled_ancestry(&ms, tip);
            CTA_CHECK("relink wrong-terminus: a non-checkpoint terminus is REFUSED",
                      rep.result == UTXO_ANCESTRY_REPAIR_REFUSED && rep.fixed == 0);
            CTA_CHECK("relink wrong-terminus: the scramble survives (no mutation)",
                      blocks[5].nHeight == anchor + 600000);
            main_state_free(&ms);
        }
    }

    return failures;
}
