/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the owner-gated nullifier_backfill_service. The service
 * must be populate-only: it reuses utxo_apply_check_and_insert_nullifiers()
 * and leaves the consensus check path unchanged. */

#include "test/test_core.h"
#include "test/block_fixtures.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "controllers/agent_security_posture.h"
#include "core/uint256.h"
#include "jobs/utxo_apply_delta.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "json/json.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "services/nullifier_backfill_service.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define NB_CHECK(name, expr) do {                                      \
    if (expr) { printf("  nullifier_backfill: %s... OK\n", (name)); } \
    else { printf("  nullifier_backfill: %s... FAIL\n", (name));      \
           failures++; }                                               \
} while (0)

struct nbf_chain {
    struct block bodies[4];
    struct block_index indices[4];
    int n;
};

struct nbf_reader_ctx {
    struct nbf_chain *source;
    struct nbf_chain *replacement;
    int replace_height;
    struct main_state *move_main;
    struct block_index *move_tip;
    int move_after_height;
    bool moved;
};

static void nbf_nf(uint8_t out[32], uint8_t tag, uint8_t mark)
{
    memset(out, 0, 32);
    out[0] = tag;
    out[1] = mark;
    out[31] = 0xBF;
}

static void nbf_txid(struct uint256 *out, int height, int salt)
{
    uint256_set_null(out);
    out->data[0] = (uint8_t)(0x40 + height);
    out->data[1] = (uint8_t)salt;
}

static bool nbf_make_block(struct block *b, int height, int salt)
{
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = (uint32_t)(1700005000u + (uint32_t)height);
    b->header.nBits = 0x1f07ffff;
    b->num_vtx = 1;
    b->vtx = zcl_calloc(1, sizeof(struct transaction), "nbf_vtx");
    if (!b->vtx)
        return false;
    transaction_init(&b->vtx[0]);
    nbf_txid(&b->vtx[0].hash, height, salt);
    return true;
}

static bool nbf_add_sapling_spend(struct transaction *tx,
                                  uint8_t tag, uint8_t mark)
{
    tx->v_shielded_spend =
        zcl_calloc(1, sizeof(struct spend_description), "nbf_sapling");
    if (!tx->v_shielded_spend)
        return false;
    tx->num_shielded_spend = 1;
    nbf_nf(tx->v_shielded_spend[0].nullifier.data, tag, mark);
    return true;
}

static bool nbf_add_joinsplit(struct transaction *tx,
                              uint8_t tag0, uint8_t tag1, uint8_t mark)
{
    tx->v_joinsplit =
        zcl_calloc(1, sizeof(struct js_description), "nbf_sprout");
    if (!tx->v_joinsplit)
        return false;
    tx->num_joinsplit = 1;
    nbf_nf(tx->v_joinsplit[0].nullifiers[0].data, tag0, mark);
    nbf_nf(tx->v_joinsplit[0].nullifiers[1].data, tag1, mark);
    return true;
}

static bool nbf_chain_init_variant(struct nbf_chain *ch, int salt_base)
{
    memset(ch, 0, sizeof(*ch));
    ch->n = 4;
    for (int i = 0; i < ch->n; i++) {
        if (!nbf_make_block(&ch->bodies[i], i, salt_base + i))
            return false;
    }
    if (!nbf_add_sapling_spend(&ch->bodies[1].vtx[0], 0xA1, 0x51) ||
        !nbf_add_joinsplit(&ch->bodies[2].vtx[0], 0xB1, 0xB2, 0x52) ||
        !nbf_add_sapling_spend(&ch->bodies[3].vtx[0], 0xA1, 0x51))
        return false;
    for (int i = 0; i < ch->n; i++) {
        if (i > 0)
            ch->bodies[i].header.hashPrevBlock = ch->indices[i - 1].hashBlock;
        ch->bodies[i].header.hashMerkleRoot =
            compute_merkle_root(&ch->bodies[i].vtx[0].hash, 1);
        block_index_init(&ch->indices[i]);
        block_get_hash(&ch->bodies[i], &ch->indices[i].hashBlock);
        ch->indices[i].phashBlock = &ch->indices[i].hashBlock;
        ch->indices[i].pprev = i > 0 ? &ch->indices[i - 1] : NULL;
        ch->indices[i].nHeight = i;
        ch->indices[i].hashMerkleRoot =
            ch->bodies[i].header.hashMerkleRoot;
        ch->indices[i].nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
        block_index_build_skip(&ch->indices[i]);
    }
    return true;
}

static bool nbf_chain_init(struct nbf_chain *ch)
{
    return nbf_chain_init_variant(ch, 0x10);
}

static void nbf_chain_free(struct nbf_chain *ch)
{
    for (int i = 0; i < ch->n; i++)
        block_free(&ch->bodies[i]);
    memset(ch, 0, sizeof(*ch));
}

static bool nbf_reader(struct block *out, int64_t height,
                       const char *datadir, void *user, bool *found_out)
{
    (void)datadir;
    struct nbf_reader_ctx *ctx = user;
    struct nbf_chain *ch = ctx ? ctx->source : NULL;
    if (found_out)
        *found_out = false;
    if (!out || !ch || !found_out || height < 0 || height >= ch->n)
        return false;
    if (ctx->replacement && height == ctx->replace_height)
        ch = ctx->replacement;
    if (!test_block_copy(out, &ch->bodies[height], "nbf_reader_copy"))
        return false;
    if (ctx->move_main && ctx->move_tip && !ctx->moved &&
        height == ctx->move_after_height) {
        if (!active_chain_move_window_tip(&ctx->move_main->chain_active,
                                          ctx->move_tip))
            return false;
        ctx->moved = true;
    }
    *found_out = true;
    return true;
}

static int64_t nbf_row_count(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int64_t n = -1;

    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM nullifiers",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

static bool nbf_marker_absent(sqlite3 *db, const char *key)
{
    char buf[32];
    size_t len = 0;
    bool found = true;

    return progress_meta_get(db, key, buf, sizeof(buf), &len, &found) &&
           !found;
}

static bool nbf_marker_is(sqlite3 *db, const char *key, const char *want)
{
    char buf[32] = {0};
    size_t len = 0;
    bool found = false;
    size_t want_len = strlen(want);
    return progress_meta_get(db, key, buf, sizeof(buf), &len, &found) &&
           found && len == want_len && memcmp(buf, want, want_len) == 0;
}

static bool nbf_posture_complete(void)
{
    struct json_value root;
    const struct json_value *posture;
    bool ok;

    json_init(&root);
    json_set_object(&root);
    agent_push_security_posture_json(&root, "security_posture", NULL);
    posture = json_get(&root, "security_posture");
    ok = posture &&
         json_get_bool(json_get(posture, "nullifier_history_complete")) &&
         !json_get_bool(json_get(posture, "nullifier_backfill_gap")) &&
         json_get_int(json_get(posture, "nullifier_activation_cursor")) == 0;
    json_free(&root);
    return ok;
}

static bool nbf_candidate_accepted(sqlite3 *db, const struct block *blk,
                                   bool *accepted_out)
{
    struct delta_summary summary;
    bool ok = true;

    if (!db || !blk || !accepted_out)
        return false;
    memset(&summary, 0, sizeof(summary));
    summary.ok = true;
    summary.status = "ok";

    progress_store_tx_lock();
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        progress_store_tx_unlock();
        return false;
    }
    ok = utxo_apply_check_and_insert_nullifiers(db, blk, 3, &summary);
    if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
        ok = false;
    progress_store_tx_unlock();
    if (!ok)
        return false;
    *accepted_out = summary.ok;
    return true;
}

static bool nbf_expected_rows_present(sqlite3 *db)
{
    uint8_t a[32], b[32], c[32];
    bool fa = false, fb = false, fc = false;
    int64_t ha = -1, hb = -1, hc = -1;

    nbf_nf(a, 0xA1, 0x51);
    nbf_nf(b, 0xB1, 0x52);
    nbf_nf(c, 0xB2, 0x52);
    return nullifier_kv_get(db, a, NULLIFIER_POOL_SAPLING, &fa, &ha) &&
           nullifier_kv_get(db, b, NULLIFIER_POOL_SPROUT, &fb, &hb) &&
           nullifier_kv_get(db, c, NULLIFIER_POOL_SPROUT, &fc, &hc) &&
           fa && fb && fc && ha == 1 && hb == 2 && hc == 2 &&
           nbf_row_count(db) == 3;
}

static bool nbf_seed_marker(sqlite3 *db, const char *key, const char *value)
{
    return progress_meta_set(db, key, value, strlen(value));
}

int test_nullifier_backfill_service(void);
int test_nullifier_backfill_service(void)
{
    int failures = 0;
    char dir[256];
    struct nbf_chain ch;
    struct nbf_chain fork;
    struct main_state main;
    struct nbf_reader_ctx reader_ctx = {0};

    test_make_tmpdir(dir, sizeof(dir), "nullifier_backfill", "main");
    NB_CHECK("chain init", nbf_chain_init(&ch));
    NB_CHECK("fork chain init", nbf_chain_init_variant(&fork, 0x30));
    main_state_init(&main);
    NB_CHECK("selected chain installed",
             active_chain_move_window_tip(&main.chain_active,
                                          &ch.indices[ch.n - 1]));
    reader_ctx.source = &ch;
    reader_ctx.replace_height = -1;
    reader_ctx.move_after_height = -1;
    NB_CHECK("progress_store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    NB_CHECK("db handle", db != NULL);
    NB_CHECK("schema ensure", nullifier_kv_ensure_schema(db));

    blocker_clear(UTXO_APPLY_NF_GAP_BLOCKER_ID);
    NB_CHECK("activation marker set",
             nbf_seed_marker(db, NULLIFIER_BACKFILL_ACTIVATION_KEY, "3"));
    utxo_apply_nullifier_gap_blocker_refresh(db);
    NB_CHECK("gap blocker visible before remediation",
             blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));

    bool accepted = false;
    NB_CHECK("pre-backfill duplicate candidate runs",
             nbf_candidate_accepted(db, &ch.bodies[3], &accepted));
    NB_CHECK("pre-backfill duplicate candidate accepted because set is empty",
             accepted);
    NB_CHECK("pre-backfill rollback left set empty", nbf_row_count(db) == 0);

    struct nullifier_backfill_config cfg = {
        .main = &main,
        .progress_db = db,
        .datadir = dir,
        .read_block = nbf_reader,
        .read_block_user = &reader_ctx,
    };
    struct nullifier_backfill_report rep;
    struct zcl_result r = nullifier_backfill_service_run(&cfg, &rep);
    NB_CHECK("service run ok", r.ok);
    NB_CHECK("service walked expected range",
             rep.completed && !rep.already_complete &&
             rep.start_height == 0 && rep.target_exclusive == 3 &&
             rep.blocks_scanned == 3 && rep.next_height == 3);
    NB_CHECK("expected nullifier rows inserted", nbf_expected_rows_present(db));
    NB_CHECK("activation completion marker is explicit zero",
             nbf_marker_is(db, NULLIFIER_BACKFILL_ACTIVATION_KEY, "0"));
    NB_CHECK("resume marker cleared",
             nbf_marker_absent(db, NULLIFIER_BACKFILL_RESUME_KEY));
    NB_CHECK("gap blocker cleared",
             !blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));
    NB_CHECK("security posture reports nullifier history complete",
             nbf_posture_complete());

    accepted = true;
    NB_CHECK("post-backfill duplicate candidate runs",
             nbf_candidate_accepted(db, &ch.bodies[3], &accepted));
    NB_CHECK("post-backfill duplicate candidate rejected", !accepted);
    NB_CHECK("post-backfill rollback kept exact set", nbf_row_count(db) == 3);

    struct nullifier_backfill_report rep2;
    r = nullifier_backfill_service_run(&cfg, &rep2);
    NB_CHECK("idempotent second run ok", r.ok);
    NB_CHECK("idempotent second run no-op",
             rep2.completed && rep2.already_complete &&
             rep2.blocks_scanned == 0 && nbf_row_count(db) == 3);

    NB_CHECK("preloaded-v3 setup restores positive boundary",
             nbf_seed_marker(db, NULLIFIER_BACKFILL_ACTIVATION_KEY, "3"));
    NB_CHECK("preloaded-v3 setup removes chain receipt",
             progress_meta_delete(db, NULLIFIER_BACKFILL_CHAIN_KEY));
    {
        uint8_t rogue[32];
        nbf_nf(rogue, 0xE1, 0x7F);
        NB_CHECK("preloaded-v3 setup seeds unbound extra row",
                 nullifier_kv_add(db, rogue, NULLIFIER_POOL_SAPLING, 0) &&
                 nbf_row_count(db) == 4);
    }
    struct nullifier_backfill_report preloaded_rep;
    r = nullifier_backfill_service_run(&cfg, &preloaded_rep);
    NB_CHECK("preloaded-v3 unbound rows are rebuilt", r.ok);
    NB_CHECK("preloaded-v3 scan removes extras and clears boundary",
             preloaded_rep.completed && preloaded_rep.blocks_scanned == 3 &&
             nbf_expected_rows_present(db) &&
             nbf_marker_is(db, NULLIFIER_BACKFILL_ACTIVATION_KEY, "0"));

    NB_CHECK("resume setup clears rows",
             nullifier_kv_delete_range(db, 0, 10) && nbf_row_count(db) == 0);
    {
        uint8_t a[32];
        nbf_nf(a, 0xA1, 0x51);
        NB_CHECK("resume setup seeds completed h=1 row",
                 nullifier_kv_add(db, a, NULLIFIER_POOL_SAPLING, 1));
    }
    NB_CHECK("resume setup activation marker",
             nbf_seed_marker(db, NULLIFIER_BACKFILL_ACTIVATION_KEY, "3"));
    NB_CHECK("resume setup cursor marker",
             nbf_seed_marker(db, NULLIFIER_BACKFILL_RESUME_KEY, "2"));

    /* dump_state_json (`z23 dumpstate nullifier_backfill`) while the
     * two durable markers are seeded mid-run: status must read
     * "in_progress" (resume_cursor 2 < activation_cursor 3). */
    {
        struct json_value v = {0};
        json_set_object(&v);
        bool ok = nullifier_backfill_dump_state_json(&v, NULL);
        const struct json_value *status = json_get(&v, "status");
        const struct json_value *activation =
            json_get(&v, "activation_cursor");
        const struct json_value *resume = json_get(&v, "resume_cursor");
        bool shape_ok = ok && status &&
                        strcmp(json_get_str(status), "in_progress") == 0 &&
                        activation && json_get_int(activation) == 3 &&
                        resume && json_get_int(resume) == 2;
        json_free(&v);
        NB_CHECK("dump_state_json reports in_progress with cursors",
                 shape_ok);
    }

    struct nullifier_backfill_report rep3;
    r = nullifier_backfill_service_run(&cfg, &rep3);
    NB_CHECK("resume run ok", r.ok);
    NB_CHECK("resume run starts at persisted next height",
             rep3.completed && rep3.start_height == 2 &&
             rep3.target_exclusive == 3 && rep3.blocks_scanned == 1 &&
             rep3.next_height == 3);
    NB_CHECK("resume run restored expected set", nbf_expected_rows_present(db));
    NB_CHECK("resume run persists zero and clears resume marker",
             nbf_marker_is(db, NULLIFIER_BACKFILL_ACTIVATION_KEY, "0") &&
             nbf_marker_absent(db, NULLIFIER_BACKFILL_RESUME_KEY));

    {
        struct json_value v = {0};
        json_set_object(&v);
        bool ok = nullifier_backfill_dump_state_json(&v, NULL);
        const struct json_value *status = json_get(&v, "status");
        bool shape_ok = ok && status &&
                        strcmp(json_get_str(status), "complete") == 0;
        json_free(&v);
        NB_CHECK("dump_state_json reports explicit complete post-run",
                 shape_ok);
    }

    /* A node.db height lookup is only a body location.  A body from a stale
     * fork at that same height must fail its selected-header hash before it
     * can contribute nullifiers or clear the positive gap marker. */
    NB_CHECK("stale-fork setup clears rows",
             nullifier_kv_delete_range(db, 0, 10) && nbf_row_count(db) == 0);
    NB_CHECK("stale-fork setup activation marker",
             nbf_seed_marker(db, NULLIFIER_BACKFILL_ACTIVATION_KEY, "3"));
    NB_CHECK("stale-fork setup clears resume",
             progress_meta_delete(db, NULLIFIER_BACKFILL_RESUME_KEY));
    reader_ctx.replacement = &fork;
    reader_ctx.replace_height = 1;
    struct nullifier_backfill_report fork_rep;
    r = nullifier_backfill_service_run(&cfg, &fork_rep);
    NB_CHECK("same-height stale-fork body is rejected", !r.ok);
    NB_CHECK("stale-fork body cannot publish completeness",
             !fork_rep.completed &&
             nbf_marker_is(db, NULLIFIER_BACKFILL_ACTIVATION_KEY, "3") &&
             nbf_marker_is(db, NULLIFIER_BACKFILL_RESUME_KEY, "1"));
    reader_ctx.replacement = NULL;
    reader_ctx.replace_height = -1;

    /* Move to a different selected tip only after the last old-generation
     * body was returned.  Every height verifies, so only the final CAS can
     * catch this.  It must discard the rows and leave a positive marker. */
    NB_CHECK("chain-change setup clears rows",
             nullifier_kv_delete_range(db, 0, 10) && nbf_row_count(db) == 0);
    NB_CHECK("chain-change setup activation marker",
             nbf_seed_marker(db, NULLIFIER_BACKFILL_ACTIVATION_KEY, "3"));
    NB_CHECK("chain-change setup clears resume",
             progress_meta_delete(db, NULLIFIER_BACKFILL_RESUME_KEY));
    reader_ctx.move_main = &main;
    reader_ctx.move_tip = &fork.indices[fork.n - 1];
    reader_ctx.move_after_height = 2;
    reader_ctx.moved = false;
    struct nullifier_backfill_report changed_rep;
    r = nullifier_backfill_service_run(&cfg, &changed_rep);
    NB_CHECK("final CAS rejects changed selected chain",
             !r.ok && reader_ctx.moved && !changed_rep.completed);
    NB_CHECK("changed generation is discarded and remains incomplete",
             nbf_row_count(db) == 0 &&
             nbf_marker_is(db, NULLIFIER_BACKFILL_ACTIVATION_KEY, "3") &&
             nbf_marker_is(db, NULLIFIER_BACKFILL_RESUME_KEY, "0"));
    reader_ctx.move_main = NULL;
    reader_ctx.move_tip = NULL;
    reader_ctx.move_after_height = -1;

    /* A resume cursor belongs to the persisted fork generation.  Returning
     * to the original chain must reset it to zero rather than trust the
     * fork's completed prefix; this invocation then safely restarts. */
    NB_CHECK("resume-fork switches selected chain",
             active_chain_move_window_tip(&main.chain_active,
                                          &ch.indices[ch.n - 1]));
    {
        uint8_t a[32];
        nbf_nf(a, 0xA1, 0x51);
        NB_CHECK("resume-fork seeds stale prefix row",
                 nullifier_kv_add(db, a, NULLIFIER_POOL_SAPLING, 1));
    }
    NB_CHECK("resume-fork seeds stale cursor",
             nbf_seed_marker(db, NULLIFIER_BACKFILL_RESUME_KEY, "2"));
    struct nullifier_backfill_report rebound_rep;
    r = nullifier_backfill_service_run(&cfg, &rebound_rep);
    NB_CHECK("fork-bound resume is discarded then restarted", r.ok);
    NB_CHECK("resume restart proves full selected prefix",
             rebound_rep.completed && rebound_rep.start_height == 0 &&
             rebound_rep.blocks_scanned == 3 &&
             nbf_expected_rows_present(db) &&
             nbf_marker_is(db, NULLIFIER_BACKFILL_ACTIVATION_KEY, "0") &&
             nbf_marker_absent(db, NULLIFIER_BACKFILL_RESUME_KEY));

    NB_CHECK("missing activation marker setup",
             progress_meta_delete(db, NULLIFIER_BACKFILL_ACTIVATION_KEY));
    struct nullifier_backfill_report missing_rep;
    r = nullifier_backfill_service_run(&cfg, &missing_rep);
    NB_CHECK("missing activation marker is unknown, never complete",
             !r.ok && !missing_rep.completed &&
             !missing_rep.already_complete);

    progress_store_close();
    blocker_clear(UTXO_APPLY_NF_GAP_BLOCKER_ID);
    main_state_free(&main);
    nbf_chain_free(&fork);
    nbf_chain_free(&ch);
    test_cleanup_tmpdir(dir);
    return failures;
}
