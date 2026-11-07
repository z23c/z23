/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Truth table for rescanwitnesses' consensus guard. A rebuilt Sapling tree is
 * persistable only when it matches a non-zero header root and every witness root
 * agrees with that tree.
 */

#include "test/test_core.h"
#include "controllers/wallet_rescan_controller_internal.h"
#include "storage/anchor_kv.h"
#include "storage/progress_store.h"
#include "config/db_service.h"
#include "config/runtime.h"

#include <sqlite3.h>
#include <sys/stat.h>
#include <string.h>
#ifndef _WIN32
#include <sys/wait.h>
void rescan_test_rollback(struct node_db *db);
#endif

static struct uint256 test_root(uint8_t seed)
{
    struct uint256 r;
    for (size_t i = 0; i < sizeof(r.data); i++)
        r.data[i] = (uint8_t)(seed + i);
    return r;
}

static void check_case(const char *name, bool got, bool want, int *failures)
{
    printf("%s... ", name);
    if (got == want) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        (*failures)++;
    }
}

static bool install_replay_endpoint_slots(struct active_chain *chain,
                                          struct block_index *older,
                                          struct block_index *recent)
{
    return active_chain_install_tip_slot(chain, older) &&
           active_chain_install_tip_slot(chain, recent);
}

static void build_sapling_body_with_one_commitment(struct block *body)
{
    block_init(body);
    body->vtx = calloc(1, sizeof(*body->vtx));
    body->num_vtx = body->vtx ? 1 : 0;
    if (body->vtx) {
        transaction_init(&body->vtx[0]);
        body->vtx[0].version = SAPLING_TX_VERSION;
        body->vtx[0].overwintered = true;
        body->vtx[0].version_group_id = SAPLING_VERSION_GROUP_ID;
        body->vtx[0].v_shielded_output =
            calloc(1, sizeof(*body->vtx[0].v_shielded_output));
        if (body->vtx[0].v_shielded_output) {
            body->vtx[0].num_shielded_output = 1;
            body->vtx[0].v_shielded_output[0].cm = test_root(0x71);
        }
    }
}

static bool decoded_body_appends_all_commitments(void)
{
    struct block body;
    build_sapling_body_with_one_commitment(&body);
    struct byte_stream body_wire;
    stream_init(&body_wire, 2048);
    bool body_serialized = body.vtx && body.vtx[0].v_shielded_output &&
                           block_serialize(&body, &body_wire);
    struct byte_stream body_read;
    stream_init_from_data(&body_read, body_wire.data, body_wire.size);
    struct block decoded;
    block_init(&decoded);
    bool body_decoded = body_serialized && block_deserialize(&decoded,
                                                             &body_read);
    struct incremental_merkle_tree replay_tree;
    sapling_tree_init(&replay_tree);
    struct incremental_witness replay_witness;
    memset(&replay_witness, 0, sizeof(replay_witness));
    bool replay_active = false;
    struct db_sapling_note replay_note;
    memset(&replay_note, 0, sizeof(replay_note));
    if (body.vtx && body.vtx[0].v_shielded_output)
        memcpy(replay_note.cm, body.vtx[0].v_shielded_output[0].cm.data, 32);
    int replay_built = 0;
    size_t replayed = body_decoded ? rescan_append_block_commitments(
        &decoded, &replay_tree, &replay_witness, &replay_active,
        &replay_note, 1, &replay_built) : 0;
    bool appended = replayed == 1 && replay_built == 1 && replay_active &&
                    incremental_tree_size(&replay_tree) == 1;
    block_free(&decoded);
    stream_free(&body_wire);
    block_free(&body);
    return appended;
}

static bool attempt_prior_anchor_seed_shortcut(
    sqlite3 **db, struct active_chain *chain, struct block_index *prior,
    struct db_sapling_note *note, struct incremental_merkle_tree *anchored,
    struct incremental_merkle_tree *seeded, int *replay_start,
    int *seed_height)
{
    return sqlite3_open(":memory:", db) == SQLITE_OK &&
        anchor_kv_ensure_schema(*db) && anchor_kv_initialize_history(*db, 0) &&
        anchor_kv_add_tree(*db, ANCHOR_POOL_SAPLING, anchored, 499999) &&
        active_chain_install_tip_slot(chain, prior) &&
        rescan_seed_before_oldest_note_from_db(
            *db, chain, note, 1, 476969, seeded, replay_start,
            seed_height);
}

static bool anchor_seeded_at_oldest_note(bool seed_ok, int replay_start,
                                         int seed_height,
                                         struct uint256 *seeded_root,
                                         struct uint256 *anchor_root)
{
    return seed_ok && replay_start == 500001 && seed_height == 500000 &&
           uint256_eq(seeded_root, anchor_root);
}

static bool rescan_changed_notes_case(const struct wallet_rpc_context *ctx,
    const struct incremental_merkle_tree *tree, const struct incremental_witness *witness,
    const bool *active, const struct db_sapling_note *note, const struct block_index *tip,
    const struct uint256 *root)
{
    struct db_sapling_note extra = *note;
    extra.txid[0] ^= 0x80;
    extra.nullifier[0] ^= 0x80;
    if (!db_sapling_note_save(ctx->node_db, &extra)) return false;
    struct wallet_witness_outcome out;
    bool refused = !rescan_test_commit(ctx, tree, witness, active, note, 1, 1,
                                        1, &tip->hashBlock, root, &out) &&
                   out.status == WALLET_WITNESS_PERSIST_FAILED;
    return db_sapling_note_delete(ctx->node_db, extra.txid, extra.output_index) && refused;
}

static bool rescan_commit_refusals(const struct wallet_rpc_context *ctx,
    const struct incremental_merkle_tree *tree, const struct incremental_witness *witness,
    const bool *active, const struct db_sapling_note *note, const struct block_index *tip,
    const struct uint256 *root)
{
    bool ok = true;
    struct wallet_witness_outcome out;
    if (ok) ok = !rescan_test_commit(ctx, tree, witness, active, note, 1, 0,
                                      1, &tip->hashBlock, root, &out) &&
                 out.status == WALLET_WITNESS_INCOMPLETE;
    struct uint256 wrong = tip->hashBlock;
    wrong.data[0] ^= 1;
    if (ok) ok = !rescan_test_commit(ctx, tree, witness, active, note, 1, 1,
                                      1, &wrong, root, &out) &&
                 out.status == WALLET_WITNESS_ENDPOINT_CHANGED;
    if (ok) ok = rescan_changed_notes_case(ctx, tree, witness, active, note, tip, root);
    zcl_mutex_lock(&ctx->main_state->cs_main);
    bool blocked = !rescan_test_commit(ctx, tree, witness, active, note, 1, 1,
                                       1, &tip->hashBlock, root, &out) &&
                   out.status == WALLET_WITNESS_BUSY;
    zcl_mutex_unlock(&ctx->main_state->cs_main);
    sqlite3_mutex *mu = sqlite3_db_mutex(ctx->node_db->db);
    sqlite3_mutex_enter(mu);
    bool db_blocked = !rescan_test_commit(ctx, tree, witness, active, note, 1, 1,
                                          1, &tip->hashBlock, root, &out) &&
                      out.status == WALLET_WITNESS_BUSY;
    sqlite3_mutex_leave(mu);
    return db_blocked && blocked && ok;
}

static bool rescan_commit_exercise(const struct wallet_rpc_context *ctx,
    const struct incremental_merkle_tree *tree, const struct incremental_witness *witness,
    const bool *active, const struct db_sapling_note *note, const struct block_index *tip,
    const struct uint256 *root)
{
    bool ok = true;
    struct wallet_witness_outcome out;
    ok = rescan_commit_refusals(ctx, tree, witness, active, note, tip, root);
    if (ok) ok = sqlite3_exec(ctx->node_db->db, "CREATE TRIGGER fail_witness BEFORE UPDATE ON wallet_sapling_notes BEGIN SELECT RAISE(ABORT,'injected'); END", NULL, NULL, NULL) == SQLITE_OK;
    if (ok) ok = !rescan_test_commit(ctx, tree, witness, active, note, 1, 1,
                                      1, &tip->hashBlock, root, &out) &&
                 out.status == WALLET_WITNESS_PERSIST_FAILED;
    uint8_t *blob = NULL; size_t len = 0; int height = -1;
    if (ok) ok = !db_sapling_note_load_witness(ctx->node_db, note->txid, 0, &blob, &len, &height);
    bool present = false; size_t tree_len = 0;
    if (ok) ok = node_db_state_read(ctx->node_db, "sapling_tree", NULL, 0, &tree_len, &present) && !present;
    free(blob); blob = NULL;
    if (ok) ok = sqlite3_exec(ctx->node_db->db, "DROP TRIGGER fail_witness", NULL, NULL, NULL) == SQLITE_OK;
    if (ok) ok = rescan_test_commit(ctx, tree, witness, active, note, 1, 1,
                                     1, &tip->hashBlock, root, &out) &&
                 out.status == WALLET_WITNESS_COMPLETE && out.witnesses_saved == 1;
    if (ok) ok = db_sapling_note_load_witness(ctx->node_db, note->txid, 0, &blob, &len, &height) && len > 0 && height == 1;
    free(blob);
    return ok;
}

#ifndef _WIN32
static int witness_deny_rollback(void *ctx, int action, const char *a,
                                 const char *b, const char *c, const char *d)
{
    (void)ctx; (void)b; (void)c; (void)d;
    return action == SQLITE_TRANSACTION && a && strcmp(a, "ROLLBACK") == 0 ? SQLITE_DENY : SQLITE_OK;
}

static bool witness_failstop_empty_db(const char *path)
{
    sqlite3 *db = NULL; sqlite3_stmt *s = NULL;
    bool ok = sqlite3_open(path, &db) == SQLITE_OK &&
        sqlite3_prepare_v2(db, "SELECT count(*) FROM witness_fatal_test", -1, &s, NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW && sqlite3_column_int(s, 0) == 0;
    if (s) sqlite3_finalize(s);
    if (db) sqlite3_close(db);
    return ok;
}

static bool witness_failstop_fixture(void)
{
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "wallet", "witness_failstop");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    pid_t child = fork();
    if (child == 0) {
        struct node_db db = {0};
        if (!node_db_open(&db, path) ||
            sqlite3_exec(db.db, "CREATE TABLE witness_fatal_test(v INTEGER)", NULL, NULL, NULL) != SQLITE_OK ||
            !node_db_begin_immediate(&db) ||
            sqlite3_exec(db.db, "INSERT INTO witness_fatal_test VALUES(1)", NULL, NULL, NULL) != SQLITE_OK ||
            sqlite3_set_authorizer(db.db, witness_deny_rollback, NULL) != SQLITE_OK) _exit(2);
        rescan_test_rollback(&db);
        _exit(3);
    }
    int status = 0;
    bool ok = child > 0 && waitpid(child, &status, 0) == child &&
        WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE;
    if (ok) ok = witness_failstop_empty_db(path);
    (void)test_rm_rf_recursive(dir);
    return ok;
}
#endif

static bool archive_empty_paths(struct wallet_rpc_context *ctx,
    const struct wallet_witness_endpoint *endpoint, struct wallet_witness_outcome *out)
{
    char too_long[4096]; memset(too_long, 120, sizeof(too_long)); too_long[sizeof(too_long) - 1] = 0;
    return !wallet_rescan_witnesses_at_archive(ctx, endpoint, NULL, out) &&
        !wallet_rescan_witnesses_at_archive(ctx, endpoint, "", out) &&
        !wallet_rescan_witnesses_at_archive(ctx, endpoint, too_long, out) &&
        wallet_rescan_witnesses_at_archive(ctx, endpoint, ctx->datadir, out);
}

static bool rescan_fixture_empty(struct wallet_rpc_context *ctx, struct node_db *db,
                                  const struct db_sapling_note *note)
{
    struct wallet_witness_outcome out = {.status = WALLET_WITNESS_COMPLETE, .endpoint_height = 1};
    if (wallet_rescan_witnesses_at(ctx, NULL, &out) || out.status == WALLET_WITNESS_COMPLETE || out.endpoint_height != -1) return false;
    const struct block_index *tip = active_chain_at(&ctx->main_state->chain_active, 1);
    if (!tip || !tip->phashBlock) return false;
    struct wallet_witness_endpoint endpoint = {.height = 1, .hash = *tip->phashBlock, .root = tip->hashFinalSaplingRoot};
    if (!archive_empty_paths(ctx, &endpoint, &out)) return false;
    endpoint.hash.data[0] ^= 1;
    bool ok = !wallet_rescan_witnesses_at(ctx, &endpoint, &out) && out.status == WALLET_WITNESS_ENDPOINT_CHANGED;
    endpoint.hash.data[0] ^= 1; endpoint.root.data[0] ^= 1;
    if (ok) ok = !wallet_rescan_witnesses_at(ctx, &endpoint, &out) && out.status == WALLET_WITNESS_ENDPOINT_CHANGED;
    endpoint.root.data[0] ^= 1;
    if (ok) ok = wallet_rescan_witnesses_at(ctx, &endpoint, &out) &&
        out.status == WALLET_WITNESS_COMPLETE && out.endpoint_height == 1;
    return ok && db_sapling_note_save(db, note);
}

static bool rescan_fixture_note_endpoint_refusal(struct wallet_rpc_context *ctx,
    struct node_db *db, const struct db_sapling_note *note)
{
    const struct block_index *tip = active_chain_at(&ctx->main_state->chain_active, 1);
    if (!tip || !tip->phashBlock) return false;
    struct wallet_witness_endpoint endpoint = {.height = 1, .hash = *tip->phashBlock,
        .root = tip->hashFinalSaplingRoot};
    endpoint.hash.data[0] ^= 1;
    struct wallet_witness_outcome out;
    bool ok = !wallet_rescan_witnesses_at(ctx, &endpoint, &out) &&
        out.status == WALLET_WITNESS_ENDPOINT_CHANGED;
    uint8_t *blob = NULL; size_t len = 0; int height = -1;
    if (ok) ok = !db_sapling_note_load_witness(db, note->txid, note->output_index, &blob, &len, &height);
    free(blob);
    return ok;
}

static bool rescan_fixture_empty_and_refusal(struct wallet_rpc_context *ctx,
    struct node_db *db, const struct db_sapling_note *note)
{
    return rescan_fixture_empty(ctx, db, note) &&
           rescan_fixture_note_endpoint_refusal(ctx, db, note);
}

bool rescan_test_resolve_archive(const struct wallet_rpc_context *, const char *, char *, size_t);
bool rescan_test_replay_archive(const struct wallet_rpc_context *, int, int, const char *, size_t *);

static bool archive_fixture_write(const char *dir, const uint8_t *cm)
{
    char blocks[320], file[384];
    snprintf(blocks, sizeof(blocks), "%s/blocks", dir);
    snprintf(file, sizeof(file), "%s/blk00000.dat", blocks);
    struct block body;
    build_sapling_body_with_one_commitment(&body);
    struct byte_stream wire;
    stream_init(&wire, 2048);
    bool ok = body.vtx && body.vtx[0].v_shielded_output;
    if (ok && cm) memcpy(body.vtx[0].v_shielded_output[0].cm.data, cm, 32);
    if (ok) ok = block_serialize(&body, &wire) && mkdir(blocks, 0700) == 0;
    FILE *f = ok ? fopen(file, "wb") : NULL;
    if (!f) ok = false;
    if (f) {
        if (fwrite(wire.data, 1, wire.size, f) != wire.size) ok = false;
        if (fclose(f) != 0) ok = false;
    }
    stream_free(&wire);
    block_free(&body);
    return ok;
}

static bool archive_body_fixture(const struct wallet_rpc_context *ctx, struct block_index *tip)
{
    char dir[256], selected[256];
    test_make_tmpdir(dir, sizeof(dir), "wallet", "witness_archive");
    bool ok = archive_fixture_write(dir, NULL);
    struct uint256 old_root = tip->hashFinalSaplingRoot;
    int old_file = tip->nFile;
    unsigned int old_pos = tip->nDataPos;
    tip->hashFinalSaplingRoot = test_root(0x91);
    tip->nFile = 0; tip->nDataPos = 0;
    size_t count = 0;
    if (ok) ok = rescan_test_resolve_archive(ctx, dir, selected, sizeof(selected)) &&
        strcmp(selected, dir) == 0 && strcmp(selected, ctx->datadir) != 0 &&
        !rescan_test_replay_archive(ctx, 1, 1, ctx->datadir, NULL) &&
        rescan_test_replay_archive(ctx, 1, 1, dir, &count) && count == 1;
    tip->hashFinalSaplingRoot = old_root;
    tip->nFile = old_file; tip->nDataPos = old_pos;
    return test_rm_rf_recursive(dir) == 0 && ok;
}


static bool rescan_fixture_replay(const struct wallet_rpc_context *ctx, struct block_index *tip)
{
    bool ok = true;
    struct uint256 saved_root = tip->hashFinalSaplingRoot;
    struct incremental_merkle_tree empty_tree;
    sapling_tree_init(&empty_tree);
    incremental_tree_root(&empty_tree, &tip->hashFinalSaplingRoot);
    tip->nFile = -1;
    if (ok) ok = rescan_test_replay(ctx, 1, 1);
    tip->hashFinalSaplingRoot = saved_root;
    if (ok) ok = !rescan_test_replay(ctx, 1, 1);
    return ok;
}

static bool archive_witness_loaded(struct node_db *db, const struct db_sapling_note *note,
                                   const struct uint256 *expected)
{
    uint8_t *blob = NULL; size_t len = 0; int height = -1;
    bool ok = db_sapling_note_load_witness(db, note->txid, note->output_index,
                                           &blob, &len, &height) && blob && height == 1;
    struct incremental_merkle_tree empty;
    sapling_tree_init(&empty);
    struct incremental_witness witness;
    struct byte_stream stream;
    if (ok) {
        stream_init_from_data(&stream, blob, len);
        ok = incremental_witness_deserialize(&witness, &stream,
            SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH, empty.combine, empty.uncommitted);
    }
    if (ok) {
        struct uint256 root;
        incremental_witness_root(&witness, &root);
        ok = uint256_eq(&root, expected);
    }
    free(blob);
    return ok;
}

static bool archive_public_verify(struct wallet_rpc_context *ctx,
    const struct wallet_witness_endpoint *endpoint, const struct db_sapling_note *note,
    const char *dir)
{
    struct wallet_witness_outcome out;
    bool ok = !wallet_rescan_witnesses_at_archive(ctx, endpoint, ctx->datadir, &out) &&
        out.status != WALLET_WITNESS_COMPLETE;
    uint8_t *blob = NULL; size_t len = 0; int height = -1;
    if (ok) ok = !db_sapling_note_load_witness(ctx->node_db, note->txid, note->output_index,
                                                &blob, &len, &height);
    free(blob);
    if (ok) ok = wallet_rescan_witnesses_at_archive(ctx, endpoint, dir, &out) &&
        out.status == WALLET_WITNESS_COMPLETE && out.notes_total == 1 &&
        out.witnesses_built == 1 && out.witnesses_saved == 1 && out.endpoint_height == 1 &&
        archive_witness_loaded(ctx->node_db, note, &endpoint->root);
    return ok;
}

static bool archive_public_witness_fixture(struct wallet_rpc_context *ctx,
    struct block_index *tip, const struct db_sapling_note *note)
{
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "wallet", "witness_public_archive");
    bool ok = archive_fixture_write(dir, note->cm);
    int old_file = tip->nFile; unsigned int old_pos = tip->nDataPos;
    tip->nFile = 0; tip->nDataPos = 0;
    struct chain_params *params = (struct chain_params *)chain_params_get();
    int old_activation = params->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight;
    params->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight = 1;
    bool progress_open = progress_store_open(dir);
    if (ok) ok = progress_open && db_sapling_note_clear_witness(ctx->node_db, note->txid, note->output_index);
    struct wallet_witness_endpoint endpoint = {.height = 1, .hash = *tip->phashBlock,
        .root = tip->hashFinalSaplingRoot};
    if (ok) ok = archive_public_verify(ctx, &endpoint, note, dir);
    if (progress_open) progress_store_close();
    params->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight = old_activation;
    tip->nFile = old_file; tip->nDataPos = old_pos;
    return test_rm_rf_recursive(dir) == 0 && ok;
}

static bool rescan_fixture_cases(struct wallet_rpc_context *ctx, struct block_index *tip,
    const struct db_sapling_note *note, const struct incremental_merkle_tree *tree,
    const struct incremental_witness *witness, const struct uint256 *root)
{
    bool ok = rescan_fixture_replay(ctx, tip);
    if (ok) ok = archive_body_fixture(ctx, tip);
    if (ok) ok = rescan_fixture_empty_and_refusal(ctx, ctx->node_db, note);
    bool active = true;
    if (ok) ok = rescan_commit_exercise(ctx, tree, witness, &active, note, tip, root);
    if (ok) ok = archive_public_witness_fixture(ctx, tip, note);
    return ok;
}

static bool rescan_commit_fixture(void)
{
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "wallet", "witness_commit");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db db = {0};
    if (!node_db_open(&db, path)) return false;
    struct db_service svc;
    db_service_init(&svc);
    bool started = db_service_attach(&svc, &db) && db_service_start_test_worker(&svc);
    struct app_runtime_context runtime = {.db_service = &svc};
    app_runtime_set_current(&runtime);
    struct main_state ms = {0};
    main_state_init(&ms);
    struct wallet *wallet = zcl_calloc(1, sizeof(*wallet), "witness test wallet");
    if (wallet) wallet_init(wallet);
    uint8_t seed[32] = {1}, diversifier[11], pk_d[32];
    bool ok = started && wallet && sapling_keystore_set_seed(&wallet->sapling_keys, seed) &&
        sapling_keystore_new_address(&wallet->sapling_keys, diversifier, pk_d);
    struct db_sapling_note note = {0};
    if (ok) {
        memset(note.txid, 1, 32); note.nullifier[0] = 1; note.rcm[0] = 1; note.value = 10; note.block_height = 1;
        memcpy(note.diversifier, diversifier, 11); memcpy(note.pk_d, pk_d, 32);
        memcpy(note.ivk, wallet->sapling_keys.keys[0].ivk, 32);
        ok = sapling_compute_cm(note.diversifier, note.pk_d, note.value, note.rcm, note.cm);
    }
    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    struct uint256 cm, root;
    memcpy(cm.data, note.cm, 32);
    incremental_tree_append(&tree, &cm);
    incremental_tree_root(&tree, &root);
    struct incremental_witness witness;
    incremental_witness_init(&witness, &tree);
    struct block_index tip;
    block_index_init(&tip);
    tip.nHeight = 1; tip.hashBlock = test_root(0x61); tip.phashBlock = &tip.hashBlock;
    tip.hashFinalSaplingRoot = root;
    ok = ok && active_chain_install_tip_slot(&ms.chain_active, &tip);
    struct wallet_rpc_context ctx = {.wallet = wallet, .main_state = &ms, .node_db = &db, .datadir = dir};
    if (ok) ok = rescan_fixture_cases(&ctx, &tip, &note, &tree, &witness, &root);
    app_runtime_set_current(NULL);
    if (started) db_service_stop(&svc);
    if (wallet) { wallet_free(wallet); free(wallet); }
    main_state_free(&ms);
    node_db_close(&db);
    return test_rm_rf_recursive(dir) == 0 && ok;
}

int test_rescanwitnesses_diverge_guard(void)
{
    printf("\n=== rescanwitnesses divergence guard ===\n");
    int failures = 0;
    check_case("partial and failed saves roll back; complete save persists",
               rescan_commit_fixture(), true, &failures);

    struct uint256 root = test_root(0x11);
    struct uint256 same = root;
    struct uint256 other = test_root(0x22);
    struct uint256 zero = {{0}};

    check_case("matching non-zero root with zero mismatches is valid",
               rescan_result_consensus_valid(&root, &same, 0), true,
               &failures);
    check_case("all-zero header root is invalid",
               rescan_result_consensus_valid(&root, &zero, 0), false,
               &failures);
    check_case("different header root is invalid",
               rescan_result_consensus_valid(&root, &other, 0), false,
               &failures);
    check_case("positive witness mismatch count is invalid",
               rescan_result_consensus_valid(&root, &same, 1), false,
               &failures);
    check_case("negative witness mismatch count is invalid",
               rescan_result_consensus_valid(&root, &same, -1), false,
               &failures);
    check_case("NULL rebuilt root is invalid",
               rescan_result_consensus_valid(NULL, &same, 0), false,
               &failures);
    check_case("NULL header root is invalid",
               rescan_result_consensus_valid(&root, NULL, 0), false,
               &failures);

    struct block_index addressable;
    block_index_init(&addressable);
    addressable.hashBlock = test_root(0x31);
    addressable.phashBlock = &addressable.hashBlock;
    addressable.hashFinalSaplingRoot = root;
    addressable.nFile = 0;
    addressable.nStatus = 0;
    check_case("durable coordinates remain recoverable without HAVE_DATA",
               rescan_endpoint_header_addressable(&addressable), true,
               &failures);
    addressable.nFile = -1;
    check_case("missing durable file coordinate is not addressable",
               rescan_endpoint_header_addressable(&addressable), false,
               &failures);
    addressable.nFile = 0;
    addressable.hashFinalSaplingRoot = zero;
    check_case("zero Sapling root is not a recovery endpoint",
               rescan_endpoint_header_addressable(&addressable), false,
               &failures);

    struct active_chain endpoint_chain;
    active_chain_init(&endpoint_chain);
    struct block_index older_endpoint;
    block_index_init(&older_endpoint);
    older_endpoint.nHeight = 102;
    older_endpoint.hashBlock = test_root(0x32);
    older_endpoint.phashBlock = &older_endpoint.hashBlock;
    older_endpoint.hashFinalSaplingRoot = root;
    older_endpoint.nFile = 0;
    struct block_index recent_endpoint;
    block_index_init(&recent_endpoint);
    recent_endpoint.nHeight = 103;
    recent_endpoint.hashBlock = test_root(0x33);
    recent_endpoint.phashBlock = &recent_endpoint.hashBlock;
    recent_endpoint.hashFinalSaplingRoot = root;
    recent_endpoint.nFile = 0;
    bool endpoints_installed = install_replay_endpoint_slots(
        &endpoint_chain, &older_endpoint, &recent_endpoint);
    int endpoint_height = -1;
    const struct block_index *selected = rescan_find_replay_endpoint(
        &endpoint_chain, 103, &endpoint_height);
    check_case("recent note selects the addressable tip inside finality window",
               endpoints_installed && selected == &recent_endpoint &&
               endpoint_height == 103, true, &failures);
    recent_endpoint.hashFinalSaplingRoot = zero;
    selected = rescan_find_replay_endpoint(&endpoint_chain, 102,
                                            &endpoint_height);
    check_case("incomplete tip falls back to newest addressable endpoint",
               selected == &older_endpoint && endpoint_height == 102, true,
               &failures);
    active_chain_free(&endpoint_chain);

#ifndef _WIN32
    check_case("rollback failure terminates and discards uncommitted rows",
               witness_failstop_fixture(), true, &failures);
#endif
    check_case("consensus-decoded body appends every commitment and note",
               decoded_body_appends_all_commitments(), true, &failures);

    sqlite3 *db = NULL;
    struct active_chain chain;
    active_chain_init(&chain);
    struct incremental_merkle_tree anchored;
    sapling_tree_init(&anchored);
    struct uint256 cm = test_root(0x44);
    incremental_tree_append(&anchored, &cm);
    struct uint256 anchor_root;
    incremental_tree_root(&anchored, &anchor_root);
    struct block_index prior;
    block_index_init(&prior);
    prior.nHeight = 500000;
    prior.hashBlock = test_root(0x55);
    prior.phashBlock = &prior.hashBlock;
    prior.hashFinalSaplingRoot = anchor_root;
    prior.nStatus = BLOCK_HAVE_DATA;
    struct db_sapling_note note;
    memset(&note, 0, sizeof(note));
    note.block_height = 500001;
    struct incremental_merkle_tree seeded;
    sapling_tree_init(&seeded);
    int replay_start = -1;
    int seed_height = -1;
    bool seed_ok = attempt_prior_anchor_seed_shortcut(
        &db, &chain, &prior, &note, &anchored, &seeded, &replay_start,
        &seed_height);
    struct uint256 seeded_root;
    incremental_tree_root(&seeded, &seeded_root);
    check_case("header-bound prior anchor seeds at the oldest note",
               anchor_seeded_at_oldest_note(seed_ok, replay_start, seed_height,
                                            &seeded_root, &anchor_root),
               true, &failures);

    prior.hashFinalSaplingRoot = test_root(0x66);
    check_case("missing prior-header anchor refuses the shortcut",
               rescan_seed_before_oldest_note_from_db(
                   db, &chain, &note, 1, 476969, &seeded, &replay_start,
                   &seed_height), false, &failures);
    if (db)
        sqlite3_close(db);
    active_chain_free(&chain);

    printf("rescanwitnesses divergence guard: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
