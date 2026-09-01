/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Truth table for rescanwitnesses' consensus guard. A rebuilt Sapling tree is
 * persistable only when it matches a non-zero header root and every witness root
 * agrees with that tree.
 */

#include "test/test_core.h"
#include "controllers/wallet_rescan_controller_internal.h"
#include "storage/anchor_kv.h"

#include <sqlite3.h>
#include <string.h>

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

int test_rescanwitnesses_diverge_guard(void)
{
    printf("\n=== rescanwitnesses divergence guard ===\n");
    int failures = 0;

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
    bool endpoints_installed =
        active_chain_install_tip_slot(&endpoint_chain, &older_endpoint) &&
        active_chain_install_tip_slot(&endpoint_chain, &recent_endpoint);
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

    struct block body;
    block_init(&body);
    body.vtx = calloc(1, sizeof(*body.vtx));
    body.num_vtx = body.vtx ? 1 : 0;
    if (body.vtx) {
        transaction_init(&body.vtx[0]);
        body.vtx[0].version = SAPLING_TX_VERSION;
        body.vtx[0].overwintered = true;
        body.vtx[0].version_group_id = SAPLING_VERSION_GROUP_ID;
        body.vtx[0].v_shielded_output =
            calloc(1, sizeof(*body.vtx[0].v_shielded_output));
        if (body.vtx[0].v_shielded_output) {
            body.vtx[0].num_shielded_output = 1;
            body.vtx[0].v_shielded_output[0].cm = test_root(0x71);
        }
    }
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
    check_case("consensus-decoded body appends every commitment and note",
               replayed == 1 && replay_built == 1 && replay_active &&
               incremental_tree_size(&replay_tree) == 1, true, &failures);
    block_free(&decoded);
    stream_free(&body_wire);
    block_free(&body);

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
    bool seed_ok = sqlite3_open(":memory:", &db) == SQLITE_OK &&
        anchor_kv_ensure_schema(db) && anchor_kv_initialize_history(db, 0) &&
        anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &anchored, 499999) &&
        active_chain_install_tip_slot(&chain, &prior) &&
        rescan_seed_before_oldest_note_from_db(
            db, &chain, &note, 1, 476969, &seeded, &replay_start,
            &seed_height);
    struct uint256 seeded_root;
    incremental_tree_root(&seeded, &seeded_root);
    check_case("header-bound prior anchor seeds at the oldest note",
               seed_ok && replay_start == 500001 && seed_height == 500000 &&
               uint256_eq(&seeded_root, &anchor_root), true, &failures);

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
