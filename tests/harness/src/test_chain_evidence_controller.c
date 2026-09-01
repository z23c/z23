/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "services/chain_evidence_authority_service.h"
#include "coins/coins_view.h"
#include "models/database.h"

#include <stdio.h>
#include <string.h>

struct auth_fixture {
    struct node_db ndb;
    struct block_map bm;
    struct active_chain chain;
    struct block_index *header_tip;
    struct coins_view_cache coins_tip;
    struct chain_state_repository csr;
    struct chain_evidence_controller authority;
    struct uint256 hashes[3];
    struct block_index blocks[3];
};

static bool auth_fixture_init(struct auth_fixture *f)
{
    /* The startup reconcile is once-per-process in production; each test
     * case needs its own fresh run. */
    chain_evidence_controller_test_reset_startup_reconcile();
    memset(f, 0, sizeof(*f));
    if (!node_db_open(&f->ndb, ":memory:"))
        return false;
    block_map_init(&f->bm);
    active_chain_init(&f->chain);

    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    coins_view_cache_init(&f->coins_tip, &null_view);

    for (int i = 0; i < 3; i++) {
        memset(f->hashes[i].data, i + 1, 32);
        block_index_init(&f->blocks[i]);
        f->blocks[i].phashBlock = &f->hashes[i];
        f->blocks[i].nHeight = i;
        f->blocks[i].pprev = i ? &f->blocks[i - 1] : NULL;
        f->blocks[i].nStatus = BLOCK_VALID_TREE;
        arith_uint256_set_u64(&f->blocks[i].nChainWork, (uint64_t)i + 1);
        block_map_insert(&f->bm, &f->hashes[i], &f->blocks[i]);
        const struct block_index *canon =
            block_map_find(&f->bm, &f->hashes[i]);
        if (canon)
            f->blocks[i].phashBlock = canon->phashBlock;
    }

    csr_init(&f->csr, &f->bm, &f->chain, &f->header_tip,
             &f->coins_tip, &f->ndb, NULL);
    chain_evidence_controller_init(&f->authority, &f->ndb, &f->csr);
    return true;
}

static void auth_fixture_free(struct auth_fixture *f)
{
    csr_free(&f->csr);
    coins_view_cache_free(&f->coins_tip);
    active_chain_free(&f->chain);
    block_map_free(&f->bm);
    node_db_close(&f->ndb);
}

static struct chain_evidence_controller_snapshot_meta auth_manifest(
    const struct auth_fixture *f)
{
    struct chain_evidence_controller_snapshot_meta m;
    memset(&m, 0, sizeof(m));
    m.anchor_height = 1;
    m.anchor_hash = *f->blocks[1].phashBlock;
    memset(m.utxo_sha3.data, 0xa5, 32);
    memset(m.chainwork, 0x0b, 32);
    memset(m.mmb_root, 0x0c, 32);
    m.utxo_count = 10;
    m.finality_depth = 100;
    m.schema_version = 1;
    m.producer = "unit";
    m.verified.source_class = CEC_SOURCE_CLASS_SNAPSHOT;
    m.verified.publish_state = CEC_PUBLISH_LOCAL_EVIDENCE;
    m.verified.header_ancestry_linked = true;
    m.verified.chainwork_recomputed = true;
    m.verified.nakamoto_selected_best_work = true;
    m.verified.utxo_sha3_verified = true;
    m.verified.mmb_flyclient_proof_verified = true;
    m.verified.chunk_hash_coverage_verified = true;
    return m;
}

static int test_manifest_missing_proofs_freezes(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;
    struct chain_evidence_controller_snapshot_meta m = auth_manifest(&f);
    m.verified.mmb_flyclient_proof_verified = false;

    enum chain_evidence_controller_result r =
        chain_evidence_controller_import_snapshot_evidence(&f.authority, &m);
    if (r != CEC_REJECTED_BAD_PROOF ||
        f.authority.state != CEC_CONTRADICTION_FROZEN)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

static int test_old_metadata_is_ignored(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    const char old_mode[] = "snapshot_assumed";
    const char old_index[] = "trusted";
    node_db_state_set(&f.ndb, "sync_mode", old_mode, sizeof(old_mode));
    node_db_state_set(&f.ndb, "block_index_trust_state",
                      old_index, sizeof(old_index));

    chain_evidence_controller_load_state(&f.authority);
    if (f.authority.state != CEC_EMPTY)
        failures++;

    struct chain_evidence_controller_view view;
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (view.block_index_evidence_state.header_ancestry_linked ||
        view.block_index_evidence_state.chainwork_recomputed ||
        view.block_index_evidence_state.block_bytes_hash_checked)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

static int test_assisted_full_validation_remains_bound_to_snapshot(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_evidence_controller_snapshot_meta m = auth_manifest(&f);
    if (chain_evidence_controller_import_snapshot_evidence(&f.authority, &m)
            != CEC_OK ||
        chain_evidence_controller_mark_fully_validated(
            &f.authority, &m.utxo_sha3) != CEC_OK)
        failures++;

    struct chain_evidence_controller_view view;
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (view.state != CEC_FULLY_VALIDATED ||
        view.full_validation_origin !=
            CEC_FULL_VALIDATION_ASSISTED_SNAPSHOT ||
        !view.snapshot_evidence_loaded ||
        !view.snapshot_evidence.full_validation_complete)
        failures++;

    if (!node_db_exec(&f.ndb,
            "DELETE FROM node_state WHERE key='cec.snapshot_evidence'"))
        failures++;
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (view.state != CEC_FULLY_VALIDATED ||
        view.snapshot_evidence_loaded ||
        view.snapshot_evidence.full_validation_complete)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

static int test_genesis_full_history_promotes_without_snapshot(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_evidence_controller_tip_request req = {
        .new_tip = &f.blocks[1],
        .utxo_max_height = 1,
        .update_header_tip = true,
        .reason = "unit.genesis_full_history",
    };
    req.verified.source_class = CEC_SOURCE_CLASS_NATIVE_P2P;
    req.verified.publish_state = CEC_PUBLISH_LOCAL_EVIDENCE;
    req.verified.header_ancestry_linked = true;
    req.verified.chainwork_recomputed = true;
    req.verified.nakamoto_selected_best_work = true;
    req.verified.block_bytes_hash_checked = true;
    if (chain_evidence_controller_promote_tip(&f.authority, &req) != CEC_OK)
        failures++;

    struct uint256 full_history_utxo;
    memset(full_history_utxo.data, 0x6d, sizeof(full_history_utxo.data));
    if (chain_evidence_controller_mark_fully_validated(
            &f.authority, &full_history_utxo) != CEC_OK)
        failures++;

    struct chain_evidence_controller_view view;
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (view.state != CEC_FULLY_VALIDATED ||
        view.full_validation_origin !=
            CEC_FULL_VALIDATION_GENESIS_HISTORY ||
        view.snapshot_evidence_loaded ||
        !view.active_tip_evidence.full_validation_complete)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

static int test_assisted_missing_evidence_cannot_fall_through_to_genesis(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_evidence_controller_snapshot_meta m = auth_manifest(&f);
    if (chain_evidence_controller_import_snapshot_evidence(&f.authority, &m)
            != CEC_OK)
        failures++;
    if (!node_db_exec(&f.ndb,
            "DELETE FROM node_state WHERE key='cec.snapshot_evidence'"))
        failures++;
    if (chain_evidence_controller_mark_fully_validated(
            &f.authority, &m.utxo_sha3) != CEC_REJECTED_PERSIST ||
        f.authority.state != CEC_CONTRADICTION_FROZEN)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

static int test_csr_commit_does_not_write_evidence_metadata(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_state_commit commit = {
        .new_tip = &f.blocks[1],
        .new_coins_best = *f.blocks[1].phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .rollback_auth = NULL,
        .wallet_scan_height = -1,
        .reason = "unit.csr_only",
    };
    if (csr_commit_tip(&f.csr, &commit) != CSR_OK)
        failures++;

    char buf[64];
    size_t len = 0;
    memset(buf, 0, sizeof(buf));
    if (node_db_state_get(&f.ndb, "cec.active_tip_evidence",
                          buf, sizeof(buf), &len))
        failures++;
    len = 0;
    if (node_db_state_get(&f.ndb, "active_tip_evidence",
                          buf, sizeof(buf), &len))
        failures++;

    auth_fixture_free(&f);
    return failures;
}

static int test_verified_local_block_bootstraps_tip_evidence(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_evidence_controller_tip_request req = {
        .new_tip = &f.blocks[1],
        .utxo_max_height = 1,
        .update_header_tip = true,
        .reason = "unit.local_validation",
    };
    req.verified.header_ancestry_linked = true;
    req.verified.chainwork_recomputed = true;
    req.verified.nakamoto_selected_best_work = true;
    req.verified.block_bytes_hash_checked = true;

    if (chain_evidence_controller_promote_tip(&f.authority, &req) != CEC_OK)
        failures++;
    if (f.authority.state != CEC_TIP_FOLLOWING)
        failures++;
    struct chain_evidence_controller_view view;
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (!view.active_tip_evidence.block_bytes_hash_checked ||
        !view.block_index_evidence_state.nakamoto_selected_best_work ||
        view.active_tip_height != 1)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

static int test_incomplete_evidence_tip_promotion_rejected(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;
    struct chain_evidence_controller_snapshot_meta m = auth_manifest(&f);
    if (chain_evidence_controller_import_snapshot_evidence(&f.authority, &m)
        != CEC_OK)
        failures++;

    struct chain_evidence_controller_tip_request req = {
        .new_tip = &f.blocks[1],
        .utxo_max_height = 1,
        .update_header_tip = true,
        .reason = "unit",
    };
    if (chain_evidence_controller_promote_tip(&f.authority, &req)
        != CEC_REJECTED_INCOMPLETE_INDEX_EVIDENCE)
        failures++;
    if (f.authority.state != CEC_SNAPSHOT_UTXO_HASH_VERIFIED)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

static int test_utxo_ahead_of_evidenced_index_rejected(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;
    struct chain_evidence_controller_snapshot_meta m = auth_manifest(&f);
    if (chain_evidence_controller_import_snapshot_evidence(&f.authority, &m)
        != CEC_OK)
        failures++;

    struct chain_evidence_controller_tip_request req = {
        .new_tip = &f.blocks[1],
        .utxo_max_height = 2,
        .update_header_tip = true,
        .reason = "unit",
    };
    req.verified.header_ancestry_linked = true;
    req.verified.chainwork_recomputed = true;
    req.verified.nakamoto_selected_best_work = true;
    req.verified.block_bytes_hash_checked = true;
    if (chain_evidence_controller_promote_tip(&f.authority, &req)
        != CEC_REJECTED_UTXO_AHEAD_OF_INDEX)
        failures++;
    if (f.authority.state != CEC_CONTRADICTION_FROZEN)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

static int test_csr_rejection_does_not_persist_tip_evidence(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;
    struct chain_state_repository uninitialized_csr;
    memset(&uninitialized_csr, 0, sizeof(uninitialized_csr));
    chain_evidence_controller_init(&f.authority, &f.ndb, &uninitialized_csr);

    struct chain_evidence_controller_snapshot_meta m = auth_manifest(&f);
    if (chain_evidence_controller_import_snapshot_evidence(&f.authority, &m)
        != CEC_OK)
        failures++;

    struct chain_evidence_controller_tip_request req = {
        .new_tip = &f.blocks[1],
        .utxo_max_height = 1,
        .update_header_tip = true,
        .reason = "unit.csr_reject",
    };
    req.verified.header_ancestry_linked = true;
    req.verified.chainwork_recomputed = true;
    req.verified.nakamoto_selected_best_work = true;
    req.verified.block_bytes_hash_checked = true;
    if (chain_evidence_controller_promote_tip(&f.authority, &req)
        != CEC_REJECTED_CSR)
        failures++;

    char hex[65];
    char key[sizeof("cec.block_evidence.") + 64];
    char buf[128];
    size_t len = 0;
    uint256_get_hex(f.blocks[1].phashBlock, hex);
    snprintf(key, sizeof(key), "cec.block_evidence.%s", hex);
    if (node_db_state_get(&f.ndb, key, buf, sizeof(buf), &len))
        failures++;
    len = 0;
    if (node_db_state_get(&f.ndb, "cec.active_tip_hash",
                          buf, sizeof(buf), &len))
        failures++;

    auth_fixture_free(&f);
    return failures;
}

static int test_persistence_preflight_blocks_csr_publication(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_evidence_controller_snapshot_meta m = auth_manifest(&f);
    if (chain_evidence_controller_import_snapshot_evidence(&f.authority, &m)
        != CEC_OK)
        failures++;

    f.authority.ndb = NULL;

    struct chain_evidence_controller_tip_request req = {
        .new_tip = &f.blocks[1],
        .utxo_max_height = 1,
        .update_header_tip = true,
        .reason = "unit.no_persistence_target",
    };
    req.verified.header_ancestry_linked = true;
    req.verified.chainwork_recomputed = true;
    req.verified.nakamoto_selected_best_work = true;
    req.verified.block_bytes_hash_checked = true;

    if (chain_evidence_controller_promote_tip(&f.authority, &req)
        != CEC_REJECTED_PERSIST)
        failures++;
    if (active_chain_height(&f.chain) != -1)
        failures++;
    if (f.header_tip != NULL)
        failures++;
    if (f.authority.state != CEC_CONTRADICTION_FROZEN)
        failures++;

    f.authority.ndb = &f.ndb;
    auth_fixture_free(&f);
    return failures;
}

static int test_evidence_transaction_can_join_outer_publication_txn(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_evidence_controller_snapshot_meta m = auth_manifest(&f);
    if (chain_evidence_controller_import_snapshot_evidence(&f.authority, &m)
        != CEC_OK)
        failures++;

    if (!node_db_begin(&f.ndb))
        failures++;

    struct chain_evidence_controller_tip_request req = {
        .new_tip = &f.blocks[1],
        .utxo_max_height = 1,
        .update_header_tip = true,
        .reason = "unit.txn_required",
    };
    req.verified.header_ancestry_linked = true;
    req.verified.chainwork_recomputed = true;
    req.verified.nakamoto_selected_best_work = true;
    req.verified.block_bytes_hash_checked = true;

    if (chain_evidence_controller_promote_tip(&f.authority, &req)
        != CEC_OK)
        failures++;
    if (active_chain_height(&f.chain) != 1)
        failures++;
    if (f.header_tip != &f.blocks[1])
        failures++;

    if (!node_db_commit(&f.ndb))
        failures++;
    auth_fixture_free(&f);
    return failures;
}

static int test_valid_evidenced_snapshot_promotes_to_tip_following(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;
    struct chain_evidence_controller_snapshot_meta m = auth_manifest(&f);
    if (chain_evidence_controller_import_snapshot_evidence(&f.authority, &m)
        != CEC_OK)
        failures++;

    struct chain_evidence_controller_tip_request req = {
        .new_tip = &f.blocks[1],
        .utxo_max_height = 1,
        .update_header_tip = true,
        .reason = "unit",
    };
    req.verified.header_ancestry_linked = true;
    req.verified.chainwork_recomputed = true;
    req.verified.nakamoto_selected_best_work = true;
    req.verified.block_bytes_hash_checked = true;
    if (chain_evidence_controller_promote_tip(&f.authority, &req) != CEC_OK)
        failures++;
    if (active_chain_height(&f.chain) != 1)
        failures++;
    if (f.header_tip != &f.blocks[1])
        failures++;
    {
        struct uint256 persisted_best;
        size_t len = 0;
        memset(&persisted_best, 0, sizeof(persisted_best));
        if (!node_db_state_get(&f.ndb, "coins_best_block",
                               persisted_best.data,
                               sizeof(persisted_best.data), &len) ||
            len != sizeof(persisted_best.data) ||
            memcmp(persisted_best.data,
                   f.blocks[1].phashBlock->data,
                   sizeof(persisted_best.data)) != 0)
            failures++;
    }
    if (f.authority.state != CEC_TIP_FOLLOWING)
        failures++;
    {
        struct chain_evidence_controller_view view;
        chain_evidence_controller_snapshot(&f.authority, &view);
        if (!view.block_index_evidence_state.header_ancestry_linked ||
            !view.block_index_evidence_state.chainwork_recomputed ||
            !view.block_index_evidence_state.block_bytes_hash_checked)
            failures++;
        if (!view.active_tip_evidence.nakamoto_selected_best_work)
            failures++;
    }

    auth_fixture_free(&f);
    return failures;
}

static int test_commit_failure_after_csr_restores_concrete_state(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_state_rollback_authorization rollback_auth = {
        .source = CSR_ROLLBACK_SOURCE_TEST,
        .decision = POLICY_ALLOW,
        .from_height = -1,
        .to_height = 0,
        .max_depth = 0,
        .evidence_class = "unit_baseline",
        .reason = "unit.baseline",
    };
    struct chain_state_commit baseline = {
        .new_tip = &f.blocks[0],
        .new_coins_best = *f.blocks[0].phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .persist_coins_best = false,
        .rollback_auth = &rollback_auth,
        .wallet_scan_height = -1,
        .reason = "unit.baseline",
    };
    if (csr_commit_tip(&f.csr, &baseline) != CSR_OK)
        failures++;

    struct chain_evidence_controller_snapshot_meta m = auth_manifest(&f);
    if (chain_evidence_controller_import_snapshot_evidence(&f.authority, &m)
        != CEC_OK)
        failures++;

    struct chain_evidence_controller_tip_request req = {
        .new_tip = &f.blocks[1],
        .utxo_max_height = 1,
        .update_header_tip = true,
        .reason = "unit.force_commit_failure",
    };
    req.verified.header_ancestry_linked = true;
    req.verified.chainwork_recomputed = true;
    req.verified.nakamoto_selected_best_work = true;
    req.verified.block_bytes_hash_checked = true;

    chain_evidence_controller_test_fail_commit_after_csr(true);
    if (chain_evidence_controller_promote_tip(&f.authority, &req)
        != CEC_REJECTED_PERSIST)
        failures++;

    if (active_chain_tip(&f.chain) != &f.blocks[0])
        failures++;
    if (f.header_tip != &f.blocks[0])
        failures++;
    {
        struct uint256 coins_best;
        coins_view_cache_get_best_block(&f.coins_tip, &coins_best);
        if (memcmp(coins_best.data, f.blocks[0].phashBlock->data,
                   sizeof(coins_best.data)) != 0)
            failures++;
    }
    if (f.authority.state != CEC_SNAPSHOT_UTXO_HASH_VERIFIED)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

static int test_full_validation_requires_matching_utxo_sha3(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;
    struct chain_evidence_controller_snapshot_meta m = auth_manifest(&f);
    if (chain_evidence_controller_import_snapshot_evidence(&f.authority, &m)
        != CEC_OK)
        failures++;

    struct uint256 wrong;
    memset(wrong.data, 0xff, 32);
    if (chain_evidence_controller_mark_fully_validated(&f.authority, &wrong)
        != CEC_REJECTED_BAD_PROOF)
        failures++;
    if (f.authority.state != CEC_CONTRADICTION_FROZEN)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

static int test_startup_reconstructs_missing_active_tip_evidence(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_state_commit commit = {
        .new_tip = &f.blocks[1],
        .new_coins_best = *f.blocks[1].phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .persist_coins_best = true,
        .rollback_auth = NULL,
        .wallet_scan_height = -1,
        .reason = "unit.reconcile_seed",
    };
    if (csr_commit_tip(&f.csr, &commit) != CSR_OK)
        failures++;

    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);

    struct chain_evidence_controller_view view;
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (view.state == CEC_CONTRADICTION_FROZEN)
        failures++;
    if (!view.repaired_active_tip_evidence)
        failures++;
    /* A reconstructed local tip is publishable (low-trust), so the
     * health_reason is empty even though has_block_index_required is
     * not yet satisfied: publish_state is LOCAL and there is no
     * contradiction. */
    if (strcmp(view.health_reason, "") != 0)
        failures++;
    /* Honest classification: a tip recovered from local disk is
     * LOCAL_IMPORT, NOT native_p2p. It carries ONLY the flags actually
     * established (ancestry + chainwork); it must NOT claim
     * bytes-verified / nakamoto-selected. */
    if (view.active_tip_source_class != CEC_SOURCE_CLASS_LOCAL_IMPORT)
        failures++;
    if (!view.active_tip_evidence.header_ancestry_linked ||
        !view.active_tip_evidence.chainwork_recomputed)
        failures++;
    if (view.active_tip_evidence.block_bytes_hash_checked ||
        view.active_tip_evidence.nakamoto_selected_best_work ||
        view.active_tip_evidence.utxo_sha3_verified)
        failures++;
    if (view.publish_state != CEC_PUBLISH_LOCAL_EVIDENCE)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

/* A hash-consistent tip whose nChainWork is zero (not yet propagated by
 * the loader after a restore) must NOT freeze: reconstruct recomputes the
 * work from ancestry and publishes LOCAL_IMPORT evidence. */
static int test_startup_zero_chainwork_tip_reconstructs_local_import(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_state_commit commit = {
        .new_tip = &f.blocks[2],
        .new_coins_best = *f.blocks[2].phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .persist_coins_best = true,
        .rollback_auth = NULL,
        .wallet_scan_height = -1,
        .reason = "unit.zero_work_seed",
    };
    if (csr_commit_tip(&f.csr, &commit) != CSR_OK)
        failures++;

    /* Simulate a freshly-restored tip whose work was never propagated. */
    arith_uint256_set_zero(&f.blocks[2].nChainWork);

    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);

    struct chain_evidence_controller_view view;
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (view.state == CEC_CONTRADICTION_FROZEN)
        failures++;
    if (!view.repaired_active_tip_evidence)
        failures++;
    if (view.active_tip_source_class != CEC_SOURCE_CLASS_LOCAL_IMPORT)
        failures++;
    if (view.publish_state != CEC_PUBLISH_LOCAL_EVIDENCE)
        failures++;
    if (!view.active_tip_evidence.chainwork_recomputed)
        failures++;
    /* Work must actually have been recomputed to non-zero. */
    if (arith_uint256_is_zero(&f.blocks[2].nChainWork))
        failures++;
    /* Verification flags it did not perform must remain false. */
    if (view.active_tip_evidence.block_bytes_hash_checked ||
        view.active_tip_evidence.nakamoto_selected_best_work)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

/* A tip that genuinely cannot be proven consistent (coins_best_block does
 * not match the active tip hash, and not a transient lag) must freeze WITH
 * a specific, non-empty reason — never an empty / unnamed freeze. */
static int test_startup_inconsistent_tip_freezes_with_named_reason(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_state_commit commit = {
        .new_tip = &f.blocks[1],
        .new_coins_best = *f.blocks[1].phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .persist_coins_best = true,
        .rollback_auth = NULL,
        .wallet_scan_height = -1,
        .reason = "unit.inconsistent_seed",
    };
    if (csr_commit_tip(&f.csr, &commit) != CSR_OK)
        failures++;

    /* Break ancestry: orphan the tip's pprev so the chain cannot link to
     * genesis. This is a genuine, unrecoverable inconsistency. */
    f.blocks[1].pprev = NULL;

    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);

    struct chain_evidence_controller_view view;
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (view.state != CEC_CONTRADICTION_FROZEN)
        failures++;
    /* The freeze MUST name itself — non-empty and specific. */
    if (view.contradiction_reason[0] == '\0')
        failures++;
    if (strstr(view.contradiction_reason, "ancestry") == NULL)
        failures++;
    if (view.health_reason[0] == '\0')
        failures++;

    auth_fixture_free(&f);
    return failures;
}

/* A controller persisted as FROZEN with an empty reason (legacy / torn
 * DB) must backfill a named reason on load — a freeze must never report
 * an empty reason via the snapshot. */
static int test_frozen_empty_reason_backfilled_on_load(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    /* Use a reason NOT in the demoted auto-clear list so the freeze
     * stays frozen; persist it with an empty reason string. */
    const char frozen[] = "contradiction_frozen";
    if (!node_db_state_set(&f.ndb, "cec.sync_state", frozen, sizeof(frozen)))
        failures++;
    if (!node_db_state_set(&f.ndb, "cec.contradiction_reason", "", 1))
        failures++;

    chain_evidence_controller_load_state(&f.authority);

    if (f.authority.state != CEC_CONTRADICTION_FROZEN)
        failures++;
    if (f.authority.contradiction_reason[0] == '\0')
        failures++;

    struct chain_evidence_controller_view view;
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (view.contradiction_reason[0] == '\0')
        failures++;
    if (view.health_reason[0] == '\0')
        failures++;

    auth_fixture_free(&f);
    return failures;
}

static int test_startup_clears_stale_missing_evidence_freeze_with_sql_lag(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_state_commit commit = {
        .new_tip = &f.blocks[1],
        .new_coins_best = *f.blocks[1].phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .persist_coins_best = true,
        .rollback_auth = NULL,
        .wallet_scan_height = -1,
        .reason = "unit.reconcile_seed",
    };
    if (csr_commit_tip(&f.csr, &commit) != CSR_OK)
        failures++;

    const char frozen[] = "contradiction_frozen";
    const char reason[] = "missing_active_tip_evidence";
    if (!node_db_state_set(&f.ndb, "cec.sync_state",
                           frozen, sizeof(frozen)))
        failures++;
    if (!node_db_state_set(&f.ndb, "cec.contradiction_reason",
                           reason, sizeof(reason)))
        failures++;

    if (sqlite3_exec(f.ndb.db,
                     "INSERT OR REPLACE INTO blocks("
                     "hash,height,prev_hash,version,merkle_root,time,bits,"
                     "nonce,solution,chain_work,status,num_tx) VALUES("
                     "X'0000000000000000000000000000000000000000000000000000000000000000',"
                     "0,"
                     "X'0000000000000000000000000000000000000000000000000000000000000000',"
                     "1,"
                     "X'0000000000000000000000000000000000000000000000000000000000000000',"
                     "0,0,"
                     "X'0000000000000000000000000000000000000000000000000000000000000000',"
                     "X'',"
                     "X'00',0,0)",
                     NULL, NULL, NULL) != SQLITE_OK)
        failures++;

    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);

    struct chain_evidence_controller_view view;
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (view.state == CEC_CONTRADICTION_FROZEN)
        failures++;
    if (!view.repaired_active_tip_evidence)
        failures++;
    if (strcmp(view.health_reason, "") != 0)
        failures++;
    if (view.active_tip_source_class != CEC_SOURCE_CLASS_LOCAL_IMPORT)
        failures++;
    if (!view.active_tip_evidence.header_ancestry_linked ||
        !view.active_tip_evidence.chainwork_recomputed)
        failures++;
    if (view.active_tip_height != 1)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

/* The coins_best_block cursor is a PROJECTION, not part of the tip's
 * block-index evidence. When it OVERSHOOTS the active tip (points to a
 * HIGHER block than the tip — the BIP30 self-write wedge, where the UTXO
 * set landed at H+1 while the tip cursor sits at H), reconstruct must NOT
 * freeze: it publishes LOCAL_IMPORT evidence and lets connect_block's
 * self-write tolerance reconcile the cursor. This pins the non-gating of
 * the coins cursor specifically for the overshoot direction (the existing
 * lag test covers the behind direction). */
static int test_startup_coins_cursor_overshoot_does_not_freeze(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    /* Commit the active tip at height 1 (hash-consistent). */
    struct chain_state_commit commit = {
        .new_tip = &f.blocks[1],
        .new_coins_best = *f.blocks[1].phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .persist_coins_best = true,
        .rollback_auth = NULL,
        .wallet_scan_height = -1,
        .reason = "unit.overshoot_seed",
    };
    if (csr_commit_tip(&f.csr, &commit) != CSR_OK)
        failures++;

    /* Now make the coins cursor OVERSHOOT: point it at block 2 (height 2),
     * one ahead of the active tip at height 1. csr_snapshot reads this
     * cursor; reconstruct must treat the divergence as a recoverable
     * projection overshoot, not a tip_hash contradiction. */
    coins_view_cache_set_best_block(&f.coins_tip, f.blocks[2].phashBlock);

    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);

    struct chain_evidence_controller_view view;
    chain_evidence_controller_snapshot(&f.authority, &view);
    /* The cursor overshoot must NOT freeze the controller... */
    if (view.state == CEC_CONTRADICTION_FROZEN)
        failures++;
    /* ...the tip evidence is reconstructed and published as low-trust
     * LOCAL_IMPORT (the node can advance), and the active tip stays the
     * in-memory tip (height 1), NOT the cursor's overshoot height. */
    if (!view.repaired_active_tip_evidence)
        failures++;
    if (view.active_tip_source_class != CEC_SOURCE_CLASS_LOCAL_IMPORT)
        failures++;
    if (view.publish_state != CEC_PUBLISH_LOCAL_EVIDENCE)
        failures++;
    if (view.active_tip_height != 1)
        failures++;
    /* The cursor divergence is surfaced as an ADVISORY health reason
     * (csr_cursor_mismatch) — logged, not gated. It must specifically NOT
     * be the freeze reason: a non-empty advisory that names the cursor,
     * never a contradiction. This is the no-silent-halt + non-gating
     * contract: the overshoot is visible but does not park the tip. */
    if (strcmp(view.health_reason, "csr_cursor_mismatch") != 0)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

/* A genuine tip_hash contradiction (the persisted active_tip_hash key
 * names a DIFFERENT block than the in-memory tip AND that persisted hash
 * is what the evidence would prove) is distinct from a coins-cursor
 * divergence: the cursor is non-gating, the tip identity is gating. This
 * companion to the overshoot test confirms a real tip mismatch is still
 * caught with a specific outcome rather than silently published. We drive
 * it via a broken ancestry (unlinkable to genesis), which is the
 * unrecoverable case reconstruct freezes on with a named reason. The
 * coins-cursor overshoot above must NOT take this path. */
static int test_startup_repairs_active_tip_hash_mismatch(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_state_commit commit = {
        .new_tip = &f.blocks[1],
        .new_coins_best = *f.blocks[1].phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .persist_coins_best = true,
        .rollback_auth = NULL,
        .wallet_scan_height = -1,
        .reason = "unit.reconcile_seed",
    };
    if (csr_commit_tip(&f.csr, &commit) != CSR_OK)
        failures++;
    if (!node_db_state_set(&f.ndb, "cec.active_tip_hash",
                           f.blocks[2].phashBlock->data, 32))
        failures++;
    if (!node_db_state_set_int(&f.ndb, "cec.active_tip_height", 1))
        failures++;

    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);
    struct chain_evidence_controller_view view;
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (view.state == CEC_CONTRADICTION_FROZEN)
        failures++;
    if (strcmp(view.health_reason, "") != 0)
        failures++;
    if (!view.has_persisted_active_tip_hash ||
        memcmp(view.persisted_active_tip_hash.data,
               f.blocks[1].phashBlock->data, 32) != 0)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

/* A persisted freeze whose reason is NOT in the demoted auto-clear list
 * (so load_state keeps it frozen) must still be LIFTED by reconcile when
 * the live tip is provably consistent — a stale freeze must not outlive
 * the condition that caused it, regardless of its label. This exercises
 * the reconcile_startup lift path, not the load_state demoted-clear. */
static int test_reconcile_lifts_stale_freeze_with_arbitrary_reason(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_state_commit commit = {
        .new_tip = &f.blocks[1],
        .new_coins_best = *f.blocks[1].phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .persist_coins_best = true,
        .rollback_auth = NULL,
        .wallet_scan_height = -1,
        .reason = "unit.reconcile_seed",
    };
    if (csr_commit_tip(&f.csr, &commit) != CSR_OK)
        failures++;

    /* A reason that is NOT demoted and NOT empty — the kind a torn DB or
     * a prior session's generic backfill would leave persisted. */
    const char frozen[] = "contradiction_frozen";
    const char reason[] = "unspecified_contradiction_persisted_without_reason";
    if (!node_db_state_set(&f.ndb, "cec.sync_state", frozen, sizeof(frozen)))
        failures++;
    if (!node_db_state_set(&f.ndb, "cec.contradiction_reason",
                           reason, sizeof(reason)))
        failures++;

    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);

    struct chain_evidence_controller_view view;
    chain_evidence_controller_snapshot(&f.authority, &view);
    /* Provably-consistent tip → freeze lifted, evidence reconstructed. */
    if (view.state == CEC_CONTRADICTION_FROZEN)
        failures++;
    if (strcmp(view.health_reason, "") != 0)
        failures++;
    if (view.active_tip_source_class != CEC_SOURCE_CLASS_LOCAL_IMPORT)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

/* The startup reconcile is once-per-process: the controller is constructed
 * by every health probe / condition poll / diagnostics dump, and each
 * construction must NOT re-run the reconcile (it re-fired identical drift
 * WARNs forever at a held tip). Observable: after the in-memory tip
 * advances, a re-construction does NOT re-reconcile the persisted height;
 * only a fresh process (test reset) does. */
static int test_startup_reconcile_runs_once_per_process(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_state_commit commit = {
        .new_tip = &f.blocks[1],
        .new_coins_best = *f.blocks[1].phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .persist_coins_best = true,
        .rollback_auth = NULL,
        .wallet_scan_height = -1,
        .reason = "unit.once_guard_seed",
    };
    if (csr_commit_tip(&f.csr, &commit) != CSR_OK)
        failures++;
    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);
    int64_t h = -1;
    if (!node_db_state_get_int(&f.ndb, "cec.active_tip_height", &h) || h != 1)
        failures++;

    struct chain_state_commit advance = {
        .new_tip = &f.blocks[2],
        .new_coins_best = *f.blocks[2].phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .persist_coins_best = true,
        .rollback_auth = NULL,
        .wallet_scan_height = -1,
        .reason = "unit.once_guard_advance",
    };
    if (csr_commit_tip(&f.csr, &advance) != CSR_OK)
        failures++;

    /* Same process: the guard holds — re-construction must not
     * re-reconcile (cec.active_tip_height stays at the first run's 1). */
    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);
    h = -1;
    if (!node_db_state_get_int(&f.ndb, "cec.active_tip_height", &h) || h != 1)
        failures++;

    /* Fresh process (test reset): the reconcile reconverges on the new
     * tip. */
    chain_evidence_controller_test_reset_startup_reconcile();
    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);
    h = -1;
    if (!node_db_state_get_int(&f.ndb, "cec.active_tip_height", &h) || h != 2)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

/* Convergence: the reconstructed LOCAL_IMPORT record persisted by a prior
 * boot must SATISFY the next boot's reconcile gate (repaired marker +
 * persisted-tip-hash match + ancestry/chainwork flags). Before the
 * acceptance, the strict has_block_index_required gate could never pass for
 * it (nakamoto/bytes flags honestly false until background validation), so
 * reconstruction re-ran forever. Proof the re-run is actually skipped:
 * break the tip's ancestry before the second boot — a re-run would freeze
 * on active_tip_ancestry_unlinkable; acceptance must keep it unfrozen. */
static int test_reconcile_accepts_prior_reconstructed_evidence(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_state_commit commit = {
        .new_tip = &f.blocks[1],
        .new_coins_best = *f.blocks[1].phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .persist_coins_best = true,
        .rollback_auth = NULL,
        .wallet_scan_height = -1,
        .reason = "unit.convergence_seed",
    };
    if (csr_commit_tip(&f.csr, &commit) != CSR_OK)
        failures++;
    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);

    struct chain_evidence_controller_view view;
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (!view.repaired_active_tip_evidence)
        failures++;

    /* "Next boot": fresh once-guard, same persisted evidence. Ancestry
     * broken so any re-reconstruction would freeze with a named reason. */
    chain_evidence_controller_test_reset_startup_reconcile();
    f.blocks[1].pprev = NULL;
    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);

    chain_evidence_controller_snapshot(&f.authority, &view);
    if (view.state == CEC_CONTRADICTION_FROZEN)
        failures++;
    if (!view.repaired_active_tip_evidence)
        failures++;
    if (view.active_tip_source_class != CEC_SOURCE_CLASS_LOCAL_IMPORT)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

/* A persisted tip AHEAD of the in-memory tip (the refuse-to-rewind branch)
 * must not short-circuit the reconcile: the stale-freeze lift still runs on
 * the PROVEN in-memory tip, while nothing rewrites the higher persisted tip
 * downward (reconstruct runs validation-only under drift_refused). */
static int test_refused_rewind_still_lifts_freeze_without_downgrade(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_state_commit commit = {
        .new_tip = &f.blocks[1],
        .new_coins_best = *f.blocks[1].phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .persist_coins_best = true,
        .rollback_auth = NULL,
        .wallet_scan_height = -1,
        .reason = "unit.refused_rewind_seed",
    };
    if (csr_commit_tip(&f.csr, &commit) != CSR_OK)
        failures++;

    /* Persist a HIGHER tip than the in-memory one, plus a stale freeze
     * whose reason is NOT in the demoted auto-clear list. */
    if (!node_db_state_set(&f.ndb, "cec.active_tip_hash",
                           f.blocks[2].phashBlock->data, 32))
        failures++;
    if (!node_db_state_set_int(&f.ndb, "cec.active_tip_height", 2))
        failures++;
    const char frozen[] = "contradiction_frozen";
    const char reason[] = "unspecified_contradiction_persisted_without_reason";
    if (!node_db_state_set(&f.ndb, "cec.sync_state", frozen, sizeof(frozen)))
        failures++;
    if (!node_db_state_set(&f.ndb, "cec.contradiction_reason",
                           reason, sizeof(reason)))
        failures++;

    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);

    /* The refused rewind no longer parks the freeze: the in-memory tip is
     * proven and the stale freeze is lifted... */
    if (f.authority.state == CEC_CONTRADICTION_FROZEN)
        failures++;
    /* ...while the higher persisted tip is left untouched (no downward
     * rewrite of hash or height)... */
    int64_t h = -1;
    if (!node_db_state_get_int(&f.ndb, "cec.active_tip_height", &h) || h != 2)
        failures++;
    struct uint256 persisted_hash;
    size_t len = 0;
    memset(&persisted_hash, 0, sizeof(persisted_hash));
    if (!node_db_state_get(&f.ndb, "cec.active_tip_hash",
                           persisted_hash.data, 32, &len) || len != 32 ||
        memcmp(persisted_hash.data, f.blocks[2].phashBlock->data, 32) != 0)
        failures++;
    /* ...and reconstruct persisted nothing (validation-only: the repaired
     * marker must not appear). */
    int64_t repaired = 0;
    if (node_db_state_get_int(&f.ndb, "cec.repaired_active_tip_evidence",
                              &repaired) && repaired == 1)
        failures++;

    auth_fixture_free(&f);
    return failures;
}

/* Runtime re-arm: a freeze caused by unlinkable tip ancestry must lift
 * once a runtime structural repair (the header band closure) relinks the
 * tip and calls chain_evidence_request_startup_reconcile — without
 * waiting for a process restart. The once-per-process guard alone would
 * park the stale freeze forever. */
static int test_request_startup_reconcile_lifts_freeze_after_relink(void)
{
    int failures = 0;
    struct auth_fixture f;
    if (!auth_fixture_init(&f))
        return 1;

    struct chain_state_commit commit = {
        .new_tip = &f.blocks[1],
        .new_coins_best = *f.blocks[1].phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .persist_coins_best = true,
        .rollback_auth = NULL,
        .wallet_scan_height = -1,
        .reason = "unit.band_relink_seed",
    };
    if (csr_commit_tip(&f.csr, &commit) != CSR_OK)
        failures++;

    /* Break ancestry → the first reconcile freezes with a named reason. */
    f.blocks[1].pprev = NULL;
    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);
    struct chain_evidence_controller_view view;
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (view.state != CEC_CONTRADICTION_FROZEN)
        failures++;

    /* Relink (the band closure), but WITHOUT the re-arm: the once-guard
     * holds, so a re-construction must stay frozen. */
    f.blocks[1].pprev = &f.blocks[0];
    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (view.state != CEC_CONTRADICTION_FROZEN)
        failures++;

    /* Re-arm → the next construction re-derives evidence on the relinked
     * tip, lifts the stale freeze, and clears the reason. */
    chain_evidence_request_startup_reconcile("unit.header_band_closed");
    chain_evidence_controller_init(&f.authority, &f.ndb, &f.csr);
    chain_evidence_controller_snapshot(&f.authority, &view);
    if (view.state == CEC_CONTRADICTION_FROZEN)
        failures++;
    if (view.contradiction_reason[0] != '\0')
        failures++;

    auth_fixture_free(&f);
    return failures;
}

int test_chain_evidence_controller(void)
{
    int failures = 0;
    failures += test_reconcile_lifts_stale_freeze_with_arbitrary_reason();
    failures += test_request_startup_reconcile_lifts_freeze_after_relink();
    failures += test_manifest_missing_proofs_freezes();
    failures += test_old_metadata_is_ignored();
    failures += test_assisted_full_validation_remains_bound_to_snapshot();
    failures += test_genesis_full_history_promotes_without_snapshot();
    failures +=
        test_assisted_missing_evidence_cannot_fall_through_to_genesis();
    failures += test_csr_commit_does_not_write_evidence_metadata();
    failures += test_verified_local_block_bootstraps_tip_evidence();
    failures += test_incomplete_evidence_tip_promotion_rejected();
    failures += test_utxo_ahead_of_evidenced_index_rejected();
    failures += test_csr_rejection_does_not_persist_tip_evidence();
    failures += test_persistence_preflight_blocks_csr_publication();
    failures += test_evidence_transaction_can_join_outer_publication_txn();
    failures += test_valid_evidenced_snapshot_promotes_to_tip_following();
    failures += test_commit_failure_after_csr_restores_concrete_state();
    failures += test_full_validation_requires_matching_utxo_sha3();
    failures += test_startup_reconstructs_missing_active_tip_evidence();
    failures += test_startup_zero_chainwork_tip_reconstructs_local_import();
    failures += test_startup_inconsistent_tip_freezes_with_named_reason();
    failures += test_frozen_empty_reason_backfilled_on_load();
    failures += test_startup_clears_stale_missing_evidence_freeze_with_sql_lag();
    failures += test_startup_coins_cursor_overshoot_does_not_freeze();
    failures += test_startup_repairs_active_tip_hash_mismatch();
    failures += test_startup_reconcile_runs_once_per_process();
    failures += test_reconcile_accepts_prior_reconstructed_evidence();
    failures += test_refused_rewind_still_lifts_freeze_without_downgrade();
    return failures;
}
