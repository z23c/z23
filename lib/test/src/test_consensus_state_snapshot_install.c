/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Atomic promotion tests for external zcl.consensus_state_bundle.v1 files. */

/* realpath() needs __USE_MISC; -D_POSIX_C_SOURCE=200809L alone does not
 * declare it. Without this the TU only builds by accident of the glibc
 * fortify inline at -O3. */
#define _DEFAULT_SOURCE

#include "test/test_core.h"

#include "coins/utxo_commitment.h"
#include "chain/checkpoints.h"
#include "chain/utxo_snapshot_loader.h"
#include "config/boot.h"
#include "config/boot_snapshot_install.h"
#include "config/consensus_state_bundle_validate.h"
#include "config/consensus_state_install_verify_receipt.h"
#include "config/consensus_state_producer_receipt.h"
#include "config/consensus_state_replay_receipt.h"
#include "config/consensus_state_snapshot_export.h"
#include "config/consensus_state_snapshot_install.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"
#include "jobs/tip_finalize_stage.h"
#include "models/database.h"
#include "sapling/incremental_merkle_tree.h"
#include "services/consensus_state_publication_cas.h"
#include "services/nullifier_backfill_service.h"
#include "services/utxo_mirror_sync_service.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/consensus_state_bundle_codec.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CSI_CHECK(label, expr) do {                                      \
    printf("consensus_state_install: %s... ", (label));                  \
    if (expr) printf("OK\n");                                           \
    else { printf("FAIL\n"); failures++; }                              \
} while (0)

struct csi_coin {
    uint8_t txid[32]; uint32_t vout; int64_t value; int32_t height;
    bool coinbase; uint8_t script[3]; size_t script_len;
};
struct csi_anchor {
    int pool; uint8_t root[32]; int64_t height;
    struct byte_stream blob;
};
struct csi_nf { int pool; uint8_t nf[32]; int64_t height; };
struct csi_fixture {
    char path[512];
    int32_t height; uint8_t block_hash[32]; bool complete; int64_t boundary;
    struct csi_coin coins[2]; size_t coin_count;
    uint8_t utxo_root[32]; int64_t supply;
    struct csi_anchor anchors[4]; size_t anchor_count;
    uint8_t anchor_digest[32];
    uint8_t frontier_root[2][32]; int64_t frontier_height[2];
    struct csi_nf nfs[2]; uint8_t nf_digest[32];
    int64_t sprout_cursor, sapling_cursor, nf_cursor, fold_cursor;
    struct consensus_state_source_receipt receipt;
    struct consensus_state_bundle_proof_summary
        proofs[CONSENSUS_STATE_BUNDLE_PROOF_COUNT];
    uint8_t proof[32], source[32], artifact[32];
};

static int boot_install_gate_alias_tests(const char *root)
{
    int failures = 0;
    char home[PATH_MAX], canonical[PATH_MAX], dot_alias[PATH_MAX];
    char symlink_alias[PATH_MAX], copy_dir[PATH_MAX];
    snprintf(home, sizeof(home), "%s/gate-home", root);
    snprintf(canonical, sizeof(canonical), "%s/.zclassic-c23", home);
    snprintf(dot_alias, sizeof(dot_alias), "%s/./.zclassic-c23", home);
    snprintf(symlink_alias, sizeof(symlink_alias), "%s/canonical-alias", root);
    snprintf(copy_dir, sizeof(copy_dir), "%s/copy-proof", root);

    const char *old_home = getenv("HOME");
    bool old_home_set = old_home != NULL;
    char old_home_copy[PATH_MAX];
    if (old_home_set)
        snprintf(old_home_copy, sizeof(old_home_copy), "%s", old_home);

    char canonical_real[PATH_MAX];
    bool setup = mkdir(home, 0700) == 0 && mkdir(canonical, 0700) == 0 &&
                 mkdir(copy_dir, 0700) == 0 &&
                 realpath(canonical, canonical_real) != NULL &&
                 symlink(canonical_real, symlink_alias) == 0 &&
                 setenv("HOME", home, 1) == 0;
    CSI_CHECK("boot gate: alias fixtures initialize", setup);

    bool is_canonical = false;
    CSI_CHECK("boot gate: $HOME/./ canonical alias refuses without owner gate",
              setup &&
              !boot_install_consensus_bundle_gate_allows_for_test(
                  dot_alias, NULL, &is_canonical) && is_canonical);
    is_canonical = false;
    CSI_CHECK("boot gate: symlink alias refuses without owner gate",
              setup &&
              !boot_install_consensus_bundle_gate_allows_for_test(
                  symlink_alias, NULL, &is_canonical) && is_canonical);
    is_canonical = false;
    CSI_CHECK("boot gate: non-exact canonical authorization refuses",
              setup &&
              !boot_install_consensus_bundle_gate_allows_for_test(
                  canonical, "0", &is_canonical) && is_canonical);
    is_canonical = false;
    CSI_CHECK("boot gate: exact canonical authorization admits canonical lane",
              setup && boot_install_consensus_bundle_gate_allows_for_test(
                  canonical, "1", &is_canonical) && is_canonical);
    is_canonical = true;
    CSI_CHECK("boot gate: distinct directory remains copy-proof",
              setup && boot_install_consensus_bundle_gate_allows_for_test(
                  copy_dir, NULL, &is_canonical) && !is_canonical);

    if (old_home_set)
        (void)setenv("HOME", old_home_copy, 1);
    else
        (void)unsetenv("HOME");
    (void)unlink(symlink_alias);
    (void)rmdir(copy_dir);
    (void)rmdir(canonical);
    (void)rmdir(home);
    return failures;
}

/* Post-install node.db `utxos` mirror reset (icb_reset_utxo_mirror in
 * boot_install_consensus_bundle.c, exercised here via the ZCL_TESTING
 * seam boot_install_consensus_bundle_reset_utxo_mirror_for_test). A stale
 * mirror left ABOVE (or anywhere around) a freshly installed bundle height
 * is a derived-projection artifact, never a consensus input — see
 * lane E5's utxo_recovery.rewind_overshoot incident (a 3,718-row mirror
 * overshoot from a prior borrowed-state fold wedged boot with a PERMANENT
 * blocker on a table that carries no consensus weight). This proves the
 * reset actually wipes the mirror + its commitment cache and forces the
 * sync cursor to a value that can never match a real coins_kv frontier. */
static int boot_install_utxo_mirror_reset_tests(const char *root)
{
    int failures = 0;
    char node_path[512];
    snprintf(node_path, sizeof(node_path), "%s/mirror-reset-node.db", root);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool opened = node_db_open(&ndb, node_path);
    CSI_CHECK("mirror reset: node.db opens", opened);
    if (opened) {
        node_db_begin(&ndb);
        for (int i = 0; i < 10; i++) {
            char sql[256];
            snprintf(sql, sizeof(sql),
                "INSERT INTO utxos(txid, vout, height, value, script) "
                "VALUES(X'%032d', %d, %d, 100000, X'00')", i, i, i);
            node_db_exec(&ndb, sql);
        }
        node_db_commit(&ndb);
        node_db_exec(&ndb,
            "INSERT OR REPLACE INTO node_state(key,value) "
            "VALUES('utxo_commitment', X'AABBCCDD')");
        CSI_CHECK("mirror reset: sync cursor seeds to a positive height",
                  node_db_state_set_int(&ndb, UTXO_MIRROR_SYNC_CURSOR_KEY,
                                        12345));

        int64_t before = node_db_utxo_count(&ndb);
        CSI_CHECK("mirror reset: fixture seeds 10 utxos rows",
                  before == 10);

        CSI_CHECK("mirror reset: NULL ndb refuses",
                  !boot_install_consensus_bundle_reset_utxo_mirror_for_test(
                      NULL));

        bool reset_ok =
            boot_install_consensus_bundle_reset_utxo_mirror_for_test(&ndb);
        CSI_CHECK("mirror reset: reset reports success", reset_ok);

        int64_t after = node_db_utxo_count(&ndb);
        CSI_CHECK("mirror reset: utxos table wiped", after == 0);

        size_t clen = 0;
        uint8_t cbuf[64];
        bool commitment_present = node_db_state_get(
            &ndb, "utxo_commitment", cbuf, sizeof(cbuf), &clen);
        CSI_CHECK("mirror reset: utxo_commitment cache cleared",
                  !commitment_present);

        int64_t cursor = -100;
        bool cursor_found = node_db_state_get_int(
            &ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, &cursor);
        CSI_CHECK("mirror reset: sync cursor forced to -1 (never a real "
                  "coins_kv frontier)",
                  cursor_found && cursor == -1);

        /* Idempotent: resetting an already-empty mirror is still success. */
        CSI_CHECK("mirror reset: idempotent on an already-empty mirror",
                  boot_install_consensus_bundle_reset_utxo_mirror_for_test(
                      &ndb));

        node_db_close(&ndb);
    }
    unlink(node_path);
    return failures;
}

static void fixture_proof_summaries(struct csi_fixture *f, uint8_t seed)
{
    static const char *const names[CONSENSUS_STATE_BUNDLE_PROOF_COUNT] = {
        "header_admit", "validate_headers", "body_fetch", "body_persist",
        "script_validate", "proof_validate", "utxo_apply", "tip_finalize",
    };
    static const bool hash_bound[CONSENSUS_STATE_BUNDLE_PROOF_COUNT] = {
        true, true, true, false, true, true, true, false,
    };
    for (size_t i = 0; i < CONSENSUS_STATE_BUNDLE_PROOF_COUNT; i++) {
        struct consensus_state_bundle_proof_summary *proof = &f->proofs[i];
        snprintf(proof->component, sizeof(proof->component), "%s", names[i]);
        proof->cursor = i == CONSENSUS_STATE_BUNDLE_PROOF_COUNT - 1
                            ? (uint64_t)f->height
                            : (uint64_t)f->height + 1;
        proof->first_height = 0;
        proof->last_height = f->height;
        proof->row_count = (uint64_t)f->height + 1;
        proof->hash_bound_count = hash_bound[i] ? proof->row_count : 0;
        for (size_t j = 0; j < 32; j++)
            proof->component_digest[j] =
                (uint8_t)(seed + 13u * i + j + 1u);
    }
    memcpy(f->proofs[0].component_digest,
           f->receipt.chain_corpus_digest, 32);
    consensus_state_bundle_proof_manifest_digest(
        f->proofs, CONSENSUS_STATE_BUNDLE_PROOF_COUNT, f->proof);
}

enum csi_fault {
    CSI_VALID = 0, CSI_WRONG_UTXO_ROOT, CSI_WRONG_SUPPLY,
    CSI_WRONG_ANCHOR_DIGEST, CSI_WRONG_NF_DIGEST, CSI_BAD_TREE_ROOT,
    CSI_BAD_COMPLETE_CURSOR, CSI_ZERO_PROOF, CSI_TEXT_ANCHOR_POOL,
    CSI_TEXT_NF_POOL, CSI_WRONG_FRONTIER_ROOT, CSI_WRONG_FRONTIER_HEIGHT,
    CSI_BAD_SOURCE_RECEIPT, CSI_BAD_SOURCE_EPOCH, CSI_UNKNOWN_PROFILE,
    CSI_EMBEDDED_BUNDLE_SCHEMA, CSI_EMBEDDED_RECEIPT_SCHEMA,
    CSI_TEXT_BLOCK_HASH, CSI_TEXT_PROOF_CURSOR, CSI_TEXT_COIN_VALUE,
    CSI_REAL_ANCHOR_HEIGHT, CSI_REAL_NF_HEIGHT,
    CSI_EXTRA_SCHEMA_OBJECT, CSI_EXTRA_SCHEMA_COLUMN, CSI_EMPTY_UTXO,
    CSI_DUPLICATE_NONFRONTIER_ANCHOR_HEIGHT,
    /* D1 tip-frontier-only anchor verification: a multi-height sprout pool with
     * a genuine non-tip row, then corruptions that exercise each layer of the
     * floor. */
    CSI_MULTIHEIGHT_VALID,
    CSI_CORRUPT_NONTIP_ANCHOR_TREE,
    CSI_CORRUPT_TIP_ANCHOR_TREE,
};

static bool bundle_codec_kat(void)
{
    static const uint8_t want_anchor[32] = {
        0xd3,0xfc,0xa6,0xc8,0x82,0xbb,0x5c,0x6b,
        0x19,0x41,0xd6,0xce,0x64,0x18,0xb5,0x8d,
        0x02,0x60,0x40,0xbb,0x4e,0x6b,0xb4,0xd0,
        0x2c,0x5b,0x01,0x55,0xd3,0x60,0x35,0x77,
    };
    static const uint8_t want_nf[32] = {
        0xc3,0x71,0x92,0x64,0xe8,0x75,0xde,0x6a,
        0xba,0x37,0x05,0x2a,0xeb,0xc9,0x8f,0x1e,
        0x5f,0x5b,0x71,0x18,0xd7,0xf4,0xd8,0x40,
        0x42,0x3b,0x6d,0x32,0xee,0x3a,0xc6,0x81,
    };
    static const uint8_t want_artifact[32] = {
        0xb8,0x57,0xf6,0x79,0xdb,0xb2,0xe5,0x4b,
        0x00,0xa5,0x05,0xc5,0x43,0xeb,0xb6,0x95,
        0xec,0xdf,0x24,0xa2,0xb4,0x53,0x7d,0xd1,
        0x6f,0x2b,0x67,0x62,0x9f,0x10,0x93,0x47,
    };
    static const uint8_t want_epoch[32] = {
        0x9c,0x27,0xe6,0x7b,0x5b,0x02,0x1d,0x09,
        0x3f,0x6d,0x5b,0x8d,0x66,0x04,0xb3,0x17,
        0x0b,0xe0,0xda,0x01,0xfc,0xce,0x13,0xdb,
        0xee,0xbc,0x1b,0x53,0xc8,0x56,0x96,0xf9,
    };
    static const uint8_t want_receipt[32] = {
        0x60,0x19,0xf1,0x3c,0xd3,0xd2,0xab,0xff,
        0x4c,0x76,0xc4,0x38,0x17,0xa2,0xda,0xcc,
        0x51,0x53,0x5b,0xf5,0x9a,0x4b,0x31,0x58,
        0x0b,0x0a,0x08,0xa2,0x65,0xba,0x4c,0x13,
    };
    static const uint8_t want_epoch_v2[32] = {
        0xdb,0x5e,0xd8,0xf9,0xa4,0x6c,0xc7,0xb6,
        0x9d,0x89,0xc7,0xee,0xc7,0x10,0x41,0xcf,
        0x91,0xc9,0x21,0x0a,0xf5,0x3b,0xbd,0x60,
        0xd3,0x82,0x9d,0x43,0x94,0xe0,0x8a,0xcc,
    };
    static const uint8_t want_receipt_v2[32] = {
        0xbe,0x4f,0x17,0x78,0x28,0x25,0x44,0x18,
        0xfe,0x87,0x8f,0x15,0x56,0x7c,0x87,0xf7,
        0x78,0x03,0x97,0x2c,0xa2,0xb7,0x76,0x0a,
        0x90,0x49,0x88,0xb5,0x2d,0x71,0x01,0xb8,
    };
    static const uint8_t want_proof[32] = {
        0x86,0x5a,0x26,0x90,0xa7,0xe0,0x41,0xa8,
        0x87,0x8f,0xdf,0xeb,0xbf,0xcb,0x1c,0x01,
        0x02,0x1c,0xe8,0x52,0xe9,0x3b,0x14,0xf7,
        0x9b,0xff,0x2e,0x8d,0xa7,0x46,0x01,0xd5,
    };
    uint8_t root[32], nf[32], tree[3] = {0xaa,0xbb,0xcc}, out[32];
    for (size_t i = 0; i < 32; i++) {
        root[i] = (uint8_t)i;
        nf[i] = (uint8_t)(32u + i);
    }
    struct sha3_256_ctx c;
    consensus_state_bundle_anchor_digest_begin(&c);
    consensus_state_bundle_anchor_digest_row(&c, 1, root, 9, tree, 3);
    sha3_256_finalize(&c, out);
    if (memcmp(out, want_anchor, 32) != 0)
        return false;
    consensus_state_bundle_nullifier_digest_begin(&c);
    consensus_state_bundle_nullifier_digest_row(&c, 0, nf, 11);
    sha3_256_finalize(&c, out);
    if (memcmp(out, want_nf, 32) != 0)
        return false;

    struct consensus_state_source_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    receipt.schema_version = CONSENSUS_STATE_SOURCE_RECEIPT_V1;
    for (size_t i = 0; i < 32; i++) {
        receipt.source_tree_root[i] = (uint8_t)i;
        receipt.running_binary_digest[i] = (uint8_t)(32u + i);
        receipt.toolchain_digest[i] = (uint8_t)(64u + i);
        receipt.build_inputs_digest[i] = (uint8_t)(96u + i);
        receipt.chain_corpus_digest[i] = (uint8_t)(128u + i);
    }
    snprintf(receipt.producer_commit, sizeof(receipt.producer_commit),
             "0123456789abcdef0123456789abcdef01234567");
    receipt.source_clean = true;
    receipt.validation_profile = CONSENSUS_STATE_VALIDATION_FULL;
    receipt.fold_cursor = 7;
    consensus_state_source_epoch_digest(&receipt,
                                        receipt.source_epoch_digest);
    if (memcmp(receipt.source_epoch_digest, want_epoch, 32) != 0)
        return false;
    consensus_state_source_receipt_digest(&receipt, out);
    if (memcmp(out, want_receipt, 32) != 0)
        return false;

    /* V2 authority is the 32-byte tree identity. Optional GitHub trace
     * metadata must not change either authoritative digest. */
    struct consensus_state_source_receipt receipt_v2 = receipt;
    receipt_v2.schema_version = CONSENSUS_STATE_SOURCE_RECEIPT_V2;
    receipt_v2.producer_commit[0] = '\0';
    uint8_t epoch_without_commit[32], receipt_without_commit[32];
    uint8_t epoch_with_commit[32], receipt_with_commit[32];
    consensus_state_source_epoch_digest(&receipt_v2, epoch_without_commit);
    memcpy(receipt_v2.source_epoch_digest, epoch_without_commit, 32);
    consensus_state_source_receipt_digest(&receipt_v2,
                                          receipt_without_commit);
    if (memcmp(epoch_without_commit, want_epoch_v2, 32) != 0 ||
        memcmp(receipt_without_commit, want_receipt_v2, 32) != 0)
        return false;
    snprintf(receipt_v2.producer_commit,
             sizeof(receipt_v2.producer_commit),
             "fedcba9876543210fedcba9876543210fedcba98");
    consensus_state_source_epoch_digest(&receipt_v2, epoch_with_commit);
    consensus_state_source_receipt_digest(&receipt_v2,
                                          receipt_with_commit);
    if (memcmp(epoch_without_commit, epoch_with_commit, 32) != 0 ||
        memcmp(receipt_without_commit, receipt_with_commit, 32) != 0)
        return false;
    struct consensus_state_bundle_proof_summary proof;
    memset(&proof, 0, sizeof(proof));
    snprintf(proof.component, sizeof(proof.component), "header_admit");
    proof.cursor = 8;
    proof.last_height = 7;
    proof.row_count = 8;
    proof.hash_bound_count = 8;
    for (size_t i = 0; i < 32; i++)
        proof.component_digest[i] = (uint8_t)i;
    consensus_state_bundle_proof_manifest_digest(&proof, 1, out);
    if (memcmp(out, want_proof, 32) != 0)
        return false;

    struct consensus_state_bundle_manifest m;
    memset(&m, 0, sizeof(m));
    m.height = 7;
    m.history_complete = true;
    m.source_clean = true;
    m.validation_profile = CONSENSUS_STATE_VALIDATION_FULL;
    m.utxo_count = 3;
    m.total_supply = 99;
    m.anchor_count = 4;
    m.sprout_frontier_height = 5;
    m.sapling_frontier_height = 6;
    m.nullifier_count = 5;
    m.source_fold_cursor = 8;
    for (size_t i = 0; i < 32; i++) {
        m.block_hash[i] = (uint8_t)i;
        m.utxo_root[i] = (uint8_t)(32u + i);
        m.anchor_digest[i] = (uint8_t)(64u + i);
        m.sprout_frontier_root[i] = (uint8_t)(96u + i);
        m.sapling_frontier_root[i] = (uint8_t)(128u + i);
        m.nullifier_digest[i] = (uint8_t)(160u + i);
        m.proof_manifest_digest[i] = (uint8_t)(192u + i);
        m.source_digest[i] = (uint8_t)(224u + i);
    }
    consensus_state_bundle_artifact_digest(&m, out);
    return memcmp(out, want_artifact, 32) == 0;
}

static void fixture_component_digests(struct csi_fixture *f)
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    f->supply = 0;
    for (size_t i = 0; i < f->coin_count; i++) {
        struct csi_coin *coin = &f->coins[i];
        utxo_commitment_sha3_write_record(
            &c, coin->txid, coin->vout, coin->value, coin->script,
            coin->script_len, (uint32_t)coin->height,
            coin->coinbase ? 1 : 0);
        f->supply += coin->value;
    }
    sha3_256_finalize(&c, f->utxo_root);

    consensus_state_bundle_anchor_digest_begin(&c);
    size_t order[4] = {0, 1, 2, 3};
    for (size_t i = 0; i < f->anchor_count; i++) {
        for (size_t j = i + 1; j < f->anchor_count; j++) {
            const struct csi_anchor *left = &f->anchors[order[i]];
            const struct csi_anchor *right = &f->anchors[order[j]];
            if (left->pool > right->pool ||
                (left->pool == right->pool &&
                 memcmp(left->root, right->root, 32) > 0)) {
                size_t swap = order[i];
                order[i] = order[j];
                order[j] = swap;
            }
        }
    }
    memset(f->frontier_root, 0, sizeof(f->frontier_root));
    f->frontier_height[0] = -1;
    f->frontier_height[1] = -1;
    for (size_t i = 0; i < f->anchor_count; i++) {
        const struct csi_anchor *anchor = &f->anchors[order[i]];
        consensus_state_bundle_anchor_digest_row(
            &c, (uint8_t)anchor->pool, anchor->root,
            (uint64_t)anchor->height, anchor->blob.data,
            (uint32_t)anchor->blob.size);
        if (anchor->height > f->frontier_height[anchor->pool]) {
            f->frontier_height[anchor->pool] = anchor->height;
            memcpy(f->frontier_root[anchor->pool], anchor->root, 32);
        }
    }
    sha3_256_finalize(&c, f->anchor_digest);

    consensus_state_bundle_nullifier_digest_begin(&c);
    for (size_t i = 0; i < 2; i++) {
        consensus_state_bundle_nullifier_digest_row(
            &c, (uint8_t)f->nfs[i].pool, f->nfs[i].nf,
            (uint64_t)f->nfs[i].height);
    }
    sha3_256_finalize(&c, f->nf_digest);
}

static void fixture_artifact_digest(struct csi_fixture *f)
{
    struct consensus_state_bundle_manifest m;
    memset(&m, 0, sizeof(m));
    m.height = f->height;
    memcpy(m.block_hash, f->block_hash, 32);
    m.history_complete = f->complete;
    m.source_clean = f->receipt.source_clean;
    m.validation_profile = f->receipt.validation_profile;
    m.activation_boundary = f->boundary;
    memcpy(m.utxo_root, f->utxo_root, 32);
    m.utxo_count = f->coin_count;
    m.total_supply = f->supply;
    memcpy(m.anchor_digest, f->anchor_digest, 32);
    m.anchor_count = f->anchor_count;
    memcpy(m.sprout_frontier_root,
           f->frontier_root[ANCHOR_POOL_SPROUT], 32);
    m.sprout_frontier_height = f->frontier_height[ANCHOR_POOL_SPROUT];
    memcpy(m.sapling_frontier_root,
           f->frontier_root[ANCHOR_POOL_SAPLING], 32);
    m.sapling_frontier_height = f->frontier_height[ANCHOR_POOL_SAPLING];
    memcpy(m.nullifier_digest, f->nf_digest, 32);
    m.nullifier_count = 2;
    m.sprout_source_cursor = f->sprout_cursor;
    m.sapling_source_cursor = f->sapling_cursor;
    m.nullifier_source_cursor = f->nf_cursor;
    m.source_fold_cursor = f->fold_cursor;
    memcpy(m.proof_manifest_digest, f->proof, 32);
    memcpy(m.source_digest, f->source, 32);
    consensus_state_bundle_artifact_digest(&m, f->artifact);
}

static bool fixture_init(struct csi_fixture *f, const char *dir,
                         const char *name, uint8_t seed, int height,
                         bool complete)
{
    memset(f, 0, sizeof(*f));
    f->receipt.schema_version = CONSENSUS_STATE_SOURCE_RECEIPT_V2;
    snprintf(f->path, sizeof(f->path), "%s/%s.bundle-v1.db", dir, name);
    f->height = height; f->complete = complete;
    f->coin_count = 2;
    f->anchor_count = 2;
    f->boundary = complete ? 0 : height;
    f->sprout_cursor = f->sapling_cursor = f->nf_cursor = complete ? 0 : height;
    f->fold_cursor = height + 1;
    for (size_t i = 0; i < 32; i++) {
        f->block_hash[i] = (uint8_t)(seed + i + 1u);
        f->receipt.source_tree_root[i] = (uint8_t)(seed + i + 5u);
        f->receipt.running_binary_digest[i] = (uint8_t)(seed + i + 37u);
        f->receipt.toolchain_digest[i] = (uint8_t)(seed + i + 69u);
        f->receipt.build_inputs_digest[i] = (uint8_t)(seed + i + 101u);
        f->receipt.chain_corpus_digest[i] = (uint8_t)(seed + i + 133u);
    }
    f->receipt.source_clean = true;
    f->receipt.validation_profile = CONSENSUS_STATE_VALIDATION_FULL;
    f->receipt.fold_cursor = f->fold_cursor;
    consensus_state_source_epoch_digest(&f->receipt,
                                        f->receipt.source_epoch_digest);
    consensus_state_source_receipt_digest(&f->receipt,
                                          f->receipt.receipt_digest);
    memcpy(f->source, f->receipt.receipt_digest, 32);
    fixture_proof_summaries(f, seed);
    for (size_t i = 0; i < 2; i++) {
        for (size_t j = 0; j < 32; j++)
            f->coins[i].txid[j] = (uint8_t)(seed + i * 64u + j);
        f->coins[i].vout = (uint32_t)i;
        f->coins[i].value = 1000 + seed + (int64_t)i;
        f->coins[i].height = height - (int)i;
        f->coins[i].coinbase = i == 0;
        f->coins[i].script[0] = 0x51;
        f->coins[i].script[1] = seed;
        f->coins[i].script[2] = (uint8_t)i;
        f->coins[i].script_len = sizeof(f->coins[i].script);
    }
    struct incremental_merkle_tree trees[2];
    struct uint256 leaf, root;
    sprout_tree_init(&trees[0]); sapling_tree_init(&trees[1]);
    for (size_t j = 0; j < 32; j++)
        leaf.data[j] = (uint8_t)(seed ^ (uint8_t)(j * 3u + 7u));
    for (int pool = 0; pool <= 1; pool++) {
        stream_init(&f->anchors[pool].blob, 128);
        incremental_tree_append(&trees[pool], &leaf);
        if (!incremental_tree_serialize(&trees[pool],
                                        &f->anchors[pool].blob))
            return false;
        incremental_tree_root(&trees[pool], &root);
        f->anchors[pool].pool = pool;
        memcpy(f->anchors[pool].root, root.data, 32);
        f->anchors[pool].height = height;
        f->nfs[pool].pool = pool;
        f->nfs[pool].height = height - 2 + pool;
        for (size_t j = 0; j < 32; j++)
            f->nfs[pool].nf[j] = (uint8_t)(seed + pool * 48u + j + 9u);
    }
    /* Two additional valid Sprout trees stay dormant in normal fixtures. The
     * malformed-height case enables them to build a root-sorted low/high/low
     * sequence: the old frontier-only duplicate check missed the final lower
     * duplicate, while the canonical UNIQUE(pool,height) schema must refuse it. */
    for (size_t extra = 2; extra < 4; extra++) {
        for (size_t j = 0; j < 32; j++)
            leaf.data[j] = (uint8_t)(seed ^
                (uint8_t)(j * (extra + 3u) + 11u * extra));
        stream_init(&f->anchors[extra].blob, 256);
        incremental_tree_append(&trees[ANCHOR_POOL_SPROUT], &leaf);
        if (!incremental_tree_serialize(
                &trees[ANCHOR_POOL_SPROUT], &f->anchors[extra].blob))
            return false;
        incremental_tree_root(&trees[ANCHOR_POOL_SPROUT], &root);
        f->anchors[extra].pool = ANCHOR_POOL_SPROUT;
        memcpy(f->anchors[extra].root, root.data, 32);
        f->anchors[extra].height = height;
    }
    fixture_component_digests(f);
    fixture_artifact_digest(f);
    return true;
}

static void fixture_free(struct csi_fixture *f)
{
    for (size_t i = 0; i < 4; i++)
        stream_free(&f->anchors[i].blob);
    unlink(f->path);
}

static void fixture_duplicate_nonfrontier_anchor_height(struct csi_fixture *f)
{
    size_t sprout[3] = {0, 2, 3};
    for (size_t i = 0; i < 3; i++) {
        for (size_t j = i + 1; j < 3; j++) {
            if (memcmp(f->anchors[sprout[i]].root,
                       f->anchors[sprout[j]].root, 32) > 0) {
                size_t swap = sprout[i];
                sprout[i] = sprout[j];
                sprout[j] = swap;
            }
        }
    }
    f->anchor_count = 4;
    f->anchors[sprout[0]].height = f->height - 1;
    f->anchors[sprout[1]].height = f->height;
    f->anchors[sprout[2]].height = f->height - 1;
}

/* Give the sprout pool two DISTINCT heights so pool 0 owns a genuine non-tip
 * row (anchors[0] at h-1) and a tip row (anchors[2] at h); sapling stays a
 * single tip row (anchors[1] at h). anchors[3] stays dormant. Both sprout
 * trees are already valid, serialized, and root-distinct from fixture_init. */
static void fixture_multiheight_sprout(struct csi_fixture *f)
{
    f->anchor_count = 3;
    f->anchors[0].height = f->height - 1;   /* non-tip sprout */
    f->anchors[2].height = f->height;       /* tip sprout      */
}

static bool exec_ok(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    bool ok = sqlite3_exec(db, sql, NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    return ok;
}

static bool write_bundle(struct csi_fixture *f, enum csi_fault fault)
{
    chmod(f->path, 0600); unlink(f->path);
    if (fault == CSI_EMPTY_UTXO)
        f->coin_count = 0;
    if (fault == CSI_DUPLICATE_NONFRONTIER_ANCHOR_HEIGHT)
        fixture_duplicate_nonfrontier_anchor_height(f);
    if (fault == CSI_MULTIHEIGHT_VALID ||
        fault == CSI_CORRUPT_NONTIP_ANCHOR_TREE ||
        fault == CSI_CORRUPT_TIP_ANCHOR_TREE)
        fixture_multiheight_sprout(f);
    fixture_component_digests(f);
    if (fault == CSI_WRONG_UTXO_ROOT) f->utxo_root[0] ^= 0xff;
    if (fault == CSI_WRONG_SUPPLY) f->supply++;
    if (fault == CSI_WRONG_ANCHOR_DIGEST) f->anchor_digest[0] ^= 0xff;
    if (fault == CSI_WRONG_NF_DIGEST) f->nf_digest[0] ^= 0xff;
    if (fault == CSI_BAD_TREE_ROOT) {
        f->anchors[0].root[0] ^= 1;
        fixture_component_digests(f); /* digest matches the bad declared root */
    }
    if (fault == CSI_CORRUPT_NONTIP_ANCHOR_TREE) {
        /* Trailing garbage on the NON-tip sprout row (anchors[0], height h-1):
         * a well-formed tree followed by a stray byte, so deserialize succeeds
         * but stream_remaining() != 0. The byte-integrity floor must refuse it
         * even though the tip-frontier-only restructure skips the Pedersen
         * recompute for non-tip rows. Recompute digests so anchor_digest
         * matches the corrupted bytes — isolating the byte floor as the SOLE
         * check that fires (not the whole-file/anchor digest). */
        stream_write_u8(&f->anchors[0].blob, 0xAB);
        fixture_component_digests(f);
    }
    if (fault == CSI_CORRUPT_TIP_ANCHOR_TREE) {
        /* Point the TIP sprout row (anchors[2], height h) at a DIFFERENT valid
         * tree (anchors[0]'s serialized bytes) while leaving its stored key
         * (anchors[2].root) intact. The bytes deserialize cleanly and leave no
         * remainder, so the byte floor passes; they Pedersen-hash to
         * anchors[0].root != the stored key, so ONLY the tip Pedersen recompute
         * can catch it. Recompute digests so anchor_digest matches, isolating
         * the tip binding as the sole check that fires. */
        memcpy(f->anchors[2].blob.data, f->anchors[0].blob.data,
               f->anchors[0].blob.size);
        f->anchors[2].blob.size = f->anchors[0].blob.size;
        fixture_component_digests(f);
    }
    if (fault == CSI_BAD_COMPLETE_CURSOR) f->sprout_cursor = 1;
    if (fault == CSI_ZERO_PROOF) memset(f->proof, 0, 32);
    if (fault == CSI_WRONG_FRONTIER_ROOT)
        f->frontier_root[ANCHOR_POOL_SAPLING][0] ^= 1;
    if (fault == CSI_WRONG_FRONTIER_HEIGHT)
        f->frontier_height[ANCHOR_POOL_SPROUT]--;
    if (fault == CSI_BAD_SOURCE_RECEIPT)
        f->receipt.receipt_digest[0] ^= 1;
    if (fault == CSI_BAD_SOURCE_EPOCH) {
        f->receipt.source_epoch_digest[0] ^= 1;
        consensus_state_source_receipt_digest(&f->receipt,
                                              f->receipt.receipt_digest);
        memcpy(f->source, f->receipt.receipt_digest, 32);
    }
    if (fault == CSI_UNKNOWN_PROFILE) {
        f->receipt.validation_profile = 3;
        consensus_state_source_receipt_digest(&f->receipt,
                                              f->receipt.receipt_digest);
        memcpy(f->source, f->receipt.receipt_digest, 32);
    }
    fixture_artifact_digest(f);

    sqlite3 *db = NULL;
    bool ok = sqlite3_open(f->path, &db) == SQLITE_OK && exec_ok(db,
        "CREATE TABLE bundle_meta("
        "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
        "schema TEXT NOT NULL,height INTEGER NOT NULL,block_hash BLOB NOT NULL,"
        "history_complete INTEGER NOT NULL,source_clean INTEGER NOT NULL,"
        "validation_profile INTEGER NOT NULL,activation_boundary INTEGER NOT NULL,"
        "utxo_root BLOB NOT NULL,utxo_count INTEGER NOT NULL,"
        "total_supply INTEGER NOT NULL,anchor_digest BLOB NOT NULL,"
        "anchor_count INTEGER NOT NULL,sprout_frontier_root BLOB NOT NULL,"
        "sprout_frontier_height INTEGER NOT NULL,"
        "sapling_frontier_root BLOB NOT NULL,"
        "sapling_frontier_height INTEGER NOT NULL,"
        "nullifier_digest BLOB NOT NULL,nullifier_count INTEGER NOT NULL,"
        "sprout_source_cursor INTEGER NOT NULL,"
        "sapling_source_cursor INTEGER NOT NULL,"
        "nullifier_source_cursor INTEGER NOT NULL,"
        "source_fold_cursor INTEGER NOT NULL,"
        "proof_manifest_digest BLOB NOT NULL,source_digest BLOB NOT NULL,"
        "artifact_digest BLOB NOT NULL);"
        "CREATE TABLE source_receipt("
        "singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema TEXT NOT NULL,"
        "source_epoch_digest BLOB NOT NULL,source_tree_root BLOB NOT NULL,"
        "running_binary_digest BLOB NOT NULL,toolchain_digest BLOB NOT NULL,"
        "build_inputs_digest BLOB NOT NULL,chain_corpus_digest BLOB NOT NULL,"
        "source_clean INTEGER NOT NULL,validation_profile INTEGER NOT NULL,"
        "producer_commit TEXT NOT NULL,fold_cursor INTEGER NOT NULL,"
        "receipt_digest BLOB NOT NULL);"
        "CREATE TABLE bundle_proof("
        "ordinal INTEGER PRIMARY KEY,component TEXT NOT NULL UNIQUE,"
        "cursor INTEGER NOT NULL,first_height INTEGER NOT NULL,"
        "last_height INTEGER NOT NULL,row_count INTEGER NOT NULL,"
        "hash_bound_count INTEGER NOT NULL,component_digest BLOB NOT NULL);"
        "CREATE TABLE coins("
        "txid BLOB NOT NULL,vout INTEGER NOT NULL,value INTEGER NOT NULL,"
        "script BLOB NOT NULL,height INTEGER NOT NULL,is_coinbase INTEGER NOT NULL,"
        "PRIMARY KEY(txid,vout)) WITHOUT ROWID;"
        );
    if (ok)
        ok = exec_ok(db,
            fault == CSI_DUPLICATE_NONFRONTIER_ANCHOR_HEIGHT
                ? "CREATE TABLE anchors("
                  "pool INTEGER NOT NULL CHECK(pool IN(0,1)),"
                  "anchor BLOB NOT NULL,height INTEGER NOT NULL,"
                  "tree BLOB NOT NULL,PRIMARY KEY(pool,anchor)) WITHOUT ROWID;"
                : "CREATE TABLE anchors("
                  "pool INTEGER NOT NULL CHECK(pool IN(0,1)),"
                  "anchor BLOB NOT NULL,height INTEGER NOT NULL,"
                  "tree BLOB NOT NULL,PRIMARY KEY(pool,anchor),"
                  "UNIQUE(pool,height)) WITHOUT ROWID;");
    if (ok)
        ok = exec_ok(db,
        "CREATE TABLE nullifiers("
        "pool INTEGER NOT NULL CHECK(pool IN(0,1)),nf BLOB NOT NULL,"
        "height INTEGER NOT NULL,PRIMARY KEY(pool,nf)) WITHOUT ROWID;BEGIN");
    if (ok && (fault == CSI_TEXT_ANCHOR_POOL ||
               fault == CSI_TEXT_NF_POOL))
        ok = exec_ok(db, "PRAGMA ignore_check_constraints=ON");
    sqlite3_stmt *st = NULL;
    if (ok) ok = sqlite3_prepare_v2(db,
        "INSERT INTO coins VALUES(?,?,?,?,?,?)", -1, &st, NULL) == SQLITE_OK;
    for (size_t i = 0; ok && i < f->coin_count; i++) {
        sqlite3_reset(st); sqlite3_clear_bindings(st);
        sqlite3_bind_blob(st,1,f->coins[i].txid,32,SQLITE_STATIC);
        sqlite3_bind_int64(st,2,f->coins[i].vout);
        if (fault == CSI_TEXT_COIN_VALUE && i == 0) {
            char numeric_prefix[48];
            snprintf(numeric_prefix, sizeof(numeric_prefix), "%lldx",
                     (long long)f->coins[i].value);
            sqlite3_bind_text(st,3,numeric_prefix,-1,SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_int64(st,3,f->coins[i].value);
        }
        if (f->coins[i].script_len == 0)
            ok = sqlite3_bind_zeroblob(st,4,0) == SQLITE_OK;
        else
            ok = sqlite3_bind_blob(st,4,f->coins[i].script,
                                   (int)f->coins[i].script_len,
                                   SQLITE_STATIC) == SQLITE_OK;
        sqlite3_bind_int(st,5,f->coins[i].height);
        sqlite3_bind_int(st,6,f->coins[i].coinbase?1:0);
        if (ok)
            ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    }
    if (st)
        sqlite3_finalize(st);
    st = NULL;
    if (ok) ok = sqlite3_prepare_v2(db,
        "INSERT INTO source_receipt VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?)",
        -1,&st,NULL)==SQLITE_OK;
    if (ok) {
        int i=1;
        const char *receipt_schema =
            consensus_state_source_receipt_schema(
                f->receipt.schema_version);
        size_t commit_len = strnlen(f->receipt.producer_commit,
                                    sizeof(f->receipt.producer_commit));
        static const char bad_receipt_schema[] =
            CONSENSUS_STATE_SOURCE_RECEIPT_SCHEMA "\0junk";
        if (fault == CSI_EMBEDDED_RECEIPT_SCHEMA)
            sqlite3_bind_text(st,i++,bad_receipt_schema,
                              (int)sizeof(bad_receipt_schema)-1,
                              SQLITE_STATIC);
        else
            sqlite3_bind_text(st,i++,receipt_schema,-1,SQLITE_STATIC);
        sqlite3_bind_blob(st,i++,f->receipt.source_epoch_digest,32,SQLITE_STATIC);
        sqlite3_bind_blob(st,i++,f->receipt.source_tree_root,32,SQLITE_STATIC);
        sqlite3_bind_blob(st,i++,f->receipt.running_binary_digest,32,
                          SQLITE_STATIC);
        sqlite3_bind_blob(st,i++,f->receipt.toolchain_digest,32,SQLITE_STATIC);
        sqlite3_bind_blob(st,i++,f->receipt.build_inputs_digest,32,
                          SQLITE_STATIC);
        sqlite3_bind_blob(st,i++,f->receipt.chain_corpus_digest,32,
                          SQLITE_STATIC);
        sqlite3_bind_int(st,i++,f->receipt.source_clean?1:0);
        sqlite3_bind_int(st,i++,f->receipt.validation_profile);
        sqlite3_bind_text(st,i++,f->receipt.producer_commit,(int)commit_len,
                          SQLITE_STATIC);
        sqlite3_bind_int64(st,i++,f->receipt.fold_cursor);
        sqlite3_bind_blob(st,i++,f->receipt.receipt_digest,32,SQLITE_STATIC);
        ok=sqlite3_step(st)==SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    }
    if (st) sqlite3_finalize(st);
    st = NULL;
    if (ok) ok = sqlite3_prepare_v2(db,
        "INSERT INTO bundle_proof VALUES(?,?,?,?,?,?,?,?)",
        -1,&st,NULL)==SQLITE_OK;
    for (size_t row=0;ok&&row<CONSENSUS_STATE_BUNDLE_PROOF_COUNT;row++) {
        struct consensus_state_bundle_proof_summary *p=&f->proofs[row];
        sqlite3_reset(st); sqlite3_clear_bindings(st);
        sqlite3_bind_int(st,1,(int)row);
        sqlite3_bind_text(st,2,p->component,-1,SQLITE_STATIC);
        if (fault == CSI_TEXT_PROOF_CURSOR && row == 0) {
            char numeric_prefix[48];
            snprintf(numeric_prefix, sizeof(numeric_prefix), "%llux",
                     (unsigned long long)p->cursor);
            sqlite3_bind_text(st,3,numeric_prefix,-1,SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_int64(st,3,(sqlite3_int64)p->cursor);
        }
        sqlite3_bind_int64(st,4,p->first_height);
        sqlite3_bind_int64(st,5,p->last_height);
        sqlite3_bind_int64(st,6,(sqlite3_int64)p->row_count);
        sqlite3_bind_int64(st,7,(sqlite3_int64)p->hash_bound_count);
        sqlite3_bind_blob(st,8,p->component_digest,32,SQLITE_STATIC);
        ok=sqlite3_step(st)==SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    }
    if (st) sqlite3_finalize(st);
    st = NULL;
    if (ok) ok = sqlite3_prepare_v2(db,
        "INSERT INTO anchors VALUES(?,?,?,?)", -1, &st, NULL) == SQLITE_OK;
    for (size_t i = 0; ok && i < f->anchor_count; i++) {
        sqlite3_reset(st); sqlite3_clear_bindings(st);
        if (fault == CSI_TEXT_ANCHOR_POOL && i == 0)
            sqlite3_bind_text(st,1,"0x",-1,SQLITE_STATIC);
        else
            sqlite3_bind_int(st,1,f->anchors[i].pool);
        sqlite3_bind_blob(st,2,f->anchors[i].root,32,SQLITE_STATIC);
        if (fault == CSI_REAL_ANCHOR_HEIGHT && i == 0)
            sqlite3_bind_double(st,3,(double)f->anchors[i].height + 0.25);
        else
            sqlite3_bind_int64(st,3,f->anchors[i].height);
        sqlite3_bind_blob(st,4,f->anchors[i].blob.data,
                          (int)f->anchors[i].blob.size,SQLITE_STATIC);
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    }
    if (st)
        sqlite3_finalize(st);
    st = NULL;
    if (ok) ok = sqlite3_prepare_v2(db,
        "INSERT INTO nullifiers VALUES(?,?,?)", -1, &st, NULL) == SQLITE_OK;
    for (size_t i = 0; ok && i < 2; i++) {
        sqlite3_reset(st); sqlite3_clear_bindings(st);
        if (fault == CSI_TEXT_NF_POOL && i == 0)
            sqlite3_bind_text(st,1,"0x",-1,SQLITE_STATIC);
        else
            sqlite3_bind_int(st,1,f->nfs[i].pool);
        sqlite3_bind_blob(st,2,f->nfs[i].nf,32,SQLITE_STATIC);
        if (fault == CSI_REAL_NF_HEIGHT && i == 0)
            sqlite3_bind_double(st,3,(double)f->nfs[i].height + 0.25);
        else
            sqlite3_bind_int64(st,3,f->nfs[i].height);
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    }
    if (st)
        sqlite3_finalize(st);
    st = NULL;
    if (ok) ok = sqlite3_prepare_v2(db,
        "INSERT INTO bundle_meta VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        -1,&st,NULL)==SQLITE_OK;
    if (ok) {
        int i=1;
        static const char bad_bundle_schema[] =
            CONSENSUS_STATE_BUNDLE_SCHEMA "\0junk";
        if (fault == CSI_EMBEDDED_BUNDLE_SCHEMA)
            sqlite3_bind_text(st,i++,bad_bundle_schema,
                              (int)sizeof(bad_bundle_schema)-1,
                              SQLITE_STATIC);
        else
            sqlite3_bind_text(st,i++,CONSENSUS_STATE_BUNDLE_SCHEMA,-1,
                              SQLITE_STATIC);
        sqlite3_bind_int(st,i++,f->height);
        if (fault == CSI_TEXT_BLOCK_HASH)
            sqlite3_bind_text(st,i++,(const char *)f->block_hash,32,
                              SQLITE_STATIC);
        else
            sqlite3_bind_blob(st,i++,f->block_hash,32,SQLITE_STATIC);
        sqlite3_bind_int(st,i++,f->complete?1:0);
        sqlite3_bind_int(st,i++,f->receipt.source_clean?1:0);
        sqlite3_bind_int(st,i++,f->receipt.validation_profile);
        sqlite3_bind_int64(st,i++,f->boundary);
        sqlite3_bind_blob(st,i++,f->utxo_root,32,SQLITE_STATIC);
        sqlite3_bind_int64(st,i++,(sqlite3_int64)f->coin_count);
        sqlite3_bind_int64(st,i++,f->supply); sqlite3_bind_blob(st,i++,f->anchor_digest,32,SQLITE_STATIC);
        sqlite3_bind_int64(st,i++,(sqlite3_int64)f->anchor_count);
        sqlite3_bind_blob(st,i++,f->frontier_root[ANCHOR_POOL_SPROUT],32,SQLITE_STATIC);
        sqlite3_bind_int64(st,i++,f->frontier_height[ANCHOR_POOL_SPROUT]);
        sqlite3_bind_blob(st,i++,f->frontier_root[ANCHOR_POOL_SAPLING],32,SQLITE_STATIC);
        sqlite3_bind_int64(st,i++,f->frontier_height[ANCHOR_POOL_SAPLING]);
        sqlite3_bind_blob(st,i++,f->nf_digest,32,SQLITE_STATIC);
        sqlite3_bind_int64(st,i++,2); sqlite3_bind_int64(st,i++,f->sprout_cursor);
        sqlite3_bind_int64(st,i++,f->sapling_cursor); sqlite3_bind_int64(st,i++,f->nf_cursor);
        sqlite3_bind_int64(st,i++,f->fold_cursor); sqlite3_bind_blob(st,i++,f->proof,32,SQLITE_STATIC);
        sqlite3_bind_blob(st,i++,f->source,32,SQLITE_STATIC); sqlite3_bind_blob(st,i++,f->artifact,32,SQLITE_STATIC);
        ok = sqlite3_step(st)==SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    }
    if (st) sqlite3_finalize(st);
    if (ok && fault == CSI_EXTRA_SCHEMA_OBJECT)
        ok = exec_ok(db, "CREATE TABLE unexpected(payload BLOB)");
    if (ok && fault == CSI_EXTRA_SCHEMA_COLUMN)
        ok = exec_ok(db, "ALTER TABLE bundle_meta ADD COLUMN unexpected BLOB");
    ok = ok && exec_ok(db, ok ? "COMMIT" : "ROLLBACK");
    if (db) sqlite3_close(db);
    return ok && chmod(f->path, 0400) == 0;
}

static bool active_is(sqlite3 *db, const struct csi_fixture *f)
{
    uint8_t root[32]; int64_t txs=0,outs=0,supply=0;
    if (coins_kv_count(db)!=2 || coins_kv_commitment(db,root)!=0 ||
        memcmp(root,f->utxo_root,32)!=0 ||
        !coins_kv_setinfo(db,&txs,&outs,&supply) || supply!=f->supply)
        return false;
    for(int pool=0;pool<=1;pool++) {
        struct uint256 ar; memcpy(ar.data,f->anchors[pool].root,32);
        int64_t h=-1,c=-1; bool found=false,nff=false;
        if(anchor_kv_get(db,pool,&ar,NULL,&h)!=ANCHOR_KV_FOUND || h!=f->height ||
           !anchor_kv_activation_cursor(db,pool,&c,&found)||!found||c!=f->boundary||
           !nullifier_kv_get(db,f->nfs[pool].nf,pool,&nff,&h)||!nff||h!=f->nfs[pool].height)
            return false;
    }
    int64_t nc=-1; bool ncf=false;
    return nullifier_kv_activation_cursor(db,&nc,&ncf)&&ncf&&nc==f->boundary;
}

static bool seed_active(sqlite3 *db, const struct csi_fixture *f)
{
    if (!coins_kv_ensure_schema(db) || !progress_meta_table_ensure(db) ||
        !anchor_kv_ensure_schema(db) || !nullifier_kv_ensure_schema(db) ||
        !anchor_kv_initialize_history(db, f->boundary) ||
        !nullifier_kv_initialize_history(db, f->boundary))
        return false;
    for (size_t i = 0; i < 2; i++) {
        if (!coins_kv_add(db, f->coins[i].txid, f->coins[i].vout,
                          f->coins[i].value, f->coins[i].height,
                          f->coins[i].coinbase, f->coins[i].script,
                          f->coins[i].script_len))
            return false;
        struct incremental_merkle_tree tree;
        if (f->anchors[i].pool == ANCHOR_POOL_SPROUT)
            sprout_tree_init(&tree);
        else
            sapling_tree_init(&tree);
        struct byte_stream stream;
        stream_init_from_data(&stream, f->anchors[i].blob.data,
                              f->anchors[i].blob.size);
        if (!incremental_tree_deserialize(&tree, &stream) ||
            stream_remaining(&stream) != 0 ||
            !anchor_kv_add_tree(db, f->anchors[i].pool, &tree,
                                f->anchors[i].height) ||
            !nullifier_kv_add(db, f->nfs[i].nf, f->nfs[i].pool,
                              f->nfs[i].height))
            return false;
    }
    return true;
}

static bool install(sqlite3 *db, struct csi_fixture *f,
                    enum consensus_state_install_failpoint fp,
                    enum consensus_state_install_status want)
{
    struct consensus_state_snapshot_install_request req;
    memset(&req, 0, sizeof(req));
    req.bundle_path = f->path;
    req.expected_height = f->height;
    memcpy(req.expected_block_hash, f->block_hash, 32);
    req.failpoint = fp;
    struct consensus_state_install_result result;
    bool ok=consensus_state_snapshot_install(db,&req,&result);
    return !ok && result.status==want;
}

static bool digest_nonzero(const uint8_t digest[32])
{
    uint8_t any=0;
    for(size_t i=0;i<32;i++) any|=digest[i];
    return any!=0;
}

static bool candidate_file_digest(const char *path,uint8_t out[32])
{
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0) return false;
    struct sha3_256_ctx context; sha3_256_init(&context);
    uint8_t buffer[4096]; bool ok=true;
    for(;;) {
        ssize_t n=read(fd,buffer,sizeof(buffer));
        if(n>0) { sha3_256_write(&context,buffer,(size_t)n); continue; }
        if(n==0) break;
        if(errno==EINTR) continue;
        ok=false; break;
    }
    if(close(fd)!=0) ok=false;
    if(ok) sha3_256_finalize(&context,out);
    return ok;
}

static int candidate_staging_count(const char *dir)
{
    DIR *stream=opendir(dir);
    if(!stream) return -1;
    int count=0;
    struct dirent *entry;
    while((entry=readdir(stream))!=NULL)
        if(strncmp(entry->d_name,".zcl-consensus-candidate-",25)==0)
            count++;
    closedir(stream);
    return count;
}

static int prior_generation_count(const char *dir)
{
    /* A4: the prior-generation backup is a VACUUM of the consensus.db kernel. */
    static const char prefix[] = "consensus.db.preinstall.";
    DIR *stream = opendir(dir);
    if (!stream)
        return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(stream)) != NULL) {
        if (strncmp(entry->d_name, prefix, sizeof(prefix) - 1) == 0)
            count++;
    }
    closedir(stream);
    return count;
}

static bool candidate_output_absent(int dirfd,const char *name)
{
    struct stat st; errno=0;
    return fstatat(dirfd,name,&st,AT_SYMLINK_NOFOLLOW)!=0&&errno==ENOENT;
}

struct candidate_sidecar_hook {
    int dirfd;
    const char *name;
    bool created;
};

struct candidate_retained_writer_hook {
    int dirfd;
    int writer_fd;
    bool ran;
};

static int candidate_retained_writer_dup_floor(void)
{
    long limit = sysconf(_SC_OPEN_MAX);
    if (limit > 1024)
        return 1024;
    if (limit > 16)
        return (int)(limit / 2);
    return 3;
}

struct activate_retained_writer_hook {
    int writer_fd;
    bool ran;
    bool mutated;
};

struct activate_transient_restore_hook {
    int writer_fd;
    sqlite3 *progress_db;
    bool ran;
    bool source_mutated;
    bool source_restored;
    bool destination_mutated;
};

struct activate_boundary_commit_hook {
    sqlite3 *writer;
    bool ran;
    bool committed;
};

static void candidate_create_sidecar(void *opaque)
{
    struct candidate_sidecar_hook *hook=opaque;
    if(!hook) return;
    int fd=openat(hook->dirfd,hook->name,
                  O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    hook->created=fd>=0;
    if(fd>=0) close(fd);
}

static void candidate_retain_staging_writer(void *opaque, int fd)
{
    struct candidate_retained_writer_hook *hook=opaque;
    hook->ran=true;
    struct stat dir_st,st;
    int flags=fd>=0?fcntl(fd,F_GETFL):-1;
    if(flags<0||(flags&O_ACCMODE)!=O_RDWR||
       fstat(hook->dirfd,&dir_st)!=0||fstat(fd,&st)!=0||
       !S_ISREG(st.st_mode)||st.st_nlink!=0||st.st_dev!=dir_st.st_dev)
        return;
    hook->writer_fd=fcntl(fd,F_DUPFD_CLOEXEC,
                          candidate_retained_writer_dup_floor());
}

static void activate_mutate_retained_writer(void *opaque)
{
    struct activate_retained_writer_hook *hook = opaque;
    if (!hook)
        return;
    hook->ran = true;
    struct stat st;
    const uint8_t byte = 0xa5;
    hook->mutated = hook->writer_fd >= 0 &&
                    fstat(hook->writer_fd, &st) == 0 &&
                    pwrite(hook->writer_fd, &byte, 1, st.st_size) == 1;
}

/* Model the result of a retained writer presenting one transient source row
 * during the stream and restoring the exact artifact bytes before the final
 * source rehash. The destination mutation is intentional: the pre-COMMIT
 * destination commitment check, not source stability, must reject it. */
static void activate_transient_restore_and_corrupt_destination(void *opaque)
{
    struct activate_transient_restore_hook *hook = opaque;
    if (!hook)
        return;
    hook->ran = true;

    uint8_t original = 0;
    if (hook->writer_fd >= 0 &&
        pread(hook->writer_fd, &original, 1, 0) == 1) {
        uint8_t changed = (uint8_t)(original ^ 0xffu);
        hook->source_mutated =
            pwrite(hook->writer_fd, &changed, 1, 0) == 1;
        if (hook->source_mutated)
            hook->source_restored =
                pwrite(hook->writer_fd, &original, 1, 0) == 1;
    }

    static const char sql[] =
        "UPDATE nullifiers SET height=height+1 "
        "WHERE nf=(SELECT nf FROM nullifiers ORDER BY pool,nf LIMIT 1) "
        "AND pool=(SELECT pool FROM nullifiers ORDER BY pool,nf LIMIT 1)";
    hook->destination_mutated = hook->progress_db &&
        sqlite3_exec(hook->progress_db, sql, NULL, NULL, NULL) == SQLITE_OK &&
        sqlite3_changes(hook->progress_db) == 1; // raw-sql-ok:test-fixture-seeding
}

static void activate_commit_between_backup_and_begin(void *opaque)
{
    struct activate_boundary_commit_hook *hook = opaque;
    if (!hook)
        return;
    hook->ran = true;
    hook->committed = hook->writer &&
        sqlite3_exec(
            hook->writer,
            "INSERT OR REPLACE INTO progress_meta(key,value) "
            "VALUES('activate_boundary_race',x'01')",
            NULL, NULL, NULL) == SQLITE_OK; // raw-sql-ok:test-fixture-seeding
}

static bool candidate_build(
    const struct consensus_state_artifact_evidence *artifact,int dirfd,
    const char *name,enum consensus_state_candidate_failpoint failpoint,
    struct consensus_state_candidate_result *result)
{
    struct consensus_state_candidate_request request;
    memset(&request,0,sizeof(request));
    request.output_dir_fd=dirfd;
    request.output_name=name;
    request.failpoint=failpoint;
    return consensus_state_snapshot_candidate_build(artifact,&request,result);
}

struct candidate_thread_fixture {
    const struct consensus_state_artifact_evidence *artifact;
    int dirfd;
    const char *name;
    struct consensus_state_candidate_result result;
    bool built;
};

static void *candidate_build_thread(void *opaque)
{
    struct candidate_thread_fixture *thread=opaque;
    thread->built=candidate_build(thread->artifact,thread->dirfd,thread->name,
                                  CONSENSUS_CANDIDATE_FAIL_NONE,
                                  &thread->result);
    return NULL;
}

static bool candidate_query_i64(sqlite3 *db,const char *sql,int64_t *out)
{
    sqlite3_stmt *stmt=NULL;
    if(sqlite3_prepare_v2(db,sql,-1,&stmt,NULL)!=SQLITE_OK) return false;
    bool ok=sqlite3_step(stmt)==SQLITE_ROW; // raw-sql-ok:test-read-only-assertion
    if(ok) *out=sqlite3_column_int64(stmt,0);
    if(ok) ok=sqlite3_step(stmt)==SQLITE_DONE; // raw-sql-ok:test-read-only-assertion
    sqlite3_finalize(stmt);
    return ok;
}

static bool candidate_progress_parity(
    sqlite3 *db,const struct csi_fixture *f,const uint8_t admission[32])
{
    int32_t applied=-1; bool found=false;
    if(!coins_kv_get_applied_height(db,&applied,&found)||!found||
       applied!=f->height+1||!coins_kv_contains_refold_marker(db))
        return false;
    for(int pool=0;pool<=1;pool++) {
        int64_t cursor=-1; bool cursor_found=false;
        if(!anchor_kv_activation_cursor(db,pool,&cursor,&cursor_found)||
           !cursor_found||cursor!=0) return false;
    }
    int64_t cursor=-1; bool cursor_found=false;
    if(!nullifier_kv_activation_cursor(db,&cursor,&cursor_found)||
       !cursor_found||cursor!=0) return false;
    int64_t count=-1;
    char sql[256];
    snprintf(sql,sizeof(sql),
        "SELECT count(*) FROM stage_cursor WHERE "
        "(name='tip_finalize' AND cursor=%d) OR "
        "(name!='tip_finalize' AND cursor=%d)",f->height,f->height+1);
    if(!candidate_query_i64(db,"SELECT count(*) FROM stage_cursor",&count)||
       count!=8||
       !candidate_query_i64(db,sql,&count)||count!=8)
        return false;
    snprintf(sql,sizeof(sql),
        "SELECT count(*) FROM utxo_apply_log WHERE height=%d AND "
        "status='anchor' AND ok=1",f->height);
    if(!candidate_query_i64(db,sql,&count)||count!=1) return false;
    snprintf(sql,sizeof(sql),
        "SELECT count(*) FROM tip_finalize_log WHERE height=%d AND "
        "status='anchor' AND ok=1 AND tip_hash IS NOT NULL",f->height);
    if(!candidate_query_i64(db,sql,&count)||count!=1) return false;
    sqlite3_stmt *stmt=NULL;
    bool ok=sqlite3_prepare_v2(db,
        "SELECT schema,receipt_digest FROM consensus_state_source_receipt "
        "WHERE singleton=1",-1,&stmt,NULL)==SQLITE_OK&&
        sqlite3_step(stmt)==SQLITE_ROW; // raw-sql-ok:test-read-only-assertion
    if(ok) {
        const char *schema=(const char *)sqlite3_column_text(stmt,0);
        const void *digest=sqlite3_column_blob(stmt,1);
        const char *expected_schema = consensus_state_source_receipt_schema(
            f->receipt.schema_version);
        ok=schema&&expected_schema&&strcmp(schema,expected_schema)==0&&
           digest&&sqlite3_column_bytes(stmt,1)==32&&
           memcmp(digest,f->receipt.receipt_digest,32)==0;
    }
    if(stmt) sqlite3_finalize(stmt);
    stmt=NULL;
    if(ok) ok=sqlite3_prepare_v2(db,
        "SELECT schema,artifact_digest,admission_receipt_digest "
        "FROM consensus_state_candidate_meta WHERE singleton=1",
        -1,&stmt,NULL)==SQLITE_OK&&
        sqlite3_step(stmt)==SQLITE_ROW; // raw-sql-ok:test-read-only-assertion
    if(ok) {
        const char *schema=(const char *)sqlite3_column_text(stmt,0);
        const void *artifact=sqlite3_column_blob(stmt,1);
        const void *receipt=sqlite3_column_blob(stmt,2);
        ok=schema&&strcmp(schema,CONSENSUS_STATE_CANDIDATE_SCHEMA)==0&&
           artifact&&receipt&&sqlite3_column_bytes(stmt,1)==32&&
           sqlite3_column_bytes(stmt,2)==32&&
           memcmp(artifact,f->artifact,32)==0&&memcmp(receipt,admission,32)==0;
    }
    if(stmt) sqlite3_finalize(stmt);
    return ok;
}

/* Lower the compiled SHA3-checkpoint finality floor so the H*-climb leg below
 * can drive the reducer at a small fixture height (the production floor is the
 * mainnet checkpoint at 3,056,758). Mirror-declared, exactly as the sibling
 * export test does. */
void reducer_frontier_test_set_compiled_anchor(int32_t height);

/* ── H*-climb leg fixture helpers ─────────────────────────────────────────
 * After ACTIVATE forces the reducer cursors to the anchor, prove the cure is
 * a LIVE fold-resume point (not just forced cursors): seed the anchor's trust
 * row, then fold real per-height stage evidence forward and watch
 * reducer_frontier_compute_hstar CLIMB. These write the durable stage-log image
 * directly (test scaffolding building the progress.kv, not production reducer
 * code — the same exemption the sibling reducer_frontier tests use), so they
 * carry the raw-sql-ok markers rather than routing through the AR lifecycle. */

/* A per-height 32-byte hash all stage receipts at that height AGREE on, so the
 * C3 hash-binding split scan never caps the climb. */
static void hs_synth_hash(uint8_t out[32], int32_t h)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = (uint8_t)((h >> 16) & 0xff);
    out[3] = (uint8_t)((h >> 24) & 0xff);
    out[31] = 0x5c;
}

/* Materialize the stage-log tables with the EXACT production DDL. ACTIVATE
 * clears (and never creates) these derived logs, so on the cured store they are
 * absent; IF NOT EXISTS keeps this safe if a table is already present. */
static bool hs_ensure_forward_schema(sqlite3 *db)
{
    return exec_ok(db,
        "CREATE TABLE IF NOT EXISTS header_admit_log("
        "height INTEGER PRIMARY KEY,hash BLOB NOT NULL,parent_hash BLOB,"
        "admitted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS validate_headers_log("
        "height INTEGER PRIMARY KEY,hash BLOB NOT NULL,ok INTEGER NOT NULL,"
        "fail_reason TEXT,validated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS script_validate_log("
        "height INTEGER PRIMARY KEY,status TEXT NOT NULL,ok INTEGER NOT NULL,"
        "tx_count INTEGER NOT NULL,input_count INTEGER NOT NULL,"
        "first_failure_txid BLOB,first_failure_vin INTEGER,"
        "first_failure_serror INTEGER,validated_at INTEGER NOT NULL,"
        "block_hash BLOB,source_epoch_digest BLOB);"
        "CREATE TABLE IF NOT EXISTS body_persist_log("
        "height INTEGER PRIMARY KEY,source TEXT NOT NULL,ok INTEGER NOT NULL,"
        "persisted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS proof_validate_log("
        "height INTEGER PRIMARY KEY,status TEXT NOT NULL,ok INTEGER NOT NULL,"
        "sapling_spends_total INTEGER NOT NULL,"
        "sapling_outputs_total INTEGER NOT NULL,"
        "sprout_joinsplits_total INTEGER NOT NULL,block_hash BLOB,"
        "source_epoch_digest BLOB,first_failure_txid BLOB,"
        "first_failure_proof_type TEXT,validated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_log("
        "height INTEGER PRIMARY KEY,status TEXT NOT NULL,ok INTEGER NOT NULL,"
        "spent_count INTEGER NOT NULL,added_count INTEGER NOT NULL,"
        "total_value_delta INTEGER NOT NULL,first_failure_kind TEXT,"
        "first_failure_detail BLOB,applied_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_delta("
        "height INTEGER PRIMARY KEY,branch_hash BLOB NOT NULL,"
        "spent_blob BLOB NOT NULL,added_blob BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log("
        "height INTEGER PRIMARY KEY,status TEXT NOT NULL,ok INTEGER NOT NULL,"
        "work_delta_high INTEGER NOT NULL,work_delta_low INTEGER NOT NULL,"
        "utxo_size_after INTEGER NOT NULL,reorg_depth INTEGER NOT NULL,"
        "finalized_at INTEGER NOT NULL,tip_hash BLOB);");
}

/* Insert one row binding ?1=height and (if hash!=NULL) ?2=the 32-byte hash. */
static bool hs_ins(sqlite3 *db, const char *sql, int32_t h,
                   const uint8_t *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[hs] prepare failed: %s\n", sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, h);
    if (hash)
        sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    if (!ok)
        fprintf(stderr, "[hs] step h=%d failed: %s\n", h, sqlite3_errmsg(db));
    sqlite3_finalize(st);
    return ok;
}

/* Fold one fully-consistent ok=1 height across every contiguity + C3 log, all
 * bound to the same per-height hash. */
static bool hs_put_forward_height(sqlite3 *db, int32_t h)
{
    uint8_t hh[32];
    hs_synth_hash(hh, h);
    return hs_ins(db,
            "INSERT INTO header_admit_log(height,hash,admitted_at) "
            "VALUES(?1,?2,0)", h, hh) &&
        hs_ins(db,
            "INSERT INTO validate_headers_log(height,hash,ok,validated_at) "
            "VALUES(?1,?2,1,0)", h, hh) &&
        hs_ins(db,
            "INSERT INTO script_validate_log(height,status,ok,tx_count,"
            "input_count,validated_at,block_hash) "
            "VALUES(?1,'verified',1,0,0,0,?2)", h, hh) &&
        hs_ins(db,
            "INSERT INTO body_persist_log(height,source,ok,persisted_at) "
            "VALUES(?1,'test',1,0)", h, NULL) &&
        hs_ins(db,
            "INSERT INTO proof_validate_log(height,status,ok,"
            "sapling_spends_total,sapling_outputs_total,"
            "sprout_joinsplits_total,validated_at,block_hash) "
            "VALUES(?1,'verified',1,0,0,0,0,?2)", h, hh) &&
        hs_ins(db,
            "INSERT INTO utxo_apply_log(height,status,ok,spent_count,"
            "added_count,total_value_delta,applied_at) "
            "VALUES(?1,'verified',1,0,0,0,0)", h, NULL) &&
        hs_ins(db,
            "INSERT INTO utxo_apply_delta(height,branch_hash,spent_blob,"
            "added_blob) VALUES(?1,?2,x'',x'')", h, hh) &&
        hs_ins(db,
            "INSERT INTO tip_finalize_log(height,status,ok,work_delta_high,"
            "work_delta_low,utxo_size_after,reorg_depth,finalized_at,tip_hash) "
            "VALUES(?1,'ok',1,0,0,0,0,0,?2)", h, hh);
}

/* Set one reducer stage cursor (upsert). */
static bool hs_set_cursor(sqlite3 *db, const char *name, int64_t cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO stage_cursor(name,cursor,updated_at) VALUES(?,?,0) "
            "ON CONFLICT(name) DO UPDATE SET cursor=excluded.cursor",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool hs_put_anchor_hash(sqlite3 *db, int32_t h,
                               const uint8_t hash[32])
{
    return hs_ins(db,
        "INSERT OR REPLACE INTO tip_finalize_log(height,status,ok,"
        "work_delta_high,work_delta_low,utxo_size_after,reorg_depth,"
        "finalized_at,tip_hash) VALUES(?1,'anchor',1,0,0,0,0,0,?2)",
        h, hash);
}

/* Give the pre-install wedge an honest durable served frontier so the
 * publication decision's CAS staleness check has a real value to bind. */
static bool hs_seed_current_frontier(sqlite3 *db, int32_t h,
                                     const uint8_t hash[32])
{
    static const char *const names[] = {
        "header_admit", "validate_headers", "body_fetch", "body_persist",
        "script_validate", "proof_validate", "utxo_apply", "tip_finalize",
    };
    if (!hs_ensure_forward_schema(db) || !hs_put_anchor_hash(db, h, hash))
        return false;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        int64_t cursor = strcmp(names[i], "tip_finalize") == 0 ? h : h + 1;
        if (!hs_set_cursor(db, names[i], cursor))
            return false;
    }
    const uint8_t one = 1;
    progress_store_tx_lock();
    bool ok = exec_ok(db, "BEGIN IMMEDIATE") &&
              coins_kv_set_applied_height_in_tx(db, h + 1) &&
              progress_meta_set_in_tx(db, COINS_KV_MIGRATION_COMPLETE_KEY,
                                      &one, 1);
    if (ok) {
        if (!exec_ok(db, "COMMIT")) {
            ok = false;
            (void)exec_ok(db, "ROLLBACK");
        }
    } else {
        (void)exec_ok(db, "ROLLBACK");
    }
    progress_store_tx_unlock();
    return ok;
}

static bool hs_meta_present(sqlite3 *db, const char *key)
{
    uint8_t value[64];
    size_t len = 0;
    bool found = false;
    return progress_meta_get(db, key, value, sizeof(value), &len, &found) &&
           found;
}

static bool hs_meta_absent(sqlite3 *db, const char *key)
{
    uint8_t value[1];
    size_t len = 0;
    bool found = false;
    return progress_meta_get(db, key, value, sizeof(value), &len, &found) &&
           !found;
}

static const char *const k_csi_stale_generation_keys[] = {
    "tipfin_backfill.progress",
    "reducer_frontier.tipfin_backfill_repair.60.aabb",
    "utxo_apply.delta_repair.60.aabb",
    "utxo_apply.coin_backfill.outpoint.aabb:0",
    "coin_backfill.scan.60.aabb",
    "coin_backfill.rounds.60.aabb",
    "coin_backfill.refused.60.aabb",
};

static bool seed_stale_generation_metadata(sqlite3 *db)
{
    static const char schema_and_rows[] =
        "CREATE TABLE IF NOT EXISTS consensus_state_producer_session("
        "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
        "schema TEXT NOT NULL,running_binary_digest BLOB NOT NULL,"
        "source_tree_root BLOB NOT NULL,toolchain_digest BLOB NOT NULL,"
        "build_inputs_digest BLOB NOT NULL,source_epoch_digest BLOB NOT NULL,"
        "source_clean INTEGER NOT NULL,validation_profile INTEGER NOT NULL,"
        "producer_commit TEXT NOT NULL,datadir TEXT NOT NULL,"
        "start_time_us INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS consensus_state_source_receipt("
        "singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema TEXT NOT NULL,"
        "source_epoch_digest BLOB NOT NULL,source_tree_root BLOB NOT NULL,"
        "running_binary_digest BLOB NOT NULL,toolchain_digest BLOB NOT NULL,"
        "build_inputs_digest BLOB NOT NULL,chain_corpus_digest BLOB NOT NULL,"
        "source_clean INTEGER NOT NULL,validation_profile INTEGER NOT NULL,"
        "producer_commit TEXT NOT NULL,fold_cursor INTEGER NOT NULL,"
        "receipt_digest BLOB NOT NULL);"
        "DELETE FROM consensus_state_producer_session;"
        "DELETE FROM consensus_state_source_receipt;"
        "INSERT INTO consensus_state_producer_session VALUES("
        "1,'zcl.consensus_state_producer_session.v2',"
        "zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),"
        "1,1,'','stale-generation',1);"
        "INSERT INTO consensus_state_source_receipt VALUES("
        "1,'zcl.consensus_state_source_receipt.v2',"
        "zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),"
        "zeroblob(32),1,1,'',61,zeroblob(32));";
    uint8_t stale_epoch[32];
    uint8_t marker[8];
    memset(stale_epoch, 0xa7, sizeof(stale_epoch));
    memset(marker, 0x5c, sizeof(marker));
    if (!exec_ok(db, schema_and_rows) ||
        !progress_meta_set(db, CONSENSUS_STATE_SOURCE_EPOCH_META_KEY,
                           stale_epoch, sizeof(stale_epoch)))
        return false;
    for (size_t i = 0;
         i < sizeof(k_csi_stale_generation_keys) /
                 sizeof(k_csi_stale_generation_keys[0]); i++) {
        if (!progress_meta_set(db, k_csi_stale_generation_keys[i], marker,
                               sizeof(marker)))
            return false;
    }
    return true;
}

static bool stale_generation_metadata_present(sqlite3 *db)
{
    int64_t sessions = -1;
    int64_t receipts = -1;
    if (!candidate_query_i64(
            db, "SELECT count(*) FROM consensus_state_producer_session",
            &sessions) ||
        !candidate_query_i64(
            db, "SELECT count(*) FROM consensus_state_source_receipt",
            &receipts) ||
        sessions != 1 || receipts != 1 ||
        !hs_meta_present(db, CONSENSUS_STATE_SOURCE_EPOCH_META_KEY))
        return false;
    for (size_t i = 0;
         i < sizeof(k_csi_stale_generation_keys) /
                 sizeof(k_csi_stale_generation_keys[0]); i++) {
        if (!hs_meta_present(db, k_csi_stale_generation_keys[i]))
            return false;
    }
    return true;
}

static bool stale_generation_metadata_absent(sqlite3 *db)
{
    int64_t sessions = -1;
    int64_t receipts = -1;
    int64_t family_rows = -1;
    if (!candidate_query_i64(
            db, "SELECT count(*) FROM consensus_state_producer_session",
            &sessions) ||
        !candidate_query_i64(
            db, "SELECT count(*) FROM consensus_state_source_receipt",
            &receipts) ||
        !candidate_query_i64(
            db,
            "SELECT count(*) FROM progress_meta WHERE "
            "key GLOB 'reducer_frontier.*_repair.*' OR "
            "key GLOB 'utxo_apply.*_repair.*' OR "
            "key GLOB 'utxo_apply.coin_backfill.outpoint.*' OR "
            "key GLOB 'coin_backfill.scan.*' OR "
            "key GLOB 'coin_backfill.rounds.*' OR "
            "key GLOB 'coin_backfill.refused.*'",
            &family_rows) ||
        sessions != 0 || receipts != 0 || family_rows != 0 ||
        !hs_meta_absent(db, CONSENSUS_STATE_SOURCE_EPOCH_META_KEY))
        return false;
    for (size_t i = 0;
         i < sizeof(k_csi_stale_generation_keys) /
                 sizeof(k_csi_stale_generation_keys[0]); i++) {
        if (!hs_meta_absent(db, k_csi_stale_generation_keys[i]))
            return false;
    }
    return true;
}

/* Deterministic 64-hex source identities so the receipt's verifier-epoch key
 * does not depend on this build's baked worktree identity. */
#define IVR_EPOCH_A_SOURCE_ID \
    "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
#define IVR_EPOCH_B_SOURCE_ID \
    "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22"

/* install-verify receipt: after a successful content verify, a
 * byte-identical bundle admitted again under the exact same verifying-binary
 * build epoch must skip the O(bundle-size) deep scan (asserted via the
 * deep-scan-call counter, not timing); a different epoch, a different
 * bundle, a corrupt receipt store, or no datadir capability must all fall
 * back to a full verify (fail-soft), and admission must succeed in every
 * case. */
static int install_verify_receipt_tests(const char *root)
{
    int failures = 0;
    char dir[300], datadir[320];
    snprintf(dir, sizeof(dir), "%s/ivr", root);
    snprintf(datadir, sizeof(datadir), "%s/datadir", dir);
    CSI_CHECK("ivr: bundle dir", mkdir(dir, 0700) == 0);
    CSI_CHECK("ivr: datadir", mkdir(datadir, 0700) == 0);

    struct csi_fixture f, other;
    memset(&f, 0, sizeof(f));
    memset(&other, 0, sizeof(other));
    CSI_CHECK("ivr: fixtures build",
              fixture_init(&f, dir, "ivr", 0x21, 44, true) &&
              fixture_init(&other, dir, "ivr-other", 0x55, 46, true));
    CSI_CHECK("ivr: bundles write",
              write_bundle(&f, CSI_VALID) && write_bundle(&other, CSI_VALID));

    int dfd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CSI_CHECK("ivr: datadir opens", dfd >= 0);

    consensus_state_producer_receipt_test_set_identity(IVR_EPOCH_A_SOURCE_ID,
                                                        true);
    consensus_state_bundle_validate_deep_scan_calls_reset_for_test();
    uint64_t calls;

    /* (1) No receipt yet: full deep scan runs, and a receipt is stored. */
    struct consensus_state_artifact_evidence *ev1 = NULL;
    struct zcl_result r1 =
        consensus_state_artifact_evidence_open(f.path, dfd, &ev1);
    CSI_CHECK("ivr: first open admits", r1.ok && ev1 != NULL);
    calls = consensus_state_bundle_validate_deep_scan_calls_for_test();
    CSI_CHECK("ivr: first open ran the deep scan", calls == 1);
    struct consensus_state_bundle_manifest m1, m2;
    memset(&m1, 0, sizeof(m1));
    CSI_CHECK("ivr: first open manifest matches the fixture",
              ev1 != NULL &&
              consensus_state_artifact_evidence_manifest_copy(ev1, &m1) &&
              m1.height == f.height &&
              memcmp(m1.block_hash, f.block_hash, 32) == 0);
    if (ev1)
        consensus_state_artifact_evidence_free(ev1);

    /* (2) Exact same bundle bytes + exact same verifier epoch: the receipt
     * is honored and the deep scan is NOT re-entered, but the returned
     * manifest is still byte-identical to the fully-verified one. */
    struct consensus_state_artifact_evidence *ev2 = NULL;
    struct zcl_result r2 =
        consensus_state_artifact_evidence_open(f.path, dfd, &ev2);
    CSI_CHECK("ivr: second open admits", r2.ok && ev2 != NULL);
    calls = consensus_state_bundle_validate_deep_scan_calls_for_test();
    CSI_CHECK("ivr: second open honored the receipt (deep scan NOT "
              "re-entered)", calls == 1);
    memset(&m2, 0, sizeof(m2));
    CSI_CHECK("ivr: receipt-honored open returns the identical manifest",
              ev2 != NULL &&
              consensus_state_artifact_evidence_manifest_copy(ev2, &m2) &&
              memcmp(&m2, &m1, sizeof(m1)) == 0);
    if (ev2)
        consensus_state_artifact_evidence_free(ev2);

    /* (3) A different verifying-binary build epoch is a different receipt
     * key: NOT honored, deep scan runs again. */
    consensus_state_producer_receipt_test_set_identity(IVR_EPOCH_B_SOURCE_ID,
                                                        true);
    struct consensus_state_artifact_evidence *ev3 = NULL;
    struct zcl_result r3 =
        consensus_state_artifact_evidence_open(f.path, dfd, &ev3);
    CSI_CHECK("ivr: different verifier epoch admits", r3.ok && ev3 != NULL);
    calls = consensus_state_bundle_validate_deep_scan_calls_for_test();
    CSI_CHECK("ivr: different verifier epoch re-ran the deep scan",
              calls == 2);
    if (ev3)
        consensus_state_artifact_evidence_free(ev3);

    /* (4) Back to epoch A, but a DIFFERENT bundle file: the on-disk receipt
     * (still keyed to `f`'s content from step 1/2) is NOT honored for
     * `other`, and the deep scan runs again; `other`'s own receipt then
     * overwrites the single-slot store. */
    consensus_state_producer_receipt_test_set_identity(IVR_EPOCH_A_SOURCE_ID,
                                                        true);
    struct consensus_state_artifact_evidence *ev4 = NULL;
    struct zcl_result r4 =
        consensus_state_artifact_evidence_open(other.path, dfd, &ev4);
    CSI_CHECK("ivr: different bundle admits", r4.ok && ev4 != NULL);
    calls = consensus_state_bundle_validate_deep_scan_calls_for_test();
    CSI_CHECK("ivr: different bundle content re-ran the deep scan",
              calls == 3);
    if (ev4)
        consensus_state_artifact_evidence_free(ev4);

    /* (5) Re-opening the ORIGINAL bundle now finds `other`'s receipt in the
     * single slot instead: a different bundle hash is NOT a match, so the
     * deep scan correctly runs once more (never a false-positive honor). */
    struct consensus_state_artifact_evidence *ev5 = NULL;
    struct zcl_result r5 =
        consensus_state_artifact_evidence_open(f.path, dfd, &ev5);
    CSI_CHECK("ivr: reopening original bundle after slot reuse admits",
              r5.ok && ev5 != NULL);
    calls = consensus_state_bundle_validate_deep_scan_calls_for_test();
    CSI_CHECK("ivr: reused-slot receipt was not mistakenly honored",
              calls == 4);
    if (ev5)
        consensus_state_artifact_evidence_free(ev5);

    /* (6) The receipt now belongs to `f` again; confirm it re-honors. */
    struct consensus_state_artifact_evidence *ev6 = NULL;
    struct zcl_result r6 =
        consensus_state_artifact_evidence_open(f.path, dfd, &ev6);
    calls = consensus_state_bundle_validate_deep_scan_calls_for_test();
    CSI_CHECK("ivr: receipt re-honored once the slot returns to f",
              r6.ok && ev6 != NULL && calls == 4);
    if (ev6)
        consensus_state_artifact_evidence_free(ev6);

    /* (7) A corrupt receipt store fails soft to a full verify, and a fresh
     * valid receipt is written over it. */
    if (dfd >= 0) {
        int cfd = openat(dfd, CONSENSUS_STATE_INSTALL_VERIFY_RECEIPT_NAME,
                         O_WRONLY | O_TRUNC | O_CLOEXEC);
        CSI_CHECK("ivr: receipt corruption fixture opens", cfd >= 0);
        if (cfd >= 0) {
            uint8_t garbage[16];
            memset(garbage, 0xAB, sizeof(garbage));
            CSI_CHECK("ivr: receipt corruption fixture writes",
                      write(cfd, garbage, sizeof(garbage)) ==
                          (ssize_t)sizeof(garbage));
            (void)close(cfd);
        }
    }
    struct consensus_state_artifact_evidence *ev7 = NULL;
    struct zcl_result r7 =
        consensus_state_artifact_evidence_open(f.path, dfd, &ev7);
    CSI_CHECK("ivr: corrupt receipt store admits (fail-soft)",
              r7.ok && ev7 != NULL);
    calls = consensus_state_bundle_validate_deep_scan_calls_for_test();
    CSI_CHECK("ivr: corrupt receipt store fell back to a full verify",
              calls == 5);
    if (ev7)
        consensus_state_artifact_evidence_free(ev7);

    /* (8) The just-repaired receipt IS honored on the very next open. */
    struct consensus_state_artifact_evidence *ev8 = NULL;
    struct zcl_result r8 =
        consensus_state_artifact_evidence_open(f.path, dfd, &ev8);
    calls = consensus_state_bundle_validate_deep_scan_calls_for_test();
    CSI_CHECK("ivr: repaired receipt is honored", r8.ok && ev8 != NULL &&
                                                       calls == 5);
    if (ev8)
        consensus_state_artifact_evidence_free(ev8);

    /* (9) No datadir capability (-1): always the full verify, receipt or
     * not — admission must still succeed. */
    struct consensus_state_artifact_evidence *ev9 = NULL;
    struct zcl_result r9 =
        consensus_state_artifact_evidence_open(f.path, -1, &ev9);
    CSI_CHECK("ivr: no datadir capability admits", r9.ok && ev9 != NULL);
    calls = consensus_state_bundle_validate_deep_scan_calls_for_test();
    CSI_CHECK("ivr: no datadir capability never honors a receipt",
              calls == 6);
    if (ev9)
        consensus_state_artifact_evidence_free(ev9);

    consensus_state_producer_receipt_test_set_identity(NULL, false);
    if (dfd >= 0)
        (void)close(dfd);
    fixture_free(&f);
    fixture_free(&other);
    return failures;
}

/* Build a rom_state_checkpoint that reproduces fixture f's complete state at
 * f->height (transparent coins + Sprout/Sapling anchor history + both frontier
 * roots + nullifier history). rom_state_root is set nonzero so the placeholder
 * guard treats it as a baked keystone (validate_rom_keystone_binding never
 * re-derives rom_state_root — the manifest carries no such field). */
static void rom_keystone_from_fixture(const struct csi_fixture *f,
                                      struct rom_state_checkpoint *rom)
{
    memset(rom, 0, sizeof(*rom));
    rom->height = f->height;
    memcpy(rom->block_hash, f->block_hash, 32);
    memcpy(rom->utxo_root, f->utxo_root, 32);
    rom->utxo_count = f->coin_count;
    rom->total_supply = f->supply;
    memcpy(rom->anchor_digest, f->anchor_digest, 32);
    rom->anchor_count = f->anchor_count;
    memcpy(rom->sprout_frontier_root, f->frontier_root[ANCHOR_POOL_SPROUT], 32);
    rom->sprout_frontier_height = f->frontier_height[ANCHOR_POOL_SPROUT];
    memcpy(rom->sapling_frontier_root, f->frontier_root[ANCHOR_POOL_SAPLING], 32);
    rom->sapling_frontier_height = f->frontier_height[ANCHOR_POOL_SAPLING];
    memcpy(rom->nullifier_digest, f->nf_digest, 32);
    rom->nullifier_count = 2;
    memset(rom->rom_state_root, 0x5a, 32); /* nonzero: a baked (non-placeholder) keystone */
}

/* Validate the on-disk bundle file directly (its own SQLite descriptor). Returns
 * the validation verdict; on refusal, out_status carries the named status. */
static bool validate_bundle_file(const char *path,
                                 enum consensus_state_install_status *out_status)
{
    sqlite3 *bdb = NULL;
    if (sqlite3_open_v2(path, &bdb, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (bdb) sqlite3_close(bdb);
        if (out_status) *out_status = CONSENSUS_INSTALL_REFUSED;
        return false;
    }
    struct consensus_state_bundle_manifest m;
    memset(&m, 0, sizeof(m));
    struct consensus_state_install_result res;
    memset(&res, 0, sizeof(res));
    bool ok = consensus_state_bundle_validate(bdb, &m, &res);
    if (out_status) *out_status = res.status;
    sqlite3_close(bdb);
    return ok;
}

/* Shielded-ROM keystone binding (validate_rom_keystone_binding in
 * consensus_state_bundle_validate.c): a bundle AT the compiled checkpoint height
 * must reproduce the compiled keystone's transparent AND shielded digests, else
 * it is refused loudly. This exercises the binding against a scaled-down fixture
 * checkpoint installed via the override seam — a MATCHING keystone admits the
 * bundle through validation; every single-field mismatch refuses; an unbaked
 * (placeholder) keystone refuses; and a keystone at any OTHER height leaves the
 * bundle untouched (no false refusal off the checkpoint height). */
static int rom_keystone_binding_tests(const char *dir)
{
    int failures = 0;
    /* Seed must keep coins[0].txid < coins[1].txid (txid byte0 = seed vs
     * seed+0x40) so the fixture's array-order utxo_root matches validate_coins'
     * ORDER BY txid,vout recompute — i.e. seed <= 0xBF (0x30 is well clear). */
    struct csi_fixture k;
    if (!fixture_init(&k, dir, "keystone", 0x30, 120, true)) {
        CSI_CHECK("keystone: fixture builds", false);
        return failures;
    }
    CSI_CHECK("keystone: valid bundle writes", write_bundle(&k, CSI_VALID));

    enum consensus_state_install_status status;

    /* Baseline: with NO override, get_rom_state_checkpoint() is the compiled
     * production keystone (height 3056758). The fixture bundle is at height 120,
     * so the keystone binding does not apply and validation admits. Proves the
     * new binding is inert off the checkpoint height. */
    CSI_CHECK("keystone: bundle off the checkpoint height validates (binding inert)",
              validate_bundle_file(k.path, &status));

    struct rom_state_checkpoint rom;
    rom_keystone_from_fixture(&k, &rom);

    /* POSITIVE: an override whose complete state matches the bundle admits. */
    checkpoints_set_rom_state_override_for_test(&rom);
    CSI_CHECK("keystone: matching complete-state keystone admits the bundle",
              validate_bundle_file(k.path, &status));

    /* NEGATIVE (shielded): each single-field mismatch refuses loudly. */
    {
        struct rom_state_checkpoint bad = rom;
        bad.anchor_digest[0] ^= 0xff;
        checkpoints_set_rom_state_override_for_test(&bad);
        CSI_CHECK("keystone: wrong anchor_digest refuses (REFUSED)",
                  !validate_bundle_file(k.path, &status) &&
                  status == CONSENSUS_INSTALL_REFUSED);
    }
    {
        struct rom_state_checkpoint bad = rom;
        bad.nullifier_digest[0] ^= 0xff;
        checkpoints_set_rom_state_override_for_test(&bad);
        CSI_CHECK("keystone: wrong nullifier_digest refuses (REFUSED)",
                  !validate_bundle_file(k.path, &status) &&
                  status == CONSENSUS_INSTALL_REFUSED);
    }
    {
        struct rom_state_checkpoint bad = rom;
        bad.sprout_frontier_root[0] ^= 0xff;
        checkpoints_set_rom_state_override_for_test(&bad);
        CSI_CHECK("keystone: wrong sprout_frontier_root refuses (REFUSED)",
                  !validate_bundle_file(k.path, &status) &&
                  status == CONSENSUS_INSTALL_REFUSED);
    }
    {
        struct rom_state_checkpoint bad = rom;
        bad.sapling_frontier_root[0] ^= 0xff;
        checkpoints_set_rom_state_override_for_test(&bad);
        CSI_CHECK("keystone: wrong sapling_frontier_root refuses (REFUSED)",
                  !validate_bundle_file(k.path, &status) &&
                  status == CONSENSUS_INSTALL_REFUSED);
    }
    {
        struct rom_state_checkpoint bad = rom;
        bad.sapling_frontier_height ^= 0x1;
        checkpoints_set_rom_state_override_for_test(&bad);
        CSI_CHECK("keystone: wrong sapling_frontier_height refuses (REFUSED)",
                  !validate_bundle_file(k.path, &status) &&
                  status == CONSENSUS_INSTALL_REFUSED);
    }
    {
        struct rom_state_checkpoint bad = rom;
        bad.anchor_count += 1;
        checkpoints_set_rom_state_override_for_test(&bad);
        CSI_CHECK("keystone: wrong anchor_count refuses (REFUSED)",
                  !validate_bundle_file(k.path, &status) &&
                  status == CONSENSUS_INSTALL_REFUSED);
    }
    {
        struct rom_state_checkpoint bad = rom;
        bad.nullifier_count += 1;
        checkpoints_set_rom_state_override_for_test(&bad);
        CSI_CHECK("keystone: wrong nullifier_count refuses (REFUSED)",
                  !validate_bundle_file(k.path, &status) &&
                  status == CONSENSUS_INSTALL_REFUSED);
    }

    /* NEGATIVE (transparent): the keystone also re-binds the transparent block
     * anchor at the checkpoint height. */
    {
        struct rom_state_checkpoint bad = rom;
        bad.utxo_root[0] ^= 0xff;
        bad.rom_state_root[0] = 0x11; /* keep nonzero: still a baked keystone */
        checkpoints_set_rom_state_override_for_test(&bad);
        CSI_CHECK("keystone: wrong utxo_root refuses (REFUSED)",
                  !validate_bundle_file(k.path, &status) &&
                  status == CONSENSUS_INSTALL_REFUSED);
    }

    /* NEGATIVE (placeholder): an unbaked keystone (zero shielded fold) at the
     * checkpoint height refuses rather than admit unbound state. */
    {
        struct rom_state_checkpoint ph = rom;
        memset(ph.anchor_digest, 0, 32);
        checkpoints_set_rom_state_override_for_test(&ph);
        CSI_CHECK("keystone: placeholder (unbaked) keystone refuses (REFUSED)",
                  !validate_bundle_file(k.path, &status) &&
                  status == CONSENSUS_INSTALL_REFUSED);
    }

    /* HEIGHT GUARD: a keystone at a DIFFERENT height leaves the bundle untouched
     * — proves the binding never false-refuses a bundle off the checkpoint. */
    {
        struct rom_state_checkpoint other = rom;
        other.height = k.height + 1;
        checkpoints_set_rom_state_override_for_test(&other);
        CSI_CHECK("keystone: keystone at a different height does not bind (admits)",
                  validate_bundle_file(k.path, &status));
    }

    checkpoints_reset_rom_state_override_for_test();
    fixture_free(&k);
    return failures;
}

int test_consensus_state_snapshot_install(void)
{
    printf("\n=== consensus_state_snapshot_install ===\n");
    int failures=0; char dir[256];
    test_make_tmpdir(dir,sizeof(dir),"consensus_state_install","main");
    failures += boot_install_gate_alias_tests(dir);
    failures += boot_install_utxo_mirror_reset_tests(dir);
    sqlite3 *db=NULL;
    CSI_CHECK("active DB opens",sqlite3_open(":memory:",&db)==SQLITE_OK);
    CSI_CHECK("shared bundle codec pinned SHA3 vectors",bundle_codec_kat());
    struct csi_fixture a,b,inc;
    bool fixtures=fixture_init(&a,dir,"a",0x10,40,true)&&
                  fixture_init(&b,dir,"b",0x80,60,true)&&
                  fixture_init(&inc,dir,"inc",0x40,80,false);
    CSI_CHECK("fixtures build",fixtures);
    CSI_CHECK("generation A active canary seeds",seed_active(db,&a));
    CSI_CHECK("generation A coherent",active_is(db,&a));

    CSI_CHECK("generation B bundle writes",write_bundle(&b,CSI_VALID));
    char sidecar[sizeof(b.path) + 16];
    snprintf(sidecar,sizeof(sidecar),"%s-wal",b.path);
    FILE *sidecar_file=fopen(sidecar,"wb");
    CSI_CHECK("unfinished bundle sidecar fixture writes",sidecar_file!=NULL);
    if(sidecar_file) fclose(sidecar_file);
    CSI_CHECK("unfinished bundle sidecar is refused",
              install(db,&b,CONSENSUS_INSTALL_FAIL_NONE,
                      CONSENSUS_INSTALL_REFUSED));
    CSI_CHECK("sidecar refusal preserves generation A",active_is(db,&a));
    unlink(sidecar);
    for(int fp=CONSENSUS_INSTALL_FAIL_AFTER_BUNDLE_OPEN;
        fp<=CONSENSUS_INSTALL_FAIL_AFTER_BUNDLE_VALIDATE;fp++) {
        char label[112]; snprintf(label,sizeof(label),"failpoint %d refuses",fp);
        CSI_CHECK(label,install(db,&b,(enum consensus_state_install_failpoint)fp,
                                CONSENSUS_INSTALL_INJECTED_FAILURE));
        snprintf(label,sizeof(label),"failpoint %d preserves A",fp);
        CSI_CHECK(label,active_is(db,&a));
    }
    b.height++;
    CSI_CHECK("wrong caller height assertion is refused",
              install(db,&b,CONSENSUS_INSTALL_FAIL_NONE,
                      CONSENSUS_INSTALL_REFUSED));
    b.height--;
    b.block_hash[0]^=1;
    CSI_CHECK("wrong caller hash assertion is refused",
              install(db,&b,CONSENSUS_INSTALL_FAIL_NONE,
                      CONSENSUS_INSTALL_REFUSED));
    b.block_hash[0]^=1;
    CSI_CHECK("caller assertion refusals preserve generation A",active_is(db,&a));

    enum csi_fault faults[]={CSI_WRONG_UTXO_ROOT,CSI_WRONG_SUPPLY,
        CSI_WRONG_ANCHOR_DIGEST,CSI_WRONG_NF_DIGEST,CSI_BAD_TREE_ROOT,
        CSI_BAD_COMPLETE_CURSOR,CSI_ZERO_PROOF,CSI_TEXT_ANCHOR_POOL,
        CSI_TEXT_NF_POOL,CSI_WRONG_FRONTIER_ROOT,CSI_WRONG_FRONTIER_HEIGHT,
        CSI_BAD_SOURCE_RECEIPT,CSI_BAD_SOURCE_EPOCH,CSI_UNKNOWN_PROFILE,
        CSI_EMBEDDED_BUNDLE_SCHEMA,CSI_EMBEDDED_RECEIPT_SCHEMA,
        CSI_TEXT_BLOCK_HASH,CSI_TEXT_PROOF_CURSOR,CSI_TEXT_COIN_VALUE,
        CSI_REAL_ANCHOR_HEIGHT,CSI_REAL_NF_HEIGHT,
        CSI_EXTRA_SCHEMA_OBJECT,
        CSI_EXTRA_SCHEMA_COLUMN,CSI_EMPTY_UTXO,
        CSI_DUPLICATE_NONFRONTIER_ANCHOR_HEIGHT,
        CSI_CORRUPT_NONTIP_ANCHOR_TREE,CSI_CORRUPT_TIP_ANCHOR_TREE};
    for(size_t i=0;i<sizeof(faults)/sizeof(faults[0]);i++) {
        CSI_CHECK("malformed bundle writes",write_bundle(&b,faults[i]));
        CSI_CHECK("malformed bundle refused",install(db,&b,CONSENSUS_INSTALL_FAIL_NONE,
                                                      CONSENSUS_INSTALL_REFUSED));
        CSI_CHECK("malformed bundle publishes nothing",active_is(db,&a));
        /* Reinitialize mutated in-memory metadata/tree roots for next case. */
        fixture_free(&b);
        CSI_CHECK("candidate fixture reinitialized",fixture_init(&b,dir,"b",0x80,60,true));
    }

    /* D1 tip-frontier-only anchor verification — explicit, self-documenting
     * coverage of exactly what each layer catches:
     *   - byte-integrity floor (every row): truncation / garbage / trailing
     *     bytes. Proven by CSI_CORRUPT_NONTIP_ANCHOR_TREE (a well-formed tree +
     *     stray byte on a genuine NON-tip row is refused even though non-tip
     *     rows skip the Pedersen recompute).
     *   - tip Pedersen bind (per-pool MAX(height) row only): stored-key vs
     *     recomputed-root agreement. Proven by CSI_CORRUPT_TIP_ANCHOR_TREE (a
     *     valid tree whose root != the stored key is caught only because the
     *     row is the pool tip). A wrong-key WELL-FORMED tree on a NON-tip row
     *     is by design NOT recomputed here — it is delegated to the whole-file
     *     digest + this tip bind (the anchor_digest, checkpoint-bound, still
     *     commits every row's exact key+tree bytes).
     * A valid multi-height bundle (genuine non-tip row present) must still be
     * ADMITTED, proving the restructure did not start rejecting historical
     * rows — so the refusals above fire on the corruption, not the shape. */
    CSI_CHECK("D1: valid multiheight-anchor bundle writes",
              write_bundle(&b, CSI_MULTIHEIGHT_VALID));
    struct consensus_state_artifact_evidence *d1_ev = NULL;
    struct zcl_result d1_open =
        consensus_state_artifact_evidence_open(b.path, -1, &d1_ev);
    CSI_CHECK("D1: valid multiheight bundle admitted (non-tip rows accepted, "
              "tip Pedersen verified)", d1_open.ok && d1_ev != NULL);
    if (d1_ev)
        consensus_state_artifact_evidence_free(d1_ev);
    fixture_free(&b);
    CSI_CHECK("D1: fixture reinit after positive control",
              fixture_init(&b,dir,"b",0x80,60,true));

    /* Empty scripts are consensus-valid.  Keep one as a true zero-length
     * SQLite BLOB through admission, candidate copy, and activation. */
    b.coins[1].script_len = 0;
    CSI_CHECK("generation B final bundle writes",write_bundle(&b,CSI_VALID));
    struct consensus_state_artifact_evidence *artifact = NULL;
    struct zcl_result artifact_opened =
        consensus_state_artifact_evidence_open(b.path, -1, &artifact);
    CSI_CHECK("valid artifact creates opaque evidence",
              artifact_opened.ok && artifact != NULL);
    struct consensus_state_bundle_manifest admitted_manifest;
    uint8_t admitted_digest[32];
    CSI_CHECK("opaque evidence exposes only validated manifest copy",
              consensus_state_artifact_evidence_manifest_copy(
                  artifact, &admitted_manifest) &&
              admitted_manifest.height == b.height &&
              memcmp(admitted_manifest.block_hash, b.block_hash, 32) == 0);
    CSI_CHECK("opaque evidence digest is the admitted artifact digest",
              consensus_state_artifact_evidence_digest(
                  artifact, admitted_digest) &&
              memcmp(admitted_digest, b.artifact, 32) == 0);

    char moved_path[sizeof(b.path) + 16];
    snprintf(moved_path, sizeof(moved_path), "%s-moved", b.path);
    unlink(moved_path);
    CSI_CHECK("admitted artifact can be renamed after descriptor pin",
              rename(b.path, moved_path) == 0);
    FILE *replacement = fopen(b.path, "wb");
    CSI_CHECK("path replacement fixture writes", replacement != NULL);
    if (replacement) {
        fputs("not the admitted artifact", replacement);
        fclose(replacement);
    }
    CSI_CHECK("inode rename invalidates admitted metadata receipt",
              !consensus_state_artifact_evidence_manifest_copy(
                  artifact, &admitted_manifest));
    consensus_state_artifact_evidence_free(artifact);
    artifact = NULL;
    unlink(b.path);
    CSI_CHECK("fixture restores admitted artifact path",
              rename(moved_path, b.path) == 0);

    char symlink_path[sizeof(b.path) + 16];
    snprintf(symlink_path, sizeof(symlink_path), "%s-link", b.path);
    unlink(symlink_path);
    CSI_CHECK("bundle symlink fixture writes",
              symlink(b.path, symlink_path) == 0);
    artifact_opened = consensus_state_artifact_evidence_open(symlink_path, -1, &artifact);
    CSI_CHECK("symlink artifact admission refuses",
              !artifact_opened.ok && artifact == NULL);
    unlink(symlink_path);
    CSI_CHECK("writable artifact fixture enables owner write",
              chmod(b.path, 0600) == 0);
    artifact_opened = consensus_state_artifact_evidence_open(b.path, -1, &artifact);
    CSI_CHECK("writable artifact admission refuses",
              !artifact_opened.ok && artifact == NULL);
    CSI_CHECK("artifact fixture returns immutable",
              chmod(b.path, 0400) == 0);

    /* A retained writer can restore bytes and mtime after a temporary rewrite,
     * but Linux advances ctime. Admission must bind ctime so that semantic
     * reads cannot be detached from the final byte image this way. */
    int retained_fd = -1;
    bool retained_ready = chmod(b.path, 0600) == 0;
    if (retained_ready)
        retained_fd = open(b.path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (retained_fd < 0 || chmod(b.path, 0400) != 0)
        retained_ready = false;
    artifact_opened = retained_ready
        ? consensus_state_artifact_evidence_open(b.path, -1, &artifact)
        : ZCL_ERR(-1, "retained writer fixture setup failed");
    CSI_CHECK("retained-writer fixture admits stable original",
              artifact_opened.ok && artifact != NULL);
    struct stat retained_before;
    uint8_t original_byte = 0;
    bool restored = artifact && retained_fd >= 0 &&
        fstat(retained_fd, &retained_before) == 0 &&
        pread(retained_fd, &original_byte, 1, 100) == 1;
    uint8_t temporary_byte = (uint8_t)(original_byte ^ 1u);
    if (restored)
        restored = pwrite(retained_fd, &temporary_byte, 1, 100) == 1 &&
                   fsync(retained_fd) == 0 &&
                   pwrite(retained_fd, &original_byte, 1, 100) == 1 &&
                   fsync(retained_fd) == 0;
    struct timespec restore_times[2] = {
        retained_before.st_atim, retained_before.st_mtim
    };
    if (restored)
        restored = futimens(retained_fd, restore_times) == 0;
    CSI_CHECK("retained writer restores exact bytes and mtime", restored);
    CSI_CHECK("ctime still invalidates restored retained-writer receipt",
              artifact &&
              !consensus_state_artifact_evidence_revalidate(artifact));
    consensus_state_artifact_evidence_free(artifact);
    artifact = NULL;
    if (retained_fd >= 0)
        close(retained_fd);
    CSI_CHECK("valid artifact restores after retained-writer test",
              write_bundle(&b, CSI_VALID));

    artifact_opened = consensus_state_artifact_evidence_open(b.path, -1, &artifact);
    CSI_CHECK("mutation fixture admits original artifact",
              artifact_opened.ok && artifact != NULL);
    uint8_t receipt_digest[32];
    CSI_CHECK("validation receipt binds full file and local identity",
              consensus_state_artifact_evidence_receipt_digest(
                  artifact, receipt_digest));
    int mutate_fd = -1;
    uint8_t changed_byte = 0;
    bool mutated = chmod(b.path, 0600) == 0;
    if (mutated)
        mutate_fd = open(b.path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (mutate_fd < 0 || pread(mutate_fd, &changed_byte, 1, 100) != 1)
        mutated = false;
    changed_byte ^= 1u;
    if (mutated && (pwrite(mutate_fd, &changed_byte, 1, 100) != 1 ||
                    fsync(mutate_fd) != 0))
        mutated = false;
    if (mutate_fd >= 0)
        close(mutate_fd);
    if (chmod(b.path, 0400) != 0)
        mutated = false;
    CSI_CHECK("post-validation mutation fixture writes", mutated);
    CSI_CHECK("complete-file mutation makes receipt stale",
              !consensus_state_artifact_evidence_revalidate(artifact) &&
              !consensus_state_artifact_evidence_receipt_digest(
                  artifact, receipt_digest));
    consensus_state_artifact_evidence_free(artifact);
    artifact = NULL;
    CSI_CHECK("valid artifact restores after mutation test",
              write_bundle(&b, CSI_VALID));

    CSI_CHECK("valid complete claim is verified but contained",
              install(db,&b,CONSENSUS_INSTALL_FAIL_NONE,
                      CONSENSUS_INSTALL_VERIFIED_CONTAINED));
    CSI_CHECK("contained complete claim preserves generation A",active_is(db,&a));

    int candidate_dirfd=open(dir,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    CSI_CHECK("candidate output directory capability opens",candidate_dirfd>=0);
    artifact_opened=consensus_state_artifact_evidence_open(b.path, -1, &artifact);
    CSI_CHECK("candidate source admits immutable complete artifact",
              artifact_opened.ok&&artifact!=NULL);
    uint8_t candidate_admission[32];
    CSI_CHECK("candidate source admission receipt is available",
              consensus_state_artifact_evidence_receipt_digest(
                  artifact,candidate_admission));
    struct consensus_state_candidate_result reserved;
    CSI_CHECK("candidate API cannot name the active progress store",
              !candidate_build(artifact,candidate_dirfd,"progress.kv",
                               CONSENSUS_CANDIDATE_FAIL_NONE,&reserved)&&
              reserved.status==CONSENSUS_CANDIDATE_REFUSED&&
              candidate_output_absent(candidate_dirfd,"progress.kv"));
    CSI_CHECK("candidate active-store family refusal is case-independent",
              !candidate_build(artifact,candidate_dirfd,"Progress.KV.next",
                               CONSENSUS_CANDIDATE_FAIL_NONE,&reserved)&&
              reserved.status==CONSENSUS_CANDIDATE_REFUSED&&
              candidate_output_absent(candidate_dirfd,"Progress.KV.next"));
    struct consensus_state_candidate_result short_name;
    CSI_CHECK("candidate short normalized name is handled safely",
              candidate_build(artifact,candidate_dirfd,"x",
                              CONSENSUS_CANDIDATE_FAIL_NONE,&short_name)&&
              short_name.status==CONSENSUS_CANDIDATE_VERIFIED_CONTAINED);
    CSI_CHECK("candidate short-name fixture removes",
              unlinkat(candidate_dirfd,"x",0)==0);
    for(int fp=CONSENSUS_CANDIDATE_FAIL_AFTER_STAGING_OPEN;
        fp<=CONSENSUS_CANDIDATE_FAIL_AFTER_REOPEN;fp++) {
        char name[64],label[128];
        snprintf(name,sizeof(name),"failed-%d.progress.kv",fp);
        struct consensus_state_candidate_result failed;
        bool built=candidate_build(
            artifact,candidate_dirfd,name,
            (enum consensus_state_candidate_failpoint)fp,&failed);
        snprintf(label,sizeof(label),"candidate failpoint %d is injected",fp);
        CSI_CHECK(label,!built&&
            failed.status==CONSENSUS_CANDIDATE_INJECTED_FAILURE);
        snprintf(label,sizeof(label),"candidate failpoint %d has no final",fp);
        CSI_CHECK(label,candidate_output_absent(candidate_dirfd,name));
        snprintf(label,sizeof(label),"candidate failpoint %d cleans staging",fp);
        CSI_CHECK(label,candidate_staging_count(dir)==0);
        snprintf(label,sizeof(label),"candidate failpoint %d preserves active",fp);
        CSI_CHECK(label,active_is(db,&a));
    }
    struct candidate_sidecar_hook sidecar_hook={
        .dirfd=candidate_dirfd,
        .name="raced.progress.kv-wal",
    };
    consensus_state_snapshot_candidate_test_set_before_link_hook(
        candidate_create_sidecar,&sidecar_hook);
    struct consensus_state_candidate_result sidecar_race;
    CSI_CHECK("candidate late sidecar race refuses publication",
              !candidate_build(artifact,candidate_dirfd,"raced.progress.kv",
                               CONSENSUS_CANDIDATE_FAIL_NONE,&sidecar_race)&&
              sidecar_race.status==CONSENSUS_CANDIDATE_OUTPUT_ERROR&&
              sidecar_hook.created&&
              candidate_output_absent(candidate_dirfd,"raced.progress.kv"));
    CSI_CHECK("candidate sidecar race preserves active generation",
              active_is(db,&a));
    CSI_CHECK("candidate sidecar race fixture removes",
              unlinkat(candidate_dirfd,sidecar_hook.name,0)==0);

    struct candidate_retained_writer_hook retained_writer={
        .dirfd=candidate_dirfd,
        .writer_fd=-1,
    };
    consensus_state_snapshot_export_test_set_after_staging_create_hook(
        candidate_retain_staging_writer,&retained_writer);
    struct consensus_state_candidate_result retained_writer_result;
    CSI_CHECK("candidate retained writable descriptor refuses publication",
              !candidate_build(artifact,candidate_dirfd,
                               "retained-writer.progress.kv",
                               CONSENSUS_CANDIDATE_FAIL_NONE,
                               &retained_writer_result)&&
              retained_writer_result.status==
                  CONSENSUS_CANDIDATE_OUTPUT_ERROR&&
              retained_writer.ran&&retained_writer.writer_fd>=0&&
              candidate_output_absent(candidate_dirfd,
                                      "retained-writer.progress.kv")&&
              candidate_staging_count(dir)==0);
    if(retained_writer.writer_fd>=0) close(retained_writer.writer_fd);

    struct candidate_thread_fixture concurrent[2]={
        {.artifact=artifact,.dirfd=candidate_dirfd,
         .name="concurrent-a.progress.kv"},
        {.artifact=artifact,.dirfd=candidate_dirfd,
         .name="concurrent-b.progress.kv"},
    };
    pthread_t candidate_threads[2];
    bool thread_a_started=pthread_create(
        &candidate_threads[0],NULL,candidate_build_thread,&concurrent[0])==0;
    bool thread_b_started=pthread_create(
        &candidate_threads[1],NULL,candidate_build_thread,&concurrent[1])==0;
    if(thread_a_started)
        pthread_join(candidate_threads[0],NULL);
    if(thread_b_started)
        pthread_join(candidate_threads[1],NULL);
    CSI_CHECK("shared evidence serializes concurrent candidate builds",
              thread_a_started&&thread_b_started&&
              concurrent[0].built&&concurrent[1].built&&
              concurrent[0].result.status==
                  CONSENSUS_CANDIDATE_VERIFIED_CONTAINED&&
              concurrent[1].result.status==
                  CONSENSUS_CANDIDATE_VERIFIED_CONTAINED);
    CSI_CHECK("concurrent candidates publish complete immutable files",
              !candidate_output_absent(candidate_dirfd,concurrent[0].name)&&
              !candidate_output_absent(candidate_dirfd,concurrent[1].name)&&
              candidate_staging_count(dir)==0);
    (void)unlinkat(candidate_dirfd,concurrent[0].name,0);
    (void)unlinkat(candidate_dirfd,concurrent[1].name,0);

    struct consensus_state_candidate_result candidate_result;
    CSI_CHECK("complete evidence builds contained candidate generation",
              candidate_build(artifact,candidate_dirfd,"candidate.progress.kv",
                              CONSENSUS_CANDIDATE_FAIL_NONE,
                              &candidate_result)&&
              candidate_result.status==
                  CONSENSUS_CANDIDATE_VERIFIED_CONTAINED&&
              candidate_result.source_clean&&
              candidate_result.validation_profile==
                  CONSENSUS_STATE_VALIDATION_FULL&&
              candidate_result.height==b.height&&
              candidate_result.utxo_count==2&&
              candidate_result.anchor_count==2&&
              candidate_result.nullifier_count==2&&
              memcmp(candidate_result.artifact_digest,b.artifact,32)==0&&
              digest_nonzero(candidate_result.candidate_file_digest));
    CSI_CHECK("successful candidate leaves no private staging",
              candidate_staging_count(dir)==0);
    char candidate_path[512];
    snprintf(candidate_path,sizeof(candidate_path),"%s/%s",dir,
             "candidate.progress.kv");
    struct stat candidate_stat;
    CSI_CHECK("candidate output is immutable regular file",
              lstat(candidate_path,&candidate_stat)==0&&
              S_ISREG(candidate_stat.st_mode)&&
              (candidate_stat.st_mode&(S_IWUSR|S_IWGRP|S_IWOTH))==0);
    uint8_t candidate_disk_digest[32];
    CSI_CHECK("candidate result binds exact final file bytes",
              candidate_file_digest(candidate_path,candidate_disk_digest)&&
              memcmp(candidate_disk_digest,
                     candidate_result.candidate_file_digest,32)==0);
    sqlite3 *candidate_db=NULL;
    CSI_CHECK("candidate independently opens read-only",
              sqlite3_open_v2(candidate_path,&candidate_db,
                              SQLITE_OPEN_READONLY|SQLITE_OPEN_NOMUTEX,
                              NULL)==SQLITE_OK);
    CSI_CHECK("candidate complete components equal admitted bundle",
              candidate_db&&active_is(candidate_db,&b));
    CSI_CHECK("candidate cursors, logs, base, and provenance are exact",
              candidate_db&&candidate_progress_parity(
                  candidate_db,&b,candidate_admission));
    int64_t candidate_empty_scripts = -1;
    CSI_CHECK("candidate preserves empty script as zero-length BLOB",
              candidate_db&&candidate_query_i64(
                  candidate_db,
                  "SELECT count(*) FROM coins WHERE "
                  "typeof(script)='blob' AND length(script)=0",
                  &candidate_empty_scripts)&&candidate_empty_scripts==1);
    if(candidate_db) sqlite3_close(candidate_db);
    struct consensus_state_candidate_result collision;
    CSI_CHECK("candidate final name collision refuses no-replace",
              !candidate_build(artifact,candidate_dirfd,"candidate.progress.kv",
                               CONSENSUS_CANDIDATE_FAIL_NONE,&collision)&&
              collision.status==CONSENSUS_CANDIDATE_REFUSED);
    struct stat candidate_after_collision;
    CSI_CHECK("candidate collision preserves exact published inode",
              lstat(candidate_path,&candidate_after_collision)==0&&
              candidate_after_collision.st_dev==candidate_stat.st_dev&&
              candidate_after_collision.st_ino==candidate_stat.st_ino&&
              candidate_after_collision.st_size==candidate_stat.st_size);
    char active_candidate_path[512];
    snprintf(active_candidate_path,sizeof(active_candidate_path),"%s/%s",dir,
             "progress.kv");
    CSI_CHECK("contained candidate can be moved only for boot refusal test",
              rename(candidate_path,active_candidate_path)==0&&
              chmod(active_candidate_path,0600)==0);
    CSI_CHECK("progress store refuses admission-only candidate authority",
              !progress_store_open(dir)&&progress_store_db()==NULL);
    CSI_CHECK("contained candidate restores after boot refusal test",
              chmod(active_candidate_path,0400)==0&&
              rename(active_candidate_path,candidate_path)==0);
    CSI_CHECK("candidate construction never mutates active generation",
              active_is(db,&a));
    consensus_state_artifact_evidence_free(artifact);
    artifact=NULL;
    unlink(candidate_path);
    if(candidate_dirfd>=0) close(candidate_dirfd);

    b.anchors[0].height = b.height - 1;
    b.anchors[1].height = b.height - 1;
    CSI_CHECK("unchanged-frontier bundle writes with latest roots below H",
              write_bundle(&b,CSI_VALID));
    CSI_CHECK("latest roots below H validate without fabricating anchor rows",
              install(db,&b,CONSENSUS_INSTALL_FAIL_NONE,
                      CONSENSUS_INSTALL_VERIFIED_CONTAINED));
    CSI_CHECK("contained older-frontier claim preserves generation A",
              active_is(db,&a));
    CSI_CHECK("incomplete bundle writes",write_bundle(&inc,CSI_VALID));
    CSI_CHECK("valid incomplete bundle is verified but contained",
              install(db,&inc,CONSENSUS_INSTALL_FAIL_NONE,
                      CONSENSUS_INSTALL_VERIFIED_CONTAINED));
    CSI_CHECK("contained incomplete bundle preserves generation A",active_is(db,&a));
    int incomplete_dirfd=open(dir,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    artifact_opened=consensus_state_artifact_evidence_open(inc.path, -1, &artifact);
    CSI_CHECK("incomplete artifact can be admitted for contained inspection",
              artifact_opened.ok&&artifact!=NULL&&incomplete_dirfd>=0);
    struct consensus_state_candidate_result incomplete_candidate;
    CSI_CHECK("incomplete shielded history cannot become a candidate",
              !candidate_build(artifact,incomplete_dirfd,
                               "incomplete.progress.kv",
                               CONSENSUS_CANDIDATE_FAIL_NONE,
                               &incomplete_candidate)&&
              incomplete_candidate.status==CONSENSUS_CANDIDATE_REFUSED&&
              candidate_output_absent(incomplete_dirfd,
                                      "incomplete.progress.kv")&&
              candidate_staging_count(dir)==0);
    CSI_CHECK("incomplete candidate refusal preserves generation A",
              active_is(db,&a));
    consensus_state_artifact_evidence_free(artifact);
    artifact=NULL;
    if(incomplete_dirfd>=0) close(incomplete_dirfd);

    /* ── A3/A2/D3: ACTIVATE-mode install into a live (wedged) progress store ──
     * Open a REAL process-singleton progress store, seed it into the exact
     * anchor_backfill_gap WEDGE (a borrowed coin + EMPTY shielded tables with a
     * positive activation cursor), then prove: (i) a tampered bundle refuses and
     * leaves the wedge intact; (ii) a non-ADMIT publication-CAS decision gates
     * the install out; (iii) an ADMIT complete bundle installs atomically and
     * CURES the wedge, forcing the reducer cursors to the anchor so the fold
     * resumes there; (iv) a physically restorable prior generation is captured. */
    {
        /* An earlier leg left b's anchor heights at b.height-1; restore them so
         * the complete-frontier invariant (anchor height == block height) holds
         * for active_is below. */
        b.anchors[0].height = b.height;
        b.anchors[1].height = b.height;
        char active_dir[320];
        snprintf(active_dir, sizeof(active_dir), "%s/activate", dir);
        CSI_CHECK("activate: datadir", mkdir(active_dir, 0700) == 0);
        CSI_CHECK("activate: live progress store opens",
                  progress_store_open(active_dir));
        sqlite3 *pdb = progress_store_db();
        int active_dir_fd = open(active_dir,
                                 O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        reducer_frontier_test_set_compiled_anchor(0);

        uint8_t borrowed_txid[32];
        memset(borrowed_txid, 0x5a, sizeof(borrowed_txid));
        const uint8_t borrowed_script[] = {0x51};
        CSI_CHECK("activate: wedged store seeds (borrowed coin, empty anchors, "
                  "positive activation cursor)",
                  pdb && coins_kv_ensure_schema(pdb) &&
                  progress_meta_table_ensure(pdb) &&
                  anchor_kv_ensure_schema(pdb) &&
                  nullifier_kv_ensure_schema(pdb) &&
                  anchor_kv_initialize_history(pdb, b.height) &&
                  nullifier_kv_initialize_history(pdb, b.height) &&
                  coins_kv_add(pdb, borrowed_txid, 0, 4242, b.height, false,
                               borrowed_script, sizeof(borrowed_script)));
        const char replay_value[] = "60";
        uint8_t backfill_binding[32];
        memset(backfill_binding, 0x7b, sizeof(backfill_binding));
        const uint8_t refold_target[4] = {
            (uint8_t)(b.height & 0xff),
            (uint8_t)((b.height >> 8) & 0xff),
            (uint8_t)((b.height >> 16) & 0xff),
            (uint8_t)((b.height >> 24) & 0xff),
        };
        const uint8_t one = 1;
        CSI_CHECK("activate: wedge carries stale recovery and generation metadata",
                  progress_meta_set(pdb, SHIELDED_REPLAY_TARGET_KEY,
                                    replay_value, sizeof(replay_value) - 1) &&
                  progress_meta_set(pdb, SHIELDED_REPLAY_NEXT_KEY,
                                    replay_value, sizeof(replay_value) - 1) &&
                  progress_meta_set(pdb, SHIELDED_REPLAY_SPROUT_STARTED_KEY,
                                    "1", 1) &&
                  progress_meta_set(pdb, SHIELDED_REPLAY_SAPLING_STARTED_KEY,
                                    "1", 1) &&
                  progress_meta_set(pdb, NULLIFIER_BACKFILL_RESUME_KEY,
                                    replay_value, sizeof(replay_value) - 1) &&
                  progress_meta_set(pdb, NULLIFIER_BACKFILL_CHAIN_KEY,
                                    backfill_binding,
                                    sizeof(backfill_binding)) &&
                  progress_meta_set(pdb, REFOLD_IN_PROGRESS_KEY, &one, 1) &&
                  progress_meta_set(pdb, REFOLD_FROM_ANCHOR_KEY, &one, 1) &&
                  progress_meta_set(pdb, REFOLD_FROM_ANCHOR_TARGET_KEY,
                                    refold_target, sizeof(refold_target)) &&
                  refold_progress_refresh(pdb) && refold_in_progress() &&
                  refold_from_anchor_active() &&
                  hs_seed_current_frontier(pdb, b.height, b.block_hash) &&
                  seed_stale_generation_metadata(pdb) &&
                  stale_generation_metadata_present(pdb));
        struct incremental_merkle_tree gate_tree;
        struct uint256 gate_root;
        int64_t gate_h = -1;
        sapling_tree_init(&gate_tree);
        CSI_CHECK("activate: pre-install sapling gate is HISTORY_INCOMPLETE "
                  "(the wedge)",
                  anchor_kv_latest_tree(pdb, ANCHOR_POOL_SAPLING, &gate_tree,
                                        &gate_root, &gate_h) ==
                      ANCHOR_KV_HISTORY_INCOMPLETE);

        struct consensus_state_activate_request areq;
        memset(&areq, 0, sizeof(areq));
        areq.expected_height = b.height;
        memcpy(areq.expected_block_hash, b.block_hash, 32);
        areq.datadir_fd = active_dir_fd;
        areq.datadir_display = active_dir;
        struct consensus_state_activate_result ares;

        /* Production is fail-closed even in this test binary: containment is
         * proven at (ii-b) below against a fully ADMIT-worthy bundle. Enable
         * the seam only for the hermetic transaction exercises. */
        areq.bundle_path = b.path;
        consensus_state_snapshot_install_activate_test_set_independent_authority(
            true);

        /* (i) Negative — a tampered (bad UTXO root) bundle must refuse. */
        CSI_CHECK("activate: tampered bundle writes",
                  write_bundle(&b, CSI_WRONG_UTXO_ROOT));
        areq.bundle_path = b.path;
        CSI_CHECK("activate: tampered bundle refuses with a typed reason",
                  !consensus_state_snapshot_install_activate(pdb, &areq, &ares) &&
                  !ares.activated &&
                  ares.status != CONSENSUS_INSTALL_ACTIVATED &&
                  ares.reason[0] != '\0');
        sapling_tree_init(&gate_tree);
        CSI_CHECK("activate: tampered refusal leaves the store wedged/intact",
                  coins_kv_count(pdb) == 1 &&
                  anchor_kv_latest_tree(pdb, ANCHOR_POOL_SAPLING, &gate_tree,
                                        &gate_root, &gate_h) ==
                      ANCHOR_KV_HISTORY_INCOMPLETE);

        /* (ii) Negative — a non-ADMIT publication-CAS decision gates out the
         * install. Build cas_decide inputs from the validated artifact; a
         * durable frontier BEHIND the bundle height yields REFUSED. */
        CSI_CHECK("activate: valid complete bundle restored",
                  write_bundle(&b, CSI_VALID));
        CSI_CHECK("activate: valid bundle without an ADMIT receipt refuses",
                  !consensus_state_snapshot_install_activate(pdb, &areq, &ares) &&
                  strstr(ares.reason, "exact CAS-admitted") != NULL &&
                  coins_kv_count(pdb) == 1);
        struct consensus_state_artifact_evidence *ev = NULL;
        struct zcl_result evr =
            consensus_state_artifact_evidence_open(b.path, -1, &ev);
        struct consensus_state_publication_cas_inputs cin;
        memset(&cin, 0, sizeof(cin));
        bool cin_ok = evr.ok && ev &&
            consensus_state_artifact_evidence_manifest_copy(ev, &cin.manifest) &&
            consensus_state_artifact_evidence_digest(
                ev, cin.artifact_logical_digest) &&
            consensus_state_artifact_evidence_receipt_digest(
                ev, cin.artifact_receipt_digest);
        cin.chain_evidence_present = true;
        cin.chain_bound_to_artifact = true;
        memset(cin.chain_evidence_digest, 0xa5, 32);
        cin.source_receipt_present = true;
        cin.source_receipt = b.receipt;
        cin.target_lane = CONSENSUS_STATE_TARGET_LANE_COPY_PROOF;
        cin.frontier_known = true;
        memcpy(cin.frontier_hash, b.block_hash, 32);
        struct consensus_state_publication_decision_record dec;
        struct consensus_state_publication_decision_record active_decision;
        memset(&active_decision, 0, sizeof(active_decision));
        cin.frontier_height = b.height;
        consensus_state_publication_cas_decide(&cin, &dec);
        CSI_CHECK("activate: complete bundle + bound evidence CAS-decides ADMIT",
                  cin_ok && dec.decision == CONSENSUS_PUBLICATION_ADMIT);
        if (dec.decision == CONSENSUS_PUBLICATION_ADMIT) {
            active_decision = dec;
            memcpy(areq.expected_artifact_receipt_digest,
                   dec.artifact_receipt_digest, 32);
            areq.publication_decision = &active_decision;
        }
        cin.frontier_height = b.height - 1;
        consensus_state_publication_cas_decide(&cin, &dec);
        bool refused = dec.decision != CONSENSUS_PUBLICATION_ADMIT &&
                       dec.refusal ==
                           CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_BEHIND;
        if (dec.decision == CONSENSUS_PUBLICATION_ADMIT) /* gate: never reached */
            (void)consensus_state_snapshot_install_activate(pdb, &areq, &ares);
        sapling_tree_init(&gate_tree);
        CSI_CHECK("activate: non-ADMIT CAS gates out the install (store "
                  "untouched, still wedged)",
                  refused && coins_kv_count(pdb) == 1 &&
                  anchor_kv_latest_tree(pdb, ANCHOR_POOL_SAPLING, &gate_tree,
                                        &gate_root, &gate_h) ==
                      ANCHOR_KV_HISTORY_INCOMPLETE);

        /* Replace the admitted pathname with a fresh, independently valid
         * inode carrying the same logical bundle and height/hash. The old CAS
         * receipt must not authorize it. */
        struct stat admitted_path_stat, replacement_path_stat;
        bool admitted_stat_ok = lstat(b.path, &admitted_path_stat) == 0;
        CSI_CHECK("activate: same-height/hash pathname replacement writes",
                  admitted_stat_ok && write_bundle(&b, CSI_VALID) &&
                  lstat(b.path, &replacement_path_stat) == 0 &&
                  (replacement_path_stat.st_dev != admitted_path_stat.st_dev ||
                   replacement_path_stat.st_ino != admitted_path_stat.st_ino));
        CSI_CHECK("activate: stale ADMIT receipt refuses pathname replacement",
                  !consensus_state_snapshot_install_activate(pdb, &areq, &ares) &&
                  strstr(ares.reason, "exact CAS-admitted") != NULL &&
                  coins_kv_count(pdb) == 1);
        if (ev)
            consensus_state_artifact_evidence_free(ev);

        /* A retained writable descriptor can still alter a mode-0400 inode.
         * Mutate after the stream but before COMMIT and prove the final source
         * revalidation rolls the live transaction back. */
        int retained_writer_fd = -1;
        bool writer_ready = chmod(b.path, 0600) == 0 &&
                            (retained_writer_fd =
                                 open(b.path, O_RDWR | O_CLOEXEC)) >= 0 &&
                            chmod(b.path, 0400) == 0;
        CSI_CHECK("activate: retained writer fixture opens before admission",
                  writer_ready);
        ev = NULL;
        evr = consensus_state_artifact_evidence_open(b.path, -1, &ev);
        bool replacement_cin_ok = evr.ok && ev &&
            consensus_state_artifact_evidence_manifest_copy(ev, &cin.manifest) &&
            consensus_state_artifact_evidence_digest(
                ev, cin.artifact_logical_digest) &&
            consensus_state_artifact_evidence_receipt_digest(
                ev, cin.artifact_receipt_digest);
        cin.frontier_height = b.height;
        consensus_state_publication_cas_decide(&cin, &dec);
        CSI_CHECK("activate: replacement receives a fresh exact ADMIT receipt",
                  replacement_cin_ok &&
                  dec.decision == CONSENSUS_PUBLICATION_ADMIT);
        if (dec.decision == CONSENSUS_PUBLICATION_ADMIT) {
            active_decision = dec;
            memcpy(areq.expected_artifact_receipt_digest,
                   dec.artifact_receipt_digest, 32);
            areq.publication_decision = &active_decision;
        }
        if (ev)
            consensus_state_artifact_evidence_free(ev);

        struct activate_retained_writer_hook mutate_hook = {
            .writer_fd = retained_writer_fd,
        };
        consensus_state_snapshot_install_activate_test_set_after_stream_hook(
            activate_mutate_retained_writer, &mutate_hook);
        bool mutation_refused =
            !consensus_state_snapshot_install_activate(pdb, &areq, &ares);
        consensus_state_snapshot_install_activate_test_set_after_stream_hook(
            NULL, NULL);
        CSI_CHECK("activate: post-stream source mutation rolls back before COMMIT",
                  mutation_refused && mutate_hook.ran && mutate_hook.mutated &&
                  strstr(ares.reason,
                         "artifact evidence changed during activation stream") !=
                      NULL &&
                  coins_kv_count(pdb) == 1);
        if (retained_writer_fd >= 0)
            (void)close(retained_writer_fd);
        if (ares.prior_generation_path[0])
            (void)unlink(ares.prior_generation_path);

        /* The persistently mutated inode needs a new valid artifact. Retain a
         * writer before the next admission so a second regression can mutate
         * and restore the source bytes while leaving a bad streamed result. */
        CSI_CHECK("activate: valid artifact restored after source mutation",
                  write_bundle(&b, CSI_VALID));
        int transient_writer_fd = -1;
        bool transient_writer_ready = chmod(b.path, 0600) == 0 &&
            (transient_writer_fd = open(b.path, O_RDWR | O_CLOEXEC)) >= 0 &&
            chmod(b.path, 0400) == 0;
        CSI_CHECK("activate: transient writer fixture opens before admission",
                  transient_writer_ready);
        ev = NULL;
        evr = consensus_state_artifact_evidence_open(b.path, -1, &ev);
        bool transient_cin_ok = evr.ok && ev &&
            consensus_state_artifact_evidence_manifest_copy(ev, &cin.manifest) &&
            consensus_state_artifact_evidence_digest(
                ev, cin.artifact_logical_digest) &&
            consensus_state_artifact_evidence_receipt_digest(
                ev, cin.artifact_receipt_digest);
        cin.frontier_height = b.height;
        consensus_state_publication_cas_decide(&cin, &dec);
        CSI_CHECK("activate: transient fixture receives exact ADMIT receipt",
                  transient_cin_ok &&
                  dec.decision == CONSENSUS_PUBLICATION_ADMIT);
        if (dec.decision == CONSENSUS_PUBLICATION_ADMIT) {
            active_decision = dec;
            memcpy(areq.expected_artifact_receipt_digest,
                   dec.artifact_receipt_digest, 32);
            areq.publication_decision = &active_decision;
        }
        if (ev)
            consensus_state_artifact_evidence_free(ev);

        struct activate_transient_restore_hook transient_hook = {
            .writer_fd = transient_writer_fd,
            .progress_db = pdb,
        };
        consensus_state_snapshot_install_activate_test_set_after_stream_hook(
            activate_transient_restore_and_corrupt_destination,
            &transient_hook);
        bool transient_refused =
            !consensus_state_snapshot_install_activate(pdb, &areq, &ares);
        consensus_state_snapshot_install_activate_test_set_after_stream_hook(
            NULL, NULL);
        CSI_CHECK("activate: transient source restore cannot hide bad "
                  "destination state",
                  transient_refused && transient_hook.ran &&
                  transient_hook.source_mutated &&
                  transient_hook.source_restored &&
                  transient_hook.destination_mutated &&
                  strstr(ares.reason,
                         "installed destination failed nullifier digest") !=
                      NULL &&
                  coins_kv_count(pdb) == 1);
        if (transient_writer_fd >= 0)
            (void)close(transient_writer_fd);
        if (ares.prior_generation_path[0])
            (void)unlink(ares.prior_generation_path);

        /* Restored bytes remain semantically valid, but the exact CAS receipt
         * is metadata-bound, so positive activation requires re-admission. */
        ev = NULL;
        evr = consensus_state_artifact_evidence_open(b.path, -1, &ev);
        bool final_cin_ok = evr.ok && ev &&
            consensus_state_artifact_evidence_manifest_copy(ev, &cin.manifest) &&
            consensus_state_artifact_evidence_digest(
                ev, cin.artifact_logical_digest) &&
            consensus_state_artifact_evidence_receipt_digest(
                ev, cin.artifact_receipt_digest);
        consensus_state_publication_cas_decide(&cin, &dec);
        CSI_CHECK("activate: transient-restored artifact receives final ADMIT "
                  "receipt",
                  final_cin_ok &&
                  dec.decision == CONSENSUS_PUBLICATION_ADMIT);
        if (dec.decision == CONSENSUS_PUBLICATION_ADMIT) {
            active_decision = dec;
            memcpy(areq.expected_artifact_receipt_digest,
                   dec.artifact_receipt_digest, 32);
            areq.publication_decision = &active_decision;
        }
        if (ev)
            consensus_state_artifact_evidence_free(ev);

        /* The classified directory capability is part of activation
         * authority; a same-process handle for another directory must refuse
         * before backup or mutation. */
        int wrong_dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        int admitted_dir_fd = areq.datadir_fd;
        areq.datadir_fd = wrong_dir_fd;
        CSI_CHECK("activate: mismatched datadir capability refuses",
                  wrong_dir_fd >= 0 &&
                  !consensus_state_snapshot_install_activate(
                      pdb, &areq, &ares) &&
                  strstr(ares.reason, "classified datadir capability") !=
                      NULL &&
                  coins_kv_count(pdb) == 1);
        areq.datadir_fd = admitted_dir_fd;
        if (wrong_dir_fd >= 0)
            (void)close(wrong_dir_fd);

        /* A writer outside the process discipline can commit in the narrow
         * VACUUM-to-BEGIN boundary. The same singleton connection's
         * data_version fence must catch it before any cutover write, while the
         * prior-generation image remains the state from before that commit. */
        char progress_path[384];
        /* A4: the live kernel singleton is consensus.db; the boundary writer
         * must commit to the SAME file so its data_version bump is fenced. */
        snprintf(progress_path, sizeof(progress_path), "%s/consensus.db",
                 active_dir);
        sqlite3 *boundary_writer = NULL;
        struct activate_boundary_commit_hook boundary_hook = {
            .writer = NULL,
        };
        bool boundary_open = sqlite3_open_v2(
            progress_path, &boundary_writer,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, NULL) == SQLITE_OK;
        boundary_hook.writer = boundary_writer;
        consensus_state_snapshot_install_activate_test_set_after_backup_hook(
            activate_commit_between_backup_and_begin, &boundary_hook);
        bool boundary_refused =
            !consensus_state_snapshot_install_activate(pdb, &areq, &ares);
        consensus_state_snapshot_install_activate_test_set_after_backup_hook(
            NULL, NULL);
        if (boundary_writer)
            sqlite3_close(boundary_writer);
        sqlite3 *boundary_prior = NULL;
        bool boundary_prior_ok = ares.prior_generation_path[0] != '\0' &&
            sqlite3_open_v2(ares.prior_generation_path, &boundary_prior,
                            SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
            boundary_prior;
        CSI_CHECK("activate: commit between backup and BEGIN is fenced before "
                  "cutover",
                  boundary_open && boundary_refused && boundary_hook.ran &&
                  boundary_hook.committed &&
                  strstr(ares.reason,
                         "changed between prior-generation backup") != NULL &&
                  hs_meta_present(pdb, "activate_boundary_race") &&
                  boundary_prior_ok &&
                  hs_meta_absent(boundary_prior, "activate_boundary_race"));
        if (boundary_prior)
            sqlite3_close(boundary_prior);
        CSI_CHECK("activate: boundary-race fixture cleans live marker",
                  progress_meta_delete(pdb, "activate_boundary_race"));
        if (ares.prior_generation_path[0])
            (void)unlink(ares.prior_generation_path);

        /* A valid ADMIT is still a compare-and-swap: changing only the live
         * durable tip hash after the decision must refuse inside the locked
         * cutover transaction. */
        uint8_t changed_frontier_hash[32];
        memcpy(changed_frontier_hash, b.block_hash, 32);
        changed_frontier_hash[0] ^= 0x5a;
        bool changed_frontier = hs_put_anchor_hash(
            pdb, b.height, changed_frontier_hash);
        CSI_CHECK("activate: frontier change after ADMIT refuses atomically",
                  changed_frontier &&
                  !consensus_state_snapshot_install_activate(
                      pdb, &areq, &ares) &&
                  strstr(ares.reason,
                         "ADMIT frontier changed before activation") != NULL &&
                  coins_kv_count(pdb) == 1);
        if (ares.prior_generation_path[0])
            (void)unlink(ares.prior_generation_path);
        CSI_CHECK("activate: fixture frontier restores after stale-ADMIT test",
                  hs_put_anchor_hash(pdb, b.height, b.block_hash));

        /* Force the seed boundary itself to fail after streaming. Everything,
         * including schemas/cursors and stale-session deletion, must roll back
         * to the wedged pre-install generation. */
        uint64_t generation_before_failed_cutover = 0;
        CSI_CHECK("activate: failed-cutover generation baseline reads",
                  coins_kv_get_authority_generation(
                      pdb, &generation_before_failed_cutover));
        consensus_state_snapshot_install_activate_test_fail_seed_once();
        bool seed_failed = !consensus_state_snapshot_install_activate(
            pdb, &areq, &ares);
        sapling_tree_init(&gate_tree);
        CSI_CHECK("activate: forced in-tx seed failure restores whole wedge",
                  seed_failed &&
                  ares.status == CONSENSUS_INSTALL_INJECTED_FAILURE &&
                  coins_kv_count(pdb) == 1 &&
                  anchor_kv_latest_tree(pdb, ANCHOR_POOL_SAPLING, &gate_tree,
                                        &gate_root, &gate_h) ==
                      ANCHOR_KV_HISTORY_INCOMPLETE &&
                  hs_meta_present(pdb, SHIELDED_REPLAY_TARGET_KEY) &&
                  hs_meta_present(pdb, SHIELDED_REPLAY_NEXT_KEY) &&
                  hs_meta_present(pdb, NULLIFIER_BACKFILL_RESUME_KEY) &&
                  hs_meta_present(pdb, NULLIFIER_BACKFILL_CHAIN_KEY) &&
                  hs_meta_present(pdb, REFOLD_IN_PROGRESS_KEY) &&
                  hs_meta_present(pdb, REFOLD_FROM_ANCHOR_KEY) &&
                  hs_meta_present(pdb, REFOLD_FROM_ANCHOR_TARGET_KEY) &&
                  refold_in_progress() && refold_from_anchor_active());
        CSI_CHECK("activate: failed cutover restores generation-bound metadata",
                  seed_failed && stale_generation_metadata_present(pdb));
        uint64_t generation_after_failed_cutover = UINT64_MAX;
        CSI_CHECK("activate: failed cutover rolls authority generation back",
                  coins_kv_get_authority_generation(
                      pdb, &generation_after_failed_cutover) &&
                  generation_after_failed_cutover ==
                      generation_before_failed_cutover);
        if (ares.prior_generation_path[0])
            (void)unlink(ares.prior_generation_path);

        /* The seed itself writes tip/UTXO anchor rows and trusted-base metadata.
         * Fail immediately afterward and prove those writes were enrolled in
         * the same rollback, not committed as a partial new generation. */
        consensus_state_snapshot_install_activate_test_fail_after_seed_once();
        bool post_seed_failed = !consensus_state_snapshot_install_activate(
            pdb, &areq, &ares);
        sapling_tree_init(&gate_tree);
        CSI_CHECK("activate: post-seed failure rolls back seed and whole cutover",
                  post_seed_failed &&
                  ares.status == CONSENSUS_INSTALL_INJECTED_FAILURE &&
                  strstr(ares.reason, "post-seed cutover") != NULL &&
                  coins_kv_count(pdb) == 1 &&
                  anchor_kv_latest_tree(pdb, ANCHOR_POOL_SAPLING, &gate_tree,
                                        &gate_root, &gate_h) ==
                      ANCHOR_KV_HISTORY_INCOMPLETE &&
                  hs_meta_present(pdb, SHIELDED_REPLAY_TARGET_KEY) &&
                  hs_meta_present(pdb, NULLIFIER_BACKFILL_RESUME_KEY) &&
                  hs_meta_present(pdb, REFOLD_IN_PROGRESS_KEY) &&
                  stale_generation_metadata_present(pdb));
        if (ares.prior_generation_path[0])
            (void)unlink(ares.prior_generation_path);

        /* (ii-b) Negative — WITHOUT independent-replay authority the ADMIT-worthy
         * bundle stays CONTAINED and writes NOTHING (the production posture: the
         * bundle's self-asserted digests do not authenticate its contents). */
        areq.bundle_path = b.path;
        consensus_state_snapshot_install_activate_test_set_independent_authority(
            false);
        sqlite3_int64 contained_changes = sqlite3_total_changes64(pdb);
        int contained_backups = prior_generation_count(active_dir);
        struct consensus_state_activate_result ares_contained;
        CSI_CHECK("activate: no replay receipt keeps the install VERIFIED_"
                  "CONTAINED (nothing written, still wedged)",
                  !consensus_state_snapshot_install_activate(pdb, &areq,
                                                             &ares_contained) &&
                  !ares_contained.activated &&
                  ares_contained.status ==
                      CONSENSUS_INSTALL_VERIFIED_CONTAINED &&
                  ares_contained.prior_generation_path[0] == '\0' &&
                  strstr(ares_contained.reason,
                         "independent replay-derived receipt") != NULL &&
                  sqlite3_total_changes64(pdb) == contained_changes &&
                  prior_generation_count(active_dir) == contained_backups &&
                  coins_kv_count(pdb) == 1);

        /* (iii) Positive — ADMIT path with authority granted (the ZCL_TESTING
         * hook stands in for a valid replay receipt): install atomically. */
        consensus_state_snapshot_install_activate_test_set_independent_authority(
            true);
        uint64_t generation_before_activation = 0;
        uint8_t stale_snapshot_artifact[32] = {0x6d};
        struct uss_header stale_snapshot_header = {
            .version = 2,
            .height = (uint32_t)b.height,
            .count = b.coin_count,
        };
        CSI_CHECK("activate: prior snapshot receipt binds current coins generation",
                  coins_kv_get_authority_generation(
                      pdb, &generation_before_activation) &&
                  boot_snapshot_install_marker_begin(
                      pdb, &stale_snapshot_header, stale_snapshot_artifact) &&
                  boot_snapshot_install_marker_complete(
                      pdb, stale_snapshot_artifact, true));
        CSI_CHECK("activate: complete bundle installs atomically",
                  consensus_state_snapshot_install_activate(pdb, &areq, &ares) &&
                  ares.activated &&
                  ares.status == CONSENSUS_INSTALL_ACTIVATED &&
                  ares.height == b.height && ares.utxo_count == 2 &&
                  ares.anchor_count == 2 && ares.nullifier_count == 2 &&
                  ares.hstar == b.height &&
                  ares.coins_applied_height == b.height + 1);
        uint64_t generation_after_activation = 0;
        CSI_CHECK("activate: successful cutover advances authority generation once",
                  coins_kv_get_authority_generation(
                      pdb, &generation_after_activation) &&
                  generation_before_activation != UINT64_MAX &&
                  generation_after_activation ==
                      generation_before_activation + 1u);
        int32_t stale_snapshot_applied = -1;
        bool stale_snapshot_pending = true;
        bool stale_snapshot_matches = false;
        bool stale_snapshot_frontier = true;
        CSI_CHECK("activate: replacing coins authority invalidates prior snapshot receipt",
                  !boot_snapshot_install_resume_allowed(
                      pdb, &stale_snapshot_header, stale_snapshot_artifact,
                      &stale_snapshot_applied, &stale_snapshot_pending,
                      &stale_snapshot_matches, &stale_snapshot_frontier) &&
                  !stale_snapshot_pending && stale_snapshot_matches &&
                  !stale_snapshot_frontier);
        CSI_CHECK("activate: installed coins/anchors/nullifiers match the bundle "
                  "with COMPLETE (cursor 0) history",
                  active_is(pdb, &b));
        int64_t activated_empty_scripts = -1;
        CSI_CHECK("activate: preserves empty script as zero-length BLOB",
                  candidate_query_i64(
                      pdb,
                      "SELECT count(*) FROM coins WHERE "
                      "typeof(script)='blob' AND length(script)=0",
                      &activated_empty_scripts) &&
                  activated_empty_scripts == 1);

        /* (iii-b) INDEPENDENT REPLAY RECEIPT — the store is now folded to the
         * anchor (coins_applied == anchor+1), so the offline verifier can
         * re-derive every component digest from THIS datadir's own tables (never
         * the bundle) and, on a full match, persist the receipt that authorizes
         * ACTIVATE with the ZCL_TESTING hook OFF. */
        consensus_state_snapshot_install_activate_test_set_independent_authority(
            false);
        {
            struct consensus_state_replay_result vres;
            /* A tampered bundle cannot even be admitted, so no receipt is made. */
            CSI_CHECK("replay: verifier persists no receipt for a tampered bundle",
                      write_bundle(&b, CSI_WRONG_UTXO_ROOT) &&
                      !consensus_state_replay_verify_and_write_receipt(
                          pdb, b.path, active_dir, &vres) &&
                      !vres.verified);
            CSI_CHECK("replay: valid bundle restored", write_bundle(&b, CSI_VALID));
            CSI_CHECK("replay: verifier re-derives from the datadir's own tables "
                      "and writes a receipt",
                      consensus_state_replay_verify_and_write_receipt(
                          pdb, b.path, active_dir, &vres) &&
                      vres.verified && vres.height == b.height &&
                      vres.utxo_count == 2 && vres.anchor_count == 2 &&
                      vres.nullifier_count == 2);

            struct consensus_state_artifact_evidence *rev = NULL;
            struct consensus_state_bundle_manifest rman;
            uint8_t rfile[32];
            struct zcl_result ro =
                consensus_state_artifact_evidence_open(b.path, -1, &rev);
            bool rgot = ro.ok && rev &&
                consensus_state_artifact_evidence_manifest_copy(rev, &rman) &&
                consensus_state_artifact_evidence_file_digest(rev, rfile);
            CSI_CHECK("replay: receipt authorizes THIS exact bundle + anchor",
                      rgot &&
                      consensus_state_replay_receipt_authority_available(
                          &rman, rfile, active_dir_fd));
            uint8_t wrong_file[32];
            memcpy(wrong_file, rfile, 32);
            wrong_file[0] ^= 0xff;
            CSI_CHECK("replay: receipt refuses a foreign bundle-file digest",
                      rgot &&
                      !consensus_state_replay_receipt_authority_available(
                          &rman, wrong_file, active_dir_fd));
            struct consensus_state_bundle_manifest wrong_man = rman;
            wrong_man.utxo_root[0] ^= 0xff;
            CSI_CHECK("replay: receipt refuses a foreign component digest",
                      rgot &&
                      !consensus_state_replay_receipt_authority_available(
                          &wrong_man, rfile, active_dir_fd));
            if (rev)
                consensus_state_artifact_evidence_free(rev);
        }

        sapling_tree_init(&gate_tree);
        CSI_CHECK("activate: post-install sapling gate is FOUND (wedge cured)",
                  anchor_kv_latest_tree(pdb, ANCHOR_POOL_SAPLING, &gate_tree,
                                        &gate_root, &gate_h) == ANCHOR_KV_FOUND);
        /* Reducer cursors forced to the anchor so the fold resumes there. */
        int64_t applied_cursor = -1, tip_cursor = -1;
        CSI_CHECK("activate: reducer stage cursors forced to the anchor frontier "
                  "(upstream=anchor+1, tip_finalize=anchor)",
                  candidate_query_i64(pdb,
                      "SELECT cursor FROM stage_cursor WHERE name='utxo_apply'",
                      &applied_cursor) && applied_cursor == b.height + 1 &&
                  candidate_query_i64(pdb,
                      "SELECT cursor FROM stage_cursor WHERE name='tip_finalize'",
                      &tip_cursor) && tip_cursor == b.height);
        int32_t applied = -1;
        bool afound = false;
        CSI_CHECK("activate: coins_applied_height == anchor+1 (fold resume point)",
                  coins_kv_get_applied_height(pdb, &applied, &afound) && afound &&
                  applied == b.height + 1 &&
                  ares.coins_applied_height == b.height + 1);
        CSI_CHECK("activate: self-folded (checkpoint-bound) provenance marker set",
                  coins_kv_contains_refold_marker(pdb));
        CSI_CHECK("activate: stale shielded recovery sessions removed",
                  hs_meta_absent(pdb, SHIELDED_REPLAY_TARGET_KEY) &&
                  hs_meta_absent(pdb, SHIELDED_REPLAY_NEXT_KEY) &&
                  hs_meta_absent(pdb,
                                 SHIELDED_REPLAY_SPROUT_STARTED_KEY) &&
                  hs_meta_absent(pdb,
                                 SHIELDED_REPLAY_SAPLING_STARTED_KEY) &&
                  hs_meta_absent(pdb, NULLIFIER_BACKFILL_RESUME_KEY) &&
                  hs_meta_absent(pdb, NULLIFIER_BACKFILL_CHAIN_KEY) &&
                  hs_meta_absent(pdb, REFOLD_IN_PROGRESS_KEY) &&
                  hs_meta_absent(pdb, REFOLD_FROM_ANCHOR_KEY) &&
                  hs_meta_absent(pdb, REFOLD_FROM_ANCHOR_TARGET_KEY) &&
                  !refold_in_progress() && !refold_from_anchor_active());
        CSI_CHECK("activate: stale producer/epoch/repair authority is purged",
                  stale_generation_metadata_absent(pdb));
        /* The installed coins projection is locally authoritative. Re-export
         * still requires a new full local proof walk + producer receipt; the
         * consumer must never inherit producer provenance from the bundle. */
        int32_t proven_applied = -1;
        CSI_CHECK("activate: installed coins projection is proven authority",
                  coins_kv_is_proven_authority(pdb, &proven_applied) &&
                  proven_applied == b.height + 1);

        /* (vi) H*-CLIMB — prove the cure is a LIVE fold-resume point, not just
         * forced cursors: confirm the in-transaction seed left H* AT the
         * wedge/anchor, then fold three consistent heights forward over stage
         * evidence and assert reducer_frontier_compute_hstar CLIMBS past the
         * wedge. Lower the compiled finality floor so the small fixture height
         * is a valid anchor (restored to the production default after). */
        /* Production ACTIVATE runs before the reducer stages initialize on a
         * genuinely fresh boot. Prove it, rather than test scaffolding,
         * materialized every H*-authoritative log schema. */
        bool frontier_schema_present = true;
        static const char *const frontier_tables[] = {
            "validate_headers_log", "script_validate_log",
            "body_persist_log", "proof_validate_log", "utxo_apply_log",
            "tip_finalize_log",
        };
        for (size_t i = 0;
             i < sizeof(frontier_tables) / sizeof(frontier_tables[0]); i++) {
            char sql[160];
            int64_t table_count = 0;
            snprintf(sql, sizeof(sql),
                     "SELECT count(*) FROM sqlite_master WHERE type='table' "
                     "AND name='%s'", frontier_tables[i]);
            frontier_schema_present = frontier_schema_present &&
                                      candidate_query_i64(pdb, sql,
                                                          &table_count) &&
                                      table_count == 1;
        }
        CSI_CHECK("activate: production materializes every H* log schema",
                  frontier_schema_present);
        int32_t hstar_base = -1, served_base = -1;
        progress_store_tx_lock();
        bool base_ok = reducer_frontier_compute_hstar(pdb, &hstar_base,
                                                      &served_base);
        progress_store_tx_unlock();
        CSI_CHECK("activate: H* rests AT the anchor before any forward fold "
                  "(the wedge floor)",
                  base_ok && hstar_base == b.height);

        bool folded = true;
        for (int32_t h = b.height + 1; h <= b.height + 3; h++)
            folded = folded && hs_put_forward_height(pdb, h);
        CSI_CHECK("activate: three consistent heights fold forward", folded);
        /* Advance the reducer cursors past the folded tip (upstream count the
         * NEXT height; tip_finalize uses the served-tip frame). */
        bool cursors = hs_set_cursor(pdb, "validate_headers", b.height + 4) &&
                       hs_set_cursor(pdb, "body_fetch", b.height + 4) &&
                       hs_set_cursor(pdb, "body_persist", b.height + 4) &&
                       hs_set_cursor(pdb, "script_validate", b.height + 4) &&
                       hs_set_cursor(pdb, "proof_validate", b.height + 4) &&
                       hs_set_cursor(pdb, "utxo_apply", b.height + 4) &&
                       hs_set_cursor(pdb, "tip_finalize", b.height + 3);
        CSI_CHECK("activate: reducer cursors advance past the folded tip",
                  cursors);
        int32_t hstar_climb = -1, served_climb = -1;
        progress_store_tx_lock();
        bool climb_ok = reducer_frontier_compute_hstar(pdb, &hstar_climb,
                                                       &served_climb);
        progress_store_tx_unlock();
        CSI_CHECK("activate: H* CLIMBS past the wedge over folded bodies "
                  "(cure enables forward progress, not just forced cursors)",
                  climb_ok && hstar_climb == b.height + 3 &&
                  hstar_climb > hstar_base && served_climb == b.height + 3);

        /* Physically restorable prior generation. */
        sqlite3 *prior = NULL;
        CSI_CHECK("activate: restorable prior generation is a valid standalone "
                  "store",
                  ares.prior_generation_path[0] != '\0' &&
                  sqlite3_open_v2(ares.prior_generation_path, &prior,
                                  SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
                  prior);
        CSI_CHECK("activate: success reason retains the exact prior-generation "
                  "path",
                  ares.prior_generation_path[0] != '\0' &&
                  strstr(ares.reason, ares.prior_generation_path) != NULL);
        CSI_CHECK("activate: prior generation is the protected pre-install "
                  "wedge, not post-cutover state",
                  prior && coins_kv_count(prior) == 1 &&
                  hs_meta_present(prior, SHIELDED_REPLAY_TARGET_KEY) &&
                  hs_meta_present(prior, NULLIFIER_BACKFILL_RESUME_KEY) &&
                  hs_meta_present(prior, REFOLD_IN_PROGRESS_KEY) &&
                  stale_generation_metadata_present(prior));
        if (prior)
            sqlite3_close(prior);
        if (ares.prior_generation_path[0])
            unlink(ares.prior_generation_path);

        /* (vii) The real replay receipt written above lifts the production
         * containment with the ZCL_TESTING hook OFF: activate consults the
         * on-disk receipt, finds it binds THIS bundle, and installs. The
         * (iii-b) rewrite replaced the bundle inode, so the CAS descriptor
         * binding correctly demands a fresh exact ADMIT first. */
        ev = NULL;
        evr = consensus_state_artifact_evidence_open(b.path, -1, &ev);
        bool auth_cin_ok = evr.ok && ev &&
            consensus_state_artifact_evidence_manifest_copy(ev, &cin.manifest) &&
            consensus_state_artifact_evidence_digest(
                ev, cin.artifact_logical_digest) &&
            consensus_state_artifact_evidence_receipt_digest(
                ev, cin.artifact_receipt_digest);
        /* The store folded 3 heights past the anchor above; the CAS fence
         * demands the decision record the LIVE frontier, resolved exactly the
         * way activate captures it (durable-tip convention included). */
        int32_t live_frontier_h = -1;
        uint8_t live_frontier_hash[32] = {0};
        CSI_CHECK("activate: live frontier resolves for the fresh ADMIT",
                  tip_finalize_stage_resolve_durable_tip(pdb, &live_frontier_h,
                                                         live_frontier_hash) &&
                  live_frontier_h == b.height + 3);
        cin.frontier_height = live_frontier_h;
        memcpy(cin.frontier_hash, live_frontier_hash, 32);
        consensus_state_publication_cas_decide(&cin, &dec);
        CSI_CHECK("activate: replay-authority bundle receives a fresh exact "
                  "ADMIT receipt",
                  auth_cin_ok && dec.decision == CONSENSUS_PUBLICATION_ADMIT);
        if (dec.decision == CONSENSUS_PUBLICATION_ADMIT) {
            active_decision = dec;
            memcpy(areq.expected_artifact_receipt_digest,
                   dec.artifact_receipt_digest, 32);
            areq.publication_decision = &active_decision;
        }
        if (ev)
            consensus_state_artifact_evidence_free(ev);
        consensus_state_snapshot_install_activate_test_set_independent_authority(
            false);
        struct consensus_state_activate_result ares_auth;
        CSI_CHECK("activate: a valid on-disk replay receipt lifts the production "
                  "containment (real authority, no test hook)",
                  consensus_state_snapshot_install_activate(pdb, &areq,
                                                            &ares_auth) &&
                  ares_auth.activated &&
                  ares_auth.status == CONSENSUS_INSTALL_ACTIVATED &&
                  active_is(pdb, &b));
        if (ares_auth.prior_generation_path[0])
            unlink(ares_auth.prior_generation_path);

        reducer_frontier_test_set_compiled_anchor(-1);
        if (active_dir_fd >= 0)
            (void)close(active_dir_fd);
        progress_store_close();
        test_cleanup_tmpdir(active_dir);
    }

    /* ── CHECKPOINT_CONTENT ACTIVATE authority ─────────────────────────────
     * The second, additive activation authority. A bundle whose coins reproduce
     * the compiled SHA3 UTXO checkpoint (sha3 + count at the checkpoint height)
     * AND whose Sapling tip frontier Pedersen-roots to THIS datadir's validated-
     * header hashFinalSaplingRoot activates WITHOUT any independent replay
     * receipt: it is bound to the compiled binary + PoW, stronger than a
     * fold-process attestation. Prove: no validated-header root CONTAINS; a
     * wrong Sapling root CONTAINS; a single-coin mutation refuses; the
     * header-bound content match activates and NAMES the authority. */
    {
        b.anchors[0].height = b.height;
        b.anchors[1].height = b.height;
        char cc_dir[320];
        snprintf(cc_dir, sizeof(cc_dir), "%s/ckpt-content", dir);
        CSI_CHECK("checkpoint-content: datadir", mkdir(cc_dir, 0700) == 0);
        CSI_CHECK("checkpoint-content: live progress store opens",
                  progress_store_open(cc_dir));
        sqlite3 *pdb = progress_store_db();
        int cc_dir_fd = open(cc_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        reducer_frontier_test_set_compiled_anchor(0);

        uint8_t borrowed_txid[32];
        memset(borrowed_txid, 0x5a, sizeof(borrowed_txid));
        const uint8_t borrowed_script[] = {0x51};
        CSI_CHECK("checkpoint-content: wedged store seeds (borrowed coin, empty "
                  "anchors, positive activation cursor)",
                  pdb && coins_kv_ensure_schema(pdb) &&
                  progress_meta_table_ensure(pdb) &&
                  anchor_kv_ensure_schema(pdb) &&
                  nullifier_kv_ensure_schema(pdb) &&
                  anchor_kv_initialize_history(pdb, b.height) &&
                  nullifier_kv_initialize_history(pdb, b.height) &&
                  coins_kv_add(pdb, borrowed_txid, 0, 4242, b.height, false,
                               borrowed_script, sizeof(borrowed_script)) &&
                  hs_seed_current_frontier(pdb, b.height, b.block_hash));

        CSI_CHECK("checkpoint-content: valid complete bundle writes",
                  write_bundle(&b, CSI_VALID));

        /* Build the ADMIT decision + exact receipt binding activate requires,
         * exactly as the boot adapter would. */
        struct consensus_state_activate_request areq;
        memset(&areq, 0, sizeof(areq));
        areq.bundle_path = b.path;
        areq.expected_height = b.height;
        memcpy(areq.expected_block_hash, b.block_hash, 32);
        areq.datadir_fd = cc_dir_fd;
        areq.datadir_display = cc_dir;

        struct consensus_state_artifact_evidence *ccev = NULL;
        struct zcl_result ccevr =
            consensus_state_artifact_evidence_open(b.path, -1, &ccev);
        struct consensus_state_publication_cas_inputs ccin;
        memset(&ccin, 0, sizeof(ccin));
        bool ccin_ok = ccevr.ok && ccev &&
            consensus_state_artifact_evidence_manifest_copy(ccev,
                                                            &ccin.manifest) &&
            consensus_state_artifact_evidence_digest(
                ccev, ccin.artifact_logical_digest) &&
            consensus_state_artifact_evidence_receipt_digest(
                ccev, ccin.artifact_receipt_digest);
        ccin.chain_evidence_present = true;
        ccin.chain_bound_to_artifact = true;
        memset(ccin.chain_evidence_digest, 0xa5, 32);
        ccin.source_receipt_present = true;
        ccin.source_receipt = b.receipt;
        ccin.target_lane = CONSENSUS_STATE_TARGET_LANE_COPY_PROOF;
        ccin.frontier_known = true;
        memcpy(ccin.frontier_hash, b.block_hash, 32);
        ccin.frontier_height = b.height;
        struct consensus_state_publication_decision_record ccdec;
        consensus_state_publication_cas_decide(&ccin, &ccdec);
        struct consensus_state_publication_decision_record cc_decision;
        memset(&cc_decision, 0, sizeof(cc_decision));
        CSI_CHECK("checkpoint-content: complete bundle CAS-decides ADMIT",
                  ccin_ok && ccdec.decision == CONSENSUS_PUBLICATION_ADMIT);
        cc_decision = ccdec;
        memcpy(areq.expected_artifact_receipt_digest,
               ccdec.artifact_receipt_digest, 32);
        areq.publication_decision = &cc_decision;
        if (ccev)
            consensus_state_artifact_evidence_free(ccev);

        /* The compiled SHA3 UTXO checkpoint the bundle's own coins reproduce by
         * construction (the fixture folds these two coins into b.utxo_root). */
        struct sha3_utxo_checkpoint cc_cp;
        memset(&cc_cp, 0, sizeof(cc_cp));
        cc_cp.height = b.height;
        memcpy(cc_cp.block_hash, b.block_hash, 32);
        cc_cp.utxo_count = b.coin_count;
        cc_cp.total_supply = b.supply;
        memcpy(cc_cp.sha3_hash, b.utxo_root, 32);
        checkpoints_set_sha3_override_for_test(&cc_cp);

        /* No independent replay receipt exists on this datadir: checkpoint-
         * content is the ONLY authority that can lift containment here. */
        consensus_state_snapshot_install_activate_test_set_independent_authority(
            false);
        struct consensus_state_activate_result cc_ares;

        /* (i) NEGATIVE — no validated-header Sapling root: the coins match the
         * checkpoint but the shielded tip is not PoW-bound, so CONTAINED. */
        areq.checkpoint_sapling_root_from_validated_header = false;
        memset(areq.checkpoint_sapling_root, 0, 32);
        CSI_CHECK("checkpoint-content: no validated-header root stays CONTAINED "
                  "(nothing written)",
                  !consensus_state_snapshot_install_activate(pdb, &areq,
                                                             &cc_ares) &&
                  !cc_ares.activated &&
                  cc_ares.status == CONSENSUS_INSTALL_VERIFIED_CONTAINED &&
                  strstr(cc_ares.reason, "validated-header") != NULL &&
                  cc_ares.prior_generation_path[0] == '\0' &&
                  coins_kv_count(pdb) == 1);

        /* (ii) NEGATIVE — a Sapling root that does not match the bundle's
         * frontier: never activate on a header-inconsistent root. CONTAINED. */
        areq.checkpoint_sapling_root_from_validated_header = true;
        memcpy(areq.checkpoint_sapling_root,
               b.frontier_root[ANCHOR_POOL_SAPLING], 32);
        areq.checkpoint_sapling_root[7] ^= 0xff;
        CSI_CHECK("checkpoint-content: wrong Sapling root stays CONTAINED",
                  !consensus_state_snapshot_install_activate(pdb, &areq,
                                                             &cc_ares) &&
                  !cc_ares.activated &&
                  cc_ares.status == CONSENSUS_INSTALL_VERIFIED_CONTAINED &&
                  strstr(cc_ares.reason, "validated-header") != NULL &&
                  coins_kv_count(pdb) == 1);

        /* (iii) NEGATIVE — a single-coin mutation flips the compiled checkpoint
         * SHA3, so the bundle's coins no longer reproduce it: no authority. */
        struct sha3_256_ctx cc_mut_ctx;
        sha3_256_init(&cc_mut_ctx);
        for (size_t i = 0; i < b.coin_count; i++) {
            const struct csi_coin *coin = &b.coins[i];
            utxo_commitment_sha3_write_record(
                &cc_mut_ctx, coin->txid, coin->vout,
                coin->value + (i == 0 ? 1 : 0), coin->script,
                coin->script_len, (uint32_t)coin->height,
                coin->coinbase ? 1 : 0);
        }
        struct sha3_utxo_checkpoint cc_mut = cc_cp;
        sha3_256_finalize(&cc_mut_ctx, cc_mut.sha3_hash);
        checkpoints_set_sha3_override_for_test(&cc_mut);
        areq.checkpoint_sapling_root_from_validated_header = true;
        memcpy(areq.checkpoint_sapling_root,
               b.frontier_root[ANCHOR_POOL_SAPLING], 32);
        CSI_CHECK("checkpoint-content: single-coin mutation refuses (coins miss "
                  "the compiled SHA3)",
                  !consensus_state_snapshot_install_activate(pdb, &areq,
                                                             &cc_ares) &&
                  !cc_ares.activated &&
                  cc_ares.status == CONSENSUS_INSTALL_VERIFIED_CONTAINED &&
                  strstr(cc_ares.reason, "checkpoint-content") != NULL &&
                  coins_kv_count(pdb) == 1);
        checkpoints_set_sha3_override_for_test(&cc_cp);

        /* (iv) POSITIVE — coins reproduce the compiled checkpoint AND the
         * Sapling frontier Pedersen-roots to the validated-header root:
         * ACTIVATE via checkpoint-content with NO receipt, naming the authority. */
        areq.checkpoint_sapling_root_from_validated_header = true;
        memcpy(areq.checkpoint_sapling_root,
               b.frontier_root[ANCHOR_POOL_SAPLING], 32);
        CSI_CHECK("checkpoint-content: content match + header root activates "
                  "with NO receipt",
                  consensus_state_snapshot_install_activate(pdb, &areq,
                                                            &cc_ares) &&
                  cc_ares.activated &&
                  cc_ares.status == CONSENSUS_INSTALL_ACTIVATED &&
                  cc_ares.height == b.height && cc_ares.utxo_count == 2 &&
                  cc_ares.anchor_count == 2 && cc_ares.nullifier_count == 2 &&
                  cc_ares.hstar == b.height &&
                  cc_ares.coins_applied_height == b.height + 1 &&
                  strstr(cc_ares.reason,
                         "authority=checkpoint_content") != NULL);
        CSI_CHECK("checkpoint-content: installed coins/anchors/nullifiers match "
                  "the bundle with COMPLETE (cursor 0) history",
                  active_is(pdb, &b));
        if (cc_ares.prior_generation_path[0])
            (void)unlink(cc_ares.prior_generation_path);

        checkpoints_reset_sha3_override_for_test();
        reducer_frontier_test_set_compiled_anchor(-1);
        if (cc_dir_fd >= 0)
            (void)close(cc_dir_fd);
        progress_store_close();
        test_cleanup_tmpdir(cc_dir);
    }

    /* ── ASSISTED ABOVE-checkpoint ACTIVATE authority (the RELEASE_ASSISTED
     *    tier, full-install integration) ───────────────────────────────────
     * A FRESHEST bundle strictly ABOVE the compiled checkpoint installs through
     * the SAME atomic, wedge-immune cutover — but stamps ONLY the operational
     * migration-complete marker and records the promotion seam; self_folded
     * (sovereign) is WITHHELD, so sync_trust_derive → RELEASE_ASSISTED_READY.
     * Proves: authority=assisted activates; migration set + self_folded ABSENT;
     * coins_kv_tip_is_self_derived false; the seam records the bundle height +
     * the three manifest commitments; wedge-immunity (post-install sapling gate
     * FOUND, cursors forced); and the assisted opt-in gates it. */
    {
        b.anchors[0].height = b.height;
        b.anchors[1].height = b.height;
        char as_dir[320];
        snprintf(as_dir, sizeof(as_dir), "%s/assisted", dir);
        CSI_CHECK("assisted: datadir", mkdir(as_dir, 0700) == 0);
        CSI_CHECK("assisted: live progress store opens",
                  progress_store_open(as_dir));
        sqlite3 *pdb = progress_store_db();
        int as_dir_fd = open(as_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        reducer_frontier_test_set_compiled_anchor(0);

        uint8_t borrowed_txid[32];
        memset(borrowed_txid, 0x5b, sizeof(borrowed_txid));
        const uint8_t borrowed_script[] = {0x51};
        CSI_CHECK("assisted: wedged store seeds (borrowed coin, empty anchors)",
                  pdb && coins_kv_ensure_schema(pdb) &&
                  progress_meta_table_ensure(pdb) &&
                  anchor_kv_ensure_schema(pdb) &&
                  nullifier_kv_ensure_schema(pdb) &&
                  anchor_kv_initialize_history(pdb, b.height) &&
                  nullifier_kv_initialize_history(pdb, b.height) &&
                  coins_kv_add(pdb, borrowed_txid, 0, 4242, b.height, false,
                               borrowed_script, sizeof(borrowed_script)) &&
                  hs_seed_current_frontier(pdb, b.height, b.block_hash));

        CSI_CHECK("assisted: valid complete bundle writes",
                  write_bundle(&b, CSI_VALID));

        struct consensus_state_activate_request areq;
        memset(&areq, 0, sizeof(areq));
        areq.bundle_path = b.path;
        areq.expected_height = b.height;
        memcpy(areq.expected_block_hash, b.block_hash, 32);
        areq.datadir_fd = as_dir_fd;
        areq.datadir_display = as_dir;

        struct consensus_state_artifact_evidence *asev = NULL;
        struct zcl_result asevr =
            consensus_state_artifact_evidence_open(b.path, -1, &asev);
        struct consensus_state_publication_cas_inputs asin;
        memset(&asin, 0, sizeof(asin));
        bool asin_ok = asevr.ok && asev &&
            consensus_state_artifact_evidence_manifest_copy(asev,
                                                            &asin.manifest) &&
            consensus_state_artifact_evidence_digest(
                asev, asin.artifact_logical_digest) &&
            consensus_state_artifact_evidence_receipt_digest(
                asev, asin.artifact_receipt_digest);
        asin.chain_evidence_present = true;
        asin.chain_bound_to_artifact = true;
        memset(asin.chain_evidence_digest, 0xa5, 32);
        asin.source_receipt_present = true;
        asin.source_receipt = b.receipt;
        asin.target_lane = CONSENSUS_STATE_TARGET_LANE_COPY_PROOF;
        asin.frontier_known = true;
        memcpy(asin.frontier_hash, b.block_hash, 32);
        asin.frontier_height = b.height;
        struct consensus_state_publication_decision_record asdec;
        consensus_state_publication_cas_decide(&asin, &asdec);
        struct consensus_state_publication_decision_record as_decision;
        memset(&as_decision, 0, sizeof(as_decision));
        CSI_CHECK("assisted: complete bundle CAS-decides ADMIT",
                  asin_ok && asdec.decision == CONSENSUS_PUBLICATION_ADMIT);
        as_decision = asdec;
        memcpy(areq.expected_artifact_receipt_digest,
               asdec.artifact_receipt_digest, 32);
        areq.publication_decision = &as_decision;
        if (asev)
            consensus_state_artifact_evidence_free(asev);

        /* A compiled SHA3 checkpoint strictly BELOW the bundle height: the bundle
         * is ABOVE it (assisted's promotion anchor). The bundle's own coins do
         * NOT reproduce it (fresher, unbound content), so checkpoint-content /
         * checkpoint-rom never fire — only the assisted authority can lift
         * containment here. */
        struct sha3_utxo_checkpoint as_cp;
        memset(&as_cp, 0, sizeof(as_cp));
        as_cp.height = b.height - 1;
        memset(as_cp.block_hash, 0xc7, 32);
        as_cp.utxo_count = 999;
        memset(as_cp.sha3_hash, 0xc8, 32);
        checkpoints_set_sha3_override_for_test(&as_cp);
        consensus_state_snapshot_install_activate_test_set_independent_authority(
            false);
        struct consensus_state_activate_result as_ares;

        /* (i) NEGATIVE — assisted_tier NOT requested (no opt-in): an above-
         * checkpoint bundle with no sovereign authority stays CONTAINED. */
        areq.assisted_tier = false;
        CSI_CHECK("assisted: opt-in OFF stays CONTAINED (nothing written)",
                  !consensus_state_snapshot_install_activate(pdb, &areq,
                                                             &as_ares) &&
                  !as_ares.activated &&
                  as_ares.status == CONSENSUS_INSTALL_VERIFIED_CONTAINED &&
                  coins_kv_count(pdb) == 1);

        /* (ii) NEGATIVE — assisted_tier requested but the shielded tip is not
         * bound to a validated-header root: never activate on an unverifiable
         * root. CONTAINED. */
        areq.assisted_tier = true;
        areq.assisted_sapling_root_from_validated_header = false;
        memset(areq.assisted_sapling_root, 0, 32);
        CSI_CHECK("assisted: no validated-header sapling root stays CONTAINED",
                  !consensus_state_snapshot_install_activate(pdb, &areq,
                                                             &as_ares) &&
                  !as_ares.activated &&
                  as_ares.status == CONSENSUS_INSTALL_VERIFIED_CONTAINED &&
                  coins_kv_count(pdb) == 1);

        /* (iii) POSITIVE — assisted_tier + the bundle-height header Sapling root:
         * ACTIVATE via the assisted authority, naming it. */
        areq.assisted_sapling_root_from_validated_header = true;
        memcpy(areq.assisted_sapling_root,
               b.frontier_root[ANCHOR_POOL_SAPLING], 32);
        CSI_CHECK("assisted: above-checkpoint bundle + header root activates",
                  consensus_state_snapshot_install_activate(pdb, &areq,
                                                            &as_ares) &&
                  as_ares.activated &&
                  as_ares.status == CONSENSUS_INSTALL_ACTIVATED &&
                  as_ares.height == b.height && as_ares.utxo_count == 2 &&
                  as_ares.anchor_count == 2 && as_ares.nullifier_count == 2 &&
                  as_ares.hstar == b.height &&
                  as_ares.coins_applied_height == b.height + 1 &&
                  strstr(as_ares.reason, "authority=assisted") != NULL);
        CSI_CHECK("assisted: installed state matches the bundle (COMPLETE "
                  "cursor-0 history — the wedge-immune atomic path)",
                  active_is(pdb, &b));

        /* Tier boundary: migration-complete SET, self_folded ABSENT. */
        CSI_CHECK("assisted: migration-complete marker SET (operational tier)",
                  hs_meta_present(pdb, COINS_KV_MIGRATION_COMPLETE_KEY));
        CSI_CHECK("assisted: self_folded marker WITHHELD (not sovereign)",
                  hs_meta_absent(pdb, COINS_KV_SELF_FOLDED_KEY) &&
                  !coins_kv_contains_refold_marker(pdb));
        char sd_reason[128];
        CSI_CHECK("assisted: coins_kv_tip_is_self_derived is FALSE (borrowed)",
                  !coins_kv_tip_is_self_derived(pdb, b.height, sd_reason,
                                                sizeof(sd_reason)));

        /* Promotion seam: bundle height + the three manifest commitments. */
        int32_t seam_h = -1;
        uint8_t seam_utxo[32], seam_anchor[32], seam_nf[32];
        bool seam_found = false;
        CSI_CHECK("assisted: promotion seam recorded (height + 3 commitments)",
                  consensus_state_install_read_assisted_seam(
                      pdb, &seam_h, seam_utxo, seam_anchor, seam_nf,
                      &seam_found) &&
                  seam_found && seam_h == b.height &&
                  memcmp(seam_utxo, b.utxo_root, 32) == 0 &&
                  memcmp(seam_anchor, b.anchor_digest, 32) == 0 &&
                  memcmp(seam_nf, b.nf_digest, 32) == 0);

        /* Wedge-immunity: the borrowed install cured the sapling gate and forced
         * the cursors, exactly like a sovereign install. */
        struct incremental_merkle_tree as_gate_tree;
        struct uint256 as_gate_root;
        int64_t as_gate_h = -1;
        sapling_tree_init(&as_gate_tree);
        CSI_CHECK("assisted: post-install sapling gate is FOUND (no wedge)",
                  anchor_kv_latest_tree(pdb, ANCHOR_POOL_SAPLING, &as_gate_tree,
                                        &as_gate_root, &as_gate_h) ==
                      ANCHOR_KV_FOUND);
        int64_t as_applied_cursor = -1, as_tip_cursor = -1;
        CSI_CHECK("assisted: reducer cursors forced to the anchor frontier",
                  candidate_query_i64(pdb,
                      "SELECT cursor FROM stage_cursor WHERE name='utxo_apply'",
                      &as_applied_cursor) &&
                  as_applied_cursor == b.height + 1 &&
                  candidate_query_i64(pdb,
                      "SELECT cursor FROM stage_cursor WHERE name='tip_finalize'",
                      &as_tip_cursor) && as_tip_cursor == b.height);

        if (as_ares.prior_generation_path[0])
            (void)unlink(as_ares.prior_generation_path);
        checkpoints_reset_sha3_override_for_test();
        reducer_frontier_test_set_compiled_anchor(-1);
        if (as_dir_fd >= 0)
            (void)close(as_dir_fd);
        progress_store_close();
        test_cleanup_tmpdir(as_dir);
    }

    /* ── CHECKPOINT_ROM ACTIVATE authority (full-install integration) ───────
     * The SOVEREIGN, header-independent ignition path: a bundle whose manifest
     * reproduces EVERY component of the compiled shielded ROM state checkpoint
     * (g_rom_state_checkpoint) byte-for-byte lifts ACTIVATE containment with NO
     * peer, NO validated header, and NO independent replay receipt — bound to a
     * fingerprint baked into the binary. The resolver and admission bindings are
     * unit-tested (test_checkpoint_rom_authority, rom_keystone_binding_tests);
     * this proves the FULL atomic install end-to-end:
     *   (i)  no matching keystone at the bundle height -> the ADMIT-worthy bundle
     *        resolves NO ignition authority and stays VERIFIED_CONTAINED, writing
     *        NOTHING (the fail-closed posture for an unmatched bundle / peer tip);
     *   (ii) a keystone reproducing the bundle byte-for-byte at the checkpoint
     *        height -> the atomic install PROCEEDS, commits, and NAMES
     *        authority=checkpoint_rom. */
    {
        b.anchors[0].height = b.height;
        b.anchors[1].height = b.height;
        char rom_dir[320];
        snprintf(rom_dir, sizeof(rom_dir), "%s/ckpt-rom", dir);
        CSI_CHECK("checkpoint-rom: datadir", mkdir(rom_dir, 0700) == 0);
        CSI_CHECK("checkpoint-rom: live progress store opens",
                  progress_store_open(rom_dir));
        sqlite3 *pdb = progress_store_db();
        int rom_dir_fd = open(rom_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        reducer_frontier_test_set_compiled_anchor(0);

        uint8_t borrowed_txid[32];
        memset(borrowed_txid, 0x5a, sizeof(borrowed_txid));
        const uint8_t borrowed_script[] = {0x51};
        CSI_CHECK("checkpoint-rom: wedged store seeds (borrowed coin, empty "
                  "anchors, positive activation cursor)",
                  pdb && coins_kv_ensure_schema(pdb) &&
                  progress_meta_table_ensure(pdb) &&
                  anchor_kv_ensure_schema(pdb) &&
                  nullifier_kv_ensure_schema(pdb) &&
                  anchor_kv_initialize_history(pdb, b.height) &&
                  nullifier_kv_initialize_history(pdb, b.height) &&
                  coins_kv_add(pdb, borrowed_txid, 0, 4242, b.height, false,
                               borrowed_script, sizeof(borrowed_script)) &&
                  hs_seed_current_frontier(pdb, b.height, b.block_hash));

        CSI_CHECK("checkpoint-rom: valid complete bundle writes",
                  write_bundle(&b, CSI_VALID));

        /* Build the ADMIT decision + exact receipt binding activate requires,
         * exactly as the boot adapter would. */
        struct consensus_state_activate_request areq;
        memset(&areq, 0, sizeof(areq));
        areq.bundle_path = b.path;
        areq.expected_height = b.height;
        memcpy(areq.expected_block_hash, b.block_hash, 32);
        areq.datadir_fd = rom_dir_fd;
        areq.datadir_display = rom_dir;

        struct consensus_state_artifact_evidence *rev = NULL;
        struct zcl_result revr =
            consensus_state_artifact_evidence_open(b.path, -1, &rev);
        struct consensus_state_publication_cas_inputs rin;
        memset(&rin, 0, sizeof(rin));
        bool rin_ok = revr.ok && rev &&
            consensus_state_artifact_evidence_manifest_copy(rev, &rin.manifest) &&
            consensus_state_artifact_evidence_digest(
                rev, rin.artifact_logical_digest) &&
            consensus_state_artifact_evidence_receipt_digest(
                rev, rin.artifact_receipt_digest);
        rin.chain_evidence_present = true;
        rin.chain_bound_to_artifact = true;
        memset(rin.chain_evidence_digest, 0xa5, 32);
        rin.source_receipt_present = true;
        rin.source_receipt = b.receipt;
        rin.target_lane = CONSENSUS_STATE_TARGET_LANE_COPY_PROOF;
        rin.frontier_known = true;
        memcpy(rin.frontier_hash, b.block_hash, 32);
        rin.frontier_height = b.height;
        struct consensus_state_publication_decision_record rdec;
        consensus_state_publication_cas_decide(&rin, &rdec);
        struct consensus_state_publication_decision_record rom_decision;
        memset(&rom_decision, 0, sizeof(rom_decision));
        CSI_CHECK("checkpoint-rom: complete bundle CAS-decides ADMIT",
                  rin_ok && rdec.decision == CONSENSUS_PUBLICATION_ADMIT);
        rom_decision = rdec;
        memcpy(areq.expected_artifact_receipt_digest,
               rdec.artifact_receipt_digest, 32);
        areq.publication_decision = &rom_decision;
        if (rev)
            consensus_state_artifact_evidence_free(rev);

        /* CHECKPOINT_ROM is header-independent: no validated-header Sapling root,
         * no SHA3 override, and the ZCL_TESTING replay hook is OFF — the compiled
         * keystone is the ONLY authority that can lift containment here. */
        consensus_state_snapshot_install_activate_test_set_independent_authority(
            false);
        struct consensus_state_activate_result rom_ares;

        /* (i) NEGATIVE — with NO matching keystone at the bundle height (the
         * compiled production keystone is inert at this small fixture height),
         * the ADMIT-worthy bundle resolves NO ignition authority and stays
         * VERIFIED_CONTAINED, writing nothing. This is precisely the fail-closed
         * posture the ignition whitelist enforces for an unmatched bundle. */
        checkpoints_reset_rom_state_override_for_test();
        sqlite3_int64 rom_contained_changes = sqlite3_total_changes64(pdb);
        int rom_contained_backups = prior_generation_count(rom_dir);
        CSI_CHECK("checkpoint-rom: no matching keystone stays CONTAINED (nothing "
                  "written)",
                  !consensus_state_snapshot_install_activate(pdb, &areq,
                                                             &rom_ares) &&
                  !rom_ares.activated &&
                  rom_ares.status == CONSENSUS_INSTALL_VERIFIED_CONTAINED &&
                  rom_ares.prior_generation_path[0] == '\0' &&
                  sqlite3_total_changes64(pdb) == rom_contained_changes &&
                  prior_generation_count(rom_dir) == rom_contained_backups &&
                  coins_kv_count(pdb) == 1);

        /* (ii) POSITIVE — a keystone reproducing the bundle byte-for-byte at the
         * checkpoint height lifts containment via CHECKPOINT_ROM with NO header
         * and NO receipt: the atomic install proceeds, commits, cures the wedge,
         * and names the authority. */
        struct rom_state_checkpoint rom;
        rom_keystone_from_fixture(&b, &rom);
        checkpoints_set_rom_state_override_for_test(&rom);
        CSI_CHECK("checkpoint-rom: full component match activates with NO "
                  "receipt/header (authority=checkpoint_rom)",
                  consensus_state_snapshot_install_activate(pdb, &areq,
                                                            &rom_ares) &&
                  rom_ares.activated &&
                  rom_ares.status == CONSENSUS_INSTALL_ACTIVATED &&
                  rom_ares.height == b.height && rom_ares.utxo_count == 2 &&
                  rom_ares.anchor_count == 2 && rom_ares.nullifier_count == 2 &&
                  rom_ares.hstar == b.height &&
                  rom_ares.coins_applied_height == b.height + 1 &&
                  strstr(rom_ares.reason,
                         "authority=checkpoint_rom") != NULL);
        CSI_CHECK("checkpoint-rom: installed coins/anchors/nullifiers match the "
                  "bundle with COMPLETE (cursor 0) history",
                  active_is(pdb, &b));
        if (rom_ares.prior_generation_path[0])
            (void)unlink(rom_ares.prior_generation_path);

        checkpoints_reset_rom_state_override_for_test();
        reducer_frontier_test_set_compiled_anchor(-1);
        if (rom_dir_fd >= 0)
            (void)close(rom_dir_fd);
        progress_store_close();
        test_cleanup_tmpdir(rom_dir);
    }

    failures += install_verify_receipt_tests(dir);
    failures += rom_keystone_binding_tests(dir);

    fixture_free(&a); fixture_free(&b); fixture_free(&inc);
    if (db)
        sqlite3_close(db);
    test_cleanup_tmpdir(dir);
    printf("=== consensus_state_snapshot_install: %d failure(s) ===\n",failures);
    return failures;
}
