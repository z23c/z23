/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_export_consensus_bundle.c — the -export-consensus-bundle verb: a
 * TERMINAL offline exporter that emits the zcl.consensus_state_bundle.v1 from a
 * finished genesis->checkpoint datadir WITHOUT re-running the exact binary that
 * folded it. The default exporter binds the bundle to the running binary that
 * folded the state (a fold-process provenance claim); a genuine, finished
 * datadir whose fold binary can no longer be rebuilt would otherwise be
 * unexportable even though its state is cryptographically correct.
 *
 * This verb substitutes that fold-binary bind with a stronger, protocol-aligned
 * CONTENT proof, wired through consensus_state_snapshot_export's
 * checkpoint_content_export mode: the frozen transparent coins must reproduce
 * the compiled SHA3 UTXO checkpoint (sha3 + count) at the checkpoint height, and
 * the Sapling tip frontier must Pedersen-root to the block header's committed
 * hashFinalSaplingRoot at that height — read HERE from this node's own validated
 * block index. Transparent state bound to the binary's SHA3, shielded tip bound
 * to PoW; the emitted bundle is byte-identical in shape to a fold-produced
 * bundle and passes the same install/verify re-derivation. Every path _exit()s.
 * Contract declared in config/boot.h. */

#include "config/boot.h"

#include "config/consensus_state_snapshot_export.h"
#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "models/block.h"
#include "storage/consensus_state_bundle_codec.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#define EXPORT_SUBSYS "export_consensus_bundle"

#ifndef _WIN32
static bool datadir_name_is_empty(const char *datadir)
{
    return !datadir || !datadir[0];
}

/* The PoW anchor for the shielded tip: the header-committed final Sapling
 * root at the checkpoint height, from THIS node's validated block index.
 * Require the validated header at the checkpoint height to be the exact
 * compiled-checkpoint block, so the root is the one PoW commits there. */
static bool checkpoint_db_header_valid(struct node_db *ndb,
                                       const struct sha3_utxo_checkpoint *cp)
{
    struct db_block blk;
    return db_block_find_by_height(ndb, cp->height, &blk) &&
           blk.status >= BLOCK_VALID_TRANSACTIONS &&
           memcmp(blk.hash, cp->block_hash, 32) == 0;
}

static bool format_bundle_name(char *name, size_t name_size, int height)
{
    int nn = snprintf(name, name_size, "consensus-state-bundle-%d.sqlite",
                      height);
    return nn > 0 && (size_t)nn < name_size;
}

/* The blocks-projection row can carry a zero sapling_root and stale file
 * positions (the legacy header import never populated them for this
 * layout), so the PoW anchor for the shielded tip comes from the in-RAM
 * validated block index: the entry at the checkpoint height must hash to
 * exactly the compiled checkpoint's block hash, and its committed final
 * Sapling root must be non-zero. */
static bool ram_chain_owns_checkpoint(const struct main_state *ms,
                                      const struct sha3_utxo_checkpoint *cp,
                                      const struct block_index **out)
{
    const struct block_index *bi =
        ms ? active_chain_at(&ms->chain_active, cp->height) : NULL;
    *out = bi;
    return bi && bi->phashBlock &&
           memcmp(bi->phashBlock->data, cp->block_hash, 32) == 0;
}

static bool sapling_root_is_zero(const struct block_index *bi)
{
    struct uint256 zero_root;
    memset(&zero_root, 0, sizeof(zero_root));
    return memcmp(bi->hashFinalSaplingRoot.data, zero_root.data, 32) == 0;
}

static bool export_result_ok(bool exported,
                             const struct consensus_state_export_result *res)
{
    return exported && res->status == CONSENSUS_EXPORT_EXPORTED;
}

static const char *export_reason_or_default(const char *reason,
                                            const char *fallback)
{
    return reason[0] ? reason : fallback;
}

static void format_digest_hex(char *digest_hex, const uint8_t digest[32])
{
    for (int i = 0; i < 32; i++)
        snprintf(digest_hex + 2 * i, 3, "%02x", digest[i]);
}
#endif

void boot_export_consensus_bundle(struct node_db *ndb, struct main_state *ms,
                                  const char *datadir)
{
#ifdef _WIN32
    (void)ndb;
    (void)ms;
    (void)datadir;
    /* Refuse at the exported boundary, before checkpoint/database reads,
     * datadir opening, staging, or export publication. An integer POSIX dirfd
     * cannot represent the directory-handle capability required for a native
     * no-reparse atomic bundle transaction. */
    fprintf(stderr,
            "REFUSED: -export-consensus-bundle: native Windows export is "
            "disabled until directory-handle atomic publication is qualified\n");
    LOG_WARN(EXPORT_SUBSYS,
             "Windows export refused before datadir or output mutation");
    exit(EXIT_FAILURE);
#else
    if (datadir_name_is_empty(datadir)) {
        fprintf(stderr, "REFUSED: -export-consensus-bundle: empty datadir\n");
        LOG_WARN(EXPORT_SUBSYS, "empty datadir");
        _exit(EXIT_FAILURE);
    }
    if (!ndb) {
        fprintf(stderr,
                "REFUSED: -export-consensus-bundle: block index unavailable\n");
        LOG_WARN(EXPORT_SUBSYS, "null node db");
        _exit(EXIT_FAILURE);
    }
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp) {
        fprintf(stderr, "REFUSED: -export-consensus-bundle: no compiled SHA3 "
                        "UTXO checkpoint to export against\n");
        LOG_WARN(EXPORT_SUBSYS, "no compiled checkpoint");
        _exit(EXIT_FAILURE);
    }

    if (!checkpoint_db_header_valid(ndb, cp)) {
        fprintf(stderr,
                "REFUSED: -export-consensus-bundle: no validated header at the "
                "compiled checkpoint height %d (import the header chain first)\n",
                cp->height);
        LOG_WARN(EXPORT_SUBSYS, "no validated header at checkpoint height %d",
                 cp->height);
        _exit(EXIT_FAILURE);
    }

    char name[128];
    if (!format_bundle_name(name, sizeof(name), cp->height)) {
        fprintf(stderr,
                "REFUSED: -export-consensus-bundle: bundle name overflow\n");
        LOG_WARN(EXPORT_SUBSYS, "bundle name overflow height=%d", cp->height);
        _exit(EXIT_FAILURE);
    }
    int dir_fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) {
        fprintf(stderr,
                "REFUSED: -export-consensus-bundle: cannot open datadir %s "
                "(errno=%d)\n", datadir, errno);
        LOG_WARN(EXPORT_SUBSYS, "datadir open failed errno=%d", errno);
        _exit(EXIT_FAILURE);
    }

    struct consensus_state_snapshot_export_request request = {
        .output_dir_fd = dir_fd,
        .output_name = name,
        .expected_height = cp->height,
        .checkpoint_content_export = true,
    };
    memcpy(request.expected_block_hash, cp->block_hash, 32);

    const struct block_index *cp_bi;
    if (!ram_chain_owns_checkpoint(ms, cp, &cp_bi)) {
        (void)close(dir_fd);
        fprintf(stderr,
                "REFUSED: -export-consensus-bundle: in-RAM header chain does "
                "not own the compiled checkpoint block at height %d (import "
                "the header chain first)\n", cp->height);
        LOG_WARN(EXPORT_SUBSYS,
                 "in-RAM chain missing/mismatched at checkpoint height %d",
                 cp->height);
        _exit(EXIT_FAILURE);
    }
    if (sapling_root_is_zero(cp_bi)) {
        (void)close(dir_fd);
        fprintf(stderr,
                "REFUSED: -export-consensus-bundle: the validated header at "
                "the checkpoint height carries an all-zero final Sapling root "
                "— refusing to bind against zeros\n");
        LOG_WARN(EXPORT_SUBSYS,
                 "zero hashFinalSaplingRoot at checkpoint height %d",
                 cp->height);
        _exit(EXIT_FAILURE);
    }
    memcpy(request.checkpoint_sapling_root,
           cp_bi->hashFinalSaplingRoot.data, 32);
    struct consensus_state_export_result res;
    memset(&res, 0, sizeof(res));
    bool exported =
        consensus_state_snapshot_export(progress_store_db(), &request, &res);
    (void)close(dir_fd);

    if (!export_result_ok(exported, &res)) {
        fprintf(stderr, "REFUSED: -export-consensus-bundle: %s\n",
                export_reason_or_default(res.reason,
                                         "checkpoint-content export failed"));
        LOG_WARN(EXPORT_SUBSYS, "export refused status=%d: %s", (int)res.status,
                 export_reason_or_default(res.reason, "unknown"));
        _exit(EXIT_FAILURE);
    }

    char digest_hex[65];
    format_digest_hex(digest_hex, res.artifact_digest);
    fprintf(stderr,
            "EXPORTED: -export-consensus-bundle: %s at h=%d -> %s/%s "
            "(digest=%s coins=%llu anchors=%llu nullifiers=%llu) via "
            "checkpoint-content proof (coins SHA3 + header Sapling root)\n",
            CONSENSUS_STATE_BUNDLE_SCHEMA, res.height, datadir, name, digest_hex,
            (unsigned long long)res.utxo_count,
            (unsigned long long)res.anchor_count,
            (unsigned long long)res.nullifier_count);
    LOG_INFO(EXPORT_SUBSYS, "exported checkpoint-content bundle h=%d count=%llu",
             res.height, (unsigned long long)res.utxo_count);
    _exit(EXIT_SUCCESS);
#endif
}
