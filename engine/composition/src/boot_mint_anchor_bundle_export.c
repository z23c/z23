/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 *
 * Purpose: Lane A1 — emit the contained full-history consensus-state bundle
 * out of the mint datadir once the producer source receipt is finalized.
 * Quiesces the in-RAM fold overlay, drives the exporter, and turns any refusal
 * into a typed PERMANENT blocker without touching the verified anchor snapshot
 * or the receipt.
 *
 * Split out of boot_mint_anchor.c along the file-size ceiling seam (E1). That
 * file keeps the mint driver itself — the boot gates, the frontier-wall report,
 * the fold drive, and the terminal SHA3==checkpoint hard-assert. The contract
 * is declared in config/boot.h, so nothing private crosses this seam.
 */
#include "config/boot_internal.h"  /* boot_full_fold_is_armed/_finish (-full-fold) */
#include "config/boot_mint_anchor_drive.h"
#include "config/mint_anchor_progress.h"
#include "config/consensus_state_producer_receipt.h"
#include "config/consensus_state_snapshot_export.h"  /* consensus_state_snapshot_export */

#include <errno.h>
#include <fcntl.h>           /* open, O_DIRECTORY */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>          /* EXIT_FAILURE, getenv */
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>          /* _exit */
#include <sqlite3.h>

#include "chain/checkpoints.h"                  /* get_sha3_utxo_checkpoint */
#include "storage/coins_kv.h"                   /* coins_kv_snapshot_write,
                                                 * coins_kv_get_applied_height,
                                                 * coins_kv_count,
                                                 * coins_kv_commitment */
#include "storage/coins_ram.h"                  /* coins_ram_active,
                                                 * coins_ram_commitment */
#include "storage/snapshot_shielded.h"          /* snapshot_shielded_collect_from_db */
#include "storage/event_log_singleton.h"        /* event_log_set_singleton (S1.2) */
#include "storage/consensus_state_bundle_codec.h" /* CONSENSUS_STATE_VALIDATION_* */
#include "storage/progress_store.h"             /* progress_store_db */
#include "jobs/mint_skip_crypto.h"              /* mint_skip_crypto_get */
#include "jobs/proof_validate_stage.h"          /* proof_validate_lookahead_start */
#include "jobs/utxo_apply_stage.h"              /* utxo_apply_stage_cursor */
#include "jobs/stage_helpers.h"                 /* stage_cursor_persisted */
#include "services/chain_activation_service.h"  /* reducer_kick,
                                                 * boot_activation_controller */
#include "event/event.h"                        /* event_emitf */
#include "util/blocker.h"                       /* blocker_init, blocker_set */
#include "util/log_macros.h"
#include "core/utiltime.h"                       /* GetTimeMicros */

/* Lane A1 — emit the contained full-history zcl.consensus_state_bundle.v1 into
 * the mint datadir once the producer source receipt has been finalized. This is
 * the exporter's (config/consensus_state_snapshot_export.h) ONLY viable caller:
 * its receipt-binding proof requires the exporting process to be the EXACT
 * binary that folded (running_binary_digest == SHA3(/proc/self/exe)), so an
 * offline verb from a different binary is provably impossible — the export must
 * happen here, in-process, right after finalize.
 *
 * The exporter demands a durable, overlay-free, fully-proven source generation,
 * so this first QUIESCES the in-RAM fold overlay: coins_ram_flush_final drains
 * the un-flushed tail into durable coins_kv (co-advancing coins_applied_height
 * to anchor+1) and coins_ram_shutdown frees the map so coins_ram_active() is
 * false (the exporter refuses while the overlay is live). It then exports to
 * <datadir>/consensus-state-bundle-<anchor>.sqlite.
 *
 * Idempotent across re-runs of the SAME binary: an already-present bundle at
 * that name is a completed export (the exporter only ever links a fully
 * validated immutable inode and publishes NOTHING on any failure), so it is
 * treated as done. A failed export never touches the verified anchor snapshot
 * or the receipt; it pages EV_OPERATOR_NEEDED, registers the typed PERMANENT
 * blocker mint_bundle.export_failed, and returns false so the one-shot exits
 * non-zero (the systemd unit shows the miss). Returns true on a fresh export or
 * an already-present bundle. Public (config/boot.h) so the
 * consensus_state_snapshot_export test group can prove the wiring fires. */
bool boot_mint_anchor_export_bundle(sqlite3 *pdb, const char *datadir,
                                    int32_t anchor,
                                    const uint8_t block_hash[32])
{
#if defined(_WIN32)
    (void)pdb;
    (void)datadir;
    (void)anchor;
    (void)block_hash;
    fprintf(stderr,
            "REFUSED: mint-anchor bundle export is unavailable on Windows "
            "until the exporter accepts a validated native directory "
            "capability\n");
    return false;
#else
    const char *dir = (datadir && datadir[0]) ? datadir : ".";
    char name[128];
    int nn = snprintf(name, sizeof(name),
                      "consensus-state-bundle-%d.sqlite", anchor);
    if (nn <= 0 || (size_t)nn >= sizeof(name)) {
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "condition=mint_bundle_export_failed reason=name_overflow "
                    "anchor=%d", anchor);
        LOG_FAIL("mint_anchor",
                 "[mint-anchor] consensus-state bundle name overflow anchor=%d",
                 anchor);
    }

    int dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) {
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "condition=mint_bundle_export_failed reason=datadir_open "
                    "anchor=%d errno=%d", anchor, errno);
        LOG_FAIL("mint_anchor",
                 "[mint-anchor] consensus-state bundle: cannot open datadir %s "
                 "for export (errno=%d)", dir, errno);
    }

    /* Already exported by a prior run? A present name is always a completed,
     * fully validated immutable bundle — nothing to redo (a failed export
     * leaves no file). Retry-on-rerun therefore comes for free: missing ->
     * export; present -> success no-op; prior failure -> absent, so retried. */
    struct stat existing;
    if (fstatat(dir_fd, name, &existing, AT_SYMLINK_NOFOLLOW) == 0) {
        (void)close(dir_fd);
        fprintf(stderr,
                "[mint-anchor] consensus-state bundle already present (prior "
                "run): %s/%s — nothing to export\n", dir, name);
        return true;
    }

    /* Quiesce the in-RAM fold overlay so the durable coins set IS the effective
     * set the exporter proves (it refuses while coins_ram_active()). */
    if (coins_ram_active()) {
        if (!coins_ram_flush_final()) {
            (void)close(dir_fd);
            event_emitf(EV_OPERATOR_NEEDED, 0,
                        "condition=mint_bundle_export_failed "
                        "reason=coins_ram_flush anchor=%d", anchor);
            struct blocker_record frec;
            if (blocker_init(&frec, "mint_bundle.export_failed", "mint_anchor",
                             BLOCKER_PERMANENT,
                             "consensus-state bundle export aborted: coins RAM "
                             "overlay flush failed before export"))
                (void)blocker_set(&frec);
            LOG_FAIL("mint_anchor",
                     "[mint-anchor] consensus-state bundle export aborted: "
                     "coins RAM overlay flush to durable coins_kv failed");
        }
        coins_ram_shutdown();
        fprintf(stderr,
                "[mint-anchor] coins RAM overlay flushed to durable coins_kv "
                "and released for the consensus-state bundle export\n");
    }

    struct consensus_state_snapshot_export_request request = {
        .output_dir_fd = dir_fd,
        .output_name = name,
        .expected_height = anchor,
    };
    memcpy(request.expected_block_hash, block_hash, 32);
    struct consensus_state_export_result res;
    bool exported = consensus_state_snapshot_export(pdb, &request, &res);
    (void)close(dir_fd);

    if (!exported || res.status != CONSENSUS_EXPORT_EXPORTED) {
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "condition=mint_bundle_export_failed anchor=%d status=%d "
                    "reason=%s", anchor, (int)res.status,
                    res.reason[0] ? res.reason : "unknown");
        char breason[640];
        snprintf(breason, sizeof(breason),
                 "consensus-state bundle export refused anchor=%d status=%d: %s "
                 "(verified anchor snapshot + receipt intact)",
                 anchor, (int)res.status,
                 res.reason[0] ? res.reason : "unknown");
        struct blocker_record frec;
        if (blocker_init(&frec, "mint_bundle.export_failed", "mint_anchor",
                         BLOCKER_PERMANENT, breason))
            (void)blocker_set(&frec);
        LOG_FAIL("mint_anchor",
                 "[mint-anchor] consensus-state bundle export FAILED (anchor=%d "
                 "status=%d): %s — the verified anchor snapshot and producer "
                 "receipt are unaffected", anchor, (int)res.status,
                 res.reason[0] ? res.reason : "unknown");
    }

    char digest_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(digest_hex + 2 * i, 3, "%02x", res.artifact_digest[i]);
    fprintf(stderr,
            "[mint-anchor] SUCCESS: exported %s at h=%d -> %s/%s (digest=%s "
            "coins=%llu anchors=%llu nullifiers=%llu profile=%s)\n",
            CONSENSUS_STATE_BUNDLE_SCHEMA, res.height, dir, name, digest_hex,
            (unsigned long long)res.utxo_count,
            (unsigned long long)res.anchor_count,
            (unsigned long long)res.nullifier_count,
            res.validation_profile == CONSENSUS_STATE_VALIDATION_FULL
                ? "full" : "checkpoint_fold");
    return true;
#endif
}
