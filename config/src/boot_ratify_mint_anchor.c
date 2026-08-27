/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_ratify_mint_anchor.c — the -ratify-mint-anchor verb: a TERMINAL offline
 * ratifier for a COMPLETED full-validation mint producer datadir (run against a
 * COPY of it). It closes the gap where a fresh producer folds genesis..anchor,
 * matches the compiled checkpoint HARD-ASSERT, finalizes its receipt — and then
 * the bundle exporter refuses because the migration-complete + self-folded
 * markers coins_kv_is_proven_authority()/contains_refold_marker() require are
 * never stamped on a self-folded mint (those keys are written only by
 * install/refold/seed paths that never run on a producer).
 *
 * The verb re-derives the coins_kv commitment + count + applied frontier from
 * THIS datadir's OWN durable tables (never the coins_ram overlay — it reads the
 * durable set and refuses if the overlay is live) and, ONLY on full agreement
 * with the compiled SHA3 UTXO checkpoint, stamps the two markers and re-arms the
 * mint resume marker (so a later -mint-anchor of the original fold binary
 * resumes at the anchor instead of genesis-resetting). Any disagreement stamps
 * NOTHING and refuses. Every path _exit()s. Contract declared in config/boot.h. */

#include "config/boot.h"

#include "chain/checkpoints.h"
#include "config/mint_anchor_progress.h"
#include "storage/coins_kv.h"
#include "storage/coins_ram.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RATIFY_SUBSYS "ratify_mint_anchor"

static void ratify_hex32(char out[65], const uint8_t in[32])
{
    for (int i = 0; i < 32; i++)
        snprintf(out + 2 * i, 3, "%02x", in[i]);
}

/* Shared ratify core. Re-derives pdb's OWN durable coins_kv commitment/count/
 * applied and, only on exact agreement with (height, coins_sha3, count) AND
 * applied-through == height, stamps migration-complete + self_folded — and,
 * when `mint_rearm_cp` is non-NULL, re-arms the mint resume marker — atomically
 * under one progress-store critical section. Stamps NOTHING on disagreement. */
static bool ratify_seam_core(struct sqlite3 *pdb, int32_t height,
                             const uint8_t coins_sha3[32], uint64_t count_want,
                             const struct sha3_utxo_checkpoint *mint_rearm_cp,
                             struct boot_ratify_result *out)
{
    if (!out)
        LOG_FAIL(RATIFY_SUBSYS, "check_and_stamp: NULL result");
    memset(out, 0, sizeof(*out));
    if (!pdb || !coins_sha3 || height < 0) {
        snprintf(out->reason, sizeof(out->reason),
                 "null/invalid args pdb=%p coins_sha3=%p height=%d", (void *)pdb,
                 (const void *)coins_sha3, height);
        LOG_FAIL(RATIFY_SUBSYS, "%s", out->reason);
    }

    /* The durable coins_kv is the ratification input; a live RAM overlay would
     * shadow coins_kv_commitment/count with an un-flushed set. Ratify runs
     * terminally with no fold, so the overlay must be inert — refuse rather than
     * ratify a value the durable set does not actually hold (mirrors the
     * exporter's coins_ram_active refusal). */
    if (coins_ram_active()) {
        snprintf(out->reason, sizeof(out->reason),
                 "coins RAM overlay is active; ratify reads the durable set");
        LOG_FAIL(RATIFY_SUBSYS, "%s", out->reason);
    }

    uint8_t got_sha3[32] = {0};
    if (coins_kv_commitment(pdb, got_sha3) != 0) {
        snprintf(out->reason, sizeof(out->reason),
                 "coins_kv commitment computation failed");
        LOG_FAIL(RATIFY_SUBSYS, "%s", out->reason);
    }
    int64_t count = coins_kv_count(pdb);
    if (count < 0) {
        snprintf(out->reason, sizeof(out->reason), "coins_kv count read failed");
        LOG_FAIL(RATIFY_SUBSYS, "%s", out->reason);
    }
    int32_t applied = -1;
    bool applied_found = false;
    if (!coins_kv_get_applied_height(pdb, &applied, &applied_found)) {
        snprintf(out->reason, sizeof(out->reason),
                 "coins_applied_height read failed");
        LOG_FAIL(RATIFY_SUBSYS, "%s", out->reason);
    }

    memcpy(out->sha3, got_sha3, 32);
    out->count = (uint64_t)count;
    out->height = height;

    bool sha3_ok = memcmp(got_sha3, coins_sha3, 32) == 0;
    bool count_ok = (uint64_t)count == count_want;
    bool applied_ok = applied_found && applied == height + 1;
    if (!sha3_ok || !count_ok || !applied_ok) {
        char got_hex[65], want_hex[65];
        ratify_hex32(got_hex, got_sha3);
        ratify_hex32(want_hex, coins_sha3);
        snprintf(out->reason, sizeof(out->reason),
                 "seam mismatch sha3=%s/%s n=%llu/%llu h=%s%d/%d",
                 got_hex, want_hex, (unsigned long long)count,
                 (unsigned long long)count_want,
                 applied_found ? "" : "absent:", applied, height + 1);
        return false;  /* legitimate negative result — stamp NOTHING */
    }

    /* Full agreement — stamp the earned authority markers (and, for the
     * checkpoint wrapper, re-arm the mint resume marker so a later -mint-anchor
     * of the original fold binary resumes at the anchor instead of genesis-
     * resetting) as one progress-store critical section. */
    progress_store_tx_lock();
    bool stamped = coins_kv_mark_migration_complete(pdb) &&
                   coins_kv_mark_self_folded(pdb) &&
                   (mint_rearm_cp == NULL ||
                    mint_anchor_progress_mark(pdb, mint_rearm_cp));
    progress_store_tx_unlock();
    if (!stamped) {
        snprintf(out->reason, sizeof(out->reason),
                 "seam agreed but stamping the sovereign markers failed");
        LOG_FAIL(RATIFY_SUBSYS, "%s", out->reason);
    }

    out->ratified = true;
    snprintf(out->reason, sizeof(out->reason),
             "coins_kv reproduces the seam at h=%d", height);
    return true;
}

bool boot_ratify_seam_check_and_stamp(struct sqlite3 *pdb, int32_t height,
                                      const uint8_t coins_sha3[32],
                                      uint64_t count,
                                      struct boot_ratify_result *out)
{
    return ratify_seam_core(pdb, height, coins_sha3, count, NULL, out);
}

bool boot_ratify_mint_anchor_check_and_stamp(
    struct sqlite3 *pdb, const struct sha3_utxo_checkpoint *cp,
    struct boot_ratify_result *out)
{
    if (!out)
        LOG_FAIL(RATIFY_SUBSYS, "check_and_stamp: NULL result");
    if (!cp) {
        memset(out, 0, sizeof(*out));
        snprintf(out->reason, sizeof(out->reason), "null args pdb=%p cp=%p",
                 (void *)pdb, (const void *)cp);
        LOG_FAIL(RATIFY_SUBSYS, "%s", out->reason);
    }
    return ratify_seam_core(pdb, cp->height, cp->sha3_hash, cp->utxo_count, cp,
                            out);
}

void boot_ratify_mint_anchor(const char *datadir)
{
    if (!datadir || !datadir[0]) {
        fprintf(stderr, "REFUSED: -ratify-mint-anchor: empty datadir\n");
        LOG_WARN(RATIFY_SUBSYS, "empty datadir");
        _exit(EXIT_FAILURE);
    }
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp) {
        fprintf(stderr, "REFUSED: -ratify-mint-anchor: no compiled SHA3 UTXO "
                        "checkpoint to ratify against\n");
        LOG_WARN(RATIFY_SUBSYS, "no compiled checkpoint");
        _exit(EXIT_FAILURE);
    }

    struct boot_ratify_result r;
    bool ok = boot_ratify_mint_anchor_check_and_stamp(progress_store_db(),
                                                      cp, &r);
    if (!ok) {
        fprintf(stderr, "REFUSED: -ratify-mint-anchor: %s\n", r.reason);
        LOG_WARN(RATIFY_SUBSYS, "%s", r.reason);
        _exit(EXIT_FAILURE);
    }

    char sha3_hex[65];
    ratify_hex32(sha3_hex, r.sha3);
    fprintf(stderr,
            "RATIFIED: -ratify-mint-anchor: this datadir's coins_kv reproduces "
            "the compiled checkpoint (height=%d count=%llu sha3=%s).\n"
            "  Stamped migration-complete + self-folded and re-armed the mint "
            "resume marker; the consensus-state bundle exporter can now admit a "
            "-mint-anchor run of the original fold binary on this datadir.\n",
            r.height, (unsigned long long)r.count, sha3_hex);
    LOG_INFO(RATIFY_SUBSYS, "ratified checkpoint h=%d count=%llu", r.height,
             (unsigned long long)r.count);
    _exit(EXIT_SUCCESS);
}
