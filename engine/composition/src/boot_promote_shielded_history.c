/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_promote_shielded_history.c — the -promote-shielded-history=<producer>
 * verb: a TERMINAL offline promote that installs a FINISHED producer's
 * below-checkpoint shielded history (Sprout+Sapling anchors + nullifiers) into a
 * WEDGED COPY datadir's progress.kv, atomically flipping all three shielded
 * activation cursors to 0 — clearing the utxo_apply.anchor_backfill_gap +
 * nullifier_backfill_gap wedge WITHOUT a from-genesis refold on the copy.
 *
 * This runs at the terminal-verb dispatch point (after the header chain is
 * loaded into the in-RAM block index), so the service can bind each installed
 * Sapling frontier to the header-committed hashFinalSaplingRoot from THIS node's
 * validated block index (active_chain), and prove below-boundary completeness.
 *
 * PATH SAFETY (physically unable to touch a live datadir): both the target
 * -datadir AND the producer path MUST carry the literal "-COPY-" marker and
 * NEITHER may name a known live datadir (~/.zclassic-c23, ~/.zclassic-c23-mint,
 * ~/.zclassic-c23-mint3, ~/.zclassic). Any failure refuses before opening
 * anything. Mirrors cognition/controllers/src/agent_copy_prove_controller.c's
 * cp_path_safety_ok. Every path _exit()s. Contract declared in config/boot.h. */

#include "config/boot.h"

#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "consensus/params.h"
#include "services/shielded_history_promote_service.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROMOTE_VERB_SUBSYS "promote_shielded_history"

/* Known live datadir basenames (never targets of a copy-prove tool). */
static bool promote_path_is_live_datadir(const char *path)
{
    if (!path || !path[0])
        return false;
    const char *home = getenv("HOME");
    static const char *const live[] = {
        ".zclassic-c23", ".zclassic-c23-mint", ".zclassic-c23-mint3",
        ".zclassic",
    };
    char buf[1200];
    for (size_t i = 0; home && home[0] && i < sizeof(live) / sizeof(live[0]);
         i++) {
        int n = snprintf(buf, sizeof(buf), "%s/%s", home, live[i]);
        if (n <= 0 || (size_t)n >= sizeof(buf))
            continue;
        /* Compare with any single trailing slash normalized away. */
        size_t tl = strlen(path);
        while (tl > 1 && path[tl - 1] == '/') tl--;
        if (strlen(buf) == tl && strncmp(path, buf, tl) == 0)
            return true;
    }
    return false;
}

/* A throwaway copy carries the literal "-COPY-" marker and is not a live
 * datadir — the same discipline agent_copy_prove_controller enforces. */
static bool promote_path_safety_ok(const char *path)
{
    return path && path[0] && strstr(path, "-COPY-") != NULL &&
           !promote_path_is_live_datadir(path);
}

void boot_promote_shielded_history(struct main_state *ms,
                                   const char *target_datadir,
                                   const char *producer_datadir)
{
    if (!target_datadir || !target_datadir[0] || !producer_datadir ||
        !producer_datadir[0]) {
        fprintf(stderr, "REFUSED: -promote-shielded-history: empty target or "
                        "producer datadir\n");
        LOG_WARN(PROMOTE_VERB_SUBSYS, "empty datadir arg");
        _exit(EXIT_FAILURE);
    }

    /* PATH SAFETY — refuse before opening anything. */
    if (!promote_path_safety_ok(target_datadir)) {
        fprintf(stderr,
                "REFUSED: -promote-shielded-history: target %s is not a "
                "throwaway *-COPY-* datadir (or aliases a live datadir). "
                "Copy-prove on a COPY first.\n", target_datadir);
        LOG_WARN(PROMOTE_VERB_SUBSYS, "unsafe target %s", target_datadir);
        _exit(EXIT_FAILURE);
    }
    if (!promote_path_safety_ok(producer_datadir)) {
        fprintf(stderr,
                "REFUSED: -promote-shielded-history: producer %s is not a "
                "throwaway *-COPY-* datadir (or aliases a live datadir).\n",
                producer_datadir);
        LOG_WARN(PROMOTE_VERB_SUBSYS, "unsafe producer %s", producer_datadir);
        _exit(EXIT_FAILURE);
    }

    if (!ms) {
        fprintf(stderr, "REFUSED: -promote-shielded-history: main state "
                        "unavailable\n");
        LOG_WARN(PROMOTE_VERB_SUBSYS, "null main state");
        _exit(EXIT_FAILURE);
    }
    struct block_index *header_tip = active_chain_tip(&ms->chain_active);
    if (!header_tip) {
        fprintf(stderr, "REFUSED: -promote-shielded-history: no in-RAM header "
                        "chain tip (import the header chain first)\n");
        LOG_WARN(PROMOTE_VERB_SUBSYS, "no active-chain tip");
        _exit(EXIT_FAILURE);
    }
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp) {
        fprintf(stderr, "REFUSED: -promote-shielded-history: no compiled SHA3 "
                        "UTXO checkpoint to bound the producer against\n");
        LOG_WARN(PROMOTE_VERB_SUBSYS, "no compiled checkpoint");
        _exit(EXIT_FAILURE);
    }

    const struct chain_params *params = chain_params_get();
    int64_t sapling_activation =
        params
            ? (int64_t)params->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight
            : -1;
    if (sapling_activation < 0) {
        fprintf(stderr, "REFUSED: -promote-shielded-history: Sapling activation "
                        "height unavailable/disabled\n");
        LOG_WARN(PROMOTE_VERB_SUBSYS, "no sapling activation height");
        _exit(EXIT_FAILURE);
    }

    struct shielded_promote_request req = {
        .target_progress_db = progress_store_db(),
        .target_copy_datadir = target_datadir,
        .producer_datadir = producer_datadir,
        .header_tip = header_tip,
        .sapling_activation_height = sapling_activation,
        .checkpoint_height = cp->height,
    };
    if (!req.target_progress_db) {
        fprintf(stderr, "REFUSED: -promote-shielded-history: target progress.kv "
                        "not open\n");
        LOG_WARN(PROMOTE_VERB_SUBSYS, "target progress store not open");
        _exit(EXIT_FAILURE);
    }

    struct shielded_promote_report rep = {0};
    bool ok = shielded_history_promote_run(&req, &rep);
    if (!ok || !rep.committed) {
        fprintf(stderr,
                "REFUSED: -promote-shielded-history: nothing committed, wedge "
                "intact (all three shielded activation cursors stay POSITIVE, "
                "gap blockers remain). See node.log [shielded_promote] for the "
                "exact gate that refused.\n");
        LOG_WARN(PROMOTE_VERB_SUBSYS, "promote refused ok=%d committed=%d", ok,
                 rep.committed);
        _exit(EXIT_FAILURE);
    }

    fprintf(stderr,
            "PROMOTED: -promote-shielded-history: %s -> %s installed "
            "sapling_anchors=%lld sprout_anchors=%lld sapling_nf=%lld "
            "sprout_nf=%lld; all three shielded activation cursors flipped to 0 "
            "(anchor + nullifier gap blockers cleared). Copy-prove H* climb + "
            "tip-hash parity vs zclassicd before cutover.\n",
            producer_datadir, target_datadir,
            (long long)rep.sapling_anchors_installed,
            (long long)rep.sprout_anchors_installed,
            (long long)rep.sapling_nullifiers_installed,
            (long long)rep.sprout_nullifiers_installed);
    LOG_INFO(PROMOTE_VERB_SUBSYS,
             "promoted shielded history from %s into %s (boundary=%lld)",
             producer_datadir, target_datadir, (long long)rep.anchor_boundary);
    _exit(EXIT_SUCCESS);
}
