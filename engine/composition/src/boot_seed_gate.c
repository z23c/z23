/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_seed_gate — up-front admission gates for the deprecated-but-guarded
 * -load-snapshot-at-own-height seed path (config/boot.h). The loader is
 * superseded by -install-consensus-bundle for complete (transparent + shielded)
 * state, but the live/dev-lane units and the cold-start driver's SEED stage
 * still reference the flag, so it is guarded rather than deleted:
 *
 *   D1  boot_seed_refuse_shieldless_or_die — a v1 transparent-only seed past
 *       Sapling activation is a guaranteed DELAYED wedge (the first shielded tx
 *       above the seed hits utxo_apply.{anchor,nullifier}_backfill_gap); refuse
 *       UP FRONT off a cheap header peek instead of after ~33 folded blocks.
 *   D3  boot_seed_oneshot_headers_preflight — the seed one-shot has no P2P/IBD;
 *       name the headers prerequisite the instant the block index is loaded
 *       rather than burning a full boot then FATAL-ing deep in the seed reset.
 *
 * The pure decision predicates (boot_seed_is_shieldless_past_sapling,
 * boot_seed_oneshot_headers_ready) have no side effects and are unit-tested in
 * tests/harness/src/test_loader_owns_seed_gate.c. */

#include "config/boot.h"          /* struct app_context, the gate declarations */

#include "chain/utxo_snapshot_loader.h"  /* uss_open/uss_version/uss_close */
#include "chain/chainparams.h"           /* chain_params_get */
#include "consensus/params.h"            /* UPGRADE_SAPLING, vUpgrades */
#include "chain/chain.h"                 /* struct block_index */
#include "validation/main_state.h"       /* struct main_state, pindex_best_header */
#include "event/event.h"                 /* event_emitf, EV_BOOT_VALIDATION_FAILED */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>                       /* _exit, EXIT_FAILURE */
#include <unistd.h>

bool boot_seed_is_shieldless_past_sapling(uint32_t version, int64_t seed_height,
                                          int64_t sapling_activation)
{
    return version < 2 && sapling_activation >= 0 &&
           seed_height >= sapling_activation;
}

bool boot_seed_oneshot_headers_ready(int64_t header_tip, int64_t seed_height)
{
    return header_tip >= seed_height;
}

void boot_seed_refuse_shieldless_or_die(const char *path)
{
    if (!path || !path[0])
        return;
    char err[256] = {0};
    struct uss_header hdr;
    struct uss_handle *peek = uss_open(path, /*verify_full_sha3=*/false,
                                       /*expected_sha3=*/NULL, &hdr, err,
                                       sizeof(err));
    if (!peek)
        return;   /* the full verified open downstream reports the real error */
    uint32_t ver = uss_version(peek);
    int64_t seed_h = (int64_t)hdr.height;
    uss_close(peek);

    const struct chain_params *cp = chain_params_get();
    int64_t sapling_activation =
        cp ? (int64_t)cp->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight
           : -1;
    if (!boot_seed_is_shieldless_past_sapling(ver, seed_h, sapling_activation))
        return;

    fprintf(stderr,
        "FATAL: -load-snapshot-at-own-height: %s is a v%u TRANSPARENT-ONLY seed "
        "with no shielded history (anchors/nullifiers), but its height h=%lld is "
        "past Sapling activation h=%lld. A mainnet node WILL wedge at the first "
        "shielded tx above the seed (utxo_apply.anchor_backfill_gap + "
        "nullifier_backfill_gap). REFUSING up front. Use the consensus-bundle "
        "install (-install-consensus-bundle=<bundle>), which carries complete "
        "shielded state, or a v2/v3 snapshot instead.\n",
        path, ver, (long long)seed_h, (long long)sapling_activation);
    event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
        "load_snapshot_at_own_height shieldless_past_sapling version=%u "
        "seed_h=%lld sapling_activation=%lld",
        ver, (long long)seed_h, (long long)sapling_activation);
    _exit(EXIT_FAILURE);
}

bool boot_seed_oneshot_headers_preflight(const struct app_context *ctx,
                                         const struct main_state *ms)
{
    if (!ctx || !ctx->cold_start_seed_oneshot ||
        !ctx->load_snapshot_at_own_height)
        return true;   /* not a seed one-shot — nothing to preflight */

    char err[256] = {0};
    struct uss_header hdr;
    struct uss_handle *peek = uss_open(ctx->load_snapshot_at_own_height,
                                       /*verify_full_sha3=*/false,
                                       /*expected_sha3=*/NULL, &hdr, err,
                                       sizeof(err));
    if (!peek) {
        fprintf(stderr, "FATAL: -coldstart-seed-oneshot: cannot open seed "
                "snapshot %s: %s\n", ctx->load_snapshot_at_own_height, err);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "coldstart_seed_oneshot snapshot_open_failed err=%s", err);
        return false;
    }
    int64_t seed_h = (int64_t)hdr.height;
    uss_close(peek);

    int64_t hdr_tip = ms && ms->pindex_best_header
                          ? ms->pindex_best_header->nHeight : -1;
    if (!boot_seed_oneshot_headers_ready(hdr_tip, seed_h)) {
        fprintf(stderr,
            "FATAL: -coldstart-seed-oneshot: PREREQUISITE NOT MET — the block "
            "index has no header at the snapshot height h=%lld (imported header "
            "tip h=%lld). The seed one-shot cannot sync headers itself; import "
            "the header chain to >= h=%lld first (zclassic23 --importblockindex "
            "<datadir-with-headers>), then re-run the seed.\n",
            (long long)seed_h, (long long)hdr_tip, (long long)seed_h);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
            "coldstart_seed_oneshot headers_prerequisite_unmet seed_h=%lld "
            "header_tip=%lld", (long long)seed_h, (long long)hdr_tip);
        return false;
    }
    fprintf(stderr, "[boot] -coldstart-seed-oneshot: headers prerequisite OK "
            "(header tip h=%lld >= seed h=%lld) — proceeding to seed.\n",
            (long long)hdr_tip, (long long)seed_h);
    return true;
}
