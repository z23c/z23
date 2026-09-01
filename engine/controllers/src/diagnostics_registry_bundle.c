/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Bundle/snapshot staleness dump. Lives here (not diagnostics_registry.c)
 * so that file stays a routing table rather than a home for every dumper's
 * full body — same pattern as diagnostics_sapling_checkpoint.c and
 * diagnostics_block_index.c. Registered as the "bundle_staleness"
 * g_dumpers[] entry in diagnostics_registry.c; declarations live in
 * diagnostics_internal.h (the shared internal header the registry already
 * includes).
 *
 * Read-only freshness signal for the published fast-sync starter pack. A
 * fresh install seeds at the bundle height then P2P-fetches the gap to tip,
 * so a bundle far below the tip turns "seconds to tip" into minutes. This
 * dumper computes (network_header_tip - bundle_seed_height), turns it into an
 * estimated catch-up time, and surfaces a re-mint recommendation so an
 * operator/CI gets a "bundle is N blocks stale — re-mint" signal WITHOUT
 * auto-minting from the live datadir (minting stays owner-driven; see
 * tools/mint_v2_snapshot.c and the runbook in docs/work).
 *
 * Lives here (not config/boot_refold_staged.c) because it needs BOTH the
 * controller-level datadir (diag_datadir) and main_state (the network tip).
 * Pure opendir/readdir/access + one locked best-header read; no mutation, no
 * sqlite, and parity-neutral. */

#include "controllers/diagnostics_internal.h"

#include "chain/chain.h"
#include "json/json.h"
#include "util/sync.h"
#include "validation/main_state.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Conservative above-seed P2P body-fetch+fold rate (blocks/sec). The published
 * gap divided by this estimates a fresh install's catch-up time. Tracks the
 * measured ~3 blk/s post-seed fetch+fold rate. */
#define ZCL_BUNDLE_CATCHUP_BLOCKS_PER_SEC 3
/* The "seconds to tip" design target: at/below this catch-up the bundle is
 * fresh enough that a fresh install is effectively at the tip on first boot. */
#define ZCL_BUNDLE_FRESH_SECS  60
/* Above this estimated catch-up, recommend re-minting a tip-fresh bundle. */
#define ZCL_BUNDLE_REMINT_SECS 600

long long bundle_scan_seed_height(const char *datadir, int *count,
                                  char *name, size_t name_sz)
{
    if (count) *count = 0;
    if (name && name_sz) name[0] = '\0';
    if (!datadir || !datadir[0])
        return -1;  // raw-return-ok:sentinel -1 = "no bundle", not an error

    DIR *d = opendir(datadir);
    if (!d)
        return -1;  // raw-return-ok:sentinel -1 = "no bundle dir", not an error

    /* Match utxo-seed-<digits>.snapshot — identical to the boot autodetect. */
    static const char PFX[] = "utxo-seed-";
    static const char SFX[] = ".snapshot";
    const size_t plen = sizeof(PFX) - 1, slen = sizeof(SFX) - 1;
    long long best_h = -1;
    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        const char *nm = ent->d_name;
        size_t len = strlen(nm);
        if (len <= plen + slen)
            continue;
        if (strncmp(nm, PFX, plen) != 0)
            continue;
        if (strcmp(nm + len - slen, SFX) != 0)
            continue;
        long long h = 0;
        bool digits_ok = true;
        for (size_t i = plen; i < len - slen; i++) {
            if (nm[i] < '0' || nm[i] > '9') { digits_ok = false; break; }
            h = h * 10 + (nm[i] - '0');
        }
        if (!digits_ok)
            continue;
        n++;
        if (h > best_h) {
            best_h = h;
            if (name && name_sz)
                snprintf(name, name_sz, "%s", nm);
        }
    }
    closedir(d);
    if (count) *count = n;
    return best_h;
}

enum bundle_freshness bundle_classify(long long seed_h, long long header_tip,
                                      long long *gap_out, long long *secs_out)
{
    if (seed_h < 0 || header_tip < 0) {
        if (gap_out) *gap_out = -1;
        if (secs_out) *secs_out = -1;
        return BUNDLE_FRESH_UNKNOWN;
    }
    long long gap = header_tip - seed_h;
    if (gap < 0) gap = 0;  /* bundle at/above our header tip — not stale */
    long long secs = gap / ZCL_BUNDLE_CATCHUP_BLOCKS_PER_SEC;
    if (gap_out) *gap_out = gap;
    if (secs_out) *secs_out = secs;
    if (secs <= ZCL_BUNDLE_FRESH_SECS)
        return BUNDLE_FRESH_OK;
    if (secs <= ZCL_BUNDLE_REMINT_SECS)
        return BUNDLE_FRESH_AGING;
    return BUNDLE_FRESH_STALE;
}

static const char *bundle_freshness_name(enum bundle_freshness f)
{
    switch (f) {
        case BUNDLE_FRESH_OK:    return "fresh";
        case BUNDLE_FRESH_AGING: return "aging";
        case BUNDLE_FRESH_STALE: return "stale";
        case BUNDLE_FRESH_UNKNOWN: break;
    }
    return "unknown";
}

bool bundle_staleness_dump_state_json(struct json_value *out,
                                      const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    const char *datadir = diag_datadir();
    json_push_kv_str(out, "datadir", datadir ? datadir : "");

    /* (1) highest utxo-seed-<h>.snapshot in the datadir. */
    char best_name[256] = {0};
    int bundle_count = 0;
    long long seed_h =
        bundle_scan_seed_height(datadir, &bundle_count, best_name,
                                sizeof(best_name));
    bool bundle_present = (seed_h >= 0);
    json_push_kv_bool(out, "bundle_present", bundle_present);
    json_push_kv_int(out, "bundle_count", bundle_count);
    json_push_kv_str(out, "bundle_name", best_name);
    json_push_kv_int(out, "bundle_seed_height", seed_h);

    /* (2) the starter pack also needs block_index.bin alongside the snapshot
     * (autodetect refuses the bundle without it), and a sibling .failed marker
     * means a prior boot quarantined the bundle (it falls back to P2P IBD). */
    bool block_index_present = false, failed_marker = false;
    if (datadir && datadir[0]) {
        char p[1200];
        int n = snprintf(p, sizeof(p), "%s/block_index.bin", datadir);
        if (n > 0 && (size_t)n < sizeof(p))
            block_index_present = (access(p, F_OK) == 0);
        if (bundle_present) {
            n = snprintf(p, sizeof(p), "%s/%s.failed", datadir, best_name);
            if (n > 0 && (size_t)n < sizeof(p))
                failed_marker = (access(p, F_OK) == 0);
        }
    }
    json_push_kv_bool(out, "block_index_present", block_index_present);
    json_push_kv_bool(out, "failed_marker", failed_marker);
    json_push_kv_bool(out, "bootable",
                      bundle_present && block_index_present && !failed_marker);

    /* (3) network tip proxy = best known PoW header height (tracks the network
     * on a connected node); the active validated tip is reported alongside. */
    long long header_tip = -1, active_tip = -1;
    struct main_state *ms = diag_main_state();
    if (ms) {
        zcl_mutex_lock(&ms->cs_main);
        if (ms->pindex_best_header)
            header_tip = (long long)ms->pindex_best_header->nHeight;
        struct block_index *at = active_chain_tip(&ms->chain_active);
        if (at)
            active_tip = (long long)at->nHeight;
        zcl_mutex_unlock(&ms->cs_main);
    }
    json_push_kv_bool(out, "has_main_state", ms != NULL);
    json_push_kv_int(out, "network_header_tip", header_tip);
    json_push_kv_int(out, "active_tip", active_tip);

    /* (4) staleness = seed→tip gap translated into estimated catch-up time. */
    json_push_kv_int(out, "catchup_blocks_per_sec",
                     ZCL_BUNDLE_CATCHUP_BLOCKS_PER_SEC);
    json_push_kv_int(out, "fresh_secs_threshold", ZCL_BUNDLE_FRESH_SECS);
    json_push_kv_int(out, "remint_secs_threshold", ZCL_BUNDLE_REMINT_SECS);

    long long gap = -1, est = -1;
    enum bundle_freshness verdict = bundle_classify(seed_h, header_tip,
                                                    &gap, &est);
    json_push_kv_int(out, "gap_blocks", gap);
    json_push_kv_int(out, "est_catchup_secs", est);
    json_push_kv_str(out, "status", bundle_freshness_name(verdict));
    json_push_kv_bool(out, "stale", verdict == BUNDLE_FRESH_STALE);
    json_push_kv_bool(out, "recommend_remint", verdict == BUNDLE_FRESH_STALE);

    char rec[320];
    if (verdict == BUNDLE_FRESH_UNKNOWN) {
        snprintf(rec, sizeof(rec), "%s",
                 !bundle_present
                     ? "no utxo-seed-<h>.snapshot in datadir; nothing to keep "
                       "fresh (fresh installs use P2P IBD)"
                     : "network header tip not known yet (still starting / no "
                       "peers); staleness undetermined");
    } else {
        const char *advice =
            verdict == BUNDLE_FRESH_OK
                ? "bundle is current"
                : (verdict == BUNDLE_FRESH_AGING
                       ? "consider re-minting a tip-fresh bundle soon"
                       : "re-mint a tip-fresh bundle now (see "
                         "tools/mint_v2_snapshot.c runbook)");
        snprintf(rec, sizeof(rec),
                 "bundle seed h=%lld is %lld blocks below header tip h=%lld "
                 "(~%llds fresh-install catch-up at %d blk/s) — %s",
                 seed_h, gap, header_tip, est,
                 ZCL_BUNDLE_CATCHUP_BLOCKS_PER_SEC, advice);
    }
    json_push_kv_str(out, "recommendation", rec);
    return true;
}
