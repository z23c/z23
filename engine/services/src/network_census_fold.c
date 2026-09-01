/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * network_census_fold — the crawler's PURE fold, in its own TU so its purity
 * is structural rather than promised: no globals, no locks, no clock, no I/O.
 * Given a census sample and our own connected-peer modal height it produces
 * the whole-network view (reachable count, version histogram, onion/clearnet
 * split, height distribution, the measured/not-probed split, and the eclipse
 * signal). Unit-tested with synthetic results — see tests/harness/src/
 * test_network_crawler.c.
 */

// one-result-type-ok:network-census-pure-fold — this TU exports exactly one
// symbol, the void, total, non-fallible fold network_census_compute(). There
// is no fallible service surface here to carry a struct zcl_result.

#include "services/network_crawler.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── pure census fold ────────────────────────────────────────────────── */

void network_census_compute(const struct ncrawl_probe_result *r, int n,
                            int64_t own_modal_height, int64_t now_unix,
                            struct network_census_view *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->ready = true;
    out->computed_at = now_unix;
    out->modal_height = -1;
    out->max_height = -1;
    out->min_height = -1;
    out->own_modal_height = own_modal_height;
    out->network_modal_height = -1;
    if (!r || n <= 0)
        return;
    if (n > NCRAWL_MAX_CENSUS)
        n = NCRAWL_MAX_CENSUS;
    out->probed = n;

    /* MEASURED vs NOT PROBED first. A not-probed row is evidence of NOTHING
     * about that node's reachability — it lands in its own bucket and is then
     * skipped by every reachability judgement below. */
    for (int i = 0; i < n; i++) {
        if (r[i].outcome == (uint8_t)NCRAWL_OUTCOME_NOT_PROBED) {
            out->not_probed_count++;
            if (r[i].is_onion)
                out->onion_not_probed_count++;
            if (!out->not_probed_reason[0] && r[i].reason[0])
                snprintf(out->not_probed_reason, sizeof(out->not_probed_reason),
                         "%s", r[i].reason);
            continue;
        }
        out->measured_count++;
        if (r[i].is_onion)
            out->onion_measured_count++;
    }

    /* version histogram + onion/clearnet split + height extremes (reachable) */
    for (int i = 0; i < n; i++) {
        if (r[i].outcome == (uint8_t)NCRAWL_OUTCOME_NOT_PROBED)
            continue;
        if (!r[i].reachable)
            continue;
        out->reachable_count++;
        if (r[i].is_onion)
            out->onion_count++;
        else
            out->clearnet_count++;

        const char *sv = r[i].subver[0] ? r[i].subver : "(unknown)";
        int found = -1;
        for (int k = 0; k < out->num_versions; k++)
            if (strcmp(out->versions[k].subver, sv) == 0) {
                found = k;
                break;
            }
        if (found >= 0) {
            out->versions[found].count++;
        } else if (out->num_versions < NCRAWL_MAX_VERSIONS) {
            struct ncrawl_version_bucket *b =
                &out->versions[out->num_versions++];
            snprintf(b->subver, sizeof(b->subver), "%s", sv);
            b->count = 1;
        }

        if (r[i].best_height >= 0) {
            out->heights_known++;
            if (out->max_height < 0 || r[i].best_height > out->max_height)
                out->max_height = r[i].best_height;
            if (out->min_height < 0 || r[i].best_height < out->min_height)
                out->min_height = r[i].best_height;
        }
    }
    if (out->max_height >= 0 && out->min_height >= 0)
        out->height_spread = out->max_height - out->min_height;

    /* modal advertised height over reachable-with-height (bounded O(n^2)) */
    int best_count = 0;
    int64_t best_h = -1;
    for (int i = 0; i < n; i++) {
        if (!r[i].reachable || r[i].best_height < 0)
            continue;
        int c = 0;
        for (int j = 0; j < n; j++)
            if (r[j].reachable && r[j].best_height == r[i].best_height)
                c++;
        if (c > best_count ||
            (c == best_count && r[i].best_height > best_h)) {
            best_count = c;
            best_h = r[i].best_height;
        }
    }
    out->modal_height = best_h;
    out->modal_height_count = best_count;
    out->network_modal_height = best_h;

    /* sort version histogram descending by count (bounded selection sort) */
    for (int i = 0; i < out->num_versions; i++)
        for (int j = i + 1; j < out->num_versions; j++)
            if (out->versions[j].count > out->versions[i].count) {
                struct ncrawl_version_bucket t = out->versions[i];
                out->versions[i] = out->versions[j];
                out->versions[j] = t;
            }

    /* whole-network eclipse signal: our connected peers cluster on a height
     * that is a small minority (<1/3) of the wider crawled network. */
    if (own_modal_height >= 0 && best_h >= 0) {
        int at_own = 0;
        for (int i = 0; i < n; i++)
            if (r[i].reachable && r[i].best_height == own_modal_height)
                at_own++;
        out->network_count_at_own_modal = at_own;
        out->eclipse_suspected =
            out->reachable_count >= NCRAWL_ECLIPSE_MIN &&
            own_modal_height != best_h &&
            (int64_t)at_own * 3 < (int64_t)out->reachable_count;
    }
}

