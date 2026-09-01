/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zid_seniority — the arithmetic behind "influence comes from having been
 * anchored a long time, under one owner". The doctrine, the policy block,
 * and the reason every piece of the shape exists live in
 * zid/zid_seniority.h; this file is only the implementation.
 *
 * Determinism note: the seniority curve and the owner cap are exact
 * rational arithmetic and are bit-identical everywhere. The final
 * multiplier calls pow(), whose last bit is not guaranteed identical across
 * libm versions. That is fine and deliberate — this is an advisory dial
 * preference, not a consensus predicate. Nothing here is ever compared for
 * equality across hosts, and a one-ULP difference changes at worst which of
 * two near-equal peers a single client dials first. */

#include "zid/zid_seniority.h"
#include "base/log_macros.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/* 2^64 as a double, for mapping a uniform 64-bit draw onto (0, 1]. */
#define ZID_SENIORITY_DRAW_SPAN 18446744073709551616.0

static bool owner_is_unknown(const uint8_t owner_id[32])
{
    for (size_t i = 0; i < 32; i++)
        if (owner_id[i])
            return false;
    return true;
}

double zid_seniority_score(int32_t registration_height, int32_t tip_height)
{
    /* Not anchored, or anchored in a future this node has not reached: no
     * evidence of age, therefore no weight. Never negative. */
    if (registration_height < 0 || tip_height < 0 ||
        registration_height > tip_height)
        return 0.0;

    int64_t age = (int64_t)tip_height - (int64_t)registration_height;

    /* THE ANTI-SYBIL FLOOR. Below it the answer is exactly zero, not a
     * small number — so N fresh registrations sum to exactly zero rather
     * than to N times a small number. */
    if (age <= (int64_t)ZID_SENIORITY_MIN_AGE_BLOCKS)
        return 0.0;

    double eff = (double)(age - (int64_t)ZID_SENIORITY_MIN_AGE_BLOCKS);
    /* Saturating: 0.5 at HALF_LIFE past the floor, asymptote 1.0. Always
     * rising, always with diminishing returns, never reaching 1.0 — so no
     * relay can ever be maximally senior and run away with the network. */
    return eff / (eff + (double)ZID_SENIORITY_HALF_LIFE_BLOCKS);
}

int32_t zid_seniority_epoch_height(int32_t tip_height)
{
    if (tip_height <= 0)
        return 0;
    return tip_height - (tip_height % (int32_t)ZID_SENIORITY_EPOCH_BLOCKS);
}

double zid_seniority_combine(double a, double b)
{
    const double span = ZID_SENIORITY_MAX_MULT - 1.0;

    /* Clamp rather than reject: a bad input must degrade to "no opinion",
     * never to an exclusion. isnan() folds to the baseline for the same
     * reason (a NaN comparison is false, so the clamps below would let it
     * through untouched). */
    if (isnan(a) || a < 1.0) a = 1.0;
    if (isnan(b) || b < 1.0) b = 1.0;
    if (a > ZID_SENIORITY_MAX_MULT) a = ZID_SENIORITY_MAX_MULT;
    if (b > ZID_SENIORITY_MAX_MULT) b = ZID_SENIORITY_MAX_MULT;

    double fa = (a - 1.0) / span;
    double fb = (b - 1.0) / span;
    double f = 1.0 - (1.0 - fa) * (1.0 - fb);

    double out = 1.0 + span * f;
    if (out < 1.0) out = 1.0;
    if (out > ZID_SENIORITY_MAX_MULT) out = ZID_SENIORITY_MAX_MULT;
    return out;
}

/* Total order used to decide which of an owner's relays keeps the most
 * mass: most senior first, then relay_id ascending, then input index. The
 * index tiebreak makes the order TOTAL even when the caller passes the same
 * relay twice — duplicates then land in successive owner ranks and decay,
 * which is exactly the Sybil behaviour we want, rather than both taking
 * rank 0. Returns true iff `a` outranks `b`. */
static bool outranks(double sen_a, const uint8_t id_a[32], size_t idx_a,
                     double sen_b, const uint8_t id_b[32], size_t idx_b)
{
    if (sen_a != sen_b)
        return sen_a > sen_b;
    int c = memcmp(id_a, id_b, 32);
    if (c != 0)
        return c < 0;
    return idx_a < idx_b;
}

static int cmp_by_relay_id(const void *va, const void *vb)
{
    const struct zid_seniority_weight *a = va;
    const struct zid_seniority_weight *b = vb;
    return memcmp(a->relay_id, b->relay_id, 32);
}

int zid_seniority_rank(const struct zid_relay_registration *relays, size_t n,
                       int32_t tip_height,
                       zid_seniority_draw_fn draw, void *draw_ctx,
                       struct zid_seniority_weight *out, size_t out_cap)
{
    if (n == 0)
        return 0;
    if (!relays)
        LOG_ERR("zid_seniority", "rank: NULL relay set (n=%zu)", n);
    if (!out)
        LOG_ERR("zid_seniority", "rank: NULL output table (n=%zu)", n);
    if (!draw)
        LOG_ERR("zid_seniority",
                "rank: NULL per-client draw — a global ranking is not an "
                "acceptable fallback (n=%zu)", n);
    if (n > (size_t)ZID_SENIORITY_MAX_RELAYS)
        LOG_ERR("zid_seniority", "rank: %zu relays exceeds the %d quota",
                n, ZID_SENIORITY_MAX_RELAYS);
    if (out_cap < n)
        LOG_ERR("zid_seniority", "rank: out_cap=%zu < n=%zu", out_cap, n);

    /* Pass 1 — raw seniority, in input order. */
    for (size_t i = 0; i < n; i++) {
        memset(&out[i], 0, sizeof(out[i]));
        memcpy(out[i].relay_id, relays[i].relay_id, 32);
        out[i].seniority =
            zid_seniority_score(relays[i].registration_height, tip_height);
        out[i].multiplier = 1.0;
    }

    /* Pass 2 — the per-owner cap, still in input order.
     *
     * owner_rank is counted directly rather than by sorting into owner
     * groups: this module allocates nothing, and a sort would need scratch
     * to carry owner_id (which is an input field, not an output one). The
     * inner loop stops the moment the rank reaches the quota, because
     * everything at or past the quota gets the same answer — zero mass —
     * so counting further would change nothing. n is bounded by
     * ZID_SENIORITY_MAX_RELAYS and this runs once per ranking epoch. */
    for (size_t i = 0; i < n; i++) {
        int32_t rank = 0;

        /* An unknown owner is its own owner. Pooling unknowns would let one
         * actor evade the cap simply by withholding the owner field — the
         * cheapest possible bypass — so they are never merged. */
        if (!owner_is_unknown(relays[i].owner_id)) {
            for (size_t j = 0; j < n && rank < ZID_SENIORITY_MAX_RELAYS_PER_OWNER;
                 j++) {
                if (j == i)
                    continue;
                if (memcmp(relays[j].owner_id, relays[i].owner_id, 32) != 0)
                    continue;
                if (outranks(out[j].seniority, out[j].relay_id, j,
                             out[i].seniority, out[i].relay_id, i))
                    rank++;
            }
        }

        out[i].owner_rank = rank;
        out[i].over_owner_quota = rank >= ZID_SENIORITY_MAX_RELAYS_PER_OWNER;

        double mass = out[i].seniority;
        if (out[i].over_owner_quota) {
            mass = 0.0;
        } else {
            /* decay^rank by repeated multiply — rank is at most 3, and a
             * loop keeps this exact instead of going through pow(). */
            for (int32_t k = 0; k < rank; k++)
                mass *= ZID_SENIORITY_OWNER_DECAY;
        }
        out[i].mass = mass;
    }

    /* Pass 3 — the per-client draw. THIS is what stops the table from
     * being a global answer: mass says how much lottery weight a relay
     * holds, the client's own draw says where that relay lands for THIS
     * client. */
    for (size_t i = 0; i < n; i++) {
        double w = out[i].mass * ZID_SENIORITY_MASS_SCALE;
        if (!(w > 0.0))
            continue;               /* fresh / over quota: baseline 1.0 */

        uint64_t d = 0;
        if (!draw(draw_ctx, out[i].relay_id, &d))
            continue;               /* no draw: baseline 1.0, never excluded */

        /* Uniform in (0, 1] — the +1 keeps u away from exactly 0, where
         * pow() would be a zero raised to a positive power rather than a
         * legitimate smallest draw. */
        double u = ((double)d + 1.0) / ZID_SENIORITY_DRAW_SPAN;

        /* Efraimidis-Spirakis weighted-sampling key. Larger w pushes the
         * key toward 1; w near 0 collapses it to 0. Per-client because u
         * is, globally proportional to w because the key is. */
        double key = pow(u, 1.0 / w);
        if (isnan(key) || key < 0.0) key = 0.0;
        if (key > 1.0) key = 1.0;

        double mult = 1.0 + (ZID_SENIORITY_MAX_MULT - 1.0) * key;
        if (mult < 1.0) mult = 1.0;
        if (mult > ZID_SENIORITY_MAX_MULT) mult = ZID_SENIORITY_MAX_MULT;
        out[i].multiplier = mult;
    }

    /* Canonical output order, so the table is comparable between clients
     * and binary-searchable by zid_seniority_find(). */
    qsort(out, n, sizeof(out[0]), cmp_by_relay_id);
    return (int)n;
}

const struct zid_seniority_weight *
zid_seniority_find(const struct zid_seniority_weight *table, size_t n,
                   const uint8_t relay_id[32])
{
    if (!table || n == 0 || !relay_id)
        return NULL;

    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(table[mid].relay_id, relay_id, 32);
        if (c == 0)
            return &table[mid];
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return NULL;
}
