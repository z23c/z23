/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_anchor_finality — proves the seniority gate on directory influence:
 * a record confers nothing at depth 9 and confers influence at depth 10, the
 * boundary has no off-by-one, the predicate is total (including a record
 * height ABOVE the current tip, a real mid-reorg state), and — the case this
 * module exists for — a reorg that unwinds a final record WITHDRAWS its
 * influence instead of leaving a weight alive after its record is gone.
 *
 * Also pins ANCHOR_INFLUENCE_MULT_MAX to ADDRMAN_REPUTATION_MAX_MULT, the
 * bound of the one sanctioned influence path, so the policy module's local
 * copy cannot drift from core/modules/net's definition. */

#include "test/test_core.h"

#include "policy/anchor_finality.h"
#include "net/addrman.h"
#include "json/json.h"
#include "validation/checkpoint.h"
#include "validation/main_constants.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

/* NOTE: the bound-parity check below is a RUNTIME assertion, not a
 * static_assert. Both operands are doubles, and a floating comparison is not
 * an integer constant expression — `static_assert` on one fails the build
 * under -Wpedantic -Werror. Running it as the first case in the group is
 * equivalent for our purposes: `make test-parallel` is the gate. */

static void mk_key(uint8_t out[ANCHOR_FINALITY_KEY_LEN], uint8_t seed)
{
    for (size_t i = 0; i < ANCHOR_FINALITY_KEY_LEN; i++)
        out[i] = (uint8_t)(seed + i);
}

static int anchor_band_matches_addrman(void)
{
    int failures = 0;

    printf("anchor_finality: advisory band matches addrman's dial... ");
    {
        /* The local copy in policy/anchor_finality.h may not drift from
         * core/modules/net's ADDRMAN_REPUTATION_MAX_MULT, and the floor must stay at
         * 1.0 — anything below it would let the directory NARROW peer
         * selection instead of only widening it. */
        if (ANCHOR_INFLUENCE_MULT_MAX == ADDRMAN_REPUTATION_MAX_MULT &&
            ANCHOR_INFLUENCE_MULT_MIN == 1.0)
            printf("OK\n");
        else {
            printf("FAIL (policy max=%.3f addrman max=%.3f min=%.3f)\n",
                   ANCHOR_INFLUENCE_MULT_MAX, ADDRMAN_REPUTATION_MAX_MULT,
                   ANCHOR_INFLUENCE_MULT_MIN);
            failures++;
        }
    }
    return failures;
}

static int anchor_depth_nine_confers_nothing(void)
{
    int failures = 0;

    printf("anchor_finality: depth 9 confers NOTHING... ");
    {
        /* tip 1000, record 991 → 9 blocks built on top. */
        struct anchor_finality f;
        anchor_finality_evaluate(991, 1000, &f);
        if (!f.confers_influence &&
            f.state == ANCHOR_FINALITY_PROVISIONAL &&
            f.depth == 9 &&
            f.blocks_until_final == 1 &&
            strcmp(f.reason, "provisional_shallow") == 0 &&
            !anchor_confers_influence(991, 1000))
            printf("OK\n");
        else {
            printf("FAIL (state=%d depth=%d until=%d reason=%s)\n",
                   (int)f.state, f.depth, f.blocks_until_final, f.reason);
            failures++;
        }
    }
    return failures;
}

static int anchor_depth_ten_confers_influence(void)
{
    int failures = 0;

    printf("anchor_finality: depth 10 confers influence... ");
    {
        struct anchor_finality f;
        anchor_finality_evaluate(990, 1000, &f);
        if (f.confers_influence &&
            f.state == ANCHOR_FINALITY_FINAL &&
            f.depth == ZCL_FINALITY_DEPTH &&
            f.blocks_until_final == 0 &&
            strcmp(f.reason, "final") == 0 &&
            anchor_confers_influence(990, 1000))
            printf("OK\n");
        else {
            printf("FAIL (state=%d depth=%d until=%d reason=%s)\n",
                   (int)f.state, f.depth, f.blocks_until_final, f.reason);
            failures++;
        }
    }
    return failures;
}

static int anchor_boundary_matches_immutable(void)
{
    int failures = 0;

    printf("anchor_finality: boundary agrees with height_is_immutable "
           "at every depth 0..20... ");
    {
        int bad = 0;
        const int tip = 5000;
        for (int d = 0; d <= 20; d++) {
            int rh = tip - d;
            bool ours = anchor_confers_influence(rh, tip);
            bool theirs = height_is_immutable(tip, rh);
            if (ours != theirs) bad++;
            /* The gate must be exactly "10 or more blocks on top". */
            if (ours != (d >= ZCL_FINALITY_DEPTH)) bad++;
        }
        if (bad == 0) printf("OK\n");
        else { printf("FAIL (%d mismatches)\n", bad); failures++; }
    }
    return failures;
}

static int anchor_blocks_until_final_countdown(void)
{
    int failures = 0;

    printf("anchor_finality: blocks_until_final counts down without "
           "off-by-one... ");
    {
        int bad = 0;
        for (int d = 0; d < ZCL_FINALITY_DEPTH; d++) {
            struct anchor_finality f;
            anchor_finality_evaluate(1000 - d, 1000, &f);
            if (f.blocks_until_final != ZCL_FINALITY_DEPTH - d) bad++;
            if (f.confers_influence) bad++;
        }
        struct anchor_finality f;
        anchor_finality_evaluate(1000 - ZCL_FINALITY_DEPTH, 1000, &f);
        if (f.blocks_until_final != 0 || !f.confers_influence) bad++;
        if (bad == 0) printf("OK\n");
        else { printf("FAIL (%d bad)\n", bad); failures++; }
    }
    return failures;
}

static int anchor_record_above_tip_provisional(void)
{
    int failures = 0;

    printf("anchor_finality: record ABOVE tip is provisional, not UB... ");
    {
        struct anchor_finality f;
        anchor_finality_evaluate(1005, 1000, &f);
        if (!f.confers_influence &&
            f.state == ANCHOR_FINALITY_PROVISIONAL &&
            f.depth == -5 &&
            f.blocks_until_final == ZCL_FINALITY_DEPTH + 5 &&
            strcmp(f.reason, "provisional_above_tip") == 0)
            printf("OK\n");
        else {
            printf("FAIL (state=%d depth=%d until=%d reason=%s)\n",
                   (int)f.state, f.depth, f.blocks_until_final, f.reason);
            failures++;
        }
    }
    return failures;
}

static int anchor_extreme_heights_stay_total(void)
{
    int failures = 0;

    printf("anchor_finality: extreme heights stay total (no overflow)... ");
    {
        struct anchor_finality a, b, c;
        /* record far above tip: depth would be -INT_MAX and the countdown
         * DEPTH + INT_MAX — saturates instead of overflowing. */
        anchor_finality_evaluate(INT_MAX, 0, &a);
        anchor_finality_evaluate(0, INT_MAX, &b);
        anchor_finality_evaluate(INT_MAX, INT_MAX, &c);
        if (!a.confers_influence && a.state == ANCHOR_FINALITY_PROVISIONAL &&
            a.depth == -INT_MAX && a.blocks_until_final == INT_MAX &&
            b.confers_influence && b.state == ANCHOR_FINALITY_FINAL &&
            !c.confers_influence && c.depth == 0)
            printf("OK\n");
        else {
            printf("FAIL (a.until=%d a.depth=%d b.inf=%d c.inf=%d)\n",
                   a.blocks_until_final, a.depth,
                   (int)b.confers_influence, (int)c.confers_influence);
            failures++;
        }
    }
    return failures;
}

static int anchor_missing_tip_is_unknown(void)
{
    int failures = 0;

    printf("anchor_finality: no tip / bad record height are UNKNOWN... ");
    {
        struct anchor_finality a, b;
        anchor_finality_evaluate(100, -1, &a);
        anchor_finality_evaluate(-7, 1000, &b);
        if (a.state == ANCHOR_FINALITY_UNKNOWN &&
            strcmp(a.reason, "no_tip") == 0 && !a.confers_influence &&
            b.state == ANCHOR_FINALITY_UNKNOWN &&
            strcmp(b.reason, "invalid_record_height") == 0 &&
            !b.confers_influence &&
            strcmp(anchor_finality_state_name(ANCHOR_FINALITY_FINAL),
                   "final") == 0 &&
            strcmp(anchor_finality_state_name((enum anchor_finality_state)99),
                   "unknown") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int anchor_shallow_tip_never_confers(void)
{
    int failures = 0;

    printf("anchor_finality: shallow tip (< depth) never confers... ");
    {
        int bad = 0;
        for (int tip = 0; tip < ZCL_FINALITY_DEPTH; tip++) {
            if (anchor_confers_influence(0, tip)) bad++;
        }
        if (!anchor_confers_influence(0, ZCL_FINALITY_DEPTH - 1) &&
            anchor_confers_influence(0, ZCL_FINALITY_DEPTH) && bad == 0)
            printf("OK\n");
        else { printf("FAIL (bad=%d)\n", bad); failures++; }
    }
    return failures;
}

static int anchor_fresh_insert_leaks_nothing(void)
{
    int failures = 0;

    printf("anchor_influence: fresh insert leaks no influence... ");
    {
        struct anchor_influence_set set;
        uint8_t k[ANCHOR_FINALITY_KEY_LEN];
        mk_key(k, 1);
        anchor_influence_set_init(&set);
        /* tip is still -1 here: the record cannot possibly be final. */
        if (anchor_influence_set_upsert(&set, k, 500, 4.0) &&
            anchor_influence_weight_for(&set, k) == 1.0 &&
            set.count == 1)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int anchor_claimed_multiplier_is_clamped(void)
{
    int failures = 0;

    printf("anchor_influence: claimed multiplier is clamped into [1,4]... ");
    {
        struct anchor_influence_set set;
        uint8_t hi[ANCHOR_FINALITY_KEY_LEN], lo[ANCHOR_FINALITY_KEY_LEN];
        uint8_t neg[ANCHOR_FINALITY_KEY_LEN];
        mk_key(hi, 10); mk_key(lo, 20); mk_key(neg, 30);
        anchor_influence_set_init(&set);
        anchor_influence_set_upsert(&set, hi, 100, 1000.0);
        anchor_influence_set_upsert(&set, lo, 100, 0.25);
        anchor_influence_set_upsert(&set, neg, 100, -12.0);
        anchor_influence_set_apply_tip(&set, 200, NULL);
        double a = anchor_influence_weight_for(&set, hi);
        double b = anchor_influence_weight_for(&set, lo);
        double c = anchor_influence_weight_for(&set, neg);
        if (a == ANCHOR_INFLUENCE_MULT_MAX && b == 1.0 && c == 1.0)
            printf("OK\n");
        else { printf("FAIL (%.3f %.3f %.3f)\n", a, b, c); failures++; }
    }
    return failures;
}

static bool anchor_reorg_shallow_record_withdrew(
    const struct anchor_influence_set *set,
    const uint8_t key[ANCHOR_FINALITY_KEY_LEN],
    size_t inf, size_t w, const struct anchor_finality *f)
{
    return inf == 0 && w == 1 &&
           anchor_influence_weight_for(set, key) == 1.0 &&
           f->state == ANCHOR_FINALITY_PROVISIONAL &&
           f->depth == 5 && f->blocks_until_final == 5 &&
           set->count == 1;
}

static int anchor_reorg_shallow_demotes(void)
{
    int failures = 0;

    printf("anchor_influence: reorg to shallow DEMOTES and withdraws... ");
    {
        struct anchor_influence_set set;
        uint8_t k[ANCHOR_FINALITY_KEY_LEN];
        mk_key(k, 2);
        anchor_influence_set_init(&set);
        anchor_influence_set_upsert(&set, k, 1000, 3.0);

        size_t w = 999;
        size_t inf = anchor_influence_set_apply_tip(&set, 1010, &w);
        bool armed = (inf == 1 && w == 0 &&
                      anchor_influence_weight_for(&set, k) == 3.0);

        /* Reorg: tip falls back to 1005. The record survives (its block is
         * still on this chain) but is only 5 deep again. */
        inf = anchor_influence_set_apply_tip(&set, 1005, &w);
        struct anchor_finality f;
        anchor_influence_lookup(&set, k, &f, NULL);
        bool withdrawn = anchor_reorg_shallow_record_withdrew(
            &set, k, inf, w, &f);

        /* And it comes back when the chain grows past it again. */
        inf = anchor_influence_set_apply_tip(&set, 1020, &w);
        bool restored = (inf == 1 && w == 0 &&
                         anchor_influence_weight_for(&set, k) == 3.0);

        if (armed && withdrawn && restored) printf("OK\n");
        else {
            printf("FAIL (armed=%d withdrawn=%d restored=%d)\n",
                   (int)armed, (int)withdrawn, (int)restored);
            failures++;
        }
    }
    return failures;
}

static int anchor_reorg_below_record_evicts(void)
{
    int failures = 0;

    printf("anchor_influence: reorg BELOW the record evicts it entirely... ");
    {
        struct anchor_influence_set set;
        uint8_t gone[ANCHOR_FINALITY_KEY_LEN], stay[ANCHOR_FINALITY_KEY_LEN];
        mk_key(gone, 3); mk_key(stay, 4);
        anchor_influence_set_init(&set);
        anchor_influence_set_upsert(&set, gone, 1000, 4.0);
        anchor_influence_set_upsert(&set, stay, 800, 2.0);

        size_t w = 0;
        size_t inf = anchor_influence_set_apply_tip(&set, 1010, &w);
        bool both_final = (inf == 2 && w == 0);

        /* Deep reorg: the tip is now BELOW the anchoring block of `gone`.
         * That block does not exist on the chain we follow. */
        inf = anchor_influence_set_apply_tip(&set, 950, &w);
        bool evicted = (inf == 1 && w == 1 && set.count == 1 &&
                        anchor_influence_weight_for(&set, gone) == 1.0 &&
                        !anchor_influence_lookup(&set, gone, NULL, NULL) &&
                        anchor_influence_weight_for(&set, stay) == 2.0);

        if (both_final && evicted) printf("OK\n");
        else {
            printf("FAIL (both_final=%d evicted=%d count=%zu)\n",
                   (int)both_final, (int)evicted, set.count);
            failures++;
        }
    }
    return failures;
}

static int anchor_lost_tip_withdraws_all(void)
{
    int failures = 0;

    printf("anchor_influence: losing the tip withdraws everything, "
           "evicts nothing... ");
    {
        struct anchor_influence_set set;
        uint8_t k[ANCHOR_FINALITY_KEY_LEN];
        mk_key(k, 5);
        anchor_influence_set_init(&set);
        anchor_influence_set_upsert(&set, k, 100, 4.0);
        anchor_influence_set_apply_tip(&set, 500, NULL);

        size_t w = 0;
        size_t inf = anchor_influence_set_apply_tip(&set, -1, &w);
        struct anchor_finality f;
        anchor_influence_lookup(&set, k, &f, NULL);
        if (inf == 0 && w == 1 && set.count == 1 &&
            f.state == ANCHOR_FINALITY_UNKNOWN &&
            strcmp(f.reason, "no_tip") == 0 &&
            anchor_influence_weight_for(&set, k) == 1.0)
            printf("OK\n");
        else { printf("FAIL (inf=%zu w=%zu)\n", inf, w); failures++; }
    }
    return failures;
}

static int anchor_explicit_remove_and_absent(void)
{
    int failures = 0;

    printf("anchor_influence: explicit remove and absent lookups... ");
    {
        struct anchor_influence_set set;
        uint8_t k[ANCHOR_FINALITY_KEY_LEN], absent[ANCHOR_FINALITY_KEY_LEN];
        mk_key(k, 6); mk_key(absent, 7);
        anchor_influence_set_init(&set);
        anchor_influence_set_upsert(&set, k, 10, 4.0);
        anchor_influence_set_apply_tip(&set, 100, NULL);
        bool had = anchor_influence_weight_for(&set, k) == 4.0;
        bool removed = anchor_influence_set_remove(&set, k);
        if (had && removed && set.count == 0 &&
            anchor_influence_weight_for(&set, k) == 1.0 &&
            anchor_influence_weight_for(&set, absent) == 1.0 &&
            !anchor_influence_set_remove(&set, k) &&
            !anchor_influence_lookup(&set, absent, NULL, NULL))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int anchor_capacity_bounded_idempotent(void)
{
    int failures = 0;

    printf("anchor_influence: capacity is bounded and upsert is idempotent... ");
    {
        static struct anchor_influence_set set;
        anchor_influence_set_init(&set);
        int inserted = 0;
        for (int i = 0; i < ANCHOR_INFLUENCE_MAX_RECORDS; i++) {
            uint8_t k[ANCHOR_FINALITY_KEY_LEN];
            memset(k, 0, sizeof k);
            k[0] = (uint8_t)(i & 0xff);
            k[1] = (uint8_t)((i >> 8) & 0xff);
            if (anchor_influence_set_upsert(&set, k, 100 + i, 2.0))
                inserted++;
        }
        uint8_t overflow_key[ANCHOR_FINALITY_KEY_LEN];
        memset(overflow_key, 0xee, sizeof overflow_key);
        bool refused = !anchor_influence_set_upsert(&set, overflow_key, 1, 2.0);

        /* Re-upserting an existing key must UPDATE, not consume a slot. */
        uint8_t first[ANCHOR_FINALITY_KEY_LEN];
        memset(first, 0, sizeof first);
        bool reupsert = anchor_influence_set_upsert(&set, first, 42, 3.5);

        if (inserted == ANCHOR_INFLUENCE_MAX_RECORDS && refused && reupsert &&
            set.count == (size_t)ANCHOR_INFLUENCE_MAX_RECORDS)
            printf("OK\n");
        else {
            printf("FAIL (inserted=%d refused=%d count=%zu)\n",
                   inserted, (int)refused, set.count);
            failures++;
        }
    }
    return failures;
}

static int anchor_negative_and_null_refused(void)
{
    int failures = 0;

    printf("anchor_influence: negative height and NULL args are refused... ");
    {
        struct anchor_influence_set set;
        uint8_t k[ANCHOR_FINALITY_KEY_LEN];
        mk_key(k, 8);
        anchor_influence_set_init(&set);
        if (!anchor_influence_set_upsert(&set, k, -1, 2.0) &&
            !anchor_influence_set_upsert(NULL, k, 5, 2.0) &&
            !anchor_influence_set_upsert(&set, NULL, 5, 2.0) &&
            !anchor_influence_set_remove(NULL, k) &&
            !anchor_influence_lookup(NULL, k, NULL, NULL) &&
            anchor_influence_weight_for(NULL, k) == 1.0 &&
            anchor_influence_set_apply_tip(NULL, 10, NULL) == 0 &&
            set.count == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int anchor_weight_never_below_floor(void)
{
    int failures = 0;

    printf("anchor_influence: no reachable weight is ever below 1.0... ");
    {
        struct anchor_influence_set set;
        int bad = 0;
        anchor_influence_set_init(&set);
        for (int i = 0; i < 16; i++) {
            uint8_t k[ANCHOR_FINALITY_KEY_LEN];
            mk_key(k, (uint8_t)(100 + i));
            anchor_influence_set_upsert(&set, k, 1000 + i * 7,
                                        (double)i - 4.0);
        }
        for (int tip = -3; tip < 1200; tip += 13) {
            anchor_influence_set_apply_tip(&set, tip, NULL);
            for (int i = 0; i < 16; i++) {
                uint8_t k[ANCHOR_FINALITY_KEY_LEN];
                mk_key(k, (uint8_t)(100 + i));
                double w = anchor_influence_weight_for(&set, k);
                if (w < ANCHOR_INFLUENCE_MULT_MIN ||
                    w > ANCHOR_INFLUENCE_MULT_MAX)
                    bad++;
            }
        }
        if (bad == 0) printf("OK\n");
        else { printf("FAIL (%d out-of-band weights)\n", bad); failures++; }
    }
    return failures;
}

static void anchor_dump_note_record_row(const struct json_value *row,
                                        int *seen_prov, int *seen_final)
{
    const struct json_value *st = json_get(row, "state");
    const struct json_value *rs = json_get(row, "reason");
    const char *s = st ? json_get_str(st) : NULL;
    const char *r = rs ? json_get_str(rs) : NULL;
    if (s && r && strcmp(s, "provisional") == 0 &&
        strcmp(r, "provisional_shallow") == 0)
        (*seen_prov)++;
    if (s && r && strcmp(s, "final") == 0 &&
        strcmp(r, "final") == 0)
        (*seen_final)++;
}

static int anchor_dump_reports_provisional_vs_final(void)
{
    int failures = 0;

    printf("anchor_influence: dump reports provisional vs final... ");
    {
        struct anchor_influence_set set;
        uint8_t prov[ANCHOR_FINALITY_KEY_LEN], fin[ANCHOR_FINALITY_KEY_LEN];
        mk_key(prov, 40); mk_key(fin, 50);
        anchor_influence_set_init(&set);
        anchor_influence_set_upsert(&set, prov, 998, 4.0);
        anchor_influence_set_upsert(&set, fin, 900, 4.0);
        anchor_influence_set_apply_tip(&set, 1000, NULL);

        struct json_value out;
        json_init(&out);
        bool ok = anchor_influence_set_dump_json(&set, &out);

        const struct json_value *rows = json_get(&out, "records");
        int seen_prov = 0, seen_final = 0;
        for (size_t i = 0; rows && i < json_size(rows); i++)
            anchor_dump_note_record_row(json_at(rows, i),
                                        &seen_prov, &seen_final);
        const struct json_value *ic = json_get(&out, "influencing_count");
        const struct json_value *th = json_get(&out, "tip_height");
        bool counts = ic && json_get_int(ic) == 1 &&
                      th && json_get_int(th) == 1000;
        json_free(&out);

        if (ok && seen_prov == 1 && seen_final == 1 && counts &&
            !anchor_influence_set_dump_json(&set, NULL))
            printf("OK\n");
        else {
            printf("FAIL (prov=%d final=%d counts=%d)\n",
                   seen_prov, seen_final, (int)counts);
            failures++;
        }
    }
    return failures;
}

static int anchor_report(const char *name, bool ok)
{
    printf("%s... ", name);
    if (ok) { printf("OK\n"); return 0; }
    printf("FAIL\n");
    return 1;
}

/* UNKNOWN keeps zeroed depth and countdown; a record AT the tip is shallow, not above it. */
static int anchor_unknown_zeroed_and_tip_edge(void)
{
    struct anchor_finality a, b, c;
    anchor_finality_evaluate(100, -1, &a);
    anchor_finality_evaluate(-7, 1000, &b);
    anchor_finality_evaluate(1000, 1000, &c);
    bool ok = a.depth == 0 && a.blocks_until_final == 0 &&
              b.depth == 0 && b.blocks_until_final == 0 &&
              c.state == ANCHOR_FINALITY_PROVISIONAL && c.depth == 0 &&
              c.blocks_until_final == ZCL_FINALITY_DEPTH &&
              strcmp(c.reason, "provisional_shallow") == 0 &&
              strcmp(anchor_finality_state_name(ANCHOR_FINALITY_UNKNOWN),
                     "unknown") == 0 &&
              strcmp(anchor_finality_state_name(ANCHOR_FINALITY_PROVISIONAL),
                     "provisional") == 0;
    return anchor_report("anchor_finality: unknown is zeroed; record at tip is shallow", ok);
}

/* A fresh set has no tip, accepts height 0, and reports it as having no tip. */
static int anchor_init_tip_and_zero_height(void)
{
    struct anchor_influence_set set;
    uint8_t k[ANCHOR_FINALITY_KEY_LEN];
    mk_key(k, 9);
    anchor_influence_set_init(&set);
    bool ok = set.tip_height == -1 && set.count == 0;
    ok = ok && anchor_influence_set_upsert(&set, k, 0, 2.0);
    struct anchor_finality f;
    double m = 0;
    ok = ok && anchor_influence_lookup(&set, k, &f, &m) &&
         f.state == ANCHOR_FINALITY_UNKNOWN &&
         strcmp(f.reason, "no_tip") == 0 && m == 1.0;
    return anchor_report("anchor_influence: init has no tip; height 0 is accepted", ok);
}

/* apply_tip: null set clears the out-count, tip 0 evicts, a record at the tip stays. */
static int anchor_apply_tip_edges(void)
{
    struct anchor_influence_set set;
    uint8_t k[ANCHOR_FINALITY_KEY_LEN], k2[ANCHOR_FINALITY_KEY_LEN];
    mk_key(k, 11); mk_key(k2, 12);
    size_t w = 77;
    bool ok = anchor_influence_set_apply_tip(NULL, 5, &w) == 0 && w == 0;

    anchor_influence_set_init(&set);
    anchor_influence_set_upsert(&set, k, 5, 4.0);
    w = 77;
    ok = ok && anchor_influence_set_apply_tip(&set, 0, &w) == 0 && w == 0;
    struct anchor_influence_record zero;
    memset(&zero, 0, sizeof(zero));
    ok = ok && set.count == 0 && memcmp(&set.records[0], &zero, sizeof(zero)) == 0;

    anchor_influence_set_upsert(&set, k2, 100, 4.0);
    anchor_influence_set_apply_tip(&set, 100, NULL);
    struct anchor_finality f;
    ok = ok && set.count == 1 && anchor_influence_lookup(&set, k2, &f, NULL) &&
         f.state == ANCHOR_FINALITY_PROVISIONAL && f.depth == 0;
    return anchor_report("anchor_influence: apply_tip edges (null, tip 0, record at tip)", ok);
}

/* remove clears the whole slot (no stale used flag) and frees it for reuse. */
static int anchor_remove_clears_slot(void)
{
    struct anchor_influence_set set;
    uint8_t k[ANCHOR_FINALITY_KEY_LEN];
    mk_key(k, 13);
    anchor_influence_set_init(&set);
    anchor_influence_set_upsert(&set, k, 50, 3.0);
    bool ok = anchor_influence_set_remove(&set, k);
    struct anchor_influence_record zero;
    memset(&zero, 0, sizeof(zero));
    ok = ok && memcmp(&set.records[0], &zero, sizeof(zero)) == 0 &&
         set.records[0].used == false;
    return anchor_report("anchor_influence: remove zeroes the slot", ok);
}

/* A full set must not read a record past its last slot when the key is absent. */
static int anchor_full_set_lookup_stops_at_capacity(void)
{
    struct {
        struct anchor_influence_set set;
        struct anchor_influence_record beyond; /* the byte range after records[255] */
    } w;
    memset(&w, 0, sizeof(w));
    anchor_influence_set_init(&w.set);
    uint8_t k[ANCHOR_FINALITY_KEY_LEN], other[ANCHOR_FINALITY_KEY_LEN];
    bool ok = true;
    for (int i = 0; i < ANCHOR_INFLUENCE_MAX_RECORDS; i++) {
        mk_key(other, (uint8_t)i);
        ok = ok && anchor_influence_set_upsert(&w.set, other, 1, 2.0);
    }
    memset(k, 0xEE, sizeof(k));
    w.beyond.used = true;
    memcpy(w.beyond.key, k, sizeof(k));
    w.beyond.effective_mult = 3.0;
    ok = ok && anchor_influence_weight_for(&w.set, k) == 1.0 &&
         !anchor_influence_lookup(&w.set, k, NULL, NULL) &&
         !anchor_influence_set_remove(&w.set, k) &&
         !anchor_influence_set_upsert(&w.set, k, 1, 2.0);
    mk_key(other, 7);
    ok = ok && anchor_influence_set_remove(&w.set, other) &&
         anchor_influence_set_upsert(&w.set, k, 1, 2.0);
    return anchor_report("anchor_influence: full-set lookup stops at capacity", ok);
}

static bool anchor_dump_int_is(const struct json_value *o, const char *k, int64_t want)
{
    const struct json_value *v = json_get(o, k);
    return v && json_get_int(v) == want;
}

static bool anchor_dump_real_is(const struct json_value *o, const char *k, double want)
{
    const struct json_value *v = json_get(o, k);
    return v && json_get_real(v) == want;
}

static bool anchor_dump_row_is(const struct json_value *row, const char *hex,
                               int height, int depth, int until, bool conf,
                               double mult)
{
    const struct json_value *key = json_get(row, "key");
    const struct json_value *cf = json_get(row, "confers_influence");
    return key && json_get_str(key) && strcmp(json_get_str(key), hex) == 0 &&
           anchor_dump_int_is(row, "height", height) &&
           anchor_dump_int_is(row, "depth", depth) &&
           anchor_dump_int_is(row, "blocks_until_final", until) &&
           cf && json_get_bool(cf) == conf &&
           anchor_dump_real_is(row, "effective_mult", mult);
}

static void anchor_key_hex(const uint8_t key[ANCHOR_FINALITY_KEY_LEN], char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < ANCHOR_FINALITY_KEY_LEN; i++) {
        out[2 * i] = digits[key[i] >> 4];
        out[2 * i + 1] = digits[key[i] & 15];
    }
    out[2 * ANCHOR_FINALITY_KEY_LEN] = '\0';
}

static bool anchor_dump_header_ok(const struct json_value *out)
{
    const struct json_value *dm = json_get(out, "depth_meaning");
    return anchor_dump_int_is(out, "tip_height", 1000) &&
           anchor_dump_int_is(out, "finality_depth", ZCL_FINALITY_DEPTH) &&
           anchor_dump_int_is(out, "immutable_height", 1000 - ZCL_FINALITY_DEPTH) &&
           anchor_dump_int_is(out, "record_count", 2) &&
           anchor_dump_int_is(out, "capacity", ANCHOR_INFLUENCE_MAX_RECORDS) &&
           anchor_dump_int_is(out, "influencing_count", 1) &&
           anchor_dump_real_is(out, "mult_min", 1.0) &&
           anchor_dump_real_is(out, "mult_max", 4.0) &&
           dm && json_get_str(dm) &&
           strcmp(json_get_str(dm), "anti-flapping, not a trust threshold") == 0;
}

/* Every dump header field and every per-record field carries its real value. */
static int anchor_dump_every_field(void)
{
    struct anchor_influence_set set;
    uint8_t prov[ANCHOR_FINALITY_KEY_LEN], fin[ANCHOR_FINALITY_KEY_LEN];
    char hp[ANCHOR_FINALITY_KEY_LEN * 2 + 1], hf[ANCHOR_FINALITY_KEY_LEN * 2 + 1];
    mk_key(prov, 40); mk_key(fin, 50);
    anchor_key_hex(prov, hp); anchor_key_hex(fin, hf);
    anchor_influence_set_init(&set);
    anchor_influence_set_upsert(&set, prov, 998, 4.0);
    anchor_influence_set_upsert(&set, fin, 900, 3.0);
    anchor_influence_set_apply_tip(&set, 1000, NULL);

    struct json_value out;
    json_init(&out);
    bool ok = anchor_influence_set_dump_json(&set, &out) &&
              anchor_dump_header_ok(&out);
    const struct json_value *rows = json_get(&out, "records");
    ok = ok && rows && json_size(rows) == 2 &&
         anchor_dump_row_is(json_at(rows, 0), hp, 998, 2, ZCL_FINALITY_DEPTH - 2,
                            false, 1.0) &&
         anchor_dump_row_is(json_at(rows, 1), hf, 900, 100, 0, true, 3.0);
    json_free(&out);

    struct anchor_finality f;
    double m = 0;
    ok = ok && anchor_influence_lookup(&set, fin, &f, &m) &&
         f.state == ANCHOR_FINALITY_FINAL && m == 3.0;
    return anchor_report("anchor_influence: dump carries every field", ok);
}

int test_anchor_finality(void)
{
    int failures = 0;

    failures += anchor_band_matches_addrman();
    failures += anchor_depth_nine_confers_nothing();
    failures += anchor_depth_ten_confers_influence();
    failures += anchor_boundary_matches_immutable();
    failures += anchor_blocks_until_final_countdown();
    failures += anchor_record_above_tip_provisional();
    failures += anchor_extreme_heights_stay_total();
    failures += anchor_missing_tip_is_unknown();
    failures += anchor_shallow_tip_never_confers();
    failures += anchor_fresh_insert_leaks_nothing();
    failures += anchor_claimed_multiplier_is_clamped();
    failures += anchor_reorg_shallow_demotes();
    failures += anchor_reorg_below_record_evicts();
    failures += anchor_lost_tip_withdraws_all();
    failures += anchor_explicit_remove_and_absent();
    failures += anchor_capacity_bounded_idempotent();
    failures += anchor_negative_and_null_refused();
    failures += anchor_weight_never_below_floor();
    failures += anchor_dump_reports_provisional_vs_final();
    failures += anchor_unknown_zeroed_and_tip_edge();
    failures += anchor_init_tip_and_zero_height();
    failures += anchor_apply_tip_edges();
    failures += anchor_remove_clears_slot();
    failures += anchor_full_set_lookup_stops_at_capacity();
    failures += anchor_dump_every_field();
    return failures;
}
