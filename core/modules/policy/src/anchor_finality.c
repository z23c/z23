/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * anchor_finality — implementation of the seniority gate on directory
 * influence. See policy/anchor_finality.h for the contract; the two facts
 * worth repeating at the point of code are:
 *
 *   1. FINAL is decided by height_is_immutable(), not by a local comparison.
 *      Re-deriving "10 blocks deep" here would create a second copy of the
 *      finality boundary that could drift from the reorg gate that enforces
 *      it. There is one boundary and it lives in core/modules/validation.
 *
 *   2. effective_mult is never assigned by a producer, only by
 *      derive_locked_to_tip(). That is what makes reorg withdrawal automatic
 *      rather than a step someone has to remember.
 *
 * SEAM — deliberately not wired here: nothing in this tree yet calls
 * anchor_influence_weight_for() and pushes the result into
 * addrman_publish_reputation_weights(). That wiring, and the live instance of
 * struct anchor_influence_set that would back a diagnostics dumper, belong to
 * the directory-seeding lane that owns core/modules/net/src/addrman.c and
 * engine/composition/src/boot_node_utilities.c. This module is the predicate plus the
 * withdrawal rail, complete and tested standalone; it holds no global state
 * and starts no thread, so there is nothing here to supervise.
 */

#include "policy/anchor_finality.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "json/json.h"
#include "validation/checkpoint.h"
#include "validation/main_constants.h"
#include "validation/sync_evidence_policy.h"

#include <limits.h>
#include <string.h>

void anchor_finality_evaluate(int record_height, int current_height,
                              struct anchor_finality *out)
{
    if (!out)
        return;

    out->state = ANCHOR_FINALITY_UNKNOWN;
    out->depth = 0;
    out->blocks_until_final = 0;
    out->confers_influence = false;
    out->reason = "unknown";

    if (record_height < 0) {
        out->reason = "invalid_record_height";
        return;
    }
    if (current_height < 0) {
        out->reason = "no_tip";
        return;
    }

    /* Both operands are >= 0, so the subtraction is in range for every int
     * pair that reaches here — the function is total by construction. */
    out->depth = current_height - record_height;

    if (out->depth < 0) {
        /* Mid-reorg: we hold a record from a branch above the tip we now
         * follow. It may come back, it may not. Either way it counts for
         * nothing until it is deep on THIS chain.
         *
         * ZCL_FINALITY_DEPTH - depth can exceed INT_MAX for an absurd height
         * pair, and signed overflow is undefined — which would make this
         * "total" function untrue for exactly the inputs a reorg produces.
         * Widen, then saturate. */
        int64_t need = (int64_t)ZCL_FINALITY_DEPTH - (int64_t)out->depth;
        if (need > (int64_t)INT_MAX)
            need = (int64_t)INT_MAX;
        out->state = ANCHOR_FINALITY_PROVISIONAL;
        out->blocks_until_final = (int)need;
        out->reason = "provisional_above_tip";
        return;
    }

    /* The one authority for "this height can no longer change". */
    if (height_is_immutable(current_height, record_height)) {
        out->state = ANCHOR_FINALITY_FINAL;
        out->blocks_until_final = 0;
        out->confers_influence = true;
        out->reason = "final";
        return;
    }

    out->state = ANCHOR_FINALITY_PROVISIONAL;
    out->blocks_until_final = ZCL_FINALITY_DEPTH - out->depth;
    if (out->blocks_until_final < 0)
        out->blocks_until_final = 0;
    out->reason = "provisional_shallow";
}

bool anchor_confers_influence(int record_height, int current_height)
{
    struct anchor_finality fin;
    anchor_finality_evaluate(record_height, current_height, &fin);
    return fin.confers_influence;
}

const char *anchor_finality_state_name(enum anchor_finality_state state)
{
    switch (state) {
    case ANCHOR_FINALITY_UNKNOWN:     return "unknown";
    case ANCHOR_FINALITY_PROVISIONAL: return "provisional";
    case ANCHOR_FINALITY_FINAL:       return "final";
    }
    return "unknown";
}

/* Clamp into the advisory band. There is no path to a value below 1.0, which
 * is what makes this module structurally incapable of narrowing selection. */
static double clamp_mult(double m)
{
    if (!(m >= ANCHOR_INFLUENCE_MULT_MIN))   /* also catches NaN */
        return ANCHOR_INFLUENCE_MULT_MIN;
    if (m > ANCHOR_INFLUENCE_MULT_MAX)
        return ANCHOR_INFLUENCE_MULT_MAX;
    return m;
}

/* THE withdrawal rail: the only writer of finality/effective_mult. */
static void derive_locked_to_tip(struct anchor_influence_record *rec,
                                 int tip_height)
{
    anchor_finality_evaluate(rec->height, tip_height, &rec->finality);
    rec->effective_mult = rec->finality.confers_influence
                              ? clamp_mult(rec->claimed_mult)
                              : ANCHOR_INFLUENCE_MULT_MIN;
}

static struct anchor_influence_record *
find_record(struct anchor_influence_set *set,
            const uint8_t key[ANCHOR_FINALITY_KEY_LEN])
{
    for (size_t i = 0; i < ANCHOR_INFLUENCE_MAX_RECORDS; i++) {
        if (set->records[i].used &&
            memcmp(set->records[i].key, key, ANCHOR_FINALITY_KEY_LEN) == 0)
            return &set->records[i];
    }
    return NULL;
}

void anchor_influence_set_init(struct anchor_influence_set *set)
{
    if (!set)
        return;
    memset(set, 0, sizeof(*set));
    set->tip_height = -1;
}

bool anchor_influence_set_upsert(struct anchor_influence_set *set,
                                 const uint8_t key[ANCHOR_FINALITY_KEY_LEN],
                                 int height, double claimed_mult)
{
    if (!set || !key)
        LOG_FAIL("policy", "null set or key");
    if (height < 0)
        LOG_FAIL("policy", "negative anchor height %d", height);

    struct anchor_influence_record *rec = find_record(set, key);
    if (!rec) {
        for (size_t i = 0; i < ANCHOR_INFLUENCE_MAX_RECORDS; i++) {
            if (!set->records[i].used) {
                rec = &set->records[i];
                break;
            }
        }
        if (!rec)
            LOG_FAIL("policy", "influence set full (%d records)",
                     ANCHOR_INFLUENCE_MAX_RECORDS);
        memset(rec, 0, sizeof(*rec));
        memcpy(rec->key, key, ANCHOR_FINALITY_KEY_LEN);
        rec->used = true;
        set->count++;
    }

    rec->height = height;
    rec->claimed_mult = clamp_mult(claimed_mult);
    /* Derive immediately so a fresh insert can never expose influence it has
     * not earned, even if the caller never reaches apply_tip. */
    derive_locked_to_tip(rec, set->tip_height);
    return true;
}

bool anchor_influence_set_remove(struct anchor_influence_set *set,
                                 const uint8_t key[ANCHOR_FINALITY_KEY_LEN])
{
    if (!set || !key)
        LOG_FAIL("policy", "null set or key");

    struct anchor_influence_record *rec = find_record(set, key);
    if (!rec)
        LOG_FAIL("policy", "anchor record not present");

    memset(rec, 0, sizeof(*rec));
    if (set->count > 0)
        set->count--;
    return true;
}

size_t anchor_influence_set_apply_tip(struct anchor_influence_set *set,
                                      int tip_height, size_t *withdrawn_out)
{
    if (withdrawn_out)
        *withdrawn_out = 0;
    if (!set) {
        LOG_WARN("policy", "apply_tip on null set");
        return 0;
    }

    size_t withdrawn = 0;
    size_t influencing = 0;

    set->tip_height = tip_height;

    for (size_t i = 0; i < ANCHOR_INFLUENCE_MAX_RECORDS; i++) {
        struct anchor_influence_record *rec = &set->records[i];
        if (!rec->used)
            continue;

        bool had_influence = rec->finality.confers_influence;

        /* A record anchored above the new tip is on a branch this node no
         * longer follows: the block carrying it does not exist here. Evict —
         * a stale weight outliving its own record is the failure this whole
         * module exists to prevent. `tip_height < 0` is "no tip", not "the
         * chain is empty", so it evicts nothing. */
        if (tip_height >= 0 && rec->height > tip_height) {
            memset(rec, 0, sizeof(*rec));
            if (set->count > 0)
                set->count--;
            if (had_influence)
                withdrawn++;
            continue;
        }

        derive_locked_to_tip(rec, tip_height);

        if (rec->finality.confers_influence)
            influencing++;
        else if (had_influence)
            withdrawn++;
    }

    if (withdrawn_out)
        *withdrawn_out = withdrawn;
    return influencing;
}

bool anchor_influence_lookup(const struct anchor_influence_set *set,
                             const uint8_t key[ANCHOR_FINALITY_KEY_LEN],
                             struct anchor_finality *finality_out,
                             double *mult_out)
{
    if (!set || !key)
        LOG_FAIL("policy", "null set or key");

    const struct anchor_influence_record *rec =
        find_record((struct anchor_influence_set *)set, key);
    if (!rec)
        LOG_FAIL("policy", "anchor record not present");

    if (finality_out)
        *finality_out = rec->finality;
    if (mult_out)
        *mult_out = rec->effective_mult;
    return true;
}

double anchor_influence_weight_for(const struct anchor_influence_set *set,
                                   const uint8_t key[ANCHOR_FINALITY_KEY_LEN])
{
    if (!set || !key)
        LOG_RETURN(ANCHOR_INFLUENCE_MULT_MIN, "policy", "null set or key");

    const struct anchor_influence_record *rec =
        find_record((struct anchor_influence_set *)set, key);
    /* Absent is a normal answer here, not an error: an unknown peer simply
     * gets the neutral multiplier. */
    if (!rec)
        return ANCHOR_INFLUENCE_MULT_MIN;
    return rec->effective_mult;
}

bool anchor_influence_set_dump_json(const struct anchor_influence_set *set,
                                    struct json_value *out)
{
    if (!set || !out)
        LOG_FAIL("policy", "null set or json out");

    json_set_object(out);
    json_push_kv_int(out, "tip_height", set->tip_height);
    json_push_kv_int(out, "finality_depth", zcl_finality_depth());
    json_push_kv_int(out, "immutable_height",
                     zcl_immutable_height(set->tip_height));
    json_push_kv_int(out, "record_count", (int64_t)set->count);
    json_push_kv_int(out, "capacity", ANCHOR_INFLUENCE_MAX_RECORDS);
    /* Say out loud what the depth is FOR — an operator reading this dump must
     * not read 10 as a safety claim. */
    json_push_kv_str(out, "depth_meaning",
                     "anti-flapping, not a trust threshold");
    json_push_kv_real(out, "mult_min", ANCHOR_INFLUENCE_MULT_MIN);
    json_push_kv_real(out, "mult_max", ANCHOR_INFLUENCE_MULT_MAX);

    size_t influencing = 0;
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);

    for (size_t i = 0; i < ANCHOR_INFLUENCE_MAX_RECORDS; i++) {
        const struct anchor_influence_record *rec = &set->records[i];
        if (!rec->used)
            continue;
        if (rec->finality.confers_influence)
            influencing++;

        char keyhex[ANCHOR_FINALITY_KEY_LEN * 2 + 1];
        zcl_hex_encode(rec->key, ANCHOR_FINALITY_KEY_LEN, keyhex);

        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        json_push_kv_str(&row, "key", keyhex);
        json_push_kv_int(&row, "height", rec->height);
        json_push_kv_int(&row, "depth", rec->finality.depth);
        json_push_kv_str(&row, "state",
                         anchor_finality_state_name(rec->finality.state));
        json_push_kv_str(&row, "reason", rec->finality.reason);
        json_push_kv_int(&row, "blocks_until_final",
                         rec->finality.blocks_until_final);
        json_push_kv_bool(&row, "confers_influence",
                          rec->finality.confers_influence);
        json_push_kv_real(&row, "effective_mult", rec->effective_mult);
        json_push_back(&arr, &row);
        json_free(&row);
    }

    json_push_kv_int(out, "influencing_count", (int64_t)influencing);
    json_push_kv(out, "records", &arr);
    json_free(&arr);
    return true;
}
