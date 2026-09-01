/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * property_work — pure implementation. See metaverse/property_work.h for
 * the contract; the two rules this file enforces mechanically are:
 *
 *   1. A non-proof-of-work kind never receives a number. The applicability
 *      check happens BEFORE the arguments are looked at, so a caller that
 *      hands a tip height to a content-addressed or locally-declared kind
 *      cannot mint a freshness claim by accident.
 *   2. Unknown never renders as zero. Each number carries its own has_
 *      flag, and the JSON puts -1 / "" in the slot when the flag is false. */

#include "metaverse/property_work.h"

#include "json/json.h"

#include <string.h>

const char *metaverse_work_gap_name(enum metaverse_work_gap gap)
{
    switch (gap) {
    case METAVERSE_WORK_GAP_NONE:           return "none";
    case METAVERSE_WORK_GAP_NOT_APPLICABLE: return "not_applicable";
    case METAVERSE_WORK_GAP_NO_ANCHOR:      return "no_anchor";
    case METAVERSE_WORK_GAP_NO_TIP:         return "no_tip";
    case METAVERSE_WORK_GAP_ANCHOR_ABOVE_TIP:
        return "anchor_above_tip";
    }
    return "unknown";
}

const char *metaverse_work_gap_reason(enum metaverse_work_gap gap)
{
    switch (gap) {
    case METAVERSE_WORK_GAP_NONE:
        return "";
    case METAVERSE_WORK_GAP_NOT_APPLICABLE:
        return "this kind is not settled by proof of work, so it has no "
               "depth and no chainwork — that is a different answer from "
               "zero of either";
    case METAVERSE_WORK_GAP_NO_ANCHOR:
        return "this kind is settled by proof of work, but no anchor height "
               "was established for this record, so nothing can be measured "
               "from it";
    case METAVERSE_WORK_GAP_NO_TIP:
        return "this kind is settled by proof of work and the record is "
               "anchored, but no chain tip was supplied to measure against";
    case METAVERSE_WORK_GAP_ANCHOR_ABOVE_TIP:
        return "the record's anchor height is above the chain tip given, so "
               "this tip does not contain it — no depth is reported rather "
               "than a clamped zero";
    }
    return "the reason this measurement is absent was not recorded";
}

void metaverse_work_none(struct metaverse_work_proof *out,
                         enum metaverse_settlement settlement)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->settlement = settlement;
    out->applicable = metaverse_settlement_work_measurable(settlement);
    out->gap = out->applicable ? METAVERSE_WORK_GAP_NO_ANCHOR
                               : METAVERSE_WORK_GAP_NOT_APPLICABLE;
    out->anchor_height  = -1;
    out->tip_height     = -1;
    out->depth          = -1;
    out->chainwork_hex[0] = '\0';
}

bool metaverse_work_measure(enum metaverse_kind kind, int64_t anchor_height,
                            const struct arith_uint256 *anchor_work,
                            int64_t tip_height,
                            const struct arith_uint256 *tip_work,
                            struct metaverse_work_proof *out)
{
    enum metaverse_settlement settlement;

    if (!out)
        return false;
    settlement = metaverse_kind_settlement(kind);
    metaverse_work_none(out, settlement);
    /* Rule 1: applicability is decided before any argument is read. */
    if (!out->applicable)
        return false;

    if (anchor_height < 0)
        return false;               /* gap stays NO_ANCHOR */
    out->has_anchor_height = true;
    out->anchor_height     = anchor_height;

    if (tip_height < 0) {
        out->gap = METAVERSE_WORK_GAP_NO_TIP;
        return false;
    }
    out->has_tip_height = true;
    out->tip_height     = tip_height;

    /* An anchor above the tip is a contradiction (a record from a chain
     * this tip does not contain, or a stale tip). Report it as an
     * unmeasured anchor rather than as a negative depth that a consumer
     * might clamp to zero and read as "just confirmed". */
    if (anchor_height > tip_height) {
        out->gap = METAVERSE_WORK_GAP_ANCHOR_ABOVE_TIP;
        return false;
    }
    out->has_depth = true;
    out->depth     = tip_height - anchor_height;
    out->gap       = METAVERSE_WORK_GAP_NONE;

    /* Chainwork is optional on top of depth: the depth answer stands even
     * when the caller could not supply both block-index entries. Both
     * values come straight from the block index's nChainWork; nothing here
     * recomputes work from difficulty. */
    if (anchor_work && tip_work &&
        arith_uint256_compare(tip_work, anchor_work) >= 0) {
        struct arith_uint256 delta;

        arith_uint256_sub(&delta, tip_work, anchor_work);
        arith_uint256_get_hex(&delta, out->chainwork_hex);
        out->has_chainwork = true;
    }
    return true;
}

bool metaverse_work_to_json(const struct metaverse_work_proof *work,
                            struct json_value *out)
{
    if (!work || !out)
        return false;
    json_set_object(out);

    (void)json_push_kv_str(out, "settlement",
                           metaverse_settlement_name(work->settlement));
    (void)json_push_kv_bool(out, "measurable", work->applicable);
    (void)json_push_kv_str(out, "gap", metaverse_work_gap_name(work->gap));
    (void)json_push_kv_str(out, "gap_reason",
                           metaverse_work_gap_reason(work->gap));

    /* -1, never 0, in every unknown slot: see the header's second rule. */
    (void)json_push_kv_bool(out, "has_anchor_height", work->has_anchor_height);
    (void)json_push_kv_int(out, "anchor_height",
                           work->has_anchor_height ? work->anchor_height : -1);
    (void)json_push_kv_bool(out, "has_tip_height", work->has_tip_height);
    (void)json_push_kv_int(out, "tip_height",
                           work->has_tip_height ? work->tip_height : -1);
    (void)json_push_kv_bool(out, "has_confirmation_depth", work->has_depth);
    (void)json_push_kv_int(out, "confirmation_depth",
                           work->has_depth ? work->depth : -1);
    (void)json_push_kv_bool(out, "has_chainwork", work->has_chainwork);
    (void)json_push_kv_str(out, "chainwork_since_anchor",
                           work->has_chainwork ? work->chainwork_hex : "");
    return true;
}
