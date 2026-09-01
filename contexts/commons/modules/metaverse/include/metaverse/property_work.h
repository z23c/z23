/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * property_work — the work beneath a proof-of-work-settled property,
 * measured rather than asserted. Pure rules: no I/O, no store, no chain
 * handle, no allocation. The caller supplies the two block-index facts and
 * this file does the subtraction.
 *
 * WHY THIS EXISTS. metaverse/property_id.h says which of four settlement
 * classes a kind belongs to. For exactly one of them —
 * METAVERSE_SETTLEMENT_PROOF_OF_WORK — the guarantee is not a yes/no but a
 * QUANTITY: how deep the anchoring record is buried, and how much work an
 * attacker would have to redo to reorder it. Reporting the class without
 * the quantity leaves "settled by proof of work" as a slogan. So the class
 * comes with three numbers:
 *
 *   anchor_height   the ZCL height of the record that fixes the ordering
 *                   (znam_entry.reg_height, zslp_token.genesis_height).
 *   depth           tip_height - anchor_height. Confirmations.
 *   chainwork       tip.nChainWork - anchor.nChainWork, i.e. the work
 *                   accumulated on top of the anchor. Taken from the block
 *                   index's own per-block nChainWork, never recomputed:
 *                   pass `bi->nChainWork` straight in.
 *
 * UNKNOWN IS NOT ZERO, AND THIS FILE WILL NOT LET THEM BLUR. Every number
 * is paired with its own `has_` flag, and the render puts -1 (never 0) in
 * the slot when the flag is false. A depth of 0 means "the anchor is the
 * tip"; an unknown depth means "we did not establish one". An operator who
 * cannot tell those apart has been misinformed, and the false-freshness
 * warning in metaverse/property_adapter.h is the same rule stated for
 * heights.
 *
 * FOR NON-PROOF-OF-WORK KINDS THE ANSWER IS "DOES NOT APPLY", NOT ZERO.
 * metaverse_work_measure() refuses to fill anything for a content-addressed,
 * locally-declared, or chain-anchored-but-unmeasurable kind, whatever the
 * caller passes: a tip height stamped beside a claim the tip does not commit
 * is a manufactured freshness claim, and this is the one place that can
 * stop it for every consumer at once.
 *
 * There is no score, rating, or trust tier here on purpose. A number an
 * operator can check beats a grade this code invented.
 */

#ifndef ZCL_METAVERSE_PROPERTY_WORK_H
#define ZCL_METAVERSE_PROPERTY_WORK_H

#include "metaverse/property_id.h"

#include "core/arith_uint256.h"

#include <stdbool.h>
#include <stdint.h>

struct json_value;

/* 64 hex digits + NUL, matching arith_uint256_get_hex(). */
#define METAVERSE_WORK_HEX_MAX 65u

/* Why a work measurement is absent. Never a silent gap: a proof reporting
 * nothing always names which of these it is. */
enum metaverse_work_gap {
    METAVERSE_WORK_GAP_NONE = 0,       /* measured; the numbers are real */
    METAVERSE_WORK_GAP_NOT_APPLICABLE, /* kind is not PoW-settled */
    METAVERSE_WORK_GAP_NO_ANCHOR,      /* PoW-settled, anchor height unknown */
    METAVERSE_WORK_GAP_NO_TIP,         /* PoW-settled, tip unknown */
    /* Anchor height is ABOVE the tip: the record and the tip disagree
     * about what chain this is, or the tip is stale. Its own gap because
     * folding it into NO_TIP would report "no tip was supplied" about a
     * call that supplied one. */
    METAVERSE_WORK_GAP_ANCHOR_ABOVE_TIP,
};

struct metaverse_work_proof {
    /* The class this proof was built for; copied so a rendered proof is
     * self-describing without the id beside it. */
    enum metaverse_settlement settlement;
    /* True only when settlement is PROOF_OF_WORK. Says the QUESTION is
     * askable, not that it was answered — that is has_depth / has_chainwork
     * below. */
    bool applicable;
    enum metaverse_work_gap gap;

    bool has_anchor_height;
    int64_t anchor_height;
    bool has_tip_height;
    int64_t tip_height;

    /* tip_height - anchor_height, never negative: an anchor above the tip
     * is a contradiction, not a negative depth, and is reported as a gap. */
    bool has_depth;
    int64_t depth;

    /* Work accumulated between anchor and tip, big-endian hex as the rest
     * of the node renders chainwork. Empty string when unknown. */
    bool has_chainwork;
    char chainwork_hex[METAVERSE_WORK_HEX_MAX];
};

const char *metaverse_work_gap_name(enum metaverse_work_gap gap);
/* One sentence an operator can read, explaining the gap. Never NULL. */
const char *metaverse_work_gap_reason(enum metaverse_work_gap gap);

/* Zero the proof and record that this kind's work is not measurable. Used
 * for every non-PoW kind and as the safe starting state for a PoW one. */
void metaverse_work_none(struct metaverse_work_proof *out,
                         enum metaverse_settlement settlement);

/* Measure the work beneath a record anchored at `anchor_height` under a tip
 * at `tip_height`.
 *
 * `anchor_work` / `tip_work` are the block index's own accumulated-work
 * values for those two blocks (`bi->nChainWork`); either may be NULL when
 * unknown, and the chainwork field is then left unknown while depth is
 * still reported. A negative height means unknown.
 *
 * Returns true only when the kind is PoW-settled AND at least the depth was
 * established. *out is always fully written (never partially), so a caller
 * that ignores the return still holds an honest proof. NULL out returns
 * false and does nothing. */
bool metaverse_work_measure(enum metaverse_kind kind, int64_t anchor_height,
                            const struct arith_uint256 *anchor_work,
                            int64_t tip_height,
                            const struct arith_uint256 *tip_work,
                            struct metaverse_work_proof *out);

/* Render as a JSON object (set to an object by this call). Every field is
 * emitted including the unknowns: unknown ints render as -1 and unknown
 * chainwork as "", each beside its own has_ boolean, so no consumer has to
 * infer a missing key's meaning or read 0 as a measurement. */
bool metaverse_work_to_json(const struct metaverse_work_proof *work,
                            struct json_value *out);

#endif /* ZCL_METAVERSE_PROPERTY_WORK_H */
