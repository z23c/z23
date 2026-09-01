/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * anchor_finality — the seniority gate on directory influence: an on-chain
 * anchored record feeds a HINT the moment it lands, but confers no INFLUENCE
 * on peer selection until the block that carries it can no longer be rewritten
 * by a reorg this node would accept.
 *
 * POLICY, NOT CONSENSUS. Nothing here validates a block, a transaction, or a
 * chain. It answers one question about an already-validated record: "does this
 * count yet?" It lives in core/modules/policy for that reason and is retunable without
 * a fork.
 *
 * ── What the depth means, precisely ───────────────────────────────────────
 *
 * `depth` here is BLOCKS BUILT ON TOP: depth = current_height - record_height.
 * A record in the tip block has depth 0. Influence begins at
 * depth >= ZCL_FINALITY_DEPTH (10), which is exactly the boundary
 * `height_is_immutable(current_height, record_height)` draws, which is in turn
 * exactly the deepest reorg `reorg_is_allowed` will accept
 * (core/modules/validation/include/validation/checkpoint.h:38,43;
 * ZCL_FINALITY_DEPTH at core/modules/validation/include/validation/main_constants.h:33).
 * The three agree by construction, not by coincidence: a record is FINAL
 * precisely when no reorg this node will follow can remove it. In wallet
 * "confirmations" terms (which count the record's own block) depth 10 is 11
 * confirmations; this module never uses that counting, because the reorg gate
 * does not either.
 *
 * ── What 10 is and is NOT ─────────────────────────────────────────────────
 *
 * Ten blocks is an ANTI-FLAPPING threshold. It is NOT a trust threshold and
 * this module does not make anything safe. An attacker holding roughly ten
 * blocks of private hashpower CAN rewrite the recent window. The reason that
 * buys them nothing here is not the depth gate — it is that influence is
 * earned from SENIORITY measured in hours to days, and the depth gate merely
 * stops a shallow reorg from making weights oscillate while that seniority
 * accrues. Do not cite this file as evidence that a 10-deep record is secure.
 *
 * ── Advisory, never exclusive ─────────────────────────────────────────────
 *
 * The only sanctioned output is a dial-chance MULTIPLIER in [1.0, 4.0] destined
 * for addrman_publish_reputation_weights (core/modules/net/src/addrman.c). 1.0 means "no
 * influence" — never "exclude". A record that is provisional, withdrawn, or
 * absent yields exactly 1.0, i.e. classic addrman behaviour byte-for-byte.
 * There is no code path in this module that can produce a value below 1.0, so
 * a directory record structurally cannot narrow peer selection or veto a peer.
 *
 * ── Pure and total ────────────────────────────────────────────────────────
 *
 * Every predicate is a pure function of its arguments: no clock, no RNG, no
 * I/O, no allocation, no globals. Caller-owned storage only. Every integer
 * height pair is defined, including record_height > current_height — a real
 * state mid-reorg, when a record we already saw sits on a branch above the tip
 * we currently follow.
 */

#ifndef ZCL_POLICY_ANCHOR_FINALITY_H
#define ZCL_POLICY_ANCHOR_FINALITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Identity of an anchored record: the 32-byte blinded record key / master
 * pubkey the anchor names (contexts/wallet/modules/zid/include/zid/zid.h zid_blinded_key,
 * contexts/wallet/modules/zid/include/zid/zid_anchor.h ZID_ANCHOR_PUBKEY_LEN). */
#define ANCHOR_FINALITY_KEY_LEN 32

/* Bounds of the advisory multiplier. MAX mirrors ADDRMAN_REPUTATION_MAX_MULT
 * (core/modules/net/include/net/addrman.h:50). It is a deliberate LOCAL copy: core/modules/net
 * ranks BELOW core/modules/policy in engine/composition/lib_module_order.def, so including
 * net/addrman.h from here would be legal but would drag the whole net header
 * into a pure policy module. The two are pinned equal by a static assertion in
 * tests/harness/src/test_anchor_finality.c, which sits above both — so this copy
 * cannot silently drift. */
#define ANCHOR_INFLUENCE_MULT_MIN 1.0
#define ANCHOR_INFLUENCE_MULT_MAX 4.0

/* How many anchored records one set tracks. Fixed and caller-owned: no
 * allocation, and a hostile flood of anchors cannot grow this node's memory. */
#define ANCHOR_INFLUENCE_MAX_RECORDS 256

enum anchor_finality_state {
    /* Inputs do not describe a record on a chain we have: no tip yet, or a
     * negative record height. Confers nothing. */
    ANCHOR_FINALITY_UNKNOWN = 0,
    /* On the chain but still rewritable: depth < ZCL_FINALITY_DEPTH, or above
     * the tip we currently follow. Confers nothing — it is a hint only. */
    ANCHOR_FINALITY_PROVISIONAL = 1,
    /* depth >= ZCL_FINALITY_DEPTH: no reorg this node accepts can remove it.
     * Confers influence. */
    ANCHOR_FINALITY_FINAL = 2,
};

/* The full, reportable answer. `reason` is a static string owned by this
 * module, never NULL, and is one of:
 *   "final"                    at or past the finality depth
 *   "provisional_shallow"      on-chain, 0 <= depth < ZCL_FINALITY_DEPTH
 *   "provisional_above_tip"    record_height > current_height (mid-reorg)
 *   "no_tip"                   current_height < 0
 *   "invalid_record_height"    record_height < 0
 * Operators read `state` + `reason` + `blocks_until_final` to see WHY a record
 * is not counting yet, instead of guessing. */
struct anchor_finality {
    enum anchor_finality_state state;
    int depth;              /* current_height - record_height; may be < 0 */
    int blocks_until_final; /* blocks still needed; 0 iff FINAL or UNKNOWN */
    bool confers_influence; /* true iff state == ANCHOR_FINALITY_FINAL */
    const char *reason;
};

/* Evaluate a record's finality. Pure and total: every (record_height,
 * current_height) pair in int x int produces a defined answer. `out` must be
 * non-NULL; it is fully written on every path. */
void anchor_finality_evaluate(int record_height, int current_height,
                              struct anchor_finality *out);

/* The bare predicate the rest of the stack should call: "does this anchored
 * record confer influence yet?" Equivalent to
 * anchor_finality_evaluate(...).confers_influence. */
bool anchor_confers_influence(int record_height, int current_height);

/* Static names for logs and JSON: "unknown" / "provisional" / "final". Never
 * NULL, including for an out-of-range enum value. */
const char *anchor_finality_state_name(enum anchor_finality_state state);

/* ── Influence set: the withdrawal rail ───────────────────────────────────
 *
 * The predicate above is stateless, so correctness under reorg depends on
 * someone RE-EVALUATING when the tip moves. A weight that was pushed into
 * addrman once and never revisited would survive its own record's
 * disappearance — the exact bug this module exists to prevent. The set below
 * makes re-evaluation the only way to read a weight: `effective_mult` is not
 * stored by the writer, it is DERIVED at every anchor_influence_set_apply_tip
 * from the record height and the tip. A reorg that lowers the tip therefore
 * withdraws influence by construction; nobody has to remember to.
 */
struct anchor_influence_record {
    bool used;
    uint8_t key[ANCHOR_FINALITY_KEY_LEN];
    int height;             /* height of the block carrying the anchor */
    double claimed_mult;    /* what it confers WHEN final; clamped to [1,4] */
    /* Derived at apply_tip; never written by the producer. */
    struct anchor_finality finality;
    double effective_mult;  /* claimed_mult iff FINAL, else exactly 1.0 */
};

struct anchor_influence_set {
    int tip_height;         /* -1 until the first apply_tip */
    size_t count;           /* live (used) records */
    struct anchor_influence_record records[ANCHOR_INFLUENCE_MAX_RECORDS];
};

/* Zero the set and park the tip at -1 (nothing confers influence yet). */
void anchor_influence_set_init(struct anchor_influence_set *set);

/* Insert or update the record for `key`. `claimed_mult` is clamped into
 * [ANCHOR_INFLUENCE_MULT_MIN, ANCHOR_INFLUENCE_MULT_MAX] — a caller cannot
 * express "penalise this peer". The record starts PROVISIONAL and is
 * re-derived against the set's current tip before returning, so a fresh
 * insert never leaks influence it has not earned.
 *
 * Returns false (and logs) on a NULL argument, a negative height, or a full
 * set. */
bool anchor_influence_set_upsert(struct anchor_influence_set *set,
                                 const uint8_t key[ANCHOR_FINALITY_KEY_LEN],
                                 int height, double claimed_mult);

/* Drop a record outright. Returns false (and logs) on a NULL argument or when
 * the key is not present. */
bool anchor_influence_set_remove(struct anchor_influence_set *set,
                                 const uint8_t key[ANCHOR_FINALITY_KEY_LEN]);

/* Re-derive EVERY record against `tip_height`, which may be lower than the
 * previous tip (a reorg). Records whose anchoring height is above the new tip
 * are evicted: on the chain we now follow, that block does not exist.
 * Surviving records are re-classified, and `effective_mult` is recomputed —
 * dropping to exactly 1.0 for anything no longer final.
 *
 * `withdrawn_out` (optional) receives the number of records that conferred
 * influence before this call and do not after it: evictions plus
 * final-to-provisional demotions. That count is the operator-visible evidence
 * that a reorg actually took influence back.
 *
 * Returns the number of records conferring influence after the call. A
 * negative `tip_height` is legal and means "no tip": every record becomes
 * UNKNOWN and confers nothing (no evictions — we do not know what to evict). */
size_t anchor_influence_set_apply_tip(struct anchor_influence_set *set,
                                      int tip_height, size_t *withdrawn_out);

/* Read one record's derived state. Returns false (and logs) when the key is
 * absent. `finality_out` / `mult_out` are optional. */
bool anchor_influence_lookup(const struct anchor_influence_set *set,
                             const uint8_t key[ANCHOR_FINALITY_KEY_LEN],
                             struct anchor_finality *finality_out,
                             double *mult_out);

/* The advisory multiplier to hand to addrman_publish_reputation_weights for `key`.
 * Always in [1.0, 4.0]; exactly 1.0 for an absent, provisional, unknown, or
 * withdrawn record. Never returns a value that could narrow selection. */
double anchor_influence_weight_for(const struct anchor_influence_set *set,
                                   const uint8_t key[ANCHOR_FINALITY_KEY_LEN]);

/* Operator report. `out` must already be an initialized json_value; this
 * fills it as an object with tip_height, counts, and a `records` array whose
 * entries carry key_hex, height, depth, state, reason, blocks_until_final and
 * effective_mult. The set is a caller argument rather than a module global on
 * purpose: no live instance is wired yet (see the seam note in
 * core/modules/policy/src/anchor_finality.c), and a diagnostics dumper reporting an
 * empty global would be a lie. Returns false (and logs) on a NULL argument. */
struct json_value;
bool anchor_influence_set_dump_json(const struct anchor_influence_set *set,
                                    struct json_value *out);

#endif /* ZCL_POLICY_ANCHOR_FINALITY_H */
