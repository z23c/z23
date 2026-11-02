/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Phone spend rule (-spend-after-checkpoint). A phone started from a snapshot
 * is refused by sovereignty_guard_allow("wallet_spend"). This gate lets
 * z_sendmany spend only funds received after the snapshot point, and only
 * when every check below holds at send time. Nothing is read from a stored
 * "approved" flag.
 *
 * Checks, in order (first failure names the reason):
 *   option_off          the process was not started with the option
 *   tip_not_validated   no validated tip block, or its header Sapling root is
 *                       unset
 *   behind_tip          the validated tip trails the best header by more than
 *                       WALLET_SPEND_TIP_SLACK blocks
 *   checkpoint_missing  no usable baked checkpoint at or below the tip, or
 *                       the header chain does not reach it
 *   tip_not_descended   the tip's ancestor at a baked height has another hash
 *   checkpoint_mismatch the header Sapling root at the baked frontier height
 *                       differs from the baked frontier root
 *   anchor_root_mismatch the header Sapling root at the tip is absent from the
 *                       reducer's per-block Sapling anchor ledger (or, at
 *                       proving time, a note witness root differs from the
 *                       header root at its witness height)
 *   floor_unknown       the Sapling anchor or nullifier activation cursor, the
 *                       assisted-install seam, the reducer seed floor or the
 *                       anchor ledger is unreadable, or the progress lock was
 *                       not obtained within the bounded wait
 *
 * Limit: the transparent coin set of the snapshot is not compared with the
 * checkpoint; after folding forward it cannot be. Only funds created in
 * blocks this node validated after the floor are spendable. */

#ifndef ZCL_CONTROLLERS_WALLET_SPEND_GATE_H
#define ZCL_CONTROLLERS_WALLET_SPEND_GATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;
struct main_state;
struct wallet_rpc_context;

#define WALLET_SPEND_REASON_MAX 48
#define WALLET_SPEND_TIP_SLACK 2
#define WALLET_SPEND_NO_FLOOR (-1)

/* Every refusal text the z_sendmany handler returns for the spend rule starts
 * with the prefix. It can carry a shortfall, so the native handler keeps it out
 * of its log; the refusal comes before anything is built, and a keyed send
 * answers it with the released-key code. */
#define WALLET_SPEND_REFUSAL_PREFIX "Error: spend refused"

/* The checks above, without the strict guard or the option. hstar is the
 * validated (reducer) tip height. On success *floor_height is the highest
 * height whose funds are NOT spendable (max of the compiled keystone height, the
 * Sapling anchor cursor, the nullifier cursor, the assisted-install seam and
 * the reducer seed floor). */
bool wallet_spend_gate_evaluate(const struct main_state *ms,
                                int32_t hstar,
                                int32_t *floor_height,
                                char *reason, size_t reason_cap);

/* True when the strict guard allows: *floor_height is WALLET_SPEND_NO_FLOOR.
 * Otherwise true only when the option is on and wallet_spend_gate_evaluate
 * passes: *floor_height is the snapshot floor. Never true otherwise. The
 * reason is a machine token, never private data. */
bool wallet_spend_gate_check(struct wallet_rpc_context *ctx,
                             int32_t *floor_height,
                             char *reason, size_t reason_cap);

/* True when funds received at `height` may be spent under `floor_height`:
 * the height is above the floor (an unknown height, 0, counts as at or below).
 * A floor of WALLET_SPEND_NO_FLOOR admits every height. The one test the note
 * and coin selection share. */
bool wallet_spend_gate_height_ok(int32_t floor_height, int32_t height);

struct db_sapling_note;

/* Refusal text for a send needing more than the post-floor funds. The amounts
 * go to the caller only; callers must not log them. */
void wallet_spend_gate_shortfall_message(char *out, size_t cap, int64_t need,
                                         int64_t have);

/* The spend entry of z_sendmany: with checkpoint_rule false this is exactly the
 * strict guard; true applies the phone rule. On refusal the error text is set
 * in `result` and false is returned (logged without private data). */
bool wallet_spend_gate_for_send(struct wallet_rpc_context *ctx,
                                bool checkpoint_rule, int32_t *floor_height,
                                struct json_value *result);

/* Insufficient-funds refusal. Without a floor: plain_text, logging the
 * amounts as before. With a floor: the shortfall text, and no amount in the
 * log. Always returns false. */
bool wallet_spend_gate_short_funds(struct json_value *result, int32_t floor,
                                   int64_t need, int64_t have,
                                   const char *tag, const char *plain_text);

/* Text for "no spendable note remains". */
const char *wallet_spend_gate_no_notes_text(int32_t floor);

/* Pre-proving check: a note witness root must equal the header Sapling root
 * at the witness height. */
bool wallet_spend_gate_witness_root_ok(const struct main_state *ms,
                                       int witness_height,
                                       const uint8_t root[32]);

#endif
