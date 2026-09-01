/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Token-derived service access: turn one `zcl.service_binding.v1` gate into a
 * reproducible verdict against the ZSLP ledger.
 *
 * THE LEDGER. Balances come from `zslp_ledger` (models/zslp_ledger.h) — the
 * debit-correct per-(token,outpoint) projection keyed on a 32-byte GENESIS
 * txid and a 20-byte hash160. They do NOT come from `zslp_balances`
 * (contexts/market/models/src/zslp.c), which is a credit-only merchant ledger keyed on
 * hardcoded ticker STRINGS that uint256_set_hex cannot parse; reading it as a
 * token balance would be reading a different table that happens to have a
 * similar name.
 *
 * REPRODUCIBILITY IS THE POINT. A verdict is (ledger contents, snapshot
 * height) -> answer, never (ledger contents, wall clock) -> answer. Two nodes
 * with the same folded ledger asked about the same binding at the same tip
 * must agree, and asking again later must not change a granted verdict into a
 * denied one because a coin moved yesterday. Three mechanisms enforce that:
 *   - the snapshot height is derived purely from the declared gate and the
 *     tip (zcl_service_gate_snapshot_height_v1);
 *   - the balance is read as-of that height, not as-of now
 *     (zslp_ledger_balance_at_height);
 *   - a ledger whose backfill cursor has not reached the snapshot height is
 *     refused outright rather than answered from a partial index.
 *
 * FAIL CLOSED. Every unreadable, unresolvable, or ambiguous input yields
 * granted=false with a named reason. There is no path that returns granted
 * without a balance at or above the declared threshold.
 *
 * NOT CONSENSUS. This is an application-layer signal. Nothing here is
 * consulted by any block or transaction validity rule; the ledger it reads is
 * itself a rebuildable projection. */

#ifndef ZCL_SERVICES_SERVICE_TOKEN_GATE_H
#define ZCL_SERVICES_SERVICE_TOKEN_GATE_H

#include "base/result.h"
#include "kernel/service_binding.h"

#include <stdbool.h>
#include <stdint.h>

struct node_db;
struct json_value;

enum service_gate_error {
    SERVICE_GATE_ERR_ARGUMENT = -3400,
};

enum service_gate_reason {
    SERVICE_GATE_REASON_GRANTED = 0,
    SERVICE_GATE_REASON_INVALID_BINDING,
    SERVICE_GATE_REASON_TOKEN_UNMINTED,
    SERVICE_GATE_REASON_NO_SNAPSHOT,
    SERVICE_GATE_REASON_LEDGER_UNAVAILABLE,
    SERVICE_GATE_REASON_LEDGER_BEHIND,
    SERVICE_GATE_REASON_HOLDER_MISSING,
    SERVICE_GATE_REASON_BALANCE_BELOW_THRESHOLD,
};

/* Everything a caller needs to re-derive the answer by hand. */
struct service_gate_verdict {
    bool granted;
    enum service_gate_reason reason;
    int32_t snapshot_height;   /* -1 when it could not be resolved */
    int32_t ledger_cursor;     /* highest height the ledger has folded */
    int64_t balance;           /* as-of snapshot_height, 0 when unresolved */
    uint64_t threshold;        /* the declared min_balance */
};

/* Stable lowercase_snake reason names for JSON and logs. Never NULL. */
const char *service_gate_reason_name(enum service_gate_reason reason);

/* Evaluate one binding's gate. `address` is required for a
 * ZCL_SERVICE_GATE_HOLDER_ADDRESS gate and ignored (may be NULL) for a
 * ZCL_SERVICE_GATE_HOLDER_WALLET gate, which folds over every address this
 * node's wallet owns. `out` is fully populated on every path, including
 * failures, so a denial is always explainable. The result is non-ok only when
 * the arguments are unusable; a DENIED verdict is a successful evaluation,
 * because "this holder does not qualify" is an answer, not an error. */
struct zcl_result service_token_gate_evaluate(
    struct node_db *ndb,
    const struct zcl_service_binding_v1 *binding,
    int32_t tip_height,
    const uint8_t address[20],
    struct service_gate_verdict *out);

/* Render a verdict into an already-object `out`. Adds no allocation. */
void service_token_gate_verdict_json(const struct service_gate_verdict *v,
                                     struct json_value *out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe.
 * key = a service name, or NULL for the whole declared catalog. */
bool service_token_gate_dump_state_json(struct json_value *out,
                                        const char *key);

#endif /* ZCL_SERVICES_SERVICE_TOKEN_GATE_H */
