/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Recovery policy — gate for destructive recovery operations.
 *
 * Background
 * ----------
 * chain_state_repository stops tip *updates* that are inconsistent. It
 * does not stop the UTXO wipes or block rollbacks themselves. The 2026-
 * 04-10 incident (1.3M UTXOs wiped) ran through `node_db_wipe_utxos`,
 * which at the time was an unguarded primitive that any recovery path
 * could call with no cap, no backup check, and no operator in the loop.
 *
 * This module is the opposite philosophy. Every destructive recovery
 * operation asks the policy for permission and honours the decision:
 *
 *     struct recovery_policy p;
 *     policy_load_from_env(&p);
 *     if (policy_check_utxo_wipe(&p, rows, "boot.reimport") != POLICY_ALLOW)
 *         return;                                         // refuse
 *     node_db_wipe_utxos(ndb);
 *
 * The policy is env-tunable so an operator can raise a cap without
 * rebuilding the binary. It emits structured events on every decision
 * so the event log records exactly who asked, what was proposed, and
 * which rule fired.
 *
 * Thread-safety
 * -------------
 * `struct recovery_policy` is a value-type; it is safe to stack-allocate
 * per call. The functions themselves are reentrant and do not take
 * locks. The operator-prompt path writes/reads `operator_ack_file` but
 * a given file is expected to be owned by one caller at a time.
 */

#ifndef ZCL_SERVICES_RECOVERY_POLICY_H
#define ZCL_SERVICES_RECOVERY_POLICY_H

#include <stdbool.h>
#include <stdint.h>

/* ── Defaults (match spec) ──────────────────────────────────────── */
#define RECOVERY_POLICY_DEFAULT_MAX_UTXO_WIPE_ROWS   1000
#define RECOVERY_POLICY_DEFAULT_MAX_BLOCK_ROLLBACK   100
#define RECOVERY_POLICY_DEFAULT_MAX_HEADER_REWIND    1000
/* Validation-only cursor rewinds (proof_validate / script_validate re-bind of a
 * pre-stamping NULL-block_hash suffix) are qualitatively cheaper and safer than
 * a block_rollback: they NEVER touch coins, nullifiers, or tip_finalize, they
 * are floored at MIN(utxo_apply_cursor, tip_finalize_cursor) by the caller so
 * no downstream-applied height is ever crossed, and every re-stamped verdict is
 * re-derived idempotently from the local block body by the same verifier the
 * live reducer runs. They therefore get their own, larger cap — the small
 * block_rollback cap (100) false-refuses the routine post-cure re-bind (a live
 * 163-deep NULL suffix). The bound still protects against an unbounded rewind
 * request (a corrupt cursor asking to re-derive millions of heights), which the
 * MIN(utxo_apply, tip_finalize) floor alone would not cap. */
#define RECOVERY_POLICY_DEFAULT_MAX_VALIDATION_REBIND 4096
#define RECOVERY_POLICY_DEFAULT_OPERATOR_ACK_FILE    "/var/tmp/zcl-operator-ack"

/* ── Tunable policy ─────────────────────────────────────────────── */
struct recovery_policy {
    int64_t     max_utxo_wipe_rows;     /* env ZCL_MAX_UTXO_WIPE_ROWS */
    int64_t     max_block_rollback;     /* env ZCL_MAX_BLOCK_ROLLBACK */
    int64_t     max_validation_rebind;  /* env ZCL_MAX_VALIDATION_REBIND */
    int64_t     max_header_rewind;      /* env ZCL_MAX_HEADER_REWIND */
    bool        require_backup_verified;/* env ZCL_REQUIRE_BACKUP_VERIFIED */
    bool        dry_run;                /* env ZCL_DRY_RUN */
    const char *operator_ack_file;      /* env ZCL_OPERATOR_ACK_FILE (optional) */

    /* Optional hook the caller can set to signal "backup is verified".
     * When require_backup_verified is true, the policy refuses unless
     * this returns true. NULL = treat backup as unverified. */
    bool (*backup_verified_fn)(void *ctx);
    void  *backup_verified_ctx;

    /* When set, policy_check_* will invoke this once it has decided an
     * operation would prompt the operator. It is the mechanism by which
     * tests inject a "fake ack file" touch — production leaves it NULL.
     * Return true to accept the prompt (the policy then returns ALLOW),
     * false to keep it as POLICY_PROMPT_OPERATOR. */
    bool (*operator_prompt_fn)(const char *ack_file,
                                const char *reason, void *ctx);
    void  *operator_prompt_ctx;
};

/* ── Decision codes ─────────────────────────────────────────────── */
enum policy_decision {
    POLICY_ALLOW = 0,           /* operation may proceed */
    POLICY_REFUSE_TOO_LARGE,    /* would exceed the tunable cap */
    POLICY_REFUSE_NO_BACKUP,    /* require_backup_verified and none present */
    POLICY_REFUSE_DRY_RUN,      /* dry_run mode — refuse everything mutating */
    POLICY_PROMPT_OPERATOR,     /* ack file written; caller should stop and wait */
    POLICY_REFUSE_INVALID,      /* structural failure (negative rows, NULL reason) */
    POLICY_NUM_DECISIONS        /* sentinel */
};

/* Human-readable decision name (stable strings for logs/events). */
const char *policy_decision_name(enum policy_decision d);

/* ── Loading ────────────────────────────────────────────────────── */

/* Populate `p` from environment variables, falling back to the defaults
 * above when a variable is unset or malformed. Always initialises every
 * field, including function-pointer hooks (set to NULL). Safe to call
 * multiple times. */
void policy_load_from_env(struct recovery_policy *p);

/* Populate `p` with the built-in defaults (no env lookup). Useful for
 * tests and for call sites that want a known-safe baseline. */
void policy_set_defaults(struct recovery_policy *p);

/* ── Decisions ──────────────────────────────────────────────────── */

/* Decide whether a UTXO wipe of `proposed_rows` rows is allowed.
 * `reason` is a grep-able caller tag, e.g. "boot.reimport" or
 * "snapshot.prepare_receive". Required — NULL returns REFUSE_INVALID.
 * Events: EV_RECOVERY_POLICY_ALLOW / REFUSED / PROMPT. */
enum policy_decision policy_check_utxo_wipe(
    const struct recovery_policy *p,
    int64_t proposed_rows,
    const char *reason);

/* Decide whether rolling the chain from `from_height` down to
 * `to_height` is allowed. Depth = from_height - to_height; a negative
 * depth is structurally invalid. Same event behaviour. */
enum policy_decision policy_check_block_rollback(
    const struct recovery_policy *p,
    int64_t from_height,
    int64_t to_height,
    const char *reason);

/* Decide whether a VALIDATION-ONLY cursor rewind from `from_height` down to
 * `to_height` is allowed. Same depth/decision semantics as
 * policy_check_block_rollback but uses the larger `max_validation_rebind` cap
 * (see RECOVERY_POLICY_DEFAULT_MAX_VALIDATION_REBIND). Callers MUST already
 * have floored `to_height` at MIN(utxo_apply_cursor, tip_finalize_cursor) — the
 * cap bounds the rewind depth, it does NOT establish the downstream-consumer
 * floor. For proof_validate / script_validate NULL-block_hash re-arms only:
 * these rewind no coins, no nullifiers, and no tip_finalize cursor. */
enum policy_decision policy_check_validation_rebind(
    const struct recovery_policy *p,
    int64_t from_height,
    int64_t to_height,
    const char *reason);

/* Decide whether rewinding the header tip by `depth` headers is allowed.
 * Same semantics as above, uses `max_header_rewind` as the cap. */
enum policy_decision policy_check_header_rewind(
    const struct recovery_policy *p,
    int64_t depth,
    const char *reason);

#endif /* ZCL_SERVICES_RECOVERY_POLICY_H */
