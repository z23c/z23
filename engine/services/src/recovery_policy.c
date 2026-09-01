/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Recovery policy — see header for rationale.
 *
 * Implementation notes
 * --------------------
 * - Pure value semantics. The struct is safe to stack-allocate per
 *   call; no global state is owned here.
 * - Events are emitted via the existing global `event_emitf` ring so
 *   every decision is recorded alongside csr tip commits. The spec
 *   originally named a `struct event_bus *` parameter, but the project
 *   uses the global ring and we match that convention.
 * - The operator-prompt path writes to `operator_ack_file` once per
 *   call and defers the ack-wait decision to the caller-supplied
 *   `operator_prompt_fn` hook. Tests use the hook to model accept /
 *   reject behaviour; production leaves it NULL and the decision
 *   stays POLICY_PROMPT_OPERATOR so the caller knows to stop.
 */

// one-result-type-ok:single-policy-decision-enum — E2 (one way out):
// every public fallible entry point returns one domain type,
// enum policy_decision (allow / refuse_* / prompt_operator). The bare
// bool helpers (zcl_parse_i64, parse_bool, write_prompt_ack_file) are
// private input-validation predicates, not a service surface, and the
// void setters cannot fail. Each decision is logged via EV_RECOVERY_POLICY_*
// events, so the refusal reason always travels with the decision.

#include "services/recovery_policy.h"

#include "event/event.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  /* strcasecmp */

#include "util/log_macros.h"
#include "util/parse_num.h"

/* ── Decision names ─────────────────────────────────────────────── */
const char *policy_decision_name(enum policy_decision d)
{
    switch (d) {
    case POLICY_ALLOW:             return "allow";
    case POLICY_REFUSE_TOO_LARGE:  return "refuse_too_large";
    case POLICY_REFUSE_NO_BACKUP:  return "refuse_no_backup";
    case POLICY_REFUSE_DRY_RUN:    return "refuse_dry_run";
    case POLICY_PROMPT_OPERATOR:   return "prompt_operator";
    case POLICY_REFUSE_INVALID:    return "refuse_invalid";
    case POLICY_NUM_DECISIONS:     break;
    }
    return "unknown";
}

/* ── Env helpers ────────────────────────────────────────────────── */

static bool parse_bool(const char *s, bool *out)
{
    if (!s || !*s || !out) return false;
    if (s[0] == '1' && s[1] == '\0') { *out = true;  return true; }
    if (s[0] == '0' && s[1] == '\0') { *out = false; return true; }
    if (!strcasecmp(s, "true")  || !strcasecmp(s, "yes") || !strcasecmp(s, "on"))
    { *out = true;  return true; }
    if (!strcasecmp(s, "false") || !strcasecmp(s, "no")  || !strcasecmp(s, "off"))
    { *out = false; return true; }
    return false;
}

/* ── Loading ────────────────────────────────────────────────────── */

void policy_set_defaults(struct recovery_policy *p)
{
    if (!p) return;
    memset(p, 0, sizeof(*p));
    p->max_utxo_wipe_rows      = RECOVERY_POLICY_DEFAULT_MAX_UTXO_WIPE_ROWS;
    p->max_block_rollback      = RECOVERY_POLICY_DEFAULT_MAX_BLOCK_ROLLBACK;
    p->max_validation_rebind   = RECOVERY_POLICY_DEFAULT_MAX_VALIDATION_REBIND;
    p->max_header_rewind       = RECOVERY_POLICY_DEFAULT_MAX_HEADER_REWIND;
    p->require_backup_verified = false;
    p->dry_run                 = false;
    p->operator_ack_file       = RECOVERY_POLICY_DEFAULT_OPERATOR_ACK_FILE;
    p->backup_verified_fn      = NULL;
    p->backup_verified_ctx     = NULL;
    p->operator_prompt_fn      = NULL;
    p->operator_prompt_ctx     = NULL;
}

void policy_load_from_env(struct recovery_policy *p)
{
    if (!p) return;
    policy_set_defaults(p);

    int64_t v64;
    bool    vb;
    const char *s;

    if ((s = getenv("ZCL_MAX_UTXO_WIPE_ROWS")) && zcl_parse_i64(s, &v64))
        p->max_utxo_wipe_rows = v64;
    if ((s = getenv("ZCL_MAX_BLOCK_ROLLBACK")) && zcl_parse_i64(s, &v64))
        p->max_block_rollback = v64;
    if ((s = getenv("ZCL_MAX_VALIDATION_REBIND")) && zcl_parse_i64(s, &v64))
        p->max_validation_rebind = v64;
    if ((s = getenv("ZCL_MAX_HEADER_REWIND")) && zcl_parse_i64(s, &v64))
        p->max_header_rewind = v64;
    if ((s = getenv("ZCL_REQUIRE_BACKUP_VERIFIED")) && parse_bool(s, &vb))
        p->require_backup_verified = vb;
    if ((s = getenv("ZCL_DRY_RUN")) && parse_bool(s, &vb))
        p->dry_run = vb;
    if ((s = getenv("ZCL_OPERATOR_ACK_FILE")) && *s)
        p->operator_ack_file = s;  /* env strings outlive any single call */
}

/* ── Event helpers ──────────────────────────────────────────────── */

static void emit_allow(const char *op, int64_t amount, const char *reason)
{
    event_emitf(EV_RECOVERY_POLICY_ALLOW, 0,
                "op=%s amount=%lld reason=%s",
                op, (long long)amount, reason ? reason : "");
}

static void emit_refused(const char *op, enum policy_decision d,
                          int64_t amount, int64_t cap, const char *reason)
{
    event_emitf(EV_RECOVERY_POLICY_REFUSED, 0,
                "op=%s code=%s amount=%lld cap=%lld reason=%s",
                op, policy_decision_name(d),
                (long long)amount, (long long)cap,
                reason ? reason : "");
}

static void emit_prompt(const char *op, int64_t amount, const char *reason,
                         const char *ack_file)
{
    event_emitf(EV_RECOVERY_POLICY_PROMPT, 0,
                "op=%s amount=%lld ack=%s reason=%s",
                op, (long long)amount,
                ack_file ? ack_file : "",
                reason ? reason : "");
}

/* Write a one-shot prompt file describing the pending operation. The
 * file is overwritten on every call, so an operator always sees the
 * most recent request. Returns true on success; failure is non-fatal
 * (we still return POLICY_PROMPT_OPERATOR — the caller should stop). */
static bool write_prompt_ack_file(const char *path, const char *op,
                                    int64_t amount, const char *reason)
{
    if (!path || !*path) return false;
    FILE *f = fopen(path, "w");
    if (!f) return false;
    fprintf(f, "op=%s\namount=%lld\nreason=%s\n",
            op, (long long)amount, reason ? reason : "");
    fclose(f);
    return true;
}

/* ── Core decision engine ───────────────────────────────────────── */

/* Centralised decision function for the three checks above. `amount`
 * is the caller-supplied size (rows / depth); `cap` is the tunable
 * drawn from the policy; `op` labels the operation in events. */
static enum policy_decision decide(const struct recovery_policy *p,
                                     const char *op,
                                     int64_t amount,
                                     int64_t cap,
                                     const char *reason)
{
    /* Structural guard rails. Everything else expects the inputs to be
     * meaningful; enforce that first so later branches can't be
     * accidentally tricked by negatives / NULLs. */
    if (!p || !reason || !*reason) {
        emit_refused(op ? op : "?", POLICY_REFUSE_INVALID, amount, cap, reason);
        return POLICY_REFUSE_INVALID;
    }
    if (amount < 0) {
        emit_refused(op, POLICY_REFUSE_INVALID, amount, cap, reason);
        return POLICY_REFUSE_INVALID;
    }

    /* Dry-run trumps everything else. An operator who set dry_run=1
     * wants zero mutations, period — even if the amount is below the
     * cap. */
    if (p->dry_run) {
        emit_refused(op, POLICY_REFUSE_DRY_RUN, amount, cap, reason);
        return POLICY_REFUSE_DRY_RUN;
    }

    /* Backup requirement. Checked before the cap so operators see the
     * most actionable refusal first ("you forgot a backup" vs "raise
     * the cap"). Missing hook = treat as unverified. */
    if (p->require_backup_verified) {
        bool ok = p->backup_verified_fn
            ? p->backup_verified_fn(p->backup_verified_ctx)
            : false;
        if (!ok) {
            emit_refused(op, POLICY_REFUSE_NO_BACKUP, amount, cap, reason);
            return POLICY_REFUSE_NO_BACKUP;
        }
    }

    /* Amount at or below the cap: allowed outright. This is the fast
     * path for routine operations that stay under the safety limit. */
    if (amount <= cap) {
        emit_allow(op, amount, reason);
        return POLICY_ALLOW;
    }

    /* Amount exceeds the cap. Two sub-cases:
     *   a) no operator prompt hook — refuse loudly (REFUSE_TOO_LARGE)
     *   b) prompt hook set — write the ack file, ask the hook for a
     *      decision. If the hook accepts, the operation is allowed.
     *      If the hook declines, we still return PROMPT_OPERATOR so
     *      the caller knows to stop and wait for a manual ack. */
    write_prompt_ack_file(p->operator_ack_file, op, amount, reason);
    if (p->operator_prompt_fn) {
        bool accept = p->operator_prompt_fn(p->operator_ack_file, reason,
                                             p->operator_prompt_ctx);
        if (accept) {
            emit_allow(op, amount, reason);
            return POLICY_ALLOW;
        }
        emit_prompt(op, amount, reason, p->operator_ack_file);
        return POLICY_PROMPT_OPERATOR;
    }

    /* No hook — refuse. The cap is the hard limit. */
    emit_refused(op, POLICY_REFUSE_TOO_LARGE, amount, cap, reason);
    return POLICY_REFUSE_TOO_LARGE;
}

/* ── Public decision entry points ───────────────────────────────── */

enum policy_decision policy_check_utxo_wipe(
    const struct recovery_policy *p,
    int64_t proposed_rows,
    const char *reason)
{
    int64_t cap = p ? p->max_utxo_wipe_rows : 0;
    return decide(p, "utxo_wipe", proposed_rows, cap, reason);
}

enum policy_decision policy_check_block_rollback(
    const struct recovery_policy *p,
    int64_t from_height,
    int64_t to_height,
    const char *reason)
{
    /* Depth is the amount of ground we would lose. Negative depth
     * (to_height > from_height) means the caller tried to "rollback"
     * forwards — that's a bug, not a recovery. */
    int64_t depth = from_height - to_height;
    int64_t cap = p ? p->max_block_rollback : 0;
    return decide(p, "block_rollback", depth, cap, reason);
}

enum policy_decision policy_check_validation_rebind(
    const struct recovery_policy *p,
    int64_t from_height,
    int64_t to_height,
    const char *reason)
{
    /* Same depth arithmetic as block_rollback, but the larger validation-rebind
     * cap: this rewinds only the proof/script VALIDATION cursors (no coins, no
     * nullifiers, no tip_finalize) and re-derives every verdict idempotently. */
    int64_t depth = from_height - to_height;
    int64_t cap = p ? p->max_validation_rebind : 0;
    return decide(p, "validation_rebind", depth, cap, reason);
}

enum policy_decision policy_check_header_rewind(
    const struct recovery_policy *p,
    int64_t depth,
    const char *reason)
{
    int64_t cap = p ? p->max_header_rewind : 0;
    return decide(p, "header_rewind", depth, cap, reason);
}
