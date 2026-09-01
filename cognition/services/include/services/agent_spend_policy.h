/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Agent spend policy — the enforcement half of
 * docs/work/agent-spend-policy-design.md ("Enforcement"). One evaluator,
 * called from the two dispatch choke points (the kernel's
 * zcl_command_registry_execute_json and the vault's vault_dispatch), bounds
 * what an agent session may do: per-tx cap, rolling-window cap, and an
 * optional recipient allowlist, all persisted on the agent_sessions row
 * (models/agent_session.h).
 *
 * ── DEFAULT DENY, keyed on the SPEC ───────────────────────────────────────
 * The gate is not "commands with an `amount` key". Keying on the input's
 * shape meant a bounded session sailed through every money-touching leaf that
 * happens to take no amount — `core.wallet.address.export-key` handed over
 * the raw spending key, `core.wallet.backup.now` wrote a readable wallet
 * backup, and `vault.session.create` let the agent mint itself an unbounded
 * grant. Caps, allowlist, window and revocation are all irrelevant once any
 * one of those succeeds.
 *
 * So the policy classifies the LEAF, from its registry spec, and a leaf it
 * does not understand is REFUSED:
 *
 *   grant surface (vault.session.*)  -> always refused. Authority over grants
 *                                       belongs to the un-sessioned local
 *                                       operator; a grant that can widen
 *                                       itself is not a bound.
 *   understood spend leaf            -> gated on the parsed amount + recipient
 *                                       (the table in agent_spend_policy.c
 *                                       names the amount and recipient keys
 *                                       per leaf, so nothing is guessed).
 *   understood wallet read           -> allowed, nothing debited.
 *   arbitrary-SQL read               -> refused (POLICY_UNBOUNDABLE). Its
 *                                       reach is every row in node.db, which
 *                                       includes another grant's bearer token
 *                                       and HTLC preimages — spend authority,
 *                                       not facts.
 *   anything else that touches the
 *   wallet capability or mutates     -> refused (POLICY_NOT_UNDERSTOOD).
 *   everything else (plain reads)    -> allowed.
 *
 * A NULL/empty session id is the explicit local-operator exemption and always
 * passes — the argv CLI with ZCL_AGENT_SESSION unset is byte-identical to
 * before this layer existed.
 *
 * ── SCOPE, stated plainly ─────────────────────────────────────────────────
 * This bounds the TYPED NATIVE SURFACE. It is not a sandbox. The session is
 * presented in the agent's own environment and the agent holds the datadir
 * cookie, so an agent that can run the CLI can also run it with the variable
 * unset, or call sendtoaddress over JSON-RPC directly. Confining an agent is
 * an OS-level job (separate uid, no cookie read access, a wrapper that execs
 * nothing else); this layer is the bound a COOPERATING agent runs under, and
 * the audit trail for what it did. See docs/work/agent-spend-policy-design.md
 * "Threat model". */

#ifndef ZCL_SERVICES_AGENT_SPEND_POLICY_H
#define ZCL_SERVICES_AGENT_SPEND_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;
struct zcl_command_spec;

/* Refusal tokens (tests assert these exactly):
 *   SESSION_INVALID       — session missing, revoked, or expired
 *   POLICY_AMOUNT         — the amount key is present but is not a
 *                           non-negative ZCL decimal (fail closed)
 *   POLICY_TX_LIMIT       — amount exceeds max_per_tx_zat
 *   POLICY_WINDOW_LIMIT   — amount would push the rolling window over
 *                           max_per_window_zat
 *   POLICY_RECIPIENT      — recipient_allowlist is non-empty and the leaf's
 *                           recipient is not in it
 *   POLICY_WALLET_SCOPE   — spend did not explicitly name dev or prod
 *   POLICY_WALLET_UNBOUND — legacy session has no captured wallet identity
 *   POLICY_WALLET_MISMATCH— session scope/id/genesis differs from the node
 *   POLICY_NO_GRANT_MINT  — the leaf mints/revokes grants; only the
 *                           un-sessioned local operator may
 *   POLICY_UNBOUNDABLE    — the leaf is understood, and what it can REACH is
 *                           the reason it is refused: it reads arbitrary node
 *                           state, which includes material whose possession
 *                           authorizes a spend (another grant's bearer token,
 *                           an HTLC preimage)
 *   POLICY_NOT_UNDERSTOOD — the leaf touches the wallet or mutates state and
 *                           this policy has no rule for it, so it is refused
 *   POLICY_UNKNOWN_COMMAND— no spec was supplied (cannot classify -> refuse)
 *   POLICY_STORE          — the grant store could not be consulted
 *   NODE_UNREACHABLE      — the node that owns the grant store is not
 *                           answering, so no decision could be obtained */

/* One dispatch's decision. `code`/`detail` are empty when allowed.
 * `evidence` is always the REDACTED session id — a refusal identifies which
 * grant said no, it never re-presents the bearer token. `debited_zat` is what
 * was actually recorded against the window (0 unless this was a committing
 * spend), and is what agent_spend_policy_release() gives back if the handler
 * then fails. */
struct agent_spend_policy_decision {
    bool allowed;
    char code[32];
    char detail[160];
    char evidence[40];
    int64_t debited_zat;
    int64_t window_remaining_zat;
    bool intent_debit_managed;
    char intent_plan_id[65];
};

/* Evaluate one dispatch.
 *
 * `session_id` NULL/empty  -> allowed, nothing recorded (local operator).
 * `committing`             -> this invocation will actually move money (the
 *                             caller resolved the plan/commit gate), so an
 *                             allowed spend is DEBITED. When false the caps
 *                             are still enforced but nothing is written, so a
 *                             plan-stage preview cannot burn the window.
 *
 * Fail-closed: every path that cannot reach a positive decision sets
 * allowed=false with a token above. Never allocates; `out` is caller-owned. */
void agent_spend_policy_evaluate(const char *session_id,
                                 const struct zcl_command_spec *spec,
                                 const struct json_value *input,
                                 bool committing,
                                 struct agent_spend_policy_decision *out);

/* Give back a debit recorded by a committing evaluate whose handler then
 * failed (no txid, nothing broadcast). Safe to call with a zero decision;
 * does nothing unless something was actually debited. */
void agent_spend_policy_release(
    const char *session_id, const struct agent_spend_policy_decision *d);

#endif
