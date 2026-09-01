# Agent spend policy (Slice 3) — scoped agent authority over digital assets

Status: design (2026-07-26). Owner roadmap order: (1) fast reliable zclassicd-parity
sync [done, arch 100/100] → (2) control of digital assets [this doc is the
remaining foundation piece] → (3) semantic system understanding → (4) network
peers overview → (5) explorer → (6) ZNAM + P2P file market.

## Problem

An AI agent operating this node today has exactly two postures: no keys, or
the omnipotent local argv operator (`tools/command/native_command.c:3149` —
`granted_capabilities=~0`, `authority_ceiling=OWNER`). There is no way to hand
an agent **bounded** authority: spend up to X per tx, Y per window, only to
these recipients. The kernel already enforces authority ceilings and capability
masks per session (`engine/modules/kernel/src/command_registry.c:1683-1705`); what is
missing is (a) a persisted session/policy store and (b) a policy check at the
two dispatch choke points.

## Decisions (owner-flagged, auto-mode defaults)

- **Per-session policy.** Each agent session carries its own policy; one
  principal may run a low-limit routine session and a high-limit operator
  session. Policies do NOT live on the principal row — `principal.c:81-94,137-139`
  recomputes and validates caps from role on every save, so anything smuggled
  there is wiped/rejected.
- **Identity stays with `app.auth.challenge/verify`** (public-key login,
  `auth_login_service.c:187-305`). No new credential type to audit. The spend
  session is a *separate, revocable grant* minted by the local operator and
  presented per-invocation.
- **v1 scope: the typed native surface (local CLI agents).** JSON-RPC spends
  (sendtoaddress over cookie Basic auth) bypass the kernel entirely and are
  out of scope for v1 — documented, not silently unprotected: the policy is
  about bounding *agents*, and agents are expected at the typed surface.

## Model (migration v36, `database_migrate_features_v30_up.c` after v35 :170-188)

Table `agent_sessions` — one row per minted session grant:

- `session_id TEXT PRIMARY KEY` — 32 hex chars (128-bit random, generated at mint)
- `account TEXT NOT NULL REFERENCES principals(address)` — identity (role derives
  ceiling/caps, unchanged)
- `max_per_tx_zat INTEGER NOT NULL CHECK(max_per_tx_zat >= 0 AND max_per_tx_zat <= 2100000000000000)`
- `max_per_window_zat INTEGER NOT NULL CHECK(... same range)` — 0 means "window limit disabled"? No:
  keep both mandatory; use the 21M-ZCL cap as "unbounded".
- `window_seconds INTEGER NOT NULL CHECK(window_seconds > 0)`
- `window_start_epoch INTEGER NOT NULL` + `spent_in_window_zat INTEGER NOT NULL DEFAULT 0`
  (rolling window accounting, updated under the AR lifecycle on every allowed spend)
- `recipient_allowlist TEXT NOT NULL DEFAULT ''` — CSV of t-/zs-addresses; empty = any recipient
- `created_at INTEGER NOT NULL`, `expires_at INTEGER NOT NULL` (0 = never), `revoked INTEGER NOT NULL DEFAULT 0`

AR model `cognition/models/src/agent_session.c` + `models/agent_session.h`, patterned on
`principal.c`: enum-as-text nowhere needed, before_validate clamps nothing but
validates ranges (`validates_money_range`), `AR_ADHOC_SAVE` upsert, find/list,
`agent_session_dump_state_json` registered in `diagnostics_dumpers.def`
(one DIAG_ENTRY row — the registry `#include`s the .def; no registry.c edit).

## Threat model — what this bounds, and what it does not

State this before the mechanism, because the mechanism only makes sense
against it.

**Bounds:** what a *cooperating* agent can move through the typed native
surface, and the audit trail of what it moved. Every dispatch that reaches a
money leaf while a grant is presented is capped, allowlisted, window-accounted,
revocable, expiring, and recorded in the reply's `authority` block.

**Does not bound:** an agent that does not cooperate. The grant is presented in
the agent's own environment, so the same agent can run `env -u
ZCL_AGENT_SESSION z23 …` and be the unbounded local operator; and it
holds the datadir, so it can read the RPC cookie and call `sendtoaddress`
straight over JSON-RPC, below the kernel entirely. Confining an agent is an
OS-level job — a separate uid with no read access to the cookie, or a wrapper
binary that injects the grant and refuses to exec anything else. This layer is
the bound an agent *runs under*, not a sandbox it is *held in*, and the
`authority` block exists so a transcript can be audited either way.

Do not write "the agent cannot widen" anywhere. It can, unless the OS stops it.

## Enforcement

`services/agent_spend_policy.h` — one evaluator, called from the two dispatch
choke points:

```c
void agent_spend_policy_evaluate(const char *session_id,
                                 const struct zcl_command_spec *spec,
                                 const struct json_value *input,
                                 bool committing,
                                 struct agent_spend_policy_decision *out);
void agent_spend_policy_release(const char *session_id,
                               const struct agent_spend_policy_decision *d);
```

### Default deny, keyed on the SPEC — not on the input's shape

Keying the gate on "the input carries an `amount`" is the trap, and it is worth
naming because the first cut fell into it. `core.wallet.address.export-key`
(READY, AUTH_OWNER, input keys `{address, confirm}`) carries no amount and
returns the raw spending key; `core.wallet.backup.now` carries no input at all
and writes a wallet backup the agent can read; `vault.session.create` carries
no amount and mints a fresh unbounded grant. Any one of those makes every cap,
allowlist, window and revocation irrelevant. Note that `export-key` is also
declared `RISK_READ`, so even "refuse RISK_WALLET" would have missed it —
nothing on a spec distinguishes "read the balance" from "read the private key".

So the policy classifies the LEAF and refuses what it does not understand:

| leaf | verdict |
|---|---|
| `vault.session.*` (the grant surface) | always `POLICY_NO_GRANT_MINT` |
| a listed spend leaf | gated on the parsed amount + recipient |
| a listed wallet read | allowed, nothing debited |
| anything else carrying `CAP_WALLET_REQUEST`, or that mutates, or `risk >= RISK_WALLET` | `POLICY_NOT_UNDERSTOOD` |
| a plain read | allowed |
| no spec at all | `POLICY_UNKNOWN_COMMAND` |

The listed surface is one table in `agent_spend_policy.c`, which also names
**which key carries the amount and which the recipient, per leaf** — that is why
`core.wallet.shielded.send` is gated on `to` and not on a guess. Adding a spend
leaf is a visible edit there, never a silent inheritance.

### Where the store lives, and who writes it

`agent_sessions` lives in `node.db`, and **the node process is its only
writer.** Both dispatch gates run in the short-lived CLI process, which never
boots the node and has no `node.db` — `app_runtime_set_current()` is called
only from `boot.c` / `boot_services.c`. So the CLI reaches the store the same
way every spend already does: one loopback RPC, `agentsession`, with
mint/list/revoke/authorize/release actions
(`controllers/agent_session_controller.h`, client side
`controllers/agent_session_client.h`). Opening `node.db` a second time from the
CLI was rejected: it is a second writer on a live node's database, which is the
cloned-ledger failure this codebase exists to avoid, and a write-lock hazard
against a node holding the tip. Requiring the node adds no new dependency —
the spend itself needs it too.

`authorize` performs the **check and the debit as one indivisible step**, under
a process-local mutex, with a targeted `UPDATE` of only the two window columns
guarded by `revoked=0`. Both halves matter:

- a check that read `spent`, returned, and let the caller write it back allowed
  N concurrent invocations to each pass a cap they jointly blew through;
- a debit that rewrote the whole row put `revoked` back to what it read, so a
  revocation landing in between was silently undone — the emergency lever lost
  to a routine spend.

`window_seconds` is bounded at one year (`AGENT_SESSION_WINDOW_SECONDS_MAX`) in
validation, at the mint surface, and by the table CHECK, and the roll is a
subtraction (`now - window_start >= window_seconds`). Unbounded, the sum
overflowed, every check read "already elapsed", and the per-window cap silently
stopped existing.

### Accounting: reserve on commit, release on failure

The debit is money that moved, not commands attempted:

- the gate runs **after** the lane/authority/capability checks, because it is
  the only one that writes — ahead of them, anyone who could reach it could
  drain an agent's window with commands that were then denied anyway;
- `committing` resolves the plan/commit gate the way handlers do, so a
  plan-stage preview enforces the caps and debits nothing;
- if the handler then reports no mutation (RPC unreachable, insufficient funds,
  a sovereignty refusal), the debit is released;
- the kernel gate is the **single** accounting point per invocation.
  `zcl_command_request` carries `agent_policy_settled`; `vault_dispatch` sees it
  and does not re-evaluate. It used to, on the forwarded input — which carries
  the same amount — so one `vault send` charged the window twice and a session
  whose window cap equalled its per-tx cap could never complete a single send.

Refusal tokens: `SESSION_INVALID`, `POLICY_AMOUNT`, `POLICY_TX_LIMIT`,
`POLICY_WINDOW_LIMIT`, `POLICY_RECIPIENT`, `POLICY_NO_GRANT_MINT`,
`POLICY_NOT_UNDERSTOOD`, `POLICY_UNKNOWN_COMMAND`, `POLICY_STORE`,
`NODE_UNREACHABLE`. Refusal `evidence` is the **redacted** grant id; the bearer
token is never re-printed into a transcript or a log line.

Hook points:
- **Kernel**: `zcl_command_registry_execute_json`, after the capability check
  and immediately before the handler. `zcl_command_context` gains
  `const char *agent_session` (NULL default; zero-init contexts unaffected).
- **Vault**: `vault_dispatch` — it calls `target->handler` directly, so the
  target never passes through `execute_json`. Only fires when the kernel gate
  did not already settle this invocation.

## Minting + presentation

- `vault.session.create --input='{"account":"<addr>","max_per_tx":..,"max_per_window":..,"window_seconds":..,"allowlist":"a,b,c","expires_in":..}'`
  (OWNER, plan/commit) → returns the `session_id` once. `vault.session.list`
  (redacted: no token echo), `vault.session.revoke --input='{"session_id":..,"confirm":true}'`.
  Registered in `engine/composition/commands/vault.def`; handlers in
  `native_vault_session_command.c` (no spend logic there — these are grants,
  not custody). All three go through the `agentsession` RPC, and all three are
  refused outright when a grant is presented.
- Presentation (v1): `ZCL_AGENT_SESSION=<session_id>`, read by the argv CLI
  context builder. Unset → the omnipotent local-operator context exactly as
  before this layer existed. Every reply carries an `authority` block naming
  `policy: bounded|exempt`, the redacted grant, and what was debited — so the
  exemption is stated rather than implied by absence, and two otherwise
  identical spends are distinguishable in a transcript.
- `app.auth.verify` reply gains `sessions_available: true` (no behavior change
  to the challenge flow).

## Tests

- `test_agent_session.c` (model): v36 migration; save/find/list/revoke; CHECK
  rejects negative/over-cap limits and an over-bound window; authorize
  accumulates, rolls, enforces both caps, and writes nothing when
  `commit=false`; a debit cannot un-revoke; release is in-window, clamped, and
  a no-op after a roll; the allowlist is exact-token.
- `test_agent_spend_policy.c`: the exemption; default-deny over
  export-key/import/backup.now/rescan and the whole grant surface; wallet reads
  free; the cap matrix; the allowlist per recipient key; amount INT/REAL/string
  plus junk/negative/absurd/missing; node-down fails closed; the kernel hook on
  **rendered bytes** (POLICY code, no plan body, redacted id, authority block);
  `vault send` debits exactly once; a failed handler gets the window back.
  It stands a real `rpc_table` in for the socket, so client → controller →
  service → model all run against a real tmp `node.db`. Substituting the
  transport and not the store is deliberate: hand-wiring `app_runtime` tests a
  path the shipped binary cannot take.
- `test_vault_dispatch.c`: the vault gate fires when the kernel did not, and
  does NOT fire when `agent_policy_settled` is set.
- `test_vault_session.c`: mint/list/revoke through the handlers over the same
  seam; the token is rendered in full exactly once.

## Explicit non-goals (v1)

- JSON-RPC spend gating (cookie path) — documented gap; see the threat model.
- OS-level agent confinement (separate uid / wrapper binary) — the only thing
  that makes this a sandbox rather than a bound.
- Mandatory-plan-commit policy knob — handlers already plan-by-default.
- Delegated/macaroon-style tokens, expiry refresh, per-command policies.
- Fee bounding: the caps bound the recipient amount, so actual outflow exceeds
  `max_per_tx` by the fee.
- REST write surface (stays operator-gated per AGENT_ARCHITECTURE.md:73).
