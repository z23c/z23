/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * The operational-vs-sovereign trust split, made explicit and enforced.
 * See docs/work/shielded-history-importer.md §5 for the design and
 * engine/modules/storage/include/storage/coins_kv.h (coins_kv_is_proven_authority,
 * coins_kv_contains_refold_marker, coins_kv_tip_is_self_derived) for the
 * two underlying provenance bits this module composes into one guard. */

#ifndef ZCL_CONTROLLERS_SOVEREIGNTY_CONTROLLER_H
#define ZCL_CONTROLLERS_SOVEREIGNTY_CONTROLLER_H

#include <stdbool.h>
#include <stddef.h>

struct json_value;

/* progress_meta keys for the two durable, monotonic trust-transition
 * timestamps (see sovereignty_dump_state_json's t_ready/t_sovereign below).
 * Exposed for tests that need to poke/inspect the stamp directly (mirrors
 * COINS_KV_MIGRATION_COMPLETE_KEY / SHIELDED_IMPORT_PROVENANCE_KEY). Value is
 * an 8-byte native-byte-order int64 wall-clock epoch-seconds blob, written
 * ONCE (checked-then-set under progress_store_tx_lock so concurrent
 * first-observers can't race a later timestamp in over the true first). */
#define SOVEREIGNTY_T_READY_KEY     "sovereignty.t_ready"
#define SOVEREIGNTY_T_SOVEREIGN_KEY "sovereignty.t_sovereign"

/* `z23 dumpstate sovereignty` — also folded into `z23 status`'s
 * trust-tier surface (event_agent_summary.c -> agent_summary_posture_cache.c).
 * Reports coins_kv_proven_authority, self_folded_marker, coins_applied_height,
 * hstar, self_derived_tip_static_checks (the G-SOV parts 2+3 predicate),
 * self_derived_reason, authority_posture, trust_mode
 * ("sovereign" | "release_assisted" | "bare"), what is gated at the
 * current posture, and the durable t_ready/t_sovereign transition stamps
 * (see SOVEREIGNTY_T_READY_KEY doc above and the stamping note on
 * sovereignty_guard_allow). `key` is unused (NULL-safe). SELECT-only apart
 * from the idempotent stamp-if-absent write, reentrant-safe; `out` is
 * caller-initialized (json_set_object done here).
 *
 * Never blocks on the progress store: it trylocks and, when a reducer fold
 * or the shielded-history importer owns progress_store_tx_lock, answers
 * from a process-wide last-known-good trust-tier cache instead of queuing —
 * `durable_store_status` is "available" (fresh read), "busy_stale_cache"
 * (busy, but a prior successful read populated the cache), or
 * "unknown_progress_store_busy" (busy, nothing observed yet). This dumper's
 * busy branch returns before ever reaching sovereignty_guard_allow() below,
 * so it never inherits that function's blocking behavior. */
bool sovereignty_dump_state_json(struct json_value *out, const char *key);

/* Machine-readable trust_mode used by both the dumper above and
 * core.status/core.status.brief so every surface agrees on the same word:
 *   "sovereign"          — self-folded coin set (checkpoint/from-genesis
 *                           derived); mint/spend/re-serve all unlocked.
 *   "release_assisted"   — coins_kv is proven-authority (populated,
 *                           self-consistent, can serve tip) but NOT
 *                           self-folded — a borrowed zclassicd-chainstate
 *                           copy. Tip-following/serving stays allowed;
 *                           mint and wallet spend are refused.
 *   "bare"                — coins_kv is not yet proven-authority (a fresh /
 *                           mid-sync / from-genesis-folding datadir that
 *                           never went through a borrowed-snapshot seed).
 *                           Treated as sovereign-eligible: G-SOV part 3's
 *                           first disjunct (!proven_authority) already
 *                           holds, so mint/spend are allowed once the
 *                           continuity check (part 2) also holds. */
const char *sovereignty_trust_mode(bool proven_authority, bool self_folded);

/* THE sovereign guard for a consequential action: the mint/mining entry
 * (mining_controller.c) and the wallet-spend entry (wallet_shielded_send.c
 * rpc_z_sendmany, which covers t->t / t->z / z->t / z->z). Returns true when
 * the action is ALLOWED under the current trust posture; false when REFUSED,
 * with a short machine-readable reason written to `reason` (nul-terminated,
 * truncated to reason_cap; NULL/0 to skip). `action` is a short tag used only
 * in the log line (e.g. "mint", "wallet_spend").
 *
 * Mirrors the existing snapshot-export gate (engine/composition/src/bundle_exporter.c
 * bx_qualified): typed, named refusal, never a bare `return false`. Refuses
 * exactly the borrowed-and-not-self-folded posture (coins_kv_tip_is_self_
 * derived()==false) — it does NOT gate tip-following: the reducer forward
 * fold, P2P relay, explorer, and wallet *viewing* are never touched here.
 * Never mutates coins_kv. The only progress.kv write this function can cause
 * is the idempotent t_ready/t_sovereign stamp-if-absent (SOVEREIGNTY_T_READY_
 * KEY / SOVEREIGNTY_T_SOVEREIGN_KEY above) — a one-shot durable timestamp,
 * not a state mutation; every provenance predicate stays SELECT-only.
 * Fail-closed: a missing progress store refuses rather than silently
 * allowing the action. */
bool sovereignty_guard_allow(const char *action, char *reason,
                             size_t reason_cap);

#endif
