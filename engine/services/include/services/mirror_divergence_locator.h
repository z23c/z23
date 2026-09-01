/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mirror_divergence_locator — fail-loud validation pack, check 6.
 *
 * A mirror hash-disagreement blocker that only fires identical quiet
 * warnings lets the node SERVE a poisoned
 * chain. Disagreement alone is not actionable; the operator needs WHERE
 * the chains diverge. On a hash-disagreement this locator binary-searches
 * the first diverging height against the co-located zclassicd (bounded
 * ~22 getblockhash probes over 3.2M heights), then emits ONE loud
 * EV_OPERATOR_NEEDED with (first_diverging_height, ours, theirs),
 * registers the PERMANENT `mirror.divergence_located` blocker (distinct
 * from the existing rate-limited transient `mirror.hash-disagreement`,
 * which stays as-is), latches the HOLD (a node serving a poisoned chain
 * must not extend it), and feeds oracle_policy_record_disagreement.
 *
 * FALSE-POSITIVE DISCIPLINE (the healthy-fork rule): a disagreement whose
 * first diverging height sits INSIDE the confirmation window of the tip
 * (first_div > disagree_height - MDL_CONFIRM_DEPTH) is indistinguishable
 * from a healthy transient state — a natural 1-block fork (we hold A at h,
 * zclassicd holds competing B until the next block, ~2.5 min) or a
 * one-tick lag behind zclassicd's own reorg switch. Latching a HOLD there
 * would refuse the very reorg that resolves the fork. So a tip-window
 * divergence is logged + counted but NOT escalated until it either
 * (a) re-locates at confirmed depth (the chains stayed split while a side
 * advanced), or (b) persists at the SAME first_div across repeated locates
 * spanning >= MDL_CONFIRM_PERSIST_SECS (the wedged-at-tip shape; a healthy
 * fork lasting that long is ~e^-10). Tip agreement observed by the mirror
 * verify path clears everything (same self-clear discipline as the window
 * sweep): identical tip hash on a hash-linked chain implies identical
 * history, so any located divergence below an agreeing tip is stale.
 *
 * Rate limits: re-locates at most once per 10 minutes; re-pages only when
 * first_div changes. Aborts silently on RPC errors (the existing
 * mirror.rpc-unreachable blocker covers that) and on a transient
 * disagreement that re-verifies as agreement. Crash-only: never FATAL. */

#ifndef ZCL_SERVICES_MIRROR_DIVERGENCE_LOCATOR_H
#define ZCL_SERVICES_MIRROR_DIVERGENCE_LOCATOR_H

#include <stdbool.h>
#include <stdint.h>

/* Depth below the disagreeing tip at which a located divergence is
 * CONFIRMED (not a transient tip fork). ~6 blocks = ~15 min of chain. */
#define MDL_CONFIRM_DEPTH         6
/* A tip-window divergence pinned at the SAME first_div for this long is
 * escalated anyway (the wedged-at-tip shape). With the 600 s relocate
 * rate limit this is the third consecutive locate. */
#define MDL_CONFIRM_PERSIST_SECS  1500

/* Entry point, called from the legacy-mirror hash-disagreement sites.
 * Runs inline on the mirror tick thread (seconds, bounded by the RPC
 * timeouts). Returns the located first diverging height, or -1 when the
 * run was skipped/aborted (rate-limited, RPC error, transient). A
 * located-but-unconfirmed tip-window divergence also returns the height
 * (it is real information) — it just does not blocker/page/HOLD yet. */
int mirror_divergence_locate(int disagree_height);

/* Called by the mirror verify path on tip AGREEMENT. Clears any pending
 * (unconfirmed) divergence and self-clears a latched
 * mirror.divergence_located blocker + HOLD: an agreeing tip hash implies
 * an identical chain below it, so the located divergence resolved. */
void mirror_divergence_note_agreement(int height);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool mirror_divergence_dump_state_json(struct json_value *out,
                                       const char *key);

#ifdef ZCL_TESTING
/* Probe injection: local/remote hash-at-height (65-byte hex out).
 * NULL restores the production probes. */
typedef bool (*mdl_probe_fn)(int height, char out_hex[65]);
void mirror_divergence_set_probes_for_testing(mdl_probe_fn local,
                                              mdl_probe_fn remote);
void mirror_divergence_reset_for_testing(void);
int  mirror_divergence_probes_last_run_for_testing(void);
/* Simulate `secs` of wall time passing: ages the pending (unconfirmed)
 * divergence record AND the relocate rate-limit stamp, so tests can cross
 * MDL_CONFIRM_PERSIST_SECS / MDL_RELOCATE_MIN_SECS without sleeping. */
void mirror_divergence_backdate_pending_for_testing(int64_t secs);
#endif

#endif /* ZCL_SERVICES_MIRROR_DIVERGENCE_LOCATOR_H */
