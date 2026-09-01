/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * shielded_gap_remedy_controller — a CONTAINED, VERIFY-ONLY remedy surface for
 * the shielded-history activation wedge (utxo_apply.anchor_backfill_gap /
 * utxo_apply.nullifier_backfill_gap).
 *
 * WHY THIS EXISTS
 * ----------------
 * When a snapshot/seed datadir holds only the current shielded frontier, every
 * historical Sprout/Sapling anchor root + nullifier below the reducer cursor is
 * absent.  anchor_kv/nullifier_kv fail those lookups CLOSED while their
 * activation cursors are positive, pinning H* at the wedge height behind two
 * PERMANENT typed blockers.  That is the SAFE state — but a bare permanent
 * blocker only names the symptom, not the cure.
 *
 * This controller turns that passive blocker into a NAMED, actionable remedy:
 * it surfaces the exact owner-run import command
 * (`-import-complete-shielded`, engine/services/src/shielded_history_import_service.c)
 * and the copy-prove step that MUST precede any live cutover
 * (tools/scripts/import-copy-prove.sh), together with an explicit CONTAINMENT
 * verdict for the node it is running on.
 *
 * WHAT IT IS NOT
 * ---------------
 * It is NOT a healer/repair rung: it NEVER executes the import, NEVER mutates
 * consensus state, and NEVER auto-runs anything.  `auto_execute` is structurally
 * false.  On any live-serving datadir it reports `refuses_live` and points the
 * operator at the copy-prove-first flow — exactly the containment
 * -import-complete-shielded itself enforces (engine/entry/main.c refuses live datadirs).
 * The remedy is only ever APPLIED by the operator, offline, against a throwaway
 * -COPY- datadir, gated on a green copy-prove.
 */
#ifndef ZCL_CONTROLLERS_SHIELDED_GAP_REMEDY_CONTROLLER_H
#define ZCL_CONTROLLERS_SHIELDED_GAP_REMEDY_CONTROLLER_H

#include <stdbool.h>

/* Which shielded-history gap blockers are currently present in the typed
 * blocker registry (a pure read of blocker_exists). */
enum shielded_gap_kind {
    SHIELDED_GAP_NONE = 0,          /* neither gap blocker present */
    SHIELDED_GAP_ANCHOR_ONLY = 1,   /* only utxo_apply.anchor_backfill_gap */
    SHIELDED_GAP_NULLIFIER_ONLY = 2,/* only utxo_apply.nullifier_backfill_gap */
    SHIELDED_GAP_BOTH = 3,          /* both present (the canonical wedge) */
};

enum shielded_gap_kind shielded_gap_remedy_classify(void);

/* Containment verdict for APPLYING the import on the node this process runs as.
 * Filled from the runtime datadir + operator lane.  The remedy is contained by
 * construction: `auto_execute` is always false; `refuses_live` is true unless
 * the runtime datadir is a throwaway copy-prove (-COPY-) datadir. */
struct shielded_gap_containment {
    bool auto_execute;          /* always false — structural, never auto-run */
    bool refuses_live;          /* true on any live-serving datadir/lane */
    bool datadir_is_live;       /* canonical/mint live datadir */
    bool datadir_is_copy_marked;/* throwaway -COPY- copy-prove datadir */
    char operator_lane[32];     /* canonical|soak|dev|copy|unknown */
    char datadir[1024];         /* runtime datadir (may be empty) */
    /* "refused_live_lane" | "eligible_offline_copy" */
    char apply_in_place[48];
};

void shielded_gap_remedy_eval_containment(struct shielded_gap_containment *out);

/* Diagnostics registry dumper: subsystem=shielded_gap_remedy.
 * See CLAUDE.md "Adding state introspection".  Reentrant-safe, allocates
 * nothing the caller does not own.  `key` is ignored. */
struct json_value;
bool shielded_gap_remedy_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_CONTROLLERS_SHIELDED_GAP_REMEDY_CONTROLLER_H */
