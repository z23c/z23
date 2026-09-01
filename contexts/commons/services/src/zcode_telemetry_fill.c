/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcode_dump_state_fill — the `zcode` domain's one telemetry collector.
 * Contract: services/zcode_telemetry.h. Field names, units, tiers, health
 * rules and meanings: util/telemetry/zcode_fields.def.
 *
 * THE THREE RULES THIS FILE OBEYS, because each is a defect class the
 * telemetry layer exists to remove:
 *
 *   1. It writes no JSON. Every value goes into the typed snapshot through
 *      the TELEMETRY_SET_* / TELEMETRY_*_LEAF macros, which write the value
 *      and its provenance together. A json_push_kv_* here fails the lint
 *      gate, and rightly: a collector that hand-writes JSON has taken back
 *      the naming and the omission the table-driven renderer took away.
 *
 *   2. It decides no health. There is no threshold, no "if this then bad",
 *      no reason string that reads as a verdict in this file. The rules live
 *      in the field table and telemetry_ontology_annotate() is the only
 *      evaluator.
 *
 *   3. It never blocks and never scans. The only node state it touches is
 *      three argv flags (lock-free), one plain pointer load, and one
 *      trylock-guarded O(1)-per-package read of the package store. A lost
 *      trylock is reported as UNAVAILABLE with a static token, so "the store
 *      was busy" and "the store holds nothing" can never be confused.
 */

// one-result-type-ok:telemetry-fill-provider — a `<domain>_dump_state_fill`
// collector cannot return struct zcl_result. Its shape is fixed in two places
// this file does not own: util/telemetry_render.h's provider contract, and
// check_dumper_never_blocks.sh, whose scanner only recognises a definition
// returning bool, void or int — a zcl_result return would make this collector
// invisible to the very gate that proves it never blocks, which is a far worse
// trade than a bool. There is also nothing for a result to carry: every real
// failure this file can meet (hosting off, store closed, lock contended) is
// reported IN the snapshot as a presence plus a static reason token, which is
// strictly more information than an error return, and the only false path is a
// NULL argument, which is a caller bug and is logged.

#include "services/zcode_telemetry.h"

#include "util/log_macros.h"
#include "util/telemetry_render.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"

/* Static reason tokens. Short, greppable, never formatted and never prose:
 * they are matched by operators and by tests, not read as sentences. */
#define ZCODE_TL_REASON_BUSY "package_store_busy"
#define ZCODE_TL_REASON_CLOSED "package_store_not_open"

/* Every store-backed leaf, in one place, so the three non-OK paths below
 * cannot disagree about which leaves they cover. Adding a store leaf to the
 * field table without adding it here leaves it UNSET on the closed/busy
 * paths, which the renderer reports as a counted provider defect — the
 * failure is loud, not silent. */
#define ZCODE_STORE_LEAF_APPLY(fn_, snap_, arg_)                              \
    do {                                                                      \
        fn_((snap_), quota_bytes, (arg_));                                    \
        fn_((snap_), tracked_packages, (arg_));                               \
        fn_((snap_), cas_chunks, (arg_));                                     \
        fn_((snap_), manifest_bytes_total, (arg_));                           \
        fn_((snap_), evictions_total, (arg_));                                \
        fn_((snap_), gc_orphans_total, (arg_));                               \
        fn_((snap_), quota_rejects_total, (arg_));                            \
        fn_((snap_), last_release_accept, (arg_));                            \
    } while (0)

/* The store is closed. That is a real answer about this node's configuration,
 * not a failed read, so the leaves are NOT_APPLICABLE rather than
 * UNAVAILABLE: `completeness.complete` stays true and nobody is sent to
 * diagnose a store that was never meant to be open. */
static void zcode_store_not_applicable(struct zcode_snapshot *snap)
{
    ZCODE_STORE_LEAF_APPLY(TELEMETRY_NOT_APPLICABLE_LEAF, snap,
                           ZCODE_TL_REASON_CLOSED);
}

/* A store IS open and we lost the race for its lock. This one is a genuine
 * failed read: the numbers exist, we could not see them this call, and
 * `completeness.complete` must go false so a caller knows to re-ask. */
static void zcode_store_unavailable(struct zcode_snapshot *snap)
{
    ZCODE_STORE_LEAF_APPLY(TELEMETRY_UNAVAILABLE_LEAF, snap,
                           ZCODE_TL_REASON_BUSY);
}

static void zcode_store_present(struct zcode_snapshot *snap,
                                const struct vcs_package_store_totals *t)
{
    TELEMETRY_SET_I64(snap, quota_bytes, t->quota_bytes,
                      TELEMETRY_SRC_CONFIG);
    TELEMETRY_SET_I64(snap, tracked_packages, t->tracked_packages,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(snap, cas_chunks, t->cas_chunks,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(snap, manifest_bytes_total, t->manifest_bytes_total,
                      TELEMETRY_SRC_DERIVED);
    TELEMETRY_SET_I64(snap, evictions_total, t->evictions_total,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(snap, gc_orphans_total, t->gc_orphans_total,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(snap, quota_rejects_total, t->quota_rejects_total,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_TEXT(snap, last_release_accept, t->last_release_accept,
                       TELEMETRY_SRC_IN_PROCESS);
}

bool zcode_dump_state_fill(struct zcode_snapshot *snap)
{
    if (!snap)
        LOG_FAIL("zcode.telemetry", "fill: null snapshot");

    TELEMETRY_SET_I64(snap, collected_unix, telemetry_now_unix(),
                      TELEMETRY_SRC_IN_PROCESS);

    /* argv, read lock-free. `hosting_enabled` is a fact about configuration
     * and is true even when nothing has opened a store yet — the pair of it
     * and store_open is what an operator reads, which is why neither is
     * judged. */
    TELEMETRY_SET_BOOL(snap, hosting_enabled,
                       vcs_package_store_hosting_enabled(),
                       TELEMETRY_SRC_CONFIG);

    struct vcs_package_store_totals totals;
    enum vcs_package_store_totals_result r =
        vcs_package_store_try_totals(&totals);
    switch (r) {
    case VCS_PACKAGE_STORE_TOTALS_OK:
        TELEMETRY_SET_BOOL(snap, store_open, true, TELEMETRY_SRC_IN_PROCESS);
        zcode_store_present(snap, &totals);
        break;
    case VCS_PACKAGE_STORE_TOTALS_CLOSED:
        TELEMETRY_SET_BOOL(snap, store_open, false, TELEMETRY_SRC_IN_PROCESS);
        zcode_store_not_applicable(snap);
        break;
    case VCS_PACKAGE_STORE_TOTALS_BUSY:
        /* Contended at the global level: we never saw the pointer, so even
         * store_open is unknown. Reporting `false` here would say "no store"
         * about a node that is busy writing into one. */
        TELEMETRY_UNAVAILABLE_LEAF(snap, store_open, ZCODE_TL_REASON_BUSY);
        zcode_store_unavailable(snap);
        break;
    case VCS_PACKAGE_STORE_TOTALS_NULL:
        /* Unreachable: `totals` is a stack object. Handled anyway so the
         * switch is total and a future result value cannot fall through into
         * leaving leaves UNSET. */
        TELEMETRY_UNAVAILABLE_LEAF(snap, store_open, ZCODE_TL_REASON_BUSY);
        zcode_store_unavailable(snap);
        break;
    }

    /* Plain pointer load, published by the transport glue at boot; no lock
     * exists to contend for, so this leaf is always present. What it can and
     * cannot tell you is stated in the field table's `means`. */
    TELEMETRY_SET_BOOL(snap, engine_running,
                       vcs_swarm_engine_global() != NULL,
                       TELEMETRY_SRC_IN_PROCESS);
    return true;
}
