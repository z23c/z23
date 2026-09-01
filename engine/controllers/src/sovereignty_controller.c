/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * The operational-vs-sovereign trust split, made explicit and enforced.
 *
 * coins_kv_is_proven_authority() is true for BOTH a self-derived coin set
 * AND a borrowed zclassicd-chainstate copy — "the store is populated and
 * self-consistent, can serve tip" (the OPERATIONAL bit).
 * coins_kv_contains_refold_marker() (COINS_KV_SELF_FOLDED_KEY) is the
 * separate SOVEREIGN bit: the set was produced by a self-derived /
 * checkpoint-verified path, never the borrow. coins_kv_tip_is_self_derived()
 * is the composite G-SOV predicate (parts 2+3): continuous
 * coins_applied_height coverage AND (not-borrowed OR self-folded).
 *
 * Before this module, only snapshot/bundle export was gated on the split
 * (engine/composition/src/bundle_exporter.c bx_qualified,
 * engine/composition/src/consensus_state_snapshot_export_proof.c,
 * engine/composition/src/boot_snapshot_offer.c) — mining and wallet spending were NOT,
 * so an operator could mint or spend on a borrowed shielded history. This
 * file closes that gap with one guard, sovereignty_guard_allow(), called
 * from the mint entry (engine/controllers/src/mining_controller.c) and the
 * wallet-spend entry (contexts/wallet/controllers/src/wallet_shielded_send.c
 * rpc_z_sendmany — covers t->t / t->z / z->t / z->z). Tip-FOLLOWING (the
 * reducer forward fold, P2P relay, explorer, wallet viewing) is never
 * gated. See docs/work/shielded-history-importer.md §5. */

#include "controllers/sovereignty_controller.h"

#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "services/shielded_history_import_service.h"
#include "services/sync_trust_policy.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ── Shielded-import provenance introspection ──────────────────────────
 *
 * Per-pool row counts (sprout_anchors/sapling_anchors/nullifiers, the same
 * tables shielded_history_import_from_chainstate streams into — see
 * engine/services/src/shielded_history_import_service.c) plus the
 * shielded_import.provenance metadata row that importer stamps in the same
 * atomic transaction on a successful commit. SELECT-only: a missing table
 * (no import has ever run on this datadir) or a missing provenance row is a
 * normal, quiet zero/absent result, never a warning. */

static bool sov_table_exists(sqlite3 *db, const char *table)
{
    if (!db || !table)
        return false;
    sqlite3_stmt *stmt = NULL;
    bool exists = false;
    int rc = sqlite3_prepare_v2(db,  // raw-controller-sql-ok:sovereignty-readonly-table-exists
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, table, -1, SQLITE_STATIC);
        exists = sqlite3_step(stmt) == SQLITE_ROW;  // raw-sql-ok:read-only-introspection
    }
    if (stmt)
        sqlite3_finalize(stmt);
    return exists;
}

static int64_t sov_count_rows(sqlite3 *db, const char *table,
                              const char *where_clause)
{
    if (!db || !sov_table_exists(db, table))
        return 0;
    char sql[192];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s%s", table,
             where_clause ? where_clause : "");
    sqlite3_stmt *stmt = NULL;
    int64_t val = 0;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);  // raw-controller-sql-ok:sovereignty-readonly-pool-count
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW)  // raw-sql-ok:read-only-introspection
            val = sqlite3_column_int64(stmt, 0);
    } else {
        LOG_WARN("sovereignty", "pool count query prepare failed: %s [%s]",
                 sqlite3_errmsg(db), sql);
    }
    if (stmt)
        sqlite3_finalize(stmt);
    return val;
}

/* ── Durable trust-transition timestamps (t_ready / t_sovereign) ───────
 *
 * First-reached instants for two trust milestones, stamped ONCE into
 * progress_meta (8-byte native int64 wall-clock epoch seconds) at the
 * moment this module observes the transition — monotonic: never
 * overwritten by a later call, never cleared by a later posture
 * regression (a repair that later drops self_folded does NOT clear
 * t_sovereign; the CURRENT posture is the separate trust_state/trust_mode
 * fields above, t_sovereign always answers "was this datadir EVER
 * sovereign"). See services/sync_trust_policy.h for the trust_state ladder:
 *   t_ready:     first instant `st` granted SYNC_CAP_SERVE_VALIDATED_TIP
 *                (RELEASE_ASSISTED_READY, PEER_ASSISTED_READY,
 *                ARTIFACT_VERIFIED, SOVEREIGN) — the node first became able
 *                to serve a validated tip on installed/proven state.
 *   t_sovereign: first instant `st` was SOVEREIGN or ARTIFACT_VERIFIED
 *                (self_derived, i.e. S holds) — the LANE SPEC's
 *                "SOVEREIGN or ARTIFACT_VERIFIED (self-derived)".
 *
 * Hooked at both existing trust-derivation call sites in this file
 * (sovereignty_guard_allow and sovereignty_dump_state_json) — no new
 * polling thread. The read-then-conditional-write is wrapped in one
 * progress_store_tx_lock scope (the lock is recursive, so nesting into
 * progress_meta_get_blob_exact/progress_meta_set is safe) so two racing
 * first-observers cannot both write, which would let the later of the two
 * timestamps win instead of the true first. */

static void sov_stamp_if_absent(sqlite3 *pdb, const char *key,
                                const char *label)
{
    if (!pdb || !key)
        return;
    progress_store_tx_lock();
    int64_t stamp = 0;
    size_t n = 0;
    bool found = false;
    bool ok = progress_meta_get_blob_exact(pdb, key, &stamp, sizeof(stamp),
                                           &n, &found);
    if (ok && (!found || n != sizeof(stamp))) {
        int64_t now = (int64_t)platform_time_wall_time_t();
        if (!progress_meta_set(pdb, key, &now, sizeof(now)))
            LOG_WARN("sovereignty", "%s stamp write failed key=%s",
                     label, key);
    } else if (!ok) {
        LOG_WARN("sovereignty", "%s stamp read failed key=%s", label, key);
    }
    progress_store_tx_unlock();
}

/* Stamp t_ready / t_sovereign (if not already stamped) for a freshly
 * derived `st`. Cheap: at most two progress_meta reads plus, on the rare
 * first transition, one write. */
static void sov_stamp_transitions(sqlite3 *pdb, enum sync_trust_state st)
{
    if (sync_trust_cap_allowed(st, SYNC_CAP_SERVE_VALIDATED_TIP))
        sov_stamp_if_absent(pdb, SOVEREIGNTY_T_READY_KEY, "t_ready");
    if (st == SYNC_TRUST_SOVEREIGN || st == SYNC_TRUST_ARTIFACT_VERIFIED)
        sov_stamp_if_absent(pdb, SOVEREIGNTY_T_SOVEREIGN_KEY, "t_sovereign");
}

/* Render a stamped transition key as {"epoch": N, "iso8601": "..."}, or
 * JSON null when the transition has not yet been observed on this datadir.
 * `field` is caller-owned (json_init'd here); SELECT-only. */
static void sov_render_stamp(sqlite3 *pdb, const char *key,
                             struct json_value *field)
{
    json_init(field);
    int64_t stamp = 0;
    size_t n = 0;
    bool found = false;
    bool ok = pdb && progress_meta_get_blob_exact(pdb, key, &stamp,
                                                   sizeof(stamp), &n, &found);
    if (!ok || !found || n != sizeof(stamp)) {
        json_set_null(field);
        return;
    }
    json_set_object(field);
    json_push_kv_int(field, "epoch", stamp);
    time_t stamp_t = (time_t)stamp;
    struct tm tm_utc;
    char iso[24] = {0};
    if (gmtime_r(&stamp_t, &tm_utc) &&
        strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%SZ", &tm_utc) > 0)
        json_push_kv_str(field, "iso8601", iso);
    else
        json_push_kv_str(field, "iso8601", "");
}

/* ── Last-known-good trust-tier cache (busy-path fallback) ──────────────
 *
 * sovereignty_dump_state_json backs `z23 status`'s trust-tier surface
 * (event_agent_summary.c -> agent_summary_posture_cache.c). The reducer drive
 * and the shielded-history importer both hold progress_store_tx_lock for
 * extended stretches, so a BLOCKING acquire in a diagnostics/status path
 * would take the whole front door dark exactly when an operator most wants
 * it (the same class of bug commit cc4de081a fixed for refold_progress.c /
 * validate_headers_stage.c — its message names `z23 status` as a
 * victim). This cache lets the busy branch answer truthfully-but-stale
 * instead of queuing: same shape as agent_security_posture.c's
 * g_posture_cache / posture_cache_store / posture_cache_load — a plain
 * mutex (never the progress-store lock) around a tiny struct copy. */
struct sov_trust_cache {
    char trust_mode[24];
    char authority_posture[40];
    char trust_state[32];
};

static pthread_mutex_t g_sov_trust_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static struct sov_trust_cache g_sov_trust_cache;
static bool g_sov_trust_cache_valid;

static void sov_trust_cache_store(const char *trust_mode,
                                  const char *authority_posture,
                                  const char *trust_state)
{
    pthread_mutex_lock(&g_sov_trust_cache_lock);
    snprintf(g_sov_trust_cache.trust_mode, sizeof(g_sov_trust_cache.trust_mode),
             "%s", trust_mode ? trust_mode : "");
    snprintf(g_sov_trust_cache.authority_posture,
             sizeof(g_sov_trust_cache.authority_posture), "%s",
             authority_posture ? authority_posture : "");
    snprintf(g_sov_trust_cache.trust_state,
             sizeof(g_sov_trust_cache.trust_state), "%s",
             trust_state ? trust_state : "");
    g_sov_trust_cache_valid = true;
    pthread_mutex_unlock(&g_sov_trust_cache_lock);
}

/* Copy the cache out under the mutex; returns false (out left untouched) when
 * no successful trylock-path collection has ever published one yet. */
static bool sov_trust_cache_load(struct sov_trust_cache *out)
{
    bool ok;
    if (!out)
        return false;
    pthread_mutex_lock(&g_sov_trust_cache_lock);
    ok = g_sov_trust_cache_valid;
    if (ok)
        *out = g_sov_trust_cache;
    pthread_mutex_unlock(&g_sov_trust_cache_lock);
    return ok;
}

const char *sovereignty_trust_mode(bool proven_authority, bool self_folded)
{
    if (!proven_authority)
        return "bare";
    return self_folded ? "sovereign" : "release_assisted";
}

bool sovereignty_guard_allow(const char *action, char *reason,
                             size_t reason_cap)
{
    if (reason && reason_cap)
        reason[0] = '\0';

    sqlite3 *pdb = progress_store_db();
    if (!pdb) {
        if (reason && reason_cap)
            snprintf(reason, reason_cap, "progress_store_unavailable");
        LOG_WARN("sovereignty", "%s refused: progress store not open",
                 action ? action : "(action)");
        return false;
    }

    int32_t hstar = reducer_frontier_provable_tip_cached();
    char why[96] = {0};
    /* Read the three provenance predicates under one consistent recursive-lock
     * scope and derive the trust state once, then route the action's allow
     * decision through the central capability table (services/sync_trust_
     * policy.h). coins_kv_is_proven_authority / coins_kv_contains_refold_marker
     * do NOT self-lock; coins_kv_tip_is_self_derived acquires the recursive lock
     * internally and nests cleanly (same pattern as sovereignty_dump_state_json
     * below). MINE and WALLET_SPEND are each granted exactly in the S states
     * (ARTIFACT_VERIFIED, SOVEREIGN), so the routed decision is identical to the
     * old bare `self_derived` gate — this centralizes the provenance bit only,
     * it does not change or weaken the gate. */
    progress_store_tx_lock();
    bool proven = coins_kv_is_proven_authority(pdb, NULL);
    bool refold = coins_kv_contains_refold_marker(pdb);
    bool self_derived = coins_kv_tip_is_self_derived(pdb, hstar, why,
                                                     sizeof(why));
    progress_store_tx_unlock();

    enum sync_trust_state st = sync_trust_derive(proven, refold, self_derived);
    sov_stamp_transitions(pdb, st);
    enum sync_capability cap = (action && strcmp(action, "mint") == 0)
                                   ? SYNC_CAP_MINE
                                   : SYNC_CAP_WALLET_SPEND;
    if (!sync_trust_cap_allowed(st, cap)) {
        if (reason && reason_cap)
            snprintf(reason, reason_cap, "release_assisted: %s",
                     why[0] ? why : "not_self_derived");
        LOG_WARN("sovereignty",
                 "%s refused — tip is release_assisted (borrowed shielded "
                 "history, not self-folded): %s",
                 action ? action : "(action)", why[0] ? why : "unknown");
        return false;
    }
    return true;
}

/* One capability the v2 dumper reports, with its stable JSON key. */
struct sov_cap_entry {
    const char *key;
    enum sync_capability cap;
};

static const struct sov_cap_entry k_sov_caps[] = {
    { "serve_validated_tip", SYNC_CAP_SERVE_VALIDATED_TIP },
    { "wallet_receive",      SYNC_CAP_WALLET_RECEIVE },
    { "wallet_spend",        SYNC_CAP_WALLET_SPEND },
    { "mine",                SYNC_CAP_MINE },
    { "export_bundle",       SYNC_CAP_EXPORT_BUNDLE },
    { "seed_bundle",         SYNC_CAP_SEED_BUNDLE },
};

/* Short, derivable reason for a capability's allow/deny under `st` — the
 * missing provenance rung, named. Pure: no persistence, no clock. */
static const char *sov_cap_reason(enum sync_trust_state st,
                                  enum sync_capability cap)
{
    if (sync_trust_cap_allowed(st, cap))
        return "granted";
    switch (cap) {
    case SYNC_CAP_SERVE_VALIDATED_TIP:
    case SYNC_CAP_WALLET_RECEIVE:
        return "requires_proven_authority";
    case SYNC_CAP_WALLET_SPEND:
    case SYNC_CAP_MINE:
    case SYNC_CAP_SEED_BUNDLE:
        return "requires_self_derived";
    case SYNC_CAP_EXPORT_BUNDLE:
        return "requires_self_folded";
    case SYNC_CAP_DIRECTORY_INFLUENCE:
        /* Not a provenance rung: the provenance state table never grants this
         * bit (see services/sync_trust_policy.h). The live answer comes from
         * services/directory_influence_policy.h. */
        return "requires_uncontested_network";
    case SYNC_CAP_NONE:
        break;
    }
    return "denied";
}

bool sovereignty_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    sqlite3 *pdb = progress_store_db();
    bool progress_open = pdb != NULL;

    /* Observability must never queue behind a fold/backfill. Trylock
     * non-blocking and, on a miss, answer from the last-known-good cache
     * above rather than blocking an RPC/status worker — mirrors the A2/
     * diagnostics-sweep trylock fix (refold_progress.c /
     * validate_headers_report.c, cc4de081a). sovereignty_guard_allow()
     * itself stays BLOCKING (enforcement gate, must be fresh) — this dumper
     * returns before ever reaching its guard-probe calls below when busy, so
     * it never inherits that block. */
    bool progress_locked = progress_open && progress_store_tx_trylock();
    if (progress_open && !progress_locked) {
        struct sov_trust_cache cached;
        bool have_cache = sov_trust_cache_load(&cached);
        json_push_kv_str(out, "schema", "zcl.sovereignty.v2");
        json_push_kv_int(out, "schema_version", 2);
        json_push_kv_bool(out, "progress_store_open", true);
        json_push_kv_str(out, "durable_store_status",
                         have_cache ? "busy_stale_cache"
                                    : "unknown_progress_store_busy");
        json_push_kv_bool(out, "served_from_cache", have_cache);
        json_push_kv_str(out, "trust_mode",
                         have_cache ? cached.trust_mode : "unknown");
        json_push_kv_str(out, "authority_posture",
                         have_cache ? cached.authority_posture
                                    : "unknown_progress_store_busy");
        json_push_kv_str(out, "trust_state",
                         have_cache ? cached.trust_state : "unknown");
        return true;
    }

    bool applied_found = false;
    bool applied_ok = false;
    bool proven_authority = false;
    bool self_folded = false;
    bool hstar_ok = false;
    bool coins_cover_hstar = false;
    bool self_derived = false;
    int32_t applied = -1;
    int32_t hstar = -1;
    int32_t served_floor = -1;
    char self_reason[128] = "progress_store_not_open";
    int64_t sprout_anchor_rows = 0;
    int64_t sapling_anchor_rows = 0;
    int64_t sprout_nullifier_rows = 0;
    int64_t sapling_nullifier_rows = 0;
    char provenance[320] = {0};
    bool provenance_present = false;

    if (progress_locked) {
        applied_ok = coins_kv_get_applied_height(pdb, &applied,
                                                 &applied_found);
        proven_authority = coins_kv_is_proven_authority(pdb, NULL);
        self_folded = coins_kv_contains_refold_marker(pdb);
        hstar_ok = reducer_frontier_compute_hstar(pdb, &hstar, &served_floor);
        if (hstar_ok) {
            coins_cover_hstar = applied_ok && applied_found &&
                applied >= hstar + 1;
            self_derived = coins_kv_tip_is_self_derived(
                pdb, hstar, self_reason, sizeof(self_reason));
            if (self_derived)
                snprintf(self_reason, sizeof(self_reason), "ok");
        } else {
            snprintf(self_reason, sizeof(self_reason), "hstar_unavailable");
        }

        /* Per-pool shielded-history row counts + the importer's provenance
         * stamp (see the sov_* helpers above) — same lock scope as the reads
         * above; progress_meta_get recursively acquires progress_store_tx_lock
         * itself, matching the coins_kv_tip_is_self_derived precedent. */
        sprout_anchor_rows = sov_count_rows(pdb, "sprout_anchors", NULL);
        sapling_anchor_rows = sov_count_rows(pdb, "sapling_anchors", NULL);
        sprout_nullifier_rows = sov_count_rows(pdb, "nullifiers",
                                               " WHERE pool=0");
        sapling_nullifier_rows = sov_count_rows(pdb, "nullifiers",
                                                " WHERE pool=1");
        size_t prov_len = 0;
        bool prov_found = false;
        bool prov_ok = progress_meta_get(pdb, SHIELDED_IMPORT_PROVENANCE_KEY,
                                         provenance, sizeof(provenance) - 1,
                                         &prov_len, &prov_found);
        if (prov_ok && prov_found) {
            size_t copy = prov_len < sizeof(provenance) - 1
                              ? prov_len : sizeof(provenance) - 1;
            provenance[copy] = '\0';
            provenance_present = true;
        } else {
            provenance[0] = '\0';
        }
        progress_store_tx_unlock();
    }

    const char *authority_posture =
        !progress_open ? "unknown_no_progress_store" :
        !proven_authority ? "not_proven" :
        self_folded ? "self_folded_marker_present" :
        "proven_but_not_self_folded";
    const char *trust_mode = sovereignty_trust_mode(proven_authority,
                                                     self_folded);

    json_push_kv_str(out, "schema", "zcl.sovereignty.v2");
    json_push_kv_int(out, "schema_version", 2);
    json_push_kv_bool(out, "progress_store_open", progress_open);
    json_push_kv_str(out, "durable_store_status",
                     !progress_open ? "progress_store_unavailable"
                                    : "available");
    json_push_kv_bool(out, "coins_kv_proven_authority", proven_authority);
    json_push_kv_bool(out, "self_folded_marker", self_folded);
    json_push_kv_bool(out, "hstar_available", hstar_ok);
    json_push_kv_int(out, "hstar", hstar_ok ? hstar : -1);
    json_push_kv_bool(out, "coins_applied_height_present", applied_found);
    json_push_kv_int(out, "coins_applied_height",
                     applied_found ? applied : -1);
    json_push_kv_bool(out, "coins_cover_hstar", coins_cover_hstar);
    json_push_kv_bool(out, "self_derived_tip_static_checks", self_derived);
    json_push_kv_str(out, "self_derived_reason", self_reason);
    json_push_kv_str(out, "authority_posture", authority_posture);
    json_push_kv_str(out, "trust_mode", trust_mode);

    /* ── v2: the central trust→capability table's view of this posture ──────
     * Derived from the SAME three provenance predicates the guard routes
     * through (proven_authority, self_folded, self_derived), so this report can
     * never disagree with the enforcement (services/sync_trust_policy.h).
     * self_derived is only computed when hstar is available; when it is not,
     * it is false (the conservative floor), matching the guard's own fail. */
    enum sync_trust_state trust_st =
        sync_trust_derive(proven_authority, self_folded, self_derived);
    if (progress_open)
        sov_stamp_transitions(pdb, trust_st);
    uint32_t cap_mask = sync_trust_caps(trust_st);
    json_push_kv_str(out, "trust_state", sync_trust_state_name(trust_st));
    /* Publish the last-known-good trust-tier cache from the SAME successful
     * read this call just produced (the busy branch above never reaches
     * here), so a subsequent busy call answers with genuinely-current-at-
     * last-observation values, never a stale placeholder. */
    sov_trust_cache_store(trust_mode, authority_posture,
                          sync_trust_state_name(trust_st));
    /* Display-only posture: a coarse status label that authorizes NOTHING —
     * every capability above/below comes from the mask, never this string. */
    json_push_kv_str(out, "posture",
                     sync_posture_name(sync_posture_from_state(trust_st)));
    json_push_kv_int(out, "capability_mask", (int64_t)cap_mask);

    struct json_value caps = {0};
    json_set_object(&caps);
    for (size_t i = 0; i < sizeof(k_sov_caps) / sizeof(k_sov_caps[0]); i++) {
        struct json_value entry = {0};
        json_set_object(&entry);
        json_push_kv_bool(&entry, "allowed",
                          sync_trust_cap_allowed(trust_st, k_sov_caps[i].cap));
        json_push_kv_str(&entry, "reason",
                         sov_cap_reason(trust_st, k_sov_caps[i].cap));
        json_push_kv(&caps, k_sov_caps[i].key, &entry);
        json_free(&entry);
    }
    json_push_kv(out, "capabilities", &caps);
    json_free(&caps);

    /* t_ready / t_sovereign: the durable, monotonic first-reached instants
     * (SOVEREIGNTY_T_READY_KEY / SOVEREIGNTY_T_SOVEREIGN_KEY, stamped by
     * sov_stamp_transitions above and at every sovereignty_guard_allow
     * call) — {"epoch": <int64 wall-clock seconds>, "iso8601": "..."} once
     * stamped, JSON null until this datadir has ever reached the milestone.
     * A later posture regression never clears these; see the stamping
     * comment above sovereignty_trust_mode for the full semantics. */
    struct json_value t_ready = {0};
    sov_render_stamp(pdb, SOVEREIGNTY_T_READY_KEY, &t_ready);
    json_push_kv(out, "t_ready", &t_ready);
    json_free(&t_ready);
    struct json_value t_sovereign = {0};
    sov_render_stamp(pdb, SOVEREIGNTY_T_SOVEREIGN_KEY, &t_sovereign);
    json_push_kv(out, "t_sovereign", &t_sovereign);
    json_free(&t_sovereign);

    /* Per-pool shielded-history row counts (anchor_kv/nullifier_kv tables) —
     * distinguishable from `self_folded_marker` above: a `release_assisted`
     * node can carry a full complete history (post-import) with these counts
     * populated, while `self_folded` stays false until sovereign promotion. */
    struct json_value pools = {0};
    json_set_object(&pools);
    json_push_kv_int(&pools, "sprout_anchors", sprout_anchor_rows);
    json_push_kv_int(&pools, "sapling_anchors", sapling_anchor_rows);
    json_push_kv_int(&pools, "sprout_nullifiers", sprout_nullifier_rows);
    json_push_kv_int(&pools, "sapling_nullifiers", sapling_nullifier_rows);
    json_push_kv(out, "shielded_pool_counts", &pools);
    json_free(&pools);

    /* The importer's provenance stamp (shielded_import.provenance in
     * progress_meta) — see shi_write_provenance in
     * engine/services/src/shielded_history_import_service.c. Absent on a node
     * that never ran -import-complete-shielded (a fresh/from-genesis-only
     * datadir); present and "self_folded=false" right after a successful
     * import, superseded wholesale by a later sovereign bundle install. */
    json_push_kv_bool(out, "shielded_import_provenance_present",
                      provenance_present);
    json_push_kv_str(out, "shielded_import_provenance", provenance);

    /* What is gated at the CURRENT posture — probe the actual guard so this
     * report can never drift from the enforcement it describes (one source
     * of truth: sovereignty_guard_allow). */
    char mint_reason[96] = {0};
    char spend_reason[96] = {0};
    bool mint_allowed = progress_open &&
        sovereignty_guard_allow("mint", mint_reason, sizeof(mint_reason));
    bool spend_allowed = progress_open &&
        sovereignty_guard_allow("wallet_spend", spend_reason,
                                sizeof(spend_reason));

    /* Snapshot/bundle export requires BOTH proven_authority AND the
     * self_folded marker (engine/composition/src/bundle_exporter.c bx_qualified: "coins
     * not proven authority" / "coins lacks self-folded refold marker") — a
     * stricter, non-disjunctive gate than G-SOV's `self_derived` above (which
     * lets an un-migrated/bare store through on part 3's first disjunct, and
     * needs hstar for part 2). Mirror bx_qualified's exact predicate here so
     * this field never disagrees with the export gate it describes, and
     * stays reportable even when hstar isn't (yet) computable. */
    bool export_allowed = proven_authority && self_folded;

    struct json_value gated = {0};
    json_set_object(&gated);
    json_push_kv_bool(&gated, "mint_mining_allowed", mint_allowed);
    json_push_kv_bool(&gated, "wallet_spend_allowed", spend_allowed);
    json_push_kv_bool(&gated, "snapshot_bundle_export_allowed",
                      export_allowed);
    json_push_kv_bool(&gated, "tip_following_allowed", true);
    json_push_kv_str(&gated, "note",
                     "tip-following (reducer fold / P2P relay / explorer / "
                     "wallet viewing) is never gated; mint, wallet spend, "
                     "and snapshot/bundle export require self_folded");
    json_push_kv(out, "gated", &gated);
    json_free(&gated);

    return true;
}
