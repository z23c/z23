/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the typed blocker primitive (platform/modules/util/src/blocker.c).
 *
 * Coverage:
 *   - init: id/owner length validation, class assignment, default budget
 *   - set: new + refresh, rate limit window, fire_count semantics
 *   - clear: removes + idempotent
 *   - snapshot_all: correct count, age field, deadline_remaining sign
 *   - count_by_class / count_active
 *   - JSON dump: keys present, blockers array, class counts
 *   - escape registry: register, lookup, duplicate, capacity
 *   - escape dispatch: edge-triggered, no re-fire, missing action handled
 *   - rate-limit: env override + testing override
 *   - capacity: cap exhaustion returns -1
 *   - test clock override + advance
 *   - lifecycle policy (wf/os-blocker-retire): TRANSIENT TTL retirement
 *     (witnessed via the retired-count + last_retired dump), a re-fire
 *     resetting the TTL clock, a per-blocker TTL override, bounded
 *     deadline re-arm → escalation for a deadline with no escape_action
 *     (the worker.stall.op.projection_backfill shape), and
 *     PERMANENT/DEPENDENCY/RESOURCE staying completely unaffected by
 *     both rules */

#include "test/test_core.h"
#include "util/blocker.h"
#include "json/json.h"
#include "hotswap/hotswap_retire_blocker.h"
#include "config/boot_declaration_drift.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define BCK_CHECK(name, expr) do { \
    printf("blocker: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Escape capture for dispatch tests. */
static _Atomic int g_esc_a_count;
static _Atomic int g_esc_b_count;
static char        g_esc_last_id[BLOCKER_ID_MAX];

static void esc_a(const struct blocker_snapshot *s)
{
    atomic_fetch_add(&g_esc_a_count, 1);
    snprintf(g_esc_last_id, sizeof(g_esc_last_id), "%s", s->id);
}

static void esc_b(const struct blocker_snapshot *s)
{
    (void)s;
    atomic_fetch_add(&g_esc_b_count, 1);
}

/* Seam stubs for the upper-layer named faults. These stand in for the
 * reclaim/reconcile implementations the owning subsystems install — the
 * hotswap one exists only under ZCL_DEV_BUILD, and the two drift organs are
 * not in-tree yet (see the handoff note in the section that uses them). */
static _Atomic bool g_reclaim_all_clear;
static _Atomic int  g_reclaim_calls;
static _Atomic bool g_reconcile_converged;
static _Atomic int  g_reconcile_calls;

static bool test_reclaim_stub(void *ctx)
{
    (void)ctx;
    atomic_fetch_add(&g_reclaim_calls, 1);
    return atomic_load(&g_reclaim_all_clear);
}

static bool test_reconcile_stub(void *ctx)
{
    (void)ctx;
    atomic_fetch_add(&g_reconcile_calls, 1);
    return atomic_load(&g_reconcile_converged);
}

int test_blocker(void)
{
    printf("\n=== blocker tests ===\n");
    int failures = 0;

    blocker_module_init();

    /* ── blocker_init basic ─────────────────────────────────────── */
    {
        blocker_reset_for_testing();
        struct blocker_record r;
        bool ok = blocker_init(&r, "alpha", "test", BLOCKER_TRANSIENT, "why");
        BCK_CHECK("init returns true on valid", ok);
        BCK_CHECK("init sets id", strcmp(r.id, "alpha") == 0);
        BCK_CHECK("init sets owner", strcmp(r.owner_subsystem, "test") == 0);
        BCK_CHECK("init sets class", r.class == BLOCKER_TRANSIENT);
        BCK_CHECK("init copies reason", strcmp(r.reason, "why") == 0);
        BCK_CHECK("init transient budget=0", r.retry_budget == 0);

        struct blocker_record r2;
        ok = blocker_init(&r2, "perm", "test", BLOCKER_PERMANENT, NULL);
        BCK_CHECK("init NULL reason OK", ok);
        BCK_CHECK("init permanent budget=-1", r2.retry_budget == -1);

        /* Null arg → false */
        bool bad = blocker_init(NULL, "x", "y", BLOCKER_TRANSIENT, "z");
        BCK_CHECK("init NULL out → false", !bad);
        bad = blocker_init(&r, NULL, "y", BLOCKER_TRANSIENT, "z");
        BCK_CHECK("init NULL id → false", !bad);
        bad = blocker_init(&r, "x", NULL, BLOCKER_TRANSIENT, "z");
        BCK_CHECK("init NULL owner → false", !bad);

        /* Length overflow */
        char long_id[BLOCKER_ID_MAX + 8];
        memset(long_id, 'x', sizeof(long_id));
        long_id[sizeof(long_id) - 1] = '\0';
        bad = blocker_init(&r, long_id, "y", BLOCKER_TRANSIENT, "z");
        BCK_CHECK("init long id → false", !bad);
    }

    /* ── blocker_set + read ─────────────────────────────────────── */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(1000000);

        struct blocker_record r;
        blocker_init(&r, "alpha", "lms", BLOCKER_TRANSIENT, "stuck");
        int rc = blocker_set(&r);
        BCK_CHECK("set new → 0", rc == 0);
        BCK_CHECK("exists after set", blocker_exists("alpha"));
        BCK_CHECK("class_for matches", blocker_class_for("alpha") == BLOCKER_TRANSIENT);
        BCK_CHECK("count_active 1", blocker_count_active() == 1);
        BCK_CHECK("count transient 1",
                  blocker_count_by_class(BLOCKER_TRANSIENT) == 1);
        BCK_CHECK("count permanent 0",
                  blocker_count_by_class(BLOCKER_PERMANENT) == 0);

        BCK_CHECK("fire_count starts at 1",
                  blocker_fire_count_for_testing("alpha") == 1u);

        /* Set again immediately → rate-limited, fire_count++ only */
        rc = blocker_set(&r);
        BCK_CHECK("set rate-limited → 1", rc == 1);
        BCK_CHECK("fire_count 2 after re-set",
                  blocker_fire_count_for_testing("alpha") == 2u);
        BCK_CHECK("still 1 active",
                  blocker_count_active() == 1);

        /* Null record → -1 */
        rc = blocker_set(NULL);
        BCK_CHECK("set NULL → -1", rc == -1);

        /* Empty id → -1 */
        struct blocker_record empty = {0};
        rc = blocker_set(&empty);
        BCK_CHECK("set empty id → -1", rc == -1);
    }

    /* ── rate limit window ─────────────────────────────────────── */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(1000000);
        blocker_set_rate_limit_ms_for_testing(100); /* 100 ms */

        struct blocker_record r;
        blocker_init(&r, "beta", "lms", BLOCKER_TRANSIENT, "x");
        blocker_set(&r);
        BCK_CHECK("first set fc=1",
                  blocker_fire_count_for_testing("beta") == 1u);

        /* Advance 50 ms → still rate-limited */
        blocker_advance_clock_for_testing(50000);
        blocker_set(&r);
        BCK_CHECK("50ms later rate-limited",
                  blocker_fire_count_for_testing("beta") == 2u);

        /* Advance another 60 ms (total 110) → passes window */
        blocker_advance_clock_for_testing(60000);
        blocker_set(&r);
        BCK_CHECK("110ms later passes window",
                  blocker_fire_count_for_testing("beta") == 3u);
    }

    /* ── clear ─────────────────────────────────────────────────── */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(1000000);

        struct blocker_record r;
        blocker_init(&r, "gamma", "lms", BLOCKER_TRANSIENT, "x");
        blocker_set(&r);
        BCK_CHECK("exists before clear", blocker_exists("gamma"));
        blocker_clear("gamma");
        BCK_CHECK("absent after clear", !blocker_exists("gamma"));
        BCK_CHECK("clear missing id no-op", (blocker_clear("nope"), true));
        BCK_CHECK("count_active 0 post-clear", blocker_count_active() == 0);
    }

    /* ── snapshot ─────────────────────────────────────────────── */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(1000000);
        blocker_set_rate_limit_ms_for_testing(0);

        struct blocker_record r;
        blocker_init(&r, "snap-a", "owner", BLOCKER_RESOURCE, "disk full");
        r.escape_deadline_secs = 60;
        snprintf(r.escape_action, sizeof(r.escape_action), "fake_action");
        blocker_set(&r);

        struct blocker_snapshot snaps[8];
        uint64_t generation = 0;
        int dispatched = -1;
        int rate_limit_ms = -1;
        int n = blocker_snapshot_all_with_meta(
            snaps, 8, &generation, &dispatched, &rate_limit_ms);
        BCK_CHECK("snapshot returns 1", n == 1);
        BCK_CHECK("snapshot generation present", generation > 0);
        BCK_CHECK("snapshot dispatched metadata", dispatched >= 0);
        BCK_CHECK("snapshot rate metadata", rate_limit_ms == 0);
        BCK_CHECK("snap id matches", strcmp(snaps[0].id, "snap-a") == 0);
        BCK_CHECK("snap owner matches",
                  strcmp(snaps[0].owner_subsystem, "owner") == 0);
        BCK_CHECK("snap class resource", snaps[0].class == BLOCKER_RESOURCE);
        BCK_CHECK("snap age >= 0", snaps[0].age_us >= 0);
        BCK_CHECK("snap deadline set", snaps[0].escape_deadline_us > 0);
        BCK_CHECK("snap deadline_remaining positive",
                  snaps[0].deadline_remaining_us > 0);
        BCK_CHECK("snap escape_action copied",
                  strcmp(snaps[0].escape_action, "fake_action") == 0);
        uint64_t before_retry = generation;
        blocker_record_retry("snap-a");
        n = blocker_snapshot_all_with_meta(
            snaps, 8, &generation, &dispatched, &rate_limit_ms);
        BCK_CHECK("observable retry advances generation",
                  n == 1 && generation > before_retry &&
                  snaps[0].retry_count == 1);

        /* Advance past deadline */
        blocker_advance_clock_for_testing(61 * 1000000);
        n = blocker_snapshot_all(snaps, 8);
        BCK_CHECK("snap deadline_remaining negative past deadline",
                  snaps[0].deadline_remaining_us < 0);
    }

    {
        struct blocker_snapshot snapshots[4] = {0};
        snprintf(snapshots[0].id, sizeof(snapshots[0].id),
                 "script_validate.prevout_unresolved");
        snapshots[0].class = BLOCKER_PERMANENT;
        snapshots[0].age_us = 900000000;
        snprintf(snapshots[1].id, sizeof(snapshots[1].id),
                 "utxo_apply.nullifier_backfill_gap");
        snapshots[1].class = BLOCKER_PERMANENT;
        snapshots[1].age_us = 2000000;
        snprintf(snapshots[2].id, sizeof(snapshots[2].id),
                 "utxo_apply.anchor_backfill_gap");
        snapshots[2].class = BLOCKER_PERMANENT;
        snapshots[2].age_us = 1000000;
        snprintf(snapshots[3].id, sizeof(snapshots[3].id),
                 "peer_floor.no_eligible_peers");
        snapshots[3].class = BLOCKER_TRANSIENT;
        snapshots[3].age_us = 1000000000;

        const struct blocker_snapshot *dominant =
            blocker_select_dominant(snapshots, 4);
        BCK_CHECK("causal selector prefers anchor history gap",
                  dominant == &snapshots[2]);
        BCK_CHECK("anchor outranks nullifier history gap",
                  blocker_causal_priority(BLOCKER_PERMANENT,
                      snapshots[2].id) >
                  blocker_causal_priority(BLOCKER_PERMANENT,
                      snapshots[1].id));
        BCK_CHECK("nullifier history outranks downstream permanent",
                  blocker_causal_priority(BLOCKER_PERMANENT,
                      snapshots[1].id) >
                  blocker_causal_priority(BLOCKER_PERMANENT,
                      snapshots[0].id));

        snapshots[3].class = BLOCKER_RESOURCE;
        snprintf(snapshots[3].id, sizeof(snapshots[3].id),
                 "storage.disk_full");
        dominant = blocker_select_dominant(snapshots, 4);
        BCK_CHECK("resource exhaustion remains dominant",
                  dominant == &snapshots[3]);
        BCK_CHECK("causal selector rejects empty input",
                  blocker_select_dominant(NULL, 4) == NULL &&
                  blocker_select_dominant(snapshots, 0) == NULL);
    }

    /* ── JSON dump ─────────────────────────────────────────────── */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(2000000);
        blocker_set_rate_limit_ms_for_testing(0);

        struct blocker_record r;
        blocker_init(&r, "j1", "lms", BLOCKER_TRANSIENT, "transient");
        blocker_set(&r);
        blocker_init(&r, "j2", "validation", BLOCKER_PERMANENT, "perm");
        blocker_set(&r);

        struct json_value v;
        json_init(&v);
        bool ok = blocker_dump_state_json(&v, NULL);
        BCK_CHECK("dump returns true", ok);
        BCK_CHECK("active_count=2",
                  json_get_int(json_get(&v, "active_count")) == 2);
        BCK_CHECK("permanent_count=1",
                  json_get_int(json_get(&v, "permanent_count")) == 1);
        BCK_CHECK("transient_count=1",
                  json_get_int(json_get(&v, "transient_count")) == 1);
        BCK_CHECK("rate_limit_ms exposed",
                  json_get(&v, "rate_limit_ms") != NULL);
        BCK_CHECK("generation exposed",
                  json_get_int(json_get(&v, "generation")) > 0);
        const struct json_value *arr = json_get(&v, "blockers");
        BCK_CHECK("blockers array present", arr != NULL);
        BCK_CHECK("blockers array len 2", arr && json_size(arr) == 2);
        json_free(&v);
    }

    /* ── root-cause chaining: caused_by / cause_detail plumbing ──── */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(2500000);
        blocker_set_rate_limit_ms_for_testing(0);

        struct blocker_record r;
        blocker_init(&r, "prefix-target.alpha", "owner1", BLOCKER_TRANSIENT, "x");
        int rc = blocker_set(&r);
        BCK_CHECK("prefix target set", rc == 0);
        {
            struct blocker_snapshot s;
            blocker_snapshot_all(&s, 1);
            BCK_CHECK("caused_by defaults empty (plain blocker_set unaffected)",
                      s.caused_by[0] == '\0');
        }

        /* blocker_find_by_id_prefix */
        struct blocker_snapshot found;
        bool hit = blocker_find_by_id_prefix("prefix-target.", &found);
        BCK_CHECK("find_by_id_prefix matches", hit &&
                  strcmp(found.id, "prefix-target.alpha") == 0);
        BCK_CHECK("find_by_id_prefix no match",
                  !blocker_find_by_id_prefix("no-such-prefix.", &found));
        BCK_CHECK("find_by_id_prefix NULL prefix -> false",
                  !blocker_find_by_id_prefix(NULL, &found));
        BCK_CHECK("find_by_id_prefix empty prefix -> false",
                  !blocker_find_by_id_prefix("", &found));
        BCK_CHECK("find_by_id_prefix NULL out -> false",
                  !blocker_find_by_id_prefix("prefix-target.", NULL));

        /* blocker_set_with_cause */
        blocker_init(&r, "symptom-b", "owner2", BLOCKER_PERMANENT, "y");
        rc = blocker_set_with_cause(&r, "prefix-target.alpha", "h=123");
        BCK_CHECK("set_with_cause new -> 0", rc == 0);

        struct blocker_snapshot snaps[8];
        int n = blocker_snapshot_all(snaps, 8);
        BCK_CHECK("2 active after cause edge", n == 2);
        const struct blocker_snapshot *sym = NULL;
        for (int i = 0; i < n; i++)
            if (strcmp(snaps[i].id, "symptom-b") == 0) sym = &snaps[i];
        BCK_CHECK("symptom found", sym != NULL);
        BCK_CHECK("symptom caused_by set", sym &&
                  strcmp(sym->caused_by, "prefix-target.alpha") == 0);
        BCK_CHECK("symptom cause_detail set", sym &&
                  strcmp(sym->cause_detail, "h=123") == 0);

        /* set_with_cause with NULL caused_by == plain blocker_set */
        blocker_init(&r, "no-cause", "owner3", BLOCKER_TRANSIENT, "z");
        rc = blocker_set_with_cause(&r, NULL, NULL);
        BCK_CHECK("set_with_cause NULL cause -> 0", rc == 0);
        n = blocker_snapshot_all(snaps, 8);
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].id, "no-cause") == 0) {
                BCK_CHECK("NULL caused_by stays empty",
                          snaps[i].caused_by[0] == '\0');
            }
        }

        /* JSON dump: chain rendering + root/symptom classification */
        struct json_value v;
        json_init(&v);
        blocker_dump_state_json(&v, NULL);
        const struct json_value *barr = json_get(&v, "blockers");
        BCK_CHECK("dump: blockers array present", barr != NULL);
        bool saw_caused_by = false;
        for (size_t i = 0; barr && i < json_size(barr); i++) {
            const struct json_value *e = json_at(barr, i);
            const char *id = json_get_str(json_get(e, "id"));
            if (id && strcmp(id, "symptom-b") == 0) {
                const char *cb = json_get_str(json_get(e, "caused_by"));
                const char *cd = json_get_str(json_get(e, "cause_detail"));
                saw_caused_by = cb && strcmp(cb, "prefix-target.alpha") == 0 &&
                                cd && strcmp(cd, "h=123") == 0;
            }
        }
        BCK_CHECK("dump: symptom entry carries caused_by/cause_detail",
                  saw_caused_by);

        const struct json_value *roots = json_get(&v, "root_blocker_ids");
        const struct json_value *orphans = json_get(&v, "orphaned_symptom_ids");
        BCK_CHECK("dump: roots array present", roots != NULL);
        bool root_has_alpha = false;
        for (size_t i = 0; roots && i < json_size(roots); i++) {
            const char *rid = json_get_str(json_at(roots, i));
            if (rid && strcmp(rid, "prefix-target.alpha") == 0) root_has_alpha = true;
        }
        BCK_CHECK("dump: prefix-target.alpha classified as root", root_has_alpha);
        BCK_CHECK("dump: no orphaned symptoms while root active",
                  orphans && json_size(orphans) == 0);
        json_free(&v);

        /* Clearing the root does NOT silently clear the symptom — each
         * blocker clears on its own remedy — and the dumper flags the
         * now-dangling edge as an orphaned symptom. */
        blocker_clear("prefix-target.alpha");
        BCK_CHECK("root cleared", !blocker_exists("prefix-target.alpha"));
        BCK_CHECK("symptom NOT silently cleared", blocker_exists("symptom-b"));

        json_init(&v);
        blocker_dump_state_json(&v, NULL);
        roots = json_get(&v, "root_blocker_ids");
        orphans = json_get(&v, "orphaned_symptom_ids");
        BCK_CHECK("dump: roots empty after root cleared",
                  roots && json_size(roots) == 0);
        bool orphan_has_symptom = false;
        for (size_t i = 0; orphans && i < json_size(orphans); i++) {
            const char *oid = json_get_str(json_at(orphans, i));
            if (oid && strcmp(oid, "symptom-b") == 0) orphan_has_symptom = true;
        }
        BCK_CHECK("dump: symptom-b flagged as orphaned symptom",
                  orphan_has_symptom);
        json_free(&v);

        blocker_reset_for_testing();
    }

    /* ── escape registry + dispatch ────────────────────────────── */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(3000000);
        blocker_set_rate_limit_ms_for_testing(0);
        atomic_store(&g_esc_a_count, 0);
        atomic_store(&g_esc_b_count, 0);
        g_esc_last_id[0] = '\0';

        bool ok = blocker_register_escape("esc_a", esc_a);
        BCK_CHECK("register esc_a ok", ok);
        ok = blocker_register_escape("esc_b", esc_b);
        BCK_CHECK("register esc_b ok", ok);

        ok = blocker_register_escape("esc_a", esc_a);
        BCK_CHECK("register duplicate → false", !ok);
        ok = blocker_register_escape(NULL, esc_a);
        BCK_CHECK("register NULL name → false", !ok);
        ok = blocker_register_escape("esc_c", NULL);
        BCK_CHECK("register NULL fn → false", !ok);

        BCK_CHECK("lookup esc_a", blocker_lookup_escape("esc_a") == esc_a);
        BCK_CHECK("lookup unknown NULL",
                  blocker_lookup_escape("nope") == NULL);

        /* Place a blocker with a 1s deadline, sweep before/after. */
        struct blocker_record r;
        blocker_init(&r, "esc-test", "lms", BLOCKER_TRANSIENT, "stuck");
        r.escape_deadline_secs = 1;
        snprintf(r.escape_action, sizeof(r.escape_action), "esc_a");
        blocker_set(&r);

        int fired = blocker_supervisor_sweep();
        BCK_CHECK("sweep before deadline → 0", fired == 0);

        /* Advance 1.5 s */
        blocker_advance_clock_for_testing(1500000);
        fired = blocker_supervisor_sweep();
        BCK_CHECK("sweep after deadline → 1", fired == 1);
        BCK_CHECK("esc_a fired once", atomic_load(&g_esc_a_count) == 1);
        BCK_CHECK("esc_a saw correct id",
                  strcmp(g_esc_last_id, "esc-test") == 0);

        /* Second sweep — edge-triggered, no re-fire */
        fired = blocker_supervisor_sweep();
        BCK_CHECK("second sweep no re-fire", fired == 0);
        BCK_CHECK("esc_a still 1", atomic_load(&g_esc_a_count) == 1);
    }

    /* ── escape: missing action ───────────────────────────────── */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(4000000);
        blocker_set_rate_limit_ms_for_testing(0);

        struct blocker_record r;
        blocker_init(&r, "missing-esc", "lms", BLOCKER_TRANSIENT, "stuck");
        r.escape_deadline_secs = 1;
        snprintf(r.escape_action, sizeof(r.escape_action), "unregistered_action");
        blocker_set(&r);

        blocker_advance_clock_for_testing(2000000);
        int fired = blocker_supervisor_sweep();
        BCK_CHECK("missing escape: sweep returns 0", fired == 0);
        /* Not re-fired on next sweep */
        fired = blocker_supervisor_sweep();
        BCK_CHECK("missing escape: second sweep returns 0", fired == 0);
    }

    /* ── lifecycle policy: TTL retirement (rule 1) ────────────────
     * A TRANSIENT blocker is a live claim, not a log line — one that has
     * not re-fired within its TTL window auto-retires, witnessed via the
     * retired counter + last_retired info (never a silent delete). This
     * is exactly the boot.stage_regression shape: a one-shot observation
     * raised once at boot with no deadline and nothing to ever clear it. */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(10000000);
        blocker_set_rate_limit_ms_for_testing(0);

        struct blocker_record r;
        blocker_init(&r, "boot.stage_regression", "boot", BLOCKER_TRANSIENT,
                     "stage=sapling_tree_load ms=6637 median=11 threshold=5000");
        blocker_set(&r);
        BCK_CHECK("ttl: one-shot blocker exists right after raise",
                  blocker_exists("boot.stage_regression"));

        /* Well before TTL: a sweep must not touch it. */
        blocker_advance_clock_for_testing(1000000);
        int fired = blocker_supervisor_sweep();
        BCK_CHECK("ttl: sweep well before TTL is a no-op for escapes",
                  fired == 0);
        BCK_CHECK("ttl: still active well before the TTL window",
                  blocker_exists("boot.stage_regression"));
        BCK_CHECK("ttl: retired_total still 0",
                  blocker_retired_transient_count() == 0);

        /* Cross the default 30-minute TTL with no re-fire → retires. */
        blocker_advance_clock_for_testing(
            (int64_t)BLOCKER_DEFAULT_TRANSIENT_TTL_SECS * 1000000 + 1000000);
        blocker_supervisor_sweep();
        BCK_CHECK("ttl: retired after inactivity window",
                  !blocker_exists("boot.stage_regression"));
        BCK_CHECK("ttl: active count drops with it",
                  blocker_count_active() == 0);
        BCK_CHECK("ttl: retired_total incremented",
                  blocker_retired_transient_count() == 1);

        struct blocker_retirement_info info;
        bool has_last = blocker_last_retired(&info);
        BCK_CHECK("ttl: last_retired reports valid", has_last && info.valid);
        BCK_CHECK("ttl: last_retired id matches",
                  strcmp(info.id, "boot.stage_regression") == 0);
        BCK_CHECK("ttl: last_retired owner matches",
                  strcmp(info.owner_subsystem, "boot") == 0);
        BCK_CHECK("ttl: last_retired fire_count captured",
                  info.fire_count_at_retirement == 1u);
    }

    /* ── lifecycle policy: re-fire resets the TTL clock ───────────── */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(20000000);
        blocker_set_rate_limit_ms_for_testing(0);

        struct blocker_record r;
        blocker_init(&r, "ttl-refire", "lms", BLOCKER_TRANSIENT, "stuck");
        blocker_set(&r);

        int64_t near_ttl =
            (int64_t)BLOCKER_DEFAULT_TRANSIENT_TTL_SECS * 1000000 - 1000000;

        /* Advance to just under the TTL, then re-fire. */
        blocker_advance_clock_for_testing(near_ttl);
        blocker_set(&r);
        blocker_supervisor_sweep();
        BCK_CHECK("ttl refire: alive right after the re-fire",
                  blocker_exists("ttl-refire"));

        /* Advance the same span again — if the TTL clock had NOT reset,
         * cumulative inactivity would now exceed the TTL and it would be
         * gone. It must still be alive. */
        blocker_advance_clock_for_testing(near_ttl);
        blocker_supervisor_sweep();
        BCK_CHECK("ttl refire: still alive — re-fire reset the TTL clock",
                  blocker_exists("ttl-refire"));

        /* Now let it go fully quiet across the TTL. */
        blocker_advance_clock_for_testing(
            (int64_t)BLOCKER_DEFAULT_TRANSIENT_TTL_SECS * 1000000 + 1000000);
        blocker_supervisor_sweep();
        BCK_CHECK("ttl refire: retires once genuinely quiet",
                  !blocker_exists("ttl-refire"));
    }

    /* ── lifecycle policy: per-blocker TTL override ───────────────── */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(30000000);
        blocker_set_rate_limit_ms_for_testing(0);

        struct blocker_record r;
        blocker_init(&r, "ttl-override", "lms", BLOCKER_TRANSIENT, "stuck");
        r.transient_ttl_secs = 5;  /* far shorter than the 30-min default */
        blocker_set(&r);

        blocker_advance_clock_for_testing(2 * 1000000);
        blocker_supervisor_sweep();
        BCK_CHECK("ttl override: still alive before the 5s override elapses",
                  blocker_exists("ttl-override"));

        blocker_advance_clock_for_testing(4 * 1000000);
        blocker_supervisor_sweep();
        BCK_CHECK("ttl override: retires at the custom TTL, not the default",
                  !blocker_exists("ttl-override"));
    }

    /* ── lifecycle policy: overdue-deadline re-arm → escalation ─────
     * Live shape: worker.stall.op.projection_backfill raised an
     * escape_deadline_secs but no escape_action (nothing to dispatch), so
     * the deadline sat negative and growing forever. A TRANSIENT blocker
     * in that shape must re-arm a bounded number of times, then escalate
     * visibly instead of sitting silently overdue. */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(40000000);
        blocker_set_rate_limit_ms_for_testing(0);

        struct blocker_record r;
        blocker_init(&r, "worker.stall.op.projection_backfill",
                     "boot.background_workers", BLOCKER_TRANSIENT,
                     "deadline exceeded us=-12800000000");
        r.escape_deadline_secs = 60;  /* set, no escape_action — matches
                                        * boot_worker_supervisor.c's
                                        * worker_on_stall() shape exactly. */
        blocker_set(&r);

        struct blocker_snapshot s;
        for (int i = 0; i < BLOCKER_MAX_DEADLINE_REARMS; i++) {
            blocker_advance_clock_for_testing(61 * 1000000);
            blocker_supervisor_sweep();
            int n = blocker_snapshot_all(&s, 1);
            BCK_CHECK("rearm: still present mid-rearm", n == 1);
            BCK_CHECK("rearm: not escalated before the budget is spent",
                      n == 1 && !s.escalated);
            BCK_CHECK("rearm: rearm_count tracks the attempt",
                      n == 1 && s.deadline_rearm_count == i + 1);
            BCK_CHECK("rearm: deadline pushed back into the future",
                      n == 1 && s.deadline_remaining_us > 0);
        }

        /* One more overdue crossing exhausts the budget → escalate. */
        blocker_advance_clock_for_testing(61 * 1000000);
        blocker_supervisor_sweep();
        int n = blocker_snapshot_all(&s, 1);
        BCK_CHECK("rearm: escalated once the re-arm budget is exhausted",
                  n == 1 && s.escalated);
        BCK_CHECK("rearm: escalated blocker is still an active, visible claim",
                  blocker_exists("worker.stall.op.projection_backfill"));

        /* Escalation is sticky — no un-escalation, no spam re-log — until
         * a re-fire or the TTL eventually retires it. */
        blocker_advance_clock_for_testing(61 * 1000000);
        blocker_supervisor_sweep();
        n = blocker_snapshot_all(&s, 1);
        BCK_CHECK("rearm: stays escalated on later overdue sweeps",
                  n == 1 && s.escalated);

        /* It never goes silent forever: TTL inactivity eventually retires
         * even an escalated blocker. */
        blocker_advance_clock_for_testing(
            (int64_t)BLOCKER_DEFAULT_TRANSIENT_TTL_SECS * 1000000);
        blocker_supervisor_sweep();
        BCK_CHECK("rearm: escalated blocker still retires on TTL inactivity",
                  !blocker_exists("worker.stall.op.projection_backfill"));
    }

    /* ── KEYSTONE: an actively-refiring blocker still escalates ─────
     * Regression for the blocker-convergence bug. Live shape:
     * worker.stall.op.projection_backfill re-raised every ~5s with the
     * SAME enum reason (a still-stalling worker), an escape_deadline_secs
     * but no escape_action. The old refresh branch reset rearm_count /
     * escalated on every touch AND re-anchored the deadline to the fixed
     * (ever-staler) since_us, so it was permanently "overdue" yet never
     * completed the 3 re-arms — it dodged BOTH TTL retirement (stays
     * active) and escalation forever (~3.6h live). With the fix, a
     * same-identity refire no longer resets the escalation clock, so the
     * sweep drives it to escalated=true. Uses the test clock, no wall
     * sleep. */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(100000000);
        blocker_set_rate_limit_ms_for_testing(0); /* every refire is genuine —
                                                    * worst case for the bug */

        struct blocker_record r;
        blocker_init(&r, "worker.stall.op.projection_backfill",
                     "boot.background_workers", BLOCKER_TRANSIENT,
                     "deadline_exceeded");   /* stable enum-name reason, as
                                              * worker_on_stall() passes */
        r.escape_deadline_secs = 10;         /* deadline set, no escape_action */
        int rc = blocker_set(&r);
        BCK_CHECK("keystone: initial set → 0", rc == 0);

        /* Re-fire every 5s and sweep every 5s, well past the deadline span
         * and the re-arm budget, but nowhere near the 30-min TTL — so the
         * only lifecycle exit available is escalation. Under the old code
         * escalated NEVER became true here; it must now. */
        bool became_escalated = false;
        struct blocker_snapshot s;
        for (int i = 0; i < 40 && !became_escalated; i++) {
            blocker_advance_clock_for_testing(5 * 1000000);
            blocker_set(&r);               /* same-identity refire */
            blocker_supervisor_sweep();
            int n = blocker_snapshot_all(&s, 1);
            if (n == 1 && s.escalated) became_escalated = true;
        }
        BCK_CHECK("keystone: actively-refiring blocker escalates (was never)",
                  became_escalated);
        BCK_CHECK("keystone: still an active, visible claim after escalation",
                  blocker_exists("worker.stall.op.projection_backfill"));
        BCK_CHECK("keystone: not TTL-retired while actively refiring",
                  blocker_retired_transient_count() == 0);

        /* A genuinely NEW occurrence (reason changes → new height/target)
         * re-anchors the horizon and resets the escalation clock. */
        blocker_init(&r, "worker.stall.op.projection_backfill",
                     "boot.background_workers", BLOCKER_TRANSIENT,
                     "no_progress");    /* different reason == new identity */
        r.escape_deadline_secs = 10;
        blocker_advance_clock_for_testing(5 * 1000000);
        blocker_set(&r);
        int n = blocker_snapshot_all(&s, 1);
        BCK_CHECK("keystone: new identity resets escalation state",
                  n == 1 && !s.escalated && s.deadline_rearm_count == 0);
        BCK_CHECK("keystone: new identity re-anchors deadline into the future",
                  n == 1 && s.deadline_remaining_us > 0);
    }

    /* ── lifecycle policy: non-TRANSIENT classes are untouched ─────
     * Rule 4: dependency blockers legitimately persist until their
     * dependency resolves; PERMANENT/RESOURCE persist until cleared. Both
     * new rules (TTL retirement, deadline re-arm/escalation) must be a
     * complete no-op for them, even when raised in the exact same
     * "deadline set, no escape_action" shape that triggers rule 2 for
     * TRANSIENT. */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(50000000);
        blocker_set_rate_limit_ms_for_testing(0);

        enum blocker_class classes[3] = {
            BLOCKER_PERMANENT, BLOCKER_DEPENDENCY, BLOCKER_RESOURCE};
        const char *ids[3] = {
            "perm-unaffected", "dep-unaffected", "res-unaffected"};
        for (int i = 0; i < 3; i++) {
            struct blocker_record r;
            blocker_init(&r, ids[i], "lms", classes[i], "x");
            r.escape_deadline_secs = 5;   /* empty escape_action */
            blocker_set(&r);
        }

        blocker_advance_clock_for_testing(
            (int64_t)(BLOCKER_DEFAULT_TRANSIENT_TTL_SECS + 1000) * 1000000);
        for (int i = 0; i < 5; i++) blocker_supervisor_sweep();

        struct blocker_snapshot snaps[3];
        int n = blocker_snapshot_all(snaps, 3);
        BCK_CHECK("non-transient: all three survive the sweep storm",
                  n == 3);
        for (int i = 0; i < 3; i++) {
            BCK_CHECK(ids[i], blocker_exists(ids[i]));
            const struct blocker_snapshot *found = NULL;
            for (int j = 0; j < n; j++) {
                if (strcmp(snaps[j].id, ids[i]) == 0) { found = &snaps[j]; break; }
            }
            char label[96];
            snprintf(label, sizeof(label), "non-transient: %s never escalated",
                     ids[i]);
            BCK_CHECK(label, found && !found->escalated);
            snprintf(label, sizeof(label),
                     "non-transient: %s deadline left as-is (no re-arm)", ids[i]);
            BCK_CHECK(label, found && found->deadline_rearm_count == 0);
        }
        BCK_CHECK("non-transient: no retirements recorded",
                  blocker_retired_transient_count() == 0);
    }

    /* ── retry counter ────────────────────────────────────────── */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(5000000);
        blocker_set_rate_limit_ms_for_testing(0);

        struct blocker_record r;
        blocker_init(&r, "retry-id", "lms", BLOCKER_TRANSIENT, "x");
        r.retry_budget = 5;
        blocker_set(&r);

        blocker_record_retry("retry-id");
        blocker_record_retry("retry-id");

        struct blocker_snapshot s;
        int n = blocker_snapshot_all(&s, 1);
        BCK_CHECK("retry_count=2", n == 1 && s.retry_count == 2);
        BCK_CHECK("retry_budget=5", s.retry_budget == 5);

        /* No-op for missing id */
        blocker_record_retry("nope");
        BCK_CHECK("missing retry id no-op", true);
    }

    /* ── capacity ─────────────────────────────────────────────── */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(6000000);
        blocker_set_rate_limit_ms_for_testing(0);

        char id[32];
        int filled = 0;
        for (int i = 0; i < BLOCKER_CAP; i++) {
            struct blocker_record r;
            snprintf(id, sizeof(id), "cap-%d", i);
            blocker_init(&r, id, "lms", BLOCKER_TRANSIENT, "x");
            if (blocker_set(&r) == 0) filled++;
        }
        BCK_CHECK("filled to cap", filled == BLOCKER_CAP);
        BCK_CHECK("count_active==cap",
                  blocker_count_active() == BLOCKER_CAP);

        /* One more should fail. */
        struct blocker_record r;
        blocker_init(&r, "overflow", "lms", BLOCKER_TRANSIENT, "x");
        int rc = blocker_set(&r);
        BCK_CHECK("overflow → -1", rc == -1);
    }

    /* ── upper-layer named faults (wf/supervision) ─────────────────
     * Three fallbacks that were SAFE but silent are now typed blockers.
     * The common bar for all three: raised with a FIXED reason (so a
     * refire is the SAME fault and dedup/escalation converge), a
     * registered escape action (an unregistered one dead-ends the sweep
     * lookup), and an escape that only clears the blocker when the fault
     * is genuinely gone. */

    /* (1) hotswap: a retired generation whose mapping never drained. */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(80000000);
        blocker_set_rate_limit_ms_for_testing(0);
        hotswap_retire_blocker_reset_for_testing();
        hotswap_retire_blocker_register_escape();

        BCK_CHECK("hotswap: escape action is registered",
                  blocker_lookup_escape(HOTSWAP_RETIRE_ESCAPE_ACTION) != NULL);
        BCK_CHECK("hotswap: nothing retained, nothing named",
                  !blocker_exists(HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID));

        hotswap_retire_blocker_raise();
        struct blocker_snapshot s;
        int n = blocker_snapshot_all(&s, 1);
        BCK_CHECK("hotswap: retention raises the named blocker",
                  n == 1 &&
                  strcmp(s.id, HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID) == 0);
        BCK_CHECK("hotswap: DEPENDENCY class (stays under a real resource "
                  "exhaustion in causal priority)",
                  n == 1 && s.class == BLOCKER_DEPENDENCY);
        BCK_CHECK("hotswap: names its escape action",
                  n == 1 && strcmp(s.escape_action,
                                   HOTSWAP_RETIRE_ESCAPE_ACTION) == 0);
        BCK_CHECK("hotswap: retained count tracks outside the record",
                  hotswap_retire_blocker_retained() == 1);

        /* Dedup keystone: a second retention is the SAME fault. The reason
         * carries no count/handle, so identity must not change and the
         * registry must not grow a second row. */
        char reason_first[BLOCKER_REASON_MAX];
        snprintf(reason_first, sizeof(reason_first), "%s", s.reason);
        hotswap_retire_blocker_raise();
        n = blocker_snapshot_all(&s, 1);
        BCK_CHECK("hotswap: second retention does not add a second blocker",
                  blocker_count_active() == 1);
        BCK_CHECK("hotswap: reason is stable across retentions (dedup holds)",
                  n == 1 && strcmp(s.reason, reason_first) == 0);
        BCK_CHECK("hotswap: fire_count records the second retention",
                  blocker_fire_count_for_testing(
                      HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID) == 2);
        BCK_CHECK("hotswap: retained count is 2 (the varying part lives "
                  "outside the reason)",
                  hotswap_retire_blocker_retained() == 2);

        /* No reclaimer installed (release build / seam not armed): the
         * escape must NOT clear a fault it did not fix. */
        blocker_advance_clock_for_testing(
            (int64_t)(HOTSWAP_RETIRE_ESCAPE_DEADLINE_SECS + 1) * 1000000);
        int fired = blocker_supervisor_sweep();
        BCK_CHECK("hotswap: escape dispatches on the deadline", fired == 1);
        BCK_CHECK("hotswap: no reclaimer → blocker stays named",
                  blocker_exists(HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID));

        /* A reclaimer that still sees a retained mapping also may not
         * clear it. */
        hotswap_retire_blocker_set_reclaimer(test_reclaim_stub, NULL);
        atomic_store(&g_reclaim_all_clear, false);
        atomic_store(&g_reclaim_calls, 0);
        /* Escape dispatch is edge-triggered per record, so re-raise on a
         * fresh record to get a fresh deadline edge. */
        blocker_clear(HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID);
        hotswap_retire_blocker_raise();
        blocker_advance_clock_for_testing(
            (int64_t)(HOTSWAP_RETIRE_ESCAPE_DEADLINE_SECS + 1) * 1000000);
        blocker_supervisor_sweep();
        BCK_CHECK("hotswap: reclaimer ran", atomic_load(&g_reclaim_calls) == 1);
        BCK_CHECK("hotswap: partial reclaim → blocker still named",
                  blocker_exists(HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID));

        /* Full reclaim clears it — the claim must not outlive the fault. */
        atomic_store(&g_reclaim_all_clear, true);
        blocker_clear(HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID);
        hotswap_retire_blocker_raise();
        blocker_advance_clock_for_testing(
            (int64_t)(HOTSWAP_RETIRE_ESCAPE_DEADLINE_SECS + 1) * 1000000);
        blocker_supervisor_sweep();
        BCK_CHECK("hotswap: full reclaim clears the blocker",
                  !blocker_exists(HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID));
        BCK_CHECK("hotswap: retained count zeroed by the reclaim",
                  hotswap_retire_blocker_retained() == 0);

        /* The non-escape path: each reclaim decrements, and only the LAST
         * one clears. */
        hotswap_retire_blocker_raise();
        hotswap_retire_blocker_raise();
        hotswap_retire_blocker_note_reclaimed();
        BCK_CHECK("hotswap: one of two reclaimed → still named",
                  blocker_exists(HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID) &&
                  hotswap_retire_blocker_retained() == 1);
        hotswap_retire_blocker_note_reclaimed();
        BCK_CHECK("hotswap: last reclaim clears the blocker",
                  !blocker_exists(HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID) &&
                  hotswap_retire_blocker_retained() == 0);
        hotswap_retire_blocker_note_reclaimed();  /* underflow guard */
        BCK_CHECK("hotswap: reclaim past zero does not underflow",
                  hotswap_retire_blocker_retained() == 0);

        hotswap_retire_blocker_reset_for_testing();
    }

    /* (2)+(3) declared-vs-observed drift. NOTE (handoff): neither
     * detecting organ exists in-tree yet — no config reload path, no
     * service-catalog observer — so these exercise the naming surface and
     * the reconciler SEAM the organs will install into, never a fabricated
     * caller. */
    {
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(90000000);
        blocker_set_rate_limit_ms_for_testing(0);
        boot_declaration_drift_reset_for_testing();
        boot_declaration_drift_register_escapes();

        BCK_CHECK("drift: config-reload escape registered",
                  blocker_lookup_escape(CONFIG_RELOAD_ESCAPE_ACTION) != NULL);
        BCK_CHECK("drift: service-declaration escape registered",
                  blocker_lookup_escape(
                      SERVICE_DECLARATION_ESCAPE_ACTION) != NULL);

        boot_config_reload_divergence_raise("rpcport");
        boot_service_declaration_divergence_raise("edge");
        BCK_CHECK("drift: both faults are named",
                  blocker_exists(CONFIG_RELOAD_DIVERGED_BLOCKER_ID) &&
                  blocker_exists(SERVICE_DECLARATION_DIVERGED_BLOCKER_ID));
        BCK_CHECK("drift: scopes recorded outside the blocker record",
                  strcmp(boot_declaration_drift_last_scope(
                             DECLARATION_DRIFT_CONFIG_RELOAD), "rpcport") == 0 &&
                  strcmp(boot_declaration_drift_last_scope(
                             DECLARATION_DRIFT_SERVICE_DECL), "edge") == 0);

        /* Dedup keystone: a DIFFERENT scope must not look like a brand-new
         * blocker. This is the whole reason the scope is not in the reason
         * text — identity keys on class+reason+cause, so a per-occurrence
         * reason would re-anchor the deadline forever. */
        struct blocker_snapshot snaps[8];
        int total = blocker_snapshot_all(snaps, 8);
        BCK_CHECK("drift: exactly two records", total == 2);
        char cfg_reason[BLOCKER_REASON_MAX] = {0};
        for (int i = 0; i < total; i++) {
            if (strcmp(snaps[i].id, CONFIG_RELOAD_DIVERGED_BLOCKER_ID) == 0)
                snprintf(cfg_reason, sizeof(cfg_reason), "%s", snaps[i].reason);
        }
        boot_config_reload_divergence_raise("datadir");
        total = blocker_snapshot_all(snaps, 8);
        BCK_CHECK("drift: a new scope does not add a record", total == 2);
        for (int i = 0; i < total; i++) {
            if (strcmp(snaps[i].id, CONFIG_RELOAD_DIVERGED_BLOCKER_ID) != 0)
                continue;
            BCK_CHECK("drift: reason unchanged by a new scope (dedup holds)",
                      strcmp(snaps[i].reason, cfg_reason) == 0);
            BCK_CHECK("drift: DEPENDENCY class",
                      snaps[i].class == BLOCKER_DEPENDENCY);
        }
        BCK_CHECK("drift: newest scope is visible where it belongs",
                  strcmp(boot_declaration_drift_last_scope(
                             DECLARATION_DRIFT_CONFIG_RELOAD), "datadir") == 0);

        /* No reconciler installed (the organs are pending) — the escapes
         * fire, escalate, and honestly leave both blockers standing. */
        blocker_advance_clock_for_testing(
            (int64_t)(DECLARATION_DRIFT_ESCAPE_DEADLINE_SECS + 1) * 1000000);
        int fired = blocker_supervisor_sweep();
        BCK_CHECK("drift: both escapes dispatch on the deadline", fired == 2);
        BCK_CHECK("drift: no reconciler → both stay named",
                  blocker_exists(CONFIG_RELOAD_DIVERGED_BLOCKER_ID) &&
                  blocker_exists(SERVICE_DECLARATION_DIVERGED_BLOCKER_ID));

        /* Seam proof: a reconciler reporting convergence clears exactly its
         * own blocker; the other is untouched. */
        atomic_store(&g_reconcile_converged, true);
        atomic_store(&g_reconcile_calls, 0);
        boot_declaration_drift_set_reconciler(DECLARATION_DRIFT_CONFIG_RELOAD,
                                              test_reconcile_stub, NULL);
        blocker_clear(CONFIG_RELOAD_DIVERGED_BLOCKER_ID);
        boot_config_reload_divergence_raise("rpcport");
        blocker_advance_clock_for_testing(
            (int64_t)(DECLARATION_DRIFT_ESCAPE_DEADLINE_SECS + 1) * 1000000);
        blocker_supervisor_sweep();
        BCK_CHECK("drift: reconciler seam was invoked",
                  atomic_load(&g_reconcile_calls) == 1);
        BCK_CHECK("drift: converged reconciler clears its blocker",
                  !blocker_exists(CONFIG_RELOAD_DIVERGED_BLOCKER_ID));
        BCK_CHECK("drift: the other fault is untouched by that escape",
                  blocker_exists(SERVICE_DECLARATION_DIVERGED_BLOCKER_ID));

        /* Convergence via the explicit clear seam. */
        boot_service_declaration_divergence_clear();
        BCK_CHECK("drift: explicit clear retires the declaration fault",
                  !blocker_exists(SERVICE_DECLARATION_DIVERGED_BLOCKER_ID));
        boot_service_declaration_divergence_clear();  /* idempotent */
        BCK_CHECK("drift: clear is idempotent", blocker_count_active() == 0);

        boot_declaration_drift_reset_for_testing();
    }

    /* ── class names ──────────────────────────────────────────── */
    {
        BCK_CHECK("class_name PERMANENT",
                  strcmp(blocker_class_name(BLOCKER_PERMANENT), "permanent") == 0);
        BCK_CHECK("class_name TRANSIENT",
                  strcmp(blocker_class_name(BLOCKER_TRANSIENT), "transient") == 0);
        BCK_CHECK("class_name DEPENDENCY",
                  strcmp(blocker_class_name(BLOCKER_DEPENDENCY), "dependency") == 0);
        BCK_CHECK("class_name RESOURCE",
                  strcmp(blocker_class_name(BLOCKER_RESOURCE), "resource") == 0);
        BCK_CHECK("class_name invalid",
                  strcmp(blocker_class_name((enum blocker_class)99),
                         "(invalid)") == 0);
    }

    /* ── module lifecycle idempotency ─────────────────────────── */
    {
        bool ok = blocker_module_init();
        BCK_CHECK("module_init re-entrant", ok);
        blocker_module_shutdown();
        ok = blocker_module_init();
        BCK_CHECK("module_init after shutdown", ok);
    }

    blocker_reset_for_testing();

    if (failures == 0) {
        printf("=== blocker tests: ALL PASS ===\n\n");
    } else {
        printf("=== blocker tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
