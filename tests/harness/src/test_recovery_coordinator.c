/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proof for the folded recovery_coordinator. The cheap rungs (cursor warm-restart,
 * bounded range re-derive, segment refetch-by-hash) belong to the
 * reducer_frontier_reconcile_light and segment_corruption conditions. The
 * coordinator's sole job is the naming fallback: on an unresolved
 * CRITICAL that no cheap self-healing condition owns, name a typed blocker so
 * a silent halt is unrepresentable.
 *
 *   gate:    no unresolved critical      -> quiet (no blocker, no run)
 *   fire:    unresolved critical, no owning condition active -> name blocker
 *   suppress: unresolved critical IS an owning condition (active) -> quiet
 *   naming:  the typed blocker is a retry-forever DEPENDENCY (no silent halt)
 */

#include "test/test_core.h"

#include "services/recovery_coordinator.h"
#include "framework/condition.h"
#include "event/event.h"
#include "util/blocker.h"
#include "util/supervisor.h"
#include "validation/main_state.h"
#include "json/json.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RC_CHECK(name, expr) do { \
    printf("recovery_coordinator: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── condition fixture: detect-true CRITICAL that never witnesses clear, so a
 * couple of ticks exhaust max_attempts and it becomes an unresolved critical
 * while staying currently_active. ────────────────────────────────────── */

static enum condition_remedy_result cf_remedy(void)  { return COND_REMEDY_OK; }
static bool cf_detect(void)  { return true; }
static bool cf_witness(int64_t t) { (void)t; return false; }

static int64_t rc_now;
static int64_t rc_clock(void) { return rc_now; }

static void drive_to_unresolved_critical(struct condition *c)
{
    (void)condition_register(c);
    condition_engine_tick();
    condition_engine_tick();
}

static void rc_reset(void)
{
    condition_engine_reset_for_testing();
    event_log_init();
    blocker_module_init();
    blocker_reset_for_testing();
    recovery_coordinator_test_reset();
}


/* ── mutation-sweep follow-ups: set comparison, format caps, state dump ── */

static bool cf_quiet(void) { return false; }

static void rc_make(struct condition *c, const char *name,
                    enum condition_severity sev, bool (*detect)(void))
{
    *c = (struct condition){
        .name = name, .severity = sev, .poll_secs = 1, .backoff_secs = 0,
        .max_attempts = 2, .detect = detect, .remedy = cf_remedy,
        .witness = cf_witness, .witness_window_secs = 60,
    };
}

static void rc_make_crit(struct condition *c, const char *name)
{
    rc_make(c, name, COND_CRITICAL, cf_detect);
    drive_to_unresolved_critical(c);
}

/* A same-size set that differs only at its first sorted name is a change;
 * a set that cleared and came back is a change from the empty set. rc_now
 * stays under the 600 s keepalive so only a change can emit. */
static int rc_set_change_cases(void)
{
    int failures = 0;
    static struct condition ca, cb, cz;
    rc_reset();
    rc_now = 100;
    recovery_coordinator_test_set_clock(rc_clock);
    rc_make_crit(&ca, "rc_sa_a");
    rc_make_crit(&cz, "rc_sa_z");
    recovery_coordinator_test_drive();
    RC_CHECK("set: first set logs", recovery_coordinator_test_log_emits() == 1);

    condition_engine_reset_for_testing();
    rc_make_crit(&cb, "rc_sa_b");
    rc_make_crit(&cz, "rc_sa_z");
    recovery_coordinator_test_drive();
    RC_CHECK("set: same size, first name differs -> logs again",
             recovery_coordinator_test_log_emits() == 2);

    condition_engine_reset_for_testing();
    recovery_coordinator_test_drive();
    rc_make_crit(&cb, "rc_sa_b");
    rc_make_crit(&cz, "rc_sa_z");
    recovery_coordinator_test_drive();
    RC_CHECK("set: cleared then back -> logs again at once",
             recovery_coordinator_test_log_emits() == 3);

    /* test_reset must also forget the logged set and the throttle. */
    recovery_coordinator_test_reset();
    recovery_coordinator_test_set_clock(rc_clock);
    recovery_coordinator_test_drive();
    RC_CHECK("set: after test_reset the same set logs afresh",
             recovery_coordinator_test_log_emits() == 1);

    recovery_coordinator_test_set_clock(NULL);
    rc_reset();
    return failures;
}

static void rc_names_fixture(struct condition *c, const char *const *names,
                             int n)
{
    rc_reset();
    for (int i = 0; i < n; i++)
        rc_make_crit(&c[i], names[i]);
    recovery_coordinator_test_drive();
}

static int rc_format_cap_cases(void)
{
    int failures = 0;
    static struct condition c[3];
    static const char *const names[3] = {"alpha", "beta", "gamma"};
    char buf[64];

    rc_reset();
    memset(buf, 'X', sizeof(buf));
    recovery_coordinator_test_format_logged(buf, sizeof(buf));
    RC_CHECK("format: empty set is the empty string", buf[0] == '\0');

    rc_names_fixture(c, names, 3);
    memset(buf, 'X', sizeof(buf));
    recovery_coordinator_test_format_logged(buf, sizeof(buf));
    RC_CHECK("format: three names fit with no +N marker",
             strcmp(buf, "alpha, beta, gamma") == 0);
    memset(buf, 'X', sizeof(buf));
    recovery_coordinator_test_format_logged(buf, 16);
    RC_CHECK("format: cap 16 cuts after beta with ...",
             strcmp(buf, "alpha, beta...") == 0);
    memset(buf, 'X', sizeof(buf));
    recovery_coordinator_test_format_logged(buf, 5);
    RC_CHECK("format: cap 5 holds only the marker", strcmp(buf, "...") == 0);
    memset(buf, 'X', sizeof(buf));
    recovery_coordinator_test_format_logged(buf, 4);
    RC_CHECK("format: cap 4 is too small, empty string", buf[0] == '\0');
    rc_reset();
    return failures;
}

static int rc_format_more_cases(void)
{
    int failures = 0;
    static struct condition c[9];
    static const char *const names[9] = {"n0", "n1", "n2", "n3", "n4",
                                         "n5", "n6", "n7", "n8"};
    char buf[64];
    rc_names_fixture(c, names, 9);
    memset(buf, 'X', sizeof(buf));
    recovery_coordinator_test_format_logged(buf, 40);
    RC_CHECK("format: cap 40 holds the whole +1 more text",
             strcmp(buf, "n0, n1, n2, n3, n4, n5, n6, n7, +1 more") == 0);
    memset(buf, 'X', sizeof(buf));
    recovery_coordinator_test_format_logged(buf, 39);
    RC_CHECK("format: cap 39 cuts the +1 more tail with ...",
             strcmp(buf, "n0, n1, n2, n3, n4, n5, n6, n7...") == 0);
    rc_reset();
    return failures;
}

/* A registered but inactive owning condition does not suppress; an active
 * segment_corruption does. */
static int rc_owner_cases(void)
{
    int failures = 0;
    static struct condition owner, other;
    rc_reset();
    rc_make(&owner, "reducer_frontier_reconcile_light", COND_WARN, cf_quiet);
    (void)condition_register(&owner);
    rc_make_crit(&other, "rc_owner_other");
    condition_engine_tick();
    recovery_coordinator_test_drive();
    RC_CHECK("owner: registered-but-inactive owner does not suppress",
             recovery_coordinator_test_runs() == 1);

    rc_reset();
    rc_make(&owner, "segment_corruption", COND_CRITICAL, cf_detect);
    drive_to_unresolved_critical(&owner);
    recovery_coordinator_test_drive();
    RC_CHECK("owner: active segment_corruption suppresses",
             recovery_coordinator_test_runs() == 0 &&
             blocker_fire_count_for_testing(
                 "recovery_coordinator.no_applicable_rung") == 0);
    rc_reset();
    return failures;
}

static int64_t dump_int(const struct json_value *o, const char *key)
{
    const struct json_value *v = json_get(o, key);
    return v ? json_get_int(v) : -1;
}

static bool dump_owner_is(const struct json_value *o, size_t i,
                          const char *want)
{
    const struct json_value *arr = json_get(o, "owning_conditions");
    const struct json_value *e = arr ? json_at(arr, i) : NULL;
    return e && json_get_str(e) && strcmp(json_get_str(e), want) == 0;
}

static int rc_dump_cases(void)
{
    int failures = 0;
    static struct condition other;
    struct json_value o;
    char events[8192];
    struct blocker_snapshot snaps[16];
    bool reason_ok = false;

    rc_reset();
    RC_CHECK("dump: NULL out is refused",
             !recovery_coordinator_dump_state_json(NULL, "x"));
    json_init(&o);
    json_set_object(&o);
    RC_CHECK("dump: returns true", recovery_coordinator_dump_state_json(&o, "x"));
    RC_CHECK("dump: fresh counters are zero",
             dump_int(&o, "runs") == 0 && dump_int(&o, "blocker_fires") == 0 &&
             dump_int(&o, "last_run_unix") == 0);
    RC_CHECK("dump: role text", json_get(&o, "role") &&
             strcmp(json_get_str(json_get(&o, "role")),
                    "no-applicable-rung naming fallback") == 0);
    RC_CHECK("dump: both owning conditions in order",
             json_size(json_get(&o, "owning_conditions")) == 2 &&
             dump_owner_is(&o, 0, "reducer_frontier_reconcile_light") &&
             dump_owner_is(&o, 1, "segment_corruption"));
    RC_CHECK("dump: registered flag present", json_get(&o, "registered"));
    json_free(&o);

    rc_make_crit(&other, "rc_dump_other");
    recovery_coordinator_test_drive();
    json_init(&o);
    json_set_object(&o);
    (void)recovery_coordinator_dump_state_json(&o, "x");
    RC_CHECK("dump: a fire shows runs, fires and a wall time",
             dump_int(&o, "runs") == 1 && dump_int(&o, "blocker_fires") == 1 &&
             dump_int(&o, "last_run_unix") > 1000000000);
    json_free(&o);

    int n = blocker_snapshot_all(snaps, 16);
    for (int i = 0; i < n; i++)
        if (strcmp(snaps[i].id, "recovery_coordinator.no_applicable_rung") == 0)
            reason_ok = strstr(snaps[i].reason, "deeper recovery") != NULL;
    RC_CHECK("fire: blocker carries its reason text", reason_ok);
    event_dump_json(events, sizeof(events), 8);
    RC_CHECK("fire: recovery action event emitted with peer 0",
             strstr(events, "\"peer\":0,\"data\":\"action=recovery-no-"
                            "applicable-rung blocker=named\"") != NULL);

    recovery_coordinator_test_reset();
    json_init(&o);
    json_set_object(&o);
    (void)recovery_coordinator_dump_state_json(&o, "x");
    RC_CHECK("reset: wall time, runs and fires return to zero",
             dump_int(&o, "last_run_unix") == 0 && dump_int(&o, "runs") == 0 &&
             dump_int(&o, "blocker_fires") == 0 &&
             recovery_coordinator_test_log_emits() == 0);
    json_free(&o);
    rc_reset();
    return failures;
}

/* test_reset puts the default clock back: a held test clock must not keep
 * driving the keepalive afterwards. */
static int rc_reset_clock_cases(void)
{
    int failures = 0;
    static struct condition c;
    rc_reset();
    rc_now = 1000;
    recovery_coordinator_test_set_clock(rc_clock);
    recovery_coordinator_test_reset();
    rc_make_crit(&c, "rc_clock_a");
    recovery_coordinator_test_drive();
    rc_now = 1000 + 700;
    recovery_coordinator_test_drive();
    RC_CHECK("reset: test clock is dropped, no 600 s keepalive from it",
             recovery_coordinator_test_log_emits() == 1);
    rc_reset();
    return failures;
}

static int rc_name_blocker_cases(void)
{
    int failures = 0;
    struct json_value o;
    rc_reset();
    RC_CHECK("name: no fires before naming",
             recovery_coordinator_test_blocker_fires() == 0);
    recovery_coordinator_test_name_blocker();
    json_init(&o);
    json_set_object(&o);
    (void)recovery_coordinator_dump_state_json(&o, "x");
    RC_CHECK("name: one blocker, one run, a wall time",
             recovery_coordinator_test_blocker_fires() == 1 &&
             recovery_coordinator_test_runs() == 1 &&
             dump_int(&o, "last_run_unix") > 1000000000);
    json_free(&o);
    rc_reset();
    return failures;
}

static int rc_register_cases(void)
{
    int failures = 0;
    static struct main_state ms;
    struct json_value o;
    int count_before;
    recovery_coordinator_register(NULL);
    recovery_coordinator_register(&ms);
    json_init(&o);
    json_set_object(&o);
    (void)recovery_coordinator_dump_state_json(&o, "x");
    RC_CHECK("register: a real main_state registers the child",
             json_get(&o, "registered") && json_get_bool(json_get(&o, "registered")));
    json_free(&o);
    count_before = supervisor_child_count_total();
    recovery_coordinator_register(&ms);
    RC_CHECK("register: a second call is a no-op",
             supervisor_child_count_total() == count_before);
    return failures;
}

static int rc_extra_cases(void)
{
    return rc_set_change_cases() + rc_format_cap_cases() +
           rc_format_more_cases() + rc_owner_cases() + rc_dump_cases() +
           rc_reset_clock_cases() + rc_name_blocker_cases() +
           rc_register_cases();
}

int test_recovery_coordinator(void);
int test_recovery_coordinator(void)
{
    printf("\n=== recovery_coordinator (naming-fallback fold) ===\n");
    int failures = 0;
    const char *BLOCKER_ID = "recovery_coordinator.no_applicable_rung";

    /* ── 1. no unresolved critical -> coordinator stays quiet ─────────── */
    {
        rc_reset();
        recovery_coordinator_test_drive();
        RC_CHECK("gate: no unresolved critical -> no run",
                 recovery_coordinator_test_runs() == 0);
        RC_CHECK("gate: no unresolved critical -> no blocker",
                 blocker_fire_count_for_testing(BLOCKER_ID) == 0);
    }

    /* ── 2. unresolved critical, no owning condition active -> name blocker */
    {
        rc_reset();
        static struct condition c_other = {
            .name = "rc_other_critical",
            .severity = COND_CRITICAL, .poll_secs = 1, .backoff_secs = 0,
            .max_attempts = 2, .detect = cf_detect, .remedy = cf_remedy,
            .witness = cf_witness, .witness_window_secs = 60,
        };
        drive_to_unresolved_critical(&c_other);
        RC_CHECK("fire: an unresolved critical exists",
                 condition_engine_get_unresolved_critical_count() > 0);

        recovery_coordinator_test_drive();
        RC_CHECK("fire: coordinator ran", recovery_coordinator_test_runs() == 1);
        RC_CHECK("fire: named the typed blocker",
                 blocker_fire_count_for_testing(BLOCKER_ID) > 0);
        RC_CHECK("fire: blocker counter advanced",
                 recovery_coordinator_test_blocker_fires() == 1);
    }

    /* ── 3. the unresolved critical IS an owning condition -> suppressed ─ */
    {
        rc_reset();
        /* Named exactly as the reconcile condition that owns rungs 1-2; when
         * IT is the active healer the coordinator must not name a blocker. */
        static struct condition c_owning = {
            .name = "reducer_frontier_reconcile_light",
            .severity = COND_CRITICAL, .poll_secs = 1, .backoff_secs = 0,
            .max_attempts = 2, .detect = cf_detect, .remedy = cf_remedy,
            .witness = cf_witness, .witness_window_secs = 60,
        };
        drive_to_unresolved_critical(&c_owning);
        struct condition_runtime_snapshot snap;
        RC_CHECK("suppress: owning condition is currently_active",
                 condition_engine_get_registered_snapshot(
                     "reducer_frontier_reconcile_light", &snap) &&
                 snap.currently_active);
        RC_CHECK("suppress: it is an unresolved critical",
                 condition_engine_get_unresolved_critical_count() > 0);

        recovery_coordinator_test_drive();
        RC_CHECK("suppress: coordinator stayed quiet (no run)",
                 recovery_coordinator_test_runs() == 0);
        RC_CHECK("suppress: no blocker named while owning healer is active",
                 blocker_fire_count_for_testing(BLOCKER_ID) == 0);
    }

    /* ── 4. naming fallback: typed retry-forever DEPENDENCY blocker ────── */
    {
        rc_reset();
        recovery_coordinator_test_name_blocker();
        RC_CHECK("naming: typed blocker named (no silent halt)",
                 blocker_fire_count_for_testing(BLOCKER_ID) > 0);
        struct blocker_snapshot snaps[16];
        int n = blocker_snapshot_all(snaps, 16);
        bool retry_forever_dependency = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].id, BLOCKER_ID) == 0) {
                retry_forever_dependency =
                    snaps[i].class == BLOCKER_DEPENDENCY &&
                    snaps[i].retry_budget == -1;
                break;
            }
        }
        RC_CHECK("naming: blocker is a retry-forever DEPENDENCY (guard kept)",
                 retry_forever_dependency);
        blocker_reset_for_testing();
    }

    /* ── 5. log cadence: identical ticks log once, a changed set logs again,
     *       and the keepalive fires once RC_KEEPALIVE_SECS (600) have passed ─ */
    {
        rc_reset();
        rc_now = 1000;
        recovery_coordinator_test_set_clock(rc_clock);
        static struct condition c_log_a = {
            .name = "rc_log_a",
            .severity = COND_CRITICAL, .poll_secs = 1, .backoff_secs = 0,
            .max_attempts = 2, .detect = cf_detect, .remedy = cf_remedy,
            .witness = cf_witness, .witness_window_secs = 60,
        };
        drive_to_unresolved_critical(&c_log_a);

        recovery_coordinator_test_drive();
        recovery_coordinator_test_drive();
        recovery_coordinator_test_drive();
        RC_CHECK("log: identical ticks emit one WARN",
                 recovery_coordinator_test_log_emits() == 1);

        rc_now = 1000 + 599;
        recovery_coordinator_test_drive();
        RC_CHECK("log: no keepalive before 600s",
                 recovery_coordinator_test_log_emits() == 1);

        rc_now = 1000 + 600;
        recovery_coordinator_test_drive();
        RC_CHECK("log: keepalive fires at 600s",
                 recovery_coordinator_test_log_emits() == 2);

        static struct condition c_log_b = {
            .name = "rc_log_b",
            .severity = COND_CRITICAL, .poll_secs = 1, .backoff_secs = 0,
            .max_attempts = 2, .detect = cf_detect, .remedy = cf_remedy,
            .witness = cf_witness, .witness_window_secs = 60,
        };
        drive_to_unresolved_critical(&c_log_b);
        recovery_coordinator_test_drive();
        RC_CHECK("log: changed unresolved set logs again at once",
                 recovery_coordinator_test_log_emits() == 3);
        recovery_coordinator_test_drive();
        RC_CHECK("log: unchanged set after the change stays quiet",
                 recovery_coordinator_test_log_emits() == 3);
        recovery_coordinator_test_set_clock(NULL);
        rc_reset();
    }

    /* ── 6. rc_format_names: nine unresolved criticals name eight, then +1 ─ */
    {
        static struct condition c_fmt[9];
        static const char *const fmt_names[9] = {
            "rc_fmt_0", "rc_fmt_1", "rc_fmt_2", "rc_fmt_3", "rc_fmt_4",
            "rc_fmt_5", "rc_fmt_6", "rc_fmt_7", "rc_fmt_8",
        };
        char text[512];
        rc_reset();
        for (int i = 0; i < 9; i++) {
            c_fmt[i] = (struct condition){
                .name = fmt_names[i],
                .severity = COND_CRITICAL, .poll_secs = 1, .backoff_secs = 0,
                .max_attempts = 2, .detect = cf_detect, .remedy = cf_remedy,
                .witness = cf_witness, .witness_window_secs = 60,
            };
            drive_to_unresolved_critical(&c_fmt[i]);
        }
        recovery_coordinator_test_drive();
        recovery_coordinator_test_format_logged(text, sizeof(text));
        RC_CHECK("format: 9 criticals name 8 then +1 more",
                 strcmp(text, "rc_fmt_0, rc_fmt_1, rc_fmt_2, rc_fmt_3, "
                              "rc_fmt_4, rc_fmt_5, rc_fmt_6, rc_fmt_7, +1 more") == 0);
        rc_reset();
    }

    /* ── 7. rc_format_names: names past the 512-byte cap end in "..." ───── */
    {
        static struct condition c_long[9];
        static char long_names[9][101];
        char text[512];
        char want[512];
        size_t at = 0;
        rc_reset();
        for (int i = 0; i < 9; i++) {
            memset(long_names[i], 'a' + i, 100);
            long_names[i][100] = '\0';
            c_long[i] = (struct condition){
                .name = long_names[i],
                .severity = COND_CRITICAL, .poll_secs = 1, .backoff_secs = 0,
                .max_attempts = 2, .detect = cf_detect, .remedy = cf_remedy,
                .witness = cf_witness, .witness_window_secs = 60,
            };
            drive_to_unresolved_critical(&c_long[i]);
        }
        recovery_coordinator_test_drive();
        recovery_coordinator_test_format_logged(text, sizeof(text));
        for (int i = 0; i < 5; i++) {
            if (i) {
                memcpy(want + at, ", ", 2);
                at += 2;
            }
            memset(want + at, 'a' + i, 100);
            at += 100;
        }
        memcpy(want + at, "...", 4);
        RC_CHECK("overflow: long names end in ... within 512 bytes",
                 strlen(text) == 511 && strcmp(text, want) == 0);
        rc_reset();
    }

    failures += rc_extra_cases();
    printf("recovery_coordinator: %d failures\n", failures);
    return failures;
}
