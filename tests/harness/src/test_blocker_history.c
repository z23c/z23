/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for blocker_history — the durable blocker/condition
 * firing-history aggregator over EV_OPERATOR_ALERT (see
 * services/blocker_history.h for the design).
 *
 * Coverage
 * --------
 *   1. Extractor rule coverage: one synthetic EV_OPERATOR_ALERT payload
 *      per rule (blocker=/check=/condition=/each fixed-prefix form/one
 *      unparsable), fed via direct event_log_append (bypassing the
 *      bridge — this isolates the parser from the emit path).
 *   2. Incremental-cursor proof: catch_up_ex is called twice with a
 *      batch of new events appended between calls; the SECOND call's
 *      return value (and the scan_visits_total delta) must equal
 *      exactly the delta appended, not the whole log.
 *   3. Overflow: BLOCKER_HISTORY_CAP+5 distinct ids -> row_count caps at
 *      BLOCKER_HISTORY_CAP, overflow_dropped == 5.
 *   4. Bridge integration: register the real EV_OPERATOR_NEEDED ->
 *      EV_OPERATOR_ALERT observer against a real event_log_t, emit one
 *      EV_OPERATOR_NEEDED, and confirm exactly one EV_OPERATOR_ALERT
 *      landed with a "ts=" prefix and the right body.
 *   5. Dumper shape.
 *
 * Fixture dirs live under ./test-tmp/ per the project's no-/tmp
 * convention (test_fmt_tmpdir, test/test_core.h). */

#include "test/test_core.h"

#include "services/blocker_history.h"
#include "event/event.h"
#include "json/json.h"
#include "models/database.h"
#include "storage/event_log.h"
#include "storage/event_log_singleton.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BH_CHECK(name, expr) do {          \
    printf("blocker_history: %s... ", (name)); \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static int bh_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static event_log_t *bh_open_fixture_log(const char *tag)
{
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "blocker_history", tag);
    bh_mkdir_p("./test-tmp");
    bh_mkdir_p(dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/events.log", dir);
    return event_log_open(path);
}

/* Struct capturing one raw stream visit, for the bridge test's direct
 * inspection of what landed on disk. */
struct bh_raw_capture {
    char     payload[400];
    size_t   len;
    enum event_log_type type;
    int      count;
};

static bool bh_raw_capture_cb(uint64_t offset, enum event_log_type type,
                              const void *payload, size_t len, void *user)
{
    (void)offset;
    struct bh_raw_capture *cap = user;
    cap->count++;
    cap->type = type;
    size_t n = len < sizeof(cap->payload) - 1 ? len : sizeof(cap->payload) - 1;
    memcpy(cap->payload, payload, n);
    cap->payload[n] = '\0';
    cap->len = len;
    return true;
}

int test_blocker_history(void)
{
    printf("\n=== blocker_history tests ===\n");
    int failures = 0;

    blocker_history_reset_for_test();
    blocker_history_bridge_unregister_for_test();

    /* ── 1. Extractor rule coverage + repeat-fire aggregation ───────── */
    {
        event_log_t *log = bh_open_fixture_log("extract");
        BH_CHECK("fixture: event log opens", log != NULL);
        struct node_db ndb;
        bool dbok = node_db_open(&ndb, ":memory:");
        BH_CHECK("fixture: in-memory node_db opens", dbok);
        if (!log || !dbok) goto extract_done;

        /* One payload per rule, in priority order, plus a repeat-fire id
         * (condition=) fired three times with increasing timestamps to
         * prove fire_count/first_seen/last_seen/last_reason aggregation. */
        const char *payloads[] = {
            /* blocker= wins over an earlier check= in the same payload */
            "ts=1000 check=chain_link blocker=foo.bar refuse_from_h=5 reason_a",
            "ts=1001 check=seed.torn_import seed_h=5 first_hole_h=6 torn",
            "ts=1002 condition=test_repeat_x attempts=1",
            "ts=1003 condition=test_repeat_x attempts=2",
            "ts=1004 condition=test_repeat_x attempts=3",
            "ts=1005 coin_backfill h=100 status=refused reason=held",
            "ts=1006 script_validate prevout_unresolved height=5 tx=ab vin=0 held",
            "ts=1007 proof_validate internal_error height=5 type=x txid=ab held",
            "ts=1008 reducer_frontier script_undetermined height=5 tx=ab vin=0 status=x",
            "ts=1009 nonsense payload with no known key token at all",
        };
        const size_t n_payloads = sizeof(payloads) / sizeof(payloads[0]);
        for (size_t i = 0; i < n_payloads; i++) {
            uint64_t off = event_log_append(log, EV_OPERATOR_ALERT,
                                            payloads[i], strlen(payloads[i]));
            BH_CHECK("append fixture event", off != UINT64_MAX);
        }

        int visited = blocker_history_catch_up_ex(log, &ndb);
        BH_CHECK("catch_up_ex: visits every appended event exactly once",
                 visited == (int)n_payloads);

        struct json_value v = {0};
        json_set_object(&v);
        bool ok = blocker_history_dump_state_json(&v, "20");
        BH_CHECK("dump: returns true", ok);

        const struct json_value *unparsed = json_get(&v, "unparsed_events");
        BH_CHECK("dump: unparsed_events == 1 (the nonsense payload)",
                 unparsed && json_get_int(unparsed) == 1);
        const struct json_value *overflow = json_get(&v, "overflow_dropped");
        BH_CHECK("dump: overflow_dropped == 0",
                 overflow && json_get_int(overflow) == 0);
        /* distinct ids: foo.bar, seed.torn_import, test_repeat_x,
         * coin_backfill, script_validate.prevout_unresolved,
         * proof_validate.internal_error, reducer_frontier.script_undetermined
         * = 7 (the nonsense payload contributes no id). */
        const struct json_value *distinct = json_get(&v, "distinct_ids");
        BH_CHECK("dump: distinct_ids == 7",
                 distinct && json_get_int(distinct) == 7);

        const struct json_value *top = json_get(&v, "top");
        bool found_blocker_eq = false, found_check_eq = false,
             found_repeat = false, found_coin_backfill = false;
        if (top && top->type == JSON_ARR) {
            for (size_t i = 0; i < json_size(top); i++) {
                const struct json_value *row = json_at(top, i);
                const char *id = json_get_str(json_get(row, "id"));
                if (!id) continue;
                if (strcmp(id, "foo.bar") == 0) {
                    found_blocker_eq = true;
                    BH_CHECK("blocker= priority: fire_count == 1",
                             json_get_int(json_get(row, "fire_count")) == 1);
                    BH_CHECK("blocker= priority: first_seen == 1000",
                             json_get_int(json_get(row, "first_seen_unix"))
                                 == 1000);
                } else if (strcmp(id, "seed.torn_import") == 0) {
                    found_check_eq = true;
                } else if (strcmp(id, "test_repeat_x") == 0) {
                    found_repeat = true;
                    BH_CHECK("condition= repeat: fire_count == 3",
                             json_get_int(json_get(row, "fire_count")) == 3);
                    BH_CHECK("condition= repeat: first_seen == 1002",
                             json_get_int(json_get(row, "first_seen_unix"))
                                 == 1002);
                    BH_CHECK("condition= repeat: last_seen == 1004",
                             json_get_int(json_get(row, "last_seen_unix"))
                                 == 1004);
                    const char *reason =
                        json_get_str(json_get(row, "last_reason"));
                    BH_CHECK("condition= repeat: last_reason is the LATEST fire",
                             reason && strstr(reason, "attempts=3") != NULL);
                } else if (strcmp(id, "coin_backfill") == 0) {
                    found_coin_backfill = true;
                }
            }
        }
        BH_CHECK("top: blocker= id present", found_blocker_eq);
        BH_CHECK("top: check= id present", found_check_eq);
        BH_CHECK("top: condition= repeat id present", found_repeat);
        BH_CHECK("top: coin_backfill coarsened id present",
                 found_coin_backfill);
        json_free(&v);

        /* ── 2. Incremental-cursor proof ─────────────────────────── */
        uint64_t visits_before = blocker_history_scan_visits_total();
        const char *more[] = {
            "ts=2000 condition=test_repeat_x attempts=4",
            "ts=2001 check=another.check_id reason_b",
            "ts=2002 blocker=another.blocker_id refuse_from_h=1 reason_c",
        };
        const size_t n_more = sizeof(more) / sizeof(more[0]);
        for (size_t i = 0; i < n_more; i++)
            BH_CHECK("append second-batch event",
                     event_log_append(log, EV_OPERATOR_ALERT, more[i],
                                      strlen(more[i])) != UINT64_MAX);

        int visited2 = blocker_history_catch_up_ex(log, &ndb);
        BH_CHECK("catch_up_ex #2: visits exactly the delta, not the "
                 "whole log", visited2 == (int)n_more);
        uint64_t visits_after = blocker_history_scan_visits_total();
        BH_CHECK("scan_visits_total advanced by exactly the delta",
                 visits_after - visits_before == n_more);

        /* A third call with nothing new appended must visit zero. */
        int visited3 = blocker_history_catch_up_ex(log, &ndb);
        BH_CHECK("catch_up_ex #3 (idle): visits zero new events",
                 visited3 == 0);

    extract_done:
        if (dbok) node_db_close(&ndb);
        if (log) event_log_close(log);
    }

    /* ── 3. Overflow ──────────────────────────────────────────────── */
    {
        blocker_history_reset_for_test();
        event_log_t *log = bh_open_fixture_log("overflow");
        BH_CHECK("overflow fixture: event log opens", log != NULL);
        struct node_db ndb;
        bool dbok = node_db_open(&ndb, ":memory:");
        BH_CHECK("overflow fixture: in-memory node_db opens", dbok);
        if (!log || !dbok) goto overflow_done;

        const int total_ids = BLOCKER_HISTORY_CAP + 5;
        for (int i = 0; i < total_ids; i++) {
            char payload[128];
            int len = snprintf(payload, sizeof(payload),
                               "ts=%d condition=overflow_id_%03d fire",
                               3000 + i, i);
            BH_CHECK("append overflow event",
                     event_log_append(log, EV_OPERATOR_ALERT, payload,
                                      (size_t)len) != UINT64_MAX);
        }
        int visited = blocker_history_catch_up_ex(log, &ndb);
        BH_CHECK("overflow: visits every distinct-id event once",
                 visited == total_ids);

        struct json_value v = {0};
        json_set_object(&v);
        bool ok = blocker_history_dump_state_json(&v, NULL);
        BH_CHECK("overflow dump: returns true", ok);
        const struct json_value *distinct = json_get(&v, "distinct_ids");
        BH_CHECK("overflow: distinct_ids caps at BLOCKER_HISTORY_CAP",
                 distinct &&
                 json_get_int(distinct) == BLOCKER_HISTORY_CAP);
        const struct json_value *overflow = json_get(&v, "overflow_dropped");
        BH_CHECK("overflow: overflow_dropped == 5",
                 overflow && json_get_int(overflow) == 5);
        const struct json_value *cap = json_get(&v, "capacity");
        BH_CHECK("overflow: capacity == BLOCKER_HISTORY_CAP",
                 cap && json_get_int(cap) == BLOCKER_HISTORY_CAP);
        json_free(&v);

    overflow_done:
        if (dbok) node_db_close(&ndb);
        if (log) event_log_close(log);
    }

    /* ── 4. Bridge integration ───────────────────────────────────── */
    {
        blocker_history_reset_for_test();
        event_log_t *log = bh_open_fixture_log("bridge");
        BH_CHECK("bridge fixture: event log opens", log != NULL);
        struct node_db ndb;
        bool dbok = node_db_open(&ndb, ":memory:");
        BH_CHECK("bridge fixture: in-memory node_db opens", dbok);
        if (!log || !dbok) goto bridge_done;

        event_log_set_singleton(log);
        blocker_history_bridge_register();

        event_emitf(EV_OPERATOR_NEEDED, 0, "condition=%s attempts=%d",
                   "test_bridge_x", 3);

        /* Exactly one EV_OPERATOR_ALERT landed, with a ts= prefix and the
         * original payload body intact. */
        struct bh_raw_capture cap = {0};
        int rc = event_log_stream(log, 0, bh_raw_capture_cb, &cap);
        BH_CHECK("bridge: stream over the durable log succeeds", rc == 0);
        BH_CHECK("bridge: exactly one durable event landed",
                 cap.count == 1);
        BH_CHECK("bridge: durable event is EV_OPERATOR_ALERT",
                 cap.type == EV_OPERATOR_ALERT);
        BH_CHECK("bridge: payload carries the ts= prefix",
                 strncmp(cap.payload, "ts=", 3) == 0);
        BH_CHECK("bridge: payload carries the original condition= body",
                 strstr(cap.payload, "condition=test_bridge_x attempts=3")
                     != NULL);

        int visited = blocker_history_catch_up_ex(log, &ndb);
        BH_CHECK("bridge: catch_up_ex folds the bridged event",
                 visited == 1);

        /* Drop the singleton BEFORE calling the dumper: the dumper's
         * internal blocker_history_catch_up() sources event_log_singleton()
         * + app_runtime_node_db() (the production globals, not this
         * test's fixture `ndb`) — leaving the singleton set here would
         * make it re-stream the same log from a different (likely
         * cursor-less) ndb and double-fold the one bridged event. NULL
         * makes that internal call a safe no-op, so the dump reflects
         * exactly what the explicit catch_up_ex call above already
         * folded. */
        event_log_set_singleton(NULL);

        struct json_value v = {0};
        json_set_object(&v);
        bool ok = blocker_history_dump_state_json(&v, NULL);
        BH_CHECK("bridge dump: returns true", ok);
        const struct json_value *top = json_get(&v, "top");
        bool found = false;
        if (top && top->type == JSON_ARR) {
            for (size_t i = 0; i < json_size(top); i++) {
                const struct json_value *row = json_at(top, i);
                const char *id = json_get_str(json_get(row, "id"));
                if (id && strcmp(id, "test_bridge_x") == 0) {
                    found = true;
                    BH_CHECK("bridge: aggregated fire_count == 1",
                             json_get_int(json_get(row, "fire_count")) == 1);
                }
            }
        }
        BH_CHECK("bridge: bridged id reached the aggregate table", found);
        json_free(&v);

    bridge_done:
        event_clear_observers(EV_OPERATOR_NEEDED);
        event_log_set_singleton(NULL);
        blocker_history_bridge_unregister_for_test();
        if (dbok) node_db_close(&ndb);
        if (log) event_log_close(log);
    }

    /* ── cleanup: no state leaks into later test groups ─────────── */
    blocker_history_reset_for_test();
    blocker_history_bridge_unregister_for_test();

    printf("blocker_history: %s (%d failures)\n",
          failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
