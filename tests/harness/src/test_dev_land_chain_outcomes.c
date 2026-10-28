/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: failure identity, chains, outcome refusals, bounded drives and proof drives.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"


int test_dev_land_watcher_admission(void)
{
    int failures = 0;
#if defined(__linux__)
    TEST("land: scheduler refusal and successful exit never invent watcher readiness") {
        char root[512], scheduler[600], detail[256];
        test_make_tmpdir(root, sizeof(root), "dev_land", "watcher_admission");
        (void)snprintf(scheduler, sizeof(scheduler), "%s/scheduler", root);
        ASSERT(dlx_write(scheduler,
            "#!/bin/sh\n"
            "test \"$1\" = --wait || exit 64\n"
            "test \"$2\" = --project || exit 64\n"
            "test \"$3\" = z23 || exit 64\n"
            "test \"$5\" = dev || exit 64\n"
            "test \"$6\" = loop || exit 64\n"
            "test \"$7\" = ensure || exit 64\n"
            "printf '%s' \"$8\" > \"$0.input\"\n"
            "exit 75\n"));
        ASSERT(chmod(scheduler, 0700) == 0);
        zcl_native_dev_land_test_watcher_launch(root, scheduler, detail,
                                                sizeof(detail));
        ASSERT(strstr(detail, "exit=75") != NULL);
        ASSERT(strstr(detail, "readiness_unconfirmed") != NULL);
        char input_path[640], input_text[1200] = {0};
        size_t input_len = 0;
        (void)snprintf(input_path, sizeof(input_path), "%s.input", scheduler);
        ASSERT(dlx_slurp(input_path, input_text, sizeof(input_text) - 1,
                         &input_len));
        ASSERT(input_len > 8 && memcmp(input_text, "--input=", 8) == 0);
        struct json_value routed;
        json_init(&routed);
        ASSERT(json_read(&routed, input_text + 8, input_len - 8));
        const char *routed_root = json_get_str(json_get(&routed, "root"));
        const char *routed_mode = json_get_str(json_get(&routed, "mode"));
        bool routed_ok = routed.num_children == 2 && routed_root && routed_mode &&
            strcmp(routed_root, root) == 0 && strcmp(routed_mode, "verify") == 0;
        json_free(&routed);
        ASSERT(routed_ok);
        ASSERT(dlx_write(scheduler, "#!/bin/sh\nexit 0\n"));
        zcl_native_dev_land_test_watcher_launch(root, scheduler, detail,
                                                sizeof(detail));
        ASSERT(strstr(detail, "exit=0") != NULL);
        ASSERT(strstr(detail, "readiness_unconfirmed") != NULL);
        ASSERT(dlx_write(scheduler,
            "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$0.pid\"\nexec sleep 30\n"));
        int64_t started = platform_time_monotonic_ms();
        zcl_native_dev_land_test_watcher_launch(root, scheduler, detail,
                                                sizeof(detail));
        int64_t elapsed = platform_time_monotonic_ms() - started;
        ASSERT(elapsed >= 9000 && elapsed < 20000);
        ASSERT(strstr(detail, "readiness_unconfirmed") != NULL);
        char pid_path[640], pid_text[32] = {0};
        size_t pid_len = 0;
        (void)snprintf(pid_path, sizeof(pid_path), "%s.pid", scheduler);
        ASSERT(dlx_slurp(pid_path, pid_text, sizeof(pid_text) - 1, &pid_len));
        char *end = NULL;
        long child = strtol(pid_text, &end, 10);
        ASSERT(pid_len > 0 && child > 1 && end && (*end == '\n' || *end == '\0'));
        errno = 0;
        ASSERT(kill((pid_t)child, 0) == -1 && errno == ESRCH);
        printf("watcher admission: timeout_ms=%lld child_reaped=yes\n",
               (long long)elapsed);
        PASS();
    } _test_next:;
#endif
    return failures;
}

int test_dev_land_long_proof_root(void)
{
    int failures = 0;
    TEST("land: a long proof root remains a structured, worker-stealable action") {
        struct dlx_rig rig;
        struct dlx_call c;
        char parent[sizeof(g_dlx_state)], extended[sizeof(g_dlx_state)];
        char leaf[201];
        dlx_isolate("long_proof_root");
        (void)snprintf(parent, sizeof(parent), "%s", g_dlx_state);
        memset(leaf, 'p', sizeof(leaf) - 1);
        leaf[sizeof(leaf) - 1] = '\0';
        ASSERT(mkdir(parent, 0700) == 0);
        ASSERT(snprintf(extended, sizeof(extended), "%s/%s", parent, leaf) <
               (int)sizeof(extended));
        ASSERT(mkdir(extended, 0700) == 0);
        (void)snprintf(g_dlx_state, sizeof(g_dlx_state), "%s", extended);
        ASSERT(setenv("XDG_STATE_HOME", g_dlx_state, 1) == 0);
        ASSERT(dlx_rig_make(&rig, "long_proof_root_rig"));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "manual", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strstr(dlx_str(&c, "detail"), rig.tip) != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "exceeds row detail") == NULL);
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        const struct json_value *flight = json_get(&c.reply.data, "in_flight");
        const struct json_value *action = json_get(flight, "proof_step");
        ASSERT(action != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(action, "command")), "dev.proof.step");
        ASSERT_STR_EQ(json_get_str(json_get(action, "local_commit")), rig.tip);
        ASSERT(strstr(json_get_str(json_get(action, "root")), leaf) != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(action, "remote_base")),
                      json_get_str(json_get(flight, "base")));
        dlx_end(&c);
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}

/* Codec cases deliberately exercise the production parser and encoder before
 * a submit interface can produce dependency authority. */
#define DLX_CHAIN_M "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define DLX_CHAIN_A "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define DLX_CHAIN_B "cccccccccccccccccccccccccccccccccccccccc"
#define DLX_CHAIN_ROW "\"seq\":3,\"tip\":\"" DLX_CHAIN_B "\",\"state\":\"queued\",\"attempt\":1"
#define DLX_CHAIN_FIELDS "\"predecessor_seq\":2,\"predecessor_local\":\"" DLX_CHAIN_A "\",\"predecessor_base\":\"" DLX_CHAIN_M "\",\"predecessor_tree\":\"" DLX_CHAIN_A "\",\"predecessor_intent\":\"" DLX_CHAIN_A "@" DLX_CHAIN_M "\""

static bool dlx_failure_fixture(struct dlx_rig *rig, char base[64], char attempt[4096], char out[32768])
{
    const char *parent[] = {"rev-parse", "HEAD^", NULL};
    return dlx_rig_make(rig, "failure_identity_rig") && dlx_git_out(rig->clone, parent, base, 64) == 0 &&
        zcl_dev_proof_test_failure_attempt_prepare(rig->clone, rig->tip, base, attempt, 4096) &&
        zcl_dev_proof_test_failure_attempt_settle(rig->clone, rig->tip, base, attempt, "child_proof_failed_exit_2") &&
        zcl_native_dev_land_test_failure_capture(rig->clone, rig->tip, base, false, out, 32768);
}

static int dlx_failure_identity_roundtrip(void)
{
    int failures = 0;
    TEST("land: exact proof identity round trips and original failed outcome survives later PASS") {
        struct dlx_rig rig; char base[64], attempt[4096], original[32768], again[32768], history[4096];
        dlx_isolate("failure_identity_roundtrip");
        ASSERT(dlx_failure_fixture(&rig, base, attempt, original));
        ASSERT(strstr(original, "\"failed_proof_attempt\":") != NULL);
        ASSERT(strstr(original, strrchr(attempt, '/') + 1) != NULL);
        ASSERT(zcl_native_dev_land_test_chain_codec(original, again, sizeof(again)));
        ASSERT_STR_EQ(original, again);
        test_make_tmpdir(history, sizeof(history), "dev_land", "failure_identity_history");
        ASSERT(zcl_native_dev_land_test_failure_replay(history, original, again, sizeof(again)));
        struct json_value timed = {0}; ASSERT(json_read(&timed, again, strlen(again)));
        ASSERT(json_get_int(json_get(&timed, "terminal_recorded_at")) > 0); json_free(&timed);
        char *time_member = strstr(again, ",\"terminal_recorded_at\":"); ASSERT(time_member != NULL);
        memcpy(time_member, "}\n", 3); /* compare every preexisting field exactly */
        ASSERT_STR_EQ(original, again);
        ASSERT(strstr(again, "\"state\":\"failed\"") != NULL);
        ASSERT(zcl_native_dev_land_test_failure_capture(rig.clone, rig.tip, base, true, again, sizeof(again)));
        ASSERT(strstr(again, "failed_proof_") == NULL);
        PASS();
    } _test_next:;
    dlx_restore(); return failures;
}

static bool dlx_failure_bad_fields(const char *original)
{
    const char *keys[] = {"failed_proof_root", "failed_proof_attempt", "failed_proof_request_sha3", "failed_proof_archive_sha3"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        for (size_t kind = 0; kind < 4; kind++) {
            struct json_value doc = {0};
            if (!json_read(&doc, original, strlen(original))) return false;
            struct json_value *field = NULL;
            for (size_t j = 0; j < doc.num_children; j++)
                if (strcmp(doc.keys[j], keys[i]) == 0) field = &doc.children[j];
            if (!field) { json_free(&doc); return false; }
            if (kind == 0) json_set_null(field);
            else if (kind == 1) json_set_int(field, 1);
            else if (kind == 2) json_set_object(field);
            else json_set_str(field, i == 0 ? "/a/../b" : "wrong");
            char changed[32768], out[32768]; size_t n = json_write(&doc, changed, sizeof(changed));
            json_free(&doc);
            if (!n || !zcl_native_dev_land_test_chain_codec(changed, out, sizeof(out)) || strstr(out, "failed_proof_")) return false;
        }
    }
    return true;
}

static int dlx_failure_identity_refusals(void)
{
    int failures = 0;
    TEST("land: malformed optional proof tuple becomes unknown without changing verdict") {
        struct dlx_rig rig; char base[64], attempt[4096], original[32768], out[32768], changed[32768];
        dlx_isolate("failure_identity_refusals");
        ASSERT(dlx_failure_fixture(&rig, base, attempt, original));
        ASSERT(dlx_failure_bad_fields(original));
        size_t n = strlen(original);
        ASSERT(snprintf(changed, sizeof(changed), "%.*s,\"failed_proof_root\":\"/duplicate\"}\n",
            (int)n - 2, original) < (int)sizeof(changed));
        ASSERT(zcl_native_dev_land_test_chain_codec(changed, out, sizeof(out)));
        ASSERT(strstr(out, "failed_proof_") == NULL);
        ASSERT(strstr(out, "\"state\":\"failed\"") != NULL);
        size_t legacy_cap = strlen(out) + 1;
        ASSERT(zcl_native_dev_land_test_chain_codec(original, changed, legacy_cap));
        ASSERT_STR_EQ(out, changed); /* optional metadata capacity never blocks the row */
        ASSERT(snprintf(changed, sizeof(changed), "{\"seq\":1,\"tip\":\"%s\",\"state\":\"failed\","
            "\"attempt\":1,\"local\":\"%s\",\"base\":\"%s\",\"failed_proof_root\":\"/partial\"}",
            rig.tip, rig.tip, base) < (int)sizeof(changed));
        ASSERT(zcl_native_dev_land_test_chain_codec(changed, out, sizeof(out)));
        ASSERT(strstr(out, "failed_proof_") == NULL);
        ASSERT(zcl_native_dev_land_test_chain_codec("{" DLX_CHAIN_ROW "}", out, sizeof(out)));
        ASSERT(strstr(out, "failed_proof_") == NULL);
        PASS();
    } _test_next:;
    dlx_restore(); return failures;
}

static int dlx_failure_identity_tamper(void)
{
    int failures = 0;
    TEST("land: changed current archive loses fresh attribution while retained outcome replay preserves its snapshot") {
        struct dlx_rig rig; char base[64], attempt[4096], original[32768], out[32768], archive[4300];
        dlx_isolate("failure_identity_tamper");
        ASSERT(dlx_failure_fixture(&rig, base, attempt, original));
        ASSERT(snprintf(archive, sizeof(archive), "%s/logs/failure.txt", attempt) < (int)sizeof(archive));
        ASSERT(dlx_write(archive, "changed archive bytes\n")); ASSERT(chmod(archive, 0600) == 0);
        ASSERT(zcl_native_dev_land_test_failure_capture(rig.clone, rig.tip, base, false, out, sizeof(out)));
        ASSERT(strstr(out, "failed_proof_") == NULL);
        ASSERT(strstr(out, "\"state\":\"failed\"") != NULL);
        ASSERT(zcl_native_dev_land_test_chain_codec(original, out, sizeof(out)));
        ASSERT_STR_EQ(original, out);
        PASS();
    } _test_next:;
    dlx_restore(); return failures;
}

static long long dlx_terminal_clock(const char *line)
{
    struct json_value doc = {0};
    if (!json_read(&doc, line, strlen(line))) return -1;
    const struct json_value *field = json_get(&doc, "terminal_recorded_at");
    long long value = field ? json_get_int(field) : 0;
    json_free(&doc); return value;
}

static int dlx_terminal_time_fresh(void)
{
    int failures = 0;
    TEST("land: fresh terminal variants record observation before append and replay never redates") {
        const char *states[] = {"failed", "cancelled", "conflict", "landed"};
        dlx_isolate("terminal_time_fresh");
        for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
            char root[4096], tag[64], line[1024], out[32768], path[4300], raw[32768]; size_t bytes;
            snprintf(tag, sizeof(tag), "terminal_time_%s", states[i]);
            test_make_tmpdir(root, sizeof(root), "dev_land", tag);
            ASSERT(snprintf(line, sizeof(line), "{\"seq\":1,\"tip\":\"" DLX_CHAIN_B "\",\"attempt\":1,\"state\":\"%s\"}", states[i]) < (int)sizeof(line));
            int64_t before = platform_time_wall_unix();
            ASSERT(zcl_native_dev_land_test_terminal_record(root, line, out, sizeof(out)));
            ASSERT(dlx_terminal_clock(out) >= before && dlx_terminal_clock(out) <= platform_time_wall_unix());
            ASSERT(snprintf(path, sizeof(path), "%s/outcomes.jsonl", root) < (int)sizeof(path));
            ASSERT(dlx_slurp(path, raw, sizeof(raw), &bytes));
            ASSERT(bytes == strlen(out) && memcmp(raw, out, bytes) == 0); /* exactly one original outcome */
        }
        PASS();
    } _test_next:;
    dlx_restore(); return failures;
}

static int dlx_terminal_time_legacy(void)
{
    int failures = 0;
    TEST("land: legacy terminal replay preserves unknown time and raw historical bytes") {
        char root[4096], path[4300], out[32768], raw[32768]; size_t bytes;
        static const char legacy[] = "{\"seq\":1,\"tip\":\"" DLX_CHAIN_B "\",\"attempt\":1,\"state\":\"failed\"}\n";
        dlx_isolate("terminal_time_legacy");
        test_make_tmpdir(root, sizeof(root), "dev_land", "terminal_legacy_history");
        ASSERT(snprintf(path, sizeof(path), "%s/outcomes.jsonl", root) < (int)sizeof(path));
        ASSERT(dlx_write(path, legacy));
        ASSERT(zcl_native_dev_land_test_terminal_record(root, legacy, out, sizeof(out)));
        ASSERT(dlx_terminal_clock(out) == 0 && strstr(out, "terminal_recorded_at") == NULL);
        ASSERT(dlx_slurp(path, raw, sizeof(raw), &bytes));
        ASSERT(bytes == strlen(legacy) && memcmp(raw, legacy, bytes) == 0);
        PASS();
    } _test_next:;
    dlx_restore(); return failures;
}

static int dlx_terminal_time_codec(void)
{
    int failures = 0;
    TEST("land: optional terminal time rejects malformed metadata without obstructing verdict or claiming clock continuity") {
        const char *values[] = {"null", "0", "-1", "1.5", "\"123\"", "{}", "[]", "true", "1,\"terminal_recorded_at\":2"};
        char line[1024], out[32768], legacy[32768];
        for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
            ASSERT(snprintf(line, sizeof(line), "{\"seq\":1,\"tip\":\"" DLX_CHAIN_B "\",\"attempt\":1,\"state\":\"failed\",\"terminal_recorded_at\":%s}", values[i]) < (int)sizeof(line));
            ASSERT(zcl_native_dev_land_test_chain_codec(line, out, sizeof(out)));
            ASSERT(dlx_terminal_clock(out) == 0 && strstr(out, "\"state\":\"failed\"") != NULL);
        }
        ASSERT(zcl_native_dev_land_test_chain_codec("{\"seq\":1,\"tip\":\"" DLX_CHAIN_B "\",\"attempt\":1,\"state\":\"failed\"}", legacy, sizeof(legacy)));
        ASSERT(snprintf(line, sizeof(line), "{\"seq\":1,\"tip\":\"" DLX_CHAIN_B "\",\"attempt\":1,\"state\":\"failed\",\"terminal_recorded_at\":4102444800}") < (int)sizeof(line));
        ASSERT(zcl_native_dev_land_test_chain_codec(line, out, sizeof(out)));
        ASSERT(dlx_terminal_clock(out) == 4102444800LL); /* caller must reject future/window anomalies */
        ASSERT(zcl_native_dev_land_test_chain_codec(line, out, strlen(legacy) + 1));
        ASSERT_STR_EQ(out, legacy); /* optional capacity cannot block the old row */
        ASSERT(zcl_native_dev_land_test_chain_codec("{" DLX_CHAIN_ROW ",\"terminal_recorded_at\":123}", out, sizeof(out)));
        ASSERT(dlx_terminal_clock(out) == 0); /* new queued/nonterminal state cannot retain stale time */
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_terminal_time_append_refusal(void)
{
    int failures = 0;
    TEST("land: refused first append creates no historical timestamp or outcome") {
        char root[4096], path[4300], out[32768];
        static const char line[] = "{\"seq\":1,\"tip\":\"" DLX_CHAIN_B "\",\"attempt\":1,\"state\":\"failed\"}";
        dlx_isolate("terminal_time_append_refusal");
        test_make_tmpdir(root, sizeof(root), "dev_land", "terminal_refused_history");
        ASSERT(snprintf(path, sizeof(path), "%s/outcomes.jsonl", root) < (int)sizeof(path));
        ASSERT(setenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND", "1", 1) == 0);
        ASSERT(setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0);
        ASSERT(!zcl_native_dev_land_test_terminal_record(root, line, out, sizeof(out)));
        ASSERT(!dlx_file_exists(path));
        unsetenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND");
        int64_t before = platform_time_wall_unix();
        ASSERT(zcl_native_dev_land_test_terminal_record(root, line, out, sizeof(out)));
        ASSERT(dlx_terminal_clock(out) >= before);
        PASS();
    } _test_next:;
    unsetenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND");
    unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    dlx_restore(); return failures;
}

int test_dev_land_chain_codec(void)
{
    int failures = 0;
    failures += dlx_terminal_time_fresh();
    failures += dlx_terminal_time_legacy();
    failures += dlx_terminal_time_codec();
    failures += dlx_terminal_time_append_refusal();
    failures += dlx_failure_identity_roundtrip();
    failures += dlx_failure_identity_refusals();
    failures += dlx_failure_identity_tamper();
    TEST("land: dependency tuple round trips and malformed authority refuses") {
        char out[32768], again[32768];
        ASSERT(zcl_native_dev_land_test_chain_codec("{" DLX_CHAIN_ROW "}", out, sizeof(out)));
        ASSERT(strstr(out, "predecessor_") == NULL);
        dlx_isolate("chain_codec_refusal");
        struct dlx_call call; dlx_begin(&call, "step"); ASSERT(dlx_run(&call) && dlx_ok(&call)); dlx_end(&call);
        char land[1024], queue[1200], history[1200], bytes[2048]; size_t len = 0;
        dlx_landdir(land, sizeof(land));
        (void)snprintf(queue, sizeof(queue), "%s/queue.jsonl", land);
        (void)snprintf(history, sizeof(history), "%s/outcomes.jsonl", land);
        static const char partial[] = "{" DLX_CHAIN_ROW ",\"predecessor_seq\":2}\n";
        static const char terminal[] = "{\"seq\":1,\"tip\":\"" DLX_CHAIN_M "\",\"state\":\"cancelled\",\"attempt\":1}\n";
        ASSERT(dlx_write(queue, partial)); ASSERT(dlx_write(history, terminal));
        static const char *actions[] = { "status", "step" };
        for (size_t i = 0; i < 2; ++i) {
            dlx_begin(&call, actions[i]);
            ASSERT(dlx_run(&call)); ASSERT_STR_EQ(dlx_err_code(&call), "QUEUE_READ_FAILED");
            ASSERT_STR_EQ(dlx_err_evidence(&call), "malformed_queue_record_1"); dlx_end(&call);
            ASSERT(dlx_slurp(queue, bytes, sizeof(bytes) - 1, &len)); bytes[len] = '\0'; ASSERT_STR_EQ(bytes, partial);
            ASSERT(dlx_slurp(history, bytes, sizeof(bytes) - 1, &len)); bytes[len] = '\0'; ASSERT_STR_EQ(bytes, terminal);
        }
        dlx_restore();
        ASSERT(zcl_native_dev_land_test_chain_codec("{" DLX_CHAIN_ROW "," DLX_CHAIN_FIELDS "}", out, sizeof(out)));
        ASSERT(strstr(out, "\"predecessor_seq\":2") != NULL);
        ASSERT(strstr(out, DLX_CHAIN_A "@" DLX_CHAIN_M) != NULL);
        ASSERT(zcl_native_dev_land_test_chain_codec(out, again, sizeof(again)));
        ASSERT_STR_EQ(out, again);
        static const char *fields[] = { "predecessor_local", "predecessor_base", "predecessor_tree", "predecessor_intent", "predecessor_seq" };
        static const long long bad_sequences[] = { -1, 0, 3, 4 };
        for (size_t i = 0; i < 5; ++i) {
            for (int kind = 0; kind < 4; ++kind) {
                struct json_value doc; json_init(&doc);
                ASSERT(json_read(&doc, again, strlen(again)));
                struct json_value *v = NULL;
                for (size_t j = 0; j < doc.num_children; ++j)
                    if (strcmp(doc.keys[j], fields[i]) == 0) v = &doc.children[j];
                ASSERT(v != NULL);
                char oversized[256]; memset(oversized, 'a', sizeof(oversized) - 1); oversized[255] = '\0';
                if (i == 4) json_set_int(v, bad_sequences[kind]);
                else if (kind == 0) json_set_null(v);
                else if (kind == 1) json_set_int(v, 1);
                else json_set_str(v, kind == 2 ? "bad" : oversized);
                char line[2048]; size_t n = json_write(&doc, line, sizeof(line)); json_free(&doc);
                ASSERT(n > 0 && n < sizeof(line));
                ASSERT(!zcl_native_dev_land_test_chain_codec(line, out, sizeof(out)));
            }
        }
        static const char *bad[] = {
            "\"predecessor_seq\":2", "\"predecessor_local\":\"" DLX_CHAIN_A "\"",
            DLX_CHAIN_FIELDS ",\"predecessor_seq\":2",
            DLX_CHAIN_FIELDS ",\"predecessor_local\":null",
            DLX_CHAIN_FIELDS ",\"predecessor_base\":0",
            DLX_CHAIN_FIELDS ",\"predecessor_tree\":\"bad\"",
            DLX_CHAIN_FIELDS ",\"predecessor_intent\":\"bad\"",
            "\"predecessor_seq\":-1", "\"predecessor_seq\":9223372036854775808",
            "\"predecessor_seq\":null", "\"predecessor_seq\":\"2\"",
            "\"predecessor_seq\":0,\"predecessor_local\":\"" DLX_CHAIN_A "\""
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
            char line[2048];
            ASSERT(snprintf(line, sizeof(line), "{%s,%s}", DLX_CHAIN_ROW, bad[i]) < (int)sizeof(line));
            ASSERT(!zcl_native_dev_land_test_chain_codec(line, out, sizeof(out)));
        }
        /* The current row boundary refuses containers before tuple parsing. */
        ASSERT(!zcl_native_dev_land_test_chain_codec("{" DLX_CHAIN_ROW ",\"nested\":{" DLX_CHAIN_FIELDS "}}", out, sizeof(out)));
        PASS();
    } _test_next:;
    return failures;
}

bool dlx_chain_row(char *out, size_t cap, long long seq,
    const char *repo, const char *local, const char *base, const char *state,
    long long predecessor, const char *pred_base, const char *pred_tree)
{
    char tree[64], dependency[512] = "";
    const char *args[] = { "--no-replace-objects", "show", "-s", "--format=%T", local, NULL };
    if (dlx_git_out(repo, args, tree, sizeof(tree)) != 0) return false;
    if (predecessor && snprintf(dependency, sizeof(dependency),
        ",\"predecessor_seq\":%lld,\"predecessor_local\":\"%s\",\"predecessor_base\":\"%s\","
        "\"predecessor_tree\":\"%s\",\"predecessor_intent\":\"%s@%s\"",
        predecessor, base, pred_base, pred_tree, base, pred_base) >= (int)sizeof(dependency)) return false;
    return snprintf(out, cap,
        "{\"seq\":%lld,\"tip\":\"%s\",\"state\":\"%s\",\"phase\":\"prove\",\"attempt\":1,"
        "\"worktree\":\"%s\",\"base\":\"%s\",\"local\":\"%s\",\"tree\":\"%s\",\"proof_intent\":\"%s@%s\"%s}",
        seq, local, state, repo, base, local, tree, local, base, dependency) < (int)cap;
}

int test_dev_land_chain_relation(void)
{
    int failures = 0;
    TEST("land: only exact live dependency anchors wait; invalid identity never becomes current") {
        struct dlx_rig rig;
        char m[64], a[64], b[64], c[64], ta[64], tb[64];
        char ar[2048], br[2048], cr[2048], changed[2048];
        long long waiting = 0;
        dlx_isolate("chain_relation");
        ASSERT(dlx_rig_make(&rig, "chain_relation_rig"));
        ASSERT(dlx_origin_main(&rig, m));
        ASSERT(dlx_sign_arm(rig.clone, "chain_relation_sign"));
        const char *sign[] = { "commit", "--amend", "--no-edit", "--no-verify", "-S", NULL };
        const char *head[] = { "rev-parse", "HEAD", NULL };
        const char *tree[] = { "rev-parse", "HEAD^{tree}", NULL };
        ASSERT(dlx_git(rig.clone, sign) == 0);
        ASSERT(dlx_git_out(rig.clone, head, a, sizeof(a)) == 0);
        ASSERT(dlx_git_out(rig.clone, tree, ta, sizeof(ta)) == 0);
        ASSERT(dlx_commit(rig.clone, "b.txt", "b\n", b));
        ASSERT(dlx_git(rig.clone, sign) == 0);
        ASSERT(dlx_git_out(rig.clone, head, b, sizeof(b)) == 0);
        ASSERT(dlx_git_out(rig.clone, tree, tb, sizeof(tb)) == 0);
        ASSERT(dlx_commit(rig.clone, "c.txt", "c\n", c));
        ASSERT(dlx_chain_row(ar, sizeof(ar), 1, rig.clone, a, m, "inflight", 0, NULL, NULL));
        ASSERT(dlx_chain_row(br, sizeof(br), 2, rig.clone, b, a, "queued", 1, m, ta));
        ASSERT(dlx_chain_row(cr, sizeof(cr), 3, rig.clone, c, b, "queued", 2, a, tb));
        const char *rows[] = { ar, br };
        ASSERT(zcl_native_dev_land_test_chain_relation(br, rows, 1, m, &waiting) == 1);
        ASSERT(waiting == 1);
        ASSERT(zcl_native_dev_land_test_chain_relation(br, rows, 1, a, &waiting) == 0);
        ASSERT(zcl_native_dev_land_test_chain_relation(br, rows, 1, c, &waiting) == 2);
        ASSERT(zcl_native_dev_land_test_chain_relation(br, rows, 1, DLX_CHAIN_M, &waiting) == 2);
        ASSERT(zcl_native_dev_land_test_chain_relation(cr, rows, 2, m, &waiting) == 1);
        ASSERT(zcl_native_dev_land_test_chain_relation(cr, rows, 2, a, &waiting) == 1);
        ASSERT(zcl_native_dev_land_test_chain_relation(cr, rows, 2, b, &waiting) == 0);
        ASSERT(zcl_native_dev_land_test_chain_relation(br, rows, 1, "", &waiting) == 3);
        ASSERT(zcl_native_dev_land_test_chain_relation(br, rows, 0, a, &waiting) == 4);
        const char *duplicates[] = { ar, ar };
        ASSERT(zcl_native_dev_land_test_chain_relation(br, duplicates, 2, a, &waiting) == 4);
        static const char *states[] = { "failed", "cancelled", "fenced", "conflict", "landed" };
        for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); ++i) {
            ASSERT(dlx_chain_row(changed, sizeof(changed), 1, rig.clone, a, m, states[i], 0, NULL, NULL));
            const char *invalid[] = { changed };
            ASSERT(zcl_native_dev_land_test_chain_relation(br, invalid, 1, a, &waiting) == 4);
        }
        ASSERT(dlx_chain_row(changed, sizeof(changed), 1, rig.clone, a, m, "inflight", 0, NULL, NULL));
        const char *invalid[] = { changed };
        static const char *pins[] = { "local", "base", "tree", "proof_intent" };
        for (size_t i = 0; i < 4; ++i) {
            ASSERT(dlx_chain_row(changed, sizeof(changed), 1, rig.clone, a, m, "inflight", 0, NULL, NULL));
            char needle[64]; (void)snprintf(needle, sizeof(needle), "\"%s\":\"", pins[i]);
            char *pin = strstr(changed, needle); ASSERT(pin != NULL); pin += strlen(needle);
            *pin = *pin == '0' ? '1' : '0';
            ASSERT(zcl_native_dev_land_test_chain_relation(br, invalid, 1, a, &waiting) == 4);
        }
        ASSERT(dlx_chain_row(changed, sizeof(changed), 1, rig.clone, a, m, "queued", 0, NULL, NULL));
        ASSERT(snprintf(changed, sizeof(changed), "{\"seq\":1,\"tip\":\"%s\",\"state\":\"queued\",\"attempt\":1}", a) < (int)sizeof(changed));
        ASSERT(zcl_native_dev_land_test_chain_relation(br, invalid, 1, a, &waiting) == 4);
        ASSERT(dlx_chain_row(changed, sizeof(changed), 1, rig.clone, rig.tip, m, "inflight", 0, NULL, NULL));
        ASSERT(zcl_native_dev_land_test_chain_relation(br, invalid, 1, a, &waiting) == 4);
        char land[1024], history[1200]; dlx_landdir(land, sizeof(land));
        (void)snprintf(history, sizeof(history), "%s/outcomes.jsonl", land);
        static const char hidden_failed[] =
            "{\"seq\":99,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"cancelled\",\"attempt\":1}\0\n"
            "{\"seq\":1,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"failed\",\"attempt\":1}\n";
        static const char hidden_duplicate[] =
            "{\"seq\":99,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"cancelled\",\"attempt\":1}\0\n"
            "{\"seq\":1,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"cancelled\",\"attempt\":1}\n"
            "{\"seq\":1,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"cancelled\",\"attempt\":1}\n";
        static const struct { const char *bytes; size_t length; } binary[] = {
            { hidden_failed, sizeof(hidden_failed) - 1 },
            { hidden_duplicate, sizeof(hidden_duplicate) - 1 }
        };
        int binary_relations[2];
        for (size_t i = 0; i < sizeof(binary) / sizeof(binary[0]); ++i) {
            FILE *file = fopen(history, "wb"); ASSERT(file != NULL);
            size_t written = fwrite(binary[i].bytes, 1, binary[i].length, file);
            int closed = fclose(file);
            ASSERT(written == binary[i].length && closed == 0);
            binary_relations[i] = zcl_native_dev_land_test_chain_relation(
                br, rows, 1, a, &waiting);
        }
        ASSERT(binary_relations[0] == 4);
        ASSERT(binary_relations[1] == 4);
        ASSERT(dlx_chain_row(changed, sizeof(changed), 1, rig.clone, a, m, "landed", 0, NULL, NULL));
        size_t n = strlen(changed); ASSERT(n + 2 < sizeof(changed)); changed[n] = '\n'; changed[n + 1] = '\0';
        ASSERT(dlx_write(history, changed));
        ASSERT(zcl_native_dev_land_test_chain_relation(br, rows, 1, a, &waiting) == 4);
        dlx_restore(); PASS();
    } _test_next:;
    dlx_restore(); return failures;
}

int test_dev_land_malformed_queue_refusal(void)
{
    int failures = 0;
    TEST("land: non-directory and malformed queue refusals preserve evidence") {
        {
            struct dlx_call c;
            char parent[1024], land[1200], after[64];
            size_t n = 0;
            static const char marker[] = "fixture marker\n";
            dlx_isolate("non_directory_land");
            ASSERT(snprintf(parent, sizeof(parent), "%s/z23/dev", g_dlx_state) < (int)sizeof(parent));
            ASSERT(dlx_mkdir_p(parent));
            dlx_landdir(land, sizeof(land));
            ASSERT(dlx_write(land, marker));
            dlx_begin(&c, "status");
            ASSERT(dlx_run(&c));
            ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
            ASSERT(!c.reply.error.mutated);
            char evidence[64];
            ASSERT(snprintf(evidence, sizeof(evidence), "queue_read_failed_errno_%d", ENOTDIR) < (int)sizeof(evidence));
            ASSERT_STR_EQ(dlx_err_evidence(&c), evidence);
            ASSERT(strstr(c.reply.error.next_action, "types and read permissions") != NULL);
            ASSERT(strstr(c.reply.error.next_action, "host that owns the queue") != NULL);
            ASSERT(dlx_slurp(land, after, sizeof(after), &n));
            ASSERT(n == sizeof(marker) - 1 && memcmp(after, marker, n) == 0);
            dlx_end(&c);
            dlx_restore();
        }
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1024], qpath[1200], before[8192], after[8192];
        size_t before_len = 0, after_len = 0;
        dlx_isolate("malformed_queue");
        ASSERT(dlx_rig_make(&rig, "malformed_queue_rig"));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "manual", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) <
               (int)sizeof(qpath));
        FILE *file = fopen(qpath, "ab");
        ASSERT(file != NULL);
        static const char legacy[] =
            "{\"seq\":2,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"queued\"}\n";
        ASSERT(fwrite(legacy, 1, sizeof(legacy) - 1, file) == sizeof(legacy) - 1);
        ASSERT(fclose(file) == 0);
        ASSERT(dlx_slurp(qpath, before, sizeof(before), &before_len));
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_queue_record_2");
        dlx_end(&c);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_queue_record_2");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_queue_record_2");
        dlx_end(&c);
        ASSERT(dlx_slurp(qpath, after, sizeof(after), &after_len));
        ASSERT(before_len == after_len);
        ASSERT(memcmp(before, after, before_len) == 0);
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}

int test_dev_land_malformed_priority_refusal(void)
{
    int failures = 0;
    TEST("land: malformed persisted priority refuses without losing the row") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1024], qpath[1200], before[8192], after[8192];
        size_t before_len = 0, after_len = 0;
        dlx_isolate("malformed_priority");
        ASSERT(dlx_rig_make(&rig, "malformed_priority_rig"));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "manual", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) <
               (int)sizeof(qpath));
        ASSERT(dlx_slurp(qpath, before, sizeof(before) - 1, &before_len));
        before[before_len] = '\0';
        char *priority = strstr(before, "\"priority_seq\":");
        ASSERT(priority != NULL);
        priority += strlen("\"priority_seq\":");
        ASSERT(*priority == '1');
        ASSERT(before_len + 2 < sizeof(before));
        memmove(priority + 3, priority + 1, strlen(priority + 1) + 1);
        priority[0] = '"';
        priority[1] = 'x';
        priority[2] = '"';
        before_len += 2;
        ASSERT(dlx_write(qpath, before));
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_queue_record_1");
        dlx_end(&c);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        dlx_end(&c);
        ASSERT(dlx_slurp(qpath, after, sizeof(after), &after_len));
        ASSERT(before_len == after_len);
        ASSERT(memcmp(before, after, before_len) == 0);
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_outcome_nul_refusal(void)
{
    int failures = 0;
    TEST("land: hidden terminal history refuses sequence assignment") {
        static const char history[] =
            "{\"seq\":1,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"failed\",\"attempt\":1}\n"
            "\0"
            "{\"seq\":2,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"failed\",\"attempt\":1}\n";
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1024], opath[1200], qpath[1200], after[1024], queue[8192];
        size_t after_len = 0, queue_len = 0;
        dlx_isolate("outcome_nul");
        ASSERT(dlx_rig_make(&rig, "outcome_nul_rig"));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "manual", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(opath));
        ASSERT(snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) <
               (int)sizeof(qpath));
        ASSERT(dlx_write(qpath, ""));
        FILE *f = fopen(opath, "wb");
        ASSERT(f != NULL);
        bool wrote = fwrite(history, 1, sizeof(history) - 1, f) ==
                     sizeof(history) - 1;
        ASSERT(fclose(f) == 0 && wrote);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c),
                      "outcomes.jsonl unreadable, malformed, or exhausted");
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        ASSERT(dlx_slurp(opath, after, sizeof(after), &after_len));
        ASSERT_EQ(after_len, sizeof(history) - 1);
        ASSERT(memcmp(after, history, after_len) == 0);
        ASSERT(dlx_queue_bytes(queue, sizeof(queue), &queue_len));
        ASSERT_EQ(queue_len, 0);
        f = fopen(opath, "wb");
        ASSERT(f != NULL);
        const char *second = history + strlen(history) + 1;
        wrote = fwrite(history, 1, strlen(history), f) == strlen(history) &&
                fwrite(second, 1, strlen(second), f) == strlen(second);
        ASSERT(fclose(f) == 0 && wrote);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 3);
        dlx_end(&c);
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

static int dlx_large_outcome_history(void)
{
    int failures = 0;
    TEST("land: durable history beyond one MiB preserves tail and sequence authority") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1024], opath[1200];
        dlx_isolate("large_outcome_history");
        ASSERT(dlx_rig_make(&rig, "large_outcome_history_rig"));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "manual", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(opath));
        FILE *f = fopen(opath, "wb");
        ASSERT(f != NULL);
        bool wrote = true;
        for (unsigned i = 1; i <= 12000; i++)
            if (fprintf(f, "{\"seq\":%u,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                           "\"state\":\"failed\",\"attempt\":1}\n", i) < 0)
                wrote = false;
        ASSERT(fclose(f) == 0 && wrote);
        struct stat before, after;
        ASSERT(stat(opath, &before) == 0 && before.st_size > 1024 * 1024);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *outcomes = json_get(&c.reply.data, "outcomes");
        ASSERT(outcomes && outcomes->type == JSON_ARR && outcomes->num_children == 10);
        ASSERT_EQ(json_get_int(json_get(&outcomes->children[0], "seq")), 11991);
        ASSERT_EQ(json_get_int(json_get(&outcomes->children[9], "seq")), 12000);
        dlx_end(&c);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 12001);
        dlx_end(&c);
        ASSERT(stat(opath, &after) == 0 && before.st_size == after.st_size);
        f = fopen(opath, "r+b");
        ASSERT(f != NULL);
        wrote = fputc('!', f) != EOF;
        ASSERT(fclose(f) == 0 && wrote);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_outcome_record_1");
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

static bool dlx_history_status_error(const char *evidence)
{
    struct dlx_call c;
    dlx_begin(&c, "status");
    bool ok = dlx_run(&c) && !dlx_ok(&c) &&
        strcmp(dlx_err_code(&c), "QUEUE_READ_FAILED") == 0 &&
        strcmp(dlx_err_evidence(&c), evidence) == 0 && !c.reply.error.mutated;
    dlx_end(&c);
    return ok;
}

static int dlx_outcome_stream_boundaries(void)
{
    int failures = 0;
    TEST("land: streaming history rejects hidden, partial, oversized and nonregular inputs") {
        struct dlx_call c;
        char landdir[1024], opath[1200], evidence[96];
        const char row[] = "{\"seq\":1,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                           "\"state\":\"failed\",\"attempt\":1}\n";
        dlx_isolate("outcome_stream_boundaries");
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(opath));
        FILE *f = fopen(opath, "wb");
        ASSERT(f != NULL);
        bool wrote = fwrite(row, 1, sizeof(row) - 1, f) == sizeof(row) - 1 &&
                     fputc(0, f) == 0;
        ASSERT(fclose(f) == 0 && wrote);
        ASSERT(dlx_history_status_error("malformed_outcome_record_2"));
        f = fopen(opath, "wb");
        ASSERT(f != NULL);
        wrote = fwrite(row, 1, sizeof(row) - 2, f) == sizeof(row) - 2;
        ASSERT(fclose(f) == 0 && wrote);
        ASSERT(dlx_history_status_error("malformed_outcome_record_1"));
        ASSERT(snprintf(evidence, sizeof(evidence), "outcomes_read_failed_errno_%d", EFBIG) <
               (int)sizeof(evidence));
        f = fopen(opath, "wb");
        ASSERT(f != NULL);
        for (unsigned i = 0; i < 32768; i++) ASSERT(fputc(' ', f) != EOF);
        ASSERT(fclose(f) == 0);
        ASSERT(dlx_history_status_error(evidence));
        int fd = open(opath, O_WRONLY | O_TRUNC);
        ASSERT(fd >= 0);
        bool sized = ftruncate(fd, 64 * 1024 * 1024 + 1) == 0;
        ASSERT(close(fd) == 0 && sized);
        ASSERT(dlx_history_status_error(evidence));
        ASSERT(unlink(opath) == 0 && mkfifo(opath, 0600) == 0);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        ASSERT(unlink(opath) == 0);
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

static int dlx_outcome_record_budget(void)
{
    int failures = 0;
    TEST("land: streaming history accepts its record budget and refuses the next row") {
        struct dlx_call c;
        char landdir[1024], opath[1200], evidence[96];
        dlx_isolate("outcome_record_budget");
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(opath));
        FILE *f = fopen(opath, "wb");
        ASSERT(f != NULL);
        bool wrote = true;
        for (unsigned i = 1; i <= 65536; i++)
            if (fprintf(f, "{\"seq\":%u,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                           "\"state\":\"failed\",\"attempt\":1}\n", i) < 0)
                wrote = false;
        ASSERT(fclose(f) == 0 && wrote);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *outcomes = json_get(&c.reply.data, "outcomes");
        ASSERT(outcomes && outcomes->num_children == 10);
        ASSERT_EQ(json_get_int(json_get(&outcomes->children[9], "seq")), 65536);
        dlx_end(&c);
        f = fopen(opath, "ab");
        ASSERT(f != NULL);
        wrote = fprintf(f, "{\"seq\":65537,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                           "\"state\":\"failed\",\"attempt\":1}\n") > 0;
        ASSERT(fclose(f) == 0 && wrote);
        ASSERT(snprintf(evidence, sizeof(evidence), "outcomes_read_failed_errno_%d", EFBIG) <
               (int)sizeof(evidence));
        ASSERT(dlx_history_status_error(evidence));
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_malformed_outcome_refusal(void)
{
    int failures = 0;
    TEST("land: a malformed terminal outcome is named, never hidden") {
        struct dlx_call c;
        char landdir[1024], opath[1200];
        dlx_isolate("malformed_outcome");
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(opath));
        ASSERT(dlx_write(opath,
            "{\"seq\":1,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"state\":\"landed\"}\n"));
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_outcome_record_1");
        dlx_end(&c);
        dlx_restore();
        PASS();
    } _test_next:;
    failures += dlx_outcome_nul_refusal();
    failures += dlx_large_outcome_history();
    failures += dlx_outcome_stream_boundaries();
    failures += dlx_outcome_record_budget();
    return failures;
}

int test_dev_land_missing_worker(void)
{
    int failures = 0;
    TEST("land: a dead proof worker leaves a resumable exact intent") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], logpath[1400], log[8192];
        size_t len = 0;
        dlx_isolate("proof_worker_dead");
        ASSERT(dlx_rig_make(&rig, "proof_worker_dead_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *flight = json_get(&c.reply.data,
                                                   "in_flight");
        ASSERT(flight != NULL);
        ASSERT(strlen(json_get_str(json_get(flight, "tree"))) == 40);
        ASSERT(strchr(json_get_str(json_get(flight, "proof_intent")), '@') !=
               NULL);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "missing", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "proving");
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(logpath, sizeof(logpath), "%s/logs/land-1-a1.log",
                       landdir);
        ASSERT(dlx_slurp(logpath, log, sizeof(log) - 1, &len));
        log[len] = '\0';
        ASSERT(strstr(log, "proof worker missing; requeueing") != NULL);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        PASS();
    }

_test_next:;
    dlx_restore();
    return failures;
}

bool dlx_pick_barrier_open(int ready[2], int release[2])
{
    if (pipe(ready) != 0 || pipe(release) != 0) return false;
    int fds[] = {ready[0], ready[1], release[0], release[1]};
    for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
        if (fcntl(fds[i], F_SETFD, FD_CLOEXEC) != 0) return false;
    return true;
}

static void dlx_pick_barrier_close(int ready[2], int release[2], pid_t child)
{
    zcl_native_dev_land_test_pick_barrier(-1, -1);
    for (size_t i = 0; i < 2; i++) {
        if (ready[i] >= 0) (void)close(ready[i]);
        if (release[i] >= 0) (void)close(release[i]);
    }
    if (child > 0) (void)waitpid(child, NULL, 0);
}

static int dlx_competing_blocked(const struct dlx_rig *rig,
                                 const struct dlx_adopt_fix *count,
                                 const char *loser, const char *expected)
{
    int failures = 0;
    struct dlx_call c;
    char base[64], observed[64], before_wire[8192], after_wire[8192];
    size_t before_len, after_len;
    ASSERT(dlx_origin_main(rig, base));
    ASSERT(dlx_queue_bytes(before_wire, sizeof(before_wire), &before_len));
    struct json_value partial;
    json_init(&partial);
    ASSERT(json_read(&partial, before_wire, before_len));
    ASSERT_STR_EQ(json_get_str(json_get(&partial, "state")), expected);
    json_free(&partial);
    dlx_begin(&c, loser);
    ASSERT(dlx_run(&c) && !dlx_ok(&c));
    ASSERT_STR_EQ(dlx_err_code(&c), "STEP_BUSY");
    dlx_end(&c);
    ASSERT(dlx_queue_bytes(after_wire, sizeof(after_wire), &after_len));
    ASSERT_EQ(before_len, after_len);
    ASSERT(memcmp(before_wire, after_wire, before_len) == 0);
    ASSERT(dlx_origin_main(rig, observed));
    ASSERT_STR_EQ(observed, base);
    ASSERT(access(count->marker, F_OK) != 0 && errno == ENOENT);
    dlx_begin(&c, "status");
    ASSERT(dlx_run(&c) && dlx_ok(&c));
    const struct json_value *pending = dlx_arr(&c, "outcomes");
    ASSERT(pending && pending->num_children == 0);
    dlx_end(&c);
_test_next:;
    return failures;
}

static void dlx_competing_child(const char *winner, bool prepared,
                                int ready[2], int release[2])
{
    (void)alarm(60);
    (void)close(ready[0]);
    (void)close(release[1]);
    struct dlx_call other;
    dlx_begin(&other, winner);
    const char *expected = prepared || strcmp(winner, "drive") == 0
                           ? "landed" : "started";
    bool landed = dlx_run(&other) && dlx_ok(&other) &&
                  strcmp(dlx_str(&other, "state"), expected) == 0;
    dlx_end(&other);
    _exit(landed ? 0 : 1);
}

static int dlx_competing_beats(const struct dlx_rig *rig,
                              const struct dlx_adopt_fix *count,
                              const char *winner, const char *loser,
                              bool prepared, int ready, int release)
{
    int failures = 0;
    int beats = !prepared && strcmp(winner, "drive") == 0 ? 2 : 1;
    for (int beat = 0; beat < beats; beat++) {
        char marker = 0;
        ASSERT(read(ready, &marker, 1) == 1 && marker == 'R');
        ASSERT(dlx_competing_blocked(rig, count, loser,
                   !prepared && beat == 0 ? "queued" : "inflight") == 0);
        ASSERT(write(release, "G", 1) == 1);
    }
_test_next:;
    return failures;
}

int test_dev_land_competing_publish(const char *winner, const char *loser,
                                           bool prepared)
{
    int failures = 0;
    int ready[2] = {-1, -1}, release[2] = {-1, -1};
    pid_t child = -1;
    char label[160];
    (void)snprintf(label, sizeof(label),
                   "land: %s versus %s %s row is singleflight", winner, loser,
                   prepared ? "in-flight" : "queued");
    TEST(label) {
        struct dlx_rig rig;
        struct dlx_call c;
        int status = 0;
        dlx_isolate("passed_competitors");
        ASSERT(dlx_rig_make(&rig, "passed_competitors_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        if (prepared) {
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c) && dlx_ok(&c));
            dlx_end(&c);
        }
        struct dlx_adopt_fix count = {.rig = rig};
        ASSERT(dlx_arm_receive_count(&count));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        ASSERT(dlx_pick_barrier_open(ready, release));
        zcl_native_dev_land_test_pick_barrier(ready[1], release[0]);
        child = fork();
        ASSERT(child >= 0);
        if (child == 0)
            dlx_competing_child(winner, prepared, ready, release);
        ASSERT(close(ready[1]) == 0);
        ready[1] = -1;
        ASSERT(close(release[0]) == 0);
        release[0] = -1;
        ASSERT(dlx_competing_beats(&rig, &count, winner, loser, prepared,
                                   ready[0], release[1]) == 0);
        ASSERT(close(release[1]) == 0);
        release[1] = -1;
        ASSERT(waitpid(child, &status, 0) == child);
        child = -1;
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        zcl_native_dev_land_test_pick_barrier(-1, -1);
        if (!prepared && strcmp(winner, "step") == 0) {
            dlx_begin(&c, "drive");
            ASSERT(dlx_run(&c) && dlx_ok(&c));
            ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
            dlx_end(&c);
        }
        ASSERT(dlx_receive_once(&count));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "empty");
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *outcomes = dlx_arr(&c, "outcomes");
        ASSERT(outcomes && outcomes->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&outcomes->children[0], "state")),
                      "landed");
        dlx_end(&c);
        PASS();
    }

_test_next:;
    dlx_pick_barrier_close(ready, release, child);
    dlx_restore();
    return failures;
}

int test_dev_land_bounded_drive(void)
{
    int failures = 0;
    TEST("land: one bounded drive publishes a passing exact pair") {
        struct dlx_rig rig;
        struct dlx_call c;
        char main_tip[64];
        dlx_isolate("bounded_drive");
        ASSERT(dlx_rig_make(&rig, "bounded_drive_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "drive");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        char pushed[64];
        (void)snprintf(pushed, sizeof(pushed), "%s",
                       dlx_str(&c, "tip_pushed"));
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, main_tip));
        ASSERT_STR_EQ(main_tip, pushed);
        PASS();
    }

_test_next:;
    dlx_restore();
    return failures;
}

/* ── drive --seq: a typed outcome for one row ──────────────────────────── */

/* The 40-hex value of a quoted member of the settled outcome row. */
static bool dlx_row_member(const char *member, char out[41])
{
    char land[1200], path[1400], ledger[16384], key[48];
    size_t len = 0;
    const char *at;
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", land);
    (void)snprintf(key, sizeof(key), "\"%s\":\"", member);
    if (!dlx_slurp(path, ledger, sizeof(ledger) - 1, &len))
        return false;
    ledger[len] = '\0';
    at = strstr(ledger, key);
    if (!at)
        return false;
    at += strlen(key);
    if (strspn(at, "0123456789abcdef") < 40)
        return false;
    memcpy(out, at, 40);
    out[40] = '\0';
    return true;
}

bool dlx_drive_seq(struct dlx_call *c, int seq)
{
    dlx_begin(c, "drive");
    (void)json_push_kv_int(&c->input, "seq", seq);
    return dlx_run(c);
}

int test_dev_land_drive_seq_lands(void)
{
    int failures = 0;
    TEST("land: drive --seq seals the intent it asks for and lands the row") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], main_tip[64];
        dlx_isolate("drive_seq_lands");
        ASSERT(dlx_attach_proven_pair(&rig, "drive_seq_lands", base));
        ASSERT(dlx_drive_seq(&c, 1) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "outcome"), "landed");
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT_EQ(dlx_int(&c, "rounds"), 2);
        ASSERT(dlx_origin_main(&rig, main_tip));
        ASSERT_STR_EQ(main_tip, dlx_str(&c, "tip_pushed"));
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_drive_seq_refusals(void)
{
    int failures = 0;
    TEST("land: drive --seq names a refused row and an unknown sequence") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("drive_seq_refused");
        ASSERT(dlx_rig_make(&rig, "drive_seq_refused_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        ASSERT(dlx_drive_seq(&c, 1));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(dlx_err_code(&c), "DRIVE_REFUSED");
        ASSERT_STR_EQ(dlx_str(&c, "outcome"), "refused");
        ASSERT(strstr(dlx_str(&c, "reason"), "row_failed") != NULL);
        dlx_end(&c);
        ASSERT(dlx_drive_seq(&c, 99));
        ASSERT_STR_EQ(dlx_err_code(&c), "DRIVE_REFUSED");
        ASSERT_STR_EQ(dlx_str(&c, "reason"), "unknown_seq_99");
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_drive_seq_proof_failed(void)
{
    int failures = 0;
    TEST("land: drive --seq on a failed row names the pair's .failed record") {
        struct dlx_rig rig;
        struct dlx_call c;
        char local[41], base[41], land[1200], dir[1500], marker[1700];
        FILE *f;
        dlx_isolate("drive_seq_proof_failed");
        ASSERT(dlx_rig_make(&rig, "drive_seq_proof_failed_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        ASSERT(dlx_drive_seq(&c, 1));
        dlx_end(&c);
        ASSERT(dlx_row_member("local", local) && dlx_row_member("base", base));
        dlx_landdir(land, sizeof(land));
        (void)snprintf(dir, sizeof(dir), "%s/wt/.cache/zcl-dev-proof", land);
        ASSERT(dlx_mkdir_p(dir));
        (void)snprintf(marker, sizeof(marker), "%s/%s-%s.failed", dir, local,
                       base);
        f = fopen(marker, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs("child_proof_failed\n", f) >= 0);
        ASSERT(fclose(f) == 0);
        ASSERT(dlx_drive_seq(&c, 1));
        ASSERT_STR_EQ(dlx_err_code(&c), "DRIVE_PROOF_FAILED");
        ASSERT_STR_EQ(dlx_str(&c, "outcome"), "proof_failed");
        ASSERT(strstr(dlx_str(&c, "failed_path"), ".failed") != NULL);
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_drive_seq_stops(void)
{
    int failures = 0;
    TEST("land: drive --seq stops after its round budget with the row live") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("drive_seq_stops");
        ASSERT(dlx_rig_make(&rig, "drive_seq_stops_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        ASSERT(dlx_drive_seq(&c, 1));
        ASSERT_STR_EQ(dlx_err_code(&c), "DRIVE_STOPPED");
        ASSERT_STR_EQ(dlx_str(&c, "outcome"), "stopped");
        ASSERT_EQ(dlx_int(&c, "rounds"), 6);
        ASSERT(c.reply.error.retryable);
        ASSERT_STR_EQ(c.reply.error.next_action,
                      "z23 dev land drive --seq=1");
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* ── drive prove:true max_rows:N: the manual proof recipe, bounded ─────── */

/* A stand-in `make`: argv is -jN -C <root> dev-bin. It builds a stand-in
 * producer in <root>/build/bin/z23-dev that counts its runs in `count` and
 * then either writes the pair's receipt (ok), exits 0 without one (quiet),
 * or fails (broken). */

static bool dlx_fake_make(const char *path, const char *count,
                          enum dlx_producer kind)
{
    char script[4000];
    const char *action =
        kind == DLX_PRODUCER_OK
            ? "mkdir -p \"$R/.cache/zcl-dev-proof/receipts\"\n"
              "echo receipt > \"$R/.cache/zcl-dev-proof/receipts/$L-$B.receipt\"\n"
            : kind == DLX_PRODUCER_QUIET ? "true\n"
                                         : "echo 'lint: boom' >&2\nexit 3\n";
    (void)snprintf(
        script, sizeof(script),
        "#!/bin/sh\n"
        "echo \"make:${ZCL_LAND_PROOF_STUB-unset}:${ZCL_LAND_MAKE-unset}\" >> '%s.env'\n"
        "[ \"$2\" = -C ] && [ \"$4\" = dev-bin ] || exit 64\n"
        "mkdir -p \"$3/build/bin\" || exit 65\n"
        "cat > \"$3/build/bin/z23-dev\" <<'PRODUCER'\n"
        "#!/bin/sh\n"
        "for a in \"$@\"; do case \"$a\" in\n"
        "--root=*) R=${a#--root=};; --local_commit=*) L=${a#--local_commit=};;\n"
        "--remote_base=*) B=${a#--remote_base=};; esac; done\n"
        "echo run >> '%s'\n"
        "echo \"proof:${ZCL_LAND_PROOF_STUB-unset}:${ZCL_LAND_ALLOW_UNSIGNED-unset}\" >> '%s.env'\n"
        "%s"
        "PRODUCER\n"
        "chmod 700 \"$3/build/bin/z23-dev\"\n",
        count, count, count, action);
    return dlx_write(path, script) && chmod(path, 0700) == 0;
}

bool dlx_prove_drive(struct dlx_call *c, int max_rows)
{
    dlx_begin(c, "drive");
    (void)json_push_kv_bool(&c->input, "prove", true);
    (void)json_push_kv_int(&c->input, "max_rows", max_rows);
    return dlx_run(c);
}

size_t dlx_runs(const char *count)
{
    char bytes[256];
    size_t len = 0;
    if (!dlx_slurp(count, bytes, sizeof(bytes) - 1, &len))
        return 0;
    return len / 4; /* "run\n" per producer run */
}


/* Two submitted rows (tip, then a child of it), the stub proof pass, and a
 * stand-in make of the requested kind. */
bool dlx_prove_rig(struct dlx_prove_rig *p, const char *tag,
                          enum dlx_producer kind)
{
    struct dlx_call c;
    char dir[1200];
    if (!dlx_rig_make(&p->rig, tag))
        return false;
    dlx_landdir(dir, sizeof(dir));
    (void)snprintf(p->make, sizeof(p->make), "%s/fake-make", p->rig.clone);
    (void)snprintf(p->count, sizeof(p->count), "%s/producer-runs",
                   p->rig.clone);
    if (!dlx_fake_make(p->make, p->count, kind) ||
        !dlx_commit(p->rig.clone, "second.txt", "two\n", p->second))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    setenv("ZCL_LAND_MAKE", p->make, 1);
    dlx_submit(&c, &p->rig, p->rig.tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    dlx_submit(&c, &p->rig, p->second);
    ok = ok && dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok;
}

int test_dev_land_prove_drive1(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: drive prove max_rows=2 proves and lands two rows, reporting each") {
        struct dlx_prove_rig p;
        struct dlx_call c;
        char main_tip[64];
        dlx_isolate("prove_drive_two");
        ASSERT(dlx_prove_rig(&p, "prove_drive_two_rig", DLX_PRODUCER_OK));
        ASSERT(dlx_prove_drive(&c, 2) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "outcome"), "landed");
        ASSERT_EQ(dlx_int(&c, "rows_landed"), 2);
        const struct json_value *rows = dlx_arr(&c, "rows");
        ASSERT(rows != NULL && rows->num_children == 2);
        for (size_t i = 0; i < 2; i++) {
            const struct json_value *r = &rows->children[i];
            ASSERT_EQ(json_get_int(json_get(r, "seq")), (int64_t)i + 1);
            ASSERT_STR_EQ(json_get_str(json_get(r, "outcome")), "landed");
            ASSERT_STR_EQ(json_get_str(json_get(r, "proof")), "ran");
            ASSERT(json_get_int(json_get(r, "proof_ms")) >= 0);
            ASSERT(strlen(json_get_str(json_get(r, "base"))) == 40);
            ASSERT(strlen(json_get_str(json_get(r, "head"))) == 40);
        }
        dlx_end(&c);
        ASSERT_EQ((int64_t)dlx_runs(p.count), 2);
        /* The lander's own control variables never reach its children. */
        {
            char seen[2048], env_path[1500];
            size_t seen_len = 0;
            (void)snprintf(env_path, sizeof(env_path), "%s.env", p.count);
            ASSERT(dlx_slurp(env_path, seen, sizeof(seen) - 1, &seen_len));
            seen[seen_len] = '\0';
            ASSERT(strstr(seen, "make:unset:unset") != NULL);
            ASSERT(strstr(seen, "proof:unset:unset") != NULL);
            ASSERT(strstr(seen, "pass") == NULL && strstr(seen, "fake-make") == NULL);
        }
        ASSERT(dlx_origin_main(&p.rig, main_tip));
        ASSERT_STR_EQ(main_tip, p.second);
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}
