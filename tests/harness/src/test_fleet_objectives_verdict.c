/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for fleet.objectives.verdict
 * (tools/command/native_fleet_objectives_verdict.c).
 *
 * Fixture snapshot files in a tmpdir only: the snapshot input always points
 * at a fixture, so no case reads the live land state.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FOV_PATH "fleet.objectives.verdict"

/* One snapshot line: lat is a min objective (target 300), rate a max one
 * (target 90), node a min one that is null in every row. Values are JSON
 * text ("412" or "null"). */
static void fov_line(char *out, size_t cap, int seq, const char *lat,
                     const char *rate, const char *extra)
{
    (void)snprintf(
        out, cap,
        "{\"schema\":\"zcl.objectives_snapshot.v1\",\"ts\":%d,\"seq\":%d,"
        "\"tip\":\"tip%04d\",\"objectives\":["
        "{\"id\":\"lat\",\"value\":%s,\"target\":300,\"direction\":\"min\","
        "\"met\":%s,\"reason\":\"%s\"},"
        "{\"id\":\"rate\",\"value\":%s,\"target\":90,\"direction\":\"max\","
        "\"met\":%s,\"reason\":\"\"},"
        "{\"id\":\"node\",\"value\":null,\"target\":5,\"direction\":\"min\","
        "\"met\":null,\"reason\":\"node down\"}%s]}\n",
        1000 + seq, seq, seq, lat, strcmp(lat, "null") == 0 ? "null" : "false",
        strcmp(lat, "null") == 0 ? "no ledger" : "", rate,
        strcmp(rate, "null") == 0 ? "null" : "true", extra);
}

static bool fov_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    size_t len = strlen(text);
    bool ok;
    if (!f)
        return false;
    ok = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

struct fov_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void fov_end(struct fov_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* before/after < 0 means "unset"; id may be NULL. Runs the validator the way
 * the dispatcher does, then the handler. */
static bool fov_run(struct fov_call *c, const char *snapshot, int before,
                    int after, const char *id)
{
    char why[192];
    json_init(&c->input);
    json_set_object(&c->input);
    (void)json_push_kv_str(&c->input, "snapshot", snapshot);
    if (before >= 0)
        (void)json_push_kv_int(&c->input, "before_seq", before);
    if (after >= 0)
        (void)json_push_kv_int(&c->input, "after_seq", after);
    if (id)
        (void)json_push_kv_str(&c->input, "id", id);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), FOV_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.test.v1");
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_fleet_objectives_verdict(&c->request, &c->reply);
    return true;
}

static const struct json_value *fov_entry(const struct fov_call *c,
                                          const char *id)
{
    const struct json_value *arr = json_get(&c->reply.data, "objectives");
    for (size_t i = 0; arr && i < json_size(arr); i++)
        if (strcmp(json_get_str(json_get(json_at(arr, i), "id")), id) == 0)
            return json_at(arr, i);
    return NULL;
}

static const char *fov_verdict(const struct fov_call *c, const char *id)
{
    return json_get_str(json_get(fov_entry(c, id), "verdict"));
}

static int64_t fov_seq(const struct fov_call *c, const char *side)
{
    return json_get_int(json_get(json_get(&c->reply.data, side), "seq"));
}

/* Writes three rows to path: seq 1 (lat 400, rate 50), seq 2 (lat 300,
 * rate 50), seq 3 (lat 350, rate 60). */
static bool fov_three(const char *path)
{
    char buf[3 * 1024], one[1024];
    buf[0] = '\0';
    fov_line(one, sizeof(one), 1, "400", "50", "");
    (void)strcat(buf, one);
    fov_line(one, sizeof(one), 2, "300", "50", "");
    (void)strcat(buf, one);
    fov_line(one, sizeof(one), 3, "350", "60", "");
    (void)strcat(buf, one);
    return fov_write(path, buf);
}

static int fov_case_rows(const char *dir)
{
    int failures = 0;
    struct fov_call c;
    char path[700];
    (void)snprintf(path, sizeof(path), "%s/three.jsonl", dir);
    TEST("verdict: fixture written") { ASSERT(fov_three(path)); PASS(); }
    TEST("verdict: the default compares the second-newest and newest rows") {
        ASSERT(fov_run(&c, path, -1, -1, NULL));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(fov_seq(&c, "before"), 2);
        ASSERT_EQ(fov_seq(&c, "after"), 3);
        ASSERT_STR_EQ(json_get_str(json_get(json_get(&c.reply.data, "after"),
                                            "tip")), "tip0003");
        ASSERT_EQ(json_get_int(json_get(json_get(&c.reply.data, "after"),
                                        "ts")), 1003);
        fov_end(&c);
        PASS();
    }
    TEST("verdict: explicit seqs pick those rows") {
        ASSERT(fov_run(&c, path, 1, 3, NULL));
        ASSERT_EQ(fov_seq(&c, "before"), 1);
        ASSERT_EQ(fov_seq(&c, "after"), 3);
        ASSERT_EQ(json_get_int(json_get(fov_entry(&c, "lat"), "delta")), -50);
        fov_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int fov_case_verdicts(const char *dir)
{
    int failures = 0;
    struct fov_call c;
    char path[700];
    (void)snprintf(path, sizeof(path), "%s/three.jsonl", dir);
    TEST("verdict: min improved, max improved, a null value is unmeasured") {
        ASSERT(fov_run(&c, path, 1, 3, NULL));
        ASSERT_STR_EQ(fov_verdict(&c, "lat"), "improved");
        ASSERT_STR_EQ(fov_verdict(&c, "rate"), "improved");
        ASSERT_STR_EQ(fov_verdict(&c, "node"), "unmeasured");
        ASSERT(strstr(json_get_str(json_get(fov_entry(&c, "node"), "reason")),
                      "node down") != NULL);
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "improved")), 2);
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "regressed")), 0);
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "unmeasured")), 1);
        ASSERT_EQ(json_size(json_get(&c.reply.data, "regressions")), 0);
        fov_end(&c);
        PASS();
    }
    TEST("verdict: min regressed, max unchanged") {
        ASSERT(fov_run(&c, path, 2, 3, NULL));
        ASSERT_STR_EQ(fov_verdict(&c, "lat"), "regressed");
        ASSERT_STR_EQ(fov_verdict(&c, "rate"), "improved");
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "regressed")), 1);
        ASSERT_STR_EQ(json_get_str(json_at(json_get(&c.reply.data,
                                                    "regressions"), 0)), "lat");
        ASSERT(strstr(json_get_str(json_get(&c.reply.data, "screen")),
                      "REGRESSED") != NULL);
        fov_end(&c);
        ASSERT(fov_run(&c, path, 1, 2, NULL));
        ASSERT_STR_EQ(fov_verdict(&c, "rate"), "unchanged");
        ASSERT_STR_EQ(fov_verdict(&c, "lat"), "improved");
        fov_end(&c);
        PASS();
    }
    TEST("verdict: max regressed") {
        char one[1024], buf[2048];
        char p2[700];
        (void)snprintf(p2, sizeof(p2), "%s/maxreg.jsonl", dir);
        fov_line(buf, sizeof(buf), 1, "300", "80", "");
        fov_line(one, sizeof(one), 2, "300", "70", "");
        (void)strcat(buf, one);
        ASSERT(fov_write(p2, buf));
        ASSERT(fov_run(&c, p2, -1, -1, NULL));
        ASSERT_STR_EQ(fov_verdict(&c, "rate"), "regressed");
        ASSERT_STR_EQ(fov_verdict(&c, "lat"), "unchanged");
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "unchanged")), 1);
        fov_end(&c);
        PASS();
    }
    TEST("verdict: an id narrows the answer to that objective") {
        ASSERT(fov_run(&c, path, 1, 3, "rate"));
        ASSERT_EQ(json_size(json_get(&c.reply.data, "objectives")), 1);
        ASSERT_STR_EQ(fov_verdict(&c, "rate"), "improved");
        fov_end(&c);
        PASS();
    }
    TEST("verdict: a null value in one row makes the pair unmeasured") {
        char one[1024], buf[2048], p2[700];
        (void)snprintf(p2, sizeof(p2), "%s/nullval.jsonl", dir);
        fov_line(buf, sizeof(buf), 1, "null", "80", "");
        fov_line(one, sizeof(one), 2, "300", "80", "");
        (void)strcat(buf, one);
        ASSERT(fov_write(p2, buf));
        ASSERT(fov_run(&c, p2, -1, -1, NULL));
        ASSERT_STR_EQ(fov_verdict(&c, "lat"), "unmeasured");
        ASSERT(json_is_null(json_get(fov_entry(&c, "lat"), "delta")));
        ASSERT(json_is_null(json_get(fov_entry(&c, "lat"), "before")));
        fov_end(&c);
        PASS();
    }
    TEST("verdict: an id in only one row is unmeasured with its reason") {
        char one[1536], buf[3072], p2[700];
        (void)snprintf(p2, sizeof(p2), "%s/oneside.jsonl", dir);
        fov_line(buf, sizeof(buf), 1, "300", "80",
                 ",{\"id\":\"gone\",\"value\":1,\"target\":2,"
                 "\"direction\":\"min\",\"met\":true,\"reason\":\"\"}");
        fov_line(one, sizeof(one), 2, "300", "80",
                 ",{\"id\":\"fresh\",\"value\":1,\"target\":2,"
                 "\"direction\":\"min\",\"met\":true,\"reason\":\"\"}");
        (void)strcat(buf, one);
        ASSERT(fov_write(p2, buf));
        ASSERT(fov_run(&c, p2, -1, -1, NULL));
        ASSERT_STR_EQ(fov_verdict(&c, "gone"), "unmeasured");
        ASSERT_STR_EQ(fov_verdict(&c, "fresh"), "unmeasured");
        ASSERT(strstr(json_get_str(json_get(fov_entry(&c, "gone"), "reason")),
                      "after row") != NULL);
        ASSERT(strstr(json_get_str(json_get(fov_entry(&c, "fresh"), "reason")),
                      "before row") != NULL);
        fov_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int fov_case_refusals(const char *dir)
{
    int failures = 0;
    struct fov_call c;
    char path[700], missing[700], empty[700], one[700], buf[1024];
    (void)snprintf(path, sizeof(path), "%s/three.jsonl", dir);
    (void)snprintf(missing, sizeof(missing), "%s/nope.jsonl", dir);
    (void)snprintf(empty, sizeof(empty), "%s/empty.jsonl", dir);
    (void)snprintf(one, sizeof(one), "%s/one.jsonl", dir);
    TEST("verdict: an unknown id is refused by name") {
        ASSERT(fov_run(&c, path, -1, -1, "no_such_id"));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(c.reply.error.code, "UNKNOWN_OBJECTIVE");
        ASSERT(strstr(c.reply.error.message, "no_such_id") != NULL);
        fov_end(&c);
        PASS();
    }
    TEST("verdict: an absent seq is refused by name") {
        ASSERT(fov_run(&c, path, 99, -1, NULL));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(c.reply.error.code, "SNAPSHOT_ROWS");
        ASSERT(strstr(c.reply.error.message, "before_seq 99") != NULL);
        fov_end(&c);
        ASSERT(fov_run(&c, path, 1, 77, NULL));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strstr(c.reply.error.message, "after_seq 77") != NULL);
        fov_end(&c);
        PASS();
    }
    TEST("verdict: the same row on both sides is refused") {
        ASSERT(fov_run(&c, path, 2, 2, NULL));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strstr(c.reply.error.message, "same row") != NULL);
        fov_end(&c);
        PASS();
    }
    TEST("verdict: a missing, empty or one-row file gives an explanation") {
        ASSERT(fov_run(&c, missing, -1, -1, NULL));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(c.reply.error.code, "SNAPSHOT_MISSING");
        ASSERT(strstr(c.reply.error.message, "cannot open") != NULL);
        fov_end(&c);
        ASSERT(fov_write(empty, ""));
        ASSERT(fov_run(&c, empty, -1, -1, NULL));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strstr(c.reply.error.message, "needs two valid rows") != NULL);
        fov_end(&c);
        fov_line(buf, sizeof(buf), 1, "300", "80", "");
        ASSERT(fov_write(one, buf));
        ASSERT(fov_run(&c, one, -1, -1, NULL));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strstr(c.reply.error.message, "has 1") != NULL);
        fov_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int fov_case_skips(const char *dir)
{
    int failures = 0;
    struct fov_call c;
    char path[700], one[1024];
    size_t cap = 80000;
    char *buf = malloc(cap);
    TEST("verdict: malformed, overlong and wrong-schema lines are skipped "
         "and counted") {
        size_t n;
        ASSERT(buf != NULL);
        (void)snprintf(path, sizeof(path), "%s/dirty.jsonl", dir);
        fov_line(buf, cap, 1, "400", "50", "");
        (void)strcat(buf, "{not json at all\n");
        (void)strcat(buf, "{\"schema\":\"zcl.other.v1\",\"seq\":9}\n");
        fov_line(one, sizeof(one), 2, "300", "60", "");
        (void)strcat(buf, one);
        n = strlen(buf);
        memset(buf + n, 'x', 70000);
        buf[n + 70000] = '\n';
        buf[n + 70001] = '\0';
        fov_line(one, sizeof(one), 3, "290", "70", "");
        (void)strcat(buf, one);
        (void)strcat(buf, "\n   \n");
        ASSERT(fov_write(path, buf));
        ASSERT(fov_run(&c, path, -1, -1, NULL));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "skipped")), 3);
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "rows")), 3);
        ASSERT_EQ(fov_seq(&c, "before"), 2);
        ASSERT_EQ(fov_seq(&c, "after"), 3);
        fov_end(&c);
        PASS();
    }
    free(buf);
_test_next:;
    return failures;
}

static int fov_case_registry(const char *dir)
{
    int failures = 0;
    struct fov_call c;
    char path[700], why[192];
    (void)snprintf(path, sizeof(path), "%s/three.jsonl", dir);
    TEST("verdict: the registry validator accepts the inputs and types the "
         "seqs as integers") {
        struct zcl_command_input_descriptor d;
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), FOV_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(fov_run(&c, path, 1, 3, "lat"));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        fov_end(&c);
        ASSERT(zcl_command_registry_input_descriptor(spec, "before_seq", &d));
        ASSERT_EQ(d.type, JSON_INT);
        ASSERT(zcl_command_registry_input_descriptor(spec, "after_seq", &d));
        ASSERT_EQ(d.type, JSON_INT);
        json_init(&c.input);
        json_set_object(&c.input);
        (void)json_push_kv_bool(&c.input, "before_seq", true);
        ASSERT(!zcl_command_registry_input_validate(spec, &c.input, why,
                                                    sizeof(why)));
        json_free(&c.input);
        PASS();
    }
_test_next:;
    return failures;
}

struct fov_delta_case {
    const char *name, *before, *after, *verdict;
    bool has_delta;
    int64_t delta;
    const char *reason;
};

static int fov_case_delta(const char *dir, const struct fov_delta_case *sample)
{
    int failures = 0;
    char path[700], text[2048], before[1024], after[1024];
    struct fov_call c;
    (void)snprintf(path, sizeof(path), "%s/delta.jsonl", dir);
    fov_line(before, sizeof(before), 1, sample->before, "0", "");
    fov_line(after, sizeof(after), 2, sample->after, "0", "");
    (void)snprintf(text, sizeof(text), "%s%s", before, after);
    TEST(sample->name) {
        ASSERT(fov_write(path, text));
        ASSERT(fov_run(&c, path, 1, 2, "lat"));
        ASSERT_EQ(c.reply.status, ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *entry = fov_entry(&c, "lat");
        ASSERT_STR_EQ(fov_verdict(&c, "lat"), sample->verdict);
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, sample->verdict)), 1);
        ASSERT_STR_EQ(json_get_str(json_get(entry, "direction")), "min");
        if (sample->has_delta) {
            ASSERT(json_get(entry, "delta")->type == JSON_INT);
            ASSERT_EQ(json_get_int(json_get(entry, "delta")), sample->delta);
        } else {
            ASSERT(json_is_null(json_get(entry, "delta")));
        }
        if (sample->reason)
            ASSERT_STR_EQ(json_get_str(json_get(entry, "reason")), sample->reason);
        else
            ASSERT(json_get(entry, "reason") == NULL);
        fov_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int fov_case_delta_boundaries(const char *dir)
{
    static const struct fov_delta_case cases[] = {
        {"verdict: positive delta overflow preserves regression",
         "-9223372036854775808", "9223372036854775807", "regressed",
         false, 0, "delta outside signed 64-bit range"},
        {"verdict: negative delta overflow preserves improvement",
         "9223372036854775807", "-9223372036854775808", "improved",
         false, 0, "delta outside signed 64-bit range"},
        {"verdict: exact INT64_MAX delta remains measured",
         "0", "9223372036854775807", "regressed", true, INT64_MAX, NULL},
        {"verdict: exact INT64_MIN delta remains measured",
         "0", "-9223372036854775808", "improved", true, INT64_MIN, NULL},
        {"verdict: ordinary delta remains unchanged",
         "10", "7", "improved", true, -3, NULL},
        {"verdict: null after extreme before preserves unmeasured reason",
         "-9223372036854775808", "null", "unmeasured", false, 0,
         "after: no ledger"},
        {"verdict: null before extreme after preserves unmeasured reason",
         "null", "9223372036854775807", "unmeasured", false, 0,
         "before: no ledger"},
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        failures += fov_case_delta(dir, &cases[i]);
    return failures;
}

int test_fleet_objectives_verdict(void);
int test_fleet_objectives_verdict(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "fleet_objectives_verdict", "root");
    failures += fov_case_rows(dir);
    failures += fov_case_verdicts(dir);
    failures += fov_case_refusals(dir);
    failures += fov_case_skips(dir);
    failures += fov_case_registry(dir);
    failures += fov_case_delta_boundaries(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_fleet_objectives_verdict: all passed\n");
    else
        printf("test_fleet_objectives_verdict: %d FAILED\n", failures);
    return failures;
}
