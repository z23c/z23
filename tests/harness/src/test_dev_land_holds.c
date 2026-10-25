/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: holds, priority, outcome strings and case registration.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"


/* Change the native fixture's one empty pushed-tip field, without adding
 * a duplicate key or changing any publication/signature field. */
static bool dlx_hold_pushed_fixture(const char *tip)
{
    static const char empty[] = "\"tip_pushed\":\"\"";
    char body[16384], changed[16384], land[1200], path[1400];
    size_t len = 0;
    if (!dlx_queue_bytes(body, sizeof(body), &len)) return false;
    char *field = strstr(body, empty);
    if (!field || strstr(field + sizeof(empty) - 1, "\"tip_pushed\":")) return false;
    int n = snprintf(changed, sizeof(changed), "%.*s\"tip_pushed\":\"%s\"%s",
                     (int)(field - body), body, tip,
                     field + sizeof(empty) - 1);
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
    return n > 0 && (size_t)n < sizeof(changed) && dlx_write(path, changed);
}

int dlx_hold_pushed_case(void)
{
    int failures = 0;
    TEST("land: held row with a pushed tip refuses as contradictory without effects") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[16384], after[16384], origin[64], current[64];
        size_t first = 0, second = 0;
        dlx_isolate("hold_pushed");
        ASSERT(dlx_rig_make(&rig, "hold_pushed_rig"));
        ASSERT(dlx_origin_main(&rig, origin));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_hold_field_replace(",\"publication_hold\":true"));
        ASSERT(dlx_hold_pushed_fixture(rig.tip));
        ASSERT(dlx_queue_bytes(before, sizeof(before), &first));
        ASSERT(strstr(before, "\"phase\":\"\"") != NULL);
        ASSERT(strstr(before, "\"publication_signature\":\"\"") != NULL);
        ASSERT(strstr(before, "\"publication_bundle\":\"\"") != NULL);
        ASSERT(strstr(before, "\"push_diagnostic_pending\":0") != NULL);
        ASSERT(strstr(before, "\"fence_peer\":0") != NULL);
        const char *actions[] = {"status", "step", "hold", "release"};
        for (size_t i = 0; i < sizeof(actions) / sizeof(actions[0]); i++) {
            dlx_begin(&c, actions[i]);
            if (i >= 2) (void)json_push_kv_int(&c.input, "seq", 1);
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT_STR_EQ(c.reply.error.code, "QUEUE_READ_FAILED"); dlx_end(&c);
            ASSERT(dlx_queue_bytes(after, sizeof(after), &second));
            ASSERT(first == second && memcmp(before, after, first) == 0);
            ASSERT(dlx_origin_main(&rig, current));
            ASSERT_STR_EQ(origin, current);
        }
        PASS();
    }
_test_next:
    dlx_restore();
    return failures;
}

int dlx_hold_malformed_case(void)
{
    int failures = 0;
    TEST("land: malformed or duplicate hold refuses without rewriting the queue") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[16384], after[16384], origin[64], current[64];
        size_t first = 0, second = 0;
        dlx_isolate("hold_malformed");
        ASSERT(dlx_rig_make(&rig, "hold_malformed_rig"));
        ASSERT(dlx_origin_main(&rig, origin));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        const char *bad[] = {",\"publication_hold\":\"true\"", ",\"publication_hold\":1",
            ",\"publication_hold\":null", ",\"publication_hold\":true,\"publication_hold\":false",
            ",\"publication_hold\":true,\"publication_hold\":true",
            ",\"publication_hold\":true,\"\\u0070ublication_hold\":true"};
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            ASSERT(dlx_hold_field_replace(bad[i]));
            ASSERT(dlx_queue_bytes(before, sizeof(before), &first));
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT_STR_EQ(c.reply.error.code, "QUEUE_READ_FAILED"); dlx_end(&c);
            ASSERT(dlx_queue_bytes(after, sizeof(after), &second));
            ASSERT(first == second && memcmp(before, after, first) == 0);
            ASSERT(dlx_origin_main(&rig, current));
            ASSERT_STR_EQ(origin, current);
        }
        PASS();
    }
_test_next:
    dlx_restore();
    return failures;
}

int dlx_hold_sealed_case(void)
{
    int failures = 0;
    TEST("land: hold and release refuse sealed and unknown sequences without changing bytes") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], current[64], before[16384], after[16384];
        size_t first = 0, second = 0;
        dlx_isolate("hold_sealed");
        ASSERT(dlx_attach_proven_pair(&rig, "hold_sealed", base));
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_queue_bytes(before, sizeof(before), &first));
        const char *actions[] = {"hold", "release"};
        for (size_t i = 0; i < 2; i++) {
            for (long long seq = 1; seq <= 2; seq++) {
                dlx_begin(&c, actions[i]);
                (void)json_push_kv_int(&c.input, "seq", seq);
                ASSERT(dlx_run(&c) && !dlx_ok(&c));
                ASSERT_STR_EQ(c.reply.error.code, seq == 1 ? "PUBLICATION_ALREADY_SEALED" : "UNKNOWN_SEQUENCE");
                dlx_end(&c);
                ASSERT(dlx_queue_bytes(after, sizeof(after), &second));
                ASSERT(first == second && memcmp(before, after, first) == 0);
                ASSERT(dlx_origin_main(&rig, current));
                ASSERT_STR_EQ(current, base);
            }
        }
        PASS();
    }
_test_next:
    dlx_restore();
    return failures;
}

int dlx_hold_lock_case(void)
{
    int failures = 0;
    int lock = -1;
    TEST("land: hold and release do not need the native step slot") {
        struct dlx_rig rig;
        struct dlx_call c;
        char land[1200], before[16384], after[16384];
        size_t first = 0, second = 0;
        dlx_isolate("hold_lock");
        ASSERT(dlx_rig_make(&rig, "hold_lock_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_queue_bytes(before, sizeof(before), &first));
        dlx_landdir(land, sizeof(land));
        lock = dlx_step_lock_take(land);
        ASSERT(lock >= 0);
        /* Deliberate contract change: a hold is admissible while a step
         * holds step.lock. The slot is never reported busy, and the
         * release round trip restores the untouched row byte for byte. */
        const char *actions[] = {"hold", "release"};
        for (size_t i = 0; i < 2; i++) {
            dlx_begin(&c, actions[i]);
            (void)json_push_kv_int(&c.input, "seq", 1);
            ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        }
        ASSERT(dlx_queue_bytes(after, sizeof(after), &second));
        ASSERT(first == second && memcmp(before, after, first) == 0);
        PASS();
    }
_test_next:
    if (lock >= 0) { (void)flock(lock, LOCK_UN); (void)close(lock); }
    dlx_restore();
    return failures;
}

static bool dlx_row_hold_is(bool held)
{
    return dlx_priority_is(held ? "\"publication_hold\":true"
                                : "\"publication_hold\":false");
}

int dlx_hold_admissible_during_step(void)
{
    int failures = 0;
    int lock = -1;
    TEST("land: a hold is admissible while step.lock is held and release clears it") {
        struct dlx_rig rig;
        struct dlx_call c;
        char land[1200];
        dlx_isolate("hold_during_step");
        ASSERT(dlx_rig_make(&rig, "hold_during_step_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        dlx_landdir(land, sizeof(land));
        lock = dlx_step_lock_take(land);
        ASSERT(lock >= 0);
        dlx_begin(&c, "hold");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_row_hold_is(true));
        dlx_begin(&c, "release");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_row_hold_is(false));
        PASS();
    }
_test_next:
    if (lock >= 0) { (void)flock(lock, LOCK_UN); (void)close(lock); }
    dlx_restore();
    return failures;
}

/* A hold written while a step is between picking its row and driving it must
 * survive the step's next queue rewrite and stop publication. */
int dlx_hold_survives_step_rewrite(void)
{
    int failures = 0;
    TEST("land: a hold set during a running step survives its rewrite and stops publication") {
        struct dlx_rig rig;
        struct dlx_call c;
        pid_t child;
        int st = 0;
        dlx_isolate("hold_lost_update");
        ASSERT(dlx_rig_make(&rig, "hold_lost_update_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_TEST_PICK_DELAY_MS", "400", 1);
        child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            struct dlx_call cc;
            dlx_begin(&cc, "step");
            (void)dlx_run(&cc);
            _exit(0);
        }
        {
            struct timespec ts = { 0, 60 * 1000 * 1000L };
            (void)nanosleep(&ts, NULL);
        }
        dlx_begin(&c, "hold");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        while (waitpid(child, &st, 0) < 0)
            ;
        ASSERT(WIFEXITED(st));
        ASSERT(dlx_row_hold_is(true));
        {
            char landdir[1200], opath[1400], body[8192] = {0};
            FILE *f;
            dlx_landdir(landdir, sizeof(landdir));
            (void)snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir);
            f = fopen(opath, "r");
            if (f) {
                size_t n = fread(body, 1, sizeof(body) - 1, f);
                body[n] = '\0';
                (void)fclose(f);
            }
            ASSERT(strstr(body, "\"landed\"") == NULL);
        }
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static bool dlx_hold_upgrade_duplicate(struct dlx_rig *rig)
{
    struct dlx_call c;
    if (!dlx_priority_is("\"priority_seq\":\"held:1\"")) return false;
    /* Legacy integer holds remain readable; idempotent hold upgrades them. */
    if (!dlx_priority_replace("1")) return false;
    dlx_begin(&c, "hold");
    (void)json_push_kv_int(&c.input, "seq", 1);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (!ok || !dlx_priority_is("\"priority_seq\":\"held:1\"")) return false;
    dlx_submit(&c, rig, rig->tip);
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok && dlx_priority_is("\"priority_seq\":\"held:1\"");
}

int dlx_publication_hold_cases(void)
{
    int failures = 0;
    TEST("land: retained hold permits proof but refuses step/drive publication; release restores flow") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], landed[64];
        dlx_isolate("publication_hold");
        ASSERT(dlx_rig_make(&rig, "publication_hold_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "hold");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(json_get_bool(json_get(&c.reply.data, "publication_hold")));
        dlx_end(&c);
        ASSERT(dlx_hold_upgrade_duplicate(&rig));
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *queued = dlx_arr(&c, "queued");
        ASSERT(queued && queued->num_children == 1);
        ASSERT(json_get_bool(json_get(&queued->children[0], "publication_hold")));
        ASSERT(strstr(dlx_str(&c, "screen"), "publication HELD") != NULL);
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        const char *beats[] = {"step", "drive"};
        for (size_t i = 0; i < 2; i++) {
            dlx_begin(&c, beats[i]);
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT(strcmp(c.reply.error.code, "PUBLICATION_HELD") == 0);
            dlx_end(&c);
            ASSERT(dlx_origin_main(&rig, after));
            ASSERT(strcmp(before, after) == 0);
        }
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *flight = json_get(&c.reply.data, "in_flight");
        ASSERT(flight != NULL);
        ASSERT(json_get_bool(json_get(flight, "publication_hold")));
        ASSERT(dlx_priority_is("\"priority_seq\":\"held:1\""));
        ASSERT(strstr(dlx_str(&c, "screen"), "publication HELD") != NULL);
        ASSERT_EQ((long long)dlx_arr(&c, "outcomes")->num_children, 0);
        dlx_end(&c);
        const char *attachments[] = {"attach", "attach_publish"};
        for (size_t i = 0; i < 2; i++) {
            dlx_begin(&c, attachments[i]);
            (void)json_push_kv_int(&c.input, "seq", 1);
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT(strcmp(c.reply.error.code, "PUBLICATION_HELD") == 0);
            dlx_end(&c);
            ASSERT(dlx_origin_main(&rig, after));
            ASSERT(strcmp(before, after) == 0);
        }
        dlx_begin(&c, "release");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(!json_get_bool(json_get(&c.reply.data, "publication_hold")));
        dlx_end(&c);
        ASSERT(dlx_priority_is("\"priority_seq\":1,"));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        (void)snprintf(landed, sizeof(landed), "%s", dlx_str(&c, "tip_pushed"));
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, landed) == 0 && strcmp(after, before) != 0);
        dlx_begin(&c, "hold");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT(strcmp(c.reply.error.code, "UNKNOWN_SEQUENCE") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:
    dlx_restore();
    return failures;
}

/* Reopen an otherwise-valid failed outcome through the actual native reader. */
static bool dlx_outcome_detail_matches(struct dlx_call *c, const char *expected)
{
    const struct json_value *outcomes = dlx_arr(c, "outcomes");
    if (!outcomes || outcomes->num_children != 1) return false;
    const char *observed = json_get_str(json_get(&outcomes->children[0], "detail"));
    return observed && strcmp(expected, observed) == 0;
}

static bool dlx_outcome_detail_wire(const char *wire, const char *expected)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char land[1200], queue[1400], outcome[1400], body[16384], changed[16384];
    size_t length = 0;
    dlx_isolate("escaped_outcome");
    bool ok = dlx_rig_make(&rig, "escaped_outcome_rig");
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    if (!ok) goto done;
    dlx_submit(&c, &rig, rig.tip);
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (!ok || !dlx_queue_bytes(body, sizeof(body), &length)) {
        ok = false;
        goto done;
    }
    char *state = strstr(body, "\"state\":\"queued\"");
    char *field = strstr(body, "\"detail\":\"\"");
    if (!state || !field) { ok = false; goto done; }
    memcpy(state + strlen("\"state\":\""), "failed", 6);
    int n = snprintf(changed, sizeof(changed), "%.*s\"detail\":%s%s",
                     (int)(field - body), body, wire,
                     field + strlen("\"detail\":\"\""));
    dlx_landdir(land, sizeof(land));
    (void)snprintf(queue, sizeof(queue), "%s/queue.jsonl", land);
    (void)snprintf(outcome, sizeof(outcome), "%s/outcomes.jsonl", land);
    ok = n > 0 && (size_t)n < sizeof(changed) &&
         dlx_write(outcome, changed) && dlx_write(queue, "");
    if (!ok) goto done;
    dlx_begin(&c, "status");
    ok = dlx_run(&c) && dlx_ok(&c) && dlx_outcome_detail_matches(&c, expected);
    dlx_end(&c);
done:
    dlx_restore();
    return ok;
}

int dlx_outcome_escape_cases(void)
{
    int failures = 0;
    TEST("land: status reopens escaped outcome diagnostics with exact identity") {
        const char *wire[] = {
            "\"repair\\ncommand\\tpath\\u0001suffix\"",
            "\"carriage\\rback\\bform\\f\"",
            "\"quote\\\"slash\\\\solidus\\/\"",
            "\"\\u00e9\\uD83D\\uDE00\"",
            "\"\""
        };
        const char *expected[] = {
            "repair\ncommand\tpath\001suffix",
            "carriage\rback\bform\f",
            "quote\"slash\\solidus/",
            "\xc3\xa9\xf0\x9f\x98\x80",
            ""
        };
        for (size_t i = 0; i < sizeof(wire) / sizeof(wire[0]); i++)
            ASSERT(dlx_outcome_detail_wire(wire[i], expected[i]));
        PASS();
    } _test_next:;
    return failures;
}

/* Independent review witnesses, one TEST per case: an early failure must not
 * hide the other baseline failures. These touch only private native rigs. */
static int dlx_string_refusal_case(unsigned index, const char *label,
                                  const char *needle, const char *replacement)
{
    int failures = 0;
    TEST(label) {
        struct dlx_rig rig; struct dlx_call c;
        char tag[64], rig_tag[64], land[1200], queue[1400], original[16384];
        char changed[16384], after[16384], base[80], remote[80];
        size_t length = 0, after_length = 0;
        ASSERT(snprintf(tag, sizeof(tag), "string_refusal_%u", index) < (int)sizeof(tag));
        dlx_isolate(tag);
        ASSERT(snprintf(rig_tag, sizeof(rig_tag), "string_refusal_rig_%u", index) < (int)sizeof(rig_tag));
        ASSERT(dlx_rig_make(&rig, rig_tag));
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "manual", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_queue_bytes(original, sizeof(original), &length));
        dlx_landdir(land, sizeof(land));
        ASSERT(snprintf(queue, sizeof(queue), "%s/queue.jsonl", land) < (int)sizeof(queue));
        char *field = strstr(original, needle);
        ASSERT(field != NULL);
        int n = snprintf(changed, sizeof(changed), "%.*s%s%s",
            (int)(field - original), original, replacement, field + strlen(needle));
        ASSERT(n > 0 && (size_t)n < sizeof(changed));
        ASSERT(dlx_write(queue, changed));
        const char *actions[] = { "status", "submit", "step" };
        for (size_t j = 0; j < sizeof(actions) / sizeof(actions[0]); j++) {
            if (j == 1) dlx_submit(&c, &rig, rig.tip);
            else dlx_begin(&c, actions[j]);
            ASSERT(dlx_run(&c));
            ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
            ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_queue_record_1");
            dlx_end(&c);
            ASSERT(dlx_queue_bytes(after, sizeof(after), &after_length));
            ASSERT(after_length == (size_t)n && memcmp(after, changed, after_length) == 0);
        }
        ASSERT(dlx_origin_main(&rig, remote)); ASSERT_STR_EQ(remote, base);
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

int dlx_optional_string_refusal_cases(void)
{
    static const struct { const char *label, *needle, *replacement; } cases[] = {
        { "land: single oversized phase refuses", "\"phase\":\"\"", "\"phase\":\"0123456789abcdef\"" },
        { "land: duplicate null phase refuses", "\"phase\":\"\"", "\"phase\":null,\"phase\":\"push\"" },
        { "land: nested phase refuses", "\"phase\":\"\"", "\"extra\":{\"phase\":\"push\"}" },
        { "land: wrong-type and nested phase refuse", "\"phase\":\"\"", "\"phase\":{},\"extra\":{\"phase\":\"push\"}" },
        { "land: unique oversized base refuses", "\"base\":\"\"", "\"base\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"" },
        { "land: displaced publication signature refuses", "\"phase\":\"\"", "\"phase\":\"\",\"extra\":{\"publication_signature\":\"aa\"}" },
        { "land: duplicate null detail refuses", "\"detail\":\"\"", "\"detail\":null,\"detail\":\"repair\"" },
        { "land: unique null phase refuses", "\"phase\":\"\"", "\"phase\":null" },
        { "land: decoded-equivalent duplicate keys refuse", "\"phase\":\"\"", "\"phase\":\"\",\"ph\\u0061se\":\"push\"" }
    };
    int failures = 0;
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        failures += dlx_string_refusal_case(i, cases[i].label, cases[i].needle, cases[i].replacement);
    return failures;
}

/* Exercise the native serializer, not a parallel wire encoder. */
extern bool zcl_native_dev_land_test_encode_detail(const char *, bool, char *, size_t);

static bool dlx_native_detail_matches(struct dlx_call *c, const char *detail,
                                      bool terminal)
{
    const struct json_value *rows = dlx_arr(c, terminal ? "outcomes" : "queued");
    if (!rows || rows->num_children != 1) return false;
    if (!terminal) return true; /* Real row reader checked detail in the seam. */
    const char *observed = json_get_str(json_get(&rows->children[0], "detail"));
    return observed && strcmp(observed, detail) == 0;
}

static bool dlx_native_detail_roundtrip(const char *detail, bool terminal)
{
    struct dlx_call c;
    char land[1200], path[1400], body[16384];
    dlx_isolate("native_detail_boundary");
    dlx_landdir(land, sizeof(land));
    bool ok = dlx_mkdir_p(land) &&
        zcl_native_dev_land_test_encode_detail(detail, terminal, body, sizeof(body));
    int n = snprintf(path, sizeof(path), "%s/%s.jsonl", land,
                     terminal ? "outcomes" : "queue");
    ok = ok && n > 0 && (size_t)n < sizeof(path) && dlx_write(path, body);
    if (ok) {
        dlx_begin(&c, "status");
        ok = dlx_run(&c) && dlx_ok(&c);
        ok = ok && dlx_native_detail_matches(&c, detail, terminal);
        dlx_end(&c);
    }
    dlx_restore();
    return ok;
}

static int dlx_native_detail_boundary_case(unsigned kind)
{
    int failures = 0;
    TEST("land: maximum native detail survives queue and outcome decoding") {
        char detail[1024];
        for (size_t i = 0; i < sizeof(detail) - 1; i++)
            detail[i] = kind == 0 ? 'a' : kind == 1 ? '\001' :
                i == 1022 ? 'x' : i % 2 == 0 ? (char)0xc3 : (char)0xa9;
        detail[1023] = '\0';
        ASSERT(dlx_native_detail_roundtrip(detail, false));
        ASSERT(dlx_native_detail_roundtrip(detail, true));
        PASS();
    } _test_next:;
    return failures;
}

static bool dlx_extended_native_row(char *body, size_t cap, unsigned members)
{
    char native[16384];
    if (!zcl_native_dev_land_test_encode_detail("", false, native, sizeof(native)))
        return false;
    struct json_value doc; json_init(&doc);
    bool ok = json_read(&doc, native, strlen(native)) && doc.type == JSON_OBJ &&
              doc.num_children == 37;
    json_free(&doc);
    char *end = strrchr(native, '}');
    if (!ok || !end || members < 37) return false;
    size_t used = (size_t)(end - native);
    if (used >= cap) return false;
    memcpy(body, native, used);
    for (unsigned i = 37; i < members; i++) {
        int n = snprintf(body + used, cap - used, ",\"extension_%u\":0", i);
        if (n <= 0 || (size_t)n >= cap - used) return false;
        used += (size_t)n;
    }
    if (cap - used < 3) return false;
    memcpy(body + used, "}\n", 3);
    return true;
}

static int dlx_row_member_boundary_case(unsigned members, bool accepted)
{
    int failures = 0;
    TEST("land: row member bound accepts 64 and refuses larger inventories") {
        char body[100000], after[100000], land[1200], path[1400];
        size_t after_length = 0;
        struct dlx_call c;
        dlx_isolate("member_boundary");
        dlx_landdir(land, sizeof(land));
        ASSERT(dlx_mkdir_p(land));
        ASSERT(snprintf(path, sizeof(path), "%s/queue.jsonl", land) < (int)sizeof(path));
        ASSERT(dlx_extended_native_row(body, sizeof(body), members));
        ASSERT(dlx_write(path, body));
        dlx_begin(&c, "status"); ASSERT(dlx_run(&c));
        if (accepted) ASSERT(dlx_ok(&c));
        else ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        dlx_end(&c);
        ASSERT(dlx_queue_bytes(after, sizeof(after), &after_length));
        ASSERT(after_length == strlen(body) && memcmp(after, body, after_length) == 0);
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

static int dlx_absent_optional_case(void)
{
    int failures = 0;
    TEST("land: absent optional fields remain valid legacy row fields") {
        struct dlx_call c;
        char land[1200], path[1400];
        dlx_isolate("absent_optional"); dlx_landdir(land, sizeof(land));
        ASSERT(dlx_mkdir_p(land));
        ASSERT(snprintf(path, sizeof(path), "%s/queue.jsonl", land) < (int)sizeof(path));
        ASSERT(dlx_write(path, "{\"seq\":1,\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                              "\"state\":\"queued\",\"attempt\":1}\n"));
        dlx_begin(&c, "status"); ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *rows = dlx_arr(&c, "queued");
        ASSERT(rows && rows->num_children == 1);
        dlx_end(&c); PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

int dlx_string_compatibility_cases(void)
{
    int failures = dlx_absent_optional_case();
    for (unsigned i = 0; i < 3; i++) failures += dlx_native_detail_boundary_case(i);
    failures += dlx_row_member_boundary_case(64, true);
    failures += dlx_row_member_boundary_case(65, false);
    failures += dlx_row_member_boundary_case(4096, false);
    return failures;
}
static const struct zcl_command_spec *dlx_leaf(const char *verb)
{
    char path[64];
    (void)snprintf(path, sizeof(path), "%s.%s", DLX_PATH, verb);
    return zcl_command_registry_find(zcl_command_catalog(), path, NULL);
}

int dlx_case_registration(void)
{
    int failures = 0;
    TEST("land: every verb is a nested leaf with its row keys") {
        static const char *const verbs[] = {
            "submit", "drive", "status", "step", "attach", "attach_publish",
            "hold", "release", "cancel", "fence_replace", "attest_only" };
        const struct zcl_command_spec *branch =
            zcl_command_registry_find(zcl_command_catalog(), DLX_PATH, NULL);
        ASSERT(branch != NULL && branch->mode == ZCL_COMMAND_MODE_BRANCH);
        for (size_t i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++) {
            const struct zcl_command_spec *leaf = dlx_leaf(verbs[i]);
            ASSERT(leaf != NULL);
            ASSERT_STR_EQ(leaf->parent, DLX_PATH);
        }
        ASSERT(strstr(dlx_leaf("submit")->input_keys, "tip") != NULL);
        ASSERT(strstr(dlx_leaf("submit")->input_keys, "worktree") != NULL);
        ASSERT(strstr(dlx_leaf("submit")->input_keys, "note") != NULL);
        ASSERT(strstr(dlx_leaf("drive")->input_keys, "seq") != NULL);
        ASSERT(strstr(dlx_leaf("drive")->input_keys, "max_rows") != NULL);
        ASSERT(strstr(dlx_leaf("drive")->input_keys, "prove") != NULL);
        ASSERT(strstr(dlx_leaf("cancel")->input_keys, "seq") != NULL);
        ASSERT(strstr(dlx_leaf("status")->input_keys, "json") != NULL);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_unknown_action(void)
{
    int failures = 0;
    TEST("land: an unknown action and a missing one are refused") {
        struct dlx_call c;
        dlx_isolate("route");
        dlx_begin(&c, "launch");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, NULL);
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

#if !defined(_WIN32)

int dlx_case_unsigned_tip(void)
{
    int failures = 0;
    TEST("land: submit refuses an unsigned tip and an unknown one") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("refuse");
        ASSERT(dlx_rig_make(&rig, "refuse_rig"));
        /* The fixture commits are --no-gpg-sign, so this IS the unsigned
         * case, and the bypass is not set. */
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        /* A commit id nobody can resolve. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, "0123456789abcdef0123456789abcdef01234567");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        /* Not a commit id at all. */
        dlx_submit(&c, &rig, "main");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        /* Nothing was stored by any of the three. */
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(dlx_arr(&c, "queued") != NULL);
        ASSERT_EQ((long long)dlx_arr(&c, "queued")->num_children, 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_checkout_location(void)
{
    int failures = 0;
    TEST("land: queue survives outside HOME from checkout and nested cwd") {
        ASSERT(dlx_run_in_child(dlx_queue_outside_home));
        PASS();
    }
    TEST("land: submit discovers the absolute checkout from its root") {
        ASSERT(dlx_run_in_child(dlx_discovery_checkout));
        PASS();
    }
    TEST("land: a step admits a worktree beside the checkout outside HOME") {
        ASSERT(dlx_run_in_child(dlx_step_beside_checkout));
        PASS();
    }
    TEST("land: submit from a nested directory discovers the checkout, and refuses outside one") {
        ASSERT(dlx_run_in_child(dlx_discovery_nested));
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_submit_status(void)
{
    int failures = 0;
    TEST("land: submit queues the tip and status lists it, without waiting") {
        struct dlx_rig rig;
        struct dlx_call c;
        const struct json_value *rows;
        char full[64];
        time_t t0, t1;
        dlx_isolate("queue");
        ASSERT(dlx_rig_make(&rig, "queue_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        (void)snprintf(full, sizeof(full), "%s", rig.tip);
        t0 = time(NULL);
        dlx_submit(&c, &rig, full);
        (void)json_push_kv_str(&c.input, "note", "the first landing");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 1);
        ASSERT(strcmp(dlx_str(&c, "state"), "queued") == 0);
        ASSERT(strcmp(dlx_str(&c, "tip"), full) == 0);
        dlx_end(&c);
        t1 = time(NULL);
        /* Submit is a file append. It cannot have proved anything. */
        ASSERT((long long)(t1 - t0) < 20);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        rows = dlx_arr(&c, "queued");
        ASSERT(rows != NULL);
        ASSERT_EQ((long long)rows->num_children, 1);
        ASSERT(json_get_str(json_get(&rows->children[0], "tip")) &&
               strcmp(json_get_str(json_get(&rows->children[0], "tip")),
                      full) == 0);
        /* Nothing is in flight before a step runs. */
        ASSERT(json_get(&c.reply.data, "in_flight") == NULL);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_duplicate_submit(void)
{
    int failures = 0;
    TEST("land: retrying the exact tip in one checkout attaches to its live row") {
        ASSERT(dlx_exact_submit_retry());
        ASSERT(dlx_exact_submit_mid_rebase_refused());
        ASSERT(dlx_submit_operation_markers_refused());
        ASSERT(dlx_marker_batch_clean());
        ASSERT(dlx_marker_batch_fallback());
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* ── dev land precheck ────────────────────────────────────────────────────
 *
 * The lint precheck submit runs before it queues. The fixture lane carries
 * its own build/bin/z23-lint, a shell script that answers --list from
 * build/precheck-known, fails (exit 1, a violation) the gate named in
 * build/precheck-fail, reports it cannot decide (exit 2) for the gate named in
 * build/precheck-unproven, and logs each gate it ran to build/precheck-ran.
 * Every file is read relative to the cwd the script was started in, so a
 * precheck that ran in the wrong directory finds nothing and the tests fail. */
#define DLX_PC_SCRIPT                                                        \
    "#!/bin/sh\n"                                                            \
    "if [ \"$1\" = --list ]; then cat build/precheck-known; exit 0; fi\n"    \
    "echo \"$1\" >> build/precheck-ran\n"                                    \
    "if [ -f build/precheck-fail ] && [ \"$1\" = \"$(cat build/precheck-fail)\" ]; then\n" \
    "  echo \"first line of $1\"; echo \"second line\"; echo \"stderr line\" >&2; exit 1\n" \
    "fi\n"                                                                   \
    "if [ -f build/precheck-unproven ] && [ \"$1\" = \"$(cat build/precheck-unproven)\" ]; then\n" \
    "  echo \"cannot decide $1 here\"; exit 2\n"                             \
    "fi\n"                                                                   \
    "exit 0\n"

bool dlx_pc_file(const struct dlx_rig *rig, const char *name,
                        const char *text)
{
    char path[1400];
    (void)snprintf(path, sizeof(path), "%s/build", rig->clone);
    (void)dlx_mkdir_p(path);
    (void)snprintf(path, sizeof(path), "%s/build/bin", rig->clone);
    (void)dlx_mkdir_p(path);
    (void)snprintf(path, sizeof(path), "%s/build/%s", rig->clone, name);
    return dlx_write(path, text);
}

#define DLX_PC_NOW INT64_C(1700000000)

bool dlx_pc_rig(struct dlx_rig *rig, const char *tag, bool with_lint,
                       const char *known)
{
    char path[1400];
    dlx_isolate(tag);
    if (!dlx_rig_make(rig, tag))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    zcl_dev_land_precheck_test_force(true);
    zcl_dev_land_precheck_test_now(DLX_PC_NOW);
    if (!dlx_pc_file(rig, "precheck-known", known))
        return false;
    if (!with_lint)
        return true;
    (void)snprintf(path, sizeof(path), "%s/build/bin/z23-lint", rig->clone);
    return dlx_write(path, DLX_PC_SCRIPT) && chmod(path, 0755) == 0;
}

/* submit through the in-process path, where `precheck` is an ordinary key. */
void dlx_pc_submit(struct dlx_call *c, const struct dlx_rig *rig,
                          const char *mode, const char *note)
{
    dlx_begin(c, NULL);
    (void)json_push_kv_str(&c->input, "action", "submit");
    (void)json_push_kv_str(&c->input, "tip", rig->tip);
    (void)json_push_kv_str(&c->input, "worktree", rig->clone);
    if (mode)
        (void)json_push_kv_str(&c->input, "precheck", mode);
    if (note)
        (void)json_push_kv_str(&c->input, "note", note);
}

bool dlx_pc_has(const struct json_value *arr, const char *name)
{
    for (size_t i = 0; arr && i < arr->num_children; i++) {
        if (arr->children[i].type == JSON_STR &&
            strcmp(json_get_str(&arr->children[i]), name) == 0)
            return true;
    }
    return false;
}

bool dlx_pc_ran(const struct dlx_rig *rig, const char *gate)
{
    char path[1400], text[1024] = "";
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/build/precheck-ran", rig->clone);
    f = fopen(path, "rb");
    if (f) {
        size_t n = fread(text, 1, sizeof(text) - 1, f);
        text[n] = '\0';
        (void)fclose(f);
    }
    return strstr(text, gate) != NULL;
}

/* Seed <land state>/outcomes.jsonl; false when it cannot be written. */
bool dlx_pc_outcomes(const char *rows)
{
    char root[512], dir[640], path[704];
    if (!platform_state_root(root, sizeof(root)))
        return false;
    (void)snprintf(dir, sizeof(dir), "%s/land", root);
    (void)dlx_mkdir_p(dir);
    (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", dir);
    return dlx_write(path, rows);
}

static long dlx_pc_outcomes_size(void)
{
    char root[512], path[704];
    struct stat st;
    if (!platform_state_root(root, sizeof(root)))
        return -2;
    (void)snprintf(path, sizeof(path), "%s/land/outcomes.jsonl", root);
    return stat(path, &st) == 0 ? (long)st.st_size : -1;
}

/* A ledger row dated `days_ago`, as outcomes.jsonl carries it. */
void dlx_pc_row(char *out, size_t cap, int seq, const char *state,
                       const char *dim, int days_ago, const char *detail)
{
    char ts[64];
    time_t t = (time_t)DLX_PC_NOW - (time_t)days_ago * 86400;
    struct tm tm_utc;
    (void)gmtime_r(&t, &tm_utc);
    (void)strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    (void)snprintf(out, cap,
                   "{\"seq\":%d,\"ts\":\"%s\",\"state\":\"%s\","
                   "\"tip\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"attempt\":1,"
                   "\"dimension\":\"%s\",\"detail\":\"%s\",\"note\":\"\"}\n",
                   seq, ts, state, dim, detail);
}

static bool dlx_pc_owned_file(const char *root, const char *relative,
                               const char *text, mode_t mode)
{
    char path[1600], parent[1600];
    if (snprintf(path, sizeof(path), "%s/%s", root, relative) >= (int)sizeof(path))
        return false;
    (void)snprintf(parent, sizeof(parent), "%s", path);
    char *slash = strrchr(parent, '/');
    if (!slash) return false;
    *slash = 0;
    return dlx_mkdir_p(parent) && chmod(parent, 0700) == 0 &&
           dlx_write(path, text) && chmod(path, mode) == 0;
}

static bool dlx_pc_history_archive(const char *suffix, int days_ago,
                                   const char *reason, char archive[1600])
{
    /* Fixed request/window clocks exercise ages without host elapsed time. */
    char root[512], wt[768], attempt[1200], request[320], failure[1200];
    if (!platform_state_root(root, sizeof(root))) return false;
    (void)snprintf(wt, sizeof(wt), "%s/land/wt", root);
    const char *parts[] = {"", ".cache", ".cache/zcl-dev-proof", ".cache/zcl-dev-proof/attempts"};
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
        char path[1000];
        (void)snprintf(path, sizeof(path), "%s/%s", wt, parts[i]);
        if (!dlx_mkdir_p(path) || chmod(path, 0700) != 0) return false;
    }
    (void)snprintf(attempt, sizeof(attempt),
        ".cache/zcl-dev-proof/attempts/1111111111111111111111111111111111111111-2222222222222222222222222222222222222222.%s", suffix);
    (void)snprintf(request, sizeof(request), "zcl.dev_proof_request.v1\n"
        "1111111111111111111111111111111111111111\n"
        "2222222222222222222222222222222222222222\n%lld\n1\n",
        (long long)DLX_PC_NOW - (long long)days_ago * 86400);
    char relative[1300];
    (void)snprintf(relative, sizeof(relative), "%s/request", attempt);
    if (!dlx_pc_owned_file(wt, relative, request, 0600)) return false;
    (void)snprintf(relative, sizeof(relative), "%s/logs/failure.txt", attempt);
    (void)snprintf(failure, sizeof(failure), "%s\n"
        "lint check-ship-remote-transaction: FAIL check-ship-remote-transaction 3445 ms (rc=1)\n", reason);
    return dlx_pc_owned_file(wt, relative, failure, 0600) &&
           snprintf(archive, 1600, "%s/%s", wt, relative) < 1600;
}

static bool dlx_pc_ship_files(const struct dlx_rig *rig, bool ready)
{
    static const char script[] = "#!/bin/sh\n"
        "echo \"ship-adapter:$0 $*\" >> build/precheck-ran\n"
        "if [ -f build/ship-exit ]; then exit \"$(cat build/ship-exit)\"; fi\nexit 0\n";
    const char *scripts[] = {"tools/ship.sh", "tools/ship_selftest.sh",
                             "tools/lint/check_ship_remote_transaction.sh"};
    const char *tools[] = {"build/bin/z23-tor-provenance", "build/bin/check_no_hardlink_seeding"};
    for (size_t i = 0; i < sizeof(scripts) / sizeof(scripts[0]); i++)
        if (!dlx_pc_owned_file(rig->clone, scripts[i], script, 0755)) return false;
    for (size_t i = 0; i < sizeof(tools) / sizeof(tools[0]); i++)
        if (!dlx_pc_owned_file(rig->clone, tools[i], "#!/bin/sh\nexit 0\n", 0755)) return false;
    if (ready && !dlx_pc_owned_file(rig->clone, "build/bin/jsonq", "#!/bin/sh\nexit 0\n", 0755))
        return false;
    return dlx_pc_owned_file(rig->clone, "tools/scripts/ship_progress_lib.sh", "# isolated fixture\n", 0600);
}

static size_t dlx_pc_ship_calls(const struct dlx_rig *rig)
{
    char path[1400], line[512];
    (void)snprintf(path, sizeof(path), "%s/build/precheck-ran", rig->clone);
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t count = 0;
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, "ship-adapter:", 13) == 0) count++;
    (void)fclose(f);
    return count;
}

static bool dlx_pc_ship_selftest_ran(const struct dlx_rig *rig, const char *absolute)
{
    return dlx_pc_ran(rig, absolute) ||
           dlx_pc_ran(rig, "ship-adapter:./tools/ship.sh --selftest");
}

bool dlx_pc_history_ship_pass(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char archive[1600], landed[512], ship[1600];
    if (!dlx_pc_rig(&rig, "precheck_history_ship", true, "check-arm-symbol-single\n") ||
        !dlx_pc_history_archive("aaaaaa", 1, "child_proof_failed_exit_2", archive) ||
        !dlx_pc_history_archive("bbbbbb", 1, "child_proof_failed_exit_2", archive) ||
        !dlx_pc_ship_files(&rig, true) ||
        snprintf(ship, sizeof(ship), "%s/tools/ship.sh --selftest", rig.clone) >= (int)sizeof(ship)) return false;
    dlx_pc_row(landed, sizeof(landed), 9, "landed", "", 0, "solo success");
    if (!dlx_pc_outcomes(landed)) return false;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.dev_land.v1");
    char note[64] = "fixture";
    bool ok = zcl_dev_land_precheck("dev.land", rig.clone, NULL, "run",
        rig.tip, false, note, sizeof(note), &reply) &&
        dlx_pc_has(json_get(&reply.data, "precheck_ran"), "check-ship-remote-transaction") &&
        dlx_pc_ship_calls(&rig) == 3;
    zcl_command_reply_free(&reply);
    dlx_pc_submit(&c, &rig, NULL, NULL);
    ok = ok && dlx_run(&c) && dlx_ok(&c) &&
        dlx_pc_has(dlx_arr(&c, "precheck_ran"), "check-ship-remote-transaction") &&
        dlx_pc_ship_calls(&rig) == 6 &&
        dlx_pc_ship_selftest_ran(&rig, ship);
    dlx_end(&c);
    ok = ok && dlx_queue_has_one();
    dlx_restore();
    return ok;
}

static bool dlx_pc_ship_failed(struct dlx_call *c, const struct dlx_rig *rig)
{
    return !dlx_ok(c) && strcmp(dlx_err_code(c), "PRECHECK_FAILED") == 0 &&
           strcmp(dlx_str(c, "gate"), "check-ship-remote-transaction") == 0 &&
           dlx_pc_ship_calls(rig) == 1 && dlx_queue_empty();
}

static bool dlx_pc_ship_missing(struct dlx_call *c, const struct dlx_rig *rig)
{
    return dlx_ok(c) && dlx_queue_has_one() &&
           dlx_pc_has(dlx_arr(c, "precheck_skipped"), "check-ship-remote-transaction") &&
           strstr(dlx_str(c, "precheck_unproven"), "build/bin/jsonq") != NULL &&
           dlx_pc_ship_calls(rig) == 0;
}

bool dlx_pc_history_ship_refusal(const char *exit_code, bool ready)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char archive[1600];
    if (!dlx_pc_rig(&rig, ready ? "precheck_ship_failure" : "precheck_ship_missing", true,
                    "check-arm-symbol-single\n") ||
        !dlx_pc_history_archive("aaaaaa", 1, "child_proof_failed_exit_2", archive) ||
        !dlx_pc_ship_files(&rig, ready)) return false;
    if (ready && !dlx_pc_file(&rig, "ship-exit", exit_code)) return false;
    dlx_pc_submit(&c, &rig, NULL, NULL);
    bool ran = dlx_run(&c);
    bool ok = ran && (ready ? dlx_pc_ship_failed(&c, &rig) : dlx_pc_ship_missing(&c, &rig));
    dlx_end(&c);
    dlx_restore();
    return ok;
}

static bool dlx_pc_no_ship(struct dlx_call *c, const struct dlx_rig *rig)
{
    return dlx_ok(c) &&
        dlx_pc_has(dlx_arr(c, "precheck_ran"), "check-learned-one") &&
        !dlx_pc_has(dlx_arr(c, "precheck_ran"), "check-ship-remote-transaction") &&
        !dlx_pc_has(dlx_arr(c, "precheck_skipped"), "check-ship-remote-transaction") &&
        dlx_pc_ship_calls(rig) == 0;
}

bool dlx_pc_history_ignored(const char *tag, int days_ago,
                                  const char *reason, bool unsafe)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char archive[1600], failed[512];
    if (!dlx_pc_rig(&rig, tag, true, "check-learned-one\n") ||
        !dlx_pc_history_archive("aaaaaa", days_ago, reason, archive)) return false;
    if (unsafe) {
        if (!dlx_pc_history_archive("bbbbbb", 1, "child_proof_failed_exit_2", archive) ||
            unlink(archive) != 0 || symlink("../request", archive) != 0) return false;
    }
    dlx_pc_row(failed, sizeof(failed), 8, "failed", "lint", 1, "check-learned-one failed");
    if (!dlx_pc_outcomes(failed)) return false;
    dlx_pc_submit(&c, &rig, NULL, NULL);
    bool ok = dlx_run(&c) && dlx_pc_no_ship(&c, &rig);
    if (unsafe || days_ago > 7 || days_ago < 0)
        ok = ok && strstr(dlx_str(&c, "precheck_unproven"), "proof-history:") != NULL;
    dlx_end(&c);
    dlx_restore();
    return ok;
}

bool dlx_pc_history_allocation_unproven(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char archive[1600], failed[512];
    if (!dlx_pc_rig(&rig, "history_allocation", true, "check-learned-one\n") ||
        !dlx_pc_history_archive("aaaaaa", 1, "child_proof_failed_exit_2", archive))
        return false;
    dlx_pc_row(failed, sizeof(failed), 8, "failed", "lint", 1, "check-learned-one failed");
    if (!dlx_pc_outcomes(failed)) return false;
    dlx_pc_submit(&c, &rig, NULL, NULL);
    zcl_alloc_fault_fail_next("dev_land_precheck.history");
    bool ran = dlx_run(&c);
    bool consumed = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    bool ok = ran && consumed && dlx_pc_no_ship(&c, &rig) &&
        strstr(dlx_str(&c, "precheck_unproven"), "history allocation unavailable") != NULL &&
        dlx_queue_has_one();
    dlx_end(&c);
    dlx_restore();
    return ok;
}

static bool dlx_pc_observation_rig(struct dlx_rig *rig, const char *tag,
                                   char canonical[1600], char metadata[1600], char lock[1600])
{
    char archive[1600], root[512], wt[800], failed[512];
    if (!dlx_pc_rig(rig, tag, true, "check-learned-one\n") ||
        !dlx_pc_history_archive("aaaaaa", 10, "child_proof_failed_exit_2", archive) ||
        !platform_state_root(root, sizeof(root))) return false;
    (void)snprintf(wt, sizeof(wt), "%s/land/wt", root);
    if (!platform_directory_canonical_real(wt, canonical, 1600)) return false;
    const char *slash = strrchr(archive, '/');
    if (!slash) return false;
    int n = snprintf(metadata, 1600, "%.*s/failure-observed.v1", (int)(slash - archive), archive);
    int l = snprintf(lock, 1600, "%s/.cache/zcl-dev-proof/queue.lock", canonical);
    dlx_pc_row(failed, sizeof(failed), 8, "failed", "lint", 1, "check-learned-one failed");
    return n > 0 && n < 1600 && l > 0 && l < 1600 && dlx_pc_outcomes(failed);
}

bool dlx_pc_observation_busy(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char root[1600], metadata[1600], lock[1600];
    if (!dlx_pc_observation_rig(&rig, "observation_busy", root, metadata, lock)) return false;
    int guard = open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (guard < 0) return false;
    if (flock(guard, LOCK_EX | LOCK_NB) != 0) { (void)close(guard); return false; }
    dlx_pc_submit(&c, &rig, NULL, NULL);
    bool ran = dlx_run(&c);
    (void)flock(guard, LOCK_UN); (void)close(guard);
    bool ok = ran && dlx_pc_no_ship(&c, &rig) && dlx_queue_has_one() &&
        strstr(dlx_str(&c, "precheck_unproven"), "legacy observation incomplete") != NULL &&
        access(metadata, F_OK) != 0;
    dlx_end(&c);
    dlx_restore();
    return ok;
}

static bool dlx_pc_observation_age(const char *root, const char *metadata, int64_t *age)
{
    struct zcl_dev_proof_observation_report report;
    if (!zcl_dev_proof_observe_legacy_failures(root, &report)) return false;
    char record[1024], changed[1024];
    FILE *file = fopen(metadata, "rb");
    if (!file) return false;
    size_t n = fread(record, 1, sizeof(record) - 1, file);
    bool ok = !ferror(file) && feof(file) && n > 0;
    if (fclose(file) != 0) ok = false;
    if (!ok) return false;
    record[n] = 0;
    const char *start = strstr(record, "\nobserved_upper_unix=");
    if (!start) return false;
    start += strlen("\nobserved_upper_unix=");
    const char *end = strchr(start, '\n');
    if (!end) return false;
    *age = DLX_PC_NOW - 8 * 86400;
    int size = snprintf(changed, sizeof(changed), "%.*s%lld%s", (int)(start - record),
        record, (long long)*age, end);
    return size > 0 && size < (int)sizeof(changed) && dlx_write(metadata, changed);
}

bool dlx_pc_observation_aged(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char root[1600], metadata[1600], lock[1600];
    int64_t age;
    if (!dlx_pc_observation_rig(&rig, "observation_aged", root, metadata, lock) ||
        !dlx_pc_observation_age(root, metadata, &age)) return false;
    dlx_pc_submit(&c, &rig, NULL, NULL);
    bool ok = dlx_run(&c) && dlx_pc_no_ship(&c, &rig) && dlx_queue_has_one() &&
        !strstr(dlx_str(&c, "precheck_unproven"), "proof-history:");
    struct zcl_dev_proof_history_failure row;
    static const char leaf[] = "1111111111111111111111111111111111111111-"
        "2222222222222222222222222222222222222222.aaaaaa";
    ok = ok && zcl_dev_proof_history_failure_read(root, leaf, &row) &&
        row.observation_state == ZCL_PROOF_HISTORY_OBSERVATION_BOUND_UPPER && row.observed_upper_unix == age;
    dlx_end(&c);
    dlx_restore();
    return ok;
}

bool dlx_pc_gate_set_learns(void)
{
    char rows[2048], one[512];
    char path[704], root[512];
    struct zcl_land_precheck_gates g;
    bool ok;
    dlx_isolate("precheck_gate_set");
    if (!platform_state_root(root, sizeof(root)))
        return false;
    rows[0] = '\0';
    dlx_pc_row(one, sizeof(one), 1, "failed", "lint", 1,
               "check-learned-one failed [x]");
    (void)strcat(rows, one);
    dlx_pc_row(one, sizeof(one), 2, "failed", "lint", 30,
               "check-too-old failed");
    (void)strcat(rows, one);
    dlx_pc_row(one, sizeof(one), 3, "failed", "lint", 1,
               "check-superseded failed");
    (void)strcat(rows, one);
    dlx_pc_row(one, sizeof(one), 3, "landed", "", 1, "");
    (void)strcat(rows, one);
    dlx_pc_row(one, sizeof(one), 4, "failed", "proof", 1,
               "check-wrong-dimension failed");
    (void)strcat(rows, one);
    if (!dlx_pc_outcomes(rows))
        return false;
    (void)snprintf(path, sizeof(path), "%s/land/outcomes.jsonl", root);
    zcl_land_precheck_gate_set(path, DLX_PC_NOW, &g);
    ok = g.count == 5;
    for (size_t i = 0; i < g.count; i++) {
        ok = ok && strcmp(g.name[i], "check-too-old") != 0 &&
             strcmp(g.name[i], "check-superseded") != 0 &&
             strcmp(g.name[i], "check-wrong-dimension") != 0;
    }
    ok = ok && g.count == 5 && strcmp(g.name[0], "check-file-size-ceiling") == 0 &&
         strcmp(g.name[4], "check-learned-one") == 0;
    zcl_land_precheck_gate_set("/nonexistent/outcomes.jsonl",
                               DLX_PC_NOW, &g);
    ok = ok && g.count == 4;
    dlx_restore();
    return ok;
}

bool dlx_pc_failing_gate_refused(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char head[64];
    const char *rev[] = { "rev-parse", "HEAD", NULL };
    bool ok;
    if (!dlx_pc_rig(&rig, "precheck_fail", true,
                    "check-file-size-ceiling\ncheck-cyclomatic-complexity\n"
                    "check-core-seal\ncheck-arm-symbol-single\n") ||
        !dlx_pc_file(&rig, "precheck-fail", "check-core-seal"))
        return false;
    long before = dlx_pc_outcomes_size();
    dlx_pc_submit(&c, &rig, NULL, "n");
    ok = dlx_run(&c) && !dlx_ok(&c) &&
         strcmp(dlx_err_code(&c), "PRECHECK_FAILED") == 0 &&
         strstr(c.reply.error.message, "check-core-seal") != NULL &&
         strstr(c.reply.error.message, "fix and resubmit") != NULL &&
         strstr(c.reply.error.evidence, "first line of check-core-seal") &&
         strstr(c.reply.error.evidence, "stderr line") != NULL &&
         strcmp(dlx_str(&c, "gate"), "check-core-seal") == 0;
    dlx_end(&c);
    ok = ok && dlx_queue_empty() && dlx_pc_outcomes_size() == before &&
         dlx_git_out(rig.clone, rev, head, sizeof(head)) == 0 &&
         strcmp(head, rig.tip) == 0;
    dlx_restore();
    return ok;
}

/* A gate exiting 2 cannot decide here: it is skipped and named, the gates
 * after it still run, and the submit still queues. */
bool dlx_pc_unproven_gate_skipped(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    bool ok;
    if (!dlx_pc_rig(&rig, "precheck_unproven", true,
                    "check-file-size-ceiling\ncheck-cyclomatic-complexity\n"
                    "check-core-seal\ncheck-arm-symbol-single\n") ||
        !dlx_pc_file(&rig, "precheck-unproven", "check-cyclomatic-complexity"))
        return false;
    dlx_pc_submit(&c, &rig, NULL, "u");
    ok = dlx_run(&c) && dlx_ok(&c) && dlx_int(&c, "seq") == 1 &&
         dlx_pc_has(dlx_arr(&c, "precheck_skipped"),
                    "check-cyclomatic-complexity") &&
         !dlx_pc_has(dlx_arr(&c, "precheck_ran"),
                     "check-cyclomatic-complexity") &&
         dlx_pc_has(dlx_arr(&c, "precheck_ran"), "check-arm-symbol-single") &&
         strstr(dlx_str(&c, "precheck_unproven"),
                "check-cyclomatic-complexity: cannot decide") != NULL;
    dlx_end(&c);
    ok = ok && dlx_queue_has_one() && dlx_pc_ran(&rig, "check-core-seal") &&
         dlx_pc_ran(&rig, "check-arm-symbol-single");
    dlx_restore();
    return ok;
}

bool dlx_pc_clean_lane_queued(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    bool ok;
    if (!dlx_pc_rig(&rig, "precheck_clean", true,
                    "check-file-size-ceiling\ncheck-cyclomatic-complexity\n"
                    "check-core-seal\ncheck-arm-symbol-single\n"))
        return false;
    dlx_pc_submit(&c, &rig, NULL, NULL);
    ok = dlx_run(&c) && dlx_ok(&c) && dlx_int(&c, "seq") == 1 &&
         dlx_pc_has(dlx_arr(&c, "precheck_ran"), "check-arm-symbol-single") &&
         dlx_arr(&c, "precheck_skipped") &&
         dlx_arr(&c, "precheck_skipped")->num_children == 0;
    dlx_end(&c);
    ok = ok && dlx_queue_has_one() && dlx_pc_ran(&rig, "check-core-seal");
    dlx_restore();
    return ok;
}

bool dlx_pc_queued_note(const char *want)
{
    struct dlx_call c;
    bool ok;
    dlx_begin(&c, "status");
    (void)json_push_kv_bool(&c.input, "json", true);
    ok = dlx_run(&c) && dlx_ok(&c);
    const struct json_value *rows = dlx_arr(&c, "queued");
    const struct json_value *n =
        rows && rows->num_children == 1 ? json_get(&rows->children[0], "note")
                                        : NULL;
    ok = ok && n && n->type == JSON_STR && strcmp(json_get_str(n), want) == 0;
    dlx_end(&c);
    return ok;
}

bool dlx_pc_skip_marks_note(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char longnote[520];
    bool ok;
    if (!dlx_pc_rig(&rig, "precheck_skip", true, "check-core-seal\n") ||
        !dlx_pc_file(&rig, "precheck-fail", "check-core-seal"))
        return false;
    memset(longnote, 'n', 500);
    longnote[500] = '\0';
    dlx_pc_submit(&c, &rig, "skip", longnote);
    ok = dlx_run(&c) && !dlx_ok(&c) &&
         strcmp(dlx_err_code(&c), "PRECHECK_NOTE_TOO_LONG") == 0;
    dlx_end(&c);
    dlx_pc_submit(&c, &rig, "bogus", NULL);
    ok = ok && dlx_run(&c) && strcmp(dlx_err_code(&c), "BAD_INPUT") == 0;
    dlx_end(&c);
    dlx_pc_submit(&c, &rig, "sent", NULL);
    ok = ok && dlx_run(&c) && strcmp(dlx_err_code(&c), "BAD_INPUT") == 0 &&
         strstr(c.reply.error.message, "skip") != NULL;
    dlx_end(&c);
    ok = ok && dlx_queue_empty();
    dlx_pc_submit(&c, &rig, "skip", "why");
    ok = ok && dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    ok = ok && dlx_pc_queued_note("why [precheck skipped]") &&
         !dlx_pc_ran(&rig, "check-core-seal");
    dlx_restore();
    return ok;
}

#endif /* !defined(_WIN32) */
