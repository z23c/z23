/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance bar for dev.agent.reviewscore
 * (tools/command/native_devagent_reviewscore.c) and for the pure rule it
 * applies (engine/modules/engine/src/engine_review_score.c). Every fixture is
 * written under a temp directory made here; nothing reads the checkout.
 */

#include "test/test_core.h"

#include "base/safe_alloc.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "engine/engine_findings.h"
#include "engine/engine_review_score.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RS_PATH "dev.agent.reviewscore"

#define RS_SOUND(id) "{\"id\":\"" id "\",\"label\":\"sound\"}\n"
#define RS_DEFECT(id, locus, cls)                                           \
    "{\"id\":\"" id "\",\"label\":\"defect\",\"locus\":\"" locus            \
    "\",\"class\":\"" cls "\",\"defect\":[{\"file\":\"a.c\",\"line_lo\":10," \
    "\"line_hi\":20}],\"tolerance\":2}\n"
#define RS_REVIEW(id, findings) \
    "{\"case\":\"" id "\",\"reviewer\":\"r1\",\"findings\":[" findings "]}\n"
#define RS_CHANGE(file, line) \
    "{\"kind\":\"CHANGE\",\"file\":\"" file "\",\"line\":" #line "}"
#define RS_CLAIM(file, line) \
    "{\"kind\":\"CLAIM\",\"file\":\"" file "\",\"line\":" #line "}"
/* A defect line from a ranges list; tol is RS_TOL(n) or "" to omit the key. */
#define RS_RANGE(file, lo, hi) \
    "{\"file\":\"" file "\",\"line_lo\":" #lo ",\"line_hi\":" #hi "}"
#define RS_TOL(t) ",\"tolerance\":" #t
#define RS_DEFECT_AT(id, locus, cls, ranges, tol)                           \
    "{\"id\":\"" id "\",\"label\":\"defect\",\"locus\":\"" locus            \
    "\",\"class\":\"" cls "\",\"defect\":[" ranges "]" tol "}\n"

struct rs_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static bool rs_write(const char *dir, const char *rel, const char *text)
{
    char path[1024];
    if (snprintf(path, sizeof(path), "%s/%s", dir, rel) < 0)
        return false;
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    size_t len = strlen(text);
    bool wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

static void rs_begin(struct rs_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), RS_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.agent_reviewscore.v1");
}

static void rs_end(struct rs_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* Validate through the real registry, then call the bound handler. */
static bool rs_run(struct rs_call *c)
{
    char why[192];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_dev_agent_reviewscore(&c->request, &c->reply);
    return true;
}

/* Write both fixtures and run the leaf. Returns false on a setup failure. */
static bool rs_score(struct rs_call *c, const char *root, const char *set,
                     const char *reviews)
{
    char sp[1024], rp[1024];
    rs_begin(c);
    if (!rs_write(root, "set.jsonl", set) ||
        !rs_write(root, "reviews.jsonl", reviews))
        return false;
    (void)snprintf(sp, sizeof(sp), "%s/set.jsonl", root);
    (void)snprintf(rp, sizeof(rp), "%s/reviews.jsonl", root);
    return json_push_kv_str(&c->input, "set", sp) &&
           json_push_kv_str(&c->input, "reviews", rp) && rs_run(c);
}

static bool rs_ok(const struct rs_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static int64_t rs_int(const struct rs_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -12345;
}

static bool rs_bool(const struct rs_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static int64_t rs_pair(const struct rs_call *c, const char *key,
                       const char *part)
{
    const struct json_value *o = json_get(&c->reply.data, key);
    const struct json_value *v = o ? json_get(o, part) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : -12345;
}

static size_t rs_len(const struct rs_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_ARR ? json_size(v) : (size_t)-1;
}

static const char *rs_err(const struct rs_call *c)
{
    return c->reply.error.message;
}

static const char *rs_code(const struct rs_call *c)
{
    return c->reply.error.code;
}

/* One class row by name, or NULL. */
static const struct json_value *rs_class(const struct rs_call *c,
                                         const char *name)
{
    const struct json_value *arr = json_get(&c->reply.data, "by_class");
    for (size_t i = 0; arr && i < json_size(arr); i++) {
        const char *n = json_get_str(json_get(json_at(arr, i), "class"));
        if (n && strcmp(n, name) == 0)
            return json_at(arr, i);
    }
    return NULL;
}

/* ── T1 T2 T3: sound cases ──────────────────────────────────────────── */

static int rs_sound(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("sound: a review with no findings is not rejected") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_SOUND("s1"), RS_REVIEW("s1", "")));
        ASSERT(rs_ok(&c));
        ASSERT_EQ(rs_int(&c, "sound_reviews"), 1);
        ASSERT_EQ(rs_int(&c, "sound_rejected"), 0);
        PASS();
    }
    TEST("sound: one CHANGE finding rejects, on the change side only") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_SOUND("s1"),
                        RS_REVIEW("s1", RS_CHANGE("a.c", 5))));
        ASSERT_EQ(rs_int(&c, "sound_rejected"), 1);
        ASSERT_EQ(rs_int(&c, "sound_rejected_change"), 1);
        ASSERT_EQ(rs_int(&c, "sound_rejected_claim"), 0);
        PASS();
    }
    TEST("sound: a finding without a line is discarded, not a rejection") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_SOUND("s1"),
                        RS_REVIEW("s1", "{\"kind\":\"CHANGE\",\"file\":\"a.c\"}")));
        ASSERT_EQ(rs_int(&c, "sound_rejected"), 0);
        ASSERT_EQ(rs_int(&c, "findings_discarded"), 1);
        ASSERT_EQ(rs_int(&c, "findings_total"), 1);
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* ── T4: the tolerance boundary ─────────────────────────────────────── */

static int rs_boundary(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    static const struct { int line; int64_t accepted; } rows[] = {
        {22, 0}, {23, 1}, {8, 0}, {7, 1}, {15, 0},
    };
    TEST("defect(code): hit at the edge of tolerance, miss one past it") {
        for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            char rev[256];
            (void)snprintf(rev, sizeof(rev),
                           "{\"case\":\"d1\",\"reviewer\":\"r\",\"findings\":["
                           "{\"kind\":\"CHANGE\",\"file\":\"a.c\",\"line\":%d}]}\n",
                           rows[i].line);
            rs_end(&c);
            ASSERT(rs_score(&c, root, RS_DEFECT("d1", "code", "logic"), rev));
            ASSERT_EQ(rs_int(&c, "defect_reviews"), 1);
            ASSERT_EQ(rs_int(&c, "defect_accepted"), rows[i].accepted);
        }
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* ── T5 T6 T7: kind and file ────────────────────────────────────────── */

static int rs_kind_file(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("defect(code): a CLAIM finding on the exact line is a miss") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_DEFECT("d1", "code", "logic"),
                        RS_REVIEW("d1", RS_CLAIM("a.c", 15))));
        ASSERT_EQ(rs_int(&c, "defect_accepted"), 1);
        ASSERT_EQ(rs_int(&c, "defect_accepted_code"), 1);
        ASSERT_EQ(rs_int(&c, "defect_accepted_claim"), 0);
        PASS();
    }
    TEST("defect(claim): a CLAIM finding in range is caught") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_DEFECT("d1", "claim", "message"),
                        RS_REVIEW("d1", RS_CLAIM("a.c", 15))));
        ASSERT_EQ(rs_int(&c, "defect_accepted"), 0);
        PASS();
    }
    TEST("defect(claim): a CHANGE finding is a miss, counted on the claim side") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_DEFECT("d1", "claim", "message"),
                        RS_REVIEW("d1", RS_CHANGE("a.c", 15))));
        ASSERT_EQ(rs_int(&c, "defect_accepted_claim"), 1);
        PASS();
    }
    TEST("defect: the right line in the wrong file is a miss") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_DEFECT("d1", "code", "logic"),
                        RS_REVIEW("d1", RS_CHANGE("A.c", 15))));
        ASSERT_EQ(rs_int(&c, "defect_accepted"), 1);
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* ── T8 T9: unreviewed and unknown ──────────────────────────────────── */

static int rs_unreviewed(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("a case with no review is listed and in no denominator") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_SOUND("s1") RS_SOUND("s2"),
                        RS_REVIEW("s1", "")));
        ASSERT_EQ(rs_len(&c, "unreviewed"), 1);
        ASSERT_EQ(rs_int(&c, "unreviewed_total"), 1);
        ASSERT(!rs_bool(&c, "unreviewed_truncated"));
        ASSERT_EQ(rs_pair(&c, "sound_reject_rate", "den"), 1);
        ASSERT_STR_EQ(json_get_str(json_at(json_get(&c.reply.data, "unreviewed"), 0)),
                      "s2");
        PASS();
    }
    TEST("a review naming an unknown id moves only the unknown counter") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_SOUND("s1"),
                        RS_REVIEW("zz", RS_CHANGE("a.c", 5))));
        ASSERT_EQ(rs_int(&c, "unknown_case_reviews"), 1);
        ASSERT_EQ(rs_int(&c, "findings_total"), 0);
        ASSERT_EQ(rs_int(&c, "sound_reviews"), 0);
        ASSERT_EQ(rs_int(&c, "unreviewed_total"), 1);
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* ── T10: refusals ──────────────────────────────────────────────────── */

static int rs_refusals(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("a duplicate case id refuses the set and names the id") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_SOUND("dup7") RS_DEFECT("dup7", "code", "x"),
                        RS_REVIEW("dup7", "")));
        ASSERT(!rs_ok(&c));
        ASSERT(strstr(rs_err(&c), "dup7") != NULL);
        PASS();
    }
    TEST("an unreadable reviews file refuses") {
        rs_end(&c);
        rs_begin(&c);
        char sp[1024], rp[1024];
        ASSERT(rs_write(root, "set.jsonl", RS_SOUND("s1")));
        (void)snprintf(sp, sizeof(sp), "%s/set.jsonl", root);
        (void)snprintf(rp, sizeof(rp), "%s/absent.jsonl", root);
        ASSERT(json_push_kv_str(&c.input, "set", sp));
        ASSERT(json_push_kv_str(&c.input, "reviews", rp));
        ASSERT(rs_run(&c));
        ASSERT(!rs_ok(&c));
        PASS();
    }
    TEST("a missing reviews key refuses with an explanatory body") {
        rs_end(&c);
        rs_begin(&c);
        char sp[1024];
        (void)snprintf(sp, sizeof(sp), "%s/set.jsonl", root);
        ASSERT(json_push_kv_str(&c.input, "set", sp));
        ASSERT(rs_run(&c));
        ASSERT(!rs_ok(&c));
        ASSERT(strstr(rs_err(&c), "reviews") != NULL);
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* ── T11: malformed lines ───────────────────────────────────────────── */

static int rs_malformed(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    static char big[9100];
    memset(big, 'x', 9000);
    big[9000] = '\n';
    (void)snprintf(big + 9001, sizeof(big) - 9001, "%s", RS_REVIEW("s1", ""));
    TEST("malformed review lines are counted and the rest scored") {
        rs_end(&c);
        ASSERT(rs_score(&c, root,
                        RS_SOUND("s1") "\n" "  \t\r\n",
                        "{\"case\":\"s1\"}\n" RS_REVIEW("s1", RS_CHANGE("a.c", 1))
                        "[1]\n"));
        ASSERT(rs_ok(&c));
        ASSERT_EQ(rs_int(&c, "set_malformed_lines"), 0);
        ASSERT_EQ(rs_int(&c, "reviews_malformed_lines"), 2);
        ASSERT_EQ(rs_int(&c, "sound_cases"), 1);
        ASSERT_EQ(rs_int(&c, "sound_rejected"), 1);
        PASS();
    }
    TEST("an oversized review line is drained and counted malformed") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_SOUND("s1"), big));
        ASSERT(rs_ok(&c));
        ASSERT_EQ(rs_int(&c, "reviews_malformed_lines"), 1);
        ASSERT_EQ(rs_int(&c, "sound_reviews"), 1);
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* ── T12: classes ───────────────────────────────────────────────────── */

static int rs_classes(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("two defect classes give two rows with their own counts") {
        rs_end(&c);
        ASSERT(rs_score(&c, root,
                        RS_DEFECT("d1", "code", "logic")
                        RS_DEFECT("d2", "code", "logic")
                        RS_DEFECT("d3", "claim", "message"),
                        RS_REVIEW("d1", RS_CHANGE("a.c", 15))
                        RS_REVIEW("d2", "")
                        RS_REVIEW("d3", "")));
        ASSERT_EQ(rs_len(&c, "by_class"), 2);
        const struct json_value *logic = rs_class(&c, "logic");
        const struct json_value *msg = rs_class(&c, "message");
        ASSERT(logic && msg);
        ASSERT_EQ(json_get_int(json_get(logic, "defect_reviews")), 2);
        ASSERT_EQ(json_get_int(json_get(logic, "defect_accepted")), 1);
        ASSERT_EQ(json_get_int(json_get(msg, "defect_reviews")), 1);
        ASSERT_EQ(json_get_int(json_get(msg, "defect_accepted")), 1);
        PASS();
    }
    TEST("classes beyond 32 fold into (other) and set classes_truncated") {
        char *set = zcl_malloc(40u * 400u, "rs_set");
        char *rev = zcl_malloc(40u * 100u, "rs_rev");
        ASSERT(set && rev);
        set[0] = rev[0] = '\0';
        for (int i = 0; i < 34; i++) {
            char line[512];
            (void)snprintf(line, sizeof(line),
                           "{\"id\":\"d%d\",\"label\":\"defect\",\"locus\":\"code\","
                           "\"class\":\"c%d\",\"defect\":[{\"file\":\"a.c\","
                           "\"line_lo\":1,\"line_hi\":2}]}\n", i, i);
            strcat(set, line);
            (void)snprintf(line, sizeof(line),
                           "{\"case\":\"d%d\",\"findings\":[]}\n", i);
            strcat(rev, line);
        }
        rs_end(&c);
        bool ran = rs_score(&c, root, set, rev);
        free(set);
        free(rev);
        ASSERT(ran);
        ASSERT_EQ(rs_len(&c, "by_class"), 33);
        ASSERT(rs_bool(&c, "classes_truncated"));
        const struct json_value *other = rs_class(&c, "(other)");
        ASSERT(other != NULL);
        ASSERT_EQ(json_get_int(json_get(other, "defect_reviews")), 2);
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* ── T13: the 59-defect floor ───────────────────────────────────────── */

static int rs_enough_run(const char *root, int defects, bool *enough,
                         int64_t *count)
{
    char *set = zcl_malloc((size_t)defects * 200u + 1u, "rs_set");
    struct rs_call c;
    if (!set)
        return 1;
    set[0] = '\0';
    for (int i = 0; i < defects; i++) {
        char line[256];
        (void)snprintf(line, sizeof(line),
                       "{\"id\":\"d%d\",\"label\":\"defect\",\"locus\":\"code\","
                       "\"class\":\"x\",\"defect\":[{\"file\":\"a.c\","
                       "\"line_lo\":1,\"line_hi\":2}]}\n", i);
        strcat(set, line);
    }
    bool ran = rs_score(&c, root, set, "");
    free(set);
    *enough = rs_bool(&c, "defect_cases_enough");
    *count = rs_int(&c, "defect_cases");
    int rc = ran && rs_int(&c, "defect_cases_min") == 59 ? 0 : 1;
    rs_end(&c);
    return rc;
}

static int rs_enough(const char *root)
{
    int failures = 0;
    bool enough = false;
    int64_t count = 0;
    TEST("defect_cases_enough is false at 58 and true at 59") {
        ASSERT_EQ(rs_enough_run(root, 58, &enough, &count), 0);
        ASSERT_EQ(count, 58);
        ASSERT(!enough);
        ASSERT_EQ(rs_enough_run(root, 59, &enough, &count), 0);
        ASSERT_EQ(count, 59);
        ASSERT(enough);
        PASS();
    }
_test_next:;
    return failures;
}

/* ── T14: rates ─────────────────────────────────────────────────────── */

static int rs_rates(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("rates are exact num/den pairs for a small mixed set") {
        rs_end(&c);
        ASSERT(rs_score(&c, root,
                        RS_SOUND("s1") RS_SOUND("s2") RS_SOUND("s3")
                        RS_DEFECT("d1", "code", "logic")
                        RS_DEFECT("d2", "code", "logic"),
                        RS_REVIEW("s1", RS_CLAIM("a.c", 3))
                        RS_REVIEW("s2", "") RS_REVIEW("s3", "")
                        RS_REVIEW("d1", RS_CHANGE("a.c", 12))
                        RS_REVIEW("d2", "")
                        RS_REVIEW("d2", RS_CHANGE("a.c", 12))));
        ASSERT_EQ(rs_pair(&c, "sound_reject_rate", "num"), 1);
        ASSERT_EQ(rs_pair(&c, "sound_reject_rate", "den"), 3);
        ASSERT_EQ(rs_int(&c, "sound_rejected_claim"), 1);
        ASSERT_EQ(rs_pair(&c, "defect_accept_rate", "num"), 1);
        ASSERT_EQ(rs_pair(&c, "defect_accept_rate", "den"), 3);
        ASSERT(rs_bool(&c, "measurable"));
        PASS();
    }
    TEST("measurable is false with no sound review, and the pair is 0/0") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_DEFECT("d1", "code", "logic"),
                        RS_REVIEW("d1", "")));
        ASSERT(!rs_bool(&c, "measurable"));
        ASSERT_EQ(rs_pair(&c, "sound_reject_rate", "num"), 0);
        ASSERT_EQ(rs_pair(&c, "sound_reject_rate", "den"), 0);
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* Score one CHANGE finding at file:line against the defect case d1 in `set`.
 * *accepted gets defect_accepted: 0 is a hit, 1 a miss. */
static bool rs_hit(struct rs_call *c, const char *root, const char *set,
                   const char *file, int line, int64_t *accepted)
{
    char rev[256];
    (void)snprintf(rev, sizeof(rev),
                   "{\"case\":\"d1\",\"reviewer\":\"r\",\"findings\":["
                   "{\"kind\":\"CHANGE\",\"file\":\"%s\",\"line\":%d}]}\n",
                   file, line);
    rs_end(c);
    if (!rs_score(c, root, set, rev))
        return false;
    *accepted = rs_int(c, "defect_accepted");
    return true;
}

/* ── T16 T17: the tolerance key ─────────────────────────────────────── */

static int rs_tolerance(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("tolerance absent defaults to 2: a hit at 22, a miss at 23") {
        const char *set = RS_DEFECT_AT("d1", "code", "logic",
                                       RS_RANGE("a.c", 10, 20), "");
        int64_t acc = -1;
        ASSERT(rs_hit(&c, root, set, "a.c", 22, &acc));
        ASSERT_EQ(acc, 0);
        ASSERT(rs_hit(&c, root, set, "a.c", 23, &acc));
        ASSERT_EQ(acc, 1);
        PASS();
    }
    TEST("tolerance 0: a hit at line_hi, misses one past either edge") {
        const char *set = RS_DEFECT_AT("d1", "code", "logic",
                                       RS_RANGE("a.c", 10, 20), RS_TOL(0));
        static const struct { int line; int64_t accepted; } rows[] = {
            {20, 0}, {21, 1}, {9, 1},
        };
        int64_t acc = -1;
        for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            ASSERT(rs_hit(&c, root, set, "a.c", rows[i].line, &acc));
            ASSERT_EQ(acc, rows[i].accepted);
        }
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* ── T18 T19: the range edges and several ranges ────────────────────── */

static int rs_ranges(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("a range at line 1 has no underflow: hits at 1 and 3, a miss at 4") {
        const char *set = RS_DEFECT_AT("d1", "code", "logic",
                                       RS_RANGE("a.c", 1, 1), RS_TOL(2));
        static const struct { int line; int64_t accepted; } rows[] = {
            {1, 0}, {3, 0}, {4, 1},
        };
        int64_t acc = -1;
        for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            ASSERT(rs_hit(&c, root, set, "a.c", rows[i].line, &acc));
            ASSERT_EQ(acc, rows[i].accepted);
        }
        PASS();
    }
    TEST("two ranges in two files: a hit in the second, a miss on the first") {
        const char *set = RS_DEFECT_AT("d1", "code", "logic",
                                       RS_RANGE("a.c", 10, 20) ","
                                       RS_RANGE("b.c", 30, 40), RS_TOL(2));
        int64_t acc = -1;
        ASSERT(rs_hit(&c, root, set, "b.c", 35, &acc));
        ASSERT_EQ(acc, 0);
        ASSERT(rs_hit(&c, root, set, "a.c", 35, &acc));
        ASSERT_EQ(acc, 1);
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* ── T20 T21: several findings and several reviews ──────────────────── */

static int rs_findings(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("one review with two non-hits and one hit is caught") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_DEFECT("d1", "code", "logic"),
                        RS_REVIEW("d1", RS_CLAIM("a.c", 15) ","
                                        RS_CHANGE("a.c", 50) ","
                                        RS_CHANGE("a.c", 15))));
        ASSERT_EQ(rs_int(&c, "defect_reviews"), 1);
        ASSERT_EQ(rs_int(&c, "defect_accepted"), 0);
        ASSERT_EQ(rs_int(&c, "findings_total"), 3);
        PASS();
    }
    TEST("a sound case reviewed twice, once with a finding, is 2 and 1") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_SOUND("s1"),
                        RS_REVIEW("s1", RS_CHANGE("a.c", 5))
                        RS_REVIEW("s1", "")));
        ASSERT_EQ(rs_int(&c, "sound_reviews"), 2);
        ASSERT_EQ(rs_int(&c, "sound_rejected"), 1);
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* ── T22 T23: a malformed set line refuses the whole set ────────────── */

static int rs_set_refusals(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    static char big[9100];
    memset(big, 'x', 9000);
    big[9000] = '\n';
    (void)snprintf(big + 9001, sizeof(big) - 9001, "%s", RS_SOUND("s2"));
    TEST("a malformed set line refuses the set and names its line") {
        rs_end(&c);
        ASSERT(rs_score(&c, root,
                        RS_SOUND("s1") "\n" "not json\n" RS_SOUND("s2"), ""));
        ASSERT(!rs_ok(&c));
        ASSERT_STR_EQ(rs_code(&c), "SET_MALFORMED");
        ASSERT(strstr(rs_err(&c), "line 3") != NULL);
        PASS();
    }
    TEST("an oversized set line refuses the set") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, big, ""));
        ASSERT(!rs_ok(&c));
        ASSERT_STR_EQ(rs_code(&c), "SET_MALFORMED");
        PASS();
    }
    TEST("a defect case with class (other) refuses the set") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_DEFECT("d1", "code", "(other)"),
                        RS_REVIEW("d1", "")));
        ASSERT(!rs_ok(&c));
        ASSERT_STR_EQ(rs_code(&c), "SET_MALFORMED");
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* ── T24: the 4096-case limit ───────────────────────────────────────── */

/* A sound set of n cases, ids t0 .. t(n-1), one per line. */
static char *rs_cases(int n)
{
    size_t cap = (size_t)n * 40u + 1u;
    char *set = zcl_malloc(cap, "rs_cases");
    if (!set)
        return NULL;
    size_t off = 0;
    for (int i = 0; i < n; i++)
        off += (size_t)snprintf(set + off, cap - off,
                                "{\"id\":\"t%d\",\"label\":\"sound\"}\n", i);
    return set;
}

static int rs_set_limit(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("4097 cases refuse the set as too large") {
        char *set = rs_cases(4097);
        ASSERT(set != NULL);
        rs_end(&c);
        bool ran = rs_score(&c, root, set, "");
        free(set);
        ASSERT(ran);
        ASSERT(!rs_ok(&c));
        ASSERT_STR_EQ(rs_code(&c), "SET_TOO_LARGE");
        PASS();
    }
    TEST("4096 cases are accepted") {
        char *set = rs_cases(4096);
        ASSERT(set != NULL);
        rs_end(&c);
        bool ran = rs_score(&c, root, set, "");
        free(set);
        ASSERT(ran);
        ASSERT(rs_ok(&c));
        ASSERT_EQ(rs_int(&c, "sound_cases"), 4096);
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* ── I1..I9: duplicate defects and independence ────────────────────── */

/* A defect line with an optional base_id (NULL omits the key). */
#define RS_DEFECT_BASE(id, cls, base)                                       \
    "{\"id\":\"" id "\",\"label\":\"defect\",\"locus\":\"code\","           \
    "\"class\":\"" cls "\",\"base_id\":\"" base "\",\"defect\":["           \
    RS_RANGE("a.c", 10, 20) "]}\n"

/* A generated set: n defect cases with distinct ranges (so none repeats), case
 * i on base b(i % nbases) (no base_id when nbases is 0) and class
 * k(i % nclasses); the first `fat` cases share the base "fat"; then `sound`
 * sound cases. */
struct rs_gen {
    int n, nbases, nclasses, fat, sound;
};

static char *rs_gen_set(const struct rs_gen *g)
{
    size_t cap = (size_t)(g->n + g->sound) * 300u + 1u;
    char *set = zcl_malloc(cap, "rs_gen_set");
    size_t off = 0;
    if (!set)
        return NULL;
    set[0] = '\0';
    for (int i = 0; i < g->n; i++) {
        char base[64] = "";
        if (g->nbases > 0)
            (void)snprintf(base, sizeof(base), "\"base_id\":\"%s%d\",",
                           i < g->fat ? "fat" : "b",
                           i < g->fat ? 0 : i % g->nbases);
        off += (size_t)snprintf(set + off, cap - off,
                                "{\"id\":\"g%d\",\"label\":\"defect\",\"locus\":"
                                "\"code\",\"class\":\"k%d\",%s\"defect\":["
                                "{\"file\":\"a.c\",\"line_lo\":%d,\"line_hi\":%d}]}\n",
                                i, i % g->nclasses, base, i + 1, i + 1);
    }
    for (int i = 0; i < g->sound; i++)
        off += (size_t)snprintf(set + off, cap - off,
                                "{\"id\":\"s%d\",\"label\":\"sound\"%s}\n", i,
                                g->nbases < 0 ? ",\"base_id\":\"sb\"" : "");
    return set;
}

/* Score a generated set with no reviews. False on a setup failure. */
static bool rs_run_gen(struct rs_call *c, const char *root,
                       const struct rs_gen *g)
{
    char *set = rs_gen_set(g);
    if (!set)
        return false;
    rs_end(c);
    bool ran = rs_score(c, root, set, "");
    free(set);
    return ran;
}

/* The independence object's member, or NULL. */
static const struct json_value *rs_ind(const struct rs_call *c, const char *key)
{
    return json_get(json_get(&c->reply.data, "independence"), key);
}

static int64_t rs_ind_int(const struct rs_call *c, const char *key)
{
    const struct json_value *v = rs_ind(c, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -12345;
}

static bool rs_ind_ok(const struct rs_call *c)
{
    const struct json_value *v = rs_ind(c, "ok");
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

/* True when the independence array `key` has exactly the one element `name`. */
static bool rs_ind_only(const struct rs_call *c, const char *key,
                        const char *name)
{
    const struct json_value *a = rs_ind(c, key);
    const char *s = a && json_size(a) == 1 ? json_get_str(json_at(a, 0)) : NULL;
    return s && strcmp(s, name) == 0;
}

static int rs_dup_defect(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("I1: the same class, locus, ranges and base twice refuses the set") {
        rs_end(&c);
        ASSERT(rs_score(&c, root,
                        RS_DEFECT_BASE("dA", "logic", "b1")
                        RS_DEFECT_BASE("dB", "logic", "b1"), ""));
        ASSERT(!rs_ok(&c));
        ASSERT_STR_EQ(rs_code(&c), "SET_DUPLICATE_DEFECT");
        ASSERT(strstr(rs_err(&c), "dA") && strstr(rs_err(&c), "dB"));
        PASS();
    }
    TEST("I2: the same class and ranges on different bases is accepted") {
        rs_end(&c);
        ASSERT(rs_score(&c, root,
                        RS_DEFECT_BASE("dA", "logic", "b1")
                        RS_DEFECT_BASE("dB", "logic", "b2"), ""));
        ASSERT(rs_ok(&c));
        ASSERT_EQ(rs_int(&c, "defect_cases"), 2);
        PASS();
    }
    TEST("I3: the same base and class on a different range is accepted") {
        rs_end(&c);
        ASSERT(rs_score(&c, root,
                        RS_DEFECT_BASE("dA", "logic", "b1")
                        "{\"id\":\"dB\",\"label\":\"defect\",\"locus\":\"code\","
                        "\"class\":\"logic\",\"base_id\":\"b1\",\"defect\":["
                        "{\"file\":\"a.c\",\"line_lo\":10,\"line_hi\":21}]}\n",
                        ""));
        ASSERT(rs_ok(&c));
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

static int rs_base_rules(const char *root)
{
    int failures = 0;
    struct rs_call c;
    char big[512];
    rs_begin(&c);
    TEST("I7: a case with no base_id is its own base") {
        rs_end(&c);
        ASSERT(rs_score(&c, root,
                        RS_DEFECT("d1", "code", "x") RS_DEFECT("d2", "code", "x"),
                        ""));
        ASSERT(rs_ok(&c));
        ASSERT_EQ(rs_ind_int(&c, "bases"), 2);
        ASSERT_EQ(rs_ind_int(&c, "max_per_base"), 1);
        PASS();
    }
    TEST("I8: a base_id of 96 bytes is a malformed set line, 95 is accepted") {
        char id[ERS_ID_MAX + 1];
        memset(id, 'b', 96);
        id[96] = '\0';
        (void)snprintf(big, sizeof(big), "{\"id\":\"s1\",\"label\":\"sound\","
                       "\"base_id\":\"%s\"}\n", id);
        rs_end(&c);
        ASSERT(rs_score(&c, root, big, ""));
        ASSERT(!rs_ok(&c));
        ASSERT_STR_EQ(rs_code(&c), "SET_MALFORMED");
        id[95] = '\0';
        (void)snprintf(big, sizeof(big), "{\"id\":\"s1\",\"label\":\"sound\","
                       "\"base_id\":\"%s\"}\n", id);
        rs_end(&c);
        ASSERT(rs_score(&c, root, big, ""));
        ASSERT(rs_ok(&c));
        PASS();
    }
    TEST("I8: a non-string base_id is a malformed set line") {
        rs_end(&c);
        ASSERT(rs_score(&c, root,
                        "{\"id\":\"s1\",\"label\":\"sound\",\"base_id\":7}\n", ""));
        ASSERT_STR_EQ(rs_code(&c), "SET_MALFORMED");
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

static int rs_independence(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("I4: four defect cases on one base are over the base limit") {
        ASSERT(rs_run_gen(&c, root, &(struct rs_gen){4, 1, 4, 0, 0}));
        ASSERT(!rs_ind_ok(&c));
        ASSERT_EQ(rs_ind_int(&c, "max_per_base"), 4);
        ASSERT_EQ(rs_ind_int(&c, "over_base_total"), 1);
        ASSERT(rs_ind_only(&c, "over_base", "b0"));
        PASS();
    }
    TEST("boundary: exactly 3 per base and exactly 8 per class is ok") {
        ASSERT(rs_run_gen(&c, root, &(struct rs_gen){3, 1, 3, 0, 0}));
        ASSERT(rs_ind_ok(&c));
        ASSERT_EQ(rs_ind_int(&c, "per_base_limit"), 3);
        ASSERT(rs_run_gen(&c, root, &(struct rs_gen){8, 8, 1, 0, 0}));
        ASSERT(rs_ind_ok(&c));
        ASSERT_EQ(rs_ind_int(&c, "per_class_limit"), 8);
        ASSERT_EQ(rs_ind_int(&c, "max_per_class"), 8);
        PASS();
    }
    TEST("I5: nine defect cases of one class on nine bases are over the class limit") {
        ASSERT(rs_run_gen(&c, root, &(struct rs_gen){9, 9, 1, 0, 0}));
        ASSERT(!rs_ind_ok(&c));
        ASSERT_EQ(rs_ind_int(&c, "over_base_total"), 0);
        ASSERT(rs_ind_only(&c, "over_class", "k0"));
        PASS();
    }
    TEST("I9: sound cases never count toward a base or a class") {
        ASSERT(rs_run_gen(&c, root, &(struct rs_gen){3, 3, 3, 0, 12}));
        ASSERT(rs_ind_ok(&c));
        ASSERT_EQ(rs_ind_int(&c, "bases"), 3);
        ASSERT_EQ(rs_ind_int(&c, "max_per_class"), 1);
        ASSERT(rs_run_gen(&c, root, &(struct rs_gen){3, -1, 3, 0, 12}));
        ASSERT(rs_ind_ok(&c));
        ASSERT_EQ(rs_ind_int(&c, "max_per_base"), 1);
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

static int rs_ready(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("I6: 59 defects within the limits plus a sound case is set_ready") {
        ASSERT(rs_run_gen(&c, root, &(struct rs_gen){59, 20, 8, 0, 1}));
        ASSERT(rs_bool(&c, "set_ready"));
        ASSERT(rs_ind_ok(&c));
        ASSERT_EQ(rs_ind_int(&c, "bases"), 20);
        PASS();
    }
    TEST("I6: the same set without a sound case is not set_ready") {
        ASSERT(rs_run_gen(&c, root, &(struct rs_gen){59, 20, 8, 0, 0}));
        ASSERT(!rs_bool(&c, "set_ready"));
        ASSERT(rs_bool(&c, "defect_cases_enough"));
        PASS();
    }
    TEST("I6: one base holding 4 is not set_ready though the count is enough") {
        ASSERT(rs_run_gen(&c, root, &(struct rs_gen){59, 20, 8, 4, 1}));
        ASSERT(!rs_bool(&c, "set_ready"));
        ASSERT(rs_bool(&c, "defect_cases_enough"));
        ASSERT(!rs_ind_ok(&c));
        PASS();
    }
    TEST("I6: 58 defects within the limits plus a sound case is not set_ready") {
        ASSERT(rs_run_gen(&c, root, &(struct rs_gen){58, 20, 8, 0, 1}));
        ASSERT(!rs_bool(&c, "set_ready"));
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* The over lists cap at 32 with the exact total; 4096 cases stay fast. */
static int rs_independence_bounds(const char *root)
{
    int failures = 0;
    struct rs_call c;
    struct timespec t0, t1;
    rs_begin(&c);
    TEST("over_base lists 32 of 40 bases and over_base_total is 40") {
        ASSERT(rs_run_gen(&c, root, &(struct rs_gen){160, 40, 4, 0, 0}));
        ASSERT_EQ(rs_ind_int(&c, "over_base_total"), 40);
        ASSERT_EQ(json_size(rs_ind(&c, "over_base")), 32);
        PASS();
    }
    TEST("4096 defect cases on 4096 bases and one class tally (time reported, not graded)") {
        (void)clock_gettime(CLOCK_MONOTONIC, &t0);
        ASSERT(rs_run_gen(&c, root, &(struct rs_gen){4096, 4096, 1, 0, 0}));
        (void)clock_gettime(CLOCK_MONOTONIC, &t1);
        double secs = (double)(t1.tv_sec - t0.tv_sec) +
                      (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        printf("[4096-case independence run: %.3f s] ", secs);
        ASSERT(rs_ok(&c));
        ASSERT_EQ(rs_ind_int(&c, "bases"), 4096);
        ASSERT_EQ(rs_ind_int(&c, "over_class_total"), 1);
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* ── the FINDING-line parser, called directly ───────────────────────── */

static struct efd_result ef_run(const char *text, struct efd_finding *out,
                                size_t cap)
{
    struct efd_result r;
    efd_parse(text, text ? strlen(text) : 0, out, cap, &r);
    return r;
}

static bool ef_text_is(const struct efd_finding *f, const char *want)
{
    return f->text_len == strlen(want) && memcmp(f->text, want, f->text_len) == 0;
}

/* F1, F2 */
static int ef_basic(void)
{
    int failures = 0;
    struct efd_finding f[4];
    struct efd_result r;
    TEST("F1: a CHANGE and a CLAIM line among prose are read with exact fields") {
        r = ef_run("Summary of the review.\n"
                   "FINDING CHANGE high a.c:12 off by one\n"
                   "1. MET - the card point\n"
                   "FINDING CLAIM low docs/x.md:7\n"
                   "NOT REVIEWED: nothing\n", f, 4);
        ASSERT_EQ(r.findings, 2);
        ASSERT_EQ(r.illformed, 0);
        ASSERT(!r.no_findings && !r.truncated);
        ASSERT(f[0].kind == ERS_KIND_CHANGE && f[0].severity == EFD_SEV_HIGH);
        ASSERT_STR_EQ(f[0].path, "a.c");
        ASSERT_EQ(f[0].line, 12);
        ASSERT(ef_text_is(&f[0], "off by one"));
        ASSERT(f[1].kind == ERS_KIND_CLAIM && f[1].severity == EFD_SEV_LOW);
        ASSERT_STR_EQ(f[1].path, "docs/x.md");
        ASSERT_EQ(f[1].line, 7);
        ASSERT_EQ(f[1].text_len, 0);
        PASS();
    }
    TEST("F2: NO FINDINGS alone sets the flag and yields no finding") {
        r = ef_run("Looks fine.\nNO FINDINGS\n", f, 4);
        ASSERT(r.no_findings);
        ASSERT_EQ(r.findings, 0);
        ASSERT_EQ(r.illformed, 0);
        r = ef_run("a NO FINDINGS here\nNO FINDINGS.\n no findings\n", f, 4);
        ASSERT(!r.no_findings);
        PASS();
    }
_test_next:;
    return failures;
}

/* F3: each ill-formed variant is counted, never a finding. */
static int ef_illformed(void)
{
    int failures = 0;
    static const char *const bad[] = {
        "FINDING CHANGES high a.c:1 x", "FINDING change high a.c:1 x",
        "FINDING CHANGE urgent a.c:1 x", "FINDING CHANGE High a.c:1 x",
        "FINDING CHANGE high a.c 1 x", "FINDING CHANGE high a.c:0 x",
        "FINDING CHANGE high a.c:-3 x", "FINDING CHANGE high a.c:1x x",
        "FINDING CHANGE high a.c:+1 x", "FINDING CHANGE high a.c: x",
        "FINDING CHANGE high a.c:99999999999999999999 x",
        "FINDING CHANGE high a.c:1000000001 x", "FINDING CHANGE high :5 x",
        "FINDING CHANGE high a:b.c:5 x", "FINDING  CHANGE high a.c:1 x",
        "FINDING CHANGE  high a.c:1 x", "FINDING CHANGE high", "FINDING CHANGE",
        "FINDING CHANGE high ", "FINDING ", "FINDING CHANGE high a.c:1\t",
    };
    struct efd_finding f[2];
    char longp[ERS_FILE_MAX + 32];
    TEST("F3: every ill-formed variant is counted and is not a finding") {
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            struct efd_result r = ef_run(bad[i], f, 2);
            if (r.findings != 0 || r.illformed != 1)
                printf("[row %zu: %s] ", i, bad[i]);
            ASSERT_EQ(r.findings, 0);
            ASSERT_EQ(r.illformed, 1);
        }
        PASS();
    }
    TEST("F3: a path of ERS_FILE_MAX bytes is ill-formed, one byte less is not") {
        char p[ERS_FILE_MAX + 1];
        memset(p, 'p', ERS_FILE_MAX);
        p[ERS_FILE_MAX] = '\0';
        (void)snprintf(longp, sizeof(longp), "FINDING CLAIM low %s:3 t", p);
        struct efd_result r = ef_run(longp, f, 2);
        ASSERT_EQ(r.findings, 0);
        ASSERT_EQ(r.illformed, 1);
        (void)snprintf(longp, sizeof(longp), "FINDING CLAIM low %s:3 t", p + 1);
        r = ef_run(longp, f, 2);
        ASSERT_EQ(r.findings, 1);
        ASSERT_EQ(strlen(f[0].path), ERS_FILE_MAX - 1);
        r = ef_run("FINDING CHANGE low a.c:1000000000 t", f, 2);
        ASSERT_EQ(r.findings, 1);
        ASSERT_EQ(f[0].line, 1000000000);
        PASS();
    }
_test_next:;
    return failures;
}

/* F4, F5 */
static int ef_layout(void)
{
    int failures = 0;
    struct efd_finding f[4];
    struct efd_result r;
    TEST("F4: a FINDING not at column 0 or not followed by a space is ignored") {
        r = ef_run("  FINDING CHANGE high a.c:1 x\n"
                   "see FINDING CHANGE high a.c:1 x\n"
                   "\tFINDING CLAIM low a.c:2 y\n"
                   "FINDING\nFINDINGS CHANGE high a.c:1 x\n", f, 4);
        ASSERT_EQ(r.findings, 0);
        ASSERT_EQ(r.illformed, 0);
        PASS();
    }
    TEST("F5: CRLF line ends and a last line without a newline") {
        r = ef_run("FINDING CHANGE high a.c:1 x\r\n"
                   "FINDING CLAIM low b.c:2 y\r\nNO FINDINGS\r\n"
                   "FINDING CHANGE low c.c:3 tail", f, 4);
        ASSERT_EQ(r.findings, 3);
        ASSERT_EQ(r.illformed, 0);
        ASSERT(r.no_findings);
        ASSERT(ef_text_is(&f[0], "x"));
        ASSERT(ef_text_is(&f[2], "tail"));
        ASSERT_STR_EQ(f[2].path, "c.c");
        PASS();
    }
_test_next:;
    return failures;
}

/* F6, F7, F8 */
static int ef_bounds(void)
{
    int failures = 0;
    struct efd_finding f[4];
    struct efd_result r;
    static const char two[] = "FINDING CHANGE high a.c:12\nFINDING CLAIM low b.c:2 z\n";
    static const char one[] = "FINDING CHANGE high a.c:1\nFINDING CLAIM low b.c:2 z\n";
    TEST("F6: nothing at or past len is read") {
        efd_parse(two, 25, f, 4, &r); /* cut inside the digits: line 1, not 12 */
        ASSERT_EQ(r.findings, 1);
        ASSERT_EQ(f[0].line, 1);
        ASSERT_EQ(f[0].text_len, 0);
        efd_parse(one, 25, f, 4, &r); /* cut at the newline: the next line is unseen */
        ASSERT_EQ(r.findings, 1);
        ASSERT_EQ(r.illformed, 0);
        efd_parse(one, 1, f, 4, &r);
        ASSERT_EQ(r.findings, 0);
        ASSERT_EQ(r.illformed, 0);
        PASS();
    }
    TEST("F7: more findings than capacity set truncated, the count stays exact") {
        const char *t = "FINDING CHANGE high a.c:1 a\nFINDING CHANGE high a.c:2 b\n"
                        "FINDING CLAIM low a.c:3 c\n";
        r = ef_run(t, f, 2);
        ASSERT_EQ(r.findings, 3);
        ASSERT(r.truncated);
        ASSERT_EQ(f[1].line, 2);
        r = ef_run(t, f, 3);
        ASSERT(!r.truncated);
        r = ef_run(t, NULL, 0);
        ASSERT_EQ(r.findings, 3);
        ASSERT(r.truncated);
        PASS();
    }
    TEST("F8: empty and NULL text") {
        memset(&r, 0xff, sizeof(r));
        efd_parse(NULL, 0, NULL, 0, &r);
        ASSERT(r.findings == 0 && r.illformed == 0);
        ASSERT(!r.no_findings && !r.truncated);
        r = ef_run("", f, 4);
        ASSERT(r.findings == 0 && r.illformed == 0 && !r.no_findings);
        PASS();
    }
_test_next:;
    return failures;
}

/* ── the scorer's second input form: a raw reply ────────────────────── */

#define RS_REPLY(id, text) \
    "{\"case\":\"" id "\",\"reviewer\":\"r1\",\"reply\":\"" text "\"}\n"

static int rs_reply_defect(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("S1: a defect reviewed by a reply whose FINDING line hits is caught") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_DEFECT("d1", "code", "k"),
                        RS_REPLY("d1", "Review.\\nFINDING CHANGE high a.c:12 off by one\\n1. MET")));
        ASSERT(rs_ok(&c));
        ASSERT_EQ(rs_int(&c, "defect_reviews"), 1);
        ASSERT_EQ(rs_int(&c, "defect_accepted"), 0);
        ASSERT_EQ(rs_int(&c, "findings_total"), 1);
        ASSERT_EQ(rs_int(&c, "reviews_unparsed"), 0);
        PASS();
    }
    TEST("S4: an ill-formed FINDING line is unparsed, not scored as a miss") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_DEFECT("d1", "code", "k"),
                        RS_REPLY("d1", "FINDING CHANGE urgent a.c:12 off by one")));
        ASSERT(rs_ok(&c));
        ASSERT_EQ(rs_int(&c, "reviews_unparsed"), 1);
        ASSERT_EQ(rs_int(&c, "findings_illformed"), 1);
        ASSERT_EQ(rs_int(&c, "defect_reviews"), 0);
        ASSERT_EQ(rs_int(&c, "defect_accepted"), 0);
        PASS();
    }
    TEST("S6: a JSON-escaped multi-line CRLF reply parses its lines") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_DEFECT("d1", "code", "k"),
                        RS_REPLY("d1", "intro\\r\\nFINDING CLAIM low a.c:300 no\\r\\nFINDING CHANGE medium a.c:11 hit\\r\\n")));
        ASSERT(rs_ok(&c));
        ASSERT_EQ(rs_int(&c, "findings_total"), 2);
        ASSERT_EQ(rs_int(&c, "defect_accepted"), 0);
        ASSERT_EQ(rs_int(&c, "reviews_unparsed"), 0);
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

static int rs_reply_sound(const char *root)
{
    int failures = 0;
    struct rs_call c;
    rs_begin(&c);
    TEST("S2: a sound case with reply NO FINDINGS is reviewed and not rejected") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_SOUND("s1"), RS_REPLY("s1", "All good.\\nNO FINDINGS")));
        ASSERT(rs_ok(&c));
        ASSERT_EQ(rs_int(&c, "sound_reviews"), 1);
        ASSERT_EQ(rs_int(&c, "sound_rejected"), 0);
        ASSERT_EQ(rs_int(&c, "reviews_unparsed"), 0);
        PASS();
    }
    TEST("S3: a prose-only reply is unparsed and the sound tally is unchanged") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_SOUND("s1") RS_SOUND("s2"),
                        RS_REPLY("s1", "NO FINDINGS")
                        RS_REPLY("s2", "Looks fine to me, nothing to add.")));
        ASSERT(rs_ok(&c));
        ASSERT_EQ(rs_int(&c, "sound_reviews"), 1);
        ASSERT_EQ(rs_int(&c, "reviews_unparsed"), 1);
        ASSERT_EQ(rs_int(&c, "findings_illformed"), 0);
        PASS();
    }
    TEST("S5: a review line with both findings and reply is malformed") {
        rs_end(&c);
        ASSERT(rs_score(&c, root, RS_SOUND("s1"),
                        "{\"case\":\"s1\",\"findings\":[],\"reply\":\"NO FINDINGS\"}\n"));
        ASSERT(rs_ok(&c));
        ASSERT_EQ(rs_int(&c, "reviews_malformed_lines"), 1);
        ASSERT_EQ(rs_int(&c, "sound_reviews"), 0);
        PASS();
    }
_test_next:;
    rs_end(&c);
    return failures;
}

/* ── T15: the pure rule, no command ─────────────────────────────────── */

static int rs_pure(void)
{
    int failures = 0;
    static const struct ers_range range = {"a.c", 10, 20};
    struct ers_case defect = {.id = "d", .cls = "k", .label = ERS_LABEL_DEFECT,
                              .locus = ERS_LOCUS_CODE, .tolerance = 2,
                              .ranges = &range, .nranges = 1};
    struct ers_case sound = {.id = "s", .label = ERS_LABEL_SOUND};
    struct ers_finding edge = {ERS_KIND_CHANGE, "a.c", 22};
    struct ers_finding past = {ERS_KIND_CHANGE, "a.c", 23};
    struct ers_finding bad[] = {
        {ERS_KIND_CHANGE, NULL, 5}, {ERS_KIND_CHANGE, "", 5},
        {ERS_KIND_CHANGE, "a.c", 0}, {ERS_KIND_INVALID, "a.c", 5},
    };
    struct ers_result r;
    TEST("pure rule: boundary, discards and sound rejection") {
        ers_score_review(&defect, &edge, 1, &r);
        ASSERT(r.caught && !r.accepted);
        ers_score_review(&defect, &past, 1, &r);
        ASSERT(!r.caught && r.accepted);
        ers_score_review(&sound, bad, 4, &r);
        ASSERT_EQ(r.discarded, 4);
        ASSERT(!r.rejected);
        ers_score_review(&sound, &edge, 1, &r);
        ASSERT(r.rejected && r.rejected_change && !r.rejected_claim);
        ers_score_review(&defect, NULL, 0, &r);
        ASSERT(r.accepted);
        PASS();
    }
_test_next:;
    return failures;
}

int test_devagent_reviewscore(void);
int test_devagent_reviewscore(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "devagent_reviewscore", "fx");
    failures += rs_sound(root);
    failures += rs_boundary(root);
    failures += rs_kind_file(root);
    failures += rs_unreviewed(root);
    failures += rs_refusals(root);
    failures += rs_malformed(root);
    failures += rs_classes(root);
    failures += rs_enough(root);
    failures += rs_rates(root);
    failures += rs_tolerance(root);
    failures += rs_ranges(root);
    failures += rs_findings(root);
    failures += rs_set_refusals(root);
    failures += rs_set_limit(root);
    failures += rs_dup_defect(root);
    failures += rs_base_rules(root);
    failures += rs_independence(root);
    failures += rs_ready(root);
    failures += rs_independence_bounds(root);
    failures += rs_pure();
    failures += ef_basic();
    failures += ef_illformed();
    failures += ef_layout();
    failures += ef_bounds();
    failures += rs_reply_defect(root);
    failures += rs_reply_sound(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0) printf("test_devagent_reviewscore: all passed\n");
    else printf("test_devagent_reviewscore: %d FAILED\n", failures);
    return failures;
}
