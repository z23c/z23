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
#include "engine/engine_review_score.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    failures += rs_pure();
    (void)test_rm_rf_recursive(root);
    if (failures == 0) printf("test_devagent_reviewscore: all passed\n");
    else printf("test_devagent_reviewscore: %d FAILED\n", failures);
    return failures;
}
