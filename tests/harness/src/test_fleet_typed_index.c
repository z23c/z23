/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exercise typed observation index ordering, ownership and refusal. */
#include "test/test_core.h"
#include "command/native_fleet_typed_index.h"
#include "json/json.h"
#include "base/safe_alloc.h"
#include <stdio.h>
#include <string.h>

struct typed_seen { int count; int64_t offset[8]; bool accept_good; };
static bool typed_visit(const struct json_value *row, void *opaque)
{
    struct typed_seen *s = opaque;
    if (s->count < 8) s->offset[s->count] = json_get_int(json_get(row, "row_offset"));
    s->count++;
    return s->accept_good && !strcmp(json_get_str(json_get(row, "sender_binding")), "good");
}
static bool typed_read(struct json_value *v, const char *text)
{
    json_init(v);
    return json_read(v, text, strlen(text));
}
static int typed_case_owned(void)
{
    int failures = 0;
    TEST("typed index owns rows, orders candidates and preserves caller filtering") {
        const char *text = "[{\"seq\":1,\"kind\":\"result\",\"stream\":\"outbox.jsonl\",\"from\":\"b\",\"to\":\"a\",\"ref\":\"r\",\"observed_stream\":\"inbox.b.jsonl\",\"observed_sha3\":\"hash\",\"observed_offset\":4,\"observed_seq\":9,\"observed_disposition\":\"READ\",\"sender_binding\":\"good\",\"row_offset\":5},"
            "{\"seq\":2,\"kind\":\"result\",\"stream\":\"outbox.jsonl\",\"from\":\"b\",\"to\":\"a\",\"ref\":\"r\",\"observed_stream\":\"inbox.b.jsonl\",\"observed_sha3\":\"hash\",\"observed_offset\":4,\"observed_seq\":9,\"observed_disposition\":\"READ\",\"sender_binding\":\"bad\",\"row_offset\":8}]";
        const char *dtext = "{\"seq\":9,\"kind\":\"directive\",\"stream\":\"inbox.b.jsonl\",\"row_sha3\":\"hash\",\"row_offset\":4,\"from\":\"a\",\"to\":\"b\",\"ref\":\"r\"}";
        struct json_value rows, d;
        ASSERT(typed_read(&rows, text)); ASSERT(typed_read(&d, dtext));
        struct zcl_fleet_typed_index full, incremental;
        zcl_fleet_typed_index_init(&full, 4, 8192);
        zcl_fleet_typed_index_init(&incremental, 4, 8192);
        ASSERT(zcl_fleet_typed_index_build(&full, &rows));
        ASSERT(zcl_fleet_typed_index_append(&incremental, json_at(&rows, 0)));
        ASSERT(zcl_fleet_typed_index_append(&incremental, json_at(&rows, 1)));
        struct typed_seen initial = {.accept_good = true};
        ASSERT(zcl_fleet_typed_index_visit(&incremental, &d, typed_visit, &initial));
        ASSERT_EQ(initial.count, 2);
        ASSERT_EQ(initial.offset[0], 8); ASSERT_EQ(initial.offset[1], 5);
        struct zcl_fleet_typed_locator key = {"a", "b", "r", "inbox.b.jsonl", "hash", 4, 9, "directive"};
        struct typed_seen direct = {.accept_good = true};
        ASSERT(zcl_fleet_typed_index_visit_key(&incremental, &key, typed_visit, &direct));
        ASSERT_EQ(direct.count, initial.count);
        ASSERT_EQ(direct.offset[0], initial.offset[0]); ASSERT_EQ(direct.offset[1], initial.offset[1]);
        struct json_value tie;
        ASSERT(typed_read(&tie, "{\"seq\":3,\"kind\":\"result\",\"stream\":\"outbox.jsonl\",\"from\":\"b\",\"to\":\"a\",\"ref\":\"r\",\"observed_stream\":\"inbox.b.jsonl\",\"observed_sha3\":\"hash\",\"observed_offset\":4,\"observed_seq\":9,\"observed_disposition\":\"READ\",\"sender_binding\":\"good\",\"row_offset\":8}"));
        ASSERT(zcl_fleet_typed_index_append(&full, &tie));
        ASSERT(zcl_fleet_typed_index_append(&incremental, &tie));
        json_free(&tie);
        json_free(&rows);
        struct typed_seen a = {.accept_good = true}, b = {.accept_good = true};
        ASSERT(zcl_fleet_typed_index_visit(&full, &d, typed_visit, &a));
        ASSERT(zcl_fleet_typed_index_visit(&incremental, &d, typed_visit, &b));
        ASSERT_EQ(a.count, 2); ASSERT_EQ(a.offset[0], 8); ASSERT_EQ(a.offset[1], 8);
        ASSERT_EQ(b.count, a.count); ASSERT_EQ(b.offset[0], a.offset[0]); ASSERT_EQ(b.offset[1], a.offset[1]);
        direct = (struct typed_seen){.accept_good = true};
        ASSERT(zcl_fleet_typed_index_visit_key(&full, &key, typed_visit, &direct));
        ASSERT_EQ(direct.count, a.count); ASSERT_EQ(direct.offset[0], a.offset[0]);
        ASSERT_EQ(direct.offset[1], a.offset[1]);
        /* A caller's authorization decision is re-evaluated on every visit. */
        struct typed_seen revoked = {.accept_good = false};
        ASSERT(zcl_fleet_typed_index_visit_key(&full, &key, typed_visit, &revoked));
        ASSERT_EQ(revoked.count, 3);
        struct typed_seen restored = {.accept_good = true};
        ASSERT(zcl_fleet_typed_index_visit_key(&full, &key, typed_visit, &restored));
        ASSERT_EQ(restored.count, 2);
        json_free(&d);
        ASSERT(typed_read(&d, "{\"kind\":\"directive\"}"));
        ASSERT(!zcl_fleet_typed_index_visit(&full, &d, typed_visit, &a));
        json_free(&d); zcl_fleet_typed_index_free(&full); zcl_fleet_typed_index_free(&incremental);
        PASS();
    } _test_next:;
    return failures;
}
static int typed_case_capacity(void)
{
    int failures = 0;
    TEST("typed index capacity failure poisons lookup") {
        struct json_value row, d;
        ASSERT(typed_read(&row, "{\"seq\":1,\"kind\":\"result\",\"stream\":\"outbox.jsonl\",\"observed_disposition\":\"READ\",\"sender_binding\":\"x\",\"row_offset\":0}"));
        ASSERT(typed_read(&d, "{\"seq\":1,\"kind\":\"directive\"}"));
        struct zcl_fleet_typed_index ix; zcl_fleet_typed_index_init(&ix, 0, 0);
        ASSERT(!zcl_fleet_typed_index_append(&ix, &row));
        struct typed_seen s = {0}; ASSERT(!zcl_fleet_typed_index_visit(&ix, &d, typed_visit, &s));
        zcl_fleet_typed_index_free(&ix);
        zcl_fleet_typed_index_init(&ix, 4, 1);
        ASSERT(!zcl_fleet_typed_index_append(&ix, &row));
        ASSERT(!zcl_fleet_typed_index_visit(&ix, &d, typed_visit, &s));
        zcl_fleet_typed_index_free(&ix);
        zcl_fleet_typed_index_init(&ix, 1, 8192);
        ASSERT(zcl_fleet_typed_index_append(&ix, &row));
        size_t exact = ix.bytes;
        zcl_fleet_typed_index_free(&ix);
        zcl_fleet_typed_index_init(&ix, 4, exact);
        ASSERT(zcl_fleet_typed_index_append(&ix, &row));
        ASSERT(!zcl_fleet_typed_index_append(&ix, &row));
        zcl_fleet_typed_index_free(&ix);
        zcl_fleet_typed_index_init(&ix, 4, 8192);
        ASSERT(!zcl_fleet_typed_index_append(&ix, NULL));
        ASSERT(!zcl_fleet_typed_index_visit(&ix, &d, typed_visit, &s));
        struct zcl_fleet_typed_locator key = {"", "", "", "", "", -1, 1, "directive"};
        ASSERT(!zcl_fleet_typed_index_visit_key(&ix, &key, typed_visit, &s));
        zcl_fleet_typed_index_free(&ix); json_free(&row); json_free(&d);
        PASS();
    } _test_next:;
    return failures;
}
static int typed_case_mismatch(void)
{
    int failures = 0;
    TEST("typed index exact keys and candidate refusal") {
        struct json_value rows, d;
        ASSERT(typed_read(&rows, "[{\"seq\":1,\"kind\":\"result\",\"stream\":\"outbox.jsonl\",\"from\":\"b\",\"to\":\"a\",\"ref\":\"\",\"observed_stream\":\"s\",\"observed_sha3\":\"h\",\"observed_offset\":4,\"observed_seq\":9,\"observed_disposition\":\"READ\",\"sender_binding\":\"good\",\"row_offset\":5},"
            "{\"seq\":2,\"kind\":\"result\",\"stream\":\"other\",\"observed_disposition\":\"READ\",\"sender_binding\":\"good\",\"row_offset\":8},"
            "{\"seq\":3,\"kind\":\"result\",\"stream\":\"outbox.jsonl\",\"observed_disposition\":\"UNVERIFIED\",\"sender_binding\":\"good\",\"row_offset\":8},{}]"));
        struct zcl_fleet_typed_index ix; zcl_fleet_typed_index_init(&ix, 8, 16384);
        ASSERT(zcl_fleet_typed_index_build(&ix, &rows)); ASSERT_EQ(ix.count, 1);
        const char *from[] = {"a", "x", "a", "a", "a", "a", "a", "a"};
        const char *to[] = {"b", "b", "x", "b", "b", "b", "b", "b"};
        const char *ref[] = {"", "", "", "x", "", "", "", ""};
        const char *stream[] = {"s", "s", "s", "s", "x", "s", "s", "s"};
        const char *hash[] = {"h", "h", "h", "h", "h", "x", "h", "h"};
        for (size_t i = 0; i < 8; ++i) {
            char buf[512];
            (void)snprintf(buf, sizeof buf, "{\"seq\":%d,\"kind\":\"directive\",\"from\":\"%s\",\"to\":\"%s\",\"ref\":\"%s\",\"stream\":\"%s\",\"row_sha3\":\"%s\",\"row_offset\":%d}", i == 7 ? 10 : 9, from[i], to[i], ref[i], stream[i], hash[i], i == 6 ? 7 : 4);
            ASSERT(typed_read(&d, buf)); struct typed_seen s = {0};
            ASSERT(zcl_fleet_typed_index_visit(&ix, &d, typed_visit, &s));
            ASSERT_EQ(s.count, i == 0 ? 1 : 0);
            struct zcl_fleet_typed_locator key = {from[i], to[i], ref[i], stream[i], hash[i],
                                                  i == 6 ? 7 : 4, i == 7 ? 10 : 9, "directive"};
            struct typed_seen direct = {0};
            ASSERT(zcl_fleet_typed_index_visit_key(&ix, &key, typed_visit, &direct));
            ASSERT_EQ(direct.count, s.count); json_free(&d);
        }
        struct zcl_fleet_typed_locator bad = {NULL, "b", "", "s", "h", 4, 9, "directive"};
        struct typed_seen unused = {0};
        ASSERT(!zcl_fleet_typed_index_visit_key(&ix, &bad, typed_visit, &unused));
        bad = (struct zcl_fleet_typed_locator){"a", NULL, "", "s", "h", 4, 9, "directive"};
        ASSERT(!zcl_fleet_typed_index_visit_key(&ix, &bad, typed_visit, &unused));
        bad = (struct zcl_fleet_typed_locator){"a", "b", NULL, "s", "h", 4, 9, "directive"};
        ASSERT(!zcl_fleet_typed_index_visit_key(&ix, &bad, typed_visit, &unused));
        bad = (struct zcl_fleet_typed_locator){"a", "b", "", NULL, "h", 4, 9, "directive"};
        ASSERT(!zcl_fleet_typed_index_visit_key(&ix, &bad, typed_visit, &unused));
        bad = (struct zcl_fleet_typed_locator){"a", "b", "", "s", NULL, 4, 9, "directive"};
        ASSERT(!zcl_fleet_typed_index_visit_key(&ix, &bad, typed_visit, &unused));
        bad = (struct zcl_fleet_typed_locator){NULL, NULL, NULL, NULL, NULL, -1, -1, "result"};
        ASSERT(zcl_fleet_typed_index_visit_key(&ix, &bad, typed_visit, &unused));
        ASSERT_EQ(unused.count, 0);
        bad.kind = NULL;
        ASSERT(!zcl_fleet_typed_index_visit_key(&ix, &bad, typed_visit, &unused));
        zcl_fleet_typed_index_free(&ix); json_free(&rows); PASS();
    } _test_next:;
    return failures;
}
static int typed_case_alloc(void)
{
    int failures = 0;
    TEST("typed index copy allocation failure poisons lookup") {
        struct json_value row, d;
        ASSERT(typed_read(&row, "{\"seq\":1,\"kind\":\"result\",\"stream\":\"outbox.jsonl\",\"observed_disposition\":\"READ\",\"sender_binding\":\"x\",\"row_offset\":0}"));
        ASSERT(typed_read(&d, "{\"seq\":1,\"kind\":\"directive\"}"));
        struct zcl_fleet_typed_index ix; zcl_fleet_typed_index_init(&ix, 4, 8192);
        zcl_alloc_fault_fail_next("json_copy_children");
        bool appended = zcl_fleet_typed_index_append(&ix, &row);
        zcl_alloc_fault_clear(); ASSERT(!appended);
        struct typed_seen s = {0}; ASSERT(!zcl_fleet_typed_index_visit(&ix, &d, typed_visit, &s));
        zcl_fleet_typed_index_free(&ix); json_free(&row); json_free(&d); PASS();
    } _test_next:;
    return failures;
}
int test_fleet_typed_index(void)
{
    int failures = typed_case_owned();
    failures += typed_case_capacity();
    failures += typed_case_mismatch();
    failures += typed_case_alloc();
    return failures;
}
