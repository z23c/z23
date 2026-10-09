/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "test/test_core.h"
#include "base/safe_alloc.h"
#include "json/json.h"

#include <string.h>
int cgo_decoder_tests(void);
int cgo_passive_tests(void);
int cga_goal_tests(void);

static bool json_append_read(int fd, char text[256])
{
    if (lseek(fd, 0, SEEK_SET) < 0) return false;
    ssize_t n = read(fd, text, 255);
    if (n < 0 || n == 255) return false;
    text[n] = '\0';
    return true;
}

static bool json_append_capture(struct json_value *target,
                                const struct json_value *child, bool keyed,
                                bool *pushed, char text[256])
{
    char path[PATH_MAX];
    int fd = test_mkstemp(path, sizeof(path), "json_append");
    if (fd < 0) return false;
    bool ok = fflush(stderr) == 0;
    int saved = dup(STDERR_FILENO);
    if (saved < 0) ok = false;
    if (ok && dup2(fd, STDERR_FILENO) >= 0) {
        *pushed = keyed ? json_push_kv(target, "k", child)
                       : json_push_back(target, child);
        ok = fflush(stderr) == 0;
        if (dup2(saved, STDERR_FILENO) < 0) abort();
        if (!json_append_read(fd, text)) ok = false;
    } else ok = false;
    if (saved >= 0 && close(saved) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (unlink(path) != 0) ok = false;
    return ok;
}

static bool json_append_scalar_unchanged(const struct json_value *target)
{
    return target->type == JSON_INT && target->val.i == 7 &&
        target->children == NULL && target->keys == NULL &&
        target->num_children == 0 && target->children_cap == 0;
}

static bool json_append_target_case(bool keyed)
{
    struct json_value target, child;
    json_init(&target); json_set_int(&target, 7);
    json_init(&child); json_set_int(&child, 9);
    char text[256] = {0}, type[32];
    snprintf(type, sizeof(type), "target type=%d", (int)JSON_INT);
    bool pushed = true;
    bool captured = json_append_capture(&target, &child, keyed, &pushed, text);
    bool unchanged = json_append_scalar_unchanged(&target);
    bool message = strstr(text, keyed ? "json_push_kv:" : "json_push_back:") &&
        strstr(text, type) &&
        strstr(text, keyed ? "json_set_object" : "json_set_array");
    bool refused = captured && !pushed && unchanged && message;
    if (keyed) json_set_object(&target); else json_set_array(&target);
    text[0] = '\0'; pushed = false;
    captured = json_append_capture(&target, &child, keyed, &pushed, text);
    const struct json_value *stored = keyed ? json_get(&target, "k")
                                          : json_at(&target, 0);
    bool accepted = captured && pushed && text[0] == '\0' &&
        json_size(&target) == 1 && json_get_int(stored) == 9;
    json_free(&target); json_free(&child);
    return refused && accepted;
}

static int json_append_target_cases(void)
{
    int failures = 0;
    printf("json array append identifies scalar target and recovery, succeeds quietly... ");
    if (json_append_target_case(false)) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    printf("json object append identifies scalar target and recovery, succeeds quietly... ");
    if (json_append_target_case(true)) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int json_heap_accounting_cases(void)
{
    int failures = 0;
    struct json_value value, copy;
    size_t before = json_test_live_blocks();
    TEST("json heap accounting: owned strings, copied trees and existing resize blocks balance") {
        const char *object = "{\"k\":\"v\"}";
        ASSERT(json_read(&value, object, strlen(object)));
        ASSERT_EQ(json_test_live_blocks(), before + 4);
        json_copy(&copy, &value);
        ASSERT_EQ(json_test_live_blocks(), before + 8);
        json_free(&copy); json_free(&value);
        ASSERT_EQ(json_test_live_blocks(), before);
        const char *array = "[0,1,2,3,4,5,6,7,8]";
        ASSERT(json_read(&value, array, strlen(array)));
        ASSERT_EQ(json_test_live_blocks(), before + 2);
        json_free(&value);
        ASSERT_EQ(json_test_live_blocks(), before);
        json_init(&value); json_free(&value);
        ASSERT_EQ(json_test_live_blocks(), before);
        PASS();
    }
_test_next:;
    return failures;
}

static bool json_growth_refusal_case(size_t cap, size_t count)
{
    struct json_value arr, child;
    json_init(&arr); json_set_array(&arr);
    json_init(&child); json_set_int(&child, 7);
    arr.children_cap = cap;
    arr.num_children = count;
    zcl_alloc_fault_fail_next("json_children");
    bool refused = !json_push_back(&arr, &child);
    const char *armed = zcl_alloc_fault_armed_label();
    bool unchanged = arr.type == JSON_ARR && arr.children == NULL &&
        arr.keys == NULL && arr.children_cap == cap && arr.num_children == count;
    bool retained = armed != NULL && strcmp(armed, "json_children") == 0;
    zcl_alloc_fault_clear();
    /* Forged metadata has no backing storage; restore before lifecycle cleanup. */
    arr.num_children = 0; arr.children_cap = 0;
    json_free(&arr); json_free(&child);
    return refused && unchanged && retained;
}

static bool json_growth_normal_case(void)
{
    struct json_value arr, obj, child;
    json_init(&arr); json_set_array(&arr);
    json_init(&obj); json_set_object(&obj);
    json_init(&child);
    bool ok = json_size(&arr) == 0;
    for (int i = 0; i < 10; i++) {
        json_set_int(&child, i);
        bool pushed = json_push_back(&arr, &child);
        ok = pushed && ok;
        ok = json_get_int(json_at(&arr, (size_t)i)) == i && ok;
    }
    bool keyed = json_push_kv(&obj, "last", &child);
    ok = keyed && ok && json_size(&arr) == 10 && json_size(&obj) == 1 &&
        json_get_int(json_get(&obj, "last")) == 9;
    json_free(&arr); json_free(&obj); json_free(&child);
    return ok;
}

static int json_growth_cases(void)
{
    int failures = 0;
    printf("json growth refuses doubling overflow before allocation... ");
    if (json_growth_refusal_case(SIZE_MAX / 2 + 2, SIZE_MAX / 2 + 2))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    printf("json growth refuses children byte overflow before allocation... ");
    size_t cap = (SIZE_MAX / sizeof(struct json_value)) / 2 + 1;
    if (json_growth_refusal_case(cap, cap)) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    printf("json growth refuses keys byte overflow before allocation... ");
    /* Step past the first overflowing key capacity so the restored growth
     * also requests positive child bytes and consumes its injected refusal. */
    cap = (SIZE_MAX / sizeof(char *)) / 2 + 2;
    if (json_growth_refusal_case(cap, cap)) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    printf("json growth refuses metadata with no next append slot... ");
    if (json_growth_refusal_case(8, 16)) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    printf("json growth preserves empty, ten-element and keyed appends... ");
    if (json_growth_normal_case()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static bool json_valid_matches_read(void)
{
    /* A caller tells malformed input from exhausted memory by asking
     * json_valid first, so the two must never disagree about a byte
     * string, including malformed numbers, malformed Unicode escapes,
     * the 64-byte number it refuses, and the depth
     * limit on both sides of the line. */
    static const char *const corpus[] = {
        "42", "-", "-7", "1.", "1e", "1.5e+3", "\"\\uZZZZ\"",
        "\"a\\qb\"", "\"open", "{\"a\":1,}", "{\"a\" 1}", "[1,2]", "[1 2]",
        "{}", " { \"k\" : [ true , false , null ] } ", "nul", "tru",
        "\"\\\"\"", "{\"a\":\"b\"} x", "[", "]", "",
        "1234567890123456789012345678901234567890123456789012345678901234",
        "123456789012345678901234567890123456789012345678901234567890123",
    };
    char deep[600];
    bool ok = true;
    size_t i, d;
    for (i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++) {
        struct json_value v;
        bool r = json_read(&v, corpus[i], strlen(corpus[i]));
        json_free(&v);
        if (r != json_valid(corpus[i], strlen(corpus[i]))) {
            printf("[disagree on '%s'] ", corpus[i]);
            ok = false;
        }
    }
    for (d = 255; d <= 258; d++) {
        struct json_value v;
        bool r;
        memset(deep, '[', d);
        memset(deep + d, ']', d);
        r = json_read(&v, deep, 2 * d);
        json_free(&v);
        ok = ok && r == (d <= 256) && json_valid(deep, 2 * d) == r;
    }
    ok = ok && !json_valid(NULL, 0);
    /* No allocation at all: armed failures are still armed after a walk
     * over strings, keys and containers. */
    zcl_alloc_fault_fail_next("json_string");
    ok = ok && json_valid("{\"a\":[\"x\",{\"b\":\"y\"}]}", 21);
    ok = ok && zcl_alloc_fault_armed_label() != NULL &&
         strcmp(zcl_alloc_fault_armed_label(), "json_string") == 0;
    zcl_alloc_fault_fail_next("json_children");
    ok = ok && json_valid("[[1],[2]]", 9);
    ok = ok && zcl_alloc_fault_armed_label() != NULL &&
         strcmp(zcl_alloc_fault_armed_label(), "json_children") == 0;
    zcl_alloc_fault_clear();
    return ok;
}

/* The json_valid case, printed like its neighbours: 0 when it holds. */
static int json_valid_case(void)
{
    if (json_valid_matches_read()) { printf("OK\n"); return 0; }
    printf("FAIL\n");
    return 1;
}

static bool json_unicode_keys_case(void)
{
    const char *wire = "{\"publication_hold\":true,\"\\u0070ublication_hold\":false}";
    struct json_value v;
    json_init(&v);
    bool ok = json_read(&v, wire, strlen(wire));
    ok = ok && v.type == JSON_OBJ && v.num_children == 2;
    if (ok) {
        ok = strcmp(v.keys[0], "publication_hold") == 0;
        ok = ok && strcmp(v.keys[1], v.keys[0]) == 0;
        ok = ok && json_get_bool(&v.children[0]);
        ok = ok && !json_get_bool(&v.children[1]);
    }
    json_free(&v);
    return ok;
}

static bool json_unicode_strings_case(void)
{
    const char *wire[] = {"\"abc\\u0041def\"", "\"\\u00e9\"",
        "\"\\uD83D\\uDE00\"", "\"\\uDBFF\\uDFFF\"", "\"\\uFFFF\""};
    const char *expected[] = {"abcAdef", "\xc3\xa9", "\xf0\x9f\x98\x80",
        "\xf4\x8f\xbf\xbf", "\xef\xbf\xbf"};
    bool ok = true;
    for (size_t i = 0; i < sizeof(wire) / sizeof(wire[0]); i++) {
        struct json_value v;
        json_init(&v);
        bool parsed = json_read(&v, wire[i], strlen(wire[i]));
        ok = parsed && ok;
        if (parsed) ok = strcmp(json_get_str(&v), expected[i]) == 0 && ok;
        ok = json_valid(wire[i], strlen(wire[i])) && ok;
        json_free(&v);
    }
    return ok;
}

static bool json_unicode_invalid_case(void)
{
    /* This C-string API cannot represent embedded NUL without losing identity. */
    const char *bad[] = {"\"\\u\"", "\"\\u0\"", "\"\\u00\"", "\"\\u000\"",
        "\"\\uZZZZ\"", "\"\\uD800\"", "\"\\uDC00\"", "\"\\uD800x\"",
        "\"\\uD800\\u0041\"", "\"\\uD800\\uD800\"", "\"\\uD800\\uDC0\"",
        "\"a\\u0000b\"", "{\"publication_hold\\u0000alias\":true}"};
    bool ok = true;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        struct json_value v;
        json_init(&v);
        bool parsed = json_read(&v, bad[i], strlen(bad[i]));
        ok = !parsed && ok;
        ok = (v.type == JSON_NULL) && ok;
        ok = !json_valid(bad[i], strlen(bad[i])) && ok;
        json_free(&v);
    }
    return ok;
}

static int json_unicode_cases(void)
{
    int failures = 0;

    printf("json escaped key equals literal key without collapsing duplicates... ");
    if (json_unicode_keys_case()) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    printf("json Unicode scalar and surrogate-pair UTF8 decoding... ");
    if (json_unicode_strings_case()) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    printf("json malformed truncated surrogate and NUL escapes refuse and clear... ");
    if (json_unicode_invalid_case()) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    return failures;
}

static bool json_number_valid_case(void)
{
    static const struct {
        const char *wire;
        enum json_type type;
        int64_t integer;
        double real;
    } cases[] = {
        {"0", JSON_INT, 0, 0}, {"-0", JSON_INT, 0, 0},
        {"-7", JSON_INT, -7, 0},
        {"9223372036854775807", JSON_INT, INT64_MAX, 0},
        {"-9223372036854775808", JSON_INT, INT64_MIN, 0},
        {"0.5", JSON_REAL, 0, 0.5}, {"-1.25", JSON_REAL, 0, -1.25},
        {"1e+3", JSON_REAL, 0, 1000}, {"1E-2", JSON_REAL, 0, 0.01},
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct json_value v;
        bool parsed = json_read(&v, cases[i].wire, strlen(cases[i].wire));
        bool match = parsed && v.type == cases[i].type;
        if (match) match = v.type == JSON_INT ? v.val.i == cases[i].integer :
                                               v.val.d == cases[i].real;
        ok = match && json_valid(cases[i].wire, strlen(cases[i].wire)) && ok;
        json_free(&v);
    }
    return ok;
}

static bool json_number_invalid_case(void)
{
    static const char *const bad[] = {
        "-", "01", "-01", "1.", "1e", "1e+", "1e-", "1.e2",
        "9223372036854775808", "-9223372036854775809",
        "1e999", "1e-999", "1x", "0 1", "+1", ".5",
        "[1,01]", "{\"owned\":\"allocated\",\"number\":1e+}",
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        struct json_value v;
        bool parsed = json_read(&v, bad[i], strlen(bad[i]));
        bool valid = json_valid(bad[i], strlen(bad[i]));
        bool cleared = v.type == JSON_NULL && v.children == NULL && v.keys == NULL;
        if (parsed || valid || !cleared) printf("[accepted/retained '%s'] ", bad[i]);
        ok = !parsed && !valid && cleared && ok;
        json_free(&v);
    }
    return ok;
}

static bool json_number_nested_cleanup_case(void)
{
    /* These refuse after an unattached container owns a string and its
     * child/key arrays. A NULL public root does not establish cleanup;
     * run this registered test under LeakSanitizer to observe ownership. */
    static const char *const cases[] = {
        "[[\"allocated\",1e999]]",
        "{\"x\":[\"allocated\",1e+]}",
        "[{\"owned\":\"allocated\",\"bad\":1e+}]",
        "{\"x\":{\"owned\":\"allocated\",\"bad\":1e999}}",
        "[[\"allocated\",9223372036854775808]]",
        "{\"x\":[\"allocated\",-9223372036854775809]}",
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct json_value v = {0};
        bool parsed = json_read(&v, cases[i], strlen(cases[i]));
        bool valid = json_valid(cases[i], strlen(cases[i]));
        ok = !parsed && !valid && v.type == JSON_NULL && ok;
        json_free(&v);
    }
    return ok;
}

static int json_number_cases(void)
{
    int failures = 0;
    printf("json bounded numbers preserve exact values... ");
    if (json_number_valid_case()) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    printf("json malformed and out-of-range numbers refuse and clear ownership... ");
    if (json_number_invalid_case()) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    printf("json rejected nested number containers release all allocations... ");
    if (json_number_nested_cleanup_case()) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    return failures;
}

int test_json(void)
{
    int failures = json_unicode_cases() + json_number_cases() + json_heap_accounting_cases() + json_growth_cases() + json_append_target_cases() + cgo_decoder_tests() + cgo_passive_tests() + cga_goal_tests();

    printf("json parse failures retire copied strings and partial trees... ");
    extern int json_failure_retirement_case(void);
    failures += json_failure_retirement_case();

    printf("json parse integer... ");
    {
        struct json_value v;
        bool ok = json_read(&v, "42", 2);
        ok = ok && (v.type == JSON_INT) && (json_get_int(&v) == 42);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json parse string... ");
    {
        struct json_value v;
        bool ok = json_read(&v, "\"hello\"", 7);
        ok = ok && (v.type == JSON_STR) && (strcmp(json_get_str(&v), "hello") == 0);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json parse bool... ");
    {
        struct json_value v;
        bool ok = json_read(&v, "true", 4) && json_get_bool(&v);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json parse null... ");
    {
        struct json_value v;
        bool ok = json_read(&v, "null", 4) && (v.type == JSON_NULL);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json parse array... ");
    {
        struct json_value v;
        bool ok = json_read(&v, "[1,2,3]", 7);
        ok = ok && (v.type == JSON_ARR) && (json_size(&v) == 3);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json parse object... ");
    {
        struct json_value v;
        const char *s = "{\"name\":\"ZCL\",\"height\":3045000}";
        bool ok = json_read(&v, s, strlen(s));
        ok = ok && (v.type == JSON_OBJ);
        const struct json_value *h = json_get(&v, "height");
        ok = ok && h && (json_get_int(h) == 3045000);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json build object + write... ");
    {
        struct json_value v;
        json_init(&v);
        json_set_object(&v);
        json_push_kv_str(&v, "ticker", "ZTEST");
        json_push_kv_int(&v, "supply", 1000);
        char buf[256];
        json_write(&v, buf, sizeof(buf));
        bool ok = (strstr(buf, "ZTEST") != NULL) && (strstr(buf, "1000") != NULL);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL (%s)\n", buf); failures++; }
    }

    printf("json parse nested object... ");
    {
        const char *s = "{\"a\":{\"b\":42}}";
        struct json_value v;
        bool ok = json_read(&v, s, strlen(s));
        const struct json_value *a = json_get(&v, "a");
        ok = ok && a && (a->type == JSON_OBJ);
        const struct json_value *b = json_get(a, "b");
        ok = ok && b && (json_get_int(b) == 42);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Edge cases ────────────────────────────────────────── */

    printf("json parse empty string... ");
    {
        struct json_value v;
        bool ok = json_read(&v, "\"\"", 2);
        ok = ok && (v.type == JSON_STR) && (strcmp(json_get_str(&v), "") == 0);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json parse empty object... ");
    {
        struct json_value v;
        bool ok = json_read(&v, "{}", 2);
        ok = ok && (v.type == JSON_OBJ) && (json_size(&v) == 0);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json parse empty array... ");
    {
        struct json_value v;
        bool ok = json_read(&v, "[]", 2);
        ok = ok && (v.type == JSON_ARR) && (json_size(&v) == 0);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json parse negative integer... ");
    {
        struct json_value v;
        bool ok = json_read(&v, "-99", 3);
        ok = ok && (v.type == JSON_INT) && (json_get_int(&v) == -99);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json parse float... ");
    {
        struct json_value v;
        bool ok = json_read(&v, "3.14", 4);
        ok = ok && (v.type == JSON_REAL);
        double d = json_get_real(&v);
        ok = ok && (d > 3.13 && d < 3.15);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json parse scientific notation... ");
    {
        struct json_value v;
        bool ok = json_read(&v, "1e5", 3);
        ok = ok && (v.type == JSON_REAL);
        double d = json_get_real(&v);
        ok = ok && (d > 99999 && d < 100001);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json parse string with escapes... ");
    {
        const char *s = "\"hello\\nworld\\t!\"";
        struct json_value v;
        bool ok = json_read(&v, s, strlen(s));
        ok = ok && (v.type == JSON_STR);
        const char *r = json_get_str(&v);
        ok = ok && r && (strcmp(r, "hello\nworld\t!") == 0);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json parse string with unicode escape... ");
    {
        const char *s = "\"abc\\u0041def\"";
        struct json_value v;
        bool ok = json_read(&v, s, strlen(s));
        ok = ok && (v.type == JSON_STR);
        /* The escaped scalar must retain its actual decoded identity. */
        const char *r = json_get_str(&v);
        ok = ok && r && (strcmp(r, "abcAdef") == 0);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json reject truncated input... ");
    {
        struct json_value v;
        bool ok = !json_read(&v, "{\"a\":", 5);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); json_free(&v); failures++; }
    }

    printf("json reject invalid input... ");
    {
        struct json_value v;
        bool ok = !json_read(&v, "xyz", 3);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); json_free(&v); failures++; }
    }

    printf("json reject valid prefix plus trailing junk... ");
    {
        const char *s = "{\"ok\":true}TRAILING";
        struct json_value v;
        bool ok = !json_read(&v, s, strlen(s));
        if (ok) printf("OK\n"); else { printf("FAIL\n"); json_free(&v); failures++; }
    }

    printf("json accept trailing whitespace... ");
    {
        const char *s = "{\"ok\":true} \n\t";
        struct json_value v;
        bool ok = json_read(&v, s, strlen(s));
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json parse zero-length... ");
    {
        struct json_value v;
        bool ok = !json_read(&v, "", 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); json_free(&v); failures++; }
    }

    printf("json parse deeply nested array... ");
    {
        /* [[[[42]]]] — 4 levels deep */
        const char *s = "[[[[42]]]]";
        struct json_value v;
        bool ok = json_read(&v, s, strlen(s));
        ok = ok && (v.type == JSON_ARR);
        const struct json_value *c = json_at(&v, 0);
        ok = ok && c && (c->type == JSON_ARR);
        c = json_at(c, 0);
        ok = ok && c && (c->type == JSON_ARR);
        c = json_at(c, 0);
        ok = ok && c && (c->type == JSON_ARR);
        c = json_at(c, 0);
        ok = ok && c && (json_get_int(c) == 42);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json parse large array (100 elements)... ");
    {
        char buf[512];
        int off = 0;
        off += snprintf(buf + off, sizeof(buf) - (size_t)off, "[");
        for (int i = 0; i < 100; i++)
            off += snprintf(buf + off, sizeof(buf) - (size_t)off, "%s%d", i ? "," : "", i);
        off += snprintf(buf + off, sizeof(buf) - (size_t)off, "]");
        (void)off;
        struct json_value v;
        bool ok = json_read(&v, buf, strlen(buf));
        ok = ok && (v.type == JSON_ARR) && (json_size(&v) == 100);
        const struct json_value *last = json_at(&v, 99);
        ok = ok && last && (json_get_int(last) == 99);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json write + read roundtrip... ");
    {
        struct json_value v;
        json_init(&v);
        json_set_object(&v);
        json_push_kv_str(&v, "name", "ZClassic");
        json_push_kv_int(&v, "height", 3045000);
        json_push_kv_bool(&v, "synced", true);

        char buf[512];
        json_write(&v, buf, sizeof(buf));
        json_free(&v);

        struct json_value v2;
        bool ok = json_read(&v2, buf, strlen(buf));
        ok = ok && (v2.type == JSON_OBJ);
        const struct json_value *n = json_get(&v2, "name");
        ok = ok && n && (strcmp(json_get_str(n), "ZClassic") == 0);
        const struct json_value *h = json_get(&v2, "height");
        ok = ok && h && (json_get_int(h) == 3045000);
        const struct json_value *s = json_get(&v2, "synced");
        ok = ok && s && json_get_bool(s);
        json_free(&v2);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json reject nesting beyond depth limit... ");
    {
        /* Build a string with 300 nested arrays — exceeds JSON_MAX_DEPTH (256) */
        char deep[700];
        memset(deep, '[', 300);
        memcpy(deep + 300, "42", 2);
        memset(deep + 302, ']', 300);
        deep[602] = '\0';
        struct json_value v;
        bool ok = !json_read(&v, deep, 602);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); json_free(&v); failures++; }
    }

    printf("json accept nesting at depth limit... ");
    {
        /* 256 levels deep — exactly at the limit, should succeed */
        char at_limit[600];
        memset(at_limit, '[', 256);
        memcpy(at_limit + 256, "1", 1);
        memset(at_limit + 257, ']', 256);
        at_limit[513] = '\0';
        struct json_value v;
        bool ok = json_read(&v, at_limit, 513);
        ok = ok && (v.type == JSON_ARR);
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json copy deep equality... ");
    {
        const char *s = "{\"a\":[1,2,{\"b\":true}],\"c\":\"hello\"}";
        struct json_value v;
        bool ok = json_read(&v, s, strlen(s));

        struct json_value v2;
        json_copy(&v2, &v);

        char buf1[256], buf2[256];
        json_write(&v, buf1, sizeof(buf1));
        json_write(&v2, buf2, sizeof(buf2));
        ok = ok && (strcmp(buf1, buf2) == 0);
        json_free(&v);
        json_free(&v2);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("json accessors NULL-safe (missing RPC param must not crash)... ");
    {
        /* json_get_str(json_at(params, N)) on an ABSENT param N gets NULL from
         * json_at(). Every read accessor
         * must treat NULL as the type's zero value, never dereference it. */
        bool ok = true;
        ok = ok && (json_at(NULL, 0) == NULL);
        ok = ok && (json_get_str(NULL)[0] == '\0');
        ok = ok && (json_get_int(NULL) == 0);
        ok = ok && (json_get_real(NULL) == 0.0);
        ok = ok && (json_get_bool(NULL) == false);
        ok = ok && (json_is_null(NULL) == true);
        ok = ok && (json_size(NULL) == 0);
        ok = ok && (json_empty(NULL) == true);
        /* The exact crash idiom on an empty params array. */
        struct json_value arr;
        json_init(&arr);
        json_set_array(&arr);
        ok = ok && (json_at(&arr, 0) == NULL);
        ok = ok && (json_get_str(json_at(&arr, 0))[0] == '\0');
        ok = ok && (json_get_int(json_at(&arr, 0)) == 0);
        json_free(&arr);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }


    printf("json_valid is json_read's grammar with no allocation... ");
    failures += json_valid_case();
    return failures;
}
