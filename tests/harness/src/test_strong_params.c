/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for strong_params.h — RPC parameter validation. */

#include "test/test_core.h"
#include "json/json.h"
#include "controllers/strong_params.h"

/* Helper: build a JSON array with one element of a given type. */
static void make_arr_str(struct json_value *arr, const char *s)
{
    json_set_array(arr);
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s);
    json_push_back(arr, &v);
    json_free(&v);
}

static void make_arr_int(struct json_value *arr, int64_t n)
{
    json_set_array(arr);
    struct json_value v;
    json_init(&v);
    json_set_int(&v, n);
    json_push_back(arr, &v);
    json_free(&v);
}

static void make_arr_real(struct json_value *arr, double d)
{
    json_set_array(arr);
    struct json_value v;
    json_init(&v);
    json_set_real(&v, d);
    json_push_back(arr, &v);
    json_free(&v);
}

static void make_arr_bool(struct json_value *arr, bool b)
{
    json_set_array(arr);
    struct json_value v;
    json_init(&v);
    json_set_bool(&v, b);
    json_push_back(arr, &v);
    json_free(&v);
}

static void make_arr_null(struct json_value *arr)
{
    json_set_array(arr);
    struct json_value v;
    json_init(&v);
    json_set_null(&v);
    json_push_back(arr, &v);
    json_free(&v);
}

static void make_empty_arr(struct json_value *arr)
{
    json_set_array(arr);
}

int test_strong_params(void)
{
    int failures = 0;

    printf("\n=== Strong Params Tests ===\n");

    /* ── rpc_params_init ──────────────────────────────────────── */

    printf("rpc_params_init: starts valid... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_empty_arr(&arr);
        struct rpc_params p;
        rpc_params_init(&p, &arr);
        if (!rpc_params_invalid(&p)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    /* ── rpc_require_str ──────────────────────────────────────── */

    printf("rpc_require_str: valid string... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_str(&arr, "hello");

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        const char *val = rpc_require_str(&p, 0, "test");
        if (val && strcmp(val, "hello") == 0 && !rpc_params_invalid(&p))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_str: missing param... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_empty_arr(&arr);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        const char *val = rpc_require_str(&p, 0, "addr");
        if (val == NULL && rpc_params_invalid(&p))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_str: wrong type (int)... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_int(&arr, 42);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        const char *val = rpc_require_str(&p, 0, "addr");
        if (val == NULL && rpc_params_invalid(&p))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    /* ── rpc_require_int ──────────────────────────────────────── */

    printf("rpc_require_int: from JSON_INT... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_int(&arr, 12345);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_require_int(&p, 0, "height");
        if (val == 12345 && !rpc_params_invalid(&p))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_int: from JSON_STR... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_str(&arr, "999");

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_require_int(&p, 0, "height");
        if (val == 999 && !rpc_params_invalid(&p))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_int: from JSON_REAL... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_real(&arr, 42.7);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_require_int(&p, 0, "count");
        if (val == 42 && !rpc_params_invalid(&p))
            printf("OK\n");
        else { printf("FAIL (val=%" PRId64 ")\n", val); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_int: missing... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_empty_arr(&arr);
        struct rpc_params p;
        rpc_params_init(&p, &arr);
        rpc_require_int(&p, 0, "idx");
        if (rpc_params_invalid(&p)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    /* ── rpc_require_bool ─────────────────────────────────────── */

    printf("rpc_require_bool: from JSON_BOOL... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_bool(&arr, true);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        bool val = rpc_require_bool(&p, 0, "verbose");
        if (val && !rpc_params_invalid(&p))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_bool: from JSON_INT (0=false)... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_int(&arr, 0);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        bool val = rpc_require_bool(&p, 0, "verbose");
        if (!val && !rpc_params_invalid(&p))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_bool: wrong type (str)... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_str(&arr, "true");

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        rpc_require_bool(&p, 0, "verbose");
        if (rpc_params_invalid(&p)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    /* ── rpc_permit_str ───────────────────────────────────────── */

    printf("rpc_permit_str: returns default on missing... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_empty_arr(&arr);
        struct rpc_params p;
        rpc_params_init(&p, &arr);
        const char *val = rpc_permit_str(&p, 0, "label", "default");
        if (val && strcmp(val, "default") == 0 && !rpc_params_invalid(&p))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    printf("rpc_permit_str: returns value when present... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_str(&arr, "custom");

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        const char *val = rpc_permit_str(&p, 0, "label", "default");
        if (val && strcmp(val, "custom") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    printf("rpc_permit_str: returns default on null... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_null(&arr);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        const char *val = rpc_permit_str(&p, 0, "label", "fallback");
        if (val && strcmp(val, "fallback") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    /* ── rpc_permit_int ───────────────────────────────────────── */

    printf("rpc_permit_int: returns default on missing... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_empty_arr(&arr);
        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_permit_int(&p, 0, "minconf", 6);
        if (val == 6 && !rpc_params_invalid(&p))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    printf("rpc_permit_int: returns value when present... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_int(&arr, 99);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_permit_int(&p, 0, "minconf", 6);
        if (val == 99) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    printf("rpc_permit_int: from JSON_STR... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_str(&arr, "77");

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_permit_int(&p, 0, "minconf", 6);
        if (val == 77) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    printf("rpc_permit_int: null returns default... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_null(&arr);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_permit_int(&p, 0, "minconf", 6);
        if (val == 6) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    /* ── rpc_permit_bool ──────────────────────────────────────── */

    printf("rpc_permit_bool: returns default on missing... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_empty_arr(&arr);
        struct rpc_params p;
        rpc_params_init(&p, &arr);
        bool val = rpc_permit_bool(&p, 0, "flag", true);
        if (val == true && !rpc_params_invalid(&p))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    printf("rpc_permit_bool: null returns default... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_null(&arr);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        bool val = rpc_permit_bool(&p, 0, "flag", false);
        if (val == false) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    /* ── rpc_require_amount ───────────────────────────────────── */

    printf("rpc_require_amount: from integer (whole ZCL)... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_int(&arr, 10);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_require_amount(&p, 0, "amount");
        if (val == 1000000000LL && !rpc_params_invalid(&p))
            printf("OK (%" PRId64 " sat)\n", val);
        else { printf("FAIL (%" PRId64 ")\n", val); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_amount: from string with decimals... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_str(&arr, "0.001");

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_require_amount(&p, 0, "amount");
        if (val == 100000LL && !rpc_params_invalid(&p))
            printf("OK (%" PRId64 " sat)\n", val);
        else { printf("FAIL (%" PRId64 ")\n", val); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_amount: from string whole number... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_str(&arr, "5");

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_require_amount(&p, 0, "amount");
        if (val == 500000000LL)
            printf("OK\n");
        else { printf("FAIL (%" PRId64 ")\n", val); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_amount: from real... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_real(&arr, 1.5);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_require_amount(&p, 0, "amount");
        if (val == 150000000LL)
            printf("OK\n");
        else { printf("FAIL (%" PRId64 ")\n", val); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_amount: 1 satoshi precision... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_str(&arr, "0.00000001");

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_require_amount(&p, 0, "amount");
        if (val == 1)
            printf("OK (1 satoshi)\n");
        else { printf("FAIL (%" PRId64 ")\n", val); failures++; }
        json_free(&arr);
    }

    /* Negative fractional string with integer part 0 ("-0.5"): the sign must
     * NOT be dropped (regression — it used to parse to +0.5 ZCL and execute a
     * real send). The result must be negative so the satoshis<0 guard fires. */
    printf("rpc_require_amount: negative fractional string \"-0.5\" rejected... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_str(&arr, "-0.5");
        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_require_amount(&p, 0, "amount");
        if (val == 0 && rpc_params_invalid(&p))
            printf("OK (rejected)\n");
        else { printf("FAIL (%" PRId64 ", invalid=%d)\n", val, rpc_params_invalid(&p)); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_amount: negative fractional string \"-0.001\" rejected... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_str(&arr, "-0.001");
        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_require_amount(&p, 0, "amount");
        if (val == 0 && rpc_params_invalid(&p))
            printf("OK (rejected)\n");
        else { printf("FAIL (%" PRId64 ")\n", val); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_amount: negative whole string \"-1.5\" rejected... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_str(&arr, "-1.5");
        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_require_amount(&p, 0, "amount");
        if (val == 0 && rpc_params_invalid(&p))
            printf("OK (rejected)\n");
        else { printf("FAIL (%" PRId64 ")\n", val); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_amount: negative integer string \"-3\" rejected... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_str(&arr, "-3");
        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_require_amount(&p, 0, "amount");
        if (val == 0 && rpc_params_invalid(&p))
            printf("OK (rejected)\n");
        else { printf("FAIL (%" PRId64 ")\n", val); failures++; }
        json_free(&arr);
    }

    /* Positive decimal still parses correctly (no sign regression). */
    printf("rpc_require_amount: positive \"0.5\" still parses... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_str(&arr, "0.5");
        struct rpc_params p;
        rpc_params_init(&p, &arr);
        int64_t val = rpc_require_amount(&p, 0, "amount");
        if (val == 50000000LL && !rpc_params_invalid(&p))
            printf("OK\n");
        else { printf("FAIL (%" PRId64 ")\n", val); failures++; }
        json_free(&arr);
    }

    printf("rpc_require_amount: missing... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_empty_arr(&arr);
        struct rpc_params p;
        rpc_params_init(&p, &arr);
        rpc_require_amount(&p, 0, "amount");
        if (rpc_params_invalid(&p)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    /* ── rpc_params_expect ────────────────────────────────────── */

    printf("rpc_params_expect: exact count... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_arr_str(&arr, "a");

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        rpc_params_expect(&p, 1, 2);
        if (!rpc_params_invalid(&p)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    printf("rpc_params_expect: too few... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_empty_arr(&arr);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        rpc_params_expect(&p, 2, 3);
        if (rpc_params_invalid(&p)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    printf("rpc_params_expect: too many... ");
    {
        struct json_value arr;
        json_init(&arr);
        json_set_array(&arr);
        struct json_value s;
        json_init(&s);
        json_set_str(&s, "a");
        json_push_back(&arr, &s);
        json_set_str(&s, "b");
        json_push_back(&arr, &s);
        json_set_str(&s, "c");
        json_push_back(&arr, &s);
        json_free(&s);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        rpc_params_expect(&p, 1, 2);
        if (rpc_params_invalid(&p)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        json_free(&arr);
    }

    /* ── Error cascading: first error sticks ──────────────────── */

    printf("rpc_params: first error sticks (no cascade)... ");
    {
        struct json_value arr;
        json_init(&arr);
        make_empty_arr(&arr);

        struct rpc_params p;
        rpc_params_init(&p, &arr);
        rpc_require_str(&p, 0, "first");
        rpc_require_str(&p, 1, "second");
        if (rpc_params_invalid(&p) &&
            strstr(p.error, "first") != NULL)
            printf("OK\n");
        else { printf("FAIL (error=%s)\n", p.error); failures++; }
        json_free(&arr);
    }

    printf("\n%d strong_params test(s) failed\n", failures);
    return failures;
}
