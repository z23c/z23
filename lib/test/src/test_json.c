/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "test/test_core.h"
#include "json/json.h"

int test_json(void)
{
    int failures = 0;

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
        /* unicode escapes produce '?' placeholder */
        const char *r = json_get_str(&v);
        ok = ok && r && (strlen(r) == 7);
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
        /* Regression: json_get_str(json_at(params, N)) on an ABSENT param N
         * returned NULL from json_at(), then json_get_str(NULL) dereferenced
         * v->type and SIGSEGV'd the whole node (observed live: diag_rpc_dumpstate
         * called with no subsystem arg crashed the process). Every read accessor
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

    return failures;
}
