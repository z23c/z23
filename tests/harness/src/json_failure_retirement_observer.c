/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Compile the production JSON reader under a cleanse observer.  Renaming the
 * public surface keeps the ordinary production object linked into the same
 * harness; any parser edit is nevertheless exercised here from its actual
 * source. */
#define memory_cleanse jr_memory_cleanse
#define json_init jr_json_init
#define json_free jr_json_free
#define json_set_null jr_json_set_null
#define json_set_bool jr_json_set_bool
#define json_set_int jr_json_set_int
#define json_set_real jr_json_set_real
#define json_set_str jr_json_set_str
#define json_set_array jr_json_set_array
#define json_set_object jr_json_set_object
#define json_push_back jr_json_push_back
#define json_push_kv jr_json_push_kv
#define json_push_kv_str jr_json_push_kv_str
#define json_push_kv_int jr_json_push_kv_int
#define json_push_kv_real jr_json_push_kv_real
#define json_push_kv_bool jr_json_push_kv_bool
#define json_copy jr_json_copy
#define json_size jr_json_size
#define json_empty jr_json_empty
#define json_get jr_json_get
#define json_at jr_json_at
#define json_is_null jr_json_is_null
#define json_get_bool jr_json_get_bool
#define json_get_int jr_json_get_int
#define json_get_real jr_json_get_real
#define json_get_str jr_json_get_str
#define json_write jr_json_write
#define json_read jr_json_read
#define json_valid jr_json_valid
#define diag_push_health jr_diag_push_health
#define json_test_live_blocks jr_json_test_live_blocks
#include "../../../platform/modules/json/src/json.c"
#undef json_test_live_blocks
#undef diag_push_health
#undef json_valid
#undef json_read
#undef json_write
#undef json_get_str
#undef json_get_real
#undef json_get_int
#undef json_get_bool
#undef json_is_null
#undef json_at
#undef json_get
#undef json_empty
#undef json_size
#undef json_copy
#undef json_push_kv_bool
#undef json_push_kv_real
#undef json_push_kv_int
#undef json_push_kv_str
#undef json_push_kv
#undef json_push_back
#undef json_set_object
#undef json_set_array
#undef json_set_str
#undef json_set_real
#undef json_set_int
#undef json_set_bool
#undef json_set_null
#undef json_free
#undef json_init
#undef memory_cleanse

static size_t jr_cleanse_calls;
static size_t jr_marked_calls;
static size_t jr_zeroed_calls;

static bool jr_span_contains(const unsigned char *span, size_t span_len,
                             const char *needle)
{
    size_t needle_len = strlen(needle);
    if (needle_len > span_len)
        return false;
    for (size_t i = 0; i + needle_len <= span_len; i++)
        if (memcmp(span + i, needle, needle_len) == 0)
            return true;
    return false;
}

void jr_memory_cleanse(void *ptr, size_t len)
{
    bool marked = ptr && jr_span_contains(ptr, len, "synthetic");
    jr_cleanse_calls++;
    if (marked)
        jr_marked_calls++;
    memset(ptr, 0, len);
    bool zeroed = true;
    for (size_t i = 0; i < len; i++)
        if (((const unsigned char *)ptr)[i] != 0)
            zeroed = false;
    if (zeroed)
        jr_zeroed_calls++;
}

static bool jr_failure_retires(const char *raw, size_t expected_calls,
                               size_t expected_marked)
{
    struct json_value v;
    jr_cleanse_calls = 0;
    jr_marked_calls = 0;
    jr_zeroed_calls = 0;
    bool parsed = jr_json_read(&v, raw, strlen(raw));
    bool ok = !parsed && v.type == JSON_NULL &&
              jr_cleanse_calls == expected_calls &&
              jr_marked_calls == expected_marked &&
              jr_zeroed_calls == expected_calls;
    jr_json_free(&v);
    return ok;
}

static bool jr_fault_failure_retires(const char *raw, const char *label,
                                     unsigned nth, size_t expected_calls,
                                     size_t expected_marked)
{
    zcl_alloc_fault_fail_nth(label, nth);
    bool ok = jr_failure_retires(raw, expected_calls, expected_marked);
    bool fault_fired = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    return ok && fault_fired;
}

int json_failure_retirement_case(void)
{
    bool ok = true;
    ok = ok && jr_failure_retires("\"synthetic-secret\\q\"", 1, 1);
    ok = ok && jr_failure_retires("{\"synthetic-private\"}", 1, 1);
    ok = ok && jr_failure_retires(
        "{\"outer\":{\"private\":\"synthetic-secret\"", 3, 1);
    ok = ok && jr_failure_retires(
        "{\"private\":\"synthetic-secret\",", 2, 1);
    ok = ok && jr_fault_failure_retires(
        "\"synthetic-secret-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
        "json_string", 2, 1, 1);
    ok = ok && jr_fault_failure_retires(
        "{\"private\":\"synthetic-secret\"}", "json_children", 1, 2, 1);
    ok = ok && jr_fault_failure_retires(
        "{\"private\":\"synthetic-secret\"}", "json_keys", 1, 2, 1);
    if (ok) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL (cleanse=%zu marked=%zu zeroed=%zu)\n",
           jr_cleanse_calls, jr_marked_calls, jr_zeroed_calls);
    return 1;
}
