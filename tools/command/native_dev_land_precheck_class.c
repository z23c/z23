/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: validate optional lane lint cost classifications before use. */
#include "command/native_dev_land_precheck.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include <string.h>

static bool pc_class_known(const char *list, const char *name, size_t n)
{
    for (const char *p = list; *p;) {
        size_t len = strcspn(p, "\n");
        if (len == n && !memcmp(p, name, n)) return true;
        p += len + (p[len] == '\n' ? 1 : 0);
    }
    return false;
}

static bool pc_class_name(const char *p, size_t n)
{
    if (n <= 6 || n >= ZCL_LAND_PRECHECK_GATE_MAX || memcmp(p, "check-", 6)) return false;
    for (size_t i = 0; i < n; i++)
        if (!((p[i] >= 'a' && p[i] <= 'z') ||
              (p[i] >= '0' && p[i] <= '9') || p[i] == '-')) return false;
    return true;
}

bool zcl_land_precheck_heavy_valid(const char *text, const char *list)
{
    static const char prefix[] = "z23-lint-heavy-v1\n";
    if (strncmp(text, prefix, sizeof(prefix) - 1)) return false;
    for (const char *p = text + sizeof(prefix) - 1; *p;) {
        const char *end = strchr(p, '\n');
        if (!end) return false;
        size_t n = (size_t)(end - p);
        if (!pc_class_name(p, n) || !pc_class_known(list, p, n)) return false;
        p = end + 1;
    }
    return true;
}

#if defined(ZCL_TESTING)
static bool pc_fail_deferred_alloc;
void zcl_land_precheck_test_fail_deferred(bool enabled)
{
    pc_fail_deferred_alloc = enabled;
}
#endif

bool zcl_land_precheck_deferred_report(struct json_value *data,
                                       const char *const *names, size_t count)
{
    struct json_value list;
    json_init(&list); json_set_array(&list);
#if defined(ZCL_TESTING)
    if (pc_fail_deferred_alloc) {
        pc_fail_deferred_alloc = false;
        zcl_alloc_fault_fail_next("json_set_str");
    }
#endif
    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        struct json_value item;
        json_init(&item); json_set_str(&item, names[i]);
        ok = item.type == JSON_STR && json_get_str(&item) &&
             json_push_back(&list, &item);
        json_free(&item);
    }
    ok = ok && json_size(&list) == count &&
        json_push_kv(data, "precheck_deferred", &list) &&
        (!count || json_push_kv_str(data, "precheck_deferred_reason",
                                    "heavy learned gates require full proof"));
    const struct json_value *stored = json_get(data, "precheck_deferred");
    ok = ok && stored && stored->type == JSON_ARR && json_size(stored) == count;
    json_free(&list);
    return ok;
}
