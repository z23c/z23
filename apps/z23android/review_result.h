/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_REVIEW_RESULT_H
#define ZAPP_REVIEW_RESULT_H

#include "json/json.h"
#include <stdio.h>

/* Only verifier-produced, fixed-size identifiers are displayed as trusted facts. */
static bool zapp_review_hex(const char *s, size_t size)
{
    if (!s || strlen(s) != size) return false;
    for (size_t i = 0; i < size; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

static bool zapp_review_flag(const struct json_value *obj, const char *key, bool expected)
{
    const struct json_value *value = json_get(obj, key);
    return value && value->type == JSON_BOOL && json_get_bool(value) == expected;
}
static bool zapp_review_fields(const struct json_value *root, const char **release,
                               const char **package, const char **publisher)
{
    const char *command = json_get_str(json_get(root, "command"));
    const char *schema = json_get_str(json_get(root, "schema"));
    const char *status = json_get_str(json_get(root, "status"));
    const struct json_value *data = json_get(root, "data");
    if (!schema || strcmp(schema, "zcl.result.v1") || !status || strcmp(status, "passed") ||
        !command || strcmp(command, "zcode.package.bundle.verify") || !zapp_review_flag(root, "ok", true) ||
        !data || data->type != JSON_OBJ || !zapp_review_flag(data, "verified", true) ||
        !zapp_review_flag(data, "executed", false)) return false;
    *release = json_get_str(json_get(data, "release_id"));
    *package = json_get_str(json_get(data, "package_root"));
    *publisher = json_get_str(json_get(data, "publisher_fingerprint"));
    return zapp_review_hex(*release, 64) && zapp_review_hex(*package, 64) && zapp_review_hex(*publisher, 66);
}
static bool zapp_review_result_text(const char *reply, char *out, size_t cap)
{
    if (!reply || !out || !cap) return false;
    out[0] = 0;
    struct json_value root = {0};
    bool ok = json_read(&root, reply, strlen(reply));
    const char *release = NULL, *package = NULL, *publisher = NULL;
    ok = ok && zapp_review_fields(&root, &release, &package, &publisher);
    if (ok) {
        int n = snprintf(out, cap, "Verified signed file. No node or app was started.\nPublisher: %s\nPackage: %s\nRelease: %s\nCheck these identities with the sender.", publisher, package, release);
        ok = n >= 0 && (size_t)n < cap;
    }
    if (!ok) out[0] = 0;
    json_free(&root);
    return ok;
}
#endif
