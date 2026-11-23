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

static bool zapp_review_result_text(const char *reply, char *out, size_t cap)
{
    if (!reply || !out || !cap) return false;
    out[0] = 0;
    struct json_value root = {0};
    bool ok = json_read(&root, reply, strlen(reply));
    const struct json_value *success = ok ? json_get(&root, "ok") : NULL;
    const struct json_value *data = ok ? json_get(&root, "data") : NULL;
    const struct json_value *verified = data ? json_get(data, "verified") : NULL;
    const struct json_value *executed = data ? json_get(data, "executed") : NULL;
    const char *command = ok ? json_get_str(json_get(&root, "command")) : NULL;
    const char *release = data ? json_get_str(json_get(data, "release_id")) : NULL;
    const char *package = data ? json_get_str(json_get(data, "package_root")) : NULL;
    const char *publisher = data ? json_get_str(json_get(data, "publisher_fingerprint")) : NULL;
    ok = command && !strcmp(command, "zcode.package.bundle.verify") && success && success->type == JSON_BOOL &&
         json_get_bool(success) && data && data->type == JSON_OBJ && verified && verified->type == JSON_BOOL &&
         json_get_bool(verified) && executed && executed->type == JSON_BOOL && !json_get_bool(executed) &&
         zapp_review_hex(release, 64) && zapp_review_hex(package, 64) && zapp_review_hex(publisher, 66);
    if (ok) {
        int n = snprintf(out, cap, "Verified signed file. No node or app was started.\nPublisher: %s\nPackage: %s\nRelease: %s\nCheck these identities with the sender.", publisher, package, release);
        ok = n >= 0 && (size_t)n < cap;
    }
    if (!ok) out[0] = 0;
    json_free(&root);
    return ok;
}
#endif
