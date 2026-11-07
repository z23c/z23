/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: run a leaf by registry path for the front door's composites
 * (command/native_app_compose.h). */

#include "command/native_app_compose.h"

#include "command/native_app_front_door.h"
#include "command/native_zcode_package_copy.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "sha3/sha3.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

bool zcl_app_inner_call(const char *path, const struct json_value *input,
                        struct zcl_command_reply *out, bool *absent)
{
    char why[256] = "";
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    if (absent)
        *absent = !spec || !spec->handler;
    zcl_command_reply_init(out, spec && spec->output_schema
                                    ? spec->output_schema
                                    : "zcl.command.inner.v1");
    if (!spec || !spec->handler) {
        zcl_package_copy_fail(out, "LEAF_ABSENT", false,
                              "this z23 has no such leaf", path);
        return false;
    }
    if (!zcl_command_registry_input_validate(spec, input, why, sizeof(why))) {
        zcl_package_copy_fail(out, "INPUT_REFUSED", false, why, path);
        return false;
    }
    const struct zcl_command_request request = {
        .input = input, .spec = spec, .invoked_name = spec->path,
    };
    spec->handler(&request, out);
    return out->status == ZCL_COMMAND_STATUS_PASSED;
}

bool zcl_app_inner_plan_confirm(const char *path, struct json_value *input,
                                struct zcl_command_reply *out)
{
    char id[65] = "";
    struct zcl_command_reply plan;
    zcl_command_reply_init(out, "zcl.command.inner.v1");
    bool ok = zcl_app_inner_call(path, input, &plan, NULL);
    const char *got = ok ? zcl_app_inner_str(&plan, "plan_id") : NULL;
    if (got && strlen(got) == 64)
        (void)snprintf(id, sizeof(id), "%s", got);
    if (!ok)
        zcl_app_inner_fail(out, &plan, false);
    else if (!id[0])
        zcl_package_copy_fail(out, "PLAN_ID_MISSING", false,
                              "the plan returned no plan_id", path);
    zcl_command_reply_free(&plan);
    if (!id[0])
        return false;
    if (!json_push_kv_str(input, "plan_id", id) ||
        !json_push_kv_bool(input, "confirm", true)) {
        zcl_package_copy_fail(out, "ALLOC", false, "confirm input", path);
        return false;
    }
    zcl_command_reply_free(out);
    return zcl_app_inner_call(path, input, out, NULL);
}

const char *zcl_app_inner_str(const struct zcl_command_reply *r,
                              const char *key)
{
    const struct json_value *v = r ? json_get(&r->data, key) : NULL;
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    return s && s[0] ? s : NULL;
}

void zcl_app_inner_fail(struct zcl_command_reply *reply,
                        const struct zcl_command_reply *inner, bool mutated)
{
    zcl_command_reply_fail(reply, inner->status == ZCL_COMMAND_STATUS_PASSED
                                      ? ZCL_COMMAND_STATUS_FAILED
                                      : inner->status,
                           inner->exit_code ? inner->exit_code
                                            : ZCL_COMMAND_EXIT_FAILED,
                           inner->error.code[0] ? inner->error.code
                                                : "INNER_FAILED",
                           "execute", inner->error.retryable,
                           mutated || inner->error.mutated,
                           inner->error.message, inner->error.evidence);
}

bool zcl_app_input(struct json_value *in, const char *const *kv, size_t n)
{
    json_init(in);
    json_set_object(in);
    for (size_t i = 0; i + 1u < n; i += 2)
        if (kv[i + 1] && !json_push_kv_str(in, kv[i], kv[i + 1]))
            return false;
    return true;
}

bool zcl_app_inner_call_built(const char *path, struct json_value *in,
                              bool built, struct zcl_command_reply *out)
{
    bool ok = false;
    if (built) {
        ok = zcl_app_inner_call(path, in, out, NULL);
    } else {
        zcl_command_reply_init(out, "zcl.command.inner.v1");
        zcl_package_copy_fail(out, "ALLOC", false, "inner input", path);
    }
    json_free(in);
    return ok;
}

bool zcl_app_input_day(const struct json_value *from, struct json_value *in)
{
    const struct json_value *day = json_get(from, "day");
    return !day || day->type != JSON_INT ||
           json_push_kv_int(in, "day", json_get_int(day));
}

void zcl_app_push_publisher(struct json_value *d, const char *full)
{
    char brief[ZCL_APP_SHORT_FINGERPRINT_LEN];
    if (!full)
        return;
    (void)json_push_kv_str(d, "publisher_fingerprint", full);
    if (zcl_app_short_fingerprint(full, brief))
        (void)json_push_kv_str(d, "publisher", brief);
}

void zcl_app_plan_id(const char *domain, const char *const *parts,
                     size_t count, uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)domain, strlen(domain) + 1u);
    for (size_t i = 0; i < count; i++) {
        const char *p = parts[i] ? parts[i] : "";
        sha3_256_write(&ctx, (const uint8_t *)p, strlen(p) + 1u);
    }
    sha3_256_finalize(&ctx, out);
}

static bool app_hint_bytes(char **out, size_t *left, const char *text, size_t n)
{
    if (n >= *left) return false;
    memcpy(*out, text, n); *out += n; *left -= n; **out = '\0';
    return true;
}

/* Escape ASCII shell syntax bytewise, so display-inserted backslash-newline
 * continuations stay outside quotes. UTF-8 bytes and plain words stay intact. */
static bool app_hint_word(char **out, size_t *left, const char *text)
{
    static const char plain[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:@+-";
    if (!text) return false;
    if (!text[0]) return app_hint_bytes(out, left, "''", 2);
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < 32 || *p == 127) return false;
        if (*p < 128 && !strchr(plain, *p) && !app_hint_bytes(out, left, "\\", 1)) return false;
        if (!app_hint_bytes(out, left, (const char *)p, 1)) return false;
    }
    return true;
}

/* All callers use trusted literal syntax with one whole argument per %s. */
static bool app_hint_tail(char **out, size_t *left, const char *fmt, va_list ap)
{
    while (*fmt) {
        if (*fmt != '%') {
            if (!app_hint_bytes(out, left, fmt++, 1)) return false;
            continue;
        }
        if (fmt[1] != 's' || !app_hint_word(out, left, va_arg(ap, const char *))) return false;
        fmt += 2;
    }
    return true;
}

bool zcl_app_hint(char *out, size_t cap, const char *datadir, const char *fmt,
                  ...)
{
    if (!out || !cap) return false;
    out[0] = '\0';
    char *at = out; size_t left = cap;
    bool ok = fmt && app_hint_bytes(&at, &left, "z23 ", 4);
    if (ok && datadir && datadir[0])
        ok = app_hint_bytes(&at, &left, "-datadir=", 9) &&
            app_hint_word(&at, &left, datadir) && app_hint_bytes(&at, &left, " ", 1);
    ok = ok && app_hint_bytes(&at, &left, "app ", 4);
    va_list ap; va_start(ap, fmt);
    ok = ok && app_hint_tail(&at, &left, fmt, ap);
    va_end(ap);
    if (!ok) out[0] = '\0';
    return ok;
}
