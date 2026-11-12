/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: run a leaf by registry path for the front door's composites
 * (command/native_app_compose.h). */

#include "command/native_app_compose.h"

#include "command/native_app_front_door.h"
#include "command/native_zcode_package_copy.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "sha3/sha3.h"
#include "vcs/app_offer.h"

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

static bool app_observation_fields(struct json_value *data, const struct json_value *source,
    const struct zcl_app_observation_field *fields, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        const struct json_value *v = json_get(source, fields[i].name);
        if (!v || v->type != fields[i].type || !json_push_kv(data, fields[i].name, v)) return false;
    }
    return true;
}
bool zcl_app_observation(struct json_value *out, const char *command,
    const struct zcl_command_reply *reply,
    const struct zcl_app_observation_field *fields, size_t count, size_t max_bytes)
{
    json_init(out);
    if (!command || !reply || reply->status != ZCL_COMMAND_STATUS_PASSED ||
        reply->exit_code != ZCL_COMMAND_EXIT_OK || !fields) return false;
    struct json_value data; json_init(&data); json_set_object(&data);
    bool ok = app_observation_fields(&data, &reply->data, fields, count);
    json_set_object(out);
    ok = ok && json_push_kv_str(out, "command", command) &&
        json_push_kv_str(out, "status", "passed") && json_push_kv_bool(out, "ok", true) &&
        json_push_kv(out, "data", &data);
    json_free(&data);
    size_t bytes = ok ? json_write(out, NULL, 0) : 0;
    return bytes > 0 && bytes <= max_bytes;
}

static void app_recovery_facts(struct json_value *facts, const struct json_value *source)
{
    static const char *const keys[] = {"copy", "destination", "received", "open_attempted", "executed", "pid"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const struct json_value *v = json_get(source, keys[i]);
        if (v && (v->type == JSON_STR || v->type == JSON_BOOL || v->type == JSON_INT))
            (void)json_push_kv(facts, keys[i], v);
    }
}
bool zcl_app_copy_recovery(struct json_value *out, const struct json_value *source)
{
    const struct json_value *nested = json_get(source, "failure_facts");
    if (nested && nested->type == JSON_OBJ) source = nested;
    struct json_value facts; json_init(&facts); json_set_object(&facts);
    app_recovery_facts(&facts, source);
    bool ok = json_push_kv(out, "failure_facts", &facts);
    json_free(&facts); return ok;
}
static void app_small_recovery(struct json_value *out, const struct json_value *source, size_t cap)
{
    static const char *const keys[] = {"received", "open_attempted", "executed", "pid"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const struct json_value *v = json_get(source, keys[i]);
        enum json_type expected = !strcmp(keys[i], "pid") ? JSON_INT : JSON_BOOL;
        if (v && v->type == expected)
            (void)json_push_kv(out, keys[i], v);
    }
    const struct json_value *copy = json_get(source, "copy");
    if (copy && copy->type == JSON_STR) {
        struct json_value candidate; json_init(&candidate);
        if (json_copy_checked(&candidate, out) && json_push_kv(&candidate, "copy", copy)) {
            size_t bytes = json_write(&candidate, NULL, 0);
            if (bytes && bytes <= cap) { json_free(out); *out = candidate; return; }
        }
        json_free(&candidate);
    }
}
static void app_compact_recovery(struct zcl_command_reply *reply, struct json_value *facts,
    size_t cap, bool passed)
{
    size_t bytes = json_write(facts, NULL, 0);
    if (!bytes || bytes > cap) {
        struct json_value small; json_init(&small); json_set_object(&small);
        app_small_recovery(&small, facts, cap);
        json_free(facts); *facts = small;
        if (!passed) {
            char original[sizeof(reply->error.message)];
            (void)snprintf(original, sizeof(original), "%s", reply->error.message);
            (void)snprintf(reply->error.message, sizeof(reply->error.message),
                           "%.140s Recovery details are unavailable.", original);
        }
    }
    json_free(&reply->data); json_init(&reply->data); json_set_object(&reply->data);
    app_recovery_facts(&reply->data, facts);
    size_t bounded = json_write(facts, NULL, 0);
    if (bounded && bounded <= cap) (void)json_push_kv(&reply->data, "failure_facts", facts);
}

void zcl_app_bound_committed_result(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const char *command)
{
    size_t cap = request && request->success_data_budget_provided ? request->success_data_budget : 12288u;
    bool passed = reply->status == ZCL_COMMAND_STATUS_PASSED;
    if (!passed && cap > 1500u) cap = 1500u; /* Leave room for the error envelope. */
    struct json_value facts; json_init(&facts); json_set_object(&facts);
    const struct json_value *existing = json_get(&reply->data, "failure_facts");
    const struct json_value *source = existing && existing->type == JSON_OBJ ? existing : &reply->data;
    app_recovery_facts(&facts, source);
    if (!passed && !existing) (void)json_push_kv(&reply->data, "failure_facts", &facts);
    size_t bytes = json_write(passed ? &reply->data : json_get(&reply->data, "failure_facts"), NULL, 0);
    if (bytes && bytes <= cap) { json_free(&facts); return; }
    app_compact_recovery(reply, &facts, cap < 1500u ? cap : 1500u, passed);
    json_free(&facts);
    if (passed) zcl_package_copy_fail(reply, "OBSERVATION_TOO_LARGE", true,
        "The app operation changed local state but the complete result did not fit; inspect the retained copy before retrying.", command);
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
    vcs_app_plan_hash(domain, parts, count, out);
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

static char g_app_program[512];

void zcl_app_set_program(const char *argv0)
{
    g_app_program[0] = '\0';
    if (!argv0 || !argv0[0] || strlen(argv0) >= sizeof(g_app_program)) return;
    for (const unsigned char *p = (const unsigned char *)argv0; *p; ++p)
        if (*p < 32 || *p == 127) return; /* not one pasteable shell word */
    (void)snprintf(g_app_program, sizeof(g_app_program), "%s", argv0);
}

/* The program word, then one space: what the user ran, else plain z23.
 * `neutral` always uses plain z23 (a command for another machine). */
static bool app_hint_program(char **out, size_t *left, bool neutral)
{
    bool ok = (g_app_program[0] && !neutral)
                  ? app_hint_word(out, left, g_app_program)
                  : app_hint_bytes(out, left, "z23", 3);
    return ok && app_hint_bytes(out, left, " ", 1);
}

static bool app_hint_v(char *out, size_t cap, bool neutral, const char *datadir,
                       const char *fmt, va_list ap)
{
    if (!out || !cap) return false;
    out[0] = '\0';
    char *at = out; size_t left = cap;
    bool ok = fmt && app_hint_program(&at, &left, neutral);
    if (ok && datadir && datadir[0])
        ok = app_hint_bytes(&at, &left, "-datadir=", 9) &&
            app_hint_word(&at, &left, datadir) && app_hint_bytes(&at, &left, " ", 1);
    ok = ok && app_hint_bytes(&at, &left, "app ", 4);
    ok = ok && app_hint_tail(&at, &left, fmt, ap);
    if (!ok) out[0] = '\0';
    return ok;
}

bool zcl_app_hint(char *out, size_t cap, const char *datadir, const char *fmt,
                  ...)
{
    va_list ap; va_start(ap, fmt);
    bool ok = app_hint_v(out, cap, false, datadir, fmt, ap);
    va_end(ap);
    return ok;
}

bool zcl_app_hint_neutral(char *out, size_t cap, const char *datadir,
                          const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    bool ok = app_hint_v(out, cap, true, datadir, fmt, ap);
    va_end(ap);
    return ok;
}
bool zcl_app_recovery_fields(struct json_value *out, const struct json_value *source,
    const char *const *keys, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        const struct json_value *v = json_get(source, keys[i]);
        if (!v || !json_push_kv(out, keys[i], v)) return false;
    }
    return true;
}

bool zcl_app_optional_fields(struct json_value *out, const struct json_value *data,
                               const char *const *keys, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        const struct json_value *v = json_get(data, keys[i]);
        if (v && !json_push_kv(out, keys[i], v)) return false;
    }
    return true;
}

bool zcl_app_fact_add(struct json_value *facts, const char *key, const struct json_value *value, size_t cap)
{
    struct json_value candidate; json_init(&candidate);
    bool ok = json_copy_checked(&candidate, facts) && json_push_kv(&candidate, key, value);
    size_t bytes = ok ? json_write(&candidate, NULL, 0) : 0;
    if (bytes && bytes <= cap) { json_free(facts); *facts = candidate; return true; }
    json_free(&candidate); return false;
}

void zcl_app_copy_facts(struct json_value *facts, const struct json_value *data,
    const char *const *keys, size_t count, size_t required, size_t cap, bool *omitted)
{
    for (size_t i = 0; i < count; ++i) {
        const struct json_value *v = json_get(data, keys[i]);
        if (!v) { if (i < required) *omitted = true; continue; }
        if (!json_get(facts, keys[i]) && !zcl_app_fact_add(facts, keys[i], v, cap)) *omitted = true;
    }
}
