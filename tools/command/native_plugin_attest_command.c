/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: plugin.attest and plugin.attest_verify. A builder who compiled a
 *          plugin from a source package root signs an attestation of the image
 *          bytes it got; the verifier accepts a manifest only when K distinct
 *          pinned builder keys attest its sha3_512 for one source root. Files
 *          only: neither leaf installs, fetches, runs or contacts the daemon,
 *          and both are owner-only and never remote. */

#include "base/safe_alloc.h"
#include "command/native_command.h"

#include "json/json.h"
#include "plugin/plugin_attest.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *pat_str(const struct zcl_command_request *request, const char *key)
{
    if (!request->input)
        return NULL;
    const struct json_value *v = json_get(request->input, key);
    if (!v || v->type != JSON_STR)
        return NULL;
    return json_get_str(v);
}

static void pat_refuse(struct zcl_command_reply *reply, const char *code,
                       const char *next_action, const char *what, const char *evidence)
{
    char message[192];
    (void)snprintf(message, sizeof(message), "plugin %s refused: %s", what, code);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                           code, what, false, false, message, evidence ? evidence : "");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action), "%s",
                   next_action);
    reply->error.human_action_required = true;
}

/* An upstream store failure keeps the store's own code and next action. */
static void pat_refuse_status(struct zcl_command_reply *reply, enum plugin_attest_status st,
                              enum plugin_status cause, const char *what, const char *evidence)
{
    if (st == PLUGIN_ATTEST_UPSTREAM)
        pat_refuse(reply, plugin_status_code(cause), plugin_status_next_action(cause),
                   what, evidence);
    else
        pat_refuse(reply, plugin_attest_status_code(st),
                   plugin_attest_status_next_action(st), what, evidence);
}

void zcl_native_handle_plugin_attest(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct plugin_attest_request in = {
        .image_path = pat_str(request, "image"),
        .key_path = pat_str(request, "key"),
        .name = pat_str(request, "name"),
        .version = pat_str(request, "version"),
        .source_root = pat_str(request, "source-root"),
        .toolchain = pat_str(request, "toolchain"),
        .dir = pat_str(request, "dir"),
    };
    struct plugin_attest_result out;
    enum plugin_attest_status st = plugin_attest_make(&in, &out);
    if (st != PLUGIN_ATTEST_OK) {
        pat_refuse_status(reply, st, out.cause, "attest", in.image_path);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_attest.v1");
    (void)json_push_kv_str(&reply->data, "name", out.record.name);
    (void)json_push_kv_str(&reply->data, "version", out.record.version);
    (void)json_push_kv_str(&reply->data, "source_root", out.record.source_root);
    (void)json_push_kv_str(&reply->data, "toolchain", out.record.toolchain);
    (void)json_push_kv_str(&reply->data, "image_sha3_512", out.record.image);
    (void)json_push_kv_str(&reply->data, "builder_key", out.record.builder_key);
    (void)json_push_kv_str(&reply->data, "attestation", out.path);
    reply->error.mutated = true;
}

/* A JSON integer, or a decimal string: any other shape is a refusal. */
static bool pat_threshold(const struct zcl_command_request *request, int64_t *out)
{
    const struct json_value *v = request->input ? json_get(request->input, "threshold") : NULL;
    if (v && v->type == JSON_INT) {
        *out = json_get_int(v);
        return true;
    }
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    char *end = NULL;
    if (!s || !*s)
        return false;
    errno = 0;
    long long n = strtoll(s, &end, 10);
    if (errno != 0 || *end != '\0')
        return false;
    *out = n;
    return true;
}

static void pat_push_report(struct json_value *data, const struct plugin_attest_report *r)
{
    struct json_value builders;
    json_init(&builders);
    json_set_array(&builders);
    for (uint32_t i = 0; i < r->attested; i++) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, r->builders[i]);
        (void)json_push_back(&builders, &s);
        json_free(&s);
    }
    json_set_object(data);
    (void)json_push_kv_str(data, "schema", "zcl.plugin_attest_verify.v1");
    (void)json_push_kv_bool(data, "accepted", true);
    (void)json_push_kv_str(data, "name", r->name);
    (void)json_push_kv_str(data, "version", r->version);
    (void)json_push_kv_str(data, "source_root", r->source_root);
    (void)json_push_kv_str(data, "image_sha3_512", r->image);
    (void)json_push_kv_int(data, "threshold", r->threshold);
    (void)json_push_kv_int(data, "pinned", r->pinned);
    (void)json_push_kv_int(data, "attested", r->attested);
    (void)json_push_kv_int(data, "toolchains", r->toolchains);
    (void)json_push_kv(data, "builders", &builders);
    json_free(&builders);
}

static void pat_evidence(const struct plugin_attest_report *r, char *out, size_t cap)
{
    (void)snprintf(out, cap, "file=%s threshold=%u pinned=%u attested=%u", r->file,
                   (unsigned)r->threshold, (unsigned)r->pinned, (unsigned)r->attested);
}

void zcl_native_handle_plugin_attest_verify(const struct zcl_command_request *request,
                                            struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    int64_t k = 0;
    struct plugin_attest_report *rep = zcl_malloc(sizeof(*rep), "plugin.attest.report");
    char evidence[512];
    if (!rep) {
        pat_refuse_status(reply, PLUGIN_ATTEST_IO, PLUGIN_OK, "attest_verify", "");
        return;
    }
    memset(rep, 0, sizeof(*rep));
    enum plugin_attest_status st =
        pat_threshold(request, &k)
            ? plugin_attest_verify_dir(pat_str(request, "manifest"),
                                       pat_str(request, "attestations"),
                                       pat_str(request, "builders"), k,
                                       pat_str(request, "source-root"), rep)
            : PLUGIN_ATTEST_THRESHOLD_INVALID;
    pat_evidence(rep, evidence, sizeof(evidence));
    if (st != PLUGIN_ATTEST_OK)
        pat_refuse_status(reply, st, rep->cause, "attest_verify", evidence);
    else
        pat_push_report(&reply->data, rep);
    free(rep);
}
