/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Read-only App-manifest inspection for the dev tree (describe / plan /
 * simulate). Each operation has a bounded JSON *buffer producer* — the single
 * source of truth — plus a thin stdout print wrapper used by the checkout-local
 * devloop dispatcher. The producers are release-safe (no process spawn, no
 * mutation), so the Wave 2.2 registry handlers in
 * tools/command/native_dev_command.c bind straight to them. */

#include "devloop.h"

#include "framework/app_definition.h"
#include "framework/app_platform.h"
#include "platform/directory_compat.h"
#include "platform/time_compat.h"
#include "sim/social_app_sim.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── bounded JSON appender ─────────────────────────────────────────────── */
struct devbuf {
    char *out;
    size_t cap;
    size_t len;
    bool ok;
};

static void devbuf_init(struct devbuf *b, char *out, size_t cap)
{
    b->out = out;
    b->cap = cap;
    b->len = 0;
    b->ok = out != NULL && cap != 0;
    if (b->ok)
        out[0] = 0;
}

static void devbuf_addf(struct devbuf *b, const char *fmt, ...)
{
    if (!b->ok || b->len >= b->cap)
        return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b->out + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= b->cap - b->len) {
        b->ok = false;
        return;
    }
    b->len += (size_t)n;
}

static void devbuf_addstr(struct devbuf *b, const char *s)
{
    devbuf_addf(b, "\"");
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
        if (*p == '"' || *p == '\\')
            devbuf_addf(b, "\\%c", *p);
        else if (*p < 0x20)
            devbuf_addf(b, "\\u%04x", *p);
        else
            devbuf_addf(b, "%c", *p);
    }
    devbuf_addf(b, "\"");
}


/* Same as devbuf_addstr, minus one trailing newline: a registry row is stored
 * with the newline it is written with, but reads better unterminated in JSON. */
static void devbuf_addstr_trim(struct devbuf *b, const char *s)
{
    char trimmed[ZCL_DEVLOOP_APP_SLICE_NAME_MAX * 2];
    size_t n = strnlen(s, sizeof(trimmed));
    if (n >= sizeof(trimmed)) {
        b->ok = false;
        return;
    }
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        n--;
    memcpy(trimmed, s, n);
    trimmed[n] = 0;
    devbuf_addstr(b, trimmed);
}
bool zcl_devloop_app_resource_valid(const char *name)
{
    if (!name)
        return false;
    const char *end = memchr(name, '\0',
                             ZCL_APP_DEFINITION_RESOURCE_NAME_MAX + 1u);
    if (!end || end == name || name[0] < 'a' || name[0] > 'z' ||
        end[-1] == '_')
        return false;
    for (const char *p = name + 1; p < end; p++) {
        bool lower = *p >= 'a' && *p <= 'z';
        bool digit = *p >= '0' && *p <= '9';
        if (!lower && !digit && *p != '_')
            return false;
        if (*p == '_' && p[-1] == '_')
            return false;
    }
    return true;
}

static bool resolve_root(const char *requested, char out[PATH_MAX])
{
    return platform_directory_canonical_real(requested, out, PATH_MAX);
}

/* ── describe ──────────────────────────────────────────────────────────── */
size_t zcl_devloop_app_describe_json(const char *repo_root, const char *app_id,
                                     char *out, size_t out_sz)
{
    char root[PATH_MAX];
    if (!zcl_app_definition_id_valid_v1(app_id) ||
        !resolve_root(repo_root, root))
        return 0;
    struct zcl_app_definition_v1 definition;
    struct zcl_result result = zcl_app_definition_load_v1(
        root, app_id, &definition);
    if (!result.ok)
        return 0;

    struct devbuf b;
    devbuf_init(&b, out, out_sz);
    devbuf_addf(&b, "{\"schema\":\"zcl.dev_app.v1\",\"status\":\"ok\","
                    "\"app_id\":");
    devbuf_addstr(&b, definition.app_id);
    devbuf_addf(&b, ",\"display_name\":");
    devbuf_addstr(&b, definition.display_name);
    devbuf_addf(&b, ",\"version\":");
    devbuf_addstr(&b, definition.app_version);
    devbuf_addf(&b, ",\"definition_version\":%u,\"compiler\":"
                    "\"strict-bounded-v1\",\"authority\":\"definition-only\","
                    "\"boundary\":"
                    "\"core_owns_truth_apps_consume_capabilities\","
                    "\"capabilities\":[",
                definition.definition_version);
    static const uint64_t capability_bits[] = {
        ZCL_APP_CAP_CHAIN_READ, ZCL_APP_CAP_SIGNED_EVENTS,
        ZCL_APP_CAP_RESIDENT_STATE, ZCL_APP_CAP_WEB_ROUTES,
        ZCL_APP_CAP_ONION_BINDING, ZCL_APP_CAP_ZNAM_BINDING,
        ZCL_APP_CAP_P2P_TOPICS, ZCL_APP_CAP_WALLET_REQUESTS,
        ZCL_APP_CAP_SCHEDULED_JOBS, ZCL_APP_CAP_CLOCK, ZCL_APP_CAP_RANDOM,
    };
    bool comma = false;
    for (size_t i = 0;
         i < sizeof(capability_bits) / sizeof(capability_bits[0]); i++) {
        if ((definition.required_capabilities & capability_bits[i]) == 0)
            continue;
        if (comma) devbuf_addf(&b, ",");
        devbuf_addstr(&b, zcl_app_capability_name(capability_bits[i]));
        comma = true;
    }
    devbuf_addf(&b, "],\"resources\":[");
    for (size_t i = 0; i < definition.resource_count; i++) {
        if (i) devbuf_addf(&b, ",");
        devbuf_addstr(&b, definition.resources[i].name);
    }
    devbuf_addf(&b, "],\"topics\":[");
    for (size_t i = 0; i < definition.topic_count; i++) {
        if (i) devbuf_addf(&b, ",");
        devbuf_addf(&b, "{\"name\":");
        devbuf_addstr(&b, definition.topics[i].name);
        devbuf_addf(&b, ",\"wire_version\":%u,\"max_event_bytes\":%u}",
                    definition.topics[i].wire_version,
                    definition.topics[i].max_event_bytes);
    }
    devbuf_addf(&b, "],\"bindings\":{\"web\":");
    devbuf_addstr(&b, definition.mount_count ? definition.mounts[0].path : "");
    devbuf_addf(&b, ",\"web_mounts\":[");
    for (size_t i = 0; i < definition.mount_count; i++) {
        if (i) devbuf_addf(&b, ",");
        devbuf_addstr(&b, definition.mounts[i].path);
    }
    devbuf_addf(&b, "],\"onion\":%s,\"znam\":",
                definition.onion_enabled ? "true" : "false");
    devbuf_addstr(&b, definition.znam_declared ? definition.znam : "");
    devbuf_addf(&b, "},\"state_schema_version\":%u,\"simulations\":[",
                definition.state_schema_version);
    for (size_t i = 0; i < definition.simulation_count; i++) {
        if (i) devbuf_addf(&b, ",");
        devbuf_addstr(&b, definition.simulations[i].name);
    }
    devbuf_addf(&b, "],\"contained\":[\"runtime_authority\","
                    "\"publication\",\"deployment\"],\"agent_next_action\":"
                    "\"dev app plan %s <resource> (preview only)\"}", app_id);
    return b.ok ? b.len : 0;
}

int zcl_devloop_app_describe(const char *repo_root, const char *app_id)
{
    char body[8192];
    size_t n = zcl_devloop_app_describe_json(repo_root, app_id, body,
                                             sizeof(body));
    if (n == 0) {
        fprintf(stderr, "[devloop] app describe: invalid app or root\n");
        return 2;
    }
    printf("%s\n", body);
    return strstr(body, "\"status\":\"ok\"") ? 0 : 1;
}

/* ── plan ──────────────────────────────────────────────────────────────── */
/* Render the slice a scaffold would materialise. The file list is not
 * restated here — it is read out of the one slice builder both commands use,
 * so a preview can never describe a slice the scaffold does not write. */
size_t zcl_devloop_app_plan_json(const char *repo_root, const char *app_id,
                                 const char *resource, char *out, size_t out_sz)
{
    struct zcl_devloop_app_slice *slice =
        zcl_devloop_app_slice_build(repo_root, app_id, resource);
    if (!slice)
        return 0;
    struct zcl_app_definition_v1 definition;
    if (!zcl_app_definition_load_v1(slice->root, slice->app_id,
                                    &definition).ok) {
        zcl_devloop_app_slice_free(slice);
        return 0;
    }

    struct devbuf b;
    devbuf_init(&b, out, out_sz);
    devbuf_addf(&b, "{\"schema\":\"zcl.dev_app_plan.v1\",\"status\":"
                    "\"planned\",\"mode\":\"preview-only\","
                    "\"writes\":false,\"authority\":\"none\",\"app_id\":");
    devbuf_addstr(&b, slice->app_id);
    devbuf_addf(&b, ",\"resource\":");
    devbuf_addstr(&b, slice->resource);
    devbuf_addf(&b, ",\"test_group\":");
    devbuf_addstr(&b, slice->group);
    devbuf_addf(&b, ",\"files\":[");
    bool comma = false;
    for (size_t i = 0; i < slice->file_count; i++) {
        if (slice->files[i].kind != ZCL_DEVLOOP_APP_SLICE_CREATE)
            continue;
        if (comma) devbuf_addf(&b, ",");
        devbuf_addstr(&b, slice->files[i].path);
        comma = true;
    }
    devbuf_addf(&b, "],\"registrations\":[");
    comma = false;
    for (size_t i = 0; i < slice->file_count; i++) {
        if (slice->files[i].kind != ZCL_DEVLOOP_APP_SLICE_ROW)
            continue;
        if (comma) devbuf_addf(&b, ",");
        devbuf_addf(&b, "{\"file\":");
        devbuf_addstr(&b, slice->files[i].path);
        devbuf_addf(&b, ",\"row\":");
        devbuf_addstr_trim(&b, slice->files[i].body);
        devbuf_addf(&b, "}");
        comma = true;
    }
    devbuf_addf(&b, "],\"bindings\":[");
    comma = false;
    static const struct { uint64_t bit; const char *name; } bindings[] = {
        { ZCL_APP_CAP_WEB_ROUTES, "web" },
        { ZCL_APP_CAP_ONION_BINDING, "onion" },
        { ZCL_APP_CAP_ZNAM_BINDING, "znam" },
        { ZCL_APP_CAP_P2P_TOPICS, "p2p_topics" },
    };
    for (size_t i = 0; i < sizeof(bindings) / sizeof(bindings[0]); i++) {
        if ((definition.required_capabilities & bindings[i].bit) == 0)
            continue;
        if (comma) devbuf_addf(&b, ",");
        devbuf_addstr(&b, bindings[i].name);
        comma = true;
    }
    devbuf_addf(&b, "],\"wiring\":["
                    "\"engine/models/src/database_migrate_features.c\","
                    "\"contexts/commons/apps/%s/app.def\","
                    "\"cognition/controllers/include/controllers/"
                    "agent_impact_rules.def\",\"docs/CODEBASE_MAP.md\"],"
                    "\"required_proofs\":[\"same_seed_replay\","
                    "\"partition_rejoin_convergence\","
                    "\"invalid_signature_rejection\","
                    "\"validation_and_relationship_tests\"],"
                    "\"forbidden\":[\"consensus_mutation\",\"wallet_keys\","
                    "\"raw_storage\",\"raw_sockets\",\"boot_ownership\"],"
                    "\"agent_next_action\":\"z23 dev app scaffold %s %s "
                    "writes exactly these files\"}",
                slice->app_id, slice->app_id, slice->resource);
    zcl_devloop_app_slice_free(slice);
    return b.ok ? b.len : 0;
}

int zcl_devloop_app_plan(const char *repo_root, const char *app_id,
                         const char *resource)
{
    char body[4096];
    size_t n = zcl_devloop_app_plan_json(repo_root, app_id, resource, body,
                                         sizeof(body));
    if (n == 0) {
        fprintf(stderr, "[devloop] app plan: invalid app, resource, or root\n");
        return 2;
    }
    printf("%s\n", body);
    return 0;
}

/* ── simulate ──────────────────────────────────────────────────────────── */
size_t zcl_devloop_app_simulate_json(const char *app_id, uint64_t seed,
                                     char *out, size_t out_sz)
{
    if (!app_id || strcmp(app_id, "social") != 0 || seed == 0)
        return 0;
    int64_t started_us = platform_time_monotonic_us();
    struct zcl_social_sim_report first, replay;
    bool first_ok = zcl_social_app_sim_run(seed, &first);
    bool replay_ok = zcl_social_app_sim_run(seed, &replay);
    bool identical = replay_ok && first.transcript == replay.transcript &&
                     first.deliveries == replay.deliveries &&
                     first.rejected_invalid == replay.rejected_invalid &&
                     first.real_secp256k1_verified ==
                         replay.real_secp256k1_verified &&
                     first.tampered_payload_rejected ==
                         replay.tampered_payload_rejected &&
                     first.wrong_author_rejected ==
                         replay.wrong_author_rejected &&
                     first.forged_event_id_distinct ==
                         replay.forged_event_id_distinct;
    int64_t elapsed_us = platform_time_monotonic_us() - started_us;
    bool ok = first_ok && identical;

    struct devbuf b;
    devbuf_init(&b, out, out_sz);
    devbuf_addf(&b, "{\"schema\":\"zcl.dev_app_sim.v1\",\"app_id\":\"social\","
                    "\"status\":\"%s\",\"seed\":\"0x%016llx\","
                    "\"transcript\":\"0x%016llx\",\"two_run_wall_us\":%lld,"
                    "\"deliveries\":%u,\"rejected_invalid\":%u,"
                    "\"proofs\":{\"censorship_bypassed\":%s,"
                    "\"partition_rejoin_converged\":%s,"
                    "\"late_joiner_caught_up\":%s,"
                    "\"invalid_signature_rejected\":%s,"
                    "\"real_secp256k1_verified\":%s,"
                    "\"tampered_payload_rejected\":%s,"
                    "\"wrong_author_rejected\":%s,"
                    "\"forged_event_id_distinct\":%s,"
                    "\"same_seed_replay\":%s},"
                    "\"contained\":[\"wallet_signing_broker\","
                    "\"event_store\",\"replay_head_store\","
                    "\"p2p_transport\",\"chat_encryption\"]}",
                ok ? "passed" : "failed", (unsigned long long)seed,
                (unsigned long long)first.transcript, (long long)elapsed_us,
                first.deliveries, first.rejected_invalid,
                first.censorship_bypassed ? "true" : "false",
                first.partition_rejoin_converged ? "true" : "false",
                first.late_joiner_caught_up ? "true" : "false",
                first.invalid_signature_rejected ? "true" : "false",
                first.real_secp256k1_verified ? "true" : "false",
                first.tampered_payload_rejected ? "true" : "false",
                first.wrong_author_rejected ? "true" : "false",
                first.forged_event_id_distinct ? "true" : "false",
                identical ? "true" : "false");
    return b.ok ? b.len : 0;
}

int zcl_devloop_app_simulate(const char *app_id, uint64_t seed)
{
    char body[4096];
    size_t n = zcl_devloop_app_simulate_json(app_id, seed, body, sizeof(body));
    if (n == 0) {
        fprintf(stderr, "[devloop] app simulate: unknown app or invalid seed\n");
        return 2;
    }
    printf("%s\n", body);
    return strstr(body, "\"status\":\"passed\"") ? 0 : 1;
}
