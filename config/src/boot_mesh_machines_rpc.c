/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fleet view RPC adapter. Renders boot_mesh_machines_collect's
 * report as zcl.mesh_machines.v1: every durable pairing row exactly once,
 * an honest reachability verdict per row, and a redacted capsule summary
 * for ONLINE rows. Mirrors the boot_mesh_status_rpc.c precedent: the
 * adapter is a pure projection — every refusal the lane can produce is
 * already a per-row verdict, so the method itself only fails on bad input
 * or an out-of-memory report allocation. */

#include "config/boot_mesh_machines.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "rpc/server.h"
#include "util/clientversion.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void rpc_error(struct json_value *result, const char *code,
                      const char *message)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", false);
    json_push_kv_str(result, "code", code);
    json_push_kv_str(result, "message", message);
}

/* Redacted durable-record projection, same keys as `ops mesh pair list`
 * rows: fingerprints and local policy only, never raw public keys. */
static void machine_record_json(struct json_value *value,
                                const struct mesh_pairing_public_view *view)
{
    json_set_object(value);
    json_push_kv_str(value, "pairing_id", view->pairing_id);
    json_push_kv_str(value, "peer_master_fingerprint",
                     view->peer_master_fingerprint);
    json_push_kv_str(value, "peer_noise_fingerprint",
                     view->peer_noise_fingerprint);
    json_push_kv_int(value, "capability_mask", (int64_t)view->capability_mask);
    json_push_kv_str(value, "capability", "status_read");
    json_push_kv_int(value, "paired_at", view->paired_at);
    json_push_kv_int(value, "expires_at", view->expires_at);
    json_push_kv_int(value, "revoked_at", view->revoked_at);
    json_push_kv_int(value, "revocation_generation",
                     (int64_t)view->revocation_generation);
    json_push_kv_str(value, "record_state", view->state);
}

static void capsule_summary_str(struct json_value *out,
                                const struct json_value *capsule,
                                const char *section, const char *key)
{
    const struct json_value *object = json_get(capsule, section);
    const char *text =
        object ? json_get_str(json_get(object, key)) : NULL;
    if (text)
        json_push_kv_str(out, key, text);
}

/* Lift the small, flat summary out of a verified OK capsule. A capsule
 * that does not parse is a responder defect: the row keeps its verdict and
 * carries capsule_json_valid=false instead of a silent omission. */
static void capsule_summary_json(struct json_value *value,
                                 const uint8_t *capsule, size_t capsule_len)
{
    struct json_value parsed;
    json_init(&parsed);
    if (!json_read(&parsed, (const char *)capsule, capsule_len) ||
        parsed.type != JSON_OBJ) {
        json_free(&parsed);
        json_push_kv_bool(value, "capsule_json_valid", false);
        return;
    }
    struct json_value summary;
    json_init(&summary);
    json_set_object(&summary);

    struct json_value platform;
    json_init(&platform);
    json_set_object(&platform);
    capsule_summary_str(&platform, &parsed, "platform", "os");
    capsule_summary_str(&platform, &parsed, "platform", "architecture");
    capsule_summary_str(&platform, &parsed, "platform", "environment");
    json_push_kv(&summary, "platform", &platform);
    json_free(&platform);

    struct json_value build;
    json_init(&build);
    json_set_object(&build);
    const struct json_value *capsule_build = json_get(&parsed, "build");
    const char *source_id =
        capsule_build ? json_get_str(json_get(capsule_build, "source_id_sha256"))
                      : NULL;
    const char *commit =
        capsule_build ? json_get_str(json_get(capsule_build, "commit")) : NULL;
    if (source_id) {
        json_push_kv_str(&build, "source_id_sha256", source_id);
        json_push_kv_bool(&build, "same_source_as_this_node",
                          strcmp(source_id, zcl_build_source_id_sha256()) == 0);
    }
    if (commit)
        json_push_kv_str(&build, "commit", commit);
    json_push_kv(&summary, "build", &build);
    json_free(&build);

    const struct json_value *confinement = json_get(&parsed, "confinement");
    if (confinement && confinement->type == JSON_OBJ) {
        struct json_value view;
        json_init(&view);
        json_set_object(&view);
        const struct json_value *active = json_get(confinement, "active");
        const struct json_value *seccomp =
            json_get(confinement, "seccomp_supported");
        if (active && active->type == JSON_BOOL)
            json_push_kv_bool(&view, "active", json_get_bool(active));
        if (seccomp && seccomp->type == JSON_BOOL)
            json_push_kv_bool(&view, "seccomp_supported",
                              json_get_bool(seccomp));
        json_push_kv(&summary, "confinement", &view);
        json_free(&view);
    }
    const struct json_value *hotswap = json_get(&parsed, "hotswap");
    if (hotswap && hotswap->type == JSON_OBJ) {
        struct json_value view;
        json_init(&view);
        json_set_object(&view);
        const struct json_value *available =
            json_get(hotswap, "native_activation_available");
        const char *status = json_get_str(json_get(hotswap, "status"));
        if (available && available->type == JSON_BOOL)
            json_push_kv_bool(&view, "native_activation_available",
                              json_get_bool(available));
        if (status)
            json_push_kv_str(&view, "status", status);
        json_push_kv(&summary, "hotswap", &view);
        json_free(&view);
    }

    json_push_kv(value, "capsule_summary", &summary);
    json_free(&summary);
    json_free(&parsed);
}

static void machine_row_json(struct json_value *value,
                             const struct mesh_machines_report *report,
                             const struct mesh_machine_row *row)
{
    machine_record_json(value, &row->view);
    char reachability[MESH_MACHINE_DETAIL_LEN + 16];
    if (row->state == MESH_MACHINE_REFUSED) {
        snprintf(reachability, sizeof(reachability), "refused:%s",
                 row->detail);
        json_push_kv_str(value, "reachability", reachability);
        json_push_kv_str(value, "refusal_status", row->detail);
    } else {
        json_push_kv_str(value, "reachability",
                         mesh_machine_state_string(row->state));
        if (row->detail[0])
            json_push_kv_str(value, "detail", row->detail);
    }
    if (row->state != MESH_MACHINE_ONLINE)
        return;
    char hex[65];
    json_push_kv_int(value, "observed_unix", (int64_t)row->observed_unix);
    zcl_hex_encode(row->responder_noise_fingerprint, 32, hex);
    json_push_kv_str(value, "responder_noise_fingerprint_sha3", hex);
    if (row->capsule_slot >= 0 &&
        (size_t)row->capsule_slot < report->capsule_count) {
        capsule_summary_json(value, report->capsules[row->capsule_slot],
                             report->capsule_lens[row->capsule_slot]);
    }
}

static bool rpc_mesh_machines(const struct json_value *params, bool help,
                              struct json_value *result)
{
    (void)params;
    if (help) {
        json_set_str(result,
                     "mesh_machines — every durable pairing with live "
                     "reachability (online/refused:<status>/unreachable/"
                     "timeout/unknown/expired/revoked); probes up to 8 "
                     "actives with a collective 12 s budget; never dials");
        return true;
    }
    struct mesh_machines_report *report =
        zcl_malloc(sizeof(*report), "mesh_machines_report");
    if (!report) {
        rpc_error(result, "UNAVAILABLE",
                  "could not allocate the fleet report");
        return true;
    }
    if (!boot_mesh_machines_collect(report)) {
        free(report);
        rpc_error(result, "UNAVAILABLE", "fleet collection failed");
        return true;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "schema", "zcl.mesh_machines.v1");
    json_push_kv_int(result, "generated_unix", report->generated_unix);
    json_push_kv_bool(result, "pairing_records_observed",
                      report->records_observed);
    if (!report->records_observed)
        json_push_kv_str(result, "blocker", report->blocker);
    json_push_kv_bool(result, "truncated", report->truncated);
    struct json_value counts;
    json_init(&counts);
    json_set_object(&counts);
    json_push_kv_int(&counts, "total", report->counts.total);
    json_push_kv_int(&counts, "online", report->counts.online);
    json_push_kv_int(&counts, "refused", report->counts.refused);
    json_push_kv_int(&counts, "unreachable", report->counts.unreachable);
    json_push_kv_int(&counts, "timeout", report->counts.timeout);
    json_push_kv_int(&counts, "expired", report->counts.expired);
    json_push_kv_int(&counts, "revoked", report->counts.revoked);
    json_push_kv(result, "counts", &counts);
    json_free(&counts);
    struct json_value machines;
    json_init(&machines);
    json_set_array(&machines);
    for (size_t i = 0; i < report->row_count; i++) {
        struct json_value row;
        json_init(&row);
        machine_row_json(&row, report, &report->rows[i]);
        json_push_back(&machines, &row);
        json_free(&row);
    }
    json_push_kv(result, "machines", &machines);
    json_free(&machines);
    free(report);
    return true;
}

void boot_mesh_machines_register_rpc(struct rpc_table *table)
{
    const struct rpc_command commands[] = {
        {"mesh", "mesh_machines", rpc_mesh_machines, true},
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}
