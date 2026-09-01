/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Private read-only REST views over the build-fabric models. */

#include "api_controller_internal.h"

#include "json/json.h"
#include "models/build_fabric.h"

#include <string.h>

enum { API_BUILD_JOB_LIMIT = 100, API_BUILD_ACTION_LIMIT = 256,
       API_BUILD_WORKER_LIMIT = 128 };

static void build_rest_freshness(struct json_value *out)
{
    (void)json_push_kv_str(out, "freshness", "durable_local");
    (void)json_push_kv_str(out, "source_projection", "build_ledger");
    (void)json_push_kv_str(out, "blocker", "none");
}

static void build_rest_job(struct json_value *out,
                           const struct db_build_job *row)
{
    (void)json_push_kv_str(out, "job_id", row->job_id);
    (void)json_push_kv_str(out, "source_sha256", row->source_sha256);
    (void)json_push_kv_str(out, "source_cas_sha3", row->source_cas_sha3);
    (void)json_push_kv_str(out, "toolchain_sha3", row->toolchain_sha3);
    (void)json_push_kv_str(out, "profile", row->profile);
    (void)json_push_kv_str(out, "state", row->state);
    (void)json_push_kv_str(out, "outcome", row->outcome);
    (void)json_push_kv_bool(out, "cancel_requested", row->cancel_requested != 0);
    (void)json_push_kv_int(out, "created_at", row->created_at);
    (void)json_push_kv_int(out, "updated_at", row->updated_at);
}

static void build_rest_action(struct json_value *out,
                              const struct db_build_action *row)
{
    (void)json_push_kv_str(out, "action_id", row->action_id);
    (void)json_push_kv_str(out, "job_id", row->job_id);
    (void)json_push_kv_int(out, "sequence", row->sequence);
    (void)json_push_kv_str(out, "kind", row->kind);
    (void)json_push_kv_str(out, "state", row->state);
    (void)json_push_kv_str(out, "outcome", row->outcome);
    (void)json_push_kv_str(out, "input_root_sha3", row->input_root_sha3);
    (void)json_push_kv_str(out, "target", row->target);
    (void)json_push_kv_str(out, "flags_sha3", row->flags_sha3);
    (void)json_push_kv_str(out, "environment_sha3", row->environment_sha3);
    (void)json_push_kv_str(out, "virtual_workdir", row->virtual_workdir);
    (void)json_push_kv_str(out, "declared_outputs", row->declared_outputs);
    (void)json_push_kv_str(out, "resource_policy", row->resource_policy);
    (void)json_push_kv_str(out, "output_root_sha3", row->output_root_sha3);
    (void)json_push_kv_str(out, "worker_id", row->worker_id);
    (void)json_push_kv_str(out, "last_error", row->last_error);
}

static void build_rest_worker(struct json_value *out,
                              const struct db_build_worker *row)
{
    (void)json_push_kv_str(out, "worker_id", row->worker_id);
    (void)json_push_kv_str(out, "signer_pubkey", row->signer_pubkey);
    (void)json_push_kv_str(out, "capabilities", row->capabilities);
    (void)json_push_kv_bool(out, "approved", row->approved != 0);
    (void)json_push_kv_bool(out, "revoked", row->revoked != 0);
    (void)json_push_kv_int(out, "approved_at", row->approved_at);
    (void)json_push_kv_int(out, "expires_at", row->expires_at);
    (void)json_push_kv_int(out, "last_seen_at", row->last_seen_at);
}

static size_t build_rest_reply(struct json_value *body, uint8_t *response,
                               size_t response_max)
{
    build_rest_freshness(body);
    size_t written = api_json_ok(response, response_max, body);
    json_free(body);
    return written;
}

size_t api_serve_builds(uint8_t *response, size_t response_max)
{
    struct node_db *ndb = api_node_db();
    if (!ndb || !ndb->open)
        return api_json_error(response, response_max, JSON_503_HEADERS,
                              "Build ledger unavailable");
    struct db_build_job rows[API_BUILD_JOB_LIMIT];
    int count = db_build_jobs_recent(ndb, rows, API_BUILD_JOB_LIMIT);
    struct json_value body, items;
    json_init(&body); json_set_object(&body);
    json_init(&items); json_set_array(&items);
    for (int i = 0; i < count; i++) {
        struct json_value item; json_init(&item); json_set_object(&item);
        build_rest_job(&item, &rows[i]);
        (void)json_push_back(&items, &item); json_free(&item);
    }
    (void)json_push_kv_str(&body, "schema", "zcl.builds.index.v1");
    (void)json_push_kv_int(&body, "count", count);
    (void)json_push_kv(&body, "builds", &items); json_free(&items);
    return build_rest_reply(&body, response, response_max);
}

size_t api_serve_build_workers(uint8_t *response, size_t response_max)
{
    struct node_db *ndb = api_node_db();
    if (!ndb || !ndb->open)
        return api_json_error(response, response_max, JSON_503_HEADERS,
                              "Build ledger unavailable");
    struct db_build_worker rows[API_BUILD_WORKER_LIMIT];
    int count = db_build_workers_list(ndb, rows, API_BUILD_WORKER_LIMIT);
    struct json_value body, items;
    json_init(&body); json_set_object(&body);
    json_init(&items); json_set_array(&items);
    for (int i = 0; i < count; i++) {
        struct json_value item; json_init(&item); json_set_object(&item);
        build_rest_worker(&item, &rows[i]);
        (void)json_push_back(&items, &item); json_free(&item);
    }
    (void)json_push_kv_str(&body, "schema", "zcl.build_workers.index.v1");
    (void)json_push_kv_int(&body, "count", count);
    (void)json_push_kv(&body, "build_workers", &items); json_free(&items);
    return build_rest_reply(&body, response, response_max);
}

size_t api_serve_build(const char *job_id, uint8_t *response,
                       size_t response_max)
{
    struct node_db *ndb = api_node_db();
    struct db_build_job row;
    if (!ndb || !ndb->open || !job_id || strlen(job_id) != 64 ||
        !db_build_job_find(ndb, job_id, &row))
        return api_json_error(response, response_max, JSON_404_HEADERS,
                              "Build not found");
    struct json_value body; json_init(&body); json_set_object(&body);
    (void)json_push_kv_str(&body, "schema", "zcl.builds.show.v1");
    build_rest_job(&body, &row);
    return build_rest_reply(&body, response, response_max);
}

size_t api_serve_build_actions(const char *job_id, uint8_t *response,
                               size_t response_max)
{
    struct node_db *ndb = api_node_db();
    struct db_build_job job;
    if (!ndb || !ndb->open || !job_id || strlen(job_id) != 64 ||
        !db_build_job_find(ndb, job_id, &job))
        return api_json_error(response, response_max, JSON_404_HEADERS,
                              "Build not found");
    struct db_build_action rows[API_BUILD_ACTION_LIMIT];
    int count = db_build_job_actions(ndb, job_id, rows, API_BUILD_ACTION_LIMIT);
    struct json_value body, items;
    json_init(&body); json_set_object(&body);
    json_init(&items); json_set_array(&items);
    for (int i = 0; i < count; i++) {
        struct json_value item; json_init(&item); json_set_object(&item);
        build_rest_action(&item, &rows[i]);
        (void)json_push_back(&items, &item); json_free(&item);
    }
    (void)json_push_kv_str(&body, "schema", "zcl.build_actions.index.v1");
    (void)json_push_kv_str(&body, "job_id", job_id);
    (void)json_push_kv_int(&body, "count", count);
    (void)json_push_kv(&body, "build_actions", &items); json_free(&items);
    return build_rest_reply(&body, response, response_max);
}

size_t api_serve_build_receipt(const char *receipt_id, uint8_t *response,
                               size_t response_max)
{
    struct node_db *ndb = api_node_db();
    struct db_build_receipt row;
    if (!ndb || !ndb->open || !receipt_id || strlen(receipt_id) != 64 ||
        !db_build_receipt_find(ndb, receipt_id, &row))
        return api_json_error(response, response_max, JSON_404_HEADERS,
                              "Build receipt not found");
    struct json_value body; json_init(&body); json_set_object(&body);
    (void)json_push_kv_str(&body, "schema", "zcl.build_receipts.show.v1");
    (void)json_push_kv_str(&body, "receipt_id", row.receipt_id);
    (void)json_push_kv_str(&body, "action_id", row.action_id);
    (void)json_push_kv_str(&body, "job_id", row.job_id);
    (void)json_push_kv_str(&body, "worker_id", row.worker_id);
    (void)json_push_kv_str(&body, "lease_id", row.lease_id);
    (void)json_push_kv_str(&body, "action_sha3", row.action_sha3);
    (void)json_push_kv_str(&body, "output_sha3", row.output_sha3);
    (void)json_push_kv_str(&body, "work_receipt_sha3",
                           row.work_receipt_sha3);
    (void)json_push_kv_str(&body, "signature", row.signature);
    (void)json_push_kv_str(&body, "confinement", row.confinement);
    (void)json_push_kv_str(&body, "trust_state", row.trust_state);
    (void)json_push_kv_int(&body, "exit_status", row.exit_status);
    (void)json_push_kv_int(&body, "created_at", row.created_at);
    return build_rest_reply(&body, response, response_max);
}
