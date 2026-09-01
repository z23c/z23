/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Internal cross-translation-unit glue for the REST API controller.
 * Private to engine/controllers/src/api_controller*.c. */

#ifndef ZCL_APP_CONTROLLERS_SRC_API_CONTROLLER_INTERNAL_H
#define ZCL_APP_CONTROLLERS_SRC_API_CONTROLLER_INTERNAL_H

#include "controllers/agent_operator_contracts.h"
#include "controllers/api_controller.h"
#include "controllers/transaction_type_catalog.h"
#include "models/database.h"
#include "util/blocker.h"
#include "util/supervisor.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>

extern _Atomic int g_api_cache_thread_running;

/* Public serving is a chain-authority claim, not a statement that every
 * optional worker or peer is currently perfect.  Permanent consensus/store
 * authority failures and resource failures hard-gate it; transient and
 * dependency blockers remain visible yellow warnings while the last locally
 * validated frontier stays servable. */
static inline bool api_blocker_hard_gates_public_serving(
    const struct blocker_snapshot *blocker)
{
    return blocker &&
        (blocker->class == BLOCKER_PERMANENT ||
         blocker->class == BLOCKER_RESOURCE);
}

/* ── Shared context (defined in api_controller.c) ── */

struct api_context {
    struct main_state *main_state;
    struct tx_mempool *mempool;
    struct coins_view_cache *coins_tip;
    struct node_db *node_db;
    const char *datadir;
};

struct api_rpc_backend {
    char user[128];
    char pass[128];
    int port;
};

extern struct api_context g_api_ctx;
extern struct api_rpc_backend g_api_rpc;
/* Serializes detached-worker generation start/stop across controller TUs. */
extern pthread_mutex_t g_api_worker_generation_mutex;

/* ── Versioned REST contract ── */

#define ZCL_REST_API_VERSION "v1"
#define ZCL_REST_API_BASE_PATH "/api/v1"
#define ZCL_REST_API_COMPAT_BASE_PATH "/api"
#define ZCL_REST_INDEX_SCHEMA "zcl.rest_index.v2"
#define ZCL_REST_OPENAPI_SCHEMA "zcl.openapi.v1"
#define ZCL_REST_ERROR_SCHEMA "zcl.rest_error.v1"
#define ZCL_REST_ROUTE_CONTRACT_SCHEMA "zcl.rest_route_contract.v1"
#define ZCL_APP_PROTOCOL_CONTRACT_SCHEMA \
    "zcl.application_protocol_contract.v2"
#define ZCL_APP_PROTOCOLS_INDEX_SCHEMA \
    "zcl.application_protocols.index.v2"
#define ZCL_SERVICE_CATALOG_SCHEMA "zcl.service_catalog.v2"
#define ZCL_SERVICE_CONTRACT_SCHEMA "zcl.service_contract.v2"
#define ZCL_SERVICE_RUNTIME_PROBE_SCHEMA "zcl.service_runtime_probe.v1"
#define ZCL_SERVICE_OPERATIONS_INDEX_SCHEMA "zcl.service_operations.index.v2"
#define ZCL_SERVICE_OPERATION_SCHEMA "zcl.service_operation.v2"
#define ZCL_NAMES_SERVICE_DIRECTORY_SCHEMA "zcl.names.service_directory.v1"
#define ZCL_QUERY_FILTER_CONTRACT_SCHEMA "zcl.query_filter_contract.v1"
#define API_QUERY_FILTER_SERVICE_OPERATIONS "service_operations"
#define API_QUERY_FILTER_NAME_SERVICE_DIRECTORY "name_service_directory"
#define ZCL_PATH_PARAM_CONTRACT_SCHEMA "zcl.path_param_contract.v1"
/* ZCL_PUBLIC_STATUS_SCHEMA lives in controllers/agent_operator_contracts.h —
 * one definition shared with the CLI reader that validates it. */
#define ZCL_MILESTONE_STATUS_SCHEMA "zcl.milestone_status.v2"
#define ZCL_REFOLD_STATUS_SCHEMA "zcl.refold_status.v2"

/* ── HTTP response headers (kept here so siblings can emit errors) ── */

#define SECURITY_HEADERS \
    "X-Content-Type-Options: nosniff\r\n" \
    "X-Frame-Options: DENY\r\n" \
    "Strict-Transport-Security: max-age=31536000\r\n"

#define JSON_HEADERS \
    "HTTP/1.1 200 OK\r\n" \
    "Content-Type: engine/application/json; charset=utf-8\r\n" \
    "Access-Control-Allow-Origin: *\r\n" \
    "Access-Control-Allow-Methods: GET, OPTIONS\r\n" \
    "Access-Control-Allow-Headers: Content-Type\r\n" \
    "Cache-Control: no-cache\r\n" \
    SECURITY_HEADERS \
    "Connection: close\r\n\r\n"

#define JSON_404_HEADERS \
    "HTTP/1.1 404 Not Found\r\n" \
    "Content-Type: engine/application/json; charset=utf-8\r\n" \
    "Access-Control-Allow-Origin: *\r\n" \
    "Connection: close\r\n\r\n"

#define JSON_500_HEADERS \
    "HTTP/1.1 500 Internal Server Error\r\n" \
    "Content-Type: engine/application/json; charset=utf-8\r\n" \
    "Access-Control-Allow-Origin: *\r\n" \
    "Connection: close\r\n\r\n"

#define JSON_503_HEADERS \
    "HTTP/1.1 503 Service Unavailable\r\n" \
    "Content-Type: engine/application/json; charset=utf-8\r\n" \
    "Access-Control-Allow-Origin: *\r\n" \
    "Retry-After: 10\r\n" \
    "Connection: close\r\n\r\n"

struct json_value;

#define API_QUERY_FILTER_MAX_FIELDS 6
#define API_QUERY_FILTER_VALUE_CAP 64

struct api_query_filter_contract_definition;

/* One private engine keeps HTTP and native collection filters aligned. */
struct api_query_filter {
    const struct api_query_filter_contract_definition *contract;
    char values[API_QUERY_FILTER_MAX_FIELDS][API_QUERY_FILTER_VALUE_CAP];
    char unknown_key[48];
    bool active;
};

struct api_freshness_meta {
    int64_t served_height;
    int64_t indexed_height;
    bool fresh;
    const char *freshness;
    const char *source_projection;
    const char *blocker;
};

struct api_app_protocol_contract {
    const char *name;
    const char *status;
    const char *layer;
    const char *base_layer;
    const char *family;
    const char *anchor;
    const char *anchor_kind;
    const char *rest_resource;
    const char *read_model;
    const char *crud_capabilities_csv;
    const char *construction_status;
    const char *mutation_authority;
    const char *write_semantics;
    const char *consensus_boundary;
    const char *object_types_csv;
    const char *ux_surfaces_csv;
    const char *projection_model;
    const char *reorg_model;
    const char *crypto_model;
    const char *transport_model;
    const char *privacy_model;
    const char *diagnostics_surface;
};

/* ── Helpers defined in api_controller.c ── */

size_t api_json_error(uint8_t *r, size_t max, const char *headers,
                  const char *message);
size_t api_json_status(uint8_t *r, size_t max, const char *status,
                       const struct json_value *body);
size_t api_json_ok(uint8_t *r, size_t max, const struct json_value *body);
const char *api_rest_index_body_json(void);
void api_rest_index_resources_json(struct json_value *resources);
void api_rest_index_cli_json(struct json_value *cli);
void api_rest_layer_model_json(struct json_value *layer_model);
const struct api_app_protocol_contract *
api_app_protocol_lookup(const char *name);
const struct api_app_protocol_contract *
api_app_protocol_for_resource(const char *resource);
void api_app_protocols_json(struct json_value *protocols);
void api_app_protocol_csv_json(const char *csv, struct json_value *out);
void api_app_protocol_crud_json(const struct api_app_protocol_contract *p,
                                struct json_value *crud);
bool api_app_protocols_index_json(struct json_value *out);
bool api_app_protocol_show_json(const char *name, struct json_value *out);
size_t api_serve_protocol_member(const char *name, const char *freshness,
                                 uint8_t *response, size_t response_max);
size_t api_serve_transaction_type_member(const char *type,
                                         const char *freshness,
                                         uint8_t *response,
                                         size_t response_max);
bool api_service_catalog_json(struct json_value *out);
bool api_service_catalog_show_json(const char *name, struct json_value *out);
bool api_service_catalog_has_service(const char *name);
bool api_service_runtime_probe_json_for_service(const char *name,
                                                struct json_value *out);
void api_service_catalog_error_json(const char *name, struct json_value *out);
void api_service_operations_json(struct json_value *out,
                                 const char *service_name);
bool api_service_operations_filtered_index_json(
    struct json_value *out,
    const char *service,
    const char *write_safety,
    const char *preferred_interface,
    const char *status,
    const char *surface,
    char *err,
    size_t err_len);
bool api_service_operations_index_path_json(const char *path,
                                            struct json_value *out,
                                            char *err,
                                            size_t err_len);
size_t api_serve_service_operations(const char *path,
                                    uint8_t *response,
                                    size_t response_max);
bool api_service_operation_show_json(const char *operation_id,
                                     struct json_value *out);
bool api_service_operation_has_id(const char *operation_id);
bool api_service_operation_for_rest_route(const char *method,
                                          const char *route,
                                          struct json_value *out);
void api_sovereign_ux_contract_json(struct json_value *out);
void api_app_protocol_push_openapi_extensions(
    const struct json_value *contract,
    struct json_value *operation);
const char *api_query_filter_contract_for_route(const char *method,
                                                const char *public_path);
void api_query_filter_init(struct api_query_filter *filter, const char *name);
void api_query_filter_set(struct api_query_filter *filter,
                          const char *key, const char *value);
void api_query_filter_from_path(struct api_query_filter *filter, const char *path);
bool api_query_filter_validate(const struct api_query_filter *filter,
                               char *err,
                               size_t err_len);
const char *api_query_filter_value(const struct api_query_filter *filter,
                                   const char *key);
bool api_query_filter_matches_value(const struct api_query_filter *filter,
                                    const char *canonical_key,
                                    const char *actual);
void api_query_filter_values_json(const struct api_query_filter *filter, struct json_value *out);
void api_query_filter_allowed_filters_json(const char *contract_name,
                                           struct json_value *out);
void api_query_filter_contract_json(const char *contract_name,
                                    struct json_value *out);
void api_query_filter_error_json(const char *contract_name,
                                 const char *message, struct json_value *out);
bool api_path_param_contracts_json(const char *method,
                                   const char *public_path,
                                   const char *alias_of,
                                   struct json_value *out);
int64_t api_served_tip_height(void);
void api_freshness_prepare(struct api_freshness_meta *out,
                           const char *source_projection,
                           int64_t indexed_height);
void api_freshness_push_json(struct json_value *obj,
                             const struct api_freshness_meta *freshness);
void api_json_add_freshness(struct json_value *obj,
                            const char *source_projection,
                            int64_t indexed_height);
void api_milestone_status_json(struct json_value *result);
void api_refold_status_json(struct json_value *result);
size_t api_serve_api_index(uint8_t *response, size_t response_max);
size_t api_serve_openapi(uint8_t *response, size_t response_max);
size_t api_serve_unsupported_version(const char *requested_version,
                                     uint8_t *response,
                                     size_t response_max);
int api_rpc_call(const char *method, const char *params_json,
             char *out, size_t outmax);
#ifdef ZCL_TESTING
typedef int (*api_test_rpc_call_fn)(const char *method,
                                    const char *params_json,
                                    char *out,
                                    size_t outmax);
void api_test_set_rpc_call(api_test_rpc_call_fn fn);
#endif
bool api_is_json_safe_param(const char *s, size_t maxlen);
struct node_db *api_node_db(void);
bool api_is_printable_ascii(const char *s);
bool api_parse_zslp_limit(const char *path, size_t *limit_out);
bool api_parse_collection_limit(const char *path, const char *query_key,
                                size_t default_limit, size_t max_limit,
                                size_t *limit_out);
bool api_start_detached_thread(pthread_t *thread_out,
                               void *(*entry)(void *),
                               void *arg);

/* #13 — cache-refresh thread supervision, defined in
 * api_controller_cache_liveness.c (split out for E1 file-size ceiling). */
void api_cache_register_supervisor(void);
void api_cache_supervisor_tick(void);
void api_cache_supervisor_quiesce(void);
void api_lookup_supervisor_quiesce(void);

#ifdef ZCL_TESTING
/* #13 supervision-coverage test seams (chain_integrity/api-controller
 * lint-gate remediation). See the "supervision for the detached ...
 * thread" block comments in api_controller.c / api_controller_lookup.c. */
void    api_cache_test_register_supervisor(void);
supervisor_child_id api_cache_test_supervisor_id(void);
int64_t api_cache_test_loop_ticks(void);
void    api_cache_test_force_stall(void);
void    api_lookup_test_register_supervisor(void);
supervisor_child_id api_lookup_test_supervisor_id(void);
void    api_lookup_test_force_stall(void);
#endif

/* ── Resource route registry (defined in api_controller_routes.c) ── */

typedef size_t (*api_route_handler)(uint8_t *response, size_t response_max);
typedef void (*api_route_contract_visit_fn)(
    void *ctx,
    const char *method,
    const char *path,
    const char *resource,
    const char *action,
    const char *response_schema,
    const char *query_params_csv,
    const char *freshness,
    const char *alias_of,
    bool private_route,
    const char *command_path);

/* command_path names the native command registry leaf (engine/composition/commands
 * dot-def files, e.g. "core.status") that owns the same data/service this
 * route serves. When no native leaf owns it, this is "none:<short-reason>"
 * — never a guessed mapping. Checked by
 * tools/lint/check_route_command_parity.sh against
 * tools/lint/route_command_parity_baseline.txt. */
struct api_resource_route {
    const char *method;
    const char *path;
    const char *resource;
    const char *action;
    api_route_handler handler;
    const char *response_schema;
    const char *query_params_csv;
    const char *freshness;
    const char *alias_of;
    bool private_route;
    const char *command_path;
};

const char *api_canonical_route_path(const char *path, char *buf,
                                     size_t buf_len);
bool api_path_has_unsupported_version(const char *path,
                                      char *version_out,
                                      size_t version_out_len);
const struct api_resource_route *
api_resource_route_find(const char *method, const char *path);
bool api_route_registry_is_private(const char *path);
void api_route_registry_visit(api_route_contract_visit_fn visit, void *ctx);
/* Public REST dynamic-dispatch entry. This is a hot-swap TRAMPOLINE
 * (engine/controllers/src/api_controller_dispatch.c): it acquire-loads an
 * atomic provider and, if a dev generation .so has installed one, delegates
 * to it; otherwise it calls the resident built-in below. See
 * docs/work/HOTSWAP.md and ZCL_HOTSWAP_EXPORT_PROVIDER. */
size_t api_resource_route_dispatch_dynamic(const char *method,
                                           const char *path,
                                           uint8_t *response,
                                           size_t response_max,
                                           bool *handled);

/* The resident built-in REST dynamic dispatch (the static route tables live
 * in the swap-eligible api_controller_routes.c). The trampoline calls this
 * when no provider is installed; a generation .so installs its own recompiled
 * copy of this symbol as the provider. */
size_t api_resource_route_dispatch_builtin(const char *method,
                                           const char *path,
                                           uint8_t *response,
                                           size_t response_max,
                                           bool *handled);

/* Matches api_resource_route_dispatch_builtin — the swap unit for REST. */
typedef size_t (*api_resource_dispatch_fn)(const char *method,
                                           const char *path,
                                           uint8_t *response,
                                           size_t response_max,
                                           bool *handled);

#ifdef ZCL_DEV_BUILD
/* DEV-ONLY: atomically re-point the resident REST dispatch provider at `fn`
 * (release store; the trampoline reads it with an acquire load). Lives in the
 * RESIDENT trampoline TU so a generation .so reaches it as an undefined symbol
 * that binds to the executable's copy. Returns false on a NULL fn. Used only
 * by the Tier-1 hot-swap generation entrypoint + tests. */
bool api_resource_dispatch_replace(api_resource_dispatch_fn fn);
#endif

size_t api_route_contract_count(void);
void api_route_contracts_json(struct json_value *out);

size_t api_route_blocks(uint8_t *response, size_t response_max);
size_t api_route_stats(uint8_t *response, size_t response_max);
size_t api_route_deep_stats(uint8_t *response, size_t response_max);
size_t api_route_supply(uint8_t *response, size_t response_max);
size_t api_route_supply_legacy(uint8_t *response, size_t response_max);
size_t api_route_hodl(uint8_t *response, size_t response_max);
size_t api_route_factoids(uint8_t *response, size_t response_max);
size_t api_serve_builds(uint8_t *response, size_t response_max);
size_t api_serve_build_workers(uint8_t *response, size_t response_max);
size_t api_serve_build(const char *job_id, uint8_t *response,
                       size_t response_max);
size_t api_serve_build_actions(const char *job_id, uint8_t *response,
                               size_t response_max);
size_t api_serve_build_receipt(const char *receipt_id, uint8_t *response,
                               size_t response_max);

/* ── Compute handlers (defined in api_controller_compute.c) ── */

size_t compute_blocks(uint8_t *r, size_t max);
size_t compute_stats(uint8_t *r, size_t max);
size_t compute_supply(uint8_t *r, size_t max);
size_t compute_supply_legacy(uint8_t *r, size_t max);
size_t compute_hodl(uint8_t *r, size_t max);
size_t compute_hodl_cache_refresh(uint8_t *r, size_t max);
int64_t api_hodl_index_tip_height(void);
int64_t api_hodl_current_tip_height(void);
bool api_hodl_index_ahead_of_served(int64_t *index_tip_out,
                                    int64_t *served_tip_out);
size_t compute_deep_stats(uint8_t *r, size_t max);
size_t compute_deep_stats_cache_refresh(uint8_t *r, size_t max);

#ifdef ZCL_TESTING
int api_cache_test_sqlite_progress(void *ctx);
#endif

/* ── Lookup handlers (defined in api_controller_lookup.c) ── */

enum lookup_type {
    LOOKUP_NONE = 0,
    LOOKUP_BLOCK,
    LOOKUP_TX,
    LOOKUP_ADDRESS,
};

size_t compute_block(const char *param, uint8_t *r, size_t max);
size_t compute_tx(const char *param, uint8_t *r, size_t max);
size_t compute_address(const char *param, uint8_t *r, size_t max);

size_t do_lookup(enum lookup_type type, const char *param,
                 uint8_t *response, size_t response_max);
void api_lookup_stop(void);
#ifdef ZCL_TESTING
bool api_lookup_test_worker_alive(void);
#endif

/* ── Resource collection handlers (defined in api_controller_resources.c) ── */

size_t api_serve_zslp_tokens(const char *path, uint8_t *response,
                             size_t response_max);
size_t api_serve_zslp_token(const char *token_id, uint8_t *response,
                            size_t response_max);
size_t api_serve_zslp_token_transfers(const char *path, const char *token_id,
                                      uint8_t *response, size_t response_max);
size_t api_serve_onion_announcements(const char *path, uint8_t *response,
                                     size_t response_max);
size_t api_serve_file_services(const char *path, uint8_t *response,
                               size_t response_max);
size_t api_serve_peers(const char *path, uint8_t *response,
                       size_t response_max);

/* ── Node / diagnostics route handlers (defined in api_controller_node.c) ──
 * None touch the background cache buffers in api_controller.c — they read
 * g_api_ctx + lock-free atomics and write directly into the caller's
 * response buffer, so the router's cache semantics are unchanged. */

size_t api_serve_events(const char *path, uint8_t *response,
                        size_t response_max);
size_t api_serve_syncstate(uint8_t *response, size_t response_max);
size_t api_serve_downloadstats(uint8_t *response, size_t response_max);
size_t api_serve_health(uint8_t *response, size_t response_max);
size_t api_serve_node_snapshot(uint8_t *response, size_t response_max);
size_t api_serve_node_mmb(uint8_t *response, size_t response_max);
size_t api_serve_node_summary(uint8_t *response, size_t response_max);
size_t api_serve_milestone(uint8_t *response, size_t response_max);
size_t api_serve_refold_status(uint8_t *response, size_t response_max);
size_t api_serve_node_status(uint8_t *response, size_t response_max);
size_t api_serve_wallet(uint8_t *response, size_t response_max);
size_t api_serve_files_manifest(uint8_t *response, size_t response_max);
size_t api_serve_file_chunk(const char *hex, uint8_t *response,
                            size_t response_max);

#endif
