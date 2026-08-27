/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared fixtures for the API controller test group.
 *
 * The group is split across test_api_*.c by the API area under test; every
 * one of those files builds requests, seeds chains, and reads JSON the same
 * way, so the helpers live here once and are defined in test_api_fixtures.c.
 * test_api.c is the dispatcher that runs the areas in order. */

#ifndef TEST_API_TEST_FIXTURES_H
#define TEST_API_TEST_FIXTURES_H

#include "test/test_core.h"
#include "coins/undo.h"
#include "models/block.h"
#include "models/utxo.h"
#include "models/peer.h"
#include "models/zslp.h"
#include "models/onion_announcement.h"
#include "controllers/agent_background_quality.h"
#include "controllers/agent_controller.h"
#include "controllers/agent_security_posture.h"
#include "controllers/api_controller.h"
#include "controllers/download_stats_json.h"
#include "controllers/explorer_internal.h"
#include "controllers/file_controller.h"
#include "controllers/misc_controller.h"
#include "controllers/name_controller.h"
#include "controllers/network_controller.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "models/file_service.h"
#include "models/znam.h"
#include "net/connman.h"
#include "net/fast_sync.h"
#include "net/net.h"
#include "net/peer_lifecycle.h"
#include "net/version.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "services/block_source_policy.h"
#include "services/node_health_service.h"
#include "storage/progress_store.h"
#include "sync/sync_state.h"
#include "util/alerts.h"
#include "util/blocker.h"
#include "storage/body_history.h"
#include "util/clientversion.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

size_t api_json_error(uint8_t *r, size_t max, const char *headers,
                      const char *message);
size_t api_resource_route_count(void);
const char *api_resource_route_resource_at(size_t i);
const char *api_resource_route_action_at(size_t i);
const char *api_resource_route_command_path_at(size_t i);
size_t api_route_contract_count(void);
size_t api_dynamic_resource_route_count(void);
const char *api_dynamic_resource_route_pattern_at(size_t i);
const char *api_dynamic_resource_route_resource_at(size_t i);
const char *api_dynamic_resource_route_action_at(size_t i);
void api_test_seed_supply_caches(const char *canonical, const char *legacy);
size_t compute_deep_stats(uint8_t *r, size_t max);
typedef int (*api_test_rpc_call_fn)(const char *method,
                                    const char *params_json,
                                    char *out,
                                    size_t outmax);
void api_test_set_rpc_call(api_test_rpc_call_fn fn);

#define API_TEST_BLOCK_HASH \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define API_TEST_PREV_HASH \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define API_TEST_NEXT_HASH \
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
#define API_TEST_TXID \
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
#define API_TEST_TXID2 \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
#define API_TEST_ADDR "t1TestLookupAddr0000000000"

/* Shared fixtures — defined once in test_api_fixtures.c. */
const char *api_test_datadir(void);
int api_test_write_rpc(char *out, size_t outmax, const char *json);
int api_test_lookup_rpc(const char *method,
                        const char *params_json,
                        char *out,
                        size_t outmax);
const struct json_value *api_test_find_contract(
    const struct json_value *routes,
    const char *path);
bool api_test_contract_has_query(const struct json_value *contract,
                                 const char *name);
bool api_test_contract_has_id_param(const struct json_value *contract,
                                    const char *name);
bool api_test_array_has_str(const struct json_value *arr,
                            const char *needle);
const struct json_value *api_test_find_named(
    const struct json_value *arr,
    const char *name);
const struct json_value *api_test_find_str_field(
    const struct json_value *arr,
    const char *field,
    const char *value);
bool api_test_runtime_probes_consistent(
    const struct json_value *catalog,
    const struct json_value *operations,
    const struct json_value *route_contracts);
bool api_test_rest_operation_route_matches(
    const struct json_value *operation,
    const struct json_value *route_contract,
    const char *expected_route);
bool api_test_rest_service_operations_bound(
    const struct json_value *operations,
    const struct json_value *route_contracts);
bool api_test_expect_readiness_shape(const struct json_value *root);
bool api_test_expect_security_posture_shape(
    const struct json_value *root);
bool api_test_expect_lane_safety_fields(
    const struct json_value *root, const char *lane,
    bool restart_ok, bool deploy_ok, bool requires,
    const char *target, const char *action);
const struct json_value *api_test_openapi_get(
    const struct json_value *root,
    const char *path);
bool api_test_openapi_has_param(const struct json_value *operation,
                                const char *name,
                                const char *location);
struct block_index *api_test_insert_block(struct main_state *ms,
                                          struct uint256 *hash,
                                          int height,
                                          struct block_index *prev);
bool api_test_build_chain(struct main_state *ms,
                          struct block_index **out,
                          int count);
bool api_test_seed_durable_tip(const char *dir, int height);
bool api_test_init_connman_peer(struct connman *cm,
                                struct net_address *addr,
                                struct p2p_node **node_out,
                                int height);
const char *api_test_body(uint8_t *resp, size_t n, size_t cap);
bool api_test_expect_freshness(const struct json_value *root,
                               const char *source_projection,
                               int64_t served_height,
                               int64_t indexed_height,
                               bool fresh);
bool api_test_save_model_block(struct node_db *ndb, int height,
                               uint8_t seed);
bool api_test_save_model_utxo(struct node_db *ndb, int height,
                              uint8_t seed, int64_t value);

/* One entry point per API area; each returns its failure count and is run
 * in order by test_api(). */
int api_query_filters_focused_tests(void);
int api_controller_supervision_focused_tests(void);
int api_http_contract_focused_tests(void);
int api_znam_routes_focused_tests(void);
int api_msg_routes_focused_tests(void);
int api_rest_index_focused_tests(void);
int api_catalog_focused_tests(void);
int api_transaction_type_focused_tests(void);
int api_openapi_focused_tests(void);
int api_route_table_focused_tests(void);
int api_status_focused_tests(void);
int api_health_gate_focused_tests(void);
int api_supply_focused_tests(void);
int api_resource_reads_focused_tests(void);
int api_access_focused_tests(void);

#endif /* TEST_API_TEST_FIXTURES_H */
