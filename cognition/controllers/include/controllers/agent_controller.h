/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_AGENT_H
#define ZCL_CONTROLLERS_AGENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct json_value;

struct agent_contract {
    const char *method;
    const char *capability;
    const char *schema;
    const char *native_command;
    const char *rest_route;
    const char *api_cli_field;
    const char *ops_surface;
    int ops_rank;
    const char *ops_name;
    const char *ops_purpose;
    const char *purpose;
};

struct agent_operator_lane_topology {
    const char *lane;
    const char *unit;
    const char *datadir;
    int rpc_port;
    int p2p_port;
    int https_port;
    int fs_port;
    const char *role;
    const char *binary_role;
    const char *deploy_command;
    const char *restart_command;
};

/* Set once from node-mode main after CLI/env parsing and before app_init()
 * starts RPC-serving threads. Tests may reset the context directly. */
void rpc_agent_set_boot_context(const char *operator_lane,
                                const char *runtime_profile,
                                const char *datadir,
                                int rpc_port, int p2p_port,
                                int https_port, int fs_port);
const char *agent_runtime_context_datadir(void);
const char *agent_runtime_context_operator_lane(void);
void agent_fill_operator_lane_contract_json(struct json_value *lane_obj,
                                            const char *operator_lane,
                                            const char *runtime_profile,
                                            const char *datadir,
                                            int rpc_port, int p2p_port,
                                            int https_port, int fs_port);
size_t agent_operator_lane_topology_count(void);
const struct agent_operator_lane_topology *
agent_operator_lane_topology_at(size_t index);
const struct agent_operator_lane_topology *
agent_operator_lane_topology_lookup(const char *operator_lane);
const struct agent_operator_lane_topology *
agent_operator_lane_topology_match_runtime(const char *datadir, int rpc_port,
                                           int p2p_port);
void agent_push_operator_lane_safety_fields_json(struct json_value *out,
                                                 const char *operator_lane);
bool agent_fill_known_operator_lane_contract_json(struct json_value *lane_obj,
                                                  const char *operator_lane);
void agent_fill_operator_lane_topology_json(
    struct json_value *lane_obj,
    const struct agent_operator_lane_topology *topology);
size_t agent_contract_count(void);
const struct agent_contract *agent_contract_at(size_t index);
const struct agent_contract *agent_contract_lookup(const char *method);
const char *agent_contract_probe_params_json(const char *method);
bool agent_push_contract_json(struct json_value *arr,
                              const struct agent_contract *contract);
void agent_push_contracts_json(struct json_value *arr);
void agent_push_contract_summary_json(struct json_value *out,
                                      const char *key);
void agent_push_contract_transport_summary_json(struct json_value *arr);
bool agent_push_contract_capability_json(struct json_value *arr,
                                         const char *method,
                                         const char *name_override,
                                         const char *purpose_override);
void agent_push_contract_capabilities_json(struct json_value *arr);
void agent_push_contract_ops_surface_json(struct json_value *arr,
                                          const char *surface);
size_t agent_contract_command_surface_count(const char *surface);
size_t agent_push_contract_command_surface_json(struct json_value *arr,
                                                const char *surface);
size_t agent_contract_field_surface_count(const char *surface);
size_t agent_push_contract_field_surface_json(struct json_value *obj,
                                              const char *surface);
size_t agent_contract_work_surface_count(const char *surface);
size_t agent_push_contract_work_surface_json(struct json_value *arr,
                                             const char *surface);
size_t agent_contract_review_surface_total_count(void);
size_t agent_contract_review_surface_count(const char *surface);
size_t agent_push_contract_review_surface_json(struct json_value *obj,
                                               const char *surface);
size_t agent_contract_schema_surface_count(void);
size_t agent_push_contract_schema_surface_json(struct json_value *arr);
bool agent_push_contract_command_json(struct json_value *arr,
                                      const char *name,
                                      const char *method,
                                      const char *purpose_override);
bool agent_push_contract_native_field_json(struct json_value *obj,
                                           const char *key,
                                           const char *method);
size_t agent_push_contract_identity_fields_json(struct json_value *obj,
                                                const char *method);
bool agent_push_contract_native_command_json(struct json_value *arr,
                                             const char *method);
void agent_push_contract_api_cli_fields_json(struct json_value *obj);
void agent_print_native_usage(FILE *out, const char *prog);
void agent_push_operator_lane_fields_json(struct json_value *out);
void agent_push_operator_lane_json(struct json_value *out,
                                   const char *key);
void agent_push_runtime_build_json(struct json_value *out,
                                   const char *key);
void agent_push_runtime_services_json(struct json_value *out,
                                      const char *key);
void agent_runtime_availability_reset(void);
void agent_runtime_availability_begin_probe(const char *source,
                                            const char *datadir,
                                            int rpc_port,
                                            const char *status);
void agent_runtime_availability_set_probe_status(const char *status);
void agent_runtime_availability_record_method(const char *method,
                                              const char *support,
                                              int64_t rpc_error_code,
                                              const char *error_message);
void agent_runtime_availability_set_target_build_commit(
    const char *build_commit);
void agent_runtime_availability_set_target_source_id_sha256(
    const char *source_id_sha256);
size_t agent_runtime_probe_method_count(void);
const char *agent_runtime_probe_method_name(size_t index);
void agent_push_runtime_availability_json(struct json_value *out,
                                          const char *key);

bool rpc_agent_map(const struct json_value *params, bool help,
                   struct json_value *result);
bool rpc_agent_lanes(const struct json_value *params, bool help,
                     struct json_value *result);
bool rpc_agent_liveness(const struct json_value *params, bool help,
                        struct json_value *result);
bool rpc_agent_impact(const struct json_value *params, bool help,
                      struct json_value *result);
bool rpc_agent_contracts(const struct json_value *params, bool help,
                         struct json_value *result);
bool rpc_agent_build(const struct json_value *params, bool help,
                     struct json_value *result);
bool rpc_agent_dev_status(const struct json_value *params, bool help,
                          struct json_value *result);
bool rpc_agent_interface(const struct json_value *params, bool help,
                         struct json_value *result);
bool rpc_agent_deploy_guard(const struct json_value *params, bool help,
                            struct json_value *result);
bool rpc_agent_ops(const struct json_value *params, bool help,
                   struct json_value *result);
bool rpc_agent_diagnose(const struct json_value *params, bool help,
                        struct json_value *result);
bool rpc_agent_anchor_status(const struct json_value *params, bool help,
                             struct json_value *result);
bool rpc_agent_proof_bundle(const struct json_value *params, bool help,
                            struct json_value *result);
bool rpc_app_protocols(const struct json_value *params, bool help,
                       struct json_value *result);
bool rpc_service_catalog(const struct json_value *params, bool help,
                         struct json_value *result);
bool rpc_service_operations(const struct json_value *params, bool help,
                            struct json_value *result);

#endif
