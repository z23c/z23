/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Operator lane topology and safety contracts for the agent API. */

#include "controllers/agent_controller.h"

#include "json/json.h"
#include "storage/boot_auto_reindex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const struct agent_operator_lane_topology g_operator_lane_topologies[] = {
    {
        .lane = "canonical",
        .unit = "zclassic23",
        .datadir = "~/.zclassic-c23",
        .rpc_port = 18232,
        .p2p_port = 8033,
        .https_port = 8443,
        .fs_port = 0,
        .role = "public daily-driver",
        .binary_role = "long_running_public_node",
        .deploy_command = "make deploy requires explicit canonical guard",
        .restart_command = "operator window only",
    },
    {
        .lane = "soak",
        .unit = "zclassic23-soak",
        .datadir = "~/.zclassic-c23-soak",
        .rpc_port = 18242,
        .p2p_port = 8043,
        .https_port = 0,
        .fs_port = 0,
        .role = "long-uptime evidence",
        .binary_role = "pinned_binary_soak_lane",
        .deploy_command = "manual rebaseline only",
        .restart_command = "operator window only",
    },
    {
        .lane = "dev",
        .unit = "zcl23-dev",
        .datadir = "~/.zclassic-c23-dev",
        .rpc_port = 18252,
        .p2p_port = 8053,
        .https_port = 0,
        .fs_port = 18034,
        .role = "fresh-build development",
        .binary_role = "restartable_development_lane",
        .deploy_command = "make deploy-dev",
        .restart_command = "make deploy-dev or systemctl --user restart zcl23-dev",
    },
};

static bool agent_lane_is(const char *lane, const char *want)
{
    return lane && want && strcmp(lane, want) == 0;
}

static const char *agent_lane_restart_policy(const char *lane)
{
    if (agent_lane_is(lane, "canonical"))
        return "operator_gated";
    if (agent_lane_is(lane, "soak"))
        return "restart_rebaselines_soak";
    if (agent_lane_is(lane, "dev"))
        return "frequent_deploy_ok";
    if (agent_lane_is(lane, "test") || agent_lane_is(lane, "copy"))
        return "ephemeral";
    return "unspecified";
}

static const char *agent_lane_safety_contract(const char *lane)
{
    if (agent_lane_is(lane, "canonical"))
        return "protect_long_running_public_node";
    if (agent_lane_is(lane, "soak"))
        return "preserve_clean_soak_window";
    if (agent_lane_is(lane, "dev"))
        return "exercise_fresh_binary_without_touching_canonical";
    if (agent_lane_is(lane, "test"))
        return "isolated_test_node";
    if (agent_lane_is(lane, "copy"))
        return "copy_proof_only_never_live_datadir";
    return "lane_not_declared";
}

static bool agent_lane_automation_restart_ok(const char *lane)
{
    return agent_lane_is(lane, "dev") ||
           agent_lane_is(lane, "test") ||
           agent_lane_is(lane, "copy");
}

static bool agent_lane_automation_deploy_ok(const char *lane)
{
    return agent_lane_is(lane, "dev") ||
           agent_lane_is(lane, "test");
}

static bool agent_lane_requires_operator_confirmation(const char *lane)
{
    return agent_lane_is(lane, "canonical") ||
           agent_lane_is(lane, "soak") ||
           agent_lane_is(lane, "unknown");
}

static bool agent_lane_is_isolated_from_canonical(const char *lane)
{
    return agent_lane_is(lane, "soak") ||
           agent_lane_is(lane, "dev") ||
           agent_lane_is(lane, "test") ||
           agent_lane_is(lane, "copy");
}

static const char *agent_lane_preferred_deploy_target(const char *lane)
{
    if (agent_lane_is(lane, "canonical") || agent_lane_is(lane, "soak"))
        return "dev";
    if (agent_lane_is(lane, "dev"))
        return "dev";
    if (agent_lane_is(lane, "test"))
        return "test";
    if (agent_lane_is(lane, "copy"))
        return "copy_fixture";
    return "declare_lane_first";
}

static const char *agent_lane_guard_env(const char *lane)
{
    if (agent_lane_is(lane, "canonical"))
        return "ZCL_DEPLOY_ALLOW_CANONICAL";
    if (agent_lane_is(lane, "soak"))
        return "ZCL_DEPLOY_ALLOW_SOAK";
    if (agent_lane_is(lane, "unknown"))
        return "ZCL_OPERATOR_LANE";
    return "";
}

static const char *agent_lane_safe_default_action(const char *lane)
{
    if (agent_lane_is(lane, "canonical"))
        return "observe_only_or_use_dev_lane";
    if (agent_lane_is(lane, "soak"))
        return "preserve_soak_window";
    if (agent_lane_is(lane, "dev"))
        return "deploy_dev_lane";
    if (agent_lane_is(lane, "test"))
        return "run_test_fixture";
    if (agent_lane_is(lane, "copy"))
        return "prove_on_copy";
    return "refuse_automation_until_lane_declared";
}

static const char *agent_lane_recovery_override_env(const char *lane)
{
    if (agent_lane_is(lane, "dev"))
        return "ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY";
    return "";
}

size_t agent_operator_lane_topology_count(void)
{
    return sizeof(g_operator_lane_topologies) /
           sizeof(g_operator_lane_topologies[0]);
}

const struct agent_operator_lane_topology *
agent_operator_lane_topology_at(size_t index)
{
    if (index >= agent_operator_lane_topology_count())
        return NULL;
    return &g_operator_lane_topologies[index];
}

const struct agent_operator_lane_topology *
agent_operator_lane_topology_lookup(const char *operator_lane)
{
    if (!operator_lane || !operator_lane[0])
        return NULL;
    for (size_t i = 0; i < agent_operator_lane_topology_count(); i++) {
        if (strcmp(g_operator_lane_topologies[i].lane, operator_lane) == 0)
            return &g_operator_lane_topologies[i];
    }
    return NULL;
}

static bool agent_lane_expand_topology_datadir(const char *path,
                                               char *out, size_t out_len)
{
    if (!path || !out || out_len == 0)
        return false; // raw-return-ok:optional-lane-datadir-expansion
    if (strncmp(path, "~/", 2) == 0) {
        const char *home = getenv("HOME");
        if (!home || !home[0])
            return false; // raw-return-ok:optional-lane-datadir-expansion
        int n = snprintf(out, out_len, "%s/%s", home, path + 2);
        return n > 0 && (size_t)n < out_len;
    }
    int n = snprintf(out, out_len, "%s", path);
    return n >= 0 && (size_t)n < out_len;
}

static bool agent_lane_datadir_matches_topology(const char *datadir,
                                                const char *topology_path)
{
    char expanded[1024];
    if (!datadir || !datadir[0] || !topology_path || !topology_path[0])
        return false;
    if (strcmp(datadir, topology_path) == 0)
        return true;
    if (!agent_lane_expand_topology_datadir(topology_path, expanded,
                                            sizeof(expanded)))
        return false;
    return strcmp(datadir, expanded) == 0;
}

static bool agent_lane_auto_reindex_path(const char *datadir,
                                         char *expanded, size_t expanded_len,
                                         char *marker, size_t marker_len)
{
    if (expanded && expanded_len > 0)
        expanded[0] = '\0';
    if (marker && marker_len > 0)
        marker[0] = '\0';
    if (!datadir || !datadir[0] || !expanded || expanded_len == 0 ||
        !marker || marker_len == 0)
        return false; // raw-return-ok:optional-lane-recovery-path
    if (!agent_lane_expand_topology_datadir(datadir, expanded, expanded_len))
        return false; // raw-return-ok:optional-lane-recovery-path
    int n = snprintf(marker, marker_len, "%s/auto_reindex_request",
                     expanded);
    return n > 0 && (size_t)n < marker_len;
}

static void agent_lane_push_recovery_state_json(struct json_value *lane_obj,
                                                const char *lane,
                                                const char *datadir)
{
    struct json_value recovery;
    char expanded[1024];
    char marker[1152];
    int32_t anchor = 0;
    int count = 0;
    bool path_ok = agent_lane_auto_reindex_path(datadir, expanded,
                                                sizeof(expanded), marker,
                                                sizeof(marker));
    bool marker_exists = path_ok && access(marker, F_OK) == 0;
    bool well_formed = path_ok &&
        boot_auto_reindex_status(expanded, &anchor, &count);
    bool pending = well_formed && count > 0;
    bool terminal = well_formed && count == BOOT_AUTO_REINDEX_TERMINAL;
    bool malformed = marker_exists && !well_formed;
    bool deploy_blocker = pending;
    const char *status = "clean";
    const char *next_action = "normal deploy guard rules apply";

    if (!path_ok) {
        status = "unknown_datadir";
        next_action = "declare lane datadir before deploy";
    } else if (pending) {
        status = "pending_auto_reindex";
        next_action = agent_lane_is(lane, "dev")
            ? "run deliberate dev recovery boot with ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY=1, or prove marker stale before clearing"
            : "inspect pending auto-reindex marker before deploy";
    } else if (terminal) {
        status = "terminal_auto_reindex";
        next_action = "operator already paged; inspect blocks and clear only after repair";
    } else if (malformed) {
        status = "malformed_auto_reindex_marker";
        next_action = "inspect auto_reindex_request before deploy";
    }

    json_init(&recovery);
    json_set_object(&recovery);
    json_push_kv_str(&recovery, "schema", "zcl.operator_lane_recovery.v1");
    json_push_kv_int(&recovery, "schema_version", 1);
    json_push_kv_str(&recovery, "status", status);
    json_push_kv_bool(&recovery, "state_available", path_ok);
    json_push_kv_str(&recovery, "datadir", path_ok ? expanded : datadir);
    json_push_kv_str(&recovery, "auto_reindex_marker_path",
                     path_ok ? marker : "");
    json_push_kv_bool(&recovery, "auto_reindex_marker_present",
                      marker_exists);
    json_push_kv_bool(&recovery, "auto_reindex_status_well_formed",
                      well_formed);
    json_push_kv_bool(&recovery, "auto_reindex_pending", pending);
    json_push_kv_bool(&recovery, "auto_reindex_terminal", terminal);
    json_push_kv_bool(&recovery, "auto_reindex_malformed", malformed);
    json_push_kv_int(&recovery, "auto_reindex_anchor", anchor);
    json_push_kv_int(&recovery, "auto_reindex_count", count);
    json_push_kv_bool(&recovery, "deploy_blocker", deploy_blocker);
    json_push_kv_str(&recovery, "deploy_blocker_reason",
                     deploy_blocker
                         ? "pending_auto_reindex_requires_explicit_recovery_boot"
                         : "");
    json_push_kv_str(&recovery, "explicit_recovery_env",
                     agent_lane_recovery_override_env(lane));
    json_push_kv_str(&recovery, "safe_next_action", next_action);
    json_push_kv(lane_obj, "recovery_state", &recovery);
    json_free(&recovery);
}

const struct agent_operator_lane_topology *
agent_operator_lane_topology_match_runtime(const char *datadir, int rpc_port,
                                           int p2p_port)
{
    if (!datadir || !datadir[0] || rpc_port <= 0 || p2p_port <= 0)
        return NULL;
    for (size_t i = 0; i < agent_operator_lane_topology_count(); i++) {
        const struct agent_operator_lane_topology *topology =
            agent_operator_lane_topology_at(i);
        if (!topology)
            continue;
        if (topology->rpc_port != rpc_port || topology->p2p_port != p2p_port)
            continue;
        if (!agent_lane_datadir_matches_topology(datadir, topology->datadir))
            continue;
        return topology;
    }
    return NULL;
}

void agent_push_operator_lane_safety_fields_json(struct json_value *out,
                                                 const char *operator_lane)
{
    if (!out)
        return;
    const char *lane =
        operator_lane && operator_lane[0] ? operator_lane : "unknown";
    json_push_kv_bool(out, "automation_restart_ok",
                      agent_lane_automation_restart_ok(lane));
    json_push_kv_bool(out, "automation_deploy_ok",
                      agent_lane_automation_deploy_ok(lane));
    json_push_kv_bool(out, "requires_operator_confirmation",
                      agent_lane_requires_operator_confirmation(lane));
    json_push_kv_str(out, "preferred_deploy_target",
                     agent_lane_preferred_deploy_target(lane));
    json_push_kv_str(out, "safe_default_action",
                     agent_lane_safe_default_action(lane));
}

void agent_fill_operator_lane_contract_json(struct json_value *lane_obj,
                                            const char *operator_lane,
                                            const char *runtime_profile,
                                            const char *datadir,
                                            int rpc_port, int p2p_port,
                                            int https_port, int fs_port)
{
    if (!lane_obj)
        return;
    const char *lane =
        operator_lane && operator_lane[0] ? operator_lane : "unknown";
    const bool canonical = agent_lane_is(lane, "canonical");
    const bool soak = agent_lane_is(lane, "soak");
    const bool dev = agent_lane_is(lane, "dev");
    const bool ephemeral = agent_lane_is(lane, "test") ||
                           agent_lane_is(lane, "copy");
    const bool automation_restart_ok =
        agent_lane_automation_restart_ok(lane);
    const bool automation_deploy_ok =
        agent_lane_automation_deploy_ok(lane);
    const bool requires_operator_confirmation =
        agent_lane_requires_operator_confirmation(lane);
    struct json_value safety;

    json_set_object(lane_obj);
    json_push_kv_str(lane_obj, "schema", "zcl.operator_lane.v1");
    json_push_kv_int(lane_obj, "schema_version", 1);
    json_push_kv_str(lane_obj, "lane", lane);
    json_push_kv_str(lane_obj, "runtime_profile",
                     runtime_profile && runtime_profile[0]
                         ? runtime_profile : "unknown");
    json_push_kv_str(lane_obj, "datadir", datadir ? datadir : "");
    json_push_kv_int(lane_obj, "rpcport", rpc_port);
    json_push_kv_int(lane_obj, "p2p_port", p2p_port);
    json_push_kv_int(lane_obj, "https_port", https_port);
    json_push_kv_int(lane_obj, "fs_port", fs_port);
    json_push_kv_bool(lane_obj, "canonical", canonical);
    json_push_kv_bool(lane_obj, "soak_evidence", soak);
    json_push_kv_bool(lane_obj, "development", dev);
    json_push_kv_bool(lane_obj, "ephemeral", ephemeral);
    json_push_kv_str(lane_obj, "restart_policy",
                     agent_lane_restart_policy(lane));
    json_push_kv_str(lane_obj, "safety_contract",
                     agent_lane_safety_contract(lane));
    json_push_kv_bool(lane_obj, "automation_restart_ok",
                      automation_restart_ok);
    json_push_kv_bool(lane_obj, "automation_deploy_ok",
                      automation_deploy_ok);
    json_push_kv_bool(lane_obj, "requires_operator_confirmation",
                      requires_operator_confirmation);

    json_init(&safety);
    json_set_object(&safety);
    json_push_kv_str(&safety, "schema",
                     "zcl.operator_deployment_safety.v1");
    json_push_kv_int(&safety, "schema_version", 1);
    json_push_kv_bool(&safety, "automation_restart_ok",
                      automation_restart_ok);
    json_push_kv_bool(&safety, "automation_deploy_ok",
                      automation_deploy_ok);
    json_push_kv_bool(&safety, "requires_operator_confirmation",
                      requires_operator_confirmation);
    json_push_kv_bool(&safety, "protects_public_endpoint", canonical);
    json_push_kv_bool(&safety, "counts_for_soak_hours", soak);
    json_push_kv_bool(&safety, "isolated_from_canonical_datadir",
                      agent_lane_is_isolated_from_canonical(lane));
    json_push_kv_str(&safety, "preferred_deploy_target",
                     agent_lane_preferred_deploy_target(lane));
    json_push_kv_str(&safety, "guard_env",
                     agent_lane_guard_env(lane));
    json_push_kv_str(&safety, "safe_default_action",
                     agent_lane_safe_default_action(lane));
    json_push_kv(lane_obj, "deployment_safety", &safety);
    json_free(&safety);

    agent_lane_push_recovery_state_json(lane_obj, lane, datadir);
}

bool agent_fill_known_operator_lane_contract_json(struct json_value *lane_obj,
                                                  const char *operator_lane)
{
    const struct agent_operator_lane_topology *topology =
        agent_operator_lane_topology_lookup(operator_lane);
    if (!topology)
        return false;
    agent_fill_operator_lane_contract_json(lane_obj, topology->lane, "full",
                                           topology->datadir,
                                           topology->rpc_port,
                                           topology->p2p_port,
                                           topology->https_port,
                                           topology->fs_port);
    return true;
}

void agent_fill_operator_lane_topology_json(
    struct json_value *lane_obj,
    const struct agent_operator_lane_topology *topology)
{
    if (!lane_obj || !topology)
        return;
    agent_fill_operator_lane_contract_json(lane_obj, topology->lane, "full",
                                           topology->datadir,
                                           topology->rpc_port,
                                           topology->p2p_port,
                                           topology->https_port,
                                           topology->fs_port);
    json_push_kv_str(lane_obj, "unit", topology->unit);
    json_push_kv_str(lane_obj, "role", topology->role);
    json_push_kv_str(lane_obj, "binary_role", topology->binary_role);
    json_push_kv_str(lane_obj, "health_probe",
                     "zclassic-cli -datadir=<datadir> -rpcport=<rpcport> agent");
    json_push_kv_str(lane_obj, "deploy_command", topology->deploy_command);
    json_push_kv_str(lane_obj, "restart_command", topology->restart_command);
}
