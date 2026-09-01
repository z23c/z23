/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Machine-readable catalog for dumpstate. This renderer consumes
 * the descriptors assembled from diagnostics_dumpers.def by the registry; it
 * does not maintain a second name-to-metadata mapping.
 */

#include "controllers/diagnostics_internal.h"
#include "controllers/strong_params.h"

#include "json/json.h"
#include "rpc/server.h"
#include "util/clientversion.h"

#include <stdint.h>
#include <stdio.h>

static void diagnostics_catalog_push_str(struct json_value *arr,
                                         const char *value)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, value ? value : "");
    json_push_back(arr, &v);
    json_free(&v);
}

static void diagnostics_catalog_push_accepted_keys(struct json_value *obj,
                                                   const struct diagnostics_dump_entry *e)
{
    struct json_value accepted, examples;
    json_init(&accepted);
    json_set_array(&accepted);
    json_init(&examples);
    json_set_array(&examples);

    if (e && e->key_hint && e->key_hint[0])
        diagnostics_catalog_push_str(&accepted, e->key_hint);
    if (e && e->key_example_1)
        diagnostics_catalog_push_str(&examples, e->key_example_1);
    if (e && e->key_example_2)
        diagnostics_catalog_push_str(&examples, e->key_example_2);

    json_push_kv(obj, "accepted_keys", &accepted);
    json_push_kv(obj, "key_examples", &examples);
    json_free(&accepted);
    json_free(&examples);
}

static void diagnostics_catalog_push_tests(struct json_value *obj,
                                           const struct diagnostics_dump_entry *e)
{
    struct json_value tests;
    json_init(&tests);
    json_set_array(&tests);
    diagnostics_catalog_push_str(&tests,
                                 "tests/harness/src/test_syncdiag_agent_ops.c:statecatalog");
    diagnostics_catalog_push_str(&tests, e ? e->primary_test : "");
    json_push_kv(obj, "tests", &tests);
    json_free(&tests);
}

static void diagnostics_catalog_push_drilldowns(struct json_value *obj,
                                                const struct diagnostics_dump_entry *e,
                                                const char *native)
{
    struct json_value drilldowns;

    json_init(&drilldowns);
    json_set_array(&drilldowns);
    diagnostics_catalog_push_str(&drilldowns, native);
    if (e && e->include_supervisor_drilldown) {
        char supervisor[224];
        snprintf(supervisor, sizeof(supervisor),
                 "z23 dumpstate supervisor.%s", e->name);
        diagnostics_catalog_push_str(&drilldowns, supervisor);
    }
    json_push_kv(obj, "drilldowns", &drilldowns);
    json_free(&drilldowns);
}

static void diagnostics_catalog_push_entry(
    struct json_value *arr,
    const struct diagnostics_dump_entry *e)
{
    struct json_value obj;
    char native[192];
    if (!e)
        return;
    bool accepts_key = e->key_hint && e->key_hint[0];
    const char *key_hint = accepts_key ? e->key_hint : "";

    json_init(&obj);
    json_set_object(&obj);
    snprintf(native, sizeof(native), accepts_key
        ? "z23 dumpstate %s <key>"
        : "z23 dumpstate %s", e->name);
    json_push_kv_str(&obj, "name", e->name);
    json_push_kv_str(&obj, "subsystem", e->name);
    json_push_kv_str(&obj, "description", e->desc);
    json_push_kv_str(&obj, "schema", "subsystem-specific diagnostic JSON");
    json_push_kv_str(&obj, "state_class", e->state_class);
    json_push_kv_str(&obj, "owner_shape", e->owner_shape);
    json_push_kv_str(&obj, "owner_file", e->owner_file);
    json_push_kv_str(&obj, "freshness", e->freshness);
    json_push_kv_str(&obj, "cost", e->cost);
    json_push_kv_str(&obj, "safety_level", "read_only");
    json_push_kv_bool(&obj, "accepts_key", accepts_key);
    json_push_kv_str(&obj, "key_hint", key_hint);
    json_push_kv_bool(&obj, "key_required", false);
    json_push_kv_str(&obj, "native_command", native);
    diagnostics_catalog_push_accepted_keys(&obj, e);
    diagnostics_catalog_push_tests(&obj, e);
    diagnostics_catalog_push_drilldowns(&obj, e, native);
    json_push_back(arr, &obj);
    json_free(&obj);
}

bool diag_rpc_statecatalog(const struct json_value *params, bool help,
                           struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "statecatalog\n"
        "\nReturn the machine-readable catalog for dumpstate.\n"
        "\nResult: { schema, count, subsystems:[{ name, description, "
        "state_class, owner_shape, owner_file, freshness, cost, "
        "safety_level, accepted_keys, tests, drilldowns, ... }] }");

    struct json_value subsystems;
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.state_catalog.v2");
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_str(result, "status", "ok");
    json_push_kv_str(result, "build_commit", zcl_build_commit());
    json_push_kv_str(result, "source", "diagnostics_registry.g_dumpers");
    json_push_kv_str(result, "default_native_command",
                     "z23 dumpstate <subsystem> [key]");
    json_push_kv_str(result, "catalog_native_command",
                     "z23 statecatalog");
    json_push_kv_int(result, "count",
                     (int64_t)diagnostics_dumper_count());

    json_init(&subsystems);
    json_set_array(&subsystems);
    for (size_t i = 0; i < diagnostics_dumper_count(); i++)
        diagnostics_catalog_push_entry(&subsystems,
                                       diagnostics_dumper_at(i));
    json_push_kv(result, "subsystems", &subsystems);
    json_free(&subsystems);
    return true;
}
