/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZNAM service-directory JSON serializer.
 *
 * This keeps the chain-projected name RPC controller small while exposing
 * machine-readable routing, validation, and service-contract metadata for
 * records such as service.p2p, service.onion, and bootstrap.
 */

#include "controllers/name_controller.h"
#include "api_controller_internal.h"
#include "models/znam.h"

#include "json/json.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define ZNAM_API_RECORD_LIMIT 64

struct service_record_classification {
    const char *service_name;
    const char *service_contract_name;
    const char *recommended_operation_id;
    const char *next_action;
    const char *transport;
    const char *endpoint_kind;
    bool is_endpoint_hint;
    bool supports_onion;
    bool supports_direct_p2p;
    bool supports_bootstrap;
};

static bool str_eq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

static bool value_mentions_onion(const char *value)
{
    return value && strstr(value, ".onion") != NULL;
}

static bool endpoint_has_port(const char *value)
{
    const char *colon;
    int port = 0;

    if (!value || !value[0])
        return false; /* raw-return-ok:predicate-null-input */
    colon = strrchr(value, ':');
    if (!colon || colon == value || !colon[1])
        return false; /* raw-return-ok:predicate-negative-match */
    for (const char *p = colon + 1; *p; p++) {
        if (!isdigit((unsigned char)*p))
            return false; /* raw-return-ok:predicate-negative-match */
        port = (port * 10) + (*p - '0');
        if (port > 65535)
            return false; /* raw-return-ok:predicate-negative-match */
    }
    return port > 0;
}

static bool service_endpoint_hint_is_valid(
    const struct service_record_classification *classification,
    const char *value)
{
    if (!classification || !classification->is_endpoint_hint)
        return false; /* raw-return-ok:predicate-null-input */
    if (classification->supports_onion)
        return value_mentions_onion(value);
    if (classification->supports_direct_p2p ||
        classification->supports_bootstrap)
        return endpoint_has_port(value);
    return false; /* raw-return-ok:predicate-negative-match */
}

static const char *service_endpoint_validation_status(
    const struct service_record_classification *classification,
    const char *value)
{
    if (!classification || !classification->is_endpoint_hint)
        return "not_endpoint";
    return service_endpoint_hint_is_valid(classification, value)
               ? "valid_endpoint_hint"
               : "invalid_endpoint_hint";
}

static const char *service_endpoint_validation_reason(
    const struct service_record_classification *classification,
    const char *value)
{
    if (!classification || !classification->is_endpoint_hint)
        return "service_metadata_record";
    if (classification->supports_onion)
        return value_mentions_onion(value)
                   ? "onion_host_hint_present"
                   : "missing_onion_host";
    if (classification->supports_direct_p2p ||
        classification->supports_bootstrap)
        return endpoint_has_port(value)
                   ? "host_port_hint_present"
                   : "missing_host_port";
    return "unsupported_endpoint_kind";
}

static const char *service_endpoint_preferred_transport(
    const struct service_record_classification *classification)
{
    if (!classification)
        return "none";
    if (classification->supports_direct_p2p)
        return "p2p";
    if (classification->supports_bootstrap)
        return "p2p_or_onion";
    if (classification->supports_onion)
        return "onion";
    return "none";
}

static const char *service_endpoint_fallback_transport(
    const struct service_record_classification *classification)
{
    if (!classification)
        return "inspect_service_catalog";
    if (classification->supports_direct_p2p)
        return "onion";
    if (classification->supports_bootstrap)
        return "onion";
    if (classification->supports_onion)
        return "direct_p2p_if_directory_advertises_it";
    return "inspect_service_catalog";
}

static int service_endpoint_routing_priority(
    const struct service_record_classification *classification)
{
    if (!classification)
        return 100;
    if (classification->supports_direct_p2p)
        return 10;
    if (classification->supports_bootstrap)
        return 20;
    if (classification->supports_onion)
        return 30;
    return 100;
}

static bool has_prefix(const char *s, const char *prefix)
{
    size_t n;

    if (!s || !prefix)
        return false; /* raw-return-ok:predicate-null-input */
    n = strlen(prefix);
    return strncmp(s, prefix, n) == 0;
}

static const char *service_key_suffix(const char *key)
{
    if (has_prefix(key, "service."))
        return key + strlen("service.");
    if (has_prefix(key, "svc."))
        return key + strlen("svc.");
    return NULL;
}

static struct service_record_classification
classify_service_record(const char *key, const char *value)
{
    const char *suffix = service_key_suffix(key);
    struct service_record_classification c = {
        .service_name = "service_hint",
        .service_contract_name = "znam_names",
        .recommended_operation_id = "znam_names.resolve_name",
        .next_action = "inspect_service_record_metadata",
        .transport = "unspecified",
        .endpoint_kind = "service_metadata",
    };

    if (str_eq(key, "onion") || str_eq(suffix, "onion") ||
        value_mentions_onion(value)) {
        c.service_name = "onion_directory";
        c.service_contract_name = "onion_directory";
        c.recommended_operation_id =
            "onion_directory.list_onion_announcements";
        c.next_action =
            "probe_onion_endpoint_then_prefer_direct_p2p_when_available";
        c.transport = "onion";
        c.endpoint_kind = "tor_hidden_service";
        c.is_endpoint_hint = true;
        c.supports_onion = true;
        return c;
    }

    if (str_eq(key, "p2p") || str_eq(suffix, "p2p") ||
        str_eq(suffix, "direct_p2p")) {
        c.service_name = "direct_p2p";
        c.service_contract_name = "bootstrap";
        c.recommended_operation_id =
            "bootstrap.inspect_peer_bootstrap_readiness";
        c.next_action = "connect_direct_p2p_and_verify_peer_readiness";
        c.transport = "p2p";
        c.endpoint_kind = "direct_peer_endpoint";
        c.is_endpoint_hint = true;
        c.supports_direct_p2p = true;
        return c;
    }

    if (str_eq(key, "bootstrap") || str_eq(suffix, "bootstrap")) {
        c.service_name = "bootstrap";
        c.service_contract_name = "bootstrap";
        c.recommended_operation_id = "bootstrap.read_bootstrap_status";
        c.next_action = "read_bootstrap_status_before_using_peer";
        c.transport = "p2p_or_onion";
        c.endpoint_kind = "bootstrap_hint";
        c.is_endpoint_hint = true;
        c.supports_bootstrap = true;
        return c;
    }

    if (str_eq(key, "service")) {
        c.service_name = "declared_service";
        c.service_contract_name = "znam_names";
        c.recommended_operation_id = "znam_names.resolve_name";
        c.endpoint_kind = "service_hint";
        return c;
    }

    if (suffix && suffix[0]) {
        c.service_name = suffix;
        c.service_contract_name = suffix;
        c.recommended_operation_id = "";
        c.next_action = "inspect_declared_service_catalog_entry";
        c.endpoint_kind = "service_metadata";
    }

    return c;
}

static void push_service_route_links(
    struct json_value *obj,
    const struct service_record_classification *classification)
{
    struct json_value runtime_probe = {0};
    struct json_value resolution = {0};
    char catalog_route[160];
    char operation_route[192];
    bool service_known = false;
    bool operation_required = false;
    bool operation_known = false;
    const char *resolution_status = "service_unknown";
    const char *resolution_next_action =
        "inspect_service_catalog_before_trusting_chain_hint";

    if (!obj || !classification)
        return;

    if (classification->service_contract_name &&
        classification->service_contract_name[0]) {
        service_known = api_service_catalog_has_service(
            classification->service_contract_name);
        snprintf(catalog_route, sizeof(catalog_route),
                 "/api/v1/service-catalog/%s",
                 classification->service_contract_name);
        catalog_route[sizeof(catalog_route) - 1] = '\0';
        json_push_kv_str(obj, "service_contract",
                         classification->service_contract_name);
        json_push_kv_str(obj, "service_catalog_route", catalog_route);
        if (api_service_runtime_probe_json_for_service(
                classification->service_contract_name, &runtime_probe)) {
            json_push_kv(obj, "runtime_probe", &runtime_probe);
            json_free(&runtime_probe);
        }
    }

    json_push_kv_str(obj, "recommended_operation_id",
                     classification->recommended_operation_id
                         ? classification->recommended_operation_id : "");
    if (classification->recommended_operation_id &&
        classification->recommended_operation_id[0]) {
        operation_required = true;
        operation_known = api_service_operation_has_id(
            classification->recommended_operation_id);
        snprintf(operation_route, sizeof(operation_route),
                 "/api/v1/service-operations/%s",
                 classification->recommended_operation_id);
        operation_route[sizeof(operation_route) - 1] = '\0';
        json_push_kv_str(obj, "service_operation_route", operation_route);
    }

    if (service_known && (!operation_required || operation_known)) {
        resolution_status = "resolved";
        resolution_next_action = "run_runtime_probe_before_routing";
    } else if (service_known) {
        resolution_status = "operation_unknown";
        resolution_next_action =
            "inspect_service_operation_contract_before_execution";
    }

    json_push_kv_bool(obj, "service_contract_known", service_known);
    json_push_kv_bool(obj, "service_operation_required",
                      operation_required);
    json_push_kv_bool(obj, "service_operation_known", operation_known);
    json_push_kv_str(obj, "contract_resolution_status",
                     resolution_status);

    json_set_object(&resolution);
    json_push_kv_str(&resolution, "schema",
                     "zcl.names.service_contract_resolution.v1");
    json_push_kv_str(&resolution, "status", resolution_status);
    json_push_kv_bool(&resolution, "service_contract_known",
                      service_known);
    json_push_kv_bool(&resolution, "operation_required",
                      operation_required);
    json_push_kv_bool(&resolution, "service_operation_known",
                      operation_known);
    json_push_kv_str(&resolution, "next_action",
                     resolution_next_action);
    json_push_kv(obj, "contract_resolution", &resolution);
    json_free(&resolution);

    json_push_kv_str(obj, "next_action",
                     classification->next_action
                         ? classification->next_action : "");
}

static void append_endpoint_validation(
    struct json_value *obj,
    const struct znam_text_record *rec,
    const struct service_record_classification *classification)
{
    struct json_value validation = {0};
    bool valid = service_endpoint_hint_is_valid(classification, rec->value);

    json_set_object(&validation);
    json_push_kv_str(&validation, "schema",
                     "zcl.names.endpoint_validation.v1");
    json_push_kv_str(&validation, "status",
                     service_endpoint_validation_status(classification,
                                                        rec->value));
    json_push_kv_bool(&validation, "accepted", valid);
    json_push_kv_str(&validation, "reason",
                     service_endpoint_validation_reason(classification,
                                                        rec->value));
    json_push_kv_str(&validation, "endpoint_kind",
                     classification->endpoint_kind);
    json_push_kv_str(&validation, "endpoint", rec->value);
    json_push_kv_bool(&validation, "chain_verified", true);
    json_push_kv_bool(&validation, "requires_runtime_probe",
                      classification->is_endpoint_hint);
    json_push_kv(obj, "endpoint_validation", &validation);
    json_free(&validation);
}

static void append_endpoint_routing(
    struct json_value *obj,
    const struct service_record_classification *classification)
{
    struct json_value routing = {0};

    json_set_object(&routing);
    json_push_kv_str(&routing, "schema",
                     "zcl.names.endpoint_routing.v1");
    json_push_kv_int(&routing, "priority",
                     service_endpoint_routing_priority(classification));
    json_push_kv_str(&routing, "preferred_transport",
                     service_endpoint_preferred_transport(classification));
    json_push_kv_str(&routing, "fallback_transport",
                     service_endpoint_fallback_transport(classification));
    json_push_kv_str(&routing, "routing_policy",
                     "verify_zcl_record_then_runtime_probe_then_connect");
    json_push_kv_str(&routing, "runtime_probe_policy",
                     "run_linked_service_runtime_probe_before_network_connect");
    json_push_kv_bool(&routing, "connectable_hint",
                      classification->is_endpoint_hint);
    json_push_kv_str(&routing, "next_action",
                     classification->next_action
                         ? classification->next_action : "");
    json_push_kv(obj, "endpoint_routing", &routing);
    json_free(&routing);
}

static void append_service_directory_routing_plan(
    struct json_value *directory,
    int endpoint_count,
    int valid_endpoint_count,
    int invalid_endpoint_count,
    bool supports_onion,
    bool supports_direct_p2p,
    bool supports_bootstrap)
{
    struct json_value plan = {0};
    const char *preferred = "none";
    const char *fallback = "inspect_service_catalog";

    if (supports_direct_p2p) {
        preferred = "p2p";
        fallback = supports_onion ? "onion" : "bootstrap";
    } else if (supports_bootstrap) {
        preferred = "p2p_or_onion";
        fallback = supports_onion ? "onion" : "inspect_bootstrap_status";
    } else if (supports_onion) {
        preferred = "onion";
        fallback = "direct_p2p_if_directory_advertises_it";
    }

    json_set_object(&plan);
    json_push_kv_str(&plan, "schema",
                     "zcl.names.service_routing_plan.v1");
    json_push_kv_str(&plan, "strategy",
                     "prefer_valid_direct_p2p_then_bootstrap_then_onion");
    json_push_kv_str(&plan, "preferred_transport", preferred);
    json_push_kv_str(&plan, "fallback_transport", fallback);
    json_push_kv_int(&plan, "endpoint_count", endpoint_count);
    json_push_kv_int(&plan, "valid_endpoint_count", valid_endpoint_count);
    json_push_kv_int(&plan, "invalid_endpoint_count",
                     invalid_endpoint_count);
    json_push_kv_bool(&plan, "chain_verified", true);
    json_push_kv_bool(&plan, "requires_runtime_probe",
                      endpoint_count > 0);
    json_push_kv_str(&plan, "next_action",
                     "run_selected_service_runtime_probe_before_connecting");
    json_push_kv(directory, "routing_plan", &plan);
    json_free(&plan);
}

static void append_service_directory(struct json_value *obj,
                                     const struct json_value *services,
                                     int service_count,
                                     const struct json_value *endpoints,
                                     int endpoint_count,
                                     int valid_endpoint_count,
                                     int invalid_endpoint_count,
                                     bool supports_onion,
                                     bool supports_direct_p2p,
                                     bool supports_bootstrap)
{
    struct json_value directory = {0};

    json_set_object(&directory);
    json_push_kv_str(&directory, "schema",
                     ZCL_NAMES_SERVICE_DIRECTORY_SCHEMA);
    json_push_kv_int(&directory, "schema_version", 1);
    json_push_kv_str(&directory, "source", "znam_text_records");
    json_push_kv_str(&directory, "transport_model",
                     "records_advertise_tor_or_p2p_endpoints");
    json_push_kv_str(&directory, "base_layer", "zclassic_l1");
    json_push_kv_str(&directory, "routing_policy",
                     "verify_zcl_name_record_then_prefer_direct_p2p_then_onion");
    json_push_kv_str(&directory, "service_contract_route",
                     "/api/v1/service-catalog/{service}");
    json_push_kv_str(&directory, "operation_contract_route",
                     "/api/v1/service-operations/{operation_id}");
    json_push_kv_str(&directory, "runtime_probe_schema",
                     ZCL_SERVICE_RUNTIME_PROBE_SCHEMA);
    json_push_kv_str(&directory, "runtime_probe_contract_field",
                     "runtime_probe");
    json_push_kv_str(&directory, "runtime_probe_policy",
                     "use_the_linked_service_contract_probe_before_routing");
    json_push_kv_bool(&directory, "has_services", service_count > 0);
    json_push_kv_int(&directory, "service_record_count", service_count);
    json_push_kv_int(&directory, "endpoint_count", endpoint_count);
    json_push_kv_int(&directory, "valid_endpoint_count",
                     valid_endpoint_count);
    json_push_kv_int(&directory, "invalid_endpoint_count",
                     invalid_endpoint_count);
    json_push_kv_bool(&directory, "supports_onion", supports_onion);
    json_push_kv_bool(&directory, "supports_direct_p2p",
                      supports_direct_p2p);
    json_push_kv_bool(&directory, "supports_bootstrap",
                      supports_bootstrap);
    append_service_directory_routing_plan(&directory, endpoint_count,
                                          valid_endpoint_count,
                                          invalid_endpoint_count,
                                          supports_onion,
                                          supports_direct_p2p,
                                          supports_bootstrap);
    json_push_kv(&directory, "records", services);
    json_push_kv(&directory, "endpoints", endpoints);
    json_push_kv(obj, "service_directory", &directory);
    json_free(&directory);
}

static bool is_service_record_key(const char *key)
{
    if (!key)
        return false; /* raw-return-ok:predicate-null-input */
    return strcmp(key, "service") == 0 ||
           strcmp(key, "onion") == 0 ||
           strcmp(key, "p2p") == 0 ||
           strcmp(key, "bootstrap") == 0 ||
           has_prefix(key, "service.") ||
           has_prefix(key, "svc.");
}

static void text_record_to_json(const struct znam_text_record *rec,
                                struct json_value *obj)
{
    json_set_object(obj);
    json_push_kv_str(obj, "name", rec->name);
    json_push_kv_str(obj, "key", rec->key);
    json_push_kv_str(obj, "value", rec->value);
}

static void service_record_to_json(
    const struct znam_text_record *rec,
    const struct service_record_classification *classification,
    struct json_value *obj)
{
    json_set_object(obj);
    json_push_kv_str(obj, "schema", "zcl.names.service_record.v1");
    json_push_kv_str(obj, "name", rec->name);
    json_push_kv_str(obj, "key", rec->key);
    json_push_kv_str(obj, "value", rec->value);
    json_push_kv_str(obj, "service_name",
                     classification->service_name);
    push_service_route_links(obj, classification);
    json_push_kv_str(obj, "transport", classification->transport);
    json_push_kv_str(obj, "endpoint_kind",
                     classification->endpoint_kind);
    json_push_kv_str(obj, "endpoint", rec->value);
    json_push_kv_int(obj, "routing_priority",
                     service_endpoint_routing_priority(classification));
    json_push_kv_bool(obj, "is_endpoint_hint",
                      classification->is_endpoint_hint);
    json_push_kv_bool(obj, "endpoint_hint_valid",
                      service_endpoint_hint_is_valid(classification,
                                                     rec->value));
    json_push_kv_bool(obj, "chain_verified", true);
    json_push_kv_str(obj, "verified_by", "confirmed_znam_text_record");
    json_push_kv_str(obj, "reachability_proof",
                     "requires_runtime_peer_or_onion_probe");
    append_endpoint_validation(obj, rec, classification);
    append_endpoint_routing(obj, classification);
}

static void addr_record_to_json(const struct znam_addr_record *rec,
                                struct json_value *obj)
{
    json_set_object(obj);
    json_push_kv_str(obj, "name", rec->name);
    json_push_kv_int(obj, "coin_type", rec->coin_type);
    json_push_kv_str(obj, "type", znam_type_name(rec->coin_type));
    json_push_kv_str(obj, "address", rec->address);
}

void api_name_append_records(struct node_db *ndb, const char *name,
                             struct json_value *obj)
{
    struct json_value texts = {0};
    struct json_value services = {0};
    struct json_value endpoints = {0};
    struct json_value addrs = {0};
    struct znam_text_record text_rows[ZNAM_API_RECORD_LIMIT];
    struct znam_addr_record addr_rows[ZNAM_API_RECORD_LIMIT];
    int text_count = 0;
    int service_count = 0;
    int endpoint_count = 0;
    int valid_endpoint_count = 0;
    int invalid_endpoint_count = 0;
    int addr_count = 0;
    bool supports_onion = false;
    bool supports_direct_p2p = false;
    bool supports_bootstrap = false;

    json_set_array(&texts);
    json_set_array(&services);
    json_set_array(&endpoints);
    json_set_array(&addrs);

    if (ndb && name) {
        text_count = db_znam_text_list(ndb, name, text_rows,
                                       ZNAM_API_RECORD_LIMIT);
        for (int i = 0; i < text_count; i++) {
            struct json_value row = {0};
            text_record_to_json(&text_rows[i], &row);
            json_push_back(&texts, &row);
            if (is_service_record_key(text_rows[i].key)) {
                struct service_record_classification classification =
                    classify_service_record(text_rows[i].key,
                                            text_rows[i].value);
                struct json_value svc = {0};
                service_record_to_json(&text_rows[i], &classification,
                                       &svc);
                json_push_back(&services, &svc);
                if (classification.is_endpoint_hint) {
                    if (service_endpoint_hint_is_valid(&classification,
                                                       text_rows[i].value))
                        valid_endpoint_count++;
                    else
                        invalid_endpoint_count++;
                    json_push_back(&endpoints, &svc);
                    endpoint_count++;
                }
                supports_onion = supports_onion ||
                                 classification.supports_onion;
                supports_direct_p2p = supports_direct_p2p ||
                                      classification.supports_direct_p2p;
                supports_bootstrap = supports_bootstrap ||
                                     classification.supports_bootstrap;
                json_free(&svc);
                service_count++;
            }
            json_free(&row);
        }

        addr_count = db_znam_addr_list(ndb, name, addr_rows,
                                       ZNAM_API_RECORD_LIMIT);
        for (int i = 0; i < addr_count; i++) {
            struct json_value row = {0};
            addr_record_to_json(&addr_rows[i], &row);
            json_push_back(&addrs, &row);
            json_free(&row);
        }
    }

    json_push_kv(obj, "text_records", &texts);
    json_push_kv_int(obj, "text_record_count", text_count);
    json_push_kv(obj, "service_records", &services);
    json_push_kv_int(obj, "service_record_count", service_count);
    json_push_kv(obj, "address_records", &addrs);
    json_push_kv_int(obj, "address_record_count", addr_count);
    append_service_directory(obj, &services, service_count, &endpoints,
                             endpoint_count, valid_endpoint_count,
                             invalid_endpoint_count, supports_onion,
                             supports_direct_p2p, supports_bootstrap);

    json_free(&texts);
    json_free(&services);
    json_free(&endpoints);
    json_free(&addrs);
}
