/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: One coherent local DHT publication projection for exact status. */

#include "config/boot_zcode_dht.h"

#include "base/hex.h"
#include "json/json.h"
#include "platform/time_compat.h"

#include <string.h>

static const struct json_value *snapshot_input(
    const struct json_value *params)
{
    const struct json_value *first =
        params && json_size(params) ? json_at(params, 0) : NULL;
    return first && first->type == JSON_OBJ ? first : NULL;
}

static const char *snapshot_str(const struct json_value *in, const char *key)
{
    const struct json_value *value = in ? json_get(in, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool snapshot_namespace(const struct json_value *in, char out[32])
{
    const char *name = snapshot_str(in, "namespace");
    size_t n = name ? strlen(name) : 0;
    memset(out, 0, 32);
    if (!n || n > VCS_ZCODE_DHT_RECORD_NAMESPACE_MAX) return false;
    for (size_t i = 0; i < n; i++)
        if (!((name[i] >= 'a' && name[i] <= 'z') ||
              (name[i] >= '0' && name[i] <= '9') || name[i] == '.' ||
              name[i] == '-' || name[i] == '_'))
            return false;
    memcpy(out, name, n);
    return true;
}

static bool snapshot_root(
    const struct json_value *in, const char *key, uint8_t out[32])
{
    const char *hex = snapshot_str(in, key);
    memset(out, 0, 32);
    return hex && strlen(hex) == 64u &&
           zcl_hex_decode_lower(hex, out, 32);
}

static const char *snapshot_kind(enum vcs_zcode_dht_record_kind kind)
{
    return kind == VCS_ZCODE_DHT_RECORD_POINTER ? "pointer" : "provider";
}

static void snapshot_record_json(
    struct json_value *row, const struct vcs_zcode_dht_record *record)
{
    char semantic[65], transport[65], provider[65], record_root[65] = "";
    uint8_t root[32];
    zcl_hex_encode(record->semantic_root, 32, semantic);
    zcl_hex_encode(record->transport_root, 32, transport);
    zcl_hex_encode(record->provider_node_id, 32, provider);
    if (vcs_zcode_dht_record_id(record, root) == VCS_ZCODE_DHT_RECORD_OK)
        zcl_hex_encode(root, 32, record_root);
    json_set_object(row);
    json_push_kv_str(row, "kind", snapshot_kind(record->kind));
    json_push_kv_str(row, "record_root", record_root);
    json_push_kv_str(row, "namespace", record->namespace_name);
    json_push_kv_str(row, "semantic_root", semantic);
    json_push_kv_str(row, "transport_root", transport);
    json_push_kv_str(row, "provider_node_id", provider);
}

static void snapshot_projection_json(
    struct json_value *out, const struct vcs_zcode_dht_record *records,
    size_t count)
{
    json_set_object(out);
    json_push_kv_bool(out, "local_projection", true);
    json_push_kv_int(out, "count", (int64_t)count);
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < count; i++) {
        struct json_value row;
        json_init(&row);
        snapshot_record_json(&row, &records[i]);
        json_push_back(&rows, &row);
        json_free(&row);
    }
    json_push_kv(out, "records", &rows);
    json_free(&rows);
}

static void snapshot_error(
    struct json_value *result, const char *code, const char *message)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", false);
    json_push_kv_str(result, "code", code);
    json_push_kv_str(result, "message", message);
}

bool boot_zcode_dht_publication_snapshot_rpc(
    const struct json_value *params, bool help, struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "zcode_dht_status publication_snapshot "
                     "{namespace,semantic_root,transport_root}");
        return true;
    }
    const struct json_value *in = snapshot_input(params);
    struct vcs_zcode_dht_record_selector pointer = {
        .kind = VCS_ZCODE_DHT_RECORD_POINTER};
    struct vcs_zcode_dht_record_selector provider = {
        .kind = VCS_ZCODE_DHT_RECORD_PROVIDER};
    if (!snapshot_namespace(in, pointer.namespace_name) ||
        !snapshot_namespace(in, provider.namespace_name) ||
        !snapshot_root(in, "semantic_root", pointer.root) ||
        !snapshot_root(in, "transport_root", provider.root)) {
        snapshot_error(result, "INVALID_PUBLICATION_SNAPSHOT",
                       "canonical namespace, semantic_root and transport_root required");
        return true;
    }
    struct vcs_zcode_dht_record pointers[VCS_ZCODE_DHT_RECORDS_PER_FRAME];
    struct vcs_zcode_dht_record providers[VCS_ZCODE_DHT_RECORDS_PER_FRAME];
    size_t pointer_count = 0, provider_count = 0;
    uint8_t local_node_id[32];
    uint64_t generation = 0;
    if (!boot_zcode_dht_publication_snapshot(
            (uint64_t)platform_time_wall_time_t(), &pointer, &provider,
            local_node_id, &generation,
            pointers, VCS_ZCODE_DHT_RECORDS_PER_FRAME, &pointer_count,
            providers, VCS_ZCODE_DHT_RECORDS_PER_FRAME, &provider_count)) {
        snapshot_error(result, "DHT_DISABLED", "authenticated DHT is disabled");
        return true;
    }
    char node_id[65];
    zcl_hex_encode(local_node_id, 32, node_id);
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_bool(result, "coherent_snapshot", true);
    json_push_kv_int(result, "service_generation", (int64_t)generation);
    json_push_kv_str(result, "local_node_id", node_id);
    struct json_value pointer_json, provider_json;
    json_init(&pointer_json);
    json_init(&provider_json);
    snapshot_projection_json(&pointer_json, pointers, pointer_count);
    snapshot_projection_json(&provider_json, providers, provider_count);
    json_push_kv(result, "pointer_records", &pointer_json);
    json_push_kv(result, "provider_records", &provider_json);
    json_free(&pointer_json);
    json_free(&provider_json);
    return true;
}
