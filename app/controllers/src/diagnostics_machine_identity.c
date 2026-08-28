/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Redacted live-machine identity and readiness projection. */

#include "controllers/diagnostics_internal.h"

#include "config/boot_zcode_dht.h"
#include "hotswap/hotswap.h"
#include "json/json.h"
#include "platform/os_sandbox.h"
#include "platform/os_proc.h"
#include "services/binary_staleness_service.h"
#include "util/clientversion.h"

#include <string.h>

static const char *machine_os(void)
{
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__linux__)
    return "linux";
#else
    return "unknown";
#endif
}

static const char *machine_arch(void)
{
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "aarch64";
#else
    return "unknown";
#endif
}

static bool object_bool(const struct json_value *obj, const char *key)
{
    const struct json_value *value = obj ? json_get(obj, key) : NULL;
    return value && value->type == JSON_BOOL && json_get_bool(value);
}

static int64_t object_int(const struct json_value *obj, const char *key)
{
    const struct json_value *value = obj ? json_get(obj, key) : NULL;
    return value && value->type == JSON_INT ? json_get_int(value) : -1;
}

static const char *object_str(const struct json_value *obj, const char *key)
{
    const struct json_value *value = obj ? json_get(obj, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : "";
}

static void push_string_item(struct json_value *array, const char *value)
{
    struct json_value item = {0};
    json_set_str(&item, value);
    (void)json_push_back(array, &item);
    json_free(&item);
}

static void push_platform(struct json_value *out)
{
    enum os_proc_environment environment = os_proc_environment_observe();
    struct json_value platform = {0};
    json_set_object(&platform);
    json_push_kv_str(&platform, "os", machine_os());
    json_push_kv_str(&platform, "architecture", machine_arch());
    json_push_kv_str(&platform, "environment",
                     os_proc_environment_string(environment));
    json_push_kv_bool(&platform, "environment_observed",
                      environment != OS_PROC_ENVIRONMENT_UNKNOWN);
    json_push_kv_bool(&platform, "runtime_observed", true);
    json_push_kv(out, "platform", &platform);
    json_free(&platform);
}

static bool push_build(struct json_value *out)
{
    struct binary_staleness_status status;
    binary_staleness_status_snapshot(&status);
    bool have_digest = status.boot_captured &&
                       strlen(status.boot_digest_hex) == 64;

    struct json_value build = {0};
    json_set_object(&build);
    json_push_kv_str(&build, "source_id_sha256",
                     zcl_build_source_id_sha256());
    json_push_kv_str(&build, "commit", zcl_build_commit());
    json_push_kv_bool(&build, "binary_identity_available", have_digest);
    json_push_kv_str(&build, "binary_sha3_256",
                     have_digest ? status.boot_digest_hex : "");
#if defined(__linux__) && !defined(_WIN32)
    json_push_kv_str(&build, "binary_identity_scope",
                     "running_image_at_boot");
#else
    json_push_kv_str(&build, "binary_identity_scope", "unavailable");
#endif
    json_push_kv_bool(&build, "installed_path_matches_running_image",
                      have_digest && status.path_valid && !status.stale);
    json_push_kv(out, "build", &build);
    json_free(&build);
    return have_digest;
}

static bool push_transport(struct json_value *out, bool *identity_loaded_out)
{
    struct json_value raw = {0};
    bool collected = net_transport_dump_state_json(&raw, NULL);
    bool enabled = collected && object_bool(&raw, "v2_enabled");
    bool identity_loaded = collected && object_bool(&raw, "identity_loaded");
    if (identity_loaded_out)
        *identity_loaded_out = identity_loaded;
    struct json_value transport = {0};
    json_set_object(&transport);
    json_push_kv_bool(&transport, "observed", collected);
    json_push_kv_bool(&transport, "v2_enabled", enabled);
    json_push_kv_bool(&transport, "identity_loaded", identity_loaded);
    json_push_kv_str(&transport, "local_noise_fingerprint_sha3",
                     object_str(&raw, "local_noise_fingerprint_sha3"));
    json_push_kv_int(&transport, "noise_peers",
                     object_int(&raw, "noise_peers"));
    json_push_kv_int(&transport, "plaintext_peers",
                     object_int(&raw, "plaintext_peers"));
    json_push_kv_int(&transport, "handshaking_peers",
                     object_int(&raw, "handshaking_peers"));
    json_push_kv(out, "transport", &transport);
    json_free(&transport);
    json_free(&raw);
    return enabled;
}

static bool push_dht(struct json_value *out)
{
    struct json_value raw = {0};
    bool collected = boot_zcode_dht_dump_state_json(&raw, "status");
    bool enabled = collected && object_bool(&raw, "enabled");
    struct json_value dht = {0};
    json_set_object(&dht);
    json_push_kv_bool(&dht, "observed", collected);
    json_push_kv_bool(&dht, "enabled", enabled);
    json_push_kv_str(&dht, "disabled_reason",
                     object_str(&raw, "disabled_reason"));
    json_push_kv_str(&dht, "node_id", object_str(&raw, "local_node_id"));
    json_push_kv_int(&dht, "connected_authenticated",
                     object_int(&raw, "connected_authenticated"));
    json_push_kv(out, "authenticated_dht", &dht);
    json_free(&dht);
    json_free(&raw);
    return enabled;
}

static void push_runtime_capabilities(struct json_value *out)
{
    struct json_value confinement = {0};
    json_set_object(&confinement);
    json_push_kv_bool(&confinement, "active", os_sandbox_active());
    json_push_kv_bool(&confinement, "seccomp_supported",
                      os_sandbox_seccomp_supported());
    json_push_kv(out, "confinement", &confinement);
    json_free(&confinement);

    bool available = hotswap_native_activation_available();
    struct json_value hotswap = {0};
    json_set_object(&hotswap);
    json_push_kv_bool(&hotswap, "native_activation_available", available);
    json_push_kv_str(&hotswap, "status", available ? "available" : "refused");
    json_push_kv_str(&hotswap, "refusal_stage",
                     available ? "" : hotswap_native_unavailable_stage());
    json_push_kv_str(&hotswap, "refusal_reason",
                     available ? "" : hotswap_native_unavailable_reason());
    json_push_kv(out, "hotswap", &hotswap);
    json_free(&hotswap);
}

bool machine_identity_dump_state_json(struct json_value *out, const char *key)
{
    if (!out)
        return false;
    if (key && key[0] && strcmp(key, "status") != 0)
        return false;

    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.machine_mesh_identity.v1");
    json_push_kv_str(out, "scope", "local_machine");
    json_push_kv_str(out, "authority", "live_daemon_observation");
    push_platform(out);
    bool binary_ready = push_build(out);
    bool noise_identity_ready = false;
    bool v2_ready = push_transport(out, &noise_identity_ready);
    bool dht_ready = push_dht(out);
    push_runtime_capabilities(out);

    bool identity_ready = binary_ready && v2_ready && noise_identity_ready &&
                          dht_ready;
    struct json_value pairing = {0};
    json_set_object(&pairing);
    json_push_kv_bool(&pairing, "identity_prerequisites_ready", identity_ready);
    json_push_kv_bool(&pairing, "implemented", false);
    json_push_kv_bool(&pairing, "private_mesh_ready", false);
    json_push_kv(out, "pairing", &pairing);
    json_free(&pairing);

    struct json_value blockers = {0};
    json_set_array(&blockers);
    if (!binary_ready)
        push_string_item(&blockers, "BINARY_IDENTITY_UNAVAILABLE");
    if (!v2_ready)
        push_string_item(&blockers, "V2_TRANSPORT_DISABLED");
    if (!noise_identity_ready)
        push_string_item(&blockers, "NOISE_IDENTITY_UNAVAILABLE");
    if (!dht_ready)
        push_string_item(&blockers, "AUTHENTICATED_DHT_INACTIVE");
    push_string_item(&blockers, "PAIRING_NOT_IMPLEMENTED");
    json_push_kv(out, "blockers", &blockers);
    json_free(&blockers);
    json_push_kv_str(out, "next_action",
                     "enable v2 and authenticated DHT identity, then implement explicit two-sided pairing");
    return true;
}
