/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Compose iterative PROVIDER and ACK discovery into replication. */

#include "config/boot_zcode_dht_replication.h"

#include "base/hex.h"
#include "config/boot_zcode_dht.h"
#include "config/boot_zcode_dht_access.h"
#include "config/boot_zcode_dht_possession.h"
#include "crypto/random_secret.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "util/sync.h"
#include "vcs/package_store.h"
#include "vcs/zcode_replication.h"

#include <stdatomic.h>
#include <string.h>

#define REPLICATION_PUBLIC_MAX 16u
#define REPLICATION_TOKEN_BYTES 16u
#define REPLICATION_ACTIVE_GRACE_S 5u
#define REPLICATION_RESULT_RETENTION_S 30u

struct replication_public_entry {
    bool used, cached, provider_done, ack_done;
    uint8_t lookup_token[REPLICATION_TOKEN_BYTES];
    uint8_t owner_token[REPLICATION_TOKEN_BYTES];
    char namespace_name[32];
    uint8_t root[32];
    uint64_t provider_id, ack_id, service_generation, expires_mono;
    uint64_t evaluated_wall;
    struct vcs_zcode_dht_record_discovery_result provider;
    struct vcs_zcode_dht_record_discovery_result ack;
    struct vcs_zcode_replication_status status;
};

struct replication_peer_context {
    uint8_t local_node_id[32];
    uint8_t authenticated[VCS_ZCODE_DHT_SERVICE_MAX_PEERS][32];
    size_t authenticated_count;
};

static zcl_mutex_t g_replication_lock;
static _Atomic int g_replication_lock_state;
static struct replication_public_entry g_replication[REPLICATION_PUBLIC_MAX];

#ifdef ZCL_TESTING
static struct boot_zcode_dht_replication_test_backend g_test_backend;
#endif

static struct vcs_zcode_dht_time replication_now(void)
{
#ifdef ZCL_TESTING
    if (g_test_backend.now)
        return g_test_backend.now(g_test_backend.ctx);
#endif
    return (struct vcs_zcode_dht_time){
        .wall_unix = (uint64_t)platform_time_wall_time_t(),
        .monotonic_s = (uint64_t)(platform_time_monotonic_ms() / 1000),
    };
}

static bool child_begin(
    const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_time now, uint64_t *operation_id,
    uint64_t *generation)
{
#ifdef ZCL_TESTING
    if (g_test_backend.begin)
        return g_test_backend.begin(g_test_backend.ctx, selector, now,
                                    operation_id, generation);
#endif
    return boot_zcode_dht_record_discovery_begin(
        selector, now, operation_id, generation);
}

static bool child_poll(
    uint64_t operation_id, uint64_t generation,
    struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record_discovery_result *out)
{
#ifdef ZCL_TESTING
    if (g_test_backend.poll)
        return g_test_backend.poll(g_test_backend.ctx, operation_id,
                                   generation, now, out);
#endif
    return boot_zcode_dht_record_discovery_poll(
        operation_id, generation, now, out);
}

static bool child_cancel(uint64_t operation_id, uint64_t generation)
{
#ifdef ZCL_TESTING
    if (g_test_backend.cancel)
        return g_test_backend.cancel(g_test_backend.ctx, operation_id,
                                     generation);
#endif
    return boot_zcode_dht_record_discovery_cancel(operation_id, generation);
}

static void replication_lock(void)
{
    if (atomic_load_explicit(&g_replication_lock_state,
                             memory_order_acquire) != 2) {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_replication_lock_state, &expected, 1,
                memory_order_acq_rel, memory_order_acquire)) {
            zcl_mutex_init(&g_replication_lock);
            atomic_store_explicit(&g_replication_lock_state, 2,
                                  memory_order_release);
        } else {
            while (atomic_load_explicit(&g_replication_lock_state,
                                        memory_order_acquire) != 2)
                ;
        }
    }
    zcl_mutex_lock(&g_replication_lock);
}

static bool token_equal(const uint8_t left[REPLICATION_TOKEN_BYTES],
                        const uint8_t right[REPLICATION_TOKEN_BYTES])
{
    uint8_t difference = 0;
    for (size_t i = 0; i < REPLICATION_TOKEN_BYTES; i++)
        difference |= left[i] ^ right[i];
    return difference == 0;
}

static struct replication_public_entry *entry_find(
    const uint8_t lookup[REPLICATION_TOKEN_BYTES],
    const uint8_t owner[REPLICATION_TOKEN_BYTES])
{
    for (size_t i = 0; i < REPLICATION_PUBLIC_MAX; i++)
        if (g_replication[i].used &&
            token_equal(g_replication[i].lookup_token, lookup) &&
            token_equal(g_replication[i].owner_token, owner))
            return &g_replication[i];
    return NULL;
}

static void entry_cancel(struct replication_public_entry *entry)
{
    if (!entry || entry->cached)
        return;
    if (!entry->provider_done && entry->provider_id)
        (void)child_cancel(entry->provider_id, entry->service_generation);
    if (!entry->ack_done && entry->ack_id)
        (void)child_cancel(entry->ack_id, entry->service_generation);
}

static void cleanup_locked(uint64_t monotonic_s)
{
    for (size_t i = 0; i < REPLICATION_PUBLIC_MAX; i++)
        if (g_replication[i].used &&
            monotonic_s >= g_replication[i].expires_mono) {
            entry_cancel(&g_replication[i]);
            memset(&g_replication[i], 0, sizeof(g_replication[i]));
        }
}

void boot_zcode_dht_replication_public_tick(uint64_t monotonic_s)
{
    replication_lock();
    cleanup_locked(monotonic_s);
    zcl_mutex_unlock(&g_replication_lock);
}

void boot_zcode_dht_replication_public_reset(void)
{
    replication_lock();
    for (size_t i = 0; i < REPLICATION_PUBLIC_MAX; i++)
        entry_cancel(&g_replication[i]);
    memset(g_replication, 0, sizeof(g_replication));
    zcl_mutex_unlock(&g_replication_lock);
}

#ifdef ZCL_TESTING
void boot_zcode_dht_replication_test_set_backend(
    const struct boot_zcode_dht_replication_test_backend *backend)
{
    /* Cancel outstanding children through the backend that admitted them
     * before replacing its callbacks. Tests call this without concurrency. */
    boot_zcode_dht_replication_public_reset();
    if (backend)
        g_test_backend = *backend;
    else
        memset(&g_test_backend, 0, sizeof(g_test_backend));
}
#endif

static const struct json_value *rpc_input(const struct json_value *params)
{
    const struct json_value *first =
        params && json_size(params) ? json_at(params, 0) : NULL;
    return first && first->type == JSON_OBJ ? first : NULL;
}

static const char *input_str(const struct json_value *in, const char *key)
{
    const struct json_value *value = in ? json_get(in, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool input_namespace(const struct json_value *in, char out[32])
{
    const char *name = input_str(in, "namespace");
    size_t length = name ? strlen(name) : 0;
    memset(out, 0, 32);
    if (!length || length > VCS_ZCODE_DHT_RECORD_NAMESPACE_MAX)
        return false;
    for (size_t i = 0; i < length; i++)
        if (!((name[i] >= 'a' && name[i] <= 'z') ||
              (name[i] >= '0' && name[i] <= '9') || name[i] == '.' ||
              name[i] == '-' || name[i] == '_'))
            return false;
    memcpy(out, name, length);
    return true;
}

static bool input_root(const struct json_value *in, uint8_t out[32])
{
    const char *hex = input_str(in, "transport_root");
    return hex && strlen(hex) == 64 && zcl_hex_decode_lower(hex, out, 32);
}

static bool input_capability(
    const struct json_value *in, uint8_t lookup[REPLICATION_TOKEN_BYTES],
    uint8_t owner[REPLICATION_TOKEN_BYTES])
{
    const char *lookup_hex = input_str(in, "lookup_id");
    const char *owner_hex = input_str(in, "owner_token");
    return lookup_hex && owner_hex &&
           strlen(lookup_hex) == 2u * REPLICATION_TOKEN_BYTES &&
           strlen(owner_hex) == 2u * REPLICATION_TOKEN_BYTES &&
           zcl_hex_decode_lower(lookup_hex, lookup, REPLICATION_TOKEN_BYTES) &&
           zcl_hex_decode_lower(owner_hex, owner, REPLICATION_TOKEN_BYTES);
}

static void rpc_error(struct json_value *result, const char *code,
                      const char *message)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", false);
    json_push_kv_str(result, "code", code);
    json_push_kv_str(result, "message", message);
}

static bool rpc_begin(const struct json_value *params, bool help,
                      struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "zcode_dht_replication_begin {namespace,transport_root}");
        return true;
    }
    const struct json_value *in = rpc_input(params);
    char namespace_name[32];
    uint8_t root[32];
    if (!input_namespace(in, namespace_name) || !input_root(in, root)) {
        rpc_error(result, "INVALID_SELECTOR",
                  "canonical namespace and transport_root required");
        return true;
    }
    uint8_t tokens[2u * REPLICATION_TOKEN_BYTES];
    if (!zcl_random_secret_bytes(tokens, sizeof(tokens),
                                 "zcode_replication_lookup")) {
        rpc_error(result, "LOOKUP_ID_UNAVAILABLE",
                  "secure replication capability generation failed");
        return true;
    }
    struct vcs_zcode_dht_time now = replication_now();
    replication_lock();
    cleanup_locked(now.monotonic_s);
    struct replication_public_entry *entry = NULL;
    bool collision = false;
    for (size_t i = 0; i < REPLICATION_PUBLIC_MAX; i++) {
        if (!g_replication[i].used && !entry)
            entry = &g_replication[i];
        if (g_replication[i].used &&
            token_equal(g_replication[i].lookup_token, tokens))
            collision = true;
    }
    struct vcs_zcode_dht_record_selector selector;
    memset(&selector, 0, sizeof(selector));
    memcpy(selector.namespace_name, namespace_name, sizeof(namespace_name));
    memcpy(selector.root, root, sizeof(selector.root));
    uint64_t provider_id = 0, ack_id = 0;
    uint64_t provider_generation = 0, ack_generation = 0;
    selector.kind = VCS_ZCODE_DHT_RECORD_PROVIDER;
    bool began = entry && !collision &&
        child_begin(&selector, now, &provider_id, &provider_generation);
    selector.kind = VCS_ZCODE_DHT_RECORD_STORAGE_ACK;
    began = began && child_begin(
                         &selector, now, &ack_id, &ack_generation) &&
            provider_generation == ack_generation;
    if (!began) {
        if (provider_id)
            (void)child_cancel(provider_id, provider_generation);
        if (ack_id)
            (void)child_cancel(ack_id, ack_generation);
        zcl_mutex_unlock(&g_replication_lock);
        rpc_error(result, "LOOKUP_UNAVAILABLE",
                  "DHT is disabled or its bounded discovery queue is full");
        return true;
    }
    memset(entry, 0, sizeof(*entry));
    entry->used = true;
    memcpy(entry->lookup_token, tokens, REPLICATION_TOKEN_BYTES);
    memcpy(entry->owner_token, tokens + REPLICATION_TOKEN_BYTES,
           REPLICATION_TOKEN_BYTES);
    memcpy(entry->namespace_name, namespace_name, sizeof(namespace_name));
    memcpy(entry->root, root, sizeof(root));
    entry->provider_id = provider_id;
    entry->ack_id = ack_id;
    entry->service_generation = provider_generation;
    entry->expires_mono = now.monotonic_s +
        VCS_ZCODE_DHT_LOOKUP_CEILING_S +
        VCS_ZCODE_DHT_SERVICE_QUERY_TIMEOUT_S + REPLICATION_ACTIVE_GRACE_S;
    char lookup_hex[2u * REPLICATION_TOKEN_BYTES + 1u];
    char owner_hex[2u * REPLICATION_TOKEN_BYTES + 1u];
    zcl_hex_encode(entry->lookup_token, REPLICATION_TOKEN_BYTES, lookup_hex);
    zcl_hex_encode(entry->owner_token, REPLICATION_TOKEN_BYTES, owner_hex);
    zcl_mutex_unlock(&g_replication_lock);
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "state", "pending");
    json_push_kv_str(result, "lookup_id", lookup_hex);
    json_push_kv_str(result, "owner_token", owner_hex);
    return true;
}

static void collect_peers_locked(struct vcs_zcode_dht_service *service,
                                 void *opaque)
{
    struct replication_peer_context *context = opaque;
    struct vcs_zcode_dht_service_status status;
    struct vcs_zcode_dht_peer_view peers[VCS_ZCODE_DHT_SERVICE_MAX_PEERS];
    vcs_zcode_dht_service_status(service, &status);
    memcpy(context->local_node_id, status.local_node_id, 32);
    size_t count = vcs_zcode_dht_service_peers(
        service, (uint64_t)platform_time_wall_time_t(), peers,
        VCS_ZCODE_DHT_SERVICE_MAX_PEERS, 0);
    for (size_t i = 0; i < count; i++)
        if (peers[i].connected && peers[i].authenticated)
            memcpy(context->authenticated[context->authenticated_count++],
                   peers[i].node_id, 32);
}

static bool discovery_complete(
    const struct vcs_zcode_dht_record_discovery_result *result)
{
    return result->state == VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE &&
           !result->truncated && !result->incomplete &&
           result->nodes_queried != 0;
}

static void entry_evaluate(struct replication_public_entry *entry,
                           struct vcs_zcode_dht_time now)
{
    struct vcs_zcode_dht_record records[VCS_ZCODE_REPLICATION_MAX_EVIDENCE];
    size_t count = entry->provider.record_count;
    memcpy(records, entry->provider.records,
           count * sizeof(*records));
    memcpy(records + count, entry->ack.records,
           entry->ack.record_count * sizeof(*records));
    count += entry->ack.record_count;
    struct replication_peer_context peers;
    memset(&peers, 0, sizeof(peers));
    (void)boot_zcode_dht_service_apply(collect_peers_locked, &peers);
    bool local_current = boot_zcode_dht_possession_current(
        vcs_package_store_global(), entry->root);
    struct vcs_zcode_replication_evidence evidence = {
        .records = records,
        .count = count,
        .authenticated_node_ids = peers.authenticated,
        .authenticated_count = peers.authenticated_count,
        .local_possession_current = local_current,
        .provider_evidence_complete = discovery_complete(&entry->provider),
        .ack_evidence_complete = discovery_complete(&entry->ack),
        .local_cache_only = entry->provider.nodes_queried == 0 &&
                            entry->ack.nodes_queried == 0,
    };
    memcpy(evidence.local_node_id, peers.local_node_id, 32);
    vcs_zcode_replication_evaluate_evidence(
        &evidence, entry->namespace_name, entry->root, now.wall_unix,
        &entry->status);
    entry->evaluated_wall = now.wall_unix;
    entry->cached = true;
    entry->expires_mono = now.monotonic_s + REPLICATION_RESULT_RETENTION_S;
}

static void conflict_json(
    struct json_value *out, const struct vcs_zcode_dht_record *records,
    size_t count)
{
    json_set_array(out);
    for (size_t i = 0; i < count; i++) {
        if (!vcs_zcode_replication_record_conflicted(records, count, i))
            continue;
        char provider[65], publisher[65];
        zcl_hex_encode(records[i].provider_node_id, 32, provider);
        zcl_hex_encode(records[i].delegation.doc.master_pubkey, 32, publisher);
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        json_push_kv_str(&row, "kind",
            records[i].kind == VCS_ZCODE_DHT_RECORD_PROVIDER
                ? "provider" : "storage_ack");
        json_push_kv_str(&row, "provider_node_id", provider);
        json_push_kv_str(&row, "publisher_zid", publisher);
        json_push_kv_int(&row, "sequence", (int64_t)records[i].sequence);
        json_push_back(out, &row);
        json_free(&row);
    }
}

static void entry_json(struct json_value *result,
                       const struct replication_public_entry *entry)
{
    const struct vcs_zcode_replication_status *status = &entry->status;
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "state", entry->cached ? "complete" : "pending");
    json_push_kv_bool(result, "partial", entry->cached ? status->partial : true);
    json_push_kv_bool(result, "local_cache_only",
                      entry->cached && status->local_cache_only);
    json_push_kv_str(result, "evidence_scope",
                     entry->cached && !status->local_cache_only
                         ? "iterative_dht" : "local_cache");
    json_push_kv_int(result, "target_providers", VCS_ZCODE_REPLICATION_TARGET);
    json_push_kv_int(result, "provider_hints", (int64_t)status->provider_hints);
    json_push_kv_int(result, "authenticated_providers",
                     (int64_t)status->authenticated_providers);
    json_push_kv_int(result, "live_signed_acks", (int64_t)status->valid_acks);
    json_push_kv_int(result, "valid_storage_acks", (int64_t)status->valid_acks);
    json_push_kv_int(result, "locally_revalidated_acks",
                     (int64_t)status->locally_revalidated_acks);
    json_push_kv_int(result, "declared_owner_groups",
                     (int64_t)status->declared_owner_groups);
    json_push_kv_int(result, "expired_acks", (int64_t)status->expired_acks);
    json_push_kv_int(result, "conflicted_records",
                     (int64_t)status->conflicted_records);
    json_push_kv_bool(result, "provider_evidence_complete",
                      status->provider_evidence_complete);
    json_push_kv_bool(result, "ack_evidence_complete",
                      status->ack_evidence_complete);
    json_push_kv_bool(result, "provider_discovery_incomplete",
                      entry->provider.incomplete);
    json_push_kv_bool(result, "ack_discovery_incomplete",
                      entry->ack.incomplete);
    json_push_kv_bool(result, "provider_discovery_truncated",
                      entry->provider.truncated);
    json_push_kv_bool(result, "ack_discovery_truncated",
                      entry->ack.truncated);
    json_push_kv_bool(result, "incomplete_evidence", status->partial);
    json_push_kv_bool(result, "conflicted_evidence",
                      status->conflicted_records != 0);
    json_push_kv_bool(result, "durable", status->durable);
    json_push_kv_bool(result, "remote_acks_locally_reverified", false);
    json_push_kv_bool(result, "owner_groups_prove_separate_operators", false);
    json_push_kv_int(result, "provider_records",
                     entry->provider.record_count);
    json_push_kv_int(result, "ack_records", entry->ack.record_count);
    json_push_kv_int(result, "provider_nodes_queried",
                     entry->provider.nodes_queried);
    json_push_kv_int(result, "ack_nodes_queried", entry->ack.nodes_queried);
    if (!entry->cached)
        return;
    struct vcs_zcode_dht_record records[VCS_ZCODE_REPLICATION_MAX_EVIDENCE];
    size_t count = entry->provider.record_count;
    memcpy(records, entry->provider.records, count * sizeof(*records));
    memcpy(records + count, entry->ack.records,
           entry->ack.record_count * sizeof(*records));
    count += entry->ack.record_count;
    struct json_value conflicts;
    json_init(&conflicts);
    conflict_json(&conflicts, records, count);
    json_push_kv(result, "conflicts", &conflicts);
    json_free(&conflicts);
}

static bool rpc_poll(const struct json_value *params, bool help,
                     struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "zcode_dht_replication_poll {lookup_id,owner_token}");
        return true;
    }
    uint8_t lookup[REPLICATION_TOKEN_BYTES], owner[REPLICATION_TOKEN_BYTES];
    if (!input_capability(rpc_input(params), lookup, owner)) {
        rpc_error(result, "INVALID_LOOKUP_CAPABILITY",
                  "lookup_id and owner_token must be canonical 32-hex values");
        return true;
    }
    struct vcs_zcode_dht_time now = replication_now();
    replication_lock();
    cleanup_locked(now.monotonic_s);
    struct replication_public_entry *entry = entry_find(lookup, owner);
    if (!entry) {
        zcl_mutex_unlock(&g_replication_lock);
        rpc_error(result, "LOOKUP_UNKNOWN",
                  "replication capability is unknown, expired, or not owned");
        return true;
    }
    bool interrupted = false;
    if (!entry->cached && !entry->provider_done) {
        interrupted = !child_poll(
            entry->provider_id, entry->service_generation, now,
            &entry->provider);
        entry->provider_done = !interrupted &&
            entry->provider.state != VCS_ZCODE_DHT_RECORD_OPERATION_PENDING;
    }
    if (!entry->cached && !entry->ack_done && !interrupted) {
        interrupted = !child_poll(
            entry->ack_id, entry->service_generation, now, &entry->ack);
        entry->ack_done = !interrupted &&
            entry->ack.state != VCS_ZCODE_DHT_RECORD_OPERATION_PENDING;
    }
    if (interrupted) {
        entry_cancel(entry);
        memset(entry, 0, sizeof(*entry));
        zcl_mutex_unlock(&g_replication_lock);
        rpc_error(result, "LOOKUP_INTERRUPTED",
                  "DHT service restarted during replication discovery");
        return true;
    }
    if (!entry->cached && entry->provider_done && entry->ack_done)
        entry_evaluate(entry, now);
    struct replication_public_entry snapshot = *entry;
    zcl_mutex_unlock(&g_replication_lock);
    entry_json(result, &snapshot);
    return true;
}

static bool rpc_cancel(const struct json_value *params, bool help,
                       struct json_value *result)
{
    if (help) {
        json_set_str(result,
                     "zcode_dht_replication_cancel {lookup_id,owner_token}");
        return true;
    }
    uint8_t lookup[REPLICATION_TOKEN_BYTES], owner[REPLICATION_TOKEN_BYTES];
    if (!input_capability(rpc_input(params), lookup, owner)) {
        rpc_error(result, "INVALID_LOOKUP_CAPABILITY",
                  "lookup_id and owner_token must be canonical 32-hex values");
        return true;
    }
    struct vcs_zcode_dht_time now = replication_now();
    replication_lock();
    cleanup_locked(now.monotonic_s);
    struct replication_public_entry *entry = entry_find(lookup, owner);
    if (!entry) {
        zcl_mutex_unlock(&g_replication_lock);
        rpc_error(result, "LOOKUP_UNKNOWN",
                  "replication capability is unknown, expired, or not owned");
        return true;
    }
    entry_cancel(entry);
    memset(entry, 0, sizeof(*entry));
    zcl_mutex_unlock(&g_replication_lock);
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_bool(result, "canceled", true);
    return true;
}

void boot_zcode_dht_replication_register_rpc(struct rpc_table *table)
{
    const struct rpc_command commands[] = {
        {"zcode", "zcode_dht_replication_begin", rpc_begin, true},
        {"zcode", "zcode_dht_replication_poll", rpc_poll, true},
        {"zcode", "zcode_dht_replication_cancel", rpc_cancel, true},
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}
