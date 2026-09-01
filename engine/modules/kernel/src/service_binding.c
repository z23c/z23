/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure validation, canonical SHA3 identity, snapshot-height resolution, and
 * the lifecycle transition table for `zcl.service_binding.v1`.
 *
 * This module performs no launch, no database access, no ledger read, and no
 * authorization. It decides only whether a DECLARATION is well formed. The
 * isolation boundary is enforced here in the only place it can be enforced
 * mechanically: a binding that does not carry the complete required flag set,
 * or that claims a reserved command root or a reserved state-table prefix,
 * does not validate — and an invalid binding fails the catalog, which fails
 * the build's contract test. */

#include "kernel/service_binding.h"

#include "crypto/sha3.h"

#include <string.h>

/* State-table prefixes a service may never claim. Each is the head of a
 * consensus, kernel, or wallet-custody table family: letting a service own
 * one would hand it a write path into state it is declared not to touch.
 * Matching is by prefix in BOTH directions, so "block" also refuses
 * "blocks_extra" and "bl" is refused for being a prefix of "blocks". */
static const char *const g_reserved_state_prefixes[] = {
    "anchor",   "block",     "chain",    "coin",     "consensus",
    "evidence", "header",    "mempool",  "nullifier","progress",
    "sapling",  "schema",    "sprout",   "stage",    "tx",
    "utxo",     "wallet",    "zslp",
};

static bool text_bounded(const char *text, size_t capacity, size_t *out_len)
{
    const char *end = memchr(text, '\0', capacity);
    if (!end)
        return false;
    if (out_len)
        *out_len = (size_t)(end - text);
    return true;
}

/* Lowercase identifier: [a-z][a-z0-9_-]*  (dotted adds '.'). */
static bool canonical_ident(const char *text, size_t capacity, bool dotted)
{
    size_t length = 0;
    if (!text_bounded(text, capacity, &length) || length == 0)
        return false;
    if (text[0] < 'a' || text[0] > 'z')
        return false;
    for (size_t i = 0; i < length; i++) {
        char c = text[i];
        bool lower = c >= 'a' && c <= 'z';
        bool digit = c >= '0' && c <= '9';
        bool sep = c == '_' || c == '-';
        if (dotted)
            sep = sep || c == '.';
        if (!lower && !digit && !sep)
            return false;
    }
    return true;
}

/* Version is deliberately looser than an identifier (digits and dots lead)
 * but still bounded and printable-ASCII-restricted. */
static bool canonical_version(const char *text, size_t capacity)
{
    size_t length = 0;
    if (!text_bounded(text, capacity, &length) || length == 0)
        return false;
    if (text[0] < '0' || text[0] > '9')
        return false;
    for (size_t i = 0; i < length; i++) {
        char c = text[i];
        bool digit = c >= '0' && c <= '9';
        bool lower = c >= 'a' && c <= 'z';
        if (!digit && !lower && c != '.' && c != '-')
            return false;
    }
    return true;
}

/* Native command leaf names the service registry itself owns directly under
 * ZCL_SERVICE_BINDING_COMMAND_ROOT. A service may not take one of these as
 * its name, or its namespace would shadow the registry's own leaf. */
static const char *const g_reserved_service_names[] = {
    "access", "catalog", "inspect", "list", "status",
};

static bool token_id_is_zero(const uint8_t token[32])
{
    uint8_t seen = 0;
    for (size_t i = 0; i < 32; i++)
        seen |= token[i];
    return seen == 0;
}

bool zcl_service_gate_token_unminted_v1(const uint8_t token_genesis_txid[32])
{
    if (!token_genesis_txid)
        return false;
    for (size_t i = 0; i < 32; i++)
        if (token_genesis_txid[i] != ZCL_SERVICE_GATE_TOKEN_UNMINTED_BYTE)
            return false;
    return true;
}

static bool prefix_overlaps(const char *a, const char *b)
{
    size_t la = strlen(a);
    size_t lb = strlen(b);
    size_t shortest = la < lb ? la : lb;
    return memcmp(a, b, shortest) == 0;
}

const char *zcl_service_binding_result_name_v1(
    enum zcl_service_binding_result result)
{
    switch (result) {
    case ZCL_SERVICE_BINDING_OK: return "ok";
    case ZCL_SERVICE_BINDING_NULL: return "null";
    case ZCL_SERVICE_BINDING_SCHEMA: return "schema";
    case ZCL_SERVICE_BINDING_IDENTITY: return "identity";
    case ZCL_SERVICE_BINDING_HOST: return "host";
    case ZCL_SERVICE_BINDING_COMMAND_PREFIX: return "command_prefix";
    case ZCL_SERVICE_BINDING_STATE_PREFIX: return "state_prefix";
    case ZCL_SERVICE_BINDING_STATE_SCHEMA: return "state_schema";
    case ZCL_SERVICE_BINDING_TOKEN_GATE: return "token_gate";
    case ZCL_SERVICE_BINDING_ISOLATION: return "isolation";
    case ZCL_SERVICE_BINDING_RESTART: return "restart";
    case ZCL_SERVICE_BINDING_HEALTH: return "health";
    case ZCL_SERVICE_BINDING_CATALOG_ORDER: return "catalog_order";
    case ZCL_SERVICE_BINDING_CATALOG_COLLISION: return "catalog_collision";
    }
    return "unknown";
}

static enum zcl_service_binding_result validate_command_prefix(
    const struct zcl_service_binding_v1 *binding)
{
    size_t length = 0;
    if (!text_bounded(binding->command_prefix,
                      sizeof(binding->command_prefix), &length))
        return ZCL_SERVICE_BINDING_COMMAND_PREFIX;
    if (!canonical_ident(binding->command_prefix,
                         sizeof(binding->command_prefix), true))
        return ZCL_SERVICE_BINDING_COMMAND_PREFIX;
    const size_t root_len = sizeof(ZCL_SERVICE_BINDING_COMMAND_ROOT) - 1u;
    if (length <= root_len ||
        memcmp(binding->command_prefix,
               ZCL_SERVICE_BINDING_COMMAND_ROOT, root_len) != 0)
        return ZCL_SERVICE_BINDING_COMMAND_PREFIX;
    /* The tail under the root is exactly the service name — one identity, not
     * two that can drift apart. */
    if (strcmp(binding->command_prefix + root_len, binding->name) != 0)
        return ZCL_SERVICE_BINDING_COMMAND_PREFIX;
    return ZCL_SERVICE_BINDING_OK;
}

static enum zcl_service_binding_result validate_state_prefix(
    const struct zcl_service_binding_v1 *binding)
{
    size_t length = 0;
    if (!text_bounded(binding->state_table_prefix,
                      sizeof(binding->state_table_prefix), &length) ||
        length < 4u)
        return ZCL_SERVICE_BINDING_STATE_PREFIX;
    if (!canonical_ident(binding->state_table_prefix,
                         sizeof(binding->state_table_prefix), false))
        return ZCL_SERVICE_BINDING_STATE_PREFIX;
    /* A prefix that does not end in '_' would let "svcx" own "svcxyz". */
    if (binding->state_table_prefix[length - 1u] != '_')
        return ZCL_SERVICE_BINDING_STATE_PREFIX;
    for (size_t i = 0; i < sizeof(g_reserved_state_prefixes) /
                               sizeof(g_reserved_state_prefixes[0]); i++) {
        if (prefix_overlaps(binding->state_table_prefix,
                            g_reserved_state_prefixes[i]))
            return ZCL_SERVICE_BINDING_STATE_PREFIX;
    }
    return ZCL_SERVICE_BINDING_OK;
}

static enum zcl_service_binding_result validate_gate(
    const struct zcl_service_token_gate_v1 *gate)
{
    if (token_id_is_zero(gate->token_genesis_txid) || gate->min_balance == 0)
        return ZCL_SERVICE_BINDING_TOKEN_GATE;
    if (gate->holder_kind != ZCL_SERVICE_GATE_HOLDER_WALLET &&
        gate->holder_kind != ZCL_SERVICE_GATE_HOLDER_ADDRESS)
        return ZCL_SERVICE_BINDING_TOKEN_GATE;
    if (gate->snapshot_kind == ZCL_SERVICE_GATE_SNAPSHOT_CONFIRMED_DEPTH) {
        if (gate->snapshot_param < 1 ||
            gate->snapshot_param > ZCL_SERVICE_GATE_DEPTH_MAX)
            return ZCL_SERVICE_BINDING_TOKEN_GATE;
        return ZCL_SERVICE_BINDING_OK;
    }
    if (gate->snapshot_kind == ZCL_SERVICE_GATE_SNAPSHOT_FIXED_HEIGHT) {
        if (gate->snapshot_param < 0)
            return ZCL_SERVICE_BINDING_TOKEN_GATE;
        return ZCL_SERVICE_BINDING_OK;
    }
    return ZCL_SERVICE_BINDING_TOKEN_GATE;
}

enum zcl_service_binding_result zcl_service_binding_validate_v1(
    const struct zcl_service_binding_v1 *binding)
{
    if (!binding)
        return ZCL_SERVICE_BINDING_NULL;
    if (binding->struct_size != sizeof(*binding) ||
        binding->schema_version != ZCL_SERVICE_BINDING_V1)
        return ZCL_SERVICE_BINDING_SCHEMA;
    if (binding->binding_id == 0 ||
        !canonical_ident(binding->name, sizeof(binding->name), false) ||
        !canonical_version(binding->version, sizeof(binding->version)))
        return ZCL_SERVICE_BINDING_IDENTITY;
    for (size_t i = 0; i < sizeof(g_reserved_service_names) /
                               sizeof(g_reserved_service_names[0]); i++) {
        if (strcmp(binding->name, g_reserved_service_names[i]) == 0)
            return ZCL_SERVICE_BINDING_IDENTITY;
    }
    size_t display_len = 0;
    if (!text_bounded(binding->display_name, sizeof(binding->display_name),
                      &display_len) || display_len == 0)
        return ZCL_SERVICE_BINDING_IDENTITY;
    if (binding->host_service_id == 0)
        return ZCL_SERVICE_BINDING_HOST;

    enum zcl_service_binding_result result = validate_command_prefix(binding);
    if (result != ZCL_SERVICE_BINDING_OK)
        return result;
    result = validate_state_prefix(binding);
    if (result != ZCL_SERVICE_BINDING_OK)
        return result;

    if (!canonical_ident(binding->state_schema, sizeof(binding->state_schema),
                         true) || binding->state_schema_version == 0)
        return ZCL_SERVICE_BINDING_STATE_SCHEMA;

    result = validate_gate(&binding->gate);
    if (result != ZCL_SERVICE_BINDING_OK)
        return result;

    /* The whole boundary, exactly. No subset (a dropped bit is a claimed
     * privilege) and no superset (an unknown bit is an undeclared one). */
    if (binding->isolation != ZCL_SERVICE_ISOLATION_REQUIRED_V1)
        return ZCL_SERVICE_BINDING_ISOLATION;

    if (binding->restart_policy > ZCL_SERVICE_RESTART_PERMANENT)
        return ZCL_SERVICE_BINDING_RESTART;
    if (binding->health_deadline_ms == 0 ||
        binding->health_deadline_ms > UINT64_C(600000))
        return ZCL_SERVICE_BINDING_HEALTH;
    return ZCL_SERVICE_BINDING_OK;
}

enum zcl_service_binding_result zcl_service_binding_catalog_validate_v1(
    const struct zcl_service_binding_v1 *bindings,
    size_t count,
    size_t *bad_index)
{
    if (bad_index)
        *bad_index = 0;
    if (!bindings || count == 0 || count > ZCL_SERVICE_BINDING_CATALOG_MAX)
        return ZCL_SERVICE_BINDING_NULL;
    for (size_t i = 0; i < count; i++) {
        enum zcl_service_binding_result result =
            zcl_service_binding_validate_v1(&bindings[i]);
        if (result != ZCL_SERVICE_BINDING_OK) {
            if (bad_index)
                *bad_index = i;
            return result;
        }
        if (i > 0 && bindings[i - 1].binding_id >= bindings[i].binding_id) {
            if (bad_index)
                *bad_index = i;
            return ZCL_SERVICE_BINDING_CATALOG_ORDER;
        }
        for (size_t j = 0; j < i; j++) {
            bool collides =
                strcmp(bindings[i].name, bindings[j].name) == 0 ||
                strcmp(bindings[i].command_prefix,
                       bindings[j].command_prefix) == 0 ||
                prefix_overlaps(bindings[i].state_table_prefix,
                                bindings[j].state_table_prefix);
            if (collides) {
                if (bad_index)
                    *bad_index = i;
                return ZCL_SERVICE_BINDING_CATALOG_COLLISION;
            }
        }
    }
    return ZCL_SERVICE_BINDING_OK;
}

enum zcl_service_binding_result zcl_service_binding_host_check_v1(
    const struct zcl_service_binding_v1 *binding,
    const struct zcl_service_manifest_v1 *manifests,
    size_t manifest_count)
{
    if (!binding || !manifests || manifest_count == 0)
        return ZCL_SERVICE_BINDING_NULL;
    for (size_t i = 0; i < manifest_count; i++) {
        if (manifests[i].service_id != binding->host_service_id)
            continue;
        /* Only the app broker may host a service. Hosting on core, wallet, or
         * init would inherit consensus, custody, or supervisor descriptors —
         * exactly the grants the isolation flags say a service does not get. */
        if (manifests[i].trust_class != ZCL_SERVICE_TRUST_APP_BROKER ||
            manifests[i].role != ZCL_SERVICE_ROLE_APPD)
            return ZCL_SERVICE_BINDING_HOST;
        return ZCL_SERVICE_BINDING_OK;
    }
    return ZCL_SERVICE_BINDING_HOST;
}

/* ── canonical identity ──────────────────────────────────────────────── */

static void digest_u32(struct sha3_256_ctx *ctx, uint32_t value)
{
    uint8_t encoded[4];
    for (size_t i = 0; i < sizeof(encoded); i++)
        encoded[i] = (uint8_t)(value >> (8u * i));
    sha3_256_write(ctx, encoded, sizeof(encoded));
}

static void digest_u64(struct sha3_256_ctx *ctx, uint64_t value)
{
    uint8_t encoded[8];
    for (size_t i = 0; i < sizeof(encoded); i++)
        encoded[i] = (uint8_t)(value >> (8u * i));
    sha3_256_write(ctx, encoded, sizeof(encoded));
}

static void digest_text(struct sha3_256_ctx *ctx, const char *text,
                        size_t capacity)
{
    size_t length = strnlen(text, capacity);
    digest_u32(ctx, (uint32_t)length);
    sha3_256_write(ctx, (const uint8_t *)text, length);
}

bool zcl_service_binding_digest_v1(
    const struct zcl_service_binding_v1 *binding, uint8_t out[32])
{
    if (!out)
        return false;
    memset(out, 0, 32);
    if (zcl_service_binding_validate_v1(binding) != ZCL_SERVICE_BINDING_OK)
        return false;
    static const uint8_t domain[] = ZCL_SERVICE_BINDING_SCHEMA_NAME;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, domain, sizeof(domain));
    digest_u32(&ctx, binding->schema_version);
    digest_u32(&ctx, binding->binding_id);
    digest_text(&ctx, binding->name, sizeof(binding->name));
    digest_text(&ctx, binding->display_name, sizeof(binding->display_name));
    digest_text(&ctx, binding->version, sizeof(binding->version));
    digest_u32(&ctx, binding->host_service_id);
    digest_text(&ctx, binding->command_prefix,
                sizeof(binding->command_prefix));
    digest_text(&ctx, binding->state_table_prefix,
                sizeof(binding->state_table_prefix));
    digest_text(&ctx, binding->state_schema, sizeof(binding->state_schema));
    digest_u32(&ctx, binding->state_schema_version);
    sha3_256_write(&ctx, binding->gate.token_genesis_txid, 32);
    digest_u64(&ctx, binding->gate.min_balance);
    digest_u32(&ctx, binding->gate.snapshot_kind);
    digest_u32(&ctx, binding->gate.holder_kind);
    digest_u32(&ctx, (uint32_t)binding->gate.snapshot_param);
    digest_u64(&ctx, binding->isolation);
    digest_u32(&ctx, binding->restart_policy);
    digest_u64(&ctx, binding->health_deadline_ms);
    sha3_256_finalize(&ctx, out);
    return true;
}

bool zcl_service_binding_catalog_digest_v1(
    const struct zcl_service_binding_v1 *bindings,
    size_t count,
    uint8_t out[32])
{
    if (!out)
        return false;
    memset(out, 0, 32);
    if (zcl_service_binding_catalog_validate_v1(bindings, count, NULL) !=
        ZCL_SERVICE_BINDING_OK)
        return false;
    static const uint8_t domain[] = ZCL_SERVICE_BINDING_CATALOG_SCHEMA_NAME;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, domain, sizeof(domain));
    digest_u32(&ctx, (uint32_t)count);
    for (size_t i = 0; i < count; i++) {
        uint8_t digest[32];
        if (!zcl_service_binding_digest_v1(&bindings[i], digest)) {
            memset(out, 0, 32);
            return false;
        }
        sha3_256_write(&ctx, digest, sizeof(digest));
    }
    sha3_256_finalize(&ctx, out);
    return true;
}

/* ── token binding: the reproducible snapshot height ─────────────────── */

bool zcl_service_gate_snapshot_height_v1(
    const struct zcl_service_token_gate_v1 *gate,
    int32_t tip_height,
    int32_t *out_height)
{
    if (!gate || !out_height)
        return false;
    *out_height = -1;
    if (validate_gate(gate) != ZCL_SERVICE_BINDING_OK)
        return false;
    if (gate->snapshot_kind == ZCL_SERVICE_GATE_SNAPSHOT_FIXED_HEIGHT) {
        *out_height = gate->snapshot_param;
        return true;
    }
    /* CONFIRMED_DEPTH. A chain shorter than the declared depth has no such
     * snapshot; clamping to 0 would silently answer a different question. */
    if (tip_height < 0 || tip_height < gate->snapshot_param)
        return false;
    *out_height = tip_height - gate->snapshot_param;
    return true;
}

bool zcl_service_binding_owns_table_v1(
    const struct zcl_service_binding_v1 *binding, const char *table)
{
    if (!binding || !table || !table[0])
        return false;
    if (zcl_service_binding_validate_v1(binding) != ZCL_SERVICE_BINDING_OK)
        return false;
    size_t prefix_len = strnlen(binding->state_table_prefix,
                                sizeof(binding->state_table_prefix));
    size_t table_len = strnlen(table, 256);
    if (table_len <= prefix_len || table_len >= 256)
        return false;
    return memcmp(table, binding->state_table_prefix, prefix_len) == 0;
}

bool zcl_service_binding_owns_command_v1(
    const struct zcl_service_binding_v1 *binding, const char *path)
{
    if (!binding || !path || !path[0])
        return false;
    if (zcl_service_binding_validate_v1(binding) != ZCL_SERVICE_BINDING_OK)
        return false;
    size_t prefix_len = strnlen(binding->command_prefix,
                                sizeof(binding->command_prefix));
    size_t path_len = strnlen(path, 256);
    if (path_len >= 256 || path_len < prefix_len)
        return false;
    if (memcmp(path, binding->command_prefix, prefix_len) != 0)
        return false;
    /* Exactly the prefix, or a dotted child of it. */
    return path_len == prefix_len || path[prefix_len] == '.';
}

/* ── lifecycle ───────────────────────────────────────────────────────── */

bool zcl_service_lifecycle_next_v1(uint32_t state, uint32_t event,
                                   uint32_t *out_state)
{
    if (!out_state)
        return false;
    uint32_t next = 0;
    switch (event) {
    case ZCL_SERVICE_EVENT_REGISTER:
        if (state != ZCL_SERVICE_LIFECYCLE_DECLARED)
            return false;
        next = ZCL_SERVICE_LIFECYCLE_STARTING;
        break;
    case ZCL_SERVICE_EVENT_START:
        if (state != ZCL_SERVICE_LIFECYCLE_STARTING)
            return false;
        next = ZCL_SERVICE_LIFECYCLE_READY;
        break;
    case ZCL_SERVICE_EVENT_DEGRADE:
        if (state != ZCL_SERVICE_LIFECYCLE_READY)
            return false;
        next = ZCL_SERVICE_LIFECYCLE_DEGRADED;
        break;
    case ZCL_SERVICE_EVENT_RECOVER:
        if (state != ZCL_SERVICE_LIFECYCLE_DEGRADED)
            return false;
        next = ZCL_SERVICE_LIFECYCLE_READY;
        break;
    case ZCL_SERVICE_EVENT_FAULT:
        /* A fault is reachable from every live state and from nowhere else.
         * BLOCKED is sticky on purpose: the only way out is a named stop. */
        if (state != ZCL_SERVICE_LIFECYCLE_STARTING &&
            state != ZCL_SERVICE_LIFECYCLE_READY &&
            state != ZCL_SERVICE_LIFECYCLE_DEGRADED)
            return false;
        next = ZCL_SERVICE_LIFECYCLE_BLOCKED;
        break;
    case ZCL_SERVICE_EVENT_STOP:
        if (state != ZCL_SERVICE_LIFECYCLE_STARTING &&
            state != ZCL_SERVICE_LIFECYCLE_READY &&
            state != ZCL_SERVICE_LIFECYCLE_DEGRADED &&
            state != ZCL_SERVICE_LIFECYCLE_BLOCKED)
            return false;
        next = ZCL_SERVICE_LIFECYCLE_STOPPING;
        break;
    case ZCL_SERVICE_EVENT_EXIT:
        if (state != ZCL_SERVICE_LIFECYCLE_STOPPING)
            return false;
        next = ZCL_SERVICE_LIFECYCLE_EXITED;
        break;
    case ZCL_SERVICE_EVENT_REMOVE:
        if (state != ZCL_SERVICE_LIFECYCLE_EXITED)
            return false;
        next = ZCL_SERVICE_LIFECYCLE_DECLARED;
        break;
    default:
        return false;
    }
    *out_state = next;
    return true;
}

const char *zcl_service_lifecycle_name_v1(uint32_t state)
{
    switch (state) {
    case ZCL_SERVICE_LIFECYCLE_DECLARED: return "declared";
    case ZCL_SERVICE_LIFECYCLE_STARTING: return "starting";
    case ZCL_SERVICE_LIFECYCLE_READY: return "ready";
    case ZCL_SERVICE_LIFECYCLE_DEGRADED: return "degraded";
    case ZCL_SERVICE_LIFECYCLE_BLOCKED: return "blocked";
    case ZCL_SERVICE_LIFECYCLE_STOPPING: return "stopping";
    case ZCL_SERVICE_LIFECYCLE_EXITED: return "exited";
    default: return "unknown";
    }
}
