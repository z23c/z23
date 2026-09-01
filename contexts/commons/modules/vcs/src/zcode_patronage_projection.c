/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rebuild simulation patronage views from canonical CAS objects. */
#include "vcs/zcode_patronage_projection.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_continuity_policy.h"
#include "vcs/zcode_patronage_funding.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATRONAGE_PROJECTION_LOG "vcs.patronage_projection"

static const uint8_t intent_magic[8] =
    {'Z','C','P','A','T','R','\r','\n'};
static const uint8_t funding_magic[8] =
    {'Z','C','P','F','U','N','\r','\n'};
static const uint8_t continuity_magic[8] =
    {'Z','C','C','O','N','T','\r','\n'};

struct vcs_zcode_patronage_projection {
    struct vcs_zcode_patronage_projection_entry *entries;
    size_t count;
    bool has_failure;
    uint8_t failure_root[32];
    char failure_reason[48];
};

static bool projection_hex(const char *text, size_t length)
{
    for (size_t i = 0; i < length; i++) {
        char c = text[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return text[length] == '\0';
}

static void projection_failure(
    struct vcs_zcode_patronage_projection *projection,
    const uint8_t root[32], const char *reason)
{
    if (projection->has_failure &&
        memcmp(root, projection->failure_root, 32) >= 0)
        return;
    projection->has_failure = true;
    memcpy(projection->failure_root, root, 32);
    (void)snprintf(projection->failure_reason,
                   sizeof(projection->failure_reason), "%s", reason);
}

static int projection_cmp(const void *left, const void *right)
{
    return memcmp(
        ((const struct vcs_zcode_patronage_projection_entry *)left)->root,
        ((const struct vcs_zcode_patronage_projection_entry *)right)->root,
        32);
}

static void projection_add(
    struct vcs_zcode_patronage_projection *projection,
    const uint8_t root[32], const uint8_t target[32], uint8_t kind,
    uint64_t amount, int64_t created, int64_t expires)
{
    if (projection->count >= VCS_ZCODE_PATRONAGE_PROJECTION_MAX_OBJECTS) {
        projection_failure(projection, root, "object-cap");
        return;
    }
    struct vcs_zcode_patronage_projection_entry *entry =
        &projection->entries[projection->count++];
    memset(entry, 0, sizeof(*entry));
    memcpy(entry->root, root, 32);
    memcpy(entry->target_root, target, 32);
    entry->kind = kind;
    entry->amount_atoms = amount;
    entry->created_unix = created;
    entry->expires_unix = expires;
}

static void projection_consider_intent(
    struct vcs_zcode_patronage_projection *projection,
    const struct vcs_zcode_patronage_validation_context *context,
    const uint8_t address[32], const uint8_t *wire, size_t wire_len)
{
    struct vcs_zcode_patronage_intent_v1 intent;
    uint8_t root[32];
    struct vcs_zcode_patronage_validation_context historical = *context;
    bool ok = vcs_zcode_patronage_intent_parse(wire, wire_len, &intent) ==
            VCS_ZCODE_PATRONAGE_OK &&
        vcs_zcode_patronage_intent_root(&intent, root) ==
            VCS_ZCODE_PATRONAGE_OK && memcmp(root, address, 32) == 0;
    if (ok) {
        historical.now_unix = intent.created_unix;
        ok = vcs_zcode_patronage_intent_verify_cas(
            &intent, &historical) == VCS_ZCODE_PATRONAGE_OK;
    }
    if (!ok) {
        projection_failure(projection, address, "intent-authority");
        return;
    }
    projection_add(projection, address, intent.target_root,
                   VCS_ZCODE_PATRONAGE_PROJECTION_OFFER,
                   intent.amount_atoms, intent.created_unix,
                   intent.expires_unix);
}

static void projection_consider_funding(
    struct vcs_zcode_patronage_projection *projection,
    const struct vcs_zcode_patronage_validation_context *context,
    const uint8_t address[32], const uint8_t *wire, size_t wire_len)
{
    struct vcs_zcode_patronage_funding_v1 funding;
    uint8_t root[32];
    struct vcs_zcode_patronage_validation_context historical = *context;
    bool ok = vcs_zcode_patronage_funding_parse(wire, wire_len, &funding) ==
            VCS_ZCODE_PATRONAGE_FUNDING_OK &&
        vcs_zcode_patronage_funding_root(&funding, root) ==
            VCS_ZCODE_PATRONAGE_FUNDING_OK && memcmp(root, address, 32) == 0;
    if (ok) {
        historical.now_unix = funding.created_unix;
        ok = vcs_zcode_patronage_funding_verify_cas(
            &funding, &historical) == VCS_ZCODE_PATRONAGE_FUNDING_OK;
    }
    if (!ok) {
        projection_failure(projection, address, "funding-authority");
        return;
    }
    projection_add(projection, address, funding.patronage_intent_root,
                   VCS_ZCODE_PATRONAGE_PROJECTION_SIMULATED_FUNDING,
                   funding.amount_atoms, funding.created_unix, 0);
}

static void projection_consider_continuity(
    struct vcs_zcode_patronage_projection *projection,
    const struct vcs_zcode_patronage_validation_context *context,
    const uint8_t address[32], const uint8_t *wire, size_t wire_len)
{
    struct vcs_zcode_continuity_policy_v1 policy;
    uint8_t root[32];
    struct vcs_zcode_patronage_validation_context historical = *context;
    bool ok = vcs_zcode_continuity_policy_parse(wire, wire_len, &policy) ==
            VCS_ZCODE_CONTINUITY_OK &&
        vcs_zcode_continuity_policy_root(&policy, root) ==
            VCS_ZCODE_CONTINUITY_OK && memcmp(root, address, 32) == 0;
    if (ok) {
        historical.now_unix = policy.created_unix;
        ok = vcs_zcode_continuity_policy_verify_cas(
            &policy, &historical) == VCS_ZCODE_CONTINUITY_OK;
    }
    if (!ok) {
        projection_failure(projection, address, "continuity-authority");
        return;
    }
    projection_add(projection, address, policy.package_root,
                   VCS_ZCODE_PATRONAGE_PROJECTION_CONTINUITY_POLICY,
                   policy.total_cap_atoms, policy.created_unix,
                   policy.expires_unix);
}

static void projection_consider(
    struct vcs_zcode_patronage_projection *projection,
    const struct vcs_zcode_patronage_validation_context *context,
    const char *hex64)
{
    uint8_t address[32], *wire = NULL;
    size_t wire_len = 0;
    if (!zcl_hex_decode_lower(hex64, address, 32)) return;
    int loaded = vcs_object_load_raw_bounded(
        context->workspace, address, VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES,
        &wire, &wire_len);
    if (loaded != 0) return;
    if (wire_len == VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES &&
        memcmp(wire, intent_magic, 8) == 0)
        projection_consider_intent(
            projection, context, address, wire, wire_len);
    else if (wire_len == VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES &&
             memcmp(wire, funding_magic, 8) == 0)
        projection_consider_funding(
            projection, context, address, wire, wire_len);
    else if (wire_len == VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES &&
             memcmp(wire, continuity_magic, 8) == 0)
        projection_consider_continuity(
            projection, context, address, wire, wire_len);
    free(wire);
}

static void projection_scan_shard(
    struct vcs_zcode_patronage_projection *projection,
    const struct vcs_zcode_patronage_validation_context *context,
    const char *objects, const char *shard)
{
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/%s", objects, shard);
    if (n <= 0 || (size_t)n >= sizeof(path)) return;
    DIR *directory = opendir(path);
    if (!directory) return;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (!projection_hex(entry->d_name, 62)) continue;
        char hex64[65];
        n = snprintf(hex64, sizeof(hex64), "%s%s", shard, entry->d_name);
        if (n == 64) projection_consider(projection, context, hex64);
    }
    closedir(directory);
}

struct vcs_zcode_patronage_projection *
vcs_zcode_patronage_projection_build(
    const struct vcs_zcode_patronage_validation_context *context)
{
    if (!context || !context->workspace ||
        !context->expected_network_genesis_root || context->now_unix <= 0)
        LOG_RETURN(NULL, PATRONAGE_PROJECTION_LOG, "invalid context");
    struct vcs_zcode_patronage_projection *projection =
        zcl_calloc(1, sizeof(*projection), "zcode_patronage_projection");
    if (!projection) return NULL;
    projection->entries = zcl_calloc(
        VCS_ZCODE_PATRONAGE_PROJECTION_MAX_OBJECTS,
        sizeof(*projection->entries), "zcode_patronage_entries");
    if (!projection->entries) {
        vcs_zcode_patronage_projection_free(projection);
        return NULL;
    }
    char objects[4400];
    int n = snprintf(objects, sizeof(objects), "%s/.zvcs/objects",
                     context->workspace);
    if (n <= 0 || (size_t)n >= sizeof(objects)) {
        vcs_zcode_patronage_projection_free(projection);
        return NULL;
    }
    DIR *directory = opendir(objects);
    if (!directory) return projection;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL)
        if (projection_hex(entry->d_name, 2))
            projection_scan_shard(
                projection, context, objects, entry->d_name);
    closedir(directory);
    qsort(projection->entries, projection->count,
          sizeof(*projection->entries), projection_cmp);
    return projection;
}

void vcs_zcode_patronage_projection_free(
    struct vcs_zcode_patronage_projection *projection)
{
    if (!projection) return;
    free(projection->entries);
    free(projection);
}

size_t vcs_zcode_patronage_projection_count(
    const struct vcs_zcode_patronage_projection *projection)
{ return projection ? projection->count : 0; }

const struct vcs_zcode_patronage_projection_entry *
vcs_zcode_patronage_projection_at(
    const struct vcs_zcode_patronage_projection *projection, size_t index)
{ return projection && index < projection->count
    ? &projection->entries[index] : NULL; }

bool vcs_zcode_patronage_projection_root(
    const struct vcs_zcode_patronage_projection *projection, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!projection || !out) return false;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_PATRONAGE_PROJECTION_DOMAIN;
    uint8_t le64[8];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    zcl_write_u64_le(le64, projection->count);
    sha3_256_write(&sha, le64, sizeof(le64));
    for (size_t i = 0; i < projection->count; i++) {
        const struct vcs_zcode_patronage_projection_entry *entry =
            &projection->entries[i];
        sha3_256_write(&sha, entry->root, 32);
        sha3_256_write(&sha, &entry->kind, sizeof(entry->kind));
    }
    sha3_256_finalize(&sha, out);
    return true;
}

bool vcs_zcode_patronage_projection_first_failure(
    const struct vcs_zcode_patronage_projection *projection,
    uint8_t root_out[32], const char **reason_out)
{
    if (root_out) memset(root_out, 0, 32);
    if (reason_out) *reason_out = NULL;
    if (!projection || !projection->has_failure || !root_out || !reason_out)
        return false;
    memcpy(root_out, projection->failure_root, 32);
    *reason_out = projection->failure_reason;
    return true;
}
