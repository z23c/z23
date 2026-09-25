/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Read-only diagnostic projection of bounded ZCODE work-node state. */

#include "zcode_work_node_internal.h"

#include "base/hex.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#define ZCODE_WORK_PROJECTED_WORKERS_MAX 8u

static void work_signer_fingerprint(const uint8_t signer[32], char out[65])
{
    static const char domain[] = "zcl.zcode.work.signer.fingerprint.v1";
    struct sha3_256_ctx hash;
    uint8_t digest[32];
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const uint8_t *)domain, sizeof(domain) - 1u);
    sha3_256_write(&hash, signer, 32);
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static const char *work_target_name(uint32_t target)
{
    return target == VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3
        ? "linux-x86_64-v3" : "unknown";
}

static void work_push_kind_names(struct json_value *row, uint32_t mask)
{
    static const struct {
        uint8_t kind;
        const char *name;
    } kinds[] = {
        { VCS_ZCODE_WORK_PROPOSE, "propose" }, { VCS_ZCODE_WORK_BUILD, "build" },
        { VCS_ZCODE_WORK_TEST, "test" }, { VCS_ZCODE_WORK_FUZZ, "fuzz" },
        { VCS_ZCODE_WORK_REVIEW, "review" }, { VCS_ZCODE_WORK_REPRODUCE, "reproduce" },
        { VCS_ZCODE_WORK_DIAGNOSE, "diagnose" },
    };
    struct json_value names = {0};
    json_set_array(&names);
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        if ((mask & (UINT32_C(1) << kinds[i].kind)) == 0) continue;
        struct json_value name = {0};
        json_set_str(&name, kinds[i].name);
        json_push_back(&names, &name);
        json_free(&name);
    }
    json_push_kv(row, "work_kinds", &names);
    json_free(&names);
}

static void work_push_confinement_names(struct json_value *row, uint32_t mask)
{
    static const struct {
        uint32_t bit;
        const char *name;
    } facts[] = {
        { VCS_ZCODE_WORK_CONFINEMENT_LANDLOCK, "landlock" },
        { VCS_ZCODE_WORK_CONFINEMENT_SECCOMP, "seccomp" },
        { VCS_ZCODE_WORK_CONFINEMENT_RLIMITS, "rlimits" },
        { VCS_ZCODE_WORK_CONFINEMENT_NO_NETWORK, "no_network" },
    };
    struct json_value names = {0};
    json_set_array(&names);
    for (size_t i = 0; i < sizeof(facts) / sizeof(facts[0]); i++) {
        if ((mask & facts[i].bit) == 0) continue;
        struct json_value name = {0};
        json_set_str(&name, facts[i].name);
        json_push_back(&names, &name);
        json_free(&name);
    }
    json_push_kv(row, "confinement", &names);
    json_free(&names);
}

static void work_push_worker(struct json_value *workers, uint64_t peer_id,
                             const struct vcs_zcode_work_capability_v1 *cap)
{
    char signer[65], toolchain[65];
    work_signer_fingerprint(cap->signer_pubkey, signer);
    zcl_hex_encode(cap->toolchain_capsule_root, 32, toolchain);
    struct json_value row = {0};
    json_set_object(&row);
    json_push_kv_int(&row, "peer_id", (int64_t)peer_id);
    json_push_kv_str(&row, "signer_fingerprint_sha3", signer);
    json_push_kv_str(&row, "toolchain_capsule_root", toolchain);
    json_push_kv_str(&row, "target", work_target_name(cap->target));
    json_push_kv_int(&row, "work_kinds_mask", (int64_t)cap->work_kinds);
    work_push_kind_names(&row, cap->work_kinds);
    json_push_kv_int(&row, "confinement_mask", (int64_t)cap->confinement);
    work_push_confinement_names(&row, cap->confinement);
    json_push_kv_int(&row, "max_cpu_seconds", cap->max_cpu_seconds);
    json_push_kv_int(&row, "max_memory_bytes", (int64_t)cap->max_memory_bytes);
    json_push_kv_int(&row, "max_output_bytes", (int64_t)cap->max_output_bytes);
    json_push_kv_int(&row, "max_lease_seconds", cap->max_lease_seconds);
    json_push_kv_int(&row, "slots", cap->slots);
    json_push_kv_int(&row, "queue_headroom", cap->queue_headroom);
    json_push_kv_int(&row, "expires_unix", cap->expires_unix);
    json_push_kv_str(&row, "freshness", "fresh");
    json_push_back(workers, &row);
    json_free(&row);
}

bool vcs_zcode_work_node_dump_state_json(struct json_value *out,
                                         const char *key)
{
    (void)key;
    if (!out) {
        LOG_FAIL("zcode_work", "dump_state_json: out is NULL");
    }
    json_set_object(out);
    struct vcs_zcode_work_node *node = vcs_zcode_work_node_global();
    if (!node) {
        json_push_kv_bool(out, "enabled", false);
        json_push_kv_int(out, "worker_capacity", 0);
        json_push_kv_int(out, "worker_active", 0);
        json_push_kv_int(out, "worker_available", 0);
        json_push_kv_int(out, "capable_peers", 0);
        json_push_kv_int(out, "total", 0);
        json_push_kv_int(out, "returned", 0);
        json_push_kv_bool(out, "truncated", false);
        struct json_value workers = {0};
        json_set_array(&workers);
        json_push_kv(out, "workers", &workers);
        json_free(&workers);
        json_push_kv_str(out, "next_action", "z23 join");
        return true;
    }
    int64_t now = platform_time_wall_unix();
    pthread_mutex_lock(&node->lock);
    size_t capacity = node->has_local_capability
        ? node->local_capability.slots : 0;
    if (capacity > sizeof(node->slots) / sizeof(node->slots[0]))
        capacity = sizeof(node->slots) / sizeof(node->slots[0]);
    size_t active = 0;
    for (size_t i = 0; i < capacity; i++)
        active += node->slots[i].used ? 1u : 0u;
    size_t total = 0, returned = 0;
    struct json_value workers = {0};
    json_set_array(&workers);
    for (size_t i = 0; i < VCS_ZCODE_WORK_NODE_MAX_PEERS; i++) {
        if (!node->peers[i].used || !node->peers[i].has_capability ||
            now <= 0 || now >= node->peers[i].capability.expires_unix)
            continue;
        total++;
        if (returned >= ZCODE_WORK_PROJECTED_WORKERS_MAX) continue;
        struct vcs_zcode_work_capability_v1 effective =
            zcode_work_node_effective_capability_internal(node, (int)i);
        work_push_worker(&workers, node->peers[i].id, &effective);
        returned++;
    }
    json_push_kv_bool(out, "enabled", node->has_local_capability);
    json_push_kv_int(out, "worker_capacity", (int64_t)capacity);
    json_push_kv_int(out, "worker_active", (int64_t)active);
    json_push_kv_int(out, "worker_available", (int64_t)(capacity - active));
    json_push_kv_int(out, "capable_peers", (int64_t)total);
    json_push_kv_int(out, "total", (int64_t)total);
    json_push_kv_int(out, "returned", (int64_t)returned);
    json_push_kv_bool(out, "truncated", returned < total);
    json_push_kv(out, "workers", &workers);
    json_free(&workers);
    json_push_kv_str(out, "next_action",
        node->has_local_capability
            ? "zcode work toolchain"
            : "z23 join");
    pthread_mutex_unlock(&node->lock);
    return true;
}
