/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded, fair possession-proof composition for DHT ACKs. */

#include "config/boot_zcode_dht_possession.h"

#include "base/hex.h"
#include "json/json.h"
#include "util/sync.h"
#include "vcs/package_manifest.h"
#include "vcs/package_possession_scheduler.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define ACK_PROOF_PACKAGES_PER_CYCLE 1u
#define ACK_PROOF_CHUNKS_PER_PACKAGE_CYCLE 1u
#define ACK_PROOF_BYTES_PER_CYCLE VCS_PACKAGE_CHUNK_BYTES
#define ACK_PROOF_SCRUB_INTERVAL_S (6u * 60u * 60u)
#define ACK_PROOF_FAILURE_RETRY_S 30u

static zcl_mutex_t g_possession_lock;
static _Atomic int g_possession_lock_state;
static struct vcs_package_possession_scheduler *g_scheduler;

struct possession_apply_one {
    boot_zcode_dht_possession_apply_fn apply;
    void *context;
    const uint8_t *root;
    uint64_t proof_epoch;
};

static void possession_apply_current(void *opaque, bool current)
{
    struct possession_apply_one *item = opaque;
    item->apply(item->context, item->root, item->proof_epoch, current);
}

static void possession_lock(void)
{
    if (atomic_load_explicit(&g_possession_lock_state,
                             memory_order_acquire) != 2) {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_possession_lock_state, &expected, 1,
                memory_order_acq_rel, memory_order_acquire)) {
            zcl_mutex_init(&g_possession_lock);
            atomic_store_explicit(&g_possession_lock_state, 2,
                                  memory_order_release);
        } else {
            while (atomic_load_explicit(&g_possession_lock_state,
                                        memory_order_acquire) != 2)
                ;
        }
    }
    zcl_mutex_lock(&g_possession_lock);
}

static bool possession_ensure(void)
{
    if (g_scheduler)
        return true;
    const struct vcs_package_possession_scheduler_config config = {
        .packages_per_cycle = ACK_PROOF_PACKAGES_PER_CYCLE,
        .chunks_per_package_cycle =
            ACK_PROOF_CHUNKS_PER_PACKAGE_CYCLE,
        .bytes_per_cycle = ACK_PROOF_BYTES_PER_CYCLE,
        .scrub_interval_s = ACK_PROOF_SCRUB_INTERVAL_S,
        .failure_retry_s = ACK_PROOF_FAILURE_RETRY_S,
    };
    g_scheduler = vcs_package_possession_scheduler_new(&config);
    return g_scheduler != NULL;
}

size_t boot_zcode_dht_possession_cycle(
    struct vcs_package_store *store,
    const struct vcs_zcode_dht_storage_ack_proof_request *requests,
    size_t request_count, uint64_t now_mono,
    boot_zcode_dht_possession_apply_fn apply, void *apply_context)
{
    if (!store || (request_count && (!requests || !apply)) ||
        request_count > VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS)
        return 0;
    uint8_t roots[VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS][32];
    for (size_t i = 0; i < request_count; i++) {
        memcpy(roots[i], requests[i].transport_root, 32);
    }
    possession_lock();
    bool ready = possession_ensure() &&
                 vcs_package_possession_scheduler_reconcile(
                     g_scheduler, store, roots, request_count, now_mono);
    if (ready)
        for (size_t i = 0; i < request_count; i++)
            if (requests[i].fresh_required ||
                !vcs_package_possession_scheduler_current(
                    g_scheduler, store, requests[i].transport_root, NULL))
                (void)vcs_package_possession_scheduler_require(
                    g_scheduler, requests[i].transport_root, now_mono);
    if (ready)
        vcs_package_possession_scheduler_run(g_scheduler, store, now_mono);
    if (ready)
        for (size_t i = 0; i < request_count; i++) {
            struct vcs_package_possession_receipt receipt;
            bool current = vcs_package_possession_scheduler_current(
                g_scheduler, store, requests[i].transport_root, &receipt);
            if (!current) {
                apply(apply_context, requests[i].transport_root,
                      requests[i].proof_epoch, false);
                continue;
            }
            struct possession_apply_one one = {
                apply, apply_context, requests[i].transport_root,
                requests[i].proof_epoch};
            vcs_package_store_possession_apply_if_current(
                store, requests[i].transport_root,
                receipt.mutation_generation, true,
                possession_apply_current, &one);
        }
    zcl_mutex_unlock(&g_possession_lock);
    return ready ? request_count : 0;
}

bool boot_zcode_dht_possession_current(
    struct vcs_package_store *store, const uint8_t root[32])
{
    if (!store || !root)
        return false;
    possession_lock();
    bool current = g_scheduler &&
        vcs_package_possession_scheduler_current(
            g_scheduler, store, root, NULL);
    zcl_mutex_unlock(&g_possession_lock);
    return current;
}

void boot_zcode_dht_possession_dump_json(struct json_value *out,
                                         uint64_t now_mono)
{
    if (!out)
        return;
    json_set_object(out);
    possession_lock();
    struct vcs_package_possession_scheduler_status status;
    vcs_package_possession_scheduler_status(g_scheduler, now_mono, &status);
    json_push_kv_int(out, "queued_roots", status.queued_roots);
    json_push_kv_int(out, "tracked_roots", status.tracked_roots);
    json_push_kv_int(out, "bytes_verified_total",
                     (int64_t)status.bytes_verified_total);
    json_push_kv_int(out, "successful_proofs",
                     (int64_t)status.successful_proofs);
    json_push_kv_int(out, "failed_proofs",
                     (int64_t)status.failed_proofs);
    json_push_kv_int(out, "last_cycle_bytes",
                     (int64_t)status.last_cycle_bytes);
    json_push_kv_int(out, "last_cycle_packages",
                     status.last_cycle_packages);
    json_push_kv_int(out, "next_due_monotonic",
                     (int64_t)status.next_due_mono);

    struct vcs_package_store *store = vcs_package_store_global();
    struct vcs_package_possession_scheduler_row
        rows[VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS];
    size_t count = g_scheduler && store
                       ? vcs_package_possession_scheduler_rows(
                             g_scheduler, store, now_mono, rows,
                             VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS)
                       : 0;
    struct json_value proofs;
    json_init(&proofs);
    json_set_array(&proofs);
    for (size_t i = 0; i < count; i++) {
        struct json_value row;
        char root_hex[65];
        json_init(&row);
        json_set_object(&row);
        zcl_hex_encode(rows[i].root, 32, root_hex);
        json_push_kv_str(&row, "root", root_hex);
        json_push_kv_bool(&row, "current", rows[i].current);
        json_push_kv_bool(&row, "queued", rows[i].queued);
        json_push_kv_int(&row, "proof_age_seconds",
                         (int64_t)rows[i].proof_age_s);
        json_push_kv_int(&row, "bytes_verified",
                         (int64_t)rows[i].bytes_verified);
        json_push_kv_int(&row, "failures", (int64_t)rows[i].failures);
        json_push_kv_str(&row, "failure",
                         vcs_package_possession_failure_string(
                             rows[i].failure));
        json_push_kv_int(&row, "next_due_monotonic",
                         (int64_t)rows[i].next_due_mono);
        json_push_back(&proofs, &row);
        json_free(&row);
    }
    json_push_kv(out, "proofs", &proofs);
    json_free(&proofs);
    zcl_mutex_unlock(&g_possession_lock);
}

void boot_zcode_dht_possession_append_json(struct json_value *out,
                                           uint64_t now_mono)
{
    if (!out)
        return;
    struct json_value possession;
    json_init(&possession);
    boot_zcode_dht_possession_dump_json(&possession, now_mono);
    json_push_kv(out, "possession_proofs", &possession);
    json_free(&possession);
}

void boot_zcode_dht_possession_reset(void)
{
    possession_lock();
    struct vcs_package_possession_scheduler *retired = g_scheduler;
    g_scheduler = NULL;
    zcl_mutex_unlock(&g_possession_lock);
    vcs_package_possession_scheduler_free(retired);
}
