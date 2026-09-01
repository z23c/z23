/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exact source reconstruction proof before signed DHT evidence. */

#include "config/boot_zcode_dht.h"

#include "base/bytes.h"
#include "config/boot_zcode_dht_access.h"
#include "vcs/package_store.h"
#include "vcs/source_package_checkout.h"

#include <string.h>

struct source_reproduction_context {
    struct vcs_zcode_dht_publish_spec spec;
    const uint8_t *plan_token;
    uint8_t *plan_token_out;
    struct vcs_zcode_dht_time now;
    struct vcs_zcode_dht_record *record_out;
    bool planning;
    bool planned;
    enum vcs_zcode_dht_record_store_result result;
};

static void source_reproduction_locked(
    struct vcs_zcode_dht_service *service, void *opaque)
{
    struct source_reproduction_context *context = opaque;
    if (context->planning) {
        context->planned =
            vcs_zcode_dht_source_reproduction_ack_plan_verified(
                service, &context->spec, context->plan_token_out,
                context->record_out);
        return;
    }
    context->result =
        vcs_zcode_dht_source_reproduction_ack_commit_verified(
            service, &context->spec, context->plan_token, context->now,
            context->record_out);
}

static void source_reproduction_current(void *opaque, bool current)
{
    if (current)
        (void)boot_zcode_dht_service_apply(
            source_reproduction_locked, opaque);
}

static bool source_reproduction_prepare(
    const struct vcs_zcode_dht_publish_spec *spec,
    struct vcs_package_store **store_out,
    struct vcs_package_possession_receipt *possession_out,
    struct vcs_zcode_dht_publish_spec *normalized)
{
    if (!spec || spec->kind !=
            VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK)
        return false;
    struct vcs_package_store *store = vcs_package_store_global();
    if (!vcs_package_store_verify_possession_receipt(
            store, spec->transport_root, false, possession_out))
        return false;
    uint8_t source_root[32], accepted_work_root[32];
    struct vcs_source_package_checkout_metrics metrics;
    if (vcs_source_package_reconstruct_verify(
            store, spec->transport_root, source_root, accepted_work_root,
            &metrics) != VCS_SOURCE_PACKAGE_CHECKOUT_OK)
        return false;
    if (zcl_bytes_any_set(spec->semantic_root, 32) &&
        memcmp(spec->semantic_root, source_root, 32) != 0)
        return false;
    *normalized = *spec;
    memcpy(normalized->semantic_root, source_root, 32);
    *store_out = store;
    return true;
}

bool boot_zcode_dht_source_reproduction_ack_plan(
    const struct vcs_zcode_dht_publish_spec *spec, uint8_t plan_token[32],
    struct vcs_zcode_dht_record *record_out)
{
    struct vcs_package_store *store = NULL;
    struct vcs_package_possession_receipt possession;
    struct source_reproduction_context context = {
        .plan_token_out = plan_token,
        .record_out = record_out,
        .planning = true,
        .result = VCS_ZCODE_DHT_RECORD_STORE_INVALID,
    };
    if (!source_reproduction_prepare(
            spec, &store, &possession, &context.spec))
        return false;
    vcs_package_store_possession_apply_if_current(
        store, spec->transport_root, possession.mutation_generation, false,
        source_reproduction_current, &context);
    return context.planned;
}

enum vcs_zcode_dht_record_store_result
boot_zcode_dht_source_reproduction_ack_commit(
    const struct vcs_zcode_dht_publish_spec *spec,
    const uint8_t plan_token[32], struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record *record_out)
{
    struct vcs_package_store *store = NULL;
    struct vcs_package_possession_receipt possession;
    struct source_reproduction_context context = {
        .plan_token = plan_token,
        .now = now,
        .record_out = record_out,
        .planning = false,
        .result = VCS_ZCODE_DHT_RECORD_STORE_INVALID,
    };
    if (!source_reproduction_prepare(
            spec, &store, &possession, &context.spec))
        return VCS_ZCODE_DHT_RECORD_STORE_INVALID;
    vcs_package_store_possession_apply_if_current(
        store, spec->transport_root, possession.mutation_generation, false,
        source_reproduction_current, &context);
    return context.result;
}
