/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Generation-bound full proofs for explicit STORAGE_ACK authoring. */

#include "config/boot_zcode_dht.h"

#include "config/boot_zcode_dht_access.h"
#include "vcs/package_store.h"

struct ack_plan_context {
    const struct vcs_zcode_dht_publish_spec *spec;
    uint8_t *plan_token;
    struct vcs_zcode_dht_record *record_out;
    bool ok;
};

static void ack_plan_locked(struct vcs_zcode_dht_service *service,
                            void *opaque)
{
    struct ack_plan_context *context = opaque;
    context->ok = vcs_zcode_dht_storage_ack_plan_verified(
        service, context->spec, context->plan_token, context->record_out);
}

static void ack_plan_current(void *opaque, bool current)
{
    if (current)
        (void)boot_zcode_dht_service_apply(ack_plan_locked, opaque);
}

bool boot_zcode_dht_storage_ack_plan(
    const struct vcs_zcode_dht_publish_spec *spec, uint8_t plan_token[32],
    struct vcs_zcode_dht_record *record_out)
{
    struct vcs_package_store *store = vcs_package_store_global();
    struct vcs_package_possession_receipt receipt;
    if (!spec || !vcs_package_store_verify_possession_receipt(
                     store, spec->transport_root, true, &receipt))
        return false;
    struct ack_plan_context context = {spec, plan_token, record_out, false};
    vcs_package_store_possession_apply_if_current(
        store, spec->transport_root, receipt.mutation_generation, true,
        ack_plan_current, &context);
    return context.ok;
}

struct ack_commit_context {
    const struct vcs_zcode_dht_publish_spec *spec;
    const uint8_t *plan_token;
    struct vcs_zcode_dht_time now;
    struct vcs_zcode_dht_record *record_out;
    enum vcs_zcode_dht_record_store_result result;
};

static void ack_commit_locked(struct vcs_zcode_dht_service *service,
                              void *opaque)
{
    struct ack_commit_context *context = opaque;
    context->result = vcs_zcode_dht_storage_ack_commit_verified(
        service, context->spec, context->plan_token, context->now,
        context->record_out);
}

static void ack_commit_current(void *opaque, bool current)
{
    if (current)
        (void)boot_zcode_dht_service_apply(ack_commit_locked, opaque);
}

enum vcs_zcode_dht_record_store_result boot_zcode_dht_storage_ack_commit(
    const struct vcs_zcode_dht_publish_spec *spec,
    const uint8_t plan_token[32], struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record *record_out)
{
    struct vcs_package_store *store = vcs_package_store_global();
    struct vcs_package_possession_receipt receipt;
    if (!spec || !vcs_package_store_verify_possession_receipt(
                     store, spec->transport_root, true, &receipt))
        return VCS_ZCODE_DHT_RECORD_STORE_INVALID;
    struct ack_commit_context context = {
        spec, plan_token, now, record_out, VCS_ZCODE_DHT_RECORD_STORE_INVALID};
    vcs_package_store_possession_apply_if_current(
        store, spec->transport_root, receipt.mutation_generation, true,
        ack_commit_current, &context);
    return context.result;
}
