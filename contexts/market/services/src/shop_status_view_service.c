/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure storefront posture rendering; reads and effects remain static. */
// one-result-type-ok:pure-vtable-uses-bounded-caller-owned-output-only

#include "services/shop_status_view_service.h"

#include "hotswap/hotswap_service.h"

#include <stdio.h>
#include <string.h>

static bool add_gap(struct shop_status_view_result_v1 *out, const char *gap,
                    const char *remedy)
{
    if (out->gap_count >= SHOP_STATUS_VIEW_GAP_MAX)
        return false;
    struct shop_status_gap_v1 *row = &out->gaps[out->gap_count++];
    (void)snprintf(row->gap, sizeof(row->gap), "%s", gap);
    (void)snprintf(row->remedy, sizeof(row->remedy), "%s", remedy);
    return true;
}

static const char *wallet_name(enum shop_status_wallet_v1 wallet)
{
    switch (wallet) {
    case SHOP_STATUS_WALLET_ABSENT: return "absent";
    case SHOP_STATUS_WALLET_PLAINTEXT: return "plaintext";
    case SHOP_STATUS_WALLET_ENCRYPTED: return "encrypted";
    case SHOP_STATUS_WALLET_UNREADABLE: return "unreadable";
    }
    return NULL;
}

static bool render(const struct shop_status_view_input_v1 *input,
                   struct shop_status_view_result_v1 *out)
{
    if (!input || !out || !wallet_name(input->wallet) ||
        (input->identity_present && !input->address[0]))
        return false;
    memset(out, 0, sizeof(*out));
    out->shop_live = input->tor_real && input->identity_present &&
        input->wallet == SHOP_STATUS_WALLET_ENCRYPTED &&
        input->node_db_present && input->store_schema && input->announced;
    (void)snprintf(out->tor_build, sizeof(out->tor_build), "%s",
                   input->tor_real ? "real_tor" : "tor_stub");
    (void)snprintf(out->address, sizeof(out->address), "%s", input->address);
    (void)snprintf(out->wallet_posture, sizeof(out->wallet_posture), "%s",
                   wallet_name(input->wallet));
    out->wallet_encrypted = input->wallet == SHOP_STATUS_WALLET_ENCRYPTED;
    out->node_db_present = input->node_db_present;
    out->store_schema = input->store_schema;
    out->schema_version = input->schema_version;
    out->product_count = input->product_count;
    out->products_json_present = input->products_json_present;
    out->announced = input->announced;
    if (input->identity_present)
        (void)snprintf(out->shop_url, sizeof(out->shop_url),
                       "http://%s.onion/store", input->address);

    if (!input->tor_real &&
        !add_gap(out, "tor_stub_build", SHOP_STATUS_REMEDY_TOR))
        return false;
    if (!input->identity_present &&
        !add_gap(out, "no_persistent_onion_identity",
                 SHOP_STATUS_REMEDY_INIT " mints the persistent identity; then "
                 SHOP_STATUS_REMEDY_PERSIST))
        return false;
    if (input->wallet == SHOP_STATUS_WALLET_PLAINTEXT &&
        !add_gap(out, "wallet_plaintext_at_rest", SHOP_STATUS_WALLET_RECIPE))
        return false;
    if (input->wallet == SHOP_STATUS_WALLET_ABSENT &&
        !add_gap(out, "wallet_absent", SHOP_STATUS_WALLET_RECIPE))
        return false;
    if (input->wallet == SHOP_STATUS_WALLET_UNREADABLE &&
        !add_gap(out, "wallet_unreadable",
                 "boot the node once to create node.db, then re-run "
                 "z23 app shop status"))
        return false;
    if (!input->node_db_present) {
        if (!add_gap(out, "node_db_missing",
                     "boot the node once: node.db and the store schema are "
                     "created on first boot"))
            return false;
    } else if (!input->store_schema &&
               !add_gap(out, "store_schema_missing", SHOP_STATUS_REMEDY_INIT)) {
        return false;
    }
    if (!input->announced &&
        !add_gap(out, "shop_not_announced",
                 SHOP_STATUS_REMEDY_INIT
                 " writes <datadir>/directory/apps.csv atomically and "
                 "idempotently."))
        return false;
    return true;
}

static const struct shop_status_view_service_v1 k_builtin = {.render = render};

ZCL_HOTSWAP_SERVICE_EXPORT(
    SHOP_STATUS_VIEW_SERVICE_ID, k_builtin, SHOP_STATUS_VIEW_ABI_FINGERPRINT,
    SHOP_STATUS_VIEW_SCHEMA_FINGERPRINT, SHOP_STATUS_VIEW_WIRE_FINGERPRINT,
    SHOP_STATUS_VIEW_KAT_FINGERPRINT)

const struct shop_status_view_service_v1 *shop_status_view_service_builtin(void)
{
    return &k_builtin;
}
