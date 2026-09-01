/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure buyer-want rendering over caller-owned, already-verified facts. */

#ifndef ZCL_SERVICES_SHOP_WANT_VIEW_SERVICE_H
#define ZCL_SERVICES_SHOP_WANT_VIEW_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SHOP_WANT_VIEW_SERVICE_ID "app.shop.want.view.v1"
#define SHOP_WANT_VIEW_ABI_FINGERPRINT \
    "app.shop.want.view.abi.v2:fulfillment-status"
#define SHOP_WANT_VIEW_SCHEMA_FINGERPRINT \
    "zcl.shop_want_post.v1+zcl.shop_want_list.v1+zcl.shop_want_status.v1+zcl.shop_want_fulfill_status.v1"
#define SHOP_WANT_VIEW_WIRE_FINGERPRINT \
    "buyer-want-state+preview+fulfillment-readiness+next-action.v1"
#define SHOP_WANT_VIEW_KAT_FINGERPRINT \
    "0a9a13ce03b8588002b63e8553350a62cbe948bb7b79b8f1df83765943c5ea72"

#define SHOP_WANT_VIEW_CRITERIA_MAX 1024u
#define SHOP_WANT_VIEW_CRITERIA_PREVIEW 160u
#define SHOP_WANT_VIEW_NEXT_ACTION_MAX 256u

struct shop_want_view_input_v1 {
    uint8_t want_id[32];
    uint8_t buyer_pubkey[32];
    uint8_t spec_hash[32];
    uint64_t amount_zatoshi;
    uint8_t criteria[SHOP_WANT_VIEW_CRITERIA_MAX];
    uint16_t criteria_len;
    int64_t issued_unix;
    int64_t expires_unix;
    int64_t cancelled_unix;
    int64_t posted_unix;
    int64_t now_unix;
    int review_state;
    bool full;
};

struct shop_want_view_result_v1 {
    char want_id[65];
    char buyer_pubkey[65];
    char spec_hash[65];
    bool spec_hash_present;
    uint64_t amount_zatoshi;
    char criteria[SHOP_WANT_VIEW_CRITERIA_MAX + 1u];
    char criteria_preview[SHOP_WANT_VIEW_CRITERIA_PREVIEW + 1u];
    bool full;
    bool criteria_truncated;
    int64_t issued_unix;
    int64_t expires_unix;
    int64_t cancelled_unix;
    int64_t posted_unix;
    bool expired;
    char state[16];
    char review_state[16];
    char next_action[SHOP_WANT_VIEW_NEXT_ACTION_MAX];
};

struct shop_fulfill_status_view_input_v1 {
    bool signature_valid;
    bool evidence_valid;
    bool visible;
    bool withdrawn;
    bool expired;
};

struct shop_fulfill_status_view_result_v1 {
    char readiness[32];
    char next_action[SHOP_WANT_VIEW_NEXT_ACTION_MAX];
};

struct shop_want_view_service_v1 {
    bool (*render)(const struct shop_want_view_input_v1 *input,
                   struct shop_want_view_result_v1 *out);
    bool (*render_fulfillment_status)(
        const struct shop_fulfill_status_view_input_v1 *input,
        struct shop_fulfill_status_view_result_v1 *out);
};

const struct shop_want_view_service_v1 *shop_want_view_service_builtin(void);

struct zcl_hotswap_service_contract;
const struct zcl_hotswap_service_contract *
zcl_native_shop_want_view_service_contract(void);

#endif /* ZCL_SERVICES_SHOP_WANT_VIEW_SERVICE_H */
