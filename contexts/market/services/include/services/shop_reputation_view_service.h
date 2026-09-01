/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure marketplace reputation presentation over caller-owned evidence. */

#ifndef ZCL_SERVICES_SHOP_REPUTATION_VIEW_SERVICE_H
#define ZCL_SERVICES_SHOP_REPUTATION_VIEW_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SHOP_REPUTATION_VIEW_SERVICE_ID "app.shop.reputation.view.v1"
#define SHOP_REPUTATION_VIEW_ABI_FINGERPRINT \
    "app.shop.reputation.view.abi.v1:1f33b720"
#define SHOP_REPUTATION_VIEW_SCHEMA_FINGERPRINT \
    "zcl.shop_reputation.v1"
#define SHOP_REPUTATION_VIEW_WIRE_FINGERPRINT \
    "publisher-evidence-rows+local-window.v1"
#define SHOP_REPUTATION_VIEW_KAT_FINGERPRINT \
    "21f8f1dfcc3f10c53af1299c283b15624a8e8d17c3c7d16869a31c5d318872de"

#define SHOP_REPUTATION_VIEW_ROW_COUNT 9u
#define SHOP_REPUTATION_VIEW_FACT_MAX 40u
#define SHOP_REPUTATION_VIEW_STATE_MAX 16u
#define SHOP_REPUTATION_VIEW_EVIDENCE_MAX 192u
#define SHOP_REPUTATION_VIEW_WINDOW_MAX 64u
#define SHOP_REPUTATION_VIEW_DETAIL_MAX 320u
#define SHOP_REPUTATION_VIEW_DOCTRINE_MAX 384u

struct shop_reputation_view_input_v1 {
    bool store_present;
    uint32_t releases;
    uint32_t packages;
    uint64_t max_publisher_sequence;
    bool observed;
    int64_t first_observed_unix;
    int64_t days_observed;
    uint32_t matching_receipts;
    uint32_t reproduced_packages;
    uint32_t valid_attestations;
    uint32_t distinct_verifiers;
    bool attestations_truncated;
    uint32_t dependent_packages;
    uint32_t declarations_read;
    uint32_t declarations_unavailable;
    uint32_t settled_entries;
};

struct shop_reputation_view_row_v1 {
    char fact[SHOP_REPUTATION_VIEW_FACT_MAX];
    char state[SHOP_REPUTATION_VIEW_STATE_MAX];
    bool has_value;
    int64_t value;
    char evidence_class[SHOP_REPUTATION_VIEW_EVIDENCE_MAX];
    char window[SHOP_REPUTATION_VIEW_WINDOW_MAX];
    char detail[SHOP_REPUTATION_VIEW_DETAIL_MAX];
};

struct shop_reputation_view_result_v1 {
    size_t row_count;
    struct shop_reputation_view_row_v1 rows[SHOP_REPUTATION_VIEW_ROW_COUNT];
    char doctrine[SHOP_REPUTATION_VIEW_DOCTRINE_MAX];
};

struct shop_reputation_view_service_v1 {
    bool (*render)(const struct shop_reputation_view_input_v1 *input,
                   struct shop_reputation_view_result_v1 *out);
};

const struct shop_reputation_view_service_v1 *
shop_reputation_view_service_builtin(void);

struct zcl_hotswap_service_contract;
const struct zcl_hotswap_service_contract *
zcl_native_shop_reputation_view_service_contract(void);

#endif /* ZCL_SERVICES_SHOP_REPUTATION_VIEW_SERVICE_H */
