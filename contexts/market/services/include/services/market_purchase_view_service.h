/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure presentation calculations for the paid-file marketplace. */

#ifndef ZCL_SERVICES_MARKET_PURCHASE_VIEW_SERVICE_H
#define ZCL_SERVICES_MARKET_PURCHASE_VIEW_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MARKET_PURCHASE_VIEW_SERVICE_ID "app.market.purchase.view.v1"
#define MARKET_PURCHASE_VIEW_ABI_FINGERPRINT \
    "app.market.purchase.view.abi.v1:1f17fa01"
#define MARKET_PURCHASE_VIEW_SCHEMA_FINGERPRINT \
    "zcl.app_market_purchase_guide.v1"
#define MARKET_PURCHASE_VIEW_WIRE_FINGERPRINT \
    "market-purchase-error-map+commit-hint+guide.v1"
#define MARKET_PURCHASE_VIEW_KAT_FINGERPRINT \
    "59a6e2f7944682cb4707701e59a7fa960c054c6f76b40821aeb3c02f24ea1ba5"

enum market_purchase_error_class_v1 {
    MARKET_PURCHASE_ERROR_FAILED = 0,
    MARKET_PURCHASE_ERROR_INVALID = 1,
    MARKET_PURCHASE_ERROR_DENIED = 2,
    MARKET_PURCHASE_ERROR_TRANSIENT = 3,
    MARKET_PURCHASE_ERROR_BLOCKED = 4,
};

struct market_purchase_error_result_v1 {
    bool known;
    enum market_purchase_error_class_v1 error_class;
};

struct market_purchase_guide_result_v1 {
    uint16_t classified_error_count;
    bool effects_swappable;
    bool payment_authority_static;
    char flow[48];
    char live_surface[128];
    char static_boundary[192];
    char next_command[256];
};

struct market_purchase_view_service_v1 {
    bool (*classify_error)(const char *code,
                           struct market_purchase_error_result_v1 *out);
    bool (*render_commit_input)(const char *wallet_scope,
                                const char *plan_id,
                                char *out, size_t out_size);
    bool (*render_guide)(struct market_purchase_guide_result_v1 *out);
};

const struct market_purchase_view_service_v1 *
market_purchase_view_service_builtin(void);
struct zcl_hotswap_service_contract;
const struct zcl_hotswap_service_contract *
zcl_native_market_purchase_view_service_contract(void);

#endif /* ZCL_SERVICES_MARKET_PURCHASE_VIEW_SERVICE_H */
