/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure presentation ABI for signed module Passport workflows. */

#ifndef ZCL_SERVICES_ZCODE_PASSPORT_VIEW_SERVICE_H
#define ZCL_SERVICES_ZCODE_PASSPORT_VIEW_SERVICE_H

#include <stdbool.h>

#define ZCODE_PASSPORT_VIEW_SERVICE_ID "zcode.passport.view.v1"
#define ZCODE_PASSPORT_VIEW_ABI_FINGERPRINT \
    "zcode.passport.view.abi.v1:0b2ee4ac"
#define ZCODE_PASSPORT_VIEW_SCHEMA_FINGERPRINT \
    "zcl.zcode_passport_status.v1+plan.v1+commit.v1+verify.v1"
#define ZCODE_PASSPORT_VIEW_WIRE_FINGERPRINT \
    "module-passport-presentation.v1"
#define ZCODE_PASSPORT_VIEW_KAT_FINGERPRINT \
    "8e03105430bec13a6766e00ab21bc1ac6f5f234ee4d17f08f8be6943d8e4140f"

enum zcode_passport_view_mode_v1 {
    ZCODE_PASSPORT_VIEW_STATUS = 1,
    ZCODE_PASSPORT_VIEW_PLAN = 2,
    ZCODE_PASSPORT_VIEW_COMMIT = 3,
    ZCODE_PASSPORT_VIEW_VERIFY = 4,
};

struct zcode_passport_view_result_v1 {
    bool valid;
    char kind[32];
    char capability[160];
    char next_action[192];
};

struct zcode_passport_view_service_v1 {
    bool (*render)(enum zcode_passport_view_mode_v1 mode,
                   struct zcode_passport_view_result_v1 *out);
};

const struct zcode_passport_view_service_v1 *
zcode_passport_view_service_builtin(void);

struct zcl_hotswap_service_contract;
const struct zcl_hotswap_service_contract *
zcl_native_zcode_passport_view_service_contract(void);

#endif /* ZCL_SERVICES_ZCODE_PASSPORT_VIEW_SERVICE_H */
