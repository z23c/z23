/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure storefront posture rendering over caller-owned facts. */

#ifndef ZCL_SERVICES_SHOP_STATUS_VIEW_SERVICE_H
#define ZCL_SERVICES_SHOP_STATUS_VIEW_SERVICE_H

#include <stdbool.h>
#include <stddef.h>

#define SHOP_STATUS_VIEW_SERVICE_ID "app.shop.status.view.v1"
#define SHOP_STATUS_VIEW_ABI_FINGERPRINT \
    "app.shop.status.view.abi.v1:6bb63120"
#define SHOP_STATUS_VIEW_SCHEMA_FINGERPRINT "zcl.shop_status.v1"
#define SHOP_STATUS_VIEW_WIRE_FINGERPRINT \
    "shop-posture+verification+named-gaps.v1"
#define SHOP_STATUS_VIEW_KAT_FINGERPRINT \
    "6ca6c3464c42512173ab79649d15964fd0c296b20c93c792c1fcaa93a01280a1"

#define SHOP_STATUS_VIEW_GAP_MAX 6u
#define SHOP_STATUS_VIEW_GAP_NAME_MAX 48u
#define SHOP_STATUS_VIEW_REMEDY_MAX 640u

#define SHOP_STATUS_WALLET_RECIPE \
    "encrypt the wallet before opening a shop. Existing plaintext wallet: " \
    "run the walletencrypt RPC (zcl-rpc walletencrypt \"<passphrase>\") — " \
    "it wraps every plaintext secret under the passphrase and locks. New " \
    "wallet: boot with the systemd wallet-passphrase credential (or " \
    "ZCL_WALLET_PASSPHRASE set at first boot) so keys are wrapped before " \
    "they hit disk. -allow-plaintext-wallet is refused on the shop lane."
#define SHOP_STATUS_REMEDY_INIT \
    "z23 app shop init --input='{\"confirm\":true}'"
#define SHOP_STATUS_REMEDY_TOR \
    "rebuild against the vendored Tor (make tor-full), then boot with -tor"
#define SHOP_STATUS_REMEDY_PERSIST \
    "boot with -tor -onion-persist so the node installs the persistent " \
    "identity as its onion service (the identity itself is already ensured)"

enum shop_status_wallet_v1 {
    SHOP_STATUS_WALLET_ABSENT = 0,
    SHOP_STATUS_WALLET_PLAINTEXT,
    SHOP_STATUS_WALLET_ENCRYPTED,
    SHOP_STATUS_WALLET_UNREADABLE,
};

struct shop_status_view_input_v1 {
    bool tor_real;
    bool identity_present;
    char address[64];
    enum shop_status_wallet_v1 wallet;
    bool node_db_present;
    bool store_schema;
    int schema_version;
    int product_count;
    bool products_json_present;
    bool announced;
};

struct shop_status_gap_v1 {
    char gap[SHOP_STATUS_VIEW_GAP_NAME_MAX];
    char remedy[SHOP_STATUS_VIEW_REMEDY_MAX];
};

struct shop_status_view_result_v1 {
    bool shop_live;
    char tor_build[16];
    char address[64];
    char wallet_posture[16];
    bool wallet_encrypted;
    bool node_db_present;
    bool store_schema;
    int schema_version;
    int product_count;
    bool products_json_present;
    bool announced;
    char shop_url[128];
    size_t gap_count;
    struct shop_status_gap_v1 gaps[SHOP_STATUS_VIEW_GAP_MAX];
};

struct shop_status_view_service_v1 {
    bool (*render)(const struct shop_status_view_input_v1 *input,
                   struct shop_status_view_result_v1 *out);
};

const struct shop_status_view_service_v1 *shop_status_view_service_builtin(void);

struct zcl_hotswap_service_contract;
const struct zcl_hotswap_service_contract *
zcl_native_shop_status_view_service_contract(void);

#endif /* ZCL_SERVICES_SHOP_STATUS_VIEW_SERVICE_H */
