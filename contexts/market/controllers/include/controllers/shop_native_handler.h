/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `app shop init` / `app shop status` — the storefront orchestration
 * (docs/work/SHOP_COMMAND.md, slice B).
 *
 * The handlers compose existing primitives; they own nothing themselves:
 *   - persistent onion identity   core/modules/net/src/tor_integration.c (slice A)
 *   - store schema + products     store_ensure_schema()
 *                                 (engine/controllers/src/store_controller_schema.c)
 *   - wallet at-rest posture      the WKS1/WKD1 envelopes the wallet
 *                                 persistence layer already writes
 *   - directory announcement      ONION_DIR_EXTRA_APPS_REL, read into the
 *                                 self /directory.json row by
 *                                 core/modules/net/src/onion_directory.c
 *
 * The datadir-local helper layer the handlers run on lives in
 * shop_native_probes.c, exposed here so test_shop can drive each piece
 * without the command registry — and so a future isolated storefront
 * worker (the process-isolation mode docs/work/SHOP_COMMAND.md designs
 * for) can run the same steps outside the main process. */

#ifndef ZCL_CONTROLLERS_SHOP_NATIVE_HANDLER_H
#define ZCL_CONTROLLERS_SHOP_NATIVE_HANDLER_H

#include <stdbool.h>
#include <stddef.h>

struct zcl_command_request;
struct zcl_command_reply;

/* The app id a shop announces on the node's /directory.json apps row. */
#define SHOP_DIRECTORY_APP_ID "shop"

/* Wallet at-rest custody, probed from the datadir on disk (the CLI process
 * asking has no wallet of its own; the answer must come from the files). */
enum shop_wallet_posture {
    SHOP_WALLET_ABSENT = 0,   /* no wallet rows at all */
    SHOP_WALLET_PLAINTEXT,    /* rows exist but nothing is wrapped at rest */
    SHOP_WALLET_ENCRYPTED,    /* a WKS1/WKD1 envelope or wrapped DEK exists */
    SHOP_WALLET_UNREADABLE    /* node.db missing, not a database, no tables */
};

/* Read-only probe of <datadir>/node.db's wallet tables: encrypted means a
 * WKS1/WKD1 envelope header on any key/seed blob OR a wrapped DEK row in
 * wallet_key_encryption — the same markers the persistence layer itself
 * uses to tell an encrypted wallet from a plaintext one. Never decrypts,
 * never mutates. */
enum shop_wallet_posture shop_probe_wallet_posture(const char *datadir);

/* Stable one-word name for replies and tests. */
const char *shop_wallet_posture_name(enum shop_wallet_posture posture);

/* True when this binary links the real vendored Tor (libtor.a) rather than
 * the default stub — reads the same weak-symbol link fact the tor telemetry
 * leaf reads. Pure. */
bool shop_tor_real_build_linked(void);

/* Copy an operator-supplied products.json to
 * <datadir>/store/products.json, creating <datadir>/store. The existing
 * loader (store_ensure_schema) only provisions from that one path, so this
 * is the whole --input step. Refuses (false, err filled) an unreadable,
 * empty, or oversized input. */
bool shop_provision_products_json(const char *datadir,
                                  const char *input_path,
                                  char *err, size_t err_size);

/* Add SHOP_DIRECTORY_APP_ID to <datadir>/directory/apps.csv (deduped,
 * normalized), creating <datadir>/directory. core/modules/net's register_self()
 * picks the file up on its next round, so the announcement reaches
 * /directory.json whether or not the node is currently running. */
bool shop_announce_directory_app(const char *datadir,
                                 char *err, size_t err_size);

/* Shared between the two shop TUs (handler + probes) — internal plumbing,
 * not a public surface. */
bool shop_internal_path_join(char *out, size_t out_size, const char *dir,
                             const char *rel);
/* Read the persistent identity address WITHOUT minting a seed; false when
 * absent or unreadable. */
bool shop_internal_read_identity(const char *datadir, char addr_out[64]);

/* Registry handlers, bound in engine/composition/commands/store.def. */
void zcl_native_handle_shop_init(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply);
void zcl_native_handle_shop_status(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply);
/* The slice-C evidence readout (shop_native_reputation.c). */
void zcl_native_handle_shop_reputation(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* The slice-D buyer-posted demand board (shop_native_want.c). */
void zcl_native_handle_shop_want_post(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_cancel(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_review(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* Slice E: signed, CAS-bound seller fulfillment claims. */
void zcl_native_handle_shop_want_fulfill_post(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_fulfill_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_fulfill_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_fulfill_withdraw(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_fulfill_review(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

#endif /* ZCL_CONTROLLERS_SHOP_NATIVE_HANDLER_H */
