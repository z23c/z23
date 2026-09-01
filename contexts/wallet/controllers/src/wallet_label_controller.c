/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Wallet address label / address-book controller.
 *
 * Two surfaces over one model (contexts/wallet/models/src/wallet_label.c, the
 * wallet_labels table):
 *   - Legacy JSON-RPC: setlabel / getaddressesbylabel / listlabels,
 *     registered into the "wallet" RPC category in wallet_controller.c.
 *   - Native commands: core.wallet.address.label (set, mutate) and
 *     core.wallet.address.by-label (read), bound directly in
 *     engine/composition/commands/core.def.
 *
 * Labels may be set on any syntactically valid address, owned or
 * watch-only, matching bitcoind's label model; they are not part of the
 * wallet keystore and carry no fund or key risk. */

#include "controllers/wallet_controller_internal.h"
#include "models/wallet_label.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

/* Row cap for one label listing. Bounds both the SQL scan and the reply
 * page; the caller is told when the cap truncated the answer. Rows are
 * heap-allocated — the struct is ~520 bytes, too large for the stack at
 * this cardinality. */
#define WALLET_LABEL_LIST_MAX 256

/* Push a single JSON string onto array-typed `result`. */
static void wallet_label_push_str(struct json_value *result, const char *s)
{
    struct json_value item;
    json_init(&item);
    json_set_str(&item, s);
    json_push_back(result, &item);
    json_free(&item);
}

/* Allocate one bounded label-row page. Returns NULL (already logged) on
 * allocation failure. */
static struct db_wallet_label *wallet_label_alloc_page(void)
{
    return zcl_malloc(sizeof(struct db_wallet_label) * WALLET_LABEL_LIST_MAX,
                      "wallet label page");
}

/* ── Legacy JSON-RPC: setlabel / getaddressesbylabel / listlabels ──── */

bool rpc_setlabel(const struct json_value *params, bool help,
                  struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "setlabel \"address\" \"label\"\n"
        "\nAssociates \"label\" with the given address. An empty label "
        "clears any existing label.\n"
        "\nArguments:\n"
        "1. \"address\"  (string, required) The address to label\n"
        "2. \"label\"    (string, required) The label ( \"\" clears it )\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 2, 2);
    const char *addr_str = rpc_require_str(&p, 0, "address");
    const char *label = rpc_require_str(&p, 1, "label");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        LOG_FAIL("wallet", "setlabel: invalid params");
    }

    ENSURE_WALLET(result);

    struct tx_destination dest;
    if (!wallet_decode_address(addr_str, &dest)) {
        json_set_str(result, "Invalid address");
        LOG_FAIL("wallet", "setlabel: invalid address %s", addr_str);
    }

    if (!wallet_ctx_db_ready(ctx)) {
        json_set_str(result,
            "Error: wallet database unavailable; label not saved");
        LOG_FAIL("wallet", "setlabel: node_db unavailable for %s", addr_str);
    }

    if (strlen(label) > WALLET_LABEL_MAX) {
        json_set_str(result, "Label too long");
        LOG_FAIL("wallet", "setlabel: label too long for %s", addr_str);
    }

    struct db_wallet_label l;
    memset(&l, 0, sizeof(l));
    snprintf(l.address, sizeof(l.address), "%s", addr_str);
    snprintf(l.label, sizeof(l.label), "%s", label);
    if (!db_wallet_label_save(ctx->node_db, &l)) {
        json_set_str(result, "Error: label did not validate or persist");
        LOG_FAIL("wallet", "setlabel: save failed for %s", addr_str);
    }

    json_set_null(result);
    return true;
}

bool rpc_getaddressesbylabel(const struct json_value *params, bool help,
                             struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "getaddressesbylabel \"label\"\n"
        "\nReturns every address currently carrying the given label.\n"
        "\nArguments:\n"
        "1. \"label\"  (string, required) The label to look up\n"
        "\nResult:\n"
        "[ \"address\", ... ]  (array, empty when the label is unused)\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 1);
    const char *label = rpc_require_str(&p, 0, "label");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        LOG_FAIL("wallet", "getaddressesbylabel: invalid params");
    }

    ENSURE_WALLET(result);

    json_set_array(result);
    if (!wallet_ctx_db_ready(ctx))
        return true; /* No durable label store yet: empty, not an error. */

    struct db_wallet_label *rows = wallet_label_alloc_page();
    if (!rows) {
        json_set_str(result, "Error: out of memory listing labels");
        LOG_FAIL("wallet", "getaddressesbylabel: page alloc failed");
    }
    int n = db_wallet_label_list_by_label(ctx->node_db, label, rows,
                                          WALLET_LABEL_LIST_MAX);
    json_set_array(result);
    for (int i = 0; i < n; i++)
        wallet_label_push_str(result, rows[i].address);
    free(rows);
    return true;
}

bool rpc_listlabels(const struct json_value *params, bool help,
                    struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result, "listlabels\n"
        "\nReturns every distinct label currently in use, sorted "
        "lexically.\n"
        "\nResult:\n"
        "[ \"label\", ... ]\n");

    ENSURE_WALLET(result);

    json_set_array(result);
    if (!wallet_ctx_db_ready(ctx))
        return true; /* No durable label store yet: empty, not an error. */

    struct db_wallet_label *rows = wallet_label_alloc_page();
    if (!rows) {
        json_set_str(result, "Error: out of memory listing labels");
        LOG_FAIL("wallet", "listlabels: page alloc failed");
    }
    int n = db_wallet_label_list_distinct(ctx->node_db, rows,
                                          WALLET_LABEL_LIST_MAX);
    json_set_array(result);
    for (int i = 0; i < n; i++)
        wallet_label_push_str(result, rows[i].label);
    free(rows);
    return true;
}

/* ── Native commands: core.wallet.address.label(.by-label) ─────────
 * Direct handlers over app_runtime_node_db(), the same shape
 * account_controller.c uses for its READY leaves. */

static void wl_fail(struct zcl_command_reply *reply,
                    enum zcl_command_exit exit_code, const char *code,
                    const char *message, const char *evidence)
{
    enum zcl_command_status status =
        exit_code == ZCL_COMMAND_EXIT_BLOCKED ? ZCL_COMMAND_STATUS_BLOCKED
                                              : ZCL_COMMAND_STATUS_FAILED;
    LOG_ERROR("wallet.label", "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, status, exit_code, code, "handle",
                           false, false, message, evidence ? evidence : "");
}

static struct node_db *wl_db(struct zcl_command_reply *reply)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !ndb->open) {
        wl_fail(reply, ZCL_COMMAND_EXIT_BLOCKED, "NODE_DB_UNAVAILABLE",
                "node database is not open", "wallet_labels");
        return NULL;
    }
    return ndb;
}

static void wl_render(struct json_value *into, const struct db_wallet_label *l)
{
    (void)json_push_kv_str(into, "address", l->address);
    (void)json_push_kv_str(into, "label", l->label);
    (void)json_push_kv_int(into, "updated_at", l->updated_at);
}

/* core.wallet.address.label: set (or clear, with label="") the label on
 * one address. */
void zcl_native_handle_wallet_address_label(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;
    const char *address = json_get_str(json_get(in, "address"));
    const char *label = json_get_str(json_get(in, "label"));
    if (!address || !address[0]) {
        wl_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_ADDRESS",
                "address is required", "address");
        return;
    }
    if (!label)
        label = "";

    struct tx_destination dest;
    if (!wallet_decode_address(address, &dest)) {
        wl_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_ADDRESS",
                "address does not decode as a valid address", address);
        return;
    }
    if (strlen(label) > WALLET_LABEL_MAX) {
        wl_fail(reply, ZCL_COMMAND_EXIT_INVALID, "LABEL_TOO_LONG",
                "label exceeds max length 255", address);
        return;
    }

    struct node_db *ndb = wl_db(reply);
    if (!ndb)
        return;

    struct db_wallet_label l;
    memset(&l, 0, sizeof(l));
    snprintf(l.address, sizeof(l.address), "%s", address);
    snprintf(l.label, sizeof(l.label), "%s", label);
    if (!db_wallet_label_save(ndb, &l)) {
        wl_fail(reply, ZCL_COMMAND_EXIT_FAILED, "SAVE_FAILED",
                "label did not validate or persist", address);
        return;
    }
    if (!db_wallet_label_find(ndb, address, &l))
        LOG_WARN("wallet.label", "label row missing right after save: %s",
                 address);
    wl_render(&reply->data, &l);
    reply->error.mutated = true;
}

/* core.wallet.address.by-label: every address currently carrying `label`. */
void zcl_native_handle_wallet_address_by_label(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *label = json_get_str(json_get(request->input, "label"));
    if (!label) {
        wl_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_LABEL",
                "label is required", "label");
        return;
    }
    struct node_db *ndb = wl_db(reply);
    if (!ndb)
        return;

    struct db_wallet_label *rows = wallet_label_alloc_page();
    if (!rows) {
        wl_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "OUT_OF_MEMORY",
                "could not allocate the label listing page", label);
        return;
    }
    int n = db_wallet_label_list_by_label(ndb, label, rows,
                                          WALLET_LABEL_LIST_MAX);
    (void)json_push_kv_str(&reply->data, "label", label);
    (void)json_push_kv_int(&reply->data, "count", n);
    (void)json_push_kv_bool(&reply->data, "truncated",
                            n >= WALLET_LABEL_LIST_MAX);
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < n; i++)
        wallet_label_push_str(&arr, rows[i].address);
    (void)json_push_kv(&reply->data, "addresses", &arr);
    json_free(&arr);
    free(rows);
}
