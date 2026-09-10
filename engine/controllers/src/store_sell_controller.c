/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the storesell_* node RPC surface — the in-node half of "a merchant
 * lists a product", so listing works while the node owns node.db.
 *
 * The merchant CLI leaf `app.store.list-product` used to open
 * <datadir>/node.db itself. A booted node holds a single-owner lease on that
 * file, so on a running store the leaf could only ever be refused. This file
 * is the mirror of contexts/market/controllers/src/store_buyer_controller.c
 * on the selling side: it parses params, calls the ONE listing body
 * (store_sell_list_product_apply, engine/controllers/src/store_native_
 * handlers.c), and renders the answer.
 *
 * Registered from engine/composition/src/boot_frontend_services.c, on the
 * same store-profile gate as the buyer methods, so a node without the store
 * profile exposes no selling surface at all. */

#include "controllers/store_sell_controller.h"
#include "json/json.h"
#include "rpc/server.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#define SSC_TAG "store_sell_rpc"

/* Bounded copy of the node's own data directory, wired once at registration.
 * A caller does not get to name the datadir it writes to: this is the only
 * store this method will ever touch. */
static char g_datadir[1024];

void rpc_store_sell_set_state(const char *datadir)
{
    (void)snprintf(g_datadir, sizeof(g_datadir), "%s", datadir ? datadir : "");
}

/* Render a refusal as a SUCCESSFUL call reporting a refusal: {ok:false, code,
 * message, evidence, exit}. Folding a refusal into an RPC error would destroy
 * the distinction the caller needs — "the store said no, here is exactly
 * why" versus "the node did not answer". `exit` carries the typed exit code
 * so the CLI reproduces the identical refusal it would have produced with no
 * node running. Always returns true. */
static bool ssc_refuse(struct json_value *result, const char *code,
                       const char *message, const char *evidence,
                       enum zcl_command_exit exit_code)
{
    LOG_ERROR(SSC_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", false);
    (void)json_push_kv_str(result, "code", code);
    (void)json_push_kv_str(result, "message", message);
    (void)json_push_kv_str(result, "evidence", evidence ? evidence : "");
    (void)json_push_kv_int(result, "exit", (int64_t)exit_code);
    return true;
}

/* Copy the outcome's product fields onto the RPC body. */
static void ssc_push_body(struct json_value *result,
                          const struct store_sell_outcome *out)
{
    for (size_t i = 0; i < out->data.num_children; i++) {
        const char *k = out->data.keys ? out->data.keys[i] : NULL;
        if (k && k[0])
            (void)json_push_kv(result, k, &out->data.children[i]);
    }
}

/* The datadir this call is allowed to write. The caller may name one, but
 * only the node's own: a merchant CLI pointed at a DIFFERENT datadir must
 * not be silently served this node's store, and this node must never be
 * talked into writing somewhere else. NULL means refuse. */
static const char *ssc_datadir(const struct json_value *params)
{
    if (!g_datadir[0])
        return NULL;   // raw-return-ok:caller-reports-NO_DATADIR_WIRED
    const char *asked = json_size(params) >= 2
                            ? json_get_str(json_at(params, 1)) : NULL;
    if (asked && asked[0] && strcmp(asked, g_datadir) != 0)
        return NULL;   // raw-return-ok:caller-reports-DATADIR_MISMATCH
    return g_datadir;
}

static bool rpc_storesell_list_product(const struct json_value *params,
                                       bool help, struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "storesell_list_product {product} [\"datadir\"]\n"
            "\nList a product for sale in this node's store. {product} is the "
            "app.store.list-product input object (name, token_id, price_zcl "
            "or price_zatoshi, tokens_per_purchase, content_path, "
            "content_type, content_filename, description). datadir, when "
            "given, must be this node's own.\n"
            "\nResult: {ok, mutated, id, name, token_id, price_zatoshi, "
            "price_zcl, tokens_per_purchase, active, has_content, "
            "content_hash, content_bytes, datadir}\n"
            "\nA refusal answers ok:false with a machine-readable code, a "
            "message, evidence and the typed exit code.\n");
        return true;
    }

    const struct json_value *in = json_at(params, 0);
    if (!in || in->type != JSON_OBJ)
        return ssc_refuse(result, "INVALID_ARGS",
                          "the first parameter must be the product object",
                          "storesell_list_product",
                          ZCL_COMMAND_EXIT_INVALID);

    const char *datadir = ssc_datadir(params);
    if (!datadir)
        return ssc_refuse(result, "DATADIR_MISMATCH",
                          "this node serves exactly one store; it will not "
                          "list a product into another datadir",
                          g_datadir[0] ? g_datadir : "(no datadir wired)",
                          ZCL_COMMAND_EXIT_DENIED);

    struct store_sell_outcome out;
    store_sell_outcome_init(&out);
    store_sell_list_product_apply(in, datadir, &out);

    bool answered;
    if (!out.ok) {
        answered = ssc_refuse(result, out.code, out.message, out.evidence,
                              out.exit_code);
    } else {
        json_set_object(result);
        (void)json_push_kv_bool(result, "ok", true);
        (void)json_push_kv_str(result, "code", "OK");
        (void)json_push_kv_bool(result, "mutated", out.mutated);
        ssc_push_body(result, &out);
        answered = true;
    }
    store_sell_outcome_free(&out);
    return answered;
}

/* ── Registration ───────────────────────────────────────────────────── */

void register_store_sell_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "store", "storesell_list_product", rpc_storesell_list_product,
          false },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
