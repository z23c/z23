/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the registry-owned `vault` tree — the one surface that
 * states what this node OWNS across the six asset classes, and routes every
 * custody action to the path that already owns it.
 *
 * THE INVARIANT OF THIS FILE: there is no spend logic here. No transaction is
 * built, no input is selected, no script is written, no signature is made, no
 * bytes are broadcast. Grep it: no signing, key, or broadcast primitive is
 * referenced. Every custody verb ends in exactly one of two calls —
 * vault_dispatch(), which resolves the owning leaf in the live catalog and
 * calls the very handler function pointer that leaf binds, or
 * vault_rpc_settle(), which calls the RPC method the swap controller
 * registers. A second builder living here would drift from the real one and
 * eventually sign something other than what the operator was shown, so there
 * is none, and `vault routes` prints the binding table that says so.
 *
 * What the vault DOES contribute is the three things a bare command cannot:
 * selection (which class, which holdings), preview (an advisory pre-flight
 * against the read model, always labelled advisory and never a precondition
 * of the dispatch), and confirmation (the plan/commit gate, reproduced from
 * the owning leaf or, for the RPC-owned swap settlements, supplied by the
 * vault because the RPC has none).
 *
 * Output is budget-aware and self-shrinking: when a document would exceed its
 * leaf budget, the human `lines` block is dropped first and then the item cap
 * is halved, and `dropped_sections` names what was cut. Absent data is always
 * an explicit unavailable row with a reason — never an omitted row, because an
 * omitted asset class reads as a zero balance.
 */

#define _GNU_SOURCE
#include "command/native_command.h"

#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "json/json.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "services/agent_spend_policy.h"
#include "services/legacy_balance_observer.h"
#include "base/log_macros.h"

/* ── THE READ SEAM ─────────────────────────────────────────────────────────
 * The vault does not aggregate. Everything the read leaves report is
 * projected from ONE call into the read model owned by engine/services/vault_read
 * (a peer lane), through the single function vault_read_seam() below. That
 * function is the whole integration surface: if the read model lands with a
 * different signature, this one function body is the only edit.
 *
 * The read model is a required node service.  Its wire class names deliberately
 * describe the underlying primitive (for example `transparent_zcl`), while
 * this command keeps the shorter user vocabulary (`transparent`).
 * k_vault_routes below is the explicit translation between those contracts.
 * The CLI fetches the projection from the target node's `dumpstate vault`
 * RPC; it never tries to open or aggregate a second wallet database locally. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VAULT_TAG "native.vault"

enum {
    VAULT_ITEM_CAP_DEFAULT = 20,
    VAULT_ITEM_CAP_MAX     = 100,
    /* Envelope + scalar fields pushed after the arrays are measured. */
    VAULT_ENVELOPE_RESERVE = 1200,
};

/* ── the six asset classes, and who owns the spend for each ────────────────
 * `route_owner` is the path or RPC method that builds/signs/broadcasts;
 * `route_builder` is the file it lives in — the evidence label for every
 * routing claim this file makes. `vault_verb` is empty for a class the vault
 * deliberately exposes no verb for: minting one would mean writing the builder
 * the route is missing, which is the one thing this file may not do. */
struct vault_route {
    const char *name;
    const char *read_class;
    const char *kind;          /* fungible_zat | contract | record */
    const char *route_kind;    /* native_command | node_rpc | none */
    const char *route_owner;
    const char *route_builder;
    const char *vault_verb;
    const char *route_note;
};

static const struct vault_route k_vault_routes[] = {
    { "transparent", "transparent_zcl", "fungible_zat", "native_command",
      "core.wallet.transaction.send",
      "contexts/wallet/controllers/src/wallet_native_handlers.c -> sendtoaddress",
      "vault.send",
      "the wallet's own send builds, signs and broadcasts" },
    { "shielded", "shielded_zcl", "fungible_zat", "native_command",
      "core.wallet.shielded.send",
      "contexts/wallet/controllers/src/wallet_native_handlers.c -> z_sendmany",
      "vault.send-shielded",
      "requires Sapling parameters loaded and a passing prover self-test" },
    { "tokens", "zslp_tokens", "record", "native_command", "app.tokens.send",
      "contexts/market/services/src/zslp_command_service.c",
      "vault.send-token",
      "the ZSLP owner explicitly spends token outputs and returns token "
      "change; ordinary wallet selection reserves every token/baton output" },
    { "names", "znam_names", "record", "node_rpc",
      "name_register,name_update,name_transfer,name_renew",
      "engine/controllers/src/name_controller.c", "",
      "the ZNAM writes are reachable as their own typed leaves "
      "(app names register/update/transfer/renew/set-record/set-text, each "
      "plan/commit gated); the vault mints no second verb over them because "
      "a name is a record, not a vault balance" },
    { "market", "file_market_offers", "record", "node_rpc", "zmarket_offer,zmarket_buy",
      "contexts/market/controllers/src/file_market_controller.c", "",
      "app.market.* write leaves are PLANNED: nothing announces a locally "
      "created offer to peers, and no code path builds the purchase payment "
      "transaction, so on-chain settlement is not wired end to end" },
    { "swaps", "swap_encumbered", "contract", "node_rpc", "swap_redeem,swap_refund",
      "engine/controllers/src/swap_controller.c",
      "vault.swap.redeem,vault.swap.refund",
      "the swap controller builds, signs, broadcasts and persists state" },
};

enum { VAULT_ROUTE_COUNT =
           (int)(sizeof(k_vault_routes) / sizeof(k_vault_routes[0])) };

/* All six class names as one comma list, for error evidence. */
static const char k_vault_class_list[] =
    "transparent,shielded,tokens,names,market,swaps";

static const struct vault_route *vault_class_find(const char *name)
{
    if (!name || !name[0])
        return NULL;
    for (int i = 0; i < VAULT_ROUTE_COUNT; i++)
        if (strcmp(k_vault_routes[i].name, name) == 0)
            return &k_vault_routes[i];
    return NULL;
}

/* ── small shared helpers ─────────────────────────────────────────────────── */

/* Fail the reply with a logged, evidence-carrying error body. Every failure
 * path in this file goes through here, so no leaf can return without saying
 * why. */
static void vault_fail(struct zcl_command_reply *reply,
                       enum zcl_command_status status,
                       enum zcl_command_exit exit_code, const char *code,
                       const char *phase, bool retryable, const char *message,
                       const char *evidence)
{
    LOG_ERROR(VAULT_TAG, "%s: %s (%s)", code ? code : "ERROR",
              message ? message : "", evidence ? evidence : "");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, retryable,
                           false, message, evidence);
}

static const char *vault_str(const struct zcl_command_request *request,
                             const char *key)
{
    const char *v = json_get_str(json_get(request->input, key));
    return (v && v[0]) ? v : NULL;
}

static int vault_item_cap(const struct zcl_command_request *request)
{
    const struct json_value *v = json_get(request->input, "limit");
    if (!v)
        return VAULT_ITEM_CAP_DEFAULT;
    long n = (long)json_get_int(v);
    if (n < 1)
        n = 1;
    if (n > VAULT_ITEM_CAP_MAX)
        n = VAULT_ITEM_CAP_MAX;
    return (int)n;
}

static void vault_push_line(struct json_value *arr, const char *s)
{
    struct json_value item;
    json_init(&item);
    json_set_str(&item, s);
    (void)json_push_back(arr, &item);
    json_free(&item);
}

static void vault_push_obj(struct json_value *arr, struct json_value *obj)
{
    (void)json_push_back(arr, obj);
    json_free(obj);
}

/* Rendered size of the given parts. A json_write overflow counts as the whole
 * scratch buffer, so an unmeasurable part always loses its budget contest
 * rather than silently passing. */
static size_t vault_used(const struct json_value *const *parts, size_t n)
{
    static char scratch[ZCL_COMMAND_LIST_BUDGET + 1];
    size_t used = 0;
    for (size_t i = 0; i < n; i++) {
        size_t w = json_write(parts[i], scratch, sizeof(scratch));
        used += (w == 0 || w >= sizeof(scratch)) ? sizeof(scratch) : w;
    }
    return used;
}

/* Copy an int field, or push an explicit "<key>_known": false. Never invents a
 * zero: a balance the read model did not report must not render as 0. */
static void vault_copy_int(struct json_value *dst, const struct json_value *src,
                           const char *key)
{
    const struct json_value *v = src ? json_get(src, key) : NULL;
    if (v && v->type == JSON_INT) {
        (void)json_push_kv_int(dst, key, json_get_int(v));
        return;
    }
    char flag[64];
    (void)snprintf(flag, sizeof(flag), "%s_known", key);
    (void)json_push_kv_bool(dst, flag, false);
}

static void vault_copy_int_as(struct json_value *dst,
                              const struct json_value *src,
                              const char *source_key, const char *output_key)
{
    const struct json_value *v = src ? json_get(src, source_key) : NULL;
    if (v && v->type == JSON_INT) {
        (void)json_push_kv_int(dst, output_key, json_get_int(v));
        return;
    }
    char flag[64];
    (void)snprintf(flag, sizeof(flag), "%s_known", output_key);
    (void)json_push_kv_bool(dst, flag, false);
}

static void vault_push_total_as(struct json_value *dst,
                                const struct json_value *row,
                                const char *output_key)
{
    static const char *const columns[] = {
        "spendable", "pending", "immature", "encumbered"
    };
    int64_t total = 0;
    for (size_t i = 0; i < sizeof(columns) / sizeof(columns[0]); i++) {
        const struct json_value *v = row ? json_get(row, columns[i]) : NULL;
        if (!v || v->type != JSON_INT) {
            char flag[64];
            (void)snprintf(flag, sizeof(flag), "%s_known", output_key);
            (void)json_push_kv_bool(dst, flag, false);
            return;
        }
        total += json_get_int(v);
    }
    (void)json_push_kv_int(dst, output_key, total);
}

static void vault_copy_str(struct json_value *dst, const struct json_value *src,
                           const char *key, const char *dflt)
{
    const char *v = src ? json_get_str(json_get(src, key)) : NULL;
    (void)json_push_kv_str(dst, key, (v && v[0]) ? v : dflt);
}

static void vault_copy_str_as(struct json_value *dst,
                              const struct json_value *src,
                              const char *source_key, const char *output_key,
                              const char *dflt)
{
    const char *v = src ? json_get_str(json_get(src, source_key)) : NULL;
    (void)json_push_kv_str(dst, output_key, (v && v[0]) ? v : dflt);
}

/* A co-located zclassicd is a separate custody authority. Report its exact
 * live observation beside the canonical vault, never folded into any class
 * row or total. Unavailable is a named state, not a zero balance. */
static void vault_push_legacy_wallet(struct zcl_command_reply *reply)
{
    struct legacy_balance_observation observed;
    struct zcl_result result = legacy_balance_observe(&observed);
    struct json_value legacy;

    json_init(&legacy);
    json_set_object(&legacy);
    (void)json_push_kv_str(&legacy, "custody_scope",
                           "local_zclassicd_wallet");
    (void)json_push_kv_str(&legacy, "source",
                           "zclassicd.z_gettotalbalance");
    (void)json_push_kv_str(&legacy, "aggregation", "excluded");
    if (result.ok && observed.complete) {
        (void)json_push_kv_str(&legacy, "status", "current");
        (void)json_push_kv_bool(&legacy, "complete", true);
        (void)json_push_kv_int(&legacy, "transparent_zat",
                               observed.transparent_zat);
        (void)json_push_kv_int(&legacy, "shielded_zat",
                               observed.shielded_zat);
        (void)json_push_kv_int(&legacy, "total_zat", observed.total_zat);
        (void)json_push_kv_int(&legacy, "observed_at_unix",
                               observed.observed_at_unix);
    } else {
        (void)json_push_kv_str(&legacy, "status", "unavailable");
        (void)json_push_kv_bool(&legacy, "complete", false);
        (void)json_push_kv_str(&legacy, "reason",
                               observed.reason[0]
                                   ? observed.reason
                                   : "legacy wallet was not observed");
    }
    (void)json_push_kv(&reply->data, "legacy_wallet", &legacy);
    json_free(&legacy);
}

/* ── THE READ SEAM (see the header block) ───────────────────────────────────
 * The ONLY place this file reads holdings. Integration with the read model is
 * this function body and nothing else. */
static bool vault_read_seam(const char *class_filter, struct json_value *out,
                            char *why, size_t why_cap)
{
    if (!out || !why || why_cap == 0) {
        LOG_FAIL(VAULT_TAG, "read seam called without an output buffer");
        return false;
    }
    (void)class_filter;

    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("dumpstate", "[\"vault\"]");
    if (!raw) {
        (void)snprintf(why, why_cap,
                       "the target node did not return its vault projection");
        return false;
    }

    struct json_value envelope;
    json_init(&envelope);
    bool parsed = json_read(&envelope, raw, strlen(raw));
    free(raw);
    if (!parsed || envelope.type != JSON_OBJ) {
        json_free(&envelope);
        (void)snprintf(why, why_cap,
                       "the target node returned an invalid vault projection");
        return false;
    }

    const struct json_value *code = json_get(&envelope, "code");
    const struct json_value *message = json_get(&envelope, "message");
    const struct json_value *state = json_get(&envelope, "state");
    const struct json_value *available = state
        ? json_get(state, "available") : NULL;
    if ((code && code->type == JSON_INT && message) || !state ||
        state->type != JSON_OBJ ||
        (available && available->type == JSON_BOOL &&
         !json_get_bool(available))) {
        json_free(&envelope);
        (void)snprintf(why, why_cap,
                       "the target node's vault projection is unavailable");
        return false;
    }

    json_copy(out, state);
    json_free(&envelope);
    return true;
}

/* Locate one class's object inside a snapshot document. NULL when the
 * snapshot carries no row for it — the caller renders that as unavailable, not
 * as empty. */
static const struct json_value *vault_snapshot_class(
    const struct json_value *snap, const char *name)
{
    const struct json_value *classes = snap ? json_get(snap, "classes") : NULL;
    if (!classes || classes->type != JSON_ARR)
        return NULL;
    for (size_t i = 0; i < json_size(classes); i++) {
        const struct json_value *row = json_at(classes, i);
        const char *cn = json_get_str(json_get(row, "class"));
        if (cn && strcmp(cn, name) == 0)
            return row;
    }
    return NULL;
}

/* Stamp the freshness + provenance of a read reply. Always emitted, so a
 * consumer never has to guess whether a number is live. */
static void vault_push_provenance(struct zcl_command_reply *reply,
                                  const struct json_value *snap, bool linked,
                                  const char *why)
{
    (void)json_push_kv_str(&reply->data, "read_model",
                           linked ? "linked" : "absent");
    (void)json_push_kv_str(&reply->data, "read_model_seam",
                           "vault_read_snapshot (services/vault_read.h)");
    if (snap) {
        vault_copy_int(&reply->data, snap, "as_of_height");
        vault_copy_int(&reply->data, snap, "as_of_unix");
        vault_copy_str(&reply->data, snap, "source", "vault_read_snapshot");
    } else {
        (void)json_push_kv_bool(&reply->data, "as_of_height_known", false);
        (void)json_push_kv_bool(&reply->data, "as_of_unix_known", false);
        (void)json_push_kv_str(&reply->data, "source", "unavailable");
        (void)json_push_kv_str(&reply->data, "unavailable_reason",
                               why && why[0] ? why : "read model unavailable");
    }
}

/* ── vault.list ───────────────────────────────────────────────────────────── */

void zcl_native_handle_vault_list(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    const char *filter = vault_str(request, "class");
    if (filter && !vault_class_find(filter)) {
        vault_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "UNKNOWN_CLASS", "normalize", false,
                   "class is not one of the vault's asset classes",
                   k_vault_class_list);
        return;
    }

    char why[192] = { 0 };
    struct json_value snap;
    json_init(&snap);
    bool linked = vault_read_seam(filter, &snap, why, sizeof(why));

    struct json_value rows, lines;
    json_init(&rows);
    json_set_array(&rows);
    json_init(&lines);
    json_set_array(&lines);

    int available = 0, unavailable = 0;
    for (int i = 0; i < VAULT_ROUTE_COUNT; i++) {
        const struct vault_route *c = &k_vault_routes[i];
        if (filter && strcmp(filter, c->name) != 0)
            continue;
        const struct json_value *row =
            linked ? vault_snapshot_class(&snap, c->read_class) : NULL;

        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        (void)json_push_kv_str(&o, "class", c->name);
        (void)json_push_kv_str(&o, "kind", c->kind);
        (void)json_push_kv_str(&o, "custody_command",
                               c->vault_verb[0] ? c->vault_verb : "none");
        if (row) {
            const struct json_value *complete = json_get(row, "determined");
            const struct json_value *money = json_get(row, "is_money");
            bool determined = complete && complete->type == JSON_BOOL &&
                              json_get_bool(complete);
            bool is_money = money && money->type == JSON_BOOL &&
                            json_get_bool(money);
            (void)json_push_kv_str(&o, "status",
                                   determined ? "ok" : "undetermined");
            vault_copy_str_as(&o, row, "source_primitive", "source",
                              "vault_read_snapshot");
            (void)json_push_kv_bool(&o, "complete",
                                    determined);
            if (is_money) {
                vault_push_total_as(&o, row, "total_zat");
                vault_copy_int_as(&o, row, "spendable", "spendable_zat");
                vault_copy_int_as(&o, row, "pending", "pending_zat");
                vault_copy_int_as(&o, row, "immature", "immature_zat");
                vault_copy_int_as(&o, row, "encumbered", "encumbered_zat");
            }
            vault_copy_int(&o, row, "item_count");
            if (!determined) {
                const char *reason = json_get_str(json_get(row, "reason"));
                (void)json_push_kv_str(&o, "reason",
                                       reason ? reason : "reader incomplete");
                unavailable++;
            } else {
                available++;
            }
        } else {
            (void)json_push_kv_str(&o, "status", "unavailable");
            (void)json_push_kv_str(&o, "source", "none");
            (void)json_push_kv_bool(&o, "complete", false);
            (void)json_push_kv_str(&o, "reason",
                                   linked ? "the read model returned no row "
                                            "for this class"
                                          : why);
            unavailable++;
        }
        vault_push_obj(&rows, &o);

        char line[220];
        (void)snprintf(line, sizeof(line), "%-12s %-12s custody=%s%s",
                       c->name, c->kind,
                       c->vault_verb[0] ? c->vault_verb : "none",
                       row ? "" : "  [unavailable]");
        vault_push_line(&lines, line);
    }

    struct json_value dropped;
    json_init(&dropped);
    json_set_array(&dropped);
    const struct json_value *parts[] = { &rows, &lines };
    bool keep_lines = true;
    if (vault_used(parts, 2) + VAULT_ENVELOPE_RESERVE > ZCL_COMMAND_LIST_BUDGET) {
        keep_lines = false;
        vault_push_line(&dropped, "lines");
    }

    (void)json_push_kv(&reply->data, "classes", &rows);
    if (keep_lines)
        (void)json_push_kv(&reply->data, "lines", &lines);
    (void)json_push_kv(&reply->data, "dropped_sections", &dropped);
    (void)json_push_kv_int(&reply->data, "classes_available", available);
    (void)json_push_kv_int(&reply->data, "classes_unavailable", unavailable);
    vault_push_legacy_wallet(reply);
    vault_push_provenance(reply, linked ? &snap : NULL, linked, why);
    json_free(&rows);
    json_free(&lines);
    json_free(&dropped);
    json_free(&snap);

    /* Every class dark is not an answer. Say so with an exit code rather than
     * handing back six zero-shaped rows that read like an empty wallet. A
     * failed envelope carries only the error, so the reason travels in the
     * error body itself and not in the rows above. */
    if (available == 0) {
        vault_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                   "VAULT_READ_UNAVAILABLE", "execute", true,
                   "no asset class could be read, so no balance is reported "
                   "for any of them", why[0] ? why : "read model unavailable");
        (void)zcl_command_reply_add_next(reply, "vault.routes", "{}",
                                         "see which custody paths exist "
                                         "regardless of the read model");
    }
}

/* ── vault.show / vault.encumbered ────────────────────────────────────────── */

/* Both leaves render the same item document; `encumbered_only` selects which
 * items pass and which summary is emitted. Neither computes an amount: every
 * number is copied from the read model or rendered as an explicit unknown. */
static void vault_render_items(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply,
                               bool encumbered_only)
{
    const char *filter = vault_str(request, "class");
    if (!encumbered_only && !filter) {
        vault_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "MISSING_CLASS", "normalize", false,
                   "class is required; name one asset class", k_vault_class_list);
        (void)zcl_command_reply_add_next(reply, "vault.list", "{}",
                                         "list the asset classes first");
        return;
    }
    if (filter && !vault_class_find(filter)) {
        vault_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "UNKNOWN_CLASS", "normalize", false,
                   "class is not one of the vault's asset classes",
                   k_vault_class_list);
        return;
    }

    char why[192] = { 0 };
    struct json_value snap;
    json_init(&snap);
    bool linked = vault_read_seam(filter, &snap, why, sizeof(why));
    if (!linked) {
        json_free(&snap);
        vault_push_provenance(reply, NULL, false, why);
        vault_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                   "VAULT_READ_UNAVAILABLE", "execute", true,
                   "the vault read model could not be reached, so no holding "
                   "can be reported", why);
        (void)zcl_command_reply_add_next(reply, "vault.routes", "{}",
                                         "see which custody paths exist "
                                         "regardless of the read model");
        return;
    }

    int cap = vault_item_cap(request);
    struct json_value items, lines, scanned;
    json_init(&items);
    json_set_array(&items);
    json_init(&lines);
    json_set_array(&lines);
    json_init(&scanned);
    json_set_array(&scanned);

    bool truncated = false;
    int emitted = 0, matched = 0, classes_missing = 0;

    for (int attempt = 0; attempt < 3; attempt++) {
        json_free(&items);
        json_init(&items);
        json_set_array(&items);
        json_free(&lines);
        json_init(&lines);
        json_set_array(&lines);
        json_free(&scanned);
        json_init(&scanned);
        json_set_array(&scanned);
        truncated = false;
        emitted = 0;
        matched = 0;
        classes_missing = 0;

        for (int ci = 0; ci < VAULT_ROUTE_COUNT; ci++) {
            const struct vault_route *c = &k_vault_routes[ci];
            if (filter && strcmp(filter, c->name) != 0)
                continue;
            const struct json_value *row = vault_snapshot_class(&snap,
                                                                 c->read_class);
            if (!row) {
                classes_missing++;
                continue;
            }
            vault_push_line(&scanned, c->name);
            const char *unit = json_get_str(json_get(row, "unit"));
            bool is_money = unit && strcmp(unit, "zatoshi") == 0;
            const struct json_value *arr = json_get(row, "items");
            if (!arr || arr->type != JSON_ARR)
                continue;
            for (size_t i = 0; i < json_size(arr); i++) {
                const struct json_value *it = json_at(arr, i);
                const struct json_value *enc = json_get(it, "encumbered");
                bool is_enc = enc && enc->type == JSON_BOOL &&
                              json_get_bool(enc);
                if (encumbered_only && !is_enc)
                    continue;
                matched++;
                if (emitted >= cap) {
                    truncated = true;
                    continue;
                }
                struct json_value o;
                json_init(&o);
                json_set_object(&o);
                (void)json_push_kv_str(&o, "class", c->name);
                vault_copy_str(&o, it, "id", "unknown");
                (void)json_push_kv_str(&o, "unit", unit ? unit : "unknown");
                if (is_money) {
                    vault_copy_int(&o, it, "amount_zat");
                } else if (strcmp(c->name, "tokens") == 0) {
                    vault_copy_int(&o, it, "units");
                    vault_copy_int(&o, it, "utxo_count");
                    vault_copy_str(&o, it, "ticker", "unknown");
                    vault_copy_str(&o, it, "name", "unknown");
                    vault_copy_int(&o, it, "decimals");
                }
                (void)json_push_kv_bool(&o, "encumbered", is_enc);
                if (is_enc) {
                    vault_copy_str(&o, it, "encumbered_reason", "unknown");
                    (void)json_push_kv_str(
                        &o, "release_command",
                        c->vault_verb[0] ? c->vault_verb : "none");
                }
                (void)json_push_kv_str(&o, "source", "vault_read_snapshot");
                vault_push_obj(&items, &o);

                char line[220];
                const char *id = json_get_str(json_get(it, "id"));
                (void)snprintf(line, sizeof(line), "%-12s %-24s %s", c->name,
                               id && id[0] ? id : "(unidentified)",
                               is_enc ? "ENCUMBERED" : "free");
                vault_push_line(&lines, line);
                emitted++;
            }
        }

        const struct json_value *parts[] = { &items, &lines, &scanned };
        if (vault_used(parts, 3) + VAULT_ENVELOPE_RESERVE <=
            ZCL_COMMAND_LIST_BUDGET)
            break;
        cap = cap > 1 ? cap / 2 : 1;
    }

    struct json_value dropped;
    json_init(&dropped);
    json_set_array(&dropped);
    const struct json_value *parts[] = { &items, &lines, &scanned };
    bool keep_lines = true;
    if (vault_used(parts, 3) + VAULT_ENVELOPE_RESERVE > ZCL_COMMAND_LIST_BUDGET) {
        keep_lines = false;
        vault_push_line(&dropped, "lines");
    }
    if (truncated)
        vault_push_line(&dropped, "items_beyond_limit");

    (void)json_push_kv_str(&reply->data, "scope",
                           encumbered_only ? "encumbered" : "holdings");
    (void)json_push_kv_str(&reply->data, "class", filter ? filter : "all");
    (void)json_push_kv(&reply->data, "items", &items);
    if (keep_lines)
        (void)json_push_kv(&reply->data, "lines", &lines);
    (void)json_push_kv(&reply->data, "classes_scanned", &scanned);
    (void)json_push_kv(&reply->data, "dropped_sections", &dropped);
    (void)json_push_kv_int(&reply->data, "items_rendered", emitted);
    (void)json_push_kv_int(&reply->data, "items_matched", matched);
    (void)json_push_kv_int(&reply->data, "item_limit", cap);
    (void)json_push_kv_bool(&reply->data, "items_truncated", truncated);
    (void)json_push_kv_int(&reply->data, "classes_missing_from_snapshot",
                           classes_missing);
    vault_push_provenance(reply, &snap, true, why);

    json_free(&items);
    json_free(&lines);
    json_free(&scanned);
    json_free(&dropped);
    json_free(&snap);
}

void zcl_native_handle_vault_show(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    vault_render_items(request, reply, false);
}

void zcl_native_handle_vault_encumbered(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    vault_render_items(request, reply, true);
}

/* ── vault.routes ─────────────────────────────────────────────────────────── */

/* Resolve one path in the live catalog and describe it. Node-free: this reads
 * the same static registry the CLI dispatches through, so a route that changed
 * owner or lost its handler shows up here immediately. */
static void vault_describe_target(struct json_value *o, const char *path)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec =
        (reg && path && path[0]) ? zcl_command_registry_find(reg, path, NULL)
                                 : NULL;
    if (!spec) {
        (void)json_push_kv_str(o, "owner_availability", "not_registered");
        (void)json_push_kv_bool(o, "handler_bound", false);
        return;
    }
    (void)json_push_kv_str(o, "owner_availability",
                           zcl_command_availability_name(spec->availability));
    (void)json_push_kv_bool(o, "handler_bound", spec->handler != NULL);
    (void)json_push_kv_str(o, "owner_authority",
                           zcl_command_authority_name(spec->authority));
    (void)json_push_kv_str(o, "owner_risk",
                           zcl_command_risk_name(spec->risk));
}

void zcl_native_handle_vault_routes(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    const char *filter = vault_str(request, "class");
    if (filter && !vault_class_find(filter)) {
        vault_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "UNKNOWN_CLASS", "normalize", false,
                   "class is not one of the vault's asset classes",
                   k_vault_class_list);
        return;
    }

    struct json_value rows, lines, unrouted;
    json_init(&rows);
    json_set_array(&rows);
    json_init(&lines);
    json_set_array(&lines);
    json_init(&unrouted);
    json_set_array(&unrouted);

    int routed = 0;
    for (int i = 0; i < VAULT_ROUTE_COUNT; i++) {
        const struct vault_route *c = &k_vault_routes[i];
        if (filter && strcmp(filter, c->name) != 0)
            continue;
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        (void)json_push_kv_str(&o, "class", c->name);
        (void)json_push_kv_str(&o, "route", c->route_kind);
        (void)json_push_kv_str(&o, "owner",
                               c->route_owner[0] ? c->route_owner : "none");
        (void)json_push_kv_str(&o, "builder_lives_in",
                               c->route_builder[0] ? c->route_builder : "none");
        (void)json_push_kv_str(&o, "vault_command",
                               c->vault_verb[0] ? c->vault_verb : "none");
        (void)json_push_kv_str(&o, "note", c->route_note);
        if (strcmp(c->route_kind, "native_command") == 0)
            vault_describe_target(&o, c->route_owner);
        else if (strcmp(c->route_kind, "node_rpc") == 0)
            (void)json_push_kv_str(&o, "owner_availability",
                                   "rpc_only (no native leaf binds it)");
        else
            (void)json_push_kv_str(&o, "owner_availability", "none");
        if (c->vault_verb[0])
            routed++;
        else
            vault_push_line(&unrouted, c->name);
        vault_push_obj(&rows, &o);

        char line[220];
        (void)snprintf(line, sizeof(line), "%-12s %-14s %s", c->name,
                       c->route_kind,
                       c->route_owner[0] ? c->route_owner : "(no owner)");
        vault_push_line(&lines, line);
    }

    struct json_value dropped;
    json_init(&dropped);
    json_set_array(&dropped);
    const struct json_value *parts[] = { &rows, &lines, &unrouted };
    bool keep_lines = true;
    if (vault_used(parts, 3) + VAULT_ENVELOPE_RESERVE > ZCL_COMMAND_LIST_BUDGET) {
        keep_lines = false;
        vault_push_line(&dropped, "lines");
    }

    (void)json_push_kv(&reply->data, "routes", &rows);
    if (keep_lines)
        (void)json_push_kv(&reply->data, "lines", &lines);
    (void)json_push_kv(&reply->data, "classes_without_a_vault_command",
                       &unrouted);
    (void)json_push_kv(&reply->data, "dropped_sections", &dropped);
    (void)json_push_kv_int(&reply->data, "classes_routed", routed);
    (void)json_push_kv_int(&reply->data, "class_count", VAULT_ROUTE_COUNT);
    (void)json_push_kv_bool(&reply->data, "spend_logic_in_vault", false);
    (void)json_push_kv_str(&reply->data, "source",
                           "engine/composition/src/command_catalog.c (live registry) + "
                           "tools/command/native_vault_command.c route table");
    (void)json_push_kv_str(&reply->data, "evidence",
                           "every custody leaf ends in vault_dispatch() or "
                           "vault_rpc_settle(); no transaction is built here");

    json_free(&rows);
    json_free(&lines);
    json_free(&unrouted);
    json_free(&dropped);
}

/* ── the custody routing ──────────────────────────────────────────────────── */

/* Copy exactly the named keys from `src` into `dst`, in the order given. No
 * key is invented, no value is transformed, no key outside the list is
 * forwarded. This is the whole of what the vault does to a custody input
 * before handing it to the path that owns the spend — which is why a vault
 * send and a direct send with the same inputs reach the owning handler with
 * the same object, and therefore produce the same transaction. */
static void vault_forward_keys(const struct json_value *src,
                               struct json_value *dst,
                               const char *const *keys, size_t nkeys)
{
    json_set_object(dst);
    for (size_t i = 0; i < nkeys; i++) {
        const struct json_value *v = json_get(src, keys[i]);
        if (!v)
            continue;
        struct json_value copy;
        json_init(&copy);
        json_copy(&copy, v);
        (void)json_push_kv(dst, keys[i], &copy);
        json_free(&copy);
    }
}

/* Route one custody request to the leaf that already owns it.
 *
 * This is the ONLY way this file reaches a spend, and it builds nothing. It
 * resolves `target_path` in the live catalog, re-runs the authorization the
 * kernel would run for a direct invocation of that leaf (availability, lane,
 * session authority ceiling, capabilities), refuses any route that would let
 * the vault leaf grant more than it declares, validates the forwarded object
 * against the TARGET's own input schema, and then calls the very handler
 * function pointer the target binds — writing into the caller's reply, so the
 * target's document, errors and next-actions come back unmodified.
 *
 * Returns true when the target handler ran. */
static bool vault_dispatch(const struct zcl_command_request *request,
                           const char *target_path,
                           const struct json_value *input,
                           struct zcl_command_reply *reply)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *self = request->spec;
    const struct zcl_command_spec *target =
        reg ? zcl_command_registry_find(reg, target_path, NULL) : NULL;

    if (!target) {
        vault_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                   ZCL_COMMAND_EXIT_INTERNAL, "ROUTE_MISSING", "dispatch",
                   false, "the command this vault verb routes to is not in "
                          "the registry", target_path);
        return false;
    }
    if (target->mode == ZCL_COMMAND_MODE_BRANCH ||
        target->availability != ZCL_COMMAND_READY || !target->handler) {
        vault_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                   ZCL_COMMAND_EXIT_BLOCKED, "ROUTE_NOT_READY", "dispatch",
                   false,
                   "the command this vault verb routes to is not executable "
                   "in this build", target_path);
        (void)zcl_command_reply_add_next(reply, "vault.routes", "{}",
                                         "inspect the custody routing table");
        return false;
    }
    /* No privilege laundering: a vault verb may never reach a path that
     * demands more authority, capability, risk or effect than the verb itself
     * declares and the operator therefore consented to. */
    if (target->authority > self->authority ||
        target->risk > self->risk || target->effect > self->effect ||
        (target->required_capabilities & ~self->required_capabilities) != 0 ||
        (self->allowed_lanes & ~target->allowed_lanes) != 0) {
        vault_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_DENIED,
                   "ROUTE_ESCALATES", "authorize", false,
                   "this vault verb declares less than the path it routes to; "
                   "refusing to dispatch", target_path);
        return false;
    }
    if (request->context &&
        target->authority > request->context->authority_ceiling) {
        vault_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_DENIED,
                   "AUTHORITY_DENIED", "authorize", false,
                   "the routed command's authority exceeds this session's "
                   "ceiling",
                   zcl_command_authority_name(target->authority));
        return false;
    }
    if (request->context &&
        (target->required_capabilities &
         ~request->context->granted_capabilities) != 0) {
        vault_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_DENIED,
                   "CAPABILITY_DENIED", "authorize", false,
                   "the routed command requires a capability this session was "
                   "not granted", target_path);
        return false;
    }
    /* Agent spend policy. The vault calls target->handler directly, so the
     * TARGET never passes through execute_json — but the vault LEAF itself
     * did, and the kernel gate already ruled on this invocation (and, for a
     * confirmed spend, already debited it). vault_forward_keys copies `amount`
     * and the recipient verbatim, so re-running the gate here would charge the
     * same spend twice: a session with max_per_window == max_per_tx could
     * never complete a single vault send, because the second check saw its own
     * first debit and refused. `agent_policy_settled` is the kernel saying "I
     * own the accounting for this dispatch"; the gate below therefore exists
     * only for a caller that reached vault_dispatch WITHOUT the kernel gate,
     * which no registry path does today and a future one must not do silently.
     */
    if (!request->agent_policy_settled) {
        const char *agent_session =
            request->context ? request->context->agent_session : NULL;
        if (agent_session && agent_session[0]) {
            struct agent_spend_policy_decision d;
            bool committing = json_get_bool_or(input, "confirm", false);
            agent_spend_policy_evaluate(agent_session, target, input,
                                        committing, &d);
            if (!d.allowed) {
                vault_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_DENIED,
                           d.code[0] ? d.code : "POLICY_DENIED", "policy",
                           false,
                           d.detail[0] ? d.detail
                                       : "the agent session's spend policy "
                                         "refused this custody route",
                           /* redacted grant id, never the bearer token */
                           d.evidence);
                return false;
            }
        }
    }

    char why[192] = { 0 };
    if (!zcl_command_registry_input_validate(target, input, why, sizeof(why))) {
        vault_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "ROUTE_INPUT_REJECTED", "normalize", false,
                   why[0] ? why : "the routed command rejected the forwarded "
                                  "input", target_path);
        return false;
    }

    struct zcl_command_request routed = {
        .spec = target,
        .context = request->context,
        .input = input,
        .view = request->view,
        .budget_bytes = request->budget_bytes,
        .max_items = request->max_items,
        .cursor = request->cursor,
        .invoked_by_alias = false,
        .invoked_name = self->path,
        /* Carried forward: the accounting for this invocation is already
         * settled, so nothing further down may debit it again. */
        .agent_policy_settled = request->agent_policy_settled,
    };
    target->handler(&routed, reply);

    (void)json_push_kv_str(&reply->data, "routed_to", target->path);
    (void)json_push_kv_str(&reply->data, "routed_from", self->path);
    (void)json_push_kv_str(&reply->data, "routed_via",
                           "vault_dispatch: the registry-bound handler of the "
                           "routed command, called with the forwarded input");
    return true;
}

/* Attach the vault's ADVISORY pre-flight for one class to a plan reply. Never
 * a precondition: an unavailable read model annotates the plan and nothing
 * more, because the owning command — not the vault — decides whether a spend
 * is fundable. */
static void vault_attach_preflight(struct zcl_command_reply *reply,
                                   const char *class_name)
{
    char why[192] = { 0 };
    struct json_value snap;
    json_init(&snap);
    struct json_value pf;
    json_init(&pf);
    json_set_object(&pf);
    (void)json_push_kv_str(&pf, "class", class_name);
    (void)json_push_kv_str(&pf, "authority", "advisory only — the routed "
                                             "command decides fundability");
    if (vault_read_seam(class_name, &snap, why, sizeof(why))) {
        const struct vault_route *route = vault_class_find(class_name);
        const struct json_value *row = route
            ? vault_snapshot_class(&snap, route->read_class) : NULL;
        if (row) {
            (void)json_push_kv_str(&pf, "status", "ok");
            vault_copy_int_as(&pf, row, "spendable", "spendable_zat");
            vault_copy_int_as(&pf, row, "encumbered", "encumbered_zat");
            vault_copy_str_as(&pf, row, "source_primitive", "source",
                              "vault_read_snapshot");
        } else {
            (void)json_push_kv_str(&pf, "status", "unknown");
            (void)json_push_kv_str(&pf, "reason",
                                   "the read model returned no row for this "
                                   "class");
        }
    } else {
        (void)json_push_kv_str(&pf, "status", "unknown");
        (void)json_push_kv_str(&pf, "reason", why);
    }
    (void)json_push_kv(&reply->data, "preflight", &pf);
    json_free(&pf);
    json_free(&snap);
}

void zcl_native_handle_vault_send(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    static const char *const keys[] = { "address", "amount", "wallet_scope",
                                        "idempotency_key", "confirm" };
    struct json_value forwarded;
    json_init(&forwarded);
    vault_forward_keys(request->input, &forwarded,
                       keys, sizeof(keys) / sizeof(keys[0]));
    bool ran = vault_dispatch(request, "core.wallet.transaction.send",
                              &forwarded, reply);
    json_free(&forwarded);
    if (ran && !json_get_bool_or(request->input, "confirm", false))
        vault_attach_preflight(reply, "transparent");
}

void zcl_native_handle_vault_send_shielded(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    static const char *const keys[] = { "from", "to", "amount",
                                        "memo", "memo_hex", "wallet_scope",
                                        "idempotency_key", "confirm" };
    struct json_value forwarded;
    json_init(&forwarded);
    vault_forward_keys(request->input, &forwarded,
                       keys, sizeof(keys) / sizeof(keys[0]));
    bool ran = vault_dispatch(request, "core.wallet.shielded.send", &forwarded,
                              reply);
    json_free(&forwarded);
    if (ran && !json_get_bool_or(request->input, "confirm", false))
        vault_attach_preflight(reply, "shielded");
}

void zcl_native_handle_vault_send_token(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    static const char *const keys[] = { "token_id", "to", "units",
                                        "confirm" };
    struct json_value forwarded;
    json_init(&forwarded);
    vault_forward_keys(request->input, &forwarded,
                       keys, sizeof(keys) / sizeof(keys[0]));
    bool ran = vault_dispatch(request, "app.tokens.send", &forwarded, reply);
    json_free(&forwarded);
    if (ran && !json_get_bool_or(request->input, "confirm", false))
        vault_attach_preflight(reply, "tokens");
}

/* ── swap settlement: the same routing, one layer lower ────────────────────
 * No native leaf binds swap_redeem / swap_refund, so the owning path is the
 * RPC method itself (engine/controllers/src/swap_controller.c), which builds,
 * signs, broadcasts and persists. The vault supplies only the plan/commit gate
 * the RPC lacks, and encodes the arguments through the sanctioned params
 * builder — it never touches the transaction. */

/* Parse the optional funding outpoint. Both halves must be present or both
 * absent: half an outpoint would silently become a different one. */
static bool vault_funding_args(const struct zcl_command_request *request,
                               const char **txid, int64_t *vout, char *why,
                               size_t why_cap)
{
    const char *t = vault_str(request, "funding_txid");
    const char *v = vault_str(request, "vout");
    *txid = NULL;
    *vout = 0;
    if (!t && !v)
        return true;
    if (!t || !v) {
        (void)snprintf(why, why_cap,
                       "funding_txid and vout must be given together");
        LOG_FAIL(VAULT_TAG, "half a funding outpoint: txid=%s vout=%s",
                 t ? t : "(absent)", v ? v : "(absent)");
    }
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (!end || *end != '\0' || n < 0 || n > 65535) {
        (void)snprintf(why, why_cap,
                       "vout must be a decimal output index in 0..65535");
        LOG_FAIL(VAULT_TAG, "unparseable vout '%s'", v);
    }
    *txid = t;
    *vout = (int64_t)n;
    return true;
}

/* Plan or commit one swap settlement. `secret` is NULL for a refund. */
static void vault_rpc_settle(const struct zcl_command_request *request,
                             struct zcl_command_reply *reply,
                             const char *rpc_method, const char *secret)
{
    const char *swap_id = vault_str(request, "swap_id");
    if (!swap_id) {
        vault_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "MISSING_SWAP_ID", "normalize", false,
                   "swap_id is required", request->spec->path);
        (void)zcl_command_reply_add_next(reply, "app.swap.list", "{}",
                                         "list the swap contracts this node "
                                         "tracks");
        return;
    }
    if (strcmp(rpc_method, "swap_redeem") == 0 && !secret) {
        vault_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "MISSING_SECRET", "normalize", false,
                   "secret is required to claim an HTLC", swap_id);
        return;
    }

    const char *funding_txid = NULL;
    int64_t vout = 0;
    char why[160] = { 0 };
    if (!vault_funding_args(request, &funding_txid, &vout, why, sizeof(why))) {
        vault_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                   "BAD_FUNDING_OUTPOINT", "normalize", false, why, swap_id);
        return;
    }

    (void)json_push_kv_str(&reply->data, "swap_id", swap_id);
    (void)json_push_kv_str(&reply->data, "routed_to", rpc_method);
    (void)json_push_kv_str(&reply->data, "routed_from", request->spec->path);
    (void)json_push_kv_str(&reply->data, "routed_via",
                           "vault_rpc_settle: the node RPC method registered "
                           "by engine/controllers/src/swap_controller.c");

    if (!json_get_bool_or(request->input, "confirm", false)) {
        struct json_value ci;
        json_init(&ci);
        json_set_object(&ci);
        (void)json_push_kv_str(&ci, "swap_id", swap_id);
        if (secret)
            (void)json_push_kv_str(&ci, "secret", secret);
        if (funding_txid) {
            (void)json_push_kv_str(&ci, "funding_txid", funding_txid);
            char vb[16];
            (void)snprintf(vb, sizeof(vb), "%lld", (long long)vout);
            (void)json_push_kv_str(&ci, "vout", vb);
        }
        (void)json_push_kv_bool(&ci, "confirm", true);
        char commit[512];
        size_t n = json_write(&ci, commit, sizeof(commit));
        if (n == 0 || n >= sizeof(commit)) {
            LOG_WARN(VAULT_TAG, "commit input truncated (%zu bytes)", n);
            (void)snprintf(commit, sizeof(commit),
                           "{\"swap_id\":\"%s\",\"confirm\":true}", swap_id);
        }
        json_free(&ci);
        (void)json_push_kv_str(&reply->data, "stage", "plan");
        (void)json_push_kv_bool(&reply->data, "committed", false);
        /* The commit travels as data, not as a next-action: the kernel rejects
         * a next-action that points back at the leaf that emitted it
         * (push_next_array, command_registry.c), and this plan's commit is
         * this same leaf re-run with confirm:true. */
        (void)json_push_kv_str(&reply->data, "commit_input", commit);
        (void)json_push_kv_str(
            &reply->data, "confirm_hint",
            "re-run this command with \"confirm\":true to let the swap "
            "controller build, sign and broadcast the settlement");
        reply->error.mutated = false;
        return;
    }

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, swap_id);
    if (secret)
        rpc_arg_builder_push_str(&p, secret);
    if (funding_txid) {
        rpc_arg_builder_push_str(&p, funding_txid);
        rpc_arg_builder_push_int(&p, vout);
    }
    char *params = rpc_arg_builder_to_json(&p);
    if (!params) {
        vault_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                   ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED", "normalize",
                   false, "could not encode the settlement RPC parameters",
                   swap_id);
        return;
    }

    zcl_native_bridge_ensure_rpc();
    char *result = node_rpc_call(rpc_method, params);
    free(params);
    if (!result) {
        vault_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                   ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE", "dispatch",
                   true, "the node returned no body for the settlement RPC",
                   rpc_method);
        (void)zcl_command_reply_add_next(reply, "status", "{}",
                                         "confirm the node is running");
        return;
    }

    struct json_value body;
    json_init(&body);
    if (!json_read(&body, result, strlen(result))) {
        json_free(&body);
        free(result);
        vault_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                   ZCL_COMMAND_EXIT_INTERNAL, "BAD_SETTLE_BODY", "serialize",
                   false, "the settlement RPC returned an unreadable body",
                   rpc_method);
        return;
    }
    free(result);

    /* node_rpc_call surfaces a failure as {"error":{...}}, a bare
     * {"code":..,"message":..}, or a plain string — the swap controller
     * returns its refusals as the latter. All three mean nothing was
     * broadcast. */
    const struct json_value *err = json_get(&body, "error");
    const struct json_value *ecode = json_get(&body, "code");
    const struct json_value *emsg = json_get(&body, "message");
    const char *msg = NULL;
    if (body.type == JSON_STR)
        msg = json_get_str(&body);
    else if (err && err->type == JSON_OBJ)
        msg = json_get_str(json_get(err, "message"));
    else if (err && err->type == JSON_STR)
        msg = json_get_str(err);
    else if (ecode && ecode->type == JSON_INT && emsg && emsg->type == JSON_STR)
        msg = json_get_str(emsg);
    if (msg) {
        vault_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                   "SETTLE_REFUSED", "execute", false,
                   msg[0] ? msg : "the swap controller refused the settlement",
                   rpc_method);
        json_free(&body);
        return;
    }

    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    vault_copy_str(&reply->data, &body, "status", "unknown");
    vault_copy_str(&reply->data, &body, "txid", "unknown");
    vault_copy_int(&reply->data, &body, "amount_zatoshi");
    reply->error.mutated = true;
    json_free(&body);
}

void zcl_native_handle_vault_swap_redeem(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    vault_rpc_settle(request, reply, "swap_redeem",
                     vault_str(request, "secret"));
}

void zcl_native_handle_vault_swap_refund(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    vault_rpc_settle(request, reply, "swap_refund", NULL);
}
