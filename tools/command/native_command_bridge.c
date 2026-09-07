/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The bridged-leaf dispatch pipeline: everything zcl_native_bridge_command
 * (tools/command/native_command.c) does once it has resolved a body function
 * (or decided the leaf is a pure 1:1 JSON-RPC proxy). This file owns three
 * cooperating pieces:
 *
 *   - direct-RPC success validation (bridge_validate_rpc_success and its
 *     helpers) — a bare, parseable JSON value from a legacy RPC is not proof
 *     the method exists or that the running node speaks this source epoch's
 *     contract, so every direct-RPC leaf's result is checked against its
 *     bridge_rpc_binding row before it is trusted;
 *   - progressive-disclosure projection (contract §8/§9) — nc_project_array /
 *     zcl_native_bridge_project bound a bridged command body to the leaf's
 *     result budget, paging via an explicit cursor rather than failing with
 *     RESPONSE_BUDGET_EXCEEDED;
 *   - zcl_native_bridge_run — the run-a-bridged-leaf sequence itself: resolve
 *     the binding, build args, dispatch, and validate/project the result.
 *
 * native_command.c keeps the two lookup tables this file's dispatch reads
 * (g_bridge_native_body / g_bridge_rpc_direct) plus their small accessors, so
 * both this file's bridge_rpc_binding_for_path() and its own
 * bridge_has_exact_binding() catalog check share one binding table.
 */

#include "command/native_command.h"
#include "command/native_command_priv.h"

#include "controllers/native_handler_body.h"
#include "controllers/rpc_client.h"
#include "controllers/status_native_helpers.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── direct JSON-RPC success validation ──────────────────────────────
 * A bare, parseable JSON value is not proof that the requested RPC exists or
 * that the running node speaks this source epoch's contract. Direct-RPC
 * leaves therefore validate the stable minimum of the legacy result shape.
 * These checks intentionally do not require a synthetic `schema` member:
 * zclassicd-compatible RPCs predate schema labels, but their field/type shape
 * is stable. Empty list results remain valid; every populated element is
 * checked so a mixed or arbitrary array fails closed. */
static const char *bridge_json_type_name(enum json_type type)
{
    static const char *const names[] = {
        "null", "bool", "int", "real", "string", "array", "object",
    };
    return (unsigned)type < sizeof(names) / sizeof(names[0])
               ? names[type]
               : "unknown";
}

static bool bridge_is_hex64(const char *s)
{
    if (!s || strlen(s) != 64)
        return false;
    for (size_t i = 0; i < 64; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isxdigit(c))
            return false;
    }
    return true;
}

static bool bridge_validate_array_item(
    const struct bridge_rpc_binding *binding,
    const struct json_value *item, size_t index,
    char *why, size_t why_cap)
{
    const char *field_a = NULL;
    const char *field_b = NULL;
    switch (binding->array_kind) {
    case BRIDGE_RPC_ARRAY_TXIDS:
        if (item->type == JSON_STR && bridge_is_hex64(json_get_str(item)))
            return true;
        (void)snprintf(why, why_cap,
                       "item %zu must be a 64-hex transaction id", index);
        return false;
    case BRIDGE_RPC_ARRAY_PEERS:
        field_a = "id";
        field_b = "addr";
        break;
    case BRIDGE_RPC_ARRAY_LATENCY:
        field_a = "peer_id";
        field_b = "addr";
        break;
    case BRIDGE_RPC_ARRAY_NONE:
        return true;
    }
    if (item->type != JSON_OBJ) {
        (void)snprintf(why, why_cap, "item %zu must be an object", index);
        return false;
    }
    const struct json_value *a = json_get(item, field_a);
    const struct json_value *b = json_get(item, field_b);
    if (!a || a->type != JSON_INT) {
        (void)snprintf(why, why_cap, "item %zu field %s must be int",
                       index, field_a);
        return false;
    }
    if (!b || b->type != JSON_STR) {
        (void)snprintf(why, why_cap, "item %zu field %s must be string",
                       index, field_b);
        return false;
    }
    return true;
}

static bool bridge_validate_rpc_success(
    const struct bridge_rpc_binding *binding,
    const struct json_value *doc, char *why, size_t why_cap)
{
    if (!binding || !doc) {
        (void)snprintf(why, why_cap, "missing direct-RPC contract");
        return false;
    }
    if (doc->type != binding->top_type) {
        (void)snprintf(why, why_cap, "top level must be %s (got %s)",
                       bridge_json_type_name(binding->top_type),
                       bridge_json_type_name(doc->type));
        return false;
    }
    for (size_t i = 0;
         i < sizeof(binding->required) / sizeof(binding->required[0]); i++) {
        const struct bridge_rpc_required_field *required =
            &binding->required[i];
        if (!required->name)
            break;
        const struct json_value *field = json_get(doc, required->name);
        if (!field || field->type != required->type) {
            (void)snprintf(why, why_cap, "field %s must be %s",
                           required->name,
                           bridge_json_type_name(required->type));
            return false;
        }
    }
    if (binding->top_type == JSON_ARR) {
        for (size_t i = 0; i < doc->num_children; i++) {
            if (!bridge_validate_array_item(binding, &doc->children[i], i,
                                            why, why_cap))
                return false;
        }
    }
    return true;
}

/* Translate the CLI leaf input into the exact argument object its handler
 * expects. Most leaves are pass-through; a few need a rename. */
static bool bridge_build_args(const char *path,
                              const struct json_value *input,
                              struct json_value *out, bool *use_out)
{
    *use_out = false;
    if (strcmp(path, "core.chain.block.get") == 0) {
        json_init(out);
        json_set_object(out);
        const struct json_value *height = json_get(input, "height");
        const struct json_value *hash = json_get(input, "hash");
        const struct json_value *verbosity = json_get(input, "verbosity");
        if (hash && !json_is_null(hash)) {
            if (!json_push_kv_str(out, "block_id", json_get_str(hash))) {
                json_free(out);
                return false;
            }
        } else if (height && !json_is_null(height)) {
            char idbuf[32];
            (void)snprintf(idbuf, sizeof(idbuf), "%lld",
                           (long long)json_get_int(height));
            if (!json_push_kv_str(out, "block_id", idbuf)) {
                json_free(out);
                return false;
            }
        }
        if (verbosity && !json_is_null(verbosity)) {
            if (!json_push_kv_int(out, "verbosity", json_get_int(verbosity))) {
                json_free(out);
                return false;
            }
        }
        *use_out = true;
        return true;
    }
    return true; /* pass-through: caller uses `input` directly */
}

/* ── progressive-disclosure projection (contract §8/§9) ──────────────────
 * A bridged command body can exceed the ordinary-result budget. Rather
 * than fail with RESPONSE_BUDGET_EXCEEDED, project the top-level object to fit:
 *   summary — scalar top-level fields only (containers dropped);
 *   normal  — greedy from --cursor until the leaf budget (default);
 *   full    — greedy from --cursor, honoring --max-items, paging via a cursor.
 * Truncation is always explicit: a `_page` object records the advancing
 * cursor, while `next` points at the leaf contract instead of creating an
 * executable self-loop. `--cursor` is honored in normal and full so a
 * truncated list can actually continue. */
enum { NC_ENVELOPE_RESERVE = 768 };

void nc_add_describe_next(struct zcl_command_reply *reply,
                          const char *path, const char *reason)
{
    if (!reply || !path || !path[0])
        return;
    char input[ZCL_COMMAND_MAX_PATH + 16];
    int n = snprintf(input, sizeof(input), "{\"path\":\"%s\"}", path);
    if (n > 0 && (size_t)n < sizeof(input))
        (void)zcl_command_reply_add_next(reply, "discover.describe", input,
                                         reason);
}

void nc_add_string_next(struct zcl_command_reply *reply,
                        const char *command, const char *key,
                        const char *value, const char *reason)
{
    if (!reply || !command || !key || !value)
        return;
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    char encoded[sizeof(reply->next[0].input_json)];
    bool ok = json_push_kv_str(&input, key, value);
    size_t n = ok ? json_write(&input, encoded, sizeof(encoded)) : 0;
    json_free(&input);
    if (n > 0 && n < sizeof(encoded))
        (void)zcl_command_reply_add_next(reply, command, encoded, reason);
}

static bool nc_is_scalar(const struct json_value *v)
{
    return v && v->type <= JSON_STR; /* NULL/BOOL/INT/REAL/STR */
}

static size_t nc_json_size(const struct json_value *value)
{
    char scratch[ZCL_COMMAND_LIST_BUDGET + 1];
    size_t n = json_write(value, scratch, sizeof(scratch));
    return (n == 0 || n >= sizeof(scratch)) ? sizeof(scratch) : n;
}

static int nc_peer_kind(const struct json_value *row)
{
    if (json_get_bool(json_get(row, "zclassic23")))
        return 0;
    if (json_get_bool(json_get(row, "magicbean")))
        return 1;
    return 2;
}

/* Stable kind order: Z23, then MagicBean, then other. No host list. */
static void nc_peer_order(const struct json_value *body, size_t *ord, size_t n)
{
    for (size_t i = 0; i < n; i++)
        ord[i] = i;
    for (size_t i = 1; i < n; i++) {
        size_t v = ord[i];
        size_t j = i;
        int vk = nc_peer_kind(&body->children[v]);
        while (j > 0 &&
               nc_peer_kind(&body->children[ord[j - 1]]) > vk) {
            ord[j] = ord[j - 1];
            j--;
        }
        ord[j] = v;
    }
}

/* Shared by both nc_project_array and zcl_native_bridge_project: `--cursor`
 * is honored in normal and full view, ignored in summary view (which always
 * restarts from the top and reports omissions instead of paging). */
static size_t nc_project_cursor_start(const struct zcl_command_request *request,
                                      bool summary)
{
    size_t start = 0;
    if (!summary && request->cursor && request->cursor[0]) {
        char *end = NULL;
        unsigned long long c = strtoull(request->cursor, &end, 10);
        if (end && !*end)
            start = (size_t)c;
    }
    return start;
}

/* Resolve the leaf's item budget: the per-leaf/per-request contract minus the
 * envelope reserve, minus room for the stable page descriptor. */
static size_t nc_project_array_items_budget(
    const struct zcl_command_request *request)
{
    size_t contract = ZCL_COMMAND_RESULT_BUDGET;
    if (request->spec && request->spec->budget_bytes > (int)contract)
        contract = (size_t)request->spec->budget_bytes;
    if (request->budget_bytes > 0 && request->budget_bytes < contract)
        contract = request->budget_bytes;
    size_t data_budget = contract > NC_ENVELOPE_RESERVE
                             ? contract - NC_ENVELOPE_RESERVE
                             : contract / 2;
    return data_budget > 256 ? data_budget - 256 : data_budget / 2;
}

/* core.network.peers.list orders Z23 peers first, then MagicBean, then other
 * — with no host list involved. `ord` must hold at least `nbody` entries;
 * returns it as the iteration map, or NULL when no reorder applies. */
static const size_t *nc_project_array_peer_map(
    const struct zcl_command_request *request, const struct json_value *body,
    size_t *ord, size_t nbody)
{
    if (request->spec && request->spec->path &&
        strcmp(request->spec->path, "core.network.peers.list") == 0 &&
        nbody > 0 && nbody <= 256) {
        nc_peer_order(body, ord, nbody);
        return ord;
    }
    return NULL;
}

/* Greedily copy body->children (in `map` order, if given) into `items` from
 * `start` until items_budget or request->max_items (full view) is hit. Fills
 * every out param nc_project_array's page descriptor and reply need. */
static void nc_project_array_collect(
    const struct zcl_command_request *request, const struct json_value *body,
    const size_t *map, size_t nbody, size_t start, bool summary, bool full,
    size_t items_budget, struct json_value *items, size_t *included_out,
    size_t *next_cursor_out, bool *truncated_out, bool *skipped_oversize_out,
    size_t *skipped_index_out)
{
    size_t included = 0;
    size_t next_cursor = summary ? 0 : nbody;
    bool truncated = summary && body->num_children > 0;
    bool skipped_oversize = false;
    size_t skipped_index = 0;

    for (size_t i = start; !summary && i < nbody; i++) {
        if (full && request->max_items > 0 && included >= request->max_items) {
            truncated = true;
            next_cursor = i;
            break;
        }
        struct json_value probe, copy;
        json_init(&probe);
        json_init(&copy);
        json_copy(&probe, items);
        json_copy(&copy, &body->children[map ? map[i] : i]);
        (void)json_push_back(&probe, &copy);
        size_t sz = nc_json_size(&probe);
        json_free(&probe);
        if (sz <= items_budget) {
            (void)json_push_back(items, &copy);
            included++;
            json_free(&copy);
            continue;
        }
        json_free(&copy);
        truncated = true;
        if (included == 0) {
            skipped_oversize = true;
            skipped_index = i;
            next_cursor = i + 1;
        } else {
            next_cursor = i;
        }
        break;
    }

    *included_out = included;
    *next_cursor_out = next_cursor;
    *truncated_out = truncated;
    *skipped_oversize_out = skipped_oversize;
    *skipped_index_out = skipped_index;
}

/* Build the `_page` descriptor nc_project_array attaches to `data`. */
static void nc_project_array_build_page(
    const struct zcl_command_request *request, const char *view,
    const struct json_value *body, size_t included, bool truncated,
    size_t next_cursor, bool skipped_oversize, size_t skipped_index,
    struct json_value *page)
{
    json_init(page);
    json_set_object(page);
    (void)json_push_kv_str(page, "view", view);
    (void)json_push_kv_int(page, "total_items", (int64_t)body->num_children);
    (void)json_push_kv_int(page, "included", (int64_t)included);
    (void)json_push_kv_bool(page, "truncated", truncated);
    if (truncated)
        (void)json_push_kv_int(page, "next_cursor", (int64_t)next_cursor);
    if (truncated && request->spec && request->spec->path) {
        char words[128];
        char cont[192];
        size_t wl = 0;
        for (const char *p = request->spec->path;
             *p && wl + 1 < sizeof(words); p++)
            words[wl++] = *p == '.' ? ' ' : *p;
        words[wl] = '\0';
        if (snprintf(cont, sizeof(cont), "z23 %s --cursor=%zu", words,
                     next_cursor) > 0)
            (void)json_push_kv_str(page, "continue", cont);
    }
    if (skipped_oversize)
        (void)json_push_kv_int(page, "skipped_oversize_index",
                               (int64_t)skipped_index);
}

static void nc_project_array(const struct zcl_command_request *request,
                             const struct json_value *body,
                             struct zcl_command_reply *reply)
{
    const char *view = request->view && request->view[0] ? request->view
                                                          : "normal";
    bool summary = strcmp(view, "summary") == 0;
    bool full = strcmp(view, "full") == 0;
    size_t items_budget = nc_project_array_items_budget(request);
    size_t start = nc_project_cursor_start(request, summary);

    size_t ord[256];
    size_t nbody = body->num_children;
    const size_t *map = nc_project_array_peer_map(request, body, ord, nbody);

    struct json_value items;
    json_init(&items);
    json_set_array(&items);
    size_t included, next_cursor, skipped_index;
    bool truncated, skipped_oversize;
    nc_project_array_collect(request, body, map, nbody, start, summary, full,
                             items_budget, &items, &included, &next_cursor,
                             &truncated, &skipped_oversize, &skipped_index);

    struct json_value page, data;
    nc_project_array_build_page(request, view, body, included, truncated,
                                next_cursor, skipped_oversize, skipped_index,
                                &page);
    json_init(&data);
    json_set_object(&data);
    (void)json_push_kv(&data, "items", &items);
    (void)json_push_kv(&data, "_page", &page);
    json_free(&items);
    json_free(&page);

    json_free(&reply->data);
    json_init(&reply->data);
    json_copy(&reply->data, &data);
    json_free(&data);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;

    if (truncated)
        nc_add_describe_next(
            reply, request->spec->path,
            summary ? "inspect paging controls before retrieving list items"
                    : "inspect paging controls before continuing this list");
}

/* Resolve the leaf's data budget for the object (field-projection) path. */
static size_t nc_project_fields_data_budget(
    const struct zcl_command_request *request)
{
    size_t contract = ZCL_COMMAND_RESULT_BUDGET;
    if (request->budget_bytes > 0 && request->budget_bytes < contract)
        contract = request->budget_bytes;
    return contract > NC_ENVELOPE_RESERVE ? contract - NC_ENVELOPE_RESERVE
                                          : contract / 2;
}

/* Greedily copy body's top-level members into `acc` from `start` (summary
 * view instead scans all members, keeping scalars only) until data_budget or
 * request->max_items (full view) is hit. Fills every out param
 * zcl_native_bridge_project's page descriptor and reply need. */
static void nc_project_fields_collect(
    const struct zcl_command_request *request, const struct json_value *body,
    size_t start, bool summary, bool full, size_t data_budget,
    struct json_value *acc, size_t *included_out, size_t *omitted_out,
    size_t *next_cursor_out, bool *truncated_out, const char **oversize_key_out)
{
    size_t total = body->num_children;
    size_t included = 0, omitted = 0, next_cursor = total;
    bool truncated = false;
    const char *oversize_key = NULL;

    for (size_t i = (summary ? 0 : start); i < total; i++) {
        const struct json_value *val = &body->children[i];
        if (summary && !nc_is_scalar(val)) {
            omitted++;
            continue;
        }
        if (full && request->max_items > 0 && included >= request->max_items) {
            truncated = true;
            next_cursor = i;
            break;
        }
        /* Measure a copy with the candidate member before committing it. */
        struct json_value probe, copy;
        json_init(&probe);
        json_init(&copy);
        json_copy(&probe, acc);
        json_copy(&copy, val);
        (void)json_push_kv(&probe, body->keys[i], &copy);
        size_t sz = nc_json_size(&probe);
        json_free(&probe);
        if (sz <= data_budget) {
            (void)json_push_kv(acc, body->keys[i], &copy);
            included++;
            json_free(&copy);
        } else {
            json_free(&copy);
            truncated = true;
            /* A single field larger than the whole page budget must not stall
             * the cursor: advance past it and name it so the caller can fetch
             * it narrowly (a wider budget, --fields, or the command directly). */
            if (included == 0) {
                next_cursor = i + 1;
                oversize_key = body->keys[i];
            } else {
                next_cursor = i;
            }
            break;
        }
    }
    if (summary && omitted > 0)
        truncated = true;

    *included_out = included;
    *omitted_out = omitted;
    *next_cursor_out = next_cursor;
    *truncated_out = truncated;
    *oversize_key_out = oversize_key;
}

/* Build the `_page` descriptor zcl_native_bridge_project attaches to `acc`. */
static void nc_project_fields_build_page(
    const char *view, size_t total, size_t included, bool truncated,
    bool summary, size_t next_cursor, const char *oversize_key,
    struct json_value *page)
{
    json_init(page);
    json_set_object(page);
    (void)json_push_kv_str(page, "view", view);
    (void)json_push_kv_int(page, "total_fields", (int64_t)total);
    (void)json_push_kv_int(page, "included", (int64_t)included);
    (void)json_push_kv_bool(page, "truncated", truncated);
    if (truncated && !summary)
        (void)json_push_kv_int(page, "next_cursor", (int64_t)next_cursor);
    if (oversize_key)
        (void)json_push_kv_str(page, "skipped_oversize", oversize_key);
}

void zcl_native_bridge_project(const struct zcl_command_request *request,
                               const struct json_value *body,
                               struct zcl_command_reply *reply)
{
    if (body && body->type == JSON_ARR) {
        nc_project_array(request, body, reply);
        return;
    }
    if (!body || body->type != JSON_OBJ) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_TOOL_BODY",
                               "serialize", false, false,
                               "command returned an unsupported body shape",
                               request && request->spec
                                   ? request->spec->path : "");
        return;
    }
    const char *view = request->view && request->view[0] ? request->view
                                                          : "normal";
    bool summary = strcmp(view, "summary") == 0;
    bool full = strcmp(view, "full") == 0;
    size_t data_budget = nc_project_fields_data_budget(request);
    size_t start = nc_project_cursor_start(request, summary);
    size_t total = body->num_children;

    struct json_value acc;
    json_init(&acc);
    json_set_object(&acc);
    size_t included, omitted, next_cursor;
    bool truncated;
    const char *oversize_key;
    nc_project_fields_collect(request, body, start, summary, full,
                              data_budget, &acc, &included, &omitted,
                              &next_cursor, &truncated, &oversize_key);

    struct json_value page;
    nc_project_fields_build_page(view, total, included, truncated, summary,
                                 next_cursor, oversize_key, &page);
    (void)json_push_kv(&acc, "_page", &page);
    json_free(&page);

    json_free(&reply->data);
    json_init(&reply->data);
    json_copy(&reply->data, &acc);
    json_free(&acc);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;

    if (truncated)
        nc_add_describe_next(
            reply, request->spec->path,
            summary ? "inspect paging controls before retrieving full fields"
                    : "inspect paging controls before continuing these fields");
}

/* ── zcl_native_bridge_run pipeline ─────────────────────────────────── */

/* Resolve which of the two dispatch bindings (a resident body function, or a
 * direct JSON-RPC method) this leaf must use, matching the caller's own
 * `body` pointer. Fails the reply (NO_BRIDGE_BINDING) and returns false when
 * the two disagree. */
static bool nc_bridge_validate_binding(
    const struct zcl_command_request *request, zcl_native_body_fn body,
    const struct bridge_rpc_binding **rpc_binding_out,
    const char **rpc_method_out, struct zcl_command_reply *reply)
{
    zcl_native_body_fn resident_body =
        zcl_native_bridge_body_for_path(request->spec->path);
    const struct bridge_rpc_binding *rpc_binding =
        bridge_rpc_binding_for_path(request->spec->path);
    const char *rpc_method = rpc_binding ? rpc_binding->rpc_method : NULL;
    bool valid_binding = body ? (resident_body != NULL && rpc_method == NULL)
                              : (resident_body == NULL && rpc_method != NULL);
    *rpc_binding_out = rpc_binding;
    *rpc_method_out = rpc_method;
    if (!valid_binding) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "NO_BRIDGE_BINDING",
                               "dispatch", false, false,
                               body && rpc_method
                                   ? "ready leaf has ambiguous dispatch bindings"
                                   : "ready leaf has no dispatch binding",
                               request->spec->path);
        return false;
    }
    return true;
}

/* Map a failed body function's reported status to the reply's failure status
 * / exit code / retryability. A null RPC result (no body function) always
 * reports plain ZCL_COMMAND_STATUS_FAILED / EXIT_FAILED, set by the caller. */
static void nc_bridge_body_failure_kind(
    enum zcl_native_body_status status, enum zcl_command_status *status_out,
    enum zcl_command_exit *exit_out, bool *retryable_out)
{
    *status_out = ZCL_COMMAND_STATUS_FAILED;
    *exit_out = ZCL_COMMAND_EXIT_FAILED;
    *retryable_out = false;
    if (status == ZCL_NATIVE_BODY_UNAVAILABLE) {
        *status_out = ZCL_COMMAND_STATUS_BLOCKED;
        *exit_out = ZCL_COMMAND_EXIT_TRANSIENT;
        *retryable_out = true;
    } else if (status == ZCL_NATIVE_BODY_INVALID) {
        *exit_out = ZCL_COMMAND_EXIT_INVALID;
    } else if (status == ZCL_NATIVE_BODY_INTERNAL) {
        *exit_out = ZCL_COMMAND_EXIT_INTERNAL;
    } else if (status == ZCL_NATIVE_BODY_PROTOCOL) {
        *exit_out = ZCL_COMMAND_EXIT_FAILED;
    }
}

/* Dispatch through the supplied body function or the backing RPC. Fails the
 * reply and returns NULL on a null result (body error, or RPC returned
 * null); the caller frees a non-NULL result after use. */
static char *nc_bridge_dispatch(
    const struct zcl_command_request *request, zcl_native_body_fn body,
    const char *rpc_method, struct zcl_command_reply *reply)
{
    struct json_value translated;
    bool use_translated = false;
    if (!bridge_build_args(request->spec->path, request->input, &translated,
                           &use_translated)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                               "normalize", false, false,
                               "could not normalize leaf arguments",
                               request->spec->path);
        return NULL;
    }
    const struct json_value *args =
        use_translated ? &translated : request->input;

    struct zcl_native_body_err body_err = { 0 };
    char *result = body ? body(args, &body_err)
                        : node_rpc_call(rpc_method, NULL);
    if (use_translated)
        json_free(&translated);

    if (!result) {
        char msgbuf[224];
        const char *msg;
        enum zcl_command_status failure_status;
        enum zcl_command_exit failure_exit;
        bool retryable;
        if (body) {
            msg = body_err.message[0] ? body_err.message
                                      : "command handler reported an error";
            nc_bridge_body_failure_kind(body_err.status, &failure_status,
                                        &failure_exit, &retryable);
        } else {
            failure_status = ZCL_COMMAND_STATUS_FAILED;
            failure_exit = ZCL_COMMAND_EXIT_FAILED;
            retryable = false;
            (void)snprintf(msgbuf, sizeof(msgbuf), "RPC %s returned null",
                           rpc_method);
            msg = msgbuf;
        }
        zcl_command_reply_fail(reply, failure_status, failure_exit,
                               "TOOL_ERROR", "execute", retryable, false, msg,
                               request->spec->path);
        nc_add_describe_next(reply, request->spec->path,
                             "inspect this command before retrying");
        return NULL;
    }
    return result;
}

/* Parse `result` (freed either way) as JSON into `*body_doc`. Fails the
 * reply and returns false on an invalid document. */
static bool nc_bridge_parse_body(
    char *result, const struct zcl_command_request *request,
    struct zcl_command_reply *reply, struct json_value *body_doc)
{
    if (!json_read(body_doc, result, strlen(result))) {
        json_free(body_doc);
        free(result);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_TOOL_BODY",
                               "serialize", false, false,
                               "command returned an invalid JSON body",
                               request->spec->path);
        return false;
    }
    free(result);
    return true;
}

/* An RPC-shaped {"error":{...}} (or legacy bare-string error) body. Frees
 * `*body_doc` and fails the reply when present, returning true. */
static bool nc_bridge_check_rpc_error(
    struct json_value *body_doc, const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const struct json_value *err = body_doc->type == JSON_OBJ
                                       ? json_get(body_doc, "error") : NULL;
    if (body_doc->type != JSON_OBJ || !status_json_is_rpc_error(body_doc))
        return false;
    const char *msg = NULL;
    if (err && err->type == JSON_OBJ)
        msg = json_get_str(json_get(err, "message"));
    else if (err && err->type == JSON_STR)
        msg = json_get_str(err);
    else
        msg = json_get_str(json_get(body_doc, "message"));
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, "TOOL_ERROR",
                           "execute", false, false,
                           msg && msg[0] ? msg : "command reported an error",
                           request->spec->path);
    json_free(body_doc);
    return true;
}

/* Legacy diag RPC handlers report errors as a bare string body ("<cmd>:
 * <reason>", the json_set_str(result, ...) convention). A string body can
 * never be a success here — the body contract requires an object — so
 * surface the handler's own message as a typed TOOL_ERROR instead of an
 * opaque BAD_TOOL_BODY that hides it. Non-string non-objects stay
 * BAD_TOOL_BODY. Frees `*body_doc` and fails the reply either way; returns
 * true only when body_doc is already a JSON_OBJ (nothing to check here). */
static bool nc_bridge_check_legacy_body(
    bool have_body_fn, struct json_value *body_doc,
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!have_body_fn || body_doc->type == JSON_OBJ)
        return true;
    const char *legacy_msg = body_doc->type == JSON_STR
                                 ? json_get_str(body_doc) : NULL;
    if (legacy_msg && legacy_msg[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "TOOL_ERROR",
                               "execute", false, false, legacy_msg,
                               request->spec->path);
        json_free(body_doc);
        return false;
    }
    json_free(body_doc);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INTERNAL, "BAD_TOOL_BODY",
                           "serialize", false, false,
                           "command returned a non-object body",
                           request->spec->path);
    return false;
}

/* A direct-RPC leaf (no body function) validates its success body against
 * the resolved binding before it is trusted. Frees `*body_doc` and fails the
 * reply on an incompatible body. */
static bool nc_bridge_validate_direct_rpc(
    bool have_body_fn, const struct bridge_rpc_binding *rpc_binding,
    const char *rpc_method, struct json_value *body_doc,
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (have_body_fn)
        return true;
    char why[160];
    if (bridge_validate_rpc_success(rpc_binding, body_doc, why, sizeof(why)))
        return true;
    char msg[224];
    (void)snprintf(msg, sizeof(msg),
                   "RPC %s returned an incompatible success body: %s",
                   rpc_method ? rpc_method : "(unbound)", why);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, "TOOL_ERROR",
                           "execute", false, false, msg, request->spec->path);
    json_free(body_doc);
    return false;
}

/* Run a bridged leaf with an EXPLICIT body function — everything
 * zcl_native_bridge_command does after resolving the body pointer: build the
 * command arguments from the request, dispatch (the supplied body function, or —
 * when `body` is NULL and the leaf is a pure 1:1 proxy — the backing JSON-RPC
 * method directly), then project the resulting body into the reply envelope.
 * A hot-swap generation supplies its OWN freshly-compiled body here; the
 * ordinary registry path passes zcl_native_bridge_body_for_path(path). When
 * `body` is NULL and the path also has no direct-RPC binding (i.e. an unknown
 * / unbound path), this fails with the same NO_BRIDGE_BINDING reply the
 * pre-extraction code produced. */
void zcl_native_bridge_run(const struct zcl_command_request *request,
                           zcl_native_body_fn body,
                           struct zcl_command_reply *reply)
{
    if (!request || !request->spec || !reply)
        return;
    const struct bridge_rpc_binding *rpc_binding = NULL;
    const char *rpc_method = NULL;
    if (!nc_bridge_validate_binding(request, body, &rpc_binding, &rpc_method,
                                    reply))
        return;

    zcl_native_bridge_ensure_rpc();

    char *result = nc_bridge_dispatch(request, body, rpc_method, reply);
    if (!result)
        return;

    struct json_value body_doc;
    if (!nc_bridge_parse_body(result, request, reply, &body_doc))
        return;

    if (nc_bridge_check_rpc_error(&body_doc, request, reply))
        return;
    if (!nc_bridge_check_legacy_body(body != NULL, &body_doc, request, reply))
        return;
    if (!nc_bridge_validate_direct_rpc(body != NULL, rpc_binding, rpc_method,
                                       &body_doc, request, reply))
        return;

    /* Success: project the command body into the result envelope's data, bounded
     * by view + budget so a large read pages instead of overflowing (§8/§9). */
    zcl_native_bridge_project(request, &body_doc, reply);
    json_free(&body_doc);
}
