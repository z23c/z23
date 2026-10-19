/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: fleet.doctor - one read-only answer to "where is this node in
 *          fleet setup and what do I run next?".
 *
 * It composes reads that already exist and nothing else: the running node's
 * peer list and machine-identity capsule over the one-shot JSON-RPC client,
 * the fleet.machines roster, the fleet.nodes.table pairing store and the
 * fleet board wiki list. It never writes, never opens a key file itself,
 * and prints public fingerprints only: an unknown field of any source is
 * dropped, never copied. Every source is bounded: the node calls share one
 * six-second deadline, rosters and pairings are capped at 64 rows, the wiki
 * count at the board's own 256.
 *
 * OUTPUT (zcl.fleet_doctor.v1)
 *   schema, state (worst check state), next (first non-empty next command),
 *   checks[] {name, state, detail, next, warning?, informational?}, connected_peers,
 *   hybrid_peers, machines_total, machines_truncated, machines[] (names),
 *   pairings_total, pairings[] {peer_master_fingerprint, state, expires_at},
 *   wiki_pages, noise_fingerprint_sha3.
 *
 * state is ok | missing | blocked | unknown. A check that needs the running
 * node is "blocked" while no node answers, never guessed. */

#include "command/native_command.h"
#include "command/native_fleet.h"

#include "config/command_catalog.h"
#include "controllers/network_controller.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FD_ROWS_MAX 64
#define FD_NODE_BUDGET_MS 6000
#define FD_CONNECT_MS 1000
#define FD_WARN_SECONDS (24 * 3600)
#define FD_TEXT 256

#define FD_NEXT_NODE "z23 core status"
#define FD_NEXT_IDENTITY "z23 ops mesh identity"
#define FD_NEXT_ENROL "z23 fleet invite --name=<box>"
#define FD_NEXT_DELEGATE "z23 zcode network delegate"
#define FD_NEXT_DELEGATE_MISSING "anchor the master key first (z23 core identity anchor, once the node folds it), then z23 zcode network delegate with seed_file while the node runs"
#define FD_NEXT_PAIR "z23 ops mesh pair plan --peer=<addr-or-fingerprint-prefix>"
#define FD_NEXT_ROSTER "z23 ops mesh roster"
#define FD_NEXT_MAIL "z23-dev dev agent mail"
#define FD_NEXT_WIKI "z23 fleet wiki write"

struct fd_sub {
    struct json_value args;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
    bool ran;
};

struct fd_ctx {
    int64_t now;
    int64_t deadline;
    bool node_up;
    int64_t peers;
    int64_t hybrid;
    bool ident_seen;
    bool noise_enabled;
    bool identity_loaded;
    bool dht_observed;
    bool dht_enabled;
    char dht_reason[96];
    char fingerprint[65];
    struct fd_sub machines;
    struct fd_sub pairs;
    int64_t wiki_pages;
    bool wiki_ok;
    int worst;
    char next[FD_TEXT];
};

/* ── JSON readers that never trust a source's shape ──────────────────── */

static const char *fd_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : "";
}

static int64_t fd_int(const struct json_value *obj, const char *key,
                      int64_t dflt)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : dflt;
}

static bool fd_bool(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static bool fd_hex64(const char *s)
{
    if (strlen(s) != 64)
        return false;
    for (size_t i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

/* One node call under the shared deadline. The parsed value is the bare
 * JSON-RPC result; false when nothing parseable came back. */
static bool fd_rpc(const struct fd_ctx *ctx, const char *method,
                   const char *params, struct json_value *out)
{
    char *raw = node_rpc_call_until(method, params, FD_CONNECT_MS,
                                    ctx->deadline);
    if (!raw)
        return false;
    json_init(out);
    bool parsed = json_read(out, raw, strlen(raw));
    free(raw);
    if (!parsed)
        json_free(out);
    return parsed;
}

/* ── sources ─────────────────────────────────────────────────────────── */

/* getpeerinfo answers an array when a node is up; anything else (a
 * connection stub, an auth error) means no node answered. */
static void fd_gather_peers(struct fd_ctx *ctx)
{
    struct json_value body;
    const char *hybrid = network_peer_transport_name(PEER_TRANSPORT_NOISE_XXHFS);
    if (!fd_rpc(ctx, "getpeerinfo", "[]", &body))
        return;
    if (body.type == JSON_ARR) {
        ctx->node_up = true;
        ctx->peers = (int64_t)body.num_children;
        for (size_t i = 0; i < body.num_children; i++)
            if (strcmp(fd_str(&body.children[i], "transport"), hybrid) == 0)
                ctx->hybrid++;
    }
    json_free(&body);
}

static void fd_read_dht(struct fd_ctx *ctx, const struct json_value *state)
{
    const struct json_value *dht = json_get(state, "authenticated_dht");
    ctx->dht_observed = fd_bool(dht, "observed");
    ctx->dht_enabled = fd_bool(dht, "enabled");
    (void)snprintf(ctx->dht_reason, sizeof(ctx->dht_reason), "%s",
                   fd_str(dht, "disabled_reason"));
}

static void fd_gather_identity(struct fd_ctx *ctx)
{
    struct json_value body;
    if (!ctx->node_up ||
        !fd_rpc(ctx, "dumpstate", "[\"machine_identity\"]", &body))
        return;
    const struct json_value *state = json_get(&body, "state");
    const struct json_value *transport =
        state ? json_get(state, "transport") : NULL;
    if (state && state->type == JSON_OBJ && transport) {
        ctx->ident_seen = fd_bool(transport, "observed");
        ctx->noise_enabled = fd_bool(transport, "noise_enabled");
        ctx->identity_loaded = fd_bool(transport, "identity_loaded");
        const char *fp = fd_str(transport, "local_noise_fingerprint_sha3");
        if (fd_hex64(fp))
            (void)snprintf(ctx->fingerprint, sizeof(ctx->fingerprint), "%s", fp);
        fd_read_dht(ctx, state);
    }
    json_free(&body);
}

static void fd_gather_wiki(struct fd_ctx *ctx)
{
    struct json_value body;
    if (!ctx->node_up ||
        !fd_rpc(ctx, "fleet_board", "[{\"op\":\"wiki_list\"}]", &body))
        return;
    const struct json_value *ret = json_get(&body, "returned");
    if (fd_bool(&body, "ok") && ret && ret->type == JSON_INT) {
        ctx->wiki_ok = true;
        ctx->wiki_pages = json_get_int(ret);
    }
    json_free(&body);
}

/* Runs one sibling leaf in-process with its own spec, exactly as dispatch
 * would, and keeps the reply for the check that reads it. */
static void fd_sub_run(struct fd_sub *s, const struct zcl_command_request *parent,
                       const char *path, const char *schema, int64_t limit)
{
    json_init(&s->args);
    json_set_object(&s->args);
    memset(&s->request, 0, sizeof(s->request));
    zcl_command_reply_init(&s->reply, schema);
    const char *datadir = fd_str(parent ? parent->input : NULL, "datadir");
    if (limit > 0)
        (void)json_push_kv_int(&s->args, "limit", limit);
    if (datadir[0] && strcmp(path, "fleet.nodes.table") == 0)
        (void)json_push_kv_str(&s->args, "datadir", datadir);
    s->request.input = &s->args;
    s->request.context = parent ? parent->context : NULL;
    s->request.view = "normal";
    s->request.spec = zcl_command_registry_find(zcl_command_catalog(), path,
                                                NULL);
    if (!s->request.spec || !s->request.spec->handler)
        return;
    s->request.spec->handler(&s->request, &s->reply);
    s->ran = true;
}

static void fd_sub_free(struct fd_sub *s)
{
    zcl_command_reply_free(&s->reply);
    json_free(&s->args);
}

static bool fd_sub_ok(const struct fd_sub *s)
{
    return s->ran && s->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

/* ── check assembly ──────────────────────────────────────────────────── */

static int fd_rank(const char *state)
{
    if (strcmp(state, "blocked") == 0)
        return 3;
    if (strcmp(state, "missing") == 0)
        return 2;
    if (strcmp(state, "unknown") == 0)
        return 1;
    return 0;
}

static void fd_check(struct fd_ctx *ctx, struct json_value *checks,
                     const char *name, const char *state, const char *detail,
                     const char *next, const char *warning)
{
    /* Mail is a developer tool: shown, never rolled into state or next. */
    bool info = strcmp(name, "mail") == 0;
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "name", name);
    (void)json_push_kv_str(&row, "state", state);
    (void)json_push_kv_str(&row, "detail", detail);
    (void)json_push_kv_str(&row, "next", next);
    if (info)
        (void)json_push_kv_bool(&row, "informational", true);
    if (warning && warning[0])
        (void)json_push_kv_str(&row, "warning", warning);
    (void)json_push_back(checks, &row);
    json_free(&row);
    if (info)
        return;
    if (fd_rank(state) > ctx->worst)
        ctx->worst = fd_rank(state);
    if (!ctx->next[0] && next[0])
        (void)snprintf(ctx->next, sizeof(ctx->next), "%s", next);
}

/* A check that needs the running node, while none answers. */
static bool fd_needs_node(struct fd_ctx *ctx, struct json_value *checks,
                          const char *name)
{
    if (ctx->node_up)
        return false;
    fd_check(ctx, checks, name, "blocked",
             "This needs a running node, and none answered.", FD_NEXT_NODE,
             NULL);
    return true;
}

static void fd_check_node(struct fd_ctx *ctx, struct json_value *checks)
{
    if (ctx->node_up)
        fd_check(ctx, checks, "node", "ok", "A node is running and answered.",
                 "", NULL);
    else
        fd_check(ctx, checks, "node", "blocked",
                 "No node answered; start the node, then inspect it.",
                 FD_NEXT_NODE, NULL);
}

static void fd_check_identity(struct fd_ctx *ctx, struct json_value *checks)
{
    if (fd_needs_node(ctx, checks, "identity"))
        return;
    if (ctx->identity_loaded && ctx->fingerprint[0])
        fd_check(ctx, checks, "identity", "ok",
                 "This node has a Noise identity; its public fingerprint is "
                 "in noise_fingerprint_sha3.",
                 "", NULL);
    else
        fd_check(ctx, checks, "identity", "missing",
                 "This node has no loaded Noise identity yet.",
                 FD_NEXT_IDENTITY, NULL);
}

static void fd_check_membership(struct fd_ctx *ctx, struct json_value *checks)
{
    const struct json_value *d = &ctx->machines.reply.data;
    char detail[FD_TEXT];
    if (!fd_sub_ok(&ctx->machines)) {
        fd_check(ctx, checks, "membership", "blocked",
                 "This box could not read its fleet roster.",
                 "z23 fleet machines", NULL);
        return;
    }
    int64_t total = fd_int(d, "total", 0);
    if (fd_bool(d, "joined") || total > 0) {
        (void)snprintf(detail, sizeof(detail),
                       "In a fleet: %s, %lld machine(s) on this roster.",
                       fd_bool(d, "joined") ? "this box joined one"
                                            : "this box is the manager",
                       (long long)total);
        fd_check(ctx, checks, "membership", "ok", detail, "", NULL);
        return;
    }
    fd_check(ctx, checks, "membership", "missing",
             "This box is not in a fleet and has admitted no machine.",
             FD_NEXT_ENROL, NULL);
}

/* Count of active recorded pairings and the soonest of their expiries (0
 * when none carries one). */
static int64_t fd_active_pairings(const struct fd_ctx *ctx, int64_t *soonest)
{
    const struct json_value *rows = json_get(&ctx->pairs.reply.data, "rows");
    int64_t active = 0;
    *soonest = 0;
    for (size_t i = 0; rows && rows->type == JSON_ARR && i < rows->num_children;
         i++) {
        const struct json_value *ps = json_get(&rows->children[i], "pairings");
        for (size_t j = 0; ps && ps->type == JSON_ARR && j < ps->num_children;
             j++) {
            int64_t at = fd_int(&ps->children[j], "expires_at", 0);
            if (strcmp(fd_str(&ps->children[j], "state"), "active") != 0)
                continue;
            active++;
            if (at > 0 && (*soonest == 0 || at < *soonest))
                *soonest = at;
        }
    }
    return active;
}

static void fd_delegation_warning(const struct fd_ctx *ctx, char *out,
                                  size_t cap)
{
    int64_t soonest = 0;
    out[0] = '\0';
    (void)fd_active_pairings(ctx, &soonest);
    if (soonest > 0 && soonest - ctx->now < FD_WARN_SECONDS) {
        int64_t left = soonest - ctx->now;
        (void)snprintf(out, cap,
                       "The soonest active pairing expires in %lld hour(s); "
                       "renew the delegation before then.",
                       (long long)(left > 0 ? left / 3600 : 0));
    }
}

static void fd_check_delegation(struct fd_ctx *ctx, struct json_value *checks)
{
    char warning[FD_TEXT], detail[FD_TEXT];
    if (fd_needs_node(ctx, checks, "delegation"))
        return;
    if (!ctx->dht_observed) {
        fd_check(ctx, checks, "delegation", "unknown",
                 "The node did not report its ZID delegation state.",
                 FD_NEXT_DELEGATE, NULL);
        return;
    }
    if (!ctx->dht_enabled) {
        (void)snprintf(detail, sizeof(detail),
                       "No ZID delegation is loaded (%s).",
                       ctx->dht_reason[0] ? ctx->dht_reason : "DHT is off");
        fd_check(ctx, checks, "delegation", "missing", detail,
                 FD_NEXT_DELEGATE_MISSING, NULL);
        return;
    }
    fd_delegation_warning(ctx, warning, sizeof(warning));
    fd_check(ctx, checks, "delegation", "ok",
             "A ZID delegation is loaded; no read exposes its own expiry, so "
             "the warning follows the soonest active pairing.",
             "", warning);
}

static void fd_check_transport(struct fd_ctx *ctx, struct json_value *checks)
{
    char detail[FD_TEXT];
    if (fd_needs_node(ctx, checks, "transport"))
        return;
    if (!ctx->noise_enabled) {
        fd_check(ctx, checks, "transport", "missing",
                 "Noise hybrid transport is off on this node.",
                 FD_NEXT_IDENTITY, NULL);
        return;
    }
    (void)snprintf(detail, sizeof(detail),
                   "Noise hybrid transport is on; %lld of %lld connected "
                   "peer(s) use it.",
                   (long long)ctx->hybrid, (long long)ctx->peers);
    fd_check(ctx, checks, "transport", "ok", detail, "", NULL);
}

static void fd_check_pairing(struct fd_ctx *ctx, struct json_value *checks)
{
    const struct fd_sub *s = &ctx->pairs;
    char detail[FD_TEXT];
    if (!fd_sub_ok(s)) {
        const char *code = s->reply.error.code;
        if (strstr(code, "TOO_LARGE"))
            fd_check(ctx, checks, "pairing", "unknown",
                     "More than 64 pairings are recorded; page them instead.",
                     FD_NEXT_ROSTER, NULL);
        else
            fd_check(ctx, checks, "pairing", "missing",
                     "This box has no mesh pairing store yet.", FD_NEXT_PAIR,
                     NULL);
        return;
    }
    int64_t total = fd_int(&s->reply.data, "pairing_count", 0);
    int64_t soonest = 0;
    int64_t active = fd_active_pairings(ctx, &soonest);
    if (active > 0) {
        (void)snprintf(detail, sizeof(detail),
                       "%lld pairing(s) recorded, %lld active.",
                       (long long)total, (long long)active);
        fd_check(ctx, checks, "pairing", "ok", detail, "", NULL);
        return;
    }
    fd_check(ctx, checks, "pairing", "missing",
             total > 0 ? "Every recorded pairing is expired or revoked."
                       : "No machine is paired with this node.",
             FD_NEXT_PAIR, NULL);
}

/* A pairing store that exists but cannot be read is refused by name, never
 * folded into a check: only an absent store, a missing datadir or an
 * over-large table are states the doctor reports. */
static bool fd_pairing_unreadable(const struct fd_ctx *ctx)
{
    const char *code = ctx->pairs.reply.error.code;
    if (fd_sub_ok(&ctx->pairs) || !ctx->pairs.ran)
        return false;
    return !(strstr(code, "TOO_LARGE") || strstr(code, "UNAVAILABLE") ||
             strstr(code, "DATADIR"));
}

static void fd_check_mail(struct fd_ctx *ctx, struct json_value *checks)
{
    fd_check(ctx, checks, "mail", "unknown",
             "The agent mail store is a developer tool, not part of the "
             "product binary, so it is not read here.",
             FD_NEXT_MAIL, NULL);
}

static void fd_check_wiki(struct fd_ctx *ctx, struct json_value *checks)
{
    char detail[FD_TEXT];
    if (fd_needs_node(ctx, checks, "wiki"))
        return;
    if (!ctx->wiki_ok) {
        fd_check(ctx, checks, "wiki", "unknown",
                 "The node did not answer the wiki list.", "z23 fleet wiki list",
                 NULL);
        return;
    }
    (void)snprintf(detail, sizeof(detail), "This node holds %lld wiki page(s).",
                   (long long)ctx->wiki_pages);
    if (ctx->wiki_pages > 0)
        fd_check(ctx, checks, "wiki", "ok", detail, "", NULL);
    else
        fd_check(ctx, checks, "wiki", "missing", detail, FD_NEXT_WIKI, NULL);
}

/* ── bounded row lists ───────────────────────────────────────────────── */

static void fd_push_machines(const struct fd_ctx *ctx, struct json_value *out)
{
    struct json_value names;
    const struct json_value *rows = json_get(&ctx->machines.reply.data,
                                             "machines");
    json_init(&names);
    json_set_array(&names);
    for (size_t i = 0; rows && rows->type == JSON_ARR &&
                       i < rows->num_children && i < FD_ROWS_MAX; i++) {
        struct json_value name;
        json_init(&name);
        json_set_str(&name, fd_str(json_get(&rows->children[i], "verified"),
                                   "name"));
        (void)json_push_back(&names, &name);
        json_free(&name);
    }
    (void)json_push_kv(out, "machines", &names);
    json_free(&names);
}

static void fd_push_pair_row(struct json_value *list, const char *fingerprint,
                             const struct json_value *pairing)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "peer_master_fingerprint", fingerprint);
    (void)json_push_kv_str(&row, "state", fd_str(pairing, "state"));
    (void)json_push_kv_int(&row, "expires_at", fd_int(pairing, "expires_at", 0));
    (void)json_push_back(list, &row);
    json_free(&row);
}

static void fd_push_pairings(const struct fd_ctx *ctx, struct json_value *out)
{
    struct json_value list;
    const struct json_value *rows = json_get(&ctx->pairs.reply.data, "rows");
    size_t emitted = 0;
    json_init(&list);
    json_set_array(&list);
    for (size_t i = 0; rows && rows->type == JSON_ARR && i < rows->num_children;
         i++) {
        const struct json_value *ps = json_get(&rows->children[i], "pairings");
        const char *fp = fd_str(&rows->children[i], "peer_master_fingerprint");
        for (size_t j = 0; ps && ps->type == JSON_ARR &&
                           j < ps->num_children && emitted < FD_ROWS_MAX; j++) {
            fd_push_pair_row(&list, fp, &ps->children[j]);
            emitted++;
        }
    }
    (void)json_push_kv(out, "pairings", &list);
    json_free(&list);
}

static void fd_emit(struct fd_ctx *ctx, struct json_value *checks,
                    struct json_value *out)
{
    static const char *const states[] = { "ok", "unknown", "missing",
                                          "blocked" };
    const struct json_value *m = &ctx->machines.reply.data;
    (void)json_push_kv_str(out, "schema", "zcl.fleet_doctor.v1");
    (void)json_push_kv_str(out, "state", states[ctx->worst]);
    (void)json_push_kv_str(out, "next", ctx->next);
    (void)json_push_kv(out, "checks", checks);
    (void)json_push_kv_int(out, "connected_peers", ctx->peers);
    (void)json_push_kv_int(out, "hybrid_peers", ctx->hybrid);
    (void)json_push_kv_int(out, "machines_total", fd_int(m, "total", 0));
    (void)json_push_kv_bool(out, "machines_truncated", fd_bool(m, "truncated"));
    fd_push_machines(ctx, out);
    (void)json_push_kv_int(out, "pairings_total",
                           fd_int(&ctx->pairs.reply.data, "pairing_count", 0));
    fd_push_pairings(ctx, out);
    (void)json_push_kv_int(out, "wiki_pages", ctx->wiki_ok ? ctx->wiki_pages : 0);
    (void)json_push_kv_str(out, "noise_fingerprint_sha3", ctx->fingerprint);
}

void zcl_native_handle_fleet_doctor(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    struct fd_ctx ctx;
    struct json_value checks;
    if (!reply)
        return;
    memset(&ctx, 0, sizeof(ctx));
    ctx.now = platform_time_wall_unix();
    zcl_native_bridge_ensure_rpc();
    ctx.deadline = platform_time_monotonic_ms() + FD_NODE_BUDGET_MS;
    fd_gather_peers(&ctx);
    fd_gather_identity(&ctx);
    fd_gather_wiki(&ctx);
    fd_sub_run(&ctx.machines, request, "fleet.machines", "zcl.fleet.machines.v1",
               FD_ROWS_MAX);
    fd_sub_run(&ctx.pairs, request, "fleet.nodes.table",
               "zcl.fleet_nodes_table.v1", 0);
    if (fd_pairing_unreadable(&ctx)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED,
                               "FLEET_DOCTOR_PAIRING_UNREADABLE", "read",
                               false, false,
                               "the mesh pairing store exists but cannot be "
                               "read; inspect it with `z23 ops mesh pair "
                               "list`",
                               ctx.pairs.reply.error.code);
        fd_sub_free(&ctx.machines);
        fd_sub_free(&ctx.pairs);
        return;
    }
    json_init(&checks);
    json_set_array(&checks);
    fd_check_node(&ctx, &checks);
    fd_check_identity(&ctx, &checks);
    fd_check_membership(&ctx, &checks);
    fd_check_delegation(&ctx, &checks);
    fd_check_transport(&ctx, &checks);
    fd_check_pairing(&ctx, &checks);
    fd_check_mail(&ctx, &checks);
    fd_check_wiki(&ctx, &checks);
    fd_emit(&ctx, &checks, &reply->data);
    json_free(&checks);
    fd_sub_free(&ctx.machines);
    fd_sub_free(&ctx.pairs);
}
