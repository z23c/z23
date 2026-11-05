/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * network sibling: the operator ban surface (listbanned, setban add/remove,
 * clearbanned). Each scenario builds an isolated connman with its own
 * datadir, bans through core where the scenario needs a ban in place, drives
 * the RPCs, and checks both the RPC answer and what banlist.dat holds on disk.
 */

#include "test/syncdiag_rpc_fixture.h"
#include "test/test_syncdiag_network_priv.h"

#include "net/netbase.h"

#define BANS_PEER_A "203.0.113.9"
#define BANS_PEER_B "198.51.100.4"
#define BANS_PEER_EXPIRED "192.0.2.77"

struct sd_bans_ctx {
    struct connman cm;
    struct node_signals sigs;
    struct rpc_table tbl;
    struct json_value params;
    struct json_value result;
    char dir_template[PATH_MAX];
    char *dir;
};

static bool sd_bans_setup(struct sd_bans_ctx *ctx)
{
    chain_params_select(CHAIN_MAIN);
    memset(&ctx->cm, 0, sizeof(ctx->cm));
    memset(&ctx->sigs, 0, sizeof(ctx->sigs));
    ctx->dir = test_mkdtemp(ctx->dir_template, sizeof(ctx->dir_template),
                            "zcl-bans");
    bool ok = ctx->dir != NULL &&
              connman_init(&ctx->cm, chain_params_get(), &ctx->sigs);
    if (ok) {
        ctx->cm.manager.datadir = ctx->dir;
        rpc_table_init(&ctx->tbl);
        register_net_rpc_commands(&ctx->tbl);
        rpc_net_set_connman(&ctx->cm);
    }
    json_init(&ctx->params);
    json_init(&ctx->result);
    return ok;
}

static bool sd_bans_teardown(struct sd_bans_ctx *ctx, bool ok)
{
    json_free(&ctx->params);
    json_free(&ctx->result);
    rpc_net_set_connman(NULL);
    connman_free(&ctx->cm);
    return ok;
}

/* Runs one RPC with up to three string params; NULL means "omitted". The
 * result is left in ctx->result (a JSON string holds the error on failure). */
static bool sd_bans_call(struct sd_bans_ctx *ctx, const char *method,
                         const char *a, const char *b, const char *c)
{
    const char *args[3] = { a, b, c };
    json_free(&ctx->params);
    json_init(&ctx->params);
    json_set_array(&ctx->params);
    json_free(&ctx->result);
    json_init(&ctx->result);
    for (size_t i = 0; i < 3 && args[i]; i++) {
        struct json_value v;
        json_init(&v);
        json_set_str(&v, args[i]);
        json_push_back(&ctx->params, &v);
        json_free(&v);
    }
    return rpc_table_execute(&ctx->tbl, method, &ctx->params, &ctx->result);
}

static bool sd_bans_error_has(const struct json_value *result,
                              const char *needle)
{
    return result->type == JSON_STR &&
           strstr(json_get_str(result), needle) != NULL;
}

/* Lists the bans over RPC. Returns false when listbanned itself fails. */
static bool sd_bans_list(struct sd_bans_ctx *ctx, size_t *count_out)
{
    bool ok = sd_bans_call(ctx, "listbanned", NULL, NULL, NULL);
    ok = ok && ctx->result.type == JSON_ARR;
    *count_out = ok ? json_size(&ctx->result) : 0;
    return ok;
}

/* Reports whether an entry for addr is listed. Returns false when the RPC
 * itself fails, so "not listed" is never mistaken for a broken listing. */
static bool sd_bans_list_has(struct sd_bans_ctx *ctx, const char *addr,
                             bool *found)
{
    size_t n = 0;
    *found = false;
    if (!sd_bans_list(ctx, &n))
        return false;
    for (size_t i = 0; i < n; i++) {
        const struct json_value *entry = json_at(&ctx->result, i);
        const struct json_value *address = json_get(entry, "address");
        if (address && json_get_str(address) &&
            strcmp(json_get_str(address), addr) == 0)
            *found = true;
    }
    return true;
}

/* Number of entries banlist.dat holds, or -1 when it cannot be read. */
static int sd_bans_disk_count(const char *dir)
{
    struct net_manager nm;
    net_manager_init(&nm);
    int n = ban_db_read(&nm, dir) ? (int)nm.num_banned : -1;
    net_manager_free(&nm);
    return n;
}

static bool sd_bans_addr(const struct sd_bans_ctx *ctx, const char *text,
                         struct net_addr *out)
{
    struct net_service svc;
    if (!lookup_numeric(text, &svc, ctx->cm.manager.default_port))
        return false;
    *out = svc.addr;
    return true;
}

/* The one listed row (the ban on BANS_PEER_A) carries a manual reason and a
 * future expiry. Expects the listbanned result already in ctx->result. */
static bool sd_bans_listed_fields(const struct sd_bans_ctx *ctx)
{
    size_t n = json_size(&ctx->result);
    const struct json_value *first = n > 0 ? json_at(&ctx->result, 0) : NULL;
    const struct json_value *reason = first ? json_get(first, "ban_reason")
                                            : NULL;
    const struct json_value *until = first ? json_get(first, "banned_until")
                                           : NULL;
    return reason && strcmp(json_get_str(reason), "manual") == 0 &&
           until && json_get_int(until) > 0;
}

/* A core ban on BANS_PEER_A is listed once, with its fields, and on disk. */
static bool sd_bans_listed_once(struct sd_bans_ctx *ctx)
{
    bool found = false;
    bool ok = sd_bans_list_has(ctx, BANS_PEER_A, &found) && found;
    return ok && sd_bans_disk_count(ctx->dir) == 1 &&
           sd_bans_listed_fields(ctx);
}

/* setban remove lifts the ban from the core table, the listing and disk. */
static bool sd_bans_lift_check(struct sd_bans_ctx *ctx,
                               const struct net_addr *addr)
{
    bool found = true;
    bool ok = sd_bans_call(ctx, "setban", BANS_PEER_A, "remove", NULL) &&
              ctx->result.type == JSON_NULL;
    ok = ok && !is_banned(&ctx->cm.manager, addr);
    ok = ok && sd_bans_list_has(ctx, BANS_PEER_A, &found) && !found;
    return ok && sd_bans_disk_count(ctx->dir) == 0;
}

static bool sd_bans_second_remove_refused(struct sd_bans_ctx *ctx)
{
    return !sd_bans_call(ctx, "setban", BANS_PEER_A, "remove", NULL) &&
           sd_bans_error_has(&ctx->result, "not found");
}

/* case: a core ban is listed with its reason, setban remove lifts it from the
 * table and from banlist.dat, and a second remove reports "not found". */
bool sd_bans_listbanned_remove_scenario(void)
{
    struct sd_bans_ctx ctx;
    bool ok = sd_bans_setup(&ctx);
    struct net_addr addr;
    ok = ok && sd_bans_addr(&ctx, BANS_PEER_A, &addr);
    if (ok)
        ban_addr(&ctx.cm.manager, &addr, 0, false);
    ok = ok && is_banned(&ctx.cm.manager, &addr) && sd_bans_listed_once(&ctx);
    ok = ok && sd_bans_lift_check(&ctx, &addr);
    ok = ok && sd_bans_second_remove_refused(&ctx);
    return sd_bans_teardown(&ctx, ok);
}

/* setban add bans a numeric address through core and persists it; a repeat
 * add refreshes the same row. */
static bool sd_bans_add_check(struct sd_bans_ctx *ctx,
                              const struct net_addr *addr)
{
    bool ok = sd_bans_call(ctx, "setban", BANS_PEER_B, "add", NULL) &&
              ctx->result.type == JSON_NULL;
    ok = ok && is_banned(&ctx->cm.manager, addr);
    ok = ok && sd_bans_disk_count(ctx->dir) == 1;
    ok = ok && sd_bans_call(ctx, "setban", BANS_PEER_B, "add", "3600");
    return ok && sd_bans_disk_count(ctx->dir) == 1;
}

/* Bad input each returns an RPC error and changes nothing. */
static bool sd_bans_add_errors_refused(struct sd_bans_ctx *ctx)
{
    bool ok = !sd_bans_call(ctx, "setban", BANS_PEER_B, "bogus", NULL);
    ok = ok && sd_bans_error_has(&ctx->result, "add or remove");
    ok = ok && !sd_bans_call(ctx, "setban", "not-an-ip", "add", NULL);
    ok = ok && sd_bans_error_has(&ctx->result, "numeric IP");
    ok = ok && !sd_bans_call(ctx, "setban", "example.onion", "add", NULL);
    ok = ok && sd_bans_error_has(&ctx->result, "numeric IP");
    ok = ok && !sd_bans_call(ctx, "setban", BANS_PEER_A, "add", "-5");
    ok = ok && sd_bans_error_has(&ctx->result, "negative");
    return ok && !sd_bans_call(ctx, "setban", BANS_PEER_A, NULL, NULL) &&
           ctx->result.type == JSON_STR;
}

/* case: setban add bans a numeric address through core and persists it; a
 * bad address, an unknown command, a negative bantime and a missing argument
 * each return an RPC error and change nothing. */
bool sd_bans_setban_add_scenario(void)
{
    struct sd_bans_ctx ctx;
    bool ok = sd_bans_setup(&ctx);
    struct net_addr addr;
    struct net_addr other;
    ok = ok && sd_bans_addr(&ctx, BANS_PEER_B, &addr);
    ok = ok && sd_bans_add_check(&ctx, &addr);
    ok = ok && sd_bans_add_errors_refused(&ctx);
    ok = ok && sd_bans_addr(&ctx, BANS_PEER_A, &other);
    ok = ok && !is_banned(&ctx.cm.manager, &other);
    return sd_bans_teardown(&ctx, ok);
}

/* Seeds two live bans and one ban that ended long ago, then checks that
 * listbanned reports exactly the two live ones. */
static bool sd_bans_seed_three(struct sd_bans_ctx *ctx,
                               const struct net_addr *a,
                               const struct net_addr *b,
                               const struct net_addr *expired)
{
    ban_addr(&ctx->cm.manager, a, 0, false);
    ban_addr(&ctx->cm.manager, b, 0, false);
    /* An offset of 1 since the epoch is a ban that ended long ago. */
    ban_addr(&ctx->cm.manager, expired, 1, true);
    size_t n = 0;
    return sd_bans_list(ctx, &n) && n == 2;
}

/* clearbanned empties the core table, the listing and banlist.dat. */
static bool sd_bans_clear_check(struct sd_bans_ctx *ctx,
                                const struct net_addr *a,
                                const struct net_addr *b)
{
    bool ok = sd_bans_call(ctx, "clearbanned", NULL, NULL, NULL) &&
              ctx->result.type == JSON_NULL;
    size_t n = 1;
    ok = ok && sd_bans_list(ctx, &n) && n == 0;
    ok = ok && !is_banned(&ctx->cm.manager, a);
    ok = ok && !is_banned(&ctx->cm.manager, b);
    return ok && sd_bans_disk_count(ctx->dir) == 0;
}

/* case: clearbanned empties the table and banlist.dat, is idempotent on an
 * empty table, and listbanned never reports an entry whose ban has expired. */
bool sd_bans_clearbanned_scenario(void)
{
    struct sd_bans_ctx ctx;
    bool ok = sd_bans_setup(&ctx);
    struct net_addr a;
    struct net_addr b;
    struct net_addr expired;
    ok = ok && sd_bans_addr(&ctx, BANS_PEER_A, &a);
    ok = ok && sd_bans_addr(&ctx, BANS_PEER_B, &b);
    ok = ok && sd_bans_addr(&ctx, BANS_PEER_EXPIRED, &expired);
    ok = ok && sd_bans_seed_three(&ctx, &a, &b, &expired);
    ok = ok && sd_bans_clear_check(&ctx, &a, &b);
    ok = ok && sd_bans_call(&ctx, "clearbanned", NULL, NULL, NULL);
    ok = ok && ctx.result.type == JSON_NULL;
    return sd_bans_teardown(&ctx, ok);
}

/* case: a bantime past the cap (a year-2038-style huge value that would wrap
 * GetTime() + offset) is refused, and bans nothing. */
bool sd_bans_overflow_bantime_scenario(void)
{
    struct sd_bans_ctx ctx;
    bool ok = sd_bans_setup(&ctx);
    struct net_addr addr;
    ok = ok && sd_bans_addr(&ctx, BANS_PEER_B, &addr);
    ok = ok && !sd_bans_call(&ctx, "setban", BANS_PEER_B, "add",
                             "9223372036854775807");
    ok = ok && sd_bans_error_has(&ctx.result, "too large");
    ok = ok && !is_banned(&ctx.cm.manager, &addr);
    ok = ok && sd_bans_disk_count(ctx.dir) != 1;
    return sd_bans_teardown(&ctx, ok);
}

/* case: a bantime that is not a whole number of seconds is refused rather
 * than read as 0 (which would silently mean the 24h default). */
bool sd_bans_nonnumeric_bantime_scenario(void)
{
    struct sd_bans_ctx ctx;
    bool ok = sd_bans_setup(&ctx);
    struct net_addr addr;
    ok = ok && sd_bans_addr(&ctx, BANS_PEER_B, &addr);
    ok = ok && !sd_bans_call(&ctx, "setban", BANS_PEER_B, "add", "abc");
    ok = ok && sd_bans_error_has(&ctx.result, "whole number");
    ok = ok && !sd_bans_call(&ctx, "setban", BANS_PEER_B, "add", "12abc");
    ok = ok && sd_bans_error_has(&ctx.result, "whole number");
    ok = ok && !is_banned(&ctx.cm.manager, &addr);
    return sd_bans_teardown(&ctx, ok);
}

/* case: setban add on a loopback address is refused, because core never bans
 * localhost and a success reply would be a silent no-op. */
bool sd_bans_loopback_add_scenario(void)
{
    struct sd_bans_ctx ctx;
    bool ok = sd_bans_setup(&ctx);
    ok = ok && !sd_bans_call(&ctx, "setban", "127.0.0.1", "add", NULL);
    ok = ok && sd_bans_error_has(&ctx.result, "loopback");
    ok = ok && sd_bans_disk_count(ctx.dir) != 1;
    return sd_bans_teardown(&ctx, ok);
}

/* Makes the scenario datadir unwritable. Returns false when a write still
 * lands (a privileged runner), so the caller skips instead of failing. */
static bool sd_bans_lock_datadir(struct sd_bans_ctx *ctx)
{
    if (chmod(ctx->dir, 0500) != 0)
        return false;
    return !ban_db_write(&ctx->cm.manager, ctx->dir);
}

static bool sd_bans_unsaved_remove_check(struct sd_bans_ctx *ctx,
                                         const struct net_addr *addr)
{
    bool refused = !sd_bans_call(ctx, "setban", BANS_PEER_B, "remove", NULL);
    return refused && sd_bans_error_has(&ctx->result, "not saved") &&
           !is_banned(&ctx->cm.manager, addr);
}

/* case: setban add when banlist.dat cannot be written must not answer plain
 * success. The ban is live in memory, so the error says it is not saved; a
 * remove that cannot be saved is reported the same way. */
bool sd_bans_unsaved_write_scenario(void)
{
    struct sd_bans_ctx ctx;
    bool ok = sd_bans_setup(&ctx);
    struct net_addr addr;
    ok = ok && sd_bans_addr(&ctx, BANS_PEER_B, &addr);
    bool locked = ok && sd_bans_lock_datadir(&ctx);
    if (ok && !locked) {
        (void)chmod(ctx.dir, 0700);
        return sd_bans_teardown(&ctx, true); /* skip: write still works */
    }
    ok = ok && !sd_bans_call(&ctx, "setban", BANS_PEER_B, "add", NULL);
    ok = ok && sd_bans_error_has(&ctx.result, "not saved");
    ok = ok && is_banned(&ctx.cm.manager, &addr);
    ok = ok && sd_bans_unsaved_remove_check(&ctx, &addr);
    if (ctx.dir)
        (void)chmod(ctx.dir, 0700);
    return sd_bans_teardown(&ctx, ok);
}
