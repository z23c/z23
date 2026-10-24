/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_rpc_readiness_classes — per-class RPC readiness layered under the
 * global warm-up flag. With the flag armed every method keeps the old
 * RPC_IN_WARMUP refusal; with it disarmed a method is refused with a class
 * reason until its class bit is set. A command that declares no class (and
 * whose category implies none) takes the strictest class and waits for all
 * bits. Arming/disarming the flag moves every class bit together. */

#include "test/test_core.h"
#include "rpc/server.h"
#include <stdio.h>
#include <string.h>

static bool rrc_actor(const struct json_value *params, bool help,
                      struct json_value *result)
{
    (void)params;
    (void)help;
    json_init(result);
    json_set_str(result, "ran");
    return true;
}

static int rrc_check(bool ok, const char *what)
{
    if (ok)
        return 0;
    printf("rpc_readiness_classes: FAIL (%s)\n", what);
    return 1;
}

/* Run a method; true when it executed, otherwise *code / msg hold the error. */
static bool rrc_run(const struct rpc_table *t, const char *method,
                    int64_t *code, char *msg, size_t msg_size)
{
    struct json_value params, result;
    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    bool ok = rpc_table_execute(t, method, &params, &result);
    *code = 0;
    msg[0] = '\0';
    if (!ok) {
        const struct json_value *c = json_get(&result, "code");
        const struct json_value *m = json_get(&result, "message");
        if (c)
            *code = json_get_int(c);
        if (m && json_get_str(m))
            snprintf(msg, msg_size, "%s", json_get_str(m));
    }
    json_free(&params);
    json_free(&result);
    return ok;
}

static int rrc_expect_refused(const struct rpc_table *t, const char *method,
                              const char *text, const char *what)
{
    int64_t code;
    char msg[256];
    bool ran = rrc_run(t, method, &code, msg, sizeof(msg));
    return rrc_check(!ran && code == RPC_IN_WARMUP && strcmp(msg, text) == 0,
                     what);
}

static int rrc_expect_runs(const struct rpc_table *t, const char *method,
                           const char *what)
{
    int64_t code;
    char msg[256];
    return rrc_check(rrc_run(t, method, &code, msg, sizeof(msg)), what);
}

int test_rpc_readiness_classes(void)
{
    int failures = 0;
    struct rpc_table t;
    rpc_table_init(&t);
    const struct rpc_command cmds[] = {
        { "wallet", "rrc_wallet", rrc_actor, true },
        { "explorer", "rrc_projection", rrc_actor, true },
        { "control", "rrc_chain", rrc_actor, true },
        { "nosuchcategory", "rrc_unclassified", rrc_actor, true },
        { "control", "rrc_declared_wallet", rrc_actor, true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        failures += rrc_check(rpc_table_append(&t, &cmds[i]), "append");
    failures += rrc_check(rpc_table_set_ready_class(&t, "rrc_declared_wallet",
                                                    RPC_READY_WALLET),
                          "declare class");

    /* Global flag armed: the old refusal text for every command. */
    set_rpc_warmup_started("Loading block index");
    static const char *const names[] = {
        "rrc_wallet", "rrc_projection", "rrc_chain", "rrc_unclassified",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        failures += rrc_expect_refused(&t, names[i], "Loading block index",
                                       "flag armed keeps old text");

    /* Flag disarmed: every class bit is set with it, so all run. */
    set_rpc_warmup_finished();
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        failures += rrc_expect_runs(&t, names[i], "all ready together");

    /* Wallet class pending. */
    rpc_ready_set(RPC_READY_WALLET, false);
    failures += rrc_expect_refused(&t, "rrc_wallet", "wallet loading",
                                   "wallet refused while loading");
    failures += rrc_expect_refused(&t, "rrc_declared_wallet", "wallet loading",
                                   "declared class beats category");
    failures += rrc_expect_refused(&t, "rrc_unclassified", "node loading",
                                   "unclassified needs every bit");
    failures += rrc_expect_runs(&t, "rrc_chain", "chain runs, wallet pending");
    failures += rrc_expect_runs(&t, "rrc_projection",
                                "projection runs, wallet pending");
    rpc_ready_set(RPC_READY_WALLET, true);
    failures += rrc_expect_runs(&t, "rrc_wallet", "wallet runs once set");
    failures += rrc_expect_runs(&t, "rrc_unclassified",
                                "unclassified runs once all set");

    /* Projection class pending. */
    rpc_ready_set(RPC_READY_PROJECTION, false);
    failures += rrc_expect_refused(&t, "rrc_projection", "projections loading",
                                   "projection refused while loading");
    failures += rrc_expect_refused(&t, "rrc_unclassified", "node loading",
                                   "unclassified refused, projection pending");
    failures += rrc_expect_runs(&t, "rrc_chain", "chain runs, projection pending");
    failures += rrc_expect_runs(&t, "rrc_wallet",
                                "wallet runs, projection pending");
    rpc_ready_set(RPC_READY_PROJECTION, true);
    failures += rrc_expect_runs(&t, "rrc_projection",
                                "projection runs once set");

    /* Re-arming clears every bit; the old text comes back. */
    set_rpc_warmup_started("RPC server restarting");
    failures += rrc_check(!rpc_ready_is(RPC_READY_CHAIN) &&
                              !rpc_ready_is(RPC_READY_WALLET) &&
                              !rpc_ready_is(RPC_READY_PROJECTION),
                          "re-arm clears bits");
    failures += rrc_expect_refused(&t, "rrc_chain", "RPC server restarting",
                                   "re-armed flag text");
    set_rpc_warmup_finished();

    printf("rpc_readiness_classes: %s\n", failures ? "FAIL" : "PASS");
    return failures;
}
