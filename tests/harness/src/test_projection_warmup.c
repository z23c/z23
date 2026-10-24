/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_projection_warmup — the projection stores open on a tracked warm-up
 * thread after the network kernel starts, not on the boot critical path.
 *
 * The open is held on a latch (ZCL_TESTING seam). While it is held: the
 * synchronous consensus/serving inputs (event log, block_index_projection) are
 * up, boot_start_projection_storage has RETURNED, projection_store_db() is NULL
 * (the idle contract), a chain-class RPC runs and a projection-class RPC
 * answers -28 "projections loading". After release the store is open and the
 * bit is set. A node stopped during warm-up joins the thread cleanly before the
 * stores close. */

#include "test/test_core.h"
#include "config/boot_internal.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "storage/block_index_projection.h"
#include "storage/event_log_singleton.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"
#include <stdio.h>
#include <string.h>

static bool pw_actor(const struct json_value *params, bool help,
                     struct json_value *result)
{
    (void)params;
    (void)help;
    json_init(result);
    json_set_str(result, "ran");
    return true;
}

static int pw_check(bool ok, const char *what)
{
    if (ok)
        return 0;
    printf("projection_warmup: FAIL (%s)\n", what);
    return 1;
}

/* true when the method ran; otherwise *code / msg hold the refusal. */
static bool pw_run(const struct rpc_table *t, const char *method,
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

static bool pw_wait_done(void)
{
    for (int i = 0; i < 10000; i++) {
        if (boot_projection_warmup_test_done())
            return true;
        platform_sleep_ms(2); /* real-clock: waits on a real OS thread finishing; no fake-clock seam exists for it */
    }
    return false;
}

/* Boot-shaped sequence with the open held: storage armed, network "started",
 * RPC front door up. */
static int pw_boot_held(const char *dir)
{
    int f = 0;
    f += pw_check(progress_store_open(dir), "progress_store opens");
    set_rpc_warmup_started("Loading block index");
    boot_projection_warmup_test_hold(true);
    boot_start_projection_storage(dir);
    boot_start_projection_warmup();
    set_rpc_warmup_finished();
    boot_projection_warmup_publish_rpc();
    return f;
}

static int pw_held_checks(const struct rpc_table *t)
{
    int f = 0;
    int64_t code;
    char msg[256];
    f += pw_check(event_log_singleton() != NULL, "event log is synchronous");
    f += pw_check(block_index_projection_singleton() != NULL,
                  "block_index_projection is synchronous");
    f += pw_check(projection_store_db() == NULL,
                  "projection store idle while held");
    f += pw_check(!boot_projection_warmup_test_done(), "warm-up not done");
    f += pw_check(rpc_ready_is(RPC_READY_CHAIN), "chain class ready");
    f += pw_check(!rpc_ready_is(RPC_READY_PROJECTION),
                  "projection bit clear while held");
    f += pw_check(pw_run(t, "pw_chain", &code, msg, sizeof(msg)),
                  "chain RPC runs while held");
    bool ran = pw_run(t, "pw_projection", &code, msg, sizeof(msg));
    f += pw_check(!ran && code == RPC_IN_WARMUP &&
                      strcmp(msg, "projections loading") == 0,
                  "projection RPC answers -28 while held");
    return f;
}

static int pw_released_checks(const struct rpc_table *t)
{
    int f = 0;
    int64_t code;
    char msg[256];
    boot_projection_warmup_test_hold(false);
    f += pw_check(pw_wait_done(), "warm-up finishes after release");
    f += pw_check(projection_store_db() != NULL, "store open after release");
    f += pw_check(rpc_ready_is(RPC_READY_PROJECTION), "bit set after release");
    f += pw_check(pw_run(t, "pw_projection", &code, msg, sizeof(msg)),
                  "projection RPC runs after release");
    return f;
}

int test_projection_warmup(void)
{
    int failures = 0;
    char dir[256];
    struct rpc_table t;
    rpc_table_init(&t);
    const struct rpc_command cmds[] = {
        { "explorer", "pw_projection", pw_actor, true },
        { "control", "pw_chain", pw_actor, true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        failures += pw_check(rpc_table_append(&t, &cmds[i]), "append");

    /* Held open, then released. */
    test_make_tmpdir(dir, sizeof(dir), "projection_warmup", "release");
    failures += pw_boot_held(dir);
    failures += pw_held_checks(&t);
    failures += pw_released_checks(&t);
    boot_projection_warmup_stop();
    boot_stop_projection_storage();
    progress_store_close();

    /* Stopped while the open is still held: joins before anything closes. */
    test_make_tmpdir(dir, sizeof(dir), "projection_warmup", "shutdown");
    failures += pw_boot_held(dir);
    failures += pw_held_checks(&t);
    boot_projection_warmup_stop();
    boot_stop_projection_storage();
    failures += pw_check(projection_store_db() == NULL,
                         "store never opened when stopped during warm-up");
    progress_store_close();

    boot_projection_warmup_test_hold(false);
    set_rpc_warmup_finished();
    printf("projection_warmup: %s\n", failures ? "FAIL" : "PASS");
    return failures;
}
