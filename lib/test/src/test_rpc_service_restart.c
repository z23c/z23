/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_rpc_service_restart — the frontend service kernel must survive a
 * stop -> start cycle of the rpc_http service, and must RE-ENTER RPC warmup
 * when it does.
 *
 * The defect this pins
 * --------------------
 * boot_rpc_http_start() clears RPC warmup with set_rpc_warmup_finished(),
 * and that function used to enforce "called exactly once" with a live
 * assert(rpc_in_warmup). assert() does not vanish in this build (-DNDEBUG is
 * set only for the vendored LevelDB compile), so it was a real abort(). The
 * paired stop hook only called rpc_http_stop() and never restored the flag,
 * so the SECOND start_all in a stop_all -> start_all cycle killed the node.
 *
 * The service kernel genuinely supports that cycle:
 * zcl_service_kernel_stop_all() clears kernel->started and start_all()
 * re-runs every .start hook. start_all()'s own partial-failure rollback
 * already stops rpc_http mid-call when a later required service fails, so
 * only the absence of a retry kept this off the live path.
 *
 * Two properties, not one
 * -----------------------
 * Surviving the restart is not enough on its own. A node that comes back up
 * still reporting "ready" while it re-initialises answers RPC from half-built
 * state, which is worse than the crash. So this test pins BOTH edges:
 *   - stop  RE-ARMS warmup (clients get RPC_IN_WARMUP + a reason)
 *   - start CLEARS it again (methods answer)
 * over the REAL hooks, obtained from boot_frontend_rpc_http_spec() — the same
 * value boot_register_frontend_services() installs into the frontend kernel,
 * so this test cannot drift from what actually boots.
 *
 * REGRESSION: revert the fix and case 6 aborts the whole test process with
 * SIGABRT rather than failing a check.
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"
#include "platform/socket_compat.h"
#include "config/boot.h"
#include "config/boot_internal.h"
#include "kernel/service_kernel.h"
#include "rpc/server.h"
#include "rpc/httpserver.h"
#include "rpc/protocol.h"
#include "json/json.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* A trivially-answerable method, so "RPC answers correctly" is a real
 * dispatch through rpc_table_execute() (which is where the warmup gate
 * lives) rather than an inspection of the flag alone. */
static bool rsr_probe_actor(const struct json_value *params, bool help,
                            struct json_value *result)
{
    (void)params;
    (void)help;
    json_set_str(result, "alive");
    return true;
}

/* Returns 1 if the method answered with its value, 0 otherwise. */
static int rsr_probe_answers(struct rpc_table *tbl)
{
    struct json_value params, result;
    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    bool ok = rpc_table_execute(tbl, "restartprobe", &params, &result);
    ok = ok && result.type == JSON_STR &&
         strcmp(json_get_str(&result), "alive") == 0;
    json_free(&params);
    json_free(&result);
    return ok ? 1 : 0;
}

/* Returns 1 if the method was refused with RPC_IN_WARMUP and `want_reason`
 * as the client-visible message. */
static int rsr_probe_refused(struct rpc_table *tbl, const char *want_reason)
{
    struct json_value params, result;
    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    bool executed = rpc_table_execute(tbl, "restartprobe", &params, &result);
    const struct json_value *code = json_get(&result, "code");
    const struct json_value *msg = json_get(&result, "message");
    int ok = !executed && code && json_get_int(code) == RPC_IN_WARMUP &&
             msg && want_reason &&
             strcmp(json_get_str(msg), want_reason) == 0;
    json_free(&params);
    json_free(&result);
    return ok;
}

/* boot_svc_ctx is large and only three fields are read by the rpc_http
 * hooks (app_ctx, rpc_table, datadir); file scope keeps it off the stack
 * and zero-initialized. */
static struct boot_svc_ctx g_svc;
static struct app_context g_ctx;
static struct rpc_table g_tbl;

/* Hold one kernel-assigned loopback port open so the production frontend
 * hook must propagate rpc_http_start()'s bind failure. */
static int rsr_hold_loopback_port(uint16_t *port_out)
{
    if (!port_out)
        return -1;
    int fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    if (fd < 0)
        return -1;
    const struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = 0,
    };
    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 1) != 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_in bound = {0};
    socklen_t bound_len = sizeof(bound);
    if (getsockname(fd, (struct sockaddr *)&bound, &bound_len) != 0 ||
        bound_len != sizeof(bound)) {
        close(fd);
        return -1;
    }
    *port_out = ntohs(bound.sin_port);
    return fd;
}

int test_rpc_service_restart(void)
{
    int failures = 0;

    char datadir[256];
    snprintf(datadir, sizeof(datadir),
             "test-tmp/rpc_service_restart_%d", (int)getpid());
    test_rm_rf(datadir);
    if (mkdir("test-tmp", 0755) != 0 && errno != EEXIST) {
        printf("rpc_service_restart: FAIL (mkdir test-tmp)\n");
        return 1;
    }
    if (mkdir(datadir, 0755) != 0) {
        printf("rpc_service_restart: FAIL (mkdir datadir)\n");
        return 1;
    }

    rpc_table_init(&g_tbl);
    struct rpc_command probe = {
        .category = "control",
        .name = "restartprobe",
        .actor = rsr_probe_actor,
        .ok_safe_mode = true,
    };
    if (!rpc_table_append(&g_tbl, &probe)) {
        printf("rpc_service_restart: FAIL (probe registration)\n");
        test_rm_rf(datadir);
        return 1;
    }

    uint16_t held_port = 0;
    int held_fd = rsr_hold_loopback_port(&held_port);
    if (held_fd < 0) {
        printf("rpc_service_restart: FAIL (hold loopback port)\n");
        test_rm_rf(datadir);
        return 1;
    }
    g_ctx.rpc_port = held_port;
    g_ctx.rpc_user = NULL;
    g_ctx.rpc_password = NULL;
    g_ctx.datadir = datadir;
    /* This test owns cookie lifecycle, not the periodic rotation worker. */
    setenv("ZCL_RPC_COOKIE_ROTATE_SEC", "0", 1);

    g_svc.app_ctx = &g_ctx;
    g_svc.rpc_table = &g_tbl;
    g_svc.datadir = datadir;

    struct zcl_service_kernel kernel;
    zcl_service_kernel_init(&kernel);
    struct zcl_service_spec spec = boot_frontend_rpc_http_spec(&g_svc);
    if (!zcl_service_kernel_register(&kernel, &spec)) {
        printf("rpc_service_restart: FAIL (service registration)\n");
        close(held_fd);
        unsetenv("ZCL_RPC_COOKIE_ROTATE_SEC");
        test_rm_rf(datadir);
        return 1;
    }

    char cookie_path[320], rpcport_path[320];
    snprintf(cookie_path, sizeof(cookie_path), "%s/.cookie", datadir);
    snprintf(rpcport_path, sizeof(rpcport_path), "%s/.rpcport", datadir);

    printf("rpc_service_restart: occupied RPC port refuses frontend start... ");
    bool occupied_started = zcl_service_kernel_start_all(&kernel);
    if (!occupied_started) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    printf("rpc_service_restart: failed start leaves no cookie authority... ");
    if (access(cookie_path, F_OK) != 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    printf("rpc_service_restart: failed start leaves no stale port hint... ");
    if (access(rpcport_path, F_OK) != 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    printf("rpc_service_restart: refused frontend stays in warmup... ");
    if (!rpc_http_is_running() && rpc_is_in_warmup(NULL, 0)) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }
    if (occupied_started)
        zcl_service_kernel_stop_all(&kernel);
    close(held_fd);

    printf("rpc_service_restart: a fresh process starts in warmup... ");
    if (rpc_is_in_warmup(NULL, 0) &&
        rsr_probe_refused(&g_tbl, "RPC server started")) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    printf("rpc_service_restart: first start clears warmup... ");
    if (zcl_service_kernel_start_all(&kernel) && !rpc_is_in_warmup(NULL, 0)) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    printf("rpc_service_restart: RPC answers after the first start... ");
    if (rsr_probe_answers(&g_tbl)) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    /* The stop edge. Without the re-arm the node would come back up still
     * claiming ready while it re-initialises. */
    zcl_service_kernel_stop_all(&kernel);

    printf("rpc_service_restart: stop removes cookie and port authority... ");
    if (access(cookie_path, F_OK) != 0 && access(rpcport_path, F_OK) != 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    printf("rpc_service_restart: stop re-arms warmup with a reason... ");
    {
        char status[256] = "";
        if (rpc_is_in_warmup(status, sizeof(status)) &&
            strcmp(status, "RPC server restarting") == 0 &&
            rsr_probe_refused(&g_tbl, "RPC server restarting")) {
            printf("OK\n");
        } else {
            printf("FAIL (status=\"%s\")\n", status);
            failures++;
        }
    }

    /* THE regression line. On the unfixed build the stop hook never re-armed
     * warmup, so the flag is already false when boot_rpc_http_start() calls
     * set_rpc_warmup_finished() a second time — its assertion fails and takes
     * this process down with SIGABRT instead of returning a verdict. */
    printf("rpc_service_restart: the service restarts without killing "
           "the node... ");
    if (zcl_service_kernel_start_all(&kernel)) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    printf("rpc_service_restart: warmup is cleared again after restart... ");
    if (!rpc_is_in_warmup(NULL, 0)) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    printf("rpc_service_restart: RPC answers after the restart... ");
    if (rsr_probe_answers(&g_tbl)) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    /* A third cycle: the lifecycle is a loop, not a single spare life. */
    zcl_service_kernel_stop_all(&kernel);
    printf("rpc_service_restart: a second restart behaves identically... ");
    if (rpc_is_in_warmup(NULL, 0) && zcl_service_kernel_start_all(&kernel) &&
        !rpc_is_in_warmup(NULL, 0) && rsr_probe_answers(&g_tbl)) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    /* Declaring ready twice in a row is a no-op, not a crash. */
    printf("rpc_service_restart: declaring ready twice is a no-op... ");
    set_rpc_warmup_finished();
    set_rpc_warmup_finished();
    if (!rpc_is_in_warmup(NULL, 0)) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    zcl_service_kernel_stop_all(&kernel);
    zcl_service_kernel_reset(&kernel);
    set_rpc_warmup_finished();
    unsetenv("ZCL_RPC_COOKIE_ROTATE_SEC");
    test_rm_rf(datadir);
    return failures;
}
