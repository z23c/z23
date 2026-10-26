/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_rpc_service_restart — the frontend service kernel must survive a
 * stop -> start cycle of the rpc_http service, and must RE-ENTER RPC warmup
 * when it does.
 *
 * boot_rpc_http_start() clears RPC warmup with set_rpc_warmup_finished(),
 * which asserts "called exactly once". The paired stop hook must restore the
 * flag, or the second start_all in a stop_all -> start_all cycle aborts.
 * zcl_service_kernel_stop_all() clears kernel->started and start_all()
 * re-runs every .start hook.
 *
 * Both edges are pinned, because a node that comes back up still reporting
 * "ready" answers RPC from half-built state:
 *   - stop  RE-ARMS warmup (clients get RPC_IN_WARMUP + a reason)
 *   - start CLEARS it again (methods answer)
 * over the REAL hooks from boot_frontend_rpc_http_spec(), the value
 * boot_register_frontend_services() installs into the frontend kernel.
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"
#include "platform/socket_compat.h"
#include "platform/time_compat.h"
#include "config/boot.h"
#include "config/boot_internal.h"
#include "config/boot_rpc_retry.h"
#include "kernel/service_kernel.h"
#include "rpc/server.h"
#include "rpc/httpserver.h"
#include "rpc/protocol.h"
#include "json/json.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
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
static platform_socket_t rsr_hold_loopback_port(uint16_t *port_out)
{
    if (!port_out)
        return PLATFORM_SOCKET_INVALID;
    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID)
        return PLATFORM_SOCKET_INVALID;
    const struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = 0,
    };
    if (platform_socket_bind(fd, (const struct sockaddr *)&addr,
                             sizeof(addr)) != 0 ||
        platform_socket_listen(fd, 1) != 0) {
        platform_socket_close(fd);
        return PLATFORM_SOCKET_INVALID;
    }
    struct sockaddr_in bound = {0};
    size_t bound_len = sizeof(bound);
    if (platform_socket_local_address(fd, (struct sockaddr *)&bound,
                                      &bound_len) != 0 ||
        bound_len != sizeof(bound)) {
        platform_socket_close(fd);
        return PLATFORM_SOCKET_INVALID;
    }
    *port_out = ntohs(bound.sin_port);
    return fd;
}

/* The stand-in public site: it only counts, so "did it get to run at all"
 * is the whole assertion. */
static int g_site_starts;

static bool rsr_site_start(void *ctx)
{
    (*(int *)ctx)++;
    return true;
}

static void rsr_site_stop(void *ctx)
{
    (void)ctx;
}

/* On the real hook: the RPC port is still held by the departing process,
 * boot_rpc_http_start() returns false, and the independent site service's
 * start must still run. */
static int rsr_site_survived_refused_front_door(void)
{
    printf("rpc_service_restart: a refused front door does not cancel the "
           "public site... ");
    if (g_site_starts == 1) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL (site starts=%d)\n", g_site_starts);
    return 1;
}

static int rsr_retry_after_bind_conflict(struct zcl_service_kernel *kernel,
                                         platform_socket_t held_fd)
{
    int failures = 0;
    /* The serving site remains up while the exact failed RPC entry is
     * retried. The production condition calls this same bounded retry when
     * its clock is due; synthetic time keeps the fixture fast. */
    boot_rpc_retry_arm(kernel);
    int64_t retry_now = platform_time_monotonic_us();
    printf("rpc_service_restart: retry waits for its first deadline... ");
    if (boot_rpc_retry_failed() && !boot_rpc_retry_due(retry_now) &&
        !boot_rpc_retry_attempt(retry_now)) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }
    platform_socket_close(held_fd);
    printf("rpc_service_restart: freed port recovers RPC without site restart... ");
    if (boot_rpc_retry_attempt(retry_now + 6000000) &&
        boot_rpc_retry_recovered() && !rpc_is_in_warmup(NULL, 0) &&
        rsr_probe_answers(&g_tbl) && g_site_starts == 1) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }
    printf("rpc_service_restart: settled retry is idempotent... ");
    if (!boot_rpc_retry_attempt(retry_now + 6000000) &&
        g_site_starts == 1 && rpc_http_is_running()) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }
    boot_rpc_retry_disarm(kernel);
    return failures;
}

/* Builds this run's datadir under test-tmp, clearing any state an earlier
 * run left behind. Returns 0, or 1 after printing why it could not. */
static int rsr_prepare_datadir(char *datadir, size_t capacity)
{
    snprintf(datadir, capacity,
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
    return 0;
}

/* Registers the probe method, holds the RPC port, and loads the real
 * frontend spec plus the stand-in site into `kernel`. Returns 0 with the
 * held socket in `*held_fd_out`, or 1 after undoing whatever was set up. */
static int rsr_bring_up_frontend_services(char *datadir,
                                          struct zcl_service_kernel *kernel,
                                          platform_socket_t *held_fd_out)
{
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
    platform_socket_t held_fd = rsr_hold_loopback_port(&held_port);
    if (held_fd == PLATFORM_SOCKET_INVALID) {
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

    zcl_service_kernel_init(kernel);
    struct zcl_service_spec spec = boot_frontend_rpc_http_spec(&g_svc);
    /* Stands in for https_explorer, registered AFTER rpc_http as
     * boot_register_frontend_services() does: a front door that cannot bind
     * must not cancel the public site. */
    struct zcl_service_spec site = {
        .name = "https_explorer",
        .start = rsr_site_start,
        .stop = rsr_site_stop,
        .ctx = &g_site_starts,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    if (!zcl_service_kernel_register(kernel, &spec) ||
        !zcl_service_kernel_register(kernel, &site)) {
        printf("rpc_service_restart: FAIL (service registration)\n");
        platform_socket_close(held_fd);
        unsetenv("ZCL_RPC_COOKIE_ROTATE_SEC");
        test_rm_rf(datadir);
        return 1;
    }
    *held_fd_out = held_fd;
    return 0;
}

/* The refused-start edge: an occupied RPC port must fail start_all, leave
 * no cookie or stale port hint behind, and keep the node in warmup. */
static int rsr_check_refused_start(struct zcl_service_kernel *kernel,
                                   const char *cookie_path,
                                   const char *rpcport_path)
{
    int failures = 0;
    printf("rpc_service_restart: occupied RPC port refuses frontend start... ");
    bool occupied_started = zcl_service_kernel_start_all(kernel);
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
    return failures;
}

/* One full stop -> start pass over the real hooks: stop re-enters warmup
 * with the restart reason, the next start clears it, methods answer. */
static int rsr_check_warmup_across_stop_start(struct zcl_service_kernel *kernel)
{
    int failures = 0;
    printf("rpc_service_restart: stopped RPC re-enters warmup... ");
    if (rpc_is_in_warmup(NULL, 0) &&
        rsr_probe_refused(&g_tbl, "RPC server restarting")) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    printf("rpc_service_restart: first start clears warmup... ");
    if (zcl_service_kernel_start_all(kernel) && !rpc_is_in_warmup(NULL, 0)) {
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
    return failures;
}

/* The measured stop edge: bounded shutdown, authority files gone, and
 * warmup re-armed with the client-visible reason. */
static int rsr_check_stop_edge(int64_t stop_elapsed_ms,
                               const char *cookie_path,
                               const char *rpcport_path)
{
    int failures = 0;
    printf("rpc_service_restart: idle listener stop is bounded... ");
    if (stop_elapsed_ms >= 0 && stop_elapsed_ms < 3000) {
        printf("OK (%lldms)\n", (long long)stop_elapsed_ms);
    } else {
        printf("FAIL (%lldms)\n", (long long)stop_elapsed_ms);
        failures++;
    }

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
    return failures;
}

/* The lifecycle is a loop, not a single spare life: the second and third
 * stop -> start cycles behave like the first, and declaring ready twice in
 * a row is a no-op. */
static int rsr_check_repeated_cycles(struct zcl_service_kernel *kernel)
{
    int failures = 0;
    /* set_rpc_warmup_finished() a second time must not abort: the stop hook
     * re-armed warmup. */
    printf("rpc_service_restart: the service restarts without killing "
           "the node... ");
    if (zcl_service_kernel_start_all(kernel)) {
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
    zcl_service_kernel_stop_all(kernel);
    printf("rpc_service_restart: a second restart behaves identically... ");
    if (rpc_is_in_warmup(NULL, 0) && zcl_service_kernel_start_all(kernel) &&
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
    return failures;
}

int test_rpc_service_restart(void)
{
    int failures = 0;

    char datadir[256];
    if (rsr_prepare_datadir(datadir, sizeof(datadir)) != 0)
        return 1;

    struct zcl_service_kernel kernel;
    platform_socket_t held_fd;
    if (rsr_bring_up_frontend_services(datadir, &kernel, &held_fd) != 0)
        return 1;

    char cookie_path[320], rpcport_path[320];
    snprintf(cookie_path, sizeof(cookie_path), "%s/.cookie", datadir);
    snprintf(rpcport_path, sizeof(rpcport_path), "%s/.rpcport", datadir);

    failures += rsr_check_refused_start(&kernel, cookie_path, rpcport_path);

    failures += rsr_site_survived_refused_front_door();

    failures += rsr_retry_after_bind_conflict(&kernel, held_fd);

    /* Close the cycle unconditionally: a failed independent service leaves its
     * siblings RUNNING, so the next start_all is a restart. */
    zcl_service_kernel_stop_all(&kernel);

    failures += rsr_check_warmup_across_stop_start(&kernel);

    /* The stop edge. Without the re-arm the node would come back up still
     * claiming ready while it re-initialises. */
    int64_t stop_started_ms = platform_time_monotonic_ms();
    zcl_service_kernel_stop_all(&kernel);
    int64_t stop_elapsed_ms =
        platform_time_monotonic_ms() - stop_started_ms;

    failures += rsr_check_stop_edge(stop_elapsed_ms, cookie_path,
                                    rpcport_path);

    failures += rsr_check_repeated_cycles(&kernel);

    zcl_service_kernel_stop_all(&kernel);
    zcl_service_kernel_reset(&kernel);
    set_rpc_warmup_finished();
    unsetenv("ZCL_RPC_COOKIE_ROTATE_SEC");
    test_rm_rf(datadir);
    return failures;
}
