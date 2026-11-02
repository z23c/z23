/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_listener_bind: -bind reaches every listener the node opens for the
 * public network. Each listener is started on an OS-assigned port inside an
 * isolated temporary directory and graded by the address getsockname()
 * reports: the wildcard without a bind address, the named address with one.
 * The loopback RPC listener is fixed to 127.0.0.1 by design and is not
 * covered here. */

#include "test/test_core.h"

#include "net/acme_selfsigned.h"
#include "net/file_service.h"
#include "net/https_server.h"
#include "platform/socket_compat.h"
#include "rpc/httpserver.h"
#include "config/boot_internal.h"
#include "config/boot_mesh_pairing.h"
#include "kernel/service_kernel.h"
#include "services/https_deferred_start.h"

#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NAME_SIZE 64

static uint16_t free_port(void)
{
    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID)
        return 0;
    struct sockaddr_storage ss;
    socklen_t len = 0;
    uint16_t port = 0;
    char text[NAME_SIZE];
    if (platform_socket_listen_address("127.0.0.1", 0, false, &ss, &len) &&
        platform_socket_bind(fd, (struct sockaddr *)&ss, len) == 0)
        (void)platform_socket_local_name(fd, text, sizeof(text), &port);
    platform_socket_close(fd);
    return port;
}

static bool name_is(bool ok, const char *got, const char *want)
{
    if (ok && strcmp(got, want) == 0)
        return true;
    printf("(listener %s, wanted %s) ", ok ? got : "absent", want);
    return false;
}

static bool https_names(bool redirect, const char *want)
{
    char text[NAME_SIZE];
    uint16_t port = 0;
    bool ok = https_server_listener_name(redirect, text, sizeof(text), &port);
    return name_is(ok && port != 0, text, want);
}

static bool https_start(const char *cert, const char *key, const char *bind)
{
    if (https_server_start_on_port(cert, key, "bind.example", 0, 0, bind) &&
        https_server_is_running())
        return true;
    https_server_stop();
    return false;
}

static bool fs_start_check(const char *dir, const char *bind, const char *want)
{
    if (!fs_server_start(dir, 0, bind))
        return false;
    for (int i = 0; i < 200 && !fs_server_is_running(); i++)
        nanosleep(&(struct timespec){ .tv_nsec = 25000000 }, NULL);
    char text[NAME_SIZE];
    uint16_t port = 0;
    bool ok = fs_server_listener_name(text, sizeof(text), &port);
    ok = name_is(ok && port != 0, text, want);
    fs_server_stop();
    return ok;
}

static bool rpc_tls_start_check(const char *dir, const char *bind,
                                const char *want)
{
    uint16_t tls_port = free_port();
    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%u", (unsigned)tls_port);
    setenv("ZCL_RPC_TLS_PORT", port_text, 1);
    if (tls_port == 0 || !rpc_http_set_tls_bind(bind))
        return false;
    struct rpc_table table = { .commands = {{0}}, .num_commands = 0 };
    if (!rpc_http_start(&table, 0, NULL, NULL, dir))
        return false;
    char text[NAME_SIZE];
    uint16_t port = 0;
    bool ok = rpc_http_tls_listener_name(text, sizeof(text), &port);
    ok = name_is(ok && port == tls_port, text, want);
    rpc_http_stop();
    return ok;
}

/* Each case is its own function: TEST_CASE labels are function-scoped. */
static int case_https_wildcard(const char *cert, const char *key)
{
    int failures = 0;

    TEST_CASE("listener_bind: HTTPS front door and redirect listen on every interface without -bind")
    {
        const char *binds[] = { NULL, "" };
        for (size_t i = 0; i < 2; i++) {
            ASSERT(https_start(cert, key, binds[i]));
            ASSERT(https_names(false, "0.0.0.0"));
            ASSERT(https_names(true, "0.0.0.0"));
            https_server_stop();
        }
    }
    TEST_END
    return failures;
}

static int case_https_bound(const char *cert, const char *key)
{
    int failures = 0;

    TEST_CASE("listener_bind: HTTPS front door and redirect listen only on the -bind address")
    {
        ASSERT(https_start(cert, key, "127.0.0.1"));
        ASSERT(https_names(false, "127.0.0.1"));
        ASSERT(https_names(true, "127.0.0.1"));
        https_server_stop();
    }
    TEST_END
    return failures;
}

static int case_https_unparsable(const char *cert, const char *key)
{
    int failures = 0;

    TEST_CASE("listener_bind: an unparsable -bind stops the HTTPS front door from starting")
    {
        ASSERT(!https_server_start_on_port(cert, key, "bind.example", 0, 0,
                                           "localhost"));
        ASSERT(!https_server_is_running());
        ASSERT(!https_server_start_on_port(cert, key, "bind.example", 0, 0,
                                           "::ffff:127.0.0.1"));
        ASSERT(!https_server_is_running());
    }
    TEST_END
    return failures;
}

static int case_fs_wildcard(const char *dir)
{
    int failures = 0;

    TEST_CASE("listener_bind: the file service listens dual-stack without -bind")
    {
        ASSERT(fs_start_check(dir, NULL, "::"));
    }
    TEST_END
    return failures;
}

static int case_fs_bound(const char *dir)
{
    int failures = 0;

    TEST_CASE("listener_bind: an IPv4 -bind makes the file service listen on that address only")
    {
        ASSERT(fs_start_check(dir, "127.0.0.1", "::ffff:127.0.0.1"));
    }
    TEST_END
    return failures;
}

static int case_fs_unparsable(const char *dir)
{
    int failures = 0;

    TEST_CASE("listener_bind: an unparsable -bind stops the file service from starting")
    {
        ASSERT(!fs_server_start(dir, 0, "localhost"));
        ASSERT(!fs_server_is_running());
    }
    TEST_END
    return failures;
}

static int case_rpc_tls(const char *dir)
{
    int failures = 0;

    TEST_CASE("listener_bind: the RPC TLS listener follows -bind")
    {
        ASSERT(rpc_tls_start_check(dir, NULL, "0.0.0.0"));
        ASSERT(rpc_tls_start_check(dir, "127.0.0.1", "127.0.0.1"));
        ASSERT(!rpc_http_set_tls_bind("localhost"));
        ASSERT(!rpc_http_set_tls_bind("::ffff:127.0.0.1"));
    }
    TEST_END
    return failures;
}

/* The boot frontend start path. boot_register_frontend_services() installs
 * the hooks the node runs, and zcl_service_kernel_start_all() runs them with
 * the -bind address carried in app_context. The context is zeroed apart from
 * the listener fields: the miner, Tor and package-store hooks return without
 * opening anything, and the chain state is empty, so the HTTPS start is not
 * deferred unless a case raises the proof-validation height. */
extern _Atomic int g_deferred_proof_validation_below_height;

static struct boot_svc_ctx bf_svc;
static struct app_context bf_ctx;
static struct main_state bf_state;
static struct rpc_table bf_tbl;
static int bf_starter_calls;
static char bf_starter_bind[64];

static bool bf_record_starter(const char *cert, const char *key,
                              const char *host, int https_port, int http_port,
                              const char *bind)
{
    (void)cert;
    (void)key;
    (void)host;
    (void)https_port;
    (void)http_port;
    bf_starter_calls++;
    snprintf(bf_starter_bind, sizeof(bf_starter_bind), "%s", bind);
    return true;
}

static bool bf_start(const char *dir, const char *bind, int fs_port,
                     int rpc_port, int https_port)
{
    memset(&bf_svc, 0, sizeof(bf_svc));
    memset(&bf_ctx, 0, sizeof(bf_ctx));
    memset(&bf_state, 0, sizeof(bf_state));
    rpc_table_init(&bf_tbl);
    bf_ctx.datadir = dir;
    bf_ctx.p2p_bind_address = bind;
    bf_ctx.fs_port = fs_port;
    bf_ctx.rpc_port = rpc_port;
    bf_ctx.https_port = https_port;
    bf_ctx.no_tor = true;
    bf_svc.app_ctx = &bf_ctx;
    bf_svc.state = &bf_state;
    bf_svc.rpc_table = &bf_tbl;
    bf_svc.datadir = dir;
    zcl_service_kernel_init(&bf_svc.frontend_kernel);
    return boot_register_frontend_services(&bf_svc) &&
           zcl_service_kernel_start_all(&bf_svc.frontend_kernel);
}

static void bf_stop(void)
{
    zcl_service_kernel_stop_all(&bf_svc.frontend_kernel);
    boot_mesh_pairing_shutdown();
}

static void bf_set_tls_port(uint16_t port)
{
    char text[16];
    snprintf(text, sizeof(text), "%u", (unsigned)port);
    setenv("ZCL_RPC_TLS_PORT", text, 1);
}

static bool bf_wait_fs(void)
{
    for (int i = 0; i < 200 && !fs_server_is_running(); i++)
        nanosleep(&(struct timespec){ .tv_nsec = 25000000 }, NULL);
    return fs_server_is_running();
}

static bool bf_fs_is(const char *want)
{
    char text[NAME_SIZE];
    uint16_t port = 0;
    bool ok = fs_server_listener_name(text, sizeof(text), &port);
    return name_is(ok && port != 0, text, want);
}

static bool bf_rpc_tls_is(uint16_t tls_port, const char *want)
{
    char text[NAME_SIZE];
    uint16_t port = 0;
    bool ok = rpc_http_tls_listener_name(text, sizeof(text), &port);
    return name_is(ok && port == tls_port, text, want);
}

static int case_boot_frontend_bind(const char *dir)
{
    int failures = 0;

    TEST_CASE("listener_bind: the boot frontend start path binds every listener to -bind")
    {
        uint16_t tls_port = free_port();
        uint16_t fs_port = free_port();
        uint16_t rpc_port = free_port();
        uint16_t https_port = free_port();
        ASSERT(tls_port != 0 && fs_port != 0 && rpc_port != 0 && https_port > 363);
        bf_set_tls_port(tls_port);
        int saved = atomic_load(&g_deferred_proof_validation_below_height);
        atomic_store(&g_deferred_proof_validation_below_height, -1);
        bool started = bf_start(dir, "127.0.0.1", fs_port, rpc_port, https_port);
        bool fs_ok = started && bf_wait_fs() && bf_fs_is("::ffff:127.0.0.1");
        bool https_ok = started && https_names(false, "127.0.0.1");
        bool redirect_ok = started && https_names(true, "127.0.0.1");
        bool rpc_ok = started && bf_rpc_tls_is(tls_port, "127.0.0.1");
        bf_stop();
        atomic_store(&g_deferred_proof_validation_below_height, saved);
        ASSERT(started);
        ASSERT(fs_ok);
        ASSERT(https_ok);
        ASSERT(redirect_ok);
        ASSERT(rpc_ok);
    }
    TEST_END
    return failures;
}

static int case_boot_frontend_deferred(const char *dir)
{
    int failures = 0;

    TEST_CASE("listener_bind: a queued HTTPS start keeps the -bind address")
    {
        uint16_t tls_port = free_port();
        uint16_t fs_port = free_port();
        uint16_t rpc_port = free_port();
        uint16_t https_port = free_port();
        ASSERT(tls_port != 0 && fs_port != 0 && rpc_port != 0 && https_port > 363);
        bf_set_tls_port(tls_port);
        int saved = atomic_load(&g_deferred_proof_validation_below_height);
        atomic_store(&g_deferred_proof_validation_below_height, 20000);
        https_deferred_start_set_starter_for_testing(bf_record_starter);
        bf_starter_calls = 0;
        bf_starter_bind[0] = '\0';
        bool started = bf_start(dir, "127.0.0.1", fs_port, rpc_port, https_port);
        https_deferred_start_check();
        bool queued = started && bf_starter_calls == 1 &&
                      name_is(true, bf_starter_bind, "127.0.0.1");
        bf_stop();
        https_deferred_start_set_starter_for_testing(NULL);
        atomic_store(&g_deferred_proof_validation_below_height, saved);
        ASSERT(started);
        ASSERT(queued);
    }
    TEST_END
    return failures;
}

int test_listener_bind(void)
{
    int failures = 0;
    char dir[512];
    char cert[640];
    char key[640];
    test_make_tmpdir(dir, sizeof(dir), "listener_bind", "run");
    snprintf(cert, sizeof(cert), "%s/cert.pem", dir);
    snprintf(key, sizeof(key), "%s/key.pem", dir);
    if (!acme_selfsigned_write(cert, key, "bind.example")) {
        printf("listener_bind: the local certificate fixture was not written\n");
        test_rm_rf(dir);
        return 1;
    }
    setenv("ZCL_RPC_TLS_CERT", cert, 1);
    setenv("ZCL_RPC_TLS_KEY", key, 1);
    rpc_http_forbid_tls(false);

    failures += case_https_wildcard(cert, key);
    failures += case_https_bound(cert, key);
    failures += case_https_unparsable(cert, key);
    failures += case_fs_wildcard(dir);
    failures += case_fs_bound(dir);
    failures += case_fs_unparsable(dir);
    failures += case_rpc_tls(dir);
    failures += case_boot_frontend_bind(dir);
    failures += case_boot_frontend_deferred(dir);

    (void)rpc_http_set_tls_bind(NULL);
    unsetenv("ZCL_RPC_TLS_CERT");
    unsetenv("ZCL_RPC_TLS_KEY");
    unsetenv("ZCL_RPC_TLS_PORT");
    test_rm_rf(dir);
    return failures;
}
