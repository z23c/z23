/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * RPC HTTP credential, cookie-file, and rotation ownership.
 *
 * This translation unit is the only owner of live RPC credentials and their
 * durable cookie path. Request dispatch can ask whether a presented header is
 * valid, but cannot read or mutate credential storage directly. */

#include "httpserver_auth.h"

#include "core/random.h"
#include "encoding/utilstrencodings.h"
#include "platform/private_file.h"
#include "rpc/httpserver.h"
#include "support/cleanse.h"
#include "util/thread_liveness.h"
#include "util/thread_registry.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char g_rpc_user[128];
static char g_rpc_password[128];
static char g_rpc_password_prev[128];
static char g_cookie_file[1024];
static char g_rpc_port_file[1024];
static bool g_auth_required = false;
static bool g_cookie_mode = false;
static pthread_mutex_t g_cookie_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_cookie_rotate_thread;
static bool g_cookie_rotate_started = false;
static _Atomic bool g_cookie_rotate_running = false;
static int g_cookie_rotate_sec = 86400;
static struct thread_liveness_child g_rpc_cookie_liveness = {
    .id = SUPERVISOR_INVALID_ID
};

/* Both credential buffers in rpc_http_auth_check() are 512 bytes and both
 * strings are NUL-terminated inside them, so no live length reaches this. */
#define RPC_AUTH_CT_BYTES 512u

static int constant_time_strcmp(const char *a, size_t alen,
                                const char *b, size_t blen)
{
    unsigned int diff = (unsigned int)(alen ^ blen);
    for (size_t i = 0; i < RPC_AUTH_CT_BYTES; i++) {
        unsigned char ca = i < alen ? (unsigned char)a[i] : 0u;
        unsigned char cb = i < blen ? (unsigned char)b[i] : 0u;
        diff |= (unsigned int)(ca ^ cb);
    }
    return diff == 0 ? 0 : 1;
}

bool rpc_http_auth_check(const char *auth_header)
{
    if (!g_auth_required) return true;
    if (!auth_header) return false;

    while (*auth_header == ' ') auth_header++;
    if (strncmp(auth_header, "Basic ", 6) != 0) return false;
    const char *b64 = auth_header + 6;
    while (*b64 == ' ') b64++;

    unsigned char decoded[512];
    size_t dlen = DecodeBase64(b64, decoded, sizeof(decoded) - 1, NULL);
    decoded[dlen] = '\0';

    char expected[512];
    static_assert(sizeof decoded >= RPC_AUTH_CT_BYTES, "decoded too small");
    static_assert(sizeof expected >= RPC_AUTH_CT_BYTES, "expected too small");
    pthread_mutex_lock(&g_cookie_mutex);
    snprintf(expected, sizeof(expected), "%s:%s", g_rpc_user,
             g_rpc_password);
    size_t elen = strlen(expected);
    bool ok = constant_time_strcmp((const char *)decoded, dlen,
                                   expected, elen) == 0;

    if (!ok && g_cookie_mode && g_rpc_password_prev[0]) {
        snprintf(expected, sizeof(expected), "%s:%s", g_rpc_user,
                 g_rpc_password_prev);
        elen = strlen(expected);
        ok = constant_time_strcmp((const char *)decoded, dlen,
                                  expected, elen) == 0;
    }
    pthread_mutex_unlock(&g_cookie_mutex);

    memory_cleanse(expected, sizeof(expected));
    memory_cleanse(decoded, sizeof(decoded));
    return ok;
}

static bool rpc_cookie_write_secure(const char *path, const char *user,
                                    const char *password)
{
    char body[sizeof(g_rpc_user) + sizeof(g_rpc_password) + 2];
    int n = snprintf(body, sizeof(body), "%s:%s", user, password);
    struct platform_private_file file;
    platform_private_file_init(&file);
    (void)platform_private_file_unlink_missing_ok(path);
    bool ok = n > 0 && (size_t)n < sizeof(body) &&
              platform_private_file_create(path, &file) &&
              platform_private_file_write_at(&file, body, (size_t)n, 0);
    platform_private_file_close(&file);
    memory_cleanse(body, sizeof(body));
    if (!ok) (void)platform_private_file_unlink_missing_ok(path);
    return ok;
}

void rpc_http_cookie_rotate(void)
{
    pthread_mutex_lock(&g_cookie_mutex);
    if (!g_cookie_mode || !g_auth_required) {
        pthread_mutex_unlock(&g_cookie_mutex);
        return;
    }

    memory_cleanse(g_rpc_password_prev, sizeof(g_rpc_password_prev));
    memcpy(g_rpc_password_prev, g_rpc_password, sizeof(g_rpc_password));

    uint64_t r1 = GetRand(UINT64_MAX);
    uint64_t r2 = GetRand(UINT64_MAX);
    snprintf(g_rpc_password, sizeof(g_rpc_password), "%016llx%016llx",
             (unsigned long long)r1, (unsigned long long)r2);

    if (g_cookie_file[0])
        (void)rpc_cookie_write_secure(g_cookie_file, g_rpc_user,
                                      g_rpc_password);
    pthread_mutex_unlock(&g_cookie_mutex);
    printf("RPC cookie rotated\n");
}

static void *cookie_rotate_thread_fn(void *arg)
{
    (void)arg;
    while (atomic_load(&g_cookie_rotate_running)) {
        for (int i = 0; i < g_cookie_rotate_sec &&
             atomic_load(&g_cookie_rotate_running); i++)
            sleep(1);
        thread_liveness_beat(&g_rpc_cookie_liveness, -1);
        if (atomic_load(&g_cookie_rotate_running))
            rpc_http_cookie_rotate();
    }
    return NULL;
}

int rpc_http_cookie_rotate_sec(void)
{
    return g_cookie_rotate_sec;
}

void rpc_http_auth_configure(const char *rpc_user, const char *rpc_password,
                             const char *datadir, uint16_t port)
{
    pthread_mutex_lock(&g_cookie_mutex);
    g_rpc_user[0] = '\0';
    g_rpc_password[0] = '\0';
    memory_cleanse(g_rpc_password_prev, sizeof(g_rpc_password_prev));
    g_cookie_file[0] = '\0';
    g_rpc_port_file[0] = '\0';
    g_auth_required = false;
    g_cookie_mode = false;

    if (rpc_user && rpc_password) {
        snprintf(g_rpc_user, sizeof(g_rpc_user), "%s", rpc_user);
        snprintf(g_rpc_password, sizeof(g_rpc_password), "%s",
                 rpc_password);
        g_auth_required = true;
    } else if (datadir) {
        snprintf(g_rpc_user, sizeof(g_rpc_user), "__cookie__");
        uint64_t r1 = GetRand(UINT64_MAX);
        uint64_t r2 = GetRand(UINT64_MAX);
        snprintf(g_rpc_password, sizeof(g_rpc_password), "%016llx%016llx",
                 (unsigned long long)r1, (unsigned long long)r2);
        g_auth_required = true;
        g_cookie_mode = true;

        snprintf(g_cookie_file, sizeof(g_cookie_file), "%s/.cookie", datadir);
        if (rpc_cookie_write_secure(g_cookie_file, g_rpc_user,
                                    g_rpc_password))
            printf("RPC cookie written to %s\n", g_cookie_file);

        snprintf(g_rpc_port_file, sizeof(g_rpc_port_file), "%s/.rpcport",
                 datadir);
        FILE *pf = fopen(g_rpc_port_file, "w");
        if (pf) {
            fprintf(pf, "%u", port);
            fclose(pf);
        }
    }

    g_cookie_rotate_sec = 86400;
    const char *rot_env = getenv("ZCL_RPC_COOKIE_ROTATE_SEC");
    if (rot_env && *rot_env) {
        int value = atoi(rot_env);
        if (value >= 0)
            g_cookie_rotate_sec = value;
    }
    pthread_mutex_unlock(&g_cookie_mutex);
}

void rpc_http_auth_start_rotation(void)
{
    if (!g_cookie_mode || g_cookie_rotate_sec <= 0 ||
        g_cookie_rotate_started)
        return;

    atomic_store(&g_cookie_rotate_running, true);
    if (thread_registry_spawn("zcl_rpc_cookie", cookie_rotate_thread_fn,
                              NULL, &g_cookie_rotate_thread) != 0) {
        atomic_store(&g_cookie_rotate_running, false);
        return;
    }
    g_cookie_rotate_started = true;
    thread_liveness_register(&g_rpc_cookie_liveness, "zcl_rpc_cookie", 0, 0);
    printf("RPC cookie rotation: every %d seconds\n", g_cookie_rotate_sec);
}

void rpc_http_auth_stop_rotation(void)
{
    atomic_store(&g_cookie_rotate_running, false);
    if (g_cookie_rotate_started) {
        pthread_join(g_cookie_rotate_thread, NULL);
        g_cookie_rotate_started = false;
        thread_liveness_retire(&g_rpc_cookie_liveness);
    }
}

void rpc_http_auth_stop(void)
{
    rpc_http_auth_stop_rotation();

    pthread_mutex_lock(&g_cookie_mutex);
    if (g_cookie_file[0]) {
        unlink(g_cookie_file);
        g_cookie_file[0] = '\0';
    }
    if (g_rpc_port_file[0]) {
        unlink(g_rpc_port_file);
        g_rpc_port_file[0] = '\0';
    }
    g_auth_required = false;
    g_cookie_mode = false;
    memory_cleanse(g_rpc_user, sizeof(g_rpc_user));
    memory_cleanse(g_rpc_password, sizeof(g_rpc_password));
    memory_cleanse(g_rpc_password_prev, sizeof(g_rpc_password_prev));
    pthread_mutex_unlock(&g_cookie_mutex);
}
