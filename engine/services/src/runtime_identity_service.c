/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

// one-result-type-ok:infallible-process-identity-snapshot

#include "services/runtime_identity_service.h"

#include "platform/rng.h"
#include "platform/time_compat.h"
#include "util/clientversion.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static pthread_once_t g_identity_once = PTHREAD_ONCE_INIT;
static struct runtime_identity_snapshot g_identity;

static void runtime_identity_init_once(void)
{
    uint8_t nonce[16] = {0};
    g_identity.process_id = (int64_t)getpid();
    g_identity.initialized_at_unix_us = platform_time_realtime_us();
    g_identity.initialized_at_monotonic_us = platform_time_monotonic_us();
    bool have_nonce = rng_fill(nonce, sizeof(nonce));
    char nonce_hex[33];
    for (size_t i = 0; i < sizeof(nonce); i++)
        snprintf(&nonce_hex[i * 2], 3, "%02x", nonce[i]);
    nonce_hex[32] = '\0';
    if (have_nonce) {
        snprintf(g_identity.instance_id, sizeof(g_identity.instance_id),
                 "%s:%lld:%s", zcl_build_source_id_sha256(),
                 (long long)g_identity.process_id, nonce_hex);
    } else {
        snprintf(g_identity.instance_id, sizeof(g_identity.instance_id),
                 "%s:%lld:%lld:%lld", zcl_build_source_id_sha256(),
                 (long long)g_identity.process_id,
                 (long long)g_identity.initialized_at_unix_us,
                 (long long)g_identity.initialized_at_monotonic_us);
    }
}

void runtime_identity_get(struct runtime_identity_snapshot *out)
{
    if (!out)
        return;
    pthread_once(&g_identity_once, runtime_identity_init_once);
    *out = g_identity;
}
