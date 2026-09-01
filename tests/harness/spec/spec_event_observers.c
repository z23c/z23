/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Spec tests for event observer system. */

#include "test/test_core.h"
#include "event/event.h"
#include <string.h>
#include <stdio.h>

static int g_obs_fired;
static enum event_type g_obs_type;
static uint32_t g_obs_peer;
static char g_obs_payload[EVENT_PAYLOAD_SIZE];
static int g_ctx_val;

static void obs_fn(enum event_type type, uint32_t peer_id,
                    const void *payload, uint32_t payload_len, void *ctx) {
    (void)ctx;
    g_obs_fired++;
    g_obs_type = type;
    g_obs_peer = peer_id;
    if (payload && payload_len > 0 && payload_len < EVENT_PAYLOAD_SIZE) {
        memcpy(g_obs_payload, payload, payload_len);
        g_obs_payload[payload_len] = '\0';
    }
}

static void obs_ctx(enum event_type type, uint32_t peer_id,
                     const void *payload, uint32_t payload_len, void *ctx) {
    (void)type;(void)peer_id;(void)payload;(void)payload_len;
    if (ctx) g_ctx_val = *(int *)ctx;
}

static void obs_reset(void) {
    g_obs_fired = 0; g_obs_type = 0; g_obs_peer = 0;
    memset(g_obs_payload, 0, sizeof(g_obs_payload));
    g_ctx_val = 0;
}

int spec_event_observers(void)
{
    int failures = 0;
    printf("\n=== Event Observer System ===\n");

    {   printf("observer fires for subscribed type... ");
        event_log_init(); obs_reset();
        event_observe(EV_BLOCK_CONNECTED, obs_fn, NULL);
        event_emitf(EV_BLOCK_CONNECTED, 0, "h=500000");
        bool ok = g_obs_fired == 1 && g_obs_type == EV_BLOCK_CONNECTED
                  && strstr(g_obs_payload, "500000") != NULL;
        event_clear_all_observers();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("observer does NOT fire for other types... ");
        event_log_init(); obs_reset();
        event_observe(EV_BLOCK_CONNECTED, obs_fn, NULL);
        event_emitf(EV_TX_ACCEPTED, 0, "tx");
        bool ok = g_obs_fired == 0;
        event_clear_all_observers();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("multiple observers on same type all fire... ");
        event_log_init(); obs_reset();
        event_observe(EV_TIP_UPDATED, obs_fn, NULL);
        event_observe(EV_TIP_UPDATED, obs_fn, NULL);
        event_emitf(EV_TIP_UPDATED, 0, "tip");
        bool ok = g_obs_fired == 2;
        event_clear_all_observers();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("observer receives peer_id... ");
        event_log_init(); obs_reset();
        event_observe(EV_PEER_VERSION, obs_fn, NULL);
        event_emitf(EV_PEER_VERSION, 42, "hello");
        bool ok = g_obs_fired == 1 && g_obs_peer == 42;
        event_clear_all_observers();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("observer receives context pointer... ");
        event_log_init(); obs_reset();
        int magic = 99;
        event_observe(EV_NODE_READY, obs_ctx, &magic);
        event_emitf(EV_NODE_READY, 0, "ready");
        bool ok = g_ctx_val == 99;
        event_clear_all_observers();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("clear_observers removes type-specific... ");
        event_log_init(); obs_reset();
        event_observe(EV_BLOCK_CONNECTED, obs_fn, NULL);
        event_clear_observers(EV_BLOCK_CONNECTED);
        event_emitf(EV_BLOCK_CONNECTED, 0, "cleared");
        bool ok = g_obs_fired == 0;
        event_clear_all_observers();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("clear_all_observers removes everything... ");
        event_log_init(); obs_reset();
        event_observe(EV_BLOCK_CONNECTED, obs_fn, NULL);
        event_observe(EV_TX_ACCEPTED, obs_fn, NULL);
        event_clear_all_observers();
        event_emitf(EV_BLOCK_CONNECTED, 0, "a");
        event_emitf(EV_TX_ACCEPTED, 0, "b");
        bool ok = g_obs_fired == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("overflow: reject beyond max observers... ");
        event_log_init();
        bool ok = true;
        for (int i = 0; i < EVENT_MAX_OBSERVERS; i++)
            ok = ok && event_observe(EV_DB_ERROR, obs_fn, NULL);
        ok = ok && !event_observe(EV_DB_ERROR, obs_fn, NULL);
        event_clear_all_observers();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("Event observers: %d failures\n", failures);
    return failures;
}
