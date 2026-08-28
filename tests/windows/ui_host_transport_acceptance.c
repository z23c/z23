/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless acceptance for the owner-only Windows presentation pipe. */

#include "views/ui_present_host_transport.h"
#include "base/log_level.h"

#include <stdint.h>
#include <stdio.h>
#include <windows.h>

/* The transport object also contains the separately tested nonce helper. */
bool rng_fill(uint8_t *out, size_t length)
{
    for (size_t i = 0; i < length; i++) out[i] = (uint8_t)(i + 1u);
    return true;
}

enum zcl_log_level zcl_log_level_get(void)
{
    return ZCL_LOG_OFF;
}

struct server_context {
    ui_host_transport_t listener;
    bool accepted;
};

static DWORD WINAPI server_main(void *opaque)
{
    struct server_context *context = opaque;
    ui_host_transport_t client = ui_host_transport_accept(
        &context->listener, 3000);
    uint8_t request[4] = {0};
    static const uint8_t reply[4] = {'p', 'o', 'n', 'g'};
    bool exchanged = client != UI_HOST_TRANSPORT_INVALID &&
        ui_host_transport_peer_allowed(client) &&
        ui_host_transport_recv_all(client, request, sizeof(request), 3000) &&
        request[0] == 'p' && request[1] == 'i' && request[2] == 'n' &&
        request[3] == 'g' &&
        ui_host_transport_send_all(client, reply, sizeof(reply));
    uint8_t absent = 0;
    ULONGLONG started = GetTickCount64();
    bool timed_out = exchanged &&
        !ui_host_transport_recv_all(client, &absent, sizeof(absent), 25);
    ULONGLONG elapsed = GetTickCount64() - started;
    context->accepted = exchanged && timed_out && elapsed >= 10u &&
                        elapsed < 1000u;
    ui_host_transport_close(client);
    return context->accepted ? 0u : 1u;
}

int main(void)
{
    struct server_context context = {
        .listener = ui_host_transport_listen(),
        .accepted = false,
    };
    if (context.listener == UI_HOST_TRANSPORT_INVALID) return 1;
    HANDLE thread = CreateThread(NULL, 0, server_main, &context, 0, NULL);
    if (!thread) return 2;
    ui_host_transport_t client = UI_HOST_TRANSPORT_INVALID;
    for (unsigned attempt = 0; attempt < 100u; attempt++) {
        client = ui_host_transport_connect_once();
        if (client != UI_HOST_TRANSPORT_INVALID) break;
        Sleep(5);
    }
    static const uint8_t request[4] = {'p', 'i', 'n', 'g'};
    uint8_t reply[4] = {0};
    bool exchanged = client != UI_HOST_TRANSPORT_INVALID &&
        ui_host_transport_send_all(client, request, sizeof(request)) &&
        ui_host_transport_recv_all(client, reply, sizeof(reply), 3000) &&
        reply[0] == 'p' && reply[1] == 'o' && reply[2] == 'n' &&
        reply[3] == 'g';
    if (exchanged) Sleep(50);
    ui_host_transport_close(client);
    DWORD wait = WaitForSingleObject(thread, 5000);
    DWORD exit_code = 1;
    if (wait == WAIT_OBJECT_0) (void)GetExitCodeThread(thread, &exit_code);
    CloseHandle(thread);
    ui_host_transport_close(context.listener);
    ui_host_transport_cleanup();
    if (!exchanged || !context.accepted || exit_code != 0) {
        (void)fprintf(stderr, "exchange=%d accepted=%d server=%lu error=%lu\n",
                      exchanged, context.accepted, (unsigned long)exit_code,
                      (unsigned long)GetLastError());
        return 3;
    }
    (void)puts("windows ui host named-pipe transport acceptance: ok");
    return 0;
}
