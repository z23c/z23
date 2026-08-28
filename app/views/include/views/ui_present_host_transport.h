/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private authenticated wire boundary for the native presentation host. */

#ifndef ZCL_VIEWS_UI_PRESENT_HOST_TRANSPORT_H
#define ZCL_VIEWS_UI_PRESENT_HOST_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
typedef intptr_t ui_host_transport_t;
#define UI_HOST_TRANSPORT_INVALID ((ui_host_transport_t)-1)
#else
typedef int ui_host_transport_t;
#define UI_HOST_TRANSPORT_INVALID (-1)
#endif

#define UI_HOST_PROTOCOL_VERSION 4u
#define UI_HOST_REQUEST_BYTES 32u
#define UI_HOST_REPLY_BYTES 48u
#define UI_HOST_NONCE_BYTES 16u
#define UI_HOST_FLAG_WAIT_EVENT 1u
#define UI_HOST_PHASE_READY 1u
#define UI_HOST_PHASE_EVENT 2u
#define UI_HOST_STATUS_OK 0u
#define UI_HOST_STATUS_REJECTED 1u
#define UI_HOST_STATUS_CAPACITY 2u
#define UI_HOST_STATUS_REQUEST_BUSY 3u

ui_host_transport_t ui_host_transport_connect_once(void);
ui_host_transport_t ui_host_transport_listen(void);
ui_host_transport_t ui_host_transport_accept(ui_host_transport_t *listener,
                                             int timeout_ms);
void ui_host_transport_close(ui_host_transport_t stream);
void ui_host_transport_cleanup(void);
bool ui_host_transport_peer_allowed(ui_host_transport_t client);
bool ui_host_transport_send_all(ui_host_transport_t fd,
                                const uint8_t *bytes, size_t length);
bool ui_host_transport_recv_all(ui_host_transport_t fd, uint8_t *bytes,
                                size_t length,
                                int timeout_ms);
bool ui_host_transport_nonce(uint8_t nonce[UI_HOST_NONCE_BYTES]);
void ui_host_transport_request_header(
    uint8_t out[UI_HOST_REQUEST_BYTES], uint16_t flags, uint32_t model_len,
    const uint8_t nonce[UI_HOST_NONCE_BYTES]);
bool ui_host_transport_parse_request_header(
    const uint8_t in[UI_HOST_REQUEST_BYTES], uint16_t *flags,
    uint32_t *model_len, uint8_t nonce[UI_HOST_NONCE_BYTES]);
void ui_host_transport_reply(
    uint8_t out[UI_HOST_REPLY_BYTES], uint16_t phase, uint32_t status,
    uint32_t value, uint32_t payload_len, uint64_t elapsed_us,
    const uint8_t nonce[UI_HOST_NONCE_BYTES]);
bool ui_host_transport_parse_reply(
    const uint8_t in[UI_HOST_REPLY_BYTES], uint16_t expected_phase,
    uint32_t *status, uint32_t *value, uint32_t *payload_len,
    uint64_t *elapsed_us,
    const uint8_t nonce[UI_HOST_NONCE_BYTES]);

#endif /* ZCL_VIEWS_UI_PRESENT_HOST_TRANSPORT_H */
