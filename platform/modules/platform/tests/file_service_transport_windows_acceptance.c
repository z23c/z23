/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Native WinSock acceptance for encrypted file-service frames and
 * authenticated C23 Commons chunks. */

#if defined(_WIN32)

#include "base/safe_alloc.h"
#include "crypto/sha3.h"
#include "net/file_service.h"
#include "platform/socket_compat.h"
#include "platform/time_compat.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_CHUNK_BYTES (256u * 1024u)

struct sender_args {
    struct fs_session *session;
    const uint8_t *frame_payload;
    uint32_t frame_size;
    const uint8_t *chunk;
    uint32_t chunk_size;
    uint8_t chunk_digest[32];
    bool ok;
};

struct timeout_sender_args {
    struct fs_session *session;
    bool ok;
    _Atomic bool done;
};

static void *send_records(void *opaque)
{
    struct sender_args *args = opaque;
    args->ok = fs_send_frame(args->session, FS_MANIFEST,
                             args->frame_payload, args->frame_size) &&
               fs_send_chunk_fast(args->session, args->chunk,
                                  args->chunk_size, args->chunk_digest);
    return NULL;
}

static void *send_timeout_record(void *opaque)
{
    struct timeout_sender_args *args = opaque;
    args->ok = fs_send_frame_until(args->session, FS_REQUEST, NULL, 0,
                                   INT64_MAX);
    atomic_store_explicit(&args->done, true, memory_order_release);
    return NULL;
}

static bool legacy_send_timeout_is_bounded(void)
{
    platform_socket_t pair[2] = {
        PLATFORM_SOCKET_INVALID, PLATFORM_SOCKET_INVALID};
    if (!platform_socket_pair(pair))
        return false;
    struct fs_session sender;
    fs_session_init(&sender, pair[0]);
    sender.key[0] = 1;
    sender.key_established = true;
    bool configured = platform_socket_set_send_buffer(pair[0], 4096) == 0 &&
        platform_socket_set_receive_buffer(pair[1], 4096) == 0 &&
        platform_socket_set_send_timeout(pair[0], 50) == 0;
    uint8_t fill[4096] = {0};
    while (configured &&
           platform_socket_send_nonblocking(pair[0], fill, sizeof(fill)) > 0) {}

    struct timeout_sender_args args = {.session = &sender};
    pthread_t thread;
    bool started = configured &&
        pthread_create(&thread, NULL, send_timeout_record, &args) == 0; /* raw-pthread-ok: short-burst-joined-immediately */
    bool finished = false;
    for (unsigned i = 0; started && i < 500; i++) {
        if (atomic_load_explicit(&args.done, memory_order_acquire)) {
            finished = true;
            break;
        }
        platform_sleep_ms(1);
    }
    if (!finished) {
        platform_socket_close(pair[1]);
        pair[1] = PLATFORM_SOCKET_INVALID;
    }
    bool joined = !started || pthread_join(thread, NULL) == 0;
    if (pair[0] != PLATFORM_SOCKET_INVALID)
        platform_socket_close(pair[0]);
    if (pair[1] != PLATFORM_SOCKET_INVALID)
        platform_socket_close(pair[1]);
    return started && finished && joined && !args.ok;
}

static int refuse(const char *message, platform_socket_t pair[2],
                  uint8_t *chunk, uint8_t *received)
{
    fprintf(stderr, "file_service_transport_windows_acceptance: REFUSE: %s\n",
            message);
    if (pair) {
        if (pair[0] != PLATFORM_SOCKET_INVALID)
            platform_socket_close(pair[0]);
        if (pair[1] != PLATFORM_SOCKET_INVALID)
            platform_socket_close(pair[1]);
    }
    free(chunk);
    free(received);
    return 1;
}

int main(void)
{
    platform_socket_t pair[2] = {
        PLATFORM_SOCKET_INVALID, PLATFORM_SOCKET_INVALID};
    if (!platform_socket_pair(pair))
        return refuse("loopback socket pair unavailable", pair, NULL, NULL);

    struct fs_session sender, receiver;
    fs_session_init(&sender, pair[0]);
    fs_session_init(&receiver, pair[1]);
    for (size_t i = 0; i < sizeof(sender.key); i++)
        sender.key[i] = receiver.key[i] = (uint8_t)(i * 7u + 3u);
    sender.key_established = receiver.key_established = true;

    static const uint8_t frame_payload[] =
        "native-windows-c23-commons-transport";
    uint8_t *chunk = zcl_malloc(TEST_CHUNK_BYTES,
                                "windows_file_service_transport_chunk");
    if (!chunk)
        return refuse("chunk allocation failed", pair, NULL, NULL);
    for (size_t i = 0; i < TEST_CHUNK_BYTES; i++)
        chunk[i] = (uint8_t)((i * 29u + (i >> 8)) & 0xffu);

    struct sender_args args = {
        .session = &sender,
        .frame_payload = frame_payload,
        .frame_size = (uint32_t)(sizeof(frame_payload) - 1u),
        .chunk = chunk,
        .chunk_size = TEST_CHUNK_BYTES,
    };
    sha3_256(chunk, TEST_CHUNK_BYTES, args.chunk_digest);

    pthread_t thread;
    /* raw-pthread-ok: short-burst-joined-immediately */
    if (pthread_create(&thread, NULL, send_records, &args) != 0)
        return refuse("sender thread creation failed", pair, chunk, NULL);

    uint8_t type = 0;
    const uint8_t *received_frame = NULL;
    uint32_t received_frame_size = 0;
    bool frame_ok = fs_recv_frame(&receiver, &type, &received_frame,
                                  &received_frame_size) &&
        type == FS_MANIFEST && received_frame_size == args.frame_size &&
        memcmp(received_frame, frame_payload, args.frame_size) == 0;
    uint8_t *received_chunk = NULL;
    uint32_t received_chunk_size = 0;
    bool chunk_ok = frame_ok &&
        fs_recv_chunk_fast(&receiver, &received_chunk, &received_chunk_size,
                           args.chunk_digest) &&
        received_chunk_size == TEST_CHUNK_BYTES &&
        memcmp(received_chunk, chunk, TEST_CHUNK_BYTES) == 0;
    bool joined = pthread_join(thread, NULL) == 0;

    bool accounting_ok =
        sender.send_counter == 2 && receiver.recv_counter == 2 &&
        sender.bytes_sent == receiver.bytes_received &&
        sender.bytes_sent == FS_FRAME_SIZE + 4u + TEST_CHUNK_BYTES + 32u &&
        fs_session_mbps(&sender) > 0.0;
    if (!args.ok || !frame_ok || !chunk_ok || !joined || !accounting_ok)
        return refuse("frame/chunk parity or accounting failed", pair, chunk,
                      received_chunk);

    bool legacy_timeout_bounded = legacy_send_timeout_is_bounded();
    if (!legacy_timeout_bounded)
        return refuse("legacy frame send ignored SO_SNDTIMEO", pair, chunk,
                      received_chunk);

    platform_socket_close(pair[0]);
    platform_socket_close(pair[1]);
    free(chunk);
    free(received_chunk);
    puts("file_service_transport_windows_acceptance: PASS "
         "transport=WinSock frame_encrypted=true chunk_authenticated=true "
         "legacy_timeout_bounded=true bytes=327716");
    return 0;
}

#else
typedef int file_service_transport_windows_acceptance_not_built;
#endif
