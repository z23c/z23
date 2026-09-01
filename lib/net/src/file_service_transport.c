/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Cross-platform encrypted frame and authenticated chunk transport
 * for the overlay file service. */

#include "net/file_service.h"

#include "base/log_macros.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "platform/socket_compat.h"
#include "platform/time_compat.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FS_FRAME_RECV_BUDGET_MS 30000
#define FS_PUBLIC_IO_BASE_BUDGET_MS INT64_C(30000)
#define FS_PUBLIC_IO_MIN_BYTES_PER_SEC (256u * 1024u)
#define FS_FAST_CHUNK_MAX (60u * 1024u * 1024u)

static const uint8_t k_fs_rom_refusal_mac_tag[32] = {'R', 'R', 'E', 'F'};

static bool fs_socket_valid(platform_socket_t socket)
{
    return socket != PLATFORM_SOCKET_INVALID;
}

static const char *fs_socket_error_text(int error, char out[64])
{
    return platform_socket_error_string(error, out, 64);
}

void fs_session_init(struct fs_session *session, platform_socket_t socket)
{
    if (!session)
        return;
    memset(session, 0, sizeof(*session));
    session->fd = socket;
    session->start_monotonic_ms = platform_time_monotonic_ms();

    if (!fs_socket_valid(socket))
        return;
    (void)platform_socket_set_no_delay(socket, true);
    (void)platform_socket_set_send_buffer(socket, 4 * 1024 * 1024);
    (void)platform_socket_set_receive_buffer(socket, 4 * 1024 * 1024);
}

double fs_session_mbps(const struct fs_session *session)
{
    if (!session)
        return 0.0;
    int64_t now_ms = platform_time_monotonic_ms();
    int64_t elapsed_ms = 1000;
    if (session->start_monotonic_ms > 0 &&
        now_ms > session->start_monotonic_ms)
        elapsed_ms = now_ms - session->start_monotonic_ms;
    if (elapsed_ms < 1000)
        elapsed_ms = 1000;
    uint64_t total = session->bytes_sent + session->bytes_received;
    return (double)total * 1000.0 /
           (1048576.0 * (double)elapsed_ms);
}

/* Bound the whole outbound record, not each send operation. A socket timeout
 * alone is only an inactivity timeout: a slow reader can reset it forever by
 * accepting a few bytes per call. */
static bool public_io_deadline_from(int64_t start_ms, size_t wire_bytes,
                                    int64_t *deadline_ms)
{
    if (!deadline_ms)
        LOG_FAIL("filesvc", "public I/O deadline output is null");
    if (start_ms <= 0)
        LOG_FAIL("filesvc", "monotonic public I/O start unavailable");
    uint64_t transfer_seconds =
        (uint64_t)wire_bytes / FS_PUBLIC_IO_MIN_BYTES_PER_SEC;
    if (wire_bytes % FS_PUBLIC_IO_MIN_BYTES_PER_SEC != 0)
        transfer_seconds++;
    if (transfer_seconds >
        (uint64_t)(INT64_MAX - FS_PUBLIC_IO_BASE_BUDGET_MS) / 1000u)
        LOG_FAIL("filesvc", "public I/O deadline exceeds monotonic range");
    int64_t budget_ms = FS_PUBLIC_IO_BASE_BUDGET_MS +
        (int64_t)(transfer_seconds * 1000u);
    if (start_ms > INT64_MAX - budget_ms)
        LOG_FAIL("filesvc", "monotonic public I/O deadline overflow");
    *deadline_ms = start_ms + budget_ms;
    return true;
}

static bool send_io_deadline(size_t wire_bytes, int64_t *deadline_ms)
{
    return public_io_deadline_from(platform_time_monotonic_ms(), wire_bytes,
                                   deadline_ms);
}

static bool wait_for_socket(platform_socket_t socket, short events,
                            int64_t deadline_ms, short *revents)
{
    if (!revents || deadline_ms <= 0)
        LOG_FAIL("filesvc", "socket wait arguments are invalid");
    for (;;) {
        int64_t now_ms = platform_time_monotonic_ms();
        if (now_ms <= 0 || now_ms >= deadline_ms)
            LOG_FAIL("filesvc", "socket I/O exceeded absolute deadline");
        int64_t remain_ms = deadline_ms - now_ms;
        int timeout_ms = remain_ms > INT32_MAX ? INT32_MAX : (int)remain_ms;
        platform_socket_pollfd descriptor = {
            .fd = socket, .events = events, .revents = 0};
        int ready = platform_socket_poll(&descriptor, 1, timeout_ms);
        int error = ready < 0 ? platform_socket_last_error() : 0;
        if (ready < 0 && platform_socket_error_interrupted(error))
            continue;
        if (ready < 0) {
            char text[64];
            LOG_FAIL("filesvc", "socket poll failed: %s",
                     fs_socket_error_text(error, text));
        }
        if (ready == 0)
            LOG_FAIL("filesvc", "socket I/O exceeded absolute deadline");
        *revents = descriptor.revents;
        return true;
    }
}

static bool send_all_until(platform_socket_t socket, const uint8_t *buffer,
                           size_t length, int64_t deadline_ms)
{
    if ((!buffer && length != 0) || !fs_socket_valid(socket))
        LOG_FAIL("filesvc", "send_all arguments are invalid");
    bool blocking_legacy_send = deadline_ms == INT64_MAX;
    if (blocking_legacy_send) {
        int timeout_ms = 0;
        if (platform_socket_get_send_timeout(socket, &timeout_ms) != 0)
            LOG_FAIL("filesvc", "send_all could not read socket timeout");
        if (timeout_ms > 0) {
            int64_t now_ms = platform_time_monotonic_ms();
            if (now_ms <= 0 || now_ms > INT64_MAX - timeout_ms)
                LOG_FAIL("filesvc", "send_all socket deadline unavailable");
            deadline_ms = now_ms + timeout_ms;
            blocking_legacy_send = false;
        }
    }
    size_t sent = 0;
    while (sent < length) {
        /* INT64_MAX with no configured socket timeout is the legacy blocking
         * contract. Finite callers use the whole-record deadline below. */
        if (blocking_legacy_send) {
            int count = platform_socket_send(socket, buffer + sent,
                                             length - sent);
            int error = count < 0 ? platform_socket_last_error() : 0;
            if (count < 0 && platform_socket_error_interrupted(error))
                continue;
            if (count <= 0) {
                char text[64];
                LOG_FAIL("filesvc", "send_all failed: %s",
                         fs_socket_error_text(error, text));
            }
            sent += (size_t)count;
            continue;
        }
        short revents = 0;
        if (!wait_for_socket(socket, PLATFORM_SOCKET_POLL_WRITE,
                             deadline_ms, &revents))
            return false;
        if (!(revents & PLATFORM_SOCKET_POLL_WRITE) ||
            (revents & PLATFORM_SOCKET_POLL_ERROR))
            LOG_FAIL("filesvc", "send_all poll revents=0x%x", revents);
        int count = platform_socket_send_nonblocking(
            socket, buffer + sent, length - sent);
        int error = count < 0 ? platform_socket_last_error() : 0;
        if (count < 0 && (platform_socket_error_interrupted(error) ||
                          platform_socket_error_would_block(error)))
            continue;
        if (count <= 0) {
            char text[64];
            LOG_FAIL("filesvc", "send_all failed: %s",
                     fs_socket_error_text(error, text));
        }
        sent += (size_t)count;
    }
    return true;
}

static bool recv_all_until(platform_socket_t socket, uint8_t *buffer,
                           size_t length, int64_t deadline_ms)
{
    if ((!buffer && length != 0) || !fs_socket_valid(socket))
        LOG_FAIL("filesvc", "recv_all arguments are invalid");
    size_t received = 0;
    while (received < length) {
        short revents = 0;
        if (!wait_for_socket(socket, PLATFORM_SOCKET_POLL_READ,
                             deadline_ms, &revents))
            return false;
        if (!(revents & (PLATFORM_SOCKET_POLL_READ |
                         PLATFORM_SOCKET_POLL_HANGUP)) ||
            (revents & PLATFORM_SOCKET_POLL_ERROR))
            LOG_FAIL("filesvc", "recv_all poll revents=0x%x", revents);
        int count = platform_socket_receive_nonblocking(
            socket, buffer + received, length - received);
        int error = count < 0 ? platform_socket_last_error() : 0;
        if (count < 0 && (platform_socket_error_interrupted(error) ||
                          platform_socket_error_would_block(error)))
            continue;
        if (count < 0) {
            char text[64];
            LOG_FAIL("filesvc", "recv_all failed: %s",
                     fs_socket_error_text(error, text));
        }
        if (count == 0)
            LOG_FAIL("filesvc", "peer closed after %zu/%zu bytes",
                     received, length);
        received += (size_t)count;
    }
    return true;
}

static bool encrypt_frame(const struct fs_session *session, uint8_t type,
                          const uint8_t *payload, uint32_t payload_len,
                          uint8_t out[FS_FRAME_SIZE], uint64_t counter)
{
    if (!session || !out || (!payload && payload_len != 0))
        LOG_FAIL("filesvc", "frame encryption arguments are invalid");
    if (payload_len > FS_MAX_PAYLOAD)
        LOG_FAIL("filesvc", "payload_len %u exceeds FS_MAX_PAYLOAD",
                 payload_len);

    uint8_t plain[FS_FRAME_SIZE - FS_MAC_SIZE] = {0};
    zcl_write_u32_le(plain, type);
    zcl_write_u32_le(plain + 4, payload_len);
    if (payload_len > 0)
        memcpy(plain + FS_HEADER_SIZE, payload, payload_len);

    uint8_t nonce[32] = {0};
    memcpy(nonce, &counter, sizeof(counter));
    size_t offset = 0;
    uint64_t block_counter = 0;
    while (offset < sizeof(plain)) {
        uint8_t key_stream[256];
        sha3_512_x4(session->key, nonce, block_counter, key_stream);
        block_counter += 4;
        size_t chunk = sizeof(plain) - offset;
        if (chunk > sizeof(key_stream))
            chunk = sizeof(key_stream);
        for (size_t i = 0; i < chunk; i++)
            plain[offset + i] ^= key_stream[i];
        memory_cleanse(key_stream, sizeof(key_stream));
        offset += chunk;
    }
    memcpy(out, plain, sizeof(plain));
    memory_cleanse(plain, sizeof(plain));

    struct sha3_256_ctx mac;
    sha3_256_init(&mac);
    sha3_256_write(&mac, session->key, sizeof(session->key));
    sha3_256_write(&mac, (const uint8_t *)&counter, sizeof(counter));
    sha3_256_write(&mac, out, FS_FRAME_SIZE - FS_MAC_SIZE);
    sha3_256_finalize(&mac, out + FS_FRAME_SIZE - FS_MAC_SIZE);
    memory_cleanse(&mac, sizeof(mac));
    return true;
}

static bool decrypt_frame(const struct fs_session *session,
                          const uint8_t in[FS_FRAME_SIZE], uint8_t *type_out,
                          uint8_t *payload_out, uint32_t *payload_len_out,
                          uint64_t counter)
{
    if (!session || !in || !type_out || !payload_out || !payload_len_out)
        LOG_FAIL("filesvc", "frame decryption arguments are invalid");
    const size_t cipher_len = FS_FRAME_SIZE - FS_MAC_SIZE;
    uint8_t expected_mac[FS_MAC_SIZE];
    struct sha3_256_ctx mac;
    sha3_256_init(&mac);
    sha3_256_write(&mac, session->key, sizeof(session->key));
    sha3_256_write(&mac, (const uint8_t *)&counter, sizeof(counter));
    sha3_256_write(&mac, in, cipher_len);
    sha3_256_finalize(&mac, expected_mac);
    memory_cleanse(&mac, sizeof(mac));

    uint8_t difference = 0;
    for (size_t i = 0; i < sizeof(expected_mac); i++)
        difference |= in[cipher_len + i] ^ expected_mac[i];
    if (difference != 0)
        LOG_FAIL("filesvc", "frame MAC verification failed at counter=%llu",
                 (unsigned long long)counter);

    uint8_t plain[FS_FRAME_SIZE - FS_MAC_SIZE];
    memcpy(plain, in, cipher_len);
    uint8_t nonce[32] = {0};
    memcpy(nonce, &counter, sizeof(counter));
    size_t offset = 0;
    uint64_t block_counter = 0;
    while (offset < cipher_len) {
        uint8_t key_stream[256];
        sha3_512_x4(session->key, nonce, block_counter, key_stream);
        block_counter += 4;
        size_t chunk = cipher_len - offset;
        if (chunk > sizeof(key_stream))
            chunk = sizeof(key_stream);
        for (size_t i = 0; i < chunk; i++)
            plain[offset + i] ^= key_stream[i];
        memory_cleanse(key_stream, sizeof(key_stream));
        offset += chunk;
    }

    *type_out = plain[0];
    uint32_t payload_len = zcl_read_u32_le(plain + 4);
    if (payload_len > FS_MAX_PAYLOAD) {
        memory_cleanse(plain, sizeof(plain));
        LOG_FAIL("filesvc", "decrypted payload_len %u exceeds maximum",
                 payload_len);
    }
    if (payload_len > 0)
        memcpy(payload_out, plain + FS_HEADER_SIZE, payload_len);
    *payload_len_out = payload_len;
    memory_cleanse(plain, sizeof(plain));
    return true;
}

bool fs_send_frame(struct fs_session *session, uint8_t type,
                   const uint8_t *payload, uint32_t payload_len)
{
    int64_t deadline_ms = 0;
    if (!send_io_deadline(0, &deadline_ms))
        return false;
    return fs_send_frame_until(session, type, payload, payload_len,
                               deadline_ms);
}

bool fs_send_frame_until(struct fs_session *session, uint8_t type,
                         const uint8_t *payload, uint32_t payload_len,
                         int64_t deadline_ms)
{
    if (!session || !fs_socket_valid(session->fd))
        LOG_FAIL("filesvc", "frame send session is invalid");
    uint8_t frame[FS_FRAME_SIZE];
    if (!encrypt_frame(session, type, payload, payload_len, frame,
                       session->send_counter))
        return false;
    session->send_counter++;
    session->bytes_sent += FS_FRAME_SIZE;
    if (!send_all_until(session->fd, frame, sizeof(frame), deadline_ms)) {
        memory_cleanse(frame, sizeof(frame));
        return false;
    }
    memory_cleanse(frame, sizeof(frame));
    return true;
}

bool fs_recv_frame(struct fs_session *session, uint8_t *type_out,
                   const uint8_t **payload_out, uint32_t *payload_len_out)
{
    return fs_recv_frame_until(session, type_out, payload_out,
                               payload_len_out, INT64_MAX);
}

bool fs_recv_frame_until(struct fs_session *session, uint8_t *type_out,
                         const uint8_t **payload_out,
                         uint32_t *payload_len_out,
                         int64_t caller_deadline_ms)
{
    if (!session || !type_out || !payload_out || !payload_len_out ||
        !fs_socket_valid(session->fd))
        LOG_FAIL("filesvc", "frame receive arguments are invalid");
    int64_t now_ms = platform_time_monotonic_ms();
    if (now_ms <= 0 || now_ms > INT64_MAX - FS_FRAME_RECV_BUDGET_MS)
        LOG_FAIL("filesvc", "frame receive deadline unavailable");
    int64_t deadline_ms = now_ms + FS_FRAME_RECV_BUDGET_MS;
    if (caller_deadline_ms <= 0)
        LOG_FAIL("filesvc", "frame receive caller deadline is invalid");
    if (caller_deadline_ms < deadline_ms)
        deadline_ms = caller_deadline_ms;
    uint8_t frame[FS_FRAME_SIZE];
    if (!recv_all_until(session->fd, frame, sizeof(frame), deadline_ms))
        return false;
    if (!decrypt_frame(session, frame, type_out, session->recv_payload,
                       payload_len_out, session->recv_counter)) {
        memory_cleanse(frame, sizeof(frame));
        return false;
    }
    memory_cleanse(frame, sizeof(frame));
    session->recv_counter++;
    session->bytes_received += FS_FRAME_SIZE;
    *payload_out = session->recv_payload;
    return true;
}

bool fs_send_chunk_fast(struct fs_session *session, const uint8_t *data,
                        uint32_t size, const uint8_t digest[32])
{
    if (!session || !data || !digest || !fs_socket_valid(session->fd) ||
        size == 0 || size > FS_FAST_CHUNK_MAX)
        LOG_FAIL("filesvc", "send_chunk_fast arguments are invalid size=%u",
                 size);
    int64_t deadline_ms = 0;
    if (!send_io_deadline(4u + (size_t)size + 32u, &deadline_ms))
        return false;
    uint8_t header[4];
    zcl_write_u32_le(header, size);
    if (!send_all_until(session->fd, header, sizeof(header), deadline_ms) ||
        !send_all_until(session->fd, data, size, deadline_ms))
        return false;

    uint8_t mac_bytes[32];
    struct sha3_256_ctx mac;
    sha3_256_init(&mac);
    sha3_256_write(&mac, session->key, sizeof(session->key));
    sha3_256_write(&mac, (const uint8_t *)&session->send_counter,
                   sizeof(session->send_counter));
    sha3_256_write(&mac, digest, 32);
    sha3_256_write(&mac, data, size);
    sha3_256_finalize(&mac, mac_bytes);
    memory_cleanse(&mac, sizeof(mac));
    bool sent = send_all_until(session->fd, mac_bytes, sizeof(mac_bytes),
                               deadline_ms);
    memory_cleanse(mac_bytes, sizeof(mac_bytes));
    if (!sent)
        return false;
    session->bytes_sent += 4u + size + 32u;
    session->send_counter++;
    return true;
}

bool fs_send_chunk_refusal(struct fs_session *session, uint8_t reason)
{
    if (!session || !fs_socket_valid(session->fd))
        LOG_FAIL("filesvc", "send_chunk_refusal session is invalid");
    int64_t deadline_ms = 0;
    if (!send_io_deadline(0, &deadline_ms))
        return false;
    uint32_t sentinel = FS_ROM_REFUSAL_SENTINEL;
    uint8_t header[4];
    zcl_write_u32_le(header, sentinel);
    if (!send_all_until(session->fd, header, sizeof(header), deadline_ms) ||
        !send_all_until(session->fd, &reason, 1, deadline_ms))
        return false;
    uint8_t mac_bytes[32];
    struct sha3_256_ctx mac;
    sha3_256_init(&mac);
    sha3_256_write(&mac, session->key, sizeof(session->key));
    sha3_256_write(&mac, (const uint8_t *)&session->send_counter,
                   sizeof(session->send_counter));
    sha3_256_write(&mac, k_fs_rom_refusal_mac_tag,
                   sizeof(k_fs_rom_refusal_mac_tag));
    sha3_256_write(&mac, &reason, 1);
    sha3_256_finalize(&mac, mac_bytes);
    memory_cleanse(&mac, sizeof(mac));
    bool sent = send_all_until(session->fd, mac_bytes, sizeof(mac_bytes),
                               deadline_ms);
    memory_cleanse(mac_bytes, sizeof(mac_bytes));
    if (!sent)
        return false;
    session->bytes_sent += 37u;
    session->send_counter++;
    return true;
}

bool fs_recv_chunk_fast(struct fs_session *session, uint8_t **out,
                        uint32_t *out_size,
                        const uint8_t expected_digest[32])
{
    if (!session || !out || !out_size || !expected_digest ||
        !fs_socket_valid(session->fd))
        LOG_FAIL("filesvc", "recv_chunk_fast arguments are invalid");
    *out = NULL;
    *out_size = 0;
    int64_t start_ms = platform_time_monotonic_ms();
    int64_t deadline_ms = 0;
    if (!public_io_deadline_from(start_ms, 0, &deadline_ms))
        return false;
    uint8_t header[4];
    if (!recv_all_until(session->fd, header, sizeof(header), deadline_ms))
        return false;
    uint32_t size = zcl_read_u32_le(header);
    if (size == 0 || size > FS_FAST_CHUNK_MAX)
        LOG_FAIL("filesvc", "recv_chunk_fast invalid chunk size=%u", size);
    if (!public_io_deadline_from(start_ms, 4u + (size_t)size + 32u,
                                 &deadline_ms))
        return false;

    uint8_t *buffer = zcl_malloc(size, "file_recv_buf");
    if (!buffer)
        LOG_FAIL("filesvc", "recv_chunk_fast allocation failed size=%u", size);
    uint8_t mac_wire[32];
    if (!recv_all_until(session->fd, buffer, size, deadline_ms) ||
        !recv_all_until(session->fd, mac_wire, sizeof(mac_wire), deadline_ms)) {
        free(buffer);
        return false;
    }

    uint8_t mac_expected[32];
    struct sha3_256_ctx mac;
    sha3_256_init(&mac);
    sha3_256_write(&mac, session->key, sizeof(session->key));
    sha3_256_write(&mac, (const uint8_t *)&session->recv_counter,
                   sizeof(session->recv_counter));
    sha3_256_write(&mac, expected_digest, 32);
    sha3_256_write(&mac, buffer, size);
    sha3_256_finalize(&mac, mac_expected);
    memory_cleanse(&mac, sizeof(mac));
    uint8_t difference = 0;
    for (size_t i = 0; i < sizeof(mac_wire); i++)
        difference |= mac_wire[i] ^ mac_expected[i];
    memory_cleanse(mac_wire, sizeof(mac_wire));
    memory_cleanse(mac_expected, sizeof(mac_expected));
    if (difference != 0) {
        free(buffer);
        LOG_FAIL("filesvc", "recv_chunk_fast MAC verification failed");
    }

    uint8_t actual_digest[32];
    sha3_256(buffer, size, actual_digest);
    bool digest_matches = memcmp(actual_digest, expected_digest, 32) == 0;
    memory_cleanse(actual_digest, sizeof(actual_digest));
    if (!digest_matches) {
        free(buffer);
        LOG_FAIL("filesvc", "recv_chunk_fast content digest mismatch");
    }
    int64_t completed_ms = platform_time_monotonic_ms();
    if (completed_ms <= 0 || completed_ms >= deadline_ms) {
        free(buffer);
        LOG_FAIL("filesvc", "recv_chunk_fast verification exceeded deadline");
    }
    session->recv_counter++;
    session->bytes_received += 4u + size + 32u;
    *out = buffer;
    *out_size = size;
    return true;
}
