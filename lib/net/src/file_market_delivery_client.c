/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Buyer-side dialing half of zfileget.v3 paid delivery: session fetches and
 * endpoint connects where every receive/send step shares one absolute
 * deadline. Split from file_market_delivery.c (E1 file-size ceiling);
 * request verification, freshness, and the authorize-before-read gate stay
 * there so server policy has exactly one home. */

#include "net/file_market_delivery.h"
#include "net/file_market_delivery_internal.h"

#include "net/file_market.h"
#include "net/file_service.h"
#include "platform/time_compat.h"
#include "support/cleanse.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static bool delivery_deadline_active(int64_t deadline_ms)
{
    if (deadline_ms == INT64_MAX)
        return true;
    int64_t now_ms = platform_time_monotonic_ms();
    return now_ms > 0 && now_ms < deadline_ms;
}

enum file_market_delivery_status file_market_delivery_fetch_session_until(
    struct fs_session *session, const uint8_t network_genesis[32],
    const uint8_t offer_id[32], uint32_t chunk_index,
    const uint8_t buyer_pubkey[32], const uint8_t buyer_seed[32],
    int64_t deadline_ms, struct file_market_delivery_chunk *out_chunk)
{
    if (out_chunk)
        memset(out_chunk, 0, sizeof(*out_chunk));
    if (!session || !session->key_established || !network_genesis ||
        !offer_id || !buyer_pubkey || !buyer_seed || !out_chunk)
        return FILE_MARKET_DELIVERY_MALFORMED;
    if (!delivery_deadline_active(deadline_ms))
        return FILE_MARKET_DELIVERY_RESOURCE_LIMIT;

    struct file_market_delivery_request request;
    memset(&request, 0, sizeof(request));
    request.version = FILE_MARKET_DELIVERY_VERSION;
    memcpy(request.network_genesis, network_genesis, 32);
    memcpy(request.offer_id, offer_id, 32);
    request.chunk_index = chunk_index;
    memcpy(request.buyer_pubkey, buyer_pubkey, 32);
    file_market_delivery_session_id(network_genesis, session->our_nonce,
                                    session->peer_nonce,
                                    request.session_id);
    if (file_market_delivery_request_seal(&request, buyer_seed) !=
        FILE_MARKET_DELIVERY_OK)
        return FILE_MARKET_DELIVERY_UNAUTHENTICATED;
    uint8_t request_wire[FILE_MARKET_DELIVERY_WIRE_BYTES];
    if (file_market_delivery_request_encode(&request, request_wire) !=
            FILE_MARKET_DELIVERY_OK ||
        !fs_send_frame_until(session, FS_REQUEST, request_wire,
                             sizeof(request_wire), deadline_ms))
        return delivery_deadline_active(deadline_ms)
            ? FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN
            : FILE_MARKET_DELIVERY_RESOURCE_LIMIT;

    uint8_t frame_type = 0;
    const uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    struct file_market_delivery_reply reply;
    if (!fs_recv_frame_until(session, &frame_type, &payload, &payload_len,
                             deadline_ms))
        return delivery_deadline_active(deadline_ms)
            ? FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN
            : FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
    if (!delivery_deadline_active(deadline_ms))
        return FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
    if (frame_type != FS_MARKET_REPLY ||
        !file_market_delivery_reply_decode(payload, payload_len, &reply) ||
        memcmp(reply.offer_id, offer_id, 32) != 0 ||
        reply.chunk_index != chunk_index)
        return FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN;
    if (reply.status != FILE_MARKET_DELIVERY_READY)
        return reply.status;
    if (reply.size == 0 || reply.size > FILE_MARKET_CHUNK_SIZE ||
        !delivery_bytes_nonzero(reply.sha3, 32))
        return FILE_MARKET_DELIVERY_MALFORMED;

    uint8_t *data = NULL;
    uint32_t size = 0;
    if (!fs_recv_chunk_private_until(session, &data, &size, reply.size,
                                     reply.sha3, deadline_ms) ||
        !data || size != reply.size) {
        if (data && size > 0)
            memory_cleanse(data, size);
        free(data);
        return delivery_deadline_active(deadline_ms)
            ? FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN
            : FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
    }
    if (!delivery_deadline_active(deadline_ms)) {
        memory_cleanse(data, size);
        free(data);
        return FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
    }
    out_chunk->data = data;
    out_chunk->size = size;
    memcpy(out_chunk->sha3, reply.sha3, 32);
    return FILE_MARKET_DELIVERY_READY;
}

enum file_market_delivery_status file_market_delivery_fetch_session(
    struct fs_session *session, const uint8_t network_genesis[32],
    const uint8_t offer_id[32], uint32_t chunk_index,
    const uint8_t buyer_pubkey[32], const uint8_t buyer_seed[32],
    struct file_market_delivery_chunk *out_chunk)
{
    return file_market_delivery_fetch_session_until(
        session, network_genesis, offer_id, chunk_index, buyer_pubkey,
        buyer_seed, INT64_MAX, out_chunk);
}

static int delivery_connect_endpoint(const uint8_t peer_ip[16],
                                     uint16_t peer_port,
                                     int64_t deadline_ms)
{
    if (!peer_ip || !delivery_bytes_nonzero(peer_ip, 16) || peer_port == 0)
        return -1;
    int64_t now_ms = platform_time_monotonic_ms();
    if (deadline_ms != INT64_MAX &&
        (now_ms <= 0 || now_ms >= deadline_ms))
        return -1;
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(peer_port);
    memcpy(&addr.sin6_addr, peer_ip, 16);
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return -1;
    }
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno == EINPROGRESS) {
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(fd, &writefds);
        struct timeval timeout = { .tv_sec = 10, .tv_usec = 0 };
        if (deadline_ms != INT64_MAX) {
            now_ms = platform_time_monotonic_ms();
            if (now_ms <= 0 || now_ms >= deadline_ms) {
                close(fd);
                return -1;
            }
            int64_t remain_ms = deadline_ms - now_ms;
            if (remain_ms < 10000) {
                timeout.tv_sec = (time_t)(remain_ms / 1000);
                timeout.tv_usec = (suseconds_t)((remain_ms % 1000) * 1000);
            }
        }
        rc = select(fd + 1, NULL, &writefds, NULL, &timeout);
        int socket_error = 0;
        socklen_t error_len = sizeof(socket_error);
        if (rc <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR,
                                  &socket_error, &error_len) != 0 ||
            socket_error != 0 || !delivery_deadline_active(deadline_ms)) {
            close(fd);
            return -1;
        }
    } else if (rc < 0) {
        close(fd);
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags) != 0) {
        close(fd);
        return -1;
    }
    struct timeval io_timeout = { .tv_sec = 30, .tv_usec = 0 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                     &io_timeout, sizeof(io_timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                     &io_timeout, sizeof(io_timeout));
    return fd;
}

enum file_market_delivery_status file_market_delivery_fetch_endpoint(
    const uint8_t peer_ip[16], uint16_t peer_port,
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32],
    struct file_market_delivery_chunk *out_chunk)
{
    return file_market_delivery_fetch_endpoint_until(
        peer_ip, peer_port, network_genesis, offer_id, chunk_index,
        buyer_pubkey, buyer_seed, INT64_MAX, out_chunk);
}

enum file_market_delivery_status file_market_delivery_fetch_endpoint_until(
    const uint8_t peer_ip[16], uint16_t peer_port,
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32], int64_t deadline_ms,
    struct file_market_delivery_chunk *out_chunk)
{
    if (out_chunk)
        memset(out_chunk, 0, sizeof(*out_chunk));
    int fd = delivery_connect_endpoint(peer_ip, peer_port, deadline_ms);
    if (fd < 0)
        return delivery_deadline_active(deadline_ms)
            ? FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN
            : FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
    struct fs_session session;
    fs_session_init(&session, fd);
    /* The existing file-service responder derives its transport key from the
     * zero root. Paid-file authenticity comes from the signed offer/request,
     * exact payment authority, session MAC, and complete content manifest;
     * do not invent a different handshake secret in this sibling client. */
    uint8_t transport_root[32] = {0};
    enum file_market_delivery_status status =
        FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN;
    if (fs_handshake_until(&session, transport_root, true, deadline_ms))
        status = file_market_delivery_fetch_session_until(
            &session, network_genesis, offer_id, chunk_index,
            buyer_pubkey, buyer_seed, deadline_ms, out_chunk);
    else if (!delivery_deadline_active(deadline_ms))
        status = FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
    fs_session_cleanup(&session);
    close(fd);
    return status;
}
