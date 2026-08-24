/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * zfileget.v2 encrypted delivery and authorize-before-read proofs. */

#include "test/test_core.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/curve25519.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "crypto/sha3_crypt.h"
#include "net/file_market_delivery.h"
#include "net/file_service.h"
#include "net/onion_v3_address.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define DELIVERY_CHECK(label, condition) do {                        \
    printf("file_market delivery: %s... ", (label));                \
    if (condition) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

struct delivery_fixture {
    enum file_market_delivery_authorization authorization;
    int authorize_calls;
    int load_calls;
    bool load_ok;
    bool corrupt_hash;
};

static enum file_market_delivery_authorization delivery_authorize(
    const uint8_t offer_id[32], const uint8_t buyer_pubkey[32],
    uint32_t chunk_index, void *ctx)
{
    struct delivery_fixture *fixture = ctx;
    fixture->authorize_calls++;
    if (!offer_id || !buyer_pubkey || chunk_index != 7)
        return FILE_MARKET_DELIVERY_REJECTED;
    return fixture->authorization;
}

static bool delivery_load(
    const uint8_t offer_id[32], uint32_t chunk_index,
    struct file_market_delivery_chunk *out, void *ctx)
{
    struct delivery_fixture *fixture = ctx;
    static const uint8_t payload[] = "paid-chunk-proof";
    fixture->load_calls++;
    if (!fixture->load_ok || !offer_id || chunk_index != 7 || !out)
        return false;
    out->data = zcl_malloc(sizeof(payload), "delivery_test_chunk");
    if (!out->data)
        return false;
    memcpy(out->data, payload, sizeof(payload));
    out->size = sizeof(payload);
    sha3_256(out->data, out->size, out->sha3);
    if (fixture->corrupt_hash)
        out->sha3[0] ^= 1;
    return true;
}

static bool delivery_request_fixture(
    struct fs_session *server,
    struct file_market_delivery_request *request,
    uint8_t wire[FILE_MARKET_DELIVERY_WIRE_BYTES], uint8_t buyer_seed[32])
{
    const struct chain_params *params = chain_params_get();
    uint8_t secret[32];
    if (!params)
        return false;
    memset(server, 0, sizeof(*server));
    memset(server->peer_nonce, 0x31, sizeof(server->peer_nonce));
    memset(server->our_nonce, 0x42, sizeof(server->our_nonce));
    memset(request, 0, sizeof(*request));
    memset(buyer_seed, 0x53, 32);
    request->version = FILE_MARKET_DELIVERY_VERSION;
    memcpy(request->network_genesis,
           params->consensus.hashGenesisBlock.data, 32);
    memset(request->offer_id, 0x64, sizeof(request->offer_id));
    request->chunk_index = 7;
    ed25519_keypair(request->buyer_pubkey, secret, buyer_seed);
    file_market_delivery_session_id(
        request->network_genesis, server->peer_nonce, server->our_nonce,
        request->session_id);
    return file_market_delivery_request_seal(request, buyer_seed) ==
               FILE_MARKET_DELIVERY_OK &&
           file_market_delivery_request_encode(request, wire) ==
               FILE_MARKET_DELIVERY_OK;
}

static bool delivery_recv_exact(int fd, uint8_t *out, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, out + got, len - got, 0);
        if (n <= 0)
            return false;
        got += (size_t)n;
    }
    return true;
}

static bool delivery_send_exact(int fd, const uint8_t *data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0)
            return false;
        sent += (size_t)n;
    }
    return true;
}

struct delivery_handshake_call {
    struct fs_session session;
    uint8_t root[32];
    bool initiator;
    bool ok;
    _Atomic bool done;
};

static void *delivery_handshake_call_main(void *opaque)
{
    struct delivery_handshake_call *call = opaque;
    call->ok = fs_handshake(&call->session, call->root, call->initiator);
    atomic_store_explicit(&call->done, true, memory_order_release);
    return NULL;
}

/* Relay and record a real handshake plus paid ciphertext. A recorder using
 * every public handshake byte and the historic KDF must fail to open it. */
static bool delivery_handshake_capture_has_no_session_key(void)
{
    static const uint8_t paid_plain[] = "paid-wire-capture-proof";
    int initiator_pair[2] = {-1, -1};
    int responder_pair[2] = {-1, -1};
    int attacker_pair[2] = {-1, -1};
    pthread_t initiator_thread, responder_thread;
    bool initiator_started = false, responder_started = false;
    struct delivery_handshake_call initiator = {.initiator = true};
    struct delivery_handshake_call responder = {.initiator = false};
    uint8_t initiator_wire[64], responder_wire[64];
    uint8_t private_wire[4 + sizeof(paid_plain) + POLY1305_TAG_SIZE];
    uint8_t paid_sha3[32], captured_derivation[32];
    uint8_t *opened = NULL, *attacker_opened = NULL;
    uint32_t opened_size = 0, attacker_size = 0;
    bool relayed = false;
    bool result = false;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, initiator_pair) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, responder_pair) != 0)
        goto done;
    fs_session_init(&initiator.session, initiator_pair[0]);
    fs_session_init(&responder.session, responder_pair[0]);
    responder_started = pthread_create(&responder_thread, NULL,
                                       delivery_handshake_call_main,
                                       &responder) == 0;
    initiator_started = responder_started &&
        pthread_create(&initiator_thread, NULL, delivery_handshake_call_main,
                       &initiator) == 0;
    if (!initiator_started)
        goto done;

    relayed = delivery_recv_exact(initiator_pair[1], initiator_wire, 32) &&
        delivery_send_exact(responder_pair[1], initiator_wire, 32) &&
        delivery_recv_exact(responder_pair[1], responder_wire, 32) &&
        delivery_send_exact(initiator_pair[1], responder_wire, 32) &&
        delivery_recv_exact(initiator_pair[1], initiator_wire + 32, 32) &&
        delivery_send_exact(responder_pair[1], initiator_wire + 32, 32) &&
        delivery_recv_exact(responder_pair[1], responder_wire + 32, 32) &&
        delivery_send_exact(initiator_pair[1], responder_wire + 32, 32);

    if (!relayed)
        goto done;
    pthread_join(initiator_thread, NULL);
    pthread_join(responder_thread, NULL);
    initiator_started = responder_started = false;
    if (!initiator.ok || !responder.ok ||
        memcmp(initiator.session.key, responder.session.key, 32) != 0)
        goto done;

    sha3_256(paid_plain, sizeof(paid_plain), paid_sha3);
    if (!fs_send_chunk_private(&responder.session, paid_plain,
                               sizeof(paid_plain), paid_sha3) ||
        !delivery_recv_exact(responder_pair[1], private_wire,
                             sizeof(private_wire)) ||
        !delivery_send_exact(initiator_pair[1], private_wire,
                             sizeof(private_wire)) ||
        !fs_recv_chunk_private(&initiator.session, &opened, &opened_size,
                               sizeof(paid_plain), paid_sha3) ||
        opened_size != sizeof(paid_plain) ||
        memcmp(opened, paid_plain, sizeof(paid_plain)) != 0)
        goto done;

    const uint8_t zero_root[32] = {0};
    sha3_crypt_derive_key(zero_root, initiator_wire, responder_wire,
                          captured_derivation);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, attacker_pair) != 0 ||
        !delivery_send_exact(attacker_pair[0], private_wire,
                             sizeof(private_wire)))
        goto done;
    struct fs_session attacker;
    fs_session_init(&attacker, attacker_pair[1]);
    memcpy(attacker.key, captured_derivation, 32);
    memcpy(attacker.our_nonce, initiator_wire, 32);
    memcpy(attacker.peer_nonce, responder_wire, 32);
    attacker.key_established = true;
    bool attacker_decrypted = fs_recv_chunk_private(
        &attacker, &attacker_opened, &attacker_size,
        sizeof(paid_plain), paid_sha3);
    fs_session_cleanup(&attacker);

    result = !attacker_decrypted && attacker_opened == NULL &&
        memcmp(initiator.session.key, captured_derivation, 32) != 0;

done:
    if (initiator_pair[1] >= 0) close(initiator_pair[1]);
    if (responder_pair[1] >= 0) close(responder_pair[1]);
    if (initiator_started) pthread_join(initiator_thread, NULL);
    if (responder_started) pthread_join(responder_thread, NULL);
    fs_session_cleanup(&initiator.session);
    fs_session_cleanup(&responder.session);
    if (initiator_pair[0] >= 0) close(initiator_pair[0]);
    if (responder_pair[0] >= 0) close(responder_pair[0]);
    if (attacker_pair[0] >= 0) close(attacker_pair[0]);
    if (attacker_pair[1] >= 0) close(attacker_pair[1]);
    free(opened);
    free(attacker_opened);
    return result;
}

static bool delivery_handshake_rejects_zero_peer_key(void)
{
    int sockets[2] = {-1, -1};
    pthread_t thread;
    bool started = false;
    struct delivery_handshake_call initiator = {.initiator = true};
    uint8_t offered_public[32];
    const uint8_t zero_public[32] = {0};
    bool relayed = false;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        return false;
    fs_session_init(&initiator.session, sockets[0]);
    started = pthread_create(&thread, NULL, delivery_handshake_call_main,
                             &initiator) == 0;
    if (started)
        relayed = delivery_recv_exact(sockets[1], offered_public, 32) &&
            delivery_send_exact(sockets[1], zero_public, 32);
    close(sockets[1]);
    if (started)
        pthread_join(thread, NULL);
    close(sockets[0]);

    uint8_t key_or = 0;
    for (size_t i = 0; i < sizeof(initiator.session.key); i++)
        key_or |= initiator.session.key[i];
    bool rejected = relayed && !initiator.ok &&
        !initiator.session.key_established && key_or == 0;
    fs_session_cleanup(&initiator.session);
    return rejected;
}

static bool delivery_handshake_rejects_wrong_confirmation(void)
{
    int sockets[2] = {-1, -1};
    pthread_t thread;
    bool started = false;
    struct delivery_handshake_call initiator = {.initiator = true};
    uint8_t initiator_public[32] = {0};
    uint8_t initiator_confirmation[32] = {0};
    uint8_t responder_private[32];
    uint8_t responder_public[32] = {0};
    uint8_t wrong_confirmation[32];
    bool relayed = false;

    memset(responder_private, 0x6D, sizeof(responder_private));
    memset(wrong_confirmation, 0xA7, sizeof(wrong_confirmation));
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 ||
        !curve25519_scalarmult_base(responder_public, responder_private))
        goto done;
    fs_session_init(&initiator.session, sockets[0]);
    started = pthread_create(&thread, NULL, delivery_handshake_call_main,
                             &initiator) == 0;
    if (started)
        relayed = delivery_recv_exact(sockets[1], initiator_public, 32) &&
            delivery_send_exact(sockets[1], responder_public, 32) &&
            delivery_recv_exact(sockets[1], initiator_confirmation, 32) &&
            delivery_send_exact(sockets[1], wrong_confirmation, 32);
    close(sockets[1]);
    sockets[1] = -1;
    if (started) {
        pthread_join(thread, NULL);
        started = false;
    }

done:
    if (sockets[1] >= 0) close(sockets[1]);
    if (started) pthread_join(thread, NULL);
    if (sockets[0] >= 0) close(sockets[0]);
    uint8_t key_or = 0;
    for (size_t i = 0; i < sizeof(initiator.session.key); i++)
        key_or |= initiator.session.key[i];
    bool rejected = relayed && !initiator.ok &&
        !initiator.session.key_established && key_or == 0;
    fs_session_cleanup(&initiator.session);
    return rejected;
}

struct delivery_handshake_clock {
    _Atomic unsigned reads;
};

static int64_t delivery_handshake_monotonic_us(void *opaque)
{
    struct delivery_handshake_clock *clock = opaque;
    unsigned read = atomic_fetch_add_explicit(&clock->reads, 1,
                                               memory_order_relaxed);
    return read < 2 ? 1000000LL : 32000000LL;
}

static int64_t delivery_handshake_wall_unix(void *opaque)
{
    (void)opaque;
    return 1;
}

static bool delivery_handshake_rejects_partial_record_on_deadline(void)
{
    int sockets[2] = {-1, -1};
    pthread_t thread;
    bool started = false, exchanged = false, finished = false;
    struct delivery_handshake_call initiator = {.initiator = true};
    struct delivery_handshake_clock clock = {0};
    struct platform_clock_source source = {
        .monotonic_us = delivery_handshake_monotonic_us,
        .wall_unix = delivery_handshake_wall_unix,
        .user = &clock,
    };
    uint8_t initiator_public[32], partial_public = 1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        return false;
    struct timeval peer_guard = {.tv_sec = 0, .tv_usec = 250000};
    if (setsockopt(sockets[1], SOL_SOCKET, SO_RCVTIMEO, &peer_guard,
                   sizeof(peer_guard)) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return false;
    }
    fs_session_init(&initiator.session, sockets[0]);
    platform_clock_set_source(&source);
    started = pthread_create(&thread, NULL, delivery_handshake_call_main,
                             &initiator) == 0;
    if (started)
        exchanged = delivery_recv_exact(sockets[1], initiator_public,
                                        sizeof(initiator_public)) &&
            delivery_send_exact(sockets[1], &partial_public, 1);
    for (unsigned i = 0; started && i < 250; i++) {
        if (atomic_load_explicit(&initiator.done, memory_order_acquire)) {
            finished = true;
            break;
        }
        platform_sleep_ms(1);
    }
    if (!finished)
        finished = atomic_load_explicit(&initiator.done, memory_order_acquire);
    close(sockets[1]);
    sockets[1] = -1;
    if (started)
        pthread_join(thread, NULL);
    platform_clock_clear_source();

    uint8_t key_or = 0;
    for (size_t i = 0; i < sizeof(initiator.session.key); i++)
        key_or |= initiator.session.key[i];
    bool rejected = exchanged && finished && !initiator.ok &&
        !initiator.session.key_established && key_or == 0 &&
        atomic_load_explicit(&clock.reads, memory_order_relaxed) >= 3;
    fs_session_cleanup(&initiator.session);
    close(sockets[0]);
    return rejected;
}

struct delivery_frame_call {
    struct fs_session *session;
    bool ok;
    _Atomic bool done;
};

static void *delivery_frame_call_main(void *opaque)
{
    struct delivery_frame_call *call = opaque;
    uint8_t type = 0;
    const uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    call->ok = fs_recv_frame(call->session, &type, &payload, &payload_len);
    atomic_store_explicit(&call->done, true, memory_order_release);
    return NULL;
}

static bool delivery_frame_rejects_partial_record_on_deadline(void)
{
    int sockets[2] = {-1, -1};
    pthread_t thread;
    bool started = false, sent = false, finished = false;
    struct fs_session receiver;
    struct delivery_frame_call call = {.session = &receiver};
    struct delivery_handshake_clock clock = {0};
    struct platform_clock_source source = {
        .monotonic_us = delivery_handshake_monotonic_us,
        .wall_unix = delivery_handshake_wall_unix,
        .user = &clock,
    };
    uint8_t partial_frame = 1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        return false;
    fs_session_init(&receiver, sockets[0]);
    receiver.key[0] = 1;
    receiver.key_established = true;
    platform_clock_set_source(&source);
    started = pthread_create(&thread, NULL, delivery_frame_call_main,
                             &call) == 0;
    if (started)
        sent = delivery_send_exact(sockets[1], &partial_frame, 1);
    for (unsigned i = 0; started && i < 250; i++) {
        if (atomic_load_explicit(&call.done, memory_order_acquire)) {
            finished = true;
            break;
        }
        platform_sleep_ms(1);
    }
    if (!finished)
        finished = atomic_load_explicit(&call.done, memory_order_acquire);
    close(sockets[1]);
    sockets[1] = -1;
    if (started)
        pthread_join(thread, NULL);
    platform_clock_clear_source();

    bool rejected = sent && finished && !call.ok &&
        receiver.recv_counter == 0 && receiver.bytes_received == 0 &&
        atomic_load_explicit(&clock.reads, memory_order_relaxed) >= 3;
    fs_session_cleanup(&receiver);
    close(sockets[0]);
    return rejected;
}

struct delivery_server_call {
    struct fs_session *session;
    bool served;
};

static void *delivery_server_call_main(void *opaque)
{
    struct delivery_server_call *call = opaque;
    uint8_t type = 0;
    const uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    uint8_t client_ip[16] = {0};
    call->served = fs_recv_frame(call->session, &type, &payload,
                                 &payload_len) &&
        type == FS_REQUEST && file_market_delivery_serve(
            call->session, client_ip, payload, payload_len);
    return NULL;
}

struct delivery_endpoint_server {
    int listen_fd;
    bool served;
};

static void *delivery_endpoint_server_main(void *opaque)
{
    struct delivery_endpoint_server *server = opaque;
    int fd = accept(server->listen_fd, NULL, NULL);
    if (fd < 0)
        return NULL;
    struct fs_session session;
    fs_session_init(&session, fd);
    uint8_t transport_root[32] = {0};
    uint8_t type = 0;
    const uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    uint8_t client_ip[16] = {0};
    server->served = fs_handshake(&session, transport_root, false) &&
        fs_recv_frame(&session, &type, &payload, &payload_len) &&
        type == FS_REQUEST && file_market_delivery_serve(
            &session, client_ip, payload, payload_len);
    fs_session_cleanup(&session);
    close(fd);
    return NULL;
}

/* > 2 * FILE_MARKET_ONION_SLICE_BYTES, so onion delivery slices it three
 * ways: two full slices and one remainder. */
#define DELIVERY_BIG_CHUNK_BYTES 130000u

static bool delivery_load_big(
    const uint8_t offer_id[32], uint32_t chunk_index,
    struct file_market_delivery_chunk *out, void *ctx)
{
    struct delivery_fixture *fixture = ctx;
    fixture->load_calls++;
    if (!fixture->load_ok || !offer_id || chunk_index != 7 || !out)
        return false;
    out->data = zcl_malloc(DELIVERY_BIG_CHUNK_BYTES, "delivery_test_big");
    if (!out->data)
        return false;
    for (uint32_t i = 0; i < DELIVERY_BIG_CHUNK_BYTES; i++)
        out->data[i] = (uint8_t)(i * 31u + (i >> 8));
    out->size = DELIVERY_BIG_CHUNK_BYTES;
    sha3_256(out->data, out->size, out->sha3);
    return true;
}

struct onion_loopback {
    char expected_address[ONION_V3_ADDRESS_LEN + 1];
    int calls;
    bool corrupt_path;
};

/* In-process stand-in for the production onion GET port: routes the GET
 * into the site-route handler and unwraps the HTTP envelope the same way
 * onion_tor_get does (non-200 is a transport failure; the body follows the
 * header split). */
static bool onion_loopback_get(void *ctx, const char *onion_address,
                               const char *path, uint8_t *body_out,
                               size_t body_cap, size_t *body_len)
{
    struct onion_loopback *loop = ctx;
    loop->calls++;
    if (strcmp(onion_address, loop->expected_address) != 0)
        return false;
    char routed[sizeof(FILE_MARKET_ONION_PATH_PREFIX) +
                2u * FILE_MARKET_DELIVERY_WIRE_BYTES + 16];
    if (loop->corrupt_path) {
        if (strlen(path) >= sizeof(routed))
            return false;
        memcpy(routed, path, strlen(path) + 1);
        routed[sizeof(FILE_MARKET_ONION_PATH_PREFIX) - 1] = '!';
        path = routed;
    }
    uint8_t response[FILE_MARKET_ONION_REPLY_MAX + 256];
    size_t written = file_market_delivery_onion_handle_request(
        "GET", path, NULL, 0, response, sizeof(response));
    if (written < 13 || memcmp(response, "HTTP/1.1 200 ", 13) != 0)
        return false;
    const uint8_t *split = NULL;
    for (size_t i = 0; i + 4 <= written; i++) {
        if (memcmp(response + i, "\r\n\r\n", 4) == 0) {
            split = response + i + 4;
            break;
        }
    }
    if (!split)
        return false;
    size_t len = written - (size_t)(split - response);
    if (len > body_cap)
        return false;
    if (len > 0)
        memcpy(body_out, split, len);
    *body_len = len;
    return true;
}

int file_market_delivery_tests(void)
{
    int failures = 0;
    DELIVERY_CHECK("captured handshake cannot reconstruct paid-file key",
                   delivery_handshake_capture_has_no_session_key());
    DELIVERY_CHECK("low-order X25519 peer key fails the handshake closed",
                   delivery_handshake_rejects_zero_peer_key());
    DELIVERY_CHECK("wrong confirmation fails handshake and cleanses key",
                   delivery_handshake_rejects_wrong_confirmation());
    DELIVERY_CHECK("partial handshake record hits one absolute deadline",
                   delivery_handshake_rejects_partial_record_on_deadline());
    DELIVERY_CHECK("partial encrypted frame hits one absolute deadline",
                   delivery_frame_rejects_partial_record_on_deadline());
    struct fs_session server;
    struct file_market_delivery_request request, decoded;
    uint8_t wire[FILE_MARKET_DELIVERY_WIRE_BYTES], buyer_seed[32];
    bool made = delivery_request_fixture(&server, &request, wire, buyer_seed);
    DELIVERY_CHECK("session-bound signed request fixture", made);
    if (!made)
        return failures;

    uint8_t expected_session[32];
    file_market_delivery_session_id(
        request.network_genesis, server.peer_nonce, server.our_nonce,
        expected_session);
    bool codec = file_market_delivery_request_decode(
                     wire, sizeof(wire), &decoded) ==
                     FILE_MARKET_DELIVERY_OK &&
                 file_market_delivery_request_verify(
                     &decoded, request.network_genesis, expected_session) ==
                     FILE_MARKET_DELIVERY_OK;
    DELIVERY_CHECK("fixed request codec and buyer signature", codec);

    uint8_t other_session[32];
    memcpy(other_session, expected_session, 32);
    other_session[0] ^= 1;
    DELIVERY_CHECK("request cannot move to another encrypted session",
        file_market_delivery_request_verify(
            &decoded, request.network_genesis, other_session) ==
        FILE_MARKET_DELIVERY_ERR_SESSION);
    struct file_market_delivery_request tampered = decoded;
    tampered.chunk_index++;
    DELIVERY_CHECK("changed chunk fails buyer authentication",
        file_market_delivery_request_verify(
            &tampered, request.network_genesis, expected_session) ==
        FILE_MARKET_DELIVERY_ERR_SIGNATURE);

    struct delivery_fixture fixture = {
        .authorization = FILE_MARKET_DELIVERY_PENDING,
        .load_ok = true,
    };
    file_market_delivery_set_handlers(
        request.network_genesis, delivery_authorize, delivery_load, &fixture);
    struct file_market_delivery_reply reply, reply_roundtrip;
    struct file_market_delivery_chunk chunk;
    enum file_market_delivery_status status = file_market_delivery_prepare(
        &server, wire, sizeof(wire), &reply, &chunk);
    DELIVERY_CHECK("pending payment never invokes content reader",
        status == FILE_MARKET_DELIVERY_PAYMENT_PENDING &&
        fixture.authorize_calls == 1 && fixture.load_calls == 0 &&
        chunk.data == NULL);

    fixture.authorization = FILE_MARKET_DELIVERY_UNKNOWN;
    status = file_market_delivery_prepare(
        &server, wire, sizeof(wire), &reply, &chunk);
    DELIVERY_CHECK("unknown payment never invokes content reader",
        status == FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN &&
        fixture.load_calls == 0 && chunk.data == NULL);
    fixture.authorization = FILE_MARKET_DELIVERY_CONFLICTED;
    status = file_market_delivery_prepare(
        &server, wire, sizeof(wire), &reply, &chunk);
    DELIVERY_CHECK("conflicted payment never invokes content reader",
        status == FILE_MARKET_DELIVERY_PAYMENT_CONFLICTED &&
        fixture.load_calls == 0 && chunk.data == NULL);

    uint8_t tampered_wire[FILE_MARKET_DELIVERY_WIRE_BYTES];
    memcpy(tampered_wire, wire, sizeof(tampered_wire));
    tampered_wire[70] ^= 1;
    int auth_before = fixture.authorize_calls;
    status = file_market_delivery_prepare(
        &server, tampered_wire, sizeof(tampered_wire), &reply, &chunk);
    DELIVERY_CHECK("unauthenticated request reaches neither app callback",
        status == FILE_MARKET_DELIVERY_UNAUTHENTICATED &&
        fixture.authorize_calls == auth_before && fixture.load_calls == 0);

    fixture.authorization = FILE_MARKET_DELIVERY_AUTHORIZED;
    status = file_market_delivery_prepare(
        &server, wire, sizeof(wire), &reply, &chunk);
    bool ready = status == FILE_MARKET_DELIVERY_READY && chunk.data &&
                 fixture.load_calls == 1 && reply.size == chunk.size &&
                 memcmp(reply.sha3, chunk.sha3, 32) == 0 &&
                 file_market_delivery_reply_encode(&reply, tampered_wire) &&
                 file_market_delivery_reply_decode(
                     tampered_wire, FILE_MARKET_DELIVERY_REPLY_BYTES,
                     &reply_roundtrip) &&
                 reply_roundtrip.status == FILE_MARKET_DELIVERY_READY;
    DELIVERY_CHECK("confirmed payment loads one exact typed chunk", ready);
    free(chunk.data);

    fixture.corrupt_hash = true;
    status = file_market_delivery_prepare(
        &server, wire, sizeof(wire), &reply, &chunk);
    DELIVERY_CHECK("content hash mismatch fails closed before send",
        status == FILE_MARKET_DELIVERY_CONTENT_UNAVAILABLE &&
        chunk.data == NULL);
    fixture.corrupt_hash = false;

    int sockets[2] = {-1, -1};
    bool socket_ready = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0;
    struct fs_session client;
    if (socket_ready) {
        fs_session_init(&server, sockets[0]);
        fs_session_init(&client, sockets[1]);
        memset(server.key, 0x75, sizeof(server.key));
        memcpy(client.key, server.key, sizeof(client.key));
        server.key_established = client.key_established = true;
        memset(server.peer_nonce, 0x31, sizeof(server.peer_nonce));
        memset(server.our_nonce, 0x42, sizeof(server.our_nonce));
        fixture.authorization = FILE_MARKET_DELIVERY_AUTHORIZED;
        fixture.load_ok = true;
        fs_pow_reset_state();
    }
    uint8_t client_ip[16] = {0};
    bool served = socket_ready && file_market_delivery_serve(
        &server, client_ip, wire, sizeof(wire));
    uint8_t type = 0;
    const uint8_t *reply_payload = NULL;
    uint32_t reply_len = 0;
    served = served && fs_recv_frame(&client, &type, &reply_payload,
                                     &reply_len) &&
             type == FS_MARKET_REPLY &&
             file_market_delivery_reply_decode(
                 reply_payload, reply_len, &reply_roundtrip) &&
             reply_roundtrip.status == FILE_MARKET_DELIVERY_READY;
    uint8_t size_wire[4], body[32], tag[POLY1305_TAG_SIZE];
    uint32_t served_size = 0;
    if (served) {
        served = delivery_recv_exact(sockets[1], size_wire, 4);
        served_size = (uint32_t)size_wire[0] |
            ((uint32_t)size_wire[1] << 8) |
            ((uint32_t)size_wire[2] << 16) |
            ((uint32_t)size_wire[3] << 24);
        served = served && served_size <= sizeof(body) &&
            delivery_recv_exact(sockets[1], body, served_size) &&
            delivery_recv_exact(sockets[1], tag, sizeof(tag));
    }
    DELIVERY_CHECK("paid chunk wire is encrypted after authenticated reply",
        served && served_size == reply_roundtrip.size &&
        memcmp(body, "paid-chunk-proof", served_size) != 0);
    if (socket_ready) {
        fs_session_cleanup(&server);
        fs_session_cleanup(&client);
    }
    if (sockets[0] >= 0) close(sockets[0]);
    if (sockets[1] >= 0) close(sockets[1]);

    int buyer_sockets[2] = {-1, -1};
    bool buyer_ready = socketpair(AF_UNIX, SOCK_STREAM, 0, buyer_sockets) == 0;
    struct fs_session buyer_server, buyer_client;
    pthread_t server_thread;
    bool server_started = false;
    struct delivery_server_call server_call = {0};
    if (buyer_ready) {
        fs_session_init(&buyer_server, buyer_sockets[0]);
        fs_session_init(&buyer_client, buyer_sockets[1]);
        memset(buyer_server.key, 0x86, sizeof(buyer_server.key));
        memcpy(buyer_client.key, buyer_server.key, sizeof(buyer_client.key));
        buyer_server.key_established = buyer_client.key_established = true;
        memset(buyer_server.peer_nonce, 0x91,
               sizeof(buyer_server.peer_nonce));
        memset(buyer_server.our_nonce, 0x92,
               sizeof(buyer_server.our_nonce));
        memcpy(buyer_client.our_nonce, buyer_server.peer_nonce, 32);
        memcpy(buyer_client.peer_nonce, buyer_server.our_nonce, 32);
        fixture.authorization = FILE_MARKET_DELIVERY_AUTHORIZED;
        fixture.load_ok = true;
        fixture.corrupt_hash = false;
        server_call.session = &buyer_server;
        server_started = pthread_create(&server_thread, NULL,
                                        delivery_server_call_main,
                                        &server_call) == 0;
    }
    uint8_t buyer_public[32], buyer_secret[32];
    ed25519_keypair(buyer_public, buyer_secret, buyer_seed);
    struct file_market_delivery_chunk fetched = {0};
    enum file_market_delivery_status fetched_status =
        buyer_ready && server_started
            ? file_market_delivery_fetch_session(
                &buyer_client, request.network_genesis, request.offer_id, 7,
                buyer_public, buyer_seed, &fetched)
            : FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN;
    if (server_started)
        pthread_join(server_thread, NULL);
    DELIVERY_CHECK("buyer client sends session-bound request and verifies chunk",
        server_call.served && fetched_status == FILE_MARKET_DELIVERY_READY &&
        fetched.data && fetched.size == sizeof("paid-chunk-proof") &&
        memcmp(fetched.data, "paid-chunk-proof",
               sizeof("paid-chunk-proof")) == 0);
    free(fetched.data);
    if (buyer_ready) {
        fs_session_cleanup(&buyer_server);
        fs_session_cleanup(&buyer_client);
    }
    if (buyer_sockets[0] >= 0) close(buyer_sockets[0]);
    if (buyer_sockets[1] >= 0) close(buyer_sockets[1]);

    int listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 endpoint_addr;
    memset(&endpoint_addr, 0, sizeof(endpoint_addr));
    endpoint_addr.sin6_family = AF_INET6;
    endpoint_addr.sin6_addr = in6addr_loopback;
    endpoint_addr.sin6_port = 0;
    socklen_t endpoint_len = sizeof(endpoint_addr);
    bool endpoint_ready = listen_fd >= 0 &&
        bind(listen_fd, (struct sockaddr *)&endpoint_addr,
             sizeof(endpoint_addr)) == 0 &&
        listen(listen_fd, 1) == 0 &&
        getsockname(listen_fd, (struct sockaddr *)&endpoint_addr,
                    &endpoint_len) == 0;
    struct delivery_endpoint_server endpoint_server = {
        .listen_fd = listen_fd,
    };
    pthread_t endpoint_thread;
    bool endpoint_started = endpoint_ready && pthread_create(
        &endpoint_thread, NULL, delivery_endpoint_server_main,
        &endpoint_server) == 0;
    uint8_t loopback_ip[16];
    memcpy(loopback_ip, &in6addr_loopback, 16);
    struct file_market_delivery_chunk endpoint_chunk = {0};
    enum file_market_delivery_status endpoint_status = endpoint_started
        ? file_market_delivery_fetch_endpoint(
            loopback_ip, ntohs(endpoint_addr.sin6_port),
            request.network_genesis, request.offer_id, 7,
            buyer_public, buyer_seed, &endpoint_chunk)
        : FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN;
    if (endpoint_started)
        pthread_join(endpoint_thread, NULL);
    DELIVERY_CHECK("signed offer endpoint completes real encrypted loopback fetch",
        endpoint_server.served &&
        endpoint_status == FILE_MARKET_DELIVERY_READY &&
        endpoint_chunk.data &&
        endpoint_chunk.size == sizeof("paid-chunk-proof") &&
        memcmp(endpoint_chunk.data, "paid-chunk-proof",
               sizeof("paid-chunk-proof")) == 0);
    free(endpoint_chunk.data);
    if (listen_fd >= 0) close(listen_fd);

    /* ── Phase B5 onion delivery (docs/work/MARKET_ONION_DELIVERY.md) ── */

    /* Tor spec example pair, verified against independent sha3/base32
     * implementations before being pinned here. */
    uint8_t vector_pubkey[32];
    bool vector_ok = zcl_hex_decode(
        "adadec040be047f9658668b11a504f3155001f231a37f54c4476c07fb4cc139e",
        vector_pubkey, 32);
    char vector_address[ONION_V3_ADDRESS_LEN + 1];
    uint8_t vector_recovered[32];
    vector_ok = vector_ok &&
        onion_v3_address_from_pubkey(vector_pubkey, vector_address) &&
        strlen(vector_address) == ONION_V3_ADDRESS_LEN &&
        strcmp(vector_address,
               "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd"
               ".onion") == 0 &&
        onion_v3_pubkey_from_address(vector_address, vector_recovered) &&
        memcmp(vector_recovered, vector_pubkey, 32) == 0 &&
        onion_v3_pubkey_from_address(
            "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd",
            vector_recovered) &&
        memcmp(vector_recovered, vector_pubkey, 32) == 0;
    DELIVERY_CHECK("onion v3 address codec matches the Tor spec example",
        vector_ok);

    char flipped_address[ONION_V3_ADDRESS_LEN + 1];
    memcpy(flipped_address, vector_address, sizeof(flipped_address));
    flipped_address[10] = flipped_address[10] == 'a' ? 'b' : 'a';
    uint8_t zero_pubkey[32] = {0};
    char zero_address[ONION_V3_ADDRESS_LEN + 1];
    DELIVERY_CHECK("onion v3 address rejects bad checksum and zero pubkey",
        !onion_v3_pubkey_from_address(flipped_address, vector_recovered) &&
        vector_recovered[0] == 0 &&
        !onion_v3_address_from_pubkey(zero_pubkey, zero_address));

    uint8_t onion_session[32];
    file_market_delivery_onion_session_id(
        request.network_genesis, request.offer_id, buyer_public,
        onion_session);
    struct file_market_delivery_request onion_request;
    memset(&onion_request, 0, sizeof(onion_request));
    onion_request.version = FILE_MARKET_DELIVERY_VERSION;
    memcpy(onion_request.network_genesis, request.network_genesis, 32);
    memcpy(onion_request.offer_id, request.offer_id, 32);
    onion_request.chunk_index = 7;
    memcpy(onion_request.buyer_pubkey, buyer_public, 32);
    memcpy(onion_request.session_id, onion_session, 32);
    uint8_t onion_wire[FILE_MARKET_DELIVERY_WIRE_BYTES];
    bool onion_made =
        file_market_delivery_request_seal(&onion_request, buyer_seed) ==
            FILE_MARKET_DELIVERY_OK &&
        file_market_delivery_request_encode(&onion_request, onion_wire) ==
            FILE_MARKET_DELIVERY_OK;
    DELIVERY_CHECK("onion session-bound request verifies",
        onion_made && file_market_delivery_request_verify(
            &onion_request, request.network_genesis, onion_session) ==
            FILE_MARKET_DELIVERY_OK);
    DELIVERY_CHECK("onion request cannot move to a clearnet session",
        onion_made && file_market_delivery_request_verify(
            &onion_request, request.network_genesis, expected_session) ==
            FILE_MARKET_DELIVERY_ERR_SESSION);

    struct file_market_delivery_reply onion_reply;
    struct file_market_delivery_chunk onion_chunk;
    enum file_market_delivery_status onion_serve_status =
        file_market_delivery_prepare_onion(wire, sizeof(wire), &onion_reply,
                                           &onion_chunk);
    DELIVERY_CHECK("clearnet-bound request fails onion authentication",
        onion_serve_status == FILE_MARKET_DELIVERY_UNAUTHENTICATED &&
        onion_chunk.data == NULL);

    uint8_t seller_onion_pubkey[32];
    memset(seller_onion_pubkey, 0xa7, sizeof(seller_onion_pubkey));
    struct onion_loopback loop;
    memset(&loop, 0, sizeof(loop));
    bool onion_address_ok = onion_v3_address_from_pubkey(
        seller_onion_pubkey, loop.expected_address);

    fixture.authorization = FILE_MARKET_DELIVERY_AUTHORIZED;
    fixture.load_ok = true;
    fixture.corrupt_hash = false;
    file_market_delivery_set_handlers(
        request.network_genesis, delivery_authorize, delivery_load,
        &fixture);
    struct file_market_delivery_chunk single = {0};
    enum file_market_delivery_status single_status = onion_address_ok
        ? file_market_delivery_fetch_onion_with(
            onion_loopback_get, &loop, seller_onion_pubkey,
            request.network_genesis, request.offer_id, 7,
            buyer_public, buyer_seed, &single)
        : FILE_MARKET_DELIVERY_MALFORMED;
    DELIVERY_CHECK("onion fetch serves one verified slice",
        single_status == FILE_MARKET_DELIVERY_READY && single.data &&
        single.size == sizeof("paid-chunk-proof") &&
        memcmp(single.data, "paid-chunk-proof",
               sizeof("paid-chunk-proof")) == 0 && loop.calls == 1);
    free(single.data);

    file_market_delivery_set_handlers(
        request.network_genesis, delivery_authorize, delivery_load_big,
        &fixture);
    loop.calls = 0;
    struct file_market_delivery_chunk multi = {0};
    enum file_market_delivery_status multi_status =
        file_market_delivery_fetch_onion_with(
            onion_loopback_get, &loop, seller_onion_pubkey,
            request.network_genesis, request.offer_id, 7,
            buyer_public, buyer_seed, &multi);
    bool multi_exact = multi_status == FILE_MARKET_DELIVERY_READY &&
        multi.data && multi.size == DELIVERY_BIG_CHUNK_BYTES;
    for (uint32_t i = 0; multi_exact && i < DELIVERY_BIG_CHUNK_BYTES; i++)
        multi_exact = multi.data[i] == (uint8_t)(i * 31u + (i >> 8));
    DELIVERY_CHECK("onion fetch reassembles three verified slices",
        multi_exact && loop.calls == 3);
    free(multi.data);

    int loads_before = fixture.load_calls;
    fixture.authorization = FILE_MARKET_DELIVERY_PENDING;
    loop.calls = 0;
    struct file_market_delivery_chunk pending = {0};
    enum file_market_delivery_status pending_status =
        file_market_delivery_fetch_onion_with(
            onion_loopback_get, &loop, seller_onion_pubkey,
            request.network_genesis, request.offer_id, 7,
            buyer_public, buyer_seed, &pending);
    DELIVERY_CHECK("pending onion payment never invokes content reader",
        pending_status == FILE_MARKET_DELIVERY_PAYMENT_PENDING &&
        loop.calls == 1 && fixture.load_calls == loads_before &&
        pending.data == NULL);

    fixture.authorization = FILE_MARKET_DELIVERY_AUTHORIZED;
    loop.calls = 0;
    loop.corrupt_path = true;
    struct file_market_delivery_chunk corrupt = {0};
    enum file_market_delivery_status corrupt_status =
        file_market_delivery_fetch_onion_with(
            onion_loopback_get, &loop, seller_onion_pubkey,
            request.network_genesis, request.offer_id, 7,
            buyer_public, buyer_seed, &corrupt);
    DELIVERY_CHECK("malformed onion path surfaces as unknown payment",
        corrupt_status == FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN &&
        corrupt.data == NULL);
    loop.corrupt_path = false;

    file_market_delivery_reset_handlers();
    return failures;
}
