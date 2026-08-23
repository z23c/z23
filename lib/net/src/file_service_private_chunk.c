/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: session-bound authenticated encryption for private paid-file data. */

#include "net/file_service.h"

#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define FS_PRIVATE_CHUNK_MAX (60u * 1024u * 1024u)
#define FS_PRIVATE_TAG_SIZE POLY1305_TAG_SIZE

static const uint8_t k_private_key_domain[] =
    "zcl.file.market.private-chunk.key.v1";
static const uint8_t k_private_aad_domain[] =
    "zcl.file.market.private-chunk.aad.v1";

static bool private_send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            LOG_FAIL("filesvc_private", "send failed: errno=%d", errno);
        sent += (size_t)n;
    }
    return true;
}

static bool private_recv_all(int fd, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            LOG_FAIL("filesvc_private", "receive failed: errno=%d", errno);
        got += (size_t)n;
    }
    return true;
}

/* Ordered sender/receiver nonces make the derived key directional. The peer
 * derives the same key by passing its peer nonce first and its own nonce
 * second; traffic in the reverse direction therefore has a different key. */
static void private_derive_key(const struct fs_session *session,
                               const uint8_t sender_nonce[32],
                               const uint8_t receiver_nonce[32],
                               uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, k_private_key_domain,
                   sizeof(k_private_key_domain));
    sha3_256_write(&sha, session->key, sizeof(session->key));
    sha3_256_write(&sha, sender_nonce, 32);
    sha3_256_write(&sha, receiver_nonce, 32);
    sha3_256_finalize(&sha, out);
    memory_cleanse(&sha, sizeof(sha));
}

static size_t private_aad(uint8_t out[sizeof(k_private_aad_domain) + 44],
                          uint32_t size, uint64_t counter,
                          const uint8_t expected_sha3[32])
{
    size_t off = 0;
    memcpy(out + off, k_private_aad_domain, sizeof(k_private_aad_domain));
    off += sizeof(k_private_aad_domain);
    zcl_write_u32_le(out + off, size);
    off += 4;
    zcl_write_u64_le(out + off, counter);
    off += 8;
    memcpy(out + off, expected_sha3, 32);
    off += 32;
    return off;
}

static void private_nonce(uint8_t out[CHACHA20_NONCE_SIZE], uint64_t counter)
{
    out[0] = 'Z';
    out[1] = 'F';
    out[2] = 'M';
    out[3] = 2;
    zcl_write_u64_le(out + 4, counter);
}

bool fs_send_chunk_private(struct fs_session *session, const uint8_t *data,
                           uint32_t size, const uint8_t sha3[32])
{
    if (!session || !session->key_established || !data || !sha3 ||
        size == 0 || size > FS_PRIVATE_CHUNK_MAX)
        LOG_FAIL("filesvc_private", "send: invalid arguments or size=%u", size);

    size_t sealed_size = (size_t)size + FS_PRIVATE_TAG_SIZE;
    uint8_t *sealed = zcl_malloc(sealed_size, "file_private_chunk_send");
    if (!sealed)
        LOG_FAIL("filesvc_private", "send: allocation failed for %zu bytes",
                 sealed_size);

    uint8_t key[32], nonce[CHACHA20_NONCE_SIZE];
    uint8_t aad[sizeof(k_private_aad_domain) + 44];
    uint8_t header[4];
    private_derive_key(session, session->our_nonce, session->peer_nonce, key);
    private_nonce(nonce, session->send_counter);
    size_t aad_size = private_aad(aad, size, session->send_counter, sha3);
    zcl_write_u32_le(header, size);
    bool ok = chacha20poly1305_encrypt(data, size, aad, aad_size, nonce, key,
                                      sealed) &&
              private_send_all(session->fd, header, sizeof(header)) &&
              private_send_all(session->fd, sealed, sealed_size);
    memory_cleanse(key, sizeof(key));
    memory_cleanse(nonce, sizeof(nonce));
    memory_cleanse(aad, sizeof(aad));
    memory_cleanse(sealed, sealed_size);
    free(sealed);
    if (!ok)
        LOG_FAIL("filesvc_private", "send: authenticated encryption failed");

    session->bytes_sent += sizeof(header) + sealed_size;
    session->send_counter++;
    return true;
}

bool fs_recv_chunk_private(struct fs_session *session, uint8_t **out,
                           uint32_t *out_size, uint32_t expected_size,
                           const uint8_t expected_sha3[32])
{
    if (!session || !out || !out_size || !expected_sha3 ||
        !session->key_established || expected_size == 0 ||
        expected_size > FS_PRIVATE_CHUNK_MAX)
        LOG_FAIL("filesvc_private", "receive: invalid arguments or size=%u",
                 expected_size);
    *out = NULL;
    *out_size = 0;

    uint8_t header[4];
    if (!private_recv_all(session->fd, header, sizeof(header)))
        LOG_FAIL("filesvc_private", "receive: size header unavailable");
    uint32_t wire_size = zcl_read_u32_le(header);
    if (wire_size != expected_size)
        LOG_FAIL("filesvc_private",
                 "receive: wire size=%u differs from authenticated reply=%u",
                 wire_size, expected_size);

    size_t sealed_size = (size_t)wire_size + FS_PRIVATE_TAG_SIZE;
    uint8_t *sealed = zcl_malloc(sealed_size, "file_private_chunk_receive");
    uint8_t *plain = zcl_malloc(wire_size, "file_private_chunk_plain");
    if (!sealed || !plain) {
        free(sealed);
        free(plain);
        LOG_FAIL("filesvc_private", "receive: allocation failed for %u bytes",
                 wire_size);
    }
    if (!private_recv_all(session->fd, sealed, sealed_size)) {
        free(sealed);
        free(plain);
        LOG_FAIL("filesvc_private", "receive: ciphertext unavailable");
    }

    uint8_t key[32], nonce[CHACHA20_NONCE_SIZE];
    uint8_t aad[sizeof(k_private_aad_domain) + 44];
    private_derive_key(session, session->peer_nonce, session->our_nonce, key);
    private_nonce(nonce, session->recv_counter);
    size_t aad_size = private_aad(aad, wire_size, session->recv_counter,
                                  expected_sha3);
    bool opened = chacha20poly1305_decrypt(
        sealed, sealed_size, aad, aad_size, nonce, key, plain);
    memory_cleanse(key, sizeof(key));
    memory_cleanse(nonce, sizeof(nonce));
    memory_cleanse(aad, sizeof(aad));
    memory_cleanse(sealed, sealed_size);
    free(sealed);
    if (!opened) {
        memory_cleanse(plain, wire_size);
        free(plain);
        LOG_FAIL("filesvc_private", "receive: authentication failed");
    }

    uint8_t actual_sha3[32];
    sha3_256(plain, wire_size, actual_sha3);
    bool hash_ok = memcmp(actual_sha3, expected_sha3, 32) == 0;
    memory_cleanse(actual_sha3, sizeof(actual_sha3));
    if (!hash_ok) {
        memory_cleanse(plain, wire_size);
        free(plain);
        LOG_FAIL("filesvc_private", "receive: plaintext hash mismatch");
    }

    session->bytes_received += sizeof(header) + sealed_size;
    session->recv_counter++;
    *out = plain;
    *out_size = wire_size;
    return true;
}
