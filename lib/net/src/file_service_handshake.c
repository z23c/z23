/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Forward-secret X25519/HKDF handshake for the direct file service. */

#include "net/file_service.h"

#include "crypto/curve25519.h"
#include "crypto/hkdf_sha256.h"
#include "crypto/random_secret.h"
#include "crypto/sha3.h"
#include "crypto/x25519_safe.h"
#include "support/cleanse.h"
#include "util/log_macros.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>

static const uint8_t k_fs_handshake_domain[] =
    "zcl.file-service.x25519-hkdf-sha256.v1";
static const uint8_t k_fs_confirmation_domain[] =
    "zcl.file-service.key-confirmation.v1";

static bool handshake_send_all(int fd, const uint8_t *data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        sent += (size_t)n;
    }
    return true;
}

static bool handshake_recv_all(int fd, uint8_t *out, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, out + got, len - got, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        got += (size_t)n;
    }
    return true;
}

static void handshake_transcript(const struct fs_session *session,
                                 bool initiator,
                                 uint8_t out[sizeof(k_fs_handshake_domain) - 1 +
                                             64])
{
    const uint8_t *initiator_pub = initiator ? session->our_nonce
                                              : session->peer_nonce;
    const uint8_t *responder_pub = initiator ? session->peer_nonce
                                              : session->our_nonce;
    size_t domain_len = sizeof(k_fs_handshake_domain) - 1;
    memcpy(out, k_fs_handshake_domain, domain_len);
    memcpy(out + domain_len, initiator_pub, 32);
    memcpy(out + domain_len + 32, responder_pub, 32);
}

static void handshake_confirmation(
    const uint8_t key[32],
    const uint8_t transcript[sizeof(k_fs_handshake_domain) - 1 + 64],
    uint8_t role, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, key, 32);
    sha3_256_write(&sha, k_fs_confirmation_domain,
                   sizeof(k_fs_confirmation_domain) - 1);
    sha3_256_write(&sha, &role, 1);
    sha3_256_write(&sha, transcript,
                   sizeof(k_fs_handshake_domain) - 1 + 64);
    sha3_256_finalize(&sha, out);
    memory_cleanse(&sha, sizeof(sha));
}

static bool confirmation_equal(const uint8_t a[32], const uint8_t b[32])
{
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

bool fs_handshake(struct fs_session *session, const uint8_t utxo_root[32],
                  bool initiator)
{
    uint8_t ephemeral_private[32] = {0};
    uint8_t shared_secret[32] = {0};
    uint8_t transcript[sizeof(k_fs_handshake_domain) - 1 + 64] = {0};
    uint8_t our_confirmation[32] = {0};
    uint8_t expected_peer_confirmation[32] = {0};
    uint8_t peer_confirmation[32] = {0};
    const char *failure = NULL;

    if (!session || !utxo_root)
        LOG_FAIL("filesvc", "handshake: null session or UTXO root");
    session->key_established = false;
    memory_cleanse(session->key, sizeof(session->key));

    if (!zcl_random_secret_bytes(ephemeral_private,
                                 sizeof(ephemeral_private),
                                 "file-service-ephemeral")) {
        failure = "ephemeral secret generation failed";
        goto done;
    }
    if (!curve25519_scalarmult_base(session->our_nonce,
                                    ephemeral_private)) {
        failure = "ephemeral public-key derivation failed";
        goto done;
    }

    if (initiator) {
        if (!handshake_send_all(session->fd, session->our_nonce, 32)) {
            failure = "initiator public-key send failed";
            goto done;
        }
        if (!handshake_recv_all(session->fd, session->peer_nonce, 32)) {
            failure = "responder public-key receive failed";
            goto done;
        }
    } else {
        if (!handshake_recv_all(session->fd, session->peer_nonce, 32)) {
            failure = "initiator public-key receive failed";
            goto done;
        }
        if (!handshake_send_all(session->fd, session->our_nonce, 32)) {
            failure = "responder public-key send failed";
            goto done;
        }
    }

    if (!x25519_safe(shared_secret, ephemeral_private,
                     session->peer_nonce)) {
        failure = "peer public key produced a degenerate shared secret";
        goto done;
    }
    handshake_transcript(session, initiator, transcript);
    if (!hkdf_sha256(utxo_root, 32, shared_secret, sizeof(shared_secret),
                     transcript, sizeof(transcript), session->key,
                     sizeof(session->key))) {
        failure = "HKDF session-key derivation failed";
        goto done;
    }

    handshake_confirmation(session->key, transcript, initiator ? 1 : 2,
                           our_confirmation);
    handshake_confirmation(session->key, transcript, initiator ? 2 : 1,
                           expected_peer_confirmation);
    if (!handshake_send_all(session->fd, our_confirmation, 32)) {
        failure = "key confirmation send failed";
        goto done;
    }
    if (!handshake_recv_all(session->fd, peer_confirmation, 32)) {
        failure = "key confirmation receive failed";
        goto done;
    }
    if (!confirmation_equal(expected_peer_confirmation, peer_confirmation)) {
        failure = "key confirmation failed (peer root or transcript differs)";
        goto done;
    }
    session->key_established = true;

done:
    memory_cleanse(ephemeral_private, sizeof(ephemeral_private));
    memory_cleanse(shared_secret, sizeof(shared_secret));
    memory_cleanse(our_confirmation, sizeof(our_confirmation));
    memory_cleanse(expected_peer_confirmation,
                   sizeof(expected_peer_confirmation));
    memory_cleanse(peer_confirmation, sizeof(peer_confirmation));
    if (failure) {
        memory_cleanse(session->key, sizeof(session->key));
        LOG_FAIL("filesvc", "handshake: %s (%s)", failure,
                 initiator ? "initiator" : "responder");
    }
    return true;
}

void fs_session_cleanup(struct fs_session *session)
{
    if (!session)
        return;
    memory_cleanse(session->key, sizeof(session->key));
    memory_cleanse(session->our_nonce, sizeof(session->our_nonce));
    memory_cleanse(session->peer_nonce, sizeof(session->peer_nonce));
    session->key_established = false;
}
