/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: pin the observable behaviour of the file service session
 * handshake (fs_handshake_until) and the private chunk receive path
 * (fs_recv_chunk_private_until) over socketpairs: agreement, deadline
 * expiry, short read or peer close, and bad-MAC or oversize refusals. */

#include "test/test_core.h"

#include "crypto/sha3.h"
#include "net/file_service.h"
#include "platform/socket_compat.h"
#include "platform/time_compat.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FSS_LONG_MS 5000
#define FSS_SHORT_MS 50
#define FSS_HEADER_SIZE 4
/* Poly1305 tag size, as sealed by the private chunk path. */
#define FSS_TAG_SIZE 16
/* One byte past FS_PRIVATE_CHUNK_MAX (60 MiB), refused before any I/O. */
#define FSS_CHUNK_OVER_MAX ((uint32_t)(60u * 1024u * 1024u + 1u))
#define FSS_NONCE_A 0x11
#define FSS_NONCE_B 0x22
#define FSS_KEY 0x33
#define FSS_WRONG_KEY 0x44

static const uint8_t k_fss_payload[] = "private-chunk-session-pin";

static int64_t fss_deadline(int64_t ms)
{
    return platform_time_monotonic_ms() + ms;
}

static bool fss_all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++)
        acc |= p[i];
    return acc == 0;
}

static void fss_close_fd(platform_socket_t *fd)
{
    if (*fd == PLATFORM_SOCKET_INVALID)
        return;
    platform_socket_close(*fd);
    *fd = PLATFORM_SOCKET_INVALID;
}

static bool fss_send_bytes(platform_socket_t fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int n = platform_socket_send_nonblocking(fd, buf + sent, len - sent);
        if (n <= 0)
            return false;
        sent += (size_t)n;
    }
    return true;
}

/* One handshake end run on a thread or on the caller. */
struct fss_hs {
    struct fs_session session;
    uint8_t root[32];
    bool initiator;
    int64_t deadline_ms;
    bool ok;
};

static void *fss_hs_run(void *arg)
{
    struct fss_hs *hs = arg;
    hs->ok = fs_handshake_until(&hs->session, hs->root, hs->initiator,
                                hs->deadline_ms);
    return NULL;
}

/* Both ends of one handshake over a fresh socketpair: the initiator runs on a
 * thread, the responder on the caller. False only when setup fails. */
static bool fss_handshake_pair(struct fss_hs *init, struct fss_hs *resp)
{
    platform_socket_t pair[2];
    pthread_t thread;
    if (!platform_socket_pair(pair))
        return false;
    fs_session_init(&init->session, pair[0]);
    fs_session_init(&resp->session, pair[1]);
    bool started = pthread_create(&thread, NULL, fss_hs_run, init) == 0;
    if (started) {
        fss_hs_run(resp);
        pthread_join(thread, NULL);
    }
    fss_close_fd(&pair[0]);
    fss_close_fd(&pair[1]);
    return started;
}

/* A single session end whose peer socket the case controls directly. */
struct fss_lone {
    platform_socket_t pair[2];
    struct fs_session session;
};

static bool fss_lone_open(struct fss_lone *l)
{
    memset(l, 0, sizeof(*l));
    l->pair[0] = PLATFORM_SOCKET_INVALID;
    l->pair[1] = PLATFORM_SOCKET_INVALID;
    if (!platform_socket_pair(l->pair))
        return false;
    fs_session_init(&l->session, l->pair[0]);
    return true;
}

static void fss_lone_close(struct fss_lone *l)
{
    fss_close_fd(&l->pair[0]);
    fss_close_fd(&l->pair[1]);
    fs_session_cleanup(&l->session);
}

static bool fss_lone_failed_clean(const struct fs_session *s)
{
    return !s->key_established && fss_all_zero(s->key, sizeof(s->key));
}

static bool fss_case_handshake_agrees(void)
{
    struct fss_hs init = {.initiator = true};
    struct fss_hs resp = {.initiator = false};
    int64_t deadline = fss_deadline(FSS_LONG_MS);
    memset(init.root, 0x5A, sizeof(init.root));
    memset(resp.root, 0x5A, sizeof(resp.root));
    init.deadline_ms = deadline;
    resp.deadline_ms = deadline;
    bool ok = fss_handshake_pair(&init, &resp) && init.ok && resp.ok &&
              init.session.key_established && resp.session.key_established &&
              !fss_all_zero(init.session.key, sizeof(init.session.key)) &&
              memcmp(init.session.key, resp.session.key, 32) == 0 &&
              memcmp(init.session.our_nonce, resp.session.peer_nonce, 32) == 0 &&
              memcmp(resp.session.our_nonce, init.session.peer_nonce, 32) == 0;
    fs_session_cleanup(&init.session);
    fs_session_cleanup(&resp.session);
    return ok;
}

static bool fss_case_handshake_root_mismatch(void)
{
    struct fss_hs init = {.initiator = true};
    struct fss_hs resp = {.initiator = false};
    int64_t deadline = fss_deadline(FSS_LONG_MS);
    memset(init.root, 0x5A, sizeof(init.root));
    memset(resp.root, 0x5B, sizeof(resp.root));
    init.deadline_ms = deadline;
    resp.deadline_ms = deadline;
    bool ok = fss_handshake_pair(&init, &resp) && !init.ok && !resp.ok &&
              fss_lone_failed_clean(&init.session) &&
              fss_lone_failed_clean(&resp.session);
    fs_session_cleanup(&init.session);
    fs_session_cleanup(&resp.session);
    return ok;
}

static bool fss_case_handshake_null_refused(void)
{
    uint8_t root[32] = {0};
    struct fss_lone l;
    if (!fss_lone_open(&l))
        return false;
    bool ok = !fs_handshake_until(NULL, root, true, fss_deadline(FSS_LONG_MS)) &&
              !fs_handshake_until(&l.session, NULL, true,
                                  fss_deadline(FSS_LONG_MS)) &&
              fss_lone_failed_clean(&l.session);
    fss_lone_close(&l);
    return ok;
}

static bool fss_case_handshake_deadline_refused(void)
{
    /* 0 and -1 are an invalid caller deadline; 1 is already expired. */
    static const int64_t bad[] = {0, -1, 1};
    bool ok = true;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        uint8_t root[32] = {0};
        struct fss_lone l;
        if (!fss_lone_open(&l))
            return false;
        ok = ok && !fs_handshake_until(&l.session, root, true, bad[i]) &&
             fss_lone_failed_clean(&l.session);
        fss_lone_close(&l);
    }
    return ok;
}

static bool fss_case_handshake_peer_closed(void)
{
    uint8_t root[32] = {0};
    struct fss_lone l;
    if (!fss_lone_open(&l))
        return false;
    fss_close_fd(&l.pair[1]);
    bool ok = !fs_handshake_until(&l.session, root, false,
                                  fss_deadline(FSS_LONG_MS)) &&
              fss_lone_failed_clean(&l.session);
    fss_lone_close(&l);
    return ok;
}

static bool fss_case_handshake_short_nonce(void)
{
    uint8_t root[32] = {0};
    uint8_t half[16];
    memset(half, 0x77, sizeof(half));
    struct fss_lone l;
    if (!fss_lone_open(&l))
        return false;
    bool sent = fss_send_bytes(l.pair[1], half, sizeof(half));
    fss_close_fd(&l.pair[1]);
    bool ok = sent && !fs_handshake_until(&l.session, root, false,
                                          fss_deadline(FSS_LONG_MS)) &&
              fss_lone_failed_clean(&l.session);
    fss_lone_close(&l);
    return ok;
}

static bool fss_case_handshake_responder_silent(void)
{
    uint8_t root[32] = {0};
    struct fss_lone l;
    if (!fss_lone_open(&l))
        return false;
    /* The peer stays open but never sends its nonce: the deadline must fire. */
    bool ok = !fs_handshake_until(&l.session, root, false,
                                  fss_deadline(FSS_SHORT_MS)) &&
              fss_lone_failed_clean(&l.session);
    fss_lone_close(&l);
    return ok;
}

static bool fss_case_handshake_initiator_silent(void)
{
    uint8_t root[32] = {0};
    struct fss_lone l;
    if (!fss_lone_open(&l))
        return false;
    /* The initiator's nonce goes out, then the silent responder's nonce never
     * arrives and the deadline fires on the receive. */
    bool ok = !fs_handshake_until(&l.session, root, true,
                                  fss_deadline(FSS_SHORT_MS)) &&
              fss_lone_failed_clean(&l.session);
    fss_lone_close(&l);
    return ok;
}

static bool fss_case_handshake_degenerate_peer(void)
{
    uint8_t root[32] = {0};
    uint8_t zero[32] = {0};
    struct fss_lone l;
    if (!fss_lone_open(&l))
        return false;
    bool sent = fss_send_bytes(l.pair[1], zero, sizeof(zero));
    bool ok = sent && !fs_handshake_until(&l.session, root, false,
                                          fss_deadline(FSS_LONG_MS)) &&
              fss_lone_failed_clean(&l.session);
    fss_lone_close(&l);
    return ok;
}

/* Sender end on pair[0] with the chunk keys, receiver end on pair[1]. The
 * sender's nonces are the receiver's peer and own nonces in reverse. */
struct fss_chunk {
    platform_socket_t pair[2];
    struct fs_session tx;
    struct fs_session rx;
};

static bool fss_chunk_open(struct fss_chunk *c)
{
    memset(c, 0, sizeof(*c));
    c->pair[0] = PLATFORM_SOCKET_INVALID;
    c->pair[1] = PLATFORM_SOCKET_INVALID;
    if (!platform_socket_pair(c->pair))
        return false;
    fs_session_init(&c->tx, c->pair[0]);
    fs_session_init(&c->rx, c->pair[1]);
    memset(c->tx.key, FSS_KEY, sizeof(c->tx.key));
    memset(c->tx.our_nonce, FSS_NONCE_A, sizeof(c->tx.our_nonce));
    memset(c->tx.peer_nonce, FSS_NONCE_B, sizeof(c->tx.peer_nonce));
    memset(c->rx.key, FSS_KEY, sizeof(c->rx.key));
    memset(c->rx.our_nonce, FSS_NONCE_B, sizeof(c->rx.our_nonce));
    memset(c->rx.peer_nonce, FSS_NONCE_A, sizeof(c->rx.peer_nonce));
    c->tx.key_established = true;
    c->rx.key_established = true;
    return true;
}

static void fss_chunk_close(struct fss_chunk *c)
{
    fss_close_fd(&c->pair[0]);
    fss_close_fd(&c->pair[1]);
    fs_session_cleanup(&c->tx);
    fs_session_cleanup(&c->rx);
}

/* True when the receive fails, leaves out NULL and size 0, and advances no
 * counter or byte total on the receiver. */
static bool fss_chunk_refused(struct fs_session *rx, uint32_t expected,
                              const uint8_t sha[32], int64_t deadline_ms)
{
    uint8_t *out = NULL;
    uint32_t out_size = 0;
    bool failed = !fs_recv_chunk_private_until(rx, &out, &out_size, expected,
                                               sha, deadline_ms);
    bool clean = out == NULL && out_size == 0 && rx->recv_counter == 0 &&
                 rx->bytes_received == 0;
    free(out);
    return failed && clean;
}

static bool fss_case_chunk_round_trip(void)
{
    struct fss_chunk c;
    uint8_t sha[32];
    uint8_t *out = NULL;
    uint32_t out_size = 0;
    const size_t len = sizeof(k_fss_payload) - 1;
    bool ok = fss_chunk_open(&c);
    if (ok) {
        sha3_256(k_fss_payload, len, sha);
        ok = fs_send_chunk_private(&c.tx, k_fss_payload, (uint32_t)len, sha) &&
             fs_recv_chunk_private_until(&c.rx, &out, &out_size, (uint32_t)len,
                                         sha, fss_deadline(FSS_LONG_MS)) &&
             out != NULL && out_size == len &&
             memcmp(out, k_fss_payload, len) == 0 &&
             c.rx.recv_counter == 1 && c.tx.send_counter == 1 &&
             c.rx.bytes_received == FSS_HEADER_SIZE + len + FSS_TAG_SIZE &&
             c.tx.bytes_sent == FSS_HEADER_SIZE + len + FSS_TAG_SIZE;
    }
    free(out);
    fss_chunk_close(&c);
    return ok;
}

static bool fss_case_chunk_deadline_refused(void)
{
    /* 0 and -1 are an invalid caller deadline; 1 is already expired. */
    static const int64_t bad[] = {0, -1, 1};
    const size_t len = sizeof(k_fss_payload) - 1;
    uint8_t sha[32];
    sha3_256(k_fss_payload, len, sha);
    bool ok = true;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        struct fss_chunk c;
        if (!fss_chunk_open(&c))
            return false;
        ok = ok && fss_chunk_refused(&c.rx, (uint32_t)len, sha, bad[i]);
        fss_chunk_close(&c);
    }
    return ok;
}

static bool fss_case_chunk_silent_peer_deadline(void)
{
    const size_t len = sizeof(k_fss_payload) - 1;
    uint8_t sha[32];
    sha3_256(k_fss_payload, len, sha);
    struct fss_chunk c;
    if (!fss_chunk_open(&c))
        return false;
    /* Nothing is sent: the header read must hit the deadline. */
    bool ok = fss_chunk_refused(&c.rx, (uint32_t)len, sha,
                                fss_deadline(FSS_SHORT_MS));
    fss_chunk_close(&c);
    return ok;
}

static bool fss_case_chunk_arguments_refused(void)
{
    struct fss_chunk c;
    uint8_t sha[32] = {0};
    uint8_t *out = NULL;
    uint32_t out_size = 0;
    int64_t deadline = fss_deadline(FSS_LONG_MS);
    bool ok = fss_chunk_open(&c);
    if (ok) {
        ok = !fs_recv_chunk_private_until(NULL, &out, &out_size, 1, sha,
                                          deadline) &&
             !fs_recv_chunk_private_until(&c.rx, NULL, &out_size, 1, sha,
                                          deadline) &&
             !fs_recv_chunk_private_until(&c.rx, &out, NULL, 1, sha,
                                          deadline) &&
             !fs_recv_chunk_private_until(&c.rx, &out, &out_size, 1, NULL,
                                          deadline) &&
             !fs_recv_chunk_private_until(&c.rx, &out, &out_size, 0, sha,
                                          deadline) &&
             !fs_recv_chunk_private_until(&c.rx, &out, &out_size,
                                          FSS_CHUNK_OVER_MAX, sha, deadline);
        c.rx.key_established = false;
        ok = ok && !fs_recv_chunk_private_until(&c.rx, &out, &out_size, 1,
                                                sha, deadline);
    }
    free(out);
    fss_chunk_close(&c);
    return ok;
}

static bool fss_case_chunk_wire_size_mismatch(void)
{
    const size_t len = sizeof(k_fss_payload) - 1;
    uint8_t sha[32];
    sha3_256(k_fss_payload, len, sha);
    /* The header claims one byte more than the authenticated reply size. */
    uint8_t header[FSS_HEADER_SIZE] = {(uint8_t)(len + 1), 0, 0, 0};
    struct fss_chunk c;
    if (!fss_chunk_open(&c))
        return false;
    bool ok = fss_send_bytes(c.pair[0], header, sizeof(header)) &&
              fss_chunk_refused(&c.rx, (uint32_t)len, sha,
                                fss_deadline(FSS_LONG_MS));
    fss_chunk_close(&c);
    return ok;
}

static bool fss_case_chunk_peer_closed_in_header(void)
{
    const size_t len = sizeof(k_fss_payload) - 1;
    uint8_t sha[32];
    sha3_256(k_fss_payload, len, sha);
    uint8_t partial[2] = {(uint8_t)len, 0};
    struct fss_chunk c;
    if (!fss_chunk_open(&c))
        return false;
    bool sent = fss_send_bytes(c.pair[0], partial, sizeof(partial));
    fss_close_fd(&c.pair[0]);
    bool ok = sent && fss_chunk_refused(&c.rx, (uint32_t)len, sha,
                                        fss_deadline(FSS_LONG_MS));
    fss_chunk_close(&c);
    return ok;
}

static bool fss_case_chunk_short_ciphertext(void)
{
    const size_t len = sizeof(k_fss_payload) - 1;
    uint8_t sha[32];
    sha3_256(k_fss_payload, len, sha);
    /* Correct header, then only 10 of the 41 sealed bytes before the close. */
    uint8_t header[FSS_HEADER_SIZE] = {(uint8_t)len, 0, 0, 0};
    uint8_t body[10] = {0};
    struct fss_chunk c;
    if (!fss_chunk_open(&c))
        return false;
    bool sent = fss_send_bytes(c.pair[0], header, sizeof(header)) &&
                fss_send_bytes(c.pair[0], body, sizeof(body));
    fss_close_fd(&c.pair[0]);
    bool ok = sent && fss_chunk_refused(&c.rx, (uint32_t)len, sha,
                                        fss_deadline(FSS_LONG_MS));
    fss_chunk_close(&c);
    return ok;
}

static bool fss_case_chunk_bad_mac_wrong_key(void)
{
    const size_t len = sizeof(k_fss_payload) - 1;
    uint8_t sha[32];
    sha3_256(k_fss_payload, len, sha);
    struct fss_chunk c;
    if (!fss_chunk_open(&c))
        return false;
    bool ok = fs_send_chunk_private(&c.tx, k_fss_payload, (uint32_t)len, sha);
    memset(c.rx.key, FSS_WRONG_KEY, sizeof(c.rx.key));
    ok = ok && fss_chunk_refused(&c.rx, (uint32_t)len, sha,
                                 fss_deadline(FSS_LONG_MS));
    fss_chunk_close(&c);
    return ok;
}

static bool fss_case_chunk_bad_mac_wrong_expected_hash(void)
{
    const size_t len = sizeof(k_fss_payload) - 1;
    uint8_t sha[32];
    uint8_t other[32];
    sha3_256(k_fss_payload, len, sha);
    memset(other, 0x99, sizeof(other));
    struct fss_chunk c;
    if (!fss_chunk_open(&c))
        return false;
    /* The expected hash is bound into the AAD, so a different one fails the
     * tag check before any plaintext hash is compared. */
    bool ok = fs_send_chunk_private(&c.tx, k_fss_payload, (uint32_t)len, sha) &&
              fss_chunk_refused(&c.rx, (uint32_t)len, other,
                                fss_deadline(FSS_LONG_MS));
    fss_chunk_close(&c);
    return ok;
}

static bool fss_case_chunk_plaintext_hash_mismatch(void)
{
    const size_t len = sizeof(k_fss_payload) - 1;
    uint8_t claimed[32];
    memset(claimed, 0xEE, sizeof(claimed));
    struct fss_chunk c;
    if (!fss_chunk_open(&c))
        return false;
    /* The sender seals a false hash as AAD, so the tag verifies and only the
     * plaintext hash comparison refuses the chunk. */
    bool ok = fs_send_chunk_private(&c.tx, k_fss_payload, (uint32_t)len,
                                    claimed) &&
              fss_chunk_refused(&c.rx, (uint32_t)len, claimed,
                                fss_deadline(FSS_LONG_MS));
    fss_chunk_close(&c);
    return ok;
}

struct fss_case {
    const char *name;
    bool (*run)(void);
};

static const struct fss_case k_fss_cases[] = {
    {"handshake agrees on one key and nonce pair", fss_case_handshake_agrees},
    {"handshake root mismatch fails both ends", fss_case_handshake_root_mismatch},
    {"handshake NULL session or root refused", fss_case_handshake_null_refused},
    {"handshake invalid or expired deadline refused",
     fss_case_handshake_deadline_refused},
    {"handshake responder sees peer closed before nonce",
     fss_case_handshake_peer_closed},
    {"handshake responder short nonce then close",
     fss_case_handshake_short_nonce},
    {"handshake responder deadline expires on silent peer",
     fss_case_handshake_responder_silent},
    {"handshake initiator deadline expires on silent responder",
     fss_case_handshake_initiator_silent},
    {"handshake degenerate zero peer key refused",
     fss_case_handshake_degenerate_peer},
    {"private chunk round trips and advances counters",
     fss_case_chunk_round_trip},
    {"private chunk invalid or expired deadline refused",
     fss_case_chunk_deadline_refused},
    {"private chunk deadline expires on silent peer",
     fss_case_chunk_silent_peer_deadline},
    {"private chunk argument and oversize refusals",
     fss_case_chunk_arguments_refused},
    {"private chunk wire size mismatch refused",
     fss_case_chunk_wire_size_mismatch},
    {"private chunk peer closed inside header",
     fss_case_chunk_peer_closed_in_header},
    {"private chunk short ciphertext then close",
     fss_case_chunk_short_ciphertext},
    {"private chunk bad MAC from wrong key",
     fss_case_chunk_bad_mac_wrong_key},
    {"private chunk bad MAC from wrong expected hash",
     fss_case_chunk_bad_mac_wrong_expected_hash},
    {"private chunk plaintext hash mismatch refused",
     fss_case_chunk_plaintext_hash_mismatch},
};

int test_file_service_session(void)
{
    int failures = 0;
    printf("\n=== file_service_session tests ===\n");
    for (size_t i = 0; i < sizeof(k_fss_cases) / sizeof(k_fss_cases[0]); i++) {
        printf("%s... ", k_fss_cases[i].name);
        bool ok = k_fss_cases[i].run();
        printf("%s\n", ok ? "OK" : "FAIL");
        if (!ok)
            failures++;
    }
    return failures;
}
