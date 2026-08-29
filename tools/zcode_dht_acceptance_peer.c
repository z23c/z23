/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Acceptance-only Noise peer for tools/dev/zcode_dht_acceptance.sh. */

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "core/hash.h"
#include "crypto/ed25519.h"
#include "net/noise_transport.h"
#include "platform/time_compat.h"
#include "support/cleanse.h"
#include "vcs/zcode_dht_identity.h"
#include "vcs/zcode_dht_msgs.h"
#include "vcs/zcode_dht_service.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define APP_CAP (1u << 20)
#define P2P_HEADER 24u
#define NODE_NETWORK UINT64_C(1)
#define NODE_ZCL23 UINT64_C(1 << 10)
#define NODE_NOISE UINT64_C(1 << 25)
#define PROTOCOL_VERSION 170011

static const uint8_t regtest_magic[4] = {0xaa, 0xe8, 0x3f, 0x5f};

struct app_buffer {
    uint8_t bytes[APP_CAP];
    size_t len;
};

static int usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s pubkey <64-lower-hex-seed>\n"
            "       %s attack <ipv4> <port> <identity-datadir>\n",
            prog, prog);
    return 2;
}

static bool write_all_fd(int fd, const uint8_t *p, size_t n)
{
    while (n) {
        ssize_t wrote = send(fd, p, n, MSG_NOSIGNAL);
        if (wrote < 0 && errno == EINTR)
            continue;
        if (wrote <= 0)
            return false;
        p += (size_t)wrote;
        n -= (size_t)wrote;
    }
    return true;
}

static bool read_exact_0600(const char *path, uint8_t *out, size_t len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
              (st.st_mode & 0777) == 0600 && st.st_size == (off_t)len;
    size_t off = 0;
    while (ok && off < len) {
        ssize_t n = read(fd, out + off, len - off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            ok = false;
            break;
        }
        off += (size_t)n;
    }
    if (close(fd) != 0)
        ok = false;
    return ok && off == len;
}

static bool p2p_message(const char *command, const uint8_t *payload,
                        size_t payload_len, uint8_t **out, size_t *out_len)
{
    if (!command || strlen(command) > 12 || payload_len > UINT32_MAX ||
        !out || !out_len)
        return false;
    size_t total = P2P_HEADER + payload_len;
    uint8_t *wire = zcl_calloc(total ? total : 1, 1, "dht-accept-p2p-wire");
    if (!wire)
        return false;
    memcpy(wire, regtest_magic, 4);
    memcpy(wire + 4, command, strlen(command));
    zcl_write_u32_le(wire + 16, (uint32_t)payload_len);
    uint8_t digest[32];
    hash256(payload, payload_len, digest);
    memcpy(wire + 20, digest, 4);
    if (payload_len)
        memcpy(wire + P2P_HEADER, payload, payload_len);
    *out = wire;
    *out_len = total;
    return true;
}

static bool send_p2p(int fd, struct noise_transport *transport,
                     const char *command, const uint8_t *payload,
                     size_t payload_len)
{
    uint8_t *plain = NULL, *sealed = NULL;
    size_t plain_len = 0, sealed_len = 0;
    bool ok = p2p_message(command, payload, payload_len, &plain, &plain_len) &&
              noise_transport_write(transport, plain, plain_len, &sealed,
                                 &sealed_len) &&
              sealed_len > 0 && write_all_fd(fd, sealed, sealed_len);
    free(plain);
    free(sealed);
    return ok;
}

static bool feed_once(int fd, struct noise_transport *transport,
                      struct app_buffer *app, int timeout_ms)
{
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int pr;
    do {
        pr = poll(&pfd, 1, timeout_ms);
    } while (pr < 0 && errno == EINTR);
    if (pr <= 0 || !(pfd.revents & POLLIN))
        return false;
    uint8_t input[8192];
    ssize_t n = recv(fd, input, sizeof(input), 0);
    if (n <= 0)
        return false;
    uint8_t *reply = NULL, *plain = NULL;
    size_t reply_len = 0, plain_len = 0;
    bool ok = noise_transport_feed(transport, input, (size_t)n, &reply,
                                &reply_len, &plain, &plain_len);
    if (ok && reply_len)
        ok = write_all_fd(fd, reply, reply_len);
    if (ok && plain_len) {
        if (plain_len > sizeof(app->bytes) - app->len)
            ok = false;
        else {
            memcpy(app->bytes + app->len, plain, plain_len);
            app->len += plain_len;
        }
    }
    free(reply);
    free(plain);
    return ok;
}

static bool pop_p2p(struct app_buffer *app, char command[13],
                    uint8_t *payload, size_t payload_cap, size_t *payload_len)
{
    if (app->len < P2P_HEADER)
        return false;
    if (memcmp(app->bytes, regtest_magic, 4) != 0)
        return false;
    uint32_t len = zcl_read_u32_le(app->bytes + 16);
    if ((size_t)len > APP_CAP - P2P_HEADER ||
        app->len < P2P_HEADER + (size_t)len)
        return false;
    memset(command, 0, 13);
    memcpy(command, app->bytes + 4, 12);
    if (len > payload_cap)
        return false;
    if (len)
        memcpy(payload, app->bytes + P2P_HEADER, len);
    *payload_len = len;
    size_t used = P2P_HEADER + (size_t)len;
    memmove(app->bytes, app->bytes + used, app->len - used);
    app->len -= used;
    return true;
}

static size_t build_version(uint8_t out[128])
{
    size_t off = 0;
    zcl_write_u32_le(out + off, PROTOCOL_VERSION); off += 4;
    zcl_write_u64_le(out + off, NODE_NETWORK | NODE_ZCL23 | NODE_NOISE); off += 8;
    zcl_write_u64_le(out + off, (uint64_t)platform_time_wall_time_t()); off += 8;
    for (int address = 0; address < 2; address++) {
        zcl_write_u64_le(out + off, NODE_NETWORK | NODE_ZCL23 | NODE_NOISE);
        off += 8;
        memset(out + off, 0, 16); off += 16;
        out[off++] = 0; out[off++] = 0;
    }
    zcl_write_u64_le(out + off, UINT64_C(0xa6c3e29b7105d44f)); off += 8;
    static const char agent[] = "/ZClassic23:0.1.0/";
    out[off++] = (uint8_t)(sizeof(agent) - 1);
    memcpy(out + off, agent, sizeof(agent) - 1); off += sizeof(agent) - 1;
    zcl_write_u32_le(out + off, 122); off += 4;
    out[off++] = 1;
    return off;
}

static bool resign(uint8_t *wire, size_t len, const uint8_t transcript[32],
                   const uint8_t seed[32])
{
    if (len < VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES)
        return false;
    uint8_t pub[32], secret[32];
    ed25519_keypair(pub, secret, seed);
    uint8_t preimage[sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN) + 32 +
                     VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES];
    size_t unsigned_len = len - VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES;
    size_t off = 0;
    memcpy(preimage + off, VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN,
           sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN));
    off += sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN);
    memcpy(preimage + off, transcript, 32); off += 32;
    memcpy(preimage + off, wire, unsigned_len); off += unsigned_len;
    ed25519_sign(wire + unsigned_len, preimage, off, secret, pub);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(preimage, off);
    return true;
}

static bool make_find(const struct vcs_zcode_dht_delegation *delegation,
                      const uint8_t node_id[32], uint64_t generation,
                      const uint8_t transcript[32], const uint8_t seed[32],
                      uint8_t query_byte, uint8_t *wire, size_t *len)
{
    struct vcs_zcode_dht_msg_find_node msg = {.session_generation = generation,
                                              .delegation = *delegation};
    memcpy(msg.sender_node_id, node_id, 32);
    memset(msg.query_id, query_byte, sizeof(msg.query_id));
    memset(msg.target_node_id, 0x7a, sizeof(msg.target_node_id));
    return vcs_zcode_dht_msg_serialize_find_node(
               &msg, transcript, seed, wire,
               VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES, len) == VCS_ZCODE_DHT_OK;
}

static bool make_nodes(const struct vcs_zcode_dht_delegation *delegation,
                       const uint8_t node_id[32], uint64_t generation,
                       const uint8_t transcript[32], const uint8_t seed[32],
                       const uint8_t query[16], bool poison,
                       uint8_t *wire, size_t *len)
{
    struct vcs_zcode_dht_msg_nodes msg = {.session_generation = generation,
                                          .delegation = *delegation};
    memcpy(msg.sender_node_id, node_id, 32);
    memcpy(msg.query_id, query, 16);
    msg.contact_count = poison ? 2 : 1;
    memcpy(msg.node_ids[0], node_id, 32);
    if (poison) {
        memset(msg.node_ids[1], 0xff, 32);
        if (memcmp(msg.node_ids[0], msg.node_ids[1], 32) > 0) {
            uint8_t tmp[32];
            memcpy(tmp, msg.node_ids[0], 32);
            memcpy(msg.node_ids[0], msg.node_ids[1], 32);
            memcpy(msg.node_ids[1], tmp, 32);
        }
    }
    if (vcs_zcode_dht_msg_serialize_nodes(
            &msg, transcript, seed, wire,
            VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES, len) != VCS_ZCODE_DHT_OK)
        return false;
    if (poison) {
        size_t nodes_off = VCS_ZCODE_DHT_MSGS_HEADER_BYTES +
                           VCS_ZCODE_DHT_MSGS_AUTH_BYTES + 1;
        memcpy(wire + nodes_off + 32, wire + nodes_off, 32);
        return resign(wire, *len, transcript, seed);
    }
    return true;
}

static int connect_ipv4(const char *host, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int attack_peer(const char *host, uint16_t port, const char *datadir)
{
    char path[1400], err[160];
    uint8_t noise_priv[32], online_seed[32], online_pub[32], node_id[32];
    struct vcs_zcode_dht_delegation delegation;
    snprintf(path, sizeof(path), "%s/v2_identity.key", datadir);
    if (!read_exact_0600(path, noise_priv, sizeof(noise_priv)) ||
        !vcs_zcode_dht_online_key_load(datadir, online_seed, online_pub,
                                       err, sizeof(err)) ||
        !vcs_zcode_dht_delegation_load(datadir, &delegation, err,
                                       sizeof(err)) ||
        !vcs_zcode_dht_delegation_node_id(node_id, &delegation)) {
        fprintf(stderr, "identity load failed: %s\n", err);
        return 2;
    }
    int fd = connect_ipv4(host, port);
    if (fd < 0) {
        perror("connect");
        return 2;
    }
    uint8_t *msg1 = NULL;
    size_t msg1_len = 0;
    struct noise_transport *transport = noise_transport_begin(
        true, noise_priv, regtest_magic, &msg1, &msg1_len);
    memory_cleanse(noise_priv, sizeof(noise_priv));
    struct app_buffer app = {0};
    bool ok = transport && msg1_len == 32 && write_all_fd(fd, msg1, msg1_len);
    free(msg1);
    for (int i = 0; ok && transport->state != NOISE_ESTABLISHED && i < 20; i++)
        ok = feed_once(fd, transport, &app, 1000);
    struct noise_transport_snapshot snapshot;
    ok = ok && noise_transport_snapshot(transport, &snapshot) &&
         snapshot.established;
    uint8_t version[128];
    size_t version_len = build_version(version);
    ok = ok && send_p2p(fd, transport, "version", version, version_len);

    bool saw_version = false, saw_verack = false, sent_verack = false;
    uint8_t peer_query[16] = {0};
    bool saw_peer_query = false;
    uint8_t payload[APP_CAP];
    for (int i = 0; ok && (!saw_version || !saw_verack) && i < 30; i++) {
        ok = feed_once(fd, transport, &app, 1000);
        char command[13]; size_t payload_len = 0;
        while (ok && pop_p2p(&app, command, payload, sizeof(payload),
                             &payload_len)) {
            if (strcmp(command, "version") == 0) {
                saw_version = true;
                if (!sent_verack) {
                    ok = send_p2p(fd, transport, "verack", NULL, 0);
                    sent_verack = ok;
                }
            } else if (strcmp(command, "verack") == 0) {
                saw_verack = true;
            }
        }
    }
    ok = ok && saw_version && saw_verack;

    /* Wait for the responder's bootstrap FIND_NODE and retain its query id
     * for the deliberately late NODES response below. */
    for (int i = 0; ok && !saw_peer_query && i < 30; i++) {
        (void)feed_once(fd, transport, &app, 500);
        char command[13]; size_t payload_len = 0;
        while (pop_p2p(&app, command, payload, sizeof(payload), &payload_len))
            if (strcmp(command, "zpkgswm") == 0 &&
                payload_len >= VCS_ZCODE_DHT_FIND_NODE_WIRE_BYTES &&
                payload[10] == VCS_ZCODE_DHT_MSG_FIND_NODE) {
                memcpy(peer_query, payload + VCS_ZCODE_DHT_MSGS_HEADER_BYTES +
                       8 + 32, 16);
                saw_peer_query = true;
            }
    }
    ok = ok && saw_peer_query;

    uint8_t wire[VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES + 1];
    size_t wire_len = 0;
    ok = ok && make_find(&delegation, node_id, snapshot.connection_generation,
                         snapshot.transcript_hash, online_seed, 0x11,
                         wire, &wire_len);
    ok = ok && send_p2p(fd, transport, "zpkgswm", wire, wire_len);
    struct timespec short_pause = {.tv_nsec = 200000000};
    nanosleep(&short_pause, NULL);
    ok = ok && send_p2p(fd, transport, "zpkgswm",
                        (const uint8_t *)"ZCDHTM", 6);
    memset(wire, 0, sizeof(wire)); memcpy(wire, "ZCDHTM", 6);
    ok = ok && send_p2p(fd, transport, "zpkgswm", wire, sizeof(wire));

    /* Put more than the old 16-entry replay-cache population through the
     * real Noise session while staying beneath the 4/s admission rate. The
     * first query must remain live in the full 30-second replay ledger. */
    struct timespec replay_pace = {.tv_nsec = 350000000};
    for (uint8_t i = 0; ok && i < 24; i++) {
        ok = make_find(&delegation, node_id, snapshot.connection_generation,
                       snapshot.transcript_hash, online_seed,
                       (uint8_t)(0x40 + i), wire, &wire_len) &&
             send_p2p(fd, transport, "zpkgswm", wire, wire_len);
        nanosleep(&replay_pace, NULL);
    }
    ok = ok && make_find(&delegation, node_id, snapshot.connection_generation,
                         snapshot.transcript_hash, online_seed, 0x11,
                         wire, &wire_len);
    ok = ok && send_p2p(fd, transport, "zpkgswm", wire, wire_len); /* replay */
    wire[VCS_ZCODE_DHT_MSGS_HEADER_BYTES + 8] ^= 1; /* sender mismatch */
    ok = ok && send_p2p(fd, transport, "zpkgswm", wire, wire_len);

    uint8_t arbitrary_query[16]; memset(arbitrary_query, 0x33, 16);
    ok = ok && make_nodes(&delegation, node_id, snapshot.connection_generation,
                          snapshot.transcript_hash, online_seed,
                          arbitrary_query, false, wire, &wire_len);
    ok = ok && send_p2p(fd, transport, "zpkgswm", wire, wire_len);
    ok = ok && make_nodes(&delegation, node_id, snapshot.connection_generation,
                          snapshot.transcript_hash, online_seed,
                          arbitrary_query, true, wire, &wire_len);
    ok = ok && send_p2p(fd, transport, "zpkgswm", wire, wire_len);

    /* Cross the per-query deadline but stay inside the 30-second expired-ID
     * tombstone so this is classified as an expired response, not merely an
     * unknown unsolicited response. */
    sleep(VCS_ZCODE_DHT_SERVICE_QUERY_TIMEOUT_S + 1);
    ok = ok && make_nodes(&delegation, node_id, snapshot.connection_generation,
                          snapshot.transcript_hash, online_seed, peer_query,
                          false, wire, &wire_len);
    ok = ok && send_p2p(fd, transport, "zpkgswm", wire, wire_len);
    nanosleep(&short_pause, NULL);

    memory_cleanse(online_seed, sizeof(online_seed));
    memory_cleanse(version, sizeof(version));
    noise_transport_free(transport);
    close(fd);
    if (!ok) {
        fprintf(stderr, "acceptance Noise attack sequence failed\n");
        return 2;
    }
    puts("attack-sequence-sent");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "pubkey") == 0) {
        uint8_t seed[32], pubkey[32], secret_copy[32];
        if (strlen(argv[2]) != 64 ||
            !zcl_hex_decode_lower(argv[2], seed, sizeof(seed))) {
            memory_cleanse(seed, sizeof(seed));
            fprintf(stderr, "seed must be exactly 64 lowercase hex characters\n");
            return 2;
        }
        zcl_ed25519_keypair(pubkey, secret_copy, seed);
        memory_cleanse(secret_copy, sizeof(secret_copy));
        memory_cleanse(seed, sizeof(seed));
        char hex[65];
        zcl_hex_encode(pubkey, sizeof(pubkey), hex);
        puts(hex);
        memory_cleanse(pubkey, sizeof(pubkey));
        memory_cleanse(hex, sizeof(hex));
        return 0;
    }
    if (argc == 5 && strcmp(argv[1], "attack") == 0) {
        char *end = NULL;
        unsigned long port = strtoul(argv[3], &end, 10);
        if (!end || *end || port == 0 || port > 65535)
            return usage(argv[0]);
        return attack_peer(argv[2], (uint16_t)port, argv[4]);
    }
    return usage(argv[0]);
}
