/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink address classification and the observed-address codec. See
 * gamelink/directlink_addr.h for the wire format. */

#include "gamelink/directlink_addr.h"

#include "codec/cursor.h"

#include <string.h>

static size_t addr_bytes(uint8_t family)
{
    return family == DIRECTLINK_V4 ? 4u : family == DIRECTLINK_V6 ? 16u : 0u;
}

/* Special-purpose IPv4 blocks that are never a peer's routable address:
 * 192.0.0.0/24, documentation 192.0.2.0/24, 198.51.100.0/24 and
 * 203.0.113.0/24, benchmarking 198.18.0.0/15, deprecated 6to4 relay
 * 192.88.99.0/24. */
static bool reserved_v4(const uint8_t *ip)
{
    return (ip[0] == 192 && ip[1] == 0 && (ip[2] == 0 || ip[2] == 2)) ||
           (ip[0] == 198 && ((ip[1] & 0xFEu) == 18 ||
                             (ip[1] == 51 && ip[2] == 100))) ||
           (ip[0] == 203 && ip[1] == 0 && ip[2] == 113) ||
           (ip[0] == 192 && ip[1] == 88 && ip[2] == 99);
}

static enum directlink_addr_class classify_v4(const uint8_t *ip)
{
    if (ip[0] == 0 || ip[0] >= 224 || reserved_v4(ip))
        return DIRECTLINK_ADDR_INVALID;
    if (ip[0] == 127)
        return DIRECTLINK_ADDR_LOOPBACK;
    if (ip[0] == 10 || (ip[0] == 172 && (ip[1] & 0xF0u) == 16) ||
        (ip[0] == 192 && ip[1] == 168) || (ip[0] == 169 && ip[1] == 254) ||
        (ip[0] == 100 && (ip[1] & 0xC0u) == 64))
        return DIRECTLINK_ADDR_PRIVATE;
    return DIRECTLINK_ADDR_PUBLIC;
}

static bool zero_prefix(const uint8_t *ip, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (ip[i] != 0)
            return false;
    return true;
}

/* Special-purpose IPv6 blocks: documentation 2001:db8::/32, Teredo 2001::/32,
 * 6to4 2002::/16, NAT64 64:ff9b::/96 and 64:ff9b:1::/48, deprecated
 * site-local fec0::/10. */
static bool prefix_match(const uint8_t *ip, const uint8_t *prefix, unsigned bits)
{
    if (memcmp(ip, prefix, bits / 8u) != 0)
        return false;
    unsigned rest = bits % 8u;
    uint8_t mask = (uint8_t)(0xFFu << (8u - rest));
    return rest == 0 || ((ip[bits / 8u] ^ prefix[bits / 8u]) & mask) == 0;
}

static bool reserved_v6(const uint8_t *ip)
{
    static const struct {
        uint8_t prefix[12];
        unsigned bits;
    } k_reserved[] = {
        {{0x20, 0x01, 0x0D, 0xB8}, 32}, /* documentation */
        {{0x20, 0x01, 0x00, 0x00}, 32}, /* Teredo */
        {{0x20, 0x02}, 16},             /* 6to4 */
        {{0x00, 0x64, 0xFF, 0x9B}, 96}, /* NAT64 */
        {{0x00, 0x64, 0xFF, 0x9B, 0x00, 0x01}, 48}, /* NAT64 local */
        {{0xFE, 0xC0}, 10},             /* site-local */
    };
    for (size_t i = 0; i < sizeof k_reserved / sizeof k_reserved[0]; i++)
        if (prefix_match(ip, k_reserved[i].prefix, k_reserved[i].bits))
            return true;
    return false;
}

static enum directlink_addr_class classify_v6(const uint8_t *ip)
{
    if (ip[0] == 0xFFu || reserved_v6(ip))
        return DIRECTLINK_ADDR_INVALID; /* multicast or special-purpose */
    if (zero_prefix(ip, 12)) {
        /* ::, ::1 and the deprecated IPv4-compatible block. */
        bool loopback = zero_prefix(ip, 15) && ip[15] == 1;
        return loopback ? DIRECTLINK_ADDR_LOOPBACK : DIRECTLINK_ADDR_INVALID;
    }
    if (zero_prefix(ip, 10) && ip[10] == 0xFFu && ip[11] == 0xFFu)
        return DIRECTLINK_ADDR_INVALID; /* IPv4-mapped: use family 4 */
    if ((ip[0] & 0xFEu) == 0xFCu || (ip[0] == 0xFEu && (ip[1] & 0xC0u) == 0x80u))
        return DIRECTLINK_ADDR_PRIVATE;
    return DIRECTLINK_ADDR_PUBLIC;
}

enum directlink_addr_class directlink_addr_classify(
    const struct directlink_addr *addr)
{
    if (!addr)
        return DIRECTLINK_ADDR_INVALID;
    if (addr->family == DIRECTLINK_V4)
        return classify_v4(addr->ip);
    if (addr->family == DIRECTLINK_V6)
        return classify_v6(addr->ip);
    return DIRECTLINK_ADDR_INVALID;
}

bool directlink_addr_same_host(const struct directlink_addr *a,
                               const struct directlink_addr *b)
{
    if (!a || !b || a->family != b->family)
        return false;
    size_t n = addr_bytes(a->family);
    return n != 0 && memcmp(a->ip, b->ip, n) == 0;
}

bool directlink_addr_equal(const struct directlink_addr *a,
                           const struct directlink_addr *b)
{
    return directlink_addr_same_host(a, b) && a->port == b->port;
}

static enum directlink_status addr_check(const struct directlink_addr *addr,
                                         unsigned allow)
{
    if (addr_bytes(addr->family) == 0)
        return DIRECTLINK_ERR_FIELD;
    if (addr->port == 0)
        return DIRECTLINK_ERR_PORT;
    enum directlink_addr_class cls = directlink_addr_classify(addr);
    if (cls == DIRECTLINK_ADDR_PUBLIC)
        return DIRECTLINK_OK;
    if ((cls == DIRECTLINK_ADDR_PRIVATE && (allow & DIRECTLINK_ALLOW_PRIVATE)) ||
        (cls == DIRECTLINK_ADDR_LOOPBACK && (allow & DIRECTLINK_ALLOW_LOOPBACK)))
        return DIRECTLINK_OK;
    return DIRECTLINK_ERR_ADDRESS;
}

enum directlink_status directlink_addr_write(struct zcl_codec_writer *writer,
                                             const struct directlink_addr *addr,
                                             unsigned allow)
{
    if (!writer || !addr)
        return DIRECTLINK_ERR_ARGUMENT;
    enum directlink_status status = addr_check(addr, allow);
    if (status != DIRECTLINK_OK)
        return status;
    if (!zcl_codec_write_u8(writer, addr->family) ||
        !zcl_codec_write_u16le(writer, addr->port) ||
        !zcl_codec_write_bytes(writer, addr->ip, addr_bytes(addr->family)))
        return DIRECTLINK_ERR_CAPACITY;
    return DIRECTLINK_OK;
}

enum directlink_status directlink_addr_read(struct zcl_codec_reader *reader,
                                            struct directlink_addr *addr,
                                            unsigned allow)
{
    struct directlink_addr tmp;
    memset(&tmp, 0, sizeof tmp);
    if (!reader || !addr)
        return DIRECTLINK_ERR_ARGUMENT;
    if (!zcl_codec_read_u8(reader, &tmp.family) ||
        !zcl_codec_read_u16le(reader, &tmp.port))
        return DIRECTLINK_ERR_TRUNCATED;
    size_t n = addr_bytes(tmp.family);
    if (n == 0)
        return DIRECTLINK_ERR_FIELD;
    if (!zcl_codec_read_bytes(reader, tmp.ip, n))
        return DIRECTLINK_ERR_TRUNCATED;
    enum directlink_status status = addr_check(&tmp, allow);
    if (status != DIRECTLINK_OK)
        return status;
    *addr = tmp;
    return DIRECTLINK_OK;
}

enum directlink_status directlink_observed_encode(
    const struct directlink_observed *observed, uint8_t *out, size_t cap,
    size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    if (!observed || !out || !out_len)
        return DIRECTLINK_ERR_ARGUMENT;
    if (observed->proto != DIRECTLINK_PROTO_UDP &&
        observed->proto != DIRECTLINK_PROTO_TCP)
        return DIRECTLINK_ERR_FIELD;
    uint8_t buf[DIRECTLINK_OBSERVED_MAX_BYTES];
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, buf, sizeof buf);
    if (!zcl_codec_write_u8(&writer, DIRECTLINK_OBSERVED_VERSION) ||
        !zcl_codec_write_u8(&writer, (uint8_t)observed->proto))
        return DIRECTLINK_ERR_CAPACITY;
    enum directlink_status status =
        directlink_addr_write(&writer, &observed->addr,
                              DIRECTLINK_ALLOW_PRIVATE);
    size_t written = 0;
    if (status != DIRECTLINK_OK || !zcl_codec_writer_finish(&writer, &written))
        return status != DIRECTLINK_OK ? status : DIRECTLINK_ERR_CAPACITY;
    if (written > cap)
        return DIRECTLINK_ERR_CAPACITY;
    memcpy(out, buf, written);
    *out_len = written;
    return DIRECTLINK_OK;
}

enum directlink_status directlink_observed_decode(
    const uint8_t *in, size_t len, struct directlink_observed *out)
{
    if (!in || !out)
        return DIRECTLINK_ERR_ARGUMENT;
    struct zcl_codec_reader reader;
    zcl_codec_reader_init(&reader, in, len);
    uint8_t version = 0;
    uint8_t proto = 0;
    if (!zcl_codec_read_u8(&reader, &version) ||
        !zcl_codec_read_u8(&reader, &proto))
        return DIRECTLINK_ERR_TRUNCATED;
    if (version != DIRECTLINK_OBSERVED_VERSION)
        return DIRECTLINK_ERR_VERSION;
    if (proto != DIRECTLINK_PROTO_UDP && proto != DIRECTLINK_PROTO_TCP)
        return DIRECTLINK_ERR_FIELD;
    struct directlink_observed tmp;
    memset(&tmp, 0, sizeof tmp);
    tmp.proto = (enum directlink_proto)proto;
    enum directlink_status status = directlink_addr_read(&reader, &tmp.addr,
                                                         DIRECTLINK_ALLOW_PRIVATE);
    if (status != DIRECTLINK_OK)
        return status;
    if (!zcl_codec_reader_finish(&reader))
        return DIRECTLINK_ERR_TRAILING;
    *out = tmp;
    return DIRECTLINK_OK;
}
