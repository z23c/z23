/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directlink transport addresses and the "observed address" message.
 *
 * A paired peer tells us the transport address from which it sees our
 * traffic. The message travels inside the authenticated paired stream, so it
 * carries no signature of its own; the decoder still treats every byte as
 * untrusted input and accepts exactly one shape.
 *
 * Wire format, version 1 (little-endian):
 *
 *   offset 0  version  u8   1
 *   offset 1  proto    u8   1 = UDP, 2 = TCP
 *   offset 2  family   u8   4 or 6
 *   offset 3  port     u16  1..65535
 *   offset 5  ip       4 bytes (family 4) or 16 bytes (family 6)
 *
 * The decoder rejects trailing bytes, unknown versions, protocols and
 * families, port 0, and unspecified, loopback, multicast, broadcast,
 * reserved and IPv4-mapped IPv6 addresses.
 */

#ifndef ZCL_GAMELINK_DIRECTLINK_ADDR_H
#define ZCL_GAMELINK_DIRECTLINK_ADDR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DIRECTLINK_OBSERVED_VERSION 1u
#define DIRECTLINK_OBSERVED_MAX_BYTES 21u

enum directlink_proto { DIRECTLINK_PROTO_UDP = 1, DIRECTLINK_PROTO_TCP = 2 };

enum directlink_family { DIRECTLINK_V4 = 4, DIRECTLINK_V6 = 6 };

/* `ip` holds 4 significant bytes for family 4 and 16 for family 6; unused
 * bytes are zero. `port` is in host order. */
struct directlink_addr {
    uint8_t family;
    uint8_t ip[16];
    uint16_t port;
};

enum directlink_addr_class {
    DIRECTLINK_ADDR_INVALID = 0, /* unspecified, multicast, reserved, mapped */
    DIRECTLINK_ADDR_LOOPBACK,
    DIRECTLINK_ADDR_PRIVATE, /* RFC 1918, shared 100.64/10, link-local, ULA */
    DIRECTLINK_ADDR_PUBLIC
};

enum directlink_addr_class directlink_addr_classify(
    const struct directlink_addr *addr);

/* Family, significant ip bytes and port all equal. */
bool directlink_addr_equal(const struct directlink_addr *a,
                           const struct directlink_addr *b);

/* Family and significant ip bytes equal; the port is ignored. */
bool directlink_addr_same_host(const struct directlink_addr *a,
                               const struct directlink_addr *b);

/* Every way a directlink codec refuses. */
enum directlink_status {
    DIRECTLINK_OK = 0,
    DIRECTLINK_ERR_ARGUMENT,     /* NULL argument or missing peer identity */
    DIRECTLINK_ERR_CAPACITY,     /* output buffer too small */
    DIRECTLINK_ERR_TRUNCATED,    /* input ends inside a field */
    DIRECTLINK_ERR_TRAILING,     /* bytes after the last field */
    DIRECTLINK_ERR_VERSION,
    DIRECTLINK_ERR_FIELD,        /* unknown enum value, zero count, bad range */
    DIRECTLINK_ERR_PORT,         /* port 0 */
    DIRECTLINK_ERR_ADDRESS,      /* address class not allowed here */
    DIRECTLINK_ERR_POLICY,       /* policy refused; see the refusal out-param */
    DIRECTLINK_ERR_SCOPE,        /* message scope differs from the peer's */
    DIRECTLINK_ERR_REPLAY,       /* (peer, session, nonce) already seen */
    DIRECTLINK_ERR_CACHE_FULL    /* replay cache has no free slot */
};

struct directlink_observed {
    enum directlink_proto proto;
    struct directlink_addr addr;
};

/* Encode into `out`. On any failure `*out_len` is 0 and `out` is untouched. */
enum directlink_status directlink_observed_encode(
    const struct directlink_observed *observed, uint8_t *out, size_t cap,
    size_t *out_len);

/* Strict decode of a whole message. `*out` is written only on success. */
enum directlink_status directlink_observed_decode(
    const uint8_t *in, size_t len, struct directlink_observed *out);

/* Shared with the punch codec: one address as family | port | ip, and the
 * matching strict read. `allow` is a mask of DIRECTLINK_ALLOW_* flags naming
 * the non-public classes that may pass; unspecified, multicast and reserved
 * addresses never pass. */
#define DIRECTLINK_ALLOW_PUBLIC_ONLY 0u
#define DIRECTLINK_ALLOW_PRIVATE 1u
#define DIRECTLINK_ALLOW_LOOPBACK 2u
struct zcl_codec_writer;
struct zcl_codec_reader;
enum directlink_status directlink_addr_write(struct zcl_codec_writer *writer,
                                             const struct directlink_addr *addr,
                                             unsigned allow);
enum directlink_status directlink_addr_read(struct zcl_codec_reader *reader,
                                            struct directlink_addr *addr,
                                            unsigned allow);

#endif /* ZCL_GAMELINK_DIRECTLINK_ADDR_H */
