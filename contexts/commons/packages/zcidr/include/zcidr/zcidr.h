/*
 * zcidr — IPv4/IPv6 address and CIDR prefix parsing, formatting, and
 * containment tests, in freestanding C23 with no network headers.
 *
 * Parsing is strict:
 *   - IPv4: four decimal octets 0..255, no leading zeros, no hex, no
 *     octal, no shorthand forms ("127.1" is rejected).
 *   - IPv6: eight 16-bit groups in lowercase-or-uppercase hex with at
 *     most one "::" compression; an embedded IPv4 tail ("::ffff:1.2.3.4")
 *     is accepted; zone ids ("fe80::1%eth0") are rejected.
 *   - A CIDR prefix length "/n" is optional and must be within the
 *     address family's range (0..32 or 0..128), no leading zeros.
 *
 * Containment is a masked comparison on the raw bytes; the host part
 * of the network address is ignored (192.168.1.77/24 contains the
 * same set as 192.168.1.0/24).
 */
#ifndef ZCIDR_H
#define ZCIDR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint8_t b[4];
} zcidr_v4;

typedef struct {
  uint8_t b[16];
} zcidr_v6;

typedef struct {
  int is_v6;        /* 0 = IPv4, 1 = IPv6 */
  int has_prefix;   /* 0 = bare address, 1 = "/n" was present */
  unsigned prefix;  /* 0..32 (v4) or 0..128 (v6); valid if has_prefix */
  zcidr_v4 v4;
  zcidr_v6 v6;
} zcidr;

/* Parse a bare address or CIDR.  Returns 1 on success, 0 on error. */
int zcidr_parse(const char *s, size_t len, zcidr *out);

/* Bare-address-only variants (reject any "/"). */
int zcidr_parse_v4(const char *s, size_t len, zcidr_v4 *out);
int zcidr_parse_v6(const char *s, size_t len, zcidr_v6 *out);

/*
 * Containment: does `addr` (bare address, same family) fall inside the
 * network described by `net`?  Returns 0 for family mismatch or when
 * `net` carries no prefix (a bare address contains only itself).
 */
int zcidr_contains(const zcidr *net, const zcidr *addr);

/* Compare two bare addresses: -1/0/1; IPv4 sorts before IPv6. */
int zcidr_cmp(const zcidr *a, const zcidr *b);

/*
 * Format.  snprintf-style: returns the length that would have been
 * written, always NUL-terminates when cap > 0.  IPv6 is formatted in
 * canonical lowercase with maximal left-most "::" compression (a lone
 * zero group is not compressed); IPv4 tails are not used (pure hex
 * groups).  Includes "/n" when the prefix is present.
 */
size_t zcidr_format(const zcidr *c, char *out, size_t cap);
size_t zcidr_format_v4(const zcidr_v4 *a, char *out, size_t cap);
size_t zcidr_format_v6(const zcidr_v6 *a, char *out, size_t cap);

/* Mask the host part in place according to c->prefix (no-op without a
 * prefix). */
void zcidr_network(zcidr *c);

#ifdef __cplusplus
}
#endif

#endif /* ZCIDR_H */
