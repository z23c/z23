/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: build a DNS TXT question and parse the answer, as pure bytes in
 * and bytes out, so the release pin's second consistency channel needs no
 * external program on the user's machine.
 *
 * WHY THIS EXISTS. platform/packaging/install/install.sh reached this channel by
 * shelling out to dig, host or nslookup, and reported `dns=no-dns-tool` when
 * a genuinely minimal container had none of the three — a stranger losing a
 * whole consistency source because of what their base image happened to
 * install. RFC 1035 §4.1 message format is about a hundred lines; three
 * external tools and three output formats to scrape were more code than this,
 * in a language where every one of those scrapes ran unverified.
 *
 * Nothing here opens a socket. The transport is in tools/install/
 * z23_bootstrap.c; keeping the wire format pure is what lets
 * tests/harness/src/test_z23_front_door.c feed it a hostile datagram byte by byte
 * without a network.
 */

#include "install/front_door.h"

#include <string.h>

/* RFC 1035 §4.1.1 header, §3.2.1 QTYPE=16 (TXT), §3.2.4 QCLASS=1 (IN). */
#define DNS_HEADER_LEN 12
#define DNS_TYPE_TXT 16
#define DNS_CLASS_IN 1
/* A pin TXT record is 140 bytes inside a ~200-byte message. 8 pointer hops is
 * far more than any sane answer needs and is the bound that stops a crafted
 * chain of compression pointers from costing us unbounded work. */
#define DNS_MAX_POINTER_HOPS 8

static uint16_t rd16(const unsigned char *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

size_t fd_dns_txt_query(uint16_t id, const char *name,
                        unsigned char *out, size_t out_len)
{
    if (!name || !out)
        return 0;
    const size_t name_len = strlen(name);
    /* RFC 1035 §2.3.4: 255 octets for the wire name, which is 253 characters
     * of presentation text plus the leading length and the root label. */
    if (name_len == 0 || name_len > 253)
        return 0;

    size_t need = DNS_HEADER_LEN + name_len + 2 + 4;
    if (need > out_len || need > FD_DNS_QUERY_MAX)
        return 0;

    memset(out, 0, need);
    out[0] = (unsigned char)(id >> 8);
    out[1] = (unsigned char)(id & 0xffu);
    out[2] = 0x01;  /* QR=0 OPCODE=QUERY RD=1: we want a recursive answer. */
    out[5] = 0x01;  /* QDCOUNT = 1 */

    size_t w = DNS_HEADER_LEN;
    const char *label = name;
    for (;;) {
        const char *dot = strchr(label, '.');
        const size_t len = dot ? (size_t)(dot - label) : strlen(label);
        /* A trailing dot is the root label and ends the name; an empty label
         * anywhere else is not a name we can ask about. */
        if (len == 0) {
            if (dot && dot[1] == '\0')
                break;
            return 0;
        }
        if (len > 63)
            return 0;
        out[w++] = (unsigned char)len;
        memcpy(out + w, label, len);
        w += len;
        if (!dot)
            break;
        label = dot + 1;
        if (*label == '\0')
            break;
    }
    out[w++] = 0x00;  /* root label terminates the name */
    out[w++] = 0x00;
    out[w++] = DNS_TYPE_TXT;
    out[w++] = 0x00;
    out[w++] = DNS_CLASS_IN;
    return w;
}

/* Advance `*off` past one wire-format name. Compression pointers (RFC 1035
 * §4.1.4) are followed only to a STRICTLY LOWER offset and at most
 * DNS_MAX_POINTER_HOPS times: a forward or self-referential pointer is the
 * classic way to make a naive resolver loop forever on one datagram, and we
 * are parsing bytes an unauthenticated resolver handed us. Returns false on
 * anything malformed. */
static bool skip_name(const unsigned char *msg, size_t len, size_t *off)
{
    size_t at = *off;
    size_t hops = 0;
    bool jumped = false;
    for (;;) {
        if (at >= len)
            return false;
        const unsigned char b = msg[at];
        if ((b & 0xc0u) == 0xc0u) {
            if (at + 1 >= len)
                return false;
            const size_t target = (size_t)(rd16(msg + at) & 0x3fffu);
            if (target >= at)
                return false;
            if (++hops > DNS_MAX_POINTER_HOPS)
                return false;
            if (!jumped) {
                *off = at + 2;
                jumped = true;
            }
            at = target;
            continue;
        }
        if ((b & 0xc0u) != 0)
            return false;  /* reserved label type */
        if (b == 0) {
            if (!jumped)
                *off = at + 1;
            return true;
        }
        at += 1u + b;
    }
}

enum fd_dns_status fd_dns_txt_parse(const unsigned char *msg, size_t len,
                                    uint16_t id, struct fd_dns_txt *out)
{
    if (!out)
        return FD_DNS_MALFORMED;
    memset(out, 0, sizeof *out);
    if (!msg || len < DNS_HEADER_LEN)
        return FD_DNS_MALFORMED;

    /* An answer to a question we did not ask is not our answer. This is the
     * only cheap off-path-spoofing check plain DNS offers, and dropping it
     * would let anything that can guess the port write our pin channel. */
    if (rd16(msg) != id)
        return FD_DNS_MALFORMED;
    const uint16_t flags = rd16(msg + 2);
    if ((flags & 0x8000u) == 0)
        return FD_DNS_MALFORMED;  /* not a response */
    if (flags & 0x0200u)
        return FD_DNS_TRUNCATED;  /* TC: the answer did not fit a datagram */
    if ((flags & 0x000fu) != 0)
        return FD_DNS_NO_ANSWER;  /* NXDOMAIN, SERVFAIL, REFUSED, ... */

    const uint16_t qdcount = rd16(msg + 4);
    const uint16_t ancount = rd16(msg + 6);
    size_t off = DNS_HEADER_LEN;
    for (uint16_t i = 0; i < qdcount; i++) {
        if (!skip_name(msg, len, &off))
            return FD_DNS_MALFORMED;
        if (off + 4 > len)
            return FD_DNS_MALFORMED;
        off += 4;
    }

    for (uint16_t i = 0; i < ancount; i++) {
        if (!skip_name(msg, len, &off))
            return FD_DNS_MALFORMED;
        if (off + 10 > len)
            return FD_DNS_MALFORMED;
        const uint16_t rtype = rd16(msg + off);
        const uint16_t rclass = rd16(msg + off + 2);
        const uint16_t rdlength = rd16(msg + off + 8);
        off += 10;
        if (off + rdlength > len)
            return FD_DNS_MALFORMED;
        const size_t rdata = off;
        off += rdlength;
        /* CNAMEs and anything else in the answer section are skipped, not
         * refused: a TXT name behind a CNAME is a legitimate answer. */
        if (rtype != DNS_TYPE_TXT || rclass != DNS_CLASS_IN)
            continue;

        /* RFC 1035 §3.3.14: TXT RDATA is one or more character-strings, each
         * a length octet followed by that many bytes. */
        size_t p = rdata;
        while (p < rdata + rdlength) {
            const size_t slen = msg[p];
            p++;
            if (p + slen > rdata + rdlength)
                return FD_DNS_MALFORMED;
            if (out->count < FD_DNS_MAX_STRINGS && slen < FD_DNS_STRING_MAX) {
                memcpy(out->s[out->count], msg + p, slen);
                out->s[out->count][slen] = '\0';
                out->count++;
            }
            p += slen;
        }
    }

    return out->count > 0 ? FD_DNS_OK : FD_DNS_NO_ANSWER;
}
