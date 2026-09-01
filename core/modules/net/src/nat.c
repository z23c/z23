/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * NAT traversal — pure C23 implementation.
 *
 * NAT-PMP (RFC 6886):
 *   Send UDP to gateway:5351, get public IP + port mapping.
 *   Single packet, ~20 bytes. Works on Apple, pfSense, many routers.
 *
 * UPnP IGD:
 *   1. SSDP M-SEARCH multicast to 239.255.255.250:1900
 *   2. Parse LOCATION URL from response
 *   3. Fetch XML device description
 *   4. POST SOAP AddPortMapping action
 *
 * Graceful degradation: NAT-PMP → UPnP → fail silently. */

#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif
#include "net/nat.h"
#include "platform/socket_compat.h"
#include "platform/time_compat.h"
#include "util/log_json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#if defined(_WIN32)
#include <netioapi.h>
#else
#include <unistd.h>
#endif
#include "util/safe_alloc.h"
#include "util/log_macros.h"

#define NAT_PMP_WAIT_MS  2000
#define NAT_SSDP_WAIT_MS 3000
#define NAT_HTTP_BUDGET_MS 3000

static int nat_send_datagram(platform_socket_t socket, const void *data,
                             size_t size, const struct sockaddr *address,
                             size_t address_size)
{
#if defined(_WIN32)
    if (size > INT_MAX || address_size > INT_MAX) return SOCKET_ERROR;
    return sendto(socket, (const char *)data, (int)size, 0, address,
                  (int)address_size);
#else
    return (int)sendto(socket, data, size, 0, address,
                       (socklen_t)address_size);
#endif
}

static int nat_receive_datagram(platform_socket_t socket, void *data,
                                size_t size)
{
    int amount = size > INT_MAX ? INT_MAX : (int)size;
#if defined(_WIN32)
    return recvfrom(socket, (char *)data, amount, 0, NULL, NULL);
#else
    return (int)recvfrom(socket, data, (size_t)amount, 0, NULL, NULL);
#endif
}

/* ════════════════════════════════════════════════════════════════
 *  Gateway discovery
 *
 *  Three arms, one output contract: gw_out holds the 4 IPv4 address bytes
 *  in NETWORK byte order (gw_out[0] is the leading dotted-quad octet),
 *  which is what natpmp_send_recv() copies into sin_addr.
 *
 *    _WIN32   — GetBestRoute2, sin_addr copied verbatim.
 *    __APPLE__ — the PF_ROUTE/NET_RT_DUMP sysctl (nat_route_dump.c);
 *                macOS has no /proc/net/route at all, so before this arm
 *                existed the fopen below simply failed and a Mac node
 *                could not map an inbound port.
 *    Linux    — /proc/net/route. The kernel prints each address as the
 *               host-order value of a network-order in_addr, so a plain
 *               4-byte copy of the parsed word yields network order on
 *               either endianness.
 *
 *  A platform matching none of these REFUSES rather than falling through
 *  to a Linux-only path.
 * ════════════════════════════════════════════════════════════════ */

bool nat_get_gateway(uint8_t gw_out[4])
{
#if defined(_WIN32)
    if (!gw_out || !platform_socket_runtime_init()) return false;
    SOCKADDR_INET destination = {0};
    destination.Ipv4.sin_family = AF_INET;
    destination.Ipv4.sin_addr.s_addr = htonl(UINT32_C(0x08080808));
    MIB_IPFORWARD_ROW2 route;
    SOCKADDR_INET source;
    if (GetBestRoute2(NULL, 0, NULL, &destination, 0, &route, &source) !=
            NO_ERROR ||
        route.NextHop.si_family != AF_INET ||
        route.NextHop.Ipv4.sin_addr.s_addr == 0)
        return false;
    memcpy(gw_out, &route.NextHop.Ipv4.sin_addr, 4);
    return true;
#elif defined(__APPLE__)
    if (!gw_out) LOG_FAIL("nat", "gateway output buffer is NULL");
    return nat_route_dump_default_gateway(gw_out);
#elif defined(__linux__) || defined(__CYGWIN__)
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) LOG_FAIL("nat", "cannot open /proc/net/route");

    char line[256];
    /* /proc/net/route always opens even when the routing table is empty, so
     * a failed header read is the only signal that there is nothing to parse.
     * Distinguishing it from "parsed every row, found no default route" is
     * what makes the two failures separately diagnosable in the log. */
    if (!fgets(line, sizeof(line), f)) { /* column header */
        fclose(f);
        LOG_FAIL("nat", "/proc/net/route has no header line — routing table "
                        "unreadable or empty");
    }
    while (fgets(line, sizeof(line), f)) {
        char iface[32];
        uint32_t dest, gw;
        if (sscanf(line, "%31s %x %x", iface, &dest, &gw) == 3) {
            if (dest == 0 && gw != 0) { /* default route */
                memcpy(gw_out, &gw, 4);
                fclose(f);
                printf("NAT: gateway %d.%d.%d.%d via %s\n",
                       gw_out[0], gw_out[1], gw_out[2], gw_out[3], iface);
                return true;
            }
        }
    }
    fclose(f);
    LOG_FAIL("nat", "no default gateway found in /proc/net/route");
#else
    /* No routing-table reader for this platform. Report unavailable — a
     * fabricated or zero gateway would send NAT-PMP at nothing and make an
     * unsupported platform look supported. */
    (void)gw_out;
    LOG_FAIL("nat", "gateway discovery is not implemented on this platform");
#endif
}

/* ════════════════════════════════════════════════════════════════
 *  NAT-PMP (RFC 6886)
 * ════════════════════════════════════════════════════════════════ */

/* NAT-PMP request/response structures */
struct natpmp_request {
    uint8_t version;    /* 0 */
    uint8_t opcode;     /* 0=external_addr, 1=map_udp, 2=map_tcp */
    uint16_t reserved;
    uint16_t internal_port;  /* network byte order */
    uint16_t external_port;  /* suggested, or 0 */
    uint32_t lifetime;       /* seconds, network byte order */
};

struct natpmp_response {
    uint8_t version;
    uint8_t opcode;     /* 128 + request opcode */
    uint16_t result;    /* 0 = success */
    uint32_t epoch;     /* seconds since boot */
    union {
        uint8_t external_ip[4];  /* for opcode 128 */
        struct {
            uint16_t internal_port;
            uint16_t mapped_port;
            uint32_t lifetime;
        } mapping;  /* for opcode 129/130 */
    };
};

static bool natpmp_send_recv(const uint8_t gw[4], const void *req, size_t req_len,
                              void *resp, size_t resp_max, size_t *resp_len)
{
    platform_socket_t sock = platform_socket_open(AF_INET, SOCK_DGRAM, 0,
                                                  true, false);
    if (sock == PLATFORM_SOCKET_INVALID)
        LOG_FAIL("nat", "UDP socket creation failed");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5351);
    memcpy(&addr.sin_addr, gw, 4);

    if (nat_send_datagram(sock, req, req_len, (struct sockaddr *)&addr,
                          sizeof(addr)) < 0) {
        platform_socket_close(sock);
        LOG_FAIL("nat", "NAT-PMP sendto gateway failed");
    }

    /* SO_RCVTIMEO is not a portable operation deadline: Winsock may leave a
     * blocking recvfrom live during shutdown even after another thread has
     * requested stop.  Readiness wait first, then consume the already-ready
     * datagram. */
    int ready = platform_socket_wait_readable(sock, NAT_PMP_WAIT_MS);
    int n = ready > 0 ? nat_receive_datagram(sock, resp, resp_max) : -1;
    platform_socket_close(sock);

    if (n < 8) return false;
    *resp_len = (size_t)n;

    struct natpmp_response *r = resp;
    return ntohs(r->result) == 0;
}

static bool natpmp_get_public_ip(const uint8_t gw[4], uint8_t ip_out[4])
{
    uint8_t req[2] = {0, 0}; /* version=0, opcode=0 (get external addr) */
    struct natpmp_response resp;
    size_t resp_len;

    if (!natpmp_send_recv(gw, req, 2, &resp, sizeof(resp), &resp_len))
        return false;

    if (resp.opcode != 128) LOG_FAIL("nat", "NAT-PMP unexpected opcode: %u (expected 128)", resp.opcode);
    memcpy(ip_out, resp.external_ip, 4);
    log_jsonf(LOG_JSON_INFO, "nat_public_ip",
              "\"protocol\":\"natpmp\",\"ip\":\"%d.%d.%d.%d\"",
              ip_out[0], ip_out[1], ip_out[2], ip_out[3]);
    return true;
}

static bool natpmp_map_port(const uint8_t gw[4], uint16_t internal, uint16_t external,
                             uint32_t lifetime, bool tcp)
{
    struct natpmp_request req;
    memset(&req, 0, sizeof(req));
    req.version = 0;
    req.opcode = tcp ? 2 : 1; /* 1=UDP, 2=TCP */
    req.internal_port = htons(internal);
    req.external_port = htons(external);
    req.lifetime = htonl(lifetime);

    struct natpmp_response resp;
    size_t resp_len;

    if (!natpmp_send_recv(gw, &req, sizeof(req), &resp, sizeof(resp), &resp_len))
        return false;

    uint16_t mapped = ntohs(resp.mapping.mapped_port);
    uint32_t granted = ntohl(resp.mapping.lifetime);
    log_jsonf(LOG_JSON_INFO, "nat_port_mapped",
              "\"protocol\":\"natpmp\",\"transport\":\"%s\","
              "\"internal\":%u,\"external\":%u,\"lifetime_s\":%u",
              tcp ? "tcp" : "udp",
              (unsigned)internal, (unsigned)mapped, (unsigned)granted);
    return true;
}

/* ════════════════════════════════════════════════════════════════
 *  UPnP IGD (SSDP discovery + SOAP control)
 * ════════════════════════════════════════════════════════════════ */

static const char SSDP_SEARCH[] =
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "\r\n";

/* Extract LOCATION URL from SSDP response */
static bool ssdp_extract_location(const char *resp, char *url, size_t url_max)
{
    const char *loc = strstr(resp, "LOCATION:");
    if (!loc) LOG_FAIL("nat", "SSDP response missing LOCATION header");
    loc += 9;
    while (*loc == ' ') loc++;
    const char *end = strstr(loc, "\r\n");
    if (!end) end = loc + strlen(loc);
    size_t len = (size_t)(end - loc);
    if (len >= url_max) LOG_FAIL("nat", "SSDP LOCATION URL too long: %zu >= %zu", len, url_max);
    memcpy(url, loc, len);
    url[len] = 0;
    return true;
}

/* Simple HTTP GET/POST — returns malloc'd response body. Caller frees. */
static char *http_request(const char *host, uint16_t port, const char *method,
                           const char *path, const char *body, size_t body_len,
                           const char *content_type)
{
    platform_socket_t sock = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                  true, false);
    if (sock == PLATFORM_SOCKET_INVALID)
        LOG_NULL("nat", "TCP socket creation failed");

    (void)platform_socket_set_send_timeout(sock, NAT_HTTP_BUDGET_MS);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (platform_socket_parse_address(AF_INET, host, &addr.sin_addr) != 1) {
        platform_socket_close(sock);
        LOG_NULL("nat", "HTTP host is not a numeric IPv4 address");
    }

    /* A blocking connect is not bounded by SO_SNDTIMEO on Winsock.  Drive it
     * nonblocking and accept success only after the socket becomes writable
     * with SO_ERROR=0 inside the same explicit budget. */
    bool connected = platform_socket_set_nonblocking(sock, true);
    if (connected) {
        int rc = platform_socket_connect(sock, (struct sockaddr *)&addr,
                                         sizeof(addr));
        if (rc != 0) {
            int error = platform_socket_last_error();
            connected = platform_socket_error_in_progress(error) &&
                        platform_socket_wait_writable(
                            sock, NAT_HTTP_BUDGET_MS) > 0;
            if (connected) {
                int pending = 0;
                connected = platform_socket_pending_error(sock, &pending) == 0 &&
                            pending == 0;
            }
        }
    }
    if (connected)
        connected = platform_socket_set_nonblocking(sock, false);
    if (!connected) {
        platform_socket_close(sock);
        LOG_NULL("nat", "HTTP connect to %s:%u failed", host, port);
    }

    char header[1024];
    int hlen;
    if (body && body_len > 0) {
        hlen = snprintf(header, sizeof(header),
            "%s %s HTTP/1.1\r\nHost: %s:%d\r\n"
            "Content-Type: %s\r\nContent-Length: %zu\r\n"
            "Connection: close\r\n\r\n",
            method, path, host, port,
            content_type ? content_type : "text/xml", body_len);
    } else {
        hlen = snprintf(header, sizeof(header),
            "%s %s HTTP/1.1\r\nHost: %s:%d\r\n"
            "Connection: close\r\n\r\n",
            method, path, host, port);
    }

    if (hlen <= 0 || (size_t)hlen >= sizeof(header) ||
        !platform_socket_send_all(sock, header, (size_t)hlen)) {
        platform_socket_close(sock);
        LOG_NULL("nat", "HTTP request header send failed");
    }
    if (body && body_len > 0)
        if (!platform_socket_send_all(sock, body, body_len)) {
            platform_socket_close(sock);
            LOG_NULL("nat", "HTTP request body send failed");
        }

    size_t cap = 8192, len = 0;
    char *buf = zcl_malloc(cap, "nat_recv_buf");
    if (!buf) { platform_socket_close(sock); LOG_NULL("nat", "malloc failed for HTTP recv buffer: %zu bytes", cap); }
    const int64_t receive_deadline_ms =
        platform_time_monotonic_ms() + NAT_HTTP_BUDGET_MS;
    for (;;) {
        int64_t remaining_ms =
            receive_deadline_ms - platform_time_monotonic_ms();
        if (remaining_ms <= 0)
            break;
        int wait_ms = remaining_ms > INT_MAX ? INT_MAX : (int)remaining_ms;
        if (platform_socket_wait_readable(sock, wait_ms) <= 0)
            break;
        int n = platform_socket_receive(sock, buf + len, cap - len - 1);
        if (n <= 0) break;
        len += (size_t)n;
        if (len + 1024 > cap) {
            cap *= 2;
            char *nb = zcl_realloc(buf, cap, "nat_recv_buf");
            if (!nb) { free(buf); LOG_NULL("nat", "realloc failed for HTTP response: cap=%zu", cap); }
            buf = nb;
        }
    }
    platform_socket_close(sock);
    buf[len] = 0;

    /* Skip HTTP headers */
    char *body_start = strstr(buf, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        memmove(buf, body_start, strlen(body_start) + 1);
    }
    return buf;
}

/* Parse host, port, path from URL */
static bool parse_url(const char *url, char *host, size_t host_max,
                       uint16_t *port, char *path, size_t path_max)
{
    const char *p = url;
    if (strncmp(p, "http://", 7) == 0) p += 7;
    const char *colon = strchr(p, ':');
    const char *slash = strchr(p, '/');
    if (!slash) slash = p + strlen(p);

    if (colon && colon < slash) {
        size_t hlen = (size_t)(colon - p);
        if (hlen >= host_max) LOG_FAIL("nat", "URL host too long: %zu >= %zu", hlen, host_max);
        memcpy(host, p, hlen); host[hlen] = 0;
        *port = (uint16_t)atoi(colon + 1);
    } else {
        size_t hlen = (size_t)(slash - p);
        if (hlen >= host_max) LOG_FAIL("nat", "URL host too long: %zu >= %zu", hlen, host_max);
        memcpy(host, p, hlen); host[hlen] = 0;
        *port = 80;
    }
    if (*slash) {
        size_t plen = strlen(slash);
        if (plen >= path_max) LOG_FAIL("nat", "URL path too long: %zu >= %zu", plen, path_max);
        memcpy(path, slash, plen + 1);
    } else {
        path[0] = '/'; path[1] = 0;
    }
    return true;
}

/* Find the WANIPConnection control URL from the device XML */
static bool upnp_find_control_url(const char *xml, const char *base_host,
                                    uint16_t base_port,
                                    char *ctrl_url, size_t ctrl_max)
{
    /* Look for WANIPConnection or WANPPPConnection service */
    const char *wan = strstr(xml, "WANIPConnection");
    if (!wan) wan = strstr(xml, "WANPPPConnection");
    if (!wan) LOG_FAIL("nat", "UPnP XML missing WANIPConnection/WANPPPConnection service");

    const char *ctrl = strstr(wan, "<controlURL>");
    if (!ctrl) LOG_FAIL("nat", "UPnP XML missing <controlURL> element");
    ctrl += 12;
    const char *end = strstr(ctrl, "</controlURL>");
    if (!end) LOG_FAIL("nat", "UPnP XML: unterminated <controlURL>");

    size_t len = (size_t)(end - ctrl);
    if (len >= ctrl_max) LOG_FAIL("nat", "UPnP controlURL too long: %zu >= %zu", len, ctrl_max);

    if (ctrl[0] == '/') {
        snprintf(ctrl_url, ctrl_max, "http://%s:%d%.*s",
                 base_host, base_port, (int)len, ctrl);
    } else {
        memcpy(ctrl_url, ctrl, len);
        ctrl_url[len] = 0;
    }
    return true;
}

static bool upnp_add_mapping(const char *ctrl_url, uint16_t external,
                               uint16_t internal, uint32_t lifetime,
                               const char *protocol)
{
    char host[256], path[512];
    uint16_t port;
    if (!parse_url(ctrl_url, host, sizeof(host), &port, path, sizeof(path)))
        LOG_FAIL("nat", "UPnP: failed to parse control URL");

    /* Get local IP for this connection */
    char local_ip[32] = "0.0.0.0";
    {
        platform_socket_t sock = platform_socket_open(AF_INET, SOCK_DGRAM, 0,
                                                      true, false);
        if (sock != PLATFORM_SOCKET_INVALID) {
            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_port = htons(port);
            (void)platform_socket_parse_address(AF_INET, host,
                                                &dest.sin_addr);
            (void)platform_socket_connect(sock, (struct sockaddr *)&dest,
                                          sizeof(dest));
            struct sockaddr_in local;
            memset(&local, 0, sizeof(local));
#if defined(_WIN32)
            int len = sizeof(local);
            (void)getsockname(sock, (struct sockaddr *)&local, &len);
            (void)InetNtopA(AF_INET, &local.sin_addr, local_ip,
                            sizeof(local_ip));
#else
            socklen_t len = sizeof(local);
            (void)getsockname(sock, (struct sockaddr *)&local, &len);
            (void)inet_ntop(AF_INET, &local.sin_addr, local_ip,
                            sizeof(local_ip));
#endif
            platform_socket_close(sock);
        }
    }

    char soap[2048];
    int slen = snprintf(soap, sizeof(soap),
        "<?xml version=\"1.0\"?>"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\""
        " s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        "<s:Body>"
        "<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>%d</NewExternalPort>"
        "<NewProtocol>%s</NewProtocol>"
        "<NewInternalPort>%d</NewInternalPort>"
        "<NewInternalClient>%s</NewInternalClient>"
        "<NewEnabled>1</NewEnabled>"
        "<NewPortMappingDescription>ZClassic</NewPortMappingDescription>"
        "<NewLeaseDuration>%u</NewLeaseDuration>"
        "</u:AddPortMapping>"
        "</s:Body></s:Envelope>",
        external, protocol, internal, local_ip, lifetime);

    char *resp = http_request(host, port, "POST", path, soap, (size_t)slen,
        "text/xml; charset=\"utf-8\"");
    if (!resp) LOG_FAIL("nat", "UPnP SOAP request failed: host=%s port=%u", host, port);

    bool ok = (strstr(resp, "AddPortMappingResponse") != NULL) ||
              (strstr(resp, "200 OK") != NULL);
    if (ok) {
        char proto_safe[8];
        char ip_safe[64];
        log_json_escape(proto_safe, sizeof(proto_safe), protocol);
        log_json_escape(ip_safe, sizeof(ip_safe), local_ip);
        log_jsonf(LOG_JSON_INFO, "nat_port_mapped",
                  "\"protocol\":\"upnp\",\"transport\":\"%s\","
                  "\"internal\":%u,\"external\":%u,"
                  "\"local_ip\":\"%s\",\"lifetime_s\":%u",
                  proto_safe, (unsigned)internal, (unsigned)external,
                  ip_safe, (unsigned)lifetime);
    } else {
        log_jsonf(LOG_JSON_WARN, "nat_port_map_failed",
                  "\"protocol\":\"upnp\"");
    }

    free(resp);
    return ok;
}

static bool upnp_discover_and_map(uint16_t external, uint16_t internal,
                                    uint32_t lifetime, const char *protocol)
{
    /* SSDP M-SEARCH via multicast */
    platform_socket_t sock = platform_socket_open(AF_INET, SOCK_DGRAM, 0,
                                                  true, false);
    if (sock == PLATFORM_SOCKET_INVALID)
        LOG_FAIL("nat", "SSDP socket creation failed");

    struct sockaddr_in mcast;
    memset(&mcast, 0, sizeof(mcast));
    mcast.sin_family = AF_INET;
    mcast.sin_port = htons(1900);
    (void)platform_socket_parse_address(AF_INET, "239.255.255.250",
                                        &mcast.sin_addr);

    (void)nat_send_datagram(sock, SSDP_SEARCH, strlen(SSDP_SEARCH),
                            (struct sockaddr *)&mcast, sizeof(mcast));

    char buf[4096];
    int ready = platform_socket_wait_readable(sock, NAT_SSDP_WAIT_MS);
    int n = ready > 0 ? nat_receive_datagram(sock, buf, sizeof(buf) - 1) : -1;
    platform_socket_close(sock);
    if (n <= 0) LOG_FAIL("nat", "SSDP M-SEARCH got no response");
    buf[n] = 0;

    /* Extract LOCATION */
    char location[512];
    if (!ssdp_extract_location(buf, location, sizeof(location)))
        LOG_FAIL("nat", "SSDP response has no valid LOCATION");
    printf("UPnP: found gateway at %s\n", location);

    /* Fetch device XML */
    char host[256], path[512];
    uint16_t port;
    if (!parse_url(location, host, sizeof(host), &port, path, sizeof(path)))
        LOG_FAIL("nat", "UPnP: failed to parse LOCATION URL: %s", location);

    char *xml = http_request(host, port, "GET", path, NULL, 0, NULL);
    if (!xml) LOG_FAIL("nat", "UPnP: failed to fetch device XML from %s:%u", host, port);

    /* Find control URL */
    char ctrl_url[512];
    bool found = upnp_find_control_url(xml, host, port, ctrl_url, sizeof(ctrl_url));
    free(xml);
    if (!found) LOG_FAIL("nat", "UPnP: no WAN control URL found in device XML");

    printf("UPnP: control URL %s\n", ctrl_url);
    return upnp_add_mapping(ctrl_url, external, internal, lifetime, protocol);
}

/* ════════════════════════════════════════════════════════════════
 *  Public API
 * ════════════════════════════════════════════════════════════════ */

bool nat_add_port_mapping(uint16_t external_port, uint16_t internal_port,
                           uint32_t lifetime, const char *protocol,
                           uint8_t public_ip_out[4])
{
    uint8_t gw[4];
    if (!nat_get_gateway(gw))
        LOG_FAIL("nat", "no gateway for port mapping: ext=%u int=%u",
                 (unsigned)external_port, (unsigned)internal_port);

    bool tcp = (strcmp(protocol, "TCP") == 0);

    /* Try NAT-PMP first */
    if (natpmp_map_port(gw, internal_port, external_port, lifetime, tcp)) {
        if (public_ip_out)
            natpmp_get_public_ip(gw, public_ip_out);
        return true;
    }

    /* Fall back to UPnP */
    if (upnp_discover_and_map(external_port, internal_port, lifetime, protocol)) {
        if (public_ip_out) {
            /* UPnP doesn't directly give us public IP, try NAT-PMP for that */
            natpmp_get_public_ip(gw, public_ip_out);
        }
        return true;
    }

    return false;
}

bool nat_discover_public_ip(uint8_t ip_out[4])
{
    uint8_t gw[4];
    if (!nat_get_gateway(gw))
        LOG_FAIL("nat", "no gateway for public IP discovery");
    return natpmp_get_public_ip(gw, ip_out);
}
