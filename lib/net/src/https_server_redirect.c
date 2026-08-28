/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Plain-HTTP half of the public front door (port 80).
 *
 * Two jobs, and deliberately no third: pass an ACME http-01 challenge token
 * through to the CA so certificate renewal works without a second daemon,
 * and 301 everything else to HTTPS. Nothing here is authenticated and
 * nothing here reads node state, which is why it is a separate translation
 * unit from https_server.c — that file owns TLS, the listeners and the
 * worker pool, and this one owns the cleartext port's whole request family.
 *
 * See docs/BLOCK_EXPLORER_HOSTING.md for the port mapping this sits behind. */

#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif
#include "net/https_frontdoor.h"
#include "net/https_server.h"
#include "https_server_internal.h"
#include "platform/socket_compat.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <strings.h>
#endif
#include "util/log_macros.h"
#include "util/path_check.h"

/* ── HTTP helpers ─────────────────────────────────────────── */

static bool plain_read_line(struct https_frontdoor_fd_reader *reader,
                            char *buf, size_t max)
{
    return https_frontdoor_read_line(reader, https_frontdoor_fd_read_byte,
                                     buf, max, reader->deadline_ms);
}

static int https_ascii_casecmp_n(const char *left, const char *right, size_t n)
{
#if defined(_WIN32)
    return _strnicmp(left, right, n);
#else
    return strncasecmp(left, right, n);
#endif
}

/* ── HTTP redirect handler (port 80) ─────────────────────── */

#define ACME_CHALLENGE_URL_PREFIX "/.well-known/acme-challenge/"
#define ACME_CHALLENGE_ROOT "/var/www/html/.well-known/acme-challenge"
#define ACME_CHALLENGE_URL_MAX 2047

static bool acme_challenge_filepath_under_root(const char *root,
                                               const char *path,
                                               char *out,
                                               size_t out_len)
{
#if defined(_WIN32)
    (void)root; (void)path; (void)out; (void)out_len;
    return false;
#else
    if (!root || !path || !out || out_len == 0)
        return false;
    if (!path_check_url_arg(path, ACME_CHALLENGE_URL_MAX))
        return false;

    const size_t prefix_len = sizeof(ACME_CHALLENGE_URL_PREFIX) - 1;
    if (strncmp(path, ACME_CHALLENGE_URL_PREFIX, prefix_len) != 0 ||
        path[prefix_len] == '\0')
        return false;

    char root_real[PATH_MAX];
    if (!realpath(root, root_real))
        return false;

    char filepath[PATH_MAX];
    int n = snprintf(filepath, sizeof(filepath), "%s/%s", root_real,
                     path + prefix_len);
    if (n < 0 || n >= (int)sizeof(filepath))
        return false;

    char file_real[PATH_MAX];
    if (!realpath(filepath, file_real))
        return false;

    size_t root_len = strlen(root_real);
    if (strncmp(file_real, root_real, root_len) != 0 ||
        (file_real[root_len] != '/' && file_real[root_len] != '\0'))
        return false;

    n = snprintf(out, out_len, "%s", file_real);
    return n >= 0 && n < (int)out_len;
#endif
}

static bool acme_challenge_filepath(const char *path, char *out, size_t out_len)
{
    return acme_challenge_filepath_under_root(ACME_CHALLENGE_ROOT, path,
                                              out, out_len);
}

#ifdef ZCL_TESTING
bool https_server_acme_challenge_filepath_for_testing(const char *root,
                                                      const char *path,
                                                      char *out,
                                                      size_t out_len)
{
    return acme_challenge_filepath_under_root(root, path, out, out_len);
}
#endif

void https_server_handle_http_client_fd(platform_socket_t fd,
                                        int64_t deadline_ms)
{
    /* Read the request line to get the path */
    struct https_frontdoor_fd_reader reader = {
        .fd = fd, .deadline_ms = deadline_ms,
    };
    char line[4096];
    if (!plain_read_line(&reader, line, sizeof(line))) {
        platform_socket_close(fd);
        return;
    }

    char method[16] = "", path[2048] = "";
    sscanf(line, "%15s %2047s", method, path);

    /* Drain headers, capturing the request Host for a generic redirect.
     * Cap the count to bound an endless-header (slowloris) connection. */
    char req_host[256] = "";
    int hdr_count = 0;
    bool headers_complete = false;
    while (plain_read_line(&reader, line, sizeof(line))) {
        if (line[0] == '\0') {
            headers_complete = true;
            break;
        }
        if (++hdr_count > HTTP_MAX_REQUEST_HEADERS) {
            platform_socket_close(fd); return;
        }
        if (req_host[0] == '\0' &&
            https_ascii_casecmp_n(line, "Host:", 5) == 0) {
            const char *v = line + 5;
            while (*v == ' ' || *v == '\t') v++;
            size_t host_len = strlen(v);
            if (host_len >= sizeof(req_host)) {
                platform_socket_close(fd);
                return;
            }
            memcpy(req_host, v, host_len + 1u);
        }
    }
    if (!headers_complete) {
        platform_socket_close(fd);
        return;
    }

    /* ACME challenge passthrough for cert renewal */
    char filepath[4096];
    if (acme_challenge_filepath(path, filepath, sizeof(filepath))) {
        FILE *f = fopen(filepath, "rb");
        if (f) {
            char body[4096];
            size_t n = fread(body, 1, sizeof(body), f);
            fclose(f);
            char hdr[512];
            int hlen = snprintf(hdr, sizeof(hdr),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n\r\n", n);
            /* Load-bearing, not cosmetic: this is the ACME HTTP-01 challenge
             * response. The CA compares the delivered body byte-for-byte with
             * the key authorization it issued, so a short write fails the
             * validation and with it the certificate renewal — silently, and
             * the consequence (an expired certificate) only shows up weeks
             * later. Logged with the token path so it is diagnosable when it
             * happens, which is rare enough not to be a log-volume lever. */
            bool sent = hlen > 0 && (size_t)hlen < sizeof(hdr) &&
                        platform_socket_send_all(fd, hdr, (size_t)hlen) &&
                        platform_socket_send_all(fd, body, n);
            if (!sent)
                LOG_WARN("https",
                         "ACME http-01 challenge response for %s was not "
                         "delivered in full (%s) — certificate renewal will "
                         "fail this attempt", filepath, strerror(errno));
            platform_socket_close(fd);
            return;
        }
    }

    /* Redirect everything to HTTPS. Prefer the operator-configured servername
     * (-httpsdomain); else echo the request's own Host header so the redirect
     * works on any domain without a hardcoded host. */
    const char *cfg_host = https_server_configured_hostname();
    const char *redir_host = cfg_host[0] ? cfg_host :
                             (req_host[0] ? req_host : NULL);
    char resp[4096];
    int n;
    if (redir_host)
        n = snprintf(resp, sizeof(resp),
            "HTTP/1.1 301 Moved Permanently\r\n"
            "Location: https://%s%s\r\n"
            "Connection: close\r\n\r\n",
            redir_host, path);
    else
        /* No host known: relative redirect keeps the browser's authority. */
        n = snprintf(resp, sizeof(resp),
            "HTTP/1.1 301 Moved Permanently\r\n"
            "Location: %s\r\n"
            "Connection: close\r\n\r\n",
            path);
    /* Best-effort and deliberately unlogged: this is the unauthenticated
     * port-80 redirect, a peer hanging up mid-response is routine, and one log
     * line per failed client write would hand an anonymous caller control of
     * our log volume. Nothing here is left inconsistent by a failure. The loop
     * is what matters — an unlooped write(2) can deliver a truncated Location
     * header, which a browser renders as a hard error instead of a redirect.
     * `n` is bounded (path <= 2047, host <= 255) but clamped regardless. */
    if (n > 0) {
        size_t resp_len = (size_t)n < sizeof(resp) ? (size_t)n : sizeof(resp) - 1;
        (void)platform_socket_send_all(fd, resp, resp_len);
    }
    platform_socket_close(fd);
}

#ifdef ZCL_TESTING
void https_server_handle_http_for_testing(platform_socket_t fd,
                                          int64_t deadline_ms)
{
    https_server_handle_http_client_fd(fd, deadline_ms);
}
#endif
