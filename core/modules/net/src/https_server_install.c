/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Public-install tree on the HTTPS front door. When the operator has placed
 * a stamped front-door shim under <datadir>/public-install, GET / serves
 * that shim instead of redirecting to the explorer. Bootstrap and release
 * bytes under the same root are streamed the same way. Absent files leave
 * the explorer redirect unchanged — a node that is not an install origin
 * does not become one by accident.
 *
 * Path jail matches the ACME http-01 helper: URL-arg check, realpath of
 * the root, realpath of the candidate, prefix test. A symlink that escapes
 * the root is refused. */
#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif
#include "net/https_server.h"
#include "https_server_internal.h"
#include "platform/socket_compat.h"
#include "util/log_macros.h"
#include "util/path_check.h"

#include <limits.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define PUBLIC_INSTALL_URL_MAX 2047
#define PUBLIC_INSTALL_FILE_MAX (64u * 1024u * 1024u)

static char g_public_install_root[PATH_MAX];

void https_server_set_public_install_root(const char *path)
{
    if (!path || !path[0]) {
        g_public_install_root[0] = '\0';
        return;
    }
    (void)snprintf(g_public_install_root, sizeof(g_public_install_root), "%s",
                   path);
}

static const char *public_install_relpath(const char *url)
{
    if (!url)
        return NULL;
    if (strcmp(url, "/") == 0 || strcmp(url, "/install.sh") == 0)
        return "install.sh";
    if (strcmp(url, "/install_z23.sh") == 0)
        return "install_z23.sh";
    if (strncmp(url, "/bootstrap/", 11) == 0 && url[11] != '\0')
        return url + 1;
    if (strncmp(url, "/release/", 9) == 0 && url[9] != '\0')
        return url + 1;
    return NULL;
}

static bool public_install_filepath_under_root(const char *root,
                                               const char *url,
                                               char *out, size_t out_len)
{
#if defined(_WIN32)
    (void)root;
    (void)url;
    (void)out;
    (void)out_len;
    return false;
#else
    const char *rel;
    char root_real[PATH_MAX];
    char filepath[PATH_MAX];
    char file_real[PATH_MAX];
    size_t root_len;
    int n;

    if (!root || !root[0] || !url || !out || out_len == 0)
        return false;
    if (!path_check_url_arg(url, PUBLIC_INSTALL_URL_MAX))
        return false;
    rel = public_install_relpath(url);
    if (!rel)
        return false;
    if (!realpath(root, root_real))
        return false;
    n = snprintf(filepath, sizeof(filepath), "%s/%s", root_real, rel);
    if (n < 0 || n >= (int)sizeof(filepath))
        return false;
    if (!realpath(filepath, file_real))
        return false;
    root_len = strlen(root_real);
    if (strncmp(file_real, root_real, root_len) != 0 ||
        (file_real[root_len] != '/' && file_real[root_len] != '\0'))
        return false;
    n = snprintf(out, out_len, "%s", file_real);
    return n >= 0 && n < (int)out_len;
#endif
}

#ifdef ZCL_TESTING
bool https_server_public_install_filepath_for_testing(const char *root,
                                                      const char *url,
                                                      char *out,
                                                      size_t out_len)
{
    return public_install_filepath_under_root(root, url, out, out_len);
}
#endif

static bool public_install_write_all(SSL *ssl, const void *buf, size_t n)
{
    const unsigned char *p = buf;
    size_t written = 0;

    while (written < n) {
        size_t chunk = n - written;
        int w;

        if (chunk > 16384)
            chunk = 16384;
        w = SSL_write(ssl, p + written, (int)chunk);
        if (w <= 0)
            return false;
        written += (size_t)w;
    }
    return true;
}

/* Operator-set front paths (-site-home= / -site-start=). Empty means the
 * default: "/" redirects browsers to /explorer and "/start" is not special.
 * Set once at boot before the listener serves, copied here. */
static char g_front_home[HTTPS_FRONT_PATH_MAX];
static char g_front_start[HTTPS_FRONT_PATH_MAX];

/* A redirect target must be a rooted local path: "/" first, not "//" (a
 * protocol-relative URL leaves the site), no backslash, and clean under
 * path_check_url_arg (no control bytes, no ".." segment). */
static bool https_front_path_ok(const char *name, const char *p)
{
    if (!path_check_url_arg(p, HTTPS_FRONT_PATH_MAX - 1) || p[1] == '/' ||
        strchr(p, '\\') != NULL) {
        LOG_WARN("https", "-site-%s path rejected; keeping the default", name);
        return false;
    }
    return true;
}

void https_server_set_front_paths(const char *home, const char *start)
{
    g_front_home[0] = '\0';
    g_front_start[0] = '\0';
    if (home && home[0] && https_front_path_ok("home", home))
        snprintf(g_front_home, sizeof(g_front_home), "%s", home);
    if (start && start[0] && https_front_path_ok("start", start))
        snprintf(g_front_start, sizeof(g_front_start), "%s", start);
}

/* Where a browser GET "/" is sent. */
const char *https_front_root_target(void)
{
    return g_front_home[0] ? g_front_home : "/explorer";
}

/* Where GET/HEAD "/start" is sent, or NULL when it is not special. */
const char *https_front_start_target(const char *path)
{
    return (g_front_start[0] && strcmp(path, "/start") == 0)
               ? g_front_start : NULL;
}

#ifdef ZCL_TESTING
const char *https_root_redirect_target_for_testing(void)
{
    return https_front_root_target();
}
const char *https_start_redirect_target_for_testing(const char *path)
{
    return https_front_start_target(path);
}
#endif

bool https_server_try_public_install(SSL *ssl, const char *url)
{
    char filepath[PATH_MAX];
    struct stat st;
    FILE *f;
    char hdr[256];
    int hlen;
    const char *ctype;
    char body[16384];
    size_t remain;
    const char *root = g_public_install_root;

    if (!ssl || !url || !root[0])
        return false;
    if (!public_install_filepath_under_root(root, url, filepath,
                                            sizeof(filepath)))
        return false;
    if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode))
        return false;
    if (st.st_size < 0 || (size_t)st.st_size > PUBLIC_INSTALL_FILE_MAX) {
        LOG_WARN("https",
                 "public-install file %s is too large to serve (%lld bytes)",
                 filepath, (long long)st.st_size);
        return false;
    }
    f = fopen(filepath, "rb");
    if (!f)
        return false;
    ctype = strstr(filepath, ".sh") ? "text/plain; charset=utf-8"
                                    : "application/octet-stream";
    hlen = snprintf(hdr, sizeof(hdr),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: %s\r\n"
                    "Content-Length: %lld\r\n"
                    "Connection: close\r\n"
                    "Cache-Control: no-store\r\n\r\n",
                    ctype, (long long)st.st_size);
    if (hlen <= 0 || (size_t)hlen >= sizeof(hdr) ||
        !public_install_write_all(ssl, hdr, (size_t)hlen)) {
        fclose(f);
        return true;
    }
    remain = (size_t)st.st_size;
    while (remain > 0) {
        size_t want = remain < sizeof(body) ? remain : sizeof(body);
        size_t n = fread(body, 1, want, f);

        if (n == 0)
            break;
        if (!public_install_write_all(ssl, body, n))
            break;
        remain -= n;
    }
    fclose(f);
    return true;
}
