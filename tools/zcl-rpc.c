/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcl-rpc: lightweight RPC client for zclassic23.
 * Reads cookie auth, sends JSON-RPC, prints result.
 * Usage: zcl-rpc <method> [param1] [param2] ... */

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Write every byte or report failure. A single write(2) may transfer fewer
 * bytes than requested; for the JSON-RPC body below a short write produces a
 * truncated request that the node rejects as malformed JSON, which surfaces
 * to the operator as an unexplained RPC error rather than an I/O error. */
#if !defined(_WIN32)
static bool write_all(int fd, const char *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        done += (size_t)n;
    }
    return true;
}
#endif

/* Read legacy zclassic.conf credentials without silently truncating them.
 * A truncated password is indistinguishable from a bad node to an operator,
 * and accepting an overlong fgets fragment could treat its continuation as a
 * separate directive. Return 1 for a complete pair, 0 when absent, -1 when
 * the file contains an invalid credential value. */
static int load_conf_auth(const char *path, char *cookie, size_t cookie_cap)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;

    char user[128] = "", pass[128] = "", line[256];
    bool invalid = false;
    while (fgets(line, sizeof(line), f)) {
        const char *value = NULL;
        char *dst = NULL;
        size_t cap = 0;
        if (strncmp(line, "rpcuser=", 8) == 0) {
            value = line + 8;
            dst = user;
            cap = sizeof(user);
        } else if (strncmp(line, "rpcpassword=", 12) == 0) {
            value = line + 12;
            dst = pass;
            cap = sizeof(pass);
        } else {
            continue;
        }

        size_t len = strcspn(value, "\r\n");
        if (len == 0 || len >= cap) {
            invalid = true;
            break;
        }
        memcpy(dst, value, len);
        dst[len] = '\0';
    }
    fclose(f);

    if (invalid) {
        fprintf(stderr,
                "zcl-rpc: invalid or overlong RPC credential in %s\n", path);
        return -1;
    }
    if (!user[0] || !pass[0])
        return 0;
    int n = snprintf(cookie, cookie_cap, "%s:%s", user, pass);
    if (n <= 0 || (size_t)n >= cookie_cap) {
        fprintf(stderr, "zcl-rpc: combined RPC credential is too long\n");
        return -1;
    }
    return 1;
}

#if defined(_WIN32)
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static bool b64_encode(const char *in, size_t in_len, char *out, size_t cap)
{
    size_t used = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        unsigned a = (unsigned char)in[i];
        unsigned b = (i + 1 < in_len) ? (unsigned char)in[i + 1] : 0;
        unsigned c = (i + 2 < in_len) ? (unsigned char)in[i + 2] : 0;
        unsigned triple = (a << 16) | (b << 8) | c;
        if (used + 4 >= cap) return false;
        out[used++] = b64_table[(triple >> 18) & 63];
        out[used++] = b64_table[(triple >> 12) & 63];
        out[used++] = (i + 1 < in_len) ? b64_table[(triple >> 6) & 63] : '=';
        out[used++] = (i + 2 < in_len) ? b64_table[triple & 63] : '=';
    }
    if (used >= cap) return false;
    out[used] = '\0';
    return true;
}

static bool send_all(SOCKET sock, const char *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        int n = send(sock, buf + done, (int)(len - done), 0);
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

static const char *http_body(const char *response)
{
    const char *body = strstr(response, "\r\n\r\n");
    return body ? body + 4 : response;
}
#endif

#if !defined(_WIN32)
/* Quote one argument for the POSIX shell used by popen(). Credentials are
 * local configuration, but they are still data: $, backticks, quotes, and
 * whitespace must never become shell syntax. */
static bool shell_quote(const char *in, char *out, size_t cap)
{
    if (!in || !out || cap < 3)
        return false;
    size_t used = 0;
    out[used++] = '\'';
    for (const char *p = in; *p; p++) {
        if (*p == '\'') {
            static const char escaped[] = "'\\''";
            if (used + sizeof(escaped) - 1 >= cap)
                return false;
            memcpy(out + used, escaped, sizeof(escaped) - 1);
            used += sizeof(escaped) - 1;
        } else {
            if (used + 1 >= cap)
                return false;
            out[used++] = *p;
        }
    }
    if (used + 2 > cap)
        return false;
    out[used++] = '\'';
    out[used] = '\0';
    return true;
}
#endif

#if defined(_WIN32)
static int rpc_call_windows(const char *host, int port, const char *cookie,
                            const char *body, int body_n, char *out,
                            size_t out_len)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "zcl-rpc: WSAStartup failed\n");
        return -1;
    }
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }
    DWORD timeout_ms = 30000;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms,
                     sizeof(timeout_ms));
    (void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms,
                     sizeof(timeout_ms));
    if (connect(sock, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }
    char auth_b64[512];
    if (!b64_encode(cookie, strlen(cookie), auth_b64, sizeof(auth_b64))) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }
    char req[16384];
    int rlen = snprintf(req, sizeof(req),
        "POST / HTTP/1.1\r\nHost: %s:%d\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
        host, port, auth_b64, body_n, body);
    if (rlen <= 0 || (size_t)rlen >= sizeof(req) ||
        !send_all(sock, req, (size_t)rlen)) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }
    size_t total = 0;
    while (total + 1 < out_len) {
        int n = recv(sock, out + total, (int)(out_len - 1 - total), 0);
        if (n <= 0) break;
        total += (size_t)n;
    }
    out[total] = '\0';
    closesocket(sock);
    WSACleanup();
    const char *payload = http_body(out);
    if (payload != out) {
        size_t payload_len = strlen(payload);
        memmove(out, payload, payload_len + 1);
        total = payload_len;
    }
    return total > 0 ? (int)total : -1;
}
#else
static int rpc_call_posix(const char *host, int port, const char *cookie,
                          const char *body, char *out, size_t out_len)
{
    /* Write body to temp file to avoid shell quoting issues */
    char tmpf[] = "/tmp/zcl-rpc-XXXXXX";
    int tfd = mkstemp(tmpf);
    if (tfd < 0) return -1;
    if (!write_all(tfd, body, strlen(body))) {
        fprintf(stderr, "zcl-rpc: writing request body to %s failed: %s\n",
                tmpf, strerror(errno));
        close(tfd);
        unlink(tmpf);
        return -1;
    }
    /* close(2) can report a deferred write error; the body must be complete
     * on disk before curl reads it back. */
    if (close(tfd) != 0) {
        fprintf(stderr, "zcl-rpc: closing request body %s failed: %s\n",
                tmpf, strerror(errno));
        unlink(tmpf);
        return -1;
    }

    char quoted_cookie[1024];
    if (!shell_quote(cookie, quoted_cookie, sizeof(quoted_cookie))) {
        fprintf(stderr, "zcl-rpc: RPC credential is too long to quote\n");
        unlink(tmpf);
        return -1;
    }
    char cmd[16384];
    int cmd_n = snprintf(cmd, sizeof(cmd),
        "curl -s --max-time 30 --user %s "
        "-d @%s -H 'content-type:text/plain;' "
        "http://%s:%d/ 2>/dev/null",
        quoted_cookie, tmpf, host, port);
    if (cmd_n <= 0 || (size_t)cmd_n >= sizeof(cmd)) {
        fprintf(stderr, "zcl-rpc: curl command is too long\n");
        unlink(tmpf);
        return -1;
    }

    FILE *p = popen(cmd, "r");
    if (!p) {
        unlink(tmpf);
        return -1;
    }

    size_t total = fread(out, 1, out_len - 1, p);
    bool read_ok = !ferror(p);
    out[total] = '\0';
    int status = pclose(p);
    unlink(tmpf);
    if (!read_ok || status < 0 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return -1;
    return (int)total;
}
#endif

static int rpc_call(const char *host, int port, const char *cookie,
                    const char *method, const char *params_json,
                    char *out, size_t out_len)
{
    char body[8192];
    int body_n = snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"1.0\",\"method\":\"%s\",\"params\":[%s],\"id\":1}",
        method, params_json ? params_json : "");
    if (body_n <= 0 || (size_t)body_n >= sizeof(body)) {
        fprintf(stderr, "zcl-rpc: request body is too long\n");
        return -1;
    }
#if defined(_WIN32)
    return rpc_call_windows(host, port, cookie, body, body_n, out, out_len);
#else
    return rpc_call_posix(host, port, cookie, body, out, out_len);
#endif
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: zcl-rpc <method> [params...]\n");
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  zcl-rpc getblockcount\n");
        fprintf(stderr, "  zcl-rpc getbalance\n");
        fprintf(stderr, "  zcl-rpc sendtoaddress '\"t1addr...\", 0.1'\n");
        return 1;
    }

    /* Read cookie */
    const char *home = getenv("HOME");
    char cookie_path[512];
    const char *datadir = getenv("ZCL_DATADIR");
    if (datadir)
        snprintf(cookie_path, sizeof(cookie_path), "%s/.cookie", datadir);
    else if (home)
        snprintf(cookie_path, sizeof(cookie_path), "%s/.zclassic-c23/.cookie", home);
    else
        snprintf(cookie_path, sizeof(cookie_path), ".zclassic-c23/.cookie");

    char cookie[256] = "";

    /* Try cookie auth first (C23 node uses cookies) */
    {
        FILE *cf = fopen(cookie_path, "r");
        if (cf) {
            if (fgets(cookie, sizeof(cookie), cf)) {
                char *nl = strchr(cookie, '\n');
                if (nl) *nl = '\0';
            }
            fclose(cf);
        }
    }

    /* Fall back to rpcuser:rpcpassword from conf (zclassicd) */
    if (cookie[0] == '\0')
    {
        char conf_path[512];
        if (datadir)
            snprintf(conf_path, sizeof(conf_path), "%s/zclassic.conf", datadir);
        else if (home)
            snprintf(conf_path, sizeof(conf_path), "%s/.zclassic-c23/zclassic.conf", home);
        else
            snprintf(conf_path, sizeof(conf_path), "zclassic.conf");

        if (load_conf_auth(conf_path, cookie, sizeof(cookie)) < 0)
            return 1;
    }

    if (cookie[0] == '\0') {
        fprintf(stderr, "No auth found (no cookie, no rpcuser/rpcpassword)\n");
        return 1;
    }

    /* Build params JSON from remaining args */
    char params[4096] = "";
    if (argc > 2) {
        /* If single arg with commas, pass as-is */
        if (argc == 3) {
            snprintf(params, sizeof(params), "%s", argv[2]);
        } else {
            /* Multiple args — join with commas */
            size_t off = 0;
            for (int i = 2; i < argc && off < sizeof(params) - 2; i++) {
                if (i > 2) params[off++] = ',';
                off += (size_t)snprintf(params + off, sizeof(params) - off, "%s", argv[i]);
            }
        }
    }

    /* Override the default RPC port via env. Matches the documentation
     * in README.md (Environment variables section). atoi() returns 0
     * for unparseable values; we keep the literal default in that
     * case rather than connecting to port 0. */
    int port = 18232;
    const char *port_env = getenv("ZCL_RPCPORT");
    if (port_env) {
        int parsed = atoi(port_env);
        if (parsed > 0 && parsed <= 65535) port = parsed;
    }

    char response[1024 * 1024];
    int n = rpc_call("127.0.0.1", port, cookie, argv[1], params,
                     response, sizeof(response));
    if (n < 0) {
        fprintf(stderr, "Connection failed (port %d)\n", port);
        return 1;
    }

    /* If we got "Unauthorized", retry with conf auth */
    if (n == 0 || strstr(response, "Unauthorized")) {
        char conf_path2[512];
        if (datadir)
            snprintf(conf_path2, sizeof(conf_path2), "%s/zclassic.conf", datadir);
        else if (home)
            snprintf(conf_path2, sizeof(conf_path2), "%s/.zclassic-c23/zclassic.conf", home);
        else
            snprintf(conf_path2, sizeof(conf_path2), "zclassic.conf");
        char fallback[256] = "";
        int auth = load_conf_auth(conf_path2, fallback, sizeof(fallback));
        if (auth < 0)
            return 1;
        if (auth > 0)
            n = rpc_call("127.0.0.1", port, fallback, argv[1], params,
                         response, sizeof(response));
    }

    if (n > 0)
        printf("%s\n", response);
    return n > 0 ? 0 : 1;
}
