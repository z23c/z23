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
#include <limits.h>
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

/* Read a small credential file whole into buf (NUL-terminated, at most
 * cap - 1 bytes). Returns 1 when read, 0 only when the file does not exist
 * (ENOENT: the caller may fall back to the next credential source), and -1,
 * named on stderr, when it exists but cannot be opened (permissions, a
 * directory, ...) or read, or is larger than the buffer. An interrupted open
 * or read (EINTR) is retried. */
static int read_credential_file(const char *path, char *buf, size_t cap)
{
    FILE *f;
    do {
        errno = 0;
        f = fopen(path, "rb");
    } while (!f && errno == EINTR);
    if (!f) {
        if (errno == ENOENT)
            return 0;
        int open_err = errno ? errno : EIO;
        fprintf(stderr, "zcl-rpc: opening %s failed: %s\n", path,
                strerror(open_err));
        return -1;
    }
    size_t n = 0;
    int read_err = 0;
    while (n < cap) {
        errno = 0;
        size_t got = fread(buf + n, 1, cap - n, f);
        n += got;
        if (got > 0 || feof(f))
            continue;
        if (errno == EINTR) {
            clearerr(f);
            continue;
        }
        read_err = errno ? errno : EIO;
        break;
    }
    bool more = n >= cap;
    fclose(f);
    if (read_err) {
        fprintf(stderr, "zcl-rpc: reading %s failed: %s\n", path,
                strerror(read_err));
        return -1;
    }
    if (more) {
        fprintf(stderr, "zcl-rpc: %s is larger than %zu bytes - refusing "
                "(no silent truncation of a credential)\n", path, cap - 1);
        return -1;
    }
    buf[n] = '\0';
    return 1;
}

/* Read legacy zclassic.conf credentials without silently truncating them.
 * A truncated password is indistinguishable from a bad node to an operator.
 * The file is read whole, so a long line is one line, never fragments whose
 * continuation could pose as a separate directive. Return 1 for a complete
 * pair, 0 when absent, -1 when the file cannot be read or contains an
 * invalid credential value. */
static int load_conf_auth(const char *path, char *cookie, size_t cookie_cap)
{
    static char text[65536];
    int got = read_credential_file(path, text, sizeof(text));
    if (got <= 0)
        return got;

    char user[128] = "", pass[128] = "";
    bool invalid = false;
    for (char *line = text, *next; line; line = next) {
        next = strchr(line, '\n');
        if (next)
            *next++ = '\0';
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

/* Space, tab, CR and LF: the bytes skipped around a JSON value here. */
static bool json_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* zcl-rpc links no JSON parser, so a body counts as JSON-shaped when, after
 * leading and trailing space, tab, CR and LF are skipped, it begins with '{'
 * and ends with '}', or begins with '[' and ends with ']'. Nothing else is
 * checked: nested syntax, strings and numbers are not validated, so a complete
 * but malformed object passes and a truncated one does not. An empty body is
 * not JSON. */
static bool body_is_json(const char *s, size_t len)
{
    size_t first = 0;
    while (first < len && json_space(s[first]))
        first++;
    size_t last = len;
    while (last > first && json_space(s[last - 1]))
        last--;
    if (first == last)
        return false;
    char open = s[first];
    char close = s[last - 1];
    return (open == '{' && close == '}') || (open == '[' && close == ']');
}

/* Decide whether one complete reply may be printed as the node's answer.
 * status is the HTTP status, or -1 when none was seen; body is len bytes.
 * Only a 200 with a JSON-shaped, non-empty body passes. Every other case
 * writes its reason to why and returns false: a missing status, a non-200
 * (named by whether its body is JSON), an empty body, or a 200 body that is
 * truncated or not JSON. The caller still returns the length, so the
 * Unauthorized retry can run; why decides the exit status. */
static bool reply_is_usable(long status, const char *body, size_t len,
                            char *why, size_t cap)
{
    if (status < 0) {
        snprintf(why, cap, "node reply carried no HTTP status");
        return false;
    }
    bool json = body_is_json(body, len);
    if (status != 200) {
        if (json)
            snprintf(why, cap, "node replied HTTP %ld with a JSON error body",
                     status);
        else
            snprintf(why, cap, "node replied HTTP %ld without a JSON body",
                     status);
        return false;
    }
    if (len == 0) {
        snprintf(why, cap, "node replied with an empty body");
        return false;
    }
    if (!json) {
        snprintf(why, cap,
                 "node replied HTTP 200 with a truncated or non-JSON body");
        return false;
    }
    return true;
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
/* Name a Winsock failure with the POSIX words for the same case: a timeout and
 * a reset get their own reason, anything else gets the caller's fallback. */
static void name_winsock_failure(int err, const char *fallback, char *why,
                                 size_t cap)
{
    if (err == WSAETIMEDOUT)
        snprintf(why, cap,
                 "timed out waiting for the node's reply after 30 s");
    else if (err == WSAECONNRESET)
        snprintf(why, cap, "node closed or reset the connection mid-reply");
    else
        snprintf(why, cap, "%s", fallback);
}

/* One recv that retries WSAEINTR. Returns the byte count, 0 at a clean close,
 * or -1 with *err set to the Winsock error. */
static int recv_once(SOCKET sock, char *buf, size_t cap, int *err)
{
    for (;;) {
        int n = recv(sock, buf, (int)cap, 0);
        if (n >= 0)
            return n;
        int e = WSAGetLastError();
        if (e != WSAEINTR) {
            *err = e;
            return -1;
        }
    }
}

/* Read the reply into out until the peer closes or cap bytes are in. Returns
 * the byte count and leaves out NUL-terminated; *err is set on a recv error. */
static size_t windows_read_reply(SOCKET sock, char *out, size_t cap, int *err)
{
    size_t total = 0;
    while (total < cap) {
        int n = recv_once(sock, out + total, cap - total, err);
        if (n <= 0)
            break;
        total += (size_t)n;
    }
    out[total] = '\0';
    return total;
}

/* A full buffer is an oversize reply only when one more byte arrives. */
static bool windows_has_more(SOCKET sock, int *err)
{
    char probe;
    return recv_once(sock, &probe, 1, err) > 0;
}

/* Turn the raw HTTP reply in out into the body, in place, and classify it
 * with the same rules as the POSIX path. Returns the body length; why names
 * any failure. A reply with no header block is refused with -1. */
static long finish_windows_reply(char *out, char *why, size_t cap)
{
    const char *sep = strstr(out, "\r\n\r\n");
    if (!sep) {
        snprintf(why, cap, "node reply has no HTTP header block");
        return -1;
    }
    long status = -1;
    if (sscanf(out, "HTTP/%*d.%*d %ld", &status) != 1)
        status = -1;
    const char *payload = sep + 4;
    size_t len = strlen(payload);
    memmove(out, payload, len + 1);
    (void)reply_is_usable(status, out, len, why, cap);
    return (long)len;
}

/* Read and classify the reply on an open socket. Returns the body length, or
 * -1 with why set for a recv error, an oversize reply or an empty reply. */
static int windows_read_and_finish(SOCKET sock, char *out, size_t out_len,
                                   char *why, size_t why_cap)
{
    int err = 0;
    size_t total = windows_read_reply(sock, out, out_len - 1, &err);
    bool overflow = err == 0 && total == out_len - 1 &&
                    windows_has_more(sock, &err);
    if (err != 0) {
        name_winsock_failure(err, "node closed the connection before replying",
                             why, why_cap);
        return -1;
    }
    if (overflow) {
        snprintf(why, why_cap, "node reply exceeds the %zu-byte reply buffer",
                 out_len);
        return -1;
    }
    if (total == 0) {
        snprintf(why, why_cap, "node closed the connection before replying");
        return -1;
    }
    return (int)finish_windows_reply(out, why, why_cap);
}

/* Open a connected socket to host:port with the 30 s budget. On failure why
 * names the case and INVALID_SOCKET is returned. */
static SOCKET windows_connect(const char *host, int port, char *why,
                              size_t why_cap)
{
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        snprintf(why, why_cap, "could not create a socket for the node");
        return INVALID_SOCKET;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        closesocket(sock);
        snprintf(why, why_cap, "could not connect to the node");
        return INVALID_SOCKET;
    }
    DWORD timeout_ms = 30000;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms,
                     sizeof(timeout_ms));
    (void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms,
                     sizeof(timeout_ms));
    if (connect(sock, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int err = WSAGetLastError();
        closesocket(sock);
        name_winsock_failure(err, "could not connect to the node", why,
                             why_cap);
        return INVALID_SOCKET;
    }
    return sock;
}

/* Send the POST for body on sock. Returns false with why set when the
 * credential cannot be encoded, the request is too long, or the send fails. */
static bool windows_send_request(SOCKET sock, const char *host, int port,
                                 const char *cookie, const char *body,
                                 int body_n, char *why, size_t why_cap)
{
    char auth_b64[512];
    if (!b64_encode(cookie, strlen(cookie), auth_b64, sizeof(auth_b64))) {
        snprintf(why, why_cap, "RPC credential is too long to encode");
        return false;
    }
    char req[16384];
    int rlen = snprintf(req, sizeof(req),
        "POST / HTTP/1.1\r\nHost: %s:%d\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
        host, port, auth_b64, body_n, body);
    if (rlen <= 0 || (size_t)rlen >= sizeof(req)) {
        snprintf(why, why_cap, "request body is too long");
        return false;
    }
    if (!send_all(sock, req, (size_t)rlen)) {
        name_winsock_failure(WSAGetLastError(),
                             "could not send the request to the node", why,
                             why_cap);
        return false;
    }
    return true;
}

static int rpc_call_windows(const char *host, int port, const char *cookie,
                            const char *body, int body_n, char *out,
                            size_t out_len, char *why, size_t why_cap)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        snprintf(why, why_cap, "could not start Winsock");
        return -1;
    }
    int n = -1;
    SOCKET sock = windows_connect(host, port, why, why_cap);
    if (sock != INVALID_SOCKET) {
        if (windows_send_request(sock, host, port, cookie, body, body_n, why,
                                 why_cap))
            n = windows_read_and_finish(sock, out, out_len, why, why_cap);
        closesocket(sock);
    }
    WSACleanup();
    return n;
}
#else
/* Bound curl's own budget for the single RPC call below. Defaults to 30s;
 * a caller that needs longer for a heavy call (e.g. `generate N` mining
 * real blocks under load) opts in explicitly via ZCL_RPC_MAX_TIME_SECS
 * rather than every caller silently waiting longer against a wedged node.
 * A malformed override (non-numeric or <= 0) is refused with a named
 * error instead of a silent fallback. */
static int rpc_max_time_secs(void)
{
    const char *raw = getenv("ZCL_RPC_MAX_TIME_SECS");
    if (!raw || raw[0] == '\0') return 30;
    char *end = NULL;
    long v = strtol(raw, &end, 10);
    if (end == raw || *end != '\0' || v <= 0 || v > INT_MAX) {
        fprintf(stderr,
                "zcl-rpc: ZCL_RPC_MAX_TIME_SECS must be a positive integer "
                "number of seconds, got '%s'\n", raw);
        return -1;
    }
    return (int)v;
}

/* curl appends this marker after the body (-w), so the HTTP status is known
 * even when the body is empty or not JSON. split_http_status strips it before
 * the body reaches the caller: a successful reply is byte-identical. */
#define ZCL_RPC_STATUS_MARK "\nZCLRPC_HTTP_STATUS:"

/* Name the transport failure in why. curl's exit code is the only signal
 * left once the node has closed the socket, so each case gets its own words
 * and an operator can tell a refusal, a timeout and a silent close apart. */
static void describe_curl_failure(int code, int max_secs, char *why,
                                  size_t cap)
{
    switch (code) {
    case 7:
        snprintf(why, cap, "could not connect to the node");
        break;
    case 28:
        snprintf(why, cap, "timed out waiting for the node's reply after %d s",
                 max_secs);
        break;
    case 52:
        snprintf(why, cap, "node closed the connection before replying");
        break;
    case 18:
    case 56:
        snprintf(why, cap,
                 "node closed or reset the connection mid-reply (curl exit %d)",
                 code);
        break;
    default:
        snprintf(why, cap, "curl failed talking to the node (curl exit %d)",
                 code);
        break;
    }
}

/* A failed read of the curl pipe is its own reason, never the end of data. */
static long read_failed(int err, char *why, size_t cap)
{
    snprintf(why, cap, "read failed: %s", strerror(err ? err : EIO));
    return -1;
}

/* Read up to cap bytes from the curl pipe into buf, stopping early at end of
 * file. EINTR is retried after clearing the stream error; any other read
 * error returns its errno value. */
static int read_pipe_upto(FILE *p, char *buf, size_t cap, size_t *got)
{
    *got = 0;
    while (*got < cap) {
        errno = 0;
        *got += fread(buf + *got, 1, cap - *got, p);
        if (!ferror(p))
            break;
        int err = errno ? errno : EIO;
        clearerr(p);
        if (err != EINTR)
            return err;
    }
    return 0;
}

/* Discard the rest of the curl pipe so curl can finish. Returns total, or -1
 * with why set when a read fails. */
static long drain_curl_reply(FILE *p, long total, char *why, size_t why_cap)
{
    char scratch[4096];
    for (;;) {
        size_t got = 0;
        int err = read_pipe_upto(p, scratch, sizeof(scratch), &got);
        if (err)
            return read_failed(err, why, why_cap);
        if (got == 0)
            return total;
    }
}

/* Read at most out_len-1 reply bytes. A longer reply sets *truncated and is
 * drained so curl can finish. Returns the byte count, or -1 with why set to
 * "read failed: ..." when the pipe reports an error. */
static long read_curl_reply(FILE *p, char *out, size_t out_len,
                            bool *truncated, char *why, size_t why_cap)
{
    size_t total = 0;
    int err = read_pipe_upto(p, out, out_len - 1, &total);
    out[total] = '\0';
    if (err)
        return read_failed(err, why, why_cap);
    if (total < out_len - 1)
        return (long)total;
    char probe;
    size_t extra = 0;
    err = read_pipe_upto(p, &probe, 1, &extra);
    if (err)
        return read_failed(err, why, why_cap);
    if (extra == 0)
        return (long)total;
    *truncated = true;
    return drain_curl_reply(p, (long)total, why, why_cap);
}

/* Remove the trailing status marker and return the HTTP status it carries,
 * or -1 when no marker is present. *total shrinks to the body length. */
static long split_http_status(char *out, size_t *total)
{
    const size_t mark_len = sizeof(ZCL_RPC_STATUS_MARK) - 1;
    char *mark = NULL;
    for (char *p = out; (p = strstr(p, ZCL_RPC_STATUS_MARK)) != NULL; p++)
        mark = p;
    if (!mark) return -1;
    char *end = NULL;
    long status = strtol(mark + mark_len, &end, 10);
    if (end == mark + mark_len || *end != '\0') return -1;
    *mark = '\0';
    *total = (size_t)(mark - out);
    return status;
}

/* Decide the outcome of one curl run. A transport failure returns -1 with
 * why set. Any reply that reply_is_usable refuses returns its length with
 * why set, so the caller can still run its Unauthorized retry and reports the
 * reason only if nothing better arrives. */
static long finish_curl_reply(int code, char *out, long total, bool truncated,
                              size_t out_len, int max_secs, char *why,
                              size_t cap)
{
    /* A read error is ours and is named first; curl's exit code after we
     * stopped reading is only a consequence of it. */
    if (total < 0)
        return -1;
    if (code != 0) {
        describe_curl_failure(code, max_secs, why, cap);
        return -1;
    }
    if (truncated) {
        snprintf(why, cap, "node reply exceeds the %zu-byte reply buffer",
                 out_len);
        return -1;
    }
    size_t len = (size_t)total;
    long status = split_http_status(out, &len);
    (void)reply_is_usable(status, out, len, why, cap);
    return (long)len;
}

static int rpc_call_posix(const char *host, int port, const char *cookie,
                          const char *body, char *out, size_t out_len,
                          char *why, size_t why_cap)
{
    int max_time_secs = rpc_max_time_secs();
    if (max_time_secs < 0) {
        snprintf(why, why_cap, "ZCL_RPC_MAX_TIME_SECS is not a positive integer");
        return -1;
    }

    /* Write body to temp file to avoid shell quoting issues */
    char tmpf[] = "/tmp/zcl-rpc-XXXXXX";
    int tfd = mkstemp(tmpf);
    if (tfd < 0) {
        snprintf(why, why_cap, "could not create the request body file");
        return -1;
    }
    if (!write_all(tfd, body, strlen(body))) {
        fprintf(stderr, "zcl-rpc: writing request body to %s failed: %s\n",
                tmpf, strerror(errno));
        close(tfd);
        unlink(tmpf);
        snprintf(why, why_cap, "could not write the request body");
        return -1;
    }
    /* close(2) can report a deferred write error; the body must be complete
     * on disk before curl reads it back. */
    if (close(tfd) != 0) {
        fprintf(stderr, "zcl-rpc: closing request body %s failed: %s\n",
                tmpf, strerror(errno));
        unlink(tmpf);
        snprintf(why, why_cap, "could not close the request body file");
        return -1;
    }

    char quoted_cookie[1024];
    if (!shell_quote(cookie, quoted_cookie, sizeof(quoted_cookie))) {
        fprintf(stderr, "zcl-rpc: RPC credential is too long to quote\n");
        unlink(tmpf);
        snprintf(why, why_cap, "RPC credential is too long to quote");
        return -1;
    }
    char cmd[16384];
    int cmd_n = snprintf(cmd, sizeof(cmd),
        "curl -s --max-time %d --user %s "
        "-d @%s -H 'content-type:text/plain;' "
        "-w '\\nZCLRPC_HTTP_STATUS:%%{http_code}' "
        "http://%s:%d/ 2>/dev/null",
        max_time_secs, quoted_cookie, tmpf, host, port);
    if (cmd_n <= 0 || (size_t)cmd_n >= sizeof(cmd)) {
        fprintf(stderr, "zcl-rpc: curl command is too long\n");
        unlink(tmpf);
        snprintf(why, why_cap, "curl command is too long");
        return -1;
    }

    FILE *p = popen(cmd, "r");
    if (!p) {
        unlink(tmpf);
        snprintf(why, why_cap, "could not start curl");
        return -1;
    }

    bool truncated = false;
    long total = read_curl_reply(p, out, out_len, &truncated, why, why_cap);
    int status = pclose(p);
    unlink(tmpf);
    int code = (status >= 0 && WIFEXITED(status)) ? WEXITSTATUS(status) : -1;
    return (int)finish_curl_reply(code, out, total, truncated, out_len,
                                  max_time_secs, why, why_cap);
}
#endif

static int rpc_call(const char *host, int port, const char *cookie,
                    const char *method, const char *params_json,
                    char *out, size_t out_len, char *why, size_t why_cap)
{
    why[0] = '\0';
    char body[8192];
    int body_n = snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"1.0\",\"method\":\"%s\",\"params\":[%s],\"id\":1}",
        method, params_json ? params_json : "");
    if (body_n <= 0 || (size_t)body_n >= sizeof(body)) {
        snprintf(why, why_cap, "request body is too long");
        return -1;
    }
#if defined(_WIN32)
    int n = rpc_call_windows(host, port, cookie, body, body_n, out, out_len,
                             why, why_cap);
    if (n < 0 && why[0] == '\0')
        snprintf(why, why_cap, "could not reach the node");
    return n;
#else
    return rpc_call_posix(host, port, cookie, body, out, out_len, why,
                          why_cap);
#endif
}

/* Compose <datadir>/<leaf>, <home>/.zclassic-c23/<leaf>, or the bare
 * no-HOME fallback into out. False (after printing error=DATADIR_TOO_LONG)
 * when the result does not fit: never a truncated path. zcl-rpc is a
 * standalone tool with no config/args.h, so the cap is sizeof the buffer. */
static bool compose_path(char *out, size_t cap, const char *datadir,
                         const char *home, const char *leaf,
                         const char *fallback)
{
    int n;
    if (datadir)
        n = snprintf(out, cap, "%s/%s", datadir, leaf);
    else if (home)
        n = snprintf(out, cap, "%s/.zclassic-c23/%s", home, leaf);
    else
        n = snprintf(out, cap, "%s", fallback);
    if (n < 0 || (size_t)n >= cap) {
        fprintf(stderr, "error=DATADIR_TOO_LONG detail=the %s path exceeds "
                "the %zu-byte path buffer - refusing (no silent "
                "truncation): a chopped cookie path can authenticate "
                "against the wrong node\n", leaf, cap);
        return false;
    }
    return true;
}

/* Read the node cookie (its first line) from path into cookie. A missing
 * file (ENOENT only) leaves cookie untouched so the caller can fall back to
 * conf credentials. A file that exists but cannot be opened or read, or
 * whose first line does not fit, is named and returns -1. */
static int read_cookie_file(const char *path, char *cookie, size_t cap)
{
    char text[1024];
    int got = read_credential_file(path, text, sizeof(text));
    if (got <= 0)
        return got;
    size_t len = strcspn(text, "\n");
    if (len >= cap) {
        fprintf(stderr, "zcl-rpc: the cookie in %s is longer than %zu bytes "
                "- refusing (no silent truncation)\n", path, cap - 1);
        return -1;
    }
    memcpy(cookie, text, len);
    cookie[len] = '\0';
    return 0;
}

/* Acquire the RPC credential: the cookie file first, then
 * rpcuser:rpcpassword from the conf. Returns 0 with cookie filled,
 * 1 when no credential exists anywhere (cookie left empty), or -1 when a
 * credential file cannot be read or the conf credential is invalid; each
 * case has already been reported to stderr. */
static int load_any_auth(const char *cookie_path, const char *conf_path,
                         char *cookie, size_t cookie_cap)
{
    /* Try cookie auth first (C23 node uses cookies) */
    if (read_cookie_file(cookie_path, cookie, cookie_cap) < 0)
        return -1;

    /* Fall back to rpcuser:rpcpassword from conf (zclassicd) */
    if (cookie[0] == '\0') {
        int conf = load_conf_auth(conf_path, cookie, cookie_cap);
        if (conf < 0)
            return -1;
        if (conf == 0)
            return 1;
    }
    return 0;
}

/* Build params JSON from remaining args */
static void build_params_json(char *params, size_t cap, int argc,
                              char *argv[])
{
    if (argc > 2) {
        /* If single arg with commas, pass as-is */
        if (argc == 3) {
            snprintf(params, cap, "%s", argv[2]);
        } else {
            /* Multiple args — join with commas */
            size_t off = 0;
            for (int i = 2; i < argc && off < cap - 2; i++) {
                if (i > 2) params[off++] = ',';
                off += (size_t)snprintf(params + off, cap - off, "%s", argv[i]);
            }
        }
    }
}

/* Map the ZCL_RPCPORT value to a usable port, keeping the default of 18232
 * for a missing, unparseable, or out-of-range value rather than connecting
 * to port 0. */
static int rpc_port_from_env(const char *port_env)
{
    int port = 18232;
    if (port_env) {
        int parsed = atoi(port_env);
        if (parsed > 0 && parsed <= 65535) port = parsed;
    }
    return port;
}

/* Compose the cookie and conf paths as a pair; compose_path reports an
 * overlong path itself, and the second compose is skipped when the first
 * already failed, exactly as the previous early return did. */
static bool compose_auth_paths(char *cookie_path, size_t cookie_cap,
                               char *conf_path, size_t conf_cap,
                               const char *datadir, const char *home)
{
    return compose_path(cookie_path, cookie_cap, datadir, home,
                        ".cookie", ".zclassic-c23/.cookie") &&
           compose_path(conf_path, conf_cap, datadir, home,
                        "zclassic.conf", "zclassic.conf");
}

/* Retry the call with rpcuser:rpcpassword credentials from zclassic.conf:
 * compose <datadir>/zclassic.conf, <home>/.zclassic-c23/zclassic.conf, or
 * the bare fallback, read the credential, and on success store the fresh
 * rpc_call result in *n_out. Returns load_conf_auth's status, so a
 * negative value means the caller must stop. */
static int conf_retry_auth(int *n_out, const char *datadir, const char *home,
                           int port, const char *method, const char *params,
                           char *response, size_t response_cap, char *why,
                           size_t why_cap)
{
    char conf_path2[512];
    if (datadir)
        snprintf(conf_path2, sizeof(conf_path2), "%s/zclassic.conf", datadir);
    else if (home)
        snprintf(conf_path2, sizeof(conf_path2), "%s/.zclassic-c23/zclassic.conf", home);
    else
        snprintf(conf_path2, sizeof(conf_path2), "zclassic.conf");
    char fallback[256] = "";
    int auth = load_conf_auth(conf_path2, fallback, sizeof(fallback));
    if (auth > 0)
        *n_out = rpc_call("127.0.0.1", port, fallback, method, params,
                          response, response_cap, why, why_cap);
    return auth;
}

/* Print the one-line failure for a reply that never produced a usable
 * body. The line names the case, the endpoint and the method. */
static int report_rpc_failure(const char *why, int port, const char *method)
{
    fprintf(stderr, "zcl-rpc: %s (127.0.0.1:%d method=%s)\n",
            why[0] != '\0' ? why : "no reply from the node", port, method);
    return 1;
}

/* Print a usable reply, or report why there is none. */
static int finish_rpc_reply(int n, const char *response, const char *why,
                            int port, const char *method)
{
    if (n <= 0 || why[0] != '\0')
        return report_rpc_failure(why, port, method);
    printf("%s\n", response);
    return 0;
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
    char conf_path[512];
    const char *datadir = getenv("ZCL_DATADIR");
    /* Compose both paths before any file is opened: a truncated prefix
     * can name another node's directory and so another node's cookie. */
    if (!compose_auth_paths(cookie_path, sizeof(cookie_path),
                            conf_path, sizeof(conf_path), datadir, home))
        return 1;

    char cookie[256] = "";

    /* 0 = credential acquired, 1 = none found (reported below), -1 = a
     * credential file could not be read or the conf credential was invalid
     * (already reported). */
    int auth = load_any_auth(cookie_path, conf_path, cookie, sizeof(cookie));
    if (auth != 0) {
        if (auth == 1)
            fprintf(stderr, "No auth found (no cookie, no rpcuser/rpcpassword)\n");
        return 1;
    }

    /* Build params JSON from remaining args */
    char params[4096] = "";
    build_params_json(params, sizeof(params), argc, argv);

    /* Override the default RPC port via env. Matches the documentation
     * in README.md (Environment variables section). atoi() returns 0
     * for unparseable values; we keep the literal default in that
     * case rather than connecting to port 0. */
    const char *port_env = getenv("ZCL_RPCPORT");
    int port = rpc_port_from_env(port_env);

    /* The reply buffer carries the status marker curl appends, so it is a
     * little larger than the 1 MiB reply it admits. */
    char response[1024 * 1024 + 256];
    char why[256] = "";
    int n = rpc_call("127.0.0.1", port, cookie, argv[1], params,
                     response, sizeof(response), why, sizeof(why));
    if (n < 0)
        return report_rpc_failure(why, port, argv[1]);

    /* If we got "Unauthorized", retry with conf auth */
    if (n == 0 || strstr(response, "Unauthorized")) {
        int retried = n;
        if (conf_retry_auth(&retried, datadir, home, port, argv[1],
                            params, response, sizeof(response), why,
                            sizeof(why)) < 0)
            return 1;
        n = retried;
    }

    return finish_rpc_reply(n, response, why, port, argv[1]);
}
