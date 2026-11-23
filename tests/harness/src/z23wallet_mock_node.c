/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: fixture-driven loopback RPC server thread for z23-wallet tests. */
#include "z23wallet_mock_node.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "platform/socket_compat.h"

#define SEEN_CAP 8192

struct script_row { char method[48]; int status; int delay_ms; int times; char file[96]; };

struct zw_mock {
    pthread_t thread;
    platform_socket_t listener;
    char dir[512], datadir[512];
    char userpass[2100]; /* when set, Basic auth must match this instead of the cookie */
    struct script_row rows[16];
    size_t nrows;
    volatile bool stop;
    unsigned count;
    char seen[SEEN_CAP];
    pthread_mutex_t mu;
};

static bool b64(const unsigned char *in, size_t n, char *out)
{
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
        out[o++] = i + 1 < n ? t[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? t[v & 63] : '=';
    }
    out[o] = 0;
    return true;
}

bool zw_mock_write_cookie(const char *datadir, const char *cookie_body)
{
    mkdir(datadir
#if !defined(_WIN32)
          , 0700
#endif
    );
    char p[600];
    snprintf(p, sizeof(p), "%s/.cookie", datadir);
    FILE *f = fopen(p, "wb");
    if (!f) return false;
    fputs(cookie_body, f);
    return fclose(f) == 0;
}

static size_t read_file(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, cap - 1, f);
    fclose(f);
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) n--;
    buf[n] = 0;
    return n;
}

static void load_script(struct zw_mock *m)
{
    char p[600], text[2048];
    snprintf(p, sizeof(p), "%s/_script.tsv", m->dir);
    if (!read_file(p, text, sizeof(text))) return;
    for (char *line = strtok(text, "\n"); line && m->nrows < 16; line = strtok(NULL, "\n")) {
        struct script_row *r = &m->rows[m->nrows];
        r->file[0] = 0;
        if (sscanf(line, "%47[^\t]\t%d\t%d\t%d\t%95s", r->method, &r->status, &r->delay_ms,
                   &r->times, r->file) >= 4) m->nrows++;
    }
}

static void send_reply(platform_socket_t c, int status, const char *body)
{
    char head[160];
    int n = snprintf(head, sizeof(head),
                     "HTTP/1.1 %d X\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n"
                     "Connection: close\r\n\r\n", status, strlen(body));
    platform_socket_send_all(c, head, (size_t)n);
    platform_socket_send_all(c, body, strlen(body));
}

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static bool authorized(struct zw_mock *m, const char *req)
{
    char p[600], ck[2100], want[3000];
    size_t n;
    if (m->userpass[0]) {
        n = strlen(m->userpass);
        memcpy(ck, m->userpass, n + 1);
    } else {
        snprintf(p, sizeof(p), "%s/.cookie", m->datadir);
        n = read_file(p, ck, sizeof(ck));
    }
    if (!n) return false;
    char enc[2900];
    b64((const unsigned char *)ck, n, enc);
    snprintf(want, sizeof(want), "Authorization: Basic %s", enc);
    return strstr(req, want) != NULL;
}

/* Hostile peers: -1 closes without a byte, -2 sends half a header, -3 stays silent
 * until the client gives up or the mock stops. */
static void reply_hostile(struct zw_mock *m, platform_socket_t c, int status)
{
    if (status == -2) {
        static const char half[] = "HTTP/1.1 200 OK\r\nContent-Le";
        platform_socket_send_all(c, half, sizeof(half) - 1);
        return;
    }
    while (status == -3 && !m->stop) {
        char b[64];
        int r = platform_socket_wait_readable(c, 50);
        if (r < 0 || (r > 0 && platform_socket_receive(c, b, sizeof(b)) <= 0)) break;
    }
}

static void reply_method(struct zw_mock *m, platform_socket_t c, const char *method)
{
    char path[700], text[8192], out[9000];
    int status = 200;
    for (size_t i = 0; i < m->nrows; i++)
        if ((!strcmp(m->rows[i].method, method) || !strcmp(m->rows[i].method, "*")) &&
            m->rows[i].times != 0) {
            if (m->rows[i].times > 0) m->rows[i].times--;
            if (m->rows[i].status == 999) { /* accept, never reply: hold, then hang up */
                for (int k = 0; k < m->rows[i].delay_ms / 10 && !m->stop; k++) sleep_ms(10);
                return;
            }
            if (m->rows[i].delay_ms) sleep_ms(m->rows[i].delay_ms);
            if (m->rows[i].status) status = m->rows[i].status;
            break;
        }
    if (status < 0) { reply_hostile(m, c, status); return; }
    if (status == 503) { send_reply(c, 503, ""); return; }
    snprintf(path, sizeof(path), "%s/%s.err", m->dir, method);
    size_t n = read_file(path, text, sizeof(text));
    if (!n) {
        snprintf(path, sizeof(path), "%s/_all.err", m->dir);
        n = read_file(path, text, sizeof(text));
    }
    if (n) {
        int code = atoi(text);
        char *tab = strchr(text, '\t');
        snprintf(out, sizeof(out), "{\"result\":null,\"error\":{\"code\":%d,\"message\":\"%s\"},\"id\":1}",
                 code, tab ? tab + 1 : "");
        send_reply(c, 500, out);
        return;
    }
    snprintf(path, sizeof(path), "%s/%s.json", m->dir, method);
    n = read_file(path, text, sizeof(text));
    if (!n) {
        send_reply(c, 404, "{\"result\":null,\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":1}");
        return;
    }
    snprintf(out, sizeof(out), "{\"result\":%s,\"error\":null,\"id\":1}", text);
    send_reply(c, status, out);
}

static void serve_one(struct zw_mock *m, platform_socket_t c)
{
    char req[4096];
    size_t have = 0;
    platform_socket_set_receive_timeout(c, 2000);
    while (have < sizeof(req) - 1) {
        int n = platform_socket_receive(c, req + have, sizeof(req) - 1 - have);
        if (n <= 0) break;
        have += (size_t)n;
        req[have] = 0;
        char *he = strstr(req, "\r\n\r\n");
        if (he) {
            const char *cl = strstr(req, "Content-Length:");
            size_t want = cl ? (size_t)atoi(cl + 15) : 0;
            if (have >= (size_t)(he - req) + 4 + want) break;
        }
    }
    req[have] = 0;
    pthread_mutex_lock(&m->mu);
    m->count++;
    char *body = strstr(req, "\r\n\r\n");
    if (body && strlen(m->seen) + strlen(body) < SEEN_CAP) strcat(m->seen, body + 4);
    pthread_mutex_unlock(&m->mu);
    if (!authorized(m, req)) { send_reply(c, 401, ""); return; }
    const char *mk = strstr(req, "\"method\":\"");
    char method[64] = "";
    if (mk) sscanf(mk + 10, "%63[^\"]", method);
    reply_method(m, c, method);
}

static void *accept_main(void *arg)
{
    struct zw_mock *m = arg;
    while (!m->stop) {
        int w = platform_socket_wait_readable(m->listener, 50);
        if (w <= 0) continue;
        struct sockaddr_in pa;
        size_t pl = sizeof(pa);
        platform_socket_t c = platform_socket_accept(m->listener, (struct sockaddr *)&pa, &pl);
        if (c == PLATFORM_SOCKET_INVALID) continue;
        serve_one(m, c);
        platform_socket_close(c);
    }
    return NULL;
}

struct zw_mock *zw_mock_start(const char *scenario_dir, const char *datadir, uint16_t *port_out)
{
    struct zw_mock *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    snprintf(m->dir, sizeof(m->dir), "%s", scenario_dir);
    snprintf(m->datadir, sizeof(m->datadir), "%s", datadir);
    pthread_mutex_init(&m->mu, NULL);
    load_script(m);
    m->listener = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (m->listener == PLATFORM_SOCKET_INVALID ||
        platform_socket_bind(m->listener, (const struct sockaddr *)&a, sizeof(a)) != 0 ||
        platform_socket_listen(m->listener, 8) != 0) {
        free(m);
        return NULL;
    }
    struct sockaddr_in got;
    memset(&got, 0, sizeof(got));
    socklen_t gl = sizeof(got);
    if (getsockname(m->listener, (struct sockaddr *)&got, &gl) != 0) { free(m); return NULL; }
    *port_out = ntohs(got.sin_port);
    pthread_create(&m->thread, NULL, accept_main, m);
    return m;
}

void zw_mock_stop(struct zw_mock *m)
{
    if (!m) return;
    m->stop = true;
    pthread_join(m->thread, NULL);
    platform_socket_close(m->listener);
    pthread_mutex_destroy(&m->mu);
    free(m);
}

unsigned zw_mock_request_count(const struct zw_mock *m) { return m->count; }

bool zw_mock_saw(const struct zw_mock *m, const char *needle) { return strstr(m->seen, needle) != NULL; }

void zw_mock_set_auth(struct zw_mock *m, const char *userpass)
{
    pthread_mutex_lock(&m->mu);
    snprintf(m->userpass, sizeof(m->userpass), "%s", userpass ? userpass : "");
    pthread_mutex_unlock(&m->mu);
}
