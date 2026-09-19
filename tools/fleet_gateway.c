/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: z23-fleet-gateway — the loopback Streamable-HTTP front for the
 *          fleet steering verbs (fleet.steer.brief/send/evidence).
 *
 * ── CONTRACT ─────────────────────────────────────────────────────────────
 *
 * WHY. A hosted AI client cannot reach a shell, an onion address, or the
 * node's operator-private API. This binary is the smallest remote surface that
 * lets it steer: one HTTP endpoint speaking Streamable HTTP
 * (JSON-RPC over POST), dispatching each tool call to the TESTED node
 * binary over fork/exec with --input JSON, and returning the node's own
 * data envelope. It never re-implements a sibling store, never mints a
 * grant (owner creation stays in fleet.steer.grant, outside AI-callable
 * tools), and never touches wallet, deployment, deletion or soak paths.
 *
 * TRANSPORT (G1: loopback only). Binds 127.0.0.1 (or ::1) on a configured
 * port, refuses non-loopback peers with 403, serves plain HTTP. TLS
 * termination and OAuth live in front of it (host front path) and behind
 * it the node enforces every grant scope, expiry and revocation itself.
 * A bearer passed as a tool argument is carried (header or tool argument), never minted here, and
 * never logged. No credentials in chat, no private data made public.
 * Every tools/call needs exactly one credential (header or "grant"
 * argument); a call with none, or two that differ, is refused with a
 * typed error before the node is forked. A call with none is also a
 * transport 401 carrying the RFC 9728 challenge: a hosted client starts
 * its sign-in only on that status, never on a 200 wrapping the error.
 *
 * OAUTH (G2: hosted-client sign-in). The same binary also speaks the OAuth
 * endpoints a hosted tool client needs: RFC 9728 protected-resource
 * discovery plus RFC 8414 authorization-server discovery, RFC 7591
 * dynamic client registration, an owner-approved authorize step (PKCE
 * S256 only), and RFC 6749 token exchange. An access token IS a scoped steer grant id:
 * no new validation surface exists — the node enforces scope, expiry
 * and revocation per call exactly as for argument-carried grants.
 * Grant minting still happens only inside the node leaf, and only after
 * the owner key (FLEET_GW_OWNER_KEY, never logged) approves the request.
 * The public path at the hosting front reverse-proxies to this binary's
 * frozen /steer; discovery issuer defaults to loopback unless
 * FLEET_GW_ISSUER names the front.
 *
 * TOOL SURFACE (frozen with the verbs). initialize / notifications /
 * tools.list / tools.call for steer_brief, steer_send, steer_evidence.
 * Stateless: no session ids. One JSON-RPC request per POST; parse,
 * invalid-request, method-not-found and invalid-params errors are typed.
 * GET /healthz answers readiness. Everything else is 404; GET on /steer
 * is 405 (writes are never disguised as reads).
 *
 * PROCESS RULE. One fork per connection, one fork/exec per tool call into
 * the configured node binary (default build/bin/z23). No threads, no
 * shell (argv exec only), no popen()/system(). Bounded buffers: 64 KiB
 * request headers, 1 MiB bodies, 4 MiB node replies. POSIX only: on
 * Windows main refuses (the node itself stays portable; the gateway
 * does not claim it).
 */

#if defined(_WIN32)
#include <stdio.h>
#else

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/sha256.h"
#include "json/json.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform/clock.h"
#include "platform/os_proc.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define GW_CAP_HEADERS (64u * 1024u)
#define GW_CAP_BODY (1024u * 1024u)
/* A node call is one execv, and the tool input rides in ONE argv string.
 *
 * This bound is LINUX-SPECIFIC, not a POSIX guarantee: Linux caps a single
 * argument at MAX_ARG_STRLEN = 32 pages = 131072 bytes including its
 * terminator, measured on the deployment host (131071 bytes exec, 131072 is
 * E2BIG). POSIX only promises ARG_MAX for the whole argument block and says
 * nothing about a per-argument cap, so other kernels draw this line
 * elsewhere. The gateway is deployed on Linux; a port must re-measure rather
 * than inherit this number.
 *
 * The argument is "--input=" plus the JSON. Anything larger
 * used to pass the 1 MiB body check, reach execv, fail with E2BIG in the
 * child and surface as the opaque "node did not answer" — the gateway
 * advertising a capacity it could not deliver. The HTTP body cap stays at
 * 1 MiB for OAuth form posts; node-dispatched tool input is bounded here and
 * refused before the fork, with the real number in the message. */
#define GW_ARG_PREFIX "--input="
#define GW_CAP_NODE_INPUT (131071u - (unsigned)(sizeof(GW_ARG_PREFIX) - 1u))
#define GW_CAP_REPLY (4u * 1024u * 1024u)
#define GW_CAP_RESP (5u * 1024u * 1024u)
#define GW_BACKLOG 16

static const char *gw_proto_versions[] = {"2025-06-18", "2025-11-25"};
static const char *gw_server_name = "z23-fleet-gateway";
static const char *gw_server_version = "0.1.0";

/* ── tiny output buffer ───────────────────────────────────────────────── */

struct gw_buf {
    char *p;
    size_t len;
    size_t cap;
    bool oom;
    /* Measure only: len counts what the writers WOULD emit and nothing is
     * stored or allocated. A size decided this way is the exact size the
     * same writers later build, and holds with no heap left at all. */
    bool count;
};

static void gw_buf_reserve(struct gw_buf *b, size_t extra)
{
    size_t need;
    char *np;
    if (!b || b->oom || b->count)
        return;
    need = b->len + extra;
    if (need <= b->cap)
        return;
    need = (need + 4095u) & ~(size_t)4095u;
    np = zcl_realloc(b->p, need, "fleet-gateway/buf");
    if (!np) {
        b->oom = true;
        return;
    }
    b->p = np;
    b->cap = need;
}

static void gw_buf_put(struct gw_buf *b, const char *s, size_t n)
{
    if (!b || b->oom || !s)
        return;
    if (b->count) {
        b->len += n;
        return;
    }
    gw_buf_reserve(b, n + 1);
    if (b->oom)
        return;
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void gw_buf_str(struct gw_buf *b, const char *s)
{
    if (s)
        gw_buf_put(b, s, strlen(s));
}

/* JSON string escape by arithmetic (no digit tables: hex-codec-single). */
static char gw_hex_digit(unsigned v)
{
    return (char)(v <= 9 ? ('0' + v) : ('a' + v - 10));
}

static void gw_buf_json_str(struct gw_buf *b, const char *s)
{
    const unsigned char *p;
    gw_buf_put(b, "\"", 1);
    if (!s) {
        gw_buf_put(b, "\"", 1);
        return;
    }
    for (p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') {
            gw_buf_put(b, "\\", 1);
            gw_buf_put(b, (const char *)p, 1);
        } else if (*p == '\n') {
            gw_buf_put(b, "\\n", 2);
        } else if (*p < 0x20) {
            char esc[7];
            esc[0] = '\\';
            esc[1] = 'u';
            esc[2] = '0';
            esc[3] = '0';
            esc[4] = gw_hex_digit((unsigned)((*p >> 4) & 0xf));
            esc[5] = gw_hex_digit((unsigned)(*p & 0xf));
            esc[6] = '\0';
            gw_buf_put(b, esc, 6);
        } else {
            gw_buf_put(b, (const char *)p, 1);
        }
    }
    gw_buf_put(b, "\"", 1);
}

static void gw_buf_free(struct gw_buf *b)
{
    if (b) {
        free(b->p);
        b->p = NULL;
        b->len = 0;
        b->cap = 0;
        b->oom = false;
    }
}

/* ── config (environment only; no files, no chat) ─────────────────────── */

struct gw_config {
    char bind[64];
    char port[16];
    char node[4096];
    char issuer[256];
    char owner_key[128];
};

/* Bound port for default-issuer rendering (loopback only). */
static int gw_bound_port_seen = 0;

/* Authorize request fields (validated). */
struct gw_authz {
    char client[80];
    char redirect[512];
    char scope[128];
    char state[256];
    char challenge[64];
};

/* Further forward declarations follow struct gw_node_out, below. */

/* Own executable's directory: the default node binary is the sibling z23,
 * so the gateway works no matter which cwd the caller runs it from.
 * The path comes from the platform seam (os_proc_exe_path), never from
 * a raw /proc read in this leaf. */
static bool gw_exe_dir(char *buf, size_t cap) {
    char *slash;
    if (!os_proc_exe_path(buf, cap)) return false;
    /* Truncate the final path component in place (no dirname():
     * its return may alias buf, and copying overlapping %s is UB). */
    slash = strrchr(buf, '/');
    if (!slash || slash == buf) return false;
    *slash = '\0';
    return true;
}

static void gw_config(struct gw_config *c)
{
    const char *v;
    memset(c, 0, sizeof(*c));
    v = getenv("FLEET_GW_BIND");
    snprintf(c->bind, sizeof(c->bind), "%s",
             v && v[0] ? v : "127.0.0.1");
    v = getenv("FLEET_GW_PORT");
    snprintf(c->port, sizeof(c->port), "%s", v && v[0] ? v : "0");
    v = getenv("FLEET_GW_ISSUER");
    snprintf(c->issuer, sizeof(c->issuer), "%s", v && v[0] ? v : "");
    /* Owner key for the authorize approval step. Empty disables OAuth
     * approval (discovery still served); the key is never logged. */
    v = getenv("FLEET_GW_OWNER_KEY");
    if (v && v[0] && strlen(v) < sizeof(c->owner_key))
        memcpy(c->owner_key, v, strlen(v) + 1);
    v = getenv("FLEET_GW_NODE");
    if (v && v[0]) {
        snprintf(c->node, sizeof(c->node), "%s", v);
    } else {
        char dir[4096];
        size_t dn = 0;
        if (gw_exe_dir(dir, sizeof dir)) dn = strlen(dir);
        if (dn > 0 && dn + 5 < sizeof(c->node)) {
            memcpy(c->node, dir, dn);
            memcpy(c->node + dn, "/z23", 5);
        } else {
            snprintf(c->node, sizeof(c->node), "%s", "build/bin/z23");
        }
    }
}

/* ── HTTP/1.1 request (headers + optional body, bounded) ──────────────── */

/* The request target (path plus "?" plus query) is scanned whole into
 * path[] before gw_split_query moves the query out, so this bound is the
 * bound on the WHOLE target, not on the path alone. A real authorize URL
 * carries client_id, a 43-byte S256 challenge, state, scope, an encoded
 * redirect_uri and a resource, which passes 256 bytes easily: at that
 * bound a hosted client's sign-in died as a 400 before any OAuth code
 * ran. Kept well above that, and still a fixed per-connection bound. */
#define GW_CAP_TARGET 2048

struct gw_http {
    char method[16];
    char path[GW_CAP_TARGET];
    char query[GW_CAP_TARGET];
    size_t content_length;
    char *body;
    size_t body_len;
    bool bad;
    /* The body could not be held: the gateway's memory, not the
     * request, so it is never answered as a bad request. */
    bool nomem;
    /* Captured "Authorization: Bearer <token>" credential, NUL-terminated
     * when auth_present. Overlong or non-token bytes set auth_bad instead;
     * both refuse a tool call before the node is forked. */
    char auth[96 + 1];
    bool auth_present;
    bool auth_bad;
};

/* Bearer [REDACTED] alphabet: grant ids are 32-hex today; OAuth bearer
 * tokens (base64url/JWT shapes) must also pass through untouched for the
 * node to rule on. Anything outside this set cannot be a credential. */
static bool gw_token_char(char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9'))
        return true;
    return c == '.' || c == '_' || c == '~' || c == '+' || c == '/' ||
           c == '-' || c == '=';
}

static bool gw_is_space(char c)
{
    return c == ' ' || c == '\t';
}

/* One SP-delimited token into out. Updates the cursor; false on overflow
 * or a missing trailing blank. */
static bool gw_scan_token(const char *line, size_t *i, char *out, size_t cap)
{
    size_t j = 0;
    memset(out, 0, cap);
    while (j + 1 < cap && line[*i] && !gw_is_space(line[*i])) {
        out[j++] = line[*i];
        (*i)++;
    }
    if (!gw_is_space(line[*i]))
        return false;
    while (gw_is_space(line[*i]))
        (*i)++;
    return out[0] != '\0';
}

/* Query string off the path into h->query (form encoding, bounded). */
static bool gw_split_query(struct gw_http *h)
{
    char *q = strchr(h->path, '?');
    size_t qn;
    if (!q)
        return true;
    qn = strlen(q + 1);
    *q = '\0';
    if (qn >= sizeof(h->query))
        return false;
    memcpy(h->query, q + 1, qn + 1);
    return true;
}

/* First line: METHOD SP PATH SP HTTP/1.x. False on any other shape. */
static bool gw_parse_request_line(struct gw_http *h, const char *line)
{
    size_t i = 0;
    memset(h->method, 0, sizeof(h->method));
    memset(h->path, 0, sizeof(h->path));
    if (!gw_scan_token(line, &i, h->method, sizeof(h->method)))
        return false;
    if (!gw_scan_token(line, &i, h->path, sizeof(h->path)))
        return false;
    if (!gw_split_query(h))
        return false;
    while (gw_is_space(line[i]))
        i++;
    if (strncmp(line + i, "HTTP/1.", 7) != 0)
        return false;
    return h->method[0] && h->path[0] && h->path[0] == '/';
}

/* Header-name match, case-insensitive, over the raw line. */
static bool gw_header_is(const char *line, const char *name)
{
    size_t i;
    for (i = 0; name[i]; i++) {
        char a = line[i];
        if (a == '\0')
            return false;
        if (a >= 'A' && a <= 'Z')
            a = (char)(a - 'A' + 'a');
        if (a != name[i])
            return false;
    }
    return line[i] == ':';
}

/* Capture "Authorization: Bearer <token>". Only the exact Bearer scheme
 * carries a credential; any other scheme leaves auth_present false so the
 * call fails closed as unauthenticated rather than half-authenticated. */
static void gw_parse_authorization(struct gw_http *h, const char *line)
{
    static const char bearer[] = "Bearer ";
    const char *v = line + strlen("authorization:");
    size_t n = 0;
    if (h->auth_present || h->auth_bad)
        return;
    while (gw_is_space(*v))
        v++;
    if (strncmp(v, bearer, sizeof(bearer) - 1) != 0)
        return;
    v += sizeof(bearer) - 1;
    while (v[n] && !gw_is_space(v[n])) {
        if (n >= sizeof(h->auth) - 1 || !gw_token_char(v[n])) {
            h->auth_bad = true;
            return;
        }
        h->auth[n] = v[n];
        n++;
    }
    if (n == 0) {
        /* "Bearer " with an empty token is no credential at all. */
        return;
    }
    h->auth[n] = '\0';
    h->auth_present = true;
}

/* One header line: Content-Length sizes the body; Authorization carries
 * the tool-call credential. Every other header is ignored. */
static void gw_parse_header(struct gw_http *h, const char *line)
{
    static const char *const cl = "content-length:";
    size_t k = strlen(cl), i;
    const char *v;
    unsigned long n = 0;
    if (gw_header_is(line, "authorization")) {
        gw_parse_authorization(h, line);
        return;
    }
    for (i = 0; i < k; i++) {
        char a = line[i];
        if (a == '\0')
            return;
        if (a >= 'A' && a <= 'Z')
            a = (char)(a - 'A' + 'a');
        if (a != cl[i])
            return;
    }
    v = line + k;
    while (gw_is_space(*v))
        v++;
    while (*v >= '0' && *v <= '9') {
        n = n * 10u + (unsigned long)(*v - '0');
        if (n > GW_CAP_BODY)
            break;
        v++;
    }
    h->content_length = (size_t)n;
}


/* Authorization value: Bearer scheme only; the token rides h->auth. */

/* Read until end-of-headers. Returns header byte count, or 0 when the
 * cap or EOF hits first. */
static size_t gw_read_headers(int fd, char *buf, size_t cap)
{
    size_t n = 0;
    ssize_t r;
    while (n + 1 < cap) {
        r = read(fd, buf + n, 1);
        if (r <= 0)
            break;
        n += (size_t)r;
        buf[n] = '\0';
        if (n >= 4 && memcmp(buf + n - 4, "\r\n\r\n", 4) == 0)
            return n;
    }
    return 0;
}

static bool gw_read_body(int fd, struct gw_http *h)
{
    size_t left;
    ssize_t r;
    if (h->content_length == 0)
        return true;
    if (h->content_length > GW_CAP_BODY)
        return false;
    h->body = zcl_malloc(h->content_length + 1, "fleet-gateway/body");
    if (!h->body) {
        h->nomem = true;
        return false;
    }
    left = h->content_length;
    h->body_len = 0;
    while (left > 0) {
        r = read(fd, h->body + h->body_len, left);
        if (r <= 0) {
            free(h->body);
            h->body = NULL;
            return false;
        }
        h->body_len += (size_t)r;
        left -= (size_t)r;
    }
    h->body[h->body_len] = '\0';
    return true;
}

static bool gw_http_read(int fd, struct gw_http *h, char *hbuf)
{
    char *eol, *line;
    memset(h, 0, sizeof(*h));
    if (gw_read_headers(fd, hbuf, GW_CAP_HEADERS) == 0) {
        h->bad = true;
        return false;
    }
    eol = strstr(hbuf, "\r\n");
    if (!eol) {
        h->bad = true;
        return false;
    }
    *eol = '\0';
    if (!gw_parse_request_line(h, hbuf)) {
        h->bad = true;
        return false;
    }
    line = eol + 2;
    while (line[0] != '\0') {
        char *nl = strstr(line, "\r\n");
        if (!nl)
            break;
        *nl = '\0';
        gw_parse_header(h, line);
        line = nl + 2;
    }
    return gw_read_body(fd, h);
}

/* ── node invocation (fork/exec argv, never a shell) ───────────────────── */

struct gw_node_out {
    char *text;
    size_t len;
    bool ok;
    /* The node's own exit code, valid when ok: 0, or non-zero with a
     * typed ok:false refusal envelope. */
    int exit_code;
    /* The gateway, not the node, ran out: a pipe, fork or reply buffer
     * could not be had. Reported as a resource failure, never as the
     * node's silence. */
    bool nomem;
};

/* Forward declarations (defined below). */
static bool gw_authorize_issue(int fd, const struct gw_config *cfg,
                               const char *dir, const struct gw_authz *az,
                               const char *comma, char *loc, size_t loccap);
static void gw_state_escape(const char *state, char *esc, size_t cap);

/* Drain the node's stdout into reply, up to GW_CAP_REPLY, growing as it
 * arrives. False when the buffer could not grow: the gateway's memory. */
static bool gw_node_read(int fd, struct gw_buf *reply)
{
    for (;;) {
        size_t room;
        ssize_t r;
        if (reply->len >= GW_CAP_REPLY)
            return true;
        gw_buf_reserve(reply, 4096u + 1u);
        if (reply->oom)
            return false;
        room = reply->cap - reply->len - 1u;
        if (room > GW_CAP_REPLY - reply->len)
            room = GW_CAP_REPLY - reply->len;
        r = read(fd, reply->p + reply->len, room);
        if (r <= 0)
            return true;
        reply->len += (size_t)r;
    }
}

/* The exit code of exactly this child, or -1 when it did not exit normally
 * or its status could not be had. Only this child's own status counts:
 * after ECHILD (reaped elsewhere, or SIGCHLD ignored) a status variable
 * holds whatever it was initialised to, and a zero there reads as a clean
 * exit. */
static int gw_node_wait(pid_t pid)
{
    int st = 0;
    pid_t w;
    do
        w = waitpid(pid, &st, 0);
    while (w < 0 && errno == EINTR);
    if (w != pid || !WIFEXITED(st))
        return -1;
    return WEXITSTATUS(st);
}

/* Run: <node> fleet steer <verb> <arg>, where arg is the whole
 * "--input=<json>" argv string, already built and already within
 * GW_CAP_NODE_INPUT. Stdout (the node's own result envelope) is captured
 * up to GW_CAP_REPLY, grown as it arrives rather than reserved up front. */
static struct gw_node_out gw_node_exec(const char *node, const char *verb,
                                       const char *arg)
{
    struct gw_node_out out;
    struct gw_buf reply;
    int fds[2];
    pid_t pid;
    memset(&out, 0, sizeof(out));
    memset(&reply, 0, sizeof(reply));
    if (pipe(fds) != 0) {
        out.nomem = true;
        return out;
    }
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        out.nomem = true;
        return out;
    }
    if (pid == 0) {
        char *const argv[] = {
            (char *)node, (char *)"fleet", (char *)"steer", (char *)verb,
            (char *)arg, NULL
        };
        dup2(fds[1], STDOUT_FILENO);
        close(fds[0]);
        close(fds[1]);
        execv(node, argv);
        _exit(127);
    }
    close(fds[1]);
    out.nomem = !gw_node_read(fds[0], &reply);
    close(fds[0]);
    out.exit_code = gw_node_wait(pid);
    out.ok = !out.nomem && out.exit_code >= 0 && reply.len > 0;
    if (!out.ok) {
        gw_buf_free(&reply);
        return out;
    }
    reply.p[reply.len] = '\0';
    out.text = reply.p;
    out.len = reply.len;
    return out;
}

/* The same call for a small gateway-built input (the OAuth mint). */
static struct gw_node_out gw_node_call(const char *node, const char *verb,
                                       const char *input_json)
{
    struct gw_node_out out;
    struct gw_buf arg;
    memset(&out, 0, sizeof(out));
    memset(&arg, 0, sizeof(arg));
    gw_buf_str(&arg, GW_ARG_PREFIX);
    gw_buf_str(&arg, input_json ? input_json : "{}");
    if (arg.oom || !arg.p || arg.len - (sizeof(GW_ARG_PREFIX) - 1u) >
                                  GW_CAP_NODE_INPUT) {
        out.nomem = arg.oom || !arg.p;
        gw_buf_free(&arg);
        return out;
    }
    out = gw_node_exec(node, verb, arg.p);
    gw_buf_free(&arg);
    if (out.ok && out.exit_code != 0) {
        free(out.text);
        out.text = NULL;
        out.len = 0;
        out.ok = false;
    }
    return out;
}

/* ── tool mapping (frozen with the verbs) ──────────────────────────────── */

struct gw_tool {
    const char *name;
    const char *verb;
    const char *desc;
    const char *schema;
};

static const struct gw_tool gw_tools[] = {
    {"steer_brief", "brief",
     "Fleet situation: agents, work, blockers, capacity, candidates, evidence refs, changes since a cursor.",
     "{\"type\":\"object\",\"properties\":{\"grant\":{\"type\":\"string\"},\"since\":{\"type\":\"integer\"},\"limit\":{\"type\":\"integer\"}}}"},
    {"steer_send", "send",
     "One bounded batch of directives to named agents; retries with the same idempotency keys never duplicate. Every item carries a ref naming the work: 1-64 of [A-Za-z0-9_.-], never a path. An agent answers a directive with kind result under the same ref.",
     "{\"type\":\"object\",\"required\":[\"items\"],\"properties\":{\"grant\":{\"type\":\"string\"},\"items\":{\"type\":\"array\",\"maxItems\":8,\"items\":{\"type\":\"object\",\"required\":[\"to\",\"body\",\"ref\",\"idempotency_key\"],\"properties\":{\"to\":{\"type\":\"string\"},\"body\":{\"type\":\"string\"},\"ref\":{\"type\":\"string\",\"pattern\":\"^[A-Za-z0-9_.-]{1,64}$\"},\"idempotency_key\":{\"type\":\"string\"},\"kind\":{\"type\":\"string\",\"enum\":[\"directive\",\"result\"]}}}},\"from\":{\"type\":\"string\"}}}"},
    {"steer_evidence", "evidence",
     "One bounded evidence object by exact reference; never a log.",
     "{\"type\":\"object\",\"required\":[\"type\",\"ref\"],\"properties\":{\"grant\":{\"type\":\"string\"},\"type\":{\"type\":\"string\"},\"ref\":{\"type\":\"string\"}}}"},
};

static const struct gw_tool *gw_tool_by_name(const char *name)
{
    size_t i;
    if (!name)
        return NULL;
    for (i = 0; i < sizeof(gw_tools) / sizeof(gw_tools[0]); i++) {
        if (strcmp(gw_tools[i].name, name) == 0)
            return &gw_tools[i];
    }
    return NULL;
}

static const char *gw_json_str(const struct json_value *o, const char *key)
{
    const struct json_value *v = o ? json_get(o, key) : NULL;
    if (!v || v->type != JSON_STR)
        return NULL;
    return json_get_str(v);
}

/* Serialize one JSON value back to text (for embedding node .data). */
static void gw_json_write(struct gw_buf *b, const struct json_value *v);

static void gw_json_write_scalar(struct gw_buf *b, const struct json_value *v)
{
    switch (v->type) {
    case JSON_NULL:
        gw_buf_str(b, "null");
        break;
    case JSON_BOOL:
        gw_buf_str(b, v->val.b ? "true" : "false");
        break;
    case JSON_INT: {
        char n[32];
        snprintf(n, sizeof(n), "%lld", (long long)v->val.i);
        gw_buf_str(b, n);
        break;
    }
    case JSON_REAL: {
        char n[40];
        snprintf(n, sizeof(n), "%.17g", v->val.d);
        gw_buf_str(b, n);
        break;
    }
    default:
        gw_buf_json_str(b, v->val.s ? v->val.s : "");
        break;
    }
}

static void gw_json_write_arr(struct gw_buf *b, const struct json_value *v)
{
    size_t i;
    gw_buf_put(b, "[", 1);
    for (i = 0; i < v->num_children; i++) {
        if (i > 0)
            gw_buf_put(b, ",", 1);
        gw_json_write(b, &v->children[i]);
    }
    gw_buf_put(b, "]", 1);
}

static void gw_json_write_obj(struct gw_buf *b, const struct json_value *v)
{
    size_t i;
    gw_buf_put(b, "{", 1);
    for (i = 0; i < v->num_children; i++) {
        if (i > 0)
            gw_buf_put(b, ",", 1);
        gw_buf_json_str(b, v->keys[i] ? v->keys[i] : "");
        gw_buf_put(b, ":", 1);
        gw_json_write(b, &v->children[i]);
    }
    gw_buf_put(b, "}", 1);
}

static void gw_json_write(struct gw_buf *b, const struct json_value *v)
{
    if (!v) {
        gw_buf_str(b, "null");
        return;
    }
    switch (v->type) {
    case JSON_ARR:
        gw_json_write_arr(b, v);
        break;
    case JSON_OBJ:
        gw_json_write_obj(b, v);
        break;
    default:
        gw_json_write_scalar(b, v);
        break;
    }
}

/* ── JSON-RPC replies ──────────────────────────────────────────────────── */

static void gw_rpc_error(struct gw_buf *b, const struct json_value *id,
                         int code, const char *message)
{
    gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":");
    gw_json_write(b, id);
    gw_buf_str(b, ",\"error\":{\"code\":");
    {
        char n[16];
        snprintf(n, sizeof(n), "%d", code);
        gw_buf_str(b, n);
    }
    gw_buf_str(b, ",\"message\":");
    gw_buf_json_str(b, message ? message : "");
    gw_buf_str(b, "}}");
}

/* Protocol version: the client's when known, else the first we speak.
 * Never invent a version. */
static const char *gw_negotiate(const char *asked)
{
    size_t i;
    if (asked) {
        for (i = 0; i < sizeof(gw_proto_versions) / sizeof(gw_proto_versions[0]);
             i++) {
            if (strcmp(asked, gw_proto_versions[i]) == 0)
                return asked;
        }
    }
    return gw_proto_versions[0];
}

static void gw_reply_initialize(struct gw_buf *b,
                                const struct json_value *id,
                                const struct json_value *params)
{
    const struct json_value *v;
    const char *asked = NULL;
    v = params ? json_get(params, "protocolVersion") : NULL;
    if (v && v->type == JSON_STR)
        asked = json_get_str(v);
    gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":");
    gw_json_write(b, id);
    gw_buf_str(b, ",\"result\":{\"protocolVersion\":");
    gw_buf_json_str(b, gw_negotiate(asked));
    gw_buf_str(b, ",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":");
    gw_buf_json_str(b, gw_server_name);
    gw_buf_str(b, ",\"version\":");
    gw_buf_json_str(b, gw_server_version);
    gw_buf_str(b, "}}}");
}

static void gw_reply_tools_list(struct gw_buf *b, const struct json_value *id)
{
    size_t i;
    gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":");
    gw_json_write(b, id);
    gw_buf_str(b, ",\"result\":{\"tools\":[");
    for (i = 0; i < sizeof(gw_tools) / sizeof(gw_tools[0]); i++) {
        if (i > 0)
            gw_buf_put(b, ",", 1);
        gw_buf_str(b, "{\"name\":");
        gw_buf_json_str(b, gw_tools[i].name);
        gw_buf_str(b, ",\"description\":");
        gw_buf_json_str(b, gw_tools[i].desc);
        gw_buf_str(b, ",\"inputSchema\":");
        gw_buf_str(b, gw_tools[i].schema);
        gw_buf_put(b, "}", 1);
    }
    gw_buf_str(b, "]}}");
}

/* ── the node input, measured where it lies ───────────────────────────────
 *
 * GW_CAP_NODE_INPUT has to hold whatever memory is left. It used to be
 * checked last, after the body had been built into a tree, the arguments
 * serialized, parsed again for the credential and serialized a second
 * time, so an oversize call got whichever answer the heap allowed. Swept
 * with ulimit -v on one 132 KB call: 3000 KB answered -32700 "parse
 * error", 3200 -32603, 3400 -32602 "arguments did not parse", and only
 * 3600 and up the real limit.
 *
 * Now nothing on the way to that verdict allocates. json_valid proves the
 * body is one value under json_read's own grammar, this walker finds the
 * few spans the node input is made of, and the size is counted with the
 * same writers that later build it. The forwarded input IS the caller's
 * own argument bytes, plus the header credential when that is the one
 * carried: built once, exactly sized, never re-parsed. */

/* JSON whitespace, as json_read skips it. */
static const char *gw_raw_ws(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        p++;
    return p;
}

/* One past the string opening at p, walked as json_read walks it: a \u
 * escape consumes four more bytes, whatever they are. */
static const char *gw_raw_str_end(const char *p, const char *end)
{
    p++;
    while (p < end && *p != '"') {
        if (*p == '\\' && end - p > 1) {
            p++;
            if (*p == 'u')
                p += end - p > 4 ? 4 : end - p - 1;
        }
        p++;
    }
    return p < end ? p + 1 : end;
}

/* The byte json_read decodes one escape letter to: the control letters by
 * table, a \u escape as '?' (json_read keeps no code points), anything else
 * as itself. */
static char gw_raw_unescape(char e)
{
    static const char from[] = "bfnrtu";
    static const char to[] = {8, 12, 10, 13, 9, '?'};
    const char *hit = e ? strchr(from, e) : NULL;
    return hit ? to[hit - from] : e;
}

/* The string at p decodes, under json_read's rules, to exactly want. */
static bool gw_raw_str_is(const char *p, const char *end, const char *want)
{
    p++;
    while (p < end && *p != '"') {
        char c = *p;
        if (c == '\\' && end - p > 1) {
            p++;
            c = gw_raw_unescape(*p);
            if (*p == 'u')
                p += end - p > 4 ? 4 : end - p - 1;
        }
        if (*want == '\0' || *want != c)
            return false;
        want++;
        p++;
    }
    return *want == '\0';
}

/* One past a bare scalar (number or literal) starting at p. */
static const char *gw_raw_scalar_end(const char *p, const char *end)
{
    while (p < end && !strchr(",}] \t\n\r", *p))
        p++;
    return p;
}

/* One past the value starting at p (the body is already json_valid). */
static const char *gw_raw_skip(const char *p, const char *end)
{
    int depth = 0;
    p = gw_raw_ws(p, end);
    do {
        if (p >= end)
            return end;
        if (*p == '"') {
            p = gw_raw_str_end(p, end);
            continue;
        }
        if (*p == '{' || *p == '[')
            depth++;
        else if (*p == '}' || *p == ']')
            depth--;
        else if (depth == 0)
            return gw_raw_scalar_end(p, end);
        p++;
    } while (depth > 0);
    return p;
}

/* The value of the FIRST member named key in the object at p, or NULL:
 * json_get's answer, found without the tree. */
static const char *gw_raw_member(const char *p, const char *end,
                                 const char *key)
{
    p = gw_raw_ws(p, end);
    if (p >= end || *p != '{')
        return NULL;
    p = gw_raw_ws(p + 1, end);
    while (p < end && *p == '"') {
        const char *k = p;
        p = gw_raw_ws(gw_raw_str_end(p, end), end);
        p = gw_raw_ws(p + 1, end);
        if (gw_raw_str_is(k, end, key))
            return p;
        p = gw_raw_ws(gw_raw_skip(p, end), end);
        if (p < end && *p == ',')
            p = gw_raw_ws(p + 1, end);
    }
    return NULL;
}

/* What one tools/call would forward, as spans of the request body. */
struct gw_call_plan {
    bool is_call;         /* method is the string "tools/call" */
    const char *id;       /* raw id bytes; NULL for a notification */
    size_t id_len;
    const char *args;     /* raw arguments bytes; "{}" when not a container */
    size_t args_len;
    bool args_obj;
    bool args_empty;
    bool arg_grant;       /* arguments carry a non-empty string grant */
};

static void gw_call_scan(const char *body, size_t len,
                         struct gw_call_plan *pl)
{
    const char *end = body + len;
    const char *v, *g;
    memset(pl, 0, sizeof(*pl));
    /* A missing or scalar arguments member forwards as an empty object. */
    pl->args = "{}";
    pl->args_len = 2;
    pl->args_obj = true;
    pl->args_empty = true;
    v = gw_raw_member(body, end, "method");
    pl->is_call = v && *v == '"' && gw_raw_str_is(v, end, "tools/call");
    v = gw_raw_member(body, end, "id");
    if (v && !(end - v >= 4 && memcmp(v, "null", 4) == 0)) {
        pl->id = v;
        pl->id_len = (size_t)(gw_raw_skip(v, end) - v);
    }
    v = gw_raw_member(body, end, "params");
    v = v ? gw_raw_member(v, end, "arguments") : NULL;
    if (v && (*v == '{' || *v == '[')) {
        pl->args = v;
        pl->args_len = (size_t)(gw_raw_skip(v, end) - v);
        pl->args_obj = *v == '{';
        pl->args_empty = pl->args_obj && *gw_raw_ws(v + 1, end) == '}';
        g = pl->args_obj ? gw_raw_member(v, end, "grant") : NULL;
        pl->arg_grant = g && *g == '"' && gw_raw_str_end(g, end) - g > 2;
    }
}

/* The node input: the caller's arguments, with the header credential
 * appended as "grant" when it is the one carried. Into a count buffer this
 * is the measurement; into a real one, the build. */
static void gw_input_write(struct gw_buf *b, const struct gw_call_plan *pl,
                           const char *carry)
{
    if (!carry) {
        gw_buf_put(b, pl->args, pl->args_len);
        return;
    }
    gw_buf_put(b, pl->args, pl->args_len - 1u);
    if (!pl->args_empty)
        gw_buf_put(b, ",", 1);
    gw_buf_str(b, "\"grant\":");
    gw_buf_json_str(b, carry);
    gw_buf_put(b, "}", 1);
}

static size_t gw_input_len(const struct gw_call_plan *pl, const char *carry)
{
    struct gw_buf m;
    memset(&m, 0, sizeof(m));
    m.count = true;
    gw_input_write(&m, pl, carry);
    return m.len;
}

/* The header credential the node input will carry, if any: the one rule
 * gw_credential enforces, read from the plan. */
static const char *gw_plan_carry(const struct gw_call_plan *pl,
                                 const char *bearer, bool bearer_bad)
{
    if (!bearer || bearer_bad || pl->arg_grant || !pl->args_obj)
        return NULL;
    return bearer;
}

static void gw_input_refusal(char *msg, size_t cap, size_t n)
{
    snprintf(msg, cap,
             "tool input is %zu bytes; one node call carries at most %u", n,
             (unsigned)GW_CAP_NODE_INPUT);
}

/* The oversize verdict, before any tree exists: a call that cannot be
 * carried is refused as soon as its bytes are known to be JSON, whatever
 * else it says. The id is echoed as the caller sent it. True when the
 * refusal was written. */
static bool gw_refuse_oversize(struct gw_buf *b, const struct gw_call_plan *pl,
                               const char *bearer, bool bearer_bad)
{
    size_t n;
    char msg[128];
    if (!pl->is_call || !pl->id)
        return false;
    n = gw_input_len(pl, gw_plan_carry(pl, bearer, bearer_bad));
    if (n <= GW_CAP_NODE_INPUT)
        return false;
    gw_input_refusal(msg, sizeof(msg), n);
    gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":");
    gw_buf_put(b, pl->id, pl->id_len);
    gw_buf_str(b, ",\"error\":{\"code\":-32602,\"message\":");
    gw_buf_json_str(b, msg);
    gw_buf_str(b, "}}");
    return true;
}

/* Fail-closed credential rule. A tool call reaches the node only with
 * exactly one credential: the Authorization Bearer [REDACTED] the tool-argument
 * grant. Neither may be ambiguous, and the node is never forked for an
 * unauthenticated call — its operator authority stays local-only. Scope,
 * expiry and revocation remain node-enforced after forwarding. *carry is
 * the header credential the input must add, or NULL. */
static bool gw_credential(struct gw_buf *b, const struct json_value *id,
                          const char *bearer, bool bearer_bad,
                          const struct json_value *args, bool args_obj,
                          const char **carry, bool *challenge)
{
    const struct json_value *g;
    const char *arg_grant = NULL;
    *carry = NULL;
    g = json_get(args, "grant");
    if (g && g->type == JSON_STR)
        arg_grant = json_get_str((struct json_value *)g);
    if (arg_grant && !arg_grant[0])
        arg_grant = NULL;
    if (bearer_bad) {
        gw_rpc_error(b, id, -32002, "bad grant credential");
        return false;
    }
    if (!bearer && !arg_grant) {
        /* The one refusal a remote client can cure by signing in: the
         * transport wraps this same typed body in a 401 OAuth challenge
         * (gw_reply_challenge), which is what starts a client's sign-in. */
        *challenge = true;
        gw_rpc_error(b, id, -32001, "grant required");
        return false;
    }
    if (bearer && arg_grant && strcmp(bearer, arg_grant) != 0) {
        gw_rpc_error(b, id, -32002, "conflicting grants");
        return false;
    }
    if (bearer && !arg_grant) {
        if (!args_obj) {
            gw_rpc_error(b, id, -32602, "grant cannot be carried");
            return false;
        }
        *carry = bearer;
    }
    return true;
}

/* Fork the node for one credentialed call and format its own envelope as
 * the tool result content (a node refusal is content with isError:true,
 * never a transport error). arg is the whole "--input=" argv string. */
static void gw_forward_call(struct gw_buf *b, const struct json_value *id,
                            const struct gw_tool *t, const char *node,
                            const char *arg)
{
    struct gw_node_out out;
    struct json_value env;
    const struct json_value *data;
    out = gw_node_exec(node, t->verb, arg);
    if (out.nomem) {
        gw_rpc_error(b, id, -32603, "gateway resources exhausted");
        return;
    }
    if (!out.ok) {
        gw_rpc_error(b, id, -32000, "node did not answer");
        return;
    }
    json_init(&env);
    if (!json_read(&env, out.text, out.len)) {
        json_free(&env);
        free(out.text);
        gw_rpc_error(b, id, -32000, "node answer did not parse");
        return;
    }
    free(out.text);
    /* The node's own data becomes the tool result content. A refused node
     * call (ok:false) is content, not a transport error: the caller sees
     * the exact typed refusal (the error object, never a bare null) and
     * its evidence. The exit status must agree with the envelope: the CLI
     * exits 0 for ok:true and non-zero (1 failed, 2 input refused) with a
     * typed ok:false refusal. A failing exit claiming success is not an
     * answer, whatever the bytes say; a signal never reaches here. */
    {
        const struct json_value *okv = json_get(&env, "ok");
        bool ok = okv && okv->type == JSON_BOOL && okv->val.b;
        if (out.exit_code != 0 && ok) {
            json_free(&env);
            gw_rpc_error(b, id, -32000, "node did not answer");
            return;
        }
        data = json_get(&env, ok ? "data" : "error");
    }
    gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":");
    gw_json_write(b, id);
    gw_buf_str(b, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
    {
        struct gw_buf text;
        memset(&text, 0, sizeof(text));
        gw_json_write(&text, data);
        if (text.oom || !text.p)
            gw_buf_json_str(b, "");
        else
            gw_buf_json_str(b, text.p);
        gw_buf_free(&text);
    }
    gw_buf_str(b, "}],\"isError\":");
    {
        const struct json_value *okv = json_get(&env, "ok");
        bool ok = okv && okv->type == JSON_BOOL && okv->val.b;
        gw_buf_str(b, ok ? "false" : "true");
    }
    gw_buf_str(b, "}}");
    json_free(&env);
}

static void gw_reply_tool_call(struct gw_buf *b, const struct json_value *id,
                               const struct json_value *params,
                               const struct gw_call_plan *pl,
                               const char *node, const char *bearer,
                               bool bearer_bad, bool *challenge)
{
    const struct gw_tool *t;
    const char *name, *carry = NULL;
    const struct json_value *args;
    struct gw_buf arg;
    size_t n;
    name = gw_json_str(params, "name");
    t = gw_tool_by_name(name);
    if (!t) {
        gw_rpc_error(b, id, -32602, "unknown tool");
        return;
    }
    args = params ? json_get(params, "arguments") : NULL;
    if (!gw_credential(b, id, bearer, bearer_bad, args, pl->args_obj, &carry,
                       challenge))
        return;
    /* gw_refuse_oversize already held this bound; stating it again here
     * keeps the fork unreachable for an input execv cannot carry, whatever
     * the plan and the tree might ever disagree on. */
    n = gw_input_len(pl, carry);
    if (n > GW_CAP_NODE_INPUT) {
        char msg[128];
        gw_input_refusal(msg, sizeof(msg), n);
        gw_rpc_error(b, id, -32602, msg);
        return;
    }
    memset(&arg, 0, sizeof(arg));
    gw_buf_reserve(&arg, sizeof(GW_ARG_PREFIX) + n);
    gw_buf_str(&arg, GW_ARG_PREFIX);
    gw_input_write(&arg, pl, carry);
    if (arg.oom || !arg.p) {
        gw_buf_free(&arg);
        gw_rpc_error(b, id, -32603, "gateway resources exhausted");
        return;
    }
    gw_forward_call(b, id, t, node, arg.p);
    gw_buf_free(&arg);
}

/* Everything decided before a tree exists, none of it allocating: malformed
 * (json_valid, so it never depends on the heap; a body it accepts is JSON
 * whatever json_read later says) and oversize. True when a reply was
 * written; *plan is loaded otherwise. */
static bool gw_rpc_pretree(struct gw_buf *b, const char *body, size_t len,
                           struct gw_call_plan *plan, const char *bearer,
                           bool bearer_bad)
{
    if (!body || !json_valid(body, len)) {
        gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":null,"
                      "\"error\":{\"code\":-32700,"
                      "\"message\":\"parse error\"}}");
        return true;
    }
    gw_call_scan(body, len, plan);
    return gw_refuse_oversize(b, plan, bearer, bearer_bad);
}

static void gw_dispatch_rpc(struct gw_buf *b, const char *body,
                            const char *node, const char *bearer,
                            bool bearer_bad, bool *challenge)
{
    struct json_value req;
    const struct json_value *v;
    const char *method;
    const struct json_value *id, *params;
    struct gw_call_plan plan;
    size_t len = body ? strlen(body) : 0;
    if (gw_rpc_pretree(b, body, len, &plan, bearer, bearer_bad))
        return;
    json_init(&req);
    if (!json_read(&req, body, len)) {
        /* Valid JSON that could not be built: memory, not the caller. */
        json_free(&req);
        gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":null,"
                      "\"error\":{\"code\":-32603,"
                      "\"message\":\"gateway resources exhausted\"}}");
        return;
    }
    if (req.type != JSON_OBJ) {
        json_free(&req);
        gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":null,"
                      "\"error\":{\"code\":-32600,"
                      "\"message\":\"invalid request\"}}");
        return;
    }
    v = json_get(&req, "method");
    method = (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
    id = json_get(&req, "id");
    params = json_get(&req, "params");
    if (!method) {
        json_free(&req);
        gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":null,"
                      "\"error\":{\"code\":-32600,"
                      "\"message\":\"invalid request\"}}");
        return;
    }
    if (!id || id->type == JSON_NULL) {
        /* Notifications carry no id and take no reply; the only one the
         * surface defines is initialized. Anything else is dropped. */
        json_free(&req);
        gw_buf_str(b, "");
        return;
    }
    if (strcmp(method, "initialize") == 0)
        gw_reply_initialize(b, id, params);
    else if (strcmp(method, "tools/list") == 0)
        gw_reply_tools_list(b, id);
    else if (strcmp(method, "tools/call") == 0)
        gw_reply_tool_call(b, id, params, &plan, node, bearer, bearer_bad,
                           challenge);
    else if (strcmp(method, "ping") == 0) {
        gw_buf_str(b, "{\"jsonrpc\":\"2.0\",\"id\":");
        gw_json_write(b, id);
        gw_buf_str(b, ",\"result\":{}}");
    } else
        gw_rpc_error(b, id, -32601, "method not found");
    json_free(&req);
}

/* ── OAuth (G2) ────────────────────────────────────────────────────────── */

#define GW_OAUTH_CODE_TTL (10LL * 60)
#define GW_OAUTH_ID_HEX 32

/* (Forward declarations live before first use, below the config.) */

/* Percent-decode one form/query pair source. Lowercase hex only on output
 * (zcl_hex_decode round-trips); malformed escapes fail the lookup. */
static bool gw_urldecode(const char *s, char *out, size_t cap)
{
    size_t o = 0;
    if (!s || !out || cap == 0)
        return false;
    while (*s && o + 1 < cap) {
        if (*s == '+') {
            out[o++] = ' ';
            s++;
        } else if (*s == '%' && s[1] && s[2]) {
            uint8_t byte = 0;
            char hex[3];
            hex[0] = s[1];
            hex[1] = s[2];
            hex[2] = '\0';
            if (!zcl_hex_decode(hex, &byte, 1))
                return false;
            out[o++] = (char)byte;
            s += 3;
        } else if (*s == '%' || *s == '&' || *s == '=') {
            return false;
        } else {
            out[o++] = *s++;
        }
    }
    if (*s)
        return false;
    out[o] = '\0';
    return true;
}

/* First k=v pair named key in a query/form body. Decoded value out. */
static bool gw_form_get(const char *body, const char *key, char *out,
                        size_t cap)
{
    size_t kn;
    const char *p;
    if (!body || !key || !out || cap == 0)
        return false;
    kn = strlen(key);
    p = body;
    for (;;) {
        const char *amp;
        size_t vlen;
        if (strncmp(p, key, kn) == 0 && p[kn] == '=') {
            char raw[2048];
            p += kn + 1;
            amp = strchr(p, '&');
            vlen = amp ? (size_t)(amp - p) : strlen(p);
            if (vlen >= sizeof(raw))
                return false;
            memcpy(raw, p, vlen);
            raw[vlen] = '\0';
            return gw_urldecode(raw, out, cap);
        }
        amp = strchr(p, '&');
        if (!amp)
            return false;
        p = amp + 1;
    }
}

/* 32 lowercase hex from /dev/urandom (no crypto link needed for ids). */
static bool gw_rand_hex(char out[GW_OAUTH_ID_HEX + 1])
{
    uint8_t raw[GW_OAUTH_ID_HEX / 2];
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got = 0;
    if (!f)
        return false;
    while (got < sizeof(raw)) {
        size_t r = fread(raw + got, 1, sizeof(raw) - got, f);
        if (r == 0)
            break;
        got += r;
    }
    (void)fclose(f);
    if (got != sizeof(raw))
        return false;
    zcl_hex_encode(raw, sizeof(raw), out);
    return true;
}

/* Constant-time compare for secrets of known length. */
static bool gw_consteq(const char *a, const char *b, size_t n)
{
    unsigned diff = 0;
    size_t i;
    if (!a || !b)
        return false;
    for (i = 0; i < n; i++)
        diff |= (unsigned)(a[i] ^ b[i]);
    return diff == 0;
}

/* base64url (no padding) of 32 bytes: PKCE S256 challenges. */
static void gw_b64url_32(const uint8_t *in, char out[44])
{
    static const char alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    unsigned i, o = 0;
    for (i = 0; i < 32; i += 3) {
        unsigned triple = ((unsigned)in[i] << 16);
        unsigned left = 32 - i;
        unsigned nout = left >= 3 ? 4 : left + 1;
        unsigned k;
        if (left > 1)
            triple |= (unsigned)in[i + 1] << 8;
        if (left > 2)
            triple |= (unsigned)in[i + 2];
        for (k = 0; k < nout; k++)
            out[o++] = alpha[(triple >> (18 - 6 * k)) & 63u];
    }
    out[o] = '\0';
}

/* S256 code challenge check: SHA-256(verifier) base64url == challenge. */
static bool gw_pkce_ok(const char *verifier, const char *challenge)
{
    struct sha256_ctx ctx;
    uint8_t digest[SHA256_OUTPUT_SIZE];
    char encoded[44];
    if (!verifier || !verifier[0] || strlen(verifier) > 512)
        return false;
    if (!challenge || strlen(challenge) != 43)
        return false;
    sha256_init(&ctx);
    sha256_write(&ctx, (const unsigned char *)verifier, strlen(verifier));
    sha256_finalize(&ctx, digest);
    gw_b64url_32(digest, encoded);
    return gw_consteq(encoded, challenge, 43);
}

/* Minimal HTML escaping for values reflected into the approval form. */
static void gw_html_escape(struct gw_buf *b, const char *s)
{
    if (!s)
        return;
    for (; *s; s++) {
        switch (*s) {
        case '&': gw_buf_str(b, "&amp;"); break;
        case '<': gw_buf_str(b, "&lt;"); break;
        case '>': gw_buf_str(b, "&gt;"); break;
        case '"': gw_buf_str(b, "&quot;"); break;
        default: gw_buf_put(b, s, 1); break;
        }
    }
}

/* Owner-private steer dir (<xdg>/z23/dev/steer), created 0700 when needed.
 * The node enforces the same root; the gateway keeps only OAuth rows here. */
static bool gw_steer_dir(char *out, size_t cap)
{
    const char *xdg = getenv("XDG_STATE_HOME");
    const char *home = getenv("HOME");
    char base[4096], z23[4096], dev[4096];
    const char *levels[3];
    size_t i;
    if (xdg && xdg[0]) {
        if (snprintf(base, sizeof(base), "%s", xdg) < 0)
            return false;
    } else if (home && home[0]) {
        if (snprintf(base, sizeof(base), "%s/.local/state", home) < 0)
            return false;
    } else {
        return false;
    }
    if (snprintf(z23, sizeof(z23), "%s/z23", base) < 0 ||
        snprintf(dev, sizeof(dev), "%s/dev", z23) < 0 ||
        snprintf(out, cap, "%s/steer", dev) < 0)
        return false;
    levels[0] = z23;
    levels[1] = dev;
    levels[2] = out;
    for (i = 0; i < 3; i++) {
        if (mkdir(levels[i], 0700) != 0 && errno != EEXIST)
            return false;
    }
    return true;
}

/* Flat JSON string/int extractors for our own OAuth rows. */
static bool gw_row_str(const char *line, const char *key, char *out,
                       size_t cap)
{
    char pat[64];
    const char *p, *q;
    size_t n;
    if (snprintf(pat, sizeof(pat), "\"%s\":\"", key) < 0)
        return false;
    p = strstr(line, pat);
    if (!p)
        return false;
    p += strlen(pat);
    q = strchr(p, '"');
    if (!q)
        return false;
    n = (size_t)(q - p);
    if (n + 1 > cap)
        return false;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static bool gw_row_int(const char *line, const char *key, long long *out)
{
    char pat[64];
    const char *p;
    char *end = NULL;
    if (snprintf(pat, sizeof(pat), "\"%s\":", key) < 0)
        return false;
    p = strstr(line, pat);
    if (!p)
        return false;
    *out = strtoll(p + strlen(pat), &end, 10);
    return end != p + strlen(pat);
}

/* Registration rows are one URI each; true when id owns exactly redir. */
static bool gw_client_find(const char *dir, const char *id, const char *redir)
{
    char path[4096 + 64];
    char line[4096];
    FILE *f;
    if (snprintf(path, sizeof(path), "%s/oauth_clients.jsonl", dir) < 0)
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    while (fgets(line, sizeof(line), f)) {
        char got[80], greg[516];
        if (gw_row_str(line, "id", got, sizeof(got)) &&
            strcmp(got, id) == 0 &&
            gw_row_str(line, "redirect", greg, sizeof(greg)) &&
            strcmp(greg, redir) == 0) {
            (void)fclose(f);
            return true;
        }
    }
    (void)fclose(f);
    return false;
}

/* Last oauth_codes.jsonl row for code (use-marking is last-wins). */
static bool gw_code_find(const char *dir, const char *code, char *grant,
                         size_t grantcap, char *client, size_t clientcap,
                         char *redir, size_t redircap, char *challenge,
                         size_t chalcap, char *scopes, size_t scopescap,
                         long long *expires, long long *grant_expires,
                         bool *used)
{
    char path[4096 + 64];
    char line[4096];
    FILE *f;
    bool found = false;
    if (snprintf(path, sizeof(path), "%s/oauth_codes.jsonl", dir) < 0)
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    while (fgets(line, sizeof(line), f)) {
        char got[80], u[8];
        if (!gw_row_str(line, "code", got, sizeof(got)) ||
            strcmp(got, code) != 0)
            continue;
        if (!gw_row_str(line, "grant", grant, grantcap) ||
            !gw_row_str(line, "client", client, clientcap) ||
            !gw_row_str(line, "redirect", redir, redircap) ||
            !gw_row_str(line, "challenge", challenge, chalcap) ||
            !gw_row_str(line, "scopes", scopes, scopescap) ||
            !gw_row_int(line, "expires", expires) ||
            !gw_row_int(line, "grant_expires", grant_expires))
            continue;
        *used = gw_row_str(line, "used", u, sizeof(u)) && strcmp(u, "1") == 0;
        found = true;
    }
    (void)fclose(f);
    return found;
}

/* Space-separated scope subset of brief,send,evidence joined with commas. */
static bool gw_scope_comma(const char *scope, char *out, size_t cap)
{
    static const char *const vocab[3] = {"brief", "send", "evidence"};
    char copy[128];
    bool seen[3] = {false, false, false};
    char *tok;
    size_t o = 0, i;
    bool any = false;
    if (!scope || !scope[0] || strlen(scope) >= sizeof(copy))
        return false;
    memcpy(copy, scope, strlen(scope) + 1);
    tok = strtok(copy, " ");
    while (tok) {
        bool known = false;
        for (i = 0; i < 3; i++) {
            if (strcmp(tok, vocab[i]) == 0) {
                seen[i] = true;
                known = true;
                break;
            }
        }
        if (!known)
            return false;
        tok = strtok(NULL, " ");
    }
    for (i = 0; i < 3; i++) {
        if (!seen[i])
            continue;
        if (o + strlen(vocab[i]) + 2 > cap)
            return false;
        if (any)
            out[o++] = ',';
        memcpy(out + o, vocab[i], strlen(vocab[i]));
        o += strlen(vocab[i]);
        any = true;
    }
    if (!any)
        return false;
    out[o] = '\0';
    return true;
}

/* Forward declarations (defined in HTTP replies below). */
static void gw_write_all(int fd, const char *p, size_t n);
static void gw_reply(int fd, int status, const char *ctype, const char *body,
                     size_t n);

/* Issuer: front-configured, else loopback with the bound port. */
static void gw_oauth_issuer(const struct gw_config *cfg, char *out,
                            size_t cap)
{
    if (cfg->issuer[0]) {
        snprintf(out, cap, "%s", cfg->issuer);
        return;
    }
    snprintf(out, cap, "http://127.0.0.1:%d", gw_bound_port_seen);
}

static void gw_reply_redirect(int fd, const char *location)
{
    struct gw_buf b;
    memset(&b, 0, sizeof(b));
    gw_buf_str(&b, "HTTP/1.1 302 Found\r\nLocation: ");
    gw_buf_str(&b, location ? location : "/");
    gw_buf_str(&b, "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    if (!b.oom && b.p)
        gw_write_all(fd, b.p, b.len);
    gw_buf_free(&b);
}

static void gw_oauth_error(int fd, const char *code)
{
    struct gw_buf b;
    memset(&b, 0, sizeof(b));
    gw_buf_str(&b, "{\"error\":\"");
    gw_buf_str(&b, code ? code : "server_error");
    gw_buf_str(&b, "\"}");
    if (!b.oom && b.p)
        gw_reply(fd, 400, "application/json", b.p, b.len);
    else
        gw_reply(fd, 400, "application/json", "{\"error\":\"server_error\"}",
                 24);
    gw_buf_free(&b);
}

static void gw_oauth_wellknown(int fd, const struct gw_config *cfg,
                               bool server_meta)
{
    char issuer[300];
    char url[340];
    struct gw_buf b;
    memset(&b, 0, sizeof(b));
    gw_oauth_issuer(cfg, issuer, sizeof(issuer));
    gw_buf_str(&b, "{");
    if (!server_meta) {
        if (snprintf(url, sizeof(url), "%s/steer", issuer) < 0)
            url[0] = '\0';
        gw_buf_str(&b, "\"resource\":");
        gw_buf_json_str(&b, url);
        gw_buf_str(&b, ",\"authorization_servers\":[");
        gw_buf_json_str(&b, issuer);
        gw_buf_str(&b, "],\"scopes_supported\":[\"brief\",\"send\","
                      "\"evidence\"],\"bearer_methods_supported\":[\"header\"]}");
    } else {
        gw_buf_str(&b, "\"issuer\":");
        gw_buf_json_str(&b, issuer);
        if (snprintf(url, sizeof(url), "%s/oauth/authorize", issuer) < 0)
            url[0] = '\0';
        gw_buf_str(&b, ",\"authorization_endpoint\":");
        gw_buf_json_str(&b, url);
        if (snprintf(url, sizeof(url), "%s/oauth/token", issuer) < 0)
            url[0] = '\0';
        gw_buf_str(&b, ",\"token_endpoint\":");
        gw_buf_json_str(&b, url);
        if (snprintf(url, sizeof(url), "%s/oauth/register", issuer) < 0)
            url[0] = '\0';
        gw_buf_str(&b, ",\"registration_endpoint\":");
        gw_buf_json_str(&b, url);
        gw_buf_str(&b, ",\"response_types_supported\":[\"code\"],"
                      "\"grant_types_supported\":[\"authorization_code\"],"
                      "\"token_endpoint_auth_methods_supported\":[\"none\"],"
                      "\"code_challenge_methods_supported\":[\"S256\"],"
                      "\"scopes_supported\":[\"brief\",\"send\",\"evidence\"]}");
    }
    if (!b.oom && b.p)
        gw_reply(fd, 200, "application/json", b.p, b.len);
    else
        gw_reply(fd, 500, "application/json", "{\"error\":\"server_error\"}",
                 24);
    gw_buf_free(&b);
}

/* Redirect URIs: https anywhere, or http on loopback hosts. */
static bool gw_redirect_ok(const char *uri)
{
    static const char *const loop[2] = {"http://127.0.0.1",
                                        "http://localhost"};
    size_t i;
    if (!uri || !uri[0] || strlen(uri) > 512)
        return false;
    if (strncmp(uri, "https://", 8) == 0 && uri[8])
        return true;
    for (i = 0; i < 2; i++) {
        size_t n = strlen(loop[i]);
        if (strncmp(uri, loop[i], n) == 0 &&
            (uri[n] == ':' || uri[n] == '/' || uri[n] == '\0'))
            return true;
    }
    return false;
}

static bool gw_client_id_ok(const char *id)
{
    size_t i;
    if (!id || strlen(id) != GW_OAUTH_ID_HEX)
        return false;
    for (i = 0; i < GW_OAUTH_ID_HEX; i++) {
        char c = id[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex)
            return false;
    }
    return true;
}

/* Validated redirect_uris out of a register body (1..8, loopback/https). */
static bool gw_register_uris(const struct gw_http *h, char redirs[8][512],
                             size_t *count)
{
    struct json_value body;
    const struct json_value *uris;
    size_t i, n;
    json_init(&body);
    if (!h->body || !json_read(&body, h->body, h->body_len)) {
        json_free(&body);
        return false;
    }
    uris = json_get(&body, "redirect_uris");
    n = (uris && uris->type == JSON_ARR) ? json_size(uris) : 0;
    if (n == 0 || n > 8) {
        json_free(&body);
        return false;
    }
    for (i = 0; i < n; i++) {
        const struct json_value *u = json_at(uris, i);
        const char *s = (u && u->type == JSON_STR) ? json_get_str(u) : NULL;
        if (!s || !gw_redirect_ok(s) || strlen(s) >= sizeof(redirs[i])) {
            json_free(&body);
            return false;
        }
        memcpy(redirs[i], s, strlen(s) + 1);
    }
    json_free(&body);
    *count = n;
    return true;
}

/* POST /oauth/register {"redirect_uris":[...]} -> client_id. */
static void gw_oauth_register(int fd, const struct gw_http *h,
                              const struct gw_config *cfg)
{
    struct gw_buf b;
    char dir[4096], path[4096 + 64], cid[GW_OAUTH_ID_HEX + 1];
    char redirs[8][512];
    size_t i, n = 0;
    FILE *f;
    (void)cfg;
    memset(&b, 0, sizeof(b));
    if (!gw_register_uris(h, redirs, &n)) {
        gw_oauth_error(fd, "invalid_redirect_uri");
        return;
    }
    if (!gw_steer_dir(dir, sizeof(dir)) || !gw_rand_hex(cid)) {
        gw_oauth_error(fd, "server_error");
        return;
    }
    if (snprintf(path, sizeof(path), "%s/oauth_clients.jsonl", dir) < 0) {
        gw_oauth_error(fd, "server_error");
        return;
    }
    f = fopen(path, "ab");
    if (!f) {
        gw_oauth_error(fd, "server_error");
        return;
    }
    for (i = 0; i < n; i++)
        fprintf(f, "{\"id\":\"%s\",\"redirect\":\"%s\"}\n", cid, redirs[i]);
    (void)fclose(f);
    gw_buf_str(&b, "{\"client_id\":\"");
    gw_buf_str(&b, cid);
    gw_buf_str(&b, "\",\"redirect_uris\":[");
    for (i = 0; i < n; i++) {
        if (i > 0)
            gw_buf_put(&b, ",", 1);
        gw_buf_json_str(&b, redirs[i]);
    }
    gw_buf_str(&b, "],\"token_endpoint_auth_method\":\"none\"}");
    if (!b.oom && b.p)
        gw_reply(fd, 201, "application/json", b.p, b.len);
    else
        gw_reply(fd, 500, "application/json", "{\"error\":\"server_error\"}",
                 24);
    gw_buf_free(&b);
}

/* Authorize request validation shared by GET (form) and POST (approve). */
static bool gw_authz_parse(const char *src, const char *dir,
                           struct gw_authz *out, char *comma, size_t commacap)
{
    char method[16];
    memset(out, 0, sizeof(*out));
    if (!gw_form_get(src, "response_type", method, sizeof(method)) ||
        strcmp(method, "code") != 0)
        return false;
    if (!gw_form_get(src, "client_id", out->client, sizeof(out->client)) ||
        !gw_client_id_ok(out->client))
        return false;
    if (!gw_form_get(src, "redirect_uri", out->redirect,
                     sizeof(out->redirect)) ||
        !gw_redirect_ok(out->redirect))
        return false;
    if (!gw_client_find(dir, out->client, out->redirect))
        return false;
    if (!gw_form_get(src, "scope", out->scope, sizeof(out->scope)) ||
        !gw_scope_comma(out->scope, comma, commacap))
        return false;
    (void)gw_form_get(src, "state", out->state, sizeof(out->state));
    {
        char method2[16];
        if (!gw_form_get(src, "code_challenge", out->challenge,
                         sizeof(out->challenge)))
            return false;
        if (!gw_form_get(src, "code_challenge_method", method2,
                         sizeof(method2)) ||
            strcmp(method2, "S256") != 0)
            return false;
    }
    return true;
}

/* GET /oauth/authorize?... -> owner approval form (values HTML-escaped). */
static void gw_oauth_authorize_get(int fd, const struct gw_http *h,
                                   const struct gw_config *cfg)
{
    struct gw_authz az;
    char comma[64], dir[4096];
    struct gw_buf b;
    (void)cfg;
    memset(&b, 0, sizeof(b));
    if (!gw_steer_dir(dir, sizeof(dir)) ||
        !gw_authz_parse(h->query, dir, &az, comma, sizeof(comma))) {
        gw_oauth_error(fd, "invalid_request");
        return;
    }
    gw_buf_str(&b, "<!doctype html><html><head><meta name=\"viewport\" "
                   "content=\"width=device-width,initial-scale=1\">"
                   "<title>Z23 Fleet sign-in</title></head><body>"
                   "<h1>Z23 Fleet sign-in</h1><p>A client requests scopes: ");
    gw_html_escape(&b, az.scope);
    gw_buf_str(&b, "</p><p>It will be redirected to: ");
    gw_html_escape(&b, az.redirect);
    gw_buf_str(&b, "</p><form method=\"post\" action=\"/oauth/authorize\">"
                   "<input type=\"hidden\" name=\"response_type\" value=\"code\">"
                   "<input type=\"hidden\" name=\"client_id\" value=\"");
    gw_html_escape(&b, az.client);
    gw_buf_str(&b, "\"><input type=\"hidden\" name=\"redirect_uri\" value=\"");
    gw_html_escape(&b, az.redirect);
    gw_buf_str(&b, "\"><input type=\"hidden\" name=\"scope\" value=\"");
    gw_html_escape(&b, az.scope);
    gw_buf_str(&b, "\"><input type=\"hidden\" name=\"state\" value=\"");
    gw_html_escape(&b, az.state);
    gw_buf_str(&b, "\"><input type=\"hidden\" name=\"code_challenge\" value=\"");
    gw_html_escape(&b, az.challenge);
    gw_buf_str(&b, "\"><input type=\"hidden\" name=\"code_challenge_method\" "
                   "value=\"S256\">"
                   "<label>Owner key <input type=\"password\" name=\"owner_key\">"
                   "</label><button type=\"submit\" name=\"approve\" value=\"1\">"
                   "Approve</button></form></body></html>");
    if (!b.oom && b.p)
        gw_reply(fd, 200, "text/html", b.p, b.len);
    else
        gw_reply(fd, 500, "application/json", "{\"error\":\"server_error\"}",
                 24);
    gw_buf_free(&b);
}

/* Mint one scoped grant inside the node leaf (owner authority, local exec).
 * Returns the grant id and expiry, or false with the node refusing. */
static bool gw_oauth_mint(const char *node, const char *comma, char *gid,
                          size_t gidcap, long long *expires)
{
    struct gw_buf input;
    struct gw_node_out out;
    struct json_value env;
    const struct json_value *v;
    bool ok = false;
    memset(&input, 0, sizeof(input));
    gw_buf_str(&input, "{\"action\":\"mint\",\"scopes\":\"");
    gw_buf_str(&input, comma);
    /* Owner rule 2026-09-19: an approved connector never expires
     * (ttl 0 = expires 0). Revocation is how its access ends. */
    gw_buf_str(&input, "\",\"ttl_seconds\":0,\"label\":\"oauth\"}");
    if (input.oom || !input.p) {
        gw_buf_free(&input);
        return false;
    }
    out = gw_node_call(node, "grant", input.p);
    gw_buf_free(&input);
    if (!out.ok)
        return false;
    json_init(&env);
    if (!json_read(&env, out.text, out.len)) {
        json_free(&env);
        free(out.text);
        return false;
    }
    free(out.text);
    v = json_get(&env, "ok");
    if (v && v->type == JSON_BOOL && v->val.b) {
        const struct json_value *data = json_get(&env, "data");
        const struct json_value *id = data ? json_get(data, "id") : NULL;
        const struct json_value *ex = data ? json_get(data, "expires") : NULL;
        if (id && id->type == JSON_STR && strlen(json_get_str(id)) == 32 &&
            ex && ex->type == JSON_INT) {
            snprintf(gid, gidcap, "%s", json_get_str(id));
            *expires = (long long)json_get_int(ex);
            ok = true;
        }
    }
    json_free(&env);
    return ok;
}

/* POST /oauth/authorize (approval form) -> 302 with code, or 403. */
static void gw_oauth_authorize_post(int fd, const struct gw_http *h,
                                    const struct gw_config *cfg)
{
    struct gw_authz az;
    char comma[64], dir[4096];
    char key[128], loc[1100];
    char approve[8];
    const char *body = h->body ? h->body : "";
    if (!gw_steer_dir(dir, sizeof(dir)) ||
        !gw_authz_parse(body, dir, &az, comma, sizeof(comma)) ||
        !gw_form_get(body, "approve", approve, sizeof(approve)) ||
        strcmp(approve, "1") != 0) {
        gw_oauth_error(fd, "invalid_request");
        return;
    }
    /* Owner approval: the key is compared constant-time and never logged. */
    if (!cfg->owner_key[0] ||
        !gw_form_get(body, "owner_key", key, sizeof(key)) ||
        strlen(key) != strlen(cfg->owner_key) ||
        !gw_consteq(key, cfg->owner_key, strlen(cfg->owner_key))) {
        memset(key, 0, sizeof(key));
        gw_reply(fd, 403, "application/json",
                 "{\"error\":\"access_denied\"}", 25);
        return;
    }
    memset(key, 0, sizeof(key));
    if (!gw_authorize_issue(fd, cfg, dir, &az, comma, loc, sizeof(loc)))
        return;
    gw_reply_redirect(fd, loc);
}

/* Mint the grant, record the single-use code, render the redirect target.
 * False after answering 500. */
static bool gw_authorize_issue(int fd, const struct gw_config *cfg,
                               const char *dir, const struct gw_authz *az,
                               const char *comma, char *loc, size_t loccap)
{
    char code[GW_OAUTH_ID_HEX + 1];
    char gid[64], path[4096 + 64];
    char esc[512];
    long long now, gexp;
    FILE *f;
    if (!gw_oauth_mint(cfg->node, comma, gid, sizeof(gid), &gexp) ||
        !gw_rand_hex(code)) {
        gw_reply(fd, 500, "application/json",
                 "{\"error\":\"server_error\"}", 24);
        return false;
    }
    now = clock_now_wall_ms() / 1000LL;
    if (snprintf(path, sizeof(path), "%s/oauth_codes.jsonl", dir) < 0) {
        gw_reply(fd, 500, "application/json",
                 "{\"error\":\"server_error\"}", 24);
        return false;
    }
    f = fopen(path, "ab");
    if (!f) {
        gw_reply(fd, 500, "application/json",
                 "{\"error\":\"server_error\"}", 24);
        return false;
    }
    fprintf(f,
            "{\"code\":\"%s\",\"grant\":\"%s\",\"client\":\"%s\","
            "\"redirect\":\"%s\",\"challenge\":\"%s\",\"scopes\":\"%s\","
            "\"expires\":%lld,\"grant_expires\":%lld,\"used\":\"0\"}\n",
            code, gid, az->client, az->redirect, az->challenge, comma,
            now + GW_OAUTH_CODE_TTL, gexp);
    (void)fclose(f);
    gw_state_escape(az->state, esc, sizeof(esc));
    if (az->state[0])
        snprintf(loc, loccap, "%s?code=%s&state=%s", az->redirect, code, esc);
    else
        snprintf(loc, loccap, "%s?code=%s", az->redirect, code);
    return true;
}

/* Percent-encode one state value for the redirect query. */
static void gw_state_escape(const char *state, char *esc, size_t cap)
{
    size_t i, o = 0;
    for (i = 0; state[i] && o + 3 < cap; i++) {
        char c = state[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
            esc[o++] = c;
        } else {
            o += (size_t)snprintf(esc + o, cap - o, "%%%02X",
                                  (unsigned char)c);
        }
    }
    esc[o] = '\0';
}

/* Redeem one code: validate, single-use mark, hand out grant+scopes.
 * False after answering the typed error. */
static bool gw_token_redeem(int fd, const char *body, const char *dir,
                            char *grant, size_t grantcap, char *scopes,
                            size_t scopescap, long long *gexp)
{
    char code[80], redir[512], client[80], verifier[512];
    char cclient[80], credir[512], challenge[64], cscopes[64];
    char path[4096 + 64];
    long long expires, now;
    bool used;
    FILE *f;
    if (!gw_form_get(body, "code", code, sizeof(code)) ||
        !gw_form_get(body, "redirect_uri", redir, sizeof(redir)) ||
        !gw_form_get(body, "client_id", client, sizeof(client)) ||
        !gw_form_get(body, "code_verifier", verifier, sizeof(verifier)) ||
        !gw_code_find(dir, code, grant, grantcap, cclient, sizeof(cclient),
                      credir, sizeof(credir), challenge, sizeof(challenge),
                      cscopes, sizeof(cscopes), &expires, gexp, &used)) {
        gw_oauth_error(fd, "invalid_grant");
        return false;
    }
    now = clock_now_wall_ms() / 1000LL;
    if (used || now >= expires || strcmp(cclient, client) != 0 ||
        strcmp(credir, redir) != 0 || !gw_pkce_ok(verifier, challenge)) {
        gw_oauth_error(fd, "invalid_grant");
        return false;
    }
    if (snprintf(path, sizeof(path), "%s/oauth_codes.jsonl", dir) < 0) {
        gw_oauth_error(fd, "server_error");
        return false;
    }
    f = fopen(path, "ab");
    if (!f) {
        gw_oauth_error(fd, "server_error");
        return false;
    }
    /* Full-row use mark: last-wins keeps single-use exact. */
    fprintf(f,
            "{\"code\":\"%s\",\"grant\":\"%s\",\"client\":\"%s\","
            "\"redirect\":\"%s\",\"challenge\":\"%s\",\"scopes\":\"%s\","
            "\"expires\":%lld,\"grant_expires\":%lld,\"used\":\"1\"}\n",
            code, grant, cclient, credir, challenge, cscopes, expires, *gexp);
    (void)fclose(f);
    if (strlen(cscopes) >= scopescap) {
        gw_oauth_error(fd, "server_error");
        return false;
    }
    memcpy(scopes, cscopes, strlen(cscopes) + 1);
    return true;
}

/* POST /oauth/token (form) -> access token, or a typed OAuth error. */
static void gw_oauth_token(int fd, const struct gw_http *h,
                           const struct gw_config *cfg)
{
    char grant_type[32];
    char dir[4096];
    char grant[64], scopes[64];
    long long gexp, now;
    struct gw_buf b;
    const char *body = h->body ? h->body : "";
    (void)cfg;
    memset(&b, 0, sizeof(b));
    if (!gw_form_get(body, "grant_type", grant_type, sizeof(grant_type)) ||
        strcmp(grant_type, "authorization_code") != 0) {
        gw_oauth_error(fd, "unsupported_grant_type");
        return;
    }
    if (!gw_steer_dir(dir, sizeof(dir))) {
        gw_oauth_error(fd, "server_error");
        return;
    }
    if (!gw_token_redeem(fd, body, dir, grant, sizeof(grant), scopes,
                         sizeof(scopes), &gexp))
        return;
    now = clock_now_wall_ms() / 1000LL;
    gw_buf_str(&b, "{\"access_token\":\"");
    gw_buf_str(&b, grant);
    gw_buf_str(&b, "\",\"token_type\":\"Bearer\",\"scope\":\"");
    {
        /* Echo the authorized scopes in space-separated OAuth form. */
        size_t i;
        for (i = 0; scopes[i]; i++)
            gw_buf_put(&b, scopes[i] == ',' ? " " : scopes + i, 1);
    }
    gw_buf_str(&b, "\"");
    if (gexp > now) {
        char n[48];
        snprintf(n, sizeof(n), ",\"expires_in\":%lld", gexp - now);
        gw_buf_str(&b, n);
    }
    gw_buf_str(&b, "}");
    if (!b.oom && b.p)
        gw_reply(fd, 200, "application/json", b.p, b.len);
    else
        gw_reply(fd, 500, "application/json", "{\"error\":\"server_error\"}",
                 24);
    gw_buf_free(&b);
}

/* OAuth route table. True when the path+method is OAuth (handled). */
static bool gw_serve_oauth(int fd, const struct gw_http *h,
                           const struct gw_config *cfg)
{
    bool get = strcmp(h->method, "GET") == 0;
    bool post = strcmp(h->method, "POST") == 0;
    /* RFC 9728 3.1: clients probe the path-suffixed form first. */
    if (get &&
        (strcmp(h->path, "/.well-known/oauth-protected-resource") == 0 ||
         strcmp(h->path, "/.well-known/oauth-protected-resource/steer") ==
             0)) {
        gw_oauth_wellknown(fd, cfg, false);
        return true;
    }
    if (get &&
        strcmp(h->path, "/.well-known/oauth-authorization-server") == 0) {
        gw_oauth_wellknown(fd, cfg, true);
        return true;
    }
    if (post && strcmp(h->path, "/oauth/register") == 0) {
        gw_oauth_register(fd, h, cfg);
        return true;
    }
    if (get && strcmp(h->path, "/oauth/authorize") == 0) {
        gw_oauth_authorize_get(fd, h, cfg);
        return true;
    }
    if (post && strcmp(h->path, "/oauth/authorize") == 0) {
        gw_oauth_authorize_post(fd, h, cfg);
        return true;
    }
    if (post && strcmp(h->path, "/oauth/token") == 0) {
        gw_oauth_token(fd, h, cfg);
        return true;
    }
    return false;
}

/* ── HTTP replies ──────────────────────────────────────────────────────── */

static void gw_write_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0)
            return;
        p += w;
        n -= (size_t)w;
    }
}

static void gw_reply(int fd, int status, const char *ctype, const char *body,
                     size_t n)
{
    char head[256];
    int hlen = snprintf(head, sizeof(head),
                        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                        "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                        status, status == 200 ? "OK" : "Error",
                        ctype ? ctype : "application/json", n);
    if (hlen > 0 && (size_t)hlen < sizeof(head))
        gw_write_all(fd, head, (size_t)hlen);
    if (body && n > 0)
        gw_write_all(fd, body, n);
}

/* 401 + RFC 6750/9728 challenge around the typed JSON-RPC refusal. A
 * remote tool client starts OAuth only on a transport-level 401 naming the
 * protected-resource metadata; a 200 carrying the same error is shown to
 * the model as a failed call and no sign-in ever begins. The body is
 * unchanged, so callers reading -32001 keep working. */
static void gw_reply_challenge(int fd, const struct gw_config *cfg,
                               struct gw_buf *b)
{
    char issuer[300];
    struct gw_buf out;
    memset(&out, 0, sizeof(out));
    gw_oauth_issuer(cfg, issuer, sizeof(issuer));
    if (!b->oom && b->p) {
        char n[32];
        snprintf(n, sizeof(n), "%zu", b->len);
        gw_buf_str(&out, "HTTP/1.1 401 Unauthorized\r\n"
                         "WWW-Authenticate: Bearer error=\"invalid_token\", "
                         "error_description=\"grant required\", "
                         "resource_metadata=\"");
        gw_buf_str(&out, issuer);
        gw_buf_str(&out, "/.well-known/oauth-protected-resource\", "
                         "scope=\"brief send evidence\"\r\n"
                         "Content-Type: application/json\r\n"
                         "Content-Length: ");
        gw_buf_str(&out, n);
        gw_buf_str(&out, "\r\nConnection: close\r\n\r\n");
        gw_buf_put(&out, b->p, b->len);
    }
    if (!out.oom && out.p)
        gw_write_all(fd, out.p, out.len);
    else
        gw_reply(fd, 500, "application/json", "{\"error\":\"server_error\"}",
                 24);
    gw_buf_free(&out);
    gw_buf_free(b);
}

static void gw_reply_json(int fd, struct gw_buf *b)
{
    if (b->oom || !b->p) {
        const char *e = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":"
                        "{\"code\":-32603,\"message\":\"internal error\"}}";
        gw_reply(fd, 500, "application/json", e, strlen(e));
    } else {
        gw_reply(fd, 200, "application/json", b->p, b->len);
    }
    gw_buf_free(b);
}

/* Loopback only: a non-local peer is refused before parsing, and a
 * tool call without exactly one credential never reaches the node. */
static bool gw_peer_is_loopback(int fd)
{
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    struct sockaddr_in *v4;
    struct sockaddr_in6 *v6;
    memset(&ss, 0, sizeof(ss));
    if (getpeername(fd, (struct sockaddr *)&ss, &sl) != 0)
        return false;
    if (ss.ss_family == AF_INET) {
        v4 = (struct sockaddr_in *)&ss;
        return ntohl(v4->sin_addr.s_addr) == INADDR_LOOPBACK;
    }
    if (ss.ss_family == AF_INET6) {
        static const uint8_t loop[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0, 0, 0, 0, 1};
        v6 = (struct sockaddr_in6 *)&ss;
        return memcmp(&v6->sin6_addr, loop, 16) == 0;
    }
    return false;
}

/* Read one request into h, answering the failure itself: 500 when the
 * gateway could not hold the headers or the body, 400 when the request was
 * bad. True when h is ready to serve. */
static bool gw_serve_read(int fd, struct gw_http *h)
{
    char *hbuf = zcl_malloc(GW_CAP_HEADERS, "fleet-gateway/headers");
    bool ok;
    if (!hbuf) {
        gw_reply(fd, 500, "application/json", "{\"error\":\"no memory\"}",
                 20);
        return false;
    }
    ok = gw_http_read(fd, h, hbuf);
    free(hbuf);
    if (ok)
        return true;
    free(h->body);
    h->body = NULL;
    if (h->nomem)
        gw_reply(fd, 500, "application/json", "{\"error\":\"no memory\"}",
                 20);
    else
        gw_reply(fd, 400, "application/json",
                 "{\"error\":\"bad request\"}", 22);
    return false;
}

static void gw_serve(int fd, const struct gw_config *cfg)
{
    struct gw_http h;
    struct gw_buf body;
    memset(&h, 0, sizeof(h));
    if (!gw_peer_is_loopback(fd)) {
        gw_reply(fd, 403, "application/json", "{\"error\":\"loopback only\"}",
                 24);
        return;
    }
    if (!gw_serve_read(fd, &h))
        return;
    memset(&body, 0, sizeof(body));
    if (strcmp(h.method, "GET") == 0 && strcmp(h.path, "/healthz") == 0) {
        gw_buf_str(&body, "{\"ok\":true}");
        free(h.body);
        gw_reply_json(fd, &body);
        return;
    }
    if (gw_serve_oauth(fd, &h, cfg)) {
        free(h.body);
        gw_buf_free(&body);
        return;
    }
    if (strcmp(h.method, "POST") == 0 && strcmp(h.path, "/steer") == 0) {
        bool challenge = false;
        gw_dispatch_rpc(&body, h.body ? h.body : "", cfg->node,
                        h.auth_present ? h.auth : NULL, h.auth_bad,
                        &challenge);
        free(h.body);
        if (challenge) {
            gw_reply_challenge(fd, cfg, &body);
        } else if (body.len == 0 && !body.oom) {
            /* A notification: 202 with no body. */
            gw_reply(fd, 202, "application/json", "", 0);
            gw_buf_free(&body);
        } else {
            gw_reply_json(fd, &body);
        }
        return;
    }
    free(h.body);
    gw_buf_free(&body);
    if (strcmp(h.path, "/steer") == 0)
        gw_reply(fd, 405, "application/json",
                 "{\"error\":\"POST only\"}", 20);
    else
        gw_reply(fd, 404, "application/json", "{\"error\":\"not found\"}",
                 21);
}

/* ── listen + fork per connection ──────────────────────────────────────── */

static int gw_listen(const struct gw_config *cfg)
{
    struct sockaddr_in v4;
    int fd, port, one = 1;
    long p;
    memset(&v4, 0, sizeof(v4));
    p = strtol(cfg->port, NULL, 10);
    port = (p > 0 && p < 65536) ? (int)p : 0;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    v4.sin_family = AF_INET;
    v4.sin_port = htons((uint16_t)port);
    if (strcmp(cfg->bind, "127.0.0.1") != 0 &&
        strcmp(cfg->bind, "localhost") != 0) {
        /* G1 binds loopback only; anything else is a misconfiguration. */
        close(fd);
        return -1;
    }
    v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&v4, sizeof(v4)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, GW_BACKLOG) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int gw_bound_port(int fd)
{
    struct sockaddr_in v4;
    socklen_t sl = sizeof(v4);
    memset(&v4, 0, sizeof(v4));
    if (getsockname(fd, (struct sockaddr *)&v4, &sl) != 0)
        return -1;
    return (int)ntohs(v4.sin_port);
}

int main(int argc, char **argv)
{
#if defined(_WIN32)
    /* POSIX only: on Windows the single main refuses (the node itself
     * stays portable; the gateway does not claim it). */
    (void)argc;
    (void)argv;
    fputs("z23-fleet-gateway: loopback gateway is unavailable on Windows\n",
          stderr);
    return 2;
#else
    struct gw_config cfg;
    int fd, port;
    (void)argc;
    (void)argv;
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    gw_config(&cfg);
    fd = gw_listen(&cfg);
    if (fd < 0) {
        fputs("z23-fleet-gateway: cannot bind loopback\n", stderr);
        return 1;
    }
    port = gw_bound_port(fd);
    gw_bound_port_seen = port;
    printf("ready port=%d node=%s\n", port, cfg.node);
    fflush(stdout);
    for (;;) {
        int cfd = accept(fd, NULL, NULL);
        pid_t pid;
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        pid = fork();
        if (pid < 0) {
            close(cfd);
            continue;
        }
        if (pid == 0) {
            close(fd);
            /* The listener ignores SIGCHLD so connection children reap
             * themselves. A connection child must not inherit that: with it
             * ignored, waitpid on the node child fails with ECHILD and the
             * node's exit status is lost. */
            signal(SIGCHLD, SIG_DFL);
            gw_serve(cfd, &cfg);
            close(cfd);
            _exit(0);
        }
        close(cfd);
    }
    close(fd);
    return 0;
#endif
}
#endif /* _WIN32 */
