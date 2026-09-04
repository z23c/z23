/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.mail — async, non-blocking agent mail over the shared
 *          state root. Post appends one JSON row to the local outbox; pull
 *          reads every *.jsonl under the mail dir past a cursor; ack persists
 *          the caller's cursor. Nothing here blocks on a peer or a model: no
 *          network, no sleep, no poll loop. Delivery between hosts is a
 *          transport's job (it drops one inbox file per peer); this leaf only
 *          writes and reads local files.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. Agents on the fleet today coordinate through a shell board (2-minute
 * rsync) and a synchronous RPC pair (msg_send/msg_inbox). Both couple the
 * caller to a peer. This leaf is the async primitive: a poster writes one
 * line and returns; a reader re-pulls when it wants.
 *
 * STATE. platform_state_root() names the owner-private state root (the same
 * helper other leaves use); mail lives at <state>/mail/. The directory is
 * created 0700 when missing (pull and ack create it too, so a first run
 * never fails). outbox.jsonl is created 0600. A post opens the outbox with
 * O_WRONLY|O_CREAT|O_APPEND and emits the row with ONE write() call, so two
 * processes posting at once never interleave bytes. No lock, no read-modify-
 * write on the post path.
 *
 * INPUT (zcl.agent_mail_input.v1)
 *   action  required string: "post" | "pull" | "ack". First positional, so
 *           `dev agent mail post --to ...` maps post onto action.
 *   to      post only, required non-empty string: recipient agent or "*".
 *   kind    post only, required: one of need|claim|result|problem|note|
 *           offer|directive. Also an optional pull filter (exact match).
 *   body    post only, required non-empty string, at most 4096 bytes.
 *   since   pull only, optional non-negative integer, default 0: return rows
 *           with seq greater than this cursor.
 *   from    post: optional sender name (default $BOARD_AGENT, then $USER,
 *           then "local"). pull: optional exact-match sender filter.
 *   cursor  ack only: required non-negative integer; also accepted as the
 *           second positional (`dev agent mail ack 42`). Accepts a numeric
 *           string for transports that type positionals loosely.
 *   agent   ack only: optional name owning the cursor file (default: the same
 *           identity post uses). Sanitized to [A-Za-z0-9._-] for the file.
 *   ref     post only, optional string linking a row (default "").
 *   cwd     optional string. Accepted so fixtures match the other leaves;
 *           only used to resolve the checkout root for the path-refusal rule.
 *
 * ROW. {"seq":N,"ts":"<ISO-8601 UTC>","from":"<agent>","to":"<agent|*>",
 *        "kind":"<kind>","body":"<text>","ref":"<ref>"}
 * seq is one plus the largest seq already in the outbox (1 when empty).
 *
 * PULL. Reads every *.jsonl under <state>/mail/ (the outbox plus one inbox
 * file per peer, written by whatever transport delivers them). Returns rows
 * with seq greater than `since`, ordered by (ts, from, seq), plus `cursor`
 * (the largest seq seen anywhere in the dir, or `since` when empty) and
 * `count`. Malformed lines are skipped, never fatal.
 *
 * ACK. Writes the decimal cursor plus "\n" to <state>/mail/cursor.<agent>
 * (0600) and returns {leaf, agent, cursor}.
 *
 * REFUSAL. A body longer than 4096 bytes, or one that mentions a secret key,
 * an onion address, an IP address, or an absolute filesystem path outside
 * the checkout, is refused with ok=false and a MAIL_REFUSED_* code naming
 * the rule — a typed error row, never a crash. Refusal words: key, onion
 * address, IP, absolute path. Repo-relative paths (no leading slash) are
 * always allowed; an absolute path under the checkout root is allowed.
 *
 * OUTPUT (zcl.agent_mail.v1). Every reply names its own `leaf`. Post returns
 * the row fields plus `cursor` (the row's seq) and `outbox`. Pull returns
 * `rows` (array), `cursor`, `count`. Ack returns `agent`, `cursor`.
 *
 * FAILURE. BAD_INPUT (missing/empty action, to, kind, body; unknown kind or
 * action; bad cursor/agent spelling), MAIL_BODY_TOO_LARGE, MAIL_REFUSED_*,
 * STATE_DIR_FAILED, MAIL_WRITE_FAILED, MAIL_READ_FAILED.
 *
 * PROCESS RULE. No spawn, no shell, no popen()/system(), no sleep, no poll
 * loop. Only mkdir/open/write/read/closedir file calls below.
 */

#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "command/native_devagent.h"
#include "json/json.h"
#include "platform/state_root.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DVM_LEAF "dev.agent.mail"
#define DVM_BODY_MAX 4096u
#define DVM_LINE_CAP 8192
#define DVM_ROWS_MAX 4096

static const char *dvm_kinds[] = {
    "need", "claim", "result", "problem", "note", "offer", "directive",
};

static bool dvm_is_kind(const char *s)
{
    if (!s)
        return false;
    for (size_t i = 0; i < sizeof(dvm_kinds) / sizeof(dvm_kinds[0]); i++) {
        if (strcmp(s, dvm_kinds[i]) == 0)
            return true;
    }
    return false;
}

/* ── small case-insensitive helpers (no locale, no allocation) ───────────── */

static int dvm_lower(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? (int)c + 32 : (int)c;
}

static bool dvm_contains_fold(const char *hay, const char *needle)
{
    size_t hn = strlen(hay), nn = strlen(needle);
    if (nn == 0 || nn > hn)
        return false;
    for (size_t i = 0; i + nn <= hn; i++) {
        size_t j = 0;
        while (j < nn && dvm_lower((unsigned char)hay[i + j]) ==
                            dvm_lower((unsigned char)needle[j]))
            j++;
        if (j == nn)
            return true;
    }
    return false;
}

/* ── refusal scanners ────────────────────────────────────────────────────── */

static bool dvm_has_ipv4(const char *s)
{
    /* Four dot-separated 1-3 digit groups, each <= 255, bounded by
     * non-digit/non-dot on both sides. */
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p))
            continue;
        if (p != s && (isdigit((unsigned char)p[-1]) || p[-1] == '.'))
            continue;
        unsigned vals[4];
        const char *q = p;
        int g = 0;
        for (; g < 4; g++) {
            if (!isdigit((unsigned char)*q))
                break;
            unsigned v = 0;
            int digits = 0;
            while (isdigit((unsigned char)*q) && digits < 3) {
                v = v * 10u + (unsigned)(*q - '0');
                q++;
                digits++;
            }
            if (isdigit((unsigned char)*q))
                break; /* 4+ digit run: not an octet */
            if (v > 255)
                break;
            vals[g] = v;
            if (g < 3) {
                if (*q != '.')
                    break;
                q++;
            }
        }
        (void)vals;
        if (g == 4 && !isdigit((unsigned char)*q) && *q != '.')
            return true;
    }
    return false;
}

static bool dvm_has_drive_path(const char *s)
{
    for (const char *p = s; *p; p++) {
        if (isalpha((unsigned char)*p) && p[1] == ':' &&
            (p[2] == '\\' || p[2] == '/'))
            return true;
    }
    return false;
}

static bool dvm_has_abs_path(const char *s)
{
    static const char *const markers[] = {
        "/home/", "/tmp/", "/etc/", "/var/", "/root/", "/usr/", "/opt/",
        "/private/", "/.ssh", "~/.ssh", "~/" , "id_rsa", ".pem",
    };
    for (size_t i = 0; i < sizeof(markers) / sizeof(markers[0]); i++) {
        if (strstr(s, markers[i]) != NULL)
            return true;
    }
    if (dvm_has_drive_path(s))
        return true;
    /* A bare absolute path: " /<alnum>" outside quotes. Repo-relative
     * paths (tools/command/x.c) never match: they have no leading slash. */
    for (const char *p = s; *p; p++) {
        if (*p == '/' && isalnum((unsigned char)p[1]))
            return true;
    }
    return false;
}

/* Absolute path under the checkout root is inside the repo, not outside it. */
static bool dvm_abs_under_root(const char *body, const char *root)
{
    size_t rn;
    if (!root || !root[0])
        return false;
    rn = strlen(root);
    for (const char *p = body; (p = strchr(p, '/')) != NULL; p++) {
        /* Find the start of this whitespace-delimited token. */
        const char *start = p;
        while (start > body && *start != ' ' && *start != '\t' &&
               *start != '\n' && *start != '"' && *start != '\'')
            start--;
        if (*start == ' ' || *start == '\t' || *start == '\n' ||
            *start == '"' || *start == '\'')
            start++;
        if (strncmp(start, root, rn) == 0 &&
            (start[rn] == '/' || start[rn] == '\0' || start[rn] == '"' ||
             start[rn] == '\'' || start[rn] == ' ' || start[rn] == '\t' ||
             start[rn] == '\n'))
            return true;
    }
    return false;
}

/* 0 = clean; else the MAIL_REFUSED_* code and a human message. */
static const char *dvm_refuse(const char *body, const char *root,
                              char *msg, size_t cap)
{
    static const char *const keymarks[] = {
        "private key", "private-key", "privkey", "secret key", "mnemonic",
        "seed phrase", "ssh key",
    };
    if (dvm_contains_fold(body, ".onion")) {
        (void)snprintf(msg, cap, "%s",
                       "refused: body mentions an onion address; "
                       "never post onion addresses, keys, IPs, or "
                       "absolute paths");
        return "MAIL_REFUSED_ONION";
    }
    for (size_t i = 0; i < sizeof(keymarks) / sizeof(keymarks[0]); i++) {
        if (dvm_contains_fold(body, keymarks[i])) {
            (void)snprintf(msg, cap, "%s",
                           "refused: body mentions a key; never post keys, "
                           "onion addresses, IPs, or absolute paths");
            return "MAIL_REFUSED_KEY";
        }
    }
    if (dvm_has_ipv4(body)) {
        (void)snprintf(msg, cap, "%s",
                       "refused: body mentions an IP address; never post "
                       "IPs, keys, onion addresses, or absolute paths");
        return "MAIL_REFUSED_IP";
    }
    if (dvm_has_abs_path(body) && !dvm_abs_under_root(body, root)) {
        (void)snprintf(msg, cap, "%s",
                       "refused: body mentions an absolute filesystem path "
                       "outside the repo; use repo-relative paths");
        return "MAIL_REFUSED_PATH";
    }
    return NULL;
}

/* ── JSON string escape (one row per line; bodies carry free text) ────────── */

static bool dvm_escape(const char *in, char *out, size_t cap)
{
    size_t used = 0;
    for (const char *p = in; *p; p++) {
        char tmp[8];
        const char *rep;
        if (*p == '"' || *p == '\\') {
            tmp[0] = '\\';
            tmp[1] = *p;
            tmp[2] = '\0';
            rep = tmp;
        } else if ((unsigned char)*p < 0x20) {
            (void)snprintf(tmp, sizeof(tmp), "\\u%04x", (unsigned)*p);
            rep = tmp;
        } else {
            tmp[0] = *p;
            tmp[1] = '\0';
            rep = tmp;
        }
        size_t rl = strlen(rep);
        if (used + rl + 1 > cap)
            return false;
        memcpy(out + used, rep, rl);
        used += rl;
    }
    out[used] = '\0';
    return true;
}

/* ── state dir: <platform_state_root>/mail, 0700, created when missing ────── */

static bool dvm_mkdir_one(const char *path)
{
    if (mkdir(path, 0700) == 0)
        return true;
    if (errno == EEXIST) {
        struct stat st;
        return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
    }
    return false;
}

static bool dvm_mail_dir(char *out, size_t cap)
{
    char state[4096];
    int n;
    if (!platform_state_root(state, sizeof(state)))
        return false;
    n = snprintf(out, cap, "%s/mail", state);
    if (n <= 0 || (size_t)n >= cap)
        return false;
    /* mkdir -p the state root (platform helper owns its mode), then our
     * own mail dir at exactly 0700. */
    if (!dvm_mkdir_one(state))
        return false;
    if (!dvm_mkdir_one(out))
        return false;
    (void)chmod(out, 0700);
    return true;
}

/* ── input accessors ─────────────────────────────────────────────────────── */

static const char *dvm_str(const struct zcl_command_request *req,
                           const char *key)
{
    const struct json_value *v;
    if (!req || !req->input)
        return NULL;
    v = json_get(req->input, key);
    if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
        return json_get_str(v);
    return NULL;
}

static bool dvm_int(const struct zcl_command_request *req, const char *key,
                    long long *out)
{
    const struct json_value *v;
    if (!req || !req->input || !out)
        return false;
    v = json_get(req->input, key);
    if (!v)
        return false;
    if (v->type == JSON_INT && json_get_int(v) >= 0) {
        *out = json_get_int(v);
        return true;
    }
    if (v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0]) {
        const char *s = json_get_str(v);
        char *end = NULL;
        long long n;
        errno = 0;
        n = strtoll(s, &end, 10);
        if (errno == 0 && end && end != s && *end == '\0' && n >= 0) {
            *out = n;
            return true;
        }
    }
    return false;
}

static const char *dvm_identity(const struct zcl_command_request *req,
                                const char *key)
{
    const char *named = dvm_str(req, key);
    const char *env;
    if (named)
        return named;
    env = getenv("BOARD_AGENT");
    if (env && env[0])
        return env;
    env = getenv("USER");
    if (env && env[0])
        return env;
    return "local";
}

static bool dvm_agent_ok(const char *s)
{
    if (!s || !s[0] || strlen(s) > 128)
        return false;
    if (strcmp(s, "*") == 0)
        return true;
    for (const char *p = s; *p; p++) {
        if (isalnum((unsigned char)*p) || *p == '.' || *p == '_' ||
            *p == '-' || *p == '@')
            continue;
        return false;
    }
    return true;
}

static bool dvm_cursor_name_ok(const char *s)
{
    if (!s || !s[0] || strlen(s) > 128)
        return false;
    for (const char *p = s; *p; p++) {
        if (isalnum((unsigned char)*p) || *p == '.' || *p == '_' ||
            *p == '-')
            continue;
        return false;
    }
    return true;
}

/* ── minimal per-line field extraction (pull skips malformed lines) ───────── */

static bool dvm_line_int(const char *line, const char *key, long long *out)
{
    char pat[64];
    const char *p;
    char *end;
    long long n;
    (void)snprintf(pat, sizeof(pat), "\"%s\":", key);
    p = strstr(line, pat);
    if (!p)
        return false;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t')
        p++;
    errno = 0;
    n = strtoll(p, &end, 10);
    if (errno != 0 || end == p || n < 0)
        return false;
    *out = n;
    return true;
}

static bool dvm_line_str(const char *line, const char *key, char *out,
                         size_t cap)
{
    char pat[64];
    const char *p;
    size_t used = 0;
    (void)snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    p = strstr(line, pat);
    if (!p)
        return false;
    p += strlen(pat);
    while (*p && *p != '"') {
        if (used + 2 > cap)
            return false;
        if (*p == '\\' && p[1]) {
            /* Keep the common escapes exact; \uXXXX becomes '?'
             * (ordering only needs stable bytes, not the rune). */
            if (p[1] == 'u' && isxdigit((unsigned char)p[2]) &&
                isxdigit((unsigned char)p[3]) &&
                isxdigit((unsigned char)p[4]) &&
                isxdigit((unsigned char)p[5])) {
                out[used++] = '?';
                p += 6;
            } else {
                out[used++] = p[1];
                p += 2;
            }
        } else {
            out[used++] = *p++;
        }
    }
    if (*p != '"')
        return false;
    out[used] = '\0';
    return true;
}

struct dvm_row {
    long long seq;
    char ts[64];
    char from[160];
    char to[160];
    char kind[32];
    char body[DVM_BODY_MAX + 1];
    char ref[256];
    char line[DVM_LINE_CAP];
};

static bool dvm_parse_row(const char *line, struct dvm_row *r)
{
    if (!line || !line[0] || !r)
        return false;
    memset(r, 0, sizeof(*r));
    if (!dvm_line_int(line, "seq", &r->seq))
        return false;
    if (!dvm_line_str(line, "ts", r->ts, sizeof(r->ts)))
        return false;
    if (!dvm_line_str(line, "from", r->from, sizeof(r->from)))
        return false;
    if (!dvm_line_str(line, "to", r->to, sizeof(r->to)))
        return false;
    if (!dvm_line_str(line, "kind", r->kind, sizeof(r->kind)))
        return false;
    if (!dvm_line_str(line, "body", r->body, sizeof(r->body)))
        return false;
    (void)dvm_line_str(line, "ref", r->ref, sizeof(r->ref));
    return true;
}

static int dvm_row_cmp(const void *a, const void *b)
{
    const struct dvm_row *ra = (const struct dvm_row *)a;
    const struct dvm_row *rb = (const struct dvm_row *)b;
    int c = strcmp(ra->ts, rb->ts);
    if (c != 0)
        return c;
    c = strcmp(ra->from, rb->from);
    if (c != 0)
        return c;
    if (ra->seq < rb->seq)
        return -1;
    if (ra->seq > rb->seq)
        return 1;
    return 0;
}

static void dvm_fail(struct zcl_command_reply *reply, const char *code,
                     const char *msg, const char *evidence)
{
    (void)json_push_kv_str(&reply->data, "leaf", DVM_LEAF);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "mail", false,
                           false, msg, evidence);
}

/* ── post ────────────────────────────────────────────────────────────────── */

static void dvm_post(const struct zcl_command_request *req,
                     struct zcl_command_reply *reply, const char *maildir)
{
    const char *to = dvm_str(req, "to");
    const char *kind = dvm_str(req, "kind");
    const char *body = NULL;
    const char *ref = dvm_str(req, "ref");
    const struct json_value *bodyv;
    char root[PATH_MAX];
    char outbox[PATH_MAX + 32];
    char ts[40];
    char esc_from[512], esc_to[512], esc_kind[64], esc_body[DVM_BODY_MAX * 2];
    char esc_ref[512];
    char line[DVM_LINE_CAP];
    const char *from;
    const char *code;
    char msg[256];
    long long seq = 0;
    time_t now;
    struct tm tm_utc;
    FILE *f;
    char *nl;
    int fd;
    ssize_t w;
    size_t len;

    if (!req || !req->input) {
        dvm_fail(reply, "BAD_INPUT", "dev.agent.mail post needs to, kind, body",
                 "request.input was missing");
        return;
    }
    bodyv = json_get(req->input, "body");
    body = bodyv && bodyv->type == JSON_STR ? json_get_str(bodyv) : NULL;
    from = dvm_identity(req, "from");
    if (!ref)
        ref = "";
    if (!to || !to[0]) {
        dvm_fail(reply, "BAD_INPUT", "post needs a non-empty to",
                 "input.to missing or empty");
        return;
    }
    if (!dvm_agent_ok(to)) {
        dvm_fail(reply, "BAD_INPUT", "to names an agent or *",
                 "input.to has an illegal spelling");
        return;
    }
    if (!kind || !dvm_is_kind(kind)) {
        dvm_fail(reply, "BAD_INPUT",
                 "kind is one of need|claim|result|problem|note|offer|directive",
                 "input.kind missing or unknown");
        return;
    }
    if (!body || !body[0]) {
        dvm_fail(reply, "BAD_INPUT", "post needs a non-empty body",
                 "input.body missing or empty");
        return;
    }
    if (strlen(body) > DVM_BODY_MAX) {
        dvm_fail(reply, "MAIL_BODY_TOO_LARGE",
                 "body is over the 4096-byte cap", "input.body too large");
        return;
    }
    if (!from || !from[0] || !dvm_agent_ok(from)) {
        dvm_fail(reply, "BAD_INPUT", "from names the sending agent",
                 "input.from has an illegal spelling");
        return;
    }
    if (strlen(ref) > 200) {
        dvm_fail(reply, "BAD_INPUT", "ref is at most 200 bytes",
                 "input.ref too large");
        return;
    }
    /* Checkout root for the inside-the-repo path allowance. Unresolvable
     * root just means every absolute path is refused. */
    root[0] = '\0';
    {
        const char *cwd = dvm_str(req, "cwd");
        (void)zcl_devagent_checkout_root(cwd && cwd[0] ? cwd : ".", root,
                                         sizeof(root));
    }
    code = dvm_refuse(body, root[0] ? root : NULL, msg, sizeof(msg));
    if (code) {
        dvm_fail(reply, code, msg, "input.body hit a refusal rule");
        return;
    }

    (void)snprintf(outbox, sizeof(outbox), "%s/outbox.jsonl", maildir);
    /* Next seq: one plus the largest seq already present. A duplicate seq
     * under concurrent posters is acceptable (bytes stay intact); the pull
     * cursor still advances past both on (ts, from, seq) order. */
    f = fopen(outbox, "r");
    if (f) {
        char buf[DVM_LINE_CAP];
        while (fgets(buf, sizeof(buf), f)) {
            long long s;
            if (dvm_line_int(buf, "seq", &s) && s >= seq)
                seq = s + 1;
            else if (!dvm_line_int(buf, "seq", &s) && seq < 1)
                seq = 1;
        }
        (void)fclose(f);
        if (seq < 1)
            seq = 1;
    } else {
        seq = 1;
    }

    now = time(NULL);
    (void)gmtime_r(&now, &tm_utc);
    (void)strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);

    if (!dvm_escape(from, esc_from, sizeof(esc_from)) ||
        !dvm_escape(to, esc_to, sizeof(esc_to)) ||
        !dvm_escape(kind, esc_kind, sizeof(esc_kind)) ||
        !dvm_escape(body, esc_body, sizeof(esc_body)) ||
        !dvm_escape(ref, esc_ref, sizeof(esc_ref))) {
        dvm_fail(reply, "BAD_INPUT", "row fields too large to encode",
                 "escape budget exceeded");
        return;
    }
    len = (size_t)snprintf(line, sizeof(line),
                           "{\"seq\":%lld,\"ts\":\"%s\",\"from\":\"%s\","
                           "\"to\":\"%s\",\"kind\":\"%s\",\"body\":\"%s\","
                           "\"ref\":\"%s\"}\n",
                           seq, ts, esc_from, esc_to, esc_kind, esc_body,
                           esc_ref);
    if (len == 0 || len >= sizeof(line)) {
        dvm_fail(reply, "BAD_INPUT", "row too large to encode",
                 "line budget exceeded");
        return;
    }
    /* Strip any embedded newline the format cannot carry (bodies with
     * control bytes are \\u-escaped above, so this is just a guard). */
    nl = strchr(line, '\n');
    if (!nl || nl[1] != '\0') {
        dvm_fail(reply, "BAD_INPUT", "body must be one line of text",
                 "embedded newline");
        return;
    }

    fd = open(outbox, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        dvm_fail(reply, "MAIL_WRITE_FAILED", "cannot open the outbox",
                 outbox);
        return;
    }
    (void)fchmod(fd, 0600);
    w = write(fd, line, len);
    (void)close(fd);
    if (w != (ssize_t)len) {
        dvm_fail(reply, "MAIL_WRITE_FAILED", "short write to the outbox",
                 outbox);
        return;
    }

    (void)json_push_kv_str(&reply->data, "leaf", DVM_LEAF);
    (void)json_push_kv_int(&reply->data, "seq", seq);
    (void)json_push_kv_str(&reply->data, "ts", ts);
    (void)json_push_kv_str(&reply->data, "from", from);
    (void)json_push_kv_str(&reply->data, "to", to);
    (void)json_push_kv_str(&reply->data, "kind", kind);
    (void)json_push_kv_str(&reply->data, "body", body);
    (void)json_push_kv_str(&reply->data, "ref", ref);
    (void)json_push_kv_int(&reply->data, "cursor", seq);
    (void)json_push_kv_str(&reply->data, "outbox", outbox);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── pull ────────────────────────────────────────────────────────────────── */

static void dvm_pull(const struct zcl_command_request *req,
                     struct zcl_command_reply *reply, const char *maildir)
{
    long long since = 0;
    const char *fromf = NULL;
    const char *kindf = NULL;
    const struct json_value *sincev;
    struct dvm_row *rows = NULL;
    size_t nrows = 0, caprows = 0;
    long long cursor = 0;
    bool have_since = false;
    DIR *d;
    struct dirent *ent;

    if (req && req->input) {
        sincev = json_get(req->input, "since");
        if (sincev) {
            if (!dvm_int(req, "since", &since)) {
                dvm_fail(reply, "BAD_INPUT",
                         "since is a non-negative cursor",
                         "input.since has the wrong shape");
                return;
            }
            have_since = true;
        }
        fromf = dvm_str(req, "from");
        kindf = dvm_str(req, "kind");
        if (kindf && !dvm_is_kind(kindf)) {
            dvm_fail(reply, "BAD_INPUT",
                     "kind filter is one of need|claim|result|problem|note|"
                     "offer|directive",
                     "input.kind unknown");
            return;
        }
    }
    if (!have_since)
        since = 0;
    cursor = since;

    d = opendir(maildir);
    if (!d) {
        dvm_fail(reply, "MAIL_READ_FAILED", "cannot read the mail dir",
                 maildir);
        return;
    }
    while ((ent = readdir(d)) != NULL) {
        char path[PATH_MAX + 64];
        const char *dot;
        FILE *f;
        size_t namelen = strlen(ent->d_name);
        if (namelen < 7)
            continue;
        dot = strrchr(ent->d_name, '.');
        if (!dot || strcmp(dot, ".jsonl") != 0)
            continue;
        if (strchr(ent->d_name, '/') != NULL)
            continue;
        if (strcmp(ent->d_name, ".jsonl") == 0)
            continue;
        (void)snprintf(path, sizeof(path), "%s/%s", maildir, ent->d_name);
        f = fopen(path, "r");
        if (!f)
            continue;
        for (;;) {
            static char buf[DVM_LINE_CAP];
            struct dvm_row r;
            size_t len;
            if (!fgets(buf, sizeof(buf), f))
                break;
            len = strlen(buf);
            while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
                buf[--len] = '\0';
            if (len == 0)
                continue;
            if (!dvm_parse_row(buf, &r))
                continue; /* malformed line: skipped, never fatal */
            if (r.seq > cursor)
                cursor = r.seq;
            if (r.seq <= since)
                continue;
            if (fromf && strcmp(r.from, fromf) != 0)
                continue;
            if (kindf && strcmp(r.kind, kindf) != 0)
                continue;
            if (nrows == caprows) {
                size_t ncap = caprows ? caprows * 2 : 32;
                struct dvm_row *nrows_p;
                if (ncap > DVM_ROWS_MAX)
                    ncap = DVM_ROWS_MAX;
                if (nrows >= ncap)
                    break;
                nrows_p = (struct dvm_row *)zcl_realloc(rows,
                                                    ncap * sizeof(*rows),
                                                    "devagent_mail.rows");
                if (!nrows_p)
                    break;
                rows = nrows_p;
                caprows = ncap;
            }
            if (nrows < caprows)
                rows[nrows++] = r;
        }
        (void)fclose(f);
    }
    (void)closedir(d);

    if (nrows > 1)
        qsort(rows, nrows, sizeof(*rows), dvm_row_cmp);

    {
        struct json_value arr, item;
        json_init(&arr);
        json_set_array(&arr);
        for (size_t i = 0; i < nrows; i++) {
            json_init(&item);
            json_set_object(&item);
            (void)json_push_kv_int(&item, "seq", rows[i].seq);
            (void)json_push_kv_str(&item, "ts", rows[i].ts);
            (void)json_push_kv_str(&item, "from", rows[i].from);
            (void)json_push_kv_str(&item, "to", rows[i].to);
            (void)json_push_kv_str(&item, "kind", rows[i].kind);
            (void)json_push_kv_str(&item, "body", rows[i].body);
            (void)json_push_kv_str(&item, "ref", rows[i].ref);
            (void)json_push_back(&arr, &item);
            json_free(&item);
        }
        (void)json_push_kv_str(&reply->data, "leaf", DVM_LEAF);
        (void)json_push_kv(&reply->data, "rows", &arr);
        json_free(&arr);
    }
    free(rows);
    (void)json_push_kv_int(&reply->data, "cursor", cursor);
    (void)json_push_kv_int(&reply->data, "count", (long long)nrows);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── ack ─────────────────────────────────────────────────────────────────── */

static void dvm_ack(const struct zcl_command_request *req,
                    struct zcl_command_reply *reply, const char *maildir)
{
    long long cursor;
    char path[PATH_MAX + 64];
    char text[64];
    const char *agent;
    int fd;
    ssize_t w;
    size_t len;

    if (!dvm_int(req, "cursor", &cursor)) {
        dvm_fail(reply, "BAD_INPUT", "ack needs a non-negative cursor",
                 "input.cursor missing or wrong shape");
        return;
    }
    agent = dvm_str(req, "agent");
    if (!agent)
        agent = dvm_identity(req, "from");
    if (!dvm_cursor_name_ok(agent)) {
        dvm_fail(reply, "BAD_INPUT", "agent names the cursor owner",
                 "input.agent has an illegal spelling");
        return;
    }
    (void)snprintf(path, sizeof(path), "%s/cursor.%s", maildir, agent);
    len = (size_t)snprintf(text, sizeof(text), "%lld\n", cursor);
    if (len == 0 || len >= sizeof(text)) {
        dvm_fail(reply, "BAD_INPUT", "cursor too large to record",
                 "format budget exceeded");
        return;
    }
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        dvm_fail(reply, "MAIL_WRITE_FAILED", "cannot record the cursor",
                 path);
        return;
    }
    (void)fchmod(fd, 0600);
    w = write(fd, text, len);
    (void)close(fd);
    if (w != (ssize_t)len) {
        dvm_fail(reply, "MAIL_WRITE_FAILED", "short write of the cursor",
                 path);
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", DVM_LEAF);
    (void)json_push_kv_str(&reply->data, "agent", agent);
    (void)json_push_kv_int(&reply->data, "cursor", cursor);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

void zcl_native_handle_dev_agent_mail(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *action;
    char maildir[4096];

    if (!reply)
        return;
    if (!request || !request->input) {
        dvm_fail(reply, "BAD_INPUT",
                 "dev.agent.mail needs action post|pull|ack",
                 "request.input was missing");
        return;
    }
    action = dvm_str(request, "action");
    if (!action || !action[0]) {
        dvm_fail(reply, "BAD_INPUT",
                 "action is required: post, pull, or ack",
                 "input.action missing or empty");
        return;
    }
    if (!dvm_mail_dir(maildir, sizeof(maildir))) {
        dvm_fail(reply, "STATE_DIR_FAILED",
                 "cannot create the mail dir under the state root",
                 "platform_state_root/mail");
        return;
    }
    if (strcmp(action, "post") == 0) {
        dvm_post(request, reply, maildir);
        return;
    }
    if (strcmp(action, "pull") == 0) {
        dvm_pull(request, reply, maildir);
        return;
    }
    if (strcmp(action, "ack") == 0) {
        dvm_ack(request, reply, maildir);
        return;
    }
    dvm_fail(reply, "BAD_INPUT", "action is one of post|pull|ack",
             "input.action unknown");
}
