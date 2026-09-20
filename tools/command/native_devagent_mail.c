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
 * never fails). outbox.jsonl is private to its owner. On POSIX a post opens
 * it with O_WRONLY|O_CREAT|O_APPEND and emits the row with ONE write() call.
 * Windows uses an owner-validated private handle and a nonblocking file lock
 * around the size/write pair, refusing contention without waiting. Both
 * paths preserve complete row bytes without interleaving concurrent writes.
 *
 * INPUT (zcl.agent_mail_input.v1)
 *   action  required string: "post" | "pull" | "ack". First positional, so
 *           `dev agent mail post --to ...` maps post onto action.
 *   to      post only, required non-empty string: recipient agent or "*".
 *   kind    post only, required: one of need|claim|result|problem|note|
 *           offer|directive. Also an optional pull filter (exact match).
 *   body    post only, required non-empty string, at most 4096 bytes.
 *   since   pull only, optional, default 0. Either a non-negative integer:
 *           return rows with seq greater than this cursor (a positive
 *           scalar refuses when multiple .jsonl streams make its sequence
 *           space ambiguous); or the `next_since` token a previous page
 *           returned, which resumes exactly where that page stopped.
 *   from    post: optional sender name (default $BOARD_AGENT, then $USER,
 *           then "local"). pull: optional exact-match sender filter.
 *   cursor  ack only: required. A non-negative integer (also as the second
 *           positional, `dev agent mail ack 42`, or a numeric string for
 *           transports that type positionals loosely), or a next_since
 *           token, which is the only cursor that resumes a multi-stream
 *           mail dir.
 *   agent   ack: optional name owning the cursor file (default: the same
 *           identity post uses). pull: when given WITHOUT since, the page
 *           resumes from that agent's acked cursor (from the start when it
 *           never acked), so a reader keeps one position across restarts
 *           instead of re-walking the whole history. [A-Za-z0-9._-] only.
 *   to      pull: optional exact-match recipient filter.
 *   ref     post: optional string linking a row (default ""). pull:
 *           optional exact-match filter, so one conversation is one page
 *           rather than a walk over every row in the dir.
 *   sender_binding
 *           post only, optional: 32 lowercase hex stamping WHICH credential
 *           sent this row, written beside `from`. This leaf does not mint,
 *           interpret or verify it — it carries it, because `from` alone is
 *           a claim and a reader that dispatches work needs something the
 *           sender could only have produced by holding its own credential.
 *           fleet.steer.send derives it from the grant that carried the
 *           request; dev.agent.receive checks it against the grant store
 *           before admitting a directive. An absent or empty value writes
 *           no field at all, which reads back as an unattributable row.
 *           Never a secret: a binding is a one-way digest, never the grant
 *           id, so it is safe in a row that crosses hosts.
 *   cwd     optional string. Accepted and ignored, so fixtures match the
 *           other leaves. NOTHING in this leaf consults it: a mail body
 *           crosses hosts, so the verdict on a body must not move with the
 *           directory the process happens to run in.
 *
 * ROW. {"seq":N,"ts":"<ISO-8601 UTC>","from":"<agent>","to":"<agent|*>",
 *        "kind":"<kind>","body":"<text>","ref":"<ref>"} plus
 *        "sender_binding":"<32 hex>" when the poster stamped one.
 * A transport that carried the row over the signed fleet board appends
 * "board_post":"<64 hex post id>","board_signer":"<64 hex host key>" after
 * the original fields. This leaf never writes those two (post has no input
 * for them) and never judges them: pull returns both, "" when absent or
 * longer than 64 bytes, and dev.agent.receive admits such a row only after
 * the local node's board confirms that exact post, text and signer.
 * seq is one plus the largest seq already in the outbox (1 when empty).
 * A body round-trips byte for byte, newlines included: the row writes the
 * two-character JSON escapes for newline, carriage return, tab, backspace
 * and form feed, and the row reader decodes them plus any six-character
 * u-escape below 0x80 that an older row used. Before that a newline was
 * written as a u-escape and read back as '?', which silently destroyed
 * every multi-line body — the machine header a reader needs most.
 *
 * PULL. Reads every *.jsonl under <state>/mail/ (the outbox plus one inbox
 * file per peer, written by whatever transport delivers them). Returns rows
 * with seq greater than the seq floor, ordered by (ts, from, seq), plus
 * `cursor` (the largest seq seen anywhere in the dir, or the floor when
 * empty) and `count`. Malformed lines are skipped, never fatal, and counted
 * in `skipped`.
 *
 * PAGING. A reply is ONE bounded page: at most 64 rows and about 16 KiB of
 * row bytes (the first row always fits, so a page is never empty while rows
 * remain), which keeps every reply inside the leaf's response budget no
 * matter how long the history grows. `truncated` is true when rows remain
 * past the page, and `next_since` is ALWAYS returned: pass it back as
 * `since` (with the same from/kind filters) to get the next page, and keep
 * it to resume later. Following it until `truncated` is false returns every
 * matching row exactly once. The token is "<floor>|<stream>:<offset>,...":
 * a byte offset per stream, each stream consumed as a prefix, so a row a
 * transport appends later — even with an older ts — is still returned on
 * a later page, never skipped. A page merges the stream heads in
 * (ts, from, seq) order, ties broken by stream name. Only complete lines
 * are consumed; a last line still being written waits for the next pull.
 * Stream names must be 1-128 of [A-Za-z0-9._-] (MAIL_STREAM_NAME_INVALID)
 * and at most 16 streams are read (MAIL_STREAMS_TOO_MANY), because the
 * token must name every one. A token whose offset is past a stream's end
 * or not on a line boundary means that stream was replaced or truncated,
 * and is refused as MAIL_CURSOR_STALE; replay with since=0.
 *
 * ACK. Writes the decimal cursor plus "\n" to <state>/mail/cursor.<agent>
 * (owner-private) via a temporary file in the same directory renamed over the target,
 * so a crash never truncates an existing cursor, and returns
 * {leaf, agent, cursor}.
 *
 * REFUSAL. A body longer than 4096 bytes, or one that mentions a secret key
 * (a key word or a Z.ai-shaped token: 32 hex chars, a dot, 16 alnum), an
 * onion address, an IP address, or ANY absolute filesystem path, is refused
 * with ok=false and a MAIL_REFUSED_* code naming the rule — a typed error
 * row, never a crash. Refusal words: key, onion address, IP, absolute path.
 * Repo-relative paths are allowed: a slash only makes a path ABSOLUTE when
 * it STARTS a token, so "docs/DEVELOPING.md" passes and "/etc/passwd" does
 * not. (A relative path whose own text contains a secret-shaped marker such
 * as "/tmp/" is still refused by the marker list that runs before that
 * test — a marker match, not a statement about leading slashes.)
 *
 * Every absolute path is refused, with no checkout root and no process cwd
 * consulted anywhere in the rule. A mail body crosses hosts: the sender's
 * filesystem path carries zero authority over how the receiver reads it,
 * and there is no root that is meaningful on both ends — a path under the
 * sender's checkout names something else, or nothing, under the receiver's.
 * The same bytes therefore get the same verdict from every directory, on
 * every box. Work is named by a logical selector (dev.agent.receive
 * resolves "muse-workspace: receiver" against ITS own configuration) and by
 * repo-relative paths.
 *
 * A path-shaped token carrying a ".." SEGMENT is refused the same way,
 * absolute or not: a climbing token is an escape attempt whether or not it
 * starts at a root, since "tests/../../../etc/passwd" names exactly what
 * "/etc/passwd" names. A filename that merely contains dots ("a..b") holds
 * no ".." segment and stays allowed.
 *
 * OUTPUT (zcl.agent_mail.v1). Every reply names its own `leaf`. Post returns
 * the row fields plus `cursor` (the row's seq) and `outbox`. Pull returns
 * `rows` (array), `cursor`, `count`, `truncated`, `next_since`, `skipped`,
 * `resumed_from` (since|agent|start) and `sources`: per stream,
 * {stream, consumed, size, complete}. `cursor` is only the largest seq seen
 * in ANY stream; it is not a fleet position, so completeness is per source.
 * Ack returns `agent`, `cursor` (the integer or the token it stored).
 *
 * FAILURE. BAD_INPUT (missing/empty action, to, kind, body; unknown kind or
 * action; bad cursor/agent spelling), MAIL_BODY_TOO_LARGE, MAIL_REFUSED_*,
 * STATE_DIR_FAILED, MAIL_WRITE_FAILED, MAIL_READ_FAILED,
 * MAIL_CURSOR_AMBIGUOUS, MAIL_CURSOR_STALE, MAIL_STREAM_NAME_INVALID,
 * MAIL_STREAMS_TOO_MANY.
 *
 * PROCESS RULE. No spawn, no shell, no popen()/system(), no sleep, no poll
 * loop. Only local filesystem operations below.
 */

#include "command/native_command.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#if defined(_WIN32)
#include "platform/directory_transaction.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#endif

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

/* MinGW declares neither macro: O_APPEND/O_CREAT etc. are ANSI, but
 * close-on-exec and fchmod are POSIX-only. The outbox/cursor files are
 * process-local and short-lived, so inheritance across exec is not a
 * concern here worth a real Windows handle-flag implementation - the
 * existing zero-fallback used by engine_receipt.c/engine_secret.c applies
 * the same way. */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define DVM_LEAF "dev.agent.mail"
#define DVM_BODY_MAX 4096u
#define DVM_LINE_CAP 8192
#define DVM_PATH_CAP 4096u
/* Width of a sender binding, fixed by the grant store that mints it
 * (ZCL_FLEET_STEER_BINDING_HEX). Stated here as a byte budget so this leaf
 * carries the field without depending on the store that means anything by
 * it: mail transports rows, it does not judge senders. */
#define DVM_BINDING_HEX 32u
/* Width of a board post id and of a board host key, both 32 bytes as hex:
 * the two fields a board-carrying transport appends to a row it imported.
 * Carried verbatim for the receiver, which is the one that verifies them. */
#define DVM_BOARD_HEX 64u

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

/* A Z.ai-style API key: 32 hex chars, a dot, 16 alphanumerics, bounded by
 * non-token characters on both sides so a longer word never matches. */
static bool dvm_has_api_key(const char *s)
{
    size_t n = strlen(s);
    if (n < 49)
        return false;
    for (size_t i = 0; i + 49 <= n; i++) {
        bool ok = true;
        if (s[i + 32] != '.')
            continue;
        for (size_t j = 0; j < 32; j++) {
            if (zcl_hex_nibble(s[i + j], true) < 0) {
                ok = false;
                break;
            }
        }
        if (!ok)
            continue;
        for (size_t j = 33; j < 49; j++) {
            if (!isalnum((unsigned char)s[i + j])) {
                ok = false;
                break;
            }
        }
        if (!ok)
            continue;
        if (i > 0 && (isalnum((unsigned char)s[i - 1]) || s[i - 1] == '.'))
            continue;
        if (i + 49 < n && isalnum((unsigned char)s[i + 49]))
            continue;
        return true;
    }
    return false;
}

static bool dvm_has_drive_path(const char *s)
{
    for (const char *p = s; *p; p++) {
        /* A web scheme is not a one-letter Windows drive. Skip only the
         * scheme itself: drive paths later in the URL remain refusals. */
        static const char *const web[] = { "http://", "https://" };
        size_t scheme_len = 0;
        for (size_t i = 0; i < sizeof(web) / sizeof(web[0]); i++) {
            size_t j = 0;
            while (web[i][j] && p[j] &&
                   tolower((unsigned char)p[j]) == web[i][j])
                j++;
            if (!web[i][j]) scheme_len = j;
        }
        if (scheme_len) {
            p += scheme_len - 1;
            continue;
        }
        if (isalpha((unsigned char)*p) && p[1] == ':' &&
            (p[2] == '\\' || p[2] == '/'))
            return true;
    }
    return false;
}

/* Where one token in a free-text body ends and the next begins. '=', '(',
 * ',' and ';' count, so "path=/etc/passwd" and "a,/etc/passwd" both still
 * read as an absolute token. */
static bool dvm_delim(char c)
{
    return c == '\0' || c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
           c == '"' || c == '\'' || c == '=' || c == '(' || c == ')' ||
           c == ',' || c == ';';
}

/* Does a token START at p, i.e. is p the first byte of the body or does a
 * delimiter sit just before it? This is what separates "/etc/passwd" (a
 * token that begins with a slash, so an absolute path) from the slash
 * INSIDE "docs/DEVELOPING.md" (a relative path, which is allowed and
 * always was meant to be). */
static bool dvm_token_start(const char *s, const char *p)
{
    return p == s || dvm_delim(p[-1]);
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
    /* A bare absolute path: a "/<alnum>" that STARTS a token. A slash in
     * the middle of a token is part of a repo-relative path
     * (tools/command/x.c) and is not an absolute path at all. The comment
     * here used to claim that already while the loop below matched every
     * slash it saw, which refused bodies that named nothing but relative
     * paths — and told them to "use repo-relative paths". */
    for (const char *p = s; *p; p++) {
        if (*p == '/' && isalnum((unsigned char)p[1]) &&
            dvm_token_start(s, p))
            return true;
    }
    return false;
}

/* Does any token in the body carry a ".." SEGMENT — ".." bounded by
 * slashes or by the token's own edges? A climbing token is an escape
 * attempt whether or not it starts at a root: "tests/../../../etc/passwd"
 * names exactly the file "/etc/passwd" names, and a body that reaches a
 * root by climbing out of a relative path has said nothing different from
 * a body that spells the root out. A filename that merely contains dots
 * ("a..b", "v1..v2") is one segment of its own, never a "..", and stays
 * allowed; so does a lone "." or "./" segment, which climbs nowhere. */
static bool dvm_has_climb(const char *s)
{
    const char *seg = s;
    for (const char *p = s;; p++) {
        if (*p == '/' || dvm_delim(*p)) {
            if (p - seg == 2 && seg[0] == '.' && seg[1] == '.')
                return true;
            seg = p + 1;
        }
        if (*p == '\0')
            return false;
    }
}

/* 0 = clean; else the MAIL_REFUSED_* code and a human message. */
static const char *dvm_refuse(const char *body, char *msg, size_t cap)
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
    if (dvm_has_api_key(body)) {
        (void)snprintf(msg, cap, "%s",
                       "refused: body contains an API key token; never "
                       "post keys, onion addresses, IPs, or absolute paths");
        return "MAIL_REFUSED_KEY";
    }
    if (dvm_has_ipv4(body)) {
        (void)snprintf(msg, cap, "%s",
                       "refused: body mentions an IP address; never post "
                       "IPs, keys, onion addresses, or absolute paths");
        return "MAIL_REFUSED_IP";
    }
    if (dvm_has_abs_path(body)) {
        (void)snprintf(msg, cap, "%s",
                       "refused: body mentions an absolute filesystem path; "
                       "a mail body crosses hosts, so use repo-relative "
                       "paths and a logical workspace selector");
        return "MAIL_REFUSED_PATH";
    }
    if (dvm_has_climb(body)) {
        (void)snprintf(msg, cap, "%s",
                       "refused: body has a path token that climbs out with "
                       "a '..' segment; use repo-relative paths that stay "
                       "inside the tree");
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
        } else if (*p == '\n' || *p == '\r' || *p == '\t' || *p == '\b' || // posix-ere-ok:json-backspace-escape
                   *p == '\f') {
            /* The two-character escapes, so a multi-line body survives the
             * round trip. A newline written as a six-character u-escape came
             * back from dvm_line_str as '?', which silently destroyed every
             * multi-line body — the header a machine reader needs most. */
            tmp[0] = '\\';
            tmp[1] = *p == '\n' ? 'n' : *p == '\r' ? 'r'
                     : *p == '\t' ? 't' : *p == '\b' ? 'b' : 'f'; // posix-ere-ok:json-backspace-escape
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
#if defined(_WIN32)
    /* Owner-private mail files require the private-directory ACL, not the
     * generic ensure seam (mode is ignored on Windows CreateDirectoryW). */
    return platform_private_directory_ensure(path);
#else
    return platform_directory_ensure(path, 0700);
#endif
}

static bool dvm_mail_dir(char *out, size_t cap, bool create)
{
    char state[4096];
    int n;
    if (!(create ? platform_state_root(state, sizeof(state))
                 : platform_state_root_existing(state, sizeof(state))))
        return false;
    n = snprintf(out, cap, "%s/mail", state);
    if (n <= 0 || (size_t)n >= cap)
        return false;
    if (!create) return true;
    /* mkdir -p the state root (platform helper owns its mode), then our
     * own mail dir at exactly 0700. */
    if (!dvm_mkdir_one(state))
        return false;
    if (!dvm_mkdir_one(out))
        return false;
#if !defined(_WIN32)
    /* The mail dir must end up 0700, but only write the mode when it is
     * actually wrong. An unconditional chmod(2) on every mail call fires an
     * inotify attribute event on this directory, which wakes any resident
     * loop watching it once per beat and turns a bounded idle wait into a
     * spin. Enforcement is unchanged: a wrong or unreadable mode is fixed. */
    struct stat dir_state;
    if (stat(out, &dir_state) != 0 || (dir_state.st_mode & 07777) != 0700)
        (void)chmod(out, 0700);
#endif
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

/* One two-character JSON escape to the byte it names. An escape this table
 * does not know keeps the character after the backslash, which is what
 * \" and \\ already needed. */
static char dvm_unescape_short(char c)
{
    switch (c) {
    case 'n': return '\n';
    case 'r': return '\r';
    case 't': return '\t';
    case 'b': return '\b'; // posix-ere-ok:json-backspace-escape
    case 'f': return '\f';
    default:  return c;
    }
}

/* One \uXXXX escape (hex digits already validated) to a single byte when it
 * names a non-NUL one below 0x80, and '?' otherwise. NUL stays '?': an
 * embedded NUL would truncate the row's own C string and make a body read
 * shorter than it is. */
static char dvm_unescape_u(const char *hex)
{
    char digits[5];
    unsigned long v;
    digits[0] = hex[0];
    digits[1] = hex[1];
    digits[2] = hex[2];
    digits[3] = hex[3];
    digits[4] = '\0';
    v = strtoul(digits, NULL, 16);
    return (v > 0u && v < 0x80u) ? (char)v : '?';
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
            /* Decode the two-character escapes to the bytes they name, so a
             * multi-line body reads back as the writer wrote it. A \uXXXX
             * escape carries its own byte when it names one below 0x80 (the
             * form older rows used for newlines and tabs) and stays '?'
             * above that, where ordering needs only stable bytes. */
            if (p[1] == 'u' && isxdigit((unsigned char)p[2]) &&
                isxdigit((unsigned char)p[3]) &&
                isxdigit((unsigned char)p[4]) &&
                isxdigit((unsigned char)p[5])) {
                out[used++] = dvm_unescape_u(p + 2);
                p += 6;
            } else {
                out[used++] = dvm_unescape_short(p[1]);
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
    /* "" when the poster stamped none; carried, never interpreted here. */
    char sender_binding[DVM_BINDING_HEX + 1];
    /* "" unless a board transport imported the row; carried, never
     * interpreted here. */
    char board_post[DVM_BOARD_HEX + 1];
    char board_signer[DVM_BOARD_HEX + 1];
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
    /* Optional by design: an older row, or one from a poster that stamped
     * nothing, keeps the empty binding. A reader that needs attribution
     * refuses on the empty value; nothing here guesses one. */
    (void)dvm_line_str(line, "sender_binding", r->sender_binding,
                       sizeof(r->sender_binding));
    /* A value too long to be a post id or a host key reads back empty,
     * which leaves the pair partial: the receiver refuses a partial pair
     * as unsigned rather than guessing which half was meant. */
    if (!dvm_line_str(line, "board_post", r->board_post,
                      sizeof(r->board_post)))
        r->board_post[0] = '\0';
    if (!dvm_line_str(line, "board_signer", r->board_signer,
                      sizeof(r->board_signer)))
        r->board_signer[0] = '\0';
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

/* Validated input for one post. Split out of dvm_post() so the guard-clause
 * chain that rejects malformed input lives apart from sequencing, encoding,
 * and the platform write. */
struct dvm_post_input {
    const char *to, *kind, *body, *from, *ref, *sender_binding;
};

/* A binding is 32 lowercase hex or nothing at all. Checked for shape only:
 * whether it is the right binding is the grant store's question, asked by
 * the reader that admits the row, not by the leaf that carries it. */
static bool dvm_binding_ok(const char *s)
{
    size_t i;
    if (!s || !s[0])
        return true;
    if (strlen(s) != DVM_BINDING_HEX)
        return false;
    for (i = 0; s[i]; i++) {
        if (!isxdigit((unsigned char)s[i]) || isupper((unsigned char)s[i]))
            return false;
    }
    return true;
}

static const struct dvm_fail_info {
    const char *code, *message, *evidence;
} to_empty_info = {"BAD_INPUT", "post needs a non-empty to",
                   "input.to missing or empty"},
  to_bad_info = {"BAD_INPUT", "to names an agent or *",
                "input.to has an illegal spelling"},
  kind_bad_info = {"BAD_INPUT",
                   "kind is one of need|claim|result|problem|note|offer|directive",
                   "input.kind missing or unknown"},
  body_empty_info = {"BAD_INPUT", "post needs a non-empty body",
                     "input.body missing or empty"},
  body_big_info = {"MAIL_BODY_TOO_LARGE", "body is over the 4096-byte cap",
                   "input.body too large"},
  from_bad_info = {"BAD_INPUT", "from names the sending agent",
                   "input.from has an illegal spelling"},
  binding_bad_info = {"BAD_INPUT",
                      "sender_binding is 32 lowercase hex, or absent",
                      "input.sender_binding has an illegal spelling"},
  ref_big_info = {"BAD_INPUT", "ref is at most 200 bytes",
                 "input.ref too large"},
  escape_info = {"BAD_INPUT", "row fields too large to encode",
                 "escape budget exceeded"},
  line_big_info = {"BAD_INPUT", "row too large to encode",
                   "line budget exceeded"},
  newline_info = {"BAD_INPUT", "body must be one line of text",
                  "embedded newline"};

/* Read to/kind/body/from/ref out of req into *in (ref defaults to ""). Pure
 * extraction, no validation. */
static void dvm_post_extract(const struct zcl_command_request *req,
                             struct dvm_post_input *in)
{
    const struct json_value *bodyv;
    in->to = dvm_str(req, "to");
    in->kind = dvm_str(req, "kind");
    in->ref = dvm_str(req, "ref");
    bodyv = json_get(req->input, "body");
    in->body = bodyv && bodyv->type == JSON_STR ? json_get_str(bodyv) : NULL;
    in->from = dvm_identity(req, "from");
    in->sender_binding = dvm_str(req, "sender_binding");
    if (!in->ref)
        in->ref = "";
    if (!in->sender_binding)
        in->sender_binding = "";
}

/* Check to/kind, the two fields validated before body is even inspected. */
static const struct dvm_fail_info *dvm_post_check_to_kind(
    const struct dvm_post_input *in)
{
    if (!in->to || !in->to[0]) return &to_empty_info;
    if (!dvm_agent_ok(in->to)) return &to_bad_info;
    if (!in->kind || !dvm_is_kind(in->kind)) return &kind_bad_info;
    return NULL;
}

/* Check body/from/ref, the fields validated after to/kind pass. */
static const struct dvm_fail_info *dvm_post_check_body_from_ref(
    const struct dvm_post_input *in)
{
    if (!in->body || !in->body[0]) return &body_empty_info;
    if (strlen(in->body) > DVM_BODY_MAX) return &body_big_info;
    if (!in->from || !in->from[0] || !dvm_agent_ok(in->from))
        return &from_bad_info;
    if (strlen(in->ref) > 200) return &ref_big_info;
    if (!dvm_binding_ok(in->sender_binding)) return &binding_bad_info;
    return NULL;
}

static const struct dvm_fail_info *dvm_post_validate(
    const struct zcl_command_request *req, struct dvm_post_input *in)
{
    const struct dvm_fail_info *bad;
    dvm_post_extract(req, in);
    bad = dvm_post_check_to_kind(in);
    if (bad)
        return bad;
    return dvm_post_check_body_from_ref(in);
}

/* Next seq: one plus the largest seq already present. A duplicate seq under
 * concurrent posters is acceptable (bytes stay intact); the pull cursor
 * still advances past both on (ts, from, seq) order. */
static long long dvm_post_next_seq(const char *outbox)
{
    long long seq = 0;
    FILE *f = fopen(outbox, "r");
    if (!f)
        return 1;
    char buf[DVM_LINE_CAP];
    while (fgets(buf, sizeof(buf), f)) {
        long long s;
        if (dvm_line_int(buf, "seq", &s) && s >= seq)
            seq = s + 1;
        else if (!dvm_line_int(buf, "seq", &s) && seq < 1)
            seq = 1;
    }
    (void)fclose(f);
    return seq < 1 ? 1 : seq;
}

/* Append line (len bytes) to the private outbox, per platform. Returns
 * true on success. Split out of dvm_post() so its own complexity does not
 * fold both platforms' write paths together. */
#if defined(_WIN32)
static bool dvm_post_write_line(const char *outbox, const char *line,
                                size_t len)
{
    /* A nonblocking private-file lock serializes the size/write pair. Raw
     * handle writes preserve LF bytes and do not inherit a CRT descriptor. */
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool written = platform_private_file_open_locked_create(outbox, &file);
    if (written) {
        /* Borrow the already-open handle for metadata only; `file` retains
         * sole ownership of its lock and close. Never re-open the pathname
         * to decide whether this exact object is private and unaliased. */
        struct platform_directory_child view = {.native = file.native};
        struct platform_directory_child_info info;
        written = platform_directory_child_info(&view, &info) &&
            info.current_user_only && info.link_count == 1 &&
            platform_private_file_write_at(&file, line, len, info.size) &&
            platform_private_file_flush(&file);
    }
    platform_private_file_close(&file);
    return written;
}
#else
static bool dvm_post_write_line(const char *outbox, const char *line,
                                size_t len)
{
    int fd = open(outbox, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    (void)fchmod(fd, 0600);
    ssize_t w = write(fd, line, len);
    (void)close(fd);
    return w == (ssize_t)len;
}
#endif

/* Compose the one outbox row this post appends. On success *len holds the
 * row's byte count and line holds exactly one newline-terminated row;
 * otherwise the refusal that stopped it is returned and line is not to be
 * used. Split out of dvm_post() so escaping, the line budget, and the
 * one-line invariant are this function's business rather than folded into
 * the post path beside sequencing and the platform write. */
static const struct dvm_fail_info *dvm_post_compose(
    const struct dvm_post_input *in, long long seq, const char *ts,
    char *line, size_t cap, size_t *len)
{
    char esc_from[512], esc_to[512], esc_kind[64], esc_body[DVM_BODY_MAX * 2];
    char esc_ref[512];
    char bind_part[DVM_BINDING_HEX + 32];
    const char *nl;
    int w;
    if (!dvm_escape(in->from, esc_from, sizeof(esc_from)) ||
        !dvm_escape(in->to, esc_to, sizeof(esc_to)) ||
        !dvm_escape(in->kind, esc_kind, sizeof(esc_kind)) ||
        !dvm_escape(in->body, esc_body, sizeof(esc_body)) ||
        !dvm_escape(in->ref, esc_ref, sizeof(esc_ref)))
        return &escape_info;
    /* The binding is written only when the poster stamped one, so an
     * unstamped row says so by carrying no field rather than by carrying
     * an empty one that a reader could mistake for a value. Its alphabet
     * was checked by validation, so it needs no escaping. */
    bind_part[0] = '\0';
    if (in->sender_binding[0])
        (void)snprintf(bind_part, sizeof(bind_part),
                       ",\"sender_binding\":\"%s\"", in->sender_binding);
    w = snprintf(line, cap,
                 "{\"seq\":%lld,\"ts\":\"%s\",\"from\":\"%s\","
                 "\"to\":\"%s\",\"kind\":\"%s\",\"body\":\"%s\","
                 "\"ref\":\"%s\"%s}\n",
                 seq, ts, esc_from, esc_to, esc_kind, esc_body, esc_ref,
                 bind_part);
    if (w <= 0 || (size_t)w >= cap)
        return &line_big_info;
    *len = (size_t)w;
    /* One row is one line: the terminator the format writes must be the
     * only one present (bodies with control bytes are \\u-escaped above,
     * so this is a guard, not a routine path). */
    nl = strchr(line, '\n');
    if (!nl || nl[1] != '\0')
        return &newline_info;
    return NULL;
}

static void dvm_post(const struct zcl_command_request *req,
                     struct zcl_command_reply *reply, const char *maildir)
{
    struct dvm_post_input in;
    char outbox[DVM_PATH_CAP];
    char ts[40];
    char line[DVM_LINE_CAP];
    const struct dvm_fail_info *invalid;
    const char *code;
    char msg[256];
    long long seq;
    time_t now;
    struct tm tm_utc;
    size_t len;

    if (!req || !req->input) {
        dvm_fail(reply, "BAD_INPUT", "dev.agent.mail post needs to, kind, body",
                 "request.input was missing");
        return;
    }
    invalid = dvm_post_validate(req, &in);
    if (invalid) {
        dvm_fail(reply, invalid->code, invalid->message, invalid->evidence);
        return;
    }
    /* The refusal reads the body and nothing else. No checkout root, no
     * process cwd, no `cwd` input: a body crosses hosts, so the same bytes
     * must get the same verdict from every directory and on every box. */
    code = dvm_refuse(in.body, msg, sizeof(msg));
    if (code) {
        dvm_fail(reply, code, msg, "input.body hit a refusal rule");
        return;
    }

    int path_length = snprintf(outbox, sizeof(outbox), "%s/outbox.jsonl", maildir);
    if (path_length <= 0 || (size_t)path_length >= sizeof(outbox)) {
        dvm_fail(reply, "MAIL_WRITE_FAILED", "outbox path exceeds its bound", maildir);
        return;
    }
    seq = dvm_post_next_seq(outbox);

    now = platform_time_wall_time_t();
    if (!platform_time_utc_tm(now, &tm_utc) ||
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0) {
        dvm_fail(reply, "MAIL_WRITE_FAILED", "cannot encode the message timestamp",
                 "UTC time conversion failed");
        return;
    }

    invalid = dvm_post_compose(&in, seq, ts, line, sizeof(line), &len);
    if (invalid) {
        dvm_fail(reply, invalid->code, invalid->message, invalid->evidence);
        return;
    }

    if (!dvm_post_write_line(outbox, line, len)) {
        dvm_fail(reply, "MAIL_WRITE_FAILED", "cannot append the private outbox",
                 outbox);
        return;
    }

    const char *to = in.to, *kind = in.kind, *body = in.body, *from = in.from,
               *ref = in.ref;
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

/* One page is bounded twice: at most DVM_PAGE_ROWS rows, and at most
 * DVM_PAGE_BYTES of estimated serialized row bytes (the first row of a page
 * is always taken, whatever it costs, so a page is never empty while rows
 * remain). A single row is at most a 4 KiB body escaped at worst six bytes
 * per byte, so the first-row exception plus the resume token and the
 * envelope still fits the leaf's 32 KiB response budget. */
#define DVM_PAGE_ROWS 64u
#define DVM_PAGE_BYTES 16384u
#define DVM_STREAMS_MAX 16u
#define DVM_STREAM_NAME_MAX 128u
#define DVM_TOKEN_CAP (DVM_STREAMS_MAX * (DVM_STREAM_NAME_MAX + 24u) + 32u)

struct dvm_pull_filter {
    long long since;      /* seq floor: rows at or below it are not returned */
    const char *from;
    const char *kind;
    const char *to;       /* exact recipient, or NULL */
    const char *ref;      /* exact ref, or NULL */
    const char *token;    /* resume entries after "<floor>|", or NULL */
    const char *resumed;  /* "since" | "agent" | "start": where paging began */
};

/* One *.jsonl stream under the mail dir, read from a byte offset. `off` is
 * the consumed boundary: every complete line before it has been returned or
 * filtered. A head row is loaded but not yet returned. */
struct dvm_stream {
    char name[DVM_STREAM_NAME_MAX + 1];
    char path[DVM_PATH_CAP];
    FILE *f;
    long long off;
    long long head_end;
    bool has_head;
    bool named; /* the resume token already named this stream */
    struct dvm_row head;
};

struct dvm_pull_state {
    struct dvm_stream *streams;
    size_t nstreams;
    long long cursor;  /* largest seq seen anywhere, or the floor */
    long long skipped; /* malformed lines this page consumed */
    char line[DVM_LINE_CAP];
};

struct dvm_page {
    struct dvm_row *rows;
    size_t n;
    size_t bytes;
    bool truncated;
};

/* A resume token is "<floor>|<name>:<offset>,..." — digits, then a bar.
 * Anything else that is not a plain non-negative integer is bad input. */
static bool dvm_since_token(const char *s, struct dvm_pull_filter *filter)
{
    char *end = NULL;
    long long n;
    if (!s || !isdigit((unsigned char)s[0]))
        return false;
    errno = 0;
    n = strtoll(s, &end, 10);
    if (errno != 0 || !end || *end != '|' || n < 0)
        return false;
    filter->since = n;
    filter->token = end + 1;
    return true;
}

/* Parse pull's since/from/kind filters from req into *filter (since defaults
 * to 0 whether req/input is absent or "since" is simply not given). Returns
 * false, with a fail reply already written, if a filter is malformed. */
static bool dvm_pull_parse_filter(const struct zcl_command_request *req,
                                  struct zcl_command_reply *reply,
                                  struct dvm_pull_filter *filter)
{
    const struct json_value *v;
    memset(filter, 0, sizeof(*filter));
    filter->resumed = "start";
    if (!req || !req->input)
        return true;
    v = json_get(req->input, "since");
    if (v)
        filter->resumed = "since";
    if (v && !dvm_int(req, "since", &filter->since) &&
        !(v->type == JSON_STR && dvm_since_token(json_get_str(v), filter))) {
        dvm_fail(reply, "BAD_INPUT",
                 "since is a non-negative cursor or a next_since token",
                 "input.since has the wrong shape");
        return false;
    }
    filter->from = dvm_str(req, "from");
    filter->kind = dvm_str(req, "kind");
    filter->to = dvm_str(req, "to");
    filter->ref = dvm_str(req, "ref");
    if (filter->kind && !dvm_is_kind(filter->kind)) {
        dvm_fail(reply, "BAD_INPUT",
                 "kind filter is one of need|claim|result|problem|note|"
                 "offer|directive",
                 "input.kind unknown");
        return false;
    }
    return true;
}

/* ── streams ── */

static void dvm_streams_close(struct dvm_pull_state *ps)
{
    for (size_t i = 0; i < ps->nstreams; i++) {
        if (ps->streams[i].f)
            (void)fclose(ps->streams[i].f);
        ps->streams[i].f = NULL;
    }
    free(ps->streams);
    ps->streams = NULL;
    ps->nstreams = 0;
}

static int dvm_stream_name_cmp(const void *a, const void *b)
{
    return strcmp(((const struct dvm_stream *)a)->name,
                  ((const struct dvm_stream *)b)->name);
}

/* A mail stream is any "<name>.jsonl" regular entry; ".jsonl" alone and
 * names shorter than one character plus the suffix are not. */
static bool dvm_is_stream_name(const char *name)
{
    const char *dot = strrchr(name, '.');
    if (strlen(name) < 7 || !dot || strcmp(dot, ".jsonl") != 0)
        return false;
    return strchr(name, '/') == NULL;
}

/* Why one directory entry cannot join the stream set, or NULL. The name
 * travels inside the resume token, so it must be spellable there. */
static const char *dvm_stream_refusal(const struct dvm_pull_state *ps,
                                      const struct dvm_pull_filter *filter,
                                      const char *name)
{
    if (!dvm_cursor_name_ok(name))
        return "MAIL_STREAM_NAME_INVALID";
    if (ps->nstreams >= DVM_STREAMS_MAX)
        return "MAIL_STREAMS_TOO_MANY";
    /* Each imported file has its own sequence space. A scalar from
     * another stream cannot establish that this stream was consumed. */
    if (ps->nstreams >= 1 && filter->since > 0)
        return "MAIL_CURSOR_AMBIGUOUS";
    return NULL;
}

static void dvm_stream_fail(struct zcl_command_reply *reply,
                            const char *code, const char *name)
{
    if (strcmp(code, "MAIL_CURSOR_AMBIGUOUS") == 0) {
        dvm_fail(reply, code,
                 "multiple mail streams cannot resume one scalar cursor; replay with since=0",
                 "independent mail sequence spaces");
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action), "%s",
                       "z23-dev dev agent mail pull --since=0");
        return;
    }
    if (strcmp(code, "MAIL_STREAMS_TOO_MANY") == 0) {
        dvm_fail(reply, code,
                 "more mail streams than one resume token can name", name);
        return;
    }
    dvm_fail(reply, code,
             "a mail stream name must be 1-128 of [A-Za-z0-9._-] to be "
             "resumable",
             name);
}

/* Enumerate maildir's streams, sorted by name so ties in row order break
 * the same way on every pull. False with a fail reply already written. */
static bool dvm_streams_list(const char *maildir,
                             struct zcl_command_reply *reply,
                             const struct dvm_pull_filter *filter,
                             struct dvm_pull_state *ps)
{
    DIR *d = opendir(maildir);
    struct dirent *ent;
    if (!d) {
        if (errno == ENOENT) return true;
        dvm_fail(reply, "MAIL_READ_FAILED", "cannot read the mail dir",
                 maildir);
        return false;
    }
#if defined(_WIN32)
    uintptr_t retained = 0;
    if (!platform_private_directory_open_validated_traverse(maildir, &retained)) {
        (void)closedir(d);
        dvm_fail(reply, "MAIL_READ_FAILED", "mail directory is not owner-private", maildir);
        return false;
    }
    platform_private_directory_close(retained);
#endif
    ps->streams = (struct dvm_stream *)zcl_calloc(
        DVM_STREAMS_MAX, sizeof(*ps->streams), "devagent_mail.streams");
    if (!ps->streams) {
        (void)closedir(d);
        dvm_fail(reply, "MAIL_READ_FAILED", "cannot allocate the stream set",
                 maildir);
        return false;
    }
    while ((ent = readdir(d)) != NULL) {
        struct dvm_stream *s;
        const char *why;
        if (!dvm_is_stream_name(ent->d_name))
            continue;
        why = dvm_stream_refusal(ps, filter, ent->d_name);
        if (why) {
            (void)closedir(d);
            dvm_stream_fail(reply, why, ent->d_name);
            return false;
        }
        s = &ps->streams[ps->nstreams];
        int path_length =
            snprintf(s->path, sizeof(s->path), "%s/%s", maildir, ent->d_name);
        if (path_length <= 0 || (size_t)path_length >= sizeof(s->path)) {
            (void)closedir(d);
            dvm_fail(reply, "MAIL_READ_FAILED", "mail path exceeds its bound",
                     maildir);
            return false;
        }
        (void)snprintf(s->name, sizeof(s->name), "%s", ent->d_name);
        ps->nstreams++;
    }
    (void)closedir(d);
    if (ps->nstreams > 1)
        qsort(ps->streams, ps->nstreams, sizeof(*ps->streams),
              dvm_stream_name_cmp);
    return true;
}

/* ── resume token ── */

/* One "<name>:<offset>" entry at p. Sets *next past the entry and its
 * trailing comma. NULL on success, else why the entry is malformed. */
static const char *dvm_token_entry(const char *p, char *name, size_t cap,
                                   long long *off, const char **next)
{
    const char *colon = strchr(p, ':');
    const char *comma = strchr(p, ',');
    char *end = NULL;
    size_t len;
    if (!colon || (comma && comma < colon))
        return "a resume entry is <stream>:<offset>";
    len = (size_t)(colon - p);
    if (len == 0 || len >= cap)
        return "a resume entry names no stream";
    memcpy(name, p, len);
    name[len] = '\0';
    if (!dvm_cursor_name_ok(name) || !isdigit((unsigned char)colon[1]))
        return "a resume entry is <stream>:<offset>";
    errno = 0;
    *off = strtoll(colon + 1, &end, 10);
    if (errno != 0 || !end || (*end != ',' && *end != '\0'))
        return "a resume offset is a non-negative integer";
    *next = *end == ',' ? end + 1 : end;
    return NULL;
}

/* Apply the token's per-stream offsets. A stream the token names but the
 * dir no longer holds is dropped; a stream the token does not name starts
 * at its beginning. NULL on success, else why the token is malformed. */
static const char *dvm_token_apply(const char *token,
                                   struct dvm_pull_state *ps)
{
    const char *p = token;
    size_t entries = 0;
    while (p && *p) {
        char name[DVM_STREAM_NAME_MAX + 1];
        long long off = 0;
        const char *why =
            dvm_token_entry(p, name, sizeof(name), &off, &p);
        if (why)
            return why;
        if (++entries > DVM_STREAMS_MAX)
            return "a resume token names more streams than a pull reads";
        for (size_t i = 0; i < ps->nstreams; i++) {
            if (strcmp(ps->streams[i].name, name) != 0)
                continue;
            if (ps->streams[i].named)
                return "a resume token names one stream twice";
            ps->streams[i].named = true;
            ps->streams[i].off = off;
        }
    }
    return NULL;
}

/* Open one stream at its offset. An offset past the end of the file, or
 * one that does not follow a newline, cannot be a boundary this leaf handed
 * out, so the file was replaced or truncated: refuse, never guess. */
static bool dvm_stream_open(struct dvm_stream *s)
{
    struct stat st;
    s->f = fopen(s->path, "rb");
    if (!s->f)
        return s->off == 0; /* vanished since the listing: nothing to read */
    if (fstat(fileno(s->f), &st) != 0 || s->off > (long long)st.st_size)
        return false;
    if (s->off > 0) {
        if (fseek(s->f, (long)(s->off - 1), SEEK_SET) != 0 ||
            fgetc(s->f) != '\n')
            return false;
    }
    return fseek(s->f, (long)s->off, SEEK_SET) == 0;
}

enum dvm_line_kind { DVM_LINE_OK, DVM_LINE_LONG, DVM_LINE_PARTIAL,
                     DVM_LINE_EOF };

/* Read one line. A last line with no newline yet is PARTIAL: a writer may
 * still be appending it, so it is not consumed. A line longer than the
 * buffer is read through to its newline and reported LONG. */
static enum dvm_line_kind dvm_read_line(FILE *f, char *buf, size_t cap)
{
    size_t len;
    if (!fgets(buf, (int)cap, f))
        return DVM_LINE_EOF;
    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        return DVM_LINE_OK;
    if (feof(f))
        return DVM_LINE_PARTIAL;
    for (;;) {
        int c = fgetc(f);
        if (c == '\n')
            return DVM_LINE_LONG;
        if (c == EOF)
            return DVM_LINE_PARTIAL;
    }
}

/* Parse one complete line into *r when it is a row this pull returns.
 * Malformed lines count as skipped; filtered rows do not. */
static bool dvm_row_wanted(char *buf, const struct dvm_pull_filter *filter,
                           struct dvm_row *r, struct dvm_pull_state *ps)
{
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    if (len == 0)
        return false;
    if (!dvm_parse_row(buf, r)) {
        ps->skipped++; /* malformed line: skipped, never fatal */
        return false;
    }
    if (r->seq <= filter->since)
        return false;
    if (filter->from && strcmp(r->from, filter->from) != 0)
        return false;
    if (filter->to && strcmp(r->to, filter->to) != 0)
        return false;
    if (filter->ref && strcmp(r->ref, filter->ref) != 0)
        return false;
    return !filter->kind || strcmp(r->kind, filter->kind) == 0;
}

/* Load the stream's next returnable row as its head, consuming every line
 * before it that this pull does not return. */
static void dvm_stream_next(struct dvm_stream *s,
                            const struct dvm_pull_filter *filter,
                            struct dvm_pull_state *ps)
{
    s->has_head = false;
    if (!s->f)
        return;
    for (;;) {
        enum dvm_line_kind k = dvm_read_line(s->f, ps->line, sizeof(ps->line));
        long long end;
        if (k == DVM_LINE_EOF || k == DVM_LINE_PARTIAL)
            return;
        end = (long long)ftell(s->f);
        if (k == DVM_LINE_LONG) {
            ps->skipped++;
            s->off = end;
            continue;
        }
        if (!dvm_row_wanted(ps->line, filter, &s->head, ps)) {
            s->off = end;
            continue;
        }
        s->head_end = end;
        s->has_head = true;
        return;
    }
}

/* The largest seq in one whole stream, whatever the page and filters. */
static void dvm_stream_max_seq(const struct dvm_stream *s,
                               struct dvm_pull_state *ps)
{
    FILE *f = fopen(s->path, "rb");
    struct dvm_row r;
    if (!f)
        return;
    for (;;) {
        enum dvm_line_kind k = dvm_read_line(f, ps->line, sizeof(ps->line));
        if (k == DVM_LINE_EOF || k == DVM_LINE_PARTIAL)
            break;
        if (k == DVM_LINE_OK && dvm_parse_row(ps->line, &r) &&
            r.seq > ps->cursor)
            ps->cursor = r.seq;
    }
    (void)fclose(f);
}

/* ── one page ── */

/* The escaped length json_write gives s, quotes included: quote and
 * backslash take two bytes, the five short control escapes (byte 8 is
 * backspace) take two, any other control byte takes six. */
static size_t dvm_json_len(const char *s)
{
    size_t n = 2;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\')
            n += 2;
        else if (c < 0x20)
            n += (c == 8u || strchr("\f\n\r\t", c)) ? 2u : 6u;
        else
            n += 1;
    }
    return n;
}

/* Serialized bytes of one row object: its strings, escaped, plus keys,
 * punctuation and the seq digits (generously). */
static size_t dvm_row_cost(const struct dvm_row *r)
{
    return 160u + dvm_json_len(r->ts) + dvm_json_len(r->from) +
           dvm_json_len(r->to) + dvm_json_len(r->kind) +
           dvm_json_len(r->body) + dvm_json_len(r->ref) +
           dvm_json_len(r->sender_binding) + dvm_json_len(r->board_post) +
           dvm_json_len(r->board_signer);
}

/* The stream whose head sorts first by (ts, from, seq); a tie goes to the
 * stream whose name sorts first. NULL when every stream is drained. */
static struct dvm_stream *dvm_pick(struct dvm_pull_state *ps)
{
    struct dvm_stream *best = NULL;
    for (size_t i = 0; i < ps->nstreams; i++) {
        struct dvm_stream *s = &ps->streams[i];
        if (!s->has_head)
            continue;
        if (!best || dvm_row_cmp(&s->head, &best->head) < 0)
            best = s;
    }
    return best;
}

/* Merge stream heads into one page until a bound is reached or every
 * stream is drained. Each stream is consumed as a prefix, so a row that a
 * transport appends later — even with an older ts — is still ahead of the
 * token and is returned on a later page, never skipped. */
static void dvm_pull_page(struct dvm_pull_state *ps,
                          const struct dvm_pull_filter *filter,
                          struct dvm_page *pg)
{
    for (;;) {
        struct dvm_stream *best = dvm_pick(ps);
        size_t cost;
        if (!best) {
            pg->truncated = false;
            return;
        }
        cost = dvm_row_cost(&best->head);
        if (pg->n > 0 && (pg->n >= DVM_PAGE_ROWS ||
                          pg->bytes + cost > DVM_PAGE_BYTES)) {
            pg->truncated = true;
            return;
        }
        pg->rows[pg->n++] = best->head;
        pg->bytes += cost;
        best->off = best->head_end;
        dvm_stream_next(best, filter, ps);
    }
}

/* "<floor>|<name>:<offset>,..." over every stream, in name order. */
static bool dvm_token_build(const struct dvm_pull_state *ps, long long floor,
                            char *out, size_t cap)
{
    size_t used;
    int n = snprintf(out, cap, "%lld|", floor);
    if (n <= 0 || (size_t)n >= cap)
        return false;
    used = (size_t)n;
    for (size_t i = 0; i < ps->nstreams; i++) {
        n = snprintf(out + used, cap - used, "%s%s:%lld", i ? "," : "",
                     ps->streams[i].name, ps->streams[i].off);
        if (n <= 0 || (size_t)n >= cap - used)
            return false;
        used += (size_t)n;
    }
    return true;
}

/* Per-source completeness: `cursor` is the largest seq seen in ANY stream,
 * which says nothing about whether each peer's file was read to its end.
 * Each source reports the bytes this page consumed against the file's size
 * now; complete=false means rows (or a line still being written) remain. */
static void dvm_pull_sources(struct zcl_command_reply *reply,
                             const struct dvm_pull_state *ps)
{
    struct json_value arr, item;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < ps->nstreams; i++) {
        const struct dvm_stream *st = &ps->streams[i];
        struct stat sb;
        long long size = stat(st->path, &sb) == 0 ? (long long)sb.st_size
                                                  : -1;
        json_init(&item);
        json_set_object(&item);
        (void)json_push_kv_str(&item, "stream", st->name);
        (void)json_push_kv_int(&item, "consumed", st->off);
        (void)json_push_kv_int(&item, "size", size);
        (void)json_push_kv_bool(&item, "complete",
                                size >= 0 && st->off == size);
        (void)json_push_back(&arr, &item);
        json_free(&item);
    }
    (void)json_push_kv(&reply->data, "sources", &arr);
    json_free(&arr);
}

static void dvm_pull_build_reply(struct zcl_command_reply *reply,
                                 const struct dvm_page *pg,
                                 const struct dvm_pull_state *ps,
                                 const char *token, const char *resumed)
{
    struct json_value arr, item;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < pg->n; i++) {
        const struct dvm_row *r = &pg->rows[i];
        json_init(&item);
        json_set_object(&item);
        (void)json_push_kv_int(&item, "seq", r->seq);
        (void)json_push_kv_str(&item, "ts", r->ts);
        (void)json_push_kv_str(&item, "from", r->from);
        (void)json_push_kv_str(&item, "to", r->to);
        (void)json_push_kv_str(&item, "kind", r->kind);
        (void)json_push_kv_str(&item, "body", r->body);
        (void)json_push_kv_str(&item, "ref", r->ref);
        (void)json_push_kv_str(&item, "sender_binding", r->sender_binding);
        (void)json_push_kv_str(&item, "board_post", r->board_post);
        (void)json_push_kv_str(&item, "board_signer", r->board_signer);
        (void)json_push_back(&arr, &item);
        json_free(&item);
    }
    (void)json_push_kv_str(&reply->data, "leaf", DVM_LEAF);
    (void)json_push_kv(&reply->data, "rows", &arr);
    json_free(&arr);
    (void)json_push_kv_int(&reply->data, "cursor", ps->cursor);
    (void)json_push_kv_int(&reply->data, "count", (long long)pg->n);
    (void)json_push_kv_bool(&reply->data, "truncated", pg->truncated);
    (void)json_push_kv_str(&reply->data, "next_since", token);
    (void)json_push_kv_int(&reply->data, "skipped", ps->skipped);
    (void)json_push_kv_str(&reply->data, "resumed_from", resumed);
    dvm_pull_sources(reply, ps);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* Position every stream at its resume offset and load its first head.
 * False with a fail reply already written. */
static bool dvm_streams_start(struct zcl_command_reply *reply,
                              const struct dvm_pull_filter *filter,
                              struct dvm_pull_state *ps)
{
    const char *why = filter->token ? dvm_token_apply(filter->token, ps)
                                    : NULL;
    if (why) {
        dvm_fail(reply, "BAD_INPUT", why, "input.since resume token");
        return false;
    }
    for (size_t i = 0; i < ps->nstreams; i++) {
        struct dvm_stream *s = &ps->streams[i];
        dvm_stream_max_seq(s, ps);
        if (!dvm_stream_open(s)) {
            dvm_fail(reply, "MAIL_CURSOR_STALE",
                     "the resume token does not name a line boundary of "
                     "this stream; it was replaced or truncated",
                     s->name);
            (void)snprintf(reply->error.next_action,
                           sizeof(reply->error.next_action), "%s",
                           "z23-dev dev agent mail pull --since=0");
            return false;
        }
        dvm_stream_next(s, filter, ps);
    }
    return true;
}

/* A cursor an agent may store: a scalar, or a next_since token. Tokens are
 * "<digits>|<name>:<offset>,..." in the stream-name alphabet only, so a
 * stored cursor can never smuggle a path or a newline into the file. */
static bool dvm_cursor_text_ok(const char *s)
{
    struct dvm_pull_filter probe;
    if (!s || !s[0] || strlen(s) >= DVM_TOKEN_CAP)
        return false;
    for (const char *p = s; *p; p++) {
        if (!isalnum((unsigned char)*p) && !strchr("._-:,|", *p))
            return false;
    }
    if (!strchr(s, '|')) {
        for (const char *p = s; *p; p++)
            if (!isdigit((unsigned char)*p))
                return false;
        return true;
    }
    return dvm_since_token(s, &probe);
}

/* Pull with `agent` and no `since` resumes from that agent's acked cursor:
 * the file ack wrote. Absent file = from the start. Returns false with a
 * fail reply written when the stored text is not a cursor. `buf` owns the
 * token the filter then points into. */
static bool dvm_pull_resume_agent(const struct zcl_command_request *req,
                                  struct zcl_command_reply *reply,
                                  const char *maildir,
                                  struct dvm_pull_filter *filter, char *buf,
                                  size_t cap)
{
    const char *agent = dvm_str(req, "agent");
    char path[DVM_PATH_CAP];
    FILE *f;
    size_t n;
    if (!agent || json_get(req->input, "since"))
        return true;
    if (!dvm_cursor_name_ok(agent)) {
        dvm_fail(reply, "BAD_INPUT", "agent names the cursor owner",
                 "input.agent has an illegal spelling");
        return false;
    }
    n = (size_t)snprintf(path, sizeof(path), "%s/cursor.%s", maildir, agent);
    if (n == 0 || n >= sizeof(path) || !(f = fopen(path, "rb")))
        return true; /* never acked: page from the start */
    n = fread(buf, 1, cap - 1, f);
    (void)fclose(f);
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';
    filter->resumed = "agent";
    if (dvm_cursor_text_ok(buf) && !strchr(buf, '|')) {
        filter->since = strtoll(buf, NULL, 10);
        return true;
    }
    if (dvm_cursor_text_ok(buf) && dvm_since_token(buf, filter))
        return true;
    dvm_fail(reply, "MAIL_CURSOR_STALE",
             "the agent's stored cursor is not a cursor; ack a fresh one",
             agent);
    return false;
}

static void dvm_pull(const struct zcl_command_request *req,
                     struct zcl_command_reply *reply, const char *maildir)
{
    struct dvm_pull_filter filter;
    struct dvm_pull_state *ps;
    struct dvm_page pg;
    char token[DVM_TOKEN_CAP];
    char stored[DVM_TOKEN_CAP];
    if (!dvm_pull_parse_filter(req, reply, &filter) ||
        !dvm_pull_resume_agent(req, reply, maildir, &filter, stored,
                               sizeof(stored)))
        return;
    ps = (struct dvm_pull_state *)zcl_calloc(1, sizeof(*ps),
                                             "devagent_mail.pull");
    memset(&pg, 0, sizeof(pg));
    pg.rows = (struct dvm_row *)zcl_calloc(DVM_PAGE_ROWS, sizeof(*pg.rows),
                                           "devagent_mail.page");
    if (!ps || !pg.rows) {
        free(ps);
        free(pg.rows);
        dvm_fail(reply, "MAIL_READ_FAILED", "cannot allocate one page",
                 maildir);
        return;
    }
    ps->cursor = filter.since;
    if (dvm_streams_list(maildir, reply, &filter, ps) &&
        dvm_streams_start(reply, &filter, ps)) {
        dvm_pull_page(ps, &filter, &pg);
        if (pg.n > 1)
            qsort(pg.rows, pg.n, sizeof(*pg.rows), dvm_row_cmp);
        if (dvm_token_build(ps, filter.since, token, sizeof(token)))
            dvm_pull_build_reply(reply, &pg, ps, token, filter.resumed);
        else
            dvm_fail(reply, "MAIL_READ_FAILED",
                     "the resume token exceeds its bound", maildir);
    }
    dvm_streams_close(ps);
    free(ps);
    free(pg.rows);
}

/* ── ack ─────────────────────────────────────────────────────────────────── */

/* Write text (len bytes) to tmp and atomically install it over path, per
 * platform. Returns NULL on success, or a dvm_fail() message/evidence pair
 * describing what failed (evidence is always one of tmp or path). Split out
 * of dvm_ack() so its own complexity does not fold both platforms' write
 * paths together. */
struct dvm_ack_write_result {
    const char *code;
    const char *message;
    const char *evidence;
};

#if defined(_WIN32)
static struct dvm_ack_write_result dvm_ack_write_cursor(
    const char *tmp, const char *path, const char *text, size_t len)
{
    struct platform_private_file file;
    platform_private_file_init(&file);
    if (!platform_private_file_create(tmp, &file))
        return (struct dvm_ack_write_result){
            "MAIL_WRITE_FAILED", "cannot create the private cursor", tmp};
    bool installed = platform_private_file_write_at(&file, text, len, 0) &&
        platform_private_file_replace(&file, tmp, path);
    if (!installed) {
        (void)platform_private_file_retire(&file, tmp);
        platform_private_file_close(&file);
        return (struct dvm_ack_write_result){
            "MAIL_WRITE_FAILED", "cannot install the private cursor", path};
    }
    platform_private_file_close(&file);
    return (struct dvm_ack_write_result){0};
}
#else
static struct dvm_ack_write_result dvm_ack_write_cursor(
    const char *tmp, const char *path, const char *text, size_t len)
{
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return (struct dvm_ack_write_result){
            "MAIL_WRITE_FAILED", "cannot record the cursor", tmp};
    (void)fchmod(fd, 0600);
    ssize_t w = write(fd, text, len);
    (void)close(fd);
    if (w != (ssize_t)len) {
        (void)unlink(tmp);
        return (struct dvm_ack_write_result){
            "MAIL_WRITE_FAILED", "short write of the cursor", tmp};
    }
    if (rename(tmp, path) != 0) {
        (void)unlink(tmp);
        return (struct dvm_ack_write_result){
            "MAIL_WRITE_FAILED", "cannot install the cursor file", path};
    }
    return (struct dvm_ack_write_result){0};
}
#endif

/* The cursor to store: a scalar (*token = NULL) or a next_since token.
 * False with a fail reply already written. */
static bool dvm_ack_cursor(const struct zcl_command_request *req,
                           struct zcl_command_reply *reply, long long *cursor,
                           const char **token)
{
    *token = dvm_str(req, "cursor");
    if (dvm_int(req, "cursor", cursor)) {
        *token = NULL; /* a number, or a numeric string */
        return true;
    }
    if (*token && strchr(*token, '|') && dvm_cursor_text_ok(*token))
        return true;
    dvm_fail(reply, "BAD_INPUT",
             "ack needs a non-negative cursor or a next_since token",
             "input.cursor missing or wrong shape");
    return false;
}

static void dvm_ack(const struct zcl_command_request *req,
                    struct zcl_command_reply *reply, const char *maildir)
{
    long long cursor = 0;
    char path[DVM_PATH_CAP];
    char tmp[DVM_PATH_CAP];
    char text[DVM_TOKEN_CAP + 2];
    const char *agent;
    size_t len;

    const char *token = NULL;
    if (!dvm_ack_cursor(req, reply, &cursor, &token))
        return;
    agent = dvm_str(req, "agent");
    if (!agent)
        agent = dvm_identity(req, "from");
    if (!dvm_cursor_name_ok(agent)) {
        dvm_fail(reply, "BAD_INPUT", "agent names the cursor owner",
                 "input.agent has an illegal spelling");
        return;
    }
    int path_length = snprintf(path, sizeof(path), "%s/cursor.%s", maildir, agent);
    int temp_length = snprintf(tmp, sizeof(tmp), "%s/.cursor.%s.%ld.tmp", maildir,
                               agent, (long)getpid());
    if (path_length <= 0 || (size_t)path_length >= sizeof(path) ||
        temp_length <= 0 || (size_t)temp_length >= sizeof(tmp)) {
        dvm_fail(reply, "MAIL_WRITE_FAILED", "cursor path exceeds its bound", maildir);
        return;
    }
    len = token ? (size_t)snprintf(text, sizeof(text), "%s\n", token)
                : (size_t)snprintf(text, sizeof(text), "%lld\n", cursor);
    if (len == 0 || len >= sizeof(text)) {
        dvm_fail(reply, "BAD_INPUT", "cursor too large to record",
                 "format budget exceeded");
        return;
    }
    /* Write to a temp file in the SAME directory, then rename it over the
     * cursor: rename(2) is atomic, so a crash mid-write leaves the previous
     * cursor intact instead of an empty file that would silently rewind or
     * lose every reader's position. */
    struct dvm_ack_write_result written = dvm_ack_write_cursor(tmp, path,
                                                               text, len);
    if (written.code) {
        dvm_fail(reply, written.code, written.message, written.evidence);
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", DVM_LEAF);
    (void)json_push_kv_str(&reply->data, "agent", agent);
    if (token)
        (void)json_push_kv_str(&reply->data, "cursor", token);
    else
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
    if (!dvm_mail_dir(maildir, sizeof(maildir), strcmp(action, "pull") != 0)) {
        dvm_fail(reply, "STATE_DIR_FAILED",
                 "cannot resolve the mail dir under the state root",
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
