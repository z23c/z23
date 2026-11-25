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
 * A private process lock covers sequence allocation through that write;
 * posting may wait for another local poster to finish this short section.
 * Windows also uses an owner-validated private handle and a nonblocking file
 * lock around the size/write pair. Both
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
 *           A successful post also returns next_since, parked at the end of
 *           every stream including the row just written, so a later pull
 *           does not replay that row and does not depend on the scalar.
 *   from    post: optional sender name (default $BOARD_AGENT, then $USER,
 *           then "local"). pull: optional exact-match sender filter.
 *   cursor  ack: required non-negative integer or next_since token; pull:
 *           optional second positional integer or token. Pull prefers explicit
 *           since, then explicit cursor, then the saved agent cursor. Composite
 *           ACK coverage requires the exact stream and a covering offset; its
 *           scalar floor alone does not acknowledge a row.
 *   agent   ack: optional name owning the cursor file (default: the same
 *           identity post uses). pull: without an explicit since or cursor, the page
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
 * with seq greater than the seq floor, in per-stream file order merged
 * across streams (see PAGING), plus `cursor` (the largest seq seen anywhere
 * in the dir, or the floor when empty) and `count`. Malformed lines are skipped, never fatal, and counted
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
 * a later page, never skipped. Rows keep the order of their stream's file;
 * a page repeatedly takes the stream whose next row sorts first by
 * (ts, from, seq), ties broken by stream name. The page is not re-sorted, so
 * a later row with an older ts stays after its stream's earlier rows. Only
 * complete lines are consumed; a last line still being written waits for the next pull.
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
 * it STARTS a token, so "docs/dev/DEVELOPING.md" passes and "/etc/passwd" does
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
 * the row fields plus `cursor` (the row's seq), `outbox`, and `delivery`:
 * "export_eligible" when the board exporter's route predicate accepts the
 * row (to another enrolled box, or back to the box a directive came from
 * under `ref`), else "local" (this box only). This is not receiver delivery
 * or acknowledgment evidence. `hint` is added for local mail to a name no
 * roster box holds. Pull returns
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
 * PROCESS RULE. No spawn, no shell, no popen()/system(), or peer wait. The
 * platform private-file helper may wait for a local post lock. Only local
 * filesystem operations below.
 */

#include "command/native_command.h"
#include "command/native_devagent.h"

#include "base/hex.h"
#include "sha3/sha3.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "zutf8/zutf8.h"
#include "platform/directory_compat.h"
#include "platform/private_file.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#if defined(_WIN32)
#include "platform/directory_transaction.h"
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

#ifdef ZCL_TESTING
static zcl_devagent_mail_test_hook_fn dvm_test_after_brief_probe;
static zcl_devagent_mail_test_hook_fn dvm_test_after_exact_read;

void zcl_devagent_mail_test_set_after_exact_read(zcl_devagent_mail_test_hook_fn hook)
{
    dvm_test_after_exact_read = hook;
}
static size_t dvm_test_max_seq_scans;
static unsigned long long dvm_test_prefix_bytes;
static unsigned long long dvm_test_content_reads;
static size_t dvm_test_ack_writes;

void zcl_devagent_mail_test_set_after_brief_probe(
    zcl_devagent_mail_test_hook_fn hook)
{
    dvm_test_after_brief_probe = hook;
}

size_t zcl_devagent_mail_test_max_seq_scans(bool reset)
{
    size_t scans = dvm_test_max_seq_scans;
    if (reset)
        dvm_test_max_seq_scans = 0;
    return scans;
}

unsigned long long zcl_devagent_mail_test_prefix_bytes(bool reset)
{
    unsigned long long n = dvm_test_prefix_bytes;
    if (reset)
        dvm_test_prefix_bytes = 0;
    return n;
}

unsigned long long zcl_devagent_mail_test_content_reads(bool reset)
{
    unsigned long long n = dvm_test_content_reads;
    if (reset)
        dvm_test_content_reads = 0;
    return n;
}

size_t zcl_devagent_mail_test_ack_writes(bool reset)
{
    size_t n = dvm_test_ack_writes;
    if (reset)
        dvm_test_ack_writes = 0;
    return n;
}
#endif

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

/* Parse one 1-3 digit octet <= 255 at *pp; on success advance *pp past it. */
static bool dvm_ipv4_octet(const char **pp, unsigned *out)
{
    const char *q = *pp;
    if (!isdigit((unsigned char)*q))
        return false;
    unsigned v = 0;
    int digits = 0;
    while (isdigit((unsigned char)*q) && digits < 3) {
        v = v * 10u + (unsigned)(*q - '0');
        q++;
        digits++;
    }
    if (isdigit((unsigned char)*q))
        return false; /* 4+ digit run: not an octet */
    if (v > 255)
        return false;
    *out = v;
    *pp = q;
    return true;
}

static bool dvm_has_ipv4(const char *s)
{
    /* Four dot-separated 1-3 digit groups, each <= 255, bounded by
     * non-digit/non-dot on both sides. */
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p))
            continue;
        if (p != s && (isdigit((unsigned char)p[-1]) || p[-1] == '.'))
            continue;
        const char *q = p;
        int g = 0;
        for (; g < 4; g++) {
            unsigned v;
            if (!dvm_ipv4_octet(&q, &v))
                break;
            if (g < 3) {
                if (*q != '.')
                    break;
                q++;
            }
        }
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
 * INSIDE "docs/dev/DEVELOPING.md" (a relative path, which is allowed and
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
    char stream[129];
    long long row_offset;
    long long row_end;
    char row_sha3[65];
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
    char observed_disposition[16];
    char observed_stream[129], observed_sha3[65];
    long long observed_offset, observed_seq;
};

/* Domain includes its NUL; record includes the original terminating newline. */
static void dvm_row_hash(const char *raw, size_t len, char hex[65])
{
    static const char domain[] = "z23.devagent.mail.row.v1";
    struct sha3_256_ctx ctx;
    unsigned char sum[32];
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&ctx, (const unsigned char *)raw, len);
    sha3_256_finalize(&ctx, sum);
    zcl_hex_encode(sum, sizeof(sum), hex);
}

static bool dvm_unique_fields(const struct json_value *object)
{
    if (!object || object->type != JSON_OBJ) return false;
    for (size_t i = 0; i < object->num_children; i++) {
        if (!object->keys[i]) return false;
        for (size_t j = 0; j < i; j++)
            if (!strcmp(object->keys[i], object->keys[j])) return false;
    }
    return true;
}

static bool dvm_observed_locator_strings(const struct json_value *stream,
                                         const struct json_value *hash)
{
    unsigned char decoded[32];
    return stream && stream->type == JSON_STR && json_get_str(stream) &&
        strlen(json_get_str(stream)) < 129 && hash && hash->type == JSON_STR &&
        json_get_str(hash) && zcl_hex_decode_lower(json_get_str(hash), decoded, sizeof(decoded));
}

static bool dvm_observed_locator_values(const struct json_value *stream,
    const struct json_value *hash, const struct json_value *offset,
    const struct json_value *seq, const struct json_value *read)
{
    return dvm_observed_locator_strings(stream, hash) &&
        offset && offset->type == JSON_INT && json_get_int(offset) >= 0 &&
        seq && seq->type == JSON_INT && json_get_int(seq) > 0 &&
        read && read->type == JSON_BOOL && json_get_bool(read);
}

static void dvm_observed_source(const struct json_value *raw,
                                const struct json_value *d, struct dvm_row *r)
{
    if (!dvm_unique_fields(raw) || !dvm_unique_fields(d)) return;
    const struct json_value *stream = json_get(d, "stream");
    const struct json_value *hash = json_get(d, "row_sha3");
    const struct json_value *offset = json_get(d, "row_offset");
    const struct json_value *seq = json_get(d, "seq");
    const struct json_value *read = json_get(d, "read");
    if (!dvm_observed_locator_values(stream, hash, offset, seq, read)) return;
    (void)snprintf(r->observed_stream, sizeof(r->observed_stream), "%s", json_get_str(stream));
    (void)snprintf(r->observed_sha3, sizeof(r->observed_sha3), "%s", json_get_str(hash));
    r->observed_offset = json_get_int(offset);
    r->observed_seq = json_get_int(seq);
}

/* Pulled metadata is only an unverified hint; it cannot complete work. */
static bool dvm_observed_disposition(const char *line, struct dvm_row *r)
{
    if (!strstr(line, "\"steer_disposition\"")) return true;
    struct json_value raw;
    json_init(&raw);
    bool ok = json_read(&raw, line, strlen(line)) && raw.type == JSON_OBJ;
    const struct json_value *d = ok ? json_get(&raw, "steer_disposition") : NULL;
    if (d) {
        (void)snprintf(r->observed_disposition, sizeof(r->observed_disposition), "UNVERIFIED");
        const struct json_value *v = d->type == JSON_OBJ ? json_get(d, "state") : NULL;
        const char *state = v && v->type == JSON_STR ? json_get_str(v) : NULL;
        if (state && (!strcmp(state, "ACCEPTED") || !strcmp(state, "DEFERRED") ||
                      !strcmp(state, "BLOCKED")))
            (void)snprintf(r->observed_disposition, sizeof(r->observed_disposition), "%s", state);
        dvm_observed_source(&raw, d, r);
    }
    json_free(&raw);
    return ok;
}

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
    return dvm_observed_disposition(line, r);
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
    const char *disposition;
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
  utf8_info = {"BAD_INPUT", "body and ref must be valid UTF-8",
               "input.body or input.ref has invalid UTF-8"},
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
    if (!zutf8_validate_n(in->body, strlen(in->body)) ||
        !zutf8_validate_n(in->ref, strlen(in->ref)))
        return &utf8_info;
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

/* Next seq: one plus the largest seq already present. The caller holds the
 * mail post lock through the append, so concurrent posters cannot reuse it. */
static bool dvm_post_next_seq(const char *outbox, long long *next)
{
    long long seq = 0;
    FILE *f = fopen(outbox, "r");
    if (!f) {
        if (errno != ENOENT) return false;
        *next = 1;
        return true;
    }
    char buf[DVM_LINE_CAP];
    while (fgets(buf, sizeof(buf), f)) {
        long long s;
        size_t len = strlen(buf);
        if (len == 0 || buf[len - 1] != '\n' ||
            !dvm_line_int(buf, "seq", &s) || s < 0 || s == LLONG_MAX) {
            (void)fclose(f);
            return false;
        }
        if (s >= seq) seq = s + 1;
    }
    bool read_ok = !ferror(f);
    if (fclose(f) != 0) read_ok = false;
    if (!read_ok) return false;
    *next = seq < 1 ? 1 : seq;
    return true;
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

static const char *const dvm_steer_names[] = {
    "seq", "steer_key", "to", "kind", "body", "from", "ref", "sender_binding"
};

static bool dvm_disposition_equal(const struct json_value *row, const char *expected)
{
    const struct json_value *v = json_get(row, "steer_disposition");
    size_t count = 0;
    for (size_t i = 0; i < row->num_children; i++)
        if (row->keys[i] && !strcmp(row->keys[i], "steer_disposition")) count++;
    if (count > 1) return false;
    if (!expected) return v == NULL;
    if (!v || v->type != JSON_OBJ) return false;
    char wire[2048];
    size_t n = json_write(v, wire, sizeof(wire));
    return n > 0 && n < sizeof(wire) && strcmp(wire, expected) == 0;
}

static bool dvm_steer_values_equal(const struct json_value *row,
                                   const size_t count[8],
                                   const struct dvm_post_input *in)
{
    const char *values[] = {in->to, in->kind, in->body, in->from, in->ref, in->sender_binding};
    for (size_t i = 0; i < 6; i++) {
        const struct json_value *v = json_get(row, dvm_steer_names[i + 2]);
        const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
        if (!s && i == 5 && count[i + 2] == 0) s = "";
        if (count[i + 2] > 1 || !s || strcmp(s, values[i]) != 0) return false;
    }
    return dvm_disposition_equal(row, in->disposition);
}

static bool dvm_steer_key_valid(const struct json_value *kv, size_t count)
{
    unsigned char decoded[32];
    return count == 1 && kv && kv->type == JSON_STR && json_get_str(kv) &&
        strlen(json_get_str(kv)) == 64 &&
        zcl_hex_decode_lower(json_get_str(kv), decoded, sizeof(decoded));
}

static int dvm_steer_row_object(const struct json_value *row, const char *key,
                                const struct dvm_post_input *in, long long *seq)
{
    size_t count[8] = {0};
    for (size_t i = 0; i < row->num_children; i++)
        for (size_t j = 0; j < 8; j++)
            if (row->keys[i] && strcmp(row->keys[i], dvm_steer_names[j]) == 0) count[j]++;
    const struct json_value *v = json_get(row, "seq");
    if (count[0] != 1 || !v || v->type != JSON_INT ||
        json_get_int(v) < 0 || json_get_int(v) == LLONG_MAX) return -1;
    *seq = json_get_int(v);
    if (!count[1]) return 0;
    const struct json_value *kv = json_get(row, "steer_key");
    if (!dvm_steer_key_valid(kv, count[1])) return -1;
    if (strcmp(json_get_str(kv), key) != 0) return 0;
    return dvm_steer_values_equal(row, count, in) ? 1 : 2;
}

/* Validate each source sequence and compare the exact keyed delivery. */
static int dvm_steer_row(const char *line, const char *key,
                         const struct dvm_post_input *in, long long *seq)
{
    struct json_value row;
    json_init(&row);
    if (!json_read(&row, line, strlen(line)) || row.type != JSON_OBJ) {
        json_free(&row); return -1;
    }
    int result = dvm_steer_row_object(&row, key, in, seq);
    json_free(&row);
    return result;
}

/* One pass supplies both the matching source row and the next sequence. */
static int dvm_steer_scan(const char *path, const char *key,
                          const struct dvm_post_input *in, long long *seq,
                          long long *next)
{
    *next = 1;
    FILE *f = fopen(path, "rb");
    if (!f) return errno == ENOENT ? 0 : -1;
    char line[DVM_LINE_CAP];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t n = strlen(line);
        if (!n || line[n - 1] != '\n') { found = -1; break; }
        long long candidate = -1;
        int r = dvm_steer_row(line, key, in, &candidate);
        if (r < 0 || (r > 0 && found > 0)) { found = -1; break; }
        if (candidate >= *next) *next = candidate + 1;
        if (r > 0) { found = r; *seq = candidate; }
    }
    if (ferror(f)) found = -1;
    if (fclose(f) != 0) found = -1;
    return found;
}

static bool dvm_steer_sync(const char *outbox, const char *maildir)
{
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = platform_private_file_open_locked_create_wait(outbox, &file);
    if (ok) ok = platform_private_file_flush(&file);
    platform_private_file_close(&file);
    return ok && platform_private_parent_flush(maildir);
}

/* The reply's `delivery` (and `hint`, when local mail names no roster box). */
static void dvm_post_delivery(struct zcl_command_reply *reply, const char *to,
                              const char *ref)
{
    struct zcl_boardmail_delivery where;
    zcl_devagent_boardmail_delivery(to, ref, &where);
    (void)json_push_kv_str(&reply->data, "delivery", where.label);
    if (where.hint[0])
        (void)json_push_kv_str(&reply->data, "hint", where.hint);
}

static void dvm_post_attach_resume(struct zcl_command_reply *reply,
                                   const char *maildir);

static bool dvm_post_append(const struct dvm_post_input *in,
                            struct zcl_command_reply *reply,
                            const char *maildir, const char *outbox,
                            const char *ts, const char *key, long long seq)
{
    char line[DVM_LINE_CAP];
    size_t len;
    const struct dvm_fail_info *invalid = dvm_post_compose(in, seq, ts, line, sizeof(line), &len);
    if (invalid) {
        dvm_fail(reply, invalid->code, invalid->message, invalid->evidence);
        return false;
    }
    if (key) {
        int n = snprintf(line + len - 2, sizeof(line) - len + 2,
                         ",\"steer_key\":\"%s\"}\n", key);
        if (n <= 0 || (size_t)n >= sizeof(line) - len + 2) {
            dvm_fail(reply, "BAD_INPUT", "keyed row too large", outbox);
            return false;
        }
        len = len - 2 + (size_t)n;
    }
    if (in->disposition) {
        int n = snprintf(line + len - 2, sizeof(line) - len + 2,
                         ",\"steer_disposition\":%s}\n", in->disposition);
        if (n <= 0 || (size_t)n >= sizeof(line) - len + 2) {
            dvm_fail(reply, "BAD_INPUT", "disposition row too large", outbox);
            return false;
        }
        len = len - 2 + (size_t)n;
    }
    bool written = dvm_post_write_line(outbox, line, len) &&
                   (!key || dvm_steer_sync(outbox, maildir));
    if (!written)
        dvm_fail(reply, "MAIL_WRITE_FAILED", "cannot append the private outbox", outbox);
    return written;
}

/* post.lock serializes keyed lookup, sequence allocation and append. */
static bool dvm_probe_absent(bool probe, int existing,
    struct platform_private_file *lock, struct zcl_command_reply *reply)
{
    if (!probe || existing != 0) return false;
    platform_private_file_close(lock);
    dvm_fail(reply, "MAIL_SOURCE_NOT_FOUND", "keyed source is absent", "outbox");
    return true;
}

static bool dvm_post_locked(const struct dvm_post_input *in,
                            struct zcl_command_reply *reply,
                            const char *maildir, const char *outbox,
                            const char *ts, const char *key, bool require_existing, bool probe,
                            long long *seq, bool *duplicate)
{
    char lock_path[DVM_PATH_CAP];
    int n = snprintf(lock_path, sizeof(lock_path), "%s/post.lock", maildir);
    if (n <= 0 || (size_t)n >= sizeof(lock_path)) {
        dvm_fail(reply, "MAIL_WRITE_FAILED", "mail lock path exceeds its bound", maildir);
        return false;
    }
    struct platform_private_file lock;
    platform_private_file_init(&lock);
    if (!platform_private_file_open_locked_create_wait(lock_path, &lock)) {
        dvm_fail(reply, "MAIL_WRITE_FAILED", "cannot lock the private outbox", lock_path);
        return false;
    }
    long long next_seq = 1;
    int existing = key ? dvm_steer_scan(outbox, key, in, seq, &next_seq) : 0;
    if (dvm_probe_absent(probe, existing, &lock, reply)) return false;
    if (existing < 0 || existing == 2 || (require_existing && existing == 0)) {
        platform_private_file_close(&lock);
        dvm_fail(reply, existing == 2 ? "IDEMPOTENCY_CONFLICT" : "MAIL_READ_FAILED",
                 "cannot reconcile keyed post", outbox);
        return false;
    }
    if (existing == 1) {
        bool synced = dvm_steer_sync(outbox, maildir);
        platform_private_file_close(&lock);
        if (!synced) dvm_fail(reply, "MAIL_WRITE_FAILED", "cannot sync keyed post", outbox);
        *duplicate = synced;
        return synced;
    }
    if (key) *seq = next_seq;
    else if (!dvm_post_next_seq(outbox, seq)) {
        platform_private_file_close(&lock);
        dvm_fail(reply, "MAIL_READ_FAILED", "cannot read the private outbox", outbox);
        return false;
    }
    bool written = dvm_post_append(in, reply, maildir, outbox, ts, key, *seq);
    platform_private_file_close(&lock);
    return written;
}

static void dvm_post(const struct zcl_command_request *req,
                     struct zcl_command_reply *reply, const char *maildir,
                     const char *steer_key, bool require_existing,
                     const char *disposition, bool probe)
{
    struct dvm_post_input in;
    char outbox[DVM_PATH_CAP];
    char ts[40];
    const struct dvm_fail_info *invalid;
    const char *code;
    char msg[256];
    long long seq = 0;
    time_t now;
    struct tm tm_utc;
    bool duplicate = false;

    if (!req || !req->input) {
        dvm_fail(reply, "BAD_INPUT", "dev.agent.mail post needs to, kind, body",
                 "request.input was missing");
        return;
    }
    in.disposition = disposition;
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
    now = platform_time_wall_time_t();
    if (!platform_time_utc_tm(now, &tm_utc) ||
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0) {
        dvm_fail(reply, "MAIL_WRITE_FAILED", "cannot encode the message timestamp",
                 "UTC time conversion failed");
        return;
    }

    if (!dvm_post_locked(&in, reply, maildir, outbox, ts, steer_key,
                         require_existing, probe, &seq, &duplicate))
        return;
    if (duplicate) {
        (void)json_push_kv_int(&reply->data, "seq", seq);
        (void)json_push_kv_bool(&reply->data, "duplicate", true);
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = 0;
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
    dvm_post_delivery(reply, to, ref);
    dvm_post_attach_resume(reply, maildir);
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
/* +64 holds the floor and a trailing ",seq.max:<int64>" hint. */
#define DVM_TOKEN_CAP (DVM_STREAMS_MAX * (DVM_STREAM_NAME_MAX + 24u) + 64u)

struct dvm_pull_filter {
    zcl_devagent_mail_ref_filter keep;
    void *keep_ctx;
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
    bool read_failed;
    bool have_seen_max; /* token or this scan already knows the max seq */
    struct dvm_stream *streams;
    size_t nstreams;
    long long cursor;  /* largest seq seen anywhere, or the floor */
    long long seen_max; /* carried max; not a stream and not the floor */
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
    const char *cursor_key = json_get(req->input, "since") ? "since" : "cursor";
    v = json_get(req->input, cursor_key);
    if (v)
        filter->resumed = "since";
    if (v && !dvm_int(req, cursor_key, &filter->since) &&
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
        size_t name_length = strlen(ent->d_name);
        why = name_length >= sizeof(ps->streams[0].name)
            ? "MAIL_STREAM_NAME_INVALID"
            : dvm_stream_refusal(ps, filter, ent->d_name);
        if (why) {
            dvm_stream_fail(reply, why, ent->d_name);
            (void)closedir(d);
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
        memcpy(s->name, ent->d_name, name_length + 1u);
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

/* seq.max is the largest seq already observed. It is not a stream, so it
 * must not consume a stream slot or move the caller's floor. */
static void dvm_note_seq_max(struct dvm_pull_state *ps, long long seq)
{
    if (seq < 0)
        return;
    if (!ps->have_seen_max || seq > ps->seen_max)
        ps->seen_max = seq;
    ps->have_seen_max = true;
}

static void dvm_raise_seen_max(struct dvm_pull_state *ps)
{
    if (ps->have_seen_max && ps->seen_max > ps->cursor)
        ps->cursor = ps->seen_max;
}

static bool dvm_cursor_duplicate(char names[][DVM_STREAM_NAME_MAX + 1],
                                 size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (!strcmp(names[i], names[count])) return true;
    return false;
}

static bool dvm_cursor_covered_entries(const char *p, const char *stream,
                                       long long row_end, bool *covered)
{
    char names[DVM_STREAMS_MAX][DVM_STREAM_NAME_MAX + 1];
    size_t count = 0;
    *covered = false;
    while (*p) {
        long long offset;
        const char *start = p;
        if (count == DVM_STREAMS_MAX ||
            dvm_token_entry(p, names[count], sizeof(names[count]), &offset, &p) ||
            dvm_cursor_duplicate(names, count)) return false;
        if (!strcmp(names[count], stream) && row_end <= offset) *covered = true;
        count++;
        if (p > start && p[-1] == ',' && !*p) return false;
    }
    return true;
}

/* Composite syntax validation is independent from row coverage. */
bool zcl_devagent_mail_cursor_valid(const char *token)
{
    struct dvm_pull_filter filter = {0};
    bool ignored;
    return token && strlen(token) < DVM_TOKEN_CAP &&
        dvm_since_token(token, &filter) &&
        dvm_cursor_covered_entries(filter.token, "", 0, &ignored);
}

bool zcl_devagent_mail_cursor_covers(const char *token, const char *stream,
                                     long long row_end, long long seq)
{
    struct dvm_pull_filter filter = {0};
    bool covered;
    if (!token || !stream || row_end < 0 || seq < 0 ||
        strlen(token) >= DVM_TOKEN_CAP || !dvm_since_token(token, &filter) ||
        !dvm_cursor_covered_entries(filter.token, stream, row_end, &covered))
        return false;
    return covered;
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
        if (strcmp(name, "seq.max") == 0) {
            dvm_note_seq_max(ps, off);
            continue;
        }
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
static bool dvm_row_matches(const struct dvm_row *r,
                            const struct dvm_pull_filter *filter)
{
    return r->seq > filter->since &&
        (!filter->from || strcmp(r->from, filter->from) == 0) &&
        (!filter->to || strcmp(r->to, filter->to) == 0) &&
        (!filter->ref || strcmp(r->ref, filter->ref) == 0) &&
        (!filter->kind || strcmp(r->kind, filter->kind) == 0) &&
        (!filter->keep || filter->keep(r->ref, filter->keep_ctx));
}

static bool dvm_row_wanted(const char *buf, const struct dvm_pull_filter *filter,
                           struct dvm_row *r, struct dvm_pull_state *ps)
{
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        --len;
    if (len == 0)
        return false;
    if (!dvm_parse_row(buf, r)) {
        ps->skipped++; /* malformed line: skipped, never fatal */
        return false;
    }
    return dvm_row_matches(r, filter);
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
        long long start = (long long)ftell(s->f);
        if (start < 0) { ps->read_failed = true; return; }
        enum dvm_line_kind k = dvm_read_line(s->f, ps->line, sizeof(ps->line));
        long long end;
        if (k == DVM_LINE_EOF || k == DVM_LINE_PARTIAL)
            return;
        end = (long long)ftell(s->f);
        if (end < start) { ps->read_failed = true; return; }
        if (k == DVM_LINE_LONG) {
            ps->skipped++;
            s->off = end;
            continue;
        }
        char hash[65];
        size_t raw_len = strlen(ps->line);
        if ((unsigned long long)(end - start) != raw_len) {
            ps->skipped++;
            s->off = end;
            continue;
        }
        if (!dvm_row_wanted(ps->line, filter, &s->head, ps)) {
            s->off = end;
            continue;
        }
        dvm_row_hash(ps->line, raw_len, hash);
        (void)snprintf(s->head.stream, sizeof(s->head.stream), "%s", s->name);
        s->head.row_offset = start;
        s->head.row_end = end;
        memcpy(s->head.row_sha3, hash, sizeof(hash));
        s->head_end = end;
        s->has_head = true;
        return;
    }
}

/* Bytes this max scan read. A read that starts before the resume offset is
 * acknowledged prefix: the caller already has those rows. */
static void dvm_count_scan(long long start, long long end, long long prefix_at)
{
#ifdef ZCL_TESTING
    long long cut;
    if (end <= start)
        return;
    dvm_test_content_reads += (unsigned long long)(end - start);
    if (start >= prefix_at)
        return;
    cut = end < prefix_at ? end : prefix_at;
    if (cut > start)
        dvm_test_prefix_bytes += (unsigned long long)(cut - start);
#else
    (void)start;
    (void)end;
    (void)prefix_at;
#endif
}

/* 1 = scan from the current position. 0 = the ack already covers this
 * file, so its body is not a poll. -1 = the position could not be read. */
static int dvm_max_seq_position(FILE *f, const struct dvm_stream *s,
                                struct dvm_pull_state *ps)
{
    struct stat st;
    if (fstat(fileno(f), &st) != 0) {
        ps->read_failed = true;
        return -1;
    }
    if (ps->have_seen_max && s->off >= (long long)st.st_size)
        return 0;
    if (ps->have_seen_max && s->off > 0 &&
        fseek(f, (long)s->off, SEEK_SET) != 0) {
        ps->read_failed = true;
        return -1;
    }
    return 1;
}

/* The largest seq in one stream. A token that already carries seq.max reads
 * only the suffix after the resume offset; the first page still reads all. */
static void dvm_stream_max_seq(const struct dvm_stream *s,
                               struct dvm_pull_state *ps)
{
#ifdef ZCL_TESTING
    dvm_test_max_seq_scans++;
#endif
    FILE *f = fopen(s->path, "rb");
    struct dvm_row r;
    int placed;
    if (!f)
        return;
    placed = dvm_max_seq_position(f, s, ps);
    if (placed != 1) {
        (void)fclose(f);
        return;
    }
    for (;;) {
        long long start = (long long)ftell(f);
        enum dvm_line_kind k = dvm_read_line(f, ps->line, sizeof(ps->line));
        long long end = (long long)ftell(f);
        if (start >= 0 && end >= start)
            dvm_count_scan(start, end, s->off);
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
    return 352u + dvm_json_len(r->stream) + dvm_json_len(r->ts) + dvm_json_len(r->from) +
           dvm_json_len(r->to) + dvm_json_len(r->kind) +
           dvm_json_len(r->body) + dvm_json_len(r->ref) +
           dvm_json_len(r->sender_binding) + dvm_json_len(r->board_post) +
           dvm_json_len(r->board_signer) + (r->observed_disposition[0] ? 256u + dvm_json_len(r->observed_disposition) + dvm_json_len(r->observed_stream) : 0);
}

/* The stream whose next unread row sorts first by (ts, from, seq); a tie goes
 * to the stream whose name sorts first. This chooses the next row of the
 * merge, not a global order: each stream still yields its rows in file
 * order. NULL when every stream is drained. */
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

/* Byte length of a stream, accepted as a resume offset only when the file
 * is empty or its last byte is a newline. */
static bool dvm_file_end(const char *path, long long *end)
{
    FILE *f = fopen(path, "rb");
    struct stat st;
    int last = 0;
    if (!f) return false;
    if (fstat(fileno(f), &st) != 0 || st.st_size < 0) {
        fclose(f);
        return false;
    }
    *end = (long long)st.st_size;
    if (*end == 0) {
        fclose(f);
        return true;
    }
    if (fseek(f, (long)(*end - 1), SEEK_SET) != 0 || (last = fgetc(f)) < 0) {
        fclose(f);
        return false;
    }
    fclose(f);
    return last == '\n';
}

/* Record one directory entry. A non-stream is skipped. A stream that cannot
 * be parked on a line boundary fails the token. */
static bool dvm_resume_add(struct dvm_pull_state *ps, const char *maildir,
                           const char *name)
{
    struct dvm_stream *s;
    long long end = 0;
    size_t n;
    int w;
    if (!dvm_is_stream_name(name)) return true;
    if (!dvm_cursor_name_ok(name) || ps->nstreams >= DVM_STREAMS_MAX)
        return false;
    s = &ps->streams[ps->nstreams];
    n = strlen(name);
    if (n >= sizeof(s->name)) return false;
    memcpy(s->name, name, n + 1);
    w = snprintf(s->path, sizeof(s->path), "%s/%s", maildir, name);
    if (w <= 0 || (size_t)w >= sizeof(s->path)) return false;
    if (!dvm_file_end(s->path, &end)) return false;
    s->off = end;
    ps->nstreams++;
    return true;
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
    if (!ps->have_seen_max)
        return true;
    n = snprintf(out + used, cap - used, "%sseq.max:%lld",
                 (used > 0 && out[used - 1] != '|') ? "," : "",
                 ps->seen_max);
    return n > 0 && (size_t)n < cap - used;
}

/* Park every current stream at its end. Floor stays 0: a positive scalar
 * floor is refused once a second stream exists. */
static bool dvm_post_resume_token(const char *maildir, char *token, size_t cap)
{
    DIR *d = opendir(maildir);
    struct dirent *ent;
    struct dvm_pull_state ps;
    bool add_ok = true;
    bool ok = false;
    if (!d) return false;
    memset(&ps, 0, sizeof(ps));
    ps.streams = (struct dvm_stream *)zcl_calloc(
        DVM_STREAMS_MAX, sizeof(*ps.streams), "devagent_mail.resume");
    if (!ps.streams) {
        closedir(d);
        return false;
    }
    while (add_ok && (ent = readdir(d)) != NULL)
        add_ok = dvm_resume_add(&ps, maildir, ent->d_name);
    if (add_ok && ps.nstreams > 1)
        qsort(ps.streams, ps.nstreams, sizeof(*ps.streams), dvm_stream_name_cmp);
    if (add_ok && ps.nstreams > 0)
        ok = dvm_token_build(&ps, 0, token, cap);
    free(ps.streams);
    closedir(d);
    return ok;
}

static void dvm_post_attach_resume(struct zcl_command_reply *reply,
                                   const char *maildir)
{
    char token[DVM_TOKEN_CAP];
    if (!dvm_post_resume_token(maildir, token, sizeof(token))) return;
    (void)json_push_kv_str(&reply->data, "next_since", token);
}

/* ── the brief's window ── */

/* Where a stream of `size` bytes is read from when only its newest
 * `window` bytes are wanted: `from` when that already is a line start,
 * else the first line start after it, so the window is whole rows and at
 * most one row shorter than asked. 0 when no line start follows: the cut
 * falls inside the last line, which has no end yet (a writer may still be
 * appending it), and that stream is read whole rather than skipped past
 * the row being written. */
static long long dvm_window_start(FILE *f, long long from, long long size)
{
    long long at;
    if (from <= 0)
        return 0;
    if (fseek(f, (long)(from - 1), SEEK_SET) != 0)
        return 0;
    if (fgetc(f) == '\n')
        return from;
    for (at = from; at < size; at++) {
        int c = fgetc(f);
        if (c < 0)
            return 0;
        if (c == '\n')
            return at + 1;
    }
    return 0;
}

/* Record one directory entry for the window token. A non-stream is
 * skipped. False when a stream cannot be named, opened or fitted: the
 * caller then hands out no token and the brief reads everything. A size
 * or first whole row that cannot be measured parks the stream at 0, so
 * that one is read whole too. */
static bool dvm_window_add(struct dvm_pull_state *ps, const char *maildir,
                           const char *name, long long window)
{
    struct dvm_stream *s;
    struct stat st;
    FILE *f;
    size_t n;
    int w;
    if (!dvm_is_stream_name(name))
        return true;
    if (!dvm_cursor_name_ok(name) || ps->nstreams >= DVM_STREAMS_MAX)
        return false;
    s = &ps->streams[ps->nstreams];
    n = strlen(name);
    if (n >= sizeof(s->name))
        return false;
    memcpy(s->name, name, n + 1);
    w = snprintf(s->path, sizeof(s->path), "%s/%s", maildir, name);
    if (w <= 0 || (size_t)w >= sizeof(s->path))
        return false;
    f = fopen(s->path, "rb");
    if (!f)
        return false;
    s->off = 0;
    if (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
        (long long)st.st_size > window)
        s->off = dvm_window_start(f, (long long)st.st_size - window,
                                  (long long)st.st_size);
    (void)fclose(f);
    ps->nstreams++;
    return true;
}

/* Every stream of the mail dir, parked for a window of `window` bytes.
 * False when one cannot be named, opened or fitted, or the dir cannot be
 * read: the caller then hands out no token and the brief reads everything
 * through the pull, which makes the same checks it always made. */
static bool dvm_window_list(const char *maildir, long long window,
                            struct dvm_pull_state *ps)
{
    DIR *d = opendir(maildir);
    struct dirent *ent;
    bool ok = d != NULL;
#if defined(_WIN32)
    uintptr_t retained = 0;
    if (d && !platform_private_directory_open_validated_traverse(maildir,
                                                                &retained)) {
        (void)closedir(d);
        return false;
    }
    if (d)
        platform_private_directory_close(retained);
#endif
    while (ok && (ent = readdir(d)) != NULL)
        ok = dvm_window_add(ps, maildir, ent->d_name, window);
    if (d)
        (void)closedir(d);
    return ok;
}

/* One entry of the caller's token: a stream it names starts no later than
 * the position it names, because the brief resolves what came after that
 * position against these rows. */
static void dvm_window_resume_entry(struct dvm_pull_state *ps,
                                     const char *name, long long off)
{
    for (size_t i = 0; i < ps->nstreams; i++) {
        struct dvm_stream *s = &ps->streams[i];
        if (strcmp(s->name, name) != 0)
            continue;
        s->named = true;
        if (s->off > off)
            s->off = off;
    }
}

/* Fold the caller's token `since` into the parked streams. A stream the
 * token does not name is read whole by the resume, so it starts at its
 * beginning here too; one the token names that the dir no longer holds
 * changes nothing. False when `since` is not a token this leaf hands out:
 * the caller then reads everything. */
static bool dvm_window_resume(struct dvm_pull_state *ps, const char *since)
{
    struct dvm_pull_filter filter = {0};
    char name[DVM_STREAM_NAME_MAX + 1];
    const char *p;
    long long off;
    if (!since || !since[0])
        return true;
    /* The leaf's own rule for a token it hands out, then its entries. */
    if (!zcl_devagent_mail_cursor_valid(since) || !dvm_since_token(since, &filter))
        return false;
    p = filter.token;
    while (*p) {
        if (dvm_token_entry(p, name, sizeof(name), &off, &p))
            return false;
        dvm_window_resume_entry(ps, name, off);
    }
    for (size_t i = 0; i < ps->nstreams; i++)
        if (!ps->streams[i].named)
            ps->streams[i].off = 0;
    return true;
}

/* Whether any stream starts past its beginning: older rows exist that a
 * walk from this token does not read. */
static bool dvm_window_cut(const struct dvm_pull_state *ps)
{
    for (size_t i = 0; i < ps->nstreams; i++)
        if (ps->streams[i].off > 0)
            return true;
    return false;
}

/* "<floor>|<name>:<offset>,..." parking every stream at the start of its
 * newest `window` bytes, in name order, the same shape a post returns:
 * the pull that resumes from it needs no other rule. Floor 0, as a
 * positive scalar floor is refused once a second stream exists. */
bool zcl_devagent_mail_brief_window(char *token, size_t cap, long long window,
                                    const char *since, bool *cut)
{
    struct dvm_pull_state ps;
    char maildir[DVM_PATH_CAP];
    bool ok;
    if (cut)
        *cut = false;
    if (!token || !dvm_mail_dir(maildir, sizeof(maildir), false))
        return false;
    memset(&ps, 0, sizeof(ps));
    ps.streams = (struct dvm_stream *)zcl_calloc(
        DVM_STREAMS_MAX, sizeof(*ps.streams), "devagent_mail.window");
    if (!ps.streams)
        return false;
    ok = window > 0 && dvm_window_list(maildir, window, &ps);
    if (ok && ps.nstreams > 1)
        qsort(ps.streams, ps.nstreams, sizeof(*ps.streams),
              dvm_stream_name_cmp);
    ok = ok && dvm_window_resume(&ps, since) && ps.nstreams > 0 &&
         dvm_token_build(&ps, 0, token, cap);
    if (ok && cut)
        *cut = dvm_window_cut(&ps);
    free(ps.streams);
    return ok;
}

_Static_assert(ZCL_DEVAGENT_MAIL_LINE_CAP == DVM_LINE_CAP,
               "presence line cap matches the pull");

/* A role suffix: 1..32 of letters, digits, '.', '_' or '-'. The same
 * alphabet the steer leaf accepts, so a longer or marked ref cannot
 * take a real role's slot. */
static bool dvm_role_token(const char *s)
{
    size_t i, n;
    if (!s || !s[0])
        return false;
    n = strlen(s);
    if (n > 32u)
        return false;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isalnum(c) || c == '.' || c == '_' || c == '-')
            continue;
        return false;
    }
    return true;
}

/* The role of a presence note, or false when this line is not one the
 * steer leaf would accept. The prefix is nine bytes. */
static bool dvm_presence_role_of(const char *line, char *role, size_t cap)
{
    char kind[32];
    char ref[256];
    const char *suffix;
    size_t n;
    if (!dvm_line_str(line, "kind", kind, sizeof(kind)) ||
        strcmp(kind, "note") != 0)
        return false;
    if (!dvm_line_str(line, "ref", ref, sizeof(ref)))
        return false;
    if (strncmp(ref, "presence-", sizeof("presence-") - 1) != 0)
        return false;
    suffix = ref + (sizeof("presence-") - 1);
    n = strlen(suffix);
    if (!dvm_role_token(suffix) || n + 1 > cap)
        return false;
    memcpy(role, suffix, n + 1);
    return true;
}

/* A kept line. `key` is the role or the sender. `ts_ok` is the
 * "YYYY-MM-DDTHH:MM:SSZ" shape the steer leaf orders on. */
struct dvm_kept {
    char key[160];
    char ts[32];
    const char *p;
    size_t len;
    bool ts_ok;
    /* The role table refused this presence line. Emit it without the
     * presence ref so last_seen can move and last_presence cannot. */
    bool blank_ref;
};

static int dvm_kept_slot(const struct dvm_kept *hit, size_t n, const char *key)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (strcmp(hit[i].key, key) == 0)
            return (int)i;
    return -1;
}

static int dvm_ts_pair(const char *ts, size_t at)
{
    return (ts[at] - '0') * 10 + (ts[at + 1] - '0');
}

/* The ranges fmc_ts_unix rejects after the shape check. A stamp it
 * ignores must not sort ahead of one it would use. */
static bool dvm_ts_ranges(const char *ts)
{
    int mo = dvm_ts_pair(ts, 5);
    int d = dvm_ts_pair(ts, 8);
    int h = dvm_ts_pair(ts, 11);
    int mi = dvm_ts_pair(ts, 14);
    int s = dvm_ts_pair(ts, 17);
    if (mo < 1 || mo > 12 || d < 1 || d > 31)
        return false;
    return h <= 23 && mi <= 59 && s <= 59;
}

/* True when fmc_ts_unix would accept the stamp. Well-formed stamps sort
 * in clock order. */
static bool dvm_ts_ok(const char *ts)
{
    static const char pat[] = "dddd-dd-ddTdd:dd:ddZ";
    size_t i;
    if (!ts || strlen(ts) != sizeof(pat) - 1)
        return false;
    for (i = 0; pat[i]; i++) {
        unsigned char c = (unsigned char)ts[i];
        if (pat[i] == 'd') {
            if (c < '0' || c > '9')
                return false;
        } else if (c != (unsigned char)pat[i]) {
            return false;
        }
    }
    return dvm_ts_ranges(ts);
}

/* A later line replaces the kept one only when its stamp parses and is
 * strictly greater. A tie, or a stamp that does not parse, keeps the
 * earlier line. */
static bool dvm_ts_replaces(const char *old_ts, bool old_ok,
                            const char *new_ts, bool new_ok)
{
    if (!new_ok)
        return false;
    if (!old_ok)
        return true;
    return strcmp(new_ts, old_ts) > 0;
}

/* 1 when `key` is stored, 0 when it is empty or the table is full and
 * `fail_full` is clear, -1 when the key does not fit or a full table
 * must drop the stream. */
static int dvm_kept_note(struct dvm_kept *hit, size_t *n, size_t ncap,
                         bool fail_full, const char *key, const char *ts,
                         bool ts_ok, const char *p, size_t len)
{
    int slot;
    size_t kn, tn;
    if (!key || !key[0])
        return 0;
    kn = strlen(key);
    if (kn >= sizeof(hit->key))
        return -1;
    slot = dvm_kept_slot(hit, *n, key);
    if (slot >= 0) {
        if (!dvm_ts_replaces(hit[slot].ts, hit[slot].ts_ok, ts, ts_ok))
            return 1;
    } else if (*n >= ncap) {
        return fail_full ? -1 : 0;
    } else {
        slot = (int)*n;
        *n += 1u;
        memcpy(hit[slot].key, key, kn + 1u);
    }
    hit[slot].p = p;
    hit[slot].len = len;
    hit[slot].ts_ok = ts_ok;
    hit[slot].blank_ref = false;
    tn = ts && ts_ok ? strlen(ts) : 0u;
    if (tn >= sizeof(hit[slot].ts))
        tn = sizeof(hit[slot].ts) - 1u;
    if (tn)
        memcpy(hit[slot].ts, ts, tn);
    hit[slot].ts[tn] = '\0';
    return 1;
}

/* 1 when the field fits, 0 when it is absent, -1 when it is present and
 * does not fit. An absent sender cannot match a recipient. */
static int dvm_field(const char *line, const char *key, char *out, size_t cap)
{
    char pat[64];
    if (dvm_line_str(line, key, out, cap))
        return 1;
    if (snprintf(pat, sizeof(pat), "\"%s\":\"", key) >= (int)sizeof(pat))
        return -1;
    return strstr(line, pat) ? -1 : 0;
}

/* 1 when the line is recorded, 0 when it is empty, -1 when it cannot be
 * classified or a sender does not fit. A full role table leaves that role
 * unseen. A full sender table fails the scan. */
static int dvm_line_keep(struct dvm_kept *roles, size_t *nrole,
                         struct dvm_kept *froms, size_t *nfrom,
                         const char *p, size_t len, size_t cap)
{
    char one[DVM_LINE_CAP];
    char role[33];
    char from[160];
    char ts[32];
    int field, rc, slot;
    bool ts_ok, refused;
    if (len == 0)
        return 0;
    if (len >= sizeof(one) || len + 1 > cap)
        return -1;
    memcpy(one, p, len);
    one[len] = '\0';
    field = dvm_field(one, "ts", ts, sizeof(ts));
    ts_ok = field > 0 && dvm_ts_ok(ts);
    refused = false;
    if (dvm_presence_role_of(one, role, sizeof(role))) {
        rc = dvm_kept_note(roles, nrole, ZCL_DEVAGENT_MAIL_PRESENCE_ROLES,
                           false, role, ts, ts_ok, p, len);
        if (rc < 0)
            return -1;
        refused = rc == 0;
    }
    field = dvm_field(one, "from", from, sizeof(from));
    if (field < 0)
        return -1;
    if (field > 0) {
        rc = dvm_kept_note(froms, nfrom, ZCL_DEVAGENT_MAIL_PRESENCE_FROMS,
                           true, from, ts, ts_ok, p, len);
        if (rc < 0)
            return -1;
        slot = dvm_kept_slot(froms, *nfrom, from);
        if (rc > 0 && slot >= 0 && froms[slot].p == p)
            froms[slot].blank_ref = refused;
    }
    return 1;
}

/* When `skip_partial` is set the first line may start mid-row and is
 * ignored. A line that does not fit fails the scan. */
static bool dvm_presence_scan(const char *buf, size_t n, bool skip_partial,
                              size_t cap, struct dvm_kept *roles, size_t *nrole,
                              struct dvm_kept *froms, size_t *nfrom)
{
    const char *p = buf;
    const char *end = buf + n;
    *nrole = 0;
    *nfrom = 0;
    if (skip_partial) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl)
            return false;
        p = nl + 1;
    }
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        int took;
        if (!nl)
            break;
        took = dvm_line_keep(roles, nrole, froms, nfrom, p,
                             (size_t)(nl - p), cap);
        if (took < 0)
            return false;
        p = nl + 1;
    }
    return true;
}

static bool dvm_presence_path(const char *stream, char *path, size_t cap)
{
    char maildir[DVM_PATH_CAP];
    int w;
    if (!dvm_is_stream_name(stream) || !dvm_cursor_name_ok(stream))
        return false;
    if (!dvm_mail_dir(maildir, sizeof(maildir), false))
        return false;
    w = snprintf(path, cap, "%s/%s", maildir, stream);
    return w > 0 && (size_t)w < cap;
}

/* Bytes [start, start+span) of `f`, or NULL. The caller frees. */
static char *dvm_presence_read(FILE *f, long long start, long long span,
                               size_t *nread)
{
    char *buf = zcl_malloc((size_t)span + 1u, "devagent_mail.presence");
    if (!buf)
        return NULL;
    if (fseek(f, (long)start, SEEK_SET) != 0) {
        free(buf);
        return NULL;
    }
    *nread = fread(buf, 1, (size_t)span, f);
    buf[*nread] = '\0';
    return buf;
}

static bool dvm_kept_same(const struct dvm_kept *hit, size_t n,
                          const char *p, size_t len)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (hit[i].p == p && hit[i].len == len)
            return true;
    return false;
}

/* A refused presence line is emitted without its ref. The steer leaf
 * then counts the sender's stamp and does not set last_presence. */
static void dvm_emit_one(const struct dvm_kept *hit, char *line,
                         void (*keep)(const char *line, void *ctx), void *ctx)
{
    int n;
    if (!hit->blank_ref) {
        memcpy(line, hit->p, hit->len);
        line[hit->len] = '\0';
        keep(line, ctx);
        return;
    }
    if (!hit->ts_ok || !dvm_role_token(hit->key))
        return;
    n = snprintf(line, DVM_LINE_CAP,
                 "{\"seq\":0,\"ts\":\"%s\",\"from\":\"%s\",\"to\":\"*\","
                 "\"kind\":\"note\",\"body\":\"\",\"ref\":\"\"}",
                 hit->ts, hit->key);
    if (n > 0 && (size_t)n < DVM_LINE_CAP)
        keep(line, ctx);
}

static void dvm_kept_emit(const struct dvm_kept *skip, size_t nskip,
                          const struct dvm_kept *hit, size_t n, char *line,
                          void (*keep)(const char *line, void *ctx), void *ctx)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (skip && dvm_kept_same(skip, nskip, hit[i].p, hit[i].len))
            continue;
        dvm_emit_one(&hit[i], line, keep, ctx);
    }
}

/* True when the lookbehind begins mid-row. `start` is one window before
 * a line-aligned cut, so the byte before it is a newline when `start`
 * itself is a line start. The caller skips a partial row only then. */
static bool dvm_presence_midline(FILE *f, long long start, bool *skip)
{
    int c;
    *skip = false;
    if (start <= 0)
        return true;
    if (fseek(f, (long)(start - 1), SEEK_SET) != 0)
        return false;
    c = fgetc(f);
    if (c < 0)
        return false;
    *skip = c != '\n';
    return true;
}

bool zcl_devagent_mail_brief_presence(const char *stream, long long before,
                                     void (*keep)(const char *line, void *ctx),
                                     void *ctx)
{
    char path[DVM_PATH_CAP];
    char line[DVM_LINE_CAP];
    struct dvm_kept *roles;
    struct dvm_kept *froms;
    long long start;
    long long span;
    char *buf;
    FILE *f;
    size_t nread = 0;
    size_t nrole = 0;
    size_t nfrom = 0;
    bool skip = false;
    if (!keep)
        return false;
    if (!stream || before <= 0 || !dvm_presence_path(stream, path, sizeof(path)))
        return false;
    roles = zcl_malloc(sizeof(*roles) * ZCL_DEVAGENT_MAIL_PRESENCE_ROLES,
                       "devagent_mail.presence.roles");
    froms = zcl_malloc(sizeof(*froms) * ZCL_DEVAGENT_MAIL_PRESENCE_FROMS,
                       "devagent_mail.presence.froms");
    if (!roles || !froms) {
        free(roles);
        free(froms);
        return false;
    }
    start = before > ZCL_DEVAGENT_MAIL_WINDOW_BYTES
                ? before - ZCL_DEVAGENT_MAIL_WINDOW_BYTES
                : 0;
    span = before - start;
    f = fopen(path, "rb");
    if (!f) {
        free(roles);
        free(froms);
        return false;
    }
    if (!dvm_presence_midline(f, start, &skip)) {
        (void)fclose(f);
        free(roles);
        free(froms);
        return false;
    }
    buf = dvm_presence_read(f, start, span, &nread);
    (void)fclose(f);
    if (!buf || !dvm_presence_scan(buf, nread, skip, sizeof(line), roles,
                                   &nrole, froms, &nfrom)) {
        free(buf);
        free(roles);
        free(froms);
        return false;
    }
    dvm_kept_emit(NULL, 0, roles, nrole, line, keep, ctx);
    dvm_kept_emit(roles, nrole, froms, nfrom, line, keep, ctx);
    free(buf);
    free(roles);
    free(froms);
    return true;
}

static bool dvm_prefix_streams(struct dvm_pull_state *ps, const char *token)
{
    struct dvm_pull_filter filter = {0};
    if (!dvm_since_token(token, &filter)) return false;
    ps->cursor = filter.since;
    const char *p = filter.token;
    while (*p) {
        char name[DVM_STREAM_NAME_MAX + 1];
        long long off = 0;
        if (dvm_token_entry(p, name, sizeof(name), &off, &p)) return false;
        if (strcmp(name, "seq.max") == 0) {
            dvm_note_seq_max(ps, off);
            continue;
        }
        if (ps->nstreams >= DVM_STREAMS_MAX) return false;
        struct dvm_stream *stream = &ps->streams[ps->nstreams];
        memcpy(stream->name, name, strlen(name) + 1u);
        stream->head_end = off;
        if (ps->nstreams && strcmp(ps->streams[ps->nstreams - 1].name, stream->name) >= 0) return false;
        ps->nstreams++;
    }
    return true;
}

static struct dvm_stream *dvm_prefix_find(struct dvm_pull_state *ps, const char *name)
{
    for (size_t i = 0; i < ps->nstreams; i++)
        if (!strcmp(ps->streams[i].name, name)) return &ps->streams[i];
    return NULL;
}

static bool dvm_cursor_scalar(const char *text, long long *value);

static bool dvm_prefix_base(struct dvm_pull_state *ps, const char *resume,
    long long *floor)
{
    struct dvm_pull_filter filter = {0};
    if (!dvm_since_token(resume, &filter)) {
        if (!dvm_cursor_scalar(resume, &filter.since)) return false;
        filter.token = "";
    }
    if (dvm_token_apply(filter.token, ps)) return false;
    *floor = filter.since;
    const char *p = filter.token;
    while (*p) {
        char name[DVM_STREAM_NAME_MAX + 1]; long long offset;
        if (dvm_token_entry(p, name, sizeof(name), &offset, &p)) return false;
        struct dvm_stream *stream = dvm_prefix_find(ps, name);
        /* The native resume rail drops streams that disappeared. */
        if (stream && stream->off > stream->head_end) return false;
    }
    return true;
}

/* A returned row moves this stream only when it begins at the cursor.
 * One offset covers every earlier byte, so a later row_end would mark an
 * unreturned row in front of it as read. A gap leaves the cursor put. */
static bool dvm_prefix_row(struct dvm_pull_state *ps, const struct json_value *row)
{
    const struct json_value *name = json_get(row, "stream");
    const struct json_value *start = json_get(row, "row_offset");
    const struct json_value *end = json_get(row, "row_end");
    long long from, to;
    if (!name || name->type != JSON_STR || !start || start->type != JSON_INT ||
        !end || end->type != JSON_INT) return false;
    struct dvm_stream *stream = dvm_prefix_find(ps, json_get_str(name));
    from = json_get_int(start);
    to = json_get_int(end);
    if (!stream || from < stream->off || to <= from || to > stream->head_end)
        return false;
    if (from == stream->off)
        stream->off = to;
    return true;
}

static bool dvm_prefix_input_ok(const char *resume, const char *end_token,
    const struct json_value *rows, const char *out, size_t cap)
{
    return resume && end_token && rows && rows->type == JSON_ARR && out && cap > 0;
}

bool zcl_devagent_mail_cursor_prefix(const char *resume, const char *end_token,
    const struct json_value *rows, char *out, size_t cap)
{
    if (!dvm_prefix_input_ok(resume, end_token, rows, out, cap)) return false;
    if (rows->num_children == 0) {
        if (strlen(resume) >= cap) return false;
        memcpy(out, resume, strlen(resume) + 1);
        return true;
    }
    if (rows->num_children > 256) return false;
    struct dvm_pull_state ps = {0};
    ps.streams = zcl_calloc(DVM_STREAMS_MAX, sizeof(*ps.streams), "devagent_mail.prefix");
    if (!ps.streams) return false;
    long long floor = 0;
    bool ok = dvm_prefix_streams(&ps, end_token) && dvm_prefix_base(&ps, resume, &floor) && floor == ps.cursor;
    for (size_t i = 0; ok && i < rows->num_children; i++) ok = dvm_prefix_row(&ps, json_at(rows, i));
    /* Coverage is the stream prefix only. seq.max stays on pull tokens. */
    ps.have_seen_max = false;
    if (ok) ok = dvm_token_build(&ps, floor, out, cap);
    free(ps.streams);
    return ok;
}

/* Per-source completeness: `cursor` is the largest seq seen in ANY stream,
 * which says nothing about whether each peer's file was read to its end.
 * Each source reports the bytes this page consumed against the file's size
 * now; complete=false means rows (or a line still being written) remain. */
static bool dvm_pull_sources(struct zcl_command_reply *reply,
                             const struct dvm_pull_state *ps)
{
    struct json_value arr, item;
    json_init(&arr);
    json_set_array(&arr);
    bool ok = true;
    for (size_t i = 0; i < ps->nstreams; i++) {
        const struct dvm_stream *st = &ps->streams[i];
        struct stat sb;
        long long size = stat(st->path, &sb) == 0 ? (long long)sb.st_size
                                                  : -1;
        json_init(&item);
        json_set_object(&item);
        ok &= json_push_kv_str(&item, "stream", st->name);
        ok &= json_push_kv_int(&item, "consumed", st->off);
        ok &= json_push_kv_int(&item, "size", size);
        ok &= json_push_kv_bool(&item, "complete",
                                size >= 0 && st->off == size);
        ok &= json_push_back(&arr, &item);
        json_free(&item);
    }
    ok &= json_push_kv(&reply->data, "sources", &arr);
    json_free(&arr);
    return ok;
}

static void dvm_pull_build_reply(struct zcl_command_reply *reply,
                                 const struct dvm_page *pg,
                                 const struct dvm_pull_state *ps,
                                 const char *token, const char *resumed)
{
    if (ps->read_failed) {
        dvm_fail(reply, "MAIL_READ_FAILED", "mail stream position could not be observed", "ftell");
        return;
    }
    struct json_value arr, item;
    json_init(&arr);
    json_set_array(&arr);
    bool ok = true;
    for (size_t i = 0; i < pg->n; i++) {
        const struct dvm_row *r = &pg->rows[i];
        json_init(&item);
        json_set_object(&item);
        ok &= json_push_kv_int(&item, "seq", r->seq);
        ok &= json_push_kv_str(&item, "stream", r->stream);
        ok &= json_push_kv_int(&item, "row_offset", r->row_offset);
        ok &= json_push_kv_int(&item, "row_end", r->row_end);
        ok &= json_push_kv_str(&item, "row_sha3", r->row_sha3);
        ok &= json_push_kv_str(&item, "ts", r->ts);
        ok &= json_push_kv_str(&item, "from", r->from);
        ok &= json_push_kv_str(&item, "to", r->to);
        ok &= json_push_kv_str(&item, "kind", r->kind);
        ok &= json_push_kv_str(&item, "body", r->body);
        ok &= json_push_kv_str(&item, "ref", r->ref);
        ok &= json_push_kv_str(&item, "sender_binding", r->sender_binding);
        ok &= json_push_kv_str(&item, "board_post", r->board_post);
        ok &= json_push_kv_str(&item, "board_signer", r->board_signer);
        if (r->observed_disposition[0])
            ok &= json_push_kv_str(&item, "observed_disposition", r->observed_disposition);
        if (r->observed_stream[0]) {
            ok &= json_push_kv_str(&item, "observed_stream", r->observed_stream);
            ok &= json_push_kv_str(&item, "observed_sha3", r->observed_sha3);
            ok &= json_push_kv_int(&item, "observed_offset", r->observed_offset);
            ok &= json_push_kv_int(&item, "observed_seq", r->observed_seq);
        }
        ok &= json_push_back(&arr, &item);
        json_free(&item);
    }
    ok &= json_push_kv_str(&reply->data, "leaf", DVM_LEAF);
    ok &= json_push_kv(&reply->data, "rows", &arr);
    json_free(&arr);
    ok &= json_push_kv_int(&reply->data, "cursor", ps->cursor);
    ok &= json_push_kv_int(&reply->data, "count", (long long)pg->n);
    ok &= json_push_kv_bool(&reply->data, "truncated", pg->truncated);
    ok &= json_push_kv_str(&reply->data, "next_since", token);
    ok &= json_push_kv_int(&reply->data, "skipped", ps->skipped);
    ok &= json_push_kv_str(&reply->data, "resumed_from", resumed);
    ok &= dvm_pull_sources(reply, ps);
    if (!ok) {
        json_free(&reply->data); json_init(&reply->data); json_set_object(&reply->data);
        dvm_fail(reply, "MAIL_READ_FAILED", "mail locator projection failed", "json");
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* Position every stream at its resume offset and load its first head.
 * False with a fail reply already written. */
static bool dvm_streams_start(struct zcl_command_reply *reply,
                              const struct dvm_pull_filter *filter,
                              struct dvm_pull_state *ps,
                              bool defer_cursor)
{
    const char *why = filter->token ? dvm_token_apply(filter->token, ps)
                                    : NULL;
    if (why) {
        dvm_fail(reply, "BAD_INPUT", why, "input.since resume token");
        return false;
    }
    dvm_raise_seen_max(ps);
    for (size_t i = 0; i < ps->nstreams; i++) {
        struct dvm_stream *s = &ps->streams[i];
        if (!defer_cursor)
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

static bool dvm_cursor_scalar(const char *text, long long *value)
{
    char *end;
    *value = 0;
    errno = 0;
    long long parsed = strtoll(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < 0)
        return false;
    *value = parsed;
    return true;
}

static void dvm_cursor_read(FILE *f, char *buf, size_t cap)
{
    size_t n = fread(buf, 1, cap - 1, f);
    bool complete = fgetc(f) == EOF && !ferror(f) &&
                    memchr(buf, '\0', n) == NULL;
    if (fclose(f) != 0) complete = false;
    if (!complete) n = 0;
    buf[n] = '\0';
    if (n > 0 && buf[n - 1] == '\n') {
        buf[--n] = '\0';
        if (n > 0 && buf[n - 1] == '\r') buf[--n] = '\0';
    }
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
    if (!agent || json_get(req->input, "since") || json_get(req->input, "cursor"))
        return true;
    if (!dvm_cursor_name_ok(agent)) {
        dvm_fail(reply, "BAD_INPUT", "agent names the cursor owner",
                 "input.agent has an illegal spelling");
        return false;
    }
    n = (size_t)snprintf(path, sizeof(path), "%s/cursor.%s", maildir, agent);
    if (n == 0 || n >= sizeof(path) || !(f = fopen(path, "rb")))
        return true; /* never acked: page from the start */
    dvm_cursor_read(f, buf, cap);
    filter->resumed = "agent";
    if (dvm_cursor_text_ok(buf) && !strchr(buf, '|')) {
        if (dvm_cursor_scalar(buf, &filter->since)) return true;
    }
    if (strchr(buf, '|') && dvm_cursor_text_ok(buf) && dvm_since_token(buf, filter))
        return true;
    dvm_fail(reply, "MAIL_CURSOR_STALE",
             "the agent's stored cursor is not a cursor; ack a fresh one",
             agent);
    return false;
}

static void dvm_pull(const struct zcl_command_request *req,
                     struct zcl_command_reply *reply, const char *maildir,
                     bool brief_drain, zcl_devagent_mail_ref_filter keep,
                     void *keep_ctx)
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
    filter.keep = keep;
    filter.keep_ctx = keep_ctx;
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
        dvm_streams_start(reply, &filter, ps, brief_drain)) {
        dvm_pull_page(ps, &filter, &pg);
        if (brief_drain && !pg.truncated) {
#ifdef ZCL_TESTING
            if (dvm_test_after_brief_probe)
                dvm_test_after_brief_probe();
#endif
            /* A final-page probe can race an append. Re-run that bounded
             * page through the public path so its max scan still precedes
             * the rows and token this internal drain returns. */
            dvm_streams_close(ps);
            free(ps);
            free(pg.rows);
            dvm_pull(req, reply, maildir, false, keep, keep_ctx);
            return;
        }
        /* Keep the merge's per-stream byte order: a later append may have
         * an older timestamp, but must remain after its consumed prefix.
         * A brief page that deferred the scan must not invent seq.max. */
        if (!brief_drain) {
            ps->have_seen_max = true;
            ps->seen_max = ps->cursor;
        }
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
#if defined(ZCL_TESTING)
int zcl_devagent_mail_test_sync(int fd);
#define DVM_ACK_SYNC(fd) zcl_devagent_mail_test_sync(fd)
#else
#define DVM_ACK_SYNC(fd) fsync(fd)
#endif
static struct dvm_ack_write_result dvm_ack_write_cursor(
    const char *tmp, const char *path, const char *text, size_t len)
{
    char staged[DVM_PATH_CAP];
    int n = snprintf(staged, sizeof(staged), "%s.XXXXXX", tmp);
    if (n < 0 || (size_t)n >= sizeof(staged))
        return (struct dvm_ack_write_result){
            "MAIL_WRITE_FAILED", "cursor staging path exceeds its bound", tmp};
    int fd = mkstemp(staged);
    if (fd < 0)
        return (struct dvm_ack_write_result){
            "MAIL_WRITE_FAILED", "cannot record the cursor", tmp};
    bool ready = fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 &&
        write(fd, text, len) == (ssize_t)len && DVM_ACK_SYNC(fd) == 0;
    int closed = close(fd);
    if (!ready || closed != 0) {
        (void)unlink(staged);
        return (struct dvm_ack_write_result){
            "MAIL_WRITE_FAILED", "cannot write, flush or close the cursor", tmp};
    }
    if (rename(staged, path) != 0) {
        (void)unlink(staged);
        return (struct dvm_ack_write_result){
            "MAIL_WRITE_FAILED", "cannot install the cursor file", path};
    }
    return (struct dvm_ack_write_result){0};
}
#endif

/* True when path already holds exactly these bytes. Rewriting the same
 * read cursor fires the mail directory watcher and spins a resident. */
static bool dvm_file_same(const char *path, const char *text, size_t len)
{
    char have[DVM_TOKEN_CAP + 2];
    FILE *f;
    size_t n;
    int bad;
    if (!path || !text || len == 0 || len >= sizeof(have))
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    n = fread(have, 1, sizeof(have), f);
    bad = ferror(f);
    if (fclose(f) != 0 || bad)
        return false;
    return n == len && memcmp(have, text, len) == 0;
}

/* mail/read.<agent> is the READ position. Same token grammar as an ack,
 * and never a substitute for cursor.<agent>. */
bool zcl_devagent_mail_record_read(const char *agent, const char *token)
{
    char maildir[DVM_PATH_CAP];
    char path[DVM_PATH_CAP];
    char tmp[DVM_PATH_CAP];
    char text[DVM_TOKEN_CAP + 2];
    int path_length, temp_length;
    size_t len;
    if (!dvm_cursor_name_ok(agent) || !dvm_cursor_text_ok(token) ||
        !strchr(token, '|'))
        return false;
    if (!dvm_mail_dir(maildir, sizeof(maildir), true))
        return false;
    path_length = snprintf(path, sizeof(path), "%s/read.%s", maildir, agent);
    temp_length = snprintf(tmp, sizeof(tmp), "%s/.read.%s.%ld.tmp", maildir,
                           agent, (long)getpid());
    if (path_length <= 0 || (size_t)path_length >= sizeof(path) ||
        temp_length <= 0 || (size_t)temp_length >= sizeof(tmp))
        return false;
    len = (size_t)snprintf(text, sizeof(text), "%s\n", token);
    if (len == 0 || len >= sizeof(text))
        return false;
    if (dvm_file_same(path, text, len))
        return true;
    return dvm_ack_write_cursor(tmp, path, text, len).code == NULL;
}

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
    if (*token && zcl_devagent_mail_cursor_valid(*token))
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
    /* Same bytes are already durable. Rewriting them wakes a directory
     * watcher and turns an idle ack into a poll. */
    if (!dvm_file_same(path, text, len)) {
        struct dvm_ack_write_result written = dvm_ack_write_cursor(tmp, path,
                                                                   text, len);
        if (written.code) {
            dvm_fail(reply, written.code, written.message, written.evidence);
            return;
        }
#ifdef ZCL_TESTING
        dvm_test_ack_writes++;
#endif
    }
    (void)json_push_kv_str(&reply->data, "leaf", DVM_LEAF);
    (void)json_push_kv_str(&reply->data, "agent", agent);
    if (token) {
        (void)json_push_kv_str(&reply->data, "cursor", token);
        (void)json_push_kv_str(&reply->data, "cursor_token", token);
    } else
        (void)json_push_kv_int(&reply->data, "cursor", cursor);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static bool dvm_exact_selectors(const struct zcl_command_request *req,
    const char **stream, long long *offset, long long *seq, const char **hash)
{
    unsigned char decoded[32];
    *stream = dvm_str(req, "stream");
    *hash = dvm_str(req, "row_sha3");
    return *stream && dvm_cursor_name_ok(*stream) && dvm_is_stream_name(*stream) &&
        *hash && zcl_hex_decode_lower(*hash, decoded, sizeof(decoded)) &&
        dvm_int(req, "row_offset", offset) && *offset >= 0 &&
        dvm_int(req, "seq", seq) && *seq > 0 && dvm_str(req, "ref");
}

#if !defined(_WIN32)
static bool dvm_exact_stat_same(const struct stat *before, const struct stat *after)
{
    bool same = before->st_size == after->st_size && before->st_mtime == after->st_mtime &&
        before->st_ctime == after->st_ctime;
#if defined(__APPLE__)
    return same && before->st_mtimespec.tv_nsec == after->st_mtimespec.tv_nsec &&
        before->st_ctimespec.tv_nsec == after->st_ctimespec.tv_nsec;
#else
    return same && before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
        before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
#endif
}

static size_t dvm_exact_newline(char raw[DVM_LINE_CAP], ssize_t got)
{
    size_t n = 0;
    while (got > 0 && n < (size_t)got && raw[n] && raw[n] != '\n') n++;
    return got > 0 && n < (size_t)got && raw[n] == '\n' ? n + 1 : 0;
}

/* Read only the selected complete line; conservatively refuse any concurrent
 * size/mtime change, including append. No pathname is reopened after binding. */
static bool dvm_exact_stable(int fd, int parent, const char *stream,
    const struct stat *before)
{
    struct stat after, named;
    return fstat(fd, &after) == 0 && dvm_exact_stat_same(before, &after) &&
        fstatat(parent, stream, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(named.st_mode) && named.st_dev == before->st_dev && named.st_ino == before->st_ino;
}

static bool dvm_exact_line(const char *dir, const char *stream, long long offset,
    char raw[DVM_LINE_CAP])
{
    uintptr_t retained;
    if (!platform_private_directory_open_validated_traverse(dir, &retained)) return false;
    int parent = (int)retained;
    int fd = openat(parent, stream, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { platform_private_directory_close(retained); return false; }
    struct stat before;
    char prior;
    bool ok = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
        offset < before.st_size && (offset == 0 ||
        (pread(fd, &prior, 1, (off_t)(offset - 1)) == 1 && prior == '\n'));
    ssize_t got = ok ? pread(fd, raw, DVM_LINE_CAP - 1, (off_t)offset) : -1;
    size_t n = dvm_exact_newline(raw, got);
#ifdef ZCL_TESTING
    if (dvm_test_after_exact_read) dvm_test_after_exact_read();
#endif
    ok = ok && n > 0 && dvm_exact_stable(fd, parent, stream, &before);
    raw[n] = '\0';
    (void)close(fd);
    platform_private_directory_close(retained);
    return ok;
}
#endif

#if !defined(_WIN32)
static bool dvm_exact_project(struct zcl_command_reply *reply,
    const struct dvm_row *row, const char *stream, long long offset,
    const char *hash, const char *raw)
{
    const struct { const char *key; const char *value; } fields[] = {
        {"representation", "zcl.devagent.mail.raw_row.v1"},
        {"stream", stream}, {"row_sha3", hash}, {"ref", row->ref}, {"raw_line", raw},
        {"body", row->body}, {"from", row->from}, {"to", row->to}, {"kind", row->kind},
        {"ts", row->ts}, {"sender_binding", row->sender_binding},
        {"board_post", row->board_post}, {"board_signer", row->board_signer}};
    bool ok = json_push_kv_int(&reply->data, "row_offset", offset);
    ok &= json_push_kv_int(&reply->data, "seq", row->seq);
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        ok &= json_push_kv_str(&reply->data, fields[i].key, fields[i].value);
    return ok;
}

#endif

#if !defined(_WIN32)
static bool dvm_exact_parse(const char *raw, struct dvm_row *row)
{
    struct json_value value;
    json_init(&value);
    bool ok = json_read(&value, raw, strlen(raw)) && value.type == JSON_OBJ;
    const struct json_value *seq = json_get(&value, "seq");
    ok = ok && seq && seq->type == JSON_INT && json_get_int(seq) > 0;
    if (ok) row->seq = json_get_int(seq);
    const struct { const char *key; char *target; size_t cap; bool optional; } fields[] = {
        {"ts", row->ts, sizeof(row->ts), false},
        {"from", row->from, sizeof(row->from), false},
        {"to", row->to, sizeof(row->to), false},
        {"kind", row->kind, sizeof(row->kind), false},
        {"body", row->body, sizeof(row->body), false},
        {"ref", row->ref, sizeof(row->ref), false},
        {"sender_binding", row->sender_binding, sizeof(row->sender_binding), true},
        {"board_post", row->board_post, sizeof(row->board_post), true},
        {"board_signer", row->board_signer, sizeof(row->board_signer), true}};
    for (size_t i = 0; ok && i < sizeof(fields) / sizeof(fields[0]); i++) {
        const struct json_value *field = json_get(&value, fields[i].key);
        if (!field && fields[i].optional) continue;
        const char *text = json_get_str(field);
        ok = field && field->type == JSON_STR && text && strlen(text) < fields[i].cap;
        if (ok) memcpy(fields[i].target, text, strlen(text) + 1);
    }
    json_free(&value);
    return ok;
}
static const char *dvm_exact_problem(const char *raw, const char *actual,
    const char *hash, long long seq, const char *ref, struct dvm_row *row)
{
    if (strcmp(actual, hash))
        return "selected mail row_sha3 differs; refresh the locator with dev agent mail pull";
    if (!dvm_exact_parse(raw, row))
        return "selected mail row is invalid; inspect the source stream read-only";
    if (row->seq != seq)
        return "selected mail sequence differs; refresh the locator with dev agent mail pull";
    if (strcmp(row->ref, ref))
        return "selected mail reference differs; refresh the locator with dev agent mail pull";
    return NULL;
}
#endif

static void dvm_exact(const struct zcl_command_request *req,
    struct zcl_command_reply *reply, const char *dir)
{
    const char *stream, *hash;
    long long offset, seq;
    if (!dvm_exact_selectors(req, &stream, &offset, &seq, &hash)) {
        dvm_fail(reply, "BAD_INPUT", "exact mail needs all locator selectors", "stream,row_offset,seq,row_sha3,ref");
        return;
    }
#if defined(_WIN32)
    (void)dir;
    dvm_fail(reply, "MAIL_EXACT_UNAVAILABLE", "descriptor-bound exact mail is unavailable", "platform");
#else
    char raw[DVM_LINE_CAP], actual[65];
    struct dvm_row row = {0};
    if (!dvm_exact_line(dir, stream, offset, raw)) {
        dvm_fail(reply, "MAIL_EXACT_UNAVAILABLE", "selected complete mail bytes are unavailable", stream);
        return;
    }
    dvm_row_hash(raw, strlen(raw), actual);
    const char *problem = dvm_exact_problem(raw, actual, hash, seq, dvm_str(req, "ref"), &row);
    if (problem) {
        dvm_fail(reply, "MAIL_EXACT_MISMATCH", problem, stream);
        return;
    }
    bool ok = dvm_exact_project(reply, &row, stream, offset, actual, raw);
    if (!ok) {
        json_free(&reply->data); json_init(&reply->data); json_set_object(&reply->data);
        dvm_fail(reply, "MAIL_READ_FAILED", "exact mail projection failed", "json");
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
#endif
}

static void dvm_handle(const struct zcl_command_request *request,
                       struct zcl_command_reply *reply, bool brief_drain,
                       zcl_devagent_mail_ref_filter keep, void *keep_ctx)
{
    const char *action;
    char maildir[4096];

    if (!reply)
        return;
    if (!request || !request->input) {
        dvm_fail(reply, "BAD_INPUT",
                 "dev.agent.mail needs action post|pull|exact|ack",
                 "request.input was missing");
        return;
    }
    action = dvm_str(request, "action");
    if (!action || !action[0]) {
        dvm_fail(reply, "BAD_INPUT",
                 "action is required: post, pull, exact, or ack",
                 "input.action missing or empty");
        return;
    }
    if (!dvm_mail_dir(maildir, sizeof(maildir), strcmp(action, "pull") != 0 && strcmp(action, "exact") != 0)) {
        dvm_fail(reply, "STATE_DIR_FAILED",
                 "cannot resolve the mail dir under the state root",
                 "platform_state_root/mail");
        return;
    }
    if (strcmp(action, "exact") == 0) {
        dvm_exact(request, reply, maildir);
        return;
    }
    if (strcmp(action, "post") == 0) {
        dvm_post(request, reply, maildir, NULL, false, NULL, false);
        return;
    }
    if (strcmp(action, "pull") == 0) {
        dvm_pull(request, reply, maildir, brief_drain, keep, keep_ctx);
        return;
    }
    if (strcmp(action, "ack") == 0) {
        dvm_ack(request, reply, maildir);
        return;
    }
    dvm_fail(reply, "BAD_INPUT", "action is one of post|pull|exact|ack",
             "input.action unknown");
}

/* Internal steer seam: the caller has already resolved and authorized the
 * sender. The digest is never accepted through the public mail schema. */
void zcl_devagent_mail_steer_post(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply,
                                  const char *key_digest, bool require_existing,
                                  const char *disposition, bool probe)
{
    char maildir[4096];
    if (!reply || !key_digest || strlen(key_digest) != 64) return;
    if (!dvm_mail_dir(maildir, sizeof(maildir), true)) {
        dvm_fail(reply, "STATE_DIR_FAILED", "cannot resolve mail dir", "platform_state_root/mail");
        return;
    }
    dvm_post(request, reply, maildir, key_digest, require_existing, disposition, probe);
}

static bool dvm_worker_envelope(const struct zcl_command_request *request, const char *name)
{
    const char *action = dvm_str(request, "action"), *to = dvm_str(request, "to");
    const char *kind = dvm_str(request, "kind"), *ref = dvm_str(request, "ref");
    const char *from = dvm_str(request, "from");
    return action && strcmp(action, "post") == 0 && to && strcmp(to, "*") == 0 &&
           kind && strcmp(kind, "result") == 0 && ref && strcmp(ref, name) == 0 &&
           from && zcl_devagent_name_ok(from) && !dvm_str(request, "sender_binding");
}

/* Keyed worker result posts are internal and cannot be requested on the
 * public mail surface. The queue identity is the idempotency domain. */
void zcl_devagent_mail_worker_post(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply,
                                   const char *name, long long attempt,
                                   long long seq)
{
    static const char domain[] = "z23.devagent.worker.result.v1";
    struct sha3_256_ctx hash;
    unsigned char sum[32];
    char key[65], identity[192], maildir[4096];
    int n;
    if (!reply || !name || !zcl_devagent_name_ok(name) || attempt <= 0 || seq <= 0) {
        if (reply) dvm_fail(reply, "BAD_INPUT", "invalid worker result identity", "queue identity");
        return;
    }
    if (!dvm_worker_envelope(request, name)) {
        dvm_fail(reply, "BAD_INPUT", "invalid worker result envelope", "result identity");
        return;
    }
    n = snprintf(identity, sizeof(identity), "%s\n%lld\n%lld", name, attempt, seq);
    if (n <= 0 || (size_t)n >= sizeof(identity)) {
        dvm_fail(reply, "BAD_INPUT", "worker result identity exceeds its bound", "queue identity");
        return;
    }
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&hash, (const unsigned char *)identity, (size_t)n);
    sha3_256_finalize(&hash, sum);
    zcl_hex_encode(sum, sizeof(sum), key);
    if (!dvm_mail_dir(maildir, sizeof(maildir), true)) {
        dvm_fail(reply, "STATE_DIR_FAILED", "cannot resolve mail dir", "platform_state_root/mail");
        return;
    }
    dvm_post(request, reply, maildir, key, false, NULL, false);
}

void zcl_native_handle_dev_agent_mail(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    dvm_handle(request, reply, false, NULL, NULL);
}

/* Internal fleet-brief path. It keeps normal validation and skips max scans
 * while pages remain; a final-page probe falls back to the public pull path. */
void zcl_native_handle_dev_agent_mail_brief_drain(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    dvm_handle(request, reply, true, NULL, NULL);
}

void zcl_native_handle_dev_agent_mail_brief_filtered(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    zcl_devagent_mail_ref_filter keep, void *ctx)
{
    dvm_handle(request, reply, true, keep, ctx);
}
