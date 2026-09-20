/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.receive
 * (tools/command/native_devagent_receive.c): the resident loop that turns a
 * directive arriving in this box's agent mail into real work with no human
 * in the path.
 *
 * Written against an isolated XDG_STATE_HOME, never the operator's real
 * state dir. No model, no network, no spawn: the receiver only composes the
 * existing dev.agent.mail, dev.agent.queue and fleet.steer grant leaves,
 * and execution stays dev.agent.worker's separate business, so every case
 * below is deterministic in-process.
 *
 * Each non-negotiable property has its own case:
 *   admission (ref alphabet, grant by label, revocation, expiry, direction
 *   shape), to-work through the existing queue, idempotence, conflict,
 *   accept-only-after-the-queue, single instance, restart safety, bounded
 *   wait, wake on new mail, SIGTERM, execution never blocking intake, and
 *   a status action that writes nothing.
 */

/* realpath() is declared by glibc only under _DEFAULT_SOURCE; with
 * -D_POSIX_C_SOURCE alone the only declaration in scope is the fortify
 * inline, which exists solely at -O2 and above. This must precede the
 * first include: feature-test macros are read when <features.h> is first
 * pulled in, and a definition after that silently does nothing. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_devagent.h"
#include "command/native_fleet.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/directory_watcher.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
void zcl_devagent_receive_test_watch_loss(bool enabled);
#endif

/* ── isolated state root (this group owns its own rig) ─────────────────── */

static char g_rtx_state[1024];
static char g_rtx_ws[1024];
static char g_rtx_base[1024];
static char g_rtx_saved_xdg[4096];
static bool g_rtx_had_xdg;
static int g_rtx_ts;

/* ── who the rig's senders are ──────────────────────────────────────────
 *
 * A directive row carries the stamp of the credential that sent it, and
 * the receiver admits on that stamp rather than on the name beside it. The
 * rig therefore has to stamp rows the way a real sender does: every grant
 * it mints is remembered here by label, and a delivery under that label
 * carries that grant's binding.
 *
 * A delivery under a label the rig never minted carries RTX_FOREIGN_BINDING
 * — a well-formed stamp belonging to nobody, which is what an outsider
 * actually presents. It is deliberately NOT an empty stamp: an unstamped
 * row is refused one gate earlier, and a case about an ungranted sender
 * must reach the sender gate to be about anything. */
#define RTX_FOREIGN_BINDING "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

struct rtx_ident {
    char label[64];
    char binding[ZCL_FLEET_STEER_BINDING_HEX + 1];
};

static struct rtx_ident g_rtx_ident[8];
static size_t g_rtx_idents;

/* Remember the binding `id` stamps under `label` (last mint wins). */
static void rtx_ident_put(const char *label, const char *id)
{
    struct rtx_ident e;
    size_t i;
    memset(&e, 0, sizeof(e));
    (void)snprintf(e.label, sizeof(e.label), "%s", label);
    if (!zcl_fleet_steer_sender_binding(id, label, e.binding,
                                        sizeof(e.binding)))
        return;
    for (i = 0; i < g_rtx_idents; i++) {
        if (strcmp(g_rtx_ident[i].label, label) == 0) {
            g_rtx_ident[i] = e;
            return;
        }
    }
    if (g_rtx_idents < sizeof(g_rtx_ident) / sizeof(g_rtx_ident[0]))
        g_rtx_ident[g_rtx_idents++] = e;
}

static const char *rtx_ident_binding(const char *label)
{
    size_t i;
    for (i = 0; i < g_rtx_idents; i++) {
        if (strcmp(g_rtx_ident[i].label, label) == 0)
            return g_rtx_ident[i].binding;
    }
    return RTX_FOREIGN_BINDING;
}

static void rtx_isolate(const char *tag)
{
    char base[512];
    /* realpath() writes up to PATH_MAX bytes and glibc's fortify check
     * aborts on anything smaller, whatever the input length. */
    char real[PATH_MAX];
    test_make_tmpdir(base, sizeof(base), "devagent_receive", tag);
    /* Canonicalize the rig's own root. The receiver records the CANONICAL
     * workspace path, so a tmpdir sitting below a symlinked component
     * (/tmp is /private/tmp on a Mac) would otherwise make every
     * path comparison below fail for a reason that is not the contract. */
    if (realpath(base, real) != NULL)
        (void)snprintf(base, sizeof(base), "%s", real);
    (void)snprintf(g_rtx_state, sizeof(g_rtx_state), "%s/state", base);
    (void)snprintf(g_rtx_base, sizeof(g_rtx_base), "%s", base);
    (void)snprintf(g_rtx_ws, sizeof(g_rtx_ws), "%s/ws", base);
    g_rtx_had_xdg = getenv("XDG_STATE_HOME") != NULL;
    if (g_rtx_had_xdg)
        (void)snprintf(g_rtx_saved_xdg, sizeof(g_rtx_saved_xdg), "%s",
                       getenv("XDG_STATE_HOME"));
    setenv("XDG_STATE_HOME", g_rtx_state, 1);
    g_rtx_ts = 0;
    g_rtx_idents = 0;
#if !defined(_WIN32)
    (void)mkdir(g_rtx_ws, 0700);
#endif
}

static void rtx_restore(void)
{
    if (g_rtx_had_xdg)
        setenv("XDG_STATE_HOME", g_rtx_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
}

/* ── one in-process leaf invocation ────────────────────────────────────── */

struct rtx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void rtx_begin(struct rtx_call *c, const char *path,
                      const char *schema)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    c->request.view = "normal";
    zcl_command_reply_init(&c->reply, schema);
}

static void rtx_end(struct rtx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool rtx_ok(const struct rtx_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *rtx_reply_str(const struct rtx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return (v && v->type == JSON_STR && json_get_str(v)) ? json_get_str(v)
                                                         : "";
}

/* ── rig helpers ───────────────────────────────────────────────────────── */

/* Mint one grant under `label` with `scopes`; returns its id in `id`. */
static bool rtx_mint(const char *label, const char *scopes, long long ttl,
                     char *id, size_t cap)
{
    struct rtx_call c;
    bool ok;
    rtx_begin(&c, "fleet.steer.grant", "zcl.fleet_steer_grant.v1");
    (void)json_push_kv_str(&c.input, "action", "mint");
    (void)json_push_kv_str(&c.input, "scopes", scopes);
    (void)json_push_kv_str(&c.input, "label", label);
    (void)json_push_kv_int(&c.input, "ttl_seconds", ttl);
    zcl_native_handle_fleet_steer_grant(&c.request, &c.reply);
    ok = rtx_ok(&c);
    if (ok) {
        /* Remember the stamp before the id goes out of scope: callers that
         * do not want the id still deliver rows under this label. */
        rtx_ident_put(label, rtx_reply_str(&c, "id"));
        if (id)
            (void)snprintf(id, cap, "%s", rtx_reply_str(&c, "id"));
    }
    rtx_end(&c);
    return ok;
}

/* Append one already-expired grant row in the store's own machine format.
 * The mint verb cannot produce one (its ttl floor is a second in the
 * future), and expiry is exactly the case a receiver must fail closed on,
 * so the row is written the way an older mint left it behind. */
static bool rtx_mint_expired(const char *label)
{
    char path[1600];
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/z23/dev/steer/grants.jsonl",
                   g_rtx_state);
    f = fopen(path, "ab");
    if (!f)
        return false;
    (void)fprintf(f,
                  "{\"id\":\"%s\",\"scopes\":\"send\",\"created\":1,"
                  "\"expires\":2,\"revoked\":\"0\",\"label\":\"%s\"}\n",
                  "00000000000000000000000000000001", label);
    /* Its rows stamp like any other grant's: the case is about expiry, so
     * the stamp must not be what refuses it. */
    rtx_ident_put(label, "00000000000000000000000000000001");
    return fclose(f) == 0;
}

static bool rtx_revoke(const char *id)
{
    struct rtx_call c;
    bool ok;
    rtx_begin(&c, "fleet.steer.grant", "zcl.fleet_steer_grant.v1");
    (void)json_push_kv_str(&c.input, "action", "revoke");
    (void)json_push_kv_str(&c.input, "id", id);
    zcl_native_handle_fleet_steer_grant(&c.request, &c.reply);
    ok = rtx_ok(&c);
    rtx_end(&c);
    return ok;
}

/* One direction body in the Muse executor's exact format. */
static void rtx_direction(char *out, size_t cap, const char *gate,
                          const char *prompt)
{
    (void)snprintf(out, cap,
                   "muse-workspace: %s\nmuse-scope: src/x.c\nmuse-gate: %s\n"
                   "\n%s\n",
                   g_rtx_ws, gate, prompt);
}

/* The same direction with a LOGICAL workspace value — which is all a remote
 * sender can carry, since dev.agent.mail refuses a body naming a foreign
 * absolute path and nothing here weakens that. `sha` is the optional HEAD
 * pin; "" leaves the header out entirely. */
static void rtx_direction_sel(char *out, size_t cap, const char *selector,
                              const char *sha, const char *prompt)
{
    char pin[128];
    pin[0] = '\0';
    if (sha[0])
        (void)snprintf(pin, sizeof(pin), "muse-sha: %s\n", sha);
    (void)snprintf(out, cap,
                   "muse-workspace: %s\nmuse-scope: src/x.c\n"
                   "muse-gate: hex_codec\n%s\n%s\n",
                   selector, pin, prompt);
}

/* ── a real-enough git checkout, built from the same bytes git writes ──── */

static bool rtx_put(const char *dir, const char *rel, const char *text)
{
    char path[1600];
    FILE *f;
    size_t n = strlen(text);
    (void)snprintf(path, sizeof(path), "%s/%s", dir, rel);
    f = fopen(path, "wb");
    if (!f)
        return false;
    if (n > 0 && fwrite(text, 1, n, f) != n) {
        (void)fclose(f);
        return false;
    }
    return fclose(f) == 0;
}

static void rtx_be32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

/* One DIRC v2 index naming exactly one tracked path with the stat data the
 * caller wants recorded — the same file layout git writes, so the
 * receiver's reader is exercised, not mocked. A clean pre-state records the
 * file's real size and mtime; a dirty one records anything else. */
static bool rtx_index(const char *ws, const char *name, uint32_t mode,
                      uint32_t size, uint32_t mtime)
{
    unsigned char buf[512];
    char path[1600];
    size_t nlen = strlen(name);
    size_t esz = (62u + nlen + 8u) & ~(size_t)7u;
    FILE *f;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "DIRC", 4);
    rtx_be32(buf + 4, 2);
    rtx_be32(buf + 8, 1);
    rtx_be32(buf + 12 + 8, mtime);
    rtx_be32(buf + 12 + 24, mode);
    rtx_be32(buf + 12 + 36, size);
    buf[12 + 60] = (unsigned char)((nlen >> 8) & 0x0F);
    buf[12 + 61] = (unsigned char)(nlen & 0xFF);
    memcpy(buf + 12 + 62, name, nlen);
    (void)snprintf(path, sizeof(path), "%s/.git/index", ws);
    f = fopen(path, "wb");
    if (!f)
        return false;
    if (fwrite(buf, 1, 12u + esz + 20u, f) != 12u + esz + 20u) {
        (void)fclose(f);
        return false;
    }
    return fclose(f) == 0;
}

static bool rtx_is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool rtx_mkdirs(const char *dir)
{
    char path[1600];
    (void)mkdir(dir, 0700);
    (void)snprintf(path, sizeof(path), "%s/.git", dir);
    (void)mkdir(path, 0700);
    (void)snprintf(path, sizeof(path), "%s/.git/refs", dir);
    (void)mkdir(path, 0700);
    (void)snprintf(path, sizeof(path), "%s/.git/refs/heads", dir);
    (void)mkdir(path, 0700);
    (void)snprintf(path, sizeof(path), "%s/src", dir);
    (void)mkdir(path, 0700);
    return rtx_is_dir(path);
}

/* A checkout on `head`: a .git directory, a symbolic HEAD, its loose ref,
 * one tracked file, and an index whose stat data matches that file. */
static bool rtx_checkout(const char *dir, const char *head)
{
    char path[1600], ref[64];
    struct stat st;
    (void)snprintf(ref, sizeof(ref), "%s\n", head);
    if (!rtx_mkdirs(dir) || !rtx_put(dir, ".git/HEAD", "ref: refs/heads/x\n") ||
        !rtx_put(dir, ".git/refs/heads/x", ref) ||
        !rtx_put(dir, "src/x.c", "int zx(void) { return 0; }\n"))
        return false;
    (void)snprintf(path, sizeof(path), "%s/src/x.c", dir);
    if (lstat(path, &st) != 0)
        return false;
    return rtx_index(dir, "src/x.c", 0100644u, (uint32_t)st.st_size,
                     (uint32_t)st.st_mtime);
}

/* Read one of the receiver's own files under the state root. */
static bool rtx_read(const char *tail, char *out, size_t cap)
{
    char path[1600];
    FILE *f;
    size_t n;
    (void)snprintf(path, sizeof(path), "%s/z23/dev/%s", g_rtx_state, tail);
    out[0] = '\0';
    f = fopen(path, "rb");
    if (!f)
        return false;
    n = fread(out, 1, cap - 1, f);
    out[n] = '\0';
    return fclose(f) == 0 && n > 0;
}

/* One drive with an explicitly configured workspace. */
static void rtx_opts_ws(struct rcv_drive_opts *o, const char *workspace)
{
    memset(o, 0, sizeof(*o));
    (void)snprintf(o->receiver, sizeof(o->receiver), "box-a");
    (void)snprintf(o->workspace, sizeof(o->workspace), "%s", workspace);
    o->deadline_s = 30;
    o->wait_ms = 50;
    o->max_beats = 1;
}

/* Post one directive through the EXISTING mail leaf. A body carrying an
 * absolute workspace is refused by the mail leaf's own path rule unless it
 * sits under the checkout, so the rig writes the inbox file the way a
 * transport does — which is also the only way a peer's directive ever
 * arrives. */
static bool rtx_deliver_bound(const char *stream, const char *peer,
                              const char *to, const char *ref,
                              const char *body, long long seq,
                              const char *binding)
{
    char dir[1200], path[1400], esc[8192];
    size_t o = 0;
    FILE *f;
    /* The transport owns the inbox file, so it owns the directory chain
     * under the state root too — a peer can deliver to a box whose
     * receiver has never run. */
    (void)snprintf(dir, sizeof(dir), "%s", g_rtx_state);
    (void)mkdir(dir, 0700);
    (void)snprintf(dir, sizeof(dir), "%s/z23", g_rtx_state);
    (void)mkdir(dir, 0700);
    (void)snprintf(dir, sizeof(dir), "%s/z23/dev", g_rtx_state);
    (void)mkdir(dir, 0700);
    (void)snprintf(dir, sizeof(dir), "%s/z23/dev/mail", g_rtx_state);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        return false;
    (void)snprintf(path, sizeof(path), "%s/inbox.%s.jsonl", dir, stream);
    for (const char *p = body; *p && o + 8 < sizeof(esc); p++) {
        if (*p == '\n') {
            esc[o++] = '\\';
            esc[o++] = 'n';
        } else if (*p == '"' || *p == '\\') {
            esc[o++] = '\\';
            esc[o++] = *p;
        } else {
            esc[o++] = *p;
        }
    }
    esc[o] = '\0';
    f = fopen(path, "ab");
    if (!f)
        return false;
    /* One stamp per delivery, in delivery order: the mail leaf orders rows
     * by (ts, from, seq), and two separately delivered rows are two rows
     * even when they carry the same stream sequence. */
    g_rtx_ts++;
    /* An empty binding writes no field at all, which is exactly the shape
     * of a row no credential stamped. */
    (void)fprintf(f,
                  "{\"seq\":%lld,\"ts\":\"2026-09-17T00:%02d:%02dZ\","
                  "\"from\":\"%s\",\"to\":\"%s\",\"kind\":\"directive\","
                  "\"body\":\"%s\",\"ref\":\"%s\"",
                  seq, (int)(g_rtx_ts / 60) % 60, (int)(g_rtx_ts % 60), peer,
                  to, esc, ref);
    if (binding && binding[0])
        (void)fprintf(f, ",\"sender_binding\":\"%s\"", binding);
    (void)fprintf(f, "}\n");
    return fclose(f) == 0;
}

/* One peer's row, stamped the way that peer's own credential stamps it. */
static bool rtx_deliver_as(const char *stream, const char *peer,
                           const char *to, const char *ref, const char *body,
                           long long seq)
{
    return rtx_deliver_bound(stream, peer, to, ref, body, seq,
                             rtx_ident_binding(peer));
}

/* The common case: one peer writing its own stream. */
static bool rtx_deliver(const char *peer, const char *to, const char *ref,
                        const char *body, long long seq)
{
    return rtx_deliver_as(peer, peer, to, ref, body, seq);
}

static void rtx_opts(struct rcv_drive_opts *o, long long beats)
{
    memset(o, 0, sizeof(*o));
    (void)snprintf(o->receiver, sizeof(o->receiver), "box-a");
    o->deadline_s = 30;
    o->wait_ms = 50;
    o->max_beats = beats;
}

/* One queue verb with at most one extra string key. */
static bool rtx_queue(const char *action, const char *k1, const char *v1,
                      const char *k2, const char *v2)
{
    struct rtx_call c;
    bool ok;
    rtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", action);
    if (k1)
        (void)json_push_kv_str(&c.input, k1, v1);
    if (k2)
        (void)json_push_kv_str(&c.input, k2, v2);
    zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
    ok = rtx_ok(&c);
    rtx_end(&c);
    return ok;
}

/* How many rows in `bucket` (queued|running) name `ref`. */
static long long rtx_queue_count(const char *bucket, const char *ref)
{
    struct rtx_call c;
    const struct json_value *arr;
    long long hits = 0;
    rtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", "status");
    (void)json_push_kv_bool(&c.input, "json", true);
    zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
    arr = rtx_ok(&c) ? json_get(&c.reply.data, bucket) : NULL;
    if (arr && arr->type == JSON_ARR) {
        size_t n = json_size(arr), i;
        for (i = 0; i < n; i++) {
            const struct json_value *r = json_at(arr, i);
            const struct json_value *v = r ? json_get(r, "name") : NULL;
            if (v && v->type == JSON_STR && json_get_str(v) &&
                strcmp(json_get_str(v), ref) == 0)
                hits++;
        }
    }
    rtx_end(&c);
    return hits;
}

/* Count one page's rows under `ref` whose body carries `needle`. */
static long long rtx_answers_in(const struct json_value *arr, const char *ref,
                                const char *needle)
{
    long long hits = 0;
    size_t n = (arr && arr->type == JSON_ARR) ? json_size(arr) : 0u, i;
    for (i = 0; i < n; i++) {
        const struct json_value *r = json_at(arr, i);
        const struct json_value *b = r ? json_get(r, "body") : NULL;
        const struct json_value *f = r ? json_get(r, "ref") : NULL;
        if (!b || b->type != JSON_STR || !f || f->type != JSON_STR)
            continue;
        if (strcmp(json_get_str(f), ref) != 0)
            continue;
        if (strstr(json_get_str(b), needle) != NULL)
            hits++;
    }
    return hits;
}

/* How many mail rows from this receiver under `ref` carry `needle`. Mail
 * answers in bounded pages, so this follows next_since to the last page. */
static long long rtx_answers(const char *ref, const char *needle)
{
    char since[4096] = "";
    long long hits = 0;
    bool more = true;
    for (int page = 0; more && page < 1000; page++) {
        struct rtx_call c;
        const struct json_value *tr;
        rtx_begin(&c, "dev.agent.mail", "zcl.agent_mail.v1");
        (void)json_push_kv_str(&c.input, "action", "pull");
        if (since[0])
            (void)json_push_kv_str(&c.input, "since", since);
        else
            (void)json_push_kv_int(&c.input, "since", 0);
        (void)json_push_kv_str(&c.input, "from", "box-a");
        zcl_native_handle_dev_agent_mail(&c.request, &c.reply);
        if (!rtx_ok(&c)) {
            rtx_end(&c);
            return -1;
        }
        hits += rtx_answers_in(json_get(&c.reply.data, "rows"), ref, needle);
        tr = json_get(&c.reply.data, "truncated");
        more = tr && tr->type == JSON_BOOL && json_get_bool(tr);
        (void)snprintf(since, sizeof(since), "%s",
                       rtx_reply_str(&c, "next_since"));
        rtx_end(&c);
    }
    return hits;
}

static void rtx_path(char *out, size_t cap, const char *tail)
{
    (void)snprintf(out, cap, "%s/z23/dev/%s", g_rtx_state, tail);
}

static bool rtx_exists(const char *tail)
{
    char path[1400];
    struct stat st;
    rtx_path(path, sizeof(path), tail);
    return stat(path, &st) == 0;
}

/* SIGALRM raises SIGTERM so the receiver's own handler is exercised inside
 * a single process: no fork, no spawn, no sleeping test. */
#if !defined(_WIN32)
static void rtx_alarm_to_term(int sig)
{
    (void)sig;
    (void)raise(SIGTERM);
}
#endif

/* ── intake paging: a long history never deafens the receiver ────────────
 * The live defect: every beat pulled the WHOLE directive history, so it
 * grew without bound, and at most 128 rows of it were ever looked at — the
 * newest directives sort last and were silently never handled. Intake now
 * pages through the mail leaf's bounded replies from a durable cursor. */
#if !defined(_WIN32)

/* Deliver n rows from `peer` to `to`, refs "<prefix>-NNN". pad > 0 makes
 * each body `pad` filler bytes; 0 makes it a well-formed direction. */
static bool rtx_deliver_many(const char *peer, const char *to,
                             const char *prefix, size_t n, size_t pad)
{
    char body[4096], ref[64];
    for (size_t i = 0; i < n; i++) {
        (void)snprintf(ref, sizeof(ref), "%s-%03zu", prefix, i);
        if (pad > 0 && pad < sizeof(body)) {
            memset(body, 'x', pad);
            body[pad] = '\0';
        } else {
            rtx_direction(body, sizeof(body), "hex_codec", "Pending work.");
        }
        if (!rtx_deliver(peer, to, ref, body, (long long)i + 1))
            return false;
    }
    return true;
}

/* Entries (not "." or "..") in one directory under the state root. */
static long long rtx_count_dir(const char *tail)
{
    char path[1400];
    DIR *d;
    struct dirent *e;
    long long n = 0;
    rtx_path(path, sizeof(path), tail);
    d = opendir(path);
    if (!d)
        return -1;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            n++;
    }
    (void)closedir(d);
    return n;
}

/* Remove every answer marker, so only the intake cursor can stop a
 * replay from being answered twice. */
static bool rtx_clear_answers(void)
{
    char dir[1400], path[1800];
    DIR *d;
    struct dirent *e;
    rtx_path(dir, sizeof(dir), "receive/answered");
    d = opendir(dir);
    if (!d)
        return false;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        (void)snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        (void)remove(path);
    }
    (void)closedir(d);
    return rtx_count_dir("receive/answered") == 0;
}

/* Write (truncate) a file under the state root with `text`. */
static bool rtx_write(const char *tail, const char *text)
{
    char path[1400];
    FILE *f;
    rtx_path(path, sizeof(path), tail);
    f = fopen(path, "wb");
    if (!f)
        return false;
    (void)fputs(text, f);
    return fclose(f) == 0;
}

/* The receiver's status action: its durable intake record. */
static bool rtx_status_intake(char *error, size_t cap, long long *failures,
                              char *state, size_t scap)
{
    struct rtx_call c;
    const struct json_value *v;
    bool ok;
    rtx_begin(&c, "dev.agent.receive", "zcl.agent_receive.v1");
    (void)json_push_kv_str(&c.input, "action", "status");
    (void)json_push_kv_str(&c.input, "receiver", "box-a");
    zcl_native_handle_dev_agent_receive(&c.request, &c.reply);
    ok = rtx_ok(&c);
    (void)snprintf(error, cap, "%s", rtx_reply_str(&c, "intake_last_error"));
    (void)snprintf(state, scap, "%s",
                   rtx_reply_str(&c, "intake_cursor_state"));
    v = json_get(&c.reply.data, "intake_failures");
    *failures = (v && v->type == JSON_INT) ? json_get_int(v) : -1;
    rtx_end(&c);
    return ok;
}

/* One-beat drive, stats zeroed first. */
static long long rtx_beat_once(struct rcv_beat_stats *st)
{
    struct rcv_drive_opts o;
    rtx_opts(&o, 1);
    memset(st, 0, sizeof(*st));
    return zcl_devagent_receive_drive(&o, st);
}

/* Is a raw directive pull over this box's mail already one truncated
 * page, i.e. is the history larger than one response? */
static bool rtx_history_pages(void)
{
    struct rtx_call c;
    const struct json_value *tr;
    bool paged;
    rtx_begin(&c, "dev.agent.mail", "zcl.agent_mail.v1");
    (void)json_push_kv_str(&c.input, "action", "pull");
    (void)json_push_kv_int(&c.input, "since", 0);
    (void)json_push_kv_str(&c.input, "kind", "directive");
    zcl_native_handle_dev_agent_mail(&c.request, &c.reply);
    tr = json_get(&c.reply.data, "truncated");
    paged = rtx_ok(&c) && tr && tr->type == JSON_BOOL && json_get_bool(tr);
    rtx_end(&c);
    return paged;
}

static int test_receive_intake_paging(void)
{
    int failures = 0;

    TEST("a history past one response budget never deafens intake")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096];
        rtx_isolate("budget");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        /* 200 directives of ~1.5 KiB for another box: several responses'
         * worth of history this receiver must read past. */
        ASSERT(rtx_deliver_many("chatgpt", "box-b", "hist", 200, 1500));
        ASSERT(rtx_history_pages());
        rtx_direction(body, sizeof(body), "hex_codec", "After the history.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-fresh", body, 201));
        /* A receiver with no cursor pages through and admits it. */
        rtx_opts(&o, 20);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 20);
        ASSERT_EQ(st.intake_failed, 0);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-fresh"), 1);
        /* Caught up, one fresh directive is admitted within one beat. */
        rtx_direction(body, sizeof(body), "hex_codec", "One more.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-fresh2", body, 202));
        ASSERT_EQ(rtx_beat_once(&st), 1);
        ASSERT_EQ(st.intake_failed, 0);
        ASSERT_EQ(st.seen, 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(rtx_answers("job-fresh2", "state=accepted"), 1);
        rtx_restore();
        PASS();
    }

    TEST("more than 128 pending directives are all handled across beats")
    {
        struct rcv_beat_stats st;
        long long total;
        rtx_isolate("backlog");
        /* 300 pending rows from a sender with no grant: each is refused,
         * answered, and marked — cheap to decide, so the case is intake. */
        ASSERT(rtx_deliver_many("stranger", "box-a", "job-b", 300, 0));
        ASSERT_EQ(rtx_beat_once(&st), 1);
        ASSERT_EQ(st.intake_failed, 0);
        /* One beat is bounded: it never swallows the whole backlog. */
        ASSERT(st.seen > 0 && st.seen < 300);
        total = st.seen;
        for (int k = 0; k < 20 && total < 300; k++) {
            ASSERT_EQ(rtx_beat_once(&st), 1);
            ASSERT_EQ(st.intake_failed, 0);
            total += st.seen;
        }
        ASSERT_EQ(total, 300);
        ASSERT_EQ(rtx_count_dir("receive/answered"), 300);
        ASSERT_EQ(rtx_answers("job-b-299", "RECEIVE_SENDER_UNGRANTED"), 1);
        /* Drained: the next beat reads nothing again. */
        ASSERT_EQ(rtx_beat_once(&st), 1);
        ASSERT_EQ(st.seen, 0);
        rtx_restore();
        PASS();
    }

    TEST("a restart resumes from the persisted intake cursor")
    {
        struct rcv_beat_stats st;
        char body[4096], err[64], state[32];
        long long fails;
        rtx_isolate("resume");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "Before restart.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-r1", body, 1));
        ASSERT_EQ(rtx_beat_once(&st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT(rtx_exists("receive/intake.state"));
        /* Without the markers, only the cursor keeps job-r1 from being
         * read, reconciled and answered a second time. */
        ASSERT(rtx_clear_answers());
        rtx_direction(body, sizeof(body), "hex_codec", "After restart.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-r2", body, 2));
        ASSERT_EQ(rtx_beat_once(&st), 1);
        ASSERT_EQ(st.seen, 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(st.reconciled, 0);
        ASSERT_EQ(rtx_queue_count("queued", "job-r1"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-r2"), 1);
        ASSERT_EQ(rtx_answers("job-r1", "state=accepted"), 1);
        ASSERT(rtx_status_intake(err, sizeof(err), &fails, state,
                                 sizeof(state)));
        ASSERT_STR_EQ(state, "resuming");
        ASSERT_EQ(fails, 0);
        rtx_restore();
        PASS();
    }

    TEST("an intake failure is logged, counted and shown, never silent")
    {
        struct rcv_beat_stats st;
        char body[4096], err[64], state[32];
        long long fails;
        rtx_isolate("intakefail");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "First.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-f1", body, 1));
        ASSERT_EQ(rtx_beat_once(&st), 1);
        ASSERT_EQ(st.admitted, 1);
        /* A stream no resume token can name makes the pull refuse. */
        ASSERT(rtx_write("mail/bad name.jsonl", ""));
        ASSERT_EQ(rtx_beat_once(&st), 1);
        ASSERT_EQ(st.intake_failed, 1);
        ASSERT(rtx_status_intake(err, sizeof(err), &fails, state,
                                 sizeof(state)));
        ASSERT_EQ(fails, 1);
        ASSERT_STR_EQ(err, "MAIL_STREAM_NAME_INVALID");
        {
            char bad[1400];
            rtx_path(bad, sizeof(bad), "mail/bad name.jsonl");
            ASSERT_EQ(remove(bad), 0);
        }
        rtx_direction(body, sizeof(body), "hex_codec", "Second.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-f2", body, 2));
        ASSERT_EQ(rtx_beat_once(&st), 1);
        ASSERT_EQ(st.intake_failed, 0);
        ASSERT_EQ(st.admitted, 1);
        /* A stream replaced under the cursor: the stale cursor is dropped
         * and the next beat replays from the start, queueing nothing twice. */
        ASSERT(rtx_write("mail/inbox.chatgpt.jsonl", ""));
        ASSERT_EQ(rtx_beat_once(&st), 1);
        ASSERT_EQ(st.intake_failed, 1);
        ASSERT(rtx_status_intake(err, sizeof(err), &fails, state,
                                 sizeof(state)));
        ASSERT_EQ(fails, 2);
        ASSERT_STR_EQ(err, "MAIL_CURSOR_STALE");
        ASSERT_STR_EQ(state, "from-start");
        rtx_direction(body, sizeof(body), "hex_codec", "Third.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-f3", body, 1));
        ASSERT_EQ(rtx_beat_once(&st), 1);
        ASSERT_EQ(st.intake_failed, 0);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-f1"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-f2"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-f3"), 1);
        rtx_restore();
        PASS();
    }

_test_next:;
    rtx_restore();
    return failures;
}

/* The queued row's integer/string field for `ref`, read back through the
 * queue's own status. -1 / "" when absent. */
static long long rtx_queued_prio(const char *ref, char *dep, size_t cap)
{
    struct rtx_call c;
    const struct json_value *arr;
    long long prio = -1;
    dep[0] = '\0';
    rtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", "status");
    (void)json_push_kv_bool(&c.input, "json", true);
    zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
    arr = rtx_ok(&c) ? json_get(&c.reply.data, "queued") : NULL;
    for (size_t i = 0; arr && arr->type == JSON_ARR && i < json_size(arr);
         i++) {
        const struct json_value *r = json_at(arr, i);
        const char *n = r ? json_get_str(json_get(r, "name")) : NULL;
        if (!n || strcmp(n, ref) != 0)
            continue;
        prio = json_get_int(json_get(r, "priority"));
        (void)snprintf(dep, cap, "%s",
                       json_get_str(json_get(r, "depends_on"))
                           ? json_get_str(json_get(r, "depends_on")) : "");
    }
    rtx_end(&c);
    return prio;
}

/* muse-priority and muse-depends-on reach the queue row the worker claims
 * by (priority, seq) and dependency; a malformed one refuses by name. */
static int test_receive_queue_order(void)
{
    int failures = 0;

    TEST("muse-priority and muse-depends-on ride into the queue row")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char dep[96], ws[1200];
        rtx_isolate("order");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_rtx_base);
        ASSERT(rtx_checkout(ws, "6666666666666666666666666666666666666666"));
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-ordered",
            "muse-workspace: receiver\nmuse-scope: src/x.c\n"
            "muse-gate: hex_codec\nmuse-priority: 1\n"
            "muse-depends-on: job-parent\n\nOrdered.\n", 1));
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-badprio",
            "muse-workspace: receiver\nmuse-scope: src/x.c\n"
            "muse-gate: hex_codec\nmuse-priority: 7\n\nBad.\n", 2));
        rtx_opts_ws(&o, ws);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(rtx_queued_prio("job-ordered", dep, sizeof(dep)), 1);
        ASSERT_STR_EQ(dep, "job-parent");
        ASSERT_EQ(rtx_answers("job-badprio", "muse-priority"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-badprio"), 0);
        PASS();
    }
_test_next:;
    rtx_restore();
    return failures;
}
#endif /* !defined(_WIN32) */

int test_devagent_receive(void);
int test_devagent_receive(void)
{
    int failures = 0;

#if !defined(_WIN32)
    failures += test_receive_intake_paging();
    failures += test_receive_queue_order();

    TEST("a granted directive becomes one queue row and one accept")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        struct rtx_call v;
        char body[4096], why[256];
        rtx_isolate("admit");
        /* The registry admits this leaf's keys, integers included, so the
         * shell spelling reaches the handler. */
        rtx_begin(&v, "dev.agent.receive", "zcl.agent_receive.v1");
        (void)json_push_kv_str(&v.input, "action", "run");
        (void)json_push_kv_str(&v.input, "receiver", "box-a");
        (void)json_push_kv_int(&v.input, "max_beats", 1);
        (void)json_push_kv_int(&v.input, "wait_ms", 50);
        (void)json_push_kv_int(&v.input, "deadline_s", 5);
        ASSERT(v.request.spec != NULL);
        ASSERT(zcl_command_registry_input_validate(v.request.spec, &v.input,
                                                   why, sizeof(why)));
        rtx_end(&v);
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "Make x.c faster.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-001", body, 1));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.seen, 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(st.refused, 0);
        /* The queue row IS the record, under the ref, with the direction's
         * own kind, gate and scope. */
        ASSERT_EQ(rtx_queue_count("queued", "job-001"), 1);
        /* The accept carries the queue seq and the brief digest. */
        ASSERT_EQ(rtx_answers("job-001", "state=accepted"), 1);
        ASSERT_EQ(rtx_answers("job-001", "queue_seq=1"), 1);
        ASSERT_EQ(rtx_answers("job-001", "brief_sha3="), 1);
        ASSERT(rtx_exists("receive/brief/job-001.brief"));
        rtx_restore();
        PASS();
    }

    TEST("an ungranted, revoked, or expired sender is refused")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], id[64];
        rtx_isolate("grant");
        rtx_direction(body, sizeof(body), "hex_codec", "Do it.");
        /* No grant at all. */
        ASSERT(rtx_deliver("stranger", "box-a", "job-ug", body, 1));
        /* A grant with the wrong scope. */
        ASSERT(rtx_mint("readonly", "brief", 3600, NULL, 0));
        ASSERT(rtx_deliver("readonly", "box-a", "job-sc", body, 2));
        /* A grant already expired. */
        ASSERT(rtx_mint_expired("stale"));
        ASSERT(rtx_deliver("stale", "box-a", "job-ex", body, 3));
        /* A grant minted then revoked: revocation is re-read every beat. */
        ASSERT(rtx_mint("gone", "send", 3600, id, sizeof(id)));
        ASSERT(rtx_revoke(id));
        ASSERT(rtx_deliver("gone", "box-a", "job-rv", body, 4));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.seen, 4);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 4);
        ASSERT_EQ(rtx_queue_count("queued", "job-ug"), 0);
        ASSERT_EQ(rtx_answers("job-ug", "RECEIVE_SENDER_UNGRANTED"), 1);
        ASSERT_EQ(rtx_answers("job-sc", "STEER_GRANT_SCOPE"), 1);
        ASSERT_EQ(rtx_answers("job-ex", "STEER_GRANT_EXPIRED"), 1);
        ASSERT_EQ(rtx_answers("job-rv", "STEER_GRANT_REVOKED"), 1);
        /* Nothing was written under any refused ref. */
        ASSERT(!rtx_exists("receive/brief/job-ug.brief"));
        rtx_restore();
        PASS();
    }

    /* Proven live on 2026-09-17: a directive sent with one grant's bearer
     * token while claiming another grant's label got PAST this gate and was
     * refused only by the direction parser after it — the sender check had
     * passed on the claimed name alone. Both halves of the close are here:
     * a stamp that belongs to a different credential, and no stamp at all. */
    TEST("a row stamped by another credential is not the sender it claims")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], actor[64];
        rtx_isolate("impersonation");
        rtx_direction(body, sizeof(body), "hex_codec", "Do it.");
        /* Two live send-capable identities. The victim is a real sender
         * with real authority here; that is the point. */
        ASSERT(rtx_mint("victim", "send", 3600, NULL, 0));
        ASSERT(rtx_mint("actor", "send", 3600, actor, sizeof(actor)));
        /* The actor's own stamp, under the victim's name. */
        {
            char stamp[ZCL_FLEET_STEER_BINDING_HEX + 1];
            ASSERT(zcl_fleet_steer_sender_binding(actor, "actor", stamp,
                                                  sizeof(stamp)));
            ASSERT(rtx_deliver_bound("actor", "victim", "box-a", "job-imp",
                                     body, 1, stamp));
        }
        /* A stamp lifted onto a name it was not minted for is refused the
         * same way: the name is folded into the stamp. */
        {
            char stamp[ZCL_FLEET_STEER_BINDING_HEX + 1];
            ASSERT(zcl_fleet_steer_sender_binding(actor, "victim", stamp,
                                                  sizeof(stamp)));
            ASSERT(rtx_deliver_bound("actor", "victim", "box-a", "job-lift",
                                     body, 2, stamp));
        }
        /* The victim itself still gets through: this refuses impersonation,
         * not the sender. */
        ASSERT(rtx_deliver("victim", "box-a", "job-real", body, 3));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.seen, 3);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(st.refused, 2);
        ASSERT_EQ(rtx_answers("job-imp", "RECEIVE_SENDER_UNGRANTED"), 1);
        ASSERT_EQ(rtx_answers("job-imp", "STEER_GRANT_BINDING"), 1);
        ASSERT_EQ(rtx_answers("job-lift", "RECEIVE_SENDER_UNGRANTED"), 1);
        /* No queue row, no brief, nothing dispatched under the claimed
         * name: the refusal happens before any of it exists. */
        ASSERT_EQ(rtx_queue_count("queued", "job-imp"), 0);
        ASSERT_EQ(rtx_queue_count("queued", "job-lift"), 0);
        ASSERT(!rtx_exists("receive/brief/job-imp.brief"));
        ASSERT(!rtx_exists("receive/brief/job-lift.brief"));
        ASSERT_EQ(rtx_queue_count("queued", "job-real"), 1);
        rtx_restore();
        PASS();
    }

    TEST("a row no credential stamped is unattributable, and refused")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096];
        rtx_isolate("unbound");
        rtx_direction(body, sizeof(body), "hex_codec", "Do it.");
        /* The sender is live, send-capable and named exactly right. The
         * row simply proves nothing about who wrote it, and work is
         * dispatched on the strength of who asked. */
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        ASSERT(rtx_deliver_bound("chatgpt", "chatgpt", "box-a", "job-nb",
                                 body, 1, ""));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.seen, 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(rtx_answers("job-nb", "RECEIVE_SENDER_UNBOUND"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-nb"), 0);
        ASSERT(!rtx_exists("receive/brief/job-nb.brief"));
        rtx_restore();
        PASS();
    }

    TEST("an empty or off-alphabet ref is invalid for coordinated work")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096];
        rtx_isolate("ref");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "Do it.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "", body, 1));
        ASSERT(rtx_deliver("chatgpt", "box-a", "../escape", body, 2));
        ASSERT(rtx_deliver("chatgpt", "box-a", "..", body, 3));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.seen, 3);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 3);
        ASSERT_EQ(rtx_answers("", "RECEIVE_REF_INVALID"), 3);
        rtx_restore();
        PASS();
    }

    TEST("a malformed direction refuses without queueing anything")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096];
        rtx_isolate("direction");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        /* No muse-gate. */
        (void)snprintf(body, sizeof(body),
                       "muse-workspace: %s\nmuse-scope: src/x.c\n\nGo.\n",
                       g_rtx_ws);
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-nogate", body, 1));
        /* A workspace that is not an existing absolute directory. */
        (void)snprintf(body, sizeof(body),
                       "muse-workspace: not-absolute\nmuse-scope: src/x.c\n"
                       "muse-gate: hex_codec\n\nGo.\n");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-nows", body, 2));
        /* A scope that climbs out of the repo. */
        (void)snprintf(body, sizeof(body),
                       "muse-workspace: %s\nmuse-scope: ../etc\n"
                       "muse-gate: hex_codec\n\nGo.\n",
                       g_rtx_ws);
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-esc", body, 3));
        /* Header but no prompt. */
        (void)snprintf(body, sizeof(body),
                       "muse-workspace: %s\nmuse-scope: src/x.c\n"
                       "muse-gate: hex_codec\n",
                       g_rtx_ws);
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-noprompt", body, 4));
        /* Free prose with no machine header at all. */
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-prose",
                           "please fix the build\n", 5));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.seen, 5);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 5);
        ASSERT_EQ(rtx_answers("job-nogate", "muse-gate"), 1);
        ASSERT_EQ(rtx_answers("job-nows", "muse-workspace"), 1);
        ASSERT_EQ(rtx_answers("job-esc", "muse-scope"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-nogate"), 0);
        ASSERT_EQ(rtx_queue_count("queued", "job-prose"), 0);
        rtx_restore();
        PASS();
    }

    TEST("the same ref and the same body never queue or execute twice")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096];
        rtx_isolate("idempotent");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "Do it once.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-dup", body, 1));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        /* The identical directive arrives again from the transport under a
         * new stream seq: the queue must not grow. */
        ASSERT(rtx_deliver_as("retry", "chatgpt", "box-a", "job-dup", body, 1));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.reconciled, 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-dup"), 1);
        rtx_restore();
        PASS();
    }

    TEST("one ref with a different body is refused as a conflict")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], other[4096];
        rtx_isolate("conflict");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "First intent.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-one", body, 1));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        rtx_direction(other, sizeof(other), "hex_codec", "Second intent.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-one", other, 2));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.reconciled, 0);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(rtx_answers("job-one", "RECEIVE_REF_CONFLICT"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-one"), 1);
        rtx_restore();
        PASS();
    }

    TEST("an accept is never posted merely because bytes arrived")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], briefdir[1400];
        rtx_isolate("noaccept");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "Do it.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-ro", body, 1));
        /* One beat to create the receive dirs, then put something in the
         * way of the next ref's brief: a fully admissible directive whose
         * work cannot be recorded must refuse, not accept. */
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        rtx_path(briefdir, sizeof(briefdir), "receive/brief/job-ro2.brief");
        ASSERT_EQ(mkdir(briefdir, 0700), 0);
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-ro2", body, 2));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(rtx_answers("job-ro2", "state=accepted"), 0);
        ASSERT_EQ(rtx_answers("job-ro2", "RECEIVE_STATE_UNWRITABLE"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-ro2"), 0);
        ASSERT_EQ(rmdir(briefdir), 0);
        rtx_restore();
        PASS();
    }

    TEST("single instance: a second drive refuses without waiting")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char dir[1400], lock[1500];
        int fd;
        rtx_isolate("single");
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        /* Hold the same lock the drive takes, exactly as a live resident
         * would, and prove the second drive refuses instead of blocking. */
        rtx_path(dir, sizeof(dir), "receive");
        (void)snprintf(lock, sizeof(lock), "%s/receive.lock", dir);
        fd = open(lock, O_RDWR);
        ASSERT(fd >= 0);
        ASSERT_EQ(flock(fd, LOCK_EX | LOCK_NB), 0);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), -1);
        ASSERT_EQ(st.beats, 0);
        ASSERT_EQ(flock(fd, LOCK_UN), 0);
        (void)close(fd);
        /* With the lock free again the loop runs. */
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        rtx_restore();
        PASS();
    }

    TEST("restart mid-flight loses no ref and executes none twice")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], brief[1600], dir[1400];
        FILE *f;
        rtx_isolate("restart");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "Survive a restart.");
        rtx_opts(&o, 1);
        /* One beat to materialize the receive directories. */
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        /* CRASH SHAPE A — the brief was installed and the process died
         * before the queue post. The next beat re-derives everything from
         * files: the ref is not known to any queue row, run dir, or
         * outcome, so it is queued exactly once. */
        rtx_path(dir, sizeof(dir), "receive");
        (void)snprintf(brief, sizeof(brief), "%s/brief/job-rs.brief", dir);
        f = fopen(brief, "wb");
        ASSERT(f != NULL);
        ASSERT(fwrite(body, 1, strlen(body), f) == strlen(body));
        ASSERT_EQ(fclose(f), 0);
        ASSERT_EQ(rtx_queue_count("queued", "job-rs"), 0);
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-rs", body, 1));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-rs"), 1);
        /* CRASH SHAPE B — the queue post landed and the accept never got
         * out. The retry (a fresh row, so no marker covers it) reconciles
         * the existing record and adds no second queue row. */
        ASSERT(rtx_deliver_as("retry", "chatgpt", "box-a", "job-rs", body, 1));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.reconciled, 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-rs"), 1);
        ASSERT_EQ(rtx_answers("job-rs", "state=accepted"), 2);
        /* A run directory alone also makes a ref known. A ref this
         * receiver never briefed is then a conflict, not a second job:
         * fail closed rather than run somebody else's name. */
        {
            char engine[1600];
            rtx_path(engine, sizeof(engine), "engine");
            (void)mkdir(engine, 0700);
            (void)snprintf(brief, sizeof(brief), "%s/job-orphan", engine);
            ASSERT_EQ(mkdir(brief, 0700), 0);
        }
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-orphan", body, 2));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(rtx_answers("job-orphan", "RECEIVE_REF_CONFLICT"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-orphan"), 0);
        rtx_restore();
        PASS();
    }

    TEST("the idle wait is bounded and never a busy poll")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        rtx_isolate("idle");
        /* An exact beat cap proves the wait returns rather than blocking
         * forever. */
        rtx_opts(&o, 3);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 3);
        ASSERT_EQ(st.beats, 3);
        /* Deadline-only: the loop must beat at least once and, because
         * each idle pass parks in the directory-watcher wait for wait_ms
         * instead of spinning, nowhere near the thousands of beats a busy
         * poll would produce inside the same deadline. The bound is a rate
         * ceiling, not a duration: load can only lower the count. */
        memset(&o, 0, sizeof(o));
        (void)snprintf(o.receiver, sizeof(o.receiver), "box-a");
        o.deadline_s = 1;
        o.wait_ms = 200;
        o.max_beats = 0;
        memset(&st, 0, sizeof(st));
        ASSERT(zcl_devagent_receive_drive(&o, &st) >= 1);
        ASSERT(st.beats >= 1);
        ASSERT(st.beats <= 60);
        rtx_restore();
        PASS();
    }

    TEST("watch failure refuses and releases the receiver for recovery")
    {
        struct rtx_call c;
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096];
        rtx_isolate("watch-loss");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "Survive watch loss.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-watch-loss", body, 1));
        rtx_begin(&c, "dev.agent.receive", "zcl.agent_receive.v1");
        (void)json_push_kv_str(&c.input, "action", "run");
        (void)json_push_kv_str(&c.input, "receiver", "box-a");
        (void)json_push_kv_int(&c.input, "max_beats", 2);
        zcl_devagent_receive_test_watch_loss(true);
        zcl_native_handle_dev_agent_receive(&c.request, &c.reply);
        zcl_devagent_receive_test_watch_loss(false);
        ASSERT(!rtx_ok(&c));
        ASSERT(c.reply.exit_code != 0);
        ASSERT_STR_EQ(c.reply.error.code, "RECEIVE_WATCH_LOST");
        rtx_end(&c);
        ASSERT_EQ(rtx_queue_count("queued", "job-watch-loss"), 1);
        ASSERT_EQ(rtx_answers("job-watch-loss", "state=accepted"), 1);
        /* An ordinary next receiver can acquire the released lock. */
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.beats, 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(rtx_queue_count("queued", "job-watch-loss"), 1);
        ASSERT_EQ(rtx_answers("job-watch-loss", "state=accepted"), 1);
        rtx_restore();
        PASS();
    }

    TEST("new mail wakes the watcher this loop waits on")
    {
        struct platform_directory_watcher w;
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char maildir[1400], body[4096];
        enum platform_directory_watch_result r;
        rtx_isolate("wake");
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        rtx_path(maildir, sizeof(maildir), "mail");
        platform_directory_watcher_init(&w);
        ASSERT(platform_directory_watcher_open(&w, maildir));
        /* A transport dropping an inbox file is exactly what must wake the
         * resident, so it is the event the watcher is asked about. */
        rtx_direction(body, sizeof(body), "hex_codec", "Wake up.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-wake", body, 1));
        r = platform_directory_watcher_wait(&w, 5000, NULL, NULL);
        ASSERT(r == PLATFORM_DIRECTORY_WATCH_CHANGED ||
               r == PLATFORM_DIRECTORY_WATCH_OVERFLOW);
        platform_directory_watcher_close(&w);
        rtx_restore();
        PASS();
    }

    TEST("SIGTERM stops new work and leaves a ref's record intact")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        struct sigaction sa, old;
        char body[4096];
        rtx_isolate("sigterm");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "Then stop.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-term", body, 1));
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = rtx_alarm_to_term;
        ASSERT_EQ(sigaction(SIGALRM, &sa, &old), 0);
        memset(&o, 0, sizeof(o));
        (void)snprintf(o.receiver, sizeof(o.receiver), "box-a");
        o.deadline_s = 30;
        o.wait_ms = 200;
        o.max_beats = 0; /* only SIGTERM can end this drive */
        (void)alarm(1);
        memset(&st, 0, sizeof(st));
        /* Without the signal this drive would run for 30 s. It returns. */
        ASSERT(zcl_devagent_receive_drive(&o, &st) >= 1);
        (void)alarm(0);
        ASSERT_EQ(sigaction(SIGALRM, &old, NULL), 0);
        /* The first beat completed and its record is whole. */
        ASSERT_EQ(rtx_queue_count("queued", "job-term"), 1);
        ASSERT_EQ(rtx_answers("job-term", "state=accepted"), 1);
        ASSERT(rtx_exists("receive/brief/job-term.brief"));
        /* The default SIGTERM disposition is restored, so a later kill of
         * this harness still ends it. */
        rtx_restore();
        PASS();
    }

    TEST("a long turn under the worker never blocks intake or status")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        struct rtx_call c;
        char body[4096], other[4096];
        rtx_isolate("nonblocking");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction(body, sizeof(body), "hex_codec", "The long one.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-long", body, 1));
        rtx_opts(&o, 1);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        /* The worker claims it: from here the job is a running model turn
         * that will not finish for a long time. The receiver holds no part
         * of that run — it is another resident's process. */
        ASSERT(rtx_queue("claim", "worker", "wtx", "session", "s1"));
        ASSERT_EQ(rtx_queue_count("running", "job-long"), 1);
        /* Intake keeps admitting a different ref while that runs. */
        rtx_direction(other, sizeof(other), "hex_codec", "The short one.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-next", other, 2));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-next"), 1);
        ASSERT_EQ(rtx_answers("job-next", "state=accepted"), 1);
        /* The running ref is re-answered from its existing record, and is
         * never queued or executed a second time. */
        ASSERT_EQ(rtx_queue_count("running", "job-long"), 1);
        /* Status answers while the turn runs, and says so. */
        memset(&st, 0, sizeof(st));
        ASSERT(zcl_devagent_receive_survey("box-a", "", &st) >= 0);
        ASSERT_EQ(st.seen, 2);
        /* And the leaf's own status action answers too. */
        rtx_begin(&c, "dev.agent.receive", "zcl.agent_receive.v1");
        (void)json_push_kv_str(&c.input, "action", "status");
        (void)json_push_kv_str(&c.input, "receiver", "box-a");
        zcl_native_handle_dev_agent_receive(&c.request, &c.reply);
        ASSERT(rtx_ok(&c));
        ASSERT_STR_EQ(rtx_reply_str(&c, "state"), "surveyed");
        rtx_end(&c);
        rtx_restore();
        PASS();
    }

    TEST("status decides the same facts and writes nothing")
    {
        struct rtx_call c;
        struct rcv_beat_stats st;
        rtx_isolate("status");
        /* A cold box: status must not bring the receiver, mail, or queue
         * state into existence just by being asked. */
        rtx_begin(&c, "dev.agent.receive", "zcl.agent_receive.v1");
        (void)json_push_kv_str(&c.input, "action", "status");
        (void)json_push_kv_str(&c.input, "receiver", "box-a");
        zcl_native_handle_dev_agent_receive(&c.request, &c.reply);
        ASSERT(rtx_ok(&c));
        ASSERT_STR_EQ(rtx_reply_str(&c, "lock"), "never-run");
        ASSERT_STR_EQ(rtx_reply_str(&c, "mail"), "absent");
        rtx_end(&c);
        ASSERT(!rtx_exists("receive"));
        ASSERT(!rtx_exists("mail"));
        ASSERT(!rtx_exists("queue"));
        /* A bad receiver name is refused, and still writes nothing. */
        rtx_begin(&c, "dev.agent.receive", "zcl.agent_receive.v1");
        (void)json_push_kv_str(&c.input, "action", "status");
        (void)json_push_kv_str(&c.input, "receiver", "not a name!");
        zcl_native_handle_dev_agent_receive(&c.request, &c.reply);
        ASSERT(!rtx_ok(&c));
        rtx_end(&c);
        ASSERT(!rtx_exists("receive"));
        /* An unknown action is refused by name. */
        rtx_begin(&c, "dev.agent.receive", "zcl.agent_receive.v1");
        (void)json_push_kv_str(&c.input, "action", "drive");
        (void)json_push_kv_str(&c.input, "receiver", "box-a");
        zcl_native_handle_dev_agent_receive(&c.request, &c.reply);
        ASSERT(!rtx_ok(&c));
        rtx_end(&c);
        memset(&st, 0, sizeof(st));
        ASSERT(zcl_devagent_receive_survey("bad name", "", &st) < 0);
        rtx_restore();
        PASS();
    }

    /* ── receiver-side workspace resolution ───────────────────────────────
     * A directive minted on another box cannot carry this box's paths: it
     * does not know them, and dev.agent.mail refuses a body naming an
     * absolute path outside the caller's own checkout. So the wire carries a
     * selector and the RECEIVER resolves it. Every case below proves one
     * half of that: only a known selector is honoured, and the resolution
     * itself is fail-closed. */

    TEST("a selector resolves to the configured workspace, exactly once")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        struct rcv_workspace w;
        char body[4096], brief[8192], record[2048], ws[1200];
        rtx_isolate("selector");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_rtx_base);
        ASSERT(rtx_checkout(ws, "1111111111111111111111111111111111111111"));
        /* The observer answers from files alone: no git, no spawn. */
        ASSERT(zcl_devagent_workspace_observe(ws, true, &w));
        ASSERT(w.directory);
        ASSERT(w.resolved);
        ASSERT(w.checkout);
        ASSERT_STR_EQ(w.head, "1111111111111111111111111111111111111111");
        ASSERT_EQ(w.dirty, 0);
        ASSERT_EQ(w.tracked, 1);
        ASSERT(w.tree[0] != '\0');
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction_sel(body, sizeof(body), "receiver", "", "Do it there.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-sel", body, 1));
        rtx_opts_ws(&o, ws);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(st.refused, 0);
        ASSERT_EQ(rtx_queue_count("queued", "job-sel"), 1);
        /* The brief the worker is handed carries the RESOLVED absolute
         * path, so the executor needs no change at all, and muse-scope is
         * untouched and still relative to that workspace. */
        ASSERT(rtx_read("receive/brief/job-sel.brief", brief, sizeof(brief)));
        ASSERT(strstr(brief, ws) != NULL);
        ASSERT(strstr(brief, "muse-workspace: receiver") == NULL);
        ASSERT(strstr(brief, "muse-scope: src/x.c") != NULL);
        /* The RECEIVED bytes are kept beside it, exactly as they arrived. */
        ASSERT(rtx_read("receive/brief/job-sel.received", record,
                        sizeof(record)));
        ASSERT_STR_EQ(record, body);
        /* The record names the selector, the resolved path, and the source
         * identity of the workspace that answered. */
        ASSERT(rtx_read("receive/brief/job-sel.evidence", record,
                        sizeof(record)));
        ASSERT(strstr(record, "workspace_selector=receiver") != NULL);
        ASSERT(strstr(record,
                      "workspace_head=1111111111111111111111111111111111"
                      "111111") != NULL);
        ASSERT(strstr(record, "workspace_tree_sha3=") != NULL);
        ASSERT(strstr(record, ws) != NULL);
        /* The answer carries that identity and NO path of any kind: the
         * mail leaf refuses a body naming one, and a peer has no use for
         * this box's filesystem. The digest is what it can check. */
        ASSERT_EQ(rtx_answers("job-sel", "workspace_selector=receiver"), 1);
        ASSERT_EQ(rtx_answers("job-sel", "workspace_head=1111"), 1);
        ASSERT_EQ(rtx_answers("job-sel", "workspace_sha3="), 1);
        ASSERT_EQ(rtx_answers("job-sel", "workspace_tree_sha3="), 1);
        ASSERT_EQ(rtx_answers("job-sel", ws), 0);
        rtx_restore();
        PASS();
    }

    TEST("only a known selector is honoured; anything else refuses")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], ws[1200];
        rtx_isolate("unknown");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_rtx_base);
        ASSERT(rtx_checkout(ws, "2222222222222222222222222222222222222222"));
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        /* A word this box does not know is not a path and never becomes
         * one. */
        rtx_direction_sel(body, sizeof(body), "workstation", "", "Go.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-unk", body, 1));
        /* A selector dressed as a traversal is still just an unknown
         * word. */
        rtx_direction_sel(body, sizeof(body), "receiver/../../etc", "", "Go.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-trav", body, 2));
        /* And "." is the ONE other spelling that IS honoured. */
        rtx_direction_sel(body, sizeof(body), ".", "", "Go here.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-dot", body, 3));
        rtx_opts_ws(&o, ws);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(st.refused, 2);
        ASSERT_EQ(rtx_answers("job-unk",
                              "RECEIVE_WORKSPACE_SELECTOR_UNKNOWN"), 1);
        ASSERT_EQ(rtx_answers("job-trav",
                              "RECEIVE_WORKSPACE_SELECTOR_UNKNOWN"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-unk"), 0);
        ASSERT_EQ(rtx_queue_count("queued", "job-trav"), 0);
        ASSERT_EQ(rtx_queue_count("queued", "job-dot"), 1);
        ASSERT(!rtx_exists("receive/brief/job-unk.brief"));
        rtx_restore();
        PASS();
    }

    TEST("the configured root is canonicalized, and a climb never starts")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        struct rcv_workspace w;
        char body[4096], brief[8192], ws[1200], link[1200], climb[1300];
        char dots[1300];
        rtx_isolate("escape");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_rtx_base);
        (void)snprintf(link, sizeof(link), "%s/link", g_rtx_base);
        (void)snprintf(climb, sizeof(climb), "%s/wt/../wt", g_rtx_base);
        ASSERT(rtx_checkout(ws, "3333333333333333333333333333333333333333"));
        ASSERT_EQ(symlink(ws, link), 0);
        /* A configured root reached through a symlink is RESOLVED, not
         * refused: realpath names the one real directory. Demanding that
         * the operator's spelling already be its own canonical path
         * refuses every workspace below a symlinked component — a Mac's
         * /tmp is /private/tmp — which breaks availability and buys no
         * safety, because realpath is what decides where the work lands. */
        ASSERT(zcl_devagent_workspace_observe(link, true, &w));
        ASSERT(w.directory);
        ASSERT(w.resolved);
        ASSERT_STR_EQ(w.root, ws);
        ASSERT(w.checkout);
        ASSERT_EQ(w.dirty, 0);
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction_sel(body, sizeof(body), "receiver", "", "Through it.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-link", body, 1));
        rtx_opts_ws(&o, link);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(st.refused, 0);
        ASSERT_EQ(rtx_queue_count("queued", "job-link"), 1);
        /* The brief carries the canonical path, never the link spelling,
         * so two spellings of one workspace cannot look like two. */
        ASSERT(rtx_read("receive/brief/job-link.brief", brief,
                        sizeof(brief)));
        ASSERT(strstr(brief, ws) != NULL);
        ASSERT(strstr(brief, link) == NULL);
        /* A directory whose NAME merely STARTS with two dots holds no ".."
         * segment of its own, so the flag accepts it and the only refusal
         * comes from the workspace not being there. The coarser rule —
         * refuse any ".." right after a slash — rejected this name at the
         * door and never started a drive at all. */
        (void)snprintf(dots, sizeof(dots), "%s/..hidden", g_rtx_base);
        rtx_direction_sel(body, sizeof(body), "receiver", "", "Dotted.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-dots", body, 2));
        rtx_opts_ws(&o, dots);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(rtx_answers("job-dots", "RECEIVE_WORKSPACE_MISSING"), 1);
        /* A ".." segment in the operator's own flag never even starts a
         * drive: a typo is loud at the door instead of silently refusing
         * every directive later. */
        rtx_opts_ws(&o, climb);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), -1);
        ASSERT_EQ(st.beats, 0);
        rtx_restore();
        PASS();
    }

    TEST("with no workspace configured a selector refuses, never guesses")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        struct rtx_call c;
        char body[4096];
        rtx_isolate("unconfigured");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction_sel(body, sizeof(body), "receiver", "", "Guess.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-nocfg", body, 1));
        rtx_opts_ws(&o, "");
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(rtx_answers("job-nocfg",
                              "RECEIVE_WORKSPACE_UNCONFIGURED"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-nocfg"), 0);
        /* No cwd, no $HOME, no discovered checkout ended up in a brief. */
        ASSERT(!rtx_exists("receive/brief/job-nocfg.brief"));
        /* And status says plainly which state it is in. */
        rtx_begin(&c, "dev.agent.receive", "zcl.agent_receive.v1");
        (void)json_push_kv_str(&c.input, "action", "status");
        (void)json_push_kv_str(&c.input, "receiver", "box-a");
        zcl_native_handle_dev_agent_receive(&c.request, &c.reply);
        ASSERT(rtx_ok(&c));
        ASSERT_STR_EQ(rtx_reply_str(&c, "workspace_state"), "unconfigured");
        rtx_end(&c);
        rtx_restore();
        PASS();
    }

    TEST("a muse-sha that is not the resolved HEAD refuses; a match admits")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], ws[1200];
        rtx_isolate("shapin");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_rtx_base);
        ASSERT(rtx_checkout(ws, "4444444444444444444444444444444444444444"));
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        /* The client pins an image this workspace is not on. */
        rtx_direction_sel(body, sizeof(body), "receiver",
                          "5555555555555555555555555555555555555555",
                          "Certify.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-wrongsha", body, 1));
        /* And one it is, by unambiguous prefix. */
        rtx_direction_sel(body, sizeof(body), "receiver", "444444444444",
                          "Certify.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-rightsha", body, 2));
        rtx_opts_ws(&o, ws);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(rtx_answers("job-wrongsha",
                              "RECEIVE_WORKSPACE_SHA_MISMATCH"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-wrongsha"), 0);
        ASSERT_EQ(rtx_queue_count("queued", "job-rightsha"), 1);
        rtx_restore();
        PASS();
    }

    TEST("a configured workspace that is not a checkout refuses")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        struct rcv_workspace w;
        char body[4096], ws[1200];
        rtx_isolate("notcheckout");
        /* A real directory the operator pointed at by mistake: it is
         * there, it resolves, and it holds no .git. This is the most
         * likely of the workspace refusals in practice — a typo, or a
         * lane directory that was removed and recreated — and it was the
         * one with no case, so the branch could have inverted and every
         * other workspace test would still have passed. */
        (void)snprintf(ws, sizeof(ws), "%s/plain", g_rtx_base);
        ASSERT_EQ(mkdir(ws, 0700), 0);
        ASSERT(zcl_devagent_workspace_observe(ws, true, &w));
        ASSERT(w.directory);
        ASSERT(w.resolved);
        ASSERT(!w.checkout);
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction_sel(body, sizeof(body), "receiver", "", "Nowhere.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-nogit", body, 1));
        rtx_opts_ws(&o, ws);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(rtx_answers("job-nogit",
                              "RECEIVE_WORKSPACE_NOT_A_CHECKOUT"), 1);
        ASSERT_EQ(rtx_answers("job-nogit",
                              "configured-workspace-not-a-checkout"), 1);
        /* Nothing reached the queue and no brief was written, so no
         * worker can start a turn against a tree with no history. */
        ASSERT_EQ(rtx_queue_count("queued", "job-nogit"), 0);
        ASSERT(!rtx_exists("receive/brief/job-nogit.brief"));
        rtx_restore();
        PASS();
    }

    TEST("a dirty resolved workspace refuses early, with the paths named")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        struct rcv_workspace w;
        char body[4096], ws[1200];
        rtx_isolate("dirty");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_rtx_base);
        ASSERT(rtx_checkout(ws, "6666666666666666666666666666666666666666"));
        /* One tracked path now diverges from what the index recorded. */
        ASSERT(rtx_put(ws, "src/x.c",
                       "int zx(void) { return 1; } /* edited on the box */\n"));
        ASSERT(zcl_devagent_workspace_observe(ws, true, &w));
        ASSERT(w.checkout);
        ASSERT_EQ(w.dirty, 1);
        ASSERT_STR_EQ(w.dirty_names, "src/x.c");
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction_sel(body, sizeof(body), "receiver", "", "On a mess.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-dirty", body, 1));
        rtx_opts_ws(&o, ws);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(rtx_answers("job-dirty", "RECEIVE_WORKSPACE_DIRTY"), 1);
        ASSERT_EQ(rtx_answers("job-dirty", "dirty-tracked-paths-1"), 1);
        /* Nothing reached the queue, so no worker can start a turn on it. */
        ASSERT_EQ(rtx_queue_count("queued", "job-dirty"), 0);
        ASSERT(!rtx_exists("receive/brief/job-dirty.brief"));
        rtx_restore();
        PASS();
    }

    TEST("a byte-identical replay reconciles and never re-resolves")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], brief[8192], ws[1200];
        rtx_isolate("replay");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_rtx_base);
        ASSERT(rtx_checkout(ws, "7777777777777777777777777777777777777777"));
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction_sel(body, sizeof(body), "receiver", "", "Once only.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-rep", body, 1));
        rtx_opts_ws(&o, ws);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        /* Now make the workspace dirty. A receiver that re-resolved a
         * settled ref would refuse this replay; one that reconciles from
         * the RECEIVED bytes answers the same terminal evidence. The
         * comparison must be against what was received, not against the
         * rewritten brief, or the replay would read as a false conflict. */
        ASSERT(rtx_put(ws, "src/x.c", "int zx(void) { return 2; } /* x */\n"));
        ASSERT(rtx_deliver_as("retry", "chatgpt", "box-a", "job-rep", body, 1));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 0);
        ASSERT_EQ(st.reconciled, 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-rep"), 1);
        ASSERT_EQ(rtx_answers("job-rep", "state=accepted"), 2);
        /* The replay's answer repeats the evidence the ref was decided
         * with, not a fresh resolution. */
        ASSERT_EQ(rtx_answers("job-rep", "workspace_selector=receiver"), 2);
        ASSERT(rtx_read("receive/brief/job-rep.brief", brief, sizeof(brief)));
        ASSERT(strstr(brief, ws) != NULL);
        rtx_restore();
        PASS();
    }

    TEST("the same ref with a different body is still a conflict")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], other[4096], ws[1200];
        rtx_isolate("selconflict");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_rtx_base);
        ASSERT(rtx_checkout(ws, "8888888888888888888888888888888888888888"));
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction_sel(body, sizeof(body), "receiver", "", "First.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-two", body, 1));
        rtx_opts_ws(&o, ws);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        rtx_direction_sel(other, sizeof(other), "receiver", "", "Second.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-two", other, 2));
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.reconciled, 0);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(rtx_answers("job-two", "RECEIVE_REF_CONFLICT"), 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-two"), 1);
        rtx_restore();
        PASS();
    }

    TEST("a receiver restarted elsewhere cannot move decided work")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], brief[8192], first[1200], second[1200];
        rtx_isolate("remap");
        (void)snprintf(first, sizeof(first), "%s/wt1", g_rtx_base);
        (void)snprintf(second, sizeof(second), "%s/wt2", g_rtx_base);
        ASSERT(rtx_checkout(first, "9999999999999999999999999999999999999999"));
        ASSERT(rtx_checkout(second,
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        rtx_direction_sel(body, sizeof(body), "receiver", "", "Stay put.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-map", body, 1));
        rtx_opts_ws(&o, first);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        /* The operator restarts the receiver against a DIFFERENT workspace
         * and the same row arrives again. The decided ref keeps the path it
         * was decided with; nothing is queued again and nothing can run in
         * the new workspace. */
        ASSERT(rtx_deliver_as("retry", "chatgpt", "box-a", "job-map", body, 1));
        rtx_opts_ws(&o, second);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.reconciled, 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-map"), 1);
        ASSERT(rtx_read("receive/brief/job-map.brief", brief, sizeof(brief)));
        ASSERT(strstr(brief, first) != NULL);
        ASSERT(strstr(brief, second) == NULL);
        rtx_restore();
        PASS();
    }

    TEST("an absolute workspace still works for the same-box case")
    {
        struct rcv_drive_opts o;
        struct rcv_beat_stats st;
        char body[4096], brief[8192], ws[1200];
        rtx_isolate("absolute");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_rtx_base);
        ASSERT(rtx_checkout(ws, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
        /* g_rtx_ws is a bare directory: no .git, no index, nothing. The
         * same-box rule is exactly what it always was — an existing
         * absolute directory — so this must still be admitted whether or
         * not a workspace is configured, and the resolution machinery must
         * not start vouching for a path the sender chose. */
        rtx_direction(body, sizeof(body), "hex_codec", "Local as ever.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-abs", body, 1));
        rtx_opts_ws(&o, ws);
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(st.refused, 0);
        ASSERT_EQ(rtx_queue_count("queued", "job-abs"), 1);
        ASSERT(rtx_read("receive/brief/job-abs.brief", brief, sizeof(brief)));
        ASSERT(strstr(brief, g_rtx_ws) != NULL);
        ASSERT(strstr(brief, ws) == NULL);
        ASSERT_EQ(rtx_answers("job-abs", "workspace_selector=absolute"), 1);
        /* And with nothing configured at all. */
        rtx_direction(body, sizeof(body), "hex_codec", "Still local.");
        ASSERT(rtx_deliver("chatgpt", "box-a", "job-abs2", body, 2));
        rtx_opts_ws(&o, "");
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(rtx_queue_count("queued", "job-abs2"), 1);
        rtx_restore();
        PASS();
    }

    TEST("this leaf is never remotely callable and never spawns")
    {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(),
                                      "dev.agent.receive", NULL);
        rtx_isolate("shape");
        ASSERT(spec != NULL);
        /* A directive addressed to another receiver is not this box's
         * work, and is not even counted as seen. */
        {
            struct rcv_drive_opts o;
            struct rcv_beat_stats st;
            char body[4096];
            ASSERT(rtx_mint("chatgpt", "send", 3600, NULL, 0));
            rtx_direction(body, sizeof(body), "hex_codec", "Not yours.");
            ASSERT(rtx_deliver("chatgpt", "box-b", "job-other", body, 1));
            rtx_opts(&o, 1);
            memset(&st, 0, sizeof(st));
            ASSERT_EQ(zcl_devagent_receive_drive(&o, &st), 1);
            ASSERT_EQ(st.seen, 0);
            ASSERT_EQ(rtx_queue_count("queued", "job-other"), 0);
        }
        rtx_restore();
        PASS();
    }
#endif /* !defined(_WIN32) */

_test_next:;
    rtx_restore();
    if (failures == 0)
        printf("test_devagent_receive: all passed\n");
    else
        printf("test_devagent_receive: %d FAILED\n", failures);
    return failures;
}
