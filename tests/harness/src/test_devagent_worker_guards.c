/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for the worker-side pre-spend guards
 * (tools/command/native_devagent_worker.c, wkr_prespend_guard) and the
 * receiver evidence they read (tools/command/native_devagent_receive.c,
 * rcv_evidence_render).
 *
 * Written against an isolated XDG_STATE_HOME, never the operator's real
 * state dir. No model, no network: rows are admitted through the real
 * receiver leaf (mail transport file, grant store, selector workspace) or
 * posted through the real queue leaf, and the worker is driven DIRECTLY
 * with a counting fixture executor or the refusing production seam
 * (zcl_devagent_worker_no_executor, zero model tokens).
 *
 * Each case pins one proof-gap clause:
 *   (a) an admitted row sits unclaimed while no worker drives;
 *   (b) a resident drive auto-claims it with zero executor invocations;
 *   (c) an empty-queue drive launches nothing on a bounded idle wait;
 *   (d) a second concurrent drive refuses on worker.lock;
 *   (e) kill after claim with submitted:false restarts to exactly-once,
 *       while submitted:true restarts to crash-record with no resubmission;
 *   (f) an authority dead at claim time (revoked, expired) or a workspace
 *       moved or dirtied at claim time refuses before the fork — submitted
 *       never flips, the executor never runs, the receipt is never written.
 *   Missing or unreadable evidence fails closed the same way.
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_devagent.h"
#include "command/native_fleet.h"
#include "config/command_catalog.h"
#include "controllers/agent_impact_rules.h"
#include "devloop.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#if defined(_WIN32)
#include "platform/windows_path.h"
#include <windows.h>
#endif

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
#include <sys/wait.h>
#include <unistd.h>
#endif

#if !defined(_WIN32)

/* ── isolated state root (this group owns its own rig) ─────────────────── */

static char g_gtx_state[1024];
static char g_gtx_base[1024];
static char g_gtx_saved_xdg[4096];
static bool g_gtx_had_xdg;
static char g_gtx_count[1024];
static int g_gtx_ts;

static void gtx_isolate(const char *tag)
{
    char base[512];
    /* realpath() writes up to PATH_MAX bytes and glibc's fortify check
     * aborts on anything smaller, whatever the input length. */
    char real[PATH_MAX];
    test_make_tmpdir(base, sizeof(base), "devagent_guards", tag);
    if (realpath(base, real) != NULL)
        (void)snprintf(base, sizeof(base), "%s", real);
    (void)snprintf(g_gtx_state, sizeof(g_gtx_state), "%s/state", base);
    (void)snprintf(g_gtx_base, sizeof(g_gtx_base), "%s", base);
    (void)snprintf(g_gtx_count, sizeof(g_gtx_count), "%s/fx.count", base);
    (void)remove(g_gtx_count);
    g_gtx_had_xdg = getenv("XDG_STATE_HOME") != NULL;
    if (g_gtx_had_xdg)
        (void)snprintf(g_gtx_saved_xdg, sizeof(g_gtx_saved_xdg), "%s",
                       getenv("XDG_STATE_HOME"));
    setenv("XDG_STATE_HOME", g_gtx_state, 1);
    g_gtx_ts = 0;
}

static void gtx_restore(void)
{
    if (g_gtx_had_xdg)
        setenv("XDG_STATE_HOME", g_gtx_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
}

/* ── one in-process leaf invocation ────────────────────────────────────── */

struct gtx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void gtx_begin(struct gtx_call *c, const char *path,
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

static void gtx_end(struct gtx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool gtx_ok(const struct gtx_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *gtx_reply_str(const struct gtx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return (v && v->type == JSON_STR && json_get_str(v)) ? json_get_str(v)
                                                        : "";
}

/* ── grant store ───────────────────────────────────────────────────────── */

static bool gtx_mint(const char *label, const char *scopes, long long ttl,
                     char *id, size_t cap)
{
    struct gtx_call c;
    bool ok;
    gtx_begin(&c, "fleet.steer.grant", "zcl.fleet_steer_grant.v1");
    (void)json_push_kv_str(&c.input, "action", "mint");
    (void)json_push_kv_str(&c.input, "scopes", scopes);
    (void)json_push_kv_str(&c.input, "label", label);
    (void)json_push_kv_int(&c.input, "ttl_seconds", ttl);
    zcl_native_handle_fleet_steer_grant(&c.request, &c.reply);
    ok = gtx_ok(&c);
    if (ok && id)
        (void)snprintf(id, cap, "%s", gtx_reply_str(&c, "id"));
    gtx_end(&c);
    return ok;
}

static bool gtx_revoke(const char *id)
{
    struct gtx_call c;
    bool ok;
    gtx_begin(&c, "fleet.steer.grant", "zcl.fleet_steer_grant.v1");
    (void)json_push_kv_str(&c.input, "action", "revoke");
    (void)json_push_kv_str(&c.input, "id", id);
    zcl_native_handle_fleet_steer_grant(&c.request, &c.reply);
    ok = gtx_ok(&c);
    gtx_end(&c);
    return ok;
}

/* ── state-root files ──────────────────────────────────────────────────── */

static void gtx_path(char *out, size_t cap, const char *tail)
{
    (void)snprintf(out, cap, "%s/z23/dev/%s", g_gtx_state, tail);
}

static bool gtx_exists(const char *tail)
{
    char path[1400];
    struct stat st;
    gtx_path(path, sizeof(path), tail);
    return stat(path, &st) == 0;
}

static bool gtx_read(const char *tail, char *out, size_t cap)
{
    char path[1400];
    FILE *f;
    size_t n;
    gtx_path(path, sizeof(path), tail);
    out[0] = '\0';
    f = fopen(path, "rb");
    if (!f)
        return false;
    n = fread(out, 1, cap - 1, f);
    out[n] = '\0';
    return fclose(f) == 0 && n > 0;
}

static bool gtx_has(const char *tail, const char *needle)
{
    char text[8192];
    return gtx_read(tail, text, sizeof(text)) && strstr(text, needle) != NULL;
}

/* ── mail transport: one stamped directive, the way a transport writes it ─ */

static bool gtx_deliver(const char *peer, const char *ref, const char *body,
                        long long seq, const char *binding)
{
    char dir[1200], path[1400], esc[8192];
    size_t o = 0;
    FILE *f;
    (void)snprintf(dir, sizeof(dir), "%s", g_gtx_state);
    (void)mkdir(dir, 0700);
    (void)snprintf(dir, sizeof(dir), "%s/z23", g_gtx_state);
    (void)mkdir(dir, 0700);
    (void)snprintf(dir, sizeof(dir), "%s/z23/dev", g_gtx_state);
    (void)mkdir(dir, 0700);
    (void)snprintf(dir, sizeof(dir), "%s/z23/dev/mail", g_gtx_state);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        return false;
    (void)snprintf(path, sizeof(path), "%s/inbox.%s.jsonl", dir, peer);
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
    g_gtx_ts++;
    (void)fprintf(f,
                  "{\"seq\":%lld,\"ts\":\"2026-09-21T00:%02d:%02dZ\","
                  "\"from\":\"%s\",\"to\":\"box-a\",\"kind\":\"directive\","
                  "\"body\":\"%s\",\"ref\":\"%s\"",
                  seq, (int)(g_gtx_ts / 60) % 60, (int)(g_gtx_ts % 60), peer,
                  esc, ref);
    if (binding && binding[0])
        (void)fprintf(f, ",\"sender_binding\":\"%s\"", binding);
    (void)fprintf(f, "}\n");
    return fclose(f) == 0;
}

/* One direction body with a LOGICAL workspace value — all a remote sender
 * may carry. */
static void gtx_direction_sel(char *out, size_t cap, const char *prompt)
{
    (void)snprintf(out, cap,
                   "muse-workspace: receiver\nmuse-scope: src/x.c\n"
                   "muse-gate: hex_codec\n\n%s\n",
                   prompt);
}

/* ── a real-enough git checkout, built from the same bytes git writes ──── */

static bool gtx_put(const char *dir, const char *rel, const char *text)
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

static void gtx_be32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static bool gtx_index(const char *ws, const char *name, uint32_t mode,
                      uint32_t size, uint32_t mtime)
{
    unsigned char buf[512];
    char path[1600];
    size_t nlen = strlen(name);
    size_t esz = (62u + nlen + 8u) & ~(size_t)7u;
    FILE *f;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "DIRC", 4);
    gtx_be32(buf + 4, 2);
    gtx_be32(buf + 8, 1);
    gtx_be32(buf + 12 + 8, mtime);
    gtx_be32(buf + 12 + 24, mode);
    gtx_be32(buf + 12 + 36, size);
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

static bool gtx_checkout(const char *dir, const char *head)
{
    char path[1600], ref[64];
    struct stat st;
    (void)snprintf(ref, sizeof(ref), "%s\n", head);
    (void)mkdir(dir, 0700);
    (void)snprintf(path, sizeof(path), "%s/.git", dir);
    (void)mkdir(path, 0700);
    (void)snprintf(path, sizeof(path), "%s/.git/refs", dir);
    (void)mkdir(path, 0700);
    (void)snprintf(path, sizeof(path), "%s/.git/refs/heads", dir);
    (void)mkdir(path, 0700);
    (void)snprintf(path, sizeof(path), "%s/src", dir);
    (void)mkdir(path, 0700);
    if (!gtx_put(dir, ".git/HEAD", "ref: refs/heads/x\n") ||
        !gtx_put(dir, ".git/refs/heads/x", ref) ||
        !gtx_put(dir, "src/x.c", "int zx(void) { return 0; }\n"))
        return false;
    (void)snprintf(path, sizeof(path), "%s/src/x.c", dir);
    if (lstat(path, &st) != 0)
        return false;
    return gtx_index(dir, "src/x.c", 0100644u, (uint32_t)st.st_size,
                     (uint32_t)st.st_mtime);
}

/* ── queue verbs ───────────────────────────────────────────────────────── */

static bool gtx_queue_post_leaf(const char *name)
{
    struct gtx_call c;
    bool ok;
    gtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", "post");
    (void)json_push_kv_str(&c.input, "kind", "leaf");
    (void)json_push_kv_str(&c.input, "name", name);
    zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
    ok = gtx_ok(&c);
    gtx_end(&c);
    return ok;
}

static bool gtx_queue_verb(const char *action)
{
    struct gtx_call c;
    bool ok;
    gtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", action);
    if (strcmp(action, "status") == 0)
        (void)json_push_kv_bool(&c.input, "json", true);
    if (strcmp(action, "claim") == 0) {
        (void)json_push_kv_str(&c.input, "worker", "gtx");
        (void)json_push_kv_str(&c.input, "session", "s1");
    }
    zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
    ok = gtx_ok(&c);
    gtx_end(&c);
    return ok;
}

/* How many rows in `bucket` (queued|running) name `ref`. */
static long long gtx_queue_count(const char *bucket, const char *ref)
{
    struct gtx_call c;
    const struct json_value *arr;
    long long hits = 0;
    gtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", "status");
    (void)json_push_kv_bool(&c.input, "json", true);
    zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
    arr = gtx_ok(&c) ? json_get(&c.reply.data, bucket) : NULL;
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
    gtx_end(&c);
    return hits;
}

/* ── worker drive ──────────────────────────────────────────────────────── */

static void gtx_opts(struct wkr_drive_opts *o, const char *worker,
                     const char *session)
{
    memset(o, 0, sizeof(*o));
    (void)snprintf(o->worker, sizeof(o->worker), "%s", worker);
    (void)snprintf(o->session, sizeof(o->session), "%s", session);
    o->deadline_s = 30;
    o->idle_start_s = 1;
    o->idle_limit_s = 3;
    o->max_jobs = 1;
    o->time_cap_s = 30;
    o->cpu_s = 600;
    o->mem_mb = 1024;
    o->token_cap = 32000;
}

/* The executor runs in a forked child, so the run count crosses the
 * fork through an append-only file, never through process memory. */
static void gtx_count_bump(void)
{
    FILE *f;
    if (!g_gtx_count[0])
        return;
    f = fopen(g_gtx_count, "ab");
    if (f) {
        (void)fwrite("x", 1, 1, f);
        (void)fclose(f);
    }
}

static long long gtx_count_read(void)
{
    FILE *f;
    long long n = 0;
    int ch;
    f = fopen(g_gtx_count, "rb");
    if (!f)
        return 0;
    while ((ch = fgetc(f)) != EOF) {
        if (ch == 'x')
            n++;
    }
    (void)fclose(f);
    return n;
}

/* One guided pass with a real candidate file, the shape the gate passes
 * for leaf rows. Zero model tokens: nothing here calls a model. */
static bool gtx_fixture(const struct wkr_job *job, struct wkr_result *res)
{
    char path[4096 + 32];
    FILE *f;
    gtx_count_bump();
    if (!gtx_put(g_gtx_state, "z23/dev/task.txt", job->task)) return false;
    memset(res, 0, sizeof(*res));
    (void)snprintf(res->terminal, sizeof(res->terminal), "%s", "pass");
    res->rc = 0;
    if (snprintf(path, sizeof(path), "%s/cand.diff", job->rundir) >=
        (int)sizeof(path))
        return true;
    f = fopen(path, "wb");
    if (f) {
        (void)fwrite("diff --guard\n", 1, 13, f);
        (void)fclose(f);
        (void)snprintf(res->candidate, sizeof(res->candidate), "%s",
                       "cand.diff");
    }
    (void)snprintf(res->evidence, sizeof(res->evidence), "%s",
                   "guard fixture saw the task");
    res->tokens_used = 0;
    res->wall_ms = 7;
    (void)snprintf(res->provider, sizeof(res->provider), "%s", "guardfix");
    res->turns = 1;
    (void)snprintf(res->command, sizeof(res->command), "%s", "guard-run");
    (void)snprintf(res->source, sizeof(res->source), "%s", "guard/src.c");
    (void)snprintf(res->diff, sizeof(res->diff), "%s", "cand.diff");
    return true;
}

/* Admit one selector directive for `label` through the real receiver and
 * return its queue name (== ref). The caller owns the workspace. */
static bool gtx_admit(struct rcv_drive_opts *ro, const char *label,
                      const char *ref, const char *prompt)
{
    struct rcv_beat_stats st;
    char body[4096], binding[ZCL_FLEET_STEER_BINDING_HEX + 1];
    char gid[64];
    long long expiry = 0;
    if (!gtx_mint(label, "send", 3600, gid, sizeof(gid)))
        return false;
    if (!zcl_fleet_steer_sender_binding(gid, label, binding, sizeof(binding)))
        return false;
    if (!zcl_fleet_steer_grant_expiry(label, "send", &expiry))
        return false;
    (void)expiry;
    gtx_direction_sel(body, sizeof(body), prompt);
    if (!gtx_deliver(label, ref, body, 1, binding))
        return false;
    memset(&st, 0, sizeof(st));
    if (zcl_devagent_receive_drive(ro, &st) != 1)
        return false;
    return st.admitted == 1 && st.refused == 0 &&
           gtx_queue_count("queued", ref) == 1;
}

static void gtx_rcv_opts(struct rcv_drive_opts *o, const char *workspace)
{
    memset(o, 0, sizeof(*o));
    (void)snprintf(o->receiver, sizeof(o->receiver), "box-a");
    (void)snprintf(o->workspace, sizeof(o->workspace), "%s", workspace);
    o->deadline_s = 30;
    o->wait_ms = 50;
    o->max_beats = 1;
}

/* Flip a run's claim.json submitted flag to true, the shape a drive that
 * died after submitting leaves behind. */
static bool gtx_flip_submitted(const char *ref)
{
    char tail[160], text[2048], out[2048];
    const char *hit;
    char path[1400];
    FILE *f;
    size_t pre, rest;
    const char *from = "\"submitted\":false", *to = "\"submitted\":true";
    (void)snprintf(tail, sizeof(tail), "engine/%s/a1/claim.json", ref);
    if (!gtx_read(tail, text, sizeof(text)))
        return false;
    hit = strstr(text, from);
    if (!hit)
        return false;
    pre = (size_t)(hit - text);
    rest = strlen(hit + strlen(from));
    if (pre + strlen(to) + rest >= sizeof(out))
        return false;
    memcpy(out, text, pre);
    memcpy(out + pre, to, strlen(to));
    memcpy(out + pre + strlen(to), hit + strlen(from), rest + 1);
    gtx_path(path, sizeof(path), tail);
    f = fopen(path, "wb");
    if (!f)
        return false;
    (void)fwrite(out, 1, strlen(out), f);
    return fclose(f) == 0;
}

/* One proof-gap clause per case function: the cyclomatic-complexity gate
 * caps every function at M<=15, so the eleven clauses below each own one
 * TEST block and the entry only sums their failures. */

/* Stage the live authority for a directly posted row, the shape the
 * receiver would have installed: the grant's own binding and the expiry
 * the worker must re-read. Starts with a reap so the queue is clean. */
static bool gtx_stage_evidence(const char *ref, const char *sender,
                               const char *gid)
{
    char binding[ZCL_FLEET_STEER_BINDING_HEX + 1];
    char dir[1200], path[1400], text[256];
    long long expiry = 0;
    FILE *f;
    int w;
    char *p;
    (void)gtx_queue_verb("reap");
    if (!zcl_fleet_steer_grant_expiry(sender, "send", &expiry))
        return false;
    if (!zcl_fleet_steer_sender_binding(gid, sender, binding,
                                        sizeof(binding)))
        return false;
    (void)snprintf(dir, sizeof(dir), "%s/z23/dev/receive/brief",
                   g_gtx_state);
    p = dir;
    if (*p == '/')
        p++;
    for (; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            (void)mkdir(dir, 0700);
            *p = '/';
        }
    }
    (void)mkdir(dir, 0700);
    if (snprintf(path, sizeof(path), "%s/%s.evidence", dir, ref) >=
        (int)sizeof(path))
        return false;
    w = snprintf(text, sizeof(text),
                 "sender=%s\nsender_binding=%s\ngrant_expiry=%lld\n",
                 sender, binding, expiry);
    if (w <= 0 || (size_t)w >= sizeof(text))
        return false;
    f = fopen(path, "wb");
    if (!f)
        return false;
    (void)fwrite(text, 1, (size_t)w, f);
    (void)fclose(f);
    return true;
}

/* True when a queue-status outcome row is the named ref's row. */
static bool gtx_row_is_named(const struct json_value *r, const char *name)
{
    const struct json_value *nm;
    const char *s;
    if (r == NULL)
        return false;
    nm = json_get(r, "name");
    if (nm == NULL || nm->type != JSON_STR)
        return false;
    s = json_get_str(nm);
    if (s == NULL)
        return false;
    return strcmp(s, name) == 0;
}

/* Find the named row in the queue status outcomes and report its verdict
 * and rc. */
static bool gtx_find_outcome(struct gtx_call *c, const char *name,
                             char *verdict, size_t verdict_cap,
                             long long *rc)
{
    const struct json_value *arr;
    size_t n, i;
    if (!gtx_ok(c))
        return false;
    arr = json_get(&c->reply.data, "outcomes");
    if (arr == NULL || arr->type != JSON_ARR)
        return false;
    n = json_size(arr);
    for (i = 0; i < n; i++) {
        const struct json_value *r = json_at(arr, i);
        const struct json_value *vv;
        const struct json_value *vr;
        if (!gtx_row_is_named(r, name))
            continue;
        vv = json_get(r, "verdict");
        vr = json_get(r, "rc");
        if (vv == NULL || vv->type != JSON_STR || json_get_str(vv) == NULL)
            return false;
        (void)snprintf(verdict, verdict_cap, "%s", json_get_str(vv));
        if (vr != NULL && vr->type == JSON_INT)
            *rc = (long long)json_get_int(vr);
        else
            *rc = -1;
        return true;
    }
    return false;
}

/* (a) An admitted row sits unclaimed while no worker drives: queued
 * once, running never, and the evidence record carries the sender
 * lines the worker will spend on. */
static int gtx_case_a(void)
{
    int failures = 0;

    TEST("(a) an admitted row sits unclaimed with no worker")
    {
        struct rcv_drive_opts o;
        char ws[1200], record[2048];
        gtx_isolate("guard-a");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_gtx_base);
        ASSERT(gtx_checkout(ws, "1111111111111111111111111111111111111111"));
        gtx_rcv_opts(&o, ws);
        ASSERT(gtx_admit(&o, "op", "guard-a", "Prove the guards."));
        ASSERT_EQ(gtx_queue_count("queued", "guard-a"), 1);
        ASSERT_EQ(gtx_queue_count("running", "guard-a"), 0);
        ASSERT(gtx_read("receive/brief/guard-a.evidence", record,
                        sizeof(record)));
        ASSERT(strstr(record, "sender=op\n") != NULL);
        ASSERT(strstr(record, "sender_binding=") != NULL);
        ASSERT(strstr(record, "grant_expiry=") != NULL);
        ASSERT(strstr(record,
                      "workspace_head=11111111111111111111111111111111"
                      "11111111") != NULL);
        /* No worker drove, so no claim, no outcome, no spend. */
        ASSERT(!gtx_exists("engine/guard-a/a1/claim.json"));
        ASSERT(!gtx_exists("engine/guard-a/a1/run.out"));
        gtx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

/* (b) A resident drive auto-claims the admitted row with zero executor
 * invocations: the refusing production seam is wired, so a processed
 * job would mean a refusal was recorded - instead nothing is
 * processed, the row is claimed, and no spend artifact exists. */
static int gtx_case_b(void)
{
    int failures = 0;

    TEST("(b) a resident drive auto-claims with zero executor invocations")
    {
        struct rcv_drive_opts ro;
        struct wkr_drive_opts o;
        char ws[1200];
        long long jobs;
        gtx_isolate("guard-b");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_gtx_base);
        ASSERT(gtx_checkout(ws, "1111111111111111111111111111111111111111"));
        gtx_rcv_opts(&ro, ws);
        ASSERT(gtx_admit(&ro, "op", "guard-b", "Claim me."));
        gtx_opts(&o, "gtx", "s-b");
        jobs = zcl_devagent_worker_drive(
            &o, zcl_devagent_worker_no_executor);
        ASSERT_EQ(jobs, 0);
        ASSERT_EQ(gtx_count_read(), 0);
        ASSERT_EQ(gtx_queue_count("running", "guard-b"), 1);
        ASSERT(gtx_has("engine/guard-b/a1/claim.json", "\"submitted\":false"));
        ASSERT(!gtx_exists("engine/guard-b/a1/run.out"));
        ASSERT(!gtx_exists("engine/guard-b/a1/receipt.json"));
        gtx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

/* (c) An empty-queue drive launches nothing: zero jobs, zero executor
 * calls, on a bounded idle wait. The wall spent here is the honest
 * idle cost of an empty queue (about idle_start + idle_limit). */
static int gtx_case_c(void)
{
    int failures = 0;

    TEST("(c) an empty-queue drive launches nothing on a bounded wait")
    {
        struct wkr_drive_opts o;
        long long t0, wall, jobs;
        gtx_isolate("guard-c");
        ASSERT(gtx_queue_verb("reap"));
        (void)remove(g_gtx_count);
        gtx_opts(&o, "gtx", "s-c");
        o.idle_start_s = 1;
        o.idle_limit_s = 2;
        t0 = (long long)platform_time_monotonic_ms();
        jobs = zcl_devagent_worker_drive(&o, gtx_fixture);
        wall = (long long)platform_time_monotonic_ms() - t0;
        ASSERT_EQ(jobs, 0);
        ASSERT_EQ(gtx_count_read(), 0);
        ASSERT(wall < 15000);
        gtx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

/* (d) A second concurrent drive refuses on worker.lock: the first
 * drive holds the whole-drive lock while idling, so the second
 * returns -1 without touching the queue. */
static int gtx_case_d(void)
{
    int failures = 0;

    TEST("(d) a second concurrent drive refuses on worker.lock")
    {
        struct wkr_drive_opts o;
        pid_t holder;
        int st = 0;
        long long second;
        gtx_isolate("guard-d");
        ASSERT(gtx_queue_verb("reap"));
        (void)fflush(NULL);
        holder = fork();
        ASSERT(holder >= 0);
        if (holder == 0) {
            struct wkr_drive_opts co;
            gtx_opts(&co, "gtx", "s-holder");
            co.deadline_s = 60;
            co.idle_start_s = 1;
            co.idle_limit_s = 60;
            co.max_jobs = 0;
            (void)zcl_devagent_worker_drive(&co, gtx_fixture);
            _exit(0);
        }
        platform_sleep_ms(2000);
        gtx_opts(&o, "gtx", "s-second");
        o.deadline_s = 5;
        o.idle_limit_s = 2;
        second = zcl_devagent_worker_drive(&o, gtx_fixture);
        (void)kill(holder, SIGTERM);
        (void)waitpid(holder, &st, 0);
        ASSERT_EQ(second, -1);
        ASSERT_EQ(gtx_count_read(), 0);
        gtx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

/* (e1) Kill after claim with submitted:false restarts to exactly-once:
 * the orphan is adopted, the submitted flag flips once, the executor
 * runs once, and the outcome completes. */
/* Under AddressSanitizer the cases that run the fixture executor cannot run.
 * The drive forks the executor and confines it with RLIMIT_DATA = mem_mb (1024
 * MB here, zcl_devagent_worker_confine). The child is a fork of the ASan test
 * process, whose private writable shadow already exceeds that (VmData is
 * terabytes, see the skip line of test_devagent_worker's ceiling case), so its
 * first malloc dies with the sanitizer's "ERROR: Failed to mmap" and the task
 * never runs (measured: test_devagent_worker_guards.c:840, 1164, 1259, 1260 in
 * the ASan run, task.txt never written). Raising mem_mb would change the cap
 * the cases exist to exercise, so only the ASan build skips them. GCC defines
 * __SANITIZE_ADDRESS__; Clang reports it through
 * __has_feature(address_sanitizer). */
#if defined(__SANITIZE_ADDRESS__)
#define GTX_UNDER_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define GTX_UNDER_ASAN 1
#endif
#endif

static bool gtx_skip_asan(const char *name)
{
#if defined(GTX_UNDER_ASAN)
    printf("worker guards: %s SKIP under AddressSanitizer (RLIMIT_DATA cage "
           "refuses the sanitizer's mappings)\n", name);
    return true;
#else
    (void)name;
    return false;
#endif
}

static int gtx_case_e1(void)
{
    int failures = 0;
    if (gtx_skip_asan("gtx_case_e1"))
        return 0;

    TEST("(e) submitted:false restarts to exactly-once")
    {
        struct wkr_drive_opts o;
        char verdict[64];
        char gid[64];
        long long rc = -1;
        struct gtx_call c;
        bool found = false;
        gtx_isolate("guard-e1");
        ASSERT(gtx_mint("op", "send", 3600, gid, sizeof(gid)));
        ASSERT(gtx_queue_post_leaf("guard-e1"));
        ASSERT(gtx_stage_evidence("guard-e1", "op", gid));
        ASSERT(gtx_queue_verb("claim"));
        ASSERT(gtx_has("engine/guard-e1/a1/claim.json", "\"submitted\":false"));
        (void)remove(g_gtx_count);
        gtx_opts(&o, "gtx", "s-e1");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, gtx_fixture), 1);
        ASSERT_EQ(gtx_count_read(), 1);
        ASSERT(gtx_has("engine/guard-e1/a1/claim.json", "\"submitted\":true"));
        ASSERT(gtx_queue_verb("reap"));
        gtx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
        (void)json_push_kv_str(&c.input, "action", "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
        found = gtx_find_outcome(&c, "guard-e1", verdict, sizeof(verdict),
                                 &rc);
        gtx_end(&c);
        ASSERT(found);
        ASSERT(zcl_devagent_closed_pass(verdict, rc));
        gtx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

/* (e2) Kill after submit with submitted:true restarts to crash-record
 * with no resubmission: zero executor calls, the named word in
 * run.out, and a no-receipt outcome. */
static int gtx_case_e2(void)
{
    int failures = 0;

    TEST("(e) submitted:true restarts to crash-record, never resubmits")
    {
        struct wkr_drive_opts o;
        gtx_isolate("guard-e2");
        ASSERT(gtx_mint("op", "send", 3600, NULL, 0));
        ASSERT(gtx_queue_post_leaf("guard-e2"));
        ASSERT(gtx_queue_verb("claim"));
        ASSERT(gtx_flip_submitted("guard-e2"));
        (void)remove(g_gtx_count);
        gtx_opts(&o, "gtx", "s-e2");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, gtx_fixture), 1);
        ASSERT_EQ(gtx_count_read(), 0);
        ASSERT(gtx_has("engine/guard-e2/a1/run.out",
                       "worker-lost-after-submit"));
        ASSERT(!gtx_exists("engine/guard-e2/a1/receipt.json"));
        ASSERT(gtx_queue_verb("reap"));
        ASSERT(gtx_has("engine/guard-e2/a1/run.out",
                       "worker-lost-after-submit"));
        gtx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

/* (f) Missing evidence fails closed: a directly posted row with no
 * per-ref record refuses before the fork. */
static int gtx_case_f0(void)
{
    int failures = 0;

    TEST("(f) missing evidence fails closed before the fork")
    {
        struct wkr_drive_opts o;
        gtx_isolate("guard-f0");
        ASSERT(gtx_mint("op", "send", 3600, NULL, 0));
        ASSERT(gtx_queue_post_leaf("guard-f0"));
        (void)remove(g_gtx_count);
        gtx_opts(&o, "gtx", "s-f0");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, gtx_fixture), 1);
        ASSERT_EQ(gtx_count_read(), 0);
        ASSERT(gtx_has("engine/guard-f0/a1/run.out", "authority-unreadable"));
        ASSERT(gtx_has("engine/guard-f0/a1/claim.json", "\"submitted\":false"));
        ASSERT(!gtx_exists("engine/guard-f0/a1/receipt.json"));
        ASSERT(!gtx_exists("engine/guard-f0/a1/executor_result.json"));
        gtx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

/* (f) A grant revoked between admission and execution refuses before
 * the fork: submitted never flips, the executor never runs. */
static int gtx_case_f1(void)
{
    int failures = 0;

    TEST("(f) a revoked grant refuses before the fork")
    {
        struct rcv_drive_opts ro;
        struct wkr_drive_opts o;
        char ws[1200], gid[64];
        gtx_isolate("guard-f1");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_gtx_base);
        ASSERT(gtx_checkout(ws, "1111111111111111111111111111111111111111"));
        ASSERT(gtx_mint("op", "send", 3600, gid, sizeof(gid)));
        {
            char body[4096];
            char binding[ZCL_FLEET_STEER_BINDING_HEX + 1];
            struct rcv_beat_stats st;
            ASSERT(zcl_fleet_steer_sender_binding(gid, "op", binding,
                                                  sizeof(binding)));
            gtx_direction_sel(body, sizeof(body), "Spend me.");
            ASSERT(gtx_deliver("op", "guard-f1", body, 1, binding));
            gtx_rcv_opts(&ro, ws);
            memset(&st, 0, sizeof(st));
            ASSERT_EQ(zcl_devagent_receive_drive(&ro, &st), 1);
            ASSERT_EQ(st.admitted, 1);
        }
        ASSERT(gtx_revoke(gid));
        (void)remove(g_gtx_count);
        gtx_opts(&o, "gtx", "s-f1");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, gtx_fixture), 1);
        ASSERT_EQ(gtx_count_read(), 0);
        ASSERT(gtx_has("engine/guard-f1/a1/run.out", "authority-ungranted"));
        ASSERT(gtx_has("engine/guard-f1/a1/claim.json", "\"submitted\":false"));
        ASSERT(!gtx_exists("engine/guard-f1/a1/receipt.json"));
        ASSERT(!gtx_exists("engine/guard-f1/a1/executor_result.json"));
        gtx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

/* (f) A grant expired between admission and execution refuses before
 * the fork. The ttl floor is a second in the future, so the test
 * spends two honest wall seconds proving expiry is re-read live. */
static int gtx_case_f2(void)
{
    int failures = 0;

    TEST("(f) an expired grant refuses before the fork")
    {
        struct rcv_drive_opts ro;
        struct wkr_drive_opts o;
        char ws[1200], gid[64];
        gtx_isolate("guard-f2");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_gtx_base);
        ASSERT(gtx_checkout(ws, "1111111111111111111111111111111111111111"));
        ASSERT(gtx_mint("op", "send", 1, gid, sizeof(gid)));
        {
            char body[4096];
            char binding[ZCL_FLEET_STEER_BINDING_HEX + 1];
            struct rcv_beat_stats st;
            ASSERT(zcl_fleet_steer_sender_binding(gid, "op", binding,
                                                  sizeof(binding)));
            gtx_direction_sel(body, sizeof(body), "Spend me slowly.");
            ASSERT(gtx_deliver("op", "guard-f2", body, 1, binding));
            gtx_rcv_opts(&ro, ws);
            memset(&st, 0, sizeof(st));
            ASSERT_EQ(zcl_devagent_receive_drive(&ro, &st), 1);
            ASSERT_EQ(st.admitted, 1);
        }
        platform_sleep_ms(2000);
        (void)remove(g_gtx_count);
        gtx_opts(&o, "gtx", "s-f2");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, gtx_fixture), 1);
        ASSERT_EQ(gtx_count_read(), 0);
        ASSERT(gtx_has("engine/guard-f2/a1/run.out", "authority-ungranted"));
        ASSERT(gtx_has("engine/guard-f2/a1/claim.json", "\"submitted\":false"));
        ASSERT(!gtx_exists("engine/guard-f2/a1/receipt.json"));
        gtx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

/* (f) A HEAD moved between admission and execution refuses before the
 * fork: the evidence recorded one commit, the checkout resolves
 * another. */
static int gtx_case_f3(void)
{
    int failures = 0;

    TEST("(f) a moved workspace HEAD refuses before the fork")
    {
        struct rcv_drive_opts ro;
        struct wkr_drive_opts o;
        char ws[1200];
        gtx_isolate("guard-f3");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_gtx_base);
        ASSERT(gtx_checkout(ws, "1111111111111111111111111111111111111111"));
        gtx_rcv_opts(&ro, ws);
        ASSERT(gtx_admit(&ro, "op", "guard-f3", "Move under me."));
        ASSERT(gtx_put(ws, ".git/refs/heads/x",
                       "2222222222222222222222222222222222222222\n"));
        (void)remove(g_gtx_count);
        gtx_opts(&o, "gtx", "s-f3");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, gtx_fixture), 1);
        ASSERT_EQ(gtx_count_read(), 0);
        ASSERT(gtx_has("engine/guard-f3/a1/run.out", "workspace-moved"));
        ASSERT(gtx_has("engine/guard-f3/a1/claim.json", "\"submitted\":false"));
        ASSERT(!gtx_exists("engine/guard-f3/a1/receipt.json"));
        gtx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

/* (f) A workspace dirtied between admission and execution refuses
 * before the fork: the tracked file no longer matches the index the
 * evidence was recorded against. */
static int gtx_case_f4(void)
{
    int failures = 0;

    TEST("(f) a dirty workspace refuses before the fork")
    {
        struct rcv_drive_opts ro;
        struct wkr_drive_opts o;
        char ws[1200];
        gtx_isolate("guard-f4");
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_gtx_base);
        ASSERT(gtx_checkout(ws, "1111111111111111111111111111111111111111"));
        gtx_rcv_opts(&ro, ws);
        ASSERT(gtx_admit(&ro, "op", "guard-f4", "Dirty me."));
        /* A longer file: the size change is visible to the index stat
         * shortcut in every second, unlike a same-size rewrite. */
        ASSERT(gtx_put(ws, "src/x.c",
                       "int zx(void) { return 1; }\n/* uncommitted */\n"));
        (void)remove(g_gtx_count);
        gtx_opts(&o, "gtx", "s-f4");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, gtx_fixture), 1);
        ASSERT_EQ(gtx_count_read(), 0);
        ASSERT(gtx_has("engine/guard-f4/a1/run.out", "workspace-dirty"));
        ASSERT(gtx_has("engine/guard-f4/a1/claim.json", "\"submitted\":false"));
        ASSERT(!gtx_exists("engine/guard-f4/a1/receipt.json"));
        gtx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

/* Replace only the admitted row's brief; retain its authority and workspace. */
static bool gtx_ledger_brief(const char *brief)
{
    char text[8192], out[8192];
    const char *start, *end;
    int n;
    if (!gtx_read("queue/queue.jsonl", text, sizeof(text))) return false;
    start = strstr(text, "\"brief\":\"");
    if (!start || !(end = strchr(start + 9, '"'))) return false;
    n = snprintf(out, sizeof(out), "%.*s%s%s", (int)(start + 9 - text), text, brief, end);
    return n > 0 && (size_t)n < sizeof(out) && gtx_put(g_gtx_state, "z23/dev/queue/queue.jsonl", out);
}

/* The parent of the checkout is outside its allowed root. Mint the fixture
 * there through the harness so test-tmp owns it, including on macOS. */
static bool gtx_brief_isolate(char outside[PATH_MAX])
{
    char cwd[PATH_MAX], checkout[PATH_MAX];
    bool ok;
    outside[0] = '\0';
    if (!getcwd(cwd, sizeof(cwd)) ||
        !zcl_devagent_checkout_root(".", checkout, sizeof(checkout)))
        return false;
    if (chdir(checkout) != 0) return false;
    ok = chdir("..") == 0;
    if (ok) ok = test_mkdtemp(outside, PATH_MAX, "gtx-brief") != NULL;
    if (ok) ok = chdir(outside) == 0;
    if (ok) gtx_isolate("brief-path");
    if (chdir(cwd) != 0) return false;
    return ok;
}

static bool gtx_brief_select(int mode, const char *cwd, const char *local,
                             char brief[PATH_MAX])
{
    size_t used = 0;
    int n = snprintf(brief, PATH_MAX, "%s/outside.txt", g_gtx_base);
    if (n < 0 || n >= PATH_MAX) return false;
    if (mode == 0) gtx_path(brief, PATH_MAX, "receive/brief/brief-path.brief");
    if (mode == 2) {
        for (const char *p = cwd; *p; p++) if (*p == '/') {
            if (used >= PATH_MAX - 3u) return false;
            memcpy(brief + used, "../", 3);
            used += 3;
        }
        n = snprintf(brief + used, PATH_MAX - used, "%s/outside.txt", g_gtx_base + 1);
        if (n < 0 || (size_t)n >= PATH_MAX - used) return false;
    }
    if (mode == 3) {
        if (symlink(brief, local) != 0) return false;
        n = snprintf(brief, PATH_MAX, "%s", local);
        if (n < 0 || n >= PATH_MAX) return false;
    }
    return true;
}

static int gtx_brief_cleanup(int mode, const char *local, const char *localdir,
                             const char *outside)
{
    int failures = 0;
    if (mode == 3 && local[0] && unlink(local) != 0) failures++;
    if (localdir[0] && test_rm_rf_recursive(localdir) != 0) failures++;
    if (outside[0] && test_rm_rf_recursive(outside) != 0) failures++;
    return failures;
}

static int gtx_case_brief(int mode)
{
    int failures = 0;
    if (gtx_skip_asan("gtx_case_brief"))
        return 0;
    bool isolated = false;
    char local[PATH_MAX] = "", localdir[PATH_MAX] = "";
    char outside[PATH_MAX] = "";
    TEST("admitted brief consumption confines resolved bytes to current roots")
    {
        struct rcv_drive_opts ro;
        struct wkr_drive_opts o;
        char ws[1200], text[8192], brief[PATH_MAX];
        char cwd[PATH_MAX];
        ASSERT(getcwd(cwd, sizeof(cwd)) != NULL);
        ASSERT(gtx_brief_isolate(outside));
        isolated = true;
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_gtx_base);
        ASSERT(gtx_checkout(ws, "1111111111111111111111111111111111111111"));
        gtx_rcv_opts(&ro, ws);
        ASSERT(gtx_admit(&ro, "op", "brief-path", "UNINTENDED TASK\nBRIEF TAIL"));
        ASSERT(gtx_read("receive/brief/brief-path.brief", text, sizeof(text)));
        ASSERT(gtx_put(g_gtx_base, "outside.txt", text));
        ASSERT(test_mkdtemp(localdir, sizeof(localdir), "gtx-brief-link") != NULL);
        ASSERT(snprintf(local, sizeof(local), "%s/brief", localdir) < (int)sizeof(local));
        ASSERT(gtx_brief_select(mode, cwd, local, brief));
        ASSERT(gtx_ledger_brief(brief));
        gtx_opts(&o, "gtx", "brief-path");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, gtx_fixture), 1);
        ASSERT_EQ(gtx_count_read(), mode == 0 ? 1 : 0);
        if (mode == 0) ASSERT(gtx_has("task.txt", text));
        else {
            ASSERT(gtx_has("engine/brief-path/a1/run.out", "brief-outside-roots"));
            ASSERT(gtx_has("engine/brief-path/a1/claim.json", "\"submitted\":false"));
            ASSERT(!gtx_exists("engine/brief-path/a1/receipt.json"));
            ASSERT(!gtx_exists("task.txt"));
        }
        PASS();
    }
_test_next:;
    if (isolated) gtx_restore();
    failures += gtx_brief_cleanup(mode, local, localdir, outside);
    return failures;
}

static int gtx_case_brief_text(int mode)
{
    static const char *const bytes[] = {
        "WHOLE \xE2\x82\xAC TEXT WITHOUT FINAL NEWLINE",
        "SAFE\0UNINTENDED TASK",
        "SAFE\xE2\x82",
    };
    static const size_t lengths[] = {
        sizeof("WHOLE \xE2\x82\xAC TEXT WITHOUT FINAL NEWLINE") - 1,
        sizeof("SAFE\0UNINTENDED TASK") - 1,
        sizeof("SAFE\xE2\x82") - 1,
    };
    int failures = 0;
    bool isolated = false;
    TEST("contained brief validates measured bytes before string composition")
    {
        struct rcv_drive_opts ro;
        struct wkr_drive_opts o;
        char ws[1200], brief[PATH_MAX], task[8192];
        const char *tail;
        gtx_isolate("brief-text");
        isolated = true;
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_gtx_base);
        ASSERT(gtx_checkout(ws, "1111111111111111111111111111111111111111"));
        gtx_rcv_opts(&ro, ws);
        ASSERT(gtx_admit(&ro, "op", "brief-text", "Original admitted text."));
        gtx_path(brief, sizeof(brief), "receive/brief/brief-text.brief");
        ASSERT(zcl_devagent_worker_write_atomic(brief, bytes[mode], lengths[mode]));
        gtx_opts(&o, "gtx", "brief-text");
        ASSERT_EQ(zcl_devagent_worker_drive(&o, gtx_fixture), 1);
        ASSERT_EQ(gtx_count_read(), mode == 0 ? 1 : 0);
        if (mode == 0) {
            ASSERT(gtx_read("task.txt", task, sizeof(task)));
            tail = strstr(task, bytes[mode]);
            ASSERT(tail != NULL);
            ASSERT_STR_EQ(tail, bytes[mode]);
        } else {
            ASSERT(gtx_has("engine/brief-text/a1/run.out", "brief-unreadable"));
            ASSERT(gtx_has("engine/brief-text/a1/claim.json", "\"submitted\":false"));
            ASSERT(!gtx_exists("engine/brief-text/a1/receipt.json"));
            ASSERT(!gtx_exists("task.txt"));
        }
        PASS();
    }
_test_next:;
    if (isolated) gtx_restore();
    return failures;
}

static int gtx_case_brief_resolution(int mode)
{
    int failures = 0;
    if (gtx_skip_asan("gtx_case_brief_resolution"))
        return 0;
    bool isolated = false;
    char link[PATH_MAX] = "";
    TEST("brief resolution follows contained links and distinguishes absence")
    {
        struct rcv_drive_opts ro;
        struct wkr_drive_opts o;
        char ws[1200], brief[PATH_MAX], text[8192];
        gtx_isolate("brief-resolve");
        isolated = true;
        (void)snprintf(ws, sizeof(ws), "%s/wt", g_gtx_base);
        ASSERT(gtx_checkout(ws, "1111111111111111111111111111111111111111"));
        gtx_rcv_opts(&ro, ws);
        ASSERT(gtx_admit(&ro, "op", "brief-resolve", "WHOLE CONTAINED LINK TEXT"));
        ASSERT(gtx_read("receive/brief/brief-resolve.brief", text, sizeof(text)));
        gtx_path(brief, sizeof(brief), "receive/brief/brief-resolve.brief");
        if (mode == 0) {
            gtx_path(link, sizeof(link), "receive/brief/contained-link");
            ASSERT(symlink(brief, link) == 0);
            ASSERT(gtx_ledger_brief(link));
        } else if (mode == 1) {
            ASSERT(unlink(brief) == 0);
        } else {
            gtx_path(brief, sizeof(brief), "receive/brief/brief-resolve.brief/child");
            ASSERT(gtx_ledger_brief(brief));
        }
        gtx_opts(&o, "gtx", "brief-resolve");
        errno = mode == 1 ? 0 : ENOENT;
        ASSERT_EQ(zcl_devagent_worker_drive(&o, gtx_fixture), 1);
        ASSERT_EQ(gtx_count_read(), mode == 2 ? 0 : 1);
        if (mode == 0) ASSERT(gtx_has("task.txt", text));
        if (mode == 1) {
            ASSERT(gtx_has("task.txt", "name=brief-resolve\n"));
            ASSERT(!gtx_has("task.txt", "WHOLE CONTAINED LINK TEXT"));
        }
        if (mode == 2) {
            ASSERT(gtx_has("engine/brief-resolve/a1/run.out", "brief-unreadable"));
            ASSERT(gtx_has("engine/brief-resolve/a1/claim.json", "\"submitted\":false"));
            ASSERT(!gtx_exists("engine/brief-resolve/a1/receipt.json"));
            ASSERT(!gtx_exists("task.txt"));
        }
        PASS();
    }
_test_next:;
    if (link[0]) (void)unlink(link);
    if (isolated) gtx_restore();
    return failures;
}

#endif /* !defined(_WIN32) */

#if defined(_WIN32)
static bool gtx_windows_brief_write(const char *path, const char *bytes,
                                    size_t length)
{
    wchar_t wide[32768];
    if (!platform_windows_wide_path(path, wide)) return false;
    FILE *file = _wfopen(wide, L"wb");
    if (!file) return false;
    bool ok = fwrite(bytes, 1, length, file) == length;
    return fclose(file) == 0 && ok;
}

static bool gtx_windows_brief_link(const char *link, const char *target)
{
    wchar_t wide_link[32768], wide_target[32768];
    return platform_windows_wide_path(link, wide_link) &&
           platform_windows_wide_path(target, wide_target) &&
           CreateSymbolicLinkW(wide_link, wide_target,
                               SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE);
}

static bool gtx_windows_brief_remove(const char *path)
{
    wchar_t wide[32768];
    if (!path[0]) return true;
    if (!platform_windows_wide_path(path, wide)) return false;
    return DeleteFileW(wide) || GetLastError() == ERROR_FILE_NOT_FOUND;
}

static int gtx_case_windows_brief_resolution(int mode)
{
    char base[PATH_MAX] = "", target[PATH_MAX] = "", brief[PATH_MAX];
    int failures = 0;
    TEST("Windows composition refuses file ancestors and preserves absent briefs") {
        struct wkr_job job = {0};
        const char *prefix = "name=missing-brief\nkind=doc\nattempt=1\nmodel=fixture\n";
        ASSERT(test_mkdtemp(base, sizeof(base), "gtx-win-resolve") != NULL);
        ASSERT(snprintf(target, sizeof(target), "%s/brief.txt", base)
               < (int)sizeof(target));
        ASSERT(gtx_windows_brief_write(target, "EXISTING BRIEF", 14));
        if (mode == 0)
            ASSERT(snprintf(brief, sizeof(brief), "%s/child", target)
                   < (int)sizeof(brief));
        else if (mode == 1)
            ASSERT(snprintf(brief, sizeof(brief), "%s/absent.brief", base)
                   < (int)sizeof(brief));
        else
            ASSERT(snprintf(brief, sizeof(brief), "%s/missing-dir/absent.brief", base)
                   < (int)sizeof(brief));
        snprintf(job.name, sizeof(job.name), "missing-brief");
        snprintf(job.kind, sizeof(job.kind), "doc");
        snprintf(job.model, sizeof(job.model), "fixture");
        job.attempt = 1;
        const char *why = zcl_devagent_worker_test_compose_task(brief, &job);
        if (mode == 0) {
            ASSERT(why != NULL);
            ASSERT_STR_EQ(why, "brief-unreadable");
            ASSERT(job.task[0] == '\0');
        } else {
            ASSERT(why == NULL);
            ASSERT_STR_EQ(job.task, prefix);
        }
        PASS();
    } _test_next:;
    if (!gtx_windows_brief_remove(target)) failures++;
    if (base[0] && test_rm_rf_recursive(base) != 0) failures++;
    return failures;
}

/* The ASCII link resolves to a UTF-8 target that narrow CRT operations
 * misinterpret on an ANSI code page. Drive the real task composition,
 * including resolution, containment, metadata, read and identity prefix. */
static int gtx_case_windows_brief(int mode)
{
    static const char *const bytes[] = {
        "WHOLE \xE2\x82\xAC TEXT WITHOUT FINAL NEWLINE",
        "SAFE\0UNINTENDED TASK",
        "SAFE\xE2\x82",
    };
    static const size_t lengths[] = {
        sizeof("WHOLE \xE2\x82\xAC TEXT WITHOUT FINAL NEWLINE") - 1,
        sizeof("SAFE\0UNINTENDED TASK") - 1,
        sizeof("SAFE\xE2\x82") - 1,
    };
    char base[PATH_MAX] = "", target[PATH_MAX] = "", link[PATH_MAX] = "";
    int failures = 0;
    TEST("Windows task composition preserves Unicode link targets or refuses text") {
        struct wkr_job job = {0};
        const char *prefix = "name=unicode-brief\nkind=doc\nattempt=1\nmodel=fixture\n";
        ASSERT(test_mkdtemp(base, sizeof(base), "gtx-win-brief") != NULL);
        ASSERT(snprintf(target, sizeof(target), "%s/\xE4\xB8\xAD.brief", base)
               < (int)sizeof(target));
        ASSERT(snprintf(link, sizeof(link), "%s/ascii-link", base)
               < (int)sizeof(link));
        ASSERT(gtx_windows_brief_write(target, bytes[mode], lengths[mode]));
        ASSERT(gtx_windows_brief_link(link, target));
        snprintf(job.name, sizeof(job.name), "unicode-brief");
        snprintf(job.kind, sizeof(job.kind), "doc");
        snprintf(job.model, sizeof(job.model), "fixture");
        job.attempt = 1;
        const char *why = zcl_devagent_worker_test_compose_task(link, &job);
        if (mode == 0) {
            ASSERT(why == NULL);
            ASSERT(strncmp(job.task, prefix, strlen(prefix)) == 0);
            ASSERT_STR_EQ(job.task + strlen(prefix), bytes[mode]);
        } else {
            ASSERT(why != NULL);
            ASSERT_STR_EQ(why, "brief-unreadable");
            ASSERT(job.task[0] == '\0');
        }
        PASS();
    } _test_next:;
    if (!gtx_windows_brief_remove(link)) failures++;
    if (!gtx_windows_brief_remove(target)) failures++;
    if (base[0] && test_rm_rf_recursive(base) != 0) failures++;
    return failures;
}
#endif

static int gtx_case_brief_reader(int mode)
{
    static const char *const bytes[] = {"", "abc", "a\0b", "\xE2\x82", "abcdefgh"};
    static const size_t lengths[] = {0, 3, 3, 2, 8};
    char base[PATH_MAX] = "", path[PATH_MAX], out[8] = "stale";
    int failures = 0;
    TEST("brief reader preserves whole text and empties refused output") {
        ASSERT(test_mkdtemp(base, sizeof(base), "gtx-reader") != NULL);
        int n = snprintf(path, sizeof(path), "%s/brief", base);
        ASSERT(n > 0 && (size_t)n < sizeof(path));
        if (mode < 5) {
#if defined(_WIN32)
            ASSERT(gtx_windows_brief_write(path, bytes[mode], lengths[mode]));
#else
            ASSERT(zcl_devagent_worker_write_atomic(path, bytes[mode], lengths[mode]));
#endif
        }
        size_t cap = mode < 2 ? lengths[mode] + 1 : sizeof(out);
        ASSERT_EQ(zcl_devagent_worker_read_file(path, out, cap), mode < 2);
        if (mode < 2) ASSERT_STR_EQ(out, bytes[mode]);
        else ASSERT(out[0] == '\0');
        PASS();
    } _test_next:;
    if (base[0] && test_rm_rf_recursive(base) != 0) failures++;
    return failures;
}

static bool gtx_impact_has_guards(const struct agent_impact_acc *impact)
{
    for (size_t i = 0; i < impact->groups_len; i++)
        if (strcmp(impact->groups[i], "devagent_worker_guards") == 0)
            return true;
    return false;
}

static bool gtx_plan_has_guards(const struct zcl_devloop_plan *plan)
{
    for (size_t i = 0; i < plan->path_groups_len; i++)
        if (strcmp(plan->path_groups[i], "devagent_worker_guards") == 0)
            return true;
    return false;
}

static int gtx_case_brief_proof_mapping(void)
{
    int failures = 0;
    TEST("production-only brief edits retain the worker guards regression") {
        static const char *const paths[] = {
            "tools/command/native_devagent_worker.c",
            "tools/command/native_devagent_worker_run.c",
            "tools/command/native_devagent.h",
        };
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
            struct agent_impact_acc impact = {0};
            struct zcl_devloop_plan plan;
            ASSERT(agent_impact_apply_shared_rules(paths[i], &impact));
            ASSERT(gtx_impact_has_guards(&impact));
            ASSERT(zcl_devloop_plan_files(&paths[i], 1, &plan));
            ASSERT(gtx_plan_has_guards(&plan));
        }
        PASS();
    } _test_next:;
    return failures;
}


int test_devagent_worker_guards(void);

/* One proof-gap clause per function: the cyclomatic-complexity gate caps
 * every function at M<=15, so the cases live in helpers above and
 * this entry only sums their failures; a failing clause does not stop later ones. */
int test_devagent_worker_guards(void)
{
    int failures = 0;
    failures += gtx_case_brief_proof_mapping();
    for (int mode = 0; mode < 6; mode++) failures += gtx_case_brief_reader(mode);

#if !defined(_WIN32)

    failures += gtx_case_a();
    failures += gtx_case_b();
    failures += gtx_case_c();
    failures += gtx_case_d();
    failures += gtx_case_e1();
    failures += gtx_case_e2();
    failures += gtx_case_f0();
    failures += gtx_case_f1();
    failures += gtx_case_f2();
    failures += gtx_case_f3();
    failures += gtx_case_f4();
    for (int mode = 0; mode < 4; mode++) failures += gtx_case_brief(mode);
    for (int mode = 0; mode < 3; mode++) failures += gtx_case_brief_text(mode);
    for (int mode = 0; mode < 3; mode++) failures += gtx_case_brief_resolution(mode);

#else
    for (int mode = 0; mode < 3; mode++) failures += gtx_case_windows_brief(mode);
    for (int mode = 0; mode < 3; mode++)
        failures += gtx_case_windows_brief_resolution(mode);
#endif /* !defined(_WIN32) */

    return failures;
}
