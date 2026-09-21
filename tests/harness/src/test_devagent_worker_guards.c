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
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"

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
static int gtx_case_e1(void)
{
    int failures = 0;

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

#endif /* !defined(_WIN32) */

int test_devagent_worker_guards(void);

/* One proof-gap clause per function: the cyclomatic-complexity gate caps
 * every function at M<=15, so the eleven cases live in helpers above and
 * this entry only sums their failures. A clause that fails still runs the
 * later clauses, unlike the old single-body goto chain. */
int test_devagent_worker_guards(void)
{
    int failures = 0;

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

#endif /* !defined(_WIN32) */

    return failures;
}

