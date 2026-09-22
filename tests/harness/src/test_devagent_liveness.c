/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE for fleet liveness: an owner, trust, or proof wait is a
 * durable WAITING_EXTERNAL worker-task, and that wait does not stop a
 * different runnable task from being claimed and started. The same
 * fixture also drives the shipped steer send and brief handlers:
 * a retry appends nothing, an aged directive is an incident, and
 * runnable debt with no resident worker is not reported idle.
 *
 * Isolated XDG_STATE_HOME. No model, network, or live datadir.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_devagent.h"
#include "command/native_fleet.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/private_directory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

static char g_liv_state[1024];
static char g_liv_saved_xdg[4096];
static bool g_liv_had_xdg;
static char g_liv_seen[1024];
static char g_liv_binding[ZCL_FLEET_STEER_BINDING_HEX + 1];
static long long g_liv_expiry;
static bool g_liv_grant_ok;

static void liv_isolate(const char *tag)
{
    char base[512];
    test_make_tmpdir(base, sizeof(base), "devagent_liveness", tag);
    (void)snprintf(g_liv_state, sizeof(g_liv_state), "%s/state", base);
    (void)platform_private_directory_ensure(g_liv_state);
    (void)snprintf(g_liv_seen, sizeof(g_liv_seen), "%s/seen", base);
    (void)remove(g_liv_seen);
    g_liv_had_xdg = getenv("XDG_STATE_HOME") != NULL;
    if (g_liv_had_xdg)
        (void)snprintf(g_liv_saved_xdg, sizeof(g_liv_saved_xdg), "%s",
                       getenv("XDG_STATE_HOME"));
    setenv("XDG_STATE_HOME", g_liv_state, 1);
    g_liv_grant_ok = false;
    g_liv_binding[0] = '\0';
}

static void liv_restore(void)
{
    if (g_liv_had_xdg)
        setenv("XDG_STATE_HOME", g_liv_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
}

struct liv_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void liv_begin(struct liv_call *c, const char *path, const char *schema)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec = zcl_command_registry_find(zcl_command_catalog(), path,
                                                NULL);
    c->request.view = "normal";
    zcl_command_reply_init(&c->reply, schema);
}

static void liv_end(struct liv_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool liv_run(struct liv_call *c,
                    void (*fn)(const struct zcl_command_request *,
                               struct zcl_command_reply *))
{
    char why[256];
    if (!c->request.spec ||
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    fn(&c->request, &c->reply);
    return true;
}

static bool liv_ok(const struct liv_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static bool liv_post(const char *name, const char *after)
{
    struct liv_call c;
    bool ok;
    liv_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", "post");
    (void)json_push_kv_str(&c.input, "kind", "leaf");
    (void)json_push_kv_str(&c.input, "name", name);
    if (after)
        (void)json_push_kv_str(&c.input, "depends_on", after);
    ok = liv_run(&c, zcl_native_handle_dev_agent_queue) && liv_ok(&c);
    liv_end(&c);
    return ok;
}

static bool liv_claim(char *name, size_t cap)
{
    struct liv_call c;
    const struct json_value *v;
    bool ok;
    name[0] = '\0';
    liv_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", "claim");
    (void)json_push_kv_str(&c.input, "worker", "worker-c");
    (void)json_push_kv_str(&c.input, "session", "s-c");
    ok = liv_run(&c, zcl_native_handle_dev_agent_queue) && liv_ok(&c);
    if (ok) {
        v = json_get(&c.reply.data, "name");
        if (v && v->type == JSON_STR && json_get_str(v))
            (void)snprintf(name, cap, "%s", json_get_str(v));
        v = json_get(&c.reply.data, "state");
        if (!v || v->type != JSON_STR ||
            strcmp(json_get_str(v), "running") != 0)
            ok = name[0] == '\0';
    }
    liv_end(&c);
    return ok;
}

static bool liv_file_has(const char *path, const char *needle)
{
    FILE *f;
    char buf[4096];
    size_t n;
    f = fopen(path, "rb");
    if (!f)
        return false;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    (void)fclose(f);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

static void liv_mkdir_p(char *path)
{
    char *p = path;
    if (*p == '/')
        p++;
    for (; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            (void)mkdir(path, 0700);
            *p = '/';
        }
    }
    (void)mkdir(path, 0700);
}

static void liv_authority(const char *name)
{
    struct liv_call c;
    const struct json_value *v;
    const char *id;
    char dir[1200], path[1400], text[256];
    FILE *f;
    int w;
    if (!g_liv_grant_ok) {
        liv_begin(&c, "fleet.steer.grant", "zcl.fleet_steer_grant.v1");
        (void)json_push_kv_str(&c.input, "action", "mint");
        (void)json_push_kv_str(&c.input, "scopes", "send");
        (void)json_push_kv_str(&c.input, "label", "liv");
        (void)json_push_kv_int(&c.input, "ttl_seconds", 3600);
        zcl_native_handle_fleet_steer_grant(&c.request, &c.reply);
        g_liv_grant_ok = liv_ok(&c);
        v = json_get(&c.reply.data, "id");
        id = (v && v->type == JSON_STR) ? json_get_str(v) : "";
        if (g_liv_grant_ok)
            g_liv_grant_ok =
                zcl_fleet_steer_sender_binding(id, "liv", g_liv_binding,
                                               sizeof(g_liv_binding)) &&
                zcl_fleet_steer_grant_expiry("liv", "send", &g_liv_expiry);
        liv_end(&c);
    }
    if (!g_liv_grant_ok)
        return;
    (void)snprintf(dir, sizeof(dir), "%s/z23/dev/receive/brief", g_liv_state);
    liv_mkdir_p(dir);
    if (snprintf(path, sizeof(path), "%s/%s.evidence", dir, name) >=
        (int)sizeof(path))
        return;
    w = snprintf(text, sizeof(text),
                 "sender=liv\nsender_binding=%s\ngrant_expiry=%lld\n",
                 g_liv_binding, g_liv_expiry);
    if (w <= 0 || (size_t)w >= sizeof(text))
        return;
    f = fopen(path, "wb");
    if (!f)
        return;
    (void)fwrite(text, 1, (size_t)w, f);
    (void)fclose(f);
}

#if !defined(_WIN32)
static bool liv_executor(const struct wkr_job *job, struct wkr_result *res)
{
    FILE *f;
    char path[4096 + 32];
    f = fopen(g_liv_seen, "ab");
    if (f) {
        (void)fprintf(f, "%s\n", job->name);
        (void)fclose(f);
    }
    if (snprintf(path, sizeof(path), "%s/cand.diff", job->rundir) <
        (int)sizeof(path)) {
        f = fopen(path, "wb");
        if (f) {
            (void)fwrite("diff --liveness\n", 1, 16, f);
            (void)fclose(f);
        }
    }
    memset(res, 0, sizeof(*res));
    (void)snprintf(res->terminal, sizeof(res->terminal), "pass");
    res->rc = 0;
    (void)snprintf(res->candidate, sizeof(res->candidate), "cand.diff");
    (void)snprintf(res->evidence, sizeof(res->evidence), "fixture started");
    res->tokens_used = 1;
    res->wall_ms = 1;
    (void)snprintf(res->provider, sizeof(res->provider), "fixture");
    res->turns = 1;
    (void)snprintf(res->command, sizeof(res->command), "fixture-run");
    (void)snprintf(res->source, sizeof(res->source), "fixture/src.c");
    (void)snprintf(res->diff, sizeof(res->diff), "cand.diff");
    return true;
}
#endif

static bool liv_mint(char *id, size_t cap)
{
    struct liv_call c;
    const struct json_value *v;
    const char *got;
    bool ok;
    liv_begin(&c, "fleet.steer.grant", "zcl.fleet_steer_grant.v1");
    (void)json_push_kv_str(&c.input, "action", "mint");
    (void)json_push_kv_str(&c.input, "scopes", "brief,send,evidence");
    (void)json_push_kv_str(&c.input, "label", "liv-sender");
    (void)json_push_kv_int(&c.input, "ttl_seconds", 3600);
    ok = liv_run(&c, zcl_native_handle_fleet_steer_grant) && liv_ok(&c);
    v = json_get(&c.reply.data, "id");
    got = (v && v->type == JSON_STR) ? json_get_str(v) : "";
    if (ok && got[0] && strlen(got) < cap)
        (void)snprintf(id, cap, "%s", got);
    else
        ok = false;
    liv_end(&c);
    return ok;
}

static bool liv_send(const char *grant, const char *body, const char *ref,
                     const char *key, bool *duplicate, long long *seq)
{
    struct liv_call c;
    struct json_value items, item;
    const struct json_value *arr, *row, *v;
    bool ok;
    *duplicate = false;
    *seq = -1;
    json_init(&items);
    json_set_array(&items);
    json_init(&item);
    json_set_object(&item);
    (void)json_push_kv_str(&item, "to", "field-agent");
    (void)json_push_kv_str(&item, "body", body);
    (void)json_push_kv_str(&item, "ref", ref);
    (void)json_push_kv_str(&item, "idempotency_key", key);
    (void)json_push_back(&items, &item);
    json_free(&item);
    liv_begin(&c, "fleet.steer.send", "zcl.fleet_steer_send.v1");
    (void)json_push_kv_str(&c.input, "grant", grant);
    (void)json_push_kv_str(&c.input, "from", "liv-sender");
    (void)json_push_kv(&c.input, "items", &items);
    ok = liv_run(&c, zcl_native_handle_fleet_steer_send) && liv_ok(&c);
    json_free(&items);
    arr = json_get(&c.reply.data, "items");
    row = (arr && arr->type == JSON_ARR) ? json_at(arr, 0) : NULL;
    v = row ? json_get(row, "seq") : NULL;
    if (v && v->type == JSON_INT)
        *seq = json_get_int(v);
    v = row ? json_get(row, "duplicate") : NULL;
    if (v && v->type == JSON_BOOL)
        *duplicate = json_get_bool(v);
    liv_end(&c);
    return ok;
}

static long long liv_mail_count(void)
{
    struct liv_call c;
    const struct json_value *v;
    long long n = -1;
    liv_begin(&c, "dev.agent.mail", "zcl.agent_mail.v1");
    (void)json_push_kv_str(&c.input, "action", "pull");
    (void)json_push_kv_int(&c.input, "since", 0);
    if (liv_run(&c, zcl_native_handle_dev_agent_mail) && liv_ok(&c)) {
        v = json_get(&c.reply.data, "count");
        if (v && v->type == JSON_INT)
            n = json_get_int(v);
    }
    liv_end(&c);
    return n;
}

static bool liv_blocker_has(const struct json_value *data, const char *needle)
{
    const struct json_value *b = json_get(data, "blockers");
    size_t i, n;
    if (!b || b->type != JSON_ARR)
        return false;
    n = json_size(b);
    for (i = 0; i < n; i++) {
        const struct json_value *v = json_at(b, i);
        if (v && v->type == JSON_STR && json_get_str(v) &&
            strstr(json_get_str(v), needle))
            return true;
    }
    return false;
}

static const char *liv_worker_state(const struct json_value *data,
                                    const char *name)
{
    const struct json_value *arr = json_get(data, "workers");
    size_t i, n;
    if (!arr || arr->type != JSON_ARR)
        return "";
    n = json_size(arr);
    for (i = 0; i < n; i++) {
        const struct json_value *w = json_at(arr, i);
        const struct json_value *nm = w ? json_get(w, "name") : NULL;
        const struct json_value *st = w ? json_get(w, "state") : NULL;
        if (nm && nm->type == JSON_STR && strcmp(json_get_str(nm), name) == 0)
            return (st && st->type == JSON_STR) ? json_get_str(st) : "";
    }
    return "";
}

static bool liv_state_file(const char *rel, const char *file, const char *text)
{
    char dir[1200], path[1400];
    FILE *f;
    size_t base, i;
    int n = snprintf(dir, sizeof(dir), "%s/z23/dev/%s/", g_liv_state, rel);
    if (n <= 0 || (size_t)n >= sizeof(dir))
        return false;
    base = strlen(g_liv_state) + 1;
    for (i = base; dir[i]; i++) {
        if (dir[i] != '/')
            continue;
        dir[i] = '\0';
        if (!platform_private_directory_ensure(dir))
            return false;
        dir[i] = '/';
    }
    dir[n - 1] = '\0';
    n = snprintf(path, sizeof(path), "%s/%s", dir, file);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    f = fopen(path, "ab");
    if (!f)
        return false;
    if (fputs(text, f) < 0) {
        (void)fclose(f);
        return false;
    }
    return fclose(f) == 0;
}

static int liv_case_claim(void)
{
    int failures = 0;
    TEST("liveness: owner wait is WAITING_EXTERNAL and claim takes the other row") {
        char claimed[80], again[80];
        char qpath[1200], packet[1200];
        liv_isolate("claim");
        ASSERT(liv_post("task-a", "owner"));
        ASSERT(liv_post("task-t", "trust"));
        ASSERT(liv_post("task-p", "proof"));
        ASSERT(liv_post("task-c", NULL));
        ASSERT(liv_claim(claimed, sizeof(claimed)));
        ASSERT_STR_EQ(claimed, "task-c");
        (void)snprintf(qpath, sizeof(qpath), "%s/z23/dev/queue/queue.jsonl",
                       g_liv_state);
        (void)snprintf(packet, sizeof(packet),
                       "%s/z23/dev/queue/wait/task-a.json", g_liv_state);
        ASSERT(liv_file_has(qpath, "WAITING_EXTERNAL"));
        ASSERT(liv_file_has(packet, "\"wait\":\"owner\""));
        (void)snprintf(packet, sizeof(packet),
                       "%s/z23/dev/queue/wait/task-t.json", g_liv_state);
        ASSERT(liv_file_has(packet, "\"wait\":\"trust\""));
        (void)snprintf(packet, sizeof(packet),
                       "%s/z23/dev/queue/wait/task-p.json", g_liv_state);
        ASSERT(liv_file_has(packet, "\"wait\":\"proof\""));
        /* The parked row is not claimed again, and task-c is already running. */
        ASSERT(liv_claim(again, sizeof(again)));
        ASSERT_STR_EQ(again, "");
        liv_restore();
        PASS();
    }
_test_next:;
    liv_restore();
    return failures;
}

#if !defined(_WIN32)
static int liv_case_drive(void)
{
    int failures = 0;
    TEST("liveness: C starts while A waits on owner and B is not running") {
        struct wkr_drive_opts o;
        char qpath[1200];
        long long jobs;
        liv_isolate("drive");
        ASSERT(liv_post("task-a", "owner"));
        ASSERT(liv_post("task-c", NULL));
        liv_authority("task-c");
        ASSERT(g_liv_grant_ok);
        memset(&o, 0, sizeof(o));
        (void)snprintf(o.worker, sizeof(o.worker), "worker-c");
        (void)snprintf(o.session, sizeof(o.session), "s-c");
        o.deadline_s = 30;
        o.idle_start_s = 1;
        o.idle_limit_s = 2;
        o.max_jobs = 1;
        o.time_cap_s = 30;
        o.cpu_s = 30;
        o.mem_mb = 256;
        o.token_cap = 1000;
        o.timed_idle_only = true;
        jobs = zcl_devagent_worker_drive(&o, liv_executor);
        ASSERT_EQ(jobs, 1);
        ASSERT(liv_file_has(g_liv_seen, "task-c"));
        ASSERT(!liv_file_has(g_liv_seen, "task-a"));
        (void)snprintf(qpath, sizeof(qpath), "%s/z23/dev/queue/queue.jsonl",
                       g_liv_state);
        ASSERT(liv_file_has(qpath, "WAITING_EXTERNAL"));
        /* Worker B was never started: no claim directory under its name. */
        {
            char bclaim[1200];
            (void)snprintf(bclaim, sizeof(bclaim),
                           "%s/z23/dev/engine/task-b/a1/claim.json",
                           g_liv_state);
            ASSERT(access(bclaim, F_OK) != 0);
        }
        liv_restore();
        PASS();
    }
_test_next:;
    liv_restore();
    return failures;
}
#endif

static int liv_case_steer(void)
{
    int failures = 0;

    TEST("liveness: a steer retry does not append a second delivery") {
        char gid[64];
        bool dup = false;
        long long seq1 = -1, seq2 = -1, before;
        liv_isolate("retry");
        ASSERT(liv_mint(gid, sizeof(gid)));
        ASSERT(liv_send(gid, "check the pump", "pump-check", "key-pump",
                        &dup, &seq1));
        ASSERT(!dup);
        ASSERT(seq1 > 0);
        before = liv_mail_count();
        ASSERT(before == 1);
        ASSERT(liv_send(gid, "check the pump", "pump-check", "key-pump",
                        &dup, &seq2));
        ASSERT(dup);
        ASSERT_EQ(seq1, seq2);
        ASSERT_EQ(liv_mail_count(), before);
        liv_restore();
        PASS();
    }

    TEST("liveness: an aged directive is a control-plane incident") {
        struct liv_call b;
        liv_isolate("stale");
        ASSERT(liv_state_file(
            "mail", "inbox.self.jsonl",
            "{\"seq\":7,\"ts\":\"2026-01-01T00:00:00Z\",\"from\":\"liv-sender\","
            "\"to\":\"silent-box\",\"kind\":\"directive\",\"body\":\"do the thing\","
            "\"ref\":\"stale-ref\"}\n"));
        ASSERT(liv_state_file(
            "steer", "sent.jsonl",
            "{\"key\":\"k-stale\",\"seq\":7,\"to\":\"silent-box\","
            "\"ref\":\"stale-ref\"}\n"));
        liv_begin(&b, "fleet.steer.brief", "zcl.fleet_steer_brief.v1");
        (void)json_push_kv_int(&b.input, "since", 0);
        ASSERT(liv_run(&b, zcl_native_handle_fleet_steer_brief));
        ASSERT(liv_ok(&b));
        ASSERT(liv_blocker_has(&b.reply.data, "stale-ref"));
        ASSERT(liv_blocker_has(&b.reply.data, "no receiver evidence after"));
        liv_end(&b);
        liv_restore();
        PASS();
    }

    TEST("liveness: runnable debt and zero workers is not idle") {
        struct liv_call b;
        const char *state;
        liv_isolate("debt");
        ASSERT(liv_post("task-ready", NULL));
        liv_begin(&b, "fleet.steer.brief", "zcl.fleet_steer_brief.v1");
        (void)json_push_kv_int(&b.input, "since", 0);
        ASSERT(liv_run(&b, zcl_native_handle_fleet_steer_brief));
        ASSERT(liv_ok(&b));
        state = liv_worker_state(&b.reply.data, "local");
        ASSERT_STR_EQ(state, "blocked");
        ASSERT(strcmp(state, "idle") != 0);
        liv_end(&b);
        liv_restore();
        PASS();
    }

_test_next:;
    liv_restore();
    return failures;
}

int test_devagent_liveness(void);
int test_devagent_liveness(void)
{
    int failures = 0;
    failures += liv_case_claim();
#if !defined(_WIN32)
    failures += liv_case_drive();
#endif
    failures += liv_case_steer();
    return failures;
}
