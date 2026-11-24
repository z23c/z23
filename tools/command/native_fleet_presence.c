/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: fleet.steer.presence - a live session posts its OWN presence.v1
 *          row so `fleet steer brief` can count it as a fresh session.
 *
 * The brief (native_fleet_steer.c, "brief: agent sessions") knows a session
 * only from a `note` row under ref presence-<ROLE> whose body is the strict
 * presence.v1 line, live while that row's mail ts is within 900 s. Nothing
 * wrote those rows. This leaf is the writer: it states only facts this
 * process can observe (host, pid, clock) plus what the caller passes, builds
 * the exact line, and hands it to the existing dev.agent.mail post leaf in
 * process. It owns no ledger and no second mail writer. Truthfulness:
 *   - it posts only when a session runs it, never on a timer of its own;
 *   - the row is dated by the mail leaf at post time and so expires by
 *     itself 900 s later; a session that ends simply stops refreshing, and
 *     `--phase=completed` ends it at once;
 *   - a stated pid must be a live process on this host, else the post is
 *     refused rather than faked;
 *   - credential-shaped values and binary_sha256 are never written.
 * Shapes mirror the reader's parser; the round-trip test pins the pair. */

#include "command/native_command.h"

#include "command/native_dev_agents.h"
#include "command/native_devagent.h"
#include "command/native_fleet.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <signal.h>
#include <unistd.h>
#else
#include <process.h>
#endif

#define FPR_LOG "fleet.steer.presence"
#define FPR_ROLE_MAX 32u
#define FPR_REPEAT_S 300
#define FPR_WINDOW_S 900
#define FPR_SECRET_RUN 24u

static const char *const fpr_phases[] = {"active", "running", "build", "test",
                                         "blocked", "completed"};

static void fpr_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message, const char *evidence)
{
    LOG_ERROR(FPR_LOG, "%s: %s (%s)", code, message, evidence);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "execute", false,
                           false, message, evidence);
}

static bool fpr_has_word(const char *s)
{
    static const char *const words[] = {
        "bearer", "password", "passwd", "secret", "apikey", "api_key",
        "api-key", "authorization", "private_key", "privkey", "sk-", "xai-",
        "gsk_", "ghp_", "gho_", "ghs_", "github_pat_", "glpat-", "akia"};
    char low[160];
    size_t i;
    for (i = 0; s[i] && i + 1 < sizeof(low); i++)
        low[i] = (char)tolower((unsigned char)s[i]);
    low[i] = '\0';
    for (i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
        if (strstr(low, words[i]))
            return true;
    }
    return false;
}

static bool fpr_has_run(const char *s)
{
    size_t i = 0, run;
    while (s[i]) {
        for (run = 0; isalnum((unsigned char)s[i + run]); run++)
            ;
        if (run >= FPR_SECRET_RUN)
            return true;
        i += run ? run : 1u;
    }
    return false;
}

/* One value: nonempty, within max, an allowed alphabet, no credential shape. */
static bool fpr_value_ok(const char *v, size_t max, bool text)
{
    size_t i, n = v ? strlen(v) : 0u;
    if (n == 0 || n > max)
        return false;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)v[i];
        if (!isalnum(c) && !strchr("._:@+-", (int)c) &&
            !(text && strchr(" /,#", (int)c)))
            return false;
    }
    return !fpr_has_word(v) && !fpr_has_run(v);
}

static bool fpr_ts_ok(const char *ts)
{
    static const char pat[] = "dddd-dd-ddTdd:dd:ddZ";
    size_t i;
    if (!ts || strlen(ts) != sizeof(pat) - 1u)
        return false;
    for (i = 0; pat[i]; i++) {
        if (pat[i] == 'd' ? !(ts[i] >= '0' && ts[i] <= '9') : ts[i] != pat[i])
            return false;
    }
    return true;
}

static void fpr_now_ts(char *out, size_t cap)
{
    struct tm tm_utc;
    time_t t = platform_time_wall_time_t();
    if (!platform_time_utc_tm(t, &tm_utc) ||
        strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0)
        out[0] = '\0';
}

static bool fpr_phase_ok(const char *p)
{
    size_t i;
    for (i = 0; p && i < sizeof(fpr_phases) / sizeof(fpr_phases[0]); i++) {
        if (strcmp(p, fpr_phases[i]) == 0)
            return true;
    }
    return false;
}

/* A stated pid names a live process here, or the post is a false claim. */
static bool fpr_pid_live(long long pid)
{
#if defined(_WIN32)
    return pid > 0;
#else
    if (pid <= 0 || pid > 4194304)
        return false;
    return kill((pid_t)pid, 0) == 0 || errno == EPERM;
#endif
}

struct fpr_in {
    const char *role, *task, *phase, *session, *started, *source;
    long long pid;
};

static const char *fpr_str(const struct zcl_command_request *req,
                           const char *key)
{
    const struct json_value *v = req->input ? json_get(req->input, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

/* pid arrives as a string from the CLI, or an integer from a JSON caller. */
static bool fpr_pid_in(const struct zcl_command_request *req, long long *pid)
{
    const struct json_value *v = req->input ? json_get(req->input, "pid") : NULL;
    const char *s;
    char *end = NULL;
    if (!v) {
        *pid = (long long)getpid();
        return true;
    }
    if (v->type == JSON_INT) {
        *pid = (long long)json_get_int(v);
        return true;
    }
    s = v->type == JSON_STR ? json_get_str(v) : NULL;
    if (!s || !s[0])
        return false;
    errno = 0;
    *pid = strtoll(s, &end, 10);
    return errno == 0 && end && *end == '\0';
}

static bool fpr_read(const struct zcl_command_request *req,
                     struct zcl_command_reply *reply, struct fpr_in *in)
{
    memset(in, 0, sizeof(*in));
    in->role = fpr_str(req, "role");
    in->task = fpr_str(req, "task");
    in->phase = fpr_str(req, "phase");
    in->session = fpr_str(req, "session");
    in->started = fpr_str(req, "started");
    in->source = fpr_str(req, "source");
    if (!in->role || !fpr_value_ok(in->role, FPR_ROLE_MAX, false) ||
        strpbrk(in->role, ":@+")) {
        fpr_fail(reply, "PRESENCE_BAD_ROLE",
                 "role must be 1..32 characters of letters, digits, '.', '_' or '-' (for example A, B or claude-main), and no credential-shaped text",
                 "role");
        return false;
    }
    if (!fpr_phase_ok(in->phase)) {
        fpr_fail(reply, "PRESENCE_BAD_PHASE",
                 "phase must be one of active, running, build, test, blocked or completed; the first four count as active work, completed ends the session",
                 "phase");
        return false;
    }
    if (!fpr_pid_in(req, &in->pid) || !fpr_pid_live(in->pid)) {
        fpr_fail(reply, "PRESENCE_PID_NOT_LIVE",
                 "pid must name a running process on this host; presence is posted only by a live session, so a dead or foreign pid is refused",
                 "pid");
        return false;
    }
    return true;
}

/* Validate the optional/free fields against the reader's shapes. */
static bool fpr_check(struct zcl_command_reply *reply, const struct fpr_in *in,
                      const char *host)
{
    const char *bad = NULL;
    if (!fpr_value_ok(host, 64, false))
        bad = "host";
    else if (!in->task || !fpr_value_ok(in->task, 96, true))
        bad = "task";
    else if (in->session && !fpr_value_ok(in->session, 64, false))
        bad = "session";
    else if (in->started && !fpr_ts_ok(in->started))
        bad = "started";
    else if (in->source && !fpr_value_ok(in->source, 96, true))
        bad = "source";
    if (!bad)
        return true;
    fpr_fail(reply, "PRESENCE_BAD_FIELD",
             "a presence field is missing, too long, outside the allowed characters (letters, digits, . _ : @ + -, plus spaces / , # in task and source), timestamp-shaped wrongly (started is YYYY-MM-DDTHH:MM:SSZ) or credential-shaped; nothing was posted",
             bad);
    return false;
}

static bool fpr_body(char *out, size_t cap, const struct fpr_in *in,
                     const char *host, const char *now)
{
    char sess[72];
    int n;
    if (in->session)
        (void)snprintf(sess, sizeof(sess), "%s", in->session);
    else
        (void)snprintf(sess, sizeof(sess), "s%lld", in->pid);
    n = snprintf(out, cap,
                 "presence.v1; host=%s; session=%s; pid=%lld; started=%s; "
                 "role=%s; observed=%s; task=%s; phase=%s; source=%s",
                 host, sess, in->pid, in->started ? in->started : now,
                 in->role, now, in->task, in->phase,
                 in->source ? in->source : "claude");
    return n > 0 && (size_t)n < cap;
}

/* Post through the existing dev.agent.mail leaf, in process. */
static bool fpr_post(const struct zcl_command_request *req,
                     struct zcl_command_reply *reply, const char *ref,
                     const char *body, long long *seq)
{
    struct json_value input;
    struct zcl_command_request sub;
    struct zcl_command_reply sr;
    const struct json_value *sv;
    bool ok;
    json_init(&input);
    json_set_object(&input);
    memset(&sub, 0, sizeof(sub));
    sub.input = &input;
    sub.context = req->context;
    sub.spec = zcl_command_registry_find(zcl_command_catalog(), "dev.agent.mail", NULL);
    sub.view = "normal";
    zcl_command_reply_init(&sr, "zcl.agent_mail.v1");
    ok = sub.spec &&
         json_push_kv_str(&input, "action", "post") &&
         json_push_kv_str(&input, "to", "*") &&
         json_push_kv_str(&input, "kind", "note") &&
         json_push_kv_str(&input, "ref", ref) &&
         json_push_kv_str(&input, "body", body);
    if (ok)
        zcl_native_handle_dev_agent_mail(&sub, &sr);
    ok = ok && sr.status == ZCL_COMMAND_STATUS_PASSED;
    if (!ok)
        fpr_fail(reply, "PRESENCE_POST_REFUSED",
                 sr.error.message[0] ? sr.error.message
                                     : "the mail leaf did not accept the presence row; nothing was posted",
                 sr.error.code[0] ? sr.error.code : "dev.agent.mail");
    sv = ok ? json_get(&sr.data, "seq") : NULL;
    *seq = sv && sv->type == JSON_INT ? (long long)json_get_int(sv) : -1;
    zcl_command_reply_free(&sr);
    json_free(&input);
    return ok;
}

void zcl_native_handle_fleet_steer_presence(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct fpr_in in;
    char host[96], now[32], ref[64], body[512];
    long long seq = -1;
    zcl_agents_host_name(host, sizeof(host));
    fpr_now_ts(now, sizeof(now));
    if (!fpr_read(request, reply, &in) || !fpr_check(reply, &in, host))
        return;
    if (!now[0] || !fpr_body(body, sizeof(body), &in, host, now)) {
        fpr_fail(reply, "PRESENCE_BAD_FIELD",
                 "the presence line could not be built within its size bound; shorten task or source",
                 "body");
        return;
    }
    (void)snprintf(ref, sizeof(ref), "presence-%s", in.role);
    if (!fpr_post(request, reply, ref, body, &seq))
        return;
    (void)json_push_kv_str(&reply->data, "ref", ref);
    (void)json_push_kv_str(&reply->data, "body", body);
    (void)json_push_kv_int(&reply->data, "seq", seq);
    (void)json_push_kv_int(&reply->data, "live_window_s", FPR_WINDOW_S);
    (void)json_push_kv_int(&reply->data, "repeat_every_s", FPR_REPEAT_S);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}
