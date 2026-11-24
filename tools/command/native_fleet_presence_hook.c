/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: fleet.steer.presence --hook=start|beat|end - the Claude Code
 *          session hook, in C23, plus the per-role state record.
 *
 * Roles come from a small fixed pool per agent kind (<kind>-1 .. <kind>-8,
 * kind defaults to claude), never one per session: the fleet brief tracks
 * a bounded, never-evicted table of roles, so a role per session would fill
 * it for good. A session claims the role it already owns, else the
 * lowest-numbered role whose last post is completed or older than the 900 s
 * live window, else (pool full) shares the role with the oldest post. Claims
 * live in <state root>/presence/role-<role>; a lost claim race heals at the
 * next beat. The hook JSON on stdin supplies session_id; --session skips it. */

#include "command/native_fleet_presence.h"

#include "json/json.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(_WIN32)
#include <io.h>
#include <process.h>
#define fph_isatty _isatty
#else
#include <unistd.h>
#define fph_isatty isatty
#endif

#define FPH_POOL 8
#define FPH_SID_MAX 40u

static bool fph_path(const char *role, char *out, size_t cap, bool ensure)
{
    char root[900], dir[960];
    if (!platform_state_root(root, sizeof(root)) ||
        snprintf(dir, sizeof(dir), "%s/presence", root) >= (int)sizeof(dir))
        return false;
    if (ensure && !platform_private_directory_ensure(dir))
        return false;
    return snprintf(out, cap, "%s/role-%s", dir, role) < (int)cap;
}
}

static void fph_field(struct zcl_presence_rec *r, const char *line)
{
    const char *eq = strchr(line, '=');
    size_t n, cap = 0;
    char *dst = NULL;
    if (!eq)
        return;
    n = (size_t)(eq - line);
    if (n == 4 && !strncmp(line, "beat", 4)) {
        r->beat = strtoll(eq + 1, NULL, 10);
        return;
    }
    if (n == 5 && !strncmp(line, "owner", 5)) {
        dst = r->owner;
        cap = sizeof(r->owner);
    } else if (n == 7 && !strncmp(line, "started", 7)) {
        dst = r->started;
        cap = sizeof(r->started);
    } else if (n == 5 && !strncmp(line, "phase", 5)) {
        dst = r->phase;
        cap = sizeof(r->phase);
    }
    if (dst) {
        (void)snprintf(dst, cap, "%s", eq + 1);
        dst[strcspn(dst, "\r\n")] = '\0';
    }
}

bool zcl_presence_rec_load(const char *role, struct zcl_presence_rec *rec)
{
    char path[1024], line[160];
    FILE *f;
    memset(rec, 0, sizeof(*rec));
    if (!fph_path(role, path, sizeof(path), false))
        return false;
    f = fopen(path, "r");
    if (!f)
        return false;
    while (fgets(line, sizeof(line), f))
        fph_field(rec, line);
    (void)fclose(f);
    return rec->beat > 0;
}

bool zcl_presence_rec_store(const char *role,
                            const struct zcl_presence_rec *rec)
{
    char path[1024], tmp[1100];
    FILE *f;
    bool ok;
    if (!fph_path(role, path, sizeof(path), true) ||
        snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
        return false;
    f = fopen(tmp, "w");
    if (!f)
        return false;
    ok = fprintf(f, "owner=%s\nstarted=%s\nphase=%s\nbeat=%lld\n", rec->owner,
                 rec->started, rec->phase, rec->beat) > 0;
    ok = (fclose(f) == 0) && ok;
#if defined(_WIN32)
    (void)remove(path);
#endif
    return ok && rename(tmp, path) == 0;
}

/* session_id from the hook JSON on stdin: "session_id" : "<id>". */
static bool fph_stdin_sid(char *out, size_t cap)
{
    char buf[16384];
    size_t n, i = 0;
    const char *p;
    if (fph_isatty(0))
        return false;
    n = fread(buf, 1, sizeof(buf) - 1u, stdin);
    buf[n] = '\0';
    p = strstr(buf, "\"session_id\"");
    if (!p)
        return false;
    p += 12;
    while (*p == ' ' || *p == ':')
        p++;
    if (*p++ != '"')
        return false;
    for (; (isalnum((unsigned char)*p) || *p == '_' || *p == '-') && i + 1 < cap;
         p++)
        out[i++] = *p;
    out[i] = '\0';
    return i > 0;
}

static bool fph_sid(const struct zcl_command_request *req, char *out,
                    size_t cap)
{
    const char *given = zcl_presence_str(req, "session");
    size_t i, n = 0;
    if (!given || !given[0])
        return fph_stdin_sid(out, cap);
    for (i = 0; given[i] && n + 1 < cap; i++) {
        if (isalnum((unsigned char)given[i]) || given[i] == '_' ||
            given[i] == '-')
            out[n++] = given[i];
    }
    out[n] = '\0';
    return n > 0;
}

static bool fph_free(const struct zcl_presence_rec *r, long long now)
{
    return r->beat <= 0 || !strcmp(r->phase, "completed") || r->beat > now ||
           now - r->beat >= ZCL_PRESENCE_WINDOW_S;
}

/* Pick the pool index for sid: owned, else lowest free, else oldest post. */
static int fph_pick(const struct zcl_presence_rec recs[FPH_POOL],
                    const char *sid, long long now, bool *owned)
{
    int i, free_i = -1, old_i = 0;
    *owned = false;
    for (i = 0; i < FPH_POOL; i++) {
        if (recs[i].beat > 0 && !strcmp(recs[i].owner, sid)) {
            *owned = true;
            return i;
        }
    }
    for (i = 0; i < FPH_POOL; i++) {
        if (free_i < 0 && fph_free(&recs[i], now))
            free_i = i;
        if (recs[i].beat < recs[old_i].beat)
            old_i = i;
    }
    return free_i >= 0 ? free_i : old_i;
}

static bool fph_name(const char *kind, char *role, size_t cap, int idx)
{
    return snprintf(role, cap, "%s-%d", kind, idx + 1) < (int)cap;
}

/* Choose the role and its record. owned reports an existing claim. */
static bool fph_choose(const char *kind, const char *sid, long long now,
                       char *role, size_t cap, struct zcl_presence_rec *rec,
                       bool *owned)
{
    struct zcl_presence_rec recs[FPH_POOL];
    char name[48];
    int i, pick;
    for (i = 0; i < FPH_POOL; i++) {
        if (!fph_name(kind, name, sizeof(name), i))
            return false;
        (void)zcl_presence_rec_load(name, &recs[i]);
    }
    pick = fph_pick(recs, sid, now, owned);
    *rec = recs[pick];
    return fph_name(kind, role, cap, pick);
}

static bool fph_throttled(const char *mode, bool owned,
                          const struct zcl_presence_rec *rec, long long now)
{
    return !strcmp(mode, "beat") && owned && strcmp(rec->phase, "completed") &&
           rec->beat <= now && now - rec->beat < ZCL_PRESENCE_BEAT_S;
}

static const char *fph_or(const char *v, const char *dflt)
{
    return v && v[0] ? v : dflt;
}

void zcl_presence_hook(const struct zcl_command_request *req,
                       struct zcl_command_reply *reply, const char *mode)
{
    struct zcl_presence_in in;
    struct zcl_presence_rec rec;
    char sid[FPH_SID_MAX + 1], role[48], sess[56];
    const char *kind = fph_or(zcl_presence_str(req, "source"), "claude");
    const char *forced = zcl_presence_str(req, "role");
    long long now = (long long)platform_time_wall_time_t();
    bool is_end = !strcmp(mode, "end"), owned = false;
    if (strcmp(mode, "start") && strcmp(mode, "beat") && !is_end) {
        zcl_presence_fail(reply, "PRESENCE_BAD_HOOK",
                          "hook must be start, beat or end", "hook");
        return;
    }
    if (!fph_sid(req, sid, sizeof(sid))) {
        zcl_presence_fail(reply, "PRESENCE_NO_SESSION",
                          "hook mode needs the session id: the hook JSON on stdin carries session_id, or pass --session=<id>",
                          "session");
        return;
    }
    if (forced && forced[0]) {
        (void)snprintf(role, sizeof(role), "%s", forced);
        (void)zcl_presence_rec_load(role, &rec);
        owned = rec.beat > 0 && !strcmp(rec.owner, sid);
    } else if (!fph_choose(kind, sid, now, role, sizeof(role), &rec, &owned)) {
        zcl_presence_fail(reply, "PRESENCE_BAD_FIELD",
                          "source is too long to name a role pool", "source");
        return;
    }
    if (is_end && !owned) {
        zcl_presence_reply_skipped(reply, role,
                                   "this session holds no role; nothing to end");
        return;
    }
    if (fph_throttled(mode, owned, &rec, now)) {
        zcl_presence_reply_skipped(reply, role, "beat posted less than 300 s ago");
        return;
    }
    memset(&in, 0, sizeof(in));
    (void)snprintf(sess, sizeof(sess), "s%.12s", sid);
    in.role = role;
    in.owner = sid;
    in.session = sess;
    in.task = fph_or(zcl_presence_str(req, "task"), "claude-session");
    in.phase = is_end ? "completed" : fph_or(zcl_presence_str(req, "phase"), "active");
    in.source = kind;
    in.started = zcl_presence_str(req, "started");
    if (!zcl_presence_pid_in(req, &in.pid)) {
        zcl_presence_fail(reply, "PRESENCE_PID_NOT_LIVE",
                          "pid must be a whole number naming a running process",
                          "pid");
        return;
    }
#if !defined(_WIN32)
    if (!json_get(req->input, "pid"))
        in.pid = (long long)getppid();
#endif
    zcl_presence_emit(req, reply, &in);
}
