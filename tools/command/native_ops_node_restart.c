/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: ops.node.restart - restart this host's z23 node unit and report
 *          the tip height and process uptime before and after. The node
 *          unit is z23-node.service, or the legacy zclassic23.service on a
 *          host that still runs it: whichever one is the only active node
 *          unit. Two steps. A call without confirm changes nothing: it
 *          reads the node, selects the unit and returns a plan_id that is
 *          valid for five minutes and one use, and the plan binds that
 *          unit. The same call with that plan_id and confirm:true first
 *          re-selects the unit and refuses if it changed since the plan,
 *          then runs exactly one `systemctl --user restart <unit>` of the
 *          planned unit, and polls the node's own RPC until it answers or
 *          wait_s (1..120, default 120) elapses. Selection refuses with
 *          NODE_UNIT_AMBIGUOUS when both units are active (two nodes would
 *          share one datadir) and with NODE_UNIT_NOT_FOUND when neither is
 *          active or an answer is unrecognised; nothing restarts then. The
 *          unit, its drop-ins and the datadir are never edited, and the
 *          only inputs are wait_s, plan_id and confirm: a flag that would
 *          wipe, reindex or move the datadir is refused. macOS (launchd)
 *          and Windows are reported UNSUPPORTED. systemctl is
 *          ZCL_SLOT_SYSTEMCTL_BIN and the plan lives in ZCL_SLOT_STATE_DIR,
 *          the seams ops.slot.activate already uses.
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_command.h"
#include "command/native_slot_common.h"

#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include "util/file_tree_ops.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(_WIN32)
#include <sys/wait.h>
#endif

#define NR_CMD "ops.node.restart"
#define NR_UNIT_NEW "z23-node.service"
#define NR_UNIT_LEGACY "zclassic23.service"
#define NR_UNIT_BYTES 40
#define NR_STATE_BYTES 64
#define NR_PLAN_FILE "node-restart.plan"
#define NR_PLAN_TTL_S 300
#define NR_WAIT_DEFAULT_S 120
#define NR_POLL_MS 250
#define NR_CONNECT_MS 500
#define NR_CALL_MS 3000
#define NR_PLAN_ID_BYTES 16

#if defined(_WIN32)
#define NR_PLATFORM "Windows"
#elif defined(__APPLE__)
#define NR_PLATFORM "macOS (launchd)"
#elif !defined(__linux__)
#define NR_PLATFORM "this platform"
#endif

#ifdef NR_PLATFORM
static void nr_handle(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply)
{
    (void)request;
    if (reply)
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "UNSUPPORTED",
                               "normalize", false, false,
                               "ops node restart is UNSUPPORTED on "
                               NR_PLATFORM ": it drives a systemd --user unit",
                               NR_CMD);
}
#else

struct nr_obs {
    int64_t height; /* -1 when the node did not answer */
    int64_t uptime; /* -1 when unknown */
};

struct nr_plan {
    char id[2 * NR_PLAN_ID_BYTES + 1];
    char unit[NR_UNIT_BYTES];
    int64_t expires;
    int wait_s;
};

enum nr_unit_state { NR_UNIT_ACTIVE, NR_UNIT_INACTIVE, NR_UNIT_UNKNOWN };

/* The first line of `systemctl --user is-active <unit>`. Live words count as
 * a running node; clear words as none; anything else is UNKNOWN and never
 * counts as clear. */
static const char *const NR_LIVE_WORDS[] = {
    "active", "activating", "reloading", "deactivating", NULL};
static const char *const NR_CLEAR_WORDS[] = {
    "inactive", "failed", "unknown", "not-found", NULL};

/* ---- unit selection ----------------------------------------------------- */

/* Runs `systemctl --user is-active <unit>` and copies its stdout. False when
 * nothing came back: systemctl missing, no user bus, or a fork failure. */
static bool nr_query_active(const char *unit, char *out, size_t cap)
{
    const char *bin = getenv("ZCL_SLOT_SYSTEMCTL_BIN");
    char *argv[5];
    int fds[2], status = 0, devnull;
    size_t used = 0;
    ssize_t n;
    pid_t pid;
    if (pipe(fds) != 0)
        return false;
    argv[0] = (char *)((bin && bin[0]) ? bin : "systemctl");
    argv[1] = (char *)"--user";
    argv[2] = (char *)"is-active";
    argv[3] = (char *)unit;
    argv[4] = NULL;
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return false;
    }
    if (pid == 0) {
        devnull = open("/dev/null", O_RDWR);
        (void)dup2(fds[1], 1);
        if (devnull >= 0) {
            (void)dup2(devnull, 0);
            (void)dup2(devnull, 2);
        }
        close(fds[0]);
        close(fds[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fds[1]);
    while (used + 1 < cap &&
           (n = read(fds[0], out + used, cap - 1 - used)) > 0)
        used += (size_t)n;
    close(fds[0]);
    out[used] = '\0';
    (void)waitpid(pid, &status, 0);
    return used > 0;
}

static enum nr_unit_state nr_classify(const char *unit)
{
    char out[NR_STATE_BYTES];
    char *eol;
    if (!nr_query_active(unit, out, sizeof(out)))
        return NR_UNIT_UNKNOWN;
    eol = strpbrk(out, "\r\n");
    if (eol)
        *eol = '\0';
    for (size_t i = 0; NR_LIVE_WORDS[i]; i++)
        if (strcmp(out, NR_LIVE_WORDS[i]) == 0)
            return NR_UNIT_ACTIVE;
    for (size_t i = 0; NR_CLEAR_WORDS[i]; i++)
        if (strcmp(out, NR_CLEAR_WORDS[i]) == 0)
            return NR_UNIT_INACTIVE;
    return NR_UNIT_UNKNOWN;
}

/* Only the listed unit names are node units; a plan file naming anything
 * else is refused. Returns the constant name, or NULL. */
static const char *nr_known_unit(const char *unit)
{
    if (unit && strcmp(unit, NR_UNIT_NEW) == 0)
        return NR_UNIT_NEW;
    if (unit && strcmp(unit, NR_UNIT_LEGACY) == 0)
        return NR_UNIT_LEGACY;
    return NULL;
}

/* Exactly one node unit must be active. Both active would mean two nodes on
 * one datadir; neither, or an unknown answer, leaves nothing to restart. */
static bool nr_select_unit(const char **unit, struct zcl_command_reply *reply)
{
    enum nr_unit_state nw = nr_classify(NR_UNIT_NEW);
    enum nr_unit_state lg = nr_classify(NR_UNIT_LEGACY);
    if (nw == NR_UNIT_UNKNOWN || lg == NR_UNIT_UNKNOWN) {
        slot_refuse(reply, "NODE_UNIT_NOT_FOUND",
                    "could not read whether z23-node.service or "
                    "zclassic23.service is active (systemctl --user is "
                    "unavailable or answered unrecognised); nothing restarted",
                    "systemctl --user is-active");
        return false;
    }
    if (nw == NR_UNIT_ACTIVE && lg == NR_UNIT_ACTIVE) {
        slot_refuse(reply, "NODE_UNIT_AMBIGUOUS",
                    "both z23-node.service and zclassic23.service are active; "
                    "two nodes on one datadir. Stop one deliberately; "
                    "nothing restarted", "systemctl --user is-active");
        return false;
    }
    if (nw == NR_UNIT_ACTIVE)
        *unit = NR_UNIT_NEW;
    else if (lg == NR_UNIT_ACTIVE)
        *unit = NR_UNIT_LEGACY;
    else {
        slot_refuse(reply, "NODE_UNIT_NOT_FOUND",
                    "neither z23-node.service nor zclassic23.service is "
                    "active; nothing restarted", "systemctl --user is-active");
        return false;
    }
    return true;
}

/* ---- node read path ----------------------------------------------------- */

/* The bare JSON result of an RPC, parsed; false when the node did not answer
 * (the client returns an error object then). */
static bool nr_rpc(const char *method, struct json_value *out)
{
    char *raw = node_rpc_call_deadline(method, NULL, NR_CONNECT_MS, NR_CALL_MS);
    bool ok = false;
    json_init(out);
    if (raw)
        ok = json_read(out, raw, strlen(raw));
    free(raw);
    if (!ok)
        json_free(out);
    return ok;
}

static int64_t nr_read_height(void)
{
    struct json_value v;
    int64_t h = -1;
    if (!nr_rpc("getblockcount", &v))
        return -1;
    if (v.type == JSON_INT && json_get_int(&v) >= 0)
        h = json_get_int(&v);
    json_free(&v);
    return h;
}

static int64_t nr_read_uptime(void)
{
    struct json_value v;
    const struct json_value *checks, *up;
    int64_t t = -1;
    if (!nr_rpc("healthcheck", &v))
        return -1;
    checks = v.type == JSON_OBJ ? json_get(&v, "checks") : NULL;
    up = checks ? json_get(checks, "uptime_seconds") : NULL;
    if (up && up->type == JSON_INT && json_get_int(up) >= 0)
        t = json_get_int(up);
    json_free(&v);
    return t;
}

static struct nr_obs nr_observe(void)
{
    struct nr_obs o = { nr_read_height(), -1 };
    if (o.height >= 0)
        o.uptime = nr_read_uptime();
    return o;
}

/* ---- input -------------------------------------------------------------- */

static bool nr_key_allowed(const char *key)
{
    return strcmp(key, "wait_s") == 0 || strcmp(key, "plan_id") == 0 ||
           strcmp(key, "confirm") == 0;
}

static bool nr_inputs_ok(const struct json_value *in,
                         struct zcl_command_reply *reply)
{
    for (size_t i = 0; in->type == JSON_OBJ && i < in->num_children; i++) {
        if (in->keys && in->keys[i] && !nr_key_allowed(in->keys[i])) {
            slot_refuse(reply, "UNKNOWN_OPTION",
                        "ops node restart takes only wait_s, plan_id and "
                        "confirm; it never wipes, reindexes or moves the "
                        "datadir", in->keys[i]);
            return false;
        }
    }
    return true;
}

static bool nr_wait_s(const struct json_value *in, int *out,
                      struct zcl_command_reply *reply)
{
    const struct json_value *w = json_get(in, "wait_s");
    *out = NR_WAIT_DEFAULT_S;
    if (!w)
        return true;
    if (w->type != JSON_INT || json_get_int(w) < 1 || json_get_int(w) > 120) {
        slot_refuse(reply, "BAD_WAIT", "wait_s must be an integer 1..120",
                    "input.wait_s");
        return false;
    }
    *out = (int)json_get_int(w);
    return true;
}

/* ---- plan record -------------------------------------------------------- */

static bool nr_plan_path(char *out, size_t cap)
{
    char dir[SLOT_PATH_MAX];
    int n;
    if (!slot_state_dir(dir, sizeof(dir)))
        return false;
    n = snprintf(out, cap, "%s/%s", dir, NR_PLAN_FILE);
    return n > 0 && (size_t)n < cap;
}

static bool nr_plan_write(const struct nr_plan *p)
{
    char path[SLOT_PATH_MAX], tmp[SLOT_PATH_MAX + 16], dir[SLOT_PATH_MAX];
    char text[192];
    int len, fd;
    bool ok;
    if (!nr_plan_path(path, sizeof(path)) ||
        !slot_state_dir(dir, sizeof(dir)) || !zcl_mkdir_p(dir, 0700).ok)
        return false;
    len = snprintf(text, sizeof(text), "%s %lld %d %s\n", p->id,
                   (long long)p->expires, p->wait_s, p->unit);
    if (len <= 0 || (size_t)len >= sizeof(text))
        return false;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
        return false;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return false;
    ok = write(fd, text, (size_t)len) == len && fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    if (!ok || rename(tmp, path) != 0) {
        unlink(tmp);
        return false;
    }
    return true;
}

static bool nr_plan_read(struct nr_plan *p)
{
    char path[SLOT_PATH_MAX], text[192], unit[NR_UNIT_BYTES];
    long long exp = 0;
    int wait = 0;
    char id[sizeof(p->id)];
    if (!nr_plan_path(path, sizeof(path)) ||
        slot_read_file(path, text, sizeof(text)) <= 0 ||
        sscanf(text, "%32s %lld %d %39s", id, &exp, &wait, unit) != 4 ||
        !nr_known_unit(unit))
        return false;
    snprintf(p->id, sizeof(p->id), "%s", id);
    snprintf(p->unit, sizeof(p->unit), "%s", unit);
    p->expires = exp;
    p->wait_s = wait;
    return true;
}

static void nr_plan_drop(void)
{
    char path[SLOT_PATH_MAX];
    if (nr_plan_path(path, sizeof(path)))
        unlink(path);
}

static bool nr_plan_new(struct nr_plan *p, const char *unit, int wait_s)
{
    uint8_t raw[NR_PLAN_ID_BYTES];
    if (!rng_fill(raw, sizeof(raw)))
        return false;
    for (size_t i = 0; i < sizeof(raw); i++)
        snprintf(p->id + 2 * i, 3, "%02x", raw[i]);
    snprintf(p->unit, sizeof(p->unit), "%s", unit);
    p->expires = platform_time_wall_unix() + NR_PLAN_TTL_S;
    p->wait_s = wait_s;
    return nr_plan_write(p);
}

/* ---- replies ------------------------------------------------------------ */

static void nr_push_obs(struct json_value *data, const char *suffix,
                        const struct nr_obs *o)
{
    char key[40];
    if (o->height >= 0) {
        snprintf(key, sizeof(key), "height_%s", suffix);
        json_push_kv_int(data, key, o->height);
    }
    if (o->uptime >= 0) {
        snprintf(key, sizeof(key), "uptime_s_%s", suffix);
        json_push_kv_int(data, key, o->uptime);
    }
}

static void nr_reply_plan(const struct nr_plan *p, const struct nr_obs *o,
                          struct zcl_command_reply *reply)
{
    char action[128];
    snprintf(action, sizeof(action), "systemctl --user restart %s", p->unit);
    json_push_kv_str(&reply->data, "plan_id", p->id);
    json_push_kv_str(&reply->data, "unit", p->unit);
    json_push_kv_str(&reply->data, "action", action);
    json_push_kv_bool(&reply->data, "answering", o->height >= 0);
    nr_push_obs(&reply->data, "now", o);
    json_push_kv_int(&reply->data, "wait_s", p->wait_s);
    json_push_kv_int(&reply->data, "expires_in_s", NR_PLAN_TTL_S);
    json_push_kv_bool(&reply->data, "mutated", false);
    json_push_kv_str(&reply->data, "next",
        "repeat the call with this plan_id and confirm:true to restart; the "
        "plan is single use");
}

static void nr_reply_done(const char *unit, const struct nr_obs *b,
                          const struct nr_obs *a,
                          struct zcl_command_reply *reply)
{
    char note[96];
    snprintf(note, sizeof(note), "restarted, answering at height %lld",
             (long long)a->height);
    json_push_kv_str(&reply->data, "unit", unit);
    json_push_kv_bool(&reply->data, "restarted", true);
    json_push_kv_bool(&reply->data, "mutated", true);
    nr_push_obs(&reply->data, "before", b);
    nr_push_obs(&reply->data, "after", a);
    json_push_kv_str(&reply->data, "note", note);
}

static void nr_fail(struct zcl_command_reply *reply, const char *code,
                    const char *phase, bool mutated, const char *message)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, phase, true, mutated,
                           message, NR_CMD);
}

/* ---- restart ------------------------------------------------------------ */

/* Exit status of `systemctl --user restart <unit>`; -1 when it cannot run. */
static int nr_systemctl_restart(const char *unit)
{
    const char *bin = getenv("ZCL_SLOT_SYSTEMCTL_BIN");
    char *argv[5];
    int status = 0, devnull;
    pid_t pid;
    argv[0] = (char *)((bin && bin[0]) ? bin : "systemctl");
    argv[1] = (char *)"--user";
    argv[2] = (char *)"restart";
    argv[3] = (char *)unit;
    argv[4] = NULL;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            (void)dup2(devnull, 0);
            (void)dup2(devnull, 1);
            (void)dup2(devnull, 2);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static bool nr_wait_answering(int wait_s, struct nr_obs *out)
{
    int64_t deadline = platform_time_monotonic_ms() + (int64_t)wait_s * 1000;
    do {
        *out = nr_observe();
        if (out->height >= 0)
            return true;
        platform_sleep_ms(NR_POLL_MS);
    } while (platform_time_monotonic_ms() < deadline);
    return false;
}

static void nr_run(const char *unit, int wait_s,
                   struct zcl_command_reply *reply)
{
    struct nr_obs before = nr_observe(), after = { -1, -1 };
    char what[128];
    snprintf(what, sizeof(what), "systemctl --user restart %s did not succeed",
             unit);
    if (nr_systemctl_restart(unit) != 0) {
        nr_fail(reply, "RESTART_FAILED", "restart", true, what);
        return;
    }
    if (!nr_wait_answering(wait_s, &after)) {
        nr_fail(reply, "NODE_NOT_ANSWERING", "wait", true,
                "restart was issued but the node did not answer within "
                "wait_s seconds; check the unit with systemctl --user status");
        return;
    }
    if (before.uptime >= 0 && after.uptime >= before.uptime) {
        nr_fail(reply, "NOT_RESTARTED", "wait", true,
                "the node answers but its process uptime did not reset");
        return;
    }
    nr_reply_done(unit, &before, &after, reply);
}

/* ---- confirm ------------------------------------------------------------ */

/* Checks the plan, consumes it, and re-selects the unit. On success *unit is
 * the planned unit, which is still the only active node unit. */
static bool nr_confirm_ok(const struct json_value *in, int wait_s,
                          const char **unit, struct zcl_command_reply *reply)
{
    const char *given = json_get_str(json_get(in, "plan_id"));
    const char *now = NULL;
    struct nr_plan p;
    bool have = nr_plan_read(&p);
    if (!given || !given[0] || !have || strcmp(given, p.id) != 0 ||
        p.wait_s != wait_s) {
        slot_refuse(reply, "PLAN_MISMATCH",
                    "plan_id is missing, wrong, already used or was planned "
                    "with another wait_s; request a new plan without confirm",
                    "input.plan_id");
        return false;
    }
    nr_plan_drop();
    if (platform_time_wall_unix() > p.expires) {
        slot_refuse(reply, "PLAN_EXPIRED",
                    "the plan is older than five minutes; request a new plan "
                    "without confirm", "input.plan_id");
        return false;
    }
    if (!nr_select_unit(&now, reply))
        return false;
    if (strcmp(now, p.unit) != 0) {
        slot_refuse(reply, "NODE_UNIT_CHANGED",
                    "the active node unit changed since the plan; request a "
                    "new plan without confirm. Nothing restarted",
                    "input.plan_id");
        return false;
    }
    *unit = nr_known_unit(p.unit);
    return *unit != NULL;
}

static void nr_plan_reply(int wait_s, struct zcl_command_reply *reply)
{
    struct nr_plan p;
    struct nr_obs o;
    const char *unit = NULL;
    if (!nr_select_unit(&unit, reply))
        return;
    o = nr_observe();
    if (!nr_plan_new(&p, unit, wait_s)) {
        nr_fail(reply, "PLAN_NOT_SAVED", "plan", false,
                "cannot record the plan under ZCL_SLOT_STATE_DIR");
        return;
    }
    nr_reply_plan(&p, &o, reply);
}

static void nr_handle(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply)
{
    const struct json_value *in = request ? request->input : NULL;
    const char *unit = NULL;
    int wait_s;
    if (!reply)
        return;
    if (!in) {
        slot_refuse(reply, "BAD_INPUT", "ops node restart needs input",
                    NR_CMD);
        return;
    }
    if (!nr_inputs_ok(in, reply) || !nr_wait_s(in, &wait_s, reply))
        return;
    if (!json_get_bool(json_get(in, "confirm"))) {
        if (json_get_str(json_get(in, "plan_id"))[0])
            slot_refuse(reply, "CONFIRM_REQUIRED",
                        "a plan_id restarts only with confirm:true",
                        "input.confirm");
        else
            nr_plan_reply(wait_s, reply);
        return;
    }
    if (nr_confirm_ok(in, wait_s, &unit, reply))
        nr_run(unit, wait_s, reply);
}

#endif /* NR_PLATFORM */

/* One public entry; each platform arm above supplies its own static nr_handle. */
void zcl_native_handle_ops_node_restart(const struct zcl_command_request *request,
                                        struct zcl_command_reply *reply)
{
    nr_handle(request, reply);
}
