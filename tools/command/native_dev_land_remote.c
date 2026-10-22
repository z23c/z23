/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land.receive / dev.land.send: submit from another machine.
 *
 * A host that cannot reach the queue host's single land queue sends its
 * unlanded commits as a git bundle and asks the queue host to queue them.
 *
 * send     (sending machine) refuses a dirty tracked tree (SEND_DIRTY_TREE),
 *          fetches origin/main, refuses when nothing is ahead
 *          (SEND_NOTHING_AHEAD), bundles HEAD ^origin/main, copies it to
 *          <host>:<inbox>/<lane>-<sha12>.bundle with scp, then runs
 *          `dev land receive` over ssh and relays the remote JSON reply as
 *          data.remote. ssh joins argv into a remote shell string, so every
 *          note, lane, path and host is checked against a closed character
 *          set (SEND_BAD_ARGUMENT) and each remote argument is single-quoted.
 * receive  (queue host) verifies the bundle in the checkout that owns the
 *          queue (RECEIVE_BAD_BUNDLE), fetches its single head into
 *          refs/heads/remote/<lane>, readies the detached worktree
 *          <state root>/land-remote/<lane> (never under land/, which the
 *          pre-push hook trusts; RECEIVE_WORKTREE_DIRTY when it holds tracked
 *          changes, which are never reset) and queues the tip through the
 *          in-process submit path, returning submit's reply unchanged.
 *
 * No shell anywhere: every child is an argv through the spawn seam. Tests
 * (ZCL_TESTING builds only) put one program in front of ssh and scp with
 * ZCL_LAND_REMOTE_XPORT, so no network is touched.
 */

#include "command/native_command.h"
#include "command/native_devagent.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/path_compat.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "platform/temp_directory.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <direct.h>
#define dlr_getcwd _getcwd
#else
#include <unistd.h>
#define dlr_getcwd getcwd
#endif

#define DLR_MS (10 * 60 * 1000)
#define DLR_PATH 4096u
#define DLR_NOTE_MAX 512u
#define DLR_OUT_CAP (64u * 1024u)
#define DLR_DEFAULT_CMD "z23-dev"
#define DLR_DEFAULT_INBOX ".cache/development-scratch/z23/land-inbox"

static const char *dlr_str(const struct zcl_command_request *req,
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

static void dlr_fail(struct zcl_command_reply *reply, const char *leaf,
                     const char *code, const char *phase, const char *msg,
                     const char *evidence)
{
    (void)json_push_kv_str(&reply->data, "leaf", leaf);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, phase, false,
                           false, msg, evidence);
    reply->error.human_action_required = true;
}

static bool dlr_alnum(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

/* [a-z0-9][a-z0-9-]{0,47} */
static bool dlr_lane_ok(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (n < 1 || n > 48)
        return false;
    for (size_t i = 0; i < n; i++) {
        bool digit = s[i] >= '0' && s[i] <= '9';
        bool lower = s[i] >= 'a' && s[i] <= 'z';
        if (!digit && !lower && !(i > 0 && s[i] == '-'))
            return false;
    }
    return true;
}

/* The closed set a remote shell string may carry inside single quotes.
 * `bare` words (the remote command, the host) lose the parentheses and may
 * not start with '-'; a set with no quote, `$`, backtick, `;`, `&`, `|`,
 * `<`, `>`, `*`, `?`, `!`, `~`, `\`, newline or '#' cannot escape quoting. */
static bool dlr_arg_ok(const char *s, bool bare)
{
    if (!s || (bare && s[0] == '-'))
        return false;
    for (const char *p = s; *p; p++) {
        bool paren = *p == '(' || *p == ')';
        if (!dlr_alnum(*p) && !strchr(" ._,:/+=-", *p) && !(paren && !bare))
            return false;
    }
    return true;
}

/* ssh_alias or user@alias: no ':' (scp would read it as a path split). */
static bool dlr_host_ok(const char *s)
{
    if (!s || !s[0] || s[0] == '-' || strlen(s) > 128)
        return false;
    for (const char *p = s; *p; p++)
        if (!dlr_alnum(*p) && !strchr("._@-", *p))
            return false;
    return true;
}

static int dlr_git(const char *dir, const char *const *args, char *out,
                   size_t cap)
{
    return zcl_native_dev_land_git(dir, args, out, cap, DLR_MS);
}

static void dlr_trim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
                     s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
}

static bool dlr_sha_ok(const char *s, size_t *len)
{
    size_t n = 0;
    while ((s[n] >= '0' && s[n] <= '9') || (s[n] >= 'a' && s[n] <= 'f'))
        n++;
    if (len)
        *len = n;
    return n == 40 || n == 64;
}

/* ── receive ───────────────────────────────────────────────────────────── */

struct dlr_recv {
    char root[DLR_PATH];
    char bundle[DLR_PATH];
    char wt[DLR_PATH + 64];
    char sha[80];
    char ref[256];
    char branch[96];
};

static void dlr_recv_fail(struct zcl_command_reply *reply, const char *code,
                          const char *phase, const char *msg,
                          const char *evidence)
{
    dlr_fail(reply, "dev.land.receive", code, phase, msg, evidence);
}

static bool dlr_bundle_abs(const char *in, char *out, size_t cap)
{
    char cwd[DLR_PATH];
    if (in[0] == '-')
        return false;
    if (platform_path_is_absolute(in))
        return snprintf(out, cap, "%s", in) < (int)cap;
    if (!dlr_getcwd(cwd, sizeof(cwd)))
        return false;
    return snprintf(out, cap, "%s/%s", cwd, in) < (int)cap;
}

static bool dlr_recv_bundle_verify(struct dlr_recv *r, const char *in,
                                   struct zcl_command_reply *reply)
{
    const char *args[] = {"bundle", "verify", r->bundle, NULL};
    char sink[512];
    if (!dlr_bundle_abs(in, r->bundle, sizeof(r->bundle)) ||
        dlr_git(r->root, args, sink, sizeof(sink)) != 0) {
        dlr_recv_fail(reply, "RECEIVE_BAD_BUNDLE", "verify",
                      "git bundle verify refused the bundle; it is not a "
                      "complete bundle on top of this checkout's history",
                      in);
        return false;
    }
    return true;
}

/* A bundle must carry exactly one head: "<sha> <ref>\n". */
static bool dlr_recv_head(struct dlr_recv *r, struct zcl_command_reply *reply)
{
    const char *args[] = {"bundle", "list-heads", r->bundle, NULL};
    char out[2048], *nl;
    size_t n = 0;
    out[0] = '\0';
    if (dlr_git(r->root, args, out, sizeof(out)) != 0)
        goto bad;
    dlr_trim(out);
    nl = strchr(out, '\n');
    if (nl || !dlr_sha_ok(out, &n) || out[n] != ' ' || !out[n + 1] ||
        out[n + 1] == '-' ||
        snprintf(r->ref, sizeof(r->ref), "%s", out + n + 1) >=
            (int)sizeof(r->ref))
        goto bad;
    out[n] = '\0';
    (void)snprintf(r->sha, sizeof(r->sha), "%s", out);
    return true;
bad:
    dlr_recv_fail(reply, "RECEIVE_BAD_BUNDLE", "heads",
                  "a bundle must carry exactly one head (HEAD ^origin/main "
                  "makes one)",
                  r->bundle);
    return false;
}

static bool dlr_recv_fetch(struct dlr_recv *r, const char *lane,
                           struct zcl_command_reply *reply)
{
    char spec[512], sink[512];
    const char *args[] = {"fetch", "--quiet", r->bundle, spec, NULL};
    const char *rp[] = {"rev-parse", "--verify", "--quiet", r->branch, NULL};
    (void)snprintf(r->branch, sizeof(r->branch), "refs/heads/remote/%s", lane);
    (void)snprintf(spec, sizeof(spec), "+%s:%s", r->ref, r->branch);
    if (dlr_git(r->root, args, sink, sizeof(sink)) != 0 ||
        dlr_git(r->root, rp, sink, sizeof(sink)) != 0) {
        dlr_recv_fail(reply, "RECEIVE_FETCH_FAILED", "fetch",
                      "could not fetch the bundle head into the lane ref",
                      r->branch);
        return false;
    }
    dlr_trim(sink);
    return strcmp(sink, r->sha) == 0;
}

static bool dlr_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static bool dlr_wt_path(struct dlr_recv *r, const char *lane,
                        struct zcl_command_reply *reply)
{
    char state[DLR_PATH];
    if (platform_state_root(state, sizeof(state)) &&
        snprintf(r->wt, sizeof(r->wt), "%s/land-remote/%s", state, lane) <
            (int)sizeof(r->wt))
        return true;
    dlr_recv_fail(reply, "RECEIVE_STATE_FAILED", "worktree",
                  "cannot resolve the owner-private state root",
                  "platform_state_root");
    return false;
}

/* Create, or move a clean one, detached at the tip; never reset a dirty one. */
static bool dlr_recv_worktree(struct dlr_recv *r, const char *lane,
                              struct zcl_command_reply *reply)
{
    char gitdir[DLR_PATH + 80], sink[2048];
    const char *st[] = {"status", "--porcelain", "--untracked-files=no", NULL};
    const char *co[] = {"checkout", "--quiet", "--detach", r->sha, NULL};
    const char *add[] = {"worktree", "add", "--quiet", "--detach", r->wt,
                         r->sha, NULL};
    if (!dlr_wt_path(r, lane, reply))
        return false;
    (void)snprintf(gitdir, sizeof(gitdir), "%s/.git", r->wt);
    if (!dlr_exists(gitdir)) {
        if (dlr_git(r->root, add, sink, sizeof(sink)) == 0)
            return true;
    } else if (dlr_git(r->wt, st, sink, sizeof(sink)) != 0) {
        dlr_recv_fail(reply, "RECEIVE_WORKTREE_FAILED", "worktree",
                      "cannot inspect the lane worktree", r->wt);
        return false;
    } else if (sink[0]) {
        dlr_recv_fail(reply, "RECEIVE_WORKTREE_DIRTY", "worktree",
                      "the lane worktree has tracked changes; it is left "
                      "untouched, clean or remove it and send again",
                      r->wt);
        return false;
    } else if (dlr_git(r->wt, co, sink, sizeof(sink)) == 0) {
        return true;
    }
    dlr_recv_fail(reply, "RECEIVE_WORKTREE_FAILED", "worktree",
                  "could not place the lane worktree at the tip", r->wt);
    return false;
}

static void dlr_recv_submit(const struct dlr_recv *r,
                            const struct zcl_command_request *req,
                            struct zcl_command_reply *reply)
{
    struct zcl_command_request sub = *req;
    struct json_value in;
    const char *note = dlr_str(req, "note");
    json_init(&in);
    json_set_object(&in);
    (void)json_push_kv_str(&in, "tip", r->sha);
    (void)json_push_kv_str(&in, "worktree", r->wt);
    if (note)
        (void)json_push_kv_str(&in, "note", note);
    sub.input = &in;
    zcl_native_dev_land_submit(&sub, reply);
    json_free(&in);
}

static void dlr_receive(const struct zcl_command_request *req,
                        struct zcl_command_reply *reply)
{
    struct dlr_recv *r;
    const char *lane = dlr_str(req, "lane");
    const char *bundle = dlr_str(req, "bundle");
    if (!dlr_lane_ok(lane) || !bundle) {
        dlr_recv_fail(reply, "RECEIVE_BAD_LANE", "input",
                      "lane must match [a-z0-9][a-z0-9-]{0,47} and bundle "
                      "must name a file",
                      lane ? lane : "input.lane missing");
        return;
    }
    r = zcl_calloc(1, sizeof(*r), "dev_land_remote.recv");
    if (!zcl_devagent_checkout_root(NULL, r->root, sizeof(r->root)))
        dlr_recv_fail(reply, "RECEIVE_NO_CHECKOUT", "checkout",
                      "run this inside the checkout that owns the land queue",
                      "no checkout root above the current directory");
    else if (dlr_recv_bundle_verify(r, bundle, reply) &&
             dlr_recv_head(r, reply) && dlr_recv_fetch(r, lane, reply) &&
             dlr_recv_worktree(r, lane, reply))
        dlr_recv_submit(r, req, reply);
    free(r);
}

/* ── send ──────────────────────────────────────────────────────────────── */

struct dlr_send {
    const char *host, *lane, *note, *cmd, *inbox;
    char root[DLR_PATH];
    char sha[80];
    char tmpdir[PLATFORM_TEMP_PATH_MAX];
    char bundle[DLR_PATH];
    char remote[DLR_PATH];
    char dest[DLR_PATH + 160];
    long ahead;
};

static void dlr_send_fail(struct zcl_command_reply *reply, const char *code,
                          const char *phase, const char *msg,
                          const char *evidence)
{
    dlr_fail(reply, "dev.land.send", code, phase, msg, evidence);
}

static bool dlr_send_args(const struct zcl_command_request *req,
                          struct dlr_send *s, struct zcl_command_reply *reply)
{
    s->host = dlr_str(req, "host");
    s->lane = dlr_str(req, "lane");
    s->note = dlr_str(req, "note");
    s->cmd = dlr_str(req, "remote_cmd");
    s->inbox = dlr_str(req, "inbox");
    if (!s->cmd)
        s->cmd = DLR_DEFAULT_CMD;
    if (!s->inbox)
        s->inbox = DLR_DEFAULT_INBOX;
    if (dlr_host_ok(s->host) && dlr_lane_ok(s->lane) &&
        dlr_arg_ok(s->cmd, true) && dlr_arg_ok(s->inbox, true) &&
        !strchr(s->inbox, ' ') &&
        (!s->note || (dlr_arg_ok(s->note, false) &&
                      strlen(s->note) <= DLR_NOTE_MAX)))
        return true;
    dlr_send_fail(reply, "SEND_BAD_ARGUMENT", "input",
                  "host, lane, note, remote_cmd and inbox may hold only "
                  "[A-Za-z0-9 ._,:/()+=-] (no parentheses in host, "
                  "remote_cmd or inbox; lane is [a-z0-9][a-z0-9-]{0,47}; "
                  "note is at most 512 characters); ssh joins them into one "
                  "remote shell string",
                  "input.host, lane, note, remote_cmd or inbox");
    return false;
}

static bool dlr_send_git(struct dlr_send *s, const char *const *args,
                         char *out, size_t cap, const char *code,
                         struct zcl_command_reply *reply)
{
    if (dlr_git(s->root, args, out, cap) == 0) {
        dlr_trim(out);
        return true;
    }
    dlr_send_fail(reply, code, "git", "a git step on the sending checkout "
                  "failed", args[0]);
    return false;
}

static bool dlr_send_prepare(struct dlr_send *s,
                             struct zcl_command_reply *reply)
{
    const char *top[] = {"rev-parse", "--show-toplevel", NULL};
    const char *dirty[] = {"status", "--porcelain", "--untracked-files=no",
                           NULL};
    const char *fetch[] = {"fetch", "--quiet", "origin", "main", NULL};
    const char *count[] = {"rev-list", "--count", "origin/main..HEAD", NULL};
    const char *head[] = {"rev-parse", "HEAD", NULL};
    char out[2048];
    if (dlr_git(".", top, s->root, sizeof(s->root)) != 0) {
        dlr_send_fail(reply, "SEND_NO_CHECKOUT", "checkout",
                      "run this inside the git checkout to send", "cwd");
        return false;
    }
    dlr_trim(s->root);
    if (!dlr_send_git(s, dirty, out, sizeof(out), "SEND_GIT_FAILED", reply))
        return false;
    if (out[0]) {
        dlr_send_fail(reply, "SEND_DIRTY_TREE", "tree",
                      "tracked files have uncommitted changes; commit or "
                      "stash them, a bundle carries commits only",
                      s->root);
        return false;
    }
    if (!dlr_send_git(s, fetch, out, sizeof(out), "SEND_FETCH_FAILED", reply) ||
        !dlr_send_git(s, count, out, sizeof(out), "SEND_GIT_FAILED", reply))
        return false;
    s->ahead = strtol(out, NULL, 10);
    if (s->ahead <= 0) {
        dlr_send_fail(reply, "SEND_NOTHING_AHEAD", "tree",
                      "HEAD has no commits beyond origin/main; there is "
                      "nothing to send",
                      "origin/main..HEAD is empty");
        return false;
    }
    return dlr_send_git(s, head, s->sha, sizeof(s->sha), "SEND_GIT_FAILED",
                        reply);
}

/* Test builds may put one program in front of ssh and scp. */
static const char *dlr_xport_prefix(void)
{
#if defined(ZCL_TESTING)
    const char *p = getenv("ZCL_LAND_REMOTE_XPORT");
    return p && p[0] ? p : NULL;
#else
    return NULL;
#endif
}

static int dlr_xport(const char *prog, const char *const *args, char *out,
                     size_t cap)
{
    const char *argv[32];
    size_t n = 0;
    const char *pre = dlr_xport_prefix();
    if (pre)
        argv[n++] = pre;
    argv[n++] = prog;
    for (size_t i = 0; args[i]; i++) {
        if (n + 2 > sizeof(argv) / sizeof(argv[0]))
            return -1;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    return zcl_spawn_capture(argv, out, cap, DLR_MS);
}

static bool dlr_send_bundle(struct dlr_send *s, struct zcl_command_reply *reply)
{
    const char *mk[] = {"bundle", "create", s->bundle, "HEAD", "^origin/main",
                        NULL};
    char sink[1024];
    if (!platform_temp_directory_create("z23-land-send-", s->tmpdir,
                                        sizeof(s->tmpdir)) ||
        snprintf(s->bundle, sizeof(s->bundle), "%s/%s-%.12s.bundle", s->tmpdir,
                 s->lane, s->sha) >= (int)sizeof(s->bundle) ||
        snprintf(s->remote, sizeof(s->remote), "%s/%s-%.12s.bundle", s->inbox,
                 s->lane, s->sha) >= (int)sizeof(s->remote) ||
        snprintf(s->dest, sizeof(s->dest), "%s:%s", s->host, s->remote) >=
            (int)sizeof(s->dest)) {
        dlr_send_fail(reply, "SEND_TEMP_FAILED", "bundle",
                      "cannot make the scratch directory for the bundle",
                      "platform_temp_directory_create");
        return false;
    }
    if (dlr_git(s->root, mk, sink, sizeof(sink)) == 0)
        return true;
    dlr_send_fail(reply, "SEND_BUNDLE_FAILED", "bundle",
                  "git bundle create failed", s->bundle);
    return false;
}

static bool dlr_send_copy(struct dlr_send *s, struct zcl_command_reply *reply)
{
    char quoted[DLR_PATH + 8], sink[1024];
    const char *mk[] = {"-o", "BatchMode=yes", s->host, "mkdir", "-p", "--",
                        quoted, NULL};
    const char *cp[] = {"-q", "-o", "BatchMode=yes", s->bundle, s->dest, NULL};
    (void)snprintf(quoted, sizeof(quoted), "'%s'", s->inbox);
    if (dlr_xport("ssh", mk, sink, sizeof(sink)) == 0 &&
        dlr_xport("scp", cp, sink, sizeof(sink)) == 0)
        return true;
    dlr_send_fail(reply, "SEND_COPY_FAILED", "copy",
                  "ssh or scp to the queue host failed; check the alias and "
                  "that key login works without a prompt",
                  s->host);
    return false;
}

/* The remote reply is relayed verbatim as data.remote; a non-zero exit stays
 * a refusal of this leaf with the remote body beside it. */
static void dlr_send_relay(const char *out, int rc,
                           struct zcl_command_reply *reply)
{
    struct json_value doc;
    json_init(&doc);
    if (json_read(&doc, out, strlen(out)))
        (void)json_push_kv(&reply->data, "remote", &doc);
    else
        (void)json_push_kv_str(&reply->data, "remote_output", out);
    json_free(&doc);
    if (rc != 0)
        dlr_send_fail(reply, "SEND_REMOTE_REFUSED", "receive",
                      "the queue host refused or failed; its reply is in "
                      "data.remote",
                      rc < 0 ? "ssh could not be launched" : "ssh exit nonzero");
}

static void dlr_send_receive(const struct dlr_send *s,
                             struct zcl_command_reply *reply)
{
    char b[DLR_PATH + 16], l[96], n[DLR_NOTE_MAX + 16], *out;
    const char *argv[16];
    size_t k = 0;
    int rc;
    (void)snprintf(b, sizeof(b), "'--bundle=%s'", s->remote);
    (void)snprintf(l, sizeof(l), "'--lane=%s'", s->lane);
    argv[k++] = "-o";
    argv[k++] = "BatchMode=yes";
    argv[k++] = s->host;
    argv[k++] = s->cmd;
    argv[k++] = "dev";
    argv[k++] = "land";
    argv[k++] = "receive";
    argv[k++] = b;
    argv[k++] = l;
    if (s->note) {
        (void)snprintf(n, sizeof(n), "'--note=%s'", s->note);
        argv[k++] = n;
    }
    argv[k] = NULL;
    out = zcl_calloc(1, DLR_OUT_CAP, "dev_land_remote.reply");
    rc = dlr_xport("ssh", argv, out, DLR_OUT_CAP);
    (void)json_push_kv_str(&reply->data, "leaf", "dev.land.send");
    (void)json_push_kv_str(&reply->data, "bundle", s->remote);
    (void)json_push_kv_str(&reply->data, "head", s->sha);
    (void)json_push_kv_int(&reply->data, "ahead", s->ahead);
    dlr_send_relay(out, rc, reply);
    free(out);
}

static void dlr_send(const struct zcl_command_request *req,
                     struct zcl_command_reply *reply)
{
    struct dlr_send *s = zcl_calloc(1, sizeof(*s), "dev_land_remote.send");
    if (dlr_send_args(req, s, reply) && dlr_send_prepare(s, reply) &&
        dlr_send_bundle(s, reply) && dlr_send_copy(s, reply))
        dlr_send_receive(s, reply);
    if (s->bundle[0])
        (void)remove(s->bundle);
    if (s->tmpdir[0])
        (void)platform_private_directory_remove_empty(s->tmpdir);
    free(s);
}

void zcl_native_handle_dev_land_remote(const struct zcl_command_request *req,
                                       struct zcl_command_reply *reply)
{
    const char *path;
    if (!reply)
        return;
    path = req && req->spec ? req->spec->path : NULL;
    if (path && strcmp(path, "dev.land.send") == 0)
        dlr_send(req, reply);
    else if (path && strcmp(path, "dev.land.receive") == 0)
        dlr_receive(req, reply);
    else
        dlr_fail(reply, "dev.land.remote", "UNKNOWN_LEAF", "route",
                 "this handler serves dev.land.send and dev.land.receive",
                 path ? path : "no leaf resolved");
}
