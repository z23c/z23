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
 *          --commit=<sha or ref> sends exactly that commit instead of HEAD:
 *          origin/main..<commit> must be that one commit (else
 *          SEND_NOT_SINGLE, whose message gives the command that makes it
 *          single). The bundle is built from the object store, so a dirty
 *          working tree is allowed with --commit: its changes cannot leak
 *          into the bundle. git bundle takes refs, not bare ids, so the
 *          commit is pinned under refs/z23-send/ for the bundle and that ref
 *          is removed again. --bundle_out=<absolute path> writes the bundle
 *          there instead (SEND_BUNDLE_EXISTS when the path exists), runs no
 *          ssh or scp and needs no --host: data.bundle, data.bundle_sha256,
 *          data.commit and data.lane, plus a READY line naming the commit and
 *          sha256, are the handoff to a queue host reached another way.
 *          It also writes <bundle_out>.offer.json (SEND_OFFER_EXISTS when
 *          that exists; reported as data.offer), a flat manifest
 *          {schema "zcl.dev_land_offer.v1", commit, base (the bundle's
 *          prerequisite: the commit's parent), bundle_sha256, lane} that the
 *          receiver checks with check_offer before it trusts the bundle.
 * check_offer (any machine, read-only) takes --bundle and --offer (absolute
 *          paths) and optional --repo (default: the checkout above the
 *          current directory). It queues nothing, fetches nothing and
 *          touches no worktree. Refusals: OFFER_BAD_MANIFEST (wrong schema,
 *          malformed commit, base or sha), OFFER_SHA_MISMATCH (the bundle's
 *          sha256 is not the offered one), OFFER_BAD_BUNDLE (git bundle
 *          verify failed in --repo), OFFER_HEAD_MISMATCH (not exactly one
 *          head, equal to the offered commit), OFFER_BASE_MISMATCH (not
 *          exactly one prerequisite, equal to the offered base). Reply:
 *          data {commit, base, bundle_sha256, verdict "ok"}.
 * attest_offer (the receiver) takes check_offer's inputs plus an absolute
 *          --receipt_out. It runs exactly check_offer's checks and only on a
 *          pass writes a receipt {schema "zcl.dev_land_offer_receipt.v1",
 *          commit, base, bundle_sha256, checks "bundle_sha256,bundle_verify,
 *          head,base", verdict "ok", signer (64 hex), signature (128 hex)}.
 *          The Ed25519 signature, by this box's dev_proof_signer key, covers
 *          "<schema>\n" commit "\n" base "\n" bundle_sha256 "\n" checks "\n"
 *          verdict "\n". A failed check writes nothing and returns
 *          check_offer's code; OFFER_RECEIPT_EXISTS when receipt_out exists
 *          (never replaced); OFFER_RECEIPT_FAILED when signing or writing
 *          fails. Reply: check_offer's data plus receipt and signer.
 * verify_offer_receipt (read-only) takes --receipt and optional --offer.
 *          OFFER_RECEIPT_BAD (not a v1 receipt), RECEIPT_SIGNATURE_INVALID
 *          (the bytes do not verify), RECEIPT_SIGNER_UNKNOWN (neither this
 *          box's key nor on its signers.allow), RECEIPT_OFFER_MISMATCH (with
 *          --offer: another commit, base or bundle_sha256). Reply: data
 *          {commit, base, signer, verdict, checks}.
 * receive (queue host) verifies the bundle in the checkout that owns the
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
#include "command/native_dev_land_precheck.h"
#include "command/native_devagent.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/path_compat.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "platform/temp_directory.h"
#include "util/spawn.h"
#include "crypto/sha256.h"
#include "dev_proof_signer.h"

#include <stdint.h>
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

/* git bundle verify of r->bundle in r->root. */
static bool dlr_bundle_verify_ok(const struct dlr_recv *r)
{
    const char *args[] = {"bundle", "verify", r->bundle, NULL};
    char sink[512];
    return dlr_git(r->root, args, sink, sizeof(sink)) == 0;
}

static bool dlr_recv_bundle_verify(struct dlr_recv *r, const char *in,
                                   struct zcl_command_reply *reply)
{
    if (!dlr_bundle_abs(in, r->bundle, sizeof(r->bundle)) ||
        !dlr_bundle_verify_ok(r)) {
        dlr_recv_fail(reply, "RECEIVE_BAD_BUNDLE", "verify",
                      "git bundle verify refused the bundle; it is not a "
                      "complete bundle on top of this checkout's history",
                      in);
        return false;
    }
    return true;
}

/* A bundle must carry exactly one head: "<sha> <ref>\n". */
static bool dlr_head_parse(struct dlr_recv *r)
{
    const char *args[] = {"bundle", "list-heads", r->bundle, NULL};
    char out[2048], *nl;
    size_t n = 0;
    out[0] = '\0';
    if (dlr_git(r->root, args, out, sizeof(out)) != 0)
        return false;
    dlr_trim(out);
    nl = strchr(out, '\n');
    if (nl || !dlr_sha_ok(out, &n) || out[n] != ' ' || !out[n + 1] ||
        out[n + 1] == '-' ||
        snprintf(r->ref, sizeof(r->ref), "%s", out + n + 1) >=
            (int)sizeof(r->ref))
        return false;
    out[n] = '\0';
    (void)snprintf(r->sha, sizeof(r->sha), "%s", out);
    return true;
}

static bool dlr_recv_head(struct dlr_recv *r, struct zcl_command_reply *reply)
{
    if (dlr_head_parse(r))
        return true;
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
    if (strcmp(sink, r->sha) != 0) {
        dlr_recv_fail(reply, "RECEIVE_FETCH_FAILED", "fetch",
                      "fetched ref does not match the bundle head", r->branch);
        return false;
    }
    return true;
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
    /* No precheck key: the sender ran it, and the received entry below
     * skips it by an internal flag no input value can set. A skip the
     * sender chose is already in the note it sent. */
    (void)json_push_kv_str(&in, "worktree", r->wt);
    if (note)
        (void)json_push_kv_str(&in, "note", note);
    sub.input = &in;
    zcl_native_dev_land_submit_received(&sub, reply);
    json_free(&in);
}

/* The queue checkout: an explicit absolute --checkout=DIR (the marker check
 * still applies), else the walk up from the current directory. */
static bool dlr_recv_root(const struct zcl_command_request *req,
                         struct dlr_recv *r, struct zcl_command_reply *reply)
{
    const char *dir = dlr_str(req, "checkout");
    if (!dir) {
        if (zcl_devagent_checkout_root(NULL, r->root, sizeof(r->root)))
            return true;
        dlr_recv_fail(reply, "RECEIVE_NO_CHECKOUT", "checkout",
                      "run this inside the checkout that owns the land "
                      "queue, or pass --checkout=DIR",
                      "no checkout root above the current directory");
        return false;
    }
    if (dir[0] == '/' && dlr_arg_ok(dir, true) &&
        zcl_devagent_checkout_root(dir, r->root, sizeof(r->root)))
        return true;
    dlr_recv_fail(reply, "RECEIVE_BAD_CHECKOUT", "checkout",
                  "--checkout must be an absolute path inside the checkout "
                  "that owns the land queue",
                  dir);
    return false;
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
    if (dlr_recv_root(req, r, reply) &&
        dlr_recv_bundle_verify(r, bundle, reply) &&
        dlr_recv_head(r, reply) && dlr_recv_fetch(r, lane, reply) &&
        dlr_recv_worktree(r, lane, reply))
        dlr_recv_submit(r, req, reply);
    free(r);
}

/* ── send ──────────────────────────────────────────────────────────────── */

struct dlr_send {
    const char *host, *lane, *note, *cmd, *inbox, *checkout;
    const char *commit, *out;
    char root[DLR_PATH];
    char sha[80];
    char base[80];
    char offer[DLR_PATH + 16];
    char tmpdir[PLATFORM_TEMP_PATH_MAX];
    char bundle[DLR_PATH];
    char remote[DLR_PATH];
    char dest[DLR_PATH + 160];
    char tmpref[DLR_PATH];
    char bsha[SHA256_OUTPUT_SIZE * 2 + 1];
    long ahead;
    char note_buf[DLR_NOTE_MAX + 1];
};

static void dlr_send_fail(struct zcl_command_reply *reply, const char *code,
                          const char *phase, const char *msg,
                          const char *evidence)
{
    dlr_fail(reply, "dev.land.send", code, phase, msg, evidence);
}

/* The names that reach ssh. --bundle_out needs no host, so the host may be
 * absent only then; a host that is present is still checked. */
static bool dlr_send_names_ok(const struct dlr_send *s)
{
    return ((!s->host && s->out) || dlr_host_ok(s->host)) &&
           dlr_lane_ok(s->lane) && dlr_arg_ok(s->cmd, true) &&
           dlr_arg_ok(s->inbox, true) && !strchr(s->inbox, ' ') &&
           (!s->checkout || (s->checkout[0] == '/' &&
                              dlr_arg_ok(s->checkout, true))) &&
           (!s->note || (dlr_arg_ok(s->note, false) &&
                         strlen(s->note) <= DLR_NOTE_MAX));
}

/* A commit name is a git argument, never a shell word: revision characters
 * only, and never something that looks like an option. */
static bool dlr_commit_ok(const char *s)
{
    if (!s)
        return true;
    size_t n = strlen(s);
    return n > 0 && n <= 200 && s[0] != '-' &&
           strspn(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                     "0123456789._/~^-") == n;
}

/* An absolute path in the closed character set, short enough for DLR_PATH. */
static bool dlr_out_ok(const char *p)
{
    return !p || (p[0] == '/' && strlen(p) < DLR_PATH &&
                  dlr_arg_ok(p, true));
}

/* bundle_out and its <bundle_out>.offer.json must both be absent: neither
 * is ever overwritten. */
static bool dlr_send_out_free(struct dlr_send *s,
                              struct zcl_command_reply *reply)
{
    if (dlr_exists(s->out)) {
        dlr_send_fail(reply, "SEND_BUNDLE_EXISTS", "bundle",
                      "bundle_out already exists; it is never overwritten",
                      s->out);
        return false;
    }
    if (snprintf(s->offer, sizeof(s->offer), "%s.offer.json", s->out) >=
        (int)sizeof(s->offer)) {
        dlr_send_fail(reply, "SEND_BAD_ARGUMENT", "input",
                      "bundle_out is too long for its .offer.json sibling",
                      "input.bundle_out");
        return false;
    }
    if (dlr_exists(s->offer)) {
        dlr_send_fail(reply, "SEND_OFFER_EXISTS", "offer",
                      "the .offer.json beside bundle_out already exists; it "
                      "is never overwritten",
                      s->offer);
        return false;
    }
    return true;
}

static bool dlr_send_args(const struct zcl_command_request *req,
                          struct dlr_send *s, struct zcl_command_reply *reply)
{
    s->host = dlr_str(req, "host");
    s->lane = dlr_str(req, "lane");
    s->note = dlr_str(req, "note");
    s->cmd = dlr_str(req, "remote_cmd");
    s->inbox = dlr_str(req, "inbox");
    s->checkout = dlr_str(req, "remote_checkout");
    s->commit = dlr_str(req, "commit");
    s->out = dlr_str(req, "bundle_out");
    if (!s->cmd)
        s->cmd = DLR_DEFAULT_CMD;
    if (!s->inbox)
        s->inbox = DLR_DEFAULT_INBOX;
    if (!s->host && !s->out) {
        dlr_send_fail(reply, "SEND_BAD_ARGUMENT", "input",
                      "host is required unless bundle_out is given: send "
                      "copies the bundle to the queue host over scp and ssh",
                      "input.host");
        return false;
    }
    if (dlr_send_names_ok(s)) {
        if (!dlr_commit_ok(s->commit) || !dlr_out_ok(s->out)) {
            dlr_send_fail(reply, "SEND_BAD_ARGUMENT", "input",
                          "commit must be 1-200 characters of "
                          "[A-Za-z0-9._/~^-] not starting with '-'; "
                          "bundle_out must be an absolute path "
                          "of [A-Za-z0-9 ._,:/+=-]",
                          "input.commit or input.bundle_out");
            return false;
        }
        return !s->out || dlr_send_out_free(s, reply);
    }
    dlr_send_fail(reply, "SEND_BAD_ARGUMENT", "input",
                  "host, lane, note, remote_cmd, inbox and remote_checkout may hold "
                  "only "
                  "[A-Za-z0-9 ._,:/()+=-] (no parentheses in host, "
                  "remote_cmd or inbox; lane is [a-z0-9][a-z0-9-]{0,47}; "
                  "note is at most 512 characters); ssh joins them into one "
                  "remote shell string",
                  "input.host, lane, note, remote_cmd, inbox or remote_checkout");
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

/* A bundle carries commits only, so tracked changes refuse the plain send.
 * --commit skips this: the bundle is made from the object store. */
static bool dlr_send_clean(struct dlr_send *s, struct zcl_command_reply *reply)
{
    const char *dirty[] = {"status", "--porcelain", "--untracked-files=no",
                           NULL};
    char out[2048];
    if (!dlr_send_git(s, dirty, out, sizeof(out), "SEND_GIT_FAILED", reply))
        return false;
    if (out[0]) {
        dlr_send_fail(reply, "SEND_DIRTY_TREE", "tree",
                      "tracked files have uncommitted changes; commit or "
                      "stash them, a bundle carries commits only",
                      s->root);
        return false;
    }
    return true;
}

static bool dlr_send_head(struct dlr_send *s, struct zcl_command_reply *reply)
{
    const char *count[] = {"rev-list", "--count", "origin/main..HEAD", NULL};
    const char *head[] = {"rev-parse", "HEAD", NULL};
    char out[2048];
    if (!dlr_send_git(s, count, out, sizeof(out), "SEND_GIT_FAILED", reply))
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

/* --commit=<name> to a full commit id in this checkout (SEND_BAD_ARGUMENT
 * when it does not resolve). */
static bool dlr_send_resolve(struct dlr_send *s,
                             struct zcl_command_reply *reply)
{
    char spec[256], out[128];
    const char *argv[] = {"rev-parse", "--verify", "--quiet", spec, NULL};
    size_t n = 0;
    out[0] = '\0';
    if (snprintf(spec, sizeof(spec), "%s^{commit}", s->commit) >=
        (int)sizeof(spec))
        goto bad;
    if (dlr_git(s->root, argv, out, sizeof(out)) == 0) {
        dlr_trim(out);
        if (dlr_sha_ok(out, &n) && out[n] == '\0' &&
            snprintf(s->sha, sizeof(s->sha), "%s", out) < (int)sizeof(s->sha))
            return true;
    }
bad:
    dlr_send_fail(reply, "SEND_BAD_ARGUMENT", "input",
                  "--commit does not name a commit in this checkout",
                  s->commit);
    return false;
}

/* origin/main..<commit> must be exactly that commit. Zero means it has
 * already landed; more than one would bundle a stack, so refuse with the
 * one command that makes a single-commit branch. */
static bool dlr_send_commit(struct dlr_send *s,
                            struct zcl_command_reply *reply)
{
    char out[2048], msg[600];
    if (!dlr_send_resolve(s, reply))
        return false;
    const char *count[] = {"rev-list", "--count", s->sha, "^origin/main",
                           NULL};
    if (!dlr_send_git(s, count, out, sizeof(out), "SEND_GIT_FAILED", reply))
        return false;
    s->ahead = strtol(out, NULL, 10);
    if (s->ahead == 0) {
        dlr_send_fail(reply, "SEND_NOTHING_AHEAD", "tree",
                      "--commit is already on origin/main; there is nothing "
                      "to send",
                      s->commit);
        return false;
    }
    if (s->ahead == 1)
        return true;
    (void)snprintf(msg, sizeof(msg),
                   "--commit is not exactly one commit beyond origin/main; "
                   "make a single-commit branch with: git switch -c "
                   "send/%s origin/main && git cherry-pick -S %s, then send "
                   "the new commit",
                   s->lane, s->commit);
    dlr_send_fail(reply, "SEND_NOT_SINGLE", "tree", msg, s->commit);
    return false;
}

static bool dlr_send_prepare(struct dlr_send *s,
                             struct zcl_command_reply *reply)
{
    const char *top[] = {"rev-parse", "--show-toplevel", NULL};
    const char *fetch[] = {"fetch", "--quiet", "origin", "main", NULL};
    char out[2048];
    if (dlr_git(".", top, s->root, sizeof(s->root)) != 0) {
        dlr_send_fail(reply, "SEND_NO_CHECKOUT", "checkout",
                      "run this inside the git checkout to send", "cwd");
        return false;
    }
    dlr_trim(s->root);
    if (!s->commit && !dlr_send_clean(s, reply))
        return false;
    if (!dlr_send_git(s, fetch, out, sizeof(out), "SEND_FETCH_FAILED", reply))
        return false;
    return s->commit ? dlr_send_commit(s, reply) : dlr_send_head(s, reply);
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

/* sha256 of a file, streamed in bounded reads, as lowercase hex. */
static bool dlr_file_sha256(const char *path, char hex[SHA256_OUTPUT_SIZE * 2 + 1])
{
    unsigned char buf[8192];
    unsigned char dig[SHA256_OUTPUT_SIZE];
    struct sha256_ctx ctx;
    size_t n;
    bool ok;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    sha256_init(&ctx);
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_write(&ctx, buf, n);
    ok = !ferror(f);
    if (fclose(f) != 0 || !ok)
        return false;
    sha256_finalize(&ctx, dig);
    for (size_t i = 0; i < sizeof(dig); i++)
        (void)snprintf(hex + 2 * i, 3, "%02x", dig[i]);
    return true;
}

/* git bundle takes refs, not bare ids: --commit pins the commit under a
 * refs/z23-send/ ref for the bundle. The ref is removed after the send. */
static bool dlr_send_pin(struct dlr_send *s, struct zcl_command_reply *reply)
{
    const char *upd[] = {"update-ref", s->tmpref, s->sha, NULL};
    char sink[1024];
    if (snprintf(s->tmpref, sizeof(s->tmpref), "refs/z23-send/%s-%.12s",
                 s->lane, s->sha) < (int)sizeof(s->tmpref) &&
        dlr_git(s->root, upd, sink, sizeof(sink)) == 0)
        return true;
    dlr_send_fail(reply, "SEND_BUNDLE_FAILED", "bundle",
                  "cannot pin the commit for git bundle", s->sha);
    return false;
}

static void dlr_send_unpin(const struct dlr_send *s)
{
    const char *del[] = {"update-ref", "-d", s->tmpref, NULL};
    char sink[1024];
    (void)dlr_git(s->root, del, sink, sizeof(sink));
}

/* Writes the bundle of origin/main..<tip> to path: HEAD, or the --commit. */
static bool dlr_send_make(struct dlr_send *s, const char *path,
                          struct zcl_command_reply *reply)
{
    char sink[1024];
    const char *tip, *mk[] = {"bundle", "create", path, NULL, "^origin/main",
                              NULL};
    if (s->commit && !dlr_send_pin(s, reply))
        return false;
    tip = s->commit ? s->tmpref : "HEAD";
    mk[3] = tip;
    if (dlr_git(s->root, mk, sink, sizeof(sink)) == 0)
        return true;
    dlr_send_fail(reply, "SEND_BUNDLE_FAILED", "bundle",
                  "git bundle create failed", path);
    return false;
}

static bool dlr_send_bundle(struct dlr_send *s, struct zcl_command_reply *reply)
{
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
    if (!dlr_send_make(s, s->bundle, reply))
        return false;
    if (dlr_file_sha256(s->bundle, s->bsha))
        return true;
    dlr_send_fail(reply, "SEND_BUNDLE_FAILED", "bundle",
                  "cannot read back the bundle to hash it", s->bundle);
    return false;
}

/* One JSON object plus a newline, created exclusively at path (an existing
 * file is never replaced); a partial file is removed again. */
static bool dlr_json_write_new(const struct json_value *doc, const char *path)
{
    char body[1024];
    size_t n = json_write(doc, body, sizeof(body) - 1);
    FILE *f = (n > 0 && n < sizeof(body) - 1) ? fopen(path, "wx") : NULL;
    bool ok;
    if (!f)
        return false;
    body[n++] = '\n';
    ok = fwrite(body, 1, n, f) == n;
    ok = fclose(f) == 0 && ok;
    if (!ok)
        (void)remove(path);
    return ok;
}

/* Writes <bundle_out>.offer.json, the flat manifest a receiver checks with
 * dev.land.check_offer: schema, commit, the bundle's prerequisite (the
 * commit's parent), the bundle's sha256 and the lane. Created exclusively. */
static bool dlr_send_offer(struct dlr_send *s, struct zcl_command_reply *reply)
{
    char spec[64];
    const char *rp[] = {"rev-parse", "--verify", "--quiet", spec, NULL};
    struct json_value doc;
    bool ok = false;
    /* The base is the bundle's prerequisite, the parent of the one included
     * commit, not the origin/main tip, which may have moved past it. */
    if (snprintf(spec, sizeof(spec), "%.40s^", s->sha) >= (int)sizeof(spec))
        return false;
    if (!dlr_send_git(s, rp, s->base, sizeof(s->base), "SEND_GIT_FAILED",
                      reply))
        return false;
    json_init(&doc);
    json_set_object(&doc);
    ok = json_push_kv_str(&doc, "schema", "zcl.dev_land_offer.v1") &&
         json_push_kv_str(&doc, "commit", s->sha) &&
         json_push_kv_str(&doc, "base", s->base) &&
         json_push_kv_str(&doc, "bundle_sha256", s->bsha) &&
         json_push_kv_str(&doc, "lane", s->lane);
    ok = ok && dlr_json_write_new(&doc, s->offer);
    json_free(&doc);
    if (!ok)
        dlr_send_fail(reply, "SEND_OFFER_FAILED", "offer",
                      "cannot write the offer manifest beside bundle_out",
                      s->offer);
    return ok;
}

/* --bundle_out: the handoff for a machine with no ssh to the queue host. */
static void dlr_send_out(struct dlr_send *s, struct zcl_command_reply *reply)
{
    char ready[256];
    /* bundle_out did not exist (dlr_send_args), so any file at it now is
     * this call's own partial output and is removed on failure. */
    if (!dlr_send_make(s, s->out, reply)) {
        (void)remove(s->out);
        return;
    }
    if (!dlr_file_sha256(s->out, s->bsha)) {
        (void)remove(s->out);
        dlr_send_fail(reply, "SEND_BUNDLE_FAILED", "bundle",
                      "cannot read back the bundle to hash it", s->out);
        return;
    }
    if (!dlr_send_offer(s, reply)) {
        (void)remove(s->out);
        return;
    }
    /* The READY line is meant for the board, so it names no local path. */
    if (snprintf(ready, sizeof(ready), "READY %s %s bundle_sha256=%s",
                 s->lane, s->sha, s->bsha) >= (int)sizeof(ready)) {
        dlr_send_fail(reply, "SEND_BUNDLE_FAILED", "bundle",
                      "the READY line does not fit", s->out);
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", "dev.land.send");
    (void)json_push_kv_str(&reply->data, "bundle", s->out);
    (void)json_push_kv_str(&reply->data, "bundle_sha256", s->bsha);
    (void)json_push_kv_str(&reply->data, "commit", s->sha);
    (void)json_push_kv_str(&reply->data, "lane", s->lane);
    (void)json_push_kv_str(&reply->data, "offer", s->offer);
    (void)json_push_kv_str(&reply->data, "ready", ready);
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

/* The local lint precheck, before the bundle is made; --precheck=skip
 * appends its marker to the note that travels to the queue host. */
static bool dlr_send_precheck(struct dlr_send *s,
                              const struct zcl_command_request *req,
                              struct zcl_command_reply *reply)
{
    (void)snprintf(s->note_buf, sizeof(s->note_buf), "%s",
                   s->note ? s->note : "");
    if (!zcl_dev_land_precheck("dev.land.send", s->root, NULL,
                               dlr_str(req, "precheck"), NULL, false,
                               s->note_buf, sizeof(s->note_buf), reply))
        return false;
    if (s->note_buf[0])
        s->note = s->note_buf;
    return true;
}

static void dlr_send_receive(const struct dlr_send *s,
                             struct zcl_command_reply *reply)
{
    char b[DLR_PATH + 16], l[96], n[DLR_NOTE_MAX + 16], c[DLR_PATH + 16], *out;
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
    if (s->checkout) {
        (void)snprintf(c, sizeof(c), "'--checkout=%s'", s->checkout);
        argv[k++] = c;
    }
    argv[k] = NULL;
    out = zcl_calloc(1, DLR_OUT_CAP, "dev_land_remote.reply");
    rc = dlr_xport("ssh", argv, out, DLR_OUT_CAP);
    (void)json_push_kv_str(&reply->data, "leaf", "dev.land.send");
    (void)json_push_kv_str(&reply->data, "bundle", s->remote);
    (void)json_push_kv_str(&reply->data, "head", s->sha);
    (void)json_push_kv_int(&reply->data, "ahead", s->ahead);
    (void)json_push_kv_str(&reply->data, "commit", s->sha);
    (void)json_push_kv_str(&reply->data, "bundle_sha256", s->bsha);
    dlr_send_relay(out, rc, reply);
    free(out);
}

static void dlr_send(const struct zcl_command_request *req,
                     struct zcl_command_reply *reply)
{
    struct dlr_send *s = zcl_calloc(1, sizeof(*s), "dev_land_remote.send");
    if (dlr_send_args(req, s, reply) && dlr_send_prepare(s, reply) &&
        dlr_send_precheck(s, req, reply)) {
        if (s->out)
            dlr_send_out(s, reply);
        else if (dlr_send_bundle(s, reply) && dlr_send_copy(s, reply))
            dlr_send_receive(s, reply);
    }
    if (s->bundle[0])
        (void)remove(s->bundle);
    if (s->tmpdir[0])
        (void)platform_private_directory_remove_empty(s->tmpdir);
    if (s->tmpref[0])
        dlr_send_unpin(s);
    free(s);
}

/* ── check_offer ───────────────────────────────────────────────────────── */

#define DLR_OFFER_SCHEMA "zcl.dev_land_offer.v1"
#define DLR_OFFER_MAX 4096u

struct dlr_offer {
    struct dlr_recv r;
    char commit[48], base[48], bsha[80], lane[64], prereq[48];
    const char *leaf; /* the leaf whose reply carries a refusal */
};

static void dlr_offer_fail(const char *leaf, struct zcl_command_reply *reply,
                           const char *code, const char *phase,
                           const char *msg, const char *evidence)
{
    dlr_fail(reply, leaf, code, phase, msg, evidence);
}

static bool dlr_hex_n(const char *s, size_t want)
{
    size_t n = 0;
    return s && dlr_sha_ok(s, &n) && n == want && s[n] == '\0';
}

/* A manifest string field, copied; false when absent, not a string or long. */
static bool dlr_offer_str(const struct json_value *doc, const char *key,
                          char *dst, size_t cap)
{
    const struct json_value *v = json_get(doc, key);
    return v && v->type == JSON_STR && json_get_str(v) &&
           snprintf(dst, cap, "%s", json_get_str(v)) < (int)cap;
}

static bool dlr_offer_fields(const struct json_value *doc, struct dlr_offer *o)
{
    char schema[48];
    return dlr_offer_str(doc, "schema", schema, sizeof(schema)) &&
           strcmp(schema, DLR_OFFER_SCHEMA) == 0 &&
           dlr_offer_str(doc, "commit", o->commit, sizeof(o->commit)) &&
           dlr_offer_str(doc, "base", o->base, sizeof(o->base)) &&
           dlr_offer_str(doc, "bundle_sha256", o->bsha, sizeof(o->bsha)) &&
           dlr_offer_str(doc, "lane", o->lane, sizeof(o->lane)) &&
           dlr_hex_n(o->commit, 40) && dlr_hex_n(o->base, 40) &&
           dlr_hex_n(o->bsha, 64) && dlr_lane_ok(o->lane);
}

/* A small JSON object file parsed into doc (always json_free it after). */
static bool dlr_json_read_file(const char *path, struct json_value *doc)
{
    char raw[DLR_OFFER_MAX];
    size_t n = 0;
    bool ok = false;
    FILE *f = fopen(path, "rb");
    if (f) {
        n = fread(raw, 1, sizeof(raw), f);
        ok = !ferror(f) && n > 0 && n < sizeof(raw);
        (void)fclose(f);
    }
    json_init(doc);
    return ok && json_read(doc, raw, n) && doc->type == JSON_OBJ;
}

/* Reads the flat manifest: right schema, 40-hex commit and base, 64-hex
 * bundle sha256, a lane name. */
static bool dlr_offer_read(const char *path, struct dlr_offer *o,
                           struct zcl_command_reply *reply)
{
    struct json_value doc;
    bool ok = dlr_json_read_file(path, &doc) && dlr_offer_fields(&doc, o);
    json_free(&doc);
    if (!ok)
        dlr_offer_fail(o->leaf, reply, "OFFER_BAD_MANIFEST", "manifest",
                       "the offer is not a flat zcl.dev_land_offer.v1 object "
                       "with a 40-hex commit and base, a 64-hex "
                       "bundle_sha256 and a lane",
                       path);
    return ok;
}

/* The bundle's prerequisites from its header ("-<sha> <subject>" lines
 * before the blank line that ends it): how many, and the first. */
static bool dlr_offer_prereq(const char *bundle, char out[48], int *count)
{
    char line[512];
    FILE *f = fopen(bundle, "rb");
    bool ok = f != NULL;
    *count = 0;
    out[0] = '\0';
    while (ok && fgets(line, sizeof(line), f) && line[0] != '\n') {
        if (line[0] != '-')
            continue;
        if (++*count == 1)
            ok = snprintf(out, 48, "%.40s", line + 1) < 48;
    }
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok;
}

/* The bundle against the offer: sha256, git's own verify, one head equal to
 * the commit, one prerequisite equal to the base. */
static bool dlr_offer_bundle(struct dlr_offer *o,
                             struct zcl_command_reply *reply)
{
    char hex[SHA256_OUTPUT_SIZE * 2 + 1];
    int count = 0;
    if (!dlr_file_sha256(o->r.bundle, hex) || strcmp(hex, o->bsha) != 0)
        dlr_offer_fail(o->leaf, reply, "OFFER_SHA_MISMATCH", "sha256",
                       "the bundle's sha256 is not the one the offer names",
                       o->r.bundle);
    else if (!dlr_bundle_verify_ok(&o->r))
        dlr_offer_fail(o->leaf, reply, "OFFER_BAD_BUNDLE", "verify",
                       "git bundle verify refused the bundle in this "
                       "checkout",
                       o->r.bundle);
    else if (!dlr_head_parse(&o->r) || strcmp(o->r.sha, o->commit) != 0)
        dlr_offer_fail(o->leaf, reply, "OFFER_HEAD_MISMATCH", "heads",
                       "the bundle must carry exactly one head, and it must "
                       "be the offered commit",
                       o->commit);
    else if (!dlr_offer_prereq(o->r.bundle, o->prereq, &count) ||
             count != 1 || strcmp(o->prereq, o->base) != 0)
        dlr_offer_fail(o->leaf, reply, "OFFER_BASE_MISMATCH", "base",
                       "the bundle must have exactly one prerequisite, and "
                       "it must be the offered base",
                       o->base);
    else
        return true;
    return false;
}

/* The repository the bundle is verified in: --repo (absolute, inside a
 * checkout) or the checkout above the current directory. */
static bool dlr_offer_root(const struct zcl_command_request *req,
                           struct dlr_offer *o,
                           struct zcl_command_reply *reply)
{
    const char *dir = dlr_str(req, "repo");
    bool ok = dir ? dir[0] == '/' && dlr_arg_ok(dir, true) &&
                        zcl_devagent_checkout_root(dir, o->r.root,
                                                   sizeof(o->r.root))
                  : zcl_devagent_checkout_root(NULL, o->r.root,
                                               sizeof(o->r.root));
    if (!ok)
        dlr_offer_fail(o->leaf, reply, "OFFER_BAD_REPO", "repo",
                       "--repo must be the absolute path of a checkout; "
                       "without it the checkout above the current directory "
                       "is used",
                       dir ? dir : "no checkout root above the cwd");
    return ok;
}

#define DLR_CHECK_LEAF "dev.land.check_offer"
#define DLR_ATTEST_LEAF "dev.land.attest_offer"
#define DLR_VERIFY_LEAF "dev.land.verify_offer_receipt"

static void dlr_offer_ok(const struct dlr_offer *o,
                         struct zcl_command_reply *reply)
{
    (void)json_push_kv_str(&reply->data, "leaf", o->leaf);
    (void)json_push_kv_str(&reply->data, "commit", o->commit);
    (void)json_push_kv_str(&reply->data, "base", o->base);
    (void)json_push_kv_str(&reply->data, "bundle_sha256", o->bsha);
    (void)json_push_kv_str(&reply->data, "verdict", "ok");
}

/* Reads the manifest and runs every check (check_offer and attest_offer
 * share this). NULL, with the refusal in reply, when any of them fails. */
static struct dlr_offer *dlr_offer_checked(const struct zcl_command_request *req,
                                           struct zcl_command_reply *reply,
                                           const char *leaf)
{
    struct dlr_offer *o;
    const char *bundle = dlr_str(req, "bundle");
    const char *offer = dlr_str(req, "offer");
    bool ok;
    if (!bundle || !offer) {
        dlr_offer_fail(leaf, reply, "OFFER_BAD_ARGUMENT", "input",
                       "bundle and offer must each name a file",
                       "input.bundle or input.offer missing");
        return NULL;
    }
    o = zcl_calloc(1, sizeof(*o), "dev_land_remote.offer");
    o->leaf = leaf;
    ok = dlr_offer_read(offer, o, reply) && dlr_offer_root(req, o, reply);
    if (ok && !dlr_bundle_abs(bundle, o->r.bundle, sizeof(o->r.bundle))) {
        dlr_offer_fail(leaf, reply, "OFFER_BAD_BUNDLE", "verify",
                       "bundle is not a usable path", bundle);
        ok = false;
    }
    if (!ok || !dlr_offer_bundle(o, reply)) {
        free(o);
        return NULL;
    }
    return o;
}

/* Read-only: nothing is queued, fetched or written, and no worktree is
 * touched; every check is on bytes already on disk. */
static void dlr_check_offer(const struct zcl_command_request *req,
                            struct zcl_command_reply *reply)
{
    struct dlr_offer *o = dlr_offer_checked(req, reply, DLR_CHECK_LEAF);
    if (o)
        dlr_offer_ok(o, reply);
    free(o);
}

/* ── offer receipts ────────────────────────────────────────────────────── */

#define DLR_RECEIPT_SCHEMA "zcl.dev_land_offer_receipt.v1"
#define DLR_RECEIPT_CHECKS "bundle_sha256,bundle_verify,head,base"
#define DLR_RECEIPT_VERDICT "ok"

/* Hex fields as written; pub and sigb are signer and sig decoded (verify). */
struct dlr_receipt {
    char commit[48], base[48], bsha[80], checks[64], verdict[16];
    char signer[ZCL_DEV_PROOF_SIGNER_PUBKEY_HEX], sig[129];
    uint8_t pub[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES];
    uint8_t sigb[ZCL_DEV_PROOF_SIGNER_SIGNATURE_BYTES];
};

/* The one signed message: the schema as the domain separator, then the five
 * fields in this fixed order, each followed by a newline. */
static size_t dlr_receipt_msg(const struct dlr_receipt *t, char *out,
                              size_t cap)
{
    int n = snprintf(out, cap, DLR_RECEIPT_SCHEMA "\n%s\n%s\n%s\n%s\n%s\n",
                     t->commit, t->base, t->bsha, t->checks, t->verdict);
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

/* Signs t's message with this box's key; fills t->signer and t->sig. */
static bool dlr_receipt_sign(struct dlr_receipt *t, const char **why)
{
    char msg[512];
    size_t n = dlr_receipt_msg(t, msg, sizeof(msg));
    uint8_t pub[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES];
    uint8_t sig[ZCL_DEV_PROOF_SIGNER_SIGNATURE_BYTES];
    if (n == 0 || !zcl_dev_proof_signer_sign((const uint8_t *)msg, n, pub, sig,
                                             why))
        return false;
    zcl_hex_encode(pub, sizeof(pub), t->signer);
    zcl_hex_encode(sig, sizeof(sig), t->sig);
    return true;
}

static void dlr_attest_fail(struct zcl_command_reply *reply, const char *code,
                            const char *msg, const char *evidence)
{
    dlr_fail(reply, DLR_ATTEST_LEAF, code, "receipt", msg, evidence);
}

/* The receipt of a bundle that passed every check, signed and written to a
 * path that did not exist. */
static void dlr_attest_write(const struct dlr_offer *o, const char *path,
                             struct zcl_command_reply *reply)
{
    struct dlr_receipt t;
    struct json_value doc;
    const char *why = NULL;
    bool ok;
    memset(&t, 0, sizeof(t));
    (void)snprintf(t.commit, sizeof(t.commit), "%s", o->commit);
    (void)snprintf(t.base, sizeof(t.base), "%s", o->base);
    (void)snprintf(t.bsha, sizeof(t.bsha), "%s", o->bsha);
    (void)snprintf(t.checks, sizeof(t.checks), "%s", DLR_RECEIPT_CHECKS);
    (void)snprintf(t.verdict, sizeof(t.verdict), "%s", DLR_RECEIPT_VERDICT);
    if (!dlr_receipt_sign(&t, &why)) {
        dlr_attest_fail(reply, "OFFER_RECEIPT_FAILED",
                        "this box's signing key could not sign the receipt",
                        why ? why : "signer_arguments_invalid");
        return;
    }
    json_init(&doc);
    json_set_object(&doc);
    ok = json_push_kv_str(&doc, "schema", DLR_RECEIPT_SCHEMA) &&
         json_push_kv_str(&doc, "commit", t.commit) &&
         json_push_kv_str(&doc, "base", t.base) &&
         json_push_kv_str(&doc, "bundle_sha256", t.bsha) &&
         json_push_kv_str(&doc, "checks", t.checks) &&
         json_push_kv_str(&doc, "verdict", t.verdict) &&
         json_push_kv_str(&doc, "signer", t.signer) &&
         json_push_kv_str(&doc, "signature", t.sig) &&
         dlr_json_write_new(&doc, path);
    json_free(&doc);
    if (!ok) {
        dlr_attest_fail(reply, "OFFER_RECEIPT_FAILED",
                        "cannot write the receipt", path);
        return;
    }
    dlr_offer_ok(o, reply);
    (void)json_push_kv_str(&reply->data, "receipt", path);
    (void)json_push_kv_str(&reply->data, "signer", t.signer);
}

/* Runs exactly the check_offer checks; only a pass writes a receipt. */
static void dlr_attest_offer(const struct zcl_command_request *req,
                             struct zcl_command_reply *reply)
{
    struct dlr_offer *o;
    const char *out = dlr_str(req, "receipt_out");
    if (!out || !platform_path_is_absolute(out)) {
        dlr_offer_fail(DLR_ATTEST_LEAF, reply, "OFFER_BAD_ARGUMENT", "input",
                       "receipt_out must be an absolute path",
                       out ? out : "input.receipt_out missing");
        return;
    }
    o = dlr_offer_checked(req, reply, DLR_ATTEST_LEAF);
    if (!o)
        return;
    if (dlr_exists(out))
        dlr_attest_fail(reply, "OFFER_RECEIPT_EXISTS",
                        "receipt_out already exists; it is never replaced",
                        out);
    else
        dlr_attest_write(o, out, reply);
    free(o);
}

static void dlr_verify_fail(struct zcl_command_reply *reply, const char *code,
                            const char *msg, const char *evidence)
{
    dlr_fail(reply, DLR_VERIFY_LEAF, code, "receipt", msg, evidence);
}

/* The receipt's fields: right schema, 40/64-hex ids, the v1 checks list, an
 * ok verdict, and signer and signature as lowercase hex of the right size. */
static bool dlr_receipt_strs(const struct json_value *doc,
                             struct dlr_receipt *t)
{
    char schema[48];
    return dlr_offer_str(doc, "schema", schema, sizeof(schema)) &&
           strcmp(schema, DLR_RECEIPT_SCHEMA) == 0 &&
           dlr_offer_str(doc, "commit", t->commit, sizeof(t->commit)) &&
           dlr_offer_str(doc, "base", t->base, sizeof(t->base)) &&
           dlr_offer_str(doc, "bundle_sha256", t->bsha, sizeof(t->bsha)) &&
           dlr_offer_str(doc, "checks", t->checks, sizeof(t->checks)) &&
           dlr_offer_str(doc, "verdict", t->verdict, sizeof(t->verdict)) &&
           dlr_offer_str(doc, "signer", t->signer, sizeof(t->signer)) &&
           dlr_offer_str(doc, "signature", t->sig, sizeof(t->sig));
}

static bool dlr_receipt_fields(const struct json_value *doc,
                               struct dlr_receipt *t)
{
    return dlr_receipt_strs(doc, t) && dlr_hex_n(t->commit, 40) &&
           dlr_hex_n(t->base, 40) && dlr_hex_n(t->bsha, 64) &&
           strcmp(t->checks, DLR_RECEIPT_CHECKS) == 0 &&
           strcmp(t->verdict, DLR_RECEIPT_VERDICT) == 0 &&
           zcl_hex_decode_lower(t->signer, t->pub, sizeof(t->pub)) &&
           zcl_hex_decode_lower(t->sig, t->sigb, sizeof(t->sigb));
}

static bool dlr_receipt_read(const char *path, struct dlr_receipt *t,
                             struct zcl_command_reply *reply)
{
    struct json_value doc;
    bool ok;
    memset(t, 0, sizeof(*t));
    ok = dlr_json_read_file(path, &doc) && dlr_receipt_fields(&doc, t);
    json_free(&doc);
    if (!ok)
        dlr_verify_fail(reply, "OFFER_RECEIPT_BAD",
                        "not a zcl.dev_land_offer_receipt.v1 object with the "
                        "v1 checks, verdict ok and hex signer and signature",
                        path);
    return ok;
}

/* The signature through the box's signer: its own key, or one on its
 * signers.allow list. */
static bool dlr_receipt_verify(const struct dlr_receipt *t,
                               struct zcl_command_reply *reply)
{
    char msg[512];
    size_t n = dlr_receipt_msg(t, msg, sizeof(msg));
    const char *why = NULL;
    if (n > 0 && zcl_dev_proof_signer_verify((const uint8_t *)msg, n, t->pub,
                                             t->sigb, &why))
        return true;
    if (why && strcmp(why, ZCL_DEV_PROOF_SIGNER_WHY_SIGNER_UNKNOWN) == 0)
        dlr_verify_fail(reply, "RECEIPT_SIGNER_UNKNOWN",
                        "the signer is not this box's key and not on its "
                        "signers.allow list",
                        t->signer);
    else
        dlr_verify_fail(reply, "RECEIPT_SIGNATURE_INVALID",
                        "the signature does not verify over the receipt "
                        "fields",
                        why ? why : "signature_invalid");
    return false;
}

/* --offer: the receipt must be about this offer's commit, base and sha. */
static bool dlr_receipt_matches(const struct dlr_receipt *t, const char *offer,
                                struct zcl_command_reply *reply)
{
    struct dlr_offer *o = zcl_calloc(1, sizeof(*o), "dev_land_remote.offer");
    bool ok;
    o->leaf = DLR_VERIFY_LEAF;
    ok = dlr_offer_read(offer, o, reply);
    if (ok && (strcmp(o->commit, t->commit) != 0 ||
               strcmp(o->base, t->base) != 0 ||
               strcmp(o->bsha, t->bsha) != 0)) {
        dlr_verify_fail(reply, "RECEIPT_OFFER_MISMATCH",
                        "the receipt names another commit, base or bundle "
                        "sha256 than the offer",
                        offer);
        ok = false;
    }
    free(o);
    return ok;
}

/* Read-only: parses, rebuilds the signed message and verifies it. */
static void dlr_verify_offer_receipt(const struct zcl_command_request *req,
                                     struct zcl_command_reply *reply)
{
    struct dlr_receipt t;
    const char *path = dlr_str(req, "receipt");
    const char *offer = dlr_str(req, "offer");
    if (!path) {
        dlr_verify_fail(reply, "OFFER_BAD_ARGUMENT", "receipt must name a file",
                        "input.receipt missing");
        return;
    }
    if (!dlr_receipt_read(path, &t, reply) || !dlr_receipt_verify(&t, reply) ||
        (offer && !dlr_receipt_matches(&t, offer, reply)))
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DLR_VERIFY_LEAF);
    (void)json_push_kv_str(&reply->data, "commit", t.commit);
    (void)json_push_kv_str(&reply->data, "base", t.base);
    (void)json_push_kv_str(&reply->data, "signer", t.signer);
    (void)json_push_kv_str(&reply->data, "verdict", t.verdict);
    (void)json_push_kv_str(&reply->data, "checks", t.checks);
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
    else if (path && strcmp(path, DLR_CHECK_LEAF) == 0)
        dlr_check_offer(req, reply);
    else if (path && strcmp(path, DLR_ATTEST_LEAF) == 0)
        dlr_attest_offer(req, reply);
    else if (path && strcmp(path, DLR_VERIFY_LEAF) == 0)
        dlr_verify_offer_receipt(req, reply);
    else
        dlr_fail(reply, "dev.land.remote", "UNKNOWN_LEAF", "route",
                 "this handler serves dev.land.send, dev.land.receive, "
                 "dev.land.check_offer, dev.land.attest_offer and "
                 "dev.land.verify_offer_receipt",
                 path ? path : "no leaf resolved");
}
