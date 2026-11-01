/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land.reverify_offer --check=verify: the general re-verification of ANY
 * offered commit (native_dev_land_offer.c keeps the complexity-split mode,
 * --check=cx, byte-identical and calls in here for the rest).
 *
 * In the scratch worktree reverify_offer already made (a detached worktree at
 * the offered base, under a private temp directory), the offered commit is
 * cherry-picked as a REAL commit (so `ONLY=@changed` sees it; REVERIFY_APPLY
 * on a conflict) and the focused proof the land queue uses runs there as one
 * child: `make agent-verify ONLY=@changed`, which already includes the fast
 * lint step. The child goes through the host admission rail: the program
 * named by ZCL_LAND_REVERIFY_RUNNER (ZCL_TESTING builds only, the fake the
 * tests use), else `devbuild` when it is on PATH
 * (`devbuild --wait --project z23 make agent-verify ONLY=@changed`), else
 * `make` directly. The child runs in the scratch worktree and nowhere else,
 * with stdout and stderr merged. Its wall time is bounded by --timeout_s
 * (default 3600, 1..86400); on timeout its whole process group is killed.
 *
 * Trust: fetched code executes only inside this bounded build/test child,
 * under this box's local policy (the host rail, the time bound, the scratch
 * worktree that is always removed). Offers come only from allowlisted
 * authors, as for every other reverify_offer mode. This is not a sandbox.
 *
 * Refusals: REVERIFY_APPLY (the commit does not apply on its base),
 * REVERIFY_VERIFY_FAILED (the child's exit and the tail of its output as
 * evidence), REVERIFY_VERIFY_TIMEOUT (the bound that was hit), REVERIFY_SETUP
 * (the child could not be started). A bad --check or --timeout_s is
 * OFFER_BAD_ARGUMENT (reverify_offer) or QUALIFY_BAD_ARGUMENT
 * (qualify_offer). A pass is signed with checks
 * "bundle_sha256,bundle_verify,head,base,agent_verify".
 */

#include "command/native_dev_land_remote_shared.h"

#include "base/safe_alloc.h"
#include "util/spawn.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DLRV_OUT_MAX (256u * 1024u)
#define DLRV_TAIL 400u
#define DLRV_TIMEOUT_DEFAULT_S 3600
#define DLRV_TIMEOUT_MAX_S 86400
#define DLRV_GIT_MS (10 * 60 * 1000)

/* --check: absent or "cx" is false (the split mode), "verify" is true;
 * anything else refuses with `code`. */
bool zcl_dlr_check_arg(const struct zcl_command_request *req, const char *leaf,
                       const char *code, bool *verify,
                       struct zcl_command_reply *reply)
{
    const char *c = zcl_dlr_str(req, "check");
    *verify = false;
    if (!c || strcmp(c, "cx") == 0)
        return true;
    if (strcmp(c, "verify") == 0) {
        *verify = true;
        return true;
    }
    zcl_dlr_fail(reply, leaf, code, "input", "check is cx or verify", c);
    return false;
}

/* --timeout_s: an integer 1..86400, default 3600. */
bool zcl_dlr_timeout_arg(const struct zcl_command_request *req,
                         const char *leaf, int *secs,
                         struct zcl_command_reply *reply)
{
    const struct json_value *t = req->input ? json_get(req->input, "timeout_s")
                                            : NULL;
    *secs = DLRV_TIMEOUT_DEFAULT_S;
    if (!t)
        return true;
    if (t->type == JSON_INT && json_get_int(t) >= 1 &&
        json_get_int(t) <= DLRV_TIMEOUT_MAX_S) {
        *secs = (int)json_get_int(t);
        return true;
    }
    zcl_dlr_fail(reply, leaf, "OFFER_BAD_ARGUMENT", "input",
                 "timeout_s is an integer 1..86400", "input.timeout_s");
    return false;
}

/* The offered commit as a real commit on the scratch worktree's detached
 * base. A fixed identity and no hooks, so nothing of the host's leaks in. */
static bool dlrv_apply(const char *wt, const char *commit, const char *leaf,
                       struct zcl_command_reply *reply)
{
    const char *cp[] = {"-c",
                        "user.name=z23-reverify",
                        "-c",
                        "user.email=reverify@invalid",
                        "-c",
                        "commit.gpgsign=false",
                        "-c",
                        "core.hooksPath=/dev/null",
                        "cherry-pick",
                        commit,
                        NULL};
    char sink[1024];
    if (zcl_native_dev_land_git(wt, cp, sink, sizeof(sink), DLRV_GIT_MS) == 0)
        return true;
    zcl_dlr_fail(reply, leaf, "REVERIFY_APPLY", "apply",
                 "the offered commit does not apply cleanly on its base",
                 commit);
    return false;
}

/* Whether `name` is an executable file in a PATH directory. */
static bool dlrv_on_path(const char *name)
{
    const char *path = getenv("PATH");
    char dir[1024], file[1100];
    while (path && *path) {
        size_t n = strcspn(path, ":");
        if (n > 0 && n < sizeof(dir)) {
            (void)snprintf(dir, sizeof(dir), "%.*s", (int)n, path);
            if (snprintf(file, sizeof(file), "%s/%s", dir, name) <
                    (int)sizeof(file) &&
                access(file, X_OK) == 0)
                return true;
        }
        path += n + (path[n] ? 1 : 0);
    }
    return false;
}

/* The admission rail program, or NULL for a direct make. */
static const char *dlrv_rail(void)
{
#if defined(ZCL_TESTING)
    const char *p = getenv("ZCL_LAND_REVERIFY_RUNNER");
    if (p && p[0])
        return p;
#endif
    return dlrv_on_path("devbuild") ? "devbuild" : NULL;
}

/* Control bytes to spaces, so the evidence is one printable line. */
static void dlrv_tail(const char *text, char *out, size_t cap)
{
    size_t n = strlen(text), from = n > DLRV_TAIL ? n - DLRV_TAIL : 0, i;
    for (i = 0; from + i < n && i + 1 < cap; i++) {
        unsigned char c = (unsigned char)text[from + i];
        out[i] = c < 0x20 || c == 0x7f ? ' ' : (char)c;
    }
    out[i] = '\0';
}

static bool dlrv_report(int rc, bool timed_out, const char *text, int secs,
                        const char *leaf, struct zcl_command_reply *reply)
{
    char ev[DLRV_TAIL + 64], tail[DLRV_TAIL + 8];
    dlrv_tail(text, tail, sizeof(tail));
    if (timed_out) {
        (void)snprintf(ev, sizeof(ev), "timeout_s=%d tail=%s", secs, tail);
        zcl_dlr_fail(reply, leaf, "REVERIFY_VERIFY_TIMEOUT", "agent_verify",
                     "make agent-verify ONLY=@changed hit the time bound and "
                     "was killed",
                     ev);
    } else if (rc < 0) {
        zcl_dlr_fail(reply, leaf, "REVERIFY_SETUP", "agent_verify",
                     "could not start the verification child", "spawn");
    } else {
        (void)snprintf(ev, sizeof(ev), "exit=%d tail=%s", rc, tail);
        zcl_dlr_fail(reply, leaf, "REVERIFY_VERIFY_FAILED", "agent_verify",
                     "make agent-verify ONLY=@changed did not pass on the "
                     "offered commit in a scratch worktree",
                     ev);
    }
    return false;
}

/* The focused proof as a bounded child in the scratch worktree. */
static bool dlrv_child(const char *wt, int secs, const char *leaf,
                       struct zcl_command_reply *reply)
{
    const char *rail = dlrv_rail();
    const char *argv[8];
    size_t n = 0;
    bool timed_out = false, pass;
    int rc;
    char *text = zcl_calloc(1, DLRV_OUT_MAX, "dev_land_verify.out");
    if (rail) {
        argv[n++] = rail;
        argv[n++] = "--wait";
        argv[n++] = "--project";
        argv[n++] = "z23";
    }
    argv[n++] = "make";
    argv[n++] = "agent-verify";
    argv[n++] = "ONLY=@changed";
    argv[n] = NULL;
    rc = zcl_spawn_capture_merged_in_dir_observed(argv, wt, text, DLRV_OUT_MAX,
                                                  secs * 1000, &timed_out);
    pass = rc == 0 && !timed_out;
    if (!pass)
        (void)dlrv_report(rc, timed_out, text, secs, leaf, reply);
    free(text);
    return pass;
}

/* Apply, then the proof; false with the refusal in reply. */
bool zcl_dlr_verify_run(const char *wt, const char *commit, int secs,
                        const char *leaf, struct zcl_command_reply *reply)
{
    return dlrv_apply(wt, commit, leaf, reply) &&
           dlrv_child(wt, secs, leaf, reply);
}
