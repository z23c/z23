/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land.reverify_offer --check=verify: the general re-verification of ANY
 * offered commit (native_dev_land_offer.c keeps the complexity-split mode,
 * --check=cx, byte-identical and calls in here for the rest).
 *
 * In the scratch worktree reverify_offer already made (a detached worktree at
 * the offered base, under a private temp directory), the offered commit is
 * cherry-picked as a REAL commit (so `ONLY=@changed` sees it). An offer is
 * exactly one commit: dev.land.send refuses anything but one commit beyond
 * origin/main (SEND_NOT_SINGLE), so this mode takes that and refuses the rest
 * with a typed refusal, REVERIFY_MERGE (a merge commit) or REVERIFY_NOT_SINGLE
 * (any count but one); a conflict is REVERIFY_APPLY. The focused proof the
 * land queue uses then runs
 * as one child: `devbuild --wait --project z23 make -jN agent-verify
 * ONLY=@changed`, which already includes the fast lint step. -jN is
 * platform_build_jobs_arg()'s count (CPUs and memory budget, capped by
 * ZCL_BUILD_MAX_JOBS), as for the land qualify build: without it the
 * top-level make built serially, one or two compiles at a time, and a peer
 * re-verify took 38+ minutes beside a -j28 gate on the same host. The admission
 * rail is mandatory: with no devbuild installed the run refuses
 * REVERIFY_NO_RAIL before anything is applied or built; there is no direct
 * make. Tests reach it only through the zcl_dlr_verify_seam_set() seam.
 * The child runs in the scratch worktree and nowhere else, with stdout and
 * stderr merged. Its wall time is bounded by --timeout_s (default 3600,
 * 1..86400); on timeout its whole process group is killed.
 *
 * Evidence is read from agent-verify's own verdict file in the scratch
 * worktree (build/scratch/agent-verify.rc, truncated at its start, ending in
 * `agent-verify: OK` or `FAILED (...)`), not from a head-truncated capture:
 * a pass needs that last line, and a failure's evidence is that file's tail.
 * `ONLY=@changed` selects against the merge-base of HEAD with origin/main, so
 * the verdict file's selection line must show at least one group and the
 * offered base as its base: REVERIFY_EMPTY_SELECTION or
 * REVERIFY_SELECTION_BASE otherwise, never a pass.
 *
 * Trust: fetched code executes only inside this bounded build/test child,
 * under this box's local policy (the host rail, the time bound, the scratch
 * worktree that is always removed). Offers come only from allowlisted
 * authors, as for every other reverify_offer mode. This is not a sandbox.
 *
 * Refusals: REVERIFY_NO_RAIL, REVERIFY_MERGE, REVERIFY_NOT_SINGLE,
 * REVERIFY_APPLY, REVERIFY_VERIFY_FAILED (the child's exit and the tail of
 * the verdict file as evidence), REVERIFY_VERIFY_TIMEOUT (the bound that was
 * hit), REVERIFY_EMPTY_SELECTION, REVERIFY_SELECTION_BASE, REVERIFY_SETUP
 * (the child could not be started). A bad --check or --timeout_s is
 * OFFER_BAD_ARGUMENT (reverify_offer) or QUALIFY_BAD_ARGUMENT
 * (qualify_offer). A pass is signed with checks
 * "bundle_sha256,bundle_verify,head,base,agent_verify".
 */

#include "command/native_dev_land_remote_shared.h"

#include "base/safe_alloc.h"
#include "platform/logical_cpu.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DLRV_OUT_MAX (256u * 1024u)
#define DLRV_RC "build/scratch/agent-verify.rc"
#define DLRV_RC_MAX (64u * 1024u)
/* with the "exit=N tail=" prefix this fits the 256-byte evidence field */
#define DLRV_TAIL 200u
#define DLRV_TIMEOUT_DEFAULT_S 3600
#define DLRV_TIMEOUT_MAX_S 86400
#define DLRV_GIT_MS (10 * 60 * 1000)

/* --check: absent or "cx" is false (the split mode), "verify" is true;
 * anything else, a non-string or empty value included, refuses with `code`
 * naming input.check. */
bool zcl_dlr_check_arg(const struct zcl_command_request *req, const char *leaf,
                       const char *code, bool *verify,
                       struct zcl_command_reply *reply)
{
    const struct json_value *v =
        req->input ? json_get(req->input, "check") : NULL;
    const char *c = zcl_dlr_str(req, "check");
    *verify = false;
    if (!v)
        return true;
    if (c && strcmp(c, "cx") == 0)
        return true;
    if (c && strcmp(c, "verify") == 0) {
        *verify = true;
        return true;
    }
    zcl_dlr_fail(reply, leaf, code, "input", "check is cx or verify",
                 "input.check");
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

/* The test seam: the child's spawn and the admission rail's name. NULL
 * members are the real ones (zcl_spawn_capture_merged_in_dir_observed and
 * "devbuild"). Only tests set it; the rail is still looked up and refused
 * when absent, so no seam skips the admission check. */
static struct zcl_dlr_verify_seam g_seam;

void zcl_dlr_verify_seam_set(const struct zcl_dlr_verify_seam *seam)
{
    memset(&g_seam, 0, sizeof(g_seam));
    if (seam)
        g_seam = *seam;
}

/* One git call in the scratch worktree: fixed identity, no hooks, so nothing
 * of the host's leaks in. `out` gets the output (NULL: discarded). */
static int dlrv_git(const char *wt, const char *a, const char *b, char *out,
                    size_t cap)
{
    const char *av[] = {"-c",
                        "user.name=z23-reverify",
                        "-c",
                        "user.email=reverify@invalid",
                        "-c",
                        "commit.gpgsign=false",
                        "-c",
                        "core.hooksPath=/dev/null",
                        a,
                        b,
                        NULL,
                        NULL};
    char sink[1024];
    if (!out) {
        out = sink;
        cap = sizeof(sink);
    }
    return zcl_native_dev_land_git(wt, av, out, cap, DLRV_GIT_MS);
}

static long dlrv_count(const char *wt, bool merges_only, const char *range)
{
    const char *av[] = {"rev-list", "--count", range, NULL, NULL};
    char out[64];
    if (merges_only) {
        av[1] = "--merges";
        av[2] = "--count";
        av[3] = range;
    }
    if (zcl_native_dev_land_git(wt, av, out, sizeof(out), DLRV_GIT_MS) != 0)
        return -1;
    return strtol(out, NULL, 10);
}

/* The offered commit as a real commit on the scratch worktree's detached
 * base. Offers carry exactly one commit (dev.land.send refuses anything but
 * one commit beyond origin/main, SEND_NOT_SINGLE), so this refuses what is
 * not one: a merge commit anywhere in base..commit (REVERIFY_MERGE) and any
 * count but one (REVERIFY_NOT_SINGLE). `base` receives the worktree's HEAD,
 * the offered base. */
static bool dlrv_apply(const char *wt, const char *commit, char *base,
                       size_t basecap, const char *leaf,
                       struct zcl_command_reply *reply)
{
    char range[200];
    if (dlrv_git(wt, "rev-parse", "HEAD", base, basecap) != 0) {
        zcl_dlr_fail(reply, leaf, "REVERIFY_SETUP", "apply",
                     "could not read the scratch worktree's base",
                     "rev-parse HEAD");
        return false;
    }
    base[strcspn(base, "\n")] = '\0';
    (void)snprintf(range, sizeof(range), "%s..%s", base, commit);
    if (dlrv_count(wt, true, range) != 0) {
        zcl_dlr_fail(reply, leaf, "REVERIFY_MERGE", "apply",
                     "the offered change contains a merge commit; only a "
                     "single non-merge commit is re-verified",
                     range);
        return false;
    }
    if (dlrv_count(wt, false, range) != 1) {
        zcl_dlr_fail(reply, leaf, "REVERIFY_NOT_SINGLE", "apply",
                     "the offered change is not exactly one commit beyond "
                     "its base; only a single non-merge commit is "
                     "re-verified",
                     range);
        return false;
    }
    if (dlrv_git(wt, "cherry-pick", commit, NULL, 0) == 0)
        return true;
    zcl_dlr_fail(reply, leaf, "REVERIFY_APPLY", "apply",
                 "the offered commit does not apply cleanly on its base",
                 commit);
    return false;
}

/* Whether `name` (a path when it holds a slash) is an executable file in a
 * PATH directory. */
static bool dlrv_on_path(const char *name)
{
    const char *path = getenv("PATH");
    char dir[1024], file[1100];
    if (strchr(name, '/'))
        return access(name, X_OK) == 0;
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

/* The admission rail program, or a typed refusal: an offered commit is never
 * built outside the rail, so there is no direct-make fallback. */
static const char *dlrv_rail(const char *leaf, struct zcl_command_reply *reply)
{
    const char *rail = g_seam.rail ? g_seam.rail : "devbuild";
    if (dlrv_on_path(rail))
        return rail;
    zcl_dlr_fail(reply, leaf, "REVERIFY_NO_RAIL", "agent_verify",
                 "the admission rail (devbuild) is not installed; an offered "
                 "commit is never built outside it",
                 "devbuild");
    return NULL;
}

/* The last DLRV_TAIL bytes of `text`, control bytes to spaces, so the
 * evidence is one printable line. */
static void dlrv_tail(const char *text, char *out, size_t cap)
{
    size_t n = strlen(text), from = n > DLRV_TAIL ? n - DLRV_TAIL : 0, i;
    for (i = 0; from + i < n && i + 1 < cap; i++) {
        unsigned char c = (unsigned char)text[from + i];
        out[i] = c < 0x20 || c == 0x7f ? ' ' : (char)c;
    }
    out[i] = '\0';
}

/* agent-verify's own verdict file in the scratch worktree: it truncates it at
 * the start and appends the selection line, every step's rc and the final
 * `agent-verify: OK` / `FAILED (...)` line, so its end IS the run's end however
 * long the run was. Missing or unreadable: an empty string. */
static void dlrv_verdict(const char *wt, char *out, size_t cap)
{
    char path[1100];
    FILE *f;
    size_t n;
    out[0] = '\0';
    (void)snprintf(path, sizeof(path), "%s/%s", wt, DLRV_RC);
    f = fopen(path, "rb");
    if (!f)
        return;
    n = fread(out, 1, cap - 1, f);
    out[n] = '\0';
    (void)fclose(f);
}

static bool dlrv_last_line_ok(const char *text)
{
    size_t n = strlen(text);
    const char *ok = "agent-verify: OK", *p;
    while (n > 0 && (text[n - 1] == '\n' || text[n - 1] == ' '))
        n--;
    p = text + n;
    while (p > text && p[-1] != '\n')
        p--;
    return (size_t)(text + n - p) == strlen(ok) && memcmp(p, ok, strlen(ok)) == 0;
}

static bool dlrv_report(int rc, bool timed_out, const char *verdict,
                        const char *out, int secs, const char *leaf,
                        struct zcl_command_reply *reply)
{
    char ev[DLRV_TAIL + 64], tail[DLRV_TAIL + 8];
    /* the verdict file's end when there is one, else the captured output */
    dlrv_tail(verdict[0] ? verdict : out, tail, sizeof(tail));
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

/* The selection line agent-verify printed: groups selected and the base it
 * selected against. A pass that selected no group, or against another base
 * than the offered one (it uses the merge-base with origin/main), proved
 * nothing about the offered change. */
static bool dlrv_selection(const char *verdict, const char *base,
                           const char *leaf, struct zcl_command_reply *reply)
{
    const char *line = strstr(verdict, "agent-verify: selection ");
    const char *g = line ? strstr(line, " groups=") : NULL;
    const char *b = line ? strstr(line, " base=") : NULL;
    const char *eol = line ? line + strcspn(line, "\n") : NULL;
    char got[64];
    size_t n;
    if (!g || g > eol || !b || b > eol || strtol(g + 8, NULL, 10) < 1) {
        zcl_dlr_fail(reply, leaf, "REVERIFY_EMPTY_SELECTION", "agent_verify",
                     "agent-verify ONLY=@changed selected no test group for "
                     "the offered change, so a pass proves nothing",
                     line ? "groups=0 or unparsable" : "no selection line");
        return false;
    }
    n = strcspn(b + 6, " \n");
    (void)snprintf(got, sizeof(got), "%.*s", (int)n, b + 6);
    if (strcmp(got, base) != 0) {
        zcl_dlr_fail(reply, leaf, "REVERIFY_SELECTION_BASE", "agent_verify",
                     "agent-verify selected against a base other than the "
                     "offered base, so its groups are not the offered "
                     "change's",
                     got);
        return false;
    }
    return true;
}

/* The focused proof as a bounded child in the scratch worktree. */
static bool dlrv_child(const char *wt, const char *rail, const char *base,
                       int secs, const char *leaf,
                       struct zcl_command_reply *reply)
{
    const char *argv[9];
    size_t n = 0;
    bool timed_out = false, pass;
    int rc;
    char jobs[16] = "-j1"; /* kept when the host count is unknown */
    char path[1100];
    char *text, *verdict;
    text = zcl_calloc(1, DLRV_OUT_MAX, "dev_land_verify.out");
    verdict = zcl_calloc(1, DLRV_RC_MAX, "dev_land_verify.rc");
    if (!text || !verdict) {
        free(verdict);
        free(text);
        zcl_dlr_fail(reply, leaf, "REVERIFY_SETUP", "agent_verify",
                     "could not allocate the verification buffers", "calloc");
        return false;
    }
    argv[n++] = rail;
    argv[n++] = "--wait";
    argv[n++] = "--project";
    argv[n++] = "z23";
    (void)platform_build_jobs_arg(jobs);
    argv[n++] = "make";
    argv[n++] = jobs;
    argv[n++] = "agent-verify";
    argv[n++] = "ONLY=@changed";
    argv[n] = NULL;
    (void)snprintf(path, sizeof(path), "%s/%s", wt, DLRV_RC);
    (void)unlink(path); /* never trust a verdict this run did not write */
    rc = (g_seam.spawn ? g_seam.spawn
                       : zcl_spawn_capture_merged_in_dir_observed)(
        argv, wt, text, DLRV_OUT_MAX, secs * 1000, &timed_out);
    dlrv_verdict(wt, verdict, DLRV_RC_MAX);
    pass = rc == 0 && !timed_out && dlrv_last_line_ok(verdict);
    if (!pass)
        (void)dlrv_report(rc, timed_out, verdict, text, secs, leaf, reply);
    else
        pass = dlrv_selection(verdict, base, leaf, reply);
    free(verdict);
    free(text);
    return pass;
}

/* Apply, then the proof; false with the refusal in reply. */
bool zcl_dlr_verify_run(const char *wt, const char *commit, int secs,
                        const char *leaf, struct zcl_command_reply *reply)
{
    char base[96];
    const char *rail = dlrv_rail(leaf, reply); /* refused before any apply */
    return rail != NULL &&
           dlrv_apply(wt, commit, base, sizeof(base), leaf, reply) &&
           dlrv_child(wt, rail, base, secs, leaf, reply);
}
