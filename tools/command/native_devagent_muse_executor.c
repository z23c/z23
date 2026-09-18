/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: C's production executor for A's resident worker loop. This
 * is the ONLY Muse entry the worker drives: it adapts one claimed
 * wkr_job to one bounded muse_run_task and maps the structured result
 * back to wkr_result. It owns no queue, no ledger, no scheduler, and
 * no lifecycle state: claim/attempt/retry, the gate predicate, reap,
 * and result mail all stay in native_devagent_worker.c, which calls
 * this function through the wkr_executor_fn seam (never the reverse).
 *
 * TASK CARRIER. The worker hands executor-ready text: identity lines
 * plus the whole brief (a brief that does not fit the task buffer is
 * refused by the worker, never cut). Muse direction rides a machine
 * header at the TOP of the brief file:
 *
 *   muse-workspace: /abs/path/to/worktree
 *   muse-scope: src/
 *   muse-gate: group_name
 *   muse-model: model-id-or-empty
 *
 *   <free prose prompt for the model...>
 *
 * Missing or malformed direction refuses WITHOUT spawning any host:
 * the result carries terminal "refused" through the normal channel.
 *
 * BOUNDS. job->token_cap (<=0 refuses: no unbounded runs) becomes the
 * MSP at-most-N cap. The wall cap splits 80/15: the turn gets
 * (cap-10)s with a 5s floor so a timeout verdict pre-empts the
 * worker's SIGKILL; the gate gets the rest. Caps under 30s refuse:
 * a model turn cannot honestly fit.
 *
 * SILENCE. The child wrapper captures the outcome through
 * executor_result.json, never this process's stdout: stdout is
 * pointed at /dev/null across the call so executor chatter can never
 * pollute the worker's streams. run.out comes from the worker.
 */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_devagent.h"
#include "services/muse_run.h"
#include "base/safe_alloc.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MX_EVIDENCE_MAX 2047

/* The header block ends at the first blank line; the prose prompt below
 * is never parsed for direction. */
static bool mx_header_end(const char *p, size_t len)
{
    return len == 0 || (len == 1 && (p[0] == '\r'));
}

/* True when this line carries "<key>: " or "<key>:\t". */
static bool mx_key_at(const char *p, size_t len, const char *key, size_t kl)
{
    return len > kl + 2 && strncmp(p, key, kl) == 0 && p[kl] == ':' &&
        (p[kl + 1] == ' ' || p[kl + 1] == '\t');
}

/* Copies one header value, trailing blanks trimmed. False when it is
 * empty or does not fit. */
static bool mx_header_value(const char *v, size_t vn, char *out, size_t cap)
{
    while (vn > 0 &&
        (v[vn - 1] == ' ' || v[vn - 1] == '\t' ||
            v[vn - 1] == '\r'))
        vn--;
    if (vn == 0 || vn >= cap) return false;
    memcpy(out, v, vn);
    out[vn] = '\0';
    return true;
}

/* One "muse-key: value" header line at a line start; value trimmed of
 * trailing blanks. False when the key is absent. */
static bool mx_header_line(const char *task, const char *key, char *out,
    size_t cap)
{
    size_t kl = strlen(key);
    const char *p = task;
    if (!task || !key || !out || cap == 0) return false;
    for (;;) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        if (mx_header_end(p, len)) return false;
        if (mx_key_at(p, len, key, kl))
            return mx_header_value(p + kl + 2, len - (kl + 2), out, cap);
        if (!eol) return false;
        p = eol + 1;
    }
}

/* The prompt is everything after the header block's blank line. */
static const char *mx_prompt(const char *task)
{
    const char *p;
    if (!task) return NULL;
    p = task;
    for (;;) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        if (len == 0) {
            const char *body = eol ? eol + 1 : p + strlen(p);
            while (*body == '\n' || *body == '\r') body++;
            return *body ? body : NULL;
        }
        if (len >= 9 && strncmp(p, "=== BRIEF", 9) == 0) return NULL;
        if (!eol) return NULL;
        p = eol + 1;
    }
}

/* Reads <rundir>/claim.json, bounded at 4 KiB. NULL when unreadable. */
static char *mx_read_claim(const char *rundir)
{
    char path[8192];
    FILE *f;
    char *text;
    long n;
    if (!rundir ||
        snprintf(path, sizeof(path), "%s/claim.json", rundir) >=
        (int)sizeof(path))
        return NULL;
    f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    n = ftell(f);
    if (n <= 0 || n > 4096) {
        fclose(f);
        return NULL;
    }
    (void)fseek(f, 0, SEEK_SET);
    text = zcl_malloc((size_t)n + 1, "devagent_muse.brief");
    if (!text) {
        fclose(f);
        return NULL;
    }
    if (fread(text, 1, (size_t)n, f) != (size_t)n) {
        free(text);
        fclose(f);
        return NULL;
    }
    text[n] = '\0';
    fclose(f);
    return text;
}

/* Copies the value of one flat JSON string field. `pat` is the whole
 * `"key":"` prefix; an absent field leaves out untouched. */
static void mx_json_str(const char *text, const char *pat, char *out,
    size_t cap)
{
    const char *p;
    if (!out || cap == 0) return;
    p = strstr(text, pat);
    if (!p) return;
    {
        const char *v = p + strlen(pat);
        const char *q = strchr(v, '"');
        if (q && (size_t)(q - v) < cap) {
            memcpy(out, v, (size_t)(q - v));
            out[q - v] = '\0';
        }
    }
}

/* Best-effort claim identity for provenance: worker/session out of
 * <rundir>/claim.json. Never blocks a run when unreadable. */
static void mx_claim_who(const char *rundir, char *worker, size_t wcap,
    char *session, size_t scap)
{
    char *text;
    if (worker && wcap > 0) worker[0] = '\0';
    if (session && scap > 0) session[0] = '\0';
    text = mx_read_claim(rundir);
    if (!text) return;
    mx_json_str(text, "\"worker\":\"", worker, wcap);
    mx_json_str(text, "\"session\":\"", session, scap);
    free(text);
}

static bool mx_dir_ok(const char *path)
{
    struct stat st;
    return path && path[0] && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Fill a refused outcome through the normal channel (the worker still
 * writes run.out + receipt + mail for it). Always true: the executor
 * ran and the refusal is the result. */
static bool mx_refuse(struct wkr_result *res, const char *reason)
{
    if (!res) return false;
    memset(res, 0, sizeof(*res));
    (void)snprintf(res->terminal, sizeof(res->terminal), "refused");
    res->rc = 1;
    if (reason)
        (void)snprintf(res->evidence, sizeof(res->evidence), "%s",
            reason);
    return true;
}

/* The direction block plus the bounds. Returns the refusal reason, or
 * NULL when the job can be attempted. Every refusal named here happens
 * before any host is spawned. */
static const char *mx_direction(const struct wkr_job *job, char *workspace,
    size_t wscap, char *scope, size_t scap, char *gate, size_t gcap,
    char *model, size_t mcap, const char **prompt)
{
    if (!mx_dir_ok(job->rundir))
        return "refused: rundir is not a directory";
    if (!mx_header_line(job->task, "muse-workspace", workspace, wscap))
        return "refused: brief carries no muse-workspace line";
    if (workspace[0] != '/' || !mx_dir_ok(workspace))
        return "refused: muse-workspace is not an absolute directory";
    if (!mx_header_line(job->task, "muse-scope", scope, scap))
        return "refused: brief carries no muse-scope line";
    if (!mx_header_line(job->task, "muse-gate", gate, gcap))
        return "refused: brief carries no muse-gate line";
    *prompt = mx_prompt(job->task);
    if (!*prompt)
        return "refused: brief carries no prompt body";
    if (job->token_cap <= 0)
        return "refused: token cap is not positive";
    if (job->time_cap_s < 30)
        return "refused: time cap too small to attempt";
    if (!mx_header_line(job->task, "muse-model", model, mcap)) {
        if (snprintf(model, mcap, "%s", job->model) >= (int)mcap)
            return "refused: model does not fit";
    }
    return NULL;
}

/* Copies the job's identity and direction into the bounded task and
 * splits its budgets. Returns the refusal reason, or NULL when it fit. */
static const char *mx_fill_task(struct muse_run_task *t,
    const struct wkr_job *job, const char *workspace, const char *scope,
    const char *gate, const char *model, const char *prompt,
    const char *cworker)
{
    memset(t, 0, sizeof(*t));
    t->ref.seq = job->seq;
    if (snprintf(t->ref.name, sizeof(t->ref.name), "%s", job->name) >=
        (int)sizeof(t->ref.name))
        return "refused: ref name does not fit";
    t->ref.attempt = job->attempt;
    if (snprintf(t->worker, sizeof(t->worker), "%s", cworker) >=
        (int)sizeof(t->worker))
        return "refused: worker identity does not fit";
    if (snprintf(t->workspace, sizeof(t->workspace), "%s", workspace) >=
        (int)sizeof(t->workspace))
        return "refused: workspace does not fit";
    if (snprintf(t->scope, sizeof(t->scope), "%s", scope) >=
        (int)sizeof(t->scope))
        return "refused: scope does not fit";
    if (snprintf(t->gate, sizeof(t->gate), "%s", gate) >=
        (int)sizeof(t->gate))
        return "refused: gate does not fit";
    if (snprintf(t->model, sizeof(t->model), "%s", model) >=
        (int)sizeof(t->model))
        return "refused: model does not fit";
    t->prompt = prompt;
    if (snprintf(t->rundir, sizeof(t->rundir), "%s", job->rundir) >=
        (int)sizeof(t->rundir))
        return "refused: rundir does not fit";
    /* 80/15 split of the wall cap: the turn verdict pre-empts the
     * worker's SIGKILL so a timeout reports instead of vanishing. */
    t->budgets.turn_timeout_ms = (int64_t)(job->time_cap_s - 10) * 1000;
    if (t->budgets.turn_timeout_ms < 5000)
        t->budgets.turn_timeout_ms = 5000;
    t->budgets.gate_timeout_ms = (int)(job->time_cap_s * 150);
    if (t->budgets.gate_timeout_ms < 2000)
        t->budgets.gate_timeout_ms = 2000;
    t->budgets.max_total_tokens = (uint64_t)job->token_cap;
    t->caller_holds_claim = true;
    return NULL;
}

/* Runs the task with this process's stdout pointed at /dev/null: the
 * child wrapper owns the outcome file, so executor chatter must never
 * reach the worker's streams. */
static int mx_run_silent(const struct muse_run_task *t,
    struct muse_run_result *mres, char err[MUSE_RUN_ERROR_MAX])
{
    int devnull = open("/dev/null", O_WRONLY);
    int saved_out = -1;
    int rc;
    if (devnull >= 0) {
        saved_out = dup(STDOUT_FILENO);
        (void)dup2(devnull, STDOUT_FILENO);
        close(devnull);
    }
    memset(mres, 0, sizeof(*mres));
    err[0] = '\0';
    rc = muse_run_task(t, mres, err);
    if (saved_out >= 0) {
        (void)dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    return rc;
}

/* The recorded value, or the stand-in for an absent reading. */
static const char *mx_or(const char *value, const char *absent)
{
    return value[0] ? value : absent;
}

/* The provenance block the result row carries: one key=value line per
 * recorded fact, with "-" or "none" standing in for an absent reading. */
static void mx_evidence(struct wkr_result *res,
    const struct muse_run_result *mres, const char *err)
{
    char evidence[MX_EVIDENCE_MAX + 1];
    int w = snprintf(evidence, sizeof(evidence),
        "ref=%lld/%s/%lld\nworker=%s\nverdict=%s\nterminal=%s\n"
        "tokens=%llu\nfiles=%lld\nbase=%.12s\ncandidate=%s\ngate=%s\n"
        "gate_evidence=%s\nmodel=%s\nsession=%s\nturn=%s\nwall_ms=%lld\n"
        "workspace_restored=%s\nworkspace_restore=%.160s\n"
        "reason=%s\n",
        mres->ref.seq, mres->ref.name, mres->ref.attempt,
        mx_or(mres->worker, "-"),
        mx_or(mres->verdict, "refused"),
        mx_or(mres->terminal, "none"),
        (unsigned long long)mres->total_tokens, mres->files_changed,
        mx_or(mres->base, "none"),
        mx_or(mres->candidate_file, "none"),
        mx_or(mres->gate, "-"),
        mx_or(mres->gate_evidence, "-"),
        mx_or(mres->model_resolved, "-"),
        mx_or(mres->session, "-"),
        mx_or(mres->turn, "-"),
        mres->wall_ms,
        mres->workspace_restored ? "true" : "false",
        mx_or(mres->workspace_restore, "-"),
        mx_or(mres->reason, mx_or(err, "-")));
    if (w > 0)
        (void)snprintf(res->evidence, sizeof(res->evidence), "%s",
            evidence);
}

bool zcl_devagent_worker_muse_executor(const struct wkr_job *job,
    struct wkr_result *res)
{
    char workspace[4096], scope[512], gate[128], model[160];
    const char *prompt = NULL;
    const char *refusal;
    char cworker[64], csession[64];
    struct muse_run_task t;
    struct muse_run_result mres;
    char err[MUSE_RUN_ERROR_MAX];
    int rc;
    if (!job || !res) return false;
    memset(res, 0, sizeof(*res));
    refusal = mx_direction(job, workspace, sizeof(workspace), scope,
        sizeof(scope), gate, sizeof(gate), model, sizeof(model), &prompt);
    if (refusal) return mx_refuse(res, refusal);
    mx_claim_who(job->rundir, cworker, sizeof(cworker), csession,
        sizeof(csession));
    refusal = mx_fill_task(&t, job, workspace, scope, gate, model, prompt,
        cworker);
    if (refusal) return mx_refuse(res, refusal);
    rc = mx_run_silent(&t, &mres, err);
    if (csession[0])
        (void)snprintf(mres.worker_session, sizeof(mres.worker_session),
            "%s", csession);
    (void)snprintf(res->terminal, sizeof(res->terminal), "%s",
        mres.verdict[0] ? mres.verdict : "refused");
    res->rc = rc == 0 ? 0 : 1;
    if (mres.candidate_file[0])
        (void)snprintf(res->candidate, sizeof(res->candidate), "%s",
            mres.candidate_file);
    res->tokens_used = (long long)mres.total_tokens;
    res->wall_ms = mres.wall_ms;
    mx_evidence(res, &mres, err);
    return true;
}
