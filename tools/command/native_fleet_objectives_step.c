/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet.objectives.step` leaf - decides the self-improving
 *          loop's next action and explains it. Read-only; it launches
 *          nothing. The glue over three existing authorities: the land
 *          queue's rows (zcl_dev_land_rows_read), the objectives snapshots
 *          and their verdict (fleet.objectives.verdict, called in process)
 *          and the work-order logic (fleet.objectives.brief, in process).
 *
 * LOOP LANDINGS. There is no loop ledger. A land row whose note starts with
 * `loop:<objective_id>:` was made by the loop (the land note prefix a loop
 * worker submits with). Everything below keys off that prefix alone.
 *
 * VERDICT PASS. For each landed loop row, newest first, at most 20, the
 * snapshot row at the landing's seq (the land queue appends one per landing)
 * is compared with the newest snapshot row below that seq, and the verdict of
 * the row's own objective is reported: improved, regressed, unchanged or
 * unmeasured (with the reason: no snapshot before or at that seq, or the
 * objective in neither row).
 *
 * PAUSE RULE (stateless). When the newest two landed loop rows both
 * regressed their own objective the action is `paused`, naming both seqs and
 * objective ids. `force: true` overrides it for that one call and the output
 * says so (`forced`); no state file is written or read.
 *
 * IN-FLIGHT RULE. A loop row still queued, proving or otherwise not final in
 * the land queue makes the action `wait`, naming its seq.
 *
 * OTHERWISE the brief runs: a runner_ok top objective is action `run` with
 * the objective, level, a suggested lane name `loop-<objective_id>-<n>` (n is
 * the next land seq), the land note prefix `loop:<objective_id>:` and the
 * brief fields.
 *
 * FALL-THROUGH. A top unmet objective that is not runner_ok is not a dead
 * end: the brief is asked over the runner_ok rows only (its runner_ok_only)
 * and reports the unmet objective it passed over, which the step lists in
 * data.skipped[], so the loop takes the top runnable objective. Only when no runner_ok objective is unmet is the action
 * `none` (the skipped ones are named in the reason).
 *
 * DISPATCH. A `run` also carries data.dispatch = {lane, note_prefix, engine,
 * engine_reason, group, group_reason, task_file, task_text, argv[]}: the work
 * card rendered as the task file engine_unit takes (a `kind:` header, a blank
 * line, prose) and the engine_unit command WITHOUT --yes-dispatch. The step
 * never dispatches, writes no file and creates no lane; an operator writes
 * task_text to task_file and runs argv plus --yes-dispatch. */

#include "command/native_command.h"
#include "command/native_dev_land_read.h"
#include "command/native_fleet_objectives.h"

#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/log_macros.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STP_SCHEMA_OUT "zcl.fleet_objectives_step.v1"
#define STP_LEAF "fleet.objectives.step"
#define STP_PREFIX "loop:"
#define STP_MAX_LANDED 20u
#define STP_ID_MAX 64u
#define STP_PATH_MAX 4352u

struct stp_landed {
    long long seq;
    char objective[STP_ID_MAX];
};

struct stp_scan {
    struct stp_landed landed[STP_MAX_LANDED]; /* newest first */
    size_t n_landed;
    long long inflight_seq; /* 0: none; else the lowest loop seq in flight */
    char inflight_state[16];
    char inflight_objective[STP_ID_MAX];
    long long max_seq;
};

struct stp_verdict {
    long long seq;
    char objective[STP_ID_MAX];
    char verdict[16];
    char reason[200];
};

struct stp_decision {
    const char *action;
    char reason[320];
    bool paused, forced;
    struct json_value next;
    struct json_value skipped;  /* array of {objective, reason} */
    struct json_value dispatch; /* object on run, else JSON_NULL */
};

struct stp_buf {
    char *out;
    size_t left;
};

/* The string at key, or NULL when absent or not a string (json_get_str
 * yields "" for those). */
static const char *stp_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

/* ── land rows ────────────────────────────────────────────────────────── */

/* True, with the objective id, when the note carries `loop:<id>:`. */
static bool stp_note_objective(const char *note, char *out, size_t cap)
{
    const char *p = note + strlen(STP_PREFIX);
    size_t n = 0;
    if (strncmp(note, STP_PREFIX, strlen(STP_PREFIX)) != 0)
        return false;
    while (p[n] && p[n] != ':' && n + 1 < cap)
        n++;
    if (n == 0 || p[n] != ':')
        return false;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static bool stp_final_state(const char *state)
{
    static const char *const fin[] = {"landed", "failed", "conflict",
                                      "cancelled", "fenced"};
    for (size_t i = 0; i < sizeof(fin) / sizeof(fin[0]); i++)
        if (strcmp(state, fin[i]) == 0)
            return true;
    return false;
}

/* Keeps the newest STP_MAX_LANDED distinct landed loop rows, newest first. */
static void stp_add_landed(struct stp_scan *sc, long long seq, const char *id)
{
    size_t at = 0;
    while (at < sc->n_landed && sc->landed[at].seq > seq)
        at++;
    if (at < sc->n_landed && sc->landed[at].seq == seq)
        return;
    if (at >= STP_MAX_LANDED)
        return;
    if (sc->n_landed < STP_MAX_LANDED)
        sc->n_landed++;
    memmove(&sc->landed[at + 1], &sc->landed[at],
            (sc->n_landed - at - 1u) * sizeof(sc->landed[0]));
    sc->landed[at].seq = seq;
    (void)snprintf(sc->landed[at].objective, STP_ID_MAX, "%s", id);
}

static void stp_add_inflight(struct stp_scan *sc,
                             const struct zcl_dl_row_view *r, const char *id)
{
    if (sc->inflight_seq != 0 && sc->inflight_seq <= r->seq)
        return;
    sc->inflight_seq = r->seq;
    (void)snprintf(sc->inflight_state, sizeof(sc->inflight_state), "%s",
                   r->state);
    (void)snprintf(sc->inflight_objective, STP_ID_MAX, "%s", id);
}

static void stp_scan_rows(struct stp_scan *sc,
                          const struct zcl_dl_row_view *rows, size_t n)
{
    char id[STP_ID_MAX];
    for (size_t i = 0; i < n; i++) {
        if (rows[i].seq > sc->max_seq)
            sc->max_seq = rows[i].seq;
        if (!stp_note_objective(rows[i].note, id, sizeof(id)))
            continue;
        if (strcmp(rows[i].state, "landed") == 0)
            stp_add_landed(sc, rows[i].seq, id);
        else if (!stp_final_state(rows[i].state))
            stp_add_inflight(sc, &rows[i], id);
    }
}

/* ── verdicts ─────────────────────────────────────────────────────────── */

static void stp_unmeasured(struct stp_verdict *v, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void stp_unmeasured(struct stp_verdict *v, const char *fmt, ...)
{
    va_list ap;
    (void)snprintf(v->verdict, sizeof(v->verdict), "unmeasured");
    va_start(ap, fmt);
    (void)vsnprintf(v->reason, sizeof(v->reason), fmt, ap);
    va_end(ap);
}

/* The newest snapshot seq below `seq` (-1: none) and whether `seq` is there. */
static int64_t stp_neighbours(const int64_t *seqs, size_t n, long long seq,
                              bool *exact)
{
    int64_t before = -1;
    *exact = false;
    for (size_t i = 0; i < n; i++) {
        if (seqs[i] == seq)
            *exact = true;
        else if (seqs[i] < seq && seqs[i] > before)
            before = seqs[i];
    }
    return before;
}

/* Runs another leaf in process through the registry, the way the dispatcher
 * does: the step hands it a private input object, never its own. False when
 * the catalog has no such ready leaf. */
static bool stp_call(const char *path, struct zcl_command_request *req,
                     struct zcl_command_reply *rep)
{
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    if (!spec || !spec->handler)
        return false;
    req->spec = spec;
    spec->handler(req, rep);
    return true;
}

/* The verdict leaf's own input object, filled for one landing. */
static bool stp_verdict_args(struct json_value *obj, const char *path,
                             int64_t before, long long after, const char *oid)
{
    json_set_object(obj);
    return json_push_kv_str(obj, "snapshot", path) &&
           json_push_kv_int(obj, "before_seq", before) &&
           json_push_kv_int(obj, "after_seq", after) &&
           json_push_kv_str(obj, "id", oid);
}

/* Runs fleet.objectives.verdict in process for the two seqs and the row's
 * own objective, and copies its verdict (or its refusal as unmeasured). */
static void stp_ask_verdict(const char *path, int64_t before, long long after,
                            struct stp_verdict *v)
{
    struct json_value in;
    struct zcl_command_request req;
    struct zcl_command_reply rep;
    const struct json_value *e;
    const char *verdict;
    bool ok;
    json_init(&in);
    memset(&req, 0, sizeof(req));
    memset(&rep, 0, sizeof(rep));
    ok = stp_verdict_args(&in, path, before, after, v->objective);
    req.input = &in;
    if (!ok) {
        stp_unmeasured(v, "out of memory building the verdict request");
    } else {
        if (!stp_call("fleet.objectives.verdict", &req, &rep))
            rep.status = ZCL_COMMAND_STATUS_FAILED;
        e = json_at(json_get(&rep.data, "objectives"), 0);
        verdict = e ? stp_str(e, "verdict") : NULL;
        if (rep.status != ZCL_COMMAND_STATUS_PASSED || !verdict)
            stp_unmeasured(v, "%.180s", rep.error.message);
        else {
            (void)snprintf(v->verdict, sizeof(v->verdict), "%s", verdict);
            (void)snprintf(v->reason, sizeof(v->reason), "%.190s",
                           stp_str(e, "reason") ? stp_str(e, "reason") : "");
        }
    }
    zcl_command_reply_free(&rep);
    json_free(&in);
}

static void stp_judge(const char *path, const int64_t *seqs, size_t n,
                      const struct stp_landed *l, struct stp_verdict *v)
{
    bool exact;
    int64_t before = stp_neighbours(seqs, n, l->seq, &exact);
    memset(v, 0, sizeof(*v));
    v->seq = l->seq;
    (void)snprintf(v->objective, sizeof(v->objective), "%s", l->objective);
    if (before < 0)
        stp_unmeasured(v, "no snapshot row before seq %lld", l->seq);
    else if (!exact)
        stp_unmeasured(v, "no snapshot row at seq %lld", l->seq);
    else
        stp_ask_verdict(path, before, l->seq, v);
}

static bool stp_regressed(const struct stp_verdict *v)
{
    return strcmp(v->verdict, "regressed") == 0;
}

/* Fills out[0..n_landed); false, with the reply filled, when the snapshot
 * file cannot be read. */
static bool stp_verdicts(const struct zcl_command_request *request,
                         const struct stp_scan *sc, struct stp_verdict *out,
                         struct zcl_command_reply *reply)
{
    char path[STP_PATH_MAX];
    int64_t *seqs = NULL;
    size_t n = 0;
    if (sc->n_landed == 0)
        return true;
    if (!zcl_objectives_snapshot_path(request, path, sizeof(path), reply))
        return false;
    if (!zcl_objectives_snapshot_seqs(path, &seqs, &n, NULL)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "SNAPSHOT_READ",
                               "decide", false, false,
                               "cannot read the objectives snapshot file", "");
        return false;
    }
    for (size_t i = 0; i < sc->n_landed; i++)
        stp_judge(path, seqs, n, &sc->landed[i], &out[i]);
    free(seqs);
    return true;
}

/* ── decision ─────────────────────────────────────────────────────────── */

static bool stp_flag(const struct zcl_command_request *request, const char *key)
{
    const struct json_value *v =
        (request && request->input) ? json_get(request->input, key) : NULL;
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static bool stp_push_str_item(struct json_value *arr, const char *s)
{
    struct json_value item;
    bool ok;
    json_init(&item);
    json_set_str(&item, s);
    ok = json_push_back(arr, &item);
    json_free(&item);
    return ok;
}

static bool stp_push_int_item(struct json_value *arr, int64_t n)
{
    struct json_value item;
    bool ok;
    json_init(&item);
    json_set_int(&item, n);
    ok = json_push_back(arr, &item);
    json_free(&item);
    return ok;
}

/* next = {seqs[2], objectives[2]}: the two regressed loop landings. */
static bool stp_paused_next(struct stp_decision *d, const struct stp_verdict *v)
{
    struct json_value seqs, ids;
    bool ok;
    json_init(&seqs);
    json_set_array(&seqs);
    json_init(&ids);
    json_set_array(&ids);
    ok = stp_push_int_item(&seqs, v[0].seq) &&
         stp_push_int_item(&seqs, v[1].seq) &&
         stp_push_str_item(&ids, v[0].objective) &&
         stp_push_str_item(&ids, v[1].objective) &&
         json_push_kv(&d->next, "seqs", &seqs) &&
         json_push_kv(&d->next, "objectives", &ids);
    json_free(&seqs);
    json_free(&ids);
    return ok;
}

static bool stp_decide_paused(struct stp_decision *d,
                              const struct stp_verdict *v, size_t n,
                              bool force)
{
    if (n < 2 || !stp_regressed(&v[0]) || !stp_regressed(&v[1]))
        return true;
    (void)snprintf(d->reason, sizeof(d->reason),
                   "the newest two loop landings both regressed their own "
                   "objective: seq %lld (%s) and seq %lld (%s)",
                   v[0].seq, v[0].objective, v[1].seq, v[1].objective);
    if (force) {
        d->forced = true;
        return true;
    }
    d->paused = true;
    d->action = "paused";
    return stp_paused_next(d, v);
}

static bool stp_decide_wait(struct stp_decision *d, const struct stp_scan *sc)
{
    if (sc->inflight_seq == 0)
        return false;
    d->action = "wait";
    (void)snprintf(d->reason, sizeof(d->reason),
                   "loop row seq %lld (%s) is %s in the land queue",
                   sc->inflight_seq, sc->inflight_objective,
                   sc->inflight_state);
    return true;
}

static bool stp_wait_next(struct stp_decision *d, const struct stp_scan *sc)
{
    return json_push_kv_int(&d->next, "seq", sc->inflight_seq) &&
           json_push_kv_str(&d->next, "state", sc->inflight_state) &&
           json_push_kv_str(&d->next, "objective", sc->inflight_objective);
}

/* ── brief ────────────────────────────────────────────────────────────── */

static bool stp_build_dispatch(struct stp_decision *d,
                               const struct json_value *card);

static bool stp_run_next(struct stp_decision *d, const struct json_value *card,
                         long long next_seq)
{
    const struct json_value *obj = json_get(card, "objective");
    const char *id = stp_str(obj, "id");
    const char *level = stp_str(card, "level");
    char lane[160], prefix[96];
    size_t k;
    (void)snprintf(prefix, sizeof(prefix), STP_PREFIX "%s:", id);
    (void)snprintf(lane, sizeof(lane), "loop-%s-%lld", id, next_seq);
    for (k = 0; lane[k]; k++)
        if (lane[k] == '_')
            lane[k] = '-';
    return json_push_kv_str(&d->next, "objective", id) &&
           json_push_kv_str(&d->next, "level", level ? level : "") &&
           json_push_kv_bool(&d->next, "runner_ok",
                             json_get_bool(json_get(obj, "runner_ok"))) &&
           json_push_kv_str(&d->next, "lane", lane) &&
           json_push_kv_str(&d->next, "note_prefix", prefix) &&
           json_push_kv(&d->next, "brief", card);
}

/* Fills d from the brief's reply: run, or none with the reason. False on
 * allocation failure. */
static bool stp_decide_brief(struct stp_decision *d,
                             const struct zcl_command_reply *brief,
                             long long next_seq)
{
    const struct json_value *obj = json_get(&brief->data, "objective");
    const char *none = stp_str(&brief->data, "none");
    const char *id = stp_str(obj, "id");
    if (none || !obj || !id) {
        d->action = "none";
        (void)snprintf(d->reason, sizeof(d->reason), "%.200s%s%.80s%s",
                       none ? none : "the brief named no objective",
                       json_size(&d->skipped) ? " (skipped " : "",
                       json_size(&d->skipped)
                           ? stp_str(json_at(&d->skipped, 0), "objective")
                           : "",
                       json_size(&d->skipped) ? ": not runner_ok)" : "");
        return true;
    }
    if (!json_get_bool(json_get(obj, "runner_ok"))) {
        d->action = "none";
        (void)snprintf(d->reason, sizeof(d->reason),
                       "the top unmet objective %.80s is not runner_ok, so no "
                       "unattended worker may take it", id);
        return true;
    }
    d->action = "run";
    (void)snprintf(d->reason, sizeof(d->reason),
                   "no loop row is in flight and the loop is not paused; the "
                   "top unmet %sobjective %.80s is runner_ok",
                   json_size(&d->skipped) ? "runner_ok " : "", id);
    return stp_run_next(d, &brief->data, next_seq) &&
           stp_build_dispatch(d, &brief->data);
}

/* Copies the brief's `skipped` array (the top objective it passed over
 * because it is not runner_ok) into d->skipped. */
static bool stp_take_skipped(struct stp_decision *d,
                             const struct zcl_command_reply *brief)
{
    const struct json_value *arr = json_get(&brief->data, "skipped");
    for (size_t i = 0; i < json_size(arr); i++)
        if (!json_push_back(&d->skipped, json_at(arr, i)))
            return false;
    return true;
}

/* ── screen ───────────────────────────────────────────────────────────── */

static void stp_put(struct stp_buf *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void stp_put(struct stp_buf *b, const char *fmt, ...)
{
    va_list ap;
    int n;
    if (b->left <= 1u)
        return;
    va_start(ap, fmt);
    n = vsnprintf(b->out, b->left, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if ((size_t)n >= b->left)
        n = (int)(b->left - 1u);
    b->out += n;
    b->left -= (size_t)n;
}

/* ── dispatch ─────────────────────────────────────────────────────────── */

/* The prompt kind the task file declares. engine_unit reads it from the
 * header (engine_prompt_kind_from_header). No kind is written for the loop
 * itself; fix-gate is the closest template: the assertion or baseline is the
 * specification and weakening it to get green is the one forbidden outcome. */
#define STP_TASK_KIND "fix-gate"
#define STP_TASK_CAP 8192u
#define STP_ENGINE_BIN "build/bin/z23-engine-unit"
#define STP_COMPLEXITY_ID "functions_over_complexity_cap"

/* "label: a, b, c\n" for a string array; nothing for an empty or absent one. */
static void stp_put_list(struct stp_buf *b, const char *label,
                         const struct json_value *arr)
{
    size_t n = json_size(arr);
    if (n == 0)
        return;
    stp_put(b, "%s: ", label);
    for (size_t i = 0; i < n; i++)
        stp_put(b, "%s%s", i ? ", " : "", json_get_str(json_at(arr, i)));
    stp_put(b, "\n");
}

/* "Functions over the cap: name (m), ..." from the card's pins. */
static void stp_put_pins(struct stp_buf *b, const struct json_value *pins)
{
    size_t n = json_size(pins);
    if (n == 0)
        return;
    stp_put(b, "Functions over the cap: ");
    for (size_t i = 0; i < n; i++) {
        const struct json_value *p = json_at(pins, i);
        stp_put(b, "%s%s (complexity %lld)", i ? ", " : "",
                json_get_str(json_get(p, "function")),
                (long long)json_get_int(json_get(p, "m")));
    }
    stp_put(b, "\n");
}

/* The work card in the form engine_unit's --task file takes: a header (the
 * `kind:` line), one blank line, then prose naming the job, the files, the
 * bar and when to stop. engine_unit treats the body as opaque text and
 * appends the contents of the files the body names. False when it did not
 * fit. */
static bool stp_render_task(const struct json_value *card, char *out,
                            size_t cap)
{
    struct stp_buf b = {out, cap};
    const struct json_value *obj = json_get(card, "objective");
    const char *target = stp_str(card, "target_file");
    out[0] = '\0';
    stp_put(&b, "kind: " STP_TASK_KIND "\n\n");
    stp_put(&b, "Work card %s (level %s) for objective %s.\n\n",
            stp_str(card, "name") ? stp_str(card, "name") : "",
            stp_str(card, "level") ? stp_str(card, "level") : "",
            stp_str(obj, "id") ? stp_str(obj, "id") : "");
    stp_put(&b, "Outcome: %s\n", stp_str(card, "outcome") ? stp_str(card, "outcome") : "");
    if (target)
        stp_put(&b, "Target file: %s\n", target);
    stp_put_list(&b, "Edit only these paths", json_get(card, "owned"));
    stp_put_list(&b, "Never touch", json_get(card, "forbidden"));
    stp_put_list(&b, "Contract", json_get(card, "contract"));
    stp_put(&b, "Acceptance: %s\n",
            stp_str(card, "acceptance") ? stp_str(card, "acceptance") : "");
    stp_put_pins(&b, json_get(card, "pins"));
    stp_put_list(&b, "Stop and report, edit nothing, when", json_get(card, "stop_if"));
    return b.left > 1u;
}

/* The engine for a card, with the reason. Complexity-cap splits are
 * mechanical and behaviour-preserving, so the cheaper claude-haiku takes
 * them, as does any card that says its level is haiku; every other runner_ok
 * card is code work and goes to claude-sonnet. */
static const char *stp_pick_engine(const char *objective, const char *level,
                                   const char **why)
{
    if (level && strcmp(level, "haiku") == 0) {
        *why = "the card's level is haiku";
        return "claude-haiku";
    }
    if (objective && strcmp(objective, STP_COMPLEXITY_ID) == 0) {
        *why = "splitting a function under the complexity cap is mechanical "
               "and behaviour-preserving, which claude-haiku can do";
        return "claude-haiku";
    }
    *why = "any other runner_ok card is code work, which needs claude-sonnet";
    return "claude-sonnet";
}

/* The test group engine_unit judges with, derived the way the card names its
 * acceptance: only an acceptance written as a group run (`ONLY=<group>`)
 * names one. False, with the reason, when it is a measurement command. */
static bool stp_pick_group(const char *acceptance, char *group, size_t cap,
                           const char **why)
{
    const char *p = acceptance ? strstr(acceptance, "ONLY=") : NULL;
    size_t n = 0;
    if (p) {
        p += strlen("ONLY=");
        n = strcspn(p, " ,");
    }
    if (n == 0 || n >= cap) {
        *why = "the acceptance is a measurement command, not a test group, "
               "so engine_unit has no group to judge with and its verdict "
               "will be UNVERIFIED; run the acceptance command to judge";
        return false;
    }
    memcpy(group, p, n);
    group[n] = '\0';
    *why = "the group named by the card's acceptance";
    return true;
}

/* The judge flags. Without a group the verdict is a measurement, which the
 * engine's round loop can never mark verified, so it gets one round: a
 * second or third round re-dispatches the same finished edit. */
static bool stp_push_judge_argv(struct json_value *argv, const char *group)
{
    if (group[0])
        return stp_push_str_item(argv, "--group") &&
               stp_push_str_item(argv, group);
    return stp_push_str_item(argv, "--no-group") &&
           stp_push_str_item(argv, "--rounds") &&
           stp_push_str_item(argv, "1");
}

static bool stp_push_argv(struct json_value *disp, const char *engine,
                          const char *file, const char *group)
{
    struct json_value argv;
    bool ok;
    json_init(&argv);
    json_set_array(&argv);
    ok = stp_push_str_item(&argv, STP_ENGINE_BIN) &&
         stp_push_str_item(&argv, "--engine") &&
         stp_push_str_item(&argv, engine) &&
         stp_push_str_item(&argv, "--task") && stp_push_str_item(&argv, file) &&
         stp_push_judge_argv(&argv, group) &&
         json_push_kv(disp, "argv", &argv);
    json_free(&argv);
    return ok;
}

/* Builds d->dispatch for the run card: {lane, note_prefix, engine,
 * engine_reason, group, group_reason, task_file, task_text, argv[]}. The
 * argv is engine_unit WITHOUT --yes-dispatch; the step never dispatches and
 * writes no file. */
static bool stp_build_dispatch(struct stp_decision *d,
                               const struct json_value *card)
{
    const struct json_value *obj = json_get(card, "objective");
    const char *engine_why, *group_why, *lane = stp_str(&d->next, "lane");
    const char *engine =
        stp_pick_engine(stp_str(obj, "id"), stp_str(card, "level"), &engine_why);
    char group[96] = "", file[200], task[STP_TASK_CAP];
    bool has_group = stp_pick_group(stp_str(card, "acceptance"), group,
                                    sizeof(group), &group_why);
    if (!stp_render_task(card, task, sizeof(task)))
        return false;
    (void)snprintf(file, sizeof(file), "build/scratch/%s.task.txt", lane);
    json_set_object(&d->dispatch);
    return json_push_kv_str(&d->dispatch, "lane", lane) &&
           json_push_kv_str(&d->dispatch, "note_prefix",
                            stp_str(&d->next, "note_prefix")) &&
           json_push_kv_str(&d->dispatch, "engine", engine) &&
           json_push_kv_str(&d->dispatch, "engine_reason", engine_why) &&
           json_push_kv_str(&d->dispatch, "group",
                            has_group ? group : "--no-group") &&
           json_push_kv_str(&d->dispatch, "group_reason", group_why) &&
           json_push_kv_str(&d->dispatch, "task_file", file) &&
           json_push_kv_str(&d->dispatch, "task_text", task) &&
           stp_push_argv(&d->dispatch, engine, file, group);
}

static void stp_screen_skipped(struct stp_buf *b, const struct stp_decision *d)
{
    for (size_t i = 0; i < json_size(&d->skipped); i++) {
        const struct json_value *s = json_at(&d->skipped, i);
        stp_put(b, "skipped %s: %s\n", stp_str(s, "objective"),
                stp_str(s, "reason"));
    }
}

/* The two commands a person runs; the step itself runs neither. */
static void stp_screen_dispatch(struct stp_buf *b, const struct stp_decision *d)
{
    const struct json_value *argv = json_get(&d->dispatch, "argv");
    if (json_size(argv) == 0)
        return;
    stp_put(b, "engine %s: %s\ngroup: %s\n",
            stp_str(&d->dispatch, "engine"),
            stp_str(&d->dispatch, "engine_reason"),
            stp_str(&d->dispatch, "group_reason"));
    stp_put(b, "1. write data.dispatch.task_text to %s\n2.",
            stp_str(&d->dispatch, "task_file"));
    for (size_t i = 0; i < json_size(argv); i++)
        stp_put(b, " %s", json_get_str(json_at(argv, i)));
    stp_put(b, " --yes-dispatch\n");
}

static void stp_screen(char *out, size_t cap, const struct stp_decision *d,
                       const struct stp_verdict *v, size_t n)
{
    struct stp_buf b = {out, cap};
    const char *objective = stp_str(&d->next, "objective");
    const char *lane = stp_str(&d->next, "lane");
    out[0] = '\0';
    stp_put(&b, "loop step: %s\n%s\n", d->action, d->reason);
    if (d->forced)
        stp_put(&b, "force: the pause rule was overridden for this call\n");
    if (lane)
        stp_put(&b, "lane %s, note prefix %s%s:\n", lane, STP_PREFIX,
                objective);
    stp_screen_skipped(&b, d);
    stp_screen_dispatch(&b, d);
    for (size_t i = 0; i < n && i < 5u; i++)
        stp_put(&b, "landed seq %lld %s: %s%s%.60s\n", v[i].seq,
                v[i].objective, v[i].verdict, v[i].reason[0] ? " - " : "",
                v[i].reason);
}

/* ── reply ────────────────────────────────────────────────────────────── */

static bool stp_push_verdict(struct json_value *arr, const struct stp_verdict *v)
{
    struct json_value o;
    bool ok;
    json_init(&o);
    json_set_object(&o);
    ok = json_push_kv_int(&o, "seq", v->seq) &&
         json_push_kv_str(&o, "objective", v->objective) &&
         json_push_kv_str(&o, "verdict", v->verdict) &&
         (!v->reason[0] || json_push_kv_str(&o, "reason", v->reason)) &&
         json_push_back(arr, &o);
    json_free(&o);
    return ok;
}

static bool stp_fill(struct zcl_command_reply *reply,
                     struct stp_decision *d, const struct stp_verdict *v,
                     size_t n)
{
    struct json_value arr;
    char screen[3072];
    bool ok = true;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; ok && i < n; i++)
        ok = stp_push_verdict(&arr, &v[i]);
    stp_screen(screen, sizeof(screen), d, v, n);
    ok = ok && json_push_kv_str(&reply->data, "schema", STP_SCHEMA_OUT) &&
         json_push_kv_str(&reply->data, "action", d->action) &&
         json_push_kv_str(&reply->data, "reason", d->reason) &&
         json_push_kv_bool(&reply->data, "paused", d->paused) &&
         json_push_kv_bool(&reply->data, "forced", d->forced) &&
         json_push_kv(&reply->data, "verdicts", &arr) &&
         json_push_kv(&reply->data, "skipped", &d->skipped) &&
         (json_is_null(&d->dispatch) ||
          json_push_kv(&reply->data, "dispatch", &d->dispatch)) &&
         json_push_kv(&reply->data, "next", &d->next) &&
         json_push_kv_str(&reply->data, "screen", screen);
    json_free(&arr);
    return ok;
}

static void stp_fail(struct zcl_command_reply *reply, int exit_code,
                     const char *code, const char *message)
{
    LOG_ERROR(STP_LEAF, "%s", message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           "decide", false, false, message,
                           "z23-dev fleet objectives step");
}

/* The measurement paths the brief reads, copied from the step's own input:
 * the brief leaf is given exactly these and never the caller's other keys. */
static bool stp_brief_args(struct json_value *obj, const struct json_value *src)
{
    static const char *const keys[] = {"outcomes", "attempts_dir", "repo",
                                       "lintc_dir", "baseline", "brief",
                                       "exclude"};
    json_set_object(obj);
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const char *s = stp_str(src, keys[i]);
        if (s && s[0] && !json_push_kv_str(obj, keys[i], s))
            return false;
    }
    return json_push_kv_bool(obj, "runner_ok_only", true);
}

/* Runs the brief in process over those paths, narrowed to runner_ok rows;
 * its reply lands in *brief. */
static bool stp_ask_brief(const struct zcl_command_request *request,
                          struct zcl_command_reply *brief)
{
    struct json_value args;
    struct zcl_command_request breq;
    bool ok;
    json_init(&args);
    ok = stp_brief_args(&args, request->input);
    breq = *request;
    breq.input = &args;
    memset(brief, 0, sizeof(*brief));
    if (ok && !stp_call("fleet.objectives.brief", &breq, brief))
        brief->status = ZCL_COMMAND_STATUS_FAILED;
    json_free(&args);
    return ok;
}

/* Asks the brief over the runner_ok rows only (it reports the top objective
 * it passed over as `skipped`), and decides run or none from the reply. False,
 * with the reply filled, on failure. */
static bool stp_decide_work(const struct zcl_command_request *request,
                            const struct stp_scan *sc, struct stp_decision *d,
                            struct zcl_command_reply *reply)
{
    struct zcl_command_reply brief;
    bool ok = false;
    if (!stp_ask_brief(request, &brief)) {
        stp_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "STEP_ALLOC",
                 "out of memory building the brief request");
        return false;
    }
    if (brief.status != ZCL_COMMAND_STATUS_PASSED)
        stp_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "STEP_BRIEF",
                 "fleet.objectives.brief could not pick an objective");
    else if (!stp_take_skipped(d, &brief) ||
             !stp_decide_brief(d, &brief, sc->max_seq + 1))
        stp_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "STEP_ALLOC",
                 "out of memory building the work order");
    else
        ok = true;
    zcl_command_reply_free(&brief);
    return ok;
}

/* Decides from the scan and verdicts; runs the brief only when nothing else
 * decides. False, with the reply filled, on failure. */
static bool stp_decide(const struct zcl_command_request *request,
                       const struct stp_scan *sc, const struct stp_verdict *v,
                       struct stp_decision *d, struct zcl_command_reply *reply)
{
    if (!stp_decide_paused(d, v, sc->n_landed, stp_flag(request, "force"))) {
        stp_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "STEP_ALLOC",
                 "out of memory building the pause record");
        return false;
    }
    if (d->paused)
        return true;
    if (stp_decide_wait(d, sc)) {
        if (stp_wait_next(d, sc))
            return true;
        stp_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "STEP_ALLOC",
                 "out of memory building the wait record");
        return false;
    }
    return stp_decide_work(request, sc, d, reply);
}

void zcl_native_handle_fleet_objectives_step(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct stp_scan sc;
    struct stp_verdict verdicts[STP_MAX_LANDED];
    struct stp_decision d;
    struct zcl_dl_row_view *rows = NULL;
    size_t n = 0;
    if (reply)
        zcl_command_reply_init(reply, STP_SCHEMA_OUT);
    if (!reply)
        return;
    memset(&sc, 0, sizeof(sc));
    memset(&d, 0, sizeof(d));
    json_init(&d.next);
    json_set_object(&d.next);
    json_init(&d.skipped);
    json_set_array(&d.skipped);
    json_init(&d.dispatch);
    if (!request || !zcl_dev_land_rows_read(&rows, &n, NULL)) {
        stp_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "STEP_LAND_READ",
                 "cannot read the land queue rows");
    } else {
        stp_scan_rows(&sc, rows, n);
        if (stp_verdicts(request, &sc, verdicts, reply) &&
            stp_decide(request, &sc, verdicts, &d, reply)) {
            if (stp_fill(reply, &d, verdicts, sc.n_landed)) {
                reply->status = ZCL_COMMAND_STATUS_PASSED;
                reply->exit_code = ZCL_COMMAND_EXIT_OK;
            } else {
                stp_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "STEP_ALLOC",
                         "cannot build the step result: out of memory");
            }
        }
    }
    free(rows);
    json_free(&d.next);
    json_free(&d.skipped);
    json_free(&d.dispatch);
}
