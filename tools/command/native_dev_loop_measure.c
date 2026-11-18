/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.loop.measure: a pure read of records the caller already loaded.
 * It classifies repeated discovery, redundant non-release builds,
 * unnecessary non-safety tests, and repair rounds. A counter that was
 * not recorded stays null. Safety-proof spend is a separate class and
 * is never eliminable. An exact prior of the four waste kinds is
 * reused. A safety proof stays required unless
 * zcl_dev_proof_receipt_admit accepts a receipt for that same input.
 * No ledger, datadir, or sealed core is written.
 */

#include "command/native_command.h"
#include "dev/dev_proof_receipt.h"

#include "base/hex.h"
#include "json/json.h"

#include <stdio.h>
#include <string.h>

#define LM_MAX_REC 32u
#define LM_MAX_DEC 40u
#define LM_MAX_UNKNOWN 8u
#define LM_ID 48u
#define LM_GROUPS 160u
#define LM_SAFETY_SCOPE "source_wide_compile_tests_lint_fast"

enum lm_cls {
    LM_DISCOVERY = 0,
    LM_BUILD,
    LM_TEST,
    LM_REPAIR,
    LM_SAFETY,
    LM_NCLASS
};

static const char *const lm_names[LM_NCLASS] = {
    "repeated_discovery", "redundant_builds", "unnecessary_tests",
    "repair_rounds", "safety_proof",
};

static const char *const lm_unknown_names[LM_NCLASS] = {
    "repeated_discovery.tokens", "redundant_builds.tokens",
    "unnecessary_tests.tokens", "repair_rounds.tokens",
    "safety_proof.tokens",
};

struct lm_acc {
    int64_t n;
    int64_t token_sum;
    int64_t seconds_ms;
    bool tokens_known;
    bool tokens_unknown;
    bool seconds_known;
    bool seconds_unknown;
};

struct lm_dec {
    const char *work;
    const char *action;
    const char *reason;
    bool start;
    char id[LM_ID];
};

struct lm_win {
    struct lm_acc a[LM_NCLASS];
    struct lm_dec d[LM_MAX_DEC];
    size_t nd;
    const char *unknown[LM_MAX_UNKNOWN];
    size_t nu;
    int64_t known_tokens;
    int64_t capabilities;
    int64_t commits;
    bool any_known;
    bool any_unknown;
};

struct lm_pair {
    bool known;
    int64_t sum;
};

static const char *lm_str(const struct json_value *o, const char *k)
{
    const struct json_value *v = json_get(o, k);
    if (!v || v->type != JSON_STR || !v->val.s)
        return "";
    return v->val.s;
}

static bool lm_eq(const struct json_value *o, const char *k, const char *want)
{
    return strcmp(lm_str(o, k), want) == 0;
}

static bool lm_same(const struct json_value *o, const char *a, const char *b)
{
    const char *sa = lm_str(o, a);
    const char *sb = lm_str(o, b);
    return sa[0] && strcmp(sa, sb) == 0;
}

static bool lm_bool(const struct json_value *o, const char *k)
{
    const struct json_value *v = json_get(o, k);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static bool lm_schema(const struct json_value *o, const char *schema)
{
    return strcmp(lm_str(o, "schema"), schema) == 0;
}

static void lm_fail(struct zcl_command_reply *reply, const char *message)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT",
                           "normalize", false, false, message, "input.records");
}

static void lm_unknown(struct lm_win *w, const char *name)
{
    for (size_t i = 0; i < w->nu; i++)
        if (strcmp(w->unknown[i], name) == 0)
            return;
    if (w->nu < LM_MAX_UNKNOWN)
        w->unknown[w->nu++] = name;
}

static bool lm_known_int(const struct json_value *o, const char *k,
                         const char *flag, int64_t *out)
{
    const struct json_value *f = json_get(o, flag);
    const struct json_value *v = json_get(o, k);
    if (f && f->type == JSON_BOOL && !json_get_bool(f))
        return false;
    if (!v || v->type != JSON_INT)
        return false;
    if (json_get_int(v) < 0)
        return false;
    *out = json_get_int(v);
    return true;
}

static bool lm_pair(const struct json_value *o, struct lm_pair *p)
{
    int64_t prompt = 0;
    int64_t completion = 0;
    bool kp = lm_known_int(o, "prompt_tokens", "prompt_tokens_known", &prompt);
    bool kc = lm_known_int(o, "completion_tokens", "completion_tokens_known",
                           &completion);
    p->known = kp && kc;
    p->sum = p->known ? prompt + completion : 0;
    return true;
}

static bool lm_mentioned(const struct json_value *r)
{
    return json_get(r, "prompt_tokens") || json_get(r, "completion_tokens") ||
           json_get(r, "prompt_tokens_known") ||
           json_get(r, "completion_tokens_known");
}

static bool lm_ms(const struct json_value *o, int64_t *ms)
{
    const struct json_value *elapsed = json_get(o, "elapsed_ms");
    const struct json_value *build = json_get(o, "build_total_us");
    if (elapsed && elapsed->type == JSON_INT && json_get_int(elapsed) >= 0) {
        *ms = json_get_int(elapsed);
        return true;
    }
    if (build && build->type == JSON_INT && json_get_int(build) >= 0) {
        *ms = json_get_int(build) / 1000;
        return true;
    }
    return false;
}

static bool lm_push_dec(struct lm_win *w, const char *work, const char *id,
                        const char *action, bool start, const char *reason)
{
    struct lm_dec *d;
    if (w->nd >= LM_MAX_DEC)
        return false;
    d = &w->d[w->nd++];
    d->work = work;
    d->action = action;
    d->start = start;
    d->reason = reason;
    (void)snprintf(d->id, sizeof(d->id), "%s", id ? id : "");
    return true;
}

static void lm_note_tokens(struct lm_win *w, const struct json_value *r,
                           bool expect, const char *name)
{
    struct lm_pair p;
    (void)lm_pair(r, &p);
    if (p.known) {
        w->known_tokens += p.sum;
        w->any_known = true;
        return;
    }
    if (!expect && !lm_mentioned(r))
        return;
    w->any_unknown = true;
    if (name)
        lm_unknown(w, name);
}

static void lm_acc(struct lm_win *w, enum lm_cls cls, const struct json_value *r)
{
    struct lm_acc *a = &w->a[cls];
    struct lm_pair p;
    int64_t ms = 0;
    (void)lm_pair(r, &p);
    a->n++;
    if (!p.known) {
        a->tokens_unknown = true;
        w->any_unknown = true;
        lm_unknown(w, lm_unknown_names[cls]);
    } else {
        w->known_tokens += p.sum;
        w->any_known = true;
        if (!a->tokens_unknown) {
            a->token_sum += p.sum;
            a->tokens_known = true;
        }
    }
    if (!lm_ms(r, &ms))
        a->seconds_unknown = true;
    else if (!a->seconds_unknown) {
        a->seconds_ms += ms;
        a->seconds_known = true;
    }
}

static bool lm_group_text(const struct json_value *v, char *out, size_t cap)
{
    size_t n = 0;
    if (!v || cap == 0)
        return false;
    out[0] = '\0';
    if (v->type == JSON_STR)
        return snprintf(out, cap, "%s", v->val.s ? v->val.s : "") < (int)cap &&
               out[0];
    if (v->type != JSON_ARR)
        return false;
    for (size_t i = 0; i < v->num_children; i++) {
        const char *s;
        int wrote;
        if (v->children[i].type != JSON_STR)
            return false;
        s = json_get_str(&v->children[i]);
        wrote = snprintf(out + n, cap - n, "%s%s", n ? "," : "", s);
        if (wrote < 0 || (size_t)wrote >= cap - n)
            return false;
        n += (size_t)wrote;
    }
    return n > 0;
}

static bool lm_selection_repeat(const struct json_value *r)
{
    char got[LM_GROUPS];
    char prior[LM_GROUPS];
    if (!lm_group_text(json_get(r, "test_groups"), got, sizeof(got)))
        return false;
    if (!lm_group_text(json_get(r, "prior_test_groups"), prior, sizeof(prior)))
        return false;
    return strcmp(got, prior) == 0;
}

static bool lm_is_have(const struct json_value *r)
{
    const struct json_value *searched = json_get(r, "searched");
    return lm_str(r, "query")[0] && searched && searched->type == JSON_OBJ;
}

static const char *lm_question(const struct json_value *r)
{
    const char *question = lm_str(r, "question");
    return question[0] ? question : lm_str(r, "query");
}

static bool lm_discovery_repeat(const struct json_value *r)
{
    const char *question = lm_question(r);
    if (!question[0] || !lm_str(r, "tree")[0])
        return false;
    if (lm_same(r, "question", "prior_question") &&
        lm_same(r, "tree", "prior_tree"))
        return true;
    return lm_same(r, "query", "prior_query") && lm_same(r, "tree", "prior_tree");
}

static bool lm_discovery(const struct json_value *r, struct lm_win *w)
{
    if (lm_discovery_repeat(r)) {
        lm_acc(w, LM_DISCOVERY, r);
        return lm_push_dec(w, "discovery", lm_question(r), "reused", false,
                           NULL);
    }
    lm_note_tokens(w, r, false, NULL);
    return lm_push_dec(w, "discovery", lm_question(r), "required", true, NULL);
}

static bool lm_build(const struct json_value *r, struct lm_win *w)
{
    bool release = lm_bool(r, "release");
    bool hit = lm_bool(r, "artifact_cache_hit") ||
               lm_same(r, "artifact_cache_key", "prior_artifact_cache_key");
    const char *id = lm_str(r, "artifact_cache_key");
    if (lm_bool(r, "candidate_bytes_executed"))
        w->capabilities++;
    if (release || !hit) {
        lm_note_tokens(w, r, false, NULL);
        return lm_push_dec(w, "build", id, "required", true,
                           release ? "release" : NULL);
    }
    lm_acc(w, LM_BUILD, r);
    return lm_push_dec(w, "build", id, "reused", false, NULL);
}

static bool lm_safety(const struct json_value *r, struct lm_win *w);

static bool lm_safety_token(const char *tok)
{
    static const char *const names[] = {
        "consensus_parity", "consensus-parity", "custody", "custody_checks",
        "sealed_core", "sealed-core", "sealed_core_checks", LM_SAFETY_SCOPE,
    };
    if (!tok || !tok[0])
        return false;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (strcmp(tok, names[i]) == 0)
            return true;
    return false;
}

static bool lm_groups_safety(const char *text)
{
    char tok[LM_GROUPS];
    size_t n = 0;
    if (!text)
        return false;
    for (size_t i = 0;; i++) {
        char c = text[i];
        if (c != '\0' && c != ',') {
            if (n + 1 < sizeof(tok))
                tok[n++] = c;
            continue;
        }
        tok[n] = '\0';
        if (lm_safety_token(tok))
            return true;
        if (c == '\0')
            return false;
        n = 0;
    }
}

static bool lm_plan_safety(const struct json_value *r)
{
    char groups[LM_GROUPS];
    if (lm_bool(r, "safety") || lm_safety_token(lm_str(r, "proof_scope")))
        return true;
    if (!lm_group_text(json_get(r, "test_groups"), groups, sizeof(groups)))
        return false;
    return lm_groups_safety(groups);
}

static bool lm_plan(const struct json_value *r, struct lm_win *w)
{
    char id[LM_GROUPS];
    if (!lm_group_text(json_get(r, "test_groups"), id, sizeof(id)))
        id[0] = '\0';
    if (lm_plan_safety(r))
        return lm_safety(r, w);
    if (!lm_selection_repeat(r)) {
        lm_note_tokens(w, r, false, NULL);
        return lm_push_dec(w, "test", id, "required", true, NULL);
    }
    lm_acc(w, LM_TEST, r);
    return lm_push_dec(w, "test", id, "reused", false, NULL);
}

static bool lm_plugin(const struct json_value *r, struct lm_win *w)
{
    bool ran = !lm_bool(r, "queued") && json_get(r, "elapsed_ms") &&
               json_get(r, "elapsed_ms")->type == JSON_INT;
    if (ran)
        w->capabilities++;
    lm_note_tokens(w, r, ran, "plugin.tokens");
    return true;
}

static bool lm_policy_old(const struct json_value *r)
{
    const struct json_value *v = json_get(r, "policy_version");
    if (!v || v->type != JSON_INT)
        return false;
    return json_get_int(v) != (int64_t)ZCL_DEV_PROOF_POLICY_VERSION;
}

static bool lm_inputs_differ(const struct json_value *r)
{
    const char *got = lm_str(r, "proof_inputs_sha3");
    const char *prior = lm_str(r, "prior_proof_inputs_sha3");
    return got[0] && prior[0] && strcmp(got, prior) != 0;
}

static bool lm_admit(const struct json_value *r, const char **why)
{
    const char *hex = lm_str(r, "receipt_hex");
    const char *local = lm_str(r, "local_commit");
    const char *base = lm_str(r, "remote_base");
    *why = "missing";
    if (!hex[0] || !local[0] || !base[0])
        return false;
    /* dev_proof_receipt.c is dev-only. The release node links this command
     * file and does not link that codec, so a release TU must not name it.
     * Dev and test builds admit the real receipt; a release call fails closed. */
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    {
        uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
        struct zcl_dev_acceptance_receipt_v1 receipt;
        char cause[64];
        if (!zcl_hex_decode(hex, wire, sizeof(wire)) ||
            !zcl_dev_proof_receipt_parse(wire, sizeof(wire), &receipt)) {
            *why = "receipt_rejected";
            return false;
        }
        if (!zcl_dev_proof_receipt_admit(&receipt, local, base, NULL, NULL,
                                         cause, sizeof(cause))) {
            *why = "receipt_rejected";
            return false;
        }
    }
#else
    *why = "receipt_rejected";
    return false;
#endif
    if (!lm_same(r, "proof_inputs_sha3", "prior_proof_inputs_sha3")) {
        *why = "missing";
        return false;
    }
    return true;
}

static const char *lm_safety_reason(const struct json_value *r, bool *ok)
{
    const char *why = "missing";
    *ok = false;
    if (lm_bool(r, "stale") || lm_policy_old(r))
        return "stale";
    if (lm_inputs_differ(r))
        return "different_input";
    if (!lm_admit(r, &why))
        return why;
    *ok = true;
    return "admitted_receipt";
}

static bool lm_safety(const struct json_value *r, struct lm_win *w)
{
    bool satisfied = false;
    const char *reason = lm_safety_reason(r, &satisfied);
    lm_acc(w, LM_SAFETY, r);
    return lm_push_dec(w, "safety_proof", lm_str(r, "proof_inputs_sha3"),
                       satisfied ? "satisfied" : "required", !satisfied,
                       reason);
}

static bool lm_focused(const struct json_value *r, struct lm_win *w)
{
    lm_note_tokens(w, r, true, "focused_proof.tokens");
    return true;
}

static bool lm_fail_status(const struct json_value *r)
{
    const char *status = lm_str(r, "status");
    return strcmp(status, "failed") == 0 || strcmp(status, "rejected") == 0 ||
           strcmp(status, "story_red") == 0;
}

static bool lm_id_conflict(const struct json_value *r, const char *got,
                           const char *prior)
{
    const char *a = lm_str(r, got);
    const char *b = lm_str(r, prior);
    if (!a[0] && !b[0])
        return false;
    return strcmp(a, b) != 0;
}

/* Native cycles name the step `phase` and again `failure_phase`.
 * Hot-swap copies that step into `stage_detail`. Each name the row
 * actually records must match; a different phase is another failure. */
static bool lm_phase_field(const struct json_value *r, const char *got,
                           const char *prior, bool *any)
{
    if (!lm_str(r, got)[0] && !lm_str(r, prior)[0])
        return true;
    *any = true;
    return lm_same(r, got, prior);
}

static bool lm_phase_same(const struct json_value *r)
{
    bool any = false;
    return lm_phase_field(r, "phase", "prior_phase", &any) &&
           lm_phase_field(r, "failure_phase", "prior_failure_phase", &any) &&
           lm_phase_field(r, "stage_detail", "prior_stage_detail", &any) &&
           any;
}

static bool lm_same_failure(const struct json_value *r)
{
    return lm_phase_same(r) &&
           !lm_id_conflict(r, "failure_id", "prior_failure_id") &&
           !lm_id_conflict(r, "failure_capsule", "prior_failure_capsule") &&
           !lm_id_conflict(r, "first_error", "prior_first_error");
}

static const char *lm_failure_name(const struct json_value *r)
{
    const char *id = lm_str(r, "failure_id");
    if (id[0])
        return id;
    id = lm_str(r, "failure_capsule");
    if (id[0])
        return id;
    id = lm_str(r, "first_error");
    if (id[0])
        return id;
    return lm_str(r, "stage_detail");
}

static bool lm_repair(const struct json_value *r, struct lm_win *w)
{
    const char *id = lm_failure_name(r);
    if (lm_same_failure(r)) {
        lm_acc(w, LM_REPAIR, r);
        return lm_push_dec(w, "failure", id, "reused", false, NULL);
    }
    lm_note_tokens(w, r, false, NULL);
    return lm_push_dec(w, "failure", id, "required", true, NULL);
}

static bool lm_focused_scope(const struct json_value *r)
{
    const char *scope = lm_str(r, "proof_scope");
    return scope[0] && strcmp(scope, "none") != 0 && !lm_safety_token(scope);
}

static bool lm_cycle(const struct json_value *r, struct lm_win *w)
{
    bool ran = lm_bool(r, "candidate_bytes_executed");
    if (lm_safety_token(lm_str(r, "proof_scope")))
        return lm_safety(r, w);
    if (lm_fail_status(r)) {
        if (ran)
            w->capabilities++;
        return lm_repair(r, w);
    }
    if (lm_eq(r, "status", "passed") && lm_focused_scope(r)) {
        w->capabilities++;
        return lm_focused(r, w);
    }
    if (ran)
        w->capabilities++;
    lm_note_tokens(w, r, ran, "executed.tokens");
    return true;
}

static bool lm_one(const struct json_value *r, struct lm_win *w)
{
    if (r->type != JSON_OBJ)
        return false;
    if (lm_schema(r, "zcl.code_guide_brief.v1") || lm_is_have(r))
        return lm_discovery(r, w);
    if (lm_schema(r, "zcl.hotswap_build_receipt.v1") ||
        lm_schema(r, "zcl.hotswap_build_stages.v1"))
        return lm_build(r, w);
    if (lm_schema(r, "zcl.agent_fast_plan.v1"))
        return lm_plan(r, w);
    if (lm_schema(r, "zcl.plugin_call.v1"))
        return lm_plugin(r, w);
    if (lm_schema(r, "zcl.dev_cycle.v1"))
        return lm_cycle(r, w);
    if (lm_str(r, "commit")[0]) {
        w->commits++;
        return true;
    }
    return true;
}

static bool lm_ensure_safety(struct lm_win *w)
{
    for (size_t i = 0; i < w->nd; i++)
        if (strcmp(w->d[i].work, "safety_proof") == 0)
            return true;
    return lm_push_dec(w, "safety_proof", "", "required", true, "missing");
}

static bool lm_scan(const struct json_value *arr, struct lm_win *w)
{
    if (arr->num_children > LM_MAX_REC)
        return false;
    for (size_t i = 0; i < arr->num_children; i++)
        if (!lm_one(&arr->children[i], w))
            return false;
    return lm_ensure_safety(w);
}

static bool lm_take(const struct zcl_command_request *req,
                    const struct json_value **arr, struct json_value *owned,
                    bool *own)
{
    const struct json_value *in = req && req->input ? req->input : NULL;
    const struct json_value *rec;
    *own = false;
    *arr = NULL;
    json_init(owned);
    if (!in || in->type != JSON_OBJ)
        return false;
    rec = json_get(in, "records");
    if (!rec)
        return false;
    if (rec->type == JSON_ARR) {
        *arr = rec;
        return true;
    }
    if (rec->type != JSON_STR || !rec->val.s)
        return false;
    if (!json_read(owned, rec->val.s, strlen(rec->val.s)) ||
        owned->type != JSON_ARR) {
        json_free(owned);
        json_init(owned);
        return false;
    }
    *own = true;
    *arr = owned;
    return true;
}

static bool lm_push_null(struct json_value *o, const char *key)
{
    struct json_value nul;
    json_init(&nul);
    json_set_null(&nul);
    bool ok = json_push_kv(o, key, &nul);
    json_free(&nul);
    return ok;
}

static bool lm_emit_seconds(struct json_value *c, const struct lm_acc *a)
{
    if (a->seconds_unknown || !a->seconds_known)
        return lm_push_null(c, "seconds_ms") && lm_push_null(c, "seconds");
    return json_push_kv_int(c, "seconds_ms", a->seconds_ms) &&
           json_push_kv_real(c, "seconds", (double)a->seconds_ms / 1000.0);
}

static bool lm_emit_tokens(struct json_value *c, const struct lm_acc *a)
{
    if (a->tokens_unknown || !a->tokens_known)
        return lm_push_null(c, "tokens");
    return json_push_kv_int(c, "tokens", a->token_sum);
}

static bool lm_emit_class(struct json_value *out, enum lm_cls cls,
                          const struct lm_acc *a)
{
    struct json_value one;
    json_init(&one);
    json_set_object(&one);
    bool ok = json_push_kv_int(&one, "n", a->n) && lm_emit_tokens(&one, a) &&
              lm_emit_seconds(&one, a) &&
              json_push_kv_bool(&one, "eliminable", cls != LM_SAFETY) &&
              json_push_kv(out, lm_names[cls], &one);
    json_free(&one);
    return ok;
}

static bool lm_emit_classes(struct json_value *out, const struct lm_win *w)
{
    struct json_value classes;
    struct json_value elim;
    json_init(&classes);
    json_set_object(&classes);
    json_init(&elim);
    json_set_array(&elim);
    bool ok = true;
    for (int i = 0; ok && i < LM_NCLASS; i++)
        ok = lm_emit_class(&classes, (enum lm_cls)i, &w->a[i]);
    for (int i = 0; ok && i < LM_SAFETY; i++) {
        struct json_value name;
        json_init(&name);
        json_set_str(&name, lm_names[i]);
        ok = json_push_back(&elim, &name);
        json_free(&name);
    }
    ok = ok && json_push_kv(out, "classes", &classes) &&
         json_push_kv(out, "eliminable", &elim);
    json_free(&classes);
    json_free(&elim);
    return ok;
}

static bool lm_emit_unknown(struct json_value *out, const struct lm_win *w)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    bool ok = true;
    for (size_t i = 0; ok && i < w->nu; i++) {
        struct json_value name;
        json_init(&name);
        json_set_str(&name, w->unknown[i]);
        ok = json_push_back(&arr, &name);
        json_free(&name);
    }
    ok = ok && json_push_kv(out, "unknown_tokens", &arr);
    json_free(&arr);
    return ok;
}

static bool lm_emit_decs(struct json_value *out, const struct lm_win *w)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    bool ok = true;
    for (size_t i = 0; ok && i < w->nd; i++) {
        struct json_value one;
        const struct lm_dec *d = &w->d[i];
        json_init(&one);
        json_set_object(&one);
        ok = json_push_kv_str(&one, "work", d->work) &&
             json_push_kv_str(&one, "id", d->id) &&
             json_push_kv_str(&one, "action", d->action) &&
             json_push_kv_bool(&one, "start", d->start);
        if (ok && d->reason)
            ok = json_push_kv_str(&one, "reason", d->reason);
        ok = ok && json_push_back(&arr, &one);
        json_free(&one);
    }
    ok = ok && json_push_kv(out, "decisions", &arr);
    json_free(&arr);
    return ok;
}

static bool lm_emit_ratio(struct json_value *o, const struct lm_win *w)
{
    if (!w->any_known)
        return lm_push_null(o, "tokens") && lm_push_null(o, "per_token_num") &&
               lm_push_null(o, "per_token_den");
    if (w->known_tokens <= 0)
        return json_push_kv_int(o, "tokens", w->known_tokens) &&
               lm_push_null(o, "per_token_num") &&
               lm_push_null(o, "per_token_den");
    return json_push_kv_int(o, "tokens", w->known_tokens) &&
           json_push_kv_int(o, "per_token_num", w->capabilities) &&
           json_push_kv_int(o, "per_token_den", w->known_tokens);
}

static bool lm_emit_running(struct json_value *out, const struct lm_win *w)
{
    struct json_value one;
    json_init(&one);
    json_set_object(&one);
    bool ok = json_push_kv_int(&one, "capabilities", w->capabilities) &&
              json_push_kv_int(&one, "commits", w->commits) &&
              json_push_kv_bool(&one, "unknown_omitted", w->any_unknown) &&
              lm_emit_ratio(&one, w) &&
              json_push_kv(out, "running_software", &one);
    json_free(&one);
    return ok;
}

static bool lm_emit(struct zcl_command_reply *reply, const struct lm_win *w)
{
    return json_push_kv_str(&reply->data, "schema", "zcl.dev_loop_measure.v1") &&
           lm_emit_classes(&reply->data, w) && lm_emit_unknown(&reply->data, w) &&
           lm_emit_decs(&reply->data, w) && lm_emit_running(&reply->data, w);
}

void zcl_native_handle_dev_loop_measure(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *records = NULL;
    struct json_value owned;
    struct lm_win win;
    bool own = false;
    if (!reply)
        return;
    if (!lm_take(request, &records, &owned, &own)) {
        lm_fail(reply, "records is a JSON array, or a string holding one");
        json_free(&owned);
        return;
    }
    memset(&win, 0, sizeof(win));
    if (!lm_scan(records, &win) || !lm_emit(reply, &win))
        lm_fail(reply, "records could not be classified");
    if (own)
        json_free(&owned);
}
