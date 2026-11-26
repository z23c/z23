/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: local task views, not another task store or evidence authority.
 * This file opens no files, takes no locks, executes nothing and joins no
 * names. Queue dependency decisions come unchanged from the scheduler.
 * Landing PASS is an exact pair admitted by dev.proof.status; review and
 * remote acceptance remain unknown. Mail/board reports cannot promote it.
 * Landing steering is copied only when its candidate commit and seq match. */
#include "command/native_fleet_steer_tasks.h"
#include <stdio.h>
#include <string.h>

static const char *ft_str(const struct json_value *o, const char *key)
{
    const struct json_value *v = json_get(o, key);
    return v && v->type == JSON_STR ? json_get_str(v) : "";
}

static long long ft_int(const struct json_value *o, const char *key)
{
    const struct json_value *v = json_get(o, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

/* Never truncate an identity, guess a missing number or turn empty into 0. */
static bool ft_copy(struct json_value *out, const char *key,
    const struct json_value *in, const char *from, enum json_type type)
{
    const struct json_value *v = json_get(in, from);
    const struct json_value *landed;
    struct json_value none = {0};
    size_t at = json_size(out);
    enum json_type want;
    if (!v || v->type != type || (type == JSON_STR && !json_get_str(v)[0]))
        v = &none;
    want = v->type;
    if (!json_push_kv(out, key, v))
        return false;
    /* json_push_kv refuses an incomplete copy; the landed child must also
     * keep the intended type, or present data would read as absent. */
    landed = json_at(out, at);
    return landed && landed->type == want;
}

static bool ft_sha(const char *s)
{
    if (!s || strlen(s) != 40) return false;
    for (size_t i = 0; i < 40; i++)
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

static const char *ft_fresh(long long observed, long long now)
{
    if (observed <= 0 || now < observed) return "unknown";
    return now - observed > ZCL_FMC_TASK_FRESH_S ? "stale" : "fresh";
}

static bool ft_detail(struct json_value *out, const struct json_value *row,
    const char *source, const char *ref_key)
{
    struct json_value evidence = {0};
    json_set_object(&evidence);
    bool ok = json_push_kv_str(&evidence, "command", "fleet.steer.evidence") &&
        json_push_kv_str(&evidence, "type", strcmp(source, "dev.land") == 0
            ? "land" : "queue") &&
        ft_copy(&evidence, "ref", row, ref_key, JSON_STR) &&
        ft_copy(&evidence, "seq", row, "seq", JSON_INT) &&
        ft_copy(&evidence, "attempt", row, "attempt", JSON_INT) &&
        json_push_kv(out, "detail", &evidence);
    json_free(&evidence);
    return ok;
}

static bool ft_unknown_authorities(struct json_value *out)
{
    struct json_value empty = {0};
    return json_push_kv(out, "canonical_task", &empty) &&
        json_push_kv(out, "canonical_candidate", &empty) &&
        json_push_kv_str(out, "link_reason", "no_persisted_canonical_identity_link") &&
        json_push_kv_str(out, "review", "unknown") &&
        json_push_kv_str(out, "review_reason", "no_exact_review_observed") &&
        json_push_kv_str(out, "publication", "unknown");
}

static bool ft_observation(struct json_value *out, long long observed, long long now)
{
    struct json_value age = {0};
    if (observed > 0 && now >= observed) json_set_int(&age, now - observed);
    return json_push_kv_int(out, "observed_unix", observed) &&
        json_push_kv_str(out, "freshness", ft_fresh(observed, now)) &&
        json_push_kv(out, "observed_age_s", &age);
}

static bool ft_common(struct json_value *out, const struct json_value *row,
    const char *source, const char *ref_key, long long observed, long long now)
{
    json_set_object(out);
    return ft_detail(out, row, source, ref_key) &&
        json_push_kv_str(out, "source", source) &&
        json_push_kv_str(out, "identity_type", strcmp(source, "dev.land") == 0
            ? "local_land_attempt" : "local_agent_queue_attempt") &&
        ft_copy(out, "seq", row, "seq", JSON_INT) &&
        ft_copy(out, "attempt", row, "attempt", JSON_INT) &&
        ft_copy(out, "ref", row, ref_key, JSON_STR) &&
        ft_copy(out, "source_ts", row, "ts", JSON_STR) &&
        ft_observation(out, observed, now) && ft_unknown_authorities(out) &&
        json_push_kv_str(out, "observed_model", "unknown");
}

static unsigned ft_rank(const struct json_value *row)
{
    if (json_get_bool(json_get(row, "historical"))) return 4;
    const char *state = ft_str(row, "state");
    if (strcmp(state, "blocked") == 0) return 0;
    if (strcmp(state, "unknown") == 0) return 1;
    if (strcmp(state, "queued") == 0) return 2;
    return 3;
}

/* After the whole-row deep copy into v->rows, every top-level field must
 * keep its built type: json_push_back refuses an incomplete copy, and this
 * independent check pins the landed types either way. */
static bool ft_landed_types_ok(const struct json_value *landed,
                               const struct json_value *row)
{
    size_t i;
    if (!landed || landed->num_children != row->num_children)
        return false;
    for (i = 0; i < row->num_children; i++) {
        if (landed->children[i].type != row->children[i].type)
            return false;
    }
    return true;
}

/* Presentation priority only. No execution order or scheduler state changes. */
static void ft_add(struct zcl_fmc_tasks *v, struct json_value *row, bool ok)
{
    v->observed++;
    if (!ok) { v->malformed++; return; }
    size_t n = json_size(&v->rows);
    if (n == ZCL_FMC_TASK_CAP) {
        v->dropped++;
        if (ft_rank(row) >= ft_rank(json_at(&v->rows, n - 1))) return;
        json_free(&v->rows.children[n - 1]);
        v->rows.num_children--;
    }
    n = json_size(&v->rows);
    if (!json_push_back(&v->rows, row)) { v->malformed++; return; }
    if (!ft_landed_types_ok(json_at(&v->rows, n), row)) {
        /* A degraded copy never ships: drop the landed row, count it. */
        json_free(&v->rows.children[n]);
        v->rows.num_children--;
        v->malformed++;
        return;
    }
    for (size_t i = json_size(&v->rows) - 1; i > 0; i--) {
        if (ft_rank(&v->rows.children[i]) >= ft_rank(&v->rows.children[i - 1]))
            break;
        struct json_value tmp = v->rows.children[i];
        v->rows.children[i] = v->rows.children[i - 1];
        v->rows.children[i - 1] = tmp;
    }
}

static bool ft_identity(const struct json_value *row, const char *ref_key)
{
    const char *ref = ft_str(row, ref_key);
    return row && row->type == JSON_OBJ && ft_int(row, "seq") > 0 &&
        ft_int(row, "attempt") > 0 && ref[0] && strlen(ref) <= 128;
}

static const char *ft_queue_state(const struct json_value *row, bool running,
    const char **reason)
{
    if (running) {
        const char *live = ft_str(row, "owner_liveness");
        if (strcmp(live, "running") == 0) {
            *reason = "exact_attempt_owner_observed_live";
            return "executing";
        }
        if (strcmp(live, "dead") == 0) {
            *reason = "exact_attempt_owner_dead";
            return "blocked";
        }
        *reason = "exact_attempt_owner_liveness_unknown";
        return "unknown";
    }
    const struct json_value *ready = json_get(row, "ready");
    const struct json_value *blocker = json_get(row, "blocker");
    if (ready && ready->type == JSON_BOOL && json_get_bool(ready) &&
        blocker && blocker->type == JSON_NULL) {
        *reason = "ready_unclaimed";
        return "queued";
    }
    if (ready && ready->type == JSON_BOOL && !json_get_bool(ready) &&
        blocker && blocker->type == JSON_OBJ && ft_str(blocker, "ref")[0]) {
        *reason = "scheduler_dependency_gate";
        return "blocked";
    }
    *reason = "scheduler_dependency_evidence_incomplete";
    return "unknown";
}

static bool ft_queue_fields(struct json_value *out, const struct json_value *row)
{
    return
        ft_copy(out, "kind", row, "kind", JSON_STR) &&
        ft_copy(out, "test_group", row, "group", JSON_STR) &&
        ft_copy(out, "work_path", row, "path", JSON_STR) &&
        ft_copy(out, "brief_path_reference", row, "brief", JSON_STR) &&
        ft_copy(out, "requested_model", row, "model", JSON_STR) &&
        ft_copy(out, "priority", row, "priority", JSON_INT) &&
        ft_copy(out, "owner", row, "worker", JSON_STR) &&
        ft_copy(out, "owner_liveness", row, "owner_liveness", JSON_STR) &&
        ft_copy(out, "depends_on", row, "depends_on", JSON_STR) &&
        ft_copy(out, "ready", row, "ready", JSON_BOOL) &&
        ft_copy(out, "blocker", row, "blocker", JSON_OBJ) &&
        ft_copy(out, "attempt_age_s", row, "age_s", JSON_INT) &&
        json_push_kv_str(out, "proof", "unknown");
}

static bool ft_queue_class(struct json_value *out, const char *state,
    const char *reason, bool running)
{
    return json_push_kv_str(out, "state", state) &&
        json_push_kv_str(out, "column", state) &&
        json_push_kv_bool(out, "historical", false) &&
        json_push_kv_str(out, "reason", reason) &&
        json_push_kv_str(out, "source_state", running ? "running" : "queued");
}

static void ft_queue_row(struct zcl_fmc_tasks *v, const struct json_value *row,
    bool running, long long observed, long long now)
{
    struct json_value out = {0};
    const char *reason, *state = ft_queue_state(row, running, &reason);
    bool identity = ft_identity(row, "name");
    if (!identity) { state = "unknown"; reason = "queue_identity_incomplete"; }
    if (strcmp(ft_fresh(observed, now), "fresh") != 0) {
        state = "unknown"; reason = "source_observation_not_fresh";
    }
    bool ok = ft_common(&out, row, "dev.agent.queue", "name", observed, now) &&
        ft_queue_class(&out, state, reason, running) &&
        ft_queue_fields(&out, row) &&
        json_push_kv_str(&out, "next_safe_command", identity
            ? "fleet.steer.evidence" : "dev.agent.queue status") &&
        json_push_kv_bool(&out, "incomplete", !identity ||
            strcmp(state, "unknown") == 0 || !ft_str(row, "worker")[0]);
    if (!identity) v->malformed++;
    ft_add(v, &out, ok);
    json_free(&out);
}

void zcl_fmc_tasks_init(struct zcl_fmc_tasks *v)
{
    memset(v, 0, sizeof(*v));
    json_set_array(&v->rows);
}

void zcl_fmc_tasks_free(struct zcl_fmc_tasks *v)
{
    json_free(&v->rows);
}

bool zcl_fmc_tasks_queue(struct zcl_fmc_tasks *v, const struct json_value *queue,
    long long observed, long long now)
{
    const char *const sections[] = {"queued", "running"};
    bool ok = true;
    size_t malformed = v->malformed;
    for (size_t s = 0; s < 2; s++) {
        const struct json_value *arr = json_get(queue, sections[s]);
        if (!arr || arr->type != JSON_ARR) { ok = false; continue; }
        for (size_t i = 0; i < json_size(arr); i++)
            ft_queue_row(v, json_at(arr, i), s == 1, observed, now);
    }
    ok = ok && v->malformed == malformed;
    v->queue_ok = ok;
    return ok;
}

static bool ft_exact_proof(const struct json_value *row,
    const struct json_value *proof)
{
    return ft_sha(ft_str(row, "local")) && ft_sha(ft_str(row, "base")) &&
        strcmp(ft_str(row, "local"), ft_str(proof, "local_commit")) == 0 &&
        strcmp(ft_str(row, "base"), ft_str(proof, "remote_base")) == 0;
}

static const char *ft_proof_state(const struct json_value *row,
    const struct json_value *proof, long long now, const char **reason)
{
    if (!ft_exact_proof(row, proof)) {
        *reason = "exact_proof_unavailable_or_mismatched";
        return "unknown";
    }
    const char *state = ft_str(proof, "status");
    const char *detail = ft_str(proof, "detail");
    *reason = detail[0] ? detail : "exact_proof_status";
    if (strcmp(state, "passed") == 0) return "verified";
    if (strcmp(state, "failed") == 0) return "blocked";
    if (strcmp(state, "missing") == 0) return "queued";
    if (strcmp(state, "running") != 0) return "unknown";
    if (strcmp(detail, "resident_proof_request_queued") == 0) return "queued";
    if (strcmp(detail, "background_verification_running") == 0 &&
        ft_int(proof, "worker_id") > 1 && ft_int(proof, "started_unix") > 0 &&
        ft_int(proof, "started_unix") <= now) return "executing";
    *reason = "proof_consumer_not_confirmed";
    return "unknown";
}

static bool ft_land_fields(struct json_value *out, const struct json_value *row)
{
    static const char *const keys[] = {"phase", "base", "local", "tree",
        "proof_intent", "publication_target", "publication_proof",
        "publication_bundle", "publication_signer", "remote_tip",
        "remote_source", "remote_signer", "dispatch_state", "acceptance_state"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (!ft_copy(out, keys[i], row, keys[i], JSON_STR)) return false;
    return true;
}

static bool ft_proof_object(struct json_value *p, const struct json_value *proof, bool exact)
{
    json_set_object(p);
    return json_push_kv_bool(p, "exact_pair", exact) &&
        ft_copy(p, "status", proof, "status", JSON_STR) &&
        ft_copy(p, "reason", proof, "detail", JSON_STR) &&
        ft_copy(p, "worker_id", proof, "worker_id", JSON_INT) &&
        ft_copy(p, "started_unix", proof, "started_unix", JSON_INT) &&
        ft_copy(p, "receipt_path", proof, "receipt_path", JSON_STR) &&
        ft_copy(p, "local_commit", proof, "local_commit", JSON_STR) &&
        ft_copy(p, "remote_base", proof, "remote_base", JSON_STR);
}

static const char *ft_land_state(const struct json_value *row,
    const struct json_value *proof, const char *section, long long now, const char **reason)
{
    const char *state = "unknown";
    *reason = "landing_executor_not_observed";
    if (strcmp(section, "queued") == 0) {
        state = "queued"; *reason = "persisted_landing_pending";
    } else if (strcmp(section, "in_flight") == 0) {
        state = ft_proof_state(row, proof, now, reason);
        if (strcmp(ft_str(row, "phase"), "push") == 0) {
            state = "unknown"; *reason = "push_checkpoint_remote_acceptance_unknown";
        }
    } else if (strcmp(ft_str(row, "state"), "landed") == 0) {
        *reason = "reported_publication_remote_acceptance_unknown";
    } else {
        state = "unknown"; *reason = "historical_landing_outcome";
    }
    return state;
}

static bool ft_land_history(struct json_value *out, const struct json_value *row,
    const char *section)
{
    return
        ft_copy(out, "recorded_state", row, "state", JSON_STR) &&
        json_push_kv_str(out, "source_state", section) &&
        json_push_kv_bool(out, "historical", strcmp(section, "outcomes") == 0);
}

static bool ft_land_disposition(struct json_value *out, const struct json_value *row, bool identity)
{
    return
        json_push_kv_bool(out, "reported_published",
            strcmp(ft_str(row, "state"), "landed") == 0) &&
        json_push_kv_str(out, "next_safe_command", identity
            ? "fleet.steer.evidence" : "dev.land status") &&
        json_push_kv_bool(out, "incomplete", true);
}

static bool ft_land_column_priority(struct json_value *out,
    const char *section, const char *state)
{
    struct json_value none = {0};
    return json_push_kv_str(out, "column",
               strcmp(section, "outcomes") == 0 ? "history" : state) &&
        json_push_kv(out, "priority", &none);
}

static bool ft_land_steer_match(const struct json_value *steer,
    const struct json_value *row)
{
    if (!steer || steer->type != JSON_OBJ || !ft_sha(ft_str(steer, "candidate")))
        return false;
    if (strcmp(ft_str(steer, "candidate"), ft_str(row, "tip")) != 0)
        return false;
    return ft_int(steer, "seq") > 0 && ft_int(steer, "seq") == ft_int(row, "seq");
}

static bool ft_land_steer_projected(struct json_value *out,
    const struct json_value *steer, const struct json_value *land)
{
    static const char *const strings[] = {"candidate", "phase", "owner",
        "lease", "proof_state", "receiver_driver", "first_missing_transition",
        "wake_command", "remote_state"};
    struct json_value projected = {0};
    bool complete = true;
    json_set_object(&projected);
    for (size_t i = 0; i < sizeof(strings) / sizeof(strings[0]); i++) {
        const struct json_value *value = json_get(steer, strings[i]);
        complete = complete && value && value->type == JSON_STR &&
            json_get_str(value)[0];
        if (!ft_copy(&projected, strings[i], steer, strings[i], JSON_STR))
            goto fail;
    }
    complete = complete && ft_int(steer, "seq") > 0 &&
        ft_str(land, "incident")[0];
    if (!ft_copy(&projected, "seq", steer, "seq", JSON_INT) ||
        !ft_copy(&projected, "incident", land, "incident", JSON_STR) ||
        !json_push_kv_str(&projected, "remote_state_basis",
            "submitter_cached_origin_main_not_fresh_acceptance") ||
        !json_push_kv(out, "landing_steer", &projected) ||
        !json_push_kv_bool(out, "landing_steer_complete", complete))
        goto fail;
    json_free(&projected);
    return true;
fail:
    json_free(&projected);
    return false;
}

static bool ft_land_steer(struct json_value *out, const struct json_value *row,
    const struct json_value *land)
{
    const struct json_value *steer = json_get(land, "steer");
    bool match = ft_land_steer_match(steer, row);
    struct json_value none = {0};
    if (!json_push_kv_str(out, "landing_steer_link", match ? "exact" : "unknown") ||
        !json_push_kv_str(out, "landing_steer_reason", match
            ? "candidate_commit_and_seq"
            : "no_exact_candidate_commit_and_seq_observation"))
        return false;
    if (match) return ft_land_steer_projected(out, steer, land);
    return json_push_kv(out, "landing_steer", &none) &&
        json_push_kv_bool(out, "landing_steer_complete", false);
}

static const char *ft_land_row_state(const struct json_value *row,
    const struct json_value *proof, const char *section, long long observed,
    long long now, const char **reason, bool *identity)
{
    const char *state = ft_land_state(row, proof, section, now, reason);
    *identity = ft_identity(row, "tip") && ft_sha(ft_str(row, "tip"));
    if (!*identity) { state = "unknown"; *reason = "landing_identity_incomplete"; }
    if (strcmp(ft_fresh(observed, now), "fresh") != 0) {
        state = "unknown"; *reason = "source_observation_not_fresh";
    }
    return state;
}

static bool ft_land_row_projection(struct json_value *out,
    const struct json_value *row, const char *section, long long observed,
    long long now, const struct json_value *land)
{
    return ft_common(out, row, "dev.land", "tip", observed, now) &&
        ft_land_fields(out, row) && ft_land_history(out, row, section) &&
        ft_land_steer(out, row, land);
}

static void ft_land_row(struct zcl_fmc_tasks *v, const struct json_value *row,
    const struct json_value *proof, const char *section,
    long long observed, long long now, const struct json_value *land)
{
    struct json_value out = {0}, p = {0};
    const char *reason;
    bool identity;
    const char *state = ft_land_row_state(row, proof, section, observed, now,
        &reason, &identity);
    bool exact = ft_exact_proof(row, proof);
    bool ok = ft_proof_object(&p, proof, exact) &&
        ft_land_row_projection(&out, row, section, observed, now, land) &&
        json_push_kv_str(&out, "state", state) &&
        ft_land_column_priority(&out, section, state) &&
        json_push_kv_str(&out, "reason", reason) &&
        json_push_kv(&out, "proof", &p) &&
        ft_copy(&out, "owner", exact ? proof : NULL, "worker_id", JSON_INT) &&
        ft_land_disposition(&out, row, identity);
    if (!identity) v->malformed++;
    ft_add(v, &out, ok);
    json_free(&p);
    json_free(&out);
}

bool zcl_fmc_tasks_land(struct zcl_fmc_tasks *v, const struct json_value *land,
    const struct json_value *proof, long long observed, long long now)
{
    const char *const sections[] = {"queued", "outcomes"};
    bool ok = true;
    const struct json_value *flight = json_get(land, "in_flight");
    if (flight && flight->type == JSON_OBJ)
        ft_land_row(v, flight, proof, "in_flight", observed, now, land);
    else if (flight) ok = false;
    for (size_t s = 0; s < 2; s++) {
        const struct json_value *arr = json_get(land, sections[s]);
        if (!arr || arr->type != JSON_ARR) { ok = false; continue; }
        for (size_t i = 0; i < json_size(arr); i++)
            ft_land_row(v, json_at(arr, i), NULL, sections[s], observed, now, land);
    }
    v->land_ok = ok && (!flight || ft_exact_proof(flight, proof));
    return ok;
}

bool zcl_fmc_tasks_emit(const struct zcl_fmc_tasks *v, struct json_value *data)
{
    return json_push_kv(data, "tasks", &v->rows) &&
        json_push_kv_str(data, "tasks_scope", "local_active_queue_and_recent_land") &&
        json_push_kv_bool(data, "tasks_sources_complete", v->queue_ok &&
            v->land_ok && !v->dropped && !v->malformed) &&
        json_push_kv_bool(data, "tasks_inventory_complete", false) &&
        json_push_kv_str(data, "tasks_coverage_reason",
            "canonical_links_unavailable; landing_outcomes_last_10; remote_tasks_not_enumerated") &&
        json_push_kv_int(data, "tasks_observed", (long long)v->observed) &&
        json_push_kv_int(data, "tasks_dropped", (long long)v->dropped) &&
        json_push_kv_int(data, "tasks_malformed", (long long)v->malformed);
}

/* Human text is a rendering of the exact emitted object, never a second
 * classifier. Names are single-line; detail input remains structured JSON. */
static void ft_screen_number(long long value, char *out, size_t cap, const char *suffix)
{
    if (value >= 0) (void)snprintf(out, cap, "%lld%s", value, suffix);
    else (void)snprintf(out, cap, "unknown");
}

static void ft_screen_owner(const struct json_value *row, char *out, size_t cap)
{
    const struct json_value *o = json_get(row, "owner");
    if (o && o->type == JSON_INT)
        (void)snprintf(out, cap, "pid:%lld", (long long)json_get_int(o));
    else
        (void)snprintf(out, cap, "%.64s", ft_str(row, "owner")[0]
            ? ft_str(row, "owner") : "unknown");
}

static void ft_screen_dependency(const struct json_value *row, char *out, size_t cap)
{
    const struct json_value *blocker = json_get(row, "blocker");
    out[0] = '\0';
    if (!ft_str(blocker, "ref")[0]) return;
    char attempt[32];
    ft_screen_number(ft_int(blocker, "attempt"), attempt, sizeof(attempt), "");
    (void)snprintf(out, cap, "; dependency=%.128s a%s %.24s %.24s",
        ft_str(blocker, "ref"), attempt, ft_str(blocker, "state"), ft_str(blocker, "verdict"));
}

static void ft_screen_pair(const struct json_value *row, char *out, size_t cap)
{
    out[0] = '\0';
    if (strcmp(ft_str(row, "source"), "dev.land") != 0) return;
    const struct json_value *proof = json_get(row, "proof");
    (void)snprintf(out, cap,
        "; prepared=%.12s base=%.12s; proof=%.16s review=%.16s publication=%.16s; source_ts=%.20s",
        ft_str(row, "local")[0] ? ft_str(row, "local") : "unknown",
        ft_str(row, "base")[0] ? ft_str(row, "base") : "unknown",
        json_get_bool(json_get(proof, "exact_pair")) && ft_str(proof, "status")[0]
            ? ft_str(proof, "status") : "unknown",
        ft_str(row, "review"), ft_str(row, "publication"),
        ft_str(row, "source_ts")[0] ? ft_str(row, "source_ts") : "unknown");
}

static void ft_screen_next(const struct json_value *row, char *out, size_t cap)
{
    const struct json_value *detail = json_get(row, "detail");
    if (strcmp(ft_str(row, "next_safe_command"), "fleet.steer.evidence") == 0 &&
        ft_int(detail, "seq") > 0 && ft_int(detail, "attempt") > 0)
        (void)snprintf(out, cap, "; next=fleet steer evidence --type=%.8s --ref=%.128s --seq=%lld --attempt=%lld",
            ft_str(detail, "type"), ft_str(detail, "ref"),
            ft_int(detail, "seq"), ft_int(detail, "attempt"));
    else
        (void)snprintf(out, cap, "; next=%s", ft_str(row, "next_safe_command"));
}

static void ft_screen_line(const struct json_value *row, char *out, size_t cap)
{
    char owner[80], age[40], seq[32], attempt[32], dependency[240] = "";
    char pair[256] = "", next[320] = "";
    ft_screen_owner(row, owner, sizeof(owner));
    ft_screen_number(ft_int(row, "observed_age_s"), age, sizeof(age), "s");
    ft_screen_number(ft_int(row, "seq"), seq, sizeof(seq), "");
    ft_screen_number(ft_int(row, "attempt"), attempt, sizeof(attempt), "");
    ft_screen_dependency(row, dependency, sizeof(dependency));
    ft_screen_pair(row, pair, sizeof(pair));
    ft_screen_next(row, next, sizeof(next));
    (void)snprintf(out, cap,
        "  %s #%s a%s %.40s: %s%s%s; owner=%s; %.160s%s%s; observed=%s %s%s%s",
        ft_str(row, "source"), seq, attempt, ft_str(row, "ref"),
        json_get_bool(json_get(row, "historical")) ? "history " : "",
        ft_str(row, "state"), ft_str(row, "recorded_state")[0] ? " (see recorded_state)" : "",
        owner, json_get_bool(json_get(row, "historical")) ? ft_str(row, "recorded_state") : ft_str(row, "reason"),
        dependency, pair, age, ft_str(row, "freshness"),
        json_get_bool(json_get(row, "incomplete")) ? "; incomplete" : "", next);
    for (size_t i = 0; out[i]; i++)
        if ((unsigned char)out[i] < 32 || out[i] == 127) out[i] = ' ';
}

static size_t ft_screen_coverage(const struct json_value *data, char *out, size_t cap)
{
    int n = snprintf(out, cap, "Local tasks (partial inventory): %zu shown; sources=%s\n",
        json_size(json_get(data, "tasks")),
        json_get_bool(json_get(data, "tasks_sources_complete")) ? "observed" : "incomplete");
    if (n < 0 || (size_t)n >= cap) return cap;
    size_t used = (size_t)n;
    const struct json_value *missing = json_get(data, "missing");
    for (size_t i = 0; i < json_size(missing); i++) {
        const struct json_value *row = json_at(missing, i);
        const char *source = ft_str(row, "source");
        if (strcmp(source, "dev.agent.queue") != 0 &&
            strcmp(source, "dev.land") != 0 && strcmp(source, "dev.proof.status") != 0)
            continue;
        n = snprintf(out + used, cap - used, "  unavailable %s: %.128s\n", source, ft_str(row, "reason"));
        if (n < 0 || (size_t)n >= cap - used) return cap;
        used += (size_t)n;
    }
    return used;
}

void zcl_fmc_tasks_screen(const struct json_value *data, char *out, size_t cap)
{
    if (!out || !cap) return;
    out[0] = '\0';
    const struct json_value *rows = json_get(data, "tasks");
    size_t used = ft_screen_coverage(data, out, cap);
    if (used >= cap) return;
    for (size_t i = 0; i < json_size(rows); i++) {
        char line[2048];
        ft_screen_line(json_at(rows, i), line, sizeof(line));
        size_t length = strlen(line);
        if (length + 96 >= cap - used) {
            (void)snprintf(out + used, cap - used, "  More task detail remains in tasks[]\n");
            break;
        }
        memcpy(out + used, line, length);
        used += length;
        out[used++] = '\n'; out[used] = '\0';
    }
}
