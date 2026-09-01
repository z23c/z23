/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * core.status.brief body — split out of status_native_handlers.c (E1 file
 * size ceiling) so it can grow its own field list without pushing the other
 * read compositions over the 800-line cap.
 *
 * A compact FLAT projection of the sync/serving fields an operator or AI
 * checks on every call. The running node already maintains those facts in
 * its bounded cached `agent` document, so this projection performs one RPC
 * and validates that document strictly. Unsupported methods, RPC errors,
 * wrong schemas, and missing required fields fail closed; they never become
 * a passing result full of "unknown" values.
 */

#include "controllers/status_native_handlers.h"
#include "controllers/agent_operator_contracts.h"
#include "controllers/native_handler_body.h"
#include "controllers/status_native_helpers.h"
#include "status_brief_readiness_read.h"

#include "json/json.h"
#include "controllers/rpc_client.h"
#include "util/log_macros.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool status_schema_is(const struct json_value *obj,
                             const char *expected)
{
    const char *schema = obj && obj->type == JSON_OBJ
        ? json_get_str(json_get(obj, "schema")) : NULL;
    return schema && expected && strcmp(schema, expected) == 0;
}

/* The two versions this handler validates STRICTLY: the current one it
 * produces (v3) and the previous one it still fully reads (v2). The v3
 * additions are optional on the read side, so one SCHECK() chain serves both
 * — a v2 document from an older node still yields a complete brief, minus
 * only the v3 readiness facts. */
static bool status_schema_is_strictly_read(const struct json_value *obj)
{
    return status_schema_is(obj, ZCL_PUBLIC_STATUS_SCHEMA) ||
           status_schema_is(obj, ZCL_PUBLIC_STATUS_SCHEMA_V2);
}

/* Name the contract version the document actually declared, so a v2 node's
 * strict-validation error says v2 and not the version this build happens to
 * target. Only ever echoes a version this build strictly reads — never
 * arbitrary text from the response — so the message stays a fixed token. */
static const char *status_schema_seen(const struct json_value *obj)
{
    if (status_schema_is(obj, ZCL_PUBLIC_STATUS_SCHEMA_V2))
        return ZCL_PUBLIC_STATUS_SCHEMA_V2;
    return ZCL_PUBLIC_STATUS_SCHEMA;
}

/* True for any schema string in the known zcl.public_status.* family that is
 * NOT one of the versions this handler validates strictly (e.g. an older
 * node's "zcl.public_status.v1", or a future "...v4"). This is the
 * present-but-different-version case: a real document from a real status
 * producer, just not one the CLI's strict validator was written against.
 * See status_brief_build_schema_skew_body(). */
static bool status_schema_known_family_mismatch(const struct json_value *obj,
                                                 const char **schema_out)
{
    const char *schema = obj && obj->type == JSON_OBJ
        ? json_get_str(json_get(obj, "schema")) : NULL;
    if (!schema || !schema[0])
        return false;
    if (status_schema_is_strictly_read(obj))
        return false;
    if (strncmp(schema, ZCL_PUBLIC_STATUS_SCHEMA_FAMILY,
               strlen(ZCL_PUBLIC_STATUS_SCHEMA_FAMILY)) != 0)
        return false;
    if (schema_out)
        *schema_out = schema;
    return true;
}

/* Front-door deadline for core.status.brief's one RPC ("agent"): the whole
 * point of a flagless `z23 status` is to answer almost immediately,
 * even against a busy/wedged node — never ride the generic 10s
 * (ZCL_RPC_DEADLINE_MS) ceiling every other command tolerates. Overridable
 * for tests; clamped to a sane floor/ceiling like every other RPC deadline
 * knob in rpc_client.c. */
#define ZCL_STATUS_DEADLINE_MS_DEFAULT 250

static long status_front_door_deadline_ms(void)
{
    const char *v = getenv("ZCL_STATUS_DEADLINE_MS");
    if (v && v[0]) {
        char *end = NULL;
        long parsed = strtol(v, &end, 10);
        if (end && *end == 0 && parsed >= 10 && parsed <= 60000)
            return parsed;
    }
    return ZCL_STATUS_DEADLINE_MS_DEFAULT;
}

/* zcl.public_status.v2 carries a numeric sentinel beside an explicit
 * `<field>_known` bit.  The bit is authoritative: an unavailable height is a
 * valid status fact and projects as null, while `known=true` with a negative
 * sentinel is malformed source/runtime skew. */
static bool status_read_known_height(const struct json_value *obj,
                                     const char *value_key,
                                     const char *known_key,
                                     int64_t *value_out, bool *known_out)
{
    const struct json_value *value = obj ? json_get(obj, value_key) : NULL;
    bool known = false;
    if (!value || value->type != JSON_INT || value->val.i < -1 ||
        value->val.i > INT_MAX ||
        !status_read_bool(obj, known_key, &known) ||
        (known && value->val.i < 0))
        return false;
    if (value_out)
        *value_out = value->val.i;
    if (known_out)
        *known_out = known;
    return true;
}

static bool status_read_optional_nonnegative(const struct json_value *obj,
                                             const char *key,
                                             int64_t *value_out,
                                             bool *known_out)
{
    const struct json_value *value = obj ? json_get(obj, key) : NULL;
    if (!value || value->type != JSON_INT || value->val.i < -1)
        return false;
    if (value_out)
        *value_out = value->val.i;
    if (known_out)
        *known_out = value->val.i >= 0;
    return true;
}

/* Status prose is a one-line machine surface.  Reject runtime-skew strings
 * that could inject whitespace/control text into key=value output. */
static bool status_machine_token(const char *value)
{
    if (!value || !value[0])
        return false;
    size_t n = strlen(value);
    if (n > 127)
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)value[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' ||
              c == '.' || c == ':'))
            return false;
    }
    return true;
}

/* ── Named-predicate validation ────────────────────────────────────
 *
 * zcl.public_status.v2 is validated by a long ordered list of
 * predicates. A single giant `&&` chain is unsafe here: whichever
 * predicate fails, the operator/AI would only ever see one
 * opaque message ("RPC agent returned an error or invalid
 * zcl.public_status.v2") with no clue which field was the problem —
 * including the common case of an older node binary whose `agent` RPC
 * predates a field the CLI now requires.
 *
 * `status_validate` tracks the FIRST predicate that fails: its field
 * name (for the error message) and whether the underlying JSON key
 * was entirely ABSENT (as opposed to present-but-malformed). Absent +
 * schema-matches is schema/version skew — the node binary predates
 * the CLI contract; present-but-wrong is a malformed/self-contradictory
 * document. The SCHECK() macro below turns each conjunct of the
 * former `&&` chain into a named, order-preserving, short-circuiting
 * check: once one predicate has failed, every later SCHECK() is a
 * no-op that does not evaluate its condition (so it stays safe to
 * dereference sub-objects the earlier checks proved exist). */
struct status_validate {
    bool failed;
    bool version_skew; /* first failing key was absent, not malformed */
    char field[96];
};

static bool status_key_missing(const struct json_value *obj, const char *key)
{
    return !obj || obj->type != JSON_OBJ || json_get(obj, key) == NULL;
}

static bool status_note_fail(struct status_validate *v, const char *field,
                             bool missing)
{
    if (!v->failed) {
        v->failed = true;
        v->version_skew = missing;
        (void)snprintf(v->field, sizeof(v->field), "%s", field);
    }
    return false;
}

/* `missing`/`cond` are only evaluated once v->failed is false, so this
 * is safe to chain even when later conds read through an object an
 * earlier failed check would have left NULL. */
#define SCHECK(v, field, missing, cond) \
    ((v)->failed ? false : ((cond) ? true : status_note_fail((v), (field), (missing))))

/* ── Shared body composition ───────────────────────────────────────
 *
 * Both the strict zcl.public_status.v2 path and the degraded schema-skew
 * path (a present-but-different-version schema, see
 * status_schema_known_family_mismatch) end up emitting the same flat
 * thirteen-field brief. This is that one shared composer, plus the typed-
 * blocker-registry sub-read both paths reuse — the schema-skew path just
 * populates every field with lenient/optional reads instead of the strict
 * SCHECK() chain above. */

struct status_brief_blocker_registry {
    bool known;
    int64_t active_blockers;
    const char *head;      /* points into the source `agent` document */
    bool overdue_known;
    int64_t overdue_count;
    const char *overdue_id; /* points into the source `agent` document */
};

/* Typed-blocker-registry head + count, from the same authority as
 * `dumpstate blocker`. Read OPTIONALLY (an older node predating this
 * contract simply omits the sub-object) so the two operator surfaces
 * always agree on the registry head instead of naming disjoint truths. */
static void status_brief_blocker_registry_read(
    const struct json_value *agent,
    struct status_brief_blocker_registry *out)
{
    *out = (struct status_brief_blocker_registry){0};
    const struct json_value *blocker_registry =
        json_get(agent, "blocker_registry");
    if (!blocker_registry || blocker_registry->type != JSON_OBJ)
        return;
    out->known = status_read_nonnegative_int(blocker_registry,
                                             "active_count",
                                             &out->active_blockers);
    const char *head =
        json_get_str(json_get(blocker_registry, "dominant_id"));
    if (head && head[0])
        out->head = head;
    /* POINT 3.4: overdue_transient_count surfaces the same registry truth
     * for TRANSIENT/DEPENDENCY blockers stuck past their deadline/TTL (see
     * agent_blocker_is_overdue_transient in event_agent_summary.c). A
     * TRANSIENT never becomes `primary_blocker`, so without this an
     * overdue transient could sit invisible behind a "healthy" brief. */
    out->overdue_known = status_read_nonnegative_int(
        blocker_registry, "overdue_transient_count", &out->overdue_count);
    const char *odom = json_get_str(
        json_get(blocker_registry, "overdue_transient_dominant_id"));
    if (odom && odom[0] && strcmp(odom, "none") != 0)
        out->overdue_id = odom;
}

/* Trust-tier surface, OPTIONAL on both `agent` sub-objects it reads:
 *   - agent.trust_tier (event_agent_summary.c, schema "zcl.trust_tier.v1") —
 *     trust_mode and the comma-joined denied-capability list.
 *   - agent.security_posture.{snapshot_anchor_height,
 *     background_validation_height} — the same two heights the posture
 *     surface already carries, read here as "install_height"/
 *     "verified_height" for the flat brief.
 * An older node predating either field simply omits it — `known` stays
 * false and status_brief_compose_body omits the flattened key, same
 * optional-sub-object contract as status_brief_blocker_registry_read. */
struct status_brief_trust_tier {
    bool known;                  /* agent.trust_tier sub-object was present */
    const char *tier;            /* trust_tier.trust_mode; points into agent */
    int64_t install_height; bool install_known;
    int64_t verified_height; bool verified_known;
    const char *capabilities_locked; /* trust_tier.capabilities_denied */
};

static void status_brief_trust_tier_read(const struct json_value *agent,
                                         const struct json_value *security,
                                         struct status_brief_trust_tier *out)
{
    *out = (struct status_brief_trust_tier){0};
    const struct json_value *tt = json_get(agent, "trust_tier");
    if (tt && tt->type == JSON_OBJ) {
        out->known = true;
        const char *tier = json_get_str(json_get(tt, "trust_mode"));
        if (tier && status_machine_token(tier))
            out->tier = tier;
        const char *locked =
            json_get_str(json_get(tt, "capabilities_denied"));
        if (locked)
            out->capabilities_locked = locked;
    }
    (void)status_read_optional_nonnegative(security, "snapshot_anchor_height",
                                           &out->install_height,
                                           &out->install_known);
    (void)status_read_optional_nonnegative(security,
                                           "background_validation_height",
                                           &out->verified_height,
                                           &out->verified_known);
}

struct status_brief_fields {
    int64_t served_height; bool served_known;
    int64_t header_height; bool header_known;
    int64_t gap; bool gap_known;
    int64_t peer_best; bool peer_best_known;
    const char *sync_state;
    bool serving;
    bool healthy;
    int64_t peer_count;
    const char *primary_blocker;
    int64_t active_conditions;
    int64_t rss_mb; bool rss_known;
    int64_t tip_advance_age_seconds; bool tip_age_known;
    struct status_brief_blocker_registry registry;
    struct status_brief_trust_tier trust_tier;
    struct status_brief_readiness_facts readiness;
    /* NULL on the strict-v2 path; the mismatched schema string on the
     * degraded schema-skew path — adds `partial_result`/`schema_skew` to
     * the emitted body so the operator/AI can tell "old/new but fine"
     * from "actually broken". */
    const char *schema_skew;
};

static char *status_brief_compose_body(const struct status_brief_fields *f,
                                       struct zcl_native_body_err *err)
{
    struct json_value root;
    json_init(&root);
    json_set_object(&root);
    status_push_int_if_known(&root, "hstar", f->served_known,
                             f->served_height);
    status_push_int_if_known(&root, "header_height", f->header_known,
                             f->header_height);
    status_push_int_if_known(&root, "gap", f->gap_known, f->gap);
    status_push_int_if_known(&root, "peer_best", f->peer_best_known,
                             f->peer_best);
    json_push_kv_str(&root, "sync_state", f->sync_state);
    json_push_kv_bool(&root, "serving", f->serving);
    json_push_kv_bool(&root, "healthy", f->healthy);
    json_push_kv_int(&root, "peer_count", f->peer_count);
    json_push_kv_str(&root, "primary_blocker", f->primary_blocker);
    /* The full agent contract does not yet export the dominant blocker's
     * capture age. Tip-stall age is a different fact and must not be passed
     * off as blocker age. */
    status_push_int_if_known(&root, "blocker_age_s", false, 0);
    /* Registry head shown beside primary_blocker so the brief and
     * `dumpstate blocker` never present disjoint truths. Both fields are
     * OMITTED (never null) when the node predates the registry export —
     * the documented optional-sub-object contract. */
    if (f->registry.known)
        json_push_kv_int(&root, "active_blockers", f->registry.active_blockers);
    if (f->registry.head)
        json_push_kv_str(&root, "blocker_head", f->registry.head);
    if (f->registry.overdue_known)
        json_push_kv_int(&root, "overdue_transient_count",
                         f->registry.overdue_count);
    if (f->registry.overdue_count > 0) {
        char note[128];
        (void)snprintf(note, sizeof(note),
                      "%lld transient blockers overdue: %s",
                      (long long)f->registry.overdue_count,
                      f->registry.overdue_id ? f->registry.overdue_id
                                             : "unknown");
        json_push_kv_str(&root, "overdue_transient_note", note);
    }
    json_push_kv_int(&root, "active_conditions", f->active_conditions);
    status_push_int_if_known(&root, "rss_mb", f->rss_known, f->rss_mb);
    status_push_int_if_known(&root, "tip_advance_age_seconds",
                             f->tip_age_known, f->tip_advance_age_seconds);
    /* Trust-tier surface: OMITTED (never null), same convention as the
     * blocker_registry sub-fields above, on an older node that predates
     * agent.trust_tier / the two security_posture heights — these are a
     * newer optional facet, not part of the always-present v2 core (unlike
     * hstar/header_height/gap, which use status_push_int_if_known's
     * always-present-possibly-null convention because the v2 schema has
     * always carried them). */
    if (f->trust_tier.tier)
        json_push_kv_str(&root, "tier", f->trust_tier.tier);
    if (f->trust_tier.install_known)
        json_push_kv_int(&root, "install_height",
                         f->trust_tier.install_height);
    if (f->trust_tier.verified_known)
        json_push_kv_int(&root, "verified_height",
                         f->trust_tier.verified_height);
    if (f->trust_tier.capabilities_locked)
        json_push_kv_str(&root, "capabilities_locked",
                         f->trust_tier.capabilities_locked);
    /* The v3 readiness facts, each emitted separately and only when the
     * producer actually reported it. They are never combined into a single
     * verdict here — that collapse is the bug this surface exists to fix. */
    if (f->readiness.tip_follow_known)
        json_push_kv_bool(&root, "tip_follow", f->readiness.tip_follow);
    if (f->readiness.wallet_view_known)
        json_push_kv_bool(&root, "wallet_view_ready",
                          f->readiness.wallet_view_ready);
    if (f->readiness.wallet_spend_known)
        json_push_kv_bool(&root, "wallet_spend_allowed",
                          f->readiness.wallet_spend_allowed);
    if (f->readiness.archive_complete)
        json_push_kv_str(&root, "archive_complete",
                         f->readiness.archive_complete);
    if (f->readiness.full_replay_known)
        json_push_kv_bool(&root, "full_replay_verified",
                          f->readiness.full_replay_verified);
    if (f->schema_skew) {
        json_push_kv_bool(&root, "partial_result", true);
        json_push_kv_str(&root, "schema_skew", f->schema_skew);
    }

    char *out = zcl_json_value_to_body(&root, "status_brief_body");
    json_free(&root);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "malloc failed for %s", "status brief response");
        LOG_NULL("native.ops", "malloc failed for %s", "status brief response");
    }
    return out;
}

/* A present schema in the known zcl.public_status.* family, but not the
 * exact version the SCHECK() chain above validates strictly (an older
 * node's v1, a newer node's v3, ...). Every field here is read LENIENTLY
 * with the same optional-field readers the strict path uses for genuinely-
 * optional sub-objects (status_read_known_height, status_read_nonnegative_int,
 * status_json_bool, ...): a field that fails to parse is simply "unknown",
 * never a hard fail. This is a best-effort degraded view of a document from
 * a status contract this CLI build doesn't fully recognize — not the
 * validated zcl.public_status.v2 contract, so it never enforces that
 * contract's cross-field arithmetic (e.g. gap == header - served). */
static char *status_brief_build_schema_skew_body(
    const struct json_value *agent, const char *schema,
    struct zcl_native_body_err *err)
{
    struct status_brief_fields f = {0};
    f.served_height = -1;
    f.header_height = -1;

    (void)status_read_known_height(agent, "served_height",
                                   "served_height_known", &f.served_height,
                                   &f.served_known);
    (void)status_read_known_height(agent, "header_height",
                                   "header_height_known", &f.header_height,
                                   &f.header_known);
    (void)status_read_known_height(agent, "peer_best_height",
                                   "peer_best_height_known", &f.peer_best,
                                   &f.peer_best_known);
    f.gap_known = status_read_nonnegative_int(agent, "gap", &f.gap);

    const char *sync_state = json_get_str(json_get(agent, "sync_state"));
    f.sync_state = status_machine_token(sync_state) ? sync_state : NULL;
    const char *primary_blocker =
        json_get_str(json_get(agent, "primary_blocker"));
    f.primary_blocker = status_machine_token(primary_blocker)
        ? primary_blocker : NULL;

    f.serving = status_json_bool(agent, "serving", false);
    f.healthy = status_json_bool(agent, "healthy", false);

    (void)status_read_nonnegative_int(json_get(agent, "peers"), "total",
                                      &f.peer_count);
    (void)status_read_nonnegative_int(json_get(agent, "conditions"),
                                      "active_count", &f.active_conditions);
    (void)status_read_optional_nonnegative(json_get(agent, "resources"),
                                           "rss_mb", &f.rss_mb,
                                           &f.rss_known);
    (void)status_read_optional_nonnegative(json_get(agent, "reducer"),
                                           "tip_advance_age_seconds",
                                           &f.tip_advance_age_seconds,
                                           &f.tip_age_known);
    status_brief_blocker_registry_read(agent, &f.registry);
    status_brief_trust_tier_read(agent, json_get(agent, "security_posture"),
                                 &f.trust_tier);
    status_brief_readiness_facts_read(agent, &f.readiness);
    f.schema_skew = schema;

    return status_brief_compose_body(&f, err);
}

char *zcl_native_status_brief_body(const struct json_value *args,
                                   struct zcl_native_body_err *err)
{
    (void)args;
    if (!err)
        LOG_NULL("native.status", "status brief missing error sink");

    /* The flagless front door: always answer fast, even against a busy/
     * wedged node, rather than ride the generic 10s RPC ceiling every other
     * command tolerates (see status_front_door_deadline_ms()). */
    long deadline_ms = status_front_door_deadline_ms();
    char *raw = node_rpc_call_deadline("agent", NULL, deadline_ms,
                                       deadline_ms);
    struct json_value agent;
    json_init(&agent);
    bool parsed = status_parse_rpc_json(&agent, raw, JSON_OBJ);

    /* A PRESENT schema that names the known zcl.public_status.* family but
     * isn't the exact version validated below (an older node's v1, a
     * newer node's v3, ...) is version skew, not corruption — degrade
     * gracefully instead of hard-failing with "missing/invalid field
     * schema". An ABSENT schema, or one outside the family entirely, falls
     * through to the strict validator unchanged. */
    const char *schema_skew = NULL;
    if (parsed && status_schema_known_family_mismatch(&agent, &schema_skew)) {
        char *out = status_brief_build_schema_skew_body(&agent, schema_skew,
                                                         err);
        json_free(&agent);
        free(raw);
        return out;
    }

    const struct json_value *peers = parsed ? json_get(&agent, "peers") : NULL;
    const struct json_value *conditions =
        parsed ? json_get(&agent, "conditions") : NULL;
    const struct json_value *resources =
        parsed ? json_get(&agent, "resources") : NULL;
    const struct json_value *reducer =
        parsed ? json_get(&agent, "reducer") : NULL;
    const struct json_value *security =
        parsed ? json_get(&agent, "security_posture") : NULL;
    const struct json_value *first_call =
        parsed ? json_get(&agent, "first_call") : NULL;

    int64_t served_height = -1, header_height = -1, gap = 0;
    int64_t target_height = -1;
    int64_t peer_best = 0, peer_count = 0, active_conditions = 0;
    int64_t rss_mb = 0, tip_advance_age_seconds = 0;
    int64_t first_call_budget_ms = 0;
    bool served_known = false, header_known = false, peer_best_known = false;
    bool target_known = false, gap_known = false, rss_known = false;
    bool tip_age_known = false, chain_evidence_consistent = false;
    bool partial_result = false, first_call_partial = false;
    bool serving = false, healthy = false, anchor_gap = false;
    bool nullifier_gap = false, budget_exceeded = true;
    const char *sync_state = parsed
        ? json_get_str(json_get(&agent, "sync_state")) : NULL;
    const char *reported_blocker = parsed
        ? json_get_str(json_get(&agent, "primary_blocker")) : NULL;

    bool resources_shape_ok = resources && resources->type == JSON_OBJ &&
        status_schema_is(resources, "zcl.node_resources.v1") &&
        status_read_optional_nonnegative(resources, "rss_mb", &rss_mb,
                                         &rss_known);

    struct status_validate v = {0};
    bool valid = parsed &&
        SCHECK(&v, "schema", status_key_missing(&agent, "schema"),
              status_schema_is_strictly_read(&agent)) &&
        SCHECK(&v, "served_height_known",
              status_key_missing(&agent, "served_height") ||
                  status_key_missing(&agent, "served_height_known"),
              status_read_known_height(&agent, "served_height",
                                       "served_height_known", &served_height,
                                       &served_known)) &&
        SCHECK(&v, "header_height_known",
              status_key_missing(&agent, "header_height") ||
                  status_key_missing(&agent, "header_height_known"),
              status_read_known_height(&agent, "header_height",
                                       "header_height_known", &header_height,
                                       &header_known)) &&
        SCHECK(&v, "gap", status_key_missing(&agent, "gap"),
              status_read_nonnegative_int(&agent, "gap", &gap)) &&
        SCHECK(&v, "peer_best_height_known",
              status_key_missing(&agent, "peer_best_height") ||
                  status_key_missing(&agent, "peer_best_height_known"),
              status_read_known_height(&agent, "peer_best_height",
                                       "peer_best_height_known", &peer_best,
                                       &peer_best_known)) &&
        SCHECK(&v, "target_height_known",
              status_key_missing(&agent, "target_height") ||
                  status_key_missing(&agent, "target_height_known"),
              status_read_known_height(&agent, "target_height",
                                       "target_height_known", &target_height,
                                       &target_known)) &&
        SCHECK(&v, "chain_evidence_consistent",
              status_key_missing(&agent, "chain_evidence_consistent"),
              status_read_bool(&agent, "chain_evidence_consistent",
                               &chain_evidence_consistent)) &&
        SCHECK(&v, "partial_result",
              status_key_missing(&agent, "partial_result"),
              status_read_bool(&agent, "partial_result", &partial_result)) &&
        SCHECK(&v, "serving", status_key_missing(&agent, "serving"),
              status_read_bool(&agent, "serving", &serving)) &&
        SCHECK(&v, "healthy", status_key_missing(&agent, "healthy"),
              status_read_bool(&agent, "healthy", &healthy)) &&
        SCHECK(&v, "sync_state", status_key_missing(&agent, "sync_state"),
              status_machine_token(sync_state)) &&
        SCHECK(&v, "primary_blocker",
              status_key_missing(&agent, "primary_blocker"),
              status_machine_token(reported_blocker)) &&
        SCHECK(&v, "peers", status_key_missing(&agent, "peers"),
              peers && peers->type == JSON_OBJ) &&
        SCHECK(&v, "conditions", status_key_missing(&agent, "conditions"),
              conditions && conditions->type == JSON_OBJ) &&
        SCHECK(&v, "conditions.schema",
              status_key_missing(conditions, "schema"),
              status_schema_is(conditions,
                               "zcl.condition_engine_summary.v2")) &&
        SCHECK(&v, "reducer", status_key_missing(&agent, "reducer"),
              reducer && reducer->type == JSON_OBJ) &&
        SCHECK(&v, "security_posture",
              status_key_missing(&agent, "security_posture"),
              security && security->type == JSON_OBJ) &&
        SCHECK(&v, "security_posture.schema",
              status_key_missing(security, "schema"),
              status_schema_is(security, "zcl.security_posture.v1")) &&
        SCHECK(&v, "first_call", status_key_missing(&agent, "first_call"),
              first_call && first_call->type == JSON_OBJ) &&
        SCHECK(&v, "first_call.schema",
              status_key_missing(first_call, "schema"),
              status_schema_is(first_call, "zcl.first_call_contract.v1")) &&
        SCHECK(&v, "peers.total", status_key_missing(peers, "total"),
              status_read_nonnegative_int(peers, "total", &peer_count)) &&
        SCHECK(&v, "conditions.active_count",
              status_key_missing(conditions, "active_count"),
              status_read_nonnegative_int(conditions, "active_count",
                                          &active_conditions)) &&
        SCHECK(&v, "reducer.tip_advance_age_seconds",
              status_key_missing(reducer, "tip_advance_age_seconds"),
              status_read_optional_nonnegative(
                  reducer, "tip_advance_age_seconds",
                  &tip_advance_age_seconds, &tip_age_known)) &&
        SCHECK(&v, "security_posture.anchor_backfill_gap",
              status_key_missing(security, "anchor_backfill_gap"),
              status_read_bool(security, "anchor_backfill_gap",
                               &anchor_gap)) &&
        SCHECK(&v, "security_posture.nullifier_backfill_gap",
              status_key_missing(security, "nullifier_backfill_gap"),
              status_read_bool(security, "nullifier_backfill_gap",
                               &nullifier_gap)) &&
        SCHECK(&v, "first_call.budget_ms",
              status_key_missing(first_call, "budget_ms"),
              status_read_nonnegative_int(first_call, "budget_ms",
                                          &first_call_budget_ms)) &&
        SCHECK(&v, "first_call.budget_ms", false, first_call_budget_ms > 0) &&
        SCHECK(&v, "first_call.partial_result",
              status_key_missing(first_call, "partial_result"),
              status_read_bool(first_call, "partial_result",
                               &first_call_partial)) &&
        SCHECK(&v, "first_call.budget_exceeded",
              status_key_missing(first_call, "budget_exceeded"),
              status_read_bool(first_call, "budget_exceeded",
                               &budget_exceeded)) &&
        /* budget_exceeded is a pure timing fact (elapsed > budget_ms) and is
         * ORTHOGONAL to completeness: a busy node whose cached-field collect
         * contends cs_main can overrun 250ms while still gathering every
         * field, so budget_exceeded=true with partial_result=false is a
         * truthful slow-but-complete result, not self-contradiction. (This
         * false coupling made the flagless status of a folding node fail with
         * a cryptic "missing/invalid field first_call.budget_exceeded" after
         * several seconds instead of returning the real, complete brief.)
         * Data completeness is enforced independently by the resources check
         * below (`resources` must be present unless partial_result), so no
         * budget-vs-partial cross-check is needed or correct here. */
        SCHECK(&v, "first_call.partial_result", false,
              first_call_partial == partial_result) &&
        SCHECK(&v, "resources", status_key_missing(&agent, "resources"),
              resources_shape_ok || (partial_result && !resources)) &&
        SCHECK(&v, "partial_reason",
              status_key_missing(&agent, "partial_reason"),
              !partial_result ||
                  (json_get_str(json_get(&agent, "partial_reason")) != NULL &&
                   json_get_str(json_get(&agent, "partial_reason"))[0])) &&
        SCHECK(&v, "served_height_known", false, !serving || served_known) &&
        SCHECK(&v, "healthy", false, !healthy || serving) &&
        SCHECK(&v, "security_posture.anchor_backfill_gap", false,
              (!anchor_gap && !nullifier_gap) || !healthy);

    if (valid) {
        gap_known = chain_evidence_consistent;
        /* A consistent local chain has target==header and an exact arithmetic
         * gap.  An inconsistent/unknown chain is emitted as null and the
         * producer's sentinel gap must remain zero. */
        valid = SCHECK(&v, "gap", false,
                       gap_known
                           ? served_known && header_known && target_known &&
                             target_height == header_height &&
                             header_height >= served_height &&
                             gap == header_height - served_height
                           : gap == 0);
    }

    if (!valid) {
        /* Transport absence is transient; a parsed document that violates
         * this build's strict contract is an internal producer/consumer
         * mismatch and must not invite a blind retry. The native bridge maps
         * these two statuses into retryable:true vs false. */
        err->status = parsed ? ZCL_NATIVE_BODY_INTERNAL
                             : ZCL_NATIVE_BODY_UNAVAILABLE;
        if (!parsed) {
            /* `parsed` is false for two very different situations that must
             * not both read as a schema fault: an unparsable byte stream, or
             * a well-formed transport/RPC error object (node not running,
             * connect refused/timed out, response deadline exceeded, cookie
             * unreadable). Surface the transport reason verbatim when we have
             * one -- that is the honest "no live node / node busy" answer the
             * operator needs, not "invalid zcl.public_status.vN". */
            const char *rpc_err = NULL;
            if (agent.type == JSON_OBJ) {
                const struct json_value *e = json_get(&agent, "error");
                rpc_err = json_get_str(json_get(
                    e && e->type == JSON_OBJ ? e : &agent, "message"));
            }
            if (rpc_err && rpc_err[0])
                (void)snprintf(err->message, sizeof(err->message),
                              "node status unavailable: %s", rpc_err);
            else
                (void)snprintf(err->message, sizeof(err->message),
                              "node status unavailable: RPC agent returned an "
                              "unparsable response");
        } else if (v.version_skew) {
            (void)snprintf(err->message, sizeof(err->message),
                          "invalid %s: node binary "
                          "predates the CLI contract (missing field %s)",
                          status_schema_seen(&agent), v.field);
        } else {
            (void)snprintf(err->message, sizeof(err->message),
                          "invalid %s: missing/invalid "
                          "field %s", status_schema_seen(&agent), v.field);
        }
        /* err->message now owns a copy of any rpc_err text, so the source
         * document is safe to release before LOG_NULL returns NULL. */
        json_free(&agent);
        free(raw);
        LOG_NULL("native.status", "%s", err->message);
    }

    /* Permanent independently-diagnosed shielded-history incompleteness is
     * causal. Rank it above downstream queue/download symptoms from the
     * general operator latch. */
    const char *primary_blocker = anchor_gap
        ? "utxo_apply.anchor_backfill_gap"
        : nullifier_gap ? "utxo_apply.nullifier_backfill_gap"
        : reported_blocker;

    struct status_brief_fields f = {
        .served_height = served_height, .served_known = served_known,
        .header_height = header_height, .header_known = header_known,
        .gap = gap, .gap_known = gap_known,
        .peer_best = peer_best, .peer_best_known = peer_best_known,
        .sync_state = sync_state,
        .serving = serving,
        .healthy = healthy,
        .peer_count = peer_count,
        .primary_blocker = primary_blocker,
        .active_conditions = active_conditions,
        .rss_mb = rss_mb, .rss_known = rss_known,
        .tip_advance_age_seconds = tip_advance_age_seconds,
        .tip_age_known = tip_age_known,
        .schema_skew = NULL,
    };
    /* `f.registry.head`/`overdue_id`/`f.trust_tier.*` point into `agent`,
     * which stays alive until after status_brief_compose_body() serializes
     * them below (json_push_kv_str copies the string). Both reads are
     * lenient/OPTIONAL — never part of the strict SCHECK() chain above, so
     * an older node missing either sub-object does not fail validation. */
    status_brief_blocker_registry_read(&agent, &f.registry);
    status_brief_trust_tier_read(&agent, security, &f.trust_tier);
    /* v3 facts, OPTIONAL: a strictly-valid v2 document omits all five and
     * still produces a complete brief — that is the retained v2 reader. */
    status_brief_readiness_facts_read(&agent, &f.readiness);

    char *out = status_brief_compose_body(&f, err);
    json_free(&agent);
    free(raw);
    return out;
}
