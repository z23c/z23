// one-result-type-ok:refusals-travel-as-named-tokens — the parser reads an
// UNTRUSTED peer document, so its refusal must be allocation-free and
// caller-visible: it lands in reason_out as a static token. A formatted
// zcl_result on that path would be a log-flood surface, not a better answer.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mesh_observation serialization — ONE emitter and ONE bounded parser.
 *
 * The same mesh_observation_emit_json() feeds both the dumpstate body
 * (`ops state --subsystem=mesh_observation`) and the document served at
 * <self>.onion/observation.json, so the two can never drift apart.
 *
 * Enums cross the wire as the static token strings below, never as
 * integers: a reader on an older build sees "deadline_expired" and can
 * refuse it BY NAME rather than mis-decoding a number.
 *
 * The emitted document contains no `pass`, no `fail`, no `verdict`, no
 * `healthy`, no aggregate "good peers" count, and deliberately no
 * `reachable` boolean. A measurement is always published beside the budget
 * that bounded it, and a peer's claim is always published as a claim.
 *
 * mesh_observation_parse_json() reads an UNTRUSTED peer document. Every
 * refusal is a distinct static token and leaves the caller's struct
 * completely unmodified — a malformed field is never guessed at, and a
 * short read is never rounded up to a healthy-looking record.
 */

#include "services/mesh_observation.h"

#include "json/json.h"

#include <stdint.h>
#include <string.h>

const int32_t MESH_OBS_ANCHOR_BACK[MESH_OBS_ANCHORS] = { 0, 1, 6, 30, 144 };

/* ── static tokens ──────────────────────────────────────────────────── */

static const char *const k_stage_tok[MESH_STAGE_NUM] = {
    [MESH_STAGE_NONE]               = "none",
    [MESH_STAGE_DESCRIPTOR]         = "descriptor",
    [MESH_STAGE_RENDEZVOUS]         = "rendezvous",
    [MESH_STAGE_CIRCUIT]            = "circuit",
    [MESH_STAGE_LISTEN]             = "listen",
    [MESH_STAGE_READY]              = "ready",
    [MESH_STAGE_DIALED]             = "dialed",
    [MESH_STAGE_VERSION_SENT]       = "version_sent",
    [MESH_STAGE_VERSION_RECVD]      = "version_received",
    [MESH_STAGE_VERACK]             = "verack",
    [MESH_STAGE_HANDSHAKE_COMPLETE] = "handshake_complete",
    [MESH_STAGE_SERVING]            = "serving",
};

static const char *const k_outcome_tok[MESH_OBS_OUTCOME_NUM] = {
    [MESH_OBS_NOT_PROBED] = "not_probed",
    [MESH_OBS_CONFIRMED]  = "confirmed",
    [MESH_OBS_REFUSED]    = "refused",
    [MESH_OBS_DEADLINE]   = "deadline_expired",
};

const char *mesh_obs_stage_name(enum mesh_obs_stage s)
{
    if (s < 0 || s >= MESH_STAGE_NUM)
        return "none";
    return k_stage_tok[s];
}

const char *mesh_obs_outcome_name(enum mesh_obs_outcome o)
{
    if (o < 0 || o >= MESH_OBS_OUTCOME_NUM)
        return "not_probed";
    return k_outcome_tok[o];
}

bool mesh_obs_stage_from_name(const char *name, enum mesh_obs_stage *out)
{
    if (!name || !out)
        return false;
    for (int i = 0; i < MESH_STAGE_NUM; i++) {
        if (strcmp(name, k_stage_tok[i]) == 0) {
            *out = (enum mesh_obs_stage)i;
            return true;
        }
    }
    return false;
}

bool mesh_obs_outcome_from_name(const char *name, enum mesh_obs_outcome *out)
{
    if (!name || !out)
        return false;
    for (int i = 0; i < MESH_OBS_OUTCOME_NUM; i++) {
        if (strcmp(name, k_outcome_tok[i]) == 0) {
            *out = (enum mesh_obs_outcome)i;
            return true;
        }
    }
    return false;
}

/* ── build-target tokens ────────────────────────────────────────────────
 *
 * Compile-time only. A runtime uname() would answer a different question
 * ("what is this process sitting on"), and on a cross-built or emulated
 * host the two answers differ — which is exactly when a reader most needs
 * to know what the BINARY was built for. An unnamed target reports
 * "unknown" rather than "": "" is reserved for an emitter that said
 * nothing at all, and the two must stay distinguishable. */
const char *mesh_obs_platform_os(void)
{
#if defined(__APPLE__)
    return "macos";
#elif defined(_WIN32)
    return "windows";
#elif defined(__linux__)
    return "linux";
#else
    return "unknown";
#endif
}

const char *mesh_obs_platform_arch(void)
{
#if defined(__aarch64__) || defined(_M_ARM64)
    return "arm64";
#elif defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#else
    return "unknown";
#endif
}

bool mesh_obs_platform_token_ok(const char *tok)
{
    if (!tok)
        return false;
    size_t n = strnlen(tok, MESH_OBS_PLATFORM_MAX);
    if (n >= MESH_OBS_PLATFORM_MAX)
        return false;               /* unterminated within the bound */
    for (size_t i = 0; i < n; i++) {
        char c = tok[i];
        bool lower = (c >= 'a' && c <= 'z');
        bool digit = (c >= '0' && c <= '9');
        if (!lower && !digit && c != '_')
            return false;
    }
    return true;                    /* n == 0 is valid: "said nothing" */
}

/* ── emit ───────────────────────────────────────────────────────────── */

static void push_anchors(struct json_value *self,
                         const struct mesh_obs_self *s)
{
    struct json_value arr = {0};
    json_set_array(&arr);
    for (int i = 0; i < MESH_OBS_ANCHORS; i++) {
        struct json_value a = {0};
        json_set_object(&a);
        json_push_kv_int(&a, "back", MESH_OBS_ANCHOR_BACK[i]);
        json_push_kv_int(&a, "height", s->anchors[i].height);
        json_push_kv_str(&a, "hash", s->anchors[i].hash_hex);
        json_push_kv_bool(&a, "present", s->anchors[i].present);
        json_push_back(&arr, &a);
        json_free(&a);
    }
    json_push_kv(self, "anchors", &arr);
    json_free(&arr);
}

static void push_capability(struct json_value *self,
                            const struct mesh_obs_self *s)
{
    /* Published so a reader may WEIGHT, never so anyone may gate:
     * mesh_observation_compose() cannot see any of it. An unmeasured probe
     * is published AS -1 — never as 0, which would read as "instant". */
    struct json_value c = {0};
    json_set_object(&c);
    json_push_kv_int(&c, "cores", s->cores);
    json_push_kv_int(&c, "ram_bytes", s->ram_bytes);
    json_push_kv_bool(&c, "rotational_known", s->rotational_known);
    json_push_kv_bool(&c, "rotational", s->rotational);
    json_push_kv_int(&c, "fsync_us", s->fsync_us);
    json_push_kv_int(&c, "pread_us", s->pread_us);
    json_push_kv_str(&c, "hw_fingerprint", s->hw_fingerprint);
    json_push_kv(self, "capability", &c);
    json_free(&c);
}

static void push_self(struct json_value *root, const struct mesh_obs_self *s)
{
    struct json_value o = {0};
    json_set_object(&o);
    json_push_kv_str(&o, "onion", s->onion);
    json_push_kv_str(&o, "source_id", s->source_id);
    /* What this binary was BUILT FOR, beside what built it. Together with
     * tor_stub_build they let a reader separate "this operator built
     * without Tor" from "this platform has no Tor to build". */
    json_push_kv_str(&o, "os", s->os);
    json_push_kv_str(&o, "arch", s->arch);
    json_push_kv_int(&o, "tip_height", s->tip_height);
    json_push_kv_str(&o, "tip_hash_hex", s->tip_hash_hex);
    json_push_kv_str(&o, "tip_chainwork_hex", s->tip_chainwork_hex);
    json_push_kv_int(&o, "tip_time_unix", s->tip_time_unix);
    push_anchors(&o, s);
    json_push_kv_int(&o, "provable_tip", s->provable_tip);
    json_push_kv_bool(&o, "provable_tip_published", s->provable_tip_published);
    json_push_kv_int(&o, "reducer_floor", s->reducer_floor);
    json_push_kv_int(&o, "implied_hashrate_ratio_milli",
                     s->implied_hashrate_ratio_milli);
    /* 0 means REFUSED TO JUDGE — an empty window, not a calm network. */
    json_push_kv_int(&o, "arrival_window_blocks", s->arrival_window_blocks);
    json_push_kv_str(&o, "listen_stage", mesh_obs_stage_name(s->listen_stage));
    json_push_kv_bool(&o, "tor_requested", s->tor_requested);
    json_push_kv_bool(&o, "tor_stub_build", s->tor_stub_build);
    push_capability(&o, s);
    json_push_kv_int(&o, "sampled_unix", s->sampled_unix);
    json_push_kv_int(&o, "sampled_monotonic_us", s->sampled_monotonic_us);
    json_push_kv_int(&o, "sample_elapsed_us", s->sample_elapsed_us);
    json_push_kv_bool(&o, "lock_contended", s->lock_contended);
    json_push_kv_str(&o, "unavailable_reason", s->unavailable_reason);
    json_push_kv(root, "self", &o);
    json_free(&o);
}

static void push_edge(struct json_value *arr, const struct mesh_obs_edge *e)
{
    struct json_value o = {0};
    json_set_object(&o);
    json_push_kv_str(&o, "peer_key_hex", e->peer_key_hex);
    json_push_kv_str(&o, "peer_onion", e->peer_onion);
    json_push_kv_bool(&o, "inbound", e->inbound);
    json_push_kv_str(&o, "transport", mesh_obs_outcome_name(e->transport));
    json_push_kv_str(&o, "stage", mesh_obs_stage_name(e->stage));
    /* The elapsed time is ALWAYS published beside the budget that bounded
     * it, on all four outcomes — so a reader with a different budget
     * re-derives without re-measuring anything. */
    json_push_kv_int(&o, "stage_elapsed_us", e->stage_elapsed_us);
    json_push_kv_int(&o, "deadline_us", e->deadline_us);
    json_push_kv_int(&o, "last_recv_age_us", e->last_recv_age_us);
    json_push_kv_int(&o, "last_send_age_us", e->last_send_age_us);
    json_push_kv_int(&o, "connected_age_us", e->connected_age_us);
    json_push_kv_int(&o, "min_ping_us", e->min_ping_us);
    json_push_kv_int(&o, "claimed_height", e->claimed_height);
    json_push_kv_str(&o, "claimed_tip_hash_hex", e->claimed_tip_hash_hex);
    json_push_kv_int(&o, "claim_age_us", e->claim_age_us);
    json_push_kv_bool(&o, "claim_verified_locally", e->claim_verified_locally);
    json_push_kv_str(&o, "header_service",
                     mesh_obs_outcome_name(e->header_service));
    json_push_back(arr, &o);
    json_free(&o);
}

bool mesh_observation_emit_json(const struct mesh_observation *rec,
                                struct json_value *out)
{
    if (!rec || !out)
        return false;
    json_set_object(out);
    json_push_kv_str(out, "schema", MESH_OBS_SCHEMA);
    push_self(out, &rec->self);

    struct json_value edges = {0};
    json_set_array(&edges);
    int n = rec->edge_count;
    if (n < 0)
        n = 0;
    if (n > MESH_OBS_EDGES_MAX)
        n = MESH_OBS_EDGES_MAX;
    for (int i = 0; i < n; i++)
        push_edge(&edges, &rec->edges[i]);
    json_push_kv(out, "edges", &edges);
    json_free(&edges);

    /* Coverage is part of the record, not an afterthought: a truncated or
     * partly unreadable sample must never look like a complete one. */
    struct json_value cov = {0};
    json_set_object(&cov);
    json_push_kv_int(&cov, "edge_count", n);
    json_push_kv_int(&cov, "edges_truncated", rec->edges_truncated);
    json_push_kv_int(&cov, "rows_unreadable", rec->rows_unreadable);
    json_push_kv(out, "coverage", &cov);
    json_free(&cov);
    return true;
}

/* ── parse (UNTRUSTED input) ────────────────────────────────────────── */

struct mo_parse_ctx {
    const char *reason;   /* static token; NULL while nothing has refused */
};

static bool mo_refuse(struct mo_parse_ctx *c, const char *token)
{
    if (!c->reason)
        c->reason = token;
    return false;
}

static bool mo_hex_n(const char *s, size_t want)
{
    if (!s)
        return false;
    size_t i = 0;
    for (; i < want; i++) {
        char ch = s[i];
        bool d = (ch >= '0' && ch <= '9');
        bool l = (ch >= 'a' && ch <= 'f');
        bool u = (ch >= 'A' && ch <= 'F');
        if (!d && !l && !u)
            return false;
    }
    return s[want] == '\0';
}

/* Copy an optional string field. Absent is fine (empty result); a wrong
 * type or an over-long value is a NAMED refusal, never a truncation. */
static bool mo_take_str(struct mo_parse_ctx *c, const struct json_value *obj,
                        const char *key, char *dst, size_t cap)
{
    dst[0] = '\0';
    const struct json_value *v = json_get(obj, key);
    if (!v || v->type == JSON_NULL)
        return true;
    if (v->type != JSON_STR)
        return mo_refuse(c, "bad_field_type");
    const char *s = json_get_str(v);
    if (!s)
        return true;
    size_t len = strnlen(s, cap);
    if (len >= cap)
        return mo_refuse(c, "string_too_long");
    memcpy(dst, s, len + 1);
    return true;
}

/* A build-target token. Unlike a stage or an outcome, the value is NOT
 * checked against a closed set this build knows: an emitter running an OS
 * this build has never heard of is carried through verbatim, because
 * refusing it would drop the first node of every new platform — the exact
 * blindness this field exists to remove. Only a MALFORMED token is
 * refused: an over-long one as "string_too_long" by the shared reader
 * above, and a bad charset under its own "bad_platform_token" so the two
 * are never conflated in a refusal tally. */
static bool mo_take_platform(struct mo_parse_ctx *c,
                             const struct json_value *obj, const char *key,
                             char *dst)
{
    if (!mo_take_str(c, obj, key, dst, MESH_OBS_PLATFORM_MAX))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mesh_obs_platform_token_ok(dst)) {
        dst[0] = '\0';
        return mo_refuse(c, "bad_platform_token");
    }
    return true;
}

/* An optional hash field: empty is "unknown"; anything present must be a
 * well-formed 64-hex string. */
static bool mo_take_hash(struct mo_parse_ctx *c, const struct json_value *obj,
                         const char *key, char *dst)
{
    if (!mo_take_str(c, obj, key, dst, MESH_OBS_HEXHASH))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (dst[0] && !mo_hex_n(dst, 64))
        return mo_refuse(c, "bad_hash_hex");
    return true;
}

/* `below` is the static token reported when the value undershoots the
 * floor, so a bad height and a bad latency never share one refusal name. */
static bool mo_take_int(struct mo_parse_ctx *c, const struct json_value *obj,
                        const char *key, int64_t floor_value,
                        const char *below, int64_t *dst)
{
    *dst = 0;
    const struct json_value *v = json_get(obj, key);
    if (!v || v->type == JSON_NULL)
        return true;
    if (v->type != JSON_INT)
        return mo_refuse(c, "bad_field_type");
    int64_t got = json_get_int(v);
    if (got < floor_value)
        return mo_refuse(c, below);
    *dst = got;
    return true;
}

static bool mo_take_bool(struct mo_parse_ctx *c, const struct json_value *obj,
                         const char *key, bool *dst)
{
    *dst = false;
    const struct json_value *v = json_get(obj, key);
    if (!v || v->type == JSON_NULL)
        return true;
    if (v->type != JSON_BOOL)
        return mo_refuse(c, "bad_field_type");
    *dst = json_get_bool(v);
    return true;
}

static bool mo_take_stage(struct mo_parse_ctx *c, const struct json_value *obj,
                          const char *key, enum mesh_obs_stage *dst)
{
    char tok[32];
    *dst = MESH_STAGE_NONE;
    if (!mo_take_str(c, obj, key, tok, sizeof(tok)))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!tok[0])
        return true;
    if (!mesh_obs_stage_from_name(tok, dst))
        return mo_refuse(c, "unknown_stage_token");
    return true;
}

static bool mo_take_outcome(struct mo_parse_ctx *c,
                            const struct json_value *obj, const char *key,
                            enum mesh_obs_outcome *dst)
{
    char tok[32];
    *dst = MESH_OBS_NOT_PROBED;
    if (!mo_take_str(c, obj, key, tok, sizeof(tok)))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!tok[0])
        return true;
    if (!mesh_obs_outcome_from_name(tok, dst))
        return mo_refuse(c, "unknown_outcome_token");
    return true;
}

static bool mo_parse_anchors(struct mo_parse_ctx *c,
                             const struct json_value *self,
                             struct mesh_obs_self *dst)
{
    const struct json_value *arr = json_get(self, "anchors");
    if (!arr || arr->type == JSON_NULL)
        return true;
    if (arr->type != JSON_ARR)
        return mo_refuse(c, "anchors_not_an_array");
    size_t n = json_size(arr);
    if (n > (size_t)MESH_OBS_ANCHORS)
        return mo_refuse(c, "anchors_overflow");
    for (size_t i = 0; i < n; i++) {
        const struct json_value *a = json_at(arr, i);
        if (!a || a->type != JSON_OBJ)
            return mo_refuse(c, "bad_field_type");
        int64_t back = 0;
        if (!mo_take_int(c, a, "back", 0, "negative_value", &back))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        int slot = -1;
        for (int r = 0; r < MESH_OBS_ANCHORS; r++)
            if (MESH_OBS_ANCHOR_BACK[r] == (int32_t)back)
                slot = r;
        if (slot < 0)
            return mo_refuse(c, "unknown_anchor_rung");
        int64_t h = 0;
        if (!mo_take_int(c, a, "height", 0, "negative_height", &h))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_hash(c, a, "hash", dst->anchors[slot].hash_hex))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_bool(c, a, "present", &dst->anchors[slot].present))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        dst->anchors[slot].height = h;
        /* A rung is only usable when it actually carries a hash — a
         * present flag with no hash is dropped, never guessed at. */
        if (!dst->anchors[slot].hash_hex[0])
            dst->anchors[slot].present = false;
    }
    return true;
}

static bool mo_parse_self(struct mo_parse_ctx *c, const struct json_value *root,
                          struct mesh_obs_self *dst)
{
    const struct json_value *self = json_get(root, "self");
    if (!self)
        return mo_refuse(c, "self_missing");
    if (self->type != JSON_OBJ)
        return mo_refuse(c, "self_not_an_object");

    memcpy(dst->schema, MESH_OBS_SCHEMA, sizeof(MESH_OBS_SCHEMA));

    int64_t tmp = 0;
    bool b = false;
    if (!mo_take_str(c, self, "onion", dst->onion, sizeof(dst->onion)))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_str(c, self, "source_id", dst->source_id,
                     sizeof(dst->source_id)))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_platform(c, self, "os", dst->os))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_platform(c, self, "arch", dst->arch))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_int(c, self, "tip_height", 0, "negative_height",
                     &dst->tip_height))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_hash(c, self, "tip_hash_hex", dst->tip_hash_hex))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_hash(c, self, "tip_chainwork_hex", dst->tip_chainwork_hex))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_int(c, self, "tip_time_unix", 0, "negative_value",
                     &dst->tip_time_unix))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_parse_anchors(c, self, dst))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_int(c, self, "provable_tip", 0, "negative_height", &tmp))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    dst->provable_tip = (int32_t)tmp;
    if (!mo_take_bool(c, self, "provable_tip_published",
                      &dst->provable_tip_published))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_int(c, self, "reducer_floor", 0, "negative_height", &tmp))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    dst->reducer_floor = (int32_t)tmp;
    if (!mo_take_int(c, self, "implied_hashrate_ratio_milli", -1,
                     "value_below_floor",
                     &dst->implied_hashrate_ratio_milli))
        return false;
    if (!mo_take_int(c, self, "arrival_window_blocks", 0, "negative_value",
                     &tmp))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    dst->arrival_window_blocks = (int32_t)tmp;
    if (!mo_take_stage(c, self, "listen_stage", &dst->listen_stage))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_bool(c, self, "tor_requested", &dst->tor_requested))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_bool(c, self, "tor_stub_build", &dst->tor_stub_build))
        return false;   // raw-return-ok:refusal-named-in-reason-out

    const struct json_value *cap = json_get(self, "capability");
    if (cap && cap->type != JSON_NULL) {
        if (cap->type != JSON_OBJ)
            return mo_refuse(c, "bad_field_type");
        if (!mo_take_int(c, cap, "cores", 0, "negative_value", &tmp))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        dst->cores = (int32_t)tmp;
        if (!mo_take_int(c, cap, "ram_bytes", 0, "negative_value",
                         &dst->ram_bytes))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_bool(c, cap, "rotational_known", &dst->rotational_known))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_bool(c, cap, "rotational", &dst->rotational))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        /* -1 is the honest "the probe never ran" value and MUST survive
         * as -1; rounding it to 0 would publish "instant". */
        if (!mo_take_int(c, cap, "fsync_us", -1, "value_below_floor",
                         &dst->fsync_us))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_int(c, cap, "pread_us", -1, "value_below_floor",
                         &dst->pread_us))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_str(c, cap, "hw_fingerprint", dst->hw_fingerprint,
                         sizeof(dst->hw_fingerprint)))
            return false;   // raw-return-ok:refusal-named-in-reason-out
    } else {
        dst->fsync_us = -1;
        dst->pread_us = -1;
    }

    if (!mo_take_int(c, self, "sampled_unix", 0, "negative_value",
                     &dst->sampled_unix))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_int(c, self, "sampled_monotonic_us", 0, "negative_value",
                     &dst->sampled_monotonic_us))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_int(c, self, "sample_elapsed_us", -1, "value_below_floor",
                     &dst->sample_elapsed_us))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_bool(c, self, "lock_contended", &b))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    dst->lock_contended = b;
    if (!mo_take_str(c, self, "unavailable_reason", dst->unavailable_reason,
                     sizeof(dst->unavailable_reason)))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    return true;
}

static bool mo_parse_edges(struct mo_parse_ctx *c,
                           const struct json_value *root,
                           struct mesh_observation *dst)
{
    const struct json_value *arr = json_get(root, "edges");
    if (!arr || arr->type == JSON_NULL)
        return true;
    if (arr->type != JSON_ARR)
        return mo_refuse(c, "edges_not_an_array");
    size_t n = json_size(arr);
    /* A document declaring more edges than connman can even hold is
     * refused BY NAME rather than silently clipped. */
    if (n > (size_t)MESH_OBS_EDGES_MAX)
        return mo_refuse(c, "edges_overflow");
    for (size_t i = 0; i < n; i++) {
        const struct json_value *e = json_at(arr, i);
        if (!e || e->type != JSON_OBJ)
            return mo_refuse(c, "bad_field_type");
        struct mesh_obs_edge *d = &dst->edges[i];
        if (!mo_take_str(c, e, "peer_key_hex", d->peer_key_hex,
                         sizeof(d->peer_key_hex)))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (d->peer_key_hex[0] &&
            !mo_hex_n(d->peer_key_hex, NET_SERVICE_KEY_SIZE * 2))
            return mo_refuse(c, "bad_key_hex");
        if (!mo_take_str(c, e, "peer_onion", d->peer_onion,
                         sizeof(d->peer_onion)))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_bool(c, e, "inbound", &d->inbound))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_outcome(c, e, "transport", &d->transport))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_stage(c, e, "stage", &d->stage))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_int(c, e, "stage_elapsed_us", -1, "value_below_floor",
                         &d->stage_elapsed_us))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_int(c, e, "deadline_us", -1, "value_below_floor",
                         &d->deadline_us))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_int(c, e, "last_recv_age_us", -1, "value_below_floor",
                         &d->last_recv_age_us))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_int(c, e, "last_send_age_us", -1, "value_below_floor",
                         &d->last_send_age_us))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_int(c, e, "connected_age_us", -1, "value_below_floor",
                         &d->connected_age_us))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_int(c, e, "min_ping_us", -1, "value_below_floor",
                         &d->min_ping_us))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        /* -1 is "the peer told me nothing"; anything below that is a
         * malformed claim. */
        if (!mo_take_int(c, e, "claimed_height", -1, "negative_height",
                         &d->claimed_height))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_hash(c, e, "claimed_tip_hash_hex",
                          d->claimed_tip_hash_hex))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_int(c, e, "claim_age_us", -1, "value_below_floor",
                         &d->claim_age_us))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_bool(c, e, "claim_verified_locally",
                          &d->claim_verified_locally))
            return false;   // raw-return-ok:refusal-named-in-reason-out
        if (!mo_take_outcome(c, e, "header_service", &d->header_service))
            return false;   // raw-return-ok:refusal-named-in-reason-out
    }
    dst->edge_count = (int32_t)n;
    return true;
}

/* Coverage, read back. The emitter has always written this block (a truncated
 * or partly unreadable sample must never look like a complete one), but until
 * now nothing parsed it, so every field in it arrived at the reader as zero —
 * i.e. a peer that honestly reported dropping rows was read as having dropped
 * none. That is the exact failure this record type exists to prevent, so an
 * absent or malformed coverage block is REFUSED BY NAME rather than defaulted.
 *
 * Must run AFTER mo_parse_edges(), which sets dst->edge_count from the array
 * actually delivered. The claimed count is then cross-checked against it: a
 * document whose own coverage disagrees with its own edge list is making an
 * unverifiable claim about itself, and is refused. */
static bool mo_parse_coverage(struct mo_parse_ctx *c,
                              const struct json_value *root,
                              struct mesh_observation *dst)
{
    const struct json_value *cov = json_get(root, "coverage");
    if (!cov || cov->type != JSON_OBJ) {
        c->reason = "coverage_missing";
        return false;
    }

    int64_t claimed = 0, truncated = 0, unreadable = 0;
    if (!mo_take_int(c, cov, "edge_count", 0, "negative_value", &claimed))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_int(c, cov, "edges_truncated", 0, "negative_value",
                     &truncated))
        return false;   // raw-return-ok:refusal-named-in-reason-out
    if (!mo_take_int(c, cov, "rows_unreadable", 0, "negative_value",
                     &unreadable))
        return false;   // raw-return-ok:refusal-named-in-reason-out

    if (claimed != (int64_t)dst->edge_count) {
        c->reason = "coverage_edge_count_mismatch";
        return false;
    }
    if (truncated > INT32_MAX || unreadable > INT32_MAX) {
        c->reason = "coverage_value_too_large";
        return false;
    }

    dst->edges_truncated = (int32_t)truncated;
    dst->rows_unreadable = (int32_t)unreadable;
    return true;
}

bool mesh_observation_parse_json(const char *body, size_t len,
                                 struct mesh_observation *out,
                                 char reason_out[MESH_OBS_REASON_MAX])
{
    struct mo_parse_ctx ctx = { .reason = NULL };
    if (reason_out)
        reason_out[0] = '\0';
    if (!out)
        return false;
    if (!body || len == 0) {
        ctx.reason = "empty_body";
        goto refuse;
    }
    if (len > MESH_OBS_DOC_MAX) {
        ctx.reason = "document_too_large";
        goto refuse;
    }

    struct json_value root = {0};
    json_init(&root);
    if (!json_read(&root, body, len)) {
        json_free(&root);
        ctx.reason = "json_malformed";
        goto refuse;
    }
    if (root.type != JSON_OBJ) {
        json_free(&root);
        ctx.reason = "not_an_object";
        goto refuse;
    }

    const struct json_value *schema = json_get(&root, "schema");
    if (!schema || schema->type != JSON_STR) {
        json_free(&root);
        ctx.reason = "schema_missing";
        goto refuse;
    }
    if (strcmp(json_get_str(schema), MESH_OBS_SCHEMA) != 0) {
        json_free(&root);
        ctx.reason = "schema_mismatch";
        goto refuse;
    }

    /* Build into a local so a refusal at ANY field leaves *out untouched.
     * The house JSON parser owns its own arena and it is released here; the
     * caller's struct is fixed-size and never grows. */
    struct mesh_observation staged;
    memset(&staged, 0, sizeof(staged));
    bool okay = mo_parse_self(&ctx, &root, &staged.self) &&
                mo_parse_edges(&ctx, &root, &staged) &&
                mo_parse_coverage(&ctx, &root, &staged);
    json_free(&root);
    if (!okay) {
        if (!ctx.reason)
            ctx.reason = "malformed_record";
        goto refuse;
    }

    *out = staged;
    return true;

refuse:
    if (reason_out && ctx.reason) {
        size_t rl = strnlen(ctx.reason, MESH_OBS_REASON_MAX - 1);
        memcpy(reason_out, ctx.reason, rl);
        reason_out[rl] = '\0';
    }
    return false;
}
