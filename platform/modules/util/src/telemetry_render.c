/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The telemetry render layer — the one place a typed domain snapshot becomes
 * JSON, and the one place a domain's health is decided.
 *
 * See util/telemetry_render.h for the contract. The three invariants worth
 * repeating at the implementation, because each one is a defect this file
 * exists to make unrepresentable:
 *
 *   1. OMISSION IS IMPOSSIBLE. Emission is driven by the descriptor table, not
 *      by the provider, so a leaf the provider never touched still renders its
 *      key — as JSON null, with presence "unset" and provider_defect set. A
 *      reader can therefore always tell "0" from "nobody wrote it".
 *
 *   2. THE VIEW FILTERS RENDERING, NEVER JUDGEMENT. Every leaf is evaluated on
 *      every call against the FULL value document; the tier prune happens
 *      afterwards, on the rendering pass only. `view=summary` reporting ok
 *      while a full-tier critical leaf is unhealthy is structurally excluded.
 *
 *   3. HEALTH IS DERIVED. Nothing here authors a verdict. It builds the value
 *      document, hands each leaf to telemetry_field_evaluate() — the same
 *      evaluator `ops debug meaning` uses — and maps the verdict through the
 *      row's severity. There is no second opinion to drift.
 *
 * DANGER: value_off/meta_off are raw byte offsets into caller memory. Every
 * one is proved to lie inside the schema's snapshot_size BEFORE the first
 * dereference, and a table that overruns is refused outright rather than
 * partially rendered. Do not add a read path that skips prove_offsets().
 *
 * Layering: metadata and rendering over diagnostics output. Reads no node
 * state, takes no lock, performs no I/O. Reentrant; the only allocation is
 * into the caller's json_value.
 */

#include "util/telemetry_render.h"

#include "json/json.h"
#include "platform/clock.h"
#include "util/log_macros.h"
#include "util/telemetry_ontology.h"

#include <stdio.h>
#include <string.h>

/* ── names ───────────────────────────────────────────────────────────── */

const char *telemetry_health_name(enum telemetry_health h)
{
    switch (h) {
    case TELEMETRY_HEALTH_OK:        return "ok";
    case TELEMETRY_HEALTH_UNKNOWN:   return "unknown";
    case TELEMETRY_HEALTH_DEGRADED:  return "degraded";
    case TELEMETRY_HEALTH_UNHEALTHY: return "unhealthy";
    }
    return "unknown";
}

const char *telemetry_presence_name(enum telemetry_presence p)
{
    switch (p) {
    case TELEMETRY_UNSET:          return "unset";
    case TELEMETRY_PRESENT:        return "present";
    case TELEMETRY_UNAVAILABLE:    return "unavailable";
    case TELEMETRY_NOT_APPLICABLE: return "not_applicable";
    case TELEMETRY_TRUNCATED:      return "truncated";
    }
    return "unset";
}

const char *telemetry_source_name(enum telemetry_source s)
{
    switch (s) {
    case TELEMETRY_SRC_UNSET:               return "unset";
    case TELEMETRY_SRC_IN_PROCESS:          return "in_process";
    case TELEMETRY_SRC_CACHED_PUBLICATION:  return "cached_publication";
    case TELEMETRY_SRC_DURABLE_STORE:       return "durable_store";
    case TELEMETRY_SRC_PEER_REPORTED:       return "peer_reported";
    case TELEMETRY_SRC_CONFIG:              return "config";
    case TELEMETRY_SRC_DERIVED:             return "derived";
    }
    return "unset";
}

const char *telemetry_view_name(enum telemetry_view v)
{
    switch (v) {
    case TLV_SUMMARY: return "summary";
    case TLV_NORMAL:  return "normal";
    case TLV_FULL:    return "full";
    }
    return "normal";
}

/* ── provider-side helpers ───────────────────────────────────────────── */

int64_t telemetry_now_unix(void)
{
    int64_t ms = clock_now_wall_ms();
    return ms > 0 ? ms / 1000 : -1;
}

void telemetry_set_text_impl(char *dst, size_t dst_sz,
                             struct telemetry_leaf_meta *meta,
                             const char *value, enum telemetry_source src)
{
    if (!dst || dst_sz == 0 || !meta)
        return;
    /* A NULL string is a failed read, not an empty value. Recording it as ""
     * would publish a plausible blank where nothing was ever read. */
    if (!value) {
        dst[0] = '\0';
        *meta = (struct telemetry_leaf_meta){
            .presence = TELEMETRY_UNAVAILABLE,
            .source = TELEMETRY_SRC_UNSET,
            .observed_unix = -1, .age_ms = -1,
            .reason = "text_value_null" };
        return;
    }
    size_t n = strlen(value);
    bool fits = n < dst_sz;
    size_t copy = fits ? n : dst_sz - 1;
    memcpy(dst, value, copy);
    dst[copy] = '\0';
    *meta = (struct telemetry_leaf_meta){
        .presence = fits ? TELEMETRY_PRESENT : TELEMETRY_TRUNCATED,
        .source = src,
        .observed_unix = telemetry_now_unix(),
        .age_ms = 0,
        .reason = fits ? "" : "text_too_long" };
}

/* ── view parsing ────────────────────────────────────────────────────── */

/* A group name is a bare lowercase identifier (the field-table grammar cannot
 * express anything else). Anything outside that shape is not a group and not a
 * view, so it is reported unrecognized instead of guessed at. */
static bool looks_like_group(const char *key)
{
    size_t n = strlen(key);
    if (n == 0 || n > 31)
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = key[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
            return false;
    }
    return true;
}

enum telemetry_view telemetry_view_parse(const char *key,
                                         const char **out_group,
                                         bool *out_unrecognized)
{
    if (out_group)
        *out_group = NULL;
    if (out_unrecognized)
        *out_unrecognized = false;
    if (!key || !key[0])
        return TLV_NORMAL;
    if (strcmp(key, "summary") == 0)
        return TLV_SUMMARY;
    if (strcmp(key, "normal") == 0)
        return TLV_NORMAL;
    if (strcmp(key, "full") == 0)
        return TLV_FULL;
    /* A plausible group name is passed through at full detail. Whether it
     * NAMES a real group is a question only the schema can answer, so
     * telemetry_render reports `group_filter_matched` rather than this
     * function pretending to know. */
    if (out_group && looks_like_group(key)) {
        *out_group = key;
        return TLV_FULL;
    }
    if (out_unrecognized)
        *out_unrecognized = true;
    return TLV_NORMAL;
}

/* ── snapshot access ─────────────────────────────────────────────────── */

static size_t leaf_width(enum telemetry_ctype c)
{
    switch (c) {
    case TLC_I64:  return sizeof(int64_t);
    case TLC_BOOL: return sizeof(bool);
    case TLC_TEXT: return (size_t)TELEMETRY_TEXT_MAX;
    }
    return 0;
}

/* Every offset the render walk will dereference, proved inside snapshot_size
 * before anything is read. Subtraction rather than addition so a hostile or
 * corrupt offset cannot wrap. */
static bool prove_offsets(const struct telemetry_domain_schema *s)
{
    const size_t meta_w = sizeof(struct telemetry_leaf_meta);
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        size_t w = leaf_width(lf->ctype);
        if (w == 0)
            LOG_FAIL("telemetry_render",
                     "domain %s leaf %s: unknown ctype %d",
                     s->domain, lf->path, (int)lf->ctype);
        if (lf->value_off > s->snapshot_size ||
            w > s->snapshot_size - lf->value_off)
            LOG_FAIL("telemetry_render",
                     "domain %s leaf %s: value_off %zu + %zu exceeds "
                     "snapshot_size %zu",
                     s->domain, lf->path, lf->value_off, w, s->snapshot_size);
        if (lf->meta_off > s->snapshot_size ||
            meta_w > s->snapshot_size - lf->meta_off)
            LOG_FAIL("telemetry_render",
                     "domain %s leaf %s: meta_off %zu + %zu exceeds "
                     "snapshot_size %zu",
                     s->domain, lf->path, lf->meta_off, meta_w,
                     s->snapshot_size);
    }
    return true;
}

static const struct telemetry_leaf_meta *leaf_meta(const void *snap,
                                                   const struct telemetry_leaf *lf)
{
    const char *base = (const char *)snap + lf->meta_off;
    /* Copied through a byte pointer because the offset came from offsetof over
     * the real struct, so alignment is guaranteed by construction. */
    return (const struct telemetry_leaf_meta *)(const void *)base;
}

/* A leaf renders its stored value only when something actually wrote one.
 * TRUNCATED counts: bounded rendering dropped detail, but the bytes that
 * survived are real and are more use to a reader than a null. */
static void set_leaf_value(struct json_value *v,
                           const struct telemetry_leaf *lf,
                           const void *snap,
                           const struct telemetry_leaf_meta *m)
{
    const char *base = (const char *)snap + lf->value_off;
    if (m->presence != TELEMETRY_PRESENT && m->presence != TELEMETRY_TRUNCATED) {
        json_set_null(v);
        return;
    }
    switch (lf->ctype) {
    case TLC_I64: {
        int64_t n = 0;
        memcpy(&n, base, sizeof n);
        json_set_int(v, n);
        return;
    }
    case TLC_BOOL: {
        bool b = false;
        memcpy(&b, base, sizeof b);
        json_set_bool(v, b);
        return;
    }
    case TLC_TEXT: {
        char buf[TELEMETRY_TEXT_MAX];
        memcpy(buf, base, sizeof buf);
        buf[TELEMETRY_TEXT_MAX - 1] = '\0';
        json_set_str(v, buf);
        return;
    }
    }
    json_set_null(v);
}

/* ── the value plane ─────────────────────────────────────────────────── */

/* Build `{ <group>: { <key>: <value|null>, ... }, ... }`.
 *
 * `full_set` means "ignore the view tier and the group filter" — that is the
 * document the evaluator judges, and it is always complete. A group with no
 * leaf at the requested tier is omitted entirely; a leaf that IS at the tier
 * is never omitted, whatever its presence. */
static bool build_values(const struct telemetry_domain_schema *s,
                         const void *snap, enum telemetry_view view,
                         const char *only_group, bool full_set,
                         struct json_value *out, size_t *out_rendered)
{
    json_set_object(out);
    size_t rendered = 0;
    for (size_t gi = 0; gi < s->group_count; gi++) {
        const struct telemetry_group *g = &s->groups[gi];
        if (!full_set && only_group && strcmp(g->name, only_group) != 0)
            continue;
        struct json_value gobj;
        json_init(&gobj);
        json_set_object(&gobj);
        size_t in_group = 0;
        for (size_t i = 0; i < s->leaf_count; i++) {
            const struct telemetry_leaf *lf = &s->leaves[i];
            if (strcmp(lf->group, g->name) != 0)
                continue;
            if (!full_set && lf->tier > view)
                continue;
            struct json_value v;
            json_init(&v);
            set_leaf_value(&v, lf, snap, leaf_meta(snap, lf));
            if (!json_push_kv(&gobj, lf->key, &v)) {
                json_free(&v);
                json_free(&gobj);
                LOG_FAIL("telemetry_render",
                         "domain %s: out of memory rendering %s",
                         s->domain, lf->path);
            }
            json_free(&v);
            in_group++;
        }
        if (in_group > 0) {
            if (!json_push_kv(out, g->name, &gobj)) {
                json_free(&gobj);
                LOG_FAIL("telemetry_render",
                         "domain %s: out of memory rendering group %s",
                         s->domain, g->name);
            }
            rendered += in_group;
        }
        json_free(&gobj);
    }
    if (out_rendered)
        *out_rendered = rendered;
    return true;
}

/* ── judgement ───────────────────────────────────────────────────────── */

/* The one mapping from "what the rule said" to "how loud that is". Severity
 * belongs to the ontology row, not to the evaluator, which is why the mapping
 * lives here and takes the row. */
static enum telemetry_health verdict_to_health(enum telemetry_verdict v,
                                               const struct telemetry_field *f)
{
    switch (v) {
    case TV_HEALTHY:
    case TV_NOT_JUDGED:
    case TV_NOT_EVALUATED:
        return TELEMETRY_HEALTH_OK;
    case TV_UNHEALTHY:
        return (f && f->severity == TFS_CRITICAL) ? TELEMETRY_HEALTH_UNHEALTHY
                                                  : TELEMETRY_HEALTH_DEGRADED;
    case TV_ABSENT:
        /* A descriptive row we could not read costs nothing; a JUDGED row we
         * could not read means the verdict is unknown, and unknown must
         * outrank ok so a reply full of unreadable leaves cannot claim
         * health. */
        return (f && f->rule != TFR_INFO) ? TELEMETRY_HEALTH_UNKNOWN
                                          : TELEMETRY_HEALTH_OK;
    }
    return TELEMETRY_HEALTH_UNKNOWN;
}

static void record_finding(struct telemetry_domain_verdict *out,
                           const struct telemetry_leaf *lf,
                           const struct telemetry_field *f,
                           enum telemetry_health h,
                           const struct json_value *val)
{
    if (out->finding_count >= TELEMETRY_MAX_FINDINGS) {
        out->findings_truncated = true;
        return;
    }
    struct telemetry_finding *fi = &out->findings[out->finding_count++];
    memset(fi, 0, sizeof *fi);
    /* path/key/means/implies/next are all static table strings; the finding
     * borrows them and outlives the value document safely. `val` does NOT
     * outlive it, so only the scalar is copied out. */
    fi->path = lf->path;
    fi->key = lf->key;
    fi->health = h;
    fi->severity = f ? f->severity : TFS_INFO;
    fi->unit = lf->unit;
    if (val && val->type == JSON_INT) {
        fi->value_known = true;
        fi->value_i = json_get_int(val);
    } else if (val && val->type == JSON_BOOL) {
        fi->value_known = true;
        fi->value_is_bool = true;
        fi->value_b = json_get_bool(val);
    }
    telemetry_field_healthy_range(f, fi->healthy_range,
                                  sizeof fi->healthy_range);
    fi->means = f ? f->means : "";
    fi->implies = f ? f->implies : "";
    fi->next = f ? f->next : "";
}

/* Judge every leaf against the FULL value document, whatever view the caller
 * asked for. This is invariant 2 in the file header, and it is why the view is
 * not a parameter here. */
static bool eval_domain(const struct telemetry_domain_schema *s,
                        const void *snap,
                        struct telemetry_domain_verdict *out)
{
    memset(out, 0, sizeof *out);

    struct json_value doc, vals;
    json_init(&doc);
    json_init(&vals);
    json_set_object(&doc);
    if (!build_values(s, snap, TLV_FULL, NULL, true, &vals, NULL)) {
        json_free(&vals);
        json_free(&doc);
        LOG_FAIL("telemetry_render", "domain %s: could not build value plane",
                 s->domain);
    }
    /* The ontology paths are TL_PATH = "values.<group>.<key>", so the document
     * the evaluator resolves against must be rooted one level above the
     * groups. Ratio operands (TL_REF) resolve as siblings inside it. */
    bool pushed = json_push_kv(&doc, "values", &vals);
    json_free(&vals);
    if (!pushed) {
        json_free(&doc);
        LOG_FAIL("telemetry_render", "domain %s: out of memory building the "
                 "evaluation document", s->domain);
    }

    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        const struct telemetry_leaf_meta *m = leaf_meta(snap, lf);
        const struct telemetry_field *f =
            telemetry_field_lookup(s->domain, lf->path);
        const struct json_value *val = NULL;
        enum telemetry_verdict v = telemetry_field_evaluate(f, &doc, &val);
        /* No ontology row means no rule could run at all. That is a build-time
         * mistake (schema->domain must equal the ontology subsystem), and it
         * reports as unknown rather than as health. */
        enum telemetry_health h = f ? verdict_to_health(v, f)
                                    : TELEMETRY_HEALTH_UNKNOWN;
        /* A leaf nobody wrote is a PROVIDER defect, independent of any rule:
         * even a TFR_INFO row must not read as fine when its value was never
         * produced. */
        if (m->presence == TELEMETRY_UNSET && h < TELEMETRY_HEALTH_UNKNOWN)
            h = TELEMETRY_HEALTH_UNKNOWN;

        if (v == TV_HEALTHY || v == TV_UNHEALTHY)
            out->rules_evaluated++;
        if (v == TV_UNHEALTHY)
            out->unhealthy_count++;
        if (h == TELEMETRY_HEALTH_UNKNOWN)
            out->unknown_count++;
        if (h > out->state)
            out->state = h;
        if (h != TELEMETRY_HEALTH_OK)
            record_finding(out, lf, f, h, val);
    }
    json_free(&doc);
    return true;
}

bool telemetry_evaluate(const struct telemetry_domain_schema *schema,
                        const void *snapshot,
                        struct telemetry_domain_verdict *out)
{
    if (!out)
        LOG_FAIL("telemetry_render", "evaluate: out is NULL");
    memset(out, 0, sizeof *out);
    if (!schema || !snapshot)
        LOG_FAIL("telemetry_render", "evaluate: schema and snapshot required");
    if (!prove_offsets(schema))
        LOG_FAIL("telemetry_render", "evaluate: domain %s has an out-of-bounds "
                 "descriptor table", schema->domain);
    return eval_domain(schema, snapshot, out);
}

/* ── the document ────────────────────────────────────────────────────────
 * EVERY push below is checked, down to one key inside `completeness`. An
 * unchecked push is the silent-omission bug wearing this layer's own clothes:
 * on allocation failure the reply would come back missing `health`, or missing
 * the `unhealthy` array — which reads as "nothing is wrong" — and still return
 * true. A complete document, or false; there is no "small push" exemption.
 * Builders accumulate with `&=` rather than returning early, so every
 * json_free() still runs on the way out. */

static bool push_int_or_null(struct json_value *obj, const char *key,
                             bool known, int64_t v)
{
    if (known)
        return json_push_kv_int(obj, key, v);
    struct json_value nul;
    json_init(&nul);
    json_set_null(&nul);
    bool ok = json_push_kv(obj, key, &nul);
    json_free(&nul);
    return ok;
}

/* Presence tallies, over the WHOLE leaf set — completeness is a property of
 * the snapshot the provider filled, not of the slice the caller asked to see. */
struct presence_tally {
    size_t present, unavailable, not_applicable, truncated, unset;
    bool provider_defect;
};

static void tally_presence(const struct telemetry_domain_schema *s,
                           const void *snap, struct presence_tally *t)
{
    memset(t, 0, sizeof *t);
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf_meta *m = leaf_meta(snap, &s->leaves[i]);
        switch (m->presence) {
        case TELEMETRY_PRESENT:        t->present++; break;
        case TELEMETRY_UNAVAILABLE:    t->unavailable++; break;
        case TELEMETRY_NOT_APPLICABLE: t->not_applicable++; break;
        case TELEMETRY_TRUNCATED:      t->truncated++; break;
        case TELEMETRY_UNSET:          t->unset++; break;
        }
        if (m->presence == TELEMETRY_UNSET)
            t->provider_defect = true;
        /* A non-present leaf owes a static reason token. Excusing a missing
         * one would hide exactly the providers this layer is meant to expose. */
        else if (m->presence != TELEMETRY_PRESENT && (!m->reason || !m->reason[0]))
            t->provider_defect = true;
    }
}

static bool push_completeness(struct json_value *out,
                              const struct telemetry_domain_schema *s,
                              const struct presence_tally *t,
                              size_t rendered)
{
    struct json_value c;
    json_init(&c);
    json_set_object(&c);
    bool ok = true;
    ok &= json_push_kv_int(&c, "leaves_total", (int64_t)s->leaf_count);
    ok &= json_push_kv_int(&c, "leaves_rendered", (int64_t)rendered);
    ok &= json_push_kv_int(&c, "present", (int64_t)t->present);
    ok &= json_push_kv_int(&c, "unavailable", (int64_t)t->unavailable);
    ok &= json_push_kv_int(&c, "not_applicable", (int64_t)t->not_applicable);
    ok &= json_push_kv_int(&c, "truncated", (int64_t)t->truncated);
    ok &= json_push_kv_int(&c, "unset", (int64_t)t->unset);
    /* not_applicable does not break completeness: it is a real answer. */
    ok &= json_push_kv_bool(&c, "complete", t->unavailable == 0 &&
                                            t->unset == 0 && t->truncated == 0);
    ok &= json_push_kv_bool(&c, "provider_defect", t->provider_defect);
    ok &= json_push_kv(out, "completeness", &c);
    json_free(&c);
    if (!ok)
        LOG_FAIL("telemetry_render",
                 "domain %s: out of memory writing completeness", s->domain);
    return true;
}

static bool push_freshness(struct json_value *out,
                           const struct telemetry_domain_schema *s,
                           const void *snap)
{
    bool have_observed = false, have_age = false;
    int64_t oldest = 0;
    int64_t max_age = 0;
    size_t unknown_age = 0;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf_meta *m = leaf_meta(snap, &s->leaves[i]);
        if (m->observed_unix >= 0 && (!have_observed || m->observed_unix < oldest)) {
            oldest = m->observed_unix;
            have_observed = true;
        }
        if (m->age_ms >= 0) {
            if (!have_age || (int64_t)m->age_ms > max_age)
                max_age = (int64_t)m->age_ms;
            have_age = true;
        } else {
            unknown_age++;
        }
    }
    struct json_value f;
    json_init(&f);
    json_set_object(&f);
    bool ok = true;
    ok &= push_int_or_null(&f, "oldest_observed_unix", have_observed, oldest);
    ok &= push_int_or_null(&f, "max_age_ms", have_age, max_age);
    ok &= json_push_kv_int(&f, "leaves_with_unknown_age", (int64_t)unknown_age);
    ok &= json_push_kv_bool(&f, "any_unknown_age", unknown_age > 0);
    ok &= json_push_kv(out, "freshness", &f);
    json_free(&f);
    if (!ok)
        LOG_FAIL("telemetry_render",
                 "domain %s: out of memory writing freshness", s->domain);
    return true;
}

/* Per-leaf provenance. At FULL every leaf in view reports; below FULL only the
 * leaves that are NOT plainly present do, because those are the only ones whose
 * provenance changes how the value should be read. TRUNCATED, UNAVAILABLE,
 * NOT_APPLICABLE and UNSET are all "not plainly present" and so report at EVERY
 * tier — deliberately: a truncated string rendered from its surviving bytes
 * must never appear without the presence that says bytes were dropped. */
static bool push_leaves(struct json_value *out,
                        const struct telemetry_domain_schema *s,
                        const void *snap, enum telemetry_view view,
                        const char *only_group)
{
    struct json_value arr;
    json_init(&arr);
    json_set_object(&arr);
    bool ok = true;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        if (only_group && strcmp(lf->group, only_group) != 0)
            continue;
        if (lf->tier > view)
            continue;
        const struct telemetry_leaf_meta *m = leaf_meta(snap, lf);
        if (view != TLV_FULL && m->presence == TELEMETRY_PRESENT)
            continue;
        struct json_value e;
        json_init(&e);
        json_set_object(&e);
        ok &= json_push_kv_str(&e, "presence",
                               telemetry_presence_name(m->presence));
        ok &= json_push_kv_str(&e, "source", telemetry_source_name(m->source));
        ok &= push_int_or_null(&e, "observed_unix", m->observed_unix >= 0,
                               m->observed_unix);
        ok &= push_int_or_null(&e, "age_ms", m->age_ms >= 0, (int64_t)m->age_ms);
        ok &= json_push_kv_str(&e, "reason", m->reason ? m->reason : "");
        ok &= json_push_kv(&arr, lf->path, &e);
        json_free(&e);
    }
    ok &= json_push_kv(out, "leaves", &arr);
    json_free(&arr);
    if (!ok)
        LOG_FAIL("telemetry_render",
                 "domain %s: out of memory writing leaf provenance", s->domain);
    return true;
}

static bool push_health(struct json_value *out, const char *domain,
                        const struct telemetry_domain_verdict *v)
{
    struct json_value h, arr;
    json_init(&h);
    json_set_object(&h);
    bool ok = true;
    ok &= json_push_kv_str(&h, "state", telemetry_health_name(v->state));
    ok &= json_push_kv_int(&h, "rules_evaluated", (int64_t)v->rules_evaluated);
    ok &= json_push_kv_int(&h, "unhealthy_count", (int64_t)v->unhealthy_count);
    ok &= json_push_kv_int(&h, "unknown_count", (int64_t)v->unknown_count);

    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < v->finding_count; i++) {
        const struct telemetry_finding *fi = &v->findings[i];
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        ok &= json_push_kv_str(&o, "path", fi->path);
        ok &= json_push_kv_str(&o, "key", fi->key);
        ok &= json_push_kv_str(&o, "state", telemetry_health_name(fi->health));
        ok &= json_push_kv_str(&o, "severity",
                               telemetry_severity_name(fi->severity));
        ok &= json_push_kv_str(&o, "unit", telemetry_unit_name(fi->unit));
        if (fi->value_known && fi->value_is_bool)
            ok &= json_push_kv_bool(&o, "value", fi->value_b);
        else
            ok &= push_int_or_null(&o, "value",
                                   fi->value_known && !fi->value_is_bool,
                                   fi->value_i);
        ok &= json_push_kv_str(&o, "healthy_range", fi->healthy_range);
        ok &= json_push_kv_str(&o, "means", fi->means);
        ok &= json_push_kv_str(&o, "implies", fi->implies);
        ok &= json_push_kv_str(&o, "next", fi->next);
        ok &= json_push_back(&arr, &o);
        json_free(&o);
    }
    /* An `unhealthy` array that failed to attach reads as "nothing is wrong".
     * That is the single most dangerous omission this document can make. */
    ok &= json_push_kv(&h, "unhealthy", &arr);
    json_free(&arr);
    ok &= json_push_kv_bool(&h, "findings_truncated", v->findings_truncated);
    ok &= json_push_kv(out, "health", &h);
    json_free(&h);
    if (!ok)
        LOG_FAIL("telemetry_render",
                 "domain %s: out of memory writing the health verdict", domain);
    return true;
}

/* The legacy `_health` tail diagnostics_health_rollup.c already reads. `reason`
 * is a mechanical triple "<domain>:<state>:<worst_path>" — three
 * colon-separated fields an agent can split, never prose. "-" is the worst_path
 * when nothing is wrong, so the triple always has three parts.
 *
 * A truncated path is worse than no path: "values.net.peers_healthy" cut to
 * "values.net.peers" names a DIFFERENT, plausible leaf. Truncation therefore
 * replaces the third field with the token `path_truncated`, which no real path
 * can collide with (every real one begins "values."). The buffer is sized well
 * above the grammar's maximum, so this guards a future grammar change. */
static bool push_legacy_health(struct json_value *out, const char *domain,
                               const struct telemetry_domain_verdict *v)
{
    const char *worst = "-";
    for (size_t i = 0; i < v->finding_count; i++) {
        if (v->findings[i].health == v->state) {
            worst = v->findings[i].path;
            break;
        }
    }
    const char *state = telemetry_health_name(v->state);
    char reason[224];
    int n = snprintf(reason, sizeof reason, "%s:%s:%s", domain, state, worst);
    if (n < 0 || (size_t)n >= sizeof reason)
        snprintf(reason, sizeof reason, "%s:%s:path_truncated", domain, state);
    /* diag_push_health returns void (the legacy shape), so the attachment is
     * confirmed by reading the key back rather than by a return value. */
    diag_push_health(out, v->state == TELEMETRY_HEALTH_OK, reason);
    if (!json_get(out, "_health"))
        LOG_FAIL("telemetry_render",
                 "domain %s: out of memory writing the _health tail", domain);
    return true;
}

/* The promised shape, checked before the reply is called a success. Belt and
 * braces over the per-section returns above: it also covers diag_push_health,
 * which cannot report failure, and turns a future refactor that quietly drops
 * a section into a failed render rather than a short one. */
static bool document_is_complete(const struct json_value *out,
                                 const char *domain)
{
    static const char *const k_required[] = {
        "schema", "domain", "view", "values", "leaves",
        "completeness", "freshness", "health", "_health",
    };
    for (size_t i = 0; i < sizeof k_required / sizeof k_required[0]; i++) {
        if (!json_get(out, k_required[i]))
            LOG_FAIL("telemetry_render",
                     "domain %s: rendered document is missing '%s' — refusing "
                     "to return a partial reply", domain, k_required[i]);
    }
    return true;
}

bool telemetry_render(const struct telemetry_domain_schema *schema,
                      const void *snapshot, enum telemetry_view view,
                      const char *only_group, struct json_value *out)
{
    if (!out)
        LOG_FAIL("telemetry_render", "render: out is NULL");
    json_set_object(out);
    if (!schema || !snapshot)
        LOG_FAIL("telemetry_render", "render: schema and snapshot required");
    if (view != TLV_SUMMARY && view != TLV_NORMAL && view != TLV_FULL)
        view = TLV_NORMAL;
    if (only_group && !only_group[0])
        only_group = NULL;
    if (!prove_offsets(schema))
        LOG_FAIL("telemetry_render", "render: domain %s has an out-of-bounds "
                 "descriptor table", schema->domain);

    struct telemetry_domain_verdict verdict;
    if (!eval_domain(schema, snapshot, &verdict))
        LOG_FAIL("telemetry_render", "render: domain %s could not be judged",
                 schema->domain);

    bool hdr = true;
    hdr &= json_push_kv_str(out, "schema", schema->schema_id);
    hdr &= json_push_kv_str(out, "domain", schema->domain);
    hdr &= json_push_kv_str(out, "view", telemetry_view_name(view));
    if (only_group) {
        bool matched = false;
        for (size_t i = 0; i < schema->group_count && !matched; i++)
            matched = strcmp(schema->groups[i].name, only_group) == 0;
        hdr &= json_push_kv_str(out, "group_filter", only_group);
        /* A filter that names no group renders nothing — and says so, rather
         * than returning an empty document that reads like an empty domain. */
        hdr &= json_push_kv_bool(out, "group_filter_matched", matched);
    }
    if (!hdr)
        LOG_FAIL("telemetry_render", "render: domain %s out of memory writing "
                 "the document header", schema->domain);

    struct json_value vals;
    json_init(&vals);
    size_t rendered = 0;
    if (!build_values(schema, snapshot, view, only_group, false, &vals,
                      &rendered)) {
        json_free(&vals);
        LOG_FAIL("telemetry_render", "render: domain %s value plane failed",
                 schema->domain);
    }
    bool attached = json_push_kv(out, "values", &vals);
    json_free(&vals);
    if (!attached)
        LOG_FAIL("telemetry_render", "render: domain %s out of memory "
                 "attaching the value plane", schema->domain);

    if (!push_leaves(out, schema, snapshot, view, only_group))
        return false;

    struct presence_tally t;
    tally_presence(schema, snapshot, &t);
    if (!push_completeness(out, schema, &t, rendered) ||
        !push_freshness(out, schema, snapshot) ||
        !push_health(out, schema->domain, &verdict) ||
        !push_legacy_health(out, schema->domain, &verdict))
        return false;
    return document_is_complete(out, schema->domain);
}
