/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Telemetry ontology — the field-level meaning table plus its evaluator.
 *
 * Everything here is static const data and pure functions over it: no locks,
 * no I/O, no node state. That is the point. An operator debugging a node that
 * will not start is exactly the operator who most needs to know what
 * `pre_handshake_disconnects` counts and what 8-of-8 implies, and that
 * operator has no running node to ask.
 *
 * See util/telemetry_ontology.h for the contract and
 * util/telemetry_ontology.def for the data.
 */

#include "util/telemetry_ontology.h"

#include "json/json.h"
#include "util/log_macros.h"
#include "util/telemetry_field_table.h"

#include <stdio.h>
#include <string.h>

/* ── the tables ──────────────────────────────────────────────────────── */

#define TELEMETRY_FIELD(sub_, path_, unit_, rule_, operand_, thr_, sev_, \
                        means_, implies_, next_) \
    { .subsystem = (sub_), .path = (path_), .unit = (unit_), \
      .rule = (rule_), .operand = (operand_), .threshold = (thr_), \
      .severity = (sev_), .means = (means_), .implies = (implies_), \
      .next = (next_) },
#define TELEMETRY_ALIAS(...)
#define TELEMETRY_QUESTION(...)
/* ONE table, ONE lookup. The hand-written subsystem rows come first and keep
 * their order, then every generated domain's field table is pasted as more
 * rows of the same struct. The render layer's evaluator and `ops debug
 * meaning` therefore read the same array — there is no second ontology for
 * typed domains to drift from, and none of the accessors below know or care
 * which half a row came from.
 *
 * `subsystem` for a domain row is the domain name (telemetry_domains.def) and
 * `path` is TL_PATH(group, member) = "values.<group>.<member>", which is where
 * telemetry_render places the value in the document it evaluates. Those two
 * spellings are the whole contract between the two files. */
static const struct telemetry_field g_fields[] = {
#include "util/telemetry_ontology.def"

/* TL_SUB is the subsystem string for the table that follows; it is redefined
 * around each include because the domain name is not available inside a
 * TL_LEAF expansion. Keep each #define adjacent to its #include. */
#define TL_DOMAIN_META(d_, id_, desc_)
#define TL_GROUP(g_, desc_)
#define TL_GROUP_END(g_)
#define TL_LEAF(g_, m_, ct_, unit_, tier_, rule_, op_, thr_, sev_, \
                means_, implies_, next_) \
    { .subsystem = TL_SUB, .path = TL_PATH(g_, m_), .unit = (unit_), \
      .rule = (rule_), .operand = (op_), .threshold = (thr_), \
      .severity = (sev_), .means = (means_), .implies = (implies_), \
      .next = (next_) },

#define TL_SUB "runtime"
#include "util/telemetry/runtime_fields.def"
#undef TL_SUB
#define TL_SUB "sync"
#include "util/telemetry/sync_fields.def"
#undef TL_SUB
#define TL_SUB "network"
#include "util/telemetry/network_fields.def"
#undef TL_SUB
#define TL_SUB "storage"
#include "util/telemetry/storage_fields.def"
#undef TL_SUB
#define TL_SUB "wallet"
#include "util/telemetry/wallet_fields.def"
#undef TL_SUB
#define TL_SUB "agents"
#include "util/telemetry/agents_fields.def"
#undef TL_SUB
#define TL_SUB "zcode"
#include "util/telemetry/zcode_fields.def"
#undef TL_SUB
#define TL_SUB "metaverse"
#include "util/telemetry/metaverse_fields.def"
#undef TL_SUB

#undef TL_LEAF
#undef TL_GROUP_END
#undef TL_GROUP
#undef TL_DOMAIN_META
};
#undef TELEMETRY_QUESTION
#undef TELEMETRY_ALIAS
#undef TELEMETRY_FIELD

#define TELEMETRY_FIELD(...)
#define TELEMETRY_ALIAS(sub_, prefix_, same_, note_) \
    { .subsystem = (sub_), .prefix = (prefix_), .same_fields_as = (same_), \
      .note = (note_) },
#define TELEMETRY_QUESTION(...)
static const struct telemetry_alias g_aliases[] = {
#include "util/telemetry_ontology.def"
};
#undef TELEMETRY_QUESTION
#undef TELEMETRY_ALIAS
#undef TELEMETRY_FIELD

#define TELEMETRY_FIELD(...)
#define TELEMETRY_ALIAS(...)
#define TELEMETRY_QUESTION(id_, q_, kw_, cmd_, sub_, fields_, how_) \
    { .id = (id_), .question = (q_), .keywords = (kw_), .command = (cmd_), \
      .subsystem = (sub_), .fields = (fields_), .how_to_read = (how_) },
static const struct telemetry_question g_questions[] = {
#include "util/telemetry_ontology.def"
};
#undef TELEMETRY_QUESTION
#undef TELEMETRY_ALIAS
#undef TELEMETRY_FIELD

#define FIELD_COUNT (sizeof(g_fields) / sizeof(g_fields[0]))
#define ALIAS_COUNT (sizeof(g_aliases) / sizeof(g_aliases[0]))
#define QUESTION_COUNT (sizeof(g_questions) / sizeof(g_questions[0]))

/* ── accessors ───────────────────────────────────────────────────────── */

size_t telemetry_field_count(void) { return FIELD_COUNT; }

const struct telemetry_field *telemetry_field_at(size_t idx)
{
    return idx < FIELD_COUNT ? &g_fields[idx] : NULL;
}

const struct telemetry_field *telemetry_field_lookup(const char *subsystem,
                                                     const char *path)
{
    if (!subsystem || !path)
        return NULL;
    for (size_t i = 0; i < FIELD_COUNT; i++) {
        if (strcmp(g_fields[i].subsystem, subsystem) == 0 &&
            strcmp(g_fields[i].path, path) == 0)
            return &g_fields[i];
    }
    return NULL;
}

size_t telemetry_alias_count(void) { return ALIAS_COUNT; }

const struct telemetry_alias *telemetry_alias_at(size_t idx)
{
    return idx < ALIAS_COUNT ? &g_aliases[idx] : NULL;
}

size_t telemetry_question_count(void) { return QUESTION_COUNT; }

const struct telemetry_question *telemetry_question_at(size_t idx)
{
    return idx < QUESTION_COUNT ? &g_questions[idx] : NULL;
}

bool telemetry_subsystem_covered(const char *subsystem)
{
    if (!subsystem || !subsystem[0])
        return false;
    for (size_t i = 0; i < FIELD_COUNT; i++) {
        if (strcmp(g_fields[i].subsystem, subsystem) == 0)
            return true;
    }
    return false;
}

/* Distinct subsystem names, in table order (the table is grouped, so this is
 * a first-occurrence walk and needs no allocation). */
size_t telemetry_subsystem_count(void)
{
    size_t n = 0;
    for (size_t i = 0; i < FIELD_COUNT; i++) {
        bool seen = false;
        for (size_t j = 0; j < i; j++) {
            if (strcmp(g_fields[i].subsystem, g_fields[j].subsystem) == 0) {
                seen = true;
                break;
            }
        }
        if (!seen)
            n++;
    }
    return n;
}

const char *telemetry_subsystem_at(size_t idx)
{
    size_t n = 0;
    for (size_t i = 0; i < FIELD_COUNT; i++) {
        bool seen = false;
        for (size_t j = 0; j < i; j++) {
            if (strcmp(g_fields[i].subsystem, g_fields[j].subsystem) == 0) {
                seen = true;
                break;
            }
        }
        if (seen)
            continue;
        if (n == idx)
            return g_fields[i].subsystem;
        n++;
    }
    return NULL;
}

const char *telemetry_unit_name(enum telemetry_unit u)
{
    switch (u) {
    case TFU_COUNT_TOTAL:    return "count_total";
    case TFU_GAUGE:          return "gauge";
    case TFU_BOOL:           return "bool";
    case TFU_ENUM:           return "enum";
    case TFU_IDENTITY:       return "identity";
    case TFU_SECONDS:        return "seconds";
    case TFU_MICROSECONDS:   return "microseconds";
    case TFU_UNIX_TIME:      return "unix_time";
    case TFU_BYTES:          return "bytes";
    case TFU_HEIGHT:         return "block_height";
    case TFU_BLOCKS:         return "blocks";
    case TFU_BPS_X1000:      return "blocks_per_second_x1000";
    }
    return "unknown";
}

const char *telemetry_rule_name(enum telemetry_rule r)
{
    switch (r) {
    case TFR_INFO:            return "info";
    case TFR_EXPECT_ZERO:     return "expect_zero";
    case TFR_EXPECT_NONZERO:  return "expect_nonzero";
    case TFR_EXPECT_TRUE:     return "expect_true";
    case TFR_EXPECT_FALSE:    return "expect_false";
    case TFR_MIN_ABS:         return "min_abs";
    case TFR_MAX_ABS:         return "max_abs";
    case TFR_MIN_RATIO_OF:    return "min_ratio_of";
    case TFR_MAX_RATIO_OF:    return "max_ratio_of";
    }
    return "unknown";
}

const char *telemetry_severity_name(enum telemetry_severity s)
{
    switch (s) {
    case TFS_INFO:     return "info";
    case TFS_WARN:     return "warn";
    case TFS_CRITICAL: return "critical";
    }
    return "unknown";
}

void telemetry_field_healthy_range(const struct telemetry_field *f,
                                   char *out, size_t out_sz)
{
    if (!out || out_sz == 0)
        return;
    out[0] = '\0';
    if (!f)
        return;
    const char *operand = f->operand ? f->operand : "?";
    switch (f->rule) {
    case TFR_INFO:
        snprintf(out, out_sz, "descriptive (no health verdict)");
        break;
    case TFR_EXPECT_ZERO:
        snprintf(out, out_sz, "value == 0");
        break;
    case TFR_EXPECT_NONZERO:
        snprintf(out, out_sz, "value != 0");
        break;
    case TFR_EXPECT_TRUE:
        snprintf(out, out_sz, "value == true");
        break;
    case TFR_EXPECT_FALSE:
        snprintf(out, out_sz, "value == false");
        break;
    case TFR_MIN_ABS:
        snprintf(out, out_sz, "value >= %d", f->threshold);
        break;
    case TFR_MAX_ABS:
        snprintf(out, out_sz, "value <= %d", f->threshold);
        break;
    case TFR_MIN_RATIO_OF:
        snprintf(out, out_sz, "value >= %d.%03d * %s",
                 f->threshold / 1000, f->threshold % 1000, operand);
        break;
    case TFR_MAX_RATIO_OF:
        snprintf(out, out_sz, "value <= %d.%03d * %s",
                 f->threshold / 1000, f->threshold % 1000, operand);
        break;
    }
}

/* ── JSON rendering ──────────────────────────────────────────────────── */

static void push_field_json(struct json_value *arr,
                            const struct telemetry_field *f)
{
    char range[192];
    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_str(&obj, "subsystem", f->subsystem);
    json_push_kv_str(&obj, "path", f->path);
    json_push_kv_str(&obj, "unit", telemetry_unit_name(f->unit));
    json_push_kv_str(&obj, "rule", telemetry_rule_name(f->rule));
    json_push_kv_str(&obj, "rule_operand", f->operand ? f->operand : "");
    json_push_kv_int(&obj, "rule_threshold", f->threshold);
    telemetry_field_healthy_range(f, range, sizeof(range));
    json_push_kv_str(&obj, "healthy_range", range);
    json_push_kv_str(&obj, "severity_if_unhealthy",
                     telemetry_severity_name(f->severity));
    json_push_kv_str(&obj, "means", f->means);
    json_push_kv_str(&obj, "implies", f->implies);
    json_push_kv_str(&obj, "next", f->next);
    json_push_kv_bool(&obj, "per_element", strstr(f->path, "[]") != NULL);
    json_push_back(arr, &obj);
    json_free(&obj);
}

static void push_question_json(struct json_value *arr,
                               const struct telemetry_question *q)
{
    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_str(&obj, "id", q->id);
    json_push_kv_str(&obj, "question", q->question);
    json_push_kv_str(&obj, "keywords", q->keywords);
    json_push_kv_str(&obj, "command", q->command);
    json_push_kv_str(&obj, "subsystem", q->subsystem);
    json_push_kv_str(&obj, "decisive_fields", q->fields);
    json_push_kv_str(&obj, "how_to_read", q->how_to_read);
    json_push_back(arr, &obj);
    json_free(&obj);
}

/* Does `path` end in the bare field name `name` (after the last '.')? */
static bool path_leaf_is(const char *path, const char *name)
{
    const char *dot = strrchr(path, '.');
    return strcmp(dot ? dot + 1 : path, name) == 0;
}

bool telemetry_ontology_json(struct json_value *out, const char *key)
{
    if (!out)
        LOG_FAIL("telemetry_ontology", "json: out is NULL");
    json_set_object(out);

    bool want_questions = !key || !key[0] || strcmp(key, "questions") == 0;
    bool questions_only = key && strcmp(key, "questions") == 0;

    json_push_kv_str(out, "schema", "zcl.telemetry_ontology.v1");
    json_push_kv_str(out, "source",
                     "platform/modules/util/include/util/telemetry_ontology.def");
    json_push_kv_bool(out, "node_free", true);
    json_push_kv_int(out, "field_rows_total", (int64_t)FIELD_COUNT);

    if (!questions_only) {
        struct json_value fields = {0};
        json_set_array(&fields);
        for (size_t i = 0; i < FIELD_COUNT; i++) {
            const struct telemetry_field *f = &g_fields[i];
            if (key && key[0]) {
                bool subsystem_match = strcmp(f->subsystem, key) == 0;
                bool leaf_match = path_leaf_is(f->path, key);
                if (!subsystem_match && !leaf_match)
                    continue;
            }
            push_field_json(&fields, f);
        }
        json_push_kv_int(out, "field_rows_returned",
                         (int64_t)json_size(&fields));
        json_push_kv(out, "fields", &fields);
        json_free(&fields);

        struct json_value aliases = {0};
        json_set_array(&aliases);
        for (size_t i = 0; i < ALIAS_COUNT; i++) {
            if (key && key[0] && strcmp(g_aliases[i].subsystem, key) != 0)
                continue;
            struct json_value obj = {0};
            json_set_object(&obj);
            json_push_kv_str(&obj, "subsystem", g_aliases[i].subsystem);
            json_push_kv_str(&obj, "prefix", g_aliases[i].prefix);
            json_push_kv_str(&obj, "same_fields_as",
                             g_aliases[i].same_fields_as);
            json_push_kv_str(&obj, "note", g_aliases[i].note);
            json_push_back(&aliases, &obj);
            json_free(&obj);
        }
        json_push_kv(out, "alias_prefixes", &aliases);
        json_free(&aliases);

        struct json_value subs = {0};
        json_set_array(&subs);
        for (size_t i = 0; i < telemetry_subsystem_count(); i++) {
            struct json_value v = {0};
            json_set_str(&v, telemetry_subsystem_at(i));
            json_push_back(&subs, &v);
            json_free(&v);
        }
        json_push_kv(out, "covered_subsystems", &subs);
        json_free(&subs);
    }

    if (want_questions || (key && key[0])) {
        struct json_value qs = {0};
        json_set_array(&qs);
        for (size_t i = 0; i < QUESTION_COUNT; i++) {
            const struct telemetry_question *q = &g_questions[i];
            if (key && key[0] && !questions_only) {
                if (strcmp(q->subsystem, key) != 0 &&
                    !strstr(q->keywords, key) && !strstr(q->fields, key))
                    continue;
            }
            push_question_json(&qs, q);
        }
        json_push_kv(out, "questions", &qs);
        json_free(&qs);
    }
    return true;
}

/* ── evaluation ──────────────────────────────────────────────────────── */

/* Resolve a dotted path against a dump body. Returns NULL when any segment is
 * missing or when the path crosses an array (per-element rows are documented,
 * never auto-judged). */
static const struct json_value *resolve_path(const struct json_value *dump,
                                             const char *path)
{
    const struct json_value *cur = dump;
    const char *p = path;
    char seg[128];

    if (strstr(path, "[]"))
        return NULL;
    while (cur && *p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len == 0 || len >= sizeof(seg))
            return NULL;
        memcpy(seg, p, len);
        seg[len] = '\0';
        cur = json_get(cur, seg);
        if (!dot)
            break;
        p = dot + 1;
    }
    return cur;
}

const char *telemetry_verdict_name(enum telemetry_verdict v)
{
    switch (v) {
    case TV_HEALTHY:       return "healthy";
    case TV_UNHEALTHY:     return "unhealthy";
    case TV_NOT_JUDGED:    return "not_judged";
    case TV_ABSENT:        return "absent";
    case TV_NOT_EVALUATED: return "not_evaluated";
    }
    return "unknown";
}

enum telemetry_verdict telemetry_field_evaluate(
    const struct telemetry_field *f, const struct json_value *dump,
    const struct json_value **out_value)
{
    if (!out_value)
        return TV_NOT_EVALUATED;
    *out_value = NULL;
    if (!f || !dump)
        return TV_NOT_EVALUATED;
    if (strstr(f->path, "[]"))
        return TV_NOT_EVALUATED;

    const struct json_value *v = resolve_path(dump, f->path);
    if (!v)
        return TV_ABSENT;
    *out_value = v;
    if (f->rule == TFR_INFO)
        return TV_NOT_JUDGED;

    bool is_bool = v->type == JSON_BOOL;
    bool bval = is_bool && json_get_bool(v);
    int64_t n = (v->type == JSON_INT) ? json_get_int(v) : 0;
    bool numeric = v->type == JSON_INT;

    switch (f->rule) {
    /* A non-bool here is "we could not read it", NOT "it is false". The
     * render layer represents an unavailable leaf as JSON null, so treating a
     * type mismatch as UNHEALTHY reported every unreadable flag as a broken
     * flag — and a critical row would have driven the whole domain unhealthy
     * on nothing but a missed read. Same guard the numeric rules below
     * already had. */
    case TFR_EXPECT_TRUE:
        if (!is_bool) return TV_ABSENT;
        return bval ? TV_HEALTHY : TV_UNHEALTHY;
    case TFR_EXPECT_FALSE:
        if (!is_bool) return TV_ABSENT;
        return !bval ? TV_HEALTHY : TV_UNHEALTHY;
    case TFR_EXPECT_ZERO:
        if (!numeric) return TV_ABSENT;
        return n == 0 ? TV_HEALTHY : TV_UNHEALTHY;
    case TFR_EXPECT_NONZERO:
        if (!numeric) return TV_ABSENT;
        return n != 0 ? TV_HEALTHY : TV_UNHEALTHY;
    case TFR_MIN_ABS:
        if (!numeric) return TV_ABSENT;
        return n >= f->threshold ? TV_HEALTHY : TV_UNHEALTHY;
    case TFR_MAX_ABS:
        if (!numeric) return TV_ABSENT;
        return n <= f->threshold ? TV_HEALTHY : TV_UNHEALTHY;
    case TFR_MIN_RATIO_OF:
    case TFR_MAX_RATIO_OF: {
        if (!numeric || !f->operand)
            return TV_ABSENT;
        const struct json_value *ov = resolve_path(dump, f->operand);
        if (!ov || ov->type != JSON_INT)
            return TV_ABSENT;
        int64_t base = json_get_int(ov);
        /* A zero or negative denominator carries no ratio information; the
         * operand's own row is where that gets judged, not here. */
        if (base <= 0)
            return TV_NOT_EVALUATED;
        int64_t lhs = n * 1000;
        int64_t rhs = base * (int64_t)f->threshold;
        if (f->rule == TFR_MIN_RATIO_OF)
            return lhs >= rhs ? TV_HEALTHY : TV_UNHEALTHY;
        return lhs <= rhs ? TV_HEALTHY : TV_UNHEALTHY;
    }
    case TFR_INFO:
        break;
    }
    return TV_NOT_JUDGED;
}

bool telemetry_ontology_annotate(const char *subsystem,
                                 const struct json_value *dump,
                                 struct json_value *out)
{
    if (!out)
        LOG_FAIL("telemetry_ontology", "annotate: out is NULL");
    if (!subsystem || !dump)
        LOG_FAIL("telemetry_ontology", "annotate: subsystem and dump required");
    json_set_object(out);
    if (!telemetry_subsystem_covered(subsystem)) {
        json_push_kv_str(out, "subsystem", subsystem);
        json_push_kv_bool(out, "covered", false);
        json_push_kv_str(out, "hint",
                         "no field ontology for this subsystem yet; "
                         "z23 ops meaning lists the covered set");
        LOG_FAIL("telemetry_ontology",
                 "annotate: subsystem '%s' has no field ontology yet",
                 subsystem);
    }

    json_push_kv_str(out, "subsystem", subsystem);
    json_push_kv_bool(out, "covered", true);

    struct json_value findings = {0};
    json_set_array(&findings);
    int64_t evaluated = 0, unhealthy = 0, absent = 0, critical = 0;

    for (size_t i = 0; i < FIELD_COUNT; i++) {
        const struct telemetry_field *f = &g_fields[i];
        if (strcmp(f->subsystem, subsystem) != 0)
            continue;
        const struct json_value *value = NULL;
        enum telemetry_verdict verdict =
            telemetry_field_evaluate(f, dump, &value);
        if (verdict == TV_HEALTHY || verdict == TV_UNHEALTHY)
            evaluated++;
        if (verdict == TV_ABSENT)
            absent++;
        if (verdict != TV_UNHEALTHY)
            continue;
        unhealthy++;
        if (f->severity == TFS_CRITICAL)
            critical++;

        char range[192];
        telemetry_field_healthy_range(f, range, sizeof(range));
        struct json_value obj = {0};
        json_set_object(&obj);
        json_push_kv_str(&obj, "path", f->path);
        if (value && value->type == JSON_INT)
            json_push_kv_int(&obj, "value", json_get_int(value));
        else if (value && value->type == JSON_BOOL)
            json_push_kv_bool(&obj, "value", json_get_bool(value));
        json_push_kv_str(&obj, "verdict", telemetry_verdict_name(verdict));
        json_push_kv_str(&obj, "severity",
                         telemetry_severity_name(f->severity));
        json_push_kv_str(&obj, "unit", telemetry_unit_name(f->unit));
        json_push_kv_str(&obj, "healthy_range", range);
        json_push_kv_str(&obj, "means", f->means);
        json_push_kv_str(&obj, "implies", f->implies);
        json_push_kv_str(&obj, "next", f->next);
        json_push_back(&findings, &obj);
        json_free(&obj);
    }

    json_push_kv_int(out, "rules_evaluated", evaluated);
    json_push_kv_int(out, "fields_absent", absent);
    json_push_kv_int(out, "unhealthy_count", unhealthy);
    json_push_kv_int(out, "critical_count", critical);
    json_push_kv_bool(out, "healthy", unhealthy == 0);
    json_push_kv(out, "findings", &findings);
    json_free(&findings);
    return true;
}

bool telemetry_ontology_dump_state_json(struct json_value *out,
                                        const char *key)
{
    return telemetry_ontology_json(out, key);
}
