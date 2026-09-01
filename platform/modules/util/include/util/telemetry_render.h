/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Telemetry render layer — the ONE place a typed domain snapshot becomes JSON.
 *
 * The problem this closes. 151 dumpers each hand-write their own JSON, decide
 * their own health in prose, and omit a field when they cannot read it. An
 * agent reading the result cannot tell "0 because it is genuinely zero" from
 * "0 because nobody set it" from "absent because the store was busy", and no
 * two subsystems answer in the same shape.
 *
 * The mechanism. A domain declares its fields ONCE in a `<domain>_fields.def`
 * table. That one table is expanded several times in different translation
 * units to produce (a) the C snapshot struct, (b) the leaf-id enum, (c) the
 * offset/unit/tier descriptor table, and (d) the ontology meaning rows. The
 * field's name token is therefore written exactly once in the repository:
 * divergence between the struct member, the JSON key and the ontology path is
 * not "kept in sync", it is unrepresentable.
 *
 * Division of labour, and it is strict:
 *   provider  fills a typed snapshot. Writes no JSON, decides no health.
 *   render    walks the descriptor table and emits every leaf. Judges health
 *             by delegating to the ontology evaluator.
 *   control   picks a snapshot and a view. ~12 lines. Names no field.
 *
 * Health is DERIVED, never authored: telemetry_ontology_annotate()'s rule
 * evaluator is the single source of a verdict, here and in `ops debug meaning`.
 *
 * Layering: metadata and rendering over diagnostics output. Reads no node
 * state, takes no lock, performs no I/O. Reentrant and callable before boot.
 */
#ifndef ZCL_UTIL_TELEMETRY_RENDER_H
#define ZCL_UTIL_TELEMETRY_RENDER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util/telemetry_ontology.h"

struct json_value;

/* ── views ──────────────────────────────────────────────────────────────
 * A tier on a field row is the SHALLOWEST view that shows it, so SUMMARY
 * fields also appear in NORMAL and FULL.
 *
 * The view filters RENDERING ONLY, never evaluation: every leaf is judged on
 * every call, so `view=summary` can never report ok while a full-tier leaf is
 * critical. */
enum telemetry_view {
    TLV_SUMMARY = 0,
    TLV_NORMAL = 1,
    TLV_FULL = 2,
};

/* Storage class of a leaf. There is deliberately no pointer-valued leaf: a
 * `const char *` into a caller's stack buffer is a use-after-free waiting for
 * the first provider who forgets, so text is copied into the snapshot. */
enum telemetry_ctype {
    TLC_I64 = 0,
    TLC_BOOL,
    TLC_TEXT,
};

#define TELEMETRY_TEXT_MAX 64

/* ── health ─────────────────────────────────────────────────────────────
 * Ordered by loudness, because a rollup is max() over its leaves.
 *
 * UNKNOWN sits deliberately between OK and DEGRADED: "we could not judge it"
 * must not shout louder than "we judged it and it is broken", but it must
 * outrank OK, so a reply full of unreadable leaves can never claim health. */
enum telemetry_health {
    TELEMETRY_HEALTH_OK = 0,
    TELEMETRY_HEALTH_UNKNOWN = 1,
    TELEMETRY_HEALTH_DEGRADED = 2,
    TELEMETRY_HEALTH_UNHEALTHY = 3,
};
const char *telemetry_health_name(enum telemetry_health h);

/* ── presence ───────────────────────────────────────────────────────────
 * Zero is UNSET, and UNSET is a provider defect, never a legitimate state.
 * A `struct foo_snapshot s = {0};` therefore starts with every leaf unset, so
 * a provider that forgets a field produces a visible, counted defect instead
 * of a plausible zero. This is the whole reason the enum starts here. */
enum telemetry_presence {
    TELEMETRY_UNSET = 0,      /* nobody wrote it — a defect, reported as such */
    TELEMETRY_PRESENT,
    TELEMETRY_UNAVAILABLE,    /* real: could not be read this cycle */
    TELEMETRY_NOT_APPLICABLE, /* real: meaningless in this configuration */
    TELEMETRY_TRUNCATED,      /* real: bounded rendering dropped detail */
};
const char *telemetry_presence_name(enum telemetry_presence p);

/* Where the value came from. An agent needs this to know whether a number is
 * live, cached by another thread, or read off disk this call. */
enum telemetry_source {
    TELEMETRY_SRC_UNSET = 0,
    TELEMETRY_SRC_IN_PROCESS,         /* a counter in this process, now */
    TELEMETRY_SRC_CACHED_PUBLICATION, /* lock-free publication by a peer thread */
    TELEMETRY_SRC_DURABLE_STORE,      /* read from SQLite on this call */
    TELEMETRY_SRC_PEER_REPORTED,      /* the network told us */
    TELEMETRY_SRC_CONFIG,             /* startup configuration */
    TELEMETRY_SRC_DERIVED,            /* computed from other leaves here */
};
const char *telemetry_source_name(enum telemetry_source s);

/* Per-leaf provenance, stored beside every value in the snapshot.
 *
 * OWNERSHIP: `reason` is a STATIC string with program lifetime — a short
 * greppable token such as "progress_store_busy", never a formatted buffer and
 * never prose. It is REQUIRED whenever presence != TELEMETRY_PRESENT; a
 * missing reason is itself reported as a provider defect rather than excused. */
struct telemetry_leaf_meta {
    enum telemetry_presence presence;
    enum telemetry_source source;
    int64_t observed_unix; /* when the VALUE was produced; -1 unknown */
    int32_t age_ms;        /* -1 unknown, rendered as null */
    const char *reason;
};

/* ── the setters ────────────────────────────────────────────────────────
 * A provider writes a leaf ONLY through these. Each one writes the value and
 * its provenance together, so a value can never arrive without a presence and
 * a presence can never drift from its value.
 *
 * `snap_` is a pointer to the domain snapshot; `m_` is the field's member
 * token exactly as it appears in the field table. */
#define TELEMETRY_SET_I64(snap_, m_, val_, src_)                              \
    do {                                                                      \
        (snap_)->m_ = (int64_t)(val_);                                        \
        (snap_)->m_##_meta = (struct telemetry_leaf_meta){                    \
            .presence = TELEMETRY_PRESENT, .source = (src_),                  \
            .observed_unix = telemetry_now_unix(), .age_ms = 0,               \
            .reason = "" };                                                   \
    } while (0)

#define TELEMETRY_SET_BOOL(snap_, m_, val_, src_)                             \
    do {                                                                      \
        (snap_)->m_ = (bool)(val_);                                           \
        (snap_)->m_##_meta = (struct telemetry_leaf_meta){                    \
            .presence = TELEMETRY_PRESENT, .source = (src_),                  \
            .observed_unix = telemetry_now_unix(), .age_ms = 0,               \
            .reason = "" };                                                   \
    } while (0)

/* Bounded copy; never truncates silently — a value that does not fit is
 * recorded as TELEMETRY_TRUNCATED with the "text_too_long" reason. */
void telemetry_set_text_impl(char *dst, size_t dst_sz,
                             struct telemetry_leaf_meta *meta,
                             const char *value, enum telemetry_source src);
#define TELEMETRY_SET_TEXT(snap_, m_, val_, src_)                             \
    telemetry_set_text_impl((snap_)->m_, sizeof((snap_)->m_),                 \
                            &(snap_)->m_##_meta, (val_), (src_))

/* A value that genuinely could not be read. `why_` must be a static token. */
#define TELEMETRY_UNAVAILABLE_LEAF(snap_, m_, why_)                           \
    do {                                                                      \
        (snap_)->m_##_meta = (struct telemetry_leaf_meta){                    \
            .presence = TELEMETRY_UNAVAILABLE,                                \
            .source = TELEMETRY_SRC_UNSET, .observed_unix = -1,               \
            .age_ms = -1, .reason = (why_) };                                 \
    } while (0)

/* A value that is meaningless in this configuration — not a failure. */
#define TELEMETRY_NOT_APPLICABLE_LEAF(snap_, m_, why_)                        \
    do {                                                                      \
        (snap_)->m_##_meta = (struct telemetry_leaf_meta){                    \
            .presence = TELEMETRY_NOT_APPLICABLE,                             \
            .source = TELEMETRY_SRC_UNSET, .observed_unix = -1,               \
            .age_ms = -1, .reason = (why_) };                                 \
    } while (0)

/* Wall-clock seconds, or -1 when the platform clock is unavailable. Wrapped
 * here so the setters above stay usable before the clock is armed. */
int64_t telemetry_now_unix(void);

/* ── the descriptor tables ──────────────────────────────────────────────
 * Generated from a domain's field table; never hand-written. */

struct telemetry_group {
    const char *name;
    const char *desc;
};

/* One field. `value_off`/`meta_off` are byte offsets into the domain's
 * snapshot struct — both generated by offsetof over the same member token
 * that declared the member, so they cannot address the wrong field. */
struct telemetry_leaf {
    const char *group;
    const char *key;  /* the JSON key inside its group */
    const char *path; /* "values.<group>.<key>" — the ontology path */
    size_t value_off;
    size_t meta_off;
    enum telemetry_ctype ctype;
    enum telemetry_unit unit;
    enum telemetry_view tier;
};

/* One domain. `domain` MUST equal the ontology subsystem name, or the
 * evaluator finds no rules and every leaf reports UNKNOWN. */
struct telemetry_domain_schema {
    const char *domain;
    const char *schema_id; /* "zcl.telemetry.sync.v1" */
    const char *desc;
    size_t snapshot_size; /* bounds every offset; a table that overruns it is
                           * refused rather than read out of bounds */
    const struct telemetry_group *groups;
    size_t group_count;
    const struct telemetry_leaf *leaves;
    size_t leaf_count;
};

/* ── verdicts ───────────────────────────────────────────────────────────
 * The typed form of what render() also emits as JSON. Bounded: a domain that
 * trips more than TELEMETRY_MAX_FINDINGS rules reports the count and sets
 * `findings_truncated`, so the overflow is stated rather than hidden. */
#define TELEMETRY_MAX_FINDINGS 24

struct telemetry_finding {
    const char *path; /* static, from the leaf table */
    const char *key;
    enum telemetry_health health;
    enum telemetry_severity severity;
    enum telemetry_unit unit;
    bool value_known;
    bool value_is_bool;
    int64_t value_i;
    bool value_b;
    char healthy_range[96];
    const char *means; /* borrowed from the ontology row; static */
    const char *implies;
    const char *next;
};

struct telemetry_domain_verdict {
    enum telemetry_health state;
    size_t rules_evaluated;
    size_t unhealthy_count;
    size_t unknown_count;
    size_t finding_count;
    bool findings_truncated;
    struct telemetry_finding findings[TELEMETRY_MAX_FINDINGS];
};

/* ── the API ────────────────────────────────────────────────────────────  */

/* Parse a dumpstate `key` into a view. Accepts NULL/"" (normal), "summary",
 * "normal", "full", or a group name (that group at full detail, returned via
 * `out_group`). Never fails: an unrecognized key yields normal, and the
 * caller reports `view_key_unrecognized` rather than guessing silently. */
enum telemetry_view telemetry_view_parse(const char *key,
                                         const char **out_group,
                                         bool *out_unrecognized);
const char *telemetry_view_name(enum telemetry_view v);

/* THE renderer. Emits values, per-leaf provenance, completeness, freshness,
 * a health verdict, and the legacy `_health` tail so the existing rollup in
 * diagnostics_health_rollup.c keeps working unchanged.
 *
 * Every leaf in the table is emitted at the requested tier — omission is not
 * something a provider can cause, only a presence it can set. Allocates only
 * into `out`, which the caller owns and must json_free(). Reentrant. */
bool telemetry_render(const struct telemetry_domain_schema *schema,
                      const void *snapshot, enum telemetry_view view,
                      const char *only_group, struct json_value *out);

/* The verdict without the document, for supervisors and conditions that want
 * the enum rather than JSON. Same evaluator, same answer as telemetry_render. */
bool telemetry_evaluate(const struct telemetry_domain_schema *schema,
                        const void *snapshot,
                        struct telemetry_domain_verdict *out);

/* The domain registry, built once from util/telemetry_domains.def. */
size_t telemetry_domain_count(void);
const struct telemetry_domain_schema *telemetry_domain_at(size_t idx);
const struct telemetry_domain_schema *telemetry_domain_find(const char *domain);

#endif /* ZCL_UTIL_TELEMETRY_RENDER_H */
