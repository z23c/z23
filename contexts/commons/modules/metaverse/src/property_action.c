/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * property_action — the ONE implementation of the operation vocabulary.
 * Every function here is a lookup into the row table generated from
 * METAVERSE_ACTION_TABLE / METAVERSE_QUERY_TABLE. There is deliberately not
 * one handwritten `switch (action)` in this file: a switch is how the two
 * vocabularies this file replaced drifted apart in the first place.
 *
 * See metaverse/property_action.h for the contract. */

#include "metaverse/property_action.h"

#include <string.h>

/* One row per action, in table order. The field order matches the column
 * order documented in the header so a reader can check a row against the
 * table by eye. */
struct mv_action_row {
    uint32_t bit;
    const char *name;
    uint32_t wire;
    bool changes_local_state;
    bool changes_external_state;
    bool changes_title;
    bool accepts_value;
    bool debits_budget;
    bool uses_counterparty;
    bool allows_zero_property_id;
    bool requires_plan_commit;
    bool requires_receipt;
};

#define MV_ACTION_ROW(id_, bit_, name_, wire_, lo_, ex_, ti_, va_, bu_, cp_,  \
                      z0_, pl_, rc_)                                          \
    { .bit = (bit_), .name = (name_), .wire = (wire_),                        \
      .changes_local_state = (lo_) != 0,                                      \
      .changes_external_state = (ex_) != 0,                                   \
      .changes_title = (ti_) != 0,                                            \
      .accepts_value = (va_) != 0,                                            \
      .debits_budget = (bu_) != 0,                                            \
      .uses_counterparty = (cp_) != 0,                                        \
      .allows_zero_property_id = (z0_) != 0,                                  \
      .requires_plan_commit = (pl_) != 0,                                     \
      .requires_receipt = (rc_) != 0 },

static const struct mv_action_row k_actions[] = { /* hotswap-static-ok: leaf registration tables are immutable */
METAVERSE_ACTION_TABLE(MV_ACTION_ROW)
};
#undef MV_ACTION_ROW

_Static_assert(sizeof(k_actions) / sizeof(k_actions[0]) ==
                   (size_t)METAVERSE_ACTION_COUNT,
               "the row table and METAVERSE_ACTION_COUNT disagree: an action "
               "would be invisible to every mask renderer");

struct mv_query_row {
    uint32_t bit;
    const char *name;
    uint32_t wire;
    bool allows_zero_property_id;
};

/* The query enum's values are assigned in the header rather than generated,
 * because there are two of them and a table-generated enum whose rows must
 * still be spelled out in the header would be a second place to look. This
 * assertion is what keeps the two in step. */
#define MV_QUERY_ROW(id_, name_, wire_, z0_)                                  \
    { .bit = (uint32_t)METAVERSE_QUERY_##id_, .name = (name_),                \
      .wire = (wire_), .allows_zero_property_id = (z0_) != 0 },

static const struct mv_query_row k_queries[] = { /* hotswap-static-ok: immutable leaf registration tables */
METAVERSE_QUERY_TABLE(MV_QUERY_ROW)
};
#undef MV_QUERY_ROW

_Static_assert(sizeof(k_queries) / sizeof(k_queries[0]) ==
                   (size_t)METAVERSE_QUERY_COUNT,
               "the query row table and METAVERSE_QUERY_COUNT disagree");

static const struct metaverse_wire_golden k_golden[] = { /* hotswap-static-ok: immutable leaf registration tables */
#define MV_GOLDEN_ROW(wire_, v1_, isq_, canon_)                               \
    { .wire = (wire_), .v1_name = (v1_), .is_query = (isq_) != 0,             \
      .canonical_name = (canon_) },
    METAVERSE_WIRE_V1_TABLE(MV_GOLDEN_ROW)
#undef MV_GOLDEN_ROW
};

/* ── Row lookup ─────────────────────────────────────────────────────────── */

static const struct mv_action_row *action_row(enum metaverse_action a)
{
    uint32_t bit = (uint32_t)a;

    if (!metaverse_action_valid(a))
        return NULL;
    for (size_t i = 0; i < sizeof(k_actions) / sizeof(k_actions[0]); i++) {
        if (k_actions[i].bit == bit)
            return &k_actions[i];
    }
    return NULL;
}

static const struct mv_query_row *query_row(enum metaverse_query q)
{
    uint32_t bit = (uint32_t)q;

    if (!metaverse_query_valid(q))
        return NULL;
    for (size_t i = 0; i < sizeof(k_queries) / sizeof(k_queries[0]); i++) {
        if (k_queries[i].bit == bit)
            return &k_queries[i];
    }
    return NULL;
}

/* Name comparison that treats '-' and '_' as the same separator, so a JSON
 * key and a CLI flag name the same operation. Case-sensitive otherwise: the
 * canonical spelling is lowercase and accepting anything else would make two
 * spellings of one name. */
static bool name_eq(const char *a, const char *b)
{
    for (size_t i = 0;; i++) {
        char ca = a[i], cb = b[i];

        if (ca == '_') ca = '-';
        if (cb == '_') cb = '-';
        if (ca != cb) return false;
        if (ca == '\0') return true;
    }
}

/* Shared CSV renderer for both vocabularies, driven by the vocabulary's own
 * iterator and namer so it holds no copy of either table. Refuses rather
 * than truncates: a short list must never read as fewer rights. */
static bool mask_format(size_t row_count, uint32_t (*bit_at)(size_t),
                        const char *(*name_of)(uint32_t), uint32_t mask,
                        char *out, size_t cap)
{
    size_t used = 0;

    for (size_t i = 0; i < row_count; i++) {
        uint32_t bit = bit_at(i);
        const char *name;
        size_t nlen;

        if (bit == 0 || (mask & bit) == 0)
            continue;
        name = name_of(bit);
        if (!name) {
            out[0] = '\0';
            return false;
        }
        nlen = strlen(name);
        if (used + (used ? 1u : 0u) + nlen + 1u > cap) {
            out[0] = '\0';
            return false;
        }
        if (used)
            out[used++] = ',';
        memcpy(out + used, name, nlen);
        used += nlen;
        out[used] = '\0';
    }
    return true;
}

/* Shared CSV parser. `resolve` maps one element to its bit, or 0. */
static bool set_parse(const char *csv, uint32_t *out,
                      uint32_t (*resolve)(const char *))
{
    const char *p = csv;
    char tok[48];

    *out = 0u;
    if (!csv || csv[0] == '\0')
        return true; /* the empty set: well-formed, authorizes nothing */

    while (*p) {
        size_t n = 0;
        uint32_t bit;

        while (*p == ' ' || *p == ',')
            p++;
        if (!*p)
            break;
        while (*p && *p != ',' && *p != ' ') {
            if (n + 1 >= sizeof(tok)) {
                *out = 0u;
                return false;
            }
            tok[n++] = *p++;
        }
        tok[n] = '\0';
        bit = resolve(tok);
        if (bit == 0u) {
            *out = 0u;
            return false;
        }
        *out |= bit;
    }
    return true;
}

/* ── Actions ────────────────────────────────────────────────────────────── */

const char *metaverse_action_name(uint32_t bit)
{
    /* Exactly one bit, or nothing. A multi-bit value has no single name and
     * must not be rendered as whichever action happens to match first. */
    if (bit == 0 || (bit & (bit - 1u)) != 0)
        return NULL;
    if (bit == METAVERSE_ACTION_RESERVED_INSPECT)
        return "inspect"; /* decoded for compatibility; never grantable */
    for (size_t i = 0; i < sizeof(k_actions) / sizeof(k_actions[0]); i++) {
        if (k_actions[i].bit == bit)
            return k_actions[i].name;
    }
    return NULL;
}

const char *metaverse_action_token(enum metaverse_action a)
{
    const char *n = metaverse_action_name((uint32_t)a);

    return n ? n : "unknown";
}

uint32_t metaverse_action_from_name(const char *name)
{
    if (!name || !*name)
        return 0;
    for (size_t i = 0; i < sizeof(k_actions) / sizeof(k_actions[0]); i++) {
        if (name_eq(name, k_actions[i].name))
            return k_actions[i].bit;
    }
    return 0;
}

bool metaverse_action_parse(const char *name, enum metaverse_action *out)
{
    uint32_t bit;

    if (!out)
        return false;
    bit = metaverse_action_from_name(name);
    if (bit == 0) {
        *out = METAVERSE_ACTION_NONE;
        return false;
    }
    *out = (enum metaverse_action)bit;
    return true;
}

uint32_t metaverse_action_at(size_t i)
{
    if (i >= sizeof(k_actions) / sizeof(k_actions[0]))
        return 0;
    return k_actions[i].bit;
}

bool metaverse_action_mask_valid(uint32_t mask)
{
    return (mask & ~(uint32_t)METAVERSE_ACTION_ALL) == 0;
}

bool metaverse_action_mask_format(uint32_t mask, char *out, size_t cap)
{
    if (!out || cap == 0)
        return false;
    out[0] = '\0';
    if (!metaverse_action_mask_valid(mask))
        return false;
    return mask_format(sizeof(k_actions) / sizeof(k_actions[0]),
                       metaverse_action_at, metaverse_action_name, mask, out,
                       cap);
}

bool metaverse_action_set_parse(const char *csv, metaverse_action_set *out)
{
    if (!out)
        return false;
    return set_parse(csv, out, metaverse_action_from_name);
}

#define MV_ACTION_PREDICATE(fn_, field_)                                      \
    bool fn_(enum metaverse_action a)                                         \
    {                                                                         \
        const struct mv_action_row *r = action_row(a);                        \
        return r && r->field_;                                                \
    }

MV_ACTION_PREDICATE(metaverse_action_changes_local_state, changes_local_state)
MV_ACTION_PREDICATE(metaverse_action_changes_external_state,
                    changes_external_state)
MV_ACTION_PREDICATE(metaverse_action_changes_title, changes_title)
MV_ACTION_PREDICATE(metaverse_action_accepts_value, accepts_value)
MV_ACTION_PREDICATE(metaverse_action_moves_value, debits_budget)
MV_ACTION_PREDICATE(metaverse_action_uses_counterparty, uses_counterparty)
MV_ACTION_PREDICATE(metaverse_action_allows_zero_property_id,
                    allows_zero_property_id)
MV_ACTION_PREDICATE(metaverse_action_requires_plan_commit,
                    requires_plan_commit)
MV_ACTION_PREDICATE(metaverse_action_requires_receipt, requires_receipt)
#undef MV_ACTION_PREDICATE

bool metaverse_action_is_mutation(enum metaverse_action a)
{
    const struct mv_action_row *r = action_row(a);

    return r && r->changes_external_state;
}

bool metaverse_action_changes_state(enum metaverse_action a)
{
    const struct mv_action_row *r = action_row(a);

    return r && (r->changes_local_state || r->changes_external_state);
}

/* ── Queries ────────────────────────────────────────────────────────────── */

const char *metaverse_query_name(enum metaverse_query q)
{
    const struct mv_query_row *r = query_row(q);

    return r ? r->name : "unknown";
}

/* The renderer's namer: NULL (not "unknown") for a bit that names nothing,
 * so a malformed mask refuses instead of rendering a placeholder. */
static const char *query_name_of_bit(uint32_t bit)
{
    const struct mv_query_row *r = query_row((enum metaverse_query)bit);

    return r ? r->name : NULL;
}

enum metaverse_query metaverse_query_from_name(const char *name)
{
    if (!name || !*name)
        return METAVERSE_QUERY_NONE;
    for (size_t i = 0; i < sizeof(k_queries) / sizeof(k_queries[0]); i++) {
        if (name_eq(name, k_queries[i].name))
            return (enum metaverse_query)k_queries[i].bit;
    }
    return METAVERSE_QUERY_NONE;
}

uint32_t metaverse_query_at(size_t i)
{
    if (i >= sizeof(k_queries) / sizeof(k_queries[0]))
        return 0;
    return k_queries[i].bit;
}

bool metaverse_query_mask_valid(uint32_t mask)
{
    return (mask & ~(uint32_t)METAVERSE_QUERY_ALL) == 0;
}

bool metaverse_query_mask_format(uint32_t mask, char *out, size_t cap)
{
    if (!out || cap == 0)
        return false;
    out[0] = '\0';
    if (!metaverse_query_mask_valid(mask))
        return false;
    return mask_format(sizeof(k_queries) / sizeof(k_queries[0]),
                       metaverse_query_at, query_name_of_bit, mask, out, cap);
}

static uint32_t query_bit_from_name(const char *name)
{
    return (uint32_t)metaverse_query_from_name(name);
}

bool metaverse_query_set_parse(const char *csv, metaverse_query_set *out)
{
    if (!out)
        return false;
    return set_parse(csv, out, query_bit_from_name);
}

bool metaverse_query_allows_zero_property_id(enum metaverse_query q)
{
    const struct mv_query_row *r = query_row(q);

    return r && r->allows_zero_property_id;
}

/* ── The broker wire ────────────────────────────────────────────────────── */

uint32_t metaverse_action_wire(enum metaverse_action a)
{
    const struct mv_action_row *r = action_row(a);

    return r ? r->wire : 0u;
}

enum metaverse_action metaverse_action_from_wire(uint32_t wire)
{
    if (wire == 0u)
        return METAVERSE_ACTION_NONE;
    for (size_t i = 0; i < sizeof(k_actions) / sizeof(k_actions[0]); i++) {
        if (k_actions[i].wire == wire)
            return (enum metaverse_action)k_actions[i].bit;
    }
    return METAVERSE_ACTION_NONE;
}

uint32_t metaverse_query_wire(enum metaverse_query q)
{
    const struct mv_query_row *r = query_row(q);

    return r ? r->wire : 0u;
}

enum metaverse_query metaverse_query_from_wire(uint32_t wire)
{
    if (wire == 0u)
        return METAVERSE_QUERY_NONE;
    for (size_t i = 0; i < sizeof(k_queries) / sizeof(k_queries[0]); i++) {
        if (k_queries[i].wire == wire)
            return (enum metaverse_query)k_queries[i].bit;
    }
    return METAVERSE_QUERY_NONE;
}

bool metaverse_operation_from_wire(uint32_t wire, uint32_t version,
                                   struct metaverse_operation *out)
{
    enum metaverse_query q;
    enum metaverse_action a;

    if (!out)
        return false;
    out->kind = METAVERSE_OP_UNKNOWN;
    out->query = METAVERSE_QUERY_NONE;
    out->action = METAVERSE_ACTION_NONE;

    if (version == 0u)
        version = METAVERSE_WIRE_VERSION;
    if (version < METAVERSE_WIRE_VERSION_MIN ||
        version > METAVERSE_WIRE_VERSION)
        return false;
    /* The bounded version-1 decoder: version 1 shipped verbs 1..13 and
     * cannot express LIST_FOR_SALE. Accepting 14 from a version-1 frame
     * would credit a peer with a verb its own encoder could not produce. */
    if (version == 1u && wire > METAVERSE_WIRE_V1_VERB_MAX)
        return false;

    q = metaverse_query_from_wire(wire);
    if (q != METAVERSE_QUERY_NONE) {
        out->kind = METAVERSE_OP_QUERY;
        out->query = q;
        return true;
    }
    a = metaverse_action_from_wire(wire);
    if (a != METAVERSE_ACTION_NONE) {
        out->kind = METAVERSE_OP_ACTION;
        out->action = a;
        return true;
    }
    return false;
}

uint32_t metaverse_operation_wire(const struct metaverse_operation *op)
{
    if (!op)
        return 0u;
    if (op->kind == METAVERSE_OP_QUERY)
        return metaverse_query_wire(op->query);
    if (op->kind == METAVERSE_OP_ACTION)
        return metaverse_action_wire(op->action);
    return 0u;
}

bool metaverse_operation_from_name(const char *name,
                                   struct metaverse_operation *out)
{
    enum metaverse_query q;
    uint32_t bit;

    if (!out)
        return false;
    out->kind = METAVERSE_OP_UNKNOWN;
    out->query = METAVERSE_QUERY_NONE;
    out->action = METAVERSE_ACTION_NONE;
    if (!name || !*name)
        return false;

    q = metaverse_query_from_name(name);
    if (q != METAVERSE_QUERY_NONE) {
        out->kind = METAVERSE_OP_QUERY;
        out->query = q;
        return true;
    }
    bit = metaverse_action_from_name(name);
    if (bit != 0u) {
        out->kind = METAVERSE_OP_ACTION;
        out->action = (enum metaverse_action)bit;
        return true;
    }
    return false;
}

const char *metaverse_operation_name(const struct metaverse_operation *op)
{
    if (!op)
        return "unknown";
    if (op->kind == METAVERSE_OP_QUERY)
        return metaverse_query_name(op->query);
    if (op->kind == METAVERSE_OP_ACTION)
        return metaverse_action_token(op->action);
    return "unknown";
}

size_t metaverse_wire_golden_count(void)
{
    return sizeof(k_golden) / sizeof(k_golden[0]);
}

const struct metaverse_wire_golden *metaverse_wire_golden_at(size_t i)
{
    if (i >= metaverse_wire_golden_count())
        return NULL;
    return &k_golden[i];
}
