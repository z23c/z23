/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * property_id — pure implementation. No I/O, no allocation, no logging
 * dependency: every failure here is a caller argument error the caller can
 * see from the return value, and this file is linked into the pure-rule
 * layer that the confined agent broker also speaks. */

#include "metaverse/property_id.h"

#include "base/hex.h"

#include <string.h>

const char *metaverse_kind_name(enum metaverse_kind kind)
{
    switch (kind) {
#define METAVERSE_KIND_NAME_CASE(id_, name_, authority_, settle_, wire_)     \
    case METAVERSE_KIND_##id_: return name_;
    METAVERSE_KIND_TABLE(METAVERSE_KIND_NAME_CASE)
#undef METAVERSE_KIND_NAME_CASE
    case METAVERSE_KIND_UNKNOWN:
    case METAVERSE_KIND_COUNT:
        break;
    }
    return "unknown";
}

const char *metaverse_kind_authority(enum metaverse_kind kind)
{
    switch (kind) {
#define METAVERSE_KIND_AUTH_CASE(id_, name_, authority_, settle_, wire_)     \
    case METAVERSE_KIND_##id_: return authority_;
    METAVERSE_KIND_TABLE(METAVERSE_KIND_AUTH_CASE)
#undef METAVERSE_KIND_AUTH_CASE
    case METAVERSE_KIND_UNKNOWN:
    case METAVERSE_KIND_COUNT:
        break;
    }
    return "unknown";
}

/* The switch is exhaustive over enum metaverse_kind and carries NO default.
 * Two things follow, and both are the point:
 *   - a kind added to METAVERSE_KIND_TABLE without a fourth column does not
 *     preprocess (the X macro takes four arguments), and
 *   - a kind added ANYWHERE ELSE — a hand-written enumerator that skipped
 *     the table — is a -Wswitch error here rather than a silent UNKNOWN.
 * The header's per-row _Static_assert covers the third case, a fourth
 * column that names a class outside the enum. */
enum metaverse_settlement metaverse_kind_settlement(enum metaverse_kind kind)
{
    switch (kind) {
#define METAVERSE_KIND_SETTLE_CASE(id_, name_, authority_, settle_, wire_)   \
    case METAVERSE_KIND_##id_: return METAVERSE_SETTLEMENT_##settle_;
    METAVERSE_KIND_TABLE(METAVERSE_KIND_SETTLE_CASE)
#undef METAVERSE_KIND_SETTLE_CASE
    case METAVERSE_KIND_UNKNOWN:
    case METAVERSE_KIND_COUNT:
        break;
    }
    return METAVERSE_SETTLEMENT_UNKNOWN;
}

const char *metaverse_settlement_name(enum metaverse_settlement settlement)
{
    switch (settlement) {
    case METAVERSE_SETTLEMENT_CONTENT_ADDRESSED:
        return "content_addressed";
    case METAVERSE_SETTLEMENT_PROOF_OF_WORK:
        return "proof_of_work";
    case METAVERSE_SETTLEMENT_LOCAL_DECLARATION:
        return "local_declaration";
    case METAVERSE_SETTLEMENT_CHAIN_ANCHORED_INCOMPLETE:
        return "chain_anchored_incomplete";
    case METAVERSE_SETTLEMENT_UNKNOWN:
    case METAVERSE_SETTLEMENT_COUNT:
        break;
    }
    return "unknown";
}

const char *metaverse_settlement_means(enum metaverse_settlement settlement)
{
    switch (settlement) {
    case METAVERSE_SETTLEMENT_CONTENT_ADDRESSED:
        return "the identifier is a hash of the bytes: anyone holding them "
               "can verify it with no authority, chain, or peer involved";
    case METAVERSE_SETTLEMENT_PROOF_OF_WORK:
        return "ownership is an ordering settled by accumulated proof of "
               "work; the depth and chainwork below say how much";
    case METAVERSE_SETTLEMENT_LOCAL_DECLARATION:
        return "this node asserts it; nothing outside this node has agreed "
               "or disagreed, and no external record settles it";
    case METAVERSE_SETTLEMENT_CHAIN_ANCHORED_INCOMPLETE:
        return "the record refers to an on-chain object, but this node "
               "tracks no anchor height for it, so the work behind it "
               "cannot be measured here";
    case METAVERSE_SETTLEMENT_UNKNOWN:
    case METAVERSE_SETTLEMENT_COUNT:
        break;
    }
    return "no settlement class is declared for this kind, so nothing here "
           "states how the claim is settled";
}

bool metaverse_settlement_work_measurable(enum metaverse_settlement s)
{
    return s == METAVERSE_SETTLEMENT_PROOF_OF_WORK;
}

enum metaverse_kind metaverse_kind_from_name(const char *name)
{
    if (!name || !*name)
        return METAVERSE_KIND_UNKNOWN;
#define METAVERSE_KIND_FROM_CASE(id_, name_, authority_, settle_, wire_)     \
    if (strcmp(name, name_) == 0) return METAVERSE_KIND_##id_;
    METAVERSE_KIND_TABLE(METAVERSE_KIND_FROM_CASE)
#undef METAVERSE_KIND_FROM_CASE
    return METAVERSE_KIND_UNKNOWN;
}

/* Broker wire value <-> kind, from the table's fifth column. Exhaustive
 * switches with no default, for the same reason metaverse_kind_settlement's
 * is: a kind added anywhere but the table is a -Wswitch error here rather
 * than a silent "any kind" on the agent socket. */
uint32_t metaverse_kind_wire(enum metaverse_kind kind)
{
    switch (kind) {
#define METAVERSE_KIND_WIRE_CASE(id_, name_, authority_, settle_, wire_)     \
    case METAVERSE_KIND_##id_: return (wire_);
    METAVERSE_KIND_TABLE(METAVERSE_KIND_WIRE_CASE)
#undef METAVERSE_KIND_WIRE_CASE
    case METAVERSE_KIND_UNKNOWN:
    case METAVERSE_KIND_COUNT:
        break;
    }
    return 0u;
}

enum metaverse_kind metaverse_kind_from_wire(uint32_t wire)
{
    if (wire == 0u)
        return METAVERSE_KIND_UNKNOWN;
#define METAVERSE_KIND_FROM_WIRE_CASE(id_, name_, authority_, settle_, wire_) \
    if (wire == (wire_)) return METAVERSE_KIND_##id_;
    METAVERSE_KIND_TABLE(METAVERSE_KIND_FROM_WIRE_CASE)
#undef METAVERSE_KIND_FROM_WIRE_CASE
    return METAVERSE_KIND_UNKNOWN;
}

bool metaverse_kind_valid(enum metaverse_kind kind)
{
    return kind > METAVERSE_KIND_UNKNOWN && kind < METAVERSE_KIND_COUNT;
}

static bool root_is_zero(const uint8_t root[METAVERSE_ROOT_BYTES])
{
    uint8_t acc = 0;

    for (size_t i = 0; i < METAVERSE_ROOT_BYTES; i++)
        acc |= root[i];
    return acc == 0;
}

bool metaverse_property_id_make(enum metaverse_kind kind,
                                const uint8_t root[METAVERSE_ROOT_BYTES],
                                struct metaverse_property_id *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!metaverse_kind_valid(kind) || !root || root_is_zero(root))
        return false;
    out->kind = kind;
    memcpy(out->root, root, METAVERSE_ROOT_BYTES);
    return true;
}

bool metaverse_property_id_valid(const struct metaverse_property_id *id)
{
    return id && metaverse_kind_valid(id->kind) && !root_is_zero(id->root);
}

bool metaverse_property_id_format(const struct metaverse_property_id *id,
                                  char *out, size_t cap)
{
    const char *kname;
    size_t klen;
    size_t need;

    if (!out || cap == 0)
        return false;
    out[0] = '\0';
    if (!metaverse_property_id_valid(id))
        return false;

    kname = metaverse_kind_name(id->kind);
    klen = strlen(kname);
    need = klen + 1u + 2u * METAVERSE_ROOT_BYTES + 1u;
    if (cap < need)
        return false;

    memcpy(out, kname, klen);
    out[klen] = ':';
    zcl_hex_encode(id->root, METAVERSE_ROOT_BYTES, out + klen + 1u);
    out[need - 1u] = '\0';
    return true;
}

bool metaverse_property_id_parse(const char *text,
                                 struct metaverse_property_id *out)
{
    const char *colon;
    char kind_name[METAVERSE_ID_TEXT_MAX];
    size_t klen;
    enum metaverse_kind kind;
    uint8_t root[METAVERSE_ROOT_BYTES];

    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!text)
        return false;

    colon = strchr(text, ':');
    if (!colon || colon == text)
        return false;
    klen = (size_t)(colon - text);
    if (klen >= sizeof(kind_name))
        return false;
    memcpy(kind_name, text, klen);
    kind_name[klen] = '\0';
    kind = metaverse_kind_from_name(kind_name);
    if (!metaverse_kind_valid(kind))
        return false;

    /* Exact-length decode: a second ':' or a trailing byte is a different
     * string and must not silently parse. */
    if (!zcl_hex_decode(colon + 1, root, METAVERSE_ROOT_BYTES))
        return false;
    return metaverse_property_id_make(kind, root, out);
}

bool metaverse_property_id_equal(const struct metaverse_property_id *a,
                                 const struct metaverse_property_id *b)
{
    if (!a || !b)
        return false;
    return a->kind == b->kind &&
           memcmp(a->root, b->root, METAVERSE_ROOT_BYTES) == 0;
}
