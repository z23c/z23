/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * property_action — THE canonical operation vocabulary of the metaverse.
 * One declaration, everything else derived. Pure rules: no I/O, no
 * allocation.
 *
 * ── QUERIES ARE NOT ACTIONS ──────────────────────────────────────────────
 * Two disjoint closed vocabularies live here, and the split is the point.
 *
 *   QUERIES read. They never mutate, never carry value, never name a
 *   counterparty, never run PLAN -> COMMIT, and never mint a receipt.
 *   There are exactly two: ENUMERATE_PROPERTIES ("what does this node
 *   hold") and INSPECT_PROPERTY ("what is this one thing").
 *
 *   ACTIONS mutate. All twelve of them change state this node or the world
 *   outside it can observe, so all twelve run PLAN -> COMMIT and mint a
 *   receipt. There is no "harmless" action; that is what makes the class
 *   meaningful.
 *
 * The word `list` used to mean both "enumerate the catalog" (a read) and
 * "list this for sale" (a market mutation), on the two sides of the same
 * socket. That single identifier is now impossible: the read is
 * ENUMERATE_PROPERTIES and the mutation is LIST_FOR_SALE.
 *
 * ── ONE ROW, THIRTEEN COLUMNS, NOTHING RESTATED ──────────────────────────
 * METAVERSE_ACTION_TABLE carries every fact any consumer needs about an
 * action: its stable bit, its canonical name, its broker wire value, and
 * nine yes/no facts about what performing it does. Enums, masks, the name
 * parser and formatter, the broker-wire mappings in both directions, every
 * predicate, and the compile-time uniqueness proofs are all generated from
 * it. No handwritten switch anywhere in the tree may restate any of these
 * facts — if you find yourself writing `case METAVERSE_ACTION_BUY:` to
 * answer one of these thirteen questions, the answer belongs in a column.
 *
 * ── WIRE VALUES ARE PRESERVED, NEVER REISSUED ────────────────────────────
 * The bit column is a WIRE CONTRACT: grants and receipts persist it. Rows
 * are appended, never renumbered or removed. Bit 0x1 was INSPECT before
 * queries were split out; it is RESERVED forever, decoded for
 * compatibility, and never reissued to a new action.
 *
 * The broker wire column is the agent-broker protocol's verb value. Every
 * value that ever shipped keeps its number and its meaning. LIST_FOR_SALE
 * never had one, so it takes the next free value (14) and the protocol
 * version becomes METAVERSE_WIRE_VERSION; version 1 frames still decode
 * through metaverse_operation_from_wire(), which simply refuses 14.
 *
 * AVAILABILITY IS NOT AUTHORITY. A property view's action set answers only
 * "does the object's present state make this action meaningful". Whether a
 * principal MAY do it is the grant engine's question
 * (metaverse/property_grant.h), asked separately and always ANDed with
 * this. Neither side is sufficient alone.
 */

#ifndef ZCL_METAVERSE_PROPERTY_ACTION_H
#define ZCL_METAVERSE_PROPERTY_ACTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* There is exactly ONE operation vocabulary in this tree, and it is this
 * file. The token exists so a test can PROVE that rather than trust it:
 * metaverse/property_action.h and metaverse/property_grant.h used to declare
 * the same thirteen identifiers with different values, and including both in
 * one translation unit was a hard redefinition error. A guard that includes
 * both and compiles is the only honest evidence the duplication is gone, so
 * arm it on this token. Its value is 1 for as long as that stays true; it is
 * never to be defined to 0 or removed to make something else compile. */
#define METAVERSE_VOCABULARY_UNIFIED 1

/* ── The query vocabulary ────────────────────────────────────────────────
 *
 * Columns: enum suffix, canonical name, broker wire value, may the request
 * carry an all-zero (absent) property id.
 *
 * ENUMERATE_PROPERTIES names no single property, so it is the one operation
 * in either vocabulary that legitimately arrives with a zero id. */
#define METAVERSE_QUERY_TABLE(X)                                             \
    X(INSPECT_PROPERTY,     "inspect_property",     1u, 0)                   \
    X(ENUMERATE_PROPERTIES, "enumerate_properties", 2u, 1)

/* The value IS the bit, exactly as for actions, so a query set is a plain
 * OR of enumerators and no position table can drift out of step with it. */
enum metaverse_query {
    METAVERSE_QUERY_NONE = 0,
    METAVERSE_QUERY_INSPECT_PROPERTY = 0x00000001u,
    METAVERSE_QUERY_ENUMERATE_PROPERTIES = 0x00000002u,
};

enum { METAVERSE_QUERY_COUNT = 2 };

#define METAVERSE_QUERY_ALL                                                  \
    (METAVERSE_QUERY_INSPECT_PROPERTY | METAVERSE_QUERY_ENUMERATE_PROPERTIES)

/* A set of queries, in the same shape as metaverse_action_set. */
typedef uint32_t metaverse_query_set;

/* ── The action vocabulary ───────────────────────────────────────────────
 *
 * Columns, in order:
 *
 *    1  id_        enum suffix (METAVERSE_ACTION_<id_>)
 *    2  bit_       stable action bit — PERSISTED, never renumbered
 *    3  name_      canonical name — the wire/CLI/JSON spelling
 *    4  wire_      broker wire value (enum mvap_verb)
 *    5  local_     changes state THIS node stores
 *    6  external_  changes state outside this node
 *    7  title_     changes who owns the property
 *    8  value_     the request may carry a non-zero ZCL amount
 *    9  budget_    that amount debits the grant's CUMULATIVE budget
 *   10  cparty_    the request names a counterparty principal
 *   11  zeroid_    the request may carry an all-zero (absent) property id
 *   12  plan_      must run PLAN -> COMMIT
 *   13  receipt_   must mint a receipt
 *
 * Columns 8 and 9 are separate on purpose. LIST_FOR_SALE names an asking
 * PRICE — a number the request legitimately carries — while moving nothing,
 * so charging it against the operator's cumulative exposure would bill them
 * for an advertisement. Every other value-carrying action moves the money
 * it names and is charged for it.
 *
 * TRANSFER carries value and IS charged. A title move for consideration is
 * exactly the thing a cumulative budget exists to bound; treating it as
 * free would let a grant move unlimited value in transfers while its
 * budget number sat untouched.
 *
 * SELL and LIST_FOR_SALE are different operations. SELL moves title for
 * value; LIST_FOR_SALE only advertises. Conflating them makes an
 * advertisement indistinguishable from a sale in the receipt chain. */
#define METAVERSE_ACTION_TABLE(X)                                            \
    /*  id_               bit_          name_               wire_ lo ex ti va bu cp z0 pl rc */ \
    X(HOST,             0x00000002u, "host",              3u,  1, 0, 0, 0, 0, 0, 0, 1, 1) \
    X(PUBLISH_REVISION, 0x00000004u, "publish_revision",  4u,  1, 1, 0, 0, 0, 0, 0, 1, 1) \
    X(UPDATE_POINTER,   0x00000008u, "update_pointer",    5u,  1, 1, 0, 0, 0, 0, 0, 1, 1) \
    X(LIST_FOR_SALE,    0x00000010u, "list_for_sale",    14u,  1, 1, 0, 1, 0, 0, 0, 1, 1) \
    X(BUY,              0x00000020u, "buy",               7u,  1, 1, 1, 1, 1, 1, 0, 1, 1) \
    X(SELL,             0x00000040u, "sell",              6u,  1, 1, 1, 1, 1, 1, 0, 1, 1) \
    X(DELIVER,          0x00000080u, "deliver",           8u,  0, 1, 0, 0, 0, 1, 0, 1, 1) \
    X(LEASE,            0x00000100u, "lease",             9u,  1, 1, 0, 1, 1, 1, 0, 1, 1) \
    X(TRANSFER,         0x00000200u, "transfer",         10u,  1, 1, 1, 1, 1, 1, 0, 1, 1) \
    X(ACCEPT_PAYMENT,   0x00000400u, "accept_payment",   11u,  1, 1, 0, 1, 1, 1, 0, 1, 1) \
    X(DELEGATE,         0x00000800u, "delegate",         12u,  1, 0, 0, 0, 0, 1, 0, 1, 1) \
    X(REVOKE,           0x00001000u, "revoke",           13u,  1, 0, 0, 0, 0, 0, 1, 1, 1)

/* Bit 0x1 was INSPECT while inspection was still an action. It is reserved
 * forever: decoded so an old grant or receipt still renders, never a member
 * of METAVERSE_ACTION_ALL, never granted, never reissued. The inspection
 * OPERATION lives on as METAVERSE_QUERY_INSPECT_PROPERTY. */
#define METAVERSE_ACTION_RESERVED_INSPECT 0x00000001u
#define METAVERSE_ACTION_RESERVED (METAVERSE_ACTION_RESERVED_INSPECT)

/* Compatibility spelling for the reserved bit, so a caller holding an old
 * persisted mask can still name what it found. It is NOT an action: passing
 * it where an action is expected is refused, not silently honoured. */
#define METAVERSE_ACTION_INSPECT METAVERSE_ACTION_RESERVED_INSPECT

/* The value IS the bit. There is no second numbering — no positions, no
 * indices, nothing for a persisted mask to be re-mapped against. */
enum metaverse_action {
    METAVERSE_ACTION_NONE = 0,
#define METAVERSE_ACTION_ENUM_ROW(id_, bit_, ...) METAVERSE_ACTION_##id_ = bit_,
    METAVERSE_ACTION_TABLE(METAVERSE_ACTION_ENUM_ROW)
#undef METAVERSE_ACTION_ENUM_ROW
};

/* A set of actions. A grant carries the set it allows; a property view
 * carries the set its CURRENT state supports; the intersection is what may
 * actually be attempted. */
typedef uint32_t metaverse_action_set;

/* Column folds. Defined, used to build the masks and the compile-time
 * proofs below, then undefined — they are scaffolding, not API. */
#define MV_ACT_FOLD_OR(id_, bit_, ...) | (bit_)
#define MV_ACT_FOLD_SUM(id_, bit_, ...) + (bit_)
#define MV_ACT_FOLD_WIRE_OR(id_, bit_, name_, wire_, ...) | (1u << (wire_))
#define MV_ACT_FOLD_WIRE_SUM(id_, bit_, name_, wire_, ...) + (1u << (wire_))
#define MV_ACT_FOLD_NAMELEN(id_, bit_, name_, ...) + sizeof(name_)
#define MV_ACT_FOLD_EXTERNAL(id_, bit_, name_, wire_, lo_, ex_, ...)         \
    | ((ex_) ? (bit_) : 0u)
#define MV_ACT_FOLD_CHANGES(id_, bit_, name_, wire_, lo_, ex_, ...)          \
    | (((lo_) || (ex_)) ? (bit_) : 0u)
#define MV_ACT_FOLD_ROWS(...) +1

#define MV_QRY_FOLD_WIRE_OR(id_, name_, wire_, ...) | (1u << (wire_))
#define MV_QRY_FOLD_WIRE_SUM(id_, name_, wire_, ...) + (1u << (wire_))

enum {
    /* Union of every defined action bit. A mask with any bit outside this
     * is MALFORMED, not "a future action" — a reader that guessed otherwise
     * would silently permit something it cannot name. */
    METAVERSE_ACTION_ALL = (0 METAVERSE_ACTION_TABLE(MV_ACT_FOLD_OR)),

    /* Number of rows in the table. */
    METAVERSE_ACTION_COUNT = (0 METAVERSE_ACTION_TABLE(MV_ACT_FOLD_ROWS)),

    /* The subset that mutates something OUTSIDE this node's own state —
     * column 6, and the same set this mask has always named. Three actions
     * are deliberately absent: HOST, DELEGATE and REVOKE. Hosting is a local
     * decision this node makes about its own storage; delegating and revoking
     * rewrite this node's own grant records. All three change real state —
     * they are in METAVERSE_ACTION_CHANGES_STATE — but none reaches past this
     * node, so ALL & ~MUTATING is HOST|DELEGATE|REVOKE, not HOST alone.
     *
     * Note what this mask is NOT: it is not "the actions that need a
     * receipt". Every action needs one, HOST included, because a change to
     * local state is still a change an operator has to be able to audit.
     * Ask column 13 (metaverse_action_requires_receipt) for that question;
     * conflating the two is how HOST ended up described as harmless. */
    METAVERSE_ACTION_MUTATING = (0 METAVERSE_ACTION_TABLE(MV_ACT_FOLD_EXTERNAL)),

    /* Every action that changes SOMETHING, local or external. Equal to
     * METAVERSE_ACTION_ALL by construction, and the assertion below is what
     * keeps it that way. */
    METAVERSE_ACTION_CHANGES_STATE =
        (0 METAVERSE_ACTION_TABLE(MV_ACT_FOLD_CHANGES)),
};

/* Every action bit is exactly one bit. */
#define MV_ACT_ONEBIT_ASSERT(id_, bit_, name_, ...)                          \
    _Static_assert((bit_) != 0u && ((bit_) & ((bit_) - 1u)) == 0u,           \
                   "action " name_ " must own exactly one bit");
METAVERSE_ACTION_TABLE(MV_ACT_ONEBIT_ASSERT)
#undef MV_ACT_ONEBIT_ASSERT

/* No two actions share a bit. The OR and the SUM of a set of values agree
 * if and only if the values are pairwise disjoint, so this one assertion
 * proves uniqueness across the whole table without an N^2 comparison. */
_Static_assert((0 METAVERSE_ACTION_TABLE(MV_ACT_FOLD_OR)) ==
                   (0 METAVERSE_ACTION_TABLE(MV_ACT_FOLD_SUM)),
               "two actions share a bit: a persisted grant mask would grant "
               "both rights at once and neither could be revoked alone");

/* No two operations share a broker wire value — actions and queries are
 * checked TOGETHER, because they travel in one verb field. */
_Static_assert(((0 METAVERSE_ACTION_TABLE(MV_ACT_FOLD_WIRE_OR))
                  METAVERSE_QUERY_TABLE(MV_QRY_FOLD_WIRE_OR)) ==
                   ((0 METAVERSE_ACTION_TABLE(MV_ACT_FOLD_WIRE_SUM))
                      METAVERSE_QUERY_TABLE(MV_QRY_FOLD_WIRE_SUM)),
               "two operations share a broker wire value: one agent request "
               "would decode to two different operations");

/* The reserved bit never rejoins the action space. */
_Static_assert((METAVERSE_ACTION_ALL & METAVERSE_ACTION_RESERVED) == 0,
               "bit 0x1 is reserved (it was INSPECT); reissuing it would "
               "silently re-grant a right an operator revoked");

/* Every action changes something, and therefore every action runs
 * PLAN -> COMMIT and mints a receipt. Stated as an assertion rather than a
 * comment so that a future row claiming otherwise has to argue with the
 * compiler. This is the line between the two vocabularies. */
_Static_assert(METAVERSE_ACTION_CHANGES_STATE == METAVERSE_ACTION_ALL,
               "an action that changes nothing is a query; move it to "
               "METAVERSE_QUERY_TABLE");

#define MV_ACT_RECEIPT_ASSERT(id_, bit_, name_, wire_, lo_, ex_, ti_, va_,   \
                              bu_, cp_, z0_, pl_, rc_)                       \
    _Static_assert((pl_) && (rc_),                                           \
                   "action " name_ " changes state, so it must run "         \
                   "PLAN -> COMMIT and mint a receipt");                     \
    _Static_assert(!(bu_) || (va_),                                          \
                   "action " name_ " debits the budget, so it must be "      \
                   "allowed to carry a value");
METAVERSE_ACTION_TABLE(MV_ACT_RECEIPT_ASSERT)
#undef MV_ACT_RECEIPT_ASSERT

/* Buffer size that always fits every action name plus separators. */
#define METAVERSE_ACTION_LIST_MAX 192u

_Static_assert((0 METAVERSE_ACTION_TABLE(MV_ACT_FOLD_NAMELEN)) <=
                   METAVERSE_ACTION_LIST_MAX,
               "METAVERSE_ACTION_LIST_MAX no longer fits every action name: "
               "a truncated action list reads as fewer rights");

#undef MV_ACT_FOLD_OR
#undef MV_ACT_FOLD_SUM
#undef MV_ACT_FOLD_WIRE_OR
#undef MV_ACT_FOLD_WIRE_SUM
#undef MV_ACT_FOLD_NAMELEN
#undef MV_ACT_FOLD_EXTERNAL
#undef MV_ACT_FOLD_CHANGES
#undef MV_ACT_FOLD_ROWS
#undef MV_QRY_FOLD_WIRE_OR
#undef MV_QRY_FOLD_WIRE_SUM

/* ── Action predicates ───────────────────────────────────────────────────
 *
 * `metaverse_action_valid` is header-inline because the grant engine, the
 * broker, and every renderer ask it on every request. Everything else is a
 * table lookup in property_action.c. */

static inline bool metaverse_action_valid(enum metaverse_action a)
{
    uint32_t b = (uint32_t)a;
    return b != 0u && (b & (b - 1u)) == 0u &&
           (b & (uint32_t)METAVERSE_ACTION_ALL) != 0u;
}

/* The action's own bit, or 0 when it names no action. Identity for a valid
 * action: the enum value IS the bit. Kept as a function because call sites
 * read better asking for "the bit" than casting. */
static inline metaverse_action_set metaverse_action_bit(enum metaverse_action a)
{
    return metaverse_action_valid(a) ? (metaverse_action_set)a : 0u;
}

/* Canonical name for exactly one action bit. NULL when `bit` is zero, has
 * more than one bit set, or names no defined action — a caller must not
 * render an unnamed bit as an action.
 *
 * The RESERVED bit is the one exception: it renders as "inspect" so an old
 * persisted mask is still legible. metaverse_action_valid() is still false
 * for it, so naming it can never be mistaken for granting it. */
const char *metaverse_action_name(uint32_t bit);

/* Same lookup with the "unknown" fallback a formatter wants. Never NULL. */
const char *metaverse_action_token(enum metaverse_action a);

/* Single action bit for a canonical name, or 0 when unknown/NULL/empty.
 * '-' and '_' are the same separator here, so `publish_revision` from a
 * JSON key and `publish-revision` from a CLI flag name the same right. The
 * reserved name "inspect" resolves to 0: it is not an action. */
uint32_t metaverse_action_from_name(const char *name);

/* Parse a canonical name into an action. False for NULL/""/unknown and for
 * the reserved "inspect". */
bool metaverse_action_parse(const char *name, enum metaverse_action *out);

/* Iterate the table in row order: 0 <= i < METAVERSE_ACTION_COUNT yields
 * the bit, out of range yields 0. Lets a renderer walk the vocabulary
 * without repeating the list. */
uint32_t metaverse_action_at(size_t i);

/* True when every set bit of `mask` is a defined action. An empty mask is
 * well-formed (it means "no action is available"). The reserved bit is NOT
 * valid in a mask that is about to authorize anything. */
bool metaverse_action_mask_valid(uint32_t mask);

/* Comma-separated canonical names of the set bits, in table order, into
 * out. Writes "" for an empty mask. False (with out[0] = 0 when cap > 0) on
 * a NULL/zero-cap out, a malformed mask, or a buffer too small for the
 * whole list — a truncated action list must never be mistaken for a shorter
 * one. */
bool metaverse_action_mask_format(uint32_t mask, char *out, size_t cap);

/* Parse a comma-separated action list ("host,publish_revision") into a set.
 * An empty/NULL list yields the empty set and returns true — a grant with
 * no actions is well-formed and useless, which is the correct default. Any
 * unrecognized element fails the WHOLE parse: a silently-kept typo narrows
 * a grant the operator believed they had written. */
bool metaverse_action_set_parse(const char *csv, metaverse_action_set *out);

/* The nine fact columns, one accessor each. Every one is a table lookup;
 * none is a switch. All are false for an invalid action — an operation
 * nobody can name gets no permissions. */
bool metaverse_action_changes_local_state(enum metaverse_action a);
bool metaverse_action_changes_external_state(enum metaverse_action a);
bool metaverse_action_changes_title(enum metaverse_action a);
bool metaverse_action_accepts_value(enum metaverse_action a);
bool metaverse_action_uses_counterparty(enum metaverse_action a);
bool metaverse_action_allows_zero_property_id(enum metaverse_action a);
bool metaverse_action_requires_plan_commit(enum metaverse_action a);
bool metaverse_action_requires_receipt(enum metaverse_action a);

/* True when the action's value debits the grant's CUMULATIVE budget. This
 * is column 9, not column 8: LIST_FOR_SALE may name a price and still not
 * be charged for it. A non-value action carrying a non-zero value is a
 * malformed request, not a free pass — metaverse_grant_check rejects it
 * (VALUE_ON_FREE_ACTION). */
bool metaverse_action_moves_value(enum metaverse_action a);

/* True when the action is in METAVERSE_ACTION_MUTATING — it changes state
 * OUTSIDE this node (column 6). HOST is false here and still needs a
 * receipt; ask metaverse_action_requires_receipt for that. */
bool metaverse_action_is_mutation(enum metaverse_action a);

/* True when the action changes anything at all, local or external. Every
 * action does; the predicate exists so a caller can ask rather than assume,
 * and so the line between actions and queries is askable at runtime. */
bool metaverse_action_changes_state(enum metaverse_action a);

/* ── Query predicates ────────────────────────────────────────────────────*/

static inline bool metaverse_query_valid(enum metaverse_query q)
{
    uint32_t b = (uint32_t)q;
    return b != 0u && (b & (b - 1u)) == 0u &&
           (b & (uint32_t)METAVERSE_QUERY_ALL) != 0u;
}

static inline metaverse_query_set metaverse_query_bit(enum metaverse_query q)
{
    return metaverse_query_valid(q) ? (metaverse_query_set)q : 0u;
}

const char *metaverse_query_name(enum metaverse_query q);
enum metaverse_query metaverse_query_from_name(const char *name);
uint32_t metaverse_query_at(size_t i);
bool metaverse_query_mask_valid(uint32_t mask);
bool metaverse_query_mask_format(uint32_t mask, char *out, size_t cap);
bool metaverse_query_set_parse(const char *csv, metaverse_query_set *out);
bool metaverse_query_allows_zero_property_id(enum metaverse_query q);

/* ── The broker wire ─────────────────────────────────────────────────────
 *
 * One verb field on the wire carries either vocabulary, so decoding it
 * yields a tagged operation rather than a bare integer. A caller that
 * ignores the tag cannot accidentally run a mutation for a read. */

#define METAVERSE_WIRE_VERSION 2u      /* current protocol version */
#define METAVERSE_WIRE_VERSION_MIN 1u  /* oldest version still decoded */

/* Version 1 shipped verbs 1..13. LIST_FOR_SALE (14) is the only value that
 * version 1 cannot express, which is the whole reason the version moved. */
#define METAVERSE_WIRE_V1_VERB_MAX 13u

enum metaverse_operation_kind {
    METAVERSE_OP_UNKNOWN = 0,
    METAVERSE_OP_QUERY,
    METAVERSE_OP_ACTION,
};

struct metaverse_operation {
    enum metaverse_operation_kind kind;
    enum metaverse_query query;   /* meaningful when kind == QUERY  */
    enum metaverse_action action; /* meaningful when kind == ACTION */
};

/* Decode one broker verb value as seen in a frame of protocol `version`.
 * False (and *out zeroed) for an unknown verb, an unsupported version, or a
 * verb this version cannot express. `version` 0 means "current". */
bool metaverse_operation_from_wire(uint32_t wire, uint32_t version,
                                   struct metaverse_operation *out);

/* Encode an operation as its broker verb value, or 0 when `op` names
 * nothing. 0 is the wire's own "no verb" value, so a caller cannot mistake
 * a refusal for a legal verb. */
uint32_t metaverse_operation_wire(const struct metaverse_operation *op);

/* Name <-> operation, across BOTH vocabularies. */
bool metaverse_operation_from_name(const char *name,
                                   struct metaverse_operation *out);
const char *metaverse_operation_name(const struct metaverse_operation *op);

/* Direct action <-> broker wire, for callers that already know which
 * vocabulary they hold. 0 / METAVERSE_ACTION_NONE on no match. */
uint32_t metaverse_action_wire(enum metaverse_action a);
enum metaverse_action metaverse_action_from_wire(uint32_t wire);
uint32_t metaverse_query_wire(enum metaverse_query q);
enum metaverse_query metaverse_query_from_wire(uint32_t wire);

/* ── Golden compatibility table ──────────────────────────────────────────
 *
 * Every wire value that ever shipped in protocol version 1, the name the
 * version-1 broker gave it, and what it decodes to now. Frozen: a row may
 * be added when a verb is added, never edited. A test walks it to prove no
 * shipped agent's vocabulary changed meaning under it. */
#define METAVERSE_WIRE_V1_TABLE(X)                                           \
    X( 1u, "inspect",          1, "inspect_property")                        \
    X( 2u, "list",             1, "enumerate_properties")                    \
    X( 3u, "host",             0, "host")                                    \
    X( 4u, "publish_revision", 0, "publish_revision")                        \
    X( 5u, "update_pointer",   0, "update_pointer")                          \
    X( 6u, "sell",             0, "sell")                                    \
    X( 7u, "buy",              0, "buy")                                     \
    X( 8u, "deliver",          0, "deliver")                                 \
    X( 9u, "lease",            0, "lease")                                   \
    X(10u, "transfer",         0, "transfer")                                \
    X(11u, "accept_payment",   0, "accept_payment")                          \
    X(12u, "delegate",         0, "delegate")                                \
    X(13u, "revoke",           0, "revoke")

struct metaverse_wire_golden {
    uint32_t wire;              /* the version-1 verb value */
    const char *v1_name;        /* what version 1 called it */
    bool is_query;              /* true = it is a read in the split model */
    const char *canonical_name; /* what it decodes to now */
};

size_t metaverse_wire_golden_count(void);
const struct metaverse_wire_golden *metaverse_wire_golden_at(size_t i);

#endif /* ZCL_METAVERSE_PROPERTY_ACTION_H */
