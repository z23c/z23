/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * property_id — the canonical name of one piece of sovereign digital
 * property. Pure rules: no I/O, no store, no chain, no allocation. Every
 * other metaverse layer (catalog, grants, receipts, broker) speaks this
 * type and nothing coarser.
 *
 * A property_id is (kind, root) where `root` is the underlying object's
 * OWN immutable root as the authoritative model already computes it — a
 * ZCODE package's content.v2 manifest root, a blob's manifest root, a
 * ZNAM registration hash, a ZSLP genesis txid, a market offer's manifest
 * root. This layer mints no identifier of its own, because a second
 * identifier would be a second ownership truth: two names for one object
 * eventually disagree about who owns it.
 *
 * `kind` is not decoration. Two different kinds may legitimately carry
 * the same 32 bytes (a blob published as a one-file ZCODE package shares
 * its manifest root), and they are DIFFERENT properties with different
 * authority sources and different available actions. Equality therefore
 * compares both fields, and the text form always carries both.
 *
 * Text form (the wire/CLI form, stable): "<kind_name>:<64 lowercase hex>",
 * e.g. "zcode_package:9f2c...". Lowercase hex only on output; parsing
 * accepts either case. Round-trips exactly.
 *
 * AUTHORITY SOURCE: each kind names the ONE existing model that owns its
 * ownership truth (third column of the kind table). This layer never
 * becomes that authority; it records which one to ask.
 *
 * SETTLEMENT CLASS (fourth column): the authority source says WHO to ask.
 * It does not say WHAT KIND OF ANSWER comes back, and the three kinds of
 * answer are not comparable guarantees:
 *
 *   CONTENT_ADDRESSED  the object IS its hash. Verification needs no
 *                      authority at all — you hash the bytes and compare.
 *                      Nobody can revoke it, outvote it, or reorg it away.
 *   PROOF_OF_WORK      ownership is an ORDERING question ("who registered
 *                      this name first") and the answer is whichever
 *                      ordering carries the most accumulated work. The
 *                      guarantee is measurable and it is a quantity, not a
 *                      yes/no: see metaverse/property_work.h.
 *   LOCAL_DECLARATION  no external settlement whatsoever. This node says
 *                      so. Nothing outside it has agreed or disagreed, and
 *                      a second node asked the same question may answer
 *                      differently with equal standing.
 *
 * A fourth class exists because one kind honestly does not fit:
 *
 *   CHAIN_ANCHORED_INCOMPLETE  the record refers to an on-chain object, but
 *                      this node cannot measure the work behind it — either
 *                      the row carries no anchor height at all, or the
 *                      anchor is on a chain this node does not validate.
 *                      Filing it under PROOF_OF_WORK would claim a
 *                      measurement that does not exist.
 *
 * Stating the class is what keeps LOCAL_DECLARATION from silently borrowing
 * the credibility of the other two. There is deliberately no ranking, score,
 * or trust tier here: the class names a MECHANISM, and property_work.h
 * reports a MEASUREMENT. Judging them is the reader's job.
 */

#ifndef ZCL_METAVERSE_PROPERTY_ID_H
#define ZCL_METAVERSE_PROPERTY_ID_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* What kind of answer a property's authority gives. Zero is not a class,
 * matching this file's discipline that a zeroed struct is never accidentally
 * valid: a kind whose class was never decided reads as UNKNOWN, not as the
 * strongest one. See the header comment for what each class means. */
enum metaverse_settlement {
    METAVERSE_SETTLEMENT_UNKNOWN = 0,
    METAVERSE_SETTLEMENT_CONTENT_ADDRESSED,
    METAVERSE_SETTLEMENT_PROOF_OF_WORK,
    METAVERSE_SETTLEMENT_LOCAL_DECLARATION,
    METAVERSE_SETTLEMENT_CHAIN_ANCHORED_INCOMPLETE,
    METAVERSE_SETTLEMENT_COUNT
};

/* The property kinds, and for each one the wire name, the existing
 * subsystem that owns its ownership truth, and the SETTLEMENT CLASS of the
 * answer that subsystem gives (the METAVERSE_SETTLEMENT_ suffix). Adding a
 * kind is one row here plus one adapter row
 * (metaverse/property_adapter.h) — the adapter table is static_assert'd
 * against this count, so a kind can never appear in the vocabulary with no
 * reader behind it, and a row with fewer than five columns will not
 * preprocess, so a kind can never appear with no settlement class and no
 * broker wire value either.
 *
 * Why each kind sits where it does:
 *
 *   content / zcode_package  the id IS the manifest root. A reader hashes
 *       the bytes it holds and compares; no registry, chain, or peer is
 *       consulted. The strongest class in the table and the one easiest to
 *       undersell.
 *   znam_name / zslp_asset   both are OP_RETURN records whose meaning is
 *       "who was first". First-ness is an ordering, an ordering is what PoW
 *       settles, and both models record the ZCL height that fixes it
 *       (znam_entry.reg_height, zslp_token.genesis_height), so the work
 *       behind the claim is a real measurable quantity.
 *   hosted_service / endpoint_onion / storefront_product   nothing outside
 *       this process has agreed these exist. A hosted service is the live
 *       diagnostics registry's own list; an onion endpoint is the embedded
 *       Tor service's runtime state; a storefront product is a row this
 *       operator inserted. All three are assertions by this node about
 *       itself, and saying so plainly is what makes the first two classes
 *       credible.
 *   contract_swap            chain-anchored but NOT measurable here. The
 *       row (models/swap_contract.h) carries funding_txid and an absolute
 *       CLTV locktime but no funding HEIGHT, so there is no anchor to
 *       measure depth from; and `chain` may be BTC/LTC/DOGE, whose height
 *       this node explicitly refuses to claim it can observe
 *       (swap_controller.c, swap_locktime_to_absolute). Redeem/refund are
 *       wired, funding-confirmation tracking is not. Hence the honest
 *       fourth class rather than a PROOF_OF_WORK label with permanently
 *       unknown numbers under it.
 *   character_sheet          the id is the hash of the character's own birth
 *       seed plus the rules revision that reads it, and the whole sheet is
 *       RECOMPUTED from that seed (metaverse/character_sheet.h). A node the
 *       owner has never met verifies a visiting character by hashing what it
 *       was handed — no registry to consult and no claim of the owner's to
 *       take on faith. That is the definition of CONTENT_ADDRESSED, and it is
 *       why the authority column names the derivation itself rather than a
 *       store: there is no seed store, and inventing one would mint a second
 *       ownership truth for an object that already names itself.
 *
 * Room to extend is deliberate: world/object kinds land as further rows,
 * never as a parallel enum.
 *
 * Columns, in order: enum suffix, wire name, authority source, settlement
 * class (the METAVERSE_SETTLEMENT_ suffix), and the BROKER WIRE VALUE the
 * agent-broker protocol carries for this kind. The broker column exists so
 * the protocol's kind numbering is declared once, beside the kind it names,
 * instead of being re-derived by a switch on the far side of a socket. It is
 * currently the identity mapping, and the per-row assertion below is what
 * keeps that a checked fact rather than an assumption. */
#define METAVERSE_KIND_TABLE(X)                                              \
    X(CONTENT,            "content",            "vcs.blob_store",            \
      CONTENT_ADDRESSED,         1u)                                         \
    X(ZCODE_PACKAGE,      "zcode_package",      "vcs.package_store",         \
      CONTENT_ADDRESSED,         2u)                                         \
    X(ZNAM_NAME,          "znam_name",          "znam.registry",             \
      PROOF_OF_WORK,             3u)                                         \
    X(ZSLP_ASSET,         "zslp_asset",         "zslp.ledger",               \
      PROOF_OF_WORK,             4u)                                         \
    X(HOSTED_SERVICE,     "hosted_service",     "service.registry",          \
      LOCAL_DECLARATION,         5u)                                         \
    X(ENDPOINT_ONION,     "endpoint_onion",     "net.onion_service",         \
      LOCAL_DECLARATION,         6u)                                         \
    X(STOREFRONT_PRODUCT, "storefront_product", "store.product",             \
      LOCAL_DECLARATION,         7u)                                         \
    X(CONTRACT_SWAP,      "contract_swap",      "swap.contract",             \
      CHAIN_ANCHORED_INCOMPLETE, 8u)                                         \
    X(CHARACTER_SHEET,    "character_sheet",    "metaverse.character_sheet", \
      CONTENT_ADDRESSED,         9u)

enum metaverse_kind {
    /* Zero is not a kind. A zeroed struct is an explicitly invalid id, so
     * a forgotten initialization can never read as CONTENT. */
    METAVERSE_KIND_UNKNOWN = 0,
#define METAVERSE_KIND_ENUM(id_, name_, authority_, settle_, wire_) \
    METAVERSE_KIND_##id_,
    METAVERSE_KIND_TABLE(METAVERSE_KIND_ENUM)
#undef METAVERSE_KIND_ENUM
    METAVERSE_KIND_COUNT
};

/* Every kind's fourth column must name a real class, and its fifth must be
 * the broker value that kind already ships under. Both fire at compile time
 * in every translation unit that includes this header, so a new kind cannot
 * reach a test run classified as UNKNOWN or silently renumbered on the
 * wire. */
#define METAVERSE_KIND_ROW_ASSERT(id_, name_, authority_, settle_, wire_)    \
    _Static_assert(METAVERSE_SETTLEMENT_##settle_ >                          \
                           METAVERSE_SETTLEMENT_UNKNOWN &&                   \
                       METAVERSE_SETTLEMENT_##settle_ <                      \
                           METAVERSE_SETTLEMENT_COUNT,                       \
                   "property kind " name_ " must name a real settlement "    \
                   "class in METAVERSE_KIND_TABLE");                         \
    _Static_assert((wire_) == (unsigned)METAVERSE_KIND_##id_,                \
                   "property kind " name_ " must keep the broker wire value "\
                   "it already ships under; renumbering it would re-map "    \
                   "every deployed agent's kind scope");
METAVERSE_KIND_TABLE(METAVERSE_KIND_ROW_ASSERT)
#undef METAVERSE_KIND_ROW_ASSERT

#define METAVERSE_ROOT_BYTES 32u

/* "storefront_product" (18) + ':' + 64 hex + NUL = 84; 96 leaves room for
 * one more long kind name without a wire change. */
#define METAVERSE_ID_TEXT_MAX 96u

struct metaverse_property_id {
    enum metaverse_kind kind;
    uint8_t root[METAVERSE_ROOT_BYTES];
};

/* Wire name / authority source for a kind. Never NULL; an out-of-range or
 * UNKNOWN kind renders as "unknown". */
const char *metaverse_kind_name(enum metaverse_kind kind);
const char *metaverse_kind_authority(enum metaverse_kind kind);

/* The kind's settlement class, straight out of the table's fourth column.
 * METAVERSE_SETTLEMENT_UNKNOWN only for UNKNOWN / out-of-range. Pure: no
 * I/O, no allocation, no chain access — the same rules as the two above. */
enum metaverse_settlement metaverse_kind_settlement(enum metaverse_kind kind);

/* Wire name of a settlement class ("content_addressed", "proof_of_work",
 * "local_declaration", "chain_anchored_incomplete"). Never NULL; an
 * UNKNOWN or out-of-range class renders as "unknown". */
const char *metaverse_settlement_name(enum metaverse_settlement settlement);

/* One sentence stating plainly what the class does and does not settle, for
 * an operator reading a view. Never NULL. The LOCAL_DECLARATION wording is
 * deliberately blunt: softening it is what would let a locally-asserted
 * product read like a chain-settled one. */
const char *metaverse_settlement_means(enum metaverse_settlement settlement);

/* True only for METAVERSE_SETTLEMENT_PROOF_OF_WORK — the one class whose
 * backing is a QUANTITY this node can measure (anchor height, confirmation
 * depth, accumulated chainwork). For every other class the honest answer to
 * "how much work is behind this" is "that question does not apply", which
 * is not the same as zero. See metaverse/property_work.h. */
bool metaverse_settlement_work_measurable(enum metaverse_settlement s);

/* Exact wire-name lookup. METAVERSE_KIND_UNKNOWN when nothing matches
 * (including NULL, "", and "unknown" itself). */
enum metaverse_kind metaverse_kind_from_name(const char *name);

/* The kind's BROKER WIRE VALUE and back, straight out of the table's fifth
 * column. 0 / METAVERSE_KIND_UNKNOWN for an invalid kind or an unrecognized
 * wire value — 0 is the protocol's own "any kind" sentinel, so a caller
 * cannot mistake a refusal for a real kind. */
uint32_t metaverse_kind_wire(enum metaverse_kind kind);
enum metaverse_kind metaverse_kind_from_wire(uint32_t wire);

/* True for a real kind (not UNKNOWN, not >= COUNT). */
bool metaverse_kind_valid(enum metaverse_kind kind);

/* Build an id. Rejects a NULL out, a NULL root, an invalid kind, and an
 * all-zero root (no authoritative model mints one, so accepting it would
 * make "uninitialized" indistinguishable from "a real object"). *out is
 * zeroed on every rejection. */
bool metaverse_property_id_make(enum metaverse_kind kind,
                                const uint8_t root[METAVERSE_ROOT_BYTES],
                                struct metaverse_property_id *out);

/* Render "<kind_name>:<64 lowercase hex>" into out (cap >=
 * METAVERSE_ID_TEXT_MAX). False (and out[0] = 0 when cap > 0) on a NULL
 * out, a short buffer, or an invalid id. */
bool metaverse_property_id_format(const struct metaverse_property_id *id,
                                  char *out, size_t cap);

/* Parse the text form. Accepts upper or lower hex; requires exactly one
 * ':', a known kind name, exactly 64 hex digits, and no trailing bytes.
 * *out is zeroed on every rejection. */
bool metaverse_property_id_parse(const char *text,
                                 struct metaverse_property_id *out);

/* Both kind and root must match. NULL on either side is never equal. */
bool metaverse_property_id_equal(const struct metaverse_property_id *a,
                                 const struct metaverse_property_id *b);

/* True when the id is well-formed (valid kind, non-zero root). */
bool metaverse_property_id_valid(const struct metaverse_property_id *id);

/* A kind-set is one bit per kind, so a grant can be scoped to kinds without
 * enumerating property ids. Bit 0 (UNKNOWN) is never set by
 * metaverse_kind_bit and a set containing it matches nothing. */
typedef uint32_t metaverse_kind_set;

static inline metaverse_kind_set metaverse_kind_bit(enum metaverse_kind kind)
{
    if (kind <= METAVERSE_KIND_UNKNOWN || kind >= METAVERSE_KIND_COUNT)
        return 0u;
    return (metaverse_kind_set)1u << (unsigned)kind;
}

#endif /* ZCL_METAVERSE_PROPERTY_ID_H */
