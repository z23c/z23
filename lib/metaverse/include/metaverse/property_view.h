/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * property_view — one honest answer to "what is this property, right now,
 * and how do we know?".
 *
 * THE TWO RULES, both inherited from services/vault_read.h because they
 * came from the same class of bug:
 *
 *   1. NO SECOND OWNERSHIP TRUTH. Every field here is produced by the
 *      authoritative model's own read API. This layer projects; it never
 *      re-derives ownership, never caches it, and holds no database. A view
 *      is built at call time and discarded — if the underlying object
 *      changes or disappears, the next read says so, because there is
 *      nothing to go stale.
 *
 *   2. NO SILENT OMISSIONS. A property an adapter cannot answer for emits
 *      a view with determined = false and a `reason`, never a missing row
 *      and never a plausible-looking zero. `populated` catches an adapter
 *      that returned without writing anything at all.
 *
 * EVIDENCE GRADE IS THE POINT, NOT A DECORATION. `evidence` states HOW
 * this node knows what the view claims, and the grades are ordered by what
 * was actually checked by THIS node:
 *
 *   LOCAL_CONTENT_HASH   this node re-derived the immutable root from bytes
 *                        it holds. Proves byte identity. Proves nothing
 *                        about authorship, title, or the chain.
 *   LOCAL_SIGNATURE      as above, plus a publisher signature over that
 *                        root that this node verified during THIS call.
 *                        Proves authorship of those exact bytes. Still not
 *                        chain-bound: a signature is not a consensus fact.
 *   CHAIN_VALIDATED_LOCAL this node itself validated the block carrying the
 *                        authority record. The only chain-bound grade.
 *   CHAIN_INDEXED_UNVALIDATED a chain record read from an index over blocks
 *                        this node did not itself validate. Believable, not
 *                        verified.
 *   PEER_REPORTED        a peer or service said so and nothing checked it.
 *
 * There is deliberately no grade that means "verified" in the abstract.
 * An adapter must name which of the above it EARNED; UNKNOWN is the honest
 * default and renders as "unknown", never as a pass. Nothing in this file
 * upgrades a grade — an adapter that did not do the work cannot claim it.
 *
 * FRESHNESS: `has_freshness_height` is false for any property whose
 * authority is not chain-anchored. A local content store has no height,
 * and reporting the node's tip height beside a claim the tip does not
 * commit would be exactly the false "we verified this" this project
 * forbids.
 *
 * SETTLEMENT IS A SEPARATE AXIS FROM EVIDENCE, and conflating them is the
 * thing this view now refuses to do. `evidence` says what THIS NODE
 * checked during this call. `settlement` (metaverse/property_id.h) says
 * WHAT KIND OF ANSWER the authority gives at all — a hash anyone can
 * recheck, an ordering settled by accumulated work, or a bare assertion by
 * this node. A view can carry a strong evidence grade over a
 * locally-declared property: we really did read the local record, and the
 * local record is still the only thing in the world that says so. Both
 * fields are emitted, always, so that combination reads as what it is.
 *
 * Inventory and manifest-only reads have deliberately weaker grades than
 * LOCAL_CONTENT_HASH. LOCAL_STORE_READ says only that the authority was
 * readable and had no match. LOCAL_MANIFEST_HASH says the manifest root was
 * re-derived but full chunk possession was not proven. LOCAL_CONTENT_HASH is
 * earned only after every committed coordinate was length- and SHA3-verified
 * during this read.
 *
 * `work` quantifies the second class and ONLY the second class. For every
 * other kind it reports not-applicable with a stated reason, never a zero
 * depth and never a zero chainwork — see metaverse/property_work.h.
 */

#ifndef ZCL_METAVERSE_PROPERTY_VIEW_H
#define ZCL_METAVERSE_PROPERTY_VIEW_H

#include "metaverse/property_action.h"
#include "metaverse/property_id.h"
#include "metaverse/property_work.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;

/* See the header comment: each grade names work THIS node did. */
enum metaverse_evidence {
    METAVERSE_EVIDENCE_UNKNOWN = 0,
    /* The local store was read successfully and contained no matching
     * object.  This is inventory evidence only: no content bytes existed
     * from which a content hash could have been earned. */
    METAVERSE_EVIDENCE_LOCAL_STORE_READ,
    /* A canonical manifest was parsed and its semantic root was re-derived,
     * but not every committed chunk was byte-verified in this call. */
    METAVERSE_EVIDENCE_LOCAL_MANIFEST_HASH,
    METAVERSE_EVIDENCE_LOCAL_CONTENT_HASH,
    METAVERSE_EVIDENCE_LOCAL_SIGNATURE,
    METAVERSE_EVIDENCE_CHAIN_VALIDATED_LOCAL,
    METAVERSE_EVIDENCE_CHAIN_INDEXED_UNVALIDATED,
    METAVERSE_EVIDENCE_PEER_REPORTED,
};

/* Present state of the object behind the id. ABSENT is a determined
 * answer: the authority was asked and holds nothing at that id. */
enum metaverse_property_status {
    METAVERSE_STATUS_UNKNOWN = 0,
    METAVERSE_STATUS_ABSENT,
    METAVERSE_STATUS_INCOMPLETE,
    METAVERSE_STATUS_PRESENT,
};

#define METAVERSE_VIEW_TEXT_MAX 128u
#define METAVERSE_VIEW_REASON_MAX 192u
#define METAVERSE_ROOT_HEX_MAX 65u

struct metaverse_property_view {
    struct metaverse_property_id id;
    char id_text[METAVERSE_ID_TEXT_MAX];
    const char *kind_name;        /* static; never NULL after view_begin */
    const char *authority_source; /* static; the model that owns the truth */

    bool determined;              /* false => `reason` says why not */
    char reason[METAVERSE_VIEW_REASON_MAX];

    /* What KIND of answer this property's authority gives. Derived purely
     * from the kind and set by metaverse_view_begin, so an adapter cannot
     * upgrade or soften it — it is a property of the mechanism, not of
     * this particular read. */
    enum metaverse_settlement settlement;

    enum metaverse_property_status status;
    enum metaverse_evidence evidence;
    /* The exact read primitive that answered, e.g.
     * "vcs_package_manifest_root". Evidence for the evidence claim. */
    const char *evidence_source;

    /* The object's own immutable root — always equal to id.root. Carried
     * explicitly so a renderer never has to know that. */
    uint8_t immutable_root[METAVERSE_ROOT_BYTES];

    bool has_content_root;        /* root over the bytes */
    uint8_t content_root[METAVERSE_ROOT_BYTES];
    bool has_descriptor_root;     /* root over the signed descriptor */
    uint8_t descriptor_root[METAVERSE_ROOT_BYTES];

    /* Optional human-facing name copied from the same authority as the
     * rest of the view (e.g. "alice" for ZNAM or publisher/package for
     * ZCODE). Empty when the authority defines no name. */
    char display_name[METAVERSE_VIEW_TEXT_MAX];

    /* Owner/controller principal as the authority records it, or "" when
     * the authority records NONE. An empty principal is a fact about the
     * model (content proves bytes, never authorship), not a lookup miss —
     * `owner_principal_kind` is "none" in that case, never "".  */
    char owner_principal[METAVERSE_VIEW_TEXT_MAX];
    const char *owner_principal_kind;

    bool has_revision;
    uint64_t revision;

    /* One short sentence naming what the authority does and does not
     * prove about this property. Always set for a determined view. */
    char provenance[METAVERSE_VIEW_TEXT_MAX];

    /* False for every non-chain-anchored authority. See header. */
    bool has_freshness_height;
    int64_t freshness_height;

    /* How much proof of work is under this record. Initialized by
     * metaverse_view_begin to the honest not-applicable/no-anchor state for
     * the kind's settlement class; a PROOF_OF_WORK adapter overwrites it
     * with metaverse_work_measure(). Every other adapter leaves it alone,
     * and leaving it alone is correct. */
    struct metaverse_work_proof work;

    /* Actions the CURRENT STATE supports. Availability, not authority —
     * intersect with a grant before acting.
     *
     * QUERIES never appear here. Reading a property is not gated on the
     * object's state — an absent or incomplete object is still a thing you
     * can ask about, and its honest answer IS the view you are holding. An
     * empty mask therefore means "nothing may be done to this", not "nothing
     * may be known about it". */
    uint32_t actions;

    /* Bounded size/completeness facts, zero when not applicable. */
    uint64_t total_bytes;
    uint32_t file_count;
    uint32_t chunk_total;
    uint32_t chunks_present;
    bool manifest_root_verified;
    uint32_t chunks_verified;
    uint64_t bytes_verified;
    bool verification_complete;
    char verification_gap[METAVERSE_VIEW_REASON_MAX];

    bool populated;               /* an adapter wrote this view */
};

const char *metaverse_evidence_name(enum metaverse_evidence evidence);
const char *metaverse_property_status_name(enum metaverse_property_status s);

/* Zero the view and set the id-derived static fields (id_text, kind_name,
 * authority_source, immutable_root). False on a NULL out or an invalid id;
 * `out` is still zeroed so a caller that ignores the return cannot read a
 * half-built view. */
bool metaverse_view_begin(struct metaverse_property_view *out,
                          const struct metaverse_property_id *id);

/* Mark the view answered by `evidence_source` at `evidence`. Refuses
 * (returns false, leaves the view undetermined) an UNKNOWN grade or a NULL
 * source: a determined view must always name what it checked. */
bool metaverse_view_determined(struct metaverse_property_view *view,
                              enum metaverse_evidence evidence,
                              const char *evidence_source);

/* Mark the view an honest gap. Status becomes UNKNOWN, evidence UNKNOWN,
 * actions empty, and `reason` says why a reader must not treat the empty
 * fields as facts. */
void metaverse_view_undetermined(struct metaverse_property_view *view,
                                 const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Render one view as a JSON object into `out` (set to an object by this
 * call). Every field is emitted, including the explicit unknowns — a
 * consumer must never have to infer a missing key's meaning. */
bool metaverse_view_to_json(const struct metaverse_property_view *view,
                            struct json_value *out);

#endif /* ZCL_METAVERSE_PROPERTY_VIEW_H */
