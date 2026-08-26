/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * node_reproduce — "did I get the same bytes as the publisher, produced by
 * MY OWN machine?" for the node's own shipped artifacts.
 *
 * THE CLAIM THIS LAYER EXISTS TO KEEP HONEST. There are two very different
 * sentences, and only one of them is worth anything:
 *
 *   (a) "the hash beside this download equals the hash of this download"
 *   (b) "the bytes I built here equal the bytes I was given"
 *
 * (a) proves nothing at all — the publisher wrote both halves. This
 * comparator structurally cannot express (a): a receipt carries a
 * PRODUCER class, and the compare REFUSES with NOT_LOCAL unless one side
 * is VCS_NODE_PRODUCER_RECEIVED (the artifact the user was handed) and
 * the other is VCS_NODE_PRODUCER_LOCAL_REBUILD (bytes this machine
 * produced). Two received receipts, two rebuild receipts, or a missing
 * producer all fail closed. That refusal is the whole point of the file.
 *
 * WHY THE VERDICT IS NOT A BOOLEAN. A bare "differs" is worthless to a
 * user: they cannot tell a benign toolchain gap from a publisher shipping
 * something other than the source it names. So the verdict names WHICH of
 * the three it is, in the only order the evidence supports:
 *
 *   SOURCE_DIFFERS     — the source tree we rebuilt is not the source tree
 *                        the artifact was built from. Nothing has been said
 *                        about the publisher; we simply did not run the
 *                        same experiment. Never a publisher fault.
 *   TOOLCHAIN_DIFFERS  — same source, different bytes, and the two sides
 *                        record DIFFERENT toolchain identities. "Your
 *                        compiler differs from the publisher's."
 *   CLAIM_FALSE        — same source AND the same recorded toolchain, and
 *                        the bytes still differ. Every declared input
 *                        agrees and the output does not: the publisher's
 *                        claim does not hold on this machine.
 *   UNDIAGNOSED        — same source, bytes differ, and at least one side
 *                        recorded NO toolchain identity. We cannot tell
 *                        the previous two apart, and say so rather than
 *                        guessing. A guess here would either libel a
 *                        publisher or excuse a real compromise.
 *
 * PARTIAL IS NOT SUCCESS. A receipt may carry `unverified` components —
 * things this machine could not reproduce (a vendored prebuilt archive, a
 * per-translation-unit LTO intermediate, a parameter blob). They are
 * NEVER dropped from the report and never counted as matching. When every
 * compared artifact matched but at least one component is unverified the
 * verdict is PARTIAL, a distinct value from MATCH, so a caller cannot read
 * a full pass out of a partial check. Silently excluding the component you
 * cannot check is exactly how a green result comes to mean nothing.
 *
 * Pure evaluation: nothing in this file opens a file, spawns a process,
 * hashes anything, or reaches the network. The receipt DECODER is a plain
 * bounded text parser over a caller-supplied buffer. Producing a rebuild
 * receipt is the caller's job (tools/scripts/node_reproduce.sh), exactly
 * as lib/vcs never compiles a package. */

#ifndef ZCL_VCS_NODE_REPRODUCE_H
#define ZCL_VCS_NODE_REPRODUCE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Canonical receipt wire schema line (first line of every receipt). */
#define VCS_NODE_REPRO_SCHEMA "zcl.node_repro_receipt.v1"

#define VCS_NODE_REPRO_PATH_MAX 128u
#define VCS_NODE_REPRO_TEXT_MAX 160u
#define VCS_NODE_REPRO_DETAIL_MAX 200u
/* Artifacts one receipt may commit, and unverified components it may name.
 * A receipt that overruns either bound is REJECTED by the decoder — never
 * silently truncated, because a truncated artifact list is precisely the
 * "quietly excluded component" this file exists to forbid. */
#define VCS_NODE_REPRO_MAX_ARTIFACTS 32u
#define VCS_NODE_REPRO_MAX_UNVERIFIED 32u
/* Bound on one receipt text the decoder will read. */
#define VCS_NODE_REPRO_MAX_WIRE_BYTES (64u * 1024u)

/* Who produced the bytes a receipt describes. The compare uses this to
 * refuse a self-referential check; see the file header. The enum order is
 * frozen — it appears in typed JSON. */
enum vcs_node_producer {
    VCS_NODE_PRODUCER_UNKNOWN = 0,
    /* The artifact the user was handed: an installed binary, a download,
     * the running node's own executable image. */
    VCS_NODE_PRODUCER_RECEIVED = 1,
    /* Bytes this machine produced by building from source it holds. */
    VCS_NODE_PRODUCER_LOCAL_REBUILD = 2,
};

const char *vcs_node_producer_string(enum vcs_node_producer producer);

/* One artifact both sides are expected to commit, by relative path. */
struct vcs_node_artifact {
    char path[VCS_NODE_REPRO_PATH_MAX];
    uint8_t sha3[32];
    uint64_t bytes;
};

/* One component the producing side could NOT reproduce, named so it can
 * never be mistaken for a verified one. `reason` is a stable token
 * (e.g. "prebuilt-vendor-archive"); `detail` is printable prose. */
struct vcs_node_unverified {
    char component[VCS_NODE_REPRO_PATH_MAX];
    char reason[VCS_NODE_REPRO_TEXT_MAX];
};

struct vcs_node_receipt {
    uint8_t producer; /* enum vcs_node_producer */
    /* The zcl.dev_source_identity.v2 SHA-256 of the source tree these
     * bytes came from, lowercase 64-hex, or "" when the producing side
     * could not establish it. "" is UNKNOWN and is never treated as a
     * match against another "". */
    char source_id[65];
    /* A digest over this side's build toolchain identity, lowercase
     * 64-hex, or "" when unrecorded. "" is UNKNOWN and never matches. */
    char toolchain_id[65];
    char toolchain_desc[VCS_NODE_REPRO_TEXT_MAX];
    struct vcs_node_artifact artifacts[VCS_NODE_REPRO_MAX_ARTIFACTS];
    size_t artifact_count;
    struct vcs_node_unverified unverified[VCS_NODE_REPRO_MAX_UNVERIFIED];
    size_t unverified_count;
};

/* The composed verdict. MATCH is the only unqualified pass; PARTIAL is a
 * pass over the artifacts that WERE compared with named gaps beside it.
 * The enum order is frozen — it appears in typed JSON. */
enum vcs_node_repro_verdict {
    VCS_NODE_REPRO_UNEVALUATED = 0,
    VCS_NODE_REPRO_MATCH,
    VCS_NODE_REPRO_PARTIAL,
    VCS_NODE_REPRO_SOURCE_DIFFERS,
    VCS_NODE_REPRO_TOOLCHAIN_DIFFERS,
    VCS_NODE_REPRO_CLAIM_FALSE,
    VCS_NODE_REPRO_UNDIAGNOSED,
    VCS_NODE_REPRO_NO_ARTIFACTS,
    VCS_NODE_REPRO_NOT_LOCAL,
    VCS_NODE_REPRO_RECEIPT_INVALID,
};

const char *vcs_node_repro_verdict_string(enum vcs_node_repro_verdict v);

/* Per-artifact rule. The enum order is frozen — it appears in typed JSON. */
enum vcs_node_repro_rule {
    VCS_NODE_ROW_MATCH = 0,
    VCS_NODE_ROW_CONTENT_DIFFERS,
    VCS_NODE_ROW_SIZE_DIFFERS,
    VCS_NODE_ROW_MISSING_FROM_REBUILD,
    VCS_NODE_ROW_MISSING_FROM_RECEIVED,
};

const char *vcs_node_repro_rule_string(enum vcs_node_repro_rule rule);

struct vcs_node_repro_row {
    char path[VCS_NODE_REPRO_PATH_MAX];
    uint8_t rule; /* enum vcs_node_repro_rule */
    char detail[VCS_NODE_REPRO_DETAIL_MAX];
};

struct vcs_node_repro_report {
    uint8_t verdict; /* enum vcs_node_repro_verdict */
    char detail[VCS_NODE_REPRO_DETAIL_MAX];
    /* Coverage, always populated, including on a refusal. `compared` is
     * the size of the union of both artifact path sets — an artifact only
     * one side emitted still counts, as a row naming the gap. */
    uint32_t compared;
    uint32_t matched;
    uint32_t differed;
    uint32_t unverified;  /* union of both sides' unverified components */
    bool source_id_agrees;
    bool source_id_known;      /* both sides recorded one */
    bool toolchain_agrees;
    bool toolchain_known;      /* both sides recorded one */
    struct vcs_node_repro_row rows[VCS_NODE_REPRO_MAX_ARTIFACTS * 2u];
    size_t row_count;
    /* The named gaps, copied so a caller rendering the report cannot omit
     * them by forgetting to look at the receipts. */
    struct vcs_node_unverified gaps[VCS_NODE_REPRO_MAX_UNVERIFIED * 2u];
    size_t gap_count;
};

/* Compare what the user RECEIVED against what this machine REBUILT.
 *
 * `received` must carry producer RECEIVED and `rebuilt` producer
 * LOCAL_REBUILD; any other combination (including two of the same class,
 * which is the self-referential hash check) yields verdict NOT_LOCAL and
 * compares nothing. NULL arguments yield RECEIPT_INVALID.
 *
 * `out` is fully written on every call. Returns true exactly when the
 * verdict is MATCH — PARTIAL deliberately returns false, so a caller that
 * ignores the verdict enum and reads only the boolean still cannot turn a
 * partial check into a pass. */
bool vcs_node_reproduce_compare(const struct vcs_node_receipt *received,
                                const struct vcs_node_receipt *rebuilt,
                                struct vcs_node_repro_report *out);

/* ── the canonical receipt text codec ───────────────────────────────────
 *
 * One directive per line, '#' comments and blank lines ignored:
 *
 *   zcl.node_repro_receipt.v1
 *   producer   received | local-rebuild
 *   source_id  <64hex>
 *   toolchain  <64hex>
 *   toolchain_desc <printable text to end of line>
 *   artifact   <64hex sha3-256> <bytes> <relative path>
 *   unverified <component> <reason text to end of line>
 *
 * Unknown directives are a REJECTION, not a skip: a receipt this build
 * does not fully understand must never be compared as if it were fully
 * understood. */

/* Decode `text` (`len` bytes, need not be NUL-terminated) into `out`.
 * `out` is zeroed first. Returns false on any malformed, over-long, or
 * unrecognised input, writing a printable reason into `why` when given. */
bool vcs_node_receipt_decode(const char *text, size_t len,
                             struct vcs_node_receipt *out, char *why,
                             size_t why_cap);

/* Encode `receipt` into `buf` in the canonical form above. Returns the
 * number of bytes written (excluding the NUL), or 0 if it does not fit. */
size_t vcs_node_receipt_encode(const struct vcs_node_receipt *receipt,
                               char *buf, size_t cap);

#endif /* ZCL_VCS_NODE_REPRODUCE_H */
