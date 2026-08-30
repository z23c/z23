/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_verify_capabilities — the RECEIVER's re-derivation of a package's
 * "capabilities" claim.
 *
 * THE GAP THIS CLOSES. Every zcode-package.json in this registry now carries
 * a "capabilities" array, and tools/lint/check_package_capabilities.sh keeps
 * it exactly equal to the union of classes the shipped sources reach. That
 * gate runs in THIS tree, against THIS tree's config/module_capabilities.def,
 * which was itself derived from an object tree only this tree has. A package
 * that travels to a stranger carries the ARRAY and none of the derivation. A
 * hostile or careless publisher writes "capabilities": [], ships a file that
 * calls connect(), and nothing on the receiving side notices.
 *
 * vcs/package_reproduce.h states the doctrine this file is the missing half
 * of: a release is REPRODUCED when an independent rebuild emits byte-for-byte
 * the same artifacts, and the signer quorum is the latency optimization over
 * that, never its superior. A capability array nobody but the publisher ever
 * derived sits on the same side of that line as a signature. This header
 * moves it back: given the package bytes and a classification table, a
 * receiver derives the reach itself and compares.
 *
 * ── 1. HOW THE TABLE REACHES THE RECEIVER, AND WHY THIS WAY ─────────────
 *
 * The derivation needs symbol -> class knowledge (config/capability_symbols.def
 * in this tree: 544 external entry points, each named with the class it
 * reaches for). Three ways that knowledge could travel were considered:
 *
 *   (a) SHIP IT INSIDE EACH PACKAGE. Rejected as a TRUST anchor. The party
 *       whose claim is being graded would also choose the grading table. A
 *       publisher shipping a table that classifies connect as harmless passes
 *       its own audit, and every byte of the check still verifies.
 *   (b) PIN ONLY ITS DIGEST IN THE MANIFEST. Rejected as a trust anchor for
 *       the same reason, and the manifest is content-addressed by its own
 *       bytes, so the pin only proves the publisher agrees with itself. It
 *       IS kept as a COORDINATION fact: see expected_table_digest below.
 *   (c) ITS OWN REGISTRY PACKAGE that others depend on. Attractive — single
 *       copy, versioned, rides the existing dependency machinery — and it is
 *       where this should eventually go. It is BLOCKED TODAY by this tree's
 *       own gate: a data-only package ships zero C sources, and
 *       check_package_capabilities.sh exits 2 UNPROVEN on exactly that,
 *       refusing to clear a package it cannot see any code in. Recording the
 *       block here rather than working around it.
 *
 * WHAT IS IMPLEMENTED: the table is RECEIVER-HELD and DIGEST-IDENTIFIED. The
 * caller — the receiving node, not the package — names the table file. The
 * package never supplies it and is never consulted about it. This is the only
 * arrangement in which the verdict means anything, because a classifier the
 * subject can choose is not a classifier.
 *
 * A SUBSTITUTED TABLE IS DETECTED TWO WAYS, and they are independent:
 *
 *   1. THE DIGEST PIN (optional, exact). The operator supplies the SHA3-256
 *      the table is expected to hash to — from its own build, from a manifest
 *      pin it wants to hold the publisher to, from anywhere out of band. Any
 *      other bytes yield UNPROVEN / TABLE_DIGEST_MISMATCH. The report always
 *      carries the digest of the table actually used, so a verdict can never
 *      be quoted without the table that produced it.
 *   2. THE ANCHOR FLOOR (always on, no pin required). A short list of
 *      symbols whose class is not negotiable — connect, socket, bind, listen,
 *      send, recv are NETWORK; execve and fork are PROCESS; dlopen is
 *      DYNLOAD; setuid is PRIVILEGE — is compiled into the RECEIVER. A table
 *      that omits one of them, or classifies one differently, is UNSOUND:
 *      UNPROVEN / TABLE_UNSOUND, naming the anchor. This is the detector that
 *      survives an operator who was handed a table by the publisher anyway,
 *      because declassifying connect is the whole point of substituting the
 *      table, and it is the first thing this refuses.
 *
 *      The floor is a FLOOR. A table that keeps all ten anchors honest and
 *      quietly declassifies a rarer entry point passes it. Only the digest
 *      pin closes that, which is why both exist.
 *
 * ── 2. THE THREE VERDICTS ───────────────────────────────────────────────
 *
 *   VERIFIED — the derived set EQUALS the claim. Nothing weaker earns it.
 *   REFUSED  — the derived reach EXCEEDS the claim. This is the attack: code
 *              that reaches a class its manifest does not name. The report
 *              names the class, the shipped file, the symbol and the line.
 *   UNPROVEN — the derivation did not complete, or completed and could not
 *              confirm the claim exactly. Never, under any input, reported as
 *              VERIFIED. This tree already has the SKIP != UNOBSERVED rule and
 *              it is the same rule.
 *
 * A claim that is a STRICT SUPERSET of the derived set is UNPROVEN
 * (CLAIM_NOT_REACHED), not VERIFIED and not REFUSED. The receiver is safe
 * either way — it will confine to the larger claim — but the source scan
 * under-approximates (section 3), so it genuinely cannot tell an over-
 * declaring publisher from its own blind spot, and calling that VERIFIED is
 * exactly the conflation this file exists to prevent. The confinement fact a
 * node can act on regardless is reported separately as no_excess_reach.
 *
 * ── 3. WHAT A SOURCE-LEVEL SCAN CANNOT SEE ──────────────────────────────
 *
 * The reach is derived from the package's OWN SHIPPED SOURCE TEXT, never from
 * compiled objects, because a receiver may not be able to build: it may lack
 * the toolchain, the dependencies, or any wish to execute a stranger's recipe
 * before deciding whether to trust it. That choice costs precision, and the
 * cost is stated here rather than discovered later. Against the nm-based gate
 * in tools/lint/check_capability_closure.sh, this scan is BLIND to:
 *
 *   - A CALL THROUGH A FUNCTION POINTER. `int (*f)(int, const struct
 *     sockaddr *, socklen_t) = resolve("conn" "ect"); f(...)` reaches the
 *     network with the token `connect` appearing nowhere. nm sees the
 *     relocation; source text does not.
 *   - A MACRO-CONSTRUCTED NAME. Token pasting (`co ## nnect`) forms the
 *     identifier during translation phase 4. There is no such token in the
 *     file for this scanner to find. (A plain `#define DIAL connect` IS
 *     caught, because the replacement list still spells the symbol.)
 *   - A NAME FORMED AT PREPROCESSING TIME by any other route — a symbol that
 *     only exists after macro expansion, or that arrives through an included
 *     header the package does not ship. This scanner runs no preprocessor and
 *     resolves no include.
 *   - CODE THAT ARRIVES LATER. Anything a DYNLOAD reach brings in was never
 *     scanned by anything, which is the classes file's own sharpest point.
 *   - A HAND-ROLLED SYSCALL or inline asm trap: no symbol at any level.
 *   - TRANSITIVE REACH THROUGH A DEPENDENCY. This grades ONE package's own
 *     shipped bytes. A package that reaches the network by calling a
 *     dependency that opens the socket is honest here; the dependency's own
 *     claim is where that shows up, and a receiver walks the lock graph.
 *
 * It is also DELIBERATELY OVER-APPROXIMATE in two directions, both of which
 * fail closed (they can turn a VERIFIED into a REFUSED or an UNPROVEN, never
 * the reverse):
 *
 *   - A classified identifier is counted whether or not it is call-shaped,
 *     because `environ` and `in6addr_any` are genuine reach with no call
 *     parentheses. A local variable named `socket` therefore reads as NETWORK
 *     reach. The finding names the file and line so a human sees that in one
 *     look, and the report records whether the match was call-shaped.
 *   - No preprocessor runs, so an inactive `#if` arm is scanned like live
 *     code. Reach that the build would never emit still counts.
 *
 * Comments, string literals and character literals are excluded, and an
 * identifier preceded by `.` or `->` is excluded as a member access.
 *
 * ONE REWRITE IS RECOVERED RATHER THAN CONCEDED. The table is keyed on the
 * string nm reports, and nm reports __fprintf_chk where the source says
 * fprintf, __isoc23_sscanf where it says sscanf, __open_2 where it says open.
 * Each identifier is therefore looked up under its own name AND under
 * __NAME_chk, __isoc23_NAME and __NAME_2, and the reach is the union: the
 * receiver cannot know which spelling this text will compile to, so it
 * assumes any of them. That is recall for one known, mechanical family, not
 * a general answer to macro-formed names.
 *
 * ── 4. WHAT THIS SAYS ABOUT THIS TREE TODAY ─────────────────────────────
 *
 * Run over the ten registry packages against config/capability_symbols.def,
 * five VERIFY, three are REFUSED and two are UNPROVEN. None of the three
 * refusals is a scanner artifact in the sense of "wrong"; each is a place
 * where the in-tree gate and a receiver honestly disagree, and the gate's
 * own header already names the mechanism:
 *
 *   - zclassic23/sha3 and zclassic23/commons-demo ship files (their test
 *     sources, and the demo application entry point) that no compiled
 *     object under the dev object tree covers, so
 *     check_package_capabilities.sh derives their contribution as UNOBSERVED
 *     and clears an empty claim. Their text calls fprintf and fputs. The
 *     receiver, which has only the text, refuses.
 *   - zclassic23/encoding reaches FS_WRITE only inside an
 *     `#if defined(__aarch64__) && defined(__ARM_NEON)` arm. The object tree
 *     that produced the module table was x86, so the gate is grading ONE
 *     build of ONE architecture. The receiver has no architecture, so it
 *     counts the arm — which is the right answer for a package that will
 *     also be installed on ARM.
 *
 * The two UNPROVEN packages (zclassic23/json, zclassic23/package) claim
 * FS_WRITE that reaches them through a DEPENDENCY's static inline —
 * base/safe_alloc.h calls fprintf on the allocation-failure path — pulled in
 * by a header they do not ship. nm attributes it to their object; a
 * receiver reading only their own bytes cannot see it, and says so.
 *
 * WHETHER A RECEIVER CAN VERIFY THIS WITHOUT BUILDING: it can bound the
 * reach, and it cannot decide it. The bound is sound in the direction that
 * matters for refusal — every symbol NAMED in the shipped text is found — and
 * unsound in the direction of clearance, because the blind spots above are
 * exactly the constructs a hostile publisher would reach for once this check
 * exists. A VERIFIED here means "the text names nothing outside the claim",
 * not "the code reaches nothing outside the claim". The second sentence needs
 * the object tree, and the object tree needs a build. Nothing in this header
 * pretends otherwise.
 */

#ifndef ZCL_VCS_PACKAGE_VERIFY_CAPABILITIES_H
#define ZCL_VCS_PACKAGE_VERIFY_CAPABILITIES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Longest capability class spelling the report will hold, CAP_ prefix and
 * NUL included. */
#define VCS_PKGCAP_CLASS_MAX 32u
/* Longest external symbol name a table row may carry. */
#define VCS_PKGCAP_SYMBOL_MAX 96u
/* Package-relative shipped path held in a finding. */
#define VCS_PKGCAP_PATH_MAX 256u
#define VCS_PKGCAP_DETAIL_MAX 256u
/* Distinct classes either side of the comparison may hold. */
#define VCS_PKGCAP_MAX_CLASSES 32u
/* Findings the report carries. Findings beyond the cap still count toward
 * the verdict — a truncated finding list never turns a REFUSED into a
 * VERIFIED. */
#define VCS_PKGCAP_MAX_FINDINGS 32u
/* Bounds on what the scan will read. A package larger than this is UNPROVEN,
 * never cleared. */
#define VCS_PKGCAP_MAX_TABLE_BYTES (8u * 1024u * 1024u)
#define VCS_PKGCAP_MAX_SOURCE_BYTES (8u * 1024u * 1024u)
#define VCS_PKGCAP_MAX_MANIFEST_BYTES (1u * 1024u * 1024u)
#define VCS_PKGCAP_MAX_SOURCES 4096u
/* A table with fewer rows than this is treated as hollow. The real table
 * carries 544 rows; anything near zero is a reader that stopped matching the
 * row shape, and grading a claim against a vocabulary that saw nothing is
 * the failure mode every gate in this tree refuses by exiting UNPROVEN. */
#define VCS_PKGCAP_MIN_TABLE_ROWS 64u

/* The verdict. UNPROVEN is deliberately zero: a zeroed report is UNPROVEN,
 * so no forgotten initialization can read as a clearance. */
enum vcs_pkgcap_verdict {
    VCS_PKGCAP_UNPROVEN = 0,
    VCS_PKGCAP_REFUSED = 1,
    VCS_PKGCAP_VERIFIED = 2,
};

/* Why. The enum order is frozen; it appears in typed output. */
enum vcs_pkgcap_rule {
    /* VERIFIED */
    VCS_PKGCAP_RULE_MATCH = 0,
    /* REFUSED */
    VCS_PKGCAP_RULE_REACH_EXCEEDS_CLAIM,
    /* UNPROVEN */
    VCS_PKGCAP_RULE_NULL_ARGUMENT,
    VCS_PKGCAP_RULE_NO_TABLE,
    VCS_PKGCAP_RULE_TABLE_HOLLOW,
    VCS_PKGCAP_RULE_TABLE_UNSOUND,
    VCS_PKGCAP_RULE_TABLE_DIGEST_MISMATCH,
    VCS_PKGCAP_RULE_NO_MANIFEST,
    VCS_PKGCAP_RULE_MANIFEST_UNPARSEABLE,
    VCS_PKGCAP_RULE_CLAIM_ABSENT,
    VCS_PKGCAP_RULE_CLAIM_MALFORMED,
    VCS_PKGCAP_RULE_NO_SHIPPED_SOURCES,
    VCS_PKGCAP_RULE_SOURCE_UNREADABLE,
    VCS_PKGCAP_RULE_LIMIT_EXCEEDED,
    VCS_PKGCAP_RULE_CLAIM_NOT_REACHED,
};

const char *vcs_pkgcap_verdict_string(enum vcs_pkgcap_verdict verdict);
const char *vcs_pkgcap_rule_string(enum vcs_pkgcap_rule rule);

/* One reach the scan found: the class, and exactly where it came from. A
 * REFUSED without this is an accusation without evidence. */
struct vcs_pkgcap_finding {
    char class_name[VCS_PKGCAP_CLASS_MAX];
    char symbol[VCS_PKGCAP_SYMBOL_MAX];
    char file[VCS_PKGCAP_PATH_MAX]; /* package-relative shipped path */
    uint32_t line;                  /* 1-based */
    bool call_shaped;               /* identifier immediately followed by ( */
    bool outside_claim;             /* this class is not in the manifest */
};

struct vcs_pkgcap_class_set {
    char names[VCS_PKGCAP_MAX_CLASSES][VCS_PKGCAP_CLASS_MAX];
    uint32_t count;
    bool truncated;
};

struct vcs_pkgcap_report {
    uint8_t verdict; /* enum vcs_pkgcap_verdict */
    uint8_t rule;    /* enum vcs_pkgcap_rule */
    char detail[VCS_PKGCAP_DETAIL_MAX]; /* NUL-terminated, "" on MATCH */

    /* The table the verdict was produced against. has_table_digest is false
     * only when no table could be read at all. */
    bool has_table_digest;
    uint8_t table_digest[32];
    uint32_t table_rows;           /* classified symbols parsed */
    uint32_t table_rows_classified;/* of those, not CAP_HARMLESS */

    uint32_t sources_listed;   /* shipped C/H paths the manifest named */
    uint32_t sources_scanned;  /* of those, read to the end */

    struct vcs_pkgcap_class_set claimed; /* straight from the manifest */
    struct vcs_pkgcap_class_set derived; /* what the shipped text reaches */

    struct vcs_pkgcap_finding findings[VCS_PKGCAP_MAX_FINDINGS];
    uint32_t finding_count;
    bool findings_truncated;

    /* True only when every listed source was scanned to the end AND no
     * derived class fell outside the claim. This is the confinement fact a
     * node can act on even when the verdict is UNPROVEN for some other
     * reason; it is false whenever the scan did not complete, because an
     * unread file is not a clean file. */
    bool no_excess_reach;
};

struct vcs_pkgcap_options {
    /* The unpacked package root: the directory holding zcode-package.json. */
    const char *package_dir;
    /* The symbol -> class table, in config/capability_symbols.def row form.
     * Supplied by the RECEIVER. Never read from the package. NULL or absent
     * yields UNPROVEN / NO_TABLE. */
    const char *table_path;
    /* Optional out-of-band pin: the SHA3-256 the table must hash to. NULL
     * means unpinned, and the anchor floor is then the only substitution
     * detector. */
    const uint8_t *expected_table_digest;
};

/* Derive the package's reach from its own shipped sources and compare it to
 * its manifest claim. Reads only inside package_dir and the caller-named
 * table; compiles nothing, executes nothing, opens no socket, writes no file.
 * out is fully written on every call, including on every failure path, and is
 * zeroed on entry — so a caller that ignores the return still holds UNPROVEN
 * rather than a stale clearance. Returns true only for VCS_PKGCAP_VERIFIED,
 * which is a convenience for `if (!...)`, never the report. */
bool vcs_package_verify_capabilities(const struct vcs_pkgcap_options *options,
                                     struct vcs_pkgcap_report *out);

#endif /* ZCL_VCS_PACKAGE_VERIFY_CAPABILITIES_H */
