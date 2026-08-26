/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_node_reproduce — the comparator and the receipt codec behind
 * `z23 zcode node verify`.
 *
 * The property under test is not "does it print match sometimes". It is:
 *
 *   1. It CANNOT be talked into the worthless check. Two receipts of the
 *      same producer class — the publisher's hash compared with the
 *      publisher's hash — are refused, not compared. Every producer
 *      combination is enumerated here, so a future edit that relaxes the
 *      rule fails a test rather than quietly turning the feature into
 *      theatre.
 *   2. PARTIAL is never a pass. A receipt that names even one component it
 *      could not rebuild yields PARTIAL and a false return, even when every
 *      byte it DID compare matched. This is the single assertion that keeps
 *      "green" meaning something.
 *   3. A mismatch is DIAGNOSED. Source, toolchain and claim are separated in
 *      evidence order, and when the evidence cannot separate them the answer
 *      is UNDIAGNOSED rather than a guess. A guess here would either libel a
 *      publisher or excuse a real compromise.
 *   4. The codec refuses what it does not understand. An unknown directive
 *      is a rejection, and an over-long artifact or unverified list is a
 *      rejection rather than a truncation — a silently truncated list is
 *      exactly the "component quietly excluded from the verdict" this whole
 *      surface exists to prevent.
 *
 * Pure: nothing here builds, spawns, or touches a datadir. */

#include "test/test_core.h"

#include "base/hex.h"
#include "vcs/node_reproduce.h"

#include <stdio.h>
#include <string.h>

#define NR_CHECK(name, expr) do {                                          \
    if (expr) { printf("  node_reproduce: %s... OK\n", (name)); }          \
    else { printf("  node_reproduce: %s... FAIL\n", (name)); failures++; } \
} while (0)

static const char SRC_A[65] =
    "1111111111111111111111111111111111111111111111111111111111111111";
static const char SRC_B[65] =
    "2222222222222222222222222222222222222222222222222222222222222222";
static const char TC_A[65] =
    "aaaa111111111111111111111111111111111111111111111111111111111111";
static const char TC_B[65] =
    "bbbb222222222222222222222222222222222222222222222222222222222222";

static void nr_fill(struct vcs_node_receipt *r, enum vcs_node_producer p,
                    const char *src, const char *tc, uint8_t seed,
                    uint64_t bytes)
{
    memset(r, 0, sizeof(*r));
    r->producer = (uint8_t)p;
    if (src)
        (void)snprintf(r->source_id, sizeof(r->source_id), "%s", src);
    if (tc)
        (void)snprintf(r->toolchain_id, sizeof(r->toolchain_id), "%s", tc);
    r->artifact_count = 1;
    (void)snprintf(r->artifacts[0].path, sizeof(r->artifacts[0].path),
                   "bin/z23");
    memset(r->artifacts[0].sha3, seed, 32);
    r->artifacts[0].bytes = bytes;
}

static void nr_add_gap(struct vcs_node_receipt *r, const char *c,
                       const char *why)
{
    (void)snprintf(r->unverified[r->unverified_count].component,
                   VCS_NODE_REPRO_PATH_MAX, "%s", c);
    (void)snprintf(r->unverified[r->unverified_count].reason,
                   VCS_NODE_REPRO_TEXT_MAX, "%s", why);
    r->unverified_count++;
}

static enum vcs_node_repro_verdict nr_run(
    const struct vcs_node_receipt *a, const struct vcs_node_receipt *b,
    struct vcs_node_repro_report *rep, bool *returned)
{
    bool r = vcs_node_reproduce_compare(a, b, rep);
    if (returned)
        *returned = r;
    return (enum vcs_node_repro_verdict)rep->verdict;
}

/* ── 1. the refusal that makes the whole thing worth running ───────────── */

static int t_refuses_self_referential_compare(void)
{
    int failures = 0;
    struct vcs_node_receipt a, b;
    struct vcs_node_repro_report rep;
    bool ret = true;

    /* Every combination that is NOT (received, local-rebuild). A publisher's
     * hash checked against the publisher's hash is one participant agreeing
     * with themselves; there must be no argument list that reaches a
     * comparison. */
    const enum vcs_node_producer all[] = {
        VCS_NODE_PRODUCER_UNKNOWN, VCS_NODE_PRODUCER_RECEIVED,
        VCS_NODE_PRODUCER_LOCAL_REBUILD
    };
    for (size_t i = 0; i < 3; i++) {
        for (size_t j = 0; j < 3; j++) {
            if (all[i] == VCS_NODE_PRODUCER_RECEIVED &&
                all[j] == VCS_NODE_PRODUCER_LOCAL_REBUILD)
                continue;
            nr_fill(&a, all[i], SRC_A, TC_A, 0x11, 100);
            nr_fill(&b, all[j], SRC_A, TC_A, 0x11, 100);
            char name[128];
            (void)snprintf(name, sizeof(name),
                           "refuses (%s, %s) — identical bytes must not pass",
                           vcs_node_producer_string(all[i]),
                           vcs_node_producer_string(all[j]));
            enum vcs_node_repro_verdict v = nr_run(&a, &b, &rep, &ret);
            NR_CHECK(name, v == VCS_NODE_REPRO_NOT_LOCAL && !ret &&
                               rep.compared == 0 && rep.row_count == 0);
        }
    }

    /* And the ONE accepted orientation really does compare. */
    nr_fill(&a, VCS_NODE_PRODUCER_RECEIVED, SRC_A, TC_A, 0x11, 100);
    nr_fill(&b, VCS_NODE_PRODUCER_LOCAL_REBUILD, SRC_A, TC_A, 0x11, 100);
    NR_CHECK("accepts (received, local-rebuild)",
             nr_run(&a, &b, &rep, &ret) == VCS_NODE_REPRO_MATCH && ret);

    NR_CHECK("NULL receipts are receipt-invalid, never a pass",
             nr_run(NULL, &b, &rep, &ret) == VCS_NODE_REPRO_RECEIPT_INVALID &&
                 !ret &&
                 nr_run(&a, NULL, &rep, &ret) ==
                     VCS_NODE_REPRO_RECEIPT_INVALID &&
                 !ret);
    return failures;
}

/* ── 2. partial is never success ───────────────────────────────────────── */

static int t_partial_is_not_success(void)
{
    int failures = 0;
    struct vcs_node_receipt a, b;
    struct vcs_node_repro_report rep;
    bool ret = true;

    nr_fill(&a, VCS_NODE_PRODUCER_RECEIVED, SRC_A, TC_A, 0x11, 100);
    nr_fill(&b, VCS_NODE_PRODUCER_LOCAL_REBUILD, SRC_A, TC_A, 0x11, 100);
    NR_CHECK("no gaps + identical bytes = match, returns true",
             nr_run(&a, &b, &rep, &ret) == VCS_NODE_REPRO_MATCH && ret &&
                 rep.matched == 1 && rep.differed == 0 &&
                 rep.unverified == 0);

    /* One component the rebuild could not produce. Every compared byte still
     * matches. This must NOT be a pass. */
    nr_add_gap(&b, "vendor/lib/libcrypto.a", "prebuilt archive linked as-is");
    NR_CHECK("one unverified component turns match into partial",
             nr_run(&a, &b, &rep, &ret) == VCS_NODE_REPRO_PARTIAL);
    NR_CHECK("partial returns FALSE — a caller reading only the bool is safe",
             !ret);
    NR_CHECK("partial still reports every byte it did match",
             rep.matched == 1 && rep.differed == 0);
    NR_CHECK("the gap is carried into the report, not left in the receipt",
             rep.unverified == 1 && rep.gap_count == 1 &&
                 strcmp(rep.gaps[0].component, "vendor/lib/libcrypto.a") == 0);
    NR_CHECK("the gap names which side could not rebuild it",
             strstr(rep.gaps[0].reason, "rebuilt:") == rep.gaps[0].reason);

    /* A gap on the RECEIVED side counts too. */
    nr_fill(&b, VCS_NODE_PRODUCER_LOCAL_REBUILD, SRC_A, TC_A, 0x11, 100);
    nr_add_gap(&a, "sapling-params", "not shipped in the artifact");
    NR_CHECK("a gap declared by the received side also blocks a full pass",
             nr_run(&a, &b, &rep, &ret) == VCS_NODE_REPRO_PARTIAL && !ret &&
                 rep.gap_count == 1);
    return failures;
}

/* ── 3. a mismatch is diagnosed, or honestly refused ───────────────────── */

static int t_mismatch_is_diagnosed(void)
{
    int failures = 0;
    struct vcs_node_receipt a, b;
    struct vcs_node_repro_report rep;
    bool ret = true;

    /* Different source: says nothing about the publisher. Checked FIRST, so
     * a wrong checkout can never be reported as a false publisher claim. */
    nr_fill(&a, VCS_NODE_PRODUCER_RECEIVED, SRC_A, TC_A, 0x11, 100);
    nr_fill(&b, VCS_NODE_PRODUCER_LOCAL_REBUILD, SRC_B, TC_B, 0x22, 100);
    NR_CHECK("different source outranks a toolchain difference",
             nr_run(&a, &b, &rep, &ret) == VCS_NODE_REPRO_SOURCE_DIFFERS &&
                 !ret && !rep.source_id_agrees && rep.source_id_known);

    /* Same source, different toolchain: the ordinary, benign explanation. */
    nr_fill(&b, VCS_NODE_PRODUCER_LOCAL_REBUILD, SRC_A, TC_B, 0x22, 100);
    NR_CHECK("same source + different toolchain = toolchain-differs",
             nr_run(&a, &b, &rep, &ret) == VCS_NODE_REPRO_TOOLCHAIN_DIFFERS &&
                 !ret && rep.source_id_agrees && rep.toolchain_known &&
                 !rep.toolchain_agrees);

    /* Same source AND same toolchain, different bytes: every declared input
     * agrees and the output does not. */
    nr_fill(&b, VCS_NODE_PRODUCER_LOCAL_REBUILD, SRC_A, TC_A, 0x22, 100);
    NR_CHECK("same source + same toolchain + different bytes = claim-false",
             nr_run(&a, &b, &rep, &ret) == VCS_NODE_REPRO_CLAIM_FALSE &&
                 !ret && rep.source_id_agrees && rep.toolchain_agrees &&
                 rep.differed == 1);
    NR_CHECK("the differing artifact is named with a rule, not a bare false",
             rep.row_count == 1 &&
                 rep.rows[0].rule == VCS_NODE_ROW_CONTENT_DIFFERS &&
                 strcmp(rep.rows[0].path, "bin/z23") == 0 &&
                 rep.rows[0].detail[0] != '\0');

    /* Missing source identity: refuse to name a culprit. */
    nr_fill(&a, VCS_NODE_PRODUCER_RECEIVED, NULL, TC_A, 0x11, 100);
    nr_fill(&b, VCS_NODE_PRODUCER_LOCAL_REBUILD, SRC_A, TC_A, 0x22, 100);
    NR_CHECK("no source identity on one side = undiagnosed, not a guess",
             nr_run(&a, &b, &rep, &ret) == VCS_NODE_REPRO_UNDIAGNOSED &&
                 !ret && !rep.source_id_known);

    /* Missing toolchain identity: same refusal, one step later. */
    nr_fill(&a, VCS_NODE_PRODUCER_RECEIVED, SRC_A, NULL, 0x11, 100);
    nr_fill(&b, VCS_NODE_PRODUCER_LOCAL_REBUILD, SRC_A, TC_A, 0x22, 100);
    NR_CHECK("no toolchain identity on one side = undiagnosed",
             nr_run(&a, &b, &rep, &ret) == VCS_NODE_REPRO_UNDIAGNOSED &&
                 !ret && rep.source_id_agrees && !rep.toolchain_known);

    /* Two absent identities must not read as agreement. */
    nr_fill(&a, VCS_NODE_PRODUCER_RECEIVED, NULL, NULL, 0x11, 100);
    nr_fill(&b, VCS_NODE_PRODUCER_LOCAL_REBUILD, NULL, NULL, 0x22, 100);
    NR_CHECK("unknown never equals unknown",
             nr_run(&a, &b, &rep, &ret) == VCS_NODE_REPRO_UNDIAGNOSED &&
                 !rep.source_id_agrees && !rep.toolchain_agrees);
    return failures;
}

/* ── 4. per-artifact rules and the empty case ──────────────────────────── */

static int t_rows_and_empty(void)
{
    int failures = 0;
    struct vcs_node_receipt a, b;
    struct vcs_node_repro_report rep;
    bool ret = true;

    nr_fill(&a, VCS_NODE_PRODUCER_RECEIVED, SRC_A, TC_A, 0x11, 100);
    nr_fill(&b, VCS_NODE_PRODUCER_LOCAL_REBUILD, SRC_A, TC_A, 0x11, 250);
    (void)nr_run(&a, &b, &rep, &ret);
    NR_CHECK("a size difference is reported as size-differs with both counts",
             rep.row_count == 1 &&
                 rep.rows[0].rule == VCS_NODE_ROW_SIZE_DIFFERS &&
                 strstr(rep.rows[0].detail, "100") &&
                 strstr(rep.rows[0].detail, "250"));

    /* An artifact only one side emitted is a NAMED row, never a silent drop:
     * dropping it is how a build that stopped emitting something keeps
     * printing green. */
    nr_fill(&a, VCS_NODE_PRODUCER_RECEIVED, SRC_A, TC_A, 0x11, 100);
    nr_fill(&b, VCS_NODE_PRODUCER_LOCAL_REBUILD, SRC_A, TC_A, 0x11, 100);
    b.artifact_count = 0;
    (void)nr_run(&a, &b, &rep, &ret);
    NR_CHECK("an artifact the rebuild did not emit is named",
             rep.compared == 1 && rep.differed == 1 && rep.row_count == 1 &&
                 rep.rows[0].rule == VCS_NODE_ROW_MISSING_FROM_REBUILD);

    nr_fill(&b, VCS_NODE_PRODUCER_LOCAL_REBUILD, SRC_A, TC_A, 0x11, 100);
    a.artifact_count = 0;
    (void)nr_run(&a, &b, &rep, &ret);
    NR_CHECK("an artifact only the rebuild emitted is named too",
             rep.compared == 1 && rep.differed == 1 && rep.row_count == 1 &&
                 rep.rows[0].rule == VCS_NODE_ROW_MISSING_FROM_RECEIVED);

    /* Nothing compared is emphatically not a pass. */
    a.artifact_count = 0;
    b.artifact_count = 0;
    NR_CHECK("zero artifacts is no-artifacts, never match",
             nr_run(&a, &b, &rep, &ret) == VCS_NODE_REPRO_NO_ARTIFACTS &&
                 !ret && rep.compared == 0);
    return failures;
}

/* ── 5. the receipt codec ──────────────────────────────────────────────── */

static int t_codec_roundtrip(void)
{
    int failures = 0;
    struct vcs_node_receipt in, out;
    nr_fill(&in, VCS_NODE_PRODUCER_LOCAL_REBUILD, SRC_A, TC_A, 0x5a, 4242);
    (void)snprintf(in.toolchain_desc, sizeof(in.toolchain_desc),
                   "GCC: (Ubuntu 14.2.0) 14.2.0");
    (void)snprintf(in.artifacts[1].path, VCS_NODE_REPRO_PATH_MAX,
                   "bin/zclassic23-package-verify");
    memset(in.artifacts[1].sha3, 0x7e, 32);
    in.artifacts[1].bytes = 99;
    in.artifact_count = 2;
    nr_add_gap(&in, "vendor/lib/libsecp256k1.a", "committed binary, no source");

    char buf[4096];
    size_t n = vcs_node_receipt_encode(&in, buf, sizeof(buf));
    NR_CHECK("encode produces bytes", n > 0 && n < sizeof(buf));

    char why[256] = "";
    NR_CHECK("decode accepts what encode wrote",
             vcs_node_receipt_decode(buf, n, &out, why, sizeof(why)));
    NR_CHECK("round-trip preserves producer, identities and both lists",
             out.producer == in.producer &&
                 strcmp(out.source_id, in.source_id) == 0 &&
                 strcmp(out.toolchain_id, in.toolchain_id) == 0 &&
                 strcmp(out.toolchain_desc, in.toolchain_desc) == 0 &&
                 out.artifact_count == 2 && out.unverified_count == 1 &&
                 strcmp(out.artifacts[1].path,
                        "bin/zclassic23-package-verify") == 0 &&
                 out.artifacts[1].bytes == 99 &&
                 memcmp(out.artifacts[0].sha3, in.artifacts[0].sha3, 32) == 0 &&
                 strcmp(out.unverified[0].component,
                        "vendor/lib/libsecp256k1.a") == 0);

    /* An encode that does not fit must report 0, never a truncated receipt
     * that decodes into a SHORTER artifact list than the build produced. */
    char tiny[16];
    NR_CHECK("encode refuses rather than truncating",
             vcs_node_receipt_encode(&in, tiny, sizeof(tiny)) == 0);
    return failures;
}

static int t_codec_rejections(void)
{
    int failures = 0;
    struct vcs_node_receipt out;
    char why[256];

#define NR_BAD(name, text) do {                                            \
    why[0] = '\0';                                                         \
    bool ok = vcs_node_receipt_decode((text), strlen(text), &out, why,     \
                                      sizeof(why));                        \
    NR_CHECK(name, !ok && why[0] != '\0');                                 \
} while (0)

    NR_BAD("rejects an empty receipt", "");
    NR_BAD("rejects a missing schema line", "producer received\n");
    NR_BAD("rejects a wrong schema line",
           "zcl.node_repro_receipt.v2\nproducer received\n");
    NR_BAD("rejects a receipt that names no producer",
           VCS_NODE_REPRO_SCHEMA "\nsource_id "
           "1111111111111111111111111111111111111111111111111111111111111111\n");
    NR_BAD("rejects an unknown producer",
           VCS_NODE_REPRO_SCHEMA "\nproducer publisher\n");
    /* THE ONE THAT MATTERS MOST: a directive this build does not understand
     * may be exactly the one that would have changed the verdict, so it is a
     * rejection and never a skip. */
    NR_BAD("rejects an unknown directive rather than skipping it",
           VCS_NODE_REPRO_SCHEMA "\nproducer received\ntrust_me yes\n");
    NR_BAD("rejects a short source_id",
           VCS_NODE_REPRO_SCHEMA "\nproducer received\nsource_id abcd\n");
    NR_BAD("rejects an uppercase source_id (encode never emits one)",
           VCS_NODE_REPRO_SCHEMA "\nproducer received\nsource_id "
           "AAAA111111111111111111111111111111111111111111111111111111111111\n");
    NR_BAD("rejects an artifact with no byte count",
           VCS_NODE_REPRO_SCHEMA "\nproducer received\nartifact "
           "1111111111111111111111111111111111111111111111111111111111111111\n");
    NR_BAD("rejects a non-decimal byte count",
           VCS_NODE_REPRO_SCHEMA "\nproducer received\nartifact "
           "1111111111111111111111111111111111111111111111111111111111111111"
           " 0x10 bin/z23\n");
    NR_BAD("rejects an artifact with no path",
           VCS_NODE_REPRO_SCHEMA "\nproducer received\nartifact "
           "1111111111111111111111111111111111111111111111111111111111111111"
           " 10\n");
    NR_BAD("rejects an unverified component with no reason",
           VCS_NODE_REPRO_SCHEMA "\nproducer received\nunverified libfoo.a\n");
#undef NR_BAD

    /* Over-long lists are REJECTED, not truncated. A truncated unverified
     * list is a component silently excluded from the verdict. */
    char big[VCS_NODE_REPRO_MAX_WIRE_BYTES];
    int w = snprintf(big, sizeof(big), "%s\nproducer received\n",
                     VCS_NODE_REPRO_SCHEMA);
    for (unsigned i = 0; i <= VCS_NODE_REPRO_MAX_UNVERIFIED; i++)
        w += snprintf(big + w, sizeof(big) - (size_t)w,
                      "unverified c%u not rebuilt here\n", i);
    why[0] = '\0';
    NR_CHECK("rejects more unverified rows than it can hold",
             !vcs_node_receipt_decode(big, (size_t)w, &out, why,
                                      sizeof(why)) && why[0] != '\0');

    w = snprintf(big, sizeof(big), "%s\nproducer received\n",
                 VCS_NODE_REPRO_SCHEMA);
    for (unsigned i = 0; i <= VCS_NODE_REPRO_MAX_ARTIFACTS; i++)
        w += snprintf(big + w, sizeof(big) - (size_t)w,
                      "artifact %064u 1 bin/a%u\n", 0, i);
    why[0] = '\0';
    NR_CHECK("rejects more artifacts than it can hold",
             !vcs_node_receipt_decode(big, (size_t)w, &out, why,
                                      sizeof(why)) && why[0] != '\0');

    /* Comments, blank lines and CRLF are ordinary text, not errors. */
    const char *tolerant =
        VCS_NODE_REPRO_SCHEMA "\r\n"
        "# written by tools/scripts/node_reproduce.sh\r\n"
        "\r\n"
        "producer local-rebuild\r\n"
        "artifact "
        "1111111111111111111111111111111111111111111111111111111111111111"
        " 7 bin/z23\r\n";
    why[0] = '\0';
    NR_CHECK("tolerates comments, blank lines and CRLF",
             vcs_node_receipt_decode(tolerant, strlen(tolerant), &out, why,
                                     sizeof(why)) &&
                 out.producer == VCS_NODE_PRODUCER_LOCAL_REBUILD &&
                 out.artifact_count == 1 && out.artifacts[0].bytes == 7 &&
                 strcmp(out.artifacts[0].path, "bin/z23") == 0);
    return failures;
}

/* ── 6. every verdict and rule has a printable name ────────────────────── */

static int t_names_are_total(void)
{
    int failures = 0;
    bool ok = true;
    for (int v = VCS_NODE_REPRO_UNEVALUATED;
         v <= VCS_NODE_REPRO_RECEIPT_INVALID; v++) {
        const char *s =
            vcs_node_repro_verdict_string((enum vcs_node_repro_verdict)v);
        if (!s || !s[0] || strcmp(s, "unknown-verdict") == 0)
            ok = false;
    }
    NR_CHECK("every verdict renders a name (typed JSON never prints a number)",
             ok);
    ok = true;
    for (int r = VCS_NODE_ROW_MATCH; r <= VCS_NODE_ROW_MISSING_FROM_RECEIVED;
         r++) {
        const char *s =
            vcs_node_repro_rule_string((enum vcs_node_repro_rule)r);
        if (!s || !s[0] || strcmp(s, "unknown-rule") == 0)
            ok = false;
    }
    NR_CHECK("every per-artifact rule renders a name", ok);
    NR_CHECK("only match is spelled match among the verdicts",
             strcmp(vcs_node_repro_verdict_string(VCS_NODE_REPRO_MATCH),
                    "match") == 0 &&
                 strcmp(vcs_node_repro_verdict_string(VCS_NODE_REPRO_PARTIAL),
                        "partial") == 0);
    return failures;
}

int test_node_reproduce(void)
{
    int failures = 0;
    printf("=== node_reproduce ===\n");
    failures += t_refuses_self_referential_compare();
    failures += t_partial_is_not_success();
    failures += t_mismatch_is_diagnosed();
    failures += t_rows_and_empty();
    failures += t_codec_roundtrip();
    failures += t_codec_rejections();
    failures += t_names_are_total();
    printf("=== node_reproduce: %d failures ===\n", failures);
    return failures;
}
