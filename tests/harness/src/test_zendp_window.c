/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zendp_window — THE SIGNED-WINDOW CEILING, and the layer it is
 * NOT allowed to reach.
 *
 * A signed endpoint record (ZIDE) says "reach this key at this address
 * until <expiry>". On a node that has SEEN the key revoked on-chain the
 * record stops being advertised within seconds
 * (test_zendp_revocation.c). On a node that has NOT — offline for the
 * revoking block, or a client holding cached bytes — the signed window
 * is the only expiry that exists. So the window is capped:
 * ZENDP_MAX_WINDOW_SECONDS, thirty days, refused at the MINT end and
 * the VERIFY end by one shared rule (zendp_window_check).
 *
 * WHAT THIS FILE PROVES:
 *   1. The rule itself, as pure arithmetic, including the hostile pairs
 *      near UINT64_MAX that separate a comparative implementation from
 *      a wrapping one.
 *   2. Ordinary windows mint and verify; the boundary is INCLUSIVE
 *      (exactly the ceiling is ACCEPTED, one second more is REFUSED),
 *      which is what zid/zendp.h documents.
 *   3. Over-long is refused at BOTH ends, and the refusal is TYPED:
 *      ZENDP_ERR_WINDOW_TOO_LONG, never the generic ZENDP_ERR_SIGN or
 *      ZENDP_ERR_VERIFY. "You signed a promise that is too long" is a
 *      publisher error an operator fixes by re-signing; "this signature
 *      does not hold" is not, and an operator must be able to tell them
 *      apart from the error code alone.
 *   4. A record that was LAWFUL UNDER THE OLD RULE is now refused —
 *      signed the only way such bytes can exist (straight through
 *      zid_doc_sign, bypassing the capped minter, exactly as an older
 *      build would have produced them) and then pushed at the real
 *      verify and accept paths.
 *   5. THE READ-PATH RECHECK. An over-long entry already RESIDENT in a
 *      directory — installed by an older build, or read back from a
 *      store written before the ceiling existed — is not projected to
 *      discovery. The directory is a projection, so judging the window
 *      only on the way in would let exactly the records the ceiling
 *      exists to bound outlive it by already being there.
 *
 *   6. THE REGRESSION GUARD, and it is the most important case in the
 *      file. The window is made of TWO fields at TWO layers:
 *      not_before lives in the ZIDE body, expiry lives in the generic
 *      zid_doc header that THREE document types share. The ceiling is
 *      enforced in zendp_sign/zendp_verify ONLY. If it ever drifts down
 *      to the zid_doc layer it takes RELEASE records (ZIDR) with it,
 *      and those legitimately carry multi-year expiries — a published
 *      release does not stop being that release after thirty days.
 *      Real ones exist in this suite already (test_proof_chain.c ≈ 2096,
 *      test_identity_command.c = 2100-01-01) and the release product
 *      default is a year. So: a decade-long ZIDR is signed and verified
 *      here, with an expiry proven to be far past the endpoint ceiling.
 *      If someone "simplifies" the two call sites into one at the doc
 *      layer, this case is what fails.
 *
 * NOT covered, because a thirty-day ceiling does not close it and was
 * never claimed to: a not_before set far in the FUTURE with a lawful
 * window still mints and later verifies, and a one-second window is
 * still legal. Both are bounds on WIDTH, not on placement. */

#include "test/test_core.h"

#include "base/log_level.h"
#include "vcs/zendp_swarm.h"
#include "zid/zendp.h"
#include "zid/zid.h"

#include <stdio.h>
#include <string.h>

#define ZW_CHECK(name, expr) do {                                     \
    if (expr) { printf("  zendp_window: %s... OK\n", (name)); }        \
    else { printf("  zendp_window: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* A valid v3 hostname: 56 base32 chars (a-z2-7) then ".onion", 62 in
 * all. ASSERTED below rather than trusted — a hostname one character off
 * fails zendp_valid, and then every mint in this file fails for a reason
 * that has nothing to do with the window. */
#define ZW_ONION \
    "zclassictwothreesignedendpointrecordwindowceilingaaaaaaa.onion"

#define ZW_NOT_BEFORE UINT64_C(1767225600)   /* 2026-01-01T00:00:00Z */
#define ZW_NOW        (ZW_NOT_BEFORE + UINT64_C(10))
#define ZW_MAX        ZENDP_MAX_WINDOW_SECONDS
#define ZW_DAY        UINT64_C(86400)

static void zw_seed(uint8_t seed[32], uint8_t b)
{
    memset(seed, b, 32);
}

/* An onion-only record — the smallest shape that passes zendp_valid. */
static void zw_endpoint(struct zendp *ep, uint64_t not_before)
{
    memset(ep, 0, sizeof(*ep));
    ep->flags = ZENDP_HAS_ONION;
    ep->services = UINT64_C(0x0000000000000409);
    ep->height = 3196556;
    ep->not_before = not_before;
    snprintf(ep->onion, sizeof(ep->onion), "%s", ZW_ONION);
    ep->onion_port = 8033;
}

/* Sign a ZIDE body straight through zid_doc_sign, BYPASSING zendp_sign.
 * This is the only way bytes with an over-long window can exist, and it
 * is exactly how an older build produced them: the doc layer has never
 * known about the endpoint window and still must not. */
static bool zw_sign_uncapped(struct zid_doc *doc, const struct zendp *ep,
                             uint64_t seq, uint64_t expiry,
                             const uint8_t seed[32])
{
    uint8_t body[ZENDP_BODY_MAX];
    size_t body_len = zendp_encode_body(body, sizeof(body), ep);
    if (body_len == 0)
        return false;
    return zid_doc_sign(doc, body, (uint16_t)body_len, seq, expiry, seed);
}

/* ── 1. the rule as arithmetic ─────────────────────────────────────
 *
 * zendp_window_check is pure: no clock, no allocation, two numbers
 * judged against each other. Every hostile pair below is chosen so that
 * a WRONG-but-plausible implementation returns a different answer than
 * the right one. */
static int zw_case_rule(void)
{
    int failures = 0;

    /* The fixture before the subject: if the hostname is malformed every
     * mint in this file fails and the window cases prove nothing. */
    ZW_CHECK("the test hostname is a well-formed v3 onion",
             strlen(ZW_ONION) == ZENDP_ONION_LEN &&
             ZENDP_ONION_LEN == 62);

    ZW_CHECK("the ceiling is thirty days", ZW_MAX == 30 * ZW_DAY);

    ZW_CHECK("an ordinary one-day window is OK",
             zendp_window_check(ZW_NOT_BEFORE, ZW_NOT_BEFORE + ZW_DAY) ==
                 ZENDP_WINDOW_OK);
    ZW_CHECK("a one-second window is OK (the ceiling bounds width, not "
             "narrowness)",
             zendp_window_check(ZW_NOT_BEFORE, ZW_NOT_BEFORE + 1) ==
                 ZENDP_WINDOW_OK);

    /* THE BOUNDARY. zid/zendp.h says "maximum" means the maximum is
     * allowed, so this pair is the contract, not an implementation
     * detail: exactly the ceiling is ACCEPTED. */
    ZW_CHECK("EXACTLY the ceiling is ACCEPTED (the boundary is inclusive)",
             zendp_window_check(ZW_NOT_BEFORE, ZW_NOT_BEFORE + ZW_MAX) ==
                 ZENDP_WINDOW_OK);
    ZW_CHECK("the ceiling plus one second is REFUSED",
             zendp_window_check(ZW_NOT_BEFORE, ZW_NOT_BEFORE + ZW_MAX + 1) ==
                 ZENDP_WINDOW_TOO_LONG);

    /* A window that never opens is its OWN verdict, and it must be
     * decided FIRST. If the width were measured before the ordering,
     * expiry < not_before would underflow to roughly 1.8e19 and this
     * would come back TOO_LONG — a true refusal for a false reason,
     * which sends an operator to fix the wrong field. */
    ZW_CHECK("expiry before not_before is NEVER_OPENS, not TOO_LONG "
             "(the ordering test runs first, so nothing underflows)",
             zendp_window_check(100, 50) == ZENDP_WINDOW_NEVER_OPENS);
    ZW_CHECK("expiry EQUAL to not_before is NEVER_OPENS",
             zendp_window_check(100, 100) == ZENDP_WINDOW_NEVER_OPENS);
    ZW_CHECK("the extreme inversion is NEVER_OPENS, not a wrapped width",
             zendp_window_check(UINT64_MAX, 0) == ZENDP_WINDOW_NEVER_OPENS);

    /* THE HOSTILE PAIRS. The algebraically equivalent
     * `expiry > not_before + ZENDP_MAX_WINDOW_SECONDS` is the form that
     * WRAPS: a not_before within thirty days of UINT64_MAX makes the sum
     * overflow to a small number, and a perfectly lawful ten-second
     * window then reads as over-long. Subtracting the smaller unsigned
     * from the larger — after the ordering test has established which is
     * which — has no such case. These two pairs are the difference. */
    ZW_CHECK("a lawful ten-second window at the very top of the range is "
             "OK (an additive implementation would wrap and refuse it)",
             zendp_window_check(UINT64_MAX - 10, UINT64_MAX) ==
                 ZENDP_WINDOW_OK);
    ZW_CHECK("exactly the ceiling at the top of the range is OK",
             zendp_window_check(UINT64_MAX - ZW_MAX, UINT64_MAX) ==
                 ZENDP_WINDOW_OK);
    ZW_CHECK("the ceiling plus one at the top of the range is REFUSED",
             zendp_window_check(UINT64_MAX - ZW_MAX - 1, UINT64_MAX) ==
                 ZENDP_WINDOW_TOO_LONG);
    ZW_CHECK("the widest window expressible is REFUSED",
             zendp_window_check(0, UINT64_MAX) == ZENDP_WINDOW_TOO_LONG);

    ZW_CHECK("every verdict has a stable name",
             strcmp(zendp_window_string(ZENDP_WINDOW_OK), "ok") == 0 &&
             strcmp(zendp_window_string(ZENDP_WINDOW_NEVER_OPENS),
                    "window-never-opens") == 0 &&
             strcmp(zendp_window_string(ZENDP_WINDOW_TOO_LONG),
                    "window-exceeds-maximum") == 0);

    return failures;
}

/* ── 2+3. mint and verify, at the boundary and past it ──────────── */
static int zw_case_mint_and_verify(void)
{
    int failures = 0;
    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);

    uint8_t seed[32];
    zw_seed(seed, 0x51);
    struct zendp ep;
    zw_endpoint(&ep, ZW_NOT_BEFORE);

    /* An ordinary one-day record: mints, and verifies. */
    struct zid_doc doc;
    bool minted = zendp_sign(&doc, &ep, 1, ZW_NOT_BEFORE + ZW_DAY, seed);
    struct zendp back;
    memset(&back, 0, sizeof(back));
    ZW_CHECK("a one-day window MINTS and VERIFIES, and the body survives",
             minted && zendp_verify(&doc, &back, ZW_NOW) &&
             back.not_before == ZW_NOT_BEFORE &&
             strcmp(back.onion, ZW_ONION) == 0 && back.onion_port == 8033);

    /* EXACTLY the ceiling: accepted at both ends. A node that minted
     * this must be able to read it back, or the two ends have drifted. */
    struct zid_doc at_max;
    bool minted_max = zendp_sign(&at_max, &ep, 2, ZW_NOT_BEFORE + ZW_MAX, seed);
    ZW_CHECK("EXACTLY the ceiling MINTS and VERIFIES (inclusive at both ends)",
             minted_max && zendp_verify(&at_max, NULL, ZW_NOW));

    /* One second more: refused at the mint end. The node must not be
     * able to sign bytes it would itself reject. */
    struct zid_doc over;
    ZW_CHECK("the ceiling plus one second is REFUSED AT THE MINT END",
             !zendp_sign(&over, &ep, 3, ZW_NOT_BEFORE + ZW_MAX + 1, seed));

    /* And a window that never opens is still refused at the mint end,
     * which the ceiling did not replace. */
    ZW_CHECK("a window that never opens is still refused at the mint end",
             !zendp_sign(&over, &ep, 4, ZW_NOT_BEFORE, seed));

    /* Refused at the VERIFY end too, on bytes the capped minter would
     * never have produced. Signature is GOOD; the window is not. */
    struct zid_doc uncapped;
    bool forged = zw_sign_uncapped(&uncapped, &ep, 5,
                                   ZW_NOT_BEFORE + ZW_MAX + 1, seed);
    ZW_CHECK("the bypass produces genuinely well-signed bytes (so the "
             "refusal below is about the window, not the signature)",
             forged && zid_doc_verify(&uncapped, ZW_NOW));
    ZW_CHECK("the ceiling plus one second is REFUSED AT THE VERIFY END",
             forged && !zendp_verify(&uncapped, NULL, ZW_NOW));

    /* A hostile pair at the top of the range mints, because ten seconds
     * is a lawful window wherever it sits. This is the end-to-end form
     * of the wrap case: an additive implementation refuses it. */
    struct zendp top;
    zw_endpoint(&top, UINT64_MAX - 10);
    struct zid_doc top_doc;
    ZW_CHECK("a ten-second window at the top of the uint64 range MINTS",
             zendp_sign(&top_doc, &top, 1, UINT64_MAX, seed));

    zcl_log_level_set(saved);
    return failures;
}

/* ── 4. a record that was lawful under the OLD rule ───────────────
 *
 * Ninety days: perfectly ordinary before the ceiling existed, and the
 * publish default was three days so nothing about it looked unusual.
 * It is refused now, and the refusal is TYPED. */
static int zw_case_lawful_under_the_old_rule(void)
{
    int failures = 0;
    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);

    uint8_t seed[32];
    zw_seed(seed, 0x52);
    struct zendp ep;
    zw_endpoint(&ep, ZW_NOT_BEFORE);

    const uint64_t ninety_days = ZW_NOT_BEFORE + 90 * ZW_DAY;
    struct zid_doc old_doc;
    bool forged = zw_sign_uncapped(&old_doc, &ep, 7, ninety_days, seed);

    ZW_CHECK("the ninety-day record is intact: signature good, doc not "
             "expired, body decodes as a real ZIDE",
             forged && zid_doc_verify(&old_doc, ZW_NOW) &&
             zendp_decode_body(&ep, old_doc.body, old_doc.body_len));
    ZW_CHECK("a ninety-day record — lawful under the old rule — is now "
             "REFUSED by zendp_verify",
             forged && !zendp_verify(&old_doc, NULL, ZW_NOW));

    /* The typed refusal, through the real ingest path. The window is
     * judged BEFORE the chain is asked, so this answer does not depend
     * on an anchor oracle being registered — and it must not read as
     * ZENDP_ERR_VERIFY (tampering) or ZENDP_ERR_BODY (wrong doc type). */
    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = zid_doc_encode(wire, sizeof(wire), &old_doc);
    struct zendp_directory dir;
    zendp_directory_init(&dir);
    enum zendp_result r = zendp_accept(&dir, wire, wire_len, ZW_NOW, NULL,
                                       NULL);
    ZW_CHECK("accept refuses it as WINDOW_TOO_LONG — not as a bad "
             "signature, and not as a wrong body type",
             wire_len > 0 && r == ZENDP_ERR_WINDOW_TOO_LONG);
    ZW_CHECK("the typed refusal has its own operator-facing name",
             strcmp(zendp_result_string(ZENDP_ERR_WINDOW_TOO_LONG),
                    "window-exceeds-maximum") == 0 &&
             strcmp(zendp_result_string(ZENDP_ERR_WINDOW_TOO_LONG),
                    zendp_result_string(ZENDP_ERR_VERIFY)) != 0 &&
             strcmp(zendp_result_string(ZENDP_ERR_WINDOW_TOO_LONG),
                    zendp_result_string(ZENDP_ERR_SIGN)) != 0);
    ZW_CHECK("nothing over-long was installed in the directory",
             dir.count == 0);

    /* The same bytes with a lawful width sail through the window gate
     * and are stopped only by the chain question — proof that the case
     * above was refused for the WINDOW and not for some shared reason
     * every synthetic record would hit. */
    struct zid_doc ok_doc;
    if (zw_sign_uncapped(&ok_doc, &ep, 8, ZW_NOT_BEFORE + ZW_DAY, seed)) {
        uint8_t ok_wire[ZID_DOC_MAX];
        size_t ok_len = zid_doc_encode(ok_wire, sizeof(ok_wire), &ok_doc);
        enum zendp_result ok_r =
            zendp_accept(&dir, ok_wire, ok_len, ZW_NOW, NULL, NULL);
        ZW_CHECK("a one-day record of the same shape gets PAST the window "
                 "gate and is judged on the chain instead",
                 ok_len > 0 && ok_r != ZENDP_ERR_WINDOW_TOO_LONG);
    } else {
        ZW_CHECK("a one-day record of the same shape signs", false);
    }

    zcl_log_level_set(saved);
    return failures;
}

/* ── 5. the read-path recheck ─────────────────────────────────────
 *
 * An entry can be RESIDENT without ever passing today's acceptance: an
 * older build installed it, or it was read back from a store written
 * before the ceiling existed. The directory is a projection, so the
 * window is re-judged on every read. Built by hand here because that is
 * precisely the state acceptance can no longer produce. */
static int zw_case_resident_entry_not_projected(void)
{
    int failures = 0;
    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);

    struct zendp_directory dir;
    zendp_directory_init(&dir);

    struct zendp ep;
    zw_endpoint(&ep, ZW_NOT_BEFORE);

    /* Two entries, identical but for the width of the window. Both are
     * in-window at ZW_NOW and both are ACTIVE-anchored, so the ONLY
     * thing that can separate them is the ceiling. */
    struct zendp_entry *lawful = &dir.e[0];
    struct zendp_entry *over = &dir.e[1];
    memset(lawful, 0, sizeof(*lawful));
    memset(over, 0, sizeof(*over));

    lawful->used = true;
    memset(lawful->master_pubkey, 0xa1, 32);
    lawful->ep = ep;
    lawful->doc.expiry = ZW_NOT_BEFORE + ZW_DAY;
    lawful->doc.seq = 1;
    lawful->anchor.state = ZENDP_ANCHOR_ACTIVE;
    lawful->anchor.anchor_height = 100;

    over->used = true;
    memset(over->master_pubkey, 0xb2, 32);
    over->ep = ep;
    over->doc.expiry = ZW_NOT_BEFORE + ZW_MAX + 1;
    over->doc.seq = 1;
    over->anchor.state = ZENDP_ANCHOR_ACTIVE;
    over->anchor.anchor_height = 100;
    dir.count = 2;

    struct zendp_record_view views[4];
    memset(views, 0, sizeof(views));
    size_t n = zendp_directory_records(&dir, ZW_NOW, views, 4);

    ZW_CHECK("only the lawful entry is projected to discovery",
             n == 1 && memcmp(views[0].master_pubkey, lawful->master_pubkey,
                              32) == 0);
    ZW_CHECK("the over-long entry is not projected even though it is "
             "in-window and ACTIVE-anchored",
             n == 1 && memcmp(views[0].master_pubkey, over->master_pubkey,
                              32) != 0);

    /* Widening the lawful entry past the ceiling empties the projection
     * — the read path judges the window, it does not remember a verdict
     * from whenever the entry arrived. */
    lawful->doc.expiry = ZW_NOT_BEFORE + ZW_MAX + 1;
    n = zendp_directory_records(&dir, ZW_NOW, views, 4);
    ZW_CHECK("widening a resident entry past the ceiling drops it from "
             "discovery on the next read",
             n == 0);

    /* Exactly the ceiling stays projected — the read path uses the same
     * inclusive boundary as mint and verify. */
    lawful->doc.expiry = ZW_NOT_BEFORE + ZW_MAX;
    n = zendp_directory_records(&dir, ZW_NOW, views, 4);
    ZW_CHECK("a resident entry at EXACTLY the ceiling is still projected",
             n == 1);

    zcl_log_level_set(saved);
    return failures;
}

/* ── 6. THE REGRESSION GUARD — release records keep long expiries ──
 *
 * If this case fails, the ceiling has drifted from the endpoint layer
 * down to the shared zid_doc layer and taken every other document type
 * with it. Read the file header before "fixing" it. */
static int zw_case_release_docs_keep_long_expiries(void)
{
    int failures = 0;
    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);

    uint8_t seed[32];
    zw_seed(seed, 0x53);

    struct zid_release rel;
    memset(&rel, 0, sizeof(rel));
    snprintf(rel.name, sizeof(rel.name), "zclassic23");
    snprintf(rel.version, sizeof(rel.version), "1.0.0");
    memset(rel.manifest_root, 0x7c, 32);

    /* 2100-01-01T00:00:00Z — the expiry test_identity_command.c already
     * uses for a real release document. */
    const uint64_t year_2100 = UINT64_C(4102444800);
    /* ≈ 2096 — the expiry test_proof_chain.c already uses. */
    const uint64_t year_2096 = UINT64_C(4000000000);
    /* The release product default: a year out. */
    const uint64_t one_year = ZW_NOT_BEFORE + 365 * ZW_DAY;

    /* State the trap in the assertion itself: every expiry below is far
     * past what an ENDPOINT record may claim. That is the point — these
     * are not endpoint records. */
    ZW_CHECK("the release expiries under test are all far past the "
             "endpoint ceiling",
             zendp_window_check(ZW_NOT_BEFORE, year_2100) ==
                 ZENDP_WINDOW_TOO_LONG &&
             zendp_window_check(ZW_NOT_BEFORE, year_2096) ==
                 ZENDP_WINDOW_TOO_LONG &&
             zendp_window_check(ZW_NOT_BEFORE, one_year) ==
                 ZENDP_WINDOW_TOO_LONG);

    struct zid_doc doc;
    struct zid_release back;
    memset(&back, 0, sizeof(back));
    bool signed_2100 = zid_release_sign(&doc, &rel, 1, year_2100, seed);
    ZW_CHECK("a ZIDR release document expiring in 2100 SIGNS and VERIFIES",
             signed_2100 && zid_release_verify(&doc, &back, ZW_NOW) &&
             strcmp(back.name, "zclassic23") == 0 &&
             strcmp(back.version, "1.0.0") == 0);

    struct zid_doc doc96;
    ZW_CHECK("a ZIDR release document expiring in 2096 SIGNS and VERIFIES",
             zid_release_sign(&doc96, &rel, 2, year_2096, seed) &&
             zid_release_verify(&doc96, NULL, ZW_NOW));

    struct zid_doc doc1y;
    ZW_CHECK("the one-year release default SIGNS and VERIFIES",
             zid_release_sign(&doc1y, &rel, 3, one_year, seed) &&
             zid_release_verify(&doc1y, NULL, ZW_NOW));

    /* And the layer underneath both document types stays innocent: the
     * generic doc header knows nothing about endpoint windows, which is
     * the structural reason release records are safe. */
    uint8_t body[8] = { 'Z', 'I', 'D', 'X', 1, 2, 3, 4 };
    struct zid_doc generic;
    ZW_CHECK("the shared zid_doc layer still signs and verifies a "
             "decade-long expiry — the ceiling lives ABOVE it",
             zid_doc_sign(&generic, body, sizeof(body), 1, year_2100, seed) &&
             zid_doc_verify(&generic, ZW_NOW));

    zcl_log_level_set(saved);
    return failures;
}

int test_zendp_window(void)
{
    printf("\n=== zendp window ceiling: a record cannot promise a key is "
           "reachable forever ===\n");
    printf("  (thirty days, refused at BOTH ends — and NOT applied to "
           "release documents, which legitimately outlive it)\n");
    int failures = 0;
    failures += zw_case_rule();
    failures += zw_case_mint_and_verify();
    failures += zw_case_lawful_under_the_old_rule();
    failures += zw_case_resident_entry_not_projected();
    failures += zw_case_release_docs_keep_long_expiries();
    if (failures == 0)
        printf("=== zendp window ceiling: all checks passed ===\n");
    else
        printf("=== zendp window ceiling: %d FAILED ===\n", failures);
    return failures;
}
