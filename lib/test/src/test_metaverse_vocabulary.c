/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_metaverse_vocabulary — the ADVERSARIAL gate on the one canonical
 * metaverse verb/kind vocabulary and its broker translation.
 *
 * This group exists because the same thirteen verbs were described three
 * times (metaverse action bits, metaverse grant positions, broker wire ints)
 * and the three descriptions did not agree. Every check below PLANTS the
 * specific drift that divergence produced and requires the system to catch
 * it. A check that merely walks a happy path does not belong here.
 *
 * What each section plants:
 *
 *  A. GOLDEN VERSION-1 FRAMES. Byte-exact request and response records,
 *     hand-derived from the wire layout as it stood at base commit
 *     96a0d0e49 (see the derivation note above k_golden_*), not captured
 *     from the encoder. Plants: a "compatible" rewrite that silently changes
 *     a field offset, width, or endianness. Old frames must decode to the
 *     SAME canonical operation forever.
 *
 *  B. ROUND-TRIP IDENTITY. encode -> decode -> encode is byte-identical for
 *     every verb, kind, and param length including the bounds. Plants: a
 *     codec that normalises on the way through, so two distinct requests
 *     collapse onto one frame.
 *
 *  C. UNIQUENESS AND GAPS. Every verb has one wire value and one name; no
 *     value is shared; a value the table does not define is refused rather
 *     than read as an unnamed verb. Plants: a gap misread as a value, which
 *     is how an agent gets a right nobody wrote down.
 *
 *  D. QUERIES ARE READ-ONLY. ENUMERATE_PROPERTIES and INSPECT_PROPERTY must
 *     not reach COMMIT, must not carry value, and must not mint a receipt.
 *     Proven by counting the seam calls, not by reading the status code: a
 *     status can be right while the mutation already happened.
 *
 *  E. LIST IS NOT LISTING. The verb whose meaning was contradictory across
 *     the boundary. On the wire, value 2 is the enumeration READ and can
 *     never set a for-sale flag; LIST_FOR_SALE is a MUTATION with its own
 *     appended wire value. Plants: the reading that made one identifier mean
 *     both.
 *
 *  F. HOST IS LOCAL. HOST is an action that changes local state and no
 *     external state — two different columns, not one word. It must still
 *     reach COMMIT. Plants: a "unification" that makes the two surfaces
 *     agree by deleting a column, which would stop HOST minting a receipt.
 *
 *  G. TRANSFER MOVES VALUE, EVERYWHERE. The metaverse rules charge it
 *     against the cumulative budget; the broker's value predicate omitted
 *     it, so the same action was budget-free on one side of the socket.
 *     This section asserts AGREEMENT between the two, plus the contract's
 *     tiebreak (the metaverse side is correct). It fails against the old
 *     code by construction.
 *
 *  H. NO BYPASS. Every refusal the grant evaluator can produce must happen
 *     BEFORE the node seam is touched. Counted, not inferred.
 *
 *  I. RECEIPT BINDING. A mutation's response receipt id is the audit row's
 *     id and the chain verifies; a successful query mints neither.
 *
 *  J. THE PRODUCTION BROKER IS NOT A FIXTURE. The shipped
 *     `--metaverse-broker` mode is run for real against an isolated
 *     directory and asked for a fixture property. A production broker must
 *     not be able to answer.
 *
 * The action-BIT half lives in test_metaverse_vocabulary_bits.c because at
 * the base commit property_action.h and property_grant.h cannot share a
 * translation unit. See that file's header.
 *
 * DATADIR: pinned to a hermetic tmp dir for the whole run. Nothing here
 * should reach a datadir; pinning is what proves it rather than assuming it.
 */

#define _GNU_SOURCE

#include "test/test_core.h"

/* BOTH headers, deliberately and in this order. At the base commit each one
 * declared its own action enum and including the pair was a redefinition
 * error; that this file compiles at all is the first half of the unification
 * proof, and check_headers_unified() is the second. */
#include "metaverse/property_action.h"
#include "metaverse/property_grant.h"
#include "metaverse/property_id.h"
#include "session/agent_broker.h"
#include "session/agent_broker_proto.h"
#include "session/agent_broker_vocab.h"
#include "util/util.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Lane A's canonical vocabulary header is expected to define this token. It
 * is the switch that arms the checks which CANNOT compile until the two
 * metaverse headers stop colliding — see check_headers_unified(). Nothing
 * else in this file is gated. */
#ifndef METAVERSE_VOCABULARY_UNIFIED
#define METAVERSE_VOCABULARY_UNIFIED 0
#endif

#define VC_CHECK(name, expr) do { \
    printf("vocabulary: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Declared in test_metaverse_vocabulary_bits.c. */
int mvv_action_bit_checks(void);

/* ── contract §2: every PRESERVED broker wire value, pinned at COMPILE time ─
 *
 * "Every existing mvap_verb wire value keeps its numeric value and its
 * current meaning." Renumbering one to make room for LIST_FOR_SALE — the
 * obvious tidy-up — is a silent reinterpretation of every frame already on
 * the wire, and it stops this translation unit compiling. LIST_FOR_SALE is
 * deliberately NOT pinned here: it is appended at the next free value and
 * its arrival is checked at runtime against MVAP_VERSION. */
_Static_assert(MVAP_VERB_INSPECT == 1, "wire value INSPECT must stay 1");
_Static_assert(MVAP_VERB_LIST == 2, "wire value LIST must stay 2");
_Static_assert(MVAP_VERB_HOST == 3, "wire value HOST must stay 3");
_Static_assert(MVAP_VERB_PUBLISH_REVISION == 4,
               "wire value PUBLISH_REVISION must stay 4");
_Static_assert(MVAP_VERB_UPDATE_POINTER == 5,
               "wire value UPDATE_POINTER must stay 5");
_Static_assert(MVAP_VERB_SELL == 6, "wire value SELL must stay 6");
_Static_assert(MVAP_VERB_BUY == 7, "wire value BUY must stay 7");
_Static_assert(MVAP_VERB_DELIVER == 8, "wire value DELIVER must stay 8");
_Static_assert(MVAP_VERB_LEASE == 9, "wire value LEASE must stay 9");
_Static_assert(MVAP_VERB_TRANSFER == 10, "wire value TRANSFER must stay 10");
_Static_assert(MVAP_VERB_ACCEPT_PAYMENT == 11,
               "wire value ACCEPT_PAYMENT must stay 11");
_Static_assert(MVAP_VERB_DELEGATE == 12, "wire value DELEGATE must stay 12");
_Static_assert(MVAP_VERB_REVOKE == 13, "wire value REVOKE must stay 13");
_Static_assert(MVAP_VERB__COUNT >= 14,
               "the thirteen version-1 verbs must all remain in range");

/* The record layout the golden vectors below are derived from. A change to
 * any of these is a change to every frame already written. */
_Static_assert(MVAP_REQ_FIXED == 56, "version-1 request header is 56 bytes");
_Static_assert(MVAP_RESP_FIXED == 50, "version-1 response header is 50 bytes");
_Static_assert(MVAP_MAGIC == 0x3141564Du, "the frame magic is a wire constant");
_Static_assert(MVAP_FRAME_PREFIX == 4, "the frame prefix is 4 little-endian bytes");

/* Contract §2: the two kind enums align numerically 1..8 under different
 * names, so the wire mapping is the identity — verified PER ROW here rather
 * than assumed, which is what the contract asks for. A row that drifts stops
 * this file compiling instead of quietly translating one kind into another. */
_Static_assert((int)METAVERSE_KIND_CONTENT == (int)MVAP_KIND_CONTENT, "kind row 1");
_Static_assert((int)METAVERSE_KIND_ZCODE_PACKAGE == (int)MVAP_KIND_ZCODE, "kind row 2");
_Static_assert((int)METAVERSE_KIND_ZNAM_NAME == (int)MVAP_KIND_NAME, "kind row 3");
_Static_assert((int)METAVERSE_KIND_ZSLP_ASSET == (int)MVAP_KIND_ASSET, "kind row 4");
_Static_assert((int)METAVERSE_KIND_HOSTED_SERVICE == (int)MVAP_KIND_SERVICE, "kind row 5");
_Static_assert((int)METAVERSE_KIND_ENDPOINT_ONION == (int)MVAP_KIND_ENDPOINT, "kind row 6");
_Static_assert((int)METAVERSE_KIND_STOREFRONT_PRODUCT == (int)MVAP_KIND_PRODUCT, "kind row 7");
_Static_assert((int)METAVERSE_KIND_CONTRACT_SWAP == (int)MVAP_KIND_CONTRACT, "kind row 8");
_Static_assert((int)METAVERSE_KIND_COUNT == (int)MVAP_KIND__COUNT,
               "the two kind vocabularies must stay the same length");
_Static_assert((int)METAVERSE_KIND_UNKNOWN == (int)MVAP_KIND_ANY,
               "zero means 'no specific kind' on both sides");

/* ── A. golden version-1 frames ──────────────────────────────────────────
 *
 * DERIVATION (deliberately BY HAND from the layout, not captured from the
 * encoder — a vector printed by the code under test restates that code
 * instead of recording the wire):
 *
 *   request record, after the 4-byte little-endian length prefix
 *     +0   u32  magic          4d 56 41 31   ("MVA1", 0x3141564D LE)
 *     +4   u16  version        01 00
 *     +6   u16  verb
 *     +8   u32  request_id
 *     +12  u64  value_zats
 *     +20  [32] property_id
 *     +52  u16  kind
 *     +54  u16  param length
 *     +56  ..   param bytes
 *   record length = 56 + param length; the prefix carries that length.
 *
 *   response record
 *     +0 magic, +4 version, +6 verb, +8 request_id, +12 i32 status,
 *     +16 [32] receipt_id, +48 u16 body length, +50 body bytes
 *   record length = 50 + body length.
 *
 * Each vector below states the fields it encodes in its comment; the hex is
 * those fields written out under the layout above. */

struct golden_req {
    const char *what;
    const char *hex;
    uint32_t verb;
    uint32_t request_id;
    uint64_t value_zats;
    uint8_t  fill;          /* every property_id byte, or 0xFF for a ramp */
    uint16_t kind;
    const char *param;
};

/* verb=INSPECT(1) id=0x11223344 value=0 property=ramp 0x01..0x20
 * kind=CONTENT(1) param="alpha" -> record 61 (0x3d) */
static const char k_golden_inspect[] =
    "3d000000"
    "4d564131" "0100" "0100" "44332211" "0000000000000000"
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    "0100" "0500" "616c706861";

/* verb=LIST(2) id=7 value=0 property=zero kind=ANY(0) param="" -> record 56 */
static const char k_golden_list[] =
    "38000000"
    "4d564131" "0100" "0200" "07000000" "0000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000" "0000";

/* verb=TRANSFER(10) id=0xdeadbeef value=100000000 property=0xaa*32
 * kind=ZCODE(2) param="counterparty-1" -> record 70 (0x46) */
static const char k_golden_transfer[] =
    "46000000"
    "4d564131" "0100" "0a00" "efbeadde" "00e1f50500000000"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "0200" "0e00" "636f756e74657270617274792d31";

/* verb=SELL(6) id=2 value=250000 property=0x5a*32 kind=PRODUCT(7)
 * param="" -> record 56. SELL is the row whose ORDER differs between the
 * two vocabularies (wire 6 before BUY 7; the action bits put BUY first), so
 * a re-derived table that follows the bit order would move it. */
static const char k_golden_sell[] =
    "38000000"
    "4d564131" "0100" "0600" "02000000" "90d0030000000000"
    "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
    "0700" "0000";

/* verb=REVOKE(13) id=0xffffffff value=0 property=zero kind=ANY param=""
 * -> record 56. REVOKE is one of the two verbs allowed a zero property id. */
static const char k_golden_revoke[] =
    "38000000"
    "4d564131" "0100" "0d00" "ffffffff" "0000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000" "0000";

/* verb=INSPECT(1) id=1 status=OK(0) receipt=zero body="{}" -> record 52 */
static const char k_golden_resp_read[] =
    "34000000"
    "4d564131" "0100" "0100" "01000000" "00000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0200" "7b7d";

/* verb=TRANSFER(10) id=9 status=DENIED_BUDGET(-12) receipt=0x77*32 body=""
 * -> record 50 (0x32) */
static const char k_golden_resp_denied[] =
    "32000000"
    "4d564131" "0100" "0a00" "09000000" "f4ffffff"
    "7777777777777777777777777777777777777777777777777777777777777777"
    "0000";

static const struct golden_req k_golden_reqs[] = {
    { "INSPECT/alpha",  k_golden_inspect,  MVAP_VERB_INSPECT,  0x11223344u,
      0, 0xFF, MVAP_KIND_CONTENT, "alpha" },
    { "LIST/zero-id",   k_golden_list,     MVAP_VERB_LIST,     7u,
      0, 0x00, MVAP_KIND_ANY, "" },
    { "TRANSFER/1zcl",  k_golden_transfer, MVAP_VERB_TRANSFER, 0xDEADBEEFu,
      100000000u, 0xAA, MVAP_KIND_ZCODE, "counterparty-1" },
    { "SELL/250000",    k_golden_sell,     MVAP_VERB_SELL,     2u,
      250000u, 0x5A, MVAP_KIND_PRODUCT, "" },
    { "REVOKE/zero-id", k_golden_revoke,   MVAP_VERB_REVOKE,   0xFFFFFFFFu,
      0, 0x00, MVAP_KIND_ANY, "" },
};

static void golden_property_id(uint8_t fill, uint8_t out[MVAP_PROPERTY_ID_LEN])
{
    for (size_t i = 0; i < MVAP_PROPERTY_ID_LEN; i++)
        out[i] = (fill == 0xFF) ? (uint8_t)(i + 1u) : fill;
}

static int check_golden_v1_frames(void)
{
    int failures = 0;

    for (size_t g = 0; g < sizeof(k_golden_reqs) / sizeof(k_golden_reqs[0]);
         g++) {
        const struct golden_req *gv = &k_golden_reqs[g];
        size_t hexlen = strlen(gv->hex);
        uint8_t bytes[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
        char label[96];

        if (hexlen % 2 != 0 || hexlen / 2 > sizeof(bytes)) {
            printf("vocabulary: golden vector %s is malformed... FAIL\n",
                   gv->what);
            failures++;
            continue;
        }
        size_t n = hexlen / 2;
        test_hex_to_bytes(gv->hex, bytes, (int)n);

        /* The prefix must agree with the record it introduces. A vector whose
         * own framing is inconsistent would prove nothing about the codec. */
        snprintf(label, sizeof(label),
                 "golden %s frames its own record length", gv->what);
        VC_CHECK(label, mvap_frame_length(bytes, n) == (uint32_t)(n - 4));

        /* DECODE is the compatibility claim and it must hold forever: a
         * version-1 frame keeps meaning the same operation. */
        struct mvap_request got;
        memset(&got, 0, sizeof(got));
        bool ok = mvap_request_decode(bytes + MVAP_FRAME_PREFIX,
                                      n - MVAP_FRAME_PREFIX, &got);
        uint8_t want_id[MVAP_PROPERTY_ID_LEN];
        golden_property_id(gv->fill, want_id);

        snprintf(label, sizeof(label),
                 "golden %s decodes to the same operation", gv->what);
        VC_CHECK(label,
                 ok && got.verb == gv->verb &&
                 got.request_id == gv->request_id &&
                 got.value_zats == gv->value_zats &&
                 got.kind == gv->kind &&
                 memcmp(got.property_id, want_id, MVAP_PROPERTY_ID_LEN) == 0 &&
                 strcmp(got.param, gv->param) == 0);

        /* While the protocol still SPEAKS version 1, the encoder must also
         * reproduce these bytes exactly. Once MVAP_VERSION moves on, the
         * decode claim above is the one that carries the compatibility
         * record and this half correctly stops applying. */
        if (MVAP_VERSION == 1u && ok) {
            uint8_t re[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
            size_t rn = mvap_request_encode(&got, re, sizeof(re));
            snprintf(label, sizeof(label),
                     "golden %s re-encodes byte-identically", gv->what);
            VC_CHECK(label, rn == n && memcmp(re, bytes, n) == 0);
        }
    }

    /* Response side: the same claim for the record an agent reads back. */
    struct {
        const char *what; const char *hex; uint32_t verb; uint32_t rid;
        int32_t status; uint8_t receipt_fill; const char *body;
    } resps[] = {
        { "read reply",   k_golden_resp_read,   MVAP_VERB_INSPECT, 1u,
          MVAP_OK, 0x00, "{}" },
        { "denied reply", k_golden_resp_denied, MVAP_VERB_TRANSFER, 9u,
          MVAP_ERR_DENIED_BUDGET, 0x77, "" },
    };
    for (size_t i = 0; i < sizeof(resps) / sizeof(resps[0]); i++) {
        uint8_t bytes[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
        size_t n = strlen(resps[i].hex) / 2;
        char label[96];
        test_hex_to_bytes(resps[i].hex, bytes, (int)n);

        struct mvap_response got;
        memset(&got, 0, sizeof(got));
        bool ok = mvap_response_decode(bytes + MVAP_FRAME_PREFIX,
                                       n - MVAP_FRAME_PREFIX, &got);
        uint8_t want_receipt[MVAP_RECEIPT_ID_LEN];
        memset(want_receipt, resps[i].receipt_fill, sizeof(want_receipt));

        snprintf(label, sizeof(label), "golden %s decodes unchanged",
                 resps[i].what);
        VC_CHECK(label,
                 ok && got.verb == resps[i].verb &&
                 got.request_id == resps[i].rid &&
                 got.status == resps[i].status &&
                 memcmp(got.receipt_id, want_receipt,
                        MVAP_RECEIPT_ID_LEN) == 0 &&
                 strcmp(got.body, resps[i].body) == 0);

        if (MVAP_VERSION == 1u && ok) {
            uint8_t re[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
            size_t rn = mvap_response_encode(&got, re, sizeof(re));
            snprintf(label, sizeof(label), "golden %s re-encodes identically",
                     resps[i].what);
            VC_CHECK(label, rn == n && memcmp(re, bytes, n) == 0);
        }
    }

    /* The status the denied golden vector carries must still MEAN the same
     * refusal; a renumbered status enum would decode to a different reason
     * with the same bytes. */
    VC_CHECK("the golden refusal still names DENIED_BUDGET",
             strcmp(mvap_status_name(MVAP_ERR_DENIED_BUDGET),
                    "DENIED_BUDGET") == 0);

    return failures;
}

/* ── B. round-trip identity over the whole vocabulary ────────────────────── */

static int check_round_trip_is_byte_identical(void)
{
    int failures = 0;

    static const char *const params[] = {
        "", "a",
        ("abcdefghij0123456789.-_ABCDEFGHIJ0123456789.-_abcdefghij0123456789"
         ".-_ABCDEFGHIJ0123456789.-_abcd"),             /* exactly 96 bytes */
    };
    _Static_assert(sizeof(
        "abcdefghij0123456789.-_ABCDEFGHIJ0123456789.-_abcdefghij0123456789"
        ".-_ABCDEFGHIJ0123456789.-_abcd") - 1 == MVAP_PARAM_MAX,
        "the long round-trip param must sit exactly on the bound");
    bool all_identical = true;
    bool covered_every_verb = true;
    size_t cases = 0;

    for (uint32_t verb = 1; verb < (uint32_t)MVAP_VERB__COUNT; verb++) {
        bool this_verb_encoded = false;
        for (uint16_t kind = 0; kind < (uint16_t)MVAP_KIND__COUNT; kind++) {
            for (size_t p = 0; p < sizeof(params) / sizeof(params[0]); p++) {
                struct mvap_request req;
                memset(&req, 0, sizeof(req));
                req.verb = verb;
                req.request_id = (uint32_t)(verb * 1000u + kind);
                req.value_zats = (uint64_t)verb << 32;
                for (size_t b = 0; b < MVAP_PROPERTY_ID_LEN; b++)
                    req.property_id[b] = (uint8_t)(b ^ verb);
                req.kind = kind;
                snprintf(req.param, sizeof(req.param), "%s", params[p]);

                uint8_t a[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
                size_t na = mvap_request_encode(&req, a, sizeof(a));
                if (na == 0) { all_identical = false; continue; }
                this_verb_encoded = true;
                cases++;

                struct mvap_request back;
                memset(&back, 0, sizeof(back));
                if (!mvap_request_decode(a + MVAP_FRAME_PREFIX,
                                         na - MVAP_FRAME_PREFIX, &back)) {
                    all_identical = false;
                    continue;
                }
                uint8_t b2[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
                size_t nb = mvap_request_encode(&back, b2, sizeof(b2));
                if (nb != na || memcmp(a, b2, na) != 0)
                    all_identical = false;
            }
        }
        if (!this_verb_encoded) covered_every_verb = false;
    }

    VC_CHECK("encode -> decode -> encode is byte-identical for every verb",
             all_identical && cases > 0);
    VC_CHECK("every defined verb is representable on the wire",
             covered_every_verb);

    /* The param bound is a bound, not a suggestion: one byte over must be
     * refused rather than silently clipped to a different request. */
    struct mvap_request over;
    memset(&over, 0, sizeof(over));
    over.verb = MVAP_VERB_INSPECT;
    /* Fill the whole field with no terminator: strnlen(param, MAX + 1) then
     * reports MAX + 1, which is exactly the "one byte over" the bound must
     * reject. Writing past the field to build the case would be the test
     * committing the overflow it is checking for. */
    memset(over.param, 'a', sizeof(over.param));
    uint8_t buf[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
    VC_CHECK("an over-long param is refused, never truncated",
             mvap_request_encode(&over, buf, sizeof(buf)) == 0);

    return failures;
}

/* ── C. one wire value per verb, and a gap is not a value ────────────────── */

static int check_wire_values_unique_and_gapless(void)
{
    int failures = 0;

    bool names_distinct = true, names_round_trip = true, names_named = true;
    for (uint32_t v = 1; v < (uint32_t)MVAP_VERB__COUNT; v++) {
        const char *n = mvap_verb_name(v);
        if (!n || !n[0] || strcmp(n, "unknown") == 0) names_named = false;
        if (n && mvap_verb_from_name(n) != v) names_round_trip = false;
        for (uint32_t w = 1; w < v; w++)
            if (n && strcmp(n, mvap_verb_name(w)) == 0) names_distinct = false;
    }
    VC_CHECK("every wire verb has a real name", names_named);
    VC_CHECK("no two wire verbs share a name", names_distinct);
    VC_CHECK("every verb name round-trips to its own value", names_round_trip);

    VC_CHECK("zero is not a verb",
             mvap_verb_from_name("NONE") == MVAP_VERB_NONE &&
             mvap_verb_from_name("") == MVAP_VERB_NONE &&
             mvap_verb_from_name(NULL) == MVAP_VERB_NONE);
    VC_CHECK("a value past the table names nothing",
             strcmp(mvap_verb_name((uint32_t)MVAP_VERB__COUNT),
                    "unknown") == 0 &&
             mvap_verb_from_name("unknown") == MVAP_VERB_NONE);

    /* A frame carrying an undefined verb or kind must be REFUSED. Reading it
     * as "some verb we do not have a name for yet" is how an unnamed right
     * gets executed. */
    struct mvap_request probe;
    memset(&probe, 0, sizeof(probe));
    probe.verb = MVAP_VERB_INSPECT;
    probe.kind = MVAP_KIND_CONTENT;
    probe.property_id[0] = 1;
    uint8_t frame[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
    size_t fn = mvap_request_encode(&probe, frame, sizeof(frame));
    bool built = (fn > MVAP_FRAME_PREFIX);

    if (built) {
        uint8_t bad[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
        struct mvap_request out;

        /* verb = one past the table */
        memcpy(bad, frame, fn);
        bad[MVAP_FRAME_PREFIX + 6] = (uint8_t)MVAP_VERB__COUNT;
        bad[MVAP_FRAME_PREFIX + 7] = 0;
        VC_CHECK("a frame with an undefined verb is refused",
                 !mvap_request_decode(bad + MVAP_FRAME_PREFIX,
                                      fn - MVAP_FRAME_PREFIX, &out));

        /* kind = one past the table */
        memcpy(bad, frame, fn);
        bad[MVAP_FRAME_PREFIX + 52] = (uint8_t)MVAP_KIND__COUNT;
        bad[MVAP_FRAME_PREFIX + 53] = 0;
        VC_CHECK("a frame with an undefined kind is refused",
                 !mvap_request_decode(bad + MVAP_FRAME_PREFIX,
                                      fn - MVAP_FRAME_PREFIX, &out));

        /* verb = 0 (the "unset" sentinel must never dispatch) */
        memcpy(bad, frame, fn);
        bad[MVAP_FRAME_PREFIX + 6] = 0;
        bad[MVAP_FRAME_PREFIX + 7] = 0;
        VC_CHECK("a frame with verb zero is refused",
                 !mvap_request_decode(bad + MVAP_FRAME_PREFIX,
                                      fn - MVAP_FRAME_PREFIX, &out));
    } else {
        VC_CHECK("could build a probe frame", false);
    }

    /* Kind names: unique, round-tripping, and no row reading as "unknown". */
    bool kind_names_ok = true;
    for (uint16_t k = 1; k < (uint16_t)MVAP_KIND__COUNT; k++) {
        const char *n = mvap_kind_name(k);
        if (!n || !n[0] || strcmp(n, "unknown") == 0) kind_names_ok = false;
        if (n && mvap_kind_from_name(n) != k) kind_names_ok = false;
        for (uint16_t j = 1; j < k; j++)
            if (n && strcmp(n, mvap_kind_name(j)) == 0) kind_names_ok = false;
    }
    VC_CHECK("every wire kind has one unique name that round-trips",
             kind_names_ok);

    return failures;
}

/* ── the counting node seam ──────────────────────────────────────────────
 *
 * The whole point of these ops: a status code proves what the broker SAID,
 * and these counters prove what it DID. A refusal that still called commit
 * has already mutated the world. */

struct seam_counts {
    unsigned plans;
    unsigned commits;
    uint16_t plan_kind;      /* the kind PLAN reports back */
    uint64_t revision;
    bool     found;
    bool     owner_matches;
};

static struct seam_counts g_seam;

static bool seam_plan(void *ctx, const struct mvap_request *req,
                      struct agent_plan *out)
{
    (void)ctx;
    if (!req || !out) return false;
    g_seam.plans++;
    memset(out, 0, sizeof(*out));
    out->found = g_seam.found;
    out->kind = g_seam.plan_kind;
    out->revision = g_seam.revision;
    out->owner_matches = g_seam.owner_matches;
    snprintf(out->detail, sizeof(out->detail), "counting-seam");
    return true;
}

static bool seam_commit(void *ctx, const struct mvap_request *req,
                        const struct agent_plan *plan,
                        struct agent_commit_outcome *out)
{
    (void)ctx; (void)plan;
    if (!req || !out) return false;
    g_seam.commits++;
    snprintf(out->body, sizeof(out->body), "{\"committed\":\"%s\"}",
             mvap_verb_name(req->verb));
    /* A seam that mints no canonical receipt leaves the id zero rather than
     * inventing one; the audit row then renders it as "none". */
    return true;
}

static struct agent_broker_node_ops seam_ops(void)
{
    return (struct agent_broker_node_ops){
        .plan = seam_plan, .commit = seam_commit, .ctx = NULL };
}

static void seam_reset(void)
{
    memset(&g_seam, 0, sizeof(g_seam));
    g_seam.plan_kind = MVAP_KIND_CONTENT;
    g_seam.revision = 5;
    g_seam.found = true;
    g_seam.owner_matches = true;
}

/* The property every broker check below is scoped to. */
static void scoped_property(uint8_t out[MVAP_PROPERTY_ID_LEN])
{
    for (size_t i = 0; i < MVAP_PROPERTY_ID_LEN; i++)
        out[i] = (uint8_t)(0xC0u + i);
}

/* A grant that allows every defined verb over one CONTENT property, with
 * room in both value ceilings. Checks narrow it from here; starting wide is
 * what makes each refusal attributable to the ONE thing the check changed. */
static void wide_grant(struct agent_grant *g)
{
    memset(g, 0, sizeof(*g));
    snprintf(g->grant_id, sizeof(g->grant_id), "vocabulary-gate-grant");
    snprintf(g->principal, sizeof(g->principal), "vocabulary-gate-agent");

    uint8_t prop[MVAP_PROPERTY_ID_LEN];
    scoped_property(prop);
    (void)agent_grant_add_property(g, prop);

    for (uint32_t v = 1; v < (uint32_t)MVAP_VERB__COUNT; v++)
        agent_grant_allow_action(g, v);
    for (uint16_t k = 0; k < (uint16_t)MVAP_KIND__COUNT; k++)
        agent_grant_allow_kind(g, k);

    g->max_value_zats = 1000;
    g->budget_zats    = 1000;
    g->may_delegate   = true;
    g->max_delegation_depth = 1;
}

/* A BROKER SESSION HOLDS NO GRANT, so a check that wants to narrow one right
 * and watch the refusal cannot assign into the session any more. It installs
 * the narrowed grant as the provider's LIVE authority and binds a session to
 * it, which is the same thing the shipped broker does and reaches the same
 * evaluator (agent_grant_authorize) by the same path.
 *
 * The reference is a file static because the session BORROWS it: a stack-local
 * would dangle the moment the checking function returned. */
static struct agent_authority_ref g_vc_authority;

static void vc_bind(struct agent_broker_session *s, const struct agent_grant *g)
{
    memset(s, 0, sizeof(*s));
    agent_broker_install_fixture_provider();
    agent_broker_fixture_set_grant(g);
    char why[192];
    (void)agent_broker_session_bind(s, &g_vc_authority, why, sizeof(why));
}

static void scoped_request(struct mvap_request *r, uint32_t verb,
                           uint64_t value, const char *param)
{
    memset(r, 0, sizeof(*r));
    r->verb = verb;
    r->request_id = verb * 17u + 1u;
    r->value_zats = value;
    scoped_property(r->property_id);
    r->kind = MVAP_KIND_ANY;
    snprintf(r->param, sizeof(r->param), "%s", param ? param : "");
}

/* ── D. queries are read-only ────────────────────────────────────────────── */

static int check_queries_are_read_only(struct agent_audit_log *audit)
{
    int failures = 0;

    /* The two query verbs, by their version-1 wire values. INSPECT_PROPERTY
     * and ENUMERATE_PROPERTIES are the canonical names; the values are the
     * compatibility contract. */
    const uint32_t queries[2] = { MVAP_VERB_INSPECT, MVAP_VERB_LIST };

    for (size_t i = 0; i < 2; i++) {
        uint32_t q = queries[i];
        char label[112];

        VC_CHECK((snprintf(label, sizeof(label),
                           "%s is classified as a read, not a mutation",
                           mvap_verb_name(q)), label),
                 !mvap_verb_is_mutation(q));

        /* 1. A query must never reach COMMIT. Counted at the seam. */
        struct agent_broker_session s;
        struct agent_grant gr;
        wide_grant(&gr);
        vc_bind(&s, &gr);
        s.ops = seam_ops();
        s.audit = audit;
        seam_reset();

        struct mvap_request req;
        scoped_request(&req, q, 0, "");
        if (q == MVAP_VERB_LIST)
            memset(req.property_id, 0, sizeof(req.property_id));

        struct mvap_response resp;
        memset(&resp, 0, sizeof(resp));
        uint64_t receipts_before = s.receipts_written;
        agent_broker_handle(&s, &req, &resp);

        VC_CHECK((snprintf(label, sizeof(label),
                           "%s is served without reaching commit",
                           mvap_verb_name(q)), label),
                 resp.status == MVAP_OK && g_seam.commits == 0);

        /* 2. A query mints NO receipt: the response carries an all-zero
         *    receipt id and the audit log grew no receipt row for it. */
        bool receipt_zero = mvap_property_id_is_zero(resp.receipt_id);
        VC_CHECK((snprintf(label, sizeof(label),
                           "%s mints no receipt", mvap_verb_name(q)), label),
                 receipt_zero && s.receipts_written == receipts_before);

        /* 3. A query cannot carry value. It must be refused BEFORE the seam,
         *    and the refusal must not debit the grant. */
        seam_reset();
        struct agent_grant before;
        agent_broker_fixture_get_grant(&before);
        struct mvap_request valued;
        scoped_request(&valued, q, 500, "");
        if (q == MVAP_VERB_LIST)
            memset(valued.property_id, 0, sizeof(valued.property_id));
        valued.request_id = 900u + (uint32_t)i;

        int32_t verdict = agent_grant_authorize(&gr, &valued,
                                                (int64_t)1);
        VC_CHECK((snprintf(label, sizeof(label),
                           "%s carrying value is refused by the evaluator",
                           mvap_verb_name(q)), label),
                 verdict == MVAP_ERR_BAD_REQUEST);

        struct mvap_response vresp;
        memset(&vresp, 0, sizeof(vresp));
        agent_broker_handle(&s, &valued, &vresp);
        VC_CHECK((snprintf(label, sizeof(label),
                           "%s carrying value never reaches the node seam",
                           mvap_verb_name(q)), label),
                 vresp.status != MVAP_OK && g_seam.plans == 0 &&
                 g_seam.commits == 0);
        /* Read the LIVE authority back, which is where a debit would have
         * landed — the session has no copy that could report otherwise. */
        struct agent_grant after;
        agent_broker_fixture_get_grant(&after);
        VC_CHECK((snprintf(label, sizeof(label),
                           "%s carrying value debits nothing",
                           mvap_verb_name(q)), label),
                 after.spent_zats == before.spent_zats &&
                 after.window_used == before.window_used);
    }

    /* A query must never be the verb that names a counterparty or a title
     * change: the enumeration read cannot be handed a counterparty and then
     * be treated as a sale. Proven through the evaluator, which is the only
     * place that could conflate them. */
    struct agent_grant g;
    wide_grant(&g);
    snprintf(g.counterparty_allowlist, sizeof(g.counterparty_allowlist),
             "only-this-buyer");
    struct mvap_request cp;
    scoped_request(&cp, MVAP_VERB_INSPECT, 0, "some-other-party");
    VC_CHECK("a read is not counterparty-scoped (it names no counterparty)",
             agent_grant_authorize(&g, &cp, 1) == MVAP_OK);

    return failures;
}

/* ── E. LIST is the read; LIST_FOR_SALE is the mutation ──────────────────── */

static int check_list_for_sale_is_a_mutation(struct agent_audit_log *audit)
{
    int failures = 0;

    /* The contradiction this whole workflow exists to delete: one identifier
     * that meant "enumerate" on one side of the socket and "advertise for
     * sale" on the other. On the wire, value 2 is the READ. */
    VC_CHECK("wire value 2 is the enumeration read, not the sale listing",
             !mvap_verb_is_mutation(MVAP_VERB_LIST) &&
             mvap_verb_from_name("LIST") == MVAP_VERB_LIST);

    /* LIST_FOR_SALE is appended at a NEW wire value and the version is
     * bumped (contract §2). Once the protocol declares version 2, the verb
     * must be present, must be a mutation, and must not have displaced the
     * enumeration read. This arms itself off MVAP_VERSION so it cannot coast
     * unnoticed. */
    uint32_t lfs = mvap_verb_from_name("LIST_FOR_SALE");
    if (MVAP_VERSION >= 2u) {
        VC_CHECK("version 2 carries LIST_FOR_SALE at an appended wire value",
                 lfs != MVAP_VERB_NONE && lfs >= 14u);
        VC_CHECK("LIST_FOR_SALE is a mutation", mvap_verb_is_mutation(lfs));
        VC_CHECK("LIST_FOR_SALE did not displace the enumeration read",
                 lfs != MVAP_VERB_LIST && !mvap_verb_is_mutation(MVAP_VERB_LIST));

        /* And it behaves like one: through the real broker it reaches
         * COMMIT and mints a receipt. */
        struct agent_broker_session s;
        struct agent_grant gr;
        wide_grant(&gr);
        vc_bind(&s, &gr);
        s.ops = seam_ops();
        s.audit = audit;
        seam_reset();

        struct mvap_request req;
        scoped_request(&req, lfs, 0, "");
        struct mvap_response resp;
        memset(&resp, 0, sizeof(resp));
        agent_broker_handle(&s, &req, &resp);

        VC_CHECK("LIST_FOR_SALE reaches commit and mints a receipt",
                 resp.status == MVAP_OK && g_seam.commits == 1 &&
                 !mvap_property_id_is_zero(resp.receipt_id));
    } else {
        printf("vocabulary: PENDING — the broker still speaks version %u, so "
               "LIST_FOR_SALE has no wire value yet; the mutation checks for "
               "it arm automatically at MVAP_VERSION >= 2\n",
               (unsigned)MVAP_VERSION);
        VC_CHECK("version 1 has not smuggled in a LIST_FOR_SALE value",
                 lfs == MVAP_VERB_NONE);
    }

    /* SELL only ever transfers for value; it must never be the thing that
     * sets a for-sale flag. That conflation lived in the broker fixture, and
     * this states the rule the replacement must keep. */
    VC_CHECK("SELL and the listing verb are different operations",
             MVAP_VERB_SELL != lfs && MVAP_VERB_SELL != MVAP_VERB_LIST);

    return failures;
}

/* ── F. HOST changes local state, and only local state ───────────────────── */

static int check_host_is_local_state(struct agent_audit_log *audit)
{
    int failures = 0;

    VC_CHECK("HOST is an action, not a query",
             mvap_verb_is_mutation(MVAP_VERB_HOST));

    /* Because it changes LOCAL state it must go through the seam. A
     * "unification" that reclassified HOST as a read to match the metaverse
     * external-state mask would silently stop it committing anything. */
    struct agent_broker_session s;
    struct agent_grant gr;
    wide_grant(&gr);
    vc_bind(&s, &gr);
    s.ops = seam_ops();
    s.audit = audit;
    seam_reset();

    struct mvap_request req;
    scoped_request(&req, MVAP_VERB_HOST, 0, "");
    struct mvap_response resp;
    memset(&resp, 0, sizeof(resp));
    agent_broker_handle(&s, &req, &resp);

    VC_CHECK("HOST reaches commit",
             resp.status == MVAP_OK && g_seam.plans == 1 &&
             g_seam.commits == 1);
    VC_CHECK("HOST mints a receipt",
             !mvap_property_id_is_zero(resp.receipt_id));

    /* And it carries no value: hosting is not a payment. */
    struct mvap_request valued;
    scoped_request(&valued, MVAP_VERB_HOST, 250, "");
    VC_CHECK("HOST carries no value",
             agent_grant_authorize(&gr, &valued, 1) ==
                 MVAP_ERR_BAD_REQUEST);

    return failures;
}

/* ── G. TRANSFER moves value on BOTH sides of the socket ─────────────────── */

static void metaverse_grant_for_transfer(struct metaverse_grant *g,
                                         int64_t budget)
{
    memset(g, 0, sizeof(*g));
    snprintf(g->grant_id, sizeof(g->grant_id),
             "0123456789abcdef0123456789abcdef");
    snprintf(g->holder, sizeof(g->holder), "t1VocabularyGateHolder000000000000");
    snprintf(g->issuer, sizeof(g->issuer), "t1VocabularyGateIssuer000000000000");
    g->scope_form = METAVERSE_SCOPE_KINDS;
    g->kinds = metaverse_kind_bit(METAVERSE_KIND_CONTENT);
    g->actions = metaverse_action_bit(METAVERSE_ACTION_TRANSFER) |
                 metaverse_action_bit(METAVERSE_ACTION_HOST);
    g->max_value_zat = budget;
    g->spent_zat = 0;
}

static void metaverse_request_for_transfer(struct metaverse_action_request *r,
                                           const struct metaverse_grant *g,
                                           enum metaverse_action a,
                                           int64_t value)
{
    memset(r, 0, sizeof(*r));
    snprintf(r->actor, sizeof(r->actor), "%s", g->holder);
    r->property.kind = METAVERSE_KIND_CONTENT;
    for (size_t i = 0; i < METAVERSE_ROOT_BYTES; i++)
        r->property.root[i] = (uint8_t)(0xC0u + i);
    r->action = a;
    r->value_zat = value;
    r->now_unix = 1700000000;
    r->height = 900000;
}

static int check_transfer_moves_value_everywhere(void)
{
    int failures = 0;

    /* (1) THE CANONICAL RULE. Contract §4: TRANSFER moves value and debits
     *     the cumulative budget. The metaverse side is the correct one. */
    bool canonical_moves_value =
        metaverse_action_moves_value(METAVERSE_ACTION_TRANSFER);
    VC_CHECK("canonically, TRANSFER moves value", canonical_moves_value);

    /* (2) THE GRANT ENGINE agrees: a valued TRANSFER inside the budget is
     *     allowed, one over it is BUDGET_EXCEEDED (not "free"). */
    struct metaverse_grant mg;
    struct metaverse_action_request mreq;

    metaverse_grant_for_transfer(&mg, 1000);
    VC_CHECK("the grant record used here is well formed",
             metaverse_grant_well_formed(&mg));

    metaverse_request_for_transfer(&mreq, &mg, METAVERSE_ACTION_TRANSFER, 500);
    VC_CHECK("the grant engine allows a valued TRANSFER inside the budget",
             metaverse_grant_check(&mg, NULL, 0, &mreq) == METAVERSE_GRANT_OK);

    metaverse_request_for_transfer(&mreq, &mg, METAVERSE_ACTION_TRANSFER, 1500);
    VC_CHECK("the grant engine charges TRANSFER against the budget",
             metaverse_grant_check(&mg, NULL, 0, &mreq) ==
                 METAVERSE_GRANT_BUDGET_EXCEEDED);

    metaverse_request_for_transfer(&mreq, &mg, METAVERSE_ACTION_TRANSFER, 500);
    VC_CHECK("a committed TRANSFER debits the cumulative budget",
             metaverse_grant_record_commit(&mg, &mreq) && mg.spent_zat == 500);

    /* A free action carrying value is malformed, never a free pass — the
     * control that proves the rule above discriminates. */
    struct metaverse_grant hg;
    metaverse_grant_for_transfer(&hg, 1000);
    metaverse_request_for_transfer(&mreq, &hg, METAVERSE_ACTION_HOST, 500);
    VC_CHECK("the grant engine rejects value on a free action",
             metaverse_grant_check(&hg, NULL, 0, &mreq) ==
                 METAVERSE_GRANT_VALUE_ON_FREE_ACTION);

    /* (3) THE BROKER TRANSLATION must give the SAME answer. This is the
     *     divergence: the broker's value predicate omitted TRANSFER, so a
     *     valued TRANSFER came back BAD_REQUEST — meaning a TRANSFER through
     *     the broker was only ever expressible with value 0, i.e. free of
     *     the cumulative budget the operator wrote down. */
    struct agent_grant bg;
    wide_grant(&bg);
    struct mvap_request breq;
    scoped_request(&breq, MVAP_VERB_TRANSFER, 500, "some-counterparty");
    int32_t verdict = agent_grant_authorize(&bg, &breq, 1);

    VC_CHECK("the broker admits a valued TRANSFER inside both ceilings",
             verdict == MVAP_OK);
    VC_CHECK("TRANSFER's value classification AGREES across the boundary",
             canonical_moves_value == (verdict == MVAP_OK));

    /* Over the cumulative budget the broker must say BUDGET, matching the
     * grant engine's BUDGET_EXCEEDED. Saying BAD_REQUEST instead reports a
     * malformed request for an action that is merely too expensive. */
    struct agent_grant bg2;
    wide_grant(&bg2);
    bg2.max_value_zats = 10000;
    bg2.budget_zats    = 100;
    struct mvap_request breq2;
    scoped_request(&breq2, MVAP_VERB_TRANSFER, 500, "some-counterparty");
    VC_CHECK("the broker charges TRANSFER against the cumulative budget",
             agent_grant_authorize(&bg2, &breq2, 1) == MVAP_ERR_DENIED_BUDGET);

    /* And a committed TRANSFER actually debits it, so the budget is spent
     * rather than merely checked. */
    struct agent_grant bg3;
    wide_grant(&bg3);
    struct mvap_request breq3;
    scoped_request(&breq3, MVAP_VERB_TRANSFER, 500, "some-counterparty");
    agent_grant_commit_debit(&bg3, &breq3, 1);
    VC_CHECK("a committed TRANSFER debits the broker's budget",
             bg3.spent_zats == 500);

    /* The whole value column, checked for agreement rather than one row: for
     * every verb that has a metaverse counterpart, "may carry value" must be
     * the same answer on both sides. One row disagreeing is what this
     * workflow is deleting; the loop is what stops the next one appearing. */
    struct {
        uint32_t verb;
        enum metaverse_action action;
        const char *what;
    } pairs[] = {
        { MVAP_VERB_BUY,            METAVERSE_ACTION_BUY,            "BUY" },
        { MVAP_VERB_SELL,           METAVERSE_ACTION_SELL,           "SELL" },
        { MVAP_VERB_LEASE,          METAVERSE_ACTION_LEASE,          "LEASE" },
        { MVAP_VERB_TRANSFER,       METAVERSE_ACTION_TRANSFER,       "TRANSFER" },
        { MVAP_VERB_ACCEPT_PAYMENT, METAVERSE_ACTION_ACCEPT_PAYMENT, "ACCEPT_PAYMENT" },
        { MVAP_VERB_HOST,           METAVERSE_ACTION_HOST,           "HOST" },
        { MVAP_VERB_PUBLISH_REVISION, METAVERSE_ACTION_PUBLISH_REVISION, "PUBLISH_REVISION" },
        { MVAP_VERB_UPDATE_POINTER, METAVERSE_ACTION_UPDATE_POINTER, "UPDATE_POINTER" },
        { MVAP_VERB_DELIVER,        METAVERSE_ACTION_DELIVER,        "DELIVER" },
        { MVAP_VERB_DELEGATE,       METAVERSE_ACTION_DELEGATE,       "DELEGATE" },
        { MVAP_VERB_REVOKE,         METAVERSE_ACTION_REVOKE,         "REVOKE" },
    };
    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        struct agent_grant g;
        wide_grant(&g);
        struct mvap_request r;
        scoped_request(&r, pairs[i].verb, 500, "");
        if (pairs[i].verb == MVAP_VERB_REVOKE)
            memset(r.property_id, 0, sizeof(r.property_id));

        int32_t v = agent_grant_authorize(&g, &r, 1);
        bool broker_takes_value = (v != MVAP_ERR_BAD_REQUEST);
        bool canonical_takes_value =
            metaverse_action_moves_value(pairs[i].action);

        char label[128];
        snprintf(label, sizeof(label),
                 "%s: both sides agree whether it may carry value",
                 pairs[i].what);
        VC_CHECK(label, broker_takes_value == canonical_takes_value);
    }

    return failures;
}

/* ── H. no request may skip the grant evaluator ──────────────────────────── */

static int check_no_bypass_of_the_evaluator(struct agent_audit_log *audit)
{
    int failures = 0;

    struct { const char *what; int32_t want; } cases[] = {
        { "an empty grant",             MVAP_ERR_DENIED_NO_GRANT },
        { "a revoked grant",            MVAP_ERR_DENIED_REVOKED },
        { "an expired grant",           MVAP_ERR_DENIED_EXPIRED },
        { "a verb outside the mask",    MVAP_ERR_DENIED_ACTION },
        { "a property outside scope",   MVAP_ERR_DENIED_PROPERTY },
        { "a kind outside scope",       MVAP_ERR_DENIED_KIND },
        { "a value over the ceiling",   MVAP_ERR_DENIED_VALUE },
        { "a counterparty off the list", MVAP_ERR_DENIED_COUNTERPARTY },
        { "delegation not permitted",   MVAP_ERR_DENIED_DELEGATION },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct agent_broker_session s;
        struct agent_grant gr;
        wide_grant(&gr);
        vc_bind(&s, &gr);
        s.ops = seam_ops();
        s.audit = audit;
        seam_reset();

        struct mvap_request req;
        scoped_request(&req, MVAP_VERB_PUBLISH_REVISION, 0, "");
        req.request_id = 4000u + (uint32_t)i;

        /* Each case narrows the LIVE authority, not a session copy — the
         * session is already bound above and holds no grant to narrow. The
         * re-install after the switch is what a running session sees. */
        switch (i) {
        case 0: memset(gr.grant_id, 0, sizeof(gr.grant_id)); break;
        case 1: gr.revoked = true; break;
        case 2: gr.expires_unix_ms = 10; break;
        /* actions_mask is the CANONICAL metaverse_action_set, not a wire-keyed
         * one, so the bit to clear is the canonical bit. Shifting by the wire
         * value would clear a different action entirely (wire 4 would land on
         * LIST_FOR_SALE's 0x10) and the verb under test would stay granted. */
        case 3: gr.actions_mask &=
                    ~(uint32_t)METAVERSE_ACTION_PUBLISH_REVISION; break;
        case 4: req.property_id[0] ^= 0xFFu; break;
        case 5: gr.kinds_mask = 0;
                req.kind = MVAP_KIND_ZCODE; break;
        /* The PER-ACTION ceiling, isolated. wide_grant() sets both ceilings to
         * 1000, so a 5000 request breaks the cumulative budget too and the
         * canonical evaluator — which runs first, by design — answers
         * DENIED_BUDGET. That is a true answer to a different question. Lift
         * the cumulative budget clear of the request so the only limit left to
         * violate is max_value_zats, and this case tests the ceiling it
         * names. DENIED_BUDGET has its own case above. */
        case 6: scoped_request(&req, MVAP_VERB_BUY, 5000, "");
                gr.budget_zats = 1000000;
                req.request_id = 4006u; break;
        case 7: scoped_request(&req, MVAP_VERB_BUY, 100, "not-on-the-list");
                snprintf(gr.counterparty_allowlist,
                         sizeof(gr.counterparty_allowlist),
                         "only-this-buyer");
                req.request_id = 4007u; break;
        case 8: scoped_request(&req, MVAP_VERB_DELEGATE, 0, "");
                gr.may_delegate = false;
                req.request_id = 4008u; break;
        default: break;
        }
        agent_broker_fixture_set_grant(&gr);

        struct mvap_response resp;
        memset(&resp, 0, sizeof(resp));
        agent_broker_handle(&s, &req, &resp);

        char label[128];
        snprintf(label, sizeof(label), "%s is refused with its own reason",
                 cases[i].what);
        VC_CHECK(label, resp.status == cases[i].want);

        snprintf(label, sizeof(label),
                 "%s never reaches the node seam", cases[i].what);
        VC_CHECK(label, g_seam.plans == 0 && g_seam.commits == 0);
    }

    /* The bypass an agent would actually attempt: understate the kind so the
     * pre-plan mask check passes, then let PLAN reveal the real kind. The
     * re-check must catch it and COMMIT must never run. */
    {
        struct agent_broker_session s;
        struct agent_grant gr;
        wide_grant(&gr);
        gr.kinds_mask = 0;
        agent_grant_allow_kind(&gr, MVAP_KIND_ANY);
        agent_grant_allow_kind(&gr, MVAP_KIND_CONTENT);
        vc_bind(&s, &gr);
        s.ops = seam_ops();
        s.audit = audit;
        seam_reset();
        g_seam.plan_kind = MVAP_KIND_ZCODE;   /* the catalog's real answer */

        struct mvap_request req;
        scoped_request(&req, MVAP_VERB_PUBLISH_REVISION, 0, "");
        req.kind = MVAP_KIND_ANY;             /* the agent's understatement */
        req.request_id = 4100u;

        struct mvap_response resp;
        memset(&resp, 0, sizeof(resp));
        agent_broker_handle(&s, &req, &resp);

        VC_CHECK("a request understating its kind dies at the post-plan recheck",
                 resp.status == MVAP_ERR_DENIED_KIND);
        VC_CHECK("the understated request planned but never committed",
                 g_seam.plans == 1 && g_seam.commits == 0);
    }

    /* An undefined verb must be refused before anything is dispatched, and
     * the wire must not have been able to carry it in the first place. */
    {
        struct agent_broker_session s;
        struct agent_grant gr;
        wide_grant(&gr);
        vc_bind(&s, &gr);
        s.ops = seam_ops();
        s.audit = audit;
        seam_reset();

        struct mvap_request req;
        scoped_request(&req, (uint32_t)MVAP_VERB__COUNT, 0, "");
        req.request_id = 4200u;
        struct mvap_response resp;
        memset(&resp, 0, sizeof(resp));
        agent_broker_handle(&s, &req, &resp);

        VC_CHECK("an undefined verb is refused before the seam",
                 resp.status == MVAP_ERR_UNKNOWN_VERB && g_seam.plans == 0 &&
                 g_seam.commits == 0);
    }

    /* And the mask arithmetic itself: allowing verb N must not allow verb M.
     * A shared or shifted bit here would hand out a right nobody granted. */
    {
        /* A grant holds TWO sets: actions_mask is the canonical
         * metaverse_action_set, queries_mask is keyed by wire value. Granting
         * one wire verb must light exactly one bit in exactly one of them and
         * nothing in the other — a shared or shifted bit would hand out a
         * right nobody granted, and folding the two sets into one word would
         * make "may read" and "may act" the same right. */
        bool one_verb_one_bit = true;
        for (uint32_t v = 1; v < (uint32_t)MVAP_VERB__COUNT; v++) {
            struct agent_grant g;
            memset(&g, 0, sizeof(g));
            snprintf(g.grant_id, sizeof(g.grant_id), "single-verb");
            agent_grant_allow_action(&g, v);

            bool v_is_query = mvap_verb_is_query(v);
            for (uint32_t w = 1; w < (uint32_t)MVAP_VERB__COUNT; w++) {
                bool want = (w == v);
                if (mvap_verb_is_query(w)) {
                    bool allowed =
                        (g.queries_mask & ((uint32_t)1u << w)) != 0;
                    if (allowed != want) one_verb_one_bit = false;
                } else {
                    enum metaverse_action a;
                    bool allowed =
                        mvap_verb_to_action(w, &a) &&
                        (g.actions_mask & (uint32_t)a) != 0;
                    if (allowed != want) one_verb_one_bit = false;
                }
            }
            /* And the set it does NOT belong in stays completely empty. */
            if (v_is_query ? (g.actions_mask != 0u) : (g.queries_mask != 0u))
                one_verb_one_bit = false;
        }
        VC_CHECK("granting one verb grants exactly that verb",
                 one_verb_one_bit);
        struct agent_grant none;
        memset(&none, 0, sizeof(none));
        agent_grant_allow_action(&none, MVAP_VERB_NONE);
        agent_grant_allow_action(&none, (uint32_t)MVAP_VERB__COUNT);
        VC_CHECK("no out-of-range verb can be granted", none.actions_mask == 0);
    }

    return failures;
}

/* ── I. the receipt id binds the response to the audit chain ─────────────── */

static int check_receipt_binds_response_to_audit(const char *dir)
{
    int failures = 0;

    struct agent_audit_log audit;
    memset(&audit, 0, sizeof(audit));
    if (!agent_audit_open(&audit, dir)) {
        VC_CHECK("the audit log opens in an isolated directory", false);
        return failures;
    }

    struct agent_broker_session s;
    struct agent_grant gr;
    wide_grant(&gr);
    vc_bind(&s, &gr);
    s.ops = seam_ops();
    s.audit = &audit;
    seam_reset();

    /* A successful query: no receipt at all. */
    struct mvap_request q;
    scoped_request(&q, MVAP_VERB_INSPECT, 0, "");
    q.request_id = 7001u;
    struct mvap_response qr;
    memset(&qr, 0, sizeof(qr));
    agent_broker_handle(&s, &q, &qr);
    VC_CHECK("a served query writes no receipt",
             qr.status == MVAP_OK && s.receipts_written == 0 &&
             mvap_property_id_is_zero(qr.receipt_id));

    /* A mutation: a real receipt id, and it is the audit row's id. */
    struct mvap_request m;
    scoped_request(&m, MVAP_VERB_PUBLISH_REVISION, 0, "");
    m.request_id = 7002u;
    struct mvap_response mr;
    memset(&mr, 0, sizeof(mr));
    agent_broker_handle(&s, &m, &mr);

    VC_CHECK("a mutation returns a non-zero receipt id",
             mr.status == MVAP_OK && s.receipts_written == 1 &&
             !mvap_property_id_is_zero(mr.receipt_id));

    char hex[65];
    for (size_t i = 0; i < MVAP_RECEIPT_ID_LEN; i++)
        snprintf(hex + i * 2, 3, "%02x", mr.receipt_id[i]);

    char doc[16384];
    size_t n = agent_audit_render_json(dir, 16, doc, sizeof(doc));
    VC_CHECK("the response receipt id is the id of an audit row",
             n > 0 && strstr(doc, hex) != NULL);

    struct agent_audit_verdict v;
    memset(&v, 0, sizeof(v));
    VC_CHECK("the audit chain verifies end to end",
             agent_audit_verify_dir(dir, &v) && v.ok && v.rows >= 1 &&
             v.chain_breaks == 0 && v.bad_signatures == 0);

    /* A replay of the same request_id must return the SAME receipt, not mint
     * a second one — otherwise a retried action is two actions in the log. */
    struct mvap_response again;
    memset(&again, 0, sizeof(again));
    agent_broker_handle(&s, &m, &again);
    VC_CHECK("a replayed request returns the same receipt and mints no second",
             s.receipts_written == 1 &&
             memcmp(again.receipt_id, mr.receipt_id,
                    MVAP_RECEIPT_ID_LEN) == 0);

    return failures;
}

/* ── J. the shipped broker mode must not be serving a fixture ────────────── */

/* The fixture catalog's property ids are SHA3 over a fixed domain tag, so no
 * authoritative model can ever mint one. A production broker that resolves
 * one is answering out of a test double. */
static int check_production_broker_has_no_fixture(void)
{
    int failures = 0;

    char dir[64];
    snprintf(dir, sizeof(dir), "/tmp/zclmvv%d", (int)getpid());
    test_rm_rf_recursive(dir);

    char sockpath[96];
    snprintf(sockpath, sizeof(sockpath), "%s/agent.sock", dir);

    char a0[] = "zclassic23";
    char a1[] = "--metaverse-broker";
    char a2[96];
    char a3[] = "--listen";
    snprintf(a2, sizeof(a2), "--broker-dir=%s", dir);
    char *argv[] = { a0, a1, a2, a3, NULL };

    (void)fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        VC_CHECK("could fork the shipped broker mode", false);
        return failures;
    }
    if (pid == 0) {
        int rc = agent_broker_mode_main(4, argv);
        _exit(rc == 0 ? 0 : 1);
    }

    /* Wait for the listening socket, bounded. */
    bool up = false;
    for (int i = 0; i < 300 && !up; i++) {
        struct stat st;
        if (stat(sockpath, &st) == 0) up = true;
        else { struct timespec ts = { 0, 20 * 1000 * 1000 }; nanosleep(&ts, NULL); }
    }
    VC_CHECK("the shipped broker mode came up on its own socket", up);

    struct mvap_response resp;
    memset(&resp, 0, sizeof(resp));
    bool answered = false;

    if (up) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un sa;
        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", sockpath);
        if (fd >= 0 && connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
            struct mvap_request req;
            memset(&req, 0, sizeof(req));
            req.verb = MVAP_VERB_INSPECT;
            req.request_id = 1;
            req.kind = MVAP_KIND_ANY;
            agent_broker_fixture_property_id(0, req.property_id);

            uint8_t frame[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
            size_t n = mvap_request_encode(&req, frame, sizeof(frame));
            if (n > 0 && write(fd, frame, n) == (ssize_t)n) {
                struct pollfd p = { .fd = fd, .events = POLLIN };
                uint8_t in[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
                if (poll(&p, 1, 5000) > 0) {
                    ssize_t got = read(fd, in, sizeof(in));
                    if (got > (ssize_t)MVAP_FRAME_PREFIX) {
                        uint32_t rec = mvap_frame_length(in, (size_t)got);
                        if (rec > 0 &&
                            (size_t)got >= (size_t)MVAP_FRAME_PREFIX + rec)
                            answered = mvap_response_decode(
                                in + MVAP_FRAME_PREFIX, rec, &resp);
                    }
                }
            }
        }
        if (fd >= 0) (void)close(fd);
    }

    VC_CHECK("the shipped broker answered the probe", answered);

    /* THE CLAIM: a production broker cannot resolve a fixture property. */
    if (answered)
        VC_CHECK("the shipped broker mode serves no fixture catalog",
                 resp.status != MVAP_OK);

    /* Reap, bounded — never leave a broker behind on a test host. */
    for (int i = 0; i < 300; i++) {
        int st = 0;
        pid_t r = waitpid(pid, &st, WNOHANG);
        if (r == pid) { pid = -1; break; }
        struct timespec ts = { 0, 20 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    if (pid > 0) {
        (void)kill(pid, SIGKILL);
        int st = 0;
        (void)waitpid(pid, &st, 0);
    }
    test_rm_rf_recursive(dir);

    return failures;
}

/* ── the unified-header regression guard ─────────────────────────────────
 *
 * At base commit metaverse/property_action.h and metaverse/property_grant.h
 * define the SAME identifiers with different values, and no translation unit
 * includes both. That is not a coincidence to be preserved — it is the
 * defect. Once the vocabulary is one declaration, a TU including both must
 * compile, and this file becomes that TU.
 *
 * This is the one check that cannot be live before the unification lands:
 * including both headers today is a hard redefinition error, which would
 * take the whole build down and with it every other check above. It arms
 * itself off METAVERSE_VOCABULARY_UNIFIED, which the canonical header
 * defines. */
static int check_headers_unified(void)
{
    int failures = 0;
#if METAVERSE_VOCABULARY_UNIFIED
    /* Both spellings now resolve in ONE translation unit and agree. */
    VC_CHECK("the two metaverse headers share one action vocabulary",
             (uint32_t)METAVERSE_ACTION_TRANSFER == 0x00000200u);
    /* 13 was the OLD single-vocabulary count, with INSPECT counted as an
     * action. The split is 12 actions + 2 queries = 14 operations; the guard
     * armed and caught this assertion still holding the pre-split number,
     * which is what it was built to do. */
    VC_CHECK("the action count is one number, not two",
             (int)METAVERSE_ACTION_COUNT == 12);
    VC_CHECK("queries are a second closed set, counted separately",
             (int)METAVERSE_QUERY_COUNT == 2);
    VC_CHECK("the two sets together are the 14 operations of the contract",
             (int)METAVERSE_ACTION_COUNT + (int)METAVERSE_QUERY_COUNT == 14);
    /* The grant record carries both, in two fields. One field would make
     * "may read" and "may act" the same right. */
    VC_CHECK("a grant carries actions and queries in separate fields",
             sizeof(((struct metaverse_grant *)0)->actions) == 4u &&
             sizeof(((struct metaverse_grant *)0)->queries) == 4u &&
             offsetof(struct metaverse_grant, actions) !=
                 offsetof(struct metaverse_grant, queries));
#else
    printf("vocabulary: PENDING — metaverse/property_action.h and "
           "metaverse/property_grant.h still declare separate action "
           "vocabularies, so no translation unit may include both. This "
           "check arms itself when the canonical header defines "
           "METAVERSE_VOCABULARY_UNIFIED.\n");
#endif
    return failures;
}

int test_metaverse_vocabulary(void)
{
    printf("\n=== metaverse_vocabulary ===\n");

    /* Hermetic datadir for the whole run. Nothing in this group should reach
     * a datadir at all; pinning it is what proves that rather than assuming
     * it, and it is what stops a check being answered by the operator's live
     * node. */
    char dd[256];
    test_make_tmpdir(dd, sizeof dd, "metaverse_vocabulary", "datadir");
    SetDataDir(dd);

    char audit_dir[256];
    test_make_tmpdir(audit_dir, sizeof audit_dir, "metaverse_vocabulary",
                     "audit");

    struct agent_audit_log audit;
    memset(&audit, 0, sizeof(audit));
    bool have_audit = agent_audit_open(&audit, audit_dir);

    int failures = 0;

    failures += mvv_action_bit_checks();
    failures += check_golden_v1_frames();
    failures += check_round_trip_is_byte_identical();
    failures += check_wire_values_unique_and_gapless();
    failures += check_queries_are_read_only(have_audit ? &audit : NULL);
    failures += check_list_for_sale_is_a_mutation(have_audit ? &audit : NULL);
    failures += check_host_is_local_state(have_audit ? &audit : NULL);
    failures += check_transfer_moves_value_everywhere();
    failures += check_no_bypass_of_the_evaluator(have_audit ? &audit : NULL);

    char bind_dir[256];
    test_make_tmpdir(bind_dir, sizeof bind_dir, "metaverse_vocabulary",
                     "receipts");
    failures += check_receipt_binds_response_to_audit(bind_dir);

    /* Un-register the fixture provider the checks above bound their sessions
     * to. The next check FORKS and runs the shipped broker mode, and a forked
     * child inherits whatever this process has installed — leaving the fixture
     * registered would have the child serving a fixture catalog for a reason
     * that has nothing to do with the shipped code. */
    agent_broker_provider_install(NULL);

    failures += check_production_broker_has_no_fixture();
    failures += check_headers_unified();

    (void)test_rm_rf_recursive(bind_dir);
    (void)test_rm_rf_recursive(audit_dir);
    (void)test_rm_rf_recursive(dd);
    SetDataDir("");
    ClearDataDirCache();

    printf("=== metaverse_vocabulary: %d failure(s) ===\n", failures);
    return failures;
}
