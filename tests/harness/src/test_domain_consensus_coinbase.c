/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/coinbase.{c,h}.
 *
 * These tests pin the pure coinbase-transaction-shaping primitives.
 * They are independent of the mempool/chain orchestration that lives
 * in core/modules/mining/src/miner.c::create_new_block. The regression seal
 * directly compares the shape produced by the domain function with the
 * byte-identical legacy construction copied into this file as a
 * reference implementation — if either side drifts the test shouts.
 */

#include "test/test_core.h"

#include "domain/consensus/coinbase.h"

#include "chain/chainparams.h"
#include "chain/subsidy.h"
#include "consensus/params.h"
#include "consensus/upgrades.h"
#include "core/amount.h"
#include "primitives/transaction.h"
#include "script/script.h"

#include <stdio.h>
#include <string.h>

#define DCC_CHECK(name, expr) do { \
    printf("domain_consensus_coinbase: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* --- zclassicd reference: the exact bytes `CScript() << nHeight << …`
 * produces — CScript::push_int64 for the height (OP_N for 1..16, else a
 * minimal CScriptNum data push) and a CScriptNum data push for the extra
 * nonce. This is the consensus encoding zclassicd's CreateNewBlock writes
 * (src/miner.cpp) and its ContextualCheckBlock BIP34 check verifies
 * (`CScript expect = CScript() << nHeight`, src/main.cpp). The seal pins
 * our builder to byte parity with it. A SECOND, implementation-independent
 * seal below asserts hand-computed golden bytes for the boundary heights,
 * so a shared conceptual error in both this reference and the builder is
 * still caught. ------------------------------------------------------- */
static size_t zcd_scriptnum_vch(uint32_t value, uint8_t buf[5])
{
    size_t n = 0;
    uint32_t v = value;
    while (v) { buf[n++] = (uint8_t)(v & 0xff); v >>= 8; }
    if (n > 0 && (buf[n - 1] & 0x80)) buf[n++] = 0x00; /* positive sign byte */
    return n;
}

/* `CScript() << n` for n >= 0 (CScript::push_int64). */
static size_t zcd_push_int64(uint8_t *p, int n)
{
    if (n == 0) { p[0] = (uint8_t)OP_0; return 1; }
    if (n >= 1 && n <= 16) { p[0] = (uint8_t)(0x50 + n); return 1; }
    uint8_t buf[5];
    size_t len = zcd_scriptnum_vch((uint32_t)n, buf);
    p[0] = (uint8_t)len;
    memcpy(p + 1, buf, len);
    return 1 + len;
}

static void zcd_script_sig_placeholder(int height, struct script *out)
{
    size_t n = zcd_push_int64(out->data, height);
    out->data[n++] = (uint8_t)OP_0;        /* << OP_0 */
    out->size = (uint16_t)n;
}

static void zcd_script_sig_with_extra_nonce(int height,
                                            uint32_t extra_nonce,
                                            struct script *out)
{
    size_t n = zcd_push_int64(out->data, height);
    uint8_t buf[5];
    size_t len = zcd_scriptnum_vch(extra_nonce, buf); /* << CScriptNum(en) */
    out->data[n++] = (uint8_t)len;
    memcpy(out->data + n, buf, len);
    n += len;
    out->size = (uint16_t)n;
}

static bool scripts_equal(const struct script *a, const struct script *b)
{
    return a->size == b->size && memcmp(a->data, b->data, a->size) == 0;
}

int test_domain_consensus_coinbase(void)
{
    int failures = 0;
    const struct chain_params *cp = chain_params_get();
    const struct consensus_params *params = &cp->consensus;

    /* --- error-path / contract tests --- */

    /* placeholder: null out. */
    {
        struct zcl_result r = domain_consensus_coinbase_script_sig_placeholder(
                100, NULL);
        DCC_CHECK("placeholder null out -> ERR_NULL_OUT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINBASE_ERR_NULL_OUT);
    }
    /* placeholder: negative height. */
    {
        struct script s; script_init(&s);
        struct zcl_result r = domain_consensus_coinbase_script_sig_placeholder(
                -1, &s);
        DCC_CHECK("placeholder negative height -> ERR_NEG_HEIGHT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINBASE_ERR_NEG_HEIGHT);
    }
    /* placeholder: 2^24 overflow. */
    {
        struct script s; script_init(&s);
        struct zcl_result r = domain_consensus_coinbase_script_sig_placeholder(
                0x01000000, &s);
        DCC_CHECK("placeholder h=2^24 -> ERR_HEIGHT_RANGE",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINBASE_ERR_HEIGHT_RANGE);
    }

    /* extra-nonce: null out. */
    {
        struct zcl_result r =
            domain_consensus_coinbase_script_sig_with_extra_nonce(100, 0, NULL);
        DCC_CHECK("extra_nonce null out -> ERR_NULL_OUT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINBASE_ERR_NULL_OUT);
    }
    /* extra-nonce: negative height. */
    {
        struct script s; script_init(&s);
        struct zcl_result r =
            domain_consensus_coinbase_script_sig_with_extra_nonce(-5, 7, &s);
        DCC_CHECK("extra_nonce negative height -> ERR_NEG_HEIGHT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINBASE_ERR_NEG_HEIGHT);
    }
    /* extra-nonce: height overflow. */
    {
        struct script s; script_init(&s);
        struct zcl_result r =
            domain_consensus_coinbase_script_sig_with_extra_nonce(
                    0x01000000, 7, &s);
        DCC_CHECK("extra_nonce h=2^24 -> ERR_HEIGHT_RANGE",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINBASE_ERR_HEIGHT_RANGE);
    }

    /* build: null out_tx. */
    {
        struct script m; script_init(&m);
        struct domain_consensus_coinbase_inputs in = {
            .n_height = 1, .subsidy = 0, .total_fees = 0,
            .miner_script = &m, .params = params,
        };
        struct zcl_result r = domain_consensus_coinbase_build(&in, NULL);
        DCC_CHECK("build null out_tx -> ERR_NULL_OUT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINBASE_ERR_NULL_OUT);
    }
    /* build: null inputs struct. */
    {
        struct transaction tx; transaction_init(&tx);
        struct zcl_result r = domain_consensus_coinbase_build(NULL, &tx);
        DCC_CHECK("build null in -> ERR_NULL_PARAMS",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINBASE_ERR_NULL_PARAMS);
        transaction_free(&tx);
    }
    /* build: null miner_script. */
    {
        struct transaction tx; transaction_init(&tx);
        (void)transaction_alloc(&tx, 1, 1);
        struct domain_consensus_coinbase_inputs in = {
            .n_height = 1, .subsidy = 0, .total_fees = 0,
            .miner_script = NULL, .params = params,
        };
        struct zcl_result r = domain_consensus_coinbase_build(&in, &tx);
        DCC_CHECK("build null script -> ERR_NULL_SCRIPT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINBASE_ERR_NULL_SCRIPT);
        transaction_free(&tx);
    }
    /* build: negative fees / subsidy / height / out of range. */
    {
        struct script m; script_init(&m);
        struct transaction tx; transaction_init(&tx);
        (void)transaction_alloc(&tx, 1, 1);

        struct domain_consensus_coinbase_inputs in = {
            .n_height = 1, .subsidy = 0, .total_fees = -1,
            .miner_script = &m, .params = params,
        };
        struct zcl_result r = domain_consensus_coinbase_build(&in, &tx);
        DCC_CHECK("build neg fees -> ERR_NEG_FEES",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINBASE_ERR_NEG_FEES);

        in.total_fees = 0;
        in.subsidy = -1;
        r = domain_consensus_coinbase_build(&in, &tx);
        DCC_CHECK("build neg subsidy -> ERR_NEG_SUBSIDY",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINBASE_ERR_NEG_SUBSIDY);

        in.subsidy = 0;
        in.n_height = -1;
        r = domain_consensus_coinbase_build(&in, &tx);
        DCC_CHECK("build neg height -> ERR_NEG_HEIGHT",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINBASE_ERR_NEG_HEIGHT);

        in.n_height = 0x01000000;
        r = domain_consensus_coinbase_build(&in, &tx);
        DCC_CHECK("build h=2^24 -> ERR_HEIGHT_RANGE",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINBASE_ERR_HEIGHT_RANGE);
        transaction_free(&tx);
    }
    /* build: out_tx not preallocated. */
    {
        struct script m; script_init(&m);
        struct transaction tx; transaction_init(&tx);   /* num_vin=0 */
        struct domain_consensus_coinbase_inputs in = {
            .n_height = 1, .subsidy = 0, .total_fees = 0,
            .miner_script = &m, .params = params,
        };
        struct zcl_result r = domain_consensus_coinbase_build(&in, &tx);
        DCC_CHECK("build no prealloc -> ERR_NOT_PREALLOC",
                  !r.ok && r.code == DOMAIN_CONSENSUS_COINBASE_ERR_NOT_PREALLOC);
        transaction_free(&tx);
    }

    /* --- script-sig shape regression seal (placeholder vs zclassicd) --- */
    {
        int heights[] = { 0, 1, 16, 17, 100, 0x7f, 0x80, 0xff, 0x100, 0xffff,
                          0x10000, 706559, 706560, 707000, 2387000,
                          0x7fffff, 0x800000, 0x00FFFFFF };
        int n = (int)(sizeof(heights) / sizeof(heights[0]));
        bool all_match = true;
        for (int i = 0; i < n; i++) {
            struct script dom, ref;
            script_init(&dom); script_init(&ref);
            struct zcl_result r =
                domain_consensus_coinbase_script_sig_placeholder(heights[i], &dom);
            zcd_script_sig_placeholder(heights[i], &ref);
            if (!r.ok || !scripts_equal(&dom, &ref)) {
                printf("\n  PLACEHOLDER MISMATCH h=%d ok=%d dom.size=%u "
                       "ref.size=%u\n", heights[i], (int)r.ok,
                       (unsigned)dom.size, (unsigned)ref.size);
                all_match = false;
            }
        }
        DCC_CHECK("placeholder script_sig matches zclassicd across heights",
                  all_match);
    }

    /* --- script-sig shape regression seal (extra-nonce vs zclassicd) --- */
    {
        int heights[] = { 0, 1, 16, 17, 706559, 706560, 707000, 2387001,
                          0x800000, 0x00FFFFFF };
        uint32_t nonces[] = { 0, 1, 16, 0x7f, 0x80, 0xff, 0x100, 0xffff,
                              0x10000, 0x7fffffffU, 0xffffffffU };
        int nh = (int)(sizeof(heights) / sizeof(heights[0]));
        int nn = (int)(sizeof(nonces)  / sizeof(nonces[0]));
        bool all_match = true;
        for (int i = 0; i < nh; i++) for (int j = 0; j < nn; j++) {
            struct script dom, ref;
            script_init(&dom); script_init(&ref);
            struct zcl_result r =
                domain_consensus_coinbase_script_sig_with_extra_nonce(
                    heights[i], nonces[j], &dom);
            zcd_script_sig_with_extra_nonce(heights[i], nonces[j], &ref);
            if (!r.ok || !scripts_equal(&dom, &ref)) {
                printf("\n  EXTRA_NONCE MISMATCH h=%d en=%u dom.size=%u "
                       "ref.size=%u\n", heights[i], nonces[j],
                       (unsigned)dom.size, (unsigned)ref.size);
                all_match = false;
            }
        }
        DCC_CHECK("extra_nonce script_sig matches zclassicd across heights x nonces",
                  all_match);
    }

    /* --- implementation-independent golden seal: hand-computed bytes for
     * `CScript() << nHeight << OP_0`, the exact placeholder scriptSig.
     * Catches a shared conceptual error in both the builder and the
     * reference above. Each row is {height, {expected bytes...}, size}. */
    {
        struct { int h; uint8_t want[8]; uint8_t len; } golden[] = {
            { 1,          { 0x51, 0x00 },                         2 }, /* OP_1 */
            { 16,         { 0x60, 0x00 },                         2 }, /* OP_16 */
            { 17,         { 0x01, 0x11, 0x00 },                   3 },
            { 0x80,       { 0x02, 0x80, 0x00, 0x00 },             4 }, /* sign byte */
            { 0x100,      { 0x02, 0x00, 0x01, 0x00 },             4 },
            { 0xffff,     { 0x03, 0xff, 0xff, 0x00, 0x00 },       5 }, /* sign byte */
            { 3145728,    { 0x03, 0x00, 0x00, 0x30, 0x00 },       5 }, /* mainnet: == legacy 3-byte (live no-op) */
            { 0x800000,   { 0x04, 0x00, 0x00, 0x80, 0x00, 0x00 }, 6 }, /* sign byte (legacy was WRONG) */
        };
        bool all_ok = true;
        for (size_t i = 0; i < sizeof(golden)/sizeof(golden[0]); i++) {
            struct script s; script_init(&s);
            struct zcl_result r =
                domain_consensus_coinbase_script_sig_placeholder(golden[i].h, &s);
            if (!r.ok || s.size != golden[i].len ||
                memcmp(s.data, golden[i].want, golden[i].len) != 0) {
                printf("\n  GOLDEN MISMATCH h=%d ok=%d size=%u want_len=%u\n",
                       golden[i].h, (int)r.ok, (unsigned)s.size,
                       (unsigned)golden[i].len);
                all_ok = false;
            }
        }
        DCC_CHECK("placeholder matches hand-computed zclassicd golden bytes",
                  all_ok);
    }

    /* extra-nonce 0 is a CScriptNum(0) data push = a single length-0 byte
     * (0x00), NOT a 4-byte field: `CScript() << 1 << CScriptNum(0)` =
     * [OP_1, 0x00]. */
    {
        struct script s; script_init(&s);
        struct zcl_result r =
            domain_consensus_coinbase_script_sig_with_extra_nonce(1, 0, &s);
        DCC_CHECK("extra_nonce=0 -> [OP_1, 0x00] (size=2)",
                  r.ok && s.size == 2 && s.data[0] == 0x51 && s.data[1] == 0x00);
    }

    /* --- coinbase_build full-tx regression seal across epochs. We
     * exercise heights spanning the pre-Overwinter / Overwinter /
     * Sapling / pre- and post-Buttercup subsidy boundary so the version
     * selection logic and the value computation are both pinned. ----- */
    {
        struct script miner; script_init(&miner);
        unsigned char p2pkh[20] = {0};
        miner.data[0] = OP_DUP;
        miner.data[1] = OP_HASH160;
        miner.data[2] = 0x14;
        memcpy(miner.data + 3, p2pkh, 20);
        miner.data[23] = OP_EQUALVERIFY;
        miner.data[24] = OP_CHECKSIG;
        miner.size = 25;

        int heights[] = {
            1,         /* slow-start, pre-Overwinter (likely v1) */
            20000,     /* past slow-start, pre-Overwinter */
            500000,    /* mainnet: Overwinter/Sapling active */
            706559,    /* one before Buttercup activation */
            706560,    /* at Buttercup activation */
            707001,    /* post-Buttercup, reduced subsidy */
            1500000,   /* deep post-Buttercup */
        };
        int64_t fee_cases[] = { 0, 1, 1000000 };
        int nh = (int)(sizeof(heights) / sizeof(heights[0]));
        int nf = (int)(sizeof(fee_cases) / sizeof(fee_cases[0]));
        bool all_match = true;
        for (int i = 0; i < nh; i++) for (int j = 0; j < nf; j++) {
            int h = heights[i];
            int64_t fees = fee_cases[j];
            int64_t subsidy = get_block_subsidy(h, params);

            struct transaction tx; transaction_init(&tx);
            if (!transaction_alloc(&tx, 1, 1)) { all_match = false; continue; }
            struct domain_consensus_coinbase_inputs in = {
                .n_height = h, .subsidy = subsidy, .total_fees = fees,
                .miner_script = &miner, .params = params,
            };
            struct zcl_result r = domain_consensus_coinbase_build(&in, &tx);
            if (!r.ok) { all_match = false; transaction_free(&tx); continue; }

            /* Structural invariants the legacy code held. */
            bool ok = transaction_is_coinbase(&tx)
                   && tx.num_vin == 1
                   && tx.num_vout == 1
                   && tx.vout[0].value == subsidy + fees
                   && tx.vout[0].script_pub_key.size == miner.size
                   && memcmp(tx.vout[0].script_pub_key.data,
                             miner.data, miner.size) == 0
                   && tx.expiry_height == 0;

            /* coinbase scriptSig == zclassicd's `CScript() << nHeight << OP_0`
             * — the minimal BIP34 height push, height-derived (NOT a fixed
             * 3-byte shape). Reuses the same reference the placeholder seal
             * above pins, so this seal tracks parity across all heights. */
            struct script exp_ss; script_init(&exp_ss);
            zcd_script_sig_placeholder(h, &exp_ss);
            ok = ok
                   && tx.vin[0].script_sig.size == exp_ss.size
                   && memcmp(tx.vin[0].script_sig.data,
                             exp_ss.data, exp_ss.size) == 0;

            /* Version per epoch matches legacy `create_new_block`. */
            if (consensus_network_upgrade_active(params, h, UPGRADE_SAPLING)) {
                ok = ok && tx.version == SAPLING_TX_VERSION
                        && tx.version_group_id == SAPLING_VERSION_GROUP_ID;
            } else if (consensus_network_upgrade_active(params, h,
                                                        UPGRADE_OVERWINTER)) {
                ok = ok && tx.version == OVERWINTER_TX_VERSION
                        && tx.version_group_id == OVERWINTER_VERSION_GROUP_ID;
            }
            /* pre-Overwinter: legacy left version untouched (v1) — same
             * here, transaction_init() sets version=1. */
            else {
                ok = ok && tx.version == 1 && tx.version_group_id == 0;
            }

            if (!ok) {
                printf("\n  BUILD MISMATCH h=%d fees=%lld subsidy=%lld "
                       "version=%d gid=0x%x scriptSig.size=%u\n",
                       h, (long long)fees, (long long)subsidy,
                       tx.version, tx.version_group_id,
                       (unsigned)tx.vin[0].script_sig.size);
                all_match = false;
            }

            /* Determinism: rebuild and compare hashes. */
            struct transaction tx2; transaction_init(&tx2);
            if (transaction_alloc(&tx2, 1, 1)) {
                struct zcl_result r2 = domain_consensus_coinbase_build(&in, &tx2);
                if (!r2.ok ||
                    memcmp(&tx.hash, &tx2.hash, sizeof(tx.hash)) != 0) {
                    printf("\n  BUILD NON-DETERMINISTIC h=%d\n", h);
                    all_match = false;
                }
                transaction_free(&tx2);
            }
            transaction_free(&tx);
        }
        DCC_CHECK("coinbase_build invariants + version selection across "
                  "pre/post-Sapling and pre/post-Buttercup", all_match);
    }

    return failures;
}
