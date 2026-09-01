/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/script_standard.{c,h}.
 *
 * Pins the pure standard-script-type detection. Tests exercise the typed
 * zcl_result API directly AND cross-check against the legacy
 * core/modules/script/standard.h wrappers (script_solver / script_extract_destination
 * / script_sig_args_expected) to prove the extraction is behaviour-preserving.
 *
 * Coverage:
 *   - null / edge contracts (null script, null out, null solutions)
 *   - per-shape recognition: P2PKH, P2PK (compressed + uncompressed),
 *     P2SH, multisig 2-of-3, OP_RETURN (null data, multiple shapes),
 *     nonstandard
 *   - extract_destination across all five recognised shapes
 *   - sig_args_expected per type
 *   - regression seal: domain wrapper == legacy wrapper for every shape
 *   - multisig graceful overflow when solutions_cap < n+2 (no buffer
 *     overrun, falls back to NONSTANDARD)
 *   - script_id_from_script: matches hash160(script) and the legacy
 *     script_id_from_script wrapper
 */

#include "test/test_core.h"

#include "domain/consensus/script_standard.h"
#include "script/standard.h"
#include "script/script.h"
#include "keys/pubkey.h"
#include "core/hash.h"

#include <stdio.h>
#include <string.h>

#define DCSS_CHECK(name, expr) do { \
    printf("domain_consensus_script_standard: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ---- script builders ---- */

static void build_p2pkh(struct script *s, unsigned char fill)
{
    s->data[0] = OP_DUP;
    s->data[1] = OP_HASH160;
    s->data[2] = 20;
    memset(s->data + 3, fill, 20);
    s->data[23] = OP_EQUALVERIFY;
    s->data[24] = OP_CHECKSIG;
    s->size = 25;
}

static void build_p2sh(struct script *s, unsigned char fill)
{
    s->data[0] = OP_HASH160;
    s->data[1] = 20;
    memset(s->data + 2, fill, 20);
    s->data[22] = OP_EQUAL;
    s->size = 23;
}

static void build_p2pk_compressed(struct script *s, unsigned char tag)
{
    s->data[0] = 33;
    s->data[1] = 0x02;  /* compressed even-y */
    /* Use a known valid compressed pubkey on secp256k1 — the generator G:
     * compressed = 0x02 || G.x (32 bytes). We hard-code the x. */
    static const unsigned char gx[32] = {
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
        0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
        0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
        0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
    };
    memcpy(s->data + 2, gx, 32);
    s->data[34] = OP_CHECKSIG;
    s->size = 35;
    (void)tag;
}

static void build_p2pk_uncompressed(struct script *s)
{
    s->data[0] = 65;
    s->data[1] = 0x04;
    /* G point uncompressed: 04 || Gx || Gy. */
    static const unsigned char g_uncompressed_64[64] = {
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
        0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
        0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
        0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
        0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
        0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
        0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
        0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
    };
    memcpy(s->data + 2, g_uncompressed_64, 64);
    s->data[66] = OP_CHECKSIG;
    s->size = 67;
}

static void build_op_return(struct script *s, const unsigned char *payload,
                            size_t plen)
{
    s->data[0] = OP_RETURN;
    s->size = 1;
    if (plen > 0 && plen < OP_PUSHDATA1) {
        s->data[1] = (unsigned char)plen;
        memcpy(s->data + 2, payload, plen);
        s->size = 2 + plen;
    } else if (plen == 0) {
        /* bare OP_RETURN is still NULL_DATA */
    }
}

/* 2-of-3 multisig with three 33-byte pubkeys (distinct tags). The
 * detector only cares about the {33,65}-len prefix bytes; the pubkey
 * contents do not affect script_solver / extract. */
static void build_multisig_2of3(struct script *s)
{
    size_t pos = 0;
    s->data[pos++] = OP_2;
    for (int k = 0; k < 3; k++) {
        s->data[pos++] = 33;
        memset(s->data + pos, 0xC0 + k, 33);
        pos += 33;
    }
    s->data[pos++] = OP_3;
    s->data[pos++] = OP_CHECKMULTISIG;
    s->size = pos;
}

/* ---- the test ---- */

int test_domain_consensus_script_standard(void)
{
    int failures = 0;

    /* ---- contract / null-arg tests ---- */

    {
        unsigned char solutions[4][65];
        size_t solution_sizes[4] = {0};
        size_t n = 0;
        enum domain_script_txnouttype t;
        bool matched;
        struct zcl_result r = domain_consensus_script_solver(
                NULL, solutions, solution_sizes, 4, &t, &n, &matched);
        DCSS_CHECK("solver null script -> ERR_NULL_SCRIPT",
                   !r.ok && r.code ==
                   DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_SCRIPT);
    }
    {
        struct script s; script_init(&s);
        build_p2pkh(&s, 0xAB);
        unsigned char solutions[4][65];
        size_t solution_sizes[4] = {0};
        size_t n = 0;
        bool matched;
        struct zcl_result r = domain_consensus_script_solver(
                &s, solutions, solution_sizes, 4, NULL, &n, &matched);
        DCSS_CHECK("solver null type_out -> ERR_NULL_OUT",
                   !r.ok && r.code ==
                   DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_OUT);
    }
    {
        struct script s; script_init(&s);
        build_p2pkh(&s, 0xAB);
        enum domain_script_txnouttype t;
        size_t n = 0;
        bool matched;
        struct zcl_result r = domain_consensus_script_solver(
                &s, NULL, NULL, 4, &t, &n, &matched);
        DCSS_CHECK("solver null solutions -> ERR_NULL_SOLUTIONS",
                   !r.ok && r.code ==
                   DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_SOLUTIONS);
    }
    {
        struct script s; script_init(&s);
        build_p2pkh(&s, 0xAB);
        struct zcl_result r = domain_consensus_script_extract_destination(
                &s, NULL, NULL);
        DCSS_CHECK("extract null dest_out -> ERR_NULL_OUT",
                   !r.ok && r.code ==
                   DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_OUT);
    }
    {
        struct zcl_result r = domain_consensus_script_id_from_script(
                NULL, NULL);
        DCSS_CHECK("script_id null script -> ERR_NULL_SCRIPT",
                   !r.ok && r.code ==
                   DOMAIN_CONSENSUS_SCRIPT_STANDARD_ERR_NULL_SCRIPT);
    }

    /* ---- name helper ---- */
    DCSS_CHECK("name nonstandard",
               strcmp(domain_consensus_script_txn_output_type_name(
                       DOMAIN_SCRIPT_TX_NONSTANDARD), "nonstandard") == 0);
    DCSS_CHECK("name pubkey",
               strcmp(domain_consensus_script_txn_output_type_name(
                       DOMAIN_SCRIPT_TX_PUBKEY), "pubkey") == 0);
    DCSS_CHECK("name pubkeyhash",
               strcmp(domain_consensus_script_txn_output_type_name(
                       DOMAIN_SCRIPT_TX_PUBKEYHASH), "pubkeyhash") == 0);
    DCSS_CHECK("name scripthash",
               strcmp(domain_consensus_script_txn_output_type_name(
                       DOMAIN_SCRIPT_TX_SCRIPTHASH), "scripthash") == 0);
    DCSS_CHECK("name multisig",
               strcmp(domain_consensus_script_txn_output_type_name(
                       DOMAIN_SCRIPT_TX_MULTISIG), "multisig") == 0);
    DCSS_CHECK("name nulldata",
               strcmp(domain_consensus_script_txn_output_type_name(
                       DOMAIN_SCRIPT_TX_NULL_DATA), "nulldata") == 0);

    /* ---- per-shape recognition ---- */

    /* P2PKH */
    {
        struct script s; script_init(&s);
        build_p2pkh(&s, 0xAB);
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        enum domain_script_txnouttype t;
        size_t n = 0;
        bool matched = false;
        struct zcl_result r = domain_consensus_script_solver(
                &s, solutions, solution_sizes, 20, &t, &n, &matched);
        bool ok = r.ok && matched &&
                  t == DOMAIN_SCRIPT_TX_PUBKEYHASH &&
                  n == 1 && solution_sizes[0] == 20 &&
                  solutions[0][0] == 0xAB;
        DCSS_CHECK("p2pkh -> PUBKEYHASH + hash extracted", ok);
    }

    /* P2SH */
    {
        struct script s; script_init(&s);
        build_p2sh(&s, 0xCD);
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        enum domain_script_txnouttype t;
        size_t n = 0;
        bool matched = false;
        struct zcl_result r = domain_consensus_script_solver(
                &s, solutions, solution_sizes, 20, &t, &n, &matched);
        bool ok = r.ok && matched &&
                  t == DOMAIN_SCRIPT_TX_SCRIPTHASH &&
                  n == 1 && solution_sizes[0] == 20 &&
                  solutions[0][0] == 0xCD;
        DCSS_CHECK("p2sh -> SCRIPTHASH + hash extracted", ok);
    }

    /* P2PK compressed */
    {
        struct script s; script_init(&s);
        build_p2pk_compressed(&s, 0x00);
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        enum domain_script_txnouttype t;
        size_t n = 0;
        bool matched = false;
        struct zcl_result r = domain_consensus_script_solver(
                &s, solutions, solution_sizes, 20, &t, &n, &matched);
        DCSS_CHECK("p2pk compressed -> PUBKEY",
                   r.ok && matched &&
                   t == DOMAIN_SCRIPT_TX_PUBKEY &&
                   n == 1 && solution_sizes[0] == 33);
    }

    /* P2PK uncompressed */
    {
        struct script s; script_init(&s);
        build_p2pk_uncompressed(&s);
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        enum domain_script_txnouttype t;
        size_t n = 0;
        bool matched = false;
        struct zcl_result r = domain_consensus_script_solver(
                &s, solutions, solution_sizes, 20, &t, &n, &matched);
        DCSS_CHECK("p2pk uncompressed -> PUBKEY",
                   r.ok && matched &&
                   t == DOMAIN_SCRIPT_TX_PUBKEY &&
                   n == 1 && solution_sizes[0] == 65);
    }

    /* OP_RETURN bare */
    {
        struct script s; script_init(&s);
        build_op_return(&s, NULL, 0);
        s.data[0] = OP_RETURN;
        s.size = 1;
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        enum domain_script_txnouttype t;
        size_t n = 0;
        bool matched = false;
        struct zcl_result r = domain_consensus_script_solver(
                &s, solutions, solution_sizes, 20, &t, &n, &matched);
        DCSS_CHECK("bare OP_RETURN -> NULL_DATA",
                   r.ok && matched &&
                   t == DOMAIN_SCRIPT_TX_NULL_DATA);
    }

    /* OP_RETURN with data push */
    {
        struct script s; script_init(&s);
        unsigned char payload[16] = { 1, 2, 3, 4, 5, 6, 7, 8,
                                       9, 10, 11, 12, 13, 14, 15, 16 };
        build_op_return(&s, payload, sizeof(payload));
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        enum domain_script_txnouttype t;
        size_t n = 0;
        bool matched = false;
        struct zcl_result r = domain_consensus_script_solver(
                &s, solutions, solution_sizes, 20, &t, &n, &matched);
        DCSS_CHECK("OP_RETURN + 16 bytes -> NULL_DATA",
                   r.ok && matched &&
                   t == DOMAIN_SCRIPT_TX_NULL_DATA);
    }

    /* Multisig 2-of-3 */
    {
        struct script s; script_init(&s);
        build_multisig_2of3(&s);
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        enum domain_script_txnouttype t;
        size_t n = 0;
        bool matched = false;
        struct zcl_result r = domain_consensus_script_solver(
                &s, solutions, solution_sizes, 20, &t, &n, &matched);
        /* Multisig fills: row0 = [M], row1..rowN = keys, last = [N]. */
        DCSS_CHECK("multisig 2-of-3 -> MULTISIG, 5 solutions",
                   r.ok && matched &&
                   t == DOMAIN_SCRIPT_TX_MULTISIG &&
                   n == 5 &&
                   solutions[0][0] == 2 &&
                   solution_sizes[0] == 1 &&
                   solutions[4][0] == 3 &&
                   solution_sizes[4] == 1);
    }

    /* Multisig graceful overflow when buffer too small.
     * 2-of-3 needs 5 rows; pass cap=4 and check we get NONSTANDARD with
     * matched=false and no overrun (the local stack buffer is exactly
     * 4 rows wide). */
    {
        struct script s; script_init(&s);
        build_multisig_2of3(&s);
        unsigned char solutions[4][65];
        size_t solution_sizes[4] = {0};
        enum domain_script_txnouttype t;
        size_t n = 99;
        bool matched = true;
        struct zcl_result r = domain_consensus_script_solver(
                &s, solutions, solution_sizes, 4, &t, &n, &matched);
        DCSS_CHECK("multisig small cap -> NONSTANDARD, no overrun",
                   r.ok && !matched &&
                   t == DOMAIN_SCRIPT_TX_NONSTANDARD &&
                   n == 0);
    }

    /* Nonstandard */
    {
        struct script s; script_init(&s);
        s.data[0] = OP_CHECKSIG;
        s.size = 1;
        unsigned char solutions[20][65];
        size_t solution_sizes[20];
        enum domain_script_txnouttype t;
        size_t n = 99;
        bool matched = true;
        struct zcl_result r = domain_consensus_script_solver(
                &s, solutions, solution_sizes, 20, &t, &n, &matched);
        DCSS_CHECK("bare CHECKSIG -> NONSTANDARD",
                   r.ok && !matched &&
                   t == DOMAIN_SCRIPT_TX_NONSTANDARD &&
                   n == 0);
    }

    /* ---- sig_args_expected per type ---- */
    {
        DCSS_CHECK("sig_args PUBKEY = 1",
                   domain_consensus_script_sig_args_expected(
                           DOMAIN_SCRIPT_TX_PUBKEY, NULL, NULL, 0) == 1);
        DCSS_CHECK("sig_args PUBKEYHASH = 2",
                   domain_consensus_script_sig_args_expected(
                           DOMAIN_SCRIPT_TX_PUBKEYHASH, NULL, NULL, 0) == 2);
        DCSS_CHECK("sig_args SCRIPTHASH = 1",
                   domain_consensus_script_sig_args_expected(
                           DOMAIN_SCRIPT_TX_SCRIPTHASH, NULL, NULL, 0) == 1);
        DCSS_CHECK("sig_args NONSTANDARD = -1",
                   domain_consensus_script_sig_args_expected(
                           DOMAIN_SCRIPT_TX_NONSTANDARD, NULL, NULL, 0) == -1);
        DCSS_CHECK("sig_args NULL_DATA = -1",
                   domain_consensus_script_sig_args_expected(
                           DOMAIN_SCRIPT_TX_NULL_DATA, NULL, NULL, 0) == -1);
        /* multisig: M+1 */
        unsigned char sol[20][65] = { { 2 } };
        size_t ssz[20] = { 1 };
        DCSS_CHECK("sig_args MULTISIG(M=2) = 3",
                   domain_consensus_script_sig_args_expected(
                           DOMAIN_SCRIPT_TX_MULTISIG, sol, ssz, 5) == 3);
        DCSS_CHECK("sig_args MULTISIG no solutions = -1",
                   domain_consensus_script_sig_args_expected(
                           DOMAIN_SCRIPT_TX_MULTISIG, NULL, NULL, 0) == -1);
    }

    /* ---- extract_destination ---- */
    {
        struct script s; script_init(&s);
        build_p2pkh(&s, 0xAB);
        struct tx_destination d = { .type = DEST_NONE };
        bool matched = false;
        struct zcl_result r = domain_consensus_script_extract_destination(
                &s, &d, &matched);
        DCSS_CHECK("extract P2PKH -> DEST_KEY_ID",
                   r.ok && matched && d.type == DEST_KEY_ID &&
                   d.id.key.id.data[0] == 0xAB);
    }
    {
        struct script s; script_init(&s);
        build_p2sh(&s, 0xCD);
        struct tx_destination d = { .type = DEST_NONE };
        bool matched = false;
        struct zcl_result r = domain_consensus_script_extract_destination(
                &s, &d, &matched);
        DCSS_CHECK("extract P2SH -> DEST_SCRIPT_ID",
                   r.ok && matched && d.type == DEST_SCRIPT_ID &&
                   d.id.script.hash.data[0] == 0xCD);
    }
    {
        struct script s; script_init(&s);
        build_p2pk_compressed(&s, 0);
        struct tx_destination d = { .type = DEST_NONE };
        bool matched = false;
        struct zcl_result r = domain_consensus_script_extract_destination(
                &s, &d, &matched);
        DCSS_CHECK("extract P2PK valid -> DEST_KEY_ID",
                   r.ok && matched && d.type == DEST_KEY_ID);
    }
    {
        /* Multisig has no single destination. */
        struct script s; script_init(&s);
        build_multisig_2of3(&s);
        struct tx_destination d = { .type = DEST_KEY_ID };
        bool matched = true;
        struct zcl_result r = domain_consensus_script_extract_destination(
                &s, &d, &matched);
        DCSS_CHECK("extract MULTISIG -> matched=false",
                   r.ok && !matched && d.type == DEST_NONE);
    }
    {
        /* Bare OP_RETURN has no destination either. */
        struct script s; script_init(&s);
        s.data[0] = OP_RETURN; s.size = 1;
        struct tx_destination d = { .type = DEST_KEY_ID };
        bool matched = true;
        struct zcl_result r = domain_consensus_script_extract_destination(
                &s, &d, &matched);
        DCSS_CHECK("extract NULL_DATA -> matched=false",
                   r.ok && !matched && d.type == DEST_NONE);
    }
    {
        /* Nonstandard. */
        struct script s; script_init(&s);
        s.data[0] = OP_CHECKSIG; s.size = 1;
        struct tx_destination d = { .type = DEST_KEY_ID };
        bool matched = true;
        struct zcl_result r = domain_consensus_script_extract_destination(
                &s, &d, &matched);
        DCSS_CHECK("extract NONSTANDARD -> matched=false",
                   r.ok && !matched && d.type == DEST_NONE);
    }

    /* ---- script_id_from_script ---- */
    {
        struct script s; script_init(&s);
        build_p2pkh(&s, 0xAB);
        unsigned char domain_h[20] = {0};
        struct zcl_result r = domain_consensus_script_id_from_script(
                &s, domain_h);
        unsigned char expect[20];
        hash160(s.data, s.size, expect);
        DCSS_CHECK("script_id_from_script == hash160",
                   r.ok && memcmp(domain_h, expect, 20) == 0);

        /* Cross-check the legacy wrapper. */
        struct script_id sid;
        script_id_from_script(&sid, &s);
        DCSS_CHECK("script_id wrapper matches domain",
                   memcmp(sid.hash.data, domain_h, 20) == 0);
    }

    /* ---- REGRESSION SEAL: domain == legacy wrapper across every shape ---- */
    {
        struct script shapes[7];
        const char *names[7] = {
            "P2PKH", "P2SH", "P2PK-compressed", "P2PK-uncompressed",
            "OP_RETURN-bare", "MULTISIG-2of3", "NONSTANDARD"
        };
        for (int i = 0; i < 7; i++) script_init(&shapes[i]);
        build_p2pkh(&shapes[0], 0x11);
        build_p2sh(&shapes[1], 0x22);
        build_p2pk_compressed(&shapes[2], 0);
        build_p2pk_uncompressed(&shapes[3]);
        shapes[4].data[0] = OP_RETURN; shapes[4].size = 1;
        build_multisig_2of3(&shapes[5]);
        shapes[6].data[0] = OP_CHECKSIG; shapes[6].size = 1;

        bool all_match = true;
        for (int i = 0; i < 7; i++) {
            /* Domain call. */
            unsigned char d_sol[20][65];
            size_t d_ssz[20] = {0};
            enum domain_script_txnouttype d_t = DOMAIN_SCRIPT_TX_NONSTANDARD;
            size_t d_n = 0;
            bool d_matched = false;
            struct zcl_result r = domain_consensus_script_solver(
                    &shapes[i], d_sol, d_ssz, 20, &d_t, &d_n, &d_matched);
            (void)r;

            /* Legacy wrapper. */
            unsigned char l_sol[20][65];
            size_t l_ssz[20] = {0};
            enum txnouttype l_t = TX_NONSTANDARD;
            size_t l_n = 0;
            bool l_matched = script_solver(&shapes[i], &l_t,
                                           l_sol, l_ssz, &l_n);

            if (d_matched != l_matched ||
                (int)d_t != (int)l_t ||
                d_n != l_n) {
                printf("\n  MISMATCH shape=%s d_matched=%d l_matched=%d "
                       "d_t=%d l_t=%d d_n=%zu l_n=%zu\n",
                       names[i], (int)d_matched, (int)l_matched,
                       (int)d_t, (int)l_t, d_n, l_n);
                all_match = false;
                continue;
            }
            for (size_t k = 0; k < d_n; k++) {
                if (d_ssz[k] != l_ssz[k] ||
                    memcmp(d_sol[k], l_sol[k], d_ssz[k]) != 0) {
                    printf("\n  MISMATCH shape=%s row=%zu\n", names[i], k);
                    all_match = false;
                }
            }

            /* Cross-check extract_destination too. */
            struct tx_destination d_d = { .type = DEST_NONE };
            bool d_em = false;
            (void)domain_consensus_script_extract_destination(
                    &shapes[i], &d_d, &d_em);
            struct tx_destination l_d = { .type = DEST_NONE };
            bool l_em = script_extract_destination(&shapes[i], &l_d);
            if (d_em != l_em || d_d.type != l_d.type) {
                printf("\n  MISMATCH extract shape=%s d_em=%d l_em=%d "
                       "d_type=%d l_type=%d\n",
                       names[i], (int)d_em, (int)l_em,
                       (int)d_d.type, (int)l_d.type);
                all_match = false;
            }
        }
        DCSS_CHECK("regression seal: domain == legacy across all shapes",
                   all_match);
    }

    return failures;
}
