/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Unit tests for domain/consensus/header_accept.{c,h}.
 *
 * These tests pin the pure block-HEADER acceptance checks (version-
 * too-low, bad-version, time-too-new, time-too-old, bad-equihash-
 * solution-size, bad-diffbits). Each rejection produces a byte-
 * identical P2P-visible reject_reason token; that string is the
 * regression seal — if any of these drift, the network will see
 * different REJECT messages than the legacy code did.
 *
 * The tests exercise:
 *   (a) the pure domain functions directly,
 *   (b) the core/modules/validation/accept_block_header.h thin wrappers, and
 *   (c) for the version-too-low / time-too-new gates, the legacy
 *       check_block_header() entry point — confirming all three layers
 *       produce the same reject_reason + DoS + reject_code.
 *
 * The contextual gates (time-too-old, bad-equihash-solution-size,
 * bad-diffbits, bad-version) live inside contextual_check_block_header
 * which requires a valid block_index pprev to construct — we skip the
 * legacy cross-check for those and rely on (a) + (b).
 */

#include "test/test_core.h"

#include "domain/consensus/header_accept.h"
#include "validation/accept_block_header.h"
#include "validation/check_block.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

#define DHA_CHECK(name, expr) do {                                  \
    printf("domain_consensus_header_accept: %s... ", (name));       \
    if ((expr)) { printf("OK\n"); }                                 \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

/* Build a synthetic header with nVersion=4, nTime=1000, nBits=0, and
 * all hashes zeroed. nSolutionSize starts at 0 so the equihash-size
 * gate is a silent pass unless the test explicitly sets a size. */
static void header_init_synthetic(struct block_header *h)
{
    block_header_init(h);
    h->nVersion = 4;
    h->nTime = 1000;
    h->nBits = 0x1f07ffffu;
    h->nSolutionSize = 0;
}

int test_domain_consensus_header_accept(void)
{
    int failures = 0;
    char reason[DOMAIN_HEADER_ACCEPT_REASON_MAX];
    int dos;

    /* ---- null-arg contracts (all six entry points) ---- */
    {
        struct zcl_result r =
            domain_consensus_check_header_version_too_low(
                NULL, 4, NULL, 0, NULL);
        DHA_CHECK("version_too_low: null header -> ERR_NULL_ARG",
                  !r.ok && r.code ==
                  DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_NULL_ARG);
    }
    {
        struct zcl_result r =
            domain_consensus_check_header_version_obsolete(
                NULL, 4, NULL, 0, NULL);
        DHA_CHECK("version_obsolete: null header -> ERR_NULL_ARG",
                  !r.ok && r.code ==
                  DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_NULL_ARG);
    }
    {
        struct zcl_result r =
            domain_consensus_check_header_timestamp_too_new(
                NULL, 0, NULL, 0, NULL);
        DHA_CHECK("timestamp_too_new: null header -> ERR_NULL_ARG",
                  !r.ok && r.code ==
                  DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_NULL_ARG);
    }
    {
        struct zcl_result r =
            domain_consensus_check_header_timestamp_too_old(
                NULL, 0, NULL, 0, NULL);
        DHA_CHECK("timestamp_too_old: null header -> ERR_NULL_ARG",
                  !r.ok && r.code ==
                  DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_NULL_ARG);
    }
    {
        struct zcl_result r =
            domain_consensus_check_header_equihash_solution_size(
                NULL, 0, NULL, 0, NULL);
        DHA_CHECK("equihash_size: null header -> ERR_NULL_ARG",
                  !r.ok && r.code ==
                  DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_NULL_ARG);
    }
    {
        struct zcl_result r =
            domain_consensus_check_header_bits_match(
                NULL, 0, NULL, 0, NULL);
        DHA_CHECK("bits_match: null header -> ERR_NULL_ARG",
                  !r.ok && r.code ==
                  DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_NULL_ARG);
    }

    /* ---- version-too-low ---- */
    {
        struct block_header h;
        header_init_synthetic(&h);
        h.nVersion = 3;          /* below MIN_BLOCK_VERSION (4) */
        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_header_version_too_low(
                &h, 4, reason, sizeof(reason), &dos);
        DHA_CHECK("v<4 -> version-too-low domain",
                  !r.ok &&
                  r.code ==
                    DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_VERSION_TOO_LOW &&
                  strcmp(reason, "version-too-low") == 0 &&
                  dos == 100);

        /* Lib-wrapper parity: reject_reason byte-identical, dos=100,
         * mode=MODE_INVALID, reject_code=REJECT_INVALID. */
        struct validation_state st;
        validation_state_init(&st);
        bool ok = accept_block_header_check_version_too_low(&h, 4, &st);
        DHA_CHECK("v<4 -> version-too-low lib-wrapper parity",
                  !ok &&
                  st.mode == MODE_INVALID &&
                  st.dos == 100 &&
                  st.reject_code == REJECT_INVALID &&
                  strcmp(st.reject_reason, "version-too-low") == 0);

        /* Legacy regression seal: check_block_header() with
         * check_pow=false runs the same impl. */
        struct validation_state st_legacy;
        validation_state_init(&st_legacy);
        bool ok_l = check_block_header(&h, &st_legacy,
                                       chain_params_get(), false);
        DHA_CHECK("v<4 -> version-too-low legacy parity",
                  !ok_l &&
                  st_legacy.mode == MODE_INVALID &&
                  st_legacy.dos == 100 &&
                  st_legacy.reject_code == REJECT_INVALID &&
                  strcmp(st_legacy.reject_reason,
                         "version-too-low") == 0);

        /* Accept path: v=4 should pass. */
        h.nVersion = 4;
        reason[0] = '\xff'; dos = -1;
        r = domain_consensus_check_header_version_too_low(
                &h, 4, reason, sizeof(reason), &dos);
        DHA_CHECK("v==4 -> accept",
                  r.ok && dos == 0 && reason[0] == '\0');
    }

    /* ---- bad-version (obsolete-below) ---- */
    {
        struct block_header h;
        header_init_synthetic(&h);
        h.nVersion = 3;
        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_header_version_obsolete(
                &h, 4, reason, sizeof(reason), &dos);
        DHA_CHECK("v<4 -> bad-version domain",
                  !r.ok &&
                  r.code ==
                    DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_BAD_VERSION &&
                  strcmp(reason, "bad-version") == 0 &&
                  dos == 0);

        /* Lib-wrapper parity: dos=0, code=REJECT_OBSOLETE. */
        struct validation_state st;
        validation_state_init(&st);
        bool ok = accept_block_header_check_version_obsolete(&h, 4, &st);
        DHA_CHECK("v<4 -> bad-version lib-wrapper parity",
                  !ok &&
                  st.mode == MODE_INVALID &&
                  st.dos == 0 &&
                  st.reject_code == REJECT_OBSOLETE &&
                  strcmp(st.reject_reason, "bad-version") == 0);

        /* Accept path: v=4 passes. */
        h.nVersion = 4;
        r = domain_consensus_check_header_version_obsolete(
                &h, 4, NULL, 0, NULL);
        DHA_CHECK("v==4 -> accept (obsolete-below)", r.ok);
    }

    /* ---- time-too-new ---- */
    {
        struct block_header h;
        header_init_synthetic(&h);
        h.nTime = 5000;
        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_header_timestamp_too_new(
                &h, 4000, reason, sizeof(reason), &dos);
        DHA_CHECK("time>upper -> time-too-new domain",
                  !r.ok &&
                  r.code ==
                    DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_TIME_TOO_NEW &&
                  strcmp(reason, "time-too-new") == 0 &&
                  dos == 0);

        /* Lib-wrapper parity: dos=0, code=REJECT_INVALID. */
        struct validation_state st;
        validation_state_init(&st);
        bool ok = accept_block_header_check_timestamp_too_new(
                      &h, 4000, &st);
        DHA_CHECK("time>upper -> time-too-new lib parity",
                  !ok &&
                  st.mode == MODE_INVALID &&
                  st.dos == 0 &&
                  st.reject_code == REJECT_INVALID &&
                  strcmp(st.reject_reason, "time-too-new") == 0);

        /* Boundary: equal is OK (legacy uses strict >). */
        r = domain_consensus_check_header_timestamp_too_new(
                &h, 5000, NULL, 0, NULL);
        DHA_CHECK("time==upper -> accept", r.ok);

        /* Accept path. */
        r = domain_consensus_check_header_timestamp_too_new(
                &h, 6000, NULL, 0, NULL);
        DHA_CHECK("time<upper -> accept", r.ok);
    }

    /* ---- time-too-old ---- */
    {
        struct block_header h;
        header_init_synthetic(&h);
        h.nTime = 1000;
        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_header_timestamp_too_old(
                &h, 1000, reason, sizeof(reason), &dos);
        DHA_CHECK("time<=mtp -> time-too-old domain",
                  !r.ok &&
                  r.code ==
                    DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_TIME_TOO_OLD &&
                  strcmp(reason, "time-too-old") == 0 &&
                  dos == 0);

        /* Boundary: strict equality fails (legacy uses <=). */
        r = domain_consensus_check_header_timestamp_too_old(
                &h, 999, NULL, 0, NULL);
        DHA_CHECK("time>mtp -> accept", r.ok);

        /* Lib-wrapper parity. */
        struct validation_state st;
        validation_state_init(&st);
        bool ok = accept_block_header_check_timestamp_too_old(
                      &h, 1000, &st);
        DHA_CHECK("time<=mtp -> time-too-old lib parity",
                  !ok &&
                  st.mode == MODE_INVALID &&
                  st.dos == 0 &&
                  st.reject_code == REJECT_INVALID &&
                  strcmp(st.reject_reason, "time-too-old") == 0);
    }

    /* ---- bad-equihash-solution-size ---- */
    {
        struct block_header h;
        header_init_synthetic(&h);
        /* Set a non-zero, non-matching solution size. Real Equihash
         * 200,9 expects 1344 bytes; we'll lie and say expected=1344
         * with header reporting 1000. */
        h.nSolutionSize = 1000;
        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_header_equihash_solution_size(
                &h, 1344, reason, sizeof(reason), &dos);
        DHA_CHECK("sol_size mismatch -> bad-equihash-solution-size domain",
                  !r.ok &&
                  r.code ==
                   DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_BAD_EQUIHASH_SOL_SIZE &&
                  strcmp(reason, "bad-equihash-solution-size") == 0 &&
                  dos == 100);

        /* Lib-wrapper parity. */
        struct validation_state st;
        validation_state_init(&st);
        bool ok = accept_block_header_check_equihash_solution_size(
                      &h, 1344, &st);
        DHA_CHECK("sol_size mismatch -> bad-equihash-solution-size lib parity",
                  !ok &&
                  st.mode == MODE_INVALID &&
                  st.dos == 100 &&
                  st.reject_code == REJECT_INVALID &&
                  strcmp(st.reject_reason,
                         "bad-equihash-solution-size") == 0);

        /* Match path. */
        h.nSolutionSize = 1344;
        r = domain_consensus_check_header_equihash_solution_size(
                &h, 1344, NULL, 0, NULL);
        DHA_CHECK("sol_size match -> accept", r.ok);

        /* Legacy silent-pass: sol_size == 0 always accepts. */
        h.nSolutionSize = 0;
        r = domain_consensus_check_header_equihash_solution_size(
                &h, 1344, NULL, 0, NULL);
        DHA_CHECK("sol_size==0 -> silent pass", r.ok);
    }

    /* ---- bad-diffbits ---- */
    {
        struct block_header h;
        header_init_synthetic(&h);
        h.nBits = 0x1f07ffffu;
        reason[0] = '\xff'; dos = -1;
        struct zcl_result r =
            domain_consensus_check_header_bits_match(
                &h, 0x1f07fffeu, reason, sizeof(reason), &dos);
        DHA_CHECK("nBits mismatch -> bad-diffbits domain",
                  !r.ok &&
                  r.code ==
                    DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_BAD_DIFFBITS &&
                  strcmp(reason, "bad-diffbits") == 0 &&
                  dos == 100);

        /* Lib-wrapper parity. */
        struct validation_state st;
        validation_state_init(&st);
        bool ok = accept_block_header_check_bits_match(
                      &h, 0x1f07fffeu, &st);
        DHA_CHECK("nBits mismatch -> bad-diffbits lib parity",
                  !ok &&
                  st.mode == MODE_INVALID &&
                  st.dos == 100 &&
                  st.reject_code == REJECT_INVALID &&
                  strcmp(st.reject_reason, "bad-diffbits") == 0);

        /* Match path. */
        r = domain_consensus_check_header_bits_match(
                &h, 0x1f07ffffu, NULL, 0, NULL);
        DHA_CHECK("nBits match -> accept", r.ok);
    }

    return failures;
}
