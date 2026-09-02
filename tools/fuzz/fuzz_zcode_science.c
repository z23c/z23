/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fuzz_zcode_science — libFuzzer harness for the ZCODE science object wire
 * parsers (study_spec.v1, benchmark_result.v1, reproduction.v1,
 * science_findings.v1, curation_vote.v1, science_statement.v1, and its
 * relation set). These bytes may arrive from the
 * public ZCODE CAS before their signatures, roots, or cross-object
 * authorities are trusted, so parsing must be total and bounded for every
 * possible input.
 *
 * Byte 0 selects one of seven parsers. The remainder is passed at its exact
 * length. No arm allocates. ASan+UBSan are supplied by FUZZ_CFLAGS.
 */

#include "vcs/zcode_science.h"

#include <signal.h>
#include <stddef.h>
#include <stdint.h>

volatile sig_atomic_t g_shutdown_requested = 0;

#define FUZZ_ZCODE_SCIENCE_ARMS 7u
#define FUZZ_ZCODE_SCIENCE_MAX_INPUT \
    (VCS_ZCODE_SCIENCE_RELATION_SET_MAX_WIRE_BYTES + 1u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > FUZZ_ZCODE_SCIENCE_MAX_INPUT)
        return 0;

    const uint8_t arm = (uint8_t)(data[0] % FUZZ_ZCODE_SCIENCE_ARMS);
    const uint8_t *wire = data + 1;
    const size_t wire_len = size - 1;

    switch (arm) {
    case 0: {
        struct vcs_zcode_study_spec_v1 out;
        (void)vcs_zcode_study_spec_parse(wire, wire_len, &out);
        break;
    }
    case 1: {
        struct vcs_zcode_benchmark_result_v1 out;
        (void)vcs_zcode_benchmark_result_parse(wire, wire_len, &out);
        break;
    }
    case 2: {
        struct vcs_zcode_reproduction_v1 out;
        (void)vcs_zcode_reproduction_parse(wire, wire_len, &out);
        break;
    }
    case 3: {
        struct vcs_zcode_science_findings_v1 out;
        (void)vcs_zcode_science_findings_parse(wire, wire_len, &out);
        break;
    }
    case 4: {
        struct vcs_zcode_curation_vote_v1 out;
        (void)vcs_zcode_curation_vote_parse(wire, wire_len, &out);
        break;
    }
    case 5: {
        struct vcs_zcode_science_statement_v1 out;
        (void)vcs_zcode_science_statement_parse(wire, wire_len, &out);
        break;
    }
    case 6: {
        struct vcs_zcode_science_relation_set_v1 out;
        (void)vcs_zcode_science_relation_set_parse(
            wire, wire_len, &out);
        break;
    }
    }
    return 0;
}
