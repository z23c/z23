/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declarations between tests/harness/src/test_sync_throughput.c
 * (fixture + S1-S5) and tests/harness/src/test_sync_throughput_index.c
 * (S6-S7 + the group entry point). Split across two files to stay under
 * the repo's per-file line ceiling; every symbol here has exactly one
 * definition, in the .c file its stage number lives in. */

#ifndef ZCL_TEST_SYNC_THROUGHPUT_INTERNAL_H
#define ZCL_TEST_SYNC_THROUGHPUT_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* Fixed fixture shape, shared by the block fixture (S1-S4) and the flat
 * synthetic chain fixture (S6-S7). */
#define ST_FIXTURE_BLOCKS 32u
#define ST_FIXED_TIME 1700000000u
#define ST_FLAT_ROWS 8192
#define ST_FLAT_READS 256

/* Every call site's enclosing scope holds `int *failures` (a stage helper
 * parameter), never a plain int: "failures++" here would bump the
 * pointer, not the count, so a failed tooth is silently dropped and a
 * later `*failures` read is now past the real counter. Dereference it. */
#define ST_CHECK(name, expr) do {             \
    printf("  %s... ", (name));               \
    if ((expr)) printf("OK\n");               \
    else { printf("FAIL\n"); (*failures)++; } \
} while (0)

/* test_sync_throughput.c: block fixture lifecycle (S1-S4). */
bool st_build_fixture(void);
void st_free_fixture(void);

/* test_sync_throughput.c: shared timing helpers, used by every stage in
 * both files. */
double st_per_s(uint64_t ops, uint64_t elapsed_us);
bool st_check_ceiling_us(const char *label, uint64_t measured_us,
                         uint64_t nominal_us, int *failures);
bool st_check_floor_per_s(const char *label, double measured_per_s,
                          double nominal_per_s, int *failures);

/* test_sync_throughput.c: S1-S5 stages. */
double st_stage_header_roundtrip(int *failures);
double st_stage_pow_verify(int *failures);
double st_stage_merkle(int *failures);
double st_stage_check_block(int *failures);
double st_stage_range_plan(int *failures);

/* test_sync_throughput_index.c: S6-S7 stages. */
double st_stage_flat_reads(int *failures);
double st_stage_forward_order(int *failures);

#endif /* ZCL_TEST_SYNC_THROUGHPUT_INTERNAL_H */
