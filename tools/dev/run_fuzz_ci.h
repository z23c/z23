/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Run libFuzzer harnesses for one slot and fail a weak rate. */

#ifndef ZCL_RUN_FUZZ_CI_H
#define ZCL_RUN_FUZZ_CI_H

/* argv is slot, wall, floor, print_funcs, leaks, then harness paths.
 * Wall "auto" or empty is the slot plus 60. leaks "1" turns leak
 * detection on. Returns 2 when no harness is named, the harness status
 * when one exits nonzero, 1 when a rate is under the floor, else 0. */
int zcl_run_fuzz_ci(int argc, char **argv);

#endif
