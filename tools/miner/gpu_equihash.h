/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Declares the bounded native GPU interface for Equihash solving. */
#ifndef Z23_TOOLS_GPU_EQUIHASH_H
#define Z23_TOOLS_GPU_EQUIHASH_H

#include "crypto/blake2b.h"
#include "crypto/equihash.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define Z23_GPU_EQUIHASH_SOLUTION_BYTES 400u

struct z23_gpu_equihash;

struct z23_gpu_equihash_device {
    char platform[128];
    char vendor[128];
    char name[256];
    uint64_t global_memory_bytes;
    uint64_t max_allocation_bytes;
    uint32_t compute_units;
};

struct z23_gpu_equihash_stats {
    uint64_t elapsed_us;
    uint64_t initial_hash_us;
    uint64_t collision_round_us[7];
    uint32_t candidates;
    uint32_t valid_solutions;
};

/* Opens the best available GPU and JITs the bounded OpenCL C kernels. The
 * driver turns those kernels into native GPU assembly for the selected card.
 * No OpenCL SDK or import library is required at build or run time. */
struct z23_gpu_equihash *z23_gpu_equihash_open(
    struct z23_gpu_equihash_device *device,
    char *error, size_t error_cap);

/* Solves one N=192,K=7 Equihash nonce. `base_state` is the exact state after
 * the 108-byte pre-solution header and 32-byte nonce have been absorbed.
 * Returned bytes are independently checked by the existing portable C23
 * consensus verifier before success is reported. */
bool z23_gpu_equihash_solve(
    struct z23_gpu_equihash *gpu,
    const struct equihash_params *params,
    const struct blake2b_ctx *base_state,
    unsigned char solution[Z23_GPU_EQUIHASH_SOLUTION_BYTES],
    struct z23_gpu_equihash_stats *stats,
    char *error, size_t error_cap);

void z23_gpu_equihash_close(struct z23_gpu_equihash *gpu);

#endif
