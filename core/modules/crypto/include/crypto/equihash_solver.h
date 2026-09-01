/* Copyright (c) 2016 John Tromp, The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Equihash solver — pure C23 port of Tromp's bucket-based Wagner algorithm.
 * Supports N=192, K=7 (ZClassic post-fork parameters). */

#ifndef ZCL_CRYPTO_EQUIHASH_SOLVER_H
#define ZCL_CRYPTO_EQUIHASH_SOLVER_H

#include "crypto/blake2b.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define EH_N            192
#define EH_K            7
#define EH_DIGITBITS    24
#define EH_RESTBITS     4
#define EH_BUCKBITS     20
#define EH_NBUCKETS     (1u << EH_BUCKBITS)
#define EH_SLOTBITS     6
#define EH_NSLOTS       64
#define EH_SLOTMASK     63
#define EH_PROOFSIZE    128
#define EH_NHASHES      (2u << EH_DIGITBITS)
#define EH_HASHPERBLAKE 2
#define EH_HASHOUT      48
#define EH_NBLOCKS      (EH_NHASHES / EH_HASHPERBLAKE)
#define EH_MAXSOLS      8
#define EH_HASHWORDS0   6
#define EH_HASHWORDS1   5
#define EH_SLOT0_WORDS  7
#define EH_SLOT1_WORDS  6
#define EH_NRESTS       16
#define EH_XFULL        16
#define EH_SOL_BYTES    400

struct eh_solver {
    uint32_t *heap0;
    uint32_t *heap1;
    uint32_t *nslot_counts;
    uint32_t sols[EH_MAXSOLS][EH_PROOFSIZE];
    uint32_t nsols;
    uint32_t xfull;
    uint32_t hfull;
    uint32_t bfull;
    struct blake2b_ctx blake_ctx;
};

struct eh_solver *eh_solver_new(void);
void eh_solver_free(struct eh_solver *s);
void eh_solver_set_state(struct eh_solver *s, const struct blake2b_ctx *ctx);
uint32_t eh_solver_run(struct eh_solver *s);

#endif
