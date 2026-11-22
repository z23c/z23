/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize_parts - per-part timers for tip_finalize_run_post_finalize.
 *
 * The reducer stage profile has one counter for the whole post-finalize step
 * (RPF_TF_POST_FINALIZE_US) and no free field to split it. This engine-side
 * module times each part so the slow one can be named. It is observation
 * only: it reads the monotonic clock at part boundaries and bumps relaxed
 * atomics; it changes no ordering, lock, wallet or chain state.
 *
 * One sample is one finalized block: the caller accumulates a part's time
 * across the block's transactions in a stack struct, then publishes once.
 * Read it with `z23 ops state --subsystem=tip_finalize_parts`. */

#ifndef ZCL_JOBS_TIP_FINALIZE_PARTS_H
#define ZCL_JOBS_TIP_FINALIZE_PARTS_H

#include <stdbool.h>
#include <stdint.h>

struct json_value;

enum tip_finalize_part {
    TF_PART_BODY_ACQUIRE,      /* stage_acquire_block_view */
    TF_PART_WALLET_SYNC,       /* wallet_sync_transaction loop */
    TF_PART_CONFIRM_ENQUEUE,   /* node_db wallet-confirmation enqueue */
    TF_PART_SAPLING_DECRYPT,   /* wallet_try_sapling_decrypt */
    TF_PART_NOTE_DB,           /* note copy + node_db note sync + zmsg */
    TF_PART_NULLIFIERS,        /* wallet_mark_sapling_nullifiers_spent */
    TF_PART_WITNESS_BIRTHDAY,  /* witness enqueue + birthday reconcile */
    TF_PART_RECONCILE_BLOCK,   /* coins cache + mempool, under cs_main */
    TF_PART_MMR_APPEND,        /* MMR append */
    TF_PART_MMB_APPEND,        /* MMB leaf (+ boundary UTXO fold) */
    TF_PART_COUNT
};

/* Index of the whole-step sample accepted by tip_finalize_parts_stat. */
#define TF_PART_TOTAL ((int)TF_PART_COUNT)

/* Per-call accumulator, owned by the caller's stack. A NULL pointer disables
 * timing: the start/add helpers then read no clock at all. */
struct tip_finalize_parts_block {
    uint64_t ns[TF_PART_COUNT];
    uint32_t ran;
};

/* Monotonic ns now, or 0 when `b` is NULL. */
int64_t tip_finalize_parts_start(const struct tip_finalize_parts_block *b);

/* Add (now - t0_ns) to `part` and mark it as having run. NULL `b` is a no-op. */
void tip_finalize_parts_add(struct tip_finalize_parts_block *b,
                            enum tip_finalize_part part, int64_t t0_ns);

/* Record one block: every part that ran, plus the whole step since `t0_ns`. */
void tip_finalize_parts_publish(const struct tip_finalize_parts_block *b,
                                int64_t t0_ns);

struct tip_finalize_part_stat {
    uint64_t count;     /* blocks in which the part ran */
    uint64_t total_us;
    uint64_t max_us;
    uint64_t p50_us;    /* log2-bucket upper bound, as the stage profile */
    uint64_t p95_us;
};

/* part is an enum tip_finalize_part or TF_PART_TOTAL. False when out of range. */
bool tip_finalize_parts_stat(int part, struct tip_finalize_part_stat *out);

const char *tip_finalize_parts_name(int part);

/* Zero every counter (tests). */
void tip_finalize_parts_reset(void);

/* `ops state` dumper: {schema, parts{name:{count,total_us,mean_us,max_us,
 * p50_us,p95_us}}, total{...}, parts_sum_us, unaccounted_us}. `key` ignored. */
bool tip_finalize_parts_dump_state_json(struct json_value *out,
                                        const char *key);

#endif /* ZCL_JOBS_TIP_FINALIZE_PARTS_H */
