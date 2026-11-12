/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Replay frozen context-only retrieval profiles and emit the sweep receipt. */

#ifndef ZCL_RETRIEVAL_PROFILE_SWEEP_H
#define ZCL_RETRIEVAL_PROFILE_SWEEP_H

/* Paths are the checker, retrieval-eval, jsonq, agent_sha3, the frozen
 * receipt, and the sweep source file whose bytes are hashed into the
 * receipt. argc/argv must be exactly one "--check" argument. 0 when the
 * transcript and the summary line were written. */
struct zcl_rps_tools {
    const char *checker;
    const char *evaluator;
    const char *jsonq;
    const char *sha3;
    const char *receipt;
    const char *sweep_source;
};

int zcl_retrieval_profile_sweep(const char *argv0, int argc, char **argv,
                                const struct zcl_rps_tools *tools);

#endif
