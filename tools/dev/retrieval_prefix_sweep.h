/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Replay six relevance-free prefixes over frozen retrieval evidence. */

#ifndef ZCL_RETRIEVAL_PREFIX_SWEEP_H
#define ZCL_RETRIEVAL_PREFIX_SWEEP_H

/* checker, retrieval-eval, jsonq, agent_sha3, the frozen receipt, and the
 * sweep source whose bytes are hashed into the receipt. argc/argv must be
 * exactly one "--check". 0 when the transcript and summary were written. */
struct zcl_rx_tools {
    const char *checker;
    const char *evaluator;
    const char *jsonq;
    const char *sha3;
    const char *receipt;
    const char *sweep_source;
};

int zcl_retrieval_prefix_sweep(const char *argv0, int argc, char **argv,
                               const struct zcl_rx_tools *tools);

#endif
