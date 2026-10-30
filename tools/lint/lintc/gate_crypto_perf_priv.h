/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the check-crypto-perf gate
 * (gate_crypto_perf.c, gate_crypto_perf_eval.c, gate_crypto_perf_usage.c)
 * and its selftest (gate_crypto_perf_selftest.c). Ported from
 * tools/scripts/check_crypto_perf.sh (deleted).
 */
#ifndef GATE_CRYPTO_PERF_PRIV_H
#define GATE_CRYPTO_PERF_PRIV_H
#include <stddef.h>
#include <stdio.h>

enum {
    CCP_RAW = 65536,
    CCP_KEYS = 128,
    CCP_KEY = 64,
    CCP_NS = 32,
    CCP_LINE = 1024,
    CCP_ENV = 512,
    CCP_PATH = 1024,
    CCP_NUM = 400,
};

enum ccp_verdict {
    CCP_OK_BEAT,
    CCP_OK_BEHIND,
    CCP_FAIL_RATCHET,
    CCP_FAIL_BEAT,
    CCP_FAIL_CONFIG,
};

struct ccp_meas {
    char key[CCP_KEY];
    char ns[CCP_NS];
};

struct ccp_opts {
    const char *binary;
    const char *baseline;
    const char *margin;
    const char *bench_file; /* selftest only: bench output read from a file */
    const char *history;
    FILE *out;
    FILE *err;
};

/* Verdict of one baseline row. Returns a ccp_verdict, or -1 when a derived
 * value could not be formatted. ratio receives the printed ratio, which is
 * empty where the script's awk divided by zero. */
int ccp_eval_row(const char *meas, const char *cbase, const char *rust,
                 const char *mode, const char *margin, char *ratio,
                 size_t rcap);
int ccp_is_number(const char *s);
const char *ccp_verdict_name(int v);
const char *ccp_verdict_tag(int v);
int ccp_core(const struct ccp_opts *o);
void ccp_usage(FILE *out);
int check_crypto_perf_selftest(void);

#endif
