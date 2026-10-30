/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declarations for the check_fuzz_artifact_replay gate parts:
 * gate_fuzz_artifact_replay.c (entry + shared helpers),
 * gate_fuzz_artifact_replay_struct.c (kinds / ledger / enumeration /
 * structural checks) and gate_fuzz_artifact_replay_replay.c (the replay
 * half). Ported from tools/lint/check_fuzz_artifact_replay.sh (deleted);
 * selftest in gate_fuzz_artifact_replay_selftest.c.
 */
#ifndef GATE_FUZZ_ARTIFACT_REPLAY_PRIV_H
#define GATE_FUZZ_ARTIFACT_REPLAY_PRIV_H
#include <stddef.h>
#include <stdio.h>

enum {
    FAR_PATH = 1024, FAR_NAME = 512, FAR_VERD = 64, FAR_DATE = 32,
    FAR_REASON = 1024, FAR_KIND = 48, FAR_ST = 16,
    FAR_KINDS = 64, FAR_LEDGER = 1024, FAR_ARTIFACTS = 1024,
    FAR_NEARMISS = 512, FAR_CORPORA = 256, FAR_SEL = 1024
};

struct far_ledger_ent {
    char file[FAR_NAME];
    char verdict[FAR_VERD];
    char date[FAR_DATE];
    char reason[FAR_REASON];
    int seen;
};

struct far_ctx {
    FILE *out, *err;
    char root[FAR_PATH];
    int ledger_only, selftest;
    char only_corpora[FAR_CORPORA];
    const char *mode;
    int replay_timeout, confirm_timeout, jobs;
    char bin_dir[FAR_PATH], pi_bin_dir[FAR_PATH];
    char kinds[FAR_KINDS][FAR_KIND];
    int n_kinds;
    struct far_ledger_ent ledger[FAR_LEDGER];
    int n_ledger;
    char artifacts[FAR_ARTIFACTS][FAR_NAME];
    char kind_of[FAR_ARTIFACTS][FAR_KIND];
    unsigned char untracked_of[FAR_ARTIFACTS];
    int n_artifacts;
    char nearmiss[FAR_NEARMISS][FAR_NAME];
    int n_nearmiss;
    int violations;
};

/* gate_fuzz_artifact_replay.c */
extern const char k_far_gate[];
extern const char k_far_seed_root[];
extern const char k_far_ledger[];
int check_fuzz_artifact_replay_selftest(void);
int far_report(struct far_ctx *c, const char *fmt, ...);
void far_note(struct far_ctx *c, const char *fmt, ...);
int far_floor(struct far_ctx *c, int count, int flr, const char *hint);
int far_ledger_find(const struct far_ctx *c, const char *rel);
int far_kind_has(const struct far_ctx *c, const char *k);
int far_has_ci(const char *hay, const char *needle);
int far_reason_named_fix(const char *r);
int far_reason_pattern_init(const char *r);
int far_kind_needs_pi(const char *kind);
int far_regression_sufficient(const char *kind, const char *r);
void far_today_utc(char *dst, size_t cap);
int far_check(struct far_ctx *c);
int far_main(int argc, char **argv, FILE *out, FILE *err);

/* gate_fuzz_artifact_replay_struct.c */
int far_load_kinds(struct far_ctx *c);
int far_load_ledger(struct far_ctx *c);
int far_enumerate(struct far_ctx *c);
int far_structural(struct far_ctx *c);
int far_spawn_cap(char *const argv[], int quiet_err, char *out, size_t cap,
                  size_t *len, int *code);

/* gate_fuzz_artifact_replay_replay.c */
int far_replay_phase(struct far_ctx *c);
#endif
