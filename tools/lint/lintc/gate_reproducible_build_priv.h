/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the check-reproducible-build gate
 * (gate_reproducible_build.c, _env.c, _diag.c and the selftest).
 */
#ifndef GATE_REPRODUCIBLE_BUILD_PRIV_H
#define GATE_REPRODUCIBLE_BUILD_PRIV_H
#include <stddef.h>
#include <stdio.h>

/* The PATH every child build and every gate-spawned tool resolves against. */
#define RPB_PATH "/usr/bin:/bin"

enum { RP_PATH = 16384, RP_ARG = RP_PATH + 32, RP_LOAD = 4 * RP_PATH,
       RP_HASH = 256, RP_SDE = 64, RP_ENVN = 512, RP_ENVL = 1200 };

enum { RPB_OUT_PIPE = 0, RPB_OUT_STDERR = 1, RPB_OUT_BOTH = 2 };

struct rpb_vars {
    char sde[RP_SDE];
    char cflags[RP_PATH];
    char ldflags[RP_PATH];
};

struct rpb_env {
    char forced[8][RP_ENVL];   /* the pinned entries; caller entries stay pointers */
    char *ptr[RP_ENVN + 1];
};

void rpb_info(FILE *out, const char *msg);
void rpb_ok(FILE *out, const char *msg);
void rpb_err(const char *msg);

/* Pure: the child environment from a caller environment (forced keys win). */
int rpb_child_env(char *const src[], struct rpb_env *e);
int rpb_env_get(const struct rpb_env *e, const char *key, char *out, size_t cap);
int rpb_resolve(const char *prog, char *out, size_t cap);

int rpb_spawn(char *const argv[], char *const envp[], int mode, char *out,
              size_t cap, int *code);
/* Build the gate into <root>; buildcmd (selftest only, NULL otherwise) replaces
 * the make step and is run as <buildcmd> <build_dir> <binary>. */
int rpb_run_root(const char *root, FILE *out, const char *buildcmd);
int rpb_profile_parse(char *buf, struct rpb_vars *v);
int rpb_cmp_files(const char *a, const char *b);
int rpb_diag(FILE *err, char *const envp[], const char *bin_a,
             const char *bin_b, const char *hash_a, const char *hash_b,
             const char *algo, const char *binary, long sa, long sb,
             const char *work);

#endif
