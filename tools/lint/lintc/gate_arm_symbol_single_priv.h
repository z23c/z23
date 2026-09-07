/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared decls between the check-arm-symbol-single family files: the
 * analyzer emits one (name, line, is_static) callback per non-static-vs-
 * static top-level function DEFINITION it finds in one file.
 */
#ifndef GATE_ARM_SYMBOL_SINGLE_PRIV_H
#define GATE_ARM_SYMBOL_SINGLE_PRIV_H

#include <stddef.h>

typedef int (*asy_emit_fn)(const char *file, void *ctx, const char *name,
                           int line, int is_static);

int asy_analyze_file(const char *path, asy_emit_fn emit, void *ctx);

/* Shared between the gate body (gate_arm_symbol_single.c) and the
 * coverage oracle (gate_arm_symbol_single_coverage.c): the scanned-file
 * set type, the default root list, and the gate's display name. */
enum { ASY_MAXROOTS = 16, ASY_ROOT = 128 };
enum { ASY_MAXFILES = 8192, ASY_PATH = 384 };
enum { ASY_NROOTS_DEFAULT = 6 };

struct asy_files { char p[ASY_MAXFILES][ASY_PATH]; int n; };

extern const char k_asy_gate[];
extern const char *const k_asy_roots_default[];

int asy_files_add(struct asy_files *fs, const char *path);
void asy_sort_files(struct asy_files *fs);
int asy_coverage(const struct asy_files *scanned, int allowance);

/* The gate body, exposed (not static) so --selftest's coverage probes can
 * re-invoke it in-process under a modified environment — the port's
 * spawn-free replacement for the shell original's `env VAR=val "$self"`
 * self-re-exec (same effect: run the real gate under a perturbed
 * environment and read its exit code), with stdout/stderr redirected to
 * the selftest's own sandbox log rather than a subprocess's. */
int asy_run(void);

#endif
