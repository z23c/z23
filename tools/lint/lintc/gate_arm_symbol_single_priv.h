/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared decls between the check-arm-symbol-single family files: the
 * analyzer emits one (name, line, is_static) callback per non-static-vs-
 * static top-level function DEFINITION it finds in one file.
 */
#ifndef GATE_ARM_SYMBOL_SINGLE_PRIV_H
#define GATE_ARM_SYMBOL_SINGLE_PRIV_H

typedef int (*asy_emit_fn)(const char *file, void *ctx, const char *name,
                           int line, int is_static);

int asy_analyze_file(const char *path, asy_emit_fn emit, void *ctx);

/* The gate body, exposed (not static) so --selftest's coverage probes can
 * re-invoke it in-process under a modified environment — the port's
 * spawn-free replacement for the shell original's `env VAR=val "$self"`
 * self-re-exec (same effect: run the real gate under a perturbed
 * environment and read its exit code), with stdout/stderr redirected to
 * the selftest's own sandbox log rather than a subprocess's. */
int asy_run(void);

#endif
