/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declarations for the check_hotswap_module_imports port
 * (gate_hotswap_module_imports.c and its selftest). No heap: all state is
 * fixed-size static storage, sized generously over the measured tree
 * (282 allowlist rows, 547 capability rows).
 */
#ifndef GATE_HOTSWAP_MODULE_IMPORTS_PRIV_H
#define GATE_HOTSWAP_MODULE_IMPORTS_PRIV_H

#include <stddef.h>
#include <stdio.h>

enum {
    HMI_PATH = 1024,
    HMI_SYM = 160,
    HMI_GRP = 48,
    HMI_LINE = 1024,
    HMI_ROWS = 512,        /* allowlist rows (real: 282, floor 100) */
    HMI_CAP_LINES = 2048,  /* physical lines of capability_symbols.def */
    HMI_CAPROWS = 2048,    /* ZCL_CAPABILITY_SYMBOL rows (real: 547) */
    HMI_SEEN = 4096,       /* distinct imports seen across modules */
    HMI_SOS = 256,         /* module .so files in one directory */
    HMI_TXT = 65536,       /* subprocess capture buffer */
    HMI_STEXT = 16384,     /* selftest captured-output buffer */
    HMI_IMPORT_FLOOR = 100,
    HMI_CLASS_VOCAB_FLOOR = 5,
    HMI_CAPABILITY_CROSS_FLOOR = 30,
};

/* Mach-O/Lloader-symbol canonicalization; empty string for dyld plumbing. */
void hmi_canonical(const char *raw, int darwin, char *out, size_t cap);

/* fork+execvp with an argv array; captures stdout (and stderr when
 * merge_err) into out[cap]. Returns 0 and sets *code to the exit status;
 * -2 when the output did not fit (truncated), -1 when it could not spawn. */
int hmi_spawn_argv(char *const argv[], int merge_err, char *out, size_t cap,
                   size_t *olen, int *code);

/* The whole gate against the env-resolved def/capfile/classfile/so-dir.
 * Returns the shell exit code: 0 clean (or UNOBSERVED), 1 violation,
 * 2 could-not-look. Honors the selftest-only override env vars exactly as
 * the shell original did, including their stray/outside refusals. */
int hmi_run_core(FILE *out, FILE *err);

#endif
