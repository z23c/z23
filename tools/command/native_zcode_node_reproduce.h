/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * native_zcode_node_reproduce.h — the "produce bytes" half of
 * `z23 zcode node verify`, in process. Implemented in
 * tools/command/native_zcode_node_reproduce.c; it replaces the former
 * shell script, with the same receipt and exit codes. */

#ifndef ZCL_NATIVE_ZCODE_NODE_REPRODUCE_H
#define ZCL_NATIVE_ZCODE_NODE_REPRODUCE_H

#include <stddef.h>

struct zcl_node_reproduce_request {
    const char *source_dir; /* checkout to build; must hold a Makefile */
    const char *scratch_dir; /* isolated root; build goes in <scratch>/build */
    const char *out_path; /* receipt to write (zcl.node_repro_receipt.v1) */
    const char *profile; /* "default" or "release" */
    int jobs; /* build parallelism, >= 1 */
    int timeout_s; /* per-subprocess deadline, > 0 seconds */
};

/* Build z23 once from source_dir and write the receipt to out_path.
 * Returns 0 when the receipt was written, 2 for a usage or prerequisite
 * refusal (nothing was built), and 1 for a build failure or an I/O failure
 * (no receipt was written). `log` receives a bounded tail of the build
 * output (or a diagnostic) and may be NULL when log_cap is 0. */
int zcl_native_node_reproduce(const struct zcl_node_reproduce_request *req,
                              char *log, size_t log_cap);

#endif
