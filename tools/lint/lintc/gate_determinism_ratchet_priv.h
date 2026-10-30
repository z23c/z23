/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the check-determinism-ratchet gate and
 * its selftest (gate_determinism_ratchet.c, gate_determinism_ratchet_
 * selftest.c). No heap anywhere in this gate: fixed static arrays only.
 */
#ifndef Z23_GATE_DETERMINISM_RATCHET_PRIV_H
#define Z23_GATE_DETERMINISM_RATCHET_PRIV_H

#include <stdio.h>

int dtr_check_root(const char *root, FILE *out);
int dtr_run(const char *file, char *const argv[], char *out, size_t cap,
            int *st);
extern const char k_dtr_baseline_rel[];
extern const char k_dtr_catalog_rel[];

#endif
