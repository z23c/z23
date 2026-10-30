/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declaration of the check-doc-accuracy gate body, used by
 * its --selftest fixture driver (gate_doc_accuracy_selftest.c).
 */
#ifndef GATE_DOC_ACCURACY_PRIV_H
#define GATE_DOC_ACCURACY_PRIV_H
#include <stdio.h>

/* Shared entry used by the selftest fixture driver. Returns 0 pass,
 * 1 lint fail (report already printed to out), 2 fatal. */
int da_check_root(const char *root, FILE *out);

#endif
