/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declarations for check-no-live-lab-history (gate and selftest).
 */
#ifndef NLLH_PRIV_H
#define NLLH_PRIV_H

#include <stdio.h>
#include <stddef.h>

#define NLLH_PLEN 1024
#define NLLH_NPATHS 65536
#define NLLH_CAP ((size_t)4 << 20)

extern const char nllh_lab_baseline[];
extern const char nllh_micro_baseline[];
extern const char nllh_micro_header[];

int nllh_check_paths(const char *root, const char *const *paths, size_t n,
                     FILE *err);

#endif
