/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: alias expansion for `code have` query terms (acronyms, synonyms).
 */
#ifndef CODEINDEX_CAPABILITY_ALIAS_H
#define CODEINDEX_CAPABILITY_ALIAS_H

#include "codeindex/codeindex_capability.h"

/* Hard bound on stems (query terms plus aliases); masks are 32 bits wide. */
#define CI_CAP_STEM_CAP 32

/* Lay out `base` (already stemmed, nbase terms) into `stems`: the first nbase
 * entries are the base terms, then alias stems. grp[i] is the index of the
 * base term stem i stands for, so an alias match counts as its term. Returns
 * the number of stems written, at most CI_CAP_STEM_CAP. */
int ci_cap_alias_expand(const char base[][CI_CAPABILITY_TERM_MAX], int nbase,
                        char stems[][CI_CAPABILITY_TERM_MAX],
                        unsigned char *grp);

#endif
