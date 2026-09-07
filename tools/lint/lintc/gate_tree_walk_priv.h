/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations between the tree-walk lint family run file
 * and its selftest sibling (gate_tree_walk.c / gate_tree_walk_selftests.c).
 */
#ifndef GATE_TREE_WALK_PRIV_H
#define GATE_TREE_WALK_PRIV_H

#include <regex.h>
#include <stddef.h>

int hs_dl_comp(regex_t *re);
int hs_scan_text(const char *text, const char *path, const regex_t *re,
                 char *buf, size_t cap, size_t *used);
void cbf_sym(char *buf, size_t cap);
extern const char k_cbf_def[];
extern const char k_cbf_allow[];

#endif
