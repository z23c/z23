/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared decls between check-macos-acceptance's gate body and its
 * --selftest sibling.
 */
#ifndef GATE_MACOS_ACCEPTANCE_PRIV_H
#define GATE_MACOS_ACCEPTANCE_PRIV_H

#include <stddef.h>

enum { MAC_PRIV_OUT = 4096 };
struct mac_result { char out[MAC_PRIV_OUT]; int rc; };

void mac_validate_pub(const char *matrix_path, const char *catalog_path,
                      struct mac_result *r);
int mac_make_target_reachable_pub(const char *makefile_path);
int mac_runtime_package_reachable_text_pub(const char *accept_text);

/* Shared between the gate body (gate_macos_acceptance.c) and the parser
 * (gate_macos_acceptance_parse.c): row/registry types and sizes, and the
 * load/lookup functions over them. */
enum { MAC_MAXROWS = 64, MAC_ID = 64, MAC_STATE = 32, MAC_REASON = 256,
      MAC_GROUPS = 2048 };
enum { MAC_MAXREQ = 64, MAC_MAXREG = 4096, MAC_REG = 128 };
enum { MAC_MAXUNION = 128 };

struct mac_row { char id[MAC_ID], state[MAC_STATE], reason[MAC_REASON],
                 groups[MAC_GROUPS]; };
struct mac_rows { struct mac_row r[MAC_MAXROWS]; int n; };
struct mac_names { char n[MAC_MAXREQ][MAC_ID]; int n_used; };
struct mac_reg { char n[MAC_MAXREG][MAC_REG]; int n_used; };
struct mac_union { char n[MAC_MAXUNION][MAC_ID]; int n_used; };

int mac_slurp(const char *path, char *buf, size_t cap);
void mac_strip_ws(const char *in, char *out, size_t cap);
int mac_load_rows(const char *matrix_text, struct mac_rows *out);
void mac_split_row(const char *raw, struct mac_row *out);
int mac_load_required(const char *matrix_text, struct mac_names *out);
int mac_load_registered(const char *catalog_text, struct mac_reg *out);
int mac_reg_has(const struct mac_reg *reg, const char *name);
void mac_join_sorted(const char names[][MAC_ID], int n, int dedup,
                     char *out, size_t cap, const char *sep);
void mac_union_add(struct mac_union *u, const char *name);

#endif
