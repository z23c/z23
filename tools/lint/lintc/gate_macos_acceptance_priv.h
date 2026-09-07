/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared decls between check-macos-acceptance's gate body and its
 * --selftest sibling.
 */
#ifndef GATE_MACOS_ACCEPTANCE_PRIV_H
#define GATE_MACOS_ACCEPTANCE_PRIV_H

enum { MAC_PRIV_OUT = 4096 };
struct mac_result { char out[MAC_PRIV_OUT]; int rc; };

void mac_validate_pub(const char *matrix_path, const char *catalog_path,
                      struct mac_result *r);
int mac_make_target_reachable_pub(const char *makefile_path);
int mac_runtime_package_reachable_text_pub(const char *accept_text);

#endif
