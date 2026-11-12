/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Born-green, born-red, and exact-revert proof for source-bundle policy. */

#ifndef ZCL_REFLEX_HOTFORK_SOURCE_BUNDLE_H
#define ZCL_REFLEX_HOTFORK_SOURCE_BUNDLE_H

/* Drives z23-dev through one green edit, one semantic mutant, and the exact
 * revert of tools/command/native_zcode_source_bundle_command.c. ZCL_SOURCE_ROOT,
 * ZCL_DEV_BIN, and ZCL_REFLEX_SOURCE_BUNDLE_ACCEPTANCE_OUTPUT select the
 * checkout, the dev binary, and the receipt. Returns 0 after PASS. A usage
 * or bound failure returns 2. A failing dev command returns that command's
 * status. The owner file is restored on every return and on SIGINT/SIGTERM. */
int zcl_reflex_hotfork_source_bundle(void);

/* Same journey for contexts/commons/modules/vcs/src/source_package_transport.c.
 * ZCL_REFLEX_TRANSPORT_ACCEPTANCE_OUTPUT selects the receipt. */
int zcl_reflex_hotfork_transport(void);

#endif
