/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Born-green, unrelated-edit, born-red, and exact-revert proof for
 *          the shop status and reputation views. */

#ifndef ZCL_REFLEX_HOTFORK_SHOP_H
#define ZCL_REFLEX_HOTFORK_SHOP_H

/* Drives z23-dev through one green edit, one unrelated edit, one semantic
 * mutant, and the exact revert of shop_native_handler.c. ZCL_SOURCE_ROOT,
 * ZCL_DEV_BIN, and ZCL_REFLEX_SHOP_STATUS_ACCEPTANCE_OUTPUT select the
 * checkout, the dev binary, and the receipt. Returns 0 after PASS. A usage
 * or bound failure returns 2. A failing dev command returns that command's
 * status. Both edited files are restored on every return. */
int zcl_reflex_hotfork_shop_status(void);

/* Same journey for shop_native_reputation.c.
 * ZCL_REFLEX_SHOP_REPUTATION_ACCEPTANCE_OUTPUT selects the receipt. */
int zcl_reflex_hotfork_shop_reputation(void);

/* Same journey for tools/command/native_zcode_work_command.c.
 * ZCL_REFLEX_ZCODE_WORK_ACCEPTANCE_OUTPUT selects the receipt.
 * The semantic mutant flips the one memcmp equality in that owner. */
int zcl_reflex_hotfork_zcode_work(void);

#endif
