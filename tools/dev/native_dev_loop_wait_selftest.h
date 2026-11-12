/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove dev loop wait against one sealed private verdict. */

#ifndef ZCL_NATIVE_DEV_LOOP_WAIT_SELFTEST_H
#define ZCL_NATIVE_DEV_LOOP_WAIT_SELFTEST_H

/* bin NULL uses ZCL_DEV_LOOP_TEST_BIN, then <root>/build/bin/zclassic23-dev.
 * root NULL is this checkout. 0 when the contract holds. 2 when the dev
 * binary is missing. 1 when a check fails. */
int zcl_native_dev_loop_wait_selftest(const char *bin, const char *root);

#endif
