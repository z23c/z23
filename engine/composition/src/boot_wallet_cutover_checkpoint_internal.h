/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: boot-only advisory DISCOVER checkpoint. */
#ifndef Z23_BOOT_WALLET_CUTOVER_CHECKPOINT_INTERNAL_H
#define Z23_BOOT_WALLET_CUTOVER_CHECKPOINT_INTERNAL_H
#include <stdbool.h>
struct boot_cutover_replay;
enum boot_discover_resume { BOOT_DISCOVER_FLOOR, BOOT_DISCOVER_RESUMED, BOOT_DISCOVER_BUSY, BOOT_DISCOVER_RETRY };
enum boot_discover_save { BOOT_DISCOVER_SAVED, BOOT_DISCOVER_SAVE_BUSY, BOOT_DISCOVER_SAVE_RETRY };
struct wallet_discover_checkpoint;
bool boot_wallet_discover_checkpoint_prepare(struct boot_cutover_replay *r,
    struct wallet_discover_checkpoint *checkpoint);
enum boot_discover_save boot_wallet_discover_checkpoint_save(struct boot_cutover_replay *r,
    struct wallet_discover_checkpoint *checkpoint);
enum boot_discover_resume boot_wallet_discover_checkpoint_resume(struct boot_cutover_replay *r);
#if defined(ZCL_TESTING) && !defined(_WIN32)
void boot_wallet_discover_checkpoint_test_before_commit(void (*fn)(void *), void *ctx);
void boot_wallet_discover_checkpoint_test_after_commit(void (*fn)(void *), void *ctx);
void boot_wallet_discover_checkpoint_test_fail_open(bool fail);
#endif
#endif
