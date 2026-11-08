/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: boot-only advisory DISCOVER checkpoint. */
#ifndef Z23_BOOT_WALLET_CUTOVER_CHECKPOINT_INTERNAL_H
#define Z23_BOOT_WALLET_CUTOVER_CHECKPOINT_INTERNAL_H
#include <stdbool.h>
#include <stdint.h>
struct boot_cutover_replay;
enum boot_discover_resume { BOOT_DISCOVER_FLOOR, BOOT_DISCOVER_RESUMED, BOOT_DISCOVER_BUSY, BOOT_DISCOVER_RETRY, BOOT_DISCOVER_STOPPED };
enum boot_discover_save { BOOT_DISCOVER_SAVED, BOOT_DISCOVER_SAVE_BUSY, BOOT_DISCOVER_SAVE_RETRY, BOOT_DISCOVER_SAVE_STOPPED };
enum boot_discover_prepare { BOOT_DISCOVER_PREPARED, BOOT_DISCOVER_PREPARE_FAILED, BOOT_DISCOVER_PREPARE_STOPPED };
struct wallet_discover_checkpoint;
bool boot_wallet_discover_checkpoint_prepare(struct boot_cutover_replay *r,
    struct wallet_discover_checkpoint *checkpoint);
enum boot_discover_prepare boot_wallet_discover_checkpoint_prepare_result(struct boot_cutover_replay *r,
    struct wallet_discover_checkpoint *checkpoint);
enum boot_discover_save boot_wallet_discover_checkpoint_save(struct boot_cutover_replay *r,
    struct wallet_discover_checkpoint *checkpoint);
enum boot_discover_resume boot_wallet_discover_checkpoint_resume(struct boot_cutover_replay *r);
#if defined(ZCL_TESTING) && !defined(_WIN32)
void boot_wallet_discover_checkpoint_test_before_commit(void (*fn)(void *), void *ctx);
void boot_wallet_discover_checkpoint_test_after_commit(void (*fn)(void *), void *ctx);
void boot_wallet_discover_checkpoint_test_fail_open(bool fail);
void boot_wallet_discover_checkpoint_test_after_digest(void (*fn)(void *), void *ctx);
void boot_wallet_discover_checkpoint_test_digest_poll(void (*fn)(void *), void *ctx);
void boot_wallet_discover_checkpoint_test_before_cancel(void (*fn)(void *), void *ctx);
void boot_wallet_discover_checkpoint_test_fail_rollback(bool fail);
bool boot_wallet_discover_checkpoint_test_digest_failed(struct boot_cutover_replay *r, uint64_t end);
#endif
#endif
