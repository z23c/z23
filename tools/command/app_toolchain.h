/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: Verified compiler-kit identity and request-owned sealed inputs. */
#ifndef ZCL_APP_TOOLCHAIN_H
#define ZCL_APP_TOOLCHAIN_H
#include "platform/os_sandbox.h"
#include "vcs/vcs_manifest.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define APP_TOOLCHAIN_DESCRIPTOR "app-toolchain.json"
#define APP_TOOLCHAIN_BUNDLE "app-toolchain.bundle"
#define APP_TOOLCHAIN_SCHEMA "zcl.app_toolchain.v1"
#define APP_TOOLCHAIN_POLICY "zcl.app_toolchain.linux_sealed.v1"
struct app_toolchain {
    bool selected;
    uint8_t tree[32], bundle_hash[32], env[32];
    char target[64];
    struct vcs_manifest manifest;
    struct os_sandbox_kit_file *files;
    size_t file_count;
    int backing_fd; bool backing_owned; size_t backing_size;
    uint8_t *bundle;
    size_t bundle_size;
};
void app_toolchain_free(struct app_toolchain *kit);
/* Zero initialize first. Inert full semantic validation; no writes/execution. */
bool app_toolchain_verify(struct app_toolchain *kit, const uint8_t *descriptor,
    size_t descriptor_size, const uint8_t *bundle, size_t bundle_size,
    char *why, size_t cap);
bool app_toolchain_artifact(struct app_toolchain *kit, const char *dir,
    const char *descriptor_sha3, char *why, size_t cap);
/* Shared installed resolver owns release selection. Absence preserves host mode;
 * malformed selected state refuses. Does not execute or materialize source. */
bool app_toolchain_resolve(struct app_toolchain *kit, char *why, size_t cap);
bool app_toolchain_seal(struct app_toolchain *kit, char *why, size_t cap);
/* A namespace absolute prerequisite is allowed only if it names a verified kit
 * member; caller separately maps declared /source prerequisites. */
bool app_toolchain_member(const struct app_toolchain *kit, const char *path);
#endif
