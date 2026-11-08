/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Resolve installer-admitted source for the current shipped executable. */
#ifndef ZCL_APP_INSTALLED_SOURCE_RESOLVE_H
#define ZCL_APP_INSTALLED_SOURCE_RESOLVE_H
#include "command/app_installed_source.h"
/* out must be initialized; previous contents are freed, also on refusal.
 * Only skycombat is supported. No environment/cwd lookup, writes or execution.
 * Authority is the retained installer manifest under root/euid-owned ancestors
 * without group/other write permission, NOT cryptographic upstream provenance.
 * Writable sticky ancestors are refused too. Authorized owner replacement is
 * outside this threat model. No ancestor links except the checked Linux app
 * selector are accepted. Missing/legacy installations fail closed.
 *
 * Success why describes os_proc_self_exe_identity(): Linux pins the running
 * inode; Darwin reopens a pathname and CANNOT prove running-image identity.
 * Callers must retain that platform limitation in their evidence. This fixed
 * API has no separate identity field; callers may query the same os_proc API.
 * Re-resolve at consent/use; use retained source bytes, and still perform the
 * loader's required source-to-package derivation before build/key operations.
 * No launch or customization authority is granted by success.
 */
bool app_installed_source_resolve(const char *app,
    struct app_installed_source *out, char *why, size_t cap);

enum app_installed_source_status {
    APP_INSTALLED_SOURCE_REFUSED = -1,
    APP_INSTALLED_SOURCE_UNSELECTED = 0,
    APP_INSTALLED_SOURCE_VERIFIED = 1
};
/* UNSELECTED permits development checkout discovery; REFUSED does not. */
enum app_installed_source_status app_installed_source_select(const char *app,
    struct app_installed_source *out, char *why, size_t cap);

enum app_installed_toolchain_status {
    APP_INSTALLED_TOOLCHAIN_REFUSED = -1,
    APP_INSTALLED_TOOLCHAIN_UNSELECTED = 0,
    APP_INSTALLED_TOOLCHAIN_VERIFIED = 1
};
struct app_installed_toolchain {
    struct app_installed_source_bytes descriptor, bundle;
};
/* Initialize out to zero before first use. Resolution frees prior contents.
 * VERIFIED means retained bytes match the installer manifest and running image;
 * the caller must still verify descriptor semantics, bundle/tree and policy.
 * UNSELECTED means a development executable or a verified legacy installation.
 * A recognized but broken installation is REFUSED, never host-tool fallback.
 * Selection is the current trusted installer state, not an ever-installed
 * ledger. Authorized removal of all installer locators is indistinguishable
 * from an unselected executable; whole-install replacement remains outside
 * the ownership threat model above. Missing kit members do not deselect it.
 * This read-only operation grants neither compiler execution nor app authority.
 * Kept-image launch does not depend on the current compiler installation. */
enum app_installed_toolchain_status app_installed_toolchain_resolve(
    struct app_installed_toolchain *out, char *why, size_t cap);
void app_installed_toolchain_free(struct app_installed_toolchain *out);
#endif
