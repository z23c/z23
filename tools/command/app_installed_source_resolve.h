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
#endif
