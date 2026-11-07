/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Internal consented publication of retained installed-app source. */
#ifndef ZCL_NATIVE_APP_SEED_INSTALLED_H
#define ZCL_NATIVE_APP_SEED_INSTALLED_H
#include "kernel/command_registry.h"
#include "command/app_installed_source.h"

struct app_seed_installed_owner {
    const char *key_path;
    const char *publisher; /* lowercase 66-hex when exists; empty otherwise */
    bool exists;
};

/* Native coordinator only, NOT a raw CLI handler or an authorization bypass.
 * Caller has obtained native owner consent and re-resolved the exact admitted
 * projection, app and absolute datadir bound to that consent. Construct input
 * with exactly app and datadir strings (no source/plan/confirm/day overrides).
 * owner carries the exact path/existence/publisher shown at consent; its
 * strings remain caller-owned and stable for this synchronous call. Rechecked
 * after staging and against the owner acquired before preparation/signing.
 * reply must be initialized. source owns a successful, still-pinned loader
 * result and remains caller-owned. This call stages retained bytes and checks
 * their content BEFORE owner-key creation, then uses the normal owner/prepare/
 * existing-release/publication lifecycle. No make or source execution.
 * Success has the existing app.seed commit/release/package result shape.
 * Source in that result is ephemeral scratch, removed before return; it is
 * not a persistent checkout or a launch authority. No sandbox claim is made.
 * Key creation and publication mutation are retained on failures. Failures
 * after attempting the owner lifecycle conservatively report possible writes
 * (the existing helper may create the key directory before refusing a key).
 * Cleanup failure returns STAGE_CLEANUP_FAILED, mutated=true and the retained
 * outer scratch path in error evidence, without clearing any committed data.
 */
void app_seed_installed_commit(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const struct app_installed_source *source,
    const struct app_seed_installed_owner *owner);
#endif
