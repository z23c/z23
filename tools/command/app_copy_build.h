/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * app_copy_build — the derivations app.build and the copy open
 * (app.run.copy) share, so a build and a later open name a copy and its
 * build record the same way:
 *   - which directory a `copy` input names (a name under <datadir>/copies,
 *     or an absolute directory);
 *   - the package root and dependency root of the copy's saved tree, as a
 *     publish would prepare them under the release's publisher key;
 *   - the copy's build store: <datadir>/app_build/{work/<fork>,images,
 *     records}.
 * Every refusal fails the reply with one named code. */

#ifndef ZCL_TOOLS_COMMAND_APP_COPY_BUILD_H
#define ZCL_TOOLS_COMMAND_APP_COPY_BUILD_H

#include "command/native_zcode_package_copy.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APP_COPY_BUILD_PATH 4400

struct app_copy_build_store {
    char work[APP_COPY_BUILD_PATH];    /* this copy's build directory */
    char images[APP_COPY_BUILD_PATH];  /* content-addressed images */
    char records[APP_COPY_BUILD_PATH]; /* zcl.app_build.v1 records */
};

/* `copy` names <datadir>/copies/<copy> or is an absolute directory; out is
 * its canonical real path. BAD_COPY or COPY_MISSING otherwise. */
bool app_copy_build_dir(const char *datadir, const char *copy, char *out,
                        size_t cap, struct zcl_command_reply *reply);

/* package_root and dependency_root of the open, clean copy's tree.
 * RELEASE_UNKNOWN or PACKAGE_INVALID otherwise. */
bool app_copy_build_roots(const char *datadir, const char *copy_dir,
                          const struct zcl_package_copy *copy,
                          uint8_t package_root[32],
                          uint8_t dependency_root[32],
                          struct zcl_command_reply *reply);

/* The build store paths for the copy whose fork record is `fork`.
 * PATH_TOO_LONG otherwise. */
bool app_copy_build_store(const char *datadir, const uint8_t fork[32],
                          struct app_copy_build_store *out,
                          struct zcl_command_reply *reply);

#endif /* ZCL_TOOLS_COMMAND_APP_COPY_BUILD_H */
