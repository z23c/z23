/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Native My Apps owner interface and bounded presenter seam. */
#ifndef ZCL_NATIVE_APP_LIBRARY_COMMAND_H
#define ZCL_NATIVE_APP_LIBRARY_COMMAND_H
#include "command/native_command.h"
#include "command/native_app_launch.h"
#include "presentation/model.h"
#include "presentation/presentation.h"
typedef bool (*app_library_presenter)(void *, const struct zcl_present_model_v1 *,
    const char *, struct zcl_present_window_event_v1 *, char *, size_t);
struct app_selection;
struct zcl_app_offer_row;
typedef bool (*app_library_catalog)(void *, struct zcl_app_offer_row *, size_t, size_t *, struct zcl_command_reply *);
typedef bool (*app_library_get)(void *, const struct json_value *, struct zcl_command_reply *);
typedef bool (*app_library_revealer)(void *, const char *);
typedef void (*app_library_sharer)(void *, const struct app_selection *, const char *, struct zcl_command_reply *);
typedef void (*app_library_preparer)(void *, const struct app_selection *,
    struct zcl_command_reply *);
#if defined(ZCL_TESTING)
void zcl_test_app_library_public(const struct app_launch_env *, struct zcl_command_reply *,
    app_library_presenter, void *, app_confirm_presenter, app_library_catalog, app_library_get);
void zcl_test_app_library_public_at(const struct app_launch_env *, const char *, struct zcl_command_reply *,
    app_library_presenter, void *, app_confirm_presenter, app_library_catalog, app_library_get);
void zcl_test_app_library_public_at_exe(const struct app_launch_env *, const char *, const char *,
    struct zcl_command_reply *, app_library_presenter, void *, app_confirm_presenter);
void zcl_test_app_library_reveal(const struct app_launch_env *env, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, app_library_sharer sharer,
    app_confirm_presenter notice, app_library_revealer revealer);
void zcl_test_app_library_refresh(const struct app_launch_env *env, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, app_library_preparer preparer,
    app_library_sharer sharer, app_confirm_presenter notice);
void zcl_test_app_library_share(const struct app_launch_env *env, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, app_library_sharer sharer,
    app_confirm_presenter notice);
void zcl_test_app_library_run(const struct app_launch_env *env,
    struct zcl_command_reply *reply, app_library_presenter presenter, void *context);
void zcl_test_app_library_setup(const struct app_launch_env *env, const char *exe,
    const char *datadir, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context);
void zcl_test_app_library_setup_prepared(const struct app_launch_env *env, const char *exe,
    const char *datadir, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, app_library_preparer preparer);
#endif
#endif
