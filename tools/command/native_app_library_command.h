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
typedef bool (*app_library_revealer)(void *, const char *);
typedef void (*app_library_sharer)(void *, const struct app_selection *, const char *, struct zcl_command_reply *);
typedef void (*app_library_preparer)(void *, const struct app_selection *,
    struct zcl_command_reply *);
typedef void (*app_library_adopter)(const struct zcl_command_request *, struct zcl_command_reply *,
    app_confirm_presenter, void *);
#if defined(ZCL_TESTING)
void zcl_test_app_library_create(const struct app_launch_env *env, const char *datadir,
    struct zcl_command_reply *reply, app_library_presenter presenter, app_confirm_presenter notice,
    void *context, app_library_adopter adopter, size_t data_cap);
void zcl_test_app_library_create_prepared(const struct app_launch_env *env, const char *datadir,
    struct zcl_command_reply *reply, app_library_presenter presenter, app_confirm_presenter notice,
    void *context, app_library_preparer preparer, app_library_adopter adopter, size_t data_cap);
struct app_network_test_hooks;
void zcl_test_app_library_network(const struct app_launch_env *env, const char *datadir,
    struct zcl_command_reply *reply, app_library_presenter presenter, app_confirm_presenter notice, void *context,
    const struct app_network_test_hooks *hooks);

void zcl_test_app_library_request(const struct app_launch_env *env, const struct zcl_command_request *request,
    struct zcl_command_reply *reply, app_library_presenter presenter,
    app_confirm_presenter receive_presenter, void *context);
void zcl_test_app_library_discover(const struct app_launch_env *env, const char *datadir,
    struct zcl_command_reply *reply, app_library_presenter presenter,
    app_confirm_presenter receive_presenter, void *context);
void zcl_test_app_library_discover_worker(const struct app_launch_env *env, const char *datadir,
    struct zcl_command_reply *reply, app_library_presenter presenter,
    app_confirm_presenter receive_presenter, void *context, const char *worker_path);
void zcl_test_app_library_discover_worker_share(const struct app_launch_env *env, const char *datadir,
    struct zcl_command_reply *reply, app_library_presenter presenter,
    app_confirm_presenter receive_presenter, void *context, const char *worker_path,
    app_library_preparer preparer, app_library_sharer sharer);
void zcl_test_app_library_native_at(const struct app_launch_env *env, const char *exe,
    const char *datadir, struct zcl_command_reply *reply, app_library_presenter presenter,
    void *context, app_confirm_presenter notice);
void zcl_test_app_library_reveal(const struct app_launch_env *env, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, app_library_preparer preparer, app_library_sharer sharer,
    app_confirm_presenter notice, app_library_revealer revealer);
void zcl_test_app_library_refresh(const struct app_launch_env *env, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, app_library_preparer preparer,
    app_library_sharer sharer, app_confirm_presenter notice);
void zcl_test_app_library_share(const struct app_launch_env *env, struct zcl_command_reply *reply,
    app_library_presenter presenter, void *context, app_library_preparer preparer, app_library_sharer sharer,
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
