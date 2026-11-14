/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared Linux test process custody for native app UI fixtures. */
#ifndef ZCL_TEST_APP_UI_FIXTURE_H
#define ZCL_TEST_APP_UI_FIXTURE_H
#if defined(__linux__) && defined(ZCL_TESTING)
#include "command/native_app_launch.h"
#include "platform/process_lifecycle.h"
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
struct app_ui_child {
    pid_t pid;
    uint64_t token;
    char before[APP_LAUNCH_PATH_MAX], image[PATH_MAX];
};
bool app_ui_pipe(int fd[2]);
bool app_ui_spawn(struct app_ui_child *c, const char *const *argv, int in, int out, int err);
enum platform_process_wait_result app_ui_wait(struct app_ui_child *c, unsigned ms, uint32_t *code);
bool app_ui_reaped_identity_failure(struct app_ui_child *c);
bool app_ui_stop(struct app_ui_child *c);
bool app_ui_image_live(struct app_ui_child *c);
bool app_ui_drive(const char *driver, const char *title, const char *action,
                  const char *log_path, bool pixels, bool replaced, unsigned timeout_ms);
#endif
#endif
