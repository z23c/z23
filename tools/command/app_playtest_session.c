/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: scripted v=1 playtest session over resident_launch (see header). */
#include "command/app_playtest_session.h"

#include <stdio.h>
#include <string.h>

const char *app_playtest_code_name(enum app_playtest_code code)
{
    (void)code;
    return "UNIMPLEMENTED";
}

size_t app_playtest_display_env(char *env[APP_PLAYTEST_ENV_MAX + 1u])
{
    env[0] = NULL;
    return 0;
}

bool app_playtest_run(const struct app_playtest_request *request,
                      struct app_playtest_result *out)
{
    (void)request;
    memset(out, 0, sizeof(*out));
    out->code = APP_PLAYTEST_INVALID_REQUEST;
    (void)snprintf(out->error, sizeof(out->error), "app playtest: not implemented");
    return false;
}

void app_playtest_result_free(struct app_playtest_result *out)
{
    (void)out;
}
