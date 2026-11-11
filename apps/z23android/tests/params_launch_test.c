/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "params_job.h"
#include <assert.h>
#include <stdio.h>

static int starts;
static bool start_result;
static bool count_start(void *ctx, const char *files)
{
    (void)ctx;
    (void)files;
    ++starts;
    return start_result;
}

enum zapp_params_result zapp_params_install_set(const struct zapp_param_file *set, size_t count,
                                                const struct zapp_params_source *source,
                                                const char *files, char *why, size_t cap)
{
    (void)set;
    (void)count;
    (void)source;
    (void)files;
    (void)why;
    (void)cap;
    return ZAPP_PARAMS_OK;
}

int main(void)
{
    assert(zapp_params_job_state(NULL, 0) == ZAPP_PARAMS_IDLE);
    start_result = true;
    assert(!zapp_params_launch(count_start, NULL, NULL, true, false) && starts == 0);
    assert(zapp_params_launch(count_start, NULL, NULL, true, true) && starts == 1);
    assert(zapp_params_launch(count_start, NULL, NULL, false, false) && starts == 2);
    assert(!zapp_params_launch(NULL, NULL, NULL, false, false) && starts == 2);
    start_result = false;
    assert(!zapp_params_launch(count_start, NULL, NULL, false, false) && starts == 3);
    assert(zapp_params_job_state(NULL, 0) == ZAPP_PARAMS_IDLE);
    puts("params launch tests passed");
    return 0;
}
