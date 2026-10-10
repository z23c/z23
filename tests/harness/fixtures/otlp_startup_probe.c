/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Start-up probe for test_trace's ZCL_OTLP_LOGS gate.
 *
 * Emits exactly one structured log event, otlp_startup_probe, then prints
 * mirror_installed=0 or mirror_installed=1 on stdout (the value of
 * log_json_mirror_installed() read after the event) and exits 0.  It is
 * linked against the real util/trace.c and util/log_json.c, so the only
 * thing that can install the mirror before main() is the process-start
 * constructor in trace.c reading ZCL_OTLP_LOGS. */

#include "util/log_json.h"

#include <stdio.h>
#include <string.h>

/* Stand-in for the real LogPrintStr in platform/modules/util/src/util.c,
 * which is not linked here because it drags in the data-dir and chain-params
 * closure (link closure only).  Same behaviour for this probe: the line goes
 * to stderr.  Everything else linked into this binary is the real tree
 * code (trace.c, log_json.c, clock.c, utilstrencodings.c, safe_alloc.c). */
int LogPrintStr(const char *str)
{
    fputs(str, stderr);
    return (int)strlen(str);
}

int main(void)
{
    log_jsonf(LOG_JSON_INFO, "otlp_startup_probe", NULL);
    printf("mirror_installed=%d\n", log_json_mirror_installed() ? 1 : 0);
    fflush(stdout);
    return 0;
}
