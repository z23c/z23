// one-result-type-ok:total-classifier — this file owns no fallible surface.
// Its one function is a total classification of an already-captured report:
// every input maps to a member of enum build_fabric_report_class, and the
// enum IS the answer. Wrapping it in a zcl_result would invent a failure
// mode that does not exist and hide the classification behind an error path.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Tell a host resource wedge apart from a confined build failure. */

#include "services/build_fabric_worker_report.h"

#include "models/build_fabric.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

enum build_fabric_report_class build_fabric_worker_classify_report(
    char *capture, int rc, char *detail, size_t detail_cap)
{
    if (!capture || !detail || detail_cap == 0)
        return BUILD_FABRIC_REPORT_OTHER;
    enum build_fabric_report_class cls = BUILD_FABRIC_REPORT_OTHER;
    if (strstr(capture, "process-headroom-exhausted"))
        cls = BUILD_FABRIC_REPORT_PROCESS_HEADROOM;
    else if (strstr(capture, "process-budget-exceeded"))
        cls = BUILD_FABRIC_REPORT_PROCESS_BUDGET;
    for (size_t i = 0; capture[i]; i++)
        if ((unsigned char)capture[i] < 0x20 || (unsigned char)capture[i] > 0x7e)
            capture[i] = ' ';
    if (cls == BUILD_FABRIC_REPORT_PROCESS_HEADROOM)
        LOG_WARN("build.fabric",
                 "confined action refused: this HOST has no process table "
                 "left for the uid — a resource wedge, not a build failure; "
                 "retry the action: %.400s", capture);
    else if (cls == BUILD_FABRIC_REPORT_PROCESS_BUDGET)
        LOG_WARN("build.fabric",
                 "confined action killed: its process subtree exceeded the "
                 "budget the action declares — a defect in the input, not a "
                 "host condition: %.400s", capture);
    (void)snprintf(detail, detail_cap, "%s%d: %.180s",
                   cls == BUILD_FABRIC_REPORT_PROCESS_HEADROOM
                       ? "process-headroom-exhausted rc="
                   : cls == BUILD_FABRIC_REPORT_PROCESS_BUDGET
                       ? "process-budget-exceeded rc="
                       : "sandbox-exit-",
                   rc, capture[0] ? capture : "no-report");
    return cls;
}
