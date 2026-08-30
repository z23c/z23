/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: name each perturbation and say what a split under it means, so a
 * report can print the cause rather than the bare fact of variation. */

#include "determinism/perturbation.h"

#include <string.h>

struct row {
    const char *name;
    const char *why;
};

static const struct row k_rows[ZCL_DET_P__COUNT] = {
    [ZCL_DET_P_BASE] = {
        "BASE",
        "the reference run; a split cannot be attributed to it" },
    [ZCL_DET_P_BASE_REPEAT] = {
        "BASE_REPEAT",
        "unstable against NOTHING — same environment, different answer; the "
        "cause is internal (race, uninitialised read, clock or RNG)" },
    [ZCL_DET_P_CC_SET] = {
        "CC_SET",
        "reads $CC/$CXX; passes for a developer whose shell has no CC and "
        "fails in the gate, which sets a two-token compiler-cache invocation" },
    [ZCL_DET_P_CC_UNSET] = {
        "CC_UNSET",
        "requires $CC/$CXX to be present; passes in the gate and fails for a "
        "developer" },
    [ZCL_DET_P_CWD_TMP] = {
        "CWD_TMP",
        "depends on the working directory or on the absolute temp path" },
    [ZCL_DET_P_LOCALE_TZ] = {
        "LOCALE_TZ",
        "depends on $TZ or on locale collation/formatting" },
    [ZCL_DET_P_ENV_PAD] = {
        "ENV_PAD",
        "depends on the initial stack address — an uninitialised automatic or "
        "an out-of-bounds read, not an environment variable" },
    [ZCL_DET_P_JOBS_LOW] = {
        "JOBS_LOW",
        "depends on concurrent load, on the pid sequence, or on another group "
        "running beside it" },
    [ZCL_DET_P_HOSTNAME] = {
        "HOSTNAME",
        "depends on the host's name" },
};

const char *zcl_det_perturbation_name(enum zcl_det_perturbation p)
{
    if ((int)p < 0 || p >= ZCL_DET_P__COUNT) return "UNKNOWN_PERTURBATION";
    return k_rows[p].name;
}

const char *zcl_det_perturbation_why(enum zcl_det_perturbation p)
{
    if ((int)p < 0 || p >= ZCL_DET_P__COUNT) return "unknown perturbation";
    return k_rows[p].why;
}

bool zcl_det_perturbation_from_name(const char *name,
                                    enum zcl_det_perturbation *out)
{
    if (!name || !out) return false;
    for (int i = 0; i < ZCL_DET_P__COUNT; i++) {
        if (strcmp(name, k_rows[i].name) == 0) {
            *out = (enum zcl_det_perturbation)i;
            return true;
        }
    }
    return false;
}
