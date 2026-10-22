/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land preparation of the landing worktree's make products --
 *          the restart plan and the sealed proof's checker binaries --
 *          right before proof admission.
 *
 * It rewrites no tracked file and makes no commit. (The regenerate-and-amend
 * phase that used to live beside it is gone: a generated or checked document
 * is a freshness gate the author fixes with its make target, and the queue
 * lands the tip exactly as submitted.)
 *
 * PROCESS RULE. `make` is the only program this file runs, always through
 * util/spawn.h's zcl_spawn_capture_merged_observed() -- no popen(), no
 * system(), no shell command string.
 */

#include "command/native_dev_land_prepare.h"

#include "base/safe_alloc.h"
#include "platform/logical_cpu.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define DLP_MAKE_CAP (256u * 1024u)
#define DLP_MAKE_TIMEOUT_MS (10 * 60 * 1000)

/* The first line naming an error or refusal, from merged stdout+stderr —
 * a smaller mirror of native_dev_land.c's dl_first_actionable(). */
static void dlp_first_actionable(const char *text, char *out, size_t cap)
{
    static const char *const needles[] = {
        "FAIL", "fail", "error:", "Error", "ERROR", "MISMATCH", "refused",
    };
    char *copy, *save = NULL, *line;
    size_t len;
    if (out && cap)
        out[0] = '\0';
    if (!text || !out || cap == 0)
        return;
    len = strlen(text) + 1;
    copy = (char *)zcl_malloc(len, "dev.land.prepare.triage");
    if (!copy)
        return;
    memcpy(copy, text, len);
    for (line = strtok_r(copy, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        /* A passing gate may itself have "fail" in its name. */
        const char *result = line + strspn(line, " \t\r");
        if (strncmp(result, "PASS", 4) == 0 &&
            (result[4] == '\0' || strchr(" \t\r", result[4])))
            continue;
        for (size_t i = 0; i < sizeof(needles) / sizeof(needles[0]); i++) {
            if (strstr(line, needles[i])) {
                (void)snprintf(out, cap, "%s", line);
                free(copy);
                return;
            }
        }
    }
    free(copy);
}

/* Run `make -s -C wt target` with merged stdout+stderr captured. Returns the
 * child's exit status, or -1 on a launch failure. On a nonzero return `why`
 * names the first actionable line, or failing that the target. Every make
 * start re-parses the whole Makefile, so callers name one goal. */
static int dlp_make(const char *wt, const char *target, char *why,
                    size_t why_cap)
{
    char jobs[16];
    const char *argv[8];
    size_t n = 0;
    char *buf;
    int rc;
    bool timed_out = false;
    if (!platform_build_jobs_arg(jobs)) {
        (void)snprintf(why, why_cap,
                       "landing build job count unavailable (ZCL_BUILD_MAX_JOBS must be a positive uint32 decimal)");
        return -1;
    }
    argv[n++] = "make";
    argv[n++] = jobs;
    argv[n++] = "-s";
    argv[n++] = "-C";
    argv[n++] = wt;
    argv[n++] = target;
    argv[n] = NULL;
    buf = (char *)zcl_malloc(DLP_MAKE_CAP, "dev.land.prepare.make");
    if (!buf) {
        (void)snprintf(why, why_cap, "out of memory running make %s", target);
        return -1;
    }
    rc = zcl_spawn_capture_merged_observed(argv, buf, DLP_MAKE_CAP,
                                           DLP_MAKE_TIMEOUT_MS, &timed_out);
    if (rc != 0) {
        dlp_first_actionable(buf, why, why_cap);
        if (!why[0])
            (void)snprintf(why, why_cap, "make %s failed%s", target,
                           timed_out ? " (timed out)" : "");
    }
    free(buf);
    return rc;
}

bool zcl_dev_land_restart_plan_prepare(const char *wt, char *why,
                                       size_t why_cap)
{
    char path[4096 + 32];
    struct stat st;
    if (!wt || !why || why_cap == 0) return false;
    why[0] = '\0';
    if (snprintf(path, sizeof(path), "%s/build/dev-loop/restart.env", wt) >=
        (int)sizeof(path)) {
        (void)snprintf(why, why_cap, "landing restart plan path too long");
        return false;
    }
    /* Lint or dependency preparation may rewrite source metadata before this
     * runs. Mere existence says nothing about the
     * plan's BASE_GENERATION. The native target's FORCE prerequisite seals
     * this checkout after every preparation stage has finished. */
    if (dlp_make(wt, "build/dev-loop/restart.env", why, why_cap) != 0)
        return false;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        (void)snprintf(why, why_cap, "landing restart plan not produced by make");
        return false;
    }
    return true;
}

/* The sealed proof copies its generated-docs checker binaries out of this
 * worktree before any dimension builds inside the generation and refuses
 * the proof when one is absent. A cold worktree — a fresh landing lane or
 * a new scratch clone — has none of them until something runs their
 * target; docs-proof-tools is the Makefile's own list of this exact set.
 * Build only when a member is missing, so a warm worktree pays nothing. */
static const char *const DLP_PROOF_TOOLS[] = {
    "build/bin/z23-lint",
    "build/bin/z23-fleet-observe",
    "build/bin/gen_capability_inventory",
};

static bool dlp_proof_tool_present(const char *wt, const char *tool,
                                    char *why, size_t why_cap)
{
    char path[4096 + 64];
    struct stat st;
    if (snprintf(path, sizeof(path), "%s/%s", wt, tool) >=
        (int)sizeof(path)) {
        (void)snprintf(why, why_cap, "proof tool path too long: %s", tool);
        return false;
    }
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

bool zcl_dev_land_proof_tools_prepare(const char *wt, char *why,
                                      size_t why_cap)
{
    size_t missing = 0, i;
    if (!wt || !why || why_cap == 0) return false;
    why[0] = '\0';
    for (i = 0; i < sizeof(DLP_PROOF_TOOLS) / sizeof(DLP_PROOF_TOOLS[0]);
         i++) {
        if (!dlp_proof_tool_present(wt, DLP_PROOF_TOOLS[i], why, why_cap)) {
            if (why[0])
                return false; /* path overflow, not a missing file */
            missing = 1;
            break;
        }
    }
    if (!missing)
        return true;
    if (dlp_make(wt, "docs-proof-tools", why, why_cap) != 0)
        return false;
    for (i = 0; i < sizeof(DLP_PROOF_TOOLS) / sizeof(DLP_PROOF_TOOLS[0]);
         i++) {
        if (!dlp_proof_tool_present(wt, DLP_PROOF_TOOLS[i], why, why_cap)) {
            if (!why[0])
                (void)snprintf(why, why_cap,
                               "proof_generation_dependency_unavailable:%s "
                               "(make docs-proof-tools)",
                               DLP_PROOF_TOOLS[i]);
            return false;
        }
    }
    return true;
}

