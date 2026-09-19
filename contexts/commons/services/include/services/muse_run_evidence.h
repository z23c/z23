/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * muse_run_evidence — the files one Muse run leaves behind, split out of
 * muse_run.c so the judgement and the publishing can each be read in one
 * sitting. Nothing here decides anything: every call writes what the
 * result already holds.
 *
 * THREE FILES, THREE READERS. receipt.json is what A's reap judges and is
 * deliberately small. muse.json is the whole measured record, for an
 * operator and for the next attempt's brief. workspace.blocked exists only
 * when the run left the workspace off its pinned base and could not put it
 * back: it is the one artifact an operator needs to clear that tree, its
 * half_undone line says whether the change is still readable in place, and
 * its absence is itself a fact.
 *
 * ATOMIC OR ABSENT. Every write goes through a tempfile in the same
 * directory plus rename, so a kill can never leave a partial evidence file
 * for a gate, a reap or an operator to read as complete.
 */
#ifndef ZCL_SERVICES_MUSE_RUN_EVIDENCE_H
#define ZCL_SERVICES_MUSE_RUN_EVIDENCE_H

#include <stdbool.h>

struct muse_run_task;
struct muse_run_result;

/* The make target the run rebuilds from the candidate tree before it runs
 * the gate group. One spelling, here, because two callers need it and they
 * must not be able to drift: muse_run.c spawns it, and muse.json records
 * it beside the build outcome. A recorded target that is not the spawned
 * target would make every build failure unreadable. */
#define MUSE_RUN_GATE_BUILD_TARGET "test_parallel"

/* Tempfile plus rename in the target's own directory. False when the
 * bytes did not land under the final name. */
bool muse_run_write_atomic(const char *path, const char *text);

/* <rundir>/receipt.json — the closed verdict A's reap reads. */
void muse_run_write_receipt(const struct muse_run_task *t,
    const struct muse_run_result *r);

/* <rundir>/muse.json — every measured fact the run established. */
void muse_run_write_facts(const struct muse_run_task *t,
    const struct muse_run_result *r);

/* <rundir>/workspace.blocked — written ONLY when the run leaves the
 * workspace off its pinned base and cannot put it back. */
void muse_run_write_blocked(const struct muse_run_task *t,
    const struct muse_run_result *r);

#endif /* ZCL_SERVICES_MUSE_RUN_EVIDENCE_H */
