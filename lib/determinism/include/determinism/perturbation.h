/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the fixed set of environment perturbations a group's verdict digest
 * must survive bitwise, and what a split under each one tells you.
 *
 * WHY PERTURBATION AND NOT REPETITION. Running a group twice in the same
 * environment proves very little — it catches a race or an uninitialised read
 * that happens to flip, and nothing else. A test that silently reads its
 * environment passes the repetition check every time and still gives two
 * different answers to two different people.
 *
 * THIS IS NOT HYPOTHETICAL. test_mutation_harness passed for every developer
 * and failed for every gate run, at the same commit, from the same binary,
 * because it read $CC — which the build sets to a two-token compiler-cache
 * invocation and a developer's interactive shell does not set at all. Two gate
 * runs were written off as flakiness before anyone looked. ZCL_DET_P_CC_SET
 * and ZCL_DET_P_CC_UNSET exist to make that exact defect a measurement rather
 * than a story.
 *
 * WHAT EACH PERTURBATION IS FOR — a digest that moves under one of these names
 * the cause, which is the whole point. "It varies" is not a finding; "it
 * varies when CC is set" is.
 *
 *   BASE          the reference run. Not a perturbation; the thing compared to.
 *   BASE_REPEAT   byte-identical environment, run again. A split here is the
 *                 strongest finding available: the group is unstable against
 *                 NOTHING, so no environment variable can be blamed and the
 *                 cause is internal (a race, an uninitialised read, a clock or
 *                 an RNG). It also stops every later perturbation from being
 *                 credited with a split that plain repetition already produces.
 *   CC_SET        CC/CXX set to the build's real two-token value.
 *   CC_UNSET      CC/CXX removed from the environment entirely.
 *   CWD_TMP       a different absolute temp path (TMPDIR/TMP/TEMP) and a
 *                 different $PWD. Catches a path baked into an output and a
 *                 test that resolves against the environment's idea of "here".
 *                 It does NOT move getcwd(2): giving the same tree a second
 *                 physical path needs a bind mount, and a host that will not
 *                 grant an unprivileged user namespace an identity uid map
 *                 cannot provide one. That half is unmeasured, and saying so
 *                 is the point — it is not quietly counted as measured.
 *   LOCALE_TZ     TZ, LANG, LC_ALL, LC_TIME and LC_COLLATE changed. Catches
 *                 locale-dependent collation in a sort and a timezone leaking
 *                 into a formatted date.
 *   ENV_PAD       ~64 KiB of padding variables. This shifts the initial stack
 *                 pointer, which is how an uninitialised automatic or a
 *                 one-past-the-end read changes its answer without any code
 *                 changing. It has caught real bugs in this tree.
 *   JOBS_LOW      the runner's worker pool reduced. Different pid sequence,
 *                 different parent timing, different concurrent load, and a
 *                 different set of groups running beside any given group.
 *   LOAD_HIGH     the runner's worker pool raised to saturate the box. Paired
 *                 with JOBS_LOW so that "the machine got busier" is a real,
 *                 wide delta and not the 8-to-5 nudge JOBS_LOW alone provides.
 *                 A 60 s budget is not tripped by five workers; the evidence
 *                 that prompted this perturbation was a group that took 22.6 s
 *                 idle and 124 s under 32 workers. These two are the only
 *                 SCHEDULING perturbations, and a split confined to them is
 *                 reported as TIMING_SENSITIVE rather than NONDETERMINISTIC.
 *   HOSTNAME      a different UTS hostname, in an unprivileged user namespace.
 *                 Refuses rather than pretends when the box will not grant one:
 *                 the only namespace this host hands an unprivileged process
 *                 also remaps the uid to root, which would perturb every
 *                 capability, sandbox and privilege test in the suite. A
 *                 measurement of something else wearing this label would be
 *                 worse than no measurement.
 *
 * NOT COVERED, AND WHY. "Run the group twice back to back in ONE process
 * image" is absent on purpose: the canonical runner forks a fresh child per
 * group, so no gate in this tree ever executes two groups in one image, and a
 * perturbation measuring an execution shape nothing uses would report defects
 * nobody can hit. BASE_REPEAT measures the fresh-process repetition that the
 * gate actually performs.
 *
 * AND THE HONEST CEILING. Every perturbation here is a LOWER BOUND on
 * non-determinism. A group that reads an input none of these move stays
 * DETERMINISTIC under this measurement and is not therefore deterministic. A
 * group that is wrong the same way every time is never caught at all. */
#ifndef ZCL_DETERMINISM_PERTURBATION_H
#define ZCL_DETERMINISM_PERTURBATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum zcl_det_perturbation {
    ZCL_DET_P_BASE = 0,
    ZCL_DET_P_BASE_REPEAT,
    ZCL_DET_P_CC_SET,
    ZCL_DET_P_CC_UNSET,
    ZCL_DET_P_CWD_TMP,
    ZCL_DET_P_LOCALE_TZ,
    ZCL_DET_P_ENV_PAD,
    ZCL_DET_P_JOBS_LOW,
    ZCL_DET_P_LOAD_HIGH,
    ZCL_DET_P_HOSTNAME,
    ZCL_DET_P__COUNT
};

/* Stable short id used in the ratchet baseline and every report. Never
 * renamed without shrinking the baseline first: the name IS the cause. */
const char *zcl_det_perturbation_name(enum zcl_det_perturbation p);
const char *zcl_det_perturbation_why(enum zcl_det_perturbation p);
bool zcl_det_perturbation_from_name(const char *name,
                                    enum zcl_det_perturbation *out);

/* ── perturbation CLASS, and why a class is needed ────────────────────────
 *
 * Two groups can both fail to reproduce and be two entirely different
 * defects. Separating them is not bookkeeping; it decides whether a receipt
 * is even possible.
 *
 * A group whose vector moves on a plain re-run at identical load, or moves
 * when an environment variable moves, has a bug in its own logic: it does not
 * settle on one answer. Nobody can corroborate it, and nobody should try.
 *
 * A group whose vector moves ONLY when the machine got busier has settled
 * logic and a bad grading rule — it is asserting on a wall clock. This one is
 * worse for a corroboration network than it looks. An honest node re-running
 * such a group on a loaded box computes a different verdict vector and
 * REFUTES a receipt that was never wrong. That is a false accusation
 * manufactured by scheduling, and the producer has no way to answer it.
 *
 * So SCHEDULING perturbations are quarantined from the rest. If a split is
 * explained by them alone, the verdict is TIMING_SENSITIVE, not
 * NONDETERMINISTIC. If any non-scheduling perturbation also splits, the
 * stronger claim wins and the group is NONDETERMINISTIC.
 *
 * REFERENCE is its own class because BASE cannot split against itself; it is
 * the thing compared to, and giving it a class keeps the four sets a
 * partition of the enum rather than a list with an exception. */
enum zcl_det_perturbation_class {
    ZCL_DET_PC_REFERENCE = 0,   /* BASE — the run everything is compared to */
    ZCL_DET_PC_REPEAT,          /* BASE_REPEAT — unstable against nothing */
    ZCL_DET_PC_ENVIRONMENT,     /* CC_*, CWD_TMP, LOCALE_TZ, ENV_PAD */
    ZCL_DET_PC_SCHEDULING       /* JOBS_LOW, LOAD_HIGH — load and wall clock */
};

enum zcl_det_perturbation_class
zcl_det_perturbation_class(enum zcl_det_perturbation p);

#endif /* ZCL_DETERMINISM_PERTURBATION_H */
