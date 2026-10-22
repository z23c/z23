/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Closure-unchanged skipping for the early feedback stage: key each early group over its input closure, skip a group whose key and toolchain identity match its last recorded PASS, and keep those records in a local dev-only store. */
#ifndef ZCL_TOOLS_DEV_DEVLOOP_EARLY_SKIP_H
#define ZCL_TOOLS_DEV_DEVLOOP_EARLY_SKIP_H

#include "test_group_catalog.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;

/* FEEDBACK ONLY, like the early stage it narrows (devloop_early.h). Nothing
 * here touches the full plan, its receipt, the test cache or the
 * failure-first store; the full plan still runs every group it selects.
 *
 * KEY. key(G) is SHA3-256 over
 *     "zcl.dev_early_skip.key.v1\n" "identity:<identity>\n" "group:<G>\n"
 * then one "<path>:<SHA3-256 of the file's bytes>\n" line per closure file
 * in byte order of path. It follows the commuting-ticket key
 * (docs/archive/COMMUTING_TICKETS.md) with two deliberate differences: file
 * bytes come from the working tree the candidate was compiled from, not
 * from a committed tip, and headers are resolved the way the compiler
 * resolves them. dev.agent.ticketkey keys the committed blobs at a tip (the
 * edit this stage answers is not committed), resolves a quoted include by
 * basename only (so "json/json.h" silently joins nothing), and routes every
 * blob of the tree through the shared rules (about 50 s cold per process).
 *
 * CLOSURE of an early group G:
 *   - its test file: tests/harness/src/<G>.c for a test_ id, and
 *     tests/harness/spec/<G>.c for a spec_ id;
 *   - every restart source, whatever G is: all of them are linked into the
 *     one candidate whose test binary runs every group (its link list);
 *   - every file those include, transitively: a quoted name in the
 *     includer's directory, then each -iquote directory, then each -I
 *     directory of the candidate's compile flags; an angle name in the -I
 *     directories only (not found there: a system header, outside the key).
 * Which groups run early at all rides on facts narrowing (devloop_early.h),
 * which is feedback-only: the full plan always reruns every group it
 * selects. The closure never rides on it. A source whose own facts name no
 * early group still links into G's binary, and an earlier per-source facts
 * attribution left such a source out of G's key: editing it kept the key
 * and skipped G (test_devloop_early "holes").
 *
 * IDENTITY is SHA3-256 over the harness version, the compiler id, the base
 * generation, and the test compile flags, link flags and libraries. Any of
 * them changing reruns every group. Base objects outside the restart set
 * reach the key through the base generation only.
 *
 * UNVOUCHED. A group whose inputs this key cannot see is never skipped and
 * never recorded:
 *   - no conventional test file; an unregistered group or one that
 *     declares a host need (tools/dev/test_group_host_needs.def);
 *   - ANY closure file (the test file, a restart source, a header either
 *     reaches) that reads the environment, starts a process, opens a file
 *     through fopen/open/openat/creat/dlopen or a platform_ *open* helper
 *     with a first argument that is not a string literal, or names a
 *     checkout path in a string literal (runtime data and fixtures; an
 *     include directive's operand is keyed through its file instead). This
 *     is a text scan after comments are blanked (string and character
 *     literals kept, so a comment opener inside one hides nothing): an
 *     opener prototype (first parameter starts with a type keyword) does
 *     not count, and a file read through a helper whose name holds none
 *     of these is not seen;
 *   - a quoted include that resolves nowhere, a computed include, an
 *     #include_next (the search it continues is not modelled), or an
 *     unreadable file;
 *   - compile flags that move include resolution in a way the resolver
 *     does not model: any -i flag but -iquote (-isystem, -idirafter,
 *     -include, -imacros, -isysroot, ...), -I-, --sysroot, an @response
 *     file, or more flags than the split holds (cflags-unmodeled);
 *   - no restart source; a closure or source set past its bound.
 * Without a toolchain identity nothing is skipped or recorded.
 *
 * MODES (ZCL_DEVLOOP_EARLY_SKIP_ENV): unset or "on" skips; "off" skips
 * nothing, for A/B measurement, and still records passes; "verify" decides
 * exactly as "on", then runs the skipped groups anyway in a second uncached
 * process and counts every failure there as a false narrow. Any other value
 * is "off".
 *
 * STORE. ZCL_DEVLOOP_EARLY_SKIP_STORE under the checkout root: a header
 * line, then "<group>\t<key>\t<identity>\t<candidate sha256>\t<run us>\n"
 * per group, replaced whole through a temporary file and a rename. A store
 * that does not parse is treated as empty. */

#define ZCL_DEVLOOP_EARLY_SKIP_ENV "ZCL_DEVLOOP_EARLY_SKIP"
#define ZCL_DEVLOOP_EARLY_SKIP_STORE "build/dev-loop/early-skip.v1.tsv"
#define ZCL_DEVLOOP_EARLY_SKIP_HARNESS "zcl.dev_early_skip.v1"
#define ZCL_DEVLOOP_EARLY_SKIP_GROUP_MAX 32
#define ZCL_DEVLOOP_EARLY_SKIP_SOURCE_MAX 64

enum zcl_devloop_early_skip_mode {
    ZCL_DEVLOOP_EARLY_SKIP_ON = 0,
    ZCL_DEVLOOP_EARLY_SKIP_OFF = 1,
    ZCL_DEVLOOP_EARLY_SKIP_VERIFY = 2,
};

/* What the candidate was built from: restart.env's identity fields and the
 * restart source set. */
struct zcl_devloop_early_toolchain {
    const char *compiler_id;
    const char *base_generation;
    const char *cflags;
    const char *ldflags;
    const char *libs;
    const char *const *sources;
    size_t source_count;
};

struct zcl_devloop_early_skip_row {
    char group[ZCL_TEST_GROUP_FULL_MAX];
    char key[65];    /* "" when not computable */
    bool skip;       /* closure-unchanged in mode on or verify */
    bool vouched;    /* the key covers every input it can name */
    /* closure-unchanged, no-record, key-changed, identity-changed,
     * identity-unknown, unvouched or skip-off. Literal. */
    const char *reason;
    char detail[128];
    int64_t last_run_us; /* the recorded PASS's run time, when one exists */
};

struct zcl_devloop_early_skip {
    enum zcl_devloop_early_skip_mode mode;
    const char *mode_name;   /* "on", "off" or "verify" */
    const char *store_state; /* "absent", "loaded" or "malformed" */
    char identity[65];
    size_t n;
    struct zcl_devloop_early_skip_row rows[ZCL_DEVLOOP_EARLY_SKIP_GROUP_MAX];
    uint32_t groups_selected;
    uint32_t groups_run;
    uint32_t groups_skipped;       /* closure-unchanged, not run */
    uint32_t groups_unvouched;
    uint32_t groups_skip_disabled; /* would skip, ran because mode is off */
    int64_t saved_us;              /* sum of skipped groups' last_run_us */
    const char *record_state;      /* "none", "written" or "failed" */
    uint32_t records_written;
    uint32_t records_forgotten;
    bool verify_ran;
    const char *verify_status;     /* "", "green" or "red" */
    uint32_t verify_groups;
    uint32_t false_narrows;
    int64_t verify_wall_us;
};

/* The mode ZCL_DEVLOOP_EARLY_SKIP_ENV names. */
enum zcl_devloop_early_skip_mode zcl_devloop_early_skip_mode_env(void);
const char *zcl_devloop_early_skip_mode_name(
    enum zcl_devloop_early_skip_mode mode);

/* Decide every row of `s` (rows[0..n) with their group filled) for
 * the checkout at `root`. Always fills the counters; a NULL `tc` is an
 * unknown identity and runs everything. */
void zcl_devloop_early_skip_decide(const char *root,
                                   const struct zcl_devloop_early_toolchain *tc,
                                   struct zcl_devloop_early_skip *s);

/* Record a PASS for every vouched row that ran, each charged an even share
 * of `run_wall_us`. False when the store could not be written. */
bool zcl_devloop_early_skip_record(const char *root,
                                   struct zcl_devloop_early_skip *s,
                                   const char *candidate_sha256,
                                   int64_t run_wall_us);

/* Drop the records of every skipped row: a verify run found a failure the
 * skip would have hidden. */
bool zcl_devloop_early_skip_forget(const char *root,
                                   struct zcl_devloop_early_skip *s);

/* Push the "closure_skip" object onto `doc`. */
void zcl_devloop_early_skip_json(const struct zcl_devloop_early_skip *s,
                                 struct json_value *doc);

#endif /* ZCL_TOOLS_DEV_DEVLOOP_EARLY_SKIP_H */
