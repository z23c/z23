/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for the G5 local binary-slot reader
 * (tools/command/native_fleet_goals_slots.c). Every case builds its own slot
 * root under a fresh tmpdir and grades it: UNMEASURED for an empty, missing
 * or record-less root and for the skip path; PARTIAL for one verified slot;
 * FAIL for a mismatch, a writable or a symlinked slot. Nothing here reads a
 * live slot directory.
 */

#include "test/test_core.h"

#include "command/native_fleet_goals.h"
#include "command/native_fleet_goals_slots.h"
#include "command/native_slot_common.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int gsl_check(bool ok, const char *what)
{
    printf("fleet_goals_slots: %s... %s\n", what, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool gsl_has(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

/* A fresh tmpdir holding an empty slots/ root; false if it cannot be made. */
static bool gsl_setup(char *slots, size_t cap, const char *leaf)
{
    char base[512];
    test_make_tmpdir(base, sizeof(base), "fleet_goals_slots", leaf);
    if (snprintf(slots, cap, "%s/slots", base) >= (int)cap)
        return false;
    return mkdir(slots, 0755) == 0;
}

/* Write <slots>/<name>/z23 with the given bytes. */
static bool gsl_put(const char *slots, const char *name, const char *bytes)
{
    char dir[SLOT_PATH_MAX], path[SLOT_PATH_MAX];
    FILE *f;
    size_t len = strlen(bytes);
    if (snprintf(dir, sizeof(dir), "%s/%s", slots, name) >= (int)sizeof(dir) ||
        snprintf(path, sizeof(path), "%s/z23", dir) >= (int)sizeof(path))
        return false;
    if (mkdir(dir, 0755) != 0 && errno != EEXIST)
        return false;
    f = fopen(path, "wb");
    if (!f)
        return false;
    if (fwrite(bytes, 1, len, f) != len) {
        (void)fclose(f);
        return false;
    }
    if (fclose(f) != 0)
        return false;
    return chmod(path, 0755) == 0;
}

/* Record the install digest of the binary as it is now. */
static bool gsl_record(const char *slots, const char *name)
{
    char dir[SLOT_PATH_MAX];
    uint8_t sha[32];
    if (snprintf(dir, sizeof(dir), "%s/%s", slots, name) >= (int)sizeof(dir))
        return false;
    return slot_binary_digest(dir, sha) && slot_record_write(dir, sha);
}

static bool gsl_good(const char *slots, const char *name, const char *bytes)
{
    return gsl_put(slots, name, bytes) && gsl_record(slots, name);
}

static struct zcl_goals_slots_in gsl_in(const char *slots, size_t admitted)
{
    struct zcl_goals_slots_in in;
    memset(&in, 0, sizeof(in));
    in.slots_root = slots;
    in.admitted_hosts = admitted;
    return in;
}

static int gsl_case_empty_and_missing(void)
{
    char slots[SLOT_PATH_MAX], absent[SLOT_PATH_MAX], base[512];
    int failures = 0;
    struct zcl_goals_slots_in in;
    struct zcl_goal_result r;
    if (!gsl_setup(slots, sizeof(slots), "empty"))
        return gsl_check(false, "setup empty root");
    in = gsl_in(slots, 3);
    r = zcl_goals_slots_measure(&in);
    failures += gsl_check(r.grade == ZCL_GOAL_UNMEASURED, "empty root is UNMEASURED");
    failures += gsl_check(gsl_has(r.evidence, "no binary slot on this host"),
                          "empty root names the missing slot");
    test_make_tmpdir(base, sizeof(base), "fleet_goals_slots", "missing");
    (void)snprintf(absent, sizeof(absent), "%s/absent", base);
    in = gsl_in(absent, 3);
    r = zcl_goals_slots_measure(&in);
    failures += gsl_check(r.grade == ZCL_GOAL_UNMEASURED, "missing root is UNMEASURED");
    failures += gsl_check(gsl_has(r.evidence, "no binary slot directory"),
                          "missing root names the directory");
    return failures;
}

static int gsl_case_ok_is_partial(void)
{
    char slots[SLOT_PATH_MAX];
    int failures = 0;
    struct zcl_goals_slots_in in;
    struct zcl_goal_result r;
    if (!gsl_setup(slots, sizeof(slots), "ok") ||
        !gsl_good(slots, "z23-alpha", "binary-one"))
        return gsl_check(false, "setup verified slot");
    in = gsl_in(slots, 3);
    r = zcl_goals_slots_measure(&in);
    failures += gsl_check(r.grade == ZCL_GOAL_PARTIAL, "verified slot is PARTIAL");
    failures += gsl_check(r.grade != ZCL_GOAL_PASS, "verified slot is never PASS");
    failures += gsl_check(gsl_has(r.evidence,
                                  "this host only, 2 of 3 admitted hosts unprobed; "
                                  "peer-fetch provenance, pin check and atomic "
                                  "install are not recorded"),
                          "PARTIAL names the unprobed hosts and the missing receipts");
    in = gsl_in(slots, 0);
    r = zcl_goals_slots_measure(&in);
    failures += gsl_check(r.grade == ZCL_GOAL_PARTIAL &&
                              gsl_has(r.evidence, "0 of 0 admitted hosts unprobed"),
                          "zero admitted hosts never underflows");
    return failures;
}

static int gsl_case_tampered_is_fail(void)
{
    char slots[SLOT_PATH_MAX];
    int failures = 0;
    struct zcl_goals_slots_in in;
    struct zcl_goal_result r;
    if (!gsl_setup(slots, sizeof(slots), "mismatch") ||
        !gsl_good(slots, "z23-beta", "binary-two") ||
        !gsl_put(slots, "z23-beta", "binary-TAMPERED"))
        return gsl_check(false, "setup tampered slot");
    in = gsl_in(slots, 3);
    r = zcl_goals_slots_measure(&in);
    failures += gsl_check(r.grade == ZCL_GOAL_FAIL, "tampered binary is FAIL");
    failures += gsl_check(gsl_has(r.evidence, "1 mismatch"),
                          "FAIL counts the mismatch");
    return failures;
}

static int gsl_case_writable_is_fail(void)
{
    char slots[SLOT_PATH_MAX], dir[SLOT_PATH_MAX];
    int failures = 0;
    struct zcl_goals_slots_in in;
    struct zcl_goal_result r;
    if (!gsl_setup(slots, sizeof(slots), "writable") ||
        !gsl_good(slots, "z23-gamma", "binary-three"))
        return gsl_check(false, "setup writable slot");
    (void)snprintf(dir, sizeof(dir), "%s/z23-gamma", slots);
    failures += gsl_check(chmod(dir, 0775) == 0, "make slot group-writable");
    in = gsl_in(slots, 3);
    r = zcl_goals_slots_measure(&in);
    failures += gsl_check(r.grade == ZCL_GOAL_FAIL, "group-writable slot is FAIL");
    failures += gsl_check(gsl_has(r.evidence, "1 writable"),
                          "FAIL counts the writable slot");
    return failures;
}

static int gsl_case_symlink_is_fail(void)
{
    char slots[SLOT_PATH_MAX], target[SLOT_PATH_MAX], link[SLOT_PATH_MAX];
    int failures = 0;
    struct zcl_goals_slots_in in;
    struct zcl_goal_result r;
    if (!gsl_setup(slots, sizeof(slots), "unsafe") ||
        !gsl_good(slots, "z23-real", "binary-four"))
        return gsl_check(false, "setup symlink target");
    (void)snprintf(target, sizeof(target), "%s/z23-real", slots);
    (void)snprintf(link, sizeof(link), "%s/z23-link", slots);
    failures += gsl_check(symlink(target, link) == 0, "create symlinked slot");
    in = gsl_in(slots, 3);
    r = zcl_goals_slots_measure(&in);
    failures += gsl_check(r.grade == ZCL_GOAL_FAIL, "symlinked slot is FAIL");
    failures += gsl_check(gsl_has(r.evidence, "1 unsafe"),
                          "FAIL counts the unsafe slot");
    return failures;
}

static int gsl_case_no_record_is_unmeasured(void)
{
    char slots[SLOT_PATH_MAX];
    int failures = 0;
    struct zcl_goals_slots_in in;
    struct zcl_goal_result r;
    if (!gsl_setup(slots, sizeof(slots), "norecord") ||
        !gsl_put(slots, "z23-delta", "binary-five"))
        return gsl_check(false, "setup record-less slot");
    in = gsl_in(slots, 3);
    r = zcl_goals_slots_measure(&in);
    failures += gsl_check(r.grade == ZCL_GOAL_UNMEASURED,
                          "slot with no install record is UNMEASURED");
    failures += gsl_check(gsl_has(r.evidence, "1 slot(s) on this host have no install record"),
                          "UNMEASURED names the missing record");
    return failures;
}

static int gsl_case_bad_beats_ok(void)
{
    char slots[SLOT_PATH_MAX];
    int failures = 0;
    struct zcl_goals_slots_in in;
    struct zcl_goal_result r;
    if (!gsl_setup(slots, sizeof(slots), "mixed") ||
        !gsl_good(slots, "z23-one", "binary-six") ||
        !gsl_good(slots, "z23-two", "binary-seven") ||
        !gsl_put(slots, "z23-two", "binary-SEVEN-TAMPERED"))
        return gsl_check(false, "setup mixed roots");
    in = gsl_in(slots, 3);
    r = zcl_goals_slots_measure(&in);
    failures += gsl_check(r.grade == ZCL_GOAL_FAIL,
                          "one verified slot never hides a mismatch");
    failures += gsl_check(gsl_has(r.evidence, "1 of 2 slot(s) verify"),
                          "FAIL reports the verified count");
    return failures;
}

static int gsl_case_non_slot_names_ignored(void)
{
    char slots[SLOT_PATH_MAX], hidden[SLOT_PATH_MAX];
    int failures = 0;
    struct zcl_goals_slots_in in;
    struct zcl_goal_result r;
    if (!gsl_setup(slots, sizeof(slots), "names") ||
        !gsl_put(slots, "Bad Name", "binary-eight"))
        return gsl_check(false, "setup non-slot name");
    (void)snprintf(hidden, sizeof(hidden), "%s/.hidden", slots);
    failures += gsl_check(mkdir(hidden, 0755) == 0, "create hidden entry");
    in = gsl_in(slots, 3);
    r = zcl_goals_slots_measure(&in);
    failures += gsl_check(r.grade == ZCL_GOAL_UNMEASURED,
                          "names slot_name_ok rejects are not slots");
    return failures;
}

static int gsl_case_skip_is_unmeasured(void)
{
    struct zcl_goals_slots_in in;
    struct zcl_goal_result r;
    int failures = 0;
    memset(&in, 0, sizeof(in));
    in.admitted_hosts = 3;
    in.skip = true;
    r = zcl_goals_slots_measure(&in);
    failures += gsl_check(r.grade == ZCL_GOAL_UNMEASURED,
                          "skip is UNMEASURED");
    failures += gsl_check(gsl_has(r.evidence, "3 admitted host(s)"),
                          "skip names the admitted host count");
    return failures;
}

int test_fleet_goals_slots(void);
int test_fleet_goals_slots(void)
{
    int failures = 0;
    failures += gsl_case_empty_and_missing();
    failures += gsl_case_ok_is_partial();
    failures += gsl_case_tampered_is_fail();
    failures += gsl_case_writable_is_fail();
    failures += gsl_case_symlink_is_fail();
    failures += gsl_case_no_record_is_unmeasured();
    failures += gsl_case_bad_beats_ok();
    failures += gsl_case_non_slot_names_ignored();
    failures += gsl_case_skip_is_unmeasured();
    if (failures == 0)
        printf("test_fleet_goals_slots: all passed\n");
    else
        printf("test_fleet_goals_slots: %d FAILED\n", failures);
    return failures;
}
