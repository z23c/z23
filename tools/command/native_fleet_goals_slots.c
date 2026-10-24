/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The local half of the G5 plugin-swarm row. It rehashes each
 *          installed slot binary and compares it with the install record
 *          (native_slot_common.c). It never fetches from a peer and never
 *          writes. The grade is for this host only: no receipt says how a
 *          binary reached the slot, so the best reading is PARTIAL. */

#include "native_fleet_goals_slots.h"

#include "native_slot_common.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>

struct gs_tally {
    size_t slots, ok, no_record, mismatch, unsafe, writable;
};

static void gs_count(struct gs_tally *t, enum slot_verify v)
{
    t->slots++;
    switch (v) {
    case SLOT_VERIFY_OK:
        t->ok++;
        break;
    case SLOT_VERIFY_NO_RECORD:
        t->no_record++;
        break;
    case SLOT_VERIFY_MISMATCH:
        t->mismatch++;
        break;
    case SLOT_VERIFY_UNSAFE:
        t->unsafe++;
        break;
    case SLOT_VERIFY_WRITABLE:
        t->writable++;
        break;
    }
}

/* Only names slot_name_ok accepts are slots. An overlong path cannot be
 * verified, so it counts as unsafe rather than being skipped. */
static void gs_probe_entry(const char *root, const char *name,
                           struct gs_tally *t)
{
    char path[SLOT_PATH_MAX];
    int n;
    if (!slot_name_ok(name))
        return;
    n = snprintf(path, sizeof(path), "%s/%s", root, name);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        gs_count(t, SLOT_VERIFY_UNSAFE);
        return;
    }
    gs_count(t, slot_verify_installed(path));
}

static bool gs_scan(const char *root, struct gs_tally *t)
{
    DIR *d = opendir(root);
    struct dirent *e;
    if (!d)
        return false;
    while ((e = readdir(d)) != NULL)
        gs_probe_entry(root, e->d_name, t);
    (void)closedir(d);
    return true;
}

static struct zcl_goal_result gs_grade_bad(const struct gs_tally *t)
{
    static const char next[] = "reinstall the slot binary from a verified "
                               "release, then rerun fleet goals";
    return zcl_goal_make(ZCL_GOAL_FAIL, next,
                         "binary slot check FAIL on this host: %zu mismatch, "
                         "%zu unsafe, %zu writable; %zu of %zu slot(s) verify",
                         t->mismatch, t->unsafe, t->writable, t->ok, t->slots);
}

static struct zcl_goal_result gs_grade_ok(const struct gs_tally *t,
                                          size_t admitted)
{
    static const char next[] = "card: peer-fetch receipts per admitted host "
                               "(source, pin check, atomic install)";
    size_t unprobed = admitted > 0 ? admitted - 1 : 0;
    return zcl_goal_make(ZCL_GOAL_PARTIAL, next,
                         "this host only, %zu of %zu admitted hosts unprobed; "
                         "peer-fetch provenance, pin check and atomic install "
                         "are not recorded (%zu of %zu slot(s) verify)",
                         unprobed, admitted, t->ok, t->slots);
}

static struct zcl_goal_result gs_grade(const struct gs_tally *t,
                                       size_t admitted)
{
    static const char next[] = "card: peer-fetch receipts per admitted host "
                               "(source, pin check, atomic install)";
    if (t->mismatch + t->unsafe + t->writable > 0)
        return gs_grade_bad(t);
    if (t->ok > 0)
        return gs_grade_ok(t, admitted);
    if (t->slots == 0)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "no binary slot on this host");
    return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                         "%zu slot(s) on this host have no install record; "
                         "not a measurement",
                         t->no_record);
}

struct zcl_goal_result zcl_goals_slots_measure(
    const struct zcl_goals_slots_in *in)
{
    static const char next[] = "card: peer-fetch receipts per admitted host "
                               "(source, pin check, atomic install)";
    char root[SLOT_PATH_MAX];
    struct gs_tally t = {0};
    const char *dir;
    size_t admitted = in ? in->admitted_hosts : 0;

    if (!in || in->skip)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "%zu admitted host(s) unprobed: binary-slot "
                             "probe skipped",
                             admitted);
    dir = in->slots_root;
    if (!dir) {
        if (!slot_root(root, sizeof(root)))
            return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                                 "no binary slot root for this user");
        dir = root;
    }
    if (!gs_scan(dir, &t))
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "no binary slot directory on this host");
    return gs_grade(&t, admitted);
}
