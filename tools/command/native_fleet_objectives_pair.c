/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The LAB producer behind the `device_pair_ttl_h` objective: hours
 *          until the soonest expiry among the CURRENT (newest-epoch) device
 *          pairings in the local pairing store, so the lab notices a tunnel
 *          grant that is about to lapse before releases start failing. A
 *          peer whose newest epoch is expired or revoked counts as 0 hours;
 *          a store that cannot be read, or that names more than 64 peers, is
 *          unmeasured (the directory or the cap named), never 0 or met.
 * Read-only: it reads the same public pairing facts
 *          `ops.mesh.device.pair.status` prints through pair_epoch_load_meta,
 *          which does not read the pre-shared key; opening the pairing
 *          profile reads the device identity key into memory only, and it
 *          is cleansed on close. options->pair_state_dir points it at a
 *          fixture. */

#include "native_fleet_objectives.h"

#include "base/safe_alloc.h"
#include "command/native_pair_common.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OBJ_PAIR_PEERS_MAX 64u
#define OBJ_PAIR_STATE_DEFAULT "/.local/state/z23-tunnel"

struct obj_pair_scan {
    char peers[OBJ_PAIR_PEERS_MAX][PAIR_NAME_MAX];
    size_t peer_count;
    bool overflow;           /* more than OBJ_PAIR_PEERS_MAX distinct peers seen */
    uint64_t now;
    bool any;
    int64_t soonest_s;       /* smallest seconds left; 0 once any is lapsed */
    char soonest_peer[PAIR_NAME_MAX];
    uint32_t soonest_epoch;
};

/* The peer part of "<peer>-e<digits>" (everything before the LAST "-e" run
 * of digits) when it is a valid pairing name, else false. */
static bool obj_pair_peer_of(const char *name, char peer[PAIR_NAME_MAX])
{
    size_t length = strlen(name), digits = 0;
    while (digits < length && name[length - 1 - digits] >= '0' && name[length - 1 - digits] <= '9')
        digits++;
    if (digits == 0 || length < digits + 3 || name[length - digits - 1] != 'e' ||
        name[length - digits - 2] != '-')
        return false;
    size_t peer_len = length - digits - 2;
    if (peer_len >= PAIR_NAME_MAX)
        return false;
    memcpy(peer, name, peer_len);
    peer[peer_len] = '\0';
    return pair_name_ok(peer);
}

static void obj_pair_add_peer(struct obj_pair_scan *scan, const char *peer)
{
    for (size_t i = 0; i < scan->peer_count; i++)
        if (strcmp(scan->peers[i], peer) == 0)
            return;
    if (scan->peer_count >= OBJ_PAIR_PEERS_MAX)
        scan->overflow = true;
    else
        snprintf(scan->peers[scan->peer_count++], PAIR_NAME_MAX, "%s", peer);
}

/* Collect the distinct peer names; false when the directory cannot be opened. */
static bool obj_pair_collect(const char *state, struct obj_pair_scan *scan)
{
    DIR *handle = opendir(state);
    if (!handle)
        return false;
    for (const struct dirent *entry = readdir(handle); entry; entry = readdir(handle)) {
        char peer[PAIR_NAME_MAX];
        if (obj_pair_peer_of(entry->d_name, peer))
            obj_pair_add_peer(scan, peer);
    }
    closedir(handle);
    return true;
}

static void obj_pair_record(struct obj_pair_scan *scan, const char *peer, const struct pair_epoch *epoch)
{
    int64_t left = 0;
    if (pair_epoch_state(epoch, scan->now) == PAIR_ACTIVE)
        left = (int64_t)epoch->row.expires_at - (int64_t)scan->now;
    if (left < 0)
        left = 0;
    if (scan->any && left >= scan->soonest_s)
        return;
    scan->any = true;
    scan->soonest_s = left;
    scan->soonest_epoch = epoch->epoch;
    snprintf(scan->soonest_peer, sizeof(scan->soonest_peer), "%s", peer);
}

/* Fold one peer's NEWEST epoch into the scan; an unloadable one is skipped. */
static void obj_pair_peer(const char *state, const char *peer, struct obj_pair_scan *scan)
{
    uint32_t epochs[PAIR_EPOCH_LIST_MAX];
    struct pair_epoch loaded;
    size_t count = pair_epoch_list(state, peer, epochs, PAIR_EPOCH_LIST_MAX);
    if (count == 0 || !pair_epoch_load_meta(state, peer, epochs[count - 1], &loaded))
        return;
    obj_pair_record(scan, peer, &loaded);
}

static bool obj_pair_state_dir(const struct zcl_objectives_options *options, char *buf, size_t cap)
{
    const char *home = getenv("HOME");
    if (options && options->pair_state_dir && options->pair_state_dir[0])
        return snprintf(buf, cap, "%s", options->pair_state_dir) < (int)cap;
    return home && home[0] && snprintf(buf, cap, "%s%s", home, OBJ_PAIR_STATE_DEFAULT) < (int)cap;
}

static void obj_pair_unmeasured(struct zcl_objective_value *v, const char *what, const char *dir)
{
    v->measured = false;
    (void)snprintf(v->reason, sizeof(v->reason), "%s: %s", what, dir[0] ? dir : "(no state directory)");
}

struct zcl_objective_value zcl_objectives_device_pair_ttl_h(const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    struct obj_pair_scan *scan = zcl_calloc(1, sizeof(*scan), "pair_ttl_scan");
    char dir[PAIR_PATH_MAX] = "";
    if (!scan) {
        obj_pair_unmeasured(&v, "out of memory reading the pairing store", dir);
        return v;
    }
    scan->now = options && options->now > 0 ? (uint64_t)options->now : pair_now();
    if (!obj_pair_state_dir(options, dir, sizeof(dir)) || !pair_path_ok(dir))
        obj_pair_unmeasured(&v, "no usable pairing store directory", dir);
    else if (!obj_pair_collect(dir, scan))
        obj_pair_unmeasured(&v, "no readable pairing store directory", dir);
    else if (scan->overflow)
        obj_pair_unmeasured(&v, "more than 64 peer names (cap 64), not measured under", dir);
    else {
        for (size_t i = 0; i < scan->peer_count; i++)
            obj_pair_peer(dir, scan->peers[i], scan);
        if (!scan->any)
            obj_pair_unmeasured(&v, "no loadable current pairing under", dir);
        else {
            v.measured = true;
            v.value = scan->soonest_s / 3600;
            (void)snprintf(v.note, sizeof(v.note), "soonest current pairing: %s epoch %u",
                           scan->soonest_peer, (unsigned)scan->soonest_epoch);
        }
    }
    free(scan);
    return v;
}
