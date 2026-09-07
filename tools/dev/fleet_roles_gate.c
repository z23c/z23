/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The half of fleet ROLES that the ENGINE reaches: the checker this box
 * installs into base/fleet_role_check.h's seam, and the bootstrap that
 * keeps a fleet which was working before roles existed working after.
 * See tools/dev/fleet_roles.h for the contract.
 *
 * Layering is the whole reason this file exists. The catalog and the signed
 * grant store live here in tools/dev; the two places another machine's
 * signed bytes enter this node — zcl_fleet_ledger_replicate() and
 * db_fleet_board_post_ingest() — live under engine/, which may not include
 * a tools/ header. So the engine declares a vtable and asks it; this file
 * fills the vtable in, and engine/entry/main.c is the one place that calls
 * the filling in, the same way it already wires every other adapter that
 * only the top of the tree can see.
 *
 * THE STORE IS OPENED PER CHECK, ON PURPOSE. A chainlog takes an exclusive
 * whole-file lock, so a handle kept for the life of the node would hold
 * that lock forever and `z23 fleet roles grant` would block until the node
 * stopped — the same argument fleet_ledger.c makes about its own chains.
 * A check therefore opens, folds the rows, answers, and closes. The ledger
 * asks once per distinct row KIND in a batch rather than once per row, and
 * a board post is one check; neither is a hot loop.
 */

#include "fleet_roles.h"

#include "fleet_enrol.h"

#include "base/fleet_role_check.h"
#include "base/log_macros.h"
#include "platform/time_compat.h"
#include "vcs/zcode_dht_identity.h"

#include <stdio.h>
#include <string.h>

#define ROLE_GATE_DOMAIN "fleet.roles"
#define ROLE_GATE_DATADIR_MAX 512u

/* Set once, at zcl_fleet_roles_enforcement_start, before the lanes that
 * read them exist. `g_self_pub` is this node's own online key: its own key
 * holds `operator` implicitly and is never looked up in the store. */
static char g_datadir[ROLE_GATE_DATADIR_MAX];
static uint8_t g_self_pub[32];
static bool g_have_self;

/* This node's own operator identity: the online key its filed delegation
 * delegates. Mirrors native_fleet_roles_command.c's roles_operator_identity
 * as its own small copy, the way each fleet leaf file already does rather
 * than reaching across for one. */
static bool gate_operator_identity(const char *datadir, uint8_t pub[32],
                                   uint8_t seed[32], const char **why)
{
    struct vcs_zcode_dht_delegation delegation;
    char error[160];
    uint8_t online_pub[32];
    if (!datadir ||
        !vcs_zcode_dht_delegation_load(datadir, &delegation, error,
                                       sizeof error)) {
        if (why)
            *why = "this machine has no filed delegation, so it has no "
                   "operator key to sign a grant with";
        return false;
    }
    if (!vcs_zcode_dht_online_key_load(datadir, seed, online_pub, error,
                                       sizeof error)) {
        if (why)
            *why = "this machine has no online key";
        return false;
    }
    if (memcmp(online_pub, delegation.online_pubkey, 32) != 0) {
        if (why)
            *why = "the online key on disk is not the one this machine's "
                   "delegation delegates";
        return false;
    }
    memcpy(pub, online_pub, 32);
    return true;
}

/* ── the checker ─────────────────────────────────────────────────────── */

static bool gate_allow(const uint8_t key[32], const char *leaf,
                       const char *kind, char *why, size_t why_cap, void *ctx)
{
    (void)ctx;
    if (g_have_self && memcmp(key, g_self_pub, 32) == 0)
        return true; /* this node's own key: `operator`, checked by identity */
    uint8_t fp[ZCL_ROLE_FP_BYTES];
    zcl_role_fingerprint(key, fp);
    struct zcl_role_report report;
    struct zcl_role_store *store = zcl_role_store_open(g_datadir, &report);
    if (!store) {
        if (why && why_cap)
            (void)snprintf(why, why_cap,
                           "REFUSED role: the role store did not open (%s)",
                           zcl_role_status_label(report.status));
        return false;
    }
    bool ok = zcl_role_check(store, fp, false, leaf, kind, why, why_cap);
    zcl_role_store_close(store);
    return ok;
}

/* ── grants ──────────────────────────────────────────────────────────── */

/* One grant against an already-open store and an already-loaded identity.
 * Returns true when the key holds `worker` afterwards. */
static bool gate_grant_one(struct zcl_role_store *store,
                           const uint8_t pubkey[32],
                           const uint8_t op_pub[32], const uint8_t op_seed[32],
                           int64_t now, bool *minted)
{
    uint8_t fp[ZCL_ROLE_FP_BYTES];
    char fp8[9];
    zcl_role_fingerprint(pubkey, fp);
    if (zcl_role_store_has_role(store, fp, ZCL_ROLE_worker))
        return true;
    enum zcl_role_status st = zcl_role_store_grant(store, fp, ZCL_ROLE_worker,
                                                   op_pub, op_seed, now, NULL);
    zcl_role_fingerprint_short(fp, fp8);
    if (st != ZCL_ROLE_OK) {
        LOG_WARN(ROLE_GATE_DOMAIN, "could not grant worker to key %s: %s",
                 fp8, zcl_role_status_label(st));
        return false;
    }
    LOG_INFO(ROLE_GATE_DOMAIN, "granted worker to enrolled key %s", fp8);
    if (minted)
        *minted = true;
    return true;
}

size_t zcl_fleet_roles_bootstrap_keys(const char *datadir,
                                      const uint8_t (*keys)[32], size_t count,
                                      int64_t now, const char **why)
{
    uint8_t op_pub[32], op_seed[32];
    if (!datadir || (!keys && count))
        return 0;
    if (!gate_operator_identity(datadir, op_pub, op_seed, why))
        return 0;
    struct zcl_role_report report;
    struct zcl_role_store *store = zcl_role_store_open(datadir, &report);
    if (!store) {
        memset(op_seed, 0, sizeof op_seed);
        if (why)
            *why = zcl_role_status_label(report.status);
        return 0;
    }
    size_t minted = 0;
    for (size_t i = 0; i < count; i++) {
        bool one = false;
        (void)gate_grant_one(store, keys[i], op_pub, op_seed, now, &one);
        if (one)
            minted++;
    }
    memset(op_seed, 0, sizeof op_seed);
    zcl_role_store_close(store);
    return minted;
}

bool zcl_fleet_roles_grant_worker(const char *datadir,
                                  const uint8_t pubkey[32], int64_t now,
                                  const char **why)
{
    uint8_t op_pub[32], op_seed[32];
    if (!datadir || !pubkey)
        return false;
    if (!gate_operator_identity(datadir, op_pub, op_seed, why))
        return false;
    struct zcl_role_report report;
    struct zcl_role_store *store = zcl_role_store_open(datadir, &report);
    if (!store) {
        memset(op_seed, 0, sizeof op_seed);
        if (why)
            *why = zcl_role_status_label(report.status);
        return false;
    }
    bool held = gate_grant_one(store, pubkey, op_pub, op_seed, now, NULL);
    memset(op_seed, 0, sizeof op_seed);
    zcl_role_store_close(store);
    if (!held && why)
        *why = "the grant row could not be written";
    return held;
}

/* ── the enrolment bootstrap ─────────────────────────────────────────── */

struct gate_roster {
    uint8_t keys[FLEET_ENROL_ROSTER_MAX][32];
    size_t count;
};

static void gate_roster_row(const struct fleet_machine *machine, void *user)
{
    struct gate_roster *r = user;
    if (r->count >= FLEET_ENROL_ROSTER_MAX)
        return;
    memcpy(r->keys[r->count++], machine->receipt.box_pubkey, 32);
}

/* Whose roster is this? On a box that joined a fleet, the operator is the
 * key the owner pasted; on the manager, it is this box's own fleet key. A
 * box that has done neither has no roster, which is a state, not an error —
 * the same answer `fleet machines` gives. */
static bool gate_roster_authority(uint8_t out[FLEET_ENROL_PUBKEY_BYTES],
                                  const char **why)
{
    bool joined = false, own_present = false;
    uint8_t seed[FLEET_ENROL_SEED_BYTES];
    if (!fleet_enrol_operator_read(out, &joined, why))
        return false;
    if (joined)
        return true;
    bool ok = fleet_enrol_key_load(seed, out, false, &own_present, why);
    memset(seed, 0, sizeof seed);
    return ok && own_present;
}

size_t zcl_fleet_roles_bootstrap_enrolled(const char *datadir, int64_t now,
                                          const char **why)
{
    uint8_t authority[FLEET_ENROL_PUBKEY_BYTES];
    struct gate_roster roster;
    struct fleet_roster_scan scan;
    memset(&roster, 0, sizeof roster);
    memset(&scan, 0, sizeof scan);
    if (!datadir || !gate_roster_authority(authority, why))
        return 0;
    if (!fleet_roster_each(authority, gate_roster_row, &roster, &scan, why))
        return 0;
    if (roster.count == 0)
        return 0;
    return zcl_fleet_roles_bootstrap_keys(datadir, roster.keys, roster.count,
                                          now, why);
}

/* ── start ───────────────────────────────────────────────────────────── */

void zcl_fleet_roles_enforcement_start(const char *datadir)
{
    static const struct zcl_fleet_role_checker checker = {
        .allow = gate_allow, .ctx = NULL, .name = "fleet_roles_store"
    };
    uint8_t seed[32];
    char error[160];
    const char *why = NULL;
    if (!datadir || datadir[0] != '/' ||
        (size_t)snprintf(g_datadir, sizeof g_datadir, "%s", datadir) >=
            sizeof g_datadir) {
        LOG_WARN(ROLE_GATE_DOMAIN,
                 "no absolute datadir: role enforcement stays closed and "
                 "every foreign-signed row and post is refused");
        return;
    }
    /* Load-only: observing our own identity must never mint one. */
    g_have_self = vcs_zcode_dht_online_key_load(g_datadir, seed, g_self_pub,
                                                error, sizeof error);
    memset(seed, 0, sizeof seed);
    zcl_fleet_role_checker_install(&checker);
    size_t minted = zcl_fleet_roles_bootstrap_enrolled(
        g_datadir, (int64_t)platform_time_wall_time_t(), &why);
    if (minted)
        LOG_INFO(ROLE_GATE_DOMAIN,
                 "granted the worker role to %zu enrolled machine(s) that "
                 "held none", minted);
    else if (why)
        LOG_INFO(ROLE_GATE_DOMAIN, "no enrolment grants minted: %s", why);
}
