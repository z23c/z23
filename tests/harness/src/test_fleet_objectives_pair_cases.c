/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Acceptance cases for the device_pair_ttl_h objective
 *          (tools/command/native_fleet_objectives_pair.c): hours until the
 *          soonest expiry among the newest-epoch pairings in a fixture
 *          pairing store. Each case builds real client epochs the way
 *          20-pair.sh leaves them (route file plus a profile holding the
 *          grant) and reads them with a fixed options.now. Called from
 *          test_fleet_objectives. */

#include "test/test_core.h"

#include "base/hex.h"
#include "command/native_pair_common.h"
#include "command/native_fleet_objectives.h"
#include "models/device_pairing.h"
#include "services/device_identity.h"
#include "util/authority_receipt.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PTL_T0 1790000000LL /* the clock every case measures from */
#define PTL_H 3600LL

enum ptl_mode { PTL_PLAIN, PTL_NO_KEY, PTL_REVOKED, PTL_FRESH };
static enum ptl_mode ptl_mode_now = PTL_PLAIN; /* how ptl_grant leaves the next grant */

static bool ptl_grant(struct device_identity *own, struct device_identity *peer, uint64_t expires,
                      struct device_pairing_store *store, uint8_t root[32])
{
    struct db_device_pairing row = {.capabilities = DEVICE_PAIRING_CAP_HOST_FORWARD,
                                    .paired_at = ptl_mode_now == PTL_FRESH ? pair_now() - 1 : (uint64_t)PTL_T0 - 1,
                                    .expires_at = expires};
    if (!device_identity_pair_store(own, peer->public_key, store).ok)
        return false;
    memcpy(row.local_key, own->public_key, 32);
    memcpy(row.peer_key, peer->public_key, 32);
    memcpy(row.profile, store->profile, 32);
    row.host_scope.outbound_port = 28022;
    row.host_scope.binding.backend_profile = DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK;
    struct device_pairing_psk_binding *binding = &row.host_scope.binding.psk;
    binding->credential_id[0] = 91;
    binding->key_epoch = 1;
    bool first = memcmp(row.local_key, row.peer_key, 32) < 0;
    memcpy(binding->endpoint_a, first ? row.local_key : row.peer_key, 32);
    memcpy(binding->endpoint_b, first ? row.peer_key : row.local_key, 32);
    uint8_t secret[32] = {17}, proposal[32];
    struct device_pairing_psk_publication report;
    struct db_device_pairing found;
    bool made = device_pairing_host_proposal_root(&row, proposal) &&
                db_device_pairing_insert_host_psk(store, &row, secret, proposal, &report) &&
                db_device_pairing_inspect(store, row.peer_key, &found, root);
    if (made && ptl_mode_now == PTL_NO_KEY) {
        char hex[65], secret_path[1300];
        zcl_hex_encode(binding->credential_id, 32, hex);
        (void)snprintf(secret_path, sizeof(secret_path), "%s/%s.psk", store->directory, hex);
        made = unlink(secret_path) == 0;
    }
    if (made && ptl_mode_now == PTL_REVOKED) {
        enum device_pairing_publication publication;
        made = db_device_pairing_revoke(store, row.peer_key, (uint64_t)PTL_T0, &publication);
    }
    return made;
}

static bool ptl_route(const char *dir, const char *profile, const char *peer, unsigned epoch,
                      const uint8_t hub_key[32], const uint8_t root[32])
{
    char hk[65], cr[65], text[1400];
    zcl_hex_encode(hub_key, 32, hk);
    zcl_hex_encode(root, 32, cr);
    int n = snprintf(text, sizeof(text),
                     "{\"directory\":\"%s\",\"peer_key\":\"%s\",\"expected_root\":\"%s\","
                     "\"target_port\":28022,\"route_id\":\"lab-%s-e%u\",\"route_address\":\"127.0.0.1\","
                     "\"route_port\":28022,\"connect_ms\":5000,\"handshake_ms\":10000,"
                     "\"session_ms\":28800000,\"idle_ms\":1800000,\"confirm\":true}",
                     profile, hk, cr, peer, epoch);
    return n > 0 && (size_t)n < sizeof(text) &&
           authority_receipt_write_atomic(dir, "client.json", (const uint8_t *)text, (size_t)n, NULL, 0);
}

/* One client epoch <state>/<peer>-e<epoch> whose grant expires at T0 + secs. */
static bool ptl_epoch(const char *root, const char *peer, unsigned epoch, int64_t secs)
{
    char dir[1100], profile[1200], hub[1100];
    struct device_identity ci = {0}, hi = {0};
    struct device_identity_publication_report report;
    struct device_pairing_store store;
    uint8_t croot[32];
    (void)snprintf(dir, sizeof(dir), "%s/state/%s-e%u", root, peer, epoch);
    (void)snprintf(profile, sizeof(profile), "%s/profile", dir);
    (void)snprintf(hub, sizeof(hub), "%s/hub-%s-e%u", root, peer, epoch);
    if (mkdir(dir, 0700) != 0)
        return false;
    bool ok = device_identity_open(&ci, profile, true, &report).ok &&
              device_identity_open(&hi, hub, true, &report).ok &&
              ptl_grant(&ci, &hi, (uint64_t)(PTL_T0 + secs), &store, croot) &&
              ptl_route(dir, profile, peer, epoch, hi.public_key, croot);
    device_identity_close(&ci);
    device_identity_close(&hi);
    return ok;
}

static bool ptl_store(char *root, size_t cap, const char *tag)
{
    char state[1100];
    if (!test_mkdtemp(root, cap, tag))
        return false;
    (void)snprintf(state, sizeof(state), "%s/state", root);
    return mkdir(state, 0700) == 0;
}

static struct zcl_objective_value ptl_measure(const char *root, int64_t shift_s, char *status, size_t cap)
{
    char state[1100];
    struct zcl_objectives_options o = {0};
    const struct zcl_objective_row *catalog;
    struct zcl_objective_value v;
    (void)snprintf(state, sizeof(state), "%s/state", root);
    o.pair_state_dir = state;
    o.now = PTL_T0 + shift_s;
    v = zcl_objectives_measure(&o, "device_pair_ttl_h");
    status[0] = '\0';
    size_t n = zcl_objectives_catalog(&catalog);
    for (size_t i = 0; i < n; i++)
        if (strcmp(catalog[i].id, "device_pair_ttl_h") == 0)
            zcl_objectives_status(&catalog[i], &v, status, cap);
    return v;
}

static int ptl_case_soonest(void)
{
    int failures = 0;
    char root[512] = "", status[256];
    TEST("pair ttl: the soonest of two current pairings is measured and unmet below 72 h") {
        ASSERT(ptl_store(root, sizeof(root), "pairttl1"));
        ASSERT(ptl_epoch(root, "r2", 1, 49 * PTL_H));
        ASSERT(ptl_epoch(root, "mac", 3, 100 * PTL_H));
        struct zcl_objective_value v = ptl_measure(root, 0, status, sizeof(status));
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)49);
        ASSERT(strcmp(status, "unmet") == 0);
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int ptl_case_met(void)
{
    int failures = 0;
    char root[512] = "", status[256];
    TEST("pair ttl: one pairing with 200 h left is met") {
        ASSERT(ptl_store(root, sizeof(root), "pairttl2"));
        ASSERT(ptl_epoch(root, "r2", 7, 200 * PTL_H));
        struct zcl_objective_value v = ptl_measure(root, 0, status, sizeof(status));
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)200);
        ASSERT(strcmp(status, "met") == 0);
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int ptl_case_expired(void)
{
    int failures = 0;
    char root[512] = "", status[256];
    TEST("pair ttl: an expired newest epoch is measured 0 and unmet, never unmeasured") {
        ASSERT(ptl_store(root, sizeof(root), "pairttl3"));
        ASSERT(ptl_epoch(root, "r2", 1, 200 * PTL_H));
        ASSERT(ptl_epoch(root, "mac", 1, 10 * PTL_H));
        struct zcl_objective_value v = ptl_measure(root, 20 * PTL_H, status, sizeof(status));
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)0);
        ASSERT(strcmp(status, "unmet") == 0);
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int ptl_case_newest_counts(void)
{
    int failures = 0;
    char root[512] = "", status[256];
    TEST("pair ttl: an old expired epoch is ignored when a newer one is active") {
        ASSERT(ptl_store(root, sizeof(root), "pairttl4"));
        ASSERT(ptl_epoch(root, "r2", 6, 10 * PTL_H));
        ASSERT(ptl_epoch(root, "r2", 7, 170 * PTL_H));
        struct zcl_objective_value v = ptl_measure(root, 20 * PTL_H, status, sizeof(status));
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)150);
        ASSERT(strcmp(status, "met") == 0);
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int ptl_case_missing_dir(void)
{
    int failures = 0;
    char root[512] = "", status[256];
    TEST("pair ttl: a missing store is unmeasured and the reason names the directory") {
        ASSERT(test_mkdtemp(root, sizeof(root), "pairttl5"));
        struct zcl_objective_value v = ptl_measure(root, 0, status, sizeof(status));
        ASSERT(!v.measured);
        ASSERT(strstr(v.reason, root) != NULL);
        ASSERT(strncmp(status, "unmeasured(", 11) == 0);
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int ptl_case_unrelated(void)
{
    int failures = 0;
    char root[512] = "", status[256], path[1200];
    TEST("pair ttl: unrelated directory names are ignored and an empty store is unmeasured") {
        ASSERT(ptl_store(root, sizeof(root), "pairttl6"));
        const char *noise[] = {"run", "reverse-r2-r1-20261017", "r2-e", "-e5", "R2-e1", "r2-r1-e1"};
        for (size_t i = 0; i < sizeof(noise) / sizeof(noise[0]); i++) {
            (void)snprintf(path, sizeof(path), "%s/state/%s", root, noise[i]);
            ASSERT(mkdir(path, 0700) == 0);
        }
        struct zcl_objective_value v = ptl_measure(root, 0, status, sizeof(status));
        ASSERT(!v.measured);
        ASSERT(v.reason[0] != '\0');
        ASSERT(ptl_epoch(root, "r2", 1, 90 * PTL_H));
        v = ptl_measure(root, 0, status, sizeof(status));
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)90);
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int ptl_case_boundary(void)
{
    int failures = 0;
    char root[512] = "", status[256];
    TEST("pair ttl: exactly 72 h left is 72 and met, one second less is 71 and unmet") {
        ASSERT(ptl_store(root, sizeof(root), "pairttl7"));
        ASSERT(ptl_epoch(root, "r2", 1, 72 * PTL_H));
        struct zcl_objective_value v = ptl_measure(root, 0, status, sizeof(status));
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)72);
        ASSERT(strcmp(status, "met") == 0);
        v = ptl_measure(root, 1, status, sizeof(status));
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)71);
        ASSERT(strcmp(status, "unmet") == 0);
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int ptl_case_revoked(void)
{
    int failures = 0;
    char root[512] = "", status[256];
    TEST("pair ttl: a revoked newest epoch is measured 0 and unmet over an older active one") {
        ASSERT(ptl_store(root, sizeof(root), "pairttl8"));
        ASSERT(ptl_epoch(root, "r2", 1, 200 * PTL_H));
        ptl_mode_now = PTL_REVOKED;
        bool made = ptl_epoch(root, "r2", 2, 200 * PTL_H);
        ptl_mode_now = PTL_PLAIN;
        ASSERT(made);
        struct zcl_objective_value v = ptl_measure(root, 0, status, sizeof(status));
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)0);
        ASSERT(strcmp(status, "unmet") == 0);
        PASS();
    }
_test_next:;
    ptl_mode_now = PTL_PLAIN;
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int ptl_case_unreadable(void)
{
    int failures = 0;
    char root[512] = "", status[256], state[1100];
    bool locked = false;
    TEST("pair ttl: an unreadable state directory is unmeasured, never 0") {
        if (geteuid() == 0) {
            printf("  SKIP pair ttl unreadable directory: running as root ignores mode 000\n");
            PASS();
            goto _test_next;
        }
        ASSERT(ptl_store(root, sizeof(root), "pairttl9"));
        ASSERT(ptl_epoch(root, "r2", 1, 200 * PTL_H));
        (void)snprintf(state, sizeof(state), "%s/state", root);
        ASSERT(chmod(state, 0) == 0);
        locked = true;
        struct zcl_objective_value v = ptl_measure(root, 0, status, sizeof(status));
        ASSERT(chmod(state, 0700) == 0);
        locked = false;
        ASSERT(!v.measured);
        ASSERT(strstr(v.reason, state) != NULL);
        ASSERT(strncmp(status, "unmeasured(", 11) == 0);
        PASS();
    }
_test_next:;
    if (locked) {
        (void)snprintf(state, sizeof(state), "%s/state", root);
        (void)chmod(state, 0700);
    }
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int ptl_case_hyphen_name(void)
{
    int failures = 0;
    char root[512] = "", status[256];
    TEST("pair ttl: a complete pairing under a hyphenated name is ignored because of its name") {
        ASSERT(ptl_store(root, sizeof(root), "pairttl10"));
        ASSERT(ptl_epoch(root, "r2-r1", 1, 10 * PTL_H));
        struct zcl_objective_value v = ptl_measure(root, 0, status, sizeof(status));
        ASSERT(!v.measured);
        ASSERT(ptl_epoch(root, "r2", 1, 90 * PTL_H));
        v = ptl_measure(root, 0, status, sizeof(status));
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)90);
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(root);
    return failures;
}

/* Empty "<name>-e1" directories only add peer names; count of them decides the cap. */
static bool ptl_noise_peers(const char *root, unsigned count)
{
    char path[1200];
    for (unsigned i = 0; i < count; i++) {
        (void)snprintf(path, sizeof(path), "%s/state/n%u-e1", root, i);
        if (mkdir(path, 0700) != 0)
            return false;
    }
    return true;
}

static int ptl_case_peer_cap(void)
{
    int failures = 0;
    char root[512] = "", status[256];
    TEST("pair ttl: 64 peers are measured, a 65th makes the objective unmeasured naming the cap") {
        ASSERT(ptl_store(root, sizeof(root), "pairttl11"));
        ASSERT(ptl_epoch(root, "r2", 1, 90 * PTL_H));
        ASSERT(ptl_noise_peers(root, 63));
        char over[1200];
        (void)snprintf(over, sizeof(over), "%s/state/n63-e1", root);
        struct zcl_objective_value v = ptl_measure(root, 0, status, sizeof(status));
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)90);
        ASSERT(mkdir(over, 0700) == 0); /* n63 is the 65th distinct peer */
        v = ptl_measure(root, 0, status, sizeof(status));
        ASSERT(!v.measured);
        ASSERT(strstr(v.reason, "64") != NULL);
        ASSERT(strncmp(status, "unmeasured(", 11) == 0);
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int ptl_case_no_key_material(void)
{
    int failures = 0;
    char root[512] = "", status[256];
    TEST("pair ttl: the read succeeds with no pre-shared key on disk (metadata only)") {
        ASSERT(ptl_store(root, sizeof(root), "pairttl12"));
        ptl_mode_now = PTL_NO_KEY;
        bool made = ptl_epoch(root, "r2", 1, 90 * PTL_H);
        ptl_mode_now = PTL_PLAIN;
        ASSERT(made);
        struct zcl_objective_value v = ptl_measure(root, 0, status, sizeof(status));
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)90);
        /* Helper contract: with the key present the metadata read still leaves the fingerprint
         * empty while the full loader fills it (the objective's own outcome cannot show this,
         * because a failed fingerprint never fails a load). */
        ptl_mode_now = PTL_FRESH; /* the grant TTL cap is 30 days from paired_at: use the real clock */
        made = ptl_epoch(root, "r3", 1, (int64_t)pair_now() - PTL_T0 + 24 * PTL_H);
        ptl_mode_now = PTL_PLAIN;
        ASSERT(made);
        char state[1100];
        struct pair_epoch meta, full;
        (void)snprintf(state, sizeof(state), "%s/state", root);
        ASSERT(pair_epoch_load_meta(state, "r3", 1, &meta));
        ASSERT(pair_epoch_load(state, "r3", 1, &full));
        ASSERT(meta.psk_fp[0] == '\0');
        ASSERT(full.psk_fp[0] != '\0');
        PASS();
    }
_test_next:;
    ptl_mode_now = PTL_PLAIN;
    (void)test_rm_rf_recursive(root);
    return failures;
}

int fox_pair_cases(void);
int fox_pair_cases(void)
{
    int failures = 0;
    failures += ptl_case_soonest();
    failures += ptl_case_met();
    failures += ptl_case_expired();
    failures += ptl_case_newest_counts();
    failures += ptl_case_missing_dir();
    failures += ptl_case_unrelated();
    failures += ptl_case_boundary();
    failures += ptl_case_revoked();
    failures += ptl_case_unreadable();
    failures += ptl_case_hyphen_name();
    failures += ptl_case_peer_cap();
    failures += ptl_case_no_key_material();
    return failures;
}
