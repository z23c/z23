/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves that local machine pairing is explicit, Noise-bound, narrowly
 * scoped, expiring, and durably revoked. */

#include "test/test_core.h"

#include "config/boot_mesh_pairing.h"
#include "config/boot_mesh_status.h"
#include "config/boot_mesh_machines.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "models/mesh_machine_observation.h"
#include "models/mesh_pairing.h"
#include "models/zid_identity.h"
#include "net/v2_identity.h"
#include "services/mesh_pairing_service.h"
#include "validation/main_constants.h"
#include "vcs/zcode_dht_delegation.h"

#include <stdio.h>
#include <string.h>

static void mesh_fill32(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

/* raw-sql-ok:test-fixture -- creates only the connected chain rows required
 * to exercise the production chain-bound pairing verifier. */
static bool mesh_seed_block(struct node_db *ndb, int height,
                            const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    static const char sql[] =
        "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,time,"
        "bits,nonce,solution,chain_work,status,num_tx) "
        "VALUES(?,?,zeroblob(32),4,zeroblob(32),1,1,zeroblob(32),"
        "X'00',zeroblob(32),3,0)";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool mesh_fixture(struct node_db *ndb, const char *path,
                         struct vcs_zcode_dht_delegation *delegation,
                         uint8_t fingerprint[32])
{
    if (!node_db_open(ndb, path))
        return false;
    uint8_t genesis[32], beacon[32], tip[32], online[32], noise[32], seed[32];
    mesh_fill32(genesis, 0x11);
    mesh_fill32(beacon, 0x22);
    mesh_fill32(tip, 0x33);
    mesh_fill32(online, 0x44);
    mesh_fill32(noise, 0x55);
    mesh_fill32(seed, 0x66);
    if (!mesh_seed_block(ndb, 0, genesis) ||
        !mesh_seed_block(ndb, ZCL_FINALITY_DEPTH, beacon) ||
        !mesh_seed_block(ndb, 2 * ZCL_FINALITY_DEPTH, tip) ||
        vcs_zcode_dht_delegation_sign(
            delegation, genesis, online, noise, ZCL_FINALITY_DEPTH, beacon,
            1000, 4000, 7, seed) != VCS_ZCODE_DHT_DELEGATION_OK ||
        !v2_identity_public_fingerprint(noise, fingerprint))
        return false;
    struct zid_identity identity = {0};
    memcpy(identity.master_pubkey, delegation->doc.master_pubkey, 32);
    mesh_fill32(identity.anchor_txid, 0x77);
    identity.anchor_height = 0;
    identity.updated_height = 0;
    snprintf(identity.status, sizeof(identity.status), "%s",
             ZID_IDENTITY_STATUS_ACTIVE);
    snprintf(identity.source, sizeof(identity.source), "%s",
             ZID_IDENTITY_SOURCE_ZID_OVERLAY);
    return db_zid_identity_save(ndb, &identity);
}

static bool mesh_observation_fixture(
    const struct db_mesh_pairing *pairing, int64_t observed_unix,
    const char *capsule, struct db_mesh_machine_observation *out)
{
    if (!pairing || !capsule || !out || observed_unix <= 0)
        return false;
    struct mesh_status_receipt_v1 receipt = {0};
    receipt.version = MESH_STATUS_PROTO_VERSION;
    receipt.flags = MESH_STATUS_PROTO_FLAGS_NONE;
    receipt.status = MESH_STATUS_RECEIPT_OK;
    mesh_fill32(receipt.request_id, 0xa1);
    mesh_fill32(receipt.request_root, 0xa2);
    memcpy(receipt.network_genesis, pairing->network_genesis, 32);
    if (!zcl_hex_decode_lower(pairing->pairing_id, receipt.pairing_id, 32))
        return false;
    memcpy(receipt.responder_master_pubkey, pairing->peer_master_pubkey, 32);
    memcpy(receipt.responder_noise_static, pairing->peer_noise_pubkey, 32);
    uint8_t online_seed[32], secret[32];
    mesh_fill32(online_seed, 0xb1);
    ed25519_keypair(receipt.responder_online_pubkey, secret, online_seed);
    memory_cleanse(secret, sizeof(secret));
    mesh_fill32(receipt.transcript_hash, 0xa3);
    receipt.connection_generation = 1;
    receipt.revocation_generation = 0;
    receipt.observed_unix = (uint64_t)observed_unix;
    receipt.expires_unix = (uint64_t)observed_unix + 30;
    receipt.capsule_len = (uint16_t)strlen(capsule);
    memcpy(receipt.capsule, capsule, receipt.capsule_len);
    if (mesh_status_capsule_v1_root(receipt.capsule, receipt.capsule_len,
                                    receipt.capsule_root) !=
            MESH_STATUS_PROTO_OK ||
        mesh_status_receipt_v1_sign(&receipt, online_seed) !=
            MESH_STATUS_PROTO_OK)
        return false;
    memset(out, 0, sizeof(*out));
    memcpy(out->pairing_id, pairing->pairing_id, sizeof(out->pairing_id));
    if (mesh_status_receipt_v1_encode(
            &receipt, out->receipt_wire, sizeof(out->receipt_wire),
            &out->receipt_len) != MESH_STATUS_PROTO_OK ||
        mesh_status_receipt_v1_root(&receipt, out->receipt_root) !=
            MESH_STATUS_PROTO_OK)
        return false;
    out->status = receipt.status;
    out->observed_unix = observed_unix;
    out->expires_unix = observed_unix + 30;
    out->received_unix = observed_unix + 1;
    return true;
}

int test_mesh_pairing(void)
{
    int failures = 0;
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "authority");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb = {0};
    struct vcs_zcode_dht_delegation delegation;
    uint8_t fingerprint[32];

    TEST("mesh pairing: explicit Noise-bound acceptance is durable") {
        ASSERT(mesh_fixture(&ndb, path, &delegation, fingerprint));
        struct db_mesh_pairing row;
        uint8_t wrong[32];
        mesh_fill32(wrong, 0x99);
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, &delegation, wrong,
                      delegation.noise_static_pubkey, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &row),
                  MESH_PAIRING_FINGERPRINT_MISMATCH);
        ASSERT_EQ(db_mesh_pairing_list(&ndb, &row, 1), 0);
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, &delegation, fingerprint, wrong, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &row),
                  MESH_PAIRING_SESSION_MISMATCH);
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, &delegation, fingerprint,
                      delegation.noise_static_pubkey, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &row),
                  MESH_PAIRING_OK);
        ASSERT(mesh_pairing_allows(&row, MESH_PAIRING_CAP_STATUS_READ, 2500));
        ASSERT(!mesh_pairing_allows(&row, MESH_PAIRING_CAP_STATUS_READ, 3000));
        struct db_mesh_pairing_counts counts;
        ASSERT(db_mesh_pairing_count_states(&ndb, 2500, &counts));
        ASSERT_EQ(counts.total, 1);
        ASSERT_EQ(counts.active, 1);
        ASSERT_EQ(counts.expired, 0);
        ASSERT_EQ(counts.revoked, 0);
        ASSERT(db_mesh_pairing_count_states(&ndb, 3000, &counts));
        ASSERT_EQ(counts.active, 0);
        ASSERT_EQ(counts.expired, 1);
        ASSERT_EQ(mesh_pairing_service_authorize_status(
                      &ndb, row.pairing_id, &delegation,
                      delegation.noise_static_pubkey, 2500),
                  MESH_PAIRING_OK);
        node_db_close(&ndb);
        ASSERT(node_db_open(&ndb, path));
        struct db_mesh_pairing persisted;
        ASSERT(db_mesh_pairing_find(&ndb, row.pairing_id, &persisted));
        ASSERT_EQ(persisted.delegation_sequence, 7);
        PASS();
    }

    TEST("mesh machine observation: exact latest receipt survives reopen") {
        struct db_mesh_pairing pairing;
        ASSERT_EQ(db_mesh_pairing_list(&ndb, &pairing, 1), 1);
        struct db_mesh_machine_observation latest;
        ASSERT(mesh_observation_fixture(&pairing, 2400, "{}", &latest));
        ASSERT(db_mesh_machine_observation_save(&ndb, &latest));
        /* An exact replay is idempotent. */
        latest.received_unix++;
        ASSERT(db_mesh_machine_observation_save(&ndb, &latest));

        struct db_mesh_machine_view view;
        ASSERT_EQ(db_mesh_machine_observation_list(&ndb, &view, 1, 2500), 1);
        ASSERT(view.has_observation);
        ASSERT_STR_EQ(view.pairing.pairing_id, pairing.pairing_id);
        ASSERT_STR_EQ(view.observation.pairing_id, pairing.pairing_id);
        ASSERT_EQ(view.observation.status, MESH_STATUS_RECEIPT_OK);
        ASSERT_EQ(view.observation.observed_unix, 2400);
        ASSERT_EQ(view.observation.expires_unix, 2430);
        ASSERT_EQ(view.observation.received_unix, 2402);
        ASSERT_EQ(view.observation.receipt_len, latest.receipt_len);
        ASSERT(memcmp(view.observation.receipt_wire, latest.receipt_wire,
                      latest.receipt_len) == 0);
        ASSERT(memcmp(view.observation.receipt_root, latest.receipt_root,
                      32) == 0);

        struct json_value machines;
        json_init(&machines);
        boot_mesh_status_machines_test_render(&ndb, 2401, &machines);
        ASSERT_STR_EQ(json_get_str(json_get(&machines, "schema")),
                      "zcl.mesh.machines.v1");
        ASSERT_EQ(json_get_int(json_get(&machines, "total")), 1);
        ASSERT_EQ(json_get_int(json_get(&machines, "returned_fresh")), 1);
        const struct json_value *items = json_get(&machines, "machines");
        const struct json_value *item = json_at(items, 0);
        ASSERT_STR_EQ(json_get_str(json_get(item, "observation_state")),
                      "fresh");
        ASSERT(json_get(item, "peer_master_pubkey") == NULL);
        ASSERT(json_get(item, "peer_noise_pubkey") == NULL);
        json_free(&machines);

        /* Stale evidence remains visible and does not become "never seen". */
        ASSERT_EQ(db_mesh_machine_observation_list(&ndb, &view, 1, 5000), 1);
        ASSERT(view.has_observation);
        ASSERT_EQ(view.observation.expires_unix, 2430);
        node_db_close(&ndb);
        ASSERT(node_db_open(&ndb, path));
        ASSERT_EQ(db_mesh_machine_observation_list(&ndb, &view, 1, 5000), 1);
        ASSERT(view.has_observation);
        ASSERT_EQ(view.observation.observed_unix, 2400);
        json_init(&machines);
        boot_mesh_status_machines_test_render(&ndb, 5000, &machines);
        ASSERT_EQ(json_get_int(json_get(&machines, "returned_stale")), 1);
        items = json_get(&machines, "machines");
        item = json_at(items, 0);
        ASSERT_STR_EQ(json_get_str(json_get(item, "observation_state")),
                      "stale");
        json_free(&machines);
        PASS();
    }

    TEST("mesh machine observation: older and same-time equivocation refuse") {
        struct db_mesh_pairing pairing;
        ASSERT_EQ(db_mesh_pairing_list(&ndb, &pairing, 1), 1);
        struct db_mesh_machine_observation older;
        ASSERT(mesh_observation_fixture(&pairing, 2300, "{}", &older));
        ASSERT(!db_mesh_machine_observation_save(&ndb, &older));
        struct db_mesh_machine_observation equivocation;
        ASSERT(mesh_observation_fixture(&pairing, 2400, "{\"changed\":true}",
                                        &equivocation));
        ASSERT(!db_mesh_machine_observation_save(&ndb, &equivocation));

        struct db_mesh_machine_observation tampered = equivocation;
        tampered.receipt_root[0] ^= 1;
        ASSERT(!db_mesh_machine_observation_save(&ndb, &tampered));
        struct db_mesh_machine_view view;
        ASSERT_EQ(db_mesh_machine_observation_list(&ndb, &view, 1, 5000), 1);
        ASSERT(view.has_observation);
        ASSERT_EQ(view.observation.observed_unix, 2400);
        ASSERT(memcmp(view.observation.receipt_root, equivocation.receipt_root,
                      32) != 0);
        PASS();
    }

    TEST("mesh machines: live probe row and durable store agree on identity") {
        /* One verified receipt feeds BOTH halves of the unified fleet view:
         * the durable observation store (through the lane's single handoff)
         * and the live sidecar row the refresh derives. Pin that both derive
         * the same pairing identity and responder Noise fingerprint from the
         * same receipt, and that the rendered document agrees. */
        struct db_mesh_pairing pairing;
        ASSERT_EQ(db_mesh_pairing_list(&ndb, &pairing, 1), 1);
        struct db_mesh_machine_observation stored;
        ASSERT(mesh_observation_fixture(&pairing, 2500, "{}", &stored));
        /* Decode the exact wire, as the status lane delivers it to the
         * persistence handoff. */
        struct mesh_status_receipt_v1 receipt;
        ASSERT_EQ(mesh_status_receipt_v1_decode(&receipt, stored.receipt_wire,
                                                stored.receipt_len),
                  MESH_STATUS_PROTO_OK);
        /* The production handoff the poll path and the fleet refresh share. */
        ASSERT(boot_mesh_status_persist_observation(&ndb, &receipt));

        struct mesh_machine_row live;
        memset(&live, 0, sizeof(live));
        snprintf(live.pairing_id, sizeof(live.pairing_id), "%s",
                 pairing.pairing_id);
        live.probed = true;
        live.state = MESH_MACHINE_ONLINE;
        ASSERT(mesh_machines_fill_live_identity(&live, &receipt));
        ASSERT_STR_EQ(live.pairing_id, pairing.pairing_id);
        ASSERT_EQ(live.observed_unix, 2500);
        uint8_t expect_fingerprint[32];
        ASSERT(v2_identity_public_fingerprint(receipt.responder_noise_static,
                                              expect_fingerprint));
        ASSERT(memcmp(expect_fingerprint, live.responder_noise_fingerprint,
                      32) == 0);

        /* The durable projection carries the same identity: receipt's
         * responder Noise key is the pairing's peer key, and the row ids
         * match the live row byte for byte. */
        struct db_mesh_machine_view view;
        ASSERT_EQ(db_mesh_machine_observation_list(&ndb, &view, 1, 2501), 1);
        ASSERT(view.has_observation);
        ASSERT_STR_EQ(view.pairing.pairing_id, live.pairing_id);
        ASSERT_STR_EQ(view.observation.pairing_id, live.pairing_id);
        ASSERT(memcmp(view.pairing.peer_noise_pubkey,
                      receipt.responder_noise_static, 32) == 0);
        ASSERT_EQ(view.observation.observed_unix, 2500);
        ASSERT_EQ(view.observation.expires_unix, 2530);

        /* The rendered document (durable evidence only, no live sidecar)
         * agrees: same pairing id, same fingerprint from the lane's one
         * shared helper, and no live keys appear. */
        struct json_value doc;
        json_init(&doc);
        boot_mesh_status_machines_test_render(&ndb, 2501, &doc);
        ASSERT_EQ(json_get_int(json_get(&doc, "returned_fresh")), 1);
        const struct json_value *item = json_at(json_get(&doc, "machines"), 0);
        ASSERT_STR_EQ(json_get_str(json_get(item, "pairing_id")),
                      live.pairing_id);
        ASSERT_STR_EQ(json_get_str(json_get(item, "observation_state")),
                      "fresh");
        char expect_hex[65];
        boot_mesh_status_key_fingerprint("zcl.mesh.noise.fingerprint.v1",
                                         receipt.responder_noise_static,
                                         expect_hex);
        ASSERT_STR_EQ(json_get_str(json_get(item, "peer_noise_fingerprint")),
                      expect_hex);
        ASSERT(json_get(item, "live_reachability") == NULL);
        json_free(&doc);
        PASS();
    }

    TEST("mesh pairing: revocation is sticky and cannot resurrect") {
        struct db_mesh_pairing row;
        ASSERT_EQ(db_mesh_pairing_list(&ndb, &row, 1), 1);
        ASSERT_EQ(mesh_pairing_service_revoke(&ndb, row.pairing_id, 2600),
                  MESH_PAIRING_OK);
        ASSERT_EQ(mesh_pairing_service_revoke(&ndb, row.pairing_id, 2700),
                  MESH_PAIRING_OK);
        node_db_close(&ndb);
        ASSERT(node_db_open(&ndb, path));
        ASSERT(db_mesh_pairing_find(&ndb, row.pairing_id, &row));
        ASSERT_EQ(row.revoked_at, 2600);
        ASSERT_EQ(row.revocation_generation, 1);
        struct db_mesh_pairing_counts counts;
        ASSERT(db_mesh_pairing_count_states(&ndb, 2800, &counts));
        ASSERT_EQ(counts.total, 1);
        ASSERT_EQ(counts.active, 0);
        ASSERT_EQ(counts.expired, 0);
        ASSERT_EQ(counts.revoked, 1);
        ASSERT_EQ(mesh_pairing_service_authorize_status(
                      &ndb, row.pairing_id, &delegation,
                      delegation.noise_static_pubkey, 2800),
                  MESH_PAIRING_ALREADY_REVOKED);
        struct db_mesh_pairing refused;
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, &delegation, fingerprint,
                      delegation.noise_static_pubkey, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &refused),
                  MESH_PAIRING_ALREADY_REVOKED);
        PASS();
    }

    TEST("pairing commands: days default, clamp boundaries, and rejection") {
        ASSERT_EQ(BOOT_MESH_PAIRING_DEFAULT_DAYS, 7);
        ASSERT_EQ(BOOT_MESH_PAIRING_MAX_DAYS, 30);
        ASSERT(boot_mesh_pairing_days_valid(1));
        ASSERT(boot_mesh_pairing_days_valid(30));
        ASSERT(!boot_mesh_pairing_days_valid(0));
        ASSERT(!boot_mesh_pairing_days_valid(-1));
        ASSERT(!boot_mesh_pairing_days_valid(31));
        ASSERT_EQ(boot_mesh_pairing_expiry(10000, 7), 10000 + 7 * 86400);
        ASSERT_EQ(boot_mesh_pairing_expiry(10000, 30), 10000 + 30 * 86400);
        /* The 30-day ceiling lands exactly on the service's own window. */
        ASSERT_EQ(BOOT_MESH_PAIRING_MAX_DAYS * 86400,
                  MESH_PAIRING_MAX_LIFETIME_SECONDS);
        PASS();
    }

    TEST("pairing commands: selector matches addr substring or fingerprint prefix") {
        char fingerprint_hex[65];
        uint8_t fp[32];
        mesh_fill32(fp, 0xab);
        zcl_hex_encode(fp, 32, fingerprint_hex);
        ASSERT(boot_mesh_pairing_selector_matches(
            "168.1", "192.168.1.7:8033", fingerprint_hex));
        ASSERT(boot_mesh_pairing_selector_matches(
            fingerprint_hex, "192.168.1.7:8033", fingerprint_hex));
        fingerprint_hex[20] = '\0'; /* prefix match on the fingerprint hex */
        ASSERT(boot_mesh_pairing_selector_matches(
            fingerprint_hex, "192.168.1.7:8033",
            "ababababababababababababababababababababababababababababababababb"));
        ASSERT(!boot_mesh_pairing_selector_matches(
            "ffff", "192.168.1.7:8033",
            "abababababababababababababababababababababababababababababababab"));
        ASSERT(boot_mesh_pairing_selector_matches(
            NULL, "192.168.1.7:8033",
            "abababababababababababababababababababababababababababababababab"));
        ASSERT(boot_mesh_pairing_selector_matches(
            "", "192.168.1.7:8033",
            "abababababababababababababababababababababababababababababababab"));
        PASS();
    }

    TEST("pairing commands: record state derives from now, revocation wins") {
        struct db_mesh_pairing row = {0};
        row.paired_at = 1000;
        row.expires_at = 3000;
        ASSERT_STR_EQ(boot_mesh_pairing_state(&row, 2500), "active");
        ASSERT_STR_EQ(boot_mesh_pairing_state(&row, 3000), "expired");
        row.revoked_at = 2600;
        ASSERT_STR_EQ(boot_mesh_pairing_state(&row, 2500), "revoked");
        ASSERT_STR_EQ(boot_mesh_pairing_state(&row, 3500), "revoked");
        PASS();
    }

    TEST("pairing commands: fingerprint decode is canonical lowercase hex") {
        uint8_t out[32];
        ASSERT(boot_mesh_pairing_decode_fingerprint(
            "abababababababababababababababababababababababababababababababab",
            out));
        ASSERT_EQ(out[0], 0xab);
        ASSERT_EQ(out[31], 0xab);
        ASSERT(!boot_mesh_pairing_decode_fingerprint("ab", out));
        ASSERT(!boot_mesh_pairing_decode_fingerprint(
            "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
            out));
        ASSERT(!boot_mesh_pairing_decode_fingerprint(NULL, out));
        PASS();
    }

    TEST("pairing commands: every service reason maps to a distinct named code") {
        const enum mesh_pairing_reason reasons[] = {
            MESH_PAIRING_OK, MESH_PAIRING_BAD_ARGUMENT,
            MESH_PAIRING_CAPABILITY_UNAVAILABLE,
            MESH_PAIRING_FINGERPRINT_MISMATCH, MESH_PAIRING_NETWORK_MISMATCH,
            MESH_PAIRING_MASTER_INACTIVE, MESH_PAIRING_BEACON_UNAVAILABLE,
            MESH_PAIRING_BEACON_PROVISIONAL, MESH_PAIRING_DELEGATION_INVALID,
            MESH_PAIRING_WINDOW_INVALID, MESH_PAIRING_ALREADY_REVOKED,
            MESH_PAIRING_IDENTITY_COLLISION, MESH_PAIRING_PERSIST_FAILED,
            MESH_PAIRING_NOT_FOUND, MESH_PAIRING_EXPIRED,
            MESH_PAIRING_SESSION_MISMATCH, MESH_PAIRING_AUTHORITY_CHANGED,
            MESH_PAIRING_CONFIRMATION_INVALID, MESH_PAIRING_PLAN_EXPIRED,
        };
        for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++) {
            const char *code = boot_mesh_pairing_reason_code(reasons[i]);
            ASSERT(code && code[0]);
            for (size_t j = i + 1;
                 j < sizeof(reasons) / sizeof(reasons[0]); j++)
                ASSERT(strcmp(code,
                              boot_mesh_pairing_reason_code(reasons[j])) != 0);
        }
        ASSERT_STR_EQ(
            boot_mesh_pairing_reason_code(MESH_PAIRING_FINGERPRINT_MISMATCH),
            "FINGERPRINT_MISMATCH");
        ASSERT_STR_EQ(boot_mesh_pairing_reason_code(MESH_PAIRING_NOT_FOUND),
                      "NOT_FOUND");
        ASSERT_STR_EQ(
            boot_mesh_pairing_reason_code(MESH_PAIRING_CONFIRMATION_INVALID),
            "CONFIRMATION_INVALID");
        ASSERT_STR_EQ(boot_mesh_pairing_reason_code(MESH_PAIRING_PLAN_EXPIRED),
                      "PLAN_EXPIRED");
        PASS();
    }

_test_next:
    if (ndb.open)
        node_db_close(&ndb);
    test_rm_rf_recursive(dir);
    return failures;
}
