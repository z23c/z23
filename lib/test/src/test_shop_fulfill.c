/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Slice-E shop fulfillment claims: signed wire, CAS evidence, replay,
 * plan/commit, expiry, listing, status, and key-checked withdrawal. */

#include "test/test_core.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "controllers/shop_native_handler.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/build_fabric.h"
#include "models/shop_fulfill.h"
#include "services/build_fabric_service.h"
#include "services/shop_fulfill_evidence_service.h"
#include "sha3/sha3.h"
#include "vcs/blob_store.h"
#include "vcs/build_action.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <string.h>

#define SF_NOW 1780000000LL
#define SF_CHECK(name, expr) do {                                      \
    printf("shop_fulfill: %s... ", (name));                           \
    if (expr) printf("OK\n");                                        \
    else { printf("FAIL\n"); failures++; }                           \
} while (0)

typedef void (*sf_handler_fn)(const struct zcl_command_request *,
                              struct zcl_command_reply *);

static void sf_hex_seed(uint8_t byte, char out[65])
{
    uint8_t seed[32];
    memset(seed, byte, sizeof(seed));
    zcl_hex_encode(seed, sizeof(seed), out);
}

static const char *sf_str(const struct json_value *obj, const char *key)
{
    const char *value = json_get_str(json_get(obj, key));
    return value ? value : "";
}

static void sf_call(sf_handler_fn fn, struct json_value *input,
                    struct zcl_command_reply *reply)
{
    struct zcl_command_request request = {.input = input};
    zcl_command_reply_init(reply, "zcl.test.shop_fulfill.v1");
    fn(&request, reply);
}

static bool sf_boot_db(const char *dir)
{
    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/node.db", dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open_runtime(&ndb, path, "test.shop.fulfill"))
        return false;
    node_db_close(&ndb);
    return true;
}

static bool sf_post_want(const char *dir, char want_id[65])
{
    char buyer_secret[65];
    sf_hex_seed(0x31, buyer_secret);
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "buyer_secret", buyer_secret);
    (void)json_push_kv_int(&input, "amount_zatoshi", 750000);
    (void)json_push_kv_str(&input, "criteria",
        "a deterministic fixture artifact whose bytes match its SHA3");
    (void)json_push_kv_int(&input, "now_unix", SF_NOW);
    (void)json_push_kv_int(&input, "expires_unix", SF_NOW + 86400);
    (void)json_push_kv_bool(&input, "confirm", true);
    struct zcl_command_reply reply;
    sf_call(zcl_native_handle_shop_want_post, &input, &reply);
    bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED &&
              strlen(sf_str(&reply.data, "want_id")) == 64;
    if (ok) (void)snprintf(want_id, 65, "%s",
                           sf_str(&reply.data, "want_id"));
    zcl_command_reply_free(&reply);
    json_free(&input);
    return ok;
}

static bool sf_put_artifact(const char *dir, const uint8_t *bytes, size_t len,
                            char artifact_hex[65], char content_hex[65])
{
    struct vcs_package_store *store =
        vcs_package_store_open(dir, 4u * 1024u * 1024u);
    if (!store) return false;
    uint8_t content_root[32], artifact_root[32];
    bool ok = vcs_blob_put_to(store, bytes, len, content_root) == VCS_BLOB_OK;
    vcs_package_store_close(store);
    if (!ok) return false;
    sha3_256(bytes, len, artifact_root);
    zcl_hex_encode(artifact_root, 32, artifact_hex);
    zcl_hex_encode(content_root, 32, content_hex);
    return true;
}

static void sf_id(uint8_t byte, char out[65])
{
    uint8_t value[32];
    memset(value, byte, sizeof(value));
    zcl_hex_encode(value, sizeof(value), out);
}

static bool sf_receipt_fixture(struct node_db *ndb, uint8_t tag,
                               const char *kind, int exit_status,
                               bool revoked, bool expired,
                               const char *trust_state,
                               uint8_t receipt_id[32])
{
    char job_id[65], action_id[65], worker_id[65], lease_id[65];
    char source_a[65], source_b[65], source_c[65], output[65];
    sf_id(tag, job_id); sf_id((uint8_t)(tag + 1), action_id);
    sf_id((uint8_t)(tag + 2), worker_id);
    sf_id((uint8_t)(tag + 3), lease_id);
    sf_id((uint8_t)(tag + 4), source_a);
    sf_id((uint8_t)(tag + 5), source_b);
    sf_id((uint8_t)(tag + 6), source_c);
    sf_id((uint8_t)(tag + 7), output);

    struct db_build_job job;
    memset(&job, 0, sizeof(job));
    (void)snprintf(job.job_id, sizeof(job.job_id), "%s", job_id);
    (void)snprintf(job.source_sha256, sizeof(job.source_sha256), "%s",
                   source_a);
    (void)snprintf(job.source_cas_sha3, sizeof(job.source_cas_sha3), "%s",
                   source_b);
    (void)snprintf(job.toolchain_sha3, sizeof(job.toolchain_sha3), "%s",
                   source_c);
    (void)snprintf(job.profile, sizeof(job.profile), "test-profile");
    (void)snprintf(job.state, sizeof(job.state), "ACCEPTED");
    (void)snprintf(job.outcome, sizeof(job.outcome),
                   exit_status == 0 ? "ACCEPTED" : "FAILED");
    job.created_at = job.updated_at = SF_NOW - 10;

    uint8_t seed[32], pubkey[32], secret[32];
    memset(seed, tag, sizeof(seed));
    ed25519_keypair(pubkey, secret, seed);
    struct db_build_worker worker;
    memset(&worker, 0, sizeof(worker));
    (void)snprintf(worker.worker_id, sizeof(worker.worker_id), "%s",
                   worker_id);
    zcl_hex_encode(pubkey, sizeof(pubkey), worker.signer_pubkey);
    (void)snprintf(worker.capabilities, sizeof(worker.capabilities), "%s",
                   kind);
    worker.approved = 1;
    worker.revoked = revoked ? 1 : 0;
    worker.expires_at = expired ? SF_NOW : 0;
    worker.approved_at = SF_NOW - 20;
    worker.last_seen_at = SF_NOW - 5;

    struct db_build_action action;
    memset(&action, 0, sizeof(action));
    (void)snprintf(action.action_id, sizeof(action.action_id), "%s",
                   action_id);
    (void)snprintf(action.job_id, sizeof(action.job_id), "%s", job_id);
    (void)snprintf(action.kind, sizeof(action.kind), "%s", kind);
    (void)snprintf(action.state, sizeof(action.state), "ACCEPTED");
    (void)snprintf(action.outcome, sizeof(action.outcome),
                   exit_status == 0 ? "ACCEPTED" : "FAILED");
    (void)snprintf(action.input_root_sha3,
                   sizeof(action.input_root_sha3), "%s", source_a);
    const char *workdir = NULL, *outputs = NULL, *resource = NULL;
    uint8_t flags_root[32], environment_root[32];
    if (!vcs_build_action_v1_descriptors(kind, &workdir, &outputs,
                                         &resource) ||
        !vcs_build_action_v1_fixed_flags_root_for_kind(kind, flags_root) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            kind, environment_root)) {
        memory_cleanse(secret, sizeof(secret));
        return false;
    }
    (void)snprintf(action.target, sizeof(action.target), "%s",
                   VCS_BUILD_TARGET_V1);
    zcl_hex_encode(flags_root, 32, action.flags_sha3);
    zcl_hex_encode(environment_root, 32, action.environment_sha3);
    (void)snprintf(action.virtual_workdir,
                   sizeof(action.virtual_workdir), "%s", workdir);
    (void)snprintf(action.declared_outputs,
                   sizeof(action.declared_outputs), "%s", outputs);
    (void)snprintf(action.resource_policy,
                   sizeof(action.resource_policy), "%s", resource);
    (void)snprintf(action.output_root_sha3,
                   sizeof(action.output_root_sha3), "%s", output);
    (void)snprintf(action.worker_id, sizeof(action.worker_id), "%s",
                   worker_id);
    (void)snprintf(action.lease_id, sizeof(action.lease_id), "%s", lease_id);
    action.created_at = action.updated_at = action.finished_at = SF_NOW - 5;
    if (!build_fabric_action_id(&job, &action, action_id).ok ||
        !build_fabric_job_id(&job, action_id, job_id).ok) {
        memory_cleanse(secret, sizeof(secret));
        return false;
    }
    (void)snprintf(action.action_id, sizeof(action.action_id), "%s",
                   action_id);
    (void)snprintf(action.job_id, sizeof(action.job_id), "%s", job_id);
    (void)snprintf(job.job_id, sizeof(job.job_id), "%s", job_id);

    struct db_build_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    (void)snprintf(receipt.action_id, sizeof(receipt.action_id), "%s",
                   action_id);
    (void)snprintf(receipt.job_id, sizeof(receipt.job_id), "%s", job_id);
    (void)snprintf(receipt.worker_id, sizeof(receipt.worker_id), "%s",
                   worker_id);
    (void)snprintf(receipt.lease_id, sizeof(receipt.lease_id), "%s", lease_id);
    (void)snprintf(receipt.action_sha3, sizeof(receipt.action_sha3), "%s",
                   action_id);
    (void)snprintf(receipt.output_sha3, sizeof(receipt.output_sha3), "%s",
                   output);
    (void)snprintf(receipt.confinement, sizeof(receipt.confinement),
                   "test=deterministic,network=0");
    (void)snprintf(receipt.trust_state, sizeof(receipt.trust_state), "%s",
                   trust_state);
    receipt.exit_status = exit_status;
    receipt.created_at = SF_NOW - 4;
    if (!build_fabric_receipt_id(&receipt, receipt.receipt_id).ok ||
        !zcl_hex_decode_lower(receipt.receipt_id, receipt_id, 32)) {
        memory_cleanse(secret, sizeof(secret));
        return false;
    }
    uint8_t signature[64];
    ed25519_sign(signature, receipt_id, 32, secret, pubkey);
    memory_cleanse(secret, sizeof(secret));
    zcl_hex_encode(signature, sizeof(signature), receipt.signature);
    return db_build_job_save(ndb, &job) &&
        db_build_worker_save(ndb, &worker) &&
        db_build_action_save(ndb, &action) &&
        db_build_receipt_save(ndb, &receipt);
}

static int sf_receipt_authorities(void)
{
    int failures = 0;
    char dir[512], path[1024];
    test_make_tmpdir(dir, sizeof(dir), "shopfulfill", "receipts");
    (void)snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    SF_CHECK("receipt fixture database opens",
             node_db_open_runtime(&ndb, path, "test.shop.receipts"));
    if (!ndb.open) {
        test_rm_rf(dir);
        return failures;
    }
    uint8_t build_id[32], fuzz_id[32], failed_id[32], revoked_id[32];
    uint8_t expired_id[32];
    uint8_t remote_id[32], fake_bench_id[32];
    SF_CHECK("valid local build receipt fixture persists",
        sf_receipt_fixture(&ndb, 0x81, VCS_BUILD_ACTION_KIND_V1, 0, false,
                           false,
                           "LOCAL_ACCEPTED", build_id));
    SF_CHECK("valid local fuzz receipt fixture persists",
        sf_receipt_fixture(&ndb, 0x91, VCS_BUILD_ACTION_KIND_FUZZ_V1, 0,
                           false, false, "LOCAL_ACCEPTED", fuzz_id));
    SF_CHECK("failed receipt fixture persists",
        sf_receipt_fixture(&ndb, 0xa1, VCS_BUILD_ACTION_KIND_V1, 9, false,
                           false,
                           "LOCAL_ACCEPTED", failed_id));
    SF_CHECK("revoked signer fixture persists",
        sf_receipt_fixture(&ndb, 0xb1, VCS_BUILD_ACTION_KIND_V1, 0, true,
                           false,
                           "LOCAL_ACCEPTED", revoked_id));
    SF_CHECK("expired signer fixture persists",
        sf_receipt_fixture(&ndb, 0xb9, VCS_BUILD_ACTION_KIND_V1, 0, false,
                           true, "LOCAL_ACCEPTED", expired_id));
    SF_CHECK("remote outer receipt fixture persists",
        sf_receipt_fixture(&ndb, 0xc1, VCS_BUILD_ACTION_KIND_V1, 0, false,
                           false,
                           "LOCAL_REPRODUCED", remote_id));
    SF_CHECK("benchmark-labelled build receipt fixture persists",
        sf_receipt_fixture(&ndb, 0xd1,
                           VCS_BUILD_ACTION_KIND_BENCHMARK_V1, 0, false, false,
                           "LOCAL_ACCEPTED", fake_bench_id));

    struct shop_fulfill_receipt_fact fact;
    SF_CHECK("local build authority verifies positive evidence",
        shop_fulfill_receipt_verify(&ndb, dir, build_id,
            SHOP_FULFILL_RECEIPT_BUILD, SF_NOW, &fact).ok && fact.passed);
    SF_CHECK("local fuzz authority verifies positive evidence",
        shop_fulfill_receipt_verify(&ndb, dir, fuzz_id,
            SHOP_FULFILL_RECEIPT_FUZZ, SF_NOW, &fact).ok && fact.passed);
    SF_CHECK("cross-kind receipt is refused",
        !shop_fulfill_receipt_verify(&ndb, dir, build_id,
            SHOP_FULFILL_RECEIPT_FUZZ, SF_NOW, &fact).ok &&
        strcmp(fact.reason, "receipt-kind-mismatch") == 0);
    char build_hex[65], relabel_sql[256];
    zcl_hex_encode(build_id, 32, build_hex);
    (void)snprintf(relabel_sql, sizeof(relabel_sql),
        "UPDATE build_actions SET kind='%s' WHERE action_id="
        "(SELECT action_id FROM build_receipts WHERE receipt_id='%s')",
        VCS_BUILD_ACTION_KIND_FUZZ_V1, build_hex);
    SF_CHECK("fixture can simulate mutable action-kind corruption",
             sqlite3_exec(ndb.db, relabel_sql, NULL, NULL, NULL) == SQLITE_OK);
    SF_CHECK("relabelled action cannot reuse a signed receipt cross-kind",
        !shop_fulfill_receipt_verify(&ndb, dir, build_id,
            SHOP_FULFILL_RECEIPT_FUZZ, SF_NOW, &fact).ok &&
        strcmp(fact.reason, "receipt-action-id-invalid") == 0);
    SF_CHECK("failed receipt is refused",
        !shop_fulfill_receipt_verify(&ndb, dir, failed_id,
            SHOP_FULFILL_RECEIPT_BUILD, SF_NOW, &fact).ok &&
        strcmp(fact.reason, "receipt-reports-failure") == 0);
    SF_CHECK("revoked signer is refused",
        !shop_fulfill_receipt_verify(&ndb, dir, revoked_id,
            SHOP_FULFILL_RECEIPT_BUILD, SF_NOW, &fact).ok &&
        strcmp(fact.reason, "receipt-signer-not-currently-approved") == 0);
    SF_CHECK("expired signer is refused",
        !shop_fulfill_receipt_verify(&ndb, dir, expired_id,
            SHOP_FULFILL_RECEIPT_BUILD, SF_NOW, &fact).ok &&
        strcmp(fact.reason, "receipt-signer-not-currently-approved") == 0);
    SF_CHECK("remote typed receipt is not decoded as a local outer receipt",
        !shop_fulfill_receipt_verify(&ndb, dir, remote_id,
            SHOP_FULFILL_RECEIPT_BUILD, SF_NOW, &fact).ok &&
        strcmp(fact.reason, "receipt-not-local-outer-authority") == 0);
    SF_CHECK("benchmark ignores the build ledger and requires science",
        !shop_fulfill_receipt_verify(&ndb, dir, fake_bench_id,
            SHOP_FULFILL_RECEIPT_BENCH, SF_NOW, &fact).ok &&
        strcmp(fact.reason, "science-receipt-not-found") == 0);
    node_db_close(&ndb);
    test_rm_rf(dir);
    return failures;
}

static void sf_post_input_at(struct json_value *input, const char *dir,
                             const char *want_id, uint8_t seller_seed,
                             const char *artifact_root,
                             const char *content_root, int64_t nonce,
                             int64_t now, bool confirm)
{
    char secret[65];
    sf_hex_seed(seller_seed, secret);
    json_init(input);
    json_set_object(input);
    (void)json_push_kv_str(input, "datadir", dir);
    (void)json_push_kv_str(input, "want_id", want_id);
    (void)json_push_kv_str(input, "seller_secret", secret);
    (void)json_push_kv_str(input, "artifact_root", artifact_root);
    (void)json_push_kv_str(input, "content_root", content_root);
    (void)json_push_kv_int(input, "nonce", nonce);
    (void)json_push_kv_int(input, "issued_unix", SF_NOW);
    (void)json_push_kv_int(input, "expires_unix", SF_NOW + 3600);
    (void)json_push_kv_int(input, "now_unix", now);
    if (confirm) (void)json_push_kv_bool(input, "confirm", true);
}

static void sf_post_input(struct json_value *input, const char *dir,
                          const char *want_id, uint8_t seller_seed,
                          const char *artifact_root, const char *content_root,
                          int64_t nonce, bool confirm)
{
    sf_post_input_at(input, dir, want_id, seller_seed, artifact_root,
                     content_root, nonce, SF_NOW, confirm);
}

static int sf_codec(void)
{
    int failures = 0;
    struct shop_fulfill_v1 claim;
    memset(&claim, 0, sizeof(claim));
    claim.schema_version = SHOP_FULFILL_VERSION;
    memset(claim.want_id, 0x11, 32);
    memset(claim.artifact_root, 0x22, 32);
    memset(claim.content_root, 0x33, 32);
    claim.nonce = 7;
    claim.issued_unix = SF_NOW;
    claim.expires_unix = SF_NOW + 3600;
    uint8_t seed[32], secret[32];
    memset(seed, 0x44, sizeof(seed));
    ed25519_keypair(claim.seller_pubkey, secret, seed);
    memory_cleanse(secret, sizeof(secret));
    SF_CHECK("unsealed claim is invalid",
             shop_fulfill_validate(&claim) == SHOP_FULFILL_ERR_SIGNATURE);
    SF_CHECK("seal and verify",
             shop_fulfill_seal(&claim, seed) == SHOP_FULFILL_OK &&
             shop_fulfill_verify(&claim) == SHOP_FULFILL_OK);
    uint8_t golden_root[32]; char golden_hex[65] = "";
    if (shop_fulfill_root(&claim, golden_root) == SHOP_FULFILL_OK)
        zcl_hex_encode(golden_root, 32, golden_hex);
    SF_CHECK("canonical signed wire has frozen root vector",
        strcmp(golden_hex,
            "8c0c4ab6d4d3853780b752a2adebffe6db788e3d6c22f0275758762489a27dc3")
            == 0);
    uint8_t wire[SHOP_FULFILL_WIRE_BYTES];
    struct shop_fulfill_v1 decoded;
    SF_CHECK("fixed wire round-trips",
             shop_fulfill_encode(&claim, wire) == SHOP_FULFILL_OK &&
             shop_fulfill_decode(wire, sizeof(wire), &decoded) ==
                 SHOP_FULFILL_OK &&
             memcmp(&claim, &decoded, sizeof(claim)) == 0);
    SF_CHECK("wrong wire length is refused",
             shop_fulfill_decode(wire, sizeof(wire) - 1, &decoded) ==
                 SHOP_FULFILL_ERR_WIRE_SIZE);
    claim.want_id[0] ^= 1u;
    SF_CHECK("tampered want binding fails signature",
             shop_fulfill_verify(&claim) == SHOP_FULFILL_ERR_SIGNATURE);
    return failures;
}

static int sf_registry_whitelist(void)
{
    int failures = 0;
    static const char *const paths[] = {
        "app.shop.want.fulfill.post", "app.shop.want.fulfill.list",
        "app.shop.want.fulfill.status", "app.shop.want.fulfill.withdraw",
        "app.shop.want.fulfill.review"};
    const struct zcl_command_registry *registry = zcl_command_catalog();
    const struct zcl_command_spec *specs[5];
    for (size_t i = 0; i < 5; i++)
        specs[i] = zcl_command_registry_find(registry, paths[i], NULL);
    SF_CHECK("all five commands are in the live catalog",
             specs[0] && specs[1] && specs[2] && specs[3] && specs[4]);

    char id[65], secret[65], why[192];
    sf_hex_seed(0x55, id);
    sf_hex_seed(0x66, secret);
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "want_id", id);
    (void)json_push_kv_str(&input, "seller_secret", secret);
    (void)json_push_kv_str(&input, "artifact_root", id);
    (void)json_push_kv_str(&input, "content_root", id);
    (void)json_push_kv_str(&input, "build_receipt_id", id);
    (void)json_push_kv_str(&input, "fuzz_receipt_id", id);
    (void)json_push_kv_str(&input, "bench_receipt_id", id);
    (void)json_push_kv_int(&input, "expires_unix", SF_NOW + 3600);
    (void)json_push_kv_int(&input, "nonce", 9);
    (void)json_push_kv_int(&input, "issued_unix", SF_NOW);
    (void)json_push_kv_int(&input, "now_unix", SF_NOW);
    (void)json_push_kv_str(&input, "datadir", "/tmp/shop-fulfill-cli");
    (void)json_push_kv_bool(&input, "confirm", true);
    SF_CHECK("post accepts every documented input key",
             specs[0] && zcl_command_registry_input_validate(
                 specs[0], &input, why, sizeof(why)));
    json_free(&input);

    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "want_id", id);
    (void)json_push_kv_str(&input, "datadir", "/tmp/shop-fulfill-cli");
    (void)json_push_kv_int(&input, "now_unix", SF_NOW);
    (void)json_push_kv_bool(&input, "all", true);
    (void)json_push_kv_str(&input, "profile", "open-view");
    SF_CHECK("list accepts every documented input key",
             specs[1] && zcl_command_registry_input_validate(
                 specs[1], &input, why, sizeof(why)));
    json_free(&input);

    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "fulfill_id", id);
    (void)json_push_kv_str(&input, "datadir", "/tmp/shop-fulfill-cli");
    (void)json_push_kv_int(&input, "now_unix", SF_NOW);
    (void)json_push_kv_str(&input, "profile", "general");
    SF_CHECK("status accepts every documented input key",
             specs[2] && zcl_command_registry_input_validate(
                 specs[2], &input, why, sizeof(why)));
    json_free(&input);

    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "fulfill_id", id);
    (void)json_push_kv_str(&input, "datadir", "/tmp/shop-fulfill-cli");
    (void)json_push_kv_int(&input, "now_unix", SF_NOW);
    (void)json_push_kv_str(&input, "seller_secret", secret);
    (void)json_push_kv_bool(&input, "confirm", true);
    SF_CHECK("withdraw accepts every documented input key",
             specs[3] && zcl_command_registry_input_validate(
                 specs[3], &input, why, sizeof(why)));
    json_free(&input);

    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "fulfill_id", id);
    (void)json_push_kv_str(&input, "review_state", "reviewed_ok");
    (void)json_push_kv_str(&input, "datadir", "/tmp/shop-fulfill-cli");
    (void)json_push_kv_bool(&input, "confirm", true);
    SF_CHECK("review accepts every documented input key",
             specs[4] && zcl_command_registry_input_validate(
                 specs[4], &input, why, sizeof(why)));
    json_free(&input);
    return failures;
}

static int sf_flow(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shopfulfill", "flow");
    SF_CHECK("fixture node.db migrated through v67", sf_boot_db(dir));
    char want_id[65];
    SF_CHECK("fixture want posted", sf_post_want(dir, want_id));
    static const uint8_t bytes_a[] = "slice-E deterministic artifact A";
    static const uint8_t bytes_b[] = "slice-E deterministic artifact B";
    char artifact_a[65], content_a[65], artifact_b[65], content_b[65];
    SF_CHECK("first artifact registered in content.v2 CAS",
             sf_put_artifact(dir, bytes_a, sizeof(bytes_a) - 1,
                             artifact_a, content_a));
    SF_CHECK("second artifact registered in content.v2 CAS",
             sf_put_artifact(dir, bytes_b, sizeof(bytes_b) - 1,
                             artifact_b, content_b));

    struct json_value input;
    struct zcl_command_reply reply;
    sf_post_input(&input, dir, want_id, 0x71, artifact_a, content_a, 77,
                  false);
    sf_call(zcl_native_handle_shop_want_fulfill_post, &input, &reply);
    SF_CHECK("post plan passes without mutation",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(sf_str(&reply.data, "mode"), "plan") == 0 &&
             !reply.error.mutated);
    const struct json_value *planned = json_get(&reply.data, "fulfillment");
    SF_CHECK("plan renders independently verified artifact facts",
             planned && json_get_bool(json_get(planned,
                                               "artifact_verified")));
    char planned_id[65];
    (void)snprintf(planned_id, sizeof(planned_id), "%s",
                   planned ? sf_str(planned, "fulfill_id") : "");
    zcl_command_reply_free(&reply);
    json_free(&input);

    sf_post_input(&input, dir, want_id, 0x71, artifact_a, content_a, 77,
                  true);
    sf_call(zcl_native_handle_shop_want_fulfill_post, &input, &reply);
    SF_CHECK("commit persists the signed claim",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             reply.error.mutated &&
             strlen(sf_str(&reply.data, "fulfill_id")) == 64);
    char fulfill_id[65];
    (void)snprintf(fulfill_id, sizeof(fulfill_id), "%s",
                   sf_str(&reply.data, "fulfill_id"));
    SF_CHECK("plan and commit preserve the exact signed identity",
             strcmp(planned_id, fulfill_id) == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    sf_post_input_at(&input, dir, want_id, 0x71, artifact_a, content_a, 77,
                     SF_NOW + 600, true);
    sf_call(zcl_native_handle_shop_want_fulfill_post, &input, &reply);
    SF_CHECK("stale byte-identical repost remains idempotent",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&reply.data, "already_posted")) &&
             !reply.error.mutated &&
             strcmp(sf_str(&reply.data, "fulfill_id"), fulfill_id) == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* Same seller+nonce, different signed evidence is a replay. */
    sf_post_input(&input, dir, want_id, 0x71, artifact_b, content_b, 77,
                  true);
    sf_call(zcl_native_handle_shop_want_fulfill_post, &input, &reply);
    SF_CHECK("seller nonce replay is refused by name",
             reply.status == ZCL_COMMAND_STATUS_BLOCKED &&
             strcmp(reply.error.code, "FULFILL_NONCE_REPLAY") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* A different signed want binding must resolve to a real open want. */
    char wrong_want[65];
    sf_hex_seed(0x99, wrong_want);
    sf_post_input(&input, dir, wrong_want, 0x72, artifact_a, content_a, 78,
                  true);
    sf_call(zcl_native_handle_shop_want_fulfill_post, &input, &reply);
    SF_CHECK("wrong want binding is WANT_NOT_FOUND",
             reply.status == ZCL_COMMAND_STATUS_BLOCKED &&
             strcmp(reply.error.code, "WANT_NOT_FOUND") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* Optional receipt ids are evidence references, never seller booleans. */
    sf_post_input(&input, dir, want_id, 0x73, artifact_a, content_a, 79,
                  true);
    char missing_receipt[65];
    sf_hex_seed(0xAB, missing_receipt);
    (void)json_push_kv_str(&input, "build_receipt_id", missing_receipt);
    sf_call(zcl_native_handle_shop_want_fulfill_post, &input, &reply);
    SF_CHECK("unverifiable receipt is refused",
             reply.status == ZCL_COMMAND_STATUS_BLOCKED &&
             strcmp(reply.error.code,
                    "FULFILLMENT_EVIDENCE_UNVERIFIED") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "fulfill_id", fulfill_id);
    (void)json_push_kv_int(&input, "now_unix", SF_NOW);
    sf_call(zcl_native_handle_shop_want_fulfill_status, &input, &reply);
    SF_CHECK("status re-verifies evidence",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&reply.data, "evidence_valid_now")) &&
             !json_get_bool(json_get(&reply.data,
                                     "visible_under_profile")));
    SF_CHECK("hidden status names one local review action",
             strcmp(sf_str(&reply.data, "readiness"),
                    "hidden_by_profile") == 0 &&
             strcmp(sf_str(&reply.data, "next_action"),
                    "app shop want fulfill review") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_int(&input, "now_unix", SF_NOW);
    sf_call(zcl_native_handle_shop_want_fulfill_list, &input, &reply);
    SF_CHECK("default view hides an unreviewed claim without deleting it",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_int(json_get(&reply.data, "rendered")) == 0 &&
             json_get_int(json_get(&reply.data, "hidden_by_profile")) == 1 &&
             json_get_int(json_get(&reply.data, "total_matching")) == 1);
    zcl_command_reply_free(&reply);
    json_free(&input);

    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "fulfill_id", fulfill_id);
    (void)json_push_kv_str(&input, "review_state", "reviewed_ok");
    sf_call(zcl_native_handle_shop_want_fulfill_review, &input, &reply);
    SF_CHECK("local review plan does not mutate",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(sf_str(&reply.data, "mode"), "plan") == 0 &&
             !reply.error.mutated);
    zcl_command_reply_free(&reply);
    (void)json_push_kv_bool(&input, "confirm", true);
    sf_call(zcl_native_handle_shop_want_fulfill_review, &input, &reply);
    SF_CHECK("local review commit marks the claim reviewed_ok",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             reply.error.mutated &&
             strcmp(sf_str(&reply.data, "review_state"),
                    "reviewed_ok") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_int(&input, "now_unix", SF_NOW);
    sf_call(zcl_native_handle_shop_want_fulfill_list, &input, &reply);
    SF_CHECK("reviewed claim is visible under the default profile",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_int(json_get(&reply.data, "rendered")) == 1);
    zcl_command_reply_free(&reply);
    json_free(&input);

    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_int(&input, "now_unix", SF_NOW);
    (void)json_push_kv_str(&input, "profile", "open-view");
    sf_call(zcl_native_handle_shop_want_status, &input, &reply);
    SF_CHECK("want status counts fulfillment claims",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&reply.data,
                                    "fulfillment_count_available")) &&
             json_get_int(json_get(&reply.data,
                                   "fulfillment_count")) == 1);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* Expiry is a view filter, never deletion. */
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_int(&input, "now_unix", SF_NOW + 7200);
    sf_call(zcl_native_handle_shop_want_fulfill_list, &input, &reply);
    SF_CHECK("expired claim leaves the active comparison list",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_int(json_get(&reply.data, "rendered")) == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    char wrong_secret[65];
    sf_hex_seed(0x74, wrong_secret);
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "fulfill_id", fulfill_id);
    (void)json_push_kv_str(&input, "seller_secret", wrong_secret);
    (void)json_push_kv_int(&input, "now_unix", SF_NOW + 10);
    (void)json_push_kv_bool(&input, "confirm", true);
    sf_call(zcl_native_handle_shop_want_fulfill_withdraw, &input, &reply);
    SF_CHECK("wrong seller cannot withdraw",
             reply.status == ZCL_COMMAND_STATUS_BLOCKED &&
             strcmp(reply.error.code, "WRONG_SELLER_KEY") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    char seller_secret[65];
    sf_hex_seed(0x71, seller_secret);
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "fulfill_id", fulfill_id);
    (void)json_push_kv_str(&input, "seller_secret", seller_secret);
    (void)json_push_kv_int(&input, "now_unix", SF_NOW + 11);
    sf_call(zcl_native_handle_shop_want_fulfill_withdraw, &input, &reply);
    SF_CHECK("owner withdrawal plan is non-mutating",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(sf_str(&reply.data, "mode"), "plan") == 0 &&
             !reply.error.mutated);
    zcl_command_reply_free(&reply);
    (void)json_push_kv_bool(&input, "confirm", true);
    sf_call(zcl_native_handle_shop_want_fulfill_withdraw, &input, &reply);
    SF_CHECK("owner withdrawal commit mutates once",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             reply.error.mutated);
    zcl_command_reply_free(&reply);
    sf_call(zcl_native_handle_shop_want_fulfill_withdraw, &input, &reply);
    SF_CHECK("owner withdrawal is idempotent",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&reply.data, "already_withdrawn")) &&
             !reply.error.mutated);
    zcl_command_reply_free(&reply);
    json_free(&input);

    test_rm_rf(dir);
    return failures;
}

int test_shop_fulfill(void)
{
    int failures = 0;
    failures += sf_codec();
    failures += sf_registry_whitelist();
    failures += sf_receipt_authorities();
    failures += sf_flow();
    return failures;
}
