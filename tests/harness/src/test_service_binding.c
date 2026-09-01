/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Contract tests for `zcl.service_binding.v1` — the declared way to add a
 * service. The four things this file is here to prove:
 *
 *   1. The declared catalog validates, composes with the process-isolation
 *      catalog (every host is an APP_BROKER), and has a stable identity.
 *   2. A binding cannot escape the boundary by DECLARING its way out: the
 *      isolation flag set is all-or-nothing, reserved consensus/kernel table
 *      prefixes are refused, and the command namespace cannot leave
 *      app.service.
 *   3. The token gate is reproducible: the snapshot height is a pure function
 *      of the declared gate and the tip, and the unminted sentinel never
 *      grants.
 *   4. The lifecycle machine only permits the declared transitions, and
 *      BLOCKED is sticky. */

#include "test/test_core.h"

#include "config/service_binding_catalog.h"
#include "config/service_catalog.h"
#include "kernel/service_binding.h"
#include "services/service_lifecycle.h"
#include "services/service_token_gate.h"

#include <string.h>

static struct zcl_service_binding_v1 sample_binding(void)
{
    struct zcl_service_binding_v1 b;
    memset(&b, 0, sizeof(b));
    b.struct_size = sizeof(b);
    b.schema_version = ZCL_SERVICE_BINDING_V1;
    b.binding_id = 7;
    (void)snprintf(b.name, sizeof(b.name), "%s", "sample");
    (void)snprintf(b.display_name, sizeof(b.display_name), "%s", "Sample");
    (void)snprintf(b.version, sizeof(b.version), "%s", "1.0.0");
    b.host_service_id = ZCL_SERVICE_ID_APPD;
    (void)snprintf(b.command_prefix, sizeof(b.command_prefix), "%s",
                   "app.service.sample");
    (void)snprintf(b.state_table_prefix, sizeof(b.state_table_prefix), "%s",
                   "svc_sample_");
    (void)snprintf(b.state_schema, sizeof(b.state_schema), "%s",
                   "zcl.service.sample.state.v1");
    b.state_schema_version = 1;
    memset(b.gate.token_genesis_txid, 0x11,
           sizeof(b.gate.token_genesis_txid));
    b.gate.min_balance = 100;
    b.gate.snapshot_kind = ZCL_SERVICE_GATE_SNAPSHOT_CONFIRMED_DEPTH;
    b.gate.holder_kind = ZCL_SERVICE_GATE_HOLDER_WALLET;
    b.gate.snapshot_param = 10;
    b.isolation = ZCL_SERVICE_ISOLATION_REQUIRED_V1;
    b.restart_policy = ZCL_SERVICE_RESTART_TRANSIENT;
    b.health_deadline_ms = 15000;
    return b;
}

static int test_declared_catalog(void)
{
    int failures = 0;
    TEST("service binding: declared catalog validates and composes") {
        size_t bad_index = 999;
        ASSERT(zcl_service_binding_catalog_check_v1(&bad_index) ==
               ZCL_SERVICE_BINDING_OK);
        ASSERT(bad_index == 0);
        size_t count = 0;
        const struct zcl_service_binding_v1 *catalog =
            zcl_service_binding_catalog_v1(&count);
        ASSERT(catalog != NULL);
        ASSERT(count >= 1 && count <= ZCL_SERVICE_BINDING_CATALOG_MAX);

        /* Every host must be the app broker, never core/wallet/init. A
         * service hosted on core would inherit consensus descriptors. */
        size_t manifest_count = 0;
        const struct zcl_service_manifest_v1 *manifests =
            zcl_service_catalog_v1(&manifest_count);
        for (size_t i = 0; i < count; i++) {
            ASSERT(catalog[i].host_service_id == ZCL_SERVICE_ID_APPD);
            ASSERT(zcl_service_binding_host_check_v1(
                       &catalog[i], manifests, manifest_count) ==
                   ZCL_SERVICE_BINDING_OK);
            /* The boundary is complete for every declared service. */
            ASSERT(catalog[i].isolation ==
                   ZCL_SERVICE_ISOLATION_REQUIRED_V1);
        }

        uint8_t root_a[32], root_b[32];
        ASSERT(zcl_service_binding_catalog_root_v1(root_a));
        ASSERT(zcl_service_binding_catalog_root_v1(root_b));
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        uint8_t zero[32];
        memset(zero, 0, sizeof(zero));
        ASSERT(memcmp(root_a, zero, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_reference_namespaces(void)
{
    int failures = 0;
    TEST("service binding: reference entry is reachable and namespaced") {
        const struct zcl_service_binding_v1 *ref =
            zcl_service_binding_find_v1("reference");
        ASSERT(ref != NULL);
        ASSERT(zcl_service_binding_find_v1("no-such-service") == NULL);
        ASSERT(zcl_service_binding_owns_command_v1(ref,
                                                   "app.service.reference"));
        ASSERT(zcl_service_binding_owns_command_v1(
            ref, "app.service.reference.anything"));
        /* A sibling name that merely shares a textual prefix is NOT owned. */
        ASSERT(!zcl_service_binding_owns_command_v1(
            ref, "app.service.referenced"));
        /* The registry's own leaves belong to no service. */
        ASSERT(zcl_service_binding_owner_of_command_v1(
                   "app.service.list") == NULL);
        ASSERT(zcl_service_binding_owner_of_command_v1(
                   "app.service.reference.x") == ref);
        ASSERT(zcl_service_binding_owns_table_v1(ref, "svc_reference_rows"));
        ASSERT(!zcl_service_binding_owns_table_v1(ref, "blocks"));
        ASSERT(!zcl_service_binding_owns_table_v1(ref, "utxos"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_isolation_cannot_be_declared_away(void)
{
    int failures = 0;
    TEST("service binding: the isolation flag set is all-or-nothing") {
        struct zcl_service_binding_v1 b = sample_binding();
        ASSERT(zcl_service_binding_validate_v1(&b) ==
               ZCL_SERVICE_BINDING_OK);
        /* Drop any one bit -> refused. A dropped bit is a claimed privilege. */
        static const uint64_t bits[] = {
            ZCL_SERVICE_ISOLATION_NO_BLOCK_VALIDITY,
            ZCL_SERVICE_ISOLATION_NO_CONSENSUS_WRITE,
            ZCL_SERVICE_ISOLATION_NO_BLOCKING_PROGRESS_LOCK,
            ZCL_SERVICE_ISOLATION_CATALOG_DECLARED_AUTH,
            ZCL_SERVICE_ISOLATION_OWNED_STATE_ONLY,
        };
        for (size_t i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
            b.isolation = ZCL_SERVICE_ISOLATION_REQUIRED_V1 & ~bits[i];
            ASSERT(zcl_service_binding_validate_v1(&b) ==
                   ZCL_SERVICE_BINDING_ISOLATION);
        }
        /* An invented bit is an undeclared privilege -> also refused. */
        b.isolation = ZCL_SERVICE_ISOLATION_REQUIRED_V1 | (UINT64_C(1) << 40);
        ASSERT(zcl_service_binding_validate_v1(&b) ==
               ZCL_SERVICE_BINDING_ISOLATION);
        PASS();
    } _test_next:;
    return failures;
}

static int test_reserved_namespaces_refused(void)
{
    int failures = 0;
    TEST("service binding: reserved state and command namespaces refused") {
        struct zcl_service_binding_v1 b = sample_binding();
        static const char *const reserved[] = {
            "blocks_", "utxo_", "coins_", "wallet_", "chain_",
            "consensus_", "nullifier_", "sapling_", "stage_", "tx_",
            "zslp_",
        };
        for (size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++) {
            b = sample_binding();
            (void)snprintf(b.state_table_prefix,
                           sizeof(b.state_table_prefix), "%s", reserved[i]);
            ASSERT(zcl_service_binding_validate_v1(&b) ==
                   ZCL_SERVICE_BINDING_STATE_PREFIX);
        }
        /* A prefix that does not end in '_' would swallow a sibling. */
        b = sample_binding();
        (void)snprintf(b.state_table_prefix, sizeof(b.state_table_prefix),
                       "%s", "svcsample");
        ASSERT(zcl_service_binding_validate_v1(&b) ==
               ZCL_SERVICE_BINDING_STATE_PREFIX);

        /* The command namespace can never leave app.service. */
        static const char *const escapes[] = {
            "core.sample", "dev.sample", "ops.sample", "app.sample",
            "app.service.", "status",
        };
        for (size_t i = 0; i < sizeof(escapes) / sizeof(escapes[0]); i++) {
            b = sample_binding();
            (void)snprintf(b.command_prefix, sizeof(b.command_prefix), "%s",
                           escapes[i]);
            ASSERT(zcl_service_binding_validate_v1(&b) ==
                   ZCL_SERVICE_BINDING_COMMAND_PREFIX);
        }
        /* The tail under the root must BE the service name — one identity. */
        b = sample_binding();
        (void)snprintf(b.command_prefix, sizeof(b.command_prefix), "%s",
                       "app.service.other");
        ASSERT(zcl_service_binding_validate_v1(&b) ==
               ZCL_SERVICE_BINDING_COMMAND_PREFIX);

        /* A service may not take a registry leaf name. */
        b = sample_binding();
        (void)snprintf(b.name, sizeof(b.name), "%s", "status");
        ASSERT(zcl_service_binding_validate_v1(&b) ==
               ZCL_SERVICE_BINDING_IDENTITY);
        PASS();
    } _test_next:;
    return failures;
}

static int test_only_app_broker_hosts(void)
{
    int failures = 0;
    TEST("service binding: only an app broker may host a service") {
        struct zcl_service_binding_v1 b = sample_binding();
        size_t manifest_count = 0;
        const struct zcl_service_manifest_v1 *manifests =
            zcl_service_catalog_v1(&manifest_count);
        static const uint32_t forbidden[] = {
            ZCL_SERVICE_ID_INIT, ZCL_SERVICE_ID_CORE, ZCL_SERVICE_ID_EDGE,
            ZCL_SERVICE_ID_WALLET, ZCL_SERVICE_ID_BUILDD,
        };
        for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
            b.host_service_id = forbidden[i];
            ASSERT(zcl_service_binding_host_check_v1(
                       &b, manifests, manifest_count) ==
                   ZCL_SERVICE_BINDING_HOST);
        }
        b.host_service_id = 4242; /* not in the catalog at all */
        ASSERT(zcl_service_binding_host_check_v1(
                   &b, manifests, manifest_count) == ZCL_SERVICE_BINDING_HOST);
        b.host_service_id = ZCL_SERVICE_ID_APPD;
        ASSERT(zcl_service_binding_host_check_v1(
                   &b, manifests, manifest_count) == ZCL_SERVICE_BINDING_OK);
        PASS();
    } _test_next:;
    return failures;
}

static int test_catalog_refuses_overlap(void)
{
    int failures = 0;
    TEST("service binding: catalog refuses overlapping namespaces") {
        struct zcl_service_binding_v1 pair[2];
        pair[0] = sample_binding();
        pair[0].binding_id = 1;
        pair[1] = sample_binding();
        pair[1].binding_id = 2;
        (void)snprintf(pair[1].name, sizeof(pair[1].name), "%s", "sample2");
        (void)snprintf(pair[1].command_prefix, sizeof(pair[1].command_prefix),
                       "%s", "app.service.sample2");
        (void)snprintf(pair[1].state_table_prefix,
                       sizeof(pair[1].state_table_prefix), "%s", "svc_two_");
        size_t bad = 999;
        ASSERT(zcl_service_binding_catalog_validate_v1(pair, 2, &bad) ==
               ZCL_SERVICE_BINDING_OK);

        /* "svc_sample_" is a prefix of "svc_sample_extra_": one service
         * could write the other's tables. Refused. */
        (void)snprintf(pair[1].state_table_prefix,
                       sizeof(pair[1].state_table_prefix), "%s",
                       "svc_sample_extra_");
        ASSERT(zcl_service_binding_catalog_validate_v1(pair, 2, &bad) ==
               ZCL_SERVICE_BINDING_CATALOG_COLLISION);
        ASSERT(bad == 1);

        /* binding_id must strictly ascend so the catalog order is an
         * identity, not an accident. */
        pair[1] = sample_binding();
        pair[1].binding_id = 1;
        (void)snprintf(pair[1].name, sizeof(pair[1].name), "%s", "sample2");
        (void)snprintf(pair[1].command_prefix, sizeof(pair[1].command_prefix),
                       "%s", "app.service.sample2");
        (void)snprintf(pair[1].state_table_prefix,
                       sizeof(pair[1].state_table_prefix), "%s", "svc_two_");
        ASSERT(zcl_service_binding_catalog_validate_v1(pair, 2, &bad) ==
               ZCL_SERVICE_BINDING_CATALOG_ORDER);
        PASS();
    } _test_next:;
    return failures;
}

static int test_token_gate_reproducible(void)
{
    int failures = 0;
    TEST("service gate: snapshot height is a pure function of gate and tip") {
        struct zcl_service_binding_v1 b = sample_binding();
        int32_t height = -1;
        /* CONFIRMED_DEPTH: tip - depth, and identical on every call. */
        ASSERT(zcl_service_gate_snapshot_height_v1(&b.gate, 1000, &height));
        ASSERT(height == 990);
        int32_t again = -1;
        ASSERT(zcl_service_gate_snapshot_height_v1(&b.gate, 1000, &again));
        ASSERT(again == height);
        /* A chain shorter than the depth has NO snapshot. Clamping to 0
         * would silently answer a different question. */
        ASSERT(!zcl_service_gate_snapshot_height_v1(&b.gate, 9, &height));
        ASSERT(height == -1);
        ASSERT(!zcl_service_gate_snapshot_height_v1(&b.gate, -1, &height));

        /* FIXED_HEIGHT ignores the tip entirely: the verdict never moves. */
        b.gate.snapshot_kind = ZCL_SERVICE_GATE_SNAPSHOT_FIXED_HEIGHT;
        b.gate.snapshot_param = 250000;
        ASSERT(zcl_service_gate_snapshot_height_v1(&b.gate, 1000, &height));
        ASSERT(height == 250000);
        ASSERT(zcl_service_gate_snapshot_height_v1(&b.gate, 9999999, &height));
        ASSERT(height == 250000);
        PASS();
    } _test_next:;
    return failures;
}

static int test_gate_malformed_never_resolves(void)
{
    int failures = 0;
    TEST("service gate: malformed gates never resolve a snapshot") {
        struct zcl_service_binding_v1 b = sample_binding();
        int32_t height = 0;
        struct zcl_service_token_gate_v1 gate = b.gate;
        memset(gate.token_genesis_txid, 0, sizeof(gate.token_genesis_txid));
        ASSERT(!zcl_service_gate_snapshot_height_v1(&gate, 1000, &height));
        gate = b.gate;
        gate.min_balance = 0;
        ASSERT(!zcl_service_gate_snapshot_height_v1(&gate, 1000, &height));
        gate = b.gate;
        gate.snapshot_kind = 99;
        ASSERT(!zcl_service_gate_snapshot_height_v1(&gate, 1000, &height));
        gate = b.gate;
        gate.snapshot_param = ZCL_SERVICE_GATE_DEPTH_MAX + 1;
        ASSERT(!zcl_service_gate_snapshot_height_v1(&gate, 10000000, &height));
        gate = b.gate;
        gate.holder_kind = 0;
        ASSERT(!zcl_service_gate_snapshot_height_v1(&gate, 1000, &height));

        /* A zero token and an all-0xff token are different things: the first
         * is malformed, the second is the declared-but-unminted sentinel. */
        uint8_t zero[32], sentinel[32];
        memset(zero, 0, sizeof(zero));
        memset(sentinel, 0xff, sizeof(sentinel));
        ASSERT(!zcl_service_gate_token_unminted_v1(zero));
        ASSERT(zcl_service_gate_token_unminted_v1(sentinel));
        PASS();
    } _test_next:;
    return failures;
}

static int test_gate_denies_never_grants(void)
{
    int failures = 0;
    TEST("service gate: unminted token and missing ledger deny, never grant") {
        const struct zcl_service_binding_v1 *ref =
            zcl_service_binding_find_v1("reference");
        ASSERT(ref != NULL);
        struct service_gate_verdict verdict;
        /* NULL ndb is a perfectly ordinary caller mistake; it must deny. */
        ASSERT(service_token_gate_evaluate(NULL, ref, 1000, NULL,
                                           &verdict).ok);
        ASSERT(!verdict.granted);
        ASSERT(verdict.reason == SERVICE_GATE_REASON_TOKEN_UNMINTED);
        ASSERT(strcmp(service_gate_reason_name(verdict.reason),
                      "token_unminted") == 0);

        /* Real token, no ledger -> ledger_unavailable, still denied. */
        struct zcl_service_binding_v1 armed = *ref;
        memset(armed.gate.token_genesis_txid, 0x22,
               sizeof(armed.gate.token_genesis_txid));
        ASSERT(service_token_gate_evaluate(NULL, &armed, 1000, NULL,
                                           &verdict).ok);
        ASSERT(!verdict.granted);
        ASSERT(verdict.reason == SERVICE_GATE_REASON_LEDGER_UNAVAILABLE);
        ASSERT(verdict.snapshot_height == 900);
        ASSERT(verdict.threshold == armed.gate.min_balance);

        /* A tip below the declared depth denies with no snapshot at all. */
        ASSERT(service_token_gate_evaluate(NULL, &armed, 3, NULL,
                                           &verdict).ok);
        ASSERT(!verdict.granted);
        ASSERT(verdict.reason == SERVICE_GATE_REASON_NO_SNAPSHOT);
        ASSERT(verdict.snapshot_height == -1);

        /* An address-holder gate with no address supplied denies. */
        armed.gate.holder_kind = ZCL_SERVICE_GATE_HOLDER_ADDRESS;
        ASSERT(service_token_gate_evaluate(NULL, &armed, 1000, NULL,
                                           &verdict).ok);
        ASSERT(!verdict.granted);

        /* An invalid binding denies rather than being trusted. */
        struct zcl_service_binding_v1 broken = *ref;
        broken.isolation = 0;
        ASSERT(service_token_gate_evaluate(NULL, &broken, 1000, NULL,
                                           &verdict).ok);
        ASSERT(!verdict.granted);
        ASSERT(verdict.reason == SERVICE_GATE_REASON_INVALID_BINDING);

        /* A NULL out pointer is a caller error, not a verdict. */
        ASSERT(!service_token_gate_evaluate(NULL, ref, 1000, NULL, NULL).ok);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lifecycle_machine(void)
{
    int failures = 0;
    TEST("service lifecycle: only the declared transitions are permitted") {
        uint32_t next = 0;
        ASSERT(zcl_service_lifecycle_next_v1(ZCL_SERVICE_LIFECYCLE_DECLARED,
                                             ZCL_SERVICE_EVENT_REGISTER,
                                             &next));
        ASSERT(next == ZCL_SERVICE_LIFECYCLE_STARTING);
        ASSERT(zcl_service_lifecycle_next_v1(next, ZCL_SERVICE_EVENT_START,
                                             &next));
        ASSERT(next == ZCL_SERVICE_LIFECYCLE_READY);
        ASSERT(zcl_service_lifecycle_next_v1(next, ZCL_SERVICE_EVENT_DEGRADE,
                                             &next));
        ASSERT(next == ZCL_SERVICE_LIFECYCLE_DEGRADED);
        ASSERT(zcl_service_lifecycle_next_v1(next, ZCL_SERVICE_EVENT_RECOVER,
                                             &next));
        ASSERT(next == ZCL_SERVICE_LIFECYCLE_READY);
        ASSERT(zcl_service_lifecycle_next_v1(next, ZCL_SERVICE_EVENT_STOP,
                                             &next));
        ASSERT(next == ZCL_SERVICE_LIFECYCLE_STOPPING);
        ASSERT(zcl_service_lifecycle_next_v1(next, ZCL_SERVICE_EVENT_EXIT,
                                             &next));
        ASSERT(next == ZCL_SERVICE_LIFECYCLE_EXITED);
        ASSERT(zcl_service_lifecycle_next_v1(next, ZCL_SERVICE_EVENT_REMOVE,
                                             &next));
        ASSERT(next == ZCL_SERVICE_LIFECYCLE_DECLARED);

        /* Skipping register, restarting a running service, and removing a
         * live one are all refused rather than silently ignored. */
        ASSERT(!zcl_service_lifecycle_next_v1(ZCL_SERVICE_LIFECYCLE_DECLARED,
                                              ZCL_SERVICE_EVENT_START, &next));
        ASSERT(!zcl_service_lifecycle_next_v1(ZCL_SERVICE_LIFECYCLE_READY,
                                              ZCL_SERVICE_EVENT_REGISTER,
                                              &next));
        ASSERT(!zcl_service_lifecycle_next_v1(ZCL_SERVICE_LIFECYCLE_READY,
                                              ZCL_SERVICE_EVENT_REMOVE, &next));
        ASSERT(!zcl_service_lifecycle_next_v1(ZCL_SERVICE_LIFECYCLE_EXITED,
                                              ZCL_SERVICE_EVENT_START, &next));
        ASSERT(!zcl_service_lifecycle_next_v1(ZCL_SERVICE_LIFECYCLE_READY, 0,
                                              &next));
        PASS();
    } _test_next:;
    return failures;
}

static int test_lifecycle_blocked_is_sticky(void)
{
    int failures = 0;
    TEST("service lifecycle: BLOCKED is sticky until an explicit stop") {
        uint32_t next = ZCL_SERVICE_LIFECYCLE_READY;
        ASSERT(zcl_service_lifecycle_next_v1(next, ZCL_SERVICE_EVENT_FAULT,
                                             &next));
        ASSERT(next == ZCL_SERVICE_LIFECYCLE_BLOCKED);
        /* No escape except stop — not recover, not start, not remove. */
        uint32_t attempt = 0;
        ASSERT(!zcl_service_lifecycle_next_v1(next, ZCL_SERVICE_EVENT_RECOVER,
                                              &attempt));
        ASSERT(!zcl_service_lifecycle_next_v1(next, ZCL_SERVICE_EVENT_START,
                                              &attempt));
        ASSERT(!zcl_service_lifecycle_next_v1(next, ZCL_SERVICE_EVENT_REMOVE,
                                              &attempt));
        ASSERT(!zcl_service_lifecycle_next_v1(next, ZCL_SERVICE_EVENT_FAULT,
                                              &attempt));
        ASSERT(zcl_service_lifecycle_next_v1(next, ZCL_SERVICE_EVENT_STOP,
                                             &next));
        ASSERT(next == ZCL_SERVICE_LIFECYCLE_STOPPING);
        PASS();
    } _test_next:;
    return failures;
}

static int test_lifecycle_registry_gates_start(void)
{
    int failures = 0;
    TEST("service lifecycle: registry gates start on the token verdict") {
        ASSERT(service_lifecycle_init().ok);
        uint32_t state = 0;
        char reason[SERVICE_LIFECYCLE_REASON_MAX];
        ASSERT(service_lifecycle_state("reference", &state, reason,
                                       sizeof(reason)).ok);
        ASSERT(state == ZCL_SERVICE_LIFECYCLE_DECLARED);
        ASSERT(reason[0] == '\0');
        ASSERT(!service_lifecycle_state("no-such", &state, reason,
                                        sizeof(reason)).ok);

        ASSERT(service_lifecycle_register("reference").ok);
        ASSERT(service_lifecycle_state("reference", &state, reason,
                                       sizeof(reason)).ok);
        ASSERT(state == ZCL_SERVICE_LIFECYCLE_STARTING);
        /* Registering twice is refused, not silently repeated. */
        ASSERT(!service_lifecycle_register("reference").ok);
        ASSERT(!service_lifecycle_register("no-such").ok);

        /* The reference binding names the unminted sentinel, so start must
         * refuse and NAME the reason rather than quietly no-op. */
        struct zcl_result started =
            service_lifecycle_start("reference", NULL, 1000);
        ASSERT(!started.ok);
        ASSERT(started.code == SERVICE_LIFECYCLE_ERR_GATE_DENIED);
        ASSERT(strstr(started.message, "token_unminted") != NULL);
        ASSERT(service_lifecycle_state("reference", &state, reason,
                                       sizeof(reason)).ok);
        ASSERT(state == ZCL_SERVICE_LIFECYCLE_BLOCKED);
        ASSERT(strcmp(reason, "token_unminted") == 0);

        /* Stop clears the blocker and lands EXITED; remove returns it to
         * DECLARED without dropping any state. */
        ASSERT(service_lifecycle_stop("reference").ok);
        ASSERT(service_lifecycle_state("reference", &state, reason,
                                       sizeof(reason)).ok);
        ASSERT(state == ZCL_SERVICE_LIFECYCLE_EXITED);
        ASSERT(reason[0] == '\0');
        ASSERT(service_lifecycle_remove("reference").ok);
        ASSERT(service_lifecycle_state("reference", &state, reason,
                                       sizeof(reason)).ok);
        ASSERT(state == ZCL_SERVICE_LIFECYCLE_DECLARED);
        ASSERT(!service_lifecycle_remove("reference").ok);

        /* init() is the fresh-boot reset. */
        ASSERT(service_lifecycle_init().ok);
        ASSERT(service_lifecycle_state("reference", &state, reason,
                                       sizeof(reason)).ok);
        ASSERT(state == ZCL_SERVICE_LIFECYCLE_DECLARED);
        PASS();
    } _test_next:;
    return failures;
}

static int test_binding_identity(void)
{
    int failures = 0;
    TEST("service binding: identity covers every declared field") {
        struct zcl_service_binding_v1 b = sample_binding();
        uint8_t base[32], other[32];
        ASSERT(zcl_service_binding_digest_v1(&b, base));

        struct zcl_service_binding_v1 mutated = b;
        mutated.gate.min_balance++;
        ASSERT(zcl_service_binding_digest_v1(&mutated, other));
        ASSERT(memcmp(base, other, 32) != 0);

        mutated = b;
        mutated.gate.snapshot_param = 11;
        ASSERT(zcl_service_binding_digest_v1(&mutated, other));
        ASSERT(memcmp(base, other, 32) != 0);

        mutated = b;
        mutated.gate.token_genesis_txid[31] ^= 0x01;
        ASSERT(zcl_service_binding_digest_v1(&mutated, other));
        ASSERT(memcmp(base, other, 32) != 0);

        /* Bytes past the NUL of a bounded string are padding, not identity. */
        mutated = b;
        mutated.name[strlen(mutated.name) + 1] = 'z';
        ASSERT(zcl_service_binding_digest_v1(&mutated, other));
        ASSERT(memcmp(base, other, 32) == 0);

        /* An invalid binding has no identity at all. */
        mutated = b;
        mutated.schema_version = 99;
        memset(other, 0xa5, sizeof(other));
        ASSERT(!zcl_service_binding_digest_v1(&mutated, other));
        uint8_t zero[32];
        memset(zero, 0, sizeof(zero));
        ASSERT(memcmp(other, zero, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_service_binding(void)
{
    int failures = 0;
    failures += test_declared_catalog();
    failures += test_reference_namespaces();
    failures += test_isolation_cannot_be_declared_away();
    failures += test_reserved_namespaces_refused();
    failures += test_only_app_broker_hosts();
    failures += test_catalog_refuses_overlap();
    failures += test_token_gate_reproducible();
    failures += test_gate_malformed_never_resolves();
    failures += test_gate_denies_never_grants();
    failures += test_lifecycle_machine();
    failures += test_lifecycle_blocked_is_sticky();
    failures += test_lifecycle_registry_gates_start();
    failures += test_binding_identity();
    return failures;
}
