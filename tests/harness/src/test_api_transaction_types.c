/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Contract tests for the semantic transaction-type resource.
 */

#include "test/api_test_fixtures.h"

#include "config/command_catalog.h"
#include "controllers/transaction_type_catalog.h"
#include "kernel/command_registry.h"
#include "primitives/transaction.h"
#include "script/standard.h"

#include <string.h>

static bool command_exists(const struct zcl_command_registry *registry,
                           const char *path)
{
    return !path || !path[0] ||
           zcl_command_registry_find(registry, path, NULL) != NULL;
}

static bool component_commands_exist(
    const struct zcl_command_registry *registry, const char *csv)
{
    if (!csv || !csv[0])
        return true;
    const char *cursor = csv;
    while (*cursor) {
        const char *start = cursor;
        while (*cursor && *cursor != ',')
            cursor++;
        size_t len = (size_t)(cursor - start);
        char path[128];
        if (len == 0 || len >= sizeof(path))
            return false;
        memcpy(path, start, len);
        path[len] = '\0';
        if (!command_exists(registry, path))
            return false;
        if (*cursor == ',')
            cursor++;
    }
    return true;
}

static bool transaction_command_is_mapped(
    const struct zcl_transaction_type_contract *types, size_t type_count,
    const char *path)
{
    for (size_t i = 0; i < type_count; i++)
        if (zcl_transaction_type_command_roles(&types[i], path) !=
            ZCL_TRANSACTION_COMMAND_ROLE_NONE)
            return true;
    return false;
}

static bool transaction_command_has_chain_signal(
    const struct zcl_command_spec *spec)
{
    const char *fields[] = { spec->summary, spec->semantics, spec->tags };
    static const char *const signals[] = {
        "on-chain", "onchain", "broadcast", "transaction", "txid",
        "OP_RETURN", "op_return", "Sapling", "sapling", "HTLC", "htlc",
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        for (size_t j = 0; j < sizeof(signals) / sizeof(signals[0]); j++)
            if (fields[i] && strstr(fields[i], signals[j]))
                return true;
    return false;
}

int api_transaction_type_focused_tests(void)
{
    int failures = 0;

    printf("api: transaction type registry references real native leaves... ");
    {
        const struct zcl_command_registry *registry = zcl_command_catalog();
        size_t count = 0;
        const struct zcl_transaction_type_contract *types =
            zcl_transaction_type_catalog(&count);
        bool ok = registry && types && count >= 30;
        for (size_t i = 0; ok && i < count; i++) {
            ok = types[i].id && types[i].id[0] &&
                 types[i].family && types[i].family[0] &&
                 types[i].availability && types[i].availability[0] &&
                 types[i].lab_case_id &&
                 strcmp(types[i].lab_case_id, types[i].id) == 0 &&
                 types[i].proof_level && types[i].proof_level[0] &&
                 command_exists(registry, types[i].builder_command) &&
                 command_exists(registry, types[i].commit_command) &&
                 command_exists(registry, types[i].inspect_command) &&
                 component_commands_exist(
                     registry, types[i].component_commands_csv);
            for (size_t j = 0; ok && j < i; j++)
                ok = strcmp(types[i].id, types[j].id) != 0;
        }
        ok = ok && zcl_command_registry_find(
            registry, "app.transaction-types.list", NULL) != NULL;
        ok = ok && zcl_command_registry_find(
            registry, "app.transaction-types.show", NULL) != NULL;
        ok = ok && zcl_command_registry_find(
            registry, "app.transaction-types.wire", NULL) != NULL;
        ok = ok && zcl_command_registry_find(
            registry, "app.transaction-types.command", NULL) != NULL;
        ok = ok && zcl_command_registry_find(
            registry, "app.transaction-types.micro-lab", NULL) != NULL;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: native micro-lab covers 100 exact slots and fails closed... ");
    {
        const struct zcl_command_registry *registry = zcl_command_catalog();
        const struct zcl_command_spec *spec = registry ?
            zcl_command_registry_find(registry,
                "app.transaction-types.micro-lab", NULL) : NULL;
        size_t profile_count = 0;
        const struct zcl_transaction_micro_lab_profile *profiles =
            zcl_transaction_micro_lab_catalog(&profile_count);
        bool ok = spec && profiles && profile_count == 14 &&
            spec->budget_bytes == ZCL_COMMAND_EXTENDED_LIST_BUDGET;
        int expected_slot = 1;
        for (size_t i = 0; ok && i < profile_count; i++) {
            const struct zcl_transaction_type_contract *type =
                zcl_transaction_type_find(profiles[i].type_id);
            ok = profiles[i].first_slot == expected_slot &&
                profiles[i].last_slot >= profiles[i].first_slot &&
                profiles[i].recipient_zat ==
                    ZCL_TRANSACTION_MICRO_LAB_RECIPIENT_ZAT &&
                profiles[i].fee_zat == ZCL_TRANSACTION_MICRO_LAB_FEE_ZAT &&
                type && strcmp(type->availability, "ready") == 0;
            expected_slot = profiles[i].last_slot + 1;
        }
        ok = ok && expected_slot == ZCL_TRANSACTION_MICRO_LAB_TARGET + 1 &&
            zcl_transaction_micro_lab_find_slot(1) == &profiles[0] &&
            zcl_transaction_micro_lab_find_slot(100) ==
                &profiles[profile_count - 1] &&
            zcl_transaction_micro_lab_find_slot(0) == NULL &&
            zcl_transaction_micro_lab_find_slot(101) == NULL;

        struct zcl_command_context context = {
            .registry = registry,
            .granted_capabilities = ~(uint64_t)0,
            .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        };
        struct json_value input;
        struct json_value root;
        char output[ZCL_COMMAND_EXTENDED_LIST_BUDGET + 1];
        enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        json_init(&input);
        json_set_object(&input);
        json_push_kv_int(&input, "slot", 91);
        char why[160];
        ok = ok && spec && zcl_command_registry_input_validate(
            spec, &input, why, sizeof(why));
        size_t n = spec ? zcl_command_registry_execute_json(
            registry, spec, &context, &input, false, spec->path, "normal",
            0, 0, NULL, output, sizeof(output) - 1, &exit_code) : 0;
        json_free(&input);
        output[n < sizeof(output) ? n : sizeof(output) - 1] = 0;
        json_init(&root);
        ok = ok && n > 0 && n <= (size_t)spec->budget_bytes &&
            exit_code == ZCL_COMMAND_EXIT_OK && json_read(&root, output, n) &&
            json_get_bool(json_get(&root, "ok"));
        const struct json_value *data = json_get(&root, "data");
        const struct json_value *profile = data ?
            json_get(data, "profile") : NULL;
        const struct json_value *type = data ?
            json_get(data, "transaction_type") : NULL;
        const struct json_value *guide_input = data ?
            json_get(data, "guide_input") : NULL;
        ok = ok && data && profile && type && guide_input &&
            strcmp(json_get_str(json_get(data, "schema")),
                   ZCL_TRANSACTION_MICRO_LAB_SCHEMA) == 0 &&
            json_get_int(json_get(data, "target_transaction_count")) == 100 &&
            json_get_int(json_get(data, "campaign_transaction_type_count")) == 14 &&
            json_get_int(json_get(data, "recipient_zat_each")) == 1000 &&
            json_get_int(json_get(data, "fee_zat_each")) == 10000 &&
            json_get_int(json_get(data, "campaign_envelope_zat")) == 2000000 &&
            json_get_int(json_get(data, "selected_slot")) == 91 &&
            json_get_int(json_get(profile, "slot")) == 91 &&
            strcmp(json_get_str(json_get(profile, "transaction_type")),
                   "htlc_redeem") == 0 &&
            strcmp(json_get_str(json_get(type, "id")), "htlc_redeem") == 0 &&
            strcmp(json_get_str(json_get(guide_input, "type")),
                   "htlc_redeem") == 0 &&
            !json_get_bool(json_get(data, "automatically_broadcasts")) &&
            strstr(output, "private_key") == NULL &&
            strstr(output, "grant_token") == NULL &&
            strstr(output, "datadir") == NULL;
        json_free(&root);

        json_init(&input);
        json_set_object(&input);
        json_push_kv_int(&input, "slot", 101);
        ok = ok && spec && !zcl_command_registry_input_validate(
            spec, &input, why, sizeof(why));
        exit_code = ZCL_COMMAND_EXIT_OK;
        n = spec ? zcl_command_registry_execute_json(
            registry, spec, &context, &input, false, spec->path, "normal",
            0, 0, NULL, output, sizeof(output) - 1, &exit_code) : 0;
        json_free(&input);
        output[n < sizeof(output) ? n : sizeof(output) - 1] = 0;
        json_init(&root);
        ok = ok && n > 0 && exit_code == ZCL_COMMAND_EXIT_INVALID &&
            json_read(&root, output, n) &&
            !json_get_bool(json_get(&root, "ok"));
        const struct json_value *error = json_get(&root, "error");
        ok = ok && error &&
            strcmp(json_get_str(json_get(error, "code")), "BAD_SLOT") == 0;
        json_free(&root);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: reverse transaction aliases reference real types and leaves... ");
    {
        const struct zcl_command_registry *registry = zcl_command_catalog();
        size_t alias_count = 0;
        const struct zcl_transaction_command_alias *aliases =
            zcl_transaction_command_alias_catalog(&alias_count);
        bool ok = registry && aliases && alias_count == 13;
        for (size_t i = 0; ok && i < alias_count; i++) {
            ok = zcl_transaction_type_find(aliases[i].type_id) != NULL &&
                 zcl_command_registry_find(registry,
                     aliases[i].command_path, NULL) != NULL &&
                 aliases[i].role != ZCL_TRANSACTION_COMMAND_ROLE_NONE &&
                 aliases[i].explanation && aliases[i].explanation[0];
            for (size_t j = 0; ok && j < i; j++)
                ok = strcmp(aliases[i].type_id, aliases[j].type_id) != 0 ||
                     strcmp(aliases[i].command_path,
                            aliases[j].command_path) != 0 ||
                     aliases[i].role != aliases[j].role;
        }
        size_t type_count = 0;
        const struct zcl_transaction_type_contract *types =
            zcl_transaction_type_catalog(&type_count);
        for (size_t i = 0; ok && i < type_count; i++) {
            if (types[i].builder_command[0])
                ok = (zcl_transaction_type_command_roles(
                    &types[i], types[i].builder_command) &
                    ZCL_TRANSACTION_COMMAND_ROLE_BUILDER) != 0;
            if (ok && types[i].commit_command[0])
                ok = (zcl_transaction_type_command_roles(
                    &types[i], types[i].commit_command) &
                    ZCL_TRANSACTION_COMMAND_ROLE_COMMIT) != 0;
            if (ok && types[i].inspect_command[0])
                ok = (zcl_transaction_type_command_roles(
                    &types[i], types[i].inspect_command) &
                    ZCL_TRANSACTION_COMMAND_ROLE_INSPECT) != 0;
        }
        size_t nonchain_count = 0;
        const struct zcl_transaction_nonchain_command *nonchain =
            zcl_transaction_nonchain_command_catalog(&nonchain_count);
        ok = ok && nonchain && nonchain_count == 35;
        for (size_t i = 0; ok && i < nonchain_count; i++) {
            const struct zcl_command_spec *spec =
                zcl_command_registry_find(registry,
                    nonchain[i].command_path, NULL);
            ok = spec && nonchain[i].category && nonchain[i].category[0] &&
                 nonchain[i].explanation && nonchain[i].explanation[0] &&
                 !transaction_command_is_mapped(types, type_count,
                                                nonchain[i].command_path);
            for (size_t j = 0; ok && j < i; j++)
                ok = strcmp(nonchain[i].command_path,
                            nonchain[j].command_path) != 0;
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: every chain-shaped mutating command has a reverse mapping... ");
    {
        const struct zcl_command_registry *registry = zcl_command_catalog();
        size_t type_count = 0;
        const struct zcl_transaction_type_contract *types =
            zcl_transaction_type_catalog(&type_count);
        bool ok = registry && types;
        size_t uncovered = 0;
        for (size_t i = 0; ok && i < registry->count; i++) {
            const struct zcl_command_spec *spec = &registry->commands[i];
            const bool candidate = spec->mode != ZCL_COMMAND_MODE_BRANCH &&
                spec->availability == ZCL_COMMAND_READY &&
                spec->effect != ZCL_COMMAND_EFFECT_READ &&
                (spec->risk == ZCL_COMMAND_RISK_WALLET ||
                 transaction_command_has_chain_signal(spec));
            if (candidate && !transaction_command_is_mapped(
                                 types, type_count, spec->path) &&
                !zcl_transaction_nonchain_command_find(spec->path)) {
                printf("\n  UNCOVERED %s", spec->path);
                uncovered++;
            }
        }
        ok = ok && uncovered == 0;
        if (ok) printf("OK\n");
        else { printf("\nFAIL (%zu uncovered)\n", uncovered); failures++; }
    }

    printf("api: wire catalog covers source-defined eras and open-ended carriers... ");
    {
        struct json_value root;
        json_init(&root);
        bool ok = zcl_transaction_wire_catalog_json(&root) &&
            strcmp(json_get_str(json_get(&root, "schema")),
                   ZCL_TRANSACTION_WIRE_CATALOG_SCHEMA) == 0 &&
            json_get_int(json_get(&root, "wire_family_count")) == 4 &&
            json_get_int(json_get(&root, "script_class_count")) ==
                (int64_t)TX_NULL_DATA + 1 &&
            json_get_bool(json_get(&root,
                                   "consensus_wire_families_are_finite")) &&
            json_get_bool(json_get(&root,
                                   "application_semantics_are_open_ended")) &&
            json_get_bool(json_get(
                &root, "mainnet_overwinter_and_sapling_activate_together")) &&
            !json_get_bool(json_get(&root, "mainnet_v3_epoch_exists")) &&
            json_get_int(json_get(&root,
                                  "canonical_script_example_count")) == 5 &&
            json_get_int(json_get(&root,
                           "script_class_solver_coverage_count")) == 6;
        const struct json_value *families = json_get(&root, "wire_families");
        const struct json_value *legacy_v1 = families ?
            api_test_find_str_field(families, "id", "legacy_v1") : NULL;
        const struct json_value *legacy_v2 = families ?
            api_test_find_str_field(families, "id", "legacy_v2") : NULL;
        const struct json_value *overwinter = families ?
            api_test_find_str_field(families, "id", "overwinter_v3") : NULL;
        const struct json_value *sapling = families ?
            api_test_find_str_field(families, "id", "sapling_v4") : NULL;
        ok = ok && legacy_v1 && legacy_v2 && overwinter && sapling &&
            json_get_int(json_get(legacy_v1, "version")) == 1 &&
            !json_get_bool(json_get(legacy_v1, "overwintered")) &&
            strcmp(json_get_str(json_get(legacy_v1, "mainnet_status")),
                   "historical_only") == 0 &&
            json_get_int(json_get(legacy_v1,
                                  "mainnet_first_height")) == 0 &&
            json_get_int(json_get(legacy_v1,
                                  "mainnet_last_height")) == 476968 &&
            json_get_int(json_get(legacy_v1, "example_height")) == 1 &&
            strcmp(json_get_str(json_get(legacy_v1, "evidence_level")),
                   "canonical_mainnet_contextual") == 0 &&
            api_test_array_has_str(json_get(legacy_v1, "test_groups"),
                                   "test_transaction_wire_evidence") &&
            json_get_int(json_get(legacy_v2, "version")) == 2 &&
            strcmp(json_get_str(json_get(legacy_v2, "sprout_proof")),
                   "phgr13") == 0 &&
            json_get_int(json_get(overwinter, "version")) ==
                OVERWINTER_TX_VERSION &&
            strcmp(json_get_str(json_get(overwinter, "version_group_id")),
                   "0x03c48270") == 0 &&
            strcmp(json_get_str(json_get(overwinter, "mainnet_status")),
                   "never_active") == 0 &&
            json_is_null(json_get(overwinter, "mainnet_first_height")) &&
            json_is_null(json_get(overwinter, "mainnet_last_height")) &&
            json_is_null(json_get(overwinter, "example_height")) &&
            json_is_null(json_get(overwinter, "example_txid")) &&
            strcmp(json_get_str(json_get(overwinter, "evidence_level")),
                   "mainnet_unreachable_boundary_proven") == 0 &&
            json_get_int(json_get(sapling, "version")) ==
                SAPLING_TX_VERSION &&
            strcmp(json_get_str(json_get(sapling, "version_group_id")),
                   "0x892f2085") == 0 &&
            strcmp(json_get_str(json_get(sapling, "sprout_proof")),
                   "groth16") == 0 &&
            strcmp(json_get_str(json_get(sapling, "mainnet_status")),
                   "current") == 0 &&
            json_get_int(json_get(sapling,
                                  "mainnet_first_height")) == 476969 &&
            json_is_null(json_get(sapling, "mainnet_last_height"));
        const struct json_value *scripts = json_get(&root, "script_classes");
        const struct json_value *nonstandard = scripts ?
            api_test_find_str_field(scripts, "id", "nonstandard") : NULL;
        const struct json_value *nulldata = scripts ?
            api_test_find_str_field(scripts, "id", "nulldata") : NULL;
        const struct json_value *multisig = scripts ?
            api_test_find_str_field(scripts, "id", "multisig") : NULL;
        ok = ok && scripts && json_size(scripts) == (size_t)TX_NULL_DATA + 1 &&
            nonstandard && nulldata && multisig &&
            !json_get_bool(json_get(nonstandard, "standard_relay_class")) &&
            strcmp(json_get_str(json_get(nonstandard, "spendability")),
                   "script_dependent") == 0 &&
            strcmp(json_get_str(json_get(nonstandard,
                                          "mainnet_example_status")),
                   "canonical_mainnet") == 0 &&
            api_test_array_has_str(json_get(nonstandard, "test_groups"),
                                   "test_transaction_wire_evidence") &&
            json_get_bool(json_get(nulldata, "standard_relay_class")) &&
            strcmp(json_get_str(json_get(nulldata, "spendability")),
                   "provably_unspendable") == 0 &&
            strcmp(json_get_str(json_get(multisig,
                                          "mainnet_example_status")),
                   "not_pinned") == 0 &&
            json_is_null(json_get(multisig, "example_height")) &&
            json_is_null(json_get(multisig, "example_txid")) &&
            strcmp(json_get_str(json_get(multisig, "evidence_level")),
                   "solver_vectors") == 0;
        const struct json_value *codecs =
            json_get(&root, "recognized_application_codecs");
        const struct json_value *zpay = codecs ?
            api_test_find_str_field(codecs, "id", "zpay") : NULL;
        ok = ok && zpay &&
            strcmp(json_get_str(json_get(zpay, "coverage")),
                   "semantic_catalog") == 0 &&
            strstr(json_get_str(json_get(&root, "unknown_op_return_policy")),
                   "without_inventing_semantics") != NULL;
        json_free(&root);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: transaction type collection separates readiness and proof... ");
    {
        static uint8_t response[262144];
        size_t n = api_handle_request("GET", "/api/v1/transaction-types",
                                      NULL, 0, response, sizeof(response));
        const char *body = api_test_body(response, n, sizeof(response));
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          ZCL_TRANSACTION_TYPES_INDEX_SCHEMA) == 0;
        const struct json_value *types = json_get(&root, "transaction_types");
        int64_t count = json_get_int(json_get(&root,
                                              "transaction_type_count"));
        ok = ok && types && types->type == JSON_ARR &&
             count == (int64_t)json_size(types) && count >= 30;
        ok = ok && count == json_get_int(json_get(&root, "ready_count")) +
                               json_get_int(json_get(&root,
                                                     "process_only_count")) +
                               json_get_int(json_get(&root,
                                                     "contained_count")) +
                               json_get_int(json_get(&root, "planned_count"));
        ok = ok && count == 39 &&
             json_get_int(json_get(&root, "demonstrated_count")) == 39 &&
             json_get_int(json_get(&root, "blocked_count")) == 0 &&
             json_get_int(json_get(&root, "chain_confirmed_count")) == 38 &&
             json_get_int(json_get(&root,
                 "process_only_consensus_verified_count")) == 1 &&
             json_get_int(json_get(&root,
                 "chain_or_process_verified_count")) == 39 &&
             json_get_int(json_get(&root,
                                   "mainnet_live_proven_count")) == 0 &&
             json_get_int(json_get(&root, "proof_test_group_count")) == 30 &&
             json_get_bool(json_get(&root, "fully_demonstrated")) &&
             json_get_bool(json_get(&root,
                 "fully_chain_or_process_verified")) &&
             strcmp(json_get_str(json_get(&root, "wire_catalog_command")),
                    "app.transaction-types.wire") == 0 &&
             strcmp(json_get_str(json_get(&root,
                                          "reverse_lookup_command")),
                    "app.transaction-types.command") == 0 &&
             json_get_int(json_get(&root,
                 "alternate_command_route_count")) == 13 &&
             json_get_int(json_get(&root,
                 "explicit_non_chain_command_count")) == 35 &&
             strcmp(json_get_str(json_get(&root,
                         "checked_in_proof_source")),
                    "docs/work/transaction-lab-events.jsonl") == 0 &&
             strcmp(json_get_str(json_get(&root, "live_proof_source")),
                    "private_local_notebook") == 0 &&
             strcmp(json_get_str(json_get(&root,
                         "funded_experiment_history_policy")),
                    "private_local_only_never_git") == 0;
        const struct json_value *transparent =
            api_test_find_str_field(types, "id", "transparent_t_to_t");
        const struct json_value *mixed =
            api_test_find_str_field(types, "id", "sapling_mixed_recipient");
        const struct json_value *multisig = api_test_find_str_field(
            types, "id", "transparent_p2sh_multisig_spend");
        const struct json_value *coinbase =
            api_test_find_str_field(types, "id", "coinbase_reward");
        const struct json_value *store =
            api_test_find_str_field(types, "id", "store_shielded_payment");
        const struct json_value *store_transparent =
            api_test_find_str_field(types, "id",
                                    "store_transparent_payment");
        const struct json_value *market =
            api_test_find_str_field(types, "id", "market_purchase");
        const struct json_value *yardsale =
            api_test_find_str_field(types, "id", "yardsale_atomic_purchase");
        const struct json_value *znam =
            api_test_find_str_field(types, "id", "znam_register");
        const struct json_value *zanc =
            api_test_find_str_field(types, "id", "zanc_epoch_anchor");
        const struct json_value *zanc_digest =
            api_test_find_str_field(types, "id", "zanc_digest_anchor");
        const struct json_value *zdir_register =
            api_test_find_str_field(types, "id", "zdir_register");
        const struct json_value *zdir_deregister =
            api_test_find_str_field(types, "id", "zdir_deregister");
        const struct json_value *zid_anchor =
            api_test_find_str_field(types, "id", "zid_anchor");
        const struct json_value *zid_rotate =
            api_test_find_str_field(types, "id", "zid_rotate");
        const struct json_value *zid_revoke =
            api_test_find_str_field(types, "id", "zid_revoke");
        const struct json_value *blog =
            api_test_find_str_field(types, "id", "blog_anchor");
        const struct json_value *zpay_type =
            api_test_find_str_field(types, "id", "zpay_memo_envelope");
        ok = ok && transparent && zanc_digest &&
             strcmp(json_get_str(json_get(transparent, "builder_command")),
                    "vault.intent.plan") == 0 &&
             strcmp(json_get_str(json_get(transparent, "proof_level")),
                    "simnet_confirmed") == 0;
        ok = ok && mixed &&
             strcmp(json_get_str(json_get(mixed, "builder_command")),
                    "vault.intent.plan") == 0 &&
             strcmp(json_get_str(json_get(mixed, "proof_level")),
                    "simnet_confirmed") == 0;
        ok = ok && multisig &&
             strcmp(json_get_str(json_get(multisig, "builder_command")),
                    "core.wallet.transaction.multisig.compose") == 0 &&
             strcmp(json_get_str(json_get(multisig, "proof_level")),
                    "simnet_confirmed") == 0;
        ok = ok &&
            strcmp(json_get_str(json_get(zanc_digest, "builder_command")),
                   "core.anchor.compose") == 0 &&
            strcmp(json_get_str(json_get(zanc_digest, "proof_level")),
                   "simnet_confirmed") == 0;
        ok = ok && coinbase &&
             strcmp(json_get_str(json_get(coinbase, "availability")),
                    "process_only") == 0;
        ok = ok && store &&
             strcmp(json_get_str(json_get(store, "network_policy")),
                    "isolated_non_mainnet_only") == 0 &&
             strcmp(json_get_str(json_get(store, "proof_level")),
                    "simnet_confirmed") == 0;
        ok = ok && store_transparent &&
             strcmp(json_get_str(json_get(store_transparent, "proof_level")),
                    "simnet_confirmed") == 0;
        ok = ok && market &&
             strcmp(json_get_str(json_get(market, "availability")),
                    "ready") == 0 &&
             strcmp(json_get_str(json_get(market, "proof_level")),
                    "simnet_confirmed") == 0;
        ok = ok && yardsale &&
             strcmp(json_get_str(json_get(yardsale, "proof_level")),
                    "simnet_confirmed") == 0;
        ok = ok && znam &&
             strcmp(json_get_str(json_get(znam, "proof_level")),
                    "simnet_confirmed") == 0;
        ok = ok && zanc &&
             strcmp(json_get_str(json_get(zanc, "proof_level")),
                    "simnet_confirmed") == 0;
        ok = ok && zdir_register && zdir_deregister &&
             strcmp(json_get_str(json_get(zdir_register, "proof_level")),
                    "simnet_confirmed") == 0 &&
             strcmp(json_get_str(json_get(zdir_deregister, "proof_level")),
                    "simnet_confirmed") == 0;
        ok = ok && zid_anchor && zid_rotate && zid_revoke &&
             strcmp(json_get_str(json_get(zid_anchor, "proof_level")),
                    "simnet_confirmed") == 0 &&
             strcmp(json_get_str(json_get(zid_rotate, "proof_level")),
                    "simnet_confirmed") == 0 &&
             strcmp(json_get_str(json_get(zid_revoke, "proof_level")),
                    "simnet_confirmed") == 0;
        ok = ok && blog &&
             strcmp(json_get_str(json_get(blog, "availability")),
                    "contained") == 0 &&
             strcmp(json_get_str(json_get(blog, "proof_level")),
                    "simnet_confirmed") == 0 &&
             strcmp(json_get_str(json_get(blog, "builder_command")),
                    "app.blog.anchor") == 0;
        ok = ok && zpay_type &&
             strcmp(json_get_str(json_get(zpay_type, "proof_level")),
                    "simnet_confirmed") == 0 &&
             strcmp(json_get_str(json_get(zpay_type, "builder_command")),
                    "app.payments.zpay.compose") == 0;
        ok = ok && strstr(body, "private_key") == NULL &&
             strstr(body, "grant_token") == NULL &&
             strstr(body, "/home/") == NULL;
        json_free(&root);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: native transaction list fits its declared response budget... ");
    {
        const struct zcl_command_registry *registry = zcl_command_catalog();
        const struct zcl_command_spec *spec = registry ?
            zcl_command_registry_find(registry,
                                      "app.transaction-types.list", NULL) : NULL;
        struct zcl_command_context context = {
            .registry = registry,
            .granted_capabilities = ~(uint64_t)0,
            .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        };
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        char output[ZCL_COMMAND_EXTENDED_LIST_BUDGET + 1];
        enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        size_t n = spec ? zcl_command_registry_execute_json(
            registry, spec, &context, &input, false, spec->path, "normal",
            0, 0, NULL, output, sizeof(output) - 1, &exit_code) : 0;
        json_free(&input);
        output[n < sizeof(output) ? n : sizeof(output) - 1] = '\0';
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && n <= ZCL_COMMAND_EXTENDED_LIST_BUDGET &&
                  n <= (size_t)spec->budget_bytes &&
                  exit_code == ZCL_COMMAND_EXIT_OK &&
                  json_read(&root, output, n) &&
                  json_get_bool(json_get(&root, "ok")) &&
                  strcmp(json_get_str(json_get(&root, "data_schema")),
                         ZCL_TRANSACTION_TYPES_INDEX_SCHEMA) == 0;
        json_free(&root);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: native wire catalog fits its declared response budget... ");
    {
        const struct zcl_command_registry *registry = zcl_command_catalog();
        const struct zcl_command_spec *spec = registry ?
            zcl_command_registry_find(registry,
                                      "app.transaction-types.wire", NULL)
            : NULL;
        struct zcl_command_context context = {
            .registry = registry,
            .granted_capabilities = ~(uint64_t)0,
            .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        };
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        char output[ZCL_COMMAND_LIST_BUDGET + 1];
        enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        size_t n = spec ? zcl_command_registry_execute_json(
            registry, spec, &context, &input, false, spec->path, "normal",
            0, 0, NULL, output, sizeof(output) - 1, &exit_code) : 0;
        json_free(&input);
        output[n < sizeof(output) ? n : sizeof(output) - 1] = '\0';
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && n <= ZCL_COMMAND_LIST_BUDGET &&
            exit_code == ZCL_COMMAND_EXIT_OK && json_read(&root, output, n) &&
            json_get_bool(json_get(&root, "ok")) &&
            strcmp(json_get_str(json_get(&root, "data_schema")),
                   ZCL_TRANSACTION_WIRE_CATALOG_SCHEMA) == 0;
        const struct json_value *data = json_get(&root, "data");
        ok = ok && data &&
            json_get_int(json_get(data, "wire_family_count")) == 4 &&
            json_get_int(json_get(data, "script_class_count")) ==
                (int64_t)TX_NULL_DATA + 1;
        json_free(&root);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: one-call transaction guide joins exact live command contracts... ");
    {
        const struct zcl_command_registry *registry = zcl_command_catalog();
        const struct zcl_command_spec *spec = registry ?
            zcl_command_registry_find(registry,
                                      "app.transaction-types.guide", NULL)
            : NULL;
        struct zcl_command_context context = {
            .registry = registry,
            .granted_capabilities = ~(uint64_t)0,
            .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        };
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "type", "sapling_z_to_t");
        char output[ZCL_COMMAND_EXTENDED_LIST_BUDGET + 1];
        enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        size_t n = spec ? zcl_command_registry_execute_json(
            registry, spec, &context, &input, false, spec->path, "normal",
            0, 0, NULL, output, sizeof(output) - 1, &exit_code) : 0;
        json_free(&input);
        output[n < sizeof(output) ? n : sizeof(output) - 1] = 0;
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && n <= ZCL_COMMAND_EXTENDED_LIST_BUDGET &&
            n <= (size_t)spec->budget_bytes &&
            exit_code == ZCL_COMMAND_EXIT_OK && json_read(&root, output, n) &&
            json_get_bool(json_get(&root, "ok"));
        const struct json_value *data = json_get(&root, "data");
        const struct json_value *type = data ?
            json_get(data, "transaction_type") : NULL;
        const struct json_value *contracts = data ?
            json_get(data, "command_contracts") : NULL;
        const struct json_value *builder = contracts ?
            api_test_find_str_field(contracts, "role", "builder") : NULL;
        const struct json_value *submit = contracts ?
            api_test_find_str_field(contracts, "role", "submit") : NULL;
        const struct json_value *inspect = contracts ?
            api_test_find_str_field(contracts, "role", "inspect") : NULL;
        ok = ok && data && type && contracts && builder && submit && inspect &&
            strcmp(json_get_str(json_get(data, "schema")),
                   ZCL_TRANSACTION_TYPE_GUIDE_SCHEMA) == 0 &&
            strcmp(json_get_str(json_get(type, "id")), "sapling_z_to_t") == 0 &&
            json_get_bool(json_get(data, "can_execute")) &&
            json_get_bool(json_get(data, "money_snapshot_required")) &&
            json_get_bool(json_get(data, "owner_authorization_required")) &&
            json_size(contracts) == 5 &&
            strcmp(json_get_str(json_get(builder, "command")),
                   "vault.intent.plan") == 0 &&
            strcmp(json_get_str(json_get(submit, "command")),
                   "vault.intent.submit") == 0 &&
            strcmp(json_get_str(json_get(data,
                   "preferred_submission_mode")),
                   "immediate_ack_async") == 0 &&
            strcmp(json_get_str(json_get(data,
                   "preferred_submission_command")),
                   "vault.intent.submit") == 0 &&
            strcmp(json_get_str(json_get(data, "initial_reply_boundary")),
                   "durable_queue") == 0 &&
            strcmp(json_get_str(json_get(data, "operation_id_source")),
                   "plan_id") == 0 &&
            strcmp(json_get_str(json_get(data, "status_command")),
                   "vault.intent.status") == 0 &&
            strstr(json_get_str(json_get(inspect, "semantics")),
                   "SHIELDED_REQUIREMENTS_MISSING") != NULL &&
            strstr(json_get_str(json_get(inspect, "semantics")),
                   "error_code") != NULL &&
            json_size(json_get(data, "lifecycle_states")) == 9 &&
            json_get(builder, "allowed_keys") &&
            json_size(json_get(builder, "allowed_keys")) > 0 &&
            strlen(json_get_str(json_get(builder, "input_schema"))) > 0 &&
            strlen(json_get_str(json_get(builder, "example"))) > 0 &&
            strstr(output, "private_key") == NULL &&
            strstr(output, "grant_token") == NULL;
        json_free(&root);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: every transaction guide fits its declared response budget... ");
    {
        const struct zcl_command_registry *registry = zcl_command_catalog();
        const struct zcl_command_spec *spec = registry ?
            zcl_command_registry_find(registry,
                                      "app.transaction-types.guide", NULL)
            : NULL;
        struct zcl_command_context context = {
            .registry = registry,
            .granted_capabilities = ~(uint64_t)0,
            .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        };
        size_t type_count = 0;
        const struct zcl_transaction_type_contract *types =
            zcl_transaction_type_catalog(&type_count);
        bool ok = spec && types && type_count == 39 &&
                  spec->budget_bytes == ZCL_COMMAND_EXTENDED_LIST_BUDGET;
        for (size_t i = 0; ok && i < type_count; i++) {
            struct json_value input;
            struct json_value root;
            char output[ZCL_COMMAND_EXTENDED_LIST_BUDGET + 1];
            enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
            json_init(&input);
            json_set_object(&input);
            json_push_kv_str(&input, "type", types[i].id);
            size_t n = zcl_command_registry_execute_json(
                registry, spec, &context, &input, false, spec->path, "normal",
                0, 0, NULL, output, sizeof(output) - 1, &exit_code);
            json_free(&input);
            output[n < sizeof(output) ? n : sizeof(output) - 1] = 0;
            json_init(&root);
            ok = n > 0 && n <= (size_t)spec->budget_bytes &&
                 exit_code == ZCL_COMMAND_EXIT_OK &&
                 json_read(&root, output, n) &&
                 json_get_bool(json_get(&root, "ok"));
            const struct json_value *data = json_get(&root, "data");
            const struct json_value *type = data ?
                json_get(data, "transaction_type") : NULL;
            ok = ok && type &&
                 strcmp(json_get_str(json_get(type, "id")), types[i].id) == 0;
            json_free(&root);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: reverse command lookup is mapped, routed, or fail-closed unclassified... ");
    {
        const struct zcl_command_registry *registry = zcl_command_catalog();
        const struct zcl_command_spec *spec = registry ?
            zcl_command_registry_find(registry,
                                      "app.transaction-types.command", NULL)
            : NULL;
        struct zcl_command_context context = {
            .registry = registry,
            .granted_capabilities = ~(uint64_t)0,
            .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        };
        char output[ZCL_COMMAND_LIST_BUDGET + 1];
        enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        struct json_value input;
        struct json_value root;
        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "path", "core.wallet.transaction.send");
        size_t n = spec ? zcl_command_registry_execute_json(
            registry, spec, &context, &input, false, spec->path, "normal",
            0, 0, NULL, output, sizeof(output) - 1, &exit_code) : 0;
        json_free(&input);
        output[n < sizeof(output) ? n : sizeof(output) - 1] = 0;
        json_init(&root);
        bool ok = n > 0 && n <= ZCL_COMMAND_LIST_BUDGET &&
            exit_code == ZCL_COMMAND_EXIT_OK && json_read(&root, output, n) &&
            json_get_bool(json_get(&root, "ok"));
        const struct json_value *data = json_get(&root, "data");
        const struct json_value *mappings = data ?
            json_get(data, "transaction_types") : NULL;
        const struct json_value *transparent = mappings ?
            api_test_find_str_field(mappings, "type", "transparent_t_to_t")
            : NULL;
        ok = ok && data && mappings && transparent &&
            strcmp(json_get_str(json_get(data, "schema")),
                   ZCL_TRANSACTION_COMMAND_SCHEMA) == 0 &&
            strcmp(json_get_str(json_get(data, "catalog_status")),
                   "mapped") == 0 &&
            json_get_int(json_get(data, "transaction_type_count")) == 5 &&
            json_get_bool(json_get(data, "may_prepare_chain_material")) &&
            json_get_bool(json_get(data, "may_sign_or_submit")) &&
            api_test_array_has_str(json_get(transparent, "roles"),
                                   "component") &&
            !api_test_array_has_str(json_get(transparent, "roles"),
                                    "builder") &&
            !api_test_array_has_str(json_get(transparent, "roles"),
                                    "commit") &&
            strcmp(json_get_str(json_get(
                       json_get(transparent, "guide_input"), "type")),
                   "transparent_t_to_t") == 0 &&
            !json_get_bool(json_get(transparent, "alternate_route"));
        json_free(&root);

        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "path", "vault.send");
        exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        n = spec ? zcl_command_registry_execute_json(
            registry, spec, &context, &input, false, spec->path, "normal",
            0, 0, NULL, output, sizeof(output) - 1, &exit_code) : 0;
        json_free(&input);
        output[n < sizeof(output) ? n : sizeof(output) - 1] = 0;
        json_init(&root);
        ok = ok && n > 0 && exit_code == ZCL_COMMAND_EXIT_OK &&
             json_read(&root, output, n);
        data = json_get(&root, "data");
        mappings = data ? json_get(data, "transaction_types") : NULL;
        transparent = mappings ?
            api_test_find_str_field(mappings, "type", "transparent_t_to_t")
            : NULL;
        ok = ok && data && transparent &&
            json_get_int(json_get(data, "transaction_type_count")) == 1 &&
            api_test_array_has_str(json_get(transparent, "roles"), "route") &&
            json_get_bool(json_get(transparent, "alternate_route"));
        json_free(&root);

        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "path", "core.wallet.address.new");
        exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        n = spec ? zcl_command_registry_execute_json(
            registry, spec, &context, &input, false, spec->path, "normal",
            0, 0, NULL, output, sizeof(output) - 1, &exit_code) : 0;
        json_free(&input);
        output[n < sizeof(output) ? n : sizeof(output) - 1] = 0;
        json_init(&root);
        ok = ok && n > 0 && exit_code == ZCL_COMMAND_EXIT_OK &&
             json_read(&root, output, n);
        data = json_get(&root, "data");
        ok = ok && data &&
            strcmp(json_get_str(json_get(data, "catalog_status")),
                   "explicitly_non_chain") == 0 &&
            json_get_bool(json_get(data, "explicitly_non_chain")) &&
            !json_get_bool(json_get(data,
                                    "unmapped_is_not_off_chain_proof")) &&
            strcmp(json_get_str(json_get(data, "non_chain_category")),
                   "wallet_key_management") == 0 &&
            json_get_int(json_get(data, "transaction_type_count")) == 0 &&
            strstr(output, "private_key") == NULL &&
            strstr(output, "grant_token") == NULL;
        json_free(&root);

        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "path", "app.qr.show");
        exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        n = spec ? zcl_command_registry_execute_json(
            registry, spec, &context, &input, false, spec->path, "normal",
            0, 0, NULL, output, sizeof(output) - 1, &exit_code) : 0;
        json_free(&input);
        output[n < sizeof(output) ? n : sizeof(output) - 1] = 0;
        json_init(&root);
        ok = ok && n > 0 && exit_code == ZCL_COMMAND_EXIT_OK &&
             json_read(&root, output, n);
        data = json_get(&root, "data");
        ok = ok && data &&
            strcmp(json_get_str(json_get(data, "catalog_status")),
                   "explicitly_non_chain") == 0 &&
            !json_get_bool(json_get(data,
                                    "unmapped_is_not_off_chain_proof")) &&
            json_get_bool(json_get(data, "explicitly_non_chain")) &&
            strcmp(json_get_str(json_get(data, "non_chain_category")),
                   "local_presentation") == 0;
        json_free(&root);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: transaction type member is exact and unknown ids 404... ");
    {
        static uint8_t response[262144];
        size_t n = api_handle_request(
            "GET", "/api/v1/transaction-types/zcode_release_anchor",
            NULL, 0, response, sizeof(response));
        const char *body = api_test_body(response, n, sizeof(response));
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          ZCL_TRANSACTION_TYPE_SCHEMA) == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "id")),
                          "zcode_release_anchor") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "chain_encoding")),
                          "op_return_zanc_zcode_domain_root") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "proof_level")),
                          "simnet_confirmed") == 0;
        ok = ok && api_test_array_has_str(json_get(&root,
                                                    "component_commands"),
                                           "zcode.release.prove");
        ok = ok && strcmp(json_get_str(json_get(&root, "evidence_status")),
                          "demonstrated") == 0;
        ok = ok && !json_get_bool(json_get(&root,
                                           "mainnet_live_proven"));
        json_free(&root);

        n = api_handle_request(
            "GET", "/api/v1/transaction-types/blog_anchor",
            NULL, 0, response, sizeof(response));
        body = api_test_body(response, n, sizeof(response));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok &&
             strcmp(json_get_str(json_get(&root, "availability")),
                    "contained") == 0 &&
             strcmp(json_get_str(json_get(&root, "proof_level")),
                    "simnet_confirmed") == 0 &&
             strcmp(json_get_str(json_get(&root, "builder_command")),
                    "app.blog.anchor") == 0 &&
             api_test_array_has_str(
                 json_get(&root, "supplemental_test_groups"),
                 "test_native_api_contract") &&
             api_test_array_has_str(
                 json_get(&root, "supplemental_test_groups"),
                 "test_simnet") &&
             api_test_array_has_str(
                 json_get(&root, "supplemental_test_groups"),
                 "test_transaction_intent");
        json_free(&root);

        n = api_handle_request(
            "GET", "/api/v1/transaction-types/market_purchase",
            NULL, 0, response, sizeof(response));
        body = api_test_body(response, n, sizeof(response));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "evidence_status")),
                          "demonstrated") == 0 &&
             strcmp(json_get_str(json_get(&root, "proof_level")),
                    "simnet_confirmed") == 0 &&
             !json_get_bool(json_get(&root, "mainnet_live_proven"));
        json_free(&root);

        n = api_handle_request(
            "GET", "/api/v1/transaction-types/htlc_redeem",
            NULL, 0, response, sizeof(response));
        body = api_test_body(response, n, sizeof(response));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok &&
             strcmp(json_get_str(json_get(&root, "proof_level")),
                    "simnet_confirmed") == 0 &&
             strcmp(json_get_str(json_get(&root, "test_group")),
                    "test_swap_settlement") == 0 &&
             api_test_array_has_str(
                 json_get(&root, "supplemental_test_groups"),
                 "test_simnet_contract");
        json_free(&root);

        n = api_handle_request("GET",
                               "/api/v1/transaction-types/not_real",
                               NULL, 0, response, sizeof(response));
        response[n < sizeof(response) ? n : sizeof(response) - 1] = '\0';
        ok = ok && strstr((char *)response,
                          "HTTP/1.1 404 Not Found") != NULL;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
