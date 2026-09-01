/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Canonical application-protocol registry for the REST/OpenAPI contract.
 * These protocols interpret or construct valid ZCL transactions; none of
 * them change consensus rules. */

#include "api_controller_internal.h"

#include "json/json.h"

#include <string.h>

static const struct api_app_protocol_contract k_api_app_protocols[] = {
    {
        .name = "zlsp",
        .status = "design",
        .layer = "zclassic23_application_layer",
        .base_layer = "zclassic_l1",
        .family = "application_protocol_framework",
        .anchor =
            "versioned services that interpret or construct valid ZCL transactions",
        .anchor_kind = "base_layer_transaction_contract",
        .rest_resource = "/api/v1/protocols",
        .read_model = "application_protocol_registry",
        .crud_capabilities_csv =
            "read_collection,read_item,construct_transaction",
        .construction_status = "protocol_framework_design",
        .mutation_authority = "versioned_controller_transaction_builder",
        .write_semantics =
            "CRUD mutations become valid ZCL transaction-construction requests",
        .consensus_boundary =
            "interprets_or_constructs_valid_zcl_transactions_only",
        .object_types_csv =
            "protocol_contract,service_contract,transaction_builder_contract",
        .ux_surfaces_csv =
            "protocol_catalog,api_discovery,agent_command_center",
        .projection_model =
            "static_registry_declares_chain_anchors_crud_and_security",
        .reorg_model =
            "protocols_must_define_rebuildable_projection_behavior",
        .crypto_model =
            "base_layer_bytes_verified_by_full_node_protocol_objects_versioned",
        .transport_model =
            "native_json_first_rest_public_read_mirror",
        .privacy_model =
            "public_catalog_no_private_wallet_material",
        .diagnostics_surface =
            "zclassic23_appprotocols_api_v1_protocols",
    },
    {
        .name = "zslp",
        .status = "active",
        .layer = "zclassic23_application_layer",
        .base_layer = "zclassic_l1",
        .family = "token",
        .anchor = "OP_RETURN token transactions",
        .anchor_kind = "op_return",
        .rest_resource = "/api/v1/zslp/tokens",
        .read_model = "zslp_projection",
        .crud_capabilities_csv = "read_collection,read_item,read_subcollection",
        .construction_status = "transaction_builders_active",
        .mutation_authority = "operator_wallet_transaction",
        .write_semantics = "construct_and_broadcast_zslp_transactions",
        .consensus_boundary =
            "interprets_or_constructs_valid_zcl_transactions_only",
        .object_types_csv = "token_genesis,token_transfer,token_mint",
        .ux_surfaces_csv = "token_explorer,asset_inventory,token_transfer_history",
        .projection_model =
            "confirmed_op_return_projection_at_served_frontier",
        .reorg_model =
            "delete_and_replay_projection_rows_from_reorg_height",
        .crypto_model =
            "transaction_hash_and_script_bytes_verified_by_zcl_consensus",
        .transport_model =
            "chain_anchored_reads_rest_native_transaction_builders_private",
        .privacy_model =
            "token_activity_is_public_chain_metadata",
        .diagnostics_surface =
            "zclassic23_appprotocols_dumpstate_zslp_projection",
    },
    {
        .name = "znam",
        .status = "active",
        .layer = "zclassic23_application_layer",
        .base_layer = "zclassic_l1",
        .family = "name_registry",
        .anchor = "OP_RETURN name registry transactions",
        .anchor_kind = "op_return",
        .rest_resource = "/api/v1/names",
        .read_model = "znam_projection",
        .crud_capabilities_csv = "read_collection,read_item,read_subcollection",
        .construction_status = "transaction_builders_active",
        .mutation_authority = "operator_wallet_transaction",
        .write_semantics = "construct_and_broadcast_znam_transactions",
        .consensus_boundary =
            "interprets_or_constructs_valid_zcl_transactions_only",
        .object_types_csv =
            "name_record,service_record,endpoint_record,text_record,revocation_record",
        .ux_surfaces_csv =
            "identity_profile,node_service_directory,onion_address_book",
        .projection_model =
            "confirmed_chain_name_projection_ordered_by_height_and_txindex",
        .reorg_model =
            "rebuild_name_state_from_confirmed_chain_after_disconnect",
        .crypto_model =
            "op_return_bytes_bound_to_txid_owner_authority_from_valid_zcl_inputs",
        .transport_model =
            "chain_records_advertise_onion_and_clearnet_endpoints_without_hosting",
        .privacy_model =
            "name_records_are_public_and_should_use_dedicated_identity_keys",
        .diagnostics_surface =
            "zclassic23_appprotocols_dumpstate_znam_projection",
    },
    {
        .name = "market",
        .status = "in_progress",
        .layer = "zclassic23_application_layer",
        .base_layer = "zclassic_l1",
        .family = "commerce",
        .anchor = "ZCL payments, ZSLP gating, and file-service manifests",
        .anchor_kind = "payment_and_manifest",
        .rest_resource = "/api/v1/market",
        .read_model = "file_market_projection",
        .crud_capabilities_csv = "read_collection,create_offer,create_purchase",
        .construction_status =
            "signed_offer_payment_authorization_paid_request_and_seller_content_active_buyer_wallet_in_progress",
        .mutation_authority = "operator_or_payment_gated",
        .write_semantics =
            "offer_and_purchase_flows_are_operator_or_payment_gated",
        .consensus_boundary =
            "interprets_or_constructs_valid_zcl_transactions_only",
        .object_types_csv =
            "signed_listing,content_descriptor,buy_intent,mirror_advertisement,payment_receipt",
        .ux_surfaces_csv =
            "storefront,listing_search,buyer_checkout,content_hosting_controls",
        .projection_model =
            "payment_and_manifest_projection_with_disposable_signed_object_cache",
        .reorg_model =
            "chain_settlement_replays_projection_signed_objects_expire_or_revalidate",
        .crypto_model =
            "listings_and_content_hashes_are_signed_hash_addressed_and_size_capped",
        .transport_model =
            "tor_reachable_storefront_direct_p2p_for_low_latency_when_verified",
        .privacy_model =
            "content_hosting_explicit_allowlist_chain_stores_commitments_not_files",
        .diagnostics_surface =
            "zclassic23_appprotocols_dumpstate_file_market_projection",
    },
    {
        .name = "messaging",
        .status = "active",
        .layer = "zclassic23_application_layer",
        .base_layer = "zclassic_l1",
        .family = "messaging",
        .anchor = "P2P messages plus active shielded Sapling memo channel",
        .anchor_kind = "p2p_and_sapling_memo",
        .rest_resource = "/api/v1/messages",
        .read_model = "message_projection",
        .crud_capabilities_csv = "read_collection,create_message",
        .construction_status = "p2p_and_sapling_memo_channels_active",
        .mutation_authority = "operator_private_message_send",
        .write_semantics =
            "send_p2p_messages_or_construct_shielded_memo_transactions",
        .consensus_boundary =
            "interprets_or_constructs_valid_zcl_transactions_only",
        .object_types_csv =
            "p2p_message,delivery_receipt,sapling_memo_message",
        .ux_surfaces_csv = "inbox,outbox,contact_thread,delivery_status",
        .projection_model =
            "message_projection_from_local_delivery_events_and_decrypted_memos",
        .reorg_model =
            "offchain_messages_are_local_state_onchain_memos_replay_by_height",
        .crypto_model =
            "onchain_messages_are_sapling_encrypted_p2p_transport_security_is_negotiated",
        .transport_model =
            "p2p_active_shielded_memo_active_tor_reachability_available",
        .privacy_model =
            "p2p_plaintext_until_v2_negotiates_onchain_content_sapling_encrypted",
        .diagnostics_surface =
            "zclassic23_appprotocols_dumpstate_message_projection",
    },
    {
        .name = "script_contracts",
        .status = "active",
        .layer = "zclassic23_application_layer",
        .base_layer = "zclassic_l1",
        .family = "script_contract",
        .anchor = "standard script contracts including HTLC atomic swaps",
        .anchor_kind = "standard_script",
        .rest_resource = "/api/v1/swaps",
        .read_model = "swap_contract_projection",
        .crud_capabilities_csv = "read_collection,read_capabilities,construct_contract",
        .construction_status = "htlc_builders_and_zcl_settlement_active",
        .mutation_authority = "operator_wallet_transaction",
        .write_semantics =
            "construct_standard_script_contract_transactions_without_consensus_changes",
        .consensus_boundary =
            "interprets_or_constructs_valid_zcl_transactions_only",
        .object_types_csv =
            "contract_template,redeem_script,refund_path,contract_state",
        .ux_surfaces_csv =
            "contract_workbench,script_preview,redeem_refund_tracker",
        .projection_model =
            "contract_projection_from_standard_script_transactions_and_status_events",
        .reorg_model =
            "replay_contract_status_from_chain_and_wallet_events",
        .crypto_model =
            "uses_only_legacy_valid_zclassic_script_hashlocks_timelocks_and_signatures",
        .transport_model =
            "operator_private_builders_public_read_status_when_safe",
        .privacy_model =
            "transparent_contract_terms_are_public_unless_settled_through_shielded_flows",
        .diagnostics_surface =
            "zclassic23_appprotocols_dumpstate_swap_contract_projection",
    },
    {
        .name = "atomic_swaps",
        .status = "in_progress",
        .layer = "zclassic23_application_layer",
        .base_layer = "zclassic_l1",
        .family = "script_contract",
        .anchor = "standard script HTLC transactions",
        .anchor_kind = "standard_script",
        .rest_resource = "/api/v1/swaps",
        .read_model = "swap_contract_projection",
        .crud_capabilities_csv = "read_collection,read_capabilities,construct_htlc",
        .construction_status =
            "zcl_builders_and_settlement_active_external_legs_operator_managed",
        .mutation_authority = "operator_wallet_transaction",
        .write_semantics =
            "construct_script_contract_transactions_without_consensus_changes",
        .consensus_boundary =
            "interprets_or_constructs_valid_zcl_transactions_only",
        .object_types_csv =
            "htlc_contract,secret_hash,redeem_transaction,refund_transaction,settlement_state",
        .ux_surfaces_csv =
            "swap_workbench,counterparty_offer,settlement_tracker",
        .projection_model =
            "swap_projection_from_standard_script_transactions_and_wallet_events",
        .reorg_model =
            "replay_swap_state_from_confirmed_chain_with_mempool_status_advisory_only",
        .crypto_model =
            "hashlock_timelock_contracts_use_existing_zclassic_script_consensus",
        .transport_model =
            "p2p_or_tor_offer_exchange_with_chain_settlement",
        .privacy_model =
            "counterparty_metadata_local_confirmed_script_state_public",
        .diagnostics_surface =
            "zclassic23_appprotocols_dumpstate_swap_contract_projection",
    },
};

static size_t api_app_protocol_count(void)
{
    return sizeof(k_api_app_protocols) / sizeof(k_api_app_protocols[0]);
}

const struct api_app_protocol_contract *
api_app_protocol_lookup(const char *name)
{
    if (!name || !name[0])
        return NULL;

    for (size_t i = 0; i < api_app_protocol_count(); i++) {
        const struct api_app_protocol_contract *p = &k_api_app_protocols[i];
        if (strcmp(p->name, name) == 0)
            return p;
    }
    return NULL;
}

const struct api_app_protocol_contract *
api_app_protocol_for_resource(const char *resource)
{
    if (!resource || !resource[0])
        return NULL;

    if (strncmp(resource, "zslp_", 5) == 0)
        return api_app_protocol_lookup("zslp");
    if (strcmp(resource, "protocols") == 0)
        return api_app_protocol_lookup("zlsp");
    if (strcmp(resource, "names") == 0)
        return api_app_protocol_lookup("znam");
    if (strcmp(resource, "market") == 0 ||
        strcmp(resource, "files") == 0 ||
        strcmp(resource, "file_services") == 0)
        return api_app_protocol_lookup("market");
    if (strcmp(resource, "messages") == 0)
        return api_app_protocol_lookup("messaging");
    if (strcmp(resource, "swaps") == 0)
        return api_app_protocol_lookup("script_contracts");

    return NULL;
}

static void api_app_protocol_set_json(
    struct json_value *obj,
    const struct api_app_protocol_contract *p)
{
    if (!obj || !p)
        return;

    json_set_object(obj);
    json_push_kv_str(obj, "schema", ZCL_APP_PROTOCOL_CONTRACT_SCHEMA);
    json_push_kv_str(obj, "name", p->name);
    json_push_kv_str(obj, "status", p->status);
    json_push_kv_str(obj, "layer", p->layer);
    json_push_kv_str(obj, "base_layer", p->base_layer);
    json_push_kv_str(obj, "family", p->family);
    json_push_kv_str(obj, "anchor", p->anchor);
    json_push_kv_str(obj, "anchor_kind", p->anchor_kind);
    json_push_kv_str(obj, "rest_resource", p->rest_resource);
    json_push_kv_str(obj, "read_model", p->read_model);

    struct json_value crud;
    json_init(&crud);
    api_app_protocol_crud_json(p, &crud);
    json_push_kv(obj, "crud_capabilities", &crud);
    json_free(&crud);

    json_push_kv_str(obj, "construction_status",
                     p->construction_status);
    json_push_kv_str(obj, "mutation_authority", p->mutation_authority);
    json_push_kv_str(obj, "write_semantics", p->write_semantics);
    json_push_kv_str(obj, "consensus_boundary", p->consensus_boundary);

    struct json_value object_types;
    json_init(&object_types);
    api_app_protocol_csv_json(p->object_types_csv, &object_types);
    json_push_kv(obj, "object_types", &object_types);
    json_free(&object_types);

    struct json_value ux_surfaces;
    json_init(&ux_surfaces);
    api_app_protocol_csv_json(p->ux_surfaces_csv, &ux_surfaces);
    json_push_kv(obj, "ux_surfaces", &ux_surfaces);
    json_free(&ux_surfaces);

    json_push_kv_str(obj, "projection_model", p->projection_model);
    json_push_kv_str(obj, "reorg_model", p->reorg_model);
    json_push_kv_str(obj, "crypto_model", p->crypto_model);
    json_push_kv_str(obj, "transport_model", p->transport_model);
    json_push_kv_str(obj, "privacy_model", p->privacy_model);
    json_push_kv_str(obj, "diagnostics_surface", p->diagnostics_surface);
}

static void api_app_protocol_push_json(
    struct json_value *protocols,
    const struct api_app_protocol_contract *p)
{
    if (!protocols || !p)
        return;

    struct json_value obj;
    json_init(&obj);
    api_app_protocol_set_json(&obj, p);
    json_push_back(protocols, &obj);
    json_free(&obj);
}

void api_app_protocol_csv_json(const char *csv, struct json_value *out)
{
    if (!out)
        return;

    json_set_array(out);
    if (!csv || !csv[0])
        return;

    const char *cursor = csv;
    while (*cursor) {
        while (*cursor == ',' || *cursor == ' ')
            cursor++;
        const char *start = cursor;
        while (*cursor && *cursor != ',')
            cursor++;

        size_t len = (size_t)(cursor - start);
        while (len > 0 && start[len - 1] == ' ')
            len--;
        if (len > 0) {
            char item_buf[64];
            if (len >= sizeof(item_buf))
                len = sizeof(item_buf) - 1;
            memcpy(item_buf, start, len);
            item_buf[len] = '\0';

            struct json_value item;
            json_init(&item);
            json_set_str(&item, item_buf);
            json_push_back(out, &item);
            json_free(&item);
        }
        if (*cursor == ',')
            cursor++;
    }
}

void api_app_protocol_crud_json(const struct api_app_protocol_contract *p,
                                struct json_value *crud)
{
    api_app_protocol_csv_json(p ? p->crud_capabilities_csv : NULL, crud);
}

void api_app_protocols_json(struct json_value *protocols)
{
    if (!protocols)
        return;

    json_set_array(protocols);
    for (size_t i = 0; i < api_app_protocol_count(); i++)
        api_app_protocol_push_json(protocols, &k_api_app_protocols[i]);
}

bool api_app_protocols_index_json(struct json_value *out)
{
    if (!out)
        return false;

    json_set_object(out);
    json_push_kv_str(out, "schema", ZCL_APP_PROTOCOLS_INDEX_SCHEMA);
    json_push_kv_str(out, "base_layer", "zclassic_l1");
    json_push_kv_str(out, "service_layer", "zclassic23_application_layer");
    json_push_kv_str(out, "consensus_boundary",
                     "overlay protocols interpret or construct valid ZCL "
                     "transactions without changing consensus rules");

    struct json_value protocols;
    json_init(&protocols);
    api_app_protocols_json(&protocols);
    json_push_kv(out, "protocols", &protocols);
    json_push_kv_int(out, "protocol_count", (int64_t)json_size(&protocols));
    json_free(&protocols);
    return true;
}

bool api_app_protocol_show_json(const char *name, struct json_value *out)
{
    if (!out)
        return false;
    const struct api_app_protocol_contract *p =
        api_app_protocol_lookup(name);
    if (!p)
        return false;

    api_app_protocol_set_json(out, p);
    return true;
}

void api_app_protocol_push_openapi_extensions(
    const struct json_value *contract,
    struct json_value *operation)
{
    if (!contract || !operation)
        return;

    const char *application_protocol =
        json_get_str(json_get(contract, "application_protocol"));
    const char *layer = json_get_str(json_get(contract, "layer"));
    const char *base_layer = json_get_str(json_get(contract, "base_layer"));
    const char *protocol_family =
        json_get_str(json_get(contract, "protocol_family"));
    const char *source_anchor =
        json_get_str(json_get(contract, "source_anchor"));
    const char *anchor_kind =
        json_get_str(json_get(contract, "protocol_anchor_kind"));
    const char *read_model =
        json_get_str(json_get(contract, "read_model"));
    const char *construction_status =
        json_get_str(json_get(contract, "protocol_construction_status"));
    const char *mutation_authority =
        json_get_str(json_get(contract, "mutation_authority"));
    const char *write_semantics =
        json_get_str(json_get(contract, "write_semantics"));
    const char *consensus_boundary =
        json_get_str(json_get(contract, "consensus_boundary"));
    const char *projection_model =
        json_get_str(json_get(contract, "projection_model"));
    const char *reorg_model =
        json_get_str(json_get(contract, "reorg_model"));
    const char *crypto_model =
        json_get_str(json_get(contract, "crypto_model"));
    const char *transport_model =
        json_get_str(json_get(contract, "transport_model"));
    const char *privacy_model =
        json_get_str(json_get(contract, "privacy_model"));
    const char *diagnostics_surface =
        json_get_str(json_get(contract, "diagnostics_surface"));

    if (layer && layer[0])
        json_push_kv_str(operation, "x-zcl-layer", layer);
    if (base_layer && base_layer[0])
        json_push_kv_str(operation, "x-zcl-base-layer", base_layer);
    if (application_protocol && application_protocol[0])
        json_push_kv_str(operation, "x-zcl-application-protocol",
                         application_protocol);
    if (protocol_family && protocol_family[0])
        json_push_kv_str(operation, "x-zcl-protocol-family",
                         protocol_family);
    if (source_anchor && source_anchor[0])
        json_push_kv_str(operation, "x-zcl-source-anchor", source_anchor);
    if (anchor_kind && anchor_kind[0])
        json_push_kv_str(operation, "x-zcl-protocol-anchor-kind",
                         anchor_kind);
    if (read_model && read_model[0])
        json_push_kv_str(operation, "x-zcl-read-model", read_model);
    const struct json_value *crud = json_get(contract, "protocol_crud");
    if (crud)
        json_push_kv(operation, "x-zcl-protocol-crud", crud);
    const struct json_value *object_types =
        json_get(contract, "protocol_object_types");
    if (object_types)
        json_push_kv(operation, "x-zcl-protocol-object-types",
                     object_types);
    const struct json_value *ux_surfaces =
        json_get(contract, "protocol_ux_surfaces");
    if (ux_surfaces)
        json_push_kv(operation, "x-zcl-protocol-ux-surfaces",
                     ux_surfaces);
    if (construction_status && construction_status[0])
        json_push_kv_str(operation, "x-zcl-protocol-construction-status",
                         construction_status);
    if (mutation_authority && mutation_authority[0])
        json_push_kv_str(operation, "x-zcl-mutation-authority",
                         mutation_authority);
    if (write_semantics && write_semantics[0])
        json_push_kv_str(operation, "x-zcl-write-semantics",
                         write_semantics);
    if (consensus_boundary && consensus_boundary[0])
        json_push_kv_str(operation, "x-zcl-consensus-boundary",
                         consensus_boundary);
    if (projection_model && projection_model[0])
        json_push_kv_str(operation, "x-zcl-projection-model",
                         projection_model);
    if (reorg_model && reorg_model[0])
        json_push_kv_str(operation, "x-zcl-reorg-model", reorg_model);
    if (crypto_model && crypto_model[0])
        json_push_kv_str(operation, "x-zcl-crypto-model", crypto_model);
    if (transport_model && transport_model[0])
        json_push_kv_str(operation, "x-zcl-transport-model",
                         transport_model);
    if (privacy_model && privacy_model[0])
        json_push_kv_str(operation, "x-zcl-privacy-model", privacy_model);
    if (diagnostics_surface && diagnostics_surface[0])
        json_push_kv_str(operation, "x-zcl-diagnostics-surface",
                         diagnostics_surface);
}
