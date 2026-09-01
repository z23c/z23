/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: render the bounded 100-transaction micro-lab plan as typed JSON.
 */

#include "controllers/transaction_type_catalog.h"

#include "json/json.h"

#define TX_MICRO_PROFILE(first_, last_, type_, variant_, pool_, prereq_,    \
                         recipient_, fee_)                                  \
    { .first_slot = first_, .last_slot = last_, .type_id = type_,           \
      .variant = variant_, .source_pool = pool_, .prerequisite = prereq_,   \
      .recipient_zat = recipient_, .fee_zat = fee_ },
static const struct zcl_transaction_micro_lab_profile k_micro_lab_profiles[] = {
#include "controllers/transaction_micro_lab_profiles.def"
};
#undef TX_MICRO_PROFILE

const struct zcl_transaction_micro_lab_profile *
zcl_transaction_micro_lab_catalog(size_t *count)
{
    if (count)
        *count = sizeof(k_micro_lab_profiles) / sizeof(k_micro_lab_profiles[0]);
    return k_micro_lab_profiles;
}

const struct zcl_transaction_micro_lab_profile *
zcl_transaction_micro_lab_find_slot(int slot)
{
    if (slot < 1 || slot > ZCL_TRANSACTION_MICRO_LAB_TARGET)
        return NULL;
    size_t count = 0;
    const struct zcl_transaction_micro_lab_profile *profiles =
        zcl_transaction_micro_lab_catalog(&count);
    for (size_t i = 0; i < count; i++)
        if (slot >= profiles[i].first_slot &&
            slot <= profiles[i].last_slot)
            return &profiles[i];
    return NULL;
}

static void micro_lab_profile_json(
    const struct zcl_transaction_micro_lab_profile *profile,
    struct json_value *out)
{
    json_set_object(out);
    (void)json_push_kv_int(out, "first_slot", profile->first_slot);
    (void)json_push_kv_int(out, "last_slot", profile->last_slot);
    (void)json_push_kv_int(out, "slot_count",
        profile->last_slot - profile->first_slot + 1);
    (void)json_push_kv_str(out, "transaction_type", profile->type_id);
    (void)json_push_kv_str(out, "variant", profile->variant);
    (void)json_push_kv_str(out, "source_pool", profile->source_pool);
    (void)json_push_kv_str(out, "prerequisite", profile->prerequisite);
    (void)json_push_kv_int(out, "recipient_zat", profile->recipient_zat);
    (void)json_push_kv_int(out, "fee_zat", profile->fee_zat);
}

static void micro_lab_summary_json(struct json_value *out,
                                   size_t profile_count)
{
    size_t transaction_type_count = 0;
    (void)zcl_transaction_type_catalog(&transaction_type_count);
    json_set_object(out);
    (void)json_push_kv_str(out, "schema", ZCL_TRANSACTION_MICRO_LAB_SCHEMA);
    (void)json_push_kv_str(out, "campaign_id", "mainnet-micro-100-v1");
    (void)json_push_kv_str(out, "authority",
        "compile_time_plan_only_no_wallet_plan_signature_or_broadcast_authority");
    (void)json_push_kv_int(out, "target_transaction_count",
                           ZCL_TRANSACTION_MICRO_LAB_TARGET);
    (void)json_push_kv_int(out, "campaign_transaction_type_count",
                           (int64_t)profile_count);
    (void)json_push_kv_int(out, "semantic_catalog_type_count",
                           (int64_t)transaction_type_count);
    (void)json_push_kv_int(out, "recipient_zat_each",
                           ZCL_TRANSACTION_MICRO_LAB_RECIPIENT_ZAT);
    (void)json_push_kv_int(out, "fee_zat_each",
                           ZCL_TRANSACTION_MICRO_LAB_FEE_ZAT);
    (void)json_push_kv_int(out, "relay_floor_zat",
                           ZCL_TRANSACTION_MICRO_LAB_RELAY_FLOOR_ZAT);
    (void)json_push_kv_str(out, "fee_policy",
                           "current_typed_wallet_default_exact");
    (void)json_push_kv_int(out, "planned_recipient_zat",
        ZCL_TRANSACTION_MICRO_LAB_TARGET *
        ZCL_TRANSACTION_MICRO_LAB_RECIPIENT_ZAT);
    (void)json_push_kv_int(out, "planned_fee_zat",
        ZCL_TRANSACTION_MICRO_LAB_TARGET * ZCL_TRANSACTION_MICRO_LAB_FEE_ZAT);
    (void)json_push_kv_int(out, "setup_envelope_zat",
                           ZCL_TRANSACTION_MICRO_LAB_SETUP_ENVELOPE_ZAT);
    (void)json_push_kv_int(out, "campaign_envelope_zat",
                           ZCL_TRANSACTION_MICRO_LAB_ENVELOPE_ZAT);
    (void)json_push_kv_int(out, "lifetime_lab_cap_zat",
                           ZCL_TRANSACTION_LAB_LIFETIME_CAP_ZAT);
    (void)json_push_kv_int(out, "reserve_floor_zat",
                           ZCL_TRANSACTION_LAB_RESERVE_FLOOR_ZAT);
    (void)json_push_kv_str(out, "wallet_scope_required", "dev");
    (void)json_push_kv_str(out, "execution_gate",
        "current_identity_bound_custody_and_owner_approved_exact_plan_required");
    (void)json_push_kv_str(out, "money_snapshot_command",
                           "metaverse.agent.money");
    (void)json_push_kv_str(out, "node_status_command", "status");
    (void)json_push_kv_str(out, "frontier_status_command",
                           "ops.state --subsystem=reducer_frontier");
    (void)json_push_kv_bool(out, "automatically_broadcasts", false);
    (void)json_push_kv_bool(out, "automatically_rebalances", false);
}

static void micro_lab_selected_json(
    int slot, const struct zcl_transaction_micro_lab_profile *selected,
    struct json_value *out)
{
    (void)json_push_kv_int(out, "selected_slot", slot);
    struct json_value profile;
    json_init(&profile);
    micro_lab_profile_json(selected, &profile);
    (void)json_push_kv_int(&profile, "slot", slot);
    (void)json_push_kv(out, "profile", &profile);
    json_free(&profile);
    struct json_value type;
    json_init(&type);
    (void)zcl_transaction_type_show_json(selected->type_id, &type);
    (void)json_push_kv(out, "transaction_type", &type);
    json_free(&type);
    struct json_value guide_input;
    json_init(&guide_input);
    json_set_object(&guide_input);
    (void)json_push_kv_str(&guide_input, "type", selected->type_id);
    (void)json_push_kv_str(out, "guide_command",
                           "app.transaction-types.guide");
    (void)json_push_kv(out, "guide_input", &guide_input);
    json_free(&guide_input);
    (void)json_push_kv_str(out, "agent_next_action",
        "refresh_current_custody_then_discover_guide_then_create_exact_nonbroadcast_plan");
}

bool zcl_transaction_micro_lab_json(int slot, struct json_value *out)
{
    if (!out || slot < 0 || slot > ZCL_TRANSACTION_MICRO_LAB_TARGET)
        return false;
    const struct zcl_transaction_micro_lab_profile *selected =
        slot == 0 ? NULL : zcl_transaction_micro_lab_find_slot(slot);
    if (slot != 0 && !selected)
        return false;
    size_t profile_count = 0;
    const struct zcl_transaction_micro_lab_profile *profiles =
        zcl_transaction_micro_lab_catalog(&profile_count);
    micro_lab_summary_json(out, profile_count);
    if (selected) {
        micro_lab_selected_json(slot, selected, out);
        return true;
    }
    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    for (size_t i = 0; i < profile_count; i++) {
        struct json_value item;
        json_init(&item);
        micro_lab_profile_json(&profiles[i], &item);
        (void)json_push_back(&list, &item);
        json_free(&item);
    }
    (void)json_push_kv(out, "profiles", &list);
    json_free(&list);
    (void)json_push_kv_str(out, "agent_next_action",
        "select_slot_then_refresh_current_custody_before_any_plan");
    return true;
}
