/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: public contract for the semantic ZCL transaction-type catalog.
 */

#ifndef ZCL_CONTROLLERS_TRANSACTION_TYPE_CATALOG_H
#define ZCL_CONTROLLERS_TRANSACTION_TYPE_CATALOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_TRANSACTION_TYPE_SCHEMA "zcl.transaction_type.v2"
#define ZCL_TRANSACTION_TYPES_INDEX_SCHEMA "zcl.transaction_types.index.v2"
#define ZCL_TRANSACTION_TYPE_GUIDE_SCHEMA "zcl.transaction_type_guide.v1"
#define ZCL_TRANSACTION_COMMAND_SCHEMA "zcl.transaction_command.v1"
#define ZCL_TRANSACTION_WIRE_CATALOG_SCHEMA \
    "zcl.transaction_wire_catalog.v1"
#define ZCL_TRANSACTION_MICRO_LAB_SCHEMA \
    "zcl.transaction_micro_lab.v1"

#define ZCL_TRANSACTION_MICRO_LAB_TARGET 100
#define ZCL_TRANSACTION_MICRO_LAB_RECIPIENT_ZAT 1000
#define ZCL_TRANSACTION_MICRO_LAB_FEE_ZAT 10000
#define ZCL_TRANSACTION_MICRO_LAB_RELAY_FLOOR_ZAT 100
#define ZCL_TRANSACTION_MICRO_LAB_SETUP_ENVELOPE_ZAT 900000
#define ZCL_TRANSACTION_MICRO_LAB_ENVELOPE_ZAT 2000000
#define ZCL_TRANSACTION_LAB_LIFETIME_CAP_ZAT 5000000
#define ZCL_TRANSACTION_LAB_RESERVE_FLOOR_ZAT 25000000

struct json_value;

/* One semantic transaction shape, not one CLI alias.  A composite row names
 * every command needed to reach its chain transaction.  This is discovery
 * data only: it grants no wallet, node, or broadcast authority. */
struct zcl_transaction_type_contract {
    const char *id;
    const char *family;
    const char *availability;
    const char *transaction_role;
    const char *chain_encoding;
    const char *privacy;
    const char *lifecycle;
    const char *builder_command;
    const char *commit_command;
    const char *inspect_command;
    const char *component_commands_csv;
    const char *network_policy;
    const char *lab_case_id;
    const char *proof_level;
    const char *test_group;
    const char *summary;
};

enum zcl_transaction_command_role {
    ZCL_TRANSACTION_COMMAND_ROLE_NONE      = 0,
    ZCL_TRANSACTION_COMMAND_ROLE_BUILDER   = 1U << 0,
    ZCL_TRANSACTION_COMMAND_ROLE_COMMIT    = 1U << 1,
    ZCL_TRANSACTION_COMMAND_ROLE_INSPECT   = 1U << 2,
    ZCL_TRANSACTION_COMMAND_ROLE_COMPONENT = 1U << 3,
    ZCL_TRANSACTION_COMMAND_ROLE_ROUTE     = 1U << 4,
    ZCL_TRANSACTION_COMMAND_ROLE_PLAN      = 1U << 5,
};

struct zcl_transaction_command_alias {
    const char *type_id;
    const char *command_path;
    enum zcl_transaction_command_role role;
    const char *explanation;
};

struct zcl_transaction_nonchain_command {
    const char *command_path;
    const char *category;
    const char *explanation;
};

struct zcl_transaction_micro_lab_profile {
    int first_slot;
    int last_slot;
    const char *type_id;
    const char *variant;
    const char *source_pool;
    const char *prerequisite;
    int64_t recipient_zat;
    int64_t fee_zat;
};

const struct zcl_transaction_type_contract *
zcl_transaction_type_catalog(size_t *count);
const struct zcl_transaction_type_contract *
zcl_transaction_type_find(const char *id);
const struct zcl_transaction_command_alias *
zcl_transaction_command_alias_catalog(size_t *count);
const struct zcl_transaction_nonchain_command *
zcl_transaction_nonchain_command_catalog(size_t *count);
const struct zcl_transaction_nonchain_command *
zcl_transaction_nonchain_command_find(const char *command_path);
uint32_t zcl_transaction_type_command_roles(
    const struct zcl_transaction_type_contract *type, const char *command_path);
const char *zcl_transaction_command_role_name(
    enum zcl_transaction_command_role role);
bool zcl_transaction_types_index_json(struct json_value *out);
bool zcl_transaction_type_show_json(const char *id, struct json_value *out);
const struct zcl_transaction_micro_lab_profile *
zcl_transaction_micro_lab_catalog(size_t *count);
const struct zcl_transaction_micro_lab_profile *
zcl_transaction_micro_lab_find_slot(int slot);
bool zcl_transaction_micro_lab_json(int slot, struct json_value *out);
/* Finite consensus wire eras and standard-policy script buckets. This is the
 * structural complement to the semantic catalog: arbitrary scripts, opaque
 * Sapling memos, and unknown/future OP_RETURN tags remain explicit buckets
 * instead of being falsely presented as an enumerable application list. */
bool zcl_transaction_wire_catalog_json(struct json_value *out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONTROLLERS_TRANSACTION_TYPE_CATALOG_H */
