/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private facet shared by the metaverse_catalog test scenario check
 * files (test_metaverse_catalog.c and its test_metaverse_catalog_*.c
 * siblings). The MV_CHECK macro, the in-process command runner, and
 * the hex/JSON-lookup fixture helpers below are defined once in
 * test_metaverse_catalog.c; every sibling uses them through this
 * header instead of declaring its own copy. No sibling declares its
 * own file-scope mutable state. */

#ifndef TEST_METAVERSE_CATALOG_PRIV_H
#define TEST_METAVERSE_CATALOG_PRIV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "json/json.h"
#include "kernel/command_registry.h"
#include "metaverse/property_id.h"

#define MV_CHECK(name, expr) do {                                       \
    if (expr) { printf("  metaverse_catalog: %s... OK\n", (name)); }    \
    else { printf("  metaverse_catalog: %s... FAIL\n", (name));         \
           failures++; }                                                \
} while (0)

/* Shared hex-nibble table used by mv_hex32/mv_hex and directly by the
 * zcode publish fixture's own inline hex encode. A file-scope const
 * lookup table, not mutable state: each translation unit that includes
 * this header gets its own copy of the same 16 constant bytes. */
static const char k_hexd[] = "0123456789abcdef";

/* Fixture helpers, defined in test_metaverse_catalog.c and used by
 * scenarios across more than one sibling file. */
void mv_hex32(const uint8_t in[32], char out[65]);
char *mv_hex(const uint8_t *data, size_t len);

/* ── in-process command runner ─────────────────────────────────────── */

struct mv_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

void mv_cmd_init(struct mv_cmd *c);
void mv_cmd_free(struct mv_cmd *c);
const struct zcl_command_spec *mv_leaf(const char *path);
void mv_show(struct mv_cmd *c, const char *dd, const char *id_text);
void mv_list(struct mv_cmd *c, const char *dd, const char *kind);
const char *mv_str(const struct json_value *v, const char *key);
const struct json_value *mv_find_item(const struct json_value *data,
                                      const char *id_text);
const struct json_value *mv_find_kind(const struct json_value *data,
                                      const char *kind_name);
bool mv_render_begin(enum metaverse_kind kind, struct json_value *out);

/* Scenario group runners — test_metaverse_catalog.c's entry point
 * calls every one of these in order; each lives in the sibling file
 * its scenario names.
 *
 * test_metaverse_catalog_rules.c — property_id pure rules, the action
 * vocabulary, the adapter registry (every kind wired or explicitly
 * unavailable), the MVP scope decision, settlement classification,
 * work measurement, and settlement reaching the inspection surfaces. */
int t_property_id_rules(void);
int t_action_vocabulary(void);
int t_adapter_registry(void);
int t_mvp_scope_decision(void);
int t_settlement_classes(void);
int t_work_measurement(void);
int t_settlement_is_surfaced(void);

/* test_metaverse_catalog_content_and_zcode.c — the CONTENT adapter
 * against a real blob (present/incomplete/integrity-gap/absent, no
 * stale caching) and the ZCODE_PACKAGE adapter against a really
 * published release (owner/revision/grade, unearned-claim refusal). */
int t_content_adapter(void);
int t_zcode_adapter(void);

/* test_metaverse_catalog_registry_and_adapters.c — the ZNAM and ZSLP
 * adapters, the read-only contract (list must not mutate the datadir),
 * the CLI path through zcl_command_registry_input_validate, and the
 * unreadable-store disclosure. */
int t_znam_adapter(void);
int t_zslp_adapter(void);
int t_readonly_contract(void);
int t_registry_path(void);
int t_unreadable_store_is_disclosed(void);

#endif
