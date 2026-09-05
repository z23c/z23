/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The closed vocabularies a row is written in, and the one place a name is
 * turned into a wire value or back.
 *
 * Every table here is CLOSED. That is the property the whole store rests
 * on: a subject nobody declared cannot be stored, so a number in this
 * ledger always has a unit and a meaning somebody wrote down. A denylist
 * over a growing vocabulary would be default-permit; these are allowlists,
 * and an id that is not in one is refused by name.
 *
 * The vitals half is not written here at all. It is pasted from
 * engine/composition/fleet_vitals.def, which is the one declaration of what
 * a fleet metric is, so this file cannot drift from it: there is no second
 * copy to forget to update. cognition/modules/codeindex pastes
 * lib_module_order.def the same way and for the same reason.
 */

#include "fleetledger/fleet_ledger.h"

#include <string.h>

const char *zcl_fleet_status_label(enum zcl_fleet_status s)
{
    switch (s) {
    case ZCL_FLEET_OK:                return "ok";
    case ZCL_FLEET_ARGUMENT:          return "ledger_argument";
    case ZCL_FLEET_IO:                return "ledger_io";
    case ZCL_FLEET_MALFORMED:         return "ledger_row_malformed";
    case ZCL_FLEET_KIND_UNKNOWN:      return "ledger_kind_unknown";
    case ZCL_FLEET_KIND_NOT_WRITABLE: return "ledger_kind_not_writable";
    case ZCL_FLEET_SUBJECT_UNKNOWN:   return "ledger_subject_unknown";
    case ZCL_FLEET_VITAL_UNKNOWN:     return "vital_unknown";
    case ZCL_FLEET_PAIR_UNKNOWN:      return "ledger_pair_unknown";
    case ZCL_FLEET_CHAIN_BROKEN:      return "ledger_chain_broken";
    case ZCL_FLEET_SIG_INVALID:       return "ledger_sig_invalid";
    case ZCL_FLEET_PEER_UNPAIRED:     return "ledger_peer_unpaired";
    case ZCL_FLEET_SEQUENCE:          return "ledger_sequence";
    case ZCL_FLEET_WINDOW:            return "ledger_window_exceeded";
    case ZCL_FLEET_FULL:              return "ledger_full";
    }
    return "ledger_argument";
}

/* ── kinds ───────────────────────────────────────────────────────────── */

struct kind_row {
    uint8_t value;
    const char *name;
    bool writable;
};

/* attest and reward are declared and NOT writable. Reserving their wire
 * values now costs nothing; discovering later that something else took
 * value 3 costs a migration of chains that are already signed. */
static const struct kind_row k_kinds[] = {
    { ZCL_FLEET_KIND_USAGE,  "usage",  true },
    { ZCL_FLEET_KIND_TASK,   "task",   true },
    { ZCL_FLEET_KIND_ATTEST, "attest", false },
    { ZCL_FLEET_KIND_REWARD, "reward", false },
    { ZCL_FLEET_KIND_VITALS, "vitals", true },
};

static const struct kind_row *kind_row(uint8_t kind)
{
    for (size_t i = 0; i < sizeof k_kinds / sizeof k_kinds[0]; i++)
        if (k_kinds[i].value == kind)
            return &k_kinds[i];
    return NULL;
}

const char *zcl_fleet_kind_name(uint8_t kind)
{
    const struct kind_row *row = kind_row(kind);
    return row ? row->name : NULL;
}

bool zcl_fleet_kind_from_name(const char *name, uint8_t *kind_out)
{
    if (!name || !kind_out)
        return false;
    for (size_t i = 0; i < sizeof k_kinds / sizeof k_kinds[0]; i++) {
        if (strcmp(k_kinds[i].name, name) == 0) {
            *kind_out = k_kinds[i].value;
            return true;
        }
    }
    return false;
}

bool zcl_fleet_kind_writable(uint8_t kind)
{
    const struct kind_row *row = kind_row(kind);
    return row && row->writable;
}

/* ── subjects, scoped by kind ────────────────────────────────────────── */

/* Order is identity: an index here is the subject value on the wire and in
 * every chain already written. Append, never reorder. */
static const char *const k_providers[] = {
    "claude-fable", "claude-opus", "claude-sonnet", "claude-haiku",
    "grok", "glm", "codex", "muse", "mac",
};

static const char *const k_task_subjects[] = {
    "quota", "lane", "unit", "train", "proof",
};

/* The vitals catalog, pasted from its one declaration. */
struct vital_row {
    const char *id;
    const char *unit;
    const char *agg;
    int64_t cadence_s;
    const char *why;
};

static const struct vital_row k_vitals[] = {
#define FLEET_VITAL(id_, unit_, agg_, cadence_s_, why_) \
    { id_, unit_, agg_, (int64_t)(cadence_s_), why_ },
#include "../../../composition/fleet_vitals.def"
#undef FLEET_VITAL
};

size_t zcl_fleet_vital_count(void)
{
    return sizeof k_vitals / sizeof k_vitals[0];
}

const char *zcl_fleet_vital_id(uint16_t index)
{
    return index < zcl_fleet_vital_count() ? k_vitals[index].id : NULL;
}

const char *zcl_fleet_vital_unit(uint16_t index)
{
    return index < zcl_fleet_vital_count() ? k_vitals[index].unit : NULL;
}

const char *zcl_fleet_vital_agg(uint16_t index)
{
    return index < zcl_fleet_vital_count() ? k_vitals[index].agg : NULL;
}

int64_t zcl_fleet_vital_cadence_s(uint16_t index)
{
    return index < zcl_fleet_vital_count() ? k_vitals[index].cadence_s : -1;
}

static bool subject_table(uint8_t kind, const char *const **table_out,
                          size_t *count_out)
{
    switch (kind) {
    case ZCL_FLEET_KIND_USAGE:
        *table_out = k_providers;
        *count_out = sizeof k_providers / sizeof k_providers[0];
        return true;
    case ZCL_FLEET_KIND_TASK:
        *table_out = k_task_subjects;
        *count_out = sizeof k_task_subjects / sizeof k_task_subjects[0];
        return true;
    default:
        return false;
    }
}

const char *zcl_fleet_subject_name(uint8_t kind, uint16_t subject)
{
    if (kind == ZCL_FLEET_KIND_VITALS)
        return zcl_fleet_vital_id(subject);
    const char *const *table = NULL;
    size_t count = 0;
    if (!subject_table(kind, &table, &count) || subject >= count)
        return NULL;
    return table[subject];
}

bool zcl_fleet_subject_from_name(uint8_t kind, const char *name,
                                 uint16_t *subject_out)
{
    if (!name || !subject_out)
        return false;
    if (kind == ZCL_FLEET_KIND_VITALS) {
        for (size_t i = 0; i < zcl_fleet_vital_count(); i++) {
            if (strcmp(k_vitals[i].id, name) == 0) {
                *subject_out = (uint16_t)i;
                return true;
            }
        }
        return false;
    }
    const char *const *table = NULL;
    size_t count = 0;
    if (!subject_table(kind, &table, &count))
        return false;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(table[i], name) == 0) {
            *subject_out = (uint16_t)i;
            return true;
        }
    }
    return false;
}

/* ── pair keys ───────────────────────────────────────────────────────── */

/* Indexed by the enum value, so slot 0 is deliberately absent: key 0 is not
 * a key, and a caller that forgot to set one gets a refusal rather than the
 * first entry in a table. */
static const char *const k_pair_names[ZCL_FLEET_PAIR_KEY_MAX + 1] = {
    NULL,
    "tokens_in", "tokens_out", "tokens_cached", "tokens_reasoning",
    "wall_ms", "turns", "tool_uses", "cost_micro_usd",
    "value", "count", "bytes", "limit",
};

const char *zcl_fleet_pair_name(uint8_t key)
{
    return key >= 1 && key <= ZCL_FLEET_PAIR_KEY_MAX ? k_pair_names[key]
                                                     : NULL;
}

bool zcl_fleet_pair_from_name(const char *name, uint8_t *key_out)
{
    if (!name || !key_out)
        return false;
    for (uint8_t k = 1; k <= ZCL_FLEET_PAIR_KEY_MAX; k++) {
        if (strcmp(k_pair_names[k], name) == 0) {
            *key_out = k;
            return true;
        }
    }
    return false;
}
