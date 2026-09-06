/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The trigger registry, pasted once from its one declaration
 * (engine/composition/triggers.def), plus the name<->enum tables the
 * evaluator and CLI both read. */

#include "command/native_fleet_triggers.h"

#include <string.h>

struct zcl_trigger_named_source {
    const char *name;
    enum zcl_trigger_source value;
};

static const struct zcl_trigger_named_source k_sources[] = {
    { "landing_outcomes", ZCL_TRIGGER_SOURCE_LANDING },
    { "board_rows", ZCL_TRIGGER_SOURCE_BOARD },
    { "experiment_rows", ZCL_TRIGGER_SOURCE_EXPERIMENT },
};

struct zcl_trigger_named_op {
    const char *name;
    enum zcl_trigger_op value;
};

static const struct zcl_trigger_named_op k_ops[] = {
    { "eq", ZCL_TRIGGER_OP_EQ },
    { "ne", ZCL_TRIGGER_OP_NE },
    { "prefix", ZCL_TRIGGER_OP_PREFIX },
    { "contains", ZCL_TRIGGER_OP_CONTAINS },
};

struct zcl_trigger_named_action {
    const char *name;
    enum zcl_trigger_action value;
};

static const struct zcl_trigger_named_action k_actions[] = {
    { "print", ZCL_TRIGGER_ACTION_PRINT },
    { "ledger", ZCL_TRIGGER_ACTION_LEDGER },
};

static enum zcl_trigger_source trg_source_value(const char *name)
{
    for (size_t i = 0; i < sizeof k_sources / sizeof k_sources[0]; i++)
        if (strcmp(k_sources[i].name, name) == 0)
            return k_sources[i].value;
    return ZCL_TRIGGER_SOURCE_LANDING;
}

static enum zcl_trigger_op trg_op_value(const char *name)
{
    for (size_t i = 0; i < sizeof k_ops / sizeof k_ops[0]; i++)
        if (strcmp(k_ops[i].name, name) == 0)
            return k_ops[i].value;
    return ZCL_TRIGGER_OP_EQ;
}

static enum zcl_trigger_action trg_action_value(const char *name)
{
    for (size_t i = 0; i < sizeof k_actions / sizeof k_actions[0]; i++)
        if (strcmp(k_actions[i].name, name) == 0)
            return k_actions[i].value;
    return ZCL_TRIGGER_ACTION_PRINT;
}

struct zcl_trigger_literal {
    const char *id;
    const char *source_name;
    const char *field;
    const char *op_name;
    const char *value;
    const char *action_name;
    const char *why;
};

static const struct zcl_trigger_literal k_literals[] = {
#define Z23_TRIGGER(id_, source_, field_, op_, value_, action_, why_) \
    { id_, source_, field_, op_, value_, action_, why_ },
#include "../../engine/composition/triggers.def"
#undef Z23_TRIGGER
};

enum { ZCL_TRIGGER_COUNT = sizeof k_literals / sizeof k_literals[0] };

static struct zcl_trigger_row g_rows[ZCL_TRIGGER_COUNT];
static bool g_rows_built;

static void trg_build_rows(void)
{
    if (g_rows_built)
        return;
    for (size_t i = 0; i < ZCL_TRIGGER_COUNT; i++) {
        const struct zcl_trigger_literal *lit = &k_literals[i];
        struct zcl_trigger_row *row = &g_rows[i];
        row->id = lit->id;
        row->source = trg_source_value(lit->source_name);
        row->source_name = lit->source_name;
        row->field = lit->field;
        row->op = trg_op_value(lit->op_name);
        row->op_name = lit->op_name;
        row->value = lit->value;
        row->action = trg_action_value(lit->action_name);
        row->action_name = lit->action_name;
        row->why = lit->why;
    }
    g_rows_built = true;
}

size_t zcl_trigger_count(void)
{
    return ZCL_TRIGGER_COUNT;
}

const struct zcl_trigger_row *zcl_trigger_at(size_t index)
{
    if (index >= ZCL_TRIGGER_COUNT)
        return NULL;
    trg_build_rows();
    return &g_rows[index];
}
