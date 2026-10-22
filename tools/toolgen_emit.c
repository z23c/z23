/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fixed generation targets and the text z23-toolgen emits into each
 *          generator-owned block. Output paths come from this table only. */

#include "toolgen.h"

#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LITERAL_WIDTH 70u

const struct tg_family tg_families[] = {
    {"fleet", "engine/composition/commands/fleet.def", "tools/command/native_fleet.h"},
};
const size_t tg_family_count = sizeof tg_families / sizeof tg_families[0];

const char tg_remote_path[] = "engine/composition/remote_command_classes.def";
static const char k_catalog_path[] = "tools/dev/test_group_catalog.def";
static const char k_datadir_path[] = "tests/harness/src/test_read_leaf_no_datadir_write.c";

size_t tg_targets(struct tg_target *out, size_t max)
{
    size_t n = 0;
    for (size_t i = 0; i < tg_family_count && n + 2u <= max; i++) {
        out[n++] = (struct tg_target){TGT_DEF, &tg_families[i], tg_families[i].def, "commands"};
        out[n++] = (struct tg_target){TGT_HEADER, &tg_families[i], tg_families[i].header, "handlers"};
    }
    if (n + 2u <= max) {
        out[n++] = (struct tg_target){TGT_CATALOG, NULL, k_catalog_path, "test-groups"};
        out[n++] = (struct tg_target){TGT_DATADIR, NULL, k_datadir_path, "datadir-leaves"};
    }
    return n;
}

bool tg_applies(const struct tg_target *t, const struct tg_manifest *m)
{
    switch (t->kind) {
    case TGT_DEF:
    case TGT_HEADER:
        return m->family == t->family;
    case TGT_DATADIR:
        return m->has_datadir;
    case TGT_CATALOG:
        return true;
    }
    return false;
}

static size_t escaped_width(char c)
{
    return (c == '"' || c == '\\') ? 2u : 1u;
}

static void put_escaped(struct tg_sb *sb, const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '"' || s[i] == '\\')
            tg_sb_putn(sb, "\\", 1);
        tg_sb_putn(sb, s + i, 1);
    }
}

static size_t chunk_end(const char *text, size_t pos, size_t len)
{
    size_t k = pos;
    size_t w = 0;
    size_t brk = pos;
    while (k < len) {
        size_t ew = escaped_width(text[k]);
        if (w + ew > LITERAL_WIDTH && brk > pos)
            return brk;
        w += ew;
        k++;
        if (text[k - 1u] == ' ' || text[k - 1u] == ',')
            brk = k;
    }
    return len;
}

/* One C string literal per output line, adjacent literals concatenate. */
static void put_literal(struct tg_sb *sb, const char *text, const char *tail)
{
    size_t len = strlen(text);
    size_t pos = 0;
    do {
        size_t end = chunk_end(text, pos, len);
        tg_sb_put(sb, "    \"");
        put_escaped(sb, text + pos, end - pos);
        tg_sb_put(sb, "\"");
        pos = end;
        if (pos < len)
            tg_sb_put(sb, "\n");
    } while (pos < len);
    tg_sb_put(sb, tail);
}

static void render_def(const struct tg_manifest *m, struct tg_sb *sb)
{
    tg_sb_printf(sb, "ZCL_COMMAND_READY_READ(\n    \"%s\", \"%s\", \"\",\n", m->path, m->parent);
    put_literal(sb, m->summary, ",\n");
    put_literal(sb, m->semantics, ",\n");
    tg_sb_printf(sb, "    %u,\n", m->budget_bytes);
    put_literal(sb, m->tags, ",\n");
    tg_sb_printf(sb, "    \"%s\", \"%s\",\n    \"%s\", \"%s\",\n", m->input_schema,
                 m->output_schema, m->input_keys, m->positional_keys);
    put_literal(sb, m->example, ",\n");
    tg_sb_put(sb, "    ZCL_COMMAND_LAYER_OPS, ZCL_COMMAND_SCOPE_LOCAL,\n");
    tg_sb_printf(sb, "    %s, %s,\n", m->authority, m->latency);
    tg_sb_printf(sb, "    %s, ZCL_COMMAND_LANE_LOCAL,\n", m->cost);
    tg_sb_printf(sb, "    %s, ZCL_COMMAND_TRAIT_IDEMPOTENT,\n", m->caps);
    tg_sb_printf(sb, "    ZCL_COMMAND_TRANSPORT_NATIVE, %s)\n", m->handler);
}

static void render_branch(const struct tg_manifest *m, struct tg_sb *sb)
{
    const char *dot = strrchr(m->parent, '.');
    size_t up = dot ? (size_t)(dot - m->parent) : 0;
    tg_sb_printf(sb, "ZCL_COMMAND_BRANCH(\"%s\", \"%.*s\",\n", m->parent, (int)up, m->parent);
    put_literal(sb, m->branch_summary, ",\n");
    tg_sb_put(sb, "    ZCL_COMMAND_LAYER_OPS)\n");
}

static void render_header(const struct tg_manifest *m, struct tg_sb *sb)
{
    tg_sb_printf(sb, "/* %s (%s) */\nvoid %s(\n", m->path, m->source, m->handler);
    tg_sb_put(sb, "    const struct zcl_command_request *request,\n");
    tg_sb_put(sb, "    struct zcl_command_reply *reply);\n");
}

static void render_datadir(const struct tg_manifest *m, struct tg_sb *sb)
{
    char head[140];
    snprintf(head, sizeof head, "\"%s\",", m->path);
    tg_sb_printf(sb, "    { %-25s %s,\n      NULL, NULL,               NULL, NULL, NULL },\n",
                 head, m->handler);
}

void tg_render_unit(const struct tg_target *t, const struct tg_manifest *m,
                    struct tg_sb *sb)
{
    switch (t->kind) {
    case TGT_DEF:
        render_def(m, sb);
        break;
    case TGT_HEADER:
        render_header(m, sb);
        break;
    case TGT_CATALOG:
        tg_sb_printf(sb, "ZCL_TEST_GROUP(%s)\n", m->test_group);
        break;
    case TGT_DATADIR:
        render_datadir(m, sb);
        break;
    }
}

static int by_group(const void *a, const void *b)
{
    const struct tg_manifest *x = *(const struct tg_manifest *const *)a;
    const struct tg_manifest *y = *(const struct tg_manifest *const *)b;
    return strcmp(x->test_group, y->test_group);
}

static bool is_group_line(const char *line, size_t len, const char *group)
{
    static const char head[] = "ZCL_TEST_GROUP(";
    size_t h = sizeof head - 1u;
    size_t g = strlen(group);
    return len == h + g + 1u && memcmp(line, head, h) == 0 &&
           memcmp(line + h, group, g) == 0 && line[len - 1u] == ')';
}

static size_t take_existing(const struct tg_manifest **ms, size_t n,
                            const struct tg_manifest **out, const char *existing,
                            size_t len)
{
    size_t placed = 0;
    for (size_t pos = 0; pos < len;) {
        const char *nl = memchr(existing + pos, '\n', len - pos);
        size_t end = nl ? (size_t)(nl - existing) : len;
        for (size_t i = 0; i < n; i++)
            if (ms[i] && is_group_line(existing + pos, end - pos, ms[i]->test_group)) {
                out[placed++] = ms[i];
                ms[i] = NULL;
                break;
            }
        pos = end + 1u;
    }
    return placed;
}

/* Rows already in the catalog keep their order; new rows follow, sorted. */
static void render_catalog(const struct tg_target *t,
                           const struct tg_manifest *const *ms, size_t n,
                           const char *existing, size_t len, struct tg_sb *sb)
{
    const struct tg_manifest **work = zcl_calloc(n ? n : 1u, sizeof *work, "toolgen.work");
    const struct tg_manifest **out = zcl_calloc(n ? n : 1u, sizeof *out, "toolgen.order");
    if (!work || !out) {
        sb->oom = true;
    } else {
        memcpy(work, ms, n * sizeof *work);
        size_t placed = take_existing(work, n, out, existing, len);
        size_t rest = placed;
        for (size_t i = 0; i < n; i++)
            if (work[i])
                out[rest++] = work[i];
        qsort(out + placed, rest - placed, sizeof *out, by_group);
        for (size_t i = 0; i < n; i++)
            tg_render_unit(t, out[i], sb);
    }
    free(work);
    free(out);
}

static size_t dot_count(const char *s)
{
    size_t n = 0;
    for (; *s; s++)
        n += *s == '.' ? 1u : 0u;
    return n;
}

/* Branch rows, shallowest first, so a parent always precedes its children. */
static size_t render_branches(const struct tg_manifest *const *ms, size_t n, struct tg_sb *sb)
{
    size_t emitted = 0;
    for (size_t depth = 0; depth < 64u; depth++)
        for (size_t i = 0; i < n; i++) {
            if (!ms[i]->has_branch || dot_count(ms[i]->parent) != depth)
                continue;
            if (emitted++)
                tg_sb_put(sb, "\n");
            render_branch(ms[i], sb);
        }
    return emitted;
}

static void render_def_body(const struct tg_target *t,
                            const struct tg_manifest *const *ms, size_t n,
                            struct tg_sb *sb)
{
    size_t branches = render_branches(ms, n, sb);
    for (size_t i = 0; i < n; i++) {
        if (branches || i)
            tg_sb_put(sb, "\n");
        tg_render_unit(t, ms[i], sb);
        branches = 0;
    }
}

void tg_render_body(const struct tg_target *t, const struct tg_manifest *const *ms,
                    size_t n, const char *existing, size_t existing_len,
                    struct tg_sb *sb)
{
    if (t->kind == TGT_DEF) {
        render_def_body(t, ms, n, sb);
        return;
    }
    if (t->kind == TGT_CATALOG) {
        render_catalog(t, ms, n, existing, existing_len, sb);
        return;
    }
    for (size_t i = 0; i < n; i++) {
        if (i && t->kind == TGT_HEADER)
            tg_sb_put(sb, "\n");
        tg_render_unit(t, ms[i], sb);
    }
}
