/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: --resolve-proof of the test-group list: validate plan IDs against
 *          the registry, expand a legacy ID to its substring union, and fold
 *          a complete shard set into its umbrella
 *          (tools/dev/test_group_umbrellas.def). The declaration grammar is
 *          deliberately narrow: C-string escapes and POSIX locale classes are
 *          refused, because decoding either here could disagree with
 *          platform_glob_match's byte-wise grammar. */

#include "test_group_list_int.h"

#include "base/safe_alloc.h"

#include "platform/glob_match.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define UM_ROW_MAX 8192
#define UM_PATTERN_MAX 4096

struct um_decl {
    char *id;
    char *glob;
};

struct um_parse {
    bool comment;
    char row[UM_ROW_MAX + 2];
    size_t rowlen;
    struct um_decl *decl;
    size_t n;
};

/* Drops C comments (which may span lines) and // tails outside quotes. */
static void um_uncomment(struct um_parse *p, const char *line, char *out)
{
    bool quoted = false;
    size_t o = 0;
    for (size_t i = 0; line[i]; i++) {
        if (p->comment) {
            if (line[i] == '*' && line[i + 1] == '/') {
                p->comment = false;
                i++;
            }
        } else if (!quoted && line[i] == '/' && line[i + 1] == '*') {
            p->comment = true;
            i++;
            out[o++] = ' ';
        } else if (!quoted && line[i] == '/' && line[i + 1] == '/') {
            break;
        } else {
            out[o++] = line[i];
            if (line[i] == '"')
                quoted = !quoted;
        }
    }
    out[o] = '\0';
}

/* [start, end) holds optional blanks around exactly the text `want`. */
static bool um_field_is(const char *start, const char *end, const char *want)
{
    size_t n = strlen(want);
    while (start < end && isspace((unsigned char)*start))
        start++;
    while (end > start && isspace((unsigned char)end[-1]))
        end--;
    return (size_t)(end - start) == n && memcmp(start, want, n) == 0;
}

/* fields[1]: ZCL_TEST_GROUP_UMBRELLA blanks ( blanks */
static bool um_head_ok(const char *start, const char *end)
{
    static const char name[] = "ZCL_TEST_GROUP_UMBRELLA";
    size_t n = sizeof(name) - 1;
    while (start < end && isspace((unsigned char)*start))
        start++;
    if ((size_t)(end - start) < n + 1 || memcmp(start, name, n) != 0)
        return false;
    start += n;
    while (start < end && isspace((unsigned char)*start))
        start++;
    return um_field_is(start, end, "(");
}

static bool um_pattern_ok(const char *g, size_t len)
{
    if (len == 0 || len > UM_PATTERN_MAX)
        return false;
    for (size_t i = 0; i < len; i++)
        if (!tgl_ident_char((unsigned char)g[i]) &&
            !strchr("*?[]!^-", g[i]))
            return false;
    for (size_t i = 0; i + 1 < len; i++)
        if (g[i] == '[' && (g[i + 1] == ':' || g[i + 1] == '.' ||
                            g[i + 1] == '='))
            return false;
    return true;
}

static bool um_id_ok(const char *id, size_t len)
{
    if (len == 0)
        return false;
    for (size_t i = 0; i < len; i++)
        if (!tgl_ident_char((unsigned char)id[i]))
            return false;
    return true;
}

static bool um_seen(const struct um_parse *p, const char *id, size_t len)
{
    for (size_t i = 0; i < p->n; i++)
        if (strlen(p->decl[i].id) == len && memcmp(p->decl[i].id, id, len) == 0)
            return true;
    return false;
}

static bool um_add(struct um_parse *p, const char *id, size_t il,
                   const char *g, size_t gl)
{
    struct um_decl *bigger = zcl_realloc(p->decl, (p->n + 1) * sizeof(*p->decl), "tgl_decl");
    if (!bigger)
        return false;
    p->decl = bigger;
    p->decl[p->n].id = strndup(id, il);
    p->decl[p->n].glob = strndup(g, gl);
    if (!p->decl[p->n].id || !p->decl[p->n].glob)
        return false;
    p->n++;
    return true;
}

/* The text around the two quoted strings: head, id, comma and tail. */
static bool um_punctuation_ok(const char *row, const char *const q[5])
{
    return um_head_ok(row, q[0]) &&
           um_id_ok(q[0] + 1, (size_t)(q[1] - q[0] - 1)) &&
           um_field_is(q[1] + 1, q[2], ",") &&
           um_field_is(q[3] + 1, q[4], ")");
}

/* One accumulated declaration (it ended with a ')'): four quotes exactly. */
static bool um_declaration(struct um_parse *p)
{
    const char *q[5] = {0}, *s = p->row, *end = p->row + p->rowlen;
    size_t found = 0;
    for (; *s; s++)
        if (*s == '"') {
            if (found == 4)
                return false;
            q[found++] = s;
        }
    if (found != 4)
        return false;
    q[4] = end;
    if (!um_punctuation_ok(p->row, q))
        return false;
    if (um_seen(p, q[0] + 1, (size_t)(q[1] - q[0] - 1)) ||
        !um_pattern_ok(q[2] + 1, (size_t)(q[3] - q[2] - 1)))
        return false;
    return um_add(p, q[0] + 1, (size_t)(q[1] - q[0] - 1), q[2] + 1,
                  (size_t)(q[3] - q[2] - 1));
}

/* One uncommented, non-blank line joins the pending row. */
static bool um_line(struct um_parse *p, const char *line)
{
    size_t len = strlen(line);
    if (p->rowlen + 1 + len > UM_ROW_MAX)
        return false;
    p->row[p->rowlen++] = ' ';
    memcpy(p->row + p->rowlen, line, len + 1);
    p->rowlen += len;
    if (!strchr(p->row, ')'))
        return true;
    if (!um_declaration(p))
        return false;
    p->row[0] = '\0';
    p->rowlen = 0;
    return true;
}

static void um_free(struct um_parse *p)
{
    for (size_t i = 0; i < p->n; i++) {
        free(p->decl[i].id);
        free(p->decl[i].glob);
    }
    free(p->decl);
}

static bool um_parse_file(struct tgl_ctx *c, struct um_parse *p, char *text)
{
    char **lines = NULL;
    size_t n = tgl_split_lines(text, &lines), at = 0;
    bool ok = lines != NULL;
    for (size_t i = 0; ok && i < n; i++) {
        char *clean = zcl_malloc(strlen(lines[i]) + 2, "tgl_clean");
        at = i + 1;
        if (!clean) {
            ok = false;
            break;
        }
        um_uncomment(p, lines[i], clean);
        if (!tgl_blank(clean))
            ok = um_line(p, clean);
        free(clean);
    }
    if (ok && (p->comment || !tgl_blank(p->row))) {
        ok = false;
        at = n;
    }
    if (!ok)
        fprintf(tgl_errf(c), "test-group-list: malformed or unsupported "
                "umbrella declaration at line %zu\n", at);
    free(lines);
    return ok;
}

/* True when every registered shard of the umbrella is selected (and there is
 * at least one), so the umbrella itself is subsumed. */
static bool um_subsumed(const struct tgl_ctx *c, const struct um_decl *d,
                        const struct tgl_strs *sel)
{
    size_t count = 0;
    for (size_t i = 0; i < c->reg.n; i++) {
        if (strcmp(c->reg.v[i], d->id) == 0 ||
            !platform_glob_match(d->glob, c->reg.v[i], false))
            continue;
        count++;
        if (!tgl_strs_has(sel, c->reg.v[i]))
            return false;
    }
    return count > 0;
}

static int um_fold(struct tgl_ctx *c, const struct tgl_strs *sel)
{
    struct um_parse p;
    struct tgl_strs drop = {0};
    char *text = tgl_read_file(c->src->umbrellas, NULL);
    bool ok;
    if (!text) {
        fprintf(tgl_errf(c), "test-group-list: missing umbrella source %s\n",
                c->src->umbrellas);
        return 1;
    }
    memset(&p, 0, sizeof(p));
    ok = um_parse_file(c, &p, text);
    free(text);
    for (size_t i = 0; ok && i < p.n; i++)
        if (tgl_is_registered(c, p.decl[i].id) &&
            tgl_strs_has(sel, p.decl[i].id) &&
            um_subsumed(c, &p.decl[i], sel))
            ok = tgl_strs_push(&drop, p.decl[i].id, strlen(p.decl[i].id));
    for (size_t i = 0; ok && i < sel->n; i++)
        if (!tgl_strs_has(&drop, sel->v[i]))
            fprintf(c->out, "%s\n", sel->v[i]);
    um_free(&p);
    tgl_strs_free(&drop);
    return ok ? 0 : 1;
}

/* One plan token: the exact primary must exist and the union must be
 * non-empty. Adds the union to `sel` in first-selection order. */
static bool proof_token(struct tgl_ctx *c, const char *needle,
                        struct tgl_strs *sel)
{
    size_t family = 0;
    if (!tgl_resolve_exact(c, needle, NULL))
        return false;
    for (size_t i = 0; i < c->reg.n; i++) {
        const char *cand = c->reg.v[i];
        if (!tgl_token_selects(c, needle, cand))
            continue;
        family++;
        if (!tgl_strs_has(sel, cand) &&
            !tgl_strs_push(sel, cand, strlen(cand)))
            return false;
    }
    return family > 0;
}

int tgl_resolve_proof(struct tgl_ctx *c, const struct tgl_strs *ids)
{
    struct tgl_strs sel = {0};
    int rc = 1;
    bool ok = true;
    for (size_t i = 0; ok && i < ids->n; i++)
        ok = proof_token(c, ids->v[i], &sel);
    if (ok && sel.n > 0)
        rc = um_fold(c, &sel);
    tgl_strs_free(&sel);
    return rc;
}
