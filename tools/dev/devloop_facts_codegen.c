/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bound the functions of one TU whose code a compile may re-emit when some of them change, over the facts reference graph, under the optimizer the TU's compile identity names. */
#include "devloop_facts_index_priv.h"

#include "devloop.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -f flags whose transforms the facts cannot bound at any -O level. -O2 and
 * above add clones specialized by their callers (ipa-cp, ipa-sra, ipa-vrp,
 * ipa-bit-cp, ipa-cp-clone), caller-saved conventions (ipa-ra), merges of
 * unrelated identical functions (ipa-icf) and an inliner with unit-wide
 * budgets; LTO, whole-program and profile feedback decide from code or data
 * no manifest of this TU carries. Matched anywhere in the IDENTITY record
 * (not as a whitespace-delimited word: the identity's flags are the
 * clang-manifest's length-prefixed strings concatenated back to back with
 * no separator, never real command-line text), so a definition or path
 * that merely spells one, or a future -fipa-* spelling, also refuses. */
static const char *const k_fxg_unbounded[] = {
    "-flto",
    "-fwhole-program",
    "-fipa-",
    "-finline-small-functions",
    "-finline-functions",
    "-fprofile-use",
    "-fauto-profile",
    "-fprofile-sample-use",
};

/* True when the len-limited literal `lit` occurs at s[i]. */
static bool fxg_at(const uint8_t *s, size_t n, size_t i, const char *lit)
{
    size_t k = strlen(lit);
    return i + k <= n && memcmp(s + i, lit, k) == 0;
}

/* If position i names one of the unbounded -f flags, points *token at its
 * literal spelling and returns true; leaves *token untouched otherwise. */
static bool fxg_aux_unbounded_at(const uint8_t *s, size_t n, size_t i,
                                 const char **token)
{
    for (size_t k = 0;
         k < sizeof(k_fxg_unbounded) / sizeof(k_fxg_unbounded[0]); k++) {
        if (fxg_at(s, n, i, k_fxg_unbounded[k])) {
            *token = k_fxg_unbounded[k];
            return true;
        }
    }
    return false;
}

/* The value of the run of ASCII digits starting at s[i] (i < n, s[i] a
 * digit), parsed numerically with leading zeros (so "02" is 2), saturating
 * at 2: only 0, 1 and "2 or more" ever matter to the model. *end is set
 * past the last digit consumed. */
static int fxg_digits_level(const uint8_t *s, size_t n, size_t i,
                            size_t *end)
{
    int v = 0;
    while (i < n && s[i] >= '0' && s[i] <= '9') {
        v = v < 2 ? v * 10 + (s[i] - '0') : v;
        if (v > 2)
            v = 2;
        i++;
    }
    *end = i;
    return v;
}

enum fxg_opt {
    FXG_OPT_NONE = 0, /* no -O / --optimize spelling at this position */
    FXG_OPT_0,
    FXG_OPT_1,
    FXG_OPT_HIGH, /* -O2 and above, -Os/-Oz/-Ofast, or an unknown spelling */
};

/* Classifies one whole "-O..." argv token (s[0]=='-' && s[1]=='O', already
 * checked by the caller; n is the token's own length, not a position in a
 * larger buffer). A bare "-O" is -O1; -Og models like -O1; -Os, -Oz and
 * -Ofast are unbounded; digits after "-O" are read numerically (leading
 * zeros included). Anything else the token could still be -- a known
 * spelling with trailing garbage glued on ("-O1x"), or a spelling this
 * parser does not know -- is an unrecognized -O spelling and unbounded
 * too: unknown widens, it never narrows. Requiring the parsed suffix to
 * reach exactly the token's end (not just its own buffer) is what makes
 * this a whole-token match: applied only per argv element (see
 * fxi_codegen_model_of), never to a raw byte position, so an "-O" spelled
 * inside another flag's text can't be mistaken for one. */
static enum fxg_opt fxg_dash_o_token(const uint8_t *s, size_t n,
                                     const char **token)
{
    size_t p = 2, end;
    int lvl;
    if (p == n) {
        *token = "-O";
        return FXG_OPT_1;
    }
    if (s[p] >= '0' && s[p] <= '9') {
        lvl = fxg_digits_level(s, n, p, &end);
        if (end != n) {
            *token = "an unrecognized -O spelling";
            return FXG_OPT_HIGH;
        }
        if (lvl == 0) {
            *token = "-O0";
            return FXG_OPT_0;
        }
        if (lvl == 1) {
            *token = "-O1";
            return FXG_OPT_1;
        }
        *token = "-O2-or-higher";
        return FXG_OPT_HIGH;
    }
    if (s[p] == 'g' && p + 1 == n) {
        *token = "-Og";
        return FXG_OPT_1;
    }
    if ((s[p] == 's' || s[p] == 'z') && p + 1 == n) {
        *token = "-Os";
        return FXG_OPT_HIGH;
    }
    if (p + 4 == n && fxg_at(s, n, p, "fast")) {
        *token = "-Ofast";
        return FXG_OPT_HIGH;
    }
    *token = "an unrecognized -O spelling";
    return FXG_OPT_HIGH;
}

/* Classifies one whole "--optimize..." argv token (the 10-byte prefix
 * already checked by the caller): "--optimize" alone is -O1;
 * "--optimize=N" parses N the same way as -O<digits>, again requiring the
 * digits to reach the token's end; any other "--optimize..." spelling is
 * unbounded. */
static enum fxg_opt fxg_optimize_token(const uint8_t *s, size_t n,
                                       const char **token)
{
    size_t p = 10, end;
    int lvl;
    if (p == n) {
        *token = "--optimize";
        return FXG_OPT_1;
    }
    if (s[p] != '=' || p + 1 >= n || s[p + 1] < '0' || s[p + 1] > '9') {
        *token = "an unrecognized --optimize spelling";
        return FXG_OPT_HIGH;
    }
    lvl = fxg_digits_level(s, n, p + 1, &end);
    if (end != n) {
        *token = "an unrecognized --optimize spelling";
        return FXG_OPT_HIGH;
    }
    if (lvl == 0) {
        *token = "--optimize=0";
        return FXG_OPT_0;
    }
    if (lvl == 1) {
        *token = "--optimize=1";
        return FXG_OPT_1;
    }
    *token = "--optimize=N (N>=2 or unparsed)";
    return FXG_OPT_HIGH;
}

/* Dispatches one whole argv token to whichever classifier applies, or
 * FXG_OPT_NONE for a token that is neither spelling. */
static enum fxg_opt fxg_opt_of_token(const uint8_t *s, size_t n,
                                     const char **token)
{
    if (n >= 2 && s[0] == '-' && s[1] == 'O')
        return fxg_dash_o_token(s, n, token);
    if (n >= 10 && memcmp(s, "--optimize", 10) == 0)
        return fxg_optimize_token(s, n, token);
    return FXG_OPT_NONE;
}

/* Reads a little-endian u32 at *p via the canonical codec
 * (platform/modules/base/include/base/serialize_le.h: zcl_read_u32_le is
 * the one place this repository decodes a fixed-width byte-order field --
 * see tools/lint/lintc/gate_byte_order_codec_single_report.c), advancing it past the
 * 4 bytes, if that many remain before `end`; leaves *p unmoved and returns
 * false on truncation. */
static bool fxg_take_u32(const uint8_t **p, const uint8_t *end, uint32_t *v)
{
    if ((size_t)(end - *p) < 4)
        return false;
    *v = zcl_read_u32_le(*p);
    *p += 4;
    return true;
}

/* Reads one schema "T"/"Q"/"P"/"A" field of the IDENTITY record (see
 * fxi_codegen_model_of): a u32le length then that many raw,
 * non-NUL-terminated bytes at *p, advancing it past both; false (leaving
 * *p unmoved) on truncation. */
static bool fxg_take_text(const uint8_t **p, const uint8_t *end,
                          const uint8_t **s, size_t *slen)
{
    uint32_t len;
    if (!fxg_take_u32(p, end, &len) || (size_t)(end - *p) < len)
        return false;
    *s = *p;
    *slen = len;
    *p += len;
    return true;
}

/* The IDENTITY record's own schema (k_sm_schema[VCS_SEMANTIC_SECTION_V1_
 * IDENTITY] == "TQTP[A[D[D[D[e" in
 * contexts/commons/modules/vcs/src/semantic_manifest.c, written in this
 * order by cm_emit_identity in tools/sensors/clang_manifest_core.c):
 * compiler text, resource-dir path, triple text, main-path path, then a
 * u32 argc and that many argv texts ("A": the flags actually passed to
 * the compiler), then three directory lists and an env-entry list this
 * parser does not need. The unbounded -f flags above are still matched
 * anywhere in the raw record (conservative: a definition or path that
 * merely spells one also refuses), but the -O/--optimize last-wins rule
 * is applied only to these whole argv tokens, never to a raw byte
 * position: a byte scan cannot tell "-O0" the flag from "-O0" glued
 * inside -DMODE=-O0, -I/opt/x-O0dir or -Wl,-O1, so it can let text in an
 * unrelated flag's value override the real optimizer level. Walking the
 * schema instead reads each argv element as the compiler would. */
enum fxi_codegen fxi_codegen_model_of(const uint8_t *identity, size_t len,
                                      const char **token)
{
    const uint8_t *p, *end, *s;
    size_t slen;
    uint32_t argc;
    enum fxg_opt opt = FXG_OPT_NONE;
    const char *opt_token = "";
    const char *aux_token = NULL;
    *token = "";
    if (identity == NULL) {
        *token = "no identity record";
        return FXI_CODEGEN_UNBOUNDED;
    }
    for (size_t i = 0; i < len && aux_token == NULL; i++)
        fxg_aux_unbounded_at(identity, len, i, &aux_token);
    if (aux_token != NULL) {
        *token = aux_token;
        return FXI_CODEGEN_UNBOUNDED;
    }
    p = identity;
    end = identity + len;
    if (!fxg_take_text(&p, end, &s, &slen) || /* compiler */
        !fxg_take_text(&p, end, &s, &slen) || /* resource_dir */
        !fxg_take_text(&p, end, &s, &slen) || /* triple */
        !fxg_take_text(&p, end, &s, &slen) || /* main_path */
        !fxg_take_u32(&p, end, &argc)) {
        *token = "malformed identity record (argv header)";
        return FXI_CODEGEN_UNBOUNDED;
    }
    for (uint32_t i = 0; i < argc; i++) {
        const char *tk = "";
        enum fxg_opt o;
        if (!fxg_take_text(&p, end, &s, &slen)) {
            *token = "malformed identity record (argv element)";
            return FXI_CODEGEN_UNBOUNDED;
        }
        o = fxg_opt_of_token(s, slen, &tk);
        if (o != FXG_OPT_NONE) {
            opt = o; /* the LAST -O / --optimize spelling wins, as gcc/clang */
            opt_token = tk;
        }
    }
    if (opt == FXG_OPT_HIGH) {
        *token = opt_token;
        return FXI_CODEGEN_UNBOUNDED;
    }
    return opt == FXG_OPT_1 ? FXI_CODEGEN_COMPONENT : FXI_CODEGEN_CALLERS;
}

bool fxi_object_cc_known(const struct fxi *x)
{
    static const char key[] = "; object-cc ", unknown[] = "unknown";
    const size_t kn = sizeof(key) - 1, un = sizeof(unknown) - 1;
    for (size_t k = 0; x->compiler != NULL && k + kn <= x->compiler_len; k++) {
        if (memcmp(x->compiler + k, key, kn) != 0)
            continue;
        k += kn;
        return !(x->compiler_len - k >= un &&
                 memcmp(x->compiler + k, unknown, un) == 0);
    }
    return false;
}

enum fxi_codegen fxi_codegen_model(const struct fxi *x, const char **token)
{
    if (!fxi_object_cc_known(x)) {
        *token = "no known object compiler";
        return FXI_CODEGEN_UNBOUNDED;
    }
    return fxi_codegen_model_of(x->identity, x->identity_len, token);
}

bool fxi_defined_function(const struct fxi *x, size_t e)
{
    return x->ents[e].defined_fn;
}

/* ---- the closure ------------------------------------------------------------ */

static bool fxg_internal(const struct fxi_ent *t)
{
    return t->id[1] == ':' && strchr(t->id + 2, ':') != NULL;
}

/* A function the TU defines, or a static variable it defines (in the main
 * file or a header: a header static is internal to every includer):
 * the code units whose bytes, or whose facts other code folds, can move. */
static bool fxg_node(const struct fxi *x, uint32_t e)
{
    const struct fxi_ent *t = &x->ents[e];
    return t->defined_fn ||
           (t->id[0] == 'v' && fxg_internal(t));
}

static bool fxg_step(enum fxi_codegen model, uint8_t kind)
{
    if (model == FXI_CODEGEN_CALLERS)
        return kind == VCS_SEMANTIC_REF_V1_CALL;
    return kind == VCS_SEMANTIC_REF_V1_CALL ||
           kind == VCS_SEMANTIC_REF_V1_ADDRESS ||
           kind == VCS_SEMANTIC_REF_V1_VARIABLE;
}

static void fxg_push(uint8_t *mark, uint32_t *q, size_t *tail, uint32_t e)
{
    if (mark[e])
        return;
    mark[e] = 2;
    q[(*tail)++] = e;
}

/* Up: every code unit that names e (a caller may inline it or fold its
 * summary). Down, beyond -O0: every internal unit e names (a callee only
 * this TU calls takes e's constants, coldness and dropped arguments; a
 * static variable takes e's stores and address uses to its readers). */
static void fxg_expand(const struct fxi *x, enum fxi_codegen model,
                       uint8_t *mark, uint32_t *q, size_t *tail, uint32_t e)
{
    for (uint32_t k = x->in_off[e]; k < x->in_off[e + 1]; k++) {
        const struct fxi_edge *g = &x->edges[x->in_edge[k]];
        if (fxg_step(model, g->kind) && fxg_node(x, g->from))
            fxg_push(mark, q, tail, g->from);
    }
    if (model != FXI_CODEGEN_COMPONENT)
        return;
    for (uint32_t k = x->out_off[e]; k < x->out_off[e + 1]; k++) {
        const struct fxi_edge *g = &x->edges[x->out_edge[k]];
        if (fxg_step(model, g->kind) && fxg_node(x, g->to) &&
            fxg_internal(&x->ents[g->to]))
            fxg_push(mark, q, tail, g->to);
    }
}

bool fxi_codegen_closure(const struct fxi *x, enum fxi_codegen model,
                         uint8_t *mark)
{
    uint32_t *q;
    size_t head = 0, tail = 0;
#if defined(ZCL_TESTING)
    if (zcl_devloop_test_consumer_mutant ==
        ZCL_DEVLOOP_MUTANT_NO_CODEGEN_CLOSURE)
        return true;
#endif
    q = zcl_calloc(x->nents + 1, sizeof(*q), "facts_codegen.queue");
    if (q == NULL)
        return false;
    for (size_t e = 0; e < x->nents; e++)
        if (mark[e])
            q[tail++] = (uint32_t)e;
    while (head < tail)
        fxg_expand(x, model, mark, q, &tail, q[head++]);
    free(q);
    return true;
}

/* ---- positions: builtins that expand to where or how often -------------- */

static bool fxg_ident_byte(unsigned char c)
{
    return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

static bool fxg_body_names(const struct fxi_macro *m, const char *ident)
{
    size_t n = strlen(ident);
    for (size_t i = 0; i + n <= m->len; i++) {
        if (memcmp(m->body + i, ident, n) != 0)
            continue;
        if ((i == 0 || !fxg_ident_byte((unsigned char)m->body[i - 1])) &&
            (i + n == m->len || !fxg_ident_byte((unsigned char)m->body[i + n])))
            return true;
    }
    return false;
}

bool fxi_expands_builtin(const struct fxi *x, const char *ident, size_t *via)
{
    char id[64];
    uint32_t e;
    uint8_t *flags = zcl_calloc(x->nents + 1, 1, "facts_codegen.builtin");
    bool ok;
    if (flags == NULL)
        return false;
    int w = snprintf(id, sizeof(id), "m:@builtin:%s", ident);
    if (w > 0 && (size_t)w < sizeof(id) && fxi_lookup(x, id, (size_t)w, &e))
        flags[e] = 1;
    for (size_t k = 0; k < x->nmacros; k++)
        if (fxg_body_names(&x->macros[k], ident))
            flags[x->macros[k].ent] = flags[x->macros[k].group] = 1;
    ok = fxi_taint(x, flags, via);
    free(flags);
    return ok;
}
