/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fp_sig — turn a function's declarator text into a CALLABLE SHAPE.
 *
 * This is the half of the problem that decides whether behavioral
 * fingerprinting is engineering or a demo: calling thousands of arbitrary
 * functions with no hand-written harness for any of them. The harness is
 * generated from the signature, so the signature has to be reduced to a
 * small set of shapes whose inputs can be SYNTHESISED SOUNDLY:
 *
 *   scalar          an integer, bool, char or enum, by value
 *   const char *    a generated NUL-terminated string
 *   const T *, n    a generated buffer with its length bound to the buffer,
 *                   in the one way that stays in bounds under BOTH readings
 *                   of `n` (bytes or elements) — see fp_emit
 *   const T x[K]    an array whose extent the signature already states
 *   const T *       an input object, pattern-filled
 *   T *, T x[K]     an output the callee writes, hashed afterwards
 *
 * Everything else is refused. The refusals are the point: a `void **`, an
 * unbounded `T *` with no length anywhere, a callback, a by-value struct, a
 * float — each of those could be made to compile, and each would produce a
 * call whose inputs are not actually determined by the signature, which
 * yields a fingerprint that is not reproducible and poisons the index.
 *
 * Nothing here uses parameter NAMES. A buffer is bound to a length because
 * an unsigned integer follows a pointer, not because someone called it
 * `len`. The shape string it produces is likewise name-blind, which is what
 * lets two independently-written implementations of one behavior land in the
 * same corpus and be compared at all.
 */

#include "fp_priv.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* Integer spellings accepted by value. Deliberately no floating point: FP
 * results are not stable across the optimisation levels the stability filter
 * varies, so a float-taking function could never survive it anyway and
 * accepting it would only inflate the false-purity number. */
static const char *const k_scalars[] = {
    "char", "signed char", "unsigned char", "short", "short int",
    "signed short", "signed short int", "unsigned short",
    "unsigned short int", "int", "signed", "signed int", "unsigned",
    "unsigned int", "long", "long int", "signed long", "unsigned long",
    "unsigned long int", "long long", "long long int", "signed long long",
    "unsigned long long", "unsigned long long int",
    "bool", "_Bool", "size_t", "ssize_t", "ptrdiff_t", "intptr_t",
    "uintptr_t", "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t",
    "uint16_t", "uint32_t", "uint64_t", "intmax_t", "uintmax_t",
    "unsigned char", NULL
};

static void fp_trim(const char *s, size_t *b, size_t *e)
{
    while (*b < *e && isspace((unsigned char)s[*b])) (*b)++;
    while (*e > *b && isspace((unsigned char)s[*e - 1])) (*e)--;
}

/* Collapse a slice of source text to a single-spaced token string. */
static void fp_norm(const char *s, size_t b, size_t e, char *out, size_t cap)
{
    size_t o = 0;
    bool sp = false;
    for (; b < e && o + 1u < cap; b++) {
        if (isspace((unsigned char)s[b])) { sp = (o > 0); continue; }
        if (sp) { out[o++] = ' '; sp = false; if (o + 1u >= cap) break; }
        out[o++] = s[b];
    }
    out[o] = '\0';
}

static bool fp_word_eq(const char *hay, const char *word)
{
    return strcmp(hay, word) == 0;
}

static bool fp_has_word(const char *s, const char *w)
{
    size_t n = strlen(w);
    const char *p = s;
    while ((p = strstr(p, w)) != NULL) {
        bool lb = (p == s) || !fp_ident_char((unsigned char)p[-1]);
        bool rb = !fp_ident_char((unsigned char)p[n]);
        if (lb && rb)
            return true;
        p += n;
    }
    return false;
}

/* Remove a whole word from a normalised type string, in place. */
static void fp_drop_word(char *s, const char *w)
{
    size_t n = strlen(w);
    char *p = s;
    while ((p = strstr(p, w)) != NULL) {
        bool lb = (p == s) || !fp_ident_char((unsigned char)p[-1]);
        bool rb = !fp_ident_char((unsigned char)p[n]);
        if (!lb || !rb) { p += n; continue; }
        memmove(p, p + n, strlen(p + n) + 1u);
        while (*p == ' ') memmove(p, p + 1, strlen(p + 1) + 1u);
        if (p > s && p[-1] == ' ' && (*p == '\0' || *p == '*'))
            memmove(p - 1, p, strlen(p) + 1u);
    }
    {   /* tidy any doubled or edge spaces the removal left behind */
        size_t i = 0;
        size_t o = 0;
        bool sp = false;
        for (; s[i]; i++) {
            if (s[i] == ' ') { sp = (o > 0); continue; }
            if (sp) { s[o++] = ' '; sp = false; }
            s[o++] = s[i];
        }
        s[o] = '\0';
    }
}

static bool fp_is_scalar_text(const char *t)
{
    size_t i;
    for (i = 0; k_scalars[i] != NULL; i++)
        if (fp_word_eq(t, k_scalars[i]))
            return true;
    return false;
}

/* One level at a time, replace an in-tree typedef name by what it aliases,
 * so `metaverse_kind_set` reaches `uint32_t` and can be passed by value.
 * Bounded, and it gives up rather than looping. */
static void fp_resolve_typedef(struct fp_index *ix, char *t, size_t cap)
{
    int round;
    for (round = 0; round < 4; round++) {
        int idx;
        char under[FP_MAX_TYPE];
        const struct fp_sym *s;
        const char *text;
        size_t b;
        size_t e;
        size_t namepos;
        if (fp_is_scalar_text(t))
            return;
        if (strchr(t, ' ') != NULL || strchr(t, '*') != NULL)
            return;
        idx = fp_sym_lookup(ix, t, strlen(t), FP_SYM_TYPE);
        if (idx < 0)
            return;
        s = &ix->syms[idx];
        text = ix->files[s->file].text;
        b = s->decl_off;
        e = s->decl_off + s->decl_len;
        /* `typedef <underlying> <name>` — drop the keyword and the name. */
        namepos = e;
        while (namepos > b && fp_ident_char((unsigned char)text[namepos - 1]))
            namepos--;
        if (namepos <= b)
            return;
        e = namepos;
        fp_norm(text, b, e, under, sizeof under);
        fp_drop_word(under, "typedef");
        if (under[0] == '\0' || strlen(under) + 1u > cap)
            return;
        snprintf(t, cap, "%s", under);
    }
}

/* Evaluate an array extent when it is a literal, or a macro or enumeration
 * constant that is one. Unknown extents keep their source text: the compiler
 * evaluates them in the generated harness, and only the shape string (which
 * decides which functions are compared with each other) loses precision. */
static bool fp_eval_extent(struct fp_index *ix, const char *txt,
                           unsigned long *out)
{
    int round;
    char cur[FP_MAX_TYPE];
    snprintf(cur, sizeof cur, "%s", txt);
    for (round = 0; round < 6; round++) {
        char *end = NULL;
        unsigned long v;
        size_t b = 0;
        size_t e = strlen(cur);
        int idx;
        fp_trim(cur, &b, &e);
        memmove(cur, cur + b, e - b);
        cur[e - b] = '\0';
        if (cur[0] == '\0')
            return false;
        v = strtoul(cur, &end, 0);
        if (end != cur) {
            while (*end == 'u' || *end == 'U' || *end == 'l' || *end == 'L')
                end++;
            if (*end == '\0') { *out = v; return true; }
        }
        idx = fp_sym_lookup(ix, cur, strlen(cur), FP_SYM_MACRO);
        if (idx < 0)
            return false;
        {
            const struct fp_sym *s = &ix->syms[idx];
            fp_norm(ix->files[s->file].text, s->body_off,
                    s->body_off + s->body_len, cur, sizeof cur);
        }
        /* strip one layer of wrapping parentheses */
        if (cur[0] == '(' && cur[strlen(cur) - 1u] == ')') {
            memmove(cur, cur + 1, strlen(cur));
            cur[strlen(cur) - 1u] = '\0';
        }
    }
    return false;
}

struct fp_typeinfo {
    char base[FP_MAX_TYPE];   /* unqualified pointee/value type */
    int  stars;
    bool is_const;
    bool is_struct;
    bool is_scalar;
    bool is_void;
    bool is_char;
    bool is_funcptr;
};

static void fp_classify(struct fp_index *ix, const char *raw,
                        struct fp_typeinfo *ti)
{
    char t[FP_MAX_TYPE];
    size_t i;

    memset(ti, 0, sizeof *ti);
    snprintf(t, sizeof t, "%s", raw);
    if (strstr(t, "(*") != NULL || strstr(t, "( *") != NULL) {
        ti->is_funcptr = true;
        return;
    }
    ti->is_const = fp_has_word(t, "const");
    fp_drop_word(t, "const");
    fp_drop_word(t, "volatile");
    fp_drop_word(t, "restrict");
    fp_drop_word(t, "__restrict");
    fp_drop_word(t, "register");
    fp_drop_word(t, "static");
    fp_drop_word(t, "extern");
    fp_drop_word(t, "inline");
    fp_drop_word(t, "_Nullable");
    for (i = 0; t[i]; i++)
        if (t[i] == '*')
            ti->stars++;
    while (strchr(t, '*') != NULL) {
        char *p = strchr(t, '*');
        memmove(p, p + 1, strlen(p + 1) + 1u);
    }
    {
        size_t b = 0;
        size_t e = strlen(t);
        fp_trim(t, &b, &e);
        memmove(t, t + b, e - b);
        t[e - b] = '\0';
    }
    ti->is_struct = (strncmp(t, "struct ", 7) == 0 ||
                     strncmp(t, "union ", 6) == 0);
    ti->is_void = fp_word_eq(t, "void");
    if (!ti->is_struct && strncmp(t, "enum ", 5) != 0)
        fp_resolve_typedef(ix, t, sizeof t);
    ti->is_scalar = fp_is_scalar_text(t) || strncmp(t, "enum ", 5) == 0;
    ti->is_char = fp_word_eq(t, "char");
    snprintf(ti->base, sizeof ti->base, "%s", t);
}

/* Split a parameter list on top-level commas. */
static int fp_split_params(const char *t, size_t b, size_t e, size_t *starts,
                           size_t *ends, int cap)
{
    int n = 0;
    int depth = 0;
    size_t s = b;
    size_t i;
    for (i = b; i < e; i++) {
        if (t[i] == '(' || t[i] == '[') depth++;
        else if (t[i] == ')' || t[i] == ']') depth--;
        else if (t[i] == ',' && depth == 0) {
            if (n >= cap) return -1;
            starts[n] = s; ends[n] = i; n++;
            s = i + 1u;
        }
    }
    if (n >= cap) return -1;
    starts[n] = s; ends[n] = e; n++;
    return n;
}

static void fp_shape_add(char *shape, size_t cap, const char *tok)
{
    size_t n = strlen(shape);
    snprintf(shape + n, (n < cap) ? cap - n : 0u, "%s", tok);
}

static enum fp_verdict fp_classify_param(struct fp_index *ix, const char *t,
                                         size_t b, size_t e, bool next_is_uint,
                                         struct fp_param *p, char *extent,
                                         size_t extent_cap)
{
    char norm[FP_MAX_TYPE * 2];
    struct fp_typeinfo ti;
    char *br;

    extent[0] = '\0';
    fp_norm(t, b, e, norm, sizeof norm);
    if (strcmp(norm, "...") == 0)
        return FP_V_VARIADIC;
    if (norm[0] == '\0')
        return FP_V_UNSUPPORTED_PARAM;

    br = strchr(norm, '[');
    if (br != NULL) {
        char *close = strchr(br, ']');
        if (close == NULL)
            return FP_V_UNSUPPORTED_PARAM;
        *close = '\0';
        snprintf(extent, extent_cap, "%s", br + 1);
        *br = '\0';
        {   /* drop the parameter name that preceded the extent */
            size_t l = strlen(norm);
            while (l > 0 && isspace((unsigned char)norm[l - 1])) l--;
            while (l > 0 && fp_ident_char((unsigned char)norm[l - 1])) l--;
            norm[l] = '\0';
        }
        if (extent[0] == '\0')
            return FP_V_UNSUPPORTED_PARAM;   /* `T x[]` — extent not stated */
    } else {
        /* drop a trailing parameter name, keeping the type */
        size_t l = strlen(norm);
        size_t nb = l;
        while (nb > 0 && fp_ident_char((unsigned char)norm[nb - 1])) nb--;
        if (nb > 0 && nb < l && (norm[nb - 1] == ' ' || norm[nb - 1] == '*')) {
            char keep[FP_MAX_TYPE * 2];
            snprintf(keep, sizeof keep, "%.*s", (int)nb, norm);
            snprintf(norm, sizeof norm, "%s", keep);
        }
    }

    fp_classify(ix, norm, &ti);
    if (ti.is_funcptr)
        return FP_V_FUNCTION_POINTER;
    snprintf(p->type_text, sizeof p->type_text, "%s", ti.base);
    p->pair = -1;

    if (extent[0] != '\0') {
        if (ti.stars > 0 || ti.is_void)
            return FP_V_UNSUPPORTED_PARAM;
        snprintf(p->elem_text, sizeof p->elem_text, "%s", extent);
        p->kind = ti.is_const ? FP_K_ARR_IN : FP_K_OUT_ARR;
        return FP_V_CANDIDATE;
    }
    if (ti.stars == 0) {
        if (!ti.is_scalar)
            return ti.is_void ? FP_V_CANDIDATE : FP_V_UNSUPPORTED_PARAM;
        p->kind = FP_K_SCALAR;
        return FP_V_CANDIDATE;
    }
    if (ti.stars > 1)
        return FP_V_UNSUPPORTED_PARAM;

    if (ti.is_const) {
        if (ti.is_char && !next_is_uint) { p->kind = FP_K_CSTR_IN; return FP_V_CANDIDATE; }
        if (ti.is_void || ti.is_scalar) {
            if (!next_is_uint)
                return FP_V_UNSUPPORTED_PARAM;   /* unbounded read */
            p->kind = FP_K_BUF_IN;
            snprintf(p->type_text, sizeof p->type_text, "%s",
                     ti.is_void ? "unsigned char" : ti.base);
            return FP_V_CANDIDATE;
        }
        if (ti.is_struct || ti.base[0] != '\0') { p->kind = FP_K_OBJ_IN; return FP_V_CANDIDATE; }
        return FP_V_UNSUPPORTED_PARAM;
    }
    if (ti.is_void)
        return FP_V_UNSUPPORTED_PARAM;       /* `void *` output, size unknown */
    if (next_is_uint && (ti.is_char || ti.is_scalar)) {
        /* `T *out, size_t cap` — the classic formatter shape. The generated
         * buffer's own size is passed as the capacity, so the callee cannot
         * be told about more room than exists. */
        p->kind = FP_K_OUT_ARR;
        p->elem_text[0] = '\0';              /* generated buffer, fixed size */
        return FP_V_CANDIDATE;
    }
    if (ti.is_char)
        return FP_V_UNSUPPORTED_PARAM;       /* `char *` with no capacity */
    if (ti.is_scalar) { p->kind = FP_K_OUT_SCALAR; return FP_V_CANDIDATE; }
    p->kind = FP_K_OUT_OBJ;
    return FP_V_CANDIDATE;
}

enum fp_verdict fp_signature_of(struct fp_index *ix, int sym,
                                struct fp_candidate *out)
{
    const struct fp_sym *s = &ix->syms[sym];
    const struct fp_file *f = &ix->files[s->file];
    const char *t = f->text;
    size_t b = s->decl_off;
    size_t e = s->decl_off + s->decl_len;
    size_t lp;
    size_t name_s;
    size_t starts[FP_MAX_PARAMS + 4];
    size_t ends[FP_MAX_PARAMS + 4];
    int np;
    int i;
    char rettext[FP_MAX_TYPE * 2];
    struct fp_typeinfo rti;
    bool observable = false;
    char shape[FP_MAX_SHAPE];

    /* Locate the parameter list: the declarator text ends at its ')'. */
    if (e <= b || t[e - 1] != ')')
        return FP_V_UNSUPPORTED_PARAM;
    {
        int depth = 0;
        size_t i2 = e;
        lp = (size_t)-1;
        while (i2 > b) {
            i2--;
            if (t[i2] == ')') depth++;
            else if (t[i2] == '(') { depth--; if (depth == 0) { lp = i2; break; } }
        }
        if (lp == (size_t)-1)
            return FP_V_UNSUPPORTED_PARAM;
    }
    name_s = lp;
    while (name_s > b && isspace((unsigned char)t[name_s - 1])) name_s--;
    while (name_s > b && fp_ident_char((unsigned char)t[name_s - 1])) name_s--;

    fp_norm(t, b, name_s, rettext, sizeof rettext);
    fp_classify(ix, rettext, &rti);
    if (rti.is_funcptr)
        return FP_V_FUNCTION_POINTER;

    memset(out, 0, sizeof *out);
    snprintf(out->name, sizeof out->name, "%s", s->name);
    snprintf(out->def_path, sizeof out->def_path, "%s", f->path);
    snprintf(out->group, sizeof out->group, "%s", f->group);
    out->def_line = s->line;
    shape[0] = '\0';

    if (rti.stars == 0 && rti.is_void) {
        out->ret.kind = FP_K_VOID;
        fp_shape_add(shape, sizeof shape, "v(");
    } else if (rti.stars == 0 && rti.is_scalar) {
        out->ret.kind = FP_K_SCALAR;
        snprintf(out->ret.type_text, sizeof out->ret.type_text, "%s", rti.base);
        observable = true;
        fp_shape_add(shape, sizeof shape, "s(");
    } else if (rti.stars == 1 && rti.is_char && rti.is_const) {
        out->ret.kind = FP_K_CSTR_OUT;
        observable = true;
        fp_shape_add(shape, sizeof shape, "t(");
    } else {
        return FP_V_UNSUPPORTED_RETURN;
    }

    np = fp_split_params(t, lp + 1u, e - 1u, starts, ends,
                         (int)(sizeof starts / sizeof starts[0]));
    if (np < 0)
        return FP_V_UNSUPPORTED_PARAM;
    {
        char only[FP_MAX_TYPE];
        fp_norm(t, starts[0], ends[0], only, sizeof only);
        if (np == 1 && (only[0] == '\0' || strcmp(only, "void") == 0))
            np = 0;
    }
    if (np > FP_MAX_PARAMS)
        return FP_V_UNSUPPORTED_PARAM;

    for (i = 0; i < np; i++) {
        char extent[FP_MAX_TYPE];
        bool next_uint = false;
        enum fp_verdict v;
        if (i > 0 && out->param[i].kind == FP_K_LEN)
            continue;                        /* already bound to a buffer */
        if (i + 1 < np) {
            char nx[FP_MAX_TYPE * 2];
            struct fp_typeinfo nti;
            fp_norm(t, starts[i + 1], ends[i + 1], nx, sizeof nx);
            {   /* drop the following parameter's name before classifying */
                size_t l = strlen(nx);
                size_t nb = l;
                while (nb > 0 && fp_ident_char((unsigned char)nx[nb - 1])) nb--;
                if (nb > 0 && nb < l && nx[nb - 1] == ' ')
                    nx[nb] = '\0';
            }
            fp_classify(ix, nx, &nti);
            next_uint = (nti.stars == 0 && nti.is_scalar && !nti.is_char &&
                         strncmp(nti.base, "enum ", 5) != 0);
        }
        v = fp_classify_param(ix, t, starts[i], ends[i], next_uint,
                              &out->param[i], extent, sizeof extent);
        if (v != FP_V_CANDIDATE)
            return v;
        if (next_uint &&
            (out->param[i].kind == FP_K_BUF_IN ||
             (out->param[i].kind == FP_K_OUT_ARR &&
              out->param[i].elem_text[0] == '\0'))) {
            /* bind the following unsigned integer as this buffer's length */
            memset(&out->param[i + 1], 0, sizeof out->param[i + 1]);
            out->param[i + 1].kind = FP_K_LEN;
            out->param[i + 1].pair = i;
        }
    }
    out->n_params = np;

    for (i = 0; i < np; i++) {
        switch (out->param[i].kind) {
        case FP_K_SCALAR:     fp_shape_add(shape, sizeof shape, "s,"); break;
        case FP_K_CSTR_IN:    fp_shape_add(shape, sizeof shape, "t,"); break;
        case FP_K_BUF_IN:     fp_shape_add(shape, sizeof shape, "b,"); break;
        case FP_K_LEN:        fp_shape_add(shape, sizeof shape, "n,"); break;
        case FP_K_OBJ_IN:     fp_shape_add(shape, sizeof shape, "o,"); break;
        case FP_K_OUT_SCALAR: fp_shape_add(shape, sizeof shape, "S,");
                              observable = true; break;
        case FP_K_OUT_OBJ:    fp_shape_add(shape, sizeof shape, "O,");
                              observable = true; break;
        case FP_K_OUT_ARR:    observable = true;
            if (out->param[i].elem_text[0] == '\0') {
                fp_shape_add(shape, sizeof shape, "A,");
            } else {
                unsigned long k = 0;
                char tok[48];
                if (fp_eval_extent(ix, out->param[i].elem_text, &k))
                    snprintf(tok, sizeof tok, "A%lu,", k);
                else
                    snprintf(tok, sizeof tok, "A?%s,", out->param[i].elem_text);
                fp_shape_add(shape, sizeof shape, tok);
            }
            break;
        case FP_K_ARR_IN: {
            unsigned long k = 0;
            char tok[48];
            if (fp_eval_extent(ix, out->param[i].elem_text, &k))
                snprintf(tok, sizeof tok, "a%lu,", k);
            else
                snprintf(tok, sizeof tok, "a?%s,", out->param[i].elem_text);
            fp_shape_add(shape, sizeof shape, tok);
            break;
        }
        default: return FP_V_UNSUPPORTED_PARAM;
        }
    }
    fp_shape_add(shape, sizeof shape, ")");
    if (!observable)
        return FP_V_NO_OBSERVABLE_OUTPUT;

    snprintf(out->shape_text, sizeof out->shape_text, "%s", shape);
    out->shape = fp_hash_str(out->shape_text);
    return FP_V_CANDIDATE;
}
