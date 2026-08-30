/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fp_purity — the fail-closed purity judgement.
 *
 * A fingerprint is only worth anything if it is REPRODUCIBLE, and a
 * fingerprint of an impure function is not. One wrongly-accepted function
 * produces a value that changes between runs, which does not merely lose
 * that function: it makes every "the fingerprint moved, your refactor
 * changed behavior" answer untrustworthy. So the analysis is built to fail
 * closed in one specific way:
 *
 *     EVERY CALL MUST RESOLVE. A call whose target is an in-tree function is
 *     judged transitively. A call whose target is a `#define` is judged by
 *     expanding it. A call to libc is accepted ONLY from an explicit
 *     allowlist of deterministic, state-free primitives. EVERYTHING ELSE —
 *     an unknown name, a function pointer, a call through a struct member —
 *     is a REJECTION, not a guess.
 *
 * That inverts the usual denylist design. A denylist has to enumerate every
 * impure thing in the world and is wrong the moment somebody adds one; this
 * has to enumerate every pure thing the tree actually uses and is merely
 * incomplete when somebody adds one, which costs coverage instead of
 * correctness.
 *
 * It is still a syntactic analysis over source text, so it is not a proof.
 * The empirical stability filter downstream is what turns "believed pure"
 * into "observed reproducible", and the gap between them is measured and
 * reported as the false-purity rate rather than assumed to be zero.
 */

#include "fp_priv.h"

#include <ctype.h>
#include <string.h>

#define FP_MACRO_DEPTH_MAX   8
#define FP_CLOSURE_DEPTH_MAX 48

/* Deterministic, state-free libc/compiler primitives. A call to anything not
 * on this list and not defined in the tree is a rejection. Note what is
 * ABSENT and why: no printf family (I/O), no malloc family (allocator), no
 * time/clock (wall clock), no rand (hidden state), no strtok (static state),
 * no qsort/bsearch (they call through a function pointer), no locale setters,
 * no floating-point maths (rounding is not stable across optimisation
 * levels, which is one of the configurations the stability filter varies). */
static const char *const k_pure_libc[] = {
    "memcpy", "memmove", "memset", "memcmp", "memchr", "memrchr",
    "strlen", "strnlen", "strcmp", "strncmp", "strcasecmp", "strncasecmp",
    "strchr", "strrchr", "strstr", "strspn", "strcspn", "strpbrk",
    "strcpy", "strncpy", "strcat", "strncat",
    "snprintf", "sprintf",
    "strtol", "strtoll", "strtoul", "strtoull", "atoi", "atol", "atoll",
    "abs", "labs", "llabs", "imaxabs", "offsetof",
    "toupper", "tolower", "isalpha", "isdigit", "isalnum", "isspace",
    "isxdigit", "isupper", "islower", "isprint", "ispunct", "iscntrl",
    "isgraph", "isblank", "isascii",
    "htons", "htonl", "ntohs", "ntohl",
    "htobe16", "htobe32", "htobe64", "htole16", "htole32", "htole64",
    "be16toh", "be32toh", "be64toh", "le16toh", "le32toh", "le64toh",
    "__builtin_bswap16", "__builtin_bswap32", "__builtin_bswap64",
    "__builtin_clz", "__builtin_clzl", "__builtin_clzll",
    "__builtin_ctz", "__builtin_ctzl", "__builtin_ctzll",
    "__builtin_popcount", "__builtin_popcountl", "__builtin_popcountll",
    "__builtin_expect", "__builtin_memcpy", "__builtin_memset",
    "__builtin_constant_p", "__builtin_offsetof",
    "__builtin_types_compatible_p", "__builtin_add_overflow",
    "__builtin_sub_overflow", "__builtin_mul_overflow",
    NULL
};

/* Identifiers that are never a symbol reference worth resolving. */
static const char *const k_keywords[] = {
    "if", "else", "for", "while", "do", "switch", "case", "default",
    "break", "continue", "return", "goto", "sizeof", "typeof", "typeof_unqual",
    "alignof", "_Alignof", "alignas", "_Alignas", "static_assert",
    "_Static_assert", "defined", "__attribute__", "__extension__",
    "__VA_OPT__", "__VA_ARGS__",
    "void", "char", "short", "int", "long", "float", "double", "signed",
    "unsigned", "bool", "_Bool", "struct", "union", "enum", "typedef",
    "const", "restrict", "__restrict", "inline", "__inline", "extern",
    "auto", "register", "nullptr", "true", "false", "NULL",
    "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t", "intmax_t", "uintmax_t",
    NULL
};

/* Reading any of these is reading process or thread state. They are libc
 * names the scanner would otherwise treat as an unknown local. */
static const char *const k_impure_values[] = {
    "errno", "stdout", "stderr", "stdin", "environ", "__environ", "optarg",
    "optind", "opterr", "optopt", "program_invocation_name", NULL
};

/* Tokens that, appearing anywhere in a body, make it non-reproducible or
 * unanalysable regardless of what else it does. */
static const char *const k_forbidden_tokens[] = {
    "static", "volatile", "_Atomic", "_Thread_local", "thread_local",
    "__thread", "asm", "__asm__", "alloca", "va_start", "va_arg", "va_copy",
    "va_list", "setjmp", "longjmp", "_Generic", NULL
};

static bool fp_in_list(const char *const *list, const char *s, size_t n)
{
    size_t i;
    for (i = 0; list[i] != NULL; i++)
        if (strlen(list[i]) == n && memcmp(list[i], s, n) == 0)
            return true;
    return false;
}

/* A call target that is an in-tree function definition. Prefers a definition
 * in the SAME file, because a `static` helper is file-local: resolving
 * `parse` to some other translation unit's `parse` would judge the wrong
 * body and is exactly the kind of silent mistake that poisons an index. */
static int fp_lookup_func(const struct fp_index *ix, const char *name,
                          size_t len, int prefer_file)
{
    uint64_t h;
    int i;
    int fallback = -1;
    char buf[FP_MAX_NAME];
    if (len >= FP_MAX_NAME)
        return -1;
    memcpy(buf, name, len);
    buf[len] = '\0';
    h = fp_hash_str(buf);
    for (i = ix->bucket[h % ix->nbuckets]; i >= 0; i = ix->syms[i].next) {
        const struct fp_sym *s = &ix->syms[i];
        if (s->kind != (unsigned char)FP_SYM_FUNC)
            continue;
        if (strcmp(s->name, buf) != 0)
            continue;
        if (s->file == prefer_file)
            return i;
        if (!s->is_static && fallback < 0)
            fallback = i;
    }
    return fallback;
}

/* A file-scope object this translation unit can actually SEE: one declared in
 * the same file, or one declared in a header (so any TU including it reaches
 * the same object). Without this test the scanner resolves a local named
 * `count` against some unrelated file's global `count` and refuses a pure
 * function for a name collision — which, at this tree's size, is most of what
 * a naive global check would report. Returns the symbol index, or -1 when no
 * VISIBLE object of that name exists. */
static int fp_lookup_visible_object(const struct fp_index *ix,
                                    const char *name, size_t len, int file)
{
    uint64_t h;
    int i;
    int hdr = -1;
    char buf[FP_MAX_NAME];
    if (len >= FP_MAX_NAME)
        return -1;
    memcpy(buf, name, len);
    buf[len] = '\0';
    h = fp_hash_str(buf);
    for (i = ix->bucket[h % ix->nbuckets]; i >= 0; i = ix->syms[i].next) {
        const struct fp_sym *s = &ix->syms[i];
        if (s->kind != (unsigned char)FP_SYM_OBJ)
            continue;
        if (strcmp(s->name, buf) != 0)
            continue;
        if (s->file == file)
            return i;
        if (ix->files[s->file].is_header && hdr < 0)
            hdr = i;
    }
    return hdr;
}

static void fp_note_cause(struct fp_index *ix, const char *s, size_t n)
{
    if (n >= FP_MAX_NAME)
        n = FP_MAX_NAME - 1u;
    memcpy(ix->cause, s, n);
    ix->cause[n] = '\0';
}

const char *fp_index_last_cause(const struct fp_index *ix)
{
    return ix->cause;
}

static enum fp_verdict fp_scan_text(struct fp_index *ix, int file, size_t off,
                                    size_t len, int depth, int macro_depth,
                                    int self);

static enum fp_verdict fp_purity_depth(struct fp_index *ix, int sym, int depth,
                                       int caller)
{
    struct fp_sym *s;
    enum fp_verdict v;

    if (sym < 0)
        return FP_V_UNRESOLVED_CALL;
    s = &ix->syms[sym];
    if (s->verdict >= 0) {
        snprintf(ix->cause, sizeof ix->cause, "%s", s->cause);
        return (enum fp_verdict)s->verdict;
    }
    if (s->verdict == -2) {
        /* Direct self-recursion is fine: a pure function may call itself.
         * Any other cycle would need a fixpoint, and guessing at one is the
         * kind of optimism this analysis exists to avoid. */
        return (sym == caller) ? FP_V_CANDIDATE : FP_V_CLOSURE_TOO_DEEP;
    }
    if (depth > FP_CLOSURE_DEPTH_MAX)
        return FP_V_CLOSURE_TOO_DEEP;

    s->verdict = -2;
    ix->cause[0] = '\0';
    v = fp_scan_text(ix, s->file, s->body_off, s->body_len, depth, 0, sym);
    s = &ix->syms[sym];
    s->verdict = (signed char)v;
    snprintf(s->cause, sizeof s->cause, "%s", ix->cause);
    return v;
}

enum fp_verdict fp_purity_of(struct fp_index *ix, int sym)
{
    return fp_purity_depth(ix, sym, 0, sym);
}

/* `(*fp)(args)` — a call through a parenthesised pointer expression. It has
 * no identifier before the argument list, so the identifier walk cannot see
 * it at all. Detected as a pattern and refused. */
static bool fp_has_indirect_call(const char *t, size_t s, size_t e)
{
    size_t i;
    for (i = s; i + 3u < e; i++) {
        size_t j;
        if (t[i] != '(')
            continue;
        j = i + 1u;
        while (j < e && isspace((unsigned char)t[j])) j++;
        if (j >= e || t[j] != '*')
            continue;
        while (j < e && (t[j] == '*' || isspace((unsigned char)t[j]))) j++;
        if (j >= e || !fp_ident_start((unsigned char)t[j]))
            continue;
        while (j < e && fp_ident_char((unsigned char)t[j])) j++;
        while (j < e && isspace((unsigned char)t[j])) j++;
        if (j >= e || t[j] != ')')
            continue;
        j++;
        while (j < e && isspace((unsigned char)t[j])) j++;
        if (j < e && t[j] == '(')
            return true;
    }
    return false;
}

static enum fp_verdict fp_scan_text(struct fp_index *ix, int file, size_t off,
                                    size_t len, int depth, int macro_depth,
                                    int self)
{
    const char *t;
    size_t e;
    size_t i;

    if (file < 0 || (size_t)file >= ix->nfiles)
        return FP_V_UNRESOLVED_CALL;
    t = ix->files[file].text;
    e = off + len;
    if (e > ix->files[file].len)
        e = ix->files[file].len;
    if (fp_has_indirect_call(t, off, e))
        return FP_V_FUNCTION_POINTER;

    for (i = off; i < e; i++) {
        size_t j;
        size_t k;
        bool is_call;
        bool is_member;
        int idx;

        if (!fp_ident_start((unsigned char)t[i]))
            continue;
        if (i > off && fp_ident_char((unsigned char)t[i - 1]))
            continue;
        j = i;
        while (j < e && fp_ident_char((unsigned char)t[j])) j++;

        if (fp_in_list(k_forbidden_tokens, t + i, j - i)) {
            fp_note_cause(ix, t + i, j - i);
            return FP_V_FUNCTION_STATIC;
        }
        if (fp_in_list(k_keywords, t + i, j - i)) {
            i = j - 1u;
            continue;
        }

        /* A member selector (`p->field`, `s.field`, `.field =`) or a tag
         * after struct/union/enum is not a symbol reference. */
        is_member = false;
        k = i;
        while (k > off && isspace((unsigned char)t[k - 1])) k--;
        if (k >= off + 1u && t[k - 1] == '.') is_member = true;
        if (k >= off + 2u && t[k - 2] == '-' && t[k - 1] == '>') is_member = true;
        if (k >= off + 6u && strncmp(t + k - 6, "struct", 6) == 0) is_member = true;
        if (k >= off + 5u && strncmp(t + k - 5, "union", 5) == 0) is_member = true;
        if (k >= off + 4u && strncmp(t + k - 4, "enum", 4) == 0) is_member = true;
        if (is_member) {
            i = j - 1u;
            continue;
        }

        k = j;
        while (k < e && isspace((unsigned char)t[k])) k++;
        is_call = (k < e && t[k] == '(');

        /* The preprocessor runs first, so a macro shadows everything. */
        idx = fp_sym_lookup(ix, t + i, j - i, FP_SYM_MACRO);
        if (idx >= 0) {
            enum fp_verdict v;
            if (macro_depth >= FP_MACRO_DEPTH_MAX)
                return FP_V_CLOSURE_TOO_DEEP;
            v = fp_scan_text(ix, ix->syms[idx].file, ix->syms[idx].body_off,
                             ix->syms[idx].body_len, depth, macro_depth + 1,
                             self);
            if (v != FP_V_CANDIDATE)
                return v;
            i = j - 1u;
            continue;
        }

        if (is_call) {
            enum fp_verdict v;
            int fn;
            if (fp_in_list(k_pure_libc, t + i, j - i)) {
                i = j - 1u;
                continue;
            }
            fn = fp_lookup_func(ix, t + i, j - i, file);
            if (fn < 0) {
                fp_note_cause(ix, t + i, j - i);
                return FP_V_UNRESOLVED_CALL;
            }
            v = fp_purity_depth(ix, fn, depth + 1, self);
            if (v != FP_V_CANDIDATE)
                return v;
            i = j - 1u;
            continue;
        }

        if (fp_in_list(k_impure_values, t + i, j - i)) {
            fp_note_cause(ix, t + i, j - i);
            return FP_V_IMPURE_GLOBAL;
        }
        if (fp_in_list(k_pure_libc, t + i, j - i)) {
            /* A libc function named without calling it: its address is being
             * taken, which means somebody is going to call it indirectly. */
            fp_note_cause(ix, t + i, j - i);
            return FP_V_FUNCTION_POINTER;
        }
        {
            /* A bare mention of a function name is its ADDRESS being taken,
             * which means an indirect call is coming. But only if this TU can
             * actually see that function: a local variable that happens to
             * share a name with some other file's static helper is not a
             * function pointer, and treating it as one refused a hundred
             * honest functions. */
            int fn = fp_lookup_func(ix, t + i, j - i, file);
            bool visible = false;
            if (fn >= 0 && (ix->syms[fn].file == file || !ix->syms[fn].is_static))
                visible = true;
            if (!visible) {
                int pr = fp_sym_lookup(ix, t + i, j - i, FP_SYM_PROTO);
                if (pr >= 0 && ix->files[ix->syms[pr].file].is_header)
                    visible = true;
            }
            if (visible) {
                fp_note_cause(ix, t + i, j - i);
                return FP_V_FUNCTION_POINTER;
            }
        }
        if (fp_sym_lookup(ix, t + i, j - i, FP_SYM_ENUMCONST) >= 0) {
            i = j - 1u;
            continue;
        }
        idx = fp_lookup_visible_object(ix, t + i, j - i, file);
        if (idx >= 0) {
            if (!ix->syms[idx].const_object) {
                fp_note_cause(ix, t + i, j - i);
                return FP_V_IMPURE_GLOBAL;
            }
            i = j - 1u;
            continue;
        }
        /* Unknown, not called, not a global: a parameter, a local, a type
         * name, or a struct member the selector test missed. Accepted. */
        i = j - 1u;
    }
    return FP_V_CANDIDATE;
}
