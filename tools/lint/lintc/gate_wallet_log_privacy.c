/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-wallet-log-privacy. A log or event call under
 * contexts/wallet must not pass a wallet address, amount, balance, memo,
 * transaction id, note value, viewing key, diversifier or seed. Each call
 * (LOG_*, ZCL_LOG_*, GUARD*, printf, fprintf, fputs, puts, event_emitf) is
 * joined across line breaks with comments and string-literal contents
 * removed, and an identifier names a field when one of its words, split at
 * underscores and at lower-to-upper case changes, is a field name. A field
 * word directly before a format conversion in a string literal is flagged
 * too, across blanks, '=', ':', quotes and brackets (address %s, address
 * '%s', address (%s)). Adjacent literals are one string ("address " "%s").
 * A conversion that comes before the word ("%s is not an address") is not
 * matched. Count, length, size, height, state, kind, type and status words
 * are exempt, as are the operands of sizeof() and strlen() and the first
 * argument of a GUARD macro, which is a condition and not a logged value. "n"
 * is a count prefix only for a lower-case plural (nnotes; nvalue is a field),
 * and "bytes" only as an all-caps constant (ADDR_BYTES). A reviewed exception carries a
 * wallet-log-ok marker with a reason, written as a line comment on any line
 * of the call. Offenders are pinned per function in
 * tools/lint/wallet_log_privacy_baseline.txt (exact-pin ratchet): a new
 * function, a larger count, a smaller count, or a pin whose calls are gone
 * fails. Owners lower the baseline with ZCL_LINT_MODE=UPDATE, which only
 * lowers or deletes pins (lint_base_tighten) and never adds one. Selftest:
 * the fixtures at the end of this file.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"

enum { WLP_CALL = 8192, WLP_TOK = 64, WLP_KEYS = 512 };

static const char k_wlp_root[] = "contexts/wallet";
static const char k_wlp_base[] = "tools/lint/wallet_log_privacy_baseline.txt";
static const char k_wlp_hint[] =
    "ZCL_LINT_MODE=UPDATE ./build/bin/z23-lint check-wallet-log-privacy";
static const char k_wlp_hdr[] =
    "# check-wallet-log-privacy RATCHET baseline (exact pins, shrink-only).\n"
    "# key = <relpath>::<enclosing function>, value = log calls in that\n"
    "# function that pass a wallet-private field. Regenerate after fixing\n"
    "# some: ZCL_LINT_MODE=UPDATE ./build/bin/z23-lint check-wallet-log-privacy\n";

static const char *const k_wlp_fields[] = {
    "addr", "addrs", "address", "addresses", "zaddr", "memo", "memos",
    "amount", "amounts", "amt", "value", "balance", "balances", "txid",
    "txids", "ivk", "ovk", "divers", "diversifier", "viewing", "privkey",
    "wif", "seed", "fvk", "xfvk", "nullifier", "note", "notes", "rcm", "bal",
    "evidence", "mnemonic", "phrase", "passphrase", "secret", "spending", "xsk",
};
static const char *const k_wlp_exempt[] = {
    "count", "cnt", "len", "size", "num", "n", "idx", "index", "max", "cap",
    "height", "state", "kind", "type", "status", "code", "rc",
};
static const char *const k_wlp_keywords[] = {
    "if", "for", "while", "switch", "return", "sizeof",
};

struct wlp_tally {
    char key[WLP_KEYS][LB_KEY];
    int count[WLP_KEYS];
    int n;
    int calls;
};

struct wlp_st {
    struct wlp_tally *tally;
    FILE *out;
    const char *path;
    struct cstrip cs;
    char func[WLP_TOK];
    char code[WLP_CALL];
    size_t code_len;
    char raw[WLP_CALL];
    size_t raw_len;
    size_t open_at;
    size_t call_at;
    int lineno;
    int start_line;
    int depth;
    int in_stmt;
    int guard;
    int overflow;
};

static struct wlp_tally g_wlp_tally;
static struct lint_base g_wlp_base;

static int wlp_eq(const char *a, size_t n, const char *b)
{
    if (strlen(b) != n)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (tolower((unsigned char)a[i]) != (unsigned char)b[i])
            return 0;
    return 1;
}

static int wlp_in(const char *a, size_t n, const char *const *set, size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (wlp_eq(a, n, set[i]))
            return 1;
    return 0;
}

static int wlp_field_word(const char *w, size_t n)
{
    return wlp_in(w, n, k_wlp_fields, sizeof k_wlp_fields / sizeof k_wlp_fields[0]);
}

static int wlp_has_case(const char *w, size_t n, int upper)
{
    for (size_t i = 0; i < n; i++)
        if (upper ? isupper((unsigned char)w[i]) : islower((unsigned char)w[i]))
            return 1;
    return 0;
}

/* A whole word that is a count, size or kind descriptor. "bytes" counts
 * only as an all-caps constant (no lower-case letter), and "n" only as a
 * lower-case plural count of a field (nnotes, naddrs); nvalue and nValue are
 * not counts. */
static int wlp_exempt_word(const char *w, size_t n)
{
    if (wlp_eq(w, n, "bytes"))
        return !wlp_has_case(w, n, 0);
    if (wlp_in(w, n, k_wlp_exempt, sizeof k_wlp_exempt / sizeof k_wlp_exempt[0]))
        return 1;
    return n > 2 && w[0] == 'n' && w[n - 1] == 's'
        && !wlp_has_case(w + 1, n - 1, 1) && wlp_field_word(w + 1, n - 1);
}

/* A camel-case piece (the n of nValue is not a count, so it is skipped). */
static int wlp_piece_exempt(const char *p, size_t n)
{
    if (n == 1 && (p[0] == 'n' || p[0] == 'N'))
        return 0;
    return wlp_exempt_word(p, n);
}

/* Break before an upper-case letter that follows a lower-case letter or a
 * digit, so addrStr splits and ADDRS does not. */
static int wlp_camel_break(const char *w, size_t i)
{
    return isupper((unsigned char)w[i]) && !isupper((unsigned char)w[i - 1]);
}

/* A field name, or an n-prefixed field name (nvalue) that is not a count:
 * exemption for counts is decided before this is asked. */
static int wlp_piece_field(const char *p, size_t n)
{
    return wlp_field_word(p, n) || (n > 1 && p[0] == 'n' && wlp_field_word(p + 1, n - 1));
}

/* Field test over the camel-case pieces of one underscore word. A count
 * piece sets *exempt; a field piece is returned as a hit. */
static int wlp_word_names_field(const char *w, size_t n, int *exempt)
{
    int field = 0;
    size_t b = 0;
    for (size_t i = 1; i <= n; i++) {
        if (i < n && !wlp_camel_break(w, i))
            continue;
        *exempt |= wlp_piece_exempt(w + b, i - b);
        field |= wlp_piece_field(w + b, i - b);
        b = i;
    }
    return field;
}

/* An identifier names a wallet-private field when one of its pieces is a
 * field name and none of its pieces is a count, size or kind descriptor. */
static int wlp_names_field(const char *t, size_t n)
{
    int field = 0, exempt = 0;
    size_t b = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i < n && t[i] != '_')
            continue;
        if (wlp_exempt_word(t + b, i - b))
            return 0;
        field |= wlp_word_names_field(t + b, i - b, &exempt);
        b = i + 1;
    }
    return field && !exempt;
}

static size_t wlp_skip_ws(const char *s, size_t n, size_t i)
{
    while (i < n && (s[i] == ' ' || s[i] == '\t'))
        i++;
    return i;
}

/* Index just past the balanced group that opens at s[i]. */
static size_t wlp_skip_group(const char *s, size_t n, size_t i)
{
    int depth = 0;
    for (; i < n; i++) {
        if (s[i] == '(')
            depth++;
        else if (s[i] == ')' && --depth == 0)
            return i + 1;
    }
    return n;
}

/* First identifier in an argument list that names a wallet-private field,
 * or NULL. The operands of sizeof() and strlen() are sizes, not values. */
static const char *wlp_first_field(const char *s, size_t n, size_t *len)
{
    size_t i = 0;
    while (i < n) {
        if (!lintc_ident_start((unsigned char)s[i])) {
            i++;
            continue;
        }
        size_t b = i;
        while (i < n && lintc_ident_char((unsigned char)s[i]))
            i++;
        if (wlp_eq(s + b, i - b, "sizeof") || wlp_eq(s + b, i - b, "strlen")) {
            i = wlp_skip_ws(s, n, i);
            if (i < n && s[i] == '(')
                i = wlp_skip_group(s, n, i);
            continue;
        }
        if (wlp_names_field(s + b, i - b)) {
            *len = i - b;
            return s + b;
        }
    }
    return NULL;
}

static int wlp_is_log(const char *t, size_t n, int *guard)
{
    *guard = n >= 5 && memcmp(t, "GUARD", 5) == 0;
    if (*guard || (n >= 4 && memcmp(t, "LOG_", 4) == 0)
        || (n >= 8 && memcmp(t, "ZCL_LOG_", 8) == 0))
        return 1;
    return wlp_eq(t, n, "printf") || wlp_eq(t, n, "fprintf")
        || wlp_eq(t, n, "fputs") || wlp_eq(t, n, "puts")
        || wlp_eq(t, n, "event_emitf");
}

static int wlp_next_is_paren(const char *code, size_t e)
{
    while (code[e] == ' ' || code[e] == '\t')
        e++;
    return code[e] == '(';
}

static int wlp_has_marker(const char *raw)
{
    static const char k_marker[] = "wallet-log-ok:";
    const char *p = raw;
    while ((p = strstr(p, k_marker)) != NULL) {
        p += sizeof k_marker - 1;
        if (isalpha((unsigned char)p[0])
            && (isalnum((unsigned char)p[1]) || p[1] == '-' || p[1] == '_'))
            return 1;
    }
    return 0;
}

static void wlp_put(char *buf, size_t *len, const char *s, size_t n,
                    int *overflow)
{
    if (*len + n >= WLP_CALL) {
        *overflow = 1;
        return;
    }
    memcpy(buf + *len, s, n);
    *len += n;
    buf[*len] = '\0';
}

static void wlp_raw(struct wlp_st *st, const char *raw)
{
    wlp_put(st->raw, &st->raw_len, raw, strlen(raw), &st->overflow);
    wlp_put(st->raw, &st->raw_len, "\n", 1, &st->overflow);
}

static int wlp_record(struct wlp_st *st)
{
    char key[LB_KEY];
    int m = snprintf(key, sizeof key, "%s::%s", st->path, st->func);
    if (m < 0 || (size_t)m >= sizeof key) {
        fprintf(stderr, "check-wallet-log-privacy: FATAL — key over %d bytes\n",
                (int)LB_KEY);
        return 2;
    }
    struct wlp_tally *t = st->tally;
    for (int i = 0; i < t->n; i++) {
        if (strcmp(t->key[i], key) == 0) {
            t->count[i]++;
            return 0;
        }
    }
    if (t->n >= WLP_KEYS) {
        fprintf(stderr, "check-wallet-log-privacy: FATAL — more than %d functions\n",
                (int)WLP_KEYS);
        return 2;
    }
    memcpy(t->key[t->n], key, (size_t)m + 1);
    t->count[t->n] = 1;
    t->n++;
    return 0;
}

static int wlp_flag(struct wlp_st *st, const char *tok, size_t tl)
{
    if (st->out)
        fprintf(st->out, "%s:%d: log call passes wallet-private field '%.*s' "
                "(log a count, size, height, error code or kind instead, or "
                "mark the call with a wallet-log-ok reason)\n",
                st->path, st->start_line, (int)tl, tok);
    return wlp_record(st);
}

/* A field word that ends at s[e]: the word a conversion follows. */
static int wlp_fmt_word(const char *s, size_t e, const char **hit, size_t *hl)
{
    size_t b = e;
    while (b > 0 && lintc_ident_char((unsigned char)s[b - 1]))
        b--;
    if (b == e || !wlp_names_field(s + b, e - b))
        return 0;
    *hit = s + b;
    *hl = e - b;
    return 1;
}

/* Separators between a field word and a conversion: blanks, '=', ':', quotes,
 * an opening parenthesis or bracket, and the backslash of an escaped quote. */
static int wlp_fmt_sep(char c)
{
    return c == ' ' || c == '\t' || c == '=' || c == ':' || c == '\'' ||
           c == '"' || c == '(' || c == '[' || c == '\\';
}

/* A field word directly before a conversion, across those separators
 * ("address %s", "address '%s'", "address (%s)"). "%%" is not a conversion.
 * A conversion that follows a word, as in "%s is not an address", is not
 * matched: "%d notes" is a count label and the same rule would flag it. */
static int wlp_fmt_names_field(const char *s, size_t n, const char **hit,
                               size_t *hl)
{
    for (size_t i = 0; i < n; i++) {
        if (s[i] != '%')
            continue;
        if (i + 1 < n && s[i + 1] == '%') {
            i++;
            continue;
        }
        size_t e = i;
        while (e > 0 && wlp_fmt_sep(s[e - 1]))
            e--;
        if (wlp_fmt_word(s, e, hit, hl))
            return 1;
    }
    return 0;
}

/* Scans the string literals of the call text for a field name. Literal
 * contents are not in code, so this reads raw. Adjacent literals ("address "
 * "%s") are one string and join before the scan; a literal separated by a
 * comma or other token is its own string. */
static int wlp_literals_name_field(const char *raw, const char **hit,
                                   size_t *hl)
{
    /* Static: *hit points here, and the caller reads it after this returns. */
    static char body[WLP_CALL];
    size_t bl = 0;
    const char *p = raw;
    while ((p = strchr(p, '"')) != NULL) {
        const char *b = ++p;
        while (*p && *p != '"')
            p += (*p == '\\' && p[1]) ? 2 : 1;
        if (*p == '\0')
            return 0;
        memcpy(body + bl, b, (size_t)(p - b));
        bl += (size_t)(p - b);
        p++;
        const char *q = p;
        while (*q == ' ' || *q == '\t' || *q == '\n')
            q++;
        if (*q == '"') {
            p = q;
            continue;
        }
        if (wlp_fmt_names_field(body, bl, hit, hl))
            return 1;
        bl = 0;
    }
    return wlp_fmt_names_field(body, bl, hit, hl);
}

/* Index in code of the first logged argument: after the macro's open
 * parenthesis, or after the first top-level comma for a GUARD macro. */
static size_t wlp_args_start(const struct wlp_st *st)
{
    size_t i = st->open_at + 1;
    if (!st->guard)
        return i;
    int d = 0;
    for (; i < st->code_len; i++) {
        if (st->code[i] == '(')
            d++;
        else if (st->code[i] == ')')
            d--;
        else if (st->code[i] == ',' && d == 0)
            return i + 1;
    }
    return st->code_len;
}

static int wlp_finish(struct wlp_st *st)
{
    if (wlp_has_marker(st->raw))
        return 0;
    if (st->overflow)
        return wlp_flag(st, "overlong-call", 13);
    size_t from = wlp_args_start(st);
    size_t tl = 0;
    const char *hit = wlp_first_field(st->code + from, st->code_len - from, &tl);
    if (hit)
        return wlp_flag(st, hit, tl);
    if (st->call_at < st->raw_len
        && wlp_literals_name_field(st->raw + st->call_at, &hit, &tl))
        return wlp_flag(st, hit, tl);
    return 0;
}

/* Feeds one character of a call; returns nonzero on a fatal error. */
static int wlp_call_char(struct wlp_st *st, char c)
{
    wlp_put(st->code, &st->code_len, &c, 1, &st->overflow);
    if (c == '(') {
        if (st->depth++ == 0)
            st->open_at = st->code_len - 1;
    } else if (c == ')' && --st->depth == 0) {
        st->in_stmt = 0;
        return wlp_finish(st);
    }
    return 0;
}

static void wlp_begin(struct wlp_st *st, const char *tok, size_t tl, int guard)
{
    st->in_stmt = 1;
    st->depth = 0;
    st->open_at = 0;
    st->guard = guard;
    st->overflow = 0;
    st->code_len = 0;
    st->code[0] = '\0';
    st->raw_len = 0;
    st->raw[0] = '\0';
    st->start_line = st->lineno;
    st->tally->calls++;
    wlp_put(st->code, &st->code_len, tok, tl, &st->overflow);
}

/* Consumes code[*i] (inside a call) or one identifier (outside), and
 * advances *i past it. Returns nonzero on a fatal error. */
static int wlp_step(struct wlp_st *st, const char *code, const char *raw,
                    size_t *i)
{
    size_t b = *i;
    if (st->in_stmt) {
        *i = b + 1;
        return wlp_call_char(st, code[b]);
    }
    if (!lintc_ident_start((unsigned char)code[b])) {
        *i = b + 1;
        return 0;
    }
    size_t e = b;
    while (lintc_ident_char((unsigned char)code[e]))
        e++;
    *i = e;
    int guard = 0;
    if (wlp_is_log(code + b, e - b, &guard) && wlp_next_is_paren(code, e)) {
        wlp_begin(st, code + b, e - b, guard);
        wlp_raw(st, raw);
        st->call_at = b;
    }
    return 0;
}

static int wlp_keyword(const char *w, size_t n)
{
    return wlp_in(w, n, k_wlp_keywords, sizeof k_wlp_keywords / sizeof k_wlp_keywords[0]);
}

/* A definition line at column 0 names the enclosing function. */
static void wlp_track_func(struct wlp_st *st, const char *code)
{
    const char *p = strchr(code, '(');
    if (!lintc_ident_start((unsigned char)code[0]) || p == NULL
        || strchr(code, ';') != NULL)
        return;
    size_t e = (size_t)(p - code);
    size_t b = e;
    while (b > 0 && lintc_ident_char((unsigned char)code[b - 1]))
        b--;
    if (b == e || e - b >= sizeof st->func || wlp_keyword(code + b, e - b))
        return;
    memcpy(st->func, code + b, e - b);
    st->func[e - b] = '\0';
}

static int wlp_preprocessor(const char *code)
{
    while (*code == ' ' || *code == '\t')
        code++;
    return *code == '#';
}

static int wlp_line(struct wlp_st *st, const char *raw)
{
    char code[CSTRIP_LINE_MAX];
    size_t n = strlen(raw);
    st->lineno++;
    if (n >= sizeof code) {
        fprintf(stderr, "check-wallet-log-privacy: FATAL — source line longer "
                "than %d bytes\n", (int)sizeof code);
        return 2;
    }
    (void)cstrip_line(&st->cs, raw, n, code, sizeof code);
    code[n] = '\0';
    if (st->in_stmt) {
        wlp_raw(st, raw);
    } else {
        if (wlp_preprocessor(code))
            return 0;
        wlp_track_func(st, code);
    }
    for (size_t i = 0; i < n;) {
        int rc = wlp_step(st, code, raw, &i);
        if (rc)
            return rc;
    }
    return 0;
}

static int wlp_scan_file(const char *path, void *ctx)
{
    struct wlp_st st;
    memset(&st, 0, sizeof st);
    st.tally = ctx;
    st.out = stderr;
    st.path = path;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("check-wallet-log-privacy: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        rc = wlp_line(&st, line);
    }
    return fin(f, line, path, rc);
}

/* Observes every scanned function against the loaded pins. */
static void wlp_observe(const struct wlp_tally *t)
{
    for (int i = 0; i < t->n; i++)
        (void)lint_base_observe(&g_wlp_base, t->key[i], t->count[i]);
}

/* UPDATE lowers pins and deletes retired ones, as --tighten-baseline does
 * in the complexity gate. It never adds a pin, so a new function still
 * fails the verdict. */
static int wlp_update(const struct wlp_tally *t)
{
    int lowered, deleted, kept;
    if (lint_base_load(&g_wlp_base, k_wlp_base, stderr))
        return 2;
    wlp_observe(t);
    if (lint_base_tighten(&g_wlp_base, 0, &lowered, &deleted, &kept))
        return 2;
    if (lint_base_write(&g_wlp_base, k_wlp_base, k_wlp_hdr))
        return 2;
    printf("check_wallet_log_privacy: tightened %s — lowered=%d deleted=%d "
           "kept=%d\n", k_wlp_base, lowered, deleted, kept);
    return 0;
}

/* Exact pins: a pin above the current count fails too, so a freed slot
 * cannot admit a new call until the pin is lowered. */
static int wlp_shrunk(void)
{
    int viol = 0;
    for (int i = 0; i < g_wlp_base.n; i++) {
        const struct lb_row *r = &g_wlp_base.row[i];
        if (r->seen && r->cur < r->pinned) {
            fprintf(stderr, "check_wallet_log_privacy: SHRUNK %s pinned at %d "
                    "but now %d; run %s\n", r->key, r->pinned, r->cur,
                    k_wlp_hint);
            viol++;
        }
    }
    return viol;
}

static int wlp_verdict(const struct wlp_tally *t)
{
    if (lint_base_load(&g_wlp_base, k_wlp_base, stderr))
        return 2;
    int viol = 0;
    for (int i = 0; i < t->n; i++) {
        if (lint_base_observe(&g_wlp_base, t->key[i], t->count[i]) < 0) {
            fprintf(stderr, "check_wallet_log_privacy: NEW %s passes %d "
                    "wallet-private field argument(s); not in the baseline\n",
                    t->key[i], t->count[i]);
            viol++;
        }
    }
    int pinned = lint_base_finish(&g_wlp_base, stderr, stdout, 0, k_wlp_hint);
    if (pinned < 0)
        return 2;
    viol += pinned + wlp_shrunk();
    if (viol) {
        fprintf(stderr, "check_wallet_log_privacy: FAIL — %d violation(s)\n", viol);
        return 1;
    }
    printf("check_wallet_log_privacy: OK — %d log call(s) scanned, "
           "%d function(s) baselined\n", t->calls, t->n);
    return 0;
}

int check_wallet_log_privacy_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    struct wlp_tally *t = &g_wlp_tally;
    memset(t, 0, sizeof *t);
    int rc = walk_src_root("check_wallet_log_privacy", k_wlp_root, 1,
                           wlp_scan_file, t);
    if (rc)
        return rc;
    if (t->calls == 0)
        return die("check_wallet_log_privacy: FATAL — no log call found under %s "
                   "(the gate would pass vacuously)\n", k_wlp_root);
    const char *mode = getenv("ZCL_LINT_MODE");
    if (mode && strcmp(mode, "UPDATE") == 0)
        return wlp_update(t);
    return wlp_verdict(t);
}

/* ── selftest ───────────────────────────────────────────────────────── */

struct wlp_fixture {
    const char *tag;
    int want;
    const char *lines[4];
};

static const struct wlp_fixture k_wlp_fixtures[] = {
    {"count argument", 0, {"LOG_WARN(\"wallet\", \"rescan %d blocks\", blocks);", NULL}},
    {"fixed message with address word", 1, {"LOG_FAIL(\"wallet\", \"address %s is bad\", \"x\");", NULL}},
    {"format word address with buf", 1, {"LOG_FAIL(\"w\", \"address %s\", buf);", NULL}},
    {"camel-case addrStr", 1, {"LOG_FAIL(\"w\", \"bad %s\", addrStr);", NULL}},
    {"memo_bytes is a field", 1, {"LOG_WARN(\"w\", \"%zu\", memo_bytes);", NULL}},
    {"txid_bytes is a field", 1, {"LOG_WARN(\"w\", \"%zu\", txid_bytes);", NULL}},
    {"nValue is a field", 1, {"LOG_WARN(\"w\", \"%lld\", nValue);", NULL}},
    {"all-caps ADDR_BYTES constant", 0, {"LOG_WARN(\"w\", \"%zu\", ADDR_BYTES);", NULL}},
    {"lower-case nnotes count", 0, {"LOG_WARN(\"w\", \"%d\", nnotes);", NULL}},
    {"camel-case addrCount", 0, {"LOG_WARN(\"w\", \"%d\", addrCount);", NULL}},
    {"bal word", 1, {"LOG_INFO(\"w\", \"bal %lld\", bal);", NULL}},
    {"importprivkey balance line", 1, {"printf(\"importprivkey: %d UTXOs, balance %.8f ZCL (instant)\\n\", found, (double)bal / 1e8);", NULL}},
    {"percent-percent is not a conversion", 0, {"LOG_INFO(\"w\", \"100%% address ok\");", NULL}},
    {"phrase word before conversion", 1, {"LOG_FAIL(\"w\", \"phrase %s\", mnemonic);", NULL}},
    {"key word before spending_key", 1, {"LOG_FAIL(\"w\", \"key %s\", spending_key);", NULL}},
    {"passphrase argument", 1, {"LOG_WARN(\"w\", \"%s\", passphrase);", NULL}},
    {"secret argument", 1, {"LOG_WARN(\"w\", \"%s\", secret);", NULL}},
    {"xsk argument", 1, {"LOG_WARN(\"w\", \"%s\", xsk);", NULL}},
    {"evidence argument", 1, {"LOG_ERROR(\"w\", \"%s: %s\", code, evidence);", NULL}},
    {"evidence word before conversion", 1, {"LOG_ERROR(\"w\", \"evidence %s\", code);", NULL}},
    {"quoted address conversion", 1, {"LOG_FAIL(\"w\", \"address '%s'\", buf);", NULL}},
    {"parenthesised address conversion", 1, {"LOG_FAIL(\"w\", \"address (%s)\", buf);", NULL}},
    {"split literal address", 1, {"LOG_FAIL(\"w\", \"address \"", "    \"%s\", buf);", NULL}},
    {"comma-separated literals are not joined", 0, {"LOG_FAIL(\"w\", \"address\", \"%s\");", NULL}},
    {"fixed message with phrase word", 0, {"LOG_INFO(\"w\", \"recovery phrase failed validation\");", NULL}},
    {"lower-case nvalue is a field", 1, {"LOG_WARN(\"w\", \"%lld\", nvalue);", NULL}},
    {"lower-case plural nnotes count", 0, {"LOG_WARN(\"w\", \"%d\", nnotes);", NULL}},
    {"address variable", 1, {"LOG_FAIL(\"wallet\", \"invalid address %s\", addr_str);", NULL}},
    {"amount cast", 1, {"LOG_WARN(\"wallet\", \"amount %lld\", (long long)amount);", NULL}},
    {"multi-line leak", 1, {"LOG_INFO(\"wallet\",", "    \"rescan %s\", zaddr);", NULL}},
    {"multi-line clean", 0, {"LOG_INFO(\"wallet\",", "    \"rescan %d\", count);", NULL}},
    {"comment is not code", 0, {"// LOG_FAIL(\"wallet\", \"%s\", addr);", NULL}},
    {"snprintf is not a log", 0, {"(void)snprintf(out, n, \"%s\", addr);", NULL}},
    {"sizeof operand", 0, {"LOG_WARN(\"wallet\", \"buf %zu\", sizeof(addr_buf));", NULL}},
    {"count word", 0, {"LOG_WARN(\"wallet\", \"%d\", addr_count);", NULL}},
    {"reviewed marker", 0, {"LOG_FAIL(\"zid\", \"NULL (seed=%p)\", (void *)seed); // wallet-log-ok:pointer-values-only", NULL}},
    {"empty marker is not a reason", 1, {"LOG_FAIL(\"w\", \"%s\", addr); // wallet-log-ok:", NULL}},
    {"guard condition", 0, {"GUARD(addr != NULL, \"wallet\", \"addr missing\");", NULL}},
    {"guard value", 1, {"GUARD(ok, \"wallet\", \"addr %s\", addr);", NULL}},
    {"printf balance", 1, {"printf(\"balance %.8f\\n\", (double)balance / 1e8);", NULL}},
    {"event txid", 1, {"event_emitf(EV_WALLET_TX_SAVED, 0, \"txid=%s\", txid_hex);", NULL}},
    {"member field", 1, {"LOG_WARN(\"wallet\", \"receive to %s\", t->address);", NULL}},
    {"state and height words", 0, {"LOG_INFO(\"wallet\", \"seed_state=%d height=%d\", seed_state, h);", NULL}},
    {"kind word", 0, {"LOG_FAIL(\"wallet\", \"kind %d\", addr_kind);", NULL}},
    {"prefix is not a log macro", 0, {"MYLOG_FAIL(\"wallet\", \"%s\", addr);", NULL}},
    {"space before parenthesis", 1, {"LOG_FAIL (\"wallet\", \"%s\", addr);", NULL}},
    {"note count", 0, {"LOG_INFO(\"wallet\", \"%d notes\", num_notes);", NULL}},
    {"preprocessor definition", 0, {"#define LOG_FAIL(domain, fmt, ...) do { addr; } while (0)", NULL}},
    {"nested call before field", 1, {"LOG_WARN(\"wallet\", \"x %d\", f(a, (b)), value);", NULL}},
};

static int wlp_fixture_run(const struct wlp_fixture *fx)
{
    static struct wlp_tally t;
    struct wlp_st st;
    memset(&t, 0, sizeof t);
    memset(&st, 0, sizeof st);
    st.tally = &t;
    st.path = "contexts/wallet/selftest.c";
    int rc = 0;
    for (size_t i = 0; fx->lines[i] && rc == 0; i++)
        rc = wlp_line(&st, fx->lines[i]);
    int got = 0;
    for (int k = 0; k < t.n; k++)
        got += t.count[k];
    if (rc || got != fx->want) {
        fprintf(stderr, "check_wallet_log_privacy selftest: %s: want %d, got %d\n",
                fx->tag, fx->want, got);
        return 1;
    }
    return 0;
}

int check_wallet_log_privacy_selftest(void)
{
    int bad = 0;
    for (size_t i = 0; i < sizeof k_wlp_fixtures / sizeof k_wlp_fixtures[0]; i++)
        bad |= wlp_fixture_run(&k_wlp_fixtures[i]);
    return st_ok(bad, "check_wallet_log_privacy selftest: OK\n");
}
