/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the wallet-owner half of check-raw-sqlite
 * (gate_raw_sqlite.c). Wallet projection tables are owned by their
 * models: controllers and services may not reconstruct direct wallet-table
 * DML, and controllers may not invoke the destructive model APIs because
 * the scan Service owns atomic replacement. Each controller/service room
 * source is comment-stripped (string literal CONTENT kept, as the awk
 * original did), lower-cased, and stripped of quotes and whitespace, so
 * the rule judges the SQL consequence rather than one spelling. The
 * bracket pattern replicates the shell glob delete-from-[chars-of-table]
 * exactly: one character drawn from the table name's own letters.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_raw_sqlite_priv.h"

static char g_crs_acc[CRS_ACC];

static const char *const k_crs_tables[] = {
    "wallet_utxos", "wallet_transactions", "wallet_sapling_notes"
};

/* Copy one quoted literal starting at line[*i] (quote included) to out. */
static void crs_ctx_literal(const char *line, size_t n, size_t *i, char *out,
                            size_t *o)
{
    char q = line[*i];
    out[(*o)++] = line[(*i)++];
    while (*i < n) {
        if (line[*i] == '\\' && *i + 1 < n) {
            out[(*o)++] = line[*i];
            out[(*o)++] = line[*i + 1];
            *i += 2;
            continue;
        }
        out[(*o)++] = line[*i];
        (*i)++;
        if (line[*i - 1] == q)
            break;
    }
}

/* Inside a block comment: skip to the closing marker. */
static void crs_ctx_skip_block(const char *line, size_t n, size_t *i,
                               int *inblk)
{
    if (*i + 1 < n && line[*i] == '*' && line[*i + 1] == '/') {
        *inblk = 0;
        *i += 2;
    } else {
        (*i)++;
    }
}

/* Strip comments from one line, keeping literal contents (both quote
 * kinds), block-comment state carried across lines of the same file. */
static void crs_ctx_norm_line(const char *line, char *out, int *inblk)
{
    size_t i = 0, o = 0, n = strlen(line);
    while (i < n) {
        char two = i + 1 < n ? line[i + 1] : '\0';
        if (*inblk) {
            crs_ctx_skip_block(line, n, &i, inblk);
        } else if (line[i] == '/' && two == '*') {
            out[o++] = ' ';
            *inblk = 1;
            i += 2;
        } else if (line[i] == '/' && two == '/') {
            out[o++] = ' ';
            break;
        } else if (line[i] == '"' || line[i] == '\'') {
            crs_ctx_literal(line, n, &i, out, &o);
        } else {
            out[o++] = line[i++];
        }
    }
    out[o] = '\0';
}

/* Lower-case, drop quotes and every whitespace char, append to the
 * accumulator. Overflow of the fixed accumulator is fatal. */
static int crs_ctx_append(const char *s, size_t *len)
{
    for (size_t i = 0; s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || isspace(c))
            continue;
        if (*len + 1 >= CRS_ACC)
            return CRS_FATAL;
        g_crs_acc[(*len)++] = (char)tolower(c);
    }
    return 0;
}

/* needle = a + b contained in n; the pieces are fixed short strings. */
static int crs_has2(const char *n, const char *a, const char *b)
{
    char needle[128];
    if (ovf(snprintf(needle, sizeof needle, "%s%s", a, b), sizeof needle))
        return 0;
    return strstr(n, needle) != NULL;
}

/* pre occurs, and somewhere after it needle2 (built from pre2 + table). */
static int crs_then(const char *n, const char *pre, const char *pre2,
                    const char *t)
{
    char needle2[128];
    if (ovf(snprintf(needle2, sizeof needle2, "%s%s", pre2, t),
            sizeof needle2))
        return 0;
    const char *p = strstr(n, pre);
    while (p != NULL) {
        if (strstr(p + strlen(pre), needle2))
            return 1;
        p = strstr(p + 1, pre);
    }
    return 0;
}

/* delete-from-[table]: the shell pattern quoted the bracket, so it is the
 * literal text, not a character class. */
static int crs_pat_bracket(const char *n, const char *t)
{
    char needle[128];
    if (ovf(snprintf(needle, sizeof needle, "deletefrom[%s]", t),
            sizeof needle))
        return 0;
    return strstr(n, needle) != NULL;
}

static int crs_table_pat(const char *n, const char *t)
{
    if (crs_has2(n, "deletefrom", t) || crs_has2(n, "deletefrommain.", t))
        return 1;
    if (crs_pat_bracket(n, t))
        return 1;
    if (crs_has2(n, "insertinto", t) || crs_has2(n, "replaceinto", t))
        return 1;
    if (crs_then(n, "insertor", "into", t))
        return 1;
    if (crs_has2(n, "update", t))
        return 1;
    return crs_then(n, "updateor", "", t);
}

static int crs_destructive(const char *n)
{
    return strstr(n, "db_wallet_utxo_delete_all") != NULL ||
           strstr(n, "db_wallet_tx_delete_all") != NULL ||
           strstr(n, "db_sapling_note_delete_all") != NULL;
}

static void crs_ctx_check(const char *path, struct crs_viol *v)
{
    for (size_t i = 0; i < sizeof k_crs_tables / sizeof k_crs_tables[0]; i++)
        if (crs_table_pat(g_crs_acc, k_crs_tables[i]))
            crs_viol_add(v, "%s: wallet projection DML for %s; call its "
                         "model API", path, k_crs_tables[i]);
    if (strstr(path, "/controllers/") && crs_destructive(g_crs_acc))
        crs_viol_add(v, "%s: Controller owns destructive wallet model call; "
                     "delegate atomic replacement to the wallet scan Service",
                     path);
}

int crs_ctx_file(const char *path, struct crs_viol *v)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return CRS_FATAL;
    static char line[CRS_LINE], out[CRS_LINE];
    size_t len = 0;
    int inblk = 0;
    int rc = 0;
    while (rc == 0 && fgets(line, sizeof line, f)) {
        if (crs_overlong(line)) {
            rc = CRS_FATAL;
            break;
        }
        crs_chomp(line);
        crs_ctx_norm_line(line, out, &inblk);
        rc = crs_ctx_append(out, &len);
    }
    if (ferror(f))
        rc = CRS_FATAL;
    fclose(f);
    if (rc == CRS_FATAL) {
        fprintf(stderr, "check_raw_sqlite: FATAL — wallet-owner "
                "normalization failed (rc=2) on %s\n", path);
        return 2;
    }
    g_crs_acc[len] = '\0';
    crs_ctx_check(path, v);
    return 0;
}

struct crs_ctx_walk {
    int count;
    struct crs_viol *v;
};

static int crs_ctx_walk_fn(const char *path, void *ctx)
{
    struct crs_ctx_walk *w = ctx;
    if (!crs_ends_ch(path))
        return 0;
    w->count++;
    return crs_ctx_file(path, w->v);
}

static int crs_room_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

/* controllers + services rooms, sorted and unique, like the shell
 * command-substitution sort -u. */
static int crs_ctx_rooms(char rooms[][RS_PATH])
{
    int cnt = 0, cnt2 = 0;
    if (repo_shape_room_dirs("controllers", rooms, CRS_ROOMS, &cnt) != 0 ||
        cnt <= 0 || cnt > CRS_ROOMS)
        return -1;
    if (repo_shape_room_dirs("services", rooms + cnt, CRS_ROOMS - cnt,
                             &cnt2) != 0 ||
        cnt2 <= 0 || cnt + cnt2 > CRS_ROOMS)
        return -1;
    int n = cnt + cnt2;
    qsort(rooms, (size_t)n, RS_PATH, crs_room_cmp);
    int w = 0;
    for (int i = 0; i < n; i++) {
        if (w > 0 && strcmp(rooms[w - 1], rooms[i]) == 0)
            continue;
        if (w != i)
            memcpy(rooms[w], rooms[i], RS_PATH);
        w++;
    }
    return w;
}

int crs_scan_context(struct crs_viol *v)
{
    static char rooms[CRS_ROOMS][RS_PATH];
    int n = crs_ctx_rooms(rooms);
    if (n <= 0)
        return 2;
    struct crs_ctx_walk w = { 0, v };
    for (int i = 0; i < n; i++) {
        int rc = crs_walk(rooms[i], 0, crs_ctx_walk_fn, &w);
        if (rc == CRS_FATAL) {
            fprintf(stderr, "check_raw_sqlite: FATAL — wallet-owner source "
                    "enumeration failed (find=%d)\n", rc);
            return 2;
        }
        if (rc)
            return rc;
    }
    if (gate_require_scanned(w.count, 2, "check_raw_sqlite.wallet_owner",
                             "expected controller and service C/header "
                             "sources") != 0)
        return 2;
    return 0;
}
