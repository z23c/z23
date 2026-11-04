/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: alias expansion for `code have` query terms. A short acronym and
 * the words it abbreviates name the same thing in different files (mmr.c vs
 * "Merkle Mountain Range"); a question uses one, the code the other. */

#include "codeindex_capability_alias.h"

#include <stdio.h>
#include <string.h>

/* Synonym sets over STEMMED words. Any member of a set found in the query
 * brings the other members in as alternates for that same term. */
static const char *const alias_sets[][5] = {
    { "pq", "quantum", "mlkem", "kyber", NULL },
    { "kem", "encapsul", "mlkem", NULL },
    { "mmr", "mountain", NULL },
    { "shell", "terminal", NULL },
    { "utxo", "unspent", "coin", NULL },
};

/* An abbreviation for a phrase. When every word of the phrase is in the
 * query, the abbreviation is an alternate for each of those words. */
static const struct { const char *abbr; const char *words[4]; } alias_phrases[] = {
    { "mmr", { "merkle", "mountain", "range", NULL } },
    { "psk", { "pre", "shar", "key", NULL } },
    { "kem", { "key", "encapsul", NULL } },
    { "pq",  { "post", "quantum", NULL } },
};

static bool has_stem(char stems[][CI_CAPABILITY_TERM_MAX], int n,
                     const char *w)
{
    for (int i = 0; i < n; i++)
        if (strcmp(stems[i], w) == 0) return true;
    return false;
}

static int add_alt(char stems[][CI_CAPABILITY_TERM_MAX], unsigned char *grp,
                   int n, const char *w, int term)
{
    if (n >= CI_CAP_STEM_CAP || has_stem(stems, n, w)) return n;
    snprintf(stems[n], CI_CAPABILITY_TERM_MAX, "%s", w);
    grp[n] = (unsigned char)term;
    return n + 1;
}

static int expand_sets(char stems[][CI_CAPABILITY_TERM_MAX],
                       unsigned char *grp, int n, int nbase)
{
    for (int t = 0; t < nbase; t++) {
        for (size_t s = 0; s < sizeof(alias_sets) / sizeof(alias_sets[0]); s++) {
            bool in = false;
            for (int m = 0; alias_sets[s][m]; m++)
                if (strcmp(alias_sets[s][m], stems[t]) == 0) in = true;
            for (int m = 0; in && alias_sets[s][m]; m++)
                n = add_alt(stems, grp, n, alias_sets[s][m], t);
        }
    }
    return n;
}

static int expand_phrases(char stems[][CI_CAPABILITY_TERM_MAX],
                          unsigned char *grp, int n, int nbase)
{
    for (size_t p = 0; p < sizeof(alias_phrases) / sizeof(alias_phrases[0]); p++) {
        int at[4];
        int w = 0;
        for (; alias_phrases[p].words[w]; w++) {
            at[w] = -1;
            for (int t = 0; t < nbase; t++)
                if (strcmp(stems[t], alias_phrases[p].words[w]) == 0) at[w] = t;
            if (at[w] < 0) break;
        }
        if (alias_phrases[p].words[w]) continue;   /* a word is missing */
        for (int k = 0; k < w; k++)
            n = add_alt(stems, grp, n, alias_phrases[p].abbr, at[k]);
    }
    return n;
}

int ci_cap_alias_expand(const char base[][CI_CAPABILITY_TERM_MAX], int nbase,
                        char stems[][CI_CAPABILITY_TERM_MAX],
                        unsigned char *grp)
{
    for (int t = 0; t < nbase; t++) {
        snprintf(stems[t], CI_CAPABILITY_TERM_MAX, "%s", base[t]);
        grp[t] = (unsigned char)t;
    }
    int n = expand_phrases(stems, grp, nbase, nbase);
    return expand_sets(stems, grp, n, nbase);
}
