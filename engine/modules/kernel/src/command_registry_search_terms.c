/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * discover.search term scoring. A query is split on non-alphanumerics, stop
 * words are dropped, and each remaining word is suffix-stemmed. A command
 * scores the sum, over query words, of the heaviest field that holds the word
 * (path or alias, then tags, summary, semantics); words from a vocabulary
 * group in command_registry_search_synonyms.def count at half weight. A
 * command matching every word earns a coverage bonus. No word is required. */

#include "command_registry_internal.h"

#include <ctype.h>
#include <string.h>

#define SEARCH_WEIGHT_PATH 200
#define SEARCH_WEIGHT_TAG 120
#define SEARCH_WEIGHT_SUMMARY 60
#define SEARCH_WEIGHT_SEMANTICS 16
#define SEARCH_COVERAGE_BONUS 100

static const char *const STOP_WORDS[] = {
    "a",  "an",   "and", "any", "at",   "by",   "for",  "from",
    "how", "i",   "in",  "into", "is",  "it",   "me",   "my",
    "of", "on",   "or",  "the", "this", "that", "to",   "with"};

static const char *const SYNONYM_GROUPS[] = {
#define SEARCH_SYNONYM_GROUP(words) words,
#include "command_registry_search_synonyms.def"
#undef SEARCH_SYNONYM_GROUP
};

/* Copy the next alphanumeric run of *p into out, lowercased. Returns its
 * length, or 0 at the end of the text. Runs longer than the buffer are cut. */
static size_t next_word(const char **p, char out[SEARCH_WORD_MAX])
{
    const unsigned char *s = (const unsigned char *)*p;
    while (*s && !isalnum(*s))
        s++;
    size_t n = 0;
    while (isalnum(*s)) {
        if (n + 1 < SEARCH_WORD_MAX)
            out[n++] = (char)tolower(*s);
        s++;
    }
    out[n] = 0;
    *p = (const char *)s;
    return n;
}

static bool ends_with(const char *w, size_t n, const char *suffix)
{
    size_t k = strlen(suffix);
    return n > k && memcmp(w + n - k, suffix, k) == 0;
}

/* Strip one inflection (ies, ing, ed, es, s) and a final e, keeping at
 * least four characters after -ing, -ed and -es removal. Applied to query
 * and registry words alike, so only equality of stems matters. */
void command_registry_search_stem(char *w)
{
    size_t n = strlen(w);
    if (ends_with(w, n, "ies") && n > 4) {
        w[n - 3] = 'y';
        n -= 2;
    } else if (ends_with(w, n, "ing") && n - 3 >= 4) {
        n -= 3;
    } else if (ends_with(w, n, "ed") && n - 2 >= 4) {
        n -= 2;
    } else if (ends_with(w, n, "es") && n - 2 >= 4 &&
               strchr("sxz", w[n - 3])) {
        n -= 2;
    } else if (n > 3 && w[n - 1] == 's' && w[n - 2] != 's') {
        n -= 1;
    }
    if (n > 3 && w[n - 1] == 'e')
        n -= 1;
    w[n] = 0;
}

static bool is_stop_word(const char *w)
{
    for (size_t i = 0; i < sizeof STOP_WORDS / sizeof STOP_WORDS[0]; i++)
        if (strcmp(w, STOP_WORDS[i]) == 0)
            return true;
    return false;
}

static bool group_has_stem(const char *group, const char *stem)
{
    char word[SEARCH_WORD_MAX];
    while (next_word(&group, word)) {
        command_registry_search_stem(word);
        if (strcmp(word, stem) == 0)
            return true;
    }
    return false;
}

static void add_slot(struct search_query *q, const char *stem, size_t term,
                     bool syn)
{
    for (size_t i = 0; i < q->slots; i++)
        if (q->slot[i].term == term && strcmp(q->slot[i].stem, stem) == 0)
            return;
    if (q->slots >= SEARCH_SLOTS_MAX)
        return;
    struct search_slot *s = &q->slot[q->slots++];
    memcpy(s->stem, stem, strlen(stem) + 1);
    q->first[(unsigned char)stem[0] & 127U] = true;
    s->term = term;
    s->syn = syn;
}

static void add_synonyms(struct search_query *q, size_t term)
{
    char stem[SEARCH_WORD_MAX];
    memcpy(stem, q->slot[term].stem, sizeof stem);
    for (size_t g = 0; g < sizeof SYNONYM_GROUPS / sizeof SYNONYM_GROUPS[0];
         g++) {
        if (!group_has_stem(SYNONYM_GROUPS[g], stem))
            continue;
        const char *rest = SYNONYM_GROUPS[g];
        char word[SEARCH_WORD_MAX];
        while (next_word(&rest, word)) {
            command_registry_search_stem(word);
            add_slot(q, word, term, true);
        }
    }
}

bool command_registry_search_query_parse(const char *normalized,
                                         struct search_query *q)
{
    memset(q, 0, sizeof *q);
    char word[SEARCH_WORD_MAX];
    const char *p = normalized;
    while (q->terms < SEARCH_TERMS_MAX && next_word(&p, word)) {
        if (is_stop_word(word))
            continue;
        command_registry_search_stem(word);
        bool seen = false;
        for (size_t i = 0; i < q->terms; i++)
            seen = seen || strcmp(q->slot[i].stem, word) == 0;
        if (!seen)
            add_slot(q, word, q->terms++, false);
    }
    /* Primary slots occupy indices [0, terms): one slot per term so far. */
    size_t primary = q->terms;
    for (size_t t = 0; t < primary; t++)
        add_synonyms(q, t);
    return q->terms > 0;
}

static void score_field(const char *text, int weight,
                        const struct search_query *q, int best[])
{
    char word[SEARCH_WORD_MAX];
    while (text && next_word(&text, word)) {
        if (!q->first[(unsigned char)word[0] & 127U])
            continue;
        command_registry_search_stem(word);
        for (size_t i = 0; i < q->slots; i++) {
            int w = q->slot[i].syn ? weight / 2 : weight;
            if (w > best[q->slot[i].term] && strcmp(q->slot[i].stem, word) == 0)
                best[q->slot[i].term] = w;
        }
    }
}

int command_registry_search_term_score(const struct zcl_command_spec *spec,
                                       const struct search_query *q)
{
    int best[SEARCH_TERMS_MAX] = {0};
    score_field(spec->path, SEARCH_WEIGHT_PATH, q, best);
    score_field(spec->aliases, SEARCH_WEIGHT_PATH, q, best);
    score_field(spec->tags, SEARCH_WEIGHT_TAG, q, best);
    score_field(spec->summary, SEARCH_WEIGHT_SUMMARY, q, best);
    score_field(spec->semantics, SEARCH_WEIGHT_SEMANTICS, q, best);
    int total = 0;
    size_t matched = 0;
    for (size_t t = 0; t < q->terms; t++) {
        total += best[t];
        matched += best[t] > 0;
    }
    if (q->terms > 1 && matched == q->terms)
        total += SEARCH_COVERAGE_BONUS;
    return total;
}
