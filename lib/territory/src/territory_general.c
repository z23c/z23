/* territory_general.c — the general's brief, and the roll-up across all of
 * them. Both are projections of territory_scorecard(); neither stores prose.
 *
 * A GENERAL GRANTS NO AUTHORITY. See the long comment in territory.h. Nothing
 * in this file approves, gates, permits, or blocks. It reports.
 *
 * ── refuses, and how it is derived ───────────────────────────────────────
 * The set of lint gates is read from tools/lint/run_lint.sh's gate_command()
 * case table, because that is the one place a gate must be wired to run at
 * all: a gate not in that table does not exist. From each row we take the
 * gate's name and the script paths it invokes. Each script is then read once
 * and scanned for path-like tokens; a token that starts with a territory's
 * name is that gate NAMING that territory. Scripts also name their own
 * baseline ledgers (BASELINE=... tools/...baseline...txt), and those ledgers
 * name individual files, so a ledger row under a territory is a debt that
 * territory already owes to that gate — the sharpest evidence available that
 * the gate binds there.
 *
 * The three buckets partition every wired gate, and UNKNOWN is not a
 * rounding bucket: a gate that names no territory path is one this method
 * cannot scope. Most gates scan the whole tree, so that count is large. It is
 * printed rather than quietly turned into "binds" or "does not bind".
 *
 * ── the roll-up's cost ───────────────────────────────────────────────────
 * Scoring every territory routes every file in the tree through the shared
 * impact router, which walks 742 glob rules per path. That is seconds, not
 * milliseconds. The answer is a pure function of the code index's sealed
 * source generation, so it is memoized beside the reach closure, digest-
 * verified on read, and replaced atomically. The reply says whether it came
 * from the memo or from the work.
 */

#include "territory/territory.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "codeindex/codeindex.h"
#include "platform/clock.h"
#if defined(_WIN32)
#include "platform/directory_transaction.h"
#endif
#include "sha3/sha3.h"

#include <stddef.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    TG_LINT_MAX     = 1u << 20,  /* run_lint.sh, bounded */
    TG_SCRIPT_MAX   = 1u << 21,  /* one gate script, bounded */
    TG_BASELINE_MAX = 1u << 21,  /* one baseline ledger, bounded */
    TG_MAX_SCRIPTS  = 512,
    TG_MAX_BASELINE = 256,
    TG_TOKEN_MAX    = 512,
};

static uint64_t tg_now_us(void)
{
    return clock_now_monotonic_ns() / 1000u;
}

const char *territory_trust_label(enum territory_trust t)
{
    switch (t) {
    case TERRITORY_TRUST_REPRODUCIBLE:     return "reproducible";
    case TERRITORY_TRUST_NOT_REPRODUCIBLE: return "not-reproducible";
    case TERRITORY_TRUST_UNKNOWN:          break;
    }
    return "unknown";
}

/* ── bounded whole-file read ─────────────────────────────────────────────
 * Returns a NUL-terminated buffer the caller frees, or NULL. A file larger
 * than `cap` is read up to `cap` and reported as truncated, because a gate
 * script that big is still worth scanning for the part we got. */
static char *tg_slurp(const char *root, const char *rel, size_t cap,
                      size_t *out_len)
{
    char full[TERRITORY_PATH_MAX + 512];
    int w = snprintf(full, sizeof(full), "%s/%s",
                     (root && root[0]) ? root : ".", rel);
    if (w < 0 || (size_t)w >= sizeof(full)) return NULL;
    FILE *f = fopen(full, "rb");
    if (!f) return NULL;
    char *buf = zcl_malloc(cap + 1, "tg_slurp");
    if (!buf) { fclose(f); LOG_NULL("territory", "gate script buffer"); }
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    buf[n] = '\0';
    /* A NUL inside the payload would truncate every scan below it. A shell
     * script with an embedded NUL is not a script this method can speak
     * about, so it is refused rather than half-read. */
    if (memchr(buf, '\0', n) != NULL) { free(buf); return NULL; }
    if (out_len) *out_len = n;
    return buf;
}

/* ── the wiring table ────────────────────────────────────────────────── */

struct tg_gate {
    char name[TERRITORY_GATE_NAME_MAX];
    /* names[i] is true when this gate's script text names territory i. */
    bool *names;
    /* baseline[i] counts ledger rows naming a file in territory i. */
    int *baseline;
    bool named_any;
};

struct territory_gates {
    bool wiring_found;
    int  count;
    int  terr_count;
    char (*terr)[TERRITORY_NAME_MAX];
    struct tg_gate *gates;
    int  baseline_rows;
    int  baseline_unattributed;
    uint64_t build_us;
};

/* A path token is a run of path-safe bytes containing at least one '/'. */
static bool tg_path_byte(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '/' ||
           c == '-' || c == '+';
}

/* Shell scripts spell the same path both ways — `tools/lint/x.sh` and
 * `./tools/lint/x.sh` appear on adjacent lines of run_lint.sh. '.' and '/'
 * are both path bytes, so the leading "./" arrives inside the token and would
 * silently defeat every prefix comparison below. Strip it once, here, rather
 * than at each of the three call sites. */
static void tg_normalize(const char **tok, size_t *len)
{
    while (*len > 2 && (*tok)[0] == '.' && (*tok)[1] == '/') {
        *tok += 2;
        *len -= 2;
    }
}

/* Longest territory whose name is a directory prefix of `tok`. -1 for none.
 * The '/' requirement is what keeps "lib/net" from swallowing "lib/network".
 * Passing a territory's own name with no trailing component (a gate that
 * says `lib/net` and nothing else) still matches, which is intended: naming
 * the directory is naming the territory. */
static int tg_attribute(const struct territory_gates *g, const char *tok,
                        size_t len)
{
    int best = -1;
    size_t best_len = 0;
    for (int i = 0; i < g->terr_count; i++) {
        size_t tl = strlen(g->terr[i]);
        if (tl == 0 || tl > len) continue;
        if (memcmp(tok, g->terr[i], tl) != 0) continue;
        if (len != tl && tok[tl] != '/') continue;
        if (tl > best_len) { best = i; best_len = tl; }
    }
    return best;
}

/* Walk every path-like token in `buf`, calling `sink` with the territory
 * index (or -1). Returns the number of tokens seen. */
typedef void (*tg_token_fn)(int terr, const char *tok, size_t len, void *user);

static int tg_scan_tokens(const char *buf, size_t len,
                          const struct territory_gates *g,
                          tg_token_fn sink, void *user)
{
    int seen = 0;
    size_t i = 0;
    while (i < len) {
        if (!tg_path_byte(buf[i])) { i++; continue; }
        size_t start = i;
        while (i < len && tg_path_byte(buf[i])) i++;
        size_t tl = i - start;
        const char *tok = buf + start;
        tg_normalize(&tok, &tl);
        if (tl < 3 || tl > TG_TOKEN_MAX) continue;
        if (memchr(tok, '/', tl) == NULL) continue;
        seen++;
        sink(tg_attribute(g, tok, tl), tok, tl, user);
    }
    return seen;
}

struct tg_name_sink { struct tg_gate *gate; };

static void tg_sink_names(int terr, const char *tok, size_t len, void *user)
{
    (void)tok; (void)len;
    struct tg_name_sink *s = user;
    if (terr >= 0) { s->gate->names[terr] = true; s->gate->named_any = true; }
}

struct tg_baseline_sink {
    struct tg_gate *gate;
    int rows;
    int unattributed;
};

static void tg_sink_baseline(int terr, const char *tok, size_t len, void *user)
{
    (void)tok; (void)len;
    struct tg_baseline_sink *s = user;
    s->rows++;
    if (terr >= 0) s->gate->baseline[terr]++;
    else s->unattributed++;
}

/* Collect the script paths a gate_command() row invokes, and any baseline
 * ledger a script names. Both are just path tokens with a known suffix. */
struct tg_path_list {
    char path[TG_MAX_SCRIPTS][TERRITORY_PATH_MAX];
    int count;
};

static void tg_path_push(struct tg_path_list *l, const char *tok, size_t len)
{
    if (l->count >= TG_MAX_SCRIPTS || len >= TERRITORY_PATH_MAX) return;
    for (int i = 0; i < l->count; i++)
        if (strncmp(l->path[i], tok, len) == 0 && l->path[i][len] == '\0')
            return;
    memcpy(l->path[l->count], tok, len);
    l->path[l->count][len] = '\0';
    l->count++;
}

/* Portable byte-substring search. The tree deliberately avoids the
 * glibc-specific memmem; this is the same convention the test sources use. */
static bool tg_contains(const char *hay, size_t hay_len, const char *needle)
{
    size_t nl = strlen(needle);
    if (nl == 0 || nl > hay_len) return false;
    for (size_t i = 0; i + nl <= hay_len; i++)
        if (memcmp(hay + i, needle, nl) == 0) return true;
    return false;
}

static bool tg_ends_with(const char *tok, size_t len, const char *suffix)
{
    size_t sl = strlen(suffix);
    return len >= sl && memcmp(tok + len - sl, suffix, sl) == 0;
}

/* Extract every `tools/…` script path named on one gate_command() line. */
static void tg_line_scripts(const char *line, size_t len,
                            struct tg_path_list *out)
{
    size_t i = 0;
    while (i < len) {
        if (!tg_path_byte(line[i])) { i++; continue; }
        size_t start = i;
        while (i < len && tg_path_byte(line[i])) i++;
        size_t tl = i - start;
        const char *tok = line + start;
        tg_normalize(&tok, &tl);
        if (tl < 6 || tl >= TERRITORY_PATH_MAX) continue;
        if (memcmp(tok, "tools/", 6) != 0) continue;
        if (!tg_ends_with(tok, tl, ".sh")) continue;
        tg_path_push(out, tok, tl);
    }
}

/* A gate_command() row: leading whitespace, then `check-<name>)`. */
static bool tg_gate_row(const char *line, size_t len, char *name, size_t cap)
{
    size_t i = 0;
    while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
    if (len - i < 7 || memcmp(line + i, "check-", 6) != 0) return false;
    size_t start = i;
    while (i < len && (line[i] == '-' || (line[i] >= 'a' && line[i] <= 'z') ||
                       (line[i] >= '0' && line[i] <= '9')))
        i++;
    if (i >= len || line[i] != ')') return false;
    size_t nl = i - start;
    if (nl == 0 || nl >= cap) return false;
    memcpy(name, line + start, nl);
    name[nl] = '\0';
    return true;
}

void territory_gates_free(struct territory_gates *g)
{
    if (!g) return;
    for (int i = 0; i < g->count; i++) {
        free(g->gates[i].names);
        free(g->gates[i].baseline);
    }
    free(g->gates);
    free(g->terr);
    free(g);
}

struct territory_gates *territory_gates_open(
    const char *root, const char (*names)[TERRITORY_NAME_MAX], int count)
{
    uint64_t t0 = tg_now_us();
    struct territory_gates *g = zcl_calloc(1, sizeof(*g), "territory_gates");
    if (!g) LOG_NULL("territory", "gate table");
    if (count < 0) count = 0;
    g->terr_count = count;
    if (count > 0) {
        g->terr = zcl_malloc(sizeof(*g->terr) * (size_t)count, "tg_terr");
        if (!g->terr) { free(g); LOG_NULL("territory", "gate territory list"); }
        memcpy(g->terr, names, sizeof(*g->terr) * (size_t)count);
    }
    g->gates = zcl_calloc(TERRITORY_MAX_GATES, sizeof(*g->gates), "tg_gates");
    if (!g->gates) {
        free(g->terr); free(g);
        LOG_NULL("territory", "gate rows");
    }

    size_t lint_len = 0;
    char *lint = tg_slurp(root, "tools/lint/run_lint.sh", TG_LINT_MAX,
                          &lint_len);
    if (!lint) {
        /* Not an error the caller has to handle: the brief reports the wiring
         * as unreadable, which is materially different from "no gates". */
        g->build_us = tg_now_us() - t0;
        return g;
    }
    g->wiring_found = true;

    struct tg_path_list *scripts =
        zcl_calloc(1, sizeof(*scripts), "tg_scripts");
    struct tg_path_list *ledgers =
        zcl_calloc(1, sizeof(*ledgers), "tg_ledgers");
    if (!scripts || !ledgers) {
        free(scripts); free(ledgers); free(lint);
        territory_gates_free(g);
        LOG_NULL("territory", "gate path lists");
    }

    /* Pass 1: the case table. One row per gate, in wiring order. */
    size_t pos = 0;
    while (pos < lint_len && g->count < TERRITORY_MAX_GATES) {
        const char *nl = memchr(lint + pos, '\n', lint_len - pos);
        size_t line_len = nl ? (size_t)(nl - (lint + pos)) : lint_len - pos;
        char gname[TERRITORY_GATE_NAME_MAX];
        if (tg_gate_row(lint + pos, line_len, gname, sizeof(gname))) {
            bool dup = false;
            for (int i = 0; i < g->count; i++)
                if (strcmp(g->gates[i].name, gname) == 0) { dup = true; break; }
            if (!dup) {
                struct tg_gate *gate = &g->gates[g->count];
                (void)snprintf(gate->name, sizeof(gate->name), "%s", gname);
                gate->names = count > 0
                    ? zcl_calloc((size_t)count, sizeof(*gate->names),
                                 "tg_gate_names")
                    : NULL;
                gate->baseline = count > 0
                    ? zcl_calloc((size_t)count, sizeof(*gate->baseline),
                                 "tg_gate_baseline")
                    : NULL;
                if (count > 0 && (!gate->names || !gate->baseline)) {
                    free(gate->names); free(gate->baseline);
                    free(scripts); free(ledgers); free(lint);
                    territory_gates_free(g);
                    LOG_NULL("territory", "gate scope vectors");
                }
                scripts->count = 0;
                tg_line_scripts(lint + pos, line_len, scripts);

                /* Pass 2, per gate: read each script it runs, record which
                 * territories its text names, and remember any baseline
                 * ledger it points at. */
                for (int s = 0; s < scripts->count; s++) {
                    size_t slen = 0;
                    char *body = tg_slurp(root, scripts->path[s],
                                          TG_SCRIPT_MAX, &slen);
                    if (!body) continue;
                    struct tg_name_sink sink = { .gate = gate };
                    (void)tg_scan_tokens(body, slen, g, tg_sink_names, &sink);

                    ledgers->count = 0;
                    size_t i = 0;
                    while (i < slen) {
                        if (!tg_path_byte(body[i])) { i++; continue; }
                        size_t st = i;
                        while (i < slen && tg_path_byte(body[i])) i++;
                        size_t tl = i - st;
                        const char *tok = body + st;
                        tg_normalize(&tok, &tl);
                        if (tl < 8 || tl >= TERRITORY_PATH_MAX) continue;
                        if (memcmp(tok, "tools/", 6) != 0) continue;
                        if (!tg_ends_with(tok, tl, ".txt") &&
                            !tg_ends_with(tok, tl, ".tsv")) continue;
                        if (!tg_contains(tok, tl, "baseline")) continue;
                        tg_path_push(ledgers, tok, tl);
                    }
                    free(body);

                    /* Pass 3: the ledger rows themselves. */
                    for (int b = 0; b < ledgers->count && b < TG_MAX_BASELINE;
                         b++) {
                        size_t blen = 0;
                        char *rows = tg_slurp(root, ledgers->path[b],
                                              TG_BASELINE_MAX, &blen);
                        if (!rows) continue;
                        struct tg_baseline_sink bs = { .gate = gate };
                        (void)tg_scan_tokens(rows, blen, g, tg_sink_baseline,
                                             &bs);
                        g->baseline_rows += bs.rows;
                        g->baseline_unattributed += bs.unattributed;
                        free(rows);
                    }
                }
                g->count++;
            }
        }
        if (!nl) break;
        pos += line_len + 1;
    }

    free(scripts);
    free(ledgers);
    free(lint);
    g->build_us = tg_now_us() - t0;
    return g;
}

bool territory_gates_wiring_found(const struct territory_gates *g)
{
    return g && g->wiring_found;
}

int territory_gates_total(const struct territory_gates *g)
{
    return g ? g->count : 0;
}

int territory_gates_baseline_rows(const struct territory_gates *g)
{
    return g ? g->baseline_rows : 0;
}

int territory_gates_baseline_unattributed(const struct territory_gates *g)
{
    return g ? g->baseline_unattributed : 0;
}

uint64_t territory_gates_build_us(const struct territory_gates *g)
{
    return g ? g->build_us : 0;
}

/* ── the brief ───────────────────────────────────────────────────────── */

void territory_brief_free(struct territory_brief *b)
{
    if (!b) return;
    territory_report_free(b->report);
    free(b);
}

struct territory_brief *territory_brief_build(
    struct codeindex *ci, const char *root, const char *name,
    const struct territory_reach_set *rs,
    const struct territory_router *router,
    const struct territory_gates *gates,
    const struct territory_trust_ledger *trust)
{
    struct territory_brief *b = zcl_calloc(1, sizeof(*b), "territory_brief");
    if (!b) LOG_NULL("territory", "brief for %s", name ? name : "(null)");

    b->report = territory_scorecard(ci, root, name, rs, router);
    if (!b->report) { free(b); return NULL; }

    b->unproven = b->report->unreached + b->report->unknown;
    b->unrouted_files = b->report->files_unrouted;

    /* refuses. Three buckets, and they partition the wired gates. */
    b->gate_wiring_found = territory_gates_wiring_found(gates);
    b->gates_total = territory_gates_total(gates);
    b->gates_us = territory_gates_build_us(gates);
    if (gates && gates->count > 0) {
        int idx = -1;
        for (int i = 0; i < gates->terr_count; i++)
            if (strcmp(gates->terr[i], b->report->name) == 0) { idx = i; break; }
        for (int i = 0; i < gates->count; i++) {
            const struct tg_gate *gate = &gates->gates[i];
            bool named = idx >= 0 && gate->names && gate->names[idx];
            int rows = (idx >= 0 && gate->baseline) ? gate->baseline[idx] : 0;
            if (named || rows > 0) {
                b->gates_binding++;
                if (b->refusal_count < TERRITORY_MAX_REFUSALS) {
                    struct territory_refusal *r =
                        &b->refuses[b->refusal_count++];
                    (void)snprintf(r->gate, sizeof(r->gate), "%s", gate->name);
                    r->named_in_gate = named;
                    r->baseline_rows = rows;
                } else {
                    b->refusals_truncated = true;
                }
            } else if (gate->named_any) {
                /* Names some territory, not this one. NOT "does not bind" —
                 * a tree-wide gate that happens to mention one module in a
                 * baseline row lands here, and calling that a "no" would be
                 * the guess this tool exists to avoid. */
                b->gates_unknown_named_others++;
            } else {
                b->gates_unknown_named_none++;
            }
        }
    }

    /* trusts. A declared hole while the determinism ledger is unlanded: every
     * routed group reports UNKNOWN, and the source says why. */
    territory_trust_fn lookup = trust ? trust->lookup : NULL;
    for (int i = 0; i < b->report->group_count; i++) {
        enum territory_trust t = TERRITORY_TRUST_UNKNOWN;
        if (lookup) t = lookup(b->report->groups[i].name, trust->user);
        switch (t) {
        case TERRITORY_TRUST_REPRODUCIBLE:     b->trust_reproducible++; break;
        case TERRITORY_TRUST_NOT_REPRODUCIBLE: b->trust_not_reproducible++;
                                               break;
        case TERRITORY_TRUST_UNKNOWN:          b->trust_unknown++; break;
        }
    }
    (void)snprintf(b->trust_source, sizeof(b->trust_source), "%s",
                   (trust && trust->source && trust->source[0])
                       ? trust->source
                       : "determinism ledger not landed");
    return b;
}

/* ── the roll-up ─────────────────────────────────────────────────────── */

static int tr_rank_cmp(const void *a, const void *b)
{
    const struct territory_rank *x = a, *y = b;
    if (x->unproven != y->unproven) return x->unproven > y->unproven ? -1 : 1;
    if (x->unrouted_files != y->unrouted_files)
        return x->unrouted_files > y->unrouted_files ? -1 : 1;
    return strcmp(x->name, y->name);
}

/* The memo. Same shape as the reach closure's: magic, version, generation,
 * digest, then a flat payload. A rejected memo just means the work runs. */
static const char TU_MAGIC[8] = { 'Z','T','R','O','L','L','U','P' };
enum {
    TU_VERSION  = 1u,
    TU_HDR_MAGIC   = 0,
    TU_HDR_VERSION = 8,
    TU_HDR_LEN     = 12,
    TU_HDR_ROOT    = 16,
    TU_HDR_DIGEST  = 48,
    TU_HDR_SIZE    = 80,
};

static int tu_cache_path(char *buf, size_t cap, const char *root)
{
    return snprintf(buf, cap, "%s/.codeindex/territory_rollup.v1", root);
}

#if defined(_WIN32)
static _Atomic uint64_t g_tu_cache_sequence = 1;

static bool tu_cache_directory(char *buf, size_t cap, const char *root)
{
    int n = snprintf(buf, cap, "%s/.codeindex", root);
    return n > 0 && (size_t)n < cap;
}
#endif

/* The bytes that get digested: everything but the two cache-provenance flags,
 * which describe THIS call and must never be baked into the payload. */
static size_t tu_payload(const struct territory_rollup *r, const uint8_t **p)
{
    *p = (const uint8_t *)r;
    return offsetof(struct territory_rollup, from_cache);
}

static bool tu_cache_load(const char *root, const uint8_t gen[32],
                          struct territory_rollup *out)
{
#if defined(_WIN32)
    char directory_path[TERRITORY_PATH_MAX + 32];
    struct platform_directory_transaction directory;
    struct platform_directory_child child;
    struct platform_directory_child_info info;
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&child);
    if (!tu_cache_directory(directory_path, sizeof(directory_path), root) ||
        !platform_directory_transaction_open(&directory, directory_path) ||
        !platform_directory_child_open(&directory, "territory_rollup.v1",
                                       &child) ||
        !platform_directory_child_info(&child, &info) ||
        info.link_count != 1 || !info.current_user_only) {
        platform_directory_child_close(&child);
        platform_directory_transaction_close(&directory);
        return false;
    }
#else
    char path[TERRITORY_PATH_MAX + 64];
    int n = tu_cache_path(path, sizeof(path), root);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    FILE *f = fopen(path, "rb");
    if (!f) return false;
#endif
    uint8_t hdr[TU_HDR_SIZE];
#if defined(_WIN32)
    if (!platform_directory_child_read_exact(&child, hdr, sizeof(hdr), 0)) {
        platform_directory_child_close(&child);
        platform_directory_transaction_close(&directory);
        return false;
    }
#else
    if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        fclose(f);
        return false;
    }
#endif
    const uint8_t *unused = NULL;
    size_t head = tu_payload(out, &unused);
    size_t tail = sizeof(*out) - offsetof(struct territory_rollup, ranks);
    uint32_t stored = zcl_read_u32_le(hdr + TU_HDR_LEN);
    if (memcmp(hdr + TU_HDR_MAGIC, TU_MAGIC, 8) != 0 ||
        zcl_read_u32_le(hdr + TU_HDR_VERSION) != TU_VERSION ||
        stored != (uint32_t)(head + tail) ||
        memcmp(hdr + TU_HDR_ROOT, gen, 32) != 0) {
#if defined(_WIN32)
        platform_directory_child_close(&child);
        platform_directory_transaction_close(&directory);
#else
        fclose(f);
#endif
        return false;
    }
    uint8_t *body = zcl_malloc(head + tail, "tu_cache_body");
#if defined(_WIN32)
    if (!body) {
        platform_directory_child_close(&child);
        platform_directory_transaction_close(&directory);
        LOG_RETURN(false, "territory", "rollup memo buffer");
    }
    bool ok = info.size == TU_HDR_SIZE + head + tail &&
        platform_directory_child_read_exact(&child, body, head + tail,
                                            TU_HDR_SIZE);
    platform_directory_child_close(&child);
    platform_directory_transaction_close(&directory);
#else
    if (!body) { fclose(f); LOG_RETURN(false, "territory", "rollup memo buffer"); }
    bool ok = fread(body, 1, head + tail, f) == head + tail;
    fclose(f);
#endif
    if (!ok) { free(body); return false; }

    uint8_t got[32];
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)body, head + tail);
    sha3_256_finalize(&c, got);
    if (memcmp(hdr + TU_HDR_DIGEST, got, 32) != 0) { free(body); return false; }

    memcpy(out, body, head);
    memcpy((uint8_t *)out + offsetof(struct territory_rollup, ranks),
           body + head, tail);
    free(body);
    /* Structural sanity after the digest: a file that passes both is
     * byte-identical to what the scoring pass produced, but a count out of
     * range would still index past the array, so it is checked. */
    if (out->count < 0 ||
        out->count > (int)(sizeof(out->ranks) / sizeof(out->ranks[0])))
        return false;
    for (int i = 0; i < out->count; i++)
        if (memchr(out->ranks[i].name, '\0', sizeof(out->ranks[i].name)) == NULL)
            return false;
    return true;
}

static void tu_cache_store(const char *root, const uint8_t gen[32],
                           const struct territory_rollup *r, bool *wrote)
{
    *wrote = false;
    char path[TERRITORY_PATH_MAX + 64];
    int n = tu_cache_path(path, sizeof(path), root);
    if (n < 0 || (size_t)n >= sizeof(path)) return;
#if !defined(_WIN32)
    char tmp[TERRITORY_PATH_MAX + 96];
    n = snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp)) return;
#endif

    const uint8_t *base = NULL;
    size_t head = tu_payload(r, &base);
    const uint8_t *ranks =
        (const uint8_t *)r + offsetof(struct territory_rollup, ranks);
    size_t tail = sizeof(*r) - offsetof(struct territory_rollup, ranks);

    uint8_t hdr[TU_HDR_SIZE];
    memset(hdr, 0, sizeof(hdr));
    memcpy(hdr + TU_HDR_MAGIC, TU_MAGIC, 8);
    zcl_write_u32_le(hdr + TU_HDR_VERSION, TU_VERSION);
    zcl_write_u32_le(hdr + TU_HDR_LEN, (uint32_t)(head + tail));
    memcpy(hdr + TU_HDR_ROOT, gen, 32);
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)base, head);
    sha3_256_write(&c, (const unsigned char *)ranks, tail);
    sha3_256_finalize(&c, hdr + TU_HDR_DIGEST);

#if defined(_WIN32)
    char directory_path[TERRITORY_PATH_MAX + 32];
    struct platform_directory_transaction directory;
    struct platform_directory_child stage;
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&stage);
    if (!tu_cache_directory(directory_path, sizeof(directory_path), root) ||
        !platform_directory_transaction_open(&directory, directory_path))
        return;
    char stage_name[96] = "";
    bool created = false;
    for (unsigned int attempt = 0; attempt < 32 && !created; attempt++) {
        uint64_t seq = atomic_fetch_add_explicit(&g_tu_cache_sequence, 1,
                                                 memory_order_relaxed);
        n = snprintf(stage_name, sizeof(stage_name),
                     "territory_rollup.v1.tmp.%llu",
                     (unsigned long long)seq);
        if (n <= 0 || (size_t)n >= sizeof(stage_name)) break;
        created = platform_directory_child_create(&directory, stage_name,
                                                  &stage);
    }
    bool stage_named = created;
    bool ok = created &&
        platform_directory_child_write_exact(&stage, hdr, sizeof(hdr), 0) &&
        platform_directory_child_write_exact(&stage, base, head,
                                             sizeof(hdr)) &&
        platform_directory_child_write_exact(&stage, ranks, tail,
                                             sizeof(hdr) + head) &&
        platform_directory_child_truncate(&stage, sizeof(hdr) + head + tail) &&
        platform_directory_child_flush(&stage);
    struct platform_directory_child_info info;
    ok = ok && platform_directory_child_info(&stage, &info) &&
         info.size == sizeof(hdr) + head + tail && info.link_count == 1 &&
         info.current_user_only;
    enum platform_directory_result published = PLATFORM_DIRECTORY_IO;
    if (ok)
        published = platform_directory_child_move_between(
            &directory, &stage, &directory, "territory_rollup.v1", false);
    if (published == PLATFORM_DIRECTORY_OK ||
        published == PLATFORM_DIRECTORY_OUTCOME_UNKNOWN)
        stage_named = false;
    platform_directory_child_close(&stage);
    if (stage_named)
        (void)platform_directory_child_unlink(&directory, stage_name, true);
    platform_directory_transaction_close(&directory);
    *wrote = published == PLATFORM_DIRECTORY_OK;
#else
    FILE *f = fopen(tmp, "wb");
    if (!f) return;  /* a read-only checkout is a normal state */
    bool ok = fwrite(hdr, 1, sizeof(hdr), f) == sizeof(hdr) &&
              fwrite(base, 1, head, f) == head &&
              fwrite(ranks, 1, tail, f) == tail;
    if (fclose(f) != 0) ok = false;
    if (!ok || rename(tmp, path) != 0) { (void)unlink(tmp); return; }
    *wrote = true;
#endif
}

void territory_rollup_free(struct territory_rollup *r) { free(r); }

struct territory_rollup *territory_rollup_build(
    struct codeindex *ci, const char *root,
    const struct territory_reach_set *rs,
    const struct territory_router *router)
{
    uint64_t t0 = tg_now_us();
    struct territory_rollup *out = zcl_calloc(1, sizeof(*out),
                                              "territory_rollup");
    if (!out) LOG_NULL("territory", "rollup");

    uint8_t gen[32];
    bool have_gen = codeindex_source_root_sha3(ci, gen);
    if (root && root[0] && have_gen && tu_cache_load(root, gen, out)) {
        out->from_cache = true;
        out->build_us = tg_now_us() - t0;
        return out;
    }
    memset(out, 0, sizeof(*out));

    int cap = (int)(sizeof(out->ranks) / sizeof(out->ranks[0]));
    char (*names)[TERRITORY_NAME_MAX] =
        zcl_malloc(sizeof(*names) * (size_t)cap, "tu_names");
    if (!names) { free(out); LOG_NULL("territory", "rollup names"); }
    int n = territory_list(ci, names, cap);
    if (n < 0) n = 0;

    for (int i = 0; i < n; i++) {
        struct territory_report *r =
            territory_scorecard(ci, root, names[i], rs, router);
        if (!r) { out->failed++; continue; }
        struct territory_rank *k = &out->ranks[out->scored++];
        (void)snprintf(k->name, sizeof(k->name), "%s", r->name);
        k->files            = r->file_count;
        k->public_symbols   = r->public_symbols;
        k->reached          = r->reached;
        k->unreached        = r->unreached;
        k->unknown          = r->unknown;
        k->unproven         = r->unreached + r->unknown;
        k->unrouted_files   = r->files_unrouted;
        k->headers_extern_c = r->headers_extern_c;
        out->total_files            += r->file_count;
        out->total_public           += r->public_symbols;
        out->total_reached          += r->reached;
        out->total_unreached        += r->unreached;
        out->total_unknown          += r->unknown;
        out->total_unrouted         += r->files_unrouted;
        out->total_headers_extern_c += r->headers_extern_c;
        territory_report_free(r);
    }
    free(names);
    out->count = out->scored;
    qsort(out->ranks, (size_t)out->scored, sizeof(out->ranks[0]), tr_rank_cmp);
    out->build_us = tg_now_us() - t0;

    /* Only a complete pass is worth memoizing: a run that failed to score a
     * territory would otherwise freeze that gap in until the next edit. */
    if (root && root[0] && have_gen && out->failed == 0 && out->scored > 0)
        tu_cache_store(root, gen, out, &out->cache_written);
    return out;
}
