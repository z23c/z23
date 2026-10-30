/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-hotswap-service-islands — pure service-island
 * confinement. Build-free and fail-loud: the C23 compiler remains the only
 * compiler authority; this gate only narrows what a hot-swap island may
 * import or own. Ported from check_hotswap_service_islands.sh
 * (deleted). Selftest: gate_hotswap_service_islands_selftest.c.
 *
 * WHAT IT ENFORCES
 * ----------------
 *   - every HOTSWAP_SERVICE(...) row of the manifest has a unique service id
 *     and a translation unit that belongs to exactly one service, living
 *     under a physical service room (a services source directory of engine,
 *     cognition or a context, holding .c files; in fixture mode also
 *     tests/harness/fixtures .c files);
 *   - private/public and service-contract headers exist;
 *   - the four frozen fingerprints (abi/schema/wire/kat) each resolve to
 *     exactly one contract header containing "stamp" literally, and the
 *     resident-owned probe leaf resolves to exactly one probe-case line;
 *   - islands own no second mutable world: no TLS, no constructor/destructor
 *     attributes, no mutable file-scope statics (lines tagged
 *     hotswap-service-static-ok: are exempt), no extern declarations;
 *   - no ambient-authority / effectful libc calls (sqlite3_*, fopen, open,
 *     socket, fork, system, ...) and no includes of wallet/storage/consensus/
 *     validation/net/coins/chain/mining/rpc directories;
 *   - every vcs_/zcl_ call is an explicitly declared stable host import;
 *   - HOTSHADOW_OWNER rows map static authority shells (admitted roots only,
 *     existing, never self, never duplicated) to exactly one admitted pure
 *     service, and HOTSHADOW_SERVICE_MEMBERS members live under the pure
 *     library roots and pass the same state/effect scans.
 *
 * No heap: every buffer is fixed static storage; on overflow the gate prints
 * what exceeded its capacity to stderr and exits 2 (fail closed). No
 * snprintf: field copies go through checked hsi_cpy/hsi_decor helpers.
 *
 * Exit 0 pass, 1 violation, 2 usage/internal error. Unreadable inputs are
 * fatal (fail closed), never a skip. Never weaken a token list or root
 * pattern to make the gate green; widen scope deliberately instead.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <fnmatch.h>
#include <regex.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

#include "gate_hotswap_service_islands_priv.h"

const char k_hsi_gate[] = "check_hotswap_service_islands";

/* ---------- per-line scanners ---------- */

static int hsi_state_line(void *ctx, const char *line, size_t len)
{
    struct hsi_line_ctx *c = ctx;
    struct hsi_env *e = c->env;
    char buf[HSI_LINE];
    c->ln++;
    if (hsi_copy_line(buf, sizeof buf, line, len, c->path, c->ln))
        return 2;
    if (strstr(buf, "hotswap-service-static-ok:"))
        return 0;
    const char *kind = NULL;
    if (strstr(buf, "_Thread_local") || strstr(buf, "__thread"))
        kind = "TLS";
    else if (regexec(&e->re_life, buf, 0, NULL, 0) == 0)
        kind = "lifecycle";
    else if (regexec(&e->re_static, buf, 0, NULL, 0) == 0 &&
             !strstr(buf, "const") && !strchr(buf, '(') &&
             (strchr(buf, '=') || strchr(buf, '[') ||
              regexec(&e->re_brace, buf, 0, NULL, 0) == 0))
        kind = "mutable";
    else if (regexec(&e->re_extern, buf, 0, NULL, 0) == 0)
        kind = "extern";
    if (!kind)
        return 0;
    return hsi_vadd(&e->v, "%s:%ld: %s: %s\n", c->path, c->ln, kind,
                    buf) ? 2 : 0;
}

static int hsi_effect_line(void *ctx, const char *line, size_t len)
{
    struct hsi_line_ctx *c = ctx;
    char buf[HSI_LINE];
    c->ln++;
    if (hsi_copy_line(buf, sizeof buf, line, len, c->path, c->ln))
        return 2;
    if (regexec(c->re, buf, 0, NULL, 0) != 0)
        return 0;
    int pre = !c->env->eff_first;
    c->env->eff_first = 1;
    return hsi_vadd(&c->env->v, "%s%s%s%s%ld:%s\n", pre ? c->prefix : "",
                    pre ? ":" : "", c->env->eff_multi ? c->path : "",
                    c->env->eff_multi ? ":" : "", c->ln, buf) ? 2 : 0;
}

static int hsi_scan_file(struct hsi_env *e, const char *path, const char *prefix,
                         const regex_t *re,
                         int (*cb)(void *, const char *, size_t))
{
    struct hsi_line_ctx c = { e, path, prefix, re, 0 };
    int rc = lc_each_line(path, cb, &c, 1);
    return rc ? 2 : 0;
}

/* One grep pass over a file list: the first hit line carries "$source:". */
static int hsi_effect_pass(struct hsi_env *e, char sf[][HSI_SRC], int ns,
                           const char *source, const regex_t *re)
{
    e->eff_first = 0;
    e->eff_multi = ns > 1;
    for (int i = 0; i < ns; i++)
        if (hsi_scan_file(e, sf[i], source, re, hsi_effect_line))
            return 2;
    return 0;
}

/* Runs the state and both effect scans over one file list. */
static int hsi_scan_row_files(struct hsi_env *e, char sf[][HSI_SRC], int ns,
                              const char *source)
{
    for (int i = 0; i < ns; i++)
        if (hsi_scan_file(e, sf[i], sf[i], NULL, hsi_state_line))
            return 2;
    if (hsi_effect_pass(e, sf, ns, source, &e->re_forb))
        return 2;
    return hsi_effect_pass(e, sf, ns, source, &e->re_inc);
}

static int hsi_scan_member_files(struct hsi_env *e, const char *m)
{
    char one[1][HSI_SRC];
    if (hsi_cpy(one[0], HSI_SRC, m))
        return 2;
    if (hsi_scan_file(e, m, m, NULL, hsi_state_line))
        return 2;
    if (hsi_effect_pass(e, one, 1, m, &e->re_forb))
        return 2;
    return hsi_effect_pass(e, one, 1, m, &e->re_inc);
}

/* ---------- row checks ---------- */

static int hsi_name_add(char names[][HSI_FLD], int *nn, const char *s,
                        size_t len)
{
    if (len >= HSI_FLD)
        len = HSI_FLD - 1;
    for (int i = 0; i < *nn; i++)
        if (strlen(names[i]) == len && !strncmp(names[i], s, len))
            return 0;
    if (*nn >= HSI_CALLS) {
        fprintf(stderr, "%s: more than %d distinct host calls in one TU\n",
                k_hsi_gate, HSI_CALLS);
        return 2;
    }
    memcpy(names[*nn], s, len);
    names[*nn][len] = '\0';
    (*nn)++;
    return 0;
}

/* Collects the distinct vcs_/zcl_ call tokens of the source. */
static int hsi_collect_calls(struct hsi_env *e, const char *buf, size_t n,
                             char names[][HSI_FLD], int *nn)
{
    size_t off = 0;
    while (off < n) {
        regmatch_t m[3];
        if (regexec(&e->re_proj, buf + off, 3, m, 0) != 0)
            break;
        size_t so = off + (size_t)m[2].rm_so, eo = so;
        while (eo < n && (isalnum((unsigned char)buf[eo]) || buf[eo] == '_'))
            eo++;
        if (hsi_name_add(names, nn, buf + so, eo - so))
            return 2;
        off += (size_t)m[0].rm_eo ? (size_t)m[0].rm_eo : 1;
    }
    return 0;
}

static int hsi_project_calls(struct hsi_env *e, const struct hsi_row *r)
{
    static char buf[HSI_TEXT];
    static char names[HSI_CALLS][HSI_FLD];
    static char imp[HSI_BIG + 2];
    char needle[HSI_FLD + 2];
    size_t n;
    int nn = 0;
    if (hsi_slurp(r->source, buf, sizeof buf, &n))
        return 2;
    if (hsi_collect_calls(e, buf, n, names, &nn))
        return 2;
    if (hsi_decor(imp, sizeof imp, " ", r->imports, " "))
        return 2;
    for (int i = 0; i < nn; i++) {
        if (hsi_decor(needle, sizeof needle, " ", names[i], " "))
            return 2;
        if (!strstr(imp, needle))
            HSI_V(e, "  %s -> %s (host symbol absent from stable-import list)\n",
                  r->source, names[i]);
    }
    return 0;
}

/* Splits one whitespace-separated header list, checking existence; appends
 * surviving paths to out. Missing headers are violations, not errors. */
static int hsi_split_list(struct hsi_env *e, const char *list,
                          const char *src, char out[][HSI_SRC], int cap,
                          int *cnt, const char *what)
{
    char tmp[HSI_BIG];
    if (hsi_cpy(tmp, sizeof tmp, list))
        return 2;
    for (char *h = strtok(tmp, " \t"); h; h = strtok(NULL, " \t")) {
        if (!strcmp(h, "-"))
            continue;
        if (access(h, F_OK) != 0) {
            HSI_V(e, "  %s -> %s (missing %s)\n", src, h, what);
            continue;
        }
        if (*cnt >= cap)
            return 2;
        if (hsi_cpy(out[(*cnt)++], HSI_SRC, h))
            return 2;
    }
    return 0;
}

static int hsi_stamps(struct hsi_env *e, const struct hsi_row *r,
                      char con[][HSI_SRC], int nc)
{
    static const struct { const char *label; size_t off; } stamps[] = {
        { "abi", offsetof(struct hsi_row, abi) },
        { "schema", offsetof(struct hsi_row, schema) },
        { "wire", offsetof(struct hsi_row, wire) },
        { "kat", offsetof(struct hsi_row, kat) },
    };
    static char cbuf[HSI_CONTRACTS][HSI_CBUF];
    int have[HSI_CONTRACTS] = { 0 };
    for (int i = 0; i < nc; i++) {
        size_t n;
        int sr = hsi_slurp(con[i], cbuf[i], HSI_CBUF, &n);
        if (sr == 2)
            return 2;
        have[i] = (sr == 0); /* unreadable counts as no match, like grep */
    }
    for (size_t s = 0; s < sizeof stamps / sizeof stamps[0]; s++) {
        const char *val = (const char *)r + stamps[s].off;
        if (!val[0]) {
            HSI_V(e, "  %s (empty frozen %s fingerprint)\n", r->source,
                  stamps[s].label);
            continue;
        }
        char lit[HSI_FLD + 4];
        if (hsi_decor(lit, sizeof lit, "\"", val, "\""))
            return 2;
        int m = 0;
        for (int i = 0; i < nc; i++)
            if (have[i] && strstr(cbuf[i], lit))
                m++;
        if (m != 1)
            HSI_V(e, "  %s (%s fingerprint '%s' resolves to %d contract "
                  "headers, expected exactly one)\n", r->source,
                  stamps[s].label, val, m);
    }
    return 0;
}

static int hsi_probe(struct hsi_env *e, const struct hsi_row *r,
                     const char *probe_buf)
{
    if (!r->probe[0]) {
        HSI_V(e, "  %s (empty resident-owned probe leaf)\n", r->source);
        return 0;
    }
    char lit[HSI_FLD + 4];
    if (hsi_decor(lit, sizeof lit, "\"", r->probe, "\","))
        return 2;
    size_t ll = strlen(lit);
    int cnt = 0;
    const char *q = probe_buf;
    while (q && *q) {
        const char *nl = strchr(q, '\n');
        size_t ln = nl ? (size_t)(nl - q) : strlen(q);
        if (hsi_line_has(q, ln, lit, ll))
            cnt++;
        q = nl ? nl + 1 : NULL;
    }
    if (cnt != 1)
        HSI_V(e, "  %s (probe '%s' resolves to %d resident cases, expected "
              "exactly one)\n", r->source, r->probe, cnt);
    return 0;
}

/* Registers the row id and source; flags duplicates. 2 on overflow. */
static int hsi_row_ident(struct hsi_env *e, const struct hsi_row *r,
                         struct bln_set *ids, struct bln_set *sources)
{
    if (!r->id[0] || bln_has(ids, r->id))
        HSI_V(e, "  %s (empty or duplicate service id)\n", r->id);
    if (bln_add(ids, r->id))
        return 2;
    if (bln_has(sources, r->source))
        HSI_V(e, "  %s (translation unit belongs to two services)\n",
              r->source);
    return bln_add(sources, r->source) ? 2 : 0;
}

/* 0 scannable, 1 violation recorded instead, 2 internal error. */
static int hsi_row_room(struct hsi_env *e, const struct hsi_row *r)
{
    int ok = regexec(&e->re_srvc, r->source, 0, NULL, 0) == 0;
    if (!ok && e->fixture_mode)
        ok = regexec(&e->re_fixture, r->source, 0, NULL, 0) == 0;
    if (!ok) {
        HSI_V(e, "  %s (service TU must live under a physical service room)\n",
              r->source);
        return 1;
    }
    if (access(r->source, F_OK) != 0) {
        HSI_V(e, "  %s (missing source)\n", r->source);
        return 1;
    }
    return 0;
}

static int hsi_check_row(struct hsi_env *e, const struct hsi_row *r,
                         struct bln_set *ids, struct bln_set *sources,
                         const char *probe_buf)
{
    static char sf[HSI_FILES][HSI_SRC], con[HSI_CONTRACTS][HSI_SRC];
    int ns = 0, nc = 0;
    e->scanned++;
    if (hsi_row_ident(e, r, ids, sources))
        return 2;
    int room = hsi_row_room(e, r);
    if (room == 2)
        return 2;
    if (room)
        return 0;
    if (r->source[0]) {
        if (hsi_cpy(sf[ns++], HSI_SRC, r->source))
            return 2;
    }
    if (hsi_split_list(e, r->headers, r->source, sf, HSI_FILES, &ns,
                       "private/public header"))
        return 2;
    if (hsi_split_list(e, r->contract, r->source, con, HSI_CONTRACTS, &nc,
                       "service contract header"))
        return 2;
    if (hsi_stamps(e, r, con, nc) || hsi_probe(e, r, probe_buf))
        return 2;
    return hsi_scan_row_files(e, sf, ns, r->source) ||
           hsi_project_calls(e, r) ? 2 : 0;
}

/* ---------- shadow owners / members ---------- */

static const char *const k_hsi_owner_pats[] = {
    "tools/command/[a-z_]*.c", "tools/dev/[a-z_]*.c",
    "engine/controllers/src/[a-z_]*.c", "engine/services/src/[a-z_]*.c",
    "cognition/controllers/src/[a-z_]*.c",
    "cognition/services/src/[a-z_]*.c", "contexts/*/controllers/src/[a-z_]*.c",
    "contexts/*/services/src/[a-z_]*.c",
    "contexts/commons/modules/vcs/src/vcs_devloop.c",
};

static const char *const k_hsi_member_pats[] = {
    "platform/modules/base/src/[a-z_]*.c",
    "platform/modules/codec/src/[a-z_]*.c",
    "platform/modules/json/src/[a-z_]*.c",
    "contexts/commons/modules/vcs/src/[a-z_]*.c",
};

static int hsi_glob_any(const char *path, const char *const *pats, size_t np)
{
    for (size_t i = 0; i < np; i++)
        if (fnmatch(pats[i], path, 0) == 0)
            return 1;
    return 0;
}

static int hsi_check_owners(struct hsi_env *e, const struct hsi_pair *ps,
                            int np, struct bln_set *sources)
{
    static struct bln_set owners;
    memset(&owners, 0, sizeof owners);
    for (int i = 0; i < np; i++) {
        const struct hsi_pair *p = &ps[i];
        if (!p->a[0] || !p->b[0])
            continue;
        e->scanned++;
        if (bln_has(&owners, p->a))
            HSI_V(e, "  %s (duplicate HOTSHADOW_OWNER)\n", p->a);
        if (bln_add(&owners, p->a))
            return 2;
        if (!hsi_glob_any(p->a, k_hsi_owner_pats,
                          sizeof k_hsi_owner_pats / sizeof k_hsi_owner_pats[0]))
            HSI_V(e, "  %s (shadow shell is outside admitted static-shell "
                  "roots)\n", p->a);
        if (access(p->a, F_OK) != 0)
            HSI_V(e, "  %s (missing static authority shell)\n", p->a);
        if (!bln_has(sources, p->b))
            HSI_V(e, "  %s -> %s (target is not one pure service row)\n",
                  p->a, p->b);
        if (!strcmp(p->a, p->b))
            HSI_V(e, "  %s (service cannot be its own static shell)\n", p->a);
    }
    return 0;
}

/* Scans one admitted HOT_EXECUTE member with the same state/effect scans. */
static int hsi_member_scan(struct hsi_env *e, const char *m)
{
    e->scanned++;
    if (!hsi_glob_any(m, k_hsi_member_pats,
                      sizeof k_hsi_member_pats /
                          sizeof k_hsi_member_pats[0]))
        HSI_V(e, "  %s (HOT_EXECUTE member is outside pure library "
              "roots)\n", m);
    if (access(m, F_OK) != 0) {
        HSI_V(e, "  %s (missing HOT_EXECUTE member)\n", m);
        return 0;
    }
    return hsi_scan_member_files(e, m);
}

static int hsi_check_members(struct hsi_env *e, const struct hsi_pair *ps,
                             int np, struct bln_set *sources)
{
    static char members[HSI_BIG];
    for (int i = 0; i < np; i++) {
        const struct hsi_pair *p = &ps[i];
        if (!p->a[0] || !p->b[0])
            continue;
        if (!bln_has(sources, p->a))
            HSI_V(e, "  %s (HOTSHADOW_SERVICE_MEMBERS target is not a pure "
                  "service)\n", p->a);
        if (hsi_cpy(members, sizeof members, p->b))
            return 2;
        for (char *m = strtok(members, " \t"); m; m = strtok(NULL, " \t"))
            if (hsi_member_scan(e, m))
                return 2;
    }
    return 0;
}

/* ---------- entry points ---------- */

static int hsi_env_init(struct hsi_env *e, int fixture_mode)
{
    static const char forb[] =
        "(^|[^A-Za-z0-9_])(sqlite3_[A-Za-z0-9_]*|fopen|freopen|open|openat|"
        "close|read|write|pread|pwrite|stat|lstat|fstat|opendir|readdir|"
        "unlink|rename|mkdir|socket|connect|bind|listen|accept|send|recv|"
        "clock_gettime|gettimeofday|time|rand|random|getrandom|fork|vfork|"
        "exec[A-Za-z0-9_]*|system|popen|posix_spawn)[[:space:]]*\\(";
    static const char inc[] =
        "^#[[:space:]]*include[[:space:]]*[<\"]([^>\"]*/)?(wallet|storage|"
        "consensus|validation|net|coins|chain|mining|rpc)/";
    static const char proj[] =
        "(^|[^A-Za-z0-9_])((vcs_|zcl_)[A-Za-z0-9_]*)[[:space:]]*\\(";
    struct { regex_t *re; const char *pat; int nosub; } tab[] = {
        { &e->re_forb, forb, 1 },   { &e->re_inc, inc, 1 },
        { &e->re_proj, proj, 0 },   { &e->re_static,
                                      "^[[:space:]]*static[[:space:]]", 1 },
        { &e->re_extern, "^[[:space:]]*extern[[:space:]]", 1 },
        { &e->re_life,
          "__attribute__[[:space:]]*\\(\\([^)]*(constructor|destructor)", 1 },
        { &e->re_brace, "\\{[[:space:]]*$", 1 },
        { &e->re_srvc,
          "^(engine|cognition|contexts/[^/]+)/services/src/.+\\.c$", 1 },
        { &e->re_fixture, "^tests/harness/fixtures/.+\\.c$", 1 },
    };
    memset(e, 0, sizeof *e);
    e->fixture_mode = fixture_mode;
    for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++) {
        int err = regcomp(tab[i].re, tab[i].pat,
                          REG_EXTENDED | (tab[i].nosub ? REG_NOSUB : 0));
        if (err) {
            (void)reg_fail(tab[i].re, err);
            return 2;
        }
    }
    return 0;
}

/* Loads the three required inputs; prints the shell-matching FATAL lines and
 * returns nonzero on any missing or oversized file. */
static int hsi_load_inputs(const char *manifest, const char *probes,
                           const char *shadow, char *mbuf, size_t *mn,
                           char *pbuf, size_t *pn, char *sbuf, size_t *sn)
{
    if (hsi_slurp(manifest, mbuf, HSI_TEXT, mn)) {
        fprintf(stderr, "%s: FATAL — manifest '%s' missing\n", k_hsi_gate,
                manifest);
        return 2;
    }
    if (hsi_slurp(probes, pbuf, HSI_TEXT, pn)) {
        fprintf(stderr, "%s: FATAL — probe cases '%s' missing\n", k_hsi_gate,
                probes);
        return 2;
    }
    if (hsi_slurp(shadow, sbuf, HSI_TEXT, sn)) {
        fprintf(stderr, "%s: FATAL — manifest '%s' missing\n", k_hsi_gate,
                shadow);
        return 2;
    }
    return 0;
}

/* Parses and checks the shadow-owner and member mappings. */
static int hsi_run_shadow(struct hsi_env *e, const char *sbuf, size_t sn,
                          struct hsi_pair *owners, int *nown,
                          struct hsi_pair *members, int *nmem,
                          struct bln_set *sources)
{
    if (hsi_parse_pairs(sbuf, sn, "HOTSHADOW_OWNER(", owners, HSI_PAIRS,
                        nown))
        return 2;
    if (hsi_check_owners(e, owners, *nown, sources))
        return 2;
    if (hsi_parse_pairs(sbuf, sn, "HOTSHADOW_SERVICE_MEMBERS(", members,
                        HSI_PAIRS, nmem))
        return 2;
    return hsi_check_members(e, members, *nmem, sources);
}

int hsi_check(const char *manifest, const char *probes, const char *shadow,
              int fixture_mode, FILE *out)
{
    fputs("══ LINT: pure hot-swap service islands ══\n", out);
    static struct hsi_row rows[HSI_ROWS];
    static struct hsi_pair owners[HSI_PAIRS], members[HSI_PAIRS];
    static char mbuf[HSI_TEXT], pbuf[HSI_TEXT], sbuf[HSI_TEXT];
    static struct hsi_env e;
    size_t mn, pn, sn;
    int nrows = 0, nown = 0, nmem = 0;
    if (hsi_load_inputs(manifest, probes, shadow, mbuf, &mn, pbuf, &pn, sbuf,
                        &sn))
        return 2;
    if (hsi_parse_manifest(mbuf, mn, rows, HSI_ROWS, &nrows))
        return 2;
    if (gate_require_scanned(nrows, 1, k_hsi_gate,
                             "no HOTSWAP_SERVICE rows parsed"))
        return 2;
    if (hsi_env_init(&e, fixture_mode))
        return 2;
    struct bln_set ids, sources;
    memset(&ids, 0, sizeof ids);
    memset(&sources, 0, sizeof sources);
    int rc = 0;
    for (int i = 0; i < nrows && !rc; i++)
        rc = hsi_check_row(&e, &rows[i], &ids, &sources, pbuf);
    if (!rc)
        rc = hsi_run_shadow(&e, sbuf, sn, owners, &nown, members, &nmem,
                            &sources);
    regfree(&e.re_forb);
    regfree(&e.re_inc);
    regfree(&e.re_proj);
    regfree(&e.re_static);
    regfree(&e.re_extern);
    regfree(&e.re_life);
    regfree(&e.re_brace);
    regfree(&e.re_srvc);
    regfree(&e.re_fixture);
    if (!rc && gate_require_scanned(e.scanned, 1, k_hsi_gate,
                                    "service scan population is empty"))
        rc = 2;
    if (rc)
        return 2;
    if (e.v.len > 0) {
        fwrite(e.v.buf, 1, e.v.len, out);
        fputs("FAIL: a pure hot-swap service island owns state, effects, or "
              "an undeclared import.\n", out);
        return 1;
    }
    fprintf(out,
            "  OK: %d admitted service/shadow row(s), frozen contracts "
            "and stable imports only\n", e.scanned);
    return 0;
}

int check_hotswap_service_islands_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return hsi_check(
        env_or("ZCL_HOTSWAP_SERVICE_MANIFEST",
               "engine/composition/hotswap_services.def"),
        env_or("ZCL_HOTSWAP_PROBE_CASES",
               "engine/composition/hotswap_probe_cases.def"),
        env_or("ZCL_HOTSWAP_SHADOW_OWNERS",
               "engine/composition/hotswap_shadow_owners.def"),
        strcmp(env_or("ZCL_HOTSWAP_SERVICE_FIXTURE", "0"), "1") == 0,
        stdout);
}
