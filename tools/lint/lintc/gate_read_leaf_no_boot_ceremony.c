/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-read-leaf-no-boot-ceremony — a leaf declared READ
 * may not reach the datadir BOOT CEREMONY (node_db_open / _impl,
 * create_schema, node_db_migrate, db_quarantine_files,
 * progress_store_open) through the transitive callee closure of its bound
 * handler. Ported from tools/lint/check_read_leaf_no_boot_ceremony.sh
 * (deleted). Phases: parse the .def leaf macros (…_def.c), build the
 * corpus from git (handlers-named files UNION the CORPUS_DIRS tracked .c),
 * index C functions to callees (…_index.c), taint closure + baseline
 * ratchet verdict (…_verdict.c). Every population is floor-gated
 * (gate_require_scanned); unreadable files and failed subprocesses are
 * exit 2, never a skip. Selftest:
 * gate_read_leaf_no_boot_ceremony_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_read_leaf_no_boot_ceremony_priv.h"

const char *const rlb_banned[RLB_NBAN] = {
    "node_db_open",    "node_db_open_impl",   "create_schema",
    "node_db_migrate", "db_quarantine_files", "progress_store_open",
};

static const char *const k_corpus[] = {
    "tools/command",           "engine/controllers/src", "engine/services/src",
    "engine/models/src", "engine/modules/storage/src",
};
enum { RLB_NCORPUS = 5, RLB_GITBUF = 2u * 1024u * 1024u };

static char rlb_gitout[RLB_GITBUF];
static char rlb_hp[RLB_READS][160];

struct rlb_ent {
    char path[RLB_PATH];
    unsigned char incorp;
};

static struct rlb_ent rlb_ents[RLB_FILES];
static const char *rlb_ptrv[RLB_FILES];
static struct rlb_fnidx rlb_fi;
static struct rlb_readset rlb_rs;
static struct rlb_fatalset rlb_fs;
static int rlb_gn;

/* Reads the child's stdout into out until EOF. Excess bytes are drained and
 * dropped. Returns -1 on a read error, 1 when the output overflowed, else 0. */
static int rlb_drain(int fd, char *out, size_t cap, size_t *olen)
{
    char drain[4096];
    int ov = 0;
    for (;;) {
        ssize_t got = read(fd, drain, sizeof drain);
        if (got == 0)
            return ov;
        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (*olen + (size_t)got <= cap) {
            memcpy(out + *olen, drain, (size_t)got);
            *olen += (size_t)got;
        } else {
            ov = 1;
        }
    }
}

/* Waits for pid, retrying only on EINTR. -1 for any other failure. */
static int rlb_reap(pid_t pid, int *st)
{
    while (waitpid(pid, st, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    return 0;
}

/* Run git with argv (argv[0] is "git"), capture stdout fully. Returns the
 * exit status, -1 on a local failure, 2 when the output exceeds cap, or 4
 * when the child did not exit normally. */
static int rlb_git(char *out, size_t cap, size_t *olen, char *const argv[])
{
    int pfd[2], st = 0;
    *olen = 0;
    if (pipe(pfd))
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (pid == 0) {
        if (dup2(pfd[1], STDOUT_FILENO) < 0)
            _exit(126);
        close(pfd[0]);
        close(pfd[1]);
        execvp("git", argv);
        _exit(127);
    }
    close(pfd[1]);
    int dr = rlb_drain(pfd[0], out, cap, olen);
    close(pfd[0]);
    if (rlb_reap(pid, &st) || dr < 0)
        return -1;
    if (dr > 0) {
        fprintf(stderr, "%s: git output exceeds %u bytes\n", RLB_GATE,
                (unsigned)cap);
        return 2;
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : 4;
}

static int rlb_ent_add(const char *path)
{
    if (rlb_gn >= RLB_FILES) {
        fprintf(stderr, "%s: source file list exceeds %d\n", RLB_GATE,
                RLB_FILES);
        return 2;
    }
    struct rlb_ent *e = &rlb_ents[rlb_gn++];
    if (ovf(snprintf(e->path, sizeof e->path, "%s", path), sizeof e->path))
        return 2;
    e->incorp = 0;
    for (int k = 0; k < RLB_NCORPUS; k++) {
        size_t l = strlen(k_corpus[k]);
        if (!strncmp(path, k_corpus[k], l) && path[l] == '/') {
            e->incorp = 1;
            break;
        }
    }
    return 0;
}

static int rlb_listing_split(const char *buf, size_t len)
{
    size_t s = 0;
    while (s < len) {
        size_t e = s;
        while (e < len && buf[e] != '\n')
            e++;
        if (e > s) {
            char tmp[RLB_PATH];
            if (e - s >= sizeof tmp) {
                fprintf(stderr, "%s: git listing path exceeds %d\n", RLB_GATE,
                        RLB_PATH);
                return 2;
            }
            memcpy(tmp, buf + s, e - s);
            tmp[e - s] = '\0';
            if (rlb_ent_add(tmp))
                return 2;
        }
        s = e + 1;
    }
    return 0;
}

static int rlb_entcmp(const void *a, const void *b)
{
    return strcmp(((const struct rlb_ent *)a)->path,
                  ((const struct rlb_ent *)b)->path);
}

/* Sorts and de-duplicates rlb_ents; returns the distinct count. */
static int rlb_ent_sort(void)
{
    qsort(rlb_ents, (size_t)rlb_gn, sizeof rlb_ents[0], rlb_entcmp);
    int m = 0;
    for (int i = 0; i < rlb_gn; i++)
        if (m == 0 || strcmp(rlb_ents[m - 1].path, rlb_ents[i].path))
            rlb_ents[m++] = rlb_ents[i];
    return m;
}

static int rlb_rowcmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int rlb_hpats_build(int *nuniq)
{
    for (int i = 0; i < rlb_rs.n; i++)
        if (ovf(snprintf(rlb_hp[i], sizeof rlb_hp[i], "%s(",
                         rlb_rs.v[i].handler), sizeof rlb_hp[i]))
            return 2;
    qsort(rlb_hp, (size_t)rlb_rs.n, sizeof rlb_hp[0], rlb_rowcmp);
    int m = 0;
    for (int i = 0; i < rlb_rs.n; i++)
        if (m == 0 || strcmp(rlb_hp[m - 1], rlb_hp[i])) {
            if (m != i)
                memcpy(rlb_hp[m], rlb_hp[i], sizeof rlb_hp[m]);
            m++;
        }
    *nuniq = m;
    return 0;
}

/* Files under root that name a READ handler symbol (git grep -F). */
static int rlb_grep_handlers(const char *root, int nh)
{
    static char *ga[2 * RLB_READS + 16];
    size_t olen = 0;
    int a = 0;
    ga[a++] = (char *)"git";
    ga[a++] = (char *)"-C";
    ga[a++] = (char *)root;
    ga[a++] = (char *)"grep";
    ga[a++] = (char *)"-l";
    ga[a++] = (char *)"-F";
    for (int i = 0; i < nh; i++) {
        ga[a++] = (char *)"-e";
        ga[a++] = rlb_hp[i];
    }
    ga[a++] = (char *)"--";
    ga[a++] = (char *)"*.c";
    ga[a] = NULL;
    int grc = rlb_git(rlb_gitout, sizeof rlb_gitout, &olen, ga);
    if (grc < 0 || grc >= 2) {
        fprintf(stderr,
                "%s: FATAL — git grep for handler\n"
                "  definitions failed (exit %d); refusing a verdict.\n",
                RLB_GATE, grc);
        return 2;
    }
    return rlb_listing_split(rlb_gitout, olen);
}

/* Every tracked .c under the CORPUS_DIRS. */
static int rlb_list_corpus(const char *root)
{
    static char *la[RLB_NCORPUS + 8];
    static char spec[RLB_NCORPUS][256];
    size_t olen = 0;
    int b = 0;
    la[b++] = (char *)"git";
    la[b++] = (char *)"-C";
    la[b++] = (char *)root;
    la[b++] = (char *)"ls-files";
    la[b++] = (char *)"--";
    for (int k = 0; k < RLB_NCORPUS; k++) {
        if (ovf(snprintf(spec[k], sizeof spec[k], "%s/*.c", k_corpus[k]),
                sizeof spec[k]))
            return 2;
        la[b++] = spec[k];
    }
    la[b] = NULL;
    int grc = rlb_git(rlb_gitout, sizeof rlb_gitout, &olen, la);
    if (grc != 0) {
        fprintf(stderr,
                "%s: FATAL — git ls-files failed (exit %d);"
                " refusing a verdict.\n",
                RLB_GATE, grc);
        return 2;
    }
    return rlb_listing_split(rlb_gitout, olen);
}

static int rlb_phase_banned(const char *root, int nfiles)
{
    unsigned char found[RLB_NBAN] = { 0 };
    for (int i = 0; i < nfiles; i++) {
        if (!rlb_ents[i].incorp)
            continue;
        int rc = rlb_banned_scan_file(root, rlb_ents[i].path, found);
        if (rc)
            return rc;
    }
    char missing[512];
    missing[0] = '\0';
    for (int k = 0; k < RLB_NBAN; k++)
        if (!found[k]) {
            if (ovf(snprintf(missing + strlen(missing),
                             sizeof missing - strlen(missing), " %s",
                             rlb_banned[k]), sizeof missing))
                return 2;
        }
    if (missing[0]) {
        fprintf(stderr,
                "%s: FATAL — banned symbol(s) not found\n"
                "  anywhere in the scanned corpus:%s\n"
                "  Either they were renamed (re-point BANNED) or the corpus"
                " moved.\n"
                "  Refusing to report 'clean' while forbidding calls nobody"
                " makes.\n",
                RLB_GATE, missing);
        return 2;
    }
    return 0;
}

/* Phase 1: the leaf declarations and their READ handler records. */
static int rlb_phase_defs(const char *root, const char *def_dir, int *nleaf)
{
    int ndefs = 0, rc;
    char hint[512];
    rc = rlb_parse_defs(root, def_dir, &rlb_rs, nleaf, &ndefs, &rlb_fs);
    if (rc)
        return rc;
    if (rlb_fs.n)
        return rlb_def_fatal_report(&rlb_fs);
    if (ovf(snprintf(hint, sizeof hint, "no *.def under: %s", def_dir),
            sizeof hint))
        return 2;
    if ((rc = gate_require_scanned(ndefs, 1, RLB_GATE, hint)))
        return rc;
    if (ovf(snprintf(hint, sizeof hint,
                     "leaf population collapsed under floor (parsed %d)",
                     *nleaf), sizeof hint))
        return 2;
    if ((rc = gate_require_scanned(
             *nleaf, atoi(env_or("ZCL_READ_LEAF_LEAF_FLOOR", "160")),
             RLB_GATE, hint)))
        return rc;
    if (ovf(snprintf(hint, sizeof hint,
                     "handler-binding READ-leaf population collapsed under"
                     " floor (parsed %d)", rlb_rs.n), sizeof hint))
        return 2;
    return gate_require_scanned(
        rlb_rs.n, atoi(env_or("ZCL_READ_LEAF_READ_FLOOR", "60")), RLB_GATE,
        hint);
}

/* Phase 2: the scanned corpus, the handler-named files UNION CORPUS_DIRS. */
static int rlb_phase_corpus(const char *root, const char *def_dir,
                            int *nfiles)
{
    int nh = 0, rc;
    char hint[512];
    if (rlb_hpats_build(&nh))
        return 2;
    if (ovf(snprintf(hint, sizeof hint,
                     "no READ handler symbols parsed out of %s/*.def",
                     def_dir), sizeof hint))
        return 2;
    if ((rc = gate_require_scanned(nh, 40, RLB_GATE, hint)))
        return rc;
    if ((rc = rlb_grep_handlers(root, nh)))
        return rc;
    if ((rc = rlb_list_corpus(root)))
        return rc;
    *nfiles = rlb_ent_sort();
    if (ovf(snprintf(hint, sizeof hint,
                     "the scanned corpus collapsed (%d files); a CORPUS_DIRS"
                     " entry was renamed or moved.", *nfiles), sizeof hint))
        return 2;
    return gate_require_scanned(
        *nfiles, atoi(env_or("ZCL_READ_LEAF_CORPUS_FLOOR", "300")), RLB_GATE,
        hint);
}

/* Phase 3: index every corpus C file into function -> callees. */
static int rlb_phase_index(const char *root, int nfiles)
{
    char hint[512];
    int rc;
    for (int i = 0; i < nfiles; i++)
        rlb_ptrv[i] = rlb_ents[i].path;
    rlb_fi.n = 0; /* entries are written on add; avoid touching the whole table */
    rlb_fi.ndef = 0;
    rlb_fi.pool_n = 0;
    if ((rc = rlb_index_paths(root, rlb_ptrv, nfiles, &rlb_fi)))
        return rc;
    if (ovf(snprintf(hint, sizeof hint,
                     "C function index collapsed under floor (indexed %d)",
                     rlb_fi.ndef), sizeof hint))
        return 2;
    return gate_require_scanned(
        rlb_fi.ndef, atoi(env_or("ZCL_READ_LEAF_FN_FLOOR", "2000")), RLB_GATE,
        hint);
}

/* Phase 4: the taint verdict, the resolved-handler floor, and the PASS line. */
static int rlb_phase_verdict(const char *baseline, const char *base_rel,
                             int nfiles)
{
    const char *mode = env_or("ZCL_LINT_MODE", "FAIL");
    char hint[512];
    struct rlb_counts c;
    FILE *tf = fopen(baseline, "a");
    if (!tf) {
        fprintf(stderr, "%s: cannot touch %s\n", RLB_GATE, baseline);
        return 2;
    }
    fclose(tf);
    int vrc = rlb_verdict(&rlb_rs, &rlb_fi, baseline, base_rel, &c, stdout);
    if (vrc == 2)
        return 2;
    if (ovf(snprintf(hint, sizeof hint,
                     "only %d of %d READ handlers resolved into the function"
                     " index — the scan is hollow; re-point it before"
                     " trusting a verdict.", c.resolved, rlb_rs.n),
            sizeof hint))
        return 2;
    int rc = gate_require_scanned(
        c.resolved, atoi(env_or("ZCL_READ_LEAF_RESOLVED_FLOOR", "40")),
        RLB_GATE, hint);
    if (rc)
        return rc;
    if (vrc == 1 && !strcmp(mode, "FAIL"))
        return 1;
    printf("[%s] PASS (%d READ leaf handler(s) resolved over %d function(s)"
           " in %d file(s); none reaches %d banned boot-ceremony symbol(s);"
           " %d grandfathered of %d baseline entry(ies))\n",
           RLB_GATE, c.resolved, rlb_fi.ndef, nfiles, RLB_NBAN, c.ngrand,
           c.nbase);
    return 0;
}

int check_read_leaf_no_boot_ceremony_run(int argc, char **argv)
{
    const char *root = argc >= 1 ? argv[0] : ".";
    const char *def_dir =
        env_or("ZCL_READ_LEAF_DEF_DIR", "engine/composition/commands");
    const char *base_rel = env_or("ZCL_READ_LEAF_BASELINE",
                                  "tools/lint/read_leaf_boot_ceremony_baseline.txt");
    char baseline[RLB_PATH];
    int rc, nleaf = 0, nfiles = 0;

    if (ovf(snprintf(baseline, sizeof baseline, "%s/%s", root, base_rel),
            sizeof baseline))
        return 2;
    if ((rc = rlb_phase_defs(root, def_dir, &nleaf)))
        return rc;
    if ((rc = rlb_phase_corpus(root, def_dir, &nfiles)))
        return rc;
    if ((rc = rlb_phase_banned(root, nfiles)))
        return rc;
    if ((rc = rlb_phase_index(root, nfiles)))
        return rc;
    return rlb_phase_verdict(baseline, base_rel, nfiles);
}
