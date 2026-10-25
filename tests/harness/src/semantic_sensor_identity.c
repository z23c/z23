/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: semantic_sensor checks that facts describe the object: the clang-facts rule senses each TU with its dev object's own argv, and the object compiler enters the IDENTITY record.
 *
 * argv runs in the semantic_manifest group: it needs only make, so it
 * runs wherever the tree builds. The rest is part of the semantic_sensor
 * group (test_semantic_manifest.c) and runs only where
 * build/bin/z23-clang-manifest is built.
 *
 *   argv       `make -n` of dev objects and their clang-facts targets, for
 *              one TU of every directory in DEV_HOT_SRC_DIRS (-O2),
 *              every dev object or object directory the Makefile gives its
 *              own DEV_COMPILE_CFLAGS or CC (found in `make -p`; each hot
 *              directory must be among them), and ordinary (-Og)
 *              samples: the sensor's --cc and argv after `--` equal the
 *              object's compiler (its compile-cache wrapper dropped) and
 *              flags, token for token.
 *              The identity TU, whose object bakes a receipt only its own
 *              rule may name, must be refused rather than sensed with other
 *              flags.
 *   resense    the facts rule, really run for one hot TU: unchanged, it
 *              does not re-sense; another hot optimizer or another
 *              toolchain identity re-senses it.
 *   compiler   --cc names the object compiler in IDENTITY by spelled path,
 *              SHA3-256 of its bytes and of the objects the loader maps
 *              for it, with --toolchain-id; no --cc or no toolchain is
 *              "object-cc unknown"; an unresolvable one refuses, and a
 *              compile-cache masquerade is resolved through (or unknown).
 *              Manifests of the same tree under two compilers differ in
 *              IDENTITY alone, and the consumer widens across them where
 *              it narrows under one.
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"
#include "test/semantic_consumer_fixture.h"
#include "test/semantic_facts_fixture.h"
#include "util/spawn.h"
#include "vcs/semantic_manifest.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SSI_SENSOR "build/bin/z23-clang-manifest"
#define SSI_MAKE_OUT (4u << 20)
#define SSI_TOKENS 1024

int semantic_sensor_argv_tests(void);
int semantic_sensor_identity_tests(void);

/* ── argv: the facts rule senses exactly what the object compiles ───────── */

/* Ordinary (-Og) samples; the hot directories and every dev-object
 * override come from the Makefile's own database (ssi_derive). */
static const char *const k_ssi_ordinary_srcs[] = {
    "engine/modules/hotswap/src/hotswap_activate.c",
    "platform/modules/util/src/signal_handler.c",
};
#define SSI_IDENTITY_TU "platform/modules/util/src/clientversion.c"
#define SSI_MAX_PROBES 256

/* The sources the dry run compares, derived from the Makefile. */
struct ssi_probes {
    char dev_obj_dir[PATH_MAX];
    char hot[1024];           /* DEV_HOT_SRC_DIRS, as the Makefile expands it */
    char *src[SSI_MAX_PROBES];
    size_t n;
    size_t hot_dirs, hot_found; /* hot directories, and those the scan saw */
    size_t overrides;          /* dev-object DEV_COMPILE_CFLAGS/CC overrides */
    bool unprobed;             /* an override this test cannot place */
};

/* Backslash-newline continuations joined, so one recipe is one line. */
static void ssi_join(char *s)
{
    char *w = s;
    for (char *r = s; *r != '\0'; r++) {
        if (r[0] == '\\' && r[1] == '\n') {
            *w++ = ' ';
            r++;
            continue;
        }
        *w++ = *r;
    }
    *w = '\0';
}

/* The line of `text` holding `needle` (and `also`, when set), copied. */
static bool ssi_line(const char *text, const char *needle, const char *also,
                     char *out, size_t cap)
{
    for (const char *p = strstr(text, needle); p != NULL;
         p = strstr(p + 1, needle)) {
        const char *b = p, *e = strchr(p, '\n');
        while (b > text && b[-1] != '\n')
            b--;
        if (e == NULL)
            e = p + strlen(p);
        if ((size_t)(e - b) >= cap)
            continue;
        memcpy(out, b, (size_t)(e - b));
        out[e - b] = '\0';
        if (also == NULL || strstr(out, also) != NULL)
            return true;
    }
    return false;
}

/* SIZE_MAX signals overflow; a prefix is not a complete argv. */
static size_t ssi_split(char *s, char **tok, size_t cap)
{
    size_t n = 0;
    char *save = NULL;
    for (char *t = strtok_r(s, " \t", &save); t != NULL;
         t = strtok_r(NULL, " \t", &save)) {
        if (n == cap)
            return SIZE_MAX;
        tok[n++] = t;
    }
    return n;
}

static bool ssi_wrapper(const char *word)
{
    const char *base = strrchr(word, '/');
    base = base != NULL ? base + 1 : word;
    return strcmp(base, "zcc") == 0 || strcmp(base, "ccache") == 0 ||
           strcmp(base, "sccache") == 0;
}

/* The --cc value of a facts recipe, before its `--` (cut in place). */
static const char *ssi_sensor_cc(char *zsm, const char *ztail)
{
    char *ccopt = strstr(zsm, " --cc ");
    if (ccopt == NULL || ccopt >= ztail)
        return NULL;
    ccopt[6 + strcspn(ccopt + 6, " \t")] = '\0';
    return ccopt + 6;
}

/* The object's flags (after its compiler word) against the sensor's. */
static bool ssi_same_flags(const char *src, char *const *o, size_t on,
                           char *const *z, size_t zn)
{
    for (size_t k = 0; k < on && k < zn; k++) {
        if (strcmp(o[k], z[k]) != 0) {
            printf("  argv %s: word %zu: object %s, sensor %s\n", src, k,
                   o[k], z[k]);
            return false;
        }
    }
    if (on != zn)
        printf("  argv %s: object has %zu flags, sensor %zu\n", src, on, zn);
    return on == zn;
}

/* Report whether the object recipe names the sensor's compiler. */
static bool ssi_same_cc(const char *src, char *const *o, size_t on,
                        size_t at, const char *cc)
{
    bool same = on > at && cc != NULL && strcmp(o[at], cc) == 0;
    if (!same)
        printf("  argv %s: object compiler %s, sensor --cc %s\n", src,
               on > at ? o[at] : "(none)", cc != NULL ? cc : "(none)");
    return same;
}

/* Compare one source's object recipe and facts recipe. A compiler mismatch
 * is reported and the flags are still compared. */
static bool ssi_same_argv(const char *src, char *obj, char *zsm)
{
    char **o = zcl_calloc(SSI_TOKENS, sizeof(char *), "ssi.otok");
    char **z = zcl_calloc(SSI_TOKENS, sizeof(char *), "ssi.ztok");
    char *otail = strstr(obj, " -- "), *ztail = strstr(zsm, " -- ");
    bool ok = o != NULL && z != NULL && otail != NULL && ztail != NULL;
    if (ok) {
        const char *cc = ssi_sensor_cc(zsm, ztail);
        size_t on = ssi_split(otail + 4, o, SSI_TOKENS);
        size_t zn = ssi_split(ztail + 4, z, SSI_TOKENS);
        if (on == SIZE_MAX || zn == SIZE_MAX) {
            printf("  argv %s: token capacity exceeded\n", src);
            ok = false;
            goto done;
        }
        size_t at = on > 0 && ssi_wrapper(o[0]) ? 1 : 0;
        bool same_cc = ssi_same_cc(src, o, on, at, cc);
        ok = on > at && ssi_same_flags(src, o + at + 1, on - at - 1, z, zn) &&
             same_cc;
    }
done:
    free(o);
    free(z);
    return ok;
}

/* One source against the dry run: equal argv, or the identity TU refused. */
static bool ssi_probe_src(const char *text, const char *src)
{
    char needle[PATH_MAX * 2], stem[PATH_MAX];
    char *obj = zcl_malloc(1u << 16, "ssi.obj");
    char *zsm = zcl_malloc(1u << 16, "ssi.zsm");
    bool refused, ok = obj != NULL && zsm != NULL;
    (void)snprintf(stem, sizeof(stem), "%.*s", (int)(strlen(src) - 2), src);
    (void)snprintf(needle, sizeof(needle), "/%s.o\" \"%s\"", stem, src);
    if (ok && !ssi_line(text, needle, " -- ", obj, 1u << 16)) {
        printf("  argv %s: no object recipe in the dry run\n", src);
        ok = false;
    }
    (void)snprintf(needle, sizeof(needle), "build/clang-facts/%s.zsm", stem);
    refused = ok && ssi_line(text, needle, "clang-facts: refused", zsm, 1u << 16);
    if (ok && strcmp(src, SSI_IDENTITY_TU) == 0) {
        if (!refused)
            printf("  argv %s: the identity TU is sensed, not refused\n", src);
        ok = refused;
    } else if (ok && refused) {
        printf("  argv %s: refused: %s\n", src, zsm);
        ok = false;
    } else if (ok && !ssi_line(text, needle, "z23-clang-manifest emit", zsm,
                               1u << 16)) {
        printf("  argv %s: no clang-facts recipe in the dry run\n", src);
        ok = false;
    } else if (ok) {
        ok = ssi_same_argv(src, obj, zsm);
    }
    free(obj);
    free(zsm);
    return ok;
}

static bool ssi_write(const char *path, const char *text)
{
    FILE *fp = fopen(path, "wb");
    bool ok = fp != NULL && fputs(text, fp) >= 0;
    if (fp != NULL && fclose(fp) != 0)
        ok = false;
    return ok;
}

static bool ssi_probe_add(struct ssi_probes *p, const char *src)
{
    for (size_t k = 0; k < p->n; k++)
        if (strcmp(p->src[k], src) == 0)
            return true;
    if (p->n >= SSI_MAX_PROBES || (p->src[p->n] = strdup(src)) == NULL)
        return false;
    p->n++;
    return true;
}

/* The first .c of dir, in byte order: one TU the directory's flags reach. */
static bool ssi_first_c(const char *dir, char *out, size_t cap)
{
    DIR *d = opendir(dir);
    char best[NAME_MAX + 1] = "";
    if (d == NULL)
        return false;
    for (struct dirent *e = readdir(d); e != NULL; e = readdir(d)) {
        size_t n = strlen(e->d_name);
        if (n > 2 && strcmp(e->d_name + n - 2, ".c") == 0 &&
            (best[0] == '\0' || strcmp(e->d_name, best) < 0))
            (void)snprintf(best, sizeof(best), "%s", e->d_name);
    }
    (void)closedir(d);
    return best[0] != '\0' &&
           (size_t)snprintf(out, cap, "%s/%s", dir, best) < cap;
}

static bool ssi_is_hot(const struct ssi_probes *p, const char *dir, size_t n)
{
    for (const char *h = p->hot; *h != '\0';) {
        size_t w = strcspn(h, " ");
        if (w == n && strncmp(h, dir, n) == 0)
            return true;
        h += w;
        h += strspn(h, " ");
    }
    return false;
}

/* A dev-object override target or pattern ("<DEV_OBJ_DIR>/<dir>/%.o" or
 * "<DEV_OBJ_DIR>/<path>.o"): probe the TU it reaches. */
static void ssi_override(struct ssi_probes *p, const char *target, size_t len)
{
    size_t root = strlen(p->dev_obj_dir);
    char path[PATH_MAX], src[PATH_MAX];
    if (len <= root + 3 || strncmp(target, p->dev_obj_dir, root) != 0 ||
        target[root] != '/' || strncmp(target + len - 2, ".o", 2) != 0)
        return;
    p->overrides++;
    target += root + 1;
    len -= root + 1;
    if (len > 4 && strncmp(target + len - 4, "/%.o", 4) == 0 &&
        memchr(target, '%', len - 4) == NULL) {
        size_t before = p->n;
        (void)snprintf(path, sizeof(path), "%.*s", (int)(len - 4), target);
        if (!ssi_first_c(path, src, sizeof(src)) || !ssi_probe_add(p, src))
            p->unprobed = true;
        p->hot_found += p->n > before && ssi_is_hot(p, path, len - 4);
    } else if (memchr(target, '%', len) == NULL) {
        (void)snprintf(src, sizeof(src), "%.*s.c", (int)(len - 2), target);
        if (access(src, F_OK) != 0 || !ssi_probe_add(p, src))
            p->unprobed = true;
    } else {
        printf("  argv: override pattern %.*s names no directory\n",
               (int)len, target);
        p->unprobed = true;
    }
}

/* "# VAR op value" (a pattern block's variable) or "tgt: VAR op value". */
static bool ssi_is_override_var(const char *s)
{
    static const char *const vars[] = {"DEV_COMPILE_CFLAGS ", "CC "};
    for (size_t k = 0; k < sizeof(vars) / sizeof(vars[0]); k++) {
        size_t n = strlen(vars[k]);
        if (strncmp(s, vars[k], n) == 0 &&
            (strncmp(s + n, "= ", 2) == 0 || strncmp(s + n, ":= ", 3) == 0 ||
             strncmp(s + n, "+= ", 3) == 0 || strncmp(s + n, "?= ", 3) == 0 ||
             strncmp(s + n, "::= ", 4) == 0))
            return true;
    }
    return false;
}

/* One line of `make -p`: the probe's echoes, pattern-specific blocks
 * ("<pattern> :" then "# makefile ..." then "# VAR op value") and
 * target-specific assignments ("<target>: VAR op value"). */
static void ssi_db_line(struct ssi_probes *p, const char *line, char *pattern,
                        size_t cap)
{
    const char *colon;
    size_t n = strlen(line);
    if (strncmp(line, "echo SSI_DEV_OBJ_DIR=", 21) == 0) {
        (void)snprintf(p->dev_obj_dir, sizeof(p->dev_obj_dir), "%s", line + 21);
    } else if (strncmp(line, "echo SSI_HOT_DIRS=", 18) == 0) {
        (void)snprintf(p->hot, sizeof(p->hot), "%s", line + 18);
    } else if (line[0] == '#') {
        if (pattern[0] != '\0' && strncmp(line, "# ", 2) == 0 &&
            ssi_is_override_var(line + 2))
            ssi_override(p, pattern, strlen(pattern));
        return;
    } else if (n > 2 && strcmp(line + n - 2, " :") == 0 && n - 2 < cap) {
        (void)snprintf(pattern, cap, "%.*s", (int)(n - 2), line);
        return;
    } else if ((colon = strstr(line, ".o: ")) != NULL &&
               ssi_is_override_var(colon + 4)) {
        ssi_override(p, line, (size_t)(colon + 2 - line));
    }
    pattern[0] = '\0';
}

/* `make -p -n` of a probe that echoes DEV_OBJ_DIR and DEV_HOT_SRC_DIRS,
 * into `db` (a file: the database is tens of megabytes). */
static bool ssi_database(const char *dir, const char *db)
{
    char probe[PATH_MAX];
    bool timed_out = false;
    char msg[4096];
    (void)snprintf(probe, sizeof(probe), "%s/db.mk", dir);
    if (!ssi_write(probe, ".PHONY: ssi-db\nssi-db:\n"
                          "\t@echo SSI_DEV_OBJ_DIR=$(DEV_OBJ_DIR)\n"
                          "\t@echo SSI_HOT_DIRS=$(DEV_HOT_SRC_DIRS)\n"))
        return false;
    const char *argv[] = {"sh", "-c", "f=$1; shift; exec \"$@\" >\"$f\" 2>&1",
                          "sh", db, "env", "-u", "MAKEFLAGS", "-u", "MFLAGS",
                          "-u", "MAKELEVEL", "-u", "MAKEOVERRIDES", "-u",
                          "GNUMAKEFLAGS", "make", "--no-print-directory", "-p",
                          "-n", "-f", "Makefile", "-f", probe, "ssi-db", NULL};
    int rc = zcl_spawn_capture_merged_observed(argv, msg, sizeof(msg), 600000,
                                               &timed_out);
    if (rc != 0 || timed_out)
        printf("  make -p exited %d%s: %s\n", rc,
               timed_out ? " (timed out)" : "", msg);
    return rc == 0 && !timed_out;
}

/* The probe set: one TU of every directory and every object the Makefile
 * gives its own DEV_COMPILE_CFLAGS or CC, plus the ordinary samples. */
static bool ssi_derive(const char *dir, struct ssi_probes *p)
{
    char db[PATH_MAX], pattern[PATH_MAX] = "";
    char *line = NULL;
    size_t lcap = 0;
    ssize_t got;
    FILE *fp;
    (void)snprintf(db, sizeof(db), "%s/db.txt", dir);
    if (!ssi_database(dir, db) || (fp = fopen(db, "r")) == NULL)
        return false;
    /* Pass 0 reads the echoes (DEV_OBJ_DIR, the hot list), pass 1 the
     * overrides, wherever make printed its database relative to them. */
    for (int pass = 0; pass < 2 && fseek(fp, 0, SEEK_SET) == 0; pass++) {
        while ((got = getline(&line, &lcap, fp)) > 0) {
            if (line[got - 1] == '\n')
                line[got - 1] = '\0';
            if ((strncmp(line, "echo SSI_", 9) == 0) == (pass == 0))
                ssi_db_line(p, line, pattern, sizeof(pattern));
        }
    }
    free(line);
    (void)fclose(fp);
    for (const char *h = p->hot; *h != '\0'; h += strspn(h, " ")) {
        h += strcspn(h, " ");
        p->hot_dirs++;
    }
    for (size_t k = 0; k < sizeof(k_ssi_ordinary_srcs) / sizeof(char *); k++)
        if (!ssi_probe_add(p, k_ssi_ordinary_srcs[k]))
            return false;
    return p->dev_obj_dir[0] != '\0';
}

/* A probe makefile read after the repository's: every probed source's dev
 * object and facts target, named as the Makefile itself names them. */
static bool ssi_probe_makefile(const char *path, const struct ssi_probes *p)
{
    size_t cap = 64 + p->n * (PATH_MAX / 4), w;
    char *text = zcl_malloc(cap, "ssi.probe_mk");
    bool ok = text != NULL;
    w = ok ? (size_t)snprintf(text, cap, "SSI_SRCS :=") : 0;
    for (size_t k = 0; ok && k < p->n && w < cap; k++)
        w += (size_t)snprintf(text + w, cap - w, " %s", p->src[k]);
    if (ok && w < cap)
        w += (size_t)snprintf(
            text + w, cap - w,
            "\n.PHONY: ssi-argv-probe\n"
            "ssi-argv-probe: $(patsubst %%.c,$(DEV_OBJ_DIR)/%%.o,$(SSI_SRCS)) "
            "$(patsubst %%.c,$(CLANG_FACTS_OUT_DIR)/%%.zsm,$(SSI_SRCS))\n");
    ok = ok && w < cap && ssi_write(path, text);
    free(text);
    return ok;
}

static bool ssi_dry_run(const char *probe, const struct ssi_probes *p,
                        char *out, size_t cap)
{
    const char **argv = zcl_calloc(32 + 2 * p->n, sizeof(char *), "ssi.argv");
    size_t k = 0;
    bool timed_out = false;
    const char *const env[] = {"env",         "-u", "MAKEFLAGS", "-u",
                               "MFLAGS",      "-u", "MAKELEVEL", "-u",
                               "MAKEOVERRIDES", "-u", "GNUMAKEFLAGS"};
    if (argv == NULL)
        return false;
    for (size_t i = 0; i < sizeof(env) / sizeof(env[0]); i++)
        argv[k++] = env[i];
    argv[k++] = "make";
    argv[k++] = "--no-print-directory";
    argv[k++] = "-n";
    argv[k++] = "-f";
    argv[k++] = "Makefile";
    argv[k++] = "-f";
    argv[k++] = probe;
    for (size_t i = 0; i < p->n; i++) {
        argv[k++] = "-W";
        argv[k++] = p->src[i];
    }
    argv[k++] = "ssi-argv-probe";
    argv[k] = NULL;
    int rc = zcl_spawn_capture_merged_observed(argv, out, cap, 600000,
                                               &timed_out);
    if (rc != 0 || timed_out)
        printf("  make -n exited %d%s: %.2000s\n", rc,
               timed_out ? " (timed out)" : "", out);
    free(argv);
    return rc == 0 && !timed_out;
}

/* Needs only `make`: no sensor, so it runs in the semantic_manifest group
 * wherever the tree builds. */
static int ssi_t_argv(void)
{
    int failures = 0;
    char dir[1024] = {0}, probe[PATH_MAX];
    char *out = zcl_malloc(SSI_MAKE_OUT, "ssi.make_out");
    struct ssi_probes *p = zcl_calloc(1, sizeof(*p), "ssi.probes");
    TEST_CASE("semantic_manifest: clang-facts senses each TU with its dev object's own compiler and argv") {
        ASSERT(out != NULL && p != NULL);
        ASSERT(test_mkdtemp(dir, sizeof(dir), "semsensor_argv") != NULL);
        ASSERT(ssi_derive(dir, p));
        printf("  argv: %zu hot directories (%zu seen as overrides), "
               "%zu dev-object overrides, %zu sources probed\n",
               p->hot_dirs, p->hot_found, p->overrides, p->n);
        ASSERT(!p->unprobed);
        ASSERT(p->hot_dirs > 0);
        ASSERT_EQ(p->hot_found, p->hot_dirs);
        (void)snprintf(probe, sizeof(probe), "%s/probe.mk", dir);
        ASSERT(ssi_probe_makefile(probe, p));
        ASSERT(ssi_dry_run(probe, p, out, SSI_MAKE_OUT));
        ssi_join(out);
        size_t bad = 0, identity = 0;
        for (size_t k = 0; k < p->n; k++) {
            bad += !ssi_probe_src(out, p->src[k]);
            identity += strcmp(p->src[k], SSI_IDENTITY_TU) == 0;
        }
        ASSERT_EQ(bad, 0);
        ASSERT_EQ(identity, 1);
    } TEST_END
    for (size_t k = 0; p != NULL && k < p->n; k++)
        free(p->src[k]);
    free(p);
    free(out);
    if (dir[0] != '\0')
        (void)test_rm_rf_recursive(dir);
    return failures;
}

/* Fixed recipes leave room for extra flags and the terminating NUL. */
struct ssi_capacity_recipes {
    char obj[SSI_TOKENS * 6 + 64];
    char zsm[SSI_TOKENS * 6 + 64];
};

static void ssi_capacity_init(struct ssi_capacity_recipes *r)
{
    size_t on = strlen(r->obj), zn = strlen(r->zsm);
    for (size_t k = 0; k < SSI_TOKENS - 1; k++) {
        memcpy(r->obj + on, "-DA=1 ", 6);
        memcpy(r->zsm + zn, "-DA=1 ", 6);
        on += 6;
        zn += 6;
    }
    r->obj[on] = '\0';
    r->zsm[zn] = '\0';
}

static int ssi_t_argv_capacity(void)
{
    int failures = 0;
    struct ssi_capacity_recipes r = {"object -- gcc ", "sensor --cc gcc -- "};
    struct ssi_capacity_recipes copy;
    ssi_capacity_init(&r);
    TEST_CASE("semantic_manifest: complete argv compares equal and excess object flag refuses") {
        copy = r;
        ASSERT(ssi_same_argv("capacity.c", copy.obj, copy.zsm));
        char small_o[] = "object -- gcc -DA=1";
        char small_z[] = "sensor --cc gcc -- -DA=1";
        ASSERT(ssi_same_argv("small.c", small_o, small_z));
        memcpy(r.obj + strlen(r.obj), "-DB=2", sizeof("-DB=2"));
        copy = r;
        ASSERT(!ssi_same_argv("overflow.c", copy.obj, copy.zsm));
    } TEST_END
    return failures;
}

static int ssi_t_split_capacity(void)
{
    int failures = 0;
    struct ssi_capacity_recipes r = {"object -- gcc ", "sensor --cc gcc -- "};
    struct ssi_capacity_recipes copy;
    char *tok[SSI_TOKENS];
    ssi_capacity_init(&r);
    TEST_CASE("semantic_manifest: token counts preserve capacity and signal overflow") {
        copy = r;
        ASSERT_EQ(ssi_split(strstr(copy.obj, " -- ") + 4, tok, SSI_TOKENS),
                  SSI_TOKENS);
        ASSERT_EQ(ssi_split(strstr(copy.zsm, " -- ") + 4, tok, SSI_TOKENS),
                  SSI_TOKENS - 1);
        memcpy(r.obj + strlen(r.obj), "-DB=2", sizeof("-DB=2"));
        copy = r;
        ASSERT(!ssi_same_argv("overflow-count.c", copy.obj, copy.zsm));
        memcpy(r.zsm + strlen(r.zsm), "-DB=2 ", sizeof("-DB=2 "));
        copy = r;
        ASSERT_EQ(ssi_split(strstr(copy.zsm, " -- ") + 4, tok, SSI_TOKENS),
                  SSI_TOKENS);
        ASSERT_EQ(ssi_split(strstr(copy.obj, " -- ") + 4, tok, SSI_TOKENS),
                  SIZE_MAX);
        memcpy(r.zsm + strlen(r.zsm), "-DC=3", sizeof("-DC=3"));
        copy = r;
        ASSERT_EQ(ssi_split(strstr(copy.zsm, " -- ") + 4, tok, SSI_TOKENS),
                  SIZE_MAX);
    } TEST_END
    return failures;
}

int semantic_sensor_argv_tests(void)
{
    return ssi_t_argv_capacity() + ssi_t_split_capacity() + ssi_t_argv();
}

/* ── resense: a compile change rewrites the manifest ────────────────────── */

#define SSI_HOT_TU "core/params/src/params"

static uint32_t ssi_changed(const uint8_t *a, size_t an, const uint8_t *b,
                            size_t bn);

/* Really run the facts rule for the hot TU into `dir`, with `extra` make
 * variables (NULL-terminated). True when make succeeded; *emitted says
 * whether the sensor ran. */
static bool ssi_facts_run(const char *dir, const char *const *extra,
                          char *out, size_t cap, bool *emitted)
{
    const char *argv[32];
    char var[PATH_MAX + 32], goal[PATH_MAX + 64];
    size_t k = 0;
    bool timed_out = false;
    const char *const env[] = {"env",         "-u", "MAKEFLAGS", "-u",
                               "MFLAGS",      "-u", "MAKELEVEL", "-u",
                               "MAKEOVERRIDES", "-u", "GNUMAKEFLAGS"};
    for (size_t i = 0; i < sizeof(env) / sizeof(env[0]); i++)
        argv[k++] = env[i];
    (void)snprintf(var, sizeof(var), "CLANG_FACTS_OUT_DIR=%s", dir);
    (void)snprintf(goal, sizeof(goal), "%s/" SSI_HOT_TU ".zsm", dir);
    argv[k++] = "make";
    argv[k++] = "--no-print-directory";
    argv[k++] = "-o"; /* the group's sensor is the one under test */
    argv[k++] = SSI_SENSOR;
    argv[k++] = var;
    for (size_t i = 0; extra[i] != NULL && k < 30; i++)
        argv[k++] = extra[i];
    argv[k++] = goal;
    argv[k] = NULL;
    int rc = zcl_spawn_capture_merged_observed(argv, out, cap, 600000,
                                               &timed_out);
    if (rc != 0 || timed_out) {
        printf("  make %s exited %d%s: %.2000s\n", goal, rc,
               timed_out ? " (timed out)" : "", out);
        size_t length = strlen(out);
        if (length > 2000)
            printf("  make failure output tail: %.4000s\n",
                   out + (length > 4000 ? length - 4000 : 0));
    }
    *emitted = strstr(out, "z23-clang-manifest emit") != NULL;
    return rc == 0 && !timed_out;
}

static int ssi_t_resense(void)
{
    int failures = 0;
    char dir[1024] = {0}, path[PATH_MAX + 64];
    char *out = zcl_malloc(SSI_MAKE_OUT, "ssi.resense_out");
    uint8_t *first = NULL, *hot = NULL;
    size_t fn = 0, hn = 0;
    bool emitted = false;
    static const char *const none[] = {NULL};
    static const char *const opt[] = {"ZCL_DEV_HOT_OPT=-O3", NULL};
    static const char *const tool[] = {
        "ZCL_DEV_HOT_OPT=-O3",
        "BUILD_COMPILER_ID="
        "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        NULL};
    TEST_CASE("semantic_sensor: a flag or toolchain change re-senses the TU, an unchanged compile does not") {
        ASSERT(out != NULL);
        ASSERT(test_mkdtemp(dir, sizeof(dir), "semsensor_resense") != NULL);
        (void)snprintf(path, sizeof(path), "%s/" SSI_HOT_TU ".zsm", dir);
        ASSERT(ssi_facts_run(dir, none, out, SSI_MAKE_OUT, &emitted));
        ASSERT(emitted);
        ASSERT(sft_read(path, &first, &fn));
        ASSERT(ssi_facts_run(dir, none, out, SSI_MAKE_OUT, &emitted));
        ASSERT(!emitted);
        /* The hot directories' optimizer: the object compiles differently. */
        ASSERT(ssi_facts_run(dir, opt, out, SSI_MAKE_OUT, &emitted));
        ASSERT(emitted);
        ASSERT(sft_read(path, &hot, &hn));
        ASSERT((ssi_changed(first, fn, hot, hn) &
                (1u << VCS_SEMANTIC_SECTION_V1_IDENTITY)) != 0);
        /* The toolchain identity alone. */
        ASSERT(ssi_facts_run(dir, tool, out, SSI_MAKE_OUT, &emitted));
        ASSERT(emitted);
    } TEST_END
    free(first);
    free(hot);
    free(out);
    if (dir[0] != '\0')
        (void)test_rm_rf_recursive(dir);
    return failures;
}

/* ── compiler: the object compiler is part of the identity ──────────────── */

#define SSI_CC_A "bin-a/cc"
#define SSI_CC_B "bin-b/cc"
/* A stand-in for Make's $(BUILD_COMPILER_ID). */
#define SSI_TC "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"

static bool ssi_emit(const char *root, const char *source, const char *out,
                     const char *cc, const char *tc, const char *const *flags,
                     size_t nflags, char *message, size_t cap)
{
    const char *argv[56];
    size_t k = 0;
    bool timed_out = false;
    argv[k++] = SSI_SENSOR;
    argv[k++] = "emit";
    argv[k++] = "--root";
    argv[k++] = root;
    argv[k++] = "--source";
    argv[k++] = source;
    argv[k++] = "--out";
    argv[k++] = out;
    argv[k++] = "--facts";
    if (cc != NULL) {
        argv[k++] = "--cc";
        argv[k++] = cc;
    }
    if (tc != NULL) {
        argv[k++] = "--toolchain-id";
        argv[k++] = tc;
    }
    argv[k++] = "--";
    for (size_t i = 0; i < nflags && k < 55; i++)
        argv[k++] = flags[i];
    argv[k] = NULL;
    int rc = zcl_spawn_capture_merged_observed(argv, message, cap, 60000,
                                               &timed_out);
    return rc == 0 && !timed_out;
}

static bool ssi_emit_ok(const char *root, const char *source, const char *out,
                        const char *cc, const char *const *flags, size_t nflags)
{
    char message[4096];
    bool ok = ssi_emit(root, source, out, cc, SSI_TC, flags, nflags, message,
                       sizeof(message));
    if (!ok)
        printf("  emit %s --cc %s failed: %s\n", source,
               cc != NULL ? cc : "(none)", message);
    return ok;
}

static bool ssi_has(const uint8_t *b, size_t n, const char *text)
{
    size_t t = strlen(text);
    for (size_t k = 0; t <= n && k + t <= n; k++)
        if (memcmp(b + k, text, t) == 0)
            return true;
    return false;
}

/* Two stand-in compilers inside the root: never run, only hashed. */
static bool ssi_write_compilers(const char *root, char *a_text, size_t cap)
{
    char path[PATH_MAX];
    uint8_t d[32];
    char hex[65];
    static const char body_a[] = "#!/bin/sh\nexit 0 # compiler a\n";
    static const char body_b[] = "#!/bin/sh\nexit 0 # compiler b\n";
    (void)snprintf(path, sizeof(path), "%s/bin-a", root);
    if (!scx_mkdir(path))
        return false;
    (void)snprintf(path, sizeof(path), "%s/bin-b", root);
    if (!scx_mkdir(path))
        return false;
    (void)snprintf(path, sizeof(path), "%s/" SSI_CC_A, root);
    if (!ssi_write(path, body_a) || chmod(path, 0755) != 0)
        return false;
    (void)snprintf(path, sizeof(path), "%s/" SSI_CC_B, root);
    if (!ssi_write(path, body_b) || chmod(path, 0755) != 0)
        return false;
    zcl_sha3_256((const unsigned char *)body_a, sizeof(body_a) - 1, d);
    zcl_hex_encode(d, 32, hex);
    (void)snprintf(a_text, cap, "object-cc " SSI_CC_A " sha3-256 %s", hex);
    return true;
}

static uint32_t ssi_changed(const uint8_t *a, size_t an, const uint8_t *b,
                            size_t bn)
{
    struct vcs_semantic_diff_v1 d;
    if (!vcs_semantic_manifest_v1_diff(a, an, b, bn, &d, NULL, NULL))
        return UINT32_MAX;
    return d.changed_sections;
}

static int ssi_t_identity(void)
{
    int failures = 0;
    char root[1024] = {0}, cc_a[PATH_MAX], cc_b[PATH_MAX], out[PATH_MAX];
    char want_a[160], message[4096];
    uint8_t *m[5] = {0};
    size_t n[5] = {0};
    static const char *const flags[] = {"-std=c23", "-O1"};
    static const char src[] = "int ssi_value(int x) { return x + 1; }\n";
    TEST_CASE("semantic_sensor: IDENTITY names the object compiler by path and bytes") {
        ASSERT(test_mkdtemp(root, sizeof(root), "semsensor_cc") != NULL);
        ASSERT(ssi_write_compilers(root, want_a, sizeof(want_a)));
        (void)snprintf(out, sizeof(out), "%s/ssi.c", root);
        ASSERT(ssi_write(out, src));
        (void)snprintf(cc_a, sizeof(cc_a), "%s/" SSI_CC_A, root);
        (void)snprintf(cc_b, sizeof(cc_b), "%s/" SSI_CC_B, root);
        const char *ccs[5] = {cc_a, cc_a, cc_b, NULL, "sh"};
        for (size_t k = 0; k < 5; k++) {
            (void)snprintf(out, sizeof(out), "%s/m%zu.zsm", root, k);
            ASSERT(ssi_emit_ok(root, "ssi.c", out, ccs[k], flags, 2));
            ASSERT(sft_read(out, &m[k], &n[k]));
        }
        ASSERT(n[0] == n[1] && memcmp(m[0], m[1], n[0]) == 0);
        ASSERT(ssi_has(m[0], n[0], want_a));
        ASSERT_EQ(ssi_changed(m[0], n[0], m[2], n[2]),
                  1u << VCS_SEMANTIC_SECTION_V1_IDENTITY);
        ASSERT(ssi_has(m[3], n[3], "; object-cc unknown"));
        ASSERT_EQ(ssi_changed(m[0], n[0], m[3], n[3]),
                  1u << VCS_SEMANTIC_SECTION_V1_IDENTITY);
#if defined(__APPLE__)
        /* The object-compiler reader cannot establish a Mach-O loader
         * closure; the documented fail-closed identity stays unknown. */
        ASSERT(ssi_has(m[4], n[4], "; object-cc unknown"));
#else
        ASSERT(ssi_has(m[4], n[4], "; object-cc @sys/"));
#endif
        (void)snprintf(out, sizeof(out), "%s/missing.zsm", root);
        ASSERT(!ssi_emit(root, "ssi.c", out, "zfx-no-such-compiler", SSI_TC,
                         flags, 2, message, sizeof(message)));
        ASSERT(strstr(message, "object compiler") != NULL);
        ASSERT(access(out, F_OK) != 0);
    } TEST_END
    for (size_t k = 0; k < 5; k++)
        free(m[k]);
    if (root[0] != '\0')
        (void)test_rm_rf_recursive(root);
    return failures;
}

/* The compiler text of one emit of ssi.c under `path_env` (NULL keeps PATH). */
static bool ssi_emit_text(const char *root, const char *cc, const char *tc,
                          const char *path_env, uint8_t **m, size_t *n)
{
    static const char *const flags[] = {"-std=c23", "-O1"};
    char out[PATH_MAX], message[4096];
    const char *old = getenv("PATH");
    char *saved = old != NULL ? strdup(old) : NULL;
    bool ok;
    (void)snprintf(out, sizeof(out), "%s/r.zsm", root);
    (void)unlink(out);
    if (path_env != NULL && setenv("PATH", path_env, 1) != 0) {
        free(saved);
        return false;
    }
    ok = ssi_emit(root, "ssi.c", out, cc, tc, flags, 2, message,
                  sizeof(message));
    if (path_env != NULL)
        (void)(saved != NULL ? setenv("PATH", saved, 1) : unsetenv("PATH"));
    free(saved);
    if (!ok)
        printf("  emit --cc %s failed: %s\n", cc, message);
    return ok && sft_read(out, m, n);
}

/* A compile-cache wrapper and a masquerade link to it named like the
 * compiler, in <root>/bin-w; <root>/bin-o holds only the link. */
static bool ssi_write_wrapper(const char *root)
{
    char path[PATH_MAX], link[PATH_MAX];
    static const char body[] = "#!/bin/sh\nexit 0 # compile cache\n";
    (void)snprintf(path, sizeof(path), "%s/bin-w", root);
    if (!scx_mkdir(path))
        return false;
    (void)snprintf(path, sizeof(path), "%s/bin-o", root);
    if (!scx_mkdir(path))
        return false;
    (void)snprintf(path, sizeof(path), "%s/bin-w/ccache", root);
    if (!ssi_write(path, body) || chmod(path, 0755) != 0)
        return false;
    (void)snprintf(link, sizeof(link), "%s/bin-w/cc", root);
    if (symlink("ccache", link) != 0)
        return false;
    (void)snprintf(link, sizeof(link), "%s/bin-o/cc", root);
    return symlink("../bin-w/ccache", link) == 0;
}

static int ssi_t_resolution(void)
{
    int failures = 0;
    char root[1024] = {0}, want_a[160], path[PATH_MAX], text[512];
    char message[4096], out[PATH_MAX];
    uint8_t *m = NULL;
    size_t n = 0;
    static const char *const flags[] = {"-std=c23", "-O1"};
    TEST_CASE("semantic_sensor: IDENTITY binds the toolchain and resolves through a compile cache") {
        ASSERT(test_mkdtemp(root, sizeof(root), "semsensor_ccres") != NULL);
        ASSERT(ssi_write_compilers(root, want_a, sizeof(want_a)));
        ASSERT(ssi_write_wrapper(root));
        (void)snprintf(out, sizeof(out), "%s/ssi.c", root);
        ASSERT(ssi_write(out, "int ssi_value(int x) { return x + 1; }\n"));
        /* A script compiler: its bytes, no loaded objects, the toolchain. */
        (void)snprintf(text, sizeof(text), "; %s libs none toolchain " SSI_TC,
                       want_a);
        (void)snprintf(path, sizeof(path), "%s/" SSI_CC_A, root);
        ASSERT(ssi_emit_text(root, path, SSI_TC, NULL, &m, &n));
        ASSERT(ssi_has(m, n, text));
        free(m);
        m = NULL;
        /* No toolchain identity: the subprograms are unbound, so unknown. */
        ASSERT(ssi_emit_text(root, path, NULL, NULL, &m, &n));
        ASSERT(ssi_has(m, n, "; object-cc unknown"));
        free(m);
        m = NULL;
        /* The masquerade link runs the next `cc` on PATH, not the cache. */
        (void)snprintf(path, sizeof(path), "%s/bin-w:%s/bin-a", root, root);
        ASSERT(ssi_emit_text(root, "cc", SSI_TC, path, &m, &n));
        ASSERT(ssi_has(m, n, text));
        ASSERT(!ssi_has(m, n, "ccache"));
        free(m);
        m = NULL;
        /* ...and with no compiler behind it the compiler is unknown. */
        (void)snprintf(path, sizeof(path), "%s/bin-o", root);
        ASSERT(ssi_emit_text(root, "cc", SSI_TC, path, &m, &n));
        ASSERT(ssi_has(m, n, "; object-cc unknown"));
        free(m);
        m = NULL;
#if defined(__linux__)
        /* A dynamic image: every object the loader maps for it is bound. */
        ASSERT(ssi_emit_text(root, "sh", SSI_TC, NULL, &m, &n));
        ASSERT(ssi_has(m, n, " libs sha3-256 "));
        free(m);
        m = NULL;
#endif
        (void)snprintf(out, sizeof(out), "%s/zero.zsm", root);
        (void)snprintf(path, sizeof(path), "%s/" SSI_CC_A, root);
        ASSERT(!ssi_emit(root, "ssi.c", out, path,
                         "0000000000000000000000000000000000000000000000000000000000000000",
                         flags, 2, message, sizeof(message)));
        ASSERT(strstr(message, "--toolchain-id") != NULL);
        ASSERT(access(out, F_OK) != 0);
    } TEST_END
    free(m);
    if (root[0] != '\0')
        (void)test_rm_rf_recursive(root);
    return failures;
}

/* Sense every TU of variant v into <out>/<tag>/<tu>.zsm with compiler cc. */
static bool ssi_sense(const char *root, const char *out, const char *tag,
                      enum scx_variant v, const char *cc,
                      uint8_t *m[SCX_TU_COUNT], size_t n[SCX_TU_COUNT])
{
    char dir[PATH_MAX], path[PATH_MAX + 64];
    (void)snprintf(dir, sizeof(dir), "%s/%s", out, tag);
    if (!scx_mkdir(dir) || !scx_write_tree(root, v))
        return false;
    for (size_t tu = 0; tu < SCX_TU_COUNT; tu++) {
        (void)snprintf(path, sizeof(path), "%s/%s.zsm", dir,
                       strrchr(k_scx_tus[tu], '/') + 1);
        if (!ssi_emit_ok(root, k_scx_tus[tu], path, cc, k_scx_flags,
                         k_scx_nflags) ||
            !sft_read(path, &m[tu], &n[tu]))
            return false;
    }
    return true;
}

/* Did the plan widen across the compiler change? Either every TU is
 * affected and broadened for identity drift (the header path: each
 * contributes its whole file-seeded plan), or the facts fell back or left
 * the universe incomplete for identity drift (the .c path, where the TUs
 * that read no changed file drift). */
static bool ssi_widened(const struct scx_result *r)
{
    size_t drift = 0;
    for (size_t k = 0; k < SCX_TU_COUNT; k++) {
        const struct zcl_devloop_facts_tu_verdict *t =
            scx_tu_of(r, k_scx_tus[k]);
        drift += t != NULL && t->affected && t->broadened &&
                 strcmp(t->reason, "identity-drift") == 0;
    }
    return drift == SCX_TU_COUNT || !r->verdict.narrowed ||
           (!r->report.complete && r->report.reason != NULL &&
            strcmp(r->report.reason, "identity-drift") == 0 &&
            r->report.plain_universal);
}

static void ssi_print_plan(enum scx_variant v, const struct scx_result *r)
{
    printf("  %s across two compilers: narrowed %d reason %s, complete %d "
           "(%s), universal %d\n", k_scx_edits[v].name,
           (int)r->verdict.narrowed, r->verdict.reason,
           (int)r->report.complete,
           r->report.reason != NULL ? r->report.reason : "",
           (int)r->report.plain_universal);
    for (size_t k = 0; k < r->report.ntus; k++)
        printf("    %s affected %d broadened %d %s\n", r->report.tus[k].path,
               (int)r->report.tus[k].affected, (int)r->report.tus[k].broadened,
               r->report.tus[k].reason);
}

/* Plan variant v with before/after evidence: under one compiler it must
 * match the edit table; across two it must widen. */
static bool ssi_plan(enum scx_variant v, uint8_t *const before[],
                     const size_t bn[], uint8_t *const after[],
                     const size_t an[], bool want_wide)
{
    char root[PATH_MAX] = {0};
    struct scx_evidence ev = {0};
    struct scx_result *res = zcl_calloc(1, sizeof(*res), "ssi.result");
    size_t unsafe = 0;
    bool ok = res != NULL &&
              test_mkdtemp(root, sizeof(root), "semsensor_ccplan") != NULL;
    for (size_t tu = 0; tu < SCX_TU_COUNT; tu++) {
        ev.before[tu] = before[tu];
        ev.before_len[tu] = bn[tu];
        ev.after[tu] = after[tu];
        ev.after_len[tu] = an[tu];
    }
    ok = ok && scx_consume(root, v, &ev, res);
    if (ok && !want_wide)
        ok = scx_compare(v, res, &unsafe, stdout) == 0;
    else if (ok)
        ok = ssi_widened(res);
    if (res != NULL && (!ok || want_wide))
        ssi_print_plan(v, res);
    if (res != NULL)
        scx_result_free(res);
    free(res);
    if (root[0] != '\0')
        (void)test_rm_rf_recursive(root);
    return ok;
}

static void ssi_free(uint8_t *m[SCX_TU_COUNT])
{
    for (size_t tu = 0; tu < SCX_TU_COUNT; tu++)
        free(m[tu]);
}

static int ssi_t_widen(void)
{
    int failures = 0;
    char out[1024] = {0}, root[1100], want[160], cc_a[1200], cc_b[1200];
    uint8_t *base[SCX_TU_COUNT] = {0}, *same[SCX_TU_COUNT] = {0},
            *other[SCX_TU_COUNT] = {0};
    size_t bn[SCX_TU_COUNT] = {0}, sn[SCX_TU_COUNT] = {0},
           on[SCX_TU_COUNT] = {0};
    static const enum scx_variant variants[] = {SCX_TAIL, SCX_BODY};
    TEST_CASE("semantic_sensor: a compiler change between the sides widens the plan") {
        ASSERT(test_mkdtemp(out, sizeof(out), "semsensor_ccwiden") != NULL);
        (void)snprintf(root, sizeof(root), "%s/tree", out);
        ASSERT(scx_mkdir(root));
        ASSERT(ssi_write_compilers(root, want, sizeof(want)));
        (void)snprintf(cc_a, sizeof(cc_a), "%s/" SSI_CC_A, root);
        (void)snprintf(cc_b, sizeof(cc_b), "%s/" SSI_CC_B, root);
        ASSERT(ssi_sense(root, out, "base", SCX_BASE, cc_a, base, bn));
        for (size_t k = 0; k < sizeof(variants) / sizeof(variants[0]); k++) {
            enum scx_variant v = variants[k];
            char tag[64];
            (void)snprintf(tag, sizeof(tag), "%s_a", k_scx_edits[v].name);
            ASSERT(ssi_sense(root, out, tag, v, cc_a, same, sn));
            (void)snprintf(tag, sizeof(tag), "%s_b", k_scx_edits[v].name);
            ASSERT(ssi_sense(root, out, tag, v, cc_b, other, on));
            ASSERT(ssi_plan(v, base, bn, same, sn, false));
            ASSERT(ssi_plan(v, base, bn, other, on, true));
            ssi_free(same);
            ssi_free(other);
            memset(same, 0, sizeof(same));
            memset(other, 0, sizeof(other));
        }
    } TEST_END
    ssi_free(base);
    ssi_free(same);
    ssi_free(other);
    if (out[0] != '\0' && failures == 0)
        (void)test_rm_rf_recursive(out);
    return failures;
}

/* Both sides say "object-cc unknown": equal IDENTITY records that cannot
 * show the object's compiler unchanged, so the plan widens as it does
 * across two known compilers. */
static int ssi_t_unknown(void)
{
    int failures = 0;
    char out[1024] = {0}, root[1100];
    uint8_t *base[SCX_TU_COUNT] = {0}, *after[SCX_TU_COUNT] = {0};
    size_t bn[SCX_TU_COUNT] = {0}, an[SCX_TU_COUNT] = {0};
    static const enum scx_variant variants[] = {SCX_TAIL, SCX_BODY};
    TEST_CASE("semantic_sensor: two sides that both say object-cc unknown widen the plan") {
        ASSERT(test_mkdtemp(out, sizeof(out), "semsensor_ccunknown") != NULL);
        (void)snprintf(root, sizeof(root), "%s/tree", out);
        ASSERT(scx_mkdir(root));
        ASSERT(ssi_sense(root, out, "base", SCX_BASE, NULL, base, bn));
        for (size_t k = 0; k < sizeof(variants) / sizeof(variants[0]); k++) {
            enum scx_variant v = variants[k];
            ASSERT(ssi_sense(root, out, k_scx_edits[v].name, v, NULL, after,
                             an));
            ASSERT(ssi_has(after[0], an[0], "; object-cc unknown"));
            ASSERT(ssi_plan(v, base, bn, after, an, true));
            ssi_free(after);
            memset(after, 0, sizeof(after));
        }
    } TEST_END
    ssi_free(base);
    ssi_free(after);
    if (out[0] != '\0' && failures == 0)
        (void)test_rm_rf_recursive(out);
    return failures;
}

int semantic_sensor_identity_tests(void)
{
    int failures = 0;
    failures += ssi_t_resense();
    failures += ssi_t_identity();
    failures += ssi_t_resolution();
    failures += ssi_t_widen();
    failures += ssi_t_unknown();
    return failures;
}
