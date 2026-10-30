/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-no-adx-overclaim
 * (gate_no_adx_overclaim.c). Ports every selftest case of the shell script:
 * generator chatter around the one canonical -I record is ignored and the
 * record is read exactly; an ambiguous pair of -I records and a hollow
 * output with no canonical record are both refused. Each fixture is written
 * to a scratch file and read back so the extractor sees real file bytes.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

enum { AOST_PATH = 1024, AOST_TEXT = 4096,
       AOST_IFLAGS = 256, AOST_IWORD = 160 };

/* Mirrors the definition in gate_no_adx_overclaim.c (no heap in lintc). */
struct aost_incset { char flag[AOST_IFLAGS][AOST_IWORD]; int n; };

extern int ao_extract_includes(const char *text, struct aost_incset *set);

static int aost_root(char *out, size_t cap)
{
    if (ovf(snprintf(out, cap, "%s/z23-lint-no-adx-self.XXXXXX",
                     env_or("TMPDIR", "/tmp")), cap))
        return 2;
    if (!mkdtemp(out))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    return 0;
}

/* Writes the fixture to path and reads it back into buf. */
static int aost_roundtrip(const char *path, const char *text, char *buf,
                          size_t cap)
{
    int rc = csr_write(path, text);
    if (rc)
        return rc;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot reopen fixture %s\n", path);
    rc = csr_slurp(f, buf, cap);
    fclose(f);
    return rc;
}

/* Joins the extracted flags with single spaces for comparison. */
static void aost_join(const struct aost_incset *s, char *out, size_t cap)
{
    size_t o = 0;
    out[0] = '\0';
    for (int i = 0; i < s->n; i++) {
        size_t n = strlen(s->flag[i]);
        if (o + n + 2 >= cap)
            return;
        if (i > 0)
            out[o++] = ' ';
        memcpy(out + o, s->flag[i], n);
        o += n;
        out[o] = '\0';
    }
}

/* One case: want_ok 1 expects extraction to succeed with want_join; want_ok
 * 0 expects the extractor to refuse (rc 1). Returns 0 when expectations
 * hold, 1 on a mismatch, 2 on an internal error. */
static int aost_case(const char *root, const char *name, const char *text,
                     int want_ok, const char *want_join)
{
    static char buf[AOST_TEXT];
    char path[AOST_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s.txt", root, name),
             sizeof path))
        return 2;
    int rc = aost_roundtrip(path, text, buf, sizeof buf);
    if (rc)
        return 2;
    struct aost_incset set;
    rc = ao_extract_includes(buf, &set);
    if (rc == 2)
        return 2;
    if (want_ok) {
        char join[AOST_TEXT];
        aost_join(&set, join, sizeof join);
        if (rc != 0 || set.n == 0 || strcmp(join, want_join) != 0) {
            fprintf(stderr, "check_no_adx_overclaim: selftest FAILED — "
                    "canonical record '%s' was mangled (rc=%d)\n", name, rc);
            return 1;
        }
    } else if (rc == 0) {
        fprintf(stderr, "check_no_adx_overclaim: selftest FAILED — "
                "refused-case '%s' was accepted\n", name);
        return 1;
    }
    return 0;
}

int check_no_adx_overclaim_selftest(void)
{
    char root[AOST_PATH];
    int rc = aost_root(root, sizeof root);
    if (rc)
        return rc;
    int bad = 0;
    bad |= aost_case(root, "chatter-one",
                     "gen_templates: 49 inputs -> generated.h (unchanged)\n"
                     "-Icore/a/include -Iengine/b/include -Iplatform/c/include",
                     1, "-Icore/a/include -Iengine/b/include "
                        "-Iplatform/c/include") != 0;
    bad |= aost_case(root, "chatter-two",
                     "make[1]: Entering directory /checkout\n"
                     "-Ione -Itwo\ngen_templates: done",
                     1, "-Ione -Itwo") != 0;
    bad |= aost_case(root, "ambiguous", "-Ione -Itwo\n-Ithree -Ifour", 0,
                     NULL) != 0;
    bad |= aost_case(root, "hollow", "gen_templates: no canonical record", 0,
                     NULL) != 0;
    rap_rm_rf(root);
    if (bad) {
        fputs("FAIL: check_no_adx_overclaim selftest\n", stderr);
        return 1;
    }
    return st_ok(bad, "check_no_adx_overclaim: selftest PASS — generator "
            "chatter ignored; ambiguous and hollow include records refused\n");
}
