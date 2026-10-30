/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-no-operator-paths
 * (gate_no_operator_paths.c). Ports the planted-violation proof of the
 * shell original: each prong's violation is planted in a sandbox file,
 * the gate core is run against ONLY that file (explicit scan override,
 * so the real index is never touched), and the expected exit is
 * required. The runner's own username and hostname are ordinary data;
 * generic, example, and onion host fields pass; removing the violation
 * restores PASS. The prong A literals are assembled from separate root
 * tokens so this file never contains an absolute home path either.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_no_operator_paths_priv.h"

enum { NOPST_PATH = 1024, NOPST_TEXT = 4096 };

/* Substitutes %A -> "home" and %B -> "Users" so no literal absolute home
 * root appears in this file. */
static int nopst_subst(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; in[i]; i++) {
        const char *rep = NULL;
        if (in[i] == '%' && in[i + 1] == 'A')
            rep = "home";
        else if (in[i] == '%' && in[i + 1] == 'B')
            rep = "Users";
        if (rep) {
            size_t rl = strlen(rep);
            if (o + rl >= cap)
                return 2;
            memcpy(out + o, rep, rl);
            o += rl;
            i++;
        } else {
            if (o + 1 >= cap)
                return 2;
            out[o++] = in[i];
        }
    }
    out[o] = '\0';
    return 0;
}

struct nopst_case {
    const char *label;
    const char *name;
    const char *text;
    const char *identities; /* NULL unless the prong B seed is needed */
    int want;
};

static const struct nopst_case k_nopst_cases[] = {
    { "clean file", "clean.txt",
      "store label = zcl-store-a\n"
      "path = contexts/commons/corpus/scopes.def\n", NULL, 0 },
    { "runner username and hostname are not policy", "runner_names.txt",
      "actors = bob, runner, t14\nfixture host = build\n", NULL, 0 },
    { "generic, example, and onion host fields", "public_hosts.txt",
      "{\"host\":\"h\"}\n{\"host\":\"peer.example.com\"}\n"
      "{\"host\":\"abcdefghijklmnop.onion\"}\n", NULL, 0 },
    { "prong A — planted absolute home path", "planted_a.txt",
      "datadir = /%A/planted-operator/.zclassic-c23-commons-factory-a\n",
      NULL, 1 },
    { "prong A — planted /Users path", "planted_a2.txt",
      "store = /%B/planted-operator/Library/zcode\n", NULL, 1 },
    { "prong B — planted operator username", "planted_b.txt",
      "ssh planted-operator@some-box\n", "planted-operator", 1 },
    { "prong C — planted explicit hostname", "planted_c.txt",
      "{\"host\":\"private-operator-box\"}\n", NULL, 1 },
    { "prong A — violation removed", "planted_a.txt",
      "datadir = $HOME/.zclassic-c23-commons-factory-a\n", NULL, 0 },
};

static int nopst_run(const char *tmp, const struct nopst_case *c)
{
    char path[NOPST_PATH], text[NOPST_TEXT];
    if (ovf(snprintf(path, sizeof path, "%s/%s", tmp, c->name), sizeof path))
        return 2;
    int rc = nopst_subst(c->text, text, sizeof text);
    if (rc)
        return rc;
    rc = csr_write(path, text);
    if (rc)
        return rc;
    FILE *sink = fopen("/dev/null", "w");
    if (!sink)
        sink = tmpfile();
    if (!sink)
        return die("z23-lint: cannot open output sink\n", "");
    const char *files[1] = { path };
    struct nop_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.files = files;
    cfg.nfiles = 1;
    cfg.test_identities = c->identities;
    cfg.update = 0;
    int got = nop_check(&cfg, sink);
    fclose(sink);
    if (got != c->want) {
        printf("[%s] SELFTEST FAIL: %s expected rc=%d, got rc=%d\n",
               nop_gate_name, c->label, c->want, got);
        return 1;
    }
    printf("[%s]   selftest ok: %s (rc=%d)\n", nop_gate_name, c->label, got);
    return 0;
}

int check_no_operator_paths_selftest(void)
{
    char tmp[NOPST_PATH];
    const char *td = env_or("TMPDIR", "test-tmp");
    if (csr_mkdirs(td))
        return 2;
    if (ovf(snprintf(tmp, sizeof tmp, "%s/z23-lint-no-operator-paths.XXXXXX",
                     td), sizeof tmp))
        return 2;
    if (!mkdtemp(tmp))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    int bad = 0;
    for (size_t i = 0; i < sizeof k_nopst_cases / sizeof k_nopst_cases[0]; i++)
        bad |= nopst_run(tmp, &k_nopst_cases[i]) != 0;
    rap_rm_rf(tmp);
    if (bad) {
        printf("[%s] SELFTEST FAILED\n", nop_gate_name);
        return 1;
    }
    printf("[%s] selftest: PASS\n", nop_gate_name);
    return 0;
}
