/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — the simnet_wire in-memory harness stays free of
 * real-network calls, and Tor's outbound dial path pre-warms before the
 * local hidden-service descriptor publishes (check-wire-harness-security-gate,
 * check-tor-dial-prewarm).
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

static int sql_glob(const char *s, const char *p)
{
    if (*p == '\0')
        return *s == '\0';
    if (*p == '*') {
        while (*p == '*')
            p++;
        if (*p == '\0')
            return 1;
        for (; *s; s++) {
            if (sql_glob(s, p))
                return 1;
        }
        return sql_glob(s, p);
    }
    if (*s != '\0' && *s == *p)
        return sql_glob(s + 1, p + 1);
    return 0;
}

static int wh_slashes(const char *s)
{
    int n = 0;
    for (; *s; s++)
        if (*s == '/')
            n++;
    return n;
}

static int wh_is_wire(const char *path)
{
    if (sql_glob(path, "engine/modules/sim/src/simnet_wire*.c")
        && wh_slashes(path) == 4)
        return 1;
    if (sql_glob(path, "tools/sim/*wire*.c") && wh_slashes(path) == 2)
        return 1;
    if (sql_glob(path, "tools/sim/*wire*.h") && wh_slashes(path) == 2)
        return 1;
    return 0;
}

static int wh_comp(regex_t *re)
{
    return reg_fail(re, regcomp(re,
        "(^|[^[:alnum:]_])(recv|send|socket|connect|bind|getaddrinfo)"
        "[[:space:]]*\\(", REG_EXTENDED));
}

enum { WH_OK = 0, WH_HOLLOW = 1, WH_HITS = 2 };

static int wh_verdict(int nfiles, int hits)
{
    if (nfiles == 0)
        return WH_HOLLOW;
    if (hits > 0)
        return WH_HITS;
    return WH_OK;
}

static int wh_report(int v, int nfiles)
{
    if (v == WH_HOLLOW) {
        fputs("FAIL: check_wire_harness_security_gate found no simnet_wire "
              "source files — gate is hollow\n", stdout);
        return 1;
    }
    if (v == WH_HITS) {
        fputs("FAIL: real-network call found in the simnet_wire in-memory harness\n",
              stdout);
        fputs("  simnet_wire is pure in-memory transport by design (deterministic,\n",
              stdout);
        fputs("  no wall-clock, no real sockets). If this is a legitimate need,\n",
              stdout);
        fputs("  it does not belong in engine/modules/sim/src/simnet_wire*.c or "
              "tools/sim/*wire*.\n", stdout);
        return 1;
    }
    printf("OK: check_wire_harness_security_gate — no "
           "recv/send/socket/connect/bind/getaddrinfo in %d wire harness file(s)\n",
           nfiles);
    return 0;
}

struct wh_acc { regex_t *re; int nfiles; int hits; };

static int on_wh(const char *path, void *ctx)
{
    struct wh_acc *a = ctx;
    if (!wh_is_wire(path))
        return 0;
    a->nfiles++;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (regexec(a->re, line, 0, NULL, 0) != 0)
            continue;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (fprintf(stdout, "%s:%d:%s\n", path, lineno, line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
        a->hits++;
    }
    return fin(f, line, path, rc);
}

int check_wire_harness_security_gate_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    regex_t re;
    int cr = wh_comp(&re);
    if (cr)
        return cr;
    struct wh_acc a = { .re = &re, .nfiles = 0, .hits = 0 };
    int rc = each_zpath(k_ls_all, on_wh, &a);
    if (rc == 0)
        rc = wh_report(wh_verdict(a.nfiles, a.hits), a.nfiles);
    regfree(&re);
    return rc;
}

int check_wire_harness_security_gate_selftest(void)
{
    regex_t re;
    int cr = wh_comp(&re);
    if (cr)
        return cr;
    const char *t = "check_wire_harness_security_gate";
    int bad = want(t, &re, "simnet_wire_peer_send_ping(", 0)
            | want(t, &re, "drain_nut_send(", 0)
            | want(t, &re, "send(", 1)
            | want(t, &re, "    recv (fd, buf, n, 0);", 1)
            | want(t, &re, "xsend(", 0)
            | want(t, &re, "reconnect(", 0);
    regfree(&re);
    bad |= !wh_is_wire("engine/modules/sim/src/simnet_wire.c");
    bad |= !wh_is_wire("engine/modules/sim/src/simnet_wire_peer.c");
    bad |= !wh_is_wire("tools/sim/wire_sweep.c");
    bad |= !wh_is_wire("tools/sim/foo_wire.h");
    bad |= wh_is_wire("engine/modules/sim/src/other.c");
    bad |= wh_is_wire("engine/modules/sim/src/simnet_wire_x/y.c");
    bad |= wh_is_wire("tools/sim/nested/wire.c");
    bad |= wh_verdict(0, 0) != WH_HOLLOW;
    bad |= wh_verdict(3, 0) != WH_OK;
    bad |= wh_verdict(3, 1) != WH_HITS;
    return st_ok(bad, "check_wire_harness_security_gate selftest: OK\n");
}

static const char k_tdp_net[] =
    "zcl_service_kernel_start_all(&svc->network_kernel)";
static const char k_tdp_front[] =
    "zcl_service_kernel_start_all(&svc->frontend_kernel)";
static const char k_tdp_dial[] = "atomic_store(&g_tor_dial_ready, true)";
static const char k_tdp_pub[] = "tor_log_has_descriptor_publication\\(";
static const char k_tdp_dial_fn[] = "tor_integration_is_dial_ready";
static const char k_tdp_ready[] = "tor_integration_is_ready";

static int tdp_first_line(const char *path, const char *lit, const regex_t *re)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char *line = NULL;
    size_t cap = 0;
    int lineno = 0, found = -1;
    while (getline(&line, &cap, f) >= 0) {
        lineno++;
        int hit = 0;
        if (lit)
            hit = strstr(line, lit) != NULL;
        else if (re)
            hit = regexec(re, line, 0, NULL, 0) == 0;
        if (hit) {
            found = lineno;
            break;
        }
    }
    free(line);
    (void)fclose(f);
    return found;
}

static int tdp_before(int a, int b)
{
    return a >= 0 && b >= 0 && a < b;
}

static int tdp_has(const char *path, const char *lit)
{
    return tdp_first_line(path, lit, NULL) >= 0;
}

struct tdp_job {
    const char *boot;
    const char *tor;
    const char *stream;
    const char *connman;
    const char *watchdog;
    int progress;
    int step5_seen;
    int network_line;
    int frontend_line;
    int dial_ready_line;
    int publication_line;
    const char *err;
};

static int tdp_run_job(struct tdp_job *j)
{
    j->progress = 0;
    j->step5_seen = 0;
    j->err = NULL;
    j->network_line = -1;
    j->frontend_line = -1;
    j->dial_ready_line = -1;
    j->publication_line = -1;

    j->progress++;
    j->network_line = tdp_first_line(j->boot, k_tdp_net, NULL);
    j->frontend_line = tdp_first_line(j->boot, k_tdp_front, NULL);
    if (j->network_line < 0 || j->frontend_line < 0) {
        j->err = "could not resolve network/frontend boot order";
        return 1;
    }

    j->progress++;
    if (!tdp_before(j->network_line, j->frontend_line)) {
        j->err = "connman must start before the frontend Tor service";
        return 1;
    }

    regex_t pub;
    int cr = reg_fail(&pub, regcomp(&pub, k_tdp_pub, REG_EXTENDED));
    if (cr)
        return cr;
    j->progress++;
    j->dial_ready_line = tdp_first_line(j->tor, k_tdp_dial, NULL);
    j->publication_line = tdp_first_line(j->tor, NULL, &pub);
    regfree(&pub);
    if (j->dial_ready_line < 0 || j->publication_line < 0) {
        j->err = "could not resolve Tor dial/publication order";
        return 1;
    }

    j->progress++;
    if (!tdp_before(j->dial_ready_line, j->publication_line)) {
        j->err = "outbound dial readiness must precede descriptor publication";
        return 1;
    }

    j->progress++;
    j->step5_seen++;
    if (!tdp_has(j->stream, k_tdp_dial_fn)) {
        j->err = "raw onion stream still waits for full inbound readiness";
        return 1;
    }

    j->progress++;
    if (!tdp_has(j->connman, k_tdp_dial_fn)) {
        j->err = "onion seed discovery still waits for full inbound readiness";
        return 1;
    }

    j->progress++;
    if (tdp_has(j->stream, k_tdp_ready) || tdp_has(j->connman, k_tdp_ready)) {
        j->err = "an outbound onion path is still gated on descriptor publication";
        return 1;
    }

    j->progress++;
    if (!tdp_has(j->watchdog, k_tdp_ready)) {
        j->err = "systemd READY no longer waits for descriptor publication";
        return 1;
    }
    return 0;
}

int check_tor_dial_prewarm_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    struct tdp_job j = {
        .boot = "engine/composition/src/boot_services.c",
        .tor = "core/modules/net/src/tor_integration.c",
        .stream = "core/modules/net/src/onion_stream.c",
        .connman = "core/modules/net/src/connman.c",
        .watchdog = "engine/composition/src/boot_sd_watchdog.c",
    };
    int rc = tdp_run_job(&j);
    if (rc == 1) {
        if (fprintf(stderr, "check_tor_dial_prewarm: FAIL: %s\n",
                    j.err ? j.err : "unknown") < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    if (rc)
        return rc;
    if (printf("check_tor_dial_prewarm: PASS network_start=%d tor_start=%d "
               "dial_ready=%d descriptor_publication=%d\n",
               j.network_line, j.frontend_line, j.dial_ready_line,
               j.publication_line) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int tdp_st_want(int got, int w, const char *tag)
{
    if (got != w) {
        fprintf(stderr, "check_tor_dial_prewarm selftest: %s want %d got %d\n",
                tag, w, got);
        return 1;
    }
    return 0;
}

struct tdp_paths {
    const char *tmp;
    char two[4096], boot[4096], tor[4096], stream[4096], connman[4096],
        watchdog[4096];
};

static int tdp_st_paths_init(struct tdp_paths *p, const char *tmp)
{
    p->tmp = tmp;
    if (ovf(snprintf(p->two, sizeof p->two, "%s/two.c", tmp), sizeof p->two)
        || ovf(snprintf(p->boot, sizeof p->boot, "%s/boot.c", tmp),
               sizeof p->boot)
        || ovf(snprintf(p->tor, sizeof p->tor, "%s/tor.c", tmp), sizeof p->tor)
        || ovf(snprintf(p->stream, sizeof p->stream, "%s/stream.c", tmp),
               sizeof p->stream)
        || ovf(snprintf(p->connman, sizeof p->connman, "%s/connman.c", tmp),
               sizeof p->connman)
        || ovf(snprintf(p->watchdog, sizeof p->watchdog, "%s/watchdog.c", tmp),
               sizeof p->watchdog))
        return 2;
    return 0;
}

static int tdp_st_write_baseline(const struct tdp_paths *p)
{
    if (csr_write(p->two, "alpha\nbravo\n")
        || csr_write(p->boot,
                     "zcl_service_kernel_start_all(&svc->network_kernel)\n"
                     "zcl_service_kernel_start_all(&svc->frontend_kernel)\n")
        || csr_write(p->tor, "atomic_store(&g_tor_dial_ready, true)\n"
                          "tor_log_has_descriptor_publication(\n")
        || csr_write(p->stream, "tor_integration_is_dial_ready\n")
        || csr_write(p->connman, "tor_integration_is_dial_ready\n")
        || csr_write(p->watchdog, "tor_integration_is_ready\n"))
        return 2;
    return 0;
}

/* Each probe below returns -1 to signal a hard (fixture-write) failure that
 * must abort the selftest, or an accumulated 0/1 "bad" flag otherwise — the
 * same two outcomes the original inline selftest body produced at each
 * step, now named for the scenario each one drives.
 */

static int tdp_st_probe_literal_scan(struct tdp_job *j, struct tdp_paths *p)
{
    (void)j;
    int bad = 0;
    bad |= tdp_st_want(tdp_first_line(p->two, "alpha", NULL), 1, "lit-line1");
    bad |= tdp_st_want(tdp_first_line(p->two, "bravo", NULL), 2, "lit-line2");
    bad |= tdp_st_want(tdp_first_line(p->two, "missing", NULL), -1, "lit-miss");
    bad |= tdp_st_want(tdp_first_line(p->tmp, "alpha", NULL), -1, "unopenable");
    regex_t ere;
    int cr = reg_fail(&ere, regcomp(&ere, "bravo", REG_EXTENDED));
    if (cr)
        return -1;
    bad |= tdp_st_want(tdp_first_line(p->two, NULL, &ere), 2, "ere-line2");
    regfree(&ere);
    return bad;
}

static int tdp_st_probe_order_pure(struct tdp_job *j, struct tdp_paths *p)
{
    (void)j;
    (void)p;
    int bad = 0;
    bad |= tdp_st_want(tdp_before(1, 2), 1, "order-pass");
    bad |= tdp_st_want(tdp_before(2, 1), 0, "order-fail");
    bad |= tdp_st_want(tdp_before(-1, 2), 0, "order-unresolved");
    bad |= tdp_st_want(tdp_before(3, 3), 0, "order-equal");
    return bad;
}

static int tdp_st_probe_full_pass(struct tdp_job *j, struct tdp_paths *p)
{
    (void)p;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 0, "full-pass");
    bad |= tdp_st_want(j->progress, 8, "full-progress");
    bad |= tdp_st_want(j->network_line, 1, "net-line");
    bad |= tdp_st_want(j->frontend_line, 2, "front-line");
    bad |= tdp_st_want(j->dial_ready_line, 1, "dial-line");
    bad |= tdp_st_want(j->publication_line, 2, "pub-line");
    return bad;
}

static int tdp_st_probe_boot_order_fail(struct tdp_job *j, struct tdp_paths *p)
{
    if (csr_write(p->boot,
                  "zcl_service_kernel_start_all(&svc->frontend_kernel)\n"
                  "zcl_service_kernel_start_all(&svc->network_kernel)\n"))
        return -1;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 1, "boot-order-fail");
    bad |= tdp_st_want(j->progress, 2, "boot-order-progress");
    bad |= !j->err || strcmp(j->err,
            "connman must start before the frontend Tor service") != 0;
    return bad;
}

static int tdp_st_probe_step1_fail(struct tdp_job *j, struct tdp_paths *p)
{
    if (csr_write(p->boot, "no markers\n")
        || csr_write(p->stream, "no dial fn\n"))
        return -1;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 1, "step1-fail");
    bad |= tdp_st_want(j->progress, 1, "step1-progress");
    bad |= tdp_st_want(j->step5_seen, 0, "die-on-first-skips-step5");
    bad |= !j->err || strcmp(j->err,
            "could not resolve network/frontend boot order") != 0;
    return bad;
}

static int tdp_st_probe_dial_order_fail(struct tdp_job *j, struct tdp_paths *p)
{
    if (csr_write(p->boot,
                  "zcl_service_kernel_start_all(&svc->network_kernel)\n"
                  "zcl_service_kernel_start_all(&svc->frontend_kernel)\n")
        || csr_write(p->tor, "tor_log_has_descriptor_publication(\n"
                          "atomic_store(&g_tor_dial_ready, true)\n")
        || csr_write(p->stream, "tor_integration_is_dial_ready\n"))
        return -1;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 1, "dial-order-fail");
    bad |= tdp_st_want(j->progress, 4, "dial-order-progress");
    bad |= !j->err || strcmp(j->err,
            "outbound dial readiness must precede descriptor publication") != 0;
    return bad;
}

static int tdp_st_probe_step5_fail(struct tdp_job *j, struct tdp_paths *p)
{
    if (csr_write(p->tor, "atomic_store(&g_tor_dial_ready, true)\n"
                       "tor_log_has_descriptor_publication(\n")
        || csr_write(p->stream, "nope\n"))
        return -1;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 1, "step5-fail");
    bad |= tdp_st_want(tdp_has(p->stream, k_tdp_dial_fn), 0, "step5-has-fail");
    bad |= !j->err || strcmp(j->err,
            "raw onion stream still waits for full inbound readiness") != 0;
    return bad;
}

static int tdp_st_probe_step6_fail(struct tdp_job *j, struct tdp_paths *p)
{
    if (csr_write(p->stream, "tor_integration_is_dial_ready\n")
        || csr_write(p->connman, "nope\n"))
        return -1;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 1, "step6-fail");
    bad |= tdp_st_want(tdp_has(p->connman, k_tdp_dial_fn), 0, "step6-has-fail");
    return bad;
}

static int tdp_st_probe_step7_fail(struct tdp_job *j, struct tdp_paths *p)
{
    if (csr_write(p->connman, "tor_integration_is_dial_ready\n")
        || csr_write(p->stream,
                     "tor_integration_is_dial_ready\ntor_integration_is_ready\n"))
        return -1;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 1, "step7-fail");
    bad |= tdp_st_want(tdp_has(p->stream, k_tdp_ready)
                      || tdp_has(p->connman, k_tdp_ready), 1, "step7-has-fail");
    return bad;
}

static int tdp_st_probe_step8_fail(struct tdp_job *j, struct tdp_paths *p)
{
    if (csr_write(p->stream, "tor_integration_is_dial_ready\n")
        || csr_write(p->watchdog, "nope\n"))
        return -1;
    int rc = tdp_run_job(j);
    int bad = 0;
    bad |= tdp_st_want(rc, 1, "step8-fail");
    bad |= tdp_st_want(tdp_has(p->watchdog, k_tdp_ready), 0, "step8-has-fail");
    return bad;
}

static int tdp_st_probe_final_has_pass(struct tdp_job *j, struct tdp_paths *p)
{
    (void)j;
    int bad = 0;
    bad |= tdp_st_want(tdp_has(p->stream, k_tdp_dial_fn), 1, "step5-has-pass");
    if (csr_write(p->connman, "tor_integration_is_dial_ready\n")
        || csr_write(p->watchdog, "tor_integration_is_ready\n"))
        return -1;
    bad |= tdp_st_want(tdp_has(p->connman, k_tdp_dial_fn), 1, "step6-has-pass");
    bad |= tdp_st_want(tdp_has(p->stream, k_tdp_ready)
                      || tdp_has(p->connman, k_tdp_ready), 0, "step7-has-pass");
    bad |= tdp_st_want(tdp_has(p->watchdog, k_tdp_ready), 1, "step8-has-pass");
    return bad;
}

typedef int (*tdp_st_probe_fn)(struct tdp_job *j, struct tdp_paths *p);

static const tdp_st_probe_fn k_tdp_st_probes[] = {
    tdp_st_probe_literal_scan,
    tdp_st_probe_order_pure,
    tdp_st_probe_full_pass,
    tdp_st_probe_boot_order_fail,
    tdp_st_probe_step1_fail,
    tdp_st_probe_dial_order_fail,
    tdp_st_probe_step5_fail,
    tdp_st_probe_step6_fail,
    tdp_st_probe_step7_fail,
    tdp_st_probe_step8_fail,
    tdp_st_probe_final_has_pass,
};

int check_tor_dial_prewarm_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-tdp-XXXXXX", td), sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);

    struct tdp_paths p;
    int rc0 = tdp_st_paths_init(&p, tmp);
    if (!rc0)
        rc0 = tdp_st_write_baseline(&p);
    if (rc0) {
        (void)rap_rm_rf(tmp);
        return rc0;
    }

    struct tdp_job j = {
        .boot = p.boot, .tor = p.tor, .stream = p.stream,
        .connman = p.connman, .watchdog = p.watchdog,
    };

    int bad = 0;
    size_t n = sizeof k_tdp_st_probes / sizeof k_tdp_st_probes[0];
    for (size_t i = 0; i < n; i++) {
        int r = k_tdp_st_probes[i](&j, &p);
        if (r < 0) {
            (void)rap_rm_rf(tmp);
            return 2;
        }
        bad |= r;
    }

    (void)rap_rm_rf(tmp);
    return st_ok(bad, "check_tor_dial_prewarm selftest: OK\n");
}
