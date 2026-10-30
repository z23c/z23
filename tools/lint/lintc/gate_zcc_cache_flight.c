/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: check-zcc-cache singleflight suite: same-content requests share
 * one compile, independent keys and audit requests compile on their own,
 * failed and killed owners hand the claim on, inputs changed while a
 * follower waits are rebuilt, and a refused lock bypasses safely.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include <dirent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_zcc_cache_priv.h"

static char sf_root[ZC_PATH], sf_state[ZC_PATH], sf_cc[ZC_PATH];

static const char *sp(const char *name)
{
    return zcf("%s/%s", sf_state, name);
}

static const char sf_wrapper[] =
    "#!/usr/bin/env bash\nset -euo pipefail\n"
    "for argument in \"$@\"; do\n"
    "    case \"$argument\" in -E|--version|-dump*|-print-prog-name=*) "
    "exec \"$SF_CC\" \"$@\" ;; esac\ndone\n"
    ": > \"$SF_STATE/compile.$$\"\nowner=0\n"
    "if [ \"${SF_HOLD:-0}\" = 1 ] && mkdir \"$SF_STATE/owner\" 2>/dev/null; then\n"
    "    owner=1\nfi\nresult=0\n"
    "if [ \"$owner\" = 1 ] && [ \"${SF_FAIL:-0}\" = 1 ]; then\n"
    "    result=75\nelse\n    \"$SF_CC\" \"$@\" || result=$?\nfi\n"
    ": > \"$SF_STATE/finished.$$\"\n"
    "if [ \"$owner\" = 1 ]; then\n"
    "    printf '%s\\n' \"$PPID\" > \"$SF_STATE/owner.zccpid\"\n"
    "    : > \"$SF_STATE/held\"\n"
    "    for ((attempt = 0; attempt < 400; attempt++)); do\n"
    "        if [ -e \"$SF_STATE/release\" ]; then\n"
    "            : > \"$SF_STATE/released\"\n"
    "            exit \"$result\"\n        fi\n        sleep 0.025\n    done\n"
    "    echo 'singleflight fixture release timed out' >&2\n    exit 76\nfi\n"
    "exit \"$result\"\n";

static void sf_nap(void)
{
    struct timespec ts = { 0, 25000000L };
    nanosleep(&ts, NULL);
}

static int sf_ready(const char *path)
{
    for (int i = 0; i < 400; i++) {
        if (zc_exists(path))
            return 0;
        sf_nap();
    }
    zc_fail(zcf("singleflight barrier timed out: %s", path));
    return 1;
}

static int sf_count(const char *kind)
{
    DIR *d = opendir(sf_state);
    struct dirent *e;
    int n = 0;
    size_t kl = strlen(kind);
    while (d && (e = readdir(d)))
        n += strncmp(e->d_name, kind, kl) == 0 && e->d_name[kl] == '.';
    if (d)
        closedir(d);
    return n;
}

static int sf_waiting(const char *output)
{
    const char *log = sp(zcf("log.%s", output));
    for (int i = 0; i < 400; i++) {
        if (zc_line_with_prefix(log, "WAIT "))
            return 0;
        sf_nap();
    }
    zc_fail(zcf("singleflight %s did not observe contention", output));
    return 1;
}

static int sf_case(const char *name)
{
    zc_str(sf_state, sizeof sf_state, zcf("%s/%s", sf_root, name));
    if (csr_mkdirs(sf_state) ||
        csr_write(sp("value.h"), "#define VALUE 42\n") ||
        csr_write(sp("value.c"), "#include \"value.h\"\nstatic int sf_unused(void) "
                  "{ return 0; }\nint value(void) { return VALUE; }\n"))
        return 1;
    return 0;
}

struct sf_job { const char *out; int def, audit, hold, reject; };

static pid_t sf_start(const struct sf_job *j)
{
    const char *o = j->out;
    const char *env[] = { j->audit ? "ZCC_AUDIT=1" : "ZCC_AUDIT",
        zcf("SF_CC=%s", sf_cc), zcf("SF_STATE=%s", sf_state),
        zcf("ZCC_DIR=%s/cache", sf_state), zcf("ZCC_LOG=%s/log.%s", sf_state, o),
        zcf("SF_HOLD=%d", j->hold), zcf("SF_FAIL=%d", j->reject), NULL };
    struct zc_cmd c = { .env = env, .outf = sp(zcf("stdout.%s", o)),
        .errf = sp(zcf("stderr.%s", o)),
        .argv = ZC_ARGV(zc.zcc, zcf("%s/compiler", sf_root), "-std=c23", "-O1",
            "-Wall", zcf("-DSF_KEY=%d", j->def), "-MD", "-MF",
            sp(zcf("%s.d", o)), "-MT", sp(zcf("%s.o", o)), "-c", sp("value.c"),
            "-o", sp(zcf("%s.o", o))) };
    return zc_start(&c);
}

static int sf_join(pid_t pid, const char *label)
{
    int rc = zc_wait(pid);
    zc_want(rc == 0, zcf("singleflight %s compile failed", label));
    return rc;
}

static int sf_sync(const char *out)
{
    struct sf_job j = { out, 1, 0, 0, 0 };
    return zc_wait(sf_start(&j));
}

static int sf_release(void)
{
    return csr_write(sp("release"), "");
}

static int sf_shared(void)
{
    struct sf_job oj = { "owner", 1, 0, 1, 0 }, fj = { "follower", 1, 0, 1, 0 };
    struct sf_job ij = { "independent", 2, 0, 0, 0 };
    if (sf_case("shared"))
        return 1;
    pid_t owner = sf_start(&oj);
    if (sf_ready(sp("held")))
        return 1;
    pid_t follower = sf_start(&fj);
    if (sf_waiting("follower"))
        return 1;
    sf_join(sf_start(&ij), "independent");
    zc_want(sf_count("compile") == 2, "same-key follower compiled while its owner was active");
    if (sf_release())
        return 1;
    sf_join(owner, "owner");
    sf_join(follower, "follower");
    zc_want(sf_count("compile") == 2, "identical cold requests did not share one compile");
    zc_want(zc_same(sp("owner.o"), sp("follower.o")), "shared compile output bytes differ");
    zc_want(zc_file_has(sp("follower.d"), zcf("%s:", sp("follower.o"))),
            "shared compile depfile does not name the follower target");
    zc_want(zc_file_has(sp("follower.d"), sp("value.h")),
            "shared compile depfile lost a header dependency");
    zc_want(zc_file_has(sp("stderr.owner"), "sf_unused"),
            "shared compile warning fixture produced no warning");
    zc_want(zc_same(sp("stderr.owner"), sp("stderr.follower")),
            "shared compile did not replay exact compiler diagnostics");
    zc_want(zc_line_with_prefix(sp("log.follower"), "HIT "),
            "same-key follower did not report a cache hit");
    return 0;
}

static int sf_audit(void)
{
    struct sf_job oj = { "audit_owner", 1, 1, 1, 0 }, pj = { "audit_peer", 1, 1, 0, 0 };
    if (sf_case("audit"))
        return 1;
    sf_sync("warm");
    pid_t owner = sf_start(&oj);
    if (sf_ready(sp("held")))
        return 1;
    sf_join(sf_start(&pj), "audit-peer");
    zc_want(sf_count("compile") == 3, "audit did not independently compile both requests");
    if (sf_release())
        return 1;
    sf_join(owner, "audit-owner");
    zc_want(zc_same(sp("audit_owner.o"), sp("audit_peer.o")),
            "independent audit output bytes differ");
    return 0;
}

static int sf_failed(void)
{
    struct sf_job oj = { "failed_owner", 1, 0, 1, 1 }, rj = { "retry", 1, 0, 1, 1 };
    if (sf_case("failed"))
        return 1;
    pid_t owner = sf_start(&oj);
    if (sf_ready(sp("held")))
        return 1;
    pid_t follower = sf_start(&rj);
    if (sf_waiting("retry") || sf_release())
        return 1;
    zc_want(zc_wait(owner) != 0, "failed compiler owner unexpectedly succeeded");
    sf_join(follower, "recovery");
    zc_want(sf_count("compile") == 2, "failed owner did not release its compile claim");
    zc_want(zc_nonempty(sp("retry.o")), "failed owner prevented successful follower output");
    return 0;
}

static int sf_changed(void)
{
    struct sf_job oj = { "owner", 1, 0, 1, 0 }, fj = { "follower", 1, 0, 1, 0 };
    if (sf_case("changed"))
        return 1;
    pid_t owner = sf_start(&oj);
    if (sf_ready(sp("held")))
        return 1;
    pid_t follower = sf_start(&fj);
    if (sf_waiting("follower") || csr_write(sp("value.h"), "#define VALUE 100\n") ||
        sf_release())
        return 1;
    sf_join(owner, "changed-owner");
    sf_join(follower, "changed-follower");
    if (zc_x(ZC_ARGV(sf_cc, "-std=c23", "-O1", "-DSF_KEY=1", "-c", sp("value.c"),
                     "-o", sp("expected.o")), NULL, NULL) != 0)
        return 1;
    zc_want(zc_same(sp("follower.o"), sp("expected.o")),
            "inputs changed during wait but the follower returned stale bytes");
    zc_want(!zc_same(sp("owner.o"), sp("follower.o")),
            "changed-input fixture did not distinguish old and new outputs");
    zc_want(sf_count("compile") == 2, "changed-input follower did not compile current inputs");
    return 0;
}

static int sf_unavailable(const char *shape)
{
    int link = strcmp(shape, "symlink") == 0;
    if (sf_case(zcf("unavailable-%s", shape)) || csr_mkdirs(sp("cache")) ||
        csr_write(sp("sentinel"), "untouched\n"))
        return 1;
    if (link ? symlink(sp("sentinel"), sp("cache/flight.lock")) != 0
             : csr_mkdirs(sp("cache/flight.lock")) != 0)
        return 1;
    if (sf_sync("first") != 0 || sf_sync("second") != 0)
        return 1;
    zc_want(sf_count("compile") == 2,
            zcf("%s lock refusal did not compile independently", shape));
    zc_want(zc_same(sp("first.o"), sp("second.o")),
            zcf("%s lock refusal changed output bytes", shape));
    zc_want(zc_file_has(sp("sentinel"), "untouched"),
            "lock refusal changed the symlink target");
    zc_want(zc_line_with_prefix(sp("log.second"), "BYPASS "),
            zcf("%s lock refusal did not report bypass", shape));
    return 0;
}

static int sf_killed(void)
{
    struct sf_job oj = { "owner", 1, 0, 1, 0 }, fj = { "follower", 1, 0, 1, 0 };
    char pidtxt[64];
    if (sf_case("killed"))
        return 1;
    pid_t owner = sf_start(&oj);
    if (sf_ready(sp("held")))
        return 1;
    pid_t follower = sf_start(&fj);
    if (sf_waiting("follower"))
        return 1;
    FILE *f = fopen(sp("owner.zccpid"), "r");
    pidtxt[0] = '\0';
    if (f && fgets(pidtxt, sizeof pidtxt, f))
        pidtxt[strcspn(pidtxt, "\n")] = '\0';
    if (f)
        fclose(f);
    if (pidtxt[0] == '\0' || pidtxt[strspn(pidtxt, "0123456789")] != '\0') {
        zc_fail("compiler wrapper did not identify its owner process");
        return 1;
    }
    kill((pid_t)atol(pidtxt), SIGKILL);
    zc_want(zc_wait(owner) != 0, "killed compiler owner unexpectedly succeeded");
    sf_join(follower, "killed-owner-recovery");
    zc_want(sf_count("compile") == 2, "killed owner did not release the compile claim");
    zc_want(zc_nonempty(sp("follower.o")), "killed owner prevented follower output");
    return sf_release() || sf_ready(sp("released"));
}

int zc_sec_flight(void)
{
    if (!zc_which("cc", sf_cc, sizeof sf_cc))
        return 1;
    zc_str(sf_root, sizeof sf_root, zcw("singleflight"));
    if (csr_mkdirs(sf_root) || csr_write(zcf("%s/compiler", sf_root), sf_wrapper) ||
        chmod(zcf("%s/compiler", sf_root), 0755) != 0)
        return 1;
    return sf_shared() || sf_audit() || sf_failed() || sf_changed() ||
           sf_unavailable("symlink") || sf_unavailable("directory") || sf_killed();
}
