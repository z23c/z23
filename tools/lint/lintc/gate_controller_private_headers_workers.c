/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-controller-private-headers
 * Third file of the check-controller-private-headers family (the 700-line
 * family ceiling split): the gate's --selftest probes. The gate body —
 * the baseline loader, the byte-order sort, the shrink-only verdict — and
 * the family's parity notes live in gate_controller_private_headers.c;
 * the native collect and include scan live in
 * gate_controller_private_headers_scan.c.
 */

/* ── --selftest ────────────────────────────────────────────────────────────
 * Byte-parity port of the original script's --selftest block: a mktemp
 * fixture tree with one private header (alpha_internal.h), proves the
 * owner-family/private-composition/test-path inclusions pass, that quoted
 * and angle-form config edges, a view edge, and a public controller-header
 * edge each fail, that a pinned config edge passes and then goes stale,
 * and that a missing or empty scan root fails closed with exit 2.
 *
 * Semantic mapping:
 * - mktemp -d "${TMPDIR:-/tmp}/z23-controller-private.XXXXXX" is
 *   cphw_setup's mkdtemp (env_or's unset-or-empty fallback matches
 *   ${TMPDIR:-/tmp}); the EXIT trap's rm -rf is rap_rm_rf on every path.
 * - Fixture directories and files are csr_mkdirs / csr_write (checked,
 *   parent-creating), the `rm -f --` removals are cphw_rm (unlink, ENOENT
 *   ignored).
 * - run_fixture is cphw_fixture: all three ZCL_CONTROLLER_PRIVATE_*
 *   assignments on every inner run via setenv, then the gate FOR REAL via
 *   cic_invoke. The call sites' redirections map to cic_invoke's merge
 *   flag: expect_fail and the two root cases used `>/dev/null 2>&1`
 *   (merge=1, merged output sunk and only the exit code graded); the three
 *   set -e `run_fixture >/dev/null` steps keep stderr LIVE (merge=0), and
 *   a nonzero inner exit there returns that code silently, as set -e did.
 * - expect_fail demands any nonzero exit; the root cases demand exactly 2,
 *   with the shell's SELFTEST FAILED texts byte-for-byte.
 *
 * Parity notes:
 * - mktemp failure: the shell exits 1 with mktemp's own message; the port
 *   die()s exit 2 (environment failure, not a gate verdict — the
 *   describe-budget precedent).
 * - The merged-output sink is bounded (64 KiB); the shell discarded
 *   unboundedly. Overflow die()s, fail-closed.
 * - The port's setenv mutations persist in-process where the shell's `env`
 *   assignments were per-subprocess; every inner run sets all three
 *   variables, and the process exits when the selftest ends, so no
 *   snapshot/restore is needed (unlike gate_supervisor_domain_workers.c).
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

static const char k_cphw_name[] = "check_controller_private_headers";
static const char k_cphw_gate[] = "check-controller-private-headers";
static char g_cphw_tmp[4096];
enum { CPHW_SINK = 65536 };

static int cphw_path(char *buf, size_t cap, const char *rel)
{
    return ovf(snprintf(buf, cap, "%s/%s", g_cphw_tmp, rel), cap);
}

/* run_fixture: all three ZCL_CONTROLLER_PRIVATE_* assignments on every
 * inner run, then the gate for real; merge=1 is the call site's
 * `>/dev/null 2>&1`, merge=0 its `>/dev/null` (stderr stays live). */
static int cphw_fixture(const char *scan_root, int merge, int *code)
{
    char hroot[4096], base[4096];
    int rc = cphw_path(hroot, sizeof hroot,
                       "app/controllers/include/controllers");
    if (rc == 0)
        rc = cphw_path(base, sizeof base, "empty-baseline.txt");
    if (rc == 0
        && setenv("ZCL_CONTROLLER_PRIVATE_SCAN_ROOT", scan_root, 1) != 0)
        rc = die("z23-lint: setenv failed\n", "");
    if (rc == 0
        && setenv("ZCL_CONTROLLER_PRIVATE_HEADER_ROOT", hroot, 1) != 0)
        rc = die("z23-lint: setenv failed\n", "");
    if (rc == 0
        && setenv("ZCL_CONTROLLER_PRIVATE_BASELINE", base, 1) != 0)
        rc = die("z23-lint: setenv failed\n", "");
    if (rc)
        return rc;
    static char sink[CPHW_SINK];
    return cic_invoke(k_cphw_gate, merge, sink, sizeof sink, code);
}

static int cphw_write(const char *rel, const char *text)
{
    char p[4096];
    int rc = cphw_path(p, sizeof p, rel);
    if (rc == 0)
        rc = csr_write(p, text);
    return rc;
}

static int cphw_write_inc(const char *rel, int angle)
{
    return cphw_write(rel, angle
        ? "#include <controllers/alpha_internal.h>\n"
        : "#include \"controllers/alpha_internal.h\"\n");
}

/* rm -f --: a missing entry is not an error. */
static void cphw_rm(const char *rel)
{
    char p[4096];
    if (cphw_path(p, sizeof p, rel) == 0)
        (void)unlink(p);
}

static int cphw_expect_fail(const char *label)
{
    int code = 0;
    int rc = cphw_fixture(g_cphw_tmp, 1, &code);
    if (rc == 0 && code == 0) {
        fprintf(stderr, "%s: SELFTEST FAILED — %s passed\n", k_cphw_name,
                label);
        rc = 2;
    }
    return rc;
}

/* One plant-a-violation case: write the includer, demand the gate fails,
 * remove the includer. */
static int cphw_viol_case(const char *rel, int angle, const char *label)
{
    int rc = cphw_write_inc(rel, angle);
    if (rc == 0)
        rc = cphw_expect_fail(label);
    if (rc == 0)
        cphw_rm(rel);
    return rc;
}

static int cphw_setup(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(g_cphw_tmp, sizeof g_cphw_tmp,
                     "%s/z23-controller-private.XXXXXX", td),
            sizeof g_cphw_tmp))
        return 2;
    if (!mkdtemp(g_cphw_tmp))
        return die("z23-lint: mktemp failed: %s\n", g_cphw_tmp);
    static const char *const dirs[] = {
        "app/controllers/src", "app/controllers/include/controllers",
        "app/views/src", "config/src", "lib/test/src",
    };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof dirs / sizeof dirs[0]; i++) {
        char p[4096];
        rc = cphw_path(p, sizeof p, dirs[i]);
        if (rc == 0)
            rc = csr_mkdirs(p);
    }
    if (rc == 0)
        rc = cphw_write("app/controllers/include/controllers/"
                        "alpha_internal.h", "");
    if (rc == 0)
        rc = cphw_write("empty-baseline.txt", "");
    if (rc == 0)
        rc = cphw_write_inc("app/controllers/src/alpha_worker.c", 0);
    if (rc == 0)
        rc = cphw_write_inc("app/controllers/include/controllers/"
                            "beta_private.h", 0);
    if (rc == 0)
        rc = cphw_write_inc("lib/test/src/test_private.c", 0);
    return rc;
}

/* The allowed set passes, then the four planted violation classes. */
static int cphw_phase1(void)
{
    int code = 0;
    int rc = cphw_fixture(g_cphw_tmp, 0, &code);
    if (rc == 0 && code)
        rc = code;
    if (rc == 0)
        rc = cphw_viol_case("config/src/wire.c", 0,
                            "config private-header violation");
    if (rc == 0)
        rc = cphw_viol_case("config/src/wire.c", 1,
                            "angle-form private-header violation");
    if (rc == 0)
        rc = cphw_viol_case("app/views/src/view.c", 0,
                            "view private-header violation");
    if (rc == 0)
        rc = cphw_viol_case("app/controllers/include/controllers/public.h", 0,
                            "public controller-header violation");
    return rc;
}

/* The pinned config edge passes, then goes stale once removed. */
static int cphw_phase2(void)
{
    int rc = cphw_write_inc("config/src/wire.c", 0);
    if (rc == 0)
        rc = cphw_write("empty-baseline.txt",
                        "config/src/wire.c:#include "
                        "\"controllers/alpha_internal.h\"\n");
    int code = 0;
    if (rc == 0)
        rc = cphw_fixture(g_cphw_tmp, 0, &code);
    if (rc == 0 && code)
        rc = code;
    if (rc == 0) {
        cphw_rm("config/src/wire.c");
        rc = cphw_expect_fail("stale baseline row");
    }
    if (rc == 0)
        rc = cphw_write("empty-baseline.txt", "");
    return rc;
}

/* A missing or empty scan root fails closed with exactly exit 2. */
static int cphw_expect2(const char *root, const char *what)
{
    int code = 0;
    int rc = cphw_fixture(root, 1, &code);
    if (rc == 0 && code != 2) {
        fprintf(stderr, "%s: SELFTEST FAILED — %s returned %d, expected 2\n",
                k_cphw_name, what, code);
        rc = 2;
    }
    return rc;
}

static int cphw_phase3(void)
{
    char p[4096];
    int rc = cphw_path(p, sizeof p, "missing");
    if (rc == 0)
        rc = cphw_expect2(p, "missing root");
    if (rc == 0)
        rc = cphw_path(p, sizeof p, "empty-root");
    if (rc == 0)
        rc = csr_mkdirs(p);
    if (rc == 0)
        rc = cphw_expect2(p, "empty root");
    int code = 0;
    if (rc == 0)
        rc = cphw_fixture(g_cphw_tmp, 0, &code);
    if (rc == 0 && code)
        rc = code;
    return rc;
}

/* ── mandatory/optional git-index-extension coverage (root=".") ─────────
 * A synthetic one-entry DIRC index proves the "." collector (p9's fix to
 * cphs_collect in gate_controller_private_headers_scan.c) now refuses a
 * mandatory extension by name instead of silently falling through to the
 * private-header floor check with a partial file list, while an optional
 * extension changes nothing — the gate_supervisor_domain_workers.c
 * sdw_ext_link/sdw_ext_tree precedent, exercised here at the gate-entry
 * layer (cic_invoke) rather than the walker layer, so it proves the
 * wiring, not just lib.c's reader (already covered by that other gate's
 * own selftest). */

enum { CPHW_IDXCAP = 128 };

static size_t cphw_idx_build(unsigned char *buf, const char *sig)
{
    memset(buf, 0, CPHW_IDXCAP);
    memcpy(buf, "DIRC", 4);
    buf[7] = 2;                     /* version 2 */
    buf[11] = 1;                    /* one entry */
    buf[12 + 61] = 3;               /* entry flags: namelen of "t.c" */
    memcpy(buf + 12 + 62, "t.c", 3);
    size_t n = 12 + 72;
    if (sig) {
        memcpy(buf + n, sig, 4);
        buf[n + 7] = 4;             /* payload size */
        n += 12;
    }
    return n + 20;
}

/* Build the synthetic index (sig = the extension to append, or NULL),
 * point GIT_INDEX_FILE at it, and invoke the real gate once with
 * ZCL_CONTROLLER_PRIVATE_SCAN_ROOT="." and the header-root/baseline vars
 * cleared (repo defaults). Returns the invocation's own rc; *code and
 * sink carry the gate's exit code and merged output. */
static int cphw_ext_probe(const char *sig, char *sink, size_t cap,
                          int *code)
{
    unsigned char buf[CPHW_IDXCAP];
    size_t n = cphw_idx_build(buf, sig);
    char path[64];
    memcpy(path, "test-tmp/cph_idxext_XXXXXX", 27);
    int fd = mkstemp(path);
    if (fd < 0)
        return die("z23-lint: mktemp failed\n", "");
    FILE *f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        unlink(path);
        return die("z23-lint: write failed\n", "");
    }
    int bad = fwrite(buf, 1, n, f) != n;
    if (fclose(f) != 0)
        bad = 1;
    if (bad) {
        unlink(path);
        return die("z23-lint: write failed\n", "");
    }
    int rc = setenv("GIT_INDEX_FILE", path, 1);
    if (rc == 0)
        rc = setenv("ZCL_CONTROLLER_PRIVATE_SCAN_ROOT", ".", 1);
    if (rc == 0)
        rc = unsetenv("ZCL_CONTROLLER_PRIVATE_HEADER_ROOT");
    if (rc == 0)
        rc = unsetenv("ZCL_CONTROLLER_PRIVATE_BASELINE");
    if (rc != 0)
        rc = die("z23-lint: setenv failed\n", "");
    else
        rc = cic_invoke(k_cphw_gate, 1, sink, cap, code);
    (void)unsetenv("GIT_INDEX_FILE");
    if (unlink(path) != 0)
        return die("z23-lint: unlink failed: %s\n", path);
    return rc;
}

/* A mandatory 'link' extension: the gate refuses (exit 2) and names it,
 * instead of falling through to the private-header floor with a partial
 * scan. */
static int cphw_ext_link(void)
{
    static char sink[CPHW_SINK];
    int code = 0;
    int rc = cphw_ext_probe("link", sink, sizeof sink, &code);
    if (rc == 0 && (code != 2 || !strstr(sink, "link"))) {
        fprintf(stderr, "%s: SELFTEST FAILED — mandatory extension not "
                "refused/named\n", k_cphw_name);
        rc = 2;
    }
    return rc;
}

/* An optional 'TREE' extension changes nothing: the gate still falls
 * through to the ordinary "no controller private headers" floor (only
 * "t.c" was collected), never the mandatory-extension message. */
static int cphw_ext_tree(void)
{
    static char sink[CPHW_SINK];
    int code = 0;
    int rc = cphw_ext_probe("TREE", sink, sizeof sink, &code);
    if (rc == 0 && (code != 2 || strstr(sink, "mandatory"))) {
        fprintf(stderr, "%s: SELFTEST FAILED — optional extension changed "
                "the verdict\n", k_cphw_name);
        rc = 2;
    }
    return rc;
}

static int cphw_phase4(void)
{
    int rc = cphw_ext_link();
    if (rc == 0)
        rc = cphw_ext_tree();
    return rc;
}

int check_controller_private_headers_selftest(void)
{
    char root[4096];
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0)
        rc = cphw_setup();
    if (rc == 0)
        rc = cphw_phase1();
    if (rc == 0)
        rc = cphw_phase2();
    if (rc == 0)
        rc = cphw_phase3();
    if (g_cphw_tmp[0])
        (void)rap_rm_rf(g_cphw_tmp);
    if (rc == 0)
        rc = cphw_phase4();
    if (rc == 0)
        fputs("[check_controller_private_headers] SELFTEST PASS (owner/"
              "private/test allowed; quoted/angle config, view, and "
              "public-header edges rejected; stale baseline and "
              "missing/empty roots fail closed; a mandatory index "
              "extension is refused and named while an optional one "
              "changes nothing)\n", stdout);
    return rc;
}
