/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Group `install_sh_site` — the /install.sh front door
 * (core/modules/net/include/net/site_routes.def, contexts/commons/views/src/install_sh_view.c) and
 * the HTTPS root curl/Wget short-circuit that serves the same body for a
 * bare `curl -fsSL https://<site> | sh`
 * (core/modules/net/src/https_server.c: https_root_wants_install_script()).
 *
 * Both are called in-process — no socket, no TLS — because both are pure
 * functions of their inputs: the handler of (method, buffer), the
 * short-circuit of (User-Agent, Accept). Neither needs a live listener to
 * prove what it decides. */

#include "test/test_core.h"

#include "net/https_server.h"
#include "views/install_sh_view.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <dirent.h>
#include <unistd.h>
#endif

#define ISH_BUF (64 * 1024)

#define ISH_CHECK(name, expr) do {                                  \
    printf("install_sh_site: %s... ", (name));                      \
    if (expr) { printf("OK\n"); }                                   \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

static int ish_front_paths(void)
{
    int failures = 0;
    /* Front paths: default-off; set paths steer the browser root and
     * /start; a bad path is refused and keeps the default. */
    https_server_set_front_paths(NULL, NULL);
    ISH_CHECK("front paths default: root goes to /explorer",
              strcmp(https_root_redirect_target_for_testing(),
                     "/explorer") == 0);
    ISH_CHECK("front paths default: public-install keeps GET /",
              https_front_home_first_for_testing("/", false) == NULL);
    ISH_CHECK("front paths default: /start is not special",
              https_start_redirect_target_for_testing("/start") == NULL);
    https_server_set_front_paths("", "");
    ISH_CHECK("empty front paths keep the defaults",
              strcmp(https_root_redirect_target_for_testing(),
                     "/explorer") == 0 &&
              https_start_redirect_target_for_testing("/start") == NULL);
    https_server_set_front_paths("/wiki/home", "/wiki/start.txt");
    ISH_CHECK("site-home steers the browser root",
              strcmp(https_root_redirect_target_for_testing(),
                     "/wiki/home") == 0);
    ISH_CHECK("site-start steers /start only",
              strcmp(https_start_redirect_target_for_testing("/start"),
                     "/wiki/start.txt") == 0 &&
              https_start_redirect_target_for_testing("/starts") == NULL &&
              https_start_redirect_target_for_testing("/") == NULL);
    ISH_CHECK("script clients still want the installer with front paths set",
              https_root_wants_install_script_for_testing("curl/8.0", ""));
    /* The request path checks site-home before the public-install tree,
     * whose install.sh would otherwise answer a browser's GET /. */
    bool browser = https_root_wants_install_script_for_testing(
        "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0",
        "text/html,application/xhtml+xml");
    bool curl = https_root_wants_install_script_for_testing("curl/8.0", "*/*");
    const char *home_first = https_front_home_first_for_testing("/", browser);
    ISH_CHECK("site-home answers a browser GET / before public-install",
              !browser && home_first && strcmp(home_first, "/wiki/home") == 0);
    ISH_CHECK("a script client's GET / still reaches public-install",
              curl && https_front_home_first_for_testing("/", curl) == NULL);
    ISH_CHECK("site-home leaves other paths to public-install",
              https_front_home_first_for_testing("/install.sh", false) == NULL);
    https_server_set_front_paths("wiki", "//evil.example/x");
    ISH_CHECK("unrooted and protocol-relative paths are refused",
              strcmp(https_root_redirect_target_for_testing(),
                     "/explorer") == 0 &&
              https_start_redirect_target_for_testing("/start") == NULL);
    https_server_set_front_paths("/a/../b", "/x\r\nSet-Cookie: y=1");
    ISH_CHECK("dot-dot and control bytes are refused",
              strcmp(https_root_redirect_target_for_testing(),
                     "/explorer") == 0 &&
              https_start_redirect_target_for_testing("/start") == NULL);
    https_server_set_front_paths(NULL, NULL);
    return failures;
}

static int ish_script_steps(const char *body)
{
    int failures = 0;
    ISH_CHECK("say writes to stderr",
              body && strstr(body, "say() {\n"
                                   "    echo \"install_from_source: $*\" >&2\n"
                                   "}\n") != NULL);
    /* Old "say \"checking tools\"" -> the numbered step 1 line. */
    ISH_CHECK("the script reports the tool check (step 1/4)",
              body && strstr(body, "say \"1/4 Checking tools") != NULL);
    /* Old "say \"cloning \"" -> the fresh-clone step 2 line + its command. */
    ISH_CHECK("the script reports a fresh clone (step 2/4)",
              body && strstr(body, "say \"2/4 Getting the source: cloning "
                                   "$REPO_URL into $SRC") != NULL &&
                  strstr(body, "run git clone \"$REPO_URL\" \"$SRC\"") != NULL);
    /* Old "say \"updating existing clone\"" -> existing-checkout step 2. */
    ISH_CHECK("the script reports updating an existing clone (step 2/4)",
              body && strstr(body, "say \"2/4 Getting the source: updating "
                                   "the existing clone in $SRC") != NULL &&
                  strstr(body, "run git -C \"$SRC\" fetch origin") != NULL);
    /* Old "say \"checking out pinned commit $Z23_PIN\"" -> log line + cmd. */
    ISH_CHECK("the script records the pinned-commit checkout",
              body && strstr(body, "echo \"checking out pinned commit "
                                   "$Z23_PIN\" >>\"$LOG\"") != NULL &&
                  strstr(body, "run git -C \"$SRC\" checkout \"$Z23_PIN\"") != NULL);
    /* Old "say \"no commit pin was served\"" -> log line + main checkout. */
    ISH_CHECK("the script records the no-pin main fallback",
              body && strstr(body, "echo \"no commit pin was served; building "
                                   "main instead\" >>\"$LOG\"") != NULL &&
                  strstr(body, "run git -C \"$SRC\" checkout main") != NULL);
    /* Old "say \"building with $jobs jobs\"" -> step 3 line + make -j. */
    ISH_CHECK("the script reports the build (step 3/4)",
              body && strstr(body, "say \"3/4 Building (several minutes") != NULL &&
                  strstr(body, "make -C \"$SRC\" -j\"$jobs\" z23") != NULL);
    /* Old "say \"done\"" -> step 4. */
    ISH_CHECK("the script reports done (step 4/4)",
              body && strstr(body, "say \"4/4 Done\"") != NULL);
    return failures;
}

#ifndef _WIN32
static bool ish_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

/* A stub tool is a symlink to a system binary, so the test adds no shell:
 * git and make are echo (their arguments become log noise), cc is true,
 * and a failing git is ls (it cannot find "clone", says so, exits 2). */
static bool ish_link(const char *d, const char *tool, const char *target)
{
    static const char *const dirs[] = { "/bin", "/usr/bin" };
    char t[64], p[1024];
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        snprintf(t, sizeof(t), "%s/%s", dirs[i], target);
        if (access(t, X_OK) != 0)
            continue;
        snprintf(p, sizeof(p), "%s/bin/%s", d, tool);
        (void)unlink(p);
        return symlink(t, p) == 0;
    }
    return false;
}

/* Fails closed: an unreadable TMPDIR counts as a leaked temp log. */
static bool ish_tmp_clean(const char *d)
{
    char p[1024];
    snprintf(p, sizeof(p), "%s/tmp", d);
    DIR *dir = opendir(p);
    if (!dir) return false;
    bool clean = true;
    for (struct dirent *e; (e = readdir(dir)) != NULL;)
        if (strncmp(e->d_name, "z23-install.", 12) == 0)
            clean = false;
    closedir(dir);
    return clean;
}

static bool ish_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    fclose(f);
    return true;
}

static bool ish_stage(const char *d, const char *body, bool fail)
{
    char p[1024];
    snprintf(p, sizeof(p), "%s/bin", d);
    if (mkdir(p, 0700) != 0 && errno != EEXIST) return false;
    snprintf(p, sizeof(p), "%s/tmp", d);
    if (mkdir(p, 0700) != 0 && errno != EEXIST) return false;
    snprintf(p, sizeof(p), "%s/inst.sh", d);
    return ish_write(p, body) && ish_link(d, "git", fail ? "ls" : "echo") &&
           ish_link(d, "make", "echo") && ish_link(d, "cc", "true");
}

/* Run the served script for real with stub git/make/cc first on PATH (see
 * ish_link; fail makes git fail). Returns the system() status; out/err/log
 * capture stdout, stderr and build/install.log. */
static int ish_run_script(const char *d, const char *body, bool fail,
                          char *out, char *err, char *log, size_t cap)
{
    char p[1024], cmd[4096];
    if (!ish_stage(d, body, fail)) return -1;
    snprintf(cmd, sizeof(cmd),
             "cd \"%s\" && env -i PATH=\"%s/bin:/usr/bin:/bin\" HOME=\"%s\" "
             "TMPDIR=\"%s/tmp\" Z23_SRC=\"%s/src\" "
             "sh \"%s/inst.sh\" </dev/null >\"%s/out\" 2>\"%s/err\"",
             d, d, d, d, d, d, d, d);
    int rc = system(cmd);
    snprintf(p, sizeof(p), "%s/out", d);
    if (!ish_slurp(p, out, cap)) return -1;
    snprintf(p, sizeof(p), "%s/err", d);
    if (!ish_slurp(p, err, cap)) return -1;
    snprintf(p, sizeof(p), "%s/src/build/install.log", d);
    log[0] = '\0';
    (void)ish_slurp(p, log, cap);
    return rc;
}

/* Occurrences of needle in hay. */
static size_t ish_count(const char *hay, const char *needle)
{
    size_t n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p++)
        n++;
    return n;
}

/* The echo stubs print their arguments: "clone https://..." for the clone,
 * and "-C <d>/src ..." for every other git and make call (checkout, pull,
 * make setup, make z23). No terminal line the script prints has "-C ". */
static int ish_real_ok(const char *d, const char *body)
{
    int failures = 0;
    static char out[8192], err[8192], log[8192];
    char dash_c[600], setup[640], build[640], checkout[640];
    snprintf(dash_c, sizeof(dash_c), "-C %s/src ", d);
    snprintf(setup, sizeof(setup), "%ssetup", dash_c);
    snprintf(build, sizeof(build), "%s-j", dash_c);
    snprintf(checkout, sizeof(checkout), "%scheckout", dash_c);
    int rc = ish_run_script(d, body, false, out, err, log, sizeof(out));
    ISH_CHECK("real run: success exits 0 with the summary on stdout",
              rc == 0 && strstr(out, "Binary:  ") != NULL &&
                  strstr(out, "https://z23.sh/start") != NULL);
    ISH_CHECK("real run: no git or make output reaches the terminal",
              strstr(out, "clone https://") == NULL &&
                  strstr(err, "clone https://") == NULL &&
                  strstr(out, "-C ") == NULL && strstr(err, "-C ") == NULL);
    ISH_CHECK("real run: every git and make call lands in build/install.log",
              strstr(log, "clone https://") != NULL &&
                  strstr(log, checkout) != NULL &&
                  strstr(log, setup) != NULL && strstr(log, build) != NULL &&
                  ish_count(log, dash_c) >= 3);
    return failures;
}

static int ish_real_fail(const char *d, const char *body)
{
    int failures = 0;
    static char out[8192], err[8192], log[8192];
    int rc = ish_run_script(d, body, true, out, err, log, sizeof(out));
    ISH_CHECK("real run: a failing step exits non-zero",
              rc != 0 && strstr(out, "Binary:  ") == NULL);
    /* The tail carries ls's own complaint about the missing "clone". */
    ISH_CHECK("real run: failure prints FAILED and the log tail",
              strstr(err, "FAILED: git clone") != NULL &&
                  strstr(err, "last 20 lines") != NULL &&
                  strstr(err, "No such file or directory") != NULL);
    ISH_CHECK("real run: a pre-clone failure leaves no temp log behind",
              ish_tmp_clean(d));
    return failures;
}

static int ish_script_real_run(const char *body)
{
    int failures = 0;
    char d[512];
    if (!body || !test_mkdtemp(d, sizeof(d), "install_sh_run")) {
        ISH_CHECK("real-run fixture directory", false);
        return failures;
    }
    failures += ish_real_ok(d, body);
    char src[600];
    snprintf(src, sizeof(src), "%s/src", d);
    test_rm_rf(src); /* the failure run must clone afresh */
    failures += ish_real_fail(d, body);
    test_rm_rf(d);
    return failures;
}
#else
static int ish_script_real_run(const char *body)
{
    (void)body;
    return 0;
}
#endif

static int ish_script_log_and_summary(const char *body)
{
    int failures = 0;
    ISH_CHECK("build output goes to a named log, tail shown on failure",
              body && strstr(body, "LOG=\"$SRC/build/install.log\"") != NULL &&
                  strstr(body, "| tail -n 20 >&2") != NULL &&
                  strstr(body, "make -C \"$SRC\" -j\"$jobs\" z23") != NULL);
    ISH_CHECK("the script ends with the summary and contributor pointer",
              body && strstr(body, "echo \"Source:  $SRC\"") != NULL &&
                  strstr(body, "echo \"Binary:  $SRC/build/bin/z23\"") != NULL &&
                  strstr(body, "Start:   (cd") != NULL &&
                  strstr(body, "build/bin/z23 status") != NULL &&
                  strstr(body, "echo \"Next steps: https://z23.sh/start\"") != NULL &&
                  strstr(strstr(body, "echo \"Next steps:"),
                         "Want to contribute? Read $SRC/.github/"
                         "CONTRIBUTING.md, then post a claim in board room "
                         "contrib (https://z23.sh/start).") != NULL);

    return failures;
}

int test_install_sh_site(void)
{
    printf("\n=== install.sh site tests ===\n");
    int failures = 0;
    static unsigned char buf[ISH_BUF];

    /* GET: 200, the right content type, no-store, body starts with the
     * shebang, and the pin line is present with SOME value (build_commit
     * may be the display-only "external", in which case the placeholder
     * is served empty — either way the line survives substitution). */
    size_t n = install_sh_handle_request("GET", "/install.sh", NULL, 0,
                                         buf, sizeof(buf));
    ISH_CHECK("GET returns a non-empty response", n > 0);
    const char *resp = (const char *)buf;
    ISH_CHECK("GET is 200 OK",
              n > 0 && strstr(resp, "HTTP/1.1 200 OK\r\n") == resp);
    ISH_CHECK("Content-Type is text/x-shellscript",
              strstr(resp, "Content-Type: text/x-shellscript; "
                           "charset=utf-8\r\n") != NULL);
    ISH_CHECK("Cache-Control: no-store",
              strstr(resp, "Cache-Control: no-store\r\n") != NULL);
    const char *body = strstr(resp, "\r\n\r\n");
    ISH_CHECK("headers end with a blank line", body != NULL);
    if (body) body += 4;
    ISH_CHECK("body starts with the POSIX shebang",
              body && strncmp(body, "#!/bin/sh\n", 10) == 0);
    ISH_CHECK("the pin placeholder was substituted (no literal "
              "__Z23_PIN__ remains)",
              body && strstr(body, "__Z23_PIN__") == NULL);
    ISH_CHECK("the Z23_PIN= assignment line survived substitution",
              body && strstr(body, "Z23_PIN=\"") != NULL);
    failures += ish_script_steps(body);
    failures += ish_script_log_and_summary(body);
    failures += ish_script_real_run(body);

    /* HEAD: same headers, no body. */
    size_t head_n = install_sh_handle_request("HEAD", "/install.sh", NULL, 0,
                                              buf, sizeof(buf));
    ISH_CHECK("HEAD returns headers only",
              head_n > 0 && head_n < n && memcmp(buf, resp, head_n) == 0);
    ISH_CHECK("HEAD carries no body after the blank line",
              head_n > 0 &&
                  (const char *)buf + head_n ==
                      strstr((const char *)buf, "\r\n\r\n") + 4);

    /* POST: refused. onion PLAIN dispatch forwards every method with no
     * check of its own, so this handler's own 405 is the only gate on
     * that listener (the HTTPS listener already 405s non-GET/HEAD before
     * dispatch ever reaches here). */
    size_t post_n = install_sh_handle_request("POST", "/install.sh",
                                              (const uint8_t *)"x", 1,
                                              buf, sizeof(buf));
    ISH_CHECK("POST is refused with 405",
              post_n > 0 &&
                  strstr((const char *)buf,
                         "HTTP/1.1 405 Method Not Allowed\r\n") ==
                      (const char *)buf);

    /* Root short-circuit: a piped script client with no Accept: text/html
     * gets the script instead of the redirect; a browser never does. */
    ISH_CHECK("curl UA with no Accept wants the install script",
              https_root_wants_install_script_for_testing("curl/8.0", ""));
    ISH_CHECK("Wget UA with no Accept wants the install script",
              https_root_wants_install_script_for_testing("Wget/1.21.3", ""));
    ISH_CHECK("curl UA that explicitly accepts text/html stays "
              "a browsing request",
              !https_root_wants_install_script_for_testing("curl/8.0",
                                                            "text/html"));
    ISH_CHECK("a browser UA never gets the install script",
              !https_root_wants_install_script_for_testing(
                  "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 "
                  "Firefox/128.0",
                  "text/html,application/xhtml+xml"));
    ISH_CHECK("no User-Agent at all stays a browsing request",
              !https_root_wants_install_script_for_testing(NULL, NULL));

    failures += ish_front_paths();

    return failures;
}
