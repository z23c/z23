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

#include <stdio.h>
#include <string.h>

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
    ISH_CHECK("the script reports each step",
              body && strstr(body, "say \"1/4 Checking tools") != NULL &&
                  strstr(body, "say \"2/4 Getting the source into $SRC") != NULL &&
                  strstr(body, "run git clone \"$REPO_URL\" \"$SRC\"") != NULL &&
                  strstr(body, "run git -C \"$SRC\" fetch origin") != NULL &&
                  strstr(body, "run git -C \"$SRC\" checkout \"$Z23_PIN\"") != NULL &&
                  strstr(body, "No commit pin was served") != NULL &&
                  strstr(body, "say \"3/4 Building (several minutes") != NULL &&
                  strstr(body, "say \"4/4 Done\"") != NULL);
    return failures;
}

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
