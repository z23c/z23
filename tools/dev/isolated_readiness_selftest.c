/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive tools/scripts/isolated_node_env.sh readiness checks.
 *          The library stays; this replaces its shell selftest. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "isolated_readiness_selftest.h"

#include <stdio.h>
#include <string.h>

static int ir_fail(const char *msg)
{
    fprintf(stderr, "isolated-readiness selftest: FAIL: %s\n", msg);
    return 1;
}

#if !defined(_WIN32)
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const char *const k_ir_bad[] = {
    "{\"result\":null,\"error\":{\"code\":-28,\"message\":\"warming up\"},\"id\":123}",
    "{\"result\":0,\"error\":{\"code\":-28},\"id\":1}",
    "{\"result\":\"0\",\"error\":null}",
    "{\"result\":0,\"error\":\"null\"}",
    "{\"result\":0}",
    "{\"result\":-1,\"error\":null}",
    "{\"result\":1.5,\"error\":null}",
    "{\"result\":1e2,\"error\":null}",
    "{\"result\":true,\"error\":null}",
    "{\"result\":[],\"error\":null}",
    "{\"result\":0,\"error\":null} trailing",
    "0",
    "",
};

static const char k_ir_date[] =
    "date() {\n"
    "    if [ \"$1\" != '+%s' ]; then command date \"$@\"; return; fi\n"
    "    if [ ! -e \"$IR_FIX/date-boundary\" ]; then\n"
    "        : > \"$IR_FIX/date-boundary\"\n"
    "        printf '100\\n'\n"
    "    else\n"
    "        printf '101\\n'\n"
    "    fi\n"
    "}\n"
    "rm -f \"$IR_FIX/date-boundary\"\n";

static int ir_quote(char *out, size_t cap, const char *text)
{
    size_t i;
    size_t o = 0;
    if (text == NULL || cap < 3)
        return -1;
    out[o++] = '\'';
    for (i = 0; text[i] != '\0'; i++) {
        if (text[i] == '\'')
            return -1;
        if (o + 2 >= cap)
            return -1;
        out[o++] = text[i];
    }
    out[o++] = '\'';
    out[o] = '\0';
    return 0;
}

static int ir_write(const char *path, const char *env, const char *jsonq,
                    const char *fixture, const char *body)
{
    char qenv[PATH_MAX];
    char qjson[PATH_MAX];
    char qfix[PATH_MAX];
    FILE *fp;
    if (ir_quote(qenv, sizeof qenv, env) != 0 ||
        ir_quote(qjson, sizeof qjson, jsonq) != 0 ||
        ir_quote(qfix, sizeof qfix, fixture) != 0)
        return -1;
    fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    if (fprintf(fp,
                "#!/usr/bin/env bash\n"
                "IR_FIX=%s\n"
                "exec >\"$IR_FIX/out\" 2>\"$IR_FIX/err\"\n"
                "set -euo pipefail\n"
                "unset ZCL_MESH_PORTS_DIR || true\n"
                "export ISO_JSONQ_BIN=%s\n"
                "source %s\n"
                "ISO_DD=\"$IR_FIX\"\n"
                "ISO_PEER_PID=\n"
                "ISO_NODE_PID=\n"
                "ISO_PEER_PORT=39328\n"
                "touch \"$ISO_DD/.cookie\"\n"
                "%s\n",
                qfix, qjson, qenv, body) < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    return 0;
}

static int ir_exec(const char *script, int *status)
{
    pid_t pid = fork();
    int st = 0;
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execl("/bin/bash", "bash", script, (char *)NULL);
        _exit(127);
    }
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    if (!WIFEXITED(st))
        return -1;
    *status = WEXITSTATUS(st);
    return 0;
}

static int ir_case(const char *env, const char *jsonq, const char *fixture,
                   const char *body, int want, const char *why)
{
    char script[PATH_MAX];
    char err[PATH_MAX];
    int status = 0;
    int n = snprintf(script, sizeof script, "%s/case.sh", fixture);
    if (n < 0 || (size_t)n >= sizeof script)
        return ir_fail("script path");
    n = snprintf(err, sizeof err, "%s/err", fixture);
    if (n < 0 || (size_t)n >= sizeof err)
        return ir_fail("stderr path");
    if (ir_write(script, env, jsonq, fixture, body) != 0)
        return ir_fail("could not write the case script");
    if (ir_exec(script, &status) != 0)
        return ir_fail("could not run the case script");
    if (status != want) {
        FILE *fp = fopen(err, "r");
        char buf[1024];
        fprintf(stderr, "isolated-readiness selftest: FAIL: %s\n", why);
        if (fp != NULL) {
            while (fgets(buf, (int)sizeof buf, fp) != NULL)
                fputs(buf, stderr);
            fclose(fp);
        }
        return 1;
    }
    return 0;
}

static int ir_reject(const char *env, const char *jsonq, const char *fixture,
                     const char *reply)
{
    char q[1024];
    char body[1400];
    if (ir_quote(q, sizeof q, reply) != 0)
        return ir_fail("reply");
    if (snprintf(body, sizeof body,
                 "fixture_reply=%s\n"
                 "fixture_rpc_rc=0\n"
                 "iso_rpc() { printf '%%s\\n' \"$fixture_reply\"; "
                 "return \"$fixture_rpc_rc\"; }\n"
                 "if iso_rpc_nonnegative_result getblockcount >/dev/null; "
                 "then exit 1; fi\n"
                 "exit 0\n",
                 q) >= (int)sizeof body)
        return ir_fail("reject body");
    return ir_case(env, jsonq, fixture, body, 0, "invalid response accepted");
}

static int ir_bad_all(const char *env, const char *jsonq, const char *fixture)
{
    size_t i;
    for (i = 0; i < sizeof k_ir_bad / sizeof k_ir_bad[0]; i++) {
        if (ir_reject(env, jsonq, fixture, k_ir_bad[i]) != 0)
            return 1;
    }
    return 0;
}

static int ir_rpc(const char *env, const char *jsonq, const char *fixture,
                  const char *reply, int rpc_rc, const char *call, int want,
                  const char *why)
{
    char q[1024];
    char body[1800];
    if (ir_quote(q, sizeof q, reply) != 0)
        return ir_fail("reply");
    if (snprintf(body, sizeof body,
                 "%s"
                 "fixture_reply=%s\n"
                 "fixture_rpc_rc=%d\n"
                 "iso_rpc() { printf '%%s\\n' \"$fixture_reply\"; "
                 "return \"$fixture_rpc_rc\"; }\n"
                 "%s\n",
                 k_ir_date, q, rpc_rc, call) >= (int)sizeof body)
        return ir_fail("rpc body");
    return ir_case(env, jsonq, fixture, body, want, why);
}

static int ir_listen(const char *env, const char *jsonq, const char *fixture,
                     int probe, const char *call, int want, const char *why)
{
    char body[1600];
    if (snprintf(body, sizeof body,
                 "%s"
                 "z23_tcp_port_listening() { return %d; }\n"
                 "%s\n",
                 k_ir_date, probe, call) >= (int)sizeof body)
        return ir_fail("listen body");
    return ir_case(env, jsonq, fixture, body, want, why);
}

static int ir_init(const char *env, const char *jsonq, const char *fixture,
                   const char *probe, int want, const char *why)
{
    char body[1200];
    if (snprintf(body, sizeof body,
                 "ISO_NODE_BIN=\"$ISO_JSONQ_BIN\"\n"
                 "ISO_RPC_BIN=\"$ISO_JSONQ_BIN\"\n"
                 "%s\n"
                 "iso_init\n",
                 probe) >= (int)sizeof body)
        return ir_fail("init body");
    return ir_case(env, jsonq, fixture, body, want, why);
}

static int ir_sink_message(const char *fixture)
{
    char err[PATH_MAX];
    FILE *fp;
    char buf[2048];
    size_t used = 0;
    int n = snprintf(err, sizeof err, "%s/err", fixture);
    if (n < 0 || (size_t)n >= sizeof err)
        return ir_fail("stderr path");
    fp = fopen(err, "r");
    if (fp == NULL)
        return ir_fail("listening dead sink refused without the sink message");
    while (used + 1 < sizeof buf) {
        size_t nread = fread(buf + used, 1, sizeof buf - 1 - used, fp);
        used += nread;
        if (nread == 0)
            break;
    }
    buf[used] = '\0';
    fclose(fp);
    if (strstr(buf, "dead -connect sink port 39999 is already LISTENING") ==
        NULL)
        return ir_fail("listening dead sink refused without the sink message");
    return 0;
}

static int ir_checks_rpc(const char *env, const char *jsonq,
                           const char *fixture)
{
    if (ir_bad_all(env, jsonq, fixture) != 0)
        return 1;
    if (ir_rpc(env, jsonq, fixture,
               "{\"result\":0,\"error\":null,\"id\":1}", 0,
               "got=$(iso_rpc_nonnegative_result getblockcount)\n"
               "[ \"$got\" = 0 ]\n",
               0, "height zero refused") != 0)
        return 1;
    if (ir_rpc(env, jsonq, fixture,
               "{\"result\":0,\"error\":null,\"id\":1}", 0,
               "iso_wait_rpc_ready 1\n",
               0, "successful height zero did not become ready") != 0)
        return 1;
    if (ir_rpc(env, jsonq, fixture,
               "{\"result\":0,\"error\":null,\"id\":1}", 0,
               "if iso_wait_peer_connected 1; then exit 1; fi\nexit 0\n",
               0, "zero peers became connected") != 0)
        return 1;
    if (ir_rpc(env, jsonq, fixture,
               "{\"result\":0,\"error\":null,\"id\":1}", 1,
               "if iso_rpc_nonnegative_result getblockcount >/dev/null; "
               "then exit 1; fi\nexit 0\n",
               0, "failed RPC transport qualified through successful-looking output") != 0)
        return 1;
    if (ir_rpc(env, jsonq, fixture,
               "{\"result\":2,\"error\":null,\"id\":1}", 0,
               "iso_wait_peer_connected 1\n",
               0, "connected peers refused") != 0)
        return 1;
    return 0;
}

static int ir_checks(const char *env, const char *jsonq, const char *fixture)
{
    if (ir_checks_rpc(env, jsonq, fixture) != 0)
        return 1;
    if (ir_rpc(env, jsonq, fixture,
               "{\"result\":null,\"error\":{\"code\":-28},\"id\":123}", 0,
               "if iso_wait_rpc_ready 1; then exit 1; fi\nexit 0\n",
               0, "RPC error became ready") != 0)
        return 1;
    if (ir_rpc(env, jsonq, fixture,
               "{\"result\":null,\"error\":{\"code\":-28},\"id\":123}", 0,
               "if iso_wait_peer_connected 1; then exit 1; fi\nexit 0\n",
               0, "RPC error became connected") != 0)
        return 1;
    if (ir_listen(env, jsonq, fixture, 0, "iso_wait_peer_listen 1\n", 0,
                  "observed listener refused") != 0)
        return 1;
    if (ir_listen(env, jsonq, fixture, 2,
                  "rc=0\niso_wait_peer_listen 1 || rc=$?\n[ \"$rc\" = 2 ]\n",
                  0, "unobserved listener lost its refusal status") != 0)
        return 1;
    if (ir_listen(env, jsonq, fixture, 1,
                  "if iso_wait_peer_listen 1; then exit 1; fi\nexit 0\n",
                  0, "absent listener qualified") != 0)
        return 1;
    if (ir_rpc(env, jsonq, fixture,
               "{\"result\":0,\"error\":null,\"id\":1}", 0,
               "iso_wait_rpc_ready 1\n",
               0, "successful height zero lost at second boundary") != 0)
        return 1;
    if (ir_rpc(env, jsonq, fixture,
               "{\"result\":2,\"error\":null,\"id\":1}", 0,
               "iso_wait_peer_connected 1\n",
               0, "connected peer lost at second boundary") != 0)
        return 1;
    if (ir_listen(env, jsonq, fixture, 0, "iso_wait_peer_listen 1\n", 0,
                  "listener lost at second boundary") != 0)
        return 1;
    if (ir_init(env, jsonq, fixture,
                "z23_tcp_port_listening() { "
                "[ \"$1\" = \"$ISO_CONNECT_SINK\" ] && return 0; return 1; }",
                1, "iso_init accepted a LISTENING dead sink") != 0)
        return 1;
    if (ir_sink_message(fixture) != 0)
        return 1;
    if (ir_init(env, jsonq, fixture,
                "z23_tcp_port_listening() { return 1; }",
                0, "iso_init refused a dead sink") != 0)
        return 1;
    return 0;
}

static int ir_scratch(char *out, size_t cap)
{
    const char *tmp = getenv("TMPDIR");
    int n;
    if (tmp == NULL || tmp[0] == '\0')
        tmp = "/tmp";
    n = snprintf(out, cap, "%s/z23-readiness.XXXXXX", tmp);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return mkdtemp(out) == NULL ? -1 : 0;
}

static void ir_rm(const char *path)
{
    pid_t pid = fork();
    if (pid < 0)
        return;
    if (pid == 0) {
        execl("/bin/rm", "rm", "-rf", "--", path, (char *)NULL);
        _exit(127);
    }
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
        ;
}

static int ir_all(const char *env_sh, const char *jsonq)
{
    char fixture[PATH_MAX];
    int rc;
    if (env_sh == NULL || env_sh[0] == '\0' || jsonq == NULL || jsonq[0] == '\0')
        return ir_fail("env script or jsonq is unset");
    if (access(jsonq, X_OK) != 0) {
        fprintf(stderr, "isolated_node_env: FATAL: readiness selftest "
                        "requires make jsonq\n");
        return 1;
    }
    if (ir_scratch(fixture, sizeof fixture) != 0)
        return ir_fail("scratch");
    rc = ir_checks(env_sh, jsonq, fixture);
    ir_rm(fixture);
    if (rc != 0)
        return 1;
    printf("isolated-readiness selftest: PASS typed_rpc=true "
           "errors_refused=true portable_listener=true "
           "unobserved_refused=true dead_sink_refused=true\n");
    return 0;
}

#endif /* !_WIN32 */

int zcl_isolated_readiness_selftest(const char *env_sh, const char *jsonq)
{
#if defined(_WIN32)
    (void)env_sh;
    (void)jsonq;
    return ir_fail("unavailable on Windows");
#else
    return ir_all(env_sh, jsonq);
#endif
}
