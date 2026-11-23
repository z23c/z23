/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: z23-wallet entry point: UTF-8 arguments (GetCommandLineW on
 * Windows), the owner-at-keyboard refusal for agent sessions, and exit
 * codes. 0 ok, 2 bad arguments, 3 window or backend unavailable, 4 shot
 * failed, 5 agent session refused. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zw.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>

/* Output of --help/--version goes to the parent console when there is one;
 * the program itself has no console window. */
static void attach_console(void)
{
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE *f;
        f = freopen("CONOUT$", "w", stdout);
        f = freopen("CONOUT$", "w", stderr);
        (void)f;
    }
}

static char **utf8_argv(int *argc)
{
    int n = 0;
    wchar_t **w = CommandLineToArgvW(GetCommandLineW(), &n);
    if (!w) return NULL;
    char **v = calloc((size_t)n + 1, sizeof(*v));
    for (int i = 0; v && i < n; i++) {
        int len = WideCharToMultiByte(CP_UTF8, 0, w[i], -1, NULL, 0, NULL, NULL);
        v[i] = len > 0 ? malloc((size_t)len) : NULL;
        if (!v[i] || WideCharToMultiByte(CP_UTF8, 0, w[i], -1, v[i], len, NULL, NULL) <= 0) {
            v = NULL;
            break;
        }
    }
    LocalFree(w);
    *argc = n;
    return v;
}
#endif

int main(int argc, char **argv)
{
#if defined(_WIN32)
    attach_console();
    int wargc = 0;
    char **uv = utf8_argv(&wargc);
    if (uv) { argc = wargc; argv = uv; }
#endif
    if (getenv("ZCL_AGENT_SESSION")) {
        fprintf(stderr, "z23-wallet is for the owner at the keyboard; agent sessions use z23 core commands\n");
        return 5;
    }
    struct zw_options o;
    char err[160];
    if (!zw_args_parse(argc, argv, &o, err, sizeof(err))) {
        fprintf(stderr, "z23-wallet: %s\n", err);
        return 2;
    }
    if (o.help) { fputs(zw_args_help(), stdout); return 0; }
    if (o.version) { puts("z23-wallet 0.1 (milestone 1: Connect, Home, Node)"); return 0; }
    zw_log_open(o.log);
    int rc = zw_app_run(&o);
    zw_log_close();
    return rc;
}
