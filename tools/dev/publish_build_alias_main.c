/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host publisher Make execs in place of publish-build-alias.sh.
 *          The session tool is the one beside this checkout's tools/dev. */

#include "publish_build_alias.h"

#include "platform/os_proc.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if !defined(_WIN32)
static int pba_session_from_exe(char *out, size_t cap)
{
    char exe[PATH_MAX];
    int i;
    if (!os_proc_exe_path(exe, sizeof exe))
        return -1;
    for (i = 0; i < 3; i++) {
        char *slash = strrchr(exe, '/');
        if (!slash)
            return -1;
        *slash = '\0';
    }
    if (snprintf(out, cap, "%s/tools/dev/build-epoch-session.sh", exe) >=
        (int)cap)
        return -1;
    return 0;
}
#endif

int main(int argc, char **argv)
{
#if defined(_WIN32)
    (void)argc;
    (void)argv;
    fprintf(stderr,
            "publish-build-alias: Windows alias publication is unavailable\n");
    return 2;
#else
    struct zcl_publish_alias req;
    char session[PATH_MAX];
    if (argc != 14 && argc != 15) {
        fprintf(stderr,
                "publish-build-alias: usage: publish-build-alias CANDIDATE "
                "ALIAS SESSION SOURCE COMPLETE MUTATION EPOCH COMPILER_ID "
                "PROFILE COMPILE_FLAGS LINK_FLAGS CC CXX [VERIFY_TOOL]\n");
        return 2;
    }
    if (pba_session_from_exe(session, sizeof session) != 0) {
        fprintf(stderr,
                "publish-build-alias: epoch verifier is not executable\n");
        return 2;
    }
    memset(&req, 0, sizeof req);
    req.candidate = argv[1];
    req.alias = argv[2];
    req.session = argv[3];
    req.source_id = argv[4];
    req.complete = argv[5];
    req.mutation = argv[6];
    req.epoch = argv[7];
    req.compiler_id = argv[8];
    req.profile = argv[9];
    req.compile_flags = argv[10];
    req.link_flags = argv[11];
    req.cc = argv[12];
    req.cxx = argv[13];
    req.verify_tool = argc == 15 ? argv[14] : NULL;
    req.session_tool = session;
    req.err_fd = STDERR_FILENO;
    return zcl_publish_build_alias(&req);
#endif
}
