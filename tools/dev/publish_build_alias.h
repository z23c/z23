/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Publish one compile-epoch candidate onto a build/bin alias.
 *          The session stamp is checked before the copy. Source authority
 *          is verified again immediately before the atomic rename. */

#ifndef ZCL_PUBLISH_BUILD_ALIAS_H
#define ZCL_PUBLISH_BUILD_ALIAS_H

struct zcl_publish_alias {
    const char *candidate;
    const char *alias;
    const char *session;
    const char *source_id;
    const char *complete;
    const char *mutation;
    const char *epoch;
    const char *compiler_id;
    const char *profile;
    const char *compile_flags;
    const char *link_flags;
    const char *cc;
    const char *cxx;
    const char *verify_tool;  /* NULL selects tools/dev/source-identity.sh */
    const char *session_tool; /* build-epoch-session.sh */
    int err_fd;               /* < 0 writes refusals to stderr */
};

/* 0 when the alias is the candidate. 2 on a publisher refusal.
 * The session tool's own status when check or verify fails.
 * The success line is written to stdout. */
int zcl_publish_build_alias(const struct zcl_publish_alias *req);

#endif
