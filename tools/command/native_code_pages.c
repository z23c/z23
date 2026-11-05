/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: Resolve a module's exact committed tree without trusting the live overlay. */
#include "native_code_pages.h"
#include "util/spawn.h"
#include <stddef.h>
#include <string.h>

static bool page_oid(const char *s, size_t n)
{
    if (n != 40 && n != 64) return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static bool page_directory(const char *s)
{
    if (!s || !s[0] || strlen(s) > 512 || s[0] == '/') return false;
    const char *component = s;
    for (const char *p = s;; p++) {
        char c = *p;
        if (c == '/' || c == '\0') {
            size_t n = (size_t)(p - component);
            if (!n || (n == 1 && component[0] == '.') ||
                (n == 2 && component[0] == '.' && component[1] == '.')) return false;
            if (!c) return true;
            component = p + 1;
        } else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) {
            return false;
        }
    }
}

static bool page_capture(const char *const argv[], char *out, size_t cap, size_t *len)
{
    struct zcl_spawn_binary_observation observation = {0};
    struct zcl_result result = zcl_spawn_capture_binary(argv, out, cap, 10000, &observation);
    if (!result.ok) return false;
    *len = observation.output_len;
    return true;
}

bool zcl_code_pages_subject(const char *repo, const char *commit,
                            const char *directory, char tree[65])
{
    if (tree) tree[0] = '\0';
    if (!repo || !repo[0] || !commit || !tree || !page_directory(directory)) return false;
    size_t oid_len = strlen(commit);
    if (!page_oid(commit, oid_len)) return false;
    const char *type_argv[] = {"/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
        "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
        "GIT_ALLOW_PROTOCOL=", "GIT_OPTIONAL_LOCKS=0", "git", "--no-replace-objects",
        "-c", "protocol.allow=never", "-C", repo, "cat-file", "-t", commit, NULL};
    char out[768];
    size_t n = 0;
    if (!page_capture(type_argv, out, sizeof(out), &n) || n != 7 || memcmp(out, "commit\n", 7))
        return false;
    const char *tree_argv[] = {"/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
        "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
        "GIT_ALLOW_PROTOCOL=", "GIT_OPTIONAL_LOCKS=0", "git", "--no-replace-objects",
        "-c", "protocol.allow=never", "-C", repo, "ls-tree", "--full-tree", "-z",
        commit, "--", directory, NULL};
    size_t prefix = sizeof("040000 tree ") - 1, path_len = strlen(directory);
    if (!page_capture(tree_argv, out, sizeof(out), &n) ||
        n != prefix + oid_len + 1 + path_len + 1 ||
        memcmp(out, "040000 tree ", prefix) || !page_oid(out + prefix, oid_len) ||
        out[prefix + oid_len] != '\t' ||
        memcmp(out + prefix + oid_len + 1, directory, path_len) || out[n - 1] != '\0')
        return false;
    memcpy(tree, out + prefix, oid_len);
    tree[oid_len] = '\0';
    return true;
}
