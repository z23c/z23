/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * Native agent metadata traversal against fixture-owned files only. */
#if defined(_WIN32)
#include "command/native_fleet_objectives.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define REQUIRE(expr) do { if (!(expr)) { \
    fprintf(stderr, "agent_lanes: line %d: %s\n", __LINE__, #expr); return 1; \
} } while (0)

static bool fixture_meta(const char *root, const char *name, const char *label,
                          bool oversized)
{
    char path[1024];
    int n = snprintf(path, sizeof path, "%s/%s", root, name);
    if (n < 0 || n >= (int)sizeof path) return false;
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fprintf(f, "{\"description\":\"%s\"}", label) > 0;
    if (oversized)
        ok = ok && fseek(f, 65536, SEEK_SET) == 0 && fputc(' ', f) != EOF;
    return fclose(f) == 0 && ok;
}

int main(void)
{
    char temp[MAX_PATH], root[MAX_PATH], nested[1024], hidden[1024], path[1024];
    REQUIRE(GetTempPathA(sizeof temp, temp));
    REQUIRE(GetTempFileNameA(temp, "zla", 0, root));
    REQUIRE(DeleteFileA(root) && CreateDirectoryA(root, NULL));
    REQUIRE(snprintf(nested, sizeof nested, "%s/subagents", root) > 0);
    REQUIRE(CreateDirectoryA(nested, NULL));
    REQUIRE(snprintf(hidden, sizeof hidden, "%s/.hidden", root) > 0);
    REQUIRE(CreateDirectoryA(hidden, NULL));
    REQUIRE(fixture_meta(root, "agent-writer.meta.json", "write:alpha", false));
    REQUIRE(fixture_meta(nested, "agent-reviewer.meta.json", "review2:beta", false));
    REQUIRE(fixture_meta(root, "agent-research.meta.json", "general research", false));
    REQUIRE(fixture_meta(root, "agent-large.meta.json", "fix:oversized", true));
    REQUIRE(fixture_meta(hidden, "agent-hidden.meta.json", "write:hidden", false));
    REQUIRE(_putenv_s("Z23_AGENT_META_ROOT", root) == 0);
    struct zcl_agent_index ix;
    REQUIRE(zcl_objectives_agent_index_build(&ix));
    REQUIRE(ix.n == 2 && ix.files == 3 && !ix.capped && !ix.oom);
    REQUIRE(zcl_objectives_agent_lane(&ix, "writer") != NULL);
    REQUIRE(zcl_objectives_agent_kind(&ix, "writer") != NULL);
    REQUIRE(zcl_objectives_agent_lane(&ix, "reviewer") != NULL);
    REQUIRE(zcl_objectives_agent_kind(&ix, "reviewer") != NULL);
    REQUIRE(!strcmp(zcl_objectives_agent_lane(&ix, "writer"), "alpha"));
    REQUIRE(!strcmp(zcl_objectives_agent_kind(&ix, "writer"), "write"));
    REQUIRE(!strcmp(zcl_objectives_agent_lane(&ix, "reviewer"), "beta"));
    REQUIRE(!strcmp(zcl_objectives_agent_kind(&ix, "reviewer"), "review2"));
    REQUIRE(zcl_objectives_agent_lane(&ix, "large") == NULL);
    REQUIRE(zcl_objectives_agent_lane(&ix, "research") == NULL);
    REQUIRE(zcl_objectives_agent_lane(&ix, "hidden") == NULL);
    zcl_objectives_agent_index_free(&ix);
    REQUIRE(_putenv_s("Z23_AGENT_META_ROOT", hidden) == 0);
    REQUIRE(zcl_objectives_agent_index_build(&ix));
    REQUIRE(ix.n == 1 && ix.files == 1 && !ix.capped && !ix.oom);
    REQUIRE(zcl_objectives_agent_lane(&ix, "hidden") != NULL);
    REQUIRE(!strcmp(zcl_objectives_agent_lane(&ix, "hidden"), "hidden"));
    zcl_objectives_agent_index_free(&ix);
    REQUIRE(_putenv_s("Z23_AGENT_META_ROOT", root) == 0);
    const char *names[] = {"agent-writer.meta.json", "agent-research.meta.json",
                          "agent-large.meta.json", ".hidden/agent-hidden.meta.json",
                          "subagents/agent-reviewer.meta.json"};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; ++i) {
        REQUIRE(snprintf(path, sizeof path, "%s/%s", root, names[i]) > 0);
        REQUIRE(DeleteFileA(path));
    }
    REQUIRE(RemoveDirectoryA(hidden) && RemoveDirectoryA(nested) &&
            RemoveDirectoryA(root));
    REQUIRE(zcl_objectives_agent_index_build(&ix));
    REQUIRE(ix.n == 0 && ix.files == 0 && !ix.oom);
    zcl_objectives_agent_index_free(&ix);
    puts("agent_lanes_windows_acceptance: PASS");
    return 0;
}
#else
typedef int agent_lanes_windows_acceptance_not_built;
#endif
