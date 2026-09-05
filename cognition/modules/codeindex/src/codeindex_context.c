/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * purpose: Derive one bounded context and one architectural shape from a source path. */

#include "codeindex/codeindex_context.h"

#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

struct ci_module_context {
    const char *module;
    const char *context;
};

static const char *const k_contexts[] = {
    "wallet", "explorer", "naming", "messaging", "market",
    "commons", "cognition", "engine", "core", "platform",
};

/* Module ownership is the smallest stable taxonomy for lib/: module names are
 * already the build/link units. File-name feature matches may refine a file
 * and expose the module/file disagreement as an overlap. */
static const struct ci_module_context k_modules[] = {
    {"astro", "platform"}, {"base", "platform"}, {"bloom", "core"},
    {"chain", "core"}, {"chainlog", "engine"}, {"codec", "platform"},
    {"codeindex", "cognition"}, {"coins", "core"},
    {"commons_demo", "commons"}, {"core", "core"},
    {"crypto", "core"}, {"crypto_registry", "core"},
    {"determinism", "engine"}, {"encoding", "platform"},
    {"engine", "engine"}, {"event", "engine"},
    {"fingerprint", "cognition"}, {"fleetfacts", "cognition"}, {"fleetledger", "engine"},
    {"framework", "engine"},
    {"health", "engine"}, {"hotswap", "engine"},
    {"install", "platform"}, {"json", "platform"},
    {"kernel", "engine"}, {"keys", "wallet"}, {"kpi", "cognition"},
    {"metaverse", "commons"}, {"metrics", "engine"},
    {"mining", "core"}, {"net", "core"}, {"noise", "core"},
    {"ontology", "cognition"}, {"overlay", "engine"},
    {"platform", "platform"}, {"policy", "core"},
    {"presentation", "explorer"}, {"primitives", "core"},
    {"receipt", "engine"}, {"retrieval", "cognition"},
    {"rpc", "engine"}, {"sapling", "core"}, {"science", "cognition"},
    {"script", "core"}, {"session", "cognition"}, {"sha3", "platform"},
    {"sim", "engine"}, {"storage", "engine"}, {"support", "platform"},
    {"sync", "core"}, {"territory", "cognition"}, {"util", "platform"},
    {"validation", "core"}, {"vcs", "commons"}, {"wallet", "wallet"},
    {"zanc", "commons"}, {"zdir", "naming"}, {"zid", "wallet"},
    {"znam", "naming"}, {"zslp", "market"}, {"zswap", "market"},
};

static bool starts(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static bool path_segment(const char *path, const char *segment)
{
    size_t n = strlen(segment);
    const char *p = path;
    while ((p = strstr(p, segment)) != NULL) {
        bool left = p == path || p[-1] == '/';
        bool right = p[n] == '\0' || p[n] == '/';
        if (left && right) return true;
        p++;
    }
    return false;
}

static void add_match(struct ci_context_assignment *out, const char *context)
{
    for (size_t i = 0; i < out->match_count; i++)
        if (strcmp(out->matches[i], context) == 0) return;
    if (out->match_count >= CI_CONTEXT_MATCH_CAP) return;
    (void)snprintf(out->matches[out->match_count],
                   sizeof(out->matches[out->match_count]), "%s", context);
    out->match_count++;
}

static const char *module_context(const char *path)
{
    const char *marker = strstr(path, "/modules/");
    if (!marker) return NULL;
    const char *p = marker + strlen("/modules/");
    const char *slash = strchr(p, '/');
    if (!slash) return NULL;
    size_t n = (size_t)(slash - p);
    for (size_t i = 0; i < sizeof(k_modules) / sizeof(k_modules[0]); i++)
        if (strlen(k_modules[i].module) == n &&
            strncmp(p, k_modules[i].module, n) == 0)
            return k_modules[i].context;
    return NULL;
}

static const char *path_context(const char *path)
{
    if (starts(path, "contexts/")) {
        const char *name = path + strlen("contexts/");
        const char *slash = strchr(name, '/');
        if (!slash) return NULL;
        size_t length = (size_t)(slash - name);
        for (size_t i = 0; i < 6; i++)
            if (length == strlen(k_contexts[i]) &&
                strncmp(name, k_contexts[i], length) == 0)
                return k_contexts[i];
        return NULL;
    }
    if (starts(path, "core/")) return "core";
    if (starts(path, "engine/")) return "engine";
    if (starts(path, "cognition/")) return "cognition";
    if (starts(path, "platform/") || starts(path, "tools/"))
        return "platform";
    return NULL;
}

static void classify_shape(const char *path, char out[CI_CONTEXT_SHAPE_MAX])
{
    const char *p = NULL;
    if (starts(path, "contexts/")) {
        p = strchr(path + strlen("contexts/"), '/');
        if (p) p++;
    } else if (starts(path, "tools/")) {
        (void)snprintf(out, CI_CONTEXT_SHAPE_MAX, "tool");
        return;
    } else {
        p = strchr(path, '/');
        if (p) p++;
    }
    if (!p || !*p) {
        (void)snprintf(out, CI_CONTEXT_SHAPE_MAX, "orphan");
        return;
    }
    const char *slash = strchr(p, '/');
    size_t length = slash ? (size_t)(slash - p) : strlen(p);
    if (length == 0 || length >= CI_CONTEXT_SHAPE_MAX) {
        (void)snprintf(out, CI_CONTEXT_SHAPE_MAX, "orphan");
        return;
    }
    (void)snprintf(out, CI_CONTEXT_SHAPE_MAX, "%.*s", (int)length, p);
}

const char *const *codeindex_context_names(size_t *count)
{
    if (count) *count = sizeof(k_contexts) / sizeof(k_contexts[0]);
    return k_contexts;
}

bool codeindex_module_group_path(const char *module, char out[64])
{
    if (!module || !module[0] || !out) return false;
    for (size_t i = 0; i < sizeof(k_modules) / sizeof(k_modules[0]); i++) {
        if (strcmp(k_modules[i].module, module) != 0) continue;
        if (strcmp(k_modules[i].context, "wallet") == 0 ||
            strcmp(k_modules[i].context, "explorer") == 0 ||
            strcmp(k_modules[i].context, "naming") == 0 ||
            strcmp(k_modules[i].context, "messaging") == 0 ||
            strcmp(k_modules[i].context, "market") == 0 ||
            strcmp(k_modules[i].context, "commons") == 0)
            (void)snprintf(out, 64, "contexts/%s/modules/%s",
                           k_modules[i].context, module);
        else
            (void)snprintf(out, 64, "%s/modules/%s",
                           k_modules[i].context, module);
        return true;
    }
    out[0] = '\0';
    return false;
}

bool codeindex_path_is_production(const char *path)
{
    if (!path || !path[0]) return false;
    if (starts(path, "tests/harness/include/test/") || starts(path, "tests/") ||
        path_segment(path, "tests") || path_segment(path, "test") ||
        path_segment(path, "examples"))
        return false;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return strncmp(base, "test_", 5) != 0 && strstr(base, "_test.") == NULL;
}

bool codeindex_context_classify(const char *path,
                                struct ci_context_assignment *out)
{
    if (!path || !out) return false;
    memset(out, 0, sizeof(*out));
    out->production = codeindex_path_is_production(path);
    classify_shape(path, out->shape);
    const char *authority = path_context(path);
    if (authority) add_match(out, authority);
    const char *module = module_context(path);
    if (module && (!authority || strcmp(module, authority) != 0))
        add_match(out, module);
    (void)snprintf(out->basis, sizeof(out->basis), "%s",
                   module ? "path_authority+module_manifest" :
                            "path_authority");

    out->orphan = out->match_count == 0 || strcmp(out->shape, "orphan") == 0;
    out->overlap = out->match_count > 1;
    if (!out->orphan)
        (void)snprintf(out->context, sizeof(out->context), "%s",
                       out->matches[0]);
    else {
        (void)snprintf(out->shape, sizeof(out->shape), "orphan");
        (void)snprintf(out->basis, sizeof(out->basis),
                       "unclassified_architecture_path");
    }
    return true;
}

static void digest_string(struct sha3_256_ctx *digest, const char *value)
{
    sha3_256_write(digest, (const unsigned char *)value, strlen(value) + 1);
}

bool codeindex_context_assignment_digest(
    const char *path, const struct ci_context_assignment *assignment,
    uint8_t out[32])
{
    if (!path || !assignment || !out ||
        assignment->match_count > CI_CONTEXT_MATCH_CAP)
        return false;
    struct sha3_256_ctx digest;
    sha3_256_init(&digest);
    digest_string(&digest, "zcl.code_context_assignment.v1");
    digest_string(&digest, path);
    digest_string(&digest, assignment->context);
    digest_string(&digest, assignment->shape);
    digest_string(&digest, assignment->basis);
    uint8_t flags[] = {
        assignment->production ? 1 : 0,
        assignment->orphan ? 1 : 0,
        assignment->overlap ? 1 : 0,
        (uint8_t)assignment->match_count,
    };
    sha3_256_write(&digest, flags, sizeof(flags));
    for (size_t i = 0; i < assignment->match_count; i++)
        digest_string(&digest, assignment->matches[i]);
    sha3_256_finalize(&digest, out);
    return true;
}
