/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * purpose: Derive one bounded context and one architectural shape from a source path. */

#include "codeindex/codeindex_context.h"

#include "sha3/sha3.h"

#include <ctype.h>
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
    {"fingerprint", "cognition"}, {"framework", "engine"},
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

static bool token_char(char c)
{
    return isalnum((unsigned char)c) != 0;
}

static bool path_token(const char *path, const char *token)
{
    size_t n = strlen(token);
    const char *p = path;
    while ((p = strstr(p, token)) != NULL) {
        bool left = p == path || !token_char(p[-1]);
        bool right = !token_char(p[n]);
        if (left && right) return true;
        p++;
    }
    return false;
}

static bool any_token(const char *path, const char *const *tokens, size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (path_token(path, tokens[i])) return true;
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

static void add_feature_matches(const char *path,
                                struct ci_context_assignment *out)
{
    static const char *const cognition[] = {
        "agent", "cognition", "codeindex", "dev", "fingerprint", "goal",
        "grok", "heuristic", "kpi", "ontology", "retrieval", "science",
        "story", "territory",
    };
    static const char *const wallet[] = {
        "hdchain", "keystore", "mnemonic", "vault", "wallet",
    };
    static const char *const explorer[] = {
        "dashboard", "explorer", "presentation", "site",
    };
    static const char *const naming[] = {
        "naming", "service_directory", "zdir", "znam",
    };
    static const char *const messaging[] = {"messaging", "zmsg"};
    static const char *const market[] = {
        "file_market", "market", "shop", "store_buyer", "store_seller",
        "yardsale", "zslp", "zswap",
    };
    static const char *const commons[] = {
        "commons", "metaverse", "package", "vcs", "zanc", "zcode",
    };

    if (any_token(path, cognition, sizeof(cognition) / sizeof(cognition[0])))
        add_match(out, "cognition");
    if (any_token(path, wallet, sizeof(wallet) / sizeof(wallet[0])))
        add_match(out, "wallet");
    if (any_token(path, naming, sizeof(naming) / sizeof(naming[0])))
        add_match(out, "naming");
    if (any_token(path, messaging, sizeof(messaging) / sizeof(messaging[0])))
        add_match(out, "messaging");
    if (any_token(path, market, sizeof(market) / sizeof(market[0])))
        add_match(out, "market");
    if (any_token(path, commons, sizeof(commons) / sizeof(commons[0])))
        add_match(out, "commons");
    /* Explorer is the generic delivery surface, so a named product feature
     * wins assignment for e.g. yardsale_site_controller while both matches
     * remain visible as an overlap. */
    if (any_token(path, explorer, sizeof(explorer) / sizeof(explorer[0])))
        add_match(out, "explorer");
}

static const char *module_context(const char *path)
{
    if (!starts(path, "lib/")) return NULL;
    const char *p = path + 4;
    const char *slash = strchr(p, '/');
    if (!slash) return NULL;
    size_t n = (size_t)(slash - p);
    for (size_t i = 0; i < sizeof(k_modules) / sizeof(k_modules[0]); i++)
        if (strlen(k_modules[i].module) == n &&
            strncmp(p, k_modules[i].module, n) == 0)
            return k_modules[i].context;
    return NULL;
}

static void classify_shape(const char *path, char out[CI_CONTEXT_SHAPE_MAX])
{
    const char *shape = "orphan";
    if (starts(path, "app/")) {
        const char *p = path + 4;
        const char *slash = strchr(p, '/');
        size_t n = slash ? (size_t)(slash - p) : strlen(p);
        (void)snprintf(out, CI_CONTEXT_SHAPE_MAX, "%.*s", (int)n, p);
        return;
    }
    if (starts(path, "core/")) shape = "core";
    else if (starts(path, "domain/")) shape = "domain";
    else if (starts(path, "lib/")) shape = "library";
    else if (starts(path, "ports/")) shape = "port";
    else if (starts(path, "adapters/")) shape = "adapter";
    else if (starts(path, "config/")) shape = "composition";
    else if (starts(path, "tools/")) shape = "tool";
    else if (starts(path, "packages/")) shape = "package";
    else if (starts(path, "src/")) shape = "entry";
    else if (starts(path, "include/")) shape = "public_header";
    (void)snprintf(out, CI_CONTEXT_SHAPE_MAX, "%s", shape);
}

const char *const *codeindex_context_names(size_t *count)
{
    if (count) *count = sizeof(k_contexts) / sizeof(k_contexts[0]);
    return k_contexts;
}

bool codeindex_path_is_production(const char *path)
{
    if (!path || !path[0]) return false;
    if (starts(path, "lib/test/") || starts(path, "tests/") ||
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
    add_feature_matches(path, out);
    size_t feature_matches = out->match_count;

    const char *module = module_context(path);
    if (module) add_match(out, module);

    if (out->match_count == 0) {
        const char *fallback = NULL;
        if (starts(path, "core/")) fallback = "core";
        else if (starts(path, "domain/wallet/")) fallback = "wallet";
        else if (starts(path, "domain/encoding/")) fallback = "platform";
        else if (starts(path, "packages/")) fallback = "commons";
        else if (starts(path, "app/views/")) fallback = "explorer";
        else if (starts(path, "app/") || starts(path, "config/") ||
                 starts(path, "ports/") || starts(path, "adapters/") ||
                 starts(path, "src/")) fallback = "engine";
        else if (starts(path, "tools/") || starts(path, "include/"))
            fallback = "platform";
        if (fallback) {
            add_match(out, fallback);
            (void)snprintf(out->basis, sizeof(out->basis), "root_fallback");
        }
    } else {
        const char *basis = "feature_token";
        if (module && feature_matches == 0) basis = "module";
        else if (module) basis = "feature_token+module";
        (void)snprintf(out->basis, sizeof(out->basis), "%s", basis);
    }

    out->orphan = out->match_count == 0 || strcmp(out->shape, "orphan") == 0;
    out->overlap = out->match_count > 1;
    if (!out->orphan)
        (void)snprintf(out->context, sizeof(out->context), "%s",
                       out->matches[0]);
    else
        (void)snprintf(out->basis, sizeof(out->basis), "unclassified_root");
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
