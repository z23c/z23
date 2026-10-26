/* ztrie CLI: longest-prefix routing demo.
 *
 *   ztrie add <prefix> <value>   define a prefix route
 *   ztrie match <text>           print value of the longest matching prefix
 *   ztrie del <prefix>           remove a route
 *   ztrie list [prefix]          list routes (optionally under a prefix)
 *
 * Routes are kept in memory only; the tool runs one command per
 * invocation chain: use it interactively via a session file is out of
 * scope — the demo builds a trie from "prefix=value" lines on stdin
 * and then matches each remaining argument.
 */
#include "ztrie/ztrie.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct print_state { bool attempted, failed; };

static bool print_one(const uint8_t *key, size_t key_len, void *value, void *ctx)
{
    struct print_state *state = ctx;
    state->attempted = true;
    state->failed = printf("%.*s=%s\n", (int)key_len, (const char *)key,
                           (const char *)value) < 0;
    return !state->failed;
}

static int finish_output(struct print_state state)
{
    if (!state.attempted) return 0;
    if (state.failed || fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "ztrie: output write failed\n");
        return 2;
    }
    return 0;
}

static int list_routes(ztrie *t, const char *prefix)
{
    struct print_state state = {0};
    bool ok = ztrie_foreach_prefix(t, prefix, strlen(prefix), print_one, &state);
    if (!ok && !state.failed) {
        fprintf(stderr, "ztrie: route enumeration failed\n");
        return 2;
    }
    return finish_output(state);
}

static int match_routes(ztrie *t, int argc, char **argv)
{
    struct print_state state = {0};
    for (int i = 1; i < argc; i++) {
        size_t ml = 0;
        const char *v = ztrie_longest_prefix(t, argv[i], strlen(argv[i]), &ml);
        state.attempted = true;
        if (printf("%s -> %s\n", argv[i], v ? v : "(no match)") < 0)
            state.failed = true;
    }
    return finish_output(state);
}

int main(int argc, char **argv)
{
    ztrie *t = ztrie_create((ztrie_alloc){0});
    if (!t) {
        fprintf(stderr, "ztrie: out of memory\n");
        return 2;
    }

    /* Load "prefix=value" lines from stdin. */
    char line[1024];
    static char storage[4096][2][512];
    size_t n = 0;
    while (n < 4096 && fgets(line, sizeof line, stdin)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *nl = strchr(eq + 1, '\n');
        if (nl) *nl = '\0';
        size_t kl = strlen(line), vl = strlen(eq + 1);
        if (kl >= 512 || vl >= 512) continue;
        memcpy(storage[n][0], line, kl + 1);
        memcpy(storage[n][1], eq + 1, vl + 1);
        if (!ztrie_put(t, storage[n][0], kl, storage[n][1], NULL)) {
            fprintf(stderr, "ztrie: out of memory\n");
            ztrie_destroy(t);
            return 2;
        }
        n++;
    }
    if (ferror(stdin)) {
        fprintf(stderr, "ztrie: input read failed\n");
        ztrie_destroy(t);
        return 2;
    }

    if (argc < 2) {
        fprintf(stderr, "usage: ztrie <text>...   (routes from stdin: prefix=value)\n");
        ztrie_destroy(t);
        return 2;
    }
    if (strcmp(argv[1], "list") == 0) {
        const char *pfx = argc > 2 ? argv[2] : "";
        int rc = list_routes(t, pfx);
        ztrie_destroy(t);
        return rc;
    }
    int rc = match_routes(t, argc, argv);
    ztrie_destroy(t);
    return rc;
}
