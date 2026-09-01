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

static bool print_one(const uint8_t *key, size_t key_len, void *value, void *ctx)
{
    (void)ctx;
    printf("%.*s=%s\n", (int)key_len, (const char *)key, (const char *)value);
    return true;
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

    if (argc < 2) {
        fprintf(stderr, "usage: ztrie <text>...   (routes from stdin: prefix=value)\n");
        ztrie_destroy(t);
        return 2;
    }
    if (strcmp(argv[1], "list") == 0) {
        const char *pfx = argc > 2 ? argv[2] : "";
        ztrie_foreach_prefix(t, pfx, strlen(pfx), print_one, NULL);
        ztrie_destroy(t);
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        size_t ml = 0;
        const char *v = ztrie_longest_prefix(t, argv[i], strlen(argv[i]), &ml);
        printf("%s -> %s\n", argv[i], v ? v : "(no match)");
    }
    ztrie_destroy(t);
    return 0;
}
