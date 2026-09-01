/* zintern CLI: deduplicate lines, emit each distinct line once with
 * its stable id.
 *
 *   zintern < input.txt        prints "<id>\t<line>" per distinct line
 *   zintern -q <word>...       print the id each word would get
 */
#include "zintern/zintern.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    zintern *p = zintern_create((zintern_alloc){0});
    if (!p) {
        fprintf(stderr, "zintern: out of memory\n");
        return 2;
    }
    if (argc > 1 && strcmp(argv[1], "-q") == 0) {
        for (int i = 2; i < argc; i++) {
            uint32_t id = zintern_put(p, argv[i], strlen(argv[i]));
            if (id == UINT32_MAX) {
                fprintf(stderr, "zintern: out of memory\n");
                zintern_destroy(p);
                return 2;
            }
            printf("%u\t%s\n", id, argv[i]);
        }
        zintern_destroy(p);
        return 0;
    }
    char line[4096];
    while (fgets(line, sizeof line, stdin)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) n--;
        uint32_t id = zintern_put(p, line, n);
        if (id == UINT32_MAX) {
            fprintf(stderr, "zintern: out of memory\n");
            zintern_destroy(p);
            return 2;
        }
        printf("%u\t%.*s\n", id, (int)n, line);
    }
    zintern_destroy(p);
    return 0;
}
