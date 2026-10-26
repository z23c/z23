/* zintern CLI: intern lines, emitting each input row with its stable id.
 *
 *   zintern < input.txt        prints "<id>\t<line>" per input line
 *   zintern -q <word>...       print the id each word would get
 */
#include "zintern/zintern.h"

#include <stdio.h>
#include <string.h>

struct output_state { bool attempted, failed; };

static int record_output(struct output_state *out, int result)
{
    out->attempted = true;
    out->failed = result < 0;
    return out->failed ? 2 : 0;
}

static int finish_output(const struct output_state *out, int result)
{
    if (out->attempted && (out->failed || fflush(stdout) != 0 || ferror(stdout))) {
        fprintf(stderr, "zintern: output write failed\n");
        return 2;
    }
    return result;
}

static int run_queries(zintern *p, int argc, char **argv, struct output_state *out)
{
    for (int i = 2; i < argc; i++) {
        uint32_t id = zintern_put(p, argv[i], strlen(argv[i]));
        if (id == UINT32_MAX) {
            fprintf(stderr, "zintern: out of memory\n");
            return 2;
        }
        if (record_output(out, printf("%u\t%s\n", id, argv[i]))) return 2;
    }
    return 0;
}

static int run_lines(zintern *p, struct output_state *out)
{
    char line[4096];
    while (fgets(line, sizeof line, stdin)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) n--;
        uint32_t id = zintern_put(p, line, n);
        if (id == UINT32_MAX) {
            fprintf(stderr, "zintern: out of memory\n");
            return 2;
        }
        if (record_output(out, printf("%u\t%.*s\n", id, (int)n, line))) return 2;
    }
    if (ferror(stdin)) {
        fprintf(stderr, "zintern: input read failed\n");
        return 2;
    }
    return 0;
}

int main(int argc, char **argv)
{
    zintern *p = zintern_create((zintern_alloc){0});
    if (!p) {
        fprintf(stderr, "zintern: out of memory\n");
        return 2;
    }
    struct output_state out = {0};
    int result = argc > 1 && strcmp(argv[1], "-q") == 0
        ? run_queries(p, argc, argv, &out) : run_lines(p, &out);
    zintern_destroy(p);
    return finish_output(&out, result);
}
