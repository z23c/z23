/* ztemplate CLI: render a {{var}} template against k=v pairs.
 *
 *   ztemplate -t <template> [name=value]...
 *   ztemplate [name=value]... < template      (template from stdin)
 *
 * Example:
 *   ztemplate -t 'Hello {{name}}!' name=Ada
 */
#include "ztemplate/ztemplate.h"

#include <stdio.h>
#include <string.h>

struct binding { char *name; char *value; };

static bool lookup(const char *name, size_t name_len,
                   const char **value, size_t *value_len, void *ctx)
{
    const struct binding *bs = ctx;
    for (size_t i = 0; bs[i].name; i++) {
        if (strlen(bs[i].name) == name_len &&
            memcmp(bs[i].name, name, name_len) == 0) {
            *value = bs[i].value;
            *value_len = strlen(bs[i].value);
            return true;
        }
    }
    return false;
}

int main(int argc, char **argv)
{
    static char tmpl[65536];
    size_t tlen = 0;
    int arg0 = 1;

    if (argc > 2 && strcmp(argv[1], "-t") == 0) {
        tlen = strlen(argv[2]);
        if (tlen >= sizeof tmpl) {
            fprintf(stderr, "ztemplate: template too long\n");
            return 2;
        }
        memcpy(tmpl, argv[2], tlen);
        arg0 = 3;
    } else {
        while (tlen < sizeof tmpl - 1) {
            size_t r = fread(tmpl + tlen, 1, sizeof tmpl - 1 - tlen, stdin);
            if (r == 0) break;
            tlen += r;
        }
    }

    size_t err = 0;
    ztemplate *tp = ztemplate_parse(tmpl, tlen, &err);
    if (!tp) {
        fprintf(stderr, "ztemplate: parse error at byte %zu\n", err);
        return 2;
    }

    static struct binding bs[256];
    int nb = 0;
    for (int i = arg0; i < argc && nb < 255; i++) {
        char *eq = strchr(argv[i], '=');
        if (!eq) {
            fprintf(stderr, "ztemplate: bad binding %s (want name=value)\n",
                    argv[i]);
            ztemplate_free(tp);
            return 2;
        }
        *eq = '\0';
        bs[nb].name = argv[i];
        bs[nb].value = eq + 1;
        nb++;
    }
    bs[nb].name = NULL;
    bs[nb].value = NULL;

    size_t need = 0;
    ztemplate_render(tp, lookup, bs, NULL, 0, &need);
    static char out[1 << 20];
    if (need >= sizeof out) {
        fprintf(stderr, "ztemplate: rendered output too long (%zu)\n", need);
        ztemplate_free(tp);
        return 2;
    }
    size_t n = 0;
    ztemplate_status st = ztemplate_render(tp, lookup, bs, out, sizeof out, &n);
    if (st != ZTEMPLATE_OK) {
        fprintf(stderr, "ztemplate: render failed (%d) — unknown variable?\n",
                (int)st);
        ztemplate_free(tp);
        return 1;
    }
    fwrite(out, 1, n, stdout);
    ztemplate_free(tp);
    return 0;
}
