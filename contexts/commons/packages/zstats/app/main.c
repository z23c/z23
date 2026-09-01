/* zstats CLI: streaming statistics over numbers from stdin or args.
 *
 *   zstats [n]...          reads doubles; prints n, min, max, mean,
 *                          stddev (population), total
 */
#include "zstats/zstats.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    zstats s;
    zstats_init(&s);

    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            char *end = NULL;
            double v = strtod(argv[i], &end);
            if (!end || *end != '\0') {
                fprintf(stderr, "zstats: bad number %s\n", argv[i]);
                return 2;
            }
            zstats_add(&s, v);
        }
    } else {
        double v;
        while (scanf("%lf", &v) == 1)
            zstats_add(&s, v);
    }

    printf("n      %llu\n", (unsigned long long)zstats_count(&s));
    printf("min    %.17g\n", zstats_min(&s));
    printf("max    %.17g\n", zstats_max(&s));
    printf("mean   %.17g\n", zstats_mean(&s));
    printf("stddev %.17g\n", zstats_stddev(&s));
    printf("total  %.17Lg\n", zstats_total(&s));
    return 0;
}
