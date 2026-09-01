/* zrate CLI: simulate a token bucket over a synthetic timeline.
 *
 *   zrate bucket <capacity> <rate_per_sec> <t_ms:n>...
 *       At each timestamp t try to take n tokens; prints ok/deny.
 *   zrate window <limit> <interval_ms> <t_ms>...
 *       Hit a sliding-window counter at each timestamp; prints ok/deny.
 */
#include "zrate/zrate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int usage(void)
{
    fprintf(stderr,
        "usage: zrate bucket <capacity> <rate/s> <t_ms:n>...\n"
        "       zrate window <limit> <interval_ms> <t_ms>...\n");
    return 2;
}

int main(int argc, char **argv)
{
    if (argc < 4) return usage();

    if (strcmp(argv[1], "bucket") == 0) {
        double cap = strtod(argv[2], NULL);
        double rate = strtod(argv[3], NULL);
        zrate_bucket b;
        zrate_bucket_init(&b, cap, rate, 0);
        int denied = 0;
        for (int i = 4; i < argc; i++) {
            char *colon = strchr(argv[i], ':');
            if (!colon) { fprintf(stderr, "zrate: bad event\n"); return 2; }
            uint64_t t = strtoull(argv[i], NULL, 10);
            double n = strtod(colon + 1, NULL);
            if (zrate_bucket_take(&b, n, t)) {
                printf("%llu ok (left %.3f)\n", (unsigned long long)t,
                       zrate_bucket_peek(&b, t));
            } else {
                printf("%llu deny (wait %llu ms)\n", (unsigned long long)t,
                       (unsigned long long)zrate_bucket_wait_ms(&b, n, t));
                denied++;
            }
        }
        return denied > 0 ? 1 : 0;
    }

    if (strcmp(argv[1], "window") == 0) {
        uint32_t limit = (uint32_t)strtoul(argv[2], NULL, 10);
        uint64_t interval = strtoull(argv[3], NULL, 10);
        if (limit == 0 || limit > 1024) return usage();
        uint64_t events[1024];
        zrate_window w;
        zrate_window_init(&w, events, limit, interval);
        int denied = 0;
        for (int i = 4; i < argc; i++) {
            uint64_t t = strtoull(argv[i], NULL, 10);
            if (zrate_window_hit(&w, t)) {
                printf("%llu ok (%u/%u)\n", (unsigned long long)t,
                       zrate_window_count(&w, t), limit);
            } else {
                printf("%llu deny (wait %llu ms)\n", (unsigned long long)t,
                       (unsigned long long)zrate_window_wait_ms(&w, t));
                denied++;
            }
        }
        return denied > 0 ? 1 : 0;
    }

    return usage();
}
