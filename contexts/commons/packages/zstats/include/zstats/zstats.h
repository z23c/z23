/* zstats — streaming statistics (C23).
 *
 * Welford online mean/variance, min/max, exact integer sums, and
 * merge of partial accumulators (Chan's parallel algorithm). No
 * allocation, fully deterministic, no wall clock.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZSTATS_H
#define ZSTATS_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t n;
    double   mean;
    double   m2;       /* sum of squared deviations from the mean */
    double   min;
    double   max;
    long double sum;   /* exact-ish running sum for total() */
} zstats;

void zstats_init(zstats *s);

/* Add one sample. */
void zstats_add(zstats *s, double x);

/* Add the same sample k times (k==0 is a no-op). */
void zstats_add_repeated(zstats *s, double x, uint64_t k);

/* Merge another accumulator into s (Chan's algorithm). */
void zstats_merge(zstats *s, const zstats *other);

uint64_t zstats_count(const zstats *s);
double   zstats_mean(const zstats *s);      /* 0 when empty */
double   zstats_variance(const zstats *s);  /* population, 0 when empty */
double   zstats_sample_variance(const zstats *s); /* n-1, 0 when n<2 */
double   zstats_stddev(const zstats *s);    /* population */
double   zstats_min(const zstats *s);       /* 0 when empty */
double   zstats_max(const zstats *s);       /* 0 when empty */
long double zstats_total(const zstats *s);  /* 0 when empty */

#ifdef __cplusplus
}
#endif

#endif /* ZSTATS_H */
