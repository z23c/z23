#include "zstats/zstats.h"

/* Newton iteration for sqrt: no libm dependency. Correctly rounded to
 * within 1 ulp for the ranges statistics produce. */
static double zsqrt(double x)
{
    if (x <= 0.0) return 0.0;
    /* Initial guess via bit hack, then refine. */
    union { double d; uint64_t u; } v = { x };
    v.u = (v.u >> 1) + 0x1ff7a3bea91d9b1bull;
    double y = v.d;
    for (int i = 0; i < 6; i++)
        y = 0.5 * (y + x / y);
    return y;
}

void zstats_init(zstats *s)
{
    if (!s) return;
    s->n = 0;
    s->mean = 0.0;
    s->m2 = 0.0;
    s->min = 0.0;
    s->max = 0.0;
    s->sum = 0.0L;
}

void zstats_add(zstats *s, double x)
{
    if (!s) return;
    s->n++;
    if (s->n == 1) {
        s->mean = x;
        s->min = x;
        s->max = x;
        s->m2 = 0.0;
    } else {
        double delta = x - s->mean;
        s->mean += delta / (double)s->n;
        double delta2 = x - s->mean;
        s->m2 += delta * delta2;
        if (x < s->min) s->min = x;
        if (x > s->max) s->max = x;
    }
    s->sum += (long double)x;
}

void zstats_add_repeated(zstats *s, double x, uint64_t k)
{
    if (!s || k == 0) return;
    if (k == 1 || s->n == 0) {
        /* Fast path for the first k identical samples. */
        if (s->n == 0) {
            s->n = k;
            s->mean = x;
            s->min = x;
            s->max = x;
            s->m2 = 0.0;
            s->sum = (long double)x * (long double)k;
            return;
        }
        zstats_add(s, x);
        return;
    }
    /* Merge k identical samples as a block: their internal variance is
     * zero; only the mean shift matters. */
    uint64_t new_n = s->n + k;
    double delta = x - s->mean;
    s->mean += delta * (double)k / (double)new_n;
    s->m2 += delta * delta * (double)s->n * (double)k / (double)new_n;
    s->n = new_n;
    if (x < s->min) s->min = x;
    if (x > s->max) s->max = x;
    s->sum += (long double)x * (long double)k;
}

void zstats_merge(zstats *s, const zstats *other)
{
    if (!s || !other || other->n == 0) return;
    if (s->n == 0) {
        *s = *other;
        return;
    }
    uint64_t new_n = s->n + other->n;
    double delta = other->mean - s->mean;
    s->mean = (s->mean * (double)s->n + other->mean * (double)other->n)
              / (double)new_n;
    s->m2 += other->m2
             + delta * delta * (double)s->n * (double)other->n
               / (double)new_n;
    s->n = new_n;
    if (other->min < s->min) s->min = other->min;
    if (other->max > s->max) s->max = other->max;
    s->sum += other->sum;
}

uint64_t zstats_count(const zstats *s)
{
    return s ? s->n : 0;
}

double zstats_mean(const zstats *s)
{
    return (s && s->n > 0) ? s->mean : 0.0;
}

double zstats_variance(const zstats *s)
{
    return (s && s->n > 0) ? s->m2 / (double)s->n : 0.0;
}

double zstats_sample_variance(const zstats *s)
{
    return (s && s->n > 1) ? s->m2 / (double)(s->n - 1) : 0.0;
}

double zstats_stddev(const zstats *s)
{
    return zsqrt(zstats_variance(s));
}

double zstats_min(const zstats *s)
{
    return (s && s->n > 0) ? s->min : 0.0;
}

double zstats_max(const zstats *s)
{
    return (s && s->n > 0) ? s->max : 0.0;
}

long double zstats_total(const zstats *s)
{
    return (s && s->n > 0) ? s->sum : 0.0L;
}
