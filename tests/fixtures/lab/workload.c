/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
/* A deterministic workload of about 500 lines: allocator, vector, hash map,
 * sorting, matrices, tokenizing, sieve, big-number addition and checksums.
 * Prints one summary line per section. */
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- deterministic generator ------------------------------------------- */

struct rng {
    uint64_t state;
};

static void rng_seed(struct rng *r, uint64_t seed)
{
    r->state = seed ? seed : UINT64_C(0x9e3779b97f4a7c15);
}

static uint64_t rng_next(struct rng *r)
{
    uint64_t x = r->state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    r->state = x;
    return x;
}

static uint32_t rng_below(struct rng *r, uint32_t bound)
{
    return (uint32_t)(rng_next(r) % bound);
}

/* ---- arena ------------------------------------------------------------- */

struct arena {
    unsigned char *base;
    size_t used;
    size_t cap;
};

static bool arena_init(struct arena *a, size_t cap)
{
    a->base = malloc(cap);
    a->used = 0;
    a->cap = a->base ? cap : 0;
    return a->base != NULL;
}

static void *arena_alloc(struct arena *a, size_t n)
{
    size_t aligned = (n + 15u) & ~(size_t)15u;
    if (aligned > a->cap - a->used)
        return NULL;
    void *p = a->base + a->used;
    a->used += aligned;
    return p;
}

static void arena_free(struct arena *a)
{
    free(a->base);
    a->base = NULL;
    a->used = a->cap = 0;
}

static int section_arena(void)
{
    struct arena a;
    if (!arena_init(&a, 1u << 16))
        return 1;
    size_t count = 0;
    while (arena_alloc(&a, 24 + count % 40) != NULL)
        count++;
    printf("arena: %zu allocations, %zu of %zu bytes\n", count, a.used, a.cap);
    arena_free(&a);
    return 0;
}

/* ---- vector ------------------------------------------------------------ */

struct vec {
    int64_t *items;
    size_t len;
    size_t cap;
};

static bool vec_push(struct vec *v, int64_t x)
{
    if (v->len == v->cap) {
        size_t cap = v->cap ? v->cap * 2 : 8;
        int64_t *grown = realloc(v->items, cap * sizeof(*grown));
        if (!grown)
            return false;
        v->items = grown;
        v->cap = cap;
    }
    v->items[v->len++] = x;
    return true;
}

static void vec_free(struct vec *v)
{
    free(v->items);
    v->items = NULL;
    v->len = v->cap = 0;
}

static int64_t vec_sum(const struct vec *v)
{
    int64_t total = 0;
    for (size_t i = 0; i < v->len; i++)
        total += v->items[i];
    return total;
}

static int64_t vec_max(const struct vec *v)
{
    int64_t best = v->len ? v->items[0] : 0;
    for (size_t i = 1; i < v->len; i++)
        if (v->items[i] > best)
            best = v->items[i];
    return best;
}

static int section_vector(void)
{
    struct rng r;
    struct vec v = { 0 };
    rng_seed(&r, 7);
    for (int i = 0; i < 5000; i++)
        if (!vec_push(&v, (int64_t)rng_below(&r, 100000) - 50000))
            return 1;
    printf("vector: %zu items, sum %" PRId64 ", max %" PRId64 "\n", v.len,
           vec_sum(&v), vec_max(&v));
    vec_free(&v);
    return 0;
}

/* ---- sorting ----------------------------------------------------------- */

static void swap_i64(int64_t *a, int64_t *b)
{
    int64_t t = *a;
    *a = *b;
    *b = t;
}

static size_t partition(int64_t *a, size_t lo, size_t hi)
{
    int64_t pivot = a[lo + (hi - lo) / 2];
    size_t i = lo, j = hi;
    for (;;) {
        while (a[i] < pivot)
            i++;
        while (a[j] > pivot)
            j--;
        if (i >= j)
            return j;
        swap_i64(&a[i], &a[j]);
        i++;
        j--;
    }
}

static void quicksort(int64_t *a, size_t lo, size_t hi)
{
    if (lo >= hi)
        return;
    size_t p = partition(a, lo, hi);
    if (p > lo)
        quicksort(a, lo, p);
    quicksort(a, p + 1, hi);
}

static void merge_runs(int64_t *a, int64_t *tmp, size_t lo, size_t mid,
                       size_t hi)
{
    size_t i = lo, j = mid, k = lo;
    while (i < mid && j < hi)
        tmp[k++] = a[i] <= a[j] ? a[i++] : a[j++];
    while (i < mid)
        tmp[k++] = a[i++];
    while (j < hi)
        tmp[k++] = a[j++];
    memcpy(a + lo, tmp + lo, (hi - lo) * sizeof(*a));
}

static void mergesort_range(int64_t *a, int64_t *tmp, size_t lo, size_t hi)
{
    if (hi - lo < 2)
        return;
    size_t mid = lo + (hi - lo) / 2;
    mergesort_range(a, tmp, lo, mid);
    mergesort_range(a, tmp, mid, hi);
    merge_runs(a, tmp, lo, mid, hi);
}

static bool is_sorted(const int64_t *a, size_t n)
{
    for (size_t i = 1; i < n; i++)
        if (a[i - 1] > a[i])
            return false;
    return true;
}

static int section_sort(void)
{
    enum { N = 20000 };
    struct rng r;
    rng_seed(&r, 11);
    int64_t *a = malloc(N * sizeof(*a));
    int64_t *b = malloc(N * sizeof(*b));
    int64_t *tmp = malloc(N * sizeof(*tmp));
    if (!a || !b || !tmp) {
        free(a);
        free(b);
        free(tmp);
        return 1;
    }
    for (size_t i = 0; i < N; i++)
        a[i] = b[i] = (int64_t)rng_below(&r, 1000000);
    quicksort(a, 0, N - 1);
    mergesort_range(b, tmp, 0, N);
    bool same = memcmp(a, b, N * sizeof(*a)) == 0;
    printf("sort: quick %s, merge %s, agree %s, min %" PRId64 ", max %" PRId64
           "\n", is_sorted(a, N) ? "ok" : "bad", is_sorted(b, N) ? "ok" : "bad",
           same ? "yes" : "no", a[0], a[N - 1]);
    free(a);
    free(b);
    free(tmp);
    return same ? 0 : 1;
}

/* ---- hash map ---------------------------------------------------------- */

struct entry {
    char key[24];
    uint32_t value;
    bool used;
};

struct map {
    struct entry *slots;
    size_t cap;
    size_t len;
};

static uint64_t fnv1a(const char *s)
{
    uint64_t h = UINT64_C(0xcbf29ce484222325);
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= UINT64_C(0x100000001b3);
    }
    return h;
}

static bool map_init(struct map *m, size_t cap)
{
    m->slots = calloc(cap, sizeof(*m->slots));
    m->cap = m->slots ? cap : 0;
    m->len = 0;
    return m->slots != NULL;
}

static struct entry *map_find(struct map *m, const char *key, bool create)
{
    size_t i = (size_t)(fnv1a(key) % m->cap);
    for (size_t probes = 0; probes < m->cap; probes++) {
        struct entry *e = &m->slots[(i + probes) % m->cap];
        if (!e->used) {
            if (!create)
                return NULL;
            snprintf(e->key, sizeof(e->key), "%s", key);
            e->used = true;
            m->len++;
            return e;
        }
        if (strcmp(e->key, key) == 0)
            return e;
    }
    return NULL;
}

static int section_map(void)
{
    struct map m;
    struct rng r;
    char key[24];
    if (!map_init(&m, 4096))
        return 1;
    rng_seed(&r, 13);
    for (int i = 0; i < 3000; i++) {
        snprintf(key, sizeof(key), "item-%u", rng_below(&r, 1500));
        struct entry *e = map_find(&m, key, true);
        if (!e)
            return 1;
        e->value++;
    }
    uint32_t top = 0;
    for (size_t i = 0; i < m.cap; i++)
        if (m.slots[i].used && m.slots[i].value > top)
            top = m.slots[i].value;
    struct entry *probe = map_find(&m, "item-0", false);
    printf("map: %zu keys, top count %u, item-0 %s\n", m.len, top,
           probe ? "present" : "absent");
    free(m.slots);
    return 0;
}

/* ---- matrices ---------------------------------------------------------- */

#define DIM 48

static void matrix_fill(double m[DIM][DIM], struct rng *r)
{
    for (int i = 0; i < DIM; i++)
        for (int j = 0; j < DIM; j++)
            m[i][j] = (double)rng_below(r, 20) - 10.0;
}

static void matrix_mul(double out[DIM][DIM], double a[DIM][DIM],
                       double b[DIM][DIM])
{
    for (int i = 0; i < DIM; i++)
        for (int j = 0; j < DIM; j++) {
            double acc = 0;
            for (int k = 0; k < DIM; k++)
                acc += a[i][k] * b[k][j];
            out[i][j] = acc;
        }
}

static double matrix_trace(double m[DIM][DIM])
{
    double t = 0;
    for (int i = 0; i < DIM; i++)
        t += m[i][i];
    return t;
}

static int section_matrix(void)
{
    static double a[DIM][DIM], b[DIM][DIM], c[DIM][DIM], d[DIM][DIM];
    struct rng r;
    rng_seed(&r, 17);
    matrix_fill(a, &r);
    matrix_fill(b, &r);
    matrix_mul(c, a, b);
    matrix_mul(d, c, a);
    printf("matrix: trace(ab) %.0f, trace(aba) %.0f\n", matrix_trace(c),
           matrix_trace(d));
    return 0;
}

/* ---- tokenizer --------------------------------------------------------- */

struct counts {
    size_t words;
    size_t numbers;
    size_t longest;
};

static bool is_word_char(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static bool is_digit_char(int c)
{
    return c >= '0' && c <= '9';
}

static struct counts tokenize(const char *text)
{
    struct counts out = { 0, 0, 0 };
    const char *p = text;
    while (*p) {
        const char *start = p;
        if (is_word_char((unsigned char)*p)) {
            while (is_word_char((unsigned char)*p) || is_digit_char((unsigned char)*p))
                p++;
            out.words++;
        } else if (is_digit_char((unsigned char)*p)) {
            while (is_digit_char((unsigned char)*p))
                p++;
            out.numbers++;
        } else {
            p++;
            continue;
        }
        if ((size_t)(p - start) > out.longest)
            out.longest = (size_t)(p - start);
    }
    return out;
}

static int section_tokens(void)
{
    static const char text[] =
        "static int add(int left, int right) { return left + right; }\n"
        "static int mul_by_42(int value) { return value * 42; }\n"
        "int total = add(1000, mul_by_42(7)) + 31337;\n";
    struct counts c = tokenize(text);
    printf("tokens: %zu words, %zu numbers, longest %zu\n", c.words, c.numbers,
           c.longest);
    return 0;
}

/* ---- sieve ------------------------------------------------------------- */

static size_t sieve_count(size_t limit, size_t *largest)
{
    unsigned char *composite = calloc(limit + 1, 1);
    size_t count = 0;
    if (!composite)
        return 0;
    for (size_t i = 2; i <= limit; i++) {
        if (composite[i])
            continue;
        count++;
        *largest = i;
        for (size_t j = i * i; j <= limit; j += i)
            composite[j] = 1;
    }
    free(composite);
    return count;
}

static unsigned collatz_steps(uint64_t n)
{
    unsigned steps = 0;
    while (n != 1) {
        n = (n & 1u) ? 3 * n + 1 : n / 2;
        steps++;
    }
    return steps;
}

static int section_numbers(void)
{
    size_t largest = 0;
    size_t primes = sieve_count(200000, &largest);
    unsigned best = 0;
    uint64_t arg = 0;
    for (uint64_t n = 1; n < 30000; n++) {
        unsigned s = collatz_steps(n);
        if (s > best) {
            best = s;
            arg = n;
        }
    }
    printf("numbers: %zu primes below 200000 (largest %zu), collatz %" PRIu64
           " takes %u steps\n", primes, largest, arg, best);
    return 0;
}

/* ---- big number addition ----------------------------------------------- */

#define DIGITS 400

static void big_from_u64(unsigned char d[DIGITS], uint64_t v)
{
    memset(d, 0, DIGITS);
    for (int i = 0; v != 0 && i < DIGITS; i++) {
        d[i] = (unsigned char)(v % 10u);
        v /= 10u;
    }
}

static void big_add(unsigned char out[DIGITS], const unsigned char a[DIGITS],
                    const unsigned char b[DIGITS])
{
    unsigned carry = 0;
    for (int i = 0; i < DIGITS; i++) {
        unsigned s = (unsigned)a[i] + b[i] + carry;
        out[i] = (unsigned char)(s % 10u);
        carry = s / 10u;
    }
}

static int big_digit_count(const unsigned char d[DIGITS])
{
    int n = DIGITS;
    while (n > 1 && d[n - 1] == 0)
        n--;
    return n;
}

static int section_fibonacci(void)
{
    unsigned char a[DIGITS], b[DIGITS], c[DIGITS];
    big_from_u64(a, 0);
    big_from_u64(b, 1);
    for (int i = 0; i < 1500; i++) {
        big_add(c, a, b);
        memcpy(a, b, DIGITS);
        memcpy(b, c, DIGITS);
    }
    printf("fibonacci: F(1500) has %d digits, leading ", big_digit_count(a));
    for (int i = big_digit_count(a) - 1, shown = 0; i >= 0 && shown < 8;
         i--, shown++)
        putchar('0' + a[i]);
    putchar('\n');
    return 0;
}

/* ---- checksums --------------------------------------------------------- */

static uint32_t crc32_update(uint32_t crc, const unsigned char *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & (0u - (crc & 1u)));
    }
    return crc;
}

static uint32_t adler32(const unsigned char *p, size_t n)
{
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < n; i++) {
        a = (a + p[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}

static int section_checksums(void)
{
    unsigned char buf[8192];
    struct rng r;
    rng_seed(&r, 23);
    for (size_t i = 0; i < sizeof(buf); i++)
        buf[i] = (unsigned char)rng_next(&r);
    uint32_t crc = ~crc32_update(UINT32_MAX, buf, sizeof(buf));
    printf("checksums: crc32 %08" PRIx32 ", adler32 %08" PRIx32 ", fnv %016"
           PRIx64 "\n", crc, adler32(buf, sizeof(buf)),
           fnv1a("one-file lab workload"));
    return 0;
}

/* ---- driver ------------------------------------------------------------ */

typedef int (*section_fn)(void);

int main(void)
{
    static const section_fn sections[] = {
        section_arena,   section_vector,    section_sort,
        section_map,     section_matrix,    section_tokens,
        section_numbers, section_fibonacci, section_checksums,
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(sections) / sizeof(sections[0]); i++)
        failures += sections[i]();
    printf("sections: %zu, failures: %d\n",
           sizeof(sections) / sizeof(sections[0]), failures);
    return failures != 0;
}
