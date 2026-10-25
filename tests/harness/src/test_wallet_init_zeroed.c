/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: pin wallet_init_zeroed equivalence and non-faulting of the big wallet arrays. */

#include "test/test_core.h"
#include "wallet/wallet.h"
#include "util/safe_alloc.h"
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__APPLE__)
typedef char wallet_residency_byte_t;
#else
/* Not exposed under _POSIX_C_SOURCE=200809L; plain glibc symbol. */
extern int mincore(void *addr, size_t length, unsigned char *vec);
typedef unsigned char wallet_residency_byte_t;
#endif

/* Bytes of a fresh anonymous struct wallet that are resident after init.
 * Returns (size_t)-1 on a setup failure. */
static size_t resident_after_init(bool zeroed)
{
    long pg = sysconf(_SC_PAGESIZE);
    size_t len = sizeof(struct wallet);
    if (pg <= 0) return (size_t)-1;
    size_t npg = (len + (size_t)pg - 1) / (size_t)pg;
    void *m = mmap(NULL, len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return (size_t)-1;
    wallet_residency_byte_t *vec = zcl_calloc(npg, 1, "test_wallet_vec");
    size_t res = (size_t)-1;
    if (vec) {
        struct wallet *w = m;
        if (zeroed) wallet_init_zeroed(w); else wallet_init(w);
        if (mincore(m, len, vec) == 0) {
            res = 0;
            for (size_t i = 0; i < npg; i++)
                if (vec[i] & 1) res += (size_t)pg;
        }
        wallet_free(w);
        free(vec);
    }
    munmap(m, len);
    return res;
}

static int check_equivalence(void)
{
    struct wallet *a = zcl_calloc(1, sizeof(*a), "test_wallet_a");
    struct wallet *b = zcl_calloc(1, sizeof(*b), "test_wallet_b");
    bool ok = a && b;
    if (ok) {
        wallet_init(a);
        wallet_init_zeroed(b);
        size_t cs_off = offsetof(struct wallet, cs);
        size_t cs_end = cs_off + sizeof(a->cs);
        ok = memcmp(a, b, cs_off) == 0 &&
             memcmp((char *)a + cs_end, (char *)b + cs_end,
                    sizeof(*a) - cs_end) == 0 &&
             b->default_fee == WALLET_DEFAULT_FEE_ZAT &&
             b->spend_zero_conf_change;
    }
    if (a) { wallet_free(a); free(a); }
    if (b) { wallet_free(b); free(b); }
    return ok ? 0 : 1;
}

static int check_residency(void)
{
    size_t z = resident_after_init(true);
    size_t h = resident_after_init(false);
    bool ok = z != (size_t)-1 && h != (size_t)-1 &&
              z <= (1u << 20) && h >= (60u << 20);
    printf("(zeroed %zu KiB vs init %zu KiB) ", z >> 10, h >> 10);
    return ok ? 0 : 1;
}

int test_wallet_init_zeroed_checks(void);
int test_wallet_init_zeroed_checks(void)
{
    int failures = 0;
    printf("wallet_init_zeroed equals wallet_init on zeroed storage... ");
    if (check_equivalence()) { printf("FAIL\n"); failures++; } else printf("OK\n");
    printf("wallet_init_zeroed leaves big arrays unfaulted... ");
    if (check_residency()) { printf("FAIL\n"); failures++; } else printf("OK\n");
    return failures;
}
