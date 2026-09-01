/* zsort — context-carrying sorts and argsort.  See zsort.h. */

#include "zsort/zsort.h"

#include <string.h>

/* ---------- byte-level helpers ------------------------------------- */

static void swap_bytes(unsigned char *a, unsigned char *b, size_t size) {
  size_t i;
  for (i = 0; i < size; i++) {
    unsigned char t = a[i];
    a[i] = b[i];
    b[i] = t;
  }
}

/* ---------- unstable introsort -------------------------------------- */

#define ZSORT_INSERTION_THRESHOLD 16

static void insertion(unsigned char *base, size_t n, size_t size,
                      zsort_cmp cmp, void *ctx) {
  size_t i, j;
  for (i = 1; i < n; i++) {
    for (j = i; j > 0; j--) {
      unsigned char *a = base + (j - 1) * size;
      unsigned char *b = base + j * size;
      if (cmp(a, b, ctx) <= 0) break;
      swap_bytes(a, b, size);
    }
  }
}

static void sift_down(unsigned char *base, size_t root, size_t n,
                      size_t size, zsort_cmp cmp, void *ctx) {
  for (;;) {
    size_t child = root * 2 + 1;
    if (child >= n) break;
    if (child + 1 < n &&
        cmp(base + child * size, base + (child + 1) * size, ctx) < 0)
      child++;
    if (cmp(base + root * size, base + child * size, ctx) < 0) {
      swap_bytes(base + root * size, base + child * size, size);
      root = child;
    } else {
      break;
    }
  }
}

static void heapsort(unsigned char *base, size_t n, size_t size,
                     zsort_cmp cmp, void *ctx) {
  size_t start = n / 2;
  size_t end = n;
  while (start > 0) sift_down(base, --start, n, size, cmp, ctx);
  while (end > 1) {
    end--;
    swap_bytes(base, base + end * size, size);
    sift_down(base, 0, end, size, cmp, ctx);
  }
}

static void introsort_rec(unsigned char *base, size_t n, size_t size,
                          zsort_cmp cmp, void *ctx, unsigned depth_limit) {
  while (n > ZSORT_INSERTION_THRESHOLD) {
    size_t mid, i, j;
    if (depth_limit == 0) {
      heapsort(base, n, size, cmp, ctx);
      return;
    }
    depth_limit--;
    /* median-of-three; pivot lands at n-1 */
    mid = n / 2;
    if (cmp(base, base + mid * size, ctx) > 0)
      swap_bytes(base, base + mid * size, size);
    if (cmp(base + mid * size, base + (n - 1) * size, ctx) > 0)
      swap_bytes(base + mid * size, base + (n - 1) * size, size);
    if (cmp(base, base + mid * size, ctx) > 0)
      swap_bytes(base, base + mid * size, size);
    swap_bytes(base + mid * size, base + (n - 1) * size, size);
    /* Lomuto partition of [0, n-1) against pivot at n-1; the pivot
     * slot is untouched until the final placement, so referencing it
     * during comparisons is safe. */
    i = 0;
    for (j = 0; j + 1 < n; j++) {
      if (cmp(base + j * size, base + (n - 1) * size, ctx) < 0) {
        swap_bytes(base + i * size, base + j * size, size);
        i++;
      }
    }
    swap_bytes(base + i * size, base + (n - 1) * size, size);
    /* recurse on the smaller side, loop on the larger */
    if (i < n - 1 - i) {
      introsort_rec(base, i, size, cmp, ctx, depth_limit);
      base += (i + 1) * size;
      n = n - i - 1;
    } else {
      introsort_rec(base + (i + 1) * size, n - i - 1, size, cmp, ctx,
                    depth_limit);
      n = i;
    }
  }
  insertion(base, n, size, cmp, ctx);
}

void zsort(void *base, size_t n, size_t size, zsort_cmp cmp, void *ctx) {
  unsigned depth = 0;
  size_t m = n;
  if (!cmp || size == 0 || n <= 1) return;
  if (!base) return;
  while (m > 1) {
    depth++;
    m >>= 1;
  }
  introsort_rec(base, n, size, cmp, ctx, 2 * depth + 1);
}

/* ---------- stable merge sort -------------------------------------- */

static void msort_rec(unsigned char *base, size_t n, size_t size,
                      zsort_cmp cmp, void *ctx, unsigned char *scratch) {
  size_t half, i, j, k;
  if (n <= 1) return;
  half = n / 2;
  msort_rec(base, half, size, cmp, ctx, scratch);
  msort_rec(base + half * size, n - half, size, cmp, ctx, scratch);
  /* already in order? (also what makes it stable cheaply) */
  if (cmp(base + (half - 1) * size, base + half * size, ctx) <= 0) return;
  memcpy(scratch, base, half * size);
  i = 0;
  j = half;
  k = 0;
  while (i < half && j < n) {
    if (cmp(scratch + i * size, base + j * size, ctx) <= 0) {
      memcpy(base + k * size, scratch + i * size, size);
      i++;
    } else {
      memcpy(base + k * size, base + j * size, size);
      j++;
    }
    k++;
  }
  while (i < half) {
    memcpy(base + k * size, scratch + i * size, size);
    i++;
    k++;
  }
}

int zsort_stable(void *base, size_t n, size_t size, zsort_cmp cmp,
                 void *ctx, void *scratch) {
  if (!cmp || size == 0) return 0;
  if (n <= 1) return 1;
  if (!base || !scratch) return 0;
  msort_rec(base, n, size, cmp, ctx, scratch);
  return 1;
}

/* ---------- argsort ------------------------------------------------- */

/* Bottom-up stable merge sort over the permutation.  Left runs up to
 * 64 entries merge through a stack buffer; larger runs fall back to
 * in-place rotation (rare, O(n^2) worst case but allocation-free). */

#define ZSORT_ARGSORT_BUF 64

static void insertion_perm(size_t *perm, size_t lo, size_t hi,
                           const unsigned char *base, size_t size,
                           zsort_cmp cmp, void *ctx) {
  size_t i;
  for (i = lo + 1; i < hi; i++) {
    size_t j = i;
    while (j > lo) {
      const unsigned char *a = base + perm[j - 1] * size;
      const unsigned char *b = base + perm[j] * size;
      size_t t;
      if (cmp(a, b, ctx) <= 0) break;
      t = perm[j - 1];
      perm[j - 1] = perm[j];
      perm[j] = t;
      j--;
    }
  }
}

static void merge_perm(size_t *perm, size_t lo, size_t mid, size_t hi,
                       const unsigned char *base, size_t size,
                       zsort_cmp cmp, void *ctx, size_t *buf) {
  size_t left_n = mid - lo;
  if (left_n <= ZSORT_ARGSORT_BUF) {
    size_t i = 0, j = mid, k = lo;
    memcpy(buf, perm + lo, left_n * sizeof *buf);
    while (i < left_n && j < hi) {
      const unsigned char *a = base + buf[i] * size;
      const unsigned char *b = base + perm[j] * size;
      if (cmp(a, b, ctx) <= 0) {
        perm[k++] = buf[i++];
      } else {
        perm[k++] = perm[j++];
      }
    }
    while (i < left_n) perm[k++] = buf[i++];
  } else {
    /* stable in-place merge by rotation */
    size_t i = lo, j = mid;
    while (i < j && j < hi) {
      const unsigned char *a = base + perm[i] * size;
      const unsigned char *b = base + perm[j] * size;
      if (cmp(a, b, ctx) <= 0) {
        i++;
      } else {
        size_t tmp = perm[j];
        size_t r;
        for (r = j; r > i; r--) perm[r] = perm[r - 1];
        perm[i] = tmp;
        i++;
        j++;
      }
    }
  }
}

int zargsort(size_t *perm, const void *base, size_t n, size_t size,
             zsort_cmp cmp, void *ctx) {
  size_t i;
  size_t buf[ZSORT_ARGSORT_BUF];
  size_t width;
  const unsigned char *b = base;
  if (!cmp || size == 0) return 0;
  if (n == 0) return perm != NULL;
  if (!perm || !base) return 0;
  for (i = 0; i < n; i++) perm[i] = i;
  for (i = 0; i < n; i += 32) {
    size_t hi = i + 32 < n ? i + 32 : n;
    insertion_perm(perm, i, hi, b, size, cmp, ctx);
  }
  for (width = 32; width < n; width *= 2) {
    size_t start;
    for (start = 0; start < n; start += 2 * width) {
      size_t mid = start + width < n ? start + width : n;
      size_t end = start + 2 * width < n ? start + 2 * width : n;
      if (mid < end) merge_perm(perm, start, mid, end, b, size, cmp, ctx, buf);
    }
  }
  return 1;
}
