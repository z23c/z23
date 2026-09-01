/* zdeque tests — hand-written behavioral cases.
 *
 * Covers: FIFO and LIFO disciplines from both ends, wrap-around of
 * the head index under interleaved push/pop, fill-to-capacity and
 * drain-to-empty, indexed access order, clear/reuse, and every error
 * path.
 */
#include "zdeque/zdeque.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
      failures++;                                                       \
    }                                                                   \
  } while (0)

static int pool[64]; /* distinct pointed-at objects */

static void test_fifo(void)
{
    void *slots[8];
    zdeque dq;
    CHECK(zdeque_init(&dq, slots, 8) == ZDEQUE_OK);
    CHECK(zdeque_empty(&dq) && !zdeque_full(&dq));

    for (int i = 0; i < 8; i++)
        CHECK(zdeque_push_back(&dq, &pool[i]) == ZDEQUE_OK);
    CHECK(zdeque_full(&dq));
    CHECK(zdeque_push_back(&dq, &pool[8]) == ZDEQUE_ERR_FULL);
    CHECK(zdeque_push_front(&dq, &pool[8]) == ZDEQUE_ERR_FULL);

    for (int i = 0; i < 8; i++) {
        void *p = NULL;
        CHECK(zdeque_pop_front(&dq, &p) == ZDEQUE_OK);
        CHECK(p == &pool[i]);
    }
    CHECK(zdeque_empty(&dq));
    CHECK(zdeque_pop_front(&dq, NULL) == ZDEQUE_ERR_EMPTY);
    CHECK(zdeque_pop_back(&dq, NULL) == ZDEQUE_ERR_EMPTY);
}

static void test_stack_discipline(void)
{
    void *slots[4];
    zdeque dq;
    CHECK(zdeque_init(&dq, slots, 4) == ZDEQUE_OK);
    for (int i = 0; i < 4; i++)
        CHECK(zdeque_push_front(&dq, &pool[i]) == ZDEQUE_OK);
    /* Front-push then front-pop is a LIFO. */
    for (int i = 3; i >= 0; i--) {
        void *p = NULL;
        CHECK(zdeque_pop_front(&dq, &p) == ZDEQUE_OK);
        CHECK(p == &pool[i]);
    }
}

static void test_wraparound(void)
{
    void *slots[4];
    zdeque dq;
    CHECK(zdeque_init(&dq, slots, 4) == ZDEQUE_OK);
    /* Churn the head index around the ring many times. */
    int next_in = 0, front_val = 0;
    for (int round = 0; round < 200; round++) {
        /* Keep 3 elements: pop front, push two backs where room. */
        void *p = NULL;
        if (zdeque_pop_front(&dq, &p) == ZDEQUE_OK) {
            CHECK(p == &pool[front_val % 64]);
            front_val++;
        }
        for (int k = 0; k < 2; k++) {
            if (zdeque_push_back(&dq, &pool[next_in % 64]) == ZDEQUE_OK)
                next_in++;
        }
        /* In-order check via zdeque_at. */
        CHECK(zdeque_size(&dq) == (size_t)(next_in - front_val));
        for (size_t i = 0; i < zdeque_size(&dq); i++) {
            void *q = NULL;
            CHECK(zdeque_at(&dq, i, &q) == ZDEQUE_OK);
            CHECK(q == &pool[(front_val + (int)i) % 64]);
        }
    }
}

static void test_peek_and_at(void)
{
    void *slots[4];
    zdeque dq;
    CHECK(zdeque_init(&dq, slots, 4) == ZDEQUE_OK);
    CHECK(zdeque_push_back(&dq, &pool[10]) == ZDEQUE_OK);
    CHECK(zdeque_push_back(&dq, &pool[20]) == ZDEQUE_OK);
    CHECK(zdeque_push_front(&dq, &pool[30]) == ZDEQUE_OK);

    void *p = NULL;
    CHECK(zdeque_peek_front(&dq, &p) == ZDEQUE_OK && p == &pool[30]);
    CHECK(zdeque_peek_back(&dq, &p) == ZDEQUE_OK && p == &pool[20]);
    CHECK(zdeque_at(&dq, 0, &p) == ZDEQUE_OK && p == &pool[30]);
    CHECK(zdeque_at(&dq, 1, &p) == ZDEQUE_OK && p == &pool[10]);
    CHECK(zdeque_at(&dq, 2, &p) == ZDEQUE_OK && p == &pool[20]);
    CHECK(zdeque_at(&dq, 3, &p) == ZDEQUE_ERR_RANGE);
    /* Peeks do not consume. */
    CHECK(zdeque_size(&dq) == 3);
}

static void test_clear_reuse(void)
{
    void *slots[4];
    zdeque dq;
    CHECK(zdeque_init(&dq, slots, 4) == ZDEQUE_OK);
    for (int i = 0; i < 4; i++)
        CHECK(zdeque_push_back(&dq, &pool[i]) == ZDEQUE_OK);
    zdeque_clear(&dq);
    CHECK(zdeque_empty(&dq) && zdeque_size(&dq) == 0);
    void *p = NULL;
    CHECK(zdeque_peek_front(&dq, &p) == ZDEQUE_ERR_EMPTY);
    /* Usable again after clear. */
    CHECK(zdeque_push_back(&dq, &pool[5]) == ZDEQUE_OK);
    CHECK(zdeque_pop_front(&dq, &p) == ZDEQUE_OK && p == &pool[5]);
}

static void test_errors(void)
{
    void *slots[2];
    zdeque dq;
    CHECK(zdeque_init(NULL, slots, 2) == ZDEQUE_ERR_ARG);
    CHECK(zdeque_init(&dq, NULL, 2) == ZDEQUE_ERR_ARG);
    CHECK(zdeque_init(&dq, slots, 0) == ZDEQUE_ERR_ARG);
    CHECK(zdeque_push_back(NULL, &pool[0]) == ZDEQUE_ERR_ARG);
    CHECK(zdeque_peek_front(NULL, NULL) == ZDEQUE_ERR_ARG);
    CHECK(zdeque_init(&dq, slots, 2) == ZDEQUE_OK);
    CHECK(zdeque_peek_front(&dq, NULL) == ZDEQUE_ERR_ARG);
    CHECK(zdeque_size(NULL) == 0);
    CHECK(zdeque_empty(NULL) == 1);

    /* err_str coverage. */
    for (int e = 0; e <= 4; e++)
        CHECK(zdeque_err_str((zdeque_err)e) != NULL);
    CHECK(strcmp(zdeque_err_str(ZDEQUE_OK), "ok") == 0);
}

int main(void)
{
    test_fifo();
    test_stack_discipline();
    test_wraparound();
    test_peek_and_at();
    test_clear_reuse();
    test_errors();
    if (failures) {
        fprintf(stderr, "zdeque: %d failure(s)\n", failures);
        return 1;
    }
    puts("zdeque: all tests passed");
    return 0;
}
