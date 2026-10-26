/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zpool - fixed-block pool exerciser.
 *
 * Usage: zpool BLOCK_SIZE BLOCK_COUNT < ops
 *
 * Replays allocation operations against a pool and prints the outcome
 * of each, one per line — a deterministic driver for exploring pool
 * behaviour (or diffing two allocator builds):
 *
 *   a        alloc: prints "a -> IDX" or "a -> FULL"
 *   f IDX    free block IDX: prints "f IDX -> ok" or "-> rejected"
 *   o IDX    owns query: prints "o IDX -> live" or "-> no"
 *   s        state: prints "s -> free N/CAP"
 *
 * Exit 0 when all ops ran, 2 on misuse, bad op, or bound violation.
 * Bounds: BLOCK_SIZE <= 64, BLOCK_COUNT <= 4096.
 */
#include "zpool/zpool.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#define MAX_BLOCK 64u
#define MAX_BLOCKS 4096u
#define MAX_OP 128u

static _Alignas(max_align_t) unsigned char arena[(size_t)MAX_BLOCK * MAX_BLOCKS];

static bool init_pool(zpool *pool, size_t block_size, size_t count) {
  size_t stride = block_size < sizeof(void *) ? sizeof(void *) : block_size;
  size_t alignment = _Alignof(max_align_t);
  if (stride > SIZE_MAX - (alignment - 1u)) return false;
  stride = (stride + alignment - 1u) / alignment * alignment;
  if (count > sizeof(arena) / stride) return false;
  return zpool_init(pool, arena, stride * count, block_size);
}

static bool parse_unsigned(const char *text, unsigned long *result, char **tail) {
  const char *sign = text;
  while (isspace((unsigned char)*sign)) sign++;
  bool negative = *sign == '-';
  errno = 0;
  char *end = NULL;
  unsigned long value = strtoul(text, &end, 10);
  if (end == text || errno == ERANGE || (negative && value != 0)) return false;
  *result = value;
  *tail = end;
  return true;
}

static bool parse_index(const char *text, size_t count, unsigned long *index) {
  char *end;
  unsigned long value;
  if (!parse_unsigned(text, &value, &end) ||
      (*end && *end != '\n') || value >= count) return false;
  *index = value;
  return true;
}

static int finish_input(FILE *in, int result) {
  if (ferror(in)) {
    fputs("zpool: read error\n", stderr);
    return 2;
  }
  return result;
}

static int finish_output(FILE *out, int result) {
  if (fflush(out) == EOF || ferror(out)) {
    fputs("zpool: write error\n", stderr);
    return 2;
  }
  return result;
}

int main(int argc, char **argv) {
  
  if (argc != 3) {
    fprintf(stderr, "usage: zpool BLOCK_SIZE BLOCK_COUNT < ops\n");
    return 2;
  }
  char *end = NULL;
  unsigned long bs;
  if (!parse_unsigned(argv[1], &bs, &end) || *end || bs < 1 || bs > 64) {
    fprintf(stderr, "zpool: BLOCK_SIZE must be 1..64\n");
    return 2;
  }
  unsigned long bc;
  if (!parse_unsigned(argv[2], &bc, &end) || *end || bc < 1 || bc > MAX_BLOCKS) {
    fprintf(stderr, "zpool: BLOCK_COUNT must be 1..%u\n", MAX_BLOCKS);
    return 2;
  }

  zpool pool;
  if (!init_pool(&pool, (size_t)bs, (size_t)bc)) {
    fprintf(stderr, "zpool: cannot initialize pool\n");
    return 2;
  }

  char op[MAX_OP];
  int bad = 0;
  while (fgets(op, sizeof(op), stdin)) {
    if (op[0] == 'a' && (op[1] == '\n' || op[1] == '\0')) {
      void *b = zpool_alloc(&pool);
      if (!b) {
        puts("a -> FULL");
      } else {
        size_t idx = (size_t)((unsigned char *)b - arena) /
                     pool.block_size;
        printf("a -> %zu\n", idx);
      }
    } else if (op[0] == 'f' || op[0] == 'o') {
      unsigned long idx;
      if (!parse_index(op + 1, pool.block_count, &idx)) {
        fprintf(stderr, "zpool: bad op '%s'", op);
        bad = 2;
        break;
      }
      void *b = arena + idx * pool.block_size;
      if (op[0] == 'f')
        printf("f %lu -> %s\n", idx, zpool_free(&pool, b) ? "ok" : "rejected");
      else
        printf("o %lu -> %s\n", idx, zpool_owns(&pool, b) ? "live" : "no");
    } else if (op[0] == 's') {
      printf("s -> free %zu/%zu\n", zpool_available(&pool),
             pool.block_count);
    } else if (op[0] == '#' || op[0] == '\n') {
      continue;
    } else {
      fprintf(stderr, "zpool: unknown op '%s'", op);
      bad = 2;
      break;
    }
  }
  return finish_output(stdout, finish_input(stdin, bad));
}
