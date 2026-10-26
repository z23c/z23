/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zpool test suite.  Exits nonzero on the first failure. */
#define _POSIX_C_SOURCE 200809L
#include "zpool/zpool.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/wait.h>

/* Compile the real driver in the declared package test translation unit.
 * Include its system headers first so private symbol renames stay local. */
#define main zpool_cli_main
#define arena zpool_cli_arena
#include "../app/main.c"
#undef arena
#undef main

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

static _Alignas(16) unsigned char arena[64 * 16]; /* 16 x 64-byte blocks */

static void test_init_validation(void) {
  zpool p;
  memset(arena, 0xAA, sizeof(arena));
  CHECK(zpool_init(&p, arena, sizeof(arena), 64));
  CHECK(p.block_size == 64);
  CHECK(p.block_count == 16);
  CHECK(zpool_available(&p) == 16);
  /* Block size rounds up to hold a link and to align. */
  CHECK(zpool_init(&p, arena, sizeof(arena), 1));
  CHECK(p.block_size == _Alignof(max_align_t));
  /* Too-small arena, NULL args, unaligned arena. */
  CHECK(!zpool_init(&p, arena, 8, 64));
  CHECK(!zpool_init(&p, NULL, sizeof(arena), 64));
  CHECK(!zpool_init(NULL, arena, sizeof(arena), 64));
  CHECK(!zpool_init(&p, arena + 1, sizeof(arena) - 1, 64));
  /* Overflow-huge block size fails closed. */
  CHECK(!zpool_init(&p, arena, sizeof(arena), SIZE_MAX - 3));
  /* Leftover tail smaller than a block is simply unused. */
  CHECK(zpool_init(&p, arena, 64 + 32, 64));
  CHECK(p.block_count == 1);
}

static void test_alloc_exhaustion(void) {
  zpool p;
  CHECK(zpool_init(&p, arena, sizeof(arena), 64));
  void *blocks[16];
  for (int i = 0; i < 16; i++) {
    blocks[i] = zpool_alloc(&p);
    CHECK(blocks[i] != NULL);
    CHECK(((uintptr_t)blocks[i] % _Alignof(max_align_t)) == 0);
    CHECK(zpool_available(&p) == (size_t)(15 - i));
  }
  CHECK(zpool_alloc(&p) == NULL); /* exhausted */
  CHECK(zpool_alloc(NULL) == NULL);
  /* All distinct. */
  for (int i = 0; i < 16; i++)
    for (int j = i + 1; j < 16; j++)
      CHECK(blocks[i] != blocks[j]);
  for (int i = 0; i < 16; i++)
    CHECK(zpool_free(&p, blocks[i]));
  CHECK(zpool_available(&p) == 16);
}

static void test_reuse_and_lifo(void) {
  zpool p;
  CHECK(zpool_init(&p, arena, sizeof(arena), 64));
  void *a = zpool_alloc(&p);
  void *b = zpool_alloc(&p);
  CHECK(a && b);
  /* User writes through the whole block; free must still work. */
  memset(a, 0x55, 64);
  memset(b, 0x66, 64);
  CHECK(zpool_free(&p, a));
  CHECK(zpool_free(&p, b));
  void *c = zpool_alloc(&p); /* LIFO: b comes back first */
  CHECK(c == b);
  void *d = zpool_alloc(&p);
  CHECK(d == a);
  CHECK(zpool_free(&p, c));
  CHECK(zpool_free(&p, d));
}

static void test_free_validation(void) {
  zpool p;
  CHECK(zpool_init(&p, arena, sizeof(arena), 64));
  void *a = zpool_alloc(&p);
  CHECK(a);
  memset(a, 0x77, 64); /* scribble over the whole live block */
  unsigned char outside[64] = {0};
  CHECK(!zpool_free(&p, NULL));
  CHECK(!zpool_free(NULL, a));
  CHECK(!zpool_free(&p, outside)); /* out of arena */
  CHECK(!zpool_free(&p, arena + sizeof(arena))); /* one past the end */
  CHECK(!zpool_free(&p, (unsigned char *)a + 8)); /* misaligned */
  CHECK(zpool_free(&p, a)); /* the real free */
  CHECK(!zpool_free(&p, a)); /* double free rejected */
  /* A never-allocated block is on the free list: freeing it is a
   * double free and must be rejected. */
  void *never = arena + 64; /* still free: only block 0 was taken */
  CHECK(!zpool_free(&p, never));
  CHECK(zpool_available(&p) == 16);
}

static void test_owns(void) {
  zpool p;
  CHECK(zpool_init(&p, arena, sizeof(arena), 64));
  void *a = zpool_alloc(&p);
  CHECK(zpool_owns(&p, a));
  CHECK(!zpool_owns(&p, arena + 64)); /* in arena but free */
  CHECK(!zpool_owns(&p, (unsigned char *)a + 8));
  CHECK(!zpool_owns(&p, NULL));
  CHECK(!zpool_owns(NULL, a));
  CHECK(zpool_free(&p, a));
  CHECK(!zpool_owns(&p, a));
}

static void test_interleaved_churn(void) {
  zpool p;
  CHECK(zpool_init(&p, arena, sizeof(arena), 64));
  void *live[16] = {0};
  size_t live_n = 0;
  for (int round = 0; round < 2000; round++) {
    if (live_n && (round % 3 == 0)) {
      size_t i = (size_t)(round * 7) % live_n;
      CHECK(zpool_owns(&p, live[i]));
      CHECK(zpool_free(&p, live[i]));
      live[i] = live[--live_n];
    } else {
      void *b = zpool_alloc(&p);
      if (!b) {
        CHECK(live_n == 16);
        continue;
      }
      live[live_n++] = b;
      memset(b, round & 0xFF, 64);
    }
    CHECK(zpool_available(&p) == 16 - live_n);
    /* Verify every live block is owned and no two live blocks alias. */
    for (size_t i = 0; i < live_n; i++) {
      CHECK(zpool_owns(&p, live[i]));
      for (size_t j = i + 1; j < live_n; j++)
        CHECK(live[i] != live[j]);
    }
  }
  for (size_t i = 0; i < live_n; i++)
    CHECK(zpool_free(&p, live[i]));
  CHECK(zpool_available(&p) == 16);
}

static void test_small_blocks(void) {
  /* 8-byte requests still get aligned, link-sized blocks. */
  _Alignas(16) unsigned char small[4 * 16];
  zpool p;
  CHECK(zpool_init(&p, small, sizeof(small), 8));
  CHECK(p.block_size == 16);
  CHECK(p.block_count == 4);
  void *b[4];
  for (int i = 0; i < 4; i++)
    CHECK((b[i] = zpool_alloc(&p)) != NULL);
  CHECK(zpool_alloc(&p) == NULL);
  for (int i = 0; i < 4; i++)
    CHECK(zpool_free(&p, b[i]));
  CHECK(zpool_available(&p) == 4);
}

static void test_foreign_pointer_ownership(void) {
  unsigned char foreign[64] = {0};
  zpool p;
  CHECK(zpool_init(&p, arena, sizeof(arena), 64));
  /* Separate objects may not be compared or subtracted as C pointers. */
  CHECK(!zpool_owns(&p, foreign));
  CHECK(zpool_available(&p) == 16);
}

/* Refusal includes both the result and the header's no-state-change promise.
 * Stop before free on a bad owns result so validator mutations cannot write
 * through foreign, one-past, or NULL pointers. */
static void check_refusal(zpool *pool, void *ptr, const char *row) {
  unsigned char before[sizeof(arena)];
  memcpy(before, arena, sizeof(before));
  zpool saved = *pool;
  if (zpool_owns(pool, ptr)) {
    fprintf(stderr, "FAIL contract row %s: owns accepted\n", row);
    failures++;
    return;
  }
  bool refused = !zpool_free(pool, ptr);
  bool unchanged = pool->arena == saved.arena &&
                   pool->block_size == saved.block_size &&
                   pool->block_count == saved.block_count &&
                   pool->free_count == saved.free_count &&
                   pool->free_head == saved.free_head &&
                   memcmp(before, arena, sizeof(before)) == 0;
  if (!refused || !unchanged) {
    fprintf(stderr, "FAIL contract row %s: free refusal/state\n", row);
    failures++;
  }
}

static void test_contract_rows(void) {
  zpool p;
  CHECK(zpool_init(&p, arena, sizeof(arena), 64));
  check_refusal(&p, arena, "never allocated");
  void *blocks[16];
  for (size_t i = 0; i < 16; i++) {
    blocks[i] = zpool_alloc(&p);
    if (blocks[i] != arena + i * p.block_size ||
        !zpool_owns(&p, blocks[i])) {
      fprintf(stderr, "FAIL contract row live starts: block %zu\n", i);
      failures++;
    }
  }
  CHECK(32 % _Alignof(max_align_t) == 0);
  check_refusal(&p, arena + 32, "aligned interior");
  check_refusal(&p, arena + 1, "misaligned interior");
  check_refusal(&p, arena + sizeof(arena), "one past");
  unsigned char foreign[64] = {0};
  unsigned char saved_foreign[sizeof(foreign)] = {0};
  check_refusal(&p, foreign, "foreign");
  CHECK(memcmp(foreign, saved_foreign, sizeof(foreign)) == 0);
  check_refusal(&p, NULL, "null");
  for (size_t i = 0; i < 16; i++) {
    CHECK(zpool_free(&p, blocks[i]));
    CHECK(zpool_available(&p) == i + 1);
    check_refusal(&p, blocks[i], "freed");
  }
}

enum cli_fault { CLI_OK, CLI_READ_ERROR, CLI_WRITE_ERROR };

static void close_cli_files(FILE **files) {
  for (size_t i = 0; i < 3; i++) {
    if (files[i] && fclose(files[i]) != 0) {
      fprintf(stderr, "FAIL CLI temporary stream cleanup: %s\n", strerror(errno));
      failures++;
    }
    files[i] = NULL;
  }
}

/* tmpfile may ignore TMPDIR. The verifier permits writes only to its own
 * scratch root, so create exclusively there and unlink only our new name. */
static FILE *cli_temporary_stream(void) {
  const char *scratch = getenv("TMPDIR");
  char path[4096];
  if (!scratch || scratch[0] != '/') {
    fprintf(stderr, "FAIL CLI scratch setup: absolute TMPDIR required\n");
    return NULL;
  }
  int n = snprintf(path, sizeof(path), "%s/zpool-cli.XXXXXX", scratch);
  if (n < 0 || (size_t)n >= sizeof(path)) {
    fprintf(stderr, "FAIL CLI scratch setup: TMPDIR path too long\n");
    return NULL;
  }
  int fd = mkstemp(path);
  if (fd < 0) {
    fprintf(stderr, "FAIL CLI scratch create: %s\n", strerror(errno));
    return NULL;
  }
  if (unlink(path) != 0) {
    fprintf(stderr, "FAIL CLI scratch unlink: %s\n", strerror(errno));
    if (close(fd) != 0)
      fprintf(stderr, "FAIL CLI scratch descriptor cleanup: %s\n", strerror(errno));
    return NULL;
  }
  FILE *stream = fdopen(fd, "w+");
  if (!stream) {
    fprintf(stderr, "FAIL CLI scratch stream: %s\n", strerror(errno));
    if (close(fd) != 0)
      fprintf(stderr, "FAIL CLI scratch descriptor cleanup: %s\n", strerror(errno));
  }
  return stream;
}

static bool open_cli_files(FILE **files, const char *ops) {
  for (size_t i = 0; i < 3; i++) {
    files[i] = cli_temporary_stream();
    if (!files[i]) {
      fprintf(stderr, "FAIL CLI temporary stream setup: %s\n", strerror(errno));
      return false;
    }
  }
  if (fputs(ops, files[0]) == EOF || fseek(files[0], 0, SEEK_SET) != 0 ||
      fflush(NULL) == EOF) {
    fprintf(stderr, "FAIL CLI input/flush setup: %s\n", strerror(errno));
    return false;
  }
  return true;
}

static void cli_child(FILE **files, char **args, enum cli_fault fault) {
  alarm(5);
  for (int i = 0; i < 3; i++) {
    if (dup2(fileno(files[i]), i) < 0) _Exit(125);
  }
  if (fault == CLI_READ_ERROR && close(STDIN_FILENO) != 0) _Exit(125);
  if (fault == CLI_WRITE_ERROR && close(STDOUT_FILENO) != 0) _Exit(125);
  errno = ERANGE;
  int rc = zpool_cli_main(3, args);
  if (fflush(stderr) == EOF) _Exit(125);
  _Exit(rc);
}

static bool cli_wait(pid_t pid, int expected) {
  int status = 0;
  pid_t result;
  do { result = waitpid(pid, &status, 0); } while (result < 0 && errno == EINTR);
  if (result != pid || !WIFEXITED(status) || WEXITSTATUS(status) != expected) {
    fprintf(stderr, "FAIL CLI child status: wait=%ld status=%d expected=%d\n",
            (long)result, status, expected);
    return false;
  }
  return true;
}

static bool cli_capture(FILE *file, const char *expected) {
  char bytes[256];
  if (fseek(file, 0, SEEK_SET) != 0) {
    fprintf(stderr, "FAIL CLI capture seek: %s\n", strerror(errno));
    return false;
  }
  size_t n = fread(bytes, 1, sizeof(bytes), file);
  bool matched = !ferror(file) && n == strlen(expected) && memcmp(bytes, expected, n) == 0;
  if (!matched)
    fprintf(stderr, "FAIL CLI capture: bytes=%zu expected=%s actual=%.*s\n",
            n, expected, (int)n, bytes);
  return matched;
}

static void cli_case(const char *size, const char *count, const char *ops,
                     enum cli_fault fault, int status,
                     const char *output, const char *diagnostic) {
  int before = failures;
  FILE *files[3] = {NULL, NULL, NULL};
  if (!open_cli_files(files, ops)) {
    failures++;
    close_cli_files(files);
    return;
  }
  pid_t pid = fork();
  if (pid == 0) {
    char *args[] = {"zpool", (char *)size, (char *)count, NULL};
    cli_child(files, args, fault);
  }
  if (pid < 0) {
    fprintf(stderr, "FAIL CLI fork: %s\n", strerror(errno));
    failures++;
  } else {
    bool matched = cli_wait(pid, status);
    matched = cli_capture(files[1], output) && matched;
    matched = cli_capture(files[2], diagnostic) && matched;
    if (!matched) {
      fprintf(stderr, "FAIL CLI row size=%s count=%s ops=%s fault=%d\n",
              size, count, ops, (int)fault);
      failures++;
    }
  }
  close_cli_files(files);
  printf("test_zpool: CLI size=%s count=%s fault=%d %s\n", size, count,
         (int)fault, failures == before ? "PASS" : "FAIL");
}

static void test_cli_capacity(void) {
  const char *sizes[] = {"1", "17", "63"};
  for (size_t i = 0; i < 3; i++)
    cli_case(sizes[i], "3", "s\n", CLI_OK, 0, "s -> free 3/3\n", "");
  cli_case("17", "4096", "s\n", CLI_OK, 0, "s -> free 4096/4096\n", "");
}

static void test_cli_bounds(void) {
  cli_case("17", "4097", "", CLI_OK, 2, "", "zpool: BLOCK_COUNT must be 1..4096\n");
  cli_case("17", "0", "", CLI_OK, 2, "", "zpool: BLOCK_COUNT must be 1..4096\n");
  char huge[64];
  int n = snprintf(huge, sizeof(huge), "%zu", SIZE_MAX);
  CHECK(n > 0 && (size_t)n < sizeof(huge));
  cli_case(huge, "2", "", CLI_OK, 2, "", "zpool: BLOCK_SIZE must be 1..64\n");
  cli_case("64", huge, "", CLI_OK, 2, "", "zpool: BLOCK_COUNT must be 1..4096\n");
}

static void test_cli_sizing(void) {
  zpool p = {0};
  CHECK(!init_pool(&p, SIZE_MAX, 2));
  CHECK(!init_pool(&p, 64, SIZE_MAX));
  CHECK(!init_pool(&p, 64, 4097));
  CHECK(p.arena == NULL && p.free_head == NULL && p.block_count == 0);
}

static void test_cli_refusals(void) {
  cli_case("16", "1", "f\n", CLI_OK, 2, "", "zpool: bad op 'f\n'");
  cli_case("16", "1", "o\n", CLI_OK, 2, "", "zpool: bad op 'o\n'");
  cli_case("16", "1", "f", CLI_OK, 2, "", "zpool: bad op 'f'");
  cli_case("16", "1", "", CLI_OK, 0, "", "");
  cli_case("16", "1", "", CLI_READ_ERROR, 2, "", "zpool: read error\n");
  cli_case("16", "1", "a\n", CLI_OK, 0, "a -> 0\n", "");
  cli_case("16", "1", "s\n", CLI_WRITE_ERROR, 2, "", "zpool: write error\n");
  cli_case("16", "1", "a\n", CLI_WRITE_ERROR, 2, "", "zpool: write error\n");
}

static void cli_bad_index(const char *index) {
  for (int free_op = 0; free_op < 2; free_op++) {
    char ops[256], diagnostic[256];
    char op = free_op ? 'f' : 'o';
    int n = snprintf(ops, sizeof ops, "s\n%c %s\n", op, index);
    int d = snprintf(diagnostic, sizeof diagnostic, "zpool: bad op '%c %s\n'", op, index);
    if (n < 0 || (size_t)n >= sizeof ops || d < 0 || (size_t)d >= sizeof diagnostic) exit(2);
    cli_case("16", "2", ops, CLI_OK, 2, "s -> free 2/2\n", diagnostic);
  }
}

static void cli_bad_numbers(const char *text) {
  cli_case(text, "2", "s\n", CLI_OK, 2, "", "zpool: BLOCK_SIZE must be 1..64\n");
  cli_case("16", text, "s\n", CLI_OK, 2, "", "zpool: BLOCK_COUNT must be 1..4096\n");
  cli_bad_index(text);
}

static void test_cli_numeric_signs(void) {
  char negative_max[64], whitespace_negative[64], overflow[64];
  int a = snprintf(negative_max, sizeof negative_max, "-%lu", ULONG_MAX);
  int b = snprintf(whitespace_negative, sizeof whitespace_negative, " \t-%lu", ULONG_MAX);
  int c = snprintf(overflow, sizeof overflow, "%lu0", ULONG_MAX);
  if (a < 0 || b < 0 || c < 0 || (size_t)a >= sizeof negative_max ||
      (size_t)b >= sizeof whitespace_negative || (size_t)c >= sizeof overflow) exit(2);
  const char *bad[] = {negative_max, whitespace_negative, overflow, "-1", "", " \t", "1junk"};
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) cli_bad_numbers(bad[i]);
  cli_case(" \t+16", " +2", "a\no -0\nf -0\ns\n", CLI_OK, 0,
           "a -> 0\no 0 -> live\nf 0 -> ok\ns -> free 2/2\n", "");
  cli_case("16", "2", "a\no +0\nf \t+0\n", CLI_OK, 0,
           "a -> 0\no 0 -> live\nf 0 -> ok\n", "");
  unsigned long index = ULONG_MAX;
  errno = ERANGE;
  CHECK(parse_index(" -0\n", 2, &index) && index == 0);
  CHECK(errno != ERANGE);
}

int main(void) {
  test_cli_numeric_signs();
  test_cli_capacity();
  test_cli_bounds();
  test_cli_sizing();
  test_cli_refusals();
  test_contract_rows();
  test_foreign_pointer_ownership();
  test_init_validation();
  test_alloc_exhaustion();
  test_reuse_and_lifo();
  test_free_validation();
  test_owns();
  test_interleaved_churn();
  test_small_blocks();
  if (failures) {
    fprintf(stderr, "test_zpool: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_zpool: all tests passed");
  return 0;
}
