/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Focused native acceptance test for the private-file publication seam. */
#include "platform/private_file.h"
#include "platform/positioned_file.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <string.h>
#include <windows.h>

static int fail(const char *message) {
  fprintf(stderr, "FAIL: %s (win32=%lu)\n", message,
          (unsigned long)GetLastError());
  return 1;
}

static bool join_path(char *out, size_t capacity, const char *root,
                      const char *suffix) {
  size_t root_size = strlen(root), suffix_size = strlen(suffix);
  if (root_size >= capacity || suffix_size >= capacity - root_size)
    return false;
  memcpy(out, root, root_size);
  memcpy(out + root_size, suffix, suffix_size + 1u);
  return true;
}

struct wait_lock_context {
  const char *path;
  bool acquired;
  DWORD error;
};

static DWORD WINAPI wait_lock_thread(LPVOID opaque) {
  struct wait_lock_context *context = opaque;
  struct platform_private_file file;
  platform_private_file_init(&file);
  context->acquired = platform_private_file_open_locked_wait(context->path,
                                                             &file);
  if (!context->acquired)
    context->error = GetLastError();
  platform_private_file_close(&file);
  return 0;
}

int main(void) {
  wchar_t temp[MAX_PATH], directory[MAX_PATH];
  if (!GetTempPathW(MAX_PATH, temp) ||
      !GetTempFileNameW(temp, L"zpf", 0, directory) ||
      !DeleteFileW(directory) || !CreateDirectoryW(directory, NULL))
    return fail("temporary directory");

  char dir[4 * MAX_PATH];
  if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, directory, -1, dir,
                           sizeof(dir), NULL, NULL))
    return fail("temporary path encoding");
  char stage[4 * MAX_PATH], destination[4 * MAX_PATH], resolved[4 * MAX_PATH],
      parent[4 * MAX_PATH], conflict[4 * MAX_PATH];
  char invalid[4 * MAX_PATH], wait_lock[4 * MAX_PATH];
  if (!join_path(stage, sizeof(stage), dir, "\\stage.part") ||
      !join_path(destination, sizeof(destination), dir, "\\result.bin") ||
      !join_path(conflict, sizeof(conflict), dir, "\\conflict.bin") ||
      !join_path(wait_lock, sizeof(wait_lock), dir, "\\wait.lock") ||
      !join_path(invalid, sizeof(invalid), dir, "\\file:stream"))
    return fail("fixture path");
  if (platform_private_path_resolve("relative\\file", resolved,
                                    sizeof(resolved), parent,
                                    sizeof(parent)) ||
      platform_private_path_resolve("\\\\server\\share\\file", resolved,
                                    sizeof(resolved), parent,
                                    sizeof(parent)) ||
      platform_private_path_resolve(invalid, resolved, sizeof(resolved),
                                    parent, sizeof(parent)))
    return fail("unsafe path accepted");
  if (!join_path(invalid, sizeof(invalid), dir, "\\CON.txt"))
    return fail("reserved path");
  if (platform_private_path_resolve(invalid, resolved, sizeof(resolved),
                                    parent, sizeof(parent)))
    return fail("reserved device leaf accepted");
  if (!join_path(invalid, sizeof(invalid), dir, "\\trailing."))
    return fail("trailing-dot path");
  if (platform_private_path_resolve(invalid, resolved, sizeof(resolved),
                                    parent, sizeof(parent)))
    return fail("ambiguous trailing-dot leaf accepted");
  if (!platform_private_path_resolve(destination, resolved, sizeof(resolved),
                                     parent, sizeof(parent)) ||
      strcmp(resolved, destination) != 0)
    return fail("canonical parent resolution");

  struct platform_private_file file, second;
  platform_private_file_init(&file);
  platform_private_file_init(&second);
  if (!platform_private_file_create(stage, &file))
    return fail("exclusive create");
  platform_private_file_close(&file);
  struct platform_positioned_file reader;
  platform_positioned_file_init(&reader);
  if (!platform_positioned_file_open(&reader, stage) ||
      !platform_positioned_file_is_private(&reader))
    return fail("private ACL validation");
  platform_positioned_file_close(&reader);
  if (!platform_positioned_file_open_beneath(&reader, dir, "stage.part") ||
      !platform_positioned_file_is_private(&reader))
    return fail("private ACL validation through retained parent");
  platform_positioned_file_close(&reader);
  if (platform_private_file_create(stage, &file))
    return fail("create clobbered existing file");
  if (!platform_private_file_open_locked(stage, &file))
    return fail("locked open");
  if (platform_private_file_open_locked(stage, &second))
    return fail("lock admitted second writer");

  /* Waiting locks must reach LockFileEx rather than fail in CreateFileW.
   * The contender stays blocked while the first handle owns the range, then
   * succeeds promptly after release. This specifically proves that every
   * access requested by pf_open(), including DELETE, is shared. */
  struct platform_private_file held;
  platform_private_file_init(&held);
  if (!platform_private_file_open_locked_create_wait(wait_lock, &held))
    return fail("waiting lock create");
  struct wait_lock_context wait_context = {.path = wait_lock};
  HANDLE waiter = CreateThread(NULL, 0, wait_lock_thread, &wait_context, 0,
                               NULL);
  if (!waiter)
    return fail("waiting lock thread");
  if (WaitForSingleObject(waiter, 100) != WAIT_TIMEOUT) {
    CloseHandle(waiter);
    return fail("waiting lock did not block");
  }
  platform_private_file_close(&held);
  if (WaitForSingleObject(waiter, 5000) != WAIT_OBJECT_0 ||
      !wait_context.acquired) {
    CloseHandle(waiter);
    SetLastError(wait_context.error);
    return fail("waiting lock did not acquire after release");
  }
  CloseHandle(waiter);
  static const char payload[] = "position-safe";
  if (!platform_private_file_write_at(&file, payload, sizeof(payload), 17) ||
      !platform_private_file_flush(&file))
    return fail("positional durable write");
  char observed[sizeof(payload)] = {0};
  if (!platform_private_file_read_at(&file, observed, sizeof(observed), 17) ||
      memcmp(payload, observed, sizeof(payload)))
    return fail("positional read");
  uint64_t size = 0;
  if (!platform_private_file_size(&file, &size) ||
      size != 17 + sizeof(payload) ||
      !platform_private_file_truncate(&file, sizeof(payload)) ||
      !platform_private_file_flush(&file))
    return fail("size/truncate");
  struct platform_private_file_identity identity;
  if (!platform_private_file_identity(&file, &identity))
    return fail("identity");
  bool same = false;
  if (!platform_private_file_link_no_clobber(stage, destination, &identity,
                                             &same) ||
      same)
    return fail("first no-clobber publication");
  if (!platform_private_file_link_no_clobber(stage, destination, &identity,
                                             &same) ||
      !same)
    return fail("idempotent publication identity");
  platform_private_file_close(&file);

  if (!platform_private_file_create(conflict, &second))
    return fail("conflict fixture");
  platform_private_file_close(&second);
  same = false;
  if (platform_private_file_link_no_clobber(stage, conflict, &identity,
                                            &same) ||
      same)
    return fail("conflicting destination accepted");

  /* Replacement stays tied to the verified staging handle and replaces an
   * existing destination atomically. */
  char replacement[4 * MAX_PATH];
  if (!join_path(replacement, sizeof(replacement), dir,
                 "\\replacement.part"))
    return fail("replacement path");
  if (!platform_private_file_create(replacement, &second) ||
      !platform_private_file_write_at(&second, payload, sizeof(payload), 0) ||
      !platform_private_file_replace(&second, replacement, conflict) ||
      !platform_private_path_absent(replacement) ||
      !platform_private_parent_flush(parent))
    return fail("handle-bound replacement");
  platform_private_file_init(&second);
  FILE *installed = fopen(conflict, "rb");
  memset(observed, 0, sizeof(observed));
  if (!installed || fread(observed, 1, sizeof(observed), installed) !=
                        sizeof(observed) ||
      fclose(installed) != 0 || memcmp(observed, payload, sizeof(payload)))
    return fail("replacement contents");

  if (!platform_private_file_open_locked(stage, &file) ||
      !platform_private_file_retire(&file, stage) ||
      !platform_private_path_absent(stage) ||
      !platform_private_file_unlink_missing_ok(stage) ||
      !platform_private_parent_flush(parent))
    return fail("durable cleanup");

  wchar_t wstage[4 * MAX_PATH], wdestination[4 * MAX_PATH],
      wconflict[4 * MAX_PATH];
  MultiByteToWideChar(CP_UTF8, 0, stage, -1, wstage, 4 * MAX_PATH);
  MultiByteToWideChar(CP_UTF8, 0, destination, -1, wdestination, 4 * MAX_PATH);
  MultiByteToWideChar(CP_UTF8, 0, conflict, -1, wconflict, 4 * MAX_PATH);
  DeleteFileW(wdestination);
  DeleteFileW(wconflict);
  wchar_t wwait_lock[4 * MAX_PATH];
  MultiByteToWideChar(CP_UTF8, 0, wait_lock, -1, wwait_lock, 4 * MAX_PATH);
  DeleteFileW(wwait_lock);
  RemoveDirectoryW(directory);
  puts("PASS private_file_acceptance");
  return 0;
}
