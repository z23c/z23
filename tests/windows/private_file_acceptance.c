/* Focused native acceptance test for the private-file publication seam. */
#include "platform/private_file.h"

#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <string.h>
#include <windows.h>

static int fail(const char *message) {
  fprintf(stderr, "FAIL: %s (win32=%lu)\n", message,
          (unsigned long)GetLastError());
  return 1;
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
  snprintf(stage, sizeof(stage), "%s\\stage.part", dir);
  snprintf(destination, sizeof(destination), "%s\\result.bin", dir);
  snprintf(conflict, sizeof(conflict), "%s\\conflict.bin", dir);
  char invalid[4 * MAX_PATH];
  snprintf(invalid, sizeof(invalid), "%s\\file:stream", dir);
  if (platform_private_path_resolve("relative\\file", resolved,
                                    sizeof(resolved), parent,
                                    sizeof(parent)) ||
      platform_private_path_resolve("\\\\server\\share\\file", resolved,
                                    sizeof(resolved), parent,
                                    sizeof(parent)) ||
      platform_private_path_resolve(invalid, resolved, sizeof(resolved),
                                    parent, sizeof(parent)))
    return fail("unsafe path accepted");
  snprintf(invalid, sizeof(invalid), "%s\\CON.txt", dir);
  if (platform_private_path_resolve(invalid, resolved, sizeof(resolved),
                                    parent, sizeof(parent)))
    return fail("reserved device leaf accepted");
  snprintf(invalid, sizeof(invalid), "%s\\trailing.", dir);
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
  if (platform_private_file_create(stage, &file))
    return fail("create clobbered existing file");
  if (!platform_private_file_open_locked(stage, &file))
    return fail("locked open");
  if (platform_private_file_open_locked(stage, &second))
    return fail("lock admitted second writer");
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
  RemoveDirectoryW(directory);
  puts("PASS private_file_acceptance");
  return 0;
}
