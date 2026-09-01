/* zmime CLI: extension/type lookup and Content-Type normalization. */

#include "zmime/zmime.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "ext") == 0) {
    puts(zmime_from_extension(argv[2], strlen(argv[2])));
    return 0;
  }
  if (argc == 3 && strcmp(argv[1], "rev") == 0) {
    const char *e = zmime_to_extension(argv[2], strlen(argv[2]));
    if (!e) {
      fprintf(stderr, "unregistered: %s\n", argv[2]);
      return 1;
    }
    puts(e);
    return 0;
  }
  if (argc == 2) {
    zmime_content_type ct;
    char buf[512];
    if (!zmime_parse_content_type(argv[1], strlen(argv[1]), &ct)) {
      fprintf(stderr, "invalid content-type: %s\n", argv[1]);
      return 1;
    }
    zmime_format_content_type(&ct, buf, sizeof buf);
    puts(buf);
    return 0;
  }
  fprintf(stderr, "usage: zmime ext EXT | zmime rev TYPE | zmime CONTENT_TYPE\n");
  return 2;
}
