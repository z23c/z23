/* zcidr CLI: normalize addresses/prefixes, test containment. */

#include "zcidr/zcidr.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc >= 4 && strcmp(argv[1], "contains") == 0) {
    zcidr net, addr;
    if (!zcidr_parse(argv[2], strlen(argv[2]), &net)) {
      fprintf(stderr, "bad network: %s\n", argv[2]);
      return 1;
    }
    if (!zcidr_parse(argv[3], strlen(argv[3]), &addr)) {
      fprintf(stderr, "bad address: %s\n", argv[3]);
      return 1;
    }
    if (zcidr_contains(&net, &addr)) {
      puts("yes");
      return 0;
    }
    puts("no");
    return 3;
  }
  if (argc == 2) {
    zcidr c;
    char buf[64];
    if (!zcidr_parse(argv[1], strlen(argv[1]), &c)) {
      fprintf(stderr, "bad address: %s\n", argv[1]);
      return 1;
    }
    zcidr_format(&c, buf, sizeof buf);
    puts(buf);
    return 0;
  }
  fprintf(stderr, "usage: zcidr ADDR[/PREFIX] | zcidr contains NET ADDR\n");
  return 2;
}
