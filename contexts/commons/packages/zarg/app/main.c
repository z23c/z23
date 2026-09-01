/* zarg CLI: parse stdin-driven demo args and echo the parsed items.
 *
 * Usage: zarg [-v] [-q] [-o file] [-n count] [-s size] [-f factor]
 *             [--dry-run] [inputs...]
 *
 * Prints each parsed option/positional on stdout, the usage block with
 * --help (spec extension below), and exits 2 with the zarg error name
 * on parse failure. This is the package's real consumer: it exercises
 * every option type and both value forms. */
#include "zarg/zarg.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  static const zarg_opt spec[] = {
      {'v', "verbose", ZARG_BOOL, "increase verbosity"},
      {'q', "quiet", ZARG_BOOL, "silence output"},
      {'o', "output", ZARG_STR, "output file"},
      {'n', "count", ZARG_I64, "repeat count"},
      {'s', "size", ZARG_U64, "byte size"},
      {'f', "factor", ZARG_F64, "scaling factor"},
      {0, "dry-run", ZARG_BOOL, "simulate only"},
      {'h', "help", ZARG_BOOL, "show usage"},
  };
  zarg_parser p;
  zarg_item it;
  zarg_err e = zarg_init(&p, spec, sizeof(spec) / sizeof(spec[0]), argc, argv);
  if (e != ZARG_OK) {
    fprintf(stderr, "zarg: %s\n", zarg_err_str(e));
    return 2;
  }
  while ((e = zarg_next(&p, &it)) == ZARG_OK && it.kind != ZARG_ITEM_END) {
    if (it.kind == ZARG_ITEM_POS) {
      printf("pos[%zu]: %s\n", it.pos_index, it.text);
      continue;
    }
    switch (spec[it.spec_index].type) {
    case ZARG_BOOL:
      printf("opt: --%s\n", spec[it.spec_index].long_name != NULL
                                ? spec[it.spec_index].long_name
                                : "?");
      if (spec[it.spec_index].short_name == 'h') {
        char buf[2048];
        zarg_usage(spec, sizeof(spec) / sizeof(spec[0]), "zarg", buf,
                   sizeof(buf));
        fputs(buf, stdout);
      }
      break;
    case ZARG_STR: printf("opt: --%s = \"%s\"\n",
                          spec[it.spec_index].long_name, it.value);
      break;
    case ZARG_I64: printf("opt: --%s = %lld\n",
                          spec[it.spec_index].long_name,
                          (long long)it.i64);
      break;
    case ZARG_U64: printf("opt: --%s = %llu\n",
                          spec[it.spec_index].long_name,
                          (unsigned long long)it.u64);
      break;
    case ZARG_F64: printf("opt: --%s = %.17g\n",
                          spec[it.spec_index].long_name, it.f64);
      break;
    }
  }
  if (e != ZARG_OK) {
    fprintf(stderr, "zarg: %s at argv[%zu]\n", zarg_err_str(e), p.err_index);
    return 2;
  }
  return 0;
}
