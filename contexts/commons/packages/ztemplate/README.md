# ztemplate

Minimal `{{variable}}` template engine in portable C23, no
dependencies beyond libc.

Templates are parsed once into a segment list and rendered any number
of times against a caller lookup callback. Rendering is
allocation-free into a caller buffer, always reporting the exact
required length so a two-pass size-then-fill pattern works.

## Syntax

```
Hello {{name}}, you have {{count}} messages. {{! a comment }}
```

- `{{ name }}` — variable (inner whitespace trimmed)
- `{{! ... }}` — comment, dropped at parse time
- unterminated `{{`, empty tags, and invalid name characters are
  parse errors with a byte offset
- unknown variables at render time fail closed
  (`ZTEMPLATE_UNKNOWN_VAR`), never silently empty

## API

```c
ztemplate *tp = ztemplate_parse(text, len, &err_pos);
ztemplate_render(tp, my_lookup, ctx, out, cap, &out_len);
ztemplate_free(tp);
```

Variable introspection: `ztemplate_var_count` and
`ztemplate_foreach_var` enumerate distinct names in parse order.

## CLI

```sh
cc -std=c23 -Iinclude -o ztemplate app/main.c src/ztemplate.c
./ztemplate -t 'Hello {{name}}!' name=Ada
```

## License

Apache-2.0
