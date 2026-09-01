# zhtml — bounded HTML escaping and unescaping

`zhtml` escapes the five HTML/XML-special characters (`& < > " '`)
into `&amp; &lt; &gt; &quot; &#39;`, and strictly unescapes the five
named entities plus decimal `&#NN;` and hex `&#xHH;` character
references, emitting UTF-8.

Strict by design: unknown entities, bare `&`, malformed or
out-of-range numeric references, lone surrogates, and control
characters (other than tab/LF/CR) are errors (`SIZE_MAX`), never
silently passed through.

## Convention

Producers return the needed byte count (excluding NUL); return >= cap
means truncated output (still NUL-terminated when cap > 0). Inputs are
capped at `ZHTML_MAX` (default 65535) bytes.

## Tests

`tests/test_zhtml.c` covers escape and unescape known answers
(including astral codepoints and the allowed C0 trio), all-256-byte
escape/unescape round trips, a 14-case malformed table, truncation and
measuring mode, over-long and NULL inputs, and a 3000-trial fuzz with
special-char bias and random corruption. Built and run under
`-fsanitize=address,undefined -Werror -pedantic`.

## License

Apache-2.0. See `LICENSE`.
