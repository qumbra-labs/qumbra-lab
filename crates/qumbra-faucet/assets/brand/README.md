# Brand assets carried by this crate

**Copies.** [`qumbra-design/brand/`](https://github.com/qumbra-labs/qumbra-design/tree/main/brand)
is the source of truth for the mark, its geometry and the four named colours — the same
sentence `qumbra-web` and `qumbra-explorer-web` carry about their copies. **If the mark
changes, change it everywhere; there are now three copies, not two.**

These two are compiled into the binary with `include_bytes!` (`src/http.rs`) and served at
`/favicon-32.png` and `/favicon-16.png`.

```
sha256  a6987ad54326628b0642150e6700d95a07d6b88b47964864f05d0f19d4b933b5  favicon-16.png
sha256  340c9a5172185a4511423872a9ecece007bd9988337af8a9a102a2f2066afe03  favicon-32.png
```

The hashes are recorded here and not in the sibling repos for a reason that is specific to
this copy: the others are *files a deploy serves*, so anyone can fetch the URL and compare.
This one is **inside a binary**, where the only way to check it after the fact is to have
written down what went in. `tests/acceptance.rs` compares the served bytes against these same
files, so a drift shows up as a failing test rather than as a subtly different mark on one of
two public faces.

## Why PNG here, when the SVG is canonical

`qumbra-mark.svg` is the canonical file and draws with `fill="currentColor"` so it inherits
from context — right for *inline* use, which is how both static sites use it. A **standalone**
SVG favicon has no context to inherit: `currentColor` resolves to black, which disappears on a
dark tab strip. These PNGs are 8-bit RGB **without alpha**, so the ground is baked in and the
mark stays legible on light and dark browser chrome alike.

There is a second reason specific to this crate, and it is worth knowing before someone
"simplifies" this to an inline data URI: `qumbra-faucet`'s page is test-locked against external
references (`http_tests::the_page_has_no_script_and_no_external_reference`), because a page that
pulls a sub-resource from another host hands that host a list of who is asking a privacy chain
for money. **Inlining the SVG trips that test on its own `xmlns="http://www.w3.org/2000/svg"`** —
the test refusing a string that is not actually an external fetch, for a reason adjacent to the
one it was written for, and correctly either way.
