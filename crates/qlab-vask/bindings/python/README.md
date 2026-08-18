# qvask Python reference binding (ctypes)

The kit's "one reference binding; more on demand" (lab #483): `qvask.py`
mirrors `include/qvask.h` over `ctypes` — no toolchain beyond a built
qlab-vask shared library, exercising the ABI exactly as a foreign runtime
would. Python because it is the lingua franca of exchange backoffice glue
(stage-0 survey §3, ratified).

```sh
cargo build -p qlab-vask                      # produces target/debug/libqlab_vask.{dylib,so}
python3 smoke.py ../../../../target/debug/libqlab_vask.dylib
```

`smoke.py` drives the committed parse fixtures (`../../fixtures/`) through
peek/verify: claim fields, every named refusal code, the reason-string free
contract. It is not wired into `cargo test` (no Python in the CI lane); the
same fixtures are locked Rust-side in `src/lib.rs`, so this script drifting
would fail against the same bytes the suite already pins.

Note the deliberate shape: `peek`/`verify` return raw `(code, ...)` tuples
rather than raising — a consumer should see the named-refusal taxonomy, not a
Python-shaped translation of it.
