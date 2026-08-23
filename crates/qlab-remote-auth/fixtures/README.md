# Authorization spike vectors

`authorization-v1.txt` is the exact stdout of:

```console
cargo run -q -p qlab-remote-auth --bin qlab-remote-auth-spike -- vector
```

Every seed and signing value in the file is synthetic, public test material.
None is wallet or deployment secret material, and none may be reused as one.

The integration test regenerates the file byte for byte. The ML-DSA values are
deterministic FIPS 204 ML-DSA-44 values produced by the pinned `ml-dsa` crate.

The final `reference_wots_leaf` and `reference_wots_signature` use these
inputs:

- RFC 8391 parameter set `XMSS-SHA2_10_256` (`WOTSP-SHA2_256`), OID 1;
- secret seed `00 01 ... 1f`;
- public seed byte `i = 2*i`;
- message byte `i = 3*i`;
- zeroed layer/tree addresses and OTS/L-tree index 7.

They were independently compared byte for byte with the RFC authors'
reference implementation at commit
`171ccbd26f098542a67eb5d2b128281c80bd71a6`:

<https://github.com/XMSS/xmss-reference/tree/171ccbd26f098542a67eb5d2b128281c80bd71a6>

The cross-check covers the RFC address encoding, HRS16 private-element
expansion, WOTS+ chains, checksum, and L-tree compression. This evidence does
not make the research implementation production cryptography.

The final outer-tree context/root pair separately locks the spike's candidate
domain-, context- and level-separated Keccak tree; it is not an RFC 8391 value.
