# Remote proving — Candidate A physical-mobile evidence, 2026-08-24

**Status: FIRST PHYSICAL-DEVICE EVIDENCE SET COMPLETE. NOT A NETWORK-WIDE
DEPTH SELECTION, PROTOCOL CONSTANT, WALLET INTEGRATION, OR IMPLEMENTATION
APPROVAL.** This record is paired with
[`remote-proving-mobile-evidence-2026-08-24-zh.md`](remote-proving-mobile-evidence-2026-08-24-zh.md).
The measurement method and trust boundary remain defined by
[`remote-proving-mobile-benchmark.md`](remote-proving-mobile-benchmark.md).

The 20 raw JSON records and their SHA-256 manifest are committed under
[`docs/evidence/remote-auth-mobile/2026-08-24/`](evidence/remote-auth-mobile/2026-08-24/).

## 1. Scope and rigs

The standalone research apps measured D12 through D16 twice on each device:

| platform | physical device | OS | memory | lab revision | shell revision |
|---|---|---|---:|---|---|
| iOS | iPhone 15 Pro Max (`iPhone16,2`) | iOS 26.6 | 8,025,686,016 B | `ac7681832916c9b9b344052c1fac1f2010c94f34` | `b19e1eb0794a8813950d7fe0482b89f60ca96c76` |
| Android | Solana Mobile Seeker (`seeker; arm64-v8a`) | Android 16 / API 36 | 7,841,386,496–7,841,513,472 B reported | `ac7681832916c9b9b344052c1fac1f2010c94f34` | `cefc17a2130dc3abc74823609a9ab3437eede711` |

Both apps were built from clean source trees and installed as isolated benchmark
targets. They used the public deterministic research fixture, not a wallet seed
or production key. The iOS target did not use wallet tests or Keychain; the
Android target had no wallet/Keystore integration and no `INTERNET` permission.

## 2. Evidence validity and correctness

All 20 retained records satisfy the evidence protocol:

- format `qlab-remote-auth-mobile-bench-v1`, ABI version 1, and 152-byte result;
- `source_trees_clean = true` with named lab and shell revisions;
- low-power mode off;
- iOS thermal start/end `nominal`; Android thermal start/end `none`;
- two completed records for every platform/depth cell; and
- no cancellation, OS termination, or discarded throttled/OOM result.

For every depth, all four cross-platform records have exactly one unique
`root`, one unique complete-intent digest, and one unique selected-index pair.
Static sizes also agree: the authorization section is 7,544 bytes, each
verifying key is 1,312 bytes per slot, and each signature is 2,420 bytes per
slot. The cross-platform correctness gate therefore passes for D12 through D16.

## 3. Timing results

Values below are arithmetic means of the two retained runs. `total` is address
initialization plus one synthetic two-slot spend/verification path; `sign` is
the two-signature/authorization-section stage reported by the harness.

| depth | leaves | iPhone total | Seeker total | Seeker / iPhone | iPhone sign | Seeker sign |
|---:|---:|---:|---:|---:|---:|---:|
| 12 | 4,096 | 0.320 s | 0.822 s | 2.57× | 0.348 ms | 0.954 ms |
| 13 | 8,192 | 0.624 s | 1.632 s | 2.61× | 0.419 ms | 1.131 ms |
| 14 | 16,384 | 1.226 s | 3.238 s | 2.64× | 0.679 ms | 1.757 ms |
| 15 | 32,768 | 2.443 s | 6.490 s | 2.66× | 0.580 ms | 1.400 ms |
| 16 | 65,536 | 4.988 s | 12.989 s | 2.60× | 0.840 ms | 1.791 ms |

The largest two-run total-time spread in any cell is 1.97%. Address-leaf
generation accounts for about 99% of total time. The measured per-spend
sign-plus-verify path remains below 1.0 ms on this iPhone and below 2.1 ms on
this Seeker; initialization, not spending, is the UX-sensitive operation.

The iOS memory metric is process `physical_footprint`; Android is PSS. Their
absolute values and deltas are not directly comparable. Android D12's first
run also includes a 39.4 MiB PSS delta that does not repeat at later depths,
consistent with process/allocator warm-up rather than depth-linear retained
state. This evidence does not establish a cross-platform memory ratio.

## 4. Ruling supported by this set

**D16 completed under the evidence protocol on these two measured devices:**
both completed twice without thermal escalation, at means of 4.988 s and
12.989 s. This closes the first-evidence-set requirement for the available
iPhone 15 Pro Max and one representative supported Android device.

**It does not select D16, or any other depth, as the network constant.** The
Seeker's 12.989 s mean has not been assessed against an approved cold
address-initialization UX threshold, and neither device proves behavior at the
product's supported-device floor. The network-wide depth gate remains open
until:

1. Larry names the minimum supported iOS and Android hardware/OS floor;
2. the same clean-revision, two-run D12..D16 protocol is executed at that floor;
3. acceptable cold address-initialization latency and background/cancellation
   UX are explicitly decided; and
4. Larry makes the depth decision from the combined evidence.

Larry deferred the floor measurement on 2026-08-24. The future physical-cloud
execution and security plan is
[`remote-proving-mobile-device-cloud-plan.md`](remote-proving-mobile-device-cloud-plan.md).

Failure at the floor means choosing a lower depth or revising the construction.
It is not permission to upload the private authorization master to the prover.

## 5. Reproduction and unrun gates

From the evidence directory:

```console
shasum -a 256 -c SHA256SUMS
jq -e . raw/*.json
```

The raw records are the authority for unrounded values. No Rust test was run
locally for this evidence-only change, in accordance with repository policy.
No production key lifecycle, crash-safe reservation, restore/multi-device
allocation, public-cache transport, wallet integration, AIR/wire/node change,
genesis change, or real-value launch gate is closed by this record.
