# The prover's payee wallet: importing the paid ledger

*Chinese translation: [`prover-payee-wallet-zh.md`](prover-payee-wallet-zh.md). EN is authoritative.*

Lab #937, the importer (after PR E). Code: `crates/qumbra-wallet` (`src/openings.rs`, the `import-openings` command, the scan merge in `src/annulet.rs`).

## Why there is a file to import

On a format-34 net the remote prover is paid inside each transaction, in its third output: asset 0, to the prover's payee address (`docs/prover-service-annulet.md`, "Format 34").

**An honest kernel** encrypts that output's discovery payload to the payee. The payee wallet's ordinary `scan --net annulet` then finds the note like any other.

**A wallet that did not** (malicious or buggy) leaves a note the payee owns but cannot detect.

So the service keeps a **paid ledger**: after the node accepts a submission, it appends that transaction's output-3 opening to the ledger.

## Where the file comes from

1. The operator copies the ledger **by hand** from the prover's box (the service's `QUMBRA_PROVER_ANNULET_PAID_LEDGER` file) to the machine that holds the payee wallet.
2. The operator imports it there.

**The payee's seed never goes to the prover's box.** The box knows only the payee's address.

The ledger opens notes, so keep it as you keep the wallet's own files: owner-only, out of logs and out of git.

## Importing

```sh
qumbra-wallet import-openings --net annulet --dir WALLET --ledger paid-ledger.txt
```

**Requirements.** The wallet must have a Candidate A authorization journal (`auth.v1`); without one the import is refused by name. A v1 net has no prover fee.

**Network.** Nothing is fetched; the import is offline.

**Re-importing.** Importing the same ledger again is safe. An opening already kept reads `already-imported`.

### What the import checks

**The file's first line** must be `qumbra-prover-paid-ledger 1`. Otherwise the whole file is refused ("not a version-1 paid ledger") and nothing is written.

**Each later line** gets its own verdict, and one refused line does not stop the others. The checks run in this order:

| Check | Refused as |
|---|---|
| The line is at most 1 KiB (checked before any parsing) | `refused:malformed(length)` |
| The entry version is `1` | `refused:entry-version-unknown(<v>)` |
| The fields are exactly `cm value asset rkm rho rseed shape at`, in that order, each in its format | `refused:malformed(<field>)` |
| `asset=0` | `refused:not-asset-0` |
| The opening `(value, 0, rkm, rho, rseed)` recomputes to the line's `cm` | `refused:cm-mismatch` |
| The `rkm` is one of this wallet's: an allocated address under a generation in its journal | `refused:not-this-wallet` |

**A last line without a newline** is a write torn by a crash on the service. It reads `skipped:torn-last-line`. The service closes that line with a newline when it next starts, so copying the file again after that imports it.

**`shape` and `at`** are checked for their format only. They are not stored and never affect a verdict.

**What is kept.** Accepted openings go to `openings.v1` in the wallet directory:
- written by a temporary file and a rename, created owner-only (0600) where the platform has permission bits — on Windows it inherits the folder's ACL, as the seed file does;
- one entry per `cm`;
- together with the address index and generation each one is owned under.

The permission is set when the file is created and not checked when it is opened, as for the wallet's other files.

When a scan loads the file, it re-checks each entry: the index must be allocated, and the opening must open its `cm` at that address and generation. A hand-edited file is refused by name, never guessed at.

**What it prints.** Per line, its number, the first 16 hex of its `cm`, and the verdict; then the counts:

```
line 2: cm 3f9ac2010b7e4d55… imported
line 3: cm 3f9ac2010b7e4d55… already-imported
line 4: cm - refused:entry-version-unknown(2)
imported 1, already imported 1, refused 1, skipped 0 — membership is checked by `scan --net annulet`, never here
```

**`rho` and `rseed` are never printed.**

### What the import does not check: membership

Whether an opening's `cm` is actually on chain is **the scan's** question. It is decided where every other note's membership is decided.

**Matching.** `scan --net annulet` (also `history` and `send`, which run the same verified scan) owns an imported note wherever the served compact stream carries its `cm`, whether or not the scan could decrypt it. Consensus binds every output's `cm` to its transaction's discovery entries, so an undetectable output's `cm` is still in the stream.

**Position.** The note's height and transaction come from the chain, never from the file. A verified scan also checks the note against the block body, as it does for every note.

**Downstream.** From there the note is like any other:
- its spend is subtracted;
- a 0-value one (a price of 0) lands in the zero bucket (seen, never spendable);
- a note the scan also decrypted counts once.

**Not found.** An imported opening whose `cm` the scan did not see in its range is only counted. It is never in a figure:

```
imported: 3 opening(s) found on chain; 1 not found in 0..=1204 (counted only, never in a figure)
```

**On a net that is not Candidate A**, a wallet that holds imported openings has its scan refused by name (`imported_openings`).
