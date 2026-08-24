# The `RPC_VERSION` reader inventory

> [中文版](rpc-version-reader-inventory-zh.md)

**Status: derived 2026-08-24 against `RPC_VERSION = 0x07`, for lab [#607](https://github.com/qumbra-labs/qumbra-lab/issues/607).**
Its complaint is that a version bump breaks every wallet client until rebuilt **and
there is no inventory of readers**. This is the inventory. It is not a fix; it makes
the next bump countable.

🔴 **Every row here was derived by search, not from recollection.** The method is
stated below so the next person re-runs it rather than trusting this table's date.
The reason that matters: on 2026-08-22 a release checklist said *"seven app repos"*
and the true number was different in both directions — one entry was a worktree of
another, and one reader (this repo's own CLI) was absent from the list entirely.

---

## 1. The two version disciplines, and only one of them breaks

`qlab-node`'s decoder has both, and which one a surface uses decides whether a bump
is a rebuild or an outage.

| | mechanism | on a bump |
|---|---|---|
| **STRICT** | `Reader::version()` → `version_in(&[RPC_VERSION])` — a list of exactly one (`rpc.rs:1485`) | **refuses**, loudly, `BadVersion { got: N }` |
| **TOLERANT** | `version_in(READABLE_TELEMETRY_VERSIONS)` — `&[0x03, 0x04, 0x05, 0x06, RPC_VERSION]` (`telemetry.rs:145`) | keeps reading |

**`/v1/telemetry` is the only surface with a compat list.** It was given one at #212
and the list has been extended at every bump since. Everything else is strict by
construction, because `Reader::version()` is what "every node-side decode uses" in
its own words.

**`Reader` is `pub(crate)`.** No out-of-repo client uses it — each has hand-rolled
its own decode, so each has its own version check or none. **That is why the
inventory cannot be derived from the lab alone.**

## 2. Out-of-repo clients, and the surfaces they read

Counted by `grep -rhoE "/v1/[a-z_]+"` per repo, worktrees and build dirs excluded:

| client repo | surfaces referenced (count of references) |
|---|---|
| `qumbra-wallet-macos` | `/v1/names` 12 · **`/v1/anchors` 7** · `/v1/tx` 4 |
| `qumbra-wallet-desktop` | `/v1/tx` 2 · `/v1/compact` 2 · `/v1/tree` 1 · `/v1/nullifiers` 1 · **`/v1/anchors` 1** |
| `qumbra-wallet-ios` | `/v1/tx` 10 · **`/v1/anchors` 7** · `/v1/compact` 3 · `/v1/coinbase` 2 |
| `qumbra-wallet-android` | **`/v1/anchors` 35** · `/v1/compact` 19 |
| `qumbra-wallet-extension` | **`/v1/anchors` 8** · `/v1/nullifiers` 5 · `/v1/coinbase` 3 · `/v1/compact` 1 |
| `qumbra-explorer-web` | none — it reads the **explorer's** JSON, which carries its own `v` field, deliberately not `RPC_VERSION` (`json.rs:46`) |
| `qumbra-web` | none |

**Plus one in-repo reader that is easy to forget because it is not an app:**
`qumbra-wallet`, this repo's own CLI. It broke on the `0x06 → 0x07` bump like the
others and it is not in any app-repo enumeration.

## 3. 🔴 The countable answer

**Five clients read `/v1/anchors`. It is strict. A bump breaks all five, plus the CLI.**

That is the surface that produced `GET /v1/anchors did not decode: BadVersion { got: 7 }`
on the macOS wallet on 2026-08-22 — the visible half of #607 — and it is the one every
client touches because it is how a wallet learns which anchors it may prove against.

**`/v1/compact` (4 clients) and `/v1/coinbase` / `/v1/nullifiers` (2 each) are also
strict**, so the blast radius is not narrower than `/v1/anchors` suggests; it is the
same set of clients through more doors.

## 4. What a bump therefore requires

Not a policy, just the list, so nobody has to remember it:

```
qumbra-wallet-macos        rebuild + reinstall
qumbra-wallet-desktop      rebuild + reinstall   (desktop-linux is a BRANCH of this repo, not a sixth client)
qumbra-wallet-ios          rebuild + redeploy to the device
qumbra-wallet-android      rebuild
qumbra-wallet-extension    rebuild
qumbra-wallet (this repo)  rebuild — the one nobody lists
```

**And the released node binaries**, which are a reader of nothing but are read *by*
these clients: a published release whose `RPC_VERSION` differs from the live fleet's
hands a user a node their wallet cannot talk to. That is lab #614, and the
`release skew` workflow now measures exactly it.

## 5. The method, so this table can be re-derived rather than trusted

```sh
# the definition
grep -rn "pub const RPC_VERSION" crates/

# strict vs tolerant
grep -rn "version_in(" crates/ | grep -v "fn version_in"

# per-client surfaces, from ~/develop/qumbra
for d in qumbra-wallet-*; do
  grep -rhoE "/v1/[a-z_]+" "$d" \
    --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=target --exclude-dir=build \
    | sort | uniq -c | sort -rn
done
```

🔴 **Exclude worktrees.** `ls -d qumbra-wallet-*` on the coordinator's machine also
lists `…-android-authbench-copy-evidence`, `…-android-remote-auth-mobile-bench`,
`…-ios-remote-auth-mobile-bench`, `…-macos-confirmed` — **none of which is a client**.
Counting directories is how "seven app repos" happened.

## 6. What this inventory does NOT establish

* **Whether each client actually checks the version byte, or ignores it.** The counts
  above are references to a *surface*, not evidence of a version check. A client that
  reads `/v1/anchors` and never inspects byte 0 would mis-parse rather than refuse —
  **a worse failure than the one #607 describes**, and this table cannot tell them apart.
* **Whether any client has its own compat list.** `qumbra-explorer-web` deliberately
  does not track `RPC_VERSION`; nothing here checks whether any wallet does.
* **The android/ios/extension counts are reference counts, not call sites.** A repo with
  35 mentions of `/v1/anchors` may have one client and 34 tests.

Each of those is a follow-up read, not a guess to fill in.
