# Join and mine on the Qumbra testnet

中文：[`join-and-mine-zh.md`](./join-and-mine-zh.md) · **English is authoritative on technical detail.**

This is the T1 path for a participant the project does not control.

> **Values filled 2026-08-16 as the T1 announcement package** (design
> `t1-sg-posture-decision`, sequence: Gate A remeasure → this package → SG open). They are
> read from the deployed fleet, not guessed: image digest/revision from the compose pin and
> its OCI label readback, seeds from the four OPEN entry points of the SG posture decision
> (node0 is deliberately not an entry point). **Until the announcement is published (Larry's
> go), the port these seeds listen on is not yet publicly open** — a connection refused before
> that moment is the posture working, not a wrong address. If the fleet rolls between this
> fill and the announcement, the digest/revision rows are re-verified at publication.

> ### ⚠️ UPDATE YOUR NODE BEFORE ~AUG 21 (height 19,008)
>
> **Every binary and image older than release
> [`t1-c5cfff8`](https://github.com/qumbra-labs/qumbra/releases/tag/t1-c5cfff8) stops
> following the chain at height 19,008** (~the morning of 2026-08-21 +08; the height is
> exact, the date is an estimate). This includes release `t1-91bdee4` and all node images
> published before it. The failure is **silent**: an old node keeps running, keeps mining,
> and walks onto a dead fork with no finality — no error is printed at the boundary.
> **The update is live: release
> [`t1-c5cfff8`](https://github.com/qumbra-labs/qumbra/releases/tag/t1-c5cfff8)** — update
> and restart before the boundary. If you skip it, your node starts rejecting honest blocks
> at 19,009 with errors classified `internal` and walks onto a dead fork — that signature
> means "update", not "debug". The chain's terms (fee table, activation height, commit–reveal) are unchanged —
> this is a software update deadline, not a rule change.

## 1. Obtain and verify the release

The node image is public at `ghcr.io/qumbra-labs/qumbra-node`. Use the **digest from the T1
announcement**, never a mutable tag. The image records its source revision in the OCI label
`org.opencontainers.image.revision`; read it back and compare it with the revision in the
announcement rather than trusting the tag or a successful pull. The label and node binary are
part of the runtime image ([`deploy/docker/Dockerfile:123-160`](../deploy/docker/Dockerfile#L123-L160));
the readback requirement is the lesson of [lab #224](https://github.com/qumbra-labs/qumbra-lab/issues/224).

```sh
IMAGE='ghcr.io/qumbra-labs/qumbra-node@sha256:c7b8b3340d35d7461daaa83acea6a8eef045bdba74d5173f9f059322ec18adbb'
EXPECTED_REV='e0b624596e29dc8a95d1f6715ed061b4247a73e2'

docker pull "$IMAGE"
ACTUAL_REV="$(docker image inspect \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE")"
test "$ACTUAL_REV" = "$EXPECTED_REV" || {
  echo "wrong image revision: got $ACTUAL_REV, want $EXPECTED_REV" >&2
  exit 1
}
```

The announcement also publishes these network-identity inputs together:

- `genesis.qmb` — **format v4**;
- `expected_genesis_hash` —
  `138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb`;
- the initial P2P seed addresses for `dial_peers`.

The format and hash are pinned in the tree
([`genesis.rs:68-77`](../crates/qumbra-node/src/genesis.rs#L68-L77),
[`genesis.rs:775-779`](../crates/qumbra-node/src/genesis.rs#L775-L779)). Distribution:
`genesis.qmb` downloads from **`https://seed.qumbra.org/genesis.qmb`** (deploy PR #150) —
always byte-verify it against `expected_genesis_hash` above; `qumbra-node check` and startup
both refuse a wrong file, so a tampered download cannot pass silently. The seed list is the
four open entry points below (`t1-sg-posture-decision`).

### Alternative: prebuilt binaries, no Docker (added 2026-08-17, lab #437)

The container above stays the **reproducible baseline** and is what this guide's numbered
steps use. If Docker is the obstacle rather than the answer, the same two binaries are
published as tarballs on the public repo's releases page:

**<https://github.com/qumbra-labs/qumbra/releases>**

> **Until the first release is cut, that page is empty and the container path is the only
> path.** The release lane exists ([`release-binaries.yml`](../.github/workflows/release-binaries.yml))
> and is dispatched by hand; the T1 announcement names the tag once one is published.

| archive | for |
|---|---|
| `…-linux-x86_64-glibc.tar.gz` | Intel/AMD Linux, glibc 2.36+ (Debian 12, Ubuntu 22.04+) |
| `…-linux-aarch64-glibc.tar.gz` | arm64 Linux — what the testnet fleet itself runs |
| `…-macos-arm64.tar.gz` | Apple Silicon, macOS 11+ |
| `…-windows-x86_64.zip` | Windows 10/11 x64 — **native, no WSL2** (added by lab #478) |

Each holds `qumbra-node`, `qumbra-wallet` and a `PROVENANCE.txt`. The Windows archive is a
`.zip` rather than a `.tar.gz` and its binaries carry `.exe`; everything else about it is the
same artifact, built and asserted by the same release lane. **It appears from the first
release cut after 2026-08-18** — an older tag on the releases page has three archives, not
four, and that is a vintage difference rather than a missing file.

```sh
# 1 — download the tarball for your platform and SHA256SUMS from the release page, then:
sha256sum -c SHA256SUMS          # macOS: shasum -a 256 -c SHA256SUMS
tar -xzf qumbra-t1-<shortrev>-<platform>.tar.gz
cd qumbra-t1-<shortrev>-<platform>

# 2 — ask the binary what it is. Both lines are load-bearing:
./qumbra-node halt-status
```

```text
  build rev:    <the source revision the release notes name>
  halt plan:    no halt scheduled
  resumes past: height 8640 (post-halt rules apply above it)
```

`build rev:` is how a downloaded binary proves which source it came from — a tarball carries
no image label, so this line is the equivalent of the `org.opencontainers.image.revision`
readback in the container path above. If `halt plan:` says **ARMED**, that binary halts at
8,640 and cannot follow this chain; do not run it. CI refuses to publish one, so an ARMED
binary from the release page would mean the artifact is not what it claims to be.

**macOS only:** the binaries are unsigned and un-notarized. A browser download quarantines
them and Gatekeeper refuses to run them. Fetch with `curl`, or clear the attribute:
`xattr -d com.apple.quarantine qumbra-node qumbra-wallet`.

### Windows: native (added 2026-08-18, lab #478)

`windows-x86_64.zip` holds `qumbra-node.exe` and `qumbra-wallet.exe`, built for
`x86_64-pc-windows-msvc` with the same RandomX C++ implementation every other platform uses.
They are the same binaries in every sense that matters to the chain: CI runs RandomX's four
official reference vectors on the MSVC build, so a Windows miner's hashes are the network's
hashes, not a near-miss.

Everything from §2 onward applies unchanged — same `genesis.qmb`, same `node.toml` fields,
same seeds. What follows is only what is *different* about Windows.

**1. Download and verify, in PowerShell.** Windows has no `sha256sum`:

```powershell
# from the release page: the zip for your platform, and SHA256SUMS
Get-FileHash .\qumbra-t1-<shortrev>-windows-x86_64.zip -Algorithm SHA256
# compare the printed hash against the matching line in SHA256SUMS — by eye, all 64 chars
Expand-Archive .\qumbra-t1-<shortrev>-windows-x86_64.zip -DestinationPath .
cd qumbra-t1-<shortrev>-windows-x86_64
.\qumbra-node.exe halt-status
```

The `halt-status` reading is the same one §1 describes above: `build rev:` must match the
release notes, and `halt plan:` must say `no halt scheduled` and not **ARMED**.

**2. 🔴 SmartScreen will stop you, and it is right to.** These executables are **unsigned** —
there is no code-signing certificate on this project, and buying one is a separate decision
nobody has taken. The first run of either binary shows *"Windows protected your PC"*. The
path through it is **More info → Run anyway**. Microsoft Defender may additionally flag a CPU
miner on reputation alone.

This is the honest position and not a reassurance: an unsigned binary from a private repo is
exactly the shape of thing SmartScreen exists to warn about, and *"click through the security
warning"* is advice you should be suspicious of by default. The only thing that makes it
reasonable here is that you can check the download yourself — **verify the SHA-256 against
SHA256SUMS before you click Run anyway**, not after.

**3. Paths in `node.toml` need single quotes.** TOML's double-quoted strings treat `\` as an
escape character, so `data_dir = "C:\Users\you\qumbra-data"` is either a parse error or a
different directory than you meant. Use a TOML *literal* string, or forward slashes:

```toml
data_dir = 'C:\Users\you\qumbra-data'          # literal string — backslashes are literal
genesis_file = 'C:\Users\you\genesis.qmb'
# or, equally valid on Windows:
# data_dir = "C:/Users/you/qumbra-data"
```

**4. Run it from a console you opened, and stop it with Ctrl-C.** Open PowerShell or Windows
Terminal and run `.\qumbra-node.exe run --config node.toml` there — do not double-click it.
**Ctrl-C is the stop that reliably flushes the snapshot.** Closing the console window flushes
too, but Windows gives any program about five seconds after a window-close before killing it,
and a node busy inside a RandomX round can miss that budget.

Nothing is lost when it does: the block log is fsync'd per record and is the source of truth,
so a node that missed its snapshot flush replays the log on next start and reaches exactly the
same state. What a missed flush costs is **replay time**, not coins or history.

**5. The wallet's seed file is not owner-only on Windows.** On Linux and macOS
`qumbra-wallet keygen` writes `wallet.seed` with mode `0600`. Windows has no such mode and
this build does not set an ACL, so the file inherits whatever the folder gives it — under your
own profile that is normally you *plus* SYSTEM and Administrators. `keygen` prints this rather
than claiming a protection it does not have. To make the wallet folder owner-only, run once:

```powershell
icacls "$env:USERPROFILE\.qumbra-wallet" /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F"
```

Anyone who can read that file owns every coin the wallet holds.

**6. Keep the machine awake.** Set Windows power settings not to sleep, and keep a laptop
plugged in — a sleeping host mines nothing.

**Not in this port** (named so nobody looks for it): no Windows service wrapper — to survive
sign-out, register the `run` command as a Task Scheduler task with *"Run whether user is
logged on or not"*, which is outside what this guide covers. No code signing. No ARM Windows
build.

### Windows: WSL2

Still supported and unchanged: `wsl --install` from an admin PowerShell, then follow this
document from §1 inside Ubuntu with the `linux-x86_64-glibc` tarball. It mines at effectively
native speed. With a native build available, WSL2 is now the fallback rather than the path.

## 2. Join as a non-mining node

Put the downloaded `genesis.qmb` beside this minimal `node.toml`:

```toml
data_dir = "/data"
listen_addr = "0.0.0.0:9400"
dial_peers = ["18.202.166.126:9444","18.141.177.109:9444","52.194.224.123:9444","52.5.0.21:9444"]
genesis_file = "/config/genesis.qmb"
expected_genesis_hash = "138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb"
mining = false
```

These are the fields a joiner needs. `mining` defaults to false, but it is explicit above. Do
**not** copy fleet configs and do **not** add `committee_key_paths`: a public joiner is a
verify-only node and holds no committee signing keys
([`config.rs:54-94`](../crates/qumbra-node/src/config.rs#L54-L94)).

Preflight the exact genesis and config before binding a socket, then run:

```sh
docker volume create qumbra-data

docker run --rm \
  -v "$PWD:/config:ro" -v qumbra-data:/data \
  --entrypoint /usr/local/bin/qumbra-node \
  "$IMAGE" check --config /config/node.toml

docker run --rm --name qumbra-node \
  -v "$PWD:/config:ro" -v qumbra-data:/data \
  --entrypoint /usr/local/bin/qumbra-node \
  "$IMAGE" run --config /config/node.toml
```

`check` exercises the same byte/format/hash gate as startup without opening a listener
([`run.rs:226-242`](../crates/qumbra-node/src/run.rs#L226-L242)). A different file hash produces
`WrongGenesisHash` and the node refuses to start
([`genesis.rs:528-555`](../crates/qumbra-node/src/genesis.rs#L528-L555)).

### The same joiner from the prebuilt binaries

Identical config, identical genesis, identical seeds — only the invocation differs. Put
`genesis.qmb` and a `node.toml` beside the extracted binaries, with `data_dir` and
`genesis_file` as ordinary paths rather than the container's `/data` and `/config`:

```toml
data_dir = "./qumbra-data"
listen_addr = "0.0.0.0:9400"
dial_peers = ["18.202.166.126:9444","18.141.177.109:9444","52.194.224.123:9444","52.5.0.21:9444"]
genesis_file = "./genesis.qmb"
expected_genesis_hash = "138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb"
mining = false
```

```sh
curl -fsSL https://seed.qumbra.org/genesis.qmb -o genesis.qmb
./qumbra-node check --config node.toml     # same preflight, exits 0 and prints the genesis hash
./qumbra-node run   --config node.toml
```

The release lane runs exactly that `check`, against exactly that published genesis, on every
artifact before it is allowed onto the release page — so a tarball that reaches you has
already preflighted clean on its own platform. `run` writes into `data_dir`, so run it from a
directory you own; everything else in this guide — the telemetry fields below, mining in §3,
the wallet in §4 — reads the same either way.

### NAT is stated, not discovered

**Outbound-only participation is accepted by design.** Behind NAT you sync, mine, and transact,
but your address is never gossiped and you serve no peers. Leave `advertise_addr` unset. Set it
**only** when the advertised host and port are genuinely publicly dialable all the way to this
node; for the container that also means publishing the P2P port, for example `-p 9400:9400/tcp`.
This behavior is the recorded 2026-07-26 NAT decision, not a workaround
([`config.rs:68-78`](../crates/qumbra-node/src/config.rs#L68-L78),
[`run.rs:588-595`](../crates/qumbra-node/src/run.rs#L588-L595)).

### What healthy joining looks like

Read successive `TELEMETRY` lines, not one isolated sample
([`run.rs:1342-1371`](../crates/qumbra-node/src/run.rs#L1342-L1371)):

- `peers=N` is the live peer count: `N > 0` means at least one connection is live; persistent
  `peers=0` means the node has not joined a peer.
- `slag=N` is fork-choice tip minus applied-state tip: it should fall toward `0` while joining;
  `slag=0` means the node has applied its own selected chain
  ([`run.rs:1017-1034`](../crates/qumbra-node/src/run.rs#L1017-L1034)).
- `mready=-` is correct for the non-mining config above. After mining is enabled, `unknown` or
  `behind` means the startup mining gate is correctly refusing; `synced` or `latched` permits
  mining. It does **not** prove `slag=0`
  ([`run.rs:376-421`](../crates/qumbra-node/src/run.rs#L376-L421)).

## 3. Turn the joined node into a miner

### One command instead of five (added 2026-08-18, lab #475)

Everything in §2 and in the rest of §3 — a wallet, its backup, the payout key, a
hand-written `node.toml`, the genesis download — is what `qumbra-node mine` does
for you. It is the same node with the same config; the difference is that the
five steps are one:

```sh
./qumbra-node mine --dir ~/.qumbra-miner
```

On a terminal, with no wallet in that directory, it generates one, prints its
mnemonic **once** behind a red banner, and **waits for you to press Enter**
before it goes any further. Write the phrase down at that moment: it is not
stored anywhere you can read back, and every coin this node mines is paid to it.

Then it downloads `genesis.qmb` (only if the directory does not already have
one), verifies it against the hash this binary was built with **before anything
binds a socket**, writes an ordinary `node.toml` into the directory, and runs it.
Nothing is hidden: read `~/.qumbra-miner/node.toml` afterwards and it is the same
file §2 and §3 tell you to write by hand.

| flag | for |
|---|---|
| `--yes-i-backed-up` | the confirmation, for a run with no terminal (a systemd unit, a container). **Without a terminal and without this flag, `mine` refuses to create a wallet** rather than creating one silently — capture the mnemonic from the command's output yourself. |
| `--rkm <64 hex>` | pay a key you already have. No wallet is read, created, or looked for; this is the manual path of the sections above, unchanged. |
| `--seeds`, `--genesis-url`, `--listen`, `--index` | override the baked defaults (the four §1 seeds, `https://seed.qumbra.org/genesis.qmb`, `0.0.0.0:9400`, address index 0). A non-zero `--index` is **allocated** in the wallet as part of the run, so what this node mines stays inside what `scan` covers; it is capped at 1024, and a higher index is served by `qumbra-wallet address --new` plus `--rkm`. |

The wallet lands in `~/.qumbra-miner/wallet`, so every wallet command in §4 works
against it — `qumbra-wallet backup --dir ~/.qumbra-miner/wallet --reveal` shows
the phrase again, and `scan` reads what this node has mined. Re-running `mine` on
a prepared directory changes nothing and just starts the node; if you have edited
`node.toml` by hand it refuses rather than overwriting your edit, and tells you to
use `run --config` instead.

On Windows this is `.\qumbra-node.exe mine --dir $HOME\.qumbra-miner` in PowerShell,
and it is the shortest native path there is — it writes the `node.toml` itself, so
the TOML backslash trap in §1's Windows section cannot bite you.

### Platform boundary — CORRECTED 2026-08-17 (was: Linux/glibc only), Windows added 2026-08-18

> **Dated correction (2026-08-17, lab #437): native macOS mining is PERMITTED.** The original
> red boundary below was conditioned on the deterministic-emission boundary not yet being
> active — that boundary activated 2026-08-12 (#299/#303 closed). Above height 8,640,
> `body.coinbase == coinbase_exact(height)` is a hard consensus rule in pure integer
> arithmetic; no libm is reachable from consensus, so a native macOS miner can neither
> compute a divergent coinbase nor scar history. **Verified live, not just argued**: a native
> macOS arm64 build joined T1 through the public entry points and won 40 accepted, finalized
> blocks in its first ~100 minutes (lab #437). The container remains the paved, reproducible
> path; a native build is now a supported alternative.
>
> **Native Windows x64 mining is permitted on the same grounds (2026-08-18, lab #478)**, and
> the platform-identity question a new miner platform actually raises is answered by
> measurement rather than by the argument above: CI runs RandomX's four official reference
> vectors against the MSVC-built C++ on every windows leg, plus the check that the recommended
> flag set (JIT + hardware AES) and portable `FLAG_DEFAULT` agree — i.e. a Windows miner cannot
> hash differently because of what its CPU supports. 🔴 **What is NOT yet evidence: no Windows
> machine has mined a block on T1.** The claim on this line is "builds, hashes identically,
> preflights clean against the published genesis", not "verified live" — that is what the
> macOS line has and Windows does not, and the two should not be read as the same claim.
>
> **If you build from source, one flag is load-bearing**: a bare `cargo build -p qumbra-node`
> produces the ARMED variant, which halts at 8,640 and cannot follow today's chain. Build with
> `--features qumbra-node/rule-boundary-resume`, and confirm with `qumbra-node check` — its
> `halt plan:` line must read `no halt scheduled`, not `ARMED`. **The published tarballs in §1
> are already built with that flag** and CI refuses to publish one that is not, so the flag is
> a concern only if you compile it yourself.

The original boundary text, preserved for the record: *Mine on Linux/glibc only until the
deterministic-emission boundary is publicly confirmed active… A macOS miner has been measured
to compute coinbase values that differ by ±1 bessel from glibc at specific heights
([lab #303](https://github.com/qumbra-labs/qumbra-lab/issues/303)); consensus at the time
accepted those values, and each such block became a permanent scar the activation rule in
[lab #299](https://github.com/qumbra-labs/qumbra-lab/issues/299) must grandfather.*

Generate the payout identity from the wallet whose address should receive coinbase:

```sh
qumbra-wallet miner-rkm --dir "$HOME/.qumbra-wallet"
```

The command derives the allocated address index (index 0 by default) and prints the exact
64-hex-character `miner_rkm = "…"` line expected by the node
([`qumbra-wallet/main.rs:147-175`](../crates/qumbra-wallet/src/main.rs#L147-L175)). Paste it into
`node.toml` and change only these mining fields:

```toml
mining = true
miner_rkm = "[64 hex characters printed by qumbra-wallet miner-rkm]"
```

On startup, prove the config took effect by finding this exact line:

```text
miner payout: coinbase notes paid to the configured miner_rkm
```

If you instead see the following warning, stop mining and fix the config: valid blocks are being
paid to an unspendable placeholder and the payout is unrecoverable
([`run.rs:596-612`](../crates/qumbra-node/src/run.rs#L596-L612)).

```text
⚠️  NO miner_rkm CONFIGURED: ... Every coin this node mines is BURNED.
```

### 🔴 The unresolved first-start silence

A node with `miner_rkm` configured has been observed once to spend **about 57 minutes at silent
100% CPU before its first log line** on first start. This is unresolved
([lab #300](https://github.com/qumbra-labs/qumbra-lab/issues/300)). It is not necessarily hung:
if the process is alive and a core is pegged while no log line appears, leave it running. A
restart does not fix the path and only discards the work already spent; wait for the first line.

### Reward, maturity, pacing, and odds

- A won block pays the wallet **65% of the block subsidy (including the integer rounding
  remainder) plus all transaction fees**
  ([`emission.rs:27-30`](../crates/qlab-node/src/emission.rs#L27-L30),
  [`coinbase.rs:133-139`](../crates/qlab-node/src/coinbase.rs#L133-L139)).
- The coinbase becomes spendable after **144 more blocks**. That is about three hours at target,
  not a wall-clock promise
  ([`emission.rs:47-55`](../crates/qlab-node/src/emission.rs#L47-L55)).
- The network target is **75 seconds per block**, retargeted every block with **LWMA-120**; the
  deployable binary uses real RandomX, not the Keccak simulation placeholder
  ([`params_devnet.rs:16-49`](../crates/qlab-devnet/src/params_devnet.rs#L16-L49),
  [`pow.rs:66-100`](../crates/qlab-devnet/src/pow.rs#L66-L100)).
- This is solo mining, not a pool and not one reward every 75 seconds. Your expected share is your
  effective RandomX work divided by all effective work currently competing. The public surface
  exposes current difficulty, not fleet hash rate, so this guide cannot honestly quote personal
  odds. Expect variance and potentially long dry spells.

## 4. Wallet quickstart — five commands

The CLI's own help is the authority for flags and units
([`qumbra-wallet/main.rs:43-66`](../crates/qumbra-wallet/src/main.rs#L43-L66)). These five commands
cover the shortest user journey; replace `RECIPIENT_QADDR` and keep in mind that `--amount` is in
**bessel** (`100,000,000` bessel = `1 QMB`;
[`emission.rs:34-35`](../crates/qlab-node/src/emission.rs#L34-L35)).
Command 3 uses `curl` and `jq`; `qumbra-wallet --help` gives the full command reference.

**On Windows**, the same five commands run in PowerShell with `.\qumbra-wallet.exe` in place of
`qumbra-wallet`; `$HOME` and `$env:USERPROFILE` both work for `--dir`. Command 3 needs a
PowerShell equivalent, since `jq` is not present by default:
`$TIP = (Invoke-RestMethod https://explorer.qumbra.org/v1/health.json).chain.tip_height`.

```sh
# 1 — create the wallet; this prints address [0]
qumbra-wallet keygen --dir "$HOME/.qumbra-wallet"

# 2 — back up the Qumbra mnemonic in a private terminal
qumbra-wallet backup --dir "$HOME/.qumbra-wallet" --reveal

# Paste the full address [0] into https://faucet.qumbra.org and wait for its grant.

# 3 — obtain the height against which the balance claim will be made
TIP="$(curl -fsS https://explorer.qumbra.org/v1/health.json | jq -r '.chain.tip_height')"

# 4 — discover outputs and subtract spent notes through the public node edge
qumbra-wallet scan --dir "$HOME/.qumbra-wallet" \
  --url https://seed.qumbra.org --to "$TIP"

# 5 — rescan, build a real proof, and submit; --node defaults to --url if omitted
qumbra-wallet send --dir "$HOME/.qumbra-wallet" \
  --url https://seed.qumbra.org --scan-to "$TIP" \
  --to RECIPIENT_QADDR --amount 100000000
```

HTTP **429 Too Many Requests is expected behavior for the current faucet limit**; do not hammer
the form. [Lab #308](https://github.com/qumbra-labs/qumbra-lab/issues/308) records that the
network-keyed bucket is currently seen through the reverse proxy as a shared bucket, so another
visitor may have consumed it. Retry after the stated window while that issue remains open.

## 5. Verification record for the image claim

This is evidence that the package path is public and that remote label readback works; it is
**not** the T1 image announcement. On 2026-08-10, without pulling or registry credentials:

```text
$ docker buildx imagetools inspect ghcr.io/qumbra-labs/qumbra-node:t0-wan-14
Name:   ghcr.io/qumbra-labs/qumbra-node:t0-wan-14
Digest: sha256:931afa0fe57844f52e5bbb390914ec3116a72c3ff04781b11d8a080dcc4c2f29

$ docker buildx imagetools inspect --format \
  '{{index .Image.Config.Labels "org.opencontainers.image.revision"}}' \
  ghcr.io/qumbra-labs/qumbra-node@sha256:931afa0fe57844f52e5bbb390914ec3116a72c3ff04781b11d8a080dcc4c2f29
e8d52d7b194d3560f70de5d1f26b99b6f37bdd2e
```

Do not substitute that historical T0 digest for the bracketed T1 digest in §1.

The §4 public reads were also checked on 2026-08-10: `GET
https://explorer.qumbra.org/v1/health.json` returned the pinned genesis hash and a numeric
`chain.tip_height`, while `GET https://seed.qumbra.org/v1/compact?from=6313&to=6313` returned
HTTP 200 with `application/octet-stream`. The JSON field is defined at
[`qumbra-explorer/json.rs:55-80`](../crates/qumbra-explorer/src/json.rs#L55-L80); the height
`6313` is only the one-sample probe height, not a network parameter.
