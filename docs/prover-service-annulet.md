# The Annulet proving service — operator guide

*Chinese translation: [`prover-service-annulet-zh.md`](prover-service-annulet-zh.md). EN is authoritative.*

Lab issue #924, 5A-D3/D4; format 34 from lab #937 PR E. Code: `crates/qumbra-prover-service` (`src/annulet.rs`, `src/annulet_v3.rs`, `src/token.rs`).

The service serves one net, format 33 or format 34. Everything below up to [Format 34](#format-34-the-prover-is-paid-in-the-transaction) describes format 33; that section says what differs on 34.

## What it is

`qumbra-prover-service` proves Candidate A **holder** spends (shapes S and P) for wallets that keep their own keys. A wallet uploads a `ProvingBundle`: its transaction with the proof empty, the authorization section already signed and attached, and the witness. The section's intent binds every public field except the proof. The service can therefore add a proof and nothing else, so it cannot spend, re-aim or re-sign anything. Issuer operations (a P row carrying an issuer secret, or a non-zero `vPublic`) are refused as `issuer-shape` and are never delegated.

The service submits the proved transaction itself, to the pinned node's `POST /v1/tx` (and to the relay, if one is configured), and returns the tx id.

The L1 `WitnessBundle` mode (`/v1/jobs`) is unchanged. It now runs only when its own valueless acknowledgement is set, and is **off on an Annulet prover**.

## API

| Route | Auth | What |
|---|---|---|
| `GET /v2/annulet/info` | none | `genesis_format`, `genesis_hash`, `shapes`, `d_auth`, `max_bundle_bytes`, `queue_capacity`, `prove_timeout_secs`, `slot_secs`, **`recommended_valid_for_blocks`** |
| `GET /v2/annulet/quota` | Bearer | `per_day`, `used_today`, `in_flight` |
| `POST /v2/annulet/jobs` | Bearer | body = the bundle bytes (`application/octet-stream`, ≤ 80 KiB); 202 with `job_url`, or 200 with the existing job for the same intent |
| `GET /v2/annulet/jobs/<cap>` | **the URL** | `state` (`queued` / `proving` / `submitting` / `submitted` / `failed` / `refused` / `cancelled`), `queue_position`, `tx_id`, `refusal`, `expires_in_secs` |
| `DELETE /v2/annulet/jobs/<cap>` | **the URL** | cancels a queued or proving job |

**The job URL is a capability.** It is 32 random bytes, and it is the only thing that authorizes reading or cancelling the job. The popup that uploaded the bundle holds it as a secret. It stops working once the result TTL (default 600 s) has passed after the job ends.

**Admission order.** Every refusal is by name, and nothing is spawned or queued before step 5 passes:

1. The token: signature, validity window, net, revocation → `401` with `unauthorized`, `token-malformed`, `token-key-unknown`, `token-signature-invalid`, `token-window-invalid`, `token-expired`, `token-wrong-net` or `token-revoked`.
2. The token's single in-flight job, its single upload being read, and its daily quota → `429` with `token-busy` or `quota-exhausted`. Only **admitted** jobs count against the quota. An admitted upload must arrive within 30 s. Past that the handler gives up (counted as `upload-deadline`), but the token's reading slot stays taken until the connection actually ends, so a slow upload holds up only its own token.
3. The byte ceiling, read bounded → `413` `bundle-too-large`.
4. Decode → `400` `bundle-malformed`, or `403` `issuer-shape`.
5. The bundle's lock, run on this net → `422` with `statement-mismatch`, `unauthorized-section`, `proof-present`, `auth-missing`, `outputs-not-the-nets` (lab #937: the bundle's output count is not this net's — a three-output bundle on format 33), `third-output-asset` (lab #937: a three-output bundle whose third output carries neither input's asset, nor asset 0 paid through the fee bank — the v3 AIR has no proof for it) or `fee-note-not-exact` (lab #937 PR D: slot 3's fee note is neither exactly the fee nor exactly the fee plus an asset-0 third output).

After admission the request can still be refused with `409` `intent-in-flight` (another token holds this intent) or `503` `prover-busy` (the queue is full).

**Idempotency.** The idempotency key is the signed intent's digest, computed by the server. Re-sending the same signed transaction returns its existing job. A job that ended without a transaction (`failed`, `refused`, `cancelled`) may be retried.

**Validity.** The service does not judge `valid_until`, because it does not know the tip. A client signs with at least `recommended_valid_for_blocks` = ⌈((queue + 1) × prove timeout + 60 s) / slot⌉. If the transaction lands too late, the node refuses it and the job fails with `node-refused:<code>`.

## Tokens

The wire form is `qpt1.<base64url(payload ‖ ML-DSA-44 signature)>`. The payload is fixed width: key id, a 16-byte token id, the net's genesis hash, `not_before`, `not_after` (at most 30 days apart), `per_day` (0 means the operator default), and flags (zero). The prover holds **verifying keys only**; the minting key never touches the prover box.

```sh
# Once, on the operator's machine. The seed is 64 hex characters in a file,
# never on a command line.
qumbra-prover-service token-key  --seed-file issuer.seed --key-id 1   > token-keys.txt   # public: copy to the box
qumbra-prover-service mint-token --seed-file issuer.seed --key-id 1 \
    --genesis-hash <64 hex> --days 30 [--per-day 20]        # token on stdout, token id on stderr
```

To revoke a token, add its token id (32 hex) to `QUMBRA_PROVER_TOKEN_DENY_FILE`. The service re-reads that file every minute.

The gateway's portal will mint tokens later by calling `qumbra_prover_service::token::mint` with its own issuer key under its own `key_id`.

## Configuration

The Annulet mode is on exactly when `QUMBRA_PROVER_ANNULET_GENESIS_HASH` is set. Everything else then fails closed:

| Variable | Default | Notes |
|---|---|---|
| `QUMBRA_PROVER_ANNULET_GENESIS_HASH` | — | 64 lowercase hex; the net's genesis file hash |
| `QUMBRA_PROVER_ANNULET_SLOT_SECS` | — | the genesis `slot_secs` |
| `QUMBRA_PROVER_ANNULET_NODE_URL` | — | a node accepting `POST /v1/tx`; https, unless the plain-http acknowledgement below is set |
| `QUMBRA_PROVER_ANNULET_RELAY_URL` | unset | best-effort second submission; same rule |
| `QUMBRA_PROVER_ANNULET_ALLOW_PLAIN_HTTP_NODE` | unset | exactly `I_UNDERSTAND_THE_NODE_LINK_IS_PLAINTEXT_AND_FIREWALLED_TO_THIS_HOST` admits a plain `http://` node or relay URL. Use it only where a firewall admits this host alone to that port. What crosses the link is a signed, proved transaction that is public once submitted, and any change to it invalidates it, so the exposure is a dropped submission. The L1 experiment's `QUMBRA_PROVER_ALLOW_INSECURE_NODE_HTTP` does not apply to this mode |
| `QUMBRA_PROVER_ANNULET_QUEUE` | 3 | 1..=8, queued jobs, not counting the running one |
| `QUMBRA_PROVER_ANNULET_TIMEOUT_SECS` | 300 | 30..=1800, per prove |
| `QUMBRA_PROVER_ANNULET_RESULT_TTL_SECS` | 600 | 60..=3600 |
| `QUMBRA_PROVER_ANNULET_PER_DAY` | 20 | the default for tokens that state 0 |
| `QUMBRA_PROVER_TOKEN_KEYS_FILE` | — | `key_id verifying_key_hex` per line |
| `QUMBRA_PROVER_TOKEN_DENY_FILE` | unset | revoked token ids |
| `QUMBRA_PROVER_SCRATCH` | — | **must be a tmpfs mount** (checked at start; Linux only) |
| `QUMBRA_PROVER_LISTEN`, `QUMBRA_PROVER_ALLOW_NON_LOOPBACK_LISTEN` | as for L1 | TLS, rate limiting and a request-header size cap live at ingress |

## The worker child

Proofs run one at a time, each in a fresh `annulet-worker` child process:

- the environment is cleared except for the protocol tag, the genesis hash and the genesis format, so the child has no URL and no token;
- core dumps are off: `RLIMIT_CORE = 0` is set between fork and exec. On Linux the child also clears `PR_SET_DUMPABLE` itself, first thing after exec (the kernel resets that flag on `execve`). After that, a same-uid process cannot `ptrace` it or read `/proc/<pid>/mem`. The server does the same to itself at startup, because it holds bundles too;
- the working directory and `TMPDIR` are the tmpfs scratch;
- stderr is closed;
- the bundle is written to the child's stdin from its own thread, because 80 KiB can exceed a pipe's buffer. The prove timeout therefore also covers a child that stalls before reading.

Both processes wipe the decoded bundle's witness when they drop it.

The child re-runs the bundle's lock and proves. The server then checks that the answer is the bundle's transaction plus a non-empty proof and nothing else (otherwise the job fails with `proof-mismatch`), and only then submits it.

## Logs and what resets

- Per job: an 8-hex job prefix, the shape, bundle and tx sizes, queue wait, prove time, and an outcome code. Bundle bytes, transaction bytes, token ids and tx ids are never logged.
- Every minute: admission refusals counted per code, under a 4-byte hash of the token id (`-` before a token verified). This shows abuse without naming the user.
- **Per-day counts, in-flight state and jobs live in memory and reset on restart.**

## Format 34: the prover is paid in the transaction

Lab #937 PR E (rulings D4 and D5, and the PR E ruling on issue #937). On a format-34 net (`QUMBRA_PROVER_ANNULET_GENESIS_FORMAT=34`) a bundle's **third output pays this service**: the configured payee's `rkm`, asset 0, at least the advertised price of the bundle's shape. There is no token and no account.

**What differs from format 33:**

- **No token.** `QUMBRA_PROVER_TOKEN_KEYS_FILE` and `QUMBRA_PROVER_TOKEN_DENY_FILE` are not read. If they are still configured (prover-1's are, until D6 retires them), they are ignored, not refused, and startup logs that they were ignored. `Authorization` is never read. `GET /v2/annulet/quota` answers `404 quota-not-served`. There is no daily quota.
- **`/v2/annulet/info`** also carries `fee_asset` (0), `price` (`{"S": n, "P": n}`) and `payee` (the full address). These are the fields the kernel's `prover_pins::admit` checks against the network's pin. On 33 these fields are absent.
- **`/healthz`** answers `503` with the follow's code until the nullifier follow has caught up, and again whenever it falls more than one slot behind (see below).

**Admission order on 34.** Every refusal is by name, and nothing is queued before step 5:

1. **The client IP**, from `X-Qumbra-Client-IP`:
   - absent, repeated or not an IP → `400 client-ip-unknown`;
   - a second live job or a second upload from the same IP → `429 ip-busy`.

   An IPv4-mapped IPv6 address counts as its IPv4 address. An IPv6 address counts by its /64. So several users behind one NAT or CGNAT share one slot: they wait for each other's job. That is accepted on the testnet.
2. The byte ceiling, decode and the bundle's lock, as on 33. A two-output bundle is `422 outputs-not-the-nets`.
3. **The fee**, read from the witness's output 3, which the lock has already bound to the transaction's third commitment:
   - not the payee's `rkm`, or not asset 0 → `402 prover-fee-missing`;
   - a value below the shape's price → `402 prover-fee-short`.

   More than the price is accepted.
4. **The nullifiers**:
   - one has landed on chain → `409 nullifier-landed`;
   - the follow is not ready → `503 nullifiers-catching-up` or `503 nullifiers-stale`;
   - one is claimed by a job here that may still land (queued, proving, submitting, or submitted within the result TTL) → `409 nullifier-in-flight`.

   The intent is still the idempotency key, and the client's IP is its submitter. While the job is live, a retry from that IP is already refused at step 1 (`429 ip-busy`, as `token-busy` is on 33). Once the job has ended (`submitted`, `failed`, `refused`, `cancelled`), a retry from that IP gets the existing job back, or a fresh one if it ended without a transaction. Another IP gets `409 intent-in-flight`.
5. The retained-job and queue bounds, as on 33.

**The client IP and its premise.** The service trusts `X-Qumbra-Client-IP` because it listens only on the internal ingress network. The `QUMBRA_PROVER_ALLOW_NON_LOOPBACK_LISTEN` acknowledgement covers that premise.

Caddy sets the header (the cut-over's deploy change, not this PR):
- `trusted_proxies static <Cloudflare's published ranges>`, with `client_ip_headers CF-Connecting-IP`;
- `header_up X-Qumbra-Client-IP {client_ip}` on `/v2/annulet/*`. This overwrites any copy a client sends.

A connection that does not come from a Cloudflare range gets its own socket address as its client IP, so going around Cloudflare cannot impersonate another IP. Closing 443 to non-Cloudflare sources is an operator step at the cut-over.

The IP is never logged. Refusals are counted under a 4-byte hash of a per-process salted key.

**The nullifier follow.** The service follows its pinned node itself (`QUMBRA_PROVER_ANNULET_NODE_URL`):
- the tip is read from `GET /v1/registry/root`;
- the landed nullifiers are paged from `GET /v1/nullifiers`, starting at height 1.

It polls every quarter slot (no more often than every 200 ms), so a slow poll still lands well inside the one slot after which the set is stale. Every height must be served, in order. A page that skips a height or a page with no block is an error, and the set does not advance past it. A tip below the followed height (a reorganisation deeper than the set, or a node rolled back) empties the set: it is logged as `error:` and rebuilt from height 1, catching up again.

The set lives in memory (32 bytes per nullifier) and is rebuilt from height 1 at every start. The first catch-up logs its size and how long it took. If that rebuild grows past 60 s, a persisted set gets its own issue.

**It fails loudly.** Admission answers `503`, and `/healthz` is not ready:
- `nullifiers-catching-up` until the first catch-up;
- `nullifiers-stale` once the last catch-up is more than one slot old. That covers an unreachable node and a follow that has fallen behind.

A follow failure is logged once as `error:`, and its recovery once.

*Residuals.*
- **At most one wasted prove per IP per prove time.** A transaction that loses a race to a spend the follow has not yet seen still gets proved, and its landed spend costs the attacker real notes (accepted at D4).
- A nullifier from a block that is later reorganised away, by a reorganisation shallower than the set, stays in the set until the next restart or the next rebuild. Until then its notes are refused as `nullifier-landed`.

**The paid ledger (D5).** `QUMBRA_PROVER_ANNULET_PAID_LEDGER` names a file.

*The file:*
- The service creates it with mode 0600 and writes the header line `qumbra-prover-paid-ledger 1`.
- An existing file must already be 0600 and start with that header. Otherwise startup refuses it by name.
- Mount it from durable storage. `/scratch` is tmpfs and is lost on restart.
- It is never logged and never goes in git.

*Writing order.* After the node **accepts** `POST /v1/tx`, the service appends one line and fsyncs it. Only then does the job read `submitted`.

*The line.* The entry version `1`, then space-separated fields:

```
1 cm=<64 hex> value=<n> asset=0 rkm=<64 hex> rho=<64 hex> rseed=<64 hex> shape=<S|P> at=<unix seconds>
```

- `cm` is the transaction's third commitment, as on chain.
- `rkm`, `rho` and `rseed` are the four `u64` lanes, each little-endian, as 64 hex.
- There is no height, because the service does not know where the transaction lands. A reader finds `cm` in the tree.

*What writes nothing:*
- A submission the node refuses.
- Anything refused at admission.
- A replay of the same transaction, which the nullifier dedupe refuses.

*If the write fails.* The submission cannot be undone. The service logs `error: annulet paid ledger write failed for cm=<hex>` for the operator to recover by hand.

*Crashes.* A crash mid-write can leave a last line without its newline. A reader skips that line.

The operator copies the file to the payee wallet's machine; the payee's seed stays off the box. It imports it with `qumbra-wallet import-openings --net annulet` — see [`prover-payee-wallet.md`](prover-payee-wallet.md). An honest kernel also encrypts output 3's discovery payload to the payee, so the payee's ordinary scan already finds these notes. The ledger covers a wallet that did not.

**Configuration on 34**, in addition to the table above (the token rows do not apply):

| Variable | Default | Notes |
|---|---|---|
| `QUMBRA_PROVER_ANNULET_GENESIS_FORMAT` | 33 | `34` serves the three-output net |
| `QUMBRA_PROVER_ANNULET_PAYEE` | — | the payee's **full** version-2 address (a `qs1…` short address is a hash and cannot be checked); compared by its decoded `rkm` |
| `QUMBRA_PROVER_ANNULET_PRICE_S` | — | the price of shape S, in asset-0 fee units |
| `QUMBRA_PROVER_ANNULET_PRICE_P` | — | the price of shape P |
| `QUMBRA_PROVER_ANNULET_PAID_LEDGER` | — | the paid ledger's path, on durable storage |

## The pilot box (prover-1)

- **Host:** r7g.2xlarge (64 GiB, arm64). One P prove peaks at about 32 GiB.
- **Container:** `mem_limit` about 58g, no swap, `ulimits: core: 0`, a tmpfs mounted at `/scratch` (1g), read-only root filesystem.
- **Env:** the variables above. The net is format 33 until the lab #937 cut-over moves it to 34; take the genesis hash from the deploy repo. The node URL must point at a node that accepts `POST /v1/tx`.
- **Ingress:** TLS, rate limiting and a request-header size cap (Caddy), plus the non-loopback acknowledgement. Security group 443 is open, because the extension calls the service directly. **Keep `/v2/annulet/jobs/<cap>` out of the ingress access log**, or log only the path prefix: the capability in that URL is the job's secret.
- **Operator-held, not on the box:** the issuer seed.
- **Manual operator steps:** the Terraform apply for the host and its security group, DNS, keeping the issuer seed, and starting and stopping the host by hand.
